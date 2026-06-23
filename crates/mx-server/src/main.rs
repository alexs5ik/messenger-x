//! # mx-server — the Messenger X backend binary (`mx`)
//!
//! The single runnable process of the modular monolith. It owns no domain logic of its
//! own; it **wires the library crates together** behind an HTTP + WebSocket API:
//!
//! - [`mx_storage`] in-memory stores (users, pre-keys, message queues, groups),
//! - [`mx_auth::AuthService`] for registration, pre-key publish/fetch and session tokens,
//! - [`mx_messaging::MessagingService`] for envelope ingest and per-device fan-out,
//! - [`mx_presence::PresenceService`] for ephemeral online/typing state,
//! - [`mx_ai::AiOrchestrator`] as the envelope-rule choke point for AI routing.
//!
//! ## Ciphertext-only invariant
//!
//! Every payload that crosses this server does so as an opaque
//! [`mx_types::Ciphertext`] inside an [`mx_types::Envelope`]. No route here ever inspects,
//! decrypts, or transforms message content — the backend stores and routes ciphertext
//! only, exactly as the design document requires.
//!
//! ## HTTP API
//!
//! | Method & path                | Purpose                                            |
//! |------------------------------|----------------------------------------------------|
//! | `GET  /health`               | Liveness probe → `200 ok` (plain text).            |
//! | `POST /v1/register`          | Create a user + its first device, issue a token.   |
//! | `POST /v1/prekeys`           | Publish a [`PreKeyBundle`] for a device.           |
//! | `GET  /v1/prekeys/:device`   | Fetch + consume a one-time pre-key bundle.         |
//! | `POST /v1/messages`          | Ingest an [`Envelope`] → `202 Accepted`.           |
//! | `GET  /v1/messages/:device`  | Drain a device's queued envelopes (JSON array).    |
//! | `GET  /v1/ws`                | WebSocket gateway (auth → send/receive loop).      |
//!
//! ## Admin API (header `x-admin-token` == env `MX_ADMIN_TOKEN`, default `mx-dev-admin`)
//!
//! | Method & path                       | Purpose                                     |
//! |-------------------------------------|---------------------------------------------|
//! | `GET  /v1/admin/overview`           | Counts (users/devices/queued) + maintenance.|
//! | `GET  /v1/admin/users`              | All accounts with identifiers + device count.|
//! | `POST /v1/admin/broadcast`          | Announcement Control envelope to all devices.|
//! | `POST /v1/admin/users/:id/delete`   | Remove a user + devices/prekeys/queue.       |
//! | `POST /v1/admin/maintenance`        | Toggle the global ingest kill-switch.        |

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::{header::CACHE_CONTROL, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream, StreamExt},
};
use argon2::password_hash::{
    rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
};
use argon2::Argon2;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;

use mx_ai::AiOrchestrator;
use mx_auth::AuthService;
use mx_messaging::MessagingService;
use mx_presence::PresenceService;
use mx_storage::{
    InMemoryGroupStore, InMemoryMessageQueue, InMemoryPreKeyStore, InMemoryUserStore, PreKeyStore,
    UserStore,
};
use mx_transport::{ClientMessage, ServerMessage};
use mx_types::{
    Ciphertext, DeviceId, Envelope, Error, MessageKind, PreKeyBundle, PublicKey, Recipient, UserId,
};

/// Concrete messaging service type used by the in-memory deployment.
///
/// The stores are shared (via [`Arc`]) with [`AuthService`], so a user registered through
/// the auth API is immediately routable by the messaging API — they are the same backing
/// state, not two copies.
type Messaging = MessagingService<
    Arc<InMemoryUserStore>,
    Arc<InMemoryGroupStore>,
    Arc<InMemoryMessageQueue>,
>;

/// Registry of live WebSocket sessions: device → a notify channel for that session.
///
/// The durable queue ([`Messaging::pull`]) remains the single source of truth for message
/// content; the hub only carries a wake-up *signal*. After an envelope is ingested, each
/// recipient device that has a live session is signaled, and that session drains the queue
/// and pushes the new envelopes immediately — real-time delivery without a polling loop.
/// Because delivery always goes through the atomic `pull`, each envelope is handed out
/// exactly once whether it is flushed on connect or pushed live.
#[derive(Default)]
struct Hub {
    sessions: Mutex<HashMap<DeviceId, mpsc::UnboundedSender<()>>>,
}

impl Hub {
    /// Register a session for `device`, returning the receiver it should await. Replaces any
    /// previous session for the same device (last connection wins).
    async fn register(&self, device: DeviceId) -> mpsc::UnboundedReceiver<()> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.sessions.lock().await.insert(device, tx);
        rx
    }

    /// Remove a device's session on disconnect.
    async fn unregister(&self, device: DeviceId) {
        self.sessions.lock().await.remove(&device);
    }

    /// Wake the live session for `device`, if any, to pull pending messages.
    async fn notify(&self, device: DeviceId) {
        if let Some(tx) = self.sessions.lock().await.get(&device) {
            let _ = tx.send(());
        }
    }
}

/// Shared application state, cloned cheaply into every request handler.
///
/// All fields are reference-counted handles; cloning an [`AppState`] clones the [`Arc`]s,
/// not the underlying services.
#[derive(Clone)]
struct AppState {
    /// Identity, pre-keys, and session tokens.
    auth: AuthService,
    /// Envelope ingest + per-device fan-out + drain.
    messaging: Arc<Messaging>,
    /// Ephemeral presence (online / typing). Behind a mutex: its API takes `&mut self`.
    presence: Arc<Mutex<PresenceService>>,
    /// Tiered AI router (envelope-rule enforcement). Held for completeness / future routes.
    #[allow(dead_code)]
    ai: Arc<AiOrchestrator>,
    /// Live WebSocket session registry for real-time push.
    hub: Arc<Hub>,
    /// Store handles retained for snapshot persistence (so a restart is non-destructive).
    users: Arc<InMemoryUserStore>,
    prekeys: Arc<InMemoryPreKeyStore>,
    groups: Arc<InMemoryGroupStore>,
    /// Message queue handle retained for admin overview (count) + user deletion (purge).
    queue: Arc<InMemoryMessageQueue>,
    /// Secret guarding all `/v1/admin/*` routes (header `x-admin-token`).
    admin_token: Arc<String>,
    /// Global kill-switch: when true, message ingest is rejected.
    maintenance: Arc<AtomicBool>,
    /// Pending email password-reset tokens (transient; not snapshotted).
    resets: Arc<Mutex<HashMap<String, ResetEntry>>>,
}

impl AppState {
    /// Build the full service graph over fresh in-memory stores.
    ///
    /// `token_secret` keys the session-token HMAC in [`AuthService`].
    fn new(token_secret: impl Into<Vec<u8>>) -> Self {
        // One backing instance per store, shared between auth and messaging.
        let users = Arc::new(InMemoryUserStore::new());
        let prekeys = Arc::new(InMemoryPreKeyStore::new());
        let queue = Arc::new(InMemoryMessageQueue::new());
        let groups = Arc::new(InMemoryGroupStore::new());

        // `AuthService` wants trait objects; coerce the shared handles (same allocation).
        let users_dyn: Arc<dyn UserStore> = users.clone();
        let prekeys_dyn: Arc<dyn PreKeyStore> = prekeys.clone();
        let auth = AuthService::new(users_dyn, prekeys_dyn, token_secret);

        // `MessagingService` owns its stores by value; the `Arc` blanket impls make the
        // shared handles satisfy the store traits, so it routes over the *same* state. We
        // clone the handles (cheap Arc bumps) so AppState can also reach them for snapshots
        // and for admin queue inspection / purge.
        let messaging = Arc::new(MessagingService::new(
            users.clone(),
            groups.clone(),
            queue.clone(),
        ));

        Self {
            auth,
            messaging,
            presence: Arc::new(Mutex::new(PresenceService::new())),
            ai: Arc::new(AiOrchestrator::with_mock_providers()),
            hub: Arc::new(Hub::default()),
            users,
            prekeys,
            groups,
            queue,
            admin_token: Arc::new(
                std::env::var("MX_ADMIN_TOKEN").unwrap_or_else(|_| "mx-dev-admin".to_string()),
            ),
            maintenance: Arc::new(AtomicBool::new(false)),
            resets: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Remove a user and every trace of it: account, devices, prekeys, and queued messages.
    async fn delete_user(&self, id: UserId) {
        let removed = self.users.delete_user(id).await;
        for d in removed {
            self.prekeys.remove_device(d).await;
            self.queue.purge_device(d).await;
        }
    }

    /// Hydrate the in-memory stores from a previously persisted snapshot.
    async fn apply_snapshot(&self, snap: mx_storage::persist::Snapshot) {
        let users = snap.users.len();
        snap.apply(&self.users, &self.prekeys, &self.groups).await;
        tracing::info!(users, "restored state snapshot");
    }

    /// Capture the current durable state for persistence.
    async fn capture_snapshot(&self) -> mx_storage::persist::Snapshot {
        mx_storage::persist::Snapshot::capture(&self.users, &self.prekeys, &self.groups).await
    }

    /// Deliver any pending envelopes for `device` over the socket. Returns `false` if the
    /// socket is gone. Shared by the connect-time flush and the live-push wake-up.
    async fn deliver_pending(&self, device: DeviceId, sender: &mut WsSink) -> bool {
        match self.messaging.pull(device).await {
            Ok(pending) => {
                for env in pending {
                    if !send_frame(sender, ServerMessage::Incoming(env)).await {
                        return false;
                    }
                }
                true
            }
            Err(_) => true,
        }
    }

    /// After an envelope is accepted, wake every recipient device that has a live session so
    /// it pulls and pushes the message immediately.
    async fn notify_recipients(&self, to: &mx_types::Recipient) {
        if let Ok(devices) = self.messaging.recipients(to).await {
            for d in devices {
                self.hub.notify(d).await;
            }
        }
    }
}

/// Current wall-clock time in milliseconds since the Unix epoch.
fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ===========================================================================
// HTTP error mapping
// ===========================================================================

/// Wrapper that turns an [`mx_types::Error`] into an HTTP response.
///
/// Domain errors map onto status codes so clients get a meaningful result rather than a
/// blanket 500. The body is a small JSON object `{"error": "..."}`.
struct ApiError(Error);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            Error::NotFound(_) => StatusCode::NOT_FOUND,
            Error::InvalidInput(_) => StatusCode::BAD_REQUEST,
            Error::Unauthorized => StatusCode::UNAUTHORIZED,
            Error::Transport(_) => StatusCode::BAD_REQUEST,
            Error::Crypto(_) | Error::Storage(_) | Error::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        let body = Json(serde_json::json!({ "error": self.0.to_string() }));
        (status, body).into_response()
    }
}

// ===========================================================================
// Password hashing & policy (argon2)
// ===========================================================================

/// How long an email reset token stays valid.
const RESET_TTL_MS: i64 = 30 * 60 * 1000;
/// Symbols used to guarantee a generated temp password satisfies the policy.
const PW_SPECIALS: &[u8] = b"!@#$%^&*()-_=+?";

/// A pending email password-reset: which account, and when the token expires.
struct ResetEntry {
    user_id: UserId,
    expires_at: i64,
}

/// Enforce the password policy: at least 8 characters and at least one non-alphanumeric symbol.
fn check_password_policy(pw: &str) -> Result<(), ApiError> {
    if pw.chars().count() < 8 {
        return Err(ApiError(Error::InvalidInput(
            "пароль должен быть не короче 8 символов".into(),
        )));
    }
    if !pw.chars().any(|c| !c.is_alphanumeric()) {
        return Err(ApiError(Error::InvalidInput(
            "пароль должен содержать хотя бы один спецсимвол".into(),
        )));
    }
    Ok(())
}

/// Hash a password with argon2 (random salt), returning the PHC string to store.
fn hash_password(pw: &str) -> Result<String, ApiError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| ApiError(Error::Internal(format!("password hash: {e}"))))
}

/// Verify a password against a stored argon2 PHC hash (constant-time inside argon2).
fn verify_password(hash: &str, pw: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(pw.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// Generate a policy-compliant temporary password (for the SMS reset flow).
fn gen_temp_password() -> String {
    const ALNUM: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    let mut s: String = (0..9)
        .map(|_| ALNUM[rng.gen_range(0..ALNUM.len())] as char)
        .collect();
    // Guarantee the policy regardless of the random draw: append a symbol and a digit.
    s.push(PW_SPECIALS[rng.gen_range(0..PW_SPECIALS.len())] as char);
    s.push(char::from(b'0' + rng.gen_range(0..10)));
    s
}

/// Generate a random hex reset token.
fn gen_reset_token() -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let mut rng = rand::thread_rng();
    (0..32).map(|_| HEX[rng.gen_range(0..16)] as char).collect()
}

// ===========================================================================
// Request / response DTOs
// ===========================================================================

/// `POST /v1/register` request: at least one identifier (username/email/phone) plus the new
/// device's identity public key. The server requires ≥1 identifier and enforces uniqueness
/// across all three.
#[derive(Debug, Deserialize)]
struct RegisterRequest {
    /// Human-facing handle for the new account.
    #[serde(default)]
    username: Option<String>,
    /// Optional email identifier.
    #[serde(default)]
    email: Option<String>,
    /// Optional phone identifier.
    #[serde(default)]
    phone: Option<String>,
    /// Account password. Required when registering by email or phone; the passwordless "name"
    /// demo path omits it. Validated against the policy and stored only as an argon2 hash.
    #[serde(default)]
    password: Option<String>,
    /// Long-term identity public key for the account's first device.
    identity_key: PublicKey,
}

/// `POST /v1/register` response: the freshly minted ids and a bearer session token.
///
/// `Deserialize` is derived so tests (and any in-process client) can parse it back. Reused for
/// `/v1/login`; `must_change` is set when the user signed in with a temporary password.
#[derive(Debug, Serialize, Deserialize)]
struct RegisterResponse {
    /// The new account id.
    user_id: UserId,
    /// The new device id (its first installation).
    device_id: DeviceId,
    /// Bearer token authenticating `(user_id, device_id)`; used for the WS `Hello`.
    token: String,
    /// True when the session was opened with a server-generated temporary password and the
    /// client must prompt the user to set a permanent one.
    #[serde(default)]
    must_change: bool,
}

/// `POST /v1/login` request: an identifier (email/phone/username) + password + a fresh device key.
#[derive(Debug, Deserialize)]
struct LoginRequest {
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    password: String,
    /// Identity public key for the device this login session creates.
    identity_key: PublicKey,
}

/// `POST /v1/auth/forgot` request: which channel + identifier to start a reset for.
#[derive(Debug, Deserialize)]
struct ForgotRequest {
    /// "email" or "phone".
    method: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
}

/// `POST /v1/auth/forgot` response. In this demo build the secret is returned to the caller (the
/// UI shows it) instead of being delivered over a real email/SMS provider.
#[derive(Debug, Serialize)]
struct ForgotResponse {
    /// "email" → a reset link/token is issued; "phone" → a temporary password is generated.
    channel: String,
    /// Email flow: the one-time reset token (the UI builds a reset link from it).
    #[serde(skip_serializing_if = "Option::is_none")]
    reset_token: Option<String>,
    /// Phone flow: the generated temporary password the user logs in with.
    #[serde(skip_serializing_if = "Option::is_none")]
    temp_password: Option<String>,
}

/// `POST /v1/auth/reset` request: complete an email reset with the token + a new password.
#[derive(Debug, Deserialize)]
struct ResetRequest {
    token: String,
    password: String,
}

/// `POST /v1/auth/change` request: set a new password for the authenticated session (used by the
/// forced change after an SMS temporary password). Auth is the `Authorization: Bearer` token.
#[derive(Debug, Deserialize)]
struct ChangeRequest {
    password: String,
}

/// JSON-safe transport wrapper for an [`Envelope`] in HTTP bodies.
///
/// `mx-types`'s [`mx_types::Recipient`] is an internally-tagged enum wrapping newtype ids,
/// which `serde_json` cannot serialize directly (see [`mx_transport::wire_envelope`]). This
/// newtype routes the field through that crate's JSON-safe adapter, so the HTTP API uses the
/// exact same wire shape as the WebSocket [`ServerMessage::Incoming`] frames. The body is a
/// bare envelope object (the wrapper is `#[serde(transparent)]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct WireEnvelope(#[serde(with = "mx_transport::wire_envelope")] Envelope);

/// `POST /v1/prekeys` request: a device's pre-key bundle to publish.
///
/// The target device is taken from `bundle.device_id`; [`AuthService::publish_prekeys`]
/// enforces that they agree, so there is no separate device field to spoof.
#[derive(Debug, Deserialize)]
struct PublishPrekeysRequest {
    /// The bundle to publish (or replace) for `bundle.device_id`.
    bundle: PreKeyBundle,
}

// ===========================================================================
// HTTP handlers
// ===========================================================================

/// Liveness probe. Returns the plain-text body `ok` with a `200` status.
async fn health() -> &'static str {
    "ok"
}

/// Create a new account and its first device, then issue a session token. Registering by email or
/// phone requires a policy-compliant password (stored as an argon2 hash); the "name" demo path is
/// passwordless.
async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let has_contact = req.email.is_some() || req.phone.is_some();
    let pw_hash = match req.password.as_deref().map(str::trim) {
        Some(pw) if !pw.is_empty() => {
            check_password_policy(pw)?;
            Some(hash_password(pw)?)
        }
        _ if has_contact => {
            return Err(ApiError(Error::InvalidInput(
                "регистрация по email/телефону требует пароль".into(),
            )));
        }
        _ => None,
    };
    let user_id = state
        .auth
        .register_account(req.username, req.email, req.phone)
        .await?;
    if let Some(h) = pw_hash {
        state.users.set_password(user_id, Some(h), false).await;
    }
    let device_id = state
        .auth
        .register_device(user_id, req.identity_key)
        .await?;
    let token = state.auth.issue_token(user_id, device_id, now_ms());
    Ok((
        StatusCode::CREATED,
        Json(RegisterResponse {
            user_id,
            device_id,
            token,
            must_change: false,
        }),
    ))
}

/// Authenticate an existing account by identifier + password and open a new device session.
async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    // Resolve the account by whichever identifier was supplied.
    let user = if let Some(email) = req.email.as_deref() {
        state.users.find_by_email(email.trim()).await
    } else if let Some(phone) = req.phone.as_deref() {
        state.users.find_by_phone(phone.trim()).await
    } else if let Some(username) = req.username.as_deref() {
        state.users.find_by_username(username.trim()).await
    } else {
        None
    };
    let user = user.ok_or_else(|| ApiError(Error::Unauthorized))?;
    let hash = user
        .password_hash
        .as_deref()
        .ok_or_else(|| ApiError(Error::Unauthorized))?;
    if !verify_password(hash, req.password.trim()) {
        return Err(ApiError(Error::Unauthorized));
    }
    let device_id = state.auth.register_device(user.id, req.identity_key).await?;
    let token = state.auth.issue_token(user.id, device_id, now_ms());
    Ok(Json(RegisterResponse {
        user_id: user.id,
        device_id,
        token,
        must_change: user.must_change_password,
    }))
}

/// Start a password reset. Email → issue a one-time reset token; phone → generate a temporary
/// password and mark the account must-change. In this demo the secret is returned to the caller.
async fn forgot_password(
    State(state): State<AppState>,
    Json(req): Json<ForgotRequest>,
) -> Result<Json<ForgotResponse>, ApiError> {
    match req.method.as_str() {
        "email" => {
            let email = req.email.unwrap_or_default();
            let user = state
                .users
                .find_by_email(email.trim())
                .await
                .ok_or_else(|| ApiError(Error::NotFound("email не зарегистрирован".into())))?;
            let token = gen_reset_token();
            state.resets.lock().await.insert(
                token.clone(),
                ResetEntry {
                    user_id: user.id,
                    expires_at: now_ms() + RESET_TTL_MS,
                },
            );
            Ok(Json(ForgotResponse {
                channel: "email".into(),
                reset_token: Some(token),
                temp_password: None,
            }))
        }
        "phone" => {
            let phone = req.phone.unwrap_or_default();
            let user = state
                .users
                .find_by_phone(phone.trim())
                .await
                .ok_or_else(|| ApiError(Error::NotFound("телефон не зарегистрирован".into())))?;
            let temp = gen_temp_password();
            let hash = hash_password(&temp)?;
            state.users.set_password(user.id, Some(hash), true).await;
            Ok(Json(ForgotResponse {
                channel: "phone".into(),
                reset_token: None,
                temp_password: Some(temp),
            }))
        }
        other => Err(ApiError(Error::InvalidInput(format!(
            "unknown reset method: {other}"
        )))),
    }
}

/// Complete an email reset: validate the token, enforce the policy, set the new password.
async fn reset_password(
    State(state): State<AppState>,
    Json(req): Json<ResetRequest>,
) -> Result<StatusCode, ApiError> {
    // Validate the password BEFORE consuming the token, so a rejected weak password leaves the
    // reset link still usable for a retry.
    check_password_policy(req.password.trim())?;
    let hash = hash_password(req.password.trim())?;
    let entry = {
        let mut resets = state.resets.lock().await;
        match resets.get(&req.token) {
            Some(e) if e.expires_at >= now_ms() => resets.remove(&req.token),
            Some(_) => {
                resets.remove(&req.token); // expired → drop it
                None
            }
            None => None,
        }
    };
    let entry = entry.ok_or_else(|| {
        ApiError(Error::InvalidInput(
            "ссылка сброса недействительна или истекла".into(),
        ))
    })?;
    state.users.set_password(entry.user_id, Some(hash), false).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Resolve the authenticated user from an `Authorization: Bearer <token>` header.
fn bearer_user(state: &AppState, headers: &HeaderMap) -> Result<UserId, ApiError> {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(ApiError(Error::Unauthorized))?;
    state
        .auth
        .verify_token(token, now_ms())
        .map(|c| c.user)
        .map_err(|_| ApiError(Error::Unauthorized))
}

/// Set a new password for the authenticated session (forced change after an SMS temp password, or
/// a voluntary change). Authenticated by the `Authorization: Bearer <token>` header.
async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ChangeRequest>,
) -> Result<StatusCode, ApiError> {
    let user = bearer_user(&state, &headers)?;
    check_password_policy(req.password.trim())?;
    let hash = hash_password(req.password.trim())?;
    if !state.users.set_password(user, Some(hash), false).await {
        return Err(ApiError(Error::NotFound("user".into())));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The editable, cross-device profile (display name, status, avatar).
#[derive(Debug, Serialize, Deserialize, Default)]
struct ProfileDto {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    avatar: Option<String>,
}

/// `GET /v1/profile` — the authenticated user's editable profile (synced across their devices).
async fn get_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ProfileDto>, ApiError> {
    let user = bearer_user(&state, &headers)?;
    let u = state.users.get_user(user).await?;
    Ok(Json(ProfileDto {
        name: u.display_name,
        status: u.status,
        avatar: u.avatar,
    }))
}

/// `PUT /v1/profile` — replace the authenticated user's editable profile.
async fn put_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProfileDto>,
) -> Result<StatusCode, ApiError> {
    let user = bearer_user(&state, &headers)?;
    // Normalize empty strings to None so a cleared field round-trips as "unset".
    let norm = |s: Option<String>| s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    if !state
        .users
        .set_profile(user, norm(req.name), norm(req.status), req.avatar)
        .await
    {
        return Err(ApiError(Error::NotFound("user".into())));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Publish (or replace) a device's pre-key bundle.
async fn publish_prekeys(
    State(state): State<AppState>,
    Json(req): Json<PublishPrekeysRequest>,
) -> Result<StatusCode, ApiError> {
    let device = req.bundle.device_id;
    state.auth.publish_prekeys(device, req.bundle).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Fetch a device's pre-key bundle, consuming one one-time pre-key.
async fn fetch_prekeys(
    State(state): State<AppState>,
    Path(device): Path<DeviceId>,
) -> Result<Json<PreKeyBundle>, ApiError> {
    let bundle = state.auth.fetch_prekey_bundle(device).await?;
    Ok(Json(bundle))
}

/// Prekey directory: resolve a *user* to one of their devices' pre-key bundles (consuming a
/// one-time pre-key), so an initiator can run PQXDH without knowing the device id up front.
async fn fetch_user_prekey(
    State(state): State<AppState>,
    Path(user): Path<UserId>,
) -> Result<Json<PreKeyBundle>, ApiError> {
    let devices = state.users.list_devices(user).await?;
    let device = devices
        .first()
        .ok_or_else(|| Error::NotFound(format!("no device for user: {user}")))?
        .id;
    let bundle = state.auth.fetch_prekey_bundle(device).await?;
    Ok(Json(bundle))
}

/// A `503 Service Unavailable` response emitted while maintenance mode is engaged. There is
/// no `503` variant in [`mx_types::Error`], so this is built directly rather than via
/// [`ApiError`].
fn maintenance_rejection() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({ "error": "maintenance mode" })),
    )
        .into_response()
}

/// Ingest an opaque envelope for fan-out. Returns `202 Accepted` once queued, or
/// `503 Service Unavailable` while the maintenance kill-switch is engaged.
async fn ingest_message(
    State(state): State<AppState>,
    Json(WireEnvelope(envelope)): Json<WireEnvelope>,
) -> Result<StatusCode, Response> {
    if state.maintenance.load(Ordering::Relaxed) {
        return Err(maintenance_rejection());
    }
    let to = envelope.to.clone();
    state
        .messaging
        .ingest(envelope)
        .await
        .map_err(|e| ApiError(e).into_response())?;
    state.notify_recipients(&to).await;
    Ok(StatusCode::ACCEPTED)
}

/// Drain a device's queued envelopes in FIFO order (empty array if none pending).
async fn pull_messages(
    State(state): State<AppState>,
    Path(device): Path<DeviceId>,
) -> Result<Json<Vec<WireEnvelope>>, ApiError> {
    let pending = state.messaging.pull(device).await?;
    Ok(Json(pending.into_iter().map(WireEnvelope).collect()))
}

// ===========================================================================
// Admin API (gated by `x-admin-token` == env `MX_ADMIN_TOKEN`)
// ===========================================================================

/// Returns `Ok(())` if the request carries the correct admin token, else `401 Unauthorized`.
fn admin_guard(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let ok = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .map(|t| t == state.admin_token.as_str())
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(ApiError(Error::Unauthorized))
    }
}

/// Snapshot counts for the admin dashboard.
#[derive(Serialize)]
struct AdminOverview {
    users: usize,
    devices: usize,
    queued_messages: usize,
    maintenance: bool,
    /// Active (non-expired) email password-reset tokens awaiting use.
    pending_resets: usize,
}

/// One row of the admin user table.
#[derive(Serialize)]
struct AdminUserRow {
    user_id: UserId,
    username: String,
    email: Option<String>,
    phone: Option<String>,
    devices: usize,
    /// Whether the account is password-protected (the hash itself is never exposed).
    has_password: bool,
    /// Whether the account is on a temporary password and must set a new one.
    must_change: bool,
}

#[derive(Deserialize)]
struct BroadcastRequest {
    text: String,
}

#[derive(Serialize)]
struct BroadcastResponse {
    sent: usize,
}

#[derive(Deserialize)]
struct MaintenanceRequest {
    on: bool,
}

/// Build the current overview snapshot (shared by `GET /overview` and the maintenance toggle).
async fn build_overview(state: &AppState) -> AdminOverview {
    let (users, devices) = state.users.export().await;
    let now = now_ms();
    let pending_resets = state
        .resets
        .lock()
        .await
        .values()
        .filter(|e| e.expires_at >= now)
        .count();
    AdminOverview {
        users: users.len(),
        devices: devices.len(),
        queued_messages: state.queue.total_len().await,
        maintenance: state.maintenance.load(Ordering::Relaxed),
        pending_resets,
    }
}

/// `GET /v1/admin/overview` — counts + maintenance state.
async fn admin_overview(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminOverview>, ApiError> {
    admin_guard(&state, &headers)?;
    Ok(Json(build_overview(&state).await))
}

/// `GET /v1/admin/users` — every account with its identifiers and device count.
async fn admin_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<AdminUserRow>>, ApiError> {
    admin_guard(&state, &headers)?;
    let (users, devices) = state.users.export().await;
    let rows = users
        .into_iter()
        .map(|u| {
            let count = devices.iter().filter(|d| d.user_id == u.id).count();
            AdminUserRow {
                user_id: u.id,
                has_password: u.password_hash.is_some(),
                must_change: u.must_change_password,
                username: u.username,
                email: u.email,
                phone: u.phone,
                devices: count,
            }
        })
        .collect();
    Ok(Json(rows))
}

/// `POST /v1/admin/broadcast` — enqueue a cleartext announcement Control envelope to every
/// device of every user, waking any live sessions. Returns the number of device deliveries.
async fn admin_broadcast(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BroadcastRequest>,
) -> Result<Json<BroadcastResponse>, ApiError> {
    admin_guard(&state, &headers)?;
    let text = req.text.trim();
    if text.is_empty() {
        return Err(ApiError(Error::InvalidInput(
            "broadcast text must not be empty".into(),
        )));
    }
    // Cleartext announce payload (NOT E2E — this is an operator system message). The client
    // routes it through the existing `control` branch by `MessageKind::Control`.
    let body = serde_json::json!({ "t": "announce", "text": text }).to_string();
    let (users, _) = state.users.export().await;
    let mut sent = 0usize;
    for u in users {
        let env = Envelope::new(
            DeviceId::new(), // synthetic server sender
            Recipient::Direct(u.id),
            MessageKind::Control,
            Ciphertext(body.clone().into_bytes()),
            now_ms(),
        );
        let to = env.to.clone();
        // ingest fans out to every device of the user and enqueues; then wake live sessions.
        if let Ok(n) = state.messaging.ingest(env).await {
            sent += n;
            state.notify_recipients(&to).await;
        }
    }
    Ok(Json(BroadcastResponse { sent }))
}

/// `POST /v1/admin/users/:id/delete` — remove a user + its devices, prekeys, and queue.
async fn admin_delete_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<UserId>,
) -> Result<StatusCode, ApiError> {
    admin_guard(&state, &headers)?;
    state.delete_user(id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/admin/maintenance` — toggle the global ingest kill-switch; returns fresh overview.
async fn admin_maintenance(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<MaintenanceRequest>,
) -> Result<Json<AdminOverview>, ApiError> {
    admin_guard(&state, &headers)?;
    state.maintenance.store(req.on, Ordering::Relaxed);
    Ok(Json(build_overview(&state).await))
}

// ===========================================================================
// WebSocket gateway
// ===========================================================================

/// How long a device is considered online after a heartbeat / activity.
const ONLINE_TTL: Duration = Duration::from_secs(30);

/// Upgrade an HTTP request to a WebSocket and hand it to [`ws_session`].
async fn ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| ws_session(state, socket))
}

/// Outgoing half of a split [`WebSocket`].
type WsSink = SplitSink<WebSocket, Message>;

/// Drive one authenticated client connection.
///
/// Protocol:
/// 1. The first frame **must** be [`ClientMessage::Hello`] carrying a valid session token
///    (verified against [`AuthService`]), or the connection is closed with a
///    [`ServerMessage::Error`].
/// 2. On success the device is marked online and any queued envelopes are flushed.
/// 3. Thereafter the loop handles [`ClientMessage::Send`] (→ ingest + ack), and tracks
///    presence on activity. Payloads stay opaque throughout.
async fn ws_session(state: AppState, socket: WebSocket) {
    let (mut sender, mut receiver) = socket.split();

    // --- 1. Authenticate on the first frame. -------------------------------
    let device = match authenticate(&state, &mut receiver).await {
        Ok(device) => device,
        Err(message) => {
            // Best-effort error frame, then drop the connection.
            let _ = send_frame(&mut sender, ServerMessage::Error { message }).await;
            return;
        }
    };

    // Register for live push and mark online, then flush anything queued while away.
    let mut wake = state.hub.register(device).await;
    {
        let mut presence = state.presence.lock().await;
        presence.set_online(device, ONLINE_TTL);
    }
    if !state.deliver_pending(device, &mut sender).await {
        state.hub.unregister(device).await;
        return; // socket gone
    }

    // --- 2. Main loop: react to client frames AND live-push wake-ups. -------
    // `replaced` distinguishes "a newer session took over this device" (don't touch the
    // registry on exit) from a normal disconnect (deregister ourselves).
    let mut replaced = false;
    loop {
        tokio::select! {
            // Someone sent this device a message: drain and push it immediately.
            signal = wake.recv() => {
                match signal {
                    Some(()) => {
                        if !state.deliver_pending(device, &mut sender).await {
                            break;
                        }
                    }
                    // Channel closed: a newer session replaced us. Stop driving this socket.
                    None => { replaced = true; break; }
                }
            }

            // A frame arrived from the client.
            frame = receiver.next() => {
                let Some(frame) = frame else { break };
                let bytes = match frame {
                    Ok(Message::Binary(b)) => b,
                    Ok(Message::Text(t)) => t.into_bytes(),
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => continue,
                };

                let msg = match ClientMessage::from_bytes(&bytes) {
                    Ok(m) => m,
                    Err(e) => {
                        if !send_frame(&mut sender, ServerMessage::Error { message: e.to_string() }).await {
                            break;
                        }
                        continue;
                    }
                };

                match msg {
                    // A second Hello is a no-op (already authenticated); refresh presence.
                    ClientMessage::Hello { .. } => heartbeat(&state, device).await,

                    ClientMessage::Send(envelope) => {
                        // Maintenance kill-switch: refuse ingest globally while engaged.
                        if state.maintenance.load(Ordering::Relaxed) {
                            if !send_frame(&mut sender, ServerMessage::Error {
                                message: "maintenance mode: messaging temporarily disabled".into(),
                            }).await {
                                break;
                            }
                            continue;
                        }
                        let id = envelope.id;
                        let to = envelope.to.clone();
                        match state.messaging.ingest(envelope).await {
                            Ok(_) => {
                                state.notify_recipients(&to).await;
                                heartbeat(&state, device).await;
                                if !send_frame(&mut sender, ServerMessage::Ack(id)).await {
                                    break;
                                }
                            }
                            Err(e) => {
                                if !send_frame(&mut sender, ServerMessage::Error { message: e.to_string() }).await {
                                    break;
                                }
                            }
                        }
                    }

                    // Transport-level ack of a delivered Incoming; the drain already removed it.
                    ClientMessage::Ack(_) => {}

                    ClientMessage::Presence(_) | ClientMessage::Typing(_) => {
                        heartbeat(&state, device).await;
                    }
                }
            }
        }
    }

    // Deregister on disconnect unless a newer session already owns the slot. Online marker
    // lapses via TTL (no explicit offline event).
    if !replaced {
        state.hub.unregister(device).await;
    }
}

/// Refresh a device's online heartbeat.
async fn heartbeat(state: &AppState, device: DeviceId) {
    let mut presence = state.presence.lock().await;
    presence.set_online(device, ONLINE_TTL);
}

/// Read and validate the mandatory opening [`ClientMessage::Hello`] frame, verifying its
/// bearer token against [`AuthService`].
///
/// Returns the authenticated [`DeviceId`] on success, or a human-readable error string
/// describing why the handshake failed.
async fn authenticate(
    state: &AppState,
    receiver: &mut SplitStream<WebSocket>,
) -> Result<DeviceId, String> {
    let frame = receiver
        .next()
        .await
        .ok_or_else(|| "connection closed before hello".to_string())?
        .map_err(|e| format!("websocket error: {e}"))?;

    let bytes = match frame {
        Message::Binary(b) => b,
        Message::Text(t) => t.into_bytes(),
        _ => return Err("first frame must be a hello".to_string()),
    };

    match ClientMessage::from_bytes(&bytes).map_err(|e| e.to_string())? {
        ClientMessage::Hello { token } => {
            let claims = state
                .auth
                .verify_token(&token, now_ms())
                .map_err(|_| "invalid or expired token".to_string())?;
            Ok(claims.device)
        }
        _ => Err("first frame must be a hello".to_string()),
    }
}

/// Encode and send a [`ServerMessage`] as a binary WS frame; returns `false` if the socket
/// is gone (so the caller can break its loop).
async fn send_frame(sender: &mut WsSink, msg: ServerMessage) -> bool {
    match msg.to_bytes() {
        Ok(bytes) => sender.send(Message::Binary(bytes)).await.is_ok(),
        Err(_) => false,
    }
}

// ===========================================================================
// Router & main
// ===========================================================================

/// Assemble the application [`Router`] over a given [`AppState`].
///
/// Factored out so integration tests can drive it via `tower::ServiceExt::oneshot`
/// without binding a real socket.
fn app(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/v1/register", post(register))
        .route("/v1/login", post(login))
        .route("/v1/auth/forgot", post(forgot_password))
        .route("/v1/auth/reset", post(reset_password))
        .route("/v1/auth/change", post(change_password))
        .route("/v1/profile", get(get_profile).put(put_profile))
        .route("/v1/prekeys", post(publish_prekeys))
        .route("/v1/prekeys/:device", get(fetch_prekeys))
        .route("/v1/users/:user/prekey", get(fetch_user_prekey))
        .route("/v1/messages", post(ingest_message))
        .route("/v1/messages/:device", get(pull_messages))
        .route("/v1/admin/overview", get(admin_overview))
        .route("/v1/admin/users", get(admin_users))
        .route("/v1/admin/broadcast", post(admin_broadcast))
        .route("/v1/admin/users/:id/delete", post(admin_delete_user))
        .route("/v1/admin/maintenance", post(admin_maintenance))
        .route("/v1/ws", get(ws_handler));

    // Serve the built web frontend from the same origin (no CORS) when present.
    // MX_WEB_DIR defaults to "web/dist"; if the directory is absent (typical local
    // API-only dev), the fallback is skipped and behavior is unchanged. SPA routing:
    // unknown paths fall back to index.html so client-side routes resolve. The
    // explicit routes above always take priority over this fallback_service.
    let web_dir = std::path::PathBuf::from(
        std::env::var("MX_WEB_DIR").unwrap_or_else(|_| "web/dist".to_string()),
    );
    if web_dir.is_dir() {
        let index = web_dir.join("index.html");
        let serve = ServeDir::new(&web_dir).not_found_service(ServeFile::new(index));
        router = router.fallback_service(serve);
        tracing::info!(dir = ?web_dir, "serving static frontend (SPA fallback)");
    } else {
        tracing::info!(dir = ?web_dir, "no static frontend dir; API-only mode");
    }

    // Force revalidation of every response (notably index.html) so a redeploy's new asset hashes
    // are picked up on the next load instead of being shadowed by a stale browser cache. The
    // hashed JS/CSS still revalidate cheaply via ETag/Last-Modified (304 when unchanged).
    router
        .layer(SetResponseHeaderLayer::overriding(
            CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        ))
        .with_state(state)
}

// ===========================================================================
// Durable snapshot persistence (Postgres or local file)
// ===========================================================================

/// Where the periodic state snapshot is persisted so a restart/redeploy is non-destructive.
///
/// The in-memory stores stay the runtime source of truth; this layer just durably stores and
/// restores a full [`Snapshot`]. Postgres is used when `DATABASE_URL` is set (survives restarts on
/// any host, including Render's free tier where the local disk is ephemeral); otherwise a local
/// JSON file (good for dev). The snapshot is a single JSONB blob — durable and admin-visible —
/// which can be migrated to normalized tables later without changing callers.
enum Persistence {
    File(PathBuf),
    Postgres(sqlx::PgPool),
}

impl Persistence {
    /// Pick the backend: Postgres if `DATABASE_URL` is set and reachable, else a JSON file at
    /// `MX_DATA_FILE` (default `data/state.json`).
    async fn init() -> Self {
        if let Ok(url) = std::env::var("DATABASE_URL") {
            match Self::connect_pg(&url).await {
                Ok(pool) => {
                    tracing::info!("durable snapshot: Postgres (DATABASE_URL)");
                    return Persistence::Postgres(pool);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Postgres connect failed; falling back to file")
                }
            }
        }
        let path = PathBuf::from(
            std::env::var("MX_DATA_FILE").unwrap_or_else(|_| "data/state.json".to_string()),
        );
        tracing::info!(?path, "durable snapshot: local file");
        Persistence::File(path)
    }

    /// Open a connection pool and ensure the single-row snapshot table exists.
    async fn connect_pg(url: &str) -> Result<sqlx::PgPool, sqlx::Error> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS app_snapshot (\
                id INT PRIMARY KEY, \
                data JSONB NOT NULL, \
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        )
        .execute(&pool)
        .await?;
        Ok(pool)
    }

    /// Load the persisted snapshot, if any.
    async fn load(&self) -> Option<mx_storage::persist::Snapshot> {
        match self {
            Persistence::File(path) => match mx_storage::persist::Snapshot::load(path) {
                Ok(snap) => snap,
                Err(e) => {
                    tracing::warn!(error = %e, "snapshot file read failed; starting empty");
                    None
                }
            },
            Persistence::Postgres(pool) => {
                let row: Result<Option<(serde_json::Value,)>, _> =
                    sqlx::query_as("SELECT data FROM app_snapshot WHERE id = 1")
                        .fetch_optional(pool)
                        .await;
                match row {
                    Ok(Some((v,))) => serde_json::from_value(v).ok(),
                    Ok(None) => None,
                    Err(e) => {
                        tracing::warn!(error = %e, "snapshot db read failed; starting empty");
                        None
                    }
                }
            }
        }
    }

    /// Persist the given snapshot (best-effort; logs on failure).
    async fn save(&self, snap: &mx_storage::persist::Snapshot) {
        match self {
            Persistence::File(path) => {
                if let Err(e) = snap.save(path) {
                    tracing::warn!(error = %e, "snapshot file write failed");
                }
            }
            Persistence::Postgres(pool) => match serde_json::to_value(snap) {
                Ok(v) => {
                    let q = sqlx::query(
                        "INSERT INTO app_snapshot (id, data) VALUES (1, $1) \
                         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()",
                    )
                    .bind(v);
                    if let Err(e) = q.execute(pool).await {
                        tracing::warn!(error = %e, "snapshot db write failed");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "snapshot serialize failed"),
            },
        }
    }
}

#[tokio::main]
async fn main() {
    // Load a local .env if present (optional; ignored if missing).
    let _ = dotenvy::dotenv();

    // Structured logging; honor RUST_LOG, defaulting to info for our crates.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,mx_server=debug".into()),
        )
        .init();

    let bind_addr = std::env::var("MX_BIND_ADDR").unwrap_or_else(|_| {
        // Render (and most PaaS) inject PORT; bind all interfaces so the platform
        // can route to us. Locally, with neither var set, keep the dev default.
        match std::env::var("PORT") {
            Ok(port) => format!("0.0.0.0:{port}"),
            Err(_) => "127.0.0.1:9990".to_string(),
        }
    });
    let token_secret = std::env::var("MX_TOKEN_SECRET").unwrap_or_else(|_| {
        tracing::warn!(
            "MX_TOKEN_SECRET not set; using a development default — DO NOT use in production"
        );
        "dev-only-insecure-token-secret-change-me".to_string()
    });

    let state = AppState::new(token_secret);

    // Durable state: load a snapshot on boot and persist periodically so a restart/redeploy does
    // not wipe accounts (clients hold long-lived tokens). Backend = Postgres (DATABASE_URL) or a
    // local JSON file (MX_DATA_FILE).
    let persistence = Arc::new(Persistence::init().await);
    match persistence.load().await {
        Some(snap) => state.apply_snapshot(snap).await,
        None => tracing::info!("no snapshot yet; starting empty"),
    }
    {
        let saver = state.clone();
        let store = persistence.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3));
            loop {
                tick.tick().await;
                store.save(&saver.capture_snapshot().await).await;
            }
        });
    }

    let shutdown_state = state.clone();
    let shutdown_store = persistence.clone();
    let router = app(state);

    let addr: SocketAddr = bind_addr
        .parse()
        .unwrap_or_else(|e| panic!("invalid MX_BIND_ADDR `{bind_addr}`: {e}"));

    tracing::info!(%addr, "mx-server listening");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server error");

    // Final flush so a clean shutdown loses nothing since the last periodic save.
    shutdown_store
        .save(&shutdown_state.capture_snapshot().await)
        .await;
    tracing::info!("state snapshot saved on shutdown");
}

/// Resolve when a Ctrl-C (SIGINT) is received, triggering graceful shutdown.
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use mx_types::crypto_material::KeyAlgo;
    use mx_types::{Ciphertext, MessageKind, Recipient};
    use tower::ServiceExt; // for `oneshot`

    fn test_state() -> AppState {
        AppState::new(b"test-secret-0123456789-abcdef".to_vec())
    }

    fn test_pubkey() -> PublicKey {
        PublicKey {
            algo: KeyAlgo::X25519,
            bytes: vec![9u8; 32],
        }
    }

    /// Decode a JSON response body into the given type.
    async fn json_body<T: serde::de::DeserializeOwned>(resp: Response) -> T {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = app(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"ok");
    }

    #[tokio::test]
    async fn register_ingest_pull_happy_path() {
        let state = test_state();

        // --- register a user + device -------------------------------------
        let reg_body = serde_json::to_vec(&serde_json::json!({
            "username": "alice",
            "identity_key": test_pubkey(),
        }))
        .unwrap();

        let resp = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/register")
                    .header("content-type", "application/json")
                    .body(Body::from(reg_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let reg: RegisterResponse = json_body(resp).await;
        assert!(!reg.token.is_empty(), "a session token should be issued");

        // --- ingest a direct message to that user -------------------------
        let envelope = Envelope::new(
            DeviceId::new(),
            Recipient::Direct(reg.user_id),
            MessageKind::Chat,
            Ciphertext(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            0,
        );
        let env_id = envelope.id;
        let env_body = serde_json::to_vec(&WireEnvelope(envelope)).unwrap();

        let resp = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(env_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // --- pull the recipient device's queue ----------------------------
        let resp = app(state.clone())
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/messages/{}", reg.device_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let pulled: Vec<WireEnvelope> = json_body(resp).await;
        assert_eq!(pulled.len(), 1, "the queued envelope should be delivered");
        assert_eq!(pulled[0].0.id, env_id);
        assert_eq!(pulled[0].0.ciphertext.0, vec![0xDE, 0xAD, 0xBE, 0xEF]);

        // --- draining leaves the queue empty ------------------------------
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/messages/{}", reg.device_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let empty: Vec<WireEnvelope> = json_body(resp).await;
        assert!(empty.is_empty(), "second pull drains nothing");
    }

    #[tokio::test]
    async fn fetch_unknown_prekeys_is_404() {
        let resp = app(test_state())
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/prekeys/{}", DeviceId::new()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Register a user and return the parsed response.
    async fn register_user(state: &AppState, username: &str) -> RegisterResponse {
        let reg_body = serde_json::to_vec(&serde_json::json!({
            "username": username,
            "identity_key": test_pubkey(),
        }))
        .unwrap();
        let resp = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/register")
                    .header("content-type", "application/json")
                    .body(Body::from(reg_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        json_body(resp).await
    }

    #[tokio::test]
    async fn admin_overview_requires_token() {
        let state = test_state();
        // No token => 401.
        let resp = app(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/overview")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Correct token (default `mx-dev-admin`) => 200.
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/overview")
                    .header("x-admin-token", "mx-dev-admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn admin_broadcast_enqueues_to_user_device() {
        let state = test_state();
        let reg = register_user(&state, "alice").await;

        let body = serde_json::to_vec(&serde_json::json!({ "text": "hello all" })).unwrap();
        let resp = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/broadcast")
                    .header("content-type", "application/json")
                    .header("x-admin-token", "mx-dev-admin")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let out: serde_json::Value = json_body(resp).await;
        assert_eq!(out["sent"], 1, "one device should receive the announcement");

        // The announcement lands in the device queue as a Control envelope.
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/messages/{}", reg.device_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let pulled: Vec<WireEnvelope> = json_body(resp).await;
        assert_eq!(pulled.len(), 1);
        let txt = String::from_utf8(pulled[0].0.ciphertext.0.clone()).unwrap();
        assert!(txt.contains("\"announce\"") && txt.contains("hello all"));
    }

    #[tokio::test]
    async fn maintenance_blocks_http_ingest_with_503() {
        let state = test_state();
        let reg = register_user(&state, "bob").await;

        // Engage maintenance.
        let body = serde_json::to_vec(&serde_json::json!({ "on": true })).unwrap();
        let resp = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/maintenance")
                    .header("content-type", "application/json")
                    .header("x-admin-token", "mx-dev-admin")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Ingest is now rejected with 503.
        let envelope = Envelope::new(
            DeviceId::new(),
            Recipient::Direct(reg.user_id),
            MessageKind::Chat,
            Ciphertext(vec![1, 2, 3]),
            0,
        );
        let env_body = serde_json::to_vec(&WireEnvelope(envelope)).unwrap();
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("content-type", "application/json")
                    .body(Body::from(env_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn admin_delete_user_removes_account() {
        let state = test_state();
        let reg = register_user(&state, "carol").await;

        let resp = app(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/admin/users/{}/delete", reg.user_id))
                    .header("x-admin-token", "mx-dev-admin")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // The user is gone: prekey directory lookup now 404s.
        let resp = app(state)
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/users/{}/prekey", reg.user_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn issued_token_round_trips_through_auth() {
        // Sanity: a token minted by register verifies (this is what the WS Hello checks).
        let state = test_state();
        let uid = UserId::new();
        let did = DeviceId::new();
        let token = state.auth.issue_token(uid, did, now_ms());
        let claims = state.auth.verify_token(&token, now_ms()).unwrap();
        assert_eq!(claims.user, uid);
        assert_eq!(claims.device, did);
    }
}
