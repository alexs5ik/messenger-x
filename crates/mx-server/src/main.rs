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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use futures_util::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream, StreamExt},
};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::sync::Mutex;

use mx_ai::AiOrchestrator;
use mx_auth::AuthService;
use mx_messaging::MessagingService;
use mx_presence::PresenceService;
use mx_storage::{
    InMemoryGroupStore, InMemoryMessageQueue, InMemoryPreKeyStore, InMemoryUserStore, PreKeyStore,
    UserStore,
};
use mx_transport::{ClientMessage, ServerMessage};
use mx_types::{DeviceId, Envelope, Error, PreKeyBundle, PublicKey, UserId};

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
        // clone the handles (cheap Arc bumps) so AppState can also reach them for snapshots.
        let messaging = Arc::new(MessagingService::new(
            users.clone(),
            groups.clone(),
            queue,
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
        }
    }

    /// Load durable state from a snapshot file (if present) into the stores.
    async fn load_snapshot(&self, path: &std::path::Path) {
        match mx_storage::persist::Snapshot::load(path) {
            Ok(Some(snap)) => {
                let users = snap.users.len();
                snap.apply(&self.users, &self.prekeys, &self.groups).await;
                tracing::info!(users, ?path, "restored state snapshot");
            }
            Ok(None) => tracing::info!(?path, "no snapshot yet; starting empty"),
            Err(e) => tracing::warn!(error = %e, ?path, "failed to read snapshot; starting empty"),
        }
    }

    /// Write the current durable state to the snapshot file.
    async fn save_snapshot(&self, path: &std::path::Path) {
        let snap =
            mx_storage::persist::Snapshot::capture(&self.users, &self.prekeys, &self.groups).await;
        if let Err(e) = snap.save(path) {
            tracing::warn!(error = %e, ?path, "failed to write snapshot");
        }
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
// Request / response DTOs
// ===========================================================================

/// `POST /v1/register` request: a username plus the new device's identity public key.
#[derive(Debug, Deserialize)]
struct RegisterRequest {
    /// Human-facing handle for the new account.
    username: String,
    /// Long-term identity public key for the account's first device.
    identity_key: PublicKey,
}

/// `POST /v1/register` response: the freshly minted ids and a bearer session token.
///
/// `Deserialize` is derived so tests (and any in-process client) can parse it back.
#[derive(Debug, Serialize, Deserialize)]
struct RegisterResponse {
    /// The new account id.
    user_id: UserId,
    /// The new device id (its first installation).
    device_id: DeviceId,
    /// Bearer token authenticating `(user_id, device_id)`; used for the WS `Hello`.
    token: String,
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

/// Create a new account and its first device, then issue a session token.
async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), ApiError> {
    let user_id = state.auth.register_user(req.username).await?;
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
        }),
    ))
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

/// Ingest an opaque envelope for fan-out. Returns `202 Accepted` once queued.
async fn ingest_message(
    State(state): State<AppState>,
    Json(WireEnvelope(envelope)): Json<WireEnvelope>,
) -> Result<StatusCode, ApiError> {
    let to = envelope.to.clone();
    state.messaging.ingest(envelope).await?;
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
    Router::new()
        .route("/health", get(health))
        .route("/v1/register", post(register))
        .route("/v1/prekeys", post(publish_prekeys))
        .route("/v1/prekeys/:device", get(fetch_prekeys))
        .route("/v1/messages", post(ingest_message))
        .route("/v1/messages/:device", get(pull_messages))
        .route("/v1/ws", get(ws_handler))
        .with_state(state)
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

    let bind_addr =
        std::env::var("MX_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:9990".to_string());
    let token_secret = std::env::var("MX_TOKEN_SECRET").unwrap_or_else(|_| {
        tracing::warn!(
            "MX_TOKEN_SECRET not set; using a development default — DO NOT use in production"
        );
        "dev-only-insecure-token-secret-change-me".to_string()
    });

    let state = AppState::new(token_secret);

    // Durable state: load a snapshot on boot and persist periodically so a restart does not
    // wipe accounts (clients hold long-lived tokens). Path is overridable via MX_DATA_FILE.
    let snapshot_path = std::path::PathBuf::from(
        std::env::var("MX_DATA_FILE").unwrap_or_else(|_| "data/state.json".to_string()),
    );
    state.load_snapshot(&snapshot_path).await;
    {
        let saver = state.clone();
        let path = snapshot_path.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3));
            loop {
                tick.tick().await;
                saver.save_snapshot(&path).await;
            }
        });
    }

    let shutdown_state = state.clone();
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
    shutdown_state.save_snapshot(&snapshot_path).await;
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
