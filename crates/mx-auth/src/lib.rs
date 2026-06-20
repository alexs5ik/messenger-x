//! # mx-auth — identity & authentication for Messenger X
//!
//! This crate sits on top of the [`mx-storage`](mx_storage) trait abstractions and the
//! [`mx-crypto`](mx_crypto) primitives. It owns the *control plane* of identity:
//!
//! - **Account & device registration** ([`AuthService::register_user`],
//!   [`AuthService::register_device`]).
//! - **Pre-key publication & fetch** ([`AuthService::publish_prekeys`],
//!   [`AuthService::fetch_prekey_bundle`]) — the asynchronous-session bootstrap surface.
//!   A fetch consumes a one-time pre-key via the underlying [`PreKeyStore`], so two peers
//!   never receive the same one-time key.
//! - **Session tokens** ([`AuthService::issue_token`], [`AuthService::verify_token`]) —
//!   stateless bearer tokens authenticated with **HMAC-SHA256** over a server secret. The
//!   token is `base64(payload || mac)`; any tampering invalidates the MAC and the token is
//!   rejected with [`mx_types::Error::Unauthorized`].
//!
//! ## Server stores ciphertext only
//!
//! Consistent with the project principle, nothing here ever touches message plaintext.
//! Pre-key bundles carry only *public* key material, and tokens carry only routing
//! identity (user/device ids + an expiry), never secrets derivable into message keys.
//!
//! ## Token format & security notes
//!
//! A token's payload is the UTF-8 string `v1.<user_uuid>.<device_uuid>.<expiry_ms>`. The
//! MAC is `HMAC-SHA256(secret, payload)`. Verification recomputes the MAC and compares it
//! in **constant time** (the `hmac` crate's `verify_slice`), then checks expiry. The
//! server secret never leaves the process; rotating it invalidates all outstanding tokens.

use std::sync::Arc;

use base64::Engine as _;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use mx_types::{
    DeviceId, Error, PreKeyBundle, PublicKey, Result, TimestampMs, UserId,
};
use mx_storage::{model::Device, model::User, PreKeyStore, UserStore};

type HmacSha256 = Hmac<Sha256>;

/// Token format/version prefix. Bumping this invalidates older tokens.
const TOKEN_VERSION: &str = "v1";

/// Default token lifetime: 24 hours, expressed in milliseconds.
pub const DEFAULT_TOKEN_TTL_MS: TimestampMs = 24 * 60 * 60 * 1000;

/// The authenticated identity carried by a verified session token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenClaims {
    /// The account the token authenticates.
    pub user: UserId,
    /// The specific device/installation the token was issued to.
    pub device: DeviceId,
    /// Absolute expiry, milliseconds since the Unix epoch.
    pub expires_at: TimestampMs,
}

/// Identity & authentication service.
///
/// Holds shared handles to the storage backends (as trait objects so any backend —
/// in-memory for tests, Postgres/Redis in production — can be injected) and the server
/// secret used to authenticate session tokens.
///
/// Cheap to [`Clone`] (it only clones [`Arc`]s), so it can be shared across request
/// handlers.
#[derive(Clone)]
pub struct AuthService {
    users: Arc<dyn UserStore>,
    prekeys: Arc<dyn PreKeyStore>,
    /// Server secret keying the token HMAC. Treated as sensitive; never serialized.
    token_secret: Arc<Vec<u8>>,
    /// Lifetime applied to freshly issued tokens.
    token_ttl_ms: TimestampMs,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Deliberately omit the token secret from any debug rendering.
        f.debug_struct("AuthService")
            .field("token_ttl_ms", &self.token_ttl_ms)
            .finish_non_exhaustive()
    }
}

impl AuthService {
    /// Construct a service from storage handles and a server secret.
    ///
    /// `token_secret` keys the HMAC used for session tokens; it must be kept private and be
    /// of sufficient entropy (≥32 bytes recommended). Uses [`DEFAULT_TOKEN_TTL_MS`] for
    /// token lifetimes — use [`AuthService::with_token_ttl`] to override.
    pub fn new(
        users: Arc<dyn UserStore>,
        prekeys: Arc<dyn PreKeyStore>,
        token_secret: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            users,
            prekeys,
            token_secret: Arc::new(token_secret.into()),
            token_ttl_ms: DEFAULT_TOKEN_TTL_MS,
        }
    }

    /// Override the lifetime applied to subsequently issued tokens (builder-style).
    pub fn with_token_ttl(mut self, ttl_ms: TimestampMs) -> Self {
        self.token_ttl_ms = ttl_ms;
        self
    }

    // ---------------------------------------------------------------------
    // Registration
    // ---------------------------------------------------------------------

    /// Register a new account with the given username and return its fresh [`UserId`].
    ///
    /// Username uniqueness is enforced by the underlying [`UserStore`]; a clash surfaces as
    /// [`mx_types::Error::InvalidInput`].
    pub async fn register_user(&self, username: impl Into<String>) -> Result<UserId> {
        let username = username.into();
        if username.trim().is_empty() {
            return Err(Error::InvalidInput("username must not be empty".into()));
        }
        let user = User::new(username);
        let id = user.id;
        self.users.create_user(user).await?;
        Ok(id)
    }

    /// Register a new device for an existing user and return its fresh [`DeviceId`].
    ///
    /// `identity_key` is the device's long-term identity public key (e.g. from
    /// [`mx_crypto::IdentityKeyPair`]). [`mx_types::Error::NotFound`] if the owning user
    /// does not exist.
    pub async fn register_device(
        &self,
        user: UserId,
        identity_key: PublicKey,
    ) -> Result<DeviceId> {
        let device = Device::new(user, identity_key);
        let id = device.id;
        self.users.register_device(device).await?;
        Ok(id)
    }

    // ---------------------------------------------------------------------
    // Pre-keys
    // ---------------------------------------------------------------------

    /// Publish (or replace) a device's [`PreKeyBundle`] so peers can start asynchronous
    /// sessions against it.
    ///
    /// The `device` argument must match `bundle.device_id`; a mismatch is rejected with
    /// [`mx_types::Error::InvalidInput`] to prevent a device from publishing under another
    /// device's identity.
    pub async fn publish_prekeys(
        &self,
        device: DeviceId,
        bundle: PreKeyBundle,
    ) -> Result<()> {
        if bundle.device_id != device {
            return Err(Error::InvalidInput(format!(
                "bundle device_id {} does not match target device {}",
                bundle.device_id, device
            )));
        }
        self.prekeys.publish_bundle(bundle).await
    }

    /// Fetch a device's pre-key bundle for session establishment, **consuming one one-time
    /// pre-key**.
    ///
    /// Subsequent fetches will not hand out the same one-time key (it is `None` once
    /// exhausted). [`mx_types::Error::NotFound`] if the device never published a bundle.
    pub async fn fetch_prekey_bundle(&self, device: DeviceId) -> Result<PreKeyBundle> {
        self.prekeys.fetch_and_consume(device).await
    }

    // ---------------------------------------------------------------------
    // Session tokens (HMAC-SHA256)
    // ---------------------------------------------------------------------

    /// Issue a bearer session token authenticating `user`/`device`.
    ///
    /// The token expires `token_ttl_ms` (default [`DEFAULT_TOKEN_TTL_MS`]) after `now_ms`.
    /// Time is injected so the function is deterministic and testable; callers pass the
    /// current wall-clock in milliseconds since the Unix epoch.
    pub fn issue_token(
        &self,
        user: UserId,
        device: DeviceId,
        now_ms: TimestampMs,
    ) -> String {
        let expires_at = now_ms.saturating_add(self.token_ttl_ms);
        let payload = encode_payload(user, device, expires_at);
        let mac = self.mac(payload.as_bytes());

        // Token bytes = payload-utf8 || mac, then base64 (URL-safe, no padding) the whole.
        let mut raw = Vec::with_capacity(payload.len() + mac.len());
        raw.extend_from_slice(payload.as_bytes());
        raw.extend_from_slice(&mac);
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    }

    /// Verify a bearer token and return its [`TokenClaims`].
    ///
    /// Returns [`mx_types::Error::Unauthorized`] for any token that is malformed, has an
    /// invalid MAC (tampered / forged / wrong secret), or has expired relative to `now_ms`.
    /// The MAC check is constant-time.
    pub fn verify_token(&self, token: &str, now_ms: TimestampMs) -> Result<TokenClaims> {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .map_err(|_| Error::Unauthorized)?;

        // The MAC is the trailing 32 bytes (HMAC-SHA256 output size); the rest is payload.
        const MAC_LEN: usize = 32;
        if raw.len() <= MAC_LEN {
            return Err(Error::Unauthorized);
        }
        let (payload_bytes, mac_bytes) = raw.split_at(raw.len() - MAC_LEN);

        // Constant-time MAC verification.
        let mut hmac = HmacSha256::new_from_slice(&self.token_secret)
            .expect("HMAC accepts keys of any length");
        hmac.update(payload_bytes);
        hmac.verify_slice(mac_bytes)
            .map_err(|_| Error::Unauthorized)?;

        // MAC is valid; the payload is authentic so parsing is now trusted.
        let payload = std::str::from_utf8(payload_bytes).map_err(|_| Error::Unauthorized)?;
        let claims = decode_payload(payload).ok_or(Error::Unauthorized)?;

        if now_ms >= claims.expires_at {
            return Err(Error::Unauthorized);
        }
        Ok(claims)
    }

    /// Compute the token HMAC over `data` with the server secret.
    fn mac(&self, data: &[u8]) -> Vec<u8> {
        let mut hmac = HmacSha256::new_from_slice(&self.token_secret)
            .expect("HMAC accepts keys of any length");
        hmac.update(data);
        hmac.finalize().into_bytes().to_vec()
    }
}

/// Encode a token payload as `v1.<user>.<device>.<expiry_ms>`.
fn encode_payload(user: UserId, device: DeviceId, expires_at: TimestampMs) -> String {
    format!("{TOKEN_VERSION}.{user}.{device}.{expires_at}")
}

/// Parse a token payload back into [`TokenClaims`], or `None` if it is malformed.
fn decode_payload(payload: &str) -> Option<TokenClaims> {
    let mut parts = payload.split('.');
    let version = parts.next()?;
    if version != TOKEN_VERSION {
        return None;
    }
    let user = parts.next()?.parse::<uuid::Uuid>().ok()?;
    let device = parts.next()?.parse::<uuid::Uuid>().ok()?;
    let expires_at = parts.next()?.parse::<TimestampMs>().ok()?;
    // Reject trailing garbage so the format is unambiguous.
    if parts.next().is_some() {
        return None;
    }
    Some(TokenClaims {
        user: UserId::from(user),
        device: DeviceId::from(device),
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_storage::{InMemoryPreKeyStore, InMemoryUserStore};
    use mx_types::crypto_material::{KeyAlgo, SigAlgo};
    use mx_types::{Signature, SignedPreKey};

    fn pubkey(tag: u8) -> PublicKey {
        PublicKey {
            algo: KeyAlgo::X25519,
            bytes: vec![tag; 32],
        }
    }

    fn signed_prekey(tag: u8) -> SignedPreKey {
        SignedPreKey {
            key: pubkey(tag),
            signature: Signature {
                algo: SigAlgo::Ed25519,
                bytes: vec![tag; 64],
            },
        }
    }

    fn bundle_for(device: DeviceId) -> PreKeyBundle {
        PreKeyBundle {
            device_id: device,
            identity_key: pubkey(1),
            signed_prekey: signed_prekey(2),
            one_time_prekey: Some(pubkey(3)),
            pq_kem_prekey: signed_prekey(4),
        }
    }

    fn service() -> AuthService {
        AuthService::new(
            Arc::new(InMemoryUserStore::new()),
            Arc::new(InMemoryPreKeyStore::new()),
            b"super-secret-server-key-0123456789".to_vec(),
        )
    }

    #[tokio::test]
    async fn register_publish_fetch_consumes_one_time_prekey() {
        let svc = service();

        let user = svc.register_user("alice").await.unwrap();
        let device = svc.register_device(user, pubkey(10)).await.unwrap();

        svc.publish_prekeys(device, bundle_for(device)).await.unwrap();

        // First fetch hands out the one-time prekey...
        let first = svc.fetch_prekey_bundle(device).await.unwrap();
        assert!(first.one_time_prekey.is_some());

        // ...and a second fetch finds it consumed.
        let second = svc.fetch_prekey_bundle(device).await.unwrap();
        assert!(second.one_time_prekey.is_none());
    }

    #[tokio::test]
    async fn publish_rejects_device_mismatch() {
        let svc = service();
        let device = DeviceId::new();
        let other = DeviceId::new();
        // Bundle is for `other`, but we publish under `device` => rejected.
        let err = svc
            .publish_prekeys(device, bundle_for(other))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[tokio::test]
    async fn register_user_rejects_empty_username() {
        let svc = service();
        assert!(matches!(
            svc.register_user("   ").await,
            Err(Error::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn register_device_for_unknown_user_fails() {
        let svc = service();
        let err = svc
            .register_device(UserId::new(), pubkey(7))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
    }

    #[test]
    fn issue_then_verify_round_trips() {
        let svc = service();
        let user = UserId::new();
        let device = DeviceId::new();
        let now = 1_000_000;

        let token = svc.issue_token(user, device, now);
        let claims = svc.verify_token(&token, now).unwrap();

        assert_eq!(claims.user, user);
        assert_eq!(claims.device, device);
        assert_eq!(claims.expires_at, now + DEFAULT_TOKEN_TTL_MS);
    }

    #[test]
    fn tampered_token_is_rejected() {
        let svc = service();
        let token = svc.issue_token(UserId::new(), DeviceId::new(), 0);

        // Flip a character in the middle of the base64 to corrupt payload-or-mac.
        let mut bytes = token.into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] = if bytes[mid] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).unwrap();

        assert!(matches!(
            svc.verify_token(&tampered, 0),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn token_from_a_different_secret_is_rejected() {
        let issuer = service();
        let attacker = AuthService::new(
            Arc::new(InMemoryUserStore::new()),
            Arc::new(InMemoryPreKeyStore::new()),
            b"a-completely-different-secret-value".to_vec(),
        );
        let token = issuer.issue_token(UserId::new(), DeviceId::new(), 0);
        assert!(matches!(
            attacker.verify_token(&token, 0),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn expired_token_is_rejected() {
        let svc = service().with_token_ttl(1000);
        let token = svc.issue_token(UserId::new(), DeviceId::new(), 0);

        // Still valid just before expiry.
        assert!(svc.verify_token(&token, 999).is_ok());
        // Rejected at/after expiry.
        assert!(matches!(
            svc.verify_token(&token, 1000),
            Err(Error::Unauthorized)
        ));
    }

    #[test]
    fn garbage_token_is_rejected() {
        let svc = service();
        assert!(matches!(
            svc.verify_token("not base64 !!!", 0),
            Err(Error::Unauthorized)
        ));
        assert!(matches!(svc.verify_token("", 0), Err(Error::Unauthorized)));
    }
}
