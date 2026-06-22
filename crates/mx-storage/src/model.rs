//! Storage-layer domain models.
//!
//! These are persistence-facing records that are *not* part of the wire contract in
//! `mx-types` (which deliberately stays dependency-light and transport-shaped). A [`User`]
//! and [`Device`] describe accounts and their installations as the backend stores them.
//! Crucially, none of these records ever contain message plaintext — only identities and
//! public key material — consistent with the "server stores ciphertext only" principle.

use serde::{Deserialize, Serialize};

use mx_types::{DeviceId, PublicKey, UserId};

/// A registered human account as the backend stores it.
///
/// The server keeps no secret about the user beyond routing identity; all message content
/// is end-to-end encrypted and opaque to it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    /// Stable account identifier.
    pub id: UserId,
    /// Human-facing handle (e.g. `@alice`). Unique by convention; uniqueness is enforced
    /// by the caller / a real DB constraint, not by the in-memory dev store.
    pub username: String,
    /// Optional email identifier (unique across accounts when present).
    #[serde(default)]
    pub email: Option<String>,
    /// Optional phone identifier (unique across accounts when present).
    #[serde(default)]
    pub phone: Option<String>,
    /// Argon2 PHC password hash, when the account is password-protected. `None` for the
    /// passwordless demo ("name") path. The cleartext password is never stored.
    #[serde(default)]
    pub password_hash: Option<String>,
    /// Set when the current password is a server-generated temporary (e.g. issued by an SMS
    /// password reset): the client must force the user to choose a new password on next login.
    #[serde(default)]
    pub must_change_password: bool,
}

impl User {
    /// Construct a user with a fresh [`UserId`].
    pub fn new(username: impl Into<String>) -> Self {
        Self {
            id: UserId::new(),
            username: username.into(),
            email: None,
            phone: None,
            password_hash: None,
            must_change_password: false,
        }
    }

    /// Construct a user with an explicit id (e.g. when re-hydrating from a real DB row).
    pub fn with_id(id: UserId, username: impl Into<String>) -> Self {
        Self {
            id,
            username: username.into(),
            email: None,
            phone: None,
            password_hash: None,
            must_change_password: false,
        }
    }

    /// Attach optional contact identifiers (builder-style).
    pub fn with_contacts(mut self, email: Option<String>, phone: Option<String>) -> Self {
        self.email = email;
        self.phone = phone;
        self
    }
}

/// A single device/installation belonging to a [`User`].
///
/// Crypto sessions are per-device (Signal-style multi-device fan-out), so each device
/// carries its own long-term identity public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Stable device identifier.
    pub id: DeviceId,
    /// Owning account.
    pub user_id: UserId,
    /// Long-term identity public key for this device.
    pub identity_key: PublicKey,
}

impl Device {
    /// Construct a device with a fresh [`DeviceId`].
    pub fn new(user_id: UserId, identity_key: PublicKey) -> Self {
        Self {
            id: DeviceId::new(),
            user_id,
            identity_key,
        }
    }

    /// Construct a device with an explicit id.
    pub fn with_id(id: DeviceId, user_id: UserId, identity_key: PublicKey) -> Self {
        Self {
            id,
            user_id,
            identity_key,
        }
    }
}
