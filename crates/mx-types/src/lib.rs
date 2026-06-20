//! # mx-types — shared domain contract for Messenger X
//!
//! Dependency-light types every other crate builds against. Cryptographic material is
//! represented as typed byte wrappers ([`PublicKey`], [`Ciphertext`], etc.) so that
//! `mx-crypto` can implement the real primitives without this crate depending on any
//! crypto library. The server is designed to store and route **ciphertext only** — see
//! the [`Envelope`] type, whose payload is opaque to the backend.

use thiserror::Error;
use uuid::Uuid;

pub mod ids;
pub mod crypto_material;
pub mod message;
pub mod prekey;

pub use crypto_material::{Ciphertext, PublicKey, Signature};
pub use ids::{DeviceId, GroupId, MessageId, SessionId, UserId};
pub use message::{Envelope, MessageKind, Recipient};
pub use prekey::{PreKeyBundle, SignedPreKey};

/// Milliseconds since the Unix epoch. We avoid `chrono` in the contract crate to keep
/// the dependency surface minimal; callers convert at the edge.
pub type TimestampMs = i64;

/// Crate-wide error type. Domain crates wrap their own errors and convert into this at
/// API boundaries where a uniform type is convenient.
#[derive(Debug, Error)]
pub enum Error {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("unauthorized")]
    Unauthorized,
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Convenience: generate a fresh v4 UUID. Centralized so id newtypes stay consistent.
#[inline]
pub fn new_uuid() -> Uuid {
    Uuid::new_v4()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuids_are_unique() {
        assert_ne!(new_uuid(), new_uuid());
    }
}
