//! # mx-crypto — cryptographic core for Messenger X
//!
//! Implements the building blocks that keep message payloads opaque to the server:
//!
//! 1. [`identity`] — long-term identity keypairs (Ed25519 signing + X25519 DH) plus
//!    signed pre-keys, one-time pre-keys, and an ML-KEM-768 KEM keypair.
//! 2. [`identity::generate_prekey_bundle`] — assembles a [`mx_types::PreKeyBundle`],
//!    signing every pre-key with the identity key.
//! 3. [`pqxdh`] — the hybrid **PQXDH** handshake: classical X3DH-style X25519 DHs
//!    *and* an ML-KEM-768 encapsulation, mixed through HKDF-SHA256 into a single root
//!    secret. Both parties derive the same secret; an attacker must break **both**
//!    X25519 and ML-KEM to recover it.
//! 4. [`ratchet`] — a Double Ratchet ([`ratchet::RatchetState`]) providing
//!    [`ratchet::RatchetState::encrypt`] / [`ratchet::RatchetState::decrypt`] over a
//!    symmetric HKDF chain with ChaCha20-Poly1305 AEAD, including a DH-ratchet step.
//!
//! ## SECURITY NOTICE
//!
//! This is an **UNAUDITED, from-scratch reference implementation** written to make the
//! Messenger X scaffold runnable and to document the intended cryptographic shape. It
//! has not been reviewed, fuzzed, or formally analyzed and is **not** constant-time in
//! every path. **Do not ship it.** The production path (design doc §7) is to adopt
//! [libsignal] for PQXDH + the (post-quantum) Triple Ratchet rather than maintain
//! bespoke crypto.
//!
//! [libsignal]: https://github.com/signalapp/libsignal

pub mod identity;
pub mod pqxdh;
pub mod ratchet;
pub mod session;

pub use identity::{
    generate_prekey_bundle, IdentityKeyPair, KemKeyPair, OneTimePreKey, PreKeySecrets,
    SignedPreKeyPair,
};
pub use pqxdh::{
    initiator_handshake, responder_handshake, InitiatorHandshake, PqxdhInitMessage, SharedSecret,
};
pub use ratchet::RatchetState;

/// Domain label mixed into every HKDF derivation so secrets from this crate cannot be
/// confused with secrets derived elsewhere (domain separation).
pub(crate) const HKDF_DOMAIN: &[u8] = b"messenger-x/mx-crypto/v1";
