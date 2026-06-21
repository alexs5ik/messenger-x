//! High-level session setup: PQXDH handshake → seeded Double Ratchet.
//!
//! These tie [`crate::pqxdh`] and [`crate::ratchet`] together so callers (e.g. the wasm
//! layer) get a ready-to-use [`RatchetState`] without touching internal pre-key fields. The
//! responder's signed pre-key is used as the initial DH ratchet key, the standard X3DH →
//! Double Ratchet handoff.

use x25519_dalek::PublicKey as XPublicKey;

use mx_types::prekey::PreKeyBundle;
use mx_types::Result;

use crate::identity::{IdentityKeyPair, PreKeySecrets};
use crate::pqxdh::{initiator_handshake, responder_handshake, PqxdhInitMessage};
use crate::ratchet::RatchetState;

/// Initiator side: run PQXDH against `bob_bundle`, then seed a ratchet toward Bob's signed
/// pre-key public. Returns the ratchet plus the init message to transmit on the first frame.
pub fn initiator_session(
    alice: &IdentityKeyPair,
    bob_bundle: &PreKeyBundle,
) -> Result<(RatchetState, PqxdhInitMessage)> {
    let hs = initiator_handshake(alice, bob_bundle)?;
    let spk_bytes: [u8; 32] = bob_bundle
        .signed_prekey
        .key
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| mx_types::Error::Crypto("bad signed pre-key length".into()))?;
    let ratchet = RatchetState::new_initiator(&hs.shared_secret, XPublicKey::from(spk_bytes));
    Ok((ratchet, hs.init_message))
}

/// Responder side: run PQXDH from the init message, then seed a ratchet from our own signed
/// pre-key secret (matching the public the initiator ratcheted toward).
pub fn responder_session(
    bob_secrets: &PreKeySecrets,
    init: &PqxdhInitMessage,
) -> Result<RatchetState> {
    let shared = responder_handshake(bob_secrets, init)?;
    let spk_secret = bob_secrets.signed_prekey.secret.clone();
    Ok(RatchetState::new_responder(&shared, spk_secret))
}
