//! WebAssembly bindings for [`mx_crypto`] — the real post-quantum crypto core, running in
//! the browser.
//!
//! Two surfaces:
//! - [`pqxdh_selftest`] runs a full hybrid PQXDH handshake (X25519 + ML-KEM-768) plus a
//!   Double Ratchet round-trip and reports the result — proof the real PQ stack executes in
//!   wasm, not a JS reimplementation.
//! - [`seal`] / [`open`] expose mx-crypto's actual AEAD (HKDF-SHA256 → ChaCha20-Poly1305) so
//!   the web client encrypts every message with the real Rust primitives instead of a
//!   WebCrypto stand-in.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use wasm_bindgen::prelude::*;

use mx_crypto::identity::{generate_prekey_bundle, IdentityKeyPair};
use mx_crypto::pqxdh::{initiator_handshake, responder_handshake};
use mx_crypto::ratchet::RatchetState;
use mx_types::{Ciphertext, DeviceId};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

/// Run a complete PQXDH handshake + ratchet exchange and return a JSON status string.
/// `ok` is true only if both parties derived the identical secret AND a message round-trips
/// through the ratchet.
#[wasm_bindgen]
pub fn pqxdh_selftest() -> String {
    // Bob publishes a bundle (with a one-time pre-key); keep his secrets.
    let (bundle, secrets) = generate_prekey_bundle(DeviceId::new(), true);
    // Alice runs the initiator side against Bob's public bundle.
    let alice = IdentityKeyPair::generate();
    let init = match initiator_handshake(&alice, &bundle) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"ok":false,"error":"initiator: {e}"}}"#),
    };
    let bob_secret = match responder_handshake(&secrets, &init.init_message) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"ok":false,"error":"responder: {e}"}}"#),
    };
    let secret_match = init.shared_secret.0 == bob_secret.0;

    // Seed a Double Ratchet from the agreed secret and exchange one message.
    let bob_dh = XStaticSecret::random_from_rng(OsRng);
    let bob_dh_pub = XPublicKey::from(&bob_dh);
    let mut alice_r = RatchetState::new_initiator(&init.shared_secret, bob_dh_pub);
    let mut bob_r = RatchetState::new_responder(&bob_secret, bob_dh);
    let plaintext = b"post-quantum hello";
    let ratchet_ok = match alice_r.encrypt(plaintext) {
        Ok(ct) => matches!(bob_r.decrypt(&ct), Ok(pt) if pt == plaintext),
        Err(_) => false,
    };

    format!(
        r#"{{"ok":{},"secretMatch":{},"ratchetOk":{},"kem":"ML-KEM-768","kdf":"HKDF-SHA256","aead":"ChaCha20-Poly1305"}}"#,
        secret_match && ratchet_ok,
        secret_match,
        ratchet_ok
    )
}

/// Derive a ChaCha20-Poly1305 key from `secret` via HKDF-SHA256.
fn aead_from_secret(secret: &[u8]) -> ChaCha20Poly1305 {
    let hk = Hkdf::<Sha256>::new(None, secret);
    let mut okm = [0u8; 32];
    hk.expand(b"mx-crypto-wasm/seal", &mut okm)
        .expect("32 is a valid HKDF output length");
    ChaCha20Poly1305::new(Key::from_slice(&okm))
}

/// Encrypt `plaintext` under a 32-byte (or any-length) `secret`. Output is `nonce(12) || ct`.
/// Uses the same AEAD as mx-crypto's ratchet, so the wire bytes are produced by real Rust
/// crypto compiled to wasm — the server only ever sees this opaque blob.
#[wasm_bindgen]
pub fn seal(secret: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let cipher = aead_from_secret(secret);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| JsError::new("seal: AEAD encrypt failed"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`seal`]: takes `nonce(12) || ct` and returns the plaintext, or an error if the
/// secret is wrong or the ciphertext was tampered with (AEAD authentication).
#[wasm_bindgen]
pub fn open(secret: &[u8], data: &[u8]) -> Result<Vec<u8>, JsError> {
    if data.len() < 12 {
        return Err(JsError::new("open: input too short"));
    }
    let (nonce, ct) = data.split_at(12);
    let cipher = aead_from_secret(secret);
    cipher
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| JsError::new("open: AEAD decrypt failed (bad key or tampered)"))
}

/// Touch `Ciphertext` so the dependency is exercised in type checks; kept tiny and harmless.
#[allow(dead_code)]
fn _ciphertext_marker(c: &Ciphertext) -> usize {
    c.0.len()
}
