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

use mx_crypto::identity::{generate_prekey_bundle, IdentityKeyPair, PreKeySecrets};
use mx_crypto::pqxdh::{initiator_handshake, responder_handshake, PqxdhInitMessage};
use mx_crypto::ratchet::RatchetState;
use mx_types::{Ciphertext, DeviceId, PreKeyBundle};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

/// Convert any displayable error into a `JsError` for the JS boundary.
fn js_err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

/// A freshly created device account: the public bundle to publish, plus the secret blob the
/// device must persist (to answer responder handshakes later). See [`PreKeySecrets::to_bytes`].
#[wasm_bindgen]
pub struct Account {
    bundle_json: String,
    secrets: Vec<u8>,
}

#[wasm_bindgen]
impl Account {
    /// JSON of the public `PreKeyBundle` to POST to `/v1/prekeys`.
    #[wasm_bindgen(getter)]
    pub fn bundle_json(&self) -> String {
        self.bundle_json.clone()
    }
    /// Opaque secret blob to store locally (e.g. sessionStorage).
    #[wasm_bindgen(getter)]
    pub fn secrets(&self) -> Vec<u8> {
        self.secrets.clone()
    }
}

/// Create a device account for `device_id` (a UUID string): generate identity + pre-keys,
/// returning the publishable bundle and the secret blob to keep.
#[wasm_bindgen]
pub fn account_create(device_id: &str) -> Result<Account, JsError> {
    let uuid = uuid::Uuid::parse_str(device_id).map_err(js_err)?;
    let (bundle, secrets) = generate_prekey_bundle(DeviceId::from(uuid), true);
    Ok(Account {
        bundle_json: serde_json::to_string(&bundle).map_err(js_err)?,
        secrets: secrets.to_bytes(),
    })
}

/// The initiator's result: the agreed 32-byte secret and the init message (JSON) to send
/// alongside the first ciphertext so the responder can derive the same secret.
#[wasm_bindgen]
pub struct InitSession {
    secret: Vec<u8>,
    init_json: String,
}

#[wasm_bindgen]
impl InitSession {
    #[wasm_bindgen(getter)]
    pub fn secret(&self) -> Vec<u8> {
        self.secret.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn init_json(&self) -> String {
        self.init_json.clone()
    }
}

/// Initiator side of a real PQXDH session: derive a shared secret against `their_bundle_json`
/// using my own secrets, returning the secret + the init message to transmit.
#[wasm_bindgen]
pub fn session_initiator(my_secrets: &[u8], their_bundle_json: &str) -> Result<InitSession, JsError> {
    let secrets = PreKeySecrets::from_bytes(my_secrets).map_err(js_err)?;
    let their: PreKeyBundle = serde_json::from_str(their_bundle_json).map_err(js_err)?;
    let hs = initiator_handshake(&secrets.identity, &their).map_err(js_err)?;
    Ok(InitSession {
        secret: hs.shared_secret.0.to_vec(),
        init_json: serde_json::to_string(&hs.init_message).map_err(js_err)?,
    })
}

/// Responder side: derive the same 32-byte secret from the initiator's init message using my
/// stored secrets.
#[wasm_bindgen]
pub fn session_responder(my_secrets: &[u8], init_json: &str) -> Result<Vec<u8>, JsError> {
    let secrets = PreKeySecrets::from_bytes(my_secrets).map_err(js_err)?;
    let init: PqxdhInitMessage = serde_json::from_str(init_json).map_err(js_err)?;
    let ss = responder_handshake(&secrets, &init).map_err(js_err)?;
    Ok(ss.0.to_vec())
}

/// Run a complete PQXDH handshake + ratchet exchange and return a JSON status string.
/// `ok` is true only if both parties derived the identical secret AND a message round-trips
/// through the ratchet.
#[wasm_bindgen]
pub fn pqxdh_selftest() -> String {
    // Bob publishes a bundle (with a one-time pre-key); keep his secrets, then round-trip
    // them through the persistence blob to also verify (de)serialization.
    let (bundle, secrets) = generate_prekey_bundle(DeviceId::new(), true);
    let secrets = match PreKeySecrets::from_bytes(&secrets.to_bytes()) {
        Ok(v) => v,
        Err(e) => return format!(r#"{{"ok":false,"error":"secrets serde: {e}"}}"#),
    };
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
