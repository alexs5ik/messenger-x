//! Opaque, typed wrappers around cryptographic byte material. These let the contract
//! crate describe key-exchange and message structures without depending on any crypto
//! implementation; `mx-crypto` produces and consumes them.

use serde::{Deserialize, Serialize};

/// A public key (classical or post-quantum). The `algo` tag records which primitive the
/// bytes belong to so a peer can route them to the right routine (hybrid handshakes carry
/// several of these).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    pub algo: KeyAlgo,
    pub bytes: Vec<u8>,
}

/// A detached signature over some message, tagged with the signing algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    pub algo: SigAlgo,
    pub bytes: Vec<u8>,
}

/// Encrypted bytes. Opaque to the server — the backend stores and routes these without
/// ever holding the key to open them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext(pub Vec<u8>);

/// Key-exchange / KEM algorithms supported by the handshake. The hybrid PQXDH design (see
/// design doc §7) combines a classical curve with a post-quantum KEM so an attacker must
/// break both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgo {
    /// Classical ECDH curve.
    X25519,
    /// NIST FIPS 203 module-lattice KEM (derived from CRYSTALS-Kyber).
    MlKem768,
}

/// Signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigAlgo {
    /// Classical EdDSA.
    Ed25519,
    /// NIST FIPS 204 module-lattice signature.
    MlDsa65,
}
