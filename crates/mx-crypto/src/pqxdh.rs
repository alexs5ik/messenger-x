//! PQXDH — Post-Quantum Extended Diffie-Hellman handshake (hybrid).
//!
//! This is the asynchronous session-establishment step. The initiator (Alice) fetches
//! Bob's published [`mx_types::PreKeyBundle`] and computes a root secret from:
//!
//! * **DH1** = DH(IK_A, SPK_B) — Alice identity ↔ Bob signed pre-key
//! * **DH2** = DH(EK_A, IK_B)  — Alice ephemeral ↔ Bob identity
//! * **DH3** = DH(EK_A, SPK_B) — Alice ephemeral ↔ Bob signed pre-key
//! * **DH4** = DH(EK_A, OPK_B) — Alice ephemeral ↔ Bob one-time pre-key (if present)
//! * **PQ**  = ML-KEM-768 shared secret, encapsulated to Bob's KEM pre-key
//!
//! All of these are concatenated and run through HKDF-SHA256 to produce the 32-byte root
//! key. Because the PQ secret is mixed in, an attacker who can break X25519 (e.g. a future
//! quantum computer) still cannot recover the root without *also* breaking ML-KEM — and
//! vice versa. This matches Signal's PQXDH design (design doc §7).
//!
//! Bob, when he comes online, reconstructs the identical secret from the same DHs (with
//! roles swapped) plus ML-KEM decapsulation of Alice's KEM ciphertext.

use hkdf::Hkdf;
use ml_kem::kem::Encapsulate;
use ml_kem::{Ciphertext as MlKemCt, Encoded, EncodedSizeUser, MlKem768};
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::Zeroize;

use mx_types::crypto_material::KeyAlgo;
use mx_types::prekey::PreKeyBundle;

use crate::identity::{IdentityKeyPair, MlKemEncapKey, PreKeySecrets};
use crate::HKDF_DOMAIN;

/// The 32-byte symmetric secret both parties derive. Feed this into [`crate::ratchet`] as
/// the initial root key.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedSecret(pub [u8; 32]);

impl Drop for SharedSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedSecret(<redacted>)")
    }
}

/// The message the initiator sends to the responder alongside the first ciphertext so the
/// responder can reconstruct the shared secret. This is itself public — it carries only
/// public ephemeral material and a KEM ciphertext.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PqxdhInitMessage {
    /// Alice's identity DH public key (X25519).
    pub initiator_identity: [u8; 32],
    /// Alice's ephemeral public key (X25519).
    pub initiator_ephemeral: [u8; 32],
    /// ML-KEM-768 ciphertext encapsulated to Bob's KEM pre-key.
    pub kem_ciphertext: Vec<u8>,
    /// Whether Bob's one-time pre-key was consumed (so the responder knows to include
    /// DH4).
    pub used_one_time: bool,
}

/// Result of the initiator side: the derived secret plus the message to transmit.
pub struct InitiatorHandshake {
    pub shared_secret: SharedSecret,
    pub init_message: PqxdhInitMessage,
}

/// Decode an mx-types X25519 [`PublicKey`] byte vec into an `x25519_dalek::PublicKey`.
fn decode_x25519(bytes: &[u8]) -> mx_types::Result<XPublicKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| mx_types::Error::Crypto("bad X25519 key length".into()))?;
    Ok(XPublicKey::from(arr))
}

/// Run HKDF-SHA256 over the concatenated handshake inputs to produce the 32-byte root.
fn kdf_root(ikm: &[u8]) -> [u8; 32] {
    // A non-secret salt of zeros is standard for X3DH/PQXDH; the domain string goes into
    // `info` for separation.
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut out = [0u8; 32];
    hk.expand(&[HKDF_DOMAIN, b"/pqxdh-root"].concat(), &mut out)
        .expect("32 is a valid HKDF-SHA256 length");
    out
}

/// Initiator (Alice) side of PQXDH against `bob_bundle`.
///
/// `alice_identity` is Alice's long-term identity. Returns the derived [`SharedSecret`] and
/// the [`PqxdhInitMessage`] to send to Bob. The caller is responsible for having verified
/// the bundle's pre-key signatures (see [`crate::identity::verify_signed_prekey`]) before
/// calling this.
pub fn initiator_handshake(
    alice_identity: &IdentityKeyPair,
    bob_bundle: &PreKeyBundle,
) -> mx_types::Result<InitiatorHandshake> {
    // Decode Bob's public material.
    let bob_ik = decode_x25519(&bob_bundle.identity_key.bytes)?;
    let bob_spk = decode_x25519(&bob_bundle.signed_prekey.key.bytes)?;
    let bob_opk = match &bob_bundle.one_time_prekey {
        Some(pk) => Some(decode_x25519(&pk.bytes)?),
        None => None,
    };

    if bob_bundle.pq_kem_prekey.key.algo != KeyAlgo::MlKem768 {
        return Err(mx_types::Error::Crypto("KEM pre-key is not ML-KEM-768".into()));
    }
    let bob_kem = decode_mlkem_encap(&bob_bundle.pq_kem_prekey.key.bytes)?;

    // Alice's ephemeral key for this handshake. We use a `StaticSecret` (not
    // `EphemeralSecret`) because the same scalar feeds DH2, DH3 and DH4; the secret is
    // still discarded once the handshake completes, preserving ephemerality in practice.
    let eph_static = XStaticSecret::random_from_rng(OsRng);

    // Classical DHs. Note: IK_A here is the X25519 identity DH key.
    // DH1 = DH(IK_A, SPK_B); DH2 = DH(EK_A, IK_B); DH3 = DH(EK_A, SPK_B); DH4 = DH(EK_A, OPK_B)
    let dh1 = alice_identity.dh_secret.diffie_hellman(&bob_spk);
    let dh2 = eph_static.diffie_hellman(&bob_ik);
    let dh3 = eph_static.diffie_hellman(&bob_spk);
    let dh4 = bob_opk.map(|opk| eph_static.diffie_hellman(&opk));

    // PQ: encapsulate to Bob's ML-KEM pre-key.
    let (kem_ct, kem_ss) = bob_kem
        .encapsulate(&mut OsRng)
        .map_err(|_| mx_types::Error::Crypto("ML-KEM encapsulation failed".into()))?;
    let kem_ss_bytes: [u8; 32] = kem_ss.into();

    // Concatenate IKM in a fixed order: DH1 || DH2 || DH3 || [DH4] || PQ.
    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(d4) = &dh4 {
        ikm.extend_from_slice(d4.as_bytes());
    }
    ikm.extend_from_slice(&kem_ss_bytes);

    let root = kdf_root(&ikm);
    ikm.zeroize();

    let init_message = PqxdhInitMessage {
        initiator_identity: alice_identity.dh_public().to_bytes(),
        initiator_ephemeral: XPublicKey::from(&eph_static).to_bytes(),
        kem_ciphertext: kem_ct.as_slice().to_vec(),
        used_one_time: dh4.is_some(),
    };

    Ok(InitiatorHandshake {
        shared_secret: SharedSecret(root),
        init_message,
    })
}

/// Responder (Bob) side of PQXDH.
///
/// `bob_secrets` are the local secrets Bob kept when he published his bundle (see
/// [`crate::identity::generate_prekey_bundle`]). `msg` is the [`PqxdhInitMessage`] received
/// from Alice. Returns the identical [`SharedSecret`].
pub fn responder_handshake(
    bob_secrets: &PreKeySecrets,
    msg: &PqxdhInitMessage,
) -> mx_types::Result<SharedSecret> {
    let alice_ik = XPublicKey::from(msg.initiator_identity);
    let alice_eph = XPublicKey::from(msg.initiator_ephemeral);

    // Mirror the initiator's DHs with roles swapped:
    // DH1 = DH(SPK_B, IK_A); DH2 = DH(IK_B, EK_A); DH3 = DH(SPK_B, EK_A); DH4 = DH(OPK_B, EK_A)
    let dh1 = bob_secrets.signed_prekey.secret.diffie_hellman(&alice_ik);
    let dh2 = bob_secrets.identity.dh_secret.diffie_hellman(&alice_eph);
    let dh3 = bob_secrets.signed_prekey.secret.diffie_hellman(&alice_eph);
    let dh4 = if msg.used_one_time {
        let opk = bob_secrets.one_time_prekey.as_ref().ok_or_else(|| {
            mx_types::Error::Crypto("handshake used a one-time pre-key Bob no longer has".into())
        })?;
        Some(opk.secret.diffie_hellman(&alice_eph))
    } else {
        None
    };

    // PQ: decapsulate Alice's KEM ciphertext with Bob's ML-KEM secret.
    let kem_ct = decode_mlkem_ct(&msg.kem_ciphertext)?;
    let kem_ss_bytes = bob_secrets.kem.decapsulate(&kem_ct)?;

    let mut ikm = Vec::with_capacity(32 * 5);
    ikm.extend_from_slice(dh1.as_bytes());
    ikm.extend_from_slice(dh2.as_bytes());
    ikm.extend_from_slice(dh3.as_bytes());
    if let Some(d4) = &dh4 {
        ikm.extend_from_slice(d4.as_bytes());
    }
    ikm.extend_from_slice(&kem_ss_bytes);

    let root = kdf_root(&ikm);
    ikm.zeroize();

    Ok(SharedSecret(root))
}

/// Decode ML-KEM-768 encapsulation key bytes.
fn decode_mlkem_encap(bytes: &[u8]) -> mx_types::Result<MlKemEncapKey> {
    let encoded = Encoded::<MlKemEncapKey>::try_from(bytes)
        .map_err(|_| mx_types::Error::Crypto("bad ML-KEM encapsulation key length".into()))?;
    Ok(<MlKemEncapKey as EncodedSizeUser>::from_bytes(&encoded))
}

/// Decode an ML-KEM-768 ciphertext.
fn decode_mlkem_ct(bytes: &[u8]) -> mx_types::Result<MlKemCt<MlKem768>> {
    MlKemCt::<MlKem768>::try_from(bytes)
        .map_err(|_| mx_types::Error::Crypto("bad ML-KEM ciphertext length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{generate_prekey_bundle, verify_signed_prekey};
    use mx_types::ids::DeviceId;

    #[test]
    fn both_parties_derive_identical_secret() {
        // Bob publishes a bundle.
        let (bob_bundle, bob_secrets) = generate_prekey_bundle(DeviceId::new(), true);
        // Bob's pre-keys verify under his identity key.
        let bob_ed = bob_secrets.identity.verifying_key();
        verify_signed_prekey(&bob_ed, &bob_bundle.signed_prekey).unwrap();
        verify_signed_prekey(&bob_ed, &bob_bundle.pq_kem_prekey).unwrap();

        // Alice runs the handshake against Bob's bundle.
        let alice_identity = IdentityKeyPair::generate();
        let init = initiator_handshake(&alice_identity, &bob_bundle).unwrap();

        // Bob reconstructs from the init message.
        let bob_secret = responder_handshake(&bob_secrets, &init.init_message).unwrap();

        assert_eq!(init.shared_secret, bob_secret, "PQXDH secrets must match");
    }

    #[test]
    fn works_without_one_time_prekey() {
        let (bob_bundle, bob_secrets) = generate_prekey_bundle(DeviceId::new(), false);
        assert!(bob_bundle.one_time_prekey.is_none());

        let alice = IdentityKeyPair::generate();
        let init = initiator_handshake(&alice, &bob_bundle).unwrap();
        assert!(!init.init_message.used_one_time);
        let bob_secret = responder_handshake(&bob_secrets, &init.init_message).unwrap();
        assert_eq!(init.shared_secret, bob_secret);
    }

    #[test]
    fn tampered_kem_ciphertext_changes_secret() {
        let (bob_bundle, bob_secrets) = generate_prekey_bundle(DeviceId::new(), true);
        let alice = IdentityKeyPair::generate();
        let mut init = initiator_handshake(&alice, &bob_bundle).unwrap();

        // Flip a byte in the KEM ciphertext: ML-KEM is IND-CCA2, so decapsulation yields a
        // different (implicit-rejection) secret, and the roots diverge.
        init.init_message.kem_ciphertext[0] ^= 0xff;
        let bob_secret = responder_handshake(&bob_secrets, &init.init_message).unwrap();
        assert_ne!(init.shared_secret, bob_secret);
    }
}
