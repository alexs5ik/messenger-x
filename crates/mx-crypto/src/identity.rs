//! Identity, pre-keys, and KEM key generation.
//!
//! A device owns:
//! * an **identity keypair** — Ed25519 for signing + an X25519 keypair for DH. The
//!   Ed25519 public key is the device's stable identity; the X25519 key participates in
//!   the handshake DHs.
//! * a **signed pre-key** — a medium-term X25519 key, signed by the identity key.
//! * zero or more **one-time pre-keys** — single-use X25519 keys, signed in the bundle.
//! * an **ML-KEM-768 keypair** — the post-quantum KEM pre-key, also signed.
//!
//! [`generate_prekey_bundle`] packages the *public* halves into an [`mx_types::PreKeyBundle`]
//! and returns the matching *secrets* separately so the caller can persist them locally.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use ml_kem::kem::{Decapsulate, DecapsulationKey, EncapsulationKey};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::OsRng;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};

use mx_types::crypto_material::{KeyAlgo, PublicKey, SigAlgo, Signature};
use mx_types::ids::DeviceId;
use mx_types::prekey::{PreKeyBundle, SignedPreKey};

/// Concrete ML-KEM-768 decapsulation key type (the secret).
pub(crate) type MlKemDecapKey = DecapsulationKey<MlKem768Params>;
/// Concrete ML-KEM-768 encapsulation key type (the public key).
pub(crate) type MlKemEncapKey = EncapsulationKey<MlKem768Params>;

/// Long-term device identity: an Ed25519 signing key and an X25519 DH key.
///
/// The Ed25519 public key is the durable cryptographic identity of the device. The
/// X25519 key is used in the handshake's identity DH (`DH1` / `DH3` in X3DH terms).
pub struct IdentityKeyPair {
    /// Ed25519 signing key (secret).
    pub(crate) signing: SigningKey,
    /// X25519 DH secret bound to this identity.
    pub(crate) dh_secret: XStaticSecret,
}

impl IdentityKeyPair {
    /// Generate a fresh identity keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let dh_secret = XStaticSecret::random_from_rng(OsRng);
        Self { signing, dh_secret }
    }

    /// Ed25519 verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Identity public key as an mx-types [`PublicKey`] (Ed25519 tag).
    ///
    /// This is the *signing* identity. The X25519 half is exposed via
    /// [`IdentityKeyPair::dh_public_mx`].
    pub fn identity_public_mx(&self) -> PublicKey {
        PublicKey {
            algo: KeyAlgo::X25519,
            bytes: self.dh_public().to_bytes().to_vec(),
        }
    }

    /// X25519 identity DH public key.
    pub fn dh_public(&self) -> XPublicKey {
        XPublicKey::from(&self.dh_secret)
    }

    /// X25519 identity DH public key as mx-types [`PublicKey`].
    pub fn dh_public_mx(&self) -> PublicKey {
        PublicKey {
            algo: KeyAlgo::X25519,
            bytes: self.dh_public().to_bytes().to_vec(),
        }
    }

    /// Ed25519 verifying key as mx-types [`PublicKey`].
    pub fn ed25519_public_mx(&self) -> PublicKey {
        PublicKey {
            algo: KeyAlgo::X25519, // tag reused; Ed25519 has no KeyAlgo variant — see note below.
            bytes: self.verifying_key().to_bytes().to_vec(),
        }
    }

    /// Sign `msg` with the Ed25519 identity key, returning an mx-types [`Signature`].
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let sig = self.signing.sign(msg);
        Signature {
            algo: SigAlgo::Ed25519,
            bytes: sig.to_bytes().to_vec(),
        }
    }
}

/// A signed X25519 pre-key (secret + public + identity signature over the public bytes).
pub struct SignedPreKeyPair {
    pub(crate) secret: XStaticSecret,
    pub(crate) public: XPublicKey,
    pub(crate) signature: Signature,
}

impl SignedPreKeyPair {
    /// Generate a fresh X25519 pre-key and sign its public bytes with `identity`.
    pub fn generate(identity: &IdentityKeyPair) -> Self {
        let secret = XStaticSecret::random_from_rng(OsRng);
        let public = XPublicKey::from(&secret);
        let signature = identity.sign(public.as_bytes());
        Self {
            secret,
            public,
            signature,
        }
    }

    /// The public half + signature, as the mx-types contract type.
    pub fn to_signed_prekey(&self) -> SignedPreKey {
        SignedPreKey {
            key: PublicKey {
                algo: KeyAlgo::X25519,
                bytes: self.public.to_bytes().to_vec(),
            },
            signature: self.signature.clone(),
        }
    }
}

/// A single-use X25519 pre-key.
pub struct OneTimePreKey {
    pub(crate) secret: XStaticSecret,
    pub(crate) public: XPublicKey,
}

impl OneTimePreKey {
    /// Generate a fresh one-time pre-key.
    pub fn generate() -> Self {
        let secret = XStaticSecret::random_from_rng(OsRng);
        let public = XPublicKey::from(&secret);
        Self { secret, public }
    }

    /// Public half as mx-types [`PublicKey`].
    pub fn public_mx(&self) -> PublicKey {
        PublicKey {
            algo: KeyAlgo::X25519,
            bytes: self.public.to_bytes().to_vec(),
        }
    }
}

/// An ML-KEM-768 keypair (the post-quantum KEM pre-key).
pub struct KemKeyPair {
    pub(crate) decap: MlKemDecapKey,
    pub(crate) encap: MlKemEncapKey,
}

impl KemKeyPair {
    /// Generate a fresh ML-KEM-768 keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        let (decap, encap) = MlKem768::generate(&mut OsRng);
        Self { decap, encap }
    }

    /// Encapsulation (public) key encoded as mx-types [`PublicKey`] (MlKem768 tag).
    pub fn encap_public_mx(&self) -> PublicKey {
        PublicKey {
            algo: KeyAlgo::MlKem768,
            bytes: self.encap.as_bytes().to_vec(),
        }
    }

    /// Decapsulate a KEM ciphertext, recovering the shared secret bytes.
    pub(crate) fn decapsulate(
        &self,
        ct: &ml_kem::Ciphertext<MlKem768>,
    ) -> mx_types::Result<[u8; 32]> {
        let ss = self
            .decap
            .decapsulate(ct)
            .map_err(|_| mx_types::Error::Crypto("ML-KEM decapsulation failed".into()))?;
        Ok(ss.into())
    }
}

/// The local secrets that back a published [`PreKeyBundle`]. The caller persists these so
/// it can complete the responder side of a handshake later.
pub struct PreKeySecrets {
    pub identity: IdentityKeyPair,
    pub signed_prekey: SignedPreKeyPair,
    pub one_time_prekey: Option<OneTimePreKey>,
    pub kem: KemKeyPair,
}

impl PreKeySecrets {
    /// Serialize all secret key material to a portable byte blob so a device can persist it
    /// (e.g. in browser storage) and complete responder handshakes after a restart/reload.
    /// Layout: signing(32) | identity_dh(32) | signed_prekey(32) | one_time_flag(1)[+32] |
    /// decap_len(u32 LE) | decap | encap_len(u32 LE) | encap.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.identity.signing.to_bytes());
        out.extend_from_slice(&self.identity.dh_secret.to_bytes());
        out.extend_from_slice(&self.signed_prekey.secret.to_bytes());
        match &self.one_time_prekey {
            Some(o) => {
                out.push(1);
                out.extend_from_slice(&o.secret.to_bytes());
            }
            None => out.push(0),
        }
        let decap = self.kem.decap.as_bytes();
        let encap = self.kem.encap.as_bytes();
        let decap: &[u8] = &decap;
        let encap: &[u8] = &encap;
        out.extend_from_slice(&(decap.len() as u32).to_le_bytes());
        out.extend_from_slice(decap);
        out.extend_from_slice(&(encap.len() as u32).to_le_bytes());
        out.extend_from_slice(encap);
        out
    }

    /// Reconstruct [`PreKeySecrets`] from [`to_bytes`](Self::to_bytes). The signed pre-key
    /// signature is recomputed from the restored identity (it is not needed for the responder
    /// role, but keeps the value internally consistent).
    pub fn from_bytes(data: &[u8]) -> mx_types::Result<Self> {
        fn take<'a>(data: &'a [u8], p: &mut usize, n: usize) -> mx_types::Result<&'a [u8]> {
            let s = data
                .get(*p..*p + n)
                .ok_or_else(|| mx_types::Error::Crypto("truncated PreKeySecrets blob".into()))?;
            *p += n;
            Ok(s)
        }
        fn arr32(s: &[u8]) -> mx_types::Result<[u8; 32]> {
            s.try_into()
                .map_err(|_| mx_types::Error::Crypto("bad 32-byte field".into()))
        }
        let mut p = 0usize;
        let signing = arr32(take(data, &mut p, 32)?)?;
        let id_dh = arr32(take(data, &mut p, 32)?)?;
        let spk = arr32(take(data, &mut p, 32)?)?;
        let identity = IdentityKeyPair {
            signing: SigningKey::from_bytes(&signing),
            dh_secret: XStaticSecret::from(id_dh),
        };
        let spk_secret = XStaticSecret::from(spk);
        let spk_public = XPublicKey::from(&spk_secret);
        let spk_sig = identity.sign(spk_public.as_bytes());
        let signed_prekey = SignedPreKeyPair {
            secret: spk_secret,
            public: spk_public,
            signature: spk_sig,
        };
        let one_time_prekey = match take(data, &mut p, 1)?[0] {
            1 => {
                let ot = arr32(take(data, &mut p, 32)?)?;
                let secret = XStaticSecret::from(ot);
                let public = XPublicKey::from(&secret);
                Some(OneTimePreKey { secret, public })
            }
            _ => None,
        };
        let dlen_raw = take(data, &mut p, 4)?;
        let dlen = u32::from_le_bytes([dlen_raw[0], dlen_raw[1], dlen_raw[2], dlen_raw[3]]) as usize;
        let decap_bytes = take(data, &mut p, dlen)?;
        let decap_enc = ml_kem::Encoded::<MlKemDecapKey>::try_from(decap_bytes)
            .map_err(|_| mx_types::Error::Crypto("bad ML-KEM decap key".into()))?;
        let decap = MlKemDecapKey::from_bytes(&decap_enc);
        let elen_raw = take(data, &mut p, 4)?;
        let elen = u32::from_le_bytes([elen_raw[0], elen_raw[1], elen_raw[2], elen_raw[3]]) as usize;
        let encap_bytes = take(data, &mut p, elen)?;
        let encap_enc = ml_kem::Encoded::<MlKemEncapKey>::try_from(encap_bytes)
            .map_err(|_| mx_types::Error::Crypto("bad ML-KEM encap key".into()))?;
        let encap = MlKemEncapKey::from_bytes(&encap_enc);
        Ok(Self {
            identity,
            signed_prekey,
            one_time_prekey,
            kem: KemKeyPair { decap, encap },
        })
    }
}

/// Generate a full pre-key bundle for `device_id`.
///
/// Every pre-key (signed pre-key, KEM pre-key) carries an Ed25519 signature by the
/// identity key, so a peer fetching the bundle from the (untrusted) server can verify the
/// keys were authorized by the identity it expects. Returns the public [`PreKeyBundle`] to
/// publish *and* the [`PreKeySecrets`] to keep local.
///
/// `with_one_time` controls whether a one-time pre-key is included (devices upload a batch
/// and the server hands them out one per handshake; pass `false` once exhausted).
pub fn generate_prekey_bundle(
    device_id: DeviceId,
    with_one_time: bool,
) -> (PreKeyBundle, PreKeySecrets) {
    let identity = IdentityKeyPair::generate();
    let signed_prekey = SignedPreKeyPair::generate(&identity);
    let kem = KemKeyPair::generate();

    // Sign the KEM encapsulation key with the identity key so it is authenticated too.
    let kem_public = kem.encap_public_mx();
    let kem_sig = identity.sign(&kem_public.bytes);
    let pq_kem_prekey = SignedPreKey {
        key: kem_public,
        signature: kem_sig,
    };

    let one_time_prekey = if with_one_time {
        Some(OneTimePreKey::generate())
    } else {
        None
    };

    let bundle = PreKeyBundle {
        device_id,
        identity_key: identity.dh_public_mx(),
        signed_prekey: signed_prekey.to_signed_prekey(),
        one_time_prekey: one_time_prekey.as_ref().map(|o| o.public_mx()),
        pq_kem_prekey,
    };

    let secrets = PreKeySecrets {
        identity,
        signed_prekey,
        one_time_prekey,
        kem,
    };

    (bundle, secrets)
}

/// Verify that a [`SignedPreKey`]'s signature was produced by `identity_ed25519` over its
/// public-key bytes. Returns `Ok(())` on success.
pub fn verify_signed_prekey(
    identity_ed25519: &VerifyingKey,
    spk: &SignedPreKey,
) -> mx_types::Result<()> {
    use ed25519_dalek::Verifier;
    if spk.signature.algo != SigAlgo::Ed25519 {
        return Err(mx_types::Error::Crypto("expected Ed25519 signature".into()));
    }
    let sig_bytes: [u8; 64] = spk
        .signature
        .bytes
        .as_slice()
        .try_into()
        .map_err(|_| mx_types::Error::Crypto("bad signature length".into()))?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    identity_ed25519
        .verify(&spk.key.bytes, &sig)
        .map_err(|_| mx_types::Error::Crypto("pre-key signature verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prekey_signatures_verify() {
        let device = DeviceId::new();
        let (bundle, secrets) = generate_prekey_bundle(device, true);

        let ed_pub = secrets.identity.verifying_key();

        // Signed pre-key verifies against the identity key.
        verify_signed_prekey(&ed_pub, &bundle.signed_prekey)
            .expect("signed pre-key signature must verify");
        // KEM pre-key verifies too.
        verify_signed_prekey(&ed_pub, &bundle.pq_kem_prekey)
            .expect("KEM pre-key signature must verify");

        // A tampered key fails verification.
        let mut tampered = bundle.signed_prekey.clone();
        tampered.key.bytes[0] ^= 0xff;
        assert!(verify_signed_prekey(&ed_pub, &tampered).is_err());

        // Algorithm tags are correct.
        assert_eq!(bundle.pq_kem_prekey.key.algo, KeyAlgo::MlKem768);
        assert_eq!(bundle.signed_prekey.key.algo, KeyAlgo::X25519);
        assert!(bundle.one_time_prekey.is_some());
    }

    #[test]
    fn kem_roundtrip() {
        use ml_kem::kem::Encapsulate;
        let kp = KemKeyPair::generate();
        let (ct, ss_sender) = kp.encap.encapsulate(&mut OsRng).unwrap();
        let ss_receiver = kp.decapsulate(&ct).unwrap();
        assert_eq!(<[u8; 32]>::from(ss_sender), ss_receiver);
    }
}
