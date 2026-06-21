//! Double Ratchet — symmetric-key + DH ratchet for per-message forward secrecy.
//!
//! After PQXDH produces a shared root key, each party runs a [`RatchetState`]. Every
//! message advances a **symmetric (sending/receiving) chain** via HKDF, deriving a fresh
//! one-time message key, so compromising one key does not expose past or future messages
//! (forward secrecy). When a party receives a message carrying a new DH public key, a
//! **DH ratchet** step mixes a fresh X25519 DH output back into the root, providing
//! post-compromise security (healing after a key leak).
//!
//! This is a faithful-shape but **simplified** Double Ratchet: it handles in-order
//! delivery and the DH ratchet, but omits skipped-message-key storage for out-of-order
//! delivery (a production implementation, or libsignal, handles that — design doc §7).
//!
//! Message framing (the [`mx_types::Ciphertext`] bytes) is:
//! `[32-byte sender DH pubkey][AEAD ciphertext+tag]`. The DH pubkey is authenticated as
//! AEAD associated data so it cannot be swapped.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use zeroize::Zeroize;

use mx_types::crypto_material::Ciphertext;

use crate::pqxdh::SharedSecret;
use crate::HKDF_DOMAIN;

/// Length of an X25519 public key, prefixed to every ciphertext frame.
const DH_PUB_LEN: usize = 32;

/// A single Double Ratchet session. Hold one per peer device.
pub struct RatchetState {
    /// Current root key (32 bytes), advanced on every DH ratchet step.
    root_key: [u8; 32],
    /// Our current DH ratchet keypair secret.
    dh_self: XStaticSecret,
    /// The peer's latest DH ratchet public key (None until first received message / set on
    /// init for the sender).
    dh_remote: Option<XPublicKey>,
    /// Sending chain key (None until we have performed the first sending DH ratchet).
    chain_send: Option<[u8; 32]>,
    /// Receiving chain key.
    chain_recv: Option<[u8; 32]>,
    /// Monotonic message counter within the sending chain — feeds the nonce.
    send_n: u32,
    /// Monotonic message counter within the receiving chain.
    recv_n: u32,
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.root_key.zeroize();
        if let Some(c) = self.chain_send.as_mut() {
            c.zeroize();
        }
        if let Some(c) = self.chain_recv.as_mut() {
            c.zeroize();
        }
    }
}

/// HKDF-derive `(new_root, chain_key)` from the current root and a DH output. This is the
/// "root KDF" of the Double Ratchet.
fn kdf_rk(root: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(Some(root), dh_out);
    let mut okm = [0u8; 64];
    hk.expand(&[HKDF_DOMAIN, b"/dr-root"].concat(), &mut okm)
        .expect("64 is a valid HKDF length");
    let mut new_root = [0u8; 32];
    let mut chain = [0u8; 32];
    new_root.copy_from_slice(&okm[..32]);
    chain.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (new_root, chain)
}

/// HKDF-derive `(next_chain_key, message_key)` from a chain key. This is the "chain KDF":
/// it ratchets the chain forward and yields a one-time message key for AEAD.
fn kdf_ck(chain: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let hk = Hkdf::<Sha256>::new(None, chain);
    let mut okm = [0u8; 64];
    hk.expand(&[HKDF_DOMAIN, b"/dr-chain"].concat(), &mut okm)
        .expect("64 is a valid HKDF length");
    let mut next = [0u8; 32];
    let mut msg = [0u8; 32];
    next.copy_from_slice(&okm[..32]);
    msg.copy_from_slice(&okm[32..]);
    okm.zeroize();
    (next, msg)
}

/// Build a 12-byte ChaCha20-Poly1305 nonce from a chain counter. Each message key is used
/// exactly once, so a counter-derived deterministic nonce is safe (a fresh key per message
/// means there is no (key, nonce) reuse).
fn nonce_from_counter(n: u32) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[8..].copy_from_slice(&n.to_be_bytes());
    *Nonce::from_slice(&bytes)
}

impl RatchetState {
    /// Initialize the **initiator** side from the PQXDH shared secret and the responder's
    /// current ratchet public key (in the simplest deployment, the responder's signed
    /// pre-key public). The initiator immediately performs a sending DH ratchet so its
    /// first message carries a fresh DH public key.
    pub fn new_initiator(shared: &SharedSecret, remote_dh_public: XPublicKey) -> Self {
        let dh_self = XStaticSecret::random_from_rng(OsRng);
        let mut state = Self {
            root_key: shared.0,
            dh_self,
            dh_remote: Some(remote_dh_public),
            chain_send: None,
            chain_recv: None,
            send_n: 0,
            recv_n: 0,
        };
        // Perform the initial sending DH ratchet: derive the first sending chain.
        let dh_out = state.dh_self.diffie_hellman(&remote_dh_public).to_bytes();
        let (new_root, chain) = kdf_rk(&state.root_key, &dh_out);
        state.root_key = new_root;
        state.chain_send = Some(chain);
        state
    }

    /// Initialize the **responder** side from the PQXDH shared secret and the responder's
    /// own ratchet keypair secret (e.g. its signed pre-key secret, matching the public the
    /// initiator was given). The responder derives its receiving chain lazily on the first
    /// inbound message's DH ratchet step.
    pub fn new_responder(shared: &SharedSecret, self_dh_secret: XStaticSecret) -> Self {
        Self {
            root_key: shared.0,
            dh_self: self_dh_secret,
            dh_remote: None,
            chain_send: None,
            chain_recv: None,
            send_n: 0,
            recv_n: 0,
        }
    }

    /// Our current DH ratchet public key (sent in each outbound frame).
    pub fn dh_public(&self) -> XPublicKey {
        XPublicKey::from(&self.dh_self)
    }

    /// Encrypt `plaintext`, advancing the sending chain. The returned [`Ciphertext`]
    /// frames our DH public key followed by the AEAD output.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> mx_types::Result<Ciphertext> {
        // If we have no sending chain yet (responder before it has ratcheted), perform a
        // sending DH ratchet against the remote's last known key.
        if self.chain_send.is_none() {
            let remote = self.dh_remote.ok_or_else(|| {
                mx_types::Error::Crypto("cannot encrypt before a remote DH key is known".into())
            })?;
            // Rotate our DH key and mix a fresh DH into the root.
            self.dh_self = XStaticSecret::random_from_rng(OsRng);
            let dh_out = self.dh_self.diffie_hellman(&remote).to_bytes();
            let (new_root, chain) = kdf_rk(&self.root_key, &dh_out);
            self.root_key = new_root;
            self.chain_send = Some(chain);
            self.send_n = 0;
        }

        let chain = self.chain_send.as_ref().expect("chain_send set above");
        let (next_chain, mut msg_key) = kdf_ck(chain);

        let dh_pub = self.dh_public().to_bytes();
        let nonce = nonce_from_counter(self.send_n);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        // Authenticate our DH public key as associated data.
        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &dh_pub,
                },
            )
            .map_err(|_| mx_types::Error::Crypto("AEAD encryption failed".into()))?;
        msg_key.zeroize();

        // Commit chain advance.
        self.chain_send = Some(next_chain);
        self.send_n = self.send_n.wrapping_add(1);

        let mut framed = Vec::with_capacity(DH_PUB_LEN + ct.len());
        framed.extend_from_slice(&dh_pub);
        framed.extend_from_slice(&ct);
        Ok(Ciphertext(framed))
    }

    /// Decrypt a frame produced by the peer's [`RatchetState::encrypt`], performing a DH
    /// ratchet step if the frame carries a new remote DH public key.
    pub fn decrypt(&mut self, ct: &Ciphertext) -> mx_types::Result<Vec<u8>> {
        if ct.0.len() < DH_PUB_LEN {
            return Err(mx_types::Error::Crypto("ciphertext frame too short".into()));
        }
        let mut dh_pub_bytes = [0u8; DH_PUB_LEN];
        dh_pub_bytes.copy_from_slice(&ct.0[..DH_PUB_LEN]);
        let remote_dh = XPublicKey::from(dh_pub_bytes);
        let aead_ct = &ct.0[DH_PUB_LEN..];

        // DH ratchet: if this is a new remote DH key, derive a fresh receiving chain.
        let is_new_remote = match &self.dh_remote {
            Some(prev) => prev.as_bytes() != remote_dh.as_bytes(),
            None => true,
        };
        if is_new_remote || self.chain_recv.is_none() {
            let dh_out = self.dh_self.diffie_hellman(&remote_dh).to_bytes();
            let (new_root, chain) = kdf_rk(&self.root_key, &dh_out);
            self.root_key = new_root;
            self.chain_recv = Some(chain);
            self.recv_n = 0;
            self.dh_remote = Some(remote_dh);
            // A received DH ratchet invalidates our sending chain; the next send rotates.
            self.chain_send = None;
        }

        let chain = self
            .chain_recv
            .as_ref()
            .expect("chain_recv set above");
        let (next_chain, mut msg_key) = kdf_ck(chain);

        let nonce = nonce_from_counter(self.recv_n);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&msg_key));
        let pt = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: aead_ct,
                    aad: &dh_pub_bytes,
                },
            )
            .map_err(|_| mx_types::Error::Crypto("AEAD decryption / authentication failed".into()));
        msg_key.zeroize();
        let pt = pt?;

        self.chain_recv = Some(next_chain);
        self.recv_n = self.recv_n.wrapping_add(1);
        Ok(pt)
    }

    /// Serialize the full ratchet state to a byte blob so a client can persist a live session
    /// (across messages and page reloads). Layout: root(32) | dh_self(32) |
    /// dh_remote_flag(1)[+32] | chain_send_flag(1)[+32] | chain_recv_flag(1)[+32] |
    /// send_n(4 LE) | recv_n(4 LE).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(140);
        o.extend_from_slice(&self.root_key);
        o.extend_from_slice(&self.dh_self.to_bytes());
        match &self.dh_remote {
            Some(p) => {
                o.push(1);
                o.extend_from_slice(p.as_bytes());
            }
            None => o.push(0),
        }
        for chain in [&self.chain_send, &self.chain_recv] {
            match chain {
                Some(c) => {
                    o.push(1);
                    o.extend_from_slice(c);
                }
                None => o.push(0),
            }
        }
        o.extend_from_slice(&self.send_n.to_le_bytes());
        o.extend_from_slice(&self.recv_n.to_le_bytes());
        o
    }

    /// Reconstruct a ratchet from [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(data: &[u8]) -> mx_types::Result<Self> {
        fn take<'a>(data: &'a [u8], p: &mut usize, n: usize) -> mx_types::Result<&'a [u8]> {
            let s = data
                .get(*p..*p + n)
                .ok_or_else(|| mx_types::Error::Crypto("truncated ratchet state".into()))?;
            *p += n;
            Ok(s)
        }
        fn arr32(s: &[u8]) -> mx_types::Result<[u8; 32]> {
            s.try_into()
                .map_err(|_| mx_types::Error::Crypto("bad 32-byte ratchet field".into()))
        }
        let mut p = 0usize;
        let root_key = arr32(take(data, &mut p, 32)?)?;
        let dh_self = XStaticSecret::from(arr32(take(data, &mut p, 32)?)?);
        let dh_remote = if take(data, &mut p, 1)?[0] == 1 {
            Some(XPublicKey::from(arr32(take(data, &mut p, 32)?)?))
        } else {
            None
        };
        let chain_send = if take(data, &mut p, 1)?[0] == 1 {
            Some(arr32(take(data, &mut p, 32)?)?)
        } else {
            None
        };
        let chain_recv = if take(data, &mut p, 1)?[0] == 1 {
            Some(arr32(take(data, &mut p, 32)?)?)
        } else {
            None
        };
        let sn = take(data, &mut p, 4)?;
        let rn = take(data, &mut p, 4)?;
        Ok(Self {
            root_key,
            dh_self,
            dh_remote,
            chain_send,
            chain_recv,
            send_n: u32::from_le_bytes([sn[0], sn[1], sn[2], sn[3]]),
            recv_n: u32::from_le_bytes([rn[0], rn[1], rn[2], rn[3]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::generate_prekey_bundle;
    use crate::pqxdh::{initiator_handshake, responder_handshake};
    use mx_types::ids::DeviceId;

    /// Establish a PQXDH secret and build a ratchet pair seeded from Bob's signed pre-key.
    fn establish() -> (RatchetState, RatchetState) {
        let (bob_bundle, bob_secrets) = generate_prekey_bundle(DeviceId::new(), true);
        let alice = crate::identity::IdentityKeyPair::generate();

        let init = initiator_handshake(&alice, &bob_bundle).unwrap();
        let bob_secret = responder_handshake(&bob_secrets, &init.init_message).unwrap();
        assert_eq!(init.shared_secret, bob_secret);

        // Alice ratchets toward Bob's signed pre-key public; Bob holds the matching secret.
        let bob_spk_public = bob_secrets.signed_prekey.public;
        let bob_spk_secret = clone_static(&bob_secrets.signed_prekey.secret);

        let alice_rt = RatchetState::new_initiator(&init.shared_secret, bob_spk_public);
        let bob_rt = RatchetState::new_responder(&bob_secret, bob_spk_secret);
        (alice_rt, bob_rt)
    }

    /// `StaticSecret` is `Clone` in x25519-dalek v2 with the `static_secrets` feature, but
    /// be explicit to make the test intent clear.
    fn clone_static(s: &XStaticSecret) -> XStaticSecret {
        s.clone()
    }

    #[test]
    fn ratchet_roundtrip() {
        let (mut alice, mut bob) = establish();

        let m1 = b"hello bob (msg 1)";
        let c1 = alice.encrypt(m1).unwrap();
        let p1 = bob.decrypt(&c1).unwrap();
        assert_eq!(p1, m1);

        // Second message in the same direction (chain ratchets).
        let m2 = b"second message";
        let c2 = alice.encrypt(m2).unwrap();
        let p2 = bob.decrypt(&c2).unwrap();
        assert_eq!(p2, m2);

        // Reply from Bob triggers a DH ratchet on Alice's side.
        let r1 = b"hi alice";
        let rc1 = bob.encrypt(r1).unwrap();
        let rp1 = alice.decrypt(&rc1).unwrap();
        assert_eq!(rp1, r1);

        // And back again, exercising the full ping-pong DH ratchet.
        let m3 = b"third";
        let c3 = alice.encrypt(m3).unwrap();
        let p3 = bob.decrypt(&c3).unwrap();
        assert_eq!(p3, m3);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (mut alice, mut bob) = establish();
        let mut c = alice.encrypt(b"top secret").unwrap();
        // Flip a byte in the AEAD region (after the 32-byte DH prefix).
        let idx = c.0.len() - 1;
        c.0[idx] ^= 0xff;
        assert!(bob.decrypt(&c).is_err(), "tampered ciphertext must fail to authenticate");
    }

    #[test]
    fn tampered_dh_prefix_fails() {
        let (mut alice, mut bob) = establish();
        let mut c = alice.encrypt(b"secret").unwrap();
        // Corrupt the authenticated DH public-key prefix.
        c.0[0] ^= 0xff;
        assert!(bob.decrypt(&c).is_err());
    }
}
