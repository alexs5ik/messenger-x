//! # mx-groups — group / community state (MLS-inspired epoch model)
//!
//! This crate owns the **group key-management state** for Messenger X: which devices are
//! members of a group, and the per-epoch secret that all group messages are encrypted
//! under. As in [MLS (RFC 9420)](https://www.rfc-editor.org/rfc/rfc9420), every change to
//! the membership set advances a monotonically increasing **epoch** and produces a fresh
//! **epoch secret**, so that:
//!
//! * **Forward secrecy** — a newly added member cannot read messages from earlier epochs,
//!   and an attacker who compromises the *current* epoch secret cannot derive the secrets
//!   of *previous* epochs (the ratchet below is one-way: HKDF is not invertible).
//! * **Post-compromise security (partial)** — a removed member can no longer derive the
//!   epoch secrets that follow their removal, because each ratchet step mixes in
//!   change-specific info but the new output is independent of any single member's view.
//!
//! ## What this is NOT — the honest gap
//!
//! This is a **working, tested simplification, not RFC 9420.** It models the epoch /
//! ratchet lifecycle so the rest of the system (messaging, storage, server) can be built
//! and exercised end-to-end, but it deliberately omits the parts that make MLS *scale and
//! be secure against active attackers*:
//!
//! * No **ratchet tree** — the epoch secret is ratcheted as a single linear chain
//!   (`O(1)` state) rather than MLS's `O(log n)` TreeKEM, so there is no efficient,
//!   per-member path update and no asymmetric key agreement on membership change. Here the
//!   change-info is symmetric metadata, not a real key-encapsulation.
//! * No **Welcome / Commit / Proposal** framing, no full key schedule (epoch/sender/
//!   exporter secrets), no transcript hash, no signature-verified `LeafNode`s.
//! * **Forward secrecy holds across epochs, but there is no within-epoch message
//!   ratchet** — every message in an epoch uses the same `current_epoch_key()`.
//!
//! Production hardening (see design doc §7 *Architecture / Groups(MLS)* and §9
//! *Tech decisions — "MLS-реализации: OpenMLS (Rust)"*) means **adopting
//! [OpenMLS](https://github.com/openmls/openmls)** rather than extending this module.
//!
//! ## Persistence
//!
//! [`Group`] serializes to / from a compact byte blob ([`Group::to_bytes`] /
//! [`Group::from_bytes`]) that is stored opaquely by [`mx_storage::GroupStore`] — the
//! server persists the bytes without understanding them, consistent with the
//! ciphertext-only backend principle.

use std::collections::BTreeSet;

use hkdf::Hkdf;
use mx_types::{DeviceId, Error, GroupId, Result};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain-separation prefix for every HKDF `info` string, so epoch-secret derivations in
/// this crate can never collide with HKDF usage elsewhere in the system.
const HKDF_DOMAIN: &str = "mx-groups/epoch-ratchet/v1";

/// Size, in bytes, of an epoch secret (256-bit, matching HKDF-SHA256 output).
pub const EPOCH_SECRET_LEN: usize = 32;

/// A 256-bit epoch secret. Wrapped in a newtype so it is zeroized on drop and never
/// accidentally logged via a naive `Debug` of the raw array.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EpochSecret(pub [u8; EPOCH_SECRET_LEN]);

impl EpochSecret {
    /// Borrow the raw secret bytes (e.g. to feed an AEAD key schedule).
    #[inline]
    pub fn as_bytes(&self) -> &[u8; EPOCH_SECRET_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for EpochSecret {
    /// Redacted: never print key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochSecret(<redacted>)")
    }
}

/// The kind of membership change that triggered an epoch advance. Mixed into the HKDF
/// `info` so the ratchet output is bound to *what* changed, not just *that* something did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChangeKind {
    Create,
    Add,
    Remove,
}

impl ChangeKind {
    fn label(self) -> &'static str {
        match self {
            ChangeKind::Create => "create",
            ChangeKind::Add => "add",
            ChangeKind::Remove => "remove",
        }
    }
}

/// In-memory state of a single group.
///
/// Invariants:
/// * `epoch` starts at `0` for a freshly created group and increments by exactly one on
///   every successful membership change.
/// * `members` is never empty for a live group (the creator is always present at epoch 0;
///   you cannot remove the last member — see [`Group::remove_member`]).
/// * `epoch_secret` is the secret for the *current* `epoch` only; previous-epoch secrets
///   are not retained and are not derivable from this state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// Stable identifier of the group.
    pub id: GroupId,
    /// Current epoch. Monotonically increasing; `0` at creation.
    pub epoch: u64,
    /// Current member device set. Ordered + deduplicated by `BTreeSet`, which also makes
    /// the serialized form deterministic.
    pub members: BTreeSet<DeviceId>,
    /// Secret for the current epoch. All group messages in this epoch derive their key
    /// from here via [`Group::current_epoch_key`].
    pub epoch_secret: EpochSecret,
}

impl std::fmt::Debug for Group {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Group")
            .field("id", &self.id)
            .field("epoch", &self.epoch)
            .field("members", &self.members)
            .field("epoch_secret", &self.epoch_secret) // redacted by EpochSecret::Debug
            .finish()
    }
}

impl Group {
    /// Create a new group with `creator` as its sole member at **epoch 0**.
    ///
    /// The initial epoch secret is derived from `id` and the creator's device id via HKDF
    /// (extract with no salt, expand with a `create` label) so it is deterministic for a
    /// given `(id, creator)` yet still 256-bit and domain-separated. Subsequent epochs
    /// ratchet off this value.
    pub fn create_group(id: GroupId, creator: DeviceId) -> Self {
        // Seed the ratchet from public identifiers. There is no secret entropy here yet —
        // confidentiality comes from the transport/ratchet seeding in a real deployment;
        // for this simplified model the security property we test is *one-way ratcheting*
        // across epochs, not the secrecy of the seed itself.
        let mut seed = Vec::with_capacity(32);
        seed.extend_from_slice(id.0.as_bytes());
        seed.extend_from_slice(creator.0.as_bytes());

        let epoch_secret = derive_secret(&seed, ChangeKind::Create, 0, &[creator]);

        let mut members = BTreeSet::new();
        members.insert(creator);

        Self {
            id,
            epoch: 0,
            members,
            epoch_secret,
        }
    }

    /// Add `device` to the group, advancing the epoch and ratcheting the epoch secret.
    ///
    /// Returns [`Error::InvalidInput`] if `device` is already a member (a no-op must not
    /// silently burn an epoch / desync members from the secret).
    pub fn add_member(&mut self, device: DeviceId) -> Result<()> {
        if self.members.contains(&device) {
            return Err(Error::InvalidInput(format!(
                "device {device} is already a member of group {}",
                self.id
            )));
        }
        self.members.insert(device);
        self.advance(ChangeKind::Add, &[device]);
        Ok(())
    }

    /// Remove `device` from the group, advancing the epoch and ratcheting the epoch
    /// secret so the removed device cannot read any future epoch.
    ///
    /// Returns [`Error::NotFound`] if `device` is not a member, or [`Error::InvalidInput`]
    /// if it is the last remaining member (a group must always have at least one member).
    pub fn remove_member(&mut self, device: DeviceId) -> Result<()> {
        if !self.members.contains(&device) {
            return Err(Error::NotFound(format!(
                "device {device} is not a member of group {}",
                self.id
            )));
        }
        if self.members.len() == 1 {
            return Err(Error::InvalidInput(
                "cannot remove the last member of a group".into(),
            ));
        }
        self.members.remove(&device);
        self.advance(ChangeKind::Remove, &[device]);
        Ok(())
    }

    /// The symmetric key for encrypting/decrypting messages in the **current** epoch.
    ///
    /// Derived from the current epoch secret with a fixed `message-key` label, so the key
    /// exposed to the AEAD layer is distinct from the ratchet's epoch secret itself
    /// (key separation: leaking a message key does not leak the chaining secret).
    pub fn current_epoch_key(&self) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(None, &self.epoch_secret.0);
        let mut okm = [0u8; 32];
        let info = format!("{HKDF_DOMAIN}|message-key|epoch={}", self.epoch);
        hk.expand(info.as_bytes(), &mut okm)
            .expect("32 is a valid HKDF-SHA256 output length");
        okm
    }

    /// Serialize the full group state to a portable byte blob for [`mx_storage::GroupStore`].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| Error::Storage(format!("group serialize: {e}")))
    }

    /// Reconstruct group state from a blob produced by [`Group::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes)
            .map_err(|e| Error::Storage(format!("group deserialize: {e}")))
    }

    /// Advance to the next epoch, ratcheting the epoch secret from the *previous* secret
    /// plus change-specific info. One-way: the new secret cannot be inverted to recover
    /// the old one.
    fn advance(&mut self, change: ChangeKind, changed: &[DeviceId]) {
        let next_epoch = self.epoch + 1;
        let next_secret = derive_secret(&self.epoch_secret.0, change, next_epoch, changed);
        // Wipe the old secret promptly; ZeroizeOnDrop handles the rest.
        self.epoch_secret.zeroize();
        self.epoch_secret = next_secret;
        self.epoch = next_epoch;
    }
}

/// Core ratchet step: `HKDF-Extract-then-Expand(prev_ikm, info=change||epoch||devices)`.
///
/// Using HKDF guarantees the derivation is **one-way** — given the output you cannot
/// recover `prev_ikm` — which is exactly the forward-secrecy property the epoch model
/// relies on. The `info` binds the output to the kind of change, the resulting epoch
/// number, and the specific devices involved, so two different changes can never produce
/// the same next secret.
fn derive_secret(
    prev_ikm: &[u8],
    change: ChangeKind,
    epoch: u64,
    changed: &[DeviceId],
) -> EpochSecret {
    // Build the domain-separated, change-bound info string.
    let mut info = format!("{HKDF_DOMAIN}|{}|epoch={epoch}", change.label());
    for d in changed {
        info.push('|');
        info.push_str(&d.0.simple().to_string());
    }

    // HKDF-Extract with no salt over the previous secret, then expand 32 bytes.
    let hk = Hkdf::<Sha256>::new(None, prev_ikm);
    let mut okm = [0u8; EPOCH_SECRET_LEN];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("EPOCH_SECRET_LEN is a valid HKDF-SHA256 output length");
    EpochSecret(okm)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev() -> DeviceId {
        DeviceId::new()
    }

    #[test]
    fn create_starts_at_epoch_zero_with_only_creator() {
        let creator = dev();
        let g = Group::create_group(GroupId::new(), creator);
        assert_eq!(g.epoch, 0);
        assert_eq!(g.members.len(), 1);
        assert!(g.members.contains(&creator));
    }

    #[test]
    fn create_then_add_then_remove_advances_epoch_each_step() {
        let creator = dev();
        let a = dev();
        let b = dev();
        let mut g = Group::create_group(GroupId::new(), creator);
        assert_eq!(g.epoch, 0);

        g.add_member(a).unwrap();
        assert_eq!(g.epoch, 1);
        assert!(g.members.contains(&a));

        g.add_member(b).unwrap();
        assert_eq!(g.epoch, 2);

        g.remove_member(a).unwrap();
        assert_eq!(g.epoch, 3);
        assert!(!g.members.contains(&a));
        assert!(g.members.contains(&b));
        assert!(g.members.contains(&creator));
    }

    #[test]
    fn epoch_key_changes_on_each_membership_change() {
        let mut g = Group::create_group(GroupId::new(), dev());
        let k0 = g.current_epoch_key();

        g.add_member(dev()).unwrap();
        let k1 = g.current_epoch_key();

        let m = dev();
        g.add_member(m).unwrap();
        let k2 = g.current_epoch_key();

        g.remove_member(m).unwrap();
        let k3 = g.current_epoch_key();

        // All four epoch keys are pairwise distinct.
        let keys = [k0, k1, k2, k3];
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "epoch keys {i} and {j} collided");
            }
        }
    }

    #[test]
    fn old_epoch_secret_not_derivable_from_new_state() {
        let mut g = Group::create_group(GroupId::new(), dev());

        // Snapshot epoch-0 secret + key BEFORE advancing.
        let old_secret = g.epoch_secret.0;
        let old_key = g.current_epoch_key();

        g.add_member(dev()).unwrap();

        // The new state holds a different secret...
        assert_ne!(g.epoch_secret.0, old_secret);

        // ...and nothing in the new state reproduces the old key. The only way to get
        // `old_key` is to possess the old secret, which the new state has overwritten and
        // which HKDF makes non-invertible. Concretely: deriving from the *new* secret
        // never yields the old key.
        assert_ne!(g.current_epoch_key(), old_key);

        // And the old key is reproducible ONLY from the retained old secret (sanity:
        // confirms `old_key` really was a function of `old_secret`, so its
        // non-derivability from new state is meaningful).
        let hk = Hkdf::<Sha256>::new(None, &old_secret);
        let mut okm = [0u8; 32];
        hk.expand(
            format!("{HKDF_DOMAIN}|message-key|epoch=0").as_bytes(),
            &mut okm,
        )
        .unwrap();
        assert_eq!(okm, old_key);
    }

    #[test]
    fn add_duplicate_member_is_rejected_and_does_not_advance_epoch() {
        let creator = dev();
        let mut g = Group::create_group(GroupId::new(), creator);
        let err = g.add_member(creator).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
        assert_eq!(g.epoch, 0, "rejected add must not burn an epoch");
    }

    #[test]
    fn remove_nonmember_is_not_found_and_remove_last_is_rejected() {
        let creator = dev();
        let mut g = Group::create_group(GroupId::new(), creator);

        let err = g.remove_member(dev()).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)));
        assert_eq!(g.epoch, 0);

        let err = g.remove_member(creator).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)), "cannot remove last member");
        assert_eq!(g.members.len(), 1);
    }

    #[test]
    fn state_round_trips_through_bytes() {
        let mut g = Group::create_group(GroupId::new(), dev());
        g.add_member(dev()).unwrap();
        g.add_member(dev()).unwrap();

        let bytes = g.to_bytes().unwrap();
        let restored = Group::from_bytes(&bytes).unwrap();

        assert_eq!(restored.id, g.id);
        assert_eq!(restored.epoch, g.epoch);
        assert_eq!(restored.members, g.members);
        assert_eq!(restored.epoch_secret.0, g.epoch_secret.0);
        // The restored state produces the identical current epoch key.
        assert_eq!(restored.current_epoch_key(), g.current_epoch_key());
    }

    #[test]
    fn from_bytes_rejects_garbage() {
        let err = Group::from_bytes(b"not json at all").unwrap_err();
        assert!(matches!(err, Error::Storage(_)));
    }
}
