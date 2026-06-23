//! In-memory implementations of the storage traits.
//!
//! These are the default backend for development and tests: the whole monolith runs and
//! its unit/integration tests pass with no external database. State lives in
//! `tokio::sync` guarded `HashMap`s and is lost on process exit. They are intentionally
//! simple and correct rather than fast; the Postgres/Redis backends replace them under
//! load (see the `postgres`/`redis` features).

use std::collections::HashMap;
use std::collections::VecDeque;

use async_trait::async_trait;
use mx_types::{DeviceId, Envelope, Error, GroupId, PreKeyBundle, Result, UserId};
use tokio::sync::{Mutex, RwLock};

use crate::model::{Device, User};
use crate::traits::{GroupStore, MessageQueue, PreKeyStore, UserStore};

// ---------------------------------------------------------------------------
// UserStore
// ---------------------------------------------------------------------------

/// In-memory [`UserStore`]: users by id, devices indexed by owning user.
#[derive(Debug, Default)]
pub struct InMemoryUserStore {
    inner: RwLock<UserState>,
}

#[derive(Debug, Default)]
struct UserState {
    users: HashMap<UserId, User>,
    /// Devices grouped by owning user, preserving registration order.
    devices: HashMap<UserId, Vec<Device>>,
}

impl InMemoryUserStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Export all users and devices (for snapshot persistence).
    pub async fn export(&self) -> (Vec<User>, Vec<Device>) {
        let st = self.inner.read().await;
        let users = st.users.values().cloned().collect();
        let devices = st.devices.values().flatten().cloned().collect();
        (users, devices)
    }

    /// Replace contents with the given users and devices (for snapshot restore).
    pub async fn import(&self, users: Vec<User>, devices: Vec<Device>) {
        let mut st = self.inner.write().await;
        st.users = users.into_iter().map(|u| (u.id, u)).collect();
        st.devices.clear();
        for d in devices {
            st.devices.entry(d.user_id).or_default().push(d);
        }
    }

    /// Find a user by email (exact match). Used by password login / reset.
    pub async fn find_by_email(&self, email: &str) -> Option<User> {
        let st = self.inner.read().await;
        st.users
            .values()
            .find(|u| u.email.as_deref() == Some(email))
            .cloned()
    }

    /// Find a user by phone (exact match).
    pub async fn find_by_phone(&self, phone: &str) -> Option<User> {
        let st = self.inner.read().await;
        st.users
            .values()
            .find(|u| u.phone.as_deref() == Some(phone))
            .cloned()
    }

    /// Find a user by username (exact match).
    pub async fn find_by_username(&self, username: &str) -> Option<User> {
        let st = self.inner.read().await;
        st.users.values().find(|u| u.username == username).cloned()
    }

    /// Replace a user's editable profile (display name, status, avatar). Returns `false` if the
    /// user does not exist.
    pub async fn set_profile(
        &self,
        id: UserId,
        display_name: Option<String>,
        status: Option<String>,
        avatar: Option<String>,
    ) -> bool {
        let mut st = self.inner.write().await;
        match st.users.get_mut(&id) {
            Some(u) => {
                u.display_name = display_name;
                u.status = status;
                u.avatar = avatar;
                true
            }
            None => false,
        }
    }

    /// Set (or clear) a user's password hash and the must-change flag. Returns `false` if the
    /// user does not exist.
    pub async fn set_password(&self, id: UserId, hash: Option<String>, must_change: bool) -> bool {
        let mut st = self.inner.write().await;
        match st.users.get_mut(&id) {
            Some(u) => {
                u.password_hash = hash;
                u.must_change_password = must_change;
                true
            }
            None => false,
        }
    }

    /// Remove a user and all its devices; returns the removed device ids.
    pub async fn delete_user(&self, id: UserId) -> Vec<DeviceId> {
        let mut st = self.inner.write().await;
        st.users.remove(&id);
        st.devices
            .remove(&id)
            .unwrap_or_default()
            .into_iter()
            .map(|d| d.id)
            .collect()
    }
}

#[async_trait]
impl UserStore for InMemoryUserStore {
    async fn create_user(&self, user: User) -> Result<()> {
        let mut st = self.inner.write().await;
        if st.users.contains_key(&user.id) {
            return Err(Error::InvalidInput(format!(
                "user id already exists: {}",
                user.id
            )));
        }
        // Enforce uniqueness across username AND email AND phone, mirroring DB unique
        // constraints.
        for existing in st.users.values() {
            if existing.username == user.username {
                return Err(Error::InvalidInput(format!(
                    "username already taken: {}",
                    user.username
                )));
            }
            if let (Some(a), Some(b)) = (&existing.email, &user.email) {
                if a == b {
                    return Err(Error::InvalidInput(format!("email already registered: {b}")));
                }
            }
            if let (Some(a), Some(b)) = (&existing.phone, &user.phone) {
                if a == b {
                    return Err(Error::InvalidInput(format!("phone already registered: {b}")));
                }
            }
        }
        st.users.insert(user.id, user);
        Ok(())
    }

    async fn get_user(&self, id: UserId) -> Result<User> {
        let st = self.inner.read().await;
        st.users
            .get(&id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("user: {id}")))
    }

    async fn register_device(&self, device: Device) -> Result<()> {
        let mut st = self.inner.write().await;
        if !st.users.contains_key(&device.user_id) {
            return Err(Error::NotFound(format!(
                "user for device: {}",
                device.user_id
            )));
        }
        let list = st.devices.entry(device.user_id).or_default();
        if list.iter().any(|d| d.id == device.id) {
            return Err(Error::InvalidInput(format!(
                "device already registered: {}",
                device.id
            )));
        }
        list.push(device);
        Ok(())
    }

    async fn list_devices(&self, user: UserId) -> Result<Vec<Device>> {
        let st = self.inner.read().await;
        Ok(st.devices.get(&user).cloned().unwrap_or_default())
    }
}

// ---------------------------------------------------------------------------
// PreKeyStore
// ---------------------------------------------------------------------------

/// In-memory [`PreKeyStore`].
///
/// Each device's published [`PreKeyBundle`] is stored as-is. Because the wire bundle only
/// carries a *single* `one_time_prekey`, consumption here means handing it out once and
/// then clearing it; further fetches return a bundle with `one_time_prekey == None` until
/// a new bundle is published. (A production store would keep a queue of many one-time
/// keys; the contract type models one slot, which we honour exactly.)
#[derive(Debug, Default)]
pub struct InMemoryPreKeyStore {
    inner: Mutex<HashMap<DeviceId, PreKeyBundle>>,
}

impl InMemoryPreKeyStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Export all stored bundles (for snapshot persistence).
    pub async fn export(&self) -> Vec<PreKeyBundle> {
        self.inner.lock().await.values().cloned().collect()
    }

    /// Replace contents with the given bundles (for snapshot restore).
    pub async fn import(&self, bundles: Vec<PreKeyBundle>) {
        let mut map = self.inner.lock().await;
        *map = bundles.into_iter().map(|b| (b.device_id, b)).collect();
    }

    /// Remove a device's prekey bundle.
    pub async fn remove_device(&self, device: DeviceId) {
        self.inner.lock().await.remove(&device);
    }
}

#[async_trait]
impl PreKeyStore for InMemoryPreKeyStore {
    async fn publish_bundle(&self, bundle: PreKeyBundle) -> Result<()> {
        let mut map = self.inner.lock().await;
        map.insert(bundle.device_id, bundle);
        Ok(())
    }

    async fn fetch_and_consume(&self, device: DeviceId) -> Result<PreKeyBundle> {
        let mut map = self.inner.lock().await;
        let stored = map
            .get_mut(&device)
            .ok_or_else(|| Error::NotFound(format!("prekey bundle: {device}")))?;
        // Take the one-time prekey out of the stored copy so it is consumed exactly once,
        // and return a snapshot reflecting what this caller received.
        let one_time = stored.one_time_prekey.take();
        let mut handed_out = stored.clone();
        handed_out.one_time_prekey = one_time;
        Ok(handed_out)
    }

    async fn get_bundle(&self, device: DeviceId) -> Result<PreKeyBundle> {
        let map = self.inner.lock().await;
        map.get(&device)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("prekey bundle: {device}")))
    }
}

// ---------------------------------------------------------------------------
// MessageQueue
// ---------------------------------------------------------------------------

/// In-memory FIFO [`MessageQueue`], one queue per device.
#[derive(Debug, Default)]
pub struct InMemoryMessageQueue {
    inner: Mutex<HashMap<DeviceId, VecDeque<Envelope>>>,
}

impl InMemoryMessageQueue {
    /// Create an empty queue store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total queued envelopes across all devices (non-destructive; for admin overview).
    pub async fn total_len(&self) -> usize {
        self.inner.lock().await.values().map(|q| q.len()).sum()
    }

    /// Drop a device's entire queue (used when deleting a user's devices).
    pub async fn purge_device(&self, device: DeviceId) {
        self.inner.lock().await.remove(&device);
    }
}

#[async_trait]
impl MessageQueue for InMemoryMessageQueue {
    async fn enqueue(&self, device: DeviceId, envelope: Envelope) -> Result<()> {
        let mut map = self.inner.lock().await;
        map.entry(device).or_default().push_back(envelope);
        Ok(())
    }

    async fn drain(&self, device: DeviceId) -> Result<Vec<Envelope>> {
        let mut map = self.inner.lock().await;
        match map.get_mut(&device) {
            // `drain(..)` preserves front-to-back (FIFO) order.
            Some(q) => Ok(q.drain(..).collect()),
            None => Ok(Vec::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// GroupStore
// ---------------------------------------------------------------------------

/// In-memory [`GroupStore`] holding opaque group state plus a member roster.
#[derive(Debug, Default)]
pub struct InMemoryGroupStore {
    inner: RwLock<HashMap<GroupId, GroupRecord>>,
}

#[derive(Debug, Default, Clone)]
struct GroupRecord {
    members: Vec<UserId>,
    /// Opaque serialized group (e.g. MLS) state; `None` until first `save_state`.
    state: Option<Vec<u8>>,
}

impl InMemoryGroupStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Export all groups as `(id, members, opaque_state)` tuples (for snapshot persistence).
    pub async fn export(&self) -> Vec<(GroupId, Vec<UserId>, Option<Vec<u8>>)> {
        self.inner
            .read()
            .await
            .iter()
            .map(|(id, rec)| (*id, rec.members.clone(), rec.state.clone()))
            .collect()
    }

    /// Replace contents from exported tuples (for snapshot restore).
    pub async fn import(&self, groups: Vec<(GroupId, Vec<UserId>, Option<Vec<u8>>)>) {
        let mut map = self.inner.write().await;
        *map = groups
            .into_iter()
            .map(|(id, members, state)| (id, GroupRecord { members, state }))
            .collect();
    }
}

#[async_trait]
impl GroupStore for InMemoryGroupStore {
    async fn create_group(&self, group: GroupId, members: Vec<UserId>) -> Result<()> {
        let mut map = self.inner.write().await;
        if map.contains_key(&group) {
            return Err(Error::InvalidInput(format!("group already exists: {group}")));
        }
        map.insert(
            group,
            GroupRecord {
                members,
                state: None,
            },
        );
        Ok(())
    }

    async fn save_state(&self, group: GroupId, state: Vec<u8>) -> Result<()> {
        let mut map = self.inner.write().await;
        let rec = map
            .get_mut(&group)
            .ok_or_else(|| Error::NotFound(format!("group: {group}")))?;
        rec.state = Some(state);
        Ok(())
    }

    async fn get_state(&self, group: GroupId) -> Result<Vec<u8>> {
        let map = self.inner.read().await;
        let rec = map
            .get(&group)
            .ok_or_else(|| Error::NotFound(format!("group: {group}")))?;
        rec.state
            .clone()
            .ok_or_else(|| Error::NotFound(format!("group state: {group}")))
    }

    async fn list_members(&self, group: GroupId) -> Result<Vec<UserId>> {
        let map = self.inner.read().await;
        map.get(&group)
            .map(|r| r.members.clone())
            .ok_or_else(|| Error::NotFound(format!("group: {group}")))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use mx_types::crypto_material::{KeyAlgo, PublicKey, SigAlgo, Signature};
    use mx_types::message::{MessageKind, Recipient};
    use mx_types::prekey::{PreKeyBundle, SignedPreKey};
    use mx_types::Ciphertext;

    fn dummy_pubkey(tag: u8) -> PublicKey {
        PublicKey {
            algo: KeyAlgo::X25519,
            bytes: vec![tag; 32],
        }
    }

    fn dummy_signed_prekey(tag: u8) -> SignedPreKey {
        SignedPreKey {
            key: dummy_pubkey(tag),
            signature: Signature {
                algo: SigAlgo::Ed25519,
                bytes: vec![tag; 64],
            },
        }
    }

    fn bundle_for(device: DeviceId, with_one_time: bool) -> PreKeyBundle {
        PreKeyBundle {
            device_id: device,
            identity_key: dummy_pubkey(1),
            signed_prekey: dummy_signed_prekey(2),
            one_time_prekey: with_one_time.then(|| dummy_pubkey(3)),
            pq_kem_prekey: dummy_signed_prekey(4),
        }
    }

    #[tokio::test]
    async fn user_round_trip() {
        let store = InMemoryUserStore::new();
        let user = User::new("alice");
        let id = user.id;
        store.create_user(user.clone()).await.unwrap();

        let fetched = store.get_user(id).await.unwrap();
        assert_eq!(fetched, user);

        // Register two devices and confirm they list in order.
        let d1 = Device::new(id, dummy_pubkey(10));
        let d2 = Device::new(id, dummy_pubkey(11));
        store.register_device(d1.clone()).await.unwrap();
        store.register_device(d2.clone()).await.unwrap();
        let devices = store.list_devices(id).await.unwrap();
        assert_eq!(devices, vec![d1, d2]);

        // Unknown user => NotFound.
        assert!(matches!(
            store.get_user(UserId::new()).await,
            Err(Error::NotFound(_))
        ));
        // Duplicate username => InvalidInput.
        assert!(matches!(
            store.create_user(User::new("alice")).await,
            Err(Error::InvalidInput(_))
        ));
        // Device for unknown user => NotFound.
        assert!(matches!(
            store
                .register_device(Device::new(UserId::new(), dummy_pubkey(99)))
                .await,
            Err(Error::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn one_time_prekey_consumed_exactly_once() {
        let store = InMemoryPreKeyStore::new();
        let device = DeviceId::new();
        store
            .publish_bundle(bundle_for(device, true))
            .await
            .unwrap();

        // First consume hands out the one-time prekey.
        let first = store.fetch_and_consume(device).await.unwrap();
        assert!(first.one_time_prekey.is_some());

        // Second consume: one-time prekey is gone, but the bundle is still served.
        let second = store.fetch_and_consume(device).await.unwrap();
        assert!(second.one_time_prekey.is_none());

        // Peek does not resurrect it.
        let peek = store.get_bundle(device).await.unwrap();
        assert!(peek.one_time_prekey.is_none());

        // Unknown device => NotFound.
        assert!(matches!(
            store.fetch_and_consume(DeviceId::new()).await,
            Err(Error::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn message_queue_is_fifo() {
        let store = InMemoryMessageQueue::new();
        let device = DeviceId::new();
        let from = DeviceId::new();
        let to = Recipient::Direct(UserId::new());

        // Drain of an empty/unknown queue is empty.
        assert!(store.drain(device).await.unwrap().is_empty());

        let mut ids = Vec::new();
        for i in 0..3u8 {
            let env = Envelope::new(
                from,
                to.clone(),
                MessageKind::Chat,
                Ciphertext(vec![i]),
                i as i64,
            );
            ids.push(env.id);
            store.enqueue(device, env).await.unwrap();
        }

        let drained = store.drain(device).await.unwrap();
        let drained_ids: Vec<_> = drained.iter().map(|e| e.id).collect();
        assert_eq!(drained_ids, ids, "envelopes must drain in FIFO order");

        // After draining, the queue is empty.
        assert!(store.drain(device).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn group_state_round_trip() {
        let store = InMemoryGroupStore::new();
        let group = GroupId::new();
        let members = vec![UserId::new(), UserId::new()];
        store.create_group(group, members.clone()).await.unwrap();

        assert_eq!(store.list_members(group).await.unwrap(), members);
        // No state yet.
        assert!(matches!(
            store.get_state(group).await,
            Err(Error::NotFound(_))
        ));

        store.save_state(group, vec![1, 2, 3]).await.unwrap();
        assert_eq!(store.get_state(group).await.unwrap(), vec![1, 2, 3]);

        // Duplicate create => InvalidInput.
        assert!(matches!(
            store.create_group(group, vec![]).await,
            Err(Error::InvalidInput(_))
        ));
        // Save to unknown group => NotFound.
        assert!(matches!(
            store.save_state(GroupId::new(), vec![]).await,
            Err(Error::NotFound(_))
        ));
    }
}
