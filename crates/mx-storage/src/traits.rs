//! Storage trait abstractions.
//!
//! The rest of the system depends on these traits, not on any concrete backend. The
//! default wiring uses the [`crate::memory`] in-memory implementations so the whole
//! monolith runs and tests without a live database; a Postgres/Redis backend can be
//! swapped in later behind the `postgres` / `redis` cargo features without touching
//! callers.
//!
//! All methods return [`mx_types::Result`] so backend failures surface as
//! [`mx_types::Error::Storage`] / [`mx_types::Error::NotFound`] uniformly.

use std::sync::Arc;

use async_trait::async_trait;
use mx_types::{DeviceId, Envelope, GroupId, PreKeyBundle, Result, UserId};

use crate::model::{Device, User};

/// Accounts and their devices.
#[async_trait]
pub trait UserStore: Send + Sync {
    /// Persist a new user. Returns [`mx_types::Error::InvalidInput`] if the username is
    /// already taken (as enforced by the backend).
    async fn create_user(&self, user: User) -> Result<()>;

    /// Fetch a user by id. [`mx_types::Error::NotFound`] if absent.
    async fn get_user(&self, id: UserId) -> Result<User>;

    /// Register a device for an existing user. [`mx_types::Error::NotFound`] if the owning
    /// user does not exist.
    async fn register_device(&self, device: Device) -> Result<()>;

    /// List all devices registered to a user (empty if the user has none).
    async fn list_devices(&self, user: UserId) -> Result<Vec<Device>>;
}

/// Pre-key bundles for asynchronous (offline) session establishment (X3DH / PQXDH).
///
/// The server stores published bundles and hands them out to peers initiating a session.
/// One-time pre-keys are consumed exactly once per fetch so two peers never get the same
/// one-time key.
#[async_trait]
pub trait PreKeyStore: Send + Sync {
    /// Publish (or replace) the bundle for a device.
    async fn publish_bundle(&self, bundle: PreKeyBundle) -> Result<()>;

    /// Fetch a device's bundle **and consume one one-time pre-key**.
    ///
    /// The returned bundle reflects the one-time key handed to this caller (or `None` if
    /// the device's one-time pre-keys are exhausted); subsequent fetches will not return
    /// the same one-time key. [`mx_types::Error::NotFound`] if no bundle is published.
    async fn fetch_and_consume(&self, device: DeviceId) -> Result<PreKeyBundle>;

    /// Read a device's bundle **without** consuming a one-time pre-key (diagnostic/peek).
    async fn get_bundle(&self, device: DeviceId) -> Result<PreKeyBundle>;
}

/// Per-device offline delivery queue for end-to-end encrypted envelopes.
///
/// The queue holds opaque [`Envelope`]s (ciphertext only) until the recipient device
/// drains them. Ordering is FIFO.
#[async_trait]
pub trait MessageQueue: Send + Sync {
    /// Append an envelope to a device's queue.
    async fn enqueue(&self, device: DeviceId, envelope: Envelope) -> Result<()>;

    /// Remove and return all queued envelopes for a device in FIFO order, leaving the
    /// queue empty.
    async fn drain(&self, device: DeviceId) -> Result<Vec<Envelope>>;
}

/// Group/community state.
///
/// The actual MLS group state is kept **opaque** here (a `Vec<u8>` blob owned by the
/// group/crypto layer); this store only persists and retrieves it plus the member roster.
#[async_trait]
pub trait GroupStore: Send + Sync {
    /// Create a group with an initial member set. [`mx_types::Error::InvalidInput`] if the
    /// group already exists.
    async fn create_group(&self, group: GroupId, members: Vec<UserId>) -> Result<()>;

    /// Replace the opaque serialized group state. [`mx_types::Error::NotFound`] if the
    /// group does not exist.
    async fn save_state(&self, group: GroupId, state: Vec<u8>) -> Result<()>;

    /// Read the opaque serialized group state. [`mx_types::Error::NotFound`] if the group
    /// does not exist or has no state saved yet.
    async fn get_state(&self, group: GroupId) -> Result<Vec<u8>>;

    /// List the members of a group. [`mx_types::Error::NotFound`] if the group does not
    /// exist.
    async fn list_members(&self, group: GroupId) -> Result<Vec<UserId>>;
}

// ---------------------------------------------------------------------------
// Shared-ownership blanket impls
//
// All store traits are `&self`-only (the concrete backends use interior mutability),
// so a single backing instance can be shared by many handles behind an [`Arc`]. These
// blanket impls let `Arc<S>` stand in anywhere an `S: …Store` is required — e.g. so the
// same `Arc<InMemoryUserStore>` can be handed to both `mx-auth` (as `Arc<dyn UserStore>`)
// and `mx-messaging` (as a by-value `UserStore`) while sharing one underlying state.
// ---------------------------------------------------------------------------

#[async_trait]
impl<S: UserStore + ?Sized> UserStore for Arc<S> {
    async fn create_user(&self, user: User) -> Result<()> {
        (**self).create_user(user).await
    }
    async fn get_user(&self, id: UserId) -> Result<User> {
        (**self).get_user(id).await
    }
    async fn register_device(&self, device: Device) -> Result<()> {
        (**self).register_device(device).await
    }
    async fn list_devices(&self, user: UserId) -> Result<Vec<Device>> {
        (**self).list_devices(user).await
    }
}

#[async_trait]
impl<S: PreKeyStore + ?Sized> PreKeyStore for Arc<S> {
    async fn publish_bundle(&self, bundle: PreKeyBundle) -> Result<()> {
        (**self).publish_bundle(bundle).await
    }
    async fn fetch_and_consume(&self, device: DeviceId) -> Result<PreKeyBundle> {
        (**self).fetch_and_consume(device).await
    }
    async fn get_bundle(&self, device: DeviceId) -> Result<PreKeyBundle> {
        (**self).get_bundle(device).await
    }
}

#[async_trait]
impl<S: MessageQueue + ?Sized> MessageQueue for Arc<S> {
    async fn enqueue(&self, device: DeviceId, envelope: Envelope) -> Result<()> {
        (**self).enqueue(device, envelope).await
    }
    async fn drain(&self, device: DeviceId) -> Result<Vec<Envelope>> {
        (**self).drain(device).await
    }
}

#[async_trait]
impl<S: GroupStore + ?Sized> GroupStore for Arc<S> {
    async fn create_group(&self, group: GroupId, members: Vec<UserId>) -> Result<()> {
        (**self).create_group(group, members).await
    }
    async fn save_state(&self, group: GroupId, state: Vec<u8>) -> Result<()> {
        (**self).save_state(group, state).await
    }
    async fn get_state(&self, group: GroupId) -> Result<Vec<u8>> {
        (**self).get_state(group).await
    }
    async fn list_members(&self, group: GroupId) -> Result<Vec<UserId>> {
        (**self).list_members(group).await
    }
}
