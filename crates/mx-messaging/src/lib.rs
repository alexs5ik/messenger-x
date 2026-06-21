//! # mx-messaging — message delivery for Messenger X
//!
//! This crate is the routing brain that sits on top of [`mx_storage`]'s persistence
//! traits. It takes an opaque, end-to-end-encrypted [`Envelope`] from a sender and **fans
//! it out** to the offline queue of every device that should receive it:
//!
//! - [`Recipient::Direct`] → every registered device of the target user.
//! - [`Recipient::Group`] → every device of every member of the group.
//!
//! Recipient devices later [`MessagingService::pull`] their queue to drain pending
//! envelopes in FIFO order.
//!
//! ## Ciphertext-only invariant
//!
//! Consistent with the project's core principle, this layer never inspects, decrypts, or
//! transforms [`Envelope::ciphertext`]. It only reads routing metadata
//! ([`Envelope::to`]) and stamps a server-receive timestamp. Payloads stay opaque.
//!
//! ## Example
//! ```
//! use mx_messaging::MessagingService;
//! use mx_storage::{InMemoryUserStore, InMemoryGroupStore, InMemoryMessageQueue, UserStore,
//!     model::{User, Device}};
//! use mx_types::{Envelope, Recipient, MessageKind, Ciphertext, PublicKey};
//! use mx_types::crypto_material::KeyAlgo;
//!
//! # async fn run() -> mx_types::Result<()> {
//! let users = InMemoryUserStore::new();
//! let groups = InMemoryGroupStore::new();
//! let queue = InMemoryMessageQueue::new();
//!
//! let alice = User::new("alice");
//! let alice_id = alice.id;
//! users.create_user(alice).await?;
//! let key = PublicKey { algo: KeyAlgo::X25519, bytes: vec![1; 32] };
//! let device = Device::new(alice_id, key.clone());
//! let device_id = device.id;
//! users.register_device(device).await?;
//!
//! let svc = MessagingService::new(users, groups, queue);
//! let from = mx_types::DeviceId::new();
//! let env = Envelope::new(from, Recipient::Direct(alice_id), MessageKind::Chat,
//!     Ciphertext(vec![0xde, 0xad]), 0);
//! svc.ingest(env).await?;
//!
//! let delivered = svc.pull(device_id).await?;
//! assert_eq!(delivered.len(), 1);
//! # Ok(())
//! # }
//! ```

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use mx_storage::{GroupStore, MessageQueue, UserStore};
use mx_types::{
    Ciphertext, DeviceId, Envelope, Error, MessageKind, Recipient, Result, TimestampMs,
};

/// Message delivery service: ingest → per-device fan-out → drain.
///
/// Generic over the three storage traits it needs so it works identically against the
/// in-memory dev stores and any real DB backend. Holding the stores by value keeps the
/// service `Send + Sync` (each store already is) and avoids lifetime plumbing for callers.
pub struct MessagingService<U, G, Q>
where
    U: UserStore,
    G: GroupStore,
    Q: MessageQueue,
{
    users: U,
    groups: G,
    queue: Q,
}

impl<U, G, Q> MessagingService<U, G, Q>
where
    U: UserStore,
    G: GroupStore,
    Q: MessageQueue,
{
    /// Build a service over the given stores.
    pub fn new(users: U, groups: G, queue: Q) -> Self {
        Self {
            users,
            groups,
            queue,
        }
    }

    /// Accept an envelope from a sender and fan it out to recipient device queues.
    ///
    /// Behavior:
    /// 1. Validates the envelope (currently: a non-empty ciphertext — the server must not
    ///    route an empty payload, which would never be a legitimate E2E message).
    /// 2. Stamps a server-receive timestamp if the sender left [`Envelope::ts`] at `0`.
    /// 3. Resolves the recipient to a concrete set of devices and enqueues a clone of the
    ///    envelope to each.
    ///
    /// Returns the number of devices the envelope was delivered to. A direct message to a
    /// user with no registered devices (or an empty group) delivers to zero devices and is
    /// **not** an error — the envelope simply has nowhere to land yet.
    ///
    /// The ciphertext is never inspected beyond its (non-)emptiness; this layer is
    /// payload-blind by design.
    pub async fn ingest(&self, mut envelope: Envelope) -> Result<usize> {
        if envelope.ciphertext.0.is_empty() {
            return Err(Error::InvalidInput(
                "envelope ciphertext must not be empty".into(),
            ));
        }

        if envelope.ts == 0 {
            envelope.ts = now_ms();
        }

        let devices = self.resolve_devices(&envelope.to).await?;

        // Fan out: one queued copy per recipient device. We clone per device so each queue
        // owns its envelope; the cheap routing metadata + opaque ciphertext copy is the
        // price of multi-device delivery.
        let mut delivered = 0usize;
        for device in devices {
            self.queue.enqueue(device, envelope.clone()).await?;
            delivered += 1;
        }
        Ok(delivered)
    }

    /// Drain all queued envelopes for a connected device in FIFO order.
    ///
    /// Returns an empty `Vec` if nothing is pending. After this call the device's queue is
    /// empty (at-most-once handoff from the server's perspective; redelivery semantics, if
    /// any, are a higher-layer concern).
    pub async fn pull(&self, device: DeviceId) -> Result<Vec<Envelope>> {
        self.queue.drain(device).await
    }

    /// Public view of [`resolve_devices`](Self::resolve_devices): the set of devices an
    /// envelope to `to` would be delivered to. Used by the server to signal live sessions
    /// to pull immediately after an ingest (real-time delivery).
    pub async fn recipients(&self, to: &Recipient) -> Result<Vec<DeviceId>> {
        self.resolve_devices(to).await
    }

    /// Resolve a [`Recipient`] into the concrete, de-duplicated set of recipient devices.
    ///
    /// For a group, members are listed and each member's devices are gathered; a user
    /// appearing in a group does not cause duplicate enqueues even if listed twice.
    async fn resolve_devices(&self, to: &Recipient) -> Result<Vec<DeviceId>> {
        match to {
            Recipient::Direct(user) => {
                let devices = self.users.list_devices(*user).await?;
                Ok(devices.into_iter().map(|d| d.id).collect())
            }
            Recipient::Group(group) => {
                let members = self.groups.list_members(*group).await?;
                let mut seen = HashSet::new();
                let mut out = Vec::new();
                for member in members {
                    for device in self.users.list_devices(member).await? {
                        if seen.insert(device.id) {
                            out.push(device.id);
                        }
                    }
                }
                Ok(out)
            }
        }
    }

    /// Build (but do not send) a delivery-receipt control envelope acknowledging
    /// `acked_message` from `receipt_from` back toward `original_sender`'s user.
    ///
    /// Receipts are modeled as ordinary [`MessageKind::Control`] envelopes whose payload
    /// is itself E2E-encrypted by the caller — the server stays payload-blind. The caller
    /// supplies the already-encrypted receipt body in `ciphertext` and feeds the returned
    /// envelope back into [`ingest`](Self::ingest) to route it.
    ///
    /// This is a convenience constructor; it performs no I/O.
    pub fn build_receipt(
        receipt_from: DeviceId,
        original_sender_user: mx_types::UserId,
        _acked_message: mx_types::MessageId,
        ciphertext: Ciphertext,
    ) -> Envelope {
        Envelope::new(
            receipt_from,
            Recipient::Direct(original_sender_user),
            MessageKind::Control,
            ciphertext,
            now_ms(),
        )
    }
}

/// Current wall-clock time in milliseconds since the Unix epoch.
///
/// Clamped to a non-negative `i64`; on the practically-impossible pre-1970 clock it
/// returns `0`, which `ingest` treats as "unstamped" — harmless and self-correcting.
fn now_ms() -> TimestampMs {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as TimestampMs)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_storage::{
        model::{Device, User},
        InMemoryGroupStore, InMemoryMessageQueue, InMemoryUserStore,
    };
    use mx_types::crypto_material::KeyAlgo;
    use mx_types::{PublicKey, UserId};

    fn test_key() -> PublicKey {
        PublicKey {
            algo: KeyAlgo::X25519,
            bytes: vec![7u8; 32],
        }
    }

    /// Register a user with `n` devices; returns the user id and its device ids.
    async fn user_with_devices(users: &InMemoryUserStore, name: &str, n: usize) -> (UserId, Vec<DeviceId>) {
        let user = User::new(name);
        let uid = user.id;
        users.create_user(user).await.unwrap();
        let mut devs = Vec::new();
        for _ in 0..n {
            let d = Device::new(uid, test_key());
            let did = d.id;
            users.register_device(d).await.unwrap();
            devs.push(did);
        }
        (uid, devs)
    }

    fn chat_to(to: Recipient, payload: &[u8]) -> Envelope {
        Envelope::new(
            DeviceId::new(),
            to,
            MessageKind::Chat,
            Ciphertext(payload.to_vec()),
            0,
        )
    }

    #[tokio::test]
    async fn direct_message_fans_out_to_both_devices_fifo() {
        let users = InMemoryUserStore::new();
        let groups = InMemoryGroupStore::new();
        let queue = InMemoryMessageQueue::new();
        let (uid, devs) = user_with_devices(&users, "bob", 2).await;
        assert_eq!(devs.len(), 2);

        let svc = MessagingService::new(users, groups, queue);

        // Two messages so we can assert FIFO ordering on drain.
        let m1 = chat_to(Recipient::Direct(uid), b"first");
        let m2 = chat_to(Recipient::Direct(uid), b"second");
        let id1 = m1.id;
        let id2 = m2.id;

        assert_eq!(svc.ingest(m1).await.unwrap(), 2, "delivers to both devices");
        assert_eq!(svc.ingest(m2).await.unwrap(), 2);

        for &d in &devs {
            let pulled = svc.pull(d).await.unwrap();
            assert_eq!(pulled.len(), 2, "each device got both messages");
            // FIFO: first enqueued comes out first.
            assert_eq!(pulled[0].id, id1);
            assert_eq!(pulled[1].id, id2);
            assert_eq!(pulled[0].ciphertext.0, b"first");
            // Draining empties the queue.
            assert!(svc.pull(d).await.unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn group_message_fans_out_to_all_member_devices() {
        let users = InMemoryUserStore::new();
        let groups = InMemoryGroupStore::new();
        let queue = InMemoryMessageQueue::new();

        let (alice, alice_devs) = user_with_devices(&users, "alice", 2).await;
        let (bob, bob_devs) = user_with_devices(&users, "bob", 1).await;

        let gid = mx_types::GroupId::new();
        groups.create_group(gid, vec![alice, bob]).await.unwrap();

        let svc = MessagingService::new(users, groups, queue);

        let delivered = svc
            .ingest(chat_to(Recipient::Group(gid), b"hello group"))
            .await
            .unwrap();
        assert_eq!(delivered, 3, "2 alice devices + 1 bob device");

        for d in alice_devs.iter().chain(bob_devs.iter()) {
            let pulled = svc.pull(*d).await.unwrap();
            assert_eq!(pulled.len(), 1);
            assert_eq!(pulled[0].ciphertext.0, b"hello group");
        }
    }

    #[tokio::test]
    async fn ingest_stamps_zero_timestamp() {
        let users = InMemoryUserStore::new();
        let groups = InMemoryGroupStore::new();
        let queue = InMemoryMessageQueue::new();
        let (uid, devs) = user_with_devices(&users, "carol", 1).await;
        let svc = MessagingService::new(users, groups, queue);

        svc.ingest(chat_to(Recipient::Direct(uid), b"x")).await.unwrap();
        let pulled = svc.pull(devs[0]).await.unwrap();
        assert!(pulled[0].ts > 0, "zero ts should be stamped on ingest");
    }

    #[tokio::test]
    async fn ingest_preserves_nonzero_timestamp() {
        let users = InMemoryUserStore::new();
        let groups = InMemoryGroupStore::new();
        let queue = InMemoryMessageQueue::new();
        let (uid, devs) = user_with_devices(&users, "dave", 1).await;
        let svc = MessagingService::new(users, groups, queue);

        let mut env = chat_to(Recipient::Direct(uid), b"x");
        env.ts = 4242;
        svc.ingest(env).await.unwrap();
        let pulled = svc.pull(devs[0]).await.unwrap();
        assert_eq!(pulled[0].ts, 4242, "sender ts must be preserved");
    }

    #[tokio::test]
    async fn empty_ciphertext_is_rejected() {
        let users = InMemoryUserStore::new();
        let groups = InMemoryGroupStore::new();
        let queue = InMemoryMessageQueue::new();
        let (uid, _) = user_with_devices(&users, "erin", 1).await;
        let svc = MessagingService::new(users, groups, queue);

        let err = svc
            .ingest(chat_to(Recipient::Direct(uid), b""))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[tokio::test]
    async fn direct_to_user_with_no_devices_delivers_zero() {
        let users = InMemoryUserStore::new();
        let groups = InMemoryGroupStore::new();
        let queue = InMemoryMessageQueue::new();
        let (uid, _) = user_with_devices(&users, "frank", 0).await;
        let svc = MessagingService::new(users, groups, queue);

        assert_eq!(
            svc.ingest(chat_to(Recipient::Direct(uid), b"x")).await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn build_receipt_is_a_control_envelope() {
        let from = DeviceId::new();
        let to_user = UserId::new();
        let msg = mx_types::MessageId::new();
        let r = MessagingService::<InMemoryUserStore, InMemoryGroupStore, InMemoryMessageQueue>::build_receipt(
            from,
            to_user,
            msg,
            Ciphertext(vec![1, 2, 3]),
        );
        assert_eq!(r.kind, MessageKind::Control);
        assert_eq!(r.to, Recipient::Direct(to_user));
        assert_eq!(r.from, from);
        assert!(r.ts > 0);
    }
}
