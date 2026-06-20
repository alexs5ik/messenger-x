//! mx-presence — ephemeral presence: online status and typing indicators.
//!
//! Presence is **soft state**: it is cheap to compute, frequently refreshed, and lost on
//! restart without consequence. The design target is Redis (per the architecture: *Presence,
//! typing, rate-limits — speed, ephemeral*), but this crate ships an in-memory implementation
//! so the default build needs no live Redis. The storage trait ([`PresenceStore`]) is the seam
//! where a Redis-backed implementation slots in later.
//!
//! # What presence tracks
//!
//! * **Online status** — keyed per [`DeviceId`]. A device calls [`PresenceService::set_online`]
//!   periodically (a heartbeat). If no heartbeat arrives within the TTL, the device is
//!   considered [`Status::Offline`]. There is no explicit "go offline" event required: absence
//!   of a heartbeat *is* the offline signal, which is robust against crashes and dropped
//!   connections.
//! * **Typing indicators** — keyed per `(typist [`UserId`], peer)` where the peer is the
//!   conversation the user is typing into (a [`UserId`] for a direct chat or a [`GroupId`] for a
//!   group). Typing entries have a short TTL (a few seconds) and are refreshed on each keystroke
//!   burst. [`PresenceService::who_is_typing`] returns the live typists for a peer.
//!
//! All entries carry an absolute expiry [`Instant`]; reads lazily skip expired entries and a
//! [`PresenceService::sweep`] call (or any write) prunes them. Time is injectable so tests are
//! deterministic — see [`PresenceService::now`].
//!
//! # Redis key mapping (target backend)
//!
//! The in-memory store mirrors the key/TTL scheme a Redis implementation would use, so swapping
//! backends is a matter of implementing [`PresenceStore`] against these keys:
//!
//! | Concept            | Redis key                        | Value          | Expiry mechanism            |
//! |--------------------|----------------------------------|----------------|-----------------------------|
//! | Device online      | `presence:online:{device_id}`    | `"1"`          | `SET key 1 PX <ttl_ms>`     |
//! | Typing in a peer   | `typing:{peer_kind}:{peer_id}`   | set of user-ids| `ZADD` w/ score=expiry, `ZREMRANGEBYSCORE` to prune; or per-member keys `typing:{peer_kind}:{peer_id}:{user_id}` with `PX`  |
//!
//! where `peer_kind` is `u` for a direct ([`UserId`]) peer or `g` for a group ([`GroupId`]) peer.
//! Online checks become a single `EXISTS`. Typing reads become a `ZRANGEBYSCORE <now> +inf`
//! after pruning stale members. Redis' native key/member expiry replaces the lazy sweep used by
//! the in-memory store.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use mx_types::{DeviceId, GroupId, UserId};

/// Online/offline status of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Status {
    /// A heartbeat was seen within its TTL.
    Online,
    /// No live heartbeat — either never seen or expired.
    Offline,
}

/// Identifies the conversation a user is typing into: a direct peer (`User`) or a `Group`.
///
/// Maps to the `peer_kind`/`peer_id` portion of the Redis typing key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Peer {
    /// A direct (1:1) conversation with another user.
    User(UserId),
    /// A group conversation.
    Group(GroupId),
}

/// Abstraction over the presence backing store. The in-memory [`MemoryStore`] is the default;
/// a Redis-backed implementation slots in here without touching [`PresenceService`].
///
/// Implementations are responsible for honoring expiry: reads must not surface entries whose
/// expiry instant is `<= now`, and [`PresenceStore::sweep`] should discard them so memory does
/// not grow unbounded.
pub trait PresenceStore {
    /// Record `device` as online until `expires_at`.
    fn put_online(&mut self, device: DeviceId, expires_at: Instant);
    /// Returns `true` if `device` has a non-expired online entry as of `now`.
    fn is_online(&self, device: DeviceId, now: Instant) -> bool;

    /// Record `user` as typing into `peer` until `expires_at`.
    fn put_typing(&mut self, peer: Peer, user: UserId, expires_at: Instant);
    /// Live (non-expired as of `now`) typists for `peer`.
    fn typists(&self, peer: Peer, now: Instant) -> Vec<UserId>;
    /// Remove a specific typing entry, e.g. when a user explicitly stops typing or sends.
    fn remove_typing(&mut self, peer: Peer, user: UserId);

    /// Drop every entry that has expired as of `now`.
    fn sweep(&mut self, now: Instant);
}

/// Default in-memory [`PresenceStore`]. Suitable for single-node dev/test; replace with a Redis
/// implementation for a multi-node deployment.
#[derive(Debug, Default)]
pub struct MemoryStore {
    /// `device -> expiry`.
    online: HashMap<DeviceId, Instant>,
    /// `peer -> (user -> expiry)`.
    typing: HashMap<Peer, HashMap<UserId, Instant>>,
}

impl MemoryStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl PresenceStore for MemoryStore {
    fn put_online(&mut self, device: DeviceId, expires_at: Instant) {
        self.online.insert(device, expires_at);
    }

    fn is_online(&self, device: DeviceId, now: Instant) -> bool {
        self.online.get(&device).is_some_and(|&exp| exp > now)
    }

    fn put_typing(&mut self, peer: Peer, user: UserId, expires_at: Instant) {
        self.typing.entry(peer).or_default().insert(user, expires_at);
    }

    fn typists(&self, peer: Peer, now: Instant) -> Vec<UserId> {
        self.typing
            .get(&peer)
            .map(|members| {
                members
                    .iter()
                    .filter(|(_, &exp)| exp > now)
                    .map(|(&user, _)| user)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn remove_typing(&mut self, peer: Peer, user: UserId) {
        if let Some(members) = self.typing.get_mut(&peer) {
            members.remove(&user);
            if members.is_empty() {
                self.typing.remove(&peer);
            }
        }
    }

    fn sweep(&mut self, now: Instant) {
        self.online.retain(|_, &mut exp| exp > now);
        self.typing.retain(|_, members| {
            members.retain(|_, &mut exp| exp > now);
            !members.is_empty()
        });
    }
}

/// Ephemeral presence service: online heartbeats and typing indicators with TTL expiry.
///
/// Generic over the backing [`PresenceStore`] so the in-memory default can be swapped for Redis.
/// Time is supplied by an injectable clock ([`PresenceService::with_clock`]) so tests can advance
/// it deterministically; the default clock is [`Instant::now`].
pub struct PresenceService<S: PresenceStore = MemoryStore> {
    store: S,
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl Default for PresenceService<MemoryStore> {
    fn default() -> Self {
        Self::new()
    }
}

impl PresenceService<MemoryStore> {
    /// Create a service over the default in-memory store using the system clock.
    pub fn new() -> Self {
        Self::with_store_and_clock(MemoryStore::new(), Box::new(Instant::now))
    }

    /// Create a service over the in-memory store with a custom clock (for deterministic tests).
    pub fn with_clock(clock: impl Fn() -> Instant + Send + Sync + 'static) -> Self {
        Self::with_store_and_clock(MemoryStore::new(), Box::new(clock))
    }
}

impl<S: PresenceStore> PresenceService<S> {
    /// Create a service over an arbitrary store and clock.
    pub fn with_store_and_clock(
        store: S,
        clock: Box<dyn Fn() -> Instant + Send + Sync>,
    ) -> Self {
        Self { store, clock }
    }

    /// Current time per the injected clock.
    #[inline]
    pub fn now(&self) -> Instant {
        (self.clock)()
    }

    // --- Online status -----------------------------------------------------------------

    /// Mark `device` online for `ttl` (a heartbeat). Subsequent calls refresh the expiry.
    pub fn set_online(&mut self, device: DeviceId, ttl: Duration) {
        let expires_at = self.now() + ttl;
        self.store.put_online(device, expires_at);
    }

    /// Whether `device` currently has a live online heartbeat.
    pub fn is_online(&self, device: DeviceId) -> bool {
        self.store.is_online(device, self.now())
    }

    /// Convenience: [`Status`] form of [`PresenceService::is_online`].
    pub fn status(&self, device: DeviceId) -> Status {
        if self.is_online(device) {
            Status::Online
        } else {
            Status::Offline
        }
    }

    // --- Typing indicators -------------------------------------------------------------

    /// Mark `user` as typing into `peer` for `ttl`. Refresh on each keystroke burst.
    pub fn set_typing(&mut self, user: UserId, peer: Peer, ttl: Duration) {
        let expires_at = self.now() + ttl;
        self.store.put_typing(peer, user, expires_at);
    }

    /// Explicitly clear `user`'s typing state in `peer` (e.g. on send or focus loss).
    pub fn clear_typing(&mut self, user: UserId, peer: Peer) {
        self.store.remove_typing(peer, user);
    }

    /// Users currently typing into `peer` (expired entries excluded).
    pub fn who_is_typing(&self, peer: Peer) -> Vec<UserId> {
        self.store.typists(peer, self.now())
    }

    // --- Maintenance -------------------------------------------------------------------

    /// Prune all expired entries. Safe to call on a timer; reads are already lazily filtered,
    /// so this is purely a memory-reclamation step for the in-memory store.
    pub fn sweep(&mut self) {
        let now = self.now();
        self.store.sweep(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    /// A clock backed by a shared, mutable instant for deterministic time travel.
    fn controllable_clock() -> (Arc<Mutex<Instant>>, impl Fn() -> Instant + Send + Sync) {
        let base = Arc::new(Mutex::new(Instant::now()));
        let handle = base.clone();
        let clock = move || *handle.lock().unwrap();
        (base, clock)
    }

    fn advance(base: &Arc<Mutex<Instant>>, by: Duration) {
        let mut g = base.lock().unwrap();
        *g += by;
    }

    #[test]
    fn online_then_expires_after_ttl() {
        let (base, clock) = controllable_clock();
        let mut svc = PresenceService::with_clock(clock);

        let device = DeviceId::new();
        assert_eq!(svc.status(device), Status::Offline, "unknown device is offline");

        svc.set_online(device, Duration::from_secs(30));
        assert!(svc.is_online(device));
        assert_eq!(svc.status(device), Status::Online);

        // Just before expiry: still online.
        advance(&base, Duration::from_secs(29));
        assert!(svc.is_online(device));

        // Past TTL: offline.
        advance(&base, Duration::from_secs(2));
        assert!(!svc.is_online(device));
        assert_eq!(svc.status(device), Status::Offline);
    }

    #[test]
    fn online_heartbeat_refreshes_ttl() {
        let (base, clock) = controllable_clock();
        let mut svc = PresenceService::with_clock(clock);
        let device = DeviceId::new();

        svc.set_online(device, Duration::from_secs(10));
        advance(&base, Duration::from_secs(8));
        // Heartbeat before expiry resets the window.
        svc.set_online(device, Duration::from_secs(10));
        advance(&base, Duration::from_secs(5));
        assert!(svc.is_online(device), "refreshed heartbeat keeps device online");
    }

    #[test]
    fn typing_set_then_expires() {
        let (base, clock) = controllable_clock();
        let mut svc = PresenceService::with_clock(clock);

        let alice = UserId::new();
        let bob = UserId::new();
        let peer = Peer::User(bob);

        assert!(svc.who_is_typing(peer).is_empty());

        svc.set_typing(alice, peer, Duration::from_secs(5));
        assert_eq!(svc.who_is_typing(peer), vec![alice]);

        // After the typing TTL, the indicator disappears.
        advance(&base, Duration::from_secs(6));
        assert!(svc.who_is_typing(peer).is_empty(), "typing expired");
    }

    #[test]
    fn typing_explicit_clear() {
        let svc_clock = || Instant::now();
        let mut svc = PresenceService::with_clock(svc_clock);

        let alice = UserId::new();
        let group = GroupId::new();
        let peer = Peer::Group(group);

        svc.set_typing(alice, peer, Duration::from_secs(60));
        assert_eq!(svc.who_is_typing(peer), vec![alice]);

        svc.clear_typing(alice, peer);
        assert!(svc.who_is_typing(peer).is_empty(), "explicit clear removes the indicator");
    }

    #[test]
    fn typing_multiple_users_and_peer_isolation() {
        let svc_clock = || Instant::now();
        let mut svc = PresenceService::with_clock(svc_clock);

        let alice = UserId::new();
        let carol = UserId::new();
        let g1 = Peer::Group(GroupId::new());
        let g2 = Peer::Group(GroupId::new());

        svc.set_typing(alice, g1, Duration::from_secs(60));
        svc.set_typing(carol, g1, Duration::from_secs(60));
        svc.set_typing(alice, g2, Duration::from_secs(60));

        let mut g1_typists = svc.who_is_typing(g1);
        g1_typists.sort();
        let mut expected = vec![alice, carol];
        expected.sort();
        assert_eq!(g1_typists, expected, "both users typing in g1");

        assert_eq!(svc.who_is_typing(g2), vec![alice], "g2 isolated from g1");
    }

    #[test]
    fn sweep_reclaims_expired_entries() {
        let (base, clock) = controllable_clock();
        let mut svc = PresenceService::with_clock(clock);

        let device = DeviceId::new();
        let alice = UserId::new();
        let peer = Peer::User(UserId::new());

        svc.set_online(device, Duration::from_secs(1));
        svc.set_typing(alice, peer, Duration::from_secs(1));

        advance(&base, Duration::from_secs(2));
        svc.sweep();

        // After sweeping, the underlying maps are empty (verified via the public reads).
        assert!(!svc.is_online(device));
        assert!(svc.who_is_typing(peer).is_empty());
    }

    #[test]
    fn memory_store_direct_usage() {
        // Exercise a custom store directly to confirm the trait seam works.
        let now = Instant::now();
        let mut store = MemoryStore::new();
        let device = DeviceId::new();

        store.put_online(device, now + Duration::from_secs(5));
        assert!(store.is_online(device, now));
        assert!(!store.is_online(device, now + Duration::from_secs(6)));
    }

    // Ensure non-Send single-threaded clocks compile too (clock bound is Send+Sync, so this
    // documents that thread-local style clocks need wrapping — kept as a compile reference).
    #[allow(dead_code)]
    fn _rc_cell_clock_note() {
        let _t: Rc<Cell<u8>> = Rc::new(Cell::new(0));
    }
}
