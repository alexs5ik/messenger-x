//! # mx-storage — persistence for Messenger X
//!
//! Storage is expressed as a set of **async trait abstractions** ([`UserStore`],
//! [`PreKeyStore`], [`MessageQueue`], [`GroupStore`]) with working **in-memory
//! implementations** so the entire modular monolith runs and is testable without any live
//! database. Concrete database backends live behind cargo features and act as a *seam*:
//!
//! - default build → in-memory only, zero external dependencies at runtime.
//! - `postgres` → a `sqlx`-backed [`postgres::PostgresStore`] skeleton (compiles offline).
//! - `redis` → a `redis`-backed [`redis::RedisMessageQueue`] skeleton (compiles offline).
//!
//! Across all backends, the core principle holds: the server persists/routes **ciphertext
//! only**. [`Envelope`](mx_types::Envelope) payloads are end-to-end encrypted and opaque
//! to this layer, and group state is kept as an opaque `Vec<u8>` blob.
//!
//! ## Example
//! ```
//! use mx_storage::{InMemoryUserStore, UserStore, model::User};
//!
//! # async fn run() -> mx_types::Result<()> {
//! let store = InMemoryUserStore::new();
//! let user = User::new("alice");
//! let id = user.id;
//! store.create_user(user).await?;
//! let fetched = store.get_user(id).await?;
//! assert_eq!(fetched.username, "alice");
//! # Ok(())
//! # }
//! ```

pub mod memory;
pub mod model;
pub mod traits;

#[cfg(feature = "postgres")]
pub mod postgres;

#[cfg(feature = "redis")]
pub mod redis;

// Re-export the public surface so callers write `mx_storage::UserStore` etc.
pub use memory::{
    InMemoryGroupStore, InMemoryMessageQueue, InMemoryPreKeyStore, InMemoryUserStore,
};
pub use model::{Device, User};
pub use traits::{GroupStore, MessageQueue, PreKeyStore, UserStore};
