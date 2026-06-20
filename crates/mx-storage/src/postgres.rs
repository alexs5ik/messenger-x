//! Postgres-backed storage skeleton (feature `postgres`).
//!
//! This module is a *thin seam*, not a finished backend. It compiles with `sqlx` but does
//! **not** require a live database to build (no compile-time-checked query macros are
//! used). Each trait method is wired to a pool and returns a clear "not yet implemented"
//! [`mx_types::Error`] so the seam is visible and callable, and the real SQL can be filled
//! in incrementally against the schema in design doc §6 without changing any signatures.
//!
//! Tables this backend will own (per §5/§6): accounts, devices, prekey bundles, MLS group
//! state + membership. Per the core principle it stores **ciphertext only** for messages;
//! the message queue at scale moves to Redis/Kafka rather than Postgres.

use async_trait::async_trait;
use mx_types::{DeviceId, Envelope, Error, GroupId, PreKeyBundle, Result, UserId};
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::model::{Device, User};
use crate::traits::{GroupStore, MessageQueue, PreKeyStore, UserStore};

/// A Postgres-backed store implementing all storage traits over a shared pool.
#[derive(Debug, Clone)]
pub struct PostgresStore {
    #[allow(dead_code)] // held for the real query implementations to come.
    pool: PgPool,
}

impl PostgresStore {
    /// Connect to Postgres at `database_url` and build a pool.
    ///
    /// Note: this *connects* (so it needs a live DB at runtime), but the crate still
    /// *compiles* without one, which is the requirement for the default/dev build.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(database_url)
            .await
            .map_err(|e| Error::Storage(format!("postgres connect: {e}")))?;
        Ok(Self { pool })
    }

    /// Wrap an externally-managed pool (e.g. shared across stores).
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Uniform placeholder for skeleton methods awaiting their SQL.
fn todo_err(what: &str) -> Error {
    Error::Storage(format!("postgres backend: {what} not yet implemented"))
}

#[async_trait]
impl UserStore for PostgresStore {
    async fn create_user(&self, _user: User) -> Result<()> {
        Err(todo_err("create_user"))
    }
    async fn get_user(&self, _id: UserId) -> Result<User> {
        Err(todo_err("get_user"))
    }
    async fn register_device(&self, _device: Device) -> Result<()> {
        Err(todo_err("register_device"))
    }
    async fn list_devices(&self, _user: UserId) -> Result<Vec<Device>> {
        Err(todo_err("list_devices"))
    }
}

#[async_trait]
impl PreKeyStore for PostgresStore {
    async fn publish_bundle(&self, _bundle: PreKeyBundle) -> Result<()> {
        Err(todo_err("publish_bundle"))
    }
    async fn fetch_and_consume(&self, _device: DeviceId) -> Result<PreKeyBundle> {
        Err(todo_err("fetch_and_consume"))
    }
    async fn get_bundle(&self, _device: DeviceId) -> Result<PreKeyBundle> {
        Err(todo_err("get_bundle"))
    }
}

#[async_trait]
impl MessageQueue for PostgresStore {
    async fn enqueue(&self, _device: DeviceId, _envelope: Envelope) -> Result<()> {
        Err(todo_err("enqueue"))
    }
    async fn drain(&self, _device: DeviceId) -> Result<Vec<Envelope>> {
        Err(todo_err("drain"))
    }
}

#[async_trait]
impl GroupStore for PostgresStore {
    async fn create_group(&self, _group: GroupId, _members: Vec<UserId>) -> Result<()> {
        Err(todo_err("create_group"))
    }
    async fn save_state(&self, _group: GroupId, _state: Vec<u8>) -> Result<()> {
        Err(todo_err("save_state"))
    }
    async fn get_state(&self, _group: GroupId) -> Result<Vec<u8>> {
        Err(todo_err("get_state"))
    }
    async fn list_members(&self, _group: GroupId) -> Result<Vec<UserId>> {
        Err(todo_err("list_members"))
    }
}
