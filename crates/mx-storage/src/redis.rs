//! Redis-backed storage skeleton (feature `redis`).
//!
//! A thin seam for the ephemeral/low-latency stores Redis owns per design doc §5/§6:
//! per-device delivery queues (offline message fan-out) and, later, presence/sessions.
//! As with the Postgres skeleton, this compiles against the `redis` crate but needs no
//! live server to build; methods return a clear "not yet implemented" error until the
//! commands are filled in.

use async_trait::async_trait;
use mx_types::{DeviceId, Envelope, Error, Result};
use redis::aio::MultiplexedConnection;
use redis::Client;

use crate::traits::MessageQueue;

/// A Redis-backed [`MessageQueue`]. Envelopes will be stored as serialized blobs in a
/// per-device list (`LPUSH`/`LRANGE`+`DEL` for FIFO drain).
#[derive(Clone)]
pub struct RedisMessageQueue {
    #[allow(dead_code)] // held for the real command implementations to come.
    conn: MultiplexedConnection,
}

impl RedisMessageQueue {
    /// Connect to Redis at `url` (e.g. `redis://127.0.0.1/`) and obtain a multiplexed
    /// async connection.
    pub async fn connect(url: &str) -> Result<Self> {
        let client =
            Client::open(url).map_err(|e| Error::Storage(format!("redis open: {e}")))?;
        let conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| Error::Storage(format!("redis connect: {e}")))?;
        Ok(Self { conn })
    }
}

fn todo_err(what: &str) -> Error {
    Error::Storage(format!("redis backend: {what} not yet implemented"))
}

#[async_trait]
impl MessageQueue for RedisMessageQueue {
    async fn enqueue(&self, _device: DeviceId, _envelope: Envelope) -> Result<()> {
        Err(todo_err("enqueue"))
    }
    async fn drain(&self, _device: DeviceId) -> Result<Vec<Envelope>> {
        Err(todo_err("drain"))
    }
}
