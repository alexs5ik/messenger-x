//! Lightweight file-snapshot persistence for the in-memory stores.
//!
//! The default dev deployment keeps state in memory, which means a server restart loses all
//! accounts — a surprising failure mode (clients hold still-valid tokens but the server no
//! longer knows their users, so messages route nowhere). This module snapshots the *durable*
//! state — users, devices, pre-key bundles, and group rosters/state — to a JSON file so a
//! restart is non-destructive. Message queues are intentionally **not** persisted: undelivered
//! envelopes are transient, and skipping them keeps the snapshot free of the wire `Envelope`
//! type (whose internally-tagged `Recipient` is not plain-`serde_json`-serializable).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use mx_types::{GroupId, PreKeyBundle, UserId};

use crate::memory::{InMemoryGroupStore, InMemoryPreKeyStore, InMemoryUserStore};
use crate::model::{Device, User};

/// A group's persistable record.
#[derive(Serialize, Deserialize)]
pub struct GroupSnapshot {
    pub id: GroupId,
    pub members: Vec<UserId>,
    pub state: Option<Vec<u8>>,
}

/// The full durable snapshot written to disk.
#[derive(Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub users: Vec<User>,
    pub devices: Vec<Device>,
    pub prekeys: Vec<PreKeyBundle>,
    pub groups: Vec<GroupSnapshot>,
}

impl Snapshot {
    /// Capture the current durable state from the stores.
    pub async fn capture(
        users: &InMemoryUserStore,
        prekeys: &InMemoryPreKeyStore,
        groups: &InMemoryGroupStore,
    ) -> Self {
        let (us, devs) = users.export().await;
        Snapshot {
            users: us,
            devices: devs,
            prekeys: prekeys.export().await,
            groups: groups
                .export()
                .await
                .into_iter()
                .map(|(id, members, state)| GroupSnapshot { id, members, state })
                .collect(),
        }
    }

    /// Apply a snapshot into the stores, replacing their contents.
    pub async fn apply(
        self,
        users: &InMemoryUserStore,
        prekeys: &InMemoryPreKeyStore,
        groups: &InMemoryGroupStore,
    ) {
        users.import(self.users, self.devices).await;
        prekeys.import(self.prekeys).await;
        groups
            .import(
                self.groups
                    .into_iter()
                    .map(|g| (g.id, g.members, g.state))
                    .collect(),
            )
            .await;
    }

    /// Load a snapshot from `path`. Returns `None` if the file does not exist; an error only
    /// for a present-but-unreadable/corrupt file.
    pub fn load(path: &Path) -> std::io::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let snap = serde_json::from_slice(&bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(Some(snap))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Write the snapshot to `path` atomically (write to a temp file, then rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp: PathBuf = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self).map_err(io_err)?)?;
        std::fs::rename(&tmp, path)
    }
}

fn io_err(e: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}
