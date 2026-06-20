//! The message envelope — the unit the backend stores and routes. Its [`Ciphertext`]
//! payload is opaque to the server (end-to-end encrypted). Only the routing metadata is
//! visible, and even that is minimized (see design doc §6/§7 on metadata minimization).

use serde::{Deserialize, Serialize};

use crate::crypto_material::Ciphertext;
use crate::ids::{DeviceId, GroupId, MessageId, UserId};
use crate::TimestampMs;

/// Where an envelope is headed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Recipient {
    /// A 1:1 conversation, fanned out per recipient device.
    Direct(UserId),
    /// A group/community using MLS group keys.
    Group(GroupId),
}

/// Coarse classification of the payload, visible to the server for routing/UX only. The
/// actual content stays inside the ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    /// Normal user-visible message (text, media reference, etc.).
    Chat,
    /// Protocol control (key update, receipt, typing) — not user content.
    Control,
    /// MLS handshake/commit message for group key management.
    GroupHandshake,
}

/// The end-to-end encrypted message envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub id: MessageId,
    /// Sending device (sealed-sender will later hide this; kept explicit for v0).
    pub from: DeviceId,
    pub to: Recipient,
    pub kind: MessageKind,
    /// Opaque encrypted payload — the server never holds the key to open this.
    pub ciphertext: Ciphertext,
    /// Server-receive timestamp (ms since epoch).
    pub ts: TimestampMs,
}

impl Envelope {
    /// Construct a new envelope with a fresh id.
    pub fn new(
        from: DeviceId,
        to: Recipient,
        kind: MessageKind,
        ciphertext: Ciphertext,
        ts: TimestampMs,
    ) -> Self {
        Self {
            id: MessageId::new(),
            from,
            to,
            kind,
            ciphertext,
            ts,
        }
    }
}
