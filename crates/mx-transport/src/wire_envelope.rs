//! Wire adapter for [`mx_types::Envelope`].
//!
//! ## Why this exists
//!
//! The shared contract crate `mx-types` (which this crate must not modify) declares
//! [`mx_types::Recipient`] as an **internally tagged** enum whose variants wrap newtype
//! ids:
//!
//! ```ignore
//! #[serde(tag = "kind", rename_all = "snake_case")]
//! pub enum Recipient { Direct(UserId), Group(GroupId) }
//! ```
//!
//! `serde_json` cannot serialize an internally-tagged enum whose variant payload is a
//! *non-map* value (a `UserId` serializes as a JSON **string**). So a bare
//! `serde_json::to_vec(&envelope)` fails at runtime with
//! *"cannot serialize tagged newtype variant Recipient::Direct containing a string"*.
//!
//! Because the transport spec mandates JSON via `serde_json` **and** that every
//! `ClientMessage` / `ServerMessage` variant — including the ones carrying an
//! [`Envelope`] — round-trips, this module provides a JSON-safe mirror of the envelope
//! and a `serde(with = ...)` module so the public message types keep carrying the real
//! [`mx_types::Envelope`] while the bytes on the wire use an externally-tagged recipient
//! that `serde_json` handles cleanly. No `mx-types` code is touched.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use mx_types::{Ciphertext, DeviceId, Envelope, GroupId, MessageId, MessageKind, Recipient, UserId};

/// JSON-safe mirror of [`mx_types::Recipient`] using **external** tagging
/// (`{"direct":"<uuid>"}` / `{"group":"<uuid>"}`), which `serde_json` serializes without
/// the internal-tag newtype limitation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireRecipient {
    Direct(UserId),
    Group(GroupId),
}

impl From<&Recipient> for WireRecipient {
    fn from(r: &Recipient) -> Self {
        match r {
            Recipient::Direct(u) => WireRecipient::Direct(*u),
            Recipient::Group(g) => WireRecipient::Group(*g),
        }
    }
}

impl From<WireRecipient> for Recipient {
    fn from(r: WireRecipient) -> Self {
        match r {
            WireRecipient::Direct(u) => Recipient::Direct(u),
            WireRecipient::Group(g) => Recipient::Group(g),
        }
    }
}

/// JSON-safe mirror of [`mx_types::Envelope`]. Field-for-field identical except the
/// recipient uses [`WireRecipient`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WireEnvelope {
    id: MessageId,
    from: DeviceId,
    to: WireRecipient,
    kind: MessageKind,
    ciphertext: Ciphertext,
    ts: i64,
}

impl From<&Envelope> for WireEnvelope {
    fn from(e: &Envelope) -> Self {
        WireEnvelope {
            id: e.id,
            from: e.from,
            to: (&e.to).into(),
            kind: e.kind,
            ciphertext: e.ciphertext.clone(),
            ts: e.ts,
        }
    }
}

impl From<WireEnvelope> for Envelope {
    fn from(w: WireEnvelope) -> Self {
        Envelope {
            id: w.id,
            from: w.from,
            to: w.to.into(),
            kind: w.kind,
            ciphertext: w.ciphertext,
            ts: w.ts,
        }
    }
}

/// `#[serde(with = "self")]`-compatible serializer for an [`Envelope`] field, routing
/// through [`WireEnvelope`] so the bytes are JSON-safe.
pub fn serialize<S>(env: &Envelope, ser: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    WireEnvelope::from(env).serialize(ser)
}

/// Companion deserializer for an [`Envelope`] field.
pub fn deserialize<'de, D>(de: D) -> Result<Envelope, D::Error>
where
    D: Deserializer<'de>,
{
    WireEnvelope::deserialize(de).map(Envelope::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(to: Recipient) -> Envelope {
        Envelope::new(
            DeviceId::new(),
            to,
            MessageKind::Chat,
            Ciphertext(vec![9, 8, 7]),
            123,
        )
    }

    #[test]
    fn direct_envelope_round_trips_via_wire() {
        let e = env(Recipient::Direct(UserId::new()));
        let json = serde_json::to_vec(&WireEnvelope::from(&e)).unwrap();
        let back: Envelope = serde_json::from_slice::<WireEnvelope>(&json).unwrap().into();
        assert_eq!(e, back);
    }

    #[test]
    fn group_envelope_round_trips_via_wire() {
        let e = env(Recipient::Group(GroupId::new()));
        let json = serde_json::to_vec(&WireEnvelope::from(&e)).unwrap();
        let back: Envelope = serde_json::from_slice::<WireEnvelope>(&json).unwrap().into();
        assert_eq!(e, back);
    }
}
