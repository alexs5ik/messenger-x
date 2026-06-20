//! # mx-transport — client ↔ server wire framing
//!
//! Defines the message types exchanged between a Messenger X client and the server's
//! gateway, plus the (de)serialization [`codec`] used to put them on the wire. The
//! types are **transport-agnostic**: they carry no dependency on any WebSocket / QUIC
//! library, so the server gateway and any client can reuse them over whatever socket
//! they choose.
//!
//! ## Transport roadmap (design doc §4)
//!
//! - **WebSocket is the primary transport today.** Frames are JSON-encoded (see
//!   [`codec`]) and ride one logical WS connection per device.
//! - **QUIC / HTTP3 is experimental, planned later** (0-RTT reconnect, no
//!   head-of-line blocking, better on lossy mobile networks). When it lands it reuses
//!   *these same* [`ClientMessage`] / [`ServerMessage`] types — only the byte pipe
//!   changes. A direct A/B of QUIC vs WS for messaging is still open per §4, so both
//!   are designed in and measured in production.
//!
//! ## End-to-end encryption boundary
//!
//! Message payloads travel as [`Envelope`]s whose [`mx_types::Ciphertext`] body is
//! opaque to the server. This crate only frames and routes; it never inspects or
//! decrypts content.
//!
//! ## Wire shape
//!
//! Both top-level enums are **adjacently tagged** with a `"t"` discriminator and a `"d"`
//! payload field, so a frame looks like `{"t":"send","d":{…}}` or `{"t":"ack","d":"…"}`.
//! Adjacent tagging (rather than internal) is required because several variants wrap
//! values that don't serialize as JSON objects (e.g. a [`MessageId`] is a string and an
//! [`Envelope`]'s [`Recipient`] is itself tagged). It keeps frames self-describing and
//! forward-compatible — unknown variant tags fail to decode rather than silently
//! mis-parsing.

use serde::{Deserialize, Serialize};

use mx_types::{Envelope, MessageId, UserId};

pub mod codec;
pub mod wire_envelope;

pub use codec::{from_bytes, to_bytes};

/// A message sent **from a client to the server**.
///
/// The `t` tag selects the variant and `d` carries its payload on the wire
/// (e.g. `{"t":"hello","d":{"token":"…"}}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", content = "d", rename_all = "snake_case")]
pub enum ClientMessage {
    /// First frame after connecting: authenticate the session with a bearer token.
    /// The token is validated by `mx-auth`; the transport layer only carries it.
    Hello {
        /// Opaque auth/bearer token issued at login.
        token: String,
    },

    /// Submit an end-to-end encrypted envelope for delivery / fan-out.
    Send(#[serde(with = "wire_envelope")] Envelope),

    /// Acknowledge that the client received and persisted an [`ServerMessage::Incoming`]
    /// envelope with this id (delivery receipt at the transport layer).
    Ack(MessageId),

    /// Presence update advertised by the client (e.g. going online/away).
    Presence(PresenceState),

    /// Typing indicator addressed at a peer the client is in conversation with.
    Typing(TypingIndicator),
}

/// A message pushed **from the server to a client**.
///
/// The `t` tag selects the variant and `d` carries its payload on the wire
/// (e.g. `{"t":"incoming","d":{…}}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", content = "d", rename_all = "snake_case")]
pub enum ServerMessage {
    /// Acknowledges that a client [`ClientMessage::Send`] was accepted by the server
    /// (server-side persistence/fan-out is underway). Echoes the accepted envelope id.
    Ack(MessageId),

    /// Server push of an inbound encrypted envelope destined for this device.
    Incoming(#[serde(with = "wire_envelope")] Envelope),

    /// A peer's presence changed (online/away/offline).
    Presence(PresenceState),

    /// A peer started/stopped typing.
    Typing(TypingIndicator),

    /// A transport- or protocol-level error the client should surface or react to
    /// (e.g. auth failure, malformed frame, rate-limit).
    Error {
        /// Human-/log-readable description. Not localized; clients map as needed.
        message: String,
    },
}

/// Coarse presence advertised over the wire. Ephemeral — never persisted as ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    /// Actively connected and available.
    Online,
    /// Connected but idle/away.
    Away,
    /// Disconnected / last-seen.
    Offline,
}

/// A presence change for a specific user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceState {
    /// Whose presence this describes.
    pub user: UserId,
    /// The new presence value.
    pub presence: Presence,
}

impl PresenceState {
    /// Construct a presence update.
    pub fn new(user: UserId, presence: Presence) -> Self {
        Self { user, presence }
    }
}

/// A typing indicator between two users.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypingIndicator {
    /// The user who is (or stopped) typing.
    pub user: UserId,
    /// `true` = started typing, `false` = stopped.
    pub typing: bool,
}

impl TypingIndicator {
    /// Construct a typing indicator.
    pub fn new(user: UserId, typing: bool) -> Self {
        Self { user, typing }
    }
}

impl ClientMessage {
    /// Serialize this frame to JSON bytes for the wire. See [`codec::to_bytes`].
    pub fn to_bytes(&self) -> mx_types::Result<Vec<u8>> {
        codec::to_bytes(self)
    }

    /// Decode a client frame from wire bytes. See [`codec::from_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> mx_types::Result<Self> {
        codec::from_bytes(bytes)
    }
}

impl ServerMessage {
    /// Serialize this frame to JSON bytes for the wire. See [`codec::to_bytes`].
    pub fn to_bytes(&self) -> mx_types::Result<Vec<u8>> {
        codec::to_bytes(self)
    }

    /// Decode a server frame from wire bytes. See [`codec::from_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> mx_types::Result<Self> {
        codec::from_bytes(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mx_types::{Ciphertext, DeviceId, GroupId, MessageKind, Recipient};

    fn sample_envelope() -> Envelope {
        Envelope::new(
            DeviceId::new(),
            Recipient::Direct(UserId::new()),
            MessageKind::Chat,
            Ciphertext(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            1_700_000_000_000,
        )
    }

    /// Round-trip a `ClientMessage` through encode -> decode and assert equality.
    fn round_trip_client(msg: ClientMessage) {
        let bytes = msg.to_bytes().expect("encode");
        let back = ClientMessage::from_bytes(&bytes).expect("decode");
        assert_eq!(msg, back);
    }

    /// Round-trip a `ServerMessage` through encode -> decode and assert equality.
    fn round_trip_server(msg: ServerMessage) {
        let bytes = msg.to_bytes().expect("encode");
        let back = ServerMessage::from_bytes(&bytes).expect("decode");
        assert_eq!(msg, back);
    }

    #[test]
    fn client_hello_round_trips() {
        round_trip_client(ClientMessage::Hello {
            token: "tok-abc-123".to_string(),
        });
    }

    #[test]
    fn client_send_round_trips() {
        round_trip_client(ClientMessage::Send(sample_envelope()));
    }

    #[test]
    fn client_ack_round_trips() {
        round_trip_client(ClientMessage::Ack(MessageId::new()));
    }

    #[test]
    fn client_presence_round_trips() {
        round_trip_client(ClientMessage::Presence(PresenceState::new(
            UserId::new(),
            Presence::Online,
        )));
    }

    #[test]
    fn client_typing_round_trips() {
        round_trip_client(ClientMessage::Typing(TypingIndicator::new(
            UserId::new(),
            true,
        )));
    }

    #[test]
    fn server_ack_round_trips() {
        round_trip_server(ServerMessage::Ack(MessageId::new()));
    }

    #[test]
    fn server_incoming_round_trips() {
        round_trip_server(ServerMessage::Incoming(sample_envelope()));
    }

    #[test]
    fn server_presence_round_trips() {
        round_trip_server(ServerMessage::Presence(PresenceState::new(
            UserId::new(),
            Presence::Away,
        )));
    }

    #[test]
    fn server_typing_round_trips() {
        round_trip_server(ServerMessage::Typing(TypingIndicator::new(
            UserId::new(),
            false,
        )));
    }

    #[test]
    fn server_error_round_trips() {
        round_trip_server(ServerMessage::Error {
            message: "rate limited".to_string(),
        });
    }

    /// A group-addressed envelope also survives the round-trip.
    #[test]
    fn group_envelope_round_trips() {
        let env = Envelope::new(
            DeviceId::new(),
            Recipient::Group(GroupId::new()),
            MessageKind::GroupHandshake,
            Ciphertext(vec![1, 2, 3]),
            42,
        );
        round_trip_server(ServerMessage::Incoming(env));
    }

    /// The internal tag is present and matches the variant name on the wire.
    #[test]
    fn wire_tag_is_present() {
        let bytes = ClientMessage::Hello {
            token: "x".into(),
        }
        .to_bytes()
        .unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("\"t\":\"hello\""), "frame was: {s}");
    }

    /// Garbage / unknown frames decode to a `Transport` error, not a panic.
    #[test]
    fn malformed_frame_is_transport_error() {
        let err = ClientMessage::from_bytes(b"{not json").unwrap_err();
        assert!(matches!(err, mx_types::Error::Transport(_)));

        let err = ServerMessage::from_bytes(b"{\"t\":\"nope\"}").unwrap_err();
        assert!(matches!(err, mx_types::Error::Transport(_)));
    }
}
