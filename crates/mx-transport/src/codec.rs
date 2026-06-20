//! Frame (de)serialization for the transport.
//!
//! Frames are encoded as **JSON** for v0 (human-debuggable, schema-evolvable). The
//! functions here are generic over any `serde`-(de)serializable frame, so the same
//! codec serves [`crate::ClientMessage`], [`crate::ServerMessage`], and any future
//! control type. All errors are mapped to [`mx_types::Error::Transport`] so callers
//! handle a single error domain at the socket boundary.
//!
//! A binary codec (e.g. CBOR/bincode) may be added later for QUIC without changing the
//! [`crate::ClientMessage`] / [`crate::ServerMessage`] types.

use serde::{de::DeserializeOwned, Serialize};

/// Serialize a frame to JSON bytes ready to be written to the socket.
///
/// # Errors
/// Returns [`mx_types::Error::Transport`] if the value cannot be serialized.
pub fn to_bytes<T: Serialize>(value: &T) -> mx_types::Result<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|e| mx_types::Error::Transport(format!("encode failed: {e}")))
}

/// Deserialize a frame from bytes received off the socket.
///
/// # Errors
/// Returns [`mx_types::Error::Transport`] if the bytes are not valid JSON for `T`
/// (malformed frame, unknown variant tag, or type mismatch).
pub fn from_bytes<T: DeserializeOwned>(bytes: &[u8]) -> mx_types::Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|e| mx_types::Error::Transport(format!("decode failed: {e}")))
}

/// Convenience: serialize a frame to a JSON `String` (e.g. for a WebSocket *text*
/// frame, as opposed to a binary frame from [`to_bytes`]).
///
/// # Errors
/// Returns [`mx_types::Error::Transport`] on serialization failure.
pub fn to_string<T: Serialize>(value: &T) -> mx_types::Result<String> {
    serde_json::to_string(value)
        .map_err(|e| mx_types::Error::Transport(format!("encode failed: {e}")))
}

/// Convenience: deserialize a frame from a JSON `&str` (WebSocket text frame).
///
/// # Errors
/// Returns [`mx_types::Error::Transport`] on parse failure.
pub fn from_str<T: DeserializeOwned>(s: &str) -> mx_types::Result<T> {
    serde_json::from_str(s)
        .map_err(|e| mx_types::Error::Transport(format!("decode failed: {e}")))
}

/// Axum/WS integration helper *signature* (kept dependency-free).
///
/// `mx-server`'s WebSocket gateway is expected to receive raw frame bytes from
/// `axum::extract::ws::Message` and feed them here. We deliberately do **not** depend
/// on `axum` in this crate; the gateway provides the bytes and dispatches the decoded
/// [`crate::ClientMessage`]. This thin wrapper documents the intended call shape and
/// gives the server a single decode entry point to reuse.
///
/// ```ignore
/// // In mx-server, on a received WS binary/text frame `data: &[u8]`:
/// match mx_transport::codec::decode_client_frame(data) {
///     Ok(msg) => handle(msg),
///     Err(e)  => reply(ServerMessage::Error { message: e.to_string() }),
/// }
/// ```
pub fn decode_client_frame(bytes: &[u8]) -> mx_types::Result<crate::ClientMessage> {
    from_bytes(bytes)
}

/// Companion to [`decode_client_frame`]: encode a server push for the gateway to write
/// back onto the WS connection.
///
/// # Errors
/// Returns [`mx_types::Error::Transport`] on serialization failure.
pub fn encode_server_frame(msg: &crate::ServerMessage) -> mx_types::Result<Vec<u8>> {
    to_bytes(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClientMessage, ServerMessage};
    use mx_types::MessageId;

    #[test]
    fn bytes_and_string_codecs_agree() {
        let msg = ClientMessage::Hello {
            token: "abc".into(),
        };
        let by_bytes = to_bytes(&msg).unwrap();
        let by_string = to_string(&msg).unwrap();
        assert_eq!(by_bytes, by_string.into_bytes());
    }

    #[test]
    fn string_round_trip() {
        let msg = ServerMessage::Error {
            message: "boom".into(),
        };
        let s = to_string(&msg).unwrap();
        let back: ServerMessage = from_str(&s).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn server_helper_pair_round_trips() {
        let msg = ServerMessage::Ack(MessageId::new());
        let bytes = encode_server_frame(&msg).unwrap();
        let back: ServerMessage = from_bytes(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn decode_client_frame_helper_works() {
        let msg = ClientMessage::Ack(MessageId::new());
        let bytes = to_bytes(&msg).unwrap();
        let back = decode_client_frame(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    #[test]
    fn decode_error_is_transport() {
        let err = decode_client_frame(b"\xff\xff").unwrap_err();
        assert!(matches!(err, mx_types::Error::Transport(_)));
    }
}
