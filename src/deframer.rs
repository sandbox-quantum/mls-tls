//! Wire framing for the sans-I/O core.
//!
//! One framing is used everywhere: the 5-byte TLS record header `{ ContentType, 0x0303, u16 len }`.
//! - Phase A (pre-key ClientHello/ServerHello) is sent as a *plaintext* record with outer
//!   `ContentType::Handshake`; the body is an encoded [`HandshakePayload`].
//! - Phase B records are produced by `RecordLayer::encrypt` (outer `ContentType::ApplicationData`),
//!   already carrying the header; the *inner* content type (revealed by `RecordLayer::decrypt`)
//!   routes application data vs in-band control.
//!
//! [`HandshakePayload`] is the wire form of the control/handshake messages (filling the draft-§8
//! wire-format gap): a 1-byte tag followed by an `MlsMessage` encoding (or a `u64` epoch).

use mls_rs::MlsMessage;

use crate::error::Error;
use crate::tls_record::ContentType;

const TLS_RECORD_HEADER_LEN: usize = 5;

/// A complete record lifted off the inbound byte stream (including its 5-byte header).
pub(crate) struct Frame {
    /// The outer record content type (22 = Handshake plaintext, 23 = encrypted ApplicationData).
    pub(crate) outer_type: u8,
    /// The full record bytes, header included (what `RecordLayer::decrypt` expects for Phase B).
    pub(crate) record: Vec<u8>,
}

impl Frame {
    /// The record body (after the 5-byte header) — used to decode a plaintext handshake payload.
    pub(crate) fn body(&self) -> &[u8] {
        &self.record[TLS_RECORD_HEADER_LEN..]
    }
}

/// Accumulates inbound bytes and yields whole records. Does not decrypt (the direct analog of
/// rustls' `MessageDeframer`).
pub(crate) struct MessageDeframer {
    buf: Vec<u8>,
}

impl MessageDeframer {
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub(crate) fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop one complete record, or `None` if the buffer does not yet hold a full record.
    pub(crate) fn pop(&mut self) -> Result<Option<Frame>, Error> {
        if self.buf.len() < TLS_RECORD_HEADER_LEN {
            return Ok(None);
        }
        let outer_type = self.buf[0];
        let len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
        let total = TLS_RECORD_HEADER_LEN + len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let record: Vec<u8> = self.buf.drain(..total).collect();
        Ok(Some(Frame { outer_type, record }))
    }
}

/// Frame a plaintext handshake payload as a record with outer `ContentType::Handshake`.
pub(crate) fn frame_plaintext_handshake(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
    out.push(ContentType::Handshake as u8);
    out.extend_from_slice(&[0x03, 0x03]); // legacy_record_version = TLS 1.2
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// Wire form of the handshake / control messages.
pub(crate) enum HandshakePayload {
    ClientHello(MlsMessage),
    ServerHello(MlsMessage),
    ConnectionUpdate(MlsMessage),
    EpochKeyUpdate(u64),
    ResumptionRequest(MlsMessage),
    ResumptionResponse(MlsMessage),
}

impl HandshakePayload {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self {
            HandshakePayload::ClientHello(m) => {
                out.push(1);
                out.extend_from_slice(&m.to_bytes()?);
            }
            HandshakePayload::ServerHello(m) => {
                out.push(2);
                out.extend_from_slice(&m.to_bytes()?);
            }
            HandshakePayload::ConnectionUpdate(m) => {
                out.push(3);
                out.extend_from_slice(&m.to_bytes()?);
            }
            HandshakePayload::EpochKeyUpdate(epoch) => {
                out.push(4);
                out.extend_from_slice(&epoch.to_be_bytes());
            }
            HandshakePayload::ResumptionRequest(m) => {
                out.push(5);
                out.extend_from_slice(&m.to_bytes()?);
            }
            HandshakePayload::ResumptionResponse(m) => {
                out.push(6);
                out.extend_from_slice(&m.to_bytes()?);
            }
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let (tag, rest) = bytes
            .split_first()
            .ok_or(Error::Decode("empty handshake payload"))?;
        Ok(match tag {
            1 => HandshakePayload::ClientHello(MlsMessage::from_bytes(rest)?),
            2 => HandshakePayload::ServerHello(MlsMessage::from_bytes(rest)?),
            3 => HandshakePayload::ConnectionUpdate(MlsMessage::from_bytes(rest)?),
            4 => {
                let arr: [u8; 8] = rest
                    .try_into()
                    .map_err(|_| Error::Decode("bad EpochKeyUpdate length"))?;
                HandshakePayload::EpochKeyUpdate(u64::from_be_bytes(arr))
            }
            5 => HandshakePayload::ResumptionRequest(MlsMessage::from_bytes(rest)?),
            6 => HandshakePayload::ResumptionResponse(MlsMessage::from_bytes(rest)?),
            _ => return Err(Error::Decode("unknown handshake payload tag")),
        })
    }
}
