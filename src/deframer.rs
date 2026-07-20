//! Wire framing aligned with the Python `mls-tls-python-pedantic`.
//!
//! Every message travels in an **outer transport frame** with a 5-byte TLS-record header whose
//! content type is always `0x17` (application_data): `0x17 0x0303 u16(len) payload`. The transport
//! does not distinguish message kinds — the receiver dispatches on the payload's first byte:
//! - `0x17` → the payload is itself an inner AEAD record (application data), decrypted by the
//!   [`RecordLayer`](crate::tls_record::RecordLayer);
//! - otherwise → a plaintext control message: an [`Envelope`] (`MlsTlsHandshake`, first bytes
//!   `0x0000`) during the handshake/resumption, or a [`Signaling`] message (`0x00xx`) in steady state.
//!
//! Pre-handshake, the server also sends its raw signing public key as a bare payload (first byte
//! `0x04`, SEC1 uncompressed).

use mls_rs::MlsMessage;

use crate::error::Error;

const TLS_RECORD_HEADER_LEN: usize = 5;
const APPLICATION_DATA: u8 = 0x17;
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];

// MlsTlsHandshake envelope.
const PROTOCOL_VERSION_V01: u16 = 0x0000;
const HANDSHAKE_PAYLOAD_CLIENT_HELLO: u16 = 0x0000;
const HANDSHAKE_PAYLOAD_RESUMPTION: u16 = 0x0001;

// SignalingMessage tags.
const SIGNALING_CONNECTION_UPDATE: u16 = 0x0000;
const SIGNALING_CONNECTION_CONFIRMATION: u16 = 0x0001;
const SIGNALING_EPOCH_KEY_UPDATE: u16 = 0x0002;

// Reference `Boolean` enum is inverted vs. C convention: True=0x00, False=0x01.
const BOOL_TRUE: u8 = 0x00;
const BOOL_FALSE: u8 = 0x01;

/// Accumulates inbound bytes and yields whole transport-frame payloads (the 5-byte outer header is
/// stripped). Does not decrypt.
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

    /// Pop one complete transport frame's payload, or `None` if a full frame isn't buffered yet.
    pub(crate) fn pop(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.buf.len() < TLS_RECORD_HEADER_LEN {
            return Ok(None);
        }
        if self.buf[0] != APPLICATION_DATA || self.buf[1..3] != LEGACY_RECORD_VERSION {
            return Err(Error::Decode("bad transport record header"));
        }
        let len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
        let total = TLS_RECORD_HEADER_LEN + len;
        if self.buf.len() < total {
            return Ok(None);
        }
        let payload = self.buf[TLS_RECORD_HEADER_LEN..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(payload))
    }
}

/// Wrap `payload` in an outer transport frame (`0x17 0x0303 u16(len) payload`).
pub(crate) fn frame_transport(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TLS_RECORD_HEADER_LEN + payload.len());
    out.push(APPLICATION_DATA);
    out.extend_from_slice(&LEGACY_RECORD_VERSION);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// True if a transport-frame payload is an inner AEAD application-data record.
pub(crate) fn is_app_data(payload: &[u8]) -> bool {
    payload.first() == Some(&APPLICATION_DATA)
}

/// A `MlsTlsHandshake`-envelope message (client→server): ClientHello or Resumption.
pub(crate) enum Envelope {
    ClientHello(MlsMessage),
    Resumption(MlsMessage),
}

impl Envelope {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        let (tag, msg) = match self {
            Envelope::ClientHello(m) => (HANDSHAKE_PAYLOAD_CLIENT_HELLO, m),
            Envelope::Resumption(m) => (HANDSHAKE_PAYLOAD_RESUMPTION, m),
        };
        let mut out = Vec::new();
        out.extend_from_slice(&PROTOCOL_VERSION_V01.to_be_bytes());
        out.extend_from_slice(&tag.to_be_bytes());
        out.extend_from_slice(&msg.to_bytes()?);
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::Decode("short MlsTlsHandshake envelope"));
        }
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        if version != PROTOCOL_VERSION_V01 {
            return Err(Error::Decode("unsupported MlsTlsHandshake version"));
        }
        let tag = u16::from_be_bytes([bytes[2], bytes[3]]);
        let msg = MlsMessage::from_bytes(&bytes[4..])?;
        match tag {
            HANDSHAKE_PAYLOAD_CLIENT_HELLO => Ok(Envelope::ClientHello(msg)),
            HANDSHAKE_PAYLOAD_RESUMPTION => Ok(Envelope::Resumption(msg)),
            _ => Err(Error::Decode("unknown MlsTlsHandshake payload tag")),
        }
    }
}

/// A steady-state `SignalingMessage`: a rekey commit, an epoch confirmation, or a resumption ack.
pub(crate) enum Signaling {
    /// A rekey commit (MLS `PrivateMessage`), with the `update_requested` flag.
    ConnectionUpdate { update_requested: bool, commit: MlsMessage },
    /// The peer confirms it advanced to `epoch`.
    EpochKeyUpdate(u64),
    /// The responder confirms a resumption advanced to `epoch`.
    ConnectionConfirmation(u64),
}

impl Signaling {
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self {
            Signaling::ConnectionUpdate { update_requested, commit } => {
                out.extend_from_slice(&SIGNALING_CONNECTION_UPDATE.to_be_bytes());
                out.push(if *update_requested { BOOL_TRUE } else { BOOL_FALSE });
                out.extend_from_slice(&commit.to_bytes()?);
            }
            Signaling::EpochKeyUpdate(epoch) => {
                out.extend_from_slice(&SIGNALING_EPOCH_KEY_UPDATE.to_be_bytes());
                out.extend_from_slice(&epoch.to_be_bytes());
            }
            Signaling::ConnectionConfirmation(epoch) => {
                out.extend_from_slice(&SIGNALING_CONNECTION_CONFIRMATION.to_be_bytes());
                out.extend_from_slice(&epoch.to_be_bytes());
            }
        }
        Ok(out)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 2 {
            return Err(Error::Decode("short SignalingMessage"));
        }
        let tag = u16::from_be_bytes([bytes[0], bytes[1]]);
        let rest = &bytes[2..];
        match tag {
            SIGNALING_CONNECTION_UPDATE => {
                let (flag, msg_bytes) = rest
                    .split_first()
                    .ok_or(Error::Decode("short ConnectionUpdate"))?;
                let update_requested = *flag == BOOL_TRUE;
                let commit = MlsMessage::from_bytes(msg_bytes)?;
                Ok(Signaling::ConnectionUpdate { update_requested, commit })
            }
            SIGNALING_EPOCH_KEY_UPDATE => Ok(Signaling::EpochKeyUpdate(read_u64(rest)?)),
            SIGNALING_CONNECTION_CONFIRMATION => {
                Ok(Signaling::ConnectionConfirmation(read_u64(rest)?))
            }
            _ => Err(Error::Decode("unknown SignalingMessage tag")),
        }
    }
}

fn read_u64(bytes: &[u8]) -> Result<u64, Error> {
    let arr: [u8; 8] = bytes.try_into().map_err(|_| Error::Decode("bad u64 length"))?;
    Ok(u64::from_be_bytes(arr))
}
