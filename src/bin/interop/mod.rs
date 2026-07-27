//! Compatibility shim for the reference Python implementation, shared by the interop peers.
//!
//! `mls-tls-python-pedantic` opens every connection with a bare transport frame carrying the
//! responder's raw signing public key, ahead of the initiator's ClientHello (`mls_tls.py`:
//! `connect` / `accept` / `resume` / `accept_resumption`). MLS-TLS itself has no such flight —
//! `draft-kohbrok-mls-two-party-profile-00` §3 has the initiator open the key agreement with a
//! ClientHello — so the `mls-tls` library does not implement it and its state machine knows nothing
//! about it. These binaries emulate it here, at the socket level, purely so the Python pairings in
//! `interop/run_live.py` keep working.
#![allow(dead_code)] // each peer uses only the half matching its role

use std::io::{self, Read, Write};
use std::net::TcpStream;

use mls_tls::SignaturePublicKey;

// The outer transport frame the whole protocol rides: `0x17 0x03 0x03 u16(len) payload`.
const APPLICATION_DATA: u8 = 0x17;
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const HEADER_LEN: usize = 5;

/// Server role: send the raw signing public key as the connection's first frame. Must happen before
/// the handshake is driven — the Python client blocks on this frame before sending its ClientHello.
pub fn send_server_pubkey(sock: &mut TcpStream, key: &SignaturePublicKey) -> io::Result<()> {
    let payload = key.as_bytes();
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.push(APPLICATION_DATA);
    frame.extend_from_slice(&LEGACY_RECORD_VERSION);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    sock.write_all(&frame)?;
    sock.flush()
}

/// Client role: consume the peer's public-key frame, and *only* that frame, so no bytes belonging to
/// the handshake proper are swallowed before the connection gets to see them.
pub fn recv_server_pubkey(sock: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut header = [0u8; HEADER_LEN];
    sock.read_exact(&mut header)?;
    if header[0] != APPLICATION_DATA || header[1..3] != LEGACY_RECORD_VERSION {
        return Err(io::Error::other("bad transport record header"));
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut payload = vec![0u8; len];
    sock.read_exact(&mut payload)?;
    Ok(payload)
}
