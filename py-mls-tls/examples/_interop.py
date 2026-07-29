"""Compatibility shim for the reference Python implementation, used by the examples only.

`mls-tls-python-pedantic` opens every connection with a bare transport frame carrying the
responder's raw signing public key, ahead of the initiator's ClientHello. MLS-TLS has no such
flight — draft-kohbrok-mls-two-party-profile-00 §3 has the initiator open the key agreement — so
neither the library nor these bindings implement it.

This mirrors `mls-tls/src/bin/interop/mod.rs`, which does the same thing for the Rust interop
peers, and lives in `examples/` for the same reason it lives in `bin/` there: it is a property of
those peers, not of the protocol.
"""

from __future__ import annotations

import socket

# The outer transport frame the whole protocol rides: 0x17 0x03 0x03 u16(len) payload.
_APPLICATION_DATA = 0x17
_LEGACY_RECORD_VERSION = b"\x03\x03"
_HEADER_LEN = 5


def send_server_pubkey(sock: socket.socket, public_key: bytes) -> None:
    """Server role: send the raw signing public key as the connection's first frame.

    Must happen before the handshake is driven — the Python client blocks on this frame before
    sending its ClientHello.
    """
    frame = (
        bytes([_APPLICATION_DATA])
        + _LEGACY_RECORD_VERSION
        + len(public_key).to_bytes(2, "big")
        + public_key
    )
    sock.sendall(frame)


def recv_server_pubkey(sock: socket.socket) -> bytes:
    """Client role: consume the peer's public-key frame, and *only* that frame.

    Reading any further would swallow bytes belonging to the handshake before the connection gets
    to see them.
    """
    header = _recv_exact(sock, _HEADER_LEN)
    if header[0] != _APPLICATION_DATA or header[1:3] != _LEGACY_RECORD_VERSION:
        raise ValueError("bad transport record header")
    return _recv_exact(sock, int.from_bytes(header[3:5], "big"))


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise EOFError("peer closed while reading the opening frame")
        buf += chunk
    return bytes(buf)
