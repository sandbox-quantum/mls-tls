"""The loopback pump the sans-I/O tests drive connections with.

The pump is a direct port of the `pump`/`drive` helpers in the crate's own loopback tests
(`mls-tls/src/lib.rs`), so the Python suite exercises the same scenarios and any divergence in
behaviour between the two shows up as a test that passes on one side and fails on the other.
"""

from __future__ import annotations

import pathlib

import mls_tls

#: The crate's test fixtures: an Ed25519 CA and server certificate, plus the raw server key.
FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "mls-tls" / "fixtures"

#: The fixture certificates are Ed25519, so the X.509 tests must pin a suite that signs with it.
ED25519_SUITE = mls_tls.MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519


def pump(source, sink) -> int:
    """Move every pending TLS byte from `source` to `sink` and process it. Returns bytes moved."""
    moved = 0
    while source.writable():
        chunk = source.write_tls()
        if not chunk:
            break
        offset = 0
        while offset < len(chunk):
            consumed = sink.read_tls(chunk[offset:])
            if consumed == 0:
                break
            offset += consumed
        moved += len(chunk)
    if moved:
        sink.process_new_packets()
    return moved


def drive(client, server, rounds: int = 16) -> None:
    """Pump both directions until the exchange settles."""
    for _ in range(rounds):
        if pump(server, client) + pump(client, server) == 0:
            return


def send(source, sink, message: bytes) -> bytes:
    """Write `message` on `source` and read it back off `sink`."""
    source.write(message)
    pump(source, sink)
    return sink.read()
