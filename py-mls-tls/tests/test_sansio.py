"""The sans-I/O surface, mirroring the crate's loopback tests in `mls-tls/src/lib.rs`.

Two of these (`test_rekey_piggyback`, `test_resumption_early_data`) assert a zero-round-trip
property that the socket wrapper deliberately cannot express, because it waits out the handshake
before writing. They only exist at this layer.
"""

from __future__ import annotations

import pytest

import mls_tls

from _helpers import drive, pump, send


def test_handshake_and_appdata(established):
    client, server = established
    assert send(client, server, b"hello server") == b"hello server"
    assert send(server, client, b"hello client") == b"hello client"


def test_peer_identity_is_the_other_side(established):
    client, server = established
    assert client.peer_identity() == b"server"
    assert server.peer_identity() == b"client"
    assert client.cipher() == server.cipher() == mls_tls.DEFAULT_CIPHER_SUITE
    assert client.epoch() == server.epoch() == 1


def test_introspection_before_handshake(client_config):
    client = mls_tls.ClientConnection(client_config, "localhost")
    assert client.is_handshaking()
    assert client.peer_identity() is None
    assert client.cipher() is None
    assert client.epoch() is None


def test_initiator_rekey(established):
    client, server = established
    assert send(client, server, b"pre") == b"pre"

    client.refresh_traffic_keys()
    drive(client, server, rounds=4)

    assert client.epoch() == 2
    assert send(client, server, b"post c2s") == b"post c2s"
    assert send(server, client, b"post s2c") == b"post s2c"


def test_rekey_piggyback(established):
    """A rekey costs no round trip: data written straight after it rides the same flight."""
    client, server = established
    assert send(client, server, b"pre") == b"pre"

    client.refresh_traffic_keys()
    client.write(b"c2s piggybacked")

    # One flight out: the ConnectionUpdate and the record, decrypted in the same pass.
    assert pump(client, server) > 0
    assert server.read() == b"c2s piggybacked"

    # One flight back: the EpochKeyUpdate rotates the client's receive key in time for the reply.
    server.write(b"s2c piggybacked")
    assert pump(server, client) > 0
    assert client.read() == b"s2c piggybacked"


def test_resumption(client_config, server_config):
    client1 = mls_tls.ClientConnection(client_config, "localhost")
    server1 = mls_tls.ServerConnection(server_config)
    drive(client1, server1)
    assert send(client1, server1, b"epoch1") == b"epoch1"
    session = client1.session()

    # A second transport, resuming the first session. Both configs are reused, which is what makes
    # the persisted group reachable on each side.
    client2 = mls_tls.ClientConnection(client_config, "localhost", session)
    server2 = mls_tls.ServerConnection(server_config)
    drive(client2, server2)
    assert not client2.is_handshaking()
    assert not server2.is_handshaking()
    assert client2.epoch() > client1.epoch()
    assert send(client2, server2, b"epoch2") == b"epoch2"
    assert send(server2, client2, b"epoch2 back") == b"epoch2 back"


def test_resumption_early_data(client_config, server_config):
    """A resumption costs no round trip either: the request rides with the Resumption itself."""
    client1 = mls_tls.ClientConnection(client_config, "localhost")
    server1 = mls_tls.ServerConnection(server_config)
    drive(client1, server1)
    session = client1.session()

    client2 = mls_tls.ClientConnection(client_config, "localhost", session)
    server2 = mls_tls.ServerConnection(server_config)
    assert client2.is_handshaking(), "should still be awaiting the ConnectionConfirmation"

    # Writing before the confirmation arrives works: `resume` already installed the keys.
    client2.write(b"early data")
    assert pump(client2, server2) > 0
    assert server2.read() == b"early data"

    server2.write(b"reply")
    assert pump(server2, client2) > 0
    assert not client2.is_handshaking()
    assert client2.read() == b"reply"


def test_resumption_rejects_unknown_group(client_config, server_config):
    """A server that never saw the group cannot reload it, so the resumption fails."""
    client1 = mls_tls.ClientConnection(client_config, "localhost")
    server1 = mls_tls.ServerConnection(server_config)
    drive(client1, server1)
    session = client1.session()

    # A fresh server config has its own, empty session storage.
    other = mls_tls.ServerConfig(basic_credential=b"server")
    client2 = mls_tls.ClientConnection(client_config, "localhost", session)
    server2 = mls_tls.ServerConnection(other)

    # Deliver the Resumption by hand rather than via `pump`, so the failure surfaces here.
    payload = client2.write_tls()
    assert payload
    offset = 0
    while offset < len(payload):
        offset += server2.read_tls(payload[offset:])

    with pytest.raises(mls_tls.HandshakeError):
        server2.process_new_packets()
    assert server2.is_handshaking()
    assert not server2.writable()


def test_session_round_trips_through_bytes(established):
    client, _ = established
    session = client.session()
    restored = mls_tls.Session.from_bytes(session.to_bytes())
    assert restored.to_bytes() == session.to_bytes()


def test_close_notify(established):
    client, server = established
    client.write(b"last words")
    client.send_close_notify()
    pump(client, server)

    # `pump` already processed; ask again for the state so the assertion reads directly.
    state = server.process_new_packets()
    assert state.peer_has_closed
    assert server.read() == b"last words"


def test_io_state_reports_pending_work(established):
    client, server = established
    client.write(b"x" * 100)
    state = client.process_new_packets()
    assert state.tls_bytes_to_write > 100
    assert not state.peer_has_closed

    pump(client, server)
    state = server.process_new_packets()
    assert state.plaintext_bytes_to_read == 100


def test_read_into_and_write_tls_into(established):
    """The zero-copy buffer forms agree with the allocating ones."""
    client, server = established
    client.write(b"buffered")

    outgoing = bytearray(16 * 1024)
    n = client.write_tls_into(outgoing)
    assert n > 0
    offset = 0
    while offset < n:
        offset += server.read_tls(bytes(outgoing[offset:n]))
    server.process_new_packets()

    plaintext = bytearray(64)
    read = server.read_into(plaintext)
    assert bytes(plaintext[:read]) == b"buffered"


def test_read_into_rejects_readonly_buffer(established):
    client, _ = established
    with pytest.raises(ValueError, match="writable"):
        client.read_into(b"immutable")


def test_read_returns_empty_when_nothing_buffered(established):
    client, _ = established
    assert client.read() == b""
