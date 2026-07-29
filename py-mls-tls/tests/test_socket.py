"""The blocking socket wrapper, over real TCP.

Each test runs the server on a thread and the client on the main one, so a hang shows up as a
timeout rather than a deadlock: every socket gets one.
"""

from __future__ import annotations

import socket
import threading

import pytest

import mls_tls

TIMEOUT = 10.0


def serve(config, handler, *, ready: threading.Event, errors: list):
    """Accept exactly one connection, wrap it, and hand it to `handler`."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(TIMEOUT)
    port = listener.getsockname()[1]

    def run():
        ready.set()
        try:
            conn, _ = listener.accept()
            conn.settimeout(TIMEOUT)
            with config.wrap_socket(conn) as tls:
                handler(tls)
        except Exception as exc:  # noqa: BLE001 - surfaced to the main thread below
            errors.append(exc)
        finally:
            listener.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    ready.wait(TIMEOUT)
    return port, thread


@pytest.fixture
def echo_server(server_config):
    """A one-shot echo server. Yields the port; re-raises anything the thread hit."""
    errors: list = []

    def handler(tls):
        data = tls.recv(4096)
        tls.sendall(b"echo: " + data)

    port, thread = serve(server_config, handler, ready=threading.Event(), errors=errors)
    yield port
    thread.join(TIMEOUT)
    if errors:
        raise errors[0]


def connect(client_config, port, **kwargs):
    sock = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
    return client_config.wrap_socket(sock, server_hostname="localhost", **kwargs)


def test_echo(client_config, echo_server):
    with connect(client_config, echo_server) as tls:
        tls.sendall(b"hello over tcp")
        assert tls.recv(4096) == b"echo: hello over tcp"


def test_handshake_details_are_reported(client_config, echo_server):
    with connect(client_config, echo_server) as tls:
        tls.do_handshake()
        assert tls.cipher() == mls_tls.DEFAULT_CIPHER_SUITE
        assert tls.cipher_name() == mls_tls.cipher_suite_name(mls_tls.DEFAULT_CIPHER_SUITE)
        assert tls.peer_identity() == b"server"
        assert tls.getpeercert(binary_form=True) is None  # Basic credential, no chain
        assert tls.epoch() == 1
        assert not tls.session_reused
        tls.sendall(b"x")
        tls.recv(4096)


def test_rekey_over_a_socket(client_config, server_config):
    """A mid-session rekey is transparent to both sides' application data."""
    errors: list = []

    def handler(tls):
        assert tls.recv(4096) == b"before"
        tls.sendall(b"ok")
        assert tls.recv(4096) == b"after"
        tls.sendall(b"still ok")

    port, thread = serve(server_config, handler, ready=threading.Event(), errors=errors)
    with connect(client_config, port) as tls:
        tls.sendall(b"before")
        assert tls.recv(4096) == b"ok"

        tls.refresh_traffic_keys()
        tls.sendall(b"after")
        assert tls.recv(4096) == b"still ok"
        assert tls.epoch() == 2

    thread.join(TIMEOUT)
    if errors:
        raise errors[0]


def test_clean_close_reads_as_eof(client_config, server_config):
    """A peer that sends close_notify ends the stream with b"" rather than an exception."""
    errors: list = []

    def handler(tls):
        tls.sendall(b"bye")
        tls.close()  # sends close_notify

    port, thread = serve(server_config, handler, ready=threading.Event(), errors=errors)
    with connect(client_config, port) as tls:
        assert tls.recv(4096) == b"bye"
        assert tls.recv(4096) == b""
        assert tls.recv(4096) == b""  # still EOF, not a blocking read

    thread.join(TIMEOUT)
    if errors:
        raise errors[0]


def test_ragged_eof_is_reported(client_config, server_config):
    """A transport that dies without close_notify is a truncation risk, so it raises."""
    errors: list = []

    def handler(tls):
        tls.sendall(b"partial")
        # Drop the socket without unwrapping: no close_notify reaches the peer.
        tls.socket.close()
        tls._closed = True

    port, thread = serve(server_config, handler, ready=threading.Event(), errors=errors)
    with connect(client_config, port) as tls:
        assert tls.recv(4096) == b"partial"
        with pytest.raises(mls_tls.RaggedEOF):
            tls.recv(4096)

    thread.join(TIMEOUT)
    if errors:
        raise errors[0]


def test_suppress_ragged_eofs(client_config, server_config):
    """Opting in to the `ssl` default turns the same case into an ordinary EOF."""
    errors: list = []

    def handler(tls):
        tls.sendall(b"partial")
        tls.socket.close()
        tls._closed = True

    port, thread = serve(server_config, handler, ready=threading.Event(), errors=errors)
    with connect(client_config, port, suppress_ragged_eofs=True) as tls:
        assert tls.recv(4096) == b"partial"
        assert tls.recv(4096) == b""

    thread.join(TIMEOUT)
    if errors:
        raise errors[0]


def test_recv_into(client_config, echo_server):
    with connect(client_config, echo_server) as tls:
        tls.sendall(b"buffered")
        buf = bytearray(64)
        n = tls.recv_into(buf)
        assert bytes(buf[:n]) == b"echo: buffered"


def test_nonblocking_socket_raises_want_read(client_config, server_config):
    """On a non-blocking socket, "no data yet" surfaces as WantReadError, as in `ssl`."""
    errors: list = []
    started = threading.Event()

    def handler(tls):
        started.wait(TIMEOUT)
        tls.recv(4096)

    port, thread = serve(server_config, handler, ready=threading.Event(), errors=errors)
    sock = socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT)
    sock.setblocking(False)
    tls = client_config.wrap_socket(sock, server_hostname="localhost")
    with pytest.raises(mls_tls.WantReadError):
        # The server has not replied yet, so the handshake cannot finish without blocking.
        tls.do_handshake()

    started.set()
    sock.close()
    thread.join(TIMEOUT)


def test_delegates_unknown_attributes_to_the_socket(client_config, echo_server):
    with connect(client_config, echo_server) as tls:
        # `getpeername` is not defined on the wrapper; it comes from the socket underneath.
        assert tls.getpeername()[0] == "127.0.0.1"
        assert isinstance(tls.fileno(), int)
        tls.sendall(b"x")
        tls.recv(4096)


def test_unwrap_returns_the_bare_socket(client_config, echo_server):
    tls = connect(client_config, echo_server)
    tls.sendall(b"x")
    assert tls.recv(4096) == b"echo: x"
    bare = tls.unwrap()
    assert isinstance(bare, socket.socket)
    bare.close()


def test_socket_resumption(client_config, server_config):
    """A session exported from one socket resumes on the next, over a fresh transport."""
    errors: list = []

    def handler(tls):
        tls.sendall(b"hi " + tls.recv(4096))

    port1, thread1 = serve(server_config, handler, ready=threading.Event(), errors=errors)
    with connect(client_config, port1) as tls:
        tls.sendall(b"first")
        assert tls.recv(4096) == b"hi first"
        session = tls.session
    thread1.join(TIMEOUT)

    port2, thread2 = serve(server_config, handler, ready=threading.Event(), errors=errors)
    with connect(client_config, port2, session=session) as tls:
        assert tls.session_reused
        tls.sendall(b"second")
        assert tls.recv(4096) == b"hi second"
        assert tls.epoch() > 1
    thread2.join(TIMEOUT)

    if errors:
        raise errors[0]
