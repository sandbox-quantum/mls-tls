"""Blocking socket wrappers over the sans-I/O connection objects.

Modelled on the crate's ``Stream``/``StreamOwned`` adapters (``mls-tls/src/stream.rs``): pump the
outgoing buffer, then pump the socket until the connection has what it needs. The socket itself is
an ordinary :class:`socket.socket`, so timeouts, non-blocking mode, ``makefile()`` and
``selectors`` all behave the way they normally do — which is the reason this layer is Python rather
than Rust.

Deliberate divergence from :mod:`ssl`: reading returns ``b""`` only on a *clean* close (the peer
sent ``close_notify``). A transport EOF without one raises :class:`RaggedEOF`, because at that point
the stream may have been truncated by an attacker rather than ended by the peer. Pass
``suppress_ragged_eofs=True`` to get the ``ssl`` default of treating it as a normal end of file.
"""

from __future__ import annotations

import socket as _socket
from typing import TYPE_CHECKING

from . import _mls_tls
from ._mls_tls import RaggedEOF, WantReadError, WantWriteError

if TYPE_CHECKING:  # pragma: no cover
    from ._mls_tls import IoState, Session

__all__ = ["ClientSocket", "ServerSocket", "MLSTLSSocket"]

# Chunk pulled from the socket per read. The record layer fragments at 2**14, and the deframer
# buffers whole frames, so anything of that order keeps the syscall count down without over-reading.
_READ_CHUNK = 16 * 1024


class MLSTLSSocket:
    """A socket with an MLS-TLS connection wrapped around it.

    Not constructed directly — use :meth:`ClientConfig.wrap_socket` or
    :meth:`ServerConfig.wrap_socket`. Anything not defined here is delegated to the underlying
    socket, so ``getpeername()``, ``setsockopt()`` and friends keep working.
    """

    def __init__(self, conn, sock: _socket.socket, *, suppress_ragged_eofs: bool = False):
        self._conn = conn
        self._sock = sock
        self._suppress_ragged_eofs = suppress_ragged_eofs
        self._closed = False
        # Set once the peer's close_notify has been seen, so repeated reads keep returning b""
        # instead of blocking on a socket that will never produce anything.
        self._peer_closed = False

    # -- introspection ----------------------------------------------------------------------

    @property
    def connection(self):
        """The underlying sans-I/O connection, for anything this wrapper does not expose."""
        return self._conn

    @property
    def socket(self) -> _socket.socket:
        """The underlying socket."""
        return self._sock

    @property
    def session(self) -> "Session":
        """A handle for resuming this session later. See :meth:`ClientConfig.wrap_socket`."""
        return self._conn.session()

    def cipher(self) -> int | None:
        """The negotiated cipher suite id, or ``None`` before the handshake completes."""
        return self._conn.cipher()

    def cipher_name(self) -> str | None:
        """The negotiated cipher suite's registry name, or ``None``."""
        suite = self._conn.cipher()
        return None if suite is None else _mls_tls.cipher_suite_name(suite)

    def epoch(self) -> int | None:
        """The current MLS epoch. Increments on every rekey and resumption."""
        return self._conn.epoch()

    def peer_identity(self) -> bytes | None:
        """The peer's Basic credential identifier, or ``None`` if it presented a certificate."""
        return self._conn.peer_identity()

    def getpeercert(self, binary_form: bool = False) -> bytes | None:
        """The peer's leaf certificate in DER. ``binary_form=True`` is required."""
        return self._conn.getpeercert(binary_form)

    def getpeercertchain(self) -> list[bytes] | None:
        """The peer's full certificate chain in DER, leaf first, or ``None``."""
        return self._conn.getpeercertchain()

    # -- handshake --------------------------------------------------------------------------

    def do_handshake(self) -> None:
        """Run the key agreement to completion.

        Called automatically on first I/O unless the socket was wrapped with
        ``do_handshake_on_connect=False``.
        """
        self._flush()
        while self._conn.is_handshaking():
            if not self._pump_once():
                raise RaggedEOF("peer closed the connection during the handshake")
            self._flush()

    # -- application data -------------------------------------------------------------------

    def send(self, data) -> int:
        """Encrypt and send ``data``. Returns the number of plaintext bytes accepted."""
        self.do_handshake()
        n = self._conn.write(data)
        self._flush()
        return n

    def sendall(self, data) -> None:
        """Encrypt and send all of ``data``."""
        view = memoryview(data)
        while view:
            view = view[self.send(view) :]

    #: :mod:`ssl` spells these ``read``/``write``; both names work here.
    write = send

    def recv(self, bufsize: int = _READ_CHUNK) -> bytes:
        """Receive up to ``bufsize`` bytes of decrypted plaintext.

        Returns ``b""`` once the peer has closed cleanly. Raises :class:`RaggedEOF` if the
        transport ended without a ``close_notify``, unless ``suppress_ragged_eofs`` was set.
        """
        self.do_handshake()
        while True:
            data = self._conn.read(bufsize)
            if data:
                return data
            if self._peer_closed:
                return b""
            if not self._pump_once():
                # EOF with no close_notify: the stream may have been cut short.
                if self._suppress_ragged_eofs:
                    return b""
                raise RaggedEOF("peer closed the transport without sending close_notify")
            self._flush()  # processing may have queued control replies

    def read(self, size: int = _READ_CHUNK) -> bytes:
        """Alias for :meth:`recv`, matching :class:`ssl.SSLSocket`."""
        return self.recv(size)

    def recv_into(self, buffer, nbytes: int | None = None) -> int:
        """Receive plaintext into a writable buffer, returning the number of bytes written."""
        view = memoryview(buffer)
        if nbytes is not None:
            view = view[:nbytes]
        data = self.recv(len(view))
        view[: len(data)] = data
        return len(data)

    # -- control ----------------------------------------------------------------------------

    def refresh_traffic_keys(self) -> None:
        """Rotate the traffic keys by advancing the MLS epoch.

        Costs no round trip — the control message and any data written straight afterwards travel
        in the same flight.
        """
        self._conn.refresh_traffic_keys()
        self._flush()

    def unwrap(self) -> _socket.socket:
        """Send ``close_notify``, then return the bare socket with MLS-TLS removed.

        The peer is not waited on: a bare transport close is a legal, if truncation-prone, way for
        it to go away, and the reference Python implementation does not send one.
        """
        try:
            self._conn.send_close_notify()
            self._flush()
        except OSError:
            pass  # the transport is already gone; nothing left to say
        return self._sock

    def close(self) -> None:
        """Send ``close_notify`` if possible, then close the socket."""
        if self._closed:
            return
        self._closed = True
        try:
            self.unwrap()
        except Exception:  # noqa: BLE001 - closing must not raise over a broken connection
            pass
        finally:
            self._sock.close()

    def __enter__(self) -> "MLSTLSSocket":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    def __getattr__(self, name: str):
        # Only reached for attributes this class does not define, so it cannot shadow the TLS
        # behaviour above -- `send`/`recv`/`close` stay ours.
        return getattr(self._sock, name)

    # -- internals --------------------------------------------------------------------------

    def _flush(self) -> None:
        """Write every queued TLS byte to the socket."""
        while self._conn.writable():
            chunk = self._conn.write_tls()
            if not chunk:
                break
            try:
                self._sock.sendall(chunk)
            except BlockingIOError as exc:
                raise WantWriteError("socket is not ready for writing") from exc

    def _pump_once(self) -> bool:
        """Read one chunk from the socket and process it. False on transport EOF."""
        try:
            data = self._sock.recv(_READ_CHUNK)
        except BlockingIOError as exc:
            raise WantReadError("socket has no data available") from exc
        if not data:
            return False
        # `read_tls` consumes a bounded amount per call, so feed until the chunk is gone.
        offset = 0
        while offset < len(data):
            consumed = self._conn.read_tls(data[offset:])
            if consumed == 0:
                break
            offset += consumed
        state: IoState = self._conn.process_new_packets()
        if state.peer_has_closed:
            self._peer_closed = True
        return True


class ClientSocket(MLSTLSSocket):
    """The initiator side. Built by :meth:`ClientConfig.wrap_socket`."""

    def __init__(
        self,
        config,
        sock: _socket.socket,
        server_hostname: str,
        *,
        do_handshake_on_connect: bool = True,
        session: "Session | None" = None,
        suppress_ragged_eofs: bool = False,
    ):
        conn = _mls_tls.ClientConnection(config, server_hostname, session)
        super().__init__(conn, sock, suppress_ragged_eofs=suppress_ragged_eofs)
        self._session_reused = session is not None
        if do_handshake_on_connect:
            # The ClientHello is already queued; push it now so the peer can start work rather than
            # waiting for the caller's first send().
            self._flush()

    @property
    def session_reused(self) -> bool:
        """Whether this connection resumed a previous session rather than starting fresh."""
        return self._session_reused


class ServerSocket(MLSTLSSocket):
    """The responder side. Built by :meth:`ServerConfig.wrap_socket`."""

    def __init__(
        self,
        config,
        sock: _socket.socket,
        *,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = False,
    ):
        conn = _mls_tls.ServerConnection(config)
        super().__init__(conn, sock, suppress_ragged_eofs=suppress_ragged_eofs)
        # Nothing is queued until the ClientHello arrives, so there is nothing to flush here;
        # `do_handshake_on_connect` is accepted for symmetry and to keep it out of **kwargs.
        del do_handshake_on_connect

    @property
    def session_reused(self) -> bool:
        """Whether the client resumed rather than starting fresh."""
        # A resumed connection reaches epoch 2 or higher, because resumption commits a self-update
        # before any application data flows; a fresh one settles at epoch 1.
        epoch = self._conn.epoch()
        return epoch is not None and epoch > 1
