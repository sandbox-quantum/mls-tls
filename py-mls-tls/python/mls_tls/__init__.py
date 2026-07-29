"""MLS-TLS for Python: an MLS group as the key-agreement engine for a TLS 1.3 record layer.

The API mirrors the Rust crate, which is itself shaped after rustls, so there are two layers and
you pick the one that fits:

* :class:`ClientConfig` / :class:`ServerConfig` produce socket wrappers via ``wrap_socket()`` —
  the ordinary blocking path, close enough to :class:`ssl.SSLSocket` to be unsurprising.
* :class:`ClientConnection` / :class:`ServerConnection` are sans-I/O: you move bytes, they hold no
  socket. Use these for event loops, testing, or protocols that own their own transport.

.. code-block:: python

    import socket, mls_tls

    cfg = mls_tls.ClientConfig(basic_credential=b"alice", verify=False)
    with cfg.wrap_socket(socket.create_connection(addr), server_hostname="localhost") as s:
        s.sendall(b"hello")
        print(s.recv(1024))

Two things differ from ``ssl`` in ways worth knowing up front. Configs are immutable and are the
unit of session sharing — resuming a session requires the *same* config object, because that is
where the MLS group state lives. And ``verify=False`` is not just an escape hatch: a peer using a
Basic credential has no certificate chain to check, so it is the correct setting there.
"""

from __future__ import annotations

import socket as _socket

from . import _mls_tls
from ._mls_tls import (
    BACKEND,
    DEFAULT_CIPHER_SUITE,
    MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
    MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519,
    MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519,
    MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
    MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
    MLS_256_DHKEMX448_AES256GCM_SHA512_ED448,
    MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448,
    MLS_256_XWING_AES256GCM_SHA512_P384,
    SUPPORTED_CIPHER_SUITES,
    CertificateError,
    ClientConnection,
    HandshakeError,
    IoState,
    MLSTLSError,
    RaggedEOF,
    ServerConnection,
    Session,
    UnsupportedError,
    WantReadError,
    WantWriteError,
    cipher_suite_name,
    derive_signature_public_key,
    generate_signature_key,
)
from ._socket import ClientSocket, MLSTLSSocket, ServerSocket

__all__ = [
    # configuration
    "ClientConfig",
    "ServerConfig",
    # sans-I/O
    "ClientConnection",
    "ServerConnection",
    "IoState",
    "Session",
    # sockets
    "ClientSocket",
    "ServerSocket",
    "MLSTLSSocket",
    # errors
    "MLSTLSError",
    "WantReadError",
    "WantWriteError",
    "CertificateError",
    "HandshakeError",
    "UnsupportedError",
    "RaggedEOF",
    # keys + suites
    "generate_signature_key",
    "derive_signature_public_key",
    "cipher_suite_name",
    "BACKEND",
    "DEFAULT_CIPHER_SUITE",
    "SUPPORTED_CIPHER_SUITES",
    "MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519",
    "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
    "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519",
    "MLS_256_DHKEMX448_AES256GCM_SHA512_ED448",
    "MLS_256_DHKEMP521_AES256GCM_SHA512_P521",
    "MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448",
    "MLS_256_DHKEMP384_AES256GCM_SHA384_P384",
    "MLS_256_XWING_AES256GCM_SHA512_P384",
]


class ClientConfig(_mls_tls.ClientConfig):
    """Immutable client configuration; see :meth:`wrap_socket`.

    Keyword arguments (all optional except a credential):

    ``basic_credential``
        An opaque identifier for a Basic credential. A signing key is generated unless
        ``private_key`` is also given.
    ``cert_chain`` / ``private_key`` / ``public_key``
        An X.509 credential: DER certificates leaf-first, plus the raw signing key. The encoding is
        the one the suite's signature scheme uses — a 48-byte scalar for P-384, 64-byte keypair
        bytes for Ed25519 — not PKCS#8. ``public_key`` is derived if omitted, and checked if given.
    ``root_certificates``
        DER trust anchors for verifying the server. Defaults to the backend's built-in roots.
    ``verify``
        ``False`` accepts any server credential. Required when the peer uses a Basic credential,
        since there is no chain to verify.
    ``cipher_suite``
        One of :data:`SUPPORTED_CIPHER_SUITES`. Defaults to :data:`DEFAULT_CIPHER_SUITE`.
    """

    def wrap_socket(
        self,
        sock: _socket.socket,
        server_hostname: str,
        *,
        do_handshake_on_connect: bool = True,
        session: Session | None = None,
        suppress_ragged_eofs: bool = False,
    ) -> ClientSocket:
        """Wrap a connected socket, returning a socket-like object that speaks MLS-TLS.

        ``server_hostname`` is checked against the server's certificate unless verification is
        off. Pass ``session`` to resume — it must have come from a connection made with *this*
        config object.
        """
        return ClientSocket(
            self,
            sock,
            server_hostname,
            do_handshake_on_connect=do_handshake_on_connect,
            session=session,
            suppress_ragged_eofs=suppress_ragged_eofs,
        )


class ServerConfig(_mls_tls.ServerConfig):
    """Immutable server configuration; see :meth:`wrap_socket`.

    Takes the same credential arguments as :class:`ClientConfig`. There is no client-verification
    setting: client X.509 authentication is not implemented end-to-end in the underlying crate, so
    the server accepts a Basic client credential.
    """

    def wrap_socket(
        self,
        sock: _socket.socket,
        *,
        do_handshake_on_connect: bool = True,
        suppress_ragged_eofs: bool = False,
    ) -> ServerSocket:
        """Wrap an accepted socket, returning a socket-like object that speaks MLS-TLS.

        Nothing is sent until the client's ClientHello arrives, so there is no separate acceptor
        step; the handshake runs on first read or write.
        """
        return ServerSocket(
            self,
            sock,
            do_handshake_on_connect=do_handshake_on_connect,
            suppress_ragged_eofs=suppress_ragged_eofs,
        )
