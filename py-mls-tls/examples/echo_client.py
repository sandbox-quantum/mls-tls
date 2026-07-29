#!/usr/bin/env python3
"""Connect to an MLS-TLS server, send one message, print the reply.

Interoperates with the crate's own peer:

    cargo run -p mls-tls --bin simple_server -- 8443 &
    python examples/echo_client.py 8443

`--interop` consumes the reference Python implementation's non-standard opening frame, which
`simple_server` also sends. Drop it when talking to a peer that does not.
"""

from __future__ import annotations

import argparse
import socket
import sys

import mls_tls
from _interop import recv_server_pubkey


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, nargs="?", default=8443)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--message", default="hello from python")
    parser.add_argument(
        "--interop",
        action="store_true",
        default=True,
        help="consume the reference implementation's opening public-key frame (default)",
    )
    parser.add_argument("--no-interop", dest="interop", action="store_false")
    args = parser.parse_args()

    # A Basic credential has no certificate chain, so there is nothing for the default verifier to
    # check — verify=False is the correct setting here, not a shortcut.
    config = mls_tls.ClientConfig(basic_credential=b"client", verify=False)

    sock = socket.create_connection((args.host, args.port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if args.interop:
        recv_server_pubkey(sock)

    with config.wrap_socket(sock, server_hostname="localhost") as tls:
        tls.sendall(args.message.encode())
        reply = tls.recv(4096)
        print(f"CLIENT_RECEIVED: {reply.decode(errors='replace')}")
        print(
            f"  suite={tls.cipher_name()} epoch={tls.epoch()} "
            f"peer={tls.peer_identity()!r}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
