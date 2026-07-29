#!/usr/bin/env python3
"""Serve one MLS-TLS connection, echoing a single message back.

Interoperates with the crate's own peer:

    python examples/echo_server.py 8444 &
    cargo run -p mls-tls --bin simple_client -- 8444

`--interop` emits the reference Python implementation's non-standard opening frame, which
`simple_client` expects. Drop it when talking to a peer that does not.
"""

from __future__ import annotations

import argparse
import socket
import sys

import mls_tls
from _interop import send_server_pubkey


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("port", type=int, nargs="?", default=8444)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--message", default="Hello from server (python)!")
    parser.add_argument(
        "--interop",
        action="store_true",
        default=True,
        help="emit the reference implementation's opening public-key frame (default)",
    )
    parser.add_argument("--no-interop", dest="interop", action="store_false")
    args = parser.parse_args()

    config = mls_tls.ServerConfig(basic_credential=b"server")

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.host, args.port))
    listener.listen(1)
    # stderr, and flushed: the interop driver watches for this before starting the client.
    print(f"listening {args.port}", file=sys.stderr, flush=True)

    conn, _ = listener.accept()
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    conn.settimeout(10)
    listener.close()

    if args.interop:
        # The config keeps the public half of the key it generated, which is exactly what this
        # frame needs.
        send_server_pubkey(conn, config.public_key)

    with config.wrap_socket(conn) as tls:
        request = tls.recv(4096)
        print(f"SERVER_RECEIVED: {request.decode(errors='replace')}")
        print(f"  suite={tls.cipher_name()} epoch={tls.epoch()} peer={tls.peer_identity()!r}")
        tls.sendall(args.message.encode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
