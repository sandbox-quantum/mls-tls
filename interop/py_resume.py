#!/usr/bin/env python3
"""
Python resumption peer for interop testing, using the Python `MlsTlsConnection` API.

  py_resume.py server <port>   # accept a fresh connection, then a resumed one
  py_resume.py client <port>   # connect fresh, then resume

Each connection exchanges one app-data message + ack. Used by interop/run_resume.py against
this repo's Rust `resume_server` / `resume_client` binaries.
"""
import sys
from pathlib import Path

PY_DIR = Path.home() / "workspace/mls-tls-paper/mls-tls/playground/mls-tls-python-pedantic"
sys.path.insert(0, str(PY_DIR))

from mls_tls import MlsTlsConnection  # noqa: E402
from mls_base_structures import Credential, CREDENTIAL_TYPE_BASIC  # noqa: E402
from crypto.signature import SignatureKeyPair, SignatureScheme  # noqa: E402

HOST = "127.0.0.1"


def run_server(port: int) -> None:
    kp = SignatureKeyPair.generate(SignatureScheme.ECDSA_SECP384R1_SHA384)
    cred = Credential(credential_type=CREDENTIAL_TYPE_BASIC, identity=b"server", certificates=None)
    listening = MlsTlsConnection.listen(HOST, port)
    print(f"SERVER_LISTENING {port}", file=sys.stderr, flush=True)

    conn1 = MlsTlsConnection.accept(listening, kp, cred)
    msg1 = conn1.receive_app_data()
    print(f"SERVER_RECEIVED: {msg1.decode(errors='replace')}", flush=True)
    conn1.send_app_data(b"ack1 (python server)")
    conn1.close()

    conn2 = MlsTlsConnection.accept_resumption(listening, conn1.state)
    msg2 = conn2.receive_app_data()
    print(f"SERVER_RECEIVED: {msg2.decode(errors='replace')}", flush=True)
    conn2.send_app_data(b"ack2 (python server)")
    conn2.close()


def run_client(port: int) -> None:
    kp = SignatureKeyPair.generate(SignatureScheme.ECDSA_SECP384R1_SHA384)

    conn1 = MlsTlsConnection.connect(HOST, port, kp)
    conn1.send_app_data(b"hello1 (python client)")
    ack1 = conn1.receive_app_data()
    print(f"CLIENT_RECEIVED_1: {ack1.decode(errors='replace')}", flush=True)
    prior = conn1.state
    conn1.close()

    conn2 = MlsTlsConnection.resume(HOST, port, prior)
    conn2.send_app_data(b"hello2 (python client)")
    ack2 = conn2.receive_app_data()
    print(f"CLIENT_RECEIVED_2: {ack2.decode(errors='replace')}", flush=True)
    conn2.close()


def main() -> int:
    role, port = sys.argv[1], int(sys.argv[2])
    if role == "server":
        run_server(port)
    elif role == "client":
        run_client(port)
    else:
        print(f"unknown role {role}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
