#!/usr/bin/env python3
"""
Python rekey peer for interop testing, using the Python `MlsTlsConnection` API.

  py_rekey.py server <port>   # recv msg1, ack1, recv msg2 (auto-processing the rekey), ack2
  py_rekey.py client <port>   # send msg1, recv ack1, initiate_connection_update, send msg2, recv ack2
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
    conn = MlsTlsConnection.accept(listening, kp, cred)

    msg1 = conn.receive_app_data()
    print(f"SERVER_RECEIVED: {msg1.decode(errors='replace')}", flush=True)
    conn.send_app_data(b"ack1 (python server)")

    # The peer's ConnectionUpdate is processed automatically inside this receive.
    msg2 = conn.receive_app_data()
    print(f"SERVER_RECEIVED: {msg2.decode(errors='replace')}", flush=True)
    conn.send_app_data(b"ack2 (python server)")
    conn.close()


def run_client(port: int) -> None:
    kp = SignatureKeyPair.generate(SignatureScheme.ECDSA_SECP384R1_SHA384)
    conn = MlsTlsConnection.connect(HOST, port, kp)

    conn.send_app_data(b"rekey1 (python client)")
    ack1 = conn.receive_app_data()
    print(f"CLIENT_RECEIVED_1: {ack1.decode(errors='replace')}", flush=True)

    conn.initiate_connection_update()  # blocks until the peer confirms (EpochKeyUpdate)

    conn.send_app_data(b"rekey2 (python client)")
    ack2 = conn.receive_app_data()
    print(f"CLIENT_RECEIVED_2: {ack2.decode(errors='replace')}", flush=True)
    conn.close()


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
