#!/usr/bin/env python3
"""
Live interop driver: run this repo's Rust MLS-TLS binaries against the Python
`mls-tls-python-pedantic` peers over real TCP sockets, in both pairings.

  A. Python e2e_client  <->  Rust simple_server
  B. Rust  simple_client <->  Python e2e_server

A pairing passes when the initial handshake completes and both peers recover each
other's plaintext application-data message.

This driver ONLY reads the Python project (it never modifies it). It runs the
Python peers with this repo's interop venv, which has `mlkem`, `ecdsa`,
`cryptography` installed. Build the Rust binaries first:

    cargo build --bins
    interop/.venv/bin/python interop/run_live.py
"""
import subprocess
import sys
import threading
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PY_DIR = Path.home() / "workspace/mls-tls-paper/mls-tls/playground/mls-tls-python-pedantic"
VENV_PY = REPO / "interop/.venv/bin/python"
RUST_SERVER = REPO / "target/debug/simple_server"
RUST_CLIENT = REPO / "target/debug/simple_client"

PY_CLIENT_MSG = "Hello from client (python)!"
PY_SERVER_MSG = "Hello from server (python)!"
RUST_CLIENT_MSG = "Hello from client (rust)!"
RUST_SERVER_MSG = "Hello from server (rust)!"

PORT_A, PORT_B = 8371, 8372


class Peer:
    def __init__(self, cmd, cwd, ready_token):
        self.proc = subprocess.Popen(
            [str(c) for c in cmd], cwd=str(cwd),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self._out, self._err = [], []
        self._ready = threading.Event()
        self._token = ready_token
        threading.Thread(target=self._drain, args=(self.proc.stdout, self._out, False), daemon=True).start()
        threading.Thread(target=self._drain, args=(self.proc.stderr, self._err, True), daemon=True).start()

    def _drain(self, stream, sink, is_err):
        for line in stream:
            sink.append(line)
            if is_err and self._token and self._token in line:
                self._ready.set()

    def wait_ready(self, timeout):
        return self._ready.wait(timeout)

    def wait(self, timeout):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return -1

    def out(self):
        return "".join(self._out)

    def err(self):
        return "".join(self._err)


def run_pairing(name, server_cmd, server_cwd, server_ready, client_cmd, client_cwd,
                expect_server, expect_client) -> bool:
    print(f"\n{name}")
    server = Peer(server_cmd, server_cwd, server_ready)
    if not server.wait_ready(20):
        print(f"    ✗ server not ready; stderr: {server.err().strip()[-300:]}")
        server.wait(1)
        return False
    client = Peer(client_cmd, client_cwd, ready_token="")
    client.wait(30)
    server.wait(15)

    server_ok = expect_server in server.out()
    client_ok = expect_client in client.out()
    print(f"    server received expected: {server_ok}")
    print(f"    client received expected: {client_ok}")
    if not (server_ok and client_ok):
        print(f"    server stderr(tail): {server.err().strip().splitlines()[-3:]}")
        print(f"    client stderr(tail): {client.err().strip().splitlines()[-3:]}")
    ok = server_ok and client_ok
    print("    => PASS" if ok else "    => FAIL")
    return ok


def main() -> int:
    for exe in (RUST_SERVER, RUST_CLIENT):
        if not exe.exists():
            print(f"✗ missing {exe} — run `cargo build --bins` first")
            return 1

    results = {}
    results["A: Python client <-> Rust server"] = run_pairing(
        "[A] Python client  <->  Rust simple_server",
        server_cmd=[RUST_SERVER, PORT_A], server_cwd=REPO, server_ready="listening",
        client_cmd=[VENV_PY, "e2e_client.py", "--port", PORT_A, "--message", PY_CLIENT_MSG],
        client_cwd=PY_DIR,
        expect_server=f"SERVER_RECEIVED: {PY_CLIENT_MSG}",
        expect_client=f"CLIENT_RECEIVED: {RUST_SERVER_MSG}",
    )
    results["B: Rust client <-> Python server"] = run_pairing(
        "[B] Rust simple_client  <->  Python server",
        server_cmd=[VENV_PY, "e2e_server.py", "--port", PORT_B, "--message", PY_SERVER_MSG],
        server_cwd=PY_DIR, server_ready="SERVER_LISTENING",
        client_cmd=[RUST_CLIENT, PORT_B], client_cwd=REPO,
        expect_server=f"SERVER_RECEIVED: {RUST_CLIENT_MSG}",
        expect_client=f"CLIENT_RECEIVED: {PY_SERVER_MSG}",
    )

    print("\n" + "=" * 60)
    print("LIVE INTEROP SUMMARY")
    print("=" * 60)
    for name, ok in results.items():
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name}")
    all_ok = all(results.values())
    print("=" * 60)
    print("ALL PAIRINGS PASSED" if all_ok else "SOME PAIRINGS FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
