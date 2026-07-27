#!/usr/bin/env python3
"""
Live interop driver: run this repo's Rust MLS-TLS binaries against the Python
`mls-tls-python-pedantic` peers over real TCP sockets, in both directions, covering the initial
handshake, a mid-session rekey, and resumption.

Pairings:
  A  Python e2e_client        <->  Rust simple_server      (handshake + app-data)
  B  Rust  simple_client      <->  Python e2e_server       (handshake + app-data)
  K1 Rust  rekey_peer client  <->  Python py_rekey server  (client-initiated rekey)
  K2 Python py_rekey client   <->  Rust  rekey_peer server (client-initiated rekey)
    R1 Rust  resume_client      <->  Python py_resume server (resumption)
    R2 Python py_resume client  <->  Rust  resume_server     (resumption)

A pairing passes when every expected substring appears in the right peer's stdout. This driver only
READS the Python project; it runs the Python peers with this repo's interop venv (mlkem/ecdsa/...).

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
BIN = REPO / "target/debug"


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

    def wait_ready(self, t):
        return self._ready.wait(t)

    def wait(self, t):
        try:
            return self.proc.wait(timeout=t)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            return -1

    def out(self):
        return "".join(self._out)

    def err(self):
        return "".join(self._err)


def run_pairing(name, server_cmd, server_cwd, server_ready, client_cmd, client_cwd,
                expect_server, expect_client) -> bool:
    server = Peer(server_cmd, server_cwd, server_ready)
    if not server.wait_ready(20):
        print(f"  [FAIL] {name}: server not ready — {server.err().strip()[-200:]}")
        server.wait(1)
        return False
    client = Peer(client_cmd, client_cwd, ready_token="")
    client.wait(30)
    server.wait(15)
    so, co = server.out(), client.out()
    ok = all(s in so for s in expect_server) and all(c in co for c in expect_client)
    if not ok:
        print(f"  [FAIL] {name}")
        print(f"         server out: {so.strip()[-200:]}")
        print(f"         client out: {co.strip()[-200:]}")
        print(f"         server err: {server.err().strip().splitlines()[-2:]}")
        print(f"         client err: {client.err().strip().splitlines()[-2:]}")
    else:
        print(f"  [PASS] {name}")
    return ok


def rust(*args):
    return [BIN / args[0], *args[1:]]


def py(script, *args):
    return [VENV_PY, script, *args]


def main() -> int:
    for exe in ("simple_server", "simple_client", "rekey_peer", "resume_server", "resume_client"):
        if not (BIN / exe).exists():
            print(f"missing {BIN / exe} — run `cargo build --bins` first")
            return 1

    results = {}

    results["A  Py client  <-> Rust server (handshake)"] = run_pairing(
        "A  handshake: Python client <-> Rust simple_server",
        rust("simple_server", "8421"), REPO, "listening",
        py("e2e_client.py", "--port", "8421", "--message", "Hello from client (python)!"), PY_DIR,
        ["SERVER_RECEIVED: Hello from client (python)!"],
        ["CLIENT_RECEIVED: Hello from server (rust)!"],
    )
    results["B  Rust client <-> Py server (handshake)"] = run_pairing(
        "B  handshake: Rust simple_client <-> Python server",
        py("e2e_server.py", "--port", "8422", "--message", "Hello from server (python)!"), PY_DIR, "SERVER_LISTENING",
        rust("simple_client", "8422"), REPO,
        ["SERVER_RECEIVED: Hello from client (rust)!"],
        ["CLIENT_RECEIVED: Hello from server (python)!"],
    )
    results["K1 Rust client <-> Py server (rekey)"] = run_pairing(
        "K1 rekey: Rust rekey_peer client <-> Python py_rekey server",
        py("interop/py_rekey.py", "server", "8423"), REPO, "SERVER_LISTENING",
        rust("rekey_peer", "client", "8423"), REPO,
        ["rekey1 (rust client)", "rekey2 (rust client)"],
        ["CLIENT_RECEIVED_1: ack1 (python server)", "CLIENT_RECEIVED_2: ack2 (python server)"],
    )
    results["K2 Py client  <-> Rust server (rekey)"] = run_pairing(
        "K2 rekey: Python py_rekey client <-> Rust rekey_peer server",
        rust("rekey_peer", "server", "8424"), REPO, "listening",
        py("interop/py_rekey.py", "client", "8424"), REPO,
        ["rekey1 (python client)", "rekey2 (python client)"],
        ["CLIENT_RECEIVED_1: ack1 (rust server)", "CLIENT_RECEIVED_2: ack2 (rust server)"],
    )
    results["R1 Rust client <-> Py server (resume)"] = run_pairing(
        "R1 resume: Rust resume_client <-> Python py_resume server",
        py("interop/py_resume.py", "server", "8425"), REPO, "SERVER_LISTENING",
        rust("resume_client", "8425"), REPO,
        ["hello1 (rust client)", "hello2 (rust client)"],
        ["CLIENT_RECEIVED_1: ack1 (python server)", "CLIENT_RECEIVED_2: ack2 (python server)"],
    )
    results["R2 Py client  <-> Rust server (resume)"] = run_pairing(
        "R2 resume: Python py_resume client <-> Rust resume_server",
        rust("resume_server", "8426"), REPO, "listening",
        py("interop/py_resume.py", "client", "8426"), REPO,
        ["hello1 (python client)", "hello2 (python client)"],
        ["CLIENT_RECEIVED_1: ack1 (rust server)", "CLIENT_RECEIVED_2: ack2 (rust server)"],
    )

    print("\n" + "=" * 64)
    print("LIVE INTEROP SUMMARY (Rust <-> Python, custom X-Wing 0x004e)")
    print("=" * 64)
    for name, ok in results.items():
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name}")
    all_ok = all(results.values())
    print("=" * 64)
    print("ALL PAIRINGS PASSED" if all_ok else "SOME PAIRINGS FAILED")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
