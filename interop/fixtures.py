#!/usr/bin/env python3
"""
Fixture-based interop checks between this repo's Rust MLS-TLS and the Python
`mls-tls-python-pedantic`, using the custom X-Wing suite (0x004e).

Two directions:
  * Rust -> Python: parse+verify a Rust-generated ClientHello with the Python parser.
      First generate it:  cargo test --lib spike_write_clienthello -- --ignored
      (writes interop/rust_clienthello.bin)
  * Python -> Rust: generate a Python ClientHello into interop/python_clienthello.bin,
      then `cargo test --test interop_fixtures` parses+checks it with mls-rs.

Run: interop/.venv/bin/python interop/fixtures.py
"""
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PY_DIR = Path.home() / "workspace/mls-tls-paper/mls-tls/playground/mls-tls-python-pedantic"
sys.path.insert(0, str(PY_DIR))

from mls_client_hello import (  # noqa: E402
    ClientState,
    clienthello_verify,
    generate_client_hello,
)
from crypto.signature import SignatureKeyPair, SignatureScheme  # noqa: E402

RUST_CH = REPO / "interop/rust_clienthello.bin"
PY_CH = REPO / "interop/python_clienthello.bin"


def check_rust_to_python() -> bool:
    print("[Rust -> Python] verifying a Rust-generated ClientHello with the Python parser")
    if not RUST_CH.exists():
        print(f"    (skip) {RUST_CH} not found — run:")
        print("      cargo test --lib spike_write_clienthello -- --ignored")
        return True
    data = RUST_CH.read_bytes()
    try:
        kp = clienthello_verify(data)
        assert kp.cipher_suite == 0x004E, f"cipher suite 0x{kp.cipher_suite:04x}"
        assert len(kp.init_key) == 1665, f"init_key {len(kp.init_key)}"
        print(f"    ✓ parsed + signatures verified (suite 0x{kp.cipher_suite:04x}, init_key {len(kp.init_key)}B)")
        return True
    except Exception as e:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        print(f"    ✗ FAILED: {e}")
        return False


def gen_python_clienthello() -> bool:
    print("[Python -> Rust] generating a Python ClientHello for mls-rs to parse")
    try:
        state = ClientState(
            signature_keypair=SignatureKeyPair.generate(SignatureScheme.ECDSA_SECP384R1_SHA384),
        )
        ch = generate_client_hello(state)
        PY_CH.write_bytes(ch)
        # Self-check it parses on the Python side too.
        kp = clienthello_verify(ch)
        assert kp.cipher_suite == 0x004E
        print(f"    ✓ wrote {PY_CH} ({len(ch)} bytes); now run: cargo test --test interop_fixtures")
        return True
    except Exception as e:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        print(f"    ✗ FAILED: {e}")
        return False


def main() -> int:
    ok1 = check_rust_to_python()
    ok2 = gen_python_clienthello()
    print("\nFIXTURE SUMMARY")
    print(f"  [{'PASS' if ok1 else 'FAIL'}]  Rust -> Python ClientHello parse+verify")
    print(f"  [{'PASS' if ok2 else 'FAIL'}]  Python -> Rust ClientHello generated (parse in Rust test)")
    return 0 if (ok1 and ok2) else 1


if __name__ == "__main__":
    sys.exit(main())
