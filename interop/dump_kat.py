#!/usr/bin/env python3
"""
Dump ML-KEM-1024 + custom X-Wing (ML-KEM-1024 + P-384) known-answer vectors from
the Python `mls-tls-python-pedantic` implementation, for cross-checking against
the RustCrypto `ml-kem` / our Rust X-Wing implementation.

All inputs are fixed byte patterns so the output is reproducible. Emits JSON
(hex-encoded) to stdout.

Run with the interop venv, pointing PYTHONPATH at the Python project:
    interop/.venv/bin/python interop/dump_kat.py
"""
import json
import os
import sys

# Make the Python reference implementation importable without modifying it.
PY_IMPL = os.path.expanduser(
    "~/workspace/mls-tls-paper/mls-tls/playground/mls-tls-python-pedantic"
)
sys.path.insert(0, PY_IMPL)

from mlkem.ml_kem import ML_KEM
from mlkem.parameter_set import ML_KEM_1024
from crypto import xwing_kem


def h(b: bytes) -> str:
    return b.hex()


def fixed(n: int, seed: int) -> bytes:
    """Deterministic byte pattern of length n."""
    return bytes((seed + i) % 256 for i in range(n))


def main() -> int:
    out = {}

    # --- ML-KEM-1024 FIPS 203 vectors (deterministic) ---
    d = fixed(32, 1)
    z = fixed(32, 100)
    m = fixed(32, 200)  # encaps message / randomness

    kem = ML_KEM(ML_KEM_1024, fast=True)
    ek, dk = kem._key_gen(d, z)            # (public 1568, private 3168)
    ss_enc, ct = kem._encaps(ek, m)        # NOTE: (ss, ct) order
    ss_dec = kem.decaps(dk, ct)

    out["mlkem1024"] = {
        "d": h(d), "z": h(z), "m": h(m),
        "ek": h(ek), "ek_len": len(ek),
        "dk_len": len(dk),
        "ct": h(ct), "ct_len": len(ct),
        "ss": h(ss_enc), "ss_len": len(ss_enc),
        "ss_decaps_matches": ss_enc == ss_dec,
    }

    # --- X-Wing (custom ML-KEM-1024 + P-384) vectors ---
    ikm = fixed(64, 7)                     # 64-byte X-Wing IKM/seed
    sk_m, sk_x_scalar, pk_m, pk_x = xwing_kem.expand_key(ikm)
    pk = pk_m + pk_x                       # 1665-byte public key

    # Combiner with fixed inputs (independent of the KEM math, checks SHA3-384 + label + order).
    comb_ss_m = fixed(32, 11)
    comb_ss_x = b"\x04" + fixed(96, 21)    # 97-byte "uncompressed point" shaped input
    comb_ct_x = b"\x04" + fixed(96, 31)
    comb_pk_x = b"\x04" + fixed(96, 41)
    combined = xwing_kem.combiner(comb_ss_m, comb_ss_x, comb_ct_x, comb_pk_x)

    # Deterministic encapsulation to `pk` with fixed 80-byte randomness, then decapsulate.
    rand80 = fixed(80, 55)
    enc, ss_xwing = xwing_kem.encapsulate(pk, rand80)
    ss_xwing_dec = xwing_kem.decapsulate(ikm, enc)

    out["xwing"] = {
        "ikm": h(ikm),
        "pk": h(pk), "pk_len": len(pk),
        "pk_m_len": len(pk_m), "pk_x": h(pk_x), "pk_x_len": len(pk_x),
        "combiner_in": {
            "ss_m": h(comb_ss_m), "ss_x": h(comb_ss_x),
            "ct_x": h(comb_ct_x), "pk_x": h(comb_pk_x),
        },
        "combiner_out": h(combined), "combiner_out_len": len(combined),
        "encap_randomness": h(rand80),
        "enc": h(enc), "enc_len": len(enc),
        "ss": h(ss_xwing), "ss_len": len(ss_xwing),
        "ss_decaps_matches": ss_xwing == ss_xwing_dec,
        "label": h(xwing_kem.X_WING_LABEL),
    }

    json.dump(out, sys.stdout, indent=2)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
