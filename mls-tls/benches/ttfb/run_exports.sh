#!/usr/bin/env bash
# Runs the TTFB benchmarks for both crypto backends and exports JSON results.
#   * openssl build  -> mls-tls (openssl backend) vs the OpenSSL TLS 1.3 stack, side by side.
#   * rustcrypto build -> mls-tls native (pure-Rust), including the X-Wing PQ suite.
# Full default RTT ladder (0..3000 ms), a representative suite set, default iteration budget.
set -u
cd "$(dirname "$0")/../../.." || exit 1   # repo root
RESULTS="mls-tls/benches/ttfb/results"
mkdir -p "$RESULTS"

echo "[1/2] openssl comparison (mls-tls openssl backend vs openssl stack): p256,p384,x25519"
cargo bench --bench ttfb --no-default-features --features openssl -- \
    --suites p256,p384,x25519 --json \
    > "$RESULTS/openssl-comparison.json" 2> "$RESULTS/openssl-comparison.log"

echo "[2/2] rustcrypto native (mls-tls, incl. X-Wing PQ): xwing,p384,x25519"
cargo bench --bench ttfb -- \
    --suites xwing,p384,x25519 --json \
    > "$RESULTS/mls-tls-rustcrypto.json" 2> "$RESULTS/mls-tls-rustcrypto.log"

echo "done: results in $RESULTS"
