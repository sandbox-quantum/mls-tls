#!/usr/bin/env python3
"""Render the TTFB benchmark JSON exports into a single readable Markdown report.

Usage: python3 render_results.py <results_dir>
Reads openssl-comparison.json and mls-tls-rustcrypto.json, writes RESULTS.md.
"""
import json
import sys
from pathlib import Path


def load(path):
    if not path.exists():
        return None
    return json.loads(path.read_text())


def fmt(x, nd=3):
    return "—" if x is None else f"{x:.{nd}f}"


def group(measurements):
    """(suite, scenario) -> list of rows sorted by (stack, rtt)."""
    out = {}
    for m in measurements:
        out.setdefault((m["suite"], m["scenario"]), []).append(m)
    for rows in out.values():
        rows.sort(key=lambda r: (r["stack"], r["rtt_ms"]))
    return out


def rtt_table(measurements, stacks):
    """A wide table: one row per (suite, scenario, stack), columns = RTTs (min ms)."""
    rtts = sorted({m["rtt_ms"] for m in measurements})
    by_key = {}
    for m in measurements:
        by_key[(m["suite"], m["scenario"], m["stack"], m["rtt_ms"])] = m
    suites = sorted({m["suite"] for m in measurements})
    order = ["handshake", "key-update", "resumption", "resumption-0rtt", "resumption-1rtt"]
    present = {m["scenario"] for m in measurements}
    scenarios = [s for s in order if s in present]
    lines = []
    head = ["suite", "scenario", "stack"] + [f"{int(r)}ms" for r in rtts] + ["flights"]
    lines.append("| " + " | ".join(head) + " |")
    lines.append("|" + "|".join(["---"] * len(head)) + "|")
    for suite in suites:
        for scen in scenarios:
            for stack in stacks:
                cells = []
                flights = None
                present = False
                for r in rtts:
                    m = by_key.get((suite, scen, stack, r))
                    if m is None:
                        cells.append("·")
                        continue
                    present = True
                    cells.append(fmt(m["min_ms"], 2))
                    if m.get("flights") is not None and (r == max(rtts)):
                        flights = m["flights"]
                if not present:
                    continue
                row = [suite, scen, stack] + cells + [fmt(flights, 2)]
                lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def main():
    rdir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    ossl = load(rdir / "openssl-comparison.json")
    rc = load(rdir / "mls-tls-rustcrypto.json")

    out = ["# mls-tls TTFB benchmark results", ""]
    out.append(
        "Time to first application byte, swept across simulated RTTs (loopback TCP through a "
        "latency-injecting relay). `min` is the fastest sample in ms; `flights` is the recovered "
        "round-trip count at the top RTT. Expected flights: handshake 4, key-update 2, mls-tls "
        "resumption 2, openssl `resumption-0rtt` 2 (TLS 1.3 early data), openssl `resumption-1rtt` 4 "
        "(replay-safe session-ticket resumption)."
    )
    out.append("")

    if ossl:
        out.append("## OpenSSL-backend comparison: mls-tls vs the OpenSSL TLS 1.3 stack")
        out.append("")
        out.append(
            f"Both stacks built with `--features openssl`. request {ossl['request_bytes']} B, "
            f"response {ossl['response_bytes']} B; up to {ossl['max_iterations']} iters/cell within a "
            f"{ossl['budget_ms']/1000:.0f}s budget."
        )
        out.append("")
        out.append(rtt_table(ossl["measurements"], ["mls-tls", "openssl"]))
        out.append("")

    if rc:
        out.append("## mls-tls native (rustcrypto backend, incl. X-Wing post-quantum)")
        out.append("")
        out.append(
            f"Built with the default `rustcrypto` backend (pure-Rust; the `xwing` suite is the "
            f"ML-KEM-1024 + P-384 hybrid, unavailable under OpenSSL). request "
            f"{rc['request_bytes']} B, response {rc['response_bytes']} B."
        )
        out.append("")
        out.append(rtt_table(rc["measurements"], ["mls-tls"]))
        out.append("")

    dest = rdir / "RESULTS.md"
    dest.write_text("\n".join(out))
    print(f"wrote {dest}")


if __name__ == "__main__":
    main()
