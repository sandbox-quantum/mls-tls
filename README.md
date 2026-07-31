# mls-tls

An experimental implementation of the **MLS-TLS** and **MLS Two-Party Profile** IETF drafts:
an [MLS](https://datatracker.ietf.org/doc/rfc9420/) group (via [`mls-rs`](https://github.com/awslabs/mls-rs))
is used as the key-agreement engine feeding a TLS 1.3 record layer.

- MLS-TLS — [`draft-kohbrok-mls-tls`](https://datatracker.ietf.org/doc/draft-kohbrok-mls-tls/)
- Two-Party Profile — [`draft-kohbrok-mls-two-party-profile`](https://datatracker.ietf.org/doc/draft-kohbrok-mls-two-party-profile/)

> [!WARNING]
> **This is not production-ready code and has not been audited.** It exists to explore,
> exercise, and sanity-check the MLS-TLS drafts — not to secure real traffic. Interfaces,
> wire formats, and behaviour track drafts that are still changing and may break at any time.
> Do not depend on it.

## What's here

| Path | What it is |
|---|---|
| [`mls-tls/`](mls-tls/) | The Rust crate. A rustls-shaped API (sans-I/O core + blocking adapters) over the two drafts. |
| [`py-mls-tls/`](py-mls-tls/) | Python bindings (PyO3/maturin) mirroring the crate — see [its README](py-mls-tls/README.md). |
| [`interop/`](interop/) | Interop scripts and known-answer vectors checked against the reference Python implementation. |
| [`PUBLIC_API_DESIGN.md`](PUBLIC_API_DESIGN.md) | Notes on the public API surface and design rationale. |

## Crypto backends

Exactly one backend is selected at compile time and serves everything (MLS group, record layer,
X.509 verification):

```console
cargo build                                          # rustcrypto (default, pure Rust)
cargo build --no-default-features --features openssl # system OpenSSL
```

`rustcrypto` covers the seven standard MLS suites plus a custom X-Wing suite (`0x004e`) used for
interop; `openssl` covers the seven standard suites only. Cargo features are additive, so the
non-default backend requires `--no-default-features`.

## Try it

```console
cargo test                                   # unit + loopback + interop tests
cargo run -p mls-tls --example loopback      # in-memory client/server handshake
cargo run -p mls-tls --example tcp           # over a real TCP socket
```

## License

See [LICENSE](LICENSE).
