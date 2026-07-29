# mls-tls for Python

Python bindings for the [`mls-tls`](../mls-tls) crate: an MLS group (via `mls-rs`) used as the
key-agreement engine feeding a TLS 1.3 record layer, per the 2PMLS and MLS-TLS IETF drafts.

The API mirrors the Rust crate, which is itself shaped after rustls — so it reads much like
[pyrtls](https://github.com/djc/pyrtls), and close enough to the standard library's `ssl` module to
be unsurprising. It is **not** a drop-in replacement for `ssl`: this is a different protocol, not
TLS with a different implementation behind it.

## Install

```console
$ pip install maturin
$ maturin develop           # from this directory
```

Requires Python 3.11+ (abi3) and a Rust toolchain.

## Two layers

```python
import socket, mls_tls

cfg = mls_tls.ClientConfig(basic_credential=b"alice", verify=False)
with cfg.wrap_socket(socket.create_connection(("127.0.0.1", 8443)),
                     server_hostname="localhost") as s:
    s.sendall(b"hello")
    print(s.recv(1024))
```

Underneath is a sans-I/O core that holds no socket, for event loops and testing:

```python
conn = mls_tls.ClientConnection(cfg, "localhost")
conn.read_tls(data_from_network)
state = conn.process_new_packets()      # -> IoState
to_send = conn.write_tls()
conn.write(b"hello")
plaintext = conn.read()
```

Both layers expose the protocol's two control operations:

```python
s.refresh_traffic_keys()   # rotate keys mid-session; costs no round trip
session = s.session        # export, to resume on a later connection
```

## Things that differ from `ssl`

**Configs are immutable, and they are the unit of session sharing.** The MLS group state lives
inside the config, so resuming requires passing the *same* config object that exported the session.
There is no separate session cache to configure.

**`verify=False` is not only an escape hatch.** A peer using a Basic credential has no certificate
chain, so there is nothing for a verifier to check — it is the correct setting for that case, and
the default (`verify=True`) will reject such a peer with `CertificateError`.

**Keys and certificates are raw bytes.** Certificates are DER, leaf first. Private keys are the
signature scheme's own raw encoding — a 48-byte scalar for P-384, 64-byte keypair bytes for
Ed25519 — *not* PKCS#8 or PEM. Wrong lengths are rejected at config construction with a message
naming what was expected. To go from PEM, strip the armour yourself
(`ssl.PEM_cert_to_DER_cert` handles certificates without any extra dependency).

**A ragged EOF raises.** Reading returns `b""` only after a real `close_notify`; a transport that
dies without one raises `RaggedEOF`, because the stream may have been truncated. Pass
`suppress_ragged_eofs=True` for the `ssl` behaviour.

**`getpeercert()` requires `binary_form=True`.** There is no parsed-dict form — this library does
not carry an X.509 parser. Feed the DER to `cryptography.x509.load_der_x509_certificate` if you
need the fields.

## Cipher suites and backends

One crypto backend is compiled in, mirroring the crate's mutually-exclusive features:

| Build | `BACKEND` | Suites |
|---|---|---|
| `maturin develop` (default) | `"rustcrypto"` | pure Rust, plus the custom X-Wing suite `0x004e` |
| `maturin develop --no-default-features --features openssl,pyo3/extension-module` | `"openssl"` | system OpenSSL, standard suites only |

`SUPPORTED_CIPHER_SUITES` is asked of the provider at import rather than hardcoded, so it is
accurate for the build you have — the RustCrypto backend serves neither the X448 nor the P-521
suites, for instance. Check it before selecting a suite; an unavailable one raises
`UnsupportedError` at config construction.

X-Wing (ML-KEM-1024 + P-384) is the default under `rustcrypto` and has no OpenSSL path.

## Errors

```
MLSTLSError
├── WantReadError        need more bytes from the transport (non-blocking sockets)
├── WantWriteError       the outgoing buffer must be drained first
├── CertificateError     the peer's credential was rejected
├── HandshakeError       key agreement or record layer failure; fatal
├── UnsupportedError     this build cannot serve the request
└── RaggedEOF            the connection ended without close_notify
```

Argument mistakes raise `ValueError`, and transport failures raise `OSError`, as usual.

## Development

```console
$ maturin develop && python -m pytest tests -v
```

The test suite ports the crate's own loopback tests (`mls-tls/src/lib.rs`), so the two run the same
scenarios and a behavioural divergence shows up as a test that passes on one side only.

`examples/` talks to the crate's Rust interop peers over real TCP in both directions:

```console
$ cargo run -p mls-tls --bin simple_server -- 8443 &
$ PYTHONPATH=examples python examples/echo_client.py 8443

$ PYTHONPATH=examples python examples/echo_server.py 8444 &
$ cargo run -p mls-tls --bin simple_client -- 8444
```

Those two Rust binaries exchange the reference Python implementation's non-standard opening frame,
which the examples emulate in `examples/_interop.py`; pass `--no-interop` for a peer that does not.

## Not implemented

* **asyncio.** The sans-I/O core is the right foundation for it, but no event-loop layer ships yet.
* **Client certificate authentication.** `ClientCertVerifier::Roots` is not wired up end-to-end in
  the underlying crate, so servers accept a Basic client credential and there is no knob for it.
