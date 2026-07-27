# FIPS test environment

`mls-tls --features fips` needs an OpenSSL FIPS module. Most distributions do not ship one by
default (Homebrew's `openssl@3`, for instance, has no `fips.dylib`), so this image builds one.

```sh
docker build -t mls-tls-fips docker/fips
docker run --rm -v "$PWD:/src" -w /src -e CARGO_TARGET_DIR=/tmp/target mls-tls-fips
```

The default command is `cargo test --no-default-features --features fips`.

`CARGO_TARGET_DIR=/tmp/target` keeps the Linux build out of the bind-mounted `target/`, which
otherwise fights with the host's artifacts. Drop it only if you don't build on the host.

Last verified: OpenSSL 3.5.0, linux/arm64 — 19 lib tests and 8 `fips_mode` tests pass, including
the record-layer byte-parity KAT.

## What the image does

1. Builds OpenSSL (3.5+) from source with `enable-fips` into `/opt/openssl-fips`.
2. Runs `openssl fipsinstall` to generate the module's integrity MAC and self-test status.
3. **Strips `activate = 1`** from the generated `fipsmodule.cnf`. `fips_module(7)` is explicit that
   for programmatic loading the line must be *absent* — `activate = 0` is not sufficient. The
   application controls activation via `mls_tls::fips::enable()`.
4. Sets `OPENSSL_DIR` so `openssl-sys` links this build rather than the system one.
5. Asserts at image-build time that the provider actually loads, so a broken module is a build
   failure rather than a confusing test failure.

## Nothing works until `enable()` is called

Worth knowing before you debug a confusing failure: declaring a `provider_sect` in openssl.cnf
suppresses OpenSSL's automatic default-provider fallback. Since this config activates *nothing*,
a process that never calls `mls_tls::fips::enable()` has **zero** providers loaded, and every
algorithm fetch fails with

```
digital envelope routines:inner_evp_generic_fetch:unsupported ... Algorithm (HKDF : 0)
```

That is not a FIPS rejection — it means no provider was available to serve the fetch at all.
`mls-tls` guards its own entry points (the three connection constructors and
`generate_signature_key`) so this surfaces as a readable `Error::Fips`, and `test_init()` in
`src/lib.rs` covers the unit tests that reach the crypto directly. Application code that calls
OpenSSL outside `mls-tls` needs the same discipline.

## Not a validated configuration

A self-built module is not CMVP-validated. This image is for checking that the *code* behaves
correctly under FIPS rules — approved suites work, non-approved ones are refused, nothing silently
falls back to the default provider. It is not evidence of compliance. For that, run against the
validated module your platform ships (RHEL, Ubuntu Pro, or a vendor build) and consult its security
policy.

## Why 3.5+

Older FIPS modules — including the OpenSSL 3.0.x line that several distributions validated — reject
HKDF in `EXPAND_ONLY` mode when the requested output is shorter than the digest. MLS derives a
12-byte AEAD nonce that way for *every* message, so the whole stack fails on such a module. The fix
landed in current branches, but a validated module cannot be patched without re-validation.

`build.rs` refuses to build below 3.5, and `tests/fips_mode.rs::short_hkdf_expand_is_accepted`
probes the behaviour directly so the module's real answer is recorded rather than assumed.

## Checking against a different module

To test against a platform module instead of this image, point the build at it and run the same
suite:

```sh
OPENSSL_DIR=/usr OPENSSL_CONF=/etc/ssl/openssl.cnf \
    cargo test --no-default-features --features fips
```

If that module predates 3.5, `build.rs` will stop the build and explain why.
