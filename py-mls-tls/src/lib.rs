//! `mls_tls._mls_tls` — the compiled core of the `mls_tls` Python package.
//!
//! This is a private module. The public API lives in `python/mls_tls/__init__.py`, which re-exports
//! everything here and adds the socket wrapper on top. Keeping the split means socket semantics
//! (timeouts, non-blocking, `makefile`) come from Python's own socket object rather than being
//! reimplemented in Rust.
//!
//! # Backend
//!
//! Exactly one crypto backend is compiled in, matching the core crate's mutually-exclusive
//! `rustcrypto` / `openssl` features. `BACKEND` and `SUPPORTED_CIPHER_SUITES` report which, so
//! callers and tests can branch on it instead of hardcoding assumptions — notably, the X-Wing suite
//! `0x004e` exists only under `rustcrypto`.

use mls_tls::CipherSuite;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

mod config;
mod conn;
mod error;

use error::to_py_err;

/// Which crypto backend this extension was built against.
#[cfg(feature = "rustcrypto")]
const BACKEND: &str = "rustcrypto";
#[cfg(feature = "openssl")]
const BACKEND: &str = "openssl";

/// Generate a signature keypair for `cipher_suite`, returning `(private_key, public_key)`.
///
/// Both are raw bytes in the encoding that suite's signature scheme uses, ready to pass back as
/// `private_key=` / `public_key=` on a config. Raises `UnsupportedError` if this build does not
/// serve the suite.
#[pyfunction]
fn generate_signature_key<'py>(
    py: Python<'py>,
    cipher_suite: u16,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let (secret, public) = py
        .detach(|| mls_tls::generate_signature_key(CipherSuite::new(cipher_suite)))
        .map_err(to_py_err)?;
    Ok((
        PyBytes::new(py, secret.as_bytes()),
        PyBytes::new(py, public.as_bytes()),
    ))
}

/// Recover the public half of an existing signature key.
///
/// The counterpart to `generate_signature_key` for a key loaded from elsewhere. Raises
/// `UnsupportedError` if the key is not valid for `cipher_suite` — the encoding is scheme-specific,
/// so this doubles as a check that a key and a suite belong together.
#[pyfunction]
fn derive_signature_public_key<'py>(
    py: Python<'py>,
    cipher_suite: u16,
    private_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let secret = mls_tls::SignatureSecretKey::new(private_key.to_vec());
    let public = mls_tls::derive_signature_public_key(CipherSuite::new(cipher_suite), &secret)
        .map_err(to_py_err)?;
    Ok(PyBytes::new(py, public.as_bytes()))
}

/// The MLS cipher suites, by their registry names.
///
/// Every suite the registry defines is listed, not only the ones this build serves, so the
/// constants are stable to import across backends; check `SUPPORTED_CIPHER_SUITES` before using one.
const CIPHER_SUITE_NAMES: &[(&str, u16)] = &[
    ("MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519", 0x0001),
    ("MLS_128_DHKEMP256_AES128GCM_SHA256_P256", 0x0002),
    (
        "MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519",
        0x0003,
    ),
    ("MLS_256_DHKEMX448_AES256GCM_SHA512_ED448", 0x0004),
    ("MLS_256_DHKEMP521_AES256GCM_SHA512_P521", 0x0005),
    ("MLS_256_DHKEMX448_CHACHA20POLY1305_SHA512_ED448", 0x0006),
    ("MLS_256_DHKEMP384_AES256GCM_SHA384_P384", 0x0007),
    // Non-standard: the X-Wing (ML-KEM-1024 + P-384) suite used for interop with the Python
    // reference implementation. `rustcrypto` only.
    ("MLS_256_XWING_AES256GCM_SHA512_P384", 0x004e),
];

/// Map a suite id back to its registry name; `None` for an id outside the table.
#[pyfunction]
fn cipher_suite_name(cipher_suite: u16) -> Option<&'static str> {
    CIPHER_SUITE_NAMES
        .iter()
        .find(|(_, id)| *id == cipher_suite)
        .map(|(name, _)| *name)
}

#[pymodule]
fn _mls_tls(module: &Bound<'_, PyModule>) -> PyResult<()> {
    error::register(module)?;

    module.add_class::<config::PyClientConfig>()?;
    module.add_class::<config::PyServerConfig>()?;
    module.add_class::<conn::PyClientConnection>()?;
    module.add_class::<conn::PyServerConnection>()?;
    module.add_class::<conn::PyIoState>()?;
    module.add_class::<conn::PySession>()?;

    module.add_function(wrap_pyfunction!(generate_signature_key, module)?)?;
    module.add_function(wrap_pyfunction!(derive_signature_public_key, module)?)?;
    module.add_function(wrap_pyfunction!(cipher_suite_name, module)?)?;

    module.add("BACKEND", BACKEND)?;
    module.add(
        "DEFAULT_CIPHER_SUITE",
        u16::from(mls_tls::DEFAULT_CIPHER_SUITE),
    )?;

    // Asked of the provider rather than hardcoded, so it stays honest about a backend that serves
    // fewer suites than the registry defines.
    let mut supported: Vec<u16> = mls_tls::supported_cipher_suites()
        .into_iter()
        .map(u16::from)
        .collect();
    supported.sort_unstable();
    module.add("SUPPORTED_CIPHER_SUITES", supported)?;

    for (name, id) in CIPHER_SUITE_NAMES {
        module.add(*name, *id)?;
    }
    Ok(())
}
