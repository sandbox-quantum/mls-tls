//! `ClientConfig` / `ServerConfig` — the Python face of the crate's typestate config builders.
//!
//! The Rust builders check at compile time that every required setting is supplied exactly once, in
//! order. Python has no such mechanism, so the same guarantees are re-imposed as keyword-argument
//! validation in one place: each constructor resolves its kwargs into exactly one branch of the
//! builder chain, raising `ValueError` for combinations the typestate would have rejected.
//!
//! A config is immutable and holds one `Arc<mls_tls::*Config>` shared by every connection made from
//! it. That is not just tidiness: the MLS group-state storage lives inside the Rust config, so
//! sharing the config is precisely what makes resumption work (see `mls_tls::resumption`).

use std::sync::Arc;

use mls_tls::{
    BasicCredential, CertificateChain, CertificateDer, CipherSuite, ClientConfig as RsClientConfig,
    ConfigBuilder, ServerConfig as RsServerConfig, SignaturePublicKey, SignatureSecretKey,
    SigningIdentity, client::WantsClientCredential, server::WantsServerCredential,
};
use pyo3::{exceptions::PyValueError, prelude::*};

use crate::error::to_py_err;

/// The credential pieces every config needs, plus the public key we hand back to callers.
struct Credential {
    identity: SigningIdentity,
    signer: SignatureSecretKey,
    public: SignaturePublicKey,
}

/// Resolve the credential kwargs into a signing identity.
///
/// Exactly one of `basic_credential` / `cert_chain` selects the credential type; the key is either
/// supplied or generated. Generating is routed through `generate_signature_key` rather than the
/// crate's `with_generated_basic_credential` shortcut so that the public half stays reachable —
/// callers need it to publish their own identity, and the interop examples need it for the Python
/// reference implementation's opening frame.
fn resolve_credential(
    cipher_suite: CipherSuite,
    basic_credential: Option<Vec<u8>>,
    cert_chain: Option<Vec<Vec<u8>>>,
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> PyResult<Credential> {
    let credential = match (basic_credential, cert_chain) {
        (Some(_), Some(_)) => {
            return Err(PyValueError::new_err(
                "pass either basic_credential or cert_chain, not both",
            ));
        }
        (None, None) => {
            return Err(PyValueError::new_err(
                "a credential is required: pass basic_credential=b'...' for a Basic credential, \
                 or cert_chain=[der, ...] with private_key= for an X.509 one",
            ));
        }
        (Some(name), None) => BasicCredential::new(name).into_credential(),
        (None, Some(chain)) => {
            if chain.is_empty() {
                return Err(PyValueError::new_err("cert_chain must not be empty"));
            }
            if private_key.is_none() {
                return Err(PyValueError::new_err(
                    "cert_chain requires private_key (the raw signing key matching the leaf \
                     certificate)",
                ));
            }
            CertificateChain::from(chain).into_credential()
        }
    };

    let (signer, public) = match private_key {
        None => mls_tls::generate_signature_key(cipher_suite).map_err(to_py_err)?,
        Some(key) => {
            let supplied_len = key.len();

            // Length-check against a throwaway key of the same suite before trusting the encoding.
            // Deriving alone is not enough: RustCrypto's P-384 accepts a short, left-padded scalar,
            // so a truncated key file would be taken as a valid — and very weak — identity instead
            // of being reported. A signature keygen is microseconds, and this only runs when the
            // caller supplies a key.
            let expected_len = mls_tls::generate_signature_key(cipher_suite)
                .map_err(to_py_err)?
                .0
                .as_bytes()
                .len();
            if supplied_len != expected_len {
                return Err(PyValueError::new_err(format!(
                    "private_key is {supplied_len} bytes but cipher suite 0x{:04x} expects \
                     {expected_len}; it must be the signature scheme's raw encoding (a 48-byte \
                     scalar for P-384, 64-byte keypair bytes for Ed25519), not PKCS#8 or PEM",
                    u16::from(cipher_suite)
                )));
            }

            let signer = SignatureSecretKey::new(key);
            // Derive rather than trust a supplied public key: right length is not the same as
            // valid, and deriving proves the scalar is usable.
            let derived =
                mls_tls::derive_signature_public_key(cipher_suite, &signer).map_err(|_| {
                    PyValueError::new_err(format!(
                        "private_key is the right length but is not a valid signing key for \
                         cipher suite 0x{:04x}",
                        u16::from(cipher_suite)
                    ))
                })?;
            match public_key {
                None => (signer, derived),
                Some(supplied) if supplied == derived.as_bytes() => (signer, derived),
                Some(_) => {
                    return Err(PyValueError::new_err(
                        "public_key does not match private_key for this cipher suite",
                    ));
                }
            }
        }
    };

    Ok(Credential {
        identity: SigningIdentity::new(credential, public.clone()),
        signer,
        public,
    })
}

fn der_roots(roots: Vec<Vec<u8>>) -> Vec<CertificateDer<'static>> {
    roots.into_iter().map(CertificateDer::from).collect()
}

/// Immutable client configuration. Every connection built from one shares its session storage, so
/// resumption requires reusing the same object.
#[pyclass(frozen, subclass, module = "mls_tls", name = "ClientConfig")]
pub(crate) struct PyClientConfig {
    pub(crate) inner: Arc<RsClientConfig>,
    cipher_suite: CipherSuite,
    public_key: Vec<u8>,
}

#[pymethods]
impl PyClientConfig {
    /// Build a client configuration.
    ///
    /// Verification: by default the server's X.509 chain is checked against the compiled backend's
    /// built-in roots. Pass `root_certificates=[der, ...]` to supply your own, or `verify=False` to
    /// accept any credential — which is what a Basic-credential peer requires, since it has no
    /// chain to check.
    #[new]
    #[pyo3(signature = (
        *,
        basic_credential = None,
        cert_chain = None,
        private_key = None,
        public_key = None,
        root_certificates = None,
        verify = true,
        cipher_suite = None,
    ))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        py: Python<'_>,
        basic_credential: Option<Vec<u8>>,
        cert_chain: Option<Vec<Vec<u8>>>,
        private_key: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
        root_certificates: Option<Vec<Vec<u8>>>,
        verify: bool,
        cipher_suite: Option<u16>,
    ) -> PyResult<Self> {
        if !verify && root_certificates.is_some() {
            return Err(PyValueError::new_err(
                "root_certificates is meaningless with verify=False; pass one or the other",
            ));
        }
        let suite = cipher_suite.map_or(mls_tls::DEFAULT_CIPHER_SUITE, CipherSuite::new);

        // Key generation runs ML-KEM for the X-Wing suite, which is slow enough to be worth
        // yielding the interpreter for.
        let credential = py.detach(|| {
            resolve_credential(suite, basic_credential, cert_chain, private_key, public_key)
        })?;

        let stage: ConfigBuilder<RsClientConfig, WantsClientCredential> = if !verify {
            RsClientConfig::builder().with_no_certificate_verification()
        } else if let Some(roots) = root_certificates {
            RsClientConfig::builder().with_root_certificates(der_roots(roots))
        } else {
            #[cfg(feature = "rustcrypto")]
            {
                RsClientConfig::builder().with_webpki_roots()
            }
            #[cfg(feature = "openssl")]
            {
                RsClientConfig::builder().with_system_roots()
            }
        };

        let public_key = credential.public.as_bytes().to_vec();
        let inner = stage
            .with_cipher_suite(suite)
            .with_client_credential(credential.identity, credential.signer);

        Ok(Self {
            inner,
            cipher_suite: suite,
            public_key,
        })
    }

    /// The MLS cipher suite this config negotiates with.
    #[getter]
    fn cipher_suite(&self) -> u16 {
        self.cipher_suite.into()
    }

    /// The public half of this config's signing key, raw-encoded for the suite's scheme.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.public_key)
    }

    fn __repr__(&self) -> String {
        format!(
            "<mls_tls.ClientConfig cipher_suite=0x{:04x}>",
            u16::from(self.cipher_suite)
        )
    }
}

/// Immutable server configuration. Shared session storage works the same way as on the client: a
/// resumed connection can only be reloaded by a server built from the same config object.
#[pyclass(frozen, subclass, module = "mls_tls", name = "ServerConfig")]
pub(crate) struct PyServerConfig {
    pub(crate) inner: Arc<RsServerConfig>,
    cipher_suite: CipherSuite,
    public_key: Vec<u8>,
}

#[pymethods]
impl PyServerConfig {
    /// Build a server configuration.
    ///
    /// There is no client-verification knob: client X.509 authentication is not wired up
    /// end-to-end in the crate, so the server always accepts a Basic client credential.
    #[new]
    #[pyo3(signature = (
        *,
        basic_credential = None,
        cert_chain = None,
        private_key = None,
        public_key = None,
        cipher_suite = None,
    ))]
    fn new(
        py: Python<'_>,
        basic_credential: Option<Vec<u8>>,
        cert_chain: Option<Vec<Vec<u8>>>,
        private_key: Option<Vec<u8>>,
        public_key: Option<Vec<u8>>,
        cipher_suite: Option<u16>,
    ) -> PyResult<Self> {
        let suite = cipher_suite.map_or(mls_tls::DEFAULT_CIPHER_SUITE, CipherSuite::new);
        let credential = py.detach(|| {
            resolve_credential(suite, basic_credential, cert_chain, private_key, public_key)
        })?;

        let stage: ConfigBuilder<RsServerConfig, WantsServerCredential> =
            RsServerConfig::builder().with_no_client_auth();

        let public_key = credential.public.as_bytes().to_vec();
        let inner = stage
            .with_cipher_suite(suite)
            .with_server_credential(credential.identity, credential.signer);

        Ok(Self {
            inner,
            cipher_suite: suite,
            public_key,
        })
    }

    /// The MLS cipher suite this config negotiates with.
    #[getter]
    fn cipher_suite(&self) -> u16 {
        self.cipher_suite.into()
    }

    /// The public half of this config's signing key, raw-encoded for the suite's scheme.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, pyo3::types::PyBytes> {
        pyo3::types::PyBytes::new(py, &self.public_key)
    }

    fn __repr__(&self) -> String {
        format!(
            "<mls_tls.ServerConfig cipher_suite=0x{:04x}>",
            u16::from(self.cipher_suite)
        )
    }
}
