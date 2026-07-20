// https://www.ietf.org/archive/id/draft-kohbrok-mls-tls-00.html


// IMPLEMENTOR'S QUESTION: does MLS-TLS support the TLS server resuming the connection? How does that even work at the transport level?

// > 6. Deriving keys for record layer protection
// > Both after the initial key agreement phase and the resumption phase, initiator and responder derive key material from the MLS group created during the initial key agreement phase.
// >
// > The client_application_traffic_secret and the server_application_traffic_secret required by the record layer are derived as follows.
// >
// > server_application_traffic_secret =
// >   MLS-Exporter("MLS-TLS s ap traffic", [], Length)
// >
// > client_application_traffic_secret =
// >   MLS-Exporter("MLS-TLS c ap traffic", [], Length)
// >
// > Where MLS-Exporter is defined in [RFC9420] and Length is the size of the secret required by the TLS record layer.

use mls_rs::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, Group, client_builder::MlsConfig, crypto::Secret, error::MlsError,
};

#[derive(Debug, thiserror::Error)]
pub enum MlsTlsError {
    #[error("unsupported cipher suite: {0:?}")]
    UnsupportedCipherSuite(CipherSuite),
    #[error("MLS secret export failed")]
    Export(#[from] MlsError),
}

/// |    |             |                  |                  |                  |
/// |----|-------------|------------------|------------------|------------------|
/// | ID | KEM         | AEAD             | Hash Function    | Signature Scheme |
/// | 1  | DHKEMX25519 | AES 128          | SHA 256          | Ed25519          |
/// | 2  | DHKEMP256   | AES 128          | SHA 256          | P256             |
/// | 3  | DHKEMX25519 | ChaCha20Poly1305 | SHA 256          | Ed25519          |
/// | 4  | DHKEMX448   | AES 256          | SHA 512          | Ed448            |
/// | 5  | DHKEMP521   | AES 256          | SHA 512          | P521             |
/// | 6  | DHKEMX448   | ChaCha20Poly1305 | SHA 512          | Ed448            |
/// | 7  | DHKEMP384   | AES 256          | SHA 512          | P384             |
fn derive_key(
    group: &Group<impl MlsConfig>,
    crypto_provider: impl CryptoProvider,
    label: &[u8],
) -> Result<Secret, MlsTlsError> {
    // IMPLEMENTOR'S NOTE (draft-kohbrok-mls-tls-00 §6): The draft does not specify how MLS cipher
    // suites map to TLS AEAD algorithms. We assume MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    // maps to TLS_AES_128_GCM_SHA256 (AES-128-GCM for record protection, SHA-256 for HKDF).
    //
    // IMPLEMENTOR'S NOTE (draft-kohbrok-mls-tls-00 §6): The "Length" parameter in the MLS-Exporter
    // call is undefined. We assume it is the hash output length (32 bytes for SHA-256), matching
    // RFC 8446 §7.1 where traffic secrets are hash-length.
    //
    // IMPLEMENTOR'S NOTE (draft-kohbrok-mls-tls-00 §6): The hash function for HKDF-Expand-Label is
    // unspecified. We assume the hash from the MLS cipher suite (SHA-256 for CURVE25519_AES128).
    // The actual HKDF derivation lives in mls_tls.rs; this module consumes the derived key and IV.
    let ciphersuite_provider = crypto_provider
        .cipher_suite_provider(group.cipher_suite())
        .ok_or_else(|| MlsTlsError::UnsupportedCipherSuite(group.cipher_suite()))?;
    let len = ciphersuite_provider.kdf_extract_size();

    let secret = group.export_secret(
        label,
        &[], // TODO: Figure out what context is, and should it be set for MLS-TLS?
        len,
    )?;
    Ok(secret)
}

// Traffic-secret labels match the Python `mls-tls-python-pedantic` reference exactly — note there
// is NO space between "1.0" and "Initial" (`"MLS-TLS 1.0" + "Initial ... Traffic Secret"`).
pub(crate) fn derive_server_application_traffic_secret(
    group: &Group<impl MlsConfig>,
    crypto_provider: impl CryptoProvider,
) -> Result<Secret, MlsTlsError> {
    derive_key(group, crypto_provider, b"MLS-TLS 1.0Initial Server Traffic Secret")
}

pub(crate) fn derive_client_application_traffic_secret(
    group: &Group<impl MlsConfig>,
    crypto_provider: impl CryptoProvider,
) -> Result<Secret, MlsTlsError> {
    derive_key(group, crypto_provider, b"MLS-TLS 1.0Initial Client Traffic Secret")
}


// IMPLEMENTOR'S QUESTION: what happens to all to the TLS key update mechanism in MLS TLS. Is i tcompletely replaced by MLS-TLS or happen in parallel? 
