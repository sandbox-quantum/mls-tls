// https://www.ietf.org/archive/id/draft-kohbrok-mls-tls-00.html

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
    CipherSuite, CipherSuiteProvider, CryptoProvider, Group, client_builder::MlsConfig,
    crypto::Secret, error::MlsError,
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
    // draft-kohbrok-mls-tls-00 §6 leaves several record-layer details to the MLS cipher suite. This
    // implementation derives a traffic secret whose length is the suite KDF output size, matching
    // TLS 1.3 traffic-secret sizing; the concrete record AEAD/hash mapping lives in `tls_record`.
    //
    let ciphersuite_provider = crypto_provider
        .cipher_suite_provider(group.cipher_suite())
        .ok_or_else(|| MlsTlsError::UnsupportedCipherSuite(group.cipher_suite()))?;
    let len = ciphersuite_provider.kdf_extract_size();

    let secret = group.export_secret(label, &[], len)?;
    Ok(secret)
}

// Traffic-secret labels match interoperable implementation exactly — note there
// is NO space between "1.0" and "Initial" (`"MLS-TLS 1.0" + "Initial ... Traffic Secret"`).
pub(crate) fn derive_server_application_traffic_secret(
    group: &Group<impl MlsConfig>,
    crypto_provider: impl CryptoProvider,
) -> Result<Secret, MlsTlsError> {
    derive_key(
        group,
        crypto_provider,
        b"MLS-TLS 1.0Initial Server Traffic Secret", // Here we match the implementation and not thedraft for interoperability
    )
}

pub(crate) fn derive_client_application_traffic_secret(
    group: &Group<impl MlsConfig>,
    crypto_provider: impl CryptoProvider,
) -> Result<Secret, MlsTlsError> {
    derive_key(
        group,
        crypto_provider,
        b"MLS-TLS 1.0Initial Client Traffic Secret", // Here we match the implementation and not the draft for interoperability
    )
}
