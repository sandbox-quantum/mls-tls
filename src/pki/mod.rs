//! Peer credential validation.
//!
//! Two things live here, and they are deliberately separate:
//!
//! - **Directional peer checks** — `validate_client_credential` / `validate_server_credential`,
//!   applied by hand at the handshake. Peer auth in this protocol is asymmetric (a Basic client may
//!   talk to an X.509 server), so it cannot be expressed as an mls-rs `IdentityProvider`.
//! - **The group's identity provider** — [`PassThroughIdentityProvider`], which is always
//!   accept-all. mls-rs applies one provider symmetrically to every member; see [`crate::mls_config`].
//!
//! ## Backends
//!
//! X.509 chain verification is cryptography, so it follows the compile-time backend rather than
//! being fixed:
//!
//! - `rustcrypto` → [`webpki_backend`], i.e. `rustls-webpki` over `ring`.
//! - `openssl` → [`openssl_backend`], i.e. an OpenSSL `X509_STORE`.
//!
//! Both expose the same `validate_chain`, so the callers above are backend-agnostic.

#[cfg(feature = "openssl")]
mod openssl_backend;
#[cfg(feature = "rustcrypto")]
mod webpki_backend;

#[cfg(feature = "openssl")]
use openssl_backend::validate_chain;
#[cfg(feature = "rustcrypto")]
use webpki_backend::validate_chain;

use std::convert::Infallible;

use mls_rs::{
    ExtensionList, IdentityProvider,
    error::IntoAnyError,
    identity::{CredentialType, SigningIdentity},
};
use mls_rs_core::identity::MemberValidationContext;
use rustls_pki_types::{CertificateDer, ServerName};

#[derive(Debug, thiserror::Error)]
pub enum PkiError {
    #[error("credential is not an X.509 certificate")]
    NotX509,
    #[error("unsupported client credential type: {0}")]
    UnsupportedClientCredential(&'static str),
    #[error("external senders are not supported")]
    UnsupportedExternalSender,
    #[error("X.509 certificate chain is empty")]
    EmptyChain,
    #[error("failed to parse certificate: {0}")]
    ParseCert(String),
    #[error("certificate chain validation failed: {0}")]
    ChainValidation(String),
    #[error("certificate subject-name validation failed: {0}")]
    NameValidation(String),
    /// The verification backend itself failed (allocation, store setup) — distinct from the
    /// certificate being rejected.
    #[error("certificate verification backend error: {0}")]
    Backend(String),
}

impl IntoAnyError for PkiError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// Where the trust anchors for a chain validation come from.
///
/// `Default` means different things per backend — the bundled Mozilla root set under `rustcrypto`,
/// OpenSSL's configured trust store under `openssl` — which is why the public builder spells it
/// with a backend-specific method name rather than one shared one.
pub(crate) enum RootSource<'a> {
    Explicit(&'a [CertificateDer<'static>]),
    Default,
}

/// Check the credential a *client* presented in its KeyPackage.
///
/// Only Basic credentials are accepted today; client X.509 auth is not wired up end to end.
pub fn validate_client_credential(signing_identity: &SigningIdentity) -> Result<(), PkiError> {
    match &signing_identity.credential {
        mls_rs::identity::Credential::Basic(_) => Ok(()),
        mls_rs::identity::Credential::X509(_) => Err(PkiError::UnsupportedClientCredential("x509")),
        mls_rs::identity::Credential::Custom(_) => {
            Err(PkiError::UnsupportedClientCredential("custom"))
        }
        _ => Err(PkiError::UnsupportedClientCredential("unknown")),
    }
}

/// Check the X.509 credential a *server* presented: chain to a trust anchor, and (when
/// `expected_name` is given) match the requested name.
pub fn validate_server_credential(
    signing_identity: &SigningIdentity,
    roots: RootSource<'_>,
    expected_name: Option<&ServerName<'_>>,
) -> Result<(), PkiError> {
    let chain = signing_identity
        .credential
        .as_x509()
        .ok_or(PkiError::NotX509)?;

    validate_chain(chain, roots, expected_name)
}

#[derive(Debug, Clone, Default)]
pub struct PassThroughIdentityProvider;

impl IdentityProvider for PassThroughIdentityProvider {
    type Error = Infallible;

    fn validate_member(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn validate_external_sender(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        match &signing_identity.credential {
            mls_rs::identity::Credential::Basic(basic) => Ok(basic.identifier.to_vec()),
            mls_rs::identity::Credential::X509(chain) if let Some(leaf) = chain.leaf() => {
                Ok(leaf.to_vec())
            }
            _ => Ok(signing_identity.signature_key.as_ref().to_vec()),
        }
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        Ok(self.identity(predecessor, extensions)? == self.identity(successor, extensions)?)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::X509, CredentialType::BASIC]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mls_rs::crypto::SignaturePublicKey;
    use mls_rs::identity::basic::BasicCredential;

    #[test]
    fn basic_client_credential_is_accepted() {
        let identity = SigningIdentity::new(
            BasicCredential::new(b"client".to_vec()).into_credential(),
            SignaturePublicKey::new(vec![1, 2, 3]),
        );

        validate_client_credential(&identity).unwrap();
    }

    #[test]
    fn x509_client_credential_is_rejected() {
        use mls_rs::identity::x509::{CertificateChain, DerCertificate};

        let chain = CertificateChain::from(vec![DerCertificate::new(vec![0x30, 0x00])]);
        let identity = SigningIdentity::new(
            chain.into_credential(),
            SignaturePublicKey::new(vec![1, 2, 3]),
        );

        assert!(matches!(
            validate_client_credential(&identity),
            Err(PkiError::UnsupportedClientCredential("x509"))
        ));
    }
}
