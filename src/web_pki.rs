use std::{convert::Infallible, time::Duration};

use mls_rs::{
    ExtensionList, IdentityProvider,
    error::IntoAnyError,
    identity::{CredentialType, SigningIdentity},
};
use mls_rs_core::identity::MemberValidationContext;
use rustls_pki_types::{CertificateDer, InvalidDnsNameError, ServerName, TrustAnchor, UnixTime};

#[derive(Debug, thiserror::Error)]
pub enum WebPkiIdentityError {
    #[error("credential is not an X.509 certificate")]
    NotX509,
    #[error("unsupported client credential type: {0}")]
    UnsupportedClientCredential(&'static str),
    #[error("external senders are not supported")]
    UnsupportedExternalSender,
    #[error("X.509 certificate chain is empty")]
    EmptyChain,
    #[error("failed to parse end-entity certificate")]
    ParseCert(#[source] webpki::Error),
    #[error("certificate chain validation failed")]
    ChainValidation(#[source] webpki::Error),
    #[error("certificate subject-name validation failed")]
    NameValidation(#[source] webpki::Error),
}

impl IntoAnyError for WebPkiIdentityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

#[derive(Debug, Clone)]
pub enum PeerValidation<'a> {
    ServerName(ServerName<'a>),
    NoSubjectValidation,
}

impl<'a> From<ServerName<'a>> for PeerValidation<'a> {
    fn from(value: ServerName<'a>) -> Self {
        PeerValidation::ServerName(value)
    }
}

impl<'a> TryFrom<&'a str> for PeerValidation<'a> {
    type Error = InvalidDnsNameError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Ok(Self::from(ServerName::try_from(value)?))
    }
}

#[derive(Debug, Clone)]
pub struct WebPkiIdentityProvider<'a> {
    peer_validation: PeerValidation<'a>,
    trust_anchors: Vec<TrustAnchor<'static>>,
}

impl<'a> WebPkiIdentityProvider<'a> {
    pub fn new(peer_validation: PeerValidation<'a>) -> Self {
        Self {
            peer_validation,
            trust_anchors: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }
    }

    pub fn with_custom_roots(
        peer_validation: PeerValidation<'a>,
        trust_anchors: Vec<TrustAnchor<'static>>,
    ) -> Self {
        Self {
            peer_validation,
            trust_anchors,
        }
    }
}

impl<'a> IdentityProvider for WebPkiIdentityProvider<'a> {
    type Error = WebPkiIdentityError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<mls_rs::time::MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        let chain = signing_identity
            .credential
            .as_x509()
            .ok_or(WebPkiIdentityError::NotX509)?;

        let leaf_der = chain.leaf().ok_or(WebPkiIdentityError::EmptyChain)?;
        let leaf_cert_der = CertificateDer::from(leaf_der.as_ref());
        let ee_cert = webpki::EndEntityCert::try_from(&leaf_cert_der)
            .map_err(WebPkiIdentityError::ParseCert)?;

        let intermediates: Vec<CertificateDer> = chain
            .iter()
            .skip(1)
            .map(|c| CertificateDer::from(c.as_ref()))
            .collect();

        let time = timestamp
            .map(|t| UnixTime::since_unix_epoch(Duration::from_secs(t.seconds_since_epoch())))
            .unwrap_or_else(UnixTime::now);

        ee_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                &self.trust_anchors,
                &intermediates,
                time,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(WebPkiIdentityError::ChainValidation)?;

        match &self.peer_validation {
            PeerValidation::ServerName(server_name) => {
                ee_cert
                    .verify_is_valid_for_subject_name(server_name)
                    .map_err(WebPkiIdentityError::NameValidation)?;
            }
            PeerValidation::NoSubjectValidation => {}
        }
        Ok(())
    }

    fn validate_external_sender(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<mls_rs::time::MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        Err(WebPkiIdentityError::UnsupportedExternalSender)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        let chain = signing_identity
            .credential
            .as_x509()
            .ok_or(WebPkiIdentityError::NotX509)?;
        let leaf = chain.leaf().ok_or(WebPkiIdentityError::EmptyChain)?;
        // The leaf certificate bytes are the stable identity handle for X.509 members.
        Ok(leaf.to_vec())
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
        vec![CredentialType::X509]
    }
}

pub fn validate_client_credential(
    signing_identity: &SigningIdentity,
) -> Result<(), WebPkiIdentityError> {
    match &signing_identity.credential {
        mls_rs::identity::Credential::Basic(_) => Ok(()),
        mls_rs::identity::Credential::X509(_) => {
            Err(WebPkiIdentityError::UnsupportedClientCredential("x509"))
        }
        mls_rs::identity::Credential::Custom(_) => {
            Err(WebPkiIdentityError::UnsupportedClientCredential("custom"))
        }
        _ => Err(WebPkiIdentityError::UnsupportedClientCredential("unknown")),
    }
}

pub fn validate_server_credential(
    signing_identity: &SigningIdentity,
    trust_anchors: &[TrustAnchor<'_>],
    expected_name: Option<&ServerName<'_>>,
) -> Result<(), WebPkiIdentityError> {
    let chain = signing_identity
        .credential
        .as_x509()
        .ok_or(WebPkiIdentityError::NotX509)?;

    let leaf_der = chain.leaf().ok_or(WebPkiIdentityError::EmptyChain)?;
    let leaf_cert_der = CertificateDer::from(leaf_der.as_ref());
    let ee_cert =
        webpki::EndEntityCert::try_from(&leaf_cert_der).map_err(WebPkiIdentityError::ParseCert)?;

    let intermediates: Vec<CertificateDer> = chain
        .iter()
        .skip(1)
        .map(|c| CertificateDer::from(c.as_ref()))
        .collect();

    ee_cert
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            trust_anchors,
            &intermediates,
            UnixTime::now(),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(WebPkiIdentityError::ChainValidation)?;

    if let Some(server_name) = expected_name {
        ee_cert
            .verify_is_valid_for_subject_name(server_name)
            .map_err(WebPkiIdentityError::NameValidation)?;
    }

    Ok(())
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
    use ed25519_dalek::SigningKey;
    use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
    use mls_rs::identity::basic::BasicCredential;
    use mls_rs::identity::x509::{CertificateChain, DerCertificate};
    use mls_rs_core::identity::MemberValidationContext;
    use rcgen::KeyPair;
    use rustls_pki_types::CertificateDer;

    fn generate_ca_and_server_cert() -> (
        rcgen::CertifiedIssuer<'static, KeyPair>,
        rcgen::Certificate,
        KeyPair,
    ) {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ca_params = rcgen::CertificateParams::new(vec!["Test CA".into()]).unwrap();
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let server_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let server_cert = server_params.signed_by(&server_key, &ca).unwrap();

        (ca, server_cert, server_key)
    }

    fn ed25519_keypair_from_rcgen(kp: &KeyPair) -> (SignatureSecretKey, SignaturePublicKey) {
        let pkcs8_der = kp.serialize_der();
        let seed: [u8; 32] = pkcs8_der[16..48].try_into().unwrap();
        let signing_key = SigningKey::from_bytes(&seed);
        (
            SignatureSecretKey::new(signing_key.to_keypair_bytes().to_vec()),
            SignaturePublicKey::new(signing_key.verifying_key().to_bytes().to_vec()),
        )
    }

    #[test]
    fn basic_client_credential_is_accepted() {
        let identity = SigningIdentity::new(
            BasicCredential::new(b"client".to_vec()).into_credential(),
            SignaturePublicKey::new(vec![1, 2, 3]),
        );

        validate_client_credential(&identity).unwrap();
    }

    #[test]
    fn test_validate_member_with_custom_ca() {
        let (ca, server_cert, server_key) = generate_ca_and_server_cert();

        let (_secret, public) = ed25519_keypair_from_rcgen(&server_key);

        let chain = CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);
        let signing_identity = SigningIdentity::new(chain.into_credential(), public);

        let ca_der = CertificateDer::from(ca.der().to_vec());
        let trust_anchor = webpki::anchor_from_trusted_cert(&ca_der)
            .unwrap()
            .to_owned();

        let provider = WebPkiIdentityProvider::with_custom_roots(
            PeerValidation::NoSubjectValidation,
            vec![trust_anchor],
        );

        provider
            .validate_member(&signing_identity, None, MemberValidationContext::None)
            .expect("validation should succeed with custom CA");
    }
}
