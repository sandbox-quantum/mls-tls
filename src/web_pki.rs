use std::time::Duration;

use mls_rs::{ExtensionList, IdentityProvider, error::IntoAnyError, identity::{CredentialType, SigningIdentity}};
use mls_rs_core::identity::MemberValidationContext;
use rustls_pki_types::{CertificateDer, InvalidDnsNameError, ServerName, UnixTime};

#[derive(Debug, Clone)]
pub enum WebPkiIdentityError {
    NotX509,
    EmptyChain,
    ChainValidation(String),
    NameValidation(String),
}

impl IntoAnyError for WebPkiIdentityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(format!("{self:?}").into())
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
}

impl<'a> WebPkiIdentityProvider<'a> {
    pub fn new(peer_validation: PeerValidation<'a>) -> Self {
        Self {
            peer_validation
        }
    }
}

impl<'a> IdentityProvider for WebPkiIdentityProvider<'a> {
    type Error = WebPkiIdentityError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<mls_rs::time::MlsTime>,
        context: MemberValidationContext<'_>, // TODO: Need to check that properly
    ) -> Result<(), Self::Error> {
        let chain = signing_identity
            .credential
            .as_x509()
            .ok_or(WebPkiIdentityError::NotX509)?;

        let leaf_der = chain.leaf().ok_or(WebPkiIdentityError::EmptyChain)?;
        let leaf_cert_der = CertificateDer::from(leaf_der.as_ref());
        let ee_cert = webpki::EndEntityCert::try_from(&leaf_cert_der)
            .map_err(|e| WebPkiIdentityError::ChainValidation(e.to_string()))?;

        let intermediates: Vec<CertificateDer> = chain
            .iter()
            .skip(1)
            .map(|c| CertificateDer::from(c.as_ref()))
            .collect();

        let time = timestamp
            .map(|t| UnixTime::since_unix_epoch(Duration::from_secs(t.seconds_since_epoch())))
            .unwrap_or_else(|| UnixTime::now());

        ee_cert
            .verify_for_usage(
                webpki::ALL_VERIFICATION_ALGS,
                webpki_roots::TLS_SERVER_ROOTS,
                &intermediates,
                time,
                webpki::KeyUsage::server_auth(),
                None,
                None,
            )
            .map_err(|err| WebPkiIdentityError::ChainValidation(err.to_string()))?;

        match &self.peer_validation {
            PeerValidation::ServerName(server_name) => {
                ee_cert
                    .verify_is_valid_for_subject_name(server_name)
                    .map_err(|e| WebPkiIdentityError::NameValidation(e.to_string()))?;
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
        unimplemented!("MLS+TLS has no external sender.")
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
        // IMPLEMENTOR NOTE: What identifier should be used with MLS+TLS when using X509?
        // should this be specified?
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
