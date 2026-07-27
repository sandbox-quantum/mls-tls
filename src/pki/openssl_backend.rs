//! X.509 chain verification via an OpenSSL `X509_STORE`.
//!
//! Used under the `openssl` backend, and required under `fips`: certificate signature verification
//! is a cryptographic service, so it has to happen inside the validated module rather than in
//! `ring`. Everything here goes through the default library context, which is where
//! [`crate::fips::enable`] installs the FIPS provider and the `fips=yes` default property.
//!
//! Name checking is done by the store's `X509_VERIFY_PARAM` (`set_host` / `set_ip`), which OpenSSL
//! applies during `X509_verify_cert` — deliberately *not* a separate post-hoc check, so a chain can
//! never be accepted with the name check accidentally skipped.

use mls_rs::identity::x509::CertificateChain;
use openssl::{
    error::ErrorStack,
    stack::Stack,
    x509::{
        X509, X509PurposeId, X509StoreContext, X509VerifyResult, store::X509StoreBuilder,
        verify::X509VerifyParam,
    },
};
use rustls_pki_types::ServerName;

use super::{PkiError, RootSource};

fn backend(e: ErrorStack) -> PkiError {
    PkiError::Backend(e.to_string())
}

fn parse(e: ErrorStack) -> PkiError {
    PkiError::ParseCert(e.to_string())
}

pub(super) fn validate_chain(
    chain: &CertificateChain,
    roots: RootSource<'_>,
    expected_name: Option<&ServerName<'_>>,
) -> Result<(), PkiError> {
    let mut builder = X509StoreBuilder::new().map_err(backend)?;

    match roots {
        RootSource::Explicit(certs) => {
            for cert in certs {
                builder
                    .add_cert(X509::from_der(cert).map_err(parse)?)
                    .map_err(backend)?;
            }
        }
        RootSource::Default => builder.set_default_paths().map_err(backend)?,
    }

    let mut param = X509VerifyParam::new().map_err(backend)?;
    param
        .set_purpose(X509PurposeId::SSL_SERVER)
        .map_err(backend)?;

    if let Some(server_name) = expected_name {
        match server_name {
            ServerName::DnsName(dns) => param
                .set_host(dns.as_ref())
                .map_err(|e| PkiError::NameValidation(e.to_string()))?,
            ServerName::IpAddress(ip) => param
                .set_ip(std::net::IpAddr::from(*ip))
                .map_err(|e| PkiError::NameValidation(e.to_string()))?,
            // `ServerName` is #[non_exhaustive]; refuse rather than silently skip the name check.
            other => {
                return Err(PkiError::NameValidation(format!(
                    "unsupported server name form: {other:?}"
                )));
            }
        }
    }

    // No explicit time is set, so OpenSSL checks validity against the current time.
    builder.set_param(&param).map_err(backend)?;
    let store = builder.build();

    let leaf_der = chain.leaf().ok_or(PkiError::EmptyChain)?;
    let leaf = X509::from_der(leaf_der).map_err(parse)?;

    // The untrusted stack is the intermediates only; the leaf is passed separately.
    let intermediates =
        chain
            .iter()
            .skip(1)
            .try_fold(Stack::new().map_err(backend)?, |mut stack, cert| {
                stack
                    .push(X509::from_der(cert).map_err(parse)?)
                    .map_err(backend)?;
                Ok::<_, PkiError>(stack)
            })?;

    let mut context = X509StoreContext::new().map_err(backend)?;
    let result = context
        .init(&store, &leaf, &intermediates, |ctx| {
            // `verify_cert` returning Err means the call itself failed; a rejected chain shows up
            // as a non-OK `ctx.error()`, which is what we surface.
            ctx.verify_cert()?;
            Ok(ctx.error())
        })
        .map_err(backend)?;

    match result {
        X509VerifyResult::OK => Ok(()),
        failure => Err(PkiError::ChainValidation(
            failure.error_string().to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::validate_server_credential;
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::x509::DerCertificate;
    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        ec::{EcGroup, EcKey},
        hash::MessageDigest,
        nid::Nid,
        pkey::{PKey, Private},
        x509::{X509Name, X509NameBuilder, extension as ext},
    };
    use rustls_pki_types::CertificateDer;

    fn p256_key() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    }

    fn name(cn: &str) -> X509Name {
        let mut b = X509NameBuilder::new().unwrap();
        b.append_entry_by_nid(Nid::COMMONNAME, cn).unwrap();
        b.build()
    }

    fn serial() -> openssl::asn1::Asn1Integer {
        let mut bn = BigNum::new().unwrap();
        bn.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        bn.to_asn1_integer().unwrap()
    }

    /// A self-signed P-256 CA. Built with OpenSSL so the `fips` test path needs no non-approved
    /// key generation (the `rustcrypto` tests use rcgen + Ed25519 instead).
    fn ca() -> (X509, PKey<Private>) {
        crate::test_init();
        let key = p256_key();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        b.set_subject_name(&name("Test CA")).unwrap();
        b.set_issuer_name(&name("Test CA")).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.append_extension(
            ext::BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.append_extension(
            ext::KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        (b.build(), key)
    }

    /// A leaf signed by `ca`, valid for `dns_name`.
    fn leaf(ca: &X509, ca_key: &PKey<Private>, dns_name: &str) -> X509 {
        let key = p256_key();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_serial_number(&serial()).unwrap();
        b.set_subject_name(&name(dns_name)).unwrap();
        b.set_issuer_name(ca.subject_name()).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        b.append_extension(ext::BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        b.append_extension(ext::ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        let san = ext::SubjectAlternativeName::new()
            .dns(dns_name)
            .build(&b.x509v3_context(Some(ca), None))
            .unwrap();
        b.append_extension(san).unwrap();
        b.sign(ca_key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    fn identity_for(cert: &X509) -> SigningIdentity {
        let chain = CertificateChain::from(vec![DerCertificate::new(cert.to_der().unwrap())]);
        // The signature key is not exercised by chain validation.
        SigningIdentity::new(
            chain.into_credential(),
            mls_rs::crypto::SignaturePublicKey::new(vec![0u8; 65]),
        )
    }

    #[test]
    fn validates_chain_against_custom_ca() {
        let (ca_cert, ca_key) = ca();
        let leaf_cert = leaf(&ca_cert, &ca_key, "localhost");
        let roots = vec![CertificateDer::from(ca_cert.to_der().unwrap())];

        validate_server_credential(
            &identity_for(&leaf_cert),
            RootSource::Explicit(&roots),
            Some(&ServerName::try_from("localhost").unwrap()),
        )
        .expect("chain should validate against its own CA");
    }

    #[test]
    fn rejects_wrong_server_name() {
        let (ca_cert, ca_key) = ca();
        let leaf_cert = leaf(&ca_cert, &ca_key, "localhost");
        let roots = vec![CertificateDer::from(ca_cert.to_der().unwrap())];

        assert!(matches!(
            validate_server_credential(
                &identity_for(&leaf_cert),
                RootSource::Explicit(&roots),
                Some(&ServerName::try_from("not-localhost").unwrap()),
            ),
            Err(PkiError::ChainValidation(_))
        ));
    }

    #[test]
    fn rejects_unknown_ca() {
        let (ca_cert, ca_key) = ca();
        let leaf_cert = leaf(&ca_cert, &ca_key, "localhost");
        let (other_ca, _) = ca();
        let roots = vec![CertificateDer::from(other_ca.to_der().unwrap())];

        assert!(matches!(
            validate_server_credential(
                &identity_for(&leaf_cert),
                RootSource::Explicit(&roots),
                Some(&ServerName::try_from("localhost").unwrap()),
            ),
            Err(PkiError::ChainValidation(_))
        ));
    }
}
