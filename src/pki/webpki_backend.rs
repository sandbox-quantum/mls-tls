//! X.509 chain verification via `rustls-webpki` (backed by `ring`). Used under the `rustcrypto`
//! backend only — an `openssl` build would otherwise pull in a second crypto stack, so it uses
//! [`super::openssl_backend`] instead.

use mls_rs::identity::x509::CertificateChain;
use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor, UnixTime};

use super::{PkiError, RootSource};

pub(super) fn validate_chain(
    chain: &CertificateChain,
    roots: RootSource<'_>,
    expected_name: Option<&ServerName<'_>>,
) -> Result<(), PkiError> {
    let anchors: Vec<TrustAnchor<'static>> = match roots {
        RootSource::Explicit(certs) => certs
            .iter()
            .map(|cert| {
                webpki::anchor_from_trusted_cert(cert)
                    .map(|anchor| anchor.to_owned())
                    .map_err(|e| PkiError::ParseCert(e.to_string()))
            })
            .collect::<Result<_, _>>()?,
        RootSource::Default => webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let leaf_der = chain.leaf().ok_or(PkiError::EmptyChain)?;
    let leaf_cert_der = CertificateDer::from(leaf_der.as_ref());
    let ee_cert = webpki::EndEntityCert::try_from(&leaf_cert_der)
        .map_err(|e| PkiError::ParseCert(e.to_string()))?;

    let intermediates: Vec<CertificateDer> = chain
        .iter()
        .skip(1)
        .map(|c| CertificateDer::from(c.as_ref()))
        .collect();

    ee_cert
        .verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &anchors,
            &intermediates,
            UnixTime::now(),
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|e| PkiError::ChainValidation(e.to_string()))?;

    if let Some(server_name) = expected_name {
        ee_cert
            .verify_is_valid_for_subject_name(server_name)
            .map_err(|e| PkiError::NameValidation(e.to_string()))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::validate_server_credential;
    use ed25519_dalek::SigningKey;
    use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::x509::DerCertificate;
    use rcgen::KeyPair;

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
    fn validates_chain_against_custom_ca() {
        let (ca, server_cert, server_key) = generate_ca_and_server_cert();
        let (_secret, public) = ed25519_keypair_from_rcgen(&server_key);

        let chain = CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);
        let signing_identity = SigningIdentity::new(chain.into_credential(), public);
        let roots = vec![CertificateDer::from(ca.der().to_vec())];

        validate_server_credential(
            &signing_identity,
            RootSource::Explicit(&roots),
            Some(&ServerName::try_from("localhost").unwrap()),
        )
        .expect("chain should validate against its own CA");
    }

    #[test]
    fn rejects_wrong_server_name() {
        let (ca, server_cert, server_key) = generate_ca_and_server_cert();
        let (_secret, public) = ed25519_keypair_from_rcgen(&server_key);

        let chain = CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);
        let signing_identity = SigningIdentity::new(chain.into_credential(), public);
        let roots = vec![CertificateDer::from(ca.der().to_vec())];

        assert!(matches!(
            validate_server_credential(
                &signing_identity,
                RootSource::Explicit(&roots),
                Some(&ServerName::try_from("not-localhost").unwrap()),
            ),
            Err(PkiError::NameValidation(_))
        ));
    }

    #[test]
    fn rejects_unknown_ca() {
        let (_ca, server_cert, server_key) = generate_ca_and_server_cert();
        let (other_ca, _, _) = generate_ca_and_server_cert();
        let (_secret, public) = ed25519_keypair_from_rcgen(&server_key);

        let chain = CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);
        let signing_identity = SigningIdentity::new(chain.into_credential(), public);
        let roots = vec![CertificateDer::from(other_ca.der().to_vec())];

        assert!(matches!(
            validate_server_credential(
                &signing_identity,
                RootSource::Explicit(&roots),
                Some(&ServerName::try_from("localhost").unwrap()),
            ),
            Err(PkiError::ChainValidation(_))
        ));
    }
}
