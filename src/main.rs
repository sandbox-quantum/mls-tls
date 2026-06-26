use std::{error::Error, fs, path::Path};

use mls_rs::{
    CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Group, IdentityProvider,
    client_builder::MlsConfig,
    crypto::{SignaturePublicKey, SignatureSecretKey},
    error::MlsError,
    group::{Node, ReceivedMessage},
    identity::{
        SigningIdentity,
        basic::BasicCredential,
        x509::{CertificateChain, DerCertificate},
    },
    mls_rules::{CommitOptions, DefaultMlsRules},
    storage_provider::in_memory::{
        InMemoryGroupStateStorage, InMemoryKeyPackageStorage, InMemoryPreSharedKeyStorage,
    },
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use rustls_pki_types::CertificateDer;

use crate::{tls_record::HkdfExpanderSha256, web_pki::PassThroughIdentityProvider};

mod mls_tls;
mod mls_two_party_profile_00;
mod tls_record;
mod tree_printer;
mod web_pki;

struct MlsTlsClient<MConf: MlsConfig, MlsIdentityProvider: IdentityProvider> {
    mls_client: Client<MConf>,
    mls_credential_validator: MlsIdentityProvider,
}

struct MlsTlsServer<MConf: MlsConfig, MlsIdentityProvider: IdentityProvider> {
    mls_client: Client<MConf>,
    mls_credential_validator: MlsIdentityProvider,
}

fn print_tree(group: &Group<impl MlsConfig>) {
    println!(
        "Group: id={:?} epoch={} cipher_suite={:?}",
        group.group_id(),
        group.current_epoch(),
        group.cipher_suite()
    );
    println!("My index: {}", group.current_member_index());
    println!();

    let tree = group.export_tree();
    for (i, node) in tree.nodes().iter().enumerate() {
        match node {
            Some(Node::Leaf(leaf)) => {
                let cred = &leaf.signing_identity.credential;
                let cred_type = match cred {
                    mls_rs::identity::Credential::Basic(b) => {
                        format!("Basic({:?})", String::from_utf8_lossy(&b.identifier))
                    }
                    mls_rs::identity::Credential::X509(_) => "X509".to_string(),
                    mls_rs::identity::Credential::Custom(c) => {
                        format!("Custom({})", c.credential_type.raw_value())
                    }
                    _ => format!("Unknown()"),
                };
                println!(
                    "[{i}] Leaf  | cred={cred_type} pk={:02x?}",
                    &leaf.signing_identity.signature_key.as_ref()[..8]
                );
            }
            Some(Node::Parent(parent)) => {
                println!(
                    "[{i}] Parent | hpke_pk={:02x?}",
                    &parent.public_key.as_ref()[..8.min(parent.public_key.as_ref().len())]
                );
            }
            None => {
                println!("[{i}] (blank)");
            }
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Load test CA + server certificate from fixtures (cargo run --example generate_fixtures)
    let fixtures = Path::new("fixtures");
    let ca_cert_der = fs::read(fixtures.join("ca_cert.der"))?;
    let server_cert_der = fs::read(fixtures.join("server_cert.der"))?;
    let server_secret_key = fs::read(fixtures.join("server_secret_key.bin"))?;
    let server_public_key = fs::read(fixtures.join("server_public_key.bin"))?;

    let ca_der = CertificateDer::from(ca_cert_der.as_slice());
    let trust_anchors = vec![webpki::anchor_from_trusted_cert(&ca_der)?.to_owned()];

    // # Key agreement
    let crypto_provider = RustCryptoProvider::default();
    let cipher_suite_provider = crypto_provider
        .cipher_suite_provider(CipherSuite::CURVE25519_AES128)
        .unwrap();
    let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();
    let signing_identity = SigningIdentity::new(
        BasicCredential::new(b"initiator".to_vec()).into_credential(),
        public,
    );

    let initiator = make_client(
        RustCryptoProvider::default(),
        signing_identity,
        secret,
        CipherSuite::CURVE25519_AES128,
    )?;
    let client_hello = mls_two_party_profile_00::initial_key_agreement_initiator_1(&initiator)?;

    let chain = CertificateChain::from(vec![DerCertificate::new(server_cert_der)]);
    let responder_signing_identity = SigningIdentity::new(
        chain.into_credential(),
        SignaturePublicKey::new(server_public_key),
    );

    let (server_hello, _server_mls_client, mut server_group) =
        mls_two_party_profile_00::initial_key_agreement_responder_1(
            client_hello,
            responder_signing_identity,
            SignatureSecretKey::new(server_secret_key),
            CipherSuite::CURVE25519_AES128,
        )?;

    let mut client_mls_group = mls_two_party_profile_00::initial_key_agreement_initiator_2(
        &initiator,
        &trust_anchors,
        server_hello,
    )?;

    // client side
    let client_application_traffic_secret = mls_tls::derive_client_application_traffic_secret(
        &client_mls_group,
        RustCryptoProvider::new(),
    )
    .unwrap();
    let server_application_traffic_secret = mls_tls::derive_server_application_traffic_secret(
        &client_mls_group,
        RustCryptoProvider::new(),
    )
    .unwrap();

    let client_exp = HkdfExpanderSha256::from_prk(client_application_traffic_secret.as_bytes());
    let server_exp = HkdfExpanderSha256::from_prk(server_application_traffic_secret.as_bytes());

    let mut client_record_layer = tls_record::RecordLayer::from_traffic_secrets(
        &client_exp,
        &server_exp,
        tls_record::Role::Client,
    );

    // server side
    let client_application_traffic_secret = mls_tls::derive_client_application_traffic_secret(
        &client_mls_group,
        RustCryptoProvider::new(),
    )
    .unwrap();
    let server_application_traffic_secret = mls_tls::derive_server_application_traffic_secret(
        &client_mls_group,
        RustCryptoProvider::new(),
    )
    .unwrap();

    let client_exp = HkdfExpanderSha256::from_prk(client_application_traffic_secret.as_bytes());
    let server_exp = HkdfExpanderSha256::from_prk(server_application_traffic_secret.as_bytes());

    let mut server_record_layer = tls_record::RecordLayer::from_traffic_secrets(
        &client_exp,
        &server_exp,
        tls_record::Role::Server,
    );

    let records = client_record_layer
        .encrypt(
            tls_record::ContentType::ApplicationData,
            b"hello from client",
        )
        .unwrap();

    let plaintext = server_record_layer.decrypt(&records[0]).unwrap();
    println!("{}", String::from_utf8_lossy(&plaintext.fragment));

    Ok(())
}

fn make_client<C: CryptoProvider + Clone>(
    crypto_provider: C,
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    cipher_suite: CipherSuite,
) -> Result<Client<impl MlsConfig>, MlsError> {
    let client = Client::builder()
        .identity_provider(PassThroughIdentityProvider)
        .crypto_provider(crypto_provider)
        .signing_identity(signing_identity, signer, cipher_suite)
        .mls_rules(DefaultMlsRules::default().with_commit_options(CommitOptions::default()))
        .group_state_storage(InMemoryGroupStateStorage::default())
        .key_package_repo(InMemoryKeyPackageStorage::default())
        .psk_store(InMemoryPreSharedKeyStorage::default())
        // .extension_types([])                                           TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES / tree extension not mentioned in the spec?
        // .crypto_provider(crypto_provider)                              TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .custom_proposal_types(types)                                  TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .extension_types(type_)                                        TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .group_state_storage(group_state_storage)                      TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .identity_provider(identity_provider)                          TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .key_package_lifetime(lifetime)                                TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .key_package_repo(key_package_repo)                            TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .mls_rules(mls_rules)                                          TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .protocol_version(version)                                     TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .protocol_versions(versions)                                   TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .psk(psk_id, psk)                                              TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .psk_store(psk_store)                                          TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .signer(signer)                                                TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        // .signing_identity(signing_identity, signer, cipher_suite)      TODO: NEED TO REVIEW THESE FOR IMPLEMENTOR NOTES
        .build();
    Ok(client)
}

// IMPLEMENTOR NOTE: do you need to send the entire tree in the server hello? Check ratchet tree extension
// apparently this might be needed for the key update.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_pki::validate_server_credential;
    use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
    use mls_rs::identity::x509::{CertificateChain, DerCertificate};
    use rcgen::KeyPair;
    use rustls_pki_types::{CertificateDer, TrustAnchor};

    fn generate_ca_and_server_cert() -> (
        rcgen::CertifiedIssuer<'static, KeyPair>,
        rcgen::Certificate,
        KeyPair,
    ) {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ca_params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
        let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

        let server_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let server_cert = server_params.signed_by(&server_key, &ca).unwrap();

        (ca, server_cert, server_key)
    }

    fn ed25519_keypair_from_rcgen(kp: &KeyPair) -> (SignatureSecretKey, SignaturePublicKey) {
        let pkcs8_der = kp.serialize_der();
        let seed: [u8; 32] = pkcs8_der[16..48].try_into().unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        (
            SignatureSecretKey::new(signing_key.to_keypair_bytes().to_vec()),
            SignaturePublicKey::new(signing_key.verifying_key().to_bytes().to_vec()),
        )
    }

    fn custom_trust_anchors(ca: &rcgen::CertifiedIssuer<'_, KeyPair>) -> Vec<TrustAnchor<'static>> {
        let ca_der = CertificateDer::from(ca.der().to_vec());
        vec![
            webpki::anchor_from_trusted_cert(&ca_der)
                .unwrap()
                .to_owned(),
        ]
    }

    #[test]
    fn test_two_party_handshake_x509_responder() {
        let (ca, server_cert, server_key) = generate_ca_and_server_cert();
        let trust_anchors = custom_trust_anchors(&ca);

        // Responder: X509 credential + PassThroughIdentityProvider
        let (responder_secret, responder_public) = ed25519_keypair_from_rcgen(&server_key);
        let chain = CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);
        let responder_signing_identity =
            SigningIdentity::new(chain.into_credential(), responder_public);

        // Initiator: BasicCredential + PassThroughIdentityProvider
        let crypto_provider = RustCryptoProvider::default();
        let cipher_suite_provider = crypto_provider
            .cipher_suite_provider(CipherSuite::CURVE25519_AES128)
            .unwrap();
        let (initiator_secret, initiator_public) =
            cipher_suite_provider.signature_key_generate().unwrap();
        let initiator_signing_identity = SigningIdentity::new(
            BasicCredential::new(b"initiator".to_vec()).into_credential(),
            initiator_public,
        );

        let initiator = make_client(
            RustCryptoProvider::default(),
            initiator_signing_identity,
            initiator_secret,
            CipherSuite::CURVE25519_AES128,
        )
        .unwrap();

        let client_hello =
            mls_two_party_profile_00::initial_key_agreement_initiator_1(&initiator).unwrap();

        let (server_hello, _server_client, mut server_group) =
            mls_two_party_profile_00::initial_key_agreement_responder_1(
                client_hello,
                responder_signing_identity,
                responder_secret,
                CipherSuite::CURVE25519_AES128,
            )
            .unwrap();

        let mut client_group = mls_two_party_profile_00::initial_key_agreement_initiator_2(
            &initiator,
            &trust_anchors,
            server_hello,
        )
        .unwrap();

        // Inline validation: initiator verifies responder's X509 cert
        let responder_member = client_group.member_at_index(0).unwrap();
        validate_server_credential(responder_member.signing_identity(), &trust_anchors, None)
            .expect("responder cert should validate against custom CA");

        let msg = server_group
            .encrypt_application_message(b"hello from server", vec![])
            .unwrap();
        let received = client_group.process_incoming_message(msg).unwrap();

        match received {
            ReceivedMessage::ApplicationMessage(app_msg) => {
                assert_eq!(app_msg.data(), b"hello from server");
            }
            _ => panic!("expected application message"),
        }
    }
}
