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

/// Print an error together with its full `source()` chain, so the origin is easy to find.
/// Set `RUST_BACKTRACE=1` to also populate the `Backtrace` captured inside each typed error.
fn report(err: &dyn Error) {
    eprintln!("error: {err}");
    let mut source = err.source();
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}

fn main() {
    if let Err(err) = run() {
        report(err.as_ref());
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
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

    let mut client_group = mls_two_party_profile_00::initial_key_agreement_initiator_2(
        &initiator,
        &trust_anchors,
        server_hello,
    )?;

    tree_printer::print_tree_detailed(&client_group);

    // client side
    let mut client_record_layer = create_record_layer(
        &client_group,
        tls_record::Role::Client,
        RustCryptoProvider::new(),
    );

    let mut server_record_layer = create_record_layer(
        &server_group,
        tls_record::Role::Server,
        RustCryptoProvider::new(),
    );

    let records = client_record_layer
        .encrypt(
            tls_record::ContentType::ApplicationData,
            b"hello from client",
        )
        .unwrap();

    let plaintext = server_record_layer.decrypt(&records[0]).unwrap();
    println!(
        "decrypted: {}",
        String::from_utf8_lossy(&plaintext.fragment)
    );

    let records = server_record_layer
        .encrypt(
            tls_record::ContentType::ApplicationData,
            b"does it work from the server?",
        )
        .unwrap();

    let plaintext = client_record_layer.decrypt(&records[0]).unwrap();
    println!(
        "decrypted: {}",
        String::from_utf8_lossy(&plaintext.fragment)
    );

    // Directional, staggered rekey (initiator-initiated). The record layers are rotated one
    // direction at a time via `apply_rekey` instead of being rebuilt wholesale, so an in-flight
    // old-epoch record is never dropped. Ordering follows emit-before-switch: each control message
    // is handed to the peer under the OLD key first, then the sender installs its new key.
    let crypto = RustCryptoProvider::new();

    let mut client_mls_2_party =
        mls_two_party_profile_00::Mls2Party::new(mls_two_party_profile_00::Role::Initiator);
    let mut server_mls_2_party =
        mls_two_party_profile_00::Mls2Party::new(mls_two_party_profile_00::Role::Responder);

    // Initiator: create + merge the commit, emit the ConnectionUpdate, then install its send key.
    let (connection_update, client_rekey) = client_mls_2_party
        .create_connection_update(&mut client_group, &crypto)
        .unwrap()
        .unwrap();
    if let Some(rekey) = client_rekey {
        client_record_layer.apply_rekey(rekey, tls_record::Role::Client);
    }

    // Responder: merge + install both directions, emit the EpochKeyUpdate (under the old key first).
    let (server_rekey, epoch_key_update) = server_mls_2_party
        .handle_connection_update(&mut server_group, &crypto, connection_update)
        .unwrap();
    let epoch_key_update = epoch_key_update.expect("responder confirms with an EpochKeyUpdate");
    if let Some(rekey) = server_rekey {
        server_record_layer.apply_rekey(rekey, tls_record::Role::Server);
    }

    // Initiator: the confirming EpochKeyUpdate lets it finally install its receive key.
    let (client_rekey, _no_return) = client_mls_2_party
        .handle_epoch_key_update(&mut client_group, &crypto, epoch_key_update)
        .unwrap();
    if let Some(rekey) = client_rekey {
        client_record_layer.apply_rekey(rekey, tls_record::Role::Client);
    }

    tree_printer::print_tree_detailed(&client_group);

    let records = server_record_layer
        .encrypt(
            tls_record::ContentType::ApplicationData,
            b"hello from server after key rolling",
        )
        .unwrap();

    let plaintext = client_record_layer.decrypt(&records[0]).unwrap();

    println!(
        "decrypted: {}",
        String::from_utf8_lossy(&plaintext.fragment)
    );

    // Resumption

    let resumption_request = client_mls_2_party
        .create_resumption_request(&mut client_group)
        .unwrap();

    let resumption_response = server_mls_2_party
        .handle_resumption_request(&mut server_group, resumption_request)
        .unwrap()
        .unwrap();

    let mut server_record_layer = create_record_layer(
        &mut server_group,
        tls_record::Role::Server,
        RustCryptoProvider::new(),
    );

    client_mls_2_party
        .handle_resumption_response(&mut client_group, resumption_response)
        .unwrap();

    let mut client_record_layer = create_record_layer(
        &mut client_group,
        tls_record::Role::Client,
        RustCryptoProvider::new(),
    );

    let records = client_record_layer
        .encrypt(
            tls_record::ContentType::ApplicationData,
            b"Sent by client after receiving resumption response",
        )
        .unwrap();

    let plaintext = server_record_layer.decrypt(&records[0]).unwrap();

    println!("decrypted: {}", String::from_utf8_lossy(&plaintext.fragment));

    Ok(())
}

fn create_record_layer<C: CryptoProvider + Clone>(
    mls_group: &Group<impl MlsConfig>,
    role: tls_record::Role,
    crypto_provider: C,
) -> tls_record::RecordLayer {
    let client_application_traffic_secret =
        mls_tls::derive_client_application_traffic_secret(mls_group, crypto_provider.clone())
            .unwrap();
    let server_application_traffic_secret =
        mls_tls::derive_server_application_traffic_secret(mls_group, crypto_provider.clone())
            .unwrap();

    let client_exp = HkdfExpanderSha256::from_prk(client_application_traffic_secret.as_bytes());
    let server_exp = HkdfExpanderSha256::from_prk(server_application_traffic_secret.as_bytes());

    tls_record::RecordLayer::from_traffic_secrets(&client_exp, &server_exp, role)
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
        .mls_rules(mls_two_party_profile_00::TwoPartyMlsRules::default()) // TODO: add a note there to say what this enforces
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

    // ----------------------------------------------------------------------
    // Directional / staggered rekey tests
    //
    // These drive a full in-process duplex exchange and interleave application data with a rekey in
    // both directions. The concrete `Group`/`Client` types produced by the handshake are
    // unnameable (`impl MlsConfig`), so the connection setup is a macro that binds the pieces in the
    // caller's scope rather than a helper returning them.
    // ----------------------------------------------------------------------

    macro_rules! establish_connection {
        (
            $crypto:ident,
            $client_group:ident,
            $server_group:ident,
            $client_mls:ident,
            $server_mls:ident,
            $client_layer:ident,
            $server_layer:ident
        ) => {
            let (ca, server_cert, server_key) = generate_ca_and_server_cert();
            let trust_anchors = custom_trust_anchors(&ca);

            let (responder_secret, responder_public) = ed25519_keypair_from_rcgen(&server_key);
            let chain =
                CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);
            let responder_signing_identity =
                SigningIdentity::new(chain.into_credential(), responder_public);

            let cs = CipherSuite::CURVE25519_AES128;
            let (initiator_secret, initiator_public) = RustCryptoProvider::default()
                .cipher_suite_provider(cs)
                .unwrap()
                .signature_key_generate()
                .unwrap();
            let initiator_signing_identity = SigningIdentity::new(
                BasicCredential::new(b"initiator".to_vec()).into_credential(),
                initiator_public,
            );

            let initiator = make_client(
                RustCryptoProvider::default(),
                initiator_signing_identity,
                initiator_secret,
                cs,
            )
            .unwrap();

            let client_hello =
                mls_two_party_profile_00::initial_key_agreement_initiator_1(&initiator).unwrap();
            let (server_hello, _server_client, mut $server_group) =
                mls_two_party_profile_00::initial_key_agreement_responder_1(
                    client_hello,
                    responder_signing_identity,
                    responder_secret,
                    cs,
                )
                .unwrap();
            let mut $client_group = mls_two_party_profile_00::initial_key_agreement_initiator_2(
                &initiator,
                &trust_anchors,
                server_hello,
            )
            .unwrap();

            let $crypto = RustCryptoProvider::new();
            let mut $client_layer = create_record_layer(
                &$client_group,
                tls_record::Role::Client,
                RustCryptoProvider::new(),
            );
            let mut $server_layer = create_record_layer(
                &$server_group,
                tls_record::Role::Server,
                RustCryptoProvider::new(),
            );
            let mut $client_mls =
                mls_two_party_profile_00::Mls2Party::new(mls_two_party_profile_00::Role::Initiator);
            let mut $server_mls =
                mls_two_party_profile_00::Mls2Party::new(mls_two_party_profile_00::Role::Responder);
        };
    }

    // Encrypt one application record under the layer's current send key.
    fn app(layer: &mut tls_record::RecordLayer, msg: &[u8]) -> Vec<u8> {
        layer
            .encrypt(tls_record::ContentType::ApplicationData, msg)
            .unwrap()
            .remove(0)
    }

    // Encrypt at `sender`, decrypt at `receiver`, assert the plaintext round-trips.
    fn send_expect(
        sender: &mut tls_record::RecordLayer,
        receiver: &mut tls_record::RecordLayer,
        msg: &[u8],
    ) {
        let record = app(sender, msg);
        let plaintext = receiver.decrypt(&record).unwrap();
        assert_eq!(plaintext.fragment, msg);
    }

    fn apply_opt(
        layer: &mut tls_record::RecordLayer,
        rekey: Option<tls_record::DirectionalRekey>,
        role: tls_record::Role,
    ) {
        if let Some(rekey) = rekey {
            layer.apply_rekey(rekey, role);
        }
    }

    // Initiator-initiated rekey (2-message flow: ConnectionUpdate -> EpochKeyUpdate).
    // Asserts: exactly 1 EpochKeyUpdate; in-flight old-key records still decrypt in both
    // directions; old keys are dropped once each direction rotates; fresh traffic works after.
    #[test]
    fn test_initiator_initiated_rekey_is_staggered() {
        establish_connection!(
            crypto,
            client_group,
            server_group,
            client_mls,
            server_mls,
            client_layer,
            server_layer
        );

        // Pre-rekey traffic in both directions.
        send_expect(&mut client_layer, &mut server_layer, b"c2s pre");
        send_expect(&mut server_layer, &mut client_layer, b"s2c pre");

        // Capture old-key records BEFORE any rotation: one to deliver while the peer still holds the
        // old receive key (must decrypt) and one to deliver after it rotates (must fail).
        let old_c2s_inflight = app(&mut client_layer, b"c2s in-flight (old)");
        let old_c2s_after = app(&mut client_layer, b"c2s after switch (old)");
        let old_s2c_inflight = app(&mut server_layer, b"s2c in-flight (old)");
        let old_s2c_after = app(&mut server_layer, b"s2c after switch (old)");

        let mut epoch_key_updates = 0;

        // Initiator sends a ConnectionUpdate and installs its send key (emit-before-switch).
        let (connection_update, client_rekey) = client_mls
            .create_connection_update(&mut client_group, &crypto)
            .unwrap()
            .unwrap();
        apply_opt(&mut client_layer, client_rekey, tls_record::Role::Client);

        // The initiator's old client->server record is still in flight; the responder has NOT yet
        // rotated its receive key, so it must still decrypt.
        assert_eq!(
            server_layer.decrypt(&old_c2s_inflight).unwrap().fragment,
            b"c2s in-flight (old)"
        );

        // Responder merges, installs both directions, and confirms with a single EpochKeyUpdate.
        let (server_rekey, epoch_key_update) = server_mls
            .handle_connection_update(&mut server_group, &crypto, connection_update)
            .unwrap();
        if epoch_key_update.is_some() {
            epoch_key_updates += 1;
        }
        let epoch_key_update = epoch_key_update.unwrap();
        apply_opt(&mut server_layer, server_rekey, tls_record::Role::Server);

        // Responder has now rotated its client->server receive key: the old-key record is dropped.
        assert!(server_layer.decrypt(&old_c2s_after).is_err());

        // The responder switched its send key, but the initiator has not yet rotated its receive
        // key, so an old server->client record still in flight must decrypt.
        assert_eq!(
            client_layer.decrypt(&old_s2c_inflight).unwrap().fragment,
            b"s2c in-flight (old)"
        );

        // Confirming EpochKeyUpdate lets the initiator install its receive key.
        let (client_rekey, no_return) = client_mls
            .handle_epoch_key_update(&mut client_group, &crypto, epoch_key_update)
            .unwrap();
        assert!(no_return.is_none());
        apply_opt(&mut client_layer, client_rekey, tls_record::Role::Client);

        // Initiator has now rotated its server->client receive key: the old-key record is dropped.
        assert!(client_layer.decrypt(&old_s2c_after).is_err());

        // Fresh traffic under the new epoch works in both directions.
        send_expect(&mut client_layer, &mut server_layer, b"c2s post");
        send_expect(&mut server_layer, &mut client_layer, b"s2c post");

        assert_eq!(epoch_key_updates, 1, "initiator-initiated rekey = 1 EpochKeyUpdate");
    }

    // Responder-initiated rekey (3-message flow: ConnectionUpdate -> EpochKeyUpdate ->
    // EpochKeyUpdate). Asserts: exactly 2 EpochKeyUpdates; in-flight old-key records still decrypt
    // in both directions; old keys dropped after rotation; fresh traffic works after.
    #[test]
    fn test_responder_initiated_rekey_is_staggered() {
        establish_connection!(
            crypto,
            client_group,
            server_group,
            client_mls,
            server_mls,
            client_layer,
            server_layer
        );

        send_expect(&mut client_layer, &mut server_layer, b"c2s pre");
        send_expect(&mut server_layer, &mut client_layer, b"s2c pre");

        let old_c2s_inflight = app(&mut client_layer, b"c2s in-flight (old)");
        let old_c2s_after = app(&mut client_layer, b"c2s after switch (old)");
        let old_s2c_inflight = app(&mut server_layer, b"s2c in-flight (old)");
        let old_s2c_after = app(&mut server_layer, b"s2c after switch (old)");

        let mut epoch_key_updates = 0;

        // Responder sends a ConnectionUpdate but holds its commit pending and rotates nothing.
        let (connection_update, server_rekey) = server_mls
            .create_connection_update(&mut server_group, &crypto)
            .unwrap()
            .unwrap();
        assert!(server_rekey.is_none(), "responder rotates nothing when initiating");
        apply_opt(&mut server_layer, server_rekey, tls_record::Role::Server);

        // Initiator merges, installs its send key, and replies with the first EpochKeyUpdate.
        let (client_rekey, epoch_key_update_1) = client_mls
            .handle_connection_update(&mut client_group, &crypto, connection_update)
            .unwrap();
        if epoch_key_update_1.is_some() {
            epoch_key_updates += 1;
        }
        let epoch_key_update_1 = epoch_key_update_1.unwrap();
        apply_opt(&mut client_layer, client_rekey, tls_record::Role::Client);

        // Initiator's old client->server record still in flight; responder has not rotated its
        // receive key yet, so it must decrypt.
        assert_eq!(
            server_layer.decrypt(&old_c2s_inflight).unwrap().fragment,
            b"c2s in-flight (old)"
        );

        // Responder merges, installs both directions, and sends the second ("return")
        // EpochKeyUpdate.
        let (server_rekey, epoch_key_update_2) = server_mls
            .handle_epoch_key_update(&mut server_group, &crypto, epoch_key_update_1)
            .unwrap();
        if epoch_key_update_2.is_some() {
            epoch_key_updates += 1;
        }
        let epoch_key_update_2 = epoch_key_update_2.unwrap();
        apply_opt(&mut server_layer, server_rekey, tls_record::Role::Server);

        // Responder rotated its client->server receive key: old-key record is dropped.
        assert!(server_layer.decrypt(&old_c2s_after).is_err());

        // Responder switched its send key; the initiator has not rotated its receive key yet, so the
        // old server->client record still in flight must decrypt.
        assert_eq!(
            client_layer.decrypt(&old_s2c_inflight).unwrap().fragment,
            b"s2c in-flight (old)"
        );

        // Return EpochKeyUpdate lets the initiator finally install its receive key.
        let (client_rekey, no_return) = client_mls
            .handle_epoch_key_update(&mut client_group, &crypto, epoch_key_update_2)
            .unwrap();
        assert!(no_return.is_none());
        apply_opt(&mut client_layer, client_rekey, tls_record::Role::Client);

        // Initiator rotated its server->client receive key: old-key record is dropped.
        assert!(client_layer.decrypt(&old_s2c_after).is_err());

        send_expect(&mut client_layer, &mut server_layer, b"c2s post");
        send_expect(&mut server_layer, &mut client_layer, b"s2c post");

        assert_eq!(epoch_key_updates, 2, "responder-initiated rekey = 2 EpochKeyUpdates");
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
