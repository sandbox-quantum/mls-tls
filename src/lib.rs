//! `mls-tls` — a rustls-shaped public API over the 2PMLS + MLS-TLS IETF drafts.
//!
//! An MLS group (via `mls-rs`) is used as the key-agreement engine feeding a TLS 1.3 record layer.
//! See `PUBLIC_API_DESIGN.md` for the full design. The public surface is built up across phases;
//! this is the library skeleton plus the internal building blocks.

pub(crate) mod mls_tls;
pub(crate) mod mls_two_party_profile_00;
pub(crate) mod tls_record;
pub(crate) mod tree_printer;
pub(crate) mod web_pki;

mod builder;
pub mod client;
mod conn;
mod deframer;
mod error;
mod mls_config;
pub mod resumption;
pub mod server;
mod stream;

// --- public API surface ---
pub use builder::ConfigBuilder;
pub use client::{ClientConfig, ClientConnection, ServerCertVerifier};
pub use conn::{Connection, ConnectionCommon, IoState, Reader, Writer};
pub use error::Error;
pub use resumption::{ResumptionState, SessionStore};
pub use server::{
    Accepted, Acceptor, ClientCertVerifier, ClientHelloInfo, ServerConfig, ServerConnection,
};
pub use stream::{Stream, StreamOwned};

// Foreign types a caller must name, re-exported so they don't add the deps directly.
pub use mls_rs::CipherSuite;
pub use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
pub use mls_rs::identity::SigningIdentity;
pub use mls_rs::identity::x509::CertificateChain;
pub use rustls_pki_types::{CertificateDer, ServerName, TrustAnchor};
pub use tls_record::Role as Side;

// --- internal imports for the crate-root handshake helpers ---
use mls_rs::{
    Client, CryptoProvider, Group, client_builder::MlsConfig, error::MlsError,
    storage_provider::in_memory::{
        InMemoryGroupStateStorage, InMemoryKeyPackageStorage, InMemoryPreSharedKeyStorage,
    },
};

use crate::{
    mls_two_party_profile_00::TwoPartyMlsRules, tls_record::HkdfExpanderSha256,
    web_pki::PassThroughIdentityProvider,
};

/// Build an MLS client with the accept-all identity provider and the two-party rules.
///
/// Retained (generic) for the tests; the public API uses the nameable
/// [`mls_config::build_mls_client`] instead.
#[allow(dead_code)]
pub(crate) fn make_client<C: CryptoProvider + Clone>(
    crypto_provider: C,
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    cipher_suite: CipherSuite,
) -> Result<Client<impl MlsConfig>, MlsError> {
    let client = Client::builder()
        .identity_provider(PassThroughIdentityProvider)
        .crypto_provider(crypto_provider)
        .signing_identity(signing_identity, signer, cipher_suite)
        .mls_rules(TwoPartyMlsRules::default())
        .group_state_storage(InMemoryGroupStateStorage::default())
        .key_package_repo(InMemoryKeyPackageStorage::default())
        .psk_store(InMemoryPreSharedKeyStorage::default())
        .build();
    Ok(client)
}

/// Derive both traffic secrets from `mls_group` and build the TLS 1.3 record layer for `role`.
pub(crate) fn create_record_layer<C: CryptoProvider + Clone>(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_pki::validate_server_credential;
    use mls_rs_crypto_rustcrypto::RustCryptoProvider;
    use mls_rs::crypto::{SignaturePublicKey, SignatureSecretKey};
    use mls_rs::identity::basic::BasicCredential;
    use mls_rs::identity::x509::{CertificateChain, DerCertificate};
    use mls_rs::group::ReceivedMessage;
    use mls_rs::CipherSuiteProvider;
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
            let (server_hello, mut $server_group) =
                mls_two_party_profile_00::initial_key_agreement_responder_1(
                    client_hello,
                    responder_signing_identity,
                    responder_secret,
                    cs,
                    mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage::default(),
                )
                .unwrap();
            let _ = &trust_anchors;
            let mut $client_group = mls_two_party_profile_00::initial_key_agreement_initiator_2(
                &initiator,
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

        let old_c2s_inflight = app(&mut client_layer, b"c2s in-flight (old)");
        let old_c2s_after = app(&mut client_layer, b"c2s after switch (old)");
        let old_s2c_inflight = app(&mut server_layer, b"s2c in-flight (old)");
        let old_s2c_after = app(&mut server_layer, b"s2c after switch (old)");

        let mut epoch_key_updates = 0;

        let (connection_update, client_rekey) = client_mls
            .create_connection_update(&mut client_group, &crypto)
            .unwrap()
            .unwrap();
        apply_opt(&mut client_layer, client_rekey, tls_record::Role::Client);

        assert_eq!(
            server_layer.decrypt(&old_c2s_inflight).unwrap().fragment,
            b"c2s in-flight (old)"
        );

        let (server_rekey, epoch_key_update) = server_mls
            .handle_connection_update(&mut server_group, &crypto, connection_update)
            .unwrap();
        if epoch_key_update.is_some() {
            epoch_key_updates += 1;
        }
        let epoch_key_update = epoch_key_update.unwrap();
        apply_opt(&mut server_layer, server_rekey, tls_record::Role::Server);

        assert!(server_layer.decrypt(&old_c2s_after).is_err());

        assert_eq!(
            client_layer.decrypt(&old_s2c_inflight).unwrap().fragment,
            b"s2c in-flight (old)"
        );

        let (client_rekey, no_return) = client_mls
            .handle_epoch_key_update(&mut client_group, &crypto, epoch_key_update)
            .unwrap();
        assert!(no_return.is_none());
        apply_opt(&mut client_layer, client_rekey, tls_record::Role::Client);

        assert!(client_layer.decrypt(&old_s2c_after).is_err());

        send_expect(&mut client_layer, &mut server_layer, b"c2s post");
        send_expect(&mut server_layer, &mut client_layer, b"s2c post");

        assert_eq!(epoch_key_updates, 1, "initiator-initiated rekey = 1 EpochKeyUpdate");
    }

    // Responder-initiated rekey (3-message flow: ConnectionUpdate -> EpochKeyUpdate -> EpochKeyUpdate).
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

        let (connection_update, server_rekey) = server_mls
            .create_connection_update(&mut server_group, &crypto)
            .unwrap()
            .unwrap();
        assert!(server_rekey.is_none(), "responder rotates nothing when initiating");
        apply_opt(&mut server_layer, server_rekey, tls_record::Role::Server);

        let (client_rekey, epoch_key_update_1) = client_mls
            .handle_connection_update(&mut client_group, &crypto, connection_update)
            .unwrap();
        if epoch_key_update_1.is_some() {
            epoch_key_updates += 1;
        }
        let epoch_key_update_1 = epoch_key_update_1.unwrap();
        apply_opt(&mut client_layer, client_rekey, tls_record::Role::Client);

        assert_eq!(
            server_layer.decrypt(&old_c2s_inflight).unwrap().fragment,
            b"c2s in-flight (old)"
        );

        let (server_rekey, epoch_key_update_2) = server_mls
            .handle_epoch_key_update(&mut server_group, &crypto, epoch_key_update_1)
            .unwrap();
        if epoch_key_update_2.is_some() {
            epoch_key_updates += 1;
        }
        let epoch_key_update_2 = epoch_key_update_2.unwrap();
        apply_opt(&mut server_layer, server_rekey, tls_record::Role::Server);

        assert!(server_layer.decrypt(&old_c2s_after).is_err());

        assert_eq!(
            client_layer.decrypt(&old_s2c_inflight).unwrap().fragment,
            b"s2c in-flight (old)"
        );

        let (client_rekey, no_return) = client_mls
            .handle_epoch_key_update(&mut client_group, &crypto, epoch_key_update_2)
            .unwrap();
        assert!(no_return.is_none());
        apply_opt(&mut client_layer, client_rekey, tls_record::Role::Client);

        assert!(client_layer.decrypt(&old_s2c_after).is_err());

        send_expect(&mut client_layer, &mut server_layer, b"c2s post");
        send_expect(&mut server_layer, &mut client_layer, b"s2c post");

        assert_eq!(epoch_key_updates, 2, "responder-initiated rekey = 2 EpochKeyUpdates");
    }

    #[test]
    fn test_two_party_handshake_x509_responder() {
        let (ca, server_cert, server_key) = generate_ca_and_server_cert();
        let trust_anchors = custom_trust_anchors(&ca);

        let (responder_secret, responder_public) = ed25519_keypair_from_rcgen(&server_key);
        let chain = CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);
        let responder_signing_identity =
            SigningIdentity::new(chain.into_credential(), responder_public);

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

        let (server_hello, mut server_group) =
            mls_two_party_profile_00::initial_key_agreement_responder_1(
                client_hello,
                responder_signing_identity,
                responder_secret,
                CipherSuite::CURVE25519_AES128,
                mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage::default(),
            )
            .unwrap();

        let mut client_group = mls_two_party_profile_00::initial_key_agreement_initiator_2(
            &initiator,
            server_hello,
        )
        .unwrap();

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

    // Flush all buffered outgoing TLS bytes from a connection into `out`.
    fn pump_out(conn: &mut ConnectionCommon, out: &mut Vec<u8>) {
        while conn.wants_write() {
            let before = out.len();
            conn.write_tls(out).unwrap();
            if out.len() == before {
                break;
            }
        }
    }

    // Full handshake + application-data round trip through the public sans-I/O API (Phase 2 exit).
    #[test]
    fn test_loopback_handshake_and_appdata() {
        use std::io::{Cursor, Read, Write};

        let (ca, server_cert, server_key) = generate_ca_and_server_cert();
        let trust_anchors = custom_trust_anchors(&ca);
        let (server_secret, server_public) = ed25519_keypair_from_rcgen(&server_key);
        let chain = CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, server_secret, server_public);
        let client_config = ClientConfig::builder()
            .with_root_certificates(trust_anchors)
            .with_generated_basic_credential(b"client")
            .unwrap();

        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut client = ClientConnection::new(client_config, server_name).unwrap();
        assert!(client.is_handshaking());

        // client -> server: ClientHello
        let mut wire = Vec::new();
        pump_out(&mut client, &mut wire);

        let mut acceptor = Acceptor::new();
        acceptor.read_tls(&mut Cursor::new(&wire)).unwrap();
        let accepted = acceptor.accept().unwrap().expect("ClientHello buffered");
        let mut server = accepted.into_connection(server_config).unwrap();
        assert!(!server.is_handshaking());

        // server -> client: ServerHello
        let mut wire = Vec::new();
        pump_out(&mut server, &mut wire);
        client.read_tls(&mut Cursor::new(&wire)).unwrap();
        client.process_new_packets().unwrap();
        assert!(!client.is_handshaking(), "client handshake should complete");

        // application data: client -> server
        client.writer().write_all(b"hello from client").unwrap();
        let mut wire = Vec::new();
        pump_out(&mut client, &mut wire);
        server.read_tls(&mut Cursor::new(&wire)).unwrap();
        server.process_new_packets().unwrap();
        let mut buf = [0u8; 64];
        let n = server.reader().read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello from client");

        // application data: server -> client
        server.writer().write_all(b"hi from server").unwrap();
        let mut wire = Vec::new();
        pump_out(&mut server, &mut wire);
        client.read_tls(&mut Cursor::new(&wire)).unwrap();
        client.process_new_packets().unwrap();
        let mut buf = [0u8; 64];
        let n = client.reader().read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi from server");
    }

    // Establish a connected client+server pair through the public API.
    fn establish_pair() -> (ClientConnection, ServerConnection) {
        use std::io::Cursor;
        let (ca, server_cert, server_key) = generate_ca_and_server_cert();
        let trust_anchors = custom_trust_anchors(&ca);
        let (server_secret, server_public) = ed25519_keypair_from_rcgen(&server_key);
        let chain = CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, server_secret, server_public);
        let client_config = ClientConfig::builder()
            .with_root_certificates(trust_anchors)
            .with_generated_basic_credential(b"client")
            .unwrap();
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();
        let mut client = ClientConnection::new(client_config, server_name).unwrap();

        let mut wire = Vec::new();
        pump_out(&mut client, &mut wire);
        let mut acceptor = Acceptor::new();
        acceptor.read_tls(&mut Cursor::new(&wire)).unwrap();
        let accepted = acceptor.accept().unwrap().unwrap();
        let mut server = accepted.into_connection(server_config).unwrap();

        let mut wire = Vec::new();
        pump_out(&mut server, &mut wire);
        client.read_tls(&mut Cursor::new(&wire)).unwrap();
        client.process_new_packets().unwrap();
        assert!(!client.is_handshaking());
        (client, server)
    }

    // Relay pending bytes both directions until the connection is quiescent (settles control flows).
    fn drive(client: &mut ClientConnection, server: &mut ServerConnection) {
        use std::io::Cursor;
        loop {
            let mut progressed = false;
            let mut wire = Vec::new();
            pump_out(client, &mut wire);
            if !wire.is_empty() {
                server.read_tls(&mut Cursor::new(&wire)).unwrap();
                server.process_new_packets().unwrap();
                progressed = true;
            }
            let mut wire = Vec::new();
            pump_out(server, &mut wire);
            if !wire.is_empty() {
                client.read_tls(&mut Cursor::new(&wire)).unwrap();
                client.process_new_packets().unwrap();
                progressed = true;
            }
            if !progressed {
                break;
            }
        }
    }

    // Send one application message and assert it round-trips.
    fn send_app(from: &mut ConnectionCommon, to: &mut ConnectionCommon, msg: &[u8]) {
        use std::io::{Cursor, Read, Write};
        from.writer().write_all(msg).unwrap();
        let mut wire = Vec::new();
        pump_out(from, &mut wire);
        to.read_tls(&mut Cursor::new(&wire)).unwrap();
        to.process_new_packets().unwrap();
        let mut buf = vec![0u8; msg.len() + 16];
        let n = to.reader().read(&mut buf).unwrap();
        assert_eq!(&buf[..n], msg);
    }

    #[test]
    fn test_public_initiator_rekey() {
        let (mut client, mut server) = establish_pair();
        send_app(&mut client, &mut server, b"pre c2s");
        send_app(&mut server, &mut client, b"pre s2c");

        client.refresh_traffic_keys().unwrap();
        drive(&mut client, &mut server);

        send_app(&mut client, &mut server, b"post c2s");
        send_app(&mut server, &mut client, b"post s2c");
    }

    #[test]
    fn test_public_responder_rekey() {
        let (mut client, mut server) = establish_pair();
        send_app(&mut client, &mut server, b"pre c2s");
        send_app(&mut server, &mut client, b"pre s2c");

        server.refresh_traffic_keys().unwrap();
        drive(&mut client, &mut server);

        send_app(&mut client, &mut server, b"post c2s");
        send_app(&mut server, &mut client, b"post s2c");
    }

    #[test]
    fn test_in_session_resumption() {
        let (mut client, mut server) = establish_pair();
        send_app(&mut client, &mut server, b"pre c2s");
        send_app(&mut server, &mut client, b"pre s2c");

        client.initiate_resumption().unwrap();
        drive(&mut client, &mut server);

        send_app(&mut client, &mut server, b"post-resume c2s");
        send_app(&mut server, &mut client, b"post-resume s2c");
    }

    #[test]
    fn test_cross_connection_resumption() {
        use std::io::Cursor;

        // Configs are reused (same Arc → shared session store) across both connections.
        let (ca, server_cert, server_key) = generate_ca_and_server_cert();
        let trust_anchors = custom_trust_anchors(&ca);
        let (server_secret, server_public) = ed25519_keypair_from_rcgen(&server_key);
        let chain = CertificateChain::from(vec![DerCertificate::new(server_cert.der().to_vec())]);
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, server_secret, server_public);
        let client_config = ClientConfig::builder()
            .with_root_certificates(trust_anchors)
            .with_generated_basic_credential(b"client")
            .unwrap();
        let server_name = rustls_pki_types::ServerName::try_from("localhost").unwrap();

        // --- original connection ---
        let mut client = ClientConnection::new(client_config.clone(), server_name.clone()).unwrap();
        let mut wire = Vec::new();
        pump_out(&mut client, &mut wire);
        let mut acceptor = Acceptor::new();
        acceptor.read_tls(&mut Cursor::new(&wire)).unwrap();
        let accepted = acceptor.accept().unwrap().unwrap();
        let mut server = accepted.into_connection(server_config.clone()).unwrap();
        let mut wire = Vec::new();
        pump_out(&mut server, &mut wire);
        client.read_tls(&mut Cursor::new(&wire)).unwrap();
        client.process_new_packets().unwrap();
        send_app(&mut client, &mut server, b"original session");

        // Snapshot and tear down.
        let resumption_state = client.export_resumption_state().unwrap();
        drop(client);
        drop(server);

        // --- resumed connection over a fresh transport ---
        let mut client2 =
            ClientConnection::resume(client_config.clone(), server_name.clone(), resumption_state)
                .unwrap();
        assert!(client2.is_handshaking());
        let mut wire = Vec::new();
        pump_out(&mut client2, &mut wire);
        let mut acceptor2 = Acceptor::new();
        acceptor2.read_tls(&mut Cursor::new(&wire)).unwrap();
        let accepted2 = acceptor2.accept().unwrap().unwrap();
        assert!(accepted2.is_resumption());
        let mut server2 = accepted2.into_connection(server_config.clone()).unwrap();
        let mut wire = Vec::new();
        pump_out(&mut server2, &mut wire);
        client2.read_tls(&mut Cursor::new(&wire)).unwrap();
        client2.process_new_packets().unwrap();
        assert!(!client2.is_handshaking(), "resume should complete");

        send_app(&mut client2, &mut server2, b"resumed c2s");
        send_app(&mut server2, &mut client2, b"resumed s2c");
    }
}
