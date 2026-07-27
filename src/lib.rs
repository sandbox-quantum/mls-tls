//! `mls-tls` — a public API over the 2PMLS + MLS-TLS IETF drafts.
//!
//! An MLS group (via `mls-rs`) is used as the key-agreement engine feeding a TLS 1.3 record layer.

// Exactly one crypto backend must be selected at compile time; the two are mutually exclusive.
#[cfg(all(feature = "rustcrypto", feature = "openssl"))]
compile_error!(
    "features `rustcrypto` and `openssl` are mutually exclusive — enable exactly one \
     (for OpenSSL use `--no-default-features --features openssl`)"
);
#[cfg(not(any(feature = "rustcrypto", feature = "openssl")))]
compile_error!("enable exactly one crypto backend feature: `rustcrypto` (default) or `openssl`");

pub(crate) mod crypto;
pub(crate) mod mls_tls_01;
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
pub use crypto::MLS_256_XWING_AES256GCM_SHA512_P384;
pub use error::Error;
pub use resumption::{ResumptionState, SessionStore};
pub use server::{ClientCertVerifier, ServerConfig, ServerConnection};
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
    Client, CryptoProvider, Group,
    client_builder::MlsConfig,
    error::MlsError,
    storage_provider::in_memory::{
        InMemoryGroupStateStorage, InMemoryKeyPackageStorage, InMemoryPreSharedKeyStorage,
    },
};

use crate::{
    crypto::provider::MlsTlsCryptoProvider, mls_two_party_profile_00::TwoPartyMlsRules,
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

/// Derive both application-traffic secrets from `mls_group` and build the record layer for `role`.
///
/// Suite parameters (hash + AEAD) follow the group's cipher suite; the `<c|s> ap traffic` context is
/// the 64-zero-byte handshake-hash placeholder at epoch 1 and empty afterwards.
pub(crate) fn create_record_layer(
    mls_group: &Group<impl MlsConfig>,
    role: tls_record::Role,
) -> Result<tls_record::RecordLayer, Error> {
    let crypto = MlsTlsCryptoProvider::new();
    let client_ts =
        mls_tls_01::derive_client_application_traffic_secret(mls_group, crypto.clone())?;
    let server_ts = mls_tls_01::derive_server_application_traffic_secret(mls_group, crypto)?;

    let params = tls_record::SuiteParams::for_cipher_suite(mls_group.cipher_suite().into())?;
    // Only ever called to build a *fresh* codec — at the initial handshake and at resumption (both
    // over a new transport) — so it always uses the epoch-1 `<c|s> ap traffic` context (the 64-zero
    // handshake-hash placeholder). Per-epoch rekeys on a live transport go through
    // `RecordLayer::apply_rekey`, which uses the empty context.
    Ok(tls_record::RecordLayer::from_traffic_secrets(
        params,
        client_ts.as_bytes(),
        server_ts.as_bytes(),
        role,
        true,
    ))
}

#[cfg(test)]
mod tests {
    use crate::client::{ClientConfig, ClientConnection};
    use crate::conn::ConnectionCommon;
    use crate::server::{ServerConfig, ServerConnection};
    use rustls_pki_types::ServerName;
    use std::io::{Read, Write};

    /// Move all of `from`'s buffered TLS bytes into `to`, then process them. Returns bytes moved.
    fn pump(from: &mut ConnectionCommon, to: &mut ConnectionCommon) -> usize {
        let mut buf = Vec::new();
        while from.wants_write() {
            if from.write_tls(&mut buf).unwrap() == 0 {
                break;
            }
        }
        if buf.is_empty() {
            return 0;
        }
        let mut cur = &buf[..];
        while !cur.is_empty() {
            if to.read_tls(&mut cur).unwrap() == 0 {
                break;
            }
        }
        to.process_new_packets().unwrap();
        buf.len()
    }

    /// Pump both directions until the handshake settles.
    fn drive(client: &mut ClientConnection, server: &mut ServerConnection) {
        for _ in 0..16 {
            let a = pump(server, client);
            let b = pump(client, server);
            if a == 0 && b == 0 {
                break;
            }
        }
    }

    fn established_pair() -> (ClientConnection, ServerConnection) {
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_generated_basic_credential(b"server")
            .unwrap();
        let client_config = ClientConfig::builder()
            .with_no_certificate_verification()
            .with_generated_basic_credential(b"client")
            .unwrap();
        let mut server = ServerConnection::new(server_config).unwrap();
        let mut client =
            ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap())
                .unwrap();
        drive(&mut client, &mut server);
        assert!(!client.is_handshaking(), "client still handshaking");
        assert!(!server.is_handshaking(), "server still handshaking");
        (client, server)
    }

    fn send(from: &mut ConnectionCommon, to: &mut ConnectionCommon, msg: &[u8]) -> Vec<u8> {
        from.writer().write_all(msg).unwrap();
        pump(from, to);
        let mut buf = vec![0u8; msg.len() + 16];
        let n = to.reader().read(&mut buf).unwrap();
        buf.truncate(n);
        buf
    }

    #[test]
    fn loopback_handshake_and_appdata() {
        let (mut client, mut server) = established_pair();
        assert_eq!(
            send(&mut client, &mut server, b"hello server"),
            b"hello server"
        );
        assert_eq!(
            send(&mut server, &mut client, b"hello client"),
            b"hello client"
        );
    }

    #[test]
    fn loopback_initiator_rekey() {
        let (mut client, mut server) = established_pair();
        assert_eq!(send(&mut client, &mut server, b"pre"), b"pre");

        // Client initiates a rekey; deliver the ConnectionUpdate + EpochKeyUpdate both ways.
        client.refresh_traffic_keys().unwrap();
        for _ in 0..4 {
            pump(&mut client, &mut server);
            pump(&mut server, &mut client);
        }
        // Traffic still flows across the new epoch, both directions.
        assert_eq!(send(&mut client, &mut server, b"post c2s"), b"post c2s");
        assert_eq!(send(&mut server, &mut client, b"post s2c"), b"post s2c");
    }

    #[test]
    fn loopback_resumption() {
        use crate::client::ClientConfig;
        use crate::server::ServerConfig;

        // Reuse the same configs across both connections so their (Arc-backed) session storage is
        // shared and the persisted group can be reloaded on resume.
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_generated_basic_credential(b"server")
            .unwrap();
        let client_config = ClientConfig::builder()
            .with_no_certificate_verification()
            .with_generated_basic_credential(b"client")
            .unwrap();
        let name = ServerName::try_from("localhost").unwrap();

        // Connection 1: fresh handshake + app data at epoch 1.
        let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
        let mut client1 = ClientConnection::new(client_config.clone(), name.clone()).unwrap();
        for _ in 0..8 {
            let a = pump(&mut server1, &mut client1);
            let b = pump(&mut client1, &mut server1);
            if a == 0 && b == 0 {
                break;
            }
        }
        assert!(!client1.is_handshaking());
        assert_eq!(send(&mut client1, &mut server1, b"epoch1"), b"epoch1");
        let resumption = client1.export_resumption_state().unwrap();

        // Connection 2: resume over a fresh transport, then app data on the resumed epoch.
        let mut server2 = ServerConnection::new(server_config.clone()).unwrap();
        let mut client2 =
            ClientConnection::resume(client_config.clone(), name, resumption).unwrap();
        for _ in 0..8 {
            let a = pump(&mut server2, &mut client2);
            let b = pump(&mut client2, &mut server2);
            if a == 0 && b == 0 {
                break;
            }
        }
        assert!(
            !client2.is_handshaking(),
            "resumed client still handshaking"
        );
        assert!(
            !server2.is_handshaking(),
            "resumed server still handshaking"
        );
        assert_eq!(send(&mut client2, &mut server2, b"epoch2"), b"epoch2");
        assert_eq!(
            send(&mut server2, &mut client2, b"epoch2 back"),
            b"epoch2 back"
        );
    }

    #[test]
    fn resumption_rejects_changed_server_identity() {
        use crate::client::{ClientConfig, generate_signature_key};
        use crate::server::{ServerConfig, ServerConnection};
        use mls_rs::identity::{SigningIdentity, basic::BasicCredential};
        use std::sync::Arc;

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_generated_basic_credential(b"server")
            .unwrap();
        let client_config = ClientConfig::builder()
            .with_no_certificate_verification()
            .with_generated_basic_credential(b"client")
            .unwrap();
        let name = ServerName::try_from("localhost").unwrap();

        let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
        let mut client1 = ClientConnection::new(client_config.clone(), name.clone()).unwrap();
        drive(&mut client1, &mut server1);
        assert!(!client1.is_handshaking());
        let resumption = client1.export_resumption_state().unwrap();

        let (bad_signer, bad_public) = generate_signature_key(server_config.cipher_suite).unwrap();
        let bad_identity = SigningIdentity::new(
            BasicCredential::new(b"other-server".to_vec()).into_credential(),
            bad_public,
        );
        let bad_server_config = Arc::new(crate::server::ServerConfig {
            client_verifier: server_config.client_verifier.clone(),
            signing_identity: bad_identity,
            signer: bad_signer,
            cipher_suite: server_config.cipher_suite,
            group_state_storage: server_config.group_state_storage.clone(),
        });

        let mut server2 = ServerConnection::new(bad_server_config).unwrap();
        let mut client2 = ClientConnection::resume(client_config, name, resumption).unwrap();

        let mut buf = Vec::new();
        while server2.wants_write() {
            if server2.write_tls(&mut buf).unwrap() == 0 {
                break;
            }
        }
        let mut incoming = &buf[..];
        while !incoming.is_empty() {
            if client2.read_tls(&mut incoming).unwrap() == 0 {
                break;
            }
        }

        assert!(matches!(
            client2.process_new_packets().unwrap_err(),
            crate::error::Error::PeerAuth("server key does not match presented key")
        ));
        assert!(!client2.wants_write());
    }
}
