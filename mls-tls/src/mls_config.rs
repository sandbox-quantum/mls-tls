//! The single concrete `MlsConfig` the whole crate is monomorphised over.
//!
//! `mls-rs` produces groups as `Group<impl MlsConfig>`, whose concrete type is unnameable — which is
//! why the original tests reached for a macro instead of a helper returning a group. A public
//! `Connection` must *own* the group, so we pin one concrete config:
//!
//! - crypto provider: [`MlsTlsCryptoProvider`] — a single concrete type whose *backend* (RustCrypto
//!   or OpenSSL) is selected at compile time via mutually-exclusive features, so `Group<MlsTlsConfig>`
//!   stays nameable;
//! - MLS rules: [`TwoPartyMlsRules`] (the deny-by-default two-party allow-list);
//! - identity provider: [`PassThroughIdentityProvider`] — **always accept-all**. mls-rs applies the
//!   group's single identity provider symmetrically to every member, but peer authentication here is
//!   asymmetric/directional (a Basic client can talk to an X.509 server), so it cannot be a strict
//!   provider. Real peer verification is done manually at the handshake (see `pki` +
//!   `initial_key_agreement_*`).
//!
//! Because all six `Config` type parameters are fixed, `Group<MlsTlsConfig>` is nameable and ownable.

use mls_rs::{
    CipherSuite, Client,
    client_builder::{BaseConfig, WithCryptoProvider, WithIdentityProvider, WithMlsRules},
    crypto::SignatureSecretKey,
    identity::SigningIdentity,
    storage_provider::in_memory::InMemoryGroupStateStorage,
};

use crate::crypto::provider::MlsTlsCryptoProvider;
use crate::mls_two_party_profile_00::TwoPartyMlsRules;
use crate::pki::PassThroughIdentityProvider;

/// The one concrete MLS configuration. All `With*` aliases resolve to the same
/// `Config<InMemoryKeyPackageStorage, InMemoryPreSharedKeyStorage, InMemoryGroupStateStorage,
/// PassThroughIdentityProvider, TwoPartyMlsRules, MlsTlsCryptoProvider>`.
///
/// The crypto provider is [`MlsTlsCryptoProvider`], which serves the standard suites (1–7) from the
/// compile-time-selected backend (RustCrypto or OpenSSL) and, under `rustcrypto`, adds the X-Wing
/// suite (`0x004e`) used for interop.
pub(crate) type MlsTlsConfig = WithMlsRules<
    TwoPartyMlsRules,
    WithCryptoProvider<
        MlsTlsCryptoProvider,
        WithIdentityProvider<PassThroughIdentityProvider, BaseConfig>,
    >,
>;

/// A nameable MLS group over the fixed config.
pub(crate) type MlsGroup = mls_rs::Group<MlsTlsConfig>;

/// A nameable MLS client over the fixed config.
pub(crate) type MlsClient = Client<MlsTlsConfig>;

/// Build a client with a *nameable* return type (the successor to the old `make_client`).
///
/// `group_state_storage` is passed in so a config can share one store across a connection's lifetime
/// and reload it for resumption (`InMemoryGroupStateStorage` is `Arc`-backed, so clones share state).
/// Injecting an `InMemoryGroupStateStorage` does not change the concrete config type.
pub(crate) fn build_mls_client(
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    cipher_suite: CipherSuite,
    group_state_storage: InMemoryGroupStateStorage,
) -> MlsClient {
    Client::builder()
        .identity_provider(PassThroughIdentityProvider)
        .crypto_provider(MlsTlsCryptoProvider::new())
        .signing_identity(signing_identity, signer, cipher_suite)
        .mls_rules(TwoPartyMlsRules::default())
        .group_state_storage(group_state_storage)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::MLS_256_XWING_AES256GCM_SHA512_P384;
    use crate::crypto::provider::MlsTlsCryptoProvider;
    use crate::mls_two_party_profile_00::{
        initial_key_agreement_initiator_1, initial_key_agreement_initiator_2,
        initial_key_agreement_responder_1,
    };
    use mls_rs::group::ReceivedMessage;
    use mls_rs::identity::basic::BasicCredential;
    use mls_rs::{CipherSuiteProvider, CryptoProvider};

    /// Build a Basic-credential signing identity for the given suite (compiled backend).
    fn basic_identity(id: &[u8], cs: CipherSuite) -> (SigningIdentity, SignatureSecretKey) {
        let csp = MlsTlsCryptoProvider::new()
            .cipher_suite_provider(cs)
            .expect("suite supported");
        let (secret, public) = csp.signature_key_generate().unwrap();
        let identity =
            SigningIdentity::new(BasicCredential::new(id.to_vec()).into_credential(), public);
        (identity, secret)
    }

    /// Drive a full two-member group on cipher suite `cs` using the compiled backend. Asserts an
    /// application message crosses the group and that both sides derive identical MLS-TLS traffic
    /// secrets. This is the backend-parity check: it runs under whichever backend is compiled.
    fn full_group_roundtrip(cs: CipherSuite) {
        let (initiator_id, initiator_secret) = basic_identity(b"initiator", cs);
        let (responder_id, responder_secret) = basic_identity(b"responder", cs);

        let initiator = build_mls_client(
            initiator_id,
            initiator_secret,
            cs,
            InMemoryGroupStateStorage::default(),
        );
        let client_hello = initial_key_agreement_initiator_1(&initiator).unwrap();
        let (server_hello, mut server_group) = initial_key_agreement_responder_1(
            client_hello,
            responder_id,
            responder_secret,
            cs,
            InMemoryGroupStateStorage::default(),
        )
        .unwrap();
        let mut client_group = initial_key_agreement_initiator_2(&initiator, server_hello).unwrap();

        // App message responder → initiator crosses the shared epoch.
        let ct = server_group
            .encrypt_application_message(b"hello full group", Default::default())
            .unwrap();
        match client_group.process_incoming_message(ct).unwrap() {
            ReceivedMessage::ApplicationMessage(app) => assert_eq!(app.data(), b"hello full group"),
            other => panic!("expected application message, got {other:?}"),
        }

        // Both sides derive the same client application traffic secret.
        let crypto = MlsTlsCryptoProvider::new();
        let client_ts = crate::mls_tls_01::derive_client_application_traffic_secret(
            &client_group,
            crypto.clone(),
        )
        .unwrap();
        let server_ts =
            crate::mls_tls_01::derive_client_application_traffic_secret(&server_group, crypto)
                .unwrap();
        assert_eq!(&*client_ts, &*server_ts);
    }

    /// A standard AES-GCM suite (P384_AES256) drives a full group under the compiled backend
    /// (RustCrypto or OpenSSL) — this is the per-backend parity check.
    #[test]
    fn standard_suite_drives_full_group() {
        full_group_roundtrip(CipherSuite::P384_AES256);
    }

    /// The custom X-Wing suite (0x004e) drives a full two-member mls-rs group (RustCrypto only):
    /// KeyPackage → commit/Welcome (HPKE encap) → join (HPKE decap) → application message.
    #[cfg(feature = "rustcrypto")]
    #[test]
    fn xwing_suite_drives_full_group() {
        full_group_roundtrip(MLS_256_XWING_AES256GCM_SHA512_P384);
    }

    /// Under the OpenSSL backend, X-Wing is unavailable: the provider does not offer suite `0x004e`,
    /// and selecting it surfaces a runtime error rather than a compile error.
    #[cfg(feature = "openssl")]
    #[test]
    fn xwing_unsupported_under_openssl() {
        let provider = MlsTlsCryptoProvider::new();
        assert!(
            provider
                .cipher_suite_provider(MLS_256_XWING_AES256GCM_SHA512_P384)
                .is_none()
        );
        assert!(
            !provider
                .supported_cipher_suites()
                .contains(&MLS_256_XWING_AES256GCM_SHA512_P384)
        );

        // Building a config that selects X-Wing fails at runtime (no compiled X-Wing suite).
        let result = crate::client::ClientConfig::builder()
            .with_no_certificate_verification()
            .with_cipher_suite(MLS_256_XWING_AES256GCM_SHA512_P384)
            .with_generated_basic_credential(b"client");
        assert!(matches!(result, Err(crate::error::Error::Unsupported(_))));
    }

    /// Spike: write an mls-rs ClientHello (MlsTlsHandshake envelope + MLSMessage(KeyPackage)) on
    /// 0x004e so the Python parser can attempt to parse+verify it (MLS byte-compat check).
    /// Run with `cargo test --lib spike_write_clienthello -- --ignored`.
    #[cfg(feature = "rustcrypto")]
    #[test]
    #[ignore]
    fn spike_write_clienthello() {
        let cs = MLS_256_XWING_AES256GCM_SHA512_P384;
        let (id, secret) = basic_identity(b"initiator", cs);
        let client = build_mls_client(id, secret, cs, InMemoryGroupStateStorage::default());
        let client_hello = initial_key_agreement_initiator_1(&client).unwrap();
        let mls_message = client_hello.key_package.to_bytes().unwrap();

        // MlsTlsHandshake envelope: u16 version(0x0000) || u16 payload_tag ClientHello(0x0000).
        let mut out = vec![0x00, 0x00, 0x00, 0x00];
        out.extend_from_slice(&mls_message);
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../interop/rust_clienthello.bin"
        );
        std::fs::write(path, &out).unwrap();
        eprintln!("wrote {} bytes to {path}", out.len());
    }
}
