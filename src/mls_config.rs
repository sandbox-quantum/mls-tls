//! The single concrete `MlsConfig` the whole crate is monomorphised over.
//!
//! `mls-rs` produces groups as `Group<impl MlsConfig>`, whose concrete type is unnameable — which is
//! why the original tests reached for a macro instead of a helper returning a group. A public
//! `Connection` must *own* the group, so we pin one concrete config:
//!
//! - crypto provider: [`RustCryptoProvider`] (fixed);
//! - MLS rules: [`TwoPartyMlsRules`] (the deny-by-default two-party allow-list);
//! - identity provider: [`PassThroughIdentityProvider`] — **always accept-all**. mls-rs applies the
//!   group's single identity provider symmetrically to every member, but peer authentication here is
//!   asymmetric/directional (a Basic client can talk to an X.509 server), so it cannot be a strict
//!   provider. Real peer verification is done manually at the handshake (see `web_pki` +
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
use mls_rs_crypto_rustcrypto::RustCryptoProvider;

use crate::mls_two_party_profile_00::TwoPartyMlsRules;
use crate::web_pki::PassThroughIdentityProvider;

/// The one concrete MLS configuration. All `With*` aliases resolve to the same
/// `Config<InMemoryKeyPackageStorage, InMemoryPreSharedKeyStorage, InMemoryGroupStateStorage,
/// PassThroughIdentityProvider, TwoPartyMlsRules, RustCryptoProvider>`.
pub(crate) type MlsTlsConfig = WithMlsRules<
    TwoPartyMlsRules,
    WithCryptoProvider<RustCryptoProvider, WithIdentityProvider<PassThroughIdentityProvider, BaseConfig>>,
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
#[allow(dead_code)] // wired in from Phase 2 onward
pub(crate) fn build_mls_client(
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    cipher_suite: CipherSuite,
    group_state_storage: InMemoryGroupStateStorage,
) -> MlsClient {
    Client::builder()
        .identity_provider(PassThroughIdentityProvider)
        .crypto_provider(RustCryptoProvider::default())
        .signing_identity(signing_identity, signer, cipher_suite)
        .mls_rules(TwoPartyMlsRules::default())
        .group_state_storage(group_state_storage)
        .build()
}
