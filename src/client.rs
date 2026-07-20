//! Client-side configuration: `ClientConfig` + its typestate builder stages.
//!
//! The `verifier` is a credential-verification *policy* — how the client checks the *server's*
//! credential during the handshake. It is consumed by the manual, directional check in
//! `web_pki::validate_server_credential` (see the connection code), **not** installed as the mls-rs
//! identity provider (which is always accept-all; see [`crate::mls_config`]).

use std::sync::Arc;

use mls_rs::{
    CipherSuite, CipherSuiteProvider, CryptoProvider,
    crypto::{SignaturePublicKey, SignatureSecretKey},
    identity::{SigningIdentity, basic::BasicCredential},
    storage_provider::in_memory::InMemoryGroupStateStorage,
};
use rustls_pki_types::TrustAnchor;

use std::ops::{Deref, DerefMut};

use rustls_pki_types::ServerName;

use crate::builder::ConfigBuilder;
use crate::conn::ConnectionCommon;
use crate::create_record_layer;
use crate::crypto::provider::MlsTlsCryptoProvider;
use crate::error::Error;
use crate::mls_config::build_mls_client;
use crate::mls_two_party_profile_00::{Mls2Party, Role, initial_key_agreement_initiator_1};
use crate::resumption::ResumptionState;
use crate::tls_record::Role as Side;

/// The default cipher suite: the custom X-Wing suite (`0x004e`) used for interop with the Python
/// implementation. The CURVE25519 suite remains selectable via the crypto provider for the crate's
/// own tests.
pub(crate) const CIPHER_SUITE: CipherSuite = crate::crypto::XWING_CIPHER_SUITE;

/// How the client verifies the **server's** credential.
///
/// This is a policy, not an mls-rs `IdentityProvider`: peer auth is asymmetric/directional and is
/// applied manually at the handshake (see [`crate::mls_config`] for why the group provider must stay
/// accept-all).
#[derive(Clone)]
pub enum ServerCertVerifier {
    /// Validate the server's X.509 chain against these trust anchors (and, at connect time, the
    /// requested `ServerName`).
    WebPki {
        trust_anchors: Vec<TrustAnchor<'static>>,
    },
    /// Accept any server credential (e.g. a Basic credential). No PKI verification.
    None,
}

/// Immutable, `Arc`-shareable client configuration. Build with [`ClientConfig::builder`].
pub struct ClientConfig {
    pub(crate) verifier: ServerCertVerifier,
    pub(crate) signing_identity: SigningIdentity,
    pub(crate) signer: SignatureSecretKey,
    pub(crate) cipher_suite: CipherSuite,
    /// Shared MLS group-state storage (Arc-backed); reused for resumption.
    pub(crate) group_state_storage: InMemoryGroupStateStorage,
}

/// Builder stage 1 (client): choose how to verify the server.
pub struct WantsVerifier;

/// Builder stage 2 (client): provide this client's own credential.
pub struct WantsClientCredential {
    verifier: ServerCertVerifier,
    session_store: InMemoryGroupStateStorage,
}

impl ClientConfig {
    /// Start building a client configuration.
    pub fn builder() -> ConfigBuilder<ClientConfig, WantsVerifier> {
        ConfigBuilder::new(WantsVerifier)
    }
}

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Verify the server's X.509 certificate against the given trust anchors.
    pub fn with_root_certificates(
        self,
        trust_anchors: Vec<TrustAnchor<'static>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCredential> {
        ConfigBuilder::new(WantsClientCredential {
            verifier: ServerCertVerifier::WebPki { trust_anchors },
            session_store: InMemoryGroupStateStorage::default(),
        })
    }

    /// Verify the server against the Mozilla webpki root set.
    pub fn with_webpki_roots(self) -> ConfigBuilder<ClientConfig, WantsClientCredential> {
        ConfigBuilder::new(WantsClientCredential {
            verifier: ServerCertVerifier::WebPki {
                trust_anchors: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
            session_store: InMemoryGroupStateStorage::default(),
        })
    }

    /// Do not verify the server's certificate. Accepts any credential — use only when peer
    /// authentication is provided by another layer.
    pub fn with_no_certificate_verification(
        self,
    ) -> ConfigBuilder<ClientConfig, WantsClientCredential> {
        ConfigBuilder::new(WantsClientCredential {
            verifier: ServerCertVerifier::None,
            session_store: InMemoryGroupStateStorage::default(),
        })
    }
}

impl ConfigBuilder<ClientConfig, WantsClientCredential> {
    /// Use a shared [`SessionStore`] so this config can resume sessions established by (or share
    /// resumable state with) another config built from the same store.
    pub fn with_session_store(mut self, store: crate::resumption::SessionStore) -> Self {
        self.state.session_store = store.storage;
        self
    }

    /// Use an existing signing identity + private key as this client's credential.
    pub fn with_client_credential(
        self,
        signing_identity: SigningIdentity,
        signer: SignatureSecretKey,
    ) -> Arc<ClientConfig> {
        Arc::new(ClientConfig {
            verifier: self.state.verifier,
            signing_identity,
            signer,
            cipher_suite: CIPHER_SUITE,
            group_state_storage: self.state.session_store,
        })
    }

    /// Generate a fresh Ed25519 key and use a Basic credential with the given identifier.
    pub fn with_generated_basic_credential(self, name: &[u8]) -> Result<Arc<ClientConfig>, Error> {
        let (signer, public) = generate_signature_key()?;
        let signing_identity =
            SigningIdentity::new(BasicCredential::new(name.to_vec()).into_credential(), public);
        Ok(Arc::new(ClientConfig {
            verifier: self.state.verifier,
            signing_identity,
            signer,
            cipher_suite: CIPHER_SUITE,
            group_state_storage: self.state.session_store,
        }))
    }
}

/// Generate a signature keypair for the default cipher suite (ECDSA-P384 for X-Wing).
pub(crate) fn generate_signature_key() -> Result<(SignatureSecretKey, SignaturePublicKey), Error> {
    let csp = MlsTlsCryptoProvider::new()
        .cipher_suite_provider(CIPHER_SUITE)
        .ok_or(Error::Unsupported("cipher suite unavailable"))?;
    csp.signature_key_generate()
        .map_err(|_| Error::Unsupported("signature key generation failed"))
}

/// A single MLS-TLS client connection (the initiator). Deref's to [`ConnectionCommon`] for the
/// sans-I/O byte pipeline.
pub struct ClientConnection {
    inner: ConnectionCommon,
}

impl ClientConnection {
    /// Start a client connection to `server_name`, queuing the ClientHello. Drive the handshake by
    /// pumping `write_tls` / `read_tls` + `process_new_packets` until `is_handshaking()` is false.
    pub fn new(config: Arc<ClientConfig>, server_name: ServerName<'static>) -> Result<Self, Error> {
        let client = build_mls_client(
            config.signing_identity.clone(),
            config.signer.clone(),
            config.cipher_suite,
            config.group_state_storage.clone(),
        );
        let client_hello = initial_key_agreement_initiator_1(&client)?;
        let inner = ConnectionCommon::new_client(
            client,
            config.verifier.clone(),
            server_name,
            client_hello.key_package,
        )?;
        Ok(Self { inner })
    }

    /// Resume a previously-established session over a fresh transport, using a [`ResumptionState`]
    /// exported earlier (via `ConnectionCommon::export_resumption_state`). The group is reloaded from
    /// the config's session store, so `config` must share the store used by the original connection
    /// (reuse the same `Arc<ClientConfig>`). Emits a ResumptionRequest; drive to completion as usual.
    pub fn resume(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        state: ResumptionState,
    ) -> Result<Self, Error> {
        // Reload the persisted group, create + merge a self-update commit (advancing to the new
        // epoch), and build the fresh record layer. The connection then sends a Resumption and awaits
        // the server's ConnectionConfirmation. The server's identity was pinned at the original
        // handshake, so `server_name` is not re-checked here.
        let client = build_mls_client(
            config.signing_identity.clone(),
            config.signer.clone(),
            config.cipher_suite,
            config.group_state_storage.clone(),
        );
        let mut group = client.load_group(&state.group_id)?;
        let mut two_party = Mls2Party::new(Role::Initiator);
        let commit = two_party.create_resumption_and_merge(&mut group)?;
        let record = create_record_layer(&group, Side::Client);
        group.write_to_storage()?;
        let inner =
            ConnectionCommon::new_client_resuming(group, record, two_party, server_name, commit)?;
        Ok(Self { inner })
    }
}

impl Deref for ClientConnection {
    type Target = ConnectionCommon;
    fn deref(&self) -> &ConnectionCommon {
        &self.inner
    }
}

impl DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut ConnectionCommon {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_secure_and_insecure_client_configs() {
        // secure (webpki roots) + generated credential
        let secure = ClientConfig::builder()
            .with_webpki_roots()
            .with_generated_basic_credential(b"alice")
            .unwrap();
        assert!(matches!(secure.verifier, ServerCertVerifier::WebPki { .. }));

        // no verification + generated credential
        let insecure = ClientConfig::builder()
            .with_no_certificate_verification()
            .with_generated_basic_credential(b"bob")
            .unwrap();
        assert!(matches!(insecure.verifier, ServerCertVerifier::None));
    }
}
