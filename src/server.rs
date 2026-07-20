//! Server-side configuration: `ServerConfig` + its typestate builder stages, and `ServerConnection`.
//!
//! `client_verifier` is the policy for how the server checks the **client's** credential from the
//! incoming KeyPackage (consumed by `web_pki::validate_client_credential` at the handshake, not the
//! mls-rs identity provider).
//!
//! Unlike rustls, there is no `Acceptor`: the server speaks first (it sends its signing public key
//! before the ClientHello), so a [`ServerConnection`] is created directly from a config and the
//! ClientHello is consumed inside `process_new_packets`.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use mls_rs::{
    CipherSuite,
    crypto::{SignaturePublicKey, SignatureSecretKey},
    identity::{SigningIdentity, basic::BasicCredential, x509::CertificateChain},
    storage_provider::in_memory::InMemoryGroupStateStorage,
};
use rustls_pki_types::TrustAnchor;

use crate::builder::ConfigBuilder;
use crate::client::{CIPHER_SUITE, generate_signature_key};
use crate::conn::{ConnectionCommon, ServerCtx};
use crate::error::Error;

/// How the server verifies the **client's** credential.
#[derive(Clone)]
pub enum ClientCertVerifier {
    /// Accept a Basic client credential (no client PKI). This is the common web-like case.
    Basic,
    /// Require and validate a client X.509 certificate against these anchors.
    ///
    /// Not yet implemented end-to-end — selecting this surfaces `Error::Unsupported` at handshake.
    WebPki {
        trust_anchors: Vec<TrustAnchor<'static>>,
    },
}

/// Immutable, `Arc`-shareable server configuration. Build with [`ServerConfig::builder`].
pub struct ServerConfig {
    pub(crate) client_verifier: ClientCertVerifier,
    pub(crate) signing_identity: SigningIdentity,
    pub(crate) signer: SignatureSecretKey,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) group_state_storage: InMemoryGroupStateStorage,
}

/// Builder stage 1 (server): choose how to verify the client.
pub struct WantsClientVerifier;

/// Builder stage 2 (server): provide the server's own credential.
pub struct WantsServerCredential {
    client_verifier: ClientCertVerifier,
    session_store: InMemoryGroupStateStorage,
}

impl ServerConfig {
    /// Start building a server configuration.
    pub fn builder() -> ConfigBuilder<ServerConfig, WantsClientVerifier> {
        ConfigBuilder::new(WantsClientVerifier)
    }
}

impl ConfigBuilder<ServerConfig, WantsClientVerifier> {
    /// Do not require client authentication (accept a Basic client credential).
    pub fn with_no_client_auth(self) -> ConfigBuilder<ServerConfig, WantsServerCredential> {
        ConfigBuilder::new(WantsServerCredential {
            client_verifier: ClientCertVerifier::Basic,
            session_store: InMemoryGroupStateStorage::default(),
        })
    }

    /// Require a client X.509 certificate validated against the given anchors.
    pub fn with_client_cert_verifier(
        self,
        trust_anchors: Vec<TrustAnchor<'static>>,
    ) -> ConfigBuilder<ServerConfig, WantsServerCredential> {
        ConfigBuilder::new(WantsServerCredential {
            client_verifier: ClientCertVerifier::WebPki { trust_anchors },
            session_store: InMemoryGroupStateStorage::default(),
        })
    }
}

impl ConfigBuilder<ServerConfig, WantsServerCredential> {
    /// Use a shared [`SessionStore`](crate::resumption::SessionStore) so resumed connections can
    /// reload groups established here.
    pub fn with_session_store(mut self, store: crate::resumption::SessionStore) -> Self {
        self.state.session_store = store.storage;
        self
    }

    /// Use an X.509 certificate chain + matching private key as the server's credential.
    pub fn with_single_cert(
        self,
        chain: CertificateChain,
        signer: SignatureSecretKey,
        public: SignaturePublicKey,
    ) -> Arc<ServerConfig> {
        let signing_identity = SigningIdentity::new(chain.into_credential(), public);
        Arc::new(ServerConfig {
            client_verifier: self.state.client_verifier,
            signing_identity,
            signer,
            cipher_suite: CIPHER_SUITE,
            group_state_storage: self.state.session_store,
        })
    }

    /// Use an existing signing identity + private key as the server's credential.
    pub fn with_server_credential(
        self,
        signing_identity: SigningIdentity,
        signer: SignatureSecretKey,
    ) -> Arc<ServerConfig> {
        Arc::new(ServerConfig {
            client_verifier: self.state.client_verifier,
            signing_identity,
            signer,
            cipher_suite: CIPHER_SUITE,
            group_state_storage: self.state.session_store,
        })
    }

    /// Generate a fresh key and use a Basic credential (convenience for testing / examples where the
    /// server does not present an X.509 certificate).
    pub fn with_generated_basic_credential(
        self,
        name: &[u8],
    ) -> Result<Arc<ServerConfig>, Error> {
        let (signer, public) = generate_signature_key()?;
        let signing_identity =
            SigningIdentity::new(BasicCredential::new(name.to_vec()).into_credential(), public);
        Ok(Arc::new(ServerConfig {
            client_verifier: self.state.client_verifier,
            signing_identity,
            signer,
            cipher_suite: CIPHER_SUITE,
            group_state_storage: self.state.session_store,
        }))
    }
}

/// A single MLS-TLS server connection (the responder). Deref's to [`ConnectionCommon`].
pub struct ServerConnection {
    inner: ConnectionCommon,
}

impl ServerConnection {
    /// Start a server connection. It queues the server's public key immediately; drive the handshake
    /// by pumping `write_tls` / `read_tls` + `process_new_packets` until `is_handshaking()` is false.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, Error> {
        let server_ctx = ServerCtx {
            signing_identity: config.signing_identity.clone(),
            signer: config.signer.clone(),
            cipher_suite: config.cipher_suite,
            storage: config.group_state_storage.clone(),
            client_verifier: config.client_verifier.clone(),
        };
        let inner = ConnectionCommon::new_server(server_ctx)?;
        Ok(Self { inner })
    }
}

impl Deref for ServerConnection {
    type Target = ConnectionCommon;
    fn deref(&self) -> &ConnectionCommon {
        &self.inner
    }
}

impl DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut ConnectionCommon {
        &mut self.inner
    }
}
