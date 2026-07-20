//! Server-side configuration: `ServerConfig` + its typestate builder stages.
//!
//! `client_verifier` is the policy for how the server checks the **client's** credential from the
//! incoming KeyPackage (consumed by `web_pki::validate_client_credential` at the handshake, not the
//! mls-rs identity provider).

use std::io::Read;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use mls_rs::{
    CipherSuite, MlsMessage,
    crypto::{SignaturePublicKey, SignatureSecretKey},
    identity::{SigningIdentity, basic::BasicCredential, x509::CertificateChain},
    storage_provider::in_memory::InMemoryGroupStateStorage,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use rustls_pki_types::TrustAnchor;

use crate::builder::ConfigBuilder;
use crate::client::{CIPHER_SUITE, generate_signature_key};
use crate::conn::ConnectionCommon;
use crate::create_record_layer;
use crate::deframer::{HandshakePayload, MessageDeframer};
use crate::error::Error;
use crate::mls_config::build_mls_client;
use crate::mls_two_party_profile_00::{
    ClientHello, Mls2Party, ResumptionRequest, Role, initial_key_agreement_responder_1,
};
use crate::tls_record::{ContentType, Role as Side};

/// How the server verifies the **client's** credential.
#[derive(Clone)]
pub enum ClientCertVerifier {
    /// Accept a Basic client credential (no client PKI). This is the common web-like case.
    Basic,
    /// Require and validate a client X.509 certificate against these anchors.
    ///
    /// Not yet implemented end-to-end — selecting this surfaces `Error::Unsupported` at handshake
    /// (the X.509 arm of `validate_client_credential` is a stub).
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
    /// Use a shared [`SessionStore`] so resumed connections can reload groups established here.
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

    /// Generate a fresh Ed25519 key and use a Basic credential (convenience, mainly for testing /
    /// examples where the server does not present an X.509 certificate).
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

/// A read-only view of the offered ClientHello, for config selection before `into_connection`.
pub struct ClientHelloInfo<'a> {
    key_package: &'a MlsMessage,
}

impl ClientHelloInfo<'_> {
    /// The cipher suite offered in the client's KeyPackage, if it parses as one.
    pub fn cipher_suite(&self) -> Option<CipherSuite> {
        self.key_package.as_key_package().map(|kp| kp.cipher_suite)
    }
}

/// What the [`Acceptor`] parsed off the wire: a fresh ClientHello or a cross-connection resumption.
enum AcceptedKind {
    Fresh(ClientHello),
    Resume(MlsMessage),
}

/// Server-side pre-config handshake acceptor: read the incoming ClientHello (KeyPackage) — or a
/// cross-connection ResumptionRequest — before choosing a [`ServerConfig`]. Mirrors rustls' `Acceptor`.
pub struct Acceptor {
    deframer: MessageDeframer,
    accepted: Option<AcceptedKind>,
}

impl Acceptor {
    pub fn new() -> Self {
        Self {
            deframer: MessageDeframer::new(),
            accepted: None,
        }
    }

    /// Feed raw TLS bytes from the transport.
    pub fn read_tls(&mut self, rd: &mut dyn Read) -> std::io::Result<usize> {
        let mut buf = [0u8; 8192];
        let n = rd.read(&mut buf)?;
        self.deframer.push(&buf[..n]);
        Ok(n)
    }

    /// Returns `Some(Accepted)` once a full opening message has been buffered.
    pub fn accept(&mut self) -> Result<Option<Accepted>, Error> {
        if self.accepted.is_none()
            && let Some(frame) = self.deframer.pop()? {
                if frame.outer_type != ContentType::Handshake as u8 {
                    return Err(Error::UnexpectedMessage("expected a handshake frame"));
                }
                self.accepted = Some(match HandshakePayload::decode(frame.body())? {
                    HandshakePayload::ClientHello(key_package) => {
                        AcceptedKind::Fresh(ClientHello { key_package })
                    }
                    HandshakePayload::ResumptionRequest(commit) => AcceptedKind::Resume(commit),
                    _ => {
                        return Err(Error::UnexpectedMessage(
                            "expected a ClientHello or ResumptionRequest",
                        ));
                    }
                });
            }
        Ok(self.accepted.take().map(|kind| Accepted { kind }))
    }
}

impl Default for Acceptor {
    fn default() -> Self {
        Self::new()
    }
}

/// A buffered opening message awaiting a config choice.
pub struct Accepted {
    kind: AcceptedKind,
}

impl Accepted {
    /// Whether this is a cross-connection resumption (rather than a fresh handshake).
    pub fn is_resumption(&self) -> bool {
        matches!(self.kind, AcceptedKind::Resume(_))
    }

    /// Inspect the offered ClientHello (KeyPackage) before choosing a config. `None` for a resumption.
    pub fn client_hello(&self) -> Option<ClientHelloInfo<'_>> {
        match &self.kind {
            AcceptedKind::Fresh(ch) => Some(ClientHelloInfo {
                key_package: &ch.key_package,
            }),
            AcceptedKind::Resume(_) => None,
        }
    }

    /// Complete the responder side with the chosen config, producing a `ServerConnection` that has
    /// queued its ServerHello (fresh) or ResumptionResponse (resumption).
    pub fn into_connection(self, config: Arc<ServerConfig>) -> Result<ServerConnection, Error> {
        match self.kind {
            AcceptedKind::Fresh(client_hello) => {
                if let ClientCertVerifier::WebPki { .. } = config.client_verifier {
                    // The X.509 client-auth arm of validate_client_credential is not implemented yet.
                    return Err(Error::Unsupported("client certificate verification"));
                }
                let (server_hello, mut group) = initial_key_agreement_responder_1(
                    client_hello,
                    config.signing_identity.clone(),
                    config.signer.clone(),
                    config.cipher_suite,
                    config.group_state_storage.clone(),
                )?;
                let record =
                    create_record_layer(&group, Side::Server, RustCryptoProvider::default());
                group.write_to_storage()?; // persist for resumption
                let inner =
                    ConnectionCommon::new_server_established(group, record, server_hello.welcome)?;
                Ok(ServerConnection { inner })
            }
            AcceptedKind::Resume(commit) => {
                // Reload the persisted group named by the commit, apply the resumption, and reply.
                let group_id = commit
                    .group_id()
                    .ok_or(Error::Decode("resumption commit missing group id"))?
                    .to_vec();
                let server = build_mls_client(
                    config.signing_identity.clone(),
                    config.signer.clone(),
                    config.cipher_suite,
                    config.group_state_storage.clone(),
                );
                let mut group = server.load_group(&group_id)?;
                let mut two_party = Mls2Party::new(Role::Responder);
                let response = two_party
                    .handle_resumption_request(&mut group, ResumptionRequest { commit })?
                    .ok_or(Error::UnexpectedMessage("resumption produced no response"))?;
                let record =
                    create_record_layer(&group, Side::Server, RustCryptoProvider::default());
                group.write_to_storage()?;
                let inner = ConnectionCommon::new_server_resumed(
                    group,
                    record,
                    two_party,
                    response.commit,
                )?;
                Ok(ServerConnection { inner })
            }
        }
    }
}

/// A single MLS-TLS server connection (the responder). Deref's to [`ConnectionCommon`].
pub struct ServerConnection {
    inner: ConnectionCommon,
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
