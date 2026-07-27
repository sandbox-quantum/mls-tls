//! Client-side configuration: `ClientConfig` + its typestate builder stages.
//!
//! The `verifier` is a credential-verification *policy* — how the client checks the *server's*
//! credential during the handshake. It is consumed by the manual, directional check in
//! `pki::validate_server_credential` (see the connection code), **not** installed as the mls-rs
//! identity provider (which is always accept-all; see [`crate::mls_config`]).

use std::sync::Arc;

use mls_rs::{
    CipherSuite, CipherSuiteProvider, CryptoProvider,
    crypto::{SignaturePublicKey, SignatureSecretKey},
    identity::{SigningIdentity, basic::BasicCredential},
    storage_provider::in_memory::InMemoryGroupStateStorage,
};
use rustls_pki_types::CertificateDer;

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

/// The default cipher suite, per compiled backend. Under `rustcrypto` it is the custom X-Wing suite
/// (`0x004e`); under `openssl` (which has no X-Wing) it is `P384_AES256`.
/// Any suite the backend supports can be selected via `with_cipher_suite`.
#[cfg(feature = "rustcrypto")]
pub(crate) const CIPHER_SUITE: CipherSuite = crate::crypto::MLS_256_XWING_AES256GCM_SHA512_P384;
#[cfg(feature = "openssl")]
pub(crate) const CIPHER_SUITE: CipherSuite = CipherSuite::P384_AES256;

/// How the client verifies the **server's** credential.
///
/// This is a policy, not an mls-rs `IdentityProvider`: peer auth is asymmetric/directional and is
/// applied manually at the handshake (see [`crate::mls_config`] for why the group provider must stay
/// accept-all).
#[derive(Clone)]
pub enum ServerCertVerifier {
    /// Validate the server's X.509 chain against these root certificates (and, at connect time,
    /// the requested `ServerName`).
    Roots(Vec<CertificateDer<'static>>),
    /// Validate against the compiled backend's built-in root set.
    ///
    /// **The trust base differs by backend**: the bundled Mozilla set under `rustcrypto`, OpenSSL's
    /// configured trust store under `openssl`. Use [`Self::Roots`] when that distinction matters.
    DefaultRoots,
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

/// Builder stage 2 (client): provide this client's own credential (and, optionally, override the
/// cipher suite / session store).
pub struct WantsClientCredential {
    verifier: ServerCertVerifier,
    session_store: InMemoryGroupStateStorage,
    cipher_suite: CipherSuite,
}

impl ClientConfig {
    /// Start building a client configuration.
    pub fn builder() -> ConfigBuilder<ClientConfig, WantsVerifier> {
        ConfigBuilder::new(WantsVerifier)
    }
}

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Verify the server's X.509 certificate against the given root certificates (DER).
    pub fn with_root_certificates(
        self,
        roots: Vec<CertificateDer<'static>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCredential> {
        ConfigBuilder::new(WantsClientCredential::new(ServerCertVerifier::Roots(roots)))
    }

    /// Verify the server against the bundled Mozilla root set.
    ///
    /// `rustcrypto` only: the set ships as webpki `TrustAnchor`s, which OpenSSL's `X509_STORE`
    /// cannot consume. Under `openssl`/`fips` use [`Self::with_system_roots`] or supply DER roots
    /// via [`Self::with_root_certificates`].
    #[cfg(feature = "rustcrypto")]
    pub fn with_webpki_roots(self) -> ConfigBuilder<ClientConfig, WantsClientCredential> {
        ConfigBuilder::new(WantsClientCredential::new(ServerCertVerifier::DefaultRoots))
    }

    /// Verify the server against OpenSSL's configured default trust store (`SSL_CERT_DIR` /
    /// `SSL_CERT_FILE` / the compiled-in `OPENSSLDIR`).
    #[cfg(feature = "openssl")]
    pub fn with_system_roots(self) -> ConfigBuilder<ClientConfig, WantsClientCredential> {
        ConfigBuilder::new(WantsClientCredential::new(ServerCertVerifier::DefaultRoots))
    }

    /// Do not verify the server's certificate. Accepts any credential — use only when peer
    /// authentication is provided by another layer.
    pub fn with_no_certificate_verification(
        self,
    ) -> ConfigBuilder<ClientConfig, WantsClientCredential> {
        ConfigBuilder::new(WantsClientCredential::new(ServerCertVerifier::None))
    }
}

impl WantsClientCredential {
    /// Stage-2 defaults: the compiled backend's default cipher suite and a fresh session store.
    /// Override with `with_cipher_suite` / `with_session_store`.
    fn new(verifier: ServerCertVerifier) -> Self {
        Self {
            verifier,
            session_store: InMemoryGroupStateStorage::default(),
            cipher_suite: CIPHER_SUITE,
        }
    }
}

impl ConfigBuilder<ClientConfig, WantsClientCredential> {
    /// Use a shared [`SessionStore`] so this config can resume sessions established by (or share
    /// resumable state with) another config built from the same store.
    pub fn with_session_store(mut self, store: crate::resumption::SessionStore) -> Self {
        self.state.session_store = store.storage;
        self
    }

    /// Select the MLS cipher suite (default
    /// [`MLS_256_XWING_AES256GCM_SHA512_P384`](crate::MLS_256_XWING_AES256GCM_SHA512_P384) under the
    /// `rustcrypto` backend, `P384_AES256` under `openssl`). The suite must be supported by the
    /// compiled backend; selecting an unsupported one (e.g. X-Wing under `openssl`) fails at runtime.
    pub fn with_cipher_suite(mut self, cipher_suite: CipherSuite) -> Self {
        self.state.cipher_suite = cipher_suite;
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
            cipher_suite: self.state.cipher_suite,
            group_state_storage: self.state.session_store,
        })
    }

    /// Generate a fresh signing key (of the scheme matching the selected suite) and use a Basic
    /// credential with the given identifier.
    pub fn with_generated_basic_credential(self, name: &[u8]) -> Result<Arc<ClientConfig>, Error> {
        let (signer, public) = generate_signature_key(self.state.cipher_suite)?;
        let signing_identity = SigningIdentity::new(
            BasicCredential::new(name.to_vec()).into_credential(),
            public,
        );
        Ok(Arc::new(ClientConfig {
            verifier: self.state.verifier,
            signing_identity,
            signer,
            cipher_suite: self.state.cipher_suite,
            group_state_storage: self.state.session_store,
        }))
    }
}

/// Generate a signature keypair for `cipher_suite` using the compiled crypto backend. Returns
/// `Error::Unsupported` if the backend does not support the suite (e.g. X-Wing under `openssl`).
pub(crate) fn generate_signature_key(
    cipher_suite: CipherSuite,
) -> Result<(SignatureSecretKey, SignaturePublicKey), Error> {
    // The earliest point at which a caller touches cryptography — before any connection exists.
    // Without this the failure would surface as an opaque "unsupported algorithm" fetch error from
    // deep inside OpenSSL, because a FIPS build has *no* providers loaded until `enable()` runs.
    #[cfg(feature = "fips")]
    crate::fips::assert_enabled()?;

    let csp = MlsTlsCryptoProvider::new()
        .cipher_suite_provider(cipher_suite)
        .ok_or(Error::Unsupported("cipher suite unavailable"))?;
    csp.signature_key_generate()
        .map_err(|_| Error::Unsupported("signature key generation failed"))
}

/// A single MLS-TLS client connection (the initiator). Deref's to [`ConnectionCommon`].
pub struct ClientConnection {
    inner: ConnectionCommon,
}

impl ClientConnection {
    /// Start a client connection to `server_name`, queuing the ClientHello. Drive the handshake by
    /// pumping `write_tls` / `read_tls` + `process_new_packets` until `is_handshaking()` is false.
    pub fn new(config: Arc<ClientConfig>, server_name: ServerName<'static>) -> Result<Self, Error> {
        #[cfg(feature = "fips")]
        crate::fips::assert_enabled()?;

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
    /// exported earlier (via `ConnectionCommon::export_resumption_state`). The group is reloaded
    /// from the config's session store, so `config` must share the store used by the original
    /// connection (reuse the same `Arc<ClientConfig>`). Emits a Resumption request; drive to
    /// completion as usual.
    pub fn resume(
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
        state: ResumptionState,
    ) -> Result<Self, Error> {
        #[cfg(feature = "fips")]
        crate::fips::assert_enabled()?;

        // Reload the persisted group, create + merge a self-update commit (advancing to the new
        // epoch), and build the fresh record layer. The connection then sends a Resumption and awaits
        // the server's ConnectionConfirmation. The fresh server pre-handshake key is checked against
        // the responder identity persisted in the group before the Resumption is sent.
        let client = build_mls_client(
            config.signing_identity.clone(),
            config.signer.clone(),
            config.cipher_suite,
            config.group_state_storage.clone(),
        );
        let mut group = client.load_group(&state.group_id)?;
        let mut two_party = Mls2Party::new(Role::Initiator);
        let commit = two_party.create_resumption_and_merge(&mut group)?;
        let record = create_record_layer(&group, Side::Client)?;
        group.write_to_storage()?;
        let inner = ConnectionCommon::new_client_resuming(
            group,
            record,
            two_party,
            config.verifier.clone(),
            server_name,
            commit,
        )?;
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

    /// The backend's built-in root set, under whichever name that backend spells it.
    fn with_default_roots() -> ConfigBuilder<ClientConfig, WantsClientCredential> {
        #[cfg(feature = "rustcrypto")]
        return ClientConfig::builder().with_webpki_roots();
        #[cfg(feature = "openssl")]
        return ClientConfig::builder().with_system_roots();
    }

    #[test]
    fn builds_secure_and_insecure_client_configs() {
        crate::test_init();
        // default roots + generated credential
        let secure = with_default_roots()
            .with_generated_basic_credential(b"alice")
            .unwrap();
        assert!(matches!(secure.verifier, ServerCertVerifier::DefaultRoots));

        // explicit DER roots
        let explicit = ClientConfig::builder()
            .with_root_certificates(vec![CertificateDer::from(vec![0x30, 0x00])])
            .with_generated_basic_credential(b"carol")
            .unwrap();
        assert!(matches!(explicit.verifier, ServerCertVerifier::Roots(ref r) if r.len() == 1));

        // no verification + generated credential
        let insecure = ClientConfig::builder()
            .with_no_certificate_verification()
            .with_generated_basic_credential(b"bob")
            .unwrap();
        assert!(matches!(insecure.verifier, ServerCertVerifier::None));
    }
}
