//! The `mls-rs` [`CryptoProvider`] for the crate, over a **single, compile-time-selected** standard
//! backend — RustCrypto (feature `rustcrypto`, default) or OpenSSL (feature `openssl`). The two
//! features are mutually exclusive (enforced by a `compile_error!` in `lib.rs`).
//!
//! Under `rustcrypto` the provider also adds the custom X-Wing suite (`0x004e`) via
//! [`XWingCipherSuite`]. Under `openssl` there is no X-Wing suite: `cipher_suite_provider(0x004e)`
//! returns `None`, which mls-rs surfaces as `UnsupportedCipherSuite` at runtime (X-Wing's bespoke
//! ML-KEM + P-384 KEM has no byte-compatible OpenSSL path, so it is RustCrypto-only by construction).
//!
//! Because exactly one backend is compiled, the HPKE context types are uniform
//! (`ContextS/R<Kdf, Aead>` of the active backend) and no cross-backend bridging is needed.
//!
//! This provider is also the crate's *single* crypto boundary: the TLS record layer
//! ([`crate::tls_record`]) derives its keys and protects its records through
//! [`MlsTlsCipherSuiteProvider`] rather than reaching for primitives of its own. That is what makes
//! `fips` meaningful — routing everything here means one place governs which algorithms are
//! reachable, and under `fips` that place is the OpenSSL FIPS provider.
//!
//! [`XWingCipherSuite`] implements [`CipherSuiteProvider`] by:
//! - running HPKE through `mls-rs-crypto-hpke`'s `Hpke` with our [`XWingKem`] and an **HKDF-SHA384**
//!   KDF + AES-256-GCM AEAD (the RFC-9180 base-mode side, matching the Python `crypto/hpke.py`),
//! - running the MLS key schedule over **HKDF-SHA512** + **SHA-512** hash/MAC,
//! - protecting MLS `PrivateMessage`s with **AES-256-GCM**,
//! - signing with **ECDSA-P384/SHA-384**.
//!
//! The KDF used by HPKE (SHA-384) is deliberately different from the MLS-layer KDF (SHA-512); the
//! two must not be conflated. `kem_derive` bypasses HPKE's `DeriveKeyPair` (`dkp_prk`) and calls the
//! KEM's SHAKE256-based derivation directly, matching the Python.

use mls_rs_core::crypto::{
    CipherSuite, CipherSuiteProvider, CryptoProvider, HpkeCiphertext, HpkePsk, HpkePublicKey,
    HpkeSecretKey, SignaturePublicKey, SignatureSecretKey,
};
#[cfg(feature = "rustcrypto")]
use mls_rs_core::error::AnyError;
use mls_rs_core::error::IntoAnyError;
use mls_rs_crypto_hpke::{
    context::{ContextR, ContextS},
    hpke::HpkeError,
};
use zeroize::Zeroizing;

// The compile-time-selected standard backend. `Kdf`/`Aead` are the backend's HPKE KDF/AEAD types,
// which parameterise the shared `ContextS/R` HPKE context types.
#[cfg(feature = "openssl")]
use mls_rs_crypto_openssl::{
    OpensslCryptoError as BackendError, OpensslCryptoProvider as BackendProvider, aead::Aead,
    kdf::Kdf,
};
#[cfg(feature = "rustcrypto")]
use mls_rs_crypto_rustcrypto::{
    RustCryptoError as BackendError, RustCryptoProvider as BackendProvider,
    aead::Aead,
    ec_signer::{EcSigner, EcSignerError},
    kdf::Kdf,
    mac::{Hash, HashError},
};

#[cfg(feature = "rustcrypto")]
use mls_rs_crypto_hpke::hpke::Hpke;
#[cfg(feature = "rustcrypto")]
use mls_rs_crypto_traits::{AeadType, KdfType, KemType};

#[cfg(feature = "rustcrypto")]
use super::MLS_256_XWING_AES256GCM_SHA512_P384;
#[cfg(feature = "rustcrypto")]
use super::xwing::{XWingError, XWingKem};

/// The concrete standard-suite cipher-suite provider produced by the active backend.
type StdCsp = <BackendProvider as CryptoProvider>::CipherSuiteProvider;

/// Unified error for the composite provider.
#[derive(Debug)]
pub(crate) enum MlsTlsCryptoError {
    /// An error from the active standard backend.
    Std(BackendError),
    /// An HPKE error (both backends share `mls-rs-crypto-hpke`'s `HpkeError`).
    Hpke(HpkeError),
    #[cfg(feature = "rustcrypto")]
    Kem(XWingError),
    #[cfg(feature = "rustcrypto")]
    Kdf(AnyError),
    #[cfg(feature = "rustcrypto")]
    Aead(AnyError),
    #[cfg(feature = "rustcrypto")]
    Hash(HashError),
    #[cfg(feature = "rustcrypto")]
    EcSigner(EcSignerError),
    #[cfg(feature = "rustcrypto")]
    Rand,
}

impl core::fmt::Display for MlsTlsCryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MlsTlsCryptoError::Std(e) => write!(f, "{e}"),
            MlsTlsCryptoError::Hpke(e) => write!(f, "{e}"),
            #[cfg(feature = "rustcrypto")]
            MlsTlsCryptoError::Kem(e) => write!(f, "{e}"),
            #[cfg(feature = "rustcrypto")]
            MlsTlsCryptoError::Kdf(e) => write!(f, "{e}"),
            #[cfg(feature = "rustcrypto")]
            MlsTlsCryptoError::Aead(e) => write!(f, "{e}"),
            #[cfg(feature = "rustcrypto")]
            MlsTlsCryptoError::Hash(e) => write!(f, "{e}"),
            #[cfg(feature = "rustcrypto")]
            MlsTlsCryptoError::EcSigner(e) => write!(f, "{e}"),
            #[cfg(feature = "rustcrypto")]
            MlsTlsCryptoError::Rand => write!(f, "RNG failure"),
        }
    }
}

impl std::error::Error for MlsTlsCryptoError {}

impl IntoAnyError for MlsTlsCryptoError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

impl From<BackendError> for MlsTlsCryptoError {
    fn from(e: BackendError) -> Self {
        MlsTlsCryptoError::Std(e)
    }
}
impl From<HpkeError> for MlsTlsCryptoError {
    fn from(e: HpkeError) -> Self {
        MlsTlsCryptoError::Hpke(e)
    }
}
#[cfg(feature = "rustcrypto")]
impl From<XWingError> for MlsTlsCryptoError {
    fn from(e: XWingError) -> Self {
        MlsTlsCryptoError::Kem(e)
    }
}
#[cfg(feature = "rustcrypto")]
impl From<HashError> for MlsTlsCryptoError {
    fn from(e: HashError) -> Self {
        MlsTlsCryptoError::Hash(e)
    }
}
#[cfg(feature = "rustcrypto")]
impl From<EcSignerError> for MlsTlsCryptoError {
    fn from(e: EcSignerError) -> Self {
        MlsTlsCryptoError::EcSigner(e)
    }
}

/// The X-Wing (`0x004e`) cipher-suite provider (RustCrypto-backed; see the module docs).
#[cfg(feature = "rustcrypto")]
#[derive(Clone)]
pub(crate) struct XWingCipherSuite {
    hpke: Hpke<XWingKem, Kdf, Aead>,
    kem: XWingKem,
    mls_kdf: Kdf,
    hash: Hash,
    aead: Aead,
    ec_signer: EcSigner,
}

#[cfg(feature = "rustcrypto")]
impl XWingCipherSuite {
    pub(crate) fn new() -> Self {
        let kem = XWingKem;
        // HPKE side: HKDF-SHA384 + AES-256-GCM (suite 7 constructors give exactly these).
        let hpke_kdf = Kdf::new(CipherSuite::P384_AES256).expect("p384 kdf");
        let hpke_aead = Aead::new(CipherSuite::P384_AES256).expect("p384 aead");
        Self {
            hpke: Hpke::new(kem.clone(), hpke_kdf, Some(hpke_aead)),
            kem,
            // MLS side: HKDF-SHA512 + SHA-512 (suite 5 gives SHA-512).
            mls_kdf: Kdf::new(CipherSuite::P521_AES256).expect("p521 kdf"),
            hash: Hash::new(CipherSuite::P521_AES256).expect("p521 hash"),
            // MLS PrivateMessage protection: AES-256-GCM.
            aead: Aead::new(CipherSuite::P384_AES256).expect("p384 aead"),
            // Signatures: ECDSA-P384/SHA-384.
            ec_signer: EcSigner::new(CipherSuite::P384_AES256).expect("p384 signer"),
        }
    }
}

#[cfg(feature = "rustcrypto")]
impl CipherSuiteProvider for XWingCipherSuite {
    type Error = MlsTlsCryptoError;
    type HpkeContextS = ContextS<Kdf, Aead>;
    type HpkeContextR = ContextR<Kdf, Aead>;

    fn cipher_suite(&self) -> CipherSuite {
        MLS_256_XWING_AES256GCM_SHA512_P384
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.hash(data))
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.hash.mac(key, data)?)
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        self.aead
            .seal(key, data, aad, nonce)
            .map_err(|e| MlsTlsCryptoError::Aead(e.into_any_error()))
    }

    fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.aead
            .open(key, ciphertext, aad, nonce)
            .map(Zeroizing::new)
            .map_err(|e| MlsTlsCryptoError::Aead(e.into_any_error()))
    }

    fn aead_key_size(&self) -> usize {
        self.aead.key_size()
    }

    fn aead_nonce_size(&self) -> usize {
        self.aead.nonce_size()
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.mls_kdf
            .extract(salt, ikm)
            .map(Zeroizing::new)
            .map_err(|e| MlsTlsCryptoError::Kdf(e.into_any_error()))
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        self.mls_kdf
            .expand(prk, info, len)
            .map(Zeroizing::new)
            .map_err(|e| MlsTlsCryptoError::Kdf(e.into_any_error()))
    }

    fn kdf_extract_size(&self) -> usize {
        self.mls_kdf.extract_size()
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke.seal(remote_key, info, None, aad, pt)?)
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        Ok(self.hpke.seal(remote_key, info, Some(psk), aad, pt)?)
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .hpke
            .open(ciphertext, local_secret, local_public, info, None, aad)?)
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        Ok(self
            .hpke
            .open(ciphertext, local_secret, local_public, info, Some(psk), aad)?)
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        Ok(self.hpke.setup_sender(remote_key, info, None)?)
    }

    fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        Ok(self
            .hpke
            .setup_receiver(kem_output, local_secret, local_public, info, None)?)
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        // Direct SHAKE256 DeriveKeyPair — NOT HPKE's dkp_prk path.
        Ok(self.kem.generate_deterministic(ikm)?)
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        Ok(self.kem.generate()?)
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        Ok(self.kem.public_key_validate(key)?)
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        use rand_core::{OsRng, RngCore};
        OsRng
            .try_fill_bytes(out)
            .map_err(|_| MlsTlsCryptoError::Rand)
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        Ok(self.ec_signer.signature_key_generate()?)
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        Ok(self.ec_signer.signature_key_derive_public(secret_key)?)
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Ok(self.ec_signer.sign(secret_key, data)?)
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        Ok(self.ec_signer.verify(public_key, signature, data)?)
    }
}

/// A cipher-suite provider: a standard suite from the active backend, or (under `rustcrypto`) the
/// X-Wing suite. Both share the backend's concrete HPKE context types (`ContextS/R<Kdf, Aead>`).
#[derive(Clone)]
pub(crate) enum MlsTlsCipherSuiteProvider {
    Standard(StdCsp),
    #[cfg(feature = "rustcrypto")]
    XWing(XWingCipherSuite),
}

/// Delegate a `&self` method to whichever inner provider is active, mapping the standard error.
macro_rules! delegate {
    ($self:ident, $p:ident => $call:expr) => {
        match $self {
            MlsTlsCipherSuiteProvider::Standard($p) => $call.map_err(MlsTlsCryptoError::Std),
            #[cfg(feature = "rustcrypto")]
            MlsTlsCipherSuiteProvider::XWing($p) => $call,
        }
    };
}

/// Delegate an infallible `&self` accessor to whichever inner provider is active.
macro_rules! delegate_plain {
    ($self:ident, $p:ident => $call:expr) => {
        match $self {
            MlsTlsCipherSuiteProvider::Standard($p) => $call,
            #[cfg(feature = "rustcrypto")]
            MlsTlsCipherSuiteProvider::XWing($p) => $call,
        }
    };
}

impl CipherSuiteProvider for MlsTlsCipherSuiteProvider {
    type Error = MlsTlsCryptoError;
    type HpkeContextS = ContextS<Kdf, Aead>;
    type HpkeContextR = ContextR<Kdf, Aead>;

    fn cipher_suite(&self) -> CipherSuite {
        delegate_plain!(self, p => p.cipher_suite())
    }

    fn hash(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        delegate!(self, p => p.hash(data))
    }

    fn mac(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        delegate!(self, p => p.mac(key, data))
    }

    fn aead_seal(
        &self,
        key: &[u8],
        data: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Vec<u8>, Self::Error> {
        delegate!(self, p => p.aead_seal(key, data, aad, nonce))
    }

    fn aead_open(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        aad: Option<&[u8]>,
        nonce: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        delegate!(self, p => p.aead_open(key, ciphertext, aad, nonce))
    }

    fn aead_key_size(&self) -> usize {
        delegate_plain!(self, p => p.aead_key_size())
    }

    fn aead_nonce_size(&self) -> usize {
        delegate_plain!(self, p => p.aead_nonce_size())
    }

    fn kdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        delegate!(self, p => p.kdf_extract(salt, ikm))
    }

    fn kdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        delegate!(self, p => p.kdf_expand(prk, info, len))
    }

    fn kdf_extract_size(&self) -> usize {
        delegate_plain!(self, p => p.kdf_extract_size())
    }

    fn hpke_seal(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
    ) -> Result<HpkeCiphertext, Self::Error> {
        delegate!(self, p => p.hpke_seal(remote_key, info, aad, pt))
    }

    fn hpke_seal_psk(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        pt: &[u8],
        psk: HpkePsk<'_>,
    ) -> Result<HpkeCiphertext, Self::Error> {
        delegate!(self, p => p.hpke_seal_psk(remote_key, info, aad, pt, psk))
    }

    fn hpke_open(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        delegate!(self, p => p.hpke_open(ciphertext, local_secret, local_public, info, aad))
    }

    fn hpke_open_psk(
        &self,
        ciphertext: &HpkeCiphertext,
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
        aad: Option<&[u8]>,
        psk: HpkePsk<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, Self::Error> {
        delegate!(self, p => p.hpke_open_psk(ciphertext, local_secret, local_public, info, aad, psk))
    }

    fn hpke_setup_s(
        &self,
        remote_key: &HpkePublicKey,
        info: &[u8],
    ) -> Result<(Vec<u8>, Self::HpkeContextS), Self::Error> {
        delegate!(self, p => p.hpke_setup_s(remote_key, info))
    }

    fn hpke_setup_r(
        &self,
        kem_output: &[u8],
        local_secret: &HpkeSecretKey,
        local_public: &HpkePublicKey,
        info: &[u8],
    ) -> Result<Self::HpkeContextR, Self::Error> {
        delegate!(self, p => p.hpke_setup_r(kem_output, local_secret, local_public, info))
    }

    fn kem_derive(&self, ikm: &[u8]) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        delegate!(self, p => p.kem_derive(ikm))
    }

    fn kem_generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        delegate!(self, p => p.kem_generate())
    }

    fn kem_public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        delegate!(self, p => p.kem_public_key_validate(key))
    }

    fn random_bytes(&self, out: &mut [u8]) -> Result<(), Self::Error> {
        delegate!(self, p => p.random_bytes(out))
    }

    fn signature_key_generate(
        &self,
    ) -> Result<(SignatureSecretKey, SignaturePublicKey), Self::Error> {
        delegate!(self, p => p.signature_key_generate())
    }

    fn signature_key_derive_public(
        &self,
        secret_key: &SignatureSecretKey,
    ) -> Result<SignaturePublicKey, Self::Error> {
        delegate!(self, p => p.signature_key_derive_public(secret_key))
    }

    fn sign(&self, secret_key: &SignatureSecretKey, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        delegate!(self, p => p.sign(secret_key, data))
    }

    fn verify(
        &self,
        public_key: &SignaturePublicKey,
        signature: &[u8],
        data: &[u8],
    ) -> Result<(), Self::Error> {
        delegate!(self, p => p.verify(public_key, signature, data))
    }
}

/// The MLS cipher suites whose every primitive is FIPS-approved.
///
/// The other four standard suites are excluded for concrete reasons, not caution:
/// - `CURVE25519_*` (0x0001, 0x0003) and `CURVE448_*` (0x0004, 0x0006) rest on X25519/X448 key
///   agreement. Those curves are in SP 800-186 but not SP 800-56Arev3, and the FIPS provider
///   flags their key management as **unapproved** — even though Ed25519/Ed448 *signatures* are
///   approved. The KEM is what disqualifies them.
/// - `*_CHACHA` (0x0003, 0x0006) additionally need ChaCha20-Poly1305, which the FIPS provider does
///   not implement at all.
/// - X-Wing (0x004e) is RustCrypto-only by construction and never reaches this build.
///
/// Filtering here rather than at the config layer means every consumer inherits it: signature key
/// generation, the record layer and the MLS group all resolve suites through
/// `cipher_suite_provider`, and each already handles `None`.
#[cfg(feature = "fips")]
const FIPS_APPROVED_SUITES: &[CipherSuite] = &[
    CipherSuite::P256_AES128,
    CipherSuite::P384_AES256,
    CipherSuite::P521_AES256,
];

/// The composite [`CryptoProvider`]: the compile-time-selected standard backend, plus (under
/// `rustcrypto`) the X-Wing suite (`0x004e`). Under `fips`, restricted to [`FIPS_APPROVED_SUITES`].
#[derive(Clone, Default)]
pub(crate) struct MlsTlsCryptoProvider {
    inner: BackendProvider,
}

impl MlsTlsCryptoProvider {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl CryptoProvider for MlsTlsCryptoProvider {
    type CipherSuiteProvider = MlsTlsCipherSuiteProvider;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        #[allow(unused_mut)]
        let mut suites = self.inner.supported_cipher_suites();
        #[cfg(feature = "fips")]
        suites.retain(|suite| FIPS_APPROVED_SUITES.contains(suite));
        #[cfg(feature = "rustcrypto")]
        suites.push(MLS_256_XWING_AES256GCM_SHA512_P384);
        suites
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        #[cfg(feature = "fips")]
        if !FIPS_APPROVED_SUITES.contains(&cipher_suite) {
            return None;
        }
        #[cfg(feature = "rustcrypto")]
        if cipher_suite == MLS_256_XWING_AES256GCM_SHA512_P384 {
            return Some(MlsTlsCipherSuiteProvider::XWing(XWingCipherSuite::new()));
        }
        self.inner
            .cipher_suite_provider(cipher_suite)
            .map(MlsTlsCipherSuiteProvider::Standard)
    }
}
