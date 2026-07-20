//! The `mls-rs` [`CryptoProvider`] that adds the X-Wing suite (`0x004e`) on top of the standard
//! RustCrypto suites (1–7).
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
use mls_rs_core::error::{AnyError, IntoAnyError};
use mls_rs_crypto_hpke::{
    context::{ContextR, ContextS},
    hpke::{Hpke, HpkeError},
};
use mls_rs_crypto_rustcrypto::{
    RustCryptoError, RustCryptoProvider,
    aead::Aead,
    ec_signer::{EcSigner, EcSignerError},
    kdf::Kdf,
    mac::{Hash, HashError},
};
use mls_rs_crypto_traits::{AeadType, KdfType, KemType};
use zeroize::Zeroizing;

use super::XWING_CIPHER_SUITE;
use super::xwing::{XWingError, XWingKem};

/// The concrete standard-suite cipher-suite provider produced by [`RustCryptoProvider`].
type StdCsp = <RustCryptoProvider as CryptoProvider>::CipherSuiteProvider;

/// Unified error for the composite provider.
#[derive(Debug)]
pub(crate) enum MlsTlsCryptoError {
    Std(RustCryptoError),
    Kem(XWingError),
    Hpke(HpkeError),
    Kdf(AnyError),
    Aead(AnyError),
    Hash(HashError),
    EcSigner(EcSignerError),
    Rand,
}

impl core::fmt::Display for MlsTlsCryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MlsTlsCryptoError::Std(e) => write!(f, "{e}"),
            MlsTlsCryptoError::Kem(e) => write!(f, "{e}"),
            MlsTlsCryptoError::Hpke(e) => write!(f, "{e}"),
            MlsTlsCryptoError::Kdf(e) => write!(f, "{e}"),
            MlsTlsCryptoError::Aead(e) => write!(f, "{e}"),
            MlsTlsCryptoError::Hash(e) => write!(f, "{e}"),
            MlsTlsCryptoError::EcSigner(e) => write!(f, "{e}"),
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

impl From<RustCryptoError> for MlsTlsCryptoError {
    fn from(e: RustCryptoError) -> Self {
        MlsTlsCryptoError::Std(e)
    }
}
impl From<XWingError> for MlsTlsCryptoError {
    fn from(e: XWingError) -> Self {
        MlsTlsCryptoError::Kem(e)
    }
}
impl From<HpkeError> for MlsTlsCryptoError {
    fn from(e: HpkeError) -> Self {
        MlsTlsCryptoError::Hpke(e)
    }
}
impl From<HashError> for MlsTlsCryptoError {
    fn from(e: HashError) -> Self {
        MlsTlsCryptoError::Hash(e)
    }
}
impl From<EcSignerError> for MlsTlsCryptoError {
    fn from(e: EcSignerError) -> Self {
        MlsTlsCryptoError::EcSigner(e)
    }
}

/// The X-Wing (`0x004e`) cipher-suite provider.
#[derive(Clone)]
pub(crate) struct XWingCipherSuite {
    hpke: Hpke<XWingKem, Kdf, Aead>,
    kem: XWingKem,
    mls_kdf: Kdf,
    hash: Hash,
    aead: Aead,
    ec_signer: EcSigner,
}

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

impl CipherSuiteProvider for XWingCipherSuite {
    type Error = MlsTlsCryptoError;
    type HpkeContextS = ContextS<Kdf, Aead>;
    type HpkeContextR = ContextR<Kdf, Aead>;

    fn cipher_suite(&self) -> CipherSuite {
        XWING_CIPHER_SUITE
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
        Ok(self.hpke.open(
            ciphertext,
            local_secret,
            local_public,
            info,
            Some(psk),
            aad,
        )?)
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
        OsRng.try_fill_bytes(out).map_err(|_| MlsTlsCryptoError::Rand)
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

/// A cipher-suite provider that is either a standard RustCrypto suite or the X-Wing suite. Both
/// share the same concrete HPKE context types (`ContextS/R<Kdf, Aead>`), so no context enum is
/// needed.
#[derive(Clone)]
pub(crate) enum MlsTlsCipherSuiteProvider {
    Standard(StdCsp),
    XWing(XWingCipherSuite),
}

/// Delegate a `&self` method to whichever inner provider is active, mapping the standard error.
macro_rules! delegate {
    ($self:ident, $p:ident => $call:expr) => {
        match $self {
            MlsTlsCipherSuiteProvider::Standard($p) => $call.map_err(MlsTlsCryptoError::Std),
            MlsTlsCipherSuiteProvider::XWing($p) => $call,
        }
    };
}

impl CipherSuiteProvider for MlsTlsCipherSuiteProvider {
    type Error = MlsTlsCryptoError;
    type HpkeContextS = ContextS<Kdf, Aead>;
    type HpkeContextR = ContextR<Kdf, Aead>;

    fn cipher_suite(&self) -> CipherSuite {
        match self {
            MlsTlsCipherSuiteProvider::Standard(p) => p.cipher_suite(),
            MlsTlsCipherSuiteProvider::XWing(p) => p.cipher_suite(),
        }
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
        match self {
            MlsTlsCipherSuiteProvider::Standard(p) => p.aead_key_size(),
            MlsTlsCipherSuiteProvider::XWing(p) => p.aead_key_size(),
        }
    }

    fn aead_nonce_size(&self) -> usize {
        match self {
            MlsTlsCipherSuiteProvider::Standard(p) => p.aead_nonce_size(),
            MlsTlsCipherSuiteProvider::XWing(p) => p.aead_nonce_size(),
        }
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
        match self {
            MlsTlsCipherSuiteProvider::Standard(p) => p.kdf_extract_size(),
            MlsTlsCipherSuiteProvider::XWing(p) => p.kdf_extract_size(),
        }
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

/// The composite [`CryptoProvider`]: standard RustCrypto suites plus X-Wing (`0x004e`).
#[derive(Clone, Default)]
pub(crate) struct MlsTlsCryptoProvider {
    inner: RustCryptoProvider,
}

impl MlsTlsCryptoProvider {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl CryptoProvider for MlsTlsCryptoProvider {
    type CipherSuiteProvider = MlsTlsCipherSuiteProvider;

    fn supported_cipher_suites(&self) -> Vec<CipherSuite> {
        let mut suites = self.inner.supported_cipher_suites();
        suites.push(XWING_CIPHER_SUITE);
        suites
    }

    fn cipher_suite_provider(
        &self,
        cipher_suite: CipherSuite,
    ) -> Option<Self::CipherSuiteProvider> {
        if cipher_suite == XWING_CIPHER_SUITE {
            Some(MlsTlsCipherSuiteProvider::XWing(XWingCipherSuite::new()))
        } else {
            self.inner
                .cipher_suite_provider(cipher_suite)
                .map(MlsTlsCipherSuiteProvider::Standard)
        }
    }
}
