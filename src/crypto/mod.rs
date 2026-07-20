//! Custom `mls-rs` crypto provider adding the non-standard **X-Wing** cipher suite (advertised as
//! id `0x004e`) used by the `mls-tls-python-pedantic` implementation, alongside the standard
//! RustCrypto suites (1–7).
//!
//! X-Wing here = ML-KEM-1024 + P-384 with a SHA3-384 combiner, HPKE base mode over HKDF-SHA384 +
//! AES-256-GCM, an MLS key schedule over SHA-512, and ECDSA-P384/SHA-384 signatures. See
//! [`xwing`] for the KEM and [`provider`] for the `CryptoProvider`/`CipherSuiteProvider` wiring.

pub(crate) mod provider;
pub(crate) mod xwing;

use mls_rs::CipherSuite;

/// The advertised cipher-suite id for the custom X-Wing suite (`MLS_256_XWING_AES256GCM_SHA512_P384`).
pub(crate) const XWING_CIPHER_SUITE: CipherSuite = CipherSuite::new(0x004e);
