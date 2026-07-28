//! Custom `mls-rs` crypto provider over a **compile-time-selected** standard backend — RustCrypto
//! (feature `rustcrypto`, default) or OpenSSL (feature `openssl`). The two are mutually exclusive.
//!
//! Under `rustcrypto` the provider also adds the non-standard **X-Wing** cipher suite (advertised as
//! id `0x004e`) used by the `mls-tls-python-pedantic` implementation: ML-KEM-1024 + P-384 with a
//! SHA3-384 combiner, HPKE base mode over HKDF-SHA384 + AES-256-GCM, an MLS key schedule over
//! SHA-512, and ECDSA-P384/SHA-384 signatures. See [`xwing`] for the KEM and [`provider`] for the
//! `CryptoProvider`/`CipherSuiteProvider` wiring.
//!
//! X-Wing is RustCrypto-only (its KEM has no byte-compatible OpenSSL path). Under the `openssl`
//! backend it is unavailable and requesting suite `0x004e` fails at runtime with
//! `UnsupportedCipherSuite`.

pub(crate) mod provider;
#[cfg(feature = "rustcrypto")]
pub(crate) mod xwing;

use mls_rs::CipherSuite;

/// The advertised cipher-suite id for the custom X-Wing suite (`MLS_256_XWING_AES256GCM_SHA512_P384`).
///
/// Pass this to `ClientConfig`/`ServerConfig`'s `with_cipher_suite` to select it (it is also the
/// default under the `rustcrypto` backend). Under the `openssl` backend it is unsupported and
/// selecting it yields a runtime error.
pub const MLS_256_XWING_AES256GCM_SHA512_P384: CipherSuite = CipherSuite::new(0x004e);
