//! Shared typestate config builder, mirroring rustls' `ConfigBuilder<Side, State>`.
//!
//! `Side` is `ClientConfig` or `ServerConfig`; `State` is a zero-cost marker that advances at each
//! `.with_*` call so required settings are provided exactly once, in order, checked at compile time.
//! The cipher suite (`CURVE25519_AES128`) and crypto provider (`RustCryptoProvider`) are fixed, so
//! the first stage a caller sees is the verifier (there are no cipher-suite/kx stages).

use std::marker::PhantomData;

/// Typestate builder for [`ClientConfig`](crate::client::ClientConfig) /
/// [`ServerConfig`](crate::server::ServerConfig). Obtain one via `ClientConfig::builder()` /
/// `ServerConfig::builder()`; you generally never name the type parameters.
pub struct ConfigBuilder<Side, State> {
    pub(crate) state: State,
    pub(crate) side: PhantomData<Side>,
}

impl<Side, State> ConfigBuilder<Side, State> {
    pub(crate) fn new(state: State) -> Self {
        Self {
            state,
            side: PhantomData,
        }
    }
}
