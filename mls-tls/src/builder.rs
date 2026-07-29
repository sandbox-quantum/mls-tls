//! Shared typestate config builder.
//!
//! `Side` is `ClientConfig` or `ServerConfig`; `State` is a zero-cost marker that advances at each
//! `.with_*` call so required settings are provided exactly once, in order, checked at compile time.
//! The verifier is the first required stage; the crypto backend is fixed at compile time (feature
//! `rustcrypto` or `openssl`) and the cipher suite has a sensible per-backend default with an optional
//! `with_cipher_suite` override on the second stage.

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
