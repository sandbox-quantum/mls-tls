//! Unified error type for the public API.
//!
//! Every fallible public method returns [`Error`]. It folds in the crate's internal error types
//! (`TwoPartyError`, `RecordError`, `MlsTlsError`, `PkiError`) plus the sans-I/O
//! framing/state errors surfaced by the connection.

use crate::mls_tls_01::MlsTlsError;
use crate::mls_two_party_profile_00::TwoPartyError;
use crate::pki::PkiError;
use crate::tls_record::RecordError;

/// The single error type returned by the `mls-tls` public API.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying transport I/O failed (from `read_tls`/`write_tls`).
    #[error("I/O error")]
    Io(#[from] std::io::Error),

    /// The two-party MLS handshake / key-agreement state machine failed.
    #[error("MLS handshake failed")]
    Handshake(#[from] TwoPartyError),

    /// A raw mls-rs operation failed (e.g. loading a group during resumption).
    #[error("MLS operation failed")]
    Mls(#[from] mls_rs::error::MlsError),

    /// The TLS 1.3 record layer failed to encrypt or decrypt.
    #[error("record layer error")]
    Record(#[from] RecordError),

    /// Deriving the traffic secrets from the MLS group failed.
    #[error("key derivation failed")]
    KeySchedule(#[from] MlsTlsError),

    /// The peer's credential was rejected during the directional peer check.
    #[error("peer identity rejected")]
    Identity(#[from] PkiError),

    /// Peer authentication failed (e.g. the joined group's key did not match the presented one).
    #[error("peer authentication failed: {0}")]
    PeerAuth(&'static str),

    /// A wire frame could not be parsed.
    #[error("malformed wire message: {0}")]
    Decode(&'static str),

    /// A frame arrived that is not valid for the connection's current state.
    #[error("unexpected message for current state: {0}")]
    UnexpectedMessage(&'static str),

    /// A feature that is defined in the design but not yet implemented.
    #[error("feature not yet supported: {0}")]
    Unsupported(&'static str),

    /// FIPS mode could not be activated, or is required by this build but is not active.
    /// See [`crate::fips`].
    #[cfg(feature = "fips")]
    #[error("FIPS mode: {0}")]
    Fips(String),

    /// The peer signalled (or the transport indicated) that the connection is closed.
    #[error("peer closed the connection")]
    PeerClosed,
}
