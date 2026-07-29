//! The Python exception hierarchy, and the translation from [`mls_tls::Error`] into it.
//!
//! Shaped after `ssl`'s: one base class so `except MLSTLSError` catches everything, with
//! subclasses for the distinctions a caller can actually act on — a rejected peer credential is
//! recoverable by changing trust anchors, an unsupported cipher suite by changing the config, a
//! protocol failure by neither.
//!
//! `Error` is `#[non_exhaustive]`, so the mapping ends in a catch-all rather than a match that
//! would fail to compile the next time a variant is added.

use pyo3::{create_exception, exceptions::PyException, prelude::*};

create_exception!(
    mls_tls,
    MLSTLSError,
    PyException,
    "Base class for every error raised by mls-tls."
);
create_exception!(
    mls_tls,
    WantReadError,
    MLSTLSError,
    "The operation needs more TLS bytes from the transport before it can complete."
);
create_exception!(
    mls_tls,
    WantWriteError,
    MLSTLSError,
    "The operation needs the outgoing TLS buffer drained before it can complete."
);
create_exception!(
    mls_tls,
    CertificateError,
    MLSTLSError,
    "The peer's credential was rejected by the configured verification policy."
);
create_exception!(
    mls_tls,
    HandshakeError,
    MLSTLSError,
    "The key agreement or record layer failed. Fatal to the connection."
);
create_exception!(
    mls_tls,
    UnsupportedError,
    MLSTLSError,
    "The request is well-formed but this build cannot serve it (e.g. a cipher suite the compiled \
     backend does not have)."
);
create_exception!(
    mls_tls,
    RaggedEOF,
    MLSTLSError,
    "The connection ended without a close_notify, so the stream may have been truncated."
);

/// Render an error together with its `source()` chain.
///
/// The crate's top-level messages are deliberately terse (`"MLS handshake failed"`); everything
/// actionable lives in the wrapped error, so flattening the chain is what makes the exception worth
/// reading.
fn describe(err: &dyn std::error::Error) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

/// Translate a crate error into the matching Python exception.
pub(crate) fn to_py_err(err: mls_tls::Error) -> PyErr {
    use mls_tls::Error;

    let message = describe(&err);
    match err {
        // Transport failures are the caller's own I/O, so they stay OSError rather than becoming a
        // TLS-flavoured exception the caller would have to unwrap.
        Error::Io(e) => PyErr::from(e),
        Error::Identity(_) => CertificateError::new_err(message),
        Error::Unsupported(_) => UnsupportedError::new_err(message),
        Error::PeerClosed => RaggedEOF::new_err(message),
        Error::Handshake(_)
        | Error::Mls(_)
        | Error::Record(_)
        | Error::KeySchedule(_)
        | Error::Decode(_)
        | Error::UnexpectedMessage(_) => HandshakeError::new_err(message),
        _ => MLSTLSError::new_err(message),
    }
}

/// Register the exception types on the module.
pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    module.add("MLSTLSError", py.get_type::<MLSTLSError>())?;
    module.add("WantReadError", py.get_type::<WantReadError>())?;
    module.add("WantWriteError", py.get_type::<WantWriteError>())?;
    module.add("CertificateError", py.get_type::<CertificateError>())?;
    module.add("HandshakeError", py.get_type::<HandshakeError>())?;
    module.add("UnsupportedError", py.get_type::<UnsupportedError>())?;
    module.add("RaggedEOF", py.get_type::<RaggedEOF>())?;
    Ok(())
}
