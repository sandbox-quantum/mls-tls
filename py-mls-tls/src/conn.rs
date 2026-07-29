//! The sans-I/O connection objects, plus `IoState` and `Session`.
//!
//! These mirror the crate's `ConnectionCommon` byte pipeline one-for-one, under the names rustls
//! and pyrtls use, so the two implementations read the same way. No socket is involved: the caller
//! moves bytes with `read_tls`/`write_tls_into` and plaintext with `write`/`read_into`. The socket
//! wrapper in `mls_tls._socket` is built on exactly this surface.
//!
//! Threading: each connection is a `frozen` pyclass around a `Mutex`, so a connection can be shared
//! between threads and the free-threaded build needs no special casing. Every method that does real
//! work releases the GIL *before* taking the lock, which is the ordering pyo3 documents to avoid
//! deadlocking against an interpreter that drops the GIL mid-call.

use std::io::Read;
use std::sync::{Arc, Mutex, MutexGuard};

use mls_tls::{
    ClientConnection as RsClientConnection, ConnectionCommon, PeerIdentity, ResumptionState,
    ServerConnection as RsServerConnection, ServerName,
};
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::PyBytes;

use crate::config::{PyClientConfig, PyServerConfig};
use crate::error::{MLSTLSError, to_py_err};

/// Take the connection lock, turning poisoning into an ordinary exception.
///
/// A poisoned lock means a previous call panicked mid-operation, which leaves the record layer's
/// sequence numbers in an unknown state — so the connection is dead either way and the useful thing
/// is to say so rather than propagate the panic.
fn lock<T>(mutex: &Mutex<T>) -> PyResult<MutexGuard<'_, T>> {
    mutex
        .lock()
        .map_err(|_| MLSTLSError::new_err("connection is unusable: a previous operation panicked"))
}

/// What [`process_new_packets`](PyClientConnection::process_new_packets) learned about the
/// connection.
#[pyclass(frozen, module = "mls_tls", name = "IoState")]
pub(crate) struct PyIoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
    peer_has_closed: bool,
}

#[pymethods]
impl PyIoState {
    /// Bytes waiting to go to the network. Non-zero implies `writable()` is true.
    #[getter]
    fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// Decrypted plaintext bytes waiting to be read.
    #[getter]
    fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }

    /// Whether the peer has sent `close_notify`. No further application data will arrive.
    #[getter]
    fn peer_has_closed(&self) -> bool {
        self.peer_has_closed
    }

    fn __repr__(&self) -> String {
        format!(
            "<mls_tls.IoState tls_bytes_to_write={} plaintext_bytes_to_read={} peer_has_closed={}>",
            self.tls_bytes_to_write,
            self.plaintext_bytes_to_read,
            if self.peer_has_closed {
                "True"
            } else {
                "False"
            }
        )
    }
}

impl From<mls_tls::IoState> for PyIoState {
    fn from(state: mls_tls::IoState) -> Self {
        Self {
            tls_bytes_to_write: state.tls_bytes_to_write,
            plaintext_bytes_to_read: state.plaintext_bytes_to_read,
            peer_has_closed: state.peer_has_closed,
        }
    }
}

/// A handle to a session that can be resumed later.
///
/// It names persisted MLS group state rather than carrying it, so it is only meaningful to a
/// connection built from the same `ClientConfig` — the group itself lives in that config's storage.
/// It is not a bearer token and resuming elsewhere will fail.
// `from_py_object` because `ClientConnection(..., session=...)` takes one by value.
#[pyclass(frozen, from_py_object, module = "mls_tls", name = "Session")]
#[derive(Clone)]
pub(crate) struct PySession {
    pub(crate) inner: ResumptionState,
}

#[pymethods]
impl PySession {
    /// Serialize the handle.
    fn to_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.to_bytes())
    }

    /// Reconstruct a handle from [`to_bytes`](Self::to_bytes).
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> Self {
        Self {
            inner: ResumptionState::from_bytes(data),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "<mls_tls.Session group_id={}>",
            hex_prefix(&self.inner.to_bytes())
        )
    }
}

/// First few bytes of an identifier, for a readable `repr`.
fn hex_prefix(bytes: &[u8]) -> String {
    let shown: String = bytes.iter().take(8).map(|b| format!("{b:02x}")).collect();
    if bytes.len() > 8 {
        format!("{shown}…")
    } else {
        shown
    }
}

/// Any bytes-like input: `bytes`, `bytearray`, or a `memoryview` (including a sliced one, which is
/// what `sendall` produces).
///
/// `bytes` is kept by reference rather than copied — it is the common case and the one worth
/// optimising — while anything else goes through the buffer protocol into an owned `Vec`. Both
/// variants are `Send`, so the data can cross into `py.detach()`.
pub(crate) enum Bytes {
    Borrowed(PyBackedBytes),
    Owned(Vec<u8>),
}

impl std::ops::Deref for Bytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Bytes::Borrowed(backed) => backed,
            Bytes::Owned(owned) => owned,
        }
    }
}

impl<'a, 'py> FromPyObject<'a, 'py> for Bytes {
    type Error = PyErr;

    fn extract(obj: pyo3::Borrowed<'a, 'py, PyAny>) -> PyResult<Self> {
        if let Ok(backed) = obj.extract::<PyBackedBytes>() {
            return Ok(Bytes::Borrowed(backed));
        }
        let buffer = PyBuffer::<u8>::get(&obj).map_err(|_| {
            PyValueError::new_err("expected a bytes-like object (bytes, bytearray or memoryview)")
        })?;
        let mut owned = vec![0u8; buffer.item_count()];
        buffer.copy_to_slice(obj.py(), &mut owned)?;
        Ok(Bytes::Owned(owned))
    }
}

/// Copy `data` into a caller-supplied writable buffer, returning the number of bytes written.
///
/// The buffer is filled through `Cell`s rather than a `&mut [u8]` because Python may hold other
/// references to it; that also means the work cannot happen with the GIL released, which is fine —
/// both callers are draining an in-memory queue, not doing cryptography.
fn fill_buffer(py: Python<'_>, buffer: &PyBuffer<u8>, data: &[u8]) -> PyResult<usize> {
    let slots = buffer.as_mut_slice(py).ok_or_else(|| {
        PyValueError::new_err("expected a writable, C-contiguous buffer (e.g. a bytearray)")
    })?;
    for (slot, byte) in slots.iter().zip(data) {
        slot.set(*byte);
    }
    Ok(data.len())
}

/// The role-agnostic half of the connection API.
///
/// Both connection types `Deref` to `ConnectionCommon`, so every method below is identical between
/// them; the macro exists only because pyo3 wants a single `#[pymethods]` block per class, which
/// rules out sharing them through a trait or a second impl.
macro_rules! connection_pymethods {
    ($ty:ident, $conn:ty, $( $ctor:item )+) => {
        #[pymethods]
        impl $ty {
            $( $ctor )+

            /// Feed TLS bytes from the network into the connection's input buffer.
            ///
            /// Returns how many of `data` were consumed, which may be fewer than supplied — call
            /// again until it is drained. Follow with `process_new_packets()`.
            ///
            /// Mirrors `RawIO.write()`.
            fn read_tls(&self, py: Python<'_>, data: Bytes) -> PyResult<usize> {
                py.detach(|| {
                    let mut conn = lock(&self.inner)?;
                    let mut cursor: &[u8] = &data;
                    conn.read_tls(&mut cursor).map_err(PyErr::from)
                })
            }

            /// Process everything `read_tls()` has buffered: advance the handshake, decrypt
            /// application data, and handle in-band control messages (queuing any replies).
            ///
            /// Errors here are protocol errors and are fatal to the connection.
            fn process_new_packets(&self, py: Python<'_>) -> PyResult<PyIoState> {
                py.detach(|| {
                    let mut conn = lock(&self.inner)?;
                    conn.process_new_packets()
                        .map(PyIoState::from)
                        .map_err(to_py_err)
                })
            }

            /// Write pending TLS bytes into `buf`, returning how many were written.
            ///
            /// Mirrors `RawIO.readinto()`. `buf` must be writable and C-contiguous — a `bytearray`
            /// or a writable `memoryview`.
            fn write_tls_into(&self, py: Python<'_>, buf: PyBuffer<u8>) -> PyResult<usize> {
                let mut scratch = vec![0u8; buf.item_count()];
                let written = {
                    let mut conn = lock(&self.inner)?;
                    let mut cursor: &mut [u8] = &mut scratch;
                    conn.write_tls(&mut cursor)?
                };
                fill_buffer(py, &buf, &scratch[..written])
            }

            /// Return up to `max_size` pending TLS bytes (all of them by default).
            ///
            /// The allocating counterpart to `write_tls_into()`, for callers that would only have
            /// made a throwaway `bytearray`.
            #[pyo3(signature = (max_size = None))]
            fn write_tls<'py>(
                &self,
                py: Python<'py>,
                max_size: Option<usize>,
            ) -> PyResult<Bound<'py, PyBytes>> {
                let mut conn = lock(&self.inner)?;
                let mut out = Vec::new();
                // `write_tls` emits at most one contiguous run per call, so loop to drain.
                loop {
                    let room = match max_size {
                        Some(cap) if out.len() >= cap => break,
                        Some(cap) => cap - out.len(),
                        None => usize::MAX,
                    };
                    if !conn.wants_write() {
                        break;
                    }
                    let mut chunk = vec![0u8; room.min(16 * 1024)];
                    let mut cursor: &mut [u8] = &mut chunk;
                    let n = conn.write_tls(&mut cursor)?;
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&chunk[..n]);
                }
                Ok(PyBytes::new(py, &out))
            }

            /// Encrypt `data` and queue it for the network. Drain with `write_tls_into()`.
            ///
            /// Returns the number of plaintext bytes accepted. Unlike rustls this does *not* buffer
            /// data sent before the record layer exists: writing during the initial handshake
            /// raises `HandshakeError`. Writing immediately after `resume()` or
            /// `refresh_traffic_keys()` is fine and costs no round trip — the keys are already
            /// installed at that point.
            fn write(&self, py: Python<'_>, data: Bytes) -> PyResult<usize> {
                py.detach(|| {
                    let mut conn = lock(&self.inner)?;
                    conn.write_plaintext(&data).map_err(to_py_err)
                })
            }

            /// Read decrypted plaintext into `buf`, returning how many bytes were written.
            ///
            /// `0` means nothing is buffered right now — **not** end of stream. Use
            /// `IoState.peer_has_closed` (or a transport EOF) to detect the end.
            fn read_into(&self, py: Python<'_>, buf: PyBuffer<u8>) -> PyResult<usize> {
                let mut scratch = vec![0u8; buf.item_count()];
                let n = {
                    let mut conn = lock(&self.inner)?;
                    conn.reader().read(&mut scratch)?
                };
                fill_buffer(py, &buf, &scratch[..n])
            }

            /// Return up to `size` bytes of decrypted plaintext (all buffered bytes by default).
            ///
            /// `b""` means nothing is buffered right now, with the same caveat as `read_into()`.
            #[pyo3(signature = (size = None))]
            fn read<'py>(
                &self,
                py: Python<'py>,
                size: Option<usize>,
            ) -> PyResult<Bound<'py, PyBytes>> {
                let mut conn = lock(&self.inner)?;
                let available = conn.process_new_packets().map_err(to_py_err)?
                    .plaintext_bytes_to_read;
                let mut scratch = vec![0u8; size.unwrap_or(available).min(available)];
                let n = conn.reader().read(&mut scratch)?;
                Ok(PyBytes::new(py, &scratch[..n]))
            }

            /// Whether the caller should feed more TLS bytes. False while plaintext is pending.
            fn readable(&self) -> PyResult<bool> {
                Ok(lock(&self.inner)?.wants_read())
            }

            /// Whether there are TLS bytes waiting to be sent.
            fn writable(&self) -> PyResult<bool> {
                Ok(lock(&self.inner)?.wants_write())
            }

            /// True until the initial key agreement completes.
            fn is_handshaking(&self) -> PyResult<bool> {
                Ok(lock(&self.inner)?.is_handshaking())
            }

            /// Rotate the traffic keys by advancing the MLS epoch.
            ///
            /// Costs no round trip: the new send key is installed before the control message is
            /// queued, so application data written straight afterwards rides the same flight.
            fn refresh_traffic_keys(&self, py: Python<'_>) -> PyResult<()> {
                py.detach(|| {
                    let mut conn = lock(&self.inner)?;
                    conn.refresh_traffic_keys().map_err(to_py_err)
                })
            }

            /// Queue an encrypted `close_notify`, signalling a clean shutdown of the write side.
            fn send_close_notify(&self, py: Python<'_>) -> PyResult<()> {
                py.detach(|| {
                    let mut conn = lock(&self.inner)?;
                    conn.send_close_notify().map_err(to_py_err)
                })
            }

            /// Export a `Session` for resuming this connection later.
            ///
            /// Only a connection built from the same `ClientConfig` can use it; the group state it
            /// names lives in that config's storage.
            fn session(&self, py: Python<'_>) -> PyResult<PySession> {
                py.detach(|| {
                    let mut conn = lock(&self.inner)?;
                    conn.export_resumption_state()
                        .map(|inner| PySession { inner })
                        .map_err(to_py_err)
                })
            }

            /// The peer's Basic credential identifier, or `None` if it presented an X.509 chain (use
            /// `getpeercert()`) or the handshake has not completed.
            fn peer_identity<'py>(
                &self,
                py: Python<'py>,
            ) -> PyResult<Option<Bound<'py, PyBytes>>> {
                Ok(match lock(&self.inner)?.peer_identity() {
                    Some(PeerIdentity::Basic(id)) => Some(PyBytes::new(py, &id)),
                    _ => None,
                })
            }

            /// The peer's leaf certificate in DER, or `None` if it presented a Basic credential or
            /// the handshake has not completed.
            ///
            /// `binary_form=True` is required: unlike `ssl`, there is no parsed-dict form, because
            /// this library does not carry an X.509 parser of its own. Pass the DER to
            /// `cryptography.x509.load_der_x509_certificate` if you need the fields.
            #[pyo3(signature = (binary_form = false))]
            fn getpeercert<'py>(
                &self,
                py: Python<'py>,
                binary_form: bool,
            ) -> PyResult<Option<Bound<'py, PyBytes>>> {
                if !binary_form {
                    return Err(PyValueError::new_err(
                        "only binary_form=True is supported; mls-tls does not parse certificates",
                    ));
                }
                Ok(match lock(&self.inner)?.peer_identity() {
                    Some(PeerIdentity::X509(chain)) => {
                        chain.first().map(|leaf| PyBytes::new(py, leaf))
                    }
                    _ => None,
                })
            }

            /// The full peer certificate chain in DER, leaf first, or `None`.
            fn getpeercertchain<'py>(
                &self,
                py: Python<'py>,
            ) -> PyResult<Option<Vec<Bound<'py, PyBytes>>>> {
                Ok(match lock(&self.inner)?.peer_identity() {
                    Some(PeerIdentity::X509(chain)) => Some(
                        chain.iter().map(|cert| PyBytes::new(py, cert)).collect(),
                    ),
                    _ => None,
                })
            }

            /// The negotiated cipher suite id, or `None` before the handshake completes.
            fn cipher(&self) -> PyResult<Option<u16>> {
                Ok(lock(&self.inner)?.cipher_suite().map(u16::from))
            }

            /// The current MLS epoch, or `None` before the handshake completes.
            ///
            /// It increments on every rekey and resumption.
            fn epoch(&self) -> PyResult<Option<u64>> {
                Ok(lock(&self.inner)?.epoch())
            }
        }

        impl $ty {
            /// Borrow the underlying connection. Used by the constructors' shared helpers.
            #[allow(dead_code)]
            fn borrow_conn(&self) -> PyResult<MutexGuard<'_, $conn>> {
                lock(&self.inner)
            }
        }
    };
}

/// The initiator side of an MLS-TLS connection.
#[pyclass(frozen, module = "mls_tls", name = "ClientConnection")]
pub(crate) struct PyClientConnection {
    inner: Mutex<RsClientConnection>,
}

connection_pymethods!(
    PyClientConnection,
    RsClientConnection,
    /// Start a connection to `server_hostname`, queuing the ClientHello.
    ///
    /// Passing `session` resumes the session it names instead, which requires `config` to be the
    /// same object the session was exported from. A resuming connection can be written to
    /// immediately — its keys are installed before the constructor returns.
    #[new]
    #[pyo3(signature = (config, server_hostname, session = None))]
    fn new(
        py: Python<'_>,
        config: &PyClientConfig,
        server_hostname: &str,
        session: Option<PySession>,
    ) -> PyResult<Self> {
        let name = ServerName::try_from(server_hostname.to_owned()).map_err(|_| {
            PyValueError::new_err(format!(
                "{server_hostname:?} is not a valid server name (expected a DNS name or IP address)"
            ))
        })?;
        let config: Arc<mls_tls::ClientConfig> = config.inner.clone();

        // The initial handshake generates a key package, which for the X-Wing suite means ML-KEM
        // key generation — milliseconds, and worth yielding the interpreter for.
        let conn = py
            .detach(move || match session {
                Some(session) => RsClientConnection::resume(config, name, session.inner),
                None => RsClientConnection::new(config, name),
            })
            .map_err(to_py_err)?;

        Ok(Self {
            inner: Mutex::new(conn),
        })
    }
);

/// The responder side of an MLS-TLS connection.
#[pyclass(frozen, module = "mls_tls", name = "ServerConnection")]
pub(crate) struct PyServerConnection {
    inner: Mutex<RsServerConnection>,
}

connection_pymethods!(
    PyServerConnection,
    RsServerConnection,
    /// Start a server connection. Nothing is queued until the client's ClientHello arrives.
    ///
    /// There is no separate acceptor type and no per-role variant for resumption: a resuming client
    /// is recognised from the message it sends, so one server connection handles both.
    #[new]
    fn new(py: Python<'_>, config: &PyServerConfig) -> PyResult<Self> {
        let config: Arc<mls_tls::ServerConfig> = config.inner.clone();
        let conn = py
            .detach(move || RsServerConnection::new(config))
            .map_err(to_py_err)?;
        Ok(Self {
            inner: Mutex::new(conn),
        })
    }
);

/// Compile-time check that both connection types really do expose the shared surface through
/// `Deref`, rather than the macro silently generating methods against the wrong type.
const _: () = {
    const fn assert_derefs<T: std::ops::DerefMut<Target = ConnectionCommon>>() {}
    assert_derefs::<RsClientConnection>();
    assert_derefs::<RsServerConnection>();
};
