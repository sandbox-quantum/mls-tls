//! An OpenSSL TLS 1.3 baseline for the TTFB benchmark, so `mls-tls` can be compared against a
//! mainstream TLS stack under the *same* latency relay, timing boundaries, and stats.
//!
//! Only the crypto/transport stack under test differs: these scenarios drive OpenSSL's own TLS 1.3
//! (via the `openssl` crate's blocking [`SslStream`]) through the same [`crate::Endpoint`]/relay the
//! mls-tls scenarios use, and return the same t0..t1 `Duration` (excludes TCP connect and setup).
//!
//! Scenario ↔ flight mapping (matched to the mls-tls scenarios so the `flights` column lines up):
//! - `handshake` (4 flights): full TLS 1.3 handshake; the request rides the client's Finished flight.
//! - `key-update` (2 flights): `SSL_key_update` then request/response on the new keys.
//! - `resumption-0rtt` (2 flights): TLS 1.3 early data — the request is sent with the ClientHello.
//! - `resumption-1rtt` (4 flights): PSK resumption *without* early data (replay-safe, but the request
//!   waits for the abbreviated handshake).
//!
//! This module is only compiled under `--features openssl` (the `openssl` crate is unavailable
//! otherwise). Cipher suites map to the closest OpenSSL (group, TLS 1.3 ciphersuite); the X-Wing PQ
//! suite has no OpenSSL equivalent and is skipped (see [`suite_to_openssl`]).

use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::os::raw::{c_int, c_void};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use foreign_types::ForeignTypeRef;
use mls_tls::CipherSuite;
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{
    Ssl, SslContext, SslMethod, SslOptions, SslSession, SslSessionCacheMode, SslStream,
    SslVerifyMode, SslVersion,
};
use openssl::x509::{X509, X509NameBuilder, extension as ext};

use crate::netsim::BenchError;
use crate::{Endpoint, REQUEST, RESPONSE, connect, io_err};

// TLS 1.3 KeyUpdate is not exposed by the `openssl` / `openssl-sys` crates, so bind it directly.
// `SSL_key_update` is exported by libssl (already linked via the `openssl` crate); the signature and
// the `SSL_KEY_UPDATE_REQUESTED` value are from OpenSSL 3.x's <openssl/ssl.h>
// (`int SSL_key_update(SSL *s, int updatetype)`, `SSL_KEY_UPDATE_REQUESTED == 1`). The pointer comes
// from `SslStream::ssl().as_ptr()` (a `*mut SSL`), cast to `*mut c_void` so we need no `openssl-sys`.
unsafe extern "C" {
    fn SSL_key_update(ssl: *mut c_void, updatetype: c_int) -> c_int;
}
const SSL_KEY_UPDATE_REQUESTED: c_int = 1;

/// `SSL_OP_NO_ANTI_REPLAY` (0x0100_0000), not exposed by the crate's `SslOptions`. Disabling
/// anti-replay lets a stateless server accept 0-RTT without a replay cache. (0-RTT is inherently
/// replayable — the standard caveat for this fast path.)
const SSL_OP_NO_ANTI_REPLAY: u64 = 0x0100_0000;

/// The resumption ticket captured by the client's new-session callback.
type SharedSession = Arc<Mutex<Option<SslSession>>>;

/// Map an mls-tls cipher suite to the closest OpenSSL `(groups, TLS 1.3 ciphersuite)`.
///
/// The group is the key-exchange curve; the ciphersuite is the AEAD + transcript hash. Returns `None`
/// for suites the OpenSSL TLS stack has no equivalent for — notably the X-Wing PQ suite, which is
/// deliberately out of scope (a fair PQ comparison would cross crypto backends).
pub(crate) fn suite_to_openssl(cs: CipherSuite) -> Option<(&'static str, &'static str)> {
    // `CipherSuite` is a newtype over its id; comparing the associated consts avoids match-on-const
    // pattern limitations.
    if cs == CipherSuite::P256_AES128 {
        Some(("P-256", "TLS_AES_128_GCM_SHA256"))
    } else if cs == CipherSuite::P384_AES256 {
        Some(("P-384", "TLS_AES_256_GCM_SHA384"))
    } else if cs == CipherSuite::P521_AES256 {
        Some(("P-521", "TLS_AES_256_GCM_SHA384"))
    } else if cs == CipherSuite::CURVE25519_AES128 {
        Some(("X25519", "TLS_AES_128_GCM_SHA256"))
    } else if cs == CipherSuite::CURVE448_AES256 {
        Some(("X448", "TLS_AES_256_GCM_SHA384"))
    } else {
        None
    }
}

fn unsupported(cs: CipherSuite) -> BenchError {
    BenchError::UnsupportedSuite(crate::suite_label(cs))
}

// ---------------------------------------------------------------------------
// Context and certificate setup (all untimed)
// ---------------------------------------------------------------------------

/// A self-signed P-256 leaf valid for `localhost`. Built with the `openssl` crate, mirroring the
/// pattern in `src/pki/openssl_backend.rs` tests. The client verifies nothing (`SslVerifyMode::NONE`,
/// matching mls-tls's `with_no_certificate_verification`), so no CA chain is needed. A P-256 /
/// ECDSA-SHA256 cert is accepted by every TLS 1.3 client regardless of the negotiated AEAD.
fn self_signed() -> (X509, PKey<Private>) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();

    let mut nb = X509NameBuilder::new().unwrap();
    nb.append_entry_by_nid(Nid::COMMONNAME, "localhost").unwrap();
    let name = nb.build();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    b.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
    let san = ext::SubjectAlternativeName::new()
        .dns("localhost")
        .build(&b.x509v3_context(None, None))
        .unwrap();
    b.append_extension(san).unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build(), key)
}

/// Common TLS 1.3-pinned context settings for the given key exchange group + ciphersuite.
fn base_builder(
    method: SslMethod,
    groups: &str,
    ciphersuite: &str,
) -> Result<openssl::ssl::SslContextBuilder, BenchError> {
    let mut b = SslContext::builder(method).map_err(io_err)?;
    b.set_min_proto_version(Some(SslVersion::TLS1_3)).map_err(io_err)?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3)).map_err(io_err)?;
    b.set_groups_list(groups).map_err(io_err)?;
    b.set_ciphersuites(ciphersuite).map_err(io_err)?;
    Ok(b)
}

/// Server context. `resumable` enables session tickets (with early data, for the resumption
/// scenarios) and a session-id context so the server actually reuses resumed sessions; otherwise
/// tickets are disabled so the fresh-handshake scenarios stay clean.
fn server_ctx(groups: &str, ciphersuite: &str, resumable: bool) -> Result<SslContext, BenchError> {
    let (cert, key) = self_signed();
    let mut b = base_builder(SslMethod::tls_server(), groups, ciphersuite)?;
    b.set_certificate(&cert).map_err(io_err)?;
    b.set_private_key(&key).map_err(io_err)?;
    if resumable {
        b.set_num_tickets(2).map_err(io_err)?;
        // Required for the server to reuse resumed sessions.
        b.set_session_id_context(b"mls-tls-ttfb-bench").map_err(io_err)?;
        // Accept 0-RTT early data (used by the resumption-0rtt scenario).
        b.set_max_early_data(u32::MAX).map_err(io_err)?;
        b.set_options(SslOptions::from_bits_retain(SSL_OP_NO_ANTI_REPLAY));
    } else {
        // No NewSessionTicket at all: a fresh handshake should not pay for ticket issuance.
        b.set_num_tickets(0).map_err(io_err)?;
    }
    Ok(b.build())
}

/// Client context. Verifies nothing (matching mls-tls's `with_no_certificate_verification`). When
/// `resumable`, installs a new-session callback that captures the server-issued ticket into the
/// returned slot, and permits sending 0-RTT early data.
fn client_ctx(
    groups: &str,
    ciphersuite: &str,
    resumable: bool,
) -> Result<(SslContext, SharedSession), BenchError> {
    let mut b = base_builder(SslMethod::tls_client(), groups, ciphersuite)?;
    b.set_verify(SslVerifyMode::NONE);
    let slot: SharedSession = Arc::new(Mutex::new(None));
    if resumable {
        b.set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
        b.set_max_early_data(u32::MAX).map_err(io_err)?;
        let sink = Arc::clone(&slot);
        // TLS 1.3 delivers each resumption ticket as a *separate* SSL_SESSION here (not via
        // SSL_get1_session), so this callback is the correct way to obtain a resumable session.
        b.set_new_session_callback(move |_ssl, session| {
            *sink.lock().expect("session slot not poisoned") = Some(session);
        });
    }
    Ok((b.build(), slot))
}

// ---------------------------------------------------------------------------
// Server routine (analog of `crate::serve`)
// ---------------------------------------------------------------------------

/// Accept one connection and echo [`RESPONSE`] to every request until the peer closes.
///
/// With `allow_early_data`, first drain any 0-RTT early data (the piggybacked request) via
/// `read_early_data`, then finish the handshake and answer it, so the response rides the server's
/// first post-handshake flight (keeping 0-RTT resumption at two flights).
fn openssl_serve(listener: TcpListener, ctx: SslContext, allow_early_data: bool) -> io::Result<()> {
    let (sock, _) = listener.accept()?;
    sock.set_nodelay(true)?;
    let mut ssl = Ssl::new(&ctx).map_err(io_err)?;
    // Accept state must be set before `read_early_data` drives the server handshake. (`set_*_state`
    // lives on `SslRef`, reached through `Ssl`.)
    ssl.set_accept_state();
    let mut stream = SslStream::new(ssl, sock).map_err(io_err)?;

    let mut buf = [0u8; 4096];

    if allow_early_data {
        // Read 0-RTT early data. `read_early_data` returns Ok(0) on the FINISH marker; anything before
        // that is an early request. Answer it *inside* the loop with `write_early_data` — the server
        // may interleave 0.5-RTT writes with early-data reads while the handshake is still in progress
        // (per SSL_read_early_data(3)), which sends the response with the server's ServerHello flight
        // without waiting for the client's Finished. That is what keeps 0-RTT resumption at two
        // flights; completing the handshake first (`accept()`) would block for the client Finished and
        // cost an extra round trip.
        loop {
            match stream.read_early_data(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    stream.write_early_data(RESPONSE).map_err(io_err)?;
                    stream.flush()?;
                }
                Err(e) => return Err(io_err(e)),
            }
        }
        stream.accept().map_err(io_err)?; // drain the client Finished, completing the handshake
    } else {
        stream.accept().map_err(io_err)?;
    }

    // Normal request/response loop. Also covers a 0-RTT rejection, where the client's request arrives
    // as ordinary data after the handshake instead of as early data.
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
            Ok(_) => {
                stream.write_all(RESPONSE)?;
                stream.flush()?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Fresh TLS 1.3 handshake, then request → response. Four flights: `connect()` costs one round trip
/// (ClientHello out, server flight in), then the request (riding the client's Finished flight) and the
/// response cost a second.
pub(crate) fn bench_handshake_openssl(
    cs: CipherSuite,
    one_way: Duration,
) -> Result<Duration, BenchError> {
    let (groups, ciphersuite) = suite_to_openssl(cs).ok_or_else(|| unsupported(cs))?;
    let (client, _slot) = client_ctx(groups, ciphersuite, false)?;
    let server = server_ctx(groups, ciphersuite, false)?;
    let endpoint = Endpoint::start(one_way, move |l| openssl_serve(l, server, false))?;
    let sock = connect(endpoint.addr())?;

    let start = Instant::now();
    let ssl = Ssl::new(&client).map_err(io_err)?;
    let mut stream = SslStream::new(ssl, sock).map_err(io_err)?;
    stream.connect().map_err(io_err)?;
    stream.write_all(REQUEST)?;
    stream.flush()?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let elapsed = start.elapsed();

    if n == 0 {
        return Err(BenchError::UnexpectedEof);
    }
    drop(stream);
    endpoint.finish()?;
    Ok(elapsed)
}

/// Mid-session TLS 1.3 KeyUpdate on an established connection, then request → response. Two flights:
/// the request rides the KeyUpdate flight (initiator rekeys its send key immediately), the response
/// rides the peer's answering KeyUpdate. Setup runs over a zero-latency relay and is untimed; the
/// relay is slowed to `one_way` only for the timed rekey (mirrors the mls-tls key-update scenario).
pub(crate) fn bench_key_update_openssl(
    cs: CipherSuite,
    one_way: Duration,
) -> Result<Duration, BenchError> {
    let (groups, ciphersuite) = suite_to_openssl(cs).ok_or_else(|| unsupported(cs))?;
    let (client, _slot) = client_ctx(groups, ciphersuite, false)?;
    let server = server_ctx(groups, ciphersuite, false)?;
    let endpoint = Endpoint::start(Duration::ZERO, move |l| openssl_serve(l, server, false))?;
    let sock = connect(endpoint.addr())?;

    let ssl = Ssl::new(&client).map_err(io_err)?;
    let mut stream = SslStream::new(ssl, sock).map_err(io_err)?;
    stream.connect().map_err(io_err)?;

    // Untimed: reach a settled connection.
    let mut buf = [0u8; 4096];
    stream.write_all(REQUEST)?;
    stream.flush()?;
    if stream.read(&mut buf)? == 0 {
        return Err(BenchError::UnexpectedEof);
    }

    // Both directions are quiesced, so no bytes are in flight carrying the old (zero) deadline.
    endpoint.set_one_way(one_way);

    let start = Instant::now();
    // Schedule a KeyUpdate (with update_requested, so the peer rekeys back). It is emitted on the next
    // write, so the request that follows rides the same flight, encrypted under the new send key.
    let rc = unsafe { SSL_key_update(stream.ssl().as_ptr() as *mut c_void, SSL_KEY_UPDATE_REQUESTED) };
    if rc != 1 {
        return Err(BenchError::Io(io::Error::other("SSL_key_update failed")));
    }
    stream.write_all(REQUEST)?;
    stream.flush()?;
    let n = stream.read(&mut buf)?;
    let elapsed = start.elapsed();

    if n == 0 {
        return Err(BenchError::UnexpectedEof);
    }
    drop(stream);
    endpoint.finish()?;
    Ok(elapsed)
}

/// Establish a connection over a zero-latency relay, exchange once, and capture the server's
/// resumption ticket. Untimed. Returns a resumable [`SslSession`].
///
/// The ticket is captured via the new-session callback (`slot`), then **round-tripped through DER**.
/// This matters: the `SslSession` handed to the callback is not directly usable with `set_session` for
/// TLS 1.3 resumption here (the server silently declines it, falling back to a full handshake);
/// `to_der` → `from_der` yields a clean, standalone session that resumes — exactly what
/// `openssl s_client -sess_out`/`-sess_in` does.
fn establish_and_capture(
    client: &SslContext,
    server: &SslContext,
    slot: &SharedSession,
) -> Result<SslSession, BenchError> {
    let server = server.clone();
    let endpoint = Endpoint::start(Duration::ZERO, move |l| openssl_serve(l, server, false))?;
    let sock = connect(endpoint.addr())?;

    let ssl = Ssl::new(client).map_err(io_err)?;
    let mut stream = SslStream::new(ssl, sock).map_err(io_err)?;
    stream.connect().map_err(io_err)?;
    stream.write_all(REQUEST)?;
    stream.flush()?;
    let mut buf = [0u8; 4096];
    stream.read(&mut buf)?;

    // TLS 1.3 sends the resumption ticket in a NewSessionTicket *after* the handshake, as
    // post-handshake traffic — not in a handshake flight. OpenSSL only fires the new-session callback
    // once the client reads and processes those bytes. OpenSSL 3.x emits it right after the handshake,
    // so it usually arrives with the response above; drain a little more (with a short timeout, off
    // the timed path) until the callback fires. Untimed setup — no measurement impact.
    stream
        .get_ref()
        .set_read_timeout(Some(Duration::from_millis(500)))
        .ok();
    for _ in 0..8 {
        if slot.lock().expect("session slot not poisoned").is_some() {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break, // timed out / would block — nothing more to drain
        }
    }

    let captured = slot
        .lock()
        .expect("session slot not poisoned")
        .take()
        .ok_or_else(|| BenchError::Io(io::Error::other("no resumption ticket captured during setup")))?;
    let der = captured.to_der().map_err(io_err)?;
    let saved = SslSession::from_der(&der).map_err(io_err)?;

    drop(stream);
    endpoint.finish()?;
    Ok(saved)
}

/// Resume an earlier session over a fresh transport using TLS 1.3 0-RTT early data. Two flights: the
/// request goes with the ClientHello as early data, the response with the server's first flight.
pub(crate) fn bench_resumption_0rtt_openssl(
    cs: CipherSuite,
    one_way: Duration,
) -> Result<Duration, BenchError> {
    let (groups, ciphersuite) = suite_to_openssl(cs).ok_or_else(|| unsupported(cs))?;
    let (client, slot) = client_ctx(groups, ciphersuite, true)?;
    // One server context (its ticket key must match between setup and resume) reused for both.
    let server = server_ctx(groups, ciphersuite, true)?;
    let saved = establish_and_capture(&client, &server, &slot)?;

    let resume_server = server.clone();
    let endpoint = Endpoint::start(one_way, move |l| openssl_serve(l, resume_server, true))?;
    let sock = connect(endpoint.addr())?;

    let start = Instant::now();
    let mut ssl = Ssl::new(&client).map_err(io_err)?;
    // SAFETY: `saved` was produced by this same client context (see `set_session` requirements).
    unsafe { ssl.set_session(&saved).map_err(io_err)? };
    // Connect state must be set before `write_early_data` sends the ClientHello.
    ssl.set_connect_state();
    let mut stream = SslStream::new(ssl, sock).map_err(io_err)?;
    stream.write_early_data(REQUEST).map_err(io_err)?; // ClientHello + early request
    stream.do_handshake().map_err(io_err)?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let elapsed = start.elapsed();

    if n == 0 {
        return Err(BenchError::UnexpectedEof);
    }
    drop(stream);
    endpoint.finish()?;
    Ok(elapsed)
}

/// Resume an earlier session over a fresh transport *without* early data (replay-safe). Four flights:
/// PSK resumption still completes the abbreviated handshake before the request goes out, so the
/// request rides the client's Finished flight and the response comes a round trip later.
pub(crate) fn bench_resumption_1rtt_openssl(
    cs: CipherSuite,
    one_way: Duration,
) -> Result<Duration, BenchError> {
    let (groups, ciphersuite) = suite_to_openssl(cs).ok_or_else(|| unsupported(cs))?;
    let (client, slot) = client_ctx(groups, ciphersuite, true)?;
    let server = server_ctx(groups, ciphersuite, true)?;
    let saved = establish_and_capture(&client, &server, &slot)?;

    let resume_server = server.clone();
    let endpoint = Endpoint::start(one_way, move |l| openssl_serve(l, resume_server, false))?;
    let sock = connect(endpoint.addr())?;

    let start = Instant::now();
    let mut ssl = Ssl::new(&client).map_err(io_err)?;
    // SAFETY: `saved` was produced by this same client context.
    unsafe { ssl.set_session(&saved).map_err(io_err)? };
    let mut stream = SslStream::new(ssl, sock).map_err(io_err)?;
    stream.connect().map_err(io_err)?; // abbreviated (PSK) handshake, no early data
    stream.write_all(REQUEST)?;
    stream.flush()?;
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf)?;
    let elapsed = start.elapsed();

    if n == 0 {
        return Err(BenchError::UnexpectedEof);
    }
    drop(stream);
    endpoint.finish()?;
    Ok(elapsed)
}
