//! A TCP relay that injects a fixed one-way delay, so the same connection code can be measured at
//! several simulated network latencies.
//!
//! [`LatencyProxy::start`] binds a local listener in front of a real server. The client connects to
//! the proxy's address instead of the server's; every byte crossing it is held for `one_way` before
//! being forwarded. Round-trip time is therefore `2 * one_way`.
//!
//! Delay is injected in-process rather than with `dnctl`/`tc netem` so the benchmark needs no
//! privileges and behaves the same on every platform.
//!
//! # What is and is not modelled
//!
//! Modelled: a symmetric one-way delay. **Not** modelled: bandwidth, MTU, loss, reordering, or the
//! TCP handshake — the relay delays payload only, and `connect` is local and undelayed. A figure
//! measured here is the protocol's own round-trip cost, not an end-to-end prediction for a real
//! link.
//!
//! # Threading
//!
//! One acceptor thread, plus a reader and a writer thread per direction, joined by an `mpsc` channel
//! of `(deadline, bytes)`. The reader/writer split is not incidental:
//!
//! * A flight larger than the loopback MSS arrives as several `read` calls. A single
//!   "read, sleep, write" thread would charge `one_way` to each chunk; stamping at arrival and
//!   delivering independently keeps a multi-segment flight at one `one_way`. An X-Wing KeyPackage is
//!   a few KB, so this is the common case, not a corner case.
//! * The piggybacked scenarios leave the client in two `write` calls (control frame, then an
//!   application record). Those are two segments of one logical flight, and stamping at arrival
//!   delivers them microseconds apart rather than a full `one_way` apart.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

/// Anything that can go wrong while running a scenario.
#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    #[error(transparent)]
    Protocol(#[from] mls_tls::Error),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("peer closed before the scenario reached its first application byte")]
    UnexpectedEof,
    #[error("cipher suite {0} is not available in this build — check --suites against --features")]
    UnsupportedSuite(String),
}

/// Bytes in flight, deliverable at `deliver_at`.
struct Segment {
    deliver_at: Instant,
    data: Vec<u8>,
}

/// The one-way delay in nanoseconds, shared with the relay's reader threads so it can be retuned
/// while a connection is live.
type SharedDelay = Arc<AtomicU64>;

/// A local TCP relay in front of `upstream` that delays every byte by a one-way delay.
///
/// Handles exactly one connection — one is constructed per benchmark iteration. Dropping it leaves
/// the worker threads to exit on their own once both sides close.
pub struct LatencyProxy {
    addr: SocketAddr,
    one_way: SharedDelay,
}

impl LatencyProxy {
    /// Bind a relay in front of `upstream`, delaying each direction by `one_way`.
    ///
    /// Returns as soon as the listener is bound, before any client connects, so the caller can
    /// connect to [`addr`](Self::addr) immediately.
    pub fn start(upstream: SocketAddr, one_way: Duration) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let addr = listener.local_addr()?;
        let one_way: SharedDelay = Arc::new(AtomicU64::new(delay_nanos(one_way)));

        let shared = Arc::clone(&one_way);
        thread::spawn(move || {
            // A failure here means the iteration is already doomed; the client's own I/O will
            // report it. Nothing useful can be surfaced from this thread.
            let Ok((downstream, _)) = listener.accept() else {
                return;
            };
            let Ok(upstream) = TcpStream::connect(upstream) else {
                return;
            };
            // Without this, Nagle plus delayed ACK adds up to 40 ms to the small ping-pong flights
            // this benchmark is built out of, swamping the delay being injected.
            downstream.set_nodelay(true).ok();
            upstream.set_nodelay(true).ok();

            relay(&downstream, &upstream, Arc::clone(&shared));
            relay(&upstream, &downstream, shared);
        });

        Ok(Self { addr, one_way })
    }

    /// The address the client should connect to.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Retune the delay, applied to every byte read from now on.
    ///
    /// Lets a scenario set a connection up over a fast link and then measure one operation on a slow
    /// one, which is the only way the mid-session rekey can be timed without paying for its own
    /// untimed handshake at the same latency. Only sound between flights: bytes already stamped keep
    /// their old deadline, so the caller must have quiesced the connection first.
    pub fn set_one_way(&self, one_way: Duration) {
        self.one_way.store(delay_nanos(one_way), Ordering::Relaxed);
    }
}

fn delay_nanos(one_way: Duration) -> u64 {
    u64::try_from(one_way.as_nanos()).expect("a one-way delay under 584 years")
}

/// Spawn the reader/writer pair shuttling `src` → `dst`, delayed by `one_way`.
fn relay(src: &TcpStream, dst: &TcpStream, one_way: SharedDelay) {
    // Cloned handles share the underlying socket, so the reader and writer can own one each.
    let (Ok(src), Ok(dst)) = (src.try_clone(), dst.try_clone()) else {
        return;
    };
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || read_and_stamp(src, tx, one_way));
    thread::spawn(move || sleep_and_write(dst, rx));
}

/// Read from `src`, stamping each chunk with the instant it becomes deliverable.
fn read_and_stamp(mut src: TcpStream, tx: Sender<Segment>, one_way: SharedDelay) {
    let mut buf = [0u8; 16 * 1024];
    loop {
        match src.read(&mut buf) {
            Ok(0) | Err(_) => return, // EOF or error: dropping `tx` shuts the writer down
            Ok(n) => {
                // Re-read per chunk rather than caching, so `set_one_way` takes effect immediately.
                let delay = Duration::from_nanos(one_way.load(Ordering::Relaxed));
                let segment = Segment {
                    deliver_at: Instant::now() + delay,
                    data: buf[..n].to_vec(),
                };
                if tx.send(segment).is_err() {
                    return;
                }
            }
        }
    }
}

/// Forward each chunk once its deadline passes, then propagate EOF.
fn sleep_and_write(mut dst: TcpStream, rx: Receiver<Segment>) {
    for segment in rx {
        sleep_until(segment.deliver_at);
        if dst.write_all(&segment.data).is_err() {
            return;
        }
    }
    // The channel closed, so the source hit EOF: half-close so the peer sees it too.
    dst.shutdown(std::net::Shutdown::Write).ok();
}

/// Block until `deadline`: back off geometrically with `thread::sleep`, then spin the last stretch.
///
/// Getting this right matters more than it looks — the injected delay is the thing being measured,
/// so any bias here lands straight in the results. Two effects pull in opposite directions:
///
/// * A single `thread::sleep(remaining)` overshoots, because macOS coalesces timers with slack
///   proportional to the requested interval. One 25 ms sleep ran ~2.5 ms long per hop, showing up as
///   a `flights` column reading 4.8 where it should read 4.
/// * Slicing the wait into many uniform chunks fixes the slack but accumulates scheduler jitter
///   instead — ~25 wakeups per hop at the top of the sweep drifted several ms the same way.
///
/// Sleeping three quarters of what is left each time avoids both: the requested interval — and so
/// its slack — shrinks geometrically, while the whole wait costs only a handful of wakeups. The last
/// [`SPIN_FLOOR`] is spun, because no sleep is precise at that scale and at `rtt=1ms` a 1 ms error
/// would be a 100 % error.
pub fn sleep_until(deadline: Instant) {
    const SPIN_FLOOR: Duration = Duration::from_millis(2);

    loop {
        let now = Instant::now();
        if now >= deadline {
            return;
        }
        let remaining = deadline - now;
        if remaining <= SPIN_FLOOR {
            std::hint::spin_loop();
        } else {
            thread::sleep(remaining * 3 / 4);
        }
    }
}
