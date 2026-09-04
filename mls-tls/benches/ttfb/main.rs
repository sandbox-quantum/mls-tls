//! Time to first byte, swept across simulated network latencies.
//!
//! Measures the wall-clock gap between a caller starting an operation and the first application
//! byte coming back from the peer, for the three flows whose cost is dominated by round trips:
//!
//! | scenario | flights | what is timed |
//! |---|---|---|
//! | `handshake` | 4 | `ClientConnection::new` → request → response |
//! | `key-update` | 2 | `refresh_traffic_keys()` → request → response, on an established connection |
//! | `resumption` | 2 | `ClientConnection::resume` → request → response, over a fresh transport |
//!
//! A *flight* is one message (or batch emitted together) crossing the network in one direction, and
//! costs one one-way delay, so N flights = N/2 RTT. Every scenario sends its request at the earliest
//! point the protocol allows: the key update and the resumption both ride in the same flight as the
//! control message that precedes them, which is why they cost one round trip rather than two. The
//! handshake cannot do better than four — before the Welcome the client has no record layer.
//!
//! Latency comes from an in-process TCP relay ([`netsim`]), so no privileges or platform tooling are
//! needed. Because it is real TCP, the figures include socket and syscall cost; because the relay
//! sits in the path at every latency including zero, that cost is a constant across rows rather than
//! a step between them.
//!
//! Reading the output: the `rtt=0` row is compute only, and the `flights` column is
//! `(min − min@rtt=0) / one_way` — the flight count recovered from the measurements. It should land
//! on a whole number; if it does not, the relay or the scenario is wrong. Trust the high-RTT rows
//! for that: at `rtt=1ms` the one-way delay is 500 µs, under the noise floor, so the column scatters
//! either side of the truth there and tightens to within 0.01 by `rtt=3000ms`.
//!
//! The default sweep runs out to a satellite-grade 3 s RTT and takes around four minutes. `--rtt-ms`
//! trims the ladder and `--budget-ms` the samples per cell; both are the fastest ways to shorten it.
//!
//! ```text
//! cargo bench --bench ttfb
//! cargo bench --bench ttfb -- --rtt-ms 0,20,200 --iterations 25
//! cargo bench --bench ttfb -- --scenarios resumption --suites p384 --json
//! ```

use std::io::{self, IsTerminal, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use mls_tls::{
    CipherSuite, ClientConfig, ClientConnection, DEFAULT_CIPHER_SUITE, ServerConfig,
    ServerConnection, ServerName, StreamOwned,
};

#[path = "netsim.rs"]
mod netsim;

// The OpenSSL TLS 1.3 baseline the mls-tls scenarios are compared against. Only available when the
// crate is built with the OpenSSL crypto backend, since it needs the `openssl` crate.
#[cfg(feature = "openssl")]
#[path = "openssl_stack.rs"]
mod openssl_stack;

use netsim::{BenchError, LatencyProxy};

/// Payloads are deliberately small: this measures round trips, not bandwidth.
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: bench.mls-tls\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\n\r\nhi";

// ---------------------------------------------------------------------------
// Peer setup
// ---------------------------------------------------------------------------

/// A matched client/server config pair. Rebuilt per iteration so signature key generation stays
/// outside the timer and no MLS group state leaks between iterations.
struct Peers {
    client: Arc<ClientConfig>,
    server: Arc<ServerConfig>,
}

fn configs(cipher_suite: CipherSuite) -> Result<Peers, BenchError> {
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_cipher_suite(cipher_suite)
        .with_generated_basic_credential(b"bench-server")?;
    let client = ClientConfig::builder()
        .with_no_certificate_verification()
        .with_cipher_suite(cipher_suite)
        .with_generated_basic_credential(b"bench-client")?;
    Ok(Peers { client, server })
}

fn server_name() -> ServerName<'static> {
    ServerName::try_from("localhost").expect("\"localhost\" is a valid server name")
}

fn connect(addr: SocketAddr) -> io::Result<TcpStream> {
    let sock = TcpStream::connect(addr)?;
    sock.set_nodelay(true)?;
    Ok(sock)
}

fn io_err<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// A one-shot server plus the relay standing in front of it. The client connects to
/// [`addr`](Self::addr); the relay forwards to the real listener after the configured delay.
struct Endpoint {
    addr: SocketAddr,
    server: JoinHandle<io::Result<()>>,
    relay: LatencyProxy,
}

impl Endpoint {
    /// Start a server driven by `serve_fn` reachable through a relay delaying each direction by
    /// `one_way`. `serve_fn` owns the accepted-connection loop (see [`serve`] for the mls-tls one and
    /// `openssl_stack::openssl_serve` for the OpenSSL baseline), so the same relay/timing plumbing
    /// fronts either stack.
    fn start(
        one_way: Duration,
        serve_fn: impl FnOnce(TcpListener) -> io::Result<()> + Send + 'static,
    ) -> Result<Self, BenchError> {
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        let upstream = listener.local_addr()?;
        let server = thread::spawn(move || serve_fn(listener));
        let relay = LatencyProxy::start(upstream, one_way)?;
        Ok(Self {
            addr: relay.addr(),
            server,
            relay,
        })
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Retune the relay's delay mid-connection. Only sound while the connection is quiesced.
    fn set_one_way(&self, one_way: Duration) {
        self.relay.set_one_way(one_way);
    }

    /// Wait for the server to finish. Call after dropping the client socket, which is what closes
    /// the connection and lets the server's read loop return.
    fn finish(self) -> Result<(), BenchError> {
        self.server.join().expect("server thread panicked")?;
        Ok(())
    }
}

/// The server side of every scenario: accept one connection, then echo a canned response to each
/// request until the peer goes away.
///
/// Uses the shipped [`StreamOwned`], which needs no special handling for the piggybacked scenarios:
/// when a `[control frame | application record]` pair arrives in a single read, `complete_io`
/// finishes the handshake and the plaintext is already buffered, so `wants_read()` is false and the
/// request is returned straight away.
fn serve(listener: TcpListener, config: Arc<ServerConfig>) -> io::Result<()> {
    let (sock, _) = listener.accept()?;
    sock.set_nodelay(true)?;
    let conn = ServerConnection::new(config).map_err(io_err)?;
    let mut tls = StreamOwned::new(conn, sock);

    let mut buf = [0u8; 4096];
    loop {
        match tls.read(&mut buf) {
            Ok(0) => return Ok(()),
            // `Stream::read` reports a closed peer as `UnexpectedEof` rather than `Ok(0)`.
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
            Ok(_) => {
                tls.write_all(RESPONSE)?;
                tls.flush()?;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

type ScenarioFn = fn(CipherSuite, Duration) -> Result<Duration, BenchError>;

/// A protocol stack under test, and the scenarios it can run. Both stacks are driven through the same
/// relay and timing plumbing, so their rows are directly comparable.
struct Stack {
    name: &'static str,
    scenarios: &'static [(&'static str, ScenarioFn)],
    /// Whether this stack can serve `cipher_suite` in this build.
    supports: fn(CipherSuite) -> bool,
}

/// mls-tls scenarios (see the module docs for flight counts).
const MLS_SCENARIOS: &[(&str, ScenarioFn)] = &[
    ("handshake", bench_handshake),
    ("key-update", bench_key_update),
    ("resumption", bench_resumption),
];

/// OpenSSL TLS 1.3 baseline scenarios. Resumption is split into 0-RTT (early data, two flights) and
/// 1-RTT (replay-safe, four flights) so both sides of that trade-off are visible next to mls-tls's
/// single two-flight resumption.
#[cfg(feature = "openssl")]
const OPENSSL_SCENARIOS: &[(&str, ScenarioFn)] = &[
    ("handshake", openssl_stack::bench_handshake_openssl),
    ("key-update", openssl_stack::bench_key_update_openssl),
    ("resumption-0rtt", openssl_stack::bench_resumption_0rtt_openssl),
    ("resumption-1rtt", openssl_stack::bench_resumption_1rtt_openssl),
];

/// Stack names selectable with `--stacks`. `openssl` is only *available* under `--features openssl`
/// (see [`available_stacks`]); it is listed here so `--stacks openssl` on a rustcrypto build fails
/// with a clear message rather than "unknown value".
const ALL_STACK_NAMES: &[&str] = &["mls-tls", "openssl"];

/// Every scenario label across all stacks, in display order — used to validate `--scenarios` and to
/// group the output so the same scenario sits together across stacks.
const ALL_SCENARIOS: &[&str] = &[
    "handshake",
    "key-update",
    "resumption",
    "resumption-0rtt",
    "resumption-1rtt",
];

/// The stacks this build can actually run: mls-tls always, plus the OpenSSL baseline under
/// `--features openssl`.
fn available_stacks() -> Vec<Stack> {
    // `mut` is only needed when the openssl push below is compiled in.
    #[cfg_attr(not(feature = "openssl"), allow(unused_mut))]
    let mut stacks = vec![Stack {
        name: "mls-tls",
        scenarios: MLS_SCENARIOS,
        supports: |cs| configs(cs).is_ok(),
    }];
    #[cfg(feature = "openssl")]
    stacks.push(Stack {
        name: "openssl",
        scenarios: OPENSSL_SCENARIOS,
        supports: |cs| openssl_stack::suite_to_openssl(cs).is_some(),
    });
    stacks
}

/// Fresh connection: `ClientConnection::new` (which generates the KeyPackage and queues the
/// ClientHello) through to the first response byte. Four flights.
fn bench_handshake(cipher_suite: CipherSuite, one_way: Duration) -> Result<Duration, BenchError> {
    let peers = configs(cipher_suite)?;
    let endpoint = Endpoint::start(one_way, move |l| serve(l, peers.server))?;
    let sock = connect(endpoint.addr())?;

    let start = Instant::now();
    let conn = ClientConnection::new(peers.client, server_name())?;
    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(REQUEST)?;
    let mut buf = [0u8; 4096];
    let n = tls.read(&mut buf)?;
    let elapsed = start.elapsed();

    if n == 0 {
        return Err(BenchError::UnexpectedEof);
    }
    drop(tls);
    endpoint.finish()?;
    Ok(elapsed)
}

/// Mid-session rekey on an established connection. Two flights: the request rides with the
/// `ConnectionUpdate` (the initiator installs its new send key before the update is emitted) and the
/// response rides back with the `EpochKeyUpdate`.
///
/// `StreamOwned` needs no bypass here — once established, `complete_io` only flushes, so the
/// `ConnectionUpdate` and the record go out back to back with no read between them.
fn bench_key_update(cipher_suite: CipherSuite, one_way: Duration) -> Result<Duration, BenchError> {
    let peers = configs(cipher_suite)?;
    // The rekey needs a live transport, so the connection cannot simply be set up against a
    // different endpoint the way resumption's can. Instead the relay starts fast and is slowed down
    // once the connection has settled, which keeps the untimed setup off the clock entirely — at
    // rtt=3s that is the difference between 9 s and 3 s per iteration.
    let endpoint = Endpoint::start(Duration::ZERO, move |l| serve(l, peers.server))?;
    let sock = connect(endpoint.addr())?;
    let conn = ClientConnection::new(peers.client, server_name())?;
    let mut tls = StreamOwned::new(conn, sock);

    // Untimed: reach a settled connection.
    let mut buf = [0u8; 4096];
    tls.write_all(REQUEST)?;
    if tls.read(&mut buf)? == 0 {
        return Err(BenchError::UnexpectedEof);
    }

    // Both directions are quiesced here — the exchange above completed — so no bytes are in flight
    // carrying a stale deadline.
    endpoint.set_one_way(one_way);

    let start = Instant::now();
    tls.conn.refresh_traffic_keys()?;
    tls.write_all(REQUEST)?;
    let n = tls.read(&mut buf)?;
    let elapsed = start.elapsed();

    if n == 0 {
        return Err(BenchError::UnexpectedEof);
    }
    drop(tls);
    endpoint.finish()?;
    Ok(elapsed)
}

/// Resuming an earlier session over a fresh transport. Two flights: the request rides with the
/// Resumption envelope, the response with the `ConnectionConfirmation`.
///
/// The setup connection runs over a zero-latency relay so only the resumption itself is charged the
/// configured delay.
fn bench_resumption(cipher_suite: CipherSuite, one_way: Duration) -> Result<Duration, BenchError> {
    let peers = configs(cipher_suite)?;

    // Untimed: establish, exchange once, and persist the group.
    let resumption = {
        let server = peers.server.clone();
        let endpoint = Endpoint::start(Duration::ZERO, move |l| serve(l, server))?;
        let sock = connect(endpoint.addr())?;
        let conn = ClientConnection::new(peers.client.clone(), server_name())?;
        let mut tls = StreamOwned::new(conn, sock);
        let mut buf = [0u8; 4096];
        tls.write_all(REQUEST)?;
        if tls.read(&mut buf)? == 0 {
            return Err(BenchError::UnexpectedEof);
        }
        let state = tls.conn.export_resumption_state()?;
        drop(tls);
        endpoint.finish()?;
        state
    };

    // The configs are shared with the setup connection, so both sides can reload the group from
    // their (Arc-backed) session stores.
    let endpoint = Endpoint::start(one_way, move |l| serve(l, peers.server))?;
    let mut sock = connect(endpoint.addr())?;

    let start = Instant::now();
    let mut conn = ClientConnection::resume(peers.client, server_name(), resumption)?;
    // Send before the ConnectionConfirmation arrives: `resume` has already merged the self-update
    // commit and built the record layer at the new epoch, and encryption is gated on the record
    // layer alone, not on the handshake state. This is what makes the scenario two flights instead
    // of four — `StreamOwned` cannot express it, because `complete_io` waits out the handshake.
    conn.writer().write_all(REQUEST)?;
    flush_tls(&mut conn, &mut sock)?;

    let mut buf = [0u8; 4096];
    loop {
        if conn.read_tls(&mut sock)? == 0 {
            return Err(BenchError::UnexpectedEof);
        }
        conn.process_new_packets()?;
        flush_tls(&mut conn, &mut sock)?;
        if conn.reader().read(&mut buf)? > 0 {
            break;
        }
    }
    let elapsed = start.elapsed();

    drop(sock);
    endpoint.finish()?;
    Ok(elapsed)
}

/// Push everything the connection has buffered out to the socket.
fn flush_tls(conn: &mut ClientConnection, sock: &mut TcpStream) -> io::Result<()> {
    while conn.wants_write() {
        if conn.write_tls(sock)? == 0 {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Cipher suites
// ---------------------------------------------------------------------------

/// Suites selectable with `--suites`, and the labels they print under.
///
/// `default` resolves to whatever the compiled backend defaults to, then reports under that suite's
/// own label — so under `rustcrypto` it collapses onto `xwing`, and under `openssl` onto `p384`.
const SUITES: &[(&str, CipherSuite)] = &[
    ("xwing", mls_tls::MLS_256_XWING_AES256GCM_SHA512_P384),
    ("p256", CipherSuite::P256_AES128),
    ("p384", CipherSuite::P384_AES256),
    ("p521", CipherSuite::P521_AES256),
    ("x25519", CipherSuite::CURVE25519_AES128),
    ("x448", CipherSuite::CURVE448_AES256),
];

fn suite_by_name(name: &str) -> Option<CipherSuite> {
    if name == "default" {
        return Some(DEFAULT_CIPHER_SUITE);
    }
    SUITES
        .iter()
        .find(|(label, _)| *label == name)
        .map(|(_, suite)| *suite)
}

fn suite_label(cipher_suite: CipherSuite) -> String {
    SUITES
        .iter()
        .find(|(_, suite)| *suite == cipher_suite)
        .map(|(label, _)| (*label).to_string())
        .unwrap_or_else(|| format!("0x{:04x}", u16::from(cipher_suite)))
}

// ---------------------------------------------------------------------------
// Statistics and reporting
// ---------------------------------------------------------------------------

/// One (stack, suite, scenario, rtt) cell: the sorted sample set plus what it took to produce.
struct Row {
    stack: &'static str,
    suite: String,
    scenario: &'static str,
    rtt_ms: f64,
    /// Ascending.
    samples: Vec<Duration>,
}

impl Row {
    fn percentile(&self, p: f64) -> f64 {
        let idx = ((p / 100.0) * (self.samples.len() - 1) as f64).round() as usize;
        ms(self.samples[idx])
    }

    fn min(&self) -> f64 {
        ms(self.samples[0])
    }

    fn max(&self) -> f64 {
        ms(self.samples[self.samples.len() - 1])
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Flights recovered from the measurements: `(min − min@rtt=0) / one_way`.
///
/// Taken from the minimum rather than the median on purpose. Every source of error here — scheduler
/// preemption, a busy machine, timer slack — only ever *adds* time, so the fastest sample is the
/// least contaminated estimate of the protocol's actual cost. Measured on a loaded laptop, the
/// medians drifted several ms while the minima stayed within 1 ms of theory, which is the difference
/// between this column reading 4.27 and reading 4.02.
///
/// `None` on the baseline row itself, and whenever the sweep contains no `rtt=0` row to subtract.
fn flights(row: &Row, rows: &[Row]) -> Option<f64> {
    if row.rtt_ms == 0.0 {
        return None;
    }
    let baseline = rows.iter().find(|r| {
        r.stack == row.stack && r.suite == row.suite && r.scenario == row.scenario && r.rtt_ms == 0.0
    })?;
    Some((row.min() - baseline.min()) / (row.rtt_ms / 2.0))
}

fn report_text(rows: &[Row], args: &Args) {
    println!("mls-tls TTFB benchmark");
    println!(
        "mls-tls crypto backend: {}   request: {} B   response: {} B",
        backend_name(),
        REQUEST.len(),
        RESPONSE.len(),
    );
    println!(
        "iterations: {}..{} per cell within a {:.1}s budget (column n)   warmup: {} per scenario",
        args.min_iterations,
        args.iterations,
        args.budget.as_secs_f64(),
        args.warmup,
    );
    println!("transport: loopback TCP through a delaying relay (TCP_NODELAY)");
    println!("excluded from t0..t1: TCP setup, config build, per-scenario setup phases");
    println!();
    println!(
        "{:<8} {:<8} {:<15} {:>7} {:>3} {:>9} {:>9} {:>9} {:>9} {:>9}",
        "stack", "suite", "scenario", "rtt", "n", "min", "p50", "p90", "max", "flights",
    );
    for row in rows {
        let flights = match flights(row, rows) {
            Some(f) => format!("{f:.2}"),
            None => "—".to_string(),
        };
        println!(
            "{:<8} {:<8} {:<15} {:>7} {:>3} {:>9.3} {:>9.3} {:>9.3} {:>9.3} {:>9}",
            row.stack,
            row.suite,
            row.scenario,
            format_rtt(row.rtt_ms),
            row.samples.len(),
            row.min(),
            row.percentile(50.0),
            row.percentile(90.0),
            row.max(),
            flights,
        );
    }
    println!();
    println!(
        "all times in ms; flights = (min − min@rtt=0) / (rtt/2), \
         taken from the minima since noise only ever adds"
    );
}

/// Render an RTT without a trailing `.0`, so the column stays narrow at `3000ms`.
fn format_rtt(rtt_ms: f64) -> String {
    if rtt_ms.fract() == 0.0 {
        format!("{}ms", rtt_ms as i64)
    } else {
        format!("{rtt_ms}ms")
    }
}

fn report_json(rows: &[Row], args: &Args) {
    let measurements: Vec<_> = rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "stack": row.stack,
                "suite": row.suite,
                "scenario": row.scenario,
                "rtt_ms": row.rtt_ms,
                "iterations": row.samples.len(),
                "min_ms": row.min(),
                "p50_ms": row.percentile(50.0),
                "p90_ms": row.percentile(90.0),
                "max_ms": row.max(),
                "flights": flights(row, rows),
                "samples_ms": row.samples.iter().copied().map(ms).collect::<Vec<_>>(),
            })
        })
        .collect();
    let doc = serde_json::json!({
        "backend": backend_name(),
        "max_iterations": args.iterations,
        "min_iterations": args.min_iterations,
        "budget_ms": args.budget.as_secs_f64() * 1000.0,
        "warmup": args.warmup,
        "request_bytes": REQUEST.len(),
        "response_bytes": RESPONSE.len(),
        "measurements": measurements,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&doc).expect("serialisable")
    );
}

fn backend_name() -> &'static str {
    #[cfg(feature = "openssl")]
    return "openssl";
    #[cfg(feature = "rustcrypto")]
    return "rustcrypto";
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE: &str = "\
mls-tls time-to-first-byte benchmark

    cargo bench --bench ttfb -- [options]

    --rtt-ms <list>      round-trip times to sweep, ms
                         (default 0,1,10,50,100,250,500,1000,2000,3000).
                         One-way delay is half of each; 0 measures compute only.
    --iterations <n>     most measured iterations per cell (default 10)
    --min-iterations <n> fewest, even when over budget (default 3)
    --budget-ms <n>      wall-clock target per cell (default 5000). Cells cheaper
                         than this run the full --iterations; slow ones run fewer,
                         down to --min-iterations. The `n` column reports which.
    --warmup <n>         discarded iterations, once per stack+suite+scenario (default 2)
    --stacks <list>      mls-tls, openssl (default: all available; openssl needs
                         --features openssl). The openssl stack is the OpenSSL
                         TLS 1.3 baseline mls-tls is compared against.
    --scenarios <list>   handshake, key-update, resumption (mls-tls),
                         resumption-0rtt, resumption-1rtt (openssl) (default: all)
    --suites <list>      default, xwing, p256, p384, p521, x25519, x448
                         (default: default,p384; duplicates collapse). Suites a
                         stack cannot serve are skipped for that stack.
    --json               machine-readable output
    --help               this text";

struct Args {
    rtt_ms: Vec<f64>,
    iterations: usize,
    min_iterations: usize,
    budget: Duration,
    warmup: usize,
    /// Scenario labels to run; empty means all. Filtered per stack (a stack skips labels it lacks).
    scenarios: Vec<String>,
    /// Stack names to run; empty means all available.
    stacks: Vec<String>,
    suites: Vec<CipherSuite>,
    json: bool,
}

impl Default for Args {
    fn default() -> Self {
        let mut args = Self {
            // Roughly logarithmic, from "no network" out to a satellite-grade 3 s. The top end is
            // where the protocol's flight count is all that matters and the cipher suite stops
            // showing at all.
            rtt_ms: vec![
                0.0, 1.0, 10.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 2000.0, 3000.0,
            ],
            iterations: 10,
            min_iterations: 3,
            budget: Duration::from_secs(5),
            warmup: 2,
            scenarios: Vec::new(),
            stacks: Vec::new(),
            suites: vec![DEFAULT_CIPHER_SUITE, CipherSuite::P384_AES256],
            json: false,
        };
        // An unoptimized build spends so long in crypto that the wire time barely shows, so a full
        // sweep would be both slow and meaningless. This is also how `cargo test --benches` invokes
        // the binary: `harness = false` means cargo passes no arguments at all, so there is no flag
        // to key off. Explicit options still override.
        if cfg!(debug_assertions) {
            args.smoke();
        }
        args
    }
}

impl Args {
    /// Enough to prove the harness runs end to end, not enough to measure anything.
    fn smoke(&mut self) {
        self.rtt_ms = vec![0.0];
        self.iterations = 1;
        self.min_iterations = 1;
        self.warmup = 0;
    }

    /// An empty filter means "all".
    fn wants_scenario(&self, label: &str) -> bool {
        self.scenarios.is_empty() || self.scenarios.iter().any(|s| s == label)
    }

    fn wants_stack(&self, name: &str) -> bool {
        self.stacks.is_empty() || self.stacks.iter().any(|s| s == name)
    }
}

impl Args {
    fn parse(argv: &[String]) -> Result<Option<Self>, String> {
        let mut args = Self::default();
        let mut iter = argv.iter().peekable();

        while let Some(arg) = iter.next() {
            let mut value = || {
                iter.next()
                    .cloned()
                    .ok_or_else(|| format!("{arg} needs a value"))
            };
            match arg.as_str() {
                "--help" | "-h" => {
                    println!("{USAGE}");
                    return Ok(None);
                }
                "--json" => args.json = true,
                "--rtt-ms" => args.rtt_ms = parse_list(&value()?, |s| s.parse::<f64>().ok())?,
                "--iterations" => {
                    args.iterations = value()?
                        .parse()
                        .map_err(|_| "--iterations needs a number".to_string())?;
                }
                "--min-iterations" => {
                    args.min_iterations = value()?
                        .parse()
                        .map_err(|_| "--min-iterations needs a number".to_string())?;
                }
                "--budget-ms" => {
                    let ms: f64 = value()?
                        .parse()
                        .map_err(|_| "--budget-ms needs a number".to_string())?;
                    args.budget = Duration::from_secs_f64(ms / 1000.0);
                }
                "--warmup" => {
                    args.warmup = value()?
                        .parse()
                        .map_err(|_| "--warmup needs a number".to_string())?;
                }
                "--scenarios" => {
                    args.scenarios = parse_list(&value()?, |s| {
                        ALL_SCENARIOS.contains(&s).then(|| s.to_string())
                    })?;
                }
                "--stacks" => {
                    args.stacks = parse_list(&value()?, |s| {
                        ALL_STACK_NAMES.contains(&s).then(|| s.to_string())
                    })?;
                }
                "--suites" => args.suites = parse_list(&value()?, suite_by_name)?,
                // `cargo bench` passes `--bench`, `cargo test --benches` passes `--test`, and both
                // may add libtest flags we have no use for. Warn rather than fail, so the benchmark
                // stays runnable through cargo while typos are still visible.
                "--bench" => {}
                "--test" => args.smoke(),
                other => eprintln!("warning: ignoring unrecognised argument {other:?}"),
            }
        }

        if args.iterations == 0 || args.min_iterations == 0 {
            return Err("iteration counts must be at least 1".to_string());
        }
        // A floor above the ceiling would silently win; make the ceiling authoritative instead.
        args.min_iterations = args.min_iterations.min(args.iterations);
        if args.rtt_ms.iter().any(|rtt| *rtt < 0.0) {
            return Err("--rtt-ms values must not be negative".to_string());
        }
        // Collapse duplicates while keeping the requested order. `default` resolves to a concrete
        // suite, so `default,p384` is a single row under the `openssl` backend and two under
        // `rustcrypto` — and the pair need not be adjacent for that to hold.
        let mut seen = Vec::new();
        args.suites.retain(|suite| {
            let fresh = !seen.contains(suite);
            if fresh {
                seen.push(*suite);
            }
            fresh
        });
        Ok(Some(args))
    }
}

/// Split a comma-separated list and map each element, failing on the first unrecognised one.
fn parse_list<T>(raw: &str, mut map: impl FnMut(&str) -> Option<T>) -> Result<Vec<T>, String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| map(s).ok_or_else(|| format!("unrecognised value {s:?}")))
        .collect()
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// How many iterations of a cell fit the wall-clock budget, given what one costs.
///
/// Clamped to `[--min-iterations, --iterations]`: the floor keeps percentiles meaningful even when a
/// single iteration blows the budget on its own, and the ceiling stops cheap cells running forever.
fn affordable_iterations(per_iteration: Duration, args: &Args) -> usize {
    let each = per_iteration.as_secs_f64().max(f64::EPSILON);
    let affordable = (args.budget.as_secs_f64() / each).floor();
    // `as usize` saturates, so an enormous ratio lands on the ceiling rather than wrapping.
    (affordable as usize).clamp(args.min_iterations, args.iterations)
}

fn run(args: &Args) -> Result<(), BenchError> {
    if cfg!(debug_assertions) {
        eprintln!(
            "warning: unoptimized build — these timings are dominated by unoptimized crypto and \
             mean nothing. Measure with `cargo bench --bench ttfb`."
        );
    }
    let stacks = available_stacks();
    // A requested stack that this build doesn't have (e.g. `openssl` on a rustcrypto build) should
    // fail loudly, not silently produce no rows.
    for name in &args.stacks {
        if !stacks.iter().any(|s| s.name == *name) {
            return Err(BenchError::UnsupportedStack(name.clone()));
        }
    }
    let selected: Vec<&Stack> = stacks.iter().filter(|s| args.wants_stack(s.name)).collect();

    // Note any (stack, suite) a stack can't serve — X-Wing has no OpenSSL row, and no suite runs on a
    // stack whose backend lacks it — so a mismatched `--suites`/`--stacks`/`--features` is visible
    // rather than quietly yielding fewer rows.
    for stack in &selected {
        for cipher_suite in &args.suites {
            if !(stack.supports)(*cipher_suite) {
                eprintln!(
                    "note: the {} stack cannot serve suite {}; skipping those cells",
                    stack.name,
                    suite_label(*cipher_suite),
                );
            }
        }
    }

    let mut rows = Vec::new();
    // A sweep takes tens of seconds, so show where it is — but only when someone is watching, since
    // the carriage returns turn into noise once stderr is redirected.
    let progress = io::stderr().is_terminal();

    // Grouped suite → scenario → stack → rtt, so the same (suite, scenario) sits together across
    // stacks and the comparison reads down the page.
    for cipher_suite in &args.suites {
        let label = suite_label(*cipher_suite);
        for scenario in ALL_SCENARIOS.iter().copied().filter(|l| args.wants_scenario(l)) {
            for stack in &selected {
                if !(stack.supports)(*cipher_suite) {
                    continue;
                }
                let Some(bench) = stack
                    .scenarios
                    .iter()
                    .find(|(l, _)| *l == scenario)
                    .map(|(_, b)| *b)
                else {
                    continue; // this stack does not have this scenario
                };

                for (index, rtt_ms) in args.rtt_ms.iter().enumerate() {
                    let one_way = Duration::from_secs_f64(rtt_ms / 2000.0);
                    if progress {
                        eprint!("\r{:<8} {label:<8} {scenario:<15} rtt={rtt_ms}ms          ", stack.name);
                    }

                    // Warm up once per stack+suite+scenario rather than per cell. What warmup is for
                    // here is process-wide state — allocator growth, page faults, lazily initialised
                    // crypto — none of which is per-RTT, and at the top of the sweep a discarded
                    // iteration costs seconds.
                    if index == 0 {
                        for _ in 0..args.warmup {
                            bench(*cipher_suite, one_way)?;
                        }
                    }

                    // Take one sample, then let its cost decide how many more to afford. A 3 s RTT
                    // handshake is 6 s an iteration, so a fixed count would put the sweep in the tens
                    // of minutes; the flights are also far more precisely resolved there, so fewer
                    // samples buy just as much confidence.
                    let mut samples = Vec::with_capacity(args.iterations);
                    samples.push(bench(*cipher_suite, one_way)?);
                    let target = affordable_iterations(samples[0], args);
                    while samples.len() < target {
                        samples.push(bench(*cipher_suite, one_way)?);
                    }
                    samples.sort_unstable();

                    rows.push(Row {
                        stack: stack.name,
                        suite: label.clone(),
                        scenario,
                        rtt_ms: *rtt_ms,
                        samples,
                    });
                }
            }
        }
    }
    if progress {
        eprintln!("\r{:<60}", "");
    }

    if rows.is_empty() {
        return Err(BenchError::Io(io::Error::other(
            "no (stack, suite, scenario) cells to run — check --stacks/--suites/--scenarios against the build",
        )));
    }

    if args.json {
        report_json(&rows, args);
    } else {
        report_text(&rows, args);
    }
    Ok(())
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse(&argv) {
        Ok(Some(args)) => args,
        Ok(None) => return,
        Err(message) => {
            eprintln!("error: {message}\n\n{USAGE}");
            std::process::exit(2);
        }
    };

    if let Err(e) = run(&args) {
        eprintln!("benchmark failed: {e}");
        std::process::exit(1);
    }
}
