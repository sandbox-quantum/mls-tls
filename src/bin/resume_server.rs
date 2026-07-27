//! Interop server for resumption. Accepts two sequential connections that share one config (hence
//! one Arc-backed session store): the first is a fresh handshake, the second resumes it. Each
//! connection receives one app-data message and replies with an ack.
//!
//! Usage: `resume_server <port>`.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use mls_tls::{ConnectionCommon, ServerConfig, ServerConnection};

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

fn complete_handshake(conn: &mut ConnectionCommon, sock: &mut TcpStream) -> io::Result<()> {
    while conn.is_handshaking() {
        while conn.wants_write() {
            conn.write_tls(sock)?;
        }
        if !conn.is_handshaking() {
            break;
        }
        conn.read_tls(sock)?;
        conn.process_new_packets().map_err(to_io)?;
    }
    while conn.wants_write() {
        conn.write_tls(sock)?;
    }
    Ok(())
}

fn recv_app(conn: &mut ConnectionCommon, sock: &mut TcpStream) -> io::Result<Vec<u8>> {
    loop {
        conn.read_tls(sock)?;
        conn.process_new_packets().map_err(to_io)?;
        let mut buf = vec![0u8; 8192];
        let n = conn.reader().read(&mut buf)?;
        if n > 0 {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

fn handle(config: Arc<ServerConfig>, sock: &mut TcpStream, ack: &[u8]) -> io::Result<()> {
    let mut server = ServerConnection::new(config).map_err(to_io)?;
    complete_handshake(&mut server, sock)?;
    let msg = recv_app(&mut server, sock)?;
    println!("SERVER_RECEIVED: {}", String::from_utf8_lossy(&msg));
    server.writer().write_all(ack).map_err(to_io)?;
    while server.wants_write() {
        server.write_tls(sock)?;
    }
    sock.flush()
}

fn main() -> io::Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("listening {port}");

    // One config across both connections → shared (Arc-backed) session storage, so the second
    // connection's Resumption can reload the group persisted by the first.
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_generated_basic_credential(b"server")
        .map_err(to_io)?;

    let (mut sock1, _) = listener.accept()?;
    sock1.set_nodelay(true).ok();
    handle(config.clone(), &mut sock1, b"ack1 (rust server)")?;

    let (mut sock2, _) = listener.accept()?;
    sock2.set_nodelay(true).ok();
    handle(config, &mut sock2, b"ack2 (rust server)")?;
    Ok(())
}
