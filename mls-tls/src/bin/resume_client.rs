//! Interop client for resumption. Opens a fresh connection, exchanges one message,
//! exports the session, then opens a second connection that RESUMES the first and exchanges another
//! message on the resumed epoch. Both connections reuse one config (shared session store).
//!
//! The Python peer opens each connection with a non-standard public-key frame, consumed here rather
//! than by the library (see [`interop`]). Usage: `resume_client <port>`.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use mls_tls::{ClientConfig, ClientConnection, ConnectionCommon, ResumptionState, ServerName};

#[path = "interop/mod.rs"]
mod interop;

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

fn send_recv(conn: &mut ConnectionCommon, sock: &mut TcpStream, msg: &[u8]) -> io::Result<Vec<u8>> {
    conn.writer().write_all(msg).map_err(to_io)?;
    while conn.wants_write() {
        conn.write_tls(sock)?;
    }
    sock.flush()?;
    recv_app(conn, sock)
}

fn main() -> io::Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let name = ServerName::try_from("localhost").map_err(to_io)?;

    let config: Arc<ClientConfig> = ClientConfig::builder()
        .with_no_certificate_verification()
        .with_generated_basic_credential(b"client")
        .map_err(to_io)?;

    // Connection 1: fresh handshake + app-data, then export the session.
    let resumption: ResumptionState = {
        let mut sock = TcpStream::connect(("127.0.0.1", port))?;
        sock.set_nodelay(true).ok();
        interop::recv_server_pubkey(&mut sock)?;
        let mut client = ClientConnection::new(config.clone(), name.clone()).map_err(to_io)?;
        complete_handshake(&mut client, &mut sock)?;
        let reply = send_recv(&mut client, &mut sock, b"hello1 (rust client)")?;
        println!("CLIENT_RECEIVED_1: {}", String::from_utf8_lossy(&reply));
        client.export_resumption_state().map_err(to_io)?
    };

    // Connection 2: resume over a fresh transport + app-data on the resumed epoch.
    {
        let mut sock = TcpStream::connect(("127.0.0.1", port))?;
        sock.set_nodelay(true).ok();
        interop::recv_server_pubkey(&mut sock)?;
        let mut client = ClientConnection::resume(config, name, resumption).map_err(to_io)?;
        complete_handshake(&mut client, &mut sock)?;
        let reply = send_recv(&mut client, &mut sock, b"hello2 (rust client)")?;
        println!("CLIENT_RECEIVED_2: {}", String::from_utf8_lossy(&reply));
    }
    Ok(())
}
