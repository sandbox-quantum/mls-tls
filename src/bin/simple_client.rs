//! A minimal blocking MLS-TLS client for interop testing against the Python `e2e_server.py`.
//!
//! Drives the protocol through the public `mls-tls` API — ClientHello, ServerHello (Welcome), then
//! one application-data message each way — plus the Python peer's non-standard opening frame, which
//! is consumed here rather than by the library (see [`interop`]). Usage: `simple_client <port>`.

use std::io::{self, Read, Write};
use std::net::TcpStream;

use mls_tls::{ClientConfig, ClientConnection, ConnectionCommon, ServerName};

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

fn main() -> io::Result<()> {
    let port: u16 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    let mut sock = TcpStream::connect(("127.0.0.1", port))?;
    sock.set_nodelay(true).ok();

    // Python-only opening frame; the library's handshake starts with our ClientHello.
    interop::recv_server_pubkey(&mut sock)?;

    let config = ClientConfig::builder()
        .with_no_certificate_verification()
        .with_generated_basic_credential(b"client")
        .map_err(to_io)?;
    let server_name = ServerName::try_from("localhost").map_err(to_io)?;
    let mut client = ClientConnection::new(config, server_name).map_err(to_io)?;

    complete_handshake(&mut client, &mut sock)?;

    // Application-data exchange (epoch 1): send one, receive one back.
    client
        .writer()
        .write_all(b"Hello from client (rust)!")
        .map_err(to_io)?;
    while client.wants_write() {
        client.write_tls(&mut sock)?;
    }
    sock.flush()?;

    let server_msg = recv_app(&mut client, &mut sock)?;
    println!("CLIENT_RECEIVED: {}", String::from_utf8_lossy(&server_msg));
    Ok(())
}
