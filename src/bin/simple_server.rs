//! A minimal blocking MLS-TLS server for interop testing against the Python `e2e_client.py`.
//!
//! Speaks the Python wire protocol via the public `mls-tls` API: sends its signing public key,
//! receives the ClientHello, sends the ServerHello (Welcome), then exchanges one application-data
//! message. Usage: `simple_server <port>`.

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

use mls_tls::{ConnectionCommon, ServerConfig, ServerConnection};

fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Drive the handshake to completion over a blocking socket, then flush any queued output.
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

/// Receive one application-data message.
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

    let listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("listening {port}");

    let (mut sock, _) = listener.accept()?;
    sock.set_nodelay(true).ok();

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_generated_basic_credential(b"server")
        .map_err(to_io)?;
    let mut server = ServerConnection::new(config).map_err(to_io)?;

    complete_handshake(&mut server, &mut sock)?;

    // Application-data exchange (epoch 1): receive one, send one back.
    let client_msg = recv_app(&mut server, &mut sock)?;
    println!("SERVER_RECEIVED: {}", String::from_utf8_lossy(&client_msg));

    server
        .writer()
        .write_all(b"Hello from server (rust)!")
        .map_err(to_io)?;
    while server.wants_write() {
        server.write_tls(&mut sock)?;
    }
    sock.flush()?;
    Ok(())
}
