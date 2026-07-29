//! Interop peer that exercises a mid-session rekey (ConnectionUpdate / EpochKeyUpdate) over the
//! wire. The client initiates the rekey; the server responds automatically inside its receive loop.
//! Whichever role it plays, it also handles the Python peer's non-standard opening frame, which the
//! library does not implement (see [`interop`]).
//!
//!   rekey_peer client <port>   # send msg1, recv ack1, rekey, send msg2 (epoch 2), recv ack2
//!   rekey_peer server <port>   # recv msg1, ack1, recv msg2 (auto-processing the rekey), ack2

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

use mls_tls::{
    BasicCredential, ClientConfig, ClientConnection, ConnectionCommon, DEFAULT_CIPHER_SUITE,
    ServerConfig, ServerConnection, ServerName, SigningIdentity, generate_signature_key,
};

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

fn flush(conn: &mut ConnectionCommon, sock: &mut TcpStream) -> io::Result<()> {
    while conn.wants_write() {
        conn.write_tls(sock)?;
    }
    sock.flush()
}

fn send(conn: &mut ConnectionCommon, sock: &mut TcpStream, msg: &[u8]) -> io::Result<()> {
    conn.writer().write_all(msg).map_err(to_io)?;
    flush(conn, sock)
}

/// Receive one app-data message, flushing any control replies (e.g. EpochKeyUpdate) queued while
/// processing inbound signaling.
fn recv_app(conn: &mut ConnectionCommon, sock: &mut TcpStream) -> io::Result<Vec<u8>> {
    loop {
        conn.read_tls(sock)?;
        conn.process_new_packets().map_err(to_io)?;
        flush(conn, sock)?;
        let mut buf = vec![0u8; 8192];
        let n = conn.reader().read(&mut buf)?;
        if n > 0 {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

fn run_client(port: u16) -> io::Result<()> {
    let mut sock = TcpStream::connect(("127.0.0.1", port))?;
    sock.set_nodelay(true).ok();
    // Python-only opening frame; the library's handshake starts with our ClientHello.
    interop::recv_server_pubkey(&mut sock)?;
    let config = ClientConfig::builder()
        .with_no_certificate_verification()
        .with_generated_basic_credential(b"client")
        .map_err(to_io)?;
    let mut client =
        ClientConnection::new(config, ServerName::try_from("localhost").map_err(to_io)?)
            .map_err(to_io)?;
    complete_handshake(&mut client, &mut sock)?;

    send(&mut client, &mut sock, b"rekey1 (rust client)")?;
    let ack1 = recv_app(&mut client, &mut sock)?;
    println!("CLIENT_RECEIVED_1: {}", String::from_utf8_lossy(&ack1));

    // Initiate the rekey: this queues a ConnectionUpdate and rolls our send key to the new epoch.
    client.refresh_traffic_keys().map_err(to_io)?;
    flush(&mut client, &mut sock)?;

    send(&mut client, &mut sock, b"rekey2 (rust client)")?;
    let ack2 = recv_app(&mut client, &mut sock)?;
    println!("CLIENT_RECEIVED_2: {}", String::from_utf8_lossy(&ack2));
    Ok(())
}

fn run_server(port: u16) -> io::Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    eprintln!("listening {port}");
    // Keep the keypair rather than using `with_generated_basic_credential`: the Python peer expects
    // the public half in the opening frame below.
    let (signer, public) = generate_signature_key(DEFAULT_CIPHER_SUITE).map_err(to_io)?;
    let identity = SigningIdentity::new(
        BasicCredential::new(b"server".to_vec()).into_credential(),
        public.clone(),
    );
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_server_credential(identity, signer);

    let (mut sock, _) = listener.accept()?;
    sock.set_nodelay(true).ok();
    // Python-only opening frame; the library's handshake starts with the peer's ClientHello.
    interop::send_server_pubkey(&mut sock, &public)?;

    let mut server = ServerConnection::new(config).map_err(to_io)?;
    complete_handshake(&mut server, &mut sock)?;

    let msg1 = recv_app(&mut server, &mut sock)?;
    println!("SERVER_RECEIVED: {}", String::from_utf8_lossy(&msg1));
    send(&mut server, &mut sock, b"ack1 (rust server)")?;

    // The rekey (ConnectionUpdate) is processed automatically inside this receive.
    let msg2 = recv_app(&mut server, &mut sock)?;
    println!("SERVER_RECEIVED: {}", String::from_utf8_lossy(&msg2));
    send(&mut server, &mut sock, b"ack2 (rust server)")?;
    Ok(())
}

fn main() -> io::Result<()> {
    let role = std::env::args().nth(1).unwrap_or_default();
    let port: u16 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    match role.as_str() {
        "client" => run_client(port),
        "server" => run_server(port),
        other => Err(io::Error::other(format!("unknown role {other}"))),
    }
}
