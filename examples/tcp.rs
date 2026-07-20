//! TCP demo of the public `mls-tls` API using the blocking `StreamOwned` helper over real sockets.
//! A server thread echoes one message back to the client.
//!
//! Run with: `cargo run --example tcp`

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use mls_tls::{Acceptor, ClientConfig, ClientConnection, ServerConfig, ServerName, StreamOwned};

fn main() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let server_config: Arc<ServerConfig> = ServerConfig::builder()
            .with_no_client_auth()
            .with_generated_basic_credential(b"server")
            .unwrap();

        let (mut sock, _) = listener.accept().unwrap();

        // Read the ClientHello off the socket before committing to a config.
        let mut acceptor = Acceptor::new();
        let accepted = loop {
            if acceptor.read_tls(&mut sock).unwrap() == 0 {
                return; // connection closed
            }
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };
        let conn = accepted.into_connection(server_config).unwrap();

        let mut tls = StreamOwned::new(conn, sock);
        let mut buf = [0u8; 256];
        let n = tls.read(&mut buf).unwrap();
        let msg = String::from_utf8_lossy(&buf[..n]).to_string();
        println!("[server] received: {msg:?}");
        tls.write_all(format!("echo: {msg}").as_bytes()).unwrap();
        tls.flush().unwrap();
    });

    let client_config: Arc<ClientConfig> = ClientConfig::builder()
        .with_no_certificate_verification()
        .with_generated_basic_credential(b"client")
        .unwrap();

    let sock = TcpStream::connect(addr).unwrap();
    let server_name = ServerName::try_from("localhost").unwrap();
    let conn = ClientConnection::new(client_config, server_name).unwrap();

    let mut tls = StreamOwned::new(conn, sock);
    tls.write_all(b"hello over tcp").unwrap();
    tls.flush().unwrap();

    let mut buf = [0u8; 256];
    let n = tls.read(&mut buf).unwrap();
    println!("[client] received: {:?}", String::from_utf8_lossy(&buf[..n]));

    server.join().unwrap();
}
