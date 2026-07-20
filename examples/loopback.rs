//! In-memory loopback demo of the public `mls-tls` API: handshake, application data both ways, and
//! an explicit rekey — all driven through the sans-I/O byte pipeline.
//!
//! Run with: `cargo run --example loopback`

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use mls_tls::{
    Acceptor, ClientConfig, ClientConnection, ConnectionCommon, ServerConfig, ServerConnection,
};

fn pump(conn: &mut ConnectionCommon) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        let before = out.len();
        conn.write_tls(&mut out).unwrap();
        if out.len() == before {
            break;
        }
    }
    out
}

fn deliver(bytes: &[u8], to: &mut ConnectionCommon) {
    if bytes.is_empty() {
        return;
    }
    to.read_tls(&mut Cursor::new(bytes)).unwrap();
    to.process_new_packets().unwrap();
}

fn send(from: &mut ConnectionCommon, to: &mut ConnectionCommon, msg: &str) {
    from.writer().write_all(msg.as_bytes()).unwrap();
    deliver(&pump(from), to);
    let mut buf = vec![0u8; msg.len()];
    let n = to.reader().read(&mut buf).unwrap();
    println!("  received: {:?}", String::from_utf8_lossy(&buf[..n]));
}

fn main() {
    // Client: generated Basic credential, no server-cert verification (peer auth out of scope here).
    // Server: generated Basic credential.
    let client_config: Arc<ClientConfig> = ClientConfig::builder()
        .with_no_certificate_verification()
        .with_generated_basic_credential(b"client")
        .unwrap();
    let server_config: Arc<ServerConfig> = ServerConfig::builder()
        .with_no_client_auth()
        .with_generated_basic_credential(b"server")
        .unwrap();

    let server_name = mls_tls::ServerName::try_from("localhost").unwrap();
    let mut client = ClientConnection::new(client_config, server_name).unwrap();
    println!("handshake: client is_handshaking = {}", client.is_handshaking());

    // ClientHello -> server (via Acceptor).
    let ch = pump(&mut client);
    let mut acceptor = Acceptor::new();
    acceptor.read_tls(&mut Cursor::new(&ch)).unwrap();
    let accepted = acceptor.accept().unwrap().expect("ClientHello");
    println!(
        "server saw offered cipher suite: {:?}",
        accepted.client_hello().and_then(|h| h.cipher_suite())
    );
    let mut server: ServerConnection = accepted.into_connection(server_config).unwrap();

    // ServerHello -> client.
    deliver(&pump(&mut server), &mut client);
    println!("handshake: client is_handshaking = {}", client.is_handshaking());

    println!("client -> server:");
    send(&mut client, &mut server, "hello from client");
    println!("server -> client:");
    send(&mut server, &mut client, "hello from server");

    // Explicit rekey initiated by the client; inbound handling is automatic.
    println!("client initiates rekey ...");
    client.refresh_traffic_keys().unwrap();
    // settle the control exchange
    loop {
        let c2s = pump(&mut client);
        let s2c = pump(&mut server);
        if c2s.is_empty() && s2c.is_empty() {
            break;
        }
        deliver(&c2s, &mut server);
        deliver(&s2c, &mut client);
    }

    println!("client -> server (post-rekey):");
    send(&mut client, &mut server, "still works after rekey");
    println!("done.");
}
