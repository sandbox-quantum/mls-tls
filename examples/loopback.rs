//! In-memory loopback demo of the public `mls-tls` API: handshake, application data both ways, and
//! an explicit rekey — all driven through the sans-I/O byte pipeline.
//!
//! Run with: `cargo run --example loopback`

use std::io::{Read, Write};
use std::sync::Arc;

use mls_tls::{
    ClientConfig, ClientConnection, ConnectionCommon, ServerConfig, ServerConnection, ServerName,
};

/// Move all of `from`'s buffered TLS bytes into `to`, then process them. Returns bytes moved.
fn pump(from: &mut ConnectionCommon, to: &mut ConnectionCommon) -> usize {
    let mut buf = Vec::new();
    while from.wants_write() {
        if from.write_tls(&mut buf).unwrap() == 0 {
            break;
        }
    }
    if buf.is_empty() {
        return 0;
    }
    let mut cur = &buf[..];
    while !cur.is_empty() {
        if to.read_tls(&mut cur).unwrap() == 0 {
            break;
        }
    }
    to.process_new_packets().unwrap();
    buf.len()
}

fn send(from: &mut ConnectionCommon, to: &mut ConnectionCommon, msg: &str) {
    from.writer().write_all(msg.as_bytes()).unwrap();
    pump(from, to);
    let mut buf = vec![0u8; msg.len()];
    let n = to.reader().read(&mut buf).unwrap();
    println!("  received: {:?}", String::from_utf8_lossy(&buf[..n]));
}

fn main() {
    let client_config: Arc<ClientConfig> = ClientConfig::builder()
        .with_no_certificate_verification()
        .with_generated_basic_credential(b"client")
        .unwrap();
    let server_config: Arc<ServerConfig> = ServerConfig::builder()
        .with_no_client_auth()
        .with_generated_basic_credential(b"server")
        .unwrap();

    let server_name = ServerName::try_from("localhost").unwrap();
    let mut client = ClientConnection::new(client_config, server_name).unwrap();
    // The server speaks first (pre-handshake public key), so build it directly (no Acceptor).
    let mut server = ServerConnection::new(server_config).unwrap();

    // Drive the handshake: server pubkey -> ClientHello -> ServerHello.
    for _ in 0..8 {
        let a = pump(&mut server, &mut client);
        let b = pump(&mut client, &mut server);
        if a == 0 && b == 0 {
            break;
        }
    }
    println!(
        "handshake done: client={}, server={}",
        !client.is_handshaking(),
        !server.is_handshaking()
    );

    println!("client -> server:");
    send(&mut client, &mut server, "hello from client");
    println!("server -> client:");
    send(&mut server, &mut client, "hello from server");

    // Explicit rekey initiated by the client; inbound handling is automatic.
    println!("client initiates rekey ...");
    client.refresh_traffic_keys().unwrap();
    for _ in 0..4 {
        let a = pump(&mut client, &mut server);
        let b = pump(&mut server, &mut client);
        if a == 0 && b == 0 {
            break;
        }
    }

    println!("client -> server (post-rekey):");
    send(&mut client, &mut server, "still works after rekey");
    println!("done.");
}
