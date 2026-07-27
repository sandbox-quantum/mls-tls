#![cfg(feature = "fips")]
//! FIPS-mode integration tests. These need a real OpenSSL FIPS module and will fail without one —
//! see `docker/fips/README.md`.
//!
//! Run with:
//!     cargo test --no-default-features --features fips --test fips_mode
//!
//! Everything runs in one binary because [`mls_tls::fips::enable`] mutates process-global OpenSSL
//! state. Cargo gives each integration test file its own process, and `enable()` is idempotent, so
//! calling it from every test is correct even though tests share a process and run in parallel.

use std::io::{Read, Write};
use std::sync::Arc;

use mls_tls::{
    CipherSuite, ClientConfig, ClientConnection, ConnectionCommon, ServerConfig, ServerConnection,
    ServerName, fips,
};

/// The three MLS suites whose primitives are all FIPS-approved.
const APPROVED: &[u16] = &[0x0002, 0x0005, 0x0007];

/// Suites that must be refused: X25519/X448 key agreement is unapproved, ChaCha20-Poly1305 is
/// absent from the FIPS provider, and X-Wing is RustCrypto-only.
const REFUSED: &[u16] = &[0x0001, 0x0003, 0x0004, 0x0006, 0x004e];

fn init() {
    fips::enable().expect("an OpenSSL FIPS module is required; see docker/fips/README.md");
}

#[test]
fn enable_is_idempotent_and_reports_enabled() {
    init();
    assert!(
        fips::is_enabled(),
        "fips=yes should be the default property"
    );
    // A second call must be a no-op, not a re-load.
    fips::enable().unwrap();
    assert!(fips::is_enabled());
}

/// The load-bearing negative control.
///
/// `mls-rs-crypto-openssl` uses legacy static algorithm objects (`EVP_sha384()`,
/// `EVP_aes_256_gcm()`), which are fetched *implicitly* with a NULL property query. The whole FIPS
/// design here rests on that NULL query merging with the context's `fips=yes` default. If it did
/// not, the crate would quietly keep using the default provider and every other test would still
/// pass.
///
/// MD5 is in the default provider and absent from the FIPS provider, so it must fail.
#[test]
fn non_approved_digest_is_unavailable() {
    init();
    let result = openssl::hash::hash(openssl::hash::MessageDigest::md5(), b"routing check");
    assert!(
        result.is_err(),
        "MD5 succeeded under FIPS mode — legacy static algorithms are NOT honouring the \
         fips=yes default property, so the crate is not actually inside the module"
    );
}

/// ChaCha20-Poly1305 is not in the FIPS provider at all.
#[test]
fn chacha20_poly1305_is_unavailable() {
    init();
    let key = [0u8; 32];
    let nonce = [0u8; 12];
    let mut tag = [0u8; 16];
    let result = openssl::symm::encrypt_aead(
        openssl::symm::Cipher::chacha20_poly1305(),
        &key,
        Some(&nonce),
        &[],
        b"plaintext",
        &mut tag,
    );
    assert!(result.is_err(), "ChaCha20-Poly1305 must not be available");
}

#[test]
fn only_approved_suites_are_offered() {
    init();

    for &suite in APPROVED {
        assert!(
            ClientConfig::builder()
                .with_no_certificate_verification()
                .with_cipher_suite(CipherSuite::new(suite))
                .with_generated_basic_credential(b"probe")
                .is_ok(),
            "suite {suite:#06x} should be available in FIPS mode"
        );
    }

    for &suite in REFUSED {
        let result = ClientConfig::builder()
            .with_no_certificate_verification()
            .with_cipher_suite(CipherSuite::new(suite))
            .with_generated_basic_credential(b"probe");
        assert!(
            matches!(result, Err(mls_tls::Error::Unsupported(_))),
            "suite {suite:#06x} must be refused in FIPS mode"
        );
    }
}

// --- full connection round-trips over each approved suite -------------------------------------

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

fn drive(client: &mut ClientConnection, server: &mut ServerConnection) {
    for _ in 0..16 {
        let a = pump(server, client);
        let b = pump(client, server);
        if a == 0 && b == 0 {
            break;
        }
    }
}

fn send(from: &mut ConnectionCommon, to: &mut ConnectionCommon, msg: &[u8]) -> Vec<u8> {
    from.writer().write_all(msg).unwrap();
    pump(from, to);
    let mut buf = vec![0u8; msg.len() + 16];
    let n = to.reader().read(&mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn configs(suite: u16) -> (Arc<ServerConfig>, Arc<ClientConfig>) {
    let cs = CipherSuite::new(suite);
    (
        ServerConfig::builder()
            .with_no_client_auth()
            .with_cipher_suite(cs)
            .with_generated_basic_credential(b"server")
            .unwrap(),
        ClientConfig::builder()
            .with_no_certificate_verification()
            .with_cipher_suite(cs)
            .with_generated_basic_credential(b"client")
            .unwrap(),
    )
}

#[test]
fn handshake_and_app_data_on_every_approved_suite() {
    init();
    for &suite in APPROVED {
        let (server_config, client_config) = configs(suite);
        let mut server = ServerConnection::new(server_config).unwrap();
        let mut client =
            ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap())
                .unwrap();
        drive(&mut client, &mut server);

        assert!(!client.is_handshaking(), "suite {suite:#06x}: client stuck");
        assert!(!server.is_handshaking(), "suite {suite:#06x}: server stuck");
        assert_eq!(send(&mut client, &mut server, b"c2s"), b"c2s");
        assert_eq!(send(&mut server, &mut client, b"s2c"), b"s2c");
    }
}

#[test]
fn rekey_on_every_approved_suite() {
    init();
    for &suite in APPROVED {
        let (server_config, client_config) = configs(suite);
        let mut server = ServerConnection::new(server_config).unwrap();
        let mut client =
            ClientConnection::new(client_config, ServerName::try_from("localhost").unwrap())
                .unwrap();
        drive(&mut client, &mut server);
        assert_eq!(send(&mut client, &mut server, b"pre"), b"pre");

        client.refresh_traffic_keys().unwrap();
        for _ in 0..4 {
            pump(&mut client, &mut server);
            pump(&mut server, &mut client);
        }

        assert_eq!(send(&mut client, &mut server, b"post c2s"), b"post c2s");
        assert_eq!(send(&mut server, &mut client, b"post s2c"), b"post s2c");
    }
}

#[test]
fn resumption_on_every_approved_suite() {
    init();
    for &suite in APPROVED {
        let (server_config, client_config) = configs(suite);
        let name = ServerName::try_from("localhost").unwrap();

        let mut server1 = ServerConnection::new(server_config.clone()).unwrap();
        let mut client1 = ClientConnection::new(client_config.clone(), name.clone()).unwrap();
        drive(&mut client1, &mut server1);
        assert_eq!(send(&mut client1, &mut server1, b"epoch1"), b"epoch1");
        let resumption = client1.export_resumption_state().unwrap();

        let mut server2 = ServerConnection::new(server_config).unwrap();
        let mut client2 = ClientConnection::resume(client_config, name, resumption).unwrap();
        drive(&mut client2, &mut server2);

        assert!(
            !client2.is_handshaking(),
            "suite {suite:#06x}: resumed client stuck"
        );
        assert_eq!(send(&mut client2, &mut server2, b"epoch2"), b"epoch2");
    }
}

/// The defect that sets the OpenSSL 3.5 floor: older validated modules reject HKDF `EXPAND_ONLY`
/// when the requested output is shorter than the digest, which is exactly how MLS derives its
/// 12-byte AEAD nonces. Probe it directly so the module's real behaviour is on record rather than
/// inferred from a version number.
#[test]
fn short_hkdf_expand_is_accepted() {
    init();
    for digest in [
        openssl::md::Md::sha256(),
        openssl::md::Md::sha384(),
        openssl::md::Md::sha512(),
    ] {
        let prk = vec![0x5au8; digest.size()];
        let mut out = [0u8; 12];
        openssl::kdf::hkdf(
            digest,
            &prk,
            None,
            Some(b"tls13 iv"),
            openssl::kdf::HkdfMode::ExpandOnly,
            None,
            &mut out,
        )
        .unwrap_or_else(|e| {
            panic!(
                "HKDF EXPAND_ONLY of 12 bytes under a {}-byte digest failed: {e}. This module has \
                 the short-expand defect; MLS cannot derive AEAD nonces on it.",
                digest.size()
            )
        });
    }
}
