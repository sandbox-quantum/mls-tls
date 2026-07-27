#![cfg(feature = "rustcrypto")]
//! Only meaningful under the `rustcrypto` backend (X-Wing is unavailable under OpenSSL).
//!
//! Fixture interop (Python -> Rust): parse a Python-generated ClientHello with mls-rs and confirm
//! it is a well-formed X-Wing (0x004e) KeyPackage that our stack accepts.
//!
//! Generate the fixture first:
//!     interop/.venv/bin/python interop/fixtures.py   # writes interop/python_clienthello.bin

use mls_rs::MlsMessage;

#[test]
fn parses_python_clienthello() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/interop/python_clienthello.bin"
    );
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("skipping: {path} not found (run interop/fixtures.py to generate it)");
            return;
        }
    };

    // The ClientHello is a MlsTlsHandshake envelope: u16 version(0x0000) || u16 tag(0x0000) || MLSMessage.
    assert!(bytes.len() > 4, "clienthello too short");
    assert_eq!(
        &bytes[..4],
        &[0x00, 0x00, 0x00, 0x00],
        "unexpected envelope header"
    );

    let msg = MlsMessage::from_bytes(&bytes[4..]).expect("parse MLSMessage(KeyPackage)");
    let kp = msg.as_key_package().expect("message is a KeyPackage");

    assert_eq!(
        u16::from(kp.cipher_suite),
        0x004e,
        "expected X-Wing cipher suite 0x004e"
    );
    assert_eq!(
        kp.hpke_init_key.as_ref().len(),
        1665,
        "X-Wing init key must be 1665 bytes"
    );
}
