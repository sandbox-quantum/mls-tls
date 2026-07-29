//! Generates the Ed25519 X.509 fixtures in `fixtures/`: a CA, a `localhost` server certificate
//! signed by it, and the server's raw keypair in the encoding mls-rs expects.
//!
//! `cargo run -p mls-tls --example generate_fixtures`
//!
//! The two certificates must carry **distinct** distinguished names and the CA must be marked as
//! one. rcgen defaults every certificate to `CN=rcgen self signed cert` with no basicConstraints,
//! which makes the leaf's issuer and subject identical: `rustls-webpki` still builds the path by
//! checking the signature, but OpenSSL's `X509_STORE` classifies the leaf as
//! `DEPTH_ZERO_SELF_SIGNED_CERT` and refuses it — so fixtures generated that way silently work
//! under one backend and fail under the other.

use std::fs;
use std::path::Path;

use rcgen::{BasicConstraints, DnType, IsCa, KeyUsagePurpose};

fn main() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    fs::create_dir_all(&fixtures_dir).unwrap();

    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut ca_params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "mls-tls test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let mut server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    server_params.is_ca = IsCa::ExplicitNoCa;
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let server_cert = server_params.signed_by(&server_key, &ca).unwrap();

    let pkcs8_der = server_key.serialize_der();
    let seed: [u8; 32] = pkcs8_der[16..48].try_into().unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);

    fs::write(fixtures_dir.join("ca_cert.der"), ca.der().as_ref()).unwrap();
    fs::write(
        fixtures_dir.join("server_cert.der"),
        server_cert.der().as_ref(),
    )
    .unwrap();
    fs::write(
        fixtures_dir.join("server_secret_key.bin"),
        signing_key.to_keypair_bytes(),
    )
    .unwrap();
    fs::write(
        fixtures_dir.join("server_public_key.bin"),
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();

    println!("Fixtures written to {}", fixtures_dir.display());
}
