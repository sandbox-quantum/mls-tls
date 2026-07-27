use std::fs;
use std::path::Path;

fn main() {
    let fixtures_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    fs::create_dir_all(&fixtures_dir).unwrap();

    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca_params = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap();
    let ca = rcgen::CertifiedIssuer::self_signed(ca_params, ca_key).unwrap();

    let server_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let server_params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
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
