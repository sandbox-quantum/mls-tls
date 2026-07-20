//! Phase-0 gate: confirm RustCrypto `ml-kem` (FIPS 203) is byte-compatible with the Python
//! `mlkem==0.0.3` used by `mls-tls-python-pedantic`. If this fails, the whole interop effort is
//! impossible with this `ml-kem` and we must stop.
//!
//! Vectors are produced by `interop/dump_kat.py` (fixed inputs) into `interop/kat_vectors.json`.

use ml_kem::{B32, Decapsulate, DecapsulationKey1024, EncapsulationKey1024, KeyExport, Seed};
use ml_kem::ml_kem_1024::Ciphertext;

fn load_vectors() -> serde_json::Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/interop/kat_vectors.json");
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("read {path}: {e} (run interop/dump_kat.py first)"));
    serde_json::from_str(&raw).expect("parse kat_vectors.json")
}

fn hexv(v: &serde_json::Value, key: &str) -> Vec<u8> {
    hex::decode(v[key].as_str().unwrap_or_else(|| panic!("missing hex field {key}"))).unwrap()
}

#[test]
fn mlkem1024_fips203_matches_python() {
    let vectors = load_vectors();
    let v = &vectors["mlkem1024"];

    let d = hexv(v, "d");
    let z = hexv(v, "z");
    let m = hexv(v, "m");
    let expected_ek = hexv(v, "ek");
    let expected_ct = hexv(v, "ct");
    let expected_ss = hexv(v, "ss");

    // Deterministic key generation from the 64-byte seed d||z.
    let mut seed_bytes = d.clone();
    seed_bytes.extend_from_slice(&z);
    let seed = Seed::try_from(&seed_bytes[..]).expect("64-byte seed");
    let dk = DecapsulationKey1024::from_seed(seed);
    let ek = dk.encapsulation_key();

    assert_eq!(
        ek.to_bytes().as_slice(),
        expected_ek.as_slice(),
        "ML-KEM-1024 encapsulation key mismatch vs Python KeyGen(d,z)"
    );

    // Deterministic encapsulation with the fixed message m.
    let m_arr = B32::try_from(&m[..]).expect("32-byte m");
    let (ct, ss) = ek.encapsulate_deterministic(&m_arr);
    assert_eq!(
        ct.as_slice(),
        expected_ct.as_slice(),
        "ML-KEM-1024 ciphertext mismatch vs Python Encaps(ek,m)"
    );
    assert_eq!(
        ss.as_slice(),
        expected_ss.as_slice(),
        "ML-KEM-1024 shared secret mismatch vs Python Encaps(ek,m)"
    );

    // Decapsulate the Python ciphertext and confirm we recover the same shared secret.
    let py_ct = Ciphertext::try_from(&expected_ct[..]).expect("1568-byte ciphertext");
    let ss_dec = dk.decapsulate(&py_ct);
    assert_eq!(
        ss_dec.as_slice(),
        expected_ss.as_slice(),
        "ML-KEM-1024 decaps(python ct) mismatch"
    );

    // And confirm a peer can reconstruct our ek from bytes (needed for X-Wing decap of peer enc).
    let ek2 = EncapsulationKey1024::new(&ek.to_bytes()).expect("reparse ek");
    assert_eq!(ek2.to_bytes().as_slice(), expected_ek.as_slice());
}
