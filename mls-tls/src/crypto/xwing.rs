//! The custom "X-Wing" hybrid KEM: ML-KEM-1024 + NIST P-384, with a SHA3-384 combiner.
//!
//!
//! Layout:
//! - public/encapsulation key = ML-KEM-1024 ek (1568) ‖ P-384 uncompressed point (97) = 1665 B
//! - stored secret/decapsulation key = the 64-byte IKM seed (keypair re-derived on each use)
//! - ciphertext (`enc`) = ML-KEM ct (1568) ‖ P-384 ephemeral uncompressed point (97) = 1665 B
//! - shared secret = SHA3-384(ss_m ‖ ss_x ‖ ct_x ‖ pk_x ‖ label) = 48 B

use ml_kem::{
    B32, Decapsulate, DecapsulationKey1024, EncapsulationKey1024, KeyExport, Seed, kem::Key,
    ml_kem_1024::Ciphertext,
};
use mls_rs_core::crypto::{HpkePublicKey, HpkeSecretKey};
use mls_rs_crypto_traits::{KemResult, KemType};
use p384::elliptic_curve::ff::PrimeField;
use p384::elliptic_curve::ops::Reduce;
use p384::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p384::{AffinePoint, EncodedPoint, FieldBytes, ProjectivePoint, Scalar, U384};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_384, Shake256};

pub(crate) const XWING_KEM_ID: u16 = 0x647b;
const MLKEM_EK: usize = 1568;
const MLKEM_CT: usize = 1568;
const P384_PT: usize = 97;
pub(crate) const PK_LEN: usize = MLKEM_EK + P384_PT; // 1665
pub(crate) const ENC_LEN: usize = MLKEM_CT + P384_PT; // 1665
const IKM_LEN: usize = 64;
/// The X-Wing combiner label `\.//^\` (6 bytes: 5c 2e 2f 2f 5e 5c).
const XWING_LABEL: &[u8] = b"\\.//^\\";

#[derive(Debug)]
pub(crate) enum XWingError {
    InvalidKeyLength(usize),
    InvalidEncLength(usize),
    MlKem,
    P384,
}

impl core::fmt::Display for XWingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            XWingError::InvalidKeyLength(n) => write!(f, "invalid X-Wing key length: {n}"),
            XWingError::InvalidEncLength(n) => write!(f, "invalid X-Wing ciphertext length: {n}"),
            XWingError::MlKem => write!(f, "ML-KEM operation failed"),
            XWingError::P384 => write!(f, "P-384 operation failed"),
        }
    }
}

impl std::error::Error for XWingError {}

impl mls_rs_core::error::IntoAnyError for XWingError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// SHAKE256(ikm) → 112 bytes split into (d[32], z[32], p384_scalar[48]).
fn expand_seed(ikm: &[u8]) -> ([u8; 32], [u8; 32], [u8; 48]) {
    let mut xof = Shake256::default();
    xof.update(ikm);
    let mut reader = xof.finalize_xof();
    let mut out = [0u8; 112];
    reader.read(&mut out);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut s = [0u8; 48];
    d.copy_from_slice(&out[0..32]);
    z.copy_from_slice(&out[32..64]);
    s.copy_from_slice(&out[64..112]);
    (d, z, s)
}

/// Interpret 48 big-endian bytes as a P-384 scalar WITHOUT reduction
/// `ec.derive_private_key`, which rejects scalars ≥ n). Errors on the negligible ≥n case.
fn p384_scalar_no_reduce(bytes: &[u8; 48]) -> Result<Scalar, XWingError> {
    let fb = FieldBytes::clone_from_slice(bytes);
    Option::<Scalar>::from(Scalar::from_repr(fb)).ok_or(XWingError::P384)
}

/// Reduce 48 big-endian bytes mod n into a P-384 scalar
fn p384_scalar_reduce(bytes: &[u8; 48]) -> Scalar {
    Scalar::reduce(U384::from_be_slice(bytes))
}

/// The P-384 public key `G * scalar` as a 97-byte uncompressed point.
fn p384_public_point(scalar: &Scalar) -> [u8; P384_PT] {
    let pt = (ProjectivePoint::GENERATOR * scalar).to_affine();
    let enc = pt.to_encoded_point(false);
    let mut out = [0u8; P384_PT];
    out.copy_from_slice(enc.as_bytes());
    out
}

/// Parse a 97-byte uncompressed P-384 point.
fn p384_parse_point(bytes: &[u8]) -> Result<ProjectivePoint, XWingError> {
    let ep = EncodedPoint::from_bytes(bytes).map_err(|_| XWingError::P384)?;
    let ap = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&ep))
        .ok_or(XWingError::P384)?;
    Ok(ProjectivePoint::from(ap))
}

/// `point * scalar` as a 97-byte uncompressed point.
fn p384_mul_point(point: &ProjectivePoint, scalar: &Scalar) -> [u8; P384_PT] {
    let pt = (*point * scalar).to_affine();
    let enc = pt.to_encoded_point(false);
    let mut out = [0u8; P384_PT];
    out.copy_from_slice(enc.as_bytes());
    out
}

/// SHA3-384(ss_m ‖ ss_x ‖ ct_x ‖ pk_x ‖ label) → 48-byte shared secret.
pub(crate) fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Vec<u8> {
    let mut h = Sha3_384::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, XWING_LABEL);
    h.finalize().to_vec()
}

/// Reconstruct the ML-KEM decapsulation key + P-384 scalar + the 97-byte P-384 public point from a
/// 64-byte IKM.
fn expand_keypair(ikm: &[u8]) -> Result<(DecapsulationKey1024, Scalar, [u8; P384_PT]), XWingError> {
    if ikm.len() != IKM_LEN {
        return Err(XWingError::InvalidKeyLength(ikm.len()));
    }
    let (d, z, scalar_bytes) = expand_seed(ikm);
    let mut seed_bytes = [0u8; 64];
    seed_bytes[..32].copy_from_slice(&d);
    seed_bytes[32..].copy_from_slice(&z);
    let seed = Seed::try_from(&seed_bytes[..]).map_err(|_| XWingError::MlKem)?;
    let dk = DecapsulationKey1024::from_seed(seed);
    let scalar = p384_scalar_no_reduce(&scalar_bytes)?;
    let pk_x = p384_public_point(&scalar);
    Ok((dk, scalar, pk_x))
}

/// Derive the (secret = IKM, public = 1665-byte encapsulation key) pair from a 64-byte IKM.
pub(crate) fn derive_keypair(ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>), XWingError> {
    let (dk, _scalar, pk_x) = expand_keypair(ikm)?;
    let ek_bytes = dk.encapsulation_key().to_bytes();
    let mut pk = Vec::with_capacity(PK_LEN);
    pk.extend_from_slice(ek_bytes.as_slice());
    pk.extend_from_slice(&pk_x);
    Ok((ikm.to_vec(), pk))
}

/// Encapsulate to a 1665-byte public key using explicit 80-byte randomness
/// (`ml_kem_message[32] ‖ p384_randomness[48]`). Returns `(enc, shared_secret)`.
pub(crate) fn encapsulate_deterministic(
    public_key: &[u8],
    randomness: &[u8; 80],
) -> Result<(Vec<u8>, Vec<u8>), XWingError> {
    if public_key.len() != PK_LEN {
        return Err(XWingError::InvalidKeyLength(public_key.len()));
    }
    let pk_m = &public_key[..MLKEM_EK];
    let pk_x = &public_key[MLKEM_EK..];

    // ML-KEM encapsulation with the fixed 32-byte message.
    let ek_key = Key::<EncapsulationKey1024>::try_from(pk_m).map_err(|_| XWingError::MlKem)?;
    let ek = EncapsulationKey1024::new(&ek_key).map_err(|_| XWingError::MlKem)?;
    let m = B32::try_from(&randomness[..32]).map_err(|_| XWingError::MlKem)?;
    let (ct_m, ss_m) = ek.encapsulate_deterministic(&m);

    // P-384 ECDH: ephemeral scalar = reduce(SHAKE256(p384_randomness) → 48 bytes) mod n.
    let mut p384_rand = [0u8; 48];
    p384_rand.copy_from_slice(&randomness[32..]);
    let mut xof = Shake256::default();
    xof.update(&p384_rand);
    let mut reader = xof.finalize_xof();
    let mut ek_scalar_bytes = [0u8; 48];
    reader.read(&mut ek_scalar_bytes);
    let ek_scalar = p384_scalar_reduce(&ek_scalar_bytes);

    let ct_x = p384_public_point(&ek_scalar);
    let pk_x_point = p384_parse_point(pk_x)?;
    let ss_x = p384_mul_point(&pk_x_point, &ek_scalar);

    let shared_secret = combiner(ss_m.as_slice(), &ss_x, &ct_x, pk_x);

    let mut enc = Vec::with_capacity(ENC_LEN);
    enc.extend_from_slice(ct_m.as_slice());
    enc.extend_from_slice(&ct_x);
    Ok((enc, shared_secret))
}

/// Decapsulate a 1665-byte ciphertext with a 64-byte IKM secret key. Returns the 48-byte secret.
pub(crate) fn decapsulate(secret_key: &[u8], enc: &[u8]) -> Result<Vec<u8>, XWingError> {
    if enc.len() != ENC_LEN {
        return Err(XWingError::InvalidEncLength(enc.len()));
    }
    let (dk, scalar, pk_x) = expand_keypair(secret_key)?;
    let ct_m = &enc[..MLKEM_CT];
    let ct_x = &enc[MLKEM_CT..];

    let ct = Ciphertext::try_from(ct_m).map_err(|_| XWingError::MlKem)?;
    let ss_m = dk.decapsulate(&ct);

    let ct_x_point = p384_parse_point(ct_x)?;
    let ss_x = p384_mul_point(&ct_x_point, &scalar);

    Ok(combiner(ss_m.as_slice(), &ss_x, ct_x, &pk_x))
}

/// The X-Wing KEM as an `mls-rs` [`KemType`], usable inside `mls-rs-crypto-hpke`'s `Hpke`.
#[derive(Clone, Default)]
pub(crate) struct XWingKem;

impl KemType for XWingKem {
    type Error = XWingError;

    fn kem_id(&self) -> u16 {
        XWING_KEM_ID
    }

    fn generate_deterministic(
        &self,
        seed: &[u8],
    ) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        let (sk, pk) = derive_keypair(seed)?;
        Ok((HpkeSecretKey::from(sk), HpkePublicKey::from(pk)))
    }

    fn generate(&self) -> Result<(HpkeSecretKey, HpkePublicKey), Self::Error> {
        use rand_core::RngCore;
        let mut ikm = [0u8; IKM_LEN];
        rand_core::OsRng.fill_bytes(&mut ikm);
        self.generate_deterministic(&ikm)
    }

    fn public_key_validate(&self, key: &HpkePublicKey) -> Result<(), Self::Error> {
        let bytes = key.as_ref();
        if bytes.len() != PK_LEN {
            return Err(XWingError::InvalidKeyLength(bytes.len()));
        }
        // Validate the ML-KEM half parses and the P-384 half is a valid point.
        let ek_key = Key::<EncapsulationKey1024>::try_from(&bytes[..MLKEM_EK])
            .map_err(|_| XWingError::MlKem)?;
        EncapsulationKey1024::new(&ek_key).map_err(|_| XWingError::MlKem)?;
        p384_parse_point(&bytes[MLKEM_EK..])?;
        Ok(())
    }

    fn encap(&self, remote_key: &HpkePublicKey) -> Result<KemResult, Self::Error> {
        use rand_core::RngCore;
        let mut randomness = [0u8; 80];
        rand_core::OsRng.fill_bytes(&mut randomness);
        let (enc, shared_secret) = encapsulate_deterministic(remote_key.as_ref(), &randomness)?;
        Ok(KemResult::new(shared_secret, enc))
    }

    fn decap(
        &self,
        enc: &[u8],
        secret_key: &HpkeSecretKey,
        _local_public: &HpkePublicKey,
    ) -> Result<Vec<u8>, Self::Error> {
        decapsulate(secret_key.as_ref(), enc)
    }

    fn seed_length_for_derive(&self) -> usize {
        IKM_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> serde_json::Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../interop/kat_vectors.json");
        let raw = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {path}: {e} (run interop/dump_kat.py first)"));
        serde_json::from_str(&raw).expect("parse kat_vectors.json")
    }

    fn hexf(v: &serde_json::Value, key: &str) -> Vec<u8> {
        hex::decode(v[key].as_str().unwrap()).unwrap()
    }

    #[test]
    fn xwing_derive_keypair_matches_python() {
        let v = &vectors()["xwing"];
        let ikm = hexf(v, "ikm");
        let expected_pk = hexf(v, "pk");
        let (sk, pk) = derive_keypair(&ikm).unwrap();
        assert_eq!(sk, ikm, "stored secret should be the IKM");
        assert_eq!(
            pk, expected_pk,
            "X-Wing public key mismatch vs Python DeriveKeyPair"
        );
    }

    #[test]
    fn xwing_combiner_matches_python() {
        let v = &vectors()["xwing"];
        let ci = &v["combiner_in"];
        let out = combiner(
            &hex::decode(ci["ss_m"].as_str().unwrap()).unwrap(),
            &hex::decode(ci["ss_x"].as_str().unwrap()).unwrap(),
            &hex::decode(ci["ct_x"].as_str().unwrap()).unwrap(),
            &hex::decode(ci["pk_x"].as_str().unwrap()).unwrap(),
        );
        assert_eq!(
            out,
            hexf(v, "combiner_out"),
            "SHA3-384 combiner mismatch vs Python"
        );
    }

    #[test]
    fn xwing_encap_deterministic_matches_python() {
        let v = &vectors()["xwing"];
        let pk = hexf(v, "pk");
        let mut rand = [0u8; 80];
        rand.copy_from_slice(&hexf(v, "encap_randomness"));
        let (enc, ss) = encapsulate_deterministic(&pk, &rand).unwrap();
        assert_eq!(
            enc,
            hexf(v, "enc"),
            "X-Wing enc mismatch vs Python encapsulate"
        );
        assert_eq!(
            ss,
            hexf(v, "ss"),
            "X-Wing shared secret mismatch vs Python encapsulate"
        );
    }

    #[test]
    fn xwing_decap_python_enc() {
        let v = &vectors()["xwing"];
        let ikm = hexf(v, "ikm");
        let enc = hexf(v, "enc");
        let ss = decapsulate(&ikm, &enc).unwrap();
        assert_eq!(ss, hexf(v, "ss"), "decap(python enc) mismatch");
    }

    #[test]
    fn xwing_roundtrip() {
        // Rust-generated keypair, Rust encap → Rust decap.
        let kem = XWingKem;
        let (sk, pk) = kem.generate().unwrap();
        let kr = kem.encap(&pk).unwrap();
        let recovered = kem.decap(kr.enc(), &sk, &pk).unwrap();
        assert_eq!(recovered, kr.shared_secret());
    }
}
