//! The application-data record layer, byte-aligned for interoperability.
//!
//! - Key/IV derivation adds an extra step: `dir_secret = HKDF-Expand-Label(traffic_secret,
//!   "<c|s> ap traffic", context, Nh)`, then `key = Expand-Label(dir_secret, "key", "", Nk)` and
//!   `iv = Expand-Label(dir_secret, "iv", "", 12)`. The `<c|s> ap traffic` context is `Nh` zero
//!   bytes at epoch 1 and empty at epoch ≥ 2.
//! - Sequence numbers are **monotonic across epochs** — a rekey rotates key/IV but does NOT reset
//!   the per-direction counter (only a fresh transport does).
//! - The AEAD record is `header || AEAD(nonce, plaintext || inner_type(0x17), aad=header)`,
//!   `nonce = iv XOR seq` in the low 8 bytes.
//!
use mls_rs::CipherSuiteProvider;
use zeroize::Zeroizing;

use crate::crypto::provider::MlsTlsCipherSuiteProvider;

// RFC 8446 §5.1 ContentType. On this wire, application data rides the AEAD layer with inner type
// `application_data`; control (signaling) is sent as plaintext transport frames, not through here.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}

impl TryFrom<u8> for ContentType {
    type Error = RecordError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ContentType::Invalid),
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            other => Err(RecordError::InvalidContentType(other)),
        }
    }
}

/// A decrypted inner record: its content type plus the plaintext fragment.
#[derive(Debug)]
pub struct TlsPlaintext {
    pub content_type: ContentType,
    pub fragment: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    #[error("invalid TLS record header")]
    InvalidHeader,
    /// Deliberately carries no detail: decryption failures are attacker-triggerable, so the cause
    /// stays out of the error path.
    #[error("AEAD decryption failed")]
    DecryptionFailed,
    #[error("AEAD encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("record key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("invalid content type: {0}")]
    InvalidContentType(u8),
    #[error("decrypted record was empty")]
    EmptyInnerPlaintext,
    #[error("sequence number would overflow")]
    SequenceNumberOverflow,
    #[error("unsupported cipher suite: {0:#06x}")]
    UnsupportedCipherSuite(u16),
}

const TLS_RECORD_HEADER_LEN: usize = 5;
const AEAD_TAG_LEN: usize = 16;
/// TLS 1.3 fixes the record nonce at 12 bytes; every MLS suite's AEAD agrees.
const NONCE_LEN: usize = 12;
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const SEQ_NUM_LIMIT: u64 = u64::MAX - 1;
const MAX_INNER_PLAINTEXT_LEN: usize = u16::MAX as usize - TLS_RECORD_HEADER_LEN - 1 - AEAD_TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// TLS-1.3 `HKDF-Expand-Label(secret, label, context, len)` with the `"tls13 "` prefix and 1-byte
/// length prefixes, over the suite's KDF.
fn expand_label(
    csp: &MlsTlsCipherSuiteProvider,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, RecordError> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";
    let mut info = Vec::new();
    // This `len` is the wire-visible `HkdfLabel.length` field — part of the KDF *input*, hashed into
    // every output byte. It is not the same thing as the number of bytes requested from HKDF below,
    // even though the two coincide today. Never derive one from the other.
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((LABEL_PREFIX.len() + label.len()) as u8);
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    csp.kdf_expand(secret, &info, len)
        .map_err(|e| RecordError::KeyDerivation(e.to_string()))
}

/// Derive `(key, iv)` from a direction's traffic secret, per the Python `_derive_key_iv`.
fn derive_key_iv(
    csp: &MlsTlsCipherSuiteProvider,
    traffic_secret: &[u8],
    dir_label: &[u8],
    epoch_one: bool,
) -> Result<(Zeroizing<Vec<u8>>, [u8; NONCE_LEN]), RecordError> {
    let nh = csp.kdf_extract_size();
    // Context quirk: `Nh` zero bytes at epoch 1, empty afterwards.
    let context = if epoch_one { vec![0u8; nh] } else { Vec::new() };
    let dir_secret = expand_label(csp, traffic_secret, dir_label, &context, nh)?;
    let key = expand_label(csp, &dir_secret, b"key", b"", csp.aead_key_size())?;
    let iv_vec = expand_label(csp, &dir_secret, b"iv", b"", NONCE_LEN)?;
    let mut iv = [0u8; NONCE_LEN];
    iv.copy_from_slice(&iv_vec);
    Ok((key, iv))
}

/// One transport direction: its AEAD key, static IV, and sequence counter.
struct Direction {
    key: Zeroizing<Vec<u8>>,
    iv: [u8; NONCE_LEN],
    seq: u64,
}

/// `nonce = iv XOR seq`, seq big-endian in the low 8 bytes.
fn make_nonce(iv: &[u8; NONCE_LEN], seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= seq_bytes[i];
    }
    nonce
}

/// The 5-byte inner record header, which doubles as the AEAD AAD.
fn header(payload_len: usize) -> [u8; TLS_RECORD_HEADER_LEN] {
    [
        ContentType::ApplicationData as u8,
        LEGACY_RECORD_VERSION[0],
        LEGACY_RECORD_VERSION[1],
        (payload_len >> 8) as u8,
        (payload_len & 0xff) as u8,
    ]
}

/// Directional rekey material, carrying the freshly-exported MLS traffic secret(s). The variant +
/// local role selects which transport direction(s) rotate; sequence numbers are preserved.
///
/// `InitiatorSecret` carries the client_application_traffic_secret; `ResponderSecret` the
/// server_application_traffic_secret.
pub enum DirectionalRekey {
    InitiatorSecret(Vec<u8>),
    ResponderSecret(Vec<u8>),
    BothSecrets {
        initiator: Vec<u8>,
        responder: Vec<u8>,
    },
}

/// The record layer: two independent directions (send/recv), each with its own key/IV and a
/// monotonic sequence number, protected by the group's cipher-suite provider.
pub struct RecordLayer {
    csp: MlsTlsCipherSuiteProvider,
    send: Direction,
    recv: Direction,
}

impl RecordLayer {
    /// Build both directions from the epoch's client/server application traffic secrets.
    /// `epoch_one` selects the `<c|s> ap traffic` context (`Nh` zero bytes vs empty).
    pub fn from_traffic_secrets(
        csp: MlsTlsCipherSuiteProvider,
        client_secret: &[u8],
        server_secret: &[u8],
        role: Role,
        epoch_one: bool,
    ) -> Result<Self, RecordError> {
        // TLS 1.3 hard-codes a 12-byte record nonce. Every MLS suite agrees, but a suite that did
        // not would silently mis-derive the IV, so reject it rather than truncate.
        if csp.aead_nonce_size() != NONCE_LEN {
            return Err(RecordError::UnsupportedCipherSuite(
                csp.cipher_suite().into(),
            ));
        }

        let (client_key, client_iv) =
            derive_key_iv(&csp, client_secret, b"c ap traffic", epoch_one)?;
        let (server_key, server_iv) =
            derive_key_iv(&csp, server_secret, b"s ap traffic", epoch_one)?;

        let client_dir = Direction {
            key: client_key,
            iv: client_iv,
            seq: 0,
        };
        let server_dir = Direction {
            key: server_key,
            iv: server_iv,
            seq: 0,
        };

        let (send, recv) = match role {
            Role::Client => (client_dir, server_dir),
            Role::Server => (server_dir, client_dir),
        };
        Ok(Self { csp, send, recv })
    }

    /// Rotate one or both directions from freshly-exported traffic secrets (epoch ≥ 2, so the
    /// `<c|s> ap traffic` context is empty). Sequence numbers are preserved (monotonic).
    pub fn apply_rekey(&mut self, update: DirectionalRekey, role: Role) -> Result<(), RecordError> {
        match update {
            DirectionalRekey::InitiatorSecret(secret) => match role {
                Role::Client => self.rotate_send(&secret, b"c ap traffic"),
                Role::Server => self.rotate_recv(&secret, b"c ap traffic"),
            },
            DirectionalRekey::ResponderSecret(secret) => match role {
                Role::Client => self.rotate_recv(&secret, b"s ap traffic"),
                Role::Server => self.rotate_send(&secret, b"s ap traffic"),
            },
            DirectionalRekey::BothSecrets {
                initiator,
                responder,
            } => match role {
                Role::Client => {
                    self.rotate_send(&initiator, b"c ap traffic")?;
                    self.rotate_recv(&responder, b"s ap traffic")
                }
                Role::Server => {
                    self.rotate_send(&responder, b"s ap traffic")?;
                    self.rotate_recv(&initiator, b"c ap traffic")
                }
            },
        }
    }

    fn rotate_send(&mut self, secret: &[u8], dir_label: &[u8]) -> Result<(), RecordError> {
        let (key, iv) = derive_key_iv(&self.csp, secret, dir_label, false)?;
        self.send.key = key;
        self.send.iv = iv;
        // seq preserved (monotonic across epochs).
        Ok(())
    }

    fn rotate_recv(&mut self, secret: &[u8], dir_label: &[u8]) -> Result<(), RecordError> {
        let (key, iv) = derive_key_iv(&self.csp, secret, dir_label, false)?;
        self.recv.key = key;
        self.recv.iv = iv;
        Ok(())
    }

    /// Encrypt application plaintext into inner AEAD records (header || ciphertext). The caller
    /// wraps this in an outer transport frame. `content_type` is the inner content type (normally
    /// `ApplicationData`).
    pub fn encrypt(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Vec<Vec<u8>>, RecordError> {
        let mut records = Vec::new();
        for chunk in plaintext.chunks(MAX_INNER_PLAINTEXT_LEN) {
            if self.send.seq >= SEQ_NUM_LIMIT {
                return Err(RecordError::SequenceNumberOverflow);
            }
            let mut buf = Vec::with_capacity(chunk.len() + 1);
            buf.extend_from_slice(chunk);
            buf.push(content_type as u8);

            // The header doubles as the AAD, so its length field must already account for the tag
            // the AEAD is about to append.
            let ct_len = buf.len() + AEAD_TAG_LEN;
            let aad = header(ct_len);
            let nonce = make_nonce(&self.send.iv, self.send.seq);
            let ciphertext = self
                .csp
                .aead_seal(&self.send.key, &buf, Some(&aad), &nonce)
                .map_err(|e| RecordError::EncryptionFailed(e.to_string()))?;
            debug_assert_eq!(ciphertext.len(), ct_len, "AEAD expansion is not tag-sized");
            self.send.seq += 1;

            let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + ciphertext.len());
            record.extend_from_slice(&aad);
            record.extend_from_slice(&ciphertext);
            records.push(record);
        }
        Ok(records)
    }

    /// Decrypt one inner AEAD record (header || ciphertext), returning the inner plaintext and
    /// content type.
    pub fn decrypt(&mut self, record: &[u8]) -> Result<TlsPlaintext, RecordError> {
        if self.recv.seq >= SEQ_NUM_LIMIT {
            return Err(RecordError::SequenceNumberOverflow);
        }
        if record.len() < TLS_RECORD_HEADER_LEN {
            return Err(RecordError::InvalidHeader);
        }
        if record[0] != ContentType::ApplicationData as u8 || record[1..3] != LEGACY_RECORD_VERSION
        {
            return Err(RecordError::InvalidHeader);
        }
        let length = u16::from_be_bytes([record[3], record[4]]) as usize;
        if record.len() != TLS_RECORD_HEADER_LEN + length {
            return Err(RecordError::InvalidHeader);
        }

        let aad = &record[..TLS_RECORD_HEADER_LEN];
        let nonce = make_nonce(&self.recv.iv, self.recv.seq);
        let mut buf = self
            .csp
            .aead_open(
                &self.recv.key,
                &record[TLS_RECORD_HEADER_LEN..],
                Some(aad),
                &nonce,
            )
            .map_err(|_| RecordError::DecryptionFailed)?
            .to_vec();
        self.recv.seq += 1;

        // Inner content type is the final byte (Python appends exactly one, no zero padding).
        let content_type_byte = buf.pop().ok_or(RecordError::EmptyInnerPlaintext)?;
        let content_type = ContentType::try_from(content_type_byte)?;
        Ok(TlsPlaintext {
            content_type,
            fragment: buf,
        })
    }
}

/// Every MLS suite plus X-Wing. Which of these the compiled backend actually serves varies —
/// X-Wing is `rustcrypto`-only — so tests iterate this list and skip what [`suite_provider`]
/// declines.
#[cfg(test)]
const ALL_SUITES: &[u16] = &[
    0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x004e,
];

/// A suite provider from the compiled backend, or `None` if it does not serve that suite.
#[cfg(test)]
fn suite_provider(suite: u16) -> Option<MlsTlsCipherSuiteProvider> {
    use mls_rs::{CipherSuite, CryptoProvider};
    crate::crypto::provider::MlsTlsCryptoProvider::new()
        .cipher_suite_provider(CipherSuite::new(suite))
}

/// Known-answer vectors pinning the exact record bytes this layer puts on the wire.
///
/// The fixture (`fixtures/record_kat.json`) is generated once, from a `rustcrypto` build, by the
/// `#[ignore]`d `generate` test below; [`matches_fixture`](kat::matches_fixture) then replays it
/// under *whichever* backend is compiled. That cross-backend replay is the point: the two backends
/// are mutually exclusive features and cannot be linked into one binary, so a committed fixture is
/// the only way to prove they agree byte-for-byte.
///
/// Regenerate only when the wire format is *intended* to change — a diff here is a compatibility
/// break with every peer, including the Python implementation in `interop/`.
#[cfg(test)]
mod kat {
    use super::*;

    const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/record_kat.json");

    const C2S: &[&[u8]] = &[b"hello server", b"second record from the client"];
    const S2C: &[&[u8]] = &[b"hello client"];
    const C2S_POST: &[&[u8]] = &[b"after rekey, client to server"];
    const S2C_POST: &[&[u8]] = &[b"after rekey, server to client"];

    /// A deterministic, suite-dependent byte pattern — deliberately not a repeated byte, so a
    /// mis-ordered or truncated secret cannot accidentally produce the right answer.
    fn fill(tag: u8, suite: u16, len: usize) -> Vec<u8> {
        let seed = tag ^ (suite as u8) ^ ((suite >> 8) as u8);
        (0..len)
            .map(|i| seed.wrapping_add((i as u8).wrapping_mul(31)))
            .collect()
    }

    /// The record bytes one suite produces, plus the inputs that produced them.
    struct Vector {
        client_secret: Vec<u8>,
        server_secret: Vec<u8>,
        rekey_client_secret: Vec<u8>,
        rekey_server_secret: Vec<u8>,
        c2s: Vec<Vec<u8>>,
        s2c: Vec<Vec<u8>>,
        c2s_post: Vec<Vec<u8>>,
        s2c_post: Vec<Vec<u8>>,
    }

    /// Encrypt the fixed script for `suite`, decrypting each record on the peer as we go so the
    /// vector can never record bytes that do not round-trip.
    fn compute(suite: u16) -> Vector {
        let csp = suite_provider(suite).expect("suite served by the compiled backend");
        let nh = csp.kdf_extract_size();

        let client_secret = fill(0x11, suite, nh);
        let server_secret = fill(0x22, suite, nh);
        let rekey_client_secret = fill(0x33, suite, nh);
        let rekey_server_secret = fill(0x44, suite, nh);

        let mut client = RecordLayer::from_traffic_secrets(
            csp.clone(),
            &client_secret,
            &server_secret,
            Role::Client,
            true,
        )
        .unwrap();
        let mut server = RecordLayer::from_traffic_secrets(
            csp,
            &client_secret,
            &server_secret,
            Role::Server,
            true,
        )
        .unwrap();

        // Sequential records in one direction exercise the monotonic sequence number / nonce XOR.
        let send = |from: &mut RecordLayer, to: &mut RecordLayer, msgs: &[&[u8]]| {
            let mut out = Vec::new();
            for msg in msgs {
                let records = from.encrypt(ContentType::ApplicationData, msg).unwrap();
                for record in &records {
                    let pt = to.decrypt(record).unwrap();
                    assert_eq!(pt.content_type, ContentType::ApplicationData);
                    assert_eq!(
                        &pt.fragment, msg,
                        "round-trip failed for suite {suite:#06x}"
                    );
                }
                out.extend(records);
            }
            out
        };

        let c2s = send(&mut client, &mut server, C2S);
        let s2c = send(&mut server, &mut client, S2C);

        // Rekey both directions: epoch >= 2, so the `<c|s> ap traffic` context is empty and the
        // sequence numbers must *not* reset.
        let rekey = |layer: &mut RecordLayer, role: Role| {
            layer
                .apply_rekey(
                    DirectionalRekey::BothSecrets {
                        initiator: rekey_client_secret.clone(),
                        responder: rekey_server_secret.clone(),
                    },
                    role,
                )
                .unwrap()
        };
        rekey(&mut client, Role::Client);
        rekey(&mut server, Role::Server);

        let c2s_post = send(&mut client, &mut server, C2S_POST);
        let s2c_post = send(&mut server, &mut client, S2C_POST);

        Vector {
            client_secret,
            server_secret,
            rekey_client_secret,
            rekey_server_secret,
            c2s,
            s2c,
            c2s_post,
            s2c_post,
        }
    }

    fn hex_all(records: &[Vec<u8>]) -> Vec<String> {
        records.iter().map(hex::encode).collect()
    }

    /// Regenerate `fixtures/record_kat.json`. `rustcrypto` only — the fixture is the reference the
    /// OpenSSL backend is checked *against*, so it must never be produced by OpenSSL.
    ///
    /// `cargo test --lib kat::generate -- --ignored`
    #[cfg(feature = "rustcrypto")]
    #[test]
    #[ignore]
    fn generate() {
        let vectors = ALL_SUITES
            .iter()
            .map(|&suite| {
                let v = compute(suite);
                serde_json::json!({
                    "suite": suite,
                    "client_secret": hex::encode(&v.client_secret),
                    "server_secret": hex::encode(&v.server_secret),
                    "rekey_client_secret": hex::encode(&v.rekey_client_secret),
                    "rekey_server_secret": hex::encode(&v.rekey_server_secret),
                    "c2s": hex_all(&v.c2s),
                    "s2c": hex_all(&v.s2c),
                    "c2s_post_rekey": hex_all(&v.c2s_post),
                    "s2c_post_rekey": hex_all(&v.s2c_post),
                })
            })
            .collect::<Vec<_>>();

        let doc = serde_json::json!({
            "comment": "Record-layer known-answer vectors. See src/tls_record.rs `mod kat`. \
                        Generated from the rustcrypto backend; replayed under every backend.",
            "plaintexts": {
                "c2s": C2S.iter().map(|m| String::from_utf8_lossy(m)).collect::<Vec<_>>(),
                "s2c": S2C.iter().map(|m| String::from_utf8_lossy(m)).collect::<Vec<_>>(),
                "c2s_post_rekey": C2S_POST.iter().map(|m| String::from_utf8_lossy(m)).collect::<Vec<_>>(),
                "s2c_post_rekey": S2C_POST.iter().map(|m| String::from_utf8_lossy(m)).collect::<Vec<_>>(),
            },
            "vectors": vectors,
        });

        std::fs::write(FIXTURE, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
        eprintln!("wrote {} vectors to {FIXTURE}", vectors.len());
    }

    /// Replay the fixture under the compiled backend. This is the guard that the record layer still
    /// puts the same bytes on the wire.
    #[test]
    fn matches_fixture() {
        let raw = std::fs::read_to_string(FIXTURE).unwrap_or_else(|e| {
            panic!(
                "read {FIXTURE}: {e} (generate with `cargo test --lib kat::generate -- --ignored`)"
            )
        });
        let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse record_kat.json");
        let vectors = doc["vectors"].as_array().expect("vectors array");
        assert!(!vectors.is_empty(), "fixture has no vectors");

        let mut checked = 0;
        for entry in vectors {
            let suite = entry["suite"].as_u64().expect("suite") as u16;
            if suite_provider(suite).is_none() {
                continue; // not served by the compiled backend (e.g. X-Wing under OpenSSL)
            }

            let v = compute(suite);
            let field = |name: &str| -> Vec<String> {
                entry[name]
                    .as_array()
                    .unwrap_or_else(|| panic!("suite {suite:#06x}: missing {name}"))
                    .iter()
                    .map(|s| s.as_str().expect("hex string").to_string())
                    .collect()
            };

            // The inputs must match too, or "same output" would be meaningless.
            assert_eq!(
                entry["client_secret"],
                hex::encode(&v.client_secret),
                "suite {suite:#06x}"
            );
            assert_eq!(
                entry["server_secret"],
                hex::encode(&v.server_secret),
                "suite {suite:#06x}"
            );
            assert_eq!(
                entry["rekey_client_secret"],
                hex::encode(&v.rekey_client_secret),
                "suite {suite:#06x}"
            );
            assert_eq!(
                entry["rekey_server_secret"],
                hex::encode(&v.rekey_server_secret),
                "suite {suite:#06x}"
            );

            assert_eq!(field("c2s"), hex_all(&v.c2s), "suite {suite:#06x} c2s");
            assert_eq!(field("s2c"), hex_all(&v.s2c), "suite {suite:#06x} s2c");
            assert_eq!(
                field("c2s_post_rekey"),
                hex_all(&v.c2s_post),
                "suite {suite:#06x} c2s post-rekey"
            );
            assert_eq!(
                field("s2c_post_rekey"),
                hex_all(&v.s2c_post),
                "suite {suite:#06x} s2c post-rekey"
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "no fixture suite was servable by the compiled backend"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `P384_AES256` — the one standard suite every backend serves.
    const UNIVERSAL_SUITE: u16 = 0x0007;

    /// Build a client/server pair for `suite` over the given secrets.
    fn pair(suite: u16, c: &[u8], s: &[u8]) -> (RecordLayer, RecordLayer) {
        let csp = suite_provider(suite).expect("suite served by the compiled backend");
        (
            RecordLayer::from_traffic_secrets(csp.clone(), c, s, Role::Client, true).unwrap(),
            RecordLayer::from_traffic_secrets(csp, c, s, Role::Server, true).unwrap(),
        )
    }

    fn roundtrip(suite: u16) {
        let nh = suite_provider(suite).unwrap().kdf_extract_size();
        let (mut client, mut server) = pair(suite, &vec![0xAAu8; nh], &vec![0xBBu8; nh]);

        // Client → server.
        let recs = client
            .encrypt(ContentType::ApplicationData, b"hello server")
            .unwrap();
        let pt = server.decrypt(&recs[0]).unwrap();
        assert_eq!(pt.content_type, ContentType::ApplicationData);
        assert_eq!(pt.fragment, b"hello server");

        // Server → client.
        let recs = server
            .encrypt(ContentType::ApplicationData, b"hello client")
            .unwrap();
        let pt = client.decrypt(&recs[0]).unwrap();
        assert_eq!(pt.fragment, b"hello client");
    }

    /// Round-trip every suite the compiled backend serves. Which those are is backend-dependent, so
    /// the test asserts that *something* ran rather than hard-coding a list per feature.
    #[test]
    fn roundtrip_every_supported_suite() {
        let mut ran = Vec::new();
        for &suite in ALL_SUITES {
            if suite_provider(suite).is_some() {
                roundtrip(suite);
                ran.push(suite);
            }
        }
        assert!(
            ran.contains(&UNIVERSAL_SUITE),
            "P384_AES256 must be servable by every backend; ran {ran:#06x?}"
        );
    }

    #[test]
    fn unknown_suite_has_no_provider() {
        assert!(suite_provider(0xffff).is_none());
    }

    #[test]
    fn seq_is_monotonic_across_rekey() {
        let nh = suite_provider(UNIVERSAL_SUITE).unwrap().kdf_extract_size();
        let (mut client, mut server) = pair(UNIVERSAL_SUITE, &vec![0x11u8; nh], &vec![0x22u8; nh]);

        // Two records at epoch 1, then rekey the send direction and send another; the receiver must
        // track the same (monotonic) sequence after applying the matching rekey.
        for msg in [b"one".as_slice(), b"two".as_slice()] {
            let r = client.encrypt(ContentType::ApplicationData, msg).unwrap();
            assert_eq!(server.decrypt(&r[0]).unwrap().fragment, msg);
        }
        let new_client_secret = vec![0x33u8; nh];
        client
            .apply_rekey(
                DirectionalRekey::InitiatorSecret(new_client_secret.clone()),
                Role::Client,
            )
            .unwrap();
        server
            .apply_rekey(
                DirectionalRekey::InitiatorSecret(new_client_secret),
                Role::Server,
            )
            .unwrap();
        let r = client
            .encrypt(ContentType::ApplicationData, b"three")
            .unwrap();
        assert_eq!(server.decrypt(&r[0]).unwrap().fragment, b"three");
    }

    #[test]
    fn oversized_plaintext_is_fragmented() {
        let nh = suite_provider(UNIVERSAL_SUITE).unwrap().kdf_extract_size();
        let (mut client, mut server) = pair(UNIVERSAL_SUITE, &vec![0x11u8; nh], &vec![0x22u8; nh]);
        let plaintext = vec![0xa5; MAX_INNER_PLAINTEXT_LEN + 1];

        let records = client
            .encrypt(ContentType::ApplicationData, &plaintext)
            .unwrap();

        assert_eq!(records.len(), 2);
        assert!(
            records
                .iter()
                .all(|record| record.len() <= u16::MAX as usize)
        );

        let mut decrypted = Vec::new();
        for record in records {
            decrypted.extend(server.decrypt(&record).unwrap().fragment);
        }
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn nonce_xor() {
        let iv = [0u8; NONCE_LEN];
        assert_eq!(make_nonce(&iv, 0), [0u8; NONCE_LEN]);
        let mut expected = [0u8; NONCE_LEN];
        expected[NONCE_LEN - 1] = 1;
        assert_eq!(make_nonce(&iv, 1), expected);
    }
}
