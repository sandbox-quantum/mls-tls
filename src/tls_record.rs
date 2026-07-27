//! The application-data record layer, byte-aligned for interoperability.
//!
//! - Key/IV derivation adds an extra step: `dir_secret = HKDF-Expand-Label(traffic_secret,
//!   "<c|s> ap traffic", context, Nh)`, then `key = Expand-Label(dir_secret, "key", "", Nk)` and
//!   `iv = Expand-Label(dir_secret, "iv", "", 12)`. The `<c|s> ap traffic` context is `Nh` zero
//!   bytes at epoch 1 and empty at epoch ≥ 2.
//! - Sequence numbers are **monotonic across epochs** — a rekey rotates key/IV but does NOT reset
//!   the per-direction counter (only a fresh transport does).
//! - The AEAD record is `header || AES-GCM(nonce, plaintext || inner_type(0x17), aad=header)`,
//!   `nonce = iv XOR seq` in the low 8 bytes.
//!
//! The suite parameters (hash, AEAD, key length) are chosen per MLS cipher suite: the AES-GCM suites
//! map to their MLS hash + AES-GCM variant, and ChaCha20-Poly1305 MLS suites use the same hash with
//! ChaCha20-Poly1305 record protection.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use sha2::{Sha256, Sha384, Sha512};

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
    #[error("AEAD decryption failed")]
    DecryptionFailed,
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
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];
const SEQ_NUM_LIMIT: u64 = u64::MAX - 1;
const MAX_INNER_PLAINTEXT_LEN: usize = u16::MAX as usize - TLS_RECORD_HEADER_LEN - 1 - AEAD_TAG_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// Which hash + AEAD a cipher suite uses in the record layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SuiteParams {
    hash: HashKind,
    aead: AeadKind,
    /// AEAD key length (16 for AES-128, 32 for AES-256/ChaCha20-Poly1305).
    key_len: usize,
    /// Hash output length `Nh` (32 for SHA-256, 64 for SHA-512).
    nh: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AeadKind {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl SuiteParams {
    /// Record-layer parameters for the X-Wing suite (SHA-512 + AES-256-GCM).
    pub fn xwing() -> Self {
        Self {
            hash: HashKind::Sha512,
            aead: AeadKind::Aes256Gcm,
            key_len: 32,
            nh: 64,
        }
    }

    /// SHA-256 + AES-128-GCM (CURVE25519_AES128 / P256_AES128).
    pub fn sha256_aes128() -> Self {
        Self {
            hash: HashKind::Sha256,
            aead: AeadKind::Aes128Gcm,
            key_len: 16,
            nh: 32,
        }
    }

    /// SHA-256 + ChaCha20-Poly1305 (CURVE25519_CHACHA20POLY1305).
    pub fn sha256_chacha20poly1305() -> Self {
        Self {
            hash: HashKind::Sha256,
            aead: AeadKind::ChaCha20Poly1305,
            key_len: 32,
            nh: 32,
        }
    }

    /// SHA-384 + AES-256-GCM (P384_AES256).
    pub fn sha384_aes256() -> Self {
        Self {
            hash: HashKind::Sha384,
            aead: AeadKind::Aes256Gcm,
            key_len: 32,
            nh: 48,
        }
    }

    /// SHA-512 + AES-256-GCM (CURVE448_AES256 / P521_AES256).
    pub fn sha512_aes256() -> Self {
        Self {
            hash: HashKind::Sha512,
            aead: AeadKind::Aes256Gcm,
            key_len: 32,
            nh: 64,
        }
    }

    /// SHA-512 + ChaCha20-Poly1305 (CURVE448_CHACHA20POLY1305).
    pub fn sha512_chacha20poly1305() -> Self {
        Self {
            hash: HashKind::Sha512,
            aead: AeadKind::ChaCha20Poly1305,
            key_len: 32,
            nh: 64,
        }
    }

    /// Choose parameters for an MLS cipher suite (raw u16 id).
    ///
    /// Covers the standard MLS suites plus X-Wing. Unknown suites are rejected instead of silently
    /// selecting a different record-protection algorithm.
    pub fn for_cipher_suite(raw: u16) -> Result<Self, RecordError> {
        match raw {
            // CURVE25519_AES128 (0x0001), P256_AES128 (0x0002)
            0x0001 | 0x0002 => Ok(Self::sha256_aes128()),
            // CURVE25519_CHACHA20POLY1305 (0x0003)
            0x0003 => Ok(Self::sha256_chacha20poly1305()),
            // CURVE448_AES256 (0x0004), P521_AES256 (0x0005)
            0x0004 | 0x0005 => Ok(Self::sha512_aes256()),
            // CURVE448_CHACHA20POLY1305 (0x0006)
            0x0006 => Ok(Self::sha512_chacha20poly1305()),
            // P384_AES256 (0x0007)
            0x0007 => Ok(Self::sha384_aes256()),
            // X-Wing (0x004e)
            0x004e => Ok(Self::xwing()),
            other => Err(RecordError::UnsupportedCipherSuite(other)),
        }
    }
}

/// TLS-1.3 `HKDF-Expand-Label(secret, label, context, len)` with the `"tls13 "` prefix and 1-byte
/// length prefixes, over the given suite hash.
fn expand_label(
    params: &SuiteParams,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Vec<u8> {
    const LABEL_PREFIX: &[u8] = b"tls13 ";
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push((LABEL_PREFIX.len() + label.len()) as u8);
    info.extend_from_slice(LABEL_PREFIX);
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    let mut out = vec![0u8; len];
    match params.hash {
        HashKind::Sha256 => Hkdf::<Sha256>::from_prk(secret)
            .expect("valid PRK")
            .expand(&info, &mut out)
            .expect("valid length"),
        HashKind::Sha384 => Hkdf::<Sha384>::from_prk(secret)
            .expect("valid PRK")
            .expand(&info, &mut out)
            .expect("valid length"),
        HashKind::Sha512 => Hkdf::<Sha512>::from_prk(secret)
            .expect("valid PRK")
            .expand(&info, &mut out)
            .expect("valid length"),
    }
    out
}

/// Derive `(key, iv)` from a direction's traffic secret, per the Python `_derive_key_iv`.
fn derive_key_iv(
    params: &SuiteParams,
    traffic_secret: &[u8],
    dir_label: &[u8],
    epoch_one: bool,
) -> (Vec<u8>, [u8; 12]) {
    // Context quirk: 64 zero bytes at epoch 1, empty afterwards.
    let context = if epoch_one {
        vec![0u8; params.nh]
    } else {
        Vec::new()
    };
    let dir_secret = expand_label(params, traffic_secret, dir_label, &context, params.nh);
    let key = expand_label(params, &dir_secret, b"key", b"", params.key_len);
    let iv_vec = expand_label(params, &dir_secret, b"iv", b"", 12);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec);
    (key, iv)
}

/// An AEAD cipher (either AES-128-GCM or AES-256-GCM), holding its static IV and per-direction
/// sequence counter.
struct Direction {
    cipher: AeadCipher,
    iv: [u8; 12],
    seq: u64,
}

enum AeadCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl AeadCipher {
    fn new(kind: AeadKind, key: &[u8]) -> Self {
        match kind {
            AeadKind::Aes128Gcm => AeadCipher::Aes128(Box::new(
                Aes128Gcm::new_from_slice(key).expect("16-byte key"),
            )),
            AeadKind::Aes256Gcm => AeadCipher::Aes256(Box::new(
                Aes256Gcm::new_from_slice(key).expect("32-byte key"),
            )),
            AeadKind::ChaCha20Poly1305 => AeadCipher::ChaCha20Poly1305(Box::new(
                ChaCha20Poly1305::new_from_slice(key).expect("32-byte key"),
            )),
        }
    }

    fn seal_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        let nonce = Nonce::from_slice(nonce);
        let r = match self {
            AeadCipher::Aes128(c) => c.encrypt_in_place(nonce, aad, buf),
            AeadCipher::Aes256(c) => c.encrypt_in_place(nonce, aad, buf),
            AeadCipher::ChaCha20Poly1305(c) => c.encrypt_in_place(nonce, aad, buf),
        };
        r.map_err(|_| RecordError::DecryptionFailed)
    }

    fn open_in_place(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), RecordError> {
        let nonce = Nonce::from_slice(nonce);
        let r = match self {
            AeadCipher::Aes128(c) => c.decrypt_in_place(nonce, aad, buf),
            AeadCipher::Aes256(c) => c.decrypt_in_place(nonce, aad, buf),
            AeadCipher::ChaCha20Poly1305(c) => c.decrypt_in_place(nonce, aad, buf),
        };
        r.map_err(|_| RecordError::DecryptionFailed)
    }
}

/// `nonce = iv XOR seq`, seq big-endian in the low 8 bytes.
fn make_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
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
/// monotonic sequence number.
pub struct RecordLayer {
    params: SuiteParams,
    send: Direction,
    recv: Direction,
}

impl RecordLayer {
    /// Build both directions from the epoch's client/server application traffic secrets.
    /// `epoch_one` selects the `<c|s> ap traffic` context (64 zero bytes vs empty).
    pub fn from_traffic_secrets(
        params: SuiteParams,
        client_secret: &[u8],
        server_secret: &[u8],
        role: Role,
        epoch_one: bool,
    ) -> Self {
        let (client_key, client_iv) =
            derive_key_iv(&params, client_secret, b"c ap traffic", epoch_one);
        let (server_key, server_iv) =
            derive_key_iv(&params, server_secret, b"s ap traffic", epoch_one);

        let client_dir = Direction {
            cipher: AeadCipher::new(params.aead, &client_key),
            iv: client_iv,
            seq: 0,
        };
        let server_dir = Direction {
            cipher: AeadCipher::new(params.aead, &server_key),
            iv: server_iv,
            seq: 0,
        };

        let (send, recv) = match role {
            Role::Client => (client_dir, server_dir),
            Role::Server => (server_dir, client_dir),
        };
        Self { params, send, recv }
    }

    /// Rotate one or both directions from freshly-exported traffic secrets (epoch ≥ 2, so the
    /// `<c|s> ap traffic` context is empty). Sequence numbers are preserved (monotonic).
    pub fn apply_rekey(&mut self, update: DirectionalRekey, role: Role) {
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
                    self.rotate_send(&initiator, b"c ap traffic");
                    self.rotate_recv(&responder, b"s ap traffic");
                }
                Role::Server => {
                    self.rotate_send(&responder, b"s ap traffic");
                    self.rotate_recv(&initiator, b"c ap traffic");
                }
            },
        }
    }

    fn rotate_send(&mut self, secret: &[u8], dir_label: &[u8]) {
        let (key, iv) = derive_key_iv(&self.params, secret, dir_label, false);
        self.send.cipher = AeadCipher::new(self.params.aead, &key);
        self.send.iv = iv;
        // seq preserved (monotonic across epochs).
    }

    fn rotate_recv(&mut self, secret: &[u8], dir_label: &[u8]) {
        let (key, iv) = derive_key_iv(&self.params, secret, dir_label, false);
        self.recv.cipher = AeadCipher::new(self.params.aead, &key);
        self.recv.iv = iv;
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
            let mut buf = Vec::with_capacity(chunk.len() + 1 + AEAD_TAG_LEN);
            buf.extend_from_slice(chunk);
            buf.push(content_type as u8);

            let ct_len = buf.len() + AEAD_TAG_LEN;
            let aad = header(ct_len);
            let nonce = make_nonce(&self.send.iv, self.send.seq);
            self.send.cipher.seal_in_place(&nonce, &aad, &mut buf)?;
            self.send.seq += 1;

            let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + buf.len());
            record.extend_from_slice(&aad);
            record.extend_from_slice(&buf);
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
        let mut buf = record[TLS_RECORD_HEADER_LEN..].to_vec();
        self.recv.cipher.open_in_place(&nonce, aad, &mut buf)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(params: SuiteParams) {
        let client_secret = vec![0xAAu8; params.nh];
        let server_secret = vec![0xBBu8; params.nh];
        let mut client = RecordLayer::from_traffic_secrets(
            params,
            &client_secret,
            &server_secret,
            Role::Client,
            true,
        );
        let mut server = RecordLayer::from_traffic_secrets(
            params,
            &client_secret,
            &server_secret,
            Role::Server,
            true,
        );

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

    #[test]
    fn roundtrip_xwing() {
        roundtrip(SuiteParams::xwing());
    }

    #[test]
    fn roundtrip_sha256_aes128() {
        roundtrip(SuiteParams::sha256_aes128());
    }

    #[test]
    fn roundtrip_sha256_chacha20poly1305() {
        roundtrip(SuiteParams::sha256_chacha20poly1305());
    }

    #[test]
    fn roundtrip_sha384_aes256() {
        roundtrip(SuiteParams::sha384_aes256());
    }

    #[test]
    fn roundtrip_sha512_chacha20poly1305() {
        roundtrip(SuiteParams::sha512_chacha20poly1305());
    }

    #[test]
    fn cipher_suite_mapping_rejects_unknown_suites() {
        assert_eq!(
            SuiteParams::for_cipher_suite(0x0003).unwrap(),
            SuiteParams::sha256_chacha20poly1305()
        );
        assert_eq!(
            SuiteParams::for_cipher_suite(0x0006).unwrap(),
            SuiteParams::sha512_chacha20poly1305()
        );
        assert!(matches!(
            SuiteParams::for_cipher_suite(0xffff),
            Err(RecordError::UnsupportedCipherSuite(0xffff))
        ));
    }

    #[test]
    fn seq_is_monotonic_across_rekey() {
        let params = SuiteParams::xwing();
        let c = vec![0x11u8; 64];
        let s = vec![0x22u8; 64];
        let mut client = RecordLayer::from_traffic_secrets(params, &c, &s, Role::Client, true);
        let mut server = RecordLayer::from_traffic_secrets(params, &c, &s, Role::Server, true);

        // Two records at epoch 1, then rekey the send direction and send another; the receiver must
        // track the same (monotonic) sequence after applying the matching rekey.
        for msg in [b"one".as_slice(), b"two".as_slice()] {
            let r = client.encrypt(ContentType::ApplicationData, msg).unwrap();
            assert_eq!(server.decrypt(&r[0]).unwrap().fragment, msg);
        }
        let new_client_secret = vec![0x33u8; 64];
        client.apply_rekey(
            DirectionalRekey::InitiatorSecret(new_client_secret.clone()),
            Role::Client,
        );
        server.apply_rekey(
            DirectionalRekey::InitiatorSecret(new_client_secret),
            Role::Server,
        );
        let r = client
            .encrypt(ContentType::ApplicationData, b"three")
            .unwrap();
        assert_eq!(server.decrypt(&r[0]).unwrap().fragment, b"three");
    }

    #[test]
    fn oversized_plaintext_is_fragmented() {
        let params = SuiteParams::sha256_aes128();
        let c = vec![0x11u8; 32];
        let s = vec![0x22u8; 32];
        let mut client = RecordLayer::from_traffic_secrets(params, &c, &s, Role::Client, true);
        let mut server = RecordLayer::from_traffic_secrets(params, &c, &s, Role::Server, true);
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
        let iv = [0u8; 12];
        assert_eq!(make_nonce(&iv, 0), [0u8; 12]);
        let mut expected = [0u8; 12];
        expected[11] = 1;
        assert_eq!(make_nonce(&iv, 1), expected);
    }
}
