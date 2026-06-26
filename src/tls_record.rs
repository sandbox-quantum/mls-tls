// TLS 1.3 Record Layer (RFC 8446 §5)
//

use aes_gcm::{Aes128Gcm, KeyInit, Nonce, aead::AeadInPlace};
use hkdf::Hkdf;
use sha2::Sha256;

// RFC 8446 §5.1:
//
// enum {
//     invalid(0),
//     change_cipher_spec(20),
//     alert(21),
//     handshake(22),
//     application_data(23),
//     (255)
// } ContentType;
//
// IMPLEMENTOR'S NOTE (draft-kohbrok-mls-tls-00 §5): Post-handshake, the record layer carries
// both ApplicationData (for application traffic) and Handshake (for in-band MLS
// ConnectionUpdate/EpochKeyUpdate messages per §4). No other content types should appear.
//
// IMPLEMENTOR'S NOTE (draft-kohbrok-mls-tls-00 §4): "TODO: The two-party profile I-D should
// define a message similar to [RFC9420]'s MLSMessage..." — the serialization format for
// ConnectionUpdate/EpochKeyUpdate is not yet defined. The record layer carries these as opaque
// Handshake-typed payloads.
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

// RFC 8446 §5.1:
//
// struct {
//     ContentType type;
//     ProtocolVersion legacy_record_version;
//     uint16 length;
//     opaque fragment[TLSPlaintext.length];
// } TLSPlaintext;
#[derive(Debug)]
pub struct TlsPlaintext {
    pub content_type: ContentType,
    pub fragment: Vec<u8>,
}

// RFC 8446 §5.2:
//
// struct {
//     opaque content[TLSPlaintext.length];
//     ContentType type;
//     uint8 zeros[length_of_padding];
// } TLSInnerPlaintext;
//
// struct {
//     ContentType opaque_type = application_data; /* 23 */
//     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
//     uint16 length;
//     opaque encrypted_record[TLSCiphertext.length];
// } TLSCiphertext;

#[derive(Debug)]
pub enum RecordError {
    PayloadTooLarge,
    RecordOverflow,
    InvalidHeader,
    DecryptionFailed,
    InvalidContentType(u8),
    EmptyInnerPlaintext,
    SequenceNumberOverflow,
    HkdfExpandError,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::PayloadTooLarge => write!(f, "plaintext exceeds 2^14 bytes"),
            RecordError::RecordOverflow => write!(f, "ciphertext exceeds 2^14 + 256 bytes"),
            RecordError::InvalidHeader => write!(f, "invalid TLS record header"),
            RecordError::DecryptionFailed => write!(f, "AEAD decryption failed"),
            RecordError::InvalidContentType(v) => write!(f, "invalid content type: {v}"),
            RecordError::EmptyInnerPlaintext => write!(f, "decrypted payload is all zeros"),
            RecordError::SequenceNumberOverflow => write!(f, "sequence number would overflow"),
            RecordError::HkdfExpandError => write!(f, "HKDF expand failed"),
        }
    }
}

impl std::error::Error for RecordError {}

// RFC 8446 §5.1:
// > "The length MUST NOT exceed 2^14 bytes."
const MAX_PLAINTEXT_LEN: usize = 16384;

// RFC 8446 §5.2:
// > "The length MUST NOT exceed 2^14 + 256 bytes."
const MAX_CIPHERTEXT_LEN: usize = 16640;

const TLS_RECORD_HEADER_LEN: usize = 5;
const AES_128_GCM_TAG_LEN: usize = 16;

// RFC 8446 §5.2:
// > "The legacy_record_version field is always 0x0303."
const LEGACY_RECORD_VERSION: [u8; 2] = [0x03, 0x03];

// RFC 8446 §5.3:
// > "Because the size of sequence numbers is 64-bit, they should not wrap. If a TLS
// >  implementation would need to wrap a sequence number, it MUST either rekey
// >  (Section 4.6.3) or terminate the connection."
const SEQ_NUM_LIMIT: u64 = u64::MAX - 1;

// ---------------------------------------------------------------------------
// HKDF abstraction
// ---------------------------------------------------------------------------

// RFC 8446 §7.1 — Key Schedule:
//
// > "HKDF-Expand-Label(Secret, Label, Context, Length) =
// >     HKDF-Expand(Secret, HkdfLabel, Length)
// >
// > Where HkdfLabel is specified as:
// >
// > struct {
// >     uint16 length = Length;
// >     opaque label<7..255> = "tls13 " + Label;
// >     opaque context<0..255> = Context;
// > } HkdfLabel;"

pub trait HkdfExpander: Send + Sync {
    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), RecordError>;
    fn hash_len(&self) -> usize;
}

pub struct HkdfExpanderSha256 {
    hkdf: Hkdf<Sha256>,
}

impl HkdfExpanderSha256 {
    pub fn from_prk(prk: &[u8]) -> Self {
        Self {
            hkdf: Hkdf::<Sha256>::from_prk(prk).expect("PRK must be hash-length (32 bytes)"),
        }
    }
}

impl HkdfExpander for HkdfExpanderSha256 {
    fn expand(&self, info: &[u8], output: &mut [u8]) -> Result<(), RecordError> {
        self.hkdf
            .expand(info, output)
            .map_err(|_| RecordError::HkdfExpandError)
    }

    fn hash_len(&self) -> usize {
        32
    }
}

// RFC 8446 §7.1 — HKDF-Expand-Label:
//
// > "HKDF-Expand-Label(Secret, Label, Context, Length) =
// >     HKDF-Expand(Secret, HkdfLabel, Length)"
//
// The HkdfLabel info is built from borrowed slices
// and flattened into a single Vec for the expand call.
fn hkdf_expand_label<const N: usize>(
    expander: &dyn HkdfExpander,
    label: &[u8],
    context: &[u8],
) -> [u8; N] {
    const LABEL_PREFIX: &[u8] = b"tls13 ";

    let output_len = (N as u16).to_be_bytes();
    let label_len = [(LABEL_PREFIX.len() + label.len()) as u8];
    let context_len = [context.len() as u8];

    let info: &[&[u8]] = &[
        &output_len,
        &label_len,
        LABEL_PREFIX,
        label,
        &context_len,
        context,
    ];
    let info_bytes: Vec<u8> = info.iter().flat_map(|s| s.iter().copied()).collect();

    let mut okm = [0u8; N];
    expander
        .expand(&info_bytes, &mut okm)
        .expect("N is a valid output length");
    okm
}

pub enum Role {
    Client,
    Server,
}

pub trait MessageEncrypter: Send + Sync {
    fn encrypt(
        &self,
        content_type: ContentType,
        plaintext: &[u8],
        seq: u64,
    ) -> Result<Vec<u8>, RecordError>;

    fn encrypted_payload_len(&self, payload_len: usize) -> usize;
}

pub trait MessageDecrypter: Send + Sync {
    fn decrypt(&self, record: &[u8], seq: u64) -> Result<TlsPlaintext, RecordError>;
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

// RFC 8446 §5.3 — Per-Record Nonce:
//
// > "1. The 64-bit record sequence number is encoded in network byte order and
// >     padded to the left with zeros to iv_length."
// > "2. The padded sequence number is XORed with either the static
// >     client_write_iv or server_write_iv (depending on the role)."
// > "The resulting quantity (of length iv_length) is used as the per-record nonce."
fn make_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let seq_bytes = seq.to_be_bytes();
    for i in 0..8 {
        nonce[12 - 8 + i] ^= seq_bytes[i];
    }
    nonce
}

// RFC 8446 §5.2:
// > "additional_data = TLSCiphertext.opaque_type ||
// >                    TLSCiphertext.legacy_record_version ||
// >                    TLSCiphertext.length"
// > "The outer opaque_type field of a TLSCiphertext record is always set to the
// >  value 23 (application_data)"
// > "The legacy_record_version field is always 0x0303."
fn make_tls13_aad(payload_len: usize) -> [u8; 5] {
    [
        ContentType::ApplicationData as u8,
        LEGACY_RECORD_VERSION[0],
        LEGACY_RECORD_VERSION[1],
        (payload_len >> 8) as u8,
        (payload_len & 0xff) as u8,
    ]
}

// RFC 8446 §5.4 — Record Padding:
//
// > "the receiving implementation scans the field from the end toward the
// >  beginning until it finds a non-zero octet. This non-zero octet is the
// >  content type of the message."
// > "If a receiving implementation does not find a non-zero octet in the
// >  cleartext, it MUST terminate the connection with an 'unexpected_message'
// >  alert."
fn unpad_tls13(decrypted: &mut Vec<u8>) -> Result<ContentType, RecordError> {
    while let Some(&0) = decrypted.last() {
        decrypted.pop();
    }
    let content_type_byte = decrypted.pop().ok_or(RecordError::EmptyInnerPlaintext)?;
    ContentType::try_from(content_type_byte)
}

// ---------------------------------------------------------------------------
// Concrete AES-128-GCM implementation
// ---------------------------------------------------------------------------

// IMPLEMENTOR'S NOTE (draft-kohbrok-mls-tls-00 §6): The draft doesn't specify how MLS cipher
// suites map to TLS AEAD algorithms. We assume MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
// → TLS_AES_128_GCM_SHA256 (AES-128-GCM with 16-byte key, 12-byte IV, 16-byte tag).
pub struct Tls13Aes128GcmEncrypter {
    cipher: Aes128Gcm,
    iv: [u8; 12],
}

impl Tls13Aes128GcmEncrypter {
    pub fn new(key: &[u8; 16], iv: [u8; 12]) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(key).expect("key length is 16"),
            iv,
        }
    }
}

impl MessageEncrypter for Tls13Aes128GcmEncrypter {
    // Encryption flow per RFC 8446 §5.2:
    //
    // > "AEADEncrypted =
    // >     AEAD-Encrypt(write_key, nonce, additional_data, plaintext)"
    // > "The encrypted_record field of TLSCiphertext is set to AEADEncrypted."
    fn encrypt(
        &self,
        content_type: ContentType,
        plaintext: &[u8],
        seq: u64,
    ) -> Result<Vec<u8>, RecordError> {
        debug_assert!(
            plaintext.len() <= MAX_PLAINTEXT_LEN,
            "RecordLayer must pre-chunk plaintext to ≤ 2^14 bytes"
        );

        // §5.2 — Build TLSInnerPlaintext:
        // struct { opaque content[...]; ContentType type; uint8 zeros[...]; }
        // "An unpadded record is just a record with a padding length of zero." (§5.4)
        let mut buf = Vec::with_capacity(plaintext.len() + 1 + AES_128_GCM_TAG_LEN);
        buf.extend_from_slice(plaintext);
        buf.push(content_type as u8);

        // §5.3 — Per-record nonce
        let nonce_bytes = make_nonce(&self.iv, seq);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // §5.2 — additional_data = opaque_type || legacy_record_version || length
        let ciphertext_len = buf.len() + AES_128_GCM_TAG_LEN;
        let aad = make_tls13_aad(ciphertext_len);

        // §5.2 — AEAD-Encrypt(write_key, nonce, additional_data, plaintext)
        self.cipher
            .encrypt_in_place(nonce, &aad, &mut buf)
            .map_err(|_| RecordError::DecryptionFailed)?;

        // Prepend the 5-byte TLSCiphertext header
        let mut record = Vec::with_capacity(TLS_RECORD_HEADER_LEN + buf.len());
        record.extend_from_slice(&aad);
        record.extend_from_slice(&buf);

        Ok(record)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        // content + 1 byte content_type + 16 byte tag
        payload_len + 1 + AES_128_GCM_TAG_LEN
    }
}

pub struct Tls13Aes128GcmDecrypter {
    cipher: Aes128Gcm,
    iv: [u8; 12],
}

impl Tls13Aes128GcmDecrypter {
    pub fn new(key: &[u8; 16], iv: [u8; 12]) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(key).expect("key length is 16"),
            iv,
        }
    }
}

impl MessageDecrypter for Tls13Aes128GcmDecrypter {
    // Decryption flow per RFC 8446 §5.2:
    //
    // > "plaintext of encrypted_record =
    // >     AEAD-Decrypt(peer_write_key, nonce, additional_data, AEADEncrypted)"
    // > "If the decryption fails, the receiver MUST terminate the connection with a
    // >  'bad_record_mac' alert."
    fn decrypt(&self, record: &[u8], seq: u64) -> Result<TlsPlaintext, RecordError> {
        // Parse the 5-byte TLSCiphertext header
        // §5.2: "ContentType opaque_type = application_data; /* 23 */"
        // §5.2: "ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */"
        if record.len() < TLS_RECORD_HEADER_LEN {
            return Err(RecordError::InvalidHeader);
        }
        if record[0] != ContentType::ApplicationData as u8 {
            return Err(RecordError::InvalidHeader);
        }
        if record[1..3] != LEGACY_RECORD_VERSION {
            return Err(RecordError::InvalidHeader);
        }

        let length = u16::from_be_bytes([record[3], record[4]]) as usize;

        // §5.2: "An endpoint that receives a record from its peer with
        //  TLSCiphertext.length larger than 2^14 + 256 octets MUST terminate the
        //  connection with a 'record_overflow' alert."
        if length > MAX_CIPHERTEXT_LEN {
            return Err(RecordError::RecordOverflow);
        }
        if record.len() != TLS_RECORD_HEADER_LEN + length {
            return Err(RecordError::InvalidHeader);
        }

        // §5.3 — Per-record nonce
        let nonce_bytes = make_nonce(&self.iv, seq);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // §5.2 — "the additional data input is the record header"
        let aad = &record[..TLS_RECORD_HEADER_LEN];

        // §5.2 — AEAD-Decrypt(peer_write_key, nonce, additional_data, AEADEncrypted)
        let mut buf = record[TLS_RECORD_HEADER_LEN..].to_vec();
        self.cipher
            .decrypt_in_place(nonce, aad, &mut buf)
            .map_err(|_| RecordError::DecryptionFailed)?;

        // §5.4 — "the receiving implementation scans the field from the end toward the
        //  beginning until it finds a non-zero octet. This non-zero octet is the content
        //  type of the message."
        let content_type = unpad_tls13(&mut buf)?;

        Ok(TlsPlaintext {
            content_type,
            fragment: buf,
        })
    }
}

// ---------------------------------------------------------------------------
// RecordLayer — owns sequence numbers, delegates crypto to trait objects
// ---------------------------------------------------------------------------

// IMPLEMENTOR'S NOTE (draft-kohbrok-mls-two-party-profile-00 §4): Neither draft specifies
// whether sequence numbers reset to 0 on epoch change. We follow RFC 8446 §4.6.3: new traffic
// keys = sequence number resets to 0.
//
// IMPLEMENTOR'S NOTE (draft-kohbrok-mls-two-party-profile-00 §4): "A party sending a
// ConnectionUpdate MUST wait until they receive the corresponding EpochKeyUpdate before they
// start using the key material of the new epoch." The draft says when to *use* new keys but not
// when to *derive* them. We derive immediately on epoch change but defer usage until
// EpochKeyUpdate is received.
pub struct RecordLayer {
    encrypter: Box<dyn MessageEncrypter>,
    decrypter: Box<dyn MessageDecrypter>,
    write_seq: u64,
    read_seq: u64,
}

impl RecordLayer {
    // RFC 8446 §5.3:
    // > "Each sequence number is set to zero at the beginning of a connection and
    // >  whenever the key is changed; the first record transmitted under a particular
    // >  traffic key MUST use sequence number 0."
    pub fn new(encrypter: Box<dyn MessageEncrypter>, decrypter: Box<dyn MessageDecrypter>) -> Self {
        Self {
            encrypter,
            decrypter,
            write_seq: 0,
            read_seq: 0,
        }
    }

    // RFC 8446 §7.3 — Traffic Key Calculation:
    //
    // > "[sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)"
    // > "[sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)"
    pub fn from_traffic_secrets(
        client_expander: &dyn HkdfExpander,
        server_expander: &dyn HkdfExpander,
        role: Role,
    ) -> Self {
        let (write_exp, read_exp) = match role {
            Role::Client => (client_expander, server_expander),
            Role::Server => (server_expander, client_expander),
        };

        let write_key: [u8; 16] = hkdf_expand_label(write_exp, b"key", b"");
        let write_iv: [u8; 12] = hkdf_expand_label(write_exp, b"iv", b"");
        let read_key: [u8; 16] = hkdf_expand_label(read_exp, b"key", b"");
        let read_iv: [u8; 12] = hkdf_expand_label(read_exp, b"iv", b"");

        RecordLayer::new(
            Box::new(Tls13Aes128GcmEncrypter::new(&write_key, write_iv)),
            Box::new(Tls13Aes128GcmDecrypter::new(&read_key, read_iv)),
        )
    }

    // RFC 8446 §5.1:
    // > "The record layer fragments information blocks into TLSPlaintext records
    // >  carrying data in chunks of 2^14 bytes or less."
    //
    // Returns one wire-format record per chunk. Each chunk gets its own sequence
    // number and is independently encrypted.
    pub fn encrypt(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> Result<Vec<Vec<u8>>, RecordError> {
        // §5.1: "Zero-length fragments of Application Data MAY be sent"
        let chunks: Box<dyn Iterator<Item = &[u8]>> = if plaintext.is_empty() {
            Box::new(std::iter::once(&[][..]))
        } else {
            Box::new(plaintext.chunks(MAX_PLAINTEXT_LEN))
        };

        let mut records = Vec::new();
        for chunk in chunks {
            // §5.3: "If a TLS implementation would need to wrap a sequence number, it MUST
            //  either rekey (Section 4.6.3) or terminate the connection."
            if self.write_seq >= SEQ_NUM_LIMIT {
                return Err(RecordError::SequenceNumberOverflow);
            }

            let record = self
                .encrypter
                .encrypt(content_type, chunk, self.write_seq)?;

            // §5.3: "The appropriate sequence number is incremented by one after reading or
            //  writing each record."
            self.write_seq += 1;

            records.push(record);
        }
        Ok(records)
    }

    pub fn decrypt(&mut self, record: &[u8]) -> Result<TlsPlaintext, RecordError> {
        // §5.3: sequence number overflow check
        if self.read_seq >= SEQ_NUM_LIMIT {
            return Err(RecordError::SequenceNumberOverflow);
        }

        let plaintext = self.decrypter.decrypt(record, self.read_seq)?;

        // §5.3: "The appropriate sequence number is incremented by one after reading or
        //  writing each record."
        self.read_seq += 1;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let hex_raw = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        hex::decode(&hex_raw).unwrap()
    }

    // RFC 8448 §3 — Simple 1-RTT Handshake, server application data (seq = 1)
    // seq=1 because seq=0 was consumed by the NewSessionTicket handshake record
    #[test]
    fn test_rfc8448_server_encrypt() {
        let key: [u8; 16] = hex("9f02283b6c9c07efc26bb9f2ac92e356").try_into().unwrap();
        let iv: [u8; 12] = hex("cf782b88dd83549aadf1e984").try_into().unwrap();
        let plaintext = hex(
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e
             0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23
             24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31",
        );
        let expected_record = hex(
            "17 03 03 00 43 2e 93 7e 11 ef 4a c7
             40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f
             82 aa 1b 36 e3 0e fa f9 7d 90 e6 df fc 60 2d cb
             50 1a 59 a8 fc c4 9c 4b f2 e5 f0 a2 1c 00 47 c2
             ab f3 32 54 0d d0 32 e1 67 c2 95 5d",
        );

        let encrypter = Tls13Aes128GcmEncrypter::new(&key, iv);
        let record = encrypter
            .encrypt(ContentType::ApplicationData, &plaintext, 1)
            .unwrap();

        assert_eq!(record, expected_record);
    }

    // RFC 8448 §3 — Simple 1-RTT Handshake, client application data (seq = 0)
    #[test]
    fn test_rfc8448_client_encrypt() {
        let key: [u8; 16] = hex("17422dda596ed5d9acd890e3c63f5051").try_into().unwrap();
        let iv: [u8; 12] = hex("5b78923dee08579033e523d9").try_into().unwrap();
        let plaintext = hex(
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e
             0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23
             24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31",
        );
        let expected_record = hex(
            "17 03 03 00 43 a2 3f 70 54 b6 2c 94
             d0 af fa fe 82 28 ba 55 cb ef ac ea 42 f9 14 aa
             66 bc ab 3f 2b 98 19 a8 a5 b4 6b 39 5b d5 4a 9a
             20 44 1e 2b 62 97 4e 1f 5a 62 92 a2 97 70 14 bd
             1e 3d ea e6 3a ee bb 21 69 49 15 e4",
        );

        let encrypter = Tls13Aes128GcmEncrypter::new(&key, iv);
        let record = encrypter
            .encrypt(ContentType::ApplicationData, &plaintext, 0)
            .unwrap();

        assert_eq!(record, expected_record);
    }

    // RFC 8448 §3 — decrypt server record (seq = 1)
    #[test]
    fn test_rfc8448_server_decrypt() {
        let key: [u8; 16] = hex("9f02283b6c9c07efc26bb9f2ac92e356").try_into().unwrap();
        let iv: [u8; 12] = hex("cf782b88dd83549aadf1e984").try_into().unwrap();
        let record = hex(
            "17 03 03 00 43 2e 93 7e 11 ef 4a c7
             40 e5 38 ad 36 00 5f c4 a4 69 32 fc 32 25 d0 5f
             82 aa 1b 36 e3 0e fa f9 7d 90 e6 df fc 60 2d cb
             50 1a 59 a8 fc c4 9c 4b f2 e5 f0 a2 1c 00 47 c2
             ab f3 32 54 0d d0 32 e1 67 c2 95 5d",
        );
        let expected_plaintext = hex(
            "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e
             0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23
             24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31",
        );

        let decrypter = Tls13Aes128GcmDecrypter::new(&key, iv);
        let result = decrypter.decrypt(&record, 1).unwrap();

        assert_eq!(result.content_type, ContentType::ApplicationData);
        assert_eq!(result.fragment, expected_plaintext);
    }

    #[test]
    fn test_round_trip() {
        let key: [u8; 16] = [0x42; 16];
        let iv: [u8; 12] = [0x13; 12];

        let mut layer = RecordLayer::new(
            Box::new(Tls13Aes128GcmEncrypter::new(&key, iv)),
            Box::new(Tls13Aes128GcmDecrypter::new(&key, iv)),
        );

        let plaintext = b"hello from the record layer";
        let records = layer
            .encrypt(ContentType::ApplicationData, plaintext)
            .unwrap();
        assert_eq!(records.len(), 1);
        let result = layer.decrypt(&records[0]).unwrap();

        assert_eq!(result.content_type, ContentType::ApplicationData);
        assert_eq!(result.fragment, plaintext);
    }

    #[test]
    fn test_round_trip_handshake_content_type() {
        let key: [u8; 16] = [0x42; 16];
        let iv: [u8; 12] = [0x13; 12];

        let mut layer = RecordLayer::new(
            Box::new(Tls13Aes128GcmEncrypter::new(&key, iv)),
            Box::new(Tls13Aes128GcmDecrypter::new(&key, iv)),
        );

        let plaintext = b"mls connection update payload";
        let records = layer.encrypt(ContentType::Handshake, plaintext).unwrap();
        assert_eq!(records.len(), 1);
        let result = layer.decrypt(&records[0]).unwrap();

        assert_eq!(result.content_type, ContentType::Handshake);
        assert_eq!(result.fragment, plaintext);
    }

    #[test]
    fn test_multi_record_sequence() {
        let key: [u8; 16] = [0xAA; 16];
        let iv: [u8; 12] = [0xBB; 12];

        let mut layer = RecordLayer::new(
            Box::new(Tls13Aes128GcmEncrypter::new(&key, iv)),
            Box::new(Tls13Aes128GcmDecrypter::new(&key, iv)),
        );

        let mut all_records = Vec::new();
        for i in 0u8..3 {
            let msg = vec![i; 100];
            let records = layer.encrypt(ContentType::ApplicationData, &msg).unwrap();
            assert_eq!(records.len(), 1);
            all_records.push(records.into_iter().next().unwrap());
        }

        for (i, record) in all_records.iter().enumerate() {
            let result = layer.decrypt(record).unwrap();
            assert_eq!(result.content_type, ContentType::ApplicationData);
            assert_eq!(result.fragment, vec![i as u8; 100]);
        }
    }

    // RFC 8446 §5.1: "fragments information blocks into TLSPlaintext records
    //  carrying data in chunks of 2^14 bytes or less"
    #[test]
    fn test_fragmentation_large_payload() {
        let key: [u8; 16] = [0x42; 16];
        let iv: [u8; 12] = [0x13; 12];

        let mut layer = RecordLayer::new(
            Box::new(Tls13Aes128GcmEncrypter::new(&key, iv)),
            Box::new(Tls13Aes128GcmDecrypter::new(&key, iv)),
        );

        let plaintext: Vec<u8> = (0u8..=255).cycle().take(40960).collect();
        let records = layer
            .encrypt(ContentType::ApplicationData, &plaintext)
            .unwrap();

        assert_eq!(records.len(), 3);

        let mut reassembled = Vec::new();
        for record in &records {
            let result = layer.decrypt(record).unwrap();
            assert_eq!(result.content_type, ContentType::ApplicationData);
            reassembled.extend_from_slice(&result.fragment);
        }
        assert_eq!(reassembled, plaintext);
    }

    // RFC 8446 §5.1: "Zero-length fragments of Application Data MAY be sent"
    #[test]
    fn test_empty_payload() {
        let key: [u8; 16] = [0x42; 16];
        let iv: [u8; 12] = [0x13; 12];

        let mut layer = RecordLayer::new(
            Box::new(Tls13Aes128GcmEncrypter::new(&key, iv)),
            Box::new(Tls13Aes128GcmDecrypter::new(&key, iv)),
        );

        let records = layer
            .encrypt(ContentType::ApplicationData, b"")
            .unwrap();
        assert_eq!(records.len(), 1);

        let result = layer.decrypt(&records[0]).unwrap();
        assert_eq!(result.content_type, ContentType::ApplicationData);
        assert!(result.fragment.is_empty());
    }

    #[test]
    fn test_exact_max_plaintext_no_split() {
        let key: [u8; 16] = [0x42; 16];
        let iv: [u8; 12] = [0x13; 12];

        let mut layer = RecordLayer::new(
            Box::new(Tls13Aes128GcmEncrypter::new(&key, iv)),
            Box::new(Tls13Aes128GcmDecrypter::new(&key, iv)),
        );

        let plaintext = vec![0xAB; MAX_PLAINTEXT_LEN];
        let records = layer
            .encrypt(ContentType::ApplicationData, &plaintext)
            .unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn test_reject_truncated_record() {
        let key: [u8; 16] = [0; 16];
        let iv: [u8; 12] = [0; 12];
        let decrypter = Tls13Aes128GcmDecrypter::new(&key, iv);

        let result = decrypter.decrypt(&[0x17, 0x03], 0);
        assert!(matches!(result, Err(RecordError::InvalidHeader)));
    }

    #[test]
    fn test_reject_tampered_ciphertext() {
        let key: [u8; 16] = [0x42; 16];
        let iv: [u8; 12] = [0x13; 12];
        let encrypter = Tls13Aes128GcmEncrypter::new(&key, iv);
        let decrypter = Tls13Aes128GcmDecrypter::new(&key, iv);

        let mut record = encrypter
            .encrypt(ContentType::ApplicationData, b"secret data", 0)
            .unwrap();

        // Flip a byte in the ciphertext
        record[10] ^= 0xff;

        let result = decrypter.decrypt(&record, 0);
        assert!(matches!(result, Err(RecordError::DecryptionFailed)));
    }

    #[test]
    fn test_reject_bad_header_version() {
        let key: [u8; 16] = [0; 16];
        let iv: [u8; 12] = [0; 12];
        let decrypter = Tls13Aes128GcmDecrypter::new(&key, iv);

        // Valid header structure but wrong version (0x0302 instead of 0x0303)
        let mut record = vec![0x17, 0x03, 0x02, 0x00, 0x11];
        record.extend_from_slice(&[0u8; 17]);
        let result = decrypter.decrypt(&record, 0);
        assert!(matches!(result, Err(RecordError::InvalidHeader)));
    }

    #[test]
    fn test_nonce_construction() {
        let iv: [u8; 12] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        ];

        // seq=0: nonce should equal IV
        assert_eq!(make_nonce(&iv, 0), iv);

        // seq=1: last byte XORed with 1
        let expected = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0a,
        ];
        assert_eq!(make_nonce(&iv, 1), expected);

        // seq=256: second-to-last byte XORed with 1
        let expected = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0b,
        ];
        assert_eq!(make_nonce(&iv, 256), expected);
    }

    // RFC 8448 §3 — verify HKDF-Expand-Label derives the correct key and iv
    // from the server application traffic secret
    #[test]
    fn test_rfc8448_hkdf_expand_label_server_key() {
        let server_traffic_secret = hex(
            "a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32
             82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43",
        );
        let expected_key = hex("9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56");
        let expected_iv = hex("cf 78 2b 88 dd 83 54 9a ad f1 e9 84");

        let expander = HkdfExpanderSha256::from_prk(&server_traffic_secret);
        let key: [u8; 16] = hkdf_expand_label(&expander, b"key", b"");
        let iv: [u8; 12] = hkdf_expand_label(&expander, b"iv", b"");

        assert_eq!(key.as_slice(), &expected_key);
        assert_eq!(iv.as_slice(), &expected_iv);
    }

    // RFC 8448 §3 — verify HKDF-Expand-Label derives the correct key and iv
    // from the client application traffic secret
    #[test]
    fn test_rfc8448_hkdf_expand_label_client_key() {
        let client_traffic_secret = hex(
            "9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52
             87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5",
        );
        let expected_key = hex("17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51");
        let expected_iv = hex("5b 78 92 3d ee 08 57 90 33 e5 23 d9");

        let expander = HkdfExpanderSha256::from_prk(&client_traffic_secret);
        let key: [u8; 16] = hkdf_expand_label(&expander, b"key", b"");
        let iv: [u8; 12] = hkdf_expand_label(&expander, b"iv", b"");

        assert_eq!(key.as_slice(), &expected_key);
        assert_eq!(iv.as_slice(), &expected_iv);
    }

    // Round-trip test: build RecordLayer from traffic secrets, encrypt as
    // client, decrypt as server
    #[test]
    fn test_from_traffic_secrets_round_trip() {
    let client_secret = [0xAA; 32];
        let server_secret = [0xBB; 32];

        let client_exp = HkdfExpanderSha256::from_prk(&client_secret);
        let server_exp = HkdfExpanderSha256::from_prk(&server_secret);

        let mut client_layer =
            RecordLayer::from_traffic_secrets(&client_exp, &server_exp, Role::Client);

        let client_exp = HkdfExpanderSha256::from_prk(&client_secret);
        let server_exp = HkdfExpanderSha256::from_prk(&server_secret);

        let mut server_layer =
            RecordLayer::from_traffic_secrets(&client_exp, &server_exp, Role::Server);

        let plaintext = b"hello from client to server";
        let records = client_layer
            .encrypt(ContentType::ApplicationData, plaintext)
            .unwrap();
        assert_eq!(records.len(), 1);
        let result = server_layer.decrypt(&records[0]).unwrap();

        assert_eq!(result.content_type, ContentType::ApplicationData);
        assert_eq!(result.fragment, plaintext);

        let reply = b"hello from server to client";
        let records = server_layer
            .encrypt(ContentType::ApplicationData, reply)
            .unwrap();
        assert_eq!(records.len(), 1);
        let result = client_layer.decrypt(&records[0]).unwrap();

        assert_eq!(result.content_type, ContentType::ApplicationData);
        assert_eq!(result.fragment, reply);
    }
}
