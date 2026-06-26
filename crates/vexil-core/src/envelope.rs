//! Versioned wire format with a Type-Length-Value (TLV) body.
//!
//! ```text
//!   offset  size  field        description
//!   0       5     magic        "VEXIL"
//!   5       1     version      0x01
//!   6       1     suite        algorithm suite id (see [`crate::Suite`])
//!   7       1     mode         operation mode (see [`Mode`])
//!   8       2     body_len     length of the TLV body, big-endian u16
//!   10      ...   tlv_body     a sequence of TLV entries
//! ```
//!
//! Each TLV entry is `type:u8 | len:u16 (BE) | value[len]`. The AEAD tag lives
//! at the tail of the ciphertext TLV (`0xFF`); the AEAD's AAD binds the header
//! plus every non-ciphertext TLV, so any tamper of suite, mode, salt, nonce, or
//! recipient data is caught on decrypt.
//!
//! The parser is a **single TLV walker** — there are no per-mode byte-level
//! branches. Modes differ only in which TLV types they expect, validated above
//! the byte layer.

use crate::error::{Result, VexilError};
use crate::suite::Suite;

/// 5-byte file magic.
pub const MAGIC: &[u8; 5] = b"VEXIL";
/// Protocol version byte.
pub const VERSION: u8 = 0x01;
/// Fixed header length (magic + version + suite + mode + body_len).
pub const HEADER_LEN: usize = 10;

// TLV type tags.
/// 16-byte Argon2id salt (symmetric mode).
pub const T_SALT: u8 = 0x01;
/// 12-byte AEAD nonce.
pub const T_NONCE: u8 = 0x02;
/// 32-byte X25519 ephemeral public key.
pub const T_EPHEMERAL_PK: u8 = 0x03;
/// 16-byte recipient fingerprint (multi-recipient).
pub const T_RECIPIENT_FPR: u8 = 0x04;
/// Wrapped per-recipient DEK stanza (multi-recipient).
pub const T_RECIPIENT_STANZA: u8 = 0x05;
/// 32-byte Ed25519 sender public key (signed mode).
pub const T_SENDER_PK: u8 = 0x06;
/// 64-byte Ed25519 signature (signed mode).
pub const T_SIGNATURE: u8 = 0x07;
/// ML-KEM-768 KEM ciphertext (PQ mode).
pub const T_MLKEM_CT: u8 = 0x08;
/// u32 chunk count (streaming mode).
pub const T_CHUNK_COUNT: u8 = 0x09;
/// Optional encrypted user metadata.
pub const T_METADATA: u8 = 0x0A;
/// i64 unix expiry timestamp, AAD-bound.
pub const T_EXPIRY: u8 = 0x0B;
/// Argon2id parameter set ID (1 byte: 0=default, 1=interactive, 2=sensitive).
pub const T_KDF_PRESET: u8 = 0x0E;
/// ML-DSA-65 sender public key (hybrid signed mode).
pub const T_SENDER_PK_PQ: u8 = 0x0C;
/// ML-DSA-65 signature (hybrid signed mode).
pub const T_SIGNATURE_PQ: u8 = 0x0D;
/// The ciphertext payload (AEAD ciphertext || tag).
pub const T_CIPHERTEXT: u8 = 0xFF;

/// Operation mode. Determines which TLV types are expected, not the byte layout.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// Password-based symmetric encryption (`VEX1-`).
    Symmetric = 0,
    /// Anonymous sealed box to a public key (`VEX1S-`).
    Sealed = 1,
    /// Signed sealed box (`VEX1A-`).
    Signed = 2,
    /// Multi-recipient (`VEX1M-`).
    MultiRecipient = 3,
    /// Streaming / framed (`VEX1F-`).
    Streaming = 4,
    /// Streaming sealed box to a public key (`VEX1SF-`).
    SealedStream = 5,
    /// Streaming signed sealed box (`VEX1AF-`).
    SignedStream = 6,
    /// Streaming multi-recipient (`VEX1MF-`).
    MultiStream = 7,
}

impl Mode {
    /// On-wire byte.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Parse from wire byte.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Mode::Symmetric),
            1 => Ok(Mode::Sealed),
            2 => Ok(Mode::Signed),
            3 => Ok(Mode::MultiRecipient),
            4 => Ok(Mode::Streaming),
            5 => Ok(Mode::SealedStream),
            6 => Ok(Mode::SignedStream),
            7 => Ok(Mode::MultiStream),
            other => Err(VexilError::UnknownMode(other)),
        }
    }

    /// Static name for diagnostics and `ModeMismatch`.
    pub fn name(self) -> &'static str {
        match self {
            Mode::Symmetric => "symmetric",
            Mode::Sealed => "sealed",
            Mode::Signed => "signed",
            Mode::MultiRecipient => "multi-recipient",
            Mode::Streaming => "streaming",
            Mode::SealedStream => "sealed-stream",
            Mode::SignedStream => "signed-stream",
            Mode::MultiStream => "multi-stream",
        }
    }
}

/// A single Type-Length-Value entry.
#[derive(Clone, Debug)]
pub struct Tlv {
    /// Type tag.
    pub typ: u8,
    /// Value bytes.
    pub val: Vec<u8>,
}

/// A parsed or in-construction VEXIL envelope.
#[derive(Clone, Debug)]
pub struct Envelope {
    /// Algorithm suite.
    pub suite: Suite,
    /// Operation mode.
    pub mode: Mode,
    /// TLV entries, in order.
    pub tlvs: Vec<Tlv>,
}

impl Envelope {
    /// Start a new empty envelope for a suite and mode.
    pub fn new(suite: Suite, mode: Mode) -> Self {
        Envelope {
            suite,
            mode,
            tlvs: Vec::new(),
        }
    }

    /// Append a TLV entry.
    pub fn push(&mut self, typ: u8, val: impl Into<Vec<u8>>) -> &mut Self {
        self.tlvs.push(Tlv {
            typ,
            val: val.into(),
        });
        self
    }

    /// First value with the given type, if any.
    pub fn get(&self, typ: u8) -> Option<&[u8]> {
        self.tlvs
            .iter()
            .find(|t| t.typ == typ)
            .map(|t| t.val.as_slice())
    }

    /// All values with the given type, in order.
    pub fn get_all(&self, typ: u8) -> impl Iterator<Item = &[u8]> {
        self.tlvs
            .iter()
            .filter(move |t| t.typ == typ)
            .map(|t| t.val.as_slice())
    }

    /// Required value with the given type, or [`VexilError::MissingField`].
    pub fn require(&self, typ: u8, name: &'static str) -> Result<&[u8]> {
        self.get(typ).ok_or(VexilError::MissingField(name))
    }

    /// Required fixed-length array, validated.
    pub fn require_n<const N: usize>(&self, typ: u8, name: &'static str) -> Result<[u8; N]> {
        let v = self.require(typ, name)?;
        v.try_into().map_err(|_| VexilError::MalformedField(name))
    }

    /// The Additional Authenticated Data the AEAD binds: the header followed by
    /// every TLV **except** the ciphertext and the signature (both are derived
    /// from the ciphertext after sealing). Tampering with suite, mode, salt,
    /// nonce, ephemeral/sender keys, recipient stanzas, or expiry invalidates
    /// the tag. The signature independently authenticates the sender.
    pub fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(HEADER_LEN + 64);
        aad.extend_from_slice(MAGIC);
        aad.push(VERSION);
        aad.push(self.suite.as_byte());
        aad.push(self.mode.as_byte());
        for t in &self.tlvs {
            if t.typ == T_CIPHERTEXT || t.typ == T_SIGNATURE || t.typ == T_SIGNATURE_PQ {
                continue;
            }
            aad.push(t.typ);
            aad.extend_from_slice(&(t.val.len() as u16).to_be_bytes());
            aad.extend_from_slice(&t.val);
        }
        aad
    }

    /// Check that every TLV value and the whole body fit the 16-bit length
    /// fields, so [`serialize`](Self::serialize) cannot silently truncate.
    pub fn validate_lengths(&self) -> Result<()> {
        let mut body = 0usize;
        for t in &self.tlvs {
            if t.val.len() > u16::MAX as usize {
                return Err(VexilError::PayloadTooLarge(t.val.len()));
            }
            body += 3 + t.val.len();
        }
        if body > u16::MAX as usize {
            return Err(VexilError::PayloadTooLarge(body));
        }
        Ok(())
    }

    /// Serialize to the wire format (header + TLV body).
    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::new();
        for t in &self.tlvs {
            body.push(t.typ);
            body.extend_from_slice(&(t.val.len() as u16).to_be_bytes());
            body.extend_from_slice(&t.val);
        }
        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(self.suite.as_byte());
        out.push(self.mode.as_byte());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Parse a wire envelope. Single TLV walker; rejects trailing garbage and
    /// truncation.
    pub fn parse(data: &[u8]) -> Result<Envelope> {
        if data.len() < HEADER_LEN || &data[0..5] != MAGIC {
            return Err(VexilError::InvalidEnvelope);
        }
        let version = data[5];
        if version != VERSION {
            return Err(VexilError::UnsupportedVersion(version));
        }
        let suite = Suite::from_byte(data[6])?;
        let mode = Mode::from_byte(data[7])?;
        let body_len = u16::from_be_bytes([data[8], data[9]]) as usize;
        if data.len() != HEADER_LEN + body_len {
            return Err(VexilError::InvalidEnvelope);
        }

        let body = &data[HEADER_LEN..];
        let mut tlvs = Vec::new();
        let mut i = 0;
        while i < body.len() {
            if i + 3 > body.len() {
                return Err(VexilError::InvalidEnvelope);
            }
            let typ = body[i];
            let len = u16::from_be_bytes([body[i + 1], body[i + 2]]) as usize;
            let start = i + 3;
            let end = start.checked_add(len).ok_or(VexilError::InvalidEnvelope)?;
            if end > body.len() {
                return Err(VexilError::InvalidEnvelope);
            }
            tlvs.push(Tlv {
                typ,
                val: body[start..end].to_vec(),
            });
            i = end;
        }

        Ok(Envelope { suite, mode, tlvs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_tlvs() {
        let mut env = Envelope::new(Suite::XChaPolyArgon, Mode::Symmetric);
        env.push(T_SALT, vec![1u8; 16])
            .push(T_NONCE, vec![2u8; 12])
            .push(T_CIPHERTEXT, vec![9u8; 40]);
        let bytes = env.serialize();
        let back = Envelope::parse(&bytes).unwrap();
        assert_eq!(back.suite, Suite::XChaPolyArgon);
        assert_eq!(back.mode, Mode::Symmetric);
        assert_eq!(back.get(T_SALT).unwrap(), &[1u8; 16]);
        assert_eq!(back.get(T_CIPHERTEXT).unwrap(), &[9u8; 40]);
    }

    #[test]
    fn aad_excludes_ciphertext() {
        let mut env = Envelope::new(Suite::XChaPolyArgon, Mode::Symmetric);
        env.push(T_SALT, vec![1u8; 16])
            .push(T_CIPHERTEXT, vec![9u8; 40]);
        let aad = env.aad();
        // aad = magic(5)+ver+suite+mode + salt tlv(3+16) = 8 + 19 = 27
        assert_eq!(aad.len(), 8 + 3 + 16);
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut env = Envelope::new(Suite::XChaPolyArgon, Mode::Symmetric);
        env.push(T_CIPHERTEXT, vec![0u8; 4]);
        let mut bytes = env.serialize();
        bytes.push(0xAA);
        assert!(Envelope::parse(&bytes).is_err());
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes = b"NOPE\x01\x01\x01\x00\x00\x00";
        assert!(Envelope::parse(bytes).is_err());
    }

    #[test]
    fn rejects_truncated_tlv() {
        // header claims body_len 5 but TLV claims len 99
        let mut bytes = Vec::new();
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.push(0x01);
        bytes.push(0x00);
        bytes.extend_from_slice(&5u16.to_be_bytes());
        bytes.push(0xFF);
        bytes.extend_from_slice(&99u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        assert!(Envelope::parse(&bytes).is_err());
    }
}
