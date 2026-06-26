//! Binary ⇆ text codecs: Base89, hex, raw, and PEM.
//!
//! [`Encoding`] selects how an envelope's bytes are rendered for transport.
//! The default, [`Encoding::Base89`], uses an 89-character ASCII alphabet
//! chosen so ciphertexts embed cleanly in source-code string literals: it
//! excludes `"`, `'`, `\`, whitespace, `;` and `,`.

use crate::error::{Result, VexilError};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

/// The Base89 alphabet. Source-code-string-safe (no quotes, backslash,
/// whitespace, `;` or `,`).
pub const ALPHABET: &[u8; 89] =
    b"!#$%&()*+-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~";

const BASE: u32 = 89;

/// PEM armor header line.
pub const PEM_HEADER: &str = "-----BEGIN VEXIL CIPHERTEXT-----";
/// PEM armor footer line.
pub const PEM_FOOTER: &str = "-----END VEXIL CIPHERTEXT-----";

/// Selects the text representation of an envelope.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum Encoding {
    /// ASCII-safe Base89 (default).
    #[default]
    Base89,
    /// Lowercase hexadecimal (debugging).
    Hex,
    /// Raw binary, no transformation (for piping).
    Raw,
    /// PEM-armored Base64.
    Pem,
}

impl Encoding {
    /// Lowercase name, as used by the `--encoding` CLI flag and `--json` output.
    pub fn name(self) -> &'static str {
        match self {
            Encoding::Base89 => "base89",
            Encoding::Hex => "hex",
            Encoding::Raw => "raw",
            Encoding::Pem => "pem",
        }
    }

    /// Best-effort detection of a body's encoding: PEM by its header, lowercase
    /// even-length hex as hex, otherwise Base89. A real Base89 ciphertext is
    /// essentially never all-hex, so this is unambiguous in practice.
    pub fn detect(body: &str) -> Self {
        if body.contains("BEGIN VEXIL") {
            return Encoding::Pem;
        }
        let t = body.trim();
        let all_hex = !t.is_empty()
            && t.len() % 2 == 0
            && t.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if all_hex {
            Encoding::Hex
        } else {
            Encoding::Base89
        }
    }

    /// Parse from the `--encoding` flag value.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "base89" => Some(Encoding::Base89),
            "hex" => Some(Encoding::Hex),
            "raw" => Some(Encoding::Raw),
            "pem" | "armor" => Some(Encoding::Pem),
            _ => None,
        }
    }

    /// Encode bytes to this representation. For [`Encoding::Raw`] the returned
    /// `String` is constructed from the bytes losslessly via `from_utf8_lossy`
    /// only when valid; callers that need exact binary should use
    /// [`Encoding::encode_bytes`].
    pub fn encode(self, data: &[u8]) -> String {
        match self {
            Encoding::Base89 => base89_encode(data),
            Encoding::Hex => hex::encode(data),
            Encoding::Pem => pem_wrap(data),
            Encoding::Raw => String::from_utf8_lossy(data).into_owned(),
        }
    }

    /// Encode bytes, returning raw bytes (exact for [`Encoding::Raw`]).
    pub fn encode_bytes(self, data: &[u8]) -> Vec<u8> {
        match self {
            Encoding::Raw => data.to_vec(),
            other => other.encode(data).into_bytes(),
        }
    }

    /// Decode a string in this representation back to bytes.
    pub fn decode(self, s: &str) -> Result<Vec<u8>> {
        match self {
            Encoding::Base89 => base89_decode(s.trim()),
            Encoding::Hex => hex::decode(s.trim()).map_err(|_| VexilError::InvalidEncoding),
            Encoding::Pem => pem_unwrap(s),
            Encoding::Raw => Ok(s.as_bytes().to_vec()),
        }
    }
}

const fn build_reverse() -> [u8; 256] {
    let mut rev = [255u8; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        rev[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    rev
}

/// Base89 reverse-lookup table, built once at compile time.
static REVERSE: [u8; 256] = build_reverse();

/// Encode bytes to Base89.
pub fn base89_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }
    let leading_zeros = data.iter().take_while(|&&b| b == 0).count();
    let trimmed = &data[leading_zeros..];

    let mut digits: Vec<u8> = Vec::new();
    if !trimmed.is_empty() {
        let mut num = trimmed.to_vec();
        loop {
            let mut rem: u32 = 0;
            let mut new_num: Vec<u8> = Vec::with_capacity(num.len());
            let mut started = false;
            for &b in &num {
                let cur = rem * 256 + b as u32;
                let q = cur / BASE;
                rem = cur % BASE;
                if started || q != 0 {
                    new_num.push(q as u8);
                    started = true;
                }
            }
            digits.push(rem as u8);
            if new_num.is_empty() {
                break;
            }
            num = new_num;
        }
    }

    let mut s = String::with_capacity(leading_zeros + digits.len());
    for _ in 0..leading_zeros {
        s.push(ALPHABET[0] as char);
    }
    for &d in digits.iter().rev() {
        s.push(ALPHABET[d as usize] as char);
    }
    s
}

/// Largest Base89 string accepted by [`base89_decode`]. Base-89 decoding is
/// O(n²) (bignum base conversion), so an unbounded input is a denial-of-service
/// vector. Valid envelopes encode to well under this; for larger payloads use a
/// linear encoding (hex/raw/pem) or streaming.
pub const MAX_BASE89_INPUT: usize = 131_072;

/// Decode a Base89 string to bytes.
pub fn base89_decode(s: &str) -> Result<Vec<u8>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() > MAX_BASE89_INPUT {
        return Err(VexilError::InvalidEncoding);
    }
    let rev = &REVERSE;
    let bytes = s.as_bytes();
    let zero_char = ALPHABET[0];
    let leading_z = bytes.iter().take_while(|&&b| b == zero_char).count();
    let trimmed = &bytes[leading_z..];

    let mut num: Vec<u8> = Vec::new();
    for &c in trimmed {
        let v = rev[c as usize];
        if v == 255 {
            return Err(VexilError::InvalidEncoding);
        }
        let mut carry = v as u32;
        for byte in num.iter_mut().rev() {
            let cur = (*byte as u32) * BASE + carry;
            *byte = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        while carry > 0 {
            num.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = vec![0u8; leading_z];
    out.extend_from_slice(&num);
    Ok(out)
}

fn pem_wrap(data: &[u8]) -> String {
    let b64 = B64.encode(data);
    let mut s = String::with_capacity(b64.len() + 80);
    s.push_str(PEM_HEADER);
    s.push('\n');
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    s.push_str(PEM_FOOTER);
    s.push('\n');
    s
}

fn pem_unwrap(s: &str) -> Result<Vec<u8>> {
    let mut body = String::new();
    let mut in_body = false;
    for line in s.lines() {
        let line = line.trim();
        if line == PEM_HEADER {
            in_body = true;
            continue;
        }
        if line == PEM_FOOTER {
            return B64
                .decode(body.as_bytes())
                .map_err(|_| VexilError::InvalidEncoding);
        }
        if in_body {
            body.push_str(line);
        }
    }
    Err(VexilError::MalformedPem)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_encodings_roundtrip() {
        let inputs: &[&[u8]] = &[
            b"",
            b"\x00",
            b"\x00\x00\x00",
            b"hello",
            b"\x00\xff",
            &[42u8; 100],
        ];
        for enc in [Encoding::Base89, Encoding::Hex, Encoding::Pem] {
            for &input in inputs {
                let s = enc.encode(input);
                let back = enc.decode(&s).unwrap();
                assert_eq!(back, input, "{:?} failed for {:?}", enc, input);
            }
        }
    }

    #[test]
    fn raw_bytes_roundtrip() {
        // Raw is a binary mode: bytes in, identical bytes out.
        for input in [&b""[..], &b"\x00\xff\x01"[..], &[42u8; 100][..]] {
            assert_eq!(Encoding::Raw.encode_bytes(input), input);
        }
    }

    #[test]
    fn base89_invalid_char_rejected() {
        assert!(base89_decode("hello\"world").is_err());
    }

    #[test]
    fn alphabet_is_source_safe() {
        let mut seen = [false; 256];
        for &c in ALPHABET.iter() {
            assert!(c != b'"' && c != b'\'' && c != b'\\');
            assert!(c != b' ' && c != b'\t' && c != b'\n');
            assert!(c != b';' && c != b',');
            assert!((0x21..0x7f).contains(&c));
            assert!(!seen[c as usize], "duplicate {}", c as char);
            seen[c as usize] = true;
        }
    }

    #[test]
    fn encoding_parse() {
        assert_eq!(Encoding::parse("BASE89"), Some(Encoding::Base89));
        assert_eq!(Encoding::parse("armor"), Some(Encoding::Pem));
        assert_eq!(Encoding::parse("nope"), None);
    }
}
