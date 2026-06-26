//! Algorithm suite identifiers and dispatch.
//!
//! VEXIL is **algorithm-agile**: the wire format carries a one-byte suite ID so
//! primitives can be swapped in a future version without breaking parsers. The
//! suite selects the AEAD (and, for suite `0x03`, the presence of an ML-KEM
//! encapsulation alongside X25519). The KDF (Argon2id) and the key-agreement
//! curve (X25519) are constant across all v1 suites.

use crate::error::{Result, VexilError};

/// AEAD primitive selected by a [`Suite`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Aead {
    /// ChaCha20-Poly1305 (RFC 8439).
    ChaCha20Poly1305,
    /// AES-256-GCM (NIST SP 800-38D).
    Aes256Gcm,
}

/// A versioned bundle of primitives, identified on the wire by a single byte.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum Suite {
    /// X25519 + ChaCha20-Poly1305 + Argon2id. The default.
    #[default]
    XChaPolyArgon = 0x01,
    /// X25519 + AES-256-GCM + Argon2id.
    XAesGcmArgon = 0x02,
    /// X25519 + ML-KEM-768 + ChaCha20-Poly1305 + Argon2id (post-quantum hybrid).
    XKyberChaPoly = 0x03,
    /// X25519 + ML-KEM-1024 + ChaCha20-Poly1305 + Argon2id (top PQ tier).
    XKyber1024ChaPoly = 0x05,
}

impl Suite {
    /// The on-wire byte for this suite.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Parse a suite from its wire byte.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(Suite::XChaPolyArgon),
            0x02 => Ok(Suite::XAesGcmArgon),
            0x03 => Ok(Suite::XKyberChaPoly),
            0x05 => Ok(Suite::XKyber1024ChaPoly),
            other => Err(VexilError::UnknownSuite(other)),
        }
    }

    /// The AEAD primitive used by this suite.
    pub fn aead(self) -> Aead {
        match self {
            Suite::XAesGcmArgon => Aead::Aes256Gcm,
            Suite::XChaPolyArgon | Suite::XKyberChaPoly | Suite::XKyber1024ChaPoly => {
                Aead::ChaCha20Poly1305
            }
        }
    }

    /// Whether this suite carries a post-quantum KEM encapsulation.
    pub fn is_pq(self) -> bool {
        matches!(self, Suite::XKyberChaPoly | Suite::XKyber1024ChaPoly)
    }

    /// Human-readable name (for `--json` output and diagnostics).
    pub fn name(self) -> &'static str {
        match self {
            Suite::XChaPolyArgon => "X25519+ChaCha20Poly1305+Argon2id",
            Suite::XAesGcmArgon => "X25519+AES256GCM+Argon2id",
            Suite::XKyberChaPoly => "X25519+MLKEM768+ChaCha20Poly1305+Argon2id",
            Suite::XKyber1024ChaPoly => "X25519+MLKEM1024+ChaCha20Poly1305+Argon2id",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_roundtrip() {
        for s in [
            Suite::XChaPolyArgon,
            Suite::XAesGcmArgon,
            Suite::XKyberChaPoly,
        ] {
            assert_eq!(Suite::from_byte(s.as_byte()).unwrap(), s);
        }
    }

    #[test]
    fn unknown_suite_rejected() {
        assert!(matches!(
            Suite::from_byte(0x99),
            Err(VexilError::UnknownSuite(0x99))
        ));
    }

    #[test]
    fn default_is_chapoly() {
        assert_eq!(Suite::default(), Suite::XChaPolyArgon);
    }
}
