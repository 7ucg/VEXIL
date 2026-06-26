//! Suite-dispatched AEAD: ChaCha20-Poly1305 and AES-256-GCM.
//!
//! Both primitives use a 256-bit key, a 96-bit nonce, and append a 128-bit
//! authentication tag. The 16-byte tag is verified on decrypt: any tampering —
//! including bit-flips in AAD-bound envelope fields — causes failure.

use crate::error::{Result, VexilError};
use crate::suite::Aead;
use aes_gcm::Aes256Gcm;
use chacha20poly1305::{
    aead::{Aead as _, KeyInit, Payload},
    ChaCha20Poly1305,
};

/// AEAD nonce length in bytes.
pub const NONCE_LEN: usize = 12;
/// AEAD tag length in bytes (appended to ciphertext).
pub const TAG_LEN: usize = 16;
/// AEAD key length in bytes.
pub const KEY_LEN: usize = 32;

/// Seal `plaintext` under `key`/`nonce`, binding `aad`. Output is
/// `ciphertext || tag`.
pub fn seal(
    aead: Aead,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let out = match aead {
        Aead::ChaCha20Poly1305 => ChaCha20Poly1305::new(key.into())
            .encrypt(nonce.into(), payload)
            .map_err(|_| VexilError::DecryptionFailed)?,
        Aead::Aes256Gcm => Aes256Gcm::new(key.into())
            .encrypt(nonce.into(), payload)
            .map_err(|_| VexilError::DecryptionFailed)?,
    };
    Ok(out)
}

/// Verify and open `ciphertext` (which is `ciphertext || tag`) under
/// `key`/`nonce`, binding `aad`.
pub fn open(
    aead: Aead,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let out = match aead {
        Aead::ChaCha20Poly1305 => ChaCha20Poly1305::new(key.into())
            .decrypt(nonce.into(), payload)
            .map_err(|_| VexilError::DecryptionFailed)?,
        Aead::Aes256Gcm => Aes256Gcm::new(key.into())
            .decrypt(nonce.into(), payload)
            .map_err(|_| VexilError::DecryptionFailed)?,
    };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(aead: Aead) {
        let key = [7u8; 32];
        let nonce = [3u8; 12];
        let ct = seal(aead, &key, &nonce, b"hello", b"aad").unwrap();
        let pt = open(aead, &key, &nonce, &ct, b"aad").unwrap();
        assert_eq!(pt, b"hello");
        // wrong aad fails
        assert!(open(aead, &key, &nonce, &ct, b"bad").is_err());
        // tamper fails
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert!(open(aead, &key, &nonce, &bad, b"aad").is_err());
    }

    #[test]
    fn chacha_roundtrip() {
        roundtrip(Aead::ChaCha20Poly1305);
    }

    #[test]
    fn aes_roundtrip() {
        roundtrip(Aead::Aes256Gcm);
    }
}
