//! Ed25519 detached signatures.
//!
//! Thin wrapper over `ed25519-dalek`. Used by the signed sealed-box mode
//! ([`Mode::Signed`](crate::Mode)) to authenticate the sender of an
//! asymmetric ciphertext.

use crate::error::{Result, VexilError};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Ed25519 public key length.
pub const PK_LEN: usize = 32;
/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;

/// Sign `msg` with an Ed25519 signing key, returning the 64-byte signature.
pub fn sign(sk: &SigningKey, msg: &[u8]) -> [u8; SIG_LEN] {
    sk.sign(msg).to_bytes()
}

/// Verify a detached Ed25519 signature. Uses `verify_strict` to reject
/// non-canonical keys and small-order points.
pub fn verify(pk_bytes: &[u8; PK_LEN], msg: &[u8], sig_bytes: &[u8; SIG_LEN]) -> Result<()> {
    let pk = VerifyingKey::from_bytes(pk_bytes).map_err(|_| VexilError::BadSignature)?;
    let sig = Signature::from_bytes(sig_bytes);
    pk.verify_strict(msg, &sig)
        .map_err(|_| VexilError::BadSignature)
}

/// Verify with the non-strict verifier (kept for completeness / interop tests).
pub fn verify_loose(pk_bytes: &[u8; PK_LEN], msg: &[u8], sig_bytes: &[u8; SIG_LEN]) -> Result<()> {
    let pk = VerifyingKey::from_bytes(pk_bytes).map_err(|_| VexilError::BadSignature)?;
    let sig = Signature::from_bytes(sig_bytes);
    pk.verify(msg, &sig).map_err(|_| VexilError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn sign_verify_roundtrip() {
        let sk = SigningKey::from_bytes(&[42u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let sig = sign(&sk, b"message");
        assert!(verify(&pk, b"message", &sig).is_ok());
        assert!(verify(&pk, b"tampered", &sig).is_err());
    }
}
