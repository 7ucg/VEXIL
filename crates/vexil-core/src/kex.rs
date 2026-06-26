//! Shared key-agreement helpers: X25519 ECDH followed by HKDF-SHA256.
//!
//! Centralises the derivation used by sealed, signed, and multi-recipient
//! modes so the transcript binding is identical everywhere.

use crate::error::{Result, VexilError};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

/// Sealed-box HKDF info string.
pub const INFO_SEALED: &[u8] = b"vexil-sealed-v1";
/// Per-recipient DEK-wrap HKDF info string.
pub const INFO_RECIPIENT: &[u8] = b"vexil-recipient-v1";
/// Post-quantum hybrid HKDF info string.
pub const INFO_PQ: &[u8] = b"vexil-pq-v1";

/// `eph_pk || peer_pk`, the transcript that salts the HKDF.
pub fn transcript(eph_pk: &PublicKey, peer_pk: &PublicKey) -> [u8; 64] {
    let mut t = [0u8; 64];
    t[..32].copy_from_slice(eph_pk.as_bytes());
    t[32..].copy_from_slice(peer_pk.as_bytes());
    t
}

/// HKDF-SHA256 a 32-byte key from input keying material.
pub fn hkdf32(salt: &[u8], ikm: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(info, key.as_mut())
        .map_err(|e| VexilError::KdfFailure(e.to_string()))?;
    Ok(key)
}
