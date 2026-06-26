use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use rand_core::{OsRng, RngCore};

use crate::error::ObfError;

pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, ObfError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| ObfError::Encrypt(e.to_string()))?;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let ct = cipher
        .encrypt(Nonce::from_slice(&iv), plaintext)
        .map_err(|e| ObfError::Encrypt(e.to_string()))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn generate_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    k
}

pub fn generate_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

pub fn generate_seed() -> [u8; 8] {
    let mut s = [0u8; 8];
    OsRng.fill_bytes(&mut s);
    s
}
