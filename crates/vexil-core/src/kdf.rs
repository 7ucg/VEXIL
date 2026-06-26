//! Argon2id password → key derivation.
//!
//! Parameters target high security on modern desktop hardware:
//!   - Memory: 64 MiB
//!   - Time: 3 iterations
//!   - Parallelism: 4 lanes
//!
//! These take roughly 0.3–1 s per derivation on a modern CPU, making
//! large-scale offline brute force prohibitively expensive.

use crate::error::{Result, VexilError};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroize;

/// Argon2id memory cost, in KiB.
pub const KDF_MEMORY_KIB: u32 = 65_536;
/// Argon2id time cost (iterations).
pub const KDF_ITERATIONS: u32 = 3;
/// Argon2id parallelism (lanes).
pub const KDF_PARALLELISM: u32 = 4;
/// Salt length in bytes.
pub const SALT_LEN: usize = 16;
/// Derived key length in bytes.
pub const KEY_LEN: usize = 32;

/// A derived 256-bit key, zeroized on drop.
pub struct DerivedKey([u8; KEY_LEN]);

impl DerivedKey {
    /// Borrow the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for DerivedKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Security preset for Argon2id parameter selection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Argon2Preset {
    /// Interactive login — m=32 MiB, t=2, p=2. Fast enough for UI flows.
    Interactive,
    /// Default at-rest — m=64 MiB, t=3, p=4.
    Default,
    /// Maximum security — m=128 MiB, t=4, p=4. For sensitive long-lived keys.
    Sensitive,
}

impl Argon2Preset {
    fn m_t_p(self) -> (u32, u32, u32) {
        match self {
            Self::Interactive => (32_768, 2, 2),
            Self::Default => (KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_PARALLELISM),
            Self::Sensitive => (131_072, 4, 4),
        }
    }

    /// On-wire byte stored in [`T_KDF_PRESET`](crate::envelope::T_KDF_PRESET).
    pub fn as_byte(self) -> u8 {
        match self {
            Self::Interactive => 1,
            Self::Default => 0,
            Self::Sensitive => 2,
        }
    }

    /// Decode from the on-wire byte.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Default),
            1 => Some(Self::Interactive),
            2 => Some(Self::Sensitive),
            _ => None,
        }
    }
}

/// Derive a key using an explicit [`Argon2Preset`].
pub fn derive_key_preset(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    preset: Argon2Preset,
) -> Result<DerivedKey> {
    let (m, t, p) = preset.m_t_p();
    let params =
        Params::new(m, t, p, Some(KEY_LEN)).map_err(|e| VexilError::KdfFailure(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| VexilError::KdfFailure(e.to_string()))?;
    Ok(DerivedKey(key))
}

/// Derive a 256-bit key from a password and 16-byte salt via Argon2id.
pub fn derive_key(password: &[u8], salt: &[u8; SALT_LEN]) -> Result<DerivedKey> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|e| VexilError::KdfFailure(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| VexilError::KdfFailure(e.to_string()))?;
    Ok(DerivedKey(key))
}
