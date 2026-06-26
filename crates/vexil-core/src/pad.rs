//! Message padding for length-hiding encryption.
//!
//! Plaintext length leaks through ciphertext size. This module provides a
//! PADME-style policy that pads short messages to the nearest bucket,
//! keeping overhead below 1/128 (≈0.8 %) for large messages while hiding
//! exact sizes from a passive observer.
//!
//! The padded format is:
//! ```text
//! u16_be(original_length) || original_bytes || zero_bytes_to_target_length
//! ```
//!
//! The 2-byte length prefix is part of the padded output; stripping recovers
//! the original bytes exactly.
//!
//! # Example
//! ```
//! use vexil_core::pad::{PaddingPolicy, apply, strip};
//!
//! let policy = PaddingPolicy::Padme;
//! let padded = apply(&policy, b"hello world").unwrap();
//! assert!(padded.len() >= 13); // at least orig + 2-byte prefix
//! let back = strip(&padded).unwrap();
//! assert_eq!(back, b"hello world");
//! ```

use crate::error::{Result, VexilError};

/// How to pad a plaintext before encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PaddingPolicy {
    /// No padding. The ciphertext length reveals the plaintext length exactly.
    None,
    /// Pad to the next multiple of `block` bytes (including the 2-byte length
    /// prefix). Minimum output is `block` bytes.
    Block(usize),
    /// PADME: round up to the nearest bucket of size `2^(floor(log2(total))-7)`,
    /// keeping overhead below 1/128 of the message size. Minimum output is
    /// 32 bytes. Good default for most message sizes.
    Padme,
}

/// Apply `policy` to `msg`. Returns the padded bytes, ready to pass to an
/// encryption function. Returns an error only if the padded size would exceed
/// 65533 bytes (the VEXIL single-envelope limit minus the AEAD tag).
pub fn apply(policy: &PaddingPolicy, msg: &[u8]) -> Result<Vec<u8>> {
    let target = match policy {
        PaddingPolicy::None => msg.len() + 2,
        PaddingPolicy::Block(block) => {
            let block = (*block).max(1);
            let total = msg.len() + 2;
            total.div_ceil(block) * block
        }
        PaddingPolicy::Padme => padme_target(msg.len() + 2),
    };
    if target > 65533 {
        return Err(VexilError::PayloadTooLarge(target));
    }
    let mut out = Vec::with_capacity(target);
    out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    out.extend_from_slice(msg);
    out.resize(target, 0);
    Ok(out)
}

/// Strip padding added by [`apply`]. Returns a slice of the original bytes
/// without copying. Returns `None` if the buffer is too short or the embedded
/// length is out of range.
pub fn strip(padded: &[u8]) -> Option<&[u8]> {
    if padded.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if 2 + len > padded.len() {
        return None;
    }
    Some(&padded[2..2 + len])
}

/// PADME target length for a buffer of `total` bytes (original + 2-byte
/// length prefix). Rounds up to the nearest `2^(e-7)` boundary where `e` is
/// `floor(log2(total))`. Overhead is at most 1/128 ≈ 0.8 % of total.
/// Minimum returned value is 32.
fn padme_target(total: usize) -> usize {
    let total = total.max(32);
    // e = floor(log2(total)) = position of the highest set bit.
    let e = (usize::BITS - total.leading_zeros() - 1) as usize;
    let s = e.saturating_sub(7);
    let block = 1usize << s;
    total.div_ceil(block) * block
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_adds_only_prefix() {
        let padded = apply(&PaddingPolicy::None, b"abc").unwrap();
        assert_eq!(padded.len(), 5); // 2 + 3
        assert_eq!(strip(&padded).unwrap(), b"abc");
    }

    #[test]
    fn block_rounds_up() {
        let padded = apply(&PaddingPolicy::Block(16), b"hello").unwrap();
        assert_eq!(padded.len(), 16); // ceil((5+2)/16)*16 = 16
        assert_eq!(strip(&padded).unwrap(), b"hello");
    }

    #[test]
    fn padme_small_message_is_at_least_32() {
        let padded = apply(&PaddingPolicy::Padme, b"hi").unwrap();
        assert!(padded.len() >= 32);
        assert_eq!(strip(&padded).unwrap(), b"hi");
    }

    #[test]
    fn padme_large_message_overhead_below_1pct() {
        let msg = vec![0u8; 10_000];
        let padded = apply(&PaddingPolicy::Padme, &msg).unwrap();
        let overhead = padded.len() - msg.len() - 2;
        assert!(
            overhead as f64 / (msg.len() as f64) < 0.02,
            "overhead {}B on 10KB msg",
            overhead
        );
        assert_eq!(strip(&padded).unwrap(), msg.as_slice());
    }

    #[test]
    fn roundtrip_various_lengths() {
        for len in [0, 1, 31, 32, 127, 128, 255, 256, 1000, 5000, 30000] {
            let msg = vec![0xABu8; len];
            for policy in [
                PaddingPolicy::None,
                PaddingPolicy::Block(64),
                PaddingPolicy::Padme,
            ] {
                let padded = apply(&policy, &msg).unwrap();
                assert_eq!(
                    strip(&padded).unwrap(),
                    msg.as_slice(),
                    "roundtrip failed for len={len} policy={policy:?}"
                );
            }
        }
    }

    #[test]
    fn strip_rejects_short_buffer() {
        assert!(strip(&[]).is_none());
        assert!(strip(&[0]).is_none());
        // length field claims 100 bytes but only 2 bytes present
        assert!(strip(&[0, 100]).is_none());
    }
}
