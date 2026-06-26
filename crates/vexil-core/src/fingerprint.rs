//! Key fingerprints via BLAKE2b-128.
//!
//! A fingerprint is the first 16 bytes of `BLAKE2b-128(suite_byte || pubkey)`,
//! shown as four dash-separated groups of four lowercase hex characters
//! (e.g. `a1b2-c3d4-e5f6-7890`). It is stable: the same key under the same
//! suite always yields the same fingerprint.

use crate::error::{Result, VexilError};
use crate::suite::Suite;
use blake2::digest::consts::U16;
use blake2::{Blake2b, Digest};

/// Length of a fingerprint in bytes.
pub const FPR_LEN: usize = 16;

type Blake2b128 = Blake2b<U16>;

/// A 16-byte key fingerprint.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint(pub [u8; FPR_LEN]);

impl Fingerprint {
    /// Compute the fingerprint of a public key under a given suite.
    pub fn of(suite: Suite, pubkey: &[u8]) -> Self {
        let mut h = Blake2b128::new();
        h.update([suite.as_byte()]);
        h.update(pubkey);
        let out = h.finalize();
        let mut fpr = [0u8; FPR_LEN];
        fpr.copy_from_slice(&out);
        Fingerprint(fpr)
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; FPR_LEN] {
        &self.0
    }

    /// Render as `xxxx-xxxx-xxxx-xxxx` (first 8 bytes, dashed groups of 4 hex).
    pub fn to_short(&self) -> String {
        let h = hex::encode(&self.0[..8]);
        format!("{}-{}-{}-{}", &h[0..4], &h[4..8], &h[8..12], &h[12..16])
    }

    /// Render the full 16 bytes as `xxxx-xxxx-...` (8 groups).
    pub fn to_full(&self) -> String {
        let h = hex::encode(self.0);
        h.as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("-")
    }

    /// Parse a `from_bytes` constructor for stanza matching.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let arr: [u8; FPR_LEN] = b
            .try_into()
            .map_err(|_| VexilError::MalformedField("fingerprint"))?;
        Ok(Fingerprint(arr))
    }

    /// Render as 8 groups of 5 decimal digits (40 digits, space-separated).
    ///
    /// Each group is a zero-padded `u16` (0–65535), so the full 16-byte
    /// fingerprint maps to 8 × 16 = 128 bits of display entropy. Read two
    /// groups aloud to confirm a shared contact — mismatches stand out audibly.
    ///
    /// ```
    /// use vexil_core::{fingerprint::Fingerprint, Suite};
    /// let fpr = Fingerprint([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    ///                        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
    /// let sas = fpr.to_decimal_sas();
    /// assert_eq!(sas.split_whitespace().count(), 8);
    /// ```
    pub fn to_decimal_sas(&self) -> String {
        (0..8)
            .map(|i| {
                let v = u16::from_be_bytes([self.0[i * 2], self.0[i * 2 + 1]]);
                format!("{:05}", v)
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Compute a combined safety number for two parties' fingerprints.
///
/// The two fingerprints are sorted in canonical (byte) order before hashing so
/// Alice and Bob both compute the same string regardless of who calls first.
/// Display it as 8 groups of 5 decimal digits — read 4 groups aloud each to
/// verify a contact out of band.
///
/// ```
/// use vexil_core::fingerprint::{Fingerprint, combined_safety_number};
/// let a = Fingerprint([1u8; 16]);
/// let b = Fingerprint([2u8; 16]);
/// assert_eq!(combined_safety_number(&a, &b), combined_safety_number(&b, &a));
/// ```
pub fn combined_safety_number(a: &Fingerprint, b: &Fingerprint) -> String {
    let (lo, hi) = if a.0 <= b.0 { (a, b) } else { (b, a) };
    let mut h = Blake2b128::new();
    h.update(lo.0);
    h.update(hi.0);
    let out = h.finalize();
    let mut combined = [0u8; FPR_LEN];
    combined.copy_from_slice(&out);
    Fingerprint(combined).to_decimal_sas()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable() {
        let pk = [9u8; 32];
        let a = Fingerprint::of(Suite::XChaPolyArgon, &pk);
        let b = Fingerprint::of(Suite::XChaPolyArgon, &pk);
        assert_eq!(a, b);
    }

    #[test]
    fn suite_changes_fingerprint() {
        let pk = [9u8; 32];
        let a = Fingerprint::of(Suite::XChaPolyArgon, &pk);
        let b = Fingerprint::of(Suite::XAesGcmArgon, &pk);
        assert_ne!(a, b);
    }

    #[test]
    fn short_format() {
        let fpr = Fingerprint([0xab; 16]);
        assert_eq!(fpr.to_short(), "abab-abab-abab-abab");
    }
}
