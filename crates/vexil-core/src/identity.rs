//! Identity files: an X25519 encryption key plus an Ed25519 signing key.
//!
//! A VEXIL identity bundles a curve25519 key for sealed-box decryption and an
//! Ed25519 key for signing. The combined 64-byte public material
//! (`x25519_pub || ed25519_pub`) is what fingerprints and pub-files refer to.
//!
//! ## File formats
//!
//! ```text
//! VEXIL-IDENTITY-v1:
//! suite=0x01
//! created=2026-06-25T19:00:00Z
//! fingerprint=a1b2-c3d4-e5f6-7890
//! key=<base89 of x_secret||ed_secret, or a VEX1- blob if passphrase-wrapped>
//! ```
//!
//! ```text
//! VEXIL-KEY-v1:
//! suite=0x01
//! fingerprint=a1b2-c3d4-e5f6-7890
//! key=<base89 of x_pub||ed_pub>
//! ```

use crate::codec::base89_encode;
use crate::error::{Result, VexilError};
use crate::fingerprint::Fingerprint;
use crate::suite::Suite;
use crate::{codec, decrypt_with_password, encrypt_with_password};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const ID_HEADER: &str = "VEXIL-IDENTITY-v1:";
const KEY_HEADER: &str = "VEXIL-KEY-v1:";

/// A secret identity: X25519 (decrypt) + Ed25519 (sign).
pub struct Identity {
    /// X25519 secret used for sealed-box decryption.
    pub x_secret: StaticSecret,
    /// Ed25519 signing key.
    pub ed_secret: SigningKey,
}

/// The public half of an [`Identity`].
#[derive(Clone)]
pub struct PublicIdentity {
    /// X25519 public key (encryption recipient).
    pub x_public: PublicKey,
    /// Ed25519 public key (signature verification).
    pub ed_public: [u8; 32],
}

impl Identity {
    /// Generate a fresh identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut OsRng)
    }

    /// Generate from an explicit RNG (deterministic tests).
    pub fn generate_with_rng<R: RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
        let x_secret = StaticSecret::random_from_rng(&mut *rng);
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let ed_secret = SigningKey::from_bytes(&seed);
        seed.zeroize();
        Identity {
            x_secret,
            ed_secret,
        }
    }

    /// Reconstruct from the 64-byte secret blob (`x_secret || ed_seed`).
    pub fn from_secret_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 64 {
            return Err(VexilError::MalformedKeyFile("secret must be 64 bytes"));
        }
        let mut x = [0u8; 32];
        let mut e = [0u8; 32];
        x.copy_from_slice(&b[..32]);
        e.copy_from_slice(&b[32..]);
        let id = Identity {
            x_secret: StaticSecret::from(x),
            ed_secret: SigningKey::from_bytes(&e),
        };
        x.zeroize();
        e.zeroize();
        Ok(id)
    }

    /// The 64-byte secret blob. Caller is responsible for zeroizing.
    pub fn secret_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x_secret.to_bytes());
        out[32..].copy_from_slice(&self.ed_secret.to_bytes());
        out
    }

    /// X25519 public key.
    pub fn x_public(&self) -> PublicKey {
        PublicKey::from(&self.x_secret)
    }

    /// Ed25519 public key bytes.
    pub fn ed_public(&self) -> [u8; 32] {
        self.ed_secret.verifying_key().to_bytes()
    }

    /// The public identity.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            x_public: self.x_public(),
            ed_public: self.ed_public(),
        }
    }

    /// Fingerprint over the combined public material under a suite.
    pub fn fingerprint(&self, suite: Suite) -> Fingerprint {
        self.public().fingerprint(suite)
    }

    /// Serialize to an identity-file string. If `passphrase` is `Some`, the
    /// `key=` field is wrapped with `VEX1-` symmetric encryption (dogfooding).
    pub fn to_identity_file(&self, suite: Suite, passphrase: Option<&[u8]>) -> Result<String> {
        let mut secret = self.secret_bytes();
        let key_field = match passphrase {
            Some(pw) => encrypt_with_password(pw, &secret)?,
            None => base89_encode(&secret),
        };
        secret.zeroize();
        Ok(format!(
            "{ID_HEADER}\nsuite=0x{:02x}\ncreated={}\nfingerprint={}\nkey={}\n",
            suite.as_byte(),
            now_rfc3339(),
            self.fingerprint(suite).to_short(),
            key_field
        ))
    }

    /// Parse an identity file, decrypting the key with `passphrase` if it is
    /// passphrase-wrapped.
    pub fn parse_identity_file(text: &str, passphrase: Option<&[u8]>) -> Result<Identity> {
        let fields = parse_kv(text, ID_HEADER)?;
        let key = fields_get(&fields, "key")?;
        let secret = if key.starts_with("VEX1-") {
            let pw = passphrase.ok_or(VexilError::MalformedKeyFile(
                "identity is passphrase-protected",
            ))?;
            decrypt_with_password(pw, key)?
        } else {
            codec::base89_decode(key)?
        };
        let id = Identity::from_secret_bytes(&secret)?;
        let mut s = secret;
        s.zeroize();
        Ok(id)
    }
}

impl PublicIdentity {
    /// Combined 64-byte public material (`x_pub || ed_pub`).
    pub fn public_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(self.x_public.as_bytes());
        out[32..].copy_from_slice(&self.ed_public);
        out
    }

    /// Reconstruct from the 64-byte public blob.
    pub fn from_public_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 64 {
            return Err(VexilError::MalformedKeyFile("public must be 64 bytes"));
        }
        let mut x = [0u8; 32];
        let mut e = [0u8; 32];
        x.copy_from_slice(&b[..32]);
        e.copy_from_slice(&b[32..]);
        Ok(PublicIdentity {
            x_public: PublicKey::from(x),
            ed_public: e,
        })
    }

    /// Fingerprint over the combined public material under a suite.
    pub fn fingerprint(&self, suite: Suite) -> Fingerprint {
        Fingerprint::of(suite, &self.public_bytes())
    }

    /// Serialize to a `.pub` file string.
    pub fn to_pub_file(&self, suite: Suite) -> String {
        format!(
            "{KEY_HEADER}\nsuite=0x{:02x}\nfingerprint={}\nkey={}\n",
            suite.as_byte(),
            self.fingerprint(suite).to_short(),
            base89_encode(&self.public_bytes())
        )
    }

    /// Parse a `.pub` file string.
    pub fn parse_pub_file(text: &str) -> Result<PublicIdentity> {
        let fields = parse_kv(text, KEY_HEADER)?;
        let key = fields_get(&fields, "key")?;
        let bytes = codec::base89_decode(key)?;
        PublicIdentity::from_public_bytes(&bytes)
    }
}

fn parse_kv(text: &str, header: &str) -> Result<Vec<(String, String)>> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let first = lines
        .next()
        .ok_or(VexilError::MalformedKeyFile("empty file"))?;
    if first != header {
        return Err(VexilError::MalformedKeyFile("bad header"));
    }
    let mut out = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once('=') {
            out.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(out)
}

fn fields_get<'a>(fields: &'a [(String, String)], key: &str) -> Result<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .ok_or(VexilError::MalformedKeyFile("missing field"))
}

/// Minimal UTC RFC-3339 timestamp from the system clock (no chrono dependency).
fn now_rfc3339() -> String {
    unix_to_rfc3339(crate::now_unix_secs())
}

/// Convert unix seconds to `YYYY-MM-DDTHH:MM:SSZ` (proleptic Gregorian, UTC).
pub fn unix_to_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil_from_days algorithm.
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, m, d, h, mi, s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::SeedableRng;

    fn det_rng(seed: u64) -> rand_chacha_stub::ChaChaStub {
        rand_chacha_stub::ChaChaStub::seed_from_u64(seed)
    }

    #[test]
    fn identity_file_roundtrip_plain() {
        let id = Identity::generate_with_rng(&mut det_rng(1));
        let file = id.to_identity_file(Suite::XChaPolyArgon, None).unwrap();
        let back = Identity::parse_identity_file(&file, None).unwrap();
        assert_eq!(back.secret_bytes(), id.secret_bytes());
    }

    #[test]
    fn pub_file_roundtrip() {
        let id = Identity::generate_with_rng(&mut det_rng(2));
        let pubf = id.public().to_pub_file(Suite::XChaPolyArgon);
        let back = PublicIdentity::parse_pub_file(&pubf).unwrap();
        assert_eq!(back.public_bytes(), id.public().public_bytes());
    }

    #[test]
    fn fingerprint_stable() {
        let id = Identity::generate_with_rng(&mut det_rng(3));
        let a = id.fingerprint(Suite::XChaPolyArgon);
        let b = id.fingerprint(Suite::XChaPolyArgon);
        assert_eq!(a, b);
    }

    #[test]
    fn rfc3339_known_epoch() {
        assert_eq!(unix_to_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(unix_to_rfc3339(1_700_000_000), "2023-11-14T22:13:20Z");
    }
}

// A tiny deterministic CryptoRng for tests without pulling rand_chacha into deps.
#[cfg(test)]
mod rand_chacha_stub {
    use rand_core::{CryptoRng, RngCore, SeedableRng};

    /// xorshift-based deterministic RNG. Test-only; NOT cryptographic, but the
    /// `CryptoRng` marker lets it satisfy key-generation bounds in tests.
    pub struct ChaChaStub(u64);

    impl SeedableRng for ChaChaStub {
        type Seed = [u8; 8];
        fn from_seed(seed: [u8; 8]) -> Self {
            ChaChaStub(u64::from_le_bytes(seed).max(1))
        }
        fn seed_from_u64(state: u64) -> Self {
            ChaChaStub(state.max(1))
        }
    }

    impl RngCore for ChaChaStub {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                chunk.copy_from_slice(&v[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for ChaChaStub {}
}
