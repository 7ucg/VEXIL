//! Post-quantum hybrid encryption (feature `pq`).
//!
//! Confidentiality holds as long as **either** X25519 **or** the ML-KEM tier
//! resists the attacker — a hybrid that survives a future quantum break of the
//! elliptic curve.
//!
//! ```text
//! ss1            = X25519(eph_sk, recipient_x_pub)
//! (kem_ct, ss2)  = ML-KEM.Encapsulate(recipient_ml_ek)
//! key            = HKDF-SHA256(salt = eph_pk || recipient_x_pub || kem_ct,
//!                              ikm  = ss1 || ss2, info = "vexil-pq-v1")
//! ciphertext     = ChaCha20Poly1305(key, nonce, plaintext, aad = envelope)
//! ```
//!
//! Two tiers are provided:
//! - [`PqSecret`] / [`PqPublic`] — ML-KEM-768, suite `0x03`, prefix `VEX1P-`.
//! - [`Pq1024Secret`] / [`Pq1024Public`] — ML-KEM-1024, suite `0x05`.
//!
//! A PQ recipient holds both an X25519 secret and an ML-KEM decapsulation key.

use crate::aead;
use crate::envelope::{Envelope, Mode, T_CIPHERTEXT, T_EPHEMERAL_PK, T_MLKEM_CT, T_NONCE};
use crate::error::{Result, VexilError};
use crate::kex::INFO_PQ;
use crate::suite::{Aead, Suite};
use crate::{armor, dearmor_auto, Encoding};
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{
    Ciphertext as KemCiphertext, Encoded, EncodedSizeUser, KemCore, MlKem1024, MlKem768, SharedKey,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Associates an ML-KEM parameter set with its VEXIL suite byte.
pub trait PqParams: KemCore {
    /// The VEXIL suite this tier maps to.
    const SUITE: Suite;
}

impl PqParams for MlKem768 {
    const SUITE: Suite = Suite::XKyberChaPoly;
}

impl PqParams for MlKem1024 {
    const SUITE: Suite = Suite::XKyber1024ChaPoly;
}

/// A post-quantum secret identity: X25519 + an ML-KEM decapsulation key.
pub struct PqSecretK<M: KemCore> {
    /// X25519 secret.
    pub x_secret: StaticSecret,
    /// ML-KEM decapsulation key.
    pub ml_dk: M::DecapsulationKey,
    /// ML-KEM encapsulation key (kept for public export).
    pub ml_ek: M::EncapsulationKey,
}

/// The public half: X25519 public + an ML-KEM encapsulation key.
pub struct PqPublicK<M: KemCore> {
    /// X25519 public key.
    pub x_public: PublicKey,
    /// ML-KEM encapsulation key.
    pub ml_ek: M::EncapsulationKey,
}

impl<M: KemCore> Clone for PqPublicK<M>
where
    M::EncapsulationKey: Clone,
{
    fn clone(&self) -> Self {
        PqPublicK {
            x_public: self.x_public,
            ml_ek: self.ml_ek.clone(),
        }
    }
}

/// ML-KEM-768 PQ secret (suite `0x03`).
pub type PqSecret = PqSecretK<MlKem768>;
/// ML-KEM-768 PQ public key (suite `0x03`).
pub type PqPublic = PqPublicK<MlKem768>;
/// ML-KEM-1024 PQ secret (suite `0x05`).
pub type Pq1024Secret = PqSecretK<MlKem1024>;
/// ML-KEM-1024 PQ public key (suite `0x05`).
pub type Pq1024Public = PqPublicK<MlKem1024>;

impl<M: KemCore> PqSecretK<M> {
    /// Generate a fresh PQ identity from the OS CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut OsRng)
    }

    /// Generate from an explicit RNG.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let x_secret = StaticSecret::random_from_rng(&mut *rng);
        let (ml_dk, ml_ek) = M::generate(rng);
        PqSecretK {
            x_secret,
            ml_dk,
            ml_ek,
        }
    }

    /// ML-KEM decapsulation key bytes (for the PQ ratchet seed).
    pub fn ml_dk_bytes(&self) -> Vec<u8> {
        self.ml_dk.as_bytes().as_slice().to_vec()
    }

    /// ML-KEM encapsulation key bytes.
    pub fn ml_ek_bytes(&self) -> Vec<u8> {
        self.ml_ek.as_bytes().as_slice().to_vec()
    }

    /// The public half.
    pub fn public(&self) -> PqPublicK<M>
    where
        M::EncapsulationKey: Clone,
    {
        PqPublicK {
            x_public: PublicKey::from(&self.x_secret),
            ml_ek: self.ml_ek.clone(),
        }
    }

    /// Serialize: `x_secret(32) || u16(ek_len) || ek || dk`. The encapsulation
    /// key is stored explicitly because the 0.2 KEM API has no portable way to
    /// recover it from the decapsulation key generically.
    pub fn to_bytes(&self) -> Vec<u8> {
        let ek = self.ml_ek.as_bytes();
        let dk = self.ml_dk.as_bytes();
        let mut v = Vec::with_capacity(32 + 2 + ek.len() + dk.len());
        v.extend_from_slice(&self.x_secret.to_bytes());
        v.extend_from_slice(&(ek.len() as u16).to_be_bytes());
        v.extend_from_slice(ek.as_slice());
        v.extend_from_slice(dk.as_slice());
        v
    }

    /// Parse from [`PqSecretK::to_bytes`] output.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 34 {
            return Err(VexilError::MalformedKeyFile("pq secret too short"));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[..32]);
        let ek_len = u16::from_be_bytes([b[32], b[33]]) as usize;
        let rest = &b[34..];
        if rest.len() < ek_len {
            return Err(VexilError::MalformedKeyFile("pq secret truncated"));
        }
        let (ek_bytes, dk_bytes) = rest.split_at(ek_len);
        let enc_ek = Encoded::<M::EncapsulationKey>::try_from(ek_bytes)
            .map_err(|_| VexilError::MalformedKeyFile("bad ml-kem ek"))?;
        let enc_dk = Encoded::<M::DecapsulationKey>::try_from(dk_bytes)
            .map_err(|_| VexilError::MalformedKeyFile("bad ml-kem dk"))?;
        Ok(PqSecretK {
            x_secret: StaticSecret::from(x),
            ml_dk: M::DecapsulationKey::from_bytes(&enc_dk),
            ml_ek: M::EncapsulationKey::from_bytes(&enc_ek),
        })
    }
}

impl<M: KemCore> PqPublicK<M> {
    /// ML-KEM encapsulation key bytes (for the PQ ratchet seed).
    pub fn ml_ek_bytes(&self) -> Vec<u8> {
        self.ml_ek.as_bytes().as_slice().to_vec()
    }

    /// Serialize: `x_public(32) || ml_ek.as_bytes()`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = self.x_public.as_bytes().to_vec();
        v.extend_from_slice(self.ml_ek.as_bytes().as_slice());
        v
    }

    /// Parse from [`PqPublicK::to_bytes`] output.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 32 {
            return Err(VexilError::MalformedKeyFile("pq public too short"));
        }
        let mut x = [0u8; 32];
        x.copy_from_slice(&b[..32]);
        let enc = Encoded::<M::EncapsulationKey>::try_from(&b[32..])
            .map_err(|_| VexilError::MalformedKeyFile("bad ml-kem ek"))?;
        Ok(PqPublicK {
            x_public: PublicKey::from(x),
            ml_ek: M::EncapsulationKey::from_bytes(&enc),
        })
    }
}

fn derive(salt: &[u8], ss1: &[u8], ss2: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(ss1.len() + ss2.len()));
    ikm.extend_from_slice(ss1);
    ikm.extend_from_slice(ss2);
    let hk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(INFO_PQ, key.as_mut())
        .map_err(|e| VexilError::KdfFailure(e.to_string()))?;
    Ok(key)
}

/// Hybrid encapsulation to a PQ recipient. Returns the ephemeral X25519 public
/// key, the ML-KEM ciphertext bytes, and the 32-byte derived key. Shared by the
/// sealed, signed, multi-recipient, and streaming PQ paths.
pub fn pq_encapsulate<M, R>(
    recipient: &PqPublicK<M>,
    rng: &mut R,
) -> Result<(PublicKey, Vec<u8>, Zeroizing<[u8; 32]>)>
where
    M: PqParams,
    R: RngCore + CryptoRng,
{
    let eph_secret = StaticSecret::random_from_rng(&mut *rng);
    let eph_public = PublicKey::from(&eph_secret);
    let ss1 = eph_secret.diffie_hellman(&recipient.x_public);

    let (kem_ct, ss2): (KemCiphertext<M>, SharedKey<M>) = recipient
        .ml_ek
        .encapsulate(rng)
        .map_err(|_| VexilError::KdfFailure("ml-kem encapsulation failed".into()))?;

    let mut salt = Vec::with_capacity(64 + kem_ct.len());
    salt.extend_from_slice(eph_public.as_bytes());
    salt.extend_from_slice(recipient.x_public.as_bytes());
    salt.extend_from_slice(kem_ct.as_slice());
    let key = derive(&salt, ss1.as_bytes(), ss2.as_slice())?;
    Ok((eph_public, kem_ct.as_slice().to_vec(), key))
}

/// Hybrid decapsulation. Recomputes the 32-byte key from the ephemeral X25519
/// key and the ML-KEM ciphertext bytes.
pub fn pq_decapsulate<M: PqParams>(
    recipient: &PqSecretK<M>,
    eph_pk: &[u8; 32],
    kem_ct_bytes: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let eph_public = PublicKey::from(*eph_pk);
    let kem_ct = KemCiphertext::<M>::try_from(kem_ct_bytes)
        .map_err(|_| VexilError::MalformedField("mlkem_ct"))?;
    let ss2 = recipient
        .ml_dk
        .decapsulate(&kem_ct)
        .map_err(|_| VexilError::DecryptionFailed)?;
    let ss1 = recipient.x_secret.diffie_hellman(&eph_public);

    let mut salt = Vec::with_capacity(64 + kem_ct_bytes.len());
    salt.extend_from_slice(eph_pk);
    salt.extend_from_slice(PublicKey::from(&recipient.x_secret).as_bytes());
    salt.extend_from_slice(kem_ct_bytes);
    derive(&salt, ss1.as_bytes(), ss2.as_slice())
}

/// Generate a bare ML-KEM-768 keypair as bytes `(decapsulation_key, encapsulation_key)`.
/// Used by the PQ ratchet, which rotates its own KEM key each turn.
pub fn mlkem768_generate<R: RngCore + CryptoRng>(rng: &mut R) -> (Vec<u8>, Vec<u8>) {
    let (dk, ek) = MlKem768::generate(rng);
    (
        dk.as_bytes().as_slice().to_vec(),
        ek.as_bytes().as_slice().to_vec(),
    )
}

/// Encapsulate to a bare ML-KEM-768 encapsulation key (bytes). Returns `(ct, ss)`.
pub fn mlkem768_encapsulate_raw<R: RngCore + CryptoRng>(
    ek_bytes: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    type Ek = <MlKem768 as KemCore>::EncapsulationKey;
    let enc =
        Encoded::<Ek>::try_from(ek_bytes).map_err(|_| VexilError::MalformedField("mlkem_ek"))?;
    let ek = Ek::from_bytes(&enc);
    let (ct, ss) = ek
        .encapsulate(rng)
        .map_err(|_| VexilError::KdfFailure("ml-kem encapsulation failed".into()))?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(ss.as_slice());
    Ok((ct.as_slice().to_vec(), out))
}

/// Decapsulate with a bare ML-KEM-768 decapsulation key (bytes).
pub fn mlkem768_decapsulate_raw(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    type Dk = <MlKem768 as KemCore>::DecapsulationKey;
    let enc =
        Encoded::<Dk>::try_from(dk_bytes).map_err(|_| VexilError::MalformedField("mlkem_dk"))?;
    let dk = Dk::from_bytes(&enc);
    let ct = KemCiphertext::<MlKem768>::try_from(ct_bytes)
        .map_err(|_| VexilError::MalformedField("mlkem_ct"))?;
    let ss = dk
        .decapsulate(&ct)
        .map_err(|_| VexilError::DecryptionFailed)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(ss.as_slice());
    Ok(out)
}

/// Raw ML-KEM encapsulation (no X25519), for callers that combine the shared
/// secret themselves (e.g. a PQXDH handshake). Returns `(kem_ct_bytes, ss)`.
pub fn mlkem_encapsulate<M, R>(
    recipient: &PqPublicK<M>,
    rng: &mut R,
) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)>
where
    M: PqParams,
    R: RngCore + CryptoRng,
{
    let (kem_ct, ss): (KemCiphertext<M>, SharedKey<M>) = recipient
        .ml_ek
        .encapsulate(rng)
        .map_err(|_| VexilError::KdfFailure("ml-kem encapsulation failed".into()))?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(ss.as_slice());
    Ok((kem_ct.as_slice().to_vec(), out))
}

/// Raw ML-KEM decapsulation matching [`mlkem_encapsulate`].
pub fn mlkem_decapsulate<M: PqParams>(
    recipient: &PqSecretK<M>,
    kem_ct_bytes: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let kem_ct = KemCiphertext::<M>::try_from(kem_ct_bytes)
        .map_err(|_| VexilError::MalformedField("mlkem_ct"))?;
    let ss = recipient
        .ml_dk
        .decapsulate(&kem_ct)
        .map_err(|_| VexilError::DecryptionFailed)?;
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(ss.as_slice());
    Ok(out)
}

/// Seal a message to a PQ recipient (generic tier). Returns `VEX1P-...`.
pub fn seal_pq_rng<M, R>(recipient: &PqPublicK<M>, plaintext: &[u8], rng: &mut R) -> Result<String>
where
    M: PqParams,
    R: RngCore + CryptoRng,
{
    let (eph_public, kem_ct, key) = pq_encapsulate(recipient, rng)?;
    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut env = Envelope::new(M::SUITE, Mode::Sealed);
    env.push(T_EPHEMERAL_PK, eph_public.as_bytes().to_vec());
    env.push(T_MLKEM_CT, kem_ct);
    env.push(T_NONCE, nonce.to_vec());
    let aad = env.aad();
    let ct = aead::seal(Aead::ChaCha20Poly1305, &key, &nonce, plaintext, &aad)?;
    env.push(T_CIPHERTEXT, ct);
    armor(&env, Encoding::Base89)
}

/// Open a PQ envelope with a PQ secret (generic tier).
pub fn open_pq_gen<M: PqParams>(recipient: &PqSecretK<M>, ciphertext: &str) -> Result<Vec<u8>> {
    let env = dearmor_auto(ciphertext)?;
    if env.suite != M::SUITE || env.mode != Mode::Sealed {
        return Err(VexilError::ModeMismatch {
            got: env.mode.name(),
            expected: "pq-sealed",
        });
    }
    let eph_pk: [u8; 32] = env.require_n(T_EPHEMERAL_PK, "ephemeral_pk")?;
    let kem_ct_bytes = env.require(T_MLKEM_CT, "mlkem_ct")?;
    let nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let ct = env.require(T_CIPHERTEXT, "ciphertext")?;

    let key = pq_decapsulate(recipient, &eph_pk, kem_ct_bytes)?;
    let aad = env.aad();
    aead::open(Aead::ChaCha20Poly1305, &key, &nonce, ct, &aad)
}

/// Seal to an ML-KEM-768 recipient. Returns `VEX1P-...`.
pub fn seal_pq(recipient: &PqPublic, plaintext: &[u8]) -> Result<String> {
    seal_pq_rng(recipient, plaintext, &mut OsRng)
}

/// Open an ML-KEM-768 PQ envelope.
pub fn open_pq(recipient: &PqSecret, ciphertext: &str) -> Result<Vec<u8>> {
    open_pq_gen(recipient, ciphertext)
}

/// Seal to an ML-KEM-1024 recipient. Returns `VEX1P-...` (suite `0x05`).
pub fn seal_pq_1024(recipient: &Pq1024Public, plaintext: &[u8]) -> Result<String> {
    seal_pq_rng(recipient, plaintext, &mut OsRng)
}

/// Open an ML-KEM-1024 PQ envelope.
pub fn open_pq_1024(recipient: &Pq1024Secret, ciphertext: &str) -> Result<Vec<u8>> {
    open_pq_gen(recipient, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq768_roundtrip() {
        let bob = PqSecret::generate();
        let ct = seal_pq(&bob.public(), b"quantum secret").unwrap();
        assert!(ct.starts_with("VEX1P-"));
        assert_eq!(open_pq(&bob, &ct).unwrap(), b"quantum secret");
    }

    #[test]
    fn pq1024_roundtrip() {
        let bob = Pq1024Secret::generate();
        let ct = seal_pq_1024(&bob.public(), b"top tier").unwrap();
        assert!(ct.starts_with("VEX1P-"));
        assert_eq!(open_pq_1024(&bob, &ct).unwrap(), b"top tier");
    }

    #[test]
    fn pq_wrong_recipient() {
        let bob = PqSecret::generate();
        let eve = PqSecret::generate();
        let ct = seal_pq(&bob.public(), b"secret").unwrap();
        assert!(open_pq(&eve, &ct).is_err());
    }

    #[test]
    fn pq_secret_and_public_bytes_roundtrip() {
        let bob = Pq1024Secret::generate();
        let pubb = Pq1024Public::from_bytes(&bob.public().to_bytes()).unwrap();
        let ct = seal_pq_1024(&pubb, b"hi").unwrap();
        let bob2 = Pq1024Secret::from_bytes(&bob.to_bytes()).unwrap();
        assert_eq!(open_pq_1024(&bob2, &ct).unwrap(), b"hi");
    }

    #[test]
    fn tier_mismatch_rejected() {
        // A 768 envelope must not open as 1024.
        let bob768 = PqSecret::generate();
        let ct = seal_pq(&bob768.public(), b"x").unwrap();
        let bob1024 = Pq1024Secret::generate();
        assert!(open_pq_1024(&bob1024, &ct).is_err());
    }
}
