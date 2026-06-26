//! Hybrid signatures: Ed25519 + ML-DSA-65 (FIPS 204), feature `pq`.
//!
//! A hybrid signature is valid only when **both** the classical Ed25519 and the
//! post-quantum ML-DSA signatures verify. An attacker has to break both schemes
//! to forge one, so authenticity survives a quantum break of the elliptic curve.
//!
//! ML-DSA-65 sizes: 32-byte seed (the secret serialization), 1952-byte public
//! key, 3309-byte signature.

use crate::error::{Result, VexilError};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, KeyExport, KeyInit, Keypair, MlDsa65, Seed,
    Signature as MlDsaSignature, Signer, SigningKey, Verifier, VerifyingKey,
};

/// ML-DSA-65 secret seed length.
pub const ML_DSA_SEED_LEN: usize = 32;
/// ML-DSA-65 public key length.
pub const ML_DSA_PK_LEN: usize = 1952;
/// ML-DSA-65 signature length.
pub const ML_DSA_SIG_LEN: usize = 3309;

/// Build an ML-DSA-65 signing key from its 32-byte seed.
pub fn ml_dsa_key_from_seed(seed: &[u8; ML_DSA_SEED_LEN]) -> SigningKey<MlDsa65> {
    SigningKey::<MlDsa65>::new(&Seed::from(*seed))
}

/// The 1952-byte ML-DSA-65 public key for a seed.
pub fn ml_dsa_public(seed: &[u8; ML_DSA_SEED_LEN]) -> Vec<u8> {
    ml_dsa_key_from_seed(seed)
        .verifying_key()
        .to_bytes()
        .as_slice()
        .to_vec()
}

/// Sign `msg` with ML-DSA-65, returning the 3309-byte signature.
pub fn ml_dsa_sign(seed: &[u8; ML_DSA_SEED_LEN], msg: &[u8]) -> Vec<u8> {
    let sk = ml_dsa_key_from_seed(seed);
    let sig: MlDsaSignature<MlDsa65> = sk.sign(msg);
    sig.encode().as_slice().to_vec()
}

/// Verify an ML-DSA-65 signature.
pub fn ml_dsa_verify(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> Result<()> {
    let enc_pk =
        EncodedVerifyingKey::<MlDsa65>::try_from(pk_bytes).map_err(|_| VexilError::BadSignature)?;
    let vk = VerifyingKey::<MlDsa65>::new(&enc_pk);
    let enc_sig =
        EncodedSignature::<MlDsa65>::try_from(sig_bytes).map_err(|_| VexilError::BadSignature)?;
    let sig = MlDsaSignature::<MlDsa65>::decode(&enc_sig).ok_or(VexilError::BadSignature)?;
    vk.verify(msg, &sig).map_err(|_| VexilError::BadSignature)
}

/// A combined Ed25519 + ML-DSA-65 signature over the same message.
pub struct HybridSignature {
    /// 64-byte Ed25519 signature.
    pub ed: [u8; 64],
    /// 3309-byte ML-DSA-65 signature.
    pub ml_dsa: Vec<u8>,
}

/// Sign `msg` under both Ed25519 and ML-DSA-65.
pub fn hybrid_sign(
    ed_sk: &ed25519_dalek::SigningKey,
    ml_dsa_seed: &[u8; ML_DSA_SEED_LEN],
    msg: &[u8],
) -> HybridSignature {
    HybridSignature {
        ed: crate::sign::sign(ed_sk, msg),
        ml_dsa: ml_dsa_sign(ml_dsa_seed, msg),
    }
}

/// Verify a hybrid signature. Both halves must verify, or this fails.
pub fn hybrid_verify(
    ed_pk: &[u8; 32],
    ml_dsa_pk: &[u8],
    msg: &[u8],
    ed_sig: &[u8; 64],
    ml_dsa_sig: &[u8],
) -> Result<()> {
    crate::sign::verify(ed_pk, msg, ed_sig)?;
    ml_dsa_verify(ml_dsa_pk, msg, ml_dsa_sig)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ml_dsa_roundtrip() {
        let seed = [9u8; 32];
        let pk = ml_dsa_public(&seed);
        assert_eq!(pk.len(), ML_DSA_PK_LEN);
        let sig = ml_dsa_sign(&seed, b"message");
        assert_eq!(sig.len(), ML_DSA_SIG_LEN);
        assert!(ml_dsa_verify(&pk, b"message", &sig).is_ok());
        assert!(ml_dsa_verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn hybrid_roundtrip() {
        let ed = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let seed = [7u8; 32];
        let ed_pk = ed.verifying_key().to_bytes();
        let ml_pk = ml_dsa_public(&seed);
        let sig = hybrid_sign(&ed, &seed, b"hi");
        assert!(hybrid_verify(&ed_pk, &ml_pk, b"hi", &sig.ed, &sig.ml_dsa).is_ok());
        // break the PQ half: classical still valid, hybrid must fail
        let mut bad = sig.ml_dsa.clone();
        bad[0] ^= 1;
        assert!(hybrid_verify(&ed_pk, &ml_pk, b"hi", &sig.ed, &bad).is_err());
        // break the classical half
        let mut bad_ed = sig.ed;
        bad_ed[0] ^= 1;
        assert!(hybrid_verify(&ed_pk, &ml_pk, b"hi", &bad_ed, &sig.ml_dsa).is_err());
    }
}
