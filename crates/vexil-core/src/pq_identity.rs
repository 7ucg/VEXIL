//! Post-quantum identities and the signed / multi-recipient PQ modes
//! (feature `pq`).
//!
//! A [`PqIdentity`] bundles everything needed for fully quantum-resistant
//! messaging:
//! - X25519 + ML-KEM-768 for confidentiality (hybrid KEM, see [`crate::pq`]).
//! - Ed25519 + ML-DSA-65 for authenticity (hybrid signatures, see
//!   [`crate::sign_pq`]).
//!
//! Identities fix the ML-KEM-768 tier (suite `0x03`); the raw 1024 tier stays
//! available through [`crate::pq`] for library callers who want it.

use crate::aead;
use crate::codec::{base89_decode, base89_encode};
use crate::envelope::{
    Envelope, Mode, T_CHUNK_COUNT, T_CIPHERTEXT, T_EPHEMERAL_PK, T_MLKEM_CT, T_NONCE,
    T_RECIPIENT_FPR, T_RECIPIENT_STANZA, T_SENDER_PK, T_SENDER_PK_PQ, T_SIGNATURE, T_SIGNATURE_PQ,
};
use crate::error::{Result, VexilError};
use crate::fingerprint::Fingerprint;
use crate::identity::unix_to_rfc3339;
use crate::pq::{pq_decapsulate, pq_encapsulate, PqPublic, PqSecret};
use crate::sign_pq::{hybrid_sign, hybrid_verify, ml_dsa_public, ML_DSA_PK_LEN};
use crate::stream::{read_chunks, read_stream_header, write_chunks, CHUNK_SIZE};
use crate::suite::{Aead, Suite};
use crate::{armor, dearmor_auto, decrypt_with_password, encrypt_with_password, Encoding};
use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, OsRng, RngCore};
use std::io::{Read, Write};
use zeroize::{Zeroize, Zeroizing};

const PQ_ID_HEADER: &str = "VEXIL-IDENTITY-v2:";
const PQ_KEY_HEADER: &str = "VEXIL-KEY-v2:";

/// ML-KEM-768 ciphertext length (the tier identities use).
const KEM_CT_LEN: usize = 1088;
/// A multi-recipient PQ stanza: eph_pk(32) || kem_ct(1088) || nonce(12) || wrapped DEK(32+16).
const STANZA_LEN: usize = 32 + KEM_CT_LEN + 12 + 48;

/// A post-quantum secret identity.
pub struct PqIdentity {
    /// X25519 + ML-KEM-768 KEM secret.
    pub kem: PqSecret,
    /// Ed25519 signing key.
    pub ed_secret: SigningKey,
    /// ML-DSA-65 secret seed.
    pub ml_dsa_seed: [u8; 32],
}

/// The public half of a [`PqIdentity`].
#[derive(Clone)]
pub struct PqPublicIdentity {
    /// X25519 + ML-KEM-768 KEM public key.
    pub kem: PqPublic,
    /// Ed25519 public key.
    pub ed_public: [u8; 32],
    /// ML-DSA-65 public key (1952 bytes).
    pub ml_dsa_public: Vec<u8>,
}

impl PqIdentity {
    /// Generate from the OS CSPRNG.
    pub fn generate() -> Self {
        Self::generate_with_rng(&mut OsRng)
    }

    /// Generate from an explicit RNG.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let kem = PqSecret::generate_with_rng(rng);
        let mut ed_seed = [0u8; 32];
        rng.fill_bytes(&mut ed_seed);
        let ed_secret = SigningKey::from_bytes(&ed_seed);
        ed_seed.zeroize();
        let mut ml_dsa_seed = [0u8; 32];
        rng.fill_bytes(&mut ml_dsa_seed);
        PqIdentity {
            kem,
            ed_secret,
            ml_dsa_seed,
        }
    }

    /// Ed25519 public key bytes (convenience for CLI/tests).
    pub fn ed_public(&self) -> [u8; 32] {
        self.ed_secret.verifying_key().to_bytes()
    }

    /// The public identity.
    pub fn public(&self) -> PqPublicIdentity {
        PqPublicIdentity {
            kem: self.kem.public(),
            ed_public: self.ed_secret.verifying_key().to_bytes(),
            ml_dsa_public: ml_dsa_public(&self.ml_dsa_seed),
        }
    }

    /// Fingerprint over the full public material under a suite.
    pub fn fingerprint(&self, suite: Suite) -> Fingerprint {
        self.public().fingerprint(suite)
    }

    /// Serialize: `u16(kem_len) || kem || ed_seed(32) || ml_dsa_seed(32)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let kem = self.kem.to_bytes();
        let mut v = Vec::with_capacity(2 + kem.len() + 64);
        v.extend_from_slice(&(kem.len() as u16).to_be_bytes());
        v.extend_from_slice(&kem);
        v.extend_from_slice(&self.ed_secret.to_bytes());
        v.extend_from_slice(&self.ml_dsa_seed);
        v
    }

    /// Parse from [`PqIdentity::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 2 {
            return Err(VexilError::MalformedKeyFile("pq identity too short"));
        }
        let kem_len = u16::from_be_bytes([b[0], b[1]]) as usize;
        let rest = &b[2..];
        if rest.len() < kem_len + 64 {
            return Err(VexilError::MalformedKeyFile("pq identity truncated"));
        }
        let kem = PqSecret::from_bytes(&rest[..kem_len])?;
        let mut ed_seed = [0u8; 32];
        ed_seed.copy_from_slice(&rest[kem_len..kem_len + 32]);
        let ed_secret = SigningKey::from_bytes(&ed_seed);
        ed_seed.zeroize();
        let mut ml_dsa_seed = [0u8; 32];
        ml_dsa_seed.copy_from_slice(&rest[kem_len + 32..kem_len + 64]);
        Ok(PqIdentity {
            kem,
            ed_secret,
            ml_dsa_seed,
        })
    }
}

impl PqPublicIdentity {
    /// Combined public material: `kem || ed_public(32) || ml_dsa_public(1952)`.
    pub fn public_bytes(&self) -> Vec<u8> {
        let kem = self.kem.to_bytes();
        let mut v = Vec::with_capacity(kem.len() + 32 + ML_DSA_PK_LEN);
        v.extend_from_slice(&kem);
        v.extend_from_slice(&self.ed_public);
        v.extend_from_slice(&self.ml_dsa_public);
        v
    }

    /// Serialize for a `.pub` file: `u16(kem_len) || kem || ed(32) || ml_dsa(1952)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let kem = self.kem.to_bytes();
        let mut v = Vec::with_capacity(2 + kem.len() + 32 + ML_DSA_PK_LEN);
        v.extend_from_slice(&(kem.len() as u16).to_be_bytes());
        v.extend_from_slice(&kem);
        v.extend_from_slice(&self.ed_public);
        v.extend_from_slice(&self.ml_dsa_public);
        v
    }

    /// Parse from [`PqPublicIdentity::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 2 {
            return Err(VexilError::MalformedKeyFile("pq public too short"));
        }
        let kem_len = u16::from_be_bytes([b[0], b[1]]) as usize;
        let rest = &b[2..];
        if rest.len() < kem_len + 32 + ML_DSA_PK_LEN {
            return Err(VexilError::MalformedKeyFile("pq public truncated"));
        }
        let kem = PqPublic::from_bytes(&rest[..kem_len])?;
        let mut ed_public = [0u8; 32];
        ed_public.copy_from_slice(&rest[kem_len..kem_len + 32]);
        let ml_dsa_public = rest[kem_len + 32..kem_len + 32 + ML_DSA_PK_LEN].to_vec();
        Ok(PqPublicIdentity {
            kem,
            ed_public,
            ml_dsa_public,
        })
    }

    /// Fingerprint over the full public material under a suite.
    pub fn fingerprint(&self, suite: Suite) -> Fingerprint {
        Fingerprint::of(suite, &self.public_bytes())
    }
}

fn sig_transcript(eph_pk: &[u8; 32], recipient_x: &[u8; 32], ct: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(64 + ct.len());
    t.extend_from_slice(eph_pk);
    t.extend_from_slice(recipient_x);
    t.extend_from_slice(ct);
    t
}

/// Seal to a PQ recipient and sign with hybrid (Ed25519 + ML-DSA) signatures.
pub fn seal_signed_pq(
    recipient: &PqPublicIdentity,
    sender: &PqIdentity,
    plaintext: &[u8],
) -> Result<String> {
    seal_signed_pq_rng(recipient, sender, plaintext, &mut OsRng)
}

/// Deterministic variant of [`seal_signed_pq`].
pub fn seal_signed_pq_rng<R: RngCore + CryptoRng>(
    recipient: &PqPublicIdentity,
    sender: &PqIdentity,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<String> {
    let (eph_public, kem_ct, key) = pq_encapsulate(&recipient.kem, rng)?;
    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut env = Envelope::new(Suite::XKyberChaPoly, Mode::Signed);
    env.push(T_EPHEMERAL_PK, eph_public.as_bytes().to_vec());
    env.push(T_MLKEM_CT, kem_ct);
    env.push(T_NONCE, nonce.to_vec());
    env.push(
        T_SENDER_PK,
        sender.ed_secret.verifying_key().to_bytes().to_vec(),
    );
    env.push(T_SENDER_PK_PQ, ml_dsa_public(&sender.ml_dsa_seed));
    let aad = env.aad();
    let ct = aead::seal(Aead::ChaCha20Poly1305, &key, &nonce, plaintext, &aad)?;

    let transcript = sig_transcript(
        eph_public.as_bytes(),
        recipient.kem.x_public.as_bytes(),
        &ct,
    );
    let sig = hybrid_sign(&sender.ed_secret, &sender.ml_dsa_seed, &transcript);
    env.push(T_SIGNATURE, sig.ed.to_vec());
    env.push(T_SIGNATURE_PQ, sig.ml_dsa);
    env.push(T_CIPHERTEXT, ct);
    armor(&env, Encoding::Base89)
}

/// Open a hybrid-signed PQ envelope. With `expected_sender`, both the Ed25519
/// and ML-DSA sender keys must match it. Returns `(plaintext, sender_ed_pk)`.
pub fn open_signed_pq(
    recipient: &PqIdentity,
    ciphertext: &str,
    expected_sender: Option<&PqPublicIdentity>,
) -> Result<(Vec<u8>, [u8; 32])> {
    let env = dearmor_auto(ciphertext)?;
    if env.suite != Suite::XKyberChaPoly || env.mode != Mode::Signed {
        return Err(VexilError::ModeMismatch {
            got: env.mode.name(),
            expected: "pq-signed",
        });
    }
    let eph_pk: [u8; 32] = env.require_n(T_EPHEMERAL_PK, "ephemeral_pk")?;
    let kem_ct = env.require(T_MLKEM_CT, "mlkem_ct")?;
    let nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let sender_ed: [u8; 32] = env.require_n(T_SENDER_PK, "sender_pk")?;
    let sender_pq = env.require(T_SENDER_PK_PQ, "sender_pk_pq")?;
    let ed_sig: [u8; 64] = env.require_n(T_SIGNATURE, "signature")?;
    let pq_sig = env.require(T_SIGNATURE_PQ, "signature_pq")?;
    let ct = env.require(T_CIPHERTEXT, "ciphertext")?;

    if let Some(exp) = expected_sender {
        if exp.ed_public != sender_ed || exp.ml_dsa_public != sender_pq {
            return Err(VexilError::BadSignature);
        }
    }

    let transcript = sig_transcript(&eph_pk, recipient.kem.public().x_public.as_bytes(), ct);
    hybrid_verify(&sender_ed, sender_pq, &transcript, &ed_sig, pq_sig)?;

    let key = pq_decapsulate(&recipient.kem, &eph_pk, kem_ct)?;
    let aad = env.aad();
    let pt = aead::open(Aead::ChaCha20Poly1305, &key, &nonce, ct, &aad)?;
    Ok((pt, sender_ed))
}

/// Encrypt once to many PQ recipients. Returns `VEX1P-...` (mode multi).
pub fn seal_multi_pq(recipients: &[PqPublicIdentity], plaintext: &[u8]) -> Result<String> {
    seal_multi_pq_rng(recipients, plaintext, &mut OsRng)
}

/// Deterministic variant of [`seal_multi_pq`].
pub fn seal_multi_pq_rng<R: RngCore + CryptoRng>(
    recipients: &[PqPublicIdentity],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<String> {
    if recipients.is_empty() {
        return Err(VexilError::MissingField("recipients"));
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(dek.as_mut());
    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut env = Envelope::new(Suite::XKyberChaPoly, Mode::MultiRecipient);
    env.push(T_NONCE, nonce.to_vec());
    for r in recipients {
        let fpr = r.fingerprint(Suite::XKyberChaPoly);
        let (eph_public, kem_ct, wrap_key) = pq_encapsulate(&r.kem, rng)?;
        let mut wrap_nonce = [0u8; 12];
        rng.fill_bytes(&mut wrap_nonce);
        let wrapped = aead::seal(
            Aead::ChaCha20Poly1305,
            &wrap_key,
            &wrap_nonce,
            dek.as_ref(),
            fpr.as_bytes(),
        )?;
        let mut stanza = Vec::with_capacity(STANZA_LEN);
        stanza.extend_from_slice(eph_public.as_bytes());
        stanza.extend_from_slice(&kem_ct);
        stanza.extend_from_slice(&wrap_nonce);
        stanza.extend_from_slice(&wrapped);
        env.push(T_RECIPIENT_FPR, fpr.as_bytes().to_vec());
        env.push(T_RECIPIENT_STANZA, stanza);
    }
    let aad = env.aad();
    let ct = aead::seal(Aead::ChaCha20Poly1305, &dek, &nonce, plaintext, &aad)?;
    env.push(T_CIPHERTEXT, ct);
    armor(&env, Encoding::Base89)
}

/// Open a multi-recipient PQ envelope with your PQ identity.
pub fn open_multi_pq(recipient: &PqIdentity, ciphertext: &str) -> Result<Vec<u8>> {
    let env = dearmor_auto(ciphertext)?;
    if env.suite != Suite::XKyberChaPoly || env.mode != Mode::MultiRecipient {
        return Err(VexilError::ModeMismatch {
            got: env.mode.name(),
            expected: "pq-multi",
        });
    }
    let nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let ct = env.require(T_CIPHERTEXT, "ciphertext")?;
    let my_fpr = recipient.public().fingerprint(Suite::XKyberChaPoly);

    let fprs: Vec<&[u8]> = env.get_all(T_RECIPIENT_FPR).collect();
    let stanzas: Vec<&[u8]> = env.get_all(T_RECIPIENT_STANZA).collect();
    // Try every matching stanza; skip malformed/unwrappable ones (a crafted
    // fingerprint collision must not block our real stanza).
    for (fb, sb) in fprs.iter().zip(stanzas.iter()) {
        if Fingerprint::from_bytes(fb)
            .map(|f| f != my_fpr)
            .unwrap_or(true)
        {
            continue;
        }
        if sb.len() != STANZA_LEN {
            continue;
        }
        let mut eph_pk = [0u8; 32];
        eph_pk.copy_from_slice(&sb[..32]);
        let kem_ct = &sb[32..32 + KEM_CT_LEN];
        let mut wrap_nonce = [0u8; 12];
        wrap_nonce.copy_from_slice(&sb[32 + KEM_CT_LEN..32 + KEM_CT_LEN + 12]);
        let wrapped = &sb[32 + KEM_CT_LEN + 12..];

        let Ok(wrap_key) = pq_decapsulate(&recipient.kem, &eph_pk, kem_ct) else {
            continue;
        };
        let Ok(dek) = aead::open(
            Aead::ChaCha20Poly1305,
            &wrap_key,
            &wrap_nonce,
            wrapped,
            my_fpr.as_bytes(),
        ) else {
            continue;
        };
        let Ok(dek) = <[u8; 32]>::try_from(dek.as_slice()) else {
            continue;
        };
        let dek = Zeroizing::new(dek);
        let aad = env.aad();
        return aead::open(Aead::ChaCha20Poly1305, &dek, &nonce, ct, &aad);
    }
    Err(VexilError::NoMatchingRecipient)
}

fn now_unix() -> i64 {
    crate::now_unix_secs()
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

fn field<'a>(fields: &'a [(String, String)], key: &str) -> Result<&'a str> {
    fields
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .ok_or(VexilError::MalformedKeyFile("missing field"))
}

impl PqIdentity {
    /// Serialize to a `VEXIL-IDENTITY-v2:` file. With a passphrase the `key=`
    /// field is itself a `VEX1-` ciphertext of the secret blob.
    pub fn to_identity_file(&self, passphrase: Option<&[u8]>) -> Result<String> {
        let mut secret = self.to_bytes();
        let key_field = match passphrase {
            Some(pw) => encrypt_with_password(pw, &secret)?,
            None => base89_encode(&secret),
        };
        secret.zeroize();
        let suite = Suite::XKyberChaPoly;
        Ok(format!(
            "{PQ_ID_HEADER}\nsuite=0x{:02x}\ncreated={}\nfingerprint={}\nkey={}\n",
            suite.as_byte(),
            unix_to_rfc3339(now_unix()),
            self.fingerprint(suite).to_short(),
            key_field
        ))
    }

    /// Parse a `VEXIL-IDENTITY-v2:` file, decrypting with `passphrase` if wrapped.
    pub fn parse_identity_file(text: &str, passphrase: Option<&[u8]>) -> Result<PqIdentity> {
        let fields = parse_kv(text, PQ_ID_HEADER)?;
        let key = field(&fields, "key")?;
        let mut secret = if key.starts_with("VEX1-") {
            let pw = passphrase.ok_or(VexilError::MalformedKeyFile(
                "identity is passphrase-protected",
            ))?;
            decrypt_with_password(pw, key)?
        } else {
            base89_decode(key)?
        };
        let id = PqIdentity::from_bytes(&secret)?;
        secret.zeroize();
        Ok(id)
    }
}

impl PqPublicIdentity {
    /// Serialize to a `VEXIL-KEY-v2:` pubkey file.
    pub fn to_pub_file(&self) -> String {
        let suite = Suite::XKyberChaPoly;
        format!(
            "{PQ_KEY_HEADER}\nsuite=0x{:02x}\nfingerprint={}\nkey={}\n",
            suite.as_byte(),
            self.fingerprint(suite).to_short(),
            base89_encode(&self.to_bytes())
        )
    }

    /// Parse a `VEXIL-KEY-v2:` pubkey file.
    pub fn parse_pub_file(text: &str) -> Result<PqPublicIdentity> {
        let fields = parse_kv(text, PQ_KEY_HEADER)?;
        let key = field(&fields, "key")?;
        PqPublicIdentity::from_bytes(&base89_decode(key)?)
    }
}

/// Encrypt a framed stream to a PQ recipient (key from the hybrid KEM, no
/// password). Writes the metadata envelope followed by chunk frames.
pub fn encrypt_stream_pq<W: Write, R: RngCore + CryptoRng>(
    recipient: &PqPublic,
    plaintext: &[u8],
    out: &mut W,
    rng: &mut R,
) -> Result<()> {
    let (eph_public, kem_ct, key) = pq_encapsulate(recipient, rng)?;
    let mut base_nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut base_nonce);
    let chunk_count = plaintext.len().div_ceil(CHUNK_SIZE).max(1) as u32;

    let mut env = Envelope::new(Suite::XKyberChaPoly, Mode::Streaming);
    env.push(T_EPHEMERAL_PK, eph_public.as_bytes().to_vec());
    env.push(T_MLKEM_CT, kem_ct);
    env.push(T_NONCE, base_nonce.to_vec());
    env.push(T_CHUNK_COUNT, chunk_count.to_be_bytes().to_vec());
    let header = env.serialize();
    out.write_all(&header)?;
    write_chunks(
        Aead::ChaCha20Poly1305,
        &key,
        &base_nonce,
        &header,
        chunk_count,
        plaintext,
        out,
    )
}

/// Decrypt a PQ framed stream produced by [`encrypt_stream_pq`].
pub fn decrypt_stream_pq<R: Read, W: Write>(
    recipient: &PqSecret,
    input: &mut R,
    out: &mut W,
) -> Result<()> {
    let (env, header) = read_stream_header(input)?;
    if env.suite != Suite::XKyberChaPoly {
        return Err(VexilError::ModeMismatch {
            got: env.mode.name(),
            expected: "pq-streaming",
        });
    }
    let eph_pk: [u8; 32] = env.require_n(T_EPHEMERAL_PK, "ephemeral_pk")?;
    let kem_ct = env.require(T_MLKEM_CT, "mlkem_ct")?;
    let base_nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let count_bytes: [u8; 4] = env.require_n(T_CHUNK_COUNT, "chunk_count")?;
    let chunk_count = u32::from_be_bytes(count_bytes);
    let key = pq_decapsulate(recipient, &eph_pk, kem_ct)?;
    read_chunks(
        Aead::ChaCha20Poly1305,
        &key,
        &base_nonce,
        &header,
        chunk_count,
        input,
        out,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_identity_bytes_roundtrip() {
        let id = PqIdentity::generate();
        let back = PqIdentity::from_bytes(&id.to_bytes()).unwrap();
        assert_eq!(back.to_bytes(), id.to_bytes());
        let pubb = PqPublicIdentity::from_bytes(&id.public().to_bytes()).unwrap();
        assert_eq!(pubb.to_bytes(), id.public().to_bytes());
    }

    #[test]
    fn fingerprint_stable() {
        let id = PqIdentity::generate();
        assert_eq!(
            id.fingerprint(Suite::XKyberChaPoly),
            id.public().fingerprint(Suite::XKyberChaPoly)
        );
    }

    #[test]
    fn signed_pq_roundtrip() {
        let bob = PqIdentity::generate();
        let alice = PqIdentity::generate();
        let ct = seal_signed_pq(&bob.public(), &alice, b"pq signed").unwrap();
        let (pt, who) = open_signed_pq(&bob, &ct, Some(&alice.public())).unwrap();
        assert_eq!(pt, b"pq signed");
        assert_eq!(who, alice.ed_public());
        let (pt2, _) = open_signed_pq(&bob, &ct, None).unwrap();
        assert_eq!(pt2, b"pq signed");
    }

    #[test]
    fn signed_pq_wrong_sender_rejected() {
        let bob = PqIdentity::generate();
        let alice = PqIdentity::generate();
        let mallory = PqIdentity::generate();
        let ct = seal_signed_pq(&bob.public(), &alice, b"x").unwrap();
        assert!(open_signed_pq(&bob, &ct, Some(&mallory.public())).is_err());
    }

    #[test]
    fn multi_pq_roundtrip() {
        let people: Vec<PqIdentity> = (0..3).map(|_| PqIdentity::generate()).collect();
        let pubs: Vec<PqPublicIdentity> = people.iter().map(|p| p.public()).collect();
        let ct = seal_multi_pq(&pubs, b"group pq").unwrap();
        for p in &people {
            assert_eq!(open_multi_pq(p, &ct).unwrap(), b"group pq");
        }
        assert!(open_multi_pq(&PqIdentity::generate(), &ct).is_err());
    }

    #[test]
    fn pq_identity_file_roundtrip() {
        let id = PqIdentity::generate();
        let plain = id.to_identity_file(None).unwrap();
        assert!(plain.starts_with("VEXIL-IDENTITY-v2:"));
        let back = PqIdentity::parse_identity_file(&plain, None).unwrap();
        assert_eq!(back.to_bytes(), id.to_bytes());

        let wrapped = id.to_identity_file(Some(b"pw")).unwrap();
        assert!(wrapped.contains("key=VEX1-"));
        assert!(PqIdentity::parse_identity_file(&wrapped, None).is_err());
        let back2 = PqIdentity::parse_identity_file(&wrapped, Some(b"pw")).unwrap();
        assert_eq!(back2.to_bytes(), id.to_bytes());

        let pubf = id.public().to_pub_file();
        assert!(pubf.starts_with("VEXIL-KEY-v2:"));
        let pb = PqPublicIdentity::parse_pub_file(&pubf).unwrap();
        assert_eq!(pb.to_bytes(), id.public().to_bytes());
    }

    #[test]
    fn stream_pq_roundtrip() {
        let bob = PqIdentity::generate();
        let data = vec![0x33u8; CHUNK_SIZE * 2 + 77];
        let mut ct = Vec::new();
        encrypt_stream_pq(&bob.public().kem, &data, &mut ct, &mut OsRng).unwrap();
        let mut pt = Vec::new();
        decrypt_stream_pq(&bob.kem, &mut ct.as_slice(), &mut pt).unwrap();
        assert_eq!(pt, data);
        // wrong recipient fails
        let eve = PqIdentity::generate();
        let mut bad = Vec::new();
        assert!(decrypt_stream_pq(&eve.kem, &mut ct.as_slice(), &mut bad).is_err());
    }
}
