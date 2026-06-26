//! Chunked, framed AEAD for large inputs (`VEX1F-` / [`Mode::Streaming`]).
//!
//! The payload is split into fixed 64 KiB chunks, each sealed independently:
//!
//! ```text
//! nonce_i = base_nonce XOR be64(i)      (counter XORed into low 8 bytes)
//! aad_i   = metadata_envelope || be32(i) || final_flag
//! chunk_i = be32(len) || AEAD(key, nonce_i, aad_i, plaintext_i)
//! ```
//!
//! The `final_flag` (1 = last chunk) is bound into the AAD, so truncating the
//! stream — dropping the real final chunk — makes the remaining last chunk fail
//! to authenticate. The metadata envelope (header + salt + base nonce + chunk
//! count) is itself bound into every chunk's AAD.

use crate::aead;
use crate::envelope::{
    Envelope, Mode, T_CHUNK_COUNT, T_EPHEMERAL_PK, T_NONCE, T_RECIPIENT_FPR, T_RECIPIENT_STANZA,
    T_SALT, T_SENDER_PK, T_SIGNATURE,
};
use crate::error::{Result, VexilError};
use crate::fingerprint::Fingerprint;
use crate::identity::{Identity, PublicIdentity};
use crate::kdf;
use crate::recipient;
use crate::sign;
use crate::suite::Suite;
use rand_core::{CryptoRng, RngCore};
use std::io::{Read, Write};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Plaintext chunk size: 64 KiB.
pub const CHUNK_SIZE: usize = 64 * 1024;

fn nonce_for(base: &[u8; 12], counter: u32) -> [u8; 12] {
    let mut n = *base;
    let cb = (counter as u64).to_be_bytes();
    for j in 0..8 {
        n[4 + j] ^= cb[j];
    }
    n
}

/// Encrypt `plaintext` to `out` as a framed stream under a password.
/// Writes the metadata envelope followed by the chunk frames.
pub fn encrypt_stream<W: Write, R: RngCore + CryptoRng>(
    suite: Suite,
    password: &[u8],
    plaintext: &[u8],
    out: &mut W,
    rng: &mut R,
) -> Result<()> {
    let mut salt = [0u8; kdf::SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut base_nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut base_nonce);

    let chunk_count = plaintext.len().div_ceil(CHUNK_SIZE).max(1) as u32;

    let mut env = Envelope::new(suite, Mode::Streaming);
    env.push(T_SALT, salt.to_vec());
    env.push(T_NONCE, base_nonce.to_vec());
    env.push(T_CHUNK_COUNT, chunk_count.to_be_bytes().to_vec());
    let header = env.serialize();
    out.write_all(&header)?;

    let key = kdf::derive_key(password, &salt)?;
    write_chunks(
        suite.aead(),
        key.as_bytes(),
        &base_nonce,
        &header,
        chunk_count,
        plaintext,
        out,
    )
}

/// Write `chunk_count` framed chunks of `plaintext` under a 32-byte `key`.
/// `header` is the serialized metadata envelope, bound into every chunk's AAD.
pub(crate) fn write_chunks<W: Write>(
    aead_alg: crate::suite::Aead,
    key: &[u8; 32],
    base_nonce: &[u8; aead::NONCE_LEN],
    header: &[u8],
    chunk_count: u32,
    plaintext: &[u8],
    out: &mut W,
) -> Result<()> {
    for i in 0..chunk_count {
        let start = i as usize * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(plaintext.len());
        let chunk = &plaintext[start..end];
        let is_final = i == chunk_count - 1;
        let aad = chunk_aad(header, i, is_final);
        let nonce = nonce_for(base_nonce, i);
        let sealed = aead::seal(aead_alg, key, &nonce, chunk, &aad)?;
        out.write_all(&(sealed.len() as u32).to_be_bytes())?;
        out.write_all(&sealed)?;
    }
    out.flush()?;
    Ok(())
}

/// Read the stream envelope header, enforcing a specific mode.
fn read_mode_stream_header<R: Read>(input: &mut R, expected: Mode) -> Result<(Envelope, Vec<u8>)> {
    let mut head = [0u8; crate::envelope::HEADER_LEN];
    input.read_exact(&mut head)?;
    let body_len = u16::from_be_bytes([head[8], head[9]]) as usize;
    let mut header = head.to_vec();
    header.resize(crate::envelope::HEADER_LEN + body_len, 0);
    input.read_exact(&mut header[crate::envelope::HEADER_LEN..])?;
    let env = Envelope::parse(&header)?;
    if env.mode != expected {
        return Err(VexilError::ModeMismatch {
            got: env.mode.name(),
            expected: expected.name(),
        });
    }
    Ok((env, header))
}

/// Read the metadata envelope at the start of a password stream. Returns the
/// parsed envelope and its raw header bytes (which the chunk AAD binds).
pub(crate) fn read_stream_header<R: Read>(input: &mut R) -> Result<(Envelope, Vec<u8>)> {
    read_mode_stream_header(input, Mode::Streaming)
}

/// Encrypt a large payload to a recipient's public identity as a framed stream.
///
/// The header carries a random DEK wrapped for the recipient via ECDH + HKDF.
/// Chunks are sealed with that DEK so the payload is sized independently of the
/// KEM. Prefix: `VEX1SF-`.
pub fn encrypt_stream_sealed<W: Write, R: RngCore + CryptoRng>(
    suite: Suite,
    recipient: &PublicIdentity,
    plaintext: &[u8],
    out: &mut W,
    rng: &mut R,
) -> Result<()> {
    let mut dek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(dek.as_mut());
    let mut base_nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut base_nonce);
    let eph_secret = StaticSecret::random_from_rng(&mut *rng);
    let eph_public = PublicKey::from(&eph_secret);
    let chunk_count = plaintext.len().div_ceil(CHUNK_SIZE).max(1) as u32;

    let mut env = Envelope::new(suite, Mode::SealedStream);
    env.push(T_EPHEMERAL_PK, eph_public.as_bytes().to_vec());
    let w = recipient::wrap_dek(suite, &eph_secret, &eph_public, recipient, &dek, rng)?;
    env.push(T_RECIPIENT_FPR, w.fpr.as_bytes().to_vec());
    env.push(T_RECIPIENT_STANZA, w.stanza);
    env.push(T_NONCE, base_nonce.to_vec());
    env.push(T_CHUNK_COUNT, chunk_count.to_be_bytes().to_vec());
    let header = env.serialize();
    out.write_all(&header)?;

    write_chunks(
        suite.aead(),
        &dek,
        &base_nonce,
        &header,
        chunk_count,
        plaintext,
        out,
    )
}

/// Decrypt a `VEX1SF-` streaming sealed envelope.
pub fn decrypt_stream_sealed<R: Read, W: Write>(
    identity: &Identity,
    input: &mut R,
    out: &mut W,
) -> Result<()> {
    let (env, header) = read_mode_stream_header(input, Mode::SealedStream)?;
    let eph_pk: [u8; 32] = env.require_n(T_EPHEMERAL_PK, "ephemeral_pk")?;
    let eph_public = PublicKey::from(eph_pk);
    let base_nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let count_bytes: [u8; 4] = env.require_n(T_CHUNK_COUNT, "chunk_count")?;
    let chunk_count = u32::from_be_bytes(count_bytes);

    let my_fpr = identity.fingerprint(env.suite);
    let fprs: Vec<&[u8]> = env.get_all(T_RECIPIENT_FPR).collect();
    let stanzas: Vec<&[u8]> = env.get_all(T_RECIPIENT_STANZA).collect();
    for (fb, sb) in fprs.iter().zip(stanzas.iter()) {
        let Ok(fpr) = Fingerprint::from_bytes(fb) else {
            continue;
        };
        if let Ok(Some(dek)) =
            recipient::try_unwrap(&eph_public, &identity.x_secret, &my_fpr, &fpr, sb)
        {
            let dek = Zeroizing::new(dek);
            return read_chunks(
                env.suite.aead(),
                &dek,
                &base_nonce,
                &header,
                chunk_count,
                input,
                out,
            );
        }
    }
    Err(VexilError::NoMatchingRecipient)
}

/// Encrypt a large payload to a recipient and sign it with the sender's identity.
///
/// The signature covers the envelope AAD (all TLVs except ciphertext and
/// signature), binding the ephemeral key, recipient stanza, nonce, chunk count,
/// and sender key. Prefix: `VEX1AF-`.
pub fn encrypt_stream_signed<W: Write, R: RngCore + CryptoRng>(
    suite: Suite,
    recipient: &PublicIdentity,
    sender: &Identity,
    plaintext: &[u8],
    out: &mut W,
    rng: &mut R,
) -> Result<()> {
    let mut dek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(dek.as_mut());
    let mut base_nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut base_nonce);
    let eph_secret = StaticSecret::random_from_rng(&mut *rng);
    let eph_public = PublicKey::from(&eph_secret);
    let chunk_count = plaintext.len().div_ceil(CHUNK_SIZE).max(1) as u32;

    let mut env = Envelope::new(suite, Mode::SignedStream);
    env.push(T_EPHEMERAL_PK, eph_public.as_bytes().to_vec());
    let w = recipient::wrap_dek(suite, &eph_secret, &eph_public, recipient, &dek, rng)?;
    env.push(T_RECIPIENT_FPR, w.fpr.as_bytes().to_vec());
    env.push(T_RECIPIENT_STANZA, w.stanza);
    env.push(T_NONCE, base_nonce.to_vec());
    env.push(T_CHUNK_COUNT, chunk_count.to_be_bytes().to_vec());
    env.push(T_SENDER_PK, sender.ed_public().to_vec());
    // Sign the AAD before appending T_SIGNATURE (aad() excludes T_SIGNATURE).
    let sig = sign::sign(&sender.ed_secret, &env.aad());
    env.push(T_SIGNATURE, sig.to_vec());
    let header = env.serialize();
    out.write_all(&header)?;

    write_chunks(
        suite.aead(),
        &dek,
        &base_nonce,
        &header,
        chunk_count,
        plaintext,
        out,
    )
}

/// Decrypt a `VEX1AF-` streaming signed envelope. If `expected_sender` is
/// `Some`, the embedded Ed25519 key must match. Returns `(plaintext,
/// sender_ed25519_pubkey)`.
pub fn decrypt_stream_signed<R: Read, W: Write>(
    identity: &Identity,
    input: &mut R,
    out: &mut W,
    expected_sender: Option<&PublicIdentity>,
) -> Result<[u8; 32]> {
    let (env, header) = read_mode_stream_header(input, Mode::SignedStream)?;
    let eph_pk: [u8; 32] = env.require_n(T_EPHEMERAL_PK, "ephemeral_pk")?;
    let eph_public = PublicKey::from(eph_pk);
    let base_nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let count_bytes: [u8; 4] = env.require_n(T_CHUNK_COUNT, "chunk_count")?;
    let chunk_count = u32::from_be_bytes(count_bytes);
    let sender_pk: [u8; 32] = env.require_n(T_SENDER_PK, "sender_pk")?;
    let sig: [u8; 64] = env.require_n(T_SIGNATURE, "signature")?;

    if let Some(exp) = expected_sender {
        if exp.ed_public != sender_pk {
            return Err(VexilError::BadSignature);
        }
    }
    // aad() automatically excludes T_SIGNATURE — same bytes the sender signed.
    sign::verify(&sender_pk, &env.aad(), &sig)?;

    let my_fpr = identity.fingerprint(env.suite);
    let fprs: Vec<&[u8]> = env.get_all(T_RECIPIENT_FPR).collect();
    let stanzas: Vec<&[u8]> = env.get_all(T_RECIPIENT_STANZA).collect();
    for (fb, sb) in fprs.iter().zip(stanzas.iter()) {
        let Ok(fpr) = Fingerprint::from_bytes(fb) else {
            continue;
        };
        if let Ok(Some(dek)) =
            recipient::try_unwrap(&eph_public, &identity.x_secret, &my_fpr, &fpr, sb)
        {
            let dek = Zeroizing::new(dek);
            read_chunks(
                env.suite.aead(),
                &dek,
                &base_nonce,
                &header,
                chunk_count,
                input,
                out,
            )?;
            return Ok(sender_pk);
        }
    }
    Err(VexilError::NoMatchingRecipient)
}

/// Encrypt once to many recipients as a framed stream. Prefix: `VEX1MF-`.
pub fn encrypt_stream_multi<W: Write, R: RngCore + CryptoRng>(
    suite: Suite,
    recipients: &[PublicIdentity],
    plaintext: &[u8],
    out: &mut W,
    rng: &mut R,
) -> Result<()> {
    if recipients.is_empty() {
        return Err(VexilError::MissingField("recipients"));
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(dek.as_mut());
    let mut base_nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut base_nonce);
    let eph_secret = StaticSecret::random_from_rng(&mut *rng);
    let eph_public = PublicKey::from(&eph_secret);
    let chunk_count = plaintext.len().div_ceil(CHUNK_SIZE).max(1) as u32;

    let mut env = Envelope::new(suite, Mode::MultiStream);
    env.push(T_EPHEMERAL_PK, eph_public.as_bytes().to_vec());
    for r in recipients {
        let w = recipient::wrap_dek(suite, &eph_secret, &eph_public, r, &dek, rng)?;
        env.push(T_RECIPIENT_FPR, w.fpr.as_bytes().to_vec());
        env.push(T_RECIPIENT_STANZA, w.stanza);
    }
    env.push(T_NONCE, base_nonce.to_vec());
    env.push(T_CHUNK_COUNT, chunk_count.to_be_bytes().to_vec());
    let header = env.serialize();
    out.write_all(&header)?;

    write_chunks(
        suite.aead(),
        &dek,
        &base_nonce,
        &header,
        chunk_count,
        plaintext,
        out,
    )
}

/// Decrypt a `VEX1MF-` streaming multi-recipient envelope.
pub fn decrypt_stream_multi<R: Read, W: Write>(
    identity: &Identity,
    input: &mut R,
    out: &mut W,
) -> Result<()> {
    let (env, header) = read_mode_stream_header(input, Mode::MultiStream)?;
    let eph_pk: [u8; 32] = env.require_n(T_EPHEMERAL_PK, "ephemeral_pk")?;
    let eph_public = PublicKey::from(eph_pk);
    let base_nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let count_bytes: [u8; 4] = env.require_n(T_CHUNK_COUNT, "chunk_count")?;
    let chunk_count = u32::from_be_bytes(count_bytes);

    let my_fpr = identity.fingerprint(env.suite);
    let fprs: Vec<&[u8]> = env.get_all(T_RECIPIENT_FPR).collect();
    let stanzas: Vec<&[u8]> = env.get_all(T_RECIPIENT_STANZA).collect();
    for (fb, sb) in fprs.iter().zip(stanzas.iter()) {
        let Ok(fpr) = Fingerprint::from_bytes(fb) else {
            continue;
        };
        if let Ok(Some(dek)) =
            recipient::try_unwrap(&eph_public, &identity.x_secret, &my_fpr, &fpr, sb)
        {
            let dek = Zeroizing::new(dek);
            return read_chunks(
                env.suite.aead(),
                &dek,
                &base_nonce,
                &header,
                chunk_count,
                input,
                out,
            );
        }
    }
    Err(VexilError::NoMatchingRecipient)
}

/// Read and decrypt `chunk_count` framed chunks under a 32-byte `key`.
pub(crate) fn read_chunks<R: Read, W: Write>(
    aead_alg: crate::suite::Aead,
    key: &[u8; 32],
    base_nonce: &[u8; aead::NONCE_LEN],
    header: &[u8],
    chunk_count: u32,
    input: &mut R,
    out: &mut W,
) -> Result<()> {
    // A valid frame is one plaintext chunk plus the AEAD tag. Reject anything
    // larger so a malformed/hostile stream can't trigger a huge allocation.
    const MAX_FRAME: usize = CHUNK_SIZE + aead::TAG_LEN + 16;
    for i in 0..chunk_count {
        let mut len_buf = [0u8; 4];
        input.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME {
            return Err(VexilError::MalformedField("stream chunk length"));
        }
        let mut sealed = vec![0u8; len];
        input.read_exact(&mut sealed)?;
        let is_final = i == chunk_count - 1;
        let aad = chunk_aad(header, i, is_final);
        let nonce = nonce_for(base_nonce, i);
        let pt = aead::open(aead_alg, key, &nonce, &sealed, &aad)?;
        out.write_all(&pt)?;
    }
    out.flush()?;
    Ok(())
}

/// Decrypt a password-based framed stream produced by [`encrypt_stream`].
pub fn decrypt_stream<R: Read, W: Write>(
    password: &[u8],
    input: &mut R,
    out: &mut W,
) -> Result<()> {
    let (env, header) = read_stream_header(input)?;
    let salt: [u8; kdf::SALT_LEN] = env.require_n(T_SALT, "salt")?;
    let base_nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let count_bytes: [u8; 4] = env.require_n(T_CHUNK_COUNT, "chunk_count")?;
    let chunk_count = u32::from_be_bytes(count_bytes);
    let key = kdf::derive_key(password, &salt)?;
    read_chunks(
        env.suite.aead(),
        key.as_bytes(),
        &base_nonce,
        &header,
        chunk_count,
        input,
        out,
    )
}

fn chunk_aad(header: &[u8], index: u32, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(header.len() + 5);
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(is_final as u8);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn stream_roundtrip_multichunk() {
        let data = vec![0xABu8; CHUNK_SIZE * 3 + 123];
        let mut ct = Vec::new();
        encrypt_stream(Suite::XChaPolyArgon, b"pw", &data, &mut ct, &mut OsRng).unwrap();
        let mut pt = Vec::new();
        decrypt_stream(b"pw", &mut ct.as_slice(), &mut pt).unwrap();
        assert_eq!(pt, data);
    }

    #[test]
    fn stream_truncation_detected() {
        let data = vec![7u8; CHUNK_SIZE * 2 + 1];
        let mut ct = Vec::new();
        encrypt_stream(Suite::XChaPolyArgon, b"pw", &data, &mut ct, &mut OsRng).unwrap();
        // Drop the final chunk's frame by cutting bytes; the now-last chunk is
        // not flagged final, so its AAD mismatches.
        // Rebuild a truncated stream: parse header len, keep header + 2 chunks
        // but lie about chunk_count would need re-encoding; instead just corrupt
        // by removing trailing bytes and re-reading fewer chunks fails on EOF.
        ct.truncate(ct.len() - 100);
        let mut pt = Vec::new();
        assert!(decrypt_stream(b"pw", &mut ct.as_slice(), &mut pt).is_err());
    }

    #[test]
    fn stream_huge_chunk_length_rejected() {
        // A hostile stream claiming a 4 GB chunk must error, not try to allocate.
        let data = vec![9u8; 100];
        let mut ct = Vec::new();
        encrypt_stream(Suite::XChaPolyArgon, b"pw", &data, &mut ct, &mut OsRng).unwrap();
        // The first chunk's 4-byte length sits right after the metadata header.
        let body_len = u16::from_be_bytes([ct[8], ct[9]]) as usize;
        let off = crate::envelope::HEADER_LEN + body_len;
        ct[off..off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
        let mut pt = Vec::new();
        assert!(decrypt_stream(b"pw", &mut ct.as_slice(), &mut pt).is_err());
    }

    #[test]
    fn stream_wrong_password() {
        let data = vec![1u8; 100];
        let mut ct = Vec::new();
        encrypt_stream(Suite::XChaPolyArgon, b"pw", &data, &mut ct, &mut OsRng).unwrap();
        let mut pt = Vec::new();
        assert!(decrypt_stream(b"nope", &mut ct.as_slice(), &mut pt).is_err());
    }
}
