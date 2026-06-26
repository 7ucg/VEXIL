//! Multi-recipient stanzas: per-recipient wrapping of a shared data key (DEK).
//!
//! A multi-recipient envelope carries one ephemeral X25519 public key, the
//! payload encrypted once under a random 32-byte DEK, and one *stanza* per
//! recipient. Each stanza wraps the DEK to that recipient:
//!
//! ```text
//! wrap_key = HKDF-SHA256(salt = eph_pk || recipient_x_pub,
//!                        ikm  = ECDH(eph_sk, recipient_x_pub),
//!                        info = "vexil-recipient-v1")
//! stanza   = nonce(12) || ChaCha20Poly1305(wrap_key, nonce, DEK, aad = fpr)
//! ```
//!
//! On decrypt the recipient finds the stanza whose fingerprint matches their
//! own, unwraps the DEK, and decrypts the payload.

use crate::aead;
use crate::error::{Result, VexilError};
use crate::fingerprint::Fingerprint;
use crate::identity::PublicIdentity;
use crate::kex::{hkdf32, transcript, INFO_RECIPIENT};
use crate::suite::{Aead, Suite};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// Wrapped-stanza length: nonce(12) + DEK(32) + tag(16).
pub const STANZA_LEN: usize = 12 + 32 + 16;

/// A per-recipient wrapped DEK plus its target fingerprint.
pub struct WrappedRecipient {
    /// Recipient fingerprint (matches [`crate::Fingerprint`] of their identity).
    pub fpr: Fingerprint,
    /// `nonce(12) || ciphertext||tag`.
    pub stanza: Vec<u8>,
}

/// Wrap `dek` for one recipient using the shared ephemeral secret.
pub fn wrap_dek<R: RngCore + CryptoRng>(
    suite: Suite,
    eph_secret: &StaticSecret,
    eph_public: &PublicKey,
    recipient: &PublicIdentity,
    dek: &[u8; 32],
    rng: &mut R,
) -> Result<WrappedRecipient> {
    let fpr = recipient.fingerprint(suite);
    let shared = eph_secret.diffie_hellman(&recipient.x_public);
    let salt = transcript(eph_public, &recipient.x_public);
    let wrap_key = hkdf32(&salt, shared.as_bytes(), INFO_RECIPIENT)?;

    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let wrapped = aead::seal(
        Aead::ChaCha20Poly1305,
        &wrap_key,
        &nonce,
        dek,
        fpr.as_bytes(),
    )?;

    let mut stanza = Vec::with_capacity(STANZA_LEN);
    stanza.extend_from_slice(&nonce);
    stanza.extend_from_slice(&wrapped);
    Ok(WrappedRecipient { fpr, stanza })
}

/// Attempt to unwrap a stanza addressed to `my_fpr` using our X25519 secret.
/// Returns the DEK on success.
pub fn try_unwrap(
    eph_public: &PublicKey,
    my_secret: &StaticSecret,
    my_fpr: &Fingerprint,
    stanza_fpr: &Fingerprint,
    stanza: &[u8],
) -> Result<Option<[u8; 32]>> {
    if stanza_fpr != my_fpr {
        return Ok(None);
    }
    if stanza.len() != STANZA_LEN {
        return Err(VexilError::MalformedField("recipient_stanza"));
    }
    let my_pub = PublicKey::from(my_secret);
    let shared = my_secret.diffie_hellman(eph_public);
    let salt = transcript(eph_public, &my_pub);
    let wrap_key = hkdf32(&salt, shared.as_bytes(), INFO_RECIPIENT)?;

    let nonce: [u8; 12] = stanza[..12].try_into().unwrap();
    let dek = aead::open(
        Aead::ChaCha20Poly1305,
        &wrap_key,
        &nonce,
        &stanza[12..],
        stanza_fpr.as_bytes(),
    )?;
    let arr: [u8; 32] = dek
        .as_slice()
        .try_into()
        .map_err(|_| VexilError::DecryptionFailed)?;
    Ok(Some(arr))
}
