//! # VEXIL Protocol
//!
//! VEXIL is a versioned, algorithm-agile hybrid-encryption protocol built
//! **only** on peer-reviewed primitives — Argon2id, ChaCha20-Poly1305,
//! AES-256-GCM, X25519, Ed25519, ML-KEM-768, HKDF, SHA-256 and BLAKE2b. The
//! novelty is in the wire format, key management, encoding, and multi-recipient
//! design, never in the math.
//!
//! ## Modes & prefixes
//!
//! | Prefix    | Mode            | API |
//! |-----------|-----------------|-----|
//! | `VEX1-`   | symmetric       | [`encrypt_with_password`] / [`decrypt_with_password`] |
//! | `VEX1S-`  | sealed box      | [`seal_to`] / [`open_sealed`] |
//! | `VEX1A-`  | signed sealed   | [`seal_signed`] / [`open_signed`] |
//! | `VEX1M-`  | multi-recipient | [`seal_multi`] / [`open_multi`] |
//! | `VEX1F-`  | streaming       | [`stream`] module |
//! | `VEX1P-`  | post-quantum    | [`pq`] module (feature `pq`) |
//!
//! ```
//! # use vexil_core::*;
//! let ct = encrypt_with_password(b"pw", b"secret").unwrap();
//! assert!(ct.starts_with("VEX1-"));
//! assert_eq!(decrypt_with_password(b"pw", &ct).unwrap(), b"secret");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod aead;
pub mod codec;
pub mod envelope;
pub mod error;
pub mod fingerprint;
pub mod identity;
pub mod kdf;
pub mod kex;
pub mod pad;
pub mod recipient;
pub mod sign;
pub mod stream;
pub mod suite;

#[cfg(feature = "pq")]
pub mod pq;

#[cfg(feature = "pq")]
pub mod sign_pq;

#[cfg(feature = "pq")]
pub mod pq_identity;

use envelope::{
    Envelope, Mode, T_CIPHERTEXT, T_EPHEMERAL_PK, T_EXPIRY, T_KDF_PRESET, T_NONCE, T_RECIPIENT_FPR,
    T_RECIPIENT_STANZA, T_SALT, T_SENDER_PK, T_SIGNATURE,
};
use error::{Result, VexilError};
use kex::{hkdf32, transcript, INFO_SEALED};
use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroizing;

pub use codec::Encoding;
pub use error::VexilError as Error;
pub use fingerprint::Fingerprint;
pub use identity::{Identity, PublicIdentity};
pub use kdf::Argon2Preset;
pub use rand_core;
pub use suite::Suite;
pub use x25519_dalek::{PublicKey, StaticSecret};

// Wire prefixes.
const P_SYM: &str = "VEX1-";
const P_SEALED: &str = "VEX1S-";
const P_SIGNED: &str = "VEX1A-";
const P_MULTI: &str = "VEX1M-";
const P_STREAM: &str = "VEX1F-";
const P_PQ: &str = "VEX1P-";
const P_SEALED_STREAM: &str = "VEX1SF-";
const P_SIGNED_STREAM: &str = "VEX1AF-";
const P_MULTI_STREAM: &str = "VEX1MF-";

/// The human-facing prefix for a (mode, suite) pair.
pub fn prefix_for(mode: Mode, suite: Suite) -> &'static str {
    if suite.is_pq() {
        return P_PQ;
    }
    match mode {
        Mode::Symmetric => P_SYM,
        Mode::Sealed => P_SEALED,
        Mode::Signed => P_SIGNED,
        Mode::MultiRecipient => P_MULTI,
        Mode::Streaming => P_STREAM,
        Mode::SealedStream => P_SEALED_STREAM,
        Mode::SignedStream => P_SIGNED_STREAM,
        Mode::MultiStream => P_MULTI_STREAM,
    }
}

/// Above this serialized size, `armor` prefers hex over Base89. Base89 decoding
/// is O(n²); hex is linear and still source-string-safe. Small ciphertexts keep
/// the denser Base89 for easy embedding.
pub const BASE89_ARMOR_LIMIT: usize = 2048;

/// Encode an envelope as `<prefix><encoded body>`. Errors if the envelope
/// exceeds the 16-bit length limit (rather than silently truncating). A Base89
/// preference is auto-upgraded to hex for large envelopes to avoid the O(n²)
/// codec; [`dearmor_auto`] detects the encoding on the way back.
pub fn armor(env: &Envelope, encoding: Encoding) -> Result<String> {
    env.validate_lengths()?;
    let bytes = env.serialize();
    let enc = if encoding == Encoding::Base89 && bytes.len() > BASE89_ARMOR_LIMIT {
        Encoding::Hex
    } else {
        encoding
    };
    Ok(format!(
        "{}{}",
        prefix_for(env.mode, env.suite),
        enc.encode(&bytes)
    ))
}

fn strip_known_prefix(s: &str) -> &str {
    // Longer prefixes before shorter ones so e.g. "VEX1SF-" isn't stripped by "VEX1S-".
    [
        P_PQ,
        P_SEALED_STREAM,
        P_SIGNED_STREAM,
        P_MULTI_STREAM,
        P_SIGNED,
        P_SEALED,
        P_MULTI,
        P_STREAM,
        P_SYM,
    ]
    .into_iter()
    .find_map(|p| s.strip_prefix(p))
    .unwrap_or(s)
}

/// Strip any known `VEX1*-` prefix and decode the body with `encoding`.
pub fn dearmor(s: &str, encoding: Encoding) -> Result<Envelope> {
    let body = strip_known_prefix(s.trim());
    Envelope::parse(&encoding.decode(body)?)
}

/// Strip the prefix and auto-detect the body encoding (PEM header, lowercase
/// hex, or Base89). Used by the decrypt paths so a ciphertext armored in any of
/// those encodings just works. Tries the detected encoding first, then falls
/// back to the others if it does not yield a parseable envelope (defensive
/// against a rare detection miss).
pub fn dearmor_auto(s: &str) -> Result<Envelope> {
    let body = strip_known_prefix(s.trim());
    let primary = Encoding::detect(body);
    for enc in [primary, Encoding::Base89, Encoding::Hex, Encoding::Pem] {
        if let Ok(bin) = enc.decode(body) {
            if let Ok(env) = Envelope::parse(&bin) {
                return Ok(env);
            }
        }
    }
    Envelope::parse(&primary.decode(body)?)
}

/// Current unix time in seconds. Returns 0 on `wasm32-unknown-unknown`, where
/// `SystemTime::now()` panics (no wall clock); on that target `created`
/// timestamps read as the epoch and expiry is not enforced.
pub fn now_unix_secs() -> i64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
    #[cfg(target_arch = "wasm32")]
    {
        0
    }
}

/// Enforce an AAD-bound expiry TLV, if present.
fn check_expiry(env: &Envelope) -> Result<()> {
    if let Some(b) = env.get(T_EXPIRY) {
        let arr: [u8; 8] = b
            .try_into()
            .map_err(|_| VexilError::MalformedField("expiry"))?;
        let expiry = i64::from_be_bytes(arr);
        if now_unix_secs() > expiry {
            return Err(VexilError::Expired(expiry));
        }
    }
    Ok(())
}

fn require_mode(env: &Envelope, expected: Mode) -> Result<()> {
    if env.mode != expected {
        return Err(VexilError::ModeMismatch {
            got: env.mode.name(),
            expected: expected.name(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Symmetric (password) — VEX1-
// ---------------------------------------------------------------------------

/// Encrypt with a password using the default suite. Returns `VEX1-...`.
pub fn encrypt_with_password(password: &[u8], plaintext: &[u8]) -> Result<String> {
    encrypt_with_password_rng(Suite::default(), password, plaintext, &mut OsRng)
}

/// Encrypt with a password and an explicit suite.
pub fn encrypt_with_password_suite(
    suite: Suite,
    password: &[u8],
    plaintext: &[u8],
) -> Result<String> {
    encrypt_with_password_rng(suite, password, plaintext, &mut OsRng)
}

/// Deterministic variant taking an explicit RNG (for tests / reproducibility).
pub fn encrypt_with_password_rng<R: RngCore + CryptoRng>(
    suite: Suite,
    password: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<String> {
    let mut salt = [0u8; kdf::SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut env = Envelope::new(suite, Mode::Symmetric);
    env.push(T_SALT, salt.to_vec());
    env.push(T_NONCE, nonce.to_vec());

    let key = kdf::derive_key(password, &salt)?;
    let aad = env.aad();
    let ct = aead::seal(suite.aead(), key.as_bytes(), &nonce, plaintext, &aad)?;
    env.push(T_CIPHERTEXT, ct);

    armor(&env, Encoding::Base89)
}

/// Decrypt a `VEX1-...` string produced by [`encrypt_with_password`].
pub fn decrypt_with_password(password: &[u8], ciphertext: &str) -> Result<Vec<u8>> {
    let env = dearmor_auto(ciphertext)?;
    require_mode(&env, Mode::Symmetric)?;
    check_expiry(&env)?;

    let salt: [u8; kdf::SALT_LEN] = env.require_n(T_SALT, "salt")?;
    let nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let ct = env.require(T_CIPHERTEXT, "ciphertext")?;

    let preset = env
        .get(T_KDF_PRESET)
        .and_then(|b| kdf::Argon2Preset::from_byte(b[0]))
        .unwrap_or(kdf::Argon2Preset::Default);
    let key = kdf::derive_key_preset(password, &salt, preset)?;
    let aad = env.aad();
    aead::open(env.suite.aead(), key.as_bytes(), &nonce, ct, &aad)
}

/// Encrypt with a password and an AAD-bound expiry timestamp.
///
/// The expiry is bound into the AEAD tag — tampering with or removing the
/// `expiry` TLV fails authentication. Decryption returns
/// [`Error::Expired`](VexilError::Expired) if the current time is past
/// `expiry_unix_secs`.
pub fn encrypt_with_password_expiry(
    password: &[u8],
    plaintext: &[u8],
    expiry_unix_secs: i64,
) -> Result<String> {
    encrypt_with_password_expiry_rng(
        Suite::default(),
        password,
        plaintext,
        expiry_unix_secs,
        &mut OsRng,
    )
}

/// Deterministic expiry variant with explicit suite + RNG (for tests).
pub fn encrypt_with_password_expiry_rng<R: RngCore + CryptoRng>(
    suite: Suite,
    password: &[u8],
    plaintext: &[u8],
    expiry_unix_secs: i64,
    rng: &mut R,
) -> Result<String> {
    let mut salt = [0u8; kdf::SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut env = Envelope::new(suite, Mode::Symmetric);
    env.push(T_SALT, salt.to_vec());
    env.push(T_NONCE, nonce.to_vec());
    env.push(T_EXPIRY, expiry_unix_secs.to_be_bytes().to_vec());

    let key = kdf::derive_key(password, &salt)?;
    let aad = env.aad();
    let ct = aead::seal(suite.aead(), key.as_bytes(), &nonce, plaintext, &aad)?;
    env.push(T_CIPHERTEXT, ct);

    armor(&env, Encoding::Base89)
}

/// Encrypt with a password using a specific [`Argon2Preset`] for key
/// derivation. Use [`Argon2Preset::Interactive`] for UI flows where latency
/// matters, or [`Argon2Preset::Sensitive`] for long-lived at-rest keys.
pub fn encrypt_with_password_preset(
    preset: Argon2Preset,
    password: &[u8],
    plaintext: &[u8],
) -> Result<String> {
    let mut salt = [0u8; kdf::SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; aead::NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let suite = Suite::default();
    let mut env = Envelope::new(suite, Mode::Symmetric);
    env.push(T_SALT, salt.to_vec());
    env.push(T_NONCE, nonce.to_vec());
    // Record the preset so the decryptor uses the same KDF parameters.
    env.push(T_KDF_PRESET, vec![preset.as_byte()]);
    let key = kdf::derive_key_preset(password, &salt, preset)?;
    let aad = env.aad();
    let ct = aead::seal(suite.aead(), key.as_bytes(), &nonce, plaintext, &aad)?;
    env.push(T_CIPHERTEXT, ct);
    armor(&env, Encoding::Base89)
}

// ---------------------------------------------------------------------------
// Sealed box (anonymous) — VEX1S-
// ---------------------------------------------------------------------------

/// Seal a message to a recipient's public identity (anonymous). `VEX1S-...`.
pub fn seal_to(recipient: &PublicIdentity, plaintext: &[u8]) -> Result<String> {
    seal_to_rng(Suite::default(), recipient, plaintext, &mut OsRng)
}

/// Deterministic sealed-box variant with explicit suite + RNG.
pub fn seal_to_rng<R: RngCore + CryptoRng>(
    suite: Suite,
    recipient: &PublicIdentity,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<String> {
    let eph_secret = StaticSecret::random_from_rng(&mut *rng);
    let eph_public = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient.x_public);
    let salt = transcript(&eph_public, &recipient.x_public);
    let key = hkdf32(&salt, shared.as_bytes(), INFO_SEALED)?;

    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut env = Envelope::new(suite, Mode::Sealed);
    env.push(T_EPHEMERAL_PK, eph_public.as_bytes().to_vec());
    env.push(T_NONCE, nonce.to_vec());
    let aad = env.aad();
    let ct = aead::seal(suite.aead(), &key, &nonce, plaintext, &aad)?;
    env.push(T_CIPHERTEXT, ct);

    armor(&env, Encoding::Base89)
}

/// Open a `VEX1S-...` sealed box with your identity.
pub fn open_sealed(identity: &Identity, ciphertext: &str) -> Result<Vec<u8>> {
    let env = dearmor_auto(ciphertext)?;
    require_mode(&env, Mode::Sealed)?;
    check_expiry(&env)?;
    let eph_pk: [u8; 32] = env.require_n(T_EPHEMERAL_PK, "ephemeral_pk")?;
    let eph_public = PublicKey::from(eph_pk);
    let nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let ct = env.require(T_CIPHERTEXT, "ciphertext")?;

    let shared = identity.x_secret.diffie_hellman(&eph_public);
    let salt = transcript(&eph_public, &identity.x_public());
    let key = hkdf32(&salt, shared.as_bytes(), INFO_SEALED)?;
    let aad = env.aad();
    aead::open(env.suite.aead(), &key, &nonce, ct, &aad)
}

// ---------------------------------------------------------------------------
// Signed sealed box — VEX1A-
// ---------------------------------------------------------------------------

/// Seal a message to a recipient and sign it with the sender's identity.
/// `VEX1A-...`. The signature covers `eph_pk || recipient_x_pub || ciphertext`.
pub fn seal_signed(
    recipient: &PublicIdentity,
    sender: &Identity,
    plaintext: &[u8],
) -> Result<String> {
    seal_signed_rng(Suite::default(), recipient, sender, plaintext, &mut OsRng)
}

/// Deterministic signed-seal variant with explicit suite + RNG.
pub fn seal_signed_rng<R: RngCore + CryptoRng>(
    suite: Suite,
    recipient: &PublicIdentity,
    sender: &Identity,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<String> {
    let eph_secret = StaticSecret::random_from_rng(&mut *rng);
    let eph_public = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&recipient.x_public);
    let salt = transcript(&eph_public, &recipient.x_public);
    let key = hkdf32(&salt, shared.as_bytes(), INFO_SEALED)?;

    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut env = Envelope::new(suite, Mode::Signed);
    env.push(T_EPHEMERAL_PK, eph_public.as_bytes().to_vec());
    env.push(T_NONCE, nonce.to_vec());
    env.push(T_SENDER_PK, sender.ed_public().to_vec());
    let aad = env.aad();
    let ct = aead::seal(suite.aead(), &key, &nonce, plaintext, &aad)?;

    let mut signed = Vec::with_capacity(32 + 32 + ct.len());
    signed.extend_from_slice(eph_public.as_bytes());
    signed.extend_from_slice(recipient.x_public.as_bytes());
    signed.extend_from_slice(&ct);
    let sig = sign::sign(&sender.ed_secret, &signed);

    env.push(T_SIGNATURE, sig.to_vec());
    env.push(T_CIPHERTEXT, ct);
    armor(&env, Encoding::Base89)
}

/// Open a `VEX1A-...` signed sealed box. If `expected_sender` is `Some`, the
/// signature must verify against that identity's Ed25519 key; otherwise the
/// signature is verified against the embedded sender key but not bound to a
/// known identity. Returns `(plaintext, sender_ed25519_pubkey)`.
pub fn open_signed(
    identity: &Identity,
    ciphertext: &str,
    expected_sender: Option<&PublicIdentity>,
) -> Result<(Vec<u8>, [u8; 32])> {
    let env = dearmor_auto(ciphertext)?;
    require_mode(&env, Mode::Signed)?;
    check_expiry(&env)?;
    let eph_pk: [u8; 32] = env.require_n(T_EPHEMERAL_PK, "ephemeral_pk")?;
    let eph_public = PublicKey::from(eph_pk);
    let nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let sender_pk: [u8; 32] = env.require_n(T_SENDER_PK, "sender_pk")?;
    let sig: [u8; 64] = env.require_n(T_SIGNATURE, "signature")?;
    let ct = env.require(T_CIPHERTEXT, "ciphertext")?;

    if let Some(exp) = expected_sender {
        if exp.ed_public != sender_pk {
            return Err(VexilError::BadSignature);
        }
    }

    let mut signed = Vec::with_capacity(32 + 32 + ct.len());
    signed.extend_from_slice(&eph_pk);
    signed.extend_from_slice(identity.x_public().as_bytes());
    signed.extend_from_slice(ct);
    sign::verify(&sender_pk, &signed, &sig)?;

    let shared = identity.x_secret.diffie_hellman(&eph_public);
    let salt = transcript(&eph_public, &identity.x_public());
    let key = hkdf32(&salt, shared.as_bytes(), INFO_SEALED)?;
    let aad = env.aad();
    let pt = aead::open(env.suite.aead(), &key, &nonce, ct, &aad)?;
    Ok((pt, sender_pk))
}

// ---------------------------------------------------------------------------
// Multi-recipient — VEX1M-
// ---------------------------------------------------------------------------

/// Encrypt once to many recipients. Each recipient can independently decrypt.
/// `VEX1M-...`.
pub fn seal_multi(recipients: &[PublicIdentity], plaintext: &[u8]) -> Result<String> {
    seal_multi_rng(Suite::default(), recipients, plaintext, &mut OsRng)
}

/// Deterministic multi-recipient variant with explicit suite + RNG.
pub fn seal_multi_rng<R: RngCore + CryptoRng>(
    suite: Suite,
    recipients: &[PublicIdentity],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<String> {
    if recipients.is_empty() {
        return Err(VexilError::MissingField("recipients"));
    }
    let mut dek = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(dek.as_mut());
    let eph_secret = StaticSecret::random_from_rng(&mut *rng);
    let eph_public = PublicKey::from(&eph_secret);

    let mut nonce = [0u8; aead::NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut env = Envelope::new(suite, Mode::MultiRecipient);
    env.push(T_EPHEMERAL_PK, eph_public.as_bytes().to_vec());
    env.push(T_NONCE, nonce.to_vec());
    for r in recipients {
        let w = recipient::wrap_dek(suite, &eph_secret, &eph_public, r, &dek, rng)?;
        env.push(T_RECIPIENT_FPR, w.fpr.as_bytes().to_vec());
        env.push(T_RECIPIENT_STANZA, w.stanza);
    }
    let aad = env.aad();
    let ct = aead::seal(suite.aead(), &dek, &nonce, plaintext, &aad)?;
    env.push(T_CIPHERTEXT, ct);

    armor(&env, Encoding::Base89)
}

/// Open a `VEX1M-...` multi-recipient envelope with your identity.
pub fn open_multi(identity: &Identity, ciphertext: &str) -> Result<Vec<u8>> {
    let env = dearmor_auto(ciphertext)?;
    require_mode(&env, Mode::MultiRecipient)?;
    check_expiry(&env)?;
    let eph_pk: [u8; 32] = env.require_n(T_EPHEMERAL_PK, "ephemeral_pk")?;
    let eph_public = PublicKey::from(eph_pk);
    let nonce: [u8; aead::NONCE_LEN] = env.require_n(T_NONCE, "nonce")?;
    let ct = env.require(T_CIPHERTEXT, "ciphertext")?;

    let my_fpr = identity.fingerprint(env.suite);
    let fprs: Vec<&[u8]> = env.get_all(T_RECIPIENT_FPR).collect();
    let stanzas: Vec<&[u8]> = env.get_all(T_RECIPIENT_STANZA).collect();

    // Try every stanza whose fingerprint matches ours; a malformed or
    // unwrappable stanza (e.g. a crafted fingerprint collision) must not stop us
    // from reaching our real stanza, so skip on error rather than failing.
    for (fb, sb) in fprs.iter().zip(stanzas.iter()) {
        let Ok(fpr) = Fingerprint::from_bytes(fb) else {
            continue;
        };
        if let Ok(Some(dek)) =
            recipient::try_unwrap(&eph_public, &identity.x_secret, &my_fpr, &fpr, sb)
        {
            let dek = Zeroizing::new(dek);
            let aad = env.aad();
            return aead::open(env.suite.aead(), &dek, &nonce, ct, &aad);
        }
    }
    Err(VexilError::NoMatchingRecipient)
}

// ---------------------------------------------------------------------------
// Detached signatures — VEXSIG-
// ---------------------------------------------------------------------------

const P_SIG: &str = "VEXSIG-";

/// Sign a message with an identity's Ed25519 key. Returns a detached
/// `VEXSIG-...` signature string (does not contain the message).
pub fn sign_detached(identity: &Identity, msg: &[u8]) -> String {
    let sig = sign::sign(&identity.ed_secret, msg);
    format!("{}{}", P_SIG, codec::base89_encode(&sig))
}

/// Verify a `VEXSIG-...` detached signature over `msg` against a signer's
/// public identity (Ed25519).
pub fn verify_detached(signer: &PublicIdentity, msg: &[u8], sig: &str) -> Result<()> {
    let body = sig
        .trim()
        .strip_prefix(P_SIG)
        .ok_or(VexilError::InvalidEnvelope)?;
    let raw = Encoding::detect(body).decode(body)?;
    let sig_bytes: [u8; 64] = raw
        .as_slice()
        .try_into()
        .map_err(|_| VexilError::BadSignature)?;
    sign::verify(&signer.ed_public, msg, &sig_bytes)
}

/// Convenience X25519+Ed25519 identity generator (re-export of
/// [`Identity::generate`]).
pub fn keygen() -> Identity {
    Identity::generate()
}

// ---------------------------------------------------------------------------
// Streaming sealed box (public key) — VEX1SF-
// ---------------------------------------------------------------------------

/// Encrypt a large payload to a recipient as a framed stream. Unlike
/// [`seal_to`], this handles arbitrarily large files without loading them fully
/// into memory on decrypt (caller supplies a `Write` sink). `VEX1SF-`.
pub fn seal_to_stream<W: std::io::Write>(
    recipient: &PublicIdentity,
    plaintext: &[u8],
    out: &mut W,
) -> Result<()> {
    stream::encrypt_stream_sealed(Suite::default(), recipient, plaintext, out, &mut OsRng)
}

/// Convenience overload: encrypt to bytes. For very large inputs prefer the
/// `Write`-based [`seal_to_stream`] to avoid double-buffering.
pub fn seal_to_stream_vec(recipient: &PublicIdentity, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    seal_to_stream(recipient, plaintext, &mut out)?;
    Ok(out)
}

/// Decrypt a `VEX1SF-` streaming sealed payload produced by [`seal_to_stream`].
pub fn open_stream_sealed<R: std::io::Read, W: std::io::Write>(
    identity: &Identity,
    input: &mut R,
    out: &mut W,
) -> Result<()> {
    stream::decrypt_stream_sealed(identity, input, out)
}

/// Convenience overload: decrypt from a byte slice.
pub fn open_stream_sealed_vec(identity: &Identity, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = ciphertext;
    open_stream_sealed(identity, &mut cur, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Streaming signed sealed box — VEX1AF-
// ---------------------------------------------------------------------------

/// Encrypt a large payload to a recipient and sign it with the sender's
/// identity. `VEX1AF-`. The signature covers all envelope metadata.
pub fn seal_signed_stream<W: std::io::Write>(
    recipient: &PublicIdentity,
    sender: &Identity,
    plaintext: &[u8],
    out: &mut W,
) -> Result<()> {
    stream::encrypt_stream_signed(
        Suite::default(),
        recipient,
        sender,
        plaintext,
        out,
        &mut OsRng,
    )
}

/// Convenience overload: returns bytes.
pub fn seal_signed_stream_vec(
    recipient: &PublicIdentity,
    sender: &Identity,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    seal_signed_stream(recipient, sender, plaintext, &mut out)?;
    Ok(out)
}

/// Decrypt a `VEX1AF-` streaming signed envelope. Returns the sender's
/// Ed25519 public key. If `expected_sender` is `Some`, its key must match.
pub fn open_stream_signed<R: std::io::Read, W: std::io::Write>(
    identity: &Identity,
    input: &mut R,
    out: &mut W,
    expected_sender: Option<&PublicIdentity>,
) -> Result<[u8; 32]> {
    stream::decrypt_stream_signed(identity, input, out, expected_sender)
}

/// Convenience overload: returns `(plaintext, sender_ed25519_pubkey)`.
pub fn open_stream_signed_vec(
    identity: &Identity,
    ciphertext: &[u8],
    expected_sender: Option<&PublicIdentity>,
) -> Result<(Vec<u8>, [u8; 32])> {
    let mut out = Vec::new();
    let mut cur = ciphertext;
    let sender_pk = open_stream_signed(identity, &mut cur, &mut out, expected_sender)?;
    Ok((out, sender_pk))
}

// ---------------------------------------------------------------------------
// Streaming multi-recipient — VEX1MF-
// ---------------------------------------------------------------------------

/// Encrypt once to many recipients as a framed stream. `VEX1MF-`.
pub fn seal_multi_stream<W: std::io::Write>(
    recipients: &[PublicIdentity],
    plaintext: &[u8],
    out: &mut W,
) -> Result<()> {
    stream::encrypt_stream_multi(Suite::default(), recipients, plaintext, out, &mut OsRng)
}

/// Convenience overload: returns bytes.
pub fn seal_multi_stream_vec(recipients: &[PublicIdentity], plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    seal_multi_stream(recipients, plaintext, &mut out)?;
    Ok(out)
}

/// Decrypt a `VEX1MF-` streaming multi-recipient envelope.
pub fn open_stream_multi<R: std::io::Read, W: std::io::Write>(
    identity: &Identity,
    input: &mut R,
    out: &mut W,
) -> Result<()> {
    stream::decrypt_stream_multi(identity, input, out)
}

/// Convenience overload: returns plaintext bytes.
pub fn open_stream_multi_vec(identity: &Identity, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut cur = ciphertext;
    open_stream_multi(identity, &mut cur, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u64) -> Identity {
        Identity::generate_with_rng(&mut testrng(seed))
    }

    // Reuse the deterministic test RNG from identity module shape.
    fn testrng(seed: u64) -> impl RngCore + CryptoRng {
        TestRng(seed.max(1))
    }
    struct TestRng(u64);
    impl RngCore for TestRng {
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
        fn fill_bytes(&mut self, d: &mut [u8]) {
            for c in d.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                c.copy_from_slice(&v[..c.len()]);
            }
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(d);
            Ok(())
        }
    }
    impl CryptoRng for TestRng {}

    #[test]
    fn symmetric_roundtrip_all_suites() {
        for suite in [Suite::XChaPolyArgon, Suite::XAesGcmArgon] {
            let ct = encrypt_with_password_rng(suite, b"pw", b"hello", &mut testrng(1)).unwrap();
            assert_eq!(decrypt_with_password(b"pw", &ct).unwrap(), b"hello");
        }
    }

    #[test]
    fn symmetric_wrong_password() {
        let ct = encrypt_with_password(b"right", b"data").unwrap();
        assert!(decrypt_with_password(b"wrong", &ct).is_err());
    }

    #[test]
    fn sealed_roundtrip() {
        let bob = id(10);
        let ct = seal_to(&bob.public(), b"secret").unwrap();
        assert!(ct.starts_with("VEX1S-"));
        assert_eq!(open_sealed(&bob, &ct).unwrap(), b"secret");
    }

    #[test]
    fn sealed_wrong_recipient() {
        let bob = id(10);
        let eve = id(11);
        let ct = seal_to(&bob.public(), b"secret").unwrap();
        assert!(open_sealed(&eve, &ct).is_err());
    }

    #[test]
    fn signed_roundtrip_with_and_without_from() {
        let bob = id(20);
        let alice = id(21);
        let ct = seal_signed(&bob.public(), &alice, b"msg").unwrap();
        assert!(ct.starts_with("VEX1A-"));
        let (pt, who) = open_signed(&bob, &ct, Some(&alice.public())).unwrap();
        assert_eq!(pt, b"msg");
        assert_eq!(who, alice.ed_public());
        // without --from
        let (pt2, _) = open_signed(&bob, &ct, None).unwrap();
        assert_eq!(pt2, b"msg");
    }

    #[test]
    fn signed_wrong_expected_sender() {
        let bob = id(20);
        let alice = id(21);
        let mallory = id(22);
        let ct = seal_signed(&bob.public(), &alice, b"msg").unwrap();
        assert!(open_signed(&bob, &ct, Some(&mallory.public())).is_err());
    }

    #[test]
    fn multi_recipient_three() {
        let r: Vec<Identity> = (0..3).map(|i| id(30 + i)).collect();
        let pubs: Vec<PublicIdentity> = r.iter().map(|i| i.public()).collect();
        let ct = seal_multi(&pubs, b"group secret").unwrap();
        assert!(ct.starts_with("VEX1M-"));
        for ident in &r {
            assert_eq!(open_multi(ident, &ct).unwrap(), b"group secret");
        }
        // non-recipient fails
        let outsider = id(99);
        assert!(open_multi(&outsider, &ct).is_err());
    }

    #[test]
    fn mode_confusion_rejected() {
        let bob = id(40);
        let sym = encrypt_with_password(b"k", b"x").unwrap();
        assert!(open_sealed(&bob, &sym).is_err());
        let sealed = seal_to(&bob.public(), b"x").unwrap();
        assert!(decrypt_with_password(b"k", &sealed).is_err());
        assert!(open_multi(&bob, &sealed).is_err());
    }

    #[test]
    fn detached_signature_roundtrip() {
        let alice = id(70);
        let sig = sign_detached(&alice, b"release v1.0");
        assert!(sig.starts_with("VEXSIG-"));
        assert!(verify_detached(&alice.public(), b"release v1.0", &sig).is_ok());
        assert!(verify_detached(&alice.public(), b"tampered", &sig).is_err());
        let mallory = id(71);
        assert!(verify_detached(&mallory.public(), b"release v1.0", &sig).is_err());
    }

    #[test]
    fn tampering_detected() {
        let ct = encrypt_with_password(b"k", b"data").unwrap();
        let mut chars: Vec<char> = ct.chars().collect();
        let i = chars.len() - 1;
        chars[i] = if chars[i] == 'A' { 'B' } else { 'A' };
        let bad: String = chars.into_iter().collect();
        assert!(decrypt_with_password(b"k", &bad).is_err());
    }
}
