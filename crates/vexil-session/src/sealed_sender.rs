//! Sealed-sender session messages.
//!
//! A normal session message reveals the sender's ratchet key (`dh` in the
//! [`Header`]) in the clear, and the initial handshake sends the initiator's
//! identity key (`ik`) in the clear. Any network observer can link messages to
//! their sender.
//!
//! Sealed sender wraps the session header + ciphertext in a second hybrid
//! PQ encryption layer addressed to the recipient's long-term identity key.
//! The sender's real public identity is embedded inside that layer as a
//! self-signed [`SenderCertificate`], so the recipient can still authenticate
//! the sender, but a network observer sees only an ephemeral public key and an
//! opaque blob — not the sender's identity.
//!
//! The outer layer is post-quantum: X25519 ECDH is combined with ML-KEM-768
//! encapsulation to the recipient's identity key, mixed through HKDF.
//!
//! # Wire format (outer)
//! ```text
//! ver(1)=0x01 | eph_x_pk(32) | u16(kem_ct_len) | kem_ct | u16(outer_ct_len) | outer_ct
//! ```
//!
//! `outer_ct` decrypts to the inner plaintext:
//! ```text
//! u16(cert_len) | cert | u16(hdr_len) | hdr | msg_ct
//! ```
//!
//! # Example
//! ```
//! use vexil_session::{Session, new_prekey_bundle, sealed_sender::{seal_session_message, open_session_message}};
//! use vexil_core::pq_identity::PqIdentity;
//! use vexil_core::rand_core::OsRng;
//!
//! let alice = PqIdentity::generate();
//! let bob   = PqIdentity::generate();
//! let (bundle, secrets) = new_prekey_bundle(&bob, &mut OsRng);
//!
//! let (mut a, hs) = Session::initiate(&alice, &bundle, &mut OsRng).unwrap();
//! let (enc_hdr, ct) = a.encrypt(b"hello sealed", &mut OsRng).unwrap();
//!
//! // Wrap in sealed-sender outer envelope.
//! let envelope = seal_session_message(&alice, &bob.public(), &enc_hdr, &ct, &mut OsRng).unwrap();
//!
//! // Bob accepts, then opens the sealed-sender envelope.
//! let mut b = Session::accept(&bob, &secrets, &hs).unwrap();
//! let (pt, cert) = open_session_message(&mut b, &bob, &envelope, &mut OsRng).unwrap();
//! assert_eq!(pt, b"hello sealed");
//! cert.verify().unwrap();
//! ```

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use vexil_core::aead;
use vexil_core::pq::{mlkem768_decapsulate_raw, mlkem768_encapsulate_raw};
use vexil_core::pq_identity::{PqIdentity, PqPublicIdentity};
use vexil_core::sign_pq::{hybrid_sign, hybrid_verify};
use vexil_core::suite::Aead;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{Result, Session, SessionError};

const VERSION: u8 = 0x01;
const OUTER_INFO: &[u8] = b"vexil-sealed-sender-v1";
const OUTER_NONCE_INFO: &[u8] = b"vexil-sealed-sender-nonce-v1";
const CERT_LABEL: &[u8] = b"vexil-sender-cert-v1";

// ---------------------------------------------------------------------------
// SenderCertificate
// ---------------------------------------------------------------------------

/// A sender certificate: the sender's full public identity, a timestamp, and a
/// self-signature (Ed25519 + ML-DSA-65). Embedded inside the outer sealed
/// envelope so the recipient can authenticate the sender without the transport
/// layer learning who sent the message.
#[derive(Clone)]
pub struct SenderCertificate {
    /// Sender's full public identity.
    pub identity: PqPublicIdentity,
    /// Unix timestamp (seconds) at certificate issue time.
    pub issued_at: i64,
    /// Ed25519 signature over `CERT_LABEL || identity_bytes || issued_at`.
    pub sig_ed: [u8; 64],
    /// ML-DSA-65 signature over the same input.
    pub sig_pq: Vec<u8>,
}

impl SenderCertificate {
    /// Issue a certificate signed with `sender`'s own identity key.
    pub fn issue<R: RngCore + CryptoRng>(sender: &PqIdentity, _rng: &mut R) -> Self {
        let id_bytes = sender.public().to_bytes();
        let now = now_unix_secs();
        let msg = cert_signing_input(&id_bytes, now);
        let sig = hybrid_sign(&sender.ed_secret, &sender.ml_dsa_seed, &msg);
        SenderCertificate {
            identity: sender.public(),
            issued_at: now,
            sig_ed: sig.ed,
            sig_pq: sig.ml_dsa,
        }
    }

    /// Verify the self-signature. Both Ed25519 and ML-DSA must check out.
    pub fn verify(&self) -> Result<()> {
        let id_bytes = self.identity.to_bytes();
        let msg = cert_signing_input(&id_bytes, self.issued_at);
        hybrid_verify(
            &self.identity.ed_public,
            &self.identity.ml_dsa_public,
            &msg,
            &self.sig_ed,
            &self.sig_pq,
        )
        .map_err(|_| SessionError::DecryptFailed)
    }

    /// Serialize:
    /// `ver(1) || u16(id_len) || id || timestamp(8) || sig_ed(64) || u16(pq_len) || sig_pq`
    pub fn to_bytes(&self) -> Vec<u8> {
        let id = self.identity.to_bytes();
        let mut v = Vec::with_capacity(1 + 2 + id.len() + 8 + 64 + 2 + self.sig_pq.len());
        v.push(VERSION);
        v.extend_from_slice(&(id.len() as u16).to_be_bytes());
        v.extend_from_slice(&id);
        v.extend_from_slice(&self.issued_at.to_be_bytes());
        v.extend_from_slice(&self.sig_ed);
        v.extend_from_slice(&(self.sig_pq.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.sig_pq);
        v
    }

    /// Parse from [`SenderCertificate::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut p = 0;
        if take_bytes(b, &mut p, 1)?[0] != VERSION {
            return Err(SessionError::Malformed);
        }
        let id_len = u16_at(b, &mut p)? as usize;
        let id_bytes = take_bytes(b, &mut p, id_len)?;
        let identity =
            PqPublicIdentity::from_bytes(id_bytes).map_err(|_| SessionError::Malformed)?;
        let ts: [u8; 8] = take_bytes(b, &mut p, 8)?.try_into().unwrap();
        let issued_at = i64::from_be_bytes(ts);
        let sig_ed: [u8; 64] = take_bytes(b, &mut p, 64)?.try_into().unwrap();
        let pq_len = u16_at(b, &mut p)? as usize;
        let sig_pq = take_bytes(b, &mut p, pq_len)?.to_vec();
        Ok(SenderCertificate {
            identity,
            issued_at,
            sig_ed,
            sig_pq,
        })
    }
}

fn cert_signing_input(id_bytes: &[u8], issued_at: i64) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CERT_LABEL.len() + id_bytes.len() + 8);
    msg.extend_from_slice(CERT_LABEL);
    msg.extend_from_slice(id_bytes);
    msg.extend_from_slice(&issued_at.to_be_bytes());
    msg
}

// ---------------------------------------------------------------------------
// Outer envelope helpers
// ---------------------------------------------------------------------------

/// Derive the outer AEAD key and nonce from X25519 + ML-KEM shared secrets.
fn outer_keys(
    x_ss: &[u8; 32],
    ml_ss: &[u8; 32],
    eph_x_pk: &[u8; 32],
    recipient_x_pk: &[u8; 32],
) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(x_ss);
    ikm[32..].copy_from_slice(ml_ss);
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_x_pk);
    salt[32..].copy_from_slice(recipient_x_pk);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &*ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(OUTER_INFO, key.as_mut()).expect("32 valid");
    let mut nonce = [0u8; 12];
    hk.expand(OUTER_NONCE_INFO, &mut nonce).expect("12 valid");
    (key, nonce)
}

fn outer_aad(eph_x_pk: &[u8; 32], recipient_x_pk: &[u8; 32]) -> Vec<u8> {
    let mut a = Vec::with_capacity(OUTER_INFO.len() + 64);
    a.extend_from_slice(OUTER_INFO);
    a.extend_from_slice(eph_x_pk);
    a.extend_from_slice(recipient_x_pk);
    a
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Wrap a session message in a sealed-sender outer envelope.
///
/// The `header` and `ct` must come from [`Session::encrypt`] or
/// [`Session::encrypt_with_ad`]. This function does not call encrypt itself —
/// the caller controls message content and associated data.
///
/// Returns an opaque byte string. Only the holder of `recipient`'s secret
/// identity key can open it. The network transport sees neither the sender's
/// identity nor the ratchet state.
pub fn seal_session_message<R: RngCore + CryptoRng>(
    sender: &PqIdentity,
    recipient: &PqPublicIdentity,
    enc_header: &[u8],
    ct: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    let cert = SenderCertificate::issue(sender, rng);
    let cert_bytes = cert.to_bytes();

    // Inner plaintext: cert || enc_header || ciphertext.
    let mut inner = Vec::with_capacity(2 + cert_bytes.len() + 2 + enc_header.len() + ct.len());
    inner.extend_from_slice(&(cert_bytes.len() as u16).to_be_bytes());
    inner.extend_from_slice(&cert_bytes);
    inner.extend_from_slice(&(enc_header.len() as u16).to_be_bytes());
    inner.extend_from_slice(&enc_header);
    inner.extend_from_slice(ct);

    // Outer hybrid key agreement.
    let eph_sk = StaticSecret::random_from_rng(&mut *rng);
    let eph_pk = PublicKey::from(&eph_sk);
    let x_ss = eph_sk.diffie_hellman(&recipient.kem.x_public);
    let kem_ek = recipient.kem.ml_ek_bytes();
    let (kem_ct, ml_ss) = mlkem768_encapsulate_raw(&kem_ek, rng)?;

    let (key, nonce) = outer_keys(
        x_ss.as_bytes(),
        &ml_ss,
        eph_pk.as_bytes(),
        recipient.kem.x_public.as_bytes(),
    );
    let aad = outer_aad(eph_pk.as_bytes(), recipient.kem.x_public.as_bytes());
    let outer_ct = aead::seal(Aead::ChaCha20Poly1305, &key, &nonce, &inner, &aad)?;

    // Outer wire: ver || eph_x_pk || u16(kem_ct_len) || kem_ct || u16(outer_ct_len) || outer_ct
    let mut out = Vec::with_capacity(1 + 32 + 2 + kem_ct.len() + 2 + outer_ct.len());
    out.push(VERSION);
    out.extend_from_slice(eph_pk.as_bytes());
    out.extend_from_slice(&(kem_ct.len() as u16).to_be_bytes());
    out.extend_from_slice(&kem_ct);
    out.extend_from_slice(&(outer_ct.len() as u16).to_be_bytes());
    out.extend_from_slice(&outer_ct);
    Ok(out)
}

/// Open a sealed-sender session message.
///
/// Decrypts the outer PQ hybrid layer with the recipient's long-term identity
/// key, verifies the embedded [`SenderCertificate`], then decrypts the inner
/// session message using `session`.
///
/// Returns `(plaintext, SenderCertificate)`. Verify the certificate's identity
/// against a trusted contact list out of band if needed.
pub fn open_session_message<R: RngCore + CryptoRng>(
    session: &mut Session,
    recipient: &PqIdentity,
    envelope: &[u8],
    rng: &mut R,
) -> Result<(Vec<u8>, SenderCertificate)> {
    let mut p = 0;

    if take_bytes(envelope, &mut p, 1)?[0] != VERSION {
        return Err(SessionError::Malformed);
    }
    let eph_x_pk: [u8; 32] = take_bytes(envelope, &mut p, 32)?.try_into().unwrap();
    let kem_ct_len = u16_at(envelope, &mut p)? as usize;
    let kem_ct = take_bytes(envelope, &mut p, kem_ct_len)?.to_vec();
    let outer_ct_len = u16_at(envelope, &mut p)? as usize;
    let outer_ct = take_bytes(envelope, &mut p, outer_ct_len)?.to_vec();

    // Outer decryption.
    let eph_pub = PublicKey::from(eph_x_pk);
    let x_ss = recipient.kem.x_secret.diffie_hellman(&eph_pub);
    let recipient_x_pub = PublicKey::from(&recipient.kem.x_secret);
    let ml_ss = mlkem768_decapsulate_raw(&recipient.kem.ml_dk_bytes(), &kem_ct)
        .map_err(|_| SessionError::DecryptFailed)?;
    let (key, nonce) = outer_keys(
        x_ss.as_bytes(),
        &ml_ss,
        &eph_x_pk,
        recipient_x_pub.as_bytes(),
    );
    let aad = outer_aad(&eph_x_pk, recipient_x_pub.as_bytes());
    let inner = aead::open(Aead::ChaCha20Poly1305, &key, &nonce, &outer_ct, &aad)
        .map_err(|_| SessionError::DecryptFailed)?;

    // Parse inner.
    let mut ip = 0;
    let cert_len = u16_at(&inner, &mut ip)? as usize;
    let cert = SenderCertificate::from_bytes(take_bytes(&inner, &mut ip, cert_len)?)?;
    cert.verify()?;
    let hdr_len = u16_at(&inner, &mut ip)? as usize;
    let hdr_bytes = take_bytes(&inner, &mut ip, hdr_len)?;
    let msg_ct = &inner[ip..];
    let pt = session.decrypt(hdr_bytes, msg_ct, rng)?;
    Ok((pt, cert))
}

// ---------------------------------------------------------------------------
// Parse helpers
// ---------------------------------------------------------------------------

fn take_bytes<'a>(b: &'a [u8], p: &mut usize, n: usize) -> Result<&'a [u8]> {
    if *p + n > b.len() {
        return Err(SessionError::Malformed);
    }
    let s = &b[*p..*p + n];
    *p += n;
    Ok(s)
}

fn u16_at(b: &[u8], p: &mut usize) -> Result<u16> {
    let bytes: [u8; 2] = take_bytes(b, p, 2)?.try_into().unwrap();
    Ok(u16::from_be_bytes(bytes))
}

fn now_unix_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use vexil_core::pq_identity::PqIdentity;

    use crate::{new_prekey_bundle, Session};

    fn session_pair() -> (PqIdentity, PqIdentity, Session, Session) {
        let alice = PqIdentity::generate();
        let bob = PqIdentity::generate();
        let (bundle, secrets) = new_prekey_bundle(&bob, &mut OsRng);
        let (mut a, hs) = Session::initiate(&alice, &bundle, &mut OsRng).unwrap();
        let (h, c) = a.encrypt(b"init", &mut OsRng).unwrap();
        let mut b = Session::accept(&bob, &secrets, &hs).unwrap();
        b.decrypt(&h, &c, &mut OsRng).unwrap();
        (alice, bob, a, b)
    }

    #[test]
    fn sealed_sender_roundtrip() {
        let (alice, bob, mut a, mut b) = session_pair();
        let (hdr, ct) = a.encrypt(b"sealed hello", &mut OsRng).unwrap();
        let env = seal_session_message(&alice, &bob.public(), &hdr, &ct, &mut OsRng).unwrap();
        let (pt, cert) = open_session_message(&mut b, &bob, &env, &mut OsRng).unwrap();
        assert_eq!(pt, b"sealed hello");
        cert.verify().unwrap();
        assert_eq!(cert.identity.ed_public, alice.public().ed_public);
    }

    #[test]
    fn tampered_outer_rejected() {
        let (alice, bob, mut a, mut b) = session_pair();
        let (hdr, ct) = a.encrypt(b"data", &mut OsRng).unwrap();
        let mut env = seal_session_message(&alice, &bob.public(), &hdr, &ct, &mut OsRng).unwrap();
        env[10] ^= 0xFF;
        assert!(open_session_message(&mut b, &bob, &env, &mut OsRng).is_err());
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let (alice, bob, mut a, _) = session_pair();
        let eve = PqIdentity::generate();
        let (bundle_e, secrets_e) = new_prekey_bundle(&eve, &mut OsRng);
        let (_, hs_e) = Session::initiate(&alice, &bundle_e, &mut OsRng).unwrap();
        let mut eve_session = Session::accept(&eve, &secrets_e, &hs_e).unwrap();

        let (hdr, ct) = a.encrypt(b"not for eve", &mut OsRng).unwrap();
        let env = seal_session_message(&alice, &bob.public(), &hdr, &ct, &mut OsRng).unwrap();
        // Eve tries to open a message sealed to Bob — must fail.
        assert!(open_session_message(&mut eve_session, &eve, &env, &mut OsRng).is_err());
    }

    #[test]
    fn cert_roundtrip() {
        let alice = PqIdentity::generate();
        let cert = SenderCertificate::issue(&alice, &mut OsRng);
        cert.verify().unwrap();
        let back = SenderCertificate::from_bytes(&cert.to_bytes()).unwrap();
        back.verify().unwrap();
        assert_eq!(back.identity.ed_public, alice.public().ed_public);
    }

    #[test]
    fn cert_wrong_key_rejected() {
        let alice = PqIdentity::generate();
        let eve = PqIdentity::generate();
        let mut cert = SenderCertificate::issue(&alice, &mut OsRng);
        // Swap the identity to Eve's while keeping Alice's signature.
        cert.identity = eve.public();
        assert!(cert.verify().is_err());
    }
}
