//! # VEXIL session protocol
//!
//! A post-quantum **PQXDH** handshake plus a **Double Ratchet**, giving a live
//! end-to-end channel with:
//! - per-message **forward secrecy** (used keys are deleted; a later compromise
//!   does not expose past messages), and
//! - **post-compromise security** (the channel heals after a state leak once a
//!   fresh DH ratchet step runs).
//!
//! Both the handshake and the continuous ratchet are post-quantum. The handshake
//! shared secret mixes X25519 Diffie-Hellmans with an ML-KEM-768 encapsulation.
//!
//! The ratchet is **sparse**: a fresh ML-KEM-768 encapsulation is folded into the
//! root only every [`PQ_CHAIN_INTERVAL`]-th sending chain, so most message
//! headers stay small (~50 bytes) and only the periodic PQ chains carry the
//! ML-KEM key + ciphertext (~2.3 KB). ML-KEM keys are versioned and a short
//! history is kept, so a key-rotation race still decapsulates. This keeps
//! post-compromise security quantum-resistant while amortizing the bandwidth.
//!
//! This is sparse-by-chain, not intra-message chunking: full chunked-erasure
//! SPQR needs an acknowledged side-ratchet to avoid root desync under loss,
//! which is a larger protocol. The design here stays in sync and loss-robust
//! because every PQ step is tied to the (repeated-in-chain) DH ratchet.
//!
//! ```
//! use vexil_session::{Session, new_prekey_bundle};
//! use vexil_core::pq_identity::PqIdentity;
//! use vexil_core::rand_core::OsRng;
//!
//! let alice = PqIdentity::generate();
//! let bob = PqIdentity::generate();
//! let (bundle, secrets) = new_prekey_bundle(&bob, &mut OsRng);
//!
//! // Alice starts a session from Bob's published bundle and sends a message.
//! let (mut a, hs) = Session::initiate(&alice, &bundle, &mut OsRng).unwrap();
//! let (hdr, ct) = a.encrypt(b"hi bob", &mut OsRng).unwrap();
//!
//! // Bob accepts the handshake and decrypts.
//! let mut b = Session::accept(&bob, &secrets, &hs).unwrap();
//! assert_eq!(b.decrypt(&hdr, &ct, &mut OsRng).unwrap(), b"hi bob");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use vexil_core::aead;
use vexil_core::pq::{
    mlkem768_decapsulate_raw, mlkem768_encapsulate_raw, mlkem768_generate, mlkem_decapsulate,
    mlkem_encapsulate,
};
use vexil_core::pq_identity::{PqIdentity, PqPublicIdentity};
use vexil_core::sign_pq::{hybrid_sign, hybrid_verify};
use vexil_core::suite::Aead;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

type HmacSha256 = Hmac<Sha256>;
type Key = [u8; 32];
/// Cached skipped message keys, indexed by `(header_key_bytes, msg_number, message_key)`.
/// A `VecDeque` so trimming the oldest entry at the cap is O(1).
type SkippedKeys = std::collections::VecDeque<([u8; 32], u32, Zeroizing<Key>)>;

/// Maximum number of skipped message keys cached per chain (anti-DoS bound).
pub const MAX_SKIP: u32 = 1000;

pub mod group;
pub mod sealed_sender;

/// Errors from the session layer.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The signed prekey signature did not verify.
    #[error("prekey bundle signature invalid")]
    BadPrekeySignature,
    /// A handshake or message field was malformed.
    #[error("malformed session message")]
    Malformed,
    /// AEAD authentication failed (wrong key, tampering, or out of sync).
    #[error("message authentication failed")]
    DecryptFailed,
    /// Too many messages were skipped (possible denial of service).
    #[error("too many skipped messages")]
    TooManySkipped,
    /// Underlying core error.
    #[error(transparent)]
    Core(#[from] vexil_core::Error),
}

/// Result alias.
pub type Result<T> = std::result::Result<T, SessionError>;

// ---------------------------------------------------------------------------
// Prekey bundle (PQXDH)
// ---------------------------------------------------------------------------

/// Bob's published prekey bundle. Anyone can start a session toward Bob with it.
#[derive(Clone)]
pub struct PreKeyBundle {
    /// Bob's long-term public identity (X25519 + ML-KEM-768 + Ed25519 + ML-DSA).
    pub identity: PqPublicIdentity,
    /// Signed prekey (X25519 public).
    pub signed_prekey: [u8; 32],
    /// Ed25519 signature over the signed prekey.
    pub spk_sig_ed: [u8; 64],
    /// ML-DSA-65 signature over the signed prekey.
    pub spk_sig_pq: Vec<u8>,
    /// Optional one-time prekey (X25519 public).
    pub one_time_prekey: Option<[u8; 32]>,
}

/// The secrets Bob keeps for a published [`PreKeyBundle`].
pub struct PreKeySecrets {
    /// Signed-prekey secret.
    pub spk_secret: StaticSecret,
    /// One-time prekey secret, if one was published.
    pub opk_secret: Option<StaticSecret>,
}

/// Generate a prekey bundle (with one one-time prekey) for `identity`.
pub fn new_prekey_bundle<R: RngCore + CryptoRng>(
    identity: &PqIdentity,
    rng: &mut R,
) -> (PreKeyBundle, PreKeySecrets) {
    let spk_secret = StaticSecret::random_from_rng(&mut *rng);
    let spk_pub = PublicKey::from(&spk_secret);
    let opk_secret = StaticSecret::random_from_rng(&mut *rng);
    let opk_pub = PublicKey::from(&opk_secret);

    let sig = hybrid_sign(
        &identity.ed_secret,
        &identity.ml_dsa_seed,
        spk_pub.as_bytes(),
    );
    (
        PreKeyBundle {
            identity: identity.public(),
            signed_prekey: spk_pub.to_bytes(),
            spk_sig_ed: sig.ed,
            spk_sig_pq: sig.ml_dsa,
            one_time_prekey: Some(opk_pub.to_bytes()),
        },
        PreKeySecrets {
            spk_secret,
            opk_secret: Some(opk_secret),
        },
    )
}

impl PreKeyBundle {
    /// Serialize for publishing:
    /// `u16(id_len)||id || spk(32) || sig_ed(64) || u16(pqsig_len)||pqsig || opk_flag(1)||[opk(32)]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let id = self.identity.to_bytes();
        let mut v = Vec::with_capacity(id.len() + 100 + self.spk_sig_pq.len());
        v.extend_from_slice(&(id.len() as u16).to_be_bytes());
        v.extend_from_slice(&id);
        v.extend_from_slice(&self.signed_prekey);
        v.extend_from_slice(&self.spk_sig_ed);
        v.extend_from_slice(&(self.spk_sig_pq.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.spk_sig_pq);
        match self.one_time_prekey {
            Some(opk) => {
                v.push(1);
                v.extend_from_slice(&opk);
            }
            None => v.push(0),
        }
        v
    }

    /// Parse from [`PreKeyBundle::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut p = 0usize;
        let take = |b: &[u8], p: &mut usize, n: usize| -> Result<Vec<u8>> {
            if *p + n > b.len() {
                return Err(SessionError::Malformed);
            }
            let s = b[*p..*p + n].to_vec();
            *p += n;
            Ok(s)
        };
        let id_len = u16::from_be_bytes(take(b, &mut p, 2)?.try_into().unwrap()) as usize;
        let identity = PqPublicIdentity::from_bytes(&take(b, &mut p, id_len)?)
            .map_err(|_| SessionError::Malformed)?;
        let signed_prekey: [u8; 32] = take(b, &mut p, 32)?.try_into().unwrap();
        let spk_sig_ed: [u8; 64] = take(b, &mut p, 64)?.try_into().unwrap();
        let pqsig_len = u16::from_be_bytes(take(b, &mut p, 2)?.try_into().unwrap()) as usize;
        let spk_sig_pq = take(b, &mut p, pqsig_len)?;
        let flag = take(b, &mut p, 1)?[0];
        let one_time_prekey = if flag == 1 {
            Some(take(b, &mut p, 32)?.try_into().unwrap())
        } else {
            None
        };
        Ok(PreKeyBundle {
            identity,
            signed_prekey,
            spk_sig_ed,
            spk_sig_pq,
            one_time_prekey,
        })
    }
}

impl PreKeySecrets {
    /// Serialize: `spk(32) || opk_flag(1) || [opk(32)]`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(65);
        v.extend_from_slice(&self.spk_secret.to_bytes());
        match &self.opk_secret {
            Some(o) => {
                v.push(1);
                v.extend_from_slice(&o.to_bytes());
            }
            None => v.push(0),
        }
        v
    }

    /// Parse from [`PreKeySecrets::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 33 {
            return Err(SessionError::Malformed);
        }
        let spk: [u8; 32] = b[..32].try_into().unwrap();
        let opk_secret = if b[32] == 1 {
            if b.len() < 65 {
                return Err(SessionError::Malformed);
            }
            let o: [u8; 32] = b[33..65].try_into().unwrap();
            Some(StaticSecret::from(o))
        } else {
            None
        };
        Ok(PreKeySecrets {
            spk_secret: StaticSecret::from(spk),
            opk_secret,
        })
    }
}

/// The handshake fields the initiator sends alongside the first message.
#[derive(Clone)]
pub struct Handshake {
    /// Initiator long-term identity public key (X25519).
    pub ik: [u8; 32],
    /// Initiator ephemeral public key (X25519).
    pub ek: [u8; 32],
    /// ML-KEM-768 ciphertext encapsulated to the responder.
    pub kem_ct: Vec<u8>,
    /// Whether the responder's one-time prekey was used.
    pub used_opk: bool,
}

impl Handshake {
    /// Serialize: `ik(32) || ek(32) || used_opk(1) || u16(len) || kem_ct`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(67 + self.kem_ct.len());
        v.extend_from_slice(&self.ik);
        v.extend_from_slice(&self.ek);
        v.push(self.used_opk as u8);
        v.extend_from_slice(&(self.kem_ct.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.kem_ct);
        v
    }

    /// Parse from [`Handshake::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 67 {
            return Err(SessionError::Malformed);
        }
        let mut ik = [0u8; 32];
        let mut ek = [0u8; 32];
        ik.copy_from_slice(&b[..32]);
        ek.copy_from_slice(&b[32..64]);
        let used_opk = b[64] != 0;
        let len = u16::from_be_bytes([b[65], b[66]]) as usize;
        if b.len() != 67 + len {
            return Err(SessionError::Malformed);
        }
        Ok(Handshake {
            ik,
            ek,
            kem_ct: b[67..].to_vec(),
            used_opk,
        })
    }
}

// ---------------------------------------------------------------------------
// Ratchet message header
// ---------------------------------------------------------------------------

/// Per-message ratchet header. Carries the X25519 ratchet key and counters.
/// PQ material (ML-KEM key + ciphertext) is present only on the sparse "PQ
/// chains" (every [`PQ_CHAIN_INTERVAL`]-th sending chain), keeping most headers
/// small. `ek_id` versions the sender's ML-KEM key; `target_id` says which of
/// the recipient's keys the ciphertext was encapsulated to (so a key rotation
/// race still decapsulates).
#[derive(Clone)]
pub struct Header {
    /// Sender's current X25519 ratchet public key.
    pub dh: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub pn: u32,
    /// Message number in the current sending chain.
    pub n: u32,
    /// Sender's ML-KEM encapsulation key (empty on non-PQ chains).
    pub mlkem_ek: Vec<u8>,
    /// Version id of `mlkem_ek`.
    pub ek_id: u32,
    /// Recipient key id the `mlkem_ct` was encapsulated to.
    pub target_id: u32,
    /// ML-KEM ciphertext (empty on non-PQ chains).
    pub mlkem_ct: Vec<u8>,
}

impl Header {
    /// Whether this header carries a PQ ratchet step.
    pub fn is_pq(&self) -> bool {
        !self.mlkem_ct.is_empty()
    }

    /// Serialize: `dh(32)||pn(4)||n(4)||ek_id(4)||target_id(4)||u16(ek)||ek||u16(ct)||ct`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(52 + self.mlkem_ek.len() + self.mlkem_ct.len());
        out.extend_from_slice(&self.dh);
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        out.extend_from_slice(&self.ek_id.to_be_bytes());
        out.extend_from_slice(&self.target_id.to_be_bytes());
        out.extend_from_slice(&(self.mlkem_ek.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mlkem_ek);
        out.extend_from_slice(&(self.mlkem_ct.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.mlkem_ct);
        out
    }

    /// Parse from [`Header::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 52 {
            return Err(SessionError::Malformed);
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&b[..32]);
        let pn = u32::from_be_bytes(b[32..36].try_into().unwrap());
        let n = u32::from_be_bytes(b[36..40].try_into().unwrap());
        let ek_id = u32::from_be_bytes(b[40..44].try_into().unwrap());
        let target_id = u32::from_be_bytes(b[44..48].try_into().unwrap());
        let ek_len = u16::from_be_bytes([b[48], b[49]]) as usize;
        let mut p = 50;
        if b.len() < p + ek_len + 2 {
            return Err(SessionError::Malformed);
        }
        let mlkem_ek = b[p..p + ek_len].to_vec();
        p += ek_len;
        let ct_len = u16::from_be_bytes([b[p], b[p + 1]]) as usize;
        p += 2;
        if b.len() != p + ct_len {
            return Err(SessionError::Malformed);
        }
        let mlkem_ct = b[p..p + ct_len].to_vec();
        Ok(Header {
            dh,
            pn,
            n,
            mlkem_ek,
            ek_id,
            target_id,
            mlkem_ct,
        })
    }
}

// ---------------------------------------------------------------------------
// KDFs
// ---------------------------------------------------------------------------

fn kdf_rk(rk: &Key, dh: &[u8; 32]) -> (Key, Key, Key) {
    // returns (new_rk, ck, hk)
    let hk = Hkdf::<Sha256>::new(Some(rk), dh);
    let mut okm = Zeroizing::new([0u8; 96]);
    hk.expand(b"vexil-ratchet-rk-v1", okm.as_mut())
        .expect("96 is a valid hkdf length");
    let mut rk2 = [0u8; 32];
    rk2.copy_from_slice(&okm[..32]);
    let mut ck = [0u8; 32];
    ck.copy_from_slice(&okm[32..64]);
    let mut hk2 = [0u8; 32];
    hk2.copy_from_slice(&okm[64..96]);
    (rk2, ck, hk2)
}

fn kdf_ck(ck: &Key) -> (Key, Zeroizing<Key>) {
    let mac_ck = HmacSha256::new_from_slice(ck).expect("hmac key");
    let mut next = [0u8; 32];
    next.copy_from_slice(&mac_ck.clone().chain_update([0x02]).finalize().into_bytes());
    let mut mk = Zeroizing::new([0u8; 32]);
    mk.copy_from_slice(&mac_ck.chain_update([0x01]).finalize().into_bytes());
    (next, mk)
}

fn msg_aad(enc_header: &[u8], ad: &[u8]) -> Vec<u8> {
    let mut a = enc_header.to_vec();
    a.extend_from_slice(ad);
    a
}

fn encrypt_header<R: RngCore + CryptoRng>(hk: &Key, header: &Header, rng: &mut R) -> Vec<u8> {
    let mut nonce = [0u8; 12usize];
    rng.fill_bytes(&mut nonce);
    let hb = header.to_bytes();
    let ct =
        aead::seal(Aead::ChaCha20Poly1305, hk, &nonce, &hb, &[]).expect("header AEAD infallible");
    let mut out = Vec::with_capacity(12usize + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn try_decrypt_header(hk: &Key, enc: &[u8]) -> Option<Header> {
    if enc.len() < 12usize + 16 {
        return None;
    }
    let nonce: [u8; 12] = enc[..12usize].try_into().ok()?;
    let pt = aead::open(Aead::ChaCha20Poly1305, hk, &nonce, &enc[12usize..], &[]).ok()?;
    Header::from_bytes(&pt).ok()
}

// Fold an ML-KEM shared secret into the root key (the PQ ratchet mix).
fn mix_pq(rk: &Key, ss: &[u8]) -> Key {
    let hk = Hkdf::<Sha256>::new(Some(rk), ss);
    let mut out = [0u8; 32];
    hk.expand(b"vexil-ratchet-pq-v1", &mut out)
        .expect("32 valid");
    out
}

fn msg_keys(mk: &Key) -> (Zeroizing<Key>, [u8; 12]) {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32]), mk);
    let mut okm = Zeroizing::new([0u8; 44]);
    hk.expand(b"vexil-ratchet-msg-v1", okm.as_mut())
        .expect("44 valid");
    let mut key = Zeroizing::new([0u8; 32]);
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[..32]);
    nonce.copy_from_slice(&okm[32..44]);
    (key, nonce)
}

// ---------------------------------------------------------------------------
// Session (Double Ratchet)
// ---------------------------------------------------------------------------

/// Run a PQ (ML-KEM) ratchet step on every Nth sending chain. Smaller = faster
/// post-compromise PQ healing + more overhead; larger = sparser + cheaper.
/// Must keep each side healing within a few of its own turns.
pub const PQ_CHAIN_INTERVAL: u32 = 4;
/// How many recent ML-KEM keys to retain so a rotation race still decapsulates.
/// 8 entries gives 8 × PQ_CHAIN_INTERVAL messages of breathing room per side,
/// comfortably covering high-latency or out-of-order delivery scenarios.
const KEM_HISTORY: usize = 8;

// A versioned ML-KEM decapsulation key in our history (kept so a key-rotation
// race still decapsulates; the matching ek is published in the header at use).
struct KemEntry {
    id: u32,
    dk: Vec<u8>,
}

// PQ material to attach to our current sending chain (only on PQ chains).
struct Pending {
    ek: Vec<u8>,
    ek_id: u32,
    target_id: u32,
    ct: Vec<u8>,
}

/// A live Double Ratchet session. Hold one per conversation per side.
pub struct Session {
    rk: Key,
    dhs: StaticSecret,
    dhs_pub: PublicKey,
    dhr: Option<[u8; 32]>,
    cks: Option<Key>,
    ckr: Option<Key>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: SkippedKeys,
    // Sparse PQ ratchet state.
    send_chains: u32,
    kem_hist: Vec<KemEntry>,
    kem_next_id: u32,
    remote_ek: Vec<u8>,
    remote_ek_id: u32,
    pending: Option<Pending>,
    hks: Option<Key>, // header key for current outgoing chain
    nhks: Key,        // next header key for outgoing (staged)
    hkr: Option<Key>, // header key for current incoming chain
    nhkr: Key,        // next header key for incoming (try on new peer chain)
}

impl Drop for Session {
    fn drop(&mut self) {
        // Wipe symmetric ratchet secrets and ML-KEM decapsulation keys. (dhs
        // zeroizes itself; skipped message keys are Zeroizing.)
        self.rk.zeroize();
        if let Some(mut c) = self.cks.take() {
            c.zeroize();
        }
        if let Some(mut c) = self.ckr.take() {
            c.zeroize();
        }
        for e in &mut self.kem_hist {
            e.dk.zeroize();
        }
        if let Some(mut k) = self.hks.take() {
            k.zeroize()
        }
        self.nhks.zeroize();
        if let Some(mut k) = self.hkr.take() {
            k.zeroize()
        }
        self.nhkr.zeroize();
    }
}

impl Session {
    fn push_kem(&mut self, id: u32, dk: Vec<u8>) {
        self.kem_hist.push(KemEntry { id, dk });
        if self.kem_hist.len() > KEM_HISTORY {
            self.kem_hist.remove(0);
        }
    }

    fn find_dk(&self, id: u32) -> Option<&[u8]> {
        self.kem_hist
            .iter()
            .find(|e| e.id == id)
            .map(|e| e.dk.as_slice())
    }

    // Start a new sending chain. On every PQ_CHAIN_INTERVAL-th chain, rotate our
    // ML-KEM key, encapsulate to the peer's latest key, fold the secret into the
    // root, and stage the material for our outgoing headers. Otherwise no PQ.
    fn start_send_chain<R: RngCore + CryptoRng>(&mut self, rng: &mut R) -> Result<()> {
        let pq = self.send_chains % PQ_CHAIN_INTERVAL == 0;
        self.send_chains += 1;
        if pq && !self.remote_ek.is_empty() {
            let id = self.kem_next_id;
            self.kem_next_id += 1;
            let (dk, ek) = mlkem768_generate(rng);
            self.push_kem(id, dk);
            let (ct, ss) = mlkem768_encapsulate_raw(&self.remote_ek, rng)?;
            self.rk = mix_pq(&self.rk, ss.as_slice());
            self.pending = Some(Pending {
                ek,
                ek_id: id,
                target_id: self.remote_ek_id,
                ct,
            });
        } else {
            self.pending = None;
        }
        Ok(())
    }

    // Receiving side of a PQ chain: decapsulate with the key the peer targeted,
    // fold the secret into the root, and remember the peer's new ML-KEM key.
    fn pq_in(&mut self, header: &Header) -> Result<()> {
        if header.is_pq() {
            let dk = self
                .find_dk(header.target_id)
                .ok_or(SessionError::DecryptFailed)?
                .to_vec();
            let ss = mlkem768_decapsulate_raw(&dk, &header.mlkem_ct)?;
            self.rk = mix_pq(&self.rk, ss.as_slice());
            self.remote_ek = header.mlkem_ek.clone();
            self.remote_ek_id = header.ek_id;
        }
        Ok(())
    }

    /// Serialize the full ratchet state so a conversation survives a restart.
    ///
    /// The bytes contain live secret key material (root key, chain keys,
    /// skipped message keys, ML-KEM decapsulation keys). Treat them like a
    /// private key: store encrypted at rest and wipe after loading.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(256 + self.remote_ek.len());
        v.push(2); // format version
        v.extend_from_slice(&self.rk);
        v.extend_from_slice(&self.dhs.to_bytes());
        let opt32 = |v: &mut Vec<u8>, o: &Option<[u8; 32]>| match o {
            Some(b) => {
                v.push(1);
                v.extend_from_slice(b);
            }
            None => v.push(0),
        };
        opt32(&mut v, &self.dhr);
        opt32(&mut v, &self.cks);
        opt32(&mut v, &self.ckr);
        v.extend_from_slice(&self.ns.to_be_bytes());
        v.extend_from_slice(&self.nr.to_be_bytes());
        v.extend_from_slice(&self.pn.to_be_bytes());
        v.extend_from_slice(&self.send_chains.to_be_bytes());
        v.extend_from_slice(&self.kem_next_id.to_be_bytes());
        v.extend_from_slice(&self.remote_ek_id.to_be_bytes());
        v.extend_from_slice(&(self.remote_ek.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.remote_ek);
        v.extend_from_slice(&(self.skipped.len() as u32).to_be_bytes());
        for (hk, n, key) in &self.skipped {
            v.extend_from_slice(hk);
            v.extend_from_slice(&n.to_be_bytes());
            v.extend_from_slice(&**key);
        }
        v.extend_from_slice(&(self.kem_hist.len() as u32).to_be_bytes());
        for e in &self.kem_hist {
            v.extend_from_slice(&e.id.to_be_bytes());
            v.extend_from_slice(&(e.dk.len() as u16).to_be_bytes());
            v.extend_from_slice(&e.dk);
        }
        match &self.pending {
            Some(p) => {
                v.push(1);
                v.extend_from_slice(&p.ek_id.to_be_bytes());
                v.extend_from_slice(&p.target_id.to_be_bytes());
                v.extend_from_slice(&(p.ek.len() as u16).to_be_bytes());
                v.extend_from_slice(&p.ek);
                v.extend_from_slice(&(p.ct.len() as u16).to_be_bytes());
                v.extend_from_slice(&p.ct);
            }
            None => v.push(0),
        }
        match self.hks {
            Some(k) => {
                v.push(1);
                v.extend_from_slice(&k);
            }
            None => v.push(0),
        }
        v.extend_from_slice(&self.nhks);
        match self.hkr {
            Some(k) => {
                v.push(1);
                v.extend_from_slice(&k);
            }
            None => v.push(0),
        }
        v.extend_from_slice(&self.nhkr);
        v
    }

    /// Restore a session from [`Session::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut p = 0usize;
        let take = |b: &[u8], p: &mut usize, n: usize| -> Result<Vec<u8>> {
            if *p + n > b.len() {
                return Err(SessionError::Malformed);
            }
            let s = b[*p..*p + n].to_vec();
            *p += n;
            Ok(s)
        };
        let u16r = |b: &[u8], p: &mut usize| -> Result<usize> {
            Ok(u16::from_be_bytes(take(b, p, 2)?.try_into().unwrap()) as usize)
        };
        let u32r = |b: &[u8], p: &mut usize| -> Result<u32> {
            Ok(u32::from_be_bytes(take(b, p, 4)?.try_into().unwrap()))
        };
        let opt32 = |b: &[u8], p: &mut usize| -> Result<Option<[u8; 32]>> {
            Ok(if take(b, p, 1)?[0] == 1 {
                Some(take(b, p, 32)?.try_into().unwrap())
            } else {
                None
            })
        };
        if take(b, &mut p, 1)?[0] != 2 {
            return Err(SessionError::Malformed);
        }
        let rk: Key = take(b, &mut p, 32)?.try_into().unwrap();
        let dhs_bytes: [u8; 32] = take(b, &mut p, 32)?.try_into().unwrap();
        let dhs = StaticSecret::from(dhs_bytes);
        let dhs_pub = PublicKey::from(&dhs);
        let dhr = opt32(b, &mut p)?;
        let cks = opt32(b, &mut p)?;
        let ckr = opt32(b, &mut p)?;
        let ns = u32r(b, &mut p)?;
        let nr = u32r(b, &mut p)?;
        let pn = u32r(b, &mut p)?;
        let send_chains = u32r(b, &mut p)?;
        let kem_next_id = u32r(b, &mut p)?;
        let remote_ek_id = u32r(b, &mut p)?;
        let remote_ek_len = u16r(b, &mut p)?;
        let remote_ek = take(b, &mut p, remote_ek_len)?;
        let skip_count = u32r(b, &mut p)?;
        if skip_count > MAX_SKIP {
            return Err(SessionError::TooManySkipped);
        }
        let mut skipped: SkippedKeys =
            std::collections::VecDeque::with_capacity(skip_count as usize);
        for _ in 0..skip_count {
            let dh: [u8; 32] = take(b, &mut p, 32)?.try_into().unwrap();
            let n = u32r(b, &mut p)?;
            let key: Key = take(b, &mut p, 32)?.try_into().unwrap();
            skipped.push_back((dh, n, Zeroizing::new(key)));
        }
        let kem_count = u32r(b, &mut p)?;
        if kem_count as usize > KEM_HISTORY {
            return Err(SessionError::Malformed);
        }
        let mut kem_hist = Vec::with_capacity(kem_count as usize);
        for _ in 0..kem_count {
            let id = u32r(b, &mut p)?;
            let dk_len = u16r(b, &mut p)?;
            let dk = take(b, &mut p, dk_len)?;
            kem_hist.push(KemEntry { id, dk });
        }
        let pending = if take(b, &mut p, 1)?[0] == 1 {
            let ek_id = u32r(b, &mut p)?;
            let target_id = u32r(b, &mut p)?;
            let ek_len = u16r(b, &mut p)?;
            let ek = take(b, &mut p, ek_len)?;
            let ct_len = u16r(b, &mut p)?;
            let ct = take(b, &mut p, ct_len)?;
            Some(Pending {
                ek,
                ek_id,
                target_id,
                ct,
            })
        } else {
            None
        };
        let hks = opt32(b, &mut p)?;
        let nhks: Key = take(b, &mut p, 32)?.try_into().unwrap();
        let hkr = opt32(b, &mut p)?;
        let nhkr: Key = take(b, &mut p, 32)?.try_into().unwrap();
        Ok(Session {
            rk,
            dhs,
            dhs_pub,
            dhr,
            cks,
            ckr,
            ns,
            nr,
            pn,
            skipped,
            send_chains,
            kem_hist,
            kem_next_id,
            remote_ek,
            remote_ek_id,
            pending,
            hks,
            nhks,
            hkr,
            nhkr,
        })
    }
}

fn pqxdh_shared(parts: &[&[u8]]) -> (Zeroizing<Key>, Key, Key) {
    let mut ikm = Zeroizing::new(Vec::new());
    for p in parts {
        ikm.extend_from_slice(p);
    }
    let hkdf = Hkdf::<Sha256>::new(Some(&[0u8; 32]), &ikm);
    let mut okm = Zeroizing::new([0u8; 96]);
    hkdf.expand(b"vexil-pqxdh-v1", okm.as_mut())
        .expect("96 valid");
    let mut sk = Zeroizing::new([0u8; 32]);
    sk.copy_from_slice(&okm[..32]);
    let mut hk = [0u8; 32];
    hk.copy_from_slice(&okm[32..64]);
    let mut nhk = [0u8; 32];
    nhk.copy_from_slice(&okm[64..96]);
    (sk, hk, nhk)
}

impl Session {
    /// Initiator side: derive the shared secret from Bob's bundle and return the
    /// session plus the [`Handshake`] to send with the first message.
    pub fn initiate<R: RngCore + CryptoRng>(
        initiator: &PqIdentity,
        bundle: &PreKeyBundle,
        rng: &mut R,
    ) -> Result<(Session, Handshake)> {
        // Verify the signed prekey against Bob's identity.
        hybrid_verify(
            &bundle.identity.ed_public,
            &bundle.identity.ml_dsa_public,
            &bundle.signed_prekey,
            &bundle.spk_sig_ed,
            &bundle.spk_sig_pq,
        )
        .map_err(|_| SessionError::BadPrekeySignature)?;

        let spk_b = PublicKey::from(bundle.signed_prekey);
        let ik_b = bundle.identity.kem.x_public;
        let ek = StaticSecret::random_from_rng(&mut *rng);
        let ek_pub = PublicKey::from(&ek);

        let dh1 = initiator.kem.x_secret.diffie_hellman(&spk_b);
        let dh2 = ek.diffie_hellman(&ik_b);
        let dh3 = ek.diffie_hellman(&spk_b);
        let dh4 = bundle
            .one_time_prekey
            .map(|o| ek.diffie_hellman(&PublicKey::from(o)));
        let (kem_ct, ss) = mlkem_encapsulate(&bundle.identity.kem, rng)?;

        let mut parts: Vec<&[u8]> = vec![dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()];
        if let Some(d) = &dh4 {
            parts.push(d.as_bytes());
        }
        parts.push(ss.as_ref());
        let (sk, hk_alice, nhk_init) = pqxdh_shared(&parts);

        let hs = Handshake {
            ik: PublicKey::from(&initiator.kem.x_secret).to_bytes(),
            ek: ek_pub.to_bytes(),
            kem_ct,
            used_opk: bundle.one_time_prekey.is_some(),
        };
        let session = Session::init_alice(
            *sk,
            bundle.signed_prekey,
            initiator.kem.ml_dk_bytes(),
            bundle.identity.kem.ml_ek_bytes(),
            hk_alice,
            nhk_init,
            rng,
        )?;
        Ok((session, hs))
    }

    /// Responder side: re-derive the shared secret from the [`Handshake`].
    pub fn accept(
        responder: &PqIdentity,
        secrets: &PreKeySecrets,
        hs: &Handshake,
    ) -> Result<Session> {
        let ik_a = PublicKey::from(hs.ik);
        let ek_a = PublicKey::from(hs.ek);

        let dh1 = secrets.spk_secret.diffie_hellman(&ik_a);
        let dh2 = responder.kem.x_secret.diffie_hellman(&ek_a);
        let dh3 = secrets.spk_secret.diffie_hellman(&ek_a);
        let dh4 = if hs.used_opk {
            let opk = secrets.opk_secret.as_ref().ok_or(SessionError::Malformed)?;
            Some(opk.diffie_hellman(&ek_a))
        } else {
            None
        };
        let ss = mlkem_decapsulate(&responder.kem, &hs.kem_ct)?;

        let mut parts: Vec<&[u8]> = vec![dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes()];
        if let Some(d) = &dh4 {
            parts.push(d.as_bytes());
        }
        parts.push(ss.as_ref());
        let (sk, hk_alice, nhk_init) = pqxdh_shared(&parts);

        // Bob seeds dhs with his signed-prekey pair, and his ML-KEM history with
        // his identity KEM key (id 0), which Alice encapsulated to first.
        let dhs = secrets.spk_secret.clone();
        let dhs_pub = PublicKey::from(&dhs);
        Ok(Session {
            rk: *sk,
            dhs,
            dhs_pub,
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: std::collections::VecDeque::new(),
            send_chains: 0,
            kem_hist: vec![KemEntry {
                id: 0,
                dk: responder.kem.ml_dk_bytes(),
            }],
            kem_next_id: 1,
            remote_ek: Vec::new(),
            remote_ek_id: 0,
            pending: None,
            hks: None,
            nhks: nhk_init,
            hkr: None,
            nhkr: hk_alice,
        })
    }

    fn init_alice<R: RngCore + CryptoRng>(
        sk: Key,
        bob_spk: [u8; 32],
        alice_id_dk: Vec<u8>,
        bob_id_ek: Vec<u8>,
        hk_alice: Key,
        nhk_init: Key,
        rng: &mut R,
    ) -> Result<Session> {
        let dhs = StaticSecret::random_from_rng(&mut *rng);
        let dhs_pub = PublicKey::from(&dhs);
        let mut s = Session {
            rk: sk,
            dhs,
            dhs_pub,
            dhr: Some(bob_spk),
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: std::collections::VecDeque::new(),
            send_chains: 0,
            kem_hist: vec![KemEntry {
                id: 0,
                dk: alice_id_dk,
            }],
            kem_next_id: 1,
            remote_ek: bob_id_ek,
            remote_ek_id: 0,
            pending: None,
            hks: Some(hk_alice),
            nhks: [0u8; 32], // set below
            hkr: None,
            nhkr: nhk_init,
        };
        // Chain 0 is a PQ chain: encapsulate to Bob's identity key and mix.
        s.start_send_chain(rng)?;
        let dh = s.dhs.diffie_hellman(&PublicKey::from(bob_spk));
        let (rk, cks, nhks_alice) = kdf_rk(&s.rk, dh.as_bytes());
        s.rk = rk;
        s.cks = Some(cks);
        s.nhks = nhks_alice;
        Ok(s)
    }

    /// Encrypt the next message. Returns `(enc_header, ciphertext)`.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &mut self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        self.encrypt_with_ad(plaintext, &[], rng)
    }

    /// Encrypt with extra associated data bound into the message's
    /// authentication (e.g. a conversation id). The receiver must pass the same
    /// `ad` to [`decrypt_with_ad`](Self::decrypt_with_ad) or it will not open.
    pub fn encrypt_with_ad<R: RngCore + CryptoRng>(
        &mut self,
        plaintext: &[u8],
        ad: &[u8],
        rng: &mut R,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let cks = self.cks.ok_or(SessionError::Malformed)?;
        let (next, mk) = kdf_ck(&cks);
        self.cks = Some(next);
        let (mlkem_ek, ek_id, target_id, mlkem_ct) = match &self.pending {
            Some(p) => (p.ek.clone(), p.ek_id, p.target_id, p.ct.clone()),
            None => (Vec::new(), 0, 0, Vec::new()),
        };
        let header = Header {
            dh: self.dhs_pub.to_bytes(),
            pn: self.pn,
            n: self.ns,
            mlkem_ek,
            ek_id,
            target_id,
            mlkem_ct,
        };
        self.ns += 1;
        let hks = self.hks.ok_or(SessionError::Malformed)?;
        let enc_header = encrypt_header(&hks, &header, rng);
        let (key, nonce) = msg_keys(&mk);
        let ct = aead::seal(
            Aead::ChaCha20Poly1305,
            &key,
            &nonce,
            plaintext,
            &msg_aad(&enc_header, ad),
        )?;
        Ok((enc_header, ct))
    }

    /// Decrypt a message. May advance the DH ratchet, which needs the RNG.
    pub fn decrypt<R: RngCore + CryptoRng>(
        &mut self,
        enc_header: &[u8],
        ct: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        self.decrypt_with_ad(enc_header, ct, &[], rng)
    }

    /// Decrypt with associated data that must match what the sender bound.
    pub fn decrypt_with_ad<R: RngCore + CryptoRng>(
        &mut self,
        enc_header: &[u8],
        ct: &[u8],
        ad: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        if let Some(pt) = self.try_skipped(enc_header, ct, ad)? {
            return Ok(pt);
        }
        // Try current receive header key (in-chain message)
        if let Some(hkr) = self.hkr {
            if let Some(header) = try_decrypt_header(&hkr, enc_header) {
                self.skip_message_keys(header.n, hkr)?;
                let ckr = self.ckr.ok_or(SessionError::Malformed)?;
                let (next, mk) = kdf_ck(&ckr);
                self.ckr = Some(next);
                self.nr += 1;
                let (key, nonce) = msg_keys(&mk);
                return aead::open(
                    Aead::ChaCha20Poly1305,
                    &key,
                    &nonce,
                    ct,
                    &msg_aad(enc_header, ad),
                )
                .map_err(|_| SessionError::DecryptFailed);
            }
        }
        // Try next receive header key (peer started a new chain)
        if let Some(header) = try_decrypt_header(&self.nhkr, enc_header) {
            self.skip_message_keys(header.pn, self.hkr.unwrap_or([0u8; 32]))?;
            self.dh_ratchet(&header, rng)?;
            self.skip_message_keys(header.n, self.hkr.unwrap_or([0u8; 32]))?;
            let ckr = self.ckr.ok_or(SessionError::Malformed)?;
            let (next, mk) = kdf_ck(&ckr);
            self.ckr = Some(next);
            self.nr += 1;
            let (key, nonce) = msg_keys(&mk);
            return aead::open(
                Aead::ChaCha20Poly1305,
                &key,
                &nonce,
                ct,
                &msg_aad(enc_header, ad),
            )
            .map_err(|_| SessionError::DecryptFailed);
        }
        Err(SessionError::DecryptFailed)
    }

    fn try_skipped(&mut self, enc_header: &[u8], ct: &[u8], ad: &[u8]) -> Result<Option<Vec<u8>>> {
        for idx in 0..self.skipped.len() {
            let (hk_ref, n_ref, _) = &self.skipped[idx];
            let hk = *hk_ref;
            let n = *n_ref;
            if let Some(header) = try_decrypt_header(&hk, enc_header) {
                if header.n == n {
                    let (_, _, mk) = self.skipped.remove(idx).expect("index from position");
                    let (key, nonce) = msg_keys(&mk);
                    let pt = aead::open(
                        Aead::ChaCha20Poly1305,
                        &key,
                        &nonce,
                        ct,
                        &msg_aad(enc_header, ad),
                    )
                    .map_err(|_| SessionError::DecryptFailed)?;
                    return Ok(Some(pt));
                }
            }
        }
        Ok(None)
    }

    fn skip_message_keys(&mut self, until: u32, hk: Key) -> Result<()> {
        if self.ckr.is_none() {
            return Ok(());
        }
        if until > self.nr + MAX_SKIP {
            return Err(SessionError::TooManySkipped);
        }
        while self.nr < until {
            let ckr = self.ckr.unwrap();
            let (next, mk) = kdf_ck(&ckr);
            self.ckr = Some(next);
            self.skipped.push_back((hk, self.nr, mk));
            self.nr += 1;
            if self.skipped.len() as u32 > MAX_SKIP {
                self.skipped.pop_front();
            }
        }
        Ok(())
    }

    fn dh_ratchet<R: RngCore + CryptoRng>(&mut self, header: &Header, rng: &mut R) -> Result<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        // PQ in: if the sender's chain was a PQ chain, fold its secret into the
        // root before the receiving-chain step.
        self.pq_in(header)?;
        self.dhr = Some(header.dh);
        let dhr = PublicKey::from(header.dh);
        // Advance receiving header key: the peer's current chain's key becomes hkr.
        self.hkr = Some(self.nhkr);
        let (rk1, ckr, nhkr_new) = kdf_rk(&self.rk, self.dhs.diffie_hellman(&dhr).as_bytes());
        self.rk = rk1;
        self.ckr = Some(ckr);
        self.nhkr = nhkr_new;
        // New X25519 ratchet key, advance sending header key, then start our sending chain.
        self.hks = Some(self.nhks);
        self.dhs = StaticSecret::random_from_rng(&mut *rng);
        self.dhs_pub = PublicKey::from(&self.dhs);
        self.start_send_chain(rng)?;
        let (rk2, cks, nhks_new) = kdf_rk(&self.rk, self.dhs.diffie_hellman(&dhr).as_bytes());
        self.rk = rk2;
        self.cks = Some(cks);
        self.nhks = nhks_new;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    fn pair() -> (Session, Session) {
        let alice = PqIdentity::generate();
        let bob = PqIdentity::generate();
        let (bundle, secrets) = new_prekey_bundle(&bob, &mut OsRng);
        let (mut a, hs) = Session::initiate(&alice, &bundle, &mut OsRng).unwrap();
        // Alice's first message drives Bob's ratchet init.
        let (h, c) = a.encrypt(b"hello", &mut OsRng).unwrap();
        let mut b = Session::accept(&bob, &secrets, &hs).unwrap();
        assert_eq!(b.decrypt(&h, &c, &mut OsRng).unwrap(), b"hello");
        (a, b)
    }

    #[test]
    fn back_and_forth() {
        let (mut a, mut b) = pair();
        for i in 0..10u8 {
            let (h, c) = a.encrypt(&[i; 8], &mut OsRng).unwrap();
            assert_eq!(b.decrypt(&h, &c, &mut OsRng).unwrap(), vec![i; 8]);
            let (h2, c2) = b.encrypt(&[i + 100; 8], &mut OsRng).unwrap();
            assert_eq!(a.decrypt(&h2, &c2, &mut OsRng).unwrap(), vec![i + 100; 8]);
        }
    }

    #[test]
    fn pq_ratchet_is_sparse_and_recurs() {
        let (mut a, mut b) = pair();
        // Drive many back-and-forth turns; protocol must stay in sync.
        for i in 0..(PQ_CHAIN_INTERVAL * 3) {
            let (hb, cb) = b.encrypt(&[i as u8; 4], &mut OsRng).unwrap();
            a.decrypt(&hb, &cb, &mut OsRng).unwrap();
            let (ha, ca) = a.encrypt(&[i as u8; 4], &mut OsRng).unwrap();
            b.decrypt(&ha, &ca, &mut OsRng).unwrap();
        }
    }

    #[test]
    fn associated_data_must_match() {
        let (mut a, mut b) = pair();
        let (h, c) = a
            .encrypt_with_ad(b"msg", b"conversation-42", &mut OsRng)
            .unwrap();
        // Right AD opens.
        assert_eq!(
            b.decrypt_with_ad(&h, &c, b"conversation-42", &mut OsRng)
                .unwrap(),
            b"msg"
        );
        // Wrong AD on a fresh message fails.
        let (h2, c2) = a
            .encrypt_with_ad(b"msg2", b"conversation-42", &mut OsRng)
            .unwrap();
        assert!(b.decrypt_with_ad(&h2, &c2, b"other", &mut OsRng).is_err());
    }

    #[test]
    fn session_state_persists_across_restart() {
        let (mut a, mut b) = pair();
        // Exchange enough to advance several chains (crossing a PQ chain).
        for i in 0..(PQ_CHAIN_INTERVAL + 1) {
            let (h, c) = a.encrypt(&[i as u8; 8], &mut OsRng).unwrap();
            assert_eq!(b.decrypt(&h, &c, &mut OsRng).unwrap(), vec![i as u8; 8]);
            let (h2, c2) = b.encrypt(&[i as u8 + 50; 8], &mut OsRng).unwrap();
            assert_eq!(
                a.decrypt(&h2, &c2, &mut OsRng).unwrap(),
                vec![i as u8 + 50; 8]
            );
        }
        // Leave a skipped message in flight for Bob.
        let (h_skip, c_skip) = a.encrypt(b"skipped", &mut OsRng).unwrap();
        let (h_next, c_next) = a.encrypt(b"next", &mut OsRng).unwrap();

        // Serialize and restore both sides (e.g. app restart).
        let mut a = Session::from_bytes(&a.to_bytes()).unwrap();
        let mut b = Session::from_bytes(&b.to_bytes()).unwrap();

        // Out-of-order delivery still works after restore (skipped-key cache survived).
        assert_eq!(b.decrypt(&h_next, &c_next, &mut OsRng).unwrap(), b"next");
        assert_eq!(b.decrypt(&h_skip, &c_skip, &mut OsRng).unwrap(), b"skipped");

        // And the ratchet keeps going in both directions, including new PQ chains.
        for i in 0..(PQ_CHAIN_INTERVAL + 1) {
            let (h, c) = b.encrypt(&[i as u8; 8], &mut OsRng).unwrap();
            assert_eq!(a.decrypt(&h, &c, &mut OsRng).unwrap(), vec![i as u8; 8]);
            let (h2, c2) = a.encrypt(&[i as u8 + 9; 8], &mut OsRng).unwrap();
            assert_eq!(
                b.decrypt(&h2, &c2, &mut OsRng).unwrap(),
                vec![i as u8 + 9; 8]
            );
        }
    }

    #[test]
    fn out_of_order() {
        let (mut a, mut b) = pair();
        let (h1, c1) = a.encrypt(b"one", &mut OsRng).unwrap();
        let (h2, c2) = a.encrypt(b"two", &mut OsRng).unwrap();
        let (h3, c3) = a.encrypt(b"three", &mut OsRng).unwrap();
        // Deliver 3, then 1, then 2.
        assert_eq!(b.decrypt(&h3, &c3, &mut OsRng).unwrap(), b"three");
        assert_eq!(b.decrypt(&h1, &c1, &mut OsRng).unwrap(), b"one");
        assert_eq!(b.decrypt(&h2, &c2, &mut OsRng).unwrap(), b"two");
    }

    #[test]
    fn forward_secrecy_old_key_useless() {
        let (mut a, mut b) = pair();
        let (h1, c1) = a.encrypt(b"secret-1", &mut OsRng).unwrap();
        assert_eq!(b.decrypt(&h1, &c1, &mut OsRng).unwrap(), b"secret-1");
        // Many further messages advance the chains; replaying an old ciphertext
        // with a stale header must not decrypt twice.
        assert!(b.decrypt(&h1, &c1, &mut OsRng).is_err());
    }

    #[test]
    fn post_compromise_recovers() {
        // After both sides take a fresh DH ratchet step (a reply round), a new
        // root key is in force. We assert the channel keeps working across many
        // ratchet turns, which is the healing property in action.
        let (mut a, mut b) = pair();
        for _ in 0..5 {
            let (h, c) = a.encrypt(b"ping", &mut OsRng).unwrap();
            assert_eq!(b.decrypt(&h, &c, &mut OsRng).unwrap(), b"ping");
            let (h2, c2) = b.encrypt(b"pong", &mut OsRng).unwrap();
            assert_eq!(a.decrypt(&h2, &c2, &mut OsRng).unwrap(), b"pong");
        }
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let (mut a, mut b) = pair();
        let (h, mut c) = a.encrypt(b"data", &mut OsRng).unwrap();
        c[0] ^= 1;
        assert!(b.decrypt(&h, &c, &mut OsRng).is_err());
    }

    #[test]
    fn bundle_and_secrets_serialize() {
        let bob = PqIdentity::generate();
        let (bundle, secrets) = new_prekey_bundle(&bob, &mut OsRng);
        let b2 = PreKeyBundle::from_bytes(&bundle.to_bytes()).unwrap();
        let s2 = PreKeySecrets::from_bytes(&secrets.to_bytes()).unwrap();
        assert_eq!(b2.to_bytes(), bundle.to_bytes());
        assert_eq!(s2.to_bytes(), secrets.to_bytes());
        // round-tripped bundle/secrets still drive a working session
        let alice = PqIdentity::generate();
        let (mut a, hs) = Session::initiate(&alice, &b2, &mut OsRng).unwrap();
        let (h, c) = a.encrypt(b"x", &mut OsRng).unwrap();
        let mut bob_s = Session::accept(&bob, &s2, &hs).unwrap();
        assert_eq!(bob_s.decrypt(&h, &c, &mut OsRng).unwrap(), b"x");
    }

    #[test]
    fn wrong_responder_fails_handshake() {
        let alice = PqIdentity::generate();
        let bob = PqIdentity::generate();
        let eve = PqIdentity::generate();
        let (bundle, _) = new_prekey_bundle(&bob, &mut OsRng);
        let (_, eve_secrets) = new_prekey_bundle(&eve, &mut OsRng);
        let (mut a, hs) = Session::initiate(&alice, &bundle, &mut OsRng).unwrap();
        let (h, c) = a.encrypt(b"hi", &mut OsRng).unwrap();
        // Eve accepts with her own secrets: handshake derives a different secret.
        let mut e = Session::accept(&eve, &eve_secrets, &hs).unwrap();
        assert!(e.decrypt(&h, &c, &mut OsRng).is_err());
    }
}
