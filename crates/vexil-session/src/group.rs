//! Group messaging via sender keys (feature: always on with `vexil-session`).
//!
//! Signal-style groups: each member owns a *sender key* — a symmetric KDF chain
//! plus a hybrid (Ed25519 + ML-DSA-65) signing key. To send, a member advances
//! its own chain (per-message forward secrecy), encrypts once, and signs. Every
//! member decrypts the same ciphertext, so cost is O(1) in group size for the
//! payload.
//!
//! The sender key is distributed to members over the pairwise PQ channel (a
//! [`crate::Session`] or a sealed box) as a [`SenderKeyDistribution`]. Adding or
//! removing a member means rotating sender keys (issue a fresh distribution).
//!
//! Confidentiality rests on the shared chain key (distributed over a PQ channel,
//! and symmetric keys are quantum-safe at 256 bits). Authenticity is post-quantum
//! via the hybrid signature, so a quantum adversary cannot forge a member's
//! messages.
//!
//! ```
//! use vexil_session::group::{GroupSender, GroupReceiver};
//! use vexil_core::rand_core::OsRng;
//!
//! let mut alice = GroupSender::new(&mut OsRng);
//! // Alice sends her distribution to Bob over their pairwise channel:
//! let mut bob = GroupReceiver::from_distribution(&alice.distribution());
//! let msg = alice.encrypt(b"hello group", &mut OsRng);
//! assert_eq!(bob.decrypt(&msg).unwrap(), b"hello group");
//! ```

use crate::{kdf_ck, msg_keys, Key, Result, SessionError, MAX_SKIP};
use ed25519_dalek::SigningKey;
use rand_core::{CryptoRng, RngCore};
use vexil_core::aead;
use vexil_core::sign_pq::{hybrid_sign, hybrid_verify, ml_dsa_public};
use vexil_core::suite::Aead;
use zeroize::Zeroize;

/// A member's sender key: a symmetric chain plus a hybrid signing key.
pub struct GroupSender {
    chain_key: Key,
    iteration: u32,
    ed: SigningKey,
    ml_dsa_seed: [u8; 32],
}

/// The public sender-key material a member shares with the group. Send it over a
/// pairwise PQ channel (it contains the symmetric chain key — treat as secret).
#[derive(Clone)]
pub struct SenderKeyDistribution {
    /// Current chain key.
    pub chain_key: Key,
    /// Current chain iteration.
    pub iteration: u32,
    /// Sender's Ed25519 public key.
    pub ed_public: [u8; 32],
    /// Sender's ML-DSA-65 public key.
    pub ml_dsa_public: Vec<u8>,
}

impl Drop for GroupSender {
    fn drop(&mut self) {
        self.chain_key.zeroize();
        self.ml_dsa_seed.zeroize();
    }
}

impl Drop for GroupReceiver {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

impl SenderKeyDistribution {
    /// Serialize: `chain_key(32) || iteration(4) || ed(32) || u16(len)||ml_dsa`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(70 + self.ml_dsa_public.len());
        v.extend_from_slice(&self.chain_key);
        v.extend_from_slice(&self.iteration.to_be_bytes());
        v.extend_from_slice(&self.ed_public);
        v.extend_from_slice(&(self.ml_dsa_public.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.ml_dsa_public);
        v
    }

    /// Parse from [`SenderKeyDistribution::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 70 {
            return Err(SessionError::Malformed);
        }
        let chain_key: Key = b[..32].try_into().unwrap();
        let iteration = u32::from_be_bytes(b[32..36].try_into().unwrap());
        let ed_public: [u8; 32] = b[36..68].try_into().unwrap();
        let len = u16::from_be_bytes([b[68], b[69]]) as usize;
        if b.len() != 70 + len {
            return Err(SessionError::Malformed);
        }
        Ok(SenderKeyDistribution {
            chain_key,
            iteration,
            ed_public,
            ml_dsa_public: b[70..].to_vec(),
        })
    }
}

/// One group message: the chain position, ciphertext, and hybrid signature.
pub struct GroupMessage {
    /// Chain iteration this message was sealed at.
    pub iteration: u32,
    /// AEAD ciphertext (`ct || tag`).
    pub ct: Vec<u8>,
    /// Ed25519 signature over `iteration || ct`.
    pub ed_sig: [u8; 64],
    /// ML-DSA-65 signature over `iteration || ct`.
    pub pq_sig: Vec<u8>,
}

impl GroupMessage {
    /// Serialize: `iteration(4) || ed_sig(64) || u16(pqsig_len)||pq_sig || ct`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(70 + self.pq_sig.len() + self.ct.len());
        v.extend_from_slice(&self.iteration.to_be_bytes());
        v.extend_from_slice(&self.ed_sig);
        v.extend_from_slice(&(self.pq_sig.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.pq_sig);
        v.extend_from_slice(&self.ct);
        v
    }

    /// Parse from [`GroupMessage::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() < 70 {
            return Err(SessionError::Malformed);
        }
        let iteration = u32::from_be_bytes(b[..4].try_into().unwrap());
        let ed_sig: [u8; 64] = b[4..68].try_into().unwrap();
        let len = u16::from_be_bytes([b[68], b[69]]) as usize;
        if b.len() < 70 + len {
            return Err(SessionError::Malformed);
        }
        Ok(GroupMessage {
            iteration,
            ed_sig,
            pq_sig: b[70..70 + len].to_vec(),
            ct: b[70 + len..].to_vec(),
        })
    }
}

fn transcript(iteration: u32, ct: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(4 + ct.len());
    t.extend_from_slice(&iteration.to_be_bytes());
    t.extend_from_slice(ct);
    t
}

impl GroupSender {
    /// Create a fresh sender key from the OS CSPRNG.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut chain_key = [0u8; 32];
        rng.fill_bytes(&mut chain_key);
        let mut ed_seed = [0u8; 32];
        rng.fill_bytes(&mut ed_seed);
        let ed = SigningKey::from_bytes(&ed_seed);
        ed_seed.zeroize();
        let mut ml_dsa_seed = [0u8; 32];
        rng.fill_bytes(&mut ml_dsa_seed);
        GroupSender {
            chain_key,
            iteration: 0,
            ed,
            ml_dsa_seed,
        }
    }

    /// The distribution to hand to group members over a pairwise channel.
    pub fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            chain_key: self.chain_key,
            iteration: self.iteration,
            ed_public: self.ed.verifying_key().to_bytes(),
            ml_dsa_public: ml_dsa_public(&self.ml_dsa_seed),
        }
    }

    /// Encrypt and sign the next group message.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &mut self,
        plaintext: &[u8],
        _rng: &mut R,
    ) -> GroupMessage {
        let (next, mk) = kdf_ck(&self.chain_key);
        let iteration = self.iteration;
        self.chain_key = next;
        self.iteration += 1;
        let (key, nonce) = msg_keys(&mk);
        let ct = aead::seal(
            Aead::ChaCha20Poly1305,
            &key,
            &nonce,
            plaintext,
            &iteration.to_be_bytes(),
        )
        .expect("aead seal");
        let sig = hybrid_sign(&self.ed, &self.ml_dsa_seed, &transcript(iteration, &ct));
        GroupMessage {
            iteration,
            ct,
            ed_sig: sig.ed,
            pq_sig: sig.ml_dsa,
        }
    }

    /// Serialize the full sender key (including the secret signing seeds) so a
    /// member keeps the same chain across restarts. Contains secrets — store
    /// encrypted at rest.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(101);
        v.push(1); // format version
        v.extend_from_slice(&self.chain_key);
        v.extend_from_slice(&self.iteration.to_be_bytes());
        v.extend_from_slice(&self.ed.to_bytes());
        v.extend_from_slice(&self.ml_dsa_seed);
        v
    }

    /// Restore from [`GroupSender::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != 101 || b[0] != 1 {
            return Err(SessionError::Malformed);
        }
        let chain_key: Key = b[1..33].try_into().unwrap();
        let iteration = u32::from_be_bytes(b[33..37].try_into().unwrap());
        let ed_seed: [u8; 32] = b[37..69].try_into().unwrap();
        let ed = SigningKey::from_bytes(&ed_seed);
        let ml_dsa_seed: [u8; 32] = b[69..101].try_into().unwrap();
        Ok(GroupSender {
            chain_key,
            iteration,
            ed,
            ml_dsa_seed,
        })
    }
}

/// A receiver's view of one sender's chain in a group.
pub struct GroupReceiver {
    chain_key: Key,
    iteration: u32,
    ed_public: [u8; 32],
    ml_dsa_public: Vec<u8>,
    skipped: Vec<(u32, zeroize::Zeroizing<Key>)>,
}

impl GroupReceiver {
    /// Build from a sender's distribution.
    pub fn from_distribution(d: &SenderKeyDistribution) -> Self {
        GroupReceiver {
            chain_key: d.chain_key,
            iteration: d.iteration,
            ed_public: d.ed_public,
            ml_dsa_public: d.ml_dsa_public.clone(),
            skipped: Vec::new(),
        }
    }

    /// Serialize the receiver's chain position and skipped-key cache so it stays
    /// in sync across restarts. Contains chain/message-key secrets.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(72 + self.ml_dsa_public.len() + self.skipped.len() * 36);
        v.push(1); // format version
        v.extend_from_slice(&self.chain_key);
        v.extend_from_slice(&self.iteration.to_be_bytes());
        v.extend_from_slice(&self.ed_public);
        v.extend_from_slice(&(self.ml_dsa_public.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.ml_dsa_public);
        v.extend_from_slice(&(self.skipped.len() as u32).to_be_bytes());
        for (i, mk) in &self.skipped {
            v.extend_from_slice(&i.to_be_bytes());
            v.extend_from_slice(&**mk);
        }
        v
    }

    /// Restore from [`GroupReceiver::to_bytes`].
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let mut p = 0usize;
        let take = |p: &mut usize, n: usize| -> Result<&[u8]> {
            if *p + n > b.len() {
                return Err(SessionError::Malformed);
            }
            let s = &b[*p..*p + n];
            *p += n;
            Ok(s)
        };
        if take(&mut p, 1)?[0] != 1 {
            return Err(SessionError::Malformed);
        }
        let chain_key: Key = take(&mut p, 32)?.try_into().unwrap();
        let iteration = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap());
        let ed_public: [u8; 32] = take(&mut p, 32)?.try_into().unwrap();
        let ml_len = u16::from_be_bytes(take(&mut p, 2)?.try_into().unwrap()) as usize;
        let ml_dsa_public = take(&mut p, ml_len)?.to_vec();
        let skip_count = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap());
        if skip_count > MAX_SKIP {
            return Err(SessionError::TooManySkipped);
        }
        let mut skipped = Vec::with_capacity(skip_count as usize);
        for _ in 0..skip_count {
            let i = u32::from_be_bytes(take(&mut p, 4)?.try_into().unwrap());
            let mk: Key = take(&mut p, 32)?.try_into().unwrap();
            skipped.push((i, zeroize::Zeroizing::new(mk)));
        }
        Ok(GroupReceiver {
            chain_key,
            iteration,
            ed_public,
            ml_dsa_public,
            skipped,
        })
    }

    /// Verify and decrypt a group message. Handles out-of-order within the
    /// sender's chain via a bounded skipped-key cache.
    pub fn decrypt(&mut self, msg: &GroupMessage) -> Result<Vec<u8>> {
        // Authenticity first: a forged or tampered message is rejected before
        // any key-chain state advances.
        hybrid_verify(
            &self.ed_public,
            &self.ml_dsa_public,
            &transcript(msg.iteration, &msg.ct),
            &msg.ed_sig,
            &msg.pq_sig,
        )
        .map_err(|_| SessionError::DecryptFailed)?;

        if let Some(idx) = self.skipped.iter().position(|(i, _)| *i == msg.iteration) {
            let (_, mk) = self.skipped.remove(idx);
            return self.open(msg, &mk);
        }
        if msg.iteration < self.iteration {
            return Err(SessionError::DecryptFailed);
        }
        if msg.iteration > self.iteration + MAX_SKIP {
            return Err(SessionError::TooManySkipped);
        }
        while self.iteration < msg.iteration {
            let (next, mk) = kdf_ck(&self.chain_key);
            self.chain_key = next;
            self.skipped.push((self.iteration, mk));
            self.iteration += 1;
            if self.skipped.len() as u32 > MAX_SKIP {
                self.skipped.remove(0);
            }
        }
        let (next, mk) = kdf_ck(&self.chain_key);
        self.chain_key = next;
        self.iteration += 1;
        self.open(msg, &mk)
    }

    fn open(&self, msg: &GroupMessage, mk: &Key) -> Result<Vec<u8>> {
        let (key, nonce) = msg_keys(mk);
        aead::open(
            Aead::ChaCha20Poly1305,
            &key,
            &nonce,
            &msg.ct,
            &msg.iteration.to_be_bytes(),
        )
        .map_err(|_| SessionError::DecryptFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn group_three_members() {
        let mut alice = GroupSender::new(&mut OsRng);
        let dist = alice.distribution();
        let mut bob = GroupReceiver::from_distribution(&dist);
        let mut carol = GroupReceiver::from_distribution(&dist);
        for i in 0..5u8 {
            let m = alice.encrypt(&[i; 16], &mut OsRng);
            assert_eq!(bob.decrypt(&m).unwrap(), vec![i; 16]);
            assert_eq!(carol.decrypt(&m).unwrap(), vec![i; 16]);
        }
    }

    #[test]
    fn group_out_of_order() {
        let mut a = GroupSender::new(&mut OsRng);
        let mut b = GroupReceiver::from_distribution(&a.distribution());
        let m0 = a.encrypt(b"zero", &mut OsRng);
        let m1 = a.encrypt(b"one", &mut OsRng);
        let m2 = a.encrypt(b"two", &mut OsRng);
        assert_eq!(b.decrypt(&m2).unwrap(), b"two");
        assert_eq!(b.decrypt(&m0).unwrap(), b"zero");
        assert_eq!(b.decrypt(&m1).unwrap(), b"one");
    }

    #[test]
    fn group_tamper_and_forgery_rejected() {
        let mut a = GroupSender::new(&mut OsRng);
        let mut b = GroupReceiver::from_distribution(&a.distribution());
        let mut m = a.encrypt(b"data", &mut OsRng);
        let good = m.ct.clone();
        m.ct[0] ^= 1;
        assert!(b.decrypt(&m).is_err());
        m.ct = good;
        // a forged signer (different sender key) must not verify
        m.ed_sig[0] ^= 1;
        assert!(b.decrypt(&m).is_err());
    }

    #[test]
    fn group_serialization_roundtrip() {
        let mut a = GroupSender::new(&mut OsRng);
        let dist = a.distribution().to_bytes();
        let mut b =
            GroupReceiver::from_distribution(&SenderKeyDistribution::from_bytes(&dist).unwrap());
        let m = a.encrypt(b"wire", &mut OsRng);
        let wire = m.to_bytes();
        let parsed = GroupMessage::from_bytes(&wire).unwrap();
        assert_eq!(b.decrypt(&parsed).unwrap(), b"wire");
    }

    #[test]
    fn group_state_persists_across_restart() {
        let mut a = GroupSender::new(&mut OsRng);
        let mut b = GroupReceiver::from_distribution(&a.distribution());
        // Skip a message so the receiver caches a skipped key.
        let m0 = a.encrypt(b"zero", &mut OsRng);
        let m1 = a.encrypt(b"one", &mut OsRng);
        assert_eq!(b.decrypt(&m1).unwrap(), b"one"); // caches iteration 0

        // Round-trip both sides through their serialized state.
        let mut a = GroupSender::from_bytes(&a.to_bytes()).unwrap();
        let mut b = GroupReceiver::from_bytes(&b.to_bytes()).unwrap();

        // Sender keeps its chain: next message continues from where it left off.
        let m2 = a.encrypt(b"two", &mut OsRng);
        assert_eq!(b.decrypt(&m2).unwrap(), b"two");
        // Receiver kept the skipped key for iteration 0.
        assert_eq!(b.decrypt(&m0).unwrap(), b"zero");
    }

    #[test]
    fn group_replay_rejected() {
        let mut a = GroupSender::new(&mut OsRng);
        let mut b = GroupReceiver::from_distribution(&a.distribution());
        let m = a.encrypt(b"once", &mut OsRng);
        assert_eq!(b.decrypt(&m).unwrap(), b"once");
        assert!(
            b.decrypt(&m).is_err(),
            "replay of a consumed iteration must fail"
        );
    }
}
