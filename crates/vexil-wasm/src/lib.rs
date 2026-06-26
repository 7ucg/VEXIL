//! VEXIL WebAssembly bridge.
//!
//! Exposes the at-rest VEXIL API (password, sealed-box, identities, detached
//! signatures) to JavaScript via `wasm-bindgen`, so Node.js and browsers can use
//! the protocol. Build with `wasm-pack build --target nodejs` (or `web`).
//!
//! ```js
//! const vexil = require("./pkg/vexil_wasm.js");
//! const ct = vexil.encrypt_password("pw", new TextEncoder().encode("secret"));
//! const pt = vexil.decrypt_password("pw", ct);            // Uint8Array
//! const kp = vexil.keygen();
//! const sealed = vexil.seal_to(kp.public, new TextEncoder().encode("hi"));
//! const open = vexil.open_sealed(kp.identity, sealed);
//! ```

use vexil_core::{
    decrypt_with_password, encrypt_with_password, encrypt_with_password_preset,
    fingerprint::combined_safety_number, open_multi, open_sealed, open_signed,
    open_stream_multi_vec, open_stream_sealed_vec, open_stream_signed_vec, seal_multi,
    seal_multi_stream_vec, seal_signed, seal_signed_stream_vec, seal_to, seal_to_stream_vec,
    sign_detached, verify_detached, Argon2Preset, Identity, PublicIdentity, Suite,
};
use wasm_bindgen::prelude::*;

fn err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

/// A generated identity: keep `identity` secret, share `public`.
#[wasm_bindgen]
pub struct Keypair {
    identity: String,
    public: String,
}

#[wasm_bindgen]
impl Keypair {
    /// The secret identity file (`VEXIL-IDENTITY-v1:` text). Keep this private.
    #[wasm_bindgen(getter)]
    pub fn identity(&self) -> String {
        self.identity.clone()
    }
    /// The shareable public-key file (`VEXIL-KEY-v1:` text).
    #[wasm_bindgen(getter)]
    pub fn public(&self) -> String {
        self.public.clone()
    }
}

/// Encrypt `plaintext` with a password. Returns a `VEX1-...` string.
#[wasm_bindgen]
pub fn encrypt_password(password: &str, plaintext: &[u8]) -> Result<String, JsError> {
    encrypt_with_password(password.as_bytes(), plaintext).map_err(err)
}

/// Decrypt a `VEX1-...` string with a password. Returns the plaintext bytes.
#[wasm_bindgen]
pub fn decrypt_password(password: &str, ciphertext: &str) -> Result<Vec<u8>, JsError> {
    decrypt_with_password(password.as_bytes(), ciphertext).map_err(err)
}

/// Generate an identity (X25519 + Ed25519).
#[wasm_bindgen]
pub fn keygen() -> Result<Keypair, JsError> {
    let id = Identity::generate();
    let suite = Suite::default();
    Ok(Keypair {
        identity: id.to_identity_file(suite, None).map_err(err)?,
        public: id.public().to_pub_file(suite),
    })
}

/// Seal `plaintext` to a recipient's public-key file. Returns `VEX1S-...`.
#[wasm_bindgen]
pub fn seal_to_pub(public_file: &str, plaintext: &[u8]) -> Result<String, JsError> {
    let recipient = PublicIdentity::parse_pub_file(public_file).map_err(err)?;
    seal_to(&recipient, plaintext).map_err(err)
}

/// Open a `VEX1S-...` sealed box with an identity file. Returns plaintext bytes.
#[wasm_bindgen]
pub fn open_sealed_box(identity_file: &str, ciphertext: &str) -> Result<Vec<u8>, JsError> {
    let id = Identity::parse_identity_file(identity_file, None).map_err(err)?;
    open_sealed(&id, ciphertext).map_err(err)
}

/// Make a detached signature over `msg` with an identity file. Returns `VEXSIG-...`.
#[wasm_bindgen]
pub fn sign(identity_file: &str, msg: &[u8]) -> Result<String, JsError> {
    let id = Identity::parse_identity_file(identity_file, None).map_err(err)?;
    Ok(sign_detached(&id, msg))
}

/// Verify a `VEXSIG-...` detached signature. Returns true if valid.
#[wasm_bindgen]
pub fn verify(public_file: &str, msg: &[u8], signature: &str) -> Result<bool, JsError> {
    let signer = PublicIdentity::parse_pub_file(public_file).map_err(err)?;
    Ok(verify_detached(&signer, msg, signature).is_ok())
}

/// Signed sealed box: seal to `public_file`, sign with `sender_identity_file`.
#[wasm_bindgen]
pub fn seal_signed_to(
    public_file: &str,
    sender_identity_file: &str,
    plaintext: &[u8],
) -> Result<String, JsError> {
    let recipient = PublicIdentity::parse_pub_file(public_file).map_err(err)?;
    let sender = Identity::parse_identity_file(sender_identity_file, None).map_err(err)?;
    seal_signed(&recipient, &sender, plaintext).map_err(err)
}

/// Open a `VEX1A-...` signed box. Pass `from_public` to pin the sender.
#[wasm_bindgen]
pub fn open_signed_box(
    identity_file: &str,
    ciphertext: &str,
    from_public: Option<String>,
) -> Result<Vec<u8>, JsError> {
    let id = Identity::parse_identity_file(identity_file, None).map_err(err)?;
    let expected = match from_public {
        Some(f) => Some(PublicIdentity::parse_pub_file(&f).map_err(err)?),
        None => None,
    };
    open_signed(&id, ciphertext, expected.as_ref())
        .map(|(pt, _)| pt)
        .map_err(err)
}

/// Multi-recipient: seal once to several recipient pubkey files. `VEX1M-...`.
#[wasm_bindgen]
pub fn seal_to_many(public_files: Vec<String>, plaintext: &[u8]) -> Result<String, JsError> {
    let mut recipients = Vec::with_capacity(public_files.len());
    for f in &public_files {
        recipients.push(PublicIdentity::parse_pub_file(f).map_err(err)?);
    }
    seal_multi(&recipients, plaintext).map_err(err)
}

/// Open a `VEX1M-...` multi-recipient envelope with your identity.
#[wasm_bindgen]
pub fn open_multi_box(identity_file: &str, ciphertext: &str) -> Result<Vec<u8>, JsError> {
    let id = Identity::parse_identity_file(identity_file, None).map_err(err)?;
    open_multi(&id, ciphertext).map_err(err)
}

/// Fingerprint of a public-key file (`a1b2-c3d4-e5f6-7890`).
#[wasm_bindgen]
pub fn fingerprint(public_file: &str) -> Result<String, JsError> {
    let p = PublicIdentity::parse_pub_file(public_file).map_err(err)?;
    Ok(p.fingerprint(Suite::default()).to_short())
}

/// One-shot streaming (framed) encrypt of `plaintext` under a password.
#[wasm_bindgen]
pub fn encrypt_stream(password: &str, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let mut out = Vec::new();
    vexil_core::stream::encrypt_stream(
        Suite::default(),
        password.as_bytes(),
        plaintext,
        &mut out,
        &mut vexil_core::rand_core::OsRng,
    )
    .map_err(err)?;
    Ok(out)
}

/// One-shot streaming decrypt of a framed stream produced by [`encrypt_stream`].
#[wasm_bindgen]
pub fn decrypt_stream(password: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    let mut out = Vec::new();
    vexil_core::stream::decrypt_stream(
        password.as_bytes(),
        &mut std::io::Cursor::new(ciphertext),
        &mut out,
    )
    .map_err(err)?;
    Ok(out)
}

// ---- Streaming public-key modes -----------------------------------------

/// Seal `plaintext` to a recipient's public-key file (streaming, `VEX1SF-`). Returns raw bytes.
#[wasm_bindgen]
pub fn seal_stream_to_pub(public_file: &str, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    let recipient = PublicIdentity::parse_pub_file(public_file).map_err(err)?;
    seal_to_stream_vec(&recipient, plaintext).map_err(err)
}

/// Open a `VEX1SF-` sealed stream with an identity file. Returns plaintext bytes.
#[wasm_bindgen]
pub fn open_stream_sealed_box(identity_file: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    let id = Identity::parse_identity_file(identity_file, None).map_err(err)?;
    open_stream_sealed_vec(&id, ciphertext).map_err(err)
}

/// Signed streaming seal: encrypt to `public_file`, sign with `sender_identity_file` (`VEX1AF-`).
#[wasm_bindgen]
pub fn seal_stream_signed_to(
    public_file: &str,
    sender_identity_file: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    let recipient = PublicIdentity::parse_pub_file(public_file).map_err(err)?;
    let sender = Identity::parse_identity_file(sender_identity_file, None).map_err(err)?;
    seal_signed_stream_vec(&recipient, &sender, plaintext).map_err(err)
}

/// Open a `VEX1AF-` signed stream. Optionally pins the expected sender. Returns plaintext.
#[wasm_bindgen]
pub fn open_stream_signed_box(
    identity_file: &str,
    ciphertext: &[u8],
    from_public: Option<String>,
) -> Result<Vec<u8>, JsError> {
    let id = Identity::parse_identity_file(identity_file, None).map_err(err)?;
    let expected = match from_public {
        Some(f) => Some(PublicIdentity::parse_pub_file(&f).map_err(err)?),
        None => None,
    };
    open_stream_signed_vec(&id, ciphertext, expected.as_ref())
        .map(|(pt, _)| pt)
        .map_err(err)
}

/// Multi-recipient streaming seal (`VEX1MF-`). `public_files` is a JS `Array<string>`.
#[wasm_bindgen]
pub fn seal_stream_to_many(
    public_files: Vec<String>,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    let mut recipients = Vec::with_capacity(public_files.len());
    for f in &public_files {
        recipients.push(PublicIdentity::parse_pub_file(f).map_err(err)?);
    }
    seal_multi_stream_vec(&recipients, plaintext).map_err(err)
}

/// Open a `VEX1MF-` multi-recipient streaming envelope with your identity.
#[wasm_bindgen]
pub fn open_stream_multi_box(identity_file: &str, ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    let id = Identity::parse_identity_file(identity_file, None).map_err(err)?;
    open_stream_multi_vec(&id, ciphertext).map_err(err)
}

// ---- Safety numbers & Argon2 presets ------------------------------------

/// Combined safety number for two public-key files (decimal, 12 groups of 5 digits).
/// Both orderings produce the same string (lexicographically sorted internally).
#[wasm_bindgen]
pub fn safety_number(pub_file_a: &str, pub_file_b: &str) -> Result<String, JsError> {
    let a = PublicIdentity::parse_pub_file(pub_file_a).map_err(err)?;
    let b = PublicIdentity::parse_pub_file(pub_file_b).map_err(err)?;
    let fa = a.fingerprint(Suite::default());
    let fb = b.fingerprint(Suite::default());
    Ok(combined_safety_number(&fa, &fb))
}

/// Encrypt with a password using a specific Argon2id preset.
/// `preset`: 0 = Default (64 MiB), 1 = Interactive (32 MiB), 2 = Sensitive (128 MiB).
/// Returns a `VEX1-...` string.
#[wasm_bindgen]
pub fn encrypt_password_preset(
    preset: u8,
    password: &str,
    plaintext: &[u8],
) -> Result<String, JsError> {
    let p = Argon2Preset::from_byte(preset).ok_or_else(|| {
        JsError::new("unknown preset; use 0 (default), 1 (interactive), 2 (sensitive)")
    })?;
    encrypt_with_password_preset(p, password.as_bytes(), plaintext).map_err(err)
}

// ---- Live session (PQXDH + Double Ratchet) & groups --------------------

use vexil_core::pq_identity::PqIdentity;
use vexil_core::rand_core::OsRng;
use vexil_session::group::{GroupMessage, GroupReceiver, GroupSender, SenderKeyDistribution};
use vexil_session::{Handshake, PreKeyBundle, PreKeySecrets, Session};

/// Generate a post-quantum identity (X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65).
/// Returns the serialized secret identity (keep it private).
#[wasm_bindgen]
pub fn pq_keygen() -> Vec<u8> {
    PqIdentity::generate().to_bytes()
}

/// A prekey bundle: publish `bundle`, keep `secrets`.
#[wasm_bindgen]
pub struct Bundle {
    bundle: Vec<u8>,
    secrets: Vec<u8>,
}

#[wasm_bindgen]
impl Bundle {
    #[wasm_bindgen(getter)]
    pub fn bundle(&self) -> Vec<u8> {
        self.bundle.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn secrets(&self) -> Vec<u8> {
        self.secrets.clone()
    }
}

/// Build a prekey bundle for a serialized PQ identity.
#[wasm_bindgen]
pub fn new_prekey_bundle(identity: &[u8]) -> Result<Bundle, JsError> {
    let id = PqIdentity::from_bytes(identity).map_err(err)?;
    let (b, s) = vexil_session::new_prekey_bundle(&id, &mut OsRng);
    Ok(Bundle {
        bundle: b.to_bytes(),
        secrets: s.to_bytes(),
    })
}

/// A live Double Ratchet session (post-quantum). Hold one per conversation side.
#[wasm_bindgen]
pub struct WasmSession {
    inner: Session,
    handshake: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl WasmSession {
    /// Initiator: start a session from a recipient's bundle. The [`handshake`]
    /// getter then returns the bytes to send with the first message.
    pub fn initiate(identity: &[u8], bundle: &[u8]) -> Result<WasmSession, JsError> {
        let id = PqIdentity::from_bytes(identity).map_err(err)?;
        let b = PreKeyBundle::from_bytes(bundle).map_err(err)?;
        let (s, hs) = Session::initiate(&id, &b, &mut OsRng).map_err(err)?;
        Ok(WasmSession {
            inner: s,
            handshake: Some(hs.to_bytes()),
        })
    }

    /// Responder: accept a handshake with your identity and bundle secrets.
    pub fn accept(
        identity: &[u8],
        secrets: &[u8],
        handshake: &[u8],
    ) -> Result<WasmSession, JsError> {
        let id = PqIdentity::from_bytes(identity).map_err(err)?;
        let sec = PreKeySecrets::from_bytes(secrets).map_err(err)?;
        let hs = Handshake::from_bytes(handshake).map_err(err)?;
        Ok(WasmSession {
            inner: Session::accept(&id, &sec, &hs).map_err(err)?,
            handshake: None,
        })
    }

    /// The handshake bytes to send with the first message (initiator only).
    #[wasm_bindgen(getter)]
    pub fn handshake(&self) -> Option<Vec<u8>> {
        self.handshake.clone()
    }

    /// Encrypt the next message. Returns `u16(enc_header_len) || enc_header || ciphertext`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        let (enc_hdr, ct) = self.inner.encrypt(plaintext, &mut OsRng).map_err(err)?;
        let mut m = Vec::with_capacity(2 + enc_hdr.len() + ct.len());
        m.extend_from_slice(&(enc_hdr.len() as u16).to_be_bytes());
        m.extend_from_slice(&enc_hdr);
        m.extend_from_slice(&ct);
        Ok(m)
    }

    /// Decrypt a message produced by [`encrypt`].
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, JsError> {
        if msg.len() < 2 {
            return Err(JsError::new("short message"));
        }
        let hlen = u16::from_be_bytes([msg[0], msg[1]]) as usize;
        if msg.len() < 2 + hlen {
            return Err(JsError::new("short message"));
        }
        let enc_hdr = &msg[2..2 + hlen];
        self.inner
            .decrypt(enc_hdr, &msg[2 + hlen..], &mut OsRng)
            .map_err(err)
    }

    /// Serialize the full ratchet state so the conversation survives a reload.
    /// The bytes contain secrets — store them encrypted (e.g. via
    /// [`encrypt_password`]) and never expose them.
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }

    /// Restore a session from [`serialize`] bytes.
    pub fn deserialize(state: &[u8]) -> Result<WasmSession, JsError> {
        Ok(WasmSession {
            inner: Session::from_bytes(state).map_err(err)?,
            handshake: None,
        })
    }
}

/// A group sender key. Broadcast [`distribution`], then [`encrypt`].
#[wasm_bindgen]
pub struct WasmGroupSender {
    inner: GroupSender,
}

#[wasm_bindgen]
impl WasmGroupSender {
    #[wasm_bindgen(constructor)]
    pub fn new() -> WasmGroupSender {
        WasmGroupSender {
            inner: GroupSender::new(&mut OsRng),
        }
    }
    /// Serialized sender-key distribution (send over a pairwise PQ channel).
    pub fn distribution(&self) -> Vec<u8> {
        self.inner.distribution().to_bytes()
    }
    /// Encrypt + sign a group message (serialized).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.inner.encrypt(plaintext, &mut OsRng).to_bytes()
    }
    /// Serialize the sender key (contains secret seeds — store encrypted).
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
    /// Restore a sender key from [`serialize`] bytes.
    pub fn deserialize(state: &[u8]) -> Result<WasmGroupSender, JsError> {
        Ok(WasmGroupSender {
            inner: GroupSender::from_bytes(state).map_err(err)?,
        })
    }
}

impl Default for WasmGroupSender {
    fn default() -> Self {
        Self::new()
    }
}

/// A receiver's view of one group sender.
#[wasm_bindgen]
pub struct WasmGroupReceiver {
    inner: GroupReceiver,
}

#[wasm_bindgen]
impl WasmGroupReceiver {
    /// Build from a sender's distribution bytes.
    pub fn from_distribution(distribution: &[u8]) -> Result<WasmGroupReceiver, JsError> {
        let d = SenderKeyDistribution::from_bytes(distribution).map_err(err)?;
        Ok(WasmGroupReceiver {
            inner: GroupReceiver::from_distribution(&d),
        })
    }
    /// Verify + decrypt a serialized group message.
    pub fn decrypt(&mut self, msg: &[u8]) -> Result<Vec<u8>, JsError> {
        let m = GroupMessage::from_bytes(msg).map_err(err)?;
        self.inner.decrypt(&m).map_err(err)
    }
    /// Serialize chain position + skipped-key cache (contains secrets).
    pub fn serialize(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
    /// Restore a receiver from [`serialize`] bytes.
    pub fn deserialize(state: &[u8]) -> Result<WasmGroupReceiver, JsError> {
        Ok(WasmGroupReceiver {
            inner: GroupReceiver::from_bytes(state).map_err(err)?,
        })
    }
}
