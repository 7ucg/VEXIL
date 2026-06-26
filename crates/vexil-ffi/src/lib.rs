//! C ABI for VEXIL.
//!
//! A thin, stable C interface over `vexil-core` so the protocol can be used from
//! Dart/Flutter, Node, C, or anything that speaks the C ABI. This first cut
//! exposes the at-rest operations (password and sealed-box) plus identity
//! generation; the live session (Double Ratchet) is exposed separately.
//!
//! ## Memory rules
//! - Functions returning `*mut c_char` give an owned, NUL-terminated string.
//!   Free it with [`vexil_string_free`]. A NULL return means error.
//! - Functions returning [`VexilBuf`] give owned bytes. Free with
//!   [`vexil_buf_free`]. A NULL `.data` means error.
//! - Input byte buffers are borrowed for the duration of the call only.

use std::ffi::{c_char, c_int, CStr, CString};
use std::ptr;
use vexil_core::{
    decrypt_with_password, encrypt_with_password, fingerprint::combined_safety_number, open_multi,
    open_sealed, open_signed, open_stream_multi_vec, open_stream_sealed_vec,
    open_stream_signed_vec, seal_multi, seal_multi_stream_vec, seal_signed, seal_signed_stream_vec,
    seal_to, seal_to_stream_vec, sign_detached, verify_detached, Argon2Preset, Identity,
    PublicIdentity, Suite,
};

/// An owned byte buffer handed across the FFI boundary. `data` is NULL on error.
#[repr(C)]
pub struct VexilBuf {
    /// Pointer to `len` bytes, or NULL on error.
    pub data: *mut u8,
    /// Length in bytes.
    pub len: usize,
}

impl VexilBuf {
    fn err() -> Self {
        VexilBuf {
            data: ptr::null_mut(),
            len: 0,
        }
    }
    fn from_vec(mut v: Vec<u8>) -> Self {
        v.shrink_to_fit();
        let len = v.len();
        let data = v.as_mut_ptr();
        std::mem::forget(v);
        VexilBuf { data, len }
    }
}

// SAFETY: `ptr`/`len` must describe a valid readable region, or ptr may be null.
unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

// SAFETY: `s` must be a valid NUL-terminated C string, or null.
unsafe fn cstr<'a>(s: *const c_char) -> Option<&'a str> {
    if s.is_null() {
        return None;
    }
    CStr::from_ptr(s).to_str().ok()
}

fn to_cstring(s: String) -> *mut c_char {
    match CString::new(s) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Encrypt `pt` under a password. Returns a `VEX1-...` C string, or NULL.
///
/// # Safety
/// `pw`/`pt` must point to `pw_len`/`pt_len` readable bytes (or be NULL).
#[no_mangle]
pub unsafe extern "C" fn vexil_encrypt_password(
    pw: *const u8,
    pw_len: usize,
    pt: *const u8,
    pt_len: usize,
) -> *mut c_char {
    let (Some(pw), Some(pt)) = (slice(pw, pw_len), slice(pt, pt_len)) else {
        return ptr::null_mut();
    };
    match encrypt_with_password(pw, pt) {
        Ok(s) => to_cstring(s),
        Err(_) => ptr::null_mut(),
    }
}

/// Decrypt a `VEX1-...` C string with a password. Returns plaintext bytes.
///
/// # Safety
/// `pw` must point to `pw_len` readable bytes; `ct` must be a valid C string.
#[no_mangle]
pub unsafe extern "C" fn vexil_decrypt_password(
    pw: *const u8,
    pw_len: usize,
    ct: *const c_char,
) -> VexilBuf {
    let (Some(pw), Some(ct)) = (slice(pw, pw_len), cstr(ct)) else {
        return VexilBuf::err();
    };
    match decrypt_with_password(pw, ct) {
        Ok(v) => VexilBuf::from_vec(v),
        Err(_) => VexilBuf::err(),
    }
}

/// Generate an identity. Writes the identity-file text to `*out_identity` and
/// the pubkey-file text to `*out_public` (both owned C strings). Returns 0 on
/// success, -1 on error.
///
/// # Safety
/// `out_identity` and `out_public` must be valid pointers to writable `*mut c_char`.
#[no_mangle]
pub unsafe extern "C" fn vexil_keygen(
    out_identity: *mut *mut c_char,
    out_public: *mut *mut c_char,
) -> c_int {
    if out_identity.is_null() || out_public.is_null() {
        return -1;
    }
    let id = Identity::generate();
    let suite = Suite::default();
    let id_file = match id.to_identity_file(suite, None) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let pub_file = id.public().to_pub_file(suite);
    let id_c = to_cstring(id_file);
    let pub_c = to_cstring(pub_file);
    if id_c.is_null() || pub_c.is_null() {
        if !id_c.is_null() {
            vexil_string_free(id_c);
        }
        if !pub_c.is_null() {
            vexil_string_free(pub_c);
        }
        return -1;
    }
    *out_identity = id_c;
    *out_public = pub_c;
    0
}

/// Seal `pt` to a recipient pubkey file. Returns a `VEX1S-...` C string, or NULL.
///
/// # Safety
/// `pub_file` must be a valid C string; `pt` must point to `pt_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_seal_to(
    pub_file: *const c_char,
    pt: *const u8,
    pt_len: usize,
) -> *mut c_char {
    let (Some(pub_file), Some(pt)) = (cstr(pub_file), slice(pt, pt_len)) else {
        return ptr::null_mut();
    };
    let recipient = match PublicIdentity::parse_pub_file(pub_file) {
        Ok(r) => r,
        Err(_) => return ptr::null_mut(),
    };
    match seal_to(&recipient, pt) {
        Ok(s) => to_cstring(s),
        Err(_) => ptr::null_mut(),
    }
}

/// Open a `VEX1S-...` sealed box with an identity file. Returns plaintext bytes.
///
/// # Safety
/// `identity_file` and `ct` must be valid C strings.
#[no_mangle]
pub unsafe extern "C" fn vexil_open_sealed(
    identity_file: *const c_char,
    ct: *const c_char,
) -> VexilBuf {
    let (Some(identity_file), Some(ct)) = (cstr(identity_file), cstr(ct)) else {
        return VexilBuf::err();
    };
    let id = match Identity::parse_identity_file(identity_file, None) {
        Ok(i) => i,
        Err(_) => return VexilBuf::err(),
    };
    match open_sealed(&id, ct) {
        Ok(v) => VexilBuf::from_vec(v),
        Err(_) => VexilBuf::err(),
    }
}

/// Signed sealed box: seal to `pub_file` and sign with `sender_identity_file`.
///
/// # Safety
/// String args are valid C strings; `pt` points to `pt_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_seal_signed(
    pub_file: *const c_char,
    sender_identity_file: *const c_char,
    pt: *const u8,
    pt_len: usize,
) -> *mut c_char {
    let (Some(pubf), Some(idf), Some(pt)) = (
        cstr(pub_file),
        cstr(sender_identity_file),
        slice(pt, pt_len),
    ) else {
        return ptr::null_mut();
    };
    let (Ok(recipient), Ok(sender)) = (
        PublicIdentity::parse_pub_file(pubf),
        Identity::parse_identity_file(idf, None),
    ) else {
        return ptr::null_mut();
    };
    match seal_signed(&recipient, &sender, pt) {
        Ok(s) => to_cstring(s),
        Err(_) => ptr::null_mut(),
    }
}

/// Open a `VEX1A-` signed sealed box. If `from_pub_file` is non-NULL, the sender
/// signature must match it.
///
/// # Safety
/// String args are valid C strings (or NULL for `from_pub_file`).
#[no_mangle]
pub unsafe extern "C" fn vexil_open_signed(
    identity_file: *const c_char,
    ct: *const c_char,
    from_pub_file: *const c_char,
) -> VexilBuf {
    let (Some(idf), Some(ct)) = (cstr(identity_file), cstr(ct)) else {
        return VexilBuf::err();
    };
    let Ok(id) = Identity::parse_identity_file(idf, None) else {
        return VexilBuf::err();
    };
    let expected = match cstr(from_pub_file) {
        Some(f) => match PublicIdentity::parse_pub_file(f) {
            Ok(p) => Some(p),
            Err(_) => return VexilBuf::err(),
        },
        None => None,
    };
    match open_signed(&id, ct, expected.as_ref()) {
        Ok((pt, _sender)) => VexilBuf::from_vec(pt),
        Err(_) => VexilBuf::err(),
    }
}

/// Multi-recipient: seal once to `n` recipient pubkey files. Returns `VEX1M-`.
///
/// # Safety
/// `pubs` points to `n` valid C-string pointers; `pt` points to `pt_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_seal_multi(
    pubs: *const *const c_char,
    n: usize,
    pt: *const u8,
    pt_len: usize,
) -> *mut c_char {
    let Some(pt) = slice(pt, pt_len) else {
        return ptr::null_mut();
    };
    if pubs.is_null() {
        return ptr::null_mut();
    }
    let ptrs = std::slice::from_raw_parts(pubs, n);
    let mut recipients = Vec::with_capacity(n);
    for &p in ptrs {
        let Some(s) = cstr(p) else {
            return ptr::null_mut();
        };
        match PublicIdentity::parse_pub_file(s) {
            Ok(r) => recipients.push(r),
            Err(_) => return ptr::null_mut(),
        }
    }
    match seal_multi(&recipients, pt) {
        Ok(s) => to_cstring(s),
        Err(_) => ptr::null_mut(),
    }
}

/// Open a `VEX1M-` multi-recipient envelope with your identity.
///
/// # Safety
/// String args are valid C strings.
#[no_mangle]
pub unsafe extern "C" fn vexil_open_multi(
    identity_file: *const c_char,
    ct: *const c_char,
) -> VexilBuf {
    let (Some(idf), Some(ct)) = (cstr(identity_file), cstr(ct)) else {
        return VexilBuf::err();
    };
    let Ok(id) = Identity::parse_identity_file(idf, None) else {
        return VexilBuf::err();
    };
    match open_multi(&id, ct) {
        Ok(v) => VexilBuf::from_vec(v),
        Err(_) => VexilBuf::err(),
    }
}

/// Detached signature over `msg` with an identity file. Returns `VEXSIG-`.
///
/// # Safety
/// `identity_file` is a valid C string; `msg` points to `msg_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_sign(
    identity_file: *const c_char,
    msg: *const u8,
    msg_len: usize,
) -> *mut c_char {
    let (Some(idf), Some(msg)) = (cstr(identity_file), slice(msg, msg_len)) else {
        return ptr::null_mut();
    };
    match Identity::parse_identity_file(idf, None) {
        Ok(id) => to_cstring(sign_detached(&id, msg)),
        Err(_) => ptr::null_mut(),
    }
}

/// Verify a `VEXSIG-` detached signature. Returns 1 valid, 0 invalid, -1 error.
///
/// # Safety
/// String args are valid C strings; `msg` points to `msg_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_verify(
    signer_pub_file: *const c_char,
    msg: *const u8,
    msg_len: usize,
    signature: *const c_char,
) -> c_int {
    let (Some(pubf), Some(msg), Some(sig)) =
        (cstr(signer_pub_file), slice(msg, msg_len), cstr(signature))
    else {
        return -1;
    };
    let Ok(signer) = PublicIdentity::parse_pub_file(pubf) else {
        return -1;
    };
    match verify_detached(&signer, msg, sig) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Fingerprint of a `.pub` file (or a v2 PQ pubkey). Returns `a1b2-...`.
///
/// # Safety
/// `pub_file` is a valid C string.
#[no_mangle]
pub unsafe extern "C" fn vexil_fingerprint(pub_file: *const c_char) -> *mut c_char {
    let Some(pubf) = cstr(pub_file) else {
        return ptr::null_mut();
    };
    match PublicIdentity::parse_pub_file(pubf) {
        Ok(p) => to_cstring(p.fingerprint(Suite::default()).to_short()),
        Err(_) => ptr::null_mut(),
    }
}

/// One-shot streaming encrypt: returns the framed stream bytes for `pt`.
///
/// # Safety
/// `pw`/`pt` point to their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn vexil_encrypt_stream(
    pw: *const u8,
    pw_len: usize,
    pt: *const u8,
    pt_len: usize,
) -> VexilBuf {
    let (Some(pw), Some(pt)) = (slice(pw, pw_len), slice(pt, pt_len)) else {
        return VexilBuf::err();
    };
    let mut out = Vec::new();
    match vexil_core::stream::encrypt_stream(Suite::default(), pw, pt, &mut out, &mut OsRng) {
        Ok(()) => VexilBuf::from_vec(out),
        Err(_) => VexilBuf::err(),
    }
}

/// One-shot streaming decrypt of a framed stream into plaintext bytes.
///
/// # Safety
/// `pw`/`ct` point to their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn vexil_decrypt_stream(
    pw: *const u8,
    pw_len: usize,
    ct: *const u8,
    ct_len: usize,
) -> VexilBuf {
    let (Some(pw), Some(ct)) = (slice(pw, pw_len), slice(ct, ct_len)) else {
        return VexilBuf::err();
    };
    let mut out = Vec::new();
    match vexil_core::stream::decrypt_stream(pw, &mut std::io::Cursor::new(ct), &mut out) {
        Ok(()) => VexilBuf::from_vec(out),
        Err(_) => VexilBuf::err(),
    }
}

/// Streaming sealed box to a public key (`VEX1SF-`). Returns raw frame bytes.
///
/// # Safety
/// `pub_file` is a valid C string; `pt` points to `pt_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_seal_stream_to(
    pub_file: *const c_char,
    pt: *const u8,
    pt_len: usize,
) -> VexilBuf {
    let (Some(pubf), Some(pt)) = (cstr(pub_file), slice(pt, pt_len)) else {
        return VexilBuf::err();
    };
    let Ok(recipient) = PublicIdentity::parse_pub_file(pubf) else {
        return VexilBuf::err();
    };
    match seal_to_stream_vec(&recipient, pt) {
        Ok(v) => VexilBuf::from_vec(v),
        Err(_) => VexilBuf::err(),
    }
}

/// Decrypt a `VEX1SF-` streaming sealed frame produced by [`vexil_seal_stream_to`].
///
/// # Safety
/// `identity_file` is a valid C string; `ct` points to `ct_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_open_stream_sealed(
    identity_file: *const c_char,
    ct: *const u8,
    ct_len: usize,
) -> VexilBuf {
    let (Some(idf), Some(ct)) = (cstr(identity_file), slice(ct, ct_len)) else {
        return VexilBuf::err();
    };
    let Ok(id) = Identity::parse_identity_file(idf, None) else {
        return VexilBuf::err();
    };
    match open_stream_sealed_vec(&id, ct) {
        Ok(v) => VexilBuf::from_vec(v),
        Err(_) => VexilBuf::err(),
    }
}

/// Streaming signed sealed box (`VEX1AF-`). Returns raw frame bytes.
///
/// # Safety
/// String args are valid C strings; `pt` points to `pt_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_seal_stream_signed(
    pub_file: *const c_char,
    sender_identity_file: *const c_char,
    pt: *const u8,
    pt_len: usize,
) -> VexilBuf {
    let (Some(pubf), Some(idf), Some(pt)) = (
        cstr(pub_file),
        cstr(sender_identity_file),
        slice(pt, pt_len),
    ) else {
        return VexilBuf::err();
    };
    let (Ok(recipient), Ok(sender)) = (
        PublicIdentity::parse_pub_file(pubf),
        Identity::parse_identity_file(idf, None),
    ) else {
        return VexilBuf::err();
    };
    match seal_signed_stream_vec(&recipient, &sender, pt) {
        Ok(v) => VexilBuf::from_vec(v),
        Err(_) => VexilBuf::err(),
    }
}

/// Decrypt a `VEX1AF-` streaming signed frame. If `from_pub_file` is non-NULL
/// the sender signature must match it.
///
/// # Safety
/// String args are valid C strings (or NULL for `from_pub_file`); `ct` points
/// to `ct_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_open_stream_signed(
    identity_file: *const c_char,
    ct: *const u8,
    ct_len: usize,
    from_pub_file: *const c_char,
) -> VexilBuf {
    let (Some(idf), Some(ct)) = (cstr(identity_file), slice(ct, ct_len)) else {
        return VexilBuf::err();
    };
    let Ok(id) = Identity::parse_identity_file(idf, None) else {
        return VexilBuf::err();
    };
    let expected = match cstr(from_pub_file) {
        Some(f) => match PublicIdentity::parse_pub_file(f) {
            Ok(p) => Some(p),
            Err(_) => return VexilBuf::err(),
        },
        None => None,
    };
    match open_stream_signed_vec(&id, ct, expected.as_ref()) {
        Ok((pt, _)) => VexilBuf::from_vec(pt),
        Err(_) => VexilBuf::err(),
    }
}

/// Streaming multi-recipient sealed box (`VEX1MF-`). Returns raw frame bytes.
///
/// # Safety
/// `pubs` points to `n` valid C-string pointers; `pt` points to `pt_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_seal_stream_multi(
    pubs: *const *const c_char,
    n: usize,
    pt: *const u8,
    pt_len: usize,
) -> VexilBuf {
    let Some(pt) = slice(pt, pt_len) else {
        return VexilBuf::err();
    };
    if pubs.is_null() {
        return VexilBuf::err();
    }
    let ptrs = std::slice::from_raw_parts(pubs, n);
    let mut recipients = Vec::with_capacity(n);
    for &p in ptrs {
        let Some(s) = cstr(p) else {
            return VexilBuf::err();
        };
        match PublicIdentity::parse_pub_file(s) {
            Ok(r) => recipients.push(r),
            Err(_) => return VexilBuf::err(),
        }
    }
    match seal_multi_stream_vec(&recipients, pt) {
        Ok(v) => VexilBuf::from_vec(v),
        Err(_) => VexilBuf::err(),
    }
}

/// Decrypt a `VEX1MF-` streaming multi-recipient frame.
///
/// # Safety
/// `identity_file` is a valid C string; `ct` points to `ct_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_open_stream_multi(
    identity_file: *const c_char,
    ct: *const u8,
    ct_len: usize,
) -> VexilBuf {
    let (Some(idf), Some(ct)) = (cstr(identity_file), slice(ct, ct_len)) else {
        return VexilBuf::err();
    };
    let Ok(id) = Identity::parse_identity_file(idf, None) else {
        return VexilBuf::err();
    };
    match open_stream_multi_vec(&id, ct) {
        Ok(v) => VexilBuf::from_vec(v),
        Err(_) => VexilBuf::err(),
    }
}

/// Combined safety number for two pubkey files (40 decimal digits, 8 groups of
/// 5, space-separated). Returns a C string, or NULL on error.
///
/// # Safety
/// Both args are valid C strings.
#[no_mangle]
pub unsafe extern "C" fn vexil_combined_safety_number(
    pub_file_a: *const c_char,
    pub_file_b: *const c_char,
) -> *mut c_char {
    let (Some(a), Some(b)) = (cstr(pub_file_a), cstr(pub_file_b)) else {
        return ptr::null_mut();
    };
    let (Ok(pa), Ok(pb)) = (
        PublicIdentity::parse_pub_file(a),
        PublicIdentity::parse_pub_file(b),
    ) else {
        return ptr::null_mut();
    };
    let suite = Suite::default();
    let fa = pa.fingerprint(suite);
    let fb = pb.fingerprint(suite);
    to_cstring(combined_safety_number(&fa, &fb))
}

/// Encrypt with an explicit Argon2id preset (0=default, 1=interactive, 2=sensitive).
/// Returns a `VEX1-...` C string, or NULL.
///
/// # Safety
/// `pw`/`pt` point to their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn vexil_encrypt_password_preset(
    preset: u8,
    pw: *const u8,
    pw_len: usize,
    pt: *const u8,
    pt_len: usize,
) -> *mut c_char {
    let (Some(pw), Some(pt)) = (slice(pw, pw_len), slice(pt, pt_len)) else {
        return ptr::null_mut();
    };
    let p = match Argon2Preset::from_byte(preset) {
        Some(p) => p,
        None => return ptr::null_mut(),
    };
    match vexil_core::encrypt_with_password_preset(p, pw, pt) {
        Ok(s) => to_cstring(s),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a string returned by this library.
///
/// # Safety
/// `s` must be a pointer returned by this library, or NULL.
#[no_mangle]
pub unsafe extern "C" fn vexil_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// Free a [`VexilBuf`] returned by this library.
///
/// # Safety
/// `buf` must have been returned by this library.
#[no_mangle]
pub unsafe extern "C" fn vexil_buf_free(buf: VexilBuf) {
    if !buf.data.is_null() {
        drop(Vec::from_raw_parts(buf.data, buf.len, buf.len));
    }
}

// --- Live session (Double Ratchet) over FFI -----------------------------

use vexil_core::pq_identity::PqIdentity;
use vexil_core::rand_core::OsRng;
use vexil_session::group::{GroupMessage, GroupReceiver, GroupSender, SenderKeyDistribution};
use vexil_session::{new_prekey_bundle, Handshake, PreKeyBundle, PreKeySecrets, Session};

unsafe fn write_buf(out: *mut VexilBuf, v: Vec<u8>) -> bool {
    if out.is_null() {
        return false;
    }
    *out = VexilBuf::from_vec(v);
    true
}

/// Generate a post-quantum identity. Returns its serialized bytes (keep secret).
#[no_mangle]
pub extern "C" fn vexil_pq_keygen() -> VexilBuf {
    VexilBuf::from_vec(PqIdentity::generate().to_bytes())
}

/// Build a prekey bundle for a PQ identity. Writes the publishable bundle to
/// `out_bundle` and the private secrets (keep them) to `out_secrets`.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `id` points to `id_len` bytes; out pointers must be valid writable `VexilBuf`.
#[no_mangle]
pub unsafe extern "C" fn vexil_session_new_prekey_bundle(
    id: *const u8,
    id_len: usize,
    out_bundle: *mut VexilBuf,
    out_secrets: *mut VexilBuf,
) -> c_int {
    let Some(idb) = slice(id, id_len) else {
        return -1;
    };
    let Ok(identity) = PqIdentity::from_bytes(idb) else {
        return -1;
    };
    let (bundle, secrets) = new_prekey_bundle(&identity, &mut OsRng);
    if write_buf(out_bundle, bundle.to_bytes()) && write_buf(out_secrets, secrets.to_bytes()) {
        0
    } else {
        -1
    }
}

/// Initiator: start a session from a recipient's bundle. Writes the handshake to
/// `out_handshake` and returns an owned session pointer (NULL on error).
///
/// # Safety
/// `id`/`bundle` point to their lengths; `out_handshake` must be writable.
#[no_mangle]
pub unsafe extern "C" fn vexil_session_initiate(
    id: *const u8,
    id_len: usize,
    bundle: *const u8,
    bundle_len: usize,
    out_handshake: *mut VexilBuf,
) -> *mut Session {
    let (Some(idb), Some(bb)) = (slice(id, id_len), slice(bundle, bundle_len)) else {
        return ptr::null_mut();
    };
    let (Ok(identity), Ok(bundle)) = (PqIdentity::from_bytes(idb), PreKeyBundle::from_bytes(bb))
    else {
        return ptr::null_mut();
    };
    match Session::initiate(&identity, &bundle, &mut OsRng) {
        Ok((session, hs)) => {
            if write_buf(out_handshake, hs.to_bytes()) {
                Box::into_raw(Box::new(session))
            } else {
                ptr::null_mut()
            }
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Responder: accept a handshake with your identity + bundle secrets. Returns an
/// owned session pointer (NULL on error).
///
/// # Safety
/// All pointers point to their stated lengths.
#[no_mangle]
pub unsafe extern "C" fn vexil_session_accept(
    id: *const u8,
    id_len: usize,
    secrets: *const u8,
    secrets_len: usize,
    handshake: *const u8,
    handshake_len: usize,
) -> *mut Session {
    let (Some(idb), Some(sb), Some(hb)) = (
        slice(id, id_len),
        slice(secrets, secrets_len),
        slice(handshake, handshake_len),
    ) else {
        return ptr::null_mut();
    };
    let (Ok(identity), Ok(secrets), Ok(hs)) = (
        PqIdentity::from_bytes(idb),
        PreKeySecrets::from_bytes(sb),
        Handshake::from_bytes(hb),
    ) else {
        return ptr::null_mut();
    };
    match Session::accept(&identity, &secrets, &hs) {
        Ok(session) => Box::into_raw(Box::new(session)),
        Err(_) => ptr::null_mut(),
    }
}

/// Encrypt the next message. Writes `header(40) || ciphertext` to `out_msg`.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `s` is a live session pointer; `pt` points to `pt_len` bytes; `out_msg` writable.
#[no_mangle]
pub unsafe extern "C" fn vexil_session_encrypt(
    s: *mut Session,
    pt: *const u8,
    pt_len: usize,
    out_msg: *mut VexilBuf,
) -> c_int {
    let (Some(session), Some(pt)) = (s.as_mut(), slice(pt, pt_len)) else {
        return -1;
    };
    match session.encrypt(pt, &mut OsRng) {
        Ok((enc_hdr, ct)) => {
            // wire: u16(enc_hdr_len) || enc_hdr || ciphertext
            let mut msg = Vec::with_capacity(2 + enc_hdr.len() + ct.len());
            msg.extend_from_slice(&(enc_hdr.len() as u16).to_be_bytes());
            msg.extend_from_slice(&enc_hdr);
            msg.extend_from_slice(&ct);
            if write_buf(out_msg, msg) {
                0
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Decrypt a `header(40) || ciphertext` message. Writes plaintext to `out_pt`.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// `s` is a live session pointer; `msg` points to `msg_len` bytes; `out_pt` writable.
#[no_mangle]
pub unsafe extern "C" fn vexil_session_decrypt(
    s: *mut Session,
    msg: *const u8,
    msg_len: usize,
    out_pt: *mut VexilBuf,
) -> c_int {
    let (Some(session), Some(msg)) = (s.as_mut(), slice(msg, msg_len)) else {
        return -1;
    };
    if msg.len() < 2 {
        return -1;
    }
    let hlen = u16::from_be_bytes([msg[0], msg[1]]) as usize;
    if msg.len() < 2 + hlen {
        return -1;
    }
    let enc_hdr = &msg[2..2 + hlen];
    match session.decrypt(enc_hdr, &msg[2 + hlen..], &mut OsRng) {
        Ok(pt) => {
            if write_buf(out_pt, pt) {
                0
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Serialize a session's full ratchet state (contains secrets — store
/// encrypted at rest). `.data == NULL` on error.
///
/// # Safety
/// `s` is a live session pointer.
#[no_mangle]
pub unsafe extern "C" fn vexil_session_serialize(s: *mut Session) -> VexilBuf {
    match s.as_ref() {
        Some(s) => VexilBuf::from_vec(s.to_bytes()),
        None => VexilBuf::err(),
    }
}

/// Restore a session from `vexil_session_serialize` bytes. NULL on error.
///
/// # Safety
/// `bytes` points to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_session_deserialize(bytes: *const u8, len: usize) -> *mut Session {
    let Some(b) = slice(bytes, len) else {
        return ptr::null_mut();
    };
    match Session::from_bytes(b) {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a session pointer.
///
/// # Safety
/// `s` must be a pointer returned by initiate/accept, or NULL.
#[no_mangle]
pub unsafe extern "C" fn vexil_session_free(s: *mut Session) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

// --- Group messaging (sender keys) over FFI -----------------------------

/// Create a group sender key. Returns an owned handle.
#[no_mangle]
pub extern "C" fn vexil_group_sender_new() -> *mut GroupSender {
    Box::into_raw(Box::new(GroupSender::new(&mut OsRng)))
}

/// Serialize the sender's distribution (send it to members over a PQ channel).
///
/// # Safety
/// `s` is a live group-sender pointer.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_sender_distribution(s: *mut GroupSender) -> VexilBuf {
    match s.as_ref() {
        Some(s) => VexilBuf::from_vec(s.distribution().to_bytes()),
        None => VexilBuf::err(),
    }
}

/// Encrypt + sign a group message; writes the serialized message to `out_msg`.
///
/// # Safety
/// `s` is a live group-sender pointer; `pt` points to `pt_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_sender_encrypt(
    s: *mut GroupSender,
    pt: *const u8,
    pt_len: usize,
    out_msg: *mut VexilBuf,
) -> c_int {
    let (Some(s), Some(pt)) = (s.as_mut(), slice(pt, pt_len)) else {
        return -1;
    };
    let msg = s.encrypt(pt, &mut OsRng);
    if write_buf(out_msg, msg.to_bytes()) {
        0
    } else {
        -1
    }
}

/// Serialize a group sender's full key (contains secret signing seeds). Error: `.data == NULL`.
///
/// # Safety
/// `s` is a live group-sender pointer.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_sender_serialize(s: *mut GroupSender) -> VexilBuf {
    match s.as_ref() {
        Some(s) => VexilBuf::from_vec(s.to_bytes()),
        None => VexilBuf::err(),
    }
}

/// Restore a group sender from `vexil_group_sender_serialize`. NULL on error.
///
/// # Safety
/// `bytes` points to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_sender_deserialize(
    bytes: *const u8,
    len: usize,
) -> *mut GroupSender {
    let Some(b) = slice(bytes, len) else {
        return ptr::null_mut();
    };
    match GroupSender::from_bytes(b) {
        Ok(s) => Box::into_raw(Box::new(s)),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a group sender.
///
/// # Safety
/// `s` must be a pointer returned by `vexil_group_sender_new`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_sender_free(s: *mut GroupSender) {
    if !s.is_null() {
        drop(Box::from_raw(s));
    }
}

/// Build a group receiver from a serialized distribution. NULL on error.
///
/// # Safety
/// `dist` points to `dist_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_receiver_new(
    dist: *const u8,
    dist_len: usize,
) -> *mut GroupReceiver {
    let Some(db) = slice(dist, dist_len) else {
        return ptr::null_mut();
    };
    match SenderKeyDistribution::from_bytes(db) {
        Ok(d) => Box::into_raw(Box::new(GroupReceiver::from_distribution(&d))),
        Err(_) => ptr::null_mut(),
    }
}

/// Verify + decrypt a serialized group message. Writes plaintext to `out_pt`.
///
/// # Safety
/// `r` is a live group-receiver pointer; `msg` points to `msg_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_receiver_decrypt(
    r: *mut GroupReceiver,
    msg: *const u8,
    msg_len: usize,
    out_pt: *mut VexilBuf,
) -> c_int {
    let (Some(r), Some(msg)) = (r.as_mut(), slice(msg, msg_len)) else {
        return -1;
    };
    let Ok(parsed) = GroupMessage::from_bytes(msg) else {
        return -1;
    };
    match r.decrypt(&parsed) {
        Ok(pt) => {
            if write_buf(out_pt, pt) {
                0
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Serialize a group receiver's chain position and skipped-key cache.
/// `.data == NULL` on error.
///
/// # Safety
/// `r` is a live group-receiver pointer.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_receiver_serialize(r: *mut GroupReceiver) -> VexilBuf {
    match r.as_ref() {
        Some(r) => VexilBuf::from_vec(r.to_bytes()),
        None => VexilBuf::err(),
    }
}

/// Restore a group receiver from `vexil_group_receiver_serialize`. NULL on error.
///
/// # Safety
/// `bytes` points to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_receiver_deserialize(
    bytes: *const u8,
    len: usize,
) -> *mut GroupReceiver {
    let Some(b) = slice(bytes, len) else {
        return ptr::null_mut();
    };
    match GroupReceiver::from_bytes(b) {
        Ok(r) => Box::into_raw(Box::new(r)),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a group receiver.
///
/// # Safety
/// `r` must be a pointer returned by `vexil_group_receiver_new`, or NULL.
#[no_mangle]
pub unsafe extern "C" fn vexil_group_receiver_free(r: *mut GroupReceiver) {
    if !r.is_null() {
        drop(Box::from_raw(r));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_roundtrip_over_ffi() {
        let pw = b"secret-pw";
        let pt = b"hello ffi";
        unsafe {
            let ct = vexil_encrypt_password(pw.as_ptr(), pw.len(), pt.as_ptr(), pt.len());
            assert!(!ct.is_null());
            let buf = vexil_decrypt_password(pw.as_ptr(), pw.len(), ct);
            assert!(!buf.data.is_null());
            let out = std::slice::from_raw_parts(buf.data, buf.len);
            assert_eq!(out, pt);
            vexil_buf_free(buf);
            vexil_string_free(ct);
        }
    }

    #[test]
    fn sealed_roundtrip_over_ffi() {
        unsafe {
            let mut id_c: *mut c_char = ptr::null_mut();
            let mut pub_c: *mut c_char = ptr::null_mut();
            assert_eq!(vexil_keygen(&mut id_c, &mut pub_c), 0);
            let pt = b"sealed via ffi";
            let ct = vexil_seal_to(pub_c, pt.as_ptr(), pt.len());
            assert!(!ct.is_null());
            let buf = vexil_open_sealed(id_c, ct);
            assert!(!buf.data.is_null());
            assert_eq!(std::slice::from_raw_parts(buf.data, buf.len), pt);
            vexil_buf_free(buf);
            vexil_string_free(ct);
            vexil_string_free(id_c);
            vexil_string_free(pub_c);
        }
    }

    #[test]
    fn session_roundtrip_over_ffi() {
        unsafe {
            let empty = || VexilBuf {
                data: ptr::null_mut(),
                len: 0,
            };
            let read = |b: &VexilBuf| std::slice::from_raw_parts(b.data, b.len).to_vec();

            // identities
            let alice = vexil_pq_keygen();
            let bob = vexil_pq_keygen();

            // Bob publishes a bundle, keeps secrets
            let mut bundle = empty();
            let mut secrets = empty();
            assert_eq!(
                vexil_session_new_prekey_bundle(bob.data, bob.len, &mut bundle, &mut secrets),
                0
            );

            // Alice initiates + sends first message
            let mut hs = empty();
            let a = vexil_session_initiate(alice.data, alice.len, bundle.data, bundle.len, &mut hs);
            assert!(!a.is_null());
            let mut msg = empty();
            assert_eq!(vexil_session_encrypt(a, b"hi".as_ptr(), 2, &mut msg), 0);

            // Bob accepts + decrypts
            let b = vexil_session_accept(
                bob.data,
                bob.len,
                secrets.data,
                secrets.len,
                hs.data,
                hs.len,
            );
            assert!(!b.is_null());
            let mut pt = empty();
            assert_eq!(vexil_session_decrypt(b, msg.data, msg.len, &mut pt), 0);
            assert_eq!(read(&pt), b"hi");

            // Bob replies, Alice reads (ratchet turns)
            let mut reply = empty();
            assert_eq!(vexil_session_encrypt(b, b"yo".as_ptr(), 2, &mut reply), 0);
            let mut pt2 = empty();
            assert_eq!(vexil_session_decrypt(a, reply.data, reply.len, &mut pt2), 0);
            assert_eq!(read(&pt2), b"yo");

            for x in [alice, bob, bundle, secrets, hs, msg, pt, reply, pt2] {
                vexil_buf_free(x);
            }
            vexil_session_free(a);
            vexil_session_free(b);
        }
    }

    #[test]
    fn group_roundtrip_over_ffi() {
        unsafe {
            let empty = || VexilBuf {
                data: ptr::null_mut(),
                len: 0,
            };
            let read = |b: &VexilBuf| std::slice::from_raw_parts(b.data, b.len).to_vec();

            let sender = vexil_group_sender_new();
            let dist = vexil_group_sender_distribution(sender);
            let recv = vexil_group_receiver_new(dist.data, dist.len);
            assert!(!recv.is_null());

            let mut msg = empty();
            assert_eq!(
                vexil_group_sender_encrypt(sender, b"grp".as_ptr(), 3, &mut msg),
                0
            );
            let mut pt = empty();
            assert_eq!(
                vexil_group_receiver_decrypt(recv, msg.data, msg.len, &mut pt),
                0
            );
            assert_eq!(read(&pt), b"grp");

            for x in [dist, msg, pt] {
                vexil_buf_free(x);
            }
            vexil_group_sender_free(sender);
            vexil_group_receiver_free(recv);
        }
    }

    #[test]
    fn serialize_restore_session_and_group_over_ffi() {
        unsafe {
            let empty = || VexilBuf {
                data: ptr::null_mut(),
                len: 0,
            };
            let read = |b: &VexilBuf| std::slice::from_raw_parts(b.data, b.len).to_vec();

            // Establish a session.
            let alice = vexil_pq_keygen();
            let bob = vexil_pq_keygen();
            let mut bundle = empty();
            let mut secrets = empty();
            assert_eq!(
                vexil_session_new_prekey_bundle(bob.data, bob.len, &mut bundle, &mut secrets),
                0
            );
            let mut hs = empty();
            let a = vexil_session_initiate(alice.data, alice.len, bundle.data, bundle.len, &mut hs);
            let mut first = empty();
            assert_eq!(vexil_session_encrypt(a, b"hi".as_ptr(), 2, &mut first), 0);
            let b = vexil_session_accept(
                bob.data,
                bob.len,
                secrets.data,
                secrets.len,
                hs.data,
                hs.len,
            );
            let mut pt = empty();
            assert_eq!(vexil_session_decrypt(b, first.data, first.len, &mut pt), 0);

            // Serialize both sides, free, restore.
            let a_state = vexil_session_serialize(a);
            let b_state = vexil_session_serialize(b);
            vexil_session_free(a);
            vexil_session_free(b);
            let a = vexil_session_deserialize(a_state.data, a_state.len);
            let b = vexil_session_deserialize(b_state.data, b_state.len);
            assert!(!a.is_null() && !b.is_null());

            // Conversation continues after restore.
            let mut msg = empty();
            assert_eq!(
                vexil_session_encrypt(a, b"resumed".as_ptr(), 7, &mut msg),
                0
            );
            let mut got = empty();
            assert_eq!(vexil_session_decrypt(b, msg.data, msg.len, &mut got), 0);
            assert_eq!(read(&got), b"resumed");

            // Group: serialize sender + receiver, restore, continue.
            let sender = vexil_group_sender_new();
            let dist = vexil_group_sender_distribution(sender);
            let recv = vexil_group_receiver_new(dist.data, dist.len);
            let s_state = vexil_group_sender_serialize(sender);
            let r_state = vexil_group_receiver_serialize(recv);
            vexil_group_sender_free(sender);
            vexil_group_receiver_free(recv);
            let sender = vexil_group_sender_deserialize(s_state.data, s_state.len);
            let recv = vexil_group_receiver_deserialize(r_state.data, r_state.len);
            assert!(!sender.is_null() && !recv.is_null());
            let mut gmsg = empty();
            assert_eq!(
                vexil_group_sender_encrypt(sender, b"g".as_ptr(), 1, &mut gmsg),
                0
            );
            let mut gpt = empty();
            assert_eq!(
                vexil_group_receiver_decrypt(recv, gmsg.data, gmsg.len, &mut gpt),
                0
            );
            assert_eq!(read(&gpt), b"g");

            for x in [
                alice, bob, bundle, secrets, hs, first, pt, a_state, b_state, msg, got, dist,
                s_state, r_state, gmsg, gpt,
            ] {
                vexil_buf_free(x);
            }
            vexil_session_free(a);
            vexil_session_free(b);
            vexil_group_sender_free(sender);
            vexil_group_receiver_free(recv);
        }
    }

    #[test]
    fn signed_multi_sign_stream_over_ffi() {
        unsafe {
            let read = |b: &VexilBuf| std::slice::from_raw_parts(b.data, b.len).to_vec();
            let (mut a_id, mut a_pub) = (ptr::null_mut(), ptr::null_mut());
            let (mut b_id, mut b_pub) = (ptr::null_mut(), ptr::null_mut());
            assert_eq!(vexil_keygen(&mut a_id, &mut a_pub), 0);
            assert_eq!(vexil_keygen(&mut b_id, &mut b_pub), 0);

            // signed sealed box
            let pt = b"signed msg";
            let sct = vexil_seal_signed(b_pub, a_id, pt.as_ptr(), pt.len());
            assert!(!sct.is_null());
            let buf = vexil_open_signed(b_id, sct, a_pub);
            assert_eq!(read(&buf), pt);
            vexil_buf_free(buf);
            vexil_string_free(sct);

            // multi-recipient
            let pubs = [a_pub as *const c_char, b_pub as *const c_char];
            let mct = vexil_seal_multi(pubs.as_ptr(), 2, b"group".as_ptr(), 5);
            assert!(!mct.is_null());
            let buf = vexil_open_multi(b_id, mct);
            assert_eq!(read(&buf), b"group");
            vexil_buf_free(buf);
            vexil_string_free(mct);

            // detached sign / verify
            let sig = vexil_sign(a_id, b"file".as_ptr(), 4);
            assert!(!sig.is_null());
            assert_eq!(vexil_verify(a_pub, b"file".as_ptr(), 4, sig), 1);
            assert_eq!(vexil_verify(a_pub, b"x".as_ptr(), 1, sig), 0);
            vexil_string_free(sig);

            // fingerprint
            let fpr = vexil_fingerprint(a_pub);
            assert!(!fpr.is_null());
            vexil_string_free(fpr);

            // streaming bytes
            let data = vec![7u8; 200_000];
            let s = vexil_encrypt_stream(b"pw".as_ptr(), 2, data.as_ptr(), data.len());
            assert!(!s.data.is_null());
            let back = vexil_decrypt_stream(b"pw".as_ptr(), 2, s.data, s.len);
            assert_eq!(read(&back), data);
            vexil_buf_free(s);
            vexil_buf_free(back);

            for c in [a_id, a_pub, b_id, b_pub] {
                vexil_string_free(c);
            }
        }
    }

    #[test]
    fn wrong_password_returns_error() {
        let pt = b"x";
        unsafe {
            let ct = vexil_encrypt_password(b"right".as_ptr(), 5, pt.as_ptr(), pt.len());
            let buf = vexil_decrypt_password(b"wrong".as_ptr(), 5, ct);
            assert!(buf.data.is_null());
            vexil_string_free(ct);
        }
    }

    #[test]
    fn streaming_sealed_over_ffi() {
        unsafe {
            let read = |b: &VexilBuf| std::slice::from_raw_parts(b.data, b.len).to_vec();
            let mut id_c: *mut c_char = ptr::null_mut();
            let mut pub_c: *mut c_char = ptr::null_mut();
            assert_eq!(vexil_keygen(&mut id_c, &mut pub_c), 0);
            let data = vec![0xABu8; 200_000];
            let ct = vexil_seal_stream_to(pub_c, data.as_ptr(), data.len());
            assert!(!ct.data.is_null());
            let pt = vexil_open_stream_sealed(id_c, ct.data, ct.len);
            assert!(!pt.data.is_null());
            assert_eq!(read(&pt), data);
            vexil_buf_free(ct);
            vexil_buf_free(pt);
            vexil_string_free(id_c);
            vexil_string_free(pub_c);
        }
    }

    #[test]
    fn streaming_signed_over_ffi() {
        unsafe {
            let read = |b: &VexilBuf| std::slice::from_raw_parts(b.data, b.len).to_vec();
            let (mut a_id, mut a_pub) = (ptr::null_mut(), ptr::null_mut());
            let (mut b_id, mut b_pub) = (ptr::null_mut(), ptr::null_mut());
            assert_eq!(vexil_keygen(&mut a_id, &mut a_pub), 0);
            assert_eq!(vexil_keygen(&mut b_id, &mut b_pub), 0);
            let data = vec![0xCCu8; 130_000];
            let ct = vexil_seal_stream_signed(b_pub, a_id, data.as_ptr(), data.len());
            assert!(!ct.data.is_null());
            let pt = vexil_open_stream_signed(b_id, ct.data, ct.len, a_pub);
            assert!(!pt.data.is_null());
            assert_eq!(read(&pt), data);
            // wrong expected sender must fail
            let bad = vexil_open_stream_signed(b_id, ct.data, ct.len, b_pub);
            assert!(bad.data.is_null());
            vexil_buf_free(ct);
            vexil_buf_free(pt);
            for c in [a_id, a_pub, b_id, b_pub] {
                vexil_string_free(c);
            }
        }
    }

    #[test]
    fn streaming_multi_over_ffi() {
        unsafe {
            let read = |b: &VexilBuf| std::slice::from_raw_parts(b.data, b.len).to_vec();
            let (mut a_id, mut a_pub) = (ptr::null_mut(), ptr::null_mut());
            let (mut b_id, mut b_pub) = (ptr::null_mut(), ptr::null_mut());
            assert_eq!(vexil_keygen(&mut a_id, &mut a_pub), 0);
            assert_eq!(vexil_keygen(&mut b_id, &mut b_pub), 0);
            let data = b"multi-stream ffi test";
            let pubs = [a_pub as *const c_char, b_pub as *const c_char];
            let ct = vexil_seal_stream_multi(pubs.as_ptr(), 2, data.as_ptr(), data.len());
            assert!(!ct.data.is_null());
            let pt_a = vexil_open_stream_multi(a_id, ct.data, ct.len);
            let pt_b = vexil_open_stream_multi(b_id, ct.data, ct.len);
            assert_eq!(read(&pt_a), data);
            assert_eq!(read(&pt_b), data);
            vexil_buf_free(ct);
            vexil_buf_free(pt_a);
            vexil_buf_free(pt_b);
            for c in [a_id, a_pub, b_id, b_pub] {
                vexil_string_free(c);
            }
        }
    }

    #[test]
    fn safety_number_and_preset_over_ffi() {
        unsafe {
            let (mut a_id, mut a_pub) = (ptr::null_mut(), ptr::null_mut());
            let (mut b_id, mut b_pub) = (ptr::null_mut(), ptr::null_mut());
            assert_eq!(vexil_keygen(&mut a_id, &mut a_pub), 0);
            assert_eq!(vexil_keygen(&mut b_id, &mut b_pub), 0);

            // combined safety number must be symmetric
            let sn_ab = vexil_combined_safety_number(a_pub, b_pub);
            let sn_ba = vexil_combined_safety_number(b_pub, a_pub);
            assert!(!sn_ab.is_null());
            let ab = std::ffi::CStr::from_ptr(sn_ab).to_str().unwrap().to_owned();
            let ba = std::ffi::CStr::from_ptr(sn_ba).to_str().unwrap().to_owned();
            assert_eq!(ab, ba);
            assert_eq!(ab.split_whitespace().count(), 8);
            vexil_string_free(sn_ab);
            vexil_string_free(sn_ba);

            // interactive preset roundtrip
            let pt = b"fast argon2";
            let ct = vexil_encrypt_password_preset(1, pt.as_ptr(), pt.len(), pt.as_ptr(), pt.len());
            assert!(!ct.is_null());
            let back = vexil_decrypt_password(pt.as_ptr(), pt.len(), ct);
            assert!(!back.data.is_null());
            assert_eq!(
                std::slice::from_raw_parts(back.data, back.len),
                pt.as_slice()
            );
            vexil_buf_free(back);
            vexil_string_free(ct);

            for c in [a_id, a_pub, b_id, b_pub] {
                vexil_string_free(c);
            }
        }
    }
}
