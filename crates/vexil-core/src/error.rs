//! Error type for the VEXIL protocol.

use thiserror::Error;

/// All fallible operations in `vexil-core` return [`Result`].
#[derive(Error, Debug)]
pub enum VexilError {
    /// The envelope magic, version, or framing was malformed.
    #[error("invalid VEXIL envelope")]
    InvalidEnvelope,

    /// The envelope declares a protocol version this build cannot parse.
    #[error("unsupported version: 0x{0:02x}")]
    UnsupportedVersion(u8),

    /// The suite byte does not correspond to a known [`crate::Suite`].
    #[error("unknown suite: 0x{0:02x}")]
    UnknownSuite(u8),

    /// The mode byte does not correspond to a known [`crate::Mode`].
    #[error("unknown mode: 0x{0:02x}")]
    UnknownMode(u8),

    /// The envelope mode did not match the operation requested
    /// (e.g. decrypting a multi-recipient blob with the symmetric API).
    #[error("mode mismatch: envelope is {got}, expected {expected}")]
    ModeMismatch {
        /// Mode found in the envelope.
        got: &'static str,
        /// Mode the caller asked for.
        expected: &'static str,
    },

    /// A required TLV entry was absent from the body.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// A TLV entry had the wrong fixed length.
    #[error("malformed field: {0}")]
    MalformedField(&'static str),

    /// AEAD tag verification failed: wrong key, wrong recipient, or tampering.
    #[error("decryption failed (wrong key/recipient or tampered ciphertext)")]
    DecryptionFailed,

    /// Argon2id / HKDF failure.
    #[error("key derivation failed: {0}")]
    KdfFailure(String),

    /// The ASCII codec hit a character outside the alphabet.
    #[error("encoding error: invalid character")]
    InvalidEncoding,

    /// A PEM block was missing its header/footer.
    #[error("encoding error: malformed PEM armor")]
    MalformedPem,

    /// A key, nonce, or salt had an unexpected length.
    #[error("invalid length for {0}")]
    InvalidLength(&'static str),

    /// Ed25519 signature verification failed.
    #[error("signature verification failed")]
    BadSignature,

    /// No recipient stanza in a multi-recipient envelope matched the supplied key.
    #[error("no matching recipient stanza for this identity")]
    NoMatchingRecipient,

    /// An identity / pubkey file header or field was malformed.
    #[error("malformed key file: {0}")]
    MalformedKeyFile(&'static str),

    /// The ciphertext has expired per its AAD-bound expiry timestamp.
    #[error("ciphertext expired at unix {0}")]
    Expired(i64),

    /// A post-quantum operation was requested without the `pq` feature.
    #[error("post-quantum support not compiled in (enable feature \"pq\")")]
    PqUnavailable,

    /// A TLV value or the body exceeds the 16-bit envelope length limit. Large
    /// data must use streaming, a linear encoding (hex/raw/pem), or be split.
    #[error("payload too large for one envelope ({0} bytes, max 65535); use streaming")]
    PayloadTooLarge(usize),

    /// Underlying I/O failure (streaming).
    #[error("io error: {0}")]
    Io(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, VexilError>;

impl From<std::io::Error> for VexilError {
    fn from(e: std::io::Error) -> Self {
        VexilError::Io(e.to_string())
    }
}
