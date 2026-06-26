//! VEXIL command-line interface.
//!
//! See `vexil --help` for the full command set. Short aliases: `enc`, `dec`,
//! `kg` (keygen), `fp` (fingerprint), `ls` (list identities).

use clap::{CommandFactory, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use vexil_core::rand_core::OsRng;
use vexil_core::{
    decrypt_with_password, encrypt_with_password_suite, open_multi, open_sealed, open_signed,
    open_stream_multi_vec, open_stream_sealed_vec, open_stream_signed_vec, seal_multi,
    seal_multi_stream_vec, seal_signed, seal_signed_stream_vec, seal_to, seal_to_stream_vec,
    sign_detached, verify_detached, Encoding, Identity, PublicIdentity, Suite,
};

#[derive(Parser)]
#[command(
    name = "vexil",
    version,
    about = "VEXIL Protocol — versioned, algorithm-agile hybrid encryption",
    long_about = "VEXIL encrypts data with peer-reviewed primitives (Argon2id, \
ChaCha20-Poly1305/AES-256-GCM, X25519, Ed25519, ML-KEM-768) behind a versioned, \
self-describing wire format. Supports password, sealed, signed, and \
multi-recipient modes plus streaming for large files."
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum SuiteArg {
    /// X25519 + ChaCha20-Poly1305 + Argon2id (default)
    Chapoly,
    /// X25519 + AES-256-GCM + Argon2id
    Aesgcm,
}

impl From<SuiteArg> for Suite {
    fn from(s: SuiteArg) -> Self {
        match s {
            SuiteArg::Chapoly => Suite::XChaPolyArgon,
            SuiteArg::Aesgcm => Suite::XAesGcmArgon,
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum EncodingArg {
    Base89,
    Hex,
    Raw,
    Pem,
}

impl From<EncodingArg> for Encoding {
    fn from(e: EncodingArg) -> Self {
        match e {
            EncodingArg::Base89 => Encoding::Base89,
            EncodingArg::Hex => Encoding::Hex,
            EncodingArg::Raw => Encoding::Raw,
            EncodingArg::Pem => Encoding::Pem,
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Encrypt (password, sealed, signed, or multi-recipient)
    #[command(visible_alias = "enc")]
    Encrypt(EncryptArgs),

    /// Decrypt any VEXIL ciphertext
    #[command(visible_alias = "dec")]
    Decrypt(DecryptArgs),

    /// Generate an identity (X25519 + Ed25519)
    #[command(visible_alias = "kg")]
    Keygen(KeygenArgs),

    /// Show the fingerprint of a public key, identity, or ciphertext
    #[command(visible_alias = "fp")]
    Fingerprint(FingerprintArgs),

    /// List identities in ~/.vexil/
    #[command(visible_alias = "ls")]
    List(ListArgs),

    /// Make a detached signature over data with your identity
    Sign(SignArgs),

    /// Verify a detached signature against a signer's public key
    Verify(VerifyArgs),

    /// Show a ciphertext's metadata (mode, suite, size) without decrypting
    Inspect(InspectArgs),

    /// Generate shell completions
    Completions {
        /// Target shell
        shell: Shell,
    },
}

#[derive(clap::Args)]
struct SignArgs {
    /// Your identity file
    #[arg(short = 'i', long)]
    identity: PathBuf,
    /// Passphrase for a passphrase-protected identity
    #[arg(long, env = "VEXIL_IDENTITY_PASS")]
    identity_pass: Option<String>,
    #[command(flatten)]
    io: IoIn,
}

#[derive(clap::Args)]
struct InspectArgs {
    #[command(flatten)]
    io: IoCt,
}

#[derive(clap::Args)]
struct VerifyArgs {
    /// Signer's public-key file
    #[arg(long = "from")]
    from: PathBuf,
    /// The detached signature (VEXSIG-...), inline
    #[arg(short = 's', long)]
    signature: Option<String>,
    /// The detached signature in a file
    #[arg(long)]
    signature_file: Option<PathBuf>,
    #[command(flatten)]
    io: IoIn,
}

#[derive(clap::Args)]
struct EncryptArgs {
    /// Password (symmetric mode). Reads $VEXIL_KEY if unset.
    #[arg(short = 'k', long, env = "VEXIL_KEY")]
    key: Option<String>,
    /// Recipient public-key file(s) for sealed / multi-recipient mode
    #[arg(long = "to")]
    to: Vec<PathBuf>,
    /// Sign with this identity file (signed mode)
    #[arg(long = "sign-with")]
    sign_with: Option<PathBuf>,
    /// Algorithm suite
    #[arg(long, value_enum, default_value = "chapoly")]
    suite: SuiteArg,
    /// Output encoding
    #[arg(long, value_enum, default_value = "base89")]
    encoding: EncodingArg,
    /// Shortcut for --encoding pem
    #[arg(long)]
    armor: bool,
    /// Emit JSON to stdout
    #[arg(long)]
    json: bool,
    /// Use streaming/framed mode (raw binary output; for large files)
    #[arg(long)]
    stream: bool,
    /// Refuse to fall back to classical crypto (requires PQ recipients)
    #[arg(long)]
    require_pq: bool,
    #[command(flatten)]
    io: IoIn,
}

#[derive(clap::Args)]
struct DecryptArgs {
    /// Password (symmetric mode). Reads $VEXIL_KEY if unset.
    #[arg(short = 'k', long, env = "VEXIL_KEY")]
    key: Option<String>,
    /// Your identity file (sealed / signed / multi-recipient mode)
    #[arg(short = 'i', long)]
    identity: Option<PathBuf>,
    /// Passphrase for a passphrase-protected identity
    #[arg(long, env = "VEXIL_IDENTITY_PASS")]
    identity_pass: Option<String>,
    /// Expected sender public key (signed mode): verify the message is from them
    #[arg(long = "from")]
    from: Option<PathBuf>,
    /// Refuse to decrypt anything that is not a post-quantum envelope
    #[arg(long)]
    require_pq: bool,
    #[command(flatten)]
    io: IoCt,
}

#[derive(clap::Args)]
struct KeygenArgs {
    /// Identity name (used for file names)
    #[arg(long, default_value = "default")]
    name: String,
    /// Output directory (default: ~/.vexil/)
    #[arg(long)]
    out: Option<PathBuf>,
    /// Encrypt the identity file with a passphrase
    #[arg(long)]
    passphrase: Option<String>,
    /// Generate a post-quantum identity (X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65)
    #[arg(long)]
    pq: bool,
}

#[derive(clap::Args)]
struct FingerprintArgs {
    /// A .pub public-key file
    #[arg(long)]
    public: Option<PathBuf>,
    /// An identity file
    #[arg(long)]
    identity: Option<PathBuf>,
}

#[derive(clap::Args)]
struct ListArgs {
    /// Directory to scan (default: ~/.vexil/)
    #[arg(long)]
    dir: Option<PathBuf>,
}

/// Plaintext input.
#[derive(clap::Args)]
struct IoIn {
    #[arg(short, long, conflicts_with_all = ["text", "stdin_flag"])]
    file: Option<PathBuf>,
    #[arg(short, long, conflicts_with_all = ["file", "stdin_flag"])]
    text: Option<String>,
    #[arg(long = "stdin", conflicts_with_all = ["file", "text"])]
    stdin_flag: bool,
    #[arg(short, long)]
    output: Option<PathBuf>,
}

/// Ciphertext input.
#[derive(clap::Args)]
struct IoCt {
    #[arg(short, long, conflicts_with_all = ["cipher", "stdin_flag"])]
    file: Option<PathBuf>,
    #[arg(short, long, conflicts_with_all = ["file", "stdin_flag"])]
    cipher: Option<String>,
    #[arg(long = "stdin", conflicts_with_all = ["file", "cipher"])]
    stdin_flag: bool,
    #[arg(short, long)]
    output: Option<PathBuf>,
}

type CliResult = Result<(), Box<dyn std::error::Error>>;

fn read_plaintext(io: &IoIn) -> io::Result<Vec<u8>> {
    if io.stdin_flag {
        let mut b = Vec::new();
        io::stdin().read_to_end(&mut b)?;
        Ok(b)
    } else if let Some(t) = &io.text {
        Ok(t.as_bytes().to_vec())
    } else if let Some(f) = &io.file {
        fs::read(f)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no input: use --text, --file, or --stdin",
        ))
    }
}

fn read_ciphertext(io: &IoCt) -> io::Result<Vec<u8>> {
    if io.stdin_flag {
        let mut b = Vec::new();
        io::stdin().read_to_end(&mut b)?;
        Ok(b)
    } else if let Some(c) = &io.cipher {
        Ok(c.as_bytes().to_vec())
    } else if let Some(f) = &io.file {
        fs::read(f)
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no input: use --cipher, --file, or --stdin",
        ))
    }
}

fn write_output(data: &[u8], output: &Option<PathBuf>) -> io::Result<()> {
    match output {
        Some(p) => fs::write(p, data),
        None => {
            io::stdout().write_all(data)?;
            if !data.ends_with(b"\n") {
                io::stdout().write_all(b"\n")?;
            }
            Ok(())
        }
    }
}

fn vexil_dir(explicit: Option<PathBuf>) -> PathBuf {
    explicit.unwrap_or_else(|| {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        home.join(".vexil")
    })
}

#[cfg(unix)]
fn chmod_600(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn chmod_600(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn run() -> CliResult {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Encrypt(a) => cmd_encrypt(a)?,
        Cmd::Decrypt(a) => cmd_decrypt(a)?,
        Cmd::Keygen(a) => cmd_keygen(a)?,
        Cmd::Fingerprint(a) => cmd_fingerprint(a)?,
        Cmd::List(a) => cmd_list(a)?,
        Cmd::Sign(a) => cmd_sign(a)?,
        Cmd::Verify(a) => cmd_verify(a)?,
        Cmd::Inspect(a) => cmd_inspect(a)?,
        Cmd::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut io::stdout());
        }
    }
    Ok(())
}

fn cmd_encrypt(mut a: EncryptArgs) -> CliResult {
    if a.armor {
        a.encoding = EncodingArg::Pem;
    }
    let suite: Suite = a.suite.into();
    let encoding: Encoding = a.encoding.into();
    let pt = read_plaintext(&a.io)?;

    // Streaming mode: raw binary framed output. Auto-engage for large inputs.
    // With --to: uses the streaming PK modes (VEX1SF-/VEX1AF-/VEX1MF-).
    // Without --to: password streaming (VEX1F-). Both need --output FILE.
    const STREAM_THRESHOLD: usize = 48 * 1024;
    if a.stream || pt.len() > STREAM_THRESHOLD {
        let out_path =
            a.io.output
                .as_ref()
                .ok_or("streaming mode needs --output FILE")?;
        if !a.to.is_empty() {
            // PK streaming: no password needed.
            let first = fs::read_to_string(&a.to[0])?;
            if first.trim_start().starts_with("VEXIL-KEY-v2:") {
                return Err(
                    "post-quantum streaming mode not yet supported; use classical keys".into(),
                );
            }
            let recipients: Vec<PublicIdentity> =
                a.to.iter()
                    .map(|p| -> CliResult2 {
                        PublicIdentity::parse_pub_file(&fs::read_to_string(p)?).map_err(Into::into)
                    })
                    .collect::<Result<_, _>>()?;
            let ct = if let Some(idp) = &a.sign_with {
                if recipients.len() != 1 {
                    return Err("signed streaming mode supports exactly one --to recipient".into());
                }
                let sender = Identity::parse_identity_file(&fs::read_to_string(idp)?, None)?;
                seal_signed_stream_vec(&recipients[0], &sender, &pt)?
            } else if recipients.len() == 1 {
                seal_to_stream_vec(&recipients[0], &pt)?
            } else {
                seal_multi_stream_vec(&recipients, &pt)?
            };
            fs::write(out_path, &ct)?;
        } else {
            // Password streaming.
            let key = a
                .key
                .as_ref()
                .ok_or("streaming mode without --to needs a --key password")?;
            let mut f = io::BufWriter::new(fs::File::create(out_path)?);
            vexil_core::stream::encrypt_stream(suite, key.as_bytes(), &pt, &mut f, &mut OsRng)?;
            f.flush()?;
        }
        eprintln!(
            "[\u{2713}] streamed {} bytes to {}",
            pt.len(),
            out_path.display()
        );
        return Ok(());
    }

    // Mode selection: recipients => sealed/signed/multi; else password. Each
    // branch returns the library's armored string; encoding is applied below.
    let lib_ct = if !a.to.is_empty() {
        let first = fs::read_to_string(&a.to[0])?;
        if first.trim_start().starts_with("VEXIL-KEY-v2:") {
            pq_encrypt(&a, &pt)?
        } else {
            if a.require_pq {
                return Err("--require-pq set, but the recipients are classical keys".into());
            }
            let recipients: Vec<PublicIdentity> =
                a.to.iter()
                    .map(|p| -> CliResult2 {
                        PublicIdentity::parse_pub_file(&fs::read_to_string(p)?).map_err(Into::into)
                    })
                    .collect::<Result<_, _>>()?;
            if let Some(idp) = &a.sign_with {
                if recipients.len() != 1 {
                    return Err("signed mode supports exactly one --to recipient".into());
                }
                let sender = Identity::parse_identity_file(&fs::read_to_string(idp)?, None)?;
                seal_signed(&recipients[0], &sender, &pt)?
            } else if recipients.len() == 1 {
                seal_to(&recipients[0], &pt)?
            } else {
                seal_multi(&recipients, &pt)?
            }
        }
    } else {
        if a.require_pq {
            return Err("--require-pq needs PQ recipients (--to a VEXIL-KEY-v2 file)".into());
        }
        let key = a
            .key
            .as_ref()
            .ok_or("no --key/--to: symmetric mode needs a password")?;
        encrypt_with_password_suite(suite, key.as_bytes(), &pt)?
    };

    if a.json {
        if encoding == Encoding::Raw {
            return Err("--encoding raw is not compatible with --json".into());
        }
        let ct = reencode(&lib_ct, encoding)?;
        let obj = serde_json::json!({
            "ciphertext": ct,
            "encoding": encoding.name(),
            "suite": suite.as_byte(),
        });
        println!("{}", serde_json::to_string(&obj)?);
    } else if encoding == Encoding::Raw {
        // Raw: write the bare envelope bytes (no prefix, no text encoding).
        let (_, body) = split_prefix(&lib_ct);
        let bytes = Encoding::detect(body).decode(body)?;
        write_output(&bytes, &a.io.output)?;
    } else {
        let ct = reencode(&lib_ct, encoding)?;
        write_output(ct.as_bytes(), &a.io.output)?;
    }
    Ok(())
}

type CliResult2 = Result<PublicIdentity, Box<dyn std::error::Error>>;

/// Re-encode an armored VEXIL string into `target`, preserving its prefix. The
/// source encoding (base89 or hex, as the library chose by size) is detected.
fn reencode(armored: &str, target: Encoding) -> Result<String, Box<dyn std::error::Error>> {
    let (prefix, body) = split_prefix(armored);
    let src = Encoding::detect(body);
    if src == target {
        return Ok(armored.to_string());
    }
    let bin = src.decode(body)?;
    Ok(format!("{}{}", prefix, target.encode(&bin)))
}

fn split_prefix(s: &str) -> (&str, &str) {
    // Longer prefixes first so "VEX1SF-" is not eaten by "VEX1S-".
    for p in [
        "VEX1SF-", "VEX1AF-", "VEX1MF-", "VEX1P-", "VEX1A-", "VEX1S-", "VEX1M-", "VEX1F-", "VEX1-",
    ] {
        if let Some(rest) = s.strip_prefix(p) {
            return (&s[..p.len()], rest);
        }
    }
    ("", s)
}

fn cmd_decrypt(a: DecryptArgs) -> CliResult {
    let raw = read_ciphertext(&a.io)?;
    let pass = a.identity_pass.as_deref().map(str::as_bytes);

    // Raw binary envelope: detect by magic + mode byte.
    if raw.len() >= 10 && &raw[0..5] == b"VEXIL" {
        let mode_byte = raw[7];
        match mode_byte {
            4 => {
                // Password streaming (VEX1F-)
                let key = a.key.as_ref().ok_or("streaming ciphertext needs --key")?;
                let out_path =
                    a.io.output
                        .as_ref()
                        .ok_or("streaming decrypt needs --output FILE")?;
                let mut reader = io::Cursor::new(&raw);
                let mut writer = io::BufWriter::new(fs::File::create(out_path)?);
                vexil_core::stream::decrypt_stream(key.as_bytes(), &mut reader, &mut writer)?;
                writer.flush()?;
                return Ok(());
            }
            5..=7 => {
                // PK streaming (VEX1SF-/VEX1AF-/VEX1MF-)
                let idp = a
                    .identity
                    .as_ref()
                    .ok_or("streaming PK ciphertext needs --identity")?;
                let identity = Identity::parse_identity_file(&fs::read_to_string(idp)?, pass)?;
                let pt = match mode_byte {
                    5 => open_stream_sealed_vec(&identity, &raw)?,
                    6 => {
                        let expected = match &a.from {
                            Some(p) => {
                                Some(PublicIdentity::parse_pub_file(&fs::read_to_string(p)?)?)
                            }
                            None => None,
                        };
                        open_stream_signed_vec(&identity, &raw, expected.as_ref())?.0
                    }
                    _ => open_stream_multi_vec(&identity, &raw)?,
                };
                write_output(&pt, &a.io.output)?;
                return Ok(());
            }
            _ => {} // Fall through to armored path.
        }
    }

    let armored = to_armored(&raw)?;

    if a.require_pq && !armored.starts_with("VEX1P-") {
        return Err("--require-pq set, but this is not a post-quantum envelope".into());
    }

    let pt = if armored.starts_with("VEX1P-") {
        pq_decrypt(&a, &armored)?
    } else if armored.starts_with("VEX1-") {
        let key = a.key.as_ref().ok_or("symmetric ciphertext needs --key")?;
        decrypt_with_password(key.as_bytes(), &armored)?
    } else {
        let idp = a
            .identity
            .as_ref()
            .ok_or("asymmetric ciphertext needs --identity")?;
        let identity = Identity::parse_identity_file(&fs::read_to_string(idp)?, pass)?;
        if armored.starts_with("VEX1A-") {
            let expected = match &a.from {
                Some(p) => Some(PublicIdentity::parse_pub_file(&fs::read_to_string(p)?)?),
                None => None,
            };
            let (pt, _sender) = open_signed(&identity, &armored, expected.as_ref())?;
            pt
        } else if armored.starts_with("VEX1M-") {
            open_multi(&identity, &armored)?
        } else if armored.starts_with("VEX1S-") {
            open_sealed(&identity, &armored)?
        } else {
            return Err(decrypt_hint().into());
        }
    };
    write_output(&pt, &a.io.output)?;
    Ok(())
}

/// Normalize ciphertext input to a prefixed, library-decodable string. Handles
/// a raw binary envelope (`--encoding raw`: no prefix, starts with magic) by
/// re-attaching the prefix and a hex body; otherwise keeps the text as-is and
/// lets the library auto-detect base89 / hex / pem.
fn to_armored(raw: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    if raw.len() >= 10 && &raw[0..5] == b"VEXIL" {
        let suite = vexil_core::Suite::from_byte(raw[6])?;
        let mode = vexil_core::envelope::Mode::from_byte(raw[7])?;
        return Ok(format!(
            "{}{}",
            vexil_core::prefix_for(mode, suite),
            Encoding::Hex.encode(raw)
        ));
    }
    let s = String::from_utf8_lossy(raw);
    let s = s.trim();
    if split_prefix(s).0.is_empty() {
        return Err(decrypt_hint().into());
    }
    Ok(s.to_string())
}

fn decrypt_hint() -> String {
    "decryption failed\nhint: this can happen when the password is wrong, the file was \
tampered with, or it was encrypted to a different recipient. Check the mode with \
`vexil fingerprint` and confirm you are using the right --key or --identity."
        .to_string()
}

fn cmd_keygen(a: KeygenArgs) -> CliResult {
    if a.pq {
        return pq_keygen(&a);
    }
    let dir = vexil_dir(a.out);
    fs::create_dir_all(&dir)?;
    let id = Identity::generate();
    let suite = Suite::default();
    let pass = a.passphrase.as_deref().map(str::as_bytes);

    let id_path = dir.join(format!("{}.identity", a.name));
    let pub_path = dir.join(format!("{}.pub", a.name));
    fs::write(&id_path, id.to_identity_file(suite, pass)?)?;
    chmod_600(&id_path)?;
    fs::write(&pub_path, id.public().to_pub_file(suite))?;

    eprintln!("[\u{2713}] {}   (chmod 600)", id_path.display());
    eprintln!("[\u{2713}] {}", pub_path.display());
    eprintln!(
        "[\u{2713}] Fingerprint: {}",
        id.fingerprint(suite).to_short()
    );
    Ok(())
}

fn cmd_inspect(a: InspectArgs) -> CliResult {
    use vexil_core::envelope::{T_CIPHERTEXT, T_EXPIRY, T_RECIPIENT_FPR};
    let raw = read_ciphertext(&a.io)?;

    if raw.len() >= 10 && &raw[0..5] == b"VEXIL" && matches!(raw[7], 4..=7) {
        let suite = vexil_core::Suite::from_byte(raw[6])?;
        let mode = vexil_core::envelope::Mode::from_byte(raw[7])?;
        println!("mode:       {} (raw binary)", mode.name());
        println!("suite:      0x{:02x} {}", suite.as_byte(), suite.name());
        println!("size:       {} bytes", raw.len());
        return Ok(());
    }

    let armored = to_armored(&raw)?;
    let env = vexil_core::dearmor_auto(&armored)?;
    let recipients = env.get_all(T_RECIPIENT_FPR).count();
    let ct_len = env.get(T_CIPHERTEXT).map(|c| c.len()).unwrap_or(0);
    let expiry = match env.get(T_EXPIRY) {
        Some(b) if b.len() == 8 => {
            let secs = i64::from_be_bytes(b.try_into().unwrap());
            vexil_core::identity::unix_to_rfc3339(secs)
        }
        _ => "none".to_string(),
    };
    println!("mode:       {}", env.mode.name());
    println!(
        "suite:      0x{:02x} {}",
        env.suite.as_byte(),
        env.suite.name()
    );
    if recipients > 0 {
        println!("recipients: {recipients}");
    }
    println!("expiry:     {expiry}");
    println!("ciphertext: {ct_len} bytes");
    Ok(())
}

fn cmd_sign(a: SignArgs) -> CliResult {
    let pass = a.identity_pass.as_deref().map(str::as_bytes);
    let id = Identity::parse_identity_file(&fs::read_to_string(&a.identity)?, pass)?;
    let msg = read_plaintext(&a.io)?;
    let sig = sign_detached(&id, &msg);
    write_output(sig.as_bytes(), &a.io.output)?;
    Ok(())
}

fn cmd_verify(a: VerifyArgs) -> CliResult {
    let signer = PublicIdentity::parse_pub_file(&fs::read_to_string(&a.from)?)?;
    let msg = read_plaintext(&a.io)?;
    let sig = match (&a.signature, &a.signature_file) {
        (Some(s), _) => s.clone(),
        (None, Some(f)) => fs::read_to_string(f)?.trim().to_string(),
        (None, None) => return Err("provide --signature or --signature-file".into()),
    };
    match verify_detached(&signer, &msg, &sig) {
        Ok(()) => {
            eprintln!("[\u{2713}] signature valid");
            Ok(())
        }
        Err(_) => Err("signature verification failed".into()),
    }
}

// --- Post-quantum CLI paths (feature `pq`) -------------------------------

#[cfg(feature = "pq")]
fn pq_keygen(a: &KeygenArgs) -> CliResult {
    use vexil_core::pq_identity::PqIdentity;
    use vexil_core::Suite;
    let dir = vexil_dir(a.out.clone());
    fs::create_dir_all(&dir)?;
    let id = PqIdentity::generate();
    let pass = a.passphrase.as_deref().map(str::as_bytes);
    let id_path = dir.join(format!("{}.identity", a.name));
    let pub_path = dir.join(format!("{}.pub", a.name));
    fs::write(&id_path, id.to_identity_file(pass)?)?;
    chmod_600(&id_path)?;
    fs::write(&pub_path, id.public().to_pub_file())?;
    eprintln!(
        "[\u{2713}] {}   (post-quantum, chmod 600)",
        id_path.display()
    );
    eprintln!("[\u{2713}] {}", pub_path.display());
    eprintln!(
        "[\u{2713}] Fingerprint: {}",
        id.fingerprint(Suite::XKyberChaPoly).to_short()
    );
    Ok(())
}

#[cfg(feature = "pq")]
fn pq_encrypt(a: &EncryptArgs, pt: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    use vexil_core::pq::seal_pq;
    use vexil_core::pq_identity::{seal_multi_pq, seal_signed_pq, PqIdentity, PqPublicIdentity};
    let recips: Vec<PqPublicIdentity> =
        a.to.iter()
            .map(
                |p| -> Result<PqPublicIdentity, Box<dyn std::error::Error>> {
                    Ok(PqPublicIdentity::parse_pub_file(&fs::read_to_string(p)?)?)
                },
            )
            .collect::<Result<_, _>>()?;
    let s = if let Some(idp) = &a.sign_with {
        if recips.len() != 1 {
            return Err("PQ signed mode supports exactly one --to recipient".into());
        }
        let sender = PqIdentity::parse_identity_file(&fs::read_to_string(idp)?, None)?;
        seal_signed_pq(&recips[0], &sender, pt)?
    } else if recips.len() == 1 {
        seal_pq(&recips[0].kem, pt)?
    } else {
        seal_multi_pq(&recips, pt)?
    };
    Ok(s)
}

#[cfg(not(feature = "pq"))]
fn pq_encrypt(_a: &EncryptArgs, _pt: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    Err("this build has no post-quantum support; rebuild with --features pq".into())
}

#[cfg(not(feature = "pq"))]
fn pq_keygen(_a: &KeygenArgs) -> CliResult {
    Err("this build has no post-quantum support; rebuild with --features pq".into())
}

#[cfg(feature = "pq")]
fn pq_decrypt(a: &DecryptArgs, armored: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use vexil_core::envelope::Mode;
    use vexil_core::pq::open_pq;
    use vexil_core::pq_identity::{open_multi_pq, open_signed_pq, PqIdentity, PqPublicIdentity};
    let idp = a
        .identity
        .as_ref()
        .ok_or("post-quantum ciphertext needs --identity (a VEXIL-IDENTITY-v2 file)")?;
    let pass = a.identity_pass.as_deref().map(str::as_bytes);
    let id = PqIdentity::parse_identity_file(&fs::read_to_string(idp)?, pass)?;
    let env = vexil_core::dearmor(armored, Encoding::Base89)?;
    match env.mode {
        Mode::Sealed => Ok(open_pq(&id.kem, armored)?),
        Mode::Signed => {
            let expected = match &a.from {
                Some(p) => Some(PqPublicIdentity::parse_pub_file(&fs::read_to_string(p)?)?),
                None => None,
            };
            Ok(open_signed_pq(&id, armored, expected.as_ref())?.0)
        }
        Mode::MultiRecipient => Ok(open_multi_pq(&id, armored)?),
        _ => Err("unsupported post-quantum envelope mode".into()),
    }
}

#[cfg(not(feature = "pq"))]
fn pq_decrypt(_a: &DecryptArgs, _armored: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Err("this is a post-quantum ciphertext; rebuild with --features pq to open it".into())
}

fn cmd_fingerprint(a: FingerprintArgs) -> CliResult {
    let (path, is_pub) = match (&a.public, &a.identity) {
        (Some(p), _) => (p, true),
        (None, Some(p)) => (p, false),
        (None, None) => return Err("specify --public or --identity".into()),
    };
    let text = fs::read_to_string(path)?;
    if text.trim_start().starts_with("VEXIL-KEY-v2:")
        || text.trim_start().starts_with("VEXIL-IDENTITY-v2:")
    {
        println!("{}", pq_fingerprint(&text, is_pub)?);
        return Ok(());
    }
    let fpr = if is_pub {
        PublicIdentity::parse_pub_file(&text)?.fingerprint(Suite::default())
    } else {
        Identity::parse_identity_file(&text, None)?.fingerprint(Suite::default())
    };
    println!("{}", fpr.to_short());
    Ok(())
}

#[cfg(feature = "pq")]
fn pq_fingerprint(text: &str, is_pub: bool) -> Result<String, Box<dyn std::error::Error>> {
    use vexil_core::pq_identity::{PqIdentity, PqPublicIdentity};
    use vexil_core::Suite;
    let fpr = if is_pub {
        PqPublicIdentity::parse_pub_file(text)?.fingerprint(Suite::XKyberChaPoly)
    } else {
        PqIdentity::parse_identity_file(text, None)?.fingerprint(Suite::XKyberChaPoly)
    };
    Ok(fpr.to_short())
}

#[cfg(not(feature = "pq"))]
fn pq_fingerprint(_text: &str, _is_pub: bool) -> Result<String, Box<dyn std::error::Error>> {
    Err("this is a post-quantum key; rebuild with --features pq".into())
}

fn cmd_list(a: ListArgs) -> CliResult {
    let dir = vexil_dir(a.dir);
    if !dir.exists() {
        eprintln!("no identities: {} does not exist", dir.display());
        return Ok(());
    }
    let mut found = false;
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("identity") {
            found = true;
            let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?");
            match fs::read_to_string(&path)
                .ok()
                .and_then(|t| Identity::parse_identity_file(&t, None).ok())
            {
                Some(id) => println!(
                    "{:<16} {}",
                    name,
                    id.fingerprint(Suite::default()).to_short()
                ),
                None => println!("{:<16} (passphrase-protected)", name),
            }
        }
    }
    if !found {
        eprintln!("no identities in {}", dir.display());
    }
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
