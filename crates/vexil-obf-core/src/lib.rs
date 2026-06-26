mod config;
mod dart;
mod encrypt;
mod error;
mod format;
pub mod runtime;

pub use config::ObfConfig;
pub use error::ObfError;

use base64::engine::general_purpose;
use base64::engine::Engine as _;

pub struct Pass2Output {
    pub js: String,
    pub key: [u8; 32],
    pub build_id: [u8; 16],
    pub node_seed: [u8; 8],
}

pub fn process_pass2(babel_ast_json: &str, config: &ObfConfig) -> Result<Pass2Output, ObfError> {
    let file: serde_json::Value = serde_json::from_str(babel_ast_json)?;
    // @babel/parser returns { type: "File", program: Program { ... } }
    // We encode the Program node directly.
    let ast = file.get("program").cloned().unwrap_or(file);

    let build_id = encrypt::generate_id();
    let node_seed = encrypt::generate_seed();
    let key = encrypt::generate_key();

    let syms = format::SymbolTable::collect(&ast);
    let ast_bytes = format::encode_ast(&ast, &syms, &node_seed)?;

    // Full payload: magic + version + build_id + node_seed + symbol/string tables + ast bytes
    let mut payload = Vec::new();
    payload.extend_from_slice(b"VOBF");
    payload.push(1u8);
    payload.extend_from_slice(&build_id);
    payload.extend_from_slice(&node_seed);
    payload.extend_from_slice(&syms.encode()?);
    payload.extend_from_slice(&ast_bytes);

    let encrypted = encrypt::encrypt(&key, &payload)?;
    let payload_b64 = general_purpose::STANDARD.encode(&encrypted);

    let js = runtime::generate_output(
        &key,
        &build_id,
        &node_seed,
        &payload_b64,
        config.env_fingerprint,
        config.format,
        config.global_name.as_str(),
    );

    Ok(Pass2Output {
        js,
        key,
        build_id,
        node_seed,
    })
}

pub fn obfuscate_dart(source: &str) -> Result<String, ObfError> {
    dart::obfuscate_dart(source)
}
