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

    // Feature 1: derive jump_key from seed (stored in header, read by vm.js after decrypt)
    let jump_key: u16 = (node_seed[0] as u16) ^ ((node_seed[1] as u16) << 8) ^ 0x5A5A;
    // Feature 4: scope_key from seed bytes 4..8; XOR all symbol strings with low byte
    let scope_key: u32 =
        u32::from_le_bytes([node_seed[4], node_seed[5], node_seed[6], node_seed[7]]);
    let scope_key_byte = (scope_key & 0xFF) as u8;

    let syms = format::SymbolTable::collect(&ast);
    // Feature 2+3: decoy opcodes and stateful opcodes injected during AST encoding
    // Feature 5: macro-op aggregation (default enabled via config.macro_ops)
    let ast_bytes = format::encode_ast(&ast, &syms, &node_seed, config.macro_ops)?;

    // Full payload: magic(4) + version(1) + build_id(16) + node_seed(8) +
    //   feature_header: jump_key(2) + scope_key(4) +
    //   symbol/string tables (symbols XOR'd with scope_key_byte) + ast bytes
    let mut payload = Vec::new();
    payload.extend_from_slice(b"VOBF");
    payload.push(1u8);
    payload.extend_from_slice(&build_id);
    payload.extend_from_slice(&node_seed);
    // Feature header (read by vm.js after AES-GCM decrypt, before symbol table)
    payload.extend_from_slice(&jump_key.to_le_bytes());
    payload.extend_from_slice(&scope_key.to_le_bytes());
    // Symbol/string tables: symbols XOR-encoded with scope_key_byte
    payload.extend_from_slice(&syms.encode_with_scope_key(scope_key_byte)?);
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
