use vexil_obf_core::{obfuscate_dart, process_pass2, ObfConfig};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct ObfOutput {
    js: String,
    key_b64: String,
    build_id_b64: String,
}

#[wasm_bindgen]
impl ObfOutput {
    #[wasm_bindgen(getter)]
    pub fn js(&self) -> String {
        self.js.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn key_b64(&self) -> String {
        self.key_b64.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn build_id_b64(&self) -> String {
        self.build_id_b64.clone()
    }
}

#[wasm_bindgen]
pub fn obf_process_js(
    babel_ast_json: &str,
    env_fingerprint: bool,
    format: Option<String>,
) -> Result<ObfOutput, JsError> {
    let fmt = match format.as_deref() {
        Some("umd") => vexil_obf_core::runtime::OutputFormat::Umd,
        Some("iife") => vexil_obf_core::runtime::OutputFormat::Iife,
        _ => vexil_obf_core::runtime::OutputFormat::Cjs,
    };
    let config = ObfConfig {
        pass2_enabled: true,
        env_fingerprint,
        format: fmt,
        global_name: String::from("__vx__"),
    };
    let out = process_pass2(babel_ast_json, &config).map_err(|e| JsError::new(&e.to_string()))?;
    use base64::engine::Engine as _;
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(&out.key);
    let build_id_b64 = base64::engine::general_purpose::STANDARD.encode(&out.build_id);
    Ok(ObfOutput {
        js: out.js,
        key_b64,
        build_id_b64,
    })
}

#[wasm_bindgen]
pub fn obf_dart(source: &str) -> Result<String, JsError> {
    obfuscate_dart(source).map_err(|e| JsError::new(&e.to_string()))
}
