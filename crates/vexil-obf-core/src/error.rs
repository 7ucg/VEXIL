use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObfError {
    #[error("JSON parse: {0}")]
    Json(#[from] serde_json::Error),
    #[error("AST encoding: {0}")]
    Encode(String),
    #[error("Encryption: {0}")]
    Encrypt(String),
}
