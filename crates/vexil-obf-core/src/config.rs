pub struct ObfConfig {
    pub pass2_enabled: bool,
    /// If true, mix process.env.VOBF_ID into the key at runtime.
    pub env_fingerprint: bool,
    pub format: crate::runtime::OutputFormat,
    pub global_name: String,
    /// If true (default), emit macro-op aggregation opcodes (220-225) for common 2-node patterns.
    pub macro_ops: bool,
}

impl Default for ObfConfig {
    fn default() -> Self {
        Self {
            pass2_enabled: true,
            env_fingerprint: false,
            format: crate::runtime::OutputFormat::Cjs,
            global_name: String::from("__vx__"),
            macro_ops: true,
        }
    }
}
