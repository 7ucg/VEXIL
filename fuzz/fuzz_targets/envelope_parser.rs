#![no_main]
//! Feed arbitrary bytes to the envelope parser. It must never panic — only
//! return a structured error or a well-formed `Envelope`. If it parses, the
//! re-serialized form must parse back to the same bytes (round-trip stability).

use libfuzzer_sys::fuzz_target;
use vexil_core::envelope::Envelope;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = Envelope::parse(data) {
        let reser = env.serialize();
        // A parsed envelope must serialize to the exact input it came from.
        assert_eq!(reser, data, "envelope round-trip mismatch");
        let _ = env.aad();
    }
});
