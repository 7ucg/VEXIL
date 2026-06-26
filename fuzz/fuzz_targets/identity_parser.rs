#![no_main]
//! Identity and pubkey file parsers must reject garbage without panicking.

use libfuzzer_sys::fuzz_target;
use vexil_core::{Identity, PublicIdentity};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Identity::parse_identity_file(s, None);
        let _ = Identity::parse_identity_file(s, Some(b"passphrase"));
        let _ = PublicIdentity::parse_pub_file(s);
    }
});
