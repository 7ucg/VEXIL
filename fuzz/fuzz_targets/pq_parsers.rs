#![no_main]
//! Feed arbitrary bytes to the post-quantum key/identity parsers. They must
//! never panic — only return Ok/Err. Where a value parses, re-serializing and
//! re-parsing must reproduce the same bytes (round-trip stability).

use libfuzzer_sys::fuzz_target;
use vexil_core::pq::{Pq1024Public, Pq1024Secret, PqPublic, PqSecret};
use vexil_core::pq_identity::{PqIdentity, PqPublicIdentity};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = PqSecret::from_bytes(data) {
        assert_eq!(
            PqSecret::from_bytes(&s.to_bytes())
                .map(|x| x.to_bytes())
                .ok(),
            Some(s.to_bytes())
        );
    }
    if let Ok(p) = PqPublic::from_bytes(data) {
        assert_eq!(p.to_bytes().is_empty(), false);
    }
    let _ = Pq1024Secret::from_bytes(data);
    let _ = Pq1024Public::from_bytes(data);

    if let Ok(id) = PqIdentity::from_bytes(data) {
        assert_eq!(
            PqIdentity::from_bytes(&id.to_bytes())
                .map(|x| x.to_bytes())
                .ok(),
            Some(id.to_bytes())
        );
    }
    if let Ok(pi) = PqPublicIdentity::from_bytes(data) {
        assert_eq!(pi.to_bytes().is_empty(), false);
    }

    // Identity files (text) must also parse without panicking.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = PqIdentity::parse_identity_file(s, None);
        let _ = PqPublicIdentity::parse_pub_file(s);
    }
});
