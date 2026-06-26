#![no_main]
//! Two invariants: encoding any bytes then decoding returns the originals, and
//! decoding arbitrary text never panics.

use libfuzzer_sys::fuzz_target;
use vexil_core::Encoding;

fuzz_target!(|data: &[u8]| {
    for enc in [Encoding::Base89, Encoding::Hex, Encoding::Pem] {
        let s = enc.encode(data);
        let back = enc.decode(&s).expect("encode output must decode");
        assert_eq!(back, data, "{:?} round-trip mismatch", enc);
    }
    // Arbitrary text fed to the decoders must not panic.
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = Encoding::Base89.decode(s);
        let _ = Encoding::Hex.decode(s);
        let _ = Encoding::Pem.decode(s);
    }
});
