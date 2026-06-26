//! A deterministic stand-in for the libFuzzer targets so the same invariants
//! get exercised on every `cargo test` run, including on platforms where
//! `cargo fuzz` (libFuzzer) is unavailable. The real fuzzers live in `fuzz/`.

use vexil_core::envelope::Envelope;
use vexil_core::{Encoding, Identity, PublicIdentity};

// Small xorshift PRNG so the corpus is reproducible without extra deps.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next() as usize) % (max + 1);
        (0..len).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

#[test]
fn envelope_parser_never_panics_and_round_trips() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for _ in 0..50_000 {
        let data = rng.bytes(64);
        if let Ok(env) = Envelope::parse(&data) {
            assert_eq!(env.serialize(), data, "round-trip mismatch");
            let _ = env.aad();
        }
    }
}

#[test]
fn codec_decoders_never_panic() {
    let mut rng = Rng(0xdead_beef_cafe_babe);
    for _ in 0..50_000 {
        let data = rng.bytes(48);
        for enc in [Encoding::Base89, Encoding::Hex, Encoding::Pem] {
            let s = enc.encode(&data);
            assert_eq!(enc.decode(&s).unwrap(), data);
        }
        if let Ok(s) = std::str::from_utf8(&data) {
            let _ = Encoding::Base89.decode(s);
            let _ = Encoding::Hex.decode(s);
            let _ = Encoding::Pem.decode(s);
        }
    }
}

#[test]
fn identity_parsers_never_panic() {
    let mut rng = Rng(0x0f0f_0f0f_1234_9999);
    for _ in 0..20_000 {
        let data = rng.bytes(96);
        if let Ok(s) = std::str::from_utf8(&data) {
            let _ = Identity::parse_identity_file(s, None);
            let _ = PublicIdentity::parse_pub_file(s);
        }
    }
}

#[test]
fn streaming_pk_parsers_never_panic() {
    // Feed random bytes to all three streaming public-key decrypt paths.
    // They must never panic — only return an Err.
    use vexil_core::stream::{decrypt_stream_multi, decrypt_stream_sealed, decrypt_stream_signed};

    let bob = Identity::generate();
    let mut rng = Rng(0xabcd_ef01_2345_6789);
    let mut out = Vec::new();
    for _ in 0..5_000 {
        let data = rng.bytes(256);
        out.clear();
        let _ = decrypt_stream_sealed(&bob, &mut data.as_slice(), &mut out);
        out.clear();
        let _ = decrypt_stream_signed(&bob, &mut data.as_slice(), &mut out, None);
        out.clear();
        let _ = decrypt_stream_multi(&bob, &mut data.as_slice(), &mut out);
    }
}

#[test]
fn pad_strip_never_panics() {
    use vexil_core::pad::strip;
    let mut rng = Rng(0x1111_2222_3333_4444);
    for _ in 0..50_000 {
        let data = rng.bytes(64);
        let _ = strip(&data); // must not panic on any input
    }
}
