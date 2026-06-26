//! Deterministic fuzz-smoke: feed random bytes to every session/group parser
//! and assert none of them panic (only return Ok/Err). Runs on every
//! `cargo test`, covering the untrusted-input surface that has no libFuzzer
//! target yet.

use vexil_session::group::{GroupMessage, SenderKeyDistribution};
use vexil_session::{Handshake, Header, PreKeyBundle, PreKeySecrets};

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
fn session_parsers_never_panic() {
    let mut rng = Rng(0xA11CE_5E5510);
    for _ in 0..40_000 {
        let b = rng.bytes(256);
        let _ = Header::from_bytes(&b);
        let _ = Handshake::from_bytes(&b);
        let _ = PreKeyBundle::from_bytes(&b);
        let _ = PreKeySecrets::from_bytes(&b);
        let _ = SenderKeyDistribution::from_bytes(&b);
        let _ = GroupMessage::from_bytes(&b);
    }
}

#[test]
fn parsers_handle_truncated_valid_prefixes() {
    // Take a few plausible lengths around the fixed-field boundaries to hit the
    // off-by-one paths in the length checks.
    for n in [0usize, 1, 32, 40, 52, 66, 67, 69, 70, 71, 255] {
        let b = vec![0u8; n];
        let _ = Header::from_bytes(&b);
        let _ = Handshake::from_bytes(&b);
        let _ = PreKeyBundle::from_bytes(&b);
        let _ = PreKeySecrets::from_bytes(&b);
        let _ = SenderKeyDistribution::from_bytes(&b);
        let _ = GroupMessage::from_bytes(&b);
    }
}
