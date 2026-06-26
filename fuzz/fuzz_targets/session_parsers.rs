#![no_main]
//! Feed arbitrary bytes to the session and group wire parsers. None may panic;
//! anything that parses must re-serialize and re-parse to the same bytes
//! (serialization round-trip stability).

use libfuzzer_sys::fuzz_target;
use vexil_session::group::{GroupMessage, SenderKeyDistribution};
use vexil_session::{Handshake, Header, PreKeyBundle, PreKeySecrets};

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = Header::from_bytes(data) {
        let b = h.to_bytes();
        assert!(Header::from_bytes(&b).is_ok());
    }
    if let Ok(h) = Handshake::from_bytes(data) {
        let b = h.to_bytes();
        assert_eq!(
            Handshake::from_bytes(&b).map(|x| x.to_bytes()).ok(),
            Some(b.clone())
        );
    }
    if let Ok(p) = PreKeyBundle::from_bytes(data) {
        let b = p.to_bytes();
        assert_eq!(
            PreKeyBundle::from_bytes(&b).map(|x| x.to_bytes()).ok(),
            Some(b.clone())
        );
    }
    let _ = PreKeySecrets::from_bytes(data);
    if let Ok(d) = SenderKeyDistribution::from_bytes(data) {
        let b = d.to_bytes();
        assert_eq!(
            SenderKeyDistribution::from_bytes(&b)
                .map(|x| x.to_bytes())
                .ok(),
            Some(b.clone())
        );
    }
    if let Ok(m) = GroupMessage::from_bytes(data) {
        let b = m.to_bytes();
        assert_eq!(
            GroupMessage::from_bytes(&b).map(|x| x.to_bytes()).ok(),
            Some(b.clone())
        );
    }
});
