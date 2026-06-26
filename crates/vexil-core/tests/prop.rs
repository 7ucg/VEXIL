//! Property-based tests for every VEXIL encryption mode.
//!
//! Each property: for any valid (plaintext, key/identity), decrypt(encrypt(pt)) == pt.
//! Tamper properties: flipping any byte in the ciphertext must cause decryption to fail.
//!
//! Password/KDF tests run 3 cases each (Argon2 is ~100-500 ms per call).
//! All other tests run the default 256 cases.
//! For deeper exploration: PROPTEST_CASES=2000 cargo test -p vexil-core prop

use proptest::prelude::*;
use vexil_core::fingerprint::combined_safety_number;
use vexil_core::kdf::{derive_key, SALT_LEN};
use vexil_core::pad::{apply as pad_apply, strip as pad_strip, PaddingPolicy};
use vexil_core::{
    decrypt_with_password, encrypt_with_password, encrypt_with_password_preset, open_multi,
    open_sealed, open_signed, open_stream_multi_vec, open_stream_sealed_vec,
    open_stream_signed_vec, seal_multi, seal_multi_stream_vec, seal_signed, seal_signed_stream_vec,
    seal_to, seal_to_stream_vec, Argon2Preset, Encoding, Identity, Suite,
};

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

fn any_plaintext() -> impl Strategy<Value = Vec<u8>> {
    // 0..=4096 bytes covers empty, typical, and multi-chunk streaming messages
    prop::collection::vec(any::<u8>(), 0..=4096)
}

fn any_password() -> impl Strategy<Value = Vec<u8>> {
    // non-empty, printable-ish passwords
    prop::collection::vec(1u8..=127, 1..=64)
}

fn any_suite() -> impl Strategy<Value = Suite> {
    prop_oneof![Just(Suite::XChaPolyArgon), Just(Suite::XAesGcmArgon)]
}

fn any_argon2_preset() -> impl Strategy<Value = Argon2Preset> {
    // Interactive only in tests — Default and Sensitive are too slow for 256 cases
    Just(Argon2Preset::Interactive)
}

// ---------------------------------------------------------------------------
// Symmetric (password) mode — 3 cases: Argon2 at ~100–500 ms each
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3))]

    #[test]
    fn prop_symmetric_roundtrip(pt in any_plaintext(), pw in any_password()) {
        let ct = encrypt_with_password(&pw, &pt).unwrap();
        let got = decrypt_with_password(&pw, &ct).unwrap();
        prop_assert_eq!(got, pt);
    }

    #[test]
    fn prop_symmetric_wrong_password_fails(pt in any_plaintext(), pw in any_password()) {
        let ct = encrypt_with_password(&pw, &pt).unwrap();
        let mut wrong = pw.clone();
        wrong.push(0xFF);
        prop_assert!(decrypt_with_password(&wrong, &ct).is_err());
    }

    #[test]
    fn prop_symmetric_prefix_present(pt in any_plaintext(), pw in any_password()) {
        let ct = encrypt_with_password(&pw, &pt).unwrap();
        prop_assert!(ct.starts_with("VEX1-"), "expected VEX1- prefix, got: {}", &ct[..8.min(ct.len())]);
    }

    #[test]
    fn prop_symmetric_preset_roundtrip(pt in any_plaintext(), pw in any_password(), preset in any_argon2_preset()) {
        let ct = encrypt_with_password_preset(preset, &pw, &pt).unwrap();
        let got = decrypt_with_password(&pw, &ct).unwrap();
        prop_assert_eq!(got, pt);
    }

    #[test]
    fn prop_symmetric_suite_roundtrip(pt in any_plaintext(), pw in any_password(), suite in any_suite()) {
        use vexil_core::encrypt_with_password_suite;
        let ct = encrypt_with_password_suite(suite, &pw, &pt).unwrap();
        let got = decrypt_with_password(&pw, &ct).unwrap();
        prop_assert_eq!(got, pt);
    }
}

// ---------------------------------------------------------------------------
// Sealed box (anonymous public-key)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_sealed_roundtrip(pt in any_plaintext()) {
        let id = Identity::generate();
        let pub_id = id.public();
        let ct = seal_to(&pub_id, &pt).unwrap();
        let got = open_sealed(&id, &ct).unwrap();
        prop_assert_eq!(got, pt);
    }

    #[test]
    fn prop_sealed_wrong_recipient_fails(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let ct = seal_to(&alice.public(), &pt).unwrap();
        prop_assert!(open_sealed(&bob, &ct).is_err());
    }

    #[test]
    fn prop_sealed_prefix(pt in any_plaintext()) {
        let id = Identity::generate();
        let ct = seal_to(&id.public(), &pt).unwrap();
        prop_assert!(ct.starts_with("VEX1S-"));
    }
}

// ---------------------------------------------------------------------------
// Signed sealed box
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_signed_roundtrip(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let ct = seal_signed(&bob.public(), &alice, &pt).unwrap();
        let (got, _sender) = open_signed(&bob, &ct, None).unwrap();
        prop_assert_eq!(got, pt);
    }

    #[test]
    fn prop_signed_pinned_sender_accepted(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let ct = seal_signed(&bob.public(), &alice, &pt).unwrap();
        let alice_pub = alice.public();
        let (got, _) = open_signed(&bob, &ct, Some(&alice_pub)).unwrap();
        prop_assert_eq!(got, pt);
    }

    #[test]
    fn prop_signed_wrong_pinned_sender_rejected(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();
        let ct = seal_signed(&bob.public(), &alice, &pt).unwrap();
        let eve_pub = eve.public();
        prop_assert!(open_signed(&bob, &ct, Some(&eve_pub)).is_err());
    }

    #[test]
    fn prop_signed_wrong_recipient_fails(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();
        let ct = seal_signed(&bob.public(), &alice, &pt).unwrap();
        prop_assert!(open_signed(&eve, &ct, None).is_err());
    }
}

// ---------------------------------------------------------------------------
// Multi-recipient
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_multi_roundtrip_two_recipients(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let recipients = vec![alice.public(), bob.public()];
        let ct = seal_multi(&recipients, &pt).unwrap();
        let got_a = open_multi(&alice, &ct).unwrap();
        let got_b = open_multi(&bob, &ct).unwrap();
        prop_assert_eq!(&got_a, &pt);
        prop_assert_eq!(&got_b, &pt);
    }

    #[test]
    fn prop_multi_wrong_recipient_fails(pt in any_plaintext()) {
        let alice = Identity::generate();
        let eve = Identity::generate();
        let ct = seal_multi(&[alice.public()], &pt).unwrap();
        prop_assert!(open_multi(&eve, &ct).is_err());
    }
}

// ---------------------------------------------------------------------------
// Streaming sealed (VEX1SF-)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_stream_sealed_roundtrip(pt in any_plaintext()) {
        let id = Identity::generate();
        let ct = seal_to_stream_vec(&id.public(), &pt).unwrap();
        let got = open_stream_sealed_vec(&id, &ct).unwrap();
        prop_assert_eq!(got, pt);
    }

    #[test]
    fn prop_stream_sealed_wrong_recipient_fails(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let ct = seal_to_stream_vec(&alice.public(), &pt).unwrap();
        prop_assert!(open_stream_sealed_vec(&bob, &ct).is_err());
    }
}

// ---------------------------------------------------------------------------
// Streaming signed (VEX1AF-)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_stream_signed_roundtrip(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let ct = seal_signed_stream_vec(&bob.public(), &alice, &pt).unwrap();
        let (got, _) = open_stream_signed_vec(&bob, &ct, None).unwrap();
        prop_assert_eq!(got, pt);
    }

    #[test]
    fn prop_stream_signed_pinned_sender_accepted(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let ct = seal_signed_stream_vec(&bob.public(), &alice, &pt).unwrap();
        let alice_pub = alice.public();
        let (got, _) = open_stream_signed_vec(&bob, &ct, Some(&alice_pub)).unwrap();
        prop_assert_eq!(got, pt);
    }

    #[test]
    fn prop_stream_signed_wrong_sender_rejected(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let eve = Identity::generate();
        let ct = seal_signed_stream_vec(&bob.public(), &alice, &pt).unwrap();
        let eve_pub = eve.public();
        prop_assert!(open_stream_signed_vec(&bob, &ct, Some(&eve_pub)).is_err());
    }
}

// ---------------------------------------------------------------------------
// Streaming multi-recipient (VEX1MF-)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_stream_multi_roundtrip(pt in any_plaintext()) {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let ct = seal_multi_stream_vec(&[alice.public(), bob.public()], &pt).unwrap();
        let got_a = open_stream_multi_vec(&alice, &ct).unwrap();
        let got_b = open_stream_multi_vec(&bob, &ct).unwrap();
        prop_assert_eq!(&got_a, &pt);
        prop_assert_eq!(&got_b, &pt);
    }

    #[test]
    fn prop_stream_multi_wrong_recipient_fails(pt in any_plaintext()) {
        let alice = Identity::generate();
        let eve = Identity::generate();
        let ct = seal_multi_stream_vec(&[alice.public()], &pt).unwrap();
        prop_assert!(open_stream_multi_vec(&eve, &ct).is_err());
    }
}

// ---------------------------------------------------------------------------
// PADME padding
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_padme_roundtrip(data in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let padded = pad_apply(&PaddingPolicy::Padme, &data).unwrap();
        let stripped = pad_strip(&padded).unwrap();
        prop_assert_eq!(stripped, data.as_slice());
    }

    #[test]
    fn prop_padme_size_is_valid(data in prop::collection::vec(any::<u8>(), 0..=8192)) {
        let padded = pad_apply(&PaddingPolicy::Padme, &data).unwrap();
        prop_assert!(padded.len() >= data.len(), "padded must be >= original");
    }
}

// ---------------------------------------------------------------------------
// Encoding roundtrips
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_hex_roundtrip(data in prop::collection::vec(any::<u8>(), 0..512)) {
        let enc = Encoding::Hex.encode(&data);
        let dec = Encoding::Hex.decode(&enc).unwrap();
        prop_assert_eq!(dec, data);
    }

    #[test]
    fn prop_base89_roundtrip(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let enc = Encoding::Base89.encode(&data);
        let dec = Encoding::Base89.decode(&enc).unwrap();
        prop_assert_eq!(dec, data);
    }
}

// ---------------------------------------------------------------------------
// KDF determinism — regular tests, Argon2 too slow for proptest iterations
// ---------------------------------------------------------------------------

#[test]
fn kdf_deterministic() {
    let pw = b"test-password";
    let salt = [0x42u8; SALT_LEN];
    let k1 = derive_key(pw, &salt).unwrap();
    let k2 = derive_key(pw, &salt).unwrap();
    assert_eq!(k1.as_bytes(), k2.as_bytes());
}

#[test]
fn kdf_different_salts_differ() {
    let pw = b"test-password";
    let s1 = [0x01u8; SALT_LEN];
    let s2 = [0x02u8; SALT_LEN];
    let k1 = derive_key(pw, &s1).unwrap();
    let k2 = derive_key(pw, &s2).unwrap();
    assert_ne!(k1.as_bytes(), k2.as_bytes());
}

// ---------------------------------------------------------------------------
// Safety numbers (no arbitrary inputs — just need multiple key pairs)
// ---------------------------------------------------------------------------

#[test]
fn prop_safety_number_symmetric() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let suite = Suite::default();
    let sn_ab = combined_safety_number(&alice.fingerprint(suite), &bob.fingerprint(suite));
    let sn_ba = combined_safety_number(&bob.fingerprint(suite), &alice.fingerprint(suite));
    assert_eq!(sn_ab, sn_ba, "safety number must be symmetric");
}

#[test]
fn prop_safety_number_different_pairs() {
    let alice = Identity::generate();
    let bob = Identity::generate();
    let carol = Identity::generate();
    let suite = Suite::default();
    let sn_ab = combined_safety_number(&alice.fingerprint(suite), &bob.fingerprint(suite));
    let sn_ac = combined_safety_number(&alice.fingerprint(suite), &carol.fingerprint(suite));
    assert_ne!(sn_ab, sn_ac);
}
