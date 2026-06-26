//! Property-based tests for vexil-session.
//!
//! Covers: in-order delivery, out-of-order delivery (up to MAX_SKIP),
//! session serialization roundtrip, and AD binding.

use proptest::prelude::*;
use rand_core::OsRng;
use vexil_core::pq_identity::PqIdentity;
use vexil_session::{new_prekey_bundle, Session};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_session_pair() -> (Session, Session) {
    let alice_id = PqIdentity::generate();
    let bob_id = PqIdentity::generate();
    let (bundle, secrets) = new_prekey_bundle(&bob_id, &mut OsRng);
    let (alice, hs) = Session::initiate(&alice_id, &bundle, &mut OsRng).unwrap();
    let bob = Session::accept(&bob_id, &secrets, &hs).unwrap();
    (alice, bob)
}

// ---------------------------------------------------------------------------
// In-order delivery
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_session_inorder(msgs in prop::collection::vec(
        prop::collection::vec(any::<u8>(), 0..256),
        1..=8,
    )) {
        let (mut alice, mut bob) = make_session_pair();

        for msg in &msgs {
            // Alice → Bob
            let (hdr, ct) = alice.encrypt(msg, &mut OsRng).unwrap();
            let got = bob.decrypt(&hdr, &ct, &mut OsRng).unwrap();
            prop_assert_eq!(&got, msg);
        }

        for msg in &msgs {
            // Bob → Alice (reply)
            let (hdr, ct) = bob.encrypt(msg, &mut OsRng).unwrap();
            let got = alice.decrypt(&hdr, &ct, &mut OsRng).unwrap();
            prop_assert_eq!(&got, msg);
        }
    }
}

// ---------------------------------------------------------------------------
// Out-of-order delivery (small window — stays well within MAX_SKIP)
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_session_out_of_order(
        msgs in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 1..=128),
            2..=6,
        ),
    ) {
        let (mut alice, mut bob) = make_session_pair();

        // Encrypt all messages first, then deliver in reverse order.
        let envelopes: Vec<(Vec<u8>, Vec<u8>)> = msgs
            .iter()
            .map(|m| alice.encrypt(m, &mut OsRng).unwrap())
            .collect();

        for ((hdr, ct), expected) in envelopes.iter().rev().zip(msgs.iter().rev()) {
            let got = bob.decrypt(hdr, ct, &mut OsRng).unwrap();
            prop_assert_eq!(&got, expected);
        }
    }
}

// ---------------------------------------------------------------------------
// Wrong ciphertext always fails
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_tampered_ct_fails(msg in prop::collection::vec(any::<u8>(), 1..=256)) {
        let (mut alice, mut bob) = make_session_pair();
        let (hdr, mut ct) = alice.encrypt(&msg, &mut OsRng).unwrap();
        // Flip the last byte of the ciphertext (AEAD tag)
        *ct.last_mut().unwrap() ^= 0xFF;
        prop_assert!(bob.decrypt(&hdr, &ct, &mut OsRng).is_err());
    }
}

// ---------------------------------------------------------------------------
// Associated-data binding
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_ad_must_match(
        msg in prop::collection::vec(any::<u8>(), 1..=256),
        ad in prop::collection::vec(any::<u8>(), 1..=64),
    ) {
        let (mut alice, mut bob) = make_session_pair();
        let (hdr, ct) = alice.encrypt_with_ad(&msg, &ad, &mut OsRng).unwrap();

        // Correct AD decrypts
        let got = bob.decrypt_with_ad(&hdr, &ct, &ad, &mut OsRng).unwrap();
        prop_assert_eq!(&got, &msg);
    }

    #[test]
    fn prop_wrong_ad_fails(
        msg in prop::collection::vec(any::<u8>(), 1..=256),
        ad in prop::collection::vec(any::<u8>(), 1..=64),
    ) {
        let (mut alice, mut bob) = make_session_pair();
        let (hdr, ct) = alice.encrypt_with_ad(&msg, &ad, &mut OsRng).unwrap();

        let mut wrong_ad = ad.clone();
        wrong_ad.push(0xFF);
        prop_assert!(bob.decrypt_with_ad(&hdr, &ct, &wrong_ad, &mut OsRng).is_err());
    }
}

// ---------------------------------------------------------------------------
// Session serialization roundtrip
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn prop_session_serialization(msgs in prop::collection::vec(
        prop::collection::vec(any::<u8>(), 1..=64),
        1..=4,
    )) {
        let (mut alice, mut bob) = make_session_pair();

        // Advance the ratchet a few steps before serializing
        for msg in &msgs {
            let (hdr, ct) = alice.encrypt(msg, &mut OsRng).unwrap();
            bob.decrypt(&hdr, &ct, &mut OsRng).unwrap();
        }

        // Serialize both sessions
        let alice_bytes = alice.to_bytes();
        let bob_bytes = bob.to_bytes();

        // Restore from bytes
        let mut alice2 = Session::from_bytes(&alice_bytes).unwrap();
        let mut bob2 = Session::from_bytes(&bob_bytes).unwrap();

        // Restored sessions continue correctly
        let test_msg = b"after restore";
        let (hdr, ct) = alice2.encrypt(test_msg, &mut OsRng).unwrap();
        let got = bob2.decrypt(&hdr, &ct, &mut OsRng).unwrap();
        prop_assert_eq!(got.as_slice(), test_msg.as_slice());
    }
}

// ---------------------------------------------------------------------------
// Serialization bytes roundtrip (to_bytes / from_bytes identity)
// ---------------------------------------------------------------------------

#[test]
fn session_bytes_roundtrip_after_messages() {
    let (mut alice, mut bob) = make_session_pair();

    // Exchange a few messages to advance the ratchet state
    for i in 0u8..5 {
        let (h, c) = alice.encrypt(&[i], &mut OsRng).unwrap();
        bob.decrypt(&h, &c, &mut OsRng).unwrap();
        let (h, c) = bob.encrypt(&[i + 100], &mut OsRng).unwrap();
        alice.decrypt(&h, &c, &mut OsRng).unwrap();
    }

    let alice_restored = Session::from_bytes(&alice.to_bytes()).unwrap();
    let bob_restored = Session::from_bytes(&bob.to_bytes()).unwrap();

    // Sanity: they serialize to the same bytes again
    assert_eq!(alice.to_bytes(), alice_restored.to_bytes());
    assert_eq!(bob.to_bytes(), bob_restored.to_bytes());
}
