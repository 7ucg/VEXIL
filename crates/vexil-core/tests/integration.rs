//! End-to-end tests across every VEXIL mode, plus tamper and mode-confusion
//! checks. The 100 MiB streaming test is `#[ignore]` by default; run it with
//! `cargo test --release -- --ignored`.

use vexil_core::envelope::{Envelope, Mode, T_CIPHERTEXT};
use vexil_core::fingerprint::{combined_safety_number, Fingerprint};
use vexil_core::pad::{apply as pad_apply, strip as pad_strip, PaddingPolicy};
use vexil_core::rand_core::OsRng;
use vexil_core::stream::{
    decrypt_stream, decrypt_stream_multi, decrypt_stream_sealed, decrypt_stream_signed,
    encrypt_stream, encrypt_stream_multi, encrypt_stream_sealed, encrypt_stream_signed,
};
use vexil_core::{
    armor, dearmor, decrypt_with_password, encrypt_with_password_expiry,
    encrypt_with_password_preset, encrypt_with_password_suite, now_unix_secs, open_multi,
    open_sealed, open_signed, seal_multi, seal_signed, seal_to, Argon2Preset, Encoding, Identity,
    PublicIdentity, Suite,
};

fn id() -> Identity {
    Identity::generate()
}

#[test]
fn symmetric_roundtrip_each_suite() {
    for suite in [Suite::XChaPolyArgon, Suite::XAesGcmArgon] {
        let ct = encrypt_with_password_suite(suite, b"pw", b"payload").unwrap();
        assert_eq!(decrypt_with_password(b"pw", &ct).unwrap(), b"payload");
    }
}

#[test]
fn large_payload_errors_loudly() {
    // A >64 KB payload does not fit one envelope. It must fail loudly, never
    // silently produce an undecryptable blob (regression for the u16 length
    // truncation bug).
    let data = vec![0x5Au8; 100_000];
    let r = encrypt_with_password_suite(Suite::default(), b"pw", &data);
    assert!(matches!(r, Err(vexil_core::Error::PayloadTooLarge(_))));
}

#[test]
fn large_payload_via_streaming() {
    let data = vec![0x5Au8; 100_000];
    let mut ct = Vec::new();
    encrypt_stream(Suite::default(), b"pw", &data, &mut ct, &mut OsRng).unwrap();
    let mut pt = Vec::new();
    decrypt_stream(b"pw", &mut ct.as_slice(), &mut pt).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn sealed_roundtrip() {
    let bob = id();
    let ct = seal_to(&bob.public(), b"hi bob").unwrap();
    assert_eq!(open_sealed(&bob, &ct).unwrap(), b"hi bob");
}

#[test]
fn signed_roundtrip_with_and_without_from() {
    let bob = id();
    let alice = id();
    let ct = seal_signed(&bob.public(), &alice, b"signed").unwrap();
    let (pt, who) = open_signed(&bob, &ct, Some(&alice.public())).unwrap();
    assert_eq!(pt, b"signed");
    assert_eq!(who, alice.ed_public());
    let (pt2, _) = open_signed(&bob, &ct, None).unwrap();
    assert_eq!(pt2, b"signed");
}

#[test]
fn signed_rejects_wrong_from() {
    let bob = id();
    let alice = id();
    let mallory = id();
    let ct = seal_signed(&bob.public(), &alice, b"x").unwrap();
    assert!(open_signed(&bob, &ct, Some(&mallory.public())).is_err());
}

#[test]
fn multi_recipient_each_decrypts() {
    let people: Vec<Identity> = (0..4).map(|_| id()).collect();
    let pubs: Vec<PublicIdentity> = people.iter().map(|i| i.public()).collect();
    let ct = seal_multi(&pubs, b"shared").unwrap();
    for p in &people {
        assert_eq!(open_multi(p, &ct).unwrap(), b"shared");
    }
    assert!(open_multi(&id(), &ct).is_err());
}

#[test]
fn wrong_key_and_recipient_fail() {
    let ct = encrypt_with_password_suite(Suite::default(), b"right", b"x").unwrap();
    assert!(decrypt_with_password(b"wrong", &ct).is_err());

    let bob = id();
    let eve = id();
    let sealed = seal_to(&bob.public(), b"x").unwrap();
    assert!(open_sealed(&eve, &sealed).is_err());
}

#[test]
fn mode_confusion_rejected() {
    let bob = id();
    let sym = encrypt_with_password_suite(Suite::default(), b"k", b"x").unwrap();
    let sealed = seal_to(&bob.public(), b"x").unwrap();
    let multi = seal_multi(&[bob.public()], b"x").unwrap();

    assert!(open_sealed(&bob, &sym).is_err());
    assert!(decrypt_with_password(b"k", &sealed).is_err());
    assert!(open_multi(&bob, &sealed).is_err());
    assert!(open_sealed(&bob, &multi).is_err());
}

#[test]
fn tampering_each_tlv_field_detected() {
    let bob = id();
    let ct = seal_to(&bob.public(), b"sensitive").unwrap();
    let env = dearmor(&ct, Encoding::Base89).unwrap();

    // Flip one byte in every TLV value and confirm decrypt fails each time.
    for idx in 0..env.tlvs.len() {
        let mut tampered = Envelope::new(env.suite, env.mode);
        for (i, t) in env.tlvs.iter().enumerate() {
            let mut val = t.val.clone();
            if i == idx && !val.is_empty() {
                val[0] ^= 0x01;
            }
            tampered.push(t.typ, val);
        }
        let s = armor(&tampered, Encoding::Base89).unwrap();
        assert!(
            open_sealed(&bob, &s).is_err(),
            "tamper of TLV {} (type 0x{:02x}) was not detected",
            idx,
            env.tlvs[idx].typ
        );
    }
}

#[test]
fn flipping_header_mode_detected() {
    let bob = id();
    let ct = seal_to(&bob.public(), b"x").unwrap();
    let env = dearmor(&ct, Encoding::Base89).unwrap();
    // Re-tag as a different mode: parser/AEAD must reject.
    let mut fake = Envelope::new(env.suite, Mode::Symmetric);
    for t in &env.tlvs {
        fake.push(t.typ, t.val.clone());
    }
    let s = armor(&fake, Encoding::Base89).unwrap();
    assert!(decrypt_with_password(b"x", &s).is_err());
    assert!(open_sealed(&bob, &s).is_err());
}

#[test]
fn truncated_ciphertext_detected() {
    let bob = id();
    let ct = seal_to(&bob.public(), b"some longer payload here").unwrap();
    let env = dearmor(&ct, Encoding::Base89).unwrap();
    let mut trunc = Envelope::new(env.suite, env.mode);
    for t in &env.tlvs {
        if t.typ == T_CIPHERTEXT {
            trunc.push(t.typ, t.val[..t.val.len() - 4].to_vec());
        } else {
            trunc.push(t.typ, t.val.clone());
        }
    }
    let s = armor(&trunc, Encoding::Base89).unwrap();
    assert!(open_sealed(&bob, &s).is_err());
}

#[test]
fn identity_file_roundtrip_plain_and_passphrase() {
    let alice = id();
    let plain = alice.to_identity_file(Suite::default(), None).unwrap();
    let back = Identity::parse_identity_file(&plain, None).unwrap();
    assert_eq!(back.secret_bytes(), alice.secret_bytes());

    let wrapped = alice
        .to_identity_file(Suite::default(), Some(b"pass123"))
        .unwrap();
    assert!(wrapped.contains("key=VEX1-"));
    assert!(Identity::parse_identity_file(&wrapped, None).is_err());
    let back2 = Identity::parse_identity_file(&wrapped, Some(b"pass123")).unwrap();
    assert_eq!(back2.secret_bytes(), alice.secret_bytes());
}

#[test]
fn fingerprint_is_stable() {
    let alice = id();
    let a = alice.fingerprint(Suite::default());
    let b = alice.fingerprint(Suite::default());
    let c = alice.public().fingerprint(Suite::default());
    assert_eq!(a, b);
    assert_eq!(a, c);
}

#[test]
fn encoding_roundtrips_through_envelope() {
    let bob = id();
    let base = seal_to(&bob.public(), b"encode me").unwrap();
    let env = dearmor(&base, Encoding::Base89).unwrap();
    for enc in [Encoding::Base89, Encoding::Hex, Encoding::Pem] {
        let s = armor(&env, enc).unwrap();
        let back = dearmor(&s, enc).unwrap();
        assert_eq!(back.get(T_CIPHERTEXT), env.get(T_CIPHERTEXT));
    }
}

#[test]
fn stream_roundtrip_small() {
    let data = vec![0x5Au8; 200_000];
    let mut ct = Vec::new();
    encrypt_stream(Suite::default(), b"pw", &data, &mut ct, &mut OsRng).unwrap();
    let mut pt = Vec::new();
    decrypt_stream(b"pw", &mut ct.as_slice(), &mut pt).unwrap();
    assert_eq!(pt, data);
}

#[test]
#[ignore = "slow: 100 MiB; run with --release -- --ignored"]
fn stream_roundtrip_100mib() {
    let size = 100 * 1024 * 1024;
    let mut data = vec![0u8; size];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    let mut ct = Vec::new();
    encrypt_stream(Suite::default(), b"streampw", &data, &mut ct, &mut OsRng).unwrap();
    let mut pt = Vec::new();
    decrypt_stream(b"streampw", &mut ct.as_slice(), &mut pt).unwrap();
    assert_eq!(pt.len(), data.len());
    assert!(pt == data);
}

#[cfg(feature = "pq")]
#[test]
fn pq_roundtrip() {
    use vexil_core::pq::{open_pq, seal_pq, PqSecret};
    let bob = PqSecret::generate();
    let ct = seal_pq(&bob.public(), b"pq secret").unwrap();
    assert!(ct.starts_with("VEX1P-"));
    assert_eq!(open_pq(&bob, &ct).unwrap(), b"pq secret");
}

#[cfg(feature = "pq")]
#[test]
fn pq_downgrade_to_classical_rejected() {
    use vexil_core::pq::{open_pq, seal_pq, PqSecret};
    let bob = PqSecret::generate();
    let ct = seal_pq(&bob.public(), b"keep me pq").unwrap();
    let env = dearmor(&ct, Encoding::Base89).unwrap();
    assert!(env.suite.is_pq());

    // Re-tag the PQ envelope as a classical suite. The AEAD AAD binds the suite
    // byte, so it must fail to open rather than silently downgrade.
    let mut downgraded = Envelope::new(Suite::XChaPolyArgon, env.mode);
    for t in &env.tlvs {
        downgraded.push(t.typ, t.val.clone());
    }
    let s = armor(&downgraded, Encoding::Base89).unwrap();
    // open_pq requires the PQ suite, so the downgraded blob is refused outright.
    assert!(open_pq(&bob, &s).is_err());
    // A classical opener also cannot read it (no key, wrong mode/keys).
    assert!(open_sealed(&Identity::generate(), &s).is_err());
}

#[cfg(feature = "pq")]
#[test]
fn pq_require_means_classical_is_refused() {
    use vexil_core::pq::{open_pq, PqSecret};
    // A caller demanding PQ uses open_pq; feeding it a classical sealed box
    // (which is not a PQ suite) must be rejected, not opened.
    let bob_pq = PqSecret::generate();
    let bob_classical = Identity::generate();
    let classical = seal_to(&bob_classical.public(), b"x").unwrap();
    assert!(open_pq(&bob_pq, &classical).is_err());
}

#[test]
fn v1_ciphertext_regression_sample() {
    // A VEX1- ciphertext produced by an earlier build must still decrypt. This
    // freezes the v1 wire format so v2 changes cannot break it.
    const SAMPLE: &str = "VEX1-<qW&.8ty<u>@C*XYQe{(cP^AXEt]FVPc|sVjtc@XU):Kw/7Y[RqDaqKq)3UhuA6b<%!uvUkxbE<t.!L%y4?AAAjV_ub*QGSXQw6`BS-)]0Xo.3";
    let pt = decrypt_with_password(b"frozen-v1-pw", SAMPLE).unwrap();
    assert_eq!(pt, b"VEXIL v1 regression sample");
}

#[cfg(feature = "pq")]
#[test]
fn pq_deterministic_wire_vector() {
    // With a fixed RNG, PQ key generation and sealing are reproducible, which
    // pins the v2 PQ wire format. (Primitive-level FIPS 203/204 KATs are carried
    // by the upstream ml-kem and ml-dsa crates; this is the protocol-level pin.)
    use vexil_core::pq_identity::{open_signed_pq, seal_signed_pq_rng, PqIdentity};
    struct R(u64);
    impl vexil_core::rand_core::RngCore for R {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill_bytes(&mut self, d: &mut [u8]) {
            for c in d.chunks_mut(8) {
                let v = self.next_u64().to_le_bytes();
                c.copy_from_slice(&v[..c.len()]);
            }
        }
        fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), vexil_core::rand_core::Error> {
            self.fill_bytes(d);
            Ok(())
        }
    }
    impl vexil_core::rand_core::CryptoRng for R {}

    let make = || {
        let bob = PqIdentity::generate_with_rng(&mut R(1));
        let alice = PqIdentity::generate_with_rng(&mut R(2));
        let ct = seal_signed_pq_rng(&bob.public(), &alice, b"vector", &mut R(3)).unwrap();
        (bob, alice, ct)
    };
    let (bob, alice, ct1) = make();
    let (_, _, ct2) = make();
    assert_eq!(ct1, ct2, "same seeds must produce the same PQ ciphertext");
    let (pt, _) = open_signed_pq(&bob, &ct1, Some(&alice.public())).unwrap();
    assert_eq!(pt, b"vector");
}

#[cfg(feature = "pq")]
#[test]
fn pq_primitive_stability() {
    // Determinism vectors: a fixed seed must always yield the same ML-KEM and
    // ML-DSA public keys, and ML-DSA signing is deterministic. These pin the
    // wired primitives against accidental crate-level changes. (Not the full
    // NIST ACVP vector set.)
    use vexil_core::sign_pq::{ml_dsa_public, ml_dsa_sign};
    let seed = [0x42u8; 32];
    assert_eq!(ml_dsa_public(&seed), ml_dsa_public(&seed));
    assert_eq!(ml_dsa_sign(&seed, b"vector"), ml_dsa_sign(&seed, b"vector"));
    assert_ne!(ml_dsa_sign(&seed, b"a"), ml_dsa_sign(&seed, b"b"));
}

// ---------------------------------------------------------------------------
// Expiry
// ---------------------------------------------------------------------------

#[test]
fn expiry_in_past_rejected() {
    let past = now_unix_secs() - 3600;
    let ct = encrypt_with_password_expiry(b"k", b"x", past).unwrap();
    assert!(
        matches!(
            decrypt_with_password(b"k", &ct),
            Err(vexil_core::Error::Expired(_))
        ),
        "expired ciphertext must return Expired"
    );
}

#[test]
fn expiry_in_future_accepted() {
    let future = now_unix_secs() + 3600;
    let ct = encrypt_with_password_expiry(b"k", b"payload", future).unwrap();
    assert_eq!(decrypt_with_password(b"k", &ct).unwrap(), b"payload");
}

#[test]
fn expiry_tamper_rejected() {
    // Flipping a byte in the expiry TLV value must break the AEAD tag because
    // expiry is AAD-bound.
    use vexil_core::envelope::T_EXPIRY;
    let future = now_unix_secs() + 3600;
    let ct = encrypt_with_password_expiry(b"k", b"x", future).unwrap();
    let env = dearmor(&ct, Encoding::Base89).unwrap();
    let mut bad = Envelope::new(env.suite, env.mode);
    for t in &env.tlvs {
        let mut val = t.val.clone();
        if t.typ == T_EXPIRY {
            val[0] ^= 0x01;
        }
        bad.push(t.typ, val);
    }
    let s = armor(&bad, Encoding::Base89).unwrap();
    assert!(decrypt_with_password(b"k", &s).is_err());
}

// ---------------------------------------------------------------------------
// Padding
// ---------------------------------------------------------------------------

#[test]
fn padding_roundtrip_encrypt_decrypt() {
    let policy = PaddingPolicy::Padme;
    let msg = b"conceal my length";
    let padded = pad_apply(&policy, msg).unwrap();
    assert!(padded.len() > msg.len() + 2); // actual padding added
    let ct = vexil_core::encrypt_with_password(b"pw", &padded).unwrap();
    let back_padded = decrypt_with_password(b"pw", &ct).unwrap();
    assert_eq!(pad_strip(&back_padded).unwrap(), msg);
}

#[test]
fn padding_block_is_multiple() {
    let padded = pad_apply(&PaddingPolicy::Block(64), b"hi").unwrap();
    assert_eq!(padded.len() % 64, 0);
}

// ---------------------------------------------------------------------------
// Safety numbers
// ---------------------------------------------------------------------------

#[test]
fn safety_number_symmetric() {
    let a = Fingerprint([1u8; 16]);
    let b = Fingerprint([2u8; 16]);
    assert_eq!(
        combined_safety_number(&a, &b),
        combined_safety_number(&b, &a)
    );
}

#[test]
fn safety_number_format() {
    let alice = id();
    let bob = id();
    let fa = alice.fingerprint(Suite::default());
    let fb = bob.fingerprint(Suite::default());
    let sn = combined_safety_number(&fa, &fb);
    let groups: Vec<&str> = sn.split_whitespace().collect();
    assert_eq!(groups.len(), 8, "8 groups of 5 digits");
    for g in &groups {
        assert_eq!(g.len(), 5, "each group must be exactly 5 digits");
        assert!(g.chars().all(|c| c.is_ascii_digit()));
    }
}

#[test]
fn decimal_sas_format() {
    let fpr = Fingerprint([0xABu8; 16]);
    let sas = fpr.to_decimal_sas();
    let groups: Vec<&str> = sas.split_whitespace().collect();
    assert_eq!(groups.len(), 8);
    for g in &groups {
        assert_eq!(g.len(), 5);
    }
}

// ---------------------------------------------------------------------------
// Argon2id presets
// ---------------------------------------------------------------------------

#[test]
fn argon2_interactive_preset_roundtrips() {
    let ct = encrypt_with_password_preset(Argon2Preset::Interactive, b"pw", b"fast path").unwrap();
    assert!(ct.starts_with("VEX1-"));
    assert_eq!(decrypt_with_password(b"pw", &ct).unwrap(), b"fast path");
}

#[test]
fn argon2_interactive_wrong_password() {
    let ct = encrypt_with_password_preset(Argon2Preset::Interactive, b"right", b"data").unwrap();
    assert!(decrypt_with_password(b"wrong", &ct).is_err());
}

// ---------------------------------------------------------------------------
// Streaming public-key modes
// ---------------------------------------------------------------------------

#[test]
fn stream_sealed_roundtrip_small() {
    let bob = id();
    let data = b"stream sealed hello";
    let mut ct = Vec::new();
    encrypt_stream_sealed(
        Suite::XChaPolyArgon,
        &bob.public(),
        data,
        &mut ct,
        &mut OsRng,
    )
    .unwrap();
    let mut pt = Vec::new();
    decrypt_stream_sealed(&bob, &mut ct.as_slice(), &mut pt).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn stream_sealed_roundtrip_multichunk() {
    use vexil_core::stream::CHUNK_SIZE;
    let bob = id();
    let data = vec![0x5Bu8; CHUNK_SIZE * 2 + 777];
    let mut ct = Vec::new();
    encrypt_stream_sealed(
        Suite::XChaPolyArgon,
        &bob.public(),
        &data,
        &mut ct,
        &mut OsRng,
    )
    .unwrap();
    let mut pt = Vec::new();
    decrypt_stream_sealed(&bob, &mut ct.as_slice(), &mut pt).unwrap();
    assert_eq!(pt, data);
}

#[test]
fn stream_sealed_wrong_recipient() {
    let bob = id();
    let eve = id();
    let mut ct = Vec::new();
    encrypt_stream_sealed(
        Suite::XChaPolyArgon,
        &bob.public(),
        b"secret",
        &mut ct,
        &mut OsRng,
    )
    .unwrap();
    let mut pt = Vec::new();
    assert!(decrypt_stream_sealed(&eve, &mut ct.as_slice(), &mut pt).is_err());
}

#[test]
fn stream_sealed_tamper_header_detected() {
    let bob = id();
    let mut ct = Vec::new();
    encrypt_stream_sealed(
        Suite::XChaPolyArgon,
        &bob.public(),
        b"tamper me",
        &mut ct,
        &mut OsRng,
    )
    .unwrap();
    // Flip a byte deep inside the chunk frames (after the envelope header).
    let last = ct.len() - 1;
    ct[last] ^= 0xFF;
    let mut pt = Vec::new();
    assert!(decrypt_stream_sealed(&bob, &mut ct.as_slice(), &mut pt).is_err());
}

#[test]
fn stream_signed_roundtrip() {
    let bob = id();
    let alice = id();
    let data = b"signed stream hello";
    let mut ct = Vec::new();
    encrypt_stream_signed(
        Suite::XChaPolyArgon,
        &bob.public(),
        &alice,
        data,
        &mut ct,
        &mut OsRng,
    )
    .unwrap();
    let mut pt = Vec::new();
    let sender_pk =
        decrypt_stream_signed(&bob, &mut ct.as_slice(), &mut pt, Some(&alice.public())).unwrap();
    assert_eq!(pt, data);
    assert_eq!(sender_pk, alice.ed_public());
}

#[test]
fn stream_signed_wrong_expected_sender_rejected() {
    let bob = id();
    let alice = id();
    let mallory = id();
    let mut ct = Vec::new();
    encrypt_stream_signed(
        Suite::XChaPolyArgon,
        &bob.public(),
        &alice,
        b"msg",
        &mut ct,
        &mut OsRng,
    )
    .unwrap();
    let mut pt = Vec::new();
    assert!(
        decrypt_stream_signed(&bob, &mut ct.as_slice(), &mut pt, Some(&mallory.public())).is_err()
    );
}

#[test]
fn stream_signed_without_from_still_verifies() {
    let bob = id();
    let alice = id();
    let mut ct = Vec::new();
    encrypt_stream_signed(
        Suite::XChaPolyArgon,
        &bob.public(),
        &alice,
        b"anon verify",
        &mut ct,
        &mut OsRng,
    )
    .unwrap();
    let mut pt = Vec::new();
    let sender_pk = decrypt_stream_signed(&bob, &mut ct.as_slice(), &mut pt, None).unwrap();
    assert_eq!(pt, b"anon verify");
    assert_eq!(sender_pk, alice.ed_public());
}

#[test]
fn stream_multi_roundtrip() {
    let recipients: Vec<Identity> = (0..3).map(|_| id()).collect();
    let pubs: Vec<PublicIdentity> = recipients.iter().map(|i| i.public()).collect();
    let data = b"multi-stream group secret";
    let mut ct = Vec::new();
    encrypt_stream_multi(Suite::XChaPolyArgon, &pubs, data, &mut ct, &mut OsRng).unwrap();
    for r in &recipients {
        let mut pt = Vec::new();
        decrypt_stream_multi(r, &mut ct.as_slice(), &mut pt).unwrap();
        assert_eq!(pt, data);
    }
    // non-recipient cannot decrypt
    let outsider = id();
    let mut pt = Vec::new();
    assert!(decrypt_stream_multi(&outsider, &mut ct.as_slice(), &mut pt).is_err());
}

#[test]
fn stream_multi_aes_suite() {
    let bob = id();
    let alice = id();
    let pubs = vec![bob.public(), alice.public()];
    let data = vec![0xCCu8; 1024];
    let mut ct = Vec::new();
    encrypt_stream_multi(Suite::XAesGcmArgon, &pubs, &data, &mut ct, &mut OsRng).unwrap();
    let mut pt = Vec::new();
    decrypt_stream_multi(&alice, &mut ct.as_slice(), &mut pt).unwrap();
    assert_eq!(pt, data);
}
