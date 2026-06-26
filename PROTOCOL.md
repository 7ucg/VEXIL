# VEXIL Protocol v1 — wire format specification

This document defines the VEXIL v1 byte format. All multi-byte integers are
big-endian. The protocol is built only on peer-reviewed primitives; the design
work is in the wire format, key management, and encoding.

## 1. Conventions

- `u8`, `u16`, `u32`, `i64`: unsigned/signed big-endian integers.
- `||` denotes concatenation.
- "AEAD" means the suite's authenticated cipher (ChaCha20-Poly1305 or
  AES-256-GCM); both use a 12-byte nonce and a 16-byte tag appended to the
  ciphertext.

## 2. Envelope header

Every envelope (except the streaming chunk frames, see §7) begins with a fixed
10-byte header followed by a TLV body.

| Offset | Size | Field | Value / meaning |
| --- | --- | --- | --- |
| 0 | 5 | `magic` | ASCII `VEXIL` (0x56 45 58 49 4C) |
| 5 | 1 | `version` | `0x01` |
| 6 | 1 | `suite` | algorithm suite, see §3 |
| 7 | 1 | `mode` | operation mode, see §4 |
| 8 | 2 | `body_len` | u16 length of the TLV body that follows |
| 10 | … | `tlv_body` | `body_len` bytes of TLV entries (§5) |

The total envelope length is exactly `10 + body_len`. A parser must reject any
input where this does not hold, where the magic differs, or where the version is
unknown.

## 3. Suites

| Byte | Name | KEX | AEAD | KDF |
| --- | --- | --- | --- | --- |
| 0x01 | `XChaPolyArgon` | X25519 | ChaCha20-Poly1305 | Argon2id |
| 0x02 | `XAesGcmArgon` | X25519 | AES-256-GCM | Argon2id |
| 0x03 | `XKyberChaPoly` | X25519 + ML-KEM-768 | ChaCha20-Poly1305 | Argon2id |
| 0x05 | `XKyber1024ChaPoly` | X25519 + ML-KEM-1024 | ChaCha20-Poly1305 | Argon2id |

The suite is read from the envelope on decrypt, so primitives can be added in a
future version without changing the parser. Suites `0x03` and `0x05` are only
available when the library is built with the `pq` feature. (Suite `0x04` is
reserved for an X-Wing KEM; it is not implemented because the `x-wing` crate
currently requires a pre-release `rand_core`/`dalek` stack incompatible with the
rest of VEXIL.)

## 4. Modes

| Byte | Mode | Prefix | Meaning |
| --- | --- | --- | --- |
| 0 | symmetric | `VEX1-` | password + Argon2id |
| 1 | sealed | `VEX1S-` | anonymous box to a public key |
| 2 | signed | `VEX1A-` | sealed box with an Ed25519 signature |
| 3 | multi-recipient | `VEX1M-` | one payload, many wrapped DEKs |
| 4 | streaming | `VEX1F-` | chunked framing, password key |
| 5 | sealed-stream | `VEX1SF-` | chunked framing, anonymous PK |
| 6 | signed-stream | `VEX1AF-` | chunked framing, signed PK |
| 7 | multi-stream | `VEX1MF-` | chunked framing, many recipients |

A PQ envelope (suite `0x03`) is mode `sealed` and uses the `VEX1P-` prefix.

The text prefix is a human-facing hint only; interpretation is driven by the
`suite` and `mode` bytes. The mode byte is bound into the AEAD's AAD (§6), so it
cannot be swapped without invalidating the tag.

## 5. TLV body

The body is a sequence of entries, each:

```text
type:u8 | length:u16 | value[length]
```

| Type | Name | Length | Used by |
| --- | --- | --- | --- |
| 0x01 | `salt` | 16 | symmetric, streaming |
| 0x02 | `nonce` | 12 | all (base nonce for streaming) |
| 0x03 | `ephemeral_pk` | 32 | sealed, signed, multi, PQ |
| 0x04 | `recipient_fpr` | 16 | multi |
| 0x05 | `recipient_stanza` | 60 | multi |
| 0x06 | `sender_pk` | 32 | signed |
| 0x07 | `signature` | 64 | signed |
| 0x08 | `mlkem_ct` | 1088 | PQ |
| 0x09 | `chunk_count` | 4 | streaming |
| 0x0A | `metadata` | var | optional |
| 0x0B | `expiry` | 8 | optional (i64 unix seconds) |
| 0x0C | `sender_pk_pq` | 1952 | ML-DSA-65 sender key (hybrid signed) |
| 0x0D | `signature_pq` | 3309 | ML-DSA-65 signature (hybrid signed) |
| 0x0E | `kdf_preset` | 1 | Argon2id preset: 0=Interactive, 1=Default, 2=Sensitive |
| 0xFF | `ciphertext` | var | all — AEAD ciphertext + 16-byte tag |

Parsing is a single TLV walk; there are no mode-specific byte branches. After
parsing, each mode validates that the TLV types it needs are present.

## 6. Authentication binding (AAD)

The AEAD seals the payload with Additional Authenticated Data equal to:

```text
AAD = magic || version || suite || mode || (every TLV except 0xFF and 0x07)
```

That is, the header and all metadata TLVs (salt, nonce, ephemeral/sender keys,
recipient stanzas, expiry, …) are bound into the tag. The ciphertext (`0xFF`)
and both signatures (`0x07` Ed25519, `0x0D` ML-DSA) are excluded because they
are produced from the ciphertext after sealing. Any change to suite, mode, salt,
nonce, keys, or stanzas makes decryption fail.

## 7. Mode details

### 7.1 Symmetric (`VEX1-`)

```text
salt  <- random 16 bytes      (TLV 0x01)
nonce <- random 12 bytes      (TLV 0x02)
key    = Argon2id(password, salt)          ; m=64MiB, t=3, p=4, 32-byte out
ct     = AEAD(key, nonce, plaintext, AAD)  (TLV 0xFF)
```

### 7.2 Sealed box (`VEX1S-`)

```text
eph_sk <- random X25519
shared  = X25519(eph_sk, recipient_x_pub)
key     = HKDF-SHA256(salt = eph_pk || recipient_x_pub,
                      ikm  = shared, info = "vexil-sealed-v1")
ct      = AEAD(key, nonce, plaintext, AAD)
```

TLVs: `ephemeral_pk`, `nonce`, `ciphertext`.

### 7.3 Signed box (`VEX1A-`)

Same key agreement as sealed, plus:

```text
sender_pk = sender Ed25519 public key        (TLV 0x06)
signature = Ed25519(sender_sk,
                    eph_pk || recipient_x_pub || ct)   (TLV 0x07)
```

On decrypt the receiver verifies the signature against `sender_pk`. With
`--from`, it additionally checks `sender_pk` equals the expected identity.

### 7.4 Multi-recipient (`VEX1M-`)

```text
dek    <- random 32 bytes
eph_sk <- random X25519                       (shared by all recipients)
ct      = AEAD(dek, nonce, plaintext, AAD)    (TLV 0xFF)

for each recipient R:
    wrap_key = HKDF-SHA256(salt = eph_pk || R_x_pub,
                           ikm  = X25519(eph_sk, R_x_pub),
                           info = "vexil-recipient-v1")
    stanza   = nonce_r(12) || ChaCha20Poly1305(wrap_key, nonce_r, dek, aad=fpr)
    emit  recipient_fpr (TLV 0x04), recipient_stanza (TLV 0x05)
```

On decrypt the receiver computes its own fingerprint, finds the matching
`recipient_fpr`, unwraps the DEK from the paired stanza, then opens `ct`.

### 7.5 Post-quantum hybrid (`VEX1P-`, suite 0x03)

```text
ss1            = X25519(eph_sk, recipient_x_pub)
(kem_ct, ss2)  = ML-KEM-768.Encapsulate(recipient_ml_ek)   (TLV 0x08)
key            = HKDF-SHA256(salt = eph_pk || recipient_x_pub || kem_ct,
                             ikm  = ss1 || ss2, info = "vexil-pq-v1")
ct             = ChaCha20Poly1305(key, nonce, plaintext, AAD)
```

Confidentiality survives if either X25519 or ML-KEM-768 holds.

### 7.6 Streaming (`VEX1F-`)

A streaming file is the serialized metadata envelope (header + `salt`, `nonce`
base, `chunk_count`) followed by chunk frames. The metadata envelope's bytes are
called `H`.

```text
key       = Argon2id(password, salt)
for chunk i in 0..chunk_count:
    nonce_i = base_nonce XOR be64(i)        ; XOR into the low 8 bytes
    final   = (i == chunk_count - 1)
    aad_i   = H || be32(i) || final_flag(1)
    frame_i = be32(len) || AEAD(key, nonce_i, plaintext_i, aad_i)
```

Plaintext chunk size is 64 KiB. The `final_flag` in the AAD prevents truncation:
dropping the real last chunk makes the new last chunk fail to authenticate.

### 7.7 Sealed streaming (`VEX1SF-`, mode 5)

Same chunk framing as §7.6, but the content key comes from an ephemeral X25519
exchange instead of a password:

```text
eph_sk  <- random X25519
shared   = X25519(eph_sk, recipient_x_pub)
key      = HKDF-SHA256(salt = eph_pk || recipient_x_pub,
                       ikm  = shared, info = "vexil-stream-sealed-v1")
```

TLVs in the metadata envelope: `ephemeral_pk`, `nonce`, `chunk_count`.

### 7.8 Signed streaming (`VEX1AF-`, mode 6)

Same key agreement as §7.7, plus an Ed25519 signature over the full concatenated
ciphertext (all chunk frames) bound to the sender's key:

```text
sender_pk  = sender Ed25519 public key          (TLV 0x06)
signature  = Ed25519(sender_sk, eph_pk || recipient_x_pub || all_chunks)
```

The signature is written into the metadata envelope after all chunks are produced.
On decrypt the receiver verifies before returning any plaintext.

### 7.9 Multi-recipient streaming (`VEX1MF-`, mode 7)

Combines §7.7 with the per-recipient DEK wrapping of §7.4:

```text
dek     <- random 32 bytes
key      = dek   (used for all chunk frames)
eph_sk  <- random X25519
for each recipient R:
    wrap_key = HKDF-SHA256(salt = eph_pk || R_x_pub,
                           ikm  = X25519(eph_sk, R_x_pub),
                           info = "vexil-recipient-v1")
    stanza   = nonce_r(12) || ChaCha20Poly1305(wrap_key, nonce_r, dek, aad=fpr)
    emit  recipient_fpr (TLV 0x04), recipient_stanza (TLV 0x05)
```

Any listed recipient can unwrap the DEK and decrypt the stream.

## 8. Identity and key files

ASCII text files. Lines are `key=value`; the first line is the header.

```text
VEXIL-IDENTITY-v1:
suite=0x01
created=2026-06-25T19:00:00Z
fingerprint=a1b2-c3d4-e5f6-7890
key=<base89 of x25519_secret(32) || ed25519_seed(32)>
```

```text
VEXIL-KEY-v1:
suite=0x01
fingerprint=a1b2-c3d4-e5f6-7890
key=<base89 of x25519_public(32) || ed25519_public(32)>
```

When an identity is passphrase-protected, the `key=` value is itself a `VEX1-`
symmetric ciphertext of the 64-byte secret blob (the protocol encrypts its own
key material).

## 9. Fingerprints

```text
fpr = BLAKE2b-128(suite_byte || public_bytes)     ; 16 bytes
```

Displayed as the first 8 bytes in four dash-separated groups of four lowercase
hex digits, e.g. `a1b2-c3d4-e5f6-7890`. The full 16 bytes are used for stanza
matching in multi-recipient mode.

## 10. Encodings

`base89` (default, source-string-safe), `hex`, `raw` (binary), and `pem`
(Base64 wrapped in `-----BEGIN VEXIL CIPHERTEXT-----` / `-----END …-----`).
Encoding affects only transport; the envelope bytes are identical.

## 11. Security claims

- **Confidentiality + integrity** of the payload under the suite's AEAD.
- **Authentication of metadata**: header and all non-ciphertext, non-signature
  TLVs are AAD-bound.
- **Sender authentication** in signed mode via Ed25519.
- **Forward secrecy** for sealed/signed/multi via ephemeral X25519 keys.
- **Multi-recipient privacy**: recipients are identified by fingerprint; the
  payload is encrypted once.
- **Post-quantum confidentiality** (suites `0x03`/`0x05`): the payload key mixes
  the X25519 and ML-KEM shared secrets through HKDF, so it stays secret as long
  as *either* X25519 or ML-KEM holds. This defends against harvest-now,
  decrypt-later: traffic captured today is not exposed by a future quantum break
  of the curve alone.
- **Post-quantum authenticity** (PQ signed mode): the sender signs with both
  Ed25519 and ML-DSA-65; a verifier accepts only if both check, so forging
  requires breaking both schemes.
- **Truncation resistance** for streaming via the final-chunk AAD flag.
- **Downgrade resistance**: the suite byte is AAD-bound and a PQ opener refuses a
  classical envelope, so a PQ ciphertext cannot be re-tagged down to a classical
  suite without failing authentication.

### PQ key agreement (suites 0x03 and 0x05)

```text
ss1            = X25519(eph_sk, recipient_x_pub)
(kem_ct, ss2)  = ML-KEM.Encapsulate(recipient_ml_ek)   ; 768 or 1024
key            = HKDF-SHA256(salt = eph_pk || recipient_x_pub || kem_ct,
                             ikm  = ss1 || ss2, info = "vexil-pq-v1")
```

Both tiers use the same combiner; only the ML-KEM parameter set (and thus the
`mlkem_ct` length: 1088 vs 1568) differs.

### Hybrid signatures (PQ signed mode)

```text
transcript = eph_pk || recipient_x_pub || ciphertext
ed_sig     = Ed25519.Sign(sender_ed_sk, transcript)      ; TLV 0x07
pq_sig     = ML-DSA-65.Sign(sender_mldsa_sk, transcript) ; TLV 0x0D
```

Sender keys travel as TLV `0x06` (Ed25519) and `0x0C` (ML-DSA). A PQ identity
file (`VEXIL-IDENTITY-v2:`) carries the X25519, ML-KEM-768, Ed25519, and ML-DSA
secrets; the public file (`VEXIL-KEY-v2:`) carries their public halves.

## 12. Session protocol (vexil-session)

The session layer adds a live, stateful E2E channel on top of the at-rest
primitives. It provides per-message forward secrecy and post-compromise security
through a PQXDH handshake followed by a Double Ratchet with encrypted headers.

### 12.1 PQXDH handshake

Bob publishes a prekey bundle containing:

- long-term identity (X25519 + ML-KEM-768 + Ed25519 + ML-DSA-65)
- a signed prekey (X25519, signed with both Ed25519 and ML-DSA-65)
- one optional one-time prekey (X25519)

Alice starts a session toward Bob by running:

```text
dh1  = X25519(alice_ed_to_x, bob_spk)
dh2  = X25519(alice_eph,     bob_identity_x)
dh3  = X25519(alice_eph,     bob_spk)
dh4  = X25519(alice_eph,     bob_opk)   ; if one-time prekey present
(kem_ct, ss_kem) = ML-KEM-768.Encapsulate(bob_ml_kem_ek)

ikm  = dh1 || dh2 || dh3 || [dh4] || ss_kem
(sk, hk_alice, nhk_init) = HKDF-SHA256(ikm, label="vexil-pqxdh-v1") ; 96 bytes
```

`sk` is the initial root key. `hk_alice` bootstraps Alice's first sending header
key (= Bob's initial receive `nhkr`). `nhk_init` is Alice's initial next-header
receive key (= Bob's initial sending `nhks`).

### 12.2 Double Ratchet with header encryption

Each `kdf_rk` call expands 96 bytes via HKDF-SHA256:

```text
(rk2, ck, hk2) = HKDF-SHA256(rk, DH_output, label="vexil-ratchet-rk-v1")
```

Session state carries four header keys:

- `hks` — current sending header key (encrypts outgoing headers)
- `nhks` — next sending header key
- `hkr` — current receive header key (tried first when decrypting)
- `nhkr` — next receive header key (tried when hkr fails; triggers DH ratchet)

Every message header is AEAD-encrypted with ChaCha20-Poly1305 using a random
12-byte nonce prepended to the output. The session message wire format is:

```text
u16(enc_hdr_len) || enc_hdr || ciphertext
```

The body AEAD is bound to the encrypted header:

```text
body_aad = enc_hdr || caller_ad
```

Skipped message keys are stored as `(header_key, msg_number, message_key)` tuples
(up to `MAX_SKIP = 1000`). Trial decryption runs against all stored entries before
advancing the ratchet.

### 12.3 Sparse PQ ratchet

A fresh ML-KEM-768 encapsulation is folded into the root key every
`PQ_CHAIN_INTERVAL` sending chains. The receiver keeps a short history of ML-KEM
decapsulation keys to handle in-flight messages from before the rotation.

### 12.4 Session serialization

`Session::to_bytes` / `from_bytes` serializes the full ratchet state (version
byte `0x02`, root key, chain keys, header keys, skipped-key cache, ratchet
public key, PQ key history) so a conversation survives an app restart. Version
`0x01` sessions are rejected as `Malformed`.

### 12.5 Group messaging

`vexil_session::group` implements sender-key ratchets. Each sender has an
independent chain distributed to group members via the multi-recipient at-rest
mode. Member additions/removals trigger a group rekeying. Group state also
serializes with `GroupSession::to_bytes` / `from_bytes`.

## 13. Threat model and non-goals

VEXIL protects data at rest and in transit. It does **not** protect against:

- A compromised endpoint (malware, key theft, a logging keyboard).
- Traffic analysis: ciphertext length leaks plaintext length, and the number of
  recipient stanzas is visible.
- Metadata beyond the payload: recipient fingerprints and the chosen suite/mode
  are in the clear.
- Weak passwords: Argon2id raises the cost of brute force but cannot rescue a
  guessable password.
- Replay at the application layer: VEXIL has an optional `expiry` TLV but no
  built-in nonce/sequence tracking across messages.
- Long-term deniability: signed mode is explicitly non-repudiable.
