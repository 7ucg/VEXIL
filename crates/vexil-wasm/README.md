# vexil-wasm

WebAssembly bridge for VEXIL — use the protocol from Node.js and browsers.

Exposes the full API via `wasm-bindgen`: the at-rest modes (password, sealed
box, signed sealed box, multi-recipient, streaming), identities and
fingerprints, detached signatures, and the live PQ session and groups —
including saving and restoring their state.

## Build

```sh
# Node.js
wasm-pack build crates/vexil-wasm --target nodejs --release
# Browser (ES modules)
wasm-pack build crates/vexil-wasm --target web --release
```

Output lands in `crates/vexil-wasm/pkg/` (`vexil_wasm.js`, `vexil_wasm_bg.wasm`,
`*.d.ts`, `package.json`). On wasm the OS RNG comes from the JS crypto API
(getrandom `js` feature).

## Use (Node.js)

```js
const v = require("./pkg/vexil_wasm.js");
const enc = new TextEncoder(), dec = new TextDecoder();

const ct = v.encrypt_password("pw", enc.encode("secret"));
dec.decode(v.decrypt_password("pw", ct));          // "secret"

const kp = v.keygen();                              // { identity, public }
const sealed = v.seal_to_pub(kp.public, enc.encode("hi"));
dec.decode(v.open_sealed_box(kp.identity, sealed)); // "hi"

const sig = v.sign(kp.identity, enc.encode("file"));
v.verify(kp.public, enc.encode("file"), sig);       // true

// signed sealed box, multi-recipient, fingerprint, streaming
const signed = v.seal_signed_to(kp.public, kp.identity, enc.encode("hi"));
dec.decode(v.open_signed_box(kp.identity, signed, kp.public));
const m = v.seal_to_many([alicePub, bobPub], enc.encode("team"));
v.fingerprint(kp.public);                           // "a1b2-c3d4-..."
const framed = v.encrypt_stream("pw", big);
dec.decode(v.decrypt_stream("pw", framed));
```

## Live session (PQXDH + Double Ratchet) and groups

```js
// Live end-to-end session (post-quantum).
const alice = v.pq_keygen();           // secret identity bytes
const bob = v.pq_keygen();
const kb = v.new_prekey_bundle(bob);   // { bundle, secrets }

const a = v.WasmSession.initiate(alice, kb.bundle);
const first = a.encrypt(enc.encode("hi bob"));
const b = v.WasmSession.accept(bob, kb.secrets, a.handshake);
dec.decode(b.decrypt(first));          // "hi bob"
const reply = b.encrypt(enc.encode("hi alice"));
dec.decode(a.decrypt(reply));          // "hi alice"

// PQ group (sender keys).
const gs = new v.WasmGroupSender();
const gr = v.WasmGroupReceiver.from_distribution(gs.distribution());
dec.decode(gr.decrypt(gs.encrypt(enc.encode("team"))));  // "team"

// Persist and restore across a reload (state holds secrets — store it
// encrypted, e.g. via encrypt_password).
const aState = a.serialize();
const a2 = v.WasmSession.deserialize(aState);
const gsState = gs.serialize();
const gs2 = v.WasmGroupSender.deserialize(gsState);
const grState = gr.serialize();
const gr2 = v.WasmGroupReceiver.deserialize(grState);
```

## Notes

- Verified working in Node: at-rest (incl. signed/multi/streaming), detached
  signatures, fingerprints, the full PQ session (handshake + multi-turn
  ratchet), PQ groups, and serialize/restore of both session and group state.
- `wasm-opt` is disabled in the manifest so the build needs no binaryen
  download; enable it for a smaller artifact in release/CI.
- The wall clock is unavailable on `wasm32-unknown-unknown`, so identity
  `created=` timestamps read as the epoch and the optional `expiry` is not
  enforced on wasm. The crypto itself is unaffected.
