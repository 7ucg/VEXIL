# vexil-obf

JavaScript obfuscator with an encrypted WASM VM at its core. Code gets compiled to a custom binary AST, AES-256-GCM encrypted, and run inside an embedded interpreter. Not just renamed and shuffled like every other tool.

## How it compares

| Feature | vexil-obf | javascript-obfuscator | obfuscator.io |
|---|:---:|:---:|:---:|
| Encrypted binary AST (not just source transforms) | ✓ | — | — |
| AES-256-GCM authenticated payload | ✓ | — | — |
| Per-build shuffled node type IDs (LCG permutation) | ✓ | — | — |
| Dispatch table VM (no switch/case opcode map) | ✓ | — | — |
| Non-linear 3-part key split (`B[(i*5+rot)%32]`) | ✓ | — | — |
| LCG-stream key binding (XOR before split) | ✓ | — | — |
| Mixed byte encoding (6 forms per build) | ✓ | — | — |
| Decoy arrays interleaved with key material | ✓ | — | — |
| Closure-chain key reconstruction (3-step IIFE) | ✓ | — | — |
| Fake checksum decoy (_vck) interleaved with key derivation | ✓ | — | — |
| BigInt function table hiding direct BigInt() calls | ✓ | — | — |
| LCG constants as split string concatenations | ✓ | — | — |
| String splitting: long strings become double _SD() lookups | ✓ | — | — |
| Anti-hook (toString check before decryption) | ✓ | — | — |
| String array with rotation | ✓ | ✓ | ✓ |
| Computed property hex encoding | ✓ | ✓ | partial |
| Integrity trap (tamper detection) | ✓ | — | — |
| Anti-analysis (webdriver/phantom/debugger) | ✓ | partial | — |
| Node.js + browser (UMD/IIFE/CJS) | ✓ | ✓ | — |
| Vite / Rollup / webpack plugin | ✓ | — | — |
| Dart / Flutter obfuscation | ✓ | — | — |
| Full ES6+ (classes, async, destructuring) | ✓ | ✓ | partial |

Other tools work at the JS source level: rename identifiers, shuffle strings, flatten control flow. Someone with enough time and a deobfuscator can still read the logic. vexil-obf compiles the code to a binary format, encrypts it, and replaces the original with a VM that decrypts and executes at runtime. There is no source to recover without the per-build key.

## How the pipeline works

```
Source JS
  │
  ▼  Pass 1 (Babel)
  ├─ Rename identifiers
  ├─ XOR-encrypt string literals
  └─ Flatten control flow (do-while dispatch)
  │
  ▼  Pass 2 (Rust/WASM)
  ├─ Encode to custom binary AST (37 node types)
  ├─ Per-build LCG Fisher-Yates shuffle of node type IDs
  ├─ AES-256-GCM encrypt with random 256-bit key
  ├─ XOR key with 32-byte LCG stream (Fibonacci-hashed seed)
  ├─ Split stream-bound key: C[i] = K[i] ^ A[i] ^ B[(i*5+rot)%32]
  ├─ Encode key bytes in 6 mixed forms (hex/decimal/XOR/complement/parseInt/charCode)
  ├─ Insert 3 decoy arrays of varying sizes (32, 24, 20 bytes)
  ├─ Build dispatch table: _dt[encoded] = _handlers[_inv[encoded]]
  └─ Embed encrypted payload + VM into output JS
  │
  ▼  Pass 3 (Babel)
  ├─ Rename all VM internals (short random names)
  ├─ String array rotation — _SA[] + _SD() decoder
  │    (lifts parseInt args, charCode strings, BigInt constants into table)
  ├─ Computed properties: obj.prop → obj['\x70\x72\x6f\x70']
  ├─ Hex number encoding
  └─ Integrity trap (XOR checksum of AES payload, hangs if tampered)
```

## Install

Not published to the npm registry. Install directly from the GitHub repo:

```sh
npm install "https://gitpkg.now.sh/7ucg/VEXIL/packages/vexil-obf?main"
```

For bundle-first workflow (Node.js projects bundled for browser):

```sh
npm install "https://gitpkg.now.sh/7ucg/VEXIL/packages/vexil-obf?main" esbuild
```

## API

### Basic

```js
const { obfuscateJs } = require('vexil-obf');

const { code } = await obfuscateJs(source, {
  pass2: true,    // binary AST + AES-256-GCM VM (default: true)
  format: 'cjs',  // 'cjs' | 'umd' | 'iife'
});
```

### Options

```ts
interface ObfOptions {
  pass2?: boolean;              // binary VM encryption (default true)
  format?: 'cjs' | 'umd' | 'iife';  // output module format (default 'cjs')
  envFingerprint?: boolean;     // tie decryption to VOBF_ID env var
  pass1?: {
    renameIdentifiers?: boolean;    // default true
    encryptStrings?: boolean;       // default true
    flattenControlFlow?: boolean;   // default true
  };
  pass3?: boolean | {
    hexNumbers?: boolean;       // default true
    computedProps?: boolean;    // default true
    stringArray?: boolean;      // default true
    integrityTrap?: boolean;    // default true
    selfDefend?: boolean;       // timing trap when devtools open
    debugProtection?: boolean;  // periodic debugger statement
    antiAnalysis?: boolean;     // detect webdriver/phantom/proxy
  };
}
```

### Formats

**CJS** — Node.js CommonJS (default):

```js
// works with require()
const { code } = await obfuscateJs(src, { format: 'cjs' });
```

**UMD** — Node.js + Browser `<script>` + AMD:

```js
const { code } = await obfuscateJs(src, { format: 'umd' });
// In Node.js: module.exports = result (sync)
// In browser: window.__vx__ = result (async, after AES decrypt)
// In AMD: define([], factory)
```

**IIFE** — Browser `<script>` only, no module system:

```js
const { code } = await obfuscateJs(src, { format: 'iife' });
```

### Bundle-first (recommended for browser with dependencies)

For code that uses `require('crypto')`, `require('path')`, etc. — bundle everything first, then obfuscate:

```js
const { bundleAndObfuscate } = require('vexil-obf/bundle');

const { code } = await bundleAndObfuscate({
  entry: 'src/index.js',
  platform: 'browser',   // esbuild resolves all requires for browser
  pass2: true,
  format: 'umd',
});
```

Requires `esbuild` as a peer dependency.

### Vite plugin

```js
// vite.config.js
import { vexilVitePlugin } from 'vexil-obf/vite-plugin';

export default {
  plugins: [vexilVitePlugin({ pass2: true })],
};
```

### Rollup plugin

```js
// rollup.config.js
import { vexilRollupPlugin } from 'vexil-obf/rollup-plugin';

export default {
  plugins: [vexilRollupPlugin({ pass2: true })],
};
```

Output format is detected from Rollup's own `output.format` — no need to set it manually.

### Webpack plugin

```js
// webpack.config.js
const { VexilWebpackPlugin } = require('vexil-obf/webpack-plugin');

module.exports = {
  plugins: [new VexilWebpackPlugin({ pass2: true })],
};
```

Works with webpack 4 and 5. Output format is detected from `output.libraryTarget` (webpack 4) or `output.library.type` (webpack 5). Pass `format` in the options to override.

### CLI

```sh
# obfuscate a file (CJS output by default)
vexil-obf js input.js -o output.js

# UMD output (Node.js + browser <script> + AMD)
vexil-obf js input.js -o output.js --format umd

# IIFE output (browser only, no module system)
vexil-obf js input.js -o output.js --format iife

# skip VM protection (pass 2) — pass 1 + 3 only
vexil-obf js input.js -o output.js --no-pass2

# tie the decryption key to an env var
vexil-obf js input.js -o output.js --env-fingerprint

# obfuscate a Dart/Flutter source file
vexil-obf dart lib/secrets.dart -o lib/secrets.obf.dart
```

### Dart / Flutter

```js
const { obfuscateDart } = require('vexil-obf');

const obfuscated = await obfuscateDart(dartSource);
```

Encrypts string literals with a per-file XOR key and injects a `_vd()` decode helper.

## Integrity and anti-tamper

The binary payload is AES-256-GCM encrypted; authentication is built in. Edit a single byte and decryption throws before any code runs.

Pass3 adds a second layer: an XOR checksum of the first 64 bytes of the payload is embedded at obfuscation time. At startup, the checksum is recomputed and compared. Mismatch → infinite loop.

The VM checks `Function.prototype.toString` before decryption. If it's been replaced (the standard technique for hooking the dispatch function to capture decrypted bytecode mid-execution), the key buffer is zeroed and decryption silently fails.

## Browser compatibility

| Environment | CJS | UMD | IIFE |
|---|:---:|:---:|:---:|
| Node.js (CJS require) | ✓ | ✓ | — |
| Browser `<script>` | — | ✓ | ✓ |
| AMD (RequireJS) | — | ✓ | — |
| Webpack bundle | ✓ | ✓ | ✓ |
| Vite / Rollup build | ✓ | ✓ | ✓ |

UMD and IIFE output includes a `require()` stub for common Node modules (`path`, `events`, `os`, `crypto`) so simple code runs in browser without a bundler. For production code with real dependencies, use the bundle-first approach.

## Benchmark

Measured on a mid-range desktop, full pass1 + pass2 + pass3 pipeline:

| Input | Output | Time |
|---|---|---|
| 512 bytes (config + helpers) | ~30 KB | ~50 ms |
| 1 KB (ApiClient class + crypto) | ~32 KB | ~57 ms |
| 3 KB (combined) | ~58 KB | ~65 ms |

Output is larger because the VM runtime is embedded in every file, and three decoy arrays add ~250 bytes before pass3 encoding. The size cost is the price of binary encryption — identically sized inputs produce different outputs every build due to random keys, LCG seed, and per-build byte encoding salts.

## AI-resistance

Standard obfuscators produce patterns that AI deobfuscators recognize — a `switch` on an opcode field, two XOR arrays `A^B`, a fixed number of operands. vexil-obf breaks those patterns at the structural level, across several independent layers.

**Dispatch table** — the VM's interpreter loop uses a pre-built handler array instead of a switch statement. `_dt[encodedId] = _handlers[_inv[encodedId]]` maps shuffled opcodes to their canonical handlers. There is no `switch(node[0])` to pattern-match against.

**Non-linear 3-part key split** — the AES-256 key is split into three arrays `A`, `B`, `C`, reconstructed as:

```text
K[i] = A[i] ^ B[(i*5+rot)%32] ^ C[i]
```

The multiplier 5 is coprime to 32, so `B[(i*5+rot)%32]` is a permutation of B — every byte of B is used exactly once but in a non-linear order that depends on `rot`. An analyst who XOR's `A^B^C` directly gets the wrong result. The pattern `A.map((b,i)=>b^B[i])` doesn't appear anywhere.

**LCG-stream key binding** — before splitting, the key is XOR'd with a 32-byte stream produced by the same LCG used for opcode shuffling, but started from a Fibonacci-hashed seed. An analyst who recovers `A^B[(i*5+rot)%32]^C` gets the stream-bound key, not the real AES key. They must also discover and reverse the LCG step, which requires:

1. Knowing the stream exists and that it uses a derived (not raw) seed
2. Identifying the two Fibonacci-hash constants
3. Running the LCG for 32 steps and XOR'ing the result back out

After pass3's string array transformation, the BigInt LCG constants are lifted into the rotated string table and appear as `_SD(_SA,N)` calls rather than literal numbers.

**Mixed byte encoding** — each byte in the key arrays is encoded in one of six forms, chosen per-byte per-build by a hash of `(value, position, build_salt)`:

| Form | Example | After pass3 |
|---|---|---|
| Hex literal | `0x4f` | `0x4f` |
| Decimal | `79` | `79` |
| XOR pair | `0x3a^0x1b` | `0x3a^0x1b` |
| Complement | `~0xb0&0xff` | `~0xb0&0xff` |
| String parse | `parseInt("4f",16)` | `parseInt(_SD(_SA,N),16)` |
| Character code | `"O".charCodeAt(0)` | `_SD(_SA,N).charCodeAt(0)` |

The salt changes every build, so the same byte at the same position is encoded differently each time.

**Decoy arrays** — three arrays of 32, 24, and 20 bytes are interleaved with the real key arrays in the declaration block. All five use the same encoding style. An automated tool that collects byte-array declarations now has five candidates to trace, not three, and they're not visually separated.

**Anti-hook** — before decryption, the VM checks that `Function.prototype.toString` returns a normal function signature. Replacing `toString` (a common technique for hooking the dispatch function to capture decrypted bytecode mid-execution) corrupts the key buffer and silently fails decryption.

All these features are generated in Rust/WASM and embedded before pass3 processes the output. By the time the file is readable JS, the structural patterns are already gone.

## Security model

- **Key**: 256-bit, generated fresh each build, not stored anywhere
- **LCG binding**: key is XOR'd with a per-build stream before being split, so extracting the three split arrays does not directly yield the AES key
- **Non-linear split**: `C[i] = K[i] ^ A[i] ^ B[(i*5+rot)%32]` — reconstruction requires knowing both `rot` and the non-linear B index
- **Mixed encoding**: key bytes written in 6 different forms; encoding choice is salted per-build, so the same source produces different-looking arrays each time
- **Per-build entropy**: LCG seed (8 bytes random) shuffles the binary AST node type table — two builds of the same source produce structurally different bytecode
- **Cipher**: AES-256-GCM — authenticated encryption, integrity built in
- **Decoys**: three unused arrays of varying size, same encoding style, interleaved with the real arrays
- **Dispatch table**: VM opcode dispatch uses an indirect handler array, not a switch statement. Opcode-to-handler mapping is hidden behind per-build LCG-shuffled indirection
- **Anti-hook**: `Function.prototype.toString` check before decryption; hook detection zeroes the key

This is not a security boundary for data at rest. The key is embedded in the output; a determined reverse engineer can extract it. The goal is raising the cost of automated extraction and AI-assisted analysis, not military-grade protection.
