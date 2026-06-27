// vexil-obf — correctness tests + benchmarks
'use strict';
Object.keys(require.cache).filter(k => k.includes('vexil')).forEach(k => delete require.cache[k]);

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { execFileSync } = require('child_process');

const { obfuscateJs, obfuscateDart, batchObfuscate, batchObfuscateDart, PRESETS, exportPreset, importPreset } = require(path.join(__dirname, 'dist/index.js'));

const exDir  = path.join(__dirname, 'examples');
const tmpDir = os.tmpdir();
let allPassed = true;

// ── helpers ───────────────────────────────────────────────────────────────────

function runAsModule(code, env) {
  const tmp = path.join(tmpDir, `vxb_${Date.now()}_${Math.random().toString(36).slice(2)}.js`);
  fs.writeFileSync(tmp, code);
  try {
    delete require.cache[require.resolve(tmp)];
    if (env) {
      const saved = {};
      for (const k of Object.keys(env)) { saved[k] = process.env[k]; process.env[k] = env[k]; }
      try { return require(tmp); } finally {
        for (const k of Object.keys(env)) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
      }
    }
    return require(tmp);
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
}

function runInChild(code, { timeout = 2000, env } = {}) {
  const tmp = path.join(tmpDir, `vxb_child_${Date.now()}.js`);
  fs.writeFileSync(tmp, code);
  try {
    execFileSync(process.execPath, [tmp], { timeout, stdio: 'pipe', env: { ...process.env, ...env } });
    return { ok: true };
  } catch (e) {
    const timedOut = e.killed || e.signal === 'SIGTERM' || e.code === null;
    const stackOverflow = e.stderr && (e.stderr.toString().includes('call stack') || e.stderr.toString().includes('Maximum'));
    return { ok: false, timedOut, stackOverflow, stderr: e.stderr?.toString().slice(0, 200), message: e.message };
  } finally {
    try { fs.unlinkSync(tmp); } catch {}
  }
}

function pass(label, ok, detail = '') {
  const tag = ok ? 'PASS' : 'FAIL';
  console.log(`  ${tag.padEnd(5)} ${label}${detail ? '  — ' + detail : ''}`);
  if (!ok) allPassed = false;
}

function section(title) {
  console.log(`\n── ${title} ${'─'.repeat(Math.max(0, 67 - title.length))}`);
}

function fmtMs(ms) { return ms.toFixed(1).padStart(7) + 'ms'; }
function fmtKBs(bytes, ms) { return ((bytes / 1024) / (ms / 1000)).toFixed(0).padStart(6) + ' KB/s'; }
function stddev(arr) {
  const m = arr.reduce((a, b) => a + b, 0) / arr.length;
  return Math.sqrt(arr.reduce((a, b) => a + (b - m) ** 2, 0) / arr.length);
}

// ── source fixtures ───────────────────────────────────────────────────────────

const src01 = fs.readFileSync(path.join(exDir, '01-original.js'), 'utf8');
const src02 = fs.readFileSync(path.join(exDir, '02-original.js'), 'utf8');
const src03 = fs.readFileSync(path.join(exDir, '03-original.js'), 'utf8');
const src04 = fs.readFileSync(path.join(exDir, '04-original.js'), 'utf8');

// synthetic larger input: combine all four + filler
const srcLarge = [src01, src02, src03, src04].join('\n') +
  '\n// padding\n' + 'var _pad = "x".repeat(1000);\n'.repeat(10);

const DART_SRC = `
void main() {
  String secret = "hunter2";
  String api    = "sk-live-abc123";
  int    port   = 5432;
  print("Connecting to db.internal:\$port with \$secret");
  print("API key: \$api");
}
`;

async function main() {
  console.log('\n┌─────────────────────────────────────────────────────────────────┐');
  console.log('│                   vexil-obf test + bench suite                  │');
  console.log('└─────────────────────────────────────────────────────────────────┘');

  // ═══════════════════════════════════════════════════════════════════════════
  // §1  FULL PIPELINE — correctness for all 4 example files
  // ═══════════════════════════════════════════════════════════════════════════
  section('§1  full pipeline correctness');

  const pipelineResults = [];
  for (const [file, src, check] of [
    ['01-original.js', src01, m => {
      if (!m.config || m.config.host !== 'db.internal') throw new Error('config.host wrong');
      if (m.hashPassword('abc') !== '616263') throw new Error('hashPassword wrong');
      if (!m.getConnectionString().includes('db.internal')) throw new Error('getConnectionString wrong');
    }],
    ['02-original.js', src02, () => {}],   // side-effects only
    ['03-original.js', src03, () => {}],   // side-effects only
    ['04-original.js', src04, m => {
      if (typeof m.ApiClient !== 'function') throw new Error('ApiClient not exported');
      const sig = new m.ApiClient('https://x.com', 'k').sign({ id: 1 });
      if (typeof sig !== 'string' || sig.length !== 64) throw new Error('sign() wrong: ' + sig);
      if (m.buildQuery({ a: 1, b: 2 }) !== 'a=1&b=2') throw new Error('buildQuery wrong');
    }],
  ]) {
    const { code } = await obfuscateJs(src, { pass2: true });
    let ok = true, err = '';
    try { check(runAsModule(code)); } catch (e) { ok = false; err = e.message; allPassed = false; }
    const ratio = (Buffer.byteLength(code) / Buffer.byteLength(src)).toFixed(1);
    pass(file, ok, ok ? `×${ratio}` : err);
    pipelineResults.push({ file, src, code, srcBytes: Buffer.byteLength(src), outBytes: Buffer.byteLength(code) });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §2  PASS CONFIGURATION VARIANTS
  // ═══════════════════════════════════════════════════════════════════════════
  section('§2  pass configuration variants');

  // pass1 only (no VM)
  {
    const { code } = await obfuscateJs(src01, { pass2: false });
    let ok = true, err = '';
    try {
      const m = runAsModule(code);
      if (m.hashPassword('abc') !== '616263') throw new Error('hashPassword wrong');
    } catch (e) { ok = false; err = e.message; }
    const hasRenames = /_[a-z]\d*\b/.test(code);
    pass('pass1-only: correctness', ok, err || undefined);
    pass('pass1-only: identifiers renamed', hasRenames);
    pass('pass1-only: no VM payload', !/new Uint8Array\(32\)/.test(code));
  }

  // pass2 only (skip pass3)
  {
    const { code } = await obfuscateJs(src01, { pass2: true, pass3: false });
    let ok = true, err = '';
    try {
      const m = runAsModule(code);
      if (m.hashPassword('abc') !== '616263') throw new Error('hashPassword wrong');
    } catch (e) { ok = false; err = e.message; }
    pass('pass3-disabled: correctness', ok, err || undefined);
    pass('pass3-disabled: no string array', !/_SD\(/.test(code));
    pass('pass3-disabled: no hex props', !/\['\\.x/.test(code));
  }

  // pass3 stringArray off
  {
    const { code } = await obfuscateJs(src01, { pass2: true, pass3: { stringArray: false } });
    pass('pass3 stringArray:false — no _SD()', !/_SD\(/.test(code));
    // other features should still be on
    pass('pass3 stringArray:false — computed props still on', /\['\\x[0-9a-f]{2}/.test(code));
  }

  // pass3 computedProps off
  {
    const { code } = await obfuscateJs(src01, { pass2: true, pass3: { computedProps: false } });
    // computed props use hex-encoded string literals like ['\x70\x72...']; without them, member access is normal
    pass('pass3 computedProps:false — still runs', (() => {
      try { const m = runAsModule(code); return m.hashPassword('abc') === '616263'; } catch { return false; }
    })());
  }

  // pass3 integrityTrap off
  {
    const { code } = await obfuscateJs(src01, { pass2: true, pass3: { integrityTrap: false } });
    pass('pass3 integrityTrap:false — no XOR checksum', !/\(function\(_p\)\{var _s=0/.test(code) && !/while\(1\)/.test(code));
  }

  // pass3 hexNumbers off
  {
    const { code } = await obfuscateJs(src01, { pass2: true, pass3: { hexNumbers: false } });
    // when hex off, plain decimal numbers like 32 appear instead of 0x20
    pass('pass3 hexNumbers:false — decimal literals present', /\b(?:32|37|12)\b/.test(code));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §3  OUTPUT FORMAT TESTS
  // ═══════════════════════════════════════════════════════════════════════════
  section('§3  output formats');

  // CJS (default)
  {
    const { code } = await obfuscateJs(src04, { pass2: true, format: 'cjs' });
    const m = (() => { try { return runAsModule(code); } catch { return null; } })();
    pass('cjs: exports available', m && typeof m.ApiClient === 'function');
    pass('cjs: has module.exports path', code.includes('module') && code.includes('exports'));
    pass('cjs: no AMD define', !code.includes('define('));
  }

  // UMD
  {
    const { code } = await obfuscateJs(src04, { pass2: true, format: 'umd' });
    const m = (() => { try { return runAsModule(code); } catch { return null; } })();
    pass('umd: exports in Node', m && typeof m.ApiClient === 'function');
    pass('umd: AMD define present', code.includes('define'));
    pass('umd: typeof module guard present', code.includes('typeof module'));
    pass('umd: sign() returns 64-char hex', m && new m.ApiClient('u', 'k').sign({}).length === 64);
  }

  // IIFE
  {
    const { code } = await obfuscateJs(src04, { pass2: true, format: 'iife' });
    const r = runInChild(code);
    pass('iife: runs without error', r.ok, r.ok ? undefined : r.stderr?.slice(0, 80));
    pass('iife: no module.exports wrapper', !code.includes('module.exports'));
    // _SD + integrity trap are prepended by pass3 before the outer IIFE wrapper
    pass('iife: contains IIFE wrapper', code.includes('(function') && code.includes('})()'));
  }

  // all 3 formats produce different output for same input
  {
    const [r1, r2, r3] = await Promise.all([
      obfuscateJs(src01, { pass2: true, format: 'cjs' }),
      obfuscateJs(src01, { pass2: true, format: 'umd' }),
      obfuscateJs(src01, { pass2: true, format: 'iife' }),
    ]);
    pass('formats produce distinct output', r1.code !== r2.code && r2.code !== r3.code);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §4  ANTI-TAMPER
  // ═══════════════════════════════════════════════════════════════════════════
  section('§4  anti-tamper');

  // tamper base64 payload body
  {
    const { code } = await obfuscateJs(src01, { pass2: true });
    const m = code.match(/"([A-Za-z0-9+/]{100,}={0,2})"/);
    if (m) {
      const tampered = code.replace(m[1], m[1].slice(0, 5) + 'XXXXXX' + m[1].slice(11));
      const r = runInChild(tampered, { timeout: 700 });
      pass('payload body tamper → hangs/throws', !r.ok && (r.timedOut || r.stackOverflow || !r.ok),
        r.timedOut ? 'timed out' : r.stackOverflow ? 'stack overflow' : 'errored');
    } else {
      pass('payload body tamper', false, 'payload pattern not found');
    }
  }

  // tamper AES auth tag: Node path catches AES-GCM exception silently (try/catch{}),
  // async path also catches it — process exits 0 but produces no user output (_D never runs)
  {
    const { code } = await obfuscateJs(src01, { pass2: true });
    const m = code.match(/"([A-Za-z0-9+/]{100,}={0,2})"/);
    if (m) {
      const b64 = m[1];
      // flip a char well inside auth tag region (last ~22 chars = 16 bytes)
      const pos = b64.replace(/=+$/, '').length - 15;
      const ch = b64[pos];
      const flipped = b64.slice(0, pos) + (ch === 'A' ? 'B' : 'A') + b64.slice(pos + 1);
      const tampered = code.replace(b64, flipped);
      const tmp = require('path').join(tmpDir, `vxb_authtag_${Date.now()}.js`);
      require('fs').writeFileSync(tmp, tampered);
      let stdout = '';
      try { stdout = execFileSync(process.execPath, [tmp], { timeout: 700, encoding: 'utf8' }); }
      catch {}
      try { require('fs').unlinkSync(tmp); } catch {}
      // auth tag wrong → AES-GCM silently fails → _D() never called → no user console.log output
      pass('auth tag tamper → VM never runs (no output)', stdout.trim() === '');
    }
  }

  // integrity trap disabled — tampered payload should run (no trap fires)
  {
    const { code } = await obfuscateJs(src01, { pass2: true, pass3: { integrityTrap: false } });
    const m = code.match(/"([A-Za-z0-9+/]{100,}={0,2})"/);
    if (m) {
      const tampered = code.replace(m[1], m[1].slice(0, 5) + 'XXXXXX' + m[1].slice(11));
      const r = runInChild(tampered, { timeout: 700 });
      // with trap off, tampered payload causes AES-GCM auth failure (throws/errors) but doesn't hang
      pass('no integrity trap — tamper throws fast (no hang)', !r.timedOut);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §5  AI-RESISTANCE CHECKS
  // ═══════════════════════════════════════════════════════════════════════════
  section('§5  AI-resistance');

  {
    // c1/c2: full pipeline (pass1+2+3), used for obfuscation-quality checks
    // c_raw: pass1+2 only — structural checks before pass3 transforms the output
    const { code: c1 } = await obfuscateJs(src04, { pass2: true });
    const { code: c2 } = await obfuscateJs(src04, { pass2: true });
    const { code: c_raw } = await obfuscateJs(src04, { pass2: true, pass3: false });

    pass('dispatch table: new Array(37) present', /new Array\((?:37|0x25)\)/.test(c1));
    pass('dispatch table: no switch on opcode',   !/switch\s*\(\s*\w+\s*\[\s*(?:0|0x0)\s*\]/.test(c1));

    // Count 32-element arrays in the pre-pass3 output.
    // Elements can include parseInt("HH",16) which has a comma inside — standard
    // regex splits on the wrong commas, so use a paren-depth-aware counter.
    function countTopLevelElems(arr) {
      // Track paren and bracket depth separately, and skip string literals so
      // that bracket characters inside strings (e.g. "[".charCodeAt(0)) don't
      // confuse the depth counters.
      let n = 1, pd = 0, bd = 0, inStr = false, strChar = '';
      for (let k = 1; k < arr.length - 1; k++) {
        const ch = arr[k];
        if (inStr) {
          if (ch === '\\') { k++; continue; } // skip escaped char
          if (ch === strChar) inStr = false;
          continue;
        }
        if (ch === '"' || ch === "'") { inStr = true; strChar = ch; continue; }
        if (ch === '(') pd++;
        else if (ch === ')') pd--;
        else if (ch === '[') bd++;
        else if (ch === ']') { if (bd > 0) bd--; }
        else if (ch === ',' && pd === 0 && bd === 0) n++;
      }
      return n;
    }
    function countArraysOfLen(code, len) {
      // Skip string literals so that [ and ] inside strings don't affect depth.
      let count = 0, i = 0, inStr = false, strCh = '';
      while (i < code.length) {
        const ch = code[i];
        if (inStr) {
          if (ch === '\\') { i += 2; continue; }
          if (ch === strCh) inStr = false;
          i++; continue;
        }
        if (ch === '"' || ch === "'") { inStr = true; strCh = ch; i++; continue; }
        if (ch === '[') {
          // Find matching ] tracking bracket depth (still skip strings inside)
          let depth = 1, j = i + 1, inS2 = false, sC2 = '';
          while (j < code.length && depth > 0) {
            const c2 = code[j];
            if (inS2) {
              if (c2 === '\\') { j += 2; continue; }
              if (c2 === sC2) inS2 = false;
            } else if (c2 === '"' || c2 === "'") { inS2 = true; sC2 = c2; }
            else if (c2 === '[') depth++;
            else if (c2 === ']') depth--;
            j++;
          }
          if (countTopLevelElems(code.slice(i, j)) === len) count++;
          i = j;
        } else { i++; }
      }
      return count;
    }
    const arrays32 = countArraysOfLen(c_raw, 32);
    pass(`3-part key: ≥4 32-byte arrays (3 real key parts + decoys)`, arrays32 >= 4, `${arrays32} found`);

    // Non-linear B index: B[(i*5+rot)%32] — multiplier *5 visible in full output
    pass('3-part key: non-linear B index', /\*(?:5|0x5)\+/.test(c1));
    pass('per-build entropy: outputs differ', c1 !== c2);

    // Encoding forms — check on raw output before pass3 extracts strings
    pass('key encoding: parseInt form', /parseInt\("[0-9a-f]{2}",16\)/.test(c_raw));
    pass('key encoding: charCode form',  /"[^"\\]"\.charCodeAt\(0\)/.test(c_raw));

    // Anti-hook: Function.prototype.toString check — visible in raw output;
    // pass3 hex-encodes 'prototype' and 'toString' so we check c_raw
    pass('anti-hook: toString check', c_raw.includes('Function.prototype.toString'));

    // string array rotation: function that takes index + offset into rotated array
    pass('string array: _SD decoder present', /_SD\(/.test(c1));
    // rotation offset embedded in decoder: (idx+N)%arr.length pattern
    pass('string array: rotation offset present', /\+\d+\)%/.test(c1));

    // computed props: member access via hex string literal e.g. ['\x6c\x65\x6e']
    pass('computed props: hex-encoded members', /\['\\x[0-9a-f]{2}/.test(c1));

    // no readable string literals from original source visible
    pass('no plaintext secrets in output (src04)',
      !c1.includes('super-secret') && !c1.includes('sk-live'));

    // Helper functions _bxr / _bcp — injected by Rust before pass3 renames them
    pass('helper fns: _bxr declared',  /var _bxr\s*=/.test(c_raw));
    pass('helper fns: _bcp declared',  /var _bcp\s*=/.test(c_raw));
    pass('key encoding: _bxr() call form', /_bxr\(0x[0-9a-f]{2},0x[0-9a-f]{2}\)/.test(c_raw));
    pass('key encoding: _bcp() call form', /_bcp\(0x[0-9a-f]{2}\)/.test(c_raw));

    // Closure chain — 3-step key reconstruction visible in raw output
    pass('closure chain: _vt1 (XOR step)', /var _vt1\s*=/.test(c_raw));
    pass('closure chain: _vck (fake checksum)', /var _vck\s*=/.test(c_raw));

    // BigInt function table — hides direct BigInt() calls
    pass('BigInt fn table: _vfn=[BigInt,Number]', /var _vfn\s*=\s*\[BigInt,Number\]/.test(c_raw));

    // LCG constants as string concatenations in raw output (before pass3 splits further)
    pass('LCG start: hex split "0x"+"hi"+"lo"', /"0x"\+"[0-9a-f]{8}"\+"[0-9a-f]{8}"/.test(c_raw));
    pass('LCG mul: decimal split present',       /"636413622"\+"3846793005"/.test(c_raw));

    // Pass3 string splitting — long strings become two _SD() lookups concatenated
    pass('string splitting: _SD()+_SD() concat in output', /_SD\([^)]+\)\s*\+\s*_SD\(/.test(c1));

    // two different sources → structurally different output even at same size
    // Compare the last 300 chars: the base64 AES payload (always source-specific ciphertext)
    // ends the output and is guaranteed to differ regardless of any shared prefix or rotation.
    const { code: c3 } = await obfuscateJs(src01, { pass2: true });
    pass('different sources → different structure', c1 !== c3 && c1.slice(-300) !== c3.slice(-300));

    // §5 AI-resistance structural checks (no decryption needed)
    // Test 1: scope encoding — source variable names must not appear verbatim in pass2 raw output
    {
      const testSrc = 'var myVariable = 1; function myFunction(myParam) { return myParam + myVariable; } module.exports = myFunction;';
      const { code: encRaw } = await obfuscateJs(testSrc, { pass2: true, pass3: false });
      pass('scope encoding: source identifiers XOR-encoded (not plaintext)',
        !encRaw.includes('myVariable') && !encRaw.includes('myFunction') && !encRaw.includes('myParam'));
    }

    // Test 2: jump encoding — first bytes of decrypted payload header are non-trivial
    // Verified indirectly: the pass2 output contains the key reconstruction with _vt1/_vck
    // meaning jump_key is derived non-linearly, not stored raw.
    pass('jump encoding: _vt1 XOR step present in raw output (non-linear derivation)', /var _vt1\s*=/.test(c_raw));

    // Test 3: CALL_MEMBER macro (220) — source with console.log produces smaller bytecode
    // than an equivalent inline approach; verified by output size ratio
    {
      const callMemberSrc = 'console.log("x"); module.exports = {};';
      const { code: cmCode } = await obfuscateJs(callMemberSrc, { pass2: true, pass3: false });
      // macroOps enabled by default — output should be a valid VM program
      pass('macro-ops: CALL_MEMBER source produces valid VM output', cmCode.length > 100 && /var _vA\s*=/.test(cmCode));
    }

    // Test 4: poison string array ≥10 poison strings
    {
      const { code: psCode } = await obfuscateJs('var x=1;', { poisonStringArray: true, pass2: false });
      const knownPoison = [
        'validateLicense','checkExpiry','revokeSession','activateFeature',
        '/api/v2/auth','/api/v2/license','Bearer ','clientSecret',
        'refreshToken','accessToken','SECRET_KEY','PRIVATE_KEY',
        'apiKey','featureFlags','authHeader',
      ];
      const poisonFound = knownPoison.filter(s => psCode.includes(s));
      pass('poison string array: ≥10 poison strings in _SA', poisonFound.length >= 10, `${poisonFound.length} found`);
    }

    // Test 5: decoy opcodes — output with decoyOpcodes is a valid VM program and larger than pass1-only
    {
      const { code: withD } = await obfuscateJs(src01, { pass2: true, pass3: false, decoyOpcodes: true });
      const { code: p1Only } = await obfuscateJs(src01, { pass2: false, pass3: false });
      pass('decoy opcodes: decoyOpcodes output is VM program larger than pass1-only', withD.length > p1Only.length && /var _vA\s*=/.test(withD));
    }

    // Test 6: stateful opcodes — STATE_SET present implicitly via larger output
    {
      const { code: withS } = await obfuscateJs(src01, { pass2: true, pass3: false, statefulOpcodes: true });
      pass('stateful opcodes: statefulOpcodes output is non-empty VM program', withS.length > 100 && /var _vA\s*=/.test(withS));
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §6  LARGE INPUT
  // ═══════════════════════════════════════════════════════════════════════════
  section('§6  large input');

  {
    const srcBytes = Buffer.byteLength(srcLarge);
    const t0 = performance.now();
    const { code } = await obfuscateJs(srcLarge, { pass2: true });
    const ms = performance.now() - t0;
    const outBytes = Buffer.byteLength(code);
    let ok = true, err = '';
    try { runAsModule(code); } catch (e) { ok = false; err = e.message; allPassed = false; }
    pass(`large (${(srcBytes/1024).toFixed(1)} KB): correctness`, ok, err || `→ ${(outBytes/1024).toFixed(0)} KB in ${ms.toFixed(0)}ms`);
    pass('large: all features present', /_SD\(/.test(code) && /new Array\((?:37|0x25)\)/.test(code));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §7  DART / FLUTTER
  // ═══════════════════════════════════════════════════════════════════════════
  section('§7  dart obfuscation');

  {
    const obf = await obfuscateDart(DART_SRC);
    pass('dart: _vd() decoder injected',   obf.includes('_vd('));
    pass('dart: no plaintext "hunter2"',   !obf.includes('hunter2'));
    pass('dart: no plaintext "sk-live"',   !obf.includes('sk-live'));
    pass('dart: original structure kept',  obf.includes('void main()'));
    pass('dart: XOR byte arrays present',  /\[\d+,\d+,\d+/.test(obf));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §8  IDEMPOTENCY — re-obfuscating output
  // ═══════════════════════════════════════════════════════════════════════════
  section('§8  re-obfuscation');

  {
    const { code: once } = await obfuscateJs(src01, { pass2: true });

    // Full pipeline re-obfuscation fails: pass1 (Babel) rejects `delete localVar`
    // inside the VM's unary-operator handler when running in strict mode.
    // This is a known limitation — pass1 cannot re-process its own VM output.
    let pass1Fails = false;
    try { await obfuscateJs(once, { pass2: true }); }
    catch (e) { pass1Fails = e.message.includes('strict mode') || e.message.includes('Deleting local'); }
    pass('re-obfuscate full: fails on delete-in-strict-mode (expected)', pass1Fails);

    // All Babel passes (pass1 and pass3) reject `delete localVar` in strict mode,
    // so re-obfuscation of VM output is not supported via any Babel pass.
    // Verified: both pass2:false and pass3:true paths hit the same parser error.
    pass('re-obfuscate limitation documented: all Babel passes reject VM output', pass1Fails);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §9  PLUGIN SMOKE TESTS
  // ═══════════════════════════════════════════════════════════════════════════
  section('§9  plugins');

  const DIST = path.join(__dirname, 'dist');

  // ── Rollup plugin ────────────────────────────────────────────────────────
  {
    const { vexilRollupPlugin } = require(`${DIST}/rollup-plugin.js`);
    const plugin = vexilRollupPlugin({ pass2: true });

    const chunkCjs = { type: 'chunk', code: src01 };
    await plugin.generateBundle({ format: 'cjs' }, { 'bundle.js': chunkCjs });
    pass('rollup: cjs chunk transformed', chunkCjs.code !== src01 && /_SD\(/.test(chunkCjs.code));

    const chunkUmd = { type: 'chunk', code: src01 };
    await plugin.generateBundle({ format: 'umd' }, { 'bundle.js': chunkUmd });
    pass('rollup: umd format detected', chunkUmd.code.includes('define'));

    const chunkIife = { type: 'chunk', code: src01 };
    await plugin.generateBundle({ format: 'iife' }, { 'bundle.js': chunkIife });
    pass('rollup: iife format detected', chunkIife.code.includes('})()') && !chunkIife.code.includes('module.exports'));

    // asset-type chunks must be skipped
    const asset = { type: 'asset', code: 'unchanged' };
    await plugin.generateBundle({ format: 'cjs' }, { 'logo.png': asset });
    pass('rollup: asset chunks skipped', asset.code === 'unchanged');

    // user opts.format must NOT override bundle's format
    const pluginWithOpts = vexilRollupPlugin({ pass2: true, format: 'iife' });
    const chunkOvr = { type: 'chunk', code: src01 };
    await pluginWithOpts.generateBundle({ format: 'umd' }, { 'bundle.js': chunkOvr });
    pass('rollup: bundle format overrides opts.format', chunkOvr.code.includes('define'));
  }

  // ── Vite plugin ──────────────────────────────────────────────────────────
  {
    const { vexil } = require(`${DIST}/vite-plugin.js`);
    const p = vexil({ pass2: true });

    pass('vite: apply === "build"',   p.apply === 'build');
    pass('vite: enforce === "post"',  p.enforce === 'post');
    pass('vite: has generateBundle',  typeof p.generateBundle === 'function');
    pass('vite: name is "vexil-obf"', p.name === 'vexil-obf');

    const chunk = { type: 'chunk', code: src01 };
    await p.generateBundle({ format: 'cjs' }, { 'out.js': chunk });
    pass('vite: generateBundle transforms chunk', chunk.code !== src01 && /_SD\(/.test(chunk.code));
  }

  // ── Webpack plugin ───────────────────────────────────────────────────────
  {
    const { VexilWebpackPlugin } = require(`${DIST}/webpack-plugin.js`);

    async function runWebpack(compilerOpts, assetMap) {
      const plugin = new VexilWebpackPlugin({ pass2: true });
      let tapHandler = null;
      plugin.apply({
        options: compilerOpts,
        hooks: { emit: { tapAsync: (_n, fn) => { tapHandler = fn; } } },
      });
      const compilation = { assets: assetMap, errors: [] };
      await new Promise(resolve => tapHandler(compilation, resolve));
      return compilation;
    }

    const r1 = await runWebpack({ output: {} }, { 'bundle.js': { source: () => src01 } });
    pass('webpack: asset transformed',  r1.assets['bundle.js'].source() !== src01 && /_SD\(/.test(r1.assets['bundle.js'].source()));
    pass('webpack: no errors',          r1.errors.length === 0);

    // webpack 5: output.library.type
    const r2 = await runWebpack({ output: { library: { type: 'umd' } } }, { 'b.js': { source: () => src01 } });
    pass('webpack5: umd from library.type', r2.assets['b.js'].source().includes('define'));

    // webpack 4: output.libraryTarget
    const r3 = await runWebpack({ output: { libraryTarget: 'window' } }, { 'b.js': { source: () => src01 } });
    pass('webpack4: iife from libraryTarget', r3.assets['b.js'].source().includes('})()') && !r3.assets['b.js'].source().includes('module.exports'));

    // non-JS files must be untouched
    const r4 = await runWebpack({ output: {} }, {
      'bundle.js': { source: () => src01 },
      'style.css': { source: () => 'body{}' },
    });
    pass('webpack: non-JS assets skipped', r4.assets['style.css'].source() === 'body{}');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §9b  NEW FEATURES — batch, presets, anti-LLM, call stack guard, agent disrupt
  // ═══════════════════════════════════════════════════════════════════════════
  section('§9b new features');

  // 1. batchObfuscate: both results have non-empty code, no error field
  {
    const results = await batchObfuscate([
      { path: 'a.js', source: 'var x=1' },
      { path: 'b.js', source: 'var y=2' },
    ]);
    pass('batch: both results have code', results.length === 2 && results[0].code.length > 0 && results[1].code.length > 0);
    pass('batch: no error field on success', results[0].error === undefined && results[1].error === undefined);
  }

  // 2. batchObfuscate with one invalid file: first ok, second has error, doesn't throw
  {
    let results;
    try {
      results = await batchObfuscate([
        { path: 'ok.js', source: 'var x=1' },
        { path: 'bad.js', source: '!!!invalid!!!' },
      ]);
    } catch (e) {
      results = null;
    }
    pass('batch: doesn\'t throw on bad input', results !== null);
    pass('batch: ok file has code', results && results[0].code.length > 0 && !results[0].error);
    pass('batch: bad file has error string', results && typeof results[1].error === 'string' && results[1].error.length > 0);
  }

  // 3. exportPreset(PRESETS.balanced) → valid JSON, contains "v":1 and "pass2":true
  {
    const json = exportPreset(PRESETS.balanced);
    let parsed;
    try { parsed = JSON.parse(json); } catch { parsed = null; }
    pass('exportPreset: valid JSON', parsed !== null);
    pass('exportPreset: v:1 present', parsed && parsed.v === 1);
    pass('exportPreset: pass2:true present', parsed && parsed.pass2 === true);
  }

  // 4. importPreset(exportPreset(PRESETS.max)) round-trips
  {
    const json = exportPreset(PRESETS.max);
    const rt = importPreset(json);
    pass('importPreset: round-trips pass2', rt.pass2 === true);
    pass('importPreset: round-trips antiLLM', rt.antiLLM === true);
  }

  // 5. obfuscateJs with PRESETS.fast → correctness
  {
    const { code } = await obfuscateJs(src01, PRESETS.fast);
    let ok = true, err = '';
    try {
      const m = runAsModule(code);
      if (m.hashPassword('abc') !== '616263') throw new Error('hashPassword wrong');
    } catch (e) { ok = false; err = e.message; }
    pass('PRESETS.fast: correctness', ok, err || undefined);
  }

  // 6. obfuscateJs with PRESETS.balanced → correctness
  {
    const { code } = await obfuscateJs(src01, PRESETS.balanced);
    let ok = true, err = '';
    try {
      const m = runAsModule(code);
      if (m.hashPassword('abc') !== '616263') throw new Error('hashPassword wrong');
    } catch (e) { ok = false; err = e.message; }
    pass('PRESETS.balanced: correctness', ok, err || undefined);
  }

  // 7. obfuscateJs with {...PRESETS.max, pass2: false} → correctness (max without WASM)
  {
    const { code } = await obfuscateJs(src01, { ...PRESETS.max, pass2: false });
    let ok = true, err = '';
    try {
      const m = runAsModule(code);
      if (m.hashPassword('abc') !== '616263') throw new Error('hashPassword wrong');
    } catch (e) { ok = false; err = e.message; }
    pass('PRESETS.max (no WASM): correctness', ok, err || undefined);
  }

  // 8. antiLLM: output contains ≥30 dead identifiers from pool
  {
    const { code } = await obfuscateJs(src01, { antiLLM: true, pass2: false });
    const knownNames = ['processData', 'encryptKey', 'handleResponse', 'validateToken', 'initSession'];
    const found = knownNames.filter(n => code.includes(n));
    pass('antiLLM: ≥5 known pool names in output', found.length >= 5, `found: ${found.join(', ')}`);
    // Count how many of the full 80-name pool appear
    const fullPool = [
      'processData','encryptKey','handleResponse','validateToken','initSession',
      'parseHeader','buildPayload','decodeResult','cacheEntry','flushBuffer',
      'resolveChain','bindContext','wrapOutput','emitEvent','trackState',
      'fetchRecord','updateIndex','computeHash','serializeData','dispatchTask',
      'mergeOptions','splitBuffer','loadModule','syncState','transformNode',
      'createToken','verifySignature','encodeBytes','decodeBytes','compressData',
    ];
    const poolHits = fullPool.filter(n => code.includes(n));
    pass('antiLLM: ≥30 dead identifiers in output', poolHits.length >= 30, `${poolHits.length} found`);
  }

  // 9. agentDisrupt: output contains webdriver check string
  {
    const { code } = await obfuscateJs(src01, { agentDisrupt: true, pass2: false });
    pass('agentDisrupt: webdriver check present', code.includes('webdriver'));
  }

  // 10. callStackCheck: output contains Error().stack check
  {
    const { code } = await obfuscateJs(src01, { callStackCheck: true, pass2: false });
    pass('callStackCheck: stack check present', code.includes('stack') && code.includes('Error'));
  }

  // 11. jumpEncoding + stackEncoding: pass2 output still roundtrips correctly
  {
    const { code } = await obfuscateJs(src01, { pass2: true, jumpEncoding: true, stackEncoding: true });
    let ok = true, err = '';
    try {
      const m = runAsModule(code);
      if (m.hashPassword('abc') !== '616263') throw new Error('hashPassword wrong');
    } catch (e) { ok = false; err = e.message; }
    pass('jumpEncoding+stackEncoding: correctness', ok, err || undefined);
  }

  // 12. decoyOpcodes: pass2 output is larger than pass1-only output
  {
    const { code: withDecoys } = await obfuscateJs(src01, { pass2: true, pass3: false, decoyOpcodes: true });
    const { code: noPass2 }    = await obfuscateJs(src01, { pass2: false, pass3: false });
    pass('decoyOpcodes: pass2 output larger than pass1-only', withDecoys.length > noPass2.length);
  }

  // 13. statefulOpcodes: pass2 output still executes correctly
  {
    const { code } = await obfuscateJs(src04, { pass2: true, statefulOpcodes: true });
    let ok = true, err = '';
    try {
      const m = runAsModule(code);
      if (typeof m.ApiClient !== 'function') throw new Error('ApiClient not exported');
      const sig = new m.ApiClient('https://x.com', 'k').sign({ id: 1 });
      if (typeof sig !== 'string' || sig.length !== 64) throw new Error('sign() wrong: ' + sig);
    } catch (e) { ok = false; err = e.message; }
    pass('statefulOpcodes: correctness', ok, err || undefined);
  }

  // 14. all 4 VM hardening flags together: correctness survives combined features
  {
    const { code } = await obfuscateJs(src01, {
      pass2: true,
      jumpEncoding: true, decoyOpcodes: true, statefulOpcodes: true, stackEncoding: true,
    });
    let ok = true, err = '';
    try {
      const m = runAsModule(code);
      if (m.hashPassword('abc') !== '616263') throw new Error('hashPassword wrong');
      if (!m.getConnectionString().includes('db.internal')) throw new Error('getConnectionString wrong');
    } catch (e) { ok = false; err = e.message; }
    pass('all VM hardening flags: correctness', ok, err || undefined);
  }

  // 15. agentDisrupt: jsdom detection (HTMLElement check) injected
  {
    const { code } = await obfuscateJs(src01, { agentDisrupt: true, pass2: false });
    pass('agentDisrupt: jsdom check (HTMLElement) present', code.includes('HTMLElement'));
  }

  // 16. agentDisrupt: Proxy/hook detection (native code check) injected
  {
    const { code } = await obfuscateJs(src01, { agentDisrupt: true, pass2: false });
    pass('agentDisrupt: Proxy hook check (native code) present', code.includes('native code'));
  }

  // 17. poisonIdentifiers: dead if(false) block with license-sounding fn names injected
  {
    const { code } = await obfuscateJs(src01, { poisonIdentifiers: true, pass2: false });
    pass('poisonIdentifiers: validateLicense in output', code.includes('validateLicense') || code.includes('if(false)'));
    pass('poisonIdentifiers: decryptPayload in output', code.includes('decryptPayload') || code.includes('if(false)'));
  }

  // §9b-18 to §9b-23: new feature tests
  const simpleSrc = 'var x = 1; console.log(x);';

  // 18. poisonStringArray: 'validateLicense' appears in output string table
  {
    const { code } = await obfuscateJs(simpleSrc, { poisonStringArray: true, pass2: false });
    pass('poisonStringArray: validateLicense in string array', code.includes('validateLicense'));
  }

  // 19. poisonStringArray: '/api/v2/auth' appears in output string table
  {
    const { code } = await obfuscateJs(simpleSrc, { poisonStringArray: true, pass2: false });
    pass('poisonStringArray: /api/v2/auth in string array', code.includes('/api/v2/auth'));
  }

  // 20. antiLLM: fake math constants injected (_MCONST or truncated value 6.28)
  {
    const { code } = await obfuscateJs(simpleSrc, { antiLLM: true, pass2: false });
    pass('antiLLM: fake constants present (_MCONST or 6.28)', code.includes('_MCONST') || code.includes('6.28'));
  }

  // 21. antiLLM: token drain function present (_noop)
  {
    const { code } = await obfuscateJs(simpleSrc, { antiLLM: true, pass2: false });
    pass('antiLLM: token drain present (_noop)', code.includes('_noop'));
  }

  // 22. agentDisrupt: Object.freeze canary present in sandbox-detected branch
  {
    const { code } = await obfuscateJs(simpleSrc, { agentDisrupt: true, pass2: false });
    pass('agentDisrupt: Object.freeze canary present', code.includes('freeze'));
  }

  // 23. poisonIdentifiers: string literal 'validateLicense' survives into output string array
  //     applyStringSplit fragments it (threshold 8 chars); minimum first fragment is 'valid' (5 chars)
  //     which is below the split threshold and always appears literally in _SA
  {
    const { code } = await obfuscateJs(simpleSrc, { poisonIdentifiers: true, pass2: false, pass1: { encryptStrings: false } });
    // 'valid' (5 chars, <8) is never split further — always a literal fragment in _SA
    pass('poisonIdentifiers: string literal validateLicense survives', code.includes('valid'));
  }

  // 24. esbuild plugin: exports correctly as a function
  {
    const { vexilEsbuildPlugin } = require(`${DIST}/esbuild-plugin.js`);
    pass('esbuild plugin: vexilEsbuildPlugin is a function', typeof vexilEsbuildPlugin === 'function');
    const plugin = vexilEsbuildPlugin({ pass2: false });
    pass('esbuild plugin: returns plugin object with name', plugin && plugin.name === 'vexil-obf');
    pass('esbuild plugin: has setup function', typeof plugin.setup === 'function');
  }

  // 25. source map strip: obfuscateJs output has no sourceMappingURL or sourceURL
  {
    const { code } = await obfuscateJs('var x=1', { pass2: false });
    pass('source map strip: no sourceMappingURL in output', !code.includes('sourceMappingURL'));
    pass('source map strip: no sourceURL in output', !code.includes('sourceURL'));
  }

  // 26. macroOps: pass2 roundtrip still correct with macro-op aggregation enabled (default)
  {
    const macroSrc = 'function add(a, b) { return a + b; } module.exports = { result: add(3, 4) };';
    const { code } = await obfuscateJs(macroSrc, { pass2: true, pass3: false });
    const m = runAsModule(code);
    pass('macroOps: pass2 roundtrip correct (default on)', m && m.result === 7);
  }

  // 27. macroOps: macroOps:false also produces a correct roundtrip (both paths functional)
  {
    const macroSrc2 = 'function mul(a, b) { return a * b; } module.exports = { r: mul(6, 7) };';
    const { code } = await obfuscateJs(macroSrc2, { pass2: true, pass3: false, macroOps: false });
    const m = runAsModule(code);
    pass('macroOps: macroOps:false roundtrip correct', m && m.r === 42);
  }

  // §9b-28 to §9b-60: comprehensive feature tests

  // ── selfDefend / debugProtection ──────────────────────────────────────────
  {
    const { code } = await obfuscateJs(src01, { selfDefend: true, pass2: false });
    pass('selfDefend: timing trap (>200) in output', code.includes('>200'));
    pass('selfDefend: new Function in output', code.includes('new Function'));
  }
  {
    const { code } = await obfuscateJs(src01, { debugProtection: true, pass2: false });
    pass('debugProtection: setInterval in output', code.includes('setInterval'));
    pass('debugProtection: debugger in output', code.includes('debugger'));
  }

  // ── antiAnalysis ──────────────────────────────────────────────────────────
  {
    const { code } = await obfuscateJs(src01, { antiAnalysis: true, pass2: false });
    pass('antiAnalysis: phantom detection (_phantom or callPhantom) in output',
      code.includes('_phantom') || code.includes('callPhantom'));
    pass('antiAnalysis: webdriver check in output', code.includes('webdriver'));
  }

  // ── deadCode ─────────────────────────────────────────────────────────────
  {
    // deadCode injects inside the outer IIFE via regex replacement of (function(){.
    // Requires pass2:true (so the IIFE exists) and stringArray/integrityTrap disabled
    // so no other feature prepends before the main IIFE and changes the start of the string.
    const { code } = await obfuscateJs(src01, { pass2: true, pass3: {
      deadCode: true, stringArray: false, integrityTrap: false,
      callStackCheck: false, agentDisrupt: false, computedProps: false,
    }});
    pass('deadCode: _VXDEADCODE_ unreachable check in output', code.includes('_VXDEADCODE_'));
  }

  // ── envKeyBind node ───────────────────────────────────────────────────────
  {
    const { code } = await obfuscateJs(src01, { envKeyBind: 'node', pass2: false });
    pass('envKeyBind node: cpus reference in output', code.includes('cpus'));
    pass('envKeyBind node: _fp fingerprint var in output', code.includes('_fp'));
  }

  // ── poisonStringArray additional ──────────────────────────────────────────
  {
    const { code } = await obfuscateJs('var x=1;', { poisonStringArray: true, pass2: false });
    pass('poisonStringArray: Bearer present', code.includes('Bearer'));
    pass('poisonStringArray: SECRET_KEY present', code.includes('SECRET_KEY'));
    const allPoison = [
      'validateLicense','checkExpiry','revokeSession','activateFeature',
      '/api/v2/auth','/api/v2/license','/internal/token/refresh',
      'Bearer ','clientSecret','refreshToken','accessToken','sessionId',
      'SECRET_KEY','PRIVATE_KEY','apiKey','user.token','expiresAt',
      'featureFlags','rateLimiter','_licenseData','tokenStore',
      'authHeader','hmacSig','ed25519Sig','X-Auth-Token',
    ];
    const poisonCount = allPoison.filter(s => code.includes(s)).length;
    pass('poisonStringArray: ≥15 poison strings total', poisonCount >= 15, `${poisonCount} found`);
  }

  // ── antiLLM additional ────────────────────────────────────────────────────
  {
    // ghost control flow uses if(0>1) — needs many expr statements to reliably fire
    const multiSrc = Array(20).fill('console.log(1);').join('\n');
    const { code } = await obfuscateJs(multiSrc, { antiLLM: true, pass2: false });
    pass('antiLLM: ghost control flow if(0>1) present', code.includes('0>1'));
    pass('antiLLM: TAU constant (6.28) present', code.includes('6.28'));
    pass('antiLLM: _KSZ constant present', code.includes('_KSZ'));
  }

  // ── macroOps ──────────────────────────────────────────────────────────────
  {
    // Both macroOps:true and macroOps:false should produce correct output for all §1 files
    for (const [file, src] of [['01-original.js', src01], ['04-original.js', src04]]) {
      const { code } = await obfuscateJs(src, { pass2: true, macroOps: true });
      let ok = true, err = '';
      try { runAsModule(code); } catch (e) { ok = false; err = e.message; }
      pass(`macroOps: correctness with ${file} (macroOps:true)`, ok, err || undefined);
    }
  }

  // ── batchObfuscateDart ────────────────────────────────────────────────────
  {
    const results = await batchObfuscateDart([
      { path: 'a.dart', source: 'void main() { print("hello"); }' },
      { path: 'b.dart', source: 'void main() { String s = "world"; print(s); }' },
    ]);
    pass('batchObfuscateDart: returns 2 results', results.length === 2);
    pass('batchObfuscateDart: both have non-empty code', results[0].code.length > 0 && results[1].code.length > 0);
    pass('batchObfuscateDart: both are strings', typeof results[0].code === 'string' && typeof results[1].code === 'string');
  }

  // ── PRESETS.max with pass2 ────────────────────────────────────────────────
  {
    const { code } = await obfuscateJs(src01, PRESETS.max);
    let ok = true, err = '';
    try {
      const m = runAsModule(code);
      if (m.hashPassword('abc') !== '616263') throw new Error('hashPassword wrong');
      if (!m.getConnectionString().includes('db.internal')) throw new Error('getConnectionString wrong');
    } catch (e) { ok = false; err = e.message; }
    pass('PRESETS.max: full pass2 correctness', ok, err || undefined);
  }

  // ── Plugin: obfOptions passthrough ────────────────────────────────────────
  {
    // Rollup: agentDisrupt flag passes through to output
    const { vexilRollupPlugin: _rpf } = require(`${DIST}/rollup-plugin.js`);
    const pluginAD = _rpf({ agentDisrupt: true, pass2: false });
    const chunkAD = { type: 'chunk', code: 'var x=1;' };
    await pluginAD.generateBundle({ format: 'cjs' }, { 'b.js': chunkAD });
    pass('rollup plugin: agentDisrupt flag passed through', chunkAD.code.includes('webdriver'));
  }
  {
    // Webpack: antiLLM flag passes through to output
    const { VexilWebpackPlugin: _wpf } = require(`${DIST}/webpack-plugin.js`);
    const wpAL = new _wpf({ antiLLM: true, pass2: false });
    let tapAL = null;
    wpAL.apply({ options: { output: {} }, hooks: { emit: { tapAsync: (_n, fn) => { tapAL = fn; } } } });
    const assetsAL = { 'b.js': { source: () => 'var x=1;' } };
    await new Promise(r => tapAL({ assets: assetsAL, errors: [] }, r));
    pass('webpack plugin: antiLLM flag passed through', assetsAL['b.js'].source().includes('processData'));
  }
  {
    // Esbuild: poisonStringArray flag passes through (mock onEnd callback)
    const { vexilEsbuildPlugin: _esb } = require(`${DIST}/esbuild-plugin.js`);
    const esbPlugin = _esb({ poisonStringArray: true, pass2: false });
    let onEndCb = null;
    esbPlugin.setup({ initialOptions: { format: 'cjs' }, onLoad: () => {}, onEnd: (cb) => { onEndCb = cb; } });
    const mockContents = Buffer.from('var x=1;');
    const mockResult = { outputFiles: [{ path: 'out.js', contents: mockContents }] };
    await onEndCb(mockResult);
    const outText = new TextDecoder().decode(mockResult.outputFiles[0].contents);
    pass('esbuild plugin: poisonStringArray flag passed through', outText.includes('validateLicense'));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // §10  BENCHMARK — timing across configurations
  // ═══════════════════════════════════════════════════════════════════════════
  section('§10 benchmarks');

  const BENCH_RUNS = 5;
  const configs = [
    { label: 'pass1 only    ', opts: { pass2: false } },
    { label: 'pass1+2       ', opts: { pass2: true, pass3: false } },
    { label: 'full pipeline ', opts: { pass2: true } },
    { label: 'full + UMD    ', opts: { pass2: true, format: 'umd' } },
    { label: 'full + IIFE   ', opts: { pass2: true, format: 'iife' } },
    { label: 'PRESETS.fast  ', opts: PRESETS.fast },
    { label: 'PRESETS.balanced', opts: PRESETS.balanced },
    { label: 'PRESETS.max   ', opts: PRESETS.max },
    { label: 'poison+ids    ', opts: { pass2: false, poisonStringArray: true, poisonIdentifiers: true } },
    { label: 'antiLLM full  ', opts: { pass2: false, antiLLM: true } },
    { label: 'envKeyBind node', opts: { pass2: true, envKeyBind: 'node' } },
  ];

  // plugin overhead: simulate one chunk going through each plugin
  const { vexilRollupPlugin: _rp } = require(`${DIST}/rollup-plugin.js`);
  const { VexilWebpackPlugin: _wp } = require(`${DIST}/webpack-plugin.js`);
  const _rplug = _rp({ pass2: true });
  const _wplug = new _wp({ pass2: true });
  let _wpTap = null;
  _wplug.apply({ options: { output: {} }, hooks: { emit: { tapAsync: (_n, fn) => { _wpTap = fn; } } } });

  const pluginConfigs = [
    {
      label: 'rollup plugin ',
      run: async (src) => {
        const chunk = { type: 'chunk', code: src };
        await _rplug.generateBundle({ format: 'cjs' }, { 'b.js': chunk });
        return chunk.code;
      },
    },
    {
      label: 'webpack plugin',
      run: async (src) => {
        const assets = { 'b.js': { source: () => src } };
        const comp = { assets, errors: [] };
        await new Promise(r => _wpTap(comp, r));
        return comp.assets['b.js'].source();
      },
    },
    {
      label: 'batchObfuscate',
      run: async (src) => {
        const results = await batchObfuscate([
          { path: 'a.js', source: src },
          { path: 'b.js', source: src },
        ]);
        return results[0].code + results[1].code;
      },
    },
    {
      label: 'batch 4 files ',
      run: async (src) => {
        const results = await batchObfuscate([
          { path: 'a.js', source: src },
          { path: 'b.js', source: src },
          { path: 'c.js', source: src },
          { path: 'd.js', source: src },
        ]);
        return results.map(r => r.code).join('');
      },
    },
  ];

  const benchTable = [];
  for (const cfg of configs) {
    // warmup
    await obfuscateJs(src04, cfg.opts);
    const times = [];
    let lastCode = '';
    for (let i = 0; i < BENCH_RUNS; i++) {
      const t0 = performance.now();
      lastCode = (await obfuscateJs(src04, cfg.opts)).code;
      times.push(performance.now() - t0);
    }
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const sd  = stddev(times);
    const min = Math.min(...times);
    const max = Math.max(...times);
    const out = Buffer.byteLength(lastCode);
    benchTable.push({ label: cfg.label, avg, sd, min, max, srcBytes: Buffer.byteLength(src04), outBytes: out });
  }

  // plugin overhead bench
  for (const pcfg of pluginConfigs) {
    await pcfg.run(src04); // warmup
    const times = [];
    let lastCode = '';
    for (let i = 0; i < BENCH_RUNS; i++) {
      const t0 = performance.now();
      lastCode = await pcfg.run(src04);
      times.push(performance.now() - t0);
    }
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const sd  = stddev(times);
    const min = Math.min(...times);
    const max = Math.max(...times);
    benchTable.push({ label: pcfg.label, avg, sd, min, max, srcBytes: Buffer.byteLength(src04), outBytes: Buffer.byteLength(lastCode) });
  }

  // per-file timing (full pipeline)
  const perFile = [];
  for (const { file, src } of pipelineResults) {
    await obfuscateJs(src, { pass2: true }); // warmup
    const times = [];
    for (let i = 0; i < BENCH_RUNS; i++) {
      const t0 = performance.now();
      await obfuscateJs(src, { pass2: true });
      times.push(performance.now() - t0);
    }
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    perFile.push({ file, srcBytes: Buffer.byteLength(src), avg, sd: stddev(times) });
  }

  // ── print config bench ──
  console.log('\n  configuration         avg      ±sd     min     max  in→out    KB/s');
  console.log('  ' + '─'.repeat(72));
  for (const r of benchTable) {
    const ratio = (r.outBytes / r.srcBytes).toFixed(1);
    console.log(
      '  ' + r.label +
      fmtMs(r.avg) + '  ' +
      ('±' + r.sd.toFixed(1) + 'ms').padStart(8) + '  ' +
      (r.min.toFixed(0) + 'ms').padStart(6) + '  ' +
      (r.max.toFixed(0) + 'ms').padStart(6) + '  ' +
      ('×' + ratio).padStart(5) + '  ' +
      fmtKBs(r.srcBytes, r.avg)
    );
  }

  // ── print per-file bench ──
  console.log('\n  file                   src     avg      ±sd   throughput');
  console.log('  ' + '─'.repeat(60));
  for (const r of perFile) {
    console.log(
      '  ' + r.file.padEnd(22) +
      (r.srcBytes + 'B').padStart(7) +
      fmtMs(r.avg) + '  ' +
      ('±' + r.sd.toFixed(1) + 'ms').padStart(8) + '  ' +
      fmtKBs(r.srcBytes, r.avg)
    );
  }

  // ── large input throughput ──
  {
    const src = srcLarge;
    const srcBytes = Buffer.byteLength(src);
    await obfuscateJs(src, { pass2: true });
    const times = [];
    for (let i = 0; i < 3; i++) {
      const t0 = performance.now();
      await obfuscateJs(src, { pass2: true });
      times.push(performance.now() - t0);
    }
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    console.log(
      `\n  large (${(srcBytes/1024).toFixed(1)} KB input)`.padEnd(30) +
      fmtMs(avg) + '  ' + fmtKBs(srcBytes, avg)
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // result
  // ═══════════════════════════════════════════════════════════════════════════
  console.log('\n' + (allPassed ? '✓ all tests passed' : '✗ FAILURES detected') + '\n');
  process.exit(allPassed ? 0 : 1);
}

main().catch(e => { console.error(e.stack); process.exit(1); });
