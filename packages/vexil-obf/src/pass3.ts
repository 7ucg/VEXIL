import * as parser from '@babel/parser';
import traverse from '@babel/traverse';
import generate from '@babel/generator';
import * as t from '@babel/types';

// Shorter names than pass1's _0xa prefix — saves bytes and looks more cryptic
function nameGen(): () => string {
  let n = 0;
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
  return () => {
    let s = '', x = n++;
    do { s = chars[x % 52] + s; x = Math.floor(x / 52) - 1; } while (x >= 0);
    return '_' + s;
  };
}

export interface Pass3Options {
  selfDefend?: boolean;      // crash/hang when devtools open
  debugProtection?: boolean; // periodic debugger; detect breakpoint timing
  deadCode?: boolean;        // insert unreachable branches
  hexNumbers?: boolean;      // emit byte arrays as 0xNN hex
  computedProps?: boolean;   // convert obj.prop -> obj['prop'] with hex strings (default true)
  stringArray?: boolean;     // collect strings into shuffled array + decode fn (default true)
  antiAnalysis?: boolean;    // inject phantom/webdriver/proxy/debugger timing checks (default false)
  integrityTrap?: boolean;   // XOR checksum the binary payload and hang if tampered (default true)
  callStackCheck?: boolean;  // inject call-stack depth guard IIFE (default true)
  agentDisrupt?: boolean;    // detect webdriver/playwright/jest and zero VM key (default true)
  antiLLM?: boolean;         // flood dead identifiers + ghost control flow + string dispersion
  poisonStringArray?: boolean; // inject misleading API/crypto strings into string array (default false; auto-enabled when antiLLM: true)
  envKeyBind?: 'node' | 'browser' | false; // XOR one key byte with runtime environment fingerprint
}

// Convert a string to a hex-escaped form: 'prop' -> '\x70\x72\x6f\x70'
function toHexString(s: string): string {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    out += '\\x' + s.charCodeAt(i).toString(16).padStart(2, '0');
  }
  return out;
}

// Split long string literals into two-part concatenations so that each half
// becomes a separate entry in the string array.  An analyst looking for a
// BigInt constant like "6364136223846793005" or a cipher name like "aes-256-gcm"
// now has to find and join two separate array slots rather than one.
//
// Threshold: strings >= 8 chars.  Base64 blobs and very long strings (>500) are
// skipped to avoid interfering with the payload integrity trap.
function applyStringSplit(ast: t.File, threshold = 8): void {
  // Collect nodes to replace after traversal to avoid re-visiting new nodes
  const replacements: Array<{ path: import('@babel/traverse').NodePath<t.StringLiteral>; left: string; right: string }> = [];

  traverse(ast, {
    StringLiteral(path) {
      const val = path.node.value;
      if (val.length < threshold) return;
      if (val.length > 500) return; // payload — leave for integrity trap
      if (path.parentPath?.isDirective()) return;
      // Don't split strings that are purely base64 and long (encoded data)
      if (val.length >= 40 && /^[A-Za-z0-9+/]+=*$/.test(val)) return;
      // Don't re-split a node that's already being replaced
      if ((path.node as t.StringLiteral & { _split?: boolean })._split) return;

      // Split at a position between 35% and 65% of the string
      const lo = Math.max(1, Math.floor(val.length * 0.35));
      const hi = Math.min(val.length - 1, Math.ceil(val.length * 0.65));
      const mid = lo + Math.floor(Math.random() * (hi - lo + 1));

      replacements.push({ path, left: val.slice(0, mid), right: val.slice(mid) });
    }
  });

  for (const { path, left, right } of replacements) {
    const leftNode = t.stringLiteral(left);
    const rightNode = t.stringLiteral(right);
    // Mark children so we don't try to split them again during this pass
    (leftNode as t.StringLiteral & { _split?: boolean })._split = true;
    (rightNode as t.StringLiteral & { _split?: boolean })._split = true;
    path.replaceWith(t.binaryExpression('+', leftNode, rightNode));
  }
}

// Inject a dead if(false){console.log(...)} block with misleading strings so they
// get captured by applyStringArray() and appear in the rotating string table.
function injectPoisonStringArray(ast: t.File): void {
  const poisonStrings = [
    'validateLicense', 'checkExpiry', 'revokeSession', 'activateFeature',
    '/api/v2/auth', '/api/v2/license', '/internal/token/refresh',
    'Bearer ', 'clientSecret', 'refreshToken', 'accessToken', 'sessionId',
    'SECRET_KEY', 'PRIVATE_KEY', 'apiKey', 'user.token', 'expiresAt',
    'featureFlags', 'rateLimiter', '_licenseData', 'tokenStore',
    'authHeader', 'hmacSig', 'ed25519Sig', 'X-Auth-Token',
  ];
  const ifNode = t.ifStatement(
    t.booleanLiteral(false),
    t.blockStatement([
      t.expressionStatement(
        t.callExpression(
          t.memberExpression(t.identifier('console'), t.identifier('log')),
          poisonStrings.map(s => t.stringLiteral(s))
        )
      )
    ])
  );
  ast.program.body.unshift(ifNode);
}

// Build env key bind injection code as a string snippet.
function buildEnvKeyBindCode(envKeyBind: 'node' | 'browser' | false): string {
  if (!envKeyBind) return '';
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const os = require('os') as typeof import('os');
  let buildFpExpected: number;
  let fpCode: string;
  if (envKeyBind === 'node') {
    buildFpExpected = os.cpus().length & 0xFF;
    fpCode = `var _fp=0;try{_fp=require('os').cpus().length&0xFF;}catch(e){}`;
  } else {
    buildFpExpected = ((4 & 0xF) ^ ((24 & 0xF) << 4)) & 0xFF;
    fpCode = `var _fp=0;try{_fp=((navigator.hardwareConcurrency&0xF)^((screen.colorDepth&0xF)<<4))&0xFF;}catch(e){}`;
  }
  return (
    fpCode +
    `if(typeof _vK!=='undefined'&&_vK.length>=32){_vK[15]^=(_fp^${buildFpExpected});}`
  );
}

// Build the string-array rotation pass on an already-traversed AST.
// Inserts _SA array and _SD decode function at top of first Program body statement.
function applyStringArray(ast: t.File): void {
  const collected: string[] = [];
  const nodeIndexMap = new Map<t.StringLiteral, number>();

  // First pass: collect eligible strings
  traverse(ast, {
    StringLiteral(path) {
      const val = path.node.value;
      // Skip payload (large base64 blobs)
      if (val.length > 500) return;
      // Skip empty strings
      if (val.length === 0) return;
      // Skip strings that are pure base64-only AND long (>=40 chars) — likely encoded data
      if (val.length >= 40 && /^[A-Za-z0-9+/]+=*$/.test(val)) return;
      // Skip strings used as directive prologues (e.g. 'use strict')
      if (path.parentPath?.isDirective()) return;
      // Skip strings that are object/import keys in certain positions
      // (we still want to collect them, they'll be referenced by index)
      if (!nodeIndexMap.has(path.node)) {
        let idx = collected.indexOf(val);
        if (idx === -1) {
          idx = collected.length;
          collected.push(val);
        }
        nodeIndexMap.set(path.node, idx);
      }
    }
  });

  if (collected.length === 0) return;

  // Pick a rotation offset
  const ROT = Math.floor(Math.random() * collected.length);

  // Build the shuffled array: element at position i in _SA is collected[(i + ROT) % len]
  // So to get original string at index origIdx, we call _SD(_SA, origIdx)
  // _SD does: _SA[(origIdx + ROT) % len] == collected[origIdx] — correct as long as we store
  // them in the shuffled order. Let's think carefully:
  // We want _SA[j] = collected[(j - ROT + len) % len]
  // And _SD(_SA, origIdx) = _SA[(origIdx + ROT) % len] = collected[origIdx] ✓
  const len = collected.length;
  const shuffled: string[] = new Array(len);
  for (let j = 0; j < len; j++) {
    shuffled[j] = collected[((j - ROT) % len + len) % len];
  }

  // Build the AST nodes for _SA and _SD
  const saId = t.identifier('_SA');
  const sdId = t.identifier('_SD');

  const saDecl = t.variableDeclaration('var', [
    t.variableDeclarator(
      saId,
      t.arrayExpression(shuffled.map(s => t.stringLiteral(s)))
    )
  ]);

  // function _SD(arr, idx) { return arr[(idx + ROT) % arr.length]; }
  const arrParam = t.identifier('arr');
  const idxParam = t.identifier('idx');
  const sdFn = t.functionDeclaration(
    sdId,
    [arrParam, idxParam],
    t.blockStatement([
      t.returnStatement(
        t.memberExpression(
          t.identifier('arr'),
          t.binaryExpression(
            '%',
            t.binaryExpression('+', t.identifier('idx'), t.numericLiteral(ROT)),
            t.memberExpression(t.identifier('arr'), t.identifier('length'))
          ),
          true // computed
        )
      )
    ])
  );

  // Prepend to program body
  const program = ast.program;
  program.body.unshift(saDecl);
  program.body.unshift(sdFn);

  // Second pass: replace StringLiteral nodes with _SD(_SA, idx)
  traverse(ast, {
    StringLiteral(path) {
      const idx = nodeIndexMap.get(path.node);
      if (idx === undefined) return;
      if (path.parentPath?.isDirective()) return;
      const call = t.callExpression(
        t.identifier('_SD'),
        [t.identifier('_SA'), t.numericLiteral(idx)]
      );
      path.replaceWith(call);
      path.skip();
    }
  });
}

// Convert all non-computed member expressions to computed with hex-encoded string keys.
function applyComputedProps(ast: t.File): void {
  traverse(ast, {
    MemberExpression(path) {
      if (path.node.computed) return;
      const prop = path.node.property;
      if (!t.isIdentifier(prop)) return;
      const name = prop.name;
      const hexStr = toHexString(name);
      const strLit = t.stringLiteral(name);
      // Set raw to hex-escaped form so generator emits hex
      (strLit as any).extra = { raw: `'${hexStr}'`, rawValue: name };
      path.node.property = strLit;
      path.node.computed = true;
    }
  });
}

// Compute a simple XOR checksum of the first 64 chars of a string.
function xorChecksum(s: string, len = 64): number {
  let sum = 0;
  for (let i = 0; i < Math.min(len, s.length); i++) sum ^= s.charCodeAt(i);
  return sum;
}

// Find the large payload string and inject an integrity check before the VM IIFE call.
function applyIntegrityTrap(ast: t.File): void {
  let payloadValue: string | null = null;
  let payloadNode: t.StringLiteral | null = null;

  // Find the payload string (> 500 chars)
  traverse(ast, {
    StringLiteral(path) {
      if (path.node.value.length > 500 && payloadNode === null) {
        payloadValue = path.node.value;
        payloadNode = path.node;
      }
    }
  });

  if (!payloadValue || !payloadNode) return;

  const checksum = xorChecksum(payloadValue);

  // Build: (function(_p){ var _s=0; for(var _i=0;_i<Math.min(64,_p.length);_i++) _s^=_p.charCodeAt(_i); if(_s!==CHECKSUM){while(1){}} })(PAYLOAD_NODE)
  const pParam = t.identifier('_p');
  const sVar = t.identifier('_s');
  const iVar = t.identifier('_i');

  const trapIIFE = t.expressionStatement(
    t.callExpression(
      t.functionExpression(
        null,
        [pParam],
        t.blockStatement([
          // var _s = 0;
          t.variableDeclaration('var', [t.variableDeclarator(sVar, t.numericLiteral(0))]),
          // for (var _i = 0; _i < Math.min(64, _p.length); _i++) _s ^= _p.charCodeAt(_i);
          t.forStatement(
            t.variableDeclaration('var', [t.variableDeclarator(iVar, t.numericLiteral(0))]),
            t.binaryExpression('<',
              t.identifier('_i'),
              t.callExpression(
                t.memberExpression(t.identifier('Math'), t.identifier('min')),
                [t.numericLiteral(64),
                 t.memberExpression(t.identifier('_p'), t.identifier('length'))]
              )
            ),
            t.updateExpression('++', t.identifier('_i')),
            t.expressionStatement(
              t.assignmentExpression('^=',
                t.identifier('_s'),
                t.callExpression(
                  t.memberExpression(t.identifier('_p'), t.identifier('charCodeAt')),
                  [t.identifier('_i')]
                )
              )
            )
          ),
          // if (_s !== CHECKSUM) { while(1) {} }
          t.ifStatement(
            t.binaryExpression('!==', t.identifier('_s'), t.numericLiteral(checksum)),
            t.blockStatement([t.whileStatement(t.numericLiteral(1), t.blockStatement([]))])
          )
        ])
      ),
      // Pass a clone of the payload StringLiteral as argument
      [t.stringLiteral(payloadValue)]
    )
  );

  // Insert the trap before the first ExpressionStatement that is a CallExpression
  // (the VM IIFE call), which is the last statement in the program body typically.
  // More robustly: find the statement containing the payloadNode and insert before it.
  const program = ast.program;
  let insertIdx = program.body.length > 0 ? program.body.length - 1 : 0;

  // Walk body to find which statement contains the payload node
  for (let i = 0; i < program.body.length; i++) {
    const stmt = program.body[i];
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stmtCode = generate(t.file(t.program([stmt as any])), { compact: true }).code;
    // Heuristic: the statement containing the payload is long
    if (stmtCode.length > 200) {
      insertIdx = i;
      break;
    }
  }

  program.body.splice(insertIdx, 0, trapIIFE);
}

// ── Anti-LLM identifier pool ─────────────────────────────────────────────────
const ANTI_LLM_POOL = [
  'processData', 'encryptKey', 'handleResponse', 'validateToken', 'initSession',
  'parseHeader', 'buildPayload', 'decodeResult', 'cacheEntry', 'flushBuffer',
  'resolveChain', 'bindContext', 'wrapOutput', 'emitEvent', 'trackState',
  'fetchRecord', 'updateIndex', 'computeHash', 'serializeData', 'dispatchTask',
  'mergeOptions', 'splitBuffer', 'loadModule', 'syncState', 'transformNode',
  'createToken', 'verifySignature', 'encodeBytes', 'decodeBytes', 'compressData',
  'decompressData', 'buildIndex', 'scanBuffer', 'filterRecords', 'sortEntries',
  'mapValues', 'reduceList', 'groupItems', 'indexMap', 'entryCache',
  'sessionKey', 'authToken', 'requestBody', 'responseData', 'statusCode',
  'errorMessage', 'traceId', 'spanContext', 'metricLabel', 'eventSource',
  'dataStream', 'byteOffset', 'frameSize', 'packetHeader', 'checksumValue',
  'configEntry', 'envPayload', 'secretBuffer', 'keyHandle', 'nonceSeed',
  'saltBytes', 'ivBuffer', 'tagLength', 'blockSize', 'cipherMode',
  'paddingScheme', 'digestOutput', 'hmacKey', 'signatureBytes', 'publicKey',
  'privateKey', 'sharedSecret', 'ephemeralKey', 'derivedKey', 'masterSecret',
  'handshakeState', 'ratchetKey', 'messageKey', 'chainKey', 'rootKey',
];

// Build call-stack depth guard + agent/automation disruption as a raw code string.
// Returns the code to prepend. Emitted after generate() so source-specific content
// (string array, etc.) precedes it and outputs remain structurally distinct.
function buildCallStackGuardCode(opts: Pick<Pass3Options, 'callStackCheck' | 'agentDisrupt'>): string {
  const doCallStack = opts.callStackCheck !== false;
  const doAgentDisrupt = opts.agentDisrupt !== false;

  let body = '';

  if (doCallStack) {
    // Browser-only stack depth check (Node.js require depth would always exceed 8)
    body += `try{if(typeof window!=='undefined'){` +
      `var _cs=new Error().stack;` +
      `if(_cs&&_cs.split('\\n').length>8){(function(){while(true){}})();}` +
      `}}catch(_ce){}`;
  }

  if (doAgentDisrupt) {
    body +=
      `var _vxSetup=(function(){try{` +
      `if((typeof navigator!=='undefined'&&navigator.webdriver)||` +
      `(typeof window!=='undefined'&&(window.__playwright||window.__selenium_unwrapped))||` +
      `(typeof global!=='undefined'&&global.__coverage__!==undefined)||` +
      `(typeof process!=='undefined'&&process.env&&(process.env.JEST_WORKER_ID||process.env.VITEST_WORKER_ID))||` +
      `(typeof window!=='undefined'&&typeof window.HTMLElement!=='undefined'&&!window.chrome&&window.name==='')||` +
      `(Object.keys.toString().indexOf('native code')===-1||Function.prototype.apply.toString().indexOf('native code')===-1)){` +
      `if(typeof _vK!=='undefined'){for(var _zi=0;_zi<32;_zi++)_vK[_zi]=0;}` +
      `try{Object.freeze(Object.prototype);}catch(_fe){}` +
      `}}catch(_ae){}` +
      // Prototype integrity check — runs independently of sandbox detection
      `var _pi=(function(){try{` +
      `var _n=Object.getOwnPropertyNames(Object.prototype).length;` +
      `return _n>50;` +
      `}catch(_e){return false;}})();` +
      `if(_pi&&typeof _vK!=='undefined'){for(var _pz=0;_pz<4;_pz++)_vK[_pz]^=0xFF;}` +
      `})();`;
  }

  if (!body) return '';
  return `(function(){${body}})();`;
}

// Inject anti-LLM noise: dead identifier flood, ghost control flow, string dispersion.
function injectAntiLLM(ast: t.File, buildId?: string): void {
  // Seed a simple PRNG from buildId for deterministic ghost-cf decisions
  let seed = 0;
  if (buildId) {
    for (let i = 0; i < buildId.length; i++) seed = (seed * 31 + buildId.charCodeAt(i)) >>> 0;
  }
  function pseudoRand(): number {
    seed = (seed * 1664525 + 1013904223) >>> 0;
    return seed / 0xFFFFFFFF;
  }

  // 1. Identifier flood: ≥50 dead var declarations (all pool entries)
  const pool = [...ANTI_LLM_POOL];
  // Shuffle pool deterministically
  for (let i = pool.length - 1; i > 0; i--) {
    const j = Math.floor(pseudoRand() * (i + 1));
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  // Use the full pool so all names are guaranteed to appear
  const chosen = pool;
  const deadDecls: t.Statement[] = chosen.map((name, i) => {
    const refName = chosen[(i + 1) % chosen.length];
    return t.variableDeclaration('var', [
      t.variableDeclarator(
        t.identifier(name),
        i === 0
          ? t.nullLiteral()
          : t.identifier(refName)
      )
    ]);
  });

  // Insert dead decls near the top (after any existing top-level declarations)
  ast.program.body.splice(1, 0, ...deadDecls);

  // Feature 4: fake numerical constants — truncated math/crypto values to mislead LLM analysis
  const mconstSrc =
    `var _MCONST=(function(){` +
    `var _TAU=6.28,_PHI=1.618,_LN2=0.693,_SQRT2=1.414,_EXP=2.718,_PPI=3.14159;` +
    `var _KSZ=256,_BSZ=16,_IVSZ=12,_TAGSZ=128,_SLTSZ=32;` +
    `var _GC=6.674e-11,_NA=6.022e23,_KB=1.38e-23;` +
    `return {tau:_TAU,phi:_PHI,keySize:_KSZ,blockSize:_BSZ};` +
    `})();void _MCONST;`;
  const mconstAst = parser.parse(mconstSrc, { sourceType: 'script' });
  // Append after dead decls block (index 1 + deadDecls.length)
  const mconstInsertIdx = 1 + deadDecls.length;
  ast.program.body.splice(mconstInsertIdx, 0, ...mconstAst.program.body);

  // Feature 5: token budget drain — recursive structure that is expensive to analyze statically
  const noopSrc =
    `var _noop=(function _noop(){` +
    `var _x=function(n,d){` +
    `return n<=0?null:d>4?[_x(n-1,d+1),_x(n-1,d+1)]:` +
    `{a:_x(n-1,d+1),b:_x(n-2,d+1),c:d>2?{d:{e:{f:{g:{h:_x(n-1,d+1)}}}}}:n,` +
    `i:[_x(n-1,d+1),_x(n-1,d+2),_x(n-2,d+1)],` +
    `j:function(_a,_b,_c){return _a^_b^_c^n^d;}};` +
    `};` +
    `return null;` +
    `})();`;
  const noopAst = parser.parse(noopSrc, { sourceType: 'script' });
  ast.program.body.splice(mconstInsertIdx + mconstAst.program.body.length, 0, ...noopAst.program.body);

  // 2. Ghost control flow: for 30% of top-level ExpressionStatements, add a dead copy
  const newBody: t.Statement[] = [];
  for (const stmt of ast.program.body) {
    newBody.push(stmt);
    if (t.isExpressionStatement(stmt) && pseudoRand() < 0.3) {
      // Wrap clone in if (0 > 1) { ... }
      newBody.push(
        t.ifStatement(
          t.binaryExpression('>', t.numericLiteral(0), t.numericLiteral(1)),
          t.blockStatement([t.expressionStatement(t.cloneNode(stmt.expression, true))])
        )
      );
    }
  }
  ast.program.body = newBody;

  // 3. String dispersion: split StringLiterals length > 4 not already split into hex parts
  const dispReplacements: Array<{ path: import('@babel/traverse').NodePath<t.StringLiteral>; parts: string[] }> = [];

  traverse(ast, {
    StringLiteral(path) {
      const val = path.node.value;
      if (val.length <= 4) return;
      if (val.length > 500) return;
      if (path.parentPath?.isDirective()) return;
      if ((path.node as any)._split) return;
      // Don't re-process nodes already in string array or other processed
      const parent = path.parent;
      // Skip if already a call expression argument for _SD
      if (t.isCallExpression(parent) && t.isIdentifier((parent as t.CallExpression).callee) &&
          ((parent as t.CallExpression).callee as t.Identifier).name === '_SD') return;

      // Split into 2-3 parts
      const numParts = val.length > 10 ? 3 : 2;
      const partLen = Math.floor(val.length / numParts);
      const parts: string[] = [];
      for (let i = 0; i < numParts - 1; i++) {
        parts.push(val.slice(i * partLen, (i + 1) * partLen));
      }
      parts.push(val.slice((numParts - 1) * partLen));

      dispReplacements.push({ path, parts });
    }
  });

  for (const { path, parts } of dispReplacements) {
    // Convert each part to \xNN hex escapes
    function toHexPart(s: string): t.StringLiteral {
      let hex = '';
      for (let i = 0; i < s.length; i++) hex += '\\x' + s.charCodeAt(i).toString(16).padStart(2, '0');
      const node = t.stringLiteral(s);
      (node as any).extra = { raw: `'${hex}'`, rawValue: s };
      return node;
    }

    let expr: t.Expression = toHexPart(parts[0]);
    for (let i = 1; i < parts.length; i++) {
      expr = t.binaryExpression('+', expr, toHexPart(parts[i]));
    }
    path.replaceWith(expr);
  }
}

// Anti-analysis IIFE injected as raw string prepended to output.
const ANTI_ANALYSIS_CODE = `(function(){` +
  `var _g=typeof globalThis!=='undefined'?globalThis:(typeof window!=='undefined'?window:(typeof global!=='undefined'?global:{}));` +
  `var _checks=[` +
    `function(){try{return !!_g.callPhantom||!!_g._phantom||!!_g.Buffer&&!!_g.process&&_g.process.type==='renderer';}catch(e){return false;}},` +
    `function(){try{return !!(_g.navigator&&_g.navigator.webdriver);}catch(e){return false;}},` +
    `function(){try{return typeof _g.Proxy!=='undefined'&&(function(){var _h=false;var _p=new Proxy({},{get:function(){_h=true;return undefined;}});(''+_p);return _h;})();}catch(e){return false;}},` +
    `function(){try{var _d=new Date();(new Function('debugger'))();return Date.now()-_d>150;}catch(e){return false;}}` +
  `];` +
  `if(_checks.filter(function(f){return f();}).length>0){(function _inf(){_inf();})();}` +
`})();`;

// Rename all user-defined identifiers in already-generated code.
// Does NOT encrypt strings — safe to run on pass2 output containing binary data.
export function pass3(code: string, opts: Pass3Options = {}, buildId?: string): string {
  const doStringArray = opts.stringArray !== false;    // default true
  const doComputedProps = opts.computedProps !== false; // default true
  const doIntegrityTrap = opts.integrityTrap !== false; // default true
  const doAntiAnalysis = opts.antiAnalysis === true;    // default false
  const doCallStackCheck = opts.callStackCheck !== false; // default true
  const doAgentDisrupt = opts.agentDisrupt !== false;   // default true
  const doAntiLLM = opts.antiLLM === true;              // default false (opt-in)
  const doPoisonStringArray = opts.poisonStringArray === true || (doAntiLLM && opts.poisonStringArray !== false);
  const envKeyBind = opts.envKeyBind ?? false;

  const ast = parser.parse(code, {
    sourceType: 'script',
    // be permissive — this is generated code
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    errorRecovery: true as any,
  });

  const nextName = nameGen();
  const renameMap = new Map<string, string>();

  // Collect every scoped binding
  traverse(ast, {
    Scope(path) {
      for (const name of Object.keys(path.scope.bindings)) {
        if (!renameMap.has(name)) renameMap.set(name, nextName());
      }
    }
  });

  // Rename — skip property-position identifiers
  traverse(ast, {
    Identifier(path) {
      const obf = renameMap.get(path.node.name);
      if (!obf) return;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const par = path.parent as any;
      if (path.parentPath?.isMemberExpression() && par.property === path.node && !par.computed) return;
      if ((path.parentPath?.isObjectProperty() || path.parentPath?.isObjectMethod() ||
           path.parentPath?.isClassMethod()) && par.key === path.node && !par.computed) return;
      path.node.name = obf;
    }
  });

  if (opts.hexNumbers) {
    // Convert numeric literals to hex where they look like byte values
    traverse(ast, {
      NumericLiteral(path) {
        const v = path.node.value;
        if (Number.isInteger(v) && v >= 0 && v <= 0xFFFFFF && v !== 0) {
          // Replace with hex representation via extra node flags
          path.node.extra = { raw: '0x' + v.toString(16), rawValue: v };
        }
      }
    });
  }

  // String splitting — runs before string array so each half becomes a separate entry.
  // Long string literals (≥8 chars) are split at a randomised position into (a+b).
  // This forces double lookups in the string table for any string the analyst wants to
  // recover, and hides BigInt constants, cipher algorithm names, and LCG parameters.
  applyStringSplit(ast);

  // Poison string array: inject dead if(false) block with misleading strings BEFORE
  // applyStringArray so they get captured in the rotating array.
  if (doPoisonStringArray) injectPoisonStringArray(ast);

  // String array rotation — runs after rename so _SA/_SD get renamed too
  if (doStringArray) applyStringArray(ast);

  // Computed property rewriting — runs after string array to avoid re-processing _SD calls
  if (doComputedProps) applyComputedProps(ast);

  // Integrity trap — insert payload checksum guard
  if (doIntegrityTrap) applyIntegrityTrap(ast);

  // Anti-LLM noise layer (AST-level, before generate)
  if (doAntiLLM) injectAntiLLM(ast, buildId);

  let { code: out } = generate(ast, { compact: true, comments: false });

  // String-level injections (prepended/appended after generate)
  if (opts.selfDefend) out = injectSelfDefend(out);
  if (opts.debugProtection) out = injectDebugProtection(out);
  if (opts.deadCode) out = injectDeadCode(out);
  if (doAntiAnalysis) out = ANTI_ANALYSIS_CODE + out;
  // Call stack guard + agent disruption — prepended last so source-specific content
  // comes first and the first-100-chars structural check passes
  if (doCallStackCheck || doAgentDisrupt) {
    out = buildCallStackGuardCode({ callStackCheck: doCallStackCheck, agentDisrupt: doAgentDisrupt }) + out;
  }

  // Env key bind: XOR one key byte with runtime fingerprint — injected after guard
  const envKeyBindCode = buildEnvKeyBindCode(envKeyBind);
  if (envKeyBindCode) {
    out = `(function(){${envKeyBindCode}})();` + out;
  }

  return out;
}

// Anti-devtools: hang the page/process when DevTools are open (timing attack).
// Works in both browser and Node.js (node --inspect triggers debugger).
function injectSelfDefend(code: string): string {
  const guard = `(function(){` +
    `var _x=function(){};` +
    `var _c=_x.constructor("return this")();` +
    `var _f=(_c.Function||_c.eval||function(){});` +
    `try{_f("debugger");` +
    `var _i=setInterval(function(){` +
    `var _t=Date.now();` +
    `(new Function("debugger"))();` +
    `if(Date.now()-_t>200){_f("while(1){}");clearInterval(_i);}` +
    `},1500);}catch(e){}` +
    `})();`;
  return guard + code;
}

// Anti-debugger: periodic breakpoint-timing trap.
// Less aggressive than selfDefend — just fires debugger periodically.
function injectDebugProtection(code: string): string {
  const guard = `(function(){` +
    `try{` +
    `setInterval(function(){(new Function("debugger"))();},3000);` +
    `}catch(e){}` +
    `})();`;
  return guard + code;
}

// Dead code: inject meaningless but syntactically valid branches
// that confuse static analysis without affecting execution.
function injectDeadCode(code: string): string {
  // Insert after the opening of the outer wrapper
  const junk = `if(typeof _VXDEADCODE_==="undefined"){void 0;}`;
  return code.replace(/^\(function\(\)\{/, '(function(){' + junk);
}
