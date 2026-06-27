// vexil-obf runtime VM — do not modify
(function _vobf() {
  // ── Node type inverse permutation from seed _vS ──────────────────────────
  // Mirrors the Rust Fisher-Yates LCG shuffle exactly.
  // _vS is an array/Uint8Array of 8 bytes (big-endian u64 seed).
  function _buildInvPerm(seed) {
    var state = BigInt(0);
    for (var i = 0; i < 8; i++) {
      state = (state << BigInt(8)) | BigInt(seed[i]);
    }
    var p = Array.from({ length: 37 }, function (_, i) { return i; });
    var MUL = BigInt("6364136223846793005");
    var ADD = BigInt("1442695040888963407");
    var MASK = BigInt("18446744073709551615");
    for (var i = 36; i > 0; i--) {
      state = ((state * MUL) + ADD) & MASK;
      var j = Number(state >> BigInt(33)) % (i + 1);
      var t = p[i]; p[i] = p[j]; p[j] = t;
    }
    // p[canonical] = shuffled byte; build inverse: inv[shuffled] = canonical
    var inv = new Array(256).fill(255);
    for (var i = 0; i < 37; i++) inv[p[i]] = i;
    return inv;
  }

  var _vINV = _buildInvPerm(_vS);

  // ── Dispatch table (populated after helpers are defined, before _run) ─────
  // Forward-declared here; filled in after evalNode helpers are available.
  var _dt;

  // ── Base64 decode ────────────────────────────────────────────────────────
  function _b64decode(s) {
    var bin = atob(s);
    var u = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
    return u;
  }

  // ── AES-256-GCM decrypt (Web Crypto API) ─────────────────────────────────
  async function _decrypt(keyBytes, data) {
    var key = await crypto.subtle.importKey(
      "raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]
    );
    var iv = data.slice(0, 12);
    var ct = data.slice(12);
    var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ct);
    return new Uint8Array(pt);
  }

  // ── Binary reader ────────────────────────────────────────────────────────
  function Reader(buf) {
    this.buf = buf;
    this.pos = 0;
  }
  Reader.prototype.u8 = function () {
    return this.buf[this.pos++];
  };
  Reader.prototype.u16 = function () {
    var v = this.buf[this.pos] | (this.buf[this.pos + 1] << 8);
    this.pos += 2;
    return v;
  };
  Reader.prototype.f64 = function () {
    var view = new DataView(this.buf.buffer, this.buf.byteOffset + this.pos, 8);
    this.pos += 8;
    return view.getFloat64(0, true);
  };
  Reader.prototype.bytes = function (n) {
    var s = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return s;
  };
  Reader.prototype.str = function (n) {
    return new TextDecoder().decode(this.bytes(n));
  };

  // ── Parse binary payload ──────────────────────────────────────────────────
  // Returns { r, syms, strs } where r is positioned at the start of the AST.
  function _parse(buf) {
    var r = new Reader(buf);
    // header: magic(4) + version(1) + build_id(16) + node_seed(8) = 29 bytes
    r.pos += 4;  // magic "VOBF"
    r.u8();      // version
    r.bytes(16); // build_id
    r.bytes(8);  // node_seed (already available as _vS)

    // Feature 1: jump_key (2 bytes LE) — reserved, stored for future use
    var _jumpKey = r.u16(); // eslint-disable-line no-unused-vars

    // Feature 4: scope_key (4 bytes LE) — low byte used to XOR-decode symbol strings
    var _scopeKey = r.u16(); r.u16(); // consume all 4 bytes (two u16 reads)
    var _scopeKeyByte = _scopeKey & 0xFF;

    // symbol table — each symbol's bytes are XOR'd with _scopeKeyByte (Feature 4)
    var nSym = r.u16();
    var syms = [];
    for (var i = 0; i < nSym; i++) {
      var len = r.u8();
      var bytes = r.bytes(len);
      // decode: XOR each byte back
      var chars = [];
      for (var j = 0; j < len; j++) chars.push(bytes[j] ^ _scopeKeyByte);
      syms.push(String.fromCharCode.apply(null, chars));
    }

    // string table (not XOR-encoded)
    var nStr = r.u16();
    var strs = [];
    for (var i = 0; i < nStr; i++) {
      var len = r.u16();
      strs.push(r.str(len));
    }

    return { r: r, syms: syms, strs: strs };
  }

  // ── Scope (lexical chain) ─────────────────────────────────────────────────
  function Scope(parent) {
    this._p = parent || null;
    this._v = Object.create(null);
  }
  Scope.prototype.get = function (sym) {
    var s = this;
    while (s !== null) {
      if (sym in s._v) return s._v[sym];
      s = s._p;
    }
    // fall back to globalThis
    var _g = (typeof globalThis !== "undefined" ? globalThis : (typeof global !== "undefined" ? global : self));
    if (sym in _g) return _g[sym];
    throw new ReferenceError(sym + " is not defined");
  };
  Scope.prototype.set = function (sym, val) {
    var s = this;
    while (s !== null) {
      if (sym in s._v) { s._v[sym] = val; return; }
      s = s._p;
    }
    // not found anywhere — assign on this (top) scope
    this._v[sym] = val;
  };
  Scope.prototype.has = function (sym) {
    var s = this;
    while (s !== null) {
      if (sym in s._v) return true;
      s = s._p;
    }
    return false;
  };
  Scope.prototype.def = function (sym, val) {
    this._v[sym] = val;
  };

  // ── Control-flow sentinels ────────────────────────────────────────────────
  function Ret(v) { this.v = v; }
  function Brk() {}
  function Cnt() {}

  // ── Operator tables ───────────────────────────────────────────────────────
  // BIN_EXPR ops 0-24
  var BIN_OPS = [
    function (a, b) { return a + b; },          // 0  +
    function (a, b) { return a - b; },          // 1  -
    function (a, b) { return a * b; },          // 2  *
    function (a, b) { return a / b; },          // 3  /
    function (a, b) { return a % b; },          // 4  %
    function (a, b) { return a ** b; },         // 5  **
    function (a, b) { return a === b; },        // 6  ===
    function (a, b) { return a !== b; },        // 7  !==
    function (a, b) { return a == b; },         // 8  ==
    function (a, b) { return a != b; },         // 9  !=
    function (a, b) { return a < b; },          // 10 <
    function (a, b) { return a > b; },          // 11 >
    function (a, b) { return a <= b; },         // 12 <=
    function (a, b) { return a >= b; },         // 13 >=
    null,                                        // 14 && (short-circuit, handled inline)
    null,                                        // 15 || (short-circuit, handled inline)
    null,                                        // 16 ?? (short-circuit, handled inline)
    function (a, b) { return a & b; },          // 17 &
    function (a, b) { return a | b; },          // 18 |
    function (a, b) { return a ^ b; },          // 19 ^
    function (a, b) { return a << b; },         // 20 <<
    function (a, b) { return a >> b; },         // 21 >>
    function (a, b) { return a >>> b; },        // 22 >>>
    function (a, b) { return a in b; },         // 23 in
    function (a, b) { return a instanceof b; }, // 24 instanceof
  ];

  // ASSIGN_EXPR ops 0-15 (applied to current lhs value + rhs)
  var ASSIGN_OPS = [
    function (a, b) { return b; },        // 0  =
    function (a, b) { return a + b; },    // 1  +=
    function (a, b) { return a - b; },    // 2  -=
    function (a, b) { return a * b; },    // 3  *=
    function (a, b) { return a / b; },    // 4  /=
    function (a, b) { return a % b; },    // 5  %=
    function (a, b) { return a ** b; },   // 6  **=
    function (a, b) { return a & b; },    // 7  &=
    function (a, b) { return a | b; },    // 8  |=
    function (a, b) { return a ^ b; },    // 9  ^=
    function (a, b) { return a << b; },   // 10 <<=
    function (a, b) { return a >> b; },   // 11 >>=
    function (a, b) { return a >>> b; },  // 12 >>>=
    null,                                  // 13 ??= (short-circuit, handled inline)
    null,                                  // 14 &&= (short-circuit, handled inline)
    null,                                  // 15 ||= (short-circuit, handled inline)
  ];

  // ── skipNode: advance reader past a node without evaluating ───────────────
  // Must mirror evalNode's read pattern exactly for every node type.
  function skipNode(r, syms) {
    // Feature 2 & 3: consume decoy/stateful opcodes before the real node byte
    for (;;) {
      var _peek = r.buf[r.pos];
      if (_peek >= 200 && _peek <= 207) { // decoy
        r.pos++; var _dl = r.u8(); r.pos += _dl; continue;
      }
      if (_peek === 210 || _peek === 211) { // STATE_SET / STATE_XOR
        r.pos += 2; continue;
      }
      break;
    }
    var raw = r.u8();
    // Feature 5: macro-op opcodes 220-225 are raw bytes (not permuted)
    if (raw === 220) { // MACRO_CALL_MEMBER: obj_node + prop_len:u8 + prop_bytes + arg_count:u8 + args
      skipNode(r, syms); // object
      var _pl = r.u8(); r.pos += _pl; // property name
      var _ac = r.u8();
      for (var _i = 0; _i < _ac; _i++) skipNode(r, syms);
      return;
    }
    if (raw === 221) { // MACRO_BINARY_LIT: op_byte + left_node + lit_type + lit_value
      r.u8(); // op
      skipNode(r, syms); // left
      var _lt = r.u8();
      if (_lt === 0) r.pos += 8; // f64
      else if (_lt === 1) r.u16(); // str_idx
      else r.u8(); // bool
      return;
    }
    if (raw === 222) { // MACRO_RETURN_EXPR: expr_node
      skipNode(r, syms);
      return;
    }
    if (raw === 223) { // MACRO_ASSIGN_LIT: sym_idx:u16 + op_byte + lit_type + lit_value
      r.u16(); // sym_idx
      r.u8(); // op
      var _lt = r.u8();
      if (_lt === 0) r.pos += 8;
      else if (_lt === 1) r.u16();
      else r.u8();
      return;
    }
    if (raw === 224) { // MACRO_IF_BINARY: op_byte + left + right + consequent + has_alt:u8 + alt?
      r.u8(); // op
      skipNode(r, syms); // left
      skipNode(r, syms); // right
      skipNode(r, syms); // consequent
      var _ha = r.u8();
      if (_ha) skipNode(r, syms);
      return;
    }
    if (raw === 225) { // MACRO_VAR_INIT: scope_kind:u8 + sym_idx:u16 + init_node
      r.u8(); // scope_kind
      r.u16(); // sym_idx
      skipNode(r, syms); // init
      return;
    }
    var type = _vINV[raw];
    switch (type) {
      case 0: case 1: { // PROGRAM, BLOCK
        var n = r.u16();
        for (var i = 0; i < n; i++) skipNode(r, syms);
        break;
      }
      case 2: { // EXPR_STMT
        skipNode(r, syms);
        break;
      }
      case 3: { // VAR_DECL
        r.u8(); // kind
        var n = r.u16();
        for (var i = 0; i < n; i++) {
          r.u16(); // name_sym_idx
          var h = r.u8();
          if (h) skipNode(r, syms);
        }
        break;
      }
      case 4: case 5: { // FUNC_DECL, FUNC_EXPR
        var hn = r.u8(); if (hn) r.u16();
        var np = r.u16();
        for (var i = 0; i < np; i++) r.u16();
        skipNode(r, syms); // body block
        break;
      }
      case 6: { // ARROW_FUNC
        var np = r.u16();
        for (var i = 0; i < np; i++) r.u16();
        r.u8(); // expr_body flag
        skipNode(r, syms); // expr or block
        break;
      }
      case 7: { // RETURN_STMT
        var h = r.u8();
        if (h) skipNode(r, syms);
        break;
      }
      case 8: { // IF_STMT
        skipNode(r, syms); // test
        skipNode(r, syms); // consequent
        var h = r.u8();
        if (h) skipNode(r, syms); // alternate
        break;
      }
      case 9: { // WHILE_STMT
        skipNode(r, syms); // test
        skipNode(r, syms); // body
        break;
      }
      case 10: { // FOR_STMT
        var it = r.u8();
        if (it > 0) skipNode(r, syms); // init
        var ht = r.u8(); if (ht) skipNode(r, syms); // test
        var hu = r.u8(); if (hu) skipNode(r, syms); // update
        skipNode(r, syms); // body
        break;
      }
      case 11: case 12: { // FOR_OF_STMT, FOR_IN_STMT
        // left is a full VAR_DECL node (type byte + payload)
        skipNode(r, syms); // left var_decl
        skipNode(r, syms); // right
        skipNode(r, syms); // body
        break;
      }
      case 13: case 14: break; // BREAK_STMT, CONTINUE_STMT
      case 15: { skipNode(r, syms); break; } // THROW_STMT
      case 16: { // TRY_STMT
        skipNode(r, syms); // block
        var hh = r.u8();
        if (hh) {
          var hp = r.u8(); if (hp) r.u16();
          skipNode(r, syms); // handler block
        }
        var hf = r.u8();
        if (hf) skipNode(r, syms); // finalizer block
        break;
      }
      case 17: case 18: { // CALL_EXPR, NEW_EXPR
        skipNode(r, syms); // callee
        var n = r.u16();
        for (var i = 0; i < n; i++) skipNode(r, syms);
        break;
      }
      case 19: { // MEMBER_EXPR
        skipNode(r, syms); // obj
        r.u16(); // prop_sym_idx
        break;
      }
      case 20: { // COMPUTED_MEMBER
        skipNode(r, syms); skipNode(r, syms);
        break;
      }
      case 21: { // BIN_EXPR
        r.u8(); // op
        skipNode(r, syms); skipNode(r, syms);
        break;
      }
      case 22: { // UNARY_EXPR
        r.u8(); // op
        skipNode(r, syms);
        break;
      }
      case 23: { // ASSIGN_EXPR
        r.u8(); // op
        skipNode(r, syms); // left
        skipNode(r, syms); // right
        break;
      }
      case 24: { // COND_EXPR
        skipNode(r, syms); skipNode(r, syms); skipNode(r, syms);
        break;
      }
      case 25: { // SEQUENCE_EXPR
        var n = r.u16();
        for (var i = 0; i < n; i++) skipNode(r, syms);
        break;
      }
      case 26: { skipNode(r, syms); break; } // SPREAD_ELEM
      case 27: { r.u16(); break; } // IDENT
      case 28: { r.u16(); break; } // STRING_LIT
      case 29: { r.pos += 8; break; } // NUM_LIT (f64)
      case 30: { r.u8(); break; } // BOOL_LIT
      case 31: break; // NULL_LIT
      case 32: { // ARRAY_LIT
        var n = r.u16();
        for (var i = 0; i < n; i++) {
          var p = r.u8();
          if (p) skipNode(r, syms);
        }
        break;
      }
      case 33: { // OBJECT_LIT
        var n = r.u16();
        for (var i = 0; i < n; i++) {
          var kt = r.u8();
          if (kt < 2) r.u16();
          else skipNode(r, syms); // computed key
          skipNode(r, syms); // value
        }
        break;
      }
      case 34: { // TEMPLATE_LIT
        var nq = r.u16(); r.pos += nq * 2;
        var ne = r.u16();
        for (var i = 0; i < ne; i++) skipNode(r, syms);
        break;
      }
      case 35: { skipNode(r, syms); skipNode(r, syms); break; } // DO_WHILE_STMT: body + test
      case 36: break; // THIS_EXPR: no payload
      default:
        throw new Error("vobf skip: unknown type " + type + " (raw=" + raw + ")");
    }
  }

  // ── _skipNoise: advance past decoy/stateful opcodes before peeking ───────
  // Features 2 & 3: must call this before inspecting r.buf[r.pos] as a node type.
  function _skipNoise(r) {
    for (;;) {
      var _b = r.buf[r.pos];
      if (_b >= 200 && _b <= 207) { r.pos++; r.pos += r.u8(); continue; }
      if (_b === 210 || _b === 211) { r.pos += 2; continue; }
      break;
    }
  }

  // ── resolveAssignTarget ───────────────────────────────────────────────────
  // Read the LHS node and return { get(), set(v) } for assignment.
  function resolveAssignTarget(r, syms, strs, scope) {
    _skipNoise(r);
    var peekType = _vINV[r.buf[r.pos]];
    if (peekType === 27) { // IDENT
      r.u8(); // type byte
      var idx = r.u16();
      var name = syms[idx];
      return {
        get: function () { return scope.get(name); },
        set: function (v) { scope.set(name, v); },
      };
    }
    if (peekType === 19) { // MEMBER_EXPR obj.prop
      r.u8();
      var obj = evalNode(r, syms, strs, scope);
      var propIdx = r.u16();
      var prop = syms[propIdx];
      return {
        get: function () { return obj[prop]; },
        set: function (v) { obj[prop] = v; },
      };
    }
    if (peekType === 20) { // COMPUTED_MEMBER obj[expr]
      r.u8();
      var obj = evalNode(r, syms, strs, scope);
      var prop = evalNode(r, syms, strs, scope);
      return {
        get: function () { return obj[prop]; },
        set: function (v) { obj[prop] = v; },
      };
    }
    // Unsupported LHS pattern — skip and no-op.
    skipNode(r, syms);
    return { get: function () { return undefined; }, set: function () {} };
  }

  // ── resolveCalleeAndThis ──────────────────────────────────────────────────
  // Read callee node and return { fn, thisArg } preserving method receiver.
  function resolveCalleeAndThis(r, syms, strs, scope) {
    _skipNoise(r);
    var peekType = _vINV[r.buf[r.pos]];
    if (peekType === 19) { // MEMBER_EXPR obj.method(...)
      r.u8();
      var obj = evalNode(r, syms, strs, scope);
      var propIdx = r.u16();
      return { fn: obj[syms[propIdx]], thisArg: obj };
    }
    if (peekType === 20) { // COMPUTED_MEMBER obj[expr](...)
      r.u8();
      var obj = evalNode(r, syms, strs, scope);
      var prop = evalNode(r, syms, strs, scope);
      return { fn: obj[prop], thisArg: obj };
    }
    var fn = evalNode(r, syms, strs, scope);
    return { fn: fn, thisArg: undefined };
  }

  // ── Function factories ────────────────────────────────────────────────────
  function makeFn(params, bodyStart, buf, syms, strs, closureScope) {
    return function () {
      var fnScope = new Scope(closureScope);
      fnScope.def('__this__', this);
      for (var i = 0; i < params.length; i++) {
        fnScope.def(syms[params[i]], arguments[i]);
      }
      var r2 = new Reader(buf);
      r2.pos = bodyStart;
      var sig = evalNode(r2, syms, strs, fnScope);
      if (sig instanceof Ret) return sig.v;
      return undefined;
    };
  }

  function makeArrow(params, bodyStart, isExpr, buf, syms, strs, closureScope) {
    // Arrows capture `this` lexically from the enclosing scope
    var outerThis;
    try { outerThis = closureScope.get('__this__'); } catch(e) { outerThis = undefined; }
    return function () {
      var fnScope = new Scope(closureScope);
      fnScope.def('__this__', outerThis);
      for (var i = 0; i < params.length; i++) {
        fnScope.def(syms[params[i]], arguments[i]);
      }
      var r2 = new Reader(buf);
      r2.pos = bodyStart;
      if (isExpr) {
        return evalNode(r2, syms, strs, fnScope);
      }
      var sig = evalNode(r2, syms, strs, fnScope);
      if (sig instanceof Ret) return sig.v;
      return undefined;
    };
  }

  // ── Main evaluator ────────────────────────────────────────────────────────
  // Handlers indexed by canonical type id (0-36).
  var _handlers = [];

  // 0: PROGRAM / 1: BLOCK
  _handlers[0] = _handlers[1] = function(r, syms, strs, scope) {
    var n = r.u16();
    var last;
    for (var i = 0; i < n; i++) {
      last = evalNode(r, syms, strs, scope);
      if (last instanceof Ret || last instanceof Brk || last instanceof Cnt) {
        for (var j = i + 1; j < n; j++) skipNode(r, syms);
        return last;
      }
    }
    return last;
  };

  // 2: EXPR_STMT
  _handlers[2] = function(r, syms, strs, scope) {
    evalNode(r, syms, strs, scope);
    return undefined;
  };

  // 3: VAR_DECL
  _handlers[3] = function(r, syms, strs, scope) {
    r.u8(); // kind: 0=var 1=let 2=const
    var nd = r.u16();
    for (var i = 0; i < nd; i++) {
      var nameIdx = r.u16();
      var hasInit = r.u8();
      var val = hasInit ? evalNode(r, syms, strs, scope) : undefined;
      scope.def(syms[nameIdx], val);
    }
    return undefined;
  };

  // 4: FUNC_DECL / 5: FUNC_EXPR
  _handlers[4] = _handlers[5] = function(r, syms, strs, scope) {
    var hasName = r.u8();
    var nameIdx = hasName ? r.u16() : -1;
    var np = r.u16();
    var params = [];
    for (var i = 0; i < np; i++) params.push(r.u16());
    var bodyStart = r.pos;
    skipNode(r, syms);
    var fn = makeFn(params, bodyStart, r.buf, syms, strs, scope);
    if (hasName) scope.def(syms[nameIdx], fn);
    return fn;
  };

  // 6: ARROW_FUNC
  _handlers[6] = function(r, syms, strs, scope) {
    var np = r.u16();
    var params = [];
    for (var i = 0; i < np; i++) params.push(r.u16());
    var isExpr = r.u8();
    var bodyStart = r.pos;
    skipNode(r, syms);
    return makeArrow(params, bodyStart, isExpr, r.buf, syms, strs, scope);
  };

  // 7: RETURN_STMT
  _handlers[7] = function(r, syms, strs, scope) {
    var hasArg = r.u8();
    var val = hasArg ? evalNode(r, syms, strs, scope) : undefined;
    return new Ret(val);
  };

  // 8: IF_STMT
  _handlers[8] = function(r, syms, strs, scope) {
    var test = evalNode(r, syms, strs, scope);
    if (test) {
      var res = evalNode(r, syms, strs, scope);
      var hasAlt = r.u8();
      if (hasAlt) skipNode(r, syms);
      return res;
    } else {
      skipNode(r, syms);
      var hasAlt = r.u8();
      if (hasAlt) return evalNode(r, syms, strs, scope);
      return undefined;
    }
  };

  // 9: WHILE_STMT
  _handlers[9] = function(r, syms, strs, scope) {
    var testStart = r.pos;
    skipNode(r, syms);
    var bodyStart = r.pos;
    skipNode(r, syms);
    var end = r.pos;
    for (;;) {
      r.pos = testStart;
      if (!evalNode(r, syms, strs, scope)) break;
      r.pos = bodyStart;
      var sig = evalNode(r, syms, strs, scope);
      if (sig instanceof Ret) { r.pos = end; return sig; }
      if (sig instanceof Brk) break;
    }
    r.pos = end;
    return undefined;
  };

  // 10: FOR_STMT
  _handlers[10] = function(r, syms, strs, scope) {
    var loopScope = new Scope(scope);
    var initType = r.u8();
    if (initType === 1 || initType === 2) {
      evalNode(r, syms, strs, loopScope);
    }
    var hasTest = r.u8();
    var testStart = r.pos;
    if (hasTest) skipNode(r, syms);
    var hasUpd = r.u8();
    var updStart = r.pos;
    if (hasUpd) skipNode(r, syms);
    var bodyStart = r.pos;
    skipNode(r, syms);
    var end = r.pos;
    for (;;) {
      if (hasTest) {
        r.pos = testStart;
        if (!evalNode(r, syms, strs, loopScope)) break;
      }
      r.pos = bodyStart;
      var sig = evalNode(r, syms, strs, loopScope);
      if (sig instanceof Ret) { r.pos = end; return sig; }
      if (sig instanceof Brk) break;
      if (hasUpd) { r.pos = updStart; evalNode(r, syms, strs, loopScope); }
    }
    r.pos = end;
    return undefined;
  };

  // 11: FOR_OF_STMT
  _handlers[11] = function(r, syms, strs, scope) {
    r.u8(); // VAR_DECL type byte (shuffled)
    r.u8(); // kind
    r.u16(); // n_decl (always 1 here)
    var nameIdx = r.u16();
    r.u8(); // has_init = 0
    var right = evalNode(r, syms, strs, scope);
    var bodyStart = r.pos;
    skipNode(r, syms);
    var end = r.pos;
    for (var _item of right) {
      var iterScope = new Scope(scope);
      iterScope.def(syms[nameIdx], _item);
      r.pos = bodyStart;
      var sig = evalNode(r, syms, strs, iterScope);
      if (sig instanceof Ret) { r.pos = end; return sig; }
      if (sig instanceof Brk) break;
    }
    r.pos = end;
    return undefined;
  };

  // 12: FOR_IN_STMT
  _handlers[12] = function(r, syms, strs, scope) {
    r.u8(); // VAR_DECL type byte
    r.u8(); // kind
    r.u16(); // n_decl
    var nameIdx = r.u16();
    r.u8(); // has_init
    var right = evalNode(r, syms, strs, scope);
    var bodyStart = r.pos;
    skipNode(r, syms);
    var end = r.pos;
    for (var _key in right) {
      var iterScope = new Scope(scope);
      iterScope.def(syms[nameIdx], _key);
      r.pos = bodyStart;
      var sig = evalNode(r, syms, strs, iterScope);
      if (sig instanceof Ret) { r.pos = end; return sig; }
      if (sig instanceof Brk) break;
    }
    r.pos = end;
    return undefined;
  };

  // 13: BREAK_STMT
  _handlers[13] = function(r, syms, strs, scope) {
    return new Brk();
  };

  // 14: CONTINUE_STMT
  _handlers[14] = function(r, syms, strs, scope) {
    return new Cnt();
  };

  // 15: THROW_STMT
  _handlers[15] = function(r, syms, strs, scope) {
    throw evalNode(r, syms, strs, scope);
  };

  // 16: TRY_STMT
  _handlers[16] = function(r, syms, strs, scope) {
    var blockStart = r.pos;
    skipNode(r, syms);

    var hasHandler = r.u8();
    var handlerParamIdx = -1;
    var handlerBodyStart = -1;
    if (hasHandler) {
      var hp = r.u8();
      if (hp) handlerParamIdx = r.u16();
      handlerBodyStart = r.pos;
      skipNode(r, syms);
    }

    var hasFinally = r.u8();
    var finallyStart = r.pos;
    if (hasFinally) skipNode(r, syms);
    var end = r.pos;

    var result;
    try {
      r.pos = blockStart;
      result = evalNode(r, syms, strs, scope);
    } catch (e) {
      if (hasHandler) {
        var catchScope = new Scope(scope);
        if (handlerParamIdx >= 0) catchScope.def(syms[handlerParamIdx], e);
        r.pos = handlerBodyStart;
        result = evalNode(r, syms, strs, catchScope);
      } else {
        throw e;
      }
    } finally {
      if (hasFinally) {
        r.pos = finallyStart;
        evalNode(r, syms, strs, scope);
      }
    }

    r.pos = end;
    return result;
  };

  // 17: CALL_EXPR
  _handlers[17] = function(r, syms, strs, scope) {
    var ct = resolveCalleeAndThis(r, syms, strs, scope);
    var na = r.u16();
    var args = [];
    for (var i = 0; i < na; i++) {
      _skipNoise(r);
      if (_vINV[r.buf[r.pos]] === 26) { // SPREAD_ELEM
        r.u8();
        var sv = evalNode(r, syms, strs, scope);
        for (var j = 0; j < sv.length; j++) args.push(sv[j]);
      } else {
        args.push(evalNode(r, syms, strs, scope));
      }
    }
    return ct.fn.apply(ct.thisArg, args);
  };

  // 18: NEW_EXPR
  _handlers[18] = function(r, syms, strs, scope) {
    var callee = evalNode(r, syms, strs, scope);
    var na = r.u16();
    var args = [];
    for (var i = 0; i < na; i++) {
      _skipNoise(r);
      if (_vINV[r.buf[r.pos]] === 26) { // SPREAD_ELEM
        r.u8();
        var sv = evalNode(r, syms, strs, scope);
        for (var j = 0; j < sv.length; j++) args.push(sv[j]);
      } else {
        args.push(evalNode(r, syms, strs, scope));
      }
    }
    return new (Function.prototype.bind.apply(callee, [null].concat(args)))();
  };

  // 19: MEMBER_EXPR (obj.prop)
  _handlers[19] = function(r, syms, strs, scope) {
    var obj = evalNode(r, syms, strs, scope);
    var propIdx = r.u16();
    return obj[syms[propIdx]];
  };

  // 20: COMPUTED_MEMBER (obj[expr])
  _handlers[20] = function(r, syms, strs, scope) {
    var obj = evalNode(r, syms, strs, scope);
    var prop = evalNode(r, syms, strs, scope);
    return obj[prop];
  };

  // 21: BIN_EXPR
  _handlers[21] = function(r, syms, strs, scope) {
    var op = r.u8();
    if (op === 14) { // &&
      var left = evalNode(r, syms, strs, scope);
      if (!left) { skipNode(r, syms); return left; }
      return evalNode(r, syms, strs, scope);
    }
    if (op === 15) { // ||
      var left = evalNode(r, syms, strs, scope);
      if (left) { skipNode(r, syms); return left; }
      return evalNode(r, syms, strs, scope);
    }
    if (op === 16) { // ??
      var left = evalNode(r, syms, strs, scope);
      if (left !== null && left !== undefined) { skipNode(r, syms); return left; }
      return evalNode(r, syms, strs, scope);
    }
    var left = evalNode(r, syms, strs, scope);
    var right = evalNode(r, syms, strs, scope);
    return BIN_OPS[op](left, right);
  };

  // 22: UNARY_EXPR (includes prefix/postfix update)
  _handlers[22] = function(r, syms, strs, scope) {
    var op = r.u8();
    if (op === 7) { // prefix ++
      var tgt = resolveAssignTarget(r, syms, strs, scope);
      var nv = tgt.get() + 1; tgt.set(nv); return nv;
    }
    if (op === 8) { // prefix --
      var tgt = resolveAssignTarget(r, syms, strs, scope);
      var nv = tgt.get() - 1; tgt.set(nv); return nv;
    }
    if (op === 9) { // postfix ++
      var tgt = resolveAssignTarget(r, syms, strs, scope);
      var ov = tgt.get(); tgt.set(ov + 1); return ov;
    }
    if (op === 10) { // postfix --
      var tgt = resolveAssignTarget(r, syms, strs, scope);
      var ov = tgt.get(); tgt.set(ov - 1); return ov;
    }
    var arg = evalNode(r, syms, strs, scope);
    switch (op) {
      case 0: return !arg;
      case 1: return -arg;
      case 2: return +arg;
      case 3: return ~arg;
      case 4: return void arg;
      case 5: return delete arg;
      case 6: return typeof arg;
    }
    throw new Error("vobf: unknown unary op " + op);
  };

  // 23: ASSIGN_EXPR
  _handlers[23] = function(r, syms, strs, scope) {
    var op = r.u8();
    var tgt = resolveAssignTarget(r, syms, strs, scope);
    var rhs = evalNode(r, syms, strs, scope);
    var newVal;
    if (op === 13) { // ??=
      newVal = (tgt.get() !== null && tgt.get() !== undefined) ? tgt.get() : rhs;
    } else if (op === 14) { // &&=
      var cur = tgt.get(); newVal = cur ? rhs : cur;
    } else if (op === 15) { // ||=
      var cur = tgt.get(); newVal = cur ? cur : rhs;
    } else {
      newVal = ASSIGN_OPS[op](tgt.get(), rhs);
    }
    tgt.set(newVal);
    return newVal;
  };

  // 24: COND_EXPR
  _handlers[24] = function(r, syms, strs, scope) {
    var test = evalNode(r, syms, strs, scope);
    var consStart = r.pos; skipNode(r, syms);
    var altStart = r.pos; skipNode(r, syms);
    var end = r.pos;
    if (test) {
      r.pos = consStart;
      var v = evalNode(r, syms, strs, scope);
      r.pos = end;
      return v;
    } else {
      r.pos = altStart;
      var v = evalNode(r, syms, strs, scope);
      r.pos = end;
      return v;
    }
  };

  // 25: SEQUENCE_EXPR
  _handlers[25] = function(r, syms, strs, scope) {
    var n = r.u16();
    var last;
    for (var i = 0; i < n; i++) last = evalNode(r, syms, strs, scope);
    return last;
  };

  // 26: SPREAD_ELEM (bare, caller handles expansion)
  _handlers[26] = function(r, syms, strs, scope) {
    return evalNode(r, syms, strs, scope);
  };

  // 27: IDENT
  _handlers[27] = function(r, syms, strs, scope) {
    var idx = r.u16();
    return scope.get(syms[idx]);
  };

  // 28: STRING_LIT
  _handlers[28] = function(r, syms, strs, scope) {
    return strs[r.u16()];
  };

  // 29: NUM_LIT
  _handlers[29] = function(r, syms, strs, scope) {
    return r.f64();
  };

  // 30: BOOL_LIT
  _handlers[30] = function(r, syms, strs, scope) {
    return r.u8() !== 0;
  };

  // 31: NULL_LIT
  _handlers[31] = function(r, syms, strs, scope) {
    return null;
  };

  // 32: ARRAY_LIT
  _handlers[32] = function(r, syms, strs, scope) {
    var n = r.u16();
    var arr = [];
    for (var i = 0; i < n; i++) {
      var present = r.u8();
      if (present) {
        if (_vINV[r.buf[r.pos]] === 26) { // SPREAD_ELEM
          r.u8();
          var sv = evalNode(r, syms, strs, scope);
          for (var j = 0; j < sv.length; j++) arr.push(sv[j]);
        } else {
          arr.push(evalNode(r, syms, strs, scope));
        }
      } else {
        arr.push(undefined);
      }
    }
    return arr;
  };

  // 33: OBJECT_LIT
  _handlers[33] = function(r, syms, strs, scope) {
    var n = r.u16();
    var obj = {};
    for (var i = 0; i < n; i++) {
      var kt = r.u8(); // 0=ident 1=str (both index into sym table), other=computed
      var key;
      if (kt === 0 || kt === 1) {
        key = syms[r.u16()];
      } else {
        key = evalNode(r, syms, strs, scope);
      }
      obj[key] = evalNode(r, syms, strs, scope);
    }
    return obj;
  };

  // 34: TEMPLATE_LIT
  _handlers[34] = function(r, syms, strs, scope) {
    var nq = r.u16();
    var quasis = [];
    for (var i = 0; i < nq; i++) quasis.push(strs[r.u16()]);
    var ne = r.u16();
    var exprs = [];
    for (var i = 0; i < ne; i++) exprs.push(evalNode(r, syms, strs, scope));
    var result = quasis[0];
    for (var i = 0; i < ne; i++) result += String(exprs[i]) + quasis[i + 1];
    return result;
  };

  // 35: DO_WHILE_STMT
  _handlers[35] = function(r, syms, strs, scope) {
    var doBodyStart = r.pos;
    skipNode(r, syms);
    var doTestStart = r.pos;
    skipNode(r, syms);
    var doEnd = r.pos;

    var doCond = true;
    while (doCond) {
      var rb = new Reader(r.buf);
      rb.pos = doBodyStart;
      var sig = evalNode(rb, syms, strs, scope);
      if (sig instanceof Ret) { r.pos = doEnd; return sig; }
      if (sig instanceof Brk) break;

      var rt = new Reader(r.buf);
      rt.pos = doTestStart;
      doCond = evalNode(rt, syms, strs, scope);
    }
    r.pos = doEnd;
    return undefined;
  };

  // 36: THIS_EXPR
  _handlers[36] = function(r, syms, strs, scope) {
    return scope.get('__this__');
  };

  // Build dispatch table: _dt[encoded_id] = _handlers[canonical_id]
  _dt = new Array(37);
  for (var _dti = 0; _dti < 37; _dti++) {
    _dt[_dti] = _handlers[_vINV[_dti]];
  }

  // Feature 3: stateful accumulator — tracked but not used in real value computation.
  // Exists to make the bytecode stateful so static analysis must track _vmAcc correctly.
  var _vmAcc = 0;

  function evalNode(r, syms, strs, scope) {
    for (;;) {
      var raw = r.u8();
      // Feature 2: decoy opcodes 200..207 — skip payload and continue dispatch
      if (raw >= 200 && raw <= 207) {
        var _dLen = r.u8();
        r.pos += _dLen;
        continue;
      }
      // Feature 3: stateful opcodes
      if (raw === 210) { // STATE_SET
        _vmAcc = r.u8();
        continue;
      }
      if (raw === 211) { // STATE_XOR
        _vmAcc ^= r.u8();
        continue;
      }
      // Feature 5: macro-op opcodes 220-225 (raw bytes, not permuted)
      if (raw === 220) { // MACRO_CALL_MEMBER: obj_node + prop_len:u8 + prop_bytes + arg_count:u8 + args
        var _obj = evalNode(r, syms, strs, scope);
        var _pl = r.u8();
        var _prop = r.str(_pl);
        var _ac = r.u8();
        var _args = [];
        for (var _i = 0; _i < _ac; _i++) _args.push(evalNode(r, syms, strs, scope));
        return _obj[_prop].apply(_obj, _args);
      }
      if (raw === 221) { // MACRO_BINARY_LIT: op_byte + left_node + lit_type + lit_value
        var _op = r.u8();
        var _left = evalNode(r, syms, strs, scope);
        var _lt = r.u8();
        var _rval;
        if (_lt === 0) _rval = r.f64();
        else if (_lt === 1) _rval = strs[r.u16()];
        else _rval = r.u8() !== 0;
        // short-circuit ops
        if (_op === 14) return _left && _rval; // &&
        if (_op === 15) return _left || _rval; // ||
        if (_op === 16) return (_left !== null && _left !== undefined) ? _left : _rval; // ??
        return BIN_OPS[_op](_left, _rval);
      }
      if (raw === 222) { // MACRO_RETURN_EXPR: expr_node
        return new Ret(evalNode(r, syms, strs, scope));
      }
      if (raw === 223) { // MACRO_ASSIGN_LIT: sym_idx:u16 + op_byte + lit_type + lit_value
        var _sidx = r.u16();
        var _name = syms[_sidx];
        var _op = r.u8();
        var _lt = r.u8();
        var _rval;
        if (_lt === 0) _rval = r.f64();
        else if (_lt === 1) _rval = strs[r.u16()];
        else _rval = r.u8() !== 0;
        var _newVal = ASSIGN_OPS[_op](scope.get(_name), _rval);
        scope.set(_name, _newVal);
        return _newVal;
      }
      if (raw === 224) { // MACRO_IF_BINARY: op_byte + left + right + consequent + has_alt:u8 + alt?
        var _op = r.u8();
        var _left = evalNode(r, syms, strs, scope);
        var _right = evalNode(r, syms, strs, scope);
        var _cond;
        if (_op === 14) _cond = _left && _right;
        else if (_op === 15) _cond = _left || _right;
        else if (_op === 16) _cond = (_left !== null && _left !== undefined) ? _left : _right;
        else _cond = BIN_OPS[_op](_left, _right);
        if (_cond) {
          var _res = evalNode(r, syms, strs, scope); // consequent
          var _ha = r.u8();
          if (_ha) skipNode(r, syms);
          return _res;
        } else {
          skipNode(r, syms); // consequent
          var _ha = r.u8();
          if (_ha) return evalNode(r, syms, strs, scope);
          return undefined;
        }
      }
      if (raw === 225) { // MACRO_VAR_INIT: scope_kind:u8 + sym_idx:u16 + init_node
        r.u8(); // scope_kind (let/const/var — all def to current scope)
        var _sidx = r.u16();
        var _val = evalNode(r, syms, strs, scope);
        scope.def(syms[_sidx], _val);
        return undefined;
      }
      var _h = _dt[raw];
      if (!_h) throw new Error("[vobf] t:" + raw);
      return _h(r, syms, strs, scope);
    }
  }

  // ── Shared runner — called once plaintext bytes are available ────────────
  function _run(plaintext) {
    var parsed = _parse(plaintext);

    var _g = (typeof globalThis !== "undefined"
      ? globalThis
      : (typeof global !== "undefined" ? global : (typeof self !== "undefined" ? self : {})));

    var globalScope = new Scope(null);

    var _wellKnown = [
      "console", "process", "require", "module", "exports",
      "__dirname", "__filename",
      "setTimeout", "clearTimeout", "setInterval", "clearInterval",
      "queueMicrotask", "Promise",
      "JSON", "Math", "Object", "Array", "String", "Number", "Boolean",
      "Function", "Error", "TypeError", "RangeError", "SyntaxError",
      "ReferenceError", "URIError", "EvalError",
      "Map", "Set", "WeakMap", "WeakSet",
      "Date", "RegExp", "Symbol", "BigInt",
      "Uint8Array", "Uint16Array", "Uint32Array",
      "Int8Array", "Int16Array", "Int32Array",
      "Float32Array", "Float64Array",
      "ArrayBuffer", "DataView", "SharedArrayBuffer",
      "TextEncoder", "TextDecoder",
      "URL", "URLSearchParams",
      "fetch", "WebSocket", "crypto", "performance",
      "document", "window", "navigator", "location", "history",
      "addEventListener", "removeEventListener", "dispatchEvent",
      "globalThis", "undefined", "NaN", "Infinity",
      "isNaN", "isFinite", "parseInt", "parseFloat",
      "encodeURIComponent", "decodeURIComponent",
      "encodeURI", "decodeURI", "atob", "btoa",
    ];

    for (var i = 0; i < _wellKnown.length; i++) {
      var _n = _wellKnown[i];
      try { if (_n in _g) globalScope.def(_n, _g[_n]); } catch (e) {}
    }

    // CommonJS — bind the *live* objects so assignments propagate back
    if (typeof module   !== "undefined") globalScope.def("module",     module);
    if (typeof exports  !== "undefined") globalScope.def("exports",    exports);
    if (typeof require  !== "undefined") globalScope.def("require",    require);
    if (typeof __dirname  !== "undefined") globalScope.def("__dirname",  __dirname);
    if (typeof __filename !== "undefined") globalScope.def("__filename", __filename);

    // Browser globals shorthand
    if (typeof window !== "undefined") {
      globalScope.def("window", window);
      globalScope.def("self", window);
    }

    evalNode(parsed.r, parsed.syms, parsed.strs, globalScope);
  }

  // ── Anti-hook: corrupt key if Function.prototype.toString is replaced ────
  // Hooking toString on dispatch functions is the standard technique for dumping
  // decrypted bytecode without re-implementing the cipher.  If the hook is
  // detected here, _vK is zeroed so AES-GCM decryption fails silently.
  (function() {
    try {
      var _fpt = Function.prototype.toString;
      var _probe = function(){};
      var _sig = _fpt.call(_probe);
      if (typeof _sig !== "string" || _sig.indexOf("function") < 0) {
        for (var _zi = 0; _zi < 32; _zi++) _vK[_zi] = 0;
      }
    } catch(_ex) {
      for (var _zi = 0; _zi < 32; _zi++) _vK[_zi] = 0;
    }
  })();

  // ── Entry point: Node.js sync path (keeps module.exports working) ────────
  var _done = false;
  var _syncPt = null;

  if (typeof require !== "undefined" && typeof process !== "undefined") {
    try {
      var _nc  = require("crypto");
      var _raw = Buffer.from(_vP, "base64");
      var _iv  = _raw.slice(0, 12);
      var _tag = _raw.slice(_raw.length - 16);
      var _ct  = _raw.slice(12, _raw.length - 16);
      var _dc  = _nc.createDecipheriv("aes-256-gcm", Buffer.from(_vK), _iv);
      _dc.setAuthTag(_tag);
      _syncPt = new Uint8Array(Buffer.concat([_dc.update(_ct), _dc.final()]));
      _done = true;
    } catch (_e) {
      // not Node.js or crypto unavailable — fall through to async path
    }
  }

  // Run outside try/catch so VM errors surface properly
  if (_done && _syncPt) {
    _run(_syncPt);
    if (typeof __vx_done_cb === "function") __vx_done_cb();
  }

  // ── Entry point: browser async path (SubtleCrypto) ───────────────────────
  if (!_done) {
    (async function () {
      var keyBuf  = new Uint8Array(_vK);
      var encData = _b64decode(_vP);
      var plain   = await _decrypt(keyBuf, encData);
      _run(plain);
      if (typeof __vx_done_cb === "function") __vx_done_cb();
    })().catch(function (e) { console.error("[vobf]", e); });
  }
})();
