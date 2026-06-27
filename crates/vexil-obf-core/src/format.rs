use crate::error::ObfError;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Symbol table
// ---------------------------------------------------------------------------

pub struct SymbolTable {
    symbols: Vec<String>,
    strings: Vec<String>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            strings: Vec::new(),
        }
    }

    fn add_sym(&mut self, name: String) -> u16 {
        if let Some(i) = self.symbols.iter().position(|s| s == &name) {
            return i as u16;
        }
        let i = self.symbols.len() as u16;
        self.symbols.push(name);
        i
    }

    fn add_str(&mut self, val: String) -> u16 {
        if let Some(i) = self.strings.iter().position(|s| s == &val) {
            return i as u16;
        }
        let i = self.strings.len() as u16;
        self.strings.push(val);
        i
    }

    pub fn sym_idx(&self, name: &str) -> Option<u16> {
        self.symbols
            .iter()
            .position(|s| s == name)
            .map(|i| i as u16)
    }

    pub fn str_idx(&self, val: &str) -> Option<u16> {
        self.strings.iter().position(|s| s == val).map(|i| i as u16)
    }

    /// Recursively walk the Babel AST JSON and collect all identifier names
    /// and string literal values.
    pub fn collect(ast: &Value) -> Self {
        let mut table = Self::new();
        table.walk(ast);
        table
    }

    fn walk(&mut self, node: &Value) {
        match node {
            Value::Object(map) => {
                if let Some(Value::String(ty)) = map.get("type") {
                    match ty.as_str() {
                        "Identifier" => {
                            if let Some(Value::String(name)) = map.get("name") {
                                self.add_sym(name.clone());
                            }
                        }
                        "StringLiteral" => {
                            if let Some(Value::String(val)) = map.get("value") {
                                self.add_str(val.clone());
                            }
                        }
                        "TemplateElement" => {
                            // quasis carry their value in value.raw and value.cooked
                            if let Some(Value::Object(v)) = map.get("value") {
                                if let Some(Value::String(cooked)) = v.get("cooked") {
                                    self.add_str(cooked.clone());
                                } else if let Some(Value::String(raw)) = v.get("raw") {
                                    self.add_str(raw.clone());
                                }
                            }
                        }
                        _ => {}
                    }
                }
                for v in map.values() {
                    self.walk(v);
                }
            }
            Value::Array(arr) => {
                for v in arr {
                    self.walk(v);
                }
            }
            _ => {}
        }
    }

    /// Encode the symbol and string tables to their wire format (no scope encoding).
    ///
    /// Symbol table: u16 n_syms, then for each: u8 len, bytes…
    /// String table: u16 n_strs, then for each: u16 len, bytes…
    pub fn encode(&self) -> Result<Vec<u8>, crate::ObfError> {
        self.encode_with_scope_key(0)
    }

    /// Encode with scope_key_byte XOR applied to all symbol string bytes (Feature 4).
    /// String table is NOT XOR-encoded (strings are not used as scope keys).
    pub fn encode_with_scope_key(&self, scope_key_byte: u8) -> Result<Vec<u8>, crate::ObfError> {
        let mut out = Vec::new();
        push_u16(&mut out, self.symbols.len() as u16);
        for s in &self.symbols {
            let b = s.as_bytes();
            if b.len() > 255 {
                return Err(crate::ObfError::Encode(format!(
                    "symbol too long ({} bytes, max 255): {}",
                    b.len(),
                    &s[..32.min(s.len())]
                )));
            }
            out.push(b.len() as u8);
            // XOR each symbol byte with scope_key_byte (0 = no-op for legacy encode())
            for &byte in b {
                out.push(byte ^ scope_key_byte);
            }
        }
        push_u16(&mut out, self.strings.len() as u16);
        for s in &self.strings {
            let b = s.as_bytes();
            push_u16(&mut out, b.len() as u16);
            out.extend_from_slice(b);
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Fisher-Yates permutation (LCG)
// ---------------------------------------------------------------------------

/// Build the canonical->shuffled permutation using the 8-byte seed.
pub fn build_perm(seed: &[u8; 8]) -> [u8; 37] {
    let mut state = u64::from_be_bytes(*seed);
    let mut perm: [u8; 37] = core::array::from_fn(|i| i as u8);

    for i in (1usize..37).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005u64)
            .wrapping_add(1_442_695_040_888_963_407u64);
        let j = ((state >> 33) as usize) % (i + 1);
        perm.swap(i, j);
    }
    perm
}

// ---------------------------------------------------------------------------
// Binary AST encoder
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Decoy and stateful opcode constants (Features 2 & 3)
// ---------------------------------------------------------------------------

/// Decoy opcode range: 200..=207 (outside the 0..=36 shuffled node type range).
/// Format: [decoy_byte: u8][payload_len: u8][payload: payload_len bytes]
const DECOY_OPCODES: [u8; 8] = [200, 201, 202, 203, 204, 205, 206, 207];

/// STATE_SET opcode: read 1 byte, set _vmAcc = byte
const OP_STATE_SET: u8 = 210;

/// STATE_XOR opcode: read 1 byte, _vmAcc ^= byte
const OP_STATE_XOR: u8 = 211;

/// Simple LCG for deterministic pseudo-random decisions during encoding.
struct Lcg(u64);

impl Lcg {
    fn new(seed: &[u8; 8]) -> Self {
        let s = u64::from_le_bytes(*seed);
        // mix to avoid low-entropy starting points
        let s = s
            .wrapping_mul(0x9e3779b97f4a7c15)
            .wrapping_add(0x6c62272e07bb0142);
        Self(if s == 0 { 1 } else { s })
    }

    fn next(&mut self) -> u8 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005u64)
            .wrapping_add(1_442_695_040_888_963_407u64);
        (self.0 >> 56) as u8
    }
}

/// Encoder context carrying the permutation and LCG state for decoy/stateful injection.
struct EncCtx<'a> {
    perm: [u8; 37],
    syms: &'a SymbolTable,
    lcg: Lcg,
    /// vm_state accumulator for Feature 3
    vm_state: u8,
    /// how many real nodes since last STATE_XOR injection
    nodes_since_state: u32,
}

impl<'a> EncCtx<'a> {
    fn new(syms: &'a SymbolTable, seed: &[u8; 8]) -> Self {
        let perm = build_perm(seed);
        let lcg = Lcg::new(seed);
        let vm_state = seed[2]; // initial state = 3rd seed byte
        Self {
            perm,
            syms,
            lcg,
            vm_state,
            nodes_since_state: 0,
        }
    }

    /// Emit a decoy sequence (Feature 2) with 20% probability.
    fn maybe_emit_decoy(&mut self, out: &mut Vec<u8>) {
        // 20% chance: lcg next byte < 51  (51/256 ≈ 20%)
        let roll = self.lcg.next();
        if roll >= 51 {
            return;
        }
        let opcode_idx = (self.lcg.next() as usize) % DECOY_OPCODES.len();
        let decoy_byte = DECOY_OPCODES[opcode_idx];
        let payload_len = 1 + (self.lcg.next() % 4); // 1..=4 bytes
        out.push(decoy_byte);
        out.push(payload_len);
        for _ in 0..payload_len {
            out.push(self.lcg.next());
        }
    }

    /// Emit a STATE_XOR opcode (Feature 3) with roughly 1/20 node frequency.
    fn maybe_emit_state_xor(&mut self, out: &mut Vec<u8>) {
        self.nodes_since_state += 1;
        // inject every 15-25 nodes (threshold derived from lcg)
        let threshold = 15 + (self.lcg.next() % 11); // 15..=25
        if self.nodes_since_state < threshold as u32 {
            return;
        }
        self.nodes_since_state = 0;
        let delta = self.lcg.next();
        out.push(OP_STATE_XOR);
        out.push(delta);
        self.vm_state ^= delta;
    }
}

/// Encode the Babel AST to binary.  Returns only the AST bytes (no header/tables).
/// Includes Feature 2 (decoy opcodes) and Feature 3 (stateful opcodes).
pub fn encode_ast(ast: &Value, syms: &SymbolTable, seed: &[u8; 8]) -> Result<Vec<u8>, ObfError> {
    let mut ctx = EncCtx::new(syms, seed);
    let mut out = Vec::new();

    // Feature 3: emit STATE_SET at the very start to initialize _vmAcc
    out.push(OP_STATE_SET);
    out.push(ctx.vm_state);

    write_node_ctx(&mut out, ast, &mut ctx)?;
    Ok(out)
}

/// Write a node with decoy/state opcode injection before it (Features 2 & 3).
fn write_node_ctx(out: &mut Vec<u8>, node: &Value, ctx: &mut EncCtx) -> Result<(), ObfError> {
    ctx.maybe_emit_decoy(out);
    ctx.maybe_emit_state_xor(out);
    // Must not pass `ctx` into write_node here — write_body handles body injection;
    // at this top-level call we only want the noise already emitted above.
    wn(out, node, ctx.syms, &ctx.perm)
}

// ---------------------------------------------------------------------------
// Node writers
// ---------------------------------------------------------------------------

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_f64(out: &mut Vec<u8>, v: f64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn push_type(out: &mut Vec<u8>, canonical: u8, perm: &[u8; 37]) {
    debug_assert!(
        (canonical as usize) < perm.len(),
        "canonical node type out of range: {}",
        canonical
    );
    out.push(perm[canonical as usize]);
}

fn get_str(node: &Value, key: &str) -> Option<String> {
    node.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn get_bool(node: &Value, key: &str) -> bool {
    node.get(key).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn get_array<'a>(node: &'a Value, key: &str) -> &'a [Value] {
    node.get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or(&[])
}

/// Emit a fallback EXPR_STMT containing a string literal for unsupported nodes.
fn write_unsupported(
    out: &mut Vec<u8>,
    type_str: &str,
    syms: &SymbolTable,
    perm: &[u8; 37],
) -> Result<(), ObfError> {
    // We need the string in the table; it won't be there unless the source had it,
    // but we still need to emit a valid node.  We'll emit EXPR_STMT(STRING_LIT).
    // If the string isn't in the table we can't reference it — use index 0 as sentinel.
    let msg = format!("/* unsupported: {} */", type_str);
    let str_idx = syms.str_idx(&msg).unwrap_or(0);

    // EXPR_STMT(2) wrapping STRING_LIT(28)
    push_type(out, 2, perm);
    push_type(out, 28, perm);
    push_u16(out, str_idx);
    Ok(())
}

/// Convenience: write a sub-node without noise injection (recursive internal calls).
#[inline(always)]
fn wn(
    out: &mut Vec<u8>,
    node: &Value,
    syms: &SymbolTable,
    perm: &[u8; 37],
) -> Result<(), ObfError> {
    write_node(out, node, syms, perm, None)
}

/// Write a body list (Program.body / Block.body), injecting noise between items.
fn write_body(
    out: &mut Vec<u8>,
    stmts: &[Value],
    syms: &SymbolTable,
    perm: &[u8; 37],
    ctx: Option<&mut EncCtx>,
) -> Result<(), ObfError> {
    if let Some(ctx) = ctx {
        for stmt in stmts {
            ctx.maybe_emit_decoy(out);
            ctx.maybe_emit_state_xor(out);
            wn(out, stmt, syms, perm)?;
        }
    } else {
        for stmt in stmts {
            wn(out, stmt, syms, perm)?;
        }
    }
    Ok(())
}

fn write_node(
    out: &mut Vec<u8>,
    node: &Value,
    syms: &SymbolTable,
    perm: &[u8; 37],
    ctx: Option<&mut EncCtx>,
) -> Result<(), ObfError> {
    let type_str = match node.get("type").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => {
            return Err(ObfError::Encode(format!(
                "AST node missing 'type' field: {:?}",
                node
            )));
        }
    };

    match type_str {
        // ------------------------------------------------------------------
        // 0  PROGRAM
        // ------------------------------------------------------------------
        "Program" => {
            push_type(out, 0, perm);
            let body = get_array(node, "body");
            push_u16(out, body.len() as u16);
            write_body(out, body, syms, perm, ctx)?;
        }

        // ------------------------------------------------------------------
        // 1  BLOCK
        // ------------------------------------------------------------------
        "BlockStatement" => {
            push_type(out, 1, perm);
            let body = get_array(node, "body");
            push_u16(out, body.len() as u16);
            write_body(out, body, syms, perm, ctx)?;
        }

        // ------------------------------------------------------------------
        // 2  EXPR_STMT
        // ------------------------------------------------------------------
        "ExpressionStatement" => {
            push_type(out, 2, perm);
            let expr = node
                .get("expression")
                .ok_or_else(|| ObfError::Encode("ExpressionStatement missing expression".into()))?;
            wn(out, expr, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 3  VAR_DECL
        // ------------------------------------------------------------------
        "VariableDeclaration" => {
            push_type(out, 3, perm);
            let kind = match get_str(node, "kind").as_deref() {
                Some("var") => 0u8,
                Some("let") => 1u8,
                Some("const") => 2u8,
                _ => 0u8,
            };
            out.push(kind);
            let decls = get_array(node, "declarations");
            push_u16(out, decls.len() as u16);
            for decl in decls {
                // VariableDeclarator: id (Identifier), init (optional expr)
                let id = decl
                    .get("id")
                    .ok_or_else(|| ObfError::Encode("VariableDeclarator missing id".into()))?;
                let name = id
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| ObfError::Encode("VariableDeclarator id missing name".into()))?;
                let sym_idx = syms
                    .sym_idx(name)
                    .ok_or_else(|| ObfError::Encode(format!("symbol not found: {}", name)))?;
                push_u16(out, sym_idx);
                let init = decl.get("init").filter(|v| !v.is_null());
                if let Some(init_expr) = init {
                    out.push(1u8);
                    wn(out, init_expr, syms, perm)?;
                } else {
                    out.push(0u8);
                }
            }
        }

        // ------------------------------------------------------------------
        // 4  FUNC_DECL
        // ------------------------------------------------------------------
        "FunctionDeclaration" => {
            push_type(out, 4, perm);
            write_func_common(out, node, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 5  FUNC_EXPR
        // ------------------------------------------------------------------
        "FunctionExpression" => {
            push_type(out, 5, perm);
            write_func_common(out, node, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 6  ARROW_FUNC
        // ------------------------------------------------------------------
        "ArrowFunctionExpression" => {
            push_type(out, 6, perm);
            let params = get_array(node, "params");
            push_u16(out, params.len() as u16);
            for p in params {
                write_param_sym(out, p, syms)?;
            }
            let body = node
                .get("body")
                .ok_or_else(|| ObfError::Encode("ArrowFunctionExpression missing body".into()))?;
            // @babel/types sets expression: null (not true), so derive it from body type
            let expr_body = body.get("type").and_then(|t| t.as_str()) != Some("BlockStatement");
            if expr_body {
                out.push(1u8);
                wn(out, body, syms, perm)?;
            } else {
                out.push(0u8);
                wn(out, body, syms, perm)?;
            }
        }

        // ------------------------------------------------------------------
        // 7  RETURN_STMT
        // ------------------------------------------------------------------
        "ReturnStatement" => {
            push_type(out, 7, perm);
            let arg = node.get("argument").filter(|v| !v.is_null());
            if let Some(a) = arg {
                out.push(1u8);
                wn(out, a, syms, perm)?;
            } else {
                out.push(0u8);
            }
        }

        // ------------------------------------------------------------------
        // 8  IF_STMT
        // ------------------------------------------------------------------
        "IfStatement" => {
            push_type(out, 8, perm);
            let test = node
                .get("test")
                .ok_or_else(|| ObfError::Encode("IfStatement missing test".into()))?;
            wn(out, test, syms, perm)?;
            let cons = node
                .get("consequent")
                .ok_or_else(|| ObfError::Encode("IfStatement missing consequent".into()))?;
            wn(out, cons, syms, perm)?;
            let alt = node.get("alternate").filter(|v| !v.is_null());
            if let Some(a) = alt {
                out.push(1u8);
                wn(out, a, syms, perm)?;
            } else {
                out.push(0u8);
            }
        }

        // ------------------------------------------------------------------
        // 9  WHILE_STMT
        // ------------------------------------------------------------------
        "WhileStatement" => {
            push_type(out, 9, perm);
            let test = node
                .get("test")
                .ok_or_else(|| ObfError::Encode("WhileStatement missing test".into()))?;
            wn(out, test, syms, perm)?;
            let body = node
                .get("body")
                .ok_or_else(|| ObfError::Encode("WhileStatement missing body".into()))?;
            wn(out, body, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 10  FOR_STMT
        // ------------------------------------------------------------------
        "ForStatement" => {
            push_type(out, 10, perm);
            let init = node.get("init").filter(|v| !v.is_null());
            match init {
                None => out.push(0u8),
                Some(n) => {
                    if n.get("type").and_then(|t| t.as_str()) == Some("VariableDeclaration") {
                        out.push(1u8);
                    } else {
                        out.push(2u8);
                    }
                    wn(out, n, syms, perm)?;
                }
            }
            let test = node.get("test").filter(|v| !v.is_null());
            if let Some(t) = test {
                out.push(1u8);
                wn(out, t, syms, perm)?;
            } else {
                out.push(0u8);
            }
            let update = node.get("update").filter(|v| !v.is_null());
            if let Some(u) = update {
                out.push(1u8);
                wn(out, u, syms, perm)?;
            } else {
                out.push(0u8);
            }
            let body = node
                .get("body")
                .ok_or_else(|| ObfError::Encode("ForStatement missing body".into()))?;
            wn(out, body, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 11  FOR_OF_STMT
        // ------------------------------------------------------------------
        "ForOfStatement" => {
            push_type(out, 11, perm);
            let left = node
                .get("left")
                .ok_or_else(|| ObfError::Encode("ForOfStatement missing left".into()))?;
            wn(out, left, syms, perm)?;
            let right = node
                .get("right")
                .ok_or_else(|| ObfError::Encode("ForOfStatement missing right".into()))?;
            wn(out, right, syms, perm)?;
            let body = node
                .get("body")
                .ok_or_else(|| ObfError::Encode("ForOfStatement missing body".into()))?;
            wn(out, body, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 12  FOR_IN_STMT
        // ------------------------------------------------------------------
        "ForInStatement" => {
            push_type(out, 12, perm);
            let left = node
                .get("left")
                .ok_or_else(|| ObfError::Encode("ForInStatement missing left".into()))?;
            wn(out, left, syms, perm)?;
            let right = node
                .get("right")
                .ok_or_else(|| ObfError::Encode("ForInStatement missing right".into()))?;
            wn(out, right, syms, perm)?;
            let body = node
                .get("body")
                .ok_or_else(|| ObfError::Encode("ForInStatement missing body".into()))?;
            wn(out, body, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 13  BREAK_STMT
        // ------------------------------------------------------------------
        "BreakStatement" => {
            push_type(out, 13, perm);
            // no payload
        }

        // ------------------------------------------------------------------
        // 14  CONTINUE_STMT
        // ------------------------------------------------------------------
        "ContinueStatement" => {
            push_type(out, 14, perm);
            // no payload
        }

        // ------------------------------------------------------------------
        // 15  THROW_STMT
        // ------------------------------------------------------------------
        "ThrowStatement" => {
            push_type(out, 15, perm);
            let arg = node
                .get("argument")
                .ok_or_else(|| ObfError::Encode("ThrowStatement missing argument".into()))?;
            wn(out, arg, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 16  TRY_STMT
        // ------------------------------------------------------------------
        "TryStatement" => {
            push_type(out, 16, perm);
            let block = node
                .get("block")
                .ok_or_else(|| ObfError::Encode("TryStatement missing block".into()))?;
            wn(out, block, syms, perm)?;

            let handler = node.get("handler").filter(|v| !v.is_null());
            if let Some(h) = handler {
                out.push(1u8);
                let param = h.get("param").filter(|v| !v.is_null());
                if let Some(p) = param {
                    out.push(1u8);
                    let name = p
                        .get("name")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ObfError::Encode("catch param missing name".into()))?;
                    let sym_idx = syms
                        .sym_idx(name)
                        .ok_or_else(|| ObfError::Encode(format!("symbol not found: {}", name)))?;
                    push_u16(out, sym_idx);
                } else {
                    out.push(0u8);
                }
                let hbody = h
                    .get("body")
                    .ok_or_else(|| ObfError::Encode("catch handler missing body".into()))?;
                wn(out, hbody, syms, perm)?;
            } else {
                out.push(0u8);
            }

            let finalizer = node.get("finalizer").filter(|v| !v.is_null());
            if let Some(f) = finalizer {
                out.push(1u8);
                wn(out, f, syms, perm)?;
            } else {
                out.push(0u8);
            }
        }

        // ------------------------------------------------------------------
        // 17  CALL_EXPR
        // ------------------------------------------------------------------
        "CallExpression" => {
            push_type(out, 17, perm);
            let callee = node
                .get("callee")
                .ok_or_else(|| ObfError::Encode("CallExpression missing callee".into()))?;
            wn(out, callee, syms, perm)?;
            let args = get_array(node, "arguments");
            push_u16(out, args.len() as u16);
            for a in args {
                wn(out, a, syms, perm)?;
            }
        }

        // ------------------------------------------------------------------
        // 18  NEW_EXPR
        // ------------------------------------------------------------------
        "NewExpression" => {
            push_type(out, 18, perm);
            let callee = node
                .get("callee")
                .ok_or_else(|| ObfError::Encode("NewExpression missing callee".into()))?;
            wn(out, callee, syms, perm)?;
            let args = get_array(node, "arguments");
            push_u16(out, args.len() as u16);
            for a in args {
                wn(out, a, syms, perm)?;
            }
        }

        // ------------------------------------------------------------------
        // 19  MEMBER_EXPR / 20  COMPUTED_MEMBER
        // ------------------------------------------------------------------
        "MemberExpression" | "OptionalMemberExpression" => {
            let computed = get_bool(node, "computed");
            if computed {
                push_type(out, 20, perm);
                let obj = node
                    .get("object")
                    .ok_or_else(|| ObfError::Encode("MemberExpression missing object".into()))?;
                wn(out, obj, syms, perm)?;
                let prop = node
                    .get("property")
                    .ok_or_else(|| ObfError::Encode("MemberExpression missing property".into()))?;
                wn(out, prop, syms, perm)?;
            } else {
                push_type(out, 19, perm);
                let obj = node
                    .get("object")
                    .ok_or_else(|| ObfError::Encode("MemberExpression missing object".into()))?;
                wn(out, obj, syms, perm)?;
                let prop = node
                    .get("property")
                    .ok_or_else(|| ObfError::Encode("MemberExpression missing property".into()))?;
                let prop_name = prop.get("name").and_then(|v| v.as_str()).ok_or_else(|| {
                    ObfError::Encode("MemberExpression property missing name".into())
                })?;
                let sym_idx = syms
                    .sym_idx(prop_name)
                    .ok_or_else(|| ObfError::Encode(format!("symbol not found: {}", prop_name)))?;
                push_u16(out, sym_idx);
            }
        }

        // ------------------------------------------------------------------
        // 21  BIN_EXPR
        // ------------------------------------------------------------------
        "BinaryExpression" | "LogicalExpression" => {
            push_type(out, 21, perm);
            let op_str = get_str(node, "operator").unwrap_or_default();
            let op_byte = bin_op_byte(&op_str);
            out.push(op_byte);
            let left = node
                .get("left")
                .ok_or_else(|| ObfError::Encode("BinaryExpression missing left".into()))?;
            wn(out, left, syms, perm)?;
            let right = node
                .get("right")
                .ok_or_else(|| ObfError::Encode("BinaryExpression missing right".into()))?;
            wn(out, right, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 22  UNARY_EXPR (also handles UpdateExpression)
        // ------------------------------------------------------------------
        "UnaryExpression" => {
            push_type(out, 22, perm);
            let op_str = get_str(node, "operator").unwrap_or_default();
            let op_byte = unary_op_byte(&op_str, true);
            out.push(op_byte);
            let arg = node
                .get("argument")
                .ok_or_else(|| ObfError::Encode("UnaryExpression missing argument".into()))?;
            wn(out, arg, syms, perm)?;
        }

        "UpdateExpression" => {
            push_type(out, 22, perm);
            let op_str = get_str(node, "operator").unwrap_or_default();
            let prefix = get_bool(node, "prefix");
            let op_byte = update_op_byte(&op_str, prefix);
            out.push(op_byte);
            let arg = node
                .get("argument")
                .ok_or_else(|| ObfError::Encode("UpdateExpression missing argument".into()))?;
            wn(out, arg, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 23  ASSIGN_EXPR
        // ------------------------------------------------------------------
        "AssignmentExpression" => {
            push_type(out, 23, perm);
            let op_str = get_str(node, "operator").unwrap_or_default();
            let op_byte = assign_op_byte(&op_str);
            out.push(op_byte);
            let left = node
                .get("left")
                .ok_or_else(|| ObfError::Encode("AssignmentExpression missing left".into()))?;
            wn(out, left, syms, perm)?;
            let right = node
                .get("right")
                .ok_or_else(|| ObfError::Encode("AssignmentExpression missing right".into()))?;
            wn(out, right, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 24  COND_EXPR
        // ------------------------------------------------------------------
        "ConditionalExpression" => {
            push_type(out, 24, perm);
            let test = node
                .get("test")
                .ok_or_else(|| ObfError::Encode("ConditionalExpression missing test".into()))?;
            wn(out, test, syms, perm)?;
            let cons = node.get("consequent").ok_or_else(|| {
                ObfError::Encode("ConditionalExpression missing consequent".into())
            })?;
            wn(out, cons, syms, perm)?;
            let alt = node.get("alternate").ok_or_else(|| {
                ObfError::Encode("ConditionalExpression missing alternate".into())
            })?;
            wn(out, alt, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 25  SEQUENCE_EXPR
        // ------------------------------------------------------------------
        "SequenceExpression" => {
            push_type(out, 25, perm);
            let exprs = get_array(node, "expressions");
            push_u16(out, exprs.len() as u16);
            for e in exprs {
                wn(out, e, syms, perm)?;
            }
        }

        // ------------------------------------------------------------------
        // 26  SPREAD_ELEM
        // ------------------------------------------------------------------
        "SpreadElement" | "RestElement" => {
            push_type(out, 26, perm);
            let arg = node
                .get("argument")
                .ok_or_else(|| ObfError::Encode("SpreadElement missing argument".into()))?;
            wn(out, arg, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 27  IDENT
        // ------------------------------------------------------------------
        "Identifier" => {
            push_type(out, 27, perm);
            let name = node
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ObfError::Encode("Identifier missing name".into()))?;
            let sym_idx = syms
                .sym_idx(name)
                .ok_or_else(|| ObfError::Encode(format!("symbol not found: {}", name)))?;
            push_u16(out, sym_idx);
        }

        // ------------------------------------------------------------------
        // 28  STRING_LIT
        // ------------------------------------------------------------------
        "StringLiteral" => {
            push_type(out, 28, perm);
            let val = node
                .get("value")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ObfError::Encode("StringLiteral missing value".into()))?;
            let str_idx = syms
                .str_idx(val)
                .ok_or_else(|| ObfError::Encode(format!("string not found: {}", val)))?;
            push_u16(out, str_idx);
        }

        // ------------------------------------------------------------------
        // 29  NUM_LIT
        // ------------------------------------------------------------------
        "NumericLiteral" => {
            push_type(out, 29, perm);
            let val = node
                .get("value")
                .and_then(|v| v.as_f64())
                .ok_or_else(|| ObfError::Encode("NumericLiteral missing value".into()))?;
            push_f64(out, val);
        }

        // ------------------------------------------------------------------
        // 30  BOOL_LIT
        // ------------------------------------------------------------------
        "BooleanLiteral" => {
            push_type(out, 30, perm);
            let val = node
                .get("value")
                .and_then(|v| v.as_bool())
                .ok_or_else(|| ObfError::Encode("BooleanLiteral missing value".into()))?;
            out.push(if val { 1u8 } else { 0u8 });
        }

        // ------------------------------------------------------------------
        // 31  NULL_LIT
        // ------------------------------------------------------------------
        "NullLiteral" => {
            push_type(out, 31, perm);
            // no payload
        }

        // ------------------------------------------------------------------
        // 32  ARRAY_LIT
        // ------------------------------------------------------------------
        "ArrayExpression" => {
            push_type(out, 32, perm);
            let elems = get_array(node, "elements");
            push_u16(out, elems.len() as u16);
            for e in elems {
                if e.is_null() {
                    out.push(0u8); // hole
                } else {
                    out.push(1u8);
                    wn(out, e, syms, perm)?;
                }
            }
        }

        // ------------------------------------------------------------------
        // 33  OBJECT_LIT
        // ------------------------------------------------------------------
        "ObjectExpression" => {
            push_type(out, 33, perm);
            let props = get_array(node, "properties");
            push_u16(out, props.len() as u16);
            for prop in props {
                // Handle SpreadElement inside object
                if prop.get("type").and_then(|t| t.as_str()) == Some("SpreadElement") {
                    // emit as key_type=1 str_idx=0 + spread arg  (best effort)
                    out.push(1u8);
                    push_u16(out, 0u16);
                    wn(out, prop, syms, perm)?;
                    continue;
                }
                let key = prop
                    .get("key")
                    .ok_or_else(|| ObfError::Encode("ObjectProperty missing key".into()))?;
                let key_type_str = key.get("type").and_then(|t| t.as_str()).unwrap_or("");
                match key_type_str {
                    "Identifier" => {
                        out.push(0u8);
                        let name = key.get("name").and_then(|v| v.as_str()).ok_or_else(|| {
                            ObfError::Encode("ObjectProperty key missing name".into())
                        })?;
                        let sym_idx = syms.sym_idx(name).ok_or_else(|| {
                            ObfError::Encode(format!("symbol not found: {}", name))
                        })?;
                        push_u16(out, sym_idx);
                    }
                    "StringLiteral" => {
                        out.push(1u8);
                        let val = key.get("value").and_then(|v| v.as_str()).ok_or_else(|| {
                            ObfError::Encode("ObjectProperty key missing value".into())
                        })?;
                        let str_idx = syms.str_idx(val).ok_or_else(|| {
                            ObfError::Encode(format!("string not found: {}", val))
                        })?;
                        push_u16(out, str_idx);
                    }
                    "NumericLiteral" => {
                        // treat as string (stringify the number)
                        out.push(1u8);
                        let val = key.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let s = format!("{}", val);
                        let str_idx = syms.str_idx(&s).unwrap_or(0);
                        push_u16(out, str_idx);
                    }
                    _ => {
                        // fallback: ident key_type=0, index=0
                        out.push(0u8);
                        push_u16(out, 0u16);
                    }
                }
                let value = prop
                    .get("value")
                    .ok_or_else(|| ObfError::Encode("ObjectProperty missing value".into()))?;
                wn(out, value, syms, perm)?;
            }
        }

        // ------------------------------------------------------------------
        // 34  TEMPLATE_LIT
        // ------------------------------------------------------------------
        "TemplateLiteral" => {
            push_type(out, 34, perm);
            let quasis = get_array(node, "quasis");
            push_u16(out, quasis.len() as u16);
            for q in quasis {
                // TemplateElement value: { raw, cooked }
                let cooked = q
                    .get("value")
                    .and_then(|v| v.get("cooked"))
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        q.get("value")
                            .and_then(|v| v.get("raw"))
                            .and_then(|v| v.as_str())
                    })
                    .unwrap_or("");
                let str_idx = syms.str_idx(cooked).ok_or_else(|| {
                    ObfError::Encode(format!("template quasi string not found: {}", cooked))
                })?;
                push_u16(out, str_idx);
            }
            let exprs = get_array(node, "expressions");
            push_u16(out, exprs.len() as u16);
            for e in exprs {
                wn(out, e, syms, perm)?;
            }
        }

        // ------------------------------------------------------------------
        // 35  DO_WHILE_STMT
        // ------------------------------------------------------------------
        "DoWhileStatement" => {
            push_type(out, 35, perm);
            let body = node
                .get("body")
                .ok_or_else(|| ObfError::Encode("DoWhileStatement missing body".into()))?;
            let test = node
                .get("test")
                .ok_or_else(|| ObfError::Encode("DoWhileStatement missing test".into()))?;
            wn(out, body, syms, perm)?;
            wn(out, test, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // 36  THIS_EXPR
        // ------------------------------------------------------------------
        "ThisExpression" => {
            push_type(out, 36, perm);
        }

        // ------------------------------------------------------------------
        // TaggedTemplateExpression — lower to CALL_EXPR (best effort)
        // ------------------------------------------------------------------
        "TaggedTemplateExpression" => {
            // Emit as CALL_EXPR: tag(quasi_strings)
            push_type(out, 17, perm);
            let tag = node
                .get("tag")
                .ok_or_else(|| ObfError::Encode("TaggedTemplateExpression missing tag".into()))?;
            wn(out, tag, syms, perm)?;
            // arguments: the quasi template literal
            let quasi = node
                .get("quasi")
                .ok_or_else(|| ObfError::Encode("TaggedTemplateExpression missing quasi".into()))?;
            push_u16(out, 1u16);
            wn(out, quasi, syms, perm)?;
        }

        // ------------------------------------------------------------------
        // Directive / DirectiveLiteral (Babel wraps "use strict" etc.)
        // ------------------------------------------------------------------
        "Directive" => {
            // Emit as EXPR_STMT(STRING_LIT)
            push_type(out, 2, perm);
            let val = node
                .get("value")
                .and_then(|v| v.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let str_idx = syms.str_idx(val).unwrap_or(0);
            push_type(out, 28, perm);
            push_u16(out, str_idx);
        }

        // ------------------------------------------------------------------
        // Everything else
        // ------------------------------------------------------------------
        other => {
            write_unsupported(out, other, syms, perm)?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helper: write function common fields (for FunctionDeclaration / FunctionExpression)
// ---------------------------------------------------------------------------

fn write_func_common(
    out: &mut Vec<u8>,
    node: &Value,
    syms: &SymbolTable,
    perm: &[u8; 37],
) -> Result<(), ObfError> {
    let id = node.get("id").filter(|v| !v.is_null());
    if let Some(id_node) = id {
        out.push(1u8);
        let name = id_node
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ObfError::Encode("FunctionDecl/Expr id missing name".into()))?;
        let sym_idx = syms
            .sym_idx(name)
            .ok_or_else(|| ObfError::Encode(format!("symbol not found: {}", name)))?;
        push_u16(out, sym_idx);
    } else {
        out.push(0u8);
    }
    let params = get_array(node, "params");
    push_u16(out, params.len() as u16);
    for p in params {
        write_param_sym(out, p, syms)?;
    }
    let body = node
        .get("body")
        .ok_or_else(|| ObfError::Encode("FunctionDecl/Expr missing body".into()))?;
    // body must be a BlockStatement — write it directly (the type byte is already handled
    // by write_node if we call it, but the spec says [block], so we recurse normally)
    wn(out, body, syms, perm)?;
    Ok(())
}

/// Write a single parameter's symbol index.  Handles plain Identifier and
/// RestElement/AssignmentPattern (uses the left-hand identifier).
fn write_param_sym(out: &mut Vec<u8>, param: &Value, syms: &SymbolTable) -> Result<(), ObfError> {
    let name = match param.get("type").and_then(|t| t.as_str()) {
        Some("Identifier") => param
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ObfError::Encode("param Identifier missing name".into()))?,
        Some("AssignmentPattern") => {
            // left side is the identifier
            param
                .get("left")
                .and_then(|l| l.get("name"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| ObfError::Encode("AssignmentPattern left missing name".into()))?
        }
        Some("RestElement") => param
            .get("argument")
            .and_then(|a| a.get("name"))
            .and_then(|v| v.as_str())
            .ok_or_else(|| ObfError::Encode("RestElement argument missing name".into()))?,
        other => {
            return Err(ObfError::Encode(format!(
                "unsupported param type: {:?}",
                other
            )));
        }
    };
    let sym_idx = syms
        .sym_idx(name)
        .ok_or_else(|| ObfError::Encode(format!("symbol not found: {}", name)))?;
    push_u16(out, sym_idx);
    Ok(())
}

// ---------------------------------------------------------------------------
// Operator byte maps
// ---------------------------------------------------------------------------

fn bin_op_byte(op: &str) -> u8 {
    match op {
        "+" => 0,
        "-" => 1,
        "*" => 2,
        "/" => 3,
        "%" => 4,
        "**" => 5,
        "===" => 6,
        "!==" => 7,
        "==" => 8,
        "!=" => 9,
        "<" => 10,
        ">" => 11,
        "<=" => 12,
        ">=" => 13,
        "&&" => 14,
        "||" => 15,
        "??" => 16,
        "&" => 17,
        "|" => 18,
        "^" => 19,
        "<<" => 20,
        ">>" => 21,
        ">>>" => 22,
        "in" => 23,
        "instanceof" => 24,
        _ => 0,
    }
}

fn unary_op_byte(op: &str, _prefix: bool) -> u8 {
    match op {
        "!" => 0,
        "-" => 1,
        "+" => 2,
        "~" => 3,
        "void" => 4,
        "delete" => 5,
        "typeof" => 6,
        _ => 0,
    }
}

fn update_op_byte(op: &str, prefix: bool) -> u8 {
    match (op, prefix) {
        ("++", true) => 7,
        ("--", true) => 8,
        ("++", false) => 9,
        ("--", false) => 10,
        _ => 7,
    }
}

fn assign_op_byte(op: &str) -> u8 {
    match op {
        "=" => 0,
        "+=" => 1,
        "-=" => 2,
        "*=" => 3,
        "/=" => 4,
        "%=" => 5,
        "**=" => 6,
        "&=" => 7,
        "|=" => 8,
        "^=" => 9,
        "<<=" => 10,
        ">>=" => 11,
        ">>>=" => 12,
        "??=" => 13,
        "&&=" => 14,
        "||=" => 15,
        _ => 0,
    }
}
