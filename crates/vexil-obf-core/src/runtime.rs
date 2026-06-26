use rand_core::{OsRng, RngCore};

const BROWSER_REQUIRE_STUB: &str = concat!(
    "if(typeof require===\"undefined\"){require=function(_m){",
    "var _r=typeof globalThis!==\"undefined\"?globalThis:typeof window!==\"undefined\"?window:{};",
    "if(_m===\"path\"){var _njoin=function(a){var s=a.split(\"\\\\\").join(\"/\");while(s.indexOf(\"//\")>=0)s=s.split(\"//\").join(\"/\");return s;};",
    "return{join:function(){return _njoin(Array.prototype.slice.call(arguments).join(\"/\"));},",
    "dirname:function(p){var s=_njoin(p).split(\"/\");s.pop();return s.join(\"/\")||\".\";},",
    "basename:function(p){return _njoin(p).split(\"/\").pop()||\";\";},",
    "extname:function(p){var b=_njoin(p).split(\"/\").pop()||\";\";var i=b.lastIndexOf(\".\");return i>0?b.slice(i):\"\";},",
    "resolve:function(){return Array.prototype.slice.call(arguments).join(\"/\");},sep:\"/\"};}",
    "if(_m===\"events\"){function _EE(){this._e={};} ",
    "_EE.prototype.on=function(e,f){(this._e[e]=this._e[e]||[]).push(f);return this;};",
    "_EE.prototype.emit=function(e){var a=Array.prototype.slice.call(arguments,1);(this._e[e]||[]).forEach(function(f){f.apply(this,a);},this);};",
    "_EE.prototype.off=function(e,f){this._e[e]=(this._e[e]||[]).filter(function(x){return x!==f;});return this;};",
    "_EE.prototype.removeAllListeners=function(e){if(e)delete this._e[e];else this._e={};return this;};",
    "return{EventEmitter:_EE};}",
    "if(_m===\"os\"){return{platform:function(){return\"browser\";},type:function(){return\"Browser\";},homedir:function(){return\"/\";},tmpdir:function(){return\"/tmp\";}};}",
    "if(_m===\"crypto\"||_m===\"node:crypto\"){return{getRandomValues:function(b){return _r.crypto.getRandomValues(b);},",
    "randomBytes:function(n){var b=new Uint8Array(n);_r.crypto.getRandomValues(b);return b;},",
    "createHash:function(algo){var _d=[];return{update:function(data){_d.push(typeof data===\"string\"?new TextEncoder().encode(data):data);return this;},",
    "digest:function(enc){var _b=[];_d.forEach(function(c){for(var i=0;i<c.length;i++)_b.push(c[i]);});",
    "var _ab=new Uint8Array(_b);",
    "if(typeof _r.crypto.subtle!==\"undefined\"){var _p=null;",
    "_r.crypto.subtle.digest(\"SHA-\"+(function(_a){var _n=\"\";for(var _ai=0;_ai<_a.length;_ai++){var _c=_a.charCodeAt(_ai);if(_c>=48&&_c<=57)_n+=_a[_ai];}return _n;})(algo),_ab).then(function(h){",
    "var hx=Array.from(new Uint8Array(h)).map(function(b){return b.toString(16).padStart(2,\"0\");}).join(\"\");",
    "_p=enc===\"hex\"?hx:new Uint8Array(h);});",
    "var _t=Date.now();while(_p===null&&Date.now()-_t<5000){}",
    "if(_p===null)throw new Error(\"crypto.createHash timeout\");return _p;}",
    "throw new Error(\"crypto.subtle not available\");}};},",
    "createHmac:function(algo,key){var _k=typeof key===\"string\"?new TextEncoder().encode(key):key;var _d=[];",
    "return{update:function(data){_d.push(typeof data===\"string\"?new TextEncoder().encode(data):data);return this;},",
    "digest:function(enc){throw new Error(\"createHmac.digest: use WebCrypto directly in browser\");}};}};} ",
    "throw new Error(\"require: module '\"+_m+\"' not available in browser\");};}\n"
);

#[derive(Debug, Clone, Copy, Default)]
pub enum OutputFormat {
    #[default]
    Cjs,
    Umd,
    Iife,
}

// ── byte encoding ─────────────────────────────────────────────────────────────

fn is_charcode_safe(b: u8) -> bool {
    (0x21..=0x7e).contains(&b) && b != 0x22 && b != 0x5c
}

/// Encode one byte as a JS expression in one of six forms.
///
/// Forms 2 and 3 use the helper functions _bxr / _bcp that are declared in the
/// output.  After pass3 renames those helpers to short ids, the expressions look
/// like arbitrary utility calls rather than bitwise operations.
///
/// Forms 4 and 5 use string literals that pass3's string-array transform will
/// extract and rotate, turning them into _SD(_SA,N) calls.
fn encode_byte(b: u8, idx: usize, salt: u8) -> String {
    let h = b
        .wrapping_mul(97)
        .wrapping_add(idx as u8)
        .wrapping_add(salt)
        .wrapping_mul(53);
    let choice = h % 6;
    match choice {
        0 => format!("0x{:02x}", b),
        1 => format!("{}", b),
        2 => {
            // XOR via helper: _bxr(a, mask) where a ^ mask = b
            let mask: u8 = (idx
                .wrapping_mul(73)
                .wrapping_add(41)
                .wrapping_add(salt as usize)) as u8;
            let a = b ^ mask;
            format!("_bxr(0x{:02x},0x{:02x})", a, mask)
        }
        3 => {
            // Complement via helper: _bcp(~b) — pass3 renames _bcp
            format!("_bcp(0x{:02x})", !b)
        }
        4 => {
            // String parse — pass3 string-split will break "HH" → "H"+"H",
            // then string-array extracts each half
            format!("parseInt(\"{:02x}\",16)", b)
        }
        _ => {
            // Character code — pass3 extracts the char string and computes props
            // rename .charCodeAt → ['\x63\x68\x61\x72\x43\x6f\x64\x65\x41\x74']
            if is_charcode_safe(b) {
                format!("\"{}\".charCodeAt(0)", b as char)
            } else {
                let mask: u8 = salt.wrapping_add(0x5b);
                let a = b ^ mask;
                format!("_bxr(0x{:02x},0x{:02x})", a, mask)
            }
        }
    }
}

fn bytes_to_js_array_plain(b: &[u8]) -> String {
    let parts: Vec<String> = b.iter().map(|x| format!("{}", x)).collect();
    format!("[{}]", parts.join(","))
}

fn bytes_to_js_array_scattered(b: &[u8], salt: u8) -> String {
    let parts: Vec<String> = b
        .iter()
        .enumerate()
        .map(|(i, &x)| encode_byte(x, i, salt))
        .collect();
    format!("[{}]", parts.join(","))
}

// ── LCG stream ────────────────────────────────────────────────────────────────

const LCG_MUL: u64 = 6364136223846793005;
const LCG_ADD: u64 = 1442695040888963407;

fn lcg_stream(seed: &[u8; 8]) -> ([u8; 32], u64) {
    let seed_u64 = u64::from_le_bytes(*seed);
    let start = seed_u64
        .wrapping_mul(0x9e3779b97f4a7c15)
        .wrapping_add(0x6c62272e07bb0142);
    let start = start
        .wrapping_mul(0xbf58476d1ce4e5b9)
        .wrapping_add(0x94d049bb133111eb);

    let mut n = start;
    let mut stream = [0u8; 32];
    for b in stream.iter_mut() {
        n = n.wrapping_mul(LCG_MUL).wrapping_add(LCG_ADD);
        *b = (n >> 56) as u8;
    }
    (stream, start)
}

// ── helpers that format u64 constants as split string concatenations ──────────

/// Format a u64 as two concatenated 8-digit hex strings (without 0x prefix on either).
/// The JS expression evaluates as the 16-hex-digit number when BigInt("0x"+hi+lo) is used.
///
/// After pass3's string-split pass, each 8-char piece gets further split, and then
/// both halves go into the rotated string array — so the BigInt constant ends up
/// assembled from 4+ _SD() calls rather than one literal.
fn u64_as_concat_hex(v: u64) -> (String, String) {
    let hi = v >> 32;
    let lo = v & 0xffff_ffff;
    (format!("{:08x}", hi), format!("{:08x}", lo))
}

/// Format a u64 decimal constant as two concatenated strings.
/// E.g. 6364136223846793005 → "636413622" + "3846793005"
fn u64_as_concat_dec(v: u64) -> (String, String) {
    let s = v.to_string();
    // Split near the middle to keep each half ≥ 8 chars for string-array eligibility
    let mid = s.len() / 2;
    (s[..mid].to_string(), s[mid..].to_string())
}

// ── output generation ─────────────────────────────────────────────────────────

pub fn generate_output(
    key: &[u8; 32],
    _build_id: &[u8; 16],
    node_seed: &[u8; 8],
    payload_b64: &str,
    env_fingerprint: bool,
    format: OutputFormat,
    global_name: &str,
) -> String {
    // Key-split material
    let mut part_a = [0u8; 32];
    let mut part_b = [0u8; 32];
    OsRng.fill_bytes(&mut part_a);
    OsRng.fill_bytes(&mut part_b);
    let rot = (OsRng.next_u32() & 0x1F) as usize;

    // LCG-stream key binding
    let (stream, lcg_start) = lcg_stream(node_seed);
    let mut modified_key = [0u8; 32];
    for i in 0..32 {
        modified_key[i] = key[i] ^ stream[i];
    }

    // Non-linear 3-part split: C[i] = K[i] ^ A[i] ^ B[(i*5+rot)%32]
    let part_c: Vec<u8> = (0..32)
        .map(|i| modified_key[i] ^ part_a[i] ^ part_b[(i * 5 + rot) % 32])
        .collect();

    // Decoy arrays (32, 24, 20 bytes)
    let mut decoy_x = [0u8; 32];
    let mut decoy_y = [0u8; 24];
    let mut decoy_z = [0u8; 20];
    OsRng.fill_bytes(&mut decoy_x);
    OsRng.fill_bytes(&mut decoy_y);
    OsRng.fill_bytes(&mut decoy_z);

    let salt_a = OsRng.next_u32() as u8;
    let salt_b = OsRng.next_u32() as u8;
    let salt_c = OsRng.next_u32() as u8;
    let salt_x = OsRng.next_u32() as u8;
    let salt_y = OsRng.next_u32() as u8;
    let salt_z = OsRng.next_u32() as u8;

    let a_arr = bytes_to_js_array_scattered(&part_a, salt_a);
    let b_arr = bytes_to_js_array_scattered(&part_b, salt_b);
    let c_arr = bytes_to_js_array_scattered(&part_c, salt_c);
    let dx_arr = bytes_to_js_array_scattered(&decoy_x, salt_x);
    let dy_arr = bytes_to_js_array_scattered(&decoy_y, salt_y);
    let dz_arr = bytes_to_js_array_scattered(&decoy_z, salt_z);
    let seed_arr = bytes_to_js_array_plain(node_seed);

    let vm_code = include_str!("../../../runtime/vm.js");

    let env_check = if env_fingerprint {
        "var _vE=(typeof process!==\"undefined\"&&process.env&&process.env.VOBF_ID)||\"\";\n\
         if(_vE){var _vEK=new TextEncoder().encode(_vE);for(var i=0;i<32;i++)_vK[i]^=_vEK[i%_vEK.length];}\n"
    } else {
        ""
    };

    // BigInt constants as split string concatenations.
    // After pass3's string-split pass the 8-char halves get split again (~4 chars each).
    // All pieces then land in the rotated string array as separate entries, so
    // a BigInt constant like 6364136223846793005 requires 4+ _SD() lookups to reconstruct.
    let (start_hi, start_lo) = u64_as_concat_hex(lcg_start);
    let (mul_hi, mul_lo) = u64_as_concat_dec(LCG_MUL);
    let (add_hi, add_lo) = u64_as_concat_dec(LCG_ADD);

    // ── Key reconstruction — 3-step closure chain ─────────────────────────────
    //
    // Step 1 (_vt1): XOR-combine A, B (non-linear index), C via helper _bxr.
    //   Result is modified_key (not the real AES key yet).
    //
    // _vck (fake checksum): reads _vt1 and decoy _vX, looks like secondary
    //   key validation, but the result is never used in decryption.
    //
    // Step 2 (_vK): LCG stream un-XOR → real AES key.
    //   Uses a function-table _vfn=[BigInt,Number] so direct BigInt() calls
    //   are hidden behind array indexing.  After pass3 renames _vfn, the
    //   accesses become _xy[0](...) which looks like arbitrary array reads.
    //
    // All BigInt constants are split into "hi"+"lo" concatenations here;
    // pass3 then further splits each piece and arrays them individually.
    let key_reconstruction = format!(
        // Helper functions — XOR and complement utilities.
        // Serve double duty: used in the key array encoding AND in the reconstruction.
        // After pass3 rename they look like unnamed utility functions.
        "var _bxr=function(_a,_b){{return _a^_b;}};\n\
         var _bcp=function(_a){{return ~_a&0xff;}};\n\
         var _vA={a},_vB={b},_vC={c};\n\
         var _vX={dx};\n\
         \n\
         var _vt1=(function(){{\n\
           if(_vA.length!==32||_vB.length!==32||_vC.length!==32){{return null;}}\n\
           var _t=new Uint8Array(32);\n\
           for(var _ki=0;_ki<32;_ki++)\n\
             _t[_ki]=_bxr(_bxr(_vA[_ki],_vB[(_ki*5+{rot})%32]),_vC[_ki]);\n\
           return _t;\n\
         }})();\n\
         \n\
         var _vck=(function(_t){{\n\
           if(!_t)return 0;\n\
           var _s=0,_m=_vX.length;\n\
           for(var _i=0;_i<_t.length;_i++)_s=_bxr(_s,_t[_i])^(_vX[_i%_m]||0);\n\
           return _s;\n\
         }})(_vt1);\n\
         \n\
         var _vK=new Uint8Array(32);\n\
         (function(_t){{\n\
           if(!_t||typeof BigInt!==\"function\"){{return;}}\n\
           var _vfn=[BigInt,Number];\n\
           var _msk=_vfn[0](\"0xffffffff\"+\"ffffffff\");\n\
           var _n=_vfn[0](\"0x\"+\"{sh}\"+\"{sl}\");\n\
           for(var _ki=0;_ki<32;_ki++){{\n\
             _n=(_n*_vfn[0](\"{mh}\"+\"{ml}\")+_vfn[0](\"{ah}\"+\"{al}\"))&_msk;\n\
             _t[_ki]=_bxr(_t[_ki],_vfn[1](_n>>_vfn[0](56))&0xff);\n\
           }}\n\
           for(var _ki=0;_ki<32;_ki++)_vK[_ki]=_t[_ki];\n\
         }})(_vt1);\n",
        a = a_arr,
        b = b_arr,
        c = c_arr,
        dx = dx_arr,
        rot = rot,
        sh = start_hi,
        sl = start_lo,
        mh = mul_hi,
        ml = mul_lo,
        ah = add_hi,
        al = add_lo,
    );

    let payload_vars = format!(
        "{key_recon}\
         {env}\
         var _vS={seed};\n\
         var _vY={dy},_vZ={dz};\n\
         var _vP=\"{payload}\";\n",
        key_recon = key_reconstruction,
        env = env_check,
        seed = seed_arr,
        dy = dy_arr,
        dz = dz_arr,
        payload = payload_b64,
    );

    match format {
        OutputFormat::Cjs => {
            format!(
                "(function(){{\n{vars}{vm}\n}})();\n",
                vars = payload_vars,
                vm = vm_code,
            )
        }
        OutputFormat::Iife => {
            format!(
                "(function(){{\n{stub}{vars}{vm}\n}})();\n",
                stub = BROWSER_REQUIRE_STUB,
                vars = payload_vars,
                vm = vm_code,
            )
        }
        OutputFormat::Umd => {
            let gn = global_name;
            format!(
                "(function(root,factory){{\n\
                 if(typeof module!==\"undefined\"&&module.exports){{module.exports=factory();}}\n\
                 else if(typeof define===\"function\"&&define.amd){{define([],factory);}}\n\
                 else{{var _r=factory();_r&&typeof _r[\"then\"]===\"function\"?_r[\"then\"](function(e){{root[\"{gn}\"]=e;}}):root[\"{gn}\"]=_r;}}\n\
                 }})(typeof globalThis!==\"undefined\"?globalThis:typeof window!==\"undefined\"?window:typeof global!==\"undefined\"?global:this,function(){{\n\
                 {vars}\
                 var _vxS=false,_vxR=null;\n\
                 var __vx_done_cb=function(){{\n\
                   _vxS=true;\n\
                   var _vxExp=(typeof module!==\"undefined\"&&module[\"exports\"])?module[\"exports\"]:\n\
                              (typeof exports!==\"undefined\"?exports:{{}});\n\
                   if(_vxR)_vxR(_vxExp);\n\
                 }};\n\
                 {vm}\n\
                 if(_vxS){{\n\
                   return (typeof module!==\"undefined\"&&module[\"exports\"])?module[\"exports\"]:\n\
                          (typeof exports!==\"undefined\"?exports:{{}});\n\
                 }}\n\
                 return new Promise(function(res){{_vxR=res;}});\n\
                 }});\n",
                gn = gn,
                vars = payload_vars,
                vm = vm_code,
            )
        }
    }
}
