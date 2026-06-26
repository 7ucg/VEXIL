"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VexilWebpackPlugin = exports.vexilVitePlugin = exports.vexilRollupPlugin = exports.bundleAndObfuscate = void 0;
exports.obfuscateJs = obfuscateJs;
exports.reObfuscate = reObfuscate;
exports.obfuscateDart = obfuscateDart;
const pass1_1 = require("./pass1");
const pass3_1 = require("./pass3");
let wasmModule = null;
async function loadWasm() {
    if (!wasmModule) {
        try {
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            wasmModule = require('../wasm/vexil_obf_wasm.js');
        }
        catch {
            wasmModule = null;
        }
    }
    return wasmModule;
}
function resolvePass3Opts(opt) {
    if (opt === false)
        return false;
    const defaults = {
        hexNumbers: true,
        computedProps: true,
        stringArray: true,
        integrityTrap: true,
    };
    if (opt === true || opt === undefined)
        return defaults;
    return { ...defaults, ...opt };
}
async function obfuscateJs(source, opts = {}) {
    const p3opts = resolvePass3Opts(opts.pass3);
    const p1opts = {
        renameIdentifiers: opts.pass1?.renameIdentifiers ?? true,
        encryptStrings: opts.pass1?.encryptStrings ?? true,
        flattenControlFlow: opts.pass1?.flattenControlFlow ?? true,
    };
    const { code: pass1Code, astJson } = (0, pass1_1.pass1)(source, p1opts);
    if (opts.pass2 !== false) {
        const wasm = await loadWasm();
        if (wasm) {
            const result = wasm.obf_process_js(astJson, opts.envFingerprint ?? false, opts.format ?? 'cjs');
            const p2code = result.js;
            const finalCode = p3opts !== false ? (0, pass3_1.pass3)(p2code, p3opts) : p2code;
            return {
                code: finalCode,
                key: result.key_b64,
                buildId: result.build_id_b64,
            };
        }
    }
    // WASM not available: return pass1 result (optionally pass3'd)
    const finalCode = p3opts !== false ? (0, pass3_1.pass3)(pass1Code, p3opts) : pass1Code;
    return { code: finalCode };
}
var bundle_1 = require("./bundle");
Object.defineProperty(exports, "bundleAndObfuscate", { enumerable: true, get: function () { return bundle_1.bundleAndObfuscate; } });
var rollup_plugin_1 = require("./rollup-plugin");
Object.defineProperty(exports, "vexilRollupPlugin", { enumerable: true, get: function () { return rollup_plugin_1.vexilRollupPlugin; } });
var vite_plugin_1 = require("./vite-plugin");
Object.defineProperty(exports, "vexilVitePlugin", { enumerable: true, get: function () { return vite_plugin_1.vexil; } });
var webpack_plugin_1 = require("./webpack-plugin");
Object.defineProperty(exports, "VexilWebpackPlugin", { enumerable: true, get: function () { return webpack_plugin_1.VexilWebpackPlugin; } });
// Re-obfuscate already-obfuscated JS (applies pass3 — identifier renaming, no string re-encryption).
async function reObfuscate(code, opts = {}) {
    return (0, pass3_1.pass3)(code, { hexNumbers: true, ...opts });
}
async function obfuscateDart(source) {
    const wasm = await loadWasm();
    if (wasm) {
        return wasm.obf_dart(source);
    }
    return dartFallback(source);
}
function dartFallback(source) {
    const key = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
    const encrypted = [];
    const result = source.replace(/'([^'\\]*)'/g, (_, s) => {
        const bytes = Array.from(new TextEncoder().encode(s));
        const enc = bytes.map((b, i) => b ^ key[i % 16]);
        encrypted.push(enc.join(','));
        return '_vd([' + enc.join(',') + '])';
    });
    const keyStr = key.join(',');
    return result + '\nList<int> _vdk=[' + keyStr + '];\n' +
        'String _vd(List<int> b)=>String.fromCharCodes(b.asMap().map((i,x)=>MapEntry(i,x^_vdk[i%_vdk.length])).values);\n';
}
