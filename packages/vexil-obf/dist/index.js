"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VexilWebpackPlugin = exports.vexilVitePlugin = exports.vexilRollupPlugin = exports.bundleAndObfuscate = exports.PRESETS = void 0;
exports.obfuscateJs = obfuscateJs;
exports.exportPreset = exportPreset;
exports.importPreset = importPreset;
exports.batchObfuscate = batchObfuscate;
exports.batchObfuscateDart = batchObfuscateDart;
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
function resolvePass3Opts(opts) {
    const opt = opts.pass3;
    if (opt === false)
        return false;
    const defaults = {
        hexNumbers: true,
        computedProps: true,
        stringArray: true,
        integrityTrap: true,
    };
    // Collect shorthand top-level flags
    const shorthands = {};
    if (opts.selfDefend !== undefined)
        shorthands.selfDefend = opts.selfDefend;
    if (opts.debugProtection !== undefined)
        shorthands.debugProtection = opts.debugProtection;
    if (opts.integrityTrap !== undefined)
        shorthands.integrityTrap = opts.integrityTrap;
    if (opts.antiAnalysis !== undefined)
        shorthands.antiAnalysis = opts.antiAnalysis;
    if (opts.deadCode !== undefined)
        shorthands.deadCode = opts.deadCode;
    if (opts.callStackCheck !== undefined)
        shorthands.callStackCheck = opts.callStackCheck;
    if (opts.agentDisrupt !== undefined)
        shorthands.agentDisrupt = opts.agentDisrupt;
    if (opts.antiLLM !== undefined)
        shorthands.antiLLM = opts.antiLLM;
    if (opt === true || opt === undefined)
        return { ...defaults, ...shorthands };
    return { ...defaults, ...shorthands, ...opt };
}
async function obfuscateJs(source, opts = {}) {
    const p3opts = resolvePass3Opts(opts);
    const p1opts = {
        renameIdentifiers: opts.pass1?.renameIdentifiers ?? true,
        encryptStrings: opts.pass1?.encryptStrings ?? true,
        flattenControlFlow: opts.pass1?.flattenControlFlow ?? true,
        poisonIdentifiers: opts.pass1?.poisonIdentifiers ?? opts.poisonIdentifiers ?? false,
    };
    const { code: pass1Code, astJson } = (0, pass1_1.pass1)(source, p1opts);
    if (opts.pass2 !== false) {
        const wasm = await loadWasm();
        if (wasm) {
            const result = wasm.obf_process_js(astJson, opts.envFingerprint ?? false, opts.format ?? 'cjs');
            const p2code = result.js;
            const finalCode = p3opts !== false ? (0, pass3_1.pass3)(p2code, p3opts, result.build_id_b64) : p2code;
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
exports.PRESETS = {
    fast: {
        pass2: false,
        pass3: true,
    },
    balanced: {
        pass2: true,
        pass3: true,
        selfDefend: true,
        integrityTrap: true,
        callStackCheck: true,
        agentDisrupt: true,
    },
    max: {
        pass2: true,
        pass3: true,
        selfDefend: true,
        debugProtection: true,
        integrityTrap: true,
        antiAnalysis: true,
        deadCode: true,
        agentDisrupt: true,
        callStackCheck: true,
        antiLLM: true,
    },
};
function exportPreset(opts) {
    return JSON.stringify({ v: 1, ...opts });
}
function importPreset(json) {
    const parsed = JSON.parse(json);
    if (!parsed || parsed.v !== 1)
        throw new Error('invalid preset: unknown version');
    const { v, ...opts } = parsed;
    return opts;
}
async function batchObfuscate(files, opts) {
    return Promise.all(files.map(async ({ path, source }) => {
        try {
            const { code } = await obfuscateJs(source, opts);
            return { path, code };
        }
        catch (e) {
            return { path, code: '', error: e?.message ?? String(e) };
        }
    }));
}
async function batchObfuscateDart(files, opts) {
    return Promise.all(files.map(async ({ path, source }) => {
        try {
            const code = await obfuscateDart(source);
            return { path, code };
        }
        catch (e) {
            return { path, code: '', error: e?.message ?? String(e) };
        }
    }));
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
