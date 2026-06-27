import { pass1, Pass1Options } from './pass1';
import { pass3, Pass3Options } from './pass3';

export interface ObfOptions {
  pass1?: Partial<Pass1Options>;
  pass2?: boolean;
  pass3?: boolean | Partial<Pass3Options>;   // extra hardening on the final output
  envFingerprint?: boolean;
  dart?: boolean;
  format?: 'cjs' | 'umd' | 'iife';
  // shorthand flags that map into pass3 options when pass3 is not explicitly configured
  selfDefend?: boolean;
  debugProtection?: boolean;
  integrityTrap?: boolean;
  antiAnalysis?: boolean;
  deadCode?: boolean;
  callStackCheck?: boolean;
  agentDisrupt?: boolean;
  antiLLM?: boolean;
  poisonIdentifiers?: boolean;
  poisonStringArray?: boolean;  // default false; auto-enabled when antiLLM: true
  envKeyBind?: 'node' | 'browser' | false;
  // VM bytecode hardening flags (accepted; always-on in Rust core when pass2 is active)
  jumpEncoding?: boolean;
  decoyOpcodes?: boolean;
  statefulOpcodes?: boolean;
  stackEncoding?: boolean;
  // Feature 5: macro-op aggregation (default true when pass2 is active)
  macroOps?: boolean;
}

export interface BatchResult {
  path: string;
  code: string;
  error?: string;
}

export interface ObfResult {
  code: string;
  key?: string;
  buildId?: string;
}

let wasmModule: any = null;

async function loadWasm() {
  if (!wasmModule) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      wasmModule = require('../wasm/vexil_obf_wasm.js') as unknown;
    } catch {
      wasmModule = null;
    }
  }
  return wasmModule;
}

function resolvePass3Opts(opts: ObfOptions): Pass3Options | false {
  const opt = opts.pass3;
  if (opt === false) return false;
  const defaults: Pass3Options = {
    hexNumbers: true,
    computedProps: true,
    stringArray: true,
    integrityTrap: true,
  };
  // Collect shorthand top-level flags
  const shorthands: Partial<Pass3Options> = {};
  if (opts.selfDefend !== undefined) shorthands.selfDefend = opts.selfDefend;
  if (opts.debugProtection !== undefined) shorthands.debugProtection = opts.debugProtection;
  if (opts.integrityTrap !== undefined) shorthands.integrityTrap = opts.integrityTrap;
  if (opts.antiAnalysis !== undefined) shorthands.antiAnalysis = opts.antiAnalysis;
  if (opts.deadCode !== undefined) shorthands.deadCode = opts.deadCode;
  if (opts.callStackCheck !== undefined) shorthands.callStackCheck = opts.callStackCheck;
  if (opts.agentDisrupt !== undefined) shorthands.agentDisrupt = opts.agentDisrupt;
  if (opts.antiLLM !== undefined) shorthands.antiLLM = opts.antiLLM;
  // poisonStringArray: explicit opt takes precedence; otherwise auto-enable when antiLLM: true
  if (opts.poisonStringArray !== undefined) {
    shorthands.poisonStringArray = opts.poisonStringArray;
  } else if (opts.antiLLM === true) {
    shorthands.poisonStringArray = true;
  }
  if (opts.envKeyBind !== undefined) shorthands.envKeyBind = opts.envKeyBind;

  if (opt === true || opt === undefined) return { ...defaults, ...shorthands };
  return { ...defaults, ...shorthands, ...opt };
}

function stripSourceMaps(code: string): string {
  code = code.replace(/\/\/# sourceMappingURL=\S+/g, '');
  code = code.replace(/\/\*# sourceMappingURL=[\s\S]*?\*\//g, '');
  code = code.replace(/\/\/# sourceURL=\S+/g, '');
  return code;
}

export async function obfuscateJs(source: string, opts: ObfOptions = {}): Promise<ObfResult> {
  const p3opts = resolvePass3Opts(opts);

  const p1opts: Pass1Options = {
    renameIdentifiers: opts.pass1?.renameIdentifiers ?? true,
    encryptStrings: opts.pass1?.encryptStrings ?? true,
    flattenControlFlow: opts.pass1?.flattenControlFlow ?? true,
    poisonIdentifiers: opts.pass1?.poisonIdentifiers ?? opts.poisonIdentifiers ?? false,
  };

  const { code: pass1Code, astJson } = pass1(source, p1opts);

  if (opts.pass2 !== false) {
    const wasm = await loadWasm();
    if (wasm) {
      const result = wasm.obf_process_js(astJson, opts.envFingerprint ?? false, opts.format ?? 'cjs', opts.macroOps !== false);
      const p2code: string = result.js;
      const rawCode = p3opts !== false ? pass3(p2code, p3opts, result.build_id_b64) : p2code;
      return {
        code: stripSourceMaps(rawCode),
        key: result.key_b64,
        buildId: result.build_id_b64,
      };
    }
  }

  // WASM not available: return pass1 result (optionally pass3'd)
  const rawCode = p3opts !== false ? pass3(pass1Code, p3opts) : pass1Code;
  return { code: stripSourceMaps(rawCode) };
}

export const PRESETS = {
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
    antiLLM: true,
    poisonStringArray: true,
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
    poisonIdentifiers: true,
    poisonStringArray: true,
    macroOps: true,
  },
} satisfies Record<string, ObfOptions>;

export function exportPreset(opts: ObfOptions): string {
  return JSON.stringify({ v: 1, ...opts });
}

export function importPreset(json: string): ObfOptions {
  const parsed = JSON.parse(json);
  if (!parsed || parsed.v !== 1) throw new Error('invalid preset: unknown version');
  const { v, ...opts } = parsed;
  return opts as ObfOptions;
}

export async function batchObfuscate(
  files: Array<{ path: string; source: string }>,
  opts?: ObfOptions
): Promise<BatchResult[]> {
  return Promise.all(
    files.map(async ({ path, source }) => {
      try {
        const { code } = await obfuscateJs(source, opts);
        return { path, code };
      } catch (e: any) {
        return { path, code: '', error: e?.message ?? String(e) };
      }
    })
  );
}

export async function batchObfuscateDart(
  files: Array<{ path: string; source: string }>,
  opts?: ObfOptions
): Promise<BatchResult[]> {
  return Promise.all(
    files.map(async ({ path, source }) => {
      try {
        const code = await obfuscateDart(source);
        return { path, code };
      } catch (e: any) {
        return { path, code: '', error: e?.message ?? String(e) };
      }
    })
  );
}

export { bundleAndObfuscate } from './bundle';
export type { BundleObfOptions } from './bundle';
export { vexilRollupPlugin } from './rollup-plugin';
export { vexil as vexilVitePlugin } from './vite-plugin';
export { VexilWebpackPlugin } from './webpack-plugin';
export { vexilEsbuildPlugin } from './esbuild-plugin';

// Re-obfuscate already-obfuscated JS (applies pass3 — identifier renaming, no string re-encryption).
export async function reObfuscate(code: string, opts: Pass3Options = {}): Promise<string> {
  return pass3(code, { hexNumbers: true, ...opts });
}

export async function obfuscateDart(source: string): Promise<string> {
  const wasm = await loadWasm();
  if (wasm) {
    return wasm.obf_dart(source);
  }
  return dartFallback(source);
}

function dartFallback(source: string): string {
  const key = Array.from({length: 16}, () => Math.floor(Math.random() * 256));
  const encrypted: string[] = [];
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
