import { pass1, Pass1Options } from './pass1';
import { pass3, Pass3Options } from './pass3';

export interface ObfOptions {
  pass1?: Partial<Pass1Options>;
  pass2?: boolean;
  pass3?: boolean | Partial<Pass3Options>;   // extra hardening on the final output
  envFingerprint?: boolean;
  dart?: boolean;
  format?: 'cjs' | 'umd' | 'iife';
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

function resolvePass3Opts(opt: ObfOptions['pass3']): Pass3Options | false {
  if (opt === false) return false;
  const defaults: Pass3Options = {
    hexNumbers: true,
    computedProps: true,
    stringArray: true,
    integrityTrap: true,
  };
  if (opt === true || opt === undefined) return defaults;
  return { ...defaults, ...opt };
}

export async function obfuscateJs(source: string, opts: ObfOptions = {}): Promise<ObfResult> {
  const p3opts = resolvePass3Opts(opts.pass3);

  const p1opts: Pass1Options = {
    renameIdentifiers: opts.pass1?.renameIdentifiers ?? true,
    encryptStrings: opts.pass1?.encryptStrings ?? true,
    flattenControlFlow: opts.pass1?.flattenControlFlow ?? true,
  };

  const { code: pass1Code, astJson } = pass1(source, p1opts);

  if (opts.pass2 !== false) {
    const wasm = await loadWasm();
    if (wasm) {
      const result = wasm.obf_process_js(astJson, opts.envFingerprint ?? false, opts.format ?? 'cjs');
      const p2code: string = result.js;
      const finalCode = p3opts !== false ? pass3(p2code, p3opts) : p2code;
      return {
        code: finalCode,
        key: result.key_b64,
        buildId: result.build_id_b64,
      };
    }
  }

  // WASM not available: return pass1 result (optionally pass3'd)
  const finalCode = p3opts !== false ? pass3(pass1Code, p3opts) : pass1Code;
  return { code: finalCode };
}

export { bundleAndObfuscate } from './bundle';
export type { BundleObfOptions } from './bundle';
export { vexilRollupPlugin } from './rollup-plugin';
export { vexil as vexilVitePlugin } from './vite-plugin';
export { VexilWebpackPlugin } from './webpack-plugin';

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
