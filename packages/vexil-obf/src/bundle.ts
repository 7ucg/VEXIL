import { obfuscateJs, ObfOptions, ObfResult } from './index';

export interface BundleObfOptions extends ObfOptions {
  entry: string;
  platform?: 'browser' | 'node' | 'neutral';
  /** esbuild output format before obfuscation; defaults to 'iife' for browser, 'cjs' for node */
  bundleFormat?: 'iife' | 'cjs' | 'esm';
  external?: string[];
  target?: string | string[];
}

export async function bundleAndObfuscate(opts: BundleObfOptions): Promise<ObfResult> {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  let esbuild: any;
  try {
    esbuild = require('esbuild');
  } catch {
    throw new Error('vexil-obf: esbuild not found. Install it: npm i esbuild');
  }

  const platform = opts.platform ?? 'browser';
  const bundleFormat = opts.bundleFormat ?? (platform === 'node' ? 'cjs' : 'iife');

  const result = await esbuild.build({
    entryPoints: [opts.entry],
    bundle: true,
    platform,
    format: bundleFormat,
    write: false,
    external: opts.external ?? [],
    target: opts.target,
    minify: false,
    sourcemap: false,
  });

  const bundledCode: string = result.outputFiles[0].text;

  const obfFormat = opts.format ?? (bundleFormat === 'iife' ? 'iife' : platform === 'node' ? 'cjs' : 'umd');

  return obfuscateJs(bundledCode, { ...opts, format: obfFormat });
}
