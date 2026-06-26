"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bundleAndObfuscate = bundleAndObfuscate;
const index_1 = require("./index");
async function bundleAndObfuscate(opts) {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    let esbuild;
    try {
        esbuild = require('esbuild');
    }
    catch {
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
    const bundledCode = result.outputFiles[0].text;
    const obfFormat = opts.format ?? (bundleFormat === 'iife' ? 'iife' : platform === 'node' ? 'cjs' : 'umd');
    return (0, index_1.obfuscateJs)(bundledCode, { ...opts, format: obfFormat });
}
