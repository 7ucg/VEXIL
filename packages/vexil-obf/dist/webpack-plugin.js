"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VexilWebpackPlugin = void 0;
const index_1 = require("./index");
const FORMAT_MAP = {
    commonjs: 'cjs',
    commonjs2: 'cjs',
    cjs: 'cjs',
    umd: 'umd',
    umd2: 'umd',
    window: 'iife',
    var: 'iife',
    assign: 'iife',
    self: 'iife',
    global: 'iife',
};
function detectFormat(compiler) {
    const out = compiler.options?.output ?? {};
    const lib5 = out.library?.type;
    if (lib5 && FORMAT_MAP[lib5])
        return FORMAT_MAP[lib5];
    const lib4 = out.libraryTarget;
    if (lib4 && FORMAT_MAP[lib4])
        return FORMAT_MAP[lib4];
    return 'cjs';
}
class VexilWebpackPlugin {
    constructor(opts = {}) {
        this.opts = opts;
    }
    apply(compiler) {
        const fmt = detectFormat(compiler);
        compiler.hooks.compilation.tap('vexil-obf', (compilation) => {
            // webpack 5: use processAssets at SUMMARIZE stage (after Terser, before emit)
            const { PROCESS_ASSETS_STAGE_SUMMARIZE } = compilation.constructor || {};
            const stage = PROCESS_ASSETS_STAGE_SUMMARIZE ?? 1000;
            compilation.hooks.processAssets.tapPromise({ name: 'vexil-obf', stage }, async (assets) => {
                const tasks = [];
                for (const filename of Object.keys(assets)) {
                    if (!filename.endsWith('.js'))
                        continue;
                    tasks.push((async () => {
                        const asset = assets[filename];
                        const src = typeof asset.source === 'function' ? asset.source() : String(asset._value ?? '');
                        const { code } = await (0, index_1.obfuscateJs)(src, { pass2: true, ...this.opts, format: fmt });
                        // webpack 5 RawSource
                        const RawSource = compiler.webpack?.sources?.RawSource ??
                            (() => {
                                try {
                                    return require('webpack-sources').RawSource;
                                }
                                catch {
                                    return null;
                                }
                            })();
                        compilation.updateAsset(filename, RawSource ? new RawSource(code, false) : { source: () => code, size: () => Buffer.byteLength(code) });
                    })());
                }
                await Promise.all(tasks).catch(err => {
                    compilation.errors.push(new Error(`vexil-obf: ${err.message}`));
                });
            });
        });
    }
}
exports.VexilWebpackPlugin = VexilWebpackPlugin;
exports.default = VexilWebpackPlugin;
