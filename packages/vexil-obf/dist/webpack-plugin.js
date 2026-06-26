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
    // webpack 5: output.library.type
    const lib5 = out.library?.type;
    if (lib5 && FORMAT_MAP[lib5])
        return FORMAT_MAP[lib5];
    // webpack 4: output.libraryTarget
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
        compiler.hooks.emit.tapAsync('vexil-obf', async (compilation, done) => {
            const tasks = [];
            for (const filename of Object.keys(compilation.assets)) {
                if (!filename.endsWith('.js'))
                    continue;
                tasks.push((async () => {
                    const asset = compilation.assets[filename];
                    const src = typeof asset.source === 'function' ? asset.source() : String(asset._value ?? '');
                    const { code } = await (0, index_1.obfuscateJs)(src, { pass2: true, ...this.opts, format: fmt });
                    compilation.assets[filename] = {
                        source: () => code,
                        size: () => Buffer.byteLength(code),
                    };
                })());
            }
            try {
                await Promise.all(tasks);
            }
            catch (err) {
                compilation.errors.push(new Error(`vexil-obf: ${err.message}`));
            }
            done();
        });
    }
}
exports.VexilWebpackPlugin = VexilWebpackPlugin;
exports.default = VexilWebpackPlugin;
