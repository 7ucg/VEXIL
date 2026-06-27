"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.vexilEsbuildPlugin = vexilEsbuildPlugin;
const index_1 = require("./index");
function vexilEsbuildPlugin(opts = {}) {
    return {
        name: 'vexil-obf',
        setup(build) {
            build.onEnd(async (result) => {
                if (!result.outputFiles)
                    return;
                const fmt = build.initialOptions.format ?? 'cjs';
                const esMap = { cjs: 'cjs', esm: 'umd', iife: 'iife' };
                const format = (esMap[fmt] ?? 'cjs');
                for (const file of result.outputFiles) {
                    if (!file.path.endsWith('.js'))
                        continue;
                    const source = new TextDecoder().decode(file.contents);
                    const { code } = await (0, index_1.obfuscateJs)(source, { pass2: true, ...opts, format });
                    file.contents = new TextEncoder().encode(code);
                }
            });
        },
    };
}
