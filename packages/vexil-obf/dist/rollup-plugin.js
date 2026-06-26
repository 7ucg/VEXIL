"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.vexilRollupPlugin = vexilRollupPlugin;
const index_1 = require("./index");
function vexilRollupPlugin(opts = {}) {
    return {
        name: 'vexil-obf',
        async generateBundle(outputOptions, bundle) {
            for (const chunk of Object.values(bundle)) {
                if (chunk.type !== 'chunk')
                    continue;
                const fmt = outputOptions.format === 'iife' ? 'iife' :
                    outputOptions.format === 'umd' ? 'umd' : 'cjs';
                const { code } = await (0, index_1.obfuscateJs)(chunk.code, {
                    pass2: true,
                    ...opts,
                    format: fmt, // outputOptions.format always wins — opts.format is for standalone use
                });
                chunk.code = code;
            }
        },
    };
}
