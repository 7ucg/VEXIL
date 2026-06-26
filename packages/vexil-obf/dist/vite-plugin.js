"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.vexil = vexil;
const rollup_plugin_1 = require("./rollup-plugin");
function vexil(opts = {}) {
    return {
        ...(0, rollup_plugin_1.vexilRollupPlugin)(opts),
        apply: 'build',
        enforce: 'post',
    };
}
exports.default = vexil;
