#!/usr/bin/env node
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const fs = __importStar(require("fs"));
const index_1 = require("./index");
const program = new commander_1.Command();
program
    .name('vexil-obf')
    .description('JS/Dart obfuscator with novel VEXIL-VM protection')
    .version('1.0.0');
program.command('js <input>')
    .description('Obfuscate a JavaScript or TypeScript file')
    .option('-o, --output <file>', 'output file (default: input.obf.js)')
    .option('-f, --format <fmt>', 'output format: cjs | umd | iife (default: cjs)', 'cjs')
    .option('--no-rename', 'skip identifier renaming')
    .option('--no-strings', 'skip string encryption')
    .option('--no-flatten', 'skip control-flow flattening')
    .option('--no-pass2', 'skip VM protection (pass 2)')
    .option('--env-fingerprint', 'tie decryption key to VOBF_ID env var')
    .option('--key-out <file>', 'write AES key to file')
    .action(async (input, opts) => {
    const fmt = opts.format;
    if (fmt !== 'cjs' && fmt !== 'umd' && fmt !== 'iife') {
        console.error('--format must be cjs, umd, or iife');
        process.exit(1);
    }
    const source = fs.readFileSync(input, 'utf8');
    const result = await (0, index_1.obfuscateJs)(source, {
        pass1: {
            renameIdentifiers: opts.rename !== false,
            encryptStrings: opts.strings !== false,
            flattenControlFlow: opts.flatten !== false,
        },
        pass2: opts.pass2 !== false,
        format: fmt,
        envFingerprint: opts.envFingerprint ?? false,
    });
    const outFile = opts.output || input.replace(/\.([jt]s)$/, '.obf.js');
    fs.writeFileSync(outFile, result.code, 'utf8');
    console.log('→ ' + outFile);
    if (result.key && opts.keyOut) {
        fs.writeFileSync(opts.keyOut, result.key, 'utf8');
        console.log('→ key: ' + opts.keyOut);
    }
    if (result.key) {
        console.log('Key (base64):', result.key);
    }
});
program.command('dart <input>')
    .description('Obfuscate a Dart source file (string encryption)')
    .option('-o, --output <file>', 'output file (default: input.obf.dart)')
    .action(async (input, opts) => {
    const source = fs.readFileSync(input, 'utf8');
    const result = await (0, index_1.obfuscateDart)(source);
    const outFile = opts.output || input.replace(/\.dart$/, '.obf.dart');
    fs.writeFileSync(outFile, result, 'utf8');
    console.log('→ ' + outFile);
});
program.parse();
