#!/usr/bin/env node
import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { obfuscateJs, obfuscateDart } from './index';

const program = new Command();

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
  .action(async (input: string, opts: any) => {
    const fmt = opts.format as 'cjs' | 'umd' | 'iife';
    if (fmt !== 'cjs' && fmt !== 'umd' && fmt !== 'iife') {
      console.error('--format must be cjs, umd, or iife');
      process.exit(1);
    }
    const source = fs.readFileSync(input, 'utf8');
    const result = await obfuscateJs(source, {
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
  .action(async (input: string, opts: any) => {
    const source = fs.readFileSync(input, 'utf8');
    const result = await obfuscateDart(source);
    const outFile = opts.output || input.replace(/\.dart$/, '.obf.dart');
    fs.writeFileSync(outFile, result, 'utf8');
    console.log('→ ' + outFile);
  });

program.parse();
