import { obfuscateJs, ObfOptions } from './index';

const FORMAT_MAP: Record<string, 'cjs' | 'umd' | 'iife'> = {
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

function detectFormat(compiler: any): 'cjs' | 'umd' | 'iife' {
  const out = compiler.options?.output ?? {};
  // webpack 5: output.library.type
  const lib5 = out.library?.type as string | undefined;
  if (lib5 && FORMAT_MAP[lib5]) return FORMAT_MAP[lib5];
  // webpack 4: output.libraryTarget
  const lib4 = out.libraryTarget as string | undefined;
  if (lib4 && FORMAT_MAP[lib4]) return FORMAT_MAP[lib4];
  return 'cjs';
}

export class VexilWebpackPlugin {
  private opts: ObfOptions;

  constructor(opts: ObfOptions = {}) {
    this.opts = opts;
  }

  apply(compiler: any): void {
    const fmt = detectFormat(compiler);

    compiler.hooks.emit.tapAsync('vexil-obf', async (compilation: any, done: () => void) => {
      const tasks: Promise<void>[] = [];

      for (const filename of Object.keys(compilation.assets)) {
        if (!filename.endsWith('.js')) continue;
        tasks.push(
          (async () => {
            const asset = compilation.assets[filename];
            const src: string =
              typeof asset.source === 'function' ? asset.source() : String(asset._value ?? '');
            const { code } = await obfuscateJs(src, { pass2: true, ...this.opts, format: fmt });
            compilation.assets[filename] = {
              source: () => code,
              size: () => Buffer.byteLength(code),
            };
          })()
        );
      }

      try {
        await Promise.all(tasks);
      } catch (err) {
        compilation.errors.push(new Error(`vexil-obf: ${(err as Error).message}`));
      }

      done();
    });
  }
}

export default VexilWebpackPlugin;
