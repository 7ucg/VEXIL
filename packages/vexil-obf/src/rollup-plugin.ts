import { obfuscateJs, ObfOptions } from './index';

export function vexilRollupPlugin(opts: ObfOptions = {}) {
  return {
    name: 'vexil-obf',
    async generateBundle(outputOptions: any, bundle: any) {
      for (const chunk of Object.values(bundle) as any[]) {
        if (chunk.type !== 'chunk') continue;
        const fmt: 'cjs' | 'umd' | 'iife' =
          outputOptions.format === 'iife' ? 'iife' :
          outputOptions.format === 'umd'  ? 'umd'  : 'cjs';
        const { code } = await obfuscateJs(chunk.code, {
          pass2: true,
          ...opts,
          format: fmt,  // outputOptions.format always wins — opts.format is for standalone use
        });
        chunk.code = code;
      }
    },
  };
}
