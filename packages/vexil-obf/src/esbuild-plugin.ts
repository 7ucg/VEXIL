import { obfuscateJs } from './index';
import type { ObfOptions } from './index';

// Minimal inline types so esbuild is not a required devDependency.
interface EsbuildOutputFile { path: string; contents: Uint8Array; }
interface EsbuildBuildResult { outputFiles?: EsbuildOutputFile[]; }
interface EsbuildBuild {
  initialOptions: { format?: string };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onEnd(callback: (result: EsbuildBuildResult) => Promise<any>): void;
}
export interface EsbuildPlugin { name: string; setup(build: EsbuildBuild): void; }

export function vexilEsbuildPlugin(opts: ObfOptions = {}): EsbuildPlugin {
  return {
    name: 'vexil-obf',
    setup(build: EsbuildBuild) {
      build.onEnd(async (result: EsbuildBuildResult) => {
        if (!result.outputFiles) return;
        const fmt = build.initialOptions.format ?? 'cjs';
        const esMap: Record<string, string> = { cjs: 'cjs', esm: 'umd', iife: 'iife' };
        const format = (esMap[fmt] ?? 'cjs') as 'cjs' | 'umd' | 'iife';
        for (const file of result.outputFiles) {
          if (!file.path.endsWith('.js')) continue;
          const source = new TextDecoder().decode(file.contents);
          const { code } = await obfuscateJs(source, { pass2: true, ...opts, format });
          file.contents = new TextEncoder().encode(code);
        }
      });
    },
  };
}
