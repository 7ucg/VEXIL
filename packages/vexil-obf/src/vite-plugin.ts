import { vexilRollupPlugin } from './rollup-plugin';
import { ObfOptions } from './index';

export function vexil(opts: ObfOptions = {}) {
  return {
    ...vexilRollupPlugin(opts),
    apply: 'build' as const,
    enforce: 'post' as const,
  };
}

export default vexil;
