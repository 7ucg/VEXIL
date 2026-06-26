import { Pass1Options } from './pass1';
import { Pass3Options } from './pass3';
export interface ObfOptions {
    pass1?: Partial<Pass1Options>;
    pass2?: boolean;
    pass3?: boolean | Partial<Pass3Options>;
    envFingerprint?: boolean;
    dart?: boolean;
    format?: 'cjs' | 'umd' | 'iife';
}
export interface ObfResult {
    code: string;
    key?: string;
    buildId?: string;
}
export declare function obfuscateJs(source: string, opts?: ObfOptions): Promise<ObfResult>;
export { bundleAndObfuscate } from './bundle';
export type { BundleObfOptions } from './bundle';
export { vexilRollupPlugin } from './rollup-plugin';
export { vexil as vexilVitePlugin } from './vite-plugin';
export { VexilWebpackPlugin } from './webpack-plugin';
export declare function reObfuscate(code: string, opts?: Pass3Options): Promise<string>;
export declare function obfuscateDart(source: string): Promise<string>;
