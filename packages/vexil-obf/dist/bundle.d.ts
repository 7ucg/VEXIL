import { ObfOptions, ObfResult } from './index';
export interface BundleObfOptions extends ObfOptions {
    entry: string;
    platform?: 'browser' | 'node' | 'neutral';
    /** esbuild output format before obfuscation; defaults to 'iife' for browser, 'cjs' for node */
    bundleFormat?: 'iife' | 'cjs' | 'esm';
    external?: string[];
    target?: string | string[];
}
export declare function bundleAndObfuscate(opts: BundleObfOptions): Promise<ObfResult>;
