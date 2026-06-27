import { Pass1Options } from './pass1';
import { Pass3Options } from './pass3';
export interface ObfOptions {
    pass1?: Partial<Pass1Options>;
    pass2?: boolean;
    pass3?: boolean | Partial<Pass3Options>;
    envFingerprint?: boolean;
    dart?: boolean;
    format?: 'cjs' | 'umd' | 'iife';
    selfDefend?: boolean;
    debugProtection?: boolean;
    integrityTrap?: boolean;
    antiAnalysis?: boolean;
    deadCode?: boolean;
    callStackCheck?: boolean;
    agentDisrupt?: boolean;
    antiLLM?: boolean;
    poisonIdentifiers?: boolean;
    jumpEncoding?: boolean;
    decoyOpcodes?: boolean;
    statefulOpcodes?: boolean;
    stackEncoding?: boolean;
}
export interface BatchResult {
    path: string;
    code: string;
    error?: string;
}
export interface ObfResult {
    code: string;
    key?: string;
    buildId?: string;
}
export declare function obfuscateJs(source: string, opts?: ObfOptions): Promise<ObfResult>;
export declare const PRESETS: {
    fast: {
        pass2: false;
        pass3: true;
    };
    balanced: {
        pass2: true;
        pass3: true;
        selfDefend: true;
        integrityTrap: true;
        callStackCheck: true;
        agentDisrupt: true;
    };
    max: {
        pass2: true;
        pass3: true;
        selfDefend: true;
        debugProtection: true;
        integrityTrap: true;
        antiAnalysis: true;
        deadCode: true;
        agentDisrupt: true;
        callStackCheck: true;
        antiLLM: true;
    };
};
export declare function exportPreset(opts: ObfOptions): string;
export declare function importPreset(json: string): ObfOptions;
export declare function batchObfuscate(files: Array<{
    path: string;
    source: string;
}>, opts?: ObfOptions): Promise<BatchResult[]>;
export declare function batchObfuscateDart(files: Array<{
    path: string;
    source: string;
}>, opts?: ObfOptions): Promise<BatchResult[]>;
export { bundleAndObfuscate } from './bundle';
export type { BundleObfOptions } from './bundle';
export { vexilRollupPlugin } from './rollup-plugin';
export { vexil as vexilVitePlugin } from './vite-plugin';
export { VexilWebpackPlugin } from './webpack-plugin';
export declare function reObfuscate(code: string, opts?: Pass3Options): Promise<string>;
export declare function obfuscateDart(source: string): Promise<string>;
