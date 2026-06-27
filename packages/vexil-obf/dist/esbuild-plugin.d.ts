import type { ObfOptions } from './index';
interface EsbuildOutputFile {
    path: string;
    contents: Uint8Array;
}
interface EsbuildBuildResult {
    outputFiles?: EsbuildOutputFile[];
}
interface EsbuildBuild {
    initialOptions: {
        format?: string;
    };
    onEnd(callback: (result: EsbuildBuildResult) => Promise<any>): void;
}
export interface EsbuildPlugin {
    name: string;
    setup(build: EsbuildBuild): void;
}
export declare function vexilEsbuildPlugin(opts?: ObfOptions): EsbuildPlugin;
export {};
