import { ObfOptions } from './index';
export declare function vexilRollupPlugin(opts?: ObfOptions): {
    name: string;
    generateBundle(outputOptions: any, bundle: any): Promise<void>;
};
