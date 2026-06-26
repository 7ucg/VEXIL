import { ObfOptions } from './index';
export declare function vexil(opts?: ObfOptions): {
    apply: "build";
    enforce: "post";
    name: string;
    generateBundle(outputOptions: any, bundle: any): Promise<void>;
};
export default vexil;
