/* tslint:disable */
/* eslint-disable */

export class ObfOutput {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly build_id_b64: string;
    readonly js: string;
    readonly key_b64: string;
}

export function obf_dart(source: string): string;

export function obf_process_js(babel_ast_json: string, env_fingerprint: boolean, format?: string | null): ObfOutput;
