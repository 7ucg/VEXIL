export interface Pass3Options {
    selfDefend?: boolean;
    debugProtection?: boolean;
    deadCode?: boolean;
    hexNumbers?: boolean;
    computedProps?: boolean;
    stringArray?: boolean;
    antiAnalysis?: boolean;
    integrityTrap?: boolean;
    callStackCheck?: boolean;
    agentDisrupt?: boolean;
    antiLLM?: boolean;
}
export declare function pass3(code: string, opts?: Pass3Options, buildId?: string): string;
