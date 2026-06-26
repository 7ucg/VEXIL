export interface Pass3Options {
    selfDefend?: boolean;
    debugProtection?: boolean;
    deadCode?: boolean;
    hexNumbers?: boolean;
    computedProps?: boolean;
    stringArray?: boolean;
    antiAnalysis?: boolean;
    integrityTrap?: boolean;
}
export declare function pass3(code: string, opts?: Pass3Options): string;
