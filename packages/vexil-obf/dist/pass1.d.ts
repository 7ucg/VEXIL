export interface Pass1Options {
    renameIdentifiers: boolean;
    encryptStrings: boolean;
    flattenControlFlow: boolean;
    poisonIdentifiers: boolean;
}
export interface Pass1Result {
    code: string;
    astJson: string;
}
export declare function pass1(source: string, opts: Pass1Options): Pass1Result;
