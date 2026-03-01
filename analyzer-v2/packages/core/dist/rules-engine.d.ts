export interface CustomRule {
    id: string;
    description: string;
    type: 'SINK' | 'SOURCE' | 'AST_PATTERN' | 'REGEX_MATCH';
    severity: number;
    targetPattern: string;
}
export declare class CustomRulesEngine {
    private rules;
    constructor();
    loadRulesFromDirectory(dirPath: string): void;
    getSinks(): {
        functionName: string;
        id: string;
        severity: number;
        description: string;
    }[];
    getSources(): {
        sourcePattern: string;
        id: string;
        severity: number;
        description: string;
    }[];
}
