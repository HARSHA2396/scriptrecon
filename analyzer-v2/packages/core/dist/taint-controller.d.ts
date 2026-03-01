interface TaintNode {
    variableName: string;
    flow: string[];
    isSanitized: boolean;
}
export declare class TaintController {
    private taintMap;
    private currentFile;
    private currentDir;
    private fileImports;
    private autoFixer;
    private customRules;
    collectedIssues: any[];
    constructor();
    loadCustomRules(rulesDir: string): void;
    /**
     * Initializes a taint trace from a known source (e.g., req.query or a function param).
     */
    markTainted(variableName: string, sourceContext: string, previousFlow?: string[]): void;
    /**
     * CFG Reachability Downshift: Returns visual severity level based on file paths
     */
    private getSeverityLevel;
    /**
     * Propagates taint from one variable to another (e.g., const b = a;)
     */
    propagateTaint(sourceName: string, targetVar: string): void;
    /**
     * Recursive Taint Tracking: Evaluates if an AST node contains tainted references.
     * Supports Identifiers, Deep Property Access (MemberExpression), TemplateLiterals, and BinaryExpressions.
     */
    isNodeTainted(node: any): {
        tainted: boolean;
        sourceVar?: string;
    };
    /**
     * Parse and walk a JS file using Acorn and Astray
     */
    analyzeFile(filePath: string): void;
    /**
     * Analyze raw source code in memory (Browser / Web App compatibility)
     */
    analyzeSource(code: string, filePath?: string): void;
    private getVisitor;
    dumpTaintState(): [string, TaintNode][];
    /**
     * Entrypoint for evaluating a Cross-File Call with Tainted Parameters
     */
    analyzeCrossFileCall(targetFile: string, exportName: string, taintedArgs: {
        index: number;
        srcFlow: string[];
    }[]): void;
}
export {};
