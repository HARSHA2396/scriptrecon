export interface RemediationPatch {
    filePath: string;
    originalContent: string;
    patchedContent: string;
    description: string;
    diffSnippet: string;
}
export declare class AutoRemediator {
    private safeReadFile;
    /**
     * Replaces a vulnerable RegExp construction with a safe alternative.
     * Pattern: new RegExp("...") -> Safe construction or note.
     * This is a simplified demo for the Enterprise Remediation Feature.
     */
    buildReDoSPatch(filePath: string, sourceLine: number, matchText: string): RemediationPatch | null;
    /**
     * Fixes Command Injection by swapping `exec` to `execFile` or `spawn`
     * and parameterizing the input.
     */
    buildCommandInjectionPatch(filePath: string, sourceLine: number, calleeName: string, argVar: string): RemediationPatch | null;
    /**
     * Fixes SQL Injection by trying to replace string concatenation with parameterized queries.
     */
    buildSqlInjectionPatch(filePath: string, sourceLine: number): RemediationPatch | null;
}
