/**
 * Generates SARIF (Static Analysis Results Interchange Format) JSON
 * Used for GitHub actions, GitLab native security, and VSCode tooltips.
 */
export interface SarifIssue {
    ruleId: string;
    level: 'error' | 'warning' | 'note';
    message: string;
    file: string;
    line: number;
}
export declare function generateSarif(issues: SarifIssue[]): string;
