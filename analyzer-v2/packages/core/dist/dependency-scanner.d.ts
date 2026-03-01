export interface DependencyIssue {
    pkg: string;
    version: string;
    vulnerabilities: string[];
    isTyposquatting: boolean;
}
/**
 * Parses package.json and checks dependencies for Typosquatting
 * and queries OSV.dev (Open Source Vulnerabilities) API for known CVEs.
 */
export declare function scanDependencies(dirPath: string): Promise<DependencyIssue[]>;
