import fs from 'fs';
import path from 'path';

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

export function generateSarif(issues: SarifIssue[]): string {
    const sarif = {
        version: "2.1.0",
        $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        runs: [
            {
                tool: {
                    driver: {
                        name: "JS Recon Analyzer PRO (Next-Gen)",
                        informationUri: "https://example.com",
                        rules: Array.from(new Set(issues.map(i => i.ruleId))).map(ruleId => ({
                            id: ruleId,
                            shortDescription: { text: ruleId }
                        }))
                    }
                },
                results: issues.map(issue => ({
                    ruleId: issue.ruleId,
                    level: issue.level,
                    message: {
                        text: issue.message
                    },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: {
                                    uri: path.basename(issue.file)
                                },
                                region: {
                                    startLine: issue.line
                                }
                            }
                        }
                    ]
                }))
            }
        ]
    };

    return JSON.stringify(sarif, null, 2);
}
