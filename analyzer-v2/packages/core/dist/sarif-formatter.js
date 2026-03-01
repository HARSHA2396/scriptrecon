import path from 'path';
export function generateSarif(issues) {
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
