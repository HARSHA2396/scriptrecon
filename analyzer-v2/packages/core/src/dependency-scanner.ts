import fs from 'fs';
import path from 'path';

export interface DependencyIssue {
    pkg: string;
    version: string;
    vulnerabilities: string[];
    isTyposquatting: boolean;
}

// A dictionary of known highly-targeted typosquatting packages
const TYPOSQUAT_DICTIONARY: Record<string, string> = {
    'lo-dash': 'lodash',
    'crossenv': 'cross-env',
    'node-fetchs': 'node-fetch',
    'expresss': 'express',
    'electorn': 'electron'
};

/**
 * Parses package.json and checks dependencies for Typosquatting
 * and queries OSV.dev (Open Source Vulnerabilities) API for known CVEs.
 */
export async function scanDependencies(dirPath: string): Promise<DependencyIssue[]> {
    const pkgPath = path.join(dirPath, 'package.json');
    if (!fs.existsSync(pkgPath)) {
        return [];
    }

    try {
        const pkgData = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        const deps = { ...(pkgData.dependencies || {}), ...(pkgData.devDependencies || {}) };
        const issues: DependencyIssue[] = [];

        // 1. Typosquatting Check
        for (const [pkgName, version] of Object.entries(deps)) {
            if (TYPOSQUAT_DICTIONARY[pkgName]) {
                issues.push({
                    pkg: pkgName,
                    version: version as string,
                    vulnerabilities: [`Critical Typosquatting detected: You likely meant to install '${TYPOSQUAT_DICTIONARY[pkgName]}'`],
                    isTyposquatting: true
                });
            }
        }

        // 2. OSV.dev CVE Query
        // For demonstration, we'll query OSV's public API to grab any known vulns for the given packages.
        // We use dynamic import for Axios to ensure compatibility if run in a restricted environment.
        const axios = (await import('axios')).default;

        for (const [pkgName, version] of Object.entries(deps)) {
            // Typosquatted packages usually aren't queried for standard CVEs
            if (TYPOSQUAT_DICTIONARY[pkgName]) continue;

            const cleanVersion = (version as string).replace(/[\^~>]/g, '');

            try {
                const response = await axios.post('https://api.osv.dev/v1/query', {
                    package: {
                        name: pkgName,
                        ecosystem: 'npm'
                    },
                    version: cleanVersion
                });

                if (response.data && response.data.vulns && response.data.vulns.length > 0) {
                    const cves = response.data.vulns.map((v: any) => v.id || v.aliases?.[0] || 'Unknown CVE');
                    issues.push({
                        pkg: pkgName,
                        version: cleanVersion,
                        vulnerabilities: cves,
                        isTyposquatting: false
                    });
                }
            } catch (err) {
                 // API failing shouldn't crash the scanner.
                 // console.warn(`Failed to connect to OSV API for ${pkgName}`);
            }
        }

        return issues;

    } catch (e: any) {
        throw new Error(`Failed to parse package.json for Dependency Scan: ${e.message}`);
    }
}
