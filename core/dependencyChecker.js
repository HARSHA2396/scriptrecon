/**
 * Dependency Vulnerability Scanner
 * Identifies known vulnerable JavaScript libraries
 */

const store = require("./store");
const { log } = require("../utils/logger");

// Database of known vulnerable packages (version ranges)
// In production, this would connect to CVE databases (NVD, Snyk, etc.)
const VULNERABLE_PACKAGES = {
    // jQuery
    "jquery": [
        { max_version: "3.4.1", cves: ["CVE-2019-11358"], severity: 6, type: "XSS" },
        { max_version: "1.12.3", cves: ["CVE-2016-10506"], severity: 7, type: "XSS" }
    ],
    
    // Lodash
    "lodash": [
        { max_version: "4.17.20", cves: ["CVE-2021-23337"], severity: 9, type: "Prototype Pollution" },
        { max_version: "4.17.15", cves: ["CVE-2018-16487"], severity: 8, type: "Prototype Pollution" }
    ],
    
    // Moment.js (deprecated, vulnerable)
    "moment": [
        { max_version: "2.29.4", severity: 5, type: "Deprecated/Vulnerable" }
    ],
    
    // Express
    "express": [
        { max_version: "4.16.3", cves: ["CVE-2018-16487"], severity: 8, type: "IDOR" }
    ],
    
    // Axios
    "axios": [
        { max_version: "0.18.0", cves: ["CVE-2019-10742"], severity: 7, type: "SSRF" }
    ],
    
    // Webpack-dev-server
    "webpack-dev-server": [
        { max_version: "3.10.3", cves: ["CVE-2019-10894"], severity: 8, type: "RCE" }
    ],
    
    // Node-fetch
    "node-fetch": [
        { max_version: "2.6.1", cves: ["CVE-2022-22911"], severity: 8, type: "SSRF" }
    ],
    
    // Serialize-javascript
    "serialize-javascript": [
        { max_version: "4.0.0", cves: ["CVE-2020-7660"], severity: 8, type: "RCE" }
    ]
};

/**
 * Extract library name and version from code
 */
function extractLibraryInfo(code) {
    const libraries = new Map();
    
    // Package metadata comments
    const patterns = [
        /\/\/!\s*(\w+)@([\d.]+)/gi,                    // //! jquery@3.6.0
        /\/\*!\s*(\w+)\s+(v?[\d.]+)/gi,                // /*! jquery 3.6.0
        /"name"\s*:\s*"([\w@\-\.]+)",\s*"version"\s*:\s*"([\d.]+)"/gi  // "name": "jquery", "version": "3.6.0"
    ];
    
    // Direct requires/imports
    const requirePatterns = [
        /require\s*\(\s*['"](\w+)['"].*?@([\d.]+)/gi,
        /import\s+[\w]*\s+from\s*['"](\w+)[@/]([\d.]+)/gi
    ];
    
    patterns.forEach(p => {
        const matches = code.matchAll(p);
        for (const match of matches) {
            if (match[1] && match[2]) {
                const name = match[1].toLowerCase();
                const version = match[2];
                if (!libraries.has(name)) {
                    libraries.set(name, version);
                }
            }
        }
    });
    
    // Library fingerprints (heuristics)
    if (code.includes("jQuery") || code.includes("jquery")) {
        if (!libraries.has("jquery")) {
            const match = code.match(/jQuery\.fn\.jquery\s*=\s*["']([^"']+)["']/);
            if (match) libraries.set("jquery", match[1]);
        }
    }
    
    if (code.includes("React.version")) {
        const match = code.match(/React\.version\s*=\s*["']([^"']+)["']/);
        if (match) libraries.set("react", match[1]);
    }
    
    if (code.includes("moment.version")) {
        const match = code.match(/moment\.version\s*=\s*["']([^"']+)["']/);
        if (match) libraries.set("moment", match[1]);
    }
    
    if (code.includes("_lodash")) {
        if (!libraries.has("lodash")) libraries.set("lodash", "unknown");
    }
    
    return libraries;
}

/**
 * Compare versions (e.g., 3.5.0 > 3.4.1)
 */
function compareVersions(current, max) {
    try {
        current = String(current).split(".").map(Number);
        max = String(max).split(".").map(Number);
        
        for (let i = 0; i < Math.max(current.length, max.length); i++) {
            const c = current[i] || 0;
            const m = max[i] || 0;
            if (c > m) return 1;
            if (c < m) return -1;
        }
        return 0;
    } catch {
        return 0; // Can't compare, assume ok
    }
}

/**
 * Check for vulnerable dependencies
 */
function detectVulnerableDependencies(code) {
    const libraries = extractLibraryInfo(code);
    const vulnerabilities = [];
    
    libraries.forEach((version, libName) => {
        const vulnList = VULNERABLE_PACKAGES[libName];
        
        if (!vulnList) return;
        
        vulnList.forEach(vuln => {
            // If version is unknown, check if library exists (potential vuln)
            if (version === "unknown") {
                vulnerabilities.push({
                    library: libName,
                    version: "unknown",
                    severity: vuln.severity,
                    type: vuln.type,
                    cves: vuln.cves || [],
                    message: `${libName}: Version unknown, may contain known vulnerabilities`
                });
                return;
            }
            
            // Check if current version is vulnerable
            const cmp = compareVersions(version, vuln.max_version);
            if (cmp <= 0) {
                vulnerabilities.push({
                    library: libName,
                    version: version,
                    vulnerableUpTo: vuln.max_version,
                    severity: vuln.severity,
                    type: vuln.type,
                    cves: vuln.cves || [],
                    message: `${libName}@${version}: Vulnerable to ${vuln.type}. Upgrade to a version > ${vuln.max_version}`
                });
            }
        });
    });
    
    if (vulnerabilities.length === 0) return;
    
    log("\n[Vulnerable Dependencies]");
    vulnerabilities.forEach(vuln => {
        const severity_map = {
            9: "🔴 CRITICAL",
            8: "🟠 HIGH",
            7: "🟡 MEDIUM",
            6: "🔵 LOW"
        };
        
        log(` ${severity_map[vuln.severity] || "ℹ️"} ${vuln.library}@${vuln.version}`);
        if (vuln.cves && vuln.cves.length > 0) {
            log(`    CVEs: ${vuln.cves.join(", ")}`);
        }
        log(`    ${vuln.message}`);
        
        // Add to store
        store.addFinding(
            "vulnerable_dependency",
            `${vuln.library}@${vuln.version}`,
            vuln.severity,
            "dependency_scanner",
            `${vuln.type}: ${vuln.message}`
        );
    });
}

module.exports = {
    detectVulnerableDependencies,
    extractLibraryInfo,
    VULNERABLE_PACKAGES
};
