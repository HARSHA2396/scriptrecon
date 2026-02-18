const store = require("./store");

/**
 * Scoring system for different finding types
 * Returns severity 1-10 (10 = critical)
 */
const scoringRules = {
    
    // Auth-related (8-10: critical)
    "auth_token": { base: 9, keywords: ["admin", "superuser", "root"] },
    "bearer_token": { base: 8 },
    "api_key": { base: 8, keywords: ["aws", "stripe", "firebase"] },
    
    // Secrets (7-9: high)
    "secret": { base: 7, keywords: ["db", "password", "private"] },
    "private_key": { base: 9 },
    "database_url": { base: 8 },
    
    // Endpoints (5-8: medium-high)
    "endpoint": { 
        base: 5, 
        keywords: {
            "/admin": 9,
            "/internal": 8,
            "/api/v": 6,
            "/callback": 7,
            "/webhook": 7,
            "/private": 8,
            "/secret": 8
        }
    },
    
    // Domains/Subdomains (3-7: low-medium)
    "subdomain": { 
        base: 4,
        keywords: {
            "admin": 7,
            "internal": 6,
            "dev": 5,
            "test": 4,
            "prod": 5,
            "api": 6
        }
    },
    
    // Source maps (7-8: high)
    "source_map": { base: 8 },
    
    // GraphQL (6-7: medium-high)
    "graphql": { base: 6 },
    
    // WebSocket (6: medium-high)
    "websocket": { base: 6 },
    
    // JWT (5-8: medium-high)
    "jwt": { base: 6 },
};

/**
 * Calculate severity score for a finding
 */
function calculateSeverity(type, value) {
    
    value = value.toLowerCase();
    const rule = scoringRules[type];
    
    if (!rule) return 5; // Default medium priority
    
    let score = rule.base;
    
    // Apply keyword multipliers
    if (rule.keywords) {
        if (typeof rule.keywords === "object" && !Array.isArray(rule.keywords)) {
            // Keyword -> score mapping
            for (const keyword in rule.keywords) {
                if (value.includes(keyword.toLowerCase())) {
                    score = rule.keywords[keyword];
                    break;
                }
            }
        } else if (Array.isArray(rule.keywords)) {
            // Keyword array (flat scoring boost)
            rule.keywords.forEach(kw => {
                if (value.includes(kw.toLowerCase())) {
                    score = Math.min(10, score + 2);
                }
            });
        }
    }
    
    return Math.min(10, Math.max(1, score));
}

/**
 * Get severity label
 */
function getSeverityLabel(score) {
    if (score >= 9) return "CRITICAL";
    if (score >= 7) return "HIGH";
    if (score >= 5) return "MEDIUM";
    if (score >= 3) return "LOW";
    return "INFO";
}

/**
 * Get severity color for console output
 */
function getSeverityColor(score) {
    if (score >= 9) return "\x1b[31m"; // Red
    if (score >= 7) return "\x1b[33m"; // Yellow
    if (score >= 5) return "\x1b[36m"; // Cyan
    if (score >= 3) return "\x1b[90m"; // Gray
    return "";
}

const reset = "\x1b[0m";

/**
 * Format finding with severity
 */
function formatFinding(finding) {
    const severity = finding.severity || 5;
    const label = getSeverityLabel(severity);
    const color = getSeverityColor(severity);
    return `${color}[${label}] ${finding.type}: ${finding.value}${reset}`;
}

/**
 * Score all findings in store
 */
function scoreAllFindings() {
    store.findings.forEach(finding => {
        if (!finding.severity || finding.severity === 0) {
            finding.severity = calculateSeverity(finding.type, finding.value);
        }
    });
}

/**
 * Get findings summary
 */
function getFindinsSummary() {
    scoreAllFindings();
    
    const critical = store.findings.filter(f => f.severity >= 9).length;
    const high = store.findings.filter(f => f.severity >= 7 && f.severity < 9).length;
    const medium = store.findings.filter(f => f.severity >= 5 && f.severity < 7).length;
    const low = store.findings.filter(f => f.severity < 5).length;
    
    return {
        total: store.findings.length,
        critical,
        high,
        medium,
        low
    };
}

module.exports = {
    calculateSeverity,
    getSeverityLabel,
    getSeverityColor,
    formatFinding,
    scoreAllFindings,
    getFindinsSummary,
    scoringRules
};
