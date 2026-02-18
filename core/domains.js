const store = require("./store");
const { log } = require("../utils/logger");
const { calculateSeverity } = require("./scoring");

function extractDomains(code){

    // Enhanced regex to catch subdomains and domains
    const patterns = [
        // Explicit domain patterns
        /(?:https?:\/\/)?([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?/gi,
        // Double-quoted or single-quoted domains
        /["']([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}["']/gi,
        // Standard domain pattern
        /\b([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b/g,
    ];

    const ignore = ["axios","function","var","const","return","script","json","jwt","token","undefined","prototype"];
    const valid = new Set();
    const interesting = new Set();
    
    const highValueKeywords = ["api", "admin", "internal", "dev", "test", "prod", "staging", "secure"];

    patterns.forEach(regex => {
        const matches = code.match(regex) || [];

        matches.forEach(d => {
            if (!d) return;

            d = d.replace(/["']/g, "").toLowerCase().trim();
            
            // ignore JS variables and functions
            if (!d.includes(".")) return;
            if (d.length > 80) return;
            if (d.startsWith("http://") || d.startsWith("https://")) {
                d = d.split("://")[1].split("/")[0];
            }

            // ignore common noise
            if (
                d.includes("object.") ||
                d.includes("window.") ||
                d.includes("classlist.") ||
                d.includes("prototype.") ||
                d.includes("function.")
            ) return;

            // Skip localhost and internal IPs
            if (d.includes("localhost") || d.includes("127.0.0.1")) return;

            // must contain valid TLD
            if (!d.match(/\.(com|edu|org|net|in|io|gov|co|uk|us|de|fr|au|jp|cn|ru|br|mx|it|es|nl|se|ch|at|be|dk|fi|no|nz|sg|hk|tw|kr|th|id|ph|vn|my|pk|bd|in|ae|sa|il|za|eg|ng|ke|tz)/i)) return;

            // Max 3 subdomains
            if ((d.match(/\./g) || []).length > 3) return;

            valid.add(d);
            
            // Check for interesting subdomains
            for (const kw of highValueKeywords) {
                if (d.includes(kw)) {
                    interesting.add(d);
                    break;
                }
            }
            
            const severity = calculateSeverity("subdomain", d);
            store.addFinding("domain", d, severity, "domain_extraction", "Domain found");
        });
    });

    if (valid.size === 0) return;

    // Only print domain section if we have either interesting or non-interesting domains
    const nonInteresting = [...valid].filter(d => !interesting.has(d));
    if (interesting.size === 0 && nonInteresting.length === 0) return;

    log("\n[Domains & Subdomains]", 'verbose');

    // Show interesting subdomains first
    if (interesting.size > 0) {
        log("  High-value:", 'verbose');
        [...interesting].sort().forEach(d => {
            log(`    ⚠️ ${d}`, 'verbose');
            store.domains.add(d);
        });
    }

    if (nonInteresting.length > 0) {
        log("  All domains:", 'verbose');
        nonInteresting.sort().forEach(d => {
            log(`   ${d}`, 'verbose');
            store.domains.add(d);
        });
    }
}

module.exports = extractDomains;
