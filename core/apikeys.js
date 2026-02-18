const store = require("./store");
const { log } = require("../utils/logger");
const { calculateSeverity } = require("./scoring");

function detectKeys(code){

    const patterns = [
        // AWS
        { pattern: /AKIA[0-9A-Z]{16}/g, type: "AWS Access Key", severity: 9 },
        { pattern: /aws_secret_access_key[^\n"']*["']?([A-Za-z0-9\/+=]+)["']?/gi, type: "AWS Secret Key", severity: 9 },
        
        // Google
        { pattern: /AIza[0-9A-Za-z\-_]{35}/g, type: "Google API Key", severity: 8 },
        { pattern: /ya29\.[0-9A-Za-z\-_]+/g, type: "Google OAuth Token", severity: 8 },
        
        // Stripe
        { pattern: /sk_live_[0-9a-zA-Z]{24}/g, type: "Stripe Live Key", severity: 9 },
        { pattern: /sk_test_[0-9a-zA-Z]{24}/g, type: "Stripe Test Key", severity: 7 },
        { pattern: /pk_live_[0-9a-zA-Z]{24}/g, type: "Stripe Public Live", severity: 6 },
        
        // GitHub
        { pattern: /ghp_[0-9a-zA-Z]{36}/g, type: "GitHub Personal Token", severity: 9 },
        { pattern: /gho_[0-9a-zA-Z]{36}/g, type: "GitHub OAuth", severity: 8 },
        
        // Firebase
        { pattern: /AIza[0-9A-Za-z\-_]{35}/g, type: "Firebase API Key", severity: 7 },
        { pattern: /AIDAI[0-9A-Za-z\-_]{32}/g, type: "Firebase Service Account", severity: 9 },
        
        // Twilio
        { pattern: /AC[0-9a-f]{32}/g, type: "Twilio Account SID", severity: 8 },
        { pattern: /SK[0-9a-f]{32}/g, type: "Twilio Auth Token", severity: 9 },
        
        // Slack
        { pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-z0-9-]*/g, type: "Slack Token", severity: 9 },
        
        // MailChimp
        { pattern: /[0-9a-f]{32}-us[0-9]{1,2}/g, type: "MailChimp API Key", severity: 7 },
        
        // SendGrid
        { pattern: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/g, type: "SendGrid API Key", severity: 8 },
        
        // PagerDuty
        { pattern: /u\+[0-9a-z\-]{20}/g, type: "PagerDuty Token", severity: 7 },
        
        // MongoDB
        { pattern: /mongodb\+srv:\/\/[^\s:]+:[^\s@]+@/g, type: "MongoDB Connection", severity: 9 },
        
        // Shopify
        { pattern: /shppa_[0-9a-f]{32}/g, type: "Shopify Access Token", severity: 9 },
        
        // Generic patterns
        { pattern: /api[_-]?key['":]?\s*[=:]\s*["']?([A-Za-z0-9\-_=+/]{20,})["']?/gi, type: "API Key (generic)", severity: 7 },
        { pattern: /api[_-]?secret['":]?\s*[=:]\s*["']?([A-Za-z0-9\-_=+/]{20,})["']?/gi, type: "API Secret", severity: 8 },
        { pattern: /private[_-]?key['":]?\s*[=:]\s*["']?([A-Za-z0-9\-_=+/]{20,})["']?/gi, type: "Private Key", severity: 9 },
    ];

    const found = new Set();

    patterns.forEach(p => {
        const m = code.match(p.pattern) || [];
        m.forEach(v => {
            if (v && v.length > 8) {
                const key = `${p.type}:${v}`;
                if (!found.has(key)) {
                    found.add(key);
                    store.addFinding("api_key", v, p.severity, "api_key_detection", p.type);
                }
            }
        });
    });

    if(found.size === 0) return;

    log("\n[API Keys/Credentials]", 'verbose');
    found.forEach(k => {
        const splitIdx = k.indexOf(":");
        const type = splitIdx !== -1 ? k.substring(0, splitIdx) : 'key';
        const value = splitIdx !== -1 ? k.substring(splitIdx+1) : k;
        const display = value.substring(0, 32) + (value.length > 32 ? "..." : "");
        log(` ${display} (${type})`, 'verbose');
    });
}

module.exports = detectKeys;
