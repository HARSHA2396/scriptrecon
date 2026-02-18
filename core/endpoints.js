const store = require("./store");
const { log } = require("../utils/logger");
const { calculateSeverity } = require("./scoring");

function endpoints(code){

    const patterns = [
        // Full URLs (http/https)
        /(https?:\/\/[^\s"'`<>{}\\|^[\]]+(?:\/[^\s"'`<>{}\\|^[\]]*)*)/g,
        
        // Relative paths with /api, /admin, etc
        /(\/(?:api|admin|internal|user|auth|callback|webhook|secure|private|graphql|action|endpoint|rest|v\d+)[^\s"'`]*)/gi,
    ];

    const valid = new Set();
    const highValue = new Set();
    const keywords = {
        "admin": 9,
        "internal": 8,
        "secret": 8,
        "private": 8,
        "auth": 7,
        "callback": 7,
        "webhook": 7,
        "user": 5,
        "api": 6,
        "graphql": 7
    };

    patterns.forEach(p => {
        const matches = code.match(p) || [];
        
        matches.forEach(e => {
            if (!e) return;
            
            e = e.trim();
            
            // Filter noise
            if (e.length < 8) return;
            if (e.includes("cloudflare")) return;
            if (e.includes("google-analytics")) return;
            if (e.includes(".png") || e.includes(".jpg") || e.includes(".css")) return;
            if (e.includes("//cdn") || e.includes("//static")) return;
            if (e.includes("data:") || e.includes("blob:")) return;
            
            valid.add(e);
            
            // Check if high-value
            let severity = 5;
            for (const kw in keywords) {
                if (e.toLowerCase().includes(kw)) {
                    severity = keywords[kw];
                    highValue.add(e);
                    break;
                }
            }
            
            store.addFinding("endpoint", e, severity, "endpoint_detection", "Endpoint found");
        });
    });

    if (valid.size === 0) return;

    log("[Endpoints]", 'verbose');
    [...valid].sort().forEach(e => {
        const isHighValue = highValue.has(e);
        const marker = isHighValue ? "⚠️  " : "  ";
        log(`${marker}${e}`, 'verbose');
    });
}

module.exports = endpoints;
