const { log } = require("../utils/logger");

/**
 * Classify JavaScript files based on filename and content patterns
 * Returns: "library", "config", "app", "bundle", "vendor"
 */
function classifyFile(filename, code = "") {
    
    filename = filename.toLowerCase();
    
    // Vendor/Library patterns
    if (filename.includes("node_modules") ||
        filename.includes("vendor") ||
        filename.includes("lib") && filename.includes(".min") ||
        /react|jquery|angular|vue|lodash|moment|axios|fetch/.test(filename) ||
        /\.min\.js$/.test(filename) && code.length > 10000
    ) {
        return "vendor";
    }
    
    // Bundle/Minified patterns
    if (/bundle|main|app\.js|index\.js/.test(filename) && 
        /\.min\.js$/.test(filename)) {
        return "bundle";
    }
    
    // Config patterns
    if (/config|settings|env|constants|keys/.test(filename) ||
        code.includes("export default {") && (code.includes("api") || code.includes("url"))) {
        return "config";
    }
    
    // Analysis-heavy content - likely app code
    if (/api|fetch|axios|endpoint|route|handler|controller|service/.test(filename)) {
        return "app";
    }
    
    // If contains fetch/ajax calls or API logic
    if (code && (
        /fetch\s*\(|axios\.|XMLHttpRequest|\.get\(|\.post\(|\.put\(|\.delete\(/i.test(code) ||
        /\/api\/|\/auth\/|\/admin\/|\/user\//.test(code)
    )) {
        return "app";
    }
    
    // Default
    return "unknown";
}

/**
 * Get analysis priority based on file classification
 * Higher score = analyze more deeply
 */
function getAnalysisPriority(classification) {
    const priority = {
        "app": 10,           // High priority
        "config": 9,         // High priority (secrets)
        "bundle": 5,         // Medium (May be minified)
        "library": 2,        // Low priority
        "vendor": 1,         // Very low priority
        "unknown": 5         // Medium priority
    };
    return priority[classification] || 5;
}

/**
 * Determine if file should be analyzed deeply
 */
function shouldAnalyzeDeep(classification) {
    return classification === "app" || classification === "config";
}

module.exports = {
    classifyFile,
    getAnalysisPriority,
    shouldAnalyzeDeep
};
