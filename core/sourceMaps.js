const axios = require("axios");
const store = require("./store");
const { log } = require("../utils/logger");

/**
 * Detect and attempt to fetch source maps
 * Source maps (.map files) often expose source code and internal APIs
 */
async function findSourceMaps(sourceUrl, code) {
    
    if (!sourceUrl || !sourceUrl.includes("http")) return;
    
    // Extract potential source map URLs from code
    const patterns = [
        /\/\/# sourceMappingURL=(.+?)$/gm,  // Inline source map reference
        /\/\*# sourceMappingURL=(.+?)\*\//gm,
    ];
    
    const found = new Set();
    
    patterns.forEach(r => {
        const matches = code.match(r) || [];
        matches.forEach(match => {
            const mapFile = match.split("=")[1]?.trim();
            if (mapFile) found.add(mapFile);
        });
    });
    
    // Common source map locations
    const commonPaths = [
        sourceUrl.replace(/\.js$/, ".js.map"),
        sourceUrl.replace(/\.js$/, ".map"),
        sourceUrl + ".map",
    ];
    
    commonPaths.forEach(p => found.add(p));
    
    if (found.size === 0) return;
    
    log("\n[Source Maps Detection]");
    
    for (const mapUrl of found) {
        // Resolve relative URLs
        let fullUrl = mapUrl;
        
        if (mapUrl.startsWith(".")) {
            const base = sourceUrl.substring(0, sourceUrl.lastIndexOf("/"));
            fullUrl = base + "/" + mapUrl;
        } else if (!mapUrl.startsWith("http")) {
            const base = sourceUrl.substring(0, sourceUrl.lastIndexOf("/"));
            fullUrl = base + "/" + mapUrl;
        }
        
        try {
            const response = await axios.get(fullUrl, { timeout: 5000 });
            
            if (response.status === 200) {
                log(" ✓ Found:", fullUrl);
                store.sourceMaps.add(fullUrl);
                store.addFinding("source_map", fullUrl, 8, sourceUrl, "Exposed source map");
                
                // Extract sources from map
                const mapData = response.data;
                if (mapData.sources) {
                    log("   Sources in map:");
                    mapData.sources.forEach(s => {
                        log("     -", s);
                        store.addFinding("source_in_map", s, 7, fullUrl, "Source referenced in map");
                    });
                }
            }
        } catch (e) {
            // Source map not accessible (expected)
        }
    }
}

module.exports = findSourceMaps;
