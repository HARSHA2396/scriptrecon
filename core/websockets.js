const store = require("./store");
const { log } = require("../utils/logger");

/**
 * Detect WebSocket connections and endpoints
 */
function detectWebSockets(code) {
    
    const patterns = [
        /ws:\/\/[^\s"'`]+/gi,        // Plain WebSocket
        /wss:\/\/[^\s"'`]+/gi,       // Secure WebSocket
        /new\s+WebSocket\s*\(\s*["']([^"']+)["']/gi,
        /\.connect\s*\(\s*["']([^"']+)["']/gi,
        /socket\.io"/gi,
        /\/socket\.io/gi,
    ];
    
    const found = new Set();
    
    patterns.forEach(p => {
        const matches = code.match(p) || [];
        matches.forEach(m => {
            if (m) found.add(m.trim());
        });
    });
    
    if (found.size === 0) return;
    
    log("\n[WebSocket Endpoints]", 'verbose');
    found.forEach(ws => {
        log(` ${ws}`, 'verbose');
        store.websockets.add(ws);
        store.addFinding("websocket", ws, 6, "websocket_detection", "WebSocket endpoint detected");
    });
}

module.exports = detectWebSockets;
