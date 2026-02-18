#!/usr/bin/env node

/**
 * ScriptRecon REST API Server
 * Standalone server for enterprise integration
 */

const app = require("./api");

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || "0.0.0.0";

const server = app.listen(PORT, HOST, () => {
    console.log(`\n🚀 ScriptRecon API Server`);
    console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
    console.log(`Status: ✓ Running`);
    console.log(`URL: http://localhost:${PORT}`);
    console.log(`\n📚 API Endpoints:`);
    console.log(`  POST /analyze/code        - Analyze JavaScript code`);
    console.log(`  POST /analyze/url         - Analyze remote URL`);
    console.log(`  POST /analyze/batch       - Batch analyze URLs`);
    console.log(`  POST /findings/by-severity - Filter by severity`);
    console.log(`  GET  /store               - Get current analysis`);
    console.log(`  POST /store/clear         - Clear results`);
    console.log(`  GET  /health              - Health check`);
    console.log(`\n💡 Example:`);
    console.log(`  curl -X POST http://localhost:${PORT}/analyze/code \\`);
    console.log(`    -H "Content-Type: application/json" \\`);
    console.log(`    -d '{"code":"var key='sk_live_xxx';", "name":"app.js"}'`);
    console.log(`\n`);
});

// Graceful shutdown
process.on("SIGTERM", () => {
    console.log("\n[SIGTERM] Shutting down gracefully...");
    server.close(() => {
        console.log("Server closed");
        process.exit(0);
    });
});

process.on("SIGINT", () => {
    console.log("\n[SIGINT] Shutting down gracefully...");
    server.close(() => {
        console.log("Server closed");
        process.exit(0);
    });
});
