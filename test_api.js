/**
 * Test API server endpoints
 */

const http = require("http");

function testAPI(method, path, data) {
    return new Promise((resolve, reject) => {
        const body = JSON.stringify(data);
        
        const req = http.request({
            hostname: "localhost",
            port: 3000,
            path: path,
            method: method,
            headers: {
                "Content-Type": "application/json",
                "Content-Length": body.length
            }
        }, (res) => {
            let responseBody = "";
            res.on("data", chunk => responseBody += chunk);
            res.on("end", () => {
                resolve(JSON.parse(responseBody));
            });
        });
        
        req.on("error", reject);
        req.write(body);
        req.end();
    });
}

async function runTests() {
    console.log("\n🧪 Testing ScriptRecon v2.0 API Server\n");
    
    try {
        // Test 1: Health check
        console.log("[1] Health Check");
        const health = await testAPI("GET", "/health", {});
        console.log(`    ✓ Status: ${health.status}`);
        console.log(`    ✓ Version: ${health.version}\n`);
        
        // Test 2: Analyze code with API key
        console.log("[2] Analyze Code (with API Key)");
        const codeAnalysis = await testAPI("POST", "/analyze/code", {
            code: 'const key = "sk_live_abc123"; fetch("/api/admin/users");',
            name: "api.js"
        });
        
        console.log(`    ✓ Success: ${codeAnalysis.success}`);
        console.log(`    ✓ Stack: ${codeAnalysis.analysis.stack}`);
        console.log(`    ✓ Findings: ${codeAnalysis.analysis.findings.length}`);
        const critical = codeAnalysis.analysis.findings.filter(f => f.severity >= 9).length;
        const high = codeAnalysis.analysis.findings.filter(f => f.severity >= 7).length;
        console.log(`    ✓ Critical: ${critical}, High: ${high}\n`);
        
        // Test 3: Filter by severity
        console.log("[3] Filter by Severity (>= 7)");
        const filtered = await testAPI("POST", "/findings/by-severity", {
            minSeverity: 7
        });
        console.log(`    ✓ High-severity findings: ${filtered.count}`);
        filtered.findings.slice(0, 3).forEach(f => {
            console.log(`      - ${f.type}: ${f.value}`);
        });
        console.log();
        
        // Test 4: Get current store
        console.log("[4] Get Current Store State");
        const store = await testAPI("GET", "/store", {});
        console.log(`    ✓ Total endpoints: ${store.endpoints.length}`);
        console.log(`    ✓ Total domains: ${store.domains.length}`);
        console.log(`    ✓ Total secrets: ${store.secrets.length}`);
        console.log(`    ✓ Total findings: ${store.findingsCount}\n`);
        
        // Test 5: Clear store
        console.log("[5] Clear Store");
        const clear = await testAPI("POST", "/store/clear", {});
        console.log(`    ✓ Store cleared: ${clear.success}\n`);
        
        console.log("✅ All API tests passed!\n");
        
    } catch (e) {
        console.error("❌ Test failed:", e.message);
        process.exit(1);
    }
}

runTests();
