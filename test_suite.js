#!/usr/bin/env node

/**
 * Comprehensive test suite for ScriptRecon
 */

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

const tests = [];
let passed = 0;
let failed = 0;

// Helper to run commands
function runCmd(cmd) {
    try {
        return execSync(cmd, { encoding: "utf-8", stdio: ["pipe", "pipe", "pipe"] });
    } catch (e) {
        return e.stdout || "";
    }
}

// Test helpers
function test(name, fn) {
    tests.push({ name, fn });
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(`Assertion failed: ${message}`);
    }
}

// ============= TESTS =============

test("File analysis", () => {
    const output = runCmd("node bin/scriptrecon.js -f test.js");
    assert(output.includes("Scan Complete"), "Should complete scan");
});

test("Output directory creation", () => {
    runCmd("node bin/scriptrecon.js -f test.js --output-dir test_basic --silent");
    assert(fs.existsSync("test_basic"), "Output directory should exist");
    assert(fs.existsSync("test_basic/full.json"), "Should create full.json");
    assert(fs.existsSync("test_basic/endpoints.txt"), "Should create endpoints.txt");
    assert(fs.existsSync("test_basic/domains.txt"), "Should create domains.txt");
    assert(fs.existsSync("test_basic/secrets.txt"), "Should create secrets.txt");
    assert(fs.existsSync("test_basic/jwt.txt"), "Should create jwt.txt");
});

test("JSON export", () => {
    runCmd("node bin/scriptrecon.js -f test.js --json test_export.json --silent");
    assert(fs.existsSync("test_export.json"), "JSON file should exist");
    const data = JSON.parse(fs.readFileSync("test_export.json", "utf-8"));
    assert(data.endpoints, "Should have endpoints");
    assert(data.domains, "Should have domains");
    assert(data.findings, "Should have findings array");
    assert(Array.isArray(data.findings), "Findings should be array");
});

test("JWT detection", () => {
    const output = runCmd("node bin/scriptrecon.js -f test.js --verbose");
    assert(output.includes("JWT"), "Should detect JWT tokens");
    assert(output.includes("admin"), "Should decode JWT payload");
});

test("Domain detection", () => {
    const data = JSON.parse(
        fs.readFileSync("test_basic/full.json", "utf-8")
    );
    assert(data.domains.length > 0, "Should find domains");
    assert(
        data.domains.some(d => d.includes("site.com")),
        "Should find site.com"
    );
});

test("Endpoint detection", () => {
    const data = JSON.parse(
        fs.readFileSync("test_export.json", "utf-8")
    );
    assert(
        data.summary.total > 0,
        "Should find at least one finding"
    );
});

test("Severity scoring", () => {
    const data = JSON.parse(
        fs.readFileSync("test_export.json", "utf-8")
    );
    const hasFindings = data.findings && data.findings.length > 0;
    assert(hasFindings, "Should have findings");
    
    if (hasFindings) {
        const firstFinding = data.findings[0];
        assert(firstFinding.severity, "Finding should have severity");
        assert(
            firstFinding.severity >= 1 && firstFinding.severity <= 10,
            "Severity should be 1-10"
        );
    }
});

test("Stack detection", () => {
    const data = JSON.parse(
        fs.readFileSync("test_export.json", "utf-8")
    );
    assert(data.stack, "Should detect stack");
});

test("--only-endpoints filter", () => {
    const output = runCmd("node bin/scriptrecon.js -f test.js --only-endpoints");
    // Should contain endpoint info
    assert(output.length > 0, "Should output endpoint data");
});

test("--only-domains filter", () => {
    const output = runCmd("node bin/scriptrecon.js -f test.js --only-domains");
    assert(output.length > 0, "Should output domain data");
});

test("Silent mode", () => {
    const output = runCmd("node bin/scriptrecon.js -f test.js --silent");
    // Silent mode should have minimal logging
    assert(!output.includes("File Type"), "Should be quieter in silent mode");
});

test("Multiple output formats", () => {
    runCmd("node bin/scriptrecon.js -f test.js --json test_multi.json --output-dir test_multi_dir --silent");
    assert(fs.existsSync("test_multi.json"), "JSON export should work");
    assert(fs.existsSync("test_multi_dir"), "Output dir should be created");
});

// ============= RUN TESTS =============

console.log("\n🧪 Running ScriptRecon Test Suite...\n");

tests.forEach((t, i) => {
    try {
        t.fn();
        console.log(`✓ [${i + 1}/${tests.length}] ${t.name}`);
        passed++;
    } catch (e) {
        console.log(`✗ [${i + 1}/${tests.length}] ${t.name}`);
        console.log(`   Error: ${e.message}`);
        failed++;
    }
});

// Cleanup
console.log("\n📁 Cleaning up test files...");
[
    "test_basic",
    "test_multi_dir",
    "wordpress_recon",
    "test_export.json",
    "test_multi.json",
    "out_test.json"
].forEach(file => {
    try {
        if (fs.lstatSync(file).isDirectory()) {
            fs.rmSync(file, { recursive: true });
        } else {
            fs.unlinkSync(file);
        }
    } catch (e) {}
});

// Summary
console.log(`\n${"=".repeat(50)}`);
console.log(`\n📊 Test Results: ${passed} passed, ${failed} failed / ${tests.length} total`);

if (failed === 0) {
    console.log("✓ All tests passed! 🎉\n");
    process.exit(0);
} else {
    console.log(`✗ ${failed} test(s) failed\n`);
    process.exit(1);
}
