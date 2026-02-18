const fs = require("fs");
const esprima = require("esprima");
const extractor = require("./extractor");
const { log } = require("../utils/logger");

async function analyze({ file, code, source }) {

    let jsCode;

    if (file) {
        jsCode = fs.readFileSync(file, "utf-8");
        source = file;
    } else {
        jsCode = code;
    }

    log("\n[+] Analyzing: " + source, 'verbose');

    let ast = null;

    try {
        ast = esprima.parseScript(jsCode, { tolerant: true });
    } catch {
        // Don't spam concise terminals with parse errors; make them visible in verbose mode
        log("[!] AST parsing failed", 'verbose');
    }

    // Await async extraction
    await extractor(jsCode, ast, source);
}

module.exports = analyze;
