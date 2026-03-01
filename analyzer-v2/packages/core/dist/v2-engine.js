import * as fs from 'fs';
import * as path from 'path';
import { TaintController } from './taint-controller.js';
import { scanDependencies } from './dependency-scanner.js';
import { generateSarif } from './sarif-formatter.js';
import { isHighEntropySecret } from './entropy.js';
import { runRegexPass } from './regex-pass.js';
/**
 * Next-Generation JS SAST Engine V2 Orchestrator
 * Integrates Acorn/Astray Backbone with 10 Advanced Security Modules.
 */
export async function runAdvancedScan(targetDirectory, customRulesDir) {
    console.log(`[V2 Engine] Initializing Next-Generation SAST Scan across: ${targetDirectory}\n`);
    const sarifIssues = [];
    const taintController = new TaintController();
    if (customRulesDir) {
        console.log(`[+] Loading Enterprise Custom YAML Rules from: ${customRulesDir}`);
        taintController.loadCustomRules(customRulesDir);
    }
    // 1. Dependency "Shadow" Scan
    console.log(`[Module 5] Executing NPM Typosquatting & OSV NVD Scan...`);
    const depIssues = await scanDependencies(targetDirectory);
    if (depIssues.length > 0) {
        depIssues.forEach(d => {
            console.log(`  -> [SCA HIGH] Package '${d.pkg}@${d.version}' is vulnerable: ${d.vulnerabilities.join(', ')}`);
        });
    }
    else {
        console.log(`  -> Clean: No critical CVES or typosquatting found in package.json.\n`);
    }
    // Crawl all JS/TS files
    const filesToScan = [];
    const crawl = (dir) => {
        const files = fs.readdirSync(dir);
        for (const file of files) {
            if (file === 'node_modules')
                continue;
            const fullPath = path.join(dir, file);
            if (fs.statSync(fullPath).isDirectory()) {
                crawl(fullPath);
            }
            else if (fullPath.endsWith('.js') || fullPath.endsWith('.ts')) {
                filesToScan.push(fullPath);
            }
        }
    };
    if (fs.statSync(targetDirectory).isDirectory()) {
        crawl(targetDirectory);
    }
    else {
        filesToScan.push(targetDirectory);
    }
    // 2. PASS 1: Regex Fast-Scanning Engine
    console.log(`[PASS 1] Executing Fast Regex Pattern Engine (Cloud SSRF, OSINT, IPs, Subdomains)...`);
    for (const file of filesToScan) {
        const content = fs.readFileSync(file, 'utf-8');
        const regexIssues = runRegexPass(file, content);
        if (regexIssues.length > 0) {
            regexIssues.forEach(issue => {
                const icon = issue.level === 'error' ? '🚨' : '⚠️';
                console.log(`\n[${icon} ${issue.ruleId}] ${issue.message} at ${path.basename(file)}:${issue.line}`);
                sarifIssues.push(issue);
            });
        }
    }
    // 3. PASS 2 & 3: Acorn + Astray Cross-File Taint Tracking & Heuristics
    console.log(`\n[PASS 2] Executing AST Pass & Taint Flow on ${filesToScan.length} files...`);
    for (const file of filesToScan) {
        // Taint Controller handles Sinks, Memory Safety, Prototype Pollution, and Logic Flaws internally
        taintController.analyzeFile(file);
        // Secret Entropy Detection (Line-by-line fallback for strings)
        const lines = fs.readFileSync(file, 'utf-8').split('\n');
        lines.forEach((line, index) => {
            // Regex to extract string literals rudimentarily for entropy check
            const strMatches = line.match(/(["'`])((?:\\\1|(?:(?!\1)).)*)\1/g);
            if (strMatches) {
                strMatches.forEach(match => {
                    const cleanStr = match.substring(1, match.length - 1);
                    if (isHighEntropySecret(cleanStr)) {
                        console.log(`\n[🚨 SECRET ENTROPY] High Entropy String detected at ${path.basename(file)}:${index + 1}. Potential Cloud/API Token.`);
                        sarifIssues.push({
                            ruleId: 'HIGH_ENTROPY_SECRET',
                            level: 'error',
                            message: 'High Entropy String detected',
                            file: file,
                            line: index + 1
                        });
                    }
                });
            }
        });
    }
    // Taint Controller logs to console, but in a real CLI we would collect the Taint Sink matches 
    // into the sarifIssues array as well.
    // 10. SARIF Export Formatting
    console.log(`\n[Module 10] Compiling results to SARIF compatibility format...`);
    const sarifOutput = generateSarif(sarifIssues);
    // Determine output directory (handle single file arguments)
    const outDir = fs.statSync(targetDirectory).isDirectory() ? targetDirectory : path.dirname(targetDirectory);
    fs.writeFileSync(path.join(outDir, 'sast-report.sarif'), sarifOutput);
    console.log(`\n✅ Scan Complete. Output written to: ${path.join(outDir, 'sast-report.sarif')}`);
    return sarifOutput;
}
