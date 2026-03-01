#!/usr/bin/env node
const { program } = require('commander');
const chalk = require('chalk');
const Table = require('cli-table3');
const { analyzeCode, runAdvancedScan } = require('@js-analyzer/core');
const fs = require('fs');
const path = require('path');

function getAllJsFiles(dirPath, arrayOfFiles = []) {
    const files = fs.readdirSync(dirPath);

    files.forEach((file) => {
        const fullPath = path.join(dirPath, file);
        if (fs.statSync(fullPath).isDirectory()) {
            if (file !== 'node_modules' && file !== '.git' && file !== 'dist') {
                arrayOfFiles = getAllJsFiles(fullPath, arrayOfFiles);
            }
        } else {
            if (file.endsWith('.js') || file.endsWith('.ts') || file.endsWith('.jsx') || file.endsWith('.tsx')) {
                arrayOfFiles.push(fullPath);
            }
        }
    });

    return arrayOfFiles;
}

program
    .version('1.0.0')
    .description('Advanced JS Analyzer CLI')
    .argument('[path]', 'File or directory to analyze (optional if using interactive/url mode)')
    .option('-f, --format <type>', 'Output format (text, json, table)', 'text')
    .option('-o, --output <file>', 'Save report to a file')
    .option('-u, --url <target>', 'Fetch JavaScript file directly from a live URL')
    .option('-i, --interactive', 'Start an interactive text session to paste code directly')
    .option('-a, --advanced', 'Run the V2 Next-Gen Engine (Taint Analysis, SCA, Regex OSINT)')
    .option('-r, --rules <dir>', 'Specify a directory containing custom YAML rules (V2 Engine only)')
    .action(async (targetPath, options) => {
        try {
            let filesToProcess = [];
            let report = {
                totalFiles: 0,
                totalComplexity: 0,
                files: []
            };

            // INTERACTIVE MODE
            if (options.interactive) {
                const inquirer = (await import('inquirer')).default;

                console.log(chalk.bold.yellow('\n=== INTERACTIVE RECON MODE ==='));
                console.log(chalk.gray('Paste your JavaScript payload block below.'));
                console.log(chalk.gray('(Press Enter on an empty line to run the analysis!)\n'));

                let codeBlock = '';
                const promptCode = async () => {
                    const ans = await inquirer.prompt([
                        { type: 'input', name: 'line', message: '> ' }
                    ]);
                    if (ans.line.trim() === '') return;
                    codeBlock += ans.line + '\n';
                    await promptCode();
                };
                await promptCode();

                if (codeBlock.trim() === '') {
                    console.log(chalk.red('No code provided! Terminating.'));
                    return;
                }

                console.log(chalk.cyan(`\nInitializing deep scan for Interactive Payload...\n`));
                try {
                    const result = analyzeCode(codeBlock);
                    report.totalComplexity = result.complexity;
                    report.totalFiles = 1;
                    report.files.push({ file: '<Interactive-Session>', complexity: result.complexity, issues: result.issues, endpoints: Array.from(result.endpoints || []) });
                } catch (e) {
                    report.files.push({ file: '<Interactive-Session>', error: e.message });
                }
            }
            // URL SCANNING MODE
            else if (options.url) {
                console.log(chalk.blue(`\nFetching live script from: ${options.url}...`));
                const axios = require('axios');
                try {
                    const response = await axios.get(options.url, { timeout: 10000 });
                    if (typeof response.data !== 'string') {
                        throw new Error('Response is not a raw string/script. Please provide a direct link to a JS file.');
                    }
                    console.log(chalk.cyan(`\nInitializing deep scan for Online Payload...\n`));
                    const result = analyzeCode(response.data);
                    report.totalComplexity = result.complexity;
                    report.totalFiles = 1;
                    report.files.push({ file: options.url, complexity: result.complexity, issues: result.issues, endpoints: Array.from(result.endpoints || []) });

                } catch (e) {
                    console.error(chalk.red(`Failed to fetch URL: ${e.message}`));
                    return;
                }
            }
            // LOCAL FILE SCANNING
            else if (targetPath) {
                const isDir = fs.statSync(targetPath).isDirectory();
                filesToProcess = isDir ? getAllJsFiles(targetPath) : [targetPath];
                report.totalFiles = filesToProcess.length;

                // V2 ADVANCED ENGINE
                if (options.advanced) {
                    console.log(chalk.blue.bold(`\n🔥 Initializing V2 Advanced Engine (Sentinel-100) on ${targetPath}...\n`));
                    try {
                        const rulesPath = options.rules ? path.resolve(options.rules) : undefined;
                        await runAdvancedScan(targetPath, rulesPath);
                    } catch (e) {
                        console.error(chalk.red('\nFatal Engine Error: '), e);
                    }
                    return; // Early return, the V2 engine handles its own SARIF/Console output for now
                }

                if (options.format !== 'json') {
                    console.log(chalk.blue(`\nInitializing deep scan for ${filesToProcess.length} file(s)...\n`));
                }

                filesToProcess.forEach(file => {
                    try {
                        const code = fs.readFileSync(file, 'utf-8');
                        const result = analyzeCode(code);
                        report.totalComplexity += result.complexity;

                        report.files.push({
                            file,
                            complexity: result.complexity,
                            issues: result.issues,
                            endpoints: Array.from(result.endpoints || [])
                        });
                    } catch (e) {
                        report.files.push({
                            file,
                            error: e.message
                        });
                    }
                });
            } else {
                console.log(chalk.red('Error: You must provide a path, a --url argument, or use --interactive.'));
                program.help();
                return;
            }

            if (options.format === 'json') {
                const jsonOut = JSON.stringify(report, null, 2);
                if (options.output) {
                    fs.writeFileSync(options.output, jsonOut);
                    console.log(chalk.green(`Report saved to ${options.output}`));
                } else {
                    console.log(jsonOut);
                }
                return;
            }

            let totalIssues = 0;

            if (options.format === 'table') {
                const table = new Table({
                    head: [chalk.cyan('File'), chalk.magenta('Complexity'), chalk.bold.green('Endpoints'), chalk.red('Threats & Issues')],
                    colWidths: [40, 15, 30, 45],
                    wordWrap: true
                });

                report.files.forEach(f => {
                    let issuesStr = f.error ? chalk.bgRed.white(f.error) : '';
                    if (f.issues && f.issues.length > 0) {
                        totalIssues += f.issues.length;
                        issuesStr = f.issues.map(i => {
                            let color = chalk.blue;
                            if (i.type === 'security') color = chalk.red.bold;
                            if (i.type === 'auth') color = chalk.magenta.bold;
                            if (i.type === 'endpoint') color = chalk.cyan;
                            if (i.type === 'performance') color = chalk.yellow;

                            return color(`[${i.type.toUpperCase()}] L${i.line}: ${i.message}`);
                        }).join('\n');
                    }
                    if (!f.error && (!f.issues || f.issues.length === 0)) issuesStr = chalk.green('Secure');

                    const epsStr = f.endpoints && f.endpoints.length > 0
                        ? chalk.cyan(f.endpoints.join('\n'))
                        : chalk.gray('None');

                    table.push([f.file, f.complexity !== undefined ? f.complexity : 'NaN', epsStr, issuesStr]);
                });

                console.log(table.toString());
            } else {
                report.files.forEach(f => {
                    console.log(chalk.bold.inverse(` File: ${f.file} `));
                    if (f.error) {
                        console.log(chalk.red(`  Error: ${f.error}\n`));
                        return;
                    }
                    console.log(chalk.cyan(`  Complexity Score: ${f.complexity}`));

                    if (f.endpoints && f.endpoints.length > 0) {
                        console.log(chalk.green.bold('  Endpoints Discovered:'));
                        f.endpoints.forEach(ep => console.log(chalk.green(`    - ${ep}`)));
                    }

                    if (f.issues && f.issues.length > 0) {
                        totalIssues += f.issues.length;
                        console.log(chalk.red.bold('  Threats Found:'));
                        f.issues.forEach(i => {
                            let color = chalk.blue;
                            if (i.type === 'security') color = chalk.red.bold;
                            if (i.type === 'auth') color = chalk.magenta.bold;
                            if (i.type === 'endpoint') color = chalk.cyan;
                            if (i.type === 'performance') color = chalk.yellow;
                            console.log(color(`    - [${i.type.toUpperCase()}] Line ${i.line}: ${i.message}`));
                        });
                    } else {
                        console.log(chalk.green('  No obvious threats found.'));
                    }
                    console.log('');
                });
            }

            console.log(chalk.bold.green('Reconnaissance Complete!'));
            console.log(chalk.white(`Sources scanned: ${report.totalFiles}`));
            console.log(chalk.white(`Total Attack Vectors: ${totalIssues}`));

        } catch (err) {
            console.error(chalk.red('Error during execution: '), err.message);
        }
    });

program.parse(process.argv);
