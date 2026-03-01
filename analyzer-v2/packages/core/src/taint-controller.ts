import { Parser } from 'acorn';
import { walk } from 'astray';
import * as fs from 'fs';
import * as path from 'path';
import { AutoRemediator } from './auto-fixer.js';
import { CustomRulesEngine } from './rules-engine.js';

// Advanced 10-Module Node.js SAST Engine Backbone
// Focus: Cross-File Taint Tracking via Acorn + Astray

interface TaintSink {
    type: 'SQL_INJECTION' | 'XSS' | 'COMMAND_INJECTION' | 'PATH_TRAVERSAL' | 'OPEN_REDIRECT' | 'SSTI' | 'INSECURE_DESERIALIZATION' | 'YAML_DESERIALIZATION' | 'PROCESS_CONTROL' | 'VM_ESCAPE' | 'FORMAT_STRING' | 'SSRF';
    functionName: string;
}

const SINKS: TaintSink[] = [
    // Category 1
    { functionName: 'eval', type: 'XSS' },
    { functionName: 'exec', type: 'COMMAND_INJECTION' },
    { functionName: 'spawn', type: 'COMMAND_INJECTION' },
    { functionName: 'fork', type: 'COMMAND_INJECTION' },
    { functionName: 'query', type: 'SQL_INJECTION' },
    { functionName: 'raw', type: 'SQL_INJECTION' },
    { functionName: 'execute', type: 'SQL_INJECTION' },
    { functionName: 'readFile', type: 'PATH_TRAVERSAL' },
    { functionName: 'writeFile', type: 'PATH_TRAVERSAL' },
    { functionName: 'join', type: 'PATH_TRAVERSAL' },
    { functionName: 'render', type: 'SSTI' }, // Server-Side Template Injection
    { functionName: 'unserialize', type: 'INSECURE_DESERIALIZATION' },
    { functionName: 'load', type: 'YAML_DESERIALIZATION' }, // js-yaml
    { functionName: 'exit', type: 'PROCESS_CONTROL' },
    { functionName: 'runInContext', type: 'VM_ESCAPE' },
    { functionName: 'format', type: 'FORMAT_STRING' },
    // Category 4
    { functionName: 'redirect', type: 'OPEN_REDIRECT' },
    { functionName: 'send', type: 'XSS' },
    // **NEW** SSRF Network Sinks
    { functionName: 'axios', type: 'SSRF' },
    { functionName: 'get', type: 'SSRF' },
    { functionName: 'post', type: 'SSRF' },
    { functionName: 'fetch', type: 'SSRF' },
    { functionName: 'request', type: 'SSRF' },
    // Category 7
    { functionName: 'kill', type: 'PROCESS_CONTROL' },
    { functionName: 'chdir', type: 'PROCESS_CONTROL' }
];

interface TaintNode {
    variableName: string;
    flow: string[]; // Tracking the path across files
    isSanitized: boolean;
}

export class TaintController {
    private taintMap: Map<string, TaintNode> = new Map();
    private currentFile: string = '';
    private currentDir: string = '';

    // localName -> { modulePath, exportName }
    private fileImports: Map<string, { modulePath: string, exportName: string }> = new Map();
    private autoFixer: AutoRemediator = new AutoRemediator();
    private customRules: CustomRulesEngine = new CustomRulesEngine();

    // Store collected issues for consumption by Web App and CLI
    public collectedIssues: any[] = [];

    constructor() { }

    public loadCustomRules(rulesDir: string) {
        this.customRules.loadRulesFromDirectory(rulesDir);
    }

    /**
     * Initializes a taint trace from a known source (e.g., req.query or a function param).
     */
    public markTainted(variableName: string, sourceContext: string, previousFlow?: string[]) {
        this.taintMap.set(variableName, {
            variableName,
            flow: previousFlow ? [...previousFlow, `${this.currentFile}:${sourceContext}`] : [`${this.currentFile}:${sourceContext}`],
            isSanitized: false
        });
    }

    /**
     * CFG Reachability Downshift: Returns visual severity level based on file paths
     */
    private getSeverityLevel(): string {
        const lowerFile = this.currentFile.toLowerCase();
        // Since we pass in paths, we should also check the absolute path if available or rely on the caller
        if (lowerFile.includes('.test.') || lowerFile.includes('.spec.') || lowerFile.includes('test') || lowerFile.includes('mock')) {
            return `[⚠️ REACHABILITY DOWNGRADE: Test File]`;
        }
        return `[🚨 CRITICAL VULNERABILITY]`;
    }

    /**
     * Propagates taint from one variable to another (e.g., const b = a;)
     */
    public propagateTaint(sourceName: string, targetVar: string) {
        if (this.taintMap.has(sourceName)) {
            const parentContext = this.taintMap.get(sourceName)!;
            if (!parentContext.isSanitized) {
                this.taintMap.set(targetVar, {
                    variableName: targetVar,
                    flow: [...parentContext.flow, `${this.currentFile}:Assigned to ${targetVar}`],
                    isSanitized: false
                });
            }
        }
    }

    /**
     * Recursive Taint Tracking: Evaluates if an AST node contains tainted references.
     * Supports Identifiers, Deep Property Access (MemberExpression), TemplateLiterals, and BinaryExpressions.
     */
    public isNodeTainted(node: any): { tainted: boolean, sourceVar?: string } {
        if (!node) return { tainted: false };

        switch (node.type) {
            case 'Identifier':
                // Base Case: Tainted Identifier Match
                if (this.taintMap.has(node.name) && !this.taintMap.get(node.name)!.isSanitized) {
                    return { tainted: true, sourceVar: node.name };
                }
                break;
            case 'MemberExpression':
                // Deep Object Property Tracking: Extract the base object name iteratively
                let iter = node;
                while (iter.type === 'MemberExpression') iter = iter.object;
                if (iter.type === 'Identifier' && this.taintMap.has(iter.name) && !this.taintMap.get(iter.name)!.isSanitized) {
                    return { tainted: true, sourceVar: iter.name };
                }
                // Also check if any property is explicitly tainted
                return this.isNodeTainted(node.object);
            case 'TemplateLiteral':
                for (const expr of node.expressions) {
                    const result = this.isNodeTainted(expr);
                    if (result.tainted) return result;
                }
                break;
            case 'BinaryExpression':
                const left = this.isNodeTainted(node.left);
                if (left.tainted) return left;
                return this.isNodeTainted(node.right);
            case 'CallExpression':
                // If a function returns a tainted source (e.g. wrapper functions), propagate. (Advanced)
                return this.isNodeTainted(node.callee);
        }
        return { tainted: false };
    }

    /**
     * Parse and walk a JS file using Acorn and Astray
     */
    public analyzeFile(filePath: string) {
        const absolutePath = path.resolve(filePath);
        this.currentDir = path.dirname(absolutePath);
        this.currentFile = path.basename(absolutePath);

        let code;
        try {
            code = fs.readFileSync(absolutePath, 'utf-8');
        } catch (e) {
            return; // File not found or unreadable, safely ignore
        }

        this.analyzeSource(code, absolutePath);
    }

    /**
     * Analyze raw source code in memory (Browser / Web App compatibility)
     */
    public analyzeSource(code: string, filePath: string = 'virtual-file.js') {
        const absolutePath = filePath ? (path && path.resolve ? path.resolve(filePath) : filePath) : 'virtual-file.js';
        this.currentDir = path && typeof path.dirname === 'function' ? path.dirname(absolutePath) : '';
        this.currentFile = path && typeof path.basename === 'function' ? path.basename(absolutePath) : absolutePath;

        let ast;
        try {
            ast = Parser.parse(code, { ecmaVersion: 2022, sourceType: 'module', locations: true });
        } catch (e: any) {
            console.error(`[Acorn] Failed to parse ${this.currentFile}: ${e.message}`);
            return;
        }

        // Astray allows powerful, lightweight custom traversal
        walk(ast, this.getVisitor(ast, code));
    }

    private getVisitor(ast: any, sourceCode: string): any {
        const self = this;
        return {
            ImportDeclaration(node: any) {
                const moduleName = node.source.value;
                if (moduleName.startsWith('.')) {
                    node.specifiers.forEach((specifier: any) => {
                        const localName = specifier.local.name;
                        const exportName = specifier.type === 'ImportDefaultSpecifier' ? 'default' : specifier.imported?.name || localName;
                        self.fileImports.set(localName, { modulePath: path.join(self.currentDir, moduleName), exportName });
                    });
                }
            },
            VariableDeclarator(node: any) {
                if (node.id.type === 'Identifier' && node.init) {

                    // NEW: detect basic require
                    if (node.init.type === 'CallExpression' && node.init.callee.name === 'require' && node.init.arguments.length > 0 && node.init.arguments[0].type === 'Literal') {
                        const moduleName = node.init.arguments[0].value;
                        if (moduleName.startsWith('.')) {
                            self.fileImports.set(node.id.name, { modulePath: path.join(self.currentDir, moduleName), exportName: 'default' });
                        }
                    }

                    // Detect Destructuring require: const { doDangerousThing } = require('./moduleB');
                    if (node.id.type === 'ObjectPattern' && node.init.type === 'CallExpression' && node.init.callee.name === 'require') {
                        const moduleName = node.init.arguments[0].value;
                        if (moduleName.startsWith('.')) {
                            node.id.properties.forEach((p: any) => {
                                if (p.key && p.key.type === 'Identifier') {
                                    self.fileImports.set(p.key.name, { modulePath: path.join(self.currentDir, moduleName), exportName: p.key.name });
                                }
                            });
                        }
                    }

                    // Detect Source: req.query / req.body (or their properties)
                    const isReqSource = (n: any): boolean => {
                        if (n.type === 'MemberExpression') {
                            if (n.object.type === 'Identifier' && n.object.name === 'req' && n.property.type === 'Identifier' && (n.property.name === 'query' || n.property.name === 'body')) return true;
                            // Recursive check for things like req.body.order
                            return isReqSource(n.object);
                        }
                        return false;
                    };

                    if (isReqSource(node.init)) {
                        self.markTainted(node.id.name, `Source Assignment (${self.currentFile})`);
                    } else {
                        // Check for Custom Sources (Enterprise Rules)
                        let customSourceHit = false;
                        if (node.init.type === 'MemberExpression' || node.init.type === 'Identifier') {
                            const initStr = node.init.type === 'Identifier' ? node.init.name : (node.init.property?.name || node.init.property?.value);
                            const cRoutes = self.customRules.getSources();
                            for (const cRate of cRoutes) {
                                // Extremely simplified custom source matching: if property/name contains the targetPattern
                                if (initStr && typeof initStr === 'string' && initStr.includes(cRate.sourcePattern)) {
                                    self.markTainted(node.id.name, `[Custom Rule: ${cRate.id}] Source Assignment (${self.currentFile})`);
                                    customSourceHit = true;
                                    break;
                                }
                            }
                        }

                        if (!customSourceHit) {
                            // Detect Taint Propagation (Template literal, member expr, etc)
                            const check = self.isNodeTainted(node.init);
                            if (check.tainted && check.sourceVar) {
                                self.propagateTaint(check.sourceVar, node.id.name);
                            }
                        }
                    }
                }

                // Object pattern require
                if (node.id.type === 'ObjectPattern' && node.init && node.init.type === 'CallExpression' && node.init.callee.name === 'require' && node.init.arguments.length > 0) {
                    const moduleName = node.init.arguments[0].value;
                    if (moduleName && moduleName.startsWith('.')) {
                        node.id.properties.forEach((p: any) => {
                            if (p.key && p.key.type === 'Identifier') {
                                self.fileImports.set(p.key.name, { modulePath: path.join(self.currentDir, moduleName), exportName: p.key.name });
                            }
                        });
                    }
                }
            },

            AssignmentExpression(node: any) {
                if (node.left.type === 'Identifier') {
                    const check = self.isNodeTainted(node.right);
                    if (check.tainted && check.sourceVar) {
                        self.propagateTaint(check.sourceVar, node.left.name);
                    }
                } else if (node.left.type === 'MemberExpression') {
                    // Category 1 & 6: innerHTML / document.write Sinks
                    const prop = node.left.property;
                    if (prop.type === 'Identifier' && (prop.name === 'innerHTML' || prop.name === 'outerHTML')) {
                        const check = self.isNodeTainted(node.right);
                        if (check.tainted && check.sourceVar) {
                            console.log(`\n${self.getSeverityLevel()} DOM-based XSS`);
                            console.log(`Sink Reached: \`.${prop.name}\` assignment at ${self.currentFile}:${node.loc?.start?.line}`);
                            console.log(`Taint Data Flow Path: \n  -> ${self.taintMap.get(check.sourceVar)!.flow.join('\n  -> ')}`);
                        }
                    }
                    // Category 4: Hardcoded Admin Roles
                    if (prop.type === 'Identifier' && prop.name === 'role') {
                        if (node.right.type === 'Literal' && (node.right.value === 'admin' || node.right.value === 'superuser')) {
                            console.log(`\n${self.getSeverityLevel()} Hardcoded Role Assignment (user.role = '${node.right.value}') detected at ${self.currentFile}:${node.loc?.start?.line}. Potential Authentication Bypass.`);
                        }
                    }
                    // Category 6: Global Variable Exposure (window.*)
                    if (node.left.object && node.left.object.type === 'Identifier' && node.left.object.name === 'window') {
                        const check = self.isNodeTainted(node.right);
                        if (check.tainted && check.sourceVar) {
                            const sName = check.sourceVar.toLowerCase();
                            if (['password', 'token', 'secret', 'key', 'auth'].some(k => sName.includes(k))) {
                                console.log(`\n[🚨 DATA LEAK] Sensitive variable '${check.sourceVar}' assigned to global window object at ${self.currentFile}:${node.loc?.start?.line}.`);
                            }
                        }
                    }
                }
            },

            IfStatement(node: any) {
                // 11. "Dead" Auth Branches (Immediate return true on fail)
                if (node.consequent.type === 'BlockStatement') {
                    const blockBody = node.consequent.body;
                    if (blockBody.length > 0) {
                        const lastStmt = blockBody[blockBody.length - 1];
                        if (lastStmt.type === 'ReturnStatement' && lastStmt.argument?.type === 'Literal' && lastStmt.argument.value === true) {
                            // High heuristic: If it's a negative check (!isValid) and returns true
                            if (node.test.type === 'UnaryExpression' && node.test.operator === '!') {
                                console.log(`\n[🚨 LOGIC FLAW] "Dead" Auth Branch detected at ${self.currentFile}:${node.loc?.start?.line}. Returning 'true' immediately after a negated check indicates a potential development backdoor.`);
                            }
                        }
                    }
                }
            },

            CallExpression(node: any) {
                // 1. Sanitize Hook
                if (node.callee.type === 'MemberExpression' && node.callee.property.name === 'sanitize') {
                    if (node.arguments.length > 0 && node.arguments[0].type === 'Identifier') {
                        const varName = node.arguments[0].name;
                        if (self.taintMap.has(varName)) {
                            self.taintMap.get(varName)!.isSanitized = true;
                            // console.log(`[INFO] Un-tainted variable: ${varName} via sanitization.`);
                        }
                    }
                }

                // 2. Exploitability Reachability Hook (Sink Hit)
                const calleeName = node.callee.type === 'Identifier' ? node.callee.name : (node.callee.property?.name || node.callee.name || '');
                const matchedSink = SINKS.find(s => s.functionName === calleeName);
                const customSinkMatch = self.customRules.getSinks().find(s => s.functionName === calleeName);

                if (matchedSink || customSinkMatch) {
                    const sinkNameType = matchedSink ? matchedSink.type : `CUSTOM_RULE: ${customSinkMatch!.id}`;

                    node.arguments.forEach((arg: any) => {
                        const check = self.isNodeTainted(arg);
                        if (check.tainted && check.sourceVar) {
                            const taintInfo = self.taintMap.get(check.sourceVar)!;
                            console.log(`\n${self.getSeverityLevel()} ${sinkNameType}`);
                            console.log(`Sink Reached: \`${calleeName}()\` at ${self.currentFile}:${node.loc?.start?.line}`);
                            if (customSinkMatch) console.log(`Description: ${customSinkMatch.description}`);
                            console.log(`Taint Data Flow Path: \n  -> ${taintInfo.flow.join('\n  -> ')}`);

                            let issueRecord: any = {
                                type: 'security',
                                message: `CRITICAL [${sinkNameType}] Data Flow Reached Sink: \`${calleeName}()\`. Flow: ${taintInfo.flow.join(' -> ')}`,
                                line: node.loc?.start?.line || 1,
                                severity: 'high',
                                isTainted: true
                            };

                            if (matchedSink) {
                                // 🚀 Enterprise Auto-Remediation Hook 🚀
                                let patch = null;
                                if (matchedSink.type === 'COMMAND_INJECTION') {
                                    patch = self.autoFixer.buildCommandInjectionPatch(path.join(self.currentDir, self.currentFile), node.loc?.start?.line, calleeName, arg.name);
                                } else if (matchedSink.type === 'SQL_INJECTION') {
                                    patch = self.autoFixer.buildSqlInjectionPatch(path.join(self.currentDir, self.currentFile), node.loc?.start?.line);
                                    if (!patch && sourceCode) {
                                        // Fallback for browser string-based fixing if code is sent via string without FS support
                                        // We would write an auto-fixer that uses the string content directly.
                                        // For MVP, we skip string based fix here, only use the FS patch.
                                    }
                                }

                                if (patch) {
                                    console.log(`\n[🛠️ AUTO-FIX AVAILABLE] ${patch.description}`);
                                    console.log(`--- DIFF SNIPPET ---\n${patch.diffSnippet}--------------------\n`);
                                    issueRecord.patch = patch;
                                }
                            }

                            self.collectedIssues.push(issueRecord);
                        }
                    });
                }

                // 3. INTER-PROCEDURAL TAINT TRACKING (Deep Semantics)
                // If the target is NOT a known sink, but we are passing tainted data into a function defined locally...
                if (!matchedSink && node.callee.type === 'Identifier') {

                    // --- CROSS FILE TAINT TRACKING (ENTERPRISE GRADE) ---
                    if (self.fileImports.has(node.callee.name)) {
                        const importInfo = self.fileImports.get(node.callee.name)!;
                        let targetPath = importInfo.modulePath;
                        if (!targetPath.endsWith('.js') && !targetPath.endsWith('.ts')) targetPath += '.js';

                        let importedFileArgs: { index: number, srcFlow: string[] }[] = [];

                        node.arguments.forEach((arg: any, argIndex: number) => {
                            const check = self.isNodeTainted(arg);
                            if (check.tainted && check.sourceVar) {
                                const taintInfo = self.taintMap.get(check.sourceVar)!;
                                importedFileArgs.push({ index: argIndex, srcFlow: taintInfo.flow });
                            }
                        });

                        if (importedFileArgs.length > 0 && fs.existsSync(targetPath)) {
                            console.log(`\n[🔍 CROSS-FILE TRACE] Tainted data passed to ${node.callee.name}(), analyzing imported module: ${targetPath}`);
                            // We instantiate a new TaintController to isolate variable scoping (so `const config` in one file doesn't override another)
                            const crossFileTracker = new TaintController();
                            crossFileTracker.analyzeCrossFileCall(targetPath, importInfo.exportName, importedFileArgs);
                            return;
                        }
                    }
                    // --- END CROSS FILE TAINT TRACKING ---

                    node.arguments.forEach((arg: any, argIndex: number) => {
                        const check = self.isNodeTainted(arg);
                        if (check.tainted && check.sourceVar) {
                            // We have tainted data passed into `calleeName`. Look up its FunctionDeclaration in Astoria tree.
                            walk(ast, {
                                FunctionDeclaration(fnNode: any) {
                                    if (fnNode.id && fnNode.id.name === node.callee.name) {
                                        // Found the definition! Taint the parameter at `argIndex`.
                                        const param = fnNode.params[argIndex];
                                        if (param && param.type === 'Identifier') {
                                            const prevTainted = self.taintMap.has(param.name) && !self.taintMap.get(param.name)!.isSanitized;
                                            if (!prevTainted) {
                                                const srcFlow = self.taintMap.has(check.sourceVar!) ? self.taintMap.get(check.sourceVar!)!.flow : [];
                                                self.markTainted(param.name, `Inter-procedural flow via \`${node.callee.name}()\` from '${check.sourceVar}'`, srcFlow);

                                                self.taintMap.get(param.name)!.flow.push(`${self.currentFile}:Function parameter '${param.name}' of ${node.callee.name}()`);

                                                // Deep Semantic Taint Tracking: Walk the function body with the newly tainted parameter context!
                                                if (fnNode.body) {
                                                    walk(fnNode.body, self.getVisitor(ast, sourceCode));
                                                }
                                            }
                                        }
                                    }
                                }
                            });
                        }
                    });
                }

                // 2.5 Sensitive Data in console.log (Taint to Logger)
                if (node.callee.type === 'MemberExpression' && node.callee.object.name === 'console') {
                    node.arguments.forEach((arg: any) => {
                        const check = self.isNodeTainted(arg);
                        if (check.tainted && check.sourceVar) {
                            // Heuristic: Is the source variable suspiciously named?
                            const sName = check.sourceVar.toLowerCase();
                            if (['password', 'token', 'secret', 'key', 'auth'].some(k => sName.includes(k))) {
                                const taintInfo = self.taintMap.get(check.sourceVar)!;
                                console.log(`\n[🚨 DATA LEAK] Sensitive variable '${check.sourceVar}' logged to console at ${self.currentFile}:${node.loc?.start?.line}.`);
                                console.log(`Taint Data Flow Path: \n  -> ${taintInfo.flow.join('\n  -> ')}`);
                            }
                        }
                    });
                }

                // 3. Node.js Memory Safety Checks
                if (node.callee.type === 'MemberExpression' && node.callee.object.name === 'Buffer' && node.callee.property.name === 'allocUnsafe') {
                    console.log(`\n[🚨 MEMORY SAFETY] Buffer.allocUnsafe() detected at ${self.currentFile}:${node.loc?.start?.line}. Potential data exposure/leak.`);
                }

                // 4. Prototype Pollution Guard (Object.assign / JSON.parse)
                if (node.callee.type === 'MemberExpression' && node.callee.object.name === 'Object' && node.callee.property.name === 'assign') {
                    console.log(`\n[🚨 PROTOTYPE POLLUTION] Object.assign() detected at ${self.currentFile}:${node.loc?.start?.line}. Ensure keys are derived securely.`);
                }
                if (node.callee.type === 'MemberExpression' && node.callee.object.name === 'JSON' && node.callee.property.name === 'parse') {
                    console.log(`\n[⚠️ PROTOTYPE LOGIC] JSON.parse() used at ${self.currentFile}:${node.loc?.start?.line}. If this parsed object is merged, it can lead to Prototype Pollution.`);
                }

                // 5. JWT "None" Algorithm Verification Flaw
                if (node.callee.type === 'MemberExpression' && node.callee.property.name === 'verify') {
                    if (node.arguments.length === 3 && node.arguments[2].type === 'ObjectExpression') {
                        const algConfig = node.arguments[2].properties.find((p: any) => p.key.name === 'algorithms');
                        if (algConfig && algConfig.value.type === 'ArrayExpression') {
                            const hasNone = algConfig.value.elements.some((e: any) => e.value === 'none');
                            if (hasNone) {
                                console.log(`\n[🚨 AUTHENTICATION BYPASS] JWT verification allows the 'none' algorithm at ${self.currentFile}:${node.loc?.start?.line}. Critical Risk.`);
                            }
                        }
                    }
                }

                // 6. Sandbox Escape Detection (vm module)
                if (node.callee.type === 'MemberExpression' && node.callee.object.name === 'vm') {
                    console.log(`\n[🚨 SANDBOX ESCAPE] Danger: Found use of 'vm' module (e.g. runInContext) at ${self.currentFile}:${node.loc?.start?.line}.`);
                }

                // 12. Insecure PostMessage Listening
                if (node.callee.type === 'MemberExpression' && node.callee.property.name === 'addEventListener') {
                    if (node.arguments.length > 0 && node.arguments[0].type === 'Literal' && node.arguments[0].value === 'message') {
                        // Very rough heuristic check: Look for 'origin' in the callback body. 
                        // In a real SAST we'd walk the BlockStatement of the ArrowFunctionExpression.
                        const callback = node.arguments[1];
                        let stringifiedBody = '';
                        try {
                            // Fast generic check if '.origin' is used anywhere in the callback
                            stringifiedBody = JSON.stringify(callback);
                        } catch (e) { }

                        if (!stringifiedBody.includes('"name":"origin"')) {
                            console.log(`\n[🚨 DOM SECURITY] Insecure \`postMessage\` listener at ${self.currentFile}:${node.loc?.start?.line}. The event handler does not appear to validate \`event.origin\`.`);
                        }
                    }
                }

                // Category 1: buffer.from without length checks (Unsafe Buffer creation)
                if (node.callee.type === 'MemberExpression' && node.callee.object.name === 'Buffer' && node.callee.property.name === 'from') {
                    if (node.arguments.length === 2 && node.arguments[1].type === 'Literal') {
                        const encoding = node.arguments[1].value;
                        if (encoding === 'hex' || encoding === 'base64') {
                            const check = self.isNodeTainted(node.arguments[0]);
                            if (check.tainted && check.sourceVar) {
                                console.log(`\n[🚨 MEMORY SAFETY] Buffer.from() created from tainted ${encoding} user input at ${self.currentFile}:${node.loc?.start?.line}. Ensure length limits are enforced.`);
                            }
                        }
                    }
                }

                // Category 6: document.write Sink
                if (node.callee.type === 'MemberExpression' && node.callee.object.name === 'document' && node.callee.property.name === 'write') {
                    const check = self.isNodeTainted(node.arguments[0]);
                    if (check.tainted && check.sourceVar) {
                        console.log(`\n${self.getSeverityLevel()} DOM-based XSS via document.write()`);
                        console.log(`Sink Reached at ${self.currentFile}:${node.loc?.start?.line}`);
                    }
                }

                // Category 7: res.send(err.stack) missing error sanitization
                if (node.callee.type === 'MemberExpression' && (node.callee.property.name === 'send' || node.callee.property.name === 'json')) {
                    if (node.arguments.length > 0 && node.arguments[0].type === 'MemberExpression') {
                        const argProp = node.arguments[0].property;
                        if (argProp.type === 'Identifier' && (argProp.name === 'stack' || argProp.name === 'message')) {
                            const argObj = node.arguments[0].object;
                            if (argObj.type === 'Identifier' && (argObj.name === 'err' || argObj.name === 'error' || argObj.name === 'e')) {
                                console.log(`\n[🚨 ERROR LEAK] Unsanitized Error Stack/Message sent directly to HTTP response at ${self.currentFile}:${node.loc?.start?.line}.`);
                            }
                        }
                    }
                }
            },

            ObjectExpression(node: any) {
                // Prototype Pollution Guard (Spread Operator)
                const hasSpread = node.properties.some((prop: any) => prop.type === 'SpreadElement');
                if (hasSpread) {
                    // console.log(`\n[⚠️ PROTOTYPE POLLUTION Warning] Object Spread (...) detected at ${self.currentFile}:${node.loc?.start?.line}.`);
                }

                // Category 1: NoSQL Injection via $where or $regex in MongoDB queries
                node.properties.forEach((prop: any) => {
                    if (prop.key && prop.key.type === 'Identifier' && (prop.key.name === '$where' || prop.key.name === '$regex')) {
                        const check = self.isNodeTainted(prop.value);
                        if (check.tainted && check.sourceVar) {
                            console.log(`\n[🚨 CRITICAL VULNERABILITY] NoSQL Injection`);
                            console.log(`Sink Reached: \`${prop.key.name}\` assignment at ${self.currentFile}:${node.loc?.start?.line}`);
                            console.log(`Taint Data Flow Path: \n  -> ${self.taintMap.get(check.sourceVar)!.flow.join('\n  -> ')}`);
                        }
                    }
                });
            },

            BinaryExpression(node: any) {
                // Business Logic "Magic Value" Detection (Hardcoded auth bypass)
                if (node.operator === '===' || node.operator === '==') {
                    const checkSide = (n: any) => n.type === 'Literal' && typeof n.value === 'string' && (n.value.includes('SECRET') || n.value.includes('DEBUG') || n.value.includes('ADMIN'));
                    if (checkSide(node.left) || checkSide(node.right)) {
                        console.log(`\n[🚨 BUSINESS LOGIC] Hardcoded Magic Value Authentication Bypass detected at ${self.currentFile}:${node.loc?.start?.line}.`);
                    }

                    // Strict Timing Equality Check
                    const checkTimeVar = (n: any) => n.type === 'Identifier' && ['hash', 'password', 'token', 'signature'].includes(n.name.toLowerCase());
                    if (checkTimeVar(node.left) || checkTimeVar(node.right)) {
                        console.log(`\n[⚠️ TIMING ATTACK] Standard equality ('${node.operator}') used for sensitive token/hash comparison at ${self.currentFile}:${node.loc?.start?.line}. Use crypto.timingSafeEqual().`);
                    }
                }
            },

            NewExpression(node: any) {
                if (node.callee.type === 'Identifier' && node.callee.name === 'RegExp') {
                    if (node.arguments.length > 0 && node.arguments[0].type === 'Literal') {
                        const regexStr = node.arguments[0].value;
                        // Sentinel-Prime: Advanced ReDoS / Star Height detection
                        if (/(?:\+[\+\*])|(?:\*[\+\*])|(?:\(\S+\+\)\+)|(?:\(\S+\*\)\*)/.test(regexStr)) {
                            console.log(`\n${self.getSeverityLevel()} "Evil Regex" pattern (Nested Quantifiers / Star Height > 1) detected in new RegExp() construction at ${self.currentFile}:${node.loc?.start?.line}.`);

                            let issueRecord: any = {
                                type: 'security',
                                message: `CRITICAL [ReDoS] Evil Regex Pattern Nested Quantifiers (Star Height > 1): /${regexStr}/`,
                                line: node.loc?.start?.line || 1,
                                severity: 'high'
                            };

                            // 🚀 Enterprise Auto-Remediation Hook 🚀
                            const patch = self.autoFixer.buildReDoSPatch(path.join(self.currentDir, self.currentFile), node.loc?.start?.line, regexStr);
                            if (patch) {
                                console.log(`\n[🛠️ AUTO-FIX AVAILABLE] ${patch.description}`);
                                console.log(`--- DIFF SNIPPET ---\n${patch.diffSnippet}--------------------\n`);
                                issueRecord.patch = patch;
                            }

                            self.collectedIssues.push(issueRecord);
                        }
                    }
                }
                // Category 1: Function Constructor Sink
                if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
                    node.arguments.forEach((arg: any) => {
                        const check = self.isNodeTainted(arg);
                        if (check.tainted && check.sourceVar) {
                            console.log(`\n${self.getSeverityLevel()} XSS / Code Execution via \`new Function()\``);
                            console.log(`Sink Reached at ${self.currentFile}:${node.loc?.start?.line}`);
                            console.log(`Taint Data Flow Path: \n  -> ${self.taintMap.get(check.sourceVar)!.flow.join('\n  -> ')}`);
                        }
                    });
                }
            }
        };
    }

    public dumpTaintState() {
        return Array.from(this.taintMap.entries());
    }

    /**
     * Entrypoint for evaluating a Cross-File Call with Tainted Parameters
     */
    public analyzeCrossFileCall(targetFile: string, exportName: string, taintedArgs: { index: number, srcFlow: string[] }[]) {
        const absolutePath = path.resolve(targetFile);
        this.currentDir = path.dirname(absolutePath);
        this.currentFile = path.basename(absolutePath);

        let code;
        try {
            code = fs.readFileSync(absolutePath, 'utf-8');
        } catch (e) { return; }

        let ast;
        try {
            ast = Parser.parse(code, { ecmaVersion: 2022, sourceType: 'module', locations: true });
        } catch (e: any) { return; }

        const self = this;
        let functionBodyPassed = false;

        // 1. First, find all imports in the target file to continue tracing deeper dependencies
        walk(ast, {
            ImportDeclaration(node: any) {
                const moduleName = node.source.value;
                if (moduleName.startsWith('.')) {
                    node.specifiers.forEach((specifier: any) => {
                        const localName = specifier.local.name;
                        const eName = specifier.type === 'ImportDefaultSpecifier' ? 'default' : specifier.imported?.name || localName;
                        self.fileImports.set(localName, { modulePath: path.join(self.currentDir, moduleName), exportName: eName });
                    });
                }
            },
            VariableDeclarator(node: any) {
                // requires
                if (node.id.type === 'Identifier' && node.init && node.init.type === 'CallExpression' && node.init.callee.name === 'require' && node.init.arguments.length > 0 && node.init.arguments[0].type === 'Literal') {
                    const moduleName = node.init.arguments[0].value;
                    if (moduleName.startsWith('.')) {
                        self.fileImports.set(node.id.name, { modulePath: path.join(self.currentDir, moduleName), exportName: 'default' });
                    }
                }
                // ObjectPattern requires
                if (node.id.type === 'ObjectPattern' && node.init && node.init.type === 'CallExpression' && node.init.callee.name === 'require') {
                    const moduleName = node.init.arguments[0].value;
                    if (moduleName && moduleName.startsWith('.')) {
                        node.id.properties.forEach((p: any) => {
                            if (p.key && p.key.type === 'Identifier') {
                                self.fileImports.set(p.key.name, { modulePath: path.join(self.currentDir, moduleName), exportName: p.key.name });
                            }
                        });
                    }
                }
            }
        });

        // 2. Find the function definition that was called
        walk(ast, {
            FunctionDeclaration(fnNode: any) {
                // Determine if this function matches the exported name we are looking for
                // Note: For 'default' or direct module.exports assignment, we are simplified here to match the name.
                // A true enterprise analyzer maps module.exports.doSomething = function doSomething()
                if (fnNode.id && (fnNode.id.name === exportName || exportName === 'default')) {
                    functionBodyPassed = true;
                    // Taint its parameters
                    taintedArgs.forEach(arg => {
                        const param = fnNode.params[arg.index];
                        if (param && param.type === 'Identifier') {
                            self.markTainted(param.name, `[Remote Call Context Setup]`, arg.srcFlow);
                            self.taintMap.get(param.name)!.flow.push(`${self.currentFile}:Function parameter '${param.name}' across file boundary`);
                        }
                    });

                    // Walk function body to detect sink hits inside this file!
                    if (fnNode.body) {
                        walk(fnNode.body, self.getVisitor(ast, code));
                    }
                }
            }
        });
    }
}
