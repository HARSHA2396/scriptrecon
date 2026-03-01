import { parse } from '@babel/parser';
import _traverse, { NodePath } from '@babel/traverse';
import * as t from '@babel/types';
import { TaintController } from './taint-controller.js';

// Babel 7 default export interop
const traverse = typeof _traverse === 'function' ? _traverse : (_traverse as any).default;

export interface Issue {
    type: 'security' | 'performance' | 'quality' | 'auth' | 'endpoint';
    message: string;
    line: number;
}

export interface AnalysisResult {
    complexity: number;
    issues: Issue[];
    endpoints: string[];
}

export function analyzeCode(code: string): AnalysisResult {
    let ast;
    try {
        ast = parse(code, {
            sourceType: 'unambiguous',
            plugins: ['typescript', 'jsx']
        });
    } catch (e: any) {
        throw new Error(`Parse error: ${e.message}`);
    }

    let complexity = 0;
    const issues: Issue[] = [];
    const endpoints = new Set<string>();

    // Advanced Heuristics: SourceMap Leak & Minification 
    if (code.includes('//# sourceMappingURL=')) {
        issues.push({
            type: 'security',
            message: 'Critical Info-Leak: SourceMap URL discovered. Attackers can use this to reconstruct the original unminified source code.',
            line: 1
        });
    }

    // Minification heuristic (Short variable names, lack of whitespace)
    const isMinified = code.split('\n').length < 10 && code.length > 1000;
    if (isMinified) {
        issues.push({
            type: 'quality',
            message: 'Analysis Warning: Code appears heavily minified or obfuscated. Some advanced heuristics might be impaired.',
            line: 1
        });
    }

    const taintedVars = new Set<string>();
    const isTaintedSource = (node: t.Node): boolean => {
        if (t.isMemberExpression(node)) {
            if (t.isIdentifier(node.object) && node.object.name === 'req' && t.isIdentifier(node.property) && (node.property.name === 'query' || node.property.name === 'body')) return true;
            if (t.isIdentifier(node.object) && node.object.name === 'window' && t.isIdentifier(node.property) && node.property.name === 'location') return true;
            if (t.isIdentifier(node.property) && node.property.name === 'location') return true;
        }
        if (t.isCallExpression(node) && t.isMemberExpression(node.callee)) {
            if (t.isIdentifier(node.callee.object) && node.callee.object.name === 'localStorage' && t.isIdentifier(node.callee.property) && node.callee.property.name === 'getItem') return true;
        }
        return false;
    };

    traverse(ast, {
        enter(path: NodePath) {
            // Taint Tracking: Source Assignment
            if (path.isVariableDeclarator() && path.node.init) {
                const initNode = path.node.init;
                if ((t.isMemberExpression(initNode) && isTaintedSource(initNode.object)) || isTaintedSource(initNode)) {
                    if (t.isIdentifier(path.node.id)) taintedVars.add(path.node.id.name);
                }
            }
            if (path.isAssignmentExpression()) {
                const rightNode = path.node.right;
                if ((t.isMemberExpression(rightNode) && isTaintedSource(rightNode.object)) || isTaintedSource(rightNode)) {
                    if (t.isIdentifier(path.node.left)) taintedVars.add(path.node.left.name);
                }
            }

            // Complexity Analysis
            if (
                path.isIfStatement() ||
                path.isForStatement() ||
                path.isForInStatement() ||
                path.isForOfStatement() ||
                path.isWhileStatement() ||
                path.isDoWhileStatement() ||
                path.isSwitchCase() ||
                path.isCatchClause() ||
                path.isConditionalExpression() ||
                path.isLogicalExpression()
            ) {
                complexity++;
            }

            // Security: eval() usage & Taint Sink
            if (path.isCallExpression() && t.isIdentifier(path.node.callee) && path.node.callee.name === 'eval') {
                const args = path.node.arguments;
                let isTainted = false;
                if (args.length > 0 && t.isIdentifier(args[0]) && taintedVars.has(args[0].name)) isTainted = true;
                if (args.length > 0 && t.isTemplateLiteral(args[0])) {
                    args[0].expressions.forEach(expr => { if (t.isIdentifier(expr) && taintedVars.has(expr.name)) isTainted = true; });
                }

                issues.push({
                    type: 'security',
                    message: isTainted ? 'CRITICAL Data Flow: User-controlled data passed directly into eval(). Remote Code Execution!' : 'Critical: Use of eval() is a severe security risk.',
                    line: path.node.loc?.start.line || 0
                });
            }

            // Security: innerHTML assignment (XSS) & Taint Sink
            if (path.isAssignmentExpression() && t.isMemberExpression(path.node.left)) {
                const property = path.node.left.property;
                if (t.isIdentifier(property) && property.name === 'innerHTML') {
                    let isTainted = t.isIdentifier(path.node.right) && taintedVars.has(path.node.right.name);
                    issues.push({
                        type: 'security',
                        message: isTainted ? 'CRITICAL Data Flow: User-controlled data directly assigned to innerHTML (Reflected DOM XSS).' : 'Warning: Assignment to innerHTML can lead to XSS vulnerabilities.',
                        line: path.node.loc?.start.line || 0
                    });
                }
            }

            // Security: child_process.exec() Command Injection
            if (path.isCallExpression() && t.isMemberExpression(path.node.callee)) {
                const callee = path.node.callee;
                if (t.isIdentifier(callee.property) && callee.property.name === 'exec') {
                    const args = path.node.arguments;
                    let isTainted = false;
                    if (args.length > 0) {
                        if (t.isIdentifier(args[0]) && taintedVars.has(args[0].name)) isTainted = true;
                        if (t.isTemplateLiteral(args[0])) {
                            args[0].expressions.forEach(expr => { if (t.isIdentifier(expr) && taintedVars.has(expr.name)) isTainted = true; });
                        }
                    }
                    if (isTainted || (t.isIdentifier(callee.object) && callee.object.name === 'child_process')) {
                        issues.push({
                            type: 'security',
                            message: isTainted ? 'CRITICAL Data Flow: User-controlled data passed to child_process.exec() (Command Injection).' : 'Warning: child_process.exec() can lead to command injection if input is unsanitized.',
                            line: path.node.loc?.start.line || 0
                        });
                    }
                }
            }

            // Endpoint Discovery: Fetch, Axios, XMLHttpRequest
            if (path.isCallExpression()) {
                const callee = path.node.callee;
                let isNetworkCall = false;

                if (t.isIdentifier(callee) && (callee.name === 'fetch' || callee.name === 'axios')) {
                    isNetworkCall = true;
                } else if (t.isMemberExpression(callee) && t.isIdentifier(callee.object) && callee.object.name === 'axios') {
                    isNetworkCall = true;
                }

                if (isNetworkCall) {
                    const args = path.node.arguments;
                    if (args.length > 0 && t.isStringLiteral(args[0])) {
                        endpoints.add((args[0] as t.StringLiteral).value);
                        issues.push({
                            type: 'endpoint',
                            message: `Endpoint/API Discovered: ${(args[0] as t.StringLiteral).value}`,
                            line: path.node.loc?.start.line || 0
                        });
                    }
                }
            }

            // Security & Auth: Hardcoded secrets / tokens / Endpoints
            if (path.isStringLiteral() || path.isTemplateElement()) {
                const val = path.isStringLiteral() ? path.node.value : path.node.value.raw;

                // Match explicit URLs as potential endpoints
                if (/^(http:\/\/|https:\/\/|\/api\/|\/v[1-9]+\/)/i.test(val)) {
                    endpoints.add(val);
                    issues.push({
                        type: 'endpoint',
                        message: `Possible Routing Path or API Discovered: ${val}`,
                        line: path.node.loc?.start.line || 0
                    });
                }

                // Token heuristics (e.g. JWT headers `eyJ`, AWS `AKIA`, GitHub `ghp_`)
                const isJWT = /^eyJ(?:[a-zA-Z0-9_-]{2,})\.eyJ(?:[a-zA-Z0-9_-]{2,})\.[a-zA-Z0-9_-]{10,}$/.test(val);
                const isAWS = /AKIA[0-9A-Z]{16}/.test(val);
                const isGitHub = /ghp_[a-zA-Z0-9]{36}/.test(val);

                if (isJWT || isAWS || isGitHub) {
                    issues.push({
                        type: 'auth',
                        message: `Critical: Hardcoded High-Entropy Secret/Token detected (${isJWT ? 'JWT' : (isAWS ? 'AWS' : 'GitHub')}).`,
                        line: path.node.loc?.start.line || 0
                    });
                } else if (val.length > 20 && /^[a-zA-Z0-9_-]{20,}$/.test(val) && (val.toLowerCase().includes('secret') || val.toLowerCase().includes('token'))) {
                    issues.push({
                        type: 'auth',
                        message: 'Warning: Possible static authentication secret or token detected.',
                        line: path.node.loc?.start.line || 0
                    });
                }
            }

            // Security: Weak Crypto
            if (path.isCallExpression() && t.isIdentifier(path.node.callee)) {
                const name = path.node.callee.name;
                if (name === 'md5' || name === 'sha1') {
                    issues.push({
                        type: 'security',
                        message: `Critical: Weak cryptographic algorithm used (${name}). Use SHA-256 or better.`,
                        line: path.node.loc?.start.line || 0
                    });
                }
            }
            if (path.isCallExpression() && t.isMemberExpression(path.node.callee)) {
                const prop = path.node.callee.property;
                // AES Hardcoded / Short Key check
                if (t.isIdentifier(prop) && prop.name === 'createCipheriv') {
                    const args = path.node.arguments;
                    if (args.length >= 3) {
                        // Key Check
                        if (t.isStringLiteral(args[1]) && args[1].value.length < 32) {
                            issues.push({ type: 'security', message: 'Warning: AES Key length is less than 256 bits (32 bytes).', line: path.node.loc?.start.line || 0 });
                        }
                        // Static IV Check
                        if (t.isStringLiteral(args[2])) {
                            issues.push({ type: 'security', message: 'Critical: Static Initialization Vector (IV) used in block cipher. This defeats semantic security.', line: path.node.loc?.start.line || 0 });
                        }
                    }
                }
                // Crypto Padding Check (RSA)
                if (t.isIdentifier(prop) && (prop.name === 'publicEncrypt' || prop.name === 'privateDecrypt')) {
                    issues.push({ type: 'security', message: 'Warning: Using default RSA padding (PKCS1v1.5). Consider using RSA-OAEP to prevent Bleichenbacher attacks.', line: path.node.loc?.start.line || 0 });
                }
            }

            // Security: Math.random() usage (insecure PRNG)
            if (path.isCallExpression() && t.isMemberExpression(path.node.callee)) {
                const pb = path.node.callee;
                if (t.isIdentifier(pb.object) && pb.object.name === 'Math' && t.isIdentifier(pb.property) && pb.property.name === 'random') {
                    issues.push({
                        type: 'security',
                        message: 'Warning: Math.random() is cryptographically insecure. Consider crypto.getRandomValues().',
                        line: path.node.loc?.start.line || 0
                    });
                }
            }

            // Category 8: Shadow Code (eval(atob/btoa))
            if (path.isCallExpression() && t.isIdentifier(path.node.callee) && path.node.callee.name === 'eval') {
                if (path.node.arguments.length > 0 && t.isCallExpression(path.node.arguments[0])) {
                    const innerCall = path.node.arguments[0];
                    if (t.isIdentifier(innerCall.callee) && innerCall.callee.name === 'atob') {
                        issues.push({
                            type: 'security',
                            message: 'Critical: Obfuscated eval(atob(...)) payload detected. Possible Malware/Shadow Code.',
                            line: path.node.loc?.start.line || 0
                        });
                    }
                }
            }

            // Performance: Synchronous I/O in Node.js
            if (path.isCallExpression() && t.isMemberExpression(path.node.callee)) {
                const property = path.node.callee.property;
                if (t.isIdentifier(property) && property.name.endsWith('Sync')) {
                    issues.push({
                        type: 'performance',
                        message: `Warning: Synchronous function ${property.name}() can block the event loop.`,
                        line: path.node.loc?.start.line || 0
                    });
                }
            }

            // Auth: Weak comparison (e.g., using `==` instead of `===` for passwords, or comparing passwords in JS)
            if (path.isBinaryExpression()) {
                const isWeakEq = path.node.operator === '==';

                const checkIdent = (node: t.Node) => {
                    if (t.isIdentifier(node)) {
                        const name = node.name.toLowerCase();
                        return name.includes('password') || name.includes('token') || name.includes('secret');
                    }
                    return false;
                };

                if (checkIdent(path.node.left) || checkIdent(path.node.right)) {
                    if (isWeakEq) {
                        issues.push({
                            type: 'auth',
                            message: 'Warning: Using weak equality (==) on sensitive authentication data. Use strict equality (===) to prevent type coercion attacks.',
                            line: path.node.loc?.start.line || 0
                        });
                    } else if (path.node.operator === '===' && (t.isStringLiteral(path.node.left) || t.isStringLiteral(path.node.right))) {
                        issues.push({
                            type: 'auth',
                            message: 'Critical: Hardcoded string comparison against sensitive authentication material (possible backdoor/hardcoded creds).',
                            line: path.node.loc?.start.line || 0
                        });
                    }
                }
            }

            // Quality: Deep nesting
            let depth = 0;
            let p: NodePath | null = path;
            while (p) {
                if (p.isBlockStatement() && (p.parentPath?.isIfStatement() || p.parentPath?.isLoop())) {
                    depth++;
                }
                p = p.parentPath;
            }
            if (depth > 4) {
                if (path.isBlockStatement()) {
                    issues.push({
                        type: 'quality',
                        message: `Warning: Deep nesting detected (depth: ${depth}). Consider refactoring.`,
                        line: path.node.loc?.start.line || 0
                    });
                }
            }

            // Logic Flaw: Prototype Pollution (Object.assign, Spread parsing)
            if (path.isCallExpression() && t.isMemberExpression(path.node.callee)) {
                const callee = path.node.callee;
                if (t.isIdentifier(callee.object) && callee.object.name === 'Object' && t.isIdentifier(callee.property) && callee.property.name === 'assign') {
                    issues.push({
                        type: 'security',
                        message: 'Warning: Object.assign() used. Ensure keys are sanitized to prevent Prototype Pollution (__proto__ overrides).',
                        line: path.node.loc?.start.line || 0
                    });
                }
            }

            if (path.isObjectExpression()) {
                const hasSpread = path.node.properties.some(prop => t.isSpreadElement(prop));
                if (hasSpread) {
                    issues.push({
                        type: 'security',
                        message: 'Warning: Object Spread (`...`) used. Ensure merged properties do not allow Prototype Pollution.',
                        line: path.node.loc?.start.line || 0
                    });
                }
            }

            // Logic Flaw: TOCTOU (Time of check to time of use) Race condition
            if (path.isCallExpression() && t.isMemberExpression(path.node.callee)) {
                const property = path.node.callee.property;
                if (t.isIdentifier(property) && (property.name === 'exists' || property.name === 'existsSync' || property.name === 'access' || property.name === 'accessSync')) {
                    issues.push({
                        type: 'security',
                        message: `Warning: fs.${property.name}() detected. Testing for file existence before acting can lead to TOCTOU race conditions. Directly open the file and handle the error instead.`,
                        line: path.node.loc?.start.line || 0
                    });
                }
            }

            // Architecture: CORS Misconfiguration
            if (path.isCallExpression() && t.isMemberExpression(path.node.callee)) {
                const property = path.node.callee.property;
                if (t.isIdentifier(property) && (property.name === 'setHeader' || property.name === 'header')) {
                    const args = path.node.arguments;
                    if (args.length === 2 && t.isStringLiteral(args[0]) && t.isStringLiteral(args[1])) {
                        if (args[0].value.toLowerCase() === 'access-control-allow-origin' && args[1].value === '*') {
                            issues.push({
                                type: 'security',
                                message: 'Critical Architecture Flaw: CORS set to wildcard (*). This allows any domain to access this resource.',
                                line: path.node.loc?.start.line || 0
                            });
                        }
                    }
                }
                // Category 5: TLS self-signed cert trust
                if (t.isIdentifier(property) && property.name === 'request') {
                    if (path.node.arguments.length > 0 && t.isObjectExpression(path.node.arguments[0])) {
                        const opts = path.node.arguments[0].properties;
                        opts.forEach(p => {
                            if (t.isObjectProperty(p) && t.isIdentifier(p.key) && p.key.name === 'rejectUnauthorized' && t.isBooleanLiteral(p.value, { value: false })) {
                                issues.push({ type: 'security', message: 'Critical: rejectUnauthorized: false disables certificate validation (MITM Risk).', line: path.node.loc?.start.line || 0 });
                            }
                        });
                    }
                }
                // Category 6: Insecure Cookie Flags
                if (t.isIdentifier(property) && property.name === 'cookie') {
                    if (path.node.arguments.length === 3 && t.isObjectExpression(path.node.arguments[2])) {
                        let secure = false;
                        let httpOnly = false;
                        let sameSite = false;
                        path.node.arguments[2].properties.forEach(p => {
                            if (t.isObjectProperty(p) && t.isIdentifier(p.key)) {
                                if (p.key.name === 'secure' && t.isBooleanLiteral(p.value, { value: true })) secure = true;
                                if (p.key.name === 'httpOnly' && t.isBooleanLiteral(p.value, { value: true })) httpOnly = true;
                                if (p.key.name.toLowerCase() === 'samesite') sameSite = true;
                            }
                        });
                        if (!secure || !httpOnly || !sameSite) {
                            issues.push({ type: 'security', message: 'Warning: res.cookie() missing one or more secure flags: secure, httpOnly, sameSite.', line: path.node.loc?.start.line || 0 });
                        }
                    } else if (path.node.arguments.length < 3) {
                        issues.push({ type: 'security', message: 'Warning: res.cookie() called without options object (Missing secure, httpOnly, sameSite).', line: path.node.loc?.start.line || 0 });
                    }
                }
            }

            // Architecture: Missing Error Handling (Empty Catch)
            if (path.isCatchClause()) {
                if (path.node.body.body.length === 0) {
                    issues.push({
                        type: 'quality',
                        message: 'Warning: Empty catch block detected ("Silent Fail"). This can mask attacks or underlying application failures.',
                        line: path.node.loc?.start.line || 0
                    });
                }
            }
        }
    });

    // 🔥 Injecting Advanced TaintController & Auto-Remediation into the Browser!
    try {
        const taintScanner = new TaintController();
        taintScanner.analyzeSource(code, 'BrowserPayload.js');
        // Aggregate the Next-Gen Taint Engine collected issues back to the classic issues array for Web App compatibility
        for (const ti of taintScanner.collectedIssues) {
            const patchText = ti.patch ? ` [AUTO-FIX AVAILABLE in CLI]` : '';
            issues.push({
                type: 'security',
                message: `${ti.message}${patchText}`,
                line: ti.line
            });
        }
    } catch (e) {
        console.warn('Taint Engine encountered an error during parsing:', e);
    }

    return { complexity, issues, endpoints: Array.from(endpoints) };
}

// Next-Gen V2 Engine Exports
export { TaintController } from './taint-controller.js';
export { scanDependencies } from './dependency-scanner.js';
export { AiEvaluationResult, submitForAiEvaluation } from './ai-filter.js';
export { generatePoC } from './exploit-generator.js';
export { isHighEntropySecret } from './entropy.js';
export { runAdvancedScan } from './v2-engine.js';
