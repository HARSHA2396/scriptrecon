# ScriptRecon

ScriptRecon is an advanced, enterprise-grade reconnaissance and static application security testing (SAST) tool designed for analyzing JavaScript files to uncover hidden attack surfaces in web applications. Built for security researchers, penetration testers, and red team operators.

This repository contains the completely revamped **Analyzer V2**, featuring a powerful new core engine, a sophisticated CLI, and a modern Web Application.

## 🚀 Features

### Core Analysis Engine
- **Deep Taint Tracking**: Cross-procedural data flow tracking to detect SQLi, RCE, XSS, and SSRF.
- **Advanced Contextual Logic**: Includes prototype pollution detection, dependency CVE scanning, and cryptographic weakness scanning.
- **Entropy Analysis**: AI-powered false positive filtering and Shannon entropy calculation to discover high-value secrets.
- **AI Auto-Remediation**: Generates precise code fixes for discovered vulnerabilities.
- **SARIF Support**: Output reports in standard SARIF format for CI/CD integrations.
- **Exploit Generator**: Automatically crafts proof-of-concept payloads for validated vulnerabilities.

### Interactive Web Application
- **Modern UI**: Full-fledged dashboard built with React and Vite.
- **Upload & Scan**: Drag and drop JavaScript files to instantly visualize vulnerabilities.
- **Severity Scoring**: Color-coded categorization from Critical to Info.
- **Interactive Reports**: View code snippets, tainted execution flows, and suggested fixes directly in the browser.

### Penetration Testing CLI
- **Rich Terminal Interface**: Colorful, interactive CLI with live progress.
- **Local & Remote Scanning**: Scan local files or fetch payloads from remote URLs.
- **Custom Rule Engine**: Supply YAML-based rules to enforce custom security policies.

## 🛠️ Architecture Overview

ScriptRecon's new architecture is built as a monorepo under the `analyzer-v2/` directory:

- `analyzer-v2/packages/core/`: The underlying analysis engine (AST parsing, taint tracking, rules).
- `analyzer-v2/packages/cli/`: The command-line interface tool.
- `analyzer-v2/packages/web/`: The React-based web dashboard.

## ⚡ Quick Start

### 1. Web Application

Deploying or running the Web App is simple! The web app is located at `analyzer-v2/packages/web/`.

**Run locally:**
```bash
cd analyzer-v2/packages/web
npm install
npm run dev
```
The app will open locally at `http://localhost:5173`.

**Deploying to Vercel / Netlify:**
Select the root directory as `analyzer-v2/packages/web/` when importing this repo in your dashboard, and let the build commands automatically execute.

### 2. CLI Tool

Use the highly advanced CLI right from your terminal.

```bash
cd analyzer-v2
npm install
node run-v2.js --interactive
```

**CLI Commands Overview:**
```bash
# Interactive mode (Recommended)
node run-v2.js --interactive

# Scan a local file
node run-v2.js --scan ./test_payload.js

# Output results to a SARIF report
node run-v2.js --scan ./test_payload.js --format sarif --output report.sarif

# Provide custom YAML security rules
node run-v2.js --scan ./target.js --rules custom.yaml
```

## 🔒 Security Focus

- **No data exfiltration** (local analysis only).
- **Safe JavaScript execution environment**.
- **Privacy-preserving design**.

## 📄 License
MIT License.
