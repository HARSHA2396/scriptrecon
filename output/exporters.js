const store = require("../core/store");
const fs = require("fs");
const { log } = require("../utils/logger");

/**
 * Export findings in Burp Suite format
 */
function exportBurp(outputPath) {
    const burpData = {
        issues: store.findings.map(f => ({
            type: f.type,
            name: f.value,
            severity: ["info", "low", "medium", "high", "critical"][Math.min(4, Math.floor(f.severity / 2))],
            confidence: "firm",
            location: f.source,
            description: f.context,
            backgroundHtml: `<p>${f.value}</p>`,
            remediationHtml: `<p>Review ${f.type}: ${f.value}</p>`
        }))
    };
    
    fs.writeFileSync(outputPath, JSON.stringify(burpData, null, 2));
    log(`[✓] Burp export: ${outputPath}`, 'summary');
}

/**
 * Export endpoints for ffuf (URL fuzzing)
 */
function exportFFuf(outputPath) {
    const lines = [
        ...store.endpoints,
        ...store.graphqlEndpoints,
        ...store.websockets,
        ...[...store.findings]
            .filter(f => f.type === "endpoint")
            .map(f => f.value)
    ];
    
    const unique = [...new Set(lines)].filter(l => l && l.length > 0);
    fs.writeFileSync(outputPath, unique.join("\n"));
    log(`[✓] ffuf export: ${outputPath} (${unique.length} endpoints)`, 'summary');
}

/**
 * Export for Nuclei template generation
 */
function exportNuclei(outputPath) {
    const templates = [];
    
    // Create endpoint check templates
    store.findings
        .filter(f => f.type === "endpoint" && f.severity >= 5)
        .forEach(f => {
            templates.push({
                id: `scriptrecon-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
                info: {
                    name: `Check: ${f.value}`,
                    severity: ["info", "low", "medium", "high", "critical"][Math.min(4, Math.floor(f.severity / 2))],
                    description: f.context
                },
                requests: [{
                    method: "GET",
                    path: f.value
                }],
                matchers: [{
                    type: "status",
                    status: ["200", "400", "401", "403", "404", "405"]
                }]
            });
        });
    
    fs.writeFileSync(outputPath, JSON.stringify(templates, null, 2));
    log(`[✓] Nuclei export: ${outputPath} (${templates.length} templates)`, 'summary');
}

/**
 * Export finding summary
 */
function exportSummary(outputPath) {
    const summary = {
        timestamp: new Date().toISOString(),
        stack: store.stackDetected,
        technologies: [...store.technologies],
        summary: {
            total_findings: store.findings.length,
            critical: store.findings.filter(f => f.severity >= 9).length,
            high: store.findings.filter(f => f.severity >= 7 && f.severity < 9).length,
            medium: store.findings.filter(f => f.severity >= 5 && f.severity < 7).length,
            low: store.findings.filter(f => f.severity < 5).length
        },
        endpoints: [...store.endpoints],
        domains: [...store.domains],
        source_maps: [...store.sourceMaps],
        websockets: [...store.websockets],
        cloud_buckets: [...store.cloudBuckets],
        findings: store.findings
    };
    
    fs.writeFileSync(outputPath, JSON.stringify(summary, null, 2));
    log(`[✓] Summary export: ${outputPath}`, 'summary');
}

/**
 * Export high-value findings
 */
function exportHighValue(outputPath) {
    const critical = store.findings.filter(f => f.severity >= 9);
    const high = store.findings.filter(f => f.severity >= 7 && f.severity < 9);
    
    let output = "=== CRITICAL FINDINGS ===\n";
    critical.forEach(f => {
        output += `\n${f.type.toUpperCase()}: ${f.value}\n`;
        output += `  Confidence: ${f.severity}/10\n`;
        output += `  Source: ${f.source}\n`;
        output += `  Details: ${f.context}\n`;
    });
    
    output += "\n\n=== HIGH SEVERITY FINDINGS ===\n";
    high.forEach(f => {
        output += `\n${f.type.toUpperCase()}: ${f.value}\n`;
        output += `  Confidence: ${f.severity}/10\n`;
        output += `  Source: ${f.source}\n`;
        output += `  Details: ${f.context}\n`;
    });
    
    fs.writeFileSync(outputPath, output);
    log(`[✓] High-value report: ${outputPath}`, 'summary');
}

/**
 * Export a concise Markdown report for operators
 */
function exportMarkdown(outputPath) {
    const summary = {
        timestamp: new Date().toISOString(),
        stack: store.stackDetected,
        total: store.findings.length,
        critical: store.findings.filter(f => f.severity >= 9).length,
        high: store.findings.filter(f => f.severity >= 7 && f.severity < 9).length
    };

    let md = `# ScriptRecon Report\n\n`;
    md += `**Timestamp**: ${summary.timestamp}  \n`;
    md += `**Stack**: ${summary.stack}  \n`;
    md += `**Total findings**: ${summary.total}  \n`;
    md += `**Critical**: ${summary.critical}  \n`;
    md += `**High**: ${summary.high}  \n\n`;

    md += `## Top Findings\n`;
    const top = store.findings.filter(f => f.severity >= 7).sort((a,b)=>b.severity-a.severity).slice(0,10);
    top.forEach(f => {
        md += `- **${f.type}**: ${f.value} (severity: ${f.severity})  \n`;
    });

    md += `\n## Summary JSON\n`;
    md += '``json\n' + JSON.stringify({ stack: summary.stack, total: summary.total, critical: summary.critical, high: summary.high }, null, 2) + '\n```\n';

    fs.writeFileSync(outputPath, md);
    log(`[✓] Markdown report: ${outputPath}`, 'summary');
}

/**
 * Export a simple HTML report
 */
function exportHTML(outputPath) {
    const title = 'ScriptRecon Report';
    const total = store.findings.length;
    const critical = store.findings.filter(f => f.severity >= 9).length;
    const high = store.findings.filter(f => f.severity >= 7 && f.severity < 9).length;

    const top = store.findings.filter(f => f.severity >= 7).sort((a,b)=>b.severity-a.severity).slice(0,10);

    let html = `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body>`;
    html += `<h1>${title}</h1>`;
    html += `<p><strong>Total findings:</strong> ${total} &nbsp; <strong>Critical:</strong> ${critical} &nbsp; <strong>High:</strong> ${high}</p>`;
    html += `<h2>Top Findings</h2><ul>`;
    top.forEach(f => {
        html += `<li><strong>${f.type}</strong>: ${f.value} (severity: ${f.severity})</li>`;
    });
    html += `</ul>`;
    html += `</body></html>`;

    fs.writeFileSync(outputPath, html);
    log(`[✓] HTML report: ${outputPath}`, 'summary');
}

module.exports = {
    exportBurp,
    exportFFuf,
    exportNuclei,
    exportSummary,
    exportHighValue,
    exportMarkdown,
    exportHTML
};

