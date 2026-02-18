#!/usr/bin/env node

const { Command } = require("commander");
const analyze = require("../core/parser");
const fetcher = require("../utils/fetcher");
const crawler = require("../crawler/crawler");
const store = require("../core/store");
const fs = require("fs");
const { setMode, log } = require("../utils/logger");
const { exportBurp, exportFFuf, exportNuclei, exportSummary, exportHighValue, exportMarkdown, exportHTML } = require("../output/exporters");


const program = new Command();

program
  .name("scriptrecon")
  .description("🔍 JavaScript Attack-Surface Reconnaissance Engine")
  .version("1.0.0");

program
  .option("-f, --file <path>", "Analyze local JS file")
  .option("-u, --url <url>", "Analyze JS from URL")
  .option("--crawl", "Crawl target for all JS files")
  .option("--json <file>", "Save results to JSON")
  .option("--formats <list>", "Comma-separated formats to generate: json,md,html,pdf")
  .option("--md", "Generate Markdown report (reports/report.md)")
  .option("--html", "Generate HTML report (reports/report.html)")
  .option("--pdf", "Generate PDF report (reports/report.pdf) — requires puppeteer")
  .option("--report-level <level>", "Set report level: concise|verbose|silent")
  .option("--burp <file>", "Export in Burp Suite format")
  .option("--ffuf <file>", "Export endpoints for ffuf")
  .option("--nuclei <file>", "Export Nuclei templates")
  .option("--output-dir <dir>", "Save recon files to directory")
  .option("--only-endpoints", "Show only endpoints")
  .option("--only-domains", "Show only domains")
  .option("--only-high-value", "Show only critical + high findings")
  .option("--silent", "Silent mode")
  .option("--verbose", "Verbose output mode")
  .option("--high-value", "Output high-value findings file");

program.parse(process.argv);
const opts = program.opts();

// Logger mode: explicit flag takes precedence, then silent/verbose, then default concise
if (opts.reportLevel) {
  const lvl = (opts.reportLevel || '').toLowerCase();
  if (['silent','verbose','concise'].includes(lvl)) setMode(lvl);
  else setMode('concise');
} else if (opts.silent) setMode('silent');
else if (opts.verbose) setMode('verbose');
else setMode('concise');

(async () => {

  // FILE ANALYSIS
  if (opts.file) {
    log(`[✓] File mode: ${opts.file}`, 'verbose');
    await analyze({ file: opts.file });
  }

  // URL ANALYSIS (with optional crawl)
  if (opts.url) {
    if (opts.crawl) {
      log(`[✓] Crawl mode: ${opts.url}`, 'verbose');
      
      // Extract base domain
      try {
        const url = new URL(opts.url);
        const baseUrl = url.origin;
        log(`[+] Base URL: ${baseUrl}`, 'verbose');
        
        // Crawl for JS files
        const jsUrls = await crawler(opts.url);
        log(`[+] Found ${jsUrls.length} JS files\n`, 'verbose');
        
        // Analyze each JS file
        for (const jsUrl of jsUrls) {
          log(`[→] Analyzing: ${jsUrl}`, 'verbose');
          try {
            const code = await fetcher(jsUrl);
            await analyze({ code, source: jsUrl });
          } catch (e) {
            log(`[!] Failed to fetch: ${jsUrl}`, 'always');
          }
        }
      } catch (e) {
        log("[!] Invalid URL: " + opts.url, 'always');
      }
    } else {
      log(`[✓] URL analysis mode: ${opts.url}`, 'verbose');
      try {
        const code = await fetcher(opts.url);
        await analyze({ code, source: opts.url });
      } catch (e) {
        log(`[!] Failed to fetch: ${opts.url}`, 'always');
      }
    }
  }

  // FILTERS & DISPLAY
  if (opts.onlyEndpoints) {
    log("\n[Endpoints]", 'summary');
    [...store.endpoints].sort().forEach(e => log(e, 'summary'));
  }

  if (opts.onlyDomains) {
    log("\n[Domains]", 'summary');
    [...store.domains].sort().forEach(d => log(d, 'summary'));
  }

  if (opts.onlyHighValue) {
    log("\n[Critical & High Severity Findings]", 'summary');
    store.findings
      .filter(f => f.severity >= 7)
      .sort((a, b) => b.severity - a.severity)
      .forEach(f => {
        log(`[${f.severity}/10] ${f.type}: ${f.value}`, 'summary');
      });
  }

  // JSON EXPORT
  if (opts.json) {
    const data = {
        stack: store.stackDetected,
        technologies: [...store.technologies],
        endpoints: [...store.endpoints],
        domains: [...store.domains],
        secrets: [...store.secrets],
        jwt: store.jwt,
        source_maps: [...store.sourceMaps],
        websockets: [...store.websockets],
        cloud_buckets: [...store.cloudBuckets],
        findings: store.findings,
        summary: {
          total: store.findings.length,
          critical: store.findings.filter(f => f.severity >= 9).length,
          high: store.findings.filter(f => f.severity >= 7).length,
          medium: store.findings.filter(f => f.severity >= 5).length
        }
    };
    
    fs.writeFileSync(opts.json, JSON.stringify(data, null, 2));
    log(`\n[✓] JSON saved: ${opts.json}`, 'summary');
  }

  // FORMAT EXPORTS
  if (opts.burp) {
    exportBurp(opts.burp);
  }

  if (opts.ffuf) {
    exportFFuf(opts.ffuf);
  }

  if (opts.nuclei) {
    exportNuclei(opts.nuclei);
  }

  // Determine requested formats
  const requestedFormats = new Set();
  if (opts.formats) {
    opts.formats.split(',').map(s=>s.trim().toLowerCase()).forEach(f => { if (f) requestedFormats.add(f); });
  }
  if (opts.md) requestedFormats.add('md');
  if (opts.html) requestedFormats.add('html');
  if (opts.pdf) requestedFormats.add('pdf');

  // 🔥 OPERATOR MODE OUTPUT
  if (opts.outputDir) {

    if (!fs.existsSync(opts.outputDir)) {
        fs.mkdirSync(opts.outputDir, { recursive: true });
    }

    // High-value endpoints
    const highValueEndpoints = [...store.endpoints].filter(e => {
      const lower = e.toLowerCase();
      return lower.includes("admin") || lower.includes("internal") || 
             lower.includes("auth") || lower.includes("api");
    });

    fs.writeFileSync(
      opts.outputDir + "/endpoints.txt",
      [...store.endpoints].join("\n")
    );

    if (highValueEndpoints.length > 0) {
      fs.writeFileSync(
        opts.outputDir + "/high_endpoints.txt",
        highValueEndpoints.join("\n")
      );
    }

    fs.writeFileSync(
      opts.outputDir + "/domains.txt",
      [...store.domains].join("\n")
    );

    fs.writeFileSync(
      opts.outputDir + "/secrets.txt",
      [...store.secrets].join("\n")
    );

    fs.writeFileSync(
      opts.outputDir + "/jwt.txt",
      store.jwt.join("\n")
    );

    // Add source maps if found
    if (store.sourceMaps.size > 0) {
      fs.writeFileSync(
        opts.outputDir + "/sourcemaps.txt",
        [...store.sourceMaps].join("\n")
      );
    }

    // Add websockets if found
    if (store.websockets.size > 0) {
      fs.writeFileSync(
        opts.outputDir + "/websockets.txt",
        [...store.websockets].join("\n")
      );
    }

    // Add cloud storage if found
    if (store.cloudBuckets.size > 0) {
      fs.writeFileSync(
        opts.outputDir + "/cloud_buckets.txt",
        [...store.cloudBuckets].join("\n")
      );
    }

    // Full JSON
    fs.writeFileSync(
      opts.outputDir + "/full.json",
      JSON.stringify({
        stack: store.stackDetected,
        technologies: [...store.technologies],
        endpoints: [...store.endpoints],
        domains: [...store.domains],
        secrets: [...store.secrets],
        jwt: store.jwt,
        source_maps: [...store.sourceMaps],
        websockets: [...store.websockets],
        cloud_buckets: [...store.cloudBuckets],
        findings: store.findings
      }, null, 2)
    );

    // Create reports directory and generate quick operator reports
    const reportsDir = opts.outputDir + "/reports";
    if (!fs.existsSync(reportsDir)) fs.mkdirSync(reportsDir, { recursive: true });

    // Summary JSON
    exportSummary(opts.outputDir + '/summary.json');

    // Markdown & HTML quick reports (respect requested formats)
    if (requestedFormats.size === 0 || requestedFormats.has('md')) {
      exportMarkdown(reportsDir + '/report.md');
      requestedFormats.delete('md');
    }
    if (requestedFormats.size === 0 || requestedFormats.has('html')) {
      exportHTML(reportsDir + '/report.html');
      requestedFormats.delete('html');
    }

    // PDF generation (if requested) — render the HTML report to PDF using puppeteer
    if (requestedFormats.has('pdf')) {
      try {
        const puppeteer = require('puppeteer');
        (async () => {
          const browser = await puppeteer.launch({ args: ['--no-sandbox', '--disable-setuid-sandbox'] });
          const page = await browser.newPage();
          const htmlPath = 'file://' + require('path').resolve(reportsDir + '/report.html');
          await page.goto(htmlPath, { waitUntil: 'networkidle0' });
          await page.pdf({ path: reportsDir + '/report.pdf', format: 'A4', printBackground: true });
          await browser.close();
          log(`[✓] PDF report: ${reportsDir}/report.pdf`, 'summary');
        })();
      } catch (e) {
        log(`[!] PDF generation skipped: puppeteer not available or failed (${e.message})`, 'always');
      }
      requestedFormats.delete('pdf');
    }

    log(`\n[✓] Recon files saved to: ${opts.outputDir}`, 'summary');
  }

  // High-value report
  if (opts.highValue) {
    exportHighValue(opts.outputDir ? `${opts.outputDir}/high_value_report.txt` : "high_value_report.txt");
  }

  // Final consolidated summary (printed once)
  try {
    const total = store.findings.length;
    const critical = store.findings.filter(f => f.severity >= 9).length;
    const high = store.findings.filter(f => f.severity >= 7 && f.severity < 9).length;
    const medium = store.findings.filter(f => f.severity >= 5 && f.severity < 7).length;
    const low = store.findings.filter(f => f.severity < 5).length;

    log('\n=== Scan Summary ===', 'summary');
    log(`  Total findings: ${total}`, 'summary');
    log(`  Critical: ${critical}`, 'summary');
    log(`  High: ${high}`, 'summary');
    log(`  Medium: ${medium}`, 'summary');
    log(`  Low: ${low}`, 'summary');

    const top = store.findings.slice().sort((a,b)=>b.severity - a.severity).slice(0,10);
    if (top.length > 0) {
      log('\nTop findings:', 'summary');
      top.forEach(f => log(` - ${f.type.toUpperCase()}: ${f.value} (sev:${f.severity})`, 'summary'));
    }

    log('\n=== Scan Complete ===\n', 'summary');
  } catch (e) {
    // ensure final logging doesn't crash CLI
    log('[!] Error while preparing final summary: ' + e.message, 'always');
  }

})();

