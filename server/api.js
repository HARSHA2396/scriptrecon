/**
 * ScriptRecon API Server
 * REST API interface for enterprise integration
 */

const express = require("express");
const cors = require("cors");
const analyze = require("../core/parser");
const store = require("../core/store");
const fetcher = require("../utils/fetcher");
const crawler = require("../crawler/crawler");
const { scoreAllFindings, getFindinsSummary } = require("../core/scoring");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json({ limit: "50mb" }));
app.use(cors());

// Middleware: Logging
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

/**
 * Health check endpoint
 */
app.get("/health", (req, res) => {
    res.json({ status: "ok", version: "1.0.0", timestamp: new Date().toISOString() });
});

/**
 * Analyze local code
 */
app.post("/analyze/code", async (req, res) => {
    try {
        const { code, name = "unknown" } = req.body;
        
        if (!code) {
            return res.status(400).json({ error: "Missing 'code' field" });
        }
        
        store.clear();
        await analyze({ code, source: name });
        
        const result = {
            success: true,
            analysis: {
                stack: store.stackDetected,
                technologies: [...store.technologies],
                summary: getFindinsSummary(),
                findings: store.findings,
                endpoints: [...store.endpoints],
                domains: [...store.domains],
                secrets: [...store.secrets],
                jwt: store.jwt,
                sourceMaps: [...store.sourceMaps],
                websockets: [...store.websockets],
                cloudBuckets: [...store.cloudBuckets],
                timestamp: new Date().toISOString()
            }
        };
        
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

/**
 * Analyze URL
 */
app.post("/analyze/url", async (req, res) => {
    try {
        const { url, crawl = false } = req.body;
        
        if (!url) {
            return res.status(400).json({ error: "Missing 'url' field" });
        }
        
        store.clear();
        
        if (crawl) {
            console.log(`[API] Crawling: ${url}`);
            const jsUrls = await crawler(url);
            
            const results = {
                jsFilesFound: jsUrls.length,
                analyses: []
            };
            
            for (const jsUrl of jsUrls.slice(0, 50)) { // Limit to 50 for API
                try {
                    const code = await fetcher(jsUrl);
                    await analyze({ code, source: jsUrl });
                    
                    results.analyses.push({
                        url: jsUrl,
                        success: true
                    });
                } catch (e) {
                    results.analyses.push({
                        url: jsUrl,
                        success: false,
                        error: e.message
                    });
                }
            }
            
            scoreAllFindings();
            
            return res.json({
                success: true,
                crawlAnalysis: results,
                analysis: {
                    stack: store.stackDetected,
                    technologies: [...store.technologies],
                    summary: getFindinsSummary(),
                    findings: store.findings.slice(0, 1000), // Limit to 1000
                    endpoints: [...store.endpoints],
                    domains: [...store.domains],
                    timestamp: new Date().toISOString()
                }
            });
        } else {
            console.log(`[API] Analyzing URL: ${url}`);
            const code = await fetcher(url);
            await analyze({ code, source: url });
            
            scoreAllFindings();
            
            return res.json({
                success: true,
                analysis: {
                    stack: store.stackDetected,
                    technologies: [...store.technologies],
                    summary: getFindinsSummary(),
                    findings: store.findings,
                    endpoints: [...store.endpoints],
                    domains: [...store.domains],
                    timestamp: new Date().toISOString()
                }
            });
        }
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

/**
 * Batch analyze multiple URLs
 */
app.post("/analyze/batch", async (req, res) => {
    try {
        const { urls } = req.body;
        
        if (!Array.isArray(urls)) {
            return res.status(400).json({ error: "URLs must be an array" });
        }
        
        if (urls.length > 100) {
            return res.status(400).json({ error: "Max 100 URLs per batch" });
        }
        
        const results = [];
        
        for (const url of urls) {
            try {
                store.clear();
                const code = await fetcher(url);
                await analyze({ code, source: url });
                scoreAllFindings();
                
                results.push({
                    url,
                    success: true,
                    summary: getFindinsSummary(),
                    findings: store.findings.slice(0, 100)
                });
            } catch (e) {
                results.push({
                    url,
                    success: false,
                    error: e.message
                });
            }
        }
        
        res.json({ success: true, analysis: results });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

/**
 * Filter findings by severity
 */
app.post("/findings/by-severity", (req, res) => {
    try {
        const { minSeverity = 7 } = req.body;
        
        const filtered = store.findings.filter(f => f.severity >= minSeverity);
        
        res.json({
            success: true,
            minSeverity,
            count: filtered.length,
            findings: filtered
        });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

/**
 * Get current store state
 */
app.get("/store", (req, res) => {
    res.json({
        stack: store.stackDetected,
        technologies: [...store.technologies],
        summary: getFindinsSummary(),
        endpoints: [...store.endpoints],
        domains: [...store.domains],
        secrets: [...store.secrets],
        jwt: store.jwt,
        sourceMaps: [...store.sourceMaps],
        websockets: [...store.websockets],
        cloudBuckets: [...store.cloudBuckets],
        findingsCount: store.findings.length
    });
});

/**
 * Clear store
 */
app.post("/store/clear", (req, res) => {
    store.clear();
    res.json({ success: true, message: "Store cleared" });
});

/**
 * Error handler
 */
app.use((err, req, res, next) => {
    console.error("[Error]", err.message);
    res.status(500).json({ error: err.message });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: "Endpoint not found" });
});

module.exports = app;
