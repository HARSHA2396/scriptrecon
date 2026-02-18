/**
 * Concurrent Analysis Engine
 * Parallel file processing using worker pool
 */

const pLimit = require("p-limit");
const fetcher = require("../utils/fetcher");
const analyze = require("./parser");
const store = require("./store");

/**
 * Analyze multiple URLs concurrently
 * @param {string[]} urls - Array of URLs to analyze
 * @param {number} concurrency - Number of parallel workers (default 4)
 * @returns {Promise<Array>} Analysis results for each URL
 */
async function analyzeUrlsConcurrent(urls, concurrency = 4) {
    const limit = pLimit(concurrency);
    
    const analysisPromises = urls.map(url =>
        limit(async () => {
            try {
                const code = await fetcher(url);
                const beforeFindings = store.findings.length;
                
                await analyze({ code, source: url });
                
                const afterFindings = store.findings.length;
                const newFindings = afterFindings - beforeFindings;
                
                return {
                    url,
                    success: true,
                    findingsAdded: newFindings,
                    totalFindings: afterFindings
                };
            } catch (error) {
                return {
                    url,
                    success: false,
                    error: error.message
                };
            }
        })
    );
    
    return Promise.all(analysisPromises);
}

/**
 * Analyze code snippets concurrently (for batch processing)
 * @param {Array} codeSnippets - Array of { code, name } objects
 * @param {number} concurrency - Number of parallel workers
 * @returns {Promise<Array>} Analysis results
 */
async function analyzeCodesConcurrent(codeSnippets, concurrency = 4) {
    const limit = pLimit(concurrency);
    
    const analysisPromises = codeSnippets.map(snippet =>
        limit(async () => {
            try {
                await analyze({ code: snippet.code, source: snippet.name });
                
                return {
                    name: snippet.name,
                    success: true,
                    findingsCount: store.findings.length
                };
            } catch (error) {
                return {
                    name: snippet.name,
                    success: false,
                    error: error.message
                };
            }
        })
    );
    
    return Promise.all(analysisPromises);
}

/**
 * Smart concurrent crawl with progress tracking
 * @param {string} baseUrl - Base URL to crawl
 * @param {Function} crawler - Crawler function
 * @param {number} concurrency - Parallel workers
 * @param {number} maxFiles - Max files to analyze
 * @param {Function} progressCallback - Called for each completion
 * @returns {Promise<Object>} Crawl results
 */
async function concurrentCrawl(baseUrl, crawler, concurrency = 6, maxFiles = 100, progressCallback = () => {}) {
    const { log } = require("../utils/logger");
    log(`[Concurrent Crawl] Starting with ${concurrency} workers, max ${maxFiles} files...`, 'verbose');
    
    // Get all JS files
    const jsUrls = await crawler(baseUrl);
    const urlsToAnalyze = jsUrls.slice(0, maxFiles);
    
    log(`[Concurrent Crawl] Found ${jsUrls.length} JS files, analyzing ${urlsToAnalyze.length}...`, 'verbose');
    
    const limit = pLimit(concurrency);
    let completed = 0;
    
    const analysisPromises = urlsToAnalyze.map(url =>
        limit(async () => {
            try {
                const beforeFindings = store.findings.length;
                const code = await fetcher(url);
                await analyze({ code, source: url });
                const newFindings = store.findings.length - beforeFindings;
                
                completed++;
                progressCallback({
                    completed,
                    total: urlsToAnalyze.length,
                    url,
                    success: true,
                    newFindings
                });
                
                return { url, success: true, newFindings };
            } catch (error) {
                completed++;
                progressCallback({
                    completed,
                    total: urlsToAnalyze.length,
                    url,
                    success: false,
                    error: error.message
                });
                
                return { url, success: false, error: error.message };
            }
        })
    );
    
    const results = await Promise.all(analysisPromises);
    
    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;
    
    return {
        totalUrls: jsUrls.length,
        analyzedUrls: urlsToAnalyze.length,
        successful,
        failed,
        totalFindings: store.findings.length,
        results
    };
}

module.exports = {
    analyzeUrlsConcurrent,
    analyzeCodesConcurrent,
    concurrentCrawl
};
