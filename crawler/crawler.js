const axios = require("axios");
const parser = require("../core/parser");
const { log } = require("../utils/logger");
const pLimit = require("p-limit");

const limit = pLimit(5);

async function crawler(url){

    log("\n[+] Crawling: " + url, 'verbose');

    let html;
    try {
        html = await axios.get(url, {
            headers: {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "en-US,en;q=0.9"
            },
            timeout: 15000
        }).then(r => r.data);
    } catch (e){
        log("[!] Failed to fetch site", 'always');
        return;
    }

    // extract ANY script src
    const regex = /<script[^>]+src=["']([^"']+)["']/g;
    let match;

    const jsFiles = new Set();

    while ((match = regex.exec(html))) {
        let jsUrl = match[1];

        if (!jsUrl.startsWith("http")) {
            jsUrl = new URL(jsUrl, url).href;
        }

        jsFiles.add(jsUrl);
    }

    log("[+] JS files found: " + jsFiles.size, 'verbose');

    const tasks = [];

    jsFiles.forEach(js => {
        tasks.push(
            limit(async () => {
                try {
                    const code = await axios.get(js, {
                        headers: { "User-Agent": "Mozilla/5.0" }
                    }).then(r => r.data);

                    parser({ code, source: js });

                } catch {}
            })
        );
    });

    await Promise.all(tasks);

    log("\n[✓] Crawl complete\n", 'summary');
}

module.exports = crawler;
