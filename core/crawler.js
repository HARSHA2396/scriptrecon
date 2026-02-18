const axios = require("axios");
const parser = require("../core/parser");
const { log } = require("../utils/logger");
const pLimit = require("p-limit");

const limit = pLimit(5);

module.exports = async function(url){

    log("\n[+] Crawling: " + url, 'verbose');

    let html;
    try {
        html = await axios.get(url).then(r => r.data);
    } catch {
        log("[!] Failed to fetch site", 'always');
        return;
    }

    const regex = /src=["'](.*?\.js)["']/g;
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
                    const code = await axios.get(js).then(r => r.data);
                    parser({ code, source: js });
                } catch {}
            })
        );
    });

    await Promise.all(tasks);

    log("\n[✓] Crawl complete\n", 'summary');
};
