const axios = require("axios");

async function fetcher(url){

    try {
        const res = await axios.get(url, {
            headers: {
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*"
            },
            timeout: 20000
        });

        return res.data;

    } catch (err) {
        console.log("[!] Failed to fetch:", url);
        return "";
    }
}

module.exports = fetcher;
