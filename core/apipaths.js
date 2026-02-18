const { log } = require("../utils/logger");

function detectAPIPaths(code){

    const regex = /\/api\/[a-zA-Z0-9\/_-]+/g;
    const matches = code.match(regex) || [];

    const unique = new Set(matches);

    if(unique.size === 0) return;

    log("\n[API Paths]", 'verbose');
    unique.forEach(p=>log(` ${p}`, 'verbose'));
}

module.exports = detectAPIPaths;
