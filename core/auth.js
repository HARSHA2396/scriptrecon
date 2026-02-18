const { log } = require("../utils/logger");

function detectAuth(code){

    const regex = /Authorization|Bearer\s+/gi;
    const matches = code.match(regex) || [];

    if(matches.length === 0) return;

    log("\n[Auth Indicators]", 'verbose');
    matches.forEach(m=>log(` ${m}`, 'verbose'));
}

module.exports = detectAuth;
