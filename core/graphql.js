const store = require("./store");
const { log } = require("../utils/logger");

function detectGraphQL(code){

    const patterns = [
        /\/graphql/gi,
        /apollo/gi
    ];

    const found = new Set();

    patterns.forEach(r=>{
        const m = code.match(r) || [];
        m.forEach(v=>found.add(v));
    });

    if(found.size === 0) return;

    log("\n[GraphQL Indicators]", 'verbose');
    found.forEach(f=>{
        log(` ${f}`, 'verbose');
    });
}

module.exports = detectGraphQL;
