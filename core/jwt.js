const jwt = require("jsonwebtoken");
const store = require("./store");
const { log } = require("../utils/logger");

function findJWTs(code){
    const regex = /eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/g;
    const matches = code.match(regex) || [];
    if (matches.length === 0) return;

    log("\n[JWT Tokens Found]", 'verbose');

    matches.forEach(token => {
        log(`\nToken: ${token}`, 'verbose');
        try {
            const decoded = jwt.decode(token, { complete:true });
            if (decoded) {
                log(` Header: ${JSON.stringify(decoded.header)}`, 'verbose');
                log(` Payload: ${JSON.stringify(decoded.payload)}`, 'verbose');
            }
            store.jwt.push(token);
        } catch {}
    });
}

module.exports = findJWTs;
