const store = require("./store");
const { log } = require("../utils/logger");

function secrets(code){
    const patterns = [
        /api[_-]?key[^\n"' ]+/gi,
        /token[^\n"' ]+/gi,
        /secret[^\n"' ]+/gi,
        /Bearer\s+[A-Za-z0-9\._\-]+/gi
    ];

    const found = [];
    patterns.forEach(r => {
        const m = code.match(r) || [];
        m.forEach(s => {
            if (s && s.length > 8) {
                found.push(s);
                store.secrets.add(s);
            }
        });
    });

    if (found.length === 0) return;
    found.forEach(s => log(` [SECRET] ${s}`, 'verbose'));
}

module.exports = secrets;
