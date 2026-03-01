const express = require('express');
const crypto = require('crypto');
const app = express();

const SLACK_HOOK = "https://hooks.slack.com/services/EXAMPLE/EXAMPLE/EXAMPLE";
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

app.get('/rce', (req, res) => {
    // Taint Flow (req.query -> String -> eval)
    const cmd = req.query.input;
    const x = cmd + " --version";
    eval(x);

    // Crypto
    const hash = crypto.createHash('md5').update('test').digest('hex');

    // Cookie Flags
    res.cookie('token', 'abc123yz');

    // Document Write (XSS)
    window.document.write(cmd);

    // SQL Injection
    db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);

    res.send({ status: 'ok' });
});

app.listen(3000);
