const express = require('express');
const child_process = require('child_process');
const axios = require('axios');
const app = express();

// Sentinel-Prime: Inter-procedural Tracking
function executeSystemCommand(systemAction) {
    // The engine should track the 'req.query.cmd' parameter all the way into this function's 'systemAction' parameter
    child_process.exec(systemAction);
}

app.get('/admin', (req, res) => {
    // 1. Deep Object Property Taint
    const userInput = req.query.cmd;
    const urlTarget = req.body.data.url;

    // 2. Inter-procedural Flow (Sending taint into a function)
    executeSystemCommand(userInput);

    // 3. SSRF via Template Literals
    axios.get(`https://${urlTarget}/api/internal`);

    // 4. ReDoS Star Height detection
    const badRegex = new RegExp("(a*)*");

    res.send('ok');
});

// 5. CFG Downgrade test will be done by running this file from a `/test/` directory path
