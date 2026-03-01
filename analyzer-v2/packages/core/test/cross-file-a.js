const express = require('express');
const { doDangerousThing } = require('./cross-file-b');
const app = express();

app.get('/admin', (req, res) => {
    // Taint source: req.query.cmd
    const userInput = req.query.cmd;

    // Cross-file sink: calling a function from another file
    doDangerousThing(userInput);

    res.send('ok');
});
