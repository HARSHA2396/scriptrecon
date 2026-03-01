const express = require('express');
const cp = require('child_process');
const app = express();

const AWS_SECRET = "AKIA1A2B3D4F5G6H7J8K9"; // High Entropy String
const ADMIN_MODE = "SECRET_DEBUG_KEY";      // Magic Logic Bypass

app.post('/api/action', (req, res) => {
    // Taint Source
    const userInput = req.body.command;
    
    // Taint Propagation
    const actionCmd = userInput;

    // Sink (Memory Safety & Logic Flaw test)
    if (req.headers['x-admin'] === "SECRET_DEBUG_KEY") {
        const buf = Buffer.allocUnsafe(1024);
        
        // Taint Sink
        cp.exec(actionCmd); 

        // Prototype Pollution Test
        const config = Object.assign({}, req.body);
    }
});
