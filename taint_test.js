const express = require('express');
const app = express();
const cp = require('child_process');

app.get('/', (req, res) => {
    // 1. Taint Source -> Assignment
    const userInput = req.query.cmd;
    const bodyArgs = req.body;
    
    // 2. Taint Sink (Eval)
    eval(userInput);
    
    // 3. Taint Sink (Exec)
    cp.exec(`echo ${userInput}`);
    
    // 4. Prototype Pollution (Object.assign)
    const merged = Object.assign({}, bodyArgs);
    
    // 5. Prototype Pollution (Spread)
    const clone = { ...req.query };
    
    // 6. Architectural: CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    // 7. Architectural: Empty Catch Silent Failure
    try {
        console.log("Risk");
    } catch (e) {
        
    }
    
    // 8. TOCTOU Race Condition
    const fs = require('fs');
    if (fs.existsSync('/etc/passwd')) {
       const key = fs.readFileSync('/etc/passwd');
    }
});
