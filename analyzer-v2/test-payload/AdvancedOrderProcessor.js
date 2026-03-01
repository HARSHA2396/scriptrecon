const express = require('express');
const cp = require('child_process');
const db = require('mysql');
const app = express();

const GITLAB_TOKEN = 'glpat-5529384756abcdef1234';

app.post('/api/order', (req, res) => {
    // 1. Taint Source (Object)
    const orderData = req.body.order;
    
    // Auth Bypass
    if (req.headers['x-admin'] === 'SECRET_DEBUG_KEY') {
        
        // 2. Taint Sink (SQL Injection via recursive property)
        db.query(`SELECT * FROM orders WHERE id = '${orderData.id}'`);
        
        // 3. Taint Sink (XSS via template literal)
        const responseHtml = `<h1>Order Note: ${orderData.note}</h1>`;
        res.send(responseHtml);
        
        // 4. Taint Sink (Command Injection)
        cp.exec(orderData.logRef);
        
        // 5. Prototype Pollution structural risk
        const config = Object.assign({}, orderData);
    }
});
