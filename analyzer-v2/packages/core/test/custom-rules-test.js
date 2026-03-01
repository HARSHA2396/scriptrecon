const express = require('express');
const app = express();

app.post('/test', (req, res) => {
    // This value is defined as a SOURCE in our YAML
    const authData = req.headers['x-custom-auth'];

    // Taint propagation 
    const payloadToLog = "User Attempt: " + authData;

    // This function is defined as a SINK in our YAML
    logToSplunk(payloadToLog);
});
