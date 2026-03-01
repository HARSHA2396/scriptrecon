const express = require('express');
const app = express();
const fetch = require('node-fetch');

// PILLAR 1: Secret & Token Intelligence
// 1. JWT "None" Algorithm Verification Flaw
const jwt = require('jsonwebtoken');
function verifyToken(token) {
    // Deliberately ignoring the "alg" or accepting "none"
    return jwt.verify(token, 'shhhhh', { algorithms: ['HS256', 'none'] });
}

// 2. High-Entropy Variable Names hiding obfuscated keys
const a1z9 = "1234567890abcdef1234567890abcdef"; // Example high-entropy string
const _0x4a21 = "ghp_123456789012345678901234567890123456"; // GitHub Token

// 3. Google Dorking Pattern Detection (Hardcoded search scraping)
const searchScraperUrl = "https://www.google.com/search?q=site:*.internal.com+ext:log";

// 4. Private Key Header Scanning
const rsaKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIB... (fake key data)
-----END RSA PRIVATE KEY-----
`;

app.get('/api/metadata', async (req, res) => {
    // 5. Cloud Metadata Sinks (AWS SSRF attempt)
    const ssrfTarget = req.query.url || 'http://169.254.169.254/latest/meta-data/iam/security-credentials/';
    const response = await fetch(ssrfTarget);
    const data = await response.text();
    res.send(data);
});

app.listen(3000, () => console.log('Final Boss App listening on port 3000!'));
