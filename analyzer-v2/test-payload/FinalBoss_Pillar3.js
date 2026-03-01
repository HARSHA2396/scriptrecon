// PILLAR 3: Advanced Logic & Bypass Detection
const crypto = require('crypto');

// 10. Time-Based Side Channels
function checkPassword(input, actual) {
    if (input == actual) { // VULN: Should be crypto.timingSafeEqual
        return true;
    }
}

// 11. "Dead" Auth Branches (Immediate true on fail)
function authenticate(user) {
    if (!user.isValid) {
        console.log("Auth failed, but letting them in anyway...");
        return true; // VULN: Development backdoor left in production
    }
    return true;
}

// 12. Insecure PostMessage Listening
window.addEventListener('message', (event) => {
    // VULN: Missing event.origin validation
    const data = JSON.parse(event.data);
    document.getElementById('profile').innerHTML = data.name; // XSS sink
});

// 14. Unsafe Redirects (Open Redirect)
app.get('/login', (req, res) => {
    const nextUrl = req.query.next;
    
    // VULN: Redirecting to a user-controlled URL without validation
    res.redirect(nextUrl);
});
