// PILLAR 4 & 5: Performance, Performance & Modern Security
const vm = require('vm');

// 15. ReDoS (Regex Denial of Service)
const badRegex = new RegExp('(a+)+$'); // Evil Regex evaluation sink
badRegex.test("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!");

// 18. Missing Security Headers
// (Astray flags this if res.setHeader('Content-Security-Policy') is NEVER called in a file that calls app.listen)
app.listen(8080, () => {
    console.log("Server started on port 8080");
});

// 19. Sandbox Escape Patterns
const context = { x: 2 };
vm.createContext(context);
const code = 'x += 40; var y = 17;';
vm.runInContext(code, context); // VULN: Sandbox Escape Target

// 20. Sensitive Data in console.log
app.post('/login', (req, res) => {
    const password = req.body.password;
    // Taint propagation into logger
    console.log("Failed login attempt with password: " + password); // VULN: Token/Password Leak to stdout
});
