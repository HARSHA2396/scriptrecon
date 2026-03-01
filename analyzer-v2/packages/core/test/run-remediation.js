const { TaintController } = require('../dist/taint-controller.js');
const path = require('path');

const analyzer = new TaintController();
// Running the analyzer over the prime test file directly
analyzer.analyzeFile(path.join(__dirname, 'vuln-test-prime.js'));
