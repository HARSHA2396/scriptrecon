const { TaintController } = require('../dist/taint-controller.js');
const path = require('path');

const analyzer = new TaintController();
// Load custom YAML rules
analyzer.loadCustomRules(path.join(__dirname, 'rules'));

// Analyze a file using the custom rules
analyzer.analyzeFile(path.join(__dirname, 'custom-rules-test.js'));
