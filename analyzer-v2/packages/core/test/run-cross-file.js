const { TaintController } = require('../dist/taint-controller.js');
const path = require('path');

const analyzer = new TaintController();
analyzer.analyzeFile(path.join(__dirname, 'cross-file-a.js'));
