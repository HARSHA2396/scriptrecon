const child_process = require('child_process');

function doDangerousThing(cmdToRun) {
    // Sink inside another file
    child_process.exec(cmdToRun);
}

module.exports = { doDangerousThing };
