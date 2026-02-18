// Simple logger with modes: 'concise' (default), 'verbose', 'silent'
let mode = 'concise';

function setMode(m){
    if (['concise','verbose','silent'].includes(m)) mode = m;
}

// logLevel: 'verbose' (detailed), 'summary' (brief), 'always' (must-print)
function log(message, logLevel = 'verbose'){
    if (mode === 'silent') return;
    if (mode === 'verbose') {
        console.log(message);
        return;
    }
    // concise mode: only print summary or always
    if (logLevel === 'summary' || logLevel === 'always') {
        console.log(message);
    }
}

module.exports = { setMode, log };
