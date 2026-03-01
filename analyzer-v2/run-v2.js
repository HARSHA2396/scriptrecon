const path = require('path');
const { runAdvancedScan } = require('./packages/core/dist/index');

const TEST_DIR = path.join(__dirname, 'test-payload');

async function main() {
    console.log("=========================================");
    console.log("   V2 NEXT-GEN SAST ENGINE TEST RUNNER   ");
    console.log("=========================================\n");
    
    await runAdvancedScan(TEST_DIR);
}

main().catch(console.error);
