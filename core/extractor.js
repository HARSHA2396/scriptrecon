const endpoints = require("./endpoints");
const astEndpoints = require("./astEndpoints");
const resolveBaseEndpoints = require("./resolver");
const extractDomains = require("./domains");
const findJWTs = require("./jwt");
const secrets = require("./secrets");
const intel = require("./intel");
const { log } = require("../utils/logger")
const detectGraphQL = require("./graphql")
const detectAuth = require("./auth")
const detectAPIPaths = require("./apipaths");
const detectKeys = require("./apikeys");
const { detectStack, getNoiseFilters } = require("./stackDetector");
const findSourceMaps = require("./sourceMaps");
const detectWebSockets = require("./websockets");
const detectCloudStorage = require("./cloudBuckets");
const store = require("./store");
const { classifyFile, shouldAnalyzeDeep } = require("./fileClassifier");
const { scoreAllFindings, getFindinsSummary } = require("./scoring");
const { detectVulnerableDependencies } = require("./dependencyChecker");
const { detectGraphQLSchema } = require("./graphqlSchema");


async function extractor(code, ast, sourceUrl = "unknown"){

    // Verbose header (only printed in verbose mode)
    log("\n=== ScriptRecon Analysis ===\n", 'verbose');

    // Classify file
    const classification = classifyFile(sourceUrl, code);
    log(`[File Type] ${classification}`, 'verbose');

    // Detect stack
    const stack = detectStack(code);
    store.stackDetected = stack;
    log(`[Stack] ${stack}`, 'verbose');

    // Core analysis
    endpoints(code);

    if (ast) {
        astEndpoints(ast);
        resolveBaseEndpoints(ast);
    }

    extractDomains(code);
    findJWTs(code);
    secrets(code);
    intel(code);
    detectGraphQL(code);
    detectAuth(code);
    detectKeys(code);
    detectAPIPaths(code);
    
    // Advanced analysis
    detectWebSockets(code);
    detectCloudStorage(code);
    
    // NEW: Vulnerability detection
    detectVulnerableDependencies(code);
    
    // NEW: GraphQL schema extraction
    await detectGraphQLSchema(code, sourceUrl);
    
    // Source maps detection (async)
    if (sourceUrl && sourceUrl.includes("http")) {
        await findSourceMaps(sourceUrl, code);
    }

    // Scoring
    scoreAllFindings();
    
    // In concise mode we avoid printing the summary here to prevent noisy repeated output
    // Final summary will be printed once by the CLI after all files are analyzed.
}

module.exports = extractor;
