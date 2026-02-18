/**
 * GraphQL Schema Extraction & Introspection
 * Identifies GraphQL endpoints and extracts schema information
 */

const axios = require("axios");
const store = require("./store");
const { log } = require("../utils/logger");

/**
 * Detect GraphQL endpoints in code
 */
function findGraphQLEndpoints(code) {
    const endpoints = new Set();
    
    const patterns = [
        /["']([^"']*\/graphql[^"']*?)["']/gi,
        /["']([^"']*\/gql[^"']*?)["']/gi,
        /["']([^"']*\/apollo[^"']*?)["']/gi,
        /url\s*[:=]\s*["']([^"']*)graphql[^"']*["']/gi,
        /endpoint\s*[:=]\s*["'](https?:\/\/[^"']*graphql[^"']*)["']/gi
    ];
    
    patterns.forEach(p => {
        const matches = code.matchAll(p);
        for (const match of matches) {
            if (match[1]) {
                let endpoint = match[1].trim();
                
                // Complete partial URLs
                if (!endpoint.startsWith("http")) {
                    endpoint = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
                }
                
                endpoints.add(endpoint);
            }
        }
    });
    
    return endpoints;
}

/**
 * Detect GraphQL client libraries and frameworks
 */
function detectGraphQLClient(code) {
    const clients = new Set();
    
    if (code.includes("apollo-client") || code.includes("@apollo/client")) {
        clients.add("Apollo Client");
    }
    if (code.includes("urql")) {
        clients.add("URQL");
    }
    if (code.includes("relay")) {
        clients.add("Relay");
    }
    if (code.includes("graphql-request")) {
        clients.add("GraphQL Request");
    }
    if (code.includes("gql`") || code.includes("graphql`")) {
        clients.add("GraphQL Query Detected");
    }
    
    return clients;
}

/**
 * Extract GraphQL queries from code
 */
function extractGraphQLQueries(code) {
    const queries = new Set();
    
    // Match gql template literals
    const gqlPattern = /gql\s*`([^`]+)`/gi;
    const matches = code.matchAll(gqlPattern);
    
    for (const match of matches) {
        if (match[1]) {
            const query = match[1].trim();
            // Extract operation names
            const opMatch = query.match(/(query|mutation|subscription)\s+(\w+)/i);
            if (opMatch) {
                queries.add({
                    type: opMatch[1],
                    name: opMatch[2],
                    query: query.substring(0, 100) + (query.length > 100 ? "..." : "")
                });
            } else {
                queries.add({ type: "query", name: "anonymous", query: query.substring(0, 100) });
            }
        }
    }
    
    // Match graphql template literals
    const graphqlPattern = /graphql\s*`([^`]+)`/gi;
    const gqlMatches = code.matchAll(graphqlPattern);
    
    for (const match of gqlMatches) {
        if (match[1]) {
            const query = match[1].trim();
            const opMatch = query.match(/(query|mutation|subscription)\s+(\w+)/i);
            if (opMatch) {
                queries.add({
                    type: opMatch[1],
                    name: opMatch[2],
                    query: query.substring(0, 100)
                });
            }
        }
    }
    
    return queries;
}

/**
 * Attempt to introspect GraphQL endpoint
 */
async function introspectGraphQL(endpoint) {
    try {
        // Try to fetch schema via introspection query
        const introspectionQuery = JSON.stringify({
            operationName: "IntrospectionQuery",
            query: `
                query IntrospectionQuery {
                    __schema {
                        types {
                            name
                            description
                            fields {
                                name
                                type { name }
                            }
                        }
                    }
                }
            `
        });
        
        // Attempt common GraphQL endpoints
        const urls = [
            endpoint,
            !endpoint.startsWith("http") ? `https://${endpoint}` : endpoint,
            endpoint.replace(/\/$/, "") + "/graphql",
            endpoint.replace(/\/$/, "") + "/gql"
        ];
        
        for (const url of urls) {
            try {
                const response = await axios.post(url, introspectionQuery, {
                    timeout: 5000,
                    headers: { "Content-Type": "application/json" }
                });
                
                if (response.data && response.data.data && response.data.data.__schema) {
                    return {
                        url: url,
                        accessible: true,
                        types: response.data.data.__schema.types.map(t => t.name)
                    };
                }
            } catch (e) {
                // Try next URL
            }
        }
    } catch (e) {
        // Introspection failed
    }
    
    return null;
}

/**
 * Main detection function
 */
async function detectGraphQLSchema(code, sourceUrl = "") {
    const endpoints = findGraphQLEndpoints(code);
    const clients = detectGraphQLClient(code);
    const queries = extractGraphQLQueries(code);

    if (endpoints.size === 0 && clients.size === 0 && queries.size === 0) return;

    log("\n[GraphQL Analysis]", 'verbose');

    // Log GraphQL endpoints
    if (endpoints.size > 0) {
        log("  Endpoints Found:", 'verbose');
        for (const ep of endpoints) {
            log(`    - ${ep}`, 'verbose');
            store.graphqlEndpoints.add(ep);
            store.addFinding("graphql_endpoint", ep, 6, "graphql_detection", "GraphQL endpoint");
        }
    }

    // Log clients
    if (clients.size > 0) {
        log("  GraphQL Clients:", 'verbose');
        for (const client of clients) {
            log(`    - ${client}`, 'verbose');
            store.addFinding("graphql_client", client, 2, "graphql_detection", "GraphQL client detected");
        }
    }

    // Log queries
    if (queries.size > 0) {
        log("  Queries/Mutations Detected:", 'verbose');
        for (const query of queries) {
            log(`    - ${query.type} ${query.name}`, 'verbose');
            store.addFinding("graphql_operation", `${query.type} ${query.name}`, 4, "graphql_detection", query.query);
        }
    }
    
    // Try introspection on first endpoint if URL-based
    if (sourceUrl && sourceUrl.includes("http") && endpoints.size > 0) {
        const firstEndpoint = [...endpoints][0];
        const fullUrl = new URL(firstEndpoint, sourceUrl).href;
        
        log(`  Attempting introspection: ${fullUrl}`, 'verbose');
        const schema = await introspectGraphQL(fullUrl);
        
        if (schema) {
            log(`    ✓ Schema introspection successful!`, 'verbose');
            log(`    Types: ${schema.types.slice(0, 5).join(", ")} (${schema.types.length} total)`, 'verbose');
            store.addFinding("graphql_schema", `Introspectable GraphQL at ${schema.url}`, 7, "graphql_detection", `${schema.types.length} types found`);
        }
    }
}

module.exports = {
    findGraphQLEndpoints,
    detectGraphQLClient,
    extractGraphQLQueries,
    introspectGraphQL,
    detectGraphQLSchema
};
