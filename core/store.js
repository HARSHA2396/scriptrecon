const store = {
    endpoints: new Set(),
    domains: new Set(),
    secrets: new Set(),
    jwt: [],
    
    // Enhanced findings with metadata
    findings: [],  // { type, value, severity, source, context }
    
    // Stack detection
    stackDetected: "unknown",
    technologies: new Set(),
    
    // Source maps
    sourceMaps: new Set(),
    
    // WebSockets
    websockets: new Set(),
    
    // Cloud storage
    cloudBuckets: new Set(),
    
    // GraphQL
    graphqlEndpoints: new Set(),
    
    // File classification
    fileClassification: {},  // filename -> classification
    
    // Add finding with scoring
    addFinding: function(type, value, severity = 3, source = "unknown", context = "") {
        this.findings.push({
            type,
            value,
            severity,
            source,
            context,
            timestamp: new Date().toISOString()
        });
    },
    
    // Deduplicate findings
    deduplicate: function() {
        const seen = new Set();
        this.findings = this.findings.filter(f => {
            const key = `${f.type}:${f.value}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    },
    
    // Get findings by severity
    findingsBySeverity: function(severity) {
        return this.findings.filter(f => f.severity >= severity);
    },
    
    // Clear all data
    clear: function() {
        this.endpoints.clear();
        this.domains.clear();
        this.secrets.clear();
        this.jwt = [];
        this.findings = [];
        this.technologies.clear();
        this.sourceMaps.clear();
        this.websockets.clear();
        this.cloudBuckets.clear();
        this.graphqlEndpoints.clear();
        this.fileClassification = {};
    }
};

module.exports = store;
