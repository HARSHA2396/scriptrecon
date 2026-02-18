const store = require("./store");
const { log } = require("../utils/logger");

/**
 * Detect cloud storage endpoints and configurations
 */
function detectCloudStorage(code) {
    
    const patterns = [
        // AWS S3
        {
            pattern: /s3[.-]([a-z0-9\-]+)\.amazonaws\.com/gi,
            type: "AWS S3 Bucket"
        },
        {
            pattern: /s3:\/\/([a-z0-9\-]+)/gi,
            type: "AWS S3 (s3:// protocol)"
        },
        
        // Firebase
        {
            pattern: /([a-z0-9\-]+)\.firebaseapp\.com/gi,
            type: "Firebase Hosting"
        },
        {
            pattern: /([a-z0-9\-]+)\.firebasestorage\.app/gi,
            type: "Firebase Storage"
        },
        
        // Google Cloud Storage
        {
            pattern: /storage\.googleapis\.com\/([a-z0-9\-]+)/gi,
            type: "Google Cloud Storage"
        },
        
        // Azure
        {
            pattern: /([a-z0-9\-]+)\.blob\.core\.windows\.net/gi,
            type: "Azure Blob Storage"
        },
        
        // DigitalOcean Spaces
        {
            pattern: /([a-z0-9\-]+)\.digitaloceanspaces\.com/gi,
            type: "DigitalOcean Spaces"
        },
        
        // Backblaze B2
        {
            pattern: /([a-z0-9]+)\.backblazeb2\.com/gi,
            type: "Backblaze B2"
        },
    ];
    
    const found = new Map();
    
    patterns.forEach(p => {
        const matches = code.matchAll(p.pattern);
        for (const match of matches) {
            const bucket = match[1] || match[0];
            if (bucket && bucket.length > 2) {
                if (!found.has(bucket)) {
                    found.set(bucket, p.type);
                }
            }
        }
    });
    
    if (found.size === 0) return;
    
    log("\n[Cloud Storage]", 'verbose');
    found.forEach((type, bucket) => {
        log(` ${bucket} (${type})`, 'verbose');
        store.cloudBuckets.add(bucket);
        store.addFinding("cloud_bucket", bucket, 7, "cloud_detection", type);
    });
}

module.exports = detectCloudStorage;
