/**
 * Pass 1: Fast Regex Scanning Engine
 * Designed to sweep files for Infrastructure OSINT, Secret Signatures, and Cloud Sinks
 * before the heavy AST parsing occurs.
 */

import { SarifIssue } from './sarif-formatter.js';
import path from 'path';

export interface RegexMatch {
    ruleId: string;
    level: 'error' | 'warning' | 'note';
    message: string;
}

const REGEX_RULES: { id: string, level: 'error' | 'warning' | 'note', pattern: RegExp, message: string }[] = [
    // --- CATEGORY 2: Secret & Credential Intelligence (15 Rules) ---
    {
        id: 'SEC_AWS_KEY',
        level: 'error',
        pattern: /AKIA[0-9A-Z]{16}/,
        message: 'AWS Access Key ID detected.'
    },
    {
        id: 'SEC_GITHUB_PAT',
        level: 'error',
        pattern: /ghp_[a-zA-Z0-9]{36}/,
        message: 'GitHub Personal Access Token (PAT) detected.'
    },
    {
        id: 'SEC_STRIPE_KEY',
        level: 'error',
        pattern: /sk_live_[0-9a-zA-Z]{24}/,
        message: 'Stripe Live Secret Key detected.'
    },
    {
        id: 'SEC_SLACK_WEBHOOK',
        level: 'error',
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8}\/B[A-Z0-9]{8}\/[a-zA-Z0-9]{24}/,
        message: 'Slack Webhook URL detected.'
    },
    {
        id: 'SEC_GCP_API_KEY',
        level: 'error',
        pattern: /AIza[0-9A-Za-z\-_]{35}/,
        message: 'Google Cloud API Key detected.'
    },
    {
        id: 'SEC_RSA_PRIVATE_KEY',
        level: 'error',
        pattern: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/,
        message: 'Hardcoded Private Key detected in raw text.'
    },
    {
        id: 'SEC_HIGH_ENTROPY_VAR',
        level: 'warning',
        // Matches variable names implying secrets being assigned long strings
        pattern: /(?:key|secret|token|password|auth|api_key)\s*[:=]\s*['"\`][A-Za-z0-9+/=_-]{32,}['"\`]/i,
        message: 'High Entropy String assigned to a suspicious variable name.'
    },
    {
        id: 'SEC_HARDCODED_PASSWORD',
        level: 'error',
        pattern: /password\s*[:=]\s*['"\`](?!\s*['"\`]|null|undefined).+['"\`]/i,
        message: 'Hardcoded password assignment detected.'
    },
    {
        id: 'SEC_FIREBASE_CONFIG_LEAK',
        level: 'error',
        pattern: /(?=.*apiKey)(?=.*authDomain)(?=.*databaseURL).*/i,
        message: 'Firebase Configuration Object Leak detected on a single line.'
    },
    {
        id: 'SEC_DB_CONNECTION_STRING',
        level: 'error',
        pattern: /(mongodb(?:\+srv)?|postgres|mysql):\/\/[^:\s]+:[^@\s]+@[^\s]+/i,
        message: 'Database Connection String with embedded credentials detected.'
    },
    {
        id: 'SEC_SSH_KEY_TYPE',
        level: 'error',
        pattern: /(?:ssh-rsa|ssh-ed25519)\s+AAAA[0-9A-Za-z+/]+[=]{0,3}/,
        message: 'Hardcoded SSH Public/Private Key material detected.'
    },
    {
        id: 'SEC_HARDCODED_JWT_SECRET',
        level: 'error',
        pattern: /jwt\.sign\s*\([^,]+,\s*(?:'[^']+'|"[^"]+"|`[^`]+`)\)/,
        message: 'JWT signed with a hardcoded string literal secret.'
    },
    {
        id: 'SEC_LEAKED_DOT_ENV',
        level: 'warning',
        pattern: /^([A-Z_]+[A-Z0-9_]*)=[\w.-]+$/m,
        message: '.env style assignment found hardcoded in source file.'
    },
    {
        id: 'SEC_POSTMAN_ENV_VAR',
        level: 'warning',
        pattern: /\{\{[a-zA-Z0-9_]+secret[a-zA-Z0-9_]*\}\}/i,
        message: 'Postman/Template Environment Variable placeholder leaked in source.'
    },
    {
        id: 'SEC_IMPLICIT_FALLBACK_SECRET',
        level: 'warning',
        pattern: /process\.env\.[A-Z0-9_]+SECRET[A-Z0-9_]*\s*\|\|\s*['"\`][^'"\`]+['"\`]/i,
        message: 'Hardcoded fallback secret for process.env detected.'
    },

    // --- CATEGORY 3: Infrastructure & Reconnaissance (15 Rules) ---
    {
        id: 'INFRA_INTERNAL_IP',
        level: 'note',
        pattern: /(?:^|['"\s])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?:['"\s]|$)/,
        message: 'Internal/Private IP footprint leaked.'
    },
    {
        id: 'INFRA_CLOUD_METADATA_SSRF',
        level: 'error',
        pattern: /169\.254\.169\.254|metadata\.google\.internal/i,
        message: 'Cloud Metadata IP/DNS found. SSRF attacks here can steal IAM roles.'
    },
    {
        id: 'INFRA_SUBDOMAIN_BRUTE_LIST',
        level: 'note',
        pattern: /\[\s*['"\`](dev|uat|prod|staging|test|internal)['"\`]/i,
        message: 'Array of environment names detected (Subdomain Brute-Force Hint).'
    },
    {
        id: 'INFRA_S3_BUCKET',
        level: 'warning',
        pattern: /(?:s3\.amazonaws\.com|s3:\/\/)[\w.-]+/i,
        message: 'S3 Bucket URL or protocol pointer discovered.'
    },
    {
        id: 'INFRA_AZURE_BLOB',
        level: 'warning',
        pattern: /[\w.-]+\.blob\.core\.windows\.net/i,
        message: 'Azure Blob Storage URL discovered.'
    },
    {
        id: 'INFRA_HARDCODED_HTTP',
        level: 'note',
        pattern: /https?:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[\w.-]+/i,
        message: 'Hardcoded external HTTP/HTTPS Endpoint (Recon).'
    },
    {
        id: 'INFRA_KUBERNETES_API',
        level: 'warning',
        pattern: /kubernetes\.default\.svc|\/var\/run\/secrets\/kubernetes\.io\/serviceaccount/i,
        message: 'Kubernetes API/Service Account token path discovered.'
    },
    {
        id: 'INFRA_DOCKER_SOCKET',
        level: 'error',
        pattern: /\/var\/run\/docker\.sock/,
        message: 'Docker Socket reference discovered. Very dangerous if exposed.'
    },
    {
        id: 'INFRA_SHADOW_API',
        level: 'warning',
        pattern: /\/(?:v0|v1|debug|internal|admin)\/(?:api|users|config)/i,
        message: 'Shadow/Debug API Endpoint path detected.'
    },
    {
        id: 'INFRA_INTRANET_PORT_SCAN',
        level: 'note',
        pattern: /localhost:\d{4,5}|127\.0\.0\.1:\d{4,5}/,
        message: 'Hardcoded localhost port pattern (potential internal service).'
    },
    {
        id: 'INFRA_EMAIL_EXTRACTION',
        level: 'note',
        pattern: /[a-zA-Z0-9._%+-]+@(?:admin|internal|corp|company)\.[a-zA-Z]{2,}/i,
        message: 'Internal/Admin email address extracted.'
    },
    {
        id: 'INFRA_DOH_USAGE',
        level: 'note',
        pattern: /cloudflare-dns\.com\/dns-query|dns\.google\/resolve/i,
        message: 'DNS Over HTTPS (DoH) provider usage detected (potential hidden lookups).'
    },
    {
        id: 'INFRA_CORS_STAR',
        level: 'error',
        pattern: /Access-Control-Allow-Origin:\s*\*/i,
        message: 'CORS Wildcard Policy (*) detected in raw string.'
    },
    {
        id: 'INFRA_GRAPHQL_INTROSPECTION',
        level: 'warning',
        pattern: /__schema|__type|introspectionQuery/i,
        message: 'GraphQL Introspection query keywords embedded in client code.'
    },
    {
        id: 'INFRA_INTERNAL_FILE_PATH',
        level: 'warning',
        pattern: /(?:\/home\/[a-zA-Z0-9_]+\/|C:\\Users\\[a-zA-Z0-9_]+\\)/,
        message: 'Internal/Local OS file path leaked.'
    }
];

export function runRegexPass(filePath: string, fileContent: string): SarifIssue[] {
    const issues: SarifIssue[] = [];
    const lines = fileContent.split('\n');

    lines.forEach((line, index) => {
        // Skip excessively long lines to prevent basic ReDoS on the scanner itself
        if (line.length > 2000) return;

        for (const rule of REGEX_RULES) {
            if (rule.pattern.test(line)) {
                issues.push({
                    ruleId: rule.id,
                    level: rule.level,
                    message: rule.message,
                    file: path.basename(filePath),
                    line: index + 1
                });
            }
        }
    });

    return issues;
}
