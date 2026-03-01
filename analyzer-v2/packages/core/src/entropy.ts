/**
 * Secret Entropy Detection
 * Calculates Shannon Entropy to identify highly random strings (likely API keys/secrets)
 */

export function calculateShannonEntropy(str: string): number {
    if (!str || str.length === 0) return 0;
    
    // Create frequency map
    const charCount = new Map<string, number>();
    for (const char of str) {
        charCount.set(char, (charCount.get(char) || 0) + 1);
    }
    
    let entropy = 0;
    const len = str.length;
    
    for (const count of charCount.values()) {
        const p = count / len;
        entropy -= p * Math.log2(p);
    }
    
    return entropy;
}

export function isHighEntropySecret(str: string): boolean {
    // Only check strings that are reasonably sized for an API key (e.g. > 16 chars)
    // Ignore very long blocks of text (like base64 images or long paragraphs)
    if (str.length < 16 || str.length > 256) return false;

    // Ignore things with spaces (sentences)
    if (str.includes(' ')) return false;
    
    // Ignore pure hashes if they don't look like keys, but actually high entropy is high entropy
    const entropy = calculateShannonEntropy(str);
    
    // A completely random base62 string of length 20 has entropy ~5.95
    // A random hex string has max entropy 4.0
    
    // If it has both uppercase, lowercase, and numbers, it's higher risk
    const hasUpper = /[A-Z]/.test(str);
    const hasLower = /[a-z]/.test(str);
    const hasNum = /[0-9]/.test(str);

    // Prefix rules for known tokens
    const hasKnownPrefix = str.startsWith('glpat-') || str.startsWith('ghp_') || str.startsWith('AKIA');

    if (hasKnownPrefix) return true;
    
    // Broad high-entropy fallback
    if (entropy > 4.5 && hasLower && hasNum && (hasUpper || entropy > 4.8)) {
        return true;
    }
    
    return false;
}
