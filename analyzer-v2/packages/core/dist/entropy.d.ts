/**
 * Secret Entropy Detection
 * Calculates Shannon Entropy to identify highly random strings (likely API keys/secrets)
 */
export declare function calculateShannonEntropy(str: string): number;
export declare function isHighEntropySecret(str: string): boolean;
