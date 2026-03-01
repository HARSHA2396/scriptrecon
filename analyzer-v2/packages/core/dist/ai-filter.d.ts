/**
 * AI-Powered False Positive Filtering Hook
 * Simulates a local LLM or API integration to evaluate the contextual risk
 * of a detected vulnerability. E.g., distinguishing 'key' as a CSS class vs API Key.
 */
export interface AiEvaluationResult {
    isFalsePositive: boolean;
    confidence: number;
    reasoning: string;
}
export declare function submitForAiEvaluation(ruleId: string, codeSnippet: string, variableName: string): Promise<AiEvaluationResult>;
