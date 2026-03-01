export interface Issue {
    type: 'security' | 'performance' | 'quality' | 'auth' | 'endpoint';
    message: string;
    line: number;
}
export interface AnalysisResult {
    complexity: number;
    issues: Issue[];
    endpoints: string[];
}
export declare function analyzeCode(code: string): AnalysisResult;
export { TaintController } from './taint-controller.js';
export { scanDependencies } from './dependency-scanner.js';
export { AiEvaluationResult, submitForAiEvaluation } from './ai-filter.js';
export { generatePoC } from './exploit-generator.js';
export { isHighEntropySecret } from './entropy.js';
export { runAdvancedScan } from './v2-engine.js';
