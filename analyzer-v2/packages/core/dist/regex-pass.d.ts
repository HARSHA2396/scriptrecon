/**
 * Pass 1: Fast Regex Scanning Engine
 * Designed to sweep files for Infrastructure OSINT, Secret Signatures, and Cloud Sinks
 * before the heavy AST parsing occurs.
 */
import { SarifIssue } from './sarif-formatter.js';
export interface RegexMatch {
    ruleId: string;
    level: 'error' | 'warning' | 'note';
    message: string;
}
export declare function runRegexPass(filePath: string, fileContent: string): SarifIssue[];
