import * as fs from 'fs';
import * as yaml from 'js-yaml';
import * as path from 'path';
export class CustomRulesEngine {
    rules = [];
    constructor() { }
    loadRulesFromDirectory(dirPath) {
        if (!fs.existsSync(dirPath))
            return;
        try {
            const files = fs.readdirSync(dirPath).filter(f => f.endsWith('.yaml') || f.endsWith('.yml'));
            for (const file of files) {
                const fullPath = path.join(dirPath, file);
                const content = fs.readFileSync(fullPath, 'utf8');
                const parsed = yaml.load(content);
                if (parsed && parsed.rules && Array.isArray(parsed.rules)) {
                    for (const r of parsed.rules) {
                        if (r.id && r.type && r.targetPattern) {
                            this.rules.push({
                                id: r.id,
                                description: r.description || '',
                                type: r.type,
                                severity: r.severity || 5,
                                targetPattern: r.targetPattern
                            });
                            console.log(`[+] Loaded Custom Rule: ${r.id}`);
                        }
                    }
                }
            }
        }
        catch (e) {
            console.error(`Error loading rules from ${dirPath}:`, e);
        }
    }
    getSinks() {
        return this.rules
            .filter(r => r.type === 'SINK')
            .map(r => ({ functionName: r.targetPattern, id: r.id, severity: r.severity, description: r.description }));
    }
    getSources() {
        return this.rules
            .filter(r => r.type === 'SOURCE')
            .map(r => ({ sourcePattern: r.targetPattern, id: r.id, severity: r.severity, description: r.description }));
    }
}
