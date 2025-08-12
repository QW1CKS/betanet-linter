import { BinaryAnalyzer } from './analyzer';
import { ComplianceResult, CheckOptions } from './types';
export declare class BetanetComplianceChecker {
    private _analyzer;
    constructor();
    get analyzer(): BinaryAnalyzer;
    checkCompliance(binaryPath: string, options?: CheckOptions): Promise<ComplianceResult>;
    private ensureAnalyzer;
    private resolveDefinitions;
    private runChecks;
    private assembleResult;
    generateSBOM(binaryPath: string, format?: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json', outputPath?: string): Promise<string>;
    displayResults(results: ComplianceResult, format?: 'json' | 'table' | 'yaml'): void;
}
//# sourceMappingURL=index.d.ts.map