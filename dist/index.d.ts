import { BinaryAnalyzer } from './analyzer';
import { ComplianceResult, CheckOptions } from './types';
export declare class BetanetComplianceChecker {
    private _analyzer;
    constructor();
    get analyzer(): BinaryAnalyzer;
    checkCompliance(binaryPath: string, options?: CheckOptions): Promise<ComplianceResult>;
    private runCheck;
    private checkHTXImplementation;
    private checkAccessTickets;
    private checkFrameEncryption;
    private checkSCIONPaths;
    private checkTransportEndpoints;
    private checkDHTBootstrap;
    private checkAliasLedger;
    private checkPaymentSystem;
    private checkBuildProvenance;
    private checkPostQuantum;
    generateSBOM(binaryPath: string, format?: 'cyclonedx' | 'spdx', outputPath?: string): Promise<string>;
    private extractComponents;
    private extractVersionFromPath;
    private generateCycloneDXSBOM;
    private generateSPDXSBOM;
    displayResults(results: ComplianceResult, format?: 'json' | 'table' | 'yaml'): void;
}
//# sourceMappingURL=index.d.ts.map