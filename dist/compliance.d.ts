import { ComplianceResult, CheckOptions } from './types';
export declare class ComplianceChecker {
    private analyzer;
    constructor(binaryPath: string, options?: CheckOptions);
    runAllChecks(): Promise<ComplianceResult>;
    private checkHTXImplementation;
    private checkRotatingAccessTickets;
    private checkInnerFrameEncryption;
    private checkSCIONPathManagement;
    private checkTransportEndpoints;
    private checkDHTBootstrap;
    private checkAliasLedgerVerification;
    private checkCashuLightningSupport;
    private checkReproducibleBuilds;
    private checkPostQuantumSuites;
}
//# sourceMappingURL=compliance.d.ts.map