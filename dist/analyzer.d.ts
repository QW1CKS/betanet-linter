import { AnalyzerDiagnostics } from './types';
export declare class BinaryAnalyzer {
    private binaryPath;
    private verbose;
    private cachedAnalysis;
    private diagnostics;
    private analysisStartHr;
    constructor(binaryPath: string, verbose?: boolean);
    getDiagnostics(): AnalyzerDiagnostics;
    private detectTools;
    analyze(): Promise<{
        strings: string[];
        symbols: string[];
        fileFormat: string;
        architecture: string;
        dependencies: string[];
        size: number;
    }>;
    private extractStrings;
    private extractSymbols;
    private detectFileFormat;
    private detectArchitecture;
    private detectDependencies;
    private getFileSize;
    checkNetworkCapabilities(): Promise<{
        hasTLS: boolean;
        hasQUIC: boolean;
        hasHTX: boolean;
        hasECH: boolean;
        port443: boolean;
    }>;
    checkCryptographicCapabilities(): Promise<{
        hasChaCha20: boolean;
        hasPoly1305: boolean;
        hasEd25519: boolean;
        hasX25519: boolean;
        hasKyber768: boolean;
        hasSHA256: boolean;
        hasHKDF: boolean;
    }>;
    checkSCIONSupport(): Promise<{
        hasSCION: boolean;
        pathManagement: boolean;
        hasIPTransition: boolean;
    }>;
    checkDHTSupport(): Promise<{
        hasDHT: boolean;
        deterministicBootstrap: boolean;
        seedManagement: boolean;
    }>;
    checkLedgerSupport(): Promise<{
        hasAliasLedger: boolean;
        hasConsensus: boolean;
        chainSupport: boolean;
    }>;
    checkPaymentSupport(): Promise<{
        hasCashu: boolean;
        hasLightning: boolean;
        hasFederation: boolean;
    }>;
    checkBuildProvenance(): Promise<{
        hasSLSA: boolean;
        reproducible: boolean;
        provenance: boolean;
    }>;
}
//# sourceMappingURL=analyzer.d.ts.map