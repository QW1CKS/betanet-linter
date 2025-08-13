import { AnalyzerDiagnostics } from './types';
import { StaticPatterns } from './static-parsers';
export declare class BinaryAnalyzer {
    private binaryPath;
    private verbose;
    private dynamicProbe;
    private cachedAnalysis;
    private diagnostics;
    private analysisStartHr;
    private toolsReady;
    private binarySha256;
    private staticPatterns;
    private structuralAugmented;
    private networkAllowed;
    private networkOps;
    private networkAllowlist;
    private userAgent;
    constructor(binaryPath: string, verbose?: boolean);
    setNetworkAllowed(allowed: boolean, allowlist?: string[]): void;
    attemptNetwork(url: string, method?: string, fn?: () => Promise<any>): Promise<any>;
    getBinarySha256(): Promise<string>;
    getStaticPatterns(): Promise<StaticPatterns>;
    setDynamicProbe(flag: boolean): void;
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
        hasWebRTC: boolean;
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
        pathDiversityCount: number;
    }>;
    checkDHTSupport(): Promise<{
        hasDHT: boolean;
        deterministicBootstrap: boolean;
        rendezvousRotation?: boolean;
        beaconSetIndicator?: boolean;
        seedManagement: boolean;
        rotationHits?: number;
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
        hasVoucherFormat?: boolean;
        hasFROST?: boolean;
        hasPoW22?: boolean;
    }>;
    checkBuildProvenance(): Promise<{
        hasSLSA: boolean;
        reproducible: boolean;
        provenance: boolean;
    }>;
}
//# sourceMappingURL=analyzer.d.ts.map