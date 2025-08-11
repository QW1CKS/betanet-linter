export interface CryptoAnalysis {
    ciphers: string[];
    hashes: string[];
    signatures: string[];
    keyExchange: string[];
    postQuantum: boolean;
    hasChaCha20: boolean;
    hasEd25519: boolean;
    hasX25519: boolean;
    hasKyber: boolean;
    libraries: string[];
}
export declare class CryptoAnalyzer {
    analyze(binaryPath: string): Promise<CryptoAnalysis>;
    detectCiphers(binaryPath: string): Promise<string[]>;
    detectHashes(binaryPath: string): Promise<string[]>;
    detectSignatures(binaryPath: string): Promise<string[]>;
    detectKeyExchange(binaryPath: string): Promise<string[]>;
    detectCryptoLibraries(binaryPath: string): Promise<string[]>;
    hasBetanetCryptoSuite(binaryPath: string): Promise<boolean>;
    hasPostQuantumSupport(binaryPath: string): Promise<boolean>;
    getCryptoComplianceScore(binaryPath: string): Promise<number>;
}
//# sourceMappingURL=crypto-analyzer.d.ts.map