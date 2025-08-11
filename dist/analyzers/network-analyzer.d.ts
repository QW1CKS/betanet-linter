export interface NetworkAnalysis {
    protocols: string[];
    ports: number[];
    endpoints: string[];
    certificates: any[];
    tlsConfig: any;
}
export declare class NetworkAnalyzer {
    analyze(binaryPath: string): Promise<NetworkAnalysis>;
    detectProtocols(binaryPath: string): Promise<string[]>;
    detectPorts(binaryPath: string): Promise<number[]>;
    detectEndpoints(binaryPath: string): Promise<string[]>;
    detectCertificates(binaryPath: string): Promise<any[]>;
    analyzeTLSConfig(binaryPath: string): Promise<any>;
    supportsHTX(binaryPath: string): Promise<boolean>;
    supportsQUIC(binaryPath: string): Promise<boolean>;
    hasTLS13WithECH(binaryPath: string): Promise<boolean>;
}
//# sourceMappingURL=network-analyzer.d.ts.map