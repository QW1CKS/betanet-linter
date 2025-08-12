export interface HarnessOptions {
    scenarios?: string[];
    maxSeconds?: number;
    verbose?: boolean;
    probeHost?: string;
    probePort?: number;
    probeTimeoutMs?: number;
    fallbackHost?: string;
    fallbackUdpPort?: number;
    fallbackTcpPort?: number;
    fallbackUdpTimeoutMs?: number;
    coverConnections?: number;
}
export interface HarnessEvidence {
    schemaVersion?: string;
    clientHello?: {
        alpn?: string[];
        extOrderSha256?: string;
    };
    noise?: {
        pattern?: string;
    };
    voucher?: {
        structLikely?: boolean;
        tokenHits?: string[];
        proximityBytes?: number;
    };
    tlsProbe?: {
        host: string;
        port: number;
        offeredAlpn: string[];
        selectedAlpn?: string | null;
        cipher?: string;
        protocol?: string | null;
        handshakeMs?: number;
        error?: string;
    };
    fallback?: {
        udpAttempted: boolean;
        udpTimeoutMs: number;
        tcpConnected: boolean;
        tcpConnectMs?: number;
        tcpRetryDelayMs?: number;
        coverConnections?: number;
        coverTeardownMs?: number[];
        error?: string;
    };
    meta: {
        generated: string;
        scenarios: string[];
    };
}
export declare function runHarness(binaryPath: string, outFile: string, opts?: HarnessOptions): Promise<string>;
//# sourceMappingURL=harness.d.ts.map