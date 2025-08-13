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
    mixSamples?: number;
    mixHopsRange?: [number, number];
    mixDeterministic?: boolean;
    rekeySimulate?: boolean;
    h2AdaptiveSimulate?: boolean;
    h3AdaptiveSimulate?: boolean;
    jitterSamples?: number;
    clientHelloSimulate?: boolean;
    clientHelloCapture?: {
        host: string;
        port?: number;
        opensslPath?: string;
    };
    quicInitialHost?: string;
    quicInitialPort?: number;
    quicInitialTimeoutMs?: number;
    noiseRun?: boolean;
    accessTicketSimulate?: boolean;
}
export interface HarnessEvidence {
    noiseTranscriptDynamic?: {
        messagesObserved?: string[];
        expectedSequenceOk?: boolean;
        rekeysObserved?: number;
        rekeyTriggers?: {
            bytes?: number;
            timeMinSec?: number;
            frames?: number;
        };
        nonceReuseDetected?: boolean;
        patternVerified?: boolean;
        pqDateOk?: boolean;
        withinPolicy?: boolean;
    };
    schemaVersion?: string;
    clientHello?: {
        alpn?: string[];
        extOrderSha256?: string;
    };
    noise?: {
        pattern?: string;
    };
    noiseExtended?: {
        pattern?: string;
        rekeysObserved?: number;
        rekeyTriggers?: {
            bytes?: number;
            timeMinSec?: number;
            frames?: number;
        };
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
        policy?: {
            retryDelayMsOk?: boolean;
            coverConnectionsOk?: boolean;
            teardownSpreadOk?: boolean;
            overall?: boolean;
        };
    };
    mix?: {
        samples: number;
        uniqueHopSets: number;
        hopSets: string[][];
        minHopsBalanced: number;
        minHopsStrict: number;
    };
    h2Adaptive?: {
        settings?: Record<string, number>;
        meanMs?: number;
        p95Ms?: number;
        stddevMs?: number;
        randomnessOk?: boolean;
        withinTolerance?: boolean;
        sampleCount?: number;
    };
    h3Adaptive?: {
        qpackTableSize?: number;
        meanMs?: number;
        p95Ms?: number;
        stddevMs?: number;
        randomnessOk?: boolean;
        withinTolerance?: boolean;
        sampleCount?: number;
    };
    dynamicClientHelloCapture?: {
        alpn?: string[];
        extOrderSha256?: string;
        ja3?: string;
        ja3Hash?: string;
        ja3Canonical?: string;
        ja4?: string;
        rawClientHelloB64?: string;
        rawClientHelloCanonicalB64?: string;
        rawClientHelloCanonicalHash?: string;
        capturedAt?: string;
        matchStaticTemplate?: boolean;
        note?: string;
        ciphers?: number[];
        extensions?: number[];
        curves?: number[];
        ecPointFormats?: number[];
        captureQuality?: string;
    };
    calibrationBaseline?: {
        alpn?: string[];
        extOrderSha256?: string;
        source?: string;
        capturedAt?: string;
    };
    quicInitial?: {
        host: string;
        port: number;
        udpSent: boolean;
        responseBytes?: number;
        responseWithinMs?: number;
        error?: string;
        parsed?: {
            version?: string;
            dcil?: number;
            scil?: number;
            tokenLength?: number;
            lengthField?: number;
            versionNegotiation?: boolean;
            retry?: boolean;
            versionsOffered?: string[];
            odcil?: number;
        };
        rawInitialB64?: string;
        responseRawB64?: string;
    };
    statisticalJitter?: {
        meanMs: number;
        p95Ms: number;
        stdDevMs: number;
        samples: number;
        withinTarget?: boolean;
    };
    meta: {
        generated: string;
        scenarios: string[];
    };
    accessTicketDynamic?: {
        samples: number;
        paddingLengths?: number[];
        uniquePadding?: number;
        rotationIntervalSec?: number;
        replayWindowSec?: number;
        rateLimitBuckets?: number;
        withinPolicy?: boolean;
        paddingVarianceOk?: boolean;
        rotationIntervalOk?: boolean;
        replayWindowOk?: boolean;
        rateLimitOk?: boolean;
    };
}
export declare function runHarness(binaryPath: string, outFile: string, opts?: HarnessOptions): Promise<string>;
//# sourceMappingURL=harness.d.ts.map