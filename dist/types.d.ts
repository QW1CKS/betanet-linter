export interface Evidence {
    echVerification?: {
        outerSni?: string;
        innerSni?: string;
        outerCertHash?: string;
        innerCertHash?: string;
        certHashesDiffer?: boolean;
        extensionPresent?: boolean;
        greasePresent?: boolean;
        greaseAbsenceObserved?: boolean;
        outerAlpn?: string[];
        innerAlpn?: string[];
        alpnConsistent?: boolean;
        diffIndicators?: string[];
        verified?: boolean;
        failureCodes?: string[];
    };
    h2AdaptiveDynamic?: {
        settings?: Record<string, number>;
        paddingJitterMeanMs?: number;
        paddingJitterP95Ms?: number;
        paddingJitterStdDevMs?: number;
        sampleCount?: number;
        withinTolerance?: boolean;
        randomnessOk?: boolean;
    };
    h3AdaptiveDynamic?: {
        qpackTableSize?: number;
        paddingJitterMeanMs?: number;
        paddingJitterP95Ms?: number;
        paddingJitterStdDevMs?: number;
        sampleCount?: number;
        withinTolerance?: boolean;
        randomnessOk?: boolean;
    };
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
    noiseTranscript?: {
        messages?: {
            type: string;
            nonce?: number;
            direction?: '->' | '<-';
            bytes?: number;
            ts?: number;
            keyEpoch?: number;
        }[];
        rekeysObserved?: number;
        rekeyTriggers?: {
            bytes?: number;
            timeMinSec?: number;
            frames?: number;
        };
        rekeyEvents?: {
            atMessage?: number;
            trigger?: 'bytes' | 'time' | 'frames';
            bytes?: number;
            frames?: number;
            timeMinSec?: number;
        }[];
        transcriptHash?: string;
        pqDateOk?: boolean;
    };
    scionControl?: {
        offers?: {
            path: string;
            latencyMs?: number;
            expiresAt?: string;
            ts?: number;
            flowId?: string;
        }[];
        rawCborB64?: string;
        uniquePaths?: number;
        noLegacyHeader?: boolean;
        duplicateOfferDetected?: boolean;
        duplicateWindowSec?: number;
        parseError?: string;
        schemaValid?: boolean;
        pathSwitchLatenciesMs?: number[];
        maxPathSwitchLatencyMs?: number;
        probeIntervalsMs?: number[];
        avgProbeIntervalMs?: number;
        rateBackoffOk?: boolean;
        signatureValid?: boolean;
        timestampSkewOk?: boolean;
    };
}
export interface ComplianceCheck {
    id: number;
    name: string;
    description: string;
    passed: boolean;
    details: string;
    severity: 'critical' | 'major' | 'minor';
    evidenceType?: 'heuristic' | 'static-structural' | 'dynamic-protocol' | 'artifact';
    durationMs?: number;
    degradedHints?: string[];
}
export interface ComplianceResult {
    binaryPath: string;
    timestamp: string;
    overallScore: number;
    passed: boolean;
    checks: ComplianceCheck[];
    summary: {
        total: number;
        passed: number;
        failed: number;
        critical: number;
    };
    specItems?: SpecItemResult[];
    multiSignal?: {
        passedHeuristic: number;
        passedStatic: number;
        passedDynamic: number;
        passedArtifact: number;
        weightedScore: number;
        categoriesPresent?: string[];
        stuffingRatio?: number;
        suspiciousStuffing?: boolean;
    };
    specSummary?: {
        baseline: string;
        latestKnown: string;
        implementedChecks: number;
        totalChecks: number;
        pendingIssues?: {
            id: string;
            title: string;
        }[];
    };
    diagnostics?: AnalyzerDiagnostics;
    checkTimings?: {
        id: number;
        durationMs: number;
    }[];
    parallelDurationMs?: number;
}
export interface SpecItemResult {
    id: number;
    key: string;
    name: string;
    status: 'full' | 'partial' | 'missing';
    passed: boolean;
    reasons: string[];
    evidenceTypes: string[];
    checks: number[];
}
export interface SBOMComponent {
    name: string;
    version: string;
    type: 'library' | 'framework' | 'tool';
    license?: string;
    supplier?: string;
    hashes?: string[];
    licenses?: string[];
}
export interface SBOM {
    format: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json';
    data: any;
    generated: string;
}
export interface ToolStatus {
    name: string;
    available: boolean;
    durationMs?: number;
    error?: string;
}
export interface AnalyzerDiagnostics {
    tools: ToolStatus[];
    analyzeInvocations: number;
    cached: boolean;
    totalAnalysisTimeMs?: number;
    degraded?: boolean;
    skippedTools?: string[];
    timedOutTools?: string[];
    platform?: string;
    missingCoreTools?: string[];
    degradationReasons?: string[];
    networkAllowed?: boolean;
    networkOps?: {
        url: string;
        method: string;
        durationMs: number;
        status?: number;
        error?: string;
        blocked?: boolean;
    }[];
    evidenceSignatureValid?: boolean;
}
export interface CheckOptions {
    verbose?: boolean;
    checkFilters?: {
        include?: number[];
        exclude?: number[];
    };
    severityMin?: 'minor' | 'major' | 'critical';
    forceRefresh?: boolean;
    maxParallel?: number;
    checkTimeoutMs?: number;
    dynamicProbe?: boolean;
    strictMode?: boolean;
    allowHeuristic?: boolean;
    evidenceFile?: string;
    sbomFile?: string;
    governanceFile?: string;
    enableNetwork?: boolean;
    failOnNetwork?: boolean;
    networkAllowlist?: string[];
    evidenceSignatureFile?: string;
    evidencePublicKeyFile?: string;
    failOnSignatureInvalid?: boolean;
    dssePublicKeysFile?: string;
    dsseRequiredKeys?: string;
    dsseThreshold?: number;
    evidenceBundleFile?: string;
    strictAuthMode?: boolean;
}
export interface SBOMOptions {
    format: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json';
    outputPath?: string;
}
export interface IngestedEvidence {
    schemaVersion?: number;
    provenance?: {
        predicateType?: string;
        builderId?: string;
        binaryDigest?: string;
        materials?: {
            uri?: string;
            digest?: string;
        }[];
        subjects?: {
            name?: string;
            digest?: {
                sha256?: string;
                [k: string]: string | undefined;
            };
        }[];
        verified?: boolean;
        sourceDateEpoch?: number;
        rebuildDigestMismatch?: boolean;
        rebuildDigestMatch?: boolean;
        materialsValidated?: boolean;
        materialsMismatchCount?: number;
        materialsComplete?: boolean;
        toolchainDiff?: number;
        signatureVerified?: boolean;
        signatureError?: string;
        signatureAlgorithm?: string;
        signaturePublicKeyFingerprint?: string;
        dsseEnvelopeVerified?: boolean;
        dsseSignerCount?: number;
        dsseVerifiedSignerCount?: number;
        dsseThresholdMet?: boolean;
        dsseRequiredKeysPresent?: boolean;
        dsseRequiredSignerThreshold?: number;
        dsseRequiredSignerCount?: number;
        dsseSignerDetails?: {
            keyid?: string;
            verified: boolean;
            reason?: string;
        }[];
        dssePolicyReasons?: string[];
        pqHybridVerified?: boolean;
        pqHybridError?: string;
    };
    signedEvidenceBundle?: {
        entries?: {
            canonicalSha256?: string;
            signatureValid?: boolean;
            signer?: string;
            signatureError?: string;
        }[];
        bundleSha256?: string;
        computedBundleSha256?: string;
        multiSignerThresholdMet?: boolean;
        hashChainValid?: boolean;
        thresholdRequired?: number;
        aggregatedSignatureValid?: boolean;
        aggregatedAlgorithm?: string;
    };
    algorithmAgility?: {
        allowedSets?: string[];
        usedSets?: string[];
        unregisteredUsed?: string[];
        registryDigest?: string;
        observedSuites?: string[];
        suiteMapping?: {
            observed: string;
            mapped?: string;
            valid: boolean;
            reason?: string;
        }[];
        unknownCombos?: string[];
        mismatches?: {
            expected: string;
            actual: string;
        }[];
        schemaValid?: boolean;
    };
    fallbackTiming?: {
        udpTimeoutMs?: number;
        tcpConnectMs?: number;
        retryDelayMs?: number;
        coverConnections?: number;
        coverTeardownMs?: number[];
        withinPolicy?: boolean;
        teardownStdDevMs?: number;
        coverStartDelayMs?: number;
        teardownIqrMs?: number;
        outlierPct?: number;
        provenanceCategories?: string[];
        coverTeardownMedianMs?: number;
        coverTeardownP95Ms?: number;
        coverTeardownCv?: number;
        coverTeardownSkewness?: number;
        coverTeardownOutlierCount?: number;
        coverTeardownAnomalyCodes?: string[];
        behaviorModelScore?: number;
        behaviorWithinPolicy?: boolean;
    };
    statisticalVariance?: {
        jitterStdDevMs?: number;
        jitterMeanMs?: number;
        sampleCount?: number;
        jitterWithinTarget?: boolean;
        mixUniquenessRatio?: number;
        mixDiversityIndex?: number;
        mixNodeEntropyBits?: number;
        mixPathLengthStdDev?: number;
    };
    clientHello?: any;
    noise?: any;
    noiseExtended?: {
        pattern?: string;
        rekeysObserved?: number;
        rekeyTriggers?: {
            bytes?: number;
            timeMinSec?: number;
            frames?: number;
        };
    };
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
    governance?: any;
    ledger?: {
        finalitySets?: string[];
        quorumCertificatesValid?: boolean;
        quorumCertificatesCbor?: string[];
        quorumCertificateInvalidReasons?: string[];
        finalityDepth?: number;
        quorumWeights?: number[];
        emergencyAdvanceUsed?: boolean;
        emergencyAdvanceJustification?: string;
        emergencyAdvanceLivenessDays?: number;
        emergencyAdvance?: {
            used?: boolean;
            justified?: boolean;
            livenessDays?: number;
            chain?: string;
        };
        chains?: {
            name: string;
            finalityDepth?: number;
            weightSum?: number;
            epoch?: number;
            signatures?: {
                signer: string;
                weight?: number;
                valid?: boolean;
            }[];
        }[];
        requiredFinalityDepth?: number;
        weightThresholdPct?: number;
        uniqueSignerCount?: number;
        duplicateSignerDetected?: boolean;
        epochMonotonic?: boolean;
        emergencyAdvanceActiveChains?: string[];
        signatureValidationMode?: 'placeholder' | 'ed25519';
        signatureSampleVerifiedPct?: number;
        weightCapExceeded?: boolean;
        chainsSignatureVerified?: boolean;
        quorumSignatureStats?: {
            total: number;
            valid: number;
            invalid: number;
            mode: string;
        };
        signerAggregatedWeights?: Record<string, number>;
        weightAggregationMismatch?: boolean;
    };
    governanceHistoricalDiversity?: {
        series?: {
            timestamp: string;
            asShares: Record<string, number>;
        }[];
        maxASShareDropPct?: number;
        stable?: boolean;
        volatility?: number;
        maxWindowShare?: number;
        maxDeltaShare?: number;
        avgTop3?: number;
        degradationPct?: number;
        degradationComputedPct?: number;
        seriesGapRatio?: number;
        advancedStable?: boolean;
    };
    mix?: {
        samples?: number;
        uniqueHopSets?: number;
        hopSets?: string[][];
        minHopsBalanced?: number;
        minHopsStrict?: number;
        mode?: 'balanced' | 'strict';
        pathLengths?: number[];
        uniquenessRatio?: number;
        diversityIndex?: number;
        nodeEntropyBits?: number;
        pathLengthStdDev?: number;
        pathLengthMean?: number;
        pathLengthStdErr?: number;
        pathLengthCI95Width?: number;
        varianceMetricsComputed?: boolean;
        entropyConfidence?: number;
        beaconSources?: {
            drand?: {
                round?: number;
                randomness?: string;
            };
            nist?: {
                entropyHex?: string;
            };
            eth?: {
                blockNumber?: number;
                blockHash?: string;
            };
        };
        aggregatedBeaconEntropyBits?: number;
        vrfProofs?: {
            hopSetIndex: number;
            proof?: string;
            valid?: boolean;
        }[];
        nodeASNs?: Record<string, string>;
        nodeOrgs?: Record<string, string>;
        asDiversityIndex?: number;
        orgDiversityIndex?: number;
        firstReuseIndex?: number;
        requiredUniqueBeforeReuse?: number;
        vrfSelectionSimulated?: boolean;
    };
    h2Adaptive?: {
        settings?: Record<string, number>;
        paddingJitterMeanMs?: number;
        paddingJitterP95Ms?: number;
        paddingJitterStdDevMs?: number;
        sampleCount?: number;
        withinTolerance?: boolean;
        randomnessOk?: boolean;
    };
    h3Adaptive?: {
        qpackTableSize?: number;
        paddingJitterMeanMs?: number;
        paddingJitterP95Ms?: number;
        paddingJitterStdDevMs?: number;
        sampleCount?: number;
        withinTolerance?: boolean;
        randomnessOk?: boolean;
    };
    binaryMeta?: {
        format?: 'elf' | 'pe' | 'macho' | 'unknown';
        sections?: string[];
        importsSample?: string[];
        hasDebug?: boolean;
        sizeBytes?: number;
    };
    clientHelloTemplate?: {
        alpn?: string[];
        extensions?: number[];
        extOrderSha256?: string;
        extensionCount?: number;
        popId?: string;
    };
    dynamicClientHelloCapture?: {
        alpn?: string[];
        extOrderSha256?: string;
        ja3?: string;
        ja3Hash?: string;
        ja3Canonical?: string;
        ja4?: string;
        capturedAt?: string;
        matchStaticTemplate?: boolean;
        note?: string;
        ciphers?: number[];
        extensions?: number[];
        curves?: number[];
        ecPointFormats?: number[];
        captureQuality?: 'simulated' | 'parsed-openssl';
        rawClientHelloB64?: string;
        rawClientHelloCanonicalB64?: string;
        rawClientHelloCanonicalHash?: string;
        extensionCount?: number;
        popId?: string;
    };
    accessTicket?: {
        detected: boolean;
        fieldsPresent: string[];
        hex16Count?: number;
        hex32Count?: number;
        structConfidence?: number;
        paddingLengths?: number[];
        paddingVariety?: number;
        rateLimitTokensPresent?: boolean;
        rotationTokenPresent?: boolean;
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
    voucherCrypto?: {
        structLikely: boolean;
        keysetIdB64?: string;
        secretB64?: string;
        aggregatedSigB64?: string;
        signatureValid?: boolean;
        frostThreshold?: {
            n?: number;
            t?: number;
        };
        publicKeysB64?: string[];
        aggregatedPublicKeyB64?: string;
        sigAlgorithm?: string;
        verificationMode?: 'synthetic' | 'aggregated-ed25519';
        signatureComputedValid?: boolean;
    };
    calibrationBaseline?: {
        alpn?: string[];
        extOrderSha256?: string;
        source?: string;
        capturedAt?: string;
    };
    statisticalJitter?: {
        meanMs: number;
        p95Ms: number;
        stdDevMs: number;
        samples: number;
        withinTarget?: boolean;
    };
    noisePatternDetail?: {
        pattern?: string;
        hkdfLabelsFound?: number;
        messageTokensFound?: number;
    };
    bootstrap?: {
        rotationEpochs?: number;
        beaconSetEntropySources?: number;
        deterministicSeedDetected?: boolean;
        sampleEpochSpanHours?: number;
    };
    powAdaptive?: {
        difficultySamples?: number[];
        targetBits?: number;
        monotonicTrend?: boolean;
        anomalies?: string[];
        acceptancePercentile?: number;
        regressionSlope?: number;
        windowSize?: number;
        windowMaxDrop?: number;
        rollingAcceptance?: number[];
        recentMeanBits?: number;
    };
    rateLimit?: {
        buckets?: {
            name?: string;
            capacity?: number;
            refillPerSec?: number;
        }[];
        bucketCount?: number;
        distinctScopes?: number;
        scopeRefillVariancePct?: number;
        bucketSaturationPct?: number[];
        dispersionRatio?: number;
        capacityP95?: number;
        capacityStdDev?: number;
        refillVarianceTrend?: number;
    };
    scionControl?: {
        offers?: {
            path?: string;
            latencyMs?: number;
            ts?: number;
            flowId?: string;
        }[];
        uniquePaths?: number;
        noLegacyHeader?: boolean;
        duplicateOfferDetected?: boolean;
        parseError?: string;
        schemaValid?: boolean;
        pathSwitchLatenciesMs?: number[];
        maxPathSwitchLatencyMs?: number;
        probeIntervalsMs?: number[];
        avgProbeIntervalMs?: number;
        rateBackoffOk?: boolean;
        signatureValid?: boolean;
        timestampSkewOk?: boolean;
        rawCborB64?: string;
        signatureB64?: string;
        publicKeyB64?: string;
        signatureAlgorithm?: string;
        controlStreamHash?: string;
        duplicateWindowSec?: number;
        tokenBucketLevels?: number[];
        expectedBucketCapacity?: number;
    };
    negative?: {
        forbiddenPresent?: string[];
    };
    quicInitialBaseline?: {
        calibrationHash?: string;
        capturedAt?: string;
    };
    quicInitial?: {
        host?: string;
        port?: number;
        udpSent?: boolean;
        error?: string;
        rawInitialB64?: string;
        responseRawB64?: string;
        responseBytes?: number;
        responseWithinMs?: number;
        parsed?: {
            version?: string;
            dcil?: number;
            scil?: number;
            dcidHex?: string;
            scidHex?: string;
            tokenLength?: number;
            tokenHex?: string;
            lengthField?: number;
            versionNegotiation?: boolean;
            retry?: boolean;
            versionsOffered?: string[];
            odcil?: number;
        };
        calibrationHash?: string;
        calibrationMismatch?: boolean;
        failureCodes?: string[];
    };
    jitterMetrics?: {
        pingIntervalsMs?: number[];
        paddingSizes?: number[];
        priorityFrameGaps?: number[];
        chiSquareP?: number;
        runsP?: number;
        ksP?: number;
        entropyBitsPerSample?: number;
        sampleCount?: number;
        stdDevPing?: number;
        stdDevPadding?: number;
        stdDevPriorityGap?: number;
    };
    [k: string]: any;
}
export interface EvidenceMeta {
    generated: string;
    scenarios: string[];
    hashes?: {
        [key: string]: string;
    };
    tooling?: {
        opensslAvailable?: boolean;
    };
}
export interface SignedEvidence {
    algorithm: string;
    signature: string;
    publicKey?: string;
    keyId?: string;
    canonicalHash?: string;
    created: string;
}
//# sourceMappingURL=types.d.ts.map