export interface QuorumCertificate {
    epoch: number;
    signatures: {
        validator: string;
        weight: number;
        sig?: string;
    }[];
    aggregateSignature?: string;
    rootHash?: string;
}
export interface GovernanceSnapshotDerived {
    maxASShare?: number;
    maxOrgShare?: number;
    asCapApplied?: boolean;
    orgCapApplied?: boolean;
    partitionsDetected?: boolean;
    quorumCertificatesValid?: boolean;
    finalitySets?: string[];
    emergencyAdvanceUsed?: boolean;
}
export declare function parseQuorumCertificates(buffers: Buffer[]): QuorumCertificate[];
export declare function deriveGovernanceMetrics(weights: {
    validator: string;
    as?: string;
    org?: string;
    weight: number;
}[]): {
    maxASShare: number;
    maxOrgShare: number;
    asCapApplied: boolean;
    orgCapApplied: boolean;
};
export declare function validateQuorumCertificates(qcs: QuorumCertificate[], thresholdFraction?: number, opts?: {
    governanceTotalWeight?: number;
    validatorKeys?: Record<string, string>;
    requireSignatures?: boolean;
}): {
    valid: boolean;
    reasons: string[];
};
export declare function evaluateHistoricalDiversity(series: {
    timestamp: string;
    asShares: Record<string, number>;
}[], cap?: number): {
    stable: boolean;
    maxASShare: number;
    avgTop3: number;
};
export declare function evaluateHistoricalDiversityAdvanced(series: {
    timestamp: string;
    asShares: Record<string, number>;
}[], cap?: number, window?: number): {
    advancedStable: boolean;
    volatility: number;
    maxWindowShare: number;
    maxDeltaShare: number;
};
//# sourceMappingURL=governance-parser.d.ts.map