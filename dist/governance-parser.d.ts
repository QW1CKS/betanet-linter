export interface QuorumCertificate {
    epoch: number;
    signatures: {
        validator: string;
        weight: number;
    }[];
    aggregateSignature?: string;
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
export declare function validateQuorumCertificates(qcs: QuorumCertificate[], thresholdFraction?: number): boolean;
//# sourceMappingURL=governance-parser.d.ts.map