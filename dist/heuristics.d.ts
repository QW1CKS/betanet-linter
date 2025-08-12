interface TextSources {
    strings: string[];
    symbols: string[];
}
export declare function detectCrypto(src: TextSources): {
    hasChaCha20: boolean;
    hasPoly1305: boolean;
    hasEd25519: boolean;
    hasX25519: boolean;
    hasKyber768: boolean;
    hasSHA256: boolean;
    hasHKDF: boolean;
};
export declare function detectNetwork(src: TextSources): {
    hasTLS: boolean;
    hasQUIC: boolean;
    hasHTX: boolean;
    hasECH: boolean;
    port443: boolean;
    hasWebRTC: boolean;
};
export declare function detectSCION(src: TextSources): {
    hasSCION: boolean;
    pathManagement: boolean;
    hasIPTransition: boolean;
    pathDiversityCount: number;
};
export declare function detectDHT(src: TextSources): {
    hasDHT: boolean;
    deterministicBootstrap: boolean;
    rendezvousRotation: boolean;
    beaconSetIndicator: boolean;
    seedManagement: boolean;
    rotationHits: number;
};
export declare function detectLedger(src: TextSources): {
    hasAliasLedger: boolean;
    hasConsensus: boolean;
    chainSupport: boolean;
};
export declare function detectPayment(src: TextSources): {
    hasCashu: boolean;
    hasLightning: boolean;
    hasFederation: boolean;
    hasVoucherFormat: boolean;
    hasFROST: boolean;
    hasPoW22: boolean;
};
export declare function detectBuildProvenance(src: TextSources): {
    hasSLSA: boolean;
    reproducible: boolean;
    provenance: boolean;
};
export declare function evaluatePrivacyTokens(strings: string[]): {
    mixScore: number;
    beaconScore: number;
    diversityScore: number;
    totalScore: number;
    passed: boolean;
};
export {};
//# sourceMappingURL=heuristics.d.ts.map