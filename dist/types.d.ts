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
}
export interface SBOMOptions {
    format: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json';
    outputPath?: string;
}
export interface IngestedEvidence {
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
        materialsValidated?: boolean;
        materialsMismatchCount?: number;
        materialsComplete?: boolean;
        signatureVerified?: boolean;
        signatureError?: string;
    };
    clientHello?: any;
    noise?: any;
    governance?: any;
    ledger?: any;
    [k: string]: any;
}
//# sourceMappingURL=types.d.ts.map