export interface ComplianceCheck {
  id: number;
  name: string;
  description: string;
  passed: boolean;
  details: string;
  severity: 'critical' | 'major' | 'minor';
  evidenceType?: 'heuristic' | 'static-structural' | 'dynamic-protocol' | 'artifact'; // classification for strict mode
  durationMs?: number; // execution time for the check
  degradedHints?: string[]; // per-check degradation context (ISSUE-035)
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
    baseline: string; // fully covered baseline spec version
    latestKnown: string; // latest spec version known to tool
    implementedChecks: number; // number of checks whose introducedIn <= latestKnown
    totalChecks: number; // total registered checks
    pendingIssues?: { id: string; title: string }[]; // subset of open enhancement issues for latest spec
  };
  diagnostics?: AnalyzerDiagnostics;
  checkTimings?: { id: number; durationMs: number }[];
  parallelDurationMs?: number; // total wall-clock duration of parallel evaluation phase
}

export interface SBOMComponent {
  name: string;
  version: string;
  type: 'library' | 'framework' | 'tool';
  license?: string;
  supplier?: string;
  hashes?: string[];
  licenses?: string[]; // enriched multi-license capture
}

// Generic SBOM structure used by sbom-generator.ts
export interface SBOM {
  format: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json';
  data: any; // Underlying JSON / XML / text representation
  generated: string; // ISO timestamp
}

// Tool availability & performance diagnostics
export interface ToolStatus {
  name: string;
  available: boolean;
  durationMs?: number;
  error?: string;
}

export interface AnalyzerDiagnostics {
  tools: ToolStatus[];
  analyzeInvocations: number; // how many times analyze() logic executed (should be 1 after memoization)
  cached: boolean; // whether subsequent calls used cache
  totalAnalysisTimeMs?: number; // elapsed time for first analysis
  degraded?: boolean; // whether any external tooling missing or timed out
  skippedTools?: string[]; // tools explicitly skipped via config
  timedOutTools?: string[]; // tools that exceeded timeout
  platform?: string; // process.platform recorded for transparency
  missingCoreTools?: string[]; // core analysis tools unavailable on this platform
  degradationReasons?: string[]; // human-readable reasons driving degraded=true
}

export interface CheckOptions {
  verbose?: boolean;
  checkFilters?: {
    include?: number[];
    exclude?: number[];
  };
  severityMin?: 'minor' | 'major' | 'critical';
  forceRefresh?: boolean; // if true, re-run analysis ignoring cache
  maxParallel?: number; // limit concurrent check evaluations (default: unlimited)
  checkTimeoutMs?: number; // per-check timeout (optional)
  dynamicProbe?: boolean; // attempt lightweight runtime '--help' probe to augment strings
  strictMode?: boolean; // if true, only non-heuristic evidence counts toward pass unless allowHeuristic
  allowHeuristic?: boolean; // if true in strict mode, heuristic passes are included
  evidenceFile?: string; // path to external evidence JSON (Phase 1 ingestion)
  sbomFile?: string; // optional SBOM file path to cross-check provenance materials (Phase 3 extension)
  governanceFile?: string; // governance & ledger evidence (Phase 6)
}

export interface SBOMOptions {
  format: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json';
  outputPath?: string;
}

// Minimal evidence schema starter (will expand in later phases)
export interface IngestedEvidence {
  provenance?: {
    predicateType?: string;
    builderId?: string;
    binaryDigest?: string;
  materials?: { uri?: string; digest?: string }[];
  subjects?: { name?: string; digest?: { sha256?: string; [k: string]: string | undefined } }[]; // SLSA subjects array
  verified?: boolean; // internal flag after validation
  sourceDateEpoch?: number; // captured SOURCE_DATE_EPOCH if present
  rebuildDigestMismatch?: boolean; // flag set when CI detects non-reproducible rebuild
  materialsValidated?: boolean; // set true when all provenance.materials digests accounted for in SBOM
  materialsMismatchCount?: number; // count of material digests not matched in SBOM (if sbom provided)
  materialsComplete?: boolean; // all listed materials include a digest
  signatureVerified?: boolean; // DSSE / provenance signature verified with provided key
  signatureError?: string; // capture signature verification error reason
  };
  clientHello?: any; // placeholder; future structured shape
  noise?: any; // placeholder
  governance?: any; // Phase 6 governance snapshot evidence
  ledger?: any; // Phase 6 ledger observation evidence
  [k: string]: any; // allow forward-compatible keys
}