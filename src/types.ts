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
  multiSignal?: {
    passedHeuristic: number;
    passedStatic: number;
    passedDynamic: number;
    passedArtifact: number;
    weightedScore: number; // artifact=3, dynamic=2, static=1, heuristic=0
  categoriesPresent?: string[]; // names of evidence categories present
  stuffingRatio?: number; // keyword stuffing detection ratio (0-1)
  suspiciousStuffing?: boolean; // flag when evasion suspected
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
  schemaVersion?: number; // evidence schema version (bumped to 2 with binaryMeta & negative assertions)
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
  noiseExtended?: { pattern?: string; rekeysObserved?: number; rekeyTriggers?: { bytes?: number; timeMinSec?: number; frames?: number } };
  governance?: any; // Phase 6 governance snapshot evidence
  ledger?: any; // Phase 6 ledger observation evidence
  mix?: {
    samples?: number; // number of path construction samples observed
    uniqueHopSets?: number; // count of unique hop sets among samples
    hopSets?: string[][]; // optional raw hop sets for future statistical validation
    minHopsBalanced?: number; // balanced mode min hops (e.g., 2)
    minHopsStrict?: number; // strict mode min hops (e.g., 3)
  }; // Phase 7 mix diversity sampling evidence
  h2Adaptive?: { settings?: Record<string, number>; paddingJitterMeanMs?: number; paddingJitterP95Ms?: number; withinTolerance?: boolean; sampleCount?: number };
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
  };
  // Dynamic TLS ClientHello capture (evidence schema v3 draft field – Step 11 slice)
  dynamicClientHelloCapture?: {
    alpn?: string[]; // observed negotiated ALPN proposal ordering
    extOrderSha256?: string; // hash of observed extension ordering
    ja3?: string; // optional JA3/JA4 style fingerprint string (simulated until real capture integrated)
    capturedAt?: string; // ISO timestamp of capture
    matchStaticTemplate?: boolean; // analyzer/harness comparison result against static template
  note?: string; // free-form note / simulation marker
  ciphers?: number[]; // parsed cipher suite IDs (for JA3 computation)
  extensions?: number[]; // parsed extension IDs (ordered)
  curves?: number[]; // supported groups IDs
  ecPointFormats?: number[]; // EC point formats
  captureQuality?: 'simulated' | 'parsed-openssl';
  };
  calibrationBaseline?: {
    alpn?: string[];
    extOrderSha256?: string;
    source?: string; // e.g. 'origin-probe', 'manual', 'simulated'
    capturedAt?: string;
  };
  statisticalJitter?: { meanMs: number; p95Ms: number; stdDevMs: number; samples: number; withinTarget?: boolean };
  noisePatternDetail?: {
    pattern?: string;
    hkdfLabelsFound?: number;
    messageTokensFound?: number;
  };
  negative?: {
    forbiddenPresent?: string[]; // list of forbidden tokens discovered
  };
  // Future: quicInitial, statisticalJitter, signedEvidence, governanceHistoricalDiversity
  [k: string]: any; // allow forward-compatible keys
}

// Augmented harness meta (Phase 2 completion hashing)
export interface EvidenceMeta {
  generated: string;
  scenarios: string[];
  hashes?: { [key: string]: string }; // sha256 over JSON string of each evidence section (integrity aid)
  tooling?: { opensslAvailable?: boolean }; // capture presence of external tools used for dynamic capture
}

export interface SignedEvidence {
  algorithm: string; // e.g. ed25519-sha256
  signature: string; // base64
  publicKey?: string; // base64 or PEM (public)
  keyId?: string; // optional key identifier
  canonicalHash?: string; // sha256 of canonicalized evidence JSON
  created: string; // ISO timestamp
}