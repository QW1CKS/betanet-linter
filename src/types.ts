export interface Evidence {
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
    rekeyTriggers?: { bytes?: number; timeMinSec?: number; frames?: number };
    nonceReuseDetected?: boolean;
    patternVerified?: boolean;
    pqDateOk?: boolean;
    withinPolicy?: boolean;
  };
  scionControl?: {
    offers?: { path: string; latencyMs?: number; expiresAt?: string }[];
    rawCborB64?: string; // original CBOR for auditing
    uniquePaths?: number;
    noLegacyHeader?: boolean;
    duplicateOfferDetected?: boolean;
    duplicateWindowSec?: number;
    parseError?: string;
  };
}
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
  // Normative §11 spec item aggregation (13 canonical items)
  specItems?: SpecItemResult[]; // synthesized from underlying checks & evidence
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

// Aggregated normative spec item status
export interface SpecItemResult {
  id: number; // 1..13 canonical ordering of §11 items
  key: string; // stable key (e.g., transport-calibration, access-tickets, noise-rekey, http-adaptive, scion-bridging ...)
  name: string; // human readable title
  status: 'full' | 'partial' | 'missing'; // full = all required normative signals satisfied; partial = some evidence present; missing = none
  passed: boolean; // convenience (true only when status === 'full')
  reasons: string[]; // unmet requirement notes when partial/missing
  evidenceTypes: string[]; // distinct evidence categories contributing (heuristic/static-structural/dynamic-protocol/artifact)
  checks: number[]; // underlying check IDs contributing to evaluation
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
  networkAllowed?: boolean; // whether network operations permitted (Phase 6)
  networkOps?: { url: string; method: string; durationMs: number; status?: number; error?: string; blocked?: boolean }[]; // recorded network attempts
  evidenceSignatureValid?: boolean; // Phase 7: detached evidence signature verification result
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
  enableNetwork?: boolean; // Phase 6: allow outbound network enrichment
  failOnNetwork?: boolean; // Phase 6: if network attempted while disabled, treat as failure condition
  networkAllowlist?: string[]; // Phase 6: restrict outbound network hosts (empty => allow any when enabled)
  evidenceSignatureFile?: string; // Phase 7: detached signature file (base64) for evidence JSON
  evidencePublicKeyFile?: string; // Phase 7: public key file (base64 raw 32B ed25519 or PEM) for signature verify
  failOnSignatureInvalid?: boolean; // Phase 7: treat invalid evidence signature as failure exit
  dssePublicKeysFile?: string; // Phase 7: map of DSSE key ids to public keys for envelope verification
  dsseRequiredKeys?: string; // comma separated list provided via CLI
  dsseThreshold?: number; // required verified signer threshold
  evidenceBundleFile?: string; // Phase 7: multi-signer evidence bundle JSON path
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
  rebuildDigestMatch?: boolean; // explicit positive flag (Task 10)
  materialsValidated?: boolean; // set true when all provenance.materials digests accounted for in SBOM
  materialsMismatchCount?: number; // count of material digests not matched in SBOM (if sbom provided)
  materialsComplete?: boolean; // all listed materials include a digest
  toolchainDiff?: number; // Task 10: count of differing toolchain components between builds
  signatureVerified?: boolean; // DSSE / provenance signature verified with provided key
  signatureError?: string; // capture signature verification error reason
  dsseEnvelopeVerified?: boolean; // Phase 7: DSSE envelope signature(s) verified
  dsseSignerCount?: number; // Phase 7: number of DSSE signers validated
  dsseVerifiedSignerCount?: number; // Count of signatures that cryptographically verified
  dsseThresholdMet?: boolean; // Policy: required threshold satisfied
  dsseRequiredKeysPresent?: boolean; // All required key ids present
  dsseRequiredSignerThreshold?: number; // Task 10 explicit threshold
  dsseRequiredSignerCount?: number; // Task 10 required signers present
  dsseSignerDetails?: { keyid?: string; verified: boolean; reason?: string }[]; // Per-signer diagnostics
  dssePolicyReasons?: string[]; // Aggregate failure reasons if policy not met
  };
  // Phase 7: multi-signer evidence bundle (canonical hash chain) placeholder
  signedEvidenceBundle?: {
    entries?: { canonicalSha256?: string; signatureValid?: boolean; signer?: string }[];
    bundleSha256?: string; // hash over concatenated entry hashes
    multiSignerThresholdMet?: boolean; // >=2 signers present
  };
  // Phase 7: quantitative fallback timing evidence
  fallbackTiming?: {
    udpTimeoutMs?: number; // observed UDP wait before TCP attempt
    tcpConnectMs?: number; // measured TCP connect duration
    retryDelayMs?: number; // delay between UDP timeout and TCP start
    coverConnections?: number; // number of cover connections spawned
    coverTeardownMs?: number[]; // teardown times for cover flows
    withinPolicy?: boolean; // aggregate policy evaluation
    teardownStdDevMs?: number; // computed stddev of teardown times
  // Task 8 additions (Cover Connection Provenance & Timing Enforcement)
  coverStartDelayMs?: number; // delay before first cover connection starts
  teardownIqrMs?: number; // interquartile range of teardown times
  outlierPct?: number; // proportion of teardown samples considered outliers
  provenanceCategories?: string[]; // classification labels for connections (e.g., ['real','cover'])
  };
  // Phase 7: enhanced statistical variance metrics (jitter, mix)
  statisticalVariance?: {
    jitterStdDevMs?: number;
    jitterMeanMs?: number;
    sampleCount?: number;
    jitterWithinTarget?: boolean;
    mixUniquenessRatio?: number; // mirror mix.uniquenessRatio for consolidated stats
    mixDiversityIndex?: number; // mirror mix.diversityIndex
  mixNodeEntropyBits?: number; // consolidated Shannon entropy bits
  mixPathLengthStdDev?: number; // consolidated path length stddev
  };
  clientHello?: any; // placeholder; future structured shape
  noise?: any; // placeholder
  noiseExtended?: { pattern?: string; rekeysObserved?: number; rekeyTriggers?: { bytes?: number; timeMinSec?: number; frames?: number } };
  noiseTranscriptDynamic?: {
    messagesObserved?: string[];
    expectedSequenceOk?: boolean;
    rekeysObserved?: number;
    rekeyTriggers?: { bytes?: number; timeMinSec?: number; frames?: number };
    nonceReuseDetected?: boolean;
    patternVerified?: boolean;
    pqDateOk?: boolean;
    withinPolicy?: boolean;
  };
  governance?: any; // Phase 6 governance snapshot evidence
  ledger?: {
    finalitySets?: string[];
    quorumCertificatesValid?: boolean;
    quorumCertificatesCbor?: string[]; // base64 encoded CBOR blobs
    quorumCertificateInvalidReasons?: string[];
    finalityDepth?: number; // observed confirmation depth
    quorumWeights?: number[]; // weight sums per epoch/chain
    emergencyAdvanceUsed?: boolean;
    emergencyAdvanceJustification?: string;
    emergencyAdvanceLivenessDays?: number;
    emergencyAdvance?: { used?: boolean; justified?: boolean; livenessDays?: number };
  };
  governanceHistoricalDiversity?: {
    // Time-series of AS share distributions: array of { timestamp, asShares: { [as: string]: number } }
    series?: { timestamp: string; asShares: Record<string, number> }[];
    maxASShareDropPct?: number; // computed metric of largest single AS share drop (partition safety)
    stable?: boolean; // flag after verification thresholds
  volatility?: number; // stddev or mean absolute change metric
  maxWindowShare?: number; // maximum share for any AS in sliding window
  maxDeltaShare?: number; // max change between consecutive windows
  avgTop3?: number; // average of top 3 AS shares across period
  degradationPct?: number; // observed degradation (>0.2 triggers PARTITION_DEGRADATION)
  advancedStable?: boolean; // previously referenced advanced stability flag
  };
  mix?: {
    samples?: number; // number of path construction samples observed
    uniqueHopSets?: number; // count of unique hop sets among samples
    hopSets?: string[][]; // optional raw hop sets for future statistical validation
    minHopsBalanced?: number; // balanced mode min hops (e.g., 2)
    minHopsStrict?: number; // strict mode min hops (e.g., 3)
  mode?: 'balanced' | 'strict'; // declared privacy mode (Phase 4 enforcement)
  pathLengths?: number[]; // observed path lengths
  uniquenessRatio?: number; // derived uniqueHopSets/samples
  diversityIndex?: number; // dispersion metric (0-1)
  nodeEntropyBits?: number; // Phase 7 extension: Shannon entropy of node occurrence distribution
  pathLengthStdDev?: number; // Phase 7 extension: stddev of path length distribution
  }; // Phase 7 mix diversity sampling evidence
  h2Adaptive?: { settings?: Record<string, number>; paddingJitterMeanMs?: number; paddingJitterP95Ms?: number; paddingJitterStdDevMs?: number; sampleCount?: number; withinTolerance?: boolean; randomnessOk?: boolean };
  h3Adaptive?: { qpackTableSize?: number; paddingJitterMeanMs?: number; paddingJitterP95Ms?: number; paddingJitterStdDevMs?: number; sampleCount?: number; withinTolerance?: boolean; randomnessOk?: boolean };
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
  ja3Hash?: string; // md5 hash of JA3 canonical string
  ja3Canonical?: string; // canonical form when full raw capture available
    capturedAt?: string; // ISO timestamp of capture
    matchStaticTemplate?: boolean; // analyzer/harness comparison result against static template
  note?: string; // free-form note / simulation marker
  ciphers?: number[]; // parsed cipher suite IDs (for JA3 computation)
  extensions?: number[]; // parsed extension IDs (ordered)
  curves?: number[]; // supported groups IDs
  ecPointFormats?: number[]; // EC point formats
  captureQuality?: 'simulated' | 'parsed-openssl';
  rawClientHelloB64?: string; // existing pseudo/raw capture
  rawClientHelloCanonicalB64?: string; // improved canonical synthetic struct
  rawClientHelloCanonicalHash?: string; // sha256 hash of canonical raw ClientHello bytes (base64 decoded)
  };
  // New static structural evidence: access ticket & voucher cryptographic struct
  accessTicket?: {
    detected: boolean;
    fieldsPresent: string[];
    hex16Count?: number;
    hex32Count?: number;
    structConfidence?: number;
  paddingLengths?: number[]; // extracted numeric padding length tokens (e.g., pad16, padding_24)
  paddingVariety?: number; // count of unique padding lengths observed
  rateLimitTokensPresent?: boolean; // presence of rate/limit tokens indicating replay/rate policy coupling
  rotationTokenPresent?: boolean; // migrated here from parser (kept for backward compat)
  };
  accessTicketDynamic?: {
    samples: number;
    paddingLengths?: number[]; // sampled padding lengths
    uniquePadding?: number; // unique count
    rotationIntervalSec?: number; // simulated/observed rotation interval
    replayWindowSec?: number; // acceptable replay window
    rateLimitBuckets?: number; // count of distinct rate-limit buckets observed
    withinPolicy?: boolean; // overall policy pass
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
    frostThreshold?: { n?: number; t?: number };
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
  // Phase 4 additions: bootstrap rotation evidence & PoW / rate-limit evolution
  bootstrap?: {
    rotationEpochs?: number; // number of distinct rendezvous/beacon epochs observed
    beaconSetEntropySources?: number; // distinct entropy sources feeding beacon set (e.g., drand, vrf, pow)
    deterministicSeedDetected?: boolean; // flag if legacy deterministic seed constant still present
    sampleEpochSpanHours?: number; // timespan covered by sampled epochs (approx)
  };
  powAdaptive?: {
    difficultySamples?: number[]; // sequential bit-difficulty observations (e.g., from replay log)
    targetBits?: number; // expected steady-state target (e.g., 22)
    monotonicTrend?: boolean; // optional precomputed trend flag (ingester may supply)
    anomalies?: string[]; // anomaly codes from ingestion (e.g., 'large-drop','oscillation')
  };
  rateLimit?: {
    buckets?: { name?: string; capacity?: number; refillPerSec?: number }[]; // parsed bucket definitions
    bucketCount?: number; // convenience (can be derived from buckets length)
    distinctScopes?: number; // number of distinct scope types (ip,user,global,...)
    scopeRefillVariancePct?: number; // variance across scope refill rates (sanity check of multi-bucket logic)
  };
  // Task 9: Algorithm agility registry validation
  algorithmAgility?: {
    registryDigest?: string; // sha256 hex of registry artifact
    allowedSets?: string[]; // e.g., 'TLS_AES_128_GCM_SHA256+X25519', 'CHACHA20_POLY1305_SHA256+X25519'
    usedSets?: string[]; // sets extracted from binary/evidence
    unregisteredUsed?: string[]; // computed: used - allowed
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