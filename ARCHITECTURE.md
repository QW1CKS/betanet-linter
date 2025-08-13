# Betanet Compliance Linter - Project Structure (Phase 7 Updated)

betanet-linter/
# Betanet Compliance Linter - Project Structure

```
betanet-linter/
├── src/
│   ├── index.ts              # Orchestrator: registry-driven compliance + SBOM delegation
│   ├── check-registry.ts     # Declarative check metadata + evaluate() functions
│   ├── analyzer.ts           # Binary + structural analysis (memoized, schema v2 population)
│   ├── heuristics.ts         # Heuristic pattern detection (legacy + supplemental)
│   ├── binary-introspect.ts  # Lightweight binary format + section/import introspection
│   ├── constants.ts          # Spec/version constants (Betanet 1.0 + partial 1.1)
│   ├── sbom/                 # Advanced SBOM generator (active)
│   └── types.ts              # TypeScript type definitions
├── bin/
│   └── cli.js                # Command-line interface
├── tests/
│   └── compliance-checker.test.ts  # Unit tests
├── github-action/
│   └── betanet-compliance.yml      # GitHub Action template
├── package.json              # Project dependencies and scripts
├── tsconfig.json            # TypeScript configuration
├── jest.config.js           # Jest test configuration
├── .eslintrc.js            # ESLint configuration
└── README.md               # Project documentation
```

## Key Components

### 1. Core Modules

- **BetanetComplianceChecker** (`src/index.ts`)
   - Orchestrates compliance using the Check Registry (no per-check methods)
   - Partial Betanet 1.1 heuristics (transport versions, rendezvous rotation hits, path diversity count, optional WebRTC, privacy weighting, PQ date override)
   - Supports analyzer cache invalidation via `forceRefresh` flag
   - Honors `BETANET_FAIL_ON_DEGRADED=1` to override pass when tooling degraded
   - Aggregates results (score, pass/fail, diagnostics) & delegates SBOM generation to sbom generator
   - Lazy analyzer instantiation → enables dependency injection during tests

-- **Check Registry** (`src/check-registry.ts`)
   - Central list of 28 compliance checks (ids 1–28) including Phase 7 additions: fallback timing policy (25), padding jitter variance (26), mix advanced variance (27), HTTP/3 adaptive emulation (28)
   - Evidence categories: heuristic, static-structural, dynamic-protocol (simulation / partial real), artifact
   - Multi-signal anti-evasion & keyword stuffing guard (Check 18)
5. Feature tagging: injects `betanet.feature` properties (transport-htx, transport-quic, transport-webrtc, crypto-pq-hybrid, payment-lightning, privacy-hop, etc.) across formats

## Performance & Diagnostics
- Single-pass memoized analysis (analyze() cached)
- Parallel evaluation of checks with per-check timeout & duration capture
- Diagnostics object: analyze invocation count, cache hit flag, tool availability, platform, missingCoreTools, degradationReasons
- Force refresh option (`--force-refresh`) to invalidate cache
- Environment gates: `BETANET_FAIL_ON_DEGRADED`, `BETANET_PQ_DATE_OVERRIDE` (UTC-safe), tool skip list
- Concise degraded summary printed when degraded=true
 - Unified external command timeout via `safeExec` (file, strings, ldd, nm, objdump, sha256sum) configurable with `BETANET_TOOL_TIMEOUT_MS` (ISSUE-034)
 - Planned: per-check inline degraded hints (ISSUE-035 partial)
 - Streaming fallback string extraction with 32MiB default cap (configurable via BETANET_FALLBACK_STRINGS_MAX_BYTES) replacing prior full-file read (ISSUE-038)
   - Each entry exposes `evaluate(analyzer, now)` returning a `ComplianceCheck`
   - Handles dynamic severity escalation (post-quantum critical date) & version acceptances (transport 1.0 / 1.1)

-- **Analyzer / Structural Augmentation** (`src/analyzer.ts`)
   - Extracts strings, symbols, dependencies (legacy heuristic base)
   - Populates schema v2 evidence: `binaryMeta`, `clientHelloTemplate`, `noisePatternDetail`, `negative`, mix variance metrics
   - Integrates `binary-introspect.ts` for format, sections, imports sample, debug marker
   - Provides static baseline for dynamic TLS calibration (Check 22)
   - Single-pass memoization; sets `schemaVersion=2`

-- **Dynamic Harness & Capture** (`src/harness.ts`)
   - Generates dynamic evidence: fallback timing distribution (mean/stddev/CV + median, p95, IQR, skew, outlier detection, anomaly codes, model score), dynamic ClientHello capture (heuristic JA3 & ja3Hash, rawClientHelloB64 placeholder → future JA4), QUIC Initial probe (rawInitialB64 placeholder with partial parsed fields), HTTP/2 and HTTP/3 adaptive jitter simulations, mix path sampling entropy & path length stddev
   - Outputs metrics consumed by Checks 22, 25, 26, 27, 28
   - Scaffolds raw TLS/QUIC capture ahead of schema v3 canonical JA3/JA4 & full QUIC Initial parse

### 2. CLI Interface

- **CLI Handler** (`bin/cli.js`)
  - Command-line argument parsing using Commander.js
  - Multiple commands: `check`, `sbom`, `validate`
  - Various output formats and options
  - Proper exit codes for automation

### 3. Compliance Checks

All 28 checks are declaratively defined (append-only). Multi-signal scoring aggregates category diversity post evaluation.

Abbreviated map (selected deltas beyond 1–14): 15 Governance Diversity (artifact), 16 Ledger Emergency Advance, 17 Diversity Sampling (dynamic), 18 Multi-Signal Anti-Evasion, 19 Noise Rekey Simulation (sim), 20 HTTP/2 Adaptive Jitter (sim), 21 Binary Structural Meta, 22 TLS Template Calibration (+ dynamic raw scaffold), 23 Negative Assertions, 24 Rate-Limit Buckets, 25 Fallback Timing & Distribution Policy, 26 Padding Jitter Variance, 27 Mix Advanced Variance (entropy + path length stddev), 28 HTTP/3 Adaptive Emulation.

### 4. SBOM Generation

Unified path via `sbom/sbom-generator.ts` providing:
1. Binary hashing (SHA-256)
2. Component & dependency extraction (best-effort via host tools: strings, ldd)
3. CycloneDX (serialized to XML) & SPDX tag-value outputs
4. Extensible structure for future license & dedupe heuristics (multi-license expression parsing implemented; CycloneDX lists each, SPDX joins with OR)

### 5. GitHub Action Template

- **Automated Checking** - Runs on push, PR, and schedule
- **Multi-Binary Support** - Finds and checks all executable binaries
- **Artifact Upload** - Stores compliance results and SBOMs
- **PR Comments** - Automatically comments on pull requests with results
- **Status Reporting** - Sets build status based on compliance

## Technical Implementation Details

### Binary Analysis Techniques

1. **String Extraction**
   - Uses `strings` command when available
   - Fallback to manual byte scanning for printable ASCII
   - Filters for minimum string length (4 characters)

2. **Symbol Analysis**
   - Uses `nm` command for dynamic symbols
   - Falls back to `objdump` for static symbols
   - Focuses on `.text` section symbols

3. **Dependency Detection**
   - Uses `ldd` to find shared library dependencies
   - Extracts version information from library paths
   - Filters out system libraries and "not found" entries

4. **Pattern Matching**
   - Case-insensitive string matching for compliance indicators
   - Symbol table analysis for function names
   - Network protocol detection via string patterns

### Compliance Detection Logic

Each compliance check uses a combination of:

- **String Analysis** - Looking for specific keywords and patterns
- **Symbol Analysis** - Checking for relevant function names
- **Dependency Analysis** - Identifying required libraries
- **Feature Detection** - Inferring capabilities from binary content

### Error Handling

- **Graceful Degradation** - When system tools are missing
- **Fallback Methods** - Alternative approaches for each analysis type
- **Verbose Logging** - Detailed output for debugging
- **Clear Error Messages** - User-friendly error reporting

### Output Formats

1. **Table Format** - Human-readable with color coding
2. **JSON Format** - Machine-readable for automation
3. **YAML Format** - Alternative machine-readable format
4. **SBOM Formats** - CycloneDX (XML) and SPDX (text)

## Testing Strategy

- **Unit Tests** - Individual method testing
- **Integration Tests** - End-to-end compliance checking
- **Mock Dependencies** - Isolated testing of analysis methods
- **Output Validation** - Verification of all output formats

## Extensibility

- **New Check**: Add object to `CHECK_REGISTRY`.
- **Heuristics**: Extend or refine functions in `heuristics.ts` used by evaluate functions.
- **Analyzer Capability**: Add new analyzer helper returning structured detection facts.
- **Reporting**: Extend `displayResults` for new output formats (e.g., markdown/HTML).
- **SBOM**: Add exporters in sbom module and route through checker.

## Performance & Diagnostics

- Single-pass memoized structural analysis + on-demand harness runs
- Per-check timing & aggregate parallel duration
- Degradation tracking (missing tools, fallbacks) influences strict mode exit conditions
- Multi-signal scoring (artifact=3, dynamic=2, static=1, heuristic=0) + stuffing density guard
- Future (schema v3): canonical raw TLS/QUIC JA3/JA4, QUIC Initial full parse, signed evidence bundle