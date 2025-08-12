# Betanet Compliance Linter - Project Structure

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
   - Central list of 23 compliance checks (ids 1–23) (id, key, name, description, severity, version metadata, evidenceType)
   - Evidence categories: heuristic, static-structural, dynamic-protocol (sim/sample), artifact
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

- **Analyzer / Structural Augmentation** (`src/analyzer.ts`)
   - Extracts strings, symbols, dependencies (legacy heuristic base)
   - Populates schema v2 evidence: `binaryMeta`, `clientHelloTemplate`, `noisePatternDetail`, `negative`
   - Integrates `binary-introspect.ts` for format, section list sample, imports sample, debug marker
   - Injects simulated dynamic evidence (`noiseRekeySim`, `h2Adaptive`) pending real capture
   - Counts Noise HKDF/message tokens for strengthened Check 13
   - Single-pass memoization; sets `schemaVersion=2`

### 2. CLI Interface

- **CLI Handler** (`bin/cli.js`)
  - Command-line argument parsing using Commander.js
  - Multiple commands: `check`, `sbom`, `validate`
  - Various output formats and options
  - Proper exit codes for automation

### 3. Compliance Checks

All 23 checks are declaratively defined. Append-only registration keeps orchestrator stable; multi-signal scoring consumes evidence categories post evaluation.

Abbreviated check map (1–23): Transport Presence, Access Tickets, Frame Encryption, SCION / legacy header absence, Transport Endpoints, DHT Bootstrap & rotation, Alias Ledger, Payment System, Build Provenance, Post-Quantum, Privacy Hop Enforcement, TLS ClientHello Template, Noise Pattern (enhanced), Payment Struct Detail, Governance Anti-Concentration, Ledger Emergency Advance, Diversity Sampling, Multi-Signal Anti-Evasion, Noise Rekey Simulation, HTTP/2 Adaptive Jitter Simulation, Binary Structural Meta, TLS Template Calibration Scaffold, Negative Assertions.

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

- Single-pass memoized analysis (analyze() cached)
- Diagnostics: invocation count, cache hit, tool availability, degradation reasons
- Per-check timing captured; multi-signal scoring aggregated (artifact=3, dynamic=2, static=1, heuristic=0)
- Environment gates: `BETANET_FAIL_ON_DEGRADED`, `BETANET_PQ_DATE_OVERRIDE`
- Future: real dynamic handshake capture, HTTP/3 adaptive metrics, signed evidence bundle