# Betanet Compliance Linter - Project Structure

```
betanet-linter/
├── src/
│   ├── index.ts              # Orchestrator: registry-driven compliance + basic SBOM
│   ├── check-registry.ts     # Declarative check metadata + evaluate() functions
│   ├── analyzer.ts           # Binary analysis (memoized)
│   ├── heuristics.ts         # Heuristic pattern detection (Plan 2)
│   ├── constants.ts          # Spec/version constants (Betanet 1.0 + partial 1.1)
│   ├── sbom/                 # Advanced SBOM generator (consolidation target)
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
   - Partial Betanet 1.1 heuristics (transport versions, rendezvous indicators, payment extensions)
   - Aggregates results (score, pass/fail, diagnostics) & provides basic SBOM output (temporary)
   - Lazy analyzer instantiation → enables dependency injection during tests

- **Check Registry** (`src/check-registry.ts`)
   - Central list of 10 compliance checks (id, key, name, description, severity, version metadata)
   - Each entry exposes `evaluate(analyzer, now)` returning a `ComplianceCheck`
   - Handles dynamic severity escalation (post-quantum critical date) & version acceptances (transport 1.0 / 1.1)

- **BinaryAnalyzer** (`src/analyzer.ts`)
  - Performs deep binary analysis
  - Extracts strings, symbols, and dependencies
  - Detects network capabilities, cryptographic features, and other compliance indicators
  - Provides fallback methods when system tools are unavailable

### 2. CLI Interface

- **CLI Handler** (`bin/cli.js`)
  - Command-line argument parsing using Commander.js
  - Multiple commands: `check`, `sbom`, `validate`
  - Various output formats and options
  - Proper exit codes for automation

### 3. Compliance Checks

All checks are declaratively defined in the registry (data + evaluate function). Orchestrator iterates filtered subset (include/exclude). This allows adding a new check by appending one object—no orchestration changes.

1. **HTX Implementation** - Checks for TLS, QUIC, HTX, ECH, and port 443 support
2. **Access Tickets** - Detects ticket rotation mechanisms
3. **Frame Encryption** - Validates ChaCha20-Poly1305 support
4. **SCION Paths** - Checks for SCION support or IP-transition headers
5. **Transport Endpoints** - Detects `/betanet/htx/{1.1.0|1.0.0}`, `/betanet/htxquic/{1.1.0|1.0.0}`, optional `/betanet/webrtc/1.0.0`
6. **DHT Bootstrap** - (1.0 heuristic) deterministic bootstrap; rendezvous rotation (1.1) partial
7. **Alias Ledger** - Checks for consensus-based ledger verification
8. **Payment System** - Detects Cashu and Lightning support
9. **Build Provenance** - Validates SLSA and reproducible build support
10. **Post-Quantum** - Checks for X25519-Kyber768 (mandatory after 2027-01-01)

### 4. SBOM Generation

Transition state:
1. Inline minimal SBOM (index.ts) – simple CycloneDX XML + basic SPDX tag-value.
2. Advanced generator (`sbom/sbom-generator.ts`) – hashing, richer component & dependency extraction, JSON-ready structures.

Plan 4 will migrate fully to the advanced generator, adding license & sanitization enhancements.

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
- Diagnostics object: analyze invocation count, cache hit flag, tool availability
- Future: per-check timings, command timeouts, force refresh option