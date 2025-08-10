# Betanet Compliance Linter - Project Structure

```
betanet-linter/
├── src/
│   ├── index.ts              # Main compliance checker class
│   ├── analyzer.ts           # Binary analysis functionality
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

### 1. Core Classes

- **BetanetComplianceChecker** (`src/index.ts`)
  - Main class that orchestrates compliance checking
  - Implements all 10 compliance checks from Betanet spec §11
  - Handles result generation and display
  - Manages SBOM generation

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

Each of the 10 checks is implemented as a separate method in `BetanetComplianceChecker`:

1. **HTX Implementation** - Checks for TLS, QUIC, HTX, ECH, and port 443 support
2. **Access Tickets** - Detects ticket rotation mechanisms
3. **Frame Encryption** - Validates ChaCha20-Poly1305 support
4. **SCION Paths** - Checks for SCION support or IP-transition headers
5. **Transport Endpoints** - Looks for specific Betanet endpoint paths
6. **DHT Bootstrap** - Validates deterministic DHT implementation
7. **Alias Ledger** - Checks for consensus-based ledger verification
8. **Payment System** - Detects Cashu and Lightning support
9. **Build Provenance** - Validates SLSA and reproducible build support
10. **Post-Quantum** - Checks for X25519-Kyber768 (mandatory after 2027-01-01)

### 4. SBOM Generation

- **CycloneDX Format** - Industry-standard XML format
- **SPDX Format** - Alternative text-based format
- **Component Detection** - Automatically detects dependencies and libraries
- **Customizable Output** - Configurable output paths and formats

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

The architecture is designed to be easily extensible:

- **New Compliance Checks** - Add methods to `BetanetComplianceChecker`
- **New Analysis Techniques** - Extend `BinaryAnalyzer`
- **New Output Formats** - Add display methods
- **New SBOM Formats** - Extend SBOM generation methods

## Performance Considerations

- **Parallel Analysis** - Multiple analysis operations run concurrently
- **Caching** - Results cached where appropriate
- **Efficient String Processing** - Optimized pattern matching
- **Memory Management** - Proper cleanup of temporary files and resources