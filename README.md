# Betanet Compliance Linter

A comprehensive CLI tool for checking Betanet specification compliance in binary implementations. It fully targets the Betanet 1.0 specification (§11) and provides partial heuristic coverage of newly published Betanet 1.1 changes (transport version bump, rendezvous DHT, optional WebRTC transport). It generates detailed compliance reports.

## Features

- ✅ **Complete Compliance Checking**: Validates all 10 Betanet specification requirements
- 🔍 **Binary Analysis**: Deep analysis of executable binaries for compliance patterns
- 📋 **SBOM Generation**: Creates Software Bill of Materials in CycloneDX or SPDX formats
- 📊 **Multiple Output Formats**: JSON, YAML, and table-based reports
- 🎯 **Selective Checking**: Run specific checks or exclude certain requirements
- 🤖 **GitHub Action Ready**: Automated compliance checking in CI/CD pipelines
- 📈 **Detailed Reporting**: Pass/fail status with detailed explanations

## Installation

### Global Installation

```bash
npm install -g betanet-compliance-linter
```

### Local Installation

```bash
npm install betanet-compliance-linter
```

### From Source

```bash
git clone <repository-url>
cd betanet-linter
npm install
npm run build
npm link
```

## Usage

### Basic Compliance Check

```bash
betanet-lint check /path/to/your/binary
```

### With SBOM Generation

```bash
betanet-lint check /path/to/binary --sbom
```

### Different Output Formats

```bash
# JSON output
betanet-lint check /path/to/binary --output json

# YAML output
betanet-lint check /path/to/binary --output yaml

# Table output (default)
betanet-lint check /path/to/binary --output table
```

### Selective Checking

```bash
# Run only specific checks (e.g., checks 1, 3, 5)
betanet-lint validate /path/to/binary --checks 1,3,5

# Exclude specific checks (e.g., exclude check 10)
betanet-lint validate /path/to/binary --exclude 10
```

### Generate SBOM Only

```bash
# CycloneDX format (default)
betanet-lint sbom /path/to/binary --format cyclonedx

# SPDX format
betanet-lint sbom /path/to/binary --format spdx

# Custom output path
betanet-lint sbom /path/to/binary --output /custom/path/sbom.xml
```

### Verbose Output

```bash
betanet-lint check /path/to/binary --verbose
```

## Compliance Checks

The tool validates 11 core requirements from Betanet specification §11 (1.0 baseline + one privacy-layer heuristic for 1.1). For Betanet 1.1 it additionally accepts updated transport endpoint versions (`/betanet/htx/1.1.0`, `/betanet/htxquic/1.1.0`) while still recognizing legacy 1.0.0 paths and will optionally note presence of `/betanet/webrtc/1.0.0`.

Architecture note: All checks are defined declaratively in a central registry (`check-registry.ts`). Adding a new requirement means appending one object with an `evaluate()` function—no orchestration refactor. Severities, names, and version gating live alongside evaluation logic for consistency.

1. **HTX over TCP-443 & QUIC-443** - Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH
2. **Rotating Access Tickets** - Uses rotating access tickets (§5.2)
3. **Inner Frame Encryption** - Encrypts inner frames with ChaCha20-Poly1305, 24-bit length, 96-bit nonce
4. **SCION Path Management** - Maintains ≥ 3 signed SCION paths or attaches a valid IP-transition header
5. **Transport Endpoints** - Offers `/betanet/htx/1.1.0` & `/betanet/htxquic/1.1.0` (1.0.0 legacy accepted)
6. **DHT Seed Bootstrap** - (1.0) deterministic bootstrap OR (1.1) rotating rendezvous (BeaconSet) heuristic
7. **Alias Ledger Verification** - Verifies alias ledger with 2-of-3 chain consensus
8. **Payment System** - Accepts Cashu vouchers from federated mints & supports Lightning settlement
9. **Build Provenance** - Builds reproducibly and publishes SLSA 3 provenance
10. **Post-Quantum Cipher Suites** - Presents X25519-Kyber768 suites once the mandatory date is reached (2027-01-01)
11. **Privacy Hop Enforcement** - Enforces ≥2 (balanced) or ≥3 (strict) mixnet hops with BeaconSet-based diversity (heuristic)

### Heuristic & Partial Coverage Disclaimer
Static binary analysis cannot fully confirm dynamic behaviors introduced in Betanet 1.1 (e.g., TLS fingerprint calibration, path diversity maintenance, voucher cryptographic workflow). Detected signals are heuristic and may produce false positives/negatives. Advanced 1.1 checks (outer TLS calibration, rendezvous beacon rotation, full access ticket protocol validation) are roadmap items.

## Output Examples

### Table Output

```
============================================================
🎯 BETANET COMPLIANCE REPORT
============================================================
Binary: /usr/local/bin/betanet-node
Timestamp: 2024-01-15T10:30:45.123Z
Overall Score: 80%
Status: ❌ FAILED
--------------------------------------------------------
COMPLIANCE CHECKS:
────────────────────────────────────────────────────────
✅ 🔴 [1] HTX over TCP-443 & QUIC-443
   Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH
   ✅ Found HTX, QUIC, TLS, ECH, and port 443 support

❌ 🟡 [2] Rotating Access Tickets
   Uses rotating access tickets (§5.2)
   ❌ Missing: ticket rotation

✅ 🔴 [3] Inner Frame Encryption
   Encrypts inner frames with ChaCha20-Poly1305, 24-bit length, 96-bit nonce
   ✅ Found ChaCha20-Poly1305 support

────────────────────────────────────────────────────────
SUMMARY:
Total Checks: 10
Passed: 8
Failed: 2
Critical Failures: 0
────────────────────────────────────────────────────────
```

### JSON Output

```json
{
  "binaryPath": "/usr/local/bin/betanet-node",
  "timestamp": "2024-01-15T10:30:45.123Z",
  "overallScore": 80,
  "passed": false,
  "checks": [
    {
      "id": 1,
      "name": "HTX over TCP-443 & QUIC-443",
      "description": "Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH",
      "passed": true,
      "details": "✅ Found HTX, QUIC, TLS, ECH, and port 443 support",
      "severity": "critical"
    }
  ],
  "summary": {
    "total": 10,
    "passed": 8,
    "failed": 2,
    "critical": 0
  }
}
```

## GitHub Action Integration

The tool includes a ready-to-use GitHub Action template for automated compliance checking:

```yaml
name: Betanet Compliance Check

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  betanet-compliance:
    runs-on: ubuntu-latest
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
      
    - name: Set up Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        
    - name: Install Betanet Compliance Linter
      run: |
        npm install -g betanet-compliance-linter
        
    - name: Run Compliance Checks
      run: |
        betanet-lint check ./target/release/betanet-node --sbom --output json
```

## System Requirements

- Node.js >= 16.0.0
- Linux, macOS, or Windows (WSL2 recommended for Windows)
- Required system tools:
  - `file` - for file type detection
  - `strings` - for string extraction (fallback available)
  - `nm` or `objdump` - for symbol extraction
  - `ldd` - for dependency detection

## Exit Codes

- `0` - All compliance checks passed
- `1` - One or more compliance checks failed
- `2` - Error in execution (invalid arguments, file not found, etc.)

## Development

### Building from Source

```bash
git clone <repository-url>
cd betanet-linter
npm install
npm run build
```

### Running Tests

```bash
npm test
```

### Linting

```bash
npm run lint
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository.

## Betanet Specification

- Primary baseline: [Betanet 1.0 Specification](https://ravendevteam.org/betanet/betanet_1.0_spec.txt)
- Partial awareness: Betanet 1.1 transport & rendezvous updates (document updated 2025-08)

For the most up-to-date specification and requirements, please refer to the official Betanet documentation. Contributions to extend 1.1 coverage are welcome (see DISCLAIMER above).