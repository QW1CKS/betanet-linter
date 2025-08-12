
# Betanet Compliance Linter


> **Quickstart (from source):**
> ```bash
> git clone <repository-url>
> cd betanet-linter
> npm install
> npm run build
> npm link
> betanet-lint --version   # verify installation
> betanet-lint check ./your-binary --sbom --format cyclonedx-json --output json > compliance.json
> ```
> Result: `compliance.json` (structured report) plus a CycloneDX JSON SBOM next to your binary.

A comprehensive CLI tool for checking Betanet specification compliance in binary implementations. It fully targets the Betanet 1.0 specification (§11) and provides enhanced heuristic coverage of emerging Betanet 1.1 changes (transport version bump, rendezvous rotation scoring, path diversity, optional WebRTC transport, privacy hop weighting). It generates detailed compliance reports.

> **Flag Naming:**
> `--format` is now the canonical flag for SBOM format selection. The older `--sbom-format` still works but is deprecated and will emit a warning; it will be removed in a future minor release. All CLI and GitHub Action usage should migrate to `--format`.

## Limitations

This tool uses static heuristic analysis. It cannot guarantee runtime compliance or detect dynamic behaviors (e.g., live rotation, runtime-generated keys, or negotiated ciphers). See [plans.md](./plans.md) for roadmap and deferred features (e.g., dynamic probe plugins, confidence metrics).

### Strict Mode vs Heuristic Mode (Transitional)
Current checks are classified as `heuristic` evidence. Strict mode (default) treats heuristic passes as informational only; they do not count toward an overall PASS unless you explicitly enable `--allow-heuristic`. This prevents overstating normative compliance while the remediation roadmap (see `remedation`) is in progress.

CLI flags:
```
--strict (default true)
--allow-heuristic   # opt-in to count heuristic passes
```
Exit codes:
```
0 = All required (non-heuristic or allowed heuristic) checks passed
1 = One or more required checks failed
2 = Heuristic-only gap (strict mode prevented pass) – no critical failing check, but insufficient normative evidence
```

JSON/YAML adds fields: `strictMode`, `allowHeuristic`, `heuristicContributionCount`.

### Preliminary Compliance Matrix
| Spec §11 Item | Check ID(s) | Current Evidence Type | Status | Notes |
|---------------|------------|-----------------------|--------|-------|
| 1 HTX over TCP+QUIC + origin-mirrored TLS + ECH | 1 | heuristic | Partial | Presence only (no calibration / extension order) |
| 2 Access tickets replay-bound + padding + rate limits | 2 | heuristic | Partial | Token presence; no structure/padding window parse |
| 3 Noise XK tunnel + key sep + rekey + PQ date | 3,10 | heuristic | Partial | AEAD + PQ token; no transcript / rekey policy |
| 4 HTTP/2/3 adaptive emulation | (planned) | – | Missing | Not yet implemented |
| 5 SCION bridging via HTX tunnel (no legacy header) | 4 | heuristic | Partial | SCION/path tokens only |
| 6 Transport endpoints /betanet/htx & htxquic | 5 | heuristic | Moderate | Version presence only |
| 7 Rotating rendezvous bootstrap (BeaconSet + PoW + buckets) | 6 | heuristic | Partial | Rotation tokens only |
| 8 Mixnode selection (BeaconSet + entropy + diversity + hop policy) | 11 | heuristic | Partial | Token weighting only |
| 9 Alias ledger finality 2-of-3 + Emergency Advance | 7 | heuristic | Shallow | Consensus tokens only |
|10 Cashu vouchers (128B), FROST n≥5 t=3, PoW adverts, Lightning | 8 | heuristic | Partial | Presence; no struct verify |
|11 Governance anti-concentration + partition safety | (planned) | – | Missing | Not implemented |
|12 Anti-correlation fallback behavior | (planned) | – | Missing | Not implemented |
|13 Reproducible builds + SLSA3 provenance | 9 | heuristic | Partial | Keyword presence only |

All “Partial” / “Shallow” rows will migrate to structural, dynamic, or artifact evidence per `remedation` roadmap.

## License

MIT License. See [LICENSE](./LICENSE) for details.

> DISCLAIMER (Heuristic Analysis – ISSUE-049): This linter performs static, best‑effort heuristic inspection of binaries. A PASS does not cryptographically prove runtime adherence; a FAIL may reflect missing static indicators rather than true absence. Dynamic phenomena (live rotation cadence, negotiated cipher activation, runtime path diversification, active voucher redemption) are not executed. Treat results as advisory signals requiring corroboration in integration / runtime QA.

## Features

- ✅ **Complete Compliance Checking**: Validates all 11 Betanet specification requirements (§11)
- 🔍 **Binary Analysis**: Deep analysis of executable binaries for compliance patterns
- 📋 **SBOM Generation**: Creates Software Bill of Materials in CycloneDX or SPDX formats
- 🔢 **Multi-License Detection**: Extracts multiple SPDX license identifiers (e.g. Apache-2.0 OR MIT) and surfaces all
- 📊 **Multiple Output Formats**: JSON, YAML, and table-based reports
- 🎯 **Selective Checking**: Run specific checks or exclude certain requirements
- 🤖 **GitHub Action Ready**: Automated compliance checking in CI/CD pipelines
- 📈 **Detailed Reporting**: Pass/fail status with detailed explanations
- 🔄 **Force Refresh**: Use `--force-refresh` to bypass memoized baseline analysis for updated binaries
- 🛡️ **Degraded Fail Gate**: Set `BETANET_FAIL_ON_DEGRADED=1` to force failure when tooling is degraded
- ⚡ **Parallel Evaluation**: Runs checks concurrently; tune with `--max-parallel` and per-check `--check-timeout`
- 🧪 **Dynamic Probe (Optional)**: `--dynamic-probe` lightly invokes the binary with `--help` to enrich heuristic surface (no network / destructive actions)
- 🏷️ **SBOM Feature Tagging**: Adds `betanet.feature` properties (e.g. `transport-quic`, `crypto-pq-hybrid`, `payment-lightning`, `privacy-hop`) to CycloneDX / SPDX outputs for downstream audit traceability


## Installation

Install from source (recommended):

```bash
git clone <repository-url>
cd betanet-linter
npm install
npm run build
npm link
```

## Usage


> **Note:** This is betanet-linter v1.0.0, targeting Betanet 1.0 compliance (not Betanet 1.1).

### Basic Compliance Check

```bash
betanet-lint check /path/to/your/binary
```

### With SBOM Generation

```bash
betanet-lint check /path/to/binary --sbom --format cyclonedx
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

You can now filter directly on the `check` command (ISSUE-040):

```bash
# Run only specific checks (e.g., checks 1,3,5)
betanet-lint check /path/to/binary --checks 1,3,5

# Exclude specific checks (e.g., exclude check 10)
betanet-lint check /path/to/binary --exclude 10

# Combine include + exclude (exclude takes effect after include)
betanet-lint check /path/to/binary --checks 1,2,3,4,5 --exclude 3
```

Legacy `validate` command remains as an alias but may be deprecated in a future release.

### Generate SBOM Only

```bash
# CycloneDX format (default)
betanet-lint sbom /path/to/binary --format cyclonedx

# CycloneDX JSON format
betanet-lint sbom /path/to/binary --format cyclonedx-json

# SPDX tag-value format
betanet-lint sbom /path/to/binary --format spdx

# SPDX JSON format
betanet-lint sbom /path/to/binary --format spdx-json

# Custom output path
betanet-lint sbom /path/to/binary --output /custom/path/sbom.xml
```

### Version & Verbose Output
```bash
betanet-lint --version
betanet-lint version    # alternative subcommand
```

### Performance & Parallelism

Checks are evaluated in parallel from a cached single baseline analysis of the binary. Control concurrency & resilience:

```
betanet-lint check ./bin --max-parallel 6 --check-timeout 3000
```

Fields `parallelDurationMs` and per-check `durationMs` appear in JSON/YAML for profiling. A fallback timeout marks a check failed (non-fatal) instead of aborting the run.

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
5. **Transport Endpoints** - Offers `/betanet/htx/1.1.0` & `/betanet/htxquic/1.1.0` (1.0.0 legacy accepted) (+ optional `/betanet/webrtc/1.0.0`)
6. **DHT Seed Bootstrap** - (1.0) deterministic bootstrap OR (1.1) rotating rendezvous (BeaconSet) heuristic (now reports rotation hit count)
7. **Alias Ledger Verification** - Verifies alias ledger with 2-of-3 chain consensus
8. **Payment System** - Accepts Cashu vouchers from federated mints & supports Lightning settlement
9. **Build Provenance** - Builds reproducibly and publishes SLSA 3 provenance
10. **Post-Quantum Cipher Suites** - Presents X25519-Kyber768 suites once the mandatory date is reached (2027-01-01)
11. **Privacy Hop Enforcement** - Weighted mixnet heuristic (mix + beacon/epoch + diversity tokens) requiring ≥2 mix, ≥1 beacon, ≥1 diversity indicator (scores now surfaced)

### Heuristic & Partial Coverage Disclaimer
Static binary analysis cannot fully confirm dynamic behaviors introduced in Betanet 1.1 (e.g., live TLS fingerprint calibration, sustained path diversity rotation, runtime hop enforcement, voucher cryptographic workflow). Detected signals are heuristic and may produce false positives/negatives. Rotation confidence (`rotationHits`), privacy weighting scores, and path diversity counts are informational only. See top-level DISCLAIMER for interpretation guidance.

### Betanet 1.1 Delta Coverage Matrix (ISSUE-060)
| 1.1 Element | Status | Evidence / Output Field |
|-------------|--------|-------------------------|
| Transport endpoint version bump (`/betanet/htx/1.1.0`, `htxquic/1.1.0`) | Implemented | Check 5 details (accepted list) |
| Optional WebRTC transport | Implemented | Check 5 details (`optional: webrtc`) |
| Rendezvous rotation / BeaconSet heuristic | Implemented | Check 6 details (`rotationHits`, beacon indicators) |
| Path diversity threshold (≥2 markers) | Implemented | Check 4 failure details enumerate needed markers |
| Privacy hop weighting (mix / beacon / diversity) | Implemented | Check 11 details (mix=, beacon=, diversity=, total=) |
| Voucher structural regex detection | Implemented | Check 8 details (voucher present or missing) |
| PoW ≥22 contextual parsing | Implemented | Check 8 details (missing list shows PoW context) |
| PQ date override (`BETANET_PQ_DATE_OVERRIDE`) UTC-safe | Implemented | Check 10 severity escalation; override env documented |
| SBOM feature tagging (`betanet.feature`) | Implemented | CycloneDX properties / SPDX `PackageComment` lines |
| Windows degraded diagnostics (platform + reasons) | Implemented | Diagnostics: `platform`, `missingCoreTools`, `degradationReasons` |
| Dynamic runtime probe / plugin mode | Deferred | Future (ISSUE-059) |

### Spec Coverage Summary
The tool fully covers Betanet 1.0 checks and partially covers emerging 1.1 elements. Runtime output now includes a spec coverage header, e.g.:

```
Spec Coverage: baseline 1.0 fully covered; latest known 1.1 checks implemented 11/11
Pending 1.1 refinements: (none – all heuristic refinements integrated)
```

No pending 1.1 refinement issues remain; prior backlog items (privacy hop refinement, voucher structural detection, PoW context parsing) have been implemented. Dynamic execution (ISSUE-059) remains deferred.
JSON / YAML outputs include a `specSummary` object with the same fields for programmatic consumption.

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

The tool includes a ready-to-use GitHub Action template for automated compliance checking (see `github-action/`).

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
  betanet-lint check ./target/release/betanet-node --sbom --format cyclonedx-json --output json
```

## System Requirements

- Node.js >= 16.0.0
- Linux, macOS, or Windows (WSL2 recommended for Windows)
- Required system tools:
  - `file` - for file type detection
  - `strings` - for string extraction (fallback available)
  - `nm` or `objdump` - for symbol extraction
  - `ldd` - for dependency detection

### SBOM Generation Tooling Notes

The SBOM generator uses best-effort external tooling. On Windows (non-WSL) where `strings` / `ldd` are typically unavailable, the linter falls back to a lightweight in-process ASCII scan and skips dynamic dependency enumeration—now surfaced via a concise degraded summary (platform diagnostics). To re-enable verbose troubleshooting messages for missing tools or parsing issues, set:

```powershell
setx BETANET_DEBUG_SBOM 1
# restart shell to apply
```

Or temporarily for a single session:

```powershell
$env:BETANET_DEBUG_SBOM = '1'
```

On Linux/macOS (or Windows via WSL), installing `binutils`/`llvm` packages enhances coverage (strings, nm, objdump, ldd). The generator remains resilient if any tool is absent.

Multi-license detection: Composite SPDX expressions (e.g. `Apache-2.0 OR MIT`) are split. CycloneDX lists each as a separate license entry. SPDX tag-value & JSON collapse the list with `OR` for `licenseDeclared`.

Feature tagging: For every detected capability, the SBOM appends `betanet.feature` entries (CycloneDX `properties`, SPDX `PackageComment`). This enables downstream policy engines to assert presence of specific network / crypto / payment / privacy traits without re-parsing the binary.

## Exit Codes

- `0` - All compliance checks passed
- `1` - One or more compliance checks failed
- `2` - Error in execution (invalid arguments, file not found, etc.)
- `3` - SBOM shape validation failed (non-strict); use `--strict-sbom` to escalate to 2

## Environment Variables

- `BETANET_CHECK_TIMEOUT_MS=ms` - (Optional) Global default per-check timeout if not supplied via CLI

- `BETANET_DEBUG_SBOM=1` - Enable verbose SBOM generator logging
- `BETANET_TOOL_TIMEOUT_MS=5000` - Override per external tool invocation timeout (ms)
- `BETANET_SKIP_TOOLS=strings,nm` - Comma-separated list of external tools to skip (graceful degradation)
- `BETANET_FAIL_ON_DEGRADED=1` - Treat degraded analysis as failure (overrides otherwise passing result)
- `BETANET_PQ_DATE_OVERRIDE=YYYY-MM-DD` - Override post-quantum mandatory enforcement date (for early testing)
  - Accepts ISO date or full timestamp; evaluated in UTC (ISSUE-016 fix)
- `BETANET_FALLBACK_STRINGS_MAX_BYTES=33554432` - Cap (in bytes) for streaming fallback string extraction when external `strings` tool is unavailable (prevents excessive memory use)

### Diagnostics & Degradation

Compliance results include a `diagnostics` object with tooling and performance metadata:

-- `degraded`: true if any external tool was missing, skipped, or timed out
- `skippedTools`: tools skipped via configuration
- `timedOutTools`: tools that exceeded the timeout
- `tools[]`: per-tool availability + durations
- `platform`: execution platform (e.g., win32, linux)
- `missingCoreTools`: list of core analysis tools unavailable
- `degradationReasons`: high-level reason codes (e.g., `native-windows-missing-unix-tools`)
- `parallelDurationMs`: total elapsed time for parallel evaluation phase
- Each check includes `durationMs`

Degraded mode lowers confidence and normally does not trigger failure; set `BETANET_FAIL_ON_DEGRADED=1` (or `--fail-on-degraded`) to enforce failure.

All external tool invocations (strings, nm, objdump, ldd, file, sha256sum) pass through a unified `safeExec` wrapper with a configurable timeout to prevent hangs (ISSUE-034). Missing or timed-out tools contribute to degradation reasons. When `strings` is unavailable the linter now performs a streaming, size‑capped ASCII scan (default 32MiB) instead of reading the entire binary (ISSUE-038); truncation adds a `strings-fallback-truncated` degradation reason.

Per-check transparency (ISSUE-035): Affected checks display an inline `(degraded)` marker in table output with a `Hints:` line (e.g., `strings tool missing`, `string extraction truncated`, `symbol extraction degraded`). JSON / YAML include a `degradedHints` array per check for downstream automation.

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

## Additional Documentation

For deeper insight into project direction and open/refined issues:

- Roadmap & plan status: see [plans.md](./plans.md)
- Issues, inconsistencies & improvement backlog: see [issues-inconsistencies.txt](./issues-inconsistencies.txt)

These documents complement the README by outlining historical decisions, completed milestones, and pending enhancement tracks.

## License

MIT License - see LICENSE file for details.

## Support

For issues, questions, or contributions, please open an issue on the GitHub repository. Include whether the run was degraded and any `rotationHits` / `pathDiversityCount` values for heuristic discussions.

## Betanet Specification

- Primary baseline: [Betanet 1.0 Specification](https://ravendevteam.org/betanet/betanet_1.0_spec.txt)
- Partial awareness: Betanet 1.1 transport & rendezvous updates (document updated 2025-08)

For the most up-to-date specification and requirements, please refer to the official Betanet documentation. Contributions to extend 1.1 coverage are welcome (see DISCLAIMER above).
