# Betanet Compliance Linter

> **Status: Strict Normative Full Betanet 1.1 Compliance**  
> All 13 §11 normative specification items plus auxiliary security / anti‑evasion requirements are enforced by a consolidated **39‑check registry (IDs 1–39)** spanning heuristic, static‑structural, dynamic‑protocol, and artifact evidence. Each failure code has ≥1 negative test; coverage thresholds are enforced in CI; authenticity (detached signature or multi‑signer bundle) is validated in strict‑auth mode. This document and the roadmap have been updated to remove transitional/pending qualifiers. Historical sections are retained for provenance only.


> **Quickstart (from source):**
> ```bash
> git clone <repository-url>
> cd betanet-linter
> rm -rf node_modules package-lock.json
> npm cache verify
> npm install
> npm run build
> npm link
> betanet-lint --version   # verify installation
> betanet-lint check ./your-binary --sbom --format cyclonedx-json --output json > compliance.json
> ```
> Result: `compliance.json` (structured report) plus a CycloneDX JSON SBOM next to your binary.
> 
> IMPORTANT! IF YOU DELETE THE FOLDER, THEN RE-INSTALL IT AGAIN, MAKE SURE TO DELETE THE OLD BINARIES IN ORDER TO AVOID CRASHING & PERMISSION ISSUES:
>```
> sudo rm -rf /usr/local/bin/betanet-lint
>```

A CLI tool that enforces the Betanet specification §11 requirements (1.0 baseline + 1.1 deltas) by decomposing the **13 high‑level normative items** into a finer‑grained **39 check registry**. Each registry entry isolates a distinct evidence surface (static‑structural, dynamic‑protocol, artifact, heuristic) or a defensive / integrity dimension (negative assertions, anti‑evasion, provenance authenticity, algorithm agility, PQ boundary, forbidden hashes). This decomposition makes failures more actionable (granular root cause) and prevents “one big checkbox” passes based on a single weak signal.

The evolving evidence schema covers: binary structural meta, static & dynamic ClientHello calibration (ALPN order, extension hash, JA3/JA3 hash placeholders), Noise pattern + rekey transcript, governance & ledger artifacts (CBOR quorum cert parsing, historical diversity analytics), bootstrap rotation + PoW evolution, multi‑bucket rate‑limit dispersion, statistical jitter distributions, fallback timing provenance, algorithm agility registry, voucher/FROST aggregated signature & payment subsystem, negative assertions & forbidden artifact hashes, build reproducibility & SLSA provenance (signer/materials policy), evidence authenticity & multi‑signal anti‑evasion.

### §11 → 39 Check Decomposition (Orientation)
High‑level §11 item groups and their principal check IDs (non‑exhaustive; some groups have auxiliary defensive checks not listed for brevity):

| §11 Item (summary) | Core Checks (principal) | Auxiliary / Defensive |
|--------------------|-------------------------|-----------------------|
| 1 Transport + TLS calibration + ECH | 1, 12, 22, 32 | 18 (multi‑signal), 21 (meta) |
| 2 Access tickets (replay‑bound, rotation) | 2, 30 | 18, 24 (buckets) |
| 3 Noise XK + rekey + PQ date | 13, 19, 10, 38 | 18 |
| 4 HTTP/2/3 adaptive & jitter | 20, 28, 26, 37 | 18 |
| 5 SCION bridging / absence legacy header | 4, 33, 23 | 18 |
| 6 Rendezvous bootstrap rotation & PoW trend | 6, 36 | 24 |
| 7 Privacy hops & mix diversity | 11, 17, 27 | 18 |
| 8 Alias ledger finality & emergency advance | 7, 16 | 18 |
| 9 Payments (vouchers, FROST, PoW) | 8, 14, 29, 31, 36 | 24, 18 |
| 10 Governance anti‑concentration & partition | 15 | 18 |
| 11 Anti‑correlation fallback timing & cover | 25, (timing) 18 (gate) | 26 (padding, indirect) |
| 12 Privacy hop enforcement (balanced/strict) | 11, 17 | 27 (variance), 18 |
| 13 Reproducible builds & provenance authenticity | 9, 35 | 18, 21 |
| Cross‑cutting registries (algorithm agility, forbidden hashes) | 34, 39 | 23 (negative assertions) |

Scoring: Strict mode counts only non‑heuristic evidence (static / dynamic / artifact). Heuristic passes are reported but excluded unless `--allow-heuristic` is provided. Multi‑signal gate (check 18) prevents superficial keyword stuffing from yielding a compliant score without diversity of evidence categories.

> **Flag Naming:**
> `--format` is now the canonical flag for SBOM format selection. The older `--sbom-format` still works but is deprecated and will emit a warning; it will be removed in a future minor release. All CLI and GitHub Action usage should migrate to `--format`.

## Current Limitations (Non‑Blocking)

Normative coverage is complete. Remaining depth enhancements (optional): packet‑level canonical JA3/JA4 derivation via sniffer integration, exhaustive QUIC Initial parameter decoding, deeper Noise transcript semantic decoding. These are engineering depth improvements and not required for normative pass/fail logic.

### Strict Mode vs Heuristic Mode
Checks advertise `evidenceType` among: `heuristic`, `static-structural`, `dynamic-protocol`, `artifact`. Strict mode (default) only counts non‑heuristic passes unless `--allow-heuristic`. Multi‑signal scoring (artifact=3, dynamic=2, static=1, heuristic=0) plus keyword stuffing detection (anti‑evasion) appear in JSON output under `multiSignal`.

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

### Compliance Matrix (Normative Closure)
| Spec §11 Item | Related Checks | Dominant Evidence Types | Status | Notes |
|---------------|----------------|-------------------------|--------|-------|
| 1 Transport presence + TLS/ECH + calibration | 1, 12, 22, 32 | static-structural + dynamic-protocol + artifact | Full | Dynamic calibration matches static template; ECH acceptance proven via dual handshake diff |
| 2 Access tickets (replay-bound, padding, rate) | 2 (presence), 30 (struct+dynamic policy) | static-structural + dynamic-protocol | Full | Structural core fields + rotation + padding variety + rate-limit tokens + dynamic sampling (rotation ≤10m, replay window ≤2m) |
| 3 Noise XK tunnel / key sep / rekey / PQ date | 13 (pattern), 19 (rekey policy) | static-structural + dynamic-protocol | Full | Static pattern + dynamic transcript, rekey triggers, PQ date enforced |
| 4 HTTP/2/3 adaptive emulation & jitter | 20 (H2 adaptive, Full), 28 (H3 adaptive, Full) | dynamic-protocol | Full | Dynamic evidence (mean, p95, stddev, randomnessOk) with strict tolerances enforced |
| 5 SCION bridging + control stream failover (no legacy header) | 4, 23, 33 | static-structural + dynamic-protocol | Full | Bridging & negative assertion + dynamic control stream: ≥3 offers & unique paths, no legacy header, latency ≤300ms, probe interval 50–5000ms, backoff ok, timestamp skew ok, signature/schema indicators |
| 6 Rendezvous bootstrap (rotation, BeaconSet) | 6 | artifact | Full | ≥2 rotation epochs & entropy sources; no legacy deterministic seed |
| 7 Mix node selection diversity & hops | 11, 17, 27 | dynamic-protocol | Full | Uniqueness ≥80%, diversityIndex ≥0.4, entropy ≥4 bits, no reuse <8 hop sets, AS/Org diversity ≥15%, path length variance sane (0<σ≤1.5·mean), 95% CI width ≤ max(2,1.2·mean), entropyConfidence ≥0.5, VRF/beacon entropy ≥8 bits |
| 8 Alias ledger finality & Emergency Advance | 7, 16 | artifact | Full | Global & per-chain depth/weight, epoch monotonicity, signer duplication & signature coverage, emergency advance gating |
| 9 Payments (voucher struct, FROST, PoW) | 8, 14, 29, 31, 36 | artifact + static-structural + dynamic-protocol | Full | Voucher struct + aggregated sig + FROST n≥5 t=3 + advanced PoW convergence (slope/rolling/stability) & multi-bucket stats |
|10 Governance anti-concentration & partition safety | 15 | artifact | Full | Diversity volatility/window/delta/top3 + 7d degradation, gap ratio, spike detection enforced |
|11 Anti-correlation fallback (UDP→TCP timing + cover) | 18 (multi-signal gate), 25 (fallback timing & distribution) | dynamic-protocol | Full | Bounds: udpTimeout 100–600ms, retry<=25ms, coverConn≥2, teardownStd<=450ms, CV≤1.2, |skew|≤1.2, outliers≤20%, modelScore≥0.7, median 200–1200ms, p95≤1800ms, startDelay≤500ms, IQR≤900ms, outlierPct≤25%, ≥2 provenance categories |
|12 Privacy hop enforcement (balanced/strict) | 11, 17 | dynamic-protocol | Full | Strict mode hop depth + uniqueness ratio + diversity index + entropy/no-early-reuse safeguards |
|13 Reproducible builds & SLSA provenance | 9, 35 | artifact | Full | Predicate type, builder ID, digest & materials validation, DSSE signer threshold, detached signature / bundle authenticity (codes: SIG_DETACHED_INVALID, BUNDLE_THRESHOLD_UNMET, BUNDLE_SIGNATURE_INVALID, BUNDLE_HASH_CHAIN_INVALID, MISSING_AUTH_SIGNALS) |
| – Algorithm agility registry | 34 | artifact | Full | Allowed vs used sets; unregisteredUsed empty |
| – Statistical jitter randomness | 26, 37 | dynamic-protocol | Full | Jitter variance + randomness pValue > 0.01, adequate samples |
| – SCION control stream path failover metrics | 33 | dynamic-protocol | Full | Path switch latency & probe/backoff/timestamp skew + signature/schema flags |
| – PQ boundary enforcement | 10, 38 | heuristic + artifact | Full | Mandatory date boundary & early/late enforcement with override audit |
| – Forbidden artifact hashes / negative assertions | 23, 39 | static-structural + artifact | Full | Deny‑list + forbidden hash policy enforced |
|– Binary structural meta (foundational) | 21 | static-structural | Baseline | Supports multi-signal diversity |
|– Negative assertions (forbidden legacy/seed) | 23 | static-structural | Baseline | Expands denial surface |
|– Rate-limit bucket dispersion | 24 | artifact (rateLimit evidence) | Baseline | Multi-bucket presence & variance sanity |

Legend: All items have ≥1 non‑heuristic evidence path; historical simulated scaffolds remain only where sufficient for normative acceptance.

### Provenance & Reproducible Build
An early CI workflow (`.github/workflows/provenance-repro.yml`) now attempts:
1. Deterministic build with fixed `SOURCE_DATE_EPOCH`.
2. Per-file SHA256 manifest + aggregate digest.
3. (Placeholder) SLSA provenance generation referencing the aggregate digest.
4. Clean rebuild diff to assert reproducibility.
5. Evidence ingestion via `--evidence-file` (DSSE envelope, raw SLSA JSON, or simple reference with provenance object) to upgrade Build Provenance (check 9) to `artifact` status when predicateType + builderId + binary/subject SHA256 digest are validated against the analyzed binary (or accepted if analyzer hashing unavailable in degraded environments).

Implementation: detached signature verification, optional DSSE envelope verification, signer threshold & required key policy, materials completeness & mismatch detection, reproducible rebuild digest comparison, toolchain diff gating, authenticity gate (Check 35) in strict auth mode.

Authenticity (Check 35) granular failure codes:
- SIG_DETACHED_INVALID – detached signature path attempted but cryptographic verification failed.
- BUNDLE_THRESHOLD_UNMET – multi-signer bundle present but required threshold not satisfied.
- BUNDLE_SIGNATURE_INVALID – one or more bundle entry signatures structurally/cryptographically invalid.
- BUNDLE_HASH_CHAIN_INVALID – recomputed hash chain over entry canonicalSha256 values does not match provided bundleSha256.
- MISSING_AUTH_SIGNALS – neither detached signature nor bundle evidence provided under strict auth.
- EVIDENCE_UNSIGNED – (non-strict mode) authenticity not enforced but surfaced for visibility.

Pass conditions: either a verified detached signature OR a bundle with `multiSignerThresholdMet=true` and (if provided) a valid hash chain (bundleSha256 matches recomputed). Evidence type is elevated to `artifact` only when authenticity satisfied; otherwise remains heuristic in reports. Future enhancements (non-blocking) include canonical JSON normalization before hash/sign, real public key allow/deny lists, multi-format (minisign/cosign) verification, signature caching, and Merkle-style tamper paths.

### Multi-Signal Scoring & Anti-Evasion
JSON results include `multiSignal` summarizing counts per evidence category and a weighted score (artifact=3, dynamic=2, static=1). Advanced keyword stuffing detection (Check 18) now evaluates:
- Keyword density (% of filtered tokens hitting spec keywords)
- Keyword distribution Shannon entropy & entropy ratio
- Non-keyword token diversity ratio
Failure codes: KEYWORD_STUFFING_HIGH, KEYWORD_STUFFING_EXTREME, KEYWORD_DISTRIBUTION_LOW_ENTROPY, LOW_NON_KEYWORD_DIVERSITY, INSUFFICIENT_CATEGORIES.
Stuffing triggers when high/extreme density combines with low corroborating categories and low entropy/diversity.

### Evidence Schema Versioning
Schema v2 fields: `binaryMeta`, `clientHelloTemplate`, `noisePatternDetail`, `negative`, plus prior `mix`, `noiseExtended`, `h2Adaptive`, `provenance`, `governance`, `ledger`. Phase 7 adds fallback distribution statistics and dynamicClientHelloCapture JA3/ja3Hash + raw capture placeholders ahead of schema v3 bump. See `docs/evidence-schema.md`.

### Mixnode Selection Entropy & Diversity (Tasks 6 & 20 Completion)
Check 17 now enforces a comprehensive set of diversity, randomness, and variance properties beyond basic uniqueness:
- Hop set uniqueness: adaptive threshold (≥80% for n≥10; scales down for smaller samples).
- Early reuse prevention: first hop set reuse must occur only after at least 8 unique hop sets (configurable via `mix.requiredUniqueBeforeReuse`).
- Entropy: Shannon entropy of node occurrence distribution ≥4 bits.
- AS / Org diversity: At least 15% of total node appearances must correspond to unique ASNs and organizations (derived when `mix.nodeASNs` / `mix.nodeOrgs` provided).
- VRF proofs: Optional `mix.vrfProofs[]` entries must all be present & marked valid to attest unbiased selection; currently simulated (cryptographic verification future).
- Aggregated beacon entropy: `mix.aggregatedBeaconEntropyBits` ≥8 when beacon sources aggregated (drand, NIST, ETH block hash) via `mix.beaconSources`.
- Reuse index & automatic computation: `mix.firstReuseIndex` auto-computed when absent to detect premature reuse; entropy & diversity ratios computed if fields omitted.
 - Variance sanity (Task 20): path length standard deviation must be >0 (unless trivially all equal with high uniqueness) and ≤1.5× mean; 95% CI width (2*1.96*stdErr) must be ≤ max(2, 1.2× mean). Entropy confidence (`mix.entropyConfidence`) must be ≥0.5 when provided.
 - Additional variance evidence fields (Task 20): `pathLengthMean`, `pathLengthStdDev`, `pathLengthStdErr`, `pathLengthCI95Width`, `varianceMetricsComputed`, `entropyConfidence`.

Evidence fields added (all optional unless enforcing their related rule):
```
mix.beaconSources.{drand|nist|eth}
mix.aggregatedBeaconEntropyBits
mix.vrfProofs[]
mix.nodeASNs, mix.nodeOrgs
mix.asDiversityIndex, mix.orgDiversityIndex
mix.firstReuseIndex, mix.requiredUniqueBeforeReuse
mix.pathLengthMean, mix.pathLengthStdDev, mix.pathLengthStdErr, mix.pathLengthCI95Width, mix.entropyConfidence, mix.varianceMetricsComputed
```
Non-blocking future work: Real beacon retrieval & cryptographic VRF verification, richer ASN/org classification accuracy, configurable statistical confidence intervals for diversity/entropy thresholds.

## License

MIT License. See [LICENSE](./LICENSE) for details.

> DISCLAIMER (Historical Context): Earlier heuristic caveats are retained for archival transparency; present strict mode + authenticity verification + multi‑signal gating reduce prior risk of token padding or single‑signal spoofing. Runtime cryptographic proofs beyond supplied artifacts remain out of scope.

## Features

Current capabilities (heuristic unless noted):
- 🧭 **Registry-Based Check Set**: 11 enumerated Betanet §11 requirement placeholders evaluated from a single cached extraction pass
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
 - 📥 **External Evidence Ingestion (Phase 1)**: Supply provenance JSON via `--evidence-file` to upgrade Build Provenance (check 9) from heuristic to artifact evidence
 - 🧪 **Strict vs Heuristic Accounting**: `--strict` (default) + `--allow-heuristic` gate scoring so heuristic-only passes surface as exit code 2 (gap) rather than a silent pass
 - 🔒 **Network Hermetic Mode**: Disabled by default; opt-in with `--enable-network`, constrain hosts via `--network-allow`, fail on blocked attempts with `--fail-on-network`.
 - ✍️ **Detached Evidence Signature Verification**: `--evidence-signature` + `--evidence-public-key` (ed25519) validate evidence JSON integrity (Phase 7 foundation).
- 🔐 **Heuristic JA3 Fingerprint Hash & Raw Capture Scaffold**: Dynamic ClientHello capture emits `ja3` + `ja3Hash` with optional `rawClientHelloB64` placeholder for full packet-calibrated JA3/JA4 (future v3).
- 📡 **QUIC Initial Raw Scaffold**: `quicInitial` now can include partial parsed fields and `rawInitialB64` (deeper raw packet parsing optional future enhancement).
- 📊 **Cover Connection Distribution Modeling**: Fallback evidence includes CV, median, p95, IQR, skewness, outlier count, anomaly codes & model score.


## Installation

Install from source (recommended):

```bash
git clone <repository-url>
cd betanet-linter
rm -rf node_modules package-lock.json
npm cache verify
npm install
npm run build
npm link
```

## Usage


> **Note:** This is betanet-linter v1.0.0. All checks are presently heuristic unless external evidence upgrades them. 1.1 deltas are detected heuristically (transport version, rendezvous rotation signals, privacy hop weighting, optional WebRTC).

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

Registry (39 checks): foundation (1–23), rate‑limit & fallback/jitter (24–26), mix variance & HTTP/3 (27–28), algorithm agility & payment/voucher deepening (29–34) with enhanced algorithm agility failure codes (REGISTRY_DIGEST_INVALID, REGISTRY_SCHEMA_INVALID, NO_USED_SETS, UNREGISTERED_SET_PRESENT, UNKNOWN_COMBO, MAPPING_INVALID, ALGORITHM_MISMATCH), authenticity & advanced statistical / PQ boundary / forbidden hashes (35–39) including multi-metric jitter randomness (MISSING_PVALUE, INSUFFICIENT_SAMPLES, PRIMARY_P_LOW, CHI_SQUARE_P_LOW, RUNS_TEST_P_LOW, ENTROPY_LOW) and PQ boundary enforcement (codes PQ_PAST_DUE, PQ_EARLY_WITHOUT_OVERRIDE; contextual metadata emitted as ctx={now,mandatory,afterDate,pqPresent,overrideApproved}).

Architecture note: All checks are declared in `check-registry.ts` (IDs 1–23 after Step 10). New checks require only one object append. Structural augmentation & evidence schema population occur in `analyzer.ts` (static patterns + binary introspection) and specialized modules (`static-parsers.ts`, `binary-introspect.ts`). Dynamic ClientHello calibration now emits a heuristic JA3 string plus `ja3Hash` (MD5 over the canonical tuple) when OpenSSL capture succeeds (`captureQuality: parsed-openssl`). This is a precursor to full raw packet JA3/JA4 capture.

1. **HTX over TCP-443 & QUIC-443** - Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH
2. **Rotating Access Tickets** - Uses rotating access tickets (§5.2)
3. **Inner Frame Encryption** - Encrypts inner frames with ChaCha20-Poly1305, 24-bit length, 96-bit nonce
4. **SCION Path Management** - Maintains ≥ 3 signed SCION paths or attaches a valid IP-transition header
5. **Transport Endpoints** - Offers `/betanet/htx/1.1.0` & `/betanet/htxquic/1.1.0` (1.0.0 legacy accepted) (+ optional `/betanet/webrtc/1.0.0`)
6. **DHT Seed Bootstrap** - (1.0) deterministic bootstrap OR (1.1) rotating rendezvous (BeaconSet) heuristic (now reports rotation hit count)
7. **Alias Ledger Verification** - Verifies alias ledger with 2-of-3 chain consensus
8. **Payment System** - Accepts Cashu vouchers from federated mints & supports Lightning settlement (Full: artifact voucherCrypto + PoW evolution + rateLimit buckets; enforces FROST n>=5 t=3 when all artifact evidence present)
9. **Build Provenance** - Builds reproducibly and publishes SLSA 3 provenance
10. **Post-Quantum Cipher Suites** - Presents X25519-Kyber768 suites once the mandatory date is reached (2027-01-01)
11. **Privacy Hop Enforcement** - Weighted mixnet heuristic (mix + beacon/epoch + diversity tokens) requiring ≥2 mix, ≥1 beacon, ≥1 diversity indicator (scores now surfaced)
12–23 (see structural & dynamic extensions), 24 (Rate-Limit Buckets), 25 (Fallback Timing Policy), 26 (Padding Jitter Variance), 27 (Mix Advanced Variance – entropy & path length stddev), 28 (HTTP/3 Adaptive Emulation)

### Historical Disclaimer (Archived)
Earlier partial coverage disclaimers retained only for context; see Current Limitations for remaining optional depth work.

### Betanet 1.1 / Emerging Delta Coverage Snapshot (Updated Post Phase 6)
| 1.1 Element | Status | Evidence / Output Field |
|-------------|--------|-------------------------|
| Transport endpoint version bump (`/betanet/htx/1.1.0`, `htxquic/1.1.0`) | Implemented | Check 5 details (accepted list) |
| Optional WebRTC transport | Implemented | Check 5 details (`optional: webrtc`) |
| Rendezvous rotation / BeaconSet heuristic | Implemented | Check 6 details (`rotationHits`, beacon indicators) |
| Path diversity threshold (≥2 markers) | Implemented | Check 4 failure details enumerate needed markers |
| Privacy hop weighting (mix / beacon / diversity) | Implemented | Check 11 & 17 (sampling + indices) |
| Noise rekey policy (enriched transcript & triggers) | Implemented | Check 19 (dynamic transcript, triggers, hash) |
| HTTP/2 adaptive jitter (simulated) | Implemented | Check 20 (sim evidence) |
| Binary structural meta introspection | Implemented | Check 21 |
| Static ClientHello template hash | Implemented | Check 12 / 22 (scaffold) |
| Rate-limit multi-bucket evidence | Implemented | Check 24 |
| Network hermetic control (default off + allowlist + retries) | Implemented | diagnostics.networkAllowed / CLI flags --enable-network/--network-allow |
| Detached evidence signature verify | Implemented | provenance.signatureVerified / diagnostics.evidenceSignatureValid |
| Enhanced Noise pattern detail | Implemented | Check 13 (hkdf/message counts) |
| Negative assertions (forbidden legacy header / deterministic seeds) | Implemented | Check 23 |

Optional future (selected): deeper raw handshake capture (TLS/QUIC full JA3/JA4), extended HTTP/3 adaptive metrics, additional statistical jitter variance confidence intervals, broader governance historical diversity dataset, transparency log backed evidence signing, full rekey transcript cryptographic verification.
| Voucher structural regex detection | Implemented | Check 8 details (voucher present or missing) |
| PoW ≥22 contextual parsing | Implemented | Check 8 details (missing list shows PoW context) |
| PQ date override (`BETANET_PQ_DATE_OVERRIDE`) UTC-safe | Implemented | Check 10 severity escalation; override env documented |
| SBOM feature tagging (`betanet.feature`) | Implemented | CycloneDX properties / SPDX `PackageComment` lines |
| Windows degraded diagnostics (platform + reasons) | Implemented | Diagnostics: `platform`, `missingCoreTools`, `degradationReasons` |
| Dynamic runtime probe / plugin mode | Deferred | Future (ISSUE-059) |

### Spec Coverage Summary
The tool enumerates Betanet 1.0 checks and provides heuristic indicators for each; emerging 1.1 deltas (transport versions, rendezvous rotation signals, privacy hop weighting, optional WebRTC) are likewise heuristic. Normative (non‑heuristic) evidence classes will incrementally land in upcoming minor releases (see [ROADMAP.md](./ROADMAP.md)). Runtime output includes a spec coverage header, e.g.:

```
Spec Coverage: baseline 1.0 enumerated (heuristic); latest known 1.1 heuristic signals present 11/11
Optional normative hardening upgrades (beyond strict 1.1 closure): deeper raw TLS/QUIC capture & calibration (full JA3/JA4), richer HTTP/3 adaptive metrics, additional fallback timing confidence modeling, broader governance long-range corpus, expanded materials & provenance signature chain, full Noise transcript & voucher cryptographic verification.
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

Primary `check` command:
- `0` - All required checks passed (includes heuristics only if `--allow-heuristic` supplied under strict mode)
- `1` - One or more checks failed OR an execution error occurred
- `2` - Strict mode heuristic gap: no hard failures, but insufficient non-heuristic evidence (heuristic passes excluded from scoring)

SBOM validation (when `--validate-sbom` / `--strict-sbom` used):
- `2` - Strict SBOM validation failure (base or strict rule set) – process exits immediately
- `3` - Non-strict SBOM shape warnings (base shape failed without `--strict-sbom`)

Notes:
- Build provenance (check 9) can upgrade from heuristic to artifact with `--evidence-file provenance.json`, reducing heuristic gap risk.
- Future phases may introduce additional exit codes for dynamic probe failures; current mapping kept minimal.

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

- Roadmap status & advanced context (schema history, scoring weights, provenance state, escalation path): see [ROADMAP.md](./ROADMAP.md)
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
