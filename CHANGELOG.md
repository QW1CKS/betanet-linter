## 1.1.0 - 2025-08-14

Betanet 1.1 normative closure release. Expands initial 11 baseline checks to a hardened 39‑check registry covering every §11 high‑level requirement plus auxiliary integrity / anti‑evasion surfaces. All tests (148) pass; provenance & SBOM generators upgraded; documentation de‑transitionalized. This version supersedes 1.0.0 which only partially surfaced 1.1 heuristics.

### Highlights
#### Added (Task 4 Completion)
- SCION Control Stream & Path Failover Metrics (Check 33) fully implemented: advanced evidence fields (latency, probe intervals, backoff flag, timestamp skew, signature indicator, schema validation). New failure codes: PATH_SWITCH_LATENCY_HIGH, NO_LATENCY_METRICS, PROBE_INTERVAL_OUT_OF_RANGE, NO_PROBE_INTERVALS, BACKOFF_VIOLATION, BACKOFF_UNKNOWN, TS_SKEW, TS_SKEW_UNKNOWN, SIGNATURE_INVALID, SIGNATURE_MISSING, SCHEMA_INVALID, SCHEMA_UNKNOWN (alongside existing INSUFFICIENT_OFFERS, INSUFFICIENT_UNIQUE_PATHS, LEGACY_HEADER_PRESENT, DUPLICATE_OFFER, CBOR_PARSE_ERROR). Tests expanded (final-compliance-tasks) adding pass + targeted negative cases.
- Full decomposition of 13 §11 normative items into 39 granular checks (static, dynamic, artifact, heuristic, defensive) with explicit mapping in README.
- Evidence schema v2+ (binaryMeta, clientHelloTemplate, noisePatternDetail, negative, mix variance, fallback timing, jitter randomness, powAdaptive, voucherCrypto, algorithmAgility, governance/ledger, provenance authenticity).
- Dynamic harness extensions: Noise rekey policy, HTTP/2 & HTTP/3 adaptive emulation, fallback timing distribution, mix diversity & variance, adaptive PoW trend, statistical jitter randomness.
- Authenticity & anti‑evasion: detached / multi‑signer evidence signature gating (check 35), multi‑signal scoring & keyword padding detection (check 18), forbidden artifact hash denial (39), negative assertions (23).
- Algorithm agility registry validation (34) & PQ boundary enforcement (10, 38) with override safeguard.
- SBOM enhancements: bom‑ref, dependency component synthesis (CycloneDX & SPDX), feature tagging (betanet.feature), metadata.tools, SPDX relationship fixes.
- Governance & ledger: diversity volatility thresholds, quorum certificate parsing scaffolds, emergency advance gating (7, 15, 16).
- Reproducible build & SLSA provenance elevation (9) with authenticity gate (35) and failing/strict auth modes.
#### Added (Task 5 Completion)
- SCION Control Stream deep metrics (enhanced): Added rolling duplicate window detection, signature material fields (signatureB64, publicKeyB64, controlStreamHash) and token bucket level sanity with new failure codes: DUPLICATE_OFFER_WINDOW, SIGNATURE_UNVERIFIED, CONTROL_HASH_MISSING, TOKEN_BUCKET_LEVEL_EXCESS, TOKEN_BUCKET_LEVEL_NEGATIVE. Updated tests for each code.
- Bootstrap PoW & Multi-Bucket Rate-Limit Statistics (Check 36) upgraded: advanced PoW convergence (slope, maxDrop, rolling window stability, acceptance percentile & recent window acceptance) and multi-bucket saturation/dispersion analytics. New failure codes: POW_SLOPE_INSTABILITY, POW_MAX_DROP_EXCEEDED, POW_ACCEPTANCE_DIVERGENCE, POW_ROLLING_WINDOW_UNSTABLE, POW_RECENT_WINDOW_LOW, BUCKET_DISPERSION_HIGH, BUCKET_SATURATION_EXCESS, POW_EVIDENCE_MISSING (generic fallback retained POW_TREND_DIVERGENCE). Evidence schema extended (powAdaptive.acceptancePercentile, regressionSlope, windowSize, windowMaxDrop, rollingAcceptance, recentMeanBits; rateLimit.bucketSaturationPct, dispersionRatio, capacityP95, capacityStdDev, refillVarianceTrend). Tests expanded covering pass + each failure code.
#### Added (Task 6 Completion)
- Mixnode Selection Entropy & Diversity Enforcement (Check 17) enhanced: new evidence fields (beaconSources, aggregatedBeaconEntropyBits, vrfProofs, nodeASNs, nodeOrgs, asDiversityIndex, orgDiversityIndex, firstReuseIndex, requiredUniqueBeforeReuse). Enforcement now includes early hop set reuse detection (threshold default 8), entropy ≥4 bits, adaptive uniqueness ratio, AS/Org diversity (≥15%), VRF proof validity, aggregated beacon entropy ≥8 bits. Added tests for early reuse failure and full diversity + VRF/beacon success. Non-blocking caveats: real beacon fetching & cryptographic VRF verification, richer AS/Org classification, configurable thresholds.
#### Added (Task 7 Completion)
- Alias Ledger 2-of-3 Finality & Emergency Advance Deep Validation (Check 16 enhanced): ledger evidence schema extended with per-chain `chains[]` objects (finalityDepth, weightSum, epoch, signatures[{signer,weight,valid}]), policy thresholds (`requiredFinalityDepth`, `weightThresholdPct`), signature coverage metric (`signatureSampleVerifiedPct`), duplicate signer heuristic, weight cap (`weightCapExceeded`). Enforcement now includes per-chain depth & weight thresholds, epoch monotonicity, signer duplication, negative weight detection, invalid signature flags, signature coverage %, and weight cap gating in addition to existing global finality/emergency advance rules.
- New failure codes: CHAIN_FINALITY_DEPTH_SHORT, CHAIN_WEIGHT_THRESHOLD, EPOCH_NON_MONOTONIC, SIGNER_WEIGHT_INVALID, DUPLICATE_SIGNER, SIGNATURE_INVALID, SIGNATURE_COVERAGE_LOW, WEIGHT_CAP_EXCEEDED (joining FINALITY_DEPTH_SHORT, EMERGENCY_LIVENESS_SHORT, QUORUM_CERTS_INVALID, QUORUM_WEIGHT_MISMATCH).
- Tests: `final-compliance-tasks.test.ts` updated with passing extended ledger scenario and comprehensive failing scenario asserting all new codes.
- Caveats: Cryptographic quorum certificate signature verification still placeholder (future Ed25519 batch verify), refined duplicate signer/org semantics & dynamic chain RPC ingestion deferred.

### Upgrade Notes
- Heuristic passes excluded by default (strict mode); use `--allow-heuristic` during transition or supply artifact/dynamic evidence via `--evidence-file` / harness.
- Deprecated `--sbom-format` retained with warning; prefer `--format`.
- Added README §11→39 decomposition table for operator clarity.
- Lint configuration updated to resolve `@typescript-eslint` ruleset naming for CI stability.

### Internal Metrics
- Test suites: 13 (148 tests) passing.
- Check registry IDs: 1–39 stable; adding a new check remains an append‑only operation.
- Evidence fields: backward compatible (schema v2 retains prior fields; new consumers ignore unknown keys).

### Security & Integrity
- Multi‑signal gating reduces single-surface spoofing risk.
- Signature verification & DSSE thresholds configurable (detached & bundle modes).
- Forbidden hash & negative assertions widen denial for deprecated constructs.

### Known Optional Enhancements (Deferred)
- Full raw JA3/JA4 canonicalization & QUIC Initial exhaustive parse.
- Extended HTTP/3 adaptive distribution metrics & additional confidence intervals.
- Long‑window governance diversity corpus & cryptographic quorum certificate signature validation.
- Full cryptographic verification of aggregated voucher signatures (beyond placeholder hash prefixes).
- Transparency log + key rotation policy for evidence signing.

## Unreleased

Post‑1.1 optional enhancements and polish items (see deferred list above). No breaking changes scheduled; future work will aim for additive schema expansions and optional flags.

### Added (since 1.0 baseline, historical aggregation)
- Evidence schema v2+ (binaryMeta, clientHelloTemplate hash, noisePatternDetail, negative assertions) and later authenticity / adaptive PoW / jitter evidence fields.
- Multi-signal scoring (artifact=3, dynamic=2, static=1) + anti-evasion keyword stuffing (Check 18) -> expanded to full authenticity & corroboration policies.
- Dynamic harness signals: rekey policy (19), HTTP/2 adaptive jitter (20), fallback timing (25), statistical jitter randomness (37), adaptive PoW & rate-limit statistics (36).
- Structural introspection & calibration scaffolding: binary structural meta (21), static ClientHello template hash (12/22), algorithm agility registry (34).
- Negative assertions & forbidden artifact hashes (23, 39).
- PQ date boundary enforcement (38), evidence authenticity (35), governance anti-concentration & diversity volatility thresholds (15), mix diversity & hop uniqueness dynamic metrics (17), voucher/FROST aggregated signature evidence (29,31).
- Total checks expanded 11 → 39 with full normative closure.

### Changed
- Noise XK Pattern (13) strengthened (HKDF + message tokens); subsequent checks integrate authenticity & multi-signer evidence.
- Strict-auth mode validates detached or multi-signer signatures before trusting artifact evidence.

### Fixed
- All exclusion / negative tests updated for registry growth to 39.
- Anti-evasion scoring prevents artificial inflation via keyword stuffing.

### Deprecated
- Schema v1 superseded; historical heuristic-only modes documented but no longer required for normative pass.

### Future (Optional / Post-1.1 Enhancements)
- Deep raw packet capture (full JA3/JA4 canonicalization) beyond current calibrated template hashing.
- HTTP/3 richer adaptive timing variance & additional statistical confidence intervals.
- Governance historical diversity long-window dataset expansion & signature crypto over quorum certificates.
- Full cryptographic verification of aggregated voucher signatures (beyond placeholder hash-prefix model).
- Formal evidence signing key rotation policy & transparency log integration.

## 1.0.0 - 2025-08-11

Highlights (betanet-linter v1.0.0):
- 11 core compliance checks (Betanet §11) with full 1.0 and partial 1.1 coverage
- SBOM generation (CycloneDX XML/JSON, SPDX tag-value/JSON) with deduplication, feature tagging, and multi-license detection
- Diagnostics: tool availability, degraded hints, per-check durations, spec coverage summary
- CLI: Stable flag naming (`--format` canonical, `--sbom-format` deprecated), `--version` flag/command, quickstart block
- Security: Name/path sanitization, streaming fallback for large binaries, timeouts, LICENSE/SECURITY.md present
- Documentation: README quickstart, limitations, license, roadmap pointer; GitHub Action usage
- Tests: 47 passing, including edge cases (zero-component SBOM, streaming, degraded analysis)

Closed issues: 001, 002, 003, 004, 005, 006, 007, 008, 009, 010, 011, 012, 013, 014, 015, 016, 017, 018, 019, 020, 021, 022, 023, 024, 025, 026, 027, 028, 029, 030, 031, 032, 033, 034, 035, 036, 037, 038, 039, 040, 041, 042, 043, 044, 045, 046, 047, 048, 049, 050, 051, 052, 053, 054, 055, 056, 057, 058, 059, 060

This release tags the v1.0.0 baseline for bounty completion and public use. This tool targets Betanet 1.0 compliance (not Betanet 1.1).
## 1.0.0 - 2025-08-11

Highlights:
- Central check registry (11 checks) with version metadata (introducedIn/mandatoryIn).
- Full Betanet 1.0 coverage; partial 1.1 heuristics (WebRTC optional transport, rotationHits, path diversity, privacy hop weighting, PQ date override).
- Parallel check evaluation with configurable concurrency & per-check timeout.
- Analyzer memoization + force refresh flag.
- Multi-license SBOM parsing & multi-format exports (CycloneDX XML/JSON, SPDX tag-value/JSON) with validation.
- Diagnostics: tool availability, degradation gating (env/flag), per-check durations, spec coverage summary.
- Environment controls: BETANET_PQ_DATE_OVERRIDE, BETANET_FAIL_ON_DEGRADED, BETANET_SKIP_TOOLS, timeouts.

Deferred (explicitly out of 1.1.0 scope):
- Voucher structural regex, PoW context refinement, privacy heuristic refinement (granularity), dynamic probe mode.
- PURL enrichment & component classification by spec feature.
- Structured JSON timing histogram export, adaptive concurrency, verbose stack traces.

All tests passing (32). This release locks baseline scope for bounty completion.
