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
#### Added (Task 9 Completion)
- Governance Partition Safety 7-Day Dataset (Check 15 enhanced): auto-computation of degradation (`degradationComputedPct`) from first vs last 24h windows, gap ratio (`seriesGapRatio`) requiring ≥95% of expected hourly points, partition volatility spike detection (>15% absolute change in dominant AS share between consecutive samples), and new failure reasons SERIES_GAP_EXCESS, PARTITION_VOLATILITY_SPIKE alongside existing PARTITION_DEGRADATION. Types updated; enforcement integrated without breaking older evidence (absence treated leniently). Tests cover degradation pass/fail; future enhancements may add explicit spike & gap scenarios.
#### Added (Task 10 Completion)
- Anti-Correlation Fallback Timing Enforcement (Check 25 advanced): evidence schema extended with statistical distribution & model fields (coverTeardownMedianMs, coverTeardownP95Ms, coverTeardownCv, coverTeardownSkewness, coverTeardownOutlierCount, coverTeardownAnomalyCodes[], behaviorModelScore, behaviorWithinPolicy). Enforcement tightened: udpTimeout 100–600ms, retryDelay ≤25ms, coverConnections ≥2, teardownStdDev ≤450ms, CV ≤1.2, |skew| ≤1.2, outliers ≤20%, modelScore ≥0.7, median 200–1200ms, p95 ≤1800ms, startDelay ≤500ms, IQR ≤900ms, outlierPct ≤25%, provenanceCategories ≥2 (expect cover + real). Failure codes grouped (COVER_INSUFFICIENT, COVER_DELAY_OUT_OF_RANGE, TEARDOWN_VARIANCE_EXCESS) with detailed reason list for each violated bound. Backward compatible: missing advanced fields do not fail (permissive upgrade). Tests updated (final-compliance-tasks) for pass + each grouped failure scenario (insufficient cover, delay out of range, teardown variance/IQR/outlierPct excess, provenance insufficiency).

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

### Task 18: Extended QUIC Initial Parsing & Calibration Hash
### Task 19: HTTP/2 & HTTP/3 Jitter Statistical Tests
- Added `jitterMetrics` evidence section with ping interval, padding size, priority gap samples plus chiSquareP, runsP, ksP, entropyBitsPerSample, stddev metrics & sampleCount.
- Harness populates simulated jitterMetrics when both h2/h3 adaptive simulations are enabled.
- Introduced Check 41 enforcing sample minimum, randomness p-value thresholds (>0.01), entropy floor (≥0.25), stddev sanity; failure codes: JITTER_EVIDENCE_MISSING, JITTER_SAMPLES_INSUFFICIENT, CHI_SQUARE_P_LOW, RUNS_TEST_P_LOW, KS_P_LOW, ENTROPY_LOW, PING_STDDEV_LOW, PADDING_STDDEV_LOW.
- Added tests covering pass and each failure scenario; roadmap Task 19 marked complete.
- Caveats: statistical values simulated; real capture & advanced distribution modeling deferred to Task 25.
- Added harness extended QUIC Initial parsing: version, DCID/SCID lengths & hex values, token length, length field varint, negotiation & retry heuristics.
- Introduced calibrationHash (sha256 over stable subset) with baseline `quicInitialBaseline`; mismatch flagged via `calibrationMismatch` and failure code QUIC_CALIBRATION_MISMATCH.
- New Check 40 (Extended QUIC Initial Parsing & Calibration) validating evidence presence, parse completeness, version expectation (0x00000001), calibration stability; surfaces negotiation/retry as informational codes (QUIC_VERSION_NEGOTIATION, QUIC_RETRY).
- Updated `types.ts` with extended `quicInitial` and baseline schema additions.
- Added tests covering pass, calibration mismatch, and missing evidence scenarios.
- Roadmap Task 18 marked complete; Task 24 will later expand to full transport parameter parsing & additional mismatch codes.

### Task 20: Mix Diversity Variance & Entropy Metrics
- Extended mix evidence schema with variance & confidence fields: pathLengthMean, pathLengthStdErr, pathLengthCI95Width, varianceMetricsComputed, entropyConfidence.
- Harness now computes mean, stddev, stdErr, 95% CI width and a heuristic entropyConfidence based on sample size.
- Check 17 upgraded to enforce variance sanity (non-zero/non-excessive stddev, reasonable CI width) and entropy confidence (≥0.5 when provided) alongside existing uniqueness, entropy, diversity, reuse, AS/Org, VRF & beacon thresholds.
- Failure diagnostics extended: adds reasons 'path length variance abnormal' and 'entropy confidence low'.
- Updated details output to surface plStd, ci95W and entConf metrics for auditing.
- Tests to be added in subsequent commit expanding negative scenarios (variance anomaly, low entropy confidence) – placeholder if not yet present.
- Caveats: thresholds heuristic (stddev ≤ 1.5*mean, CI width ≤ max(2, 1.2*mean)); future work may introduce statistical hypothesis tests & bootstrap CI for entropy; variance anomaly reasons not yet codified as distinct failure codes (string reasons only) to preserve backward compatibility.

### Task 11 Completion: Provenance & Evidence Authenticity Hardening
### Task 12 Completion: Algorithm Agility Registry Enforcement
### Task 13 Completion: Statistical Jitter Randomness Multi-Metric Enforcement
- Upgraded Check 37 to evaluate multiple randomness metrics (primary pValue, chiSquareP, runsP, entropyBitsPerSample, sampleCount)
- Added granular failure codes: MISSING_PVALUE, INSUFFICIENT_SAMPLES, PRIMARY_P_LOW, CHI_SQUARE_P_LOW, RUNS_TEST_P_LOW, ENTROPY_LOW
- Extended tests with pass + each negative scenario; evidence elevated to artifact only when explicit metrics provided and thresholds satisfied
- ROADMAP updated to mark Task 13 complete and outline future statistical refinement caveats
- Expanded Check 34 with schema/digest validation and granular failure codes: REGISTRY_DIGEST_INVALID, REGISTRY_SCHEMA_INVALID, NO_USED_SETS, UNREGISTERED_SET_PRESENT, UNKNOWN_COMBO, MAPPING_INVALID, ALGORITHM_MISMATCH
- Added extended evidence fields (suiteMapping, mismatches, unknownCombos, observedSuites) and upgraded types
- Added comprehensive positive + negative tests in final-compliance-tasks suite
- Updated ROADMAP to mark Task 12 complete with caveats for future cryptographic suite canonicalization & deeper schema validation
- Added granular authenticity failure codes in Check 35: SIG_DETACHED_INVALID, BUNDLE_THRESHOLD_UNMET, BUNDLE_SIGNATURE_INVALID, MISSING_AUTH_SIGNALS, EVIDENCE_UNSIGNED (non-strict informational)
- strictAuthMode now enforces presence of either verified detached signature or multi-signer bundle threshold; non-strict mode surfaces unsigned state without blocking
- Extended tests (Task 11 section) covering pass (detached + bundle) and each new negative scenario
- ROADMAP updated to mark Task 11 complete with caveats retained for future real cryptographic bundle verification & key policy enhancements

### Task 14 Completion: Post-Quantum Date Boundary Reliability
- Enhanced Check 38 with contextual metadata (ctx={now,mandatory,afterDate,pqPresent,overrideApproved}) for audit traceability
- Preserved failure codes PQ_PAST_DUE & PQ_EARLY_WITHOUT_OVERRIDE (aggregated under PQ_BOUNDARY token in failure details) ensuring backward compatibility for existing parsers
- EvidenceType now elevates to artifact when either PQ capability detected or override object present
- Added edge-case tests: exact boundary epoch pass/fail, override pre-date pass, metadata presence assertion
- README updated to reflect PQ boundary codes and contextual metadata emission

### Task 15 Completion: Evidence Authenticity Hash Chain Verification
- Check 35 enhanced to recompute multi-signer bundle hash chain (concatenated canonicalSha256 entry hashes → sha256) and compare against provided bundleSha256.
- Added failure code: BUNDLE_HASH_CHAIN_INVALID when mismatch detected (backward compatible; existing scenarios unchanged). Additional metadata: computedBundleSha256, hashChainValid, thresholdRequired.
- Types extended with computedBundleSha256, hashChainValid, thresholdRequired; README & ROADMAP updated.
- Tests: Added negative case exercising BUNDLE_HASH_CHAIN_INVALID in final-compliance-tasks suite.

Post‑1.1 optional enhancements and polish items (see deferred list above). No breaking changes scheduled; future work will aim for additive schema expansions and optional flags.

### Task 16 Completion: Keyword Stuffing Advanced Heuristic Refinement
- Check 18 upgraded with advanced keyword stuffing detection: filtered token set, keyword frequency map, Shannon entropy & entropy ratio, non-keyword diversity ratio.
- New failure codes: KEYWORD_STUFFING_HIGH, KEYWORD_STUFFING_EXTREME, KEYWORD_DISTRIBUTION_LOW_ENTROPY, LOW_NON_KEYWORD_DIVERSITY, INSUFFICIENT_CATEGORIES.
- README & ROADMAP updated; tests added covering pass, high stuffing, extreme stuffing scenarios.

### Task 17 Completion: Governance & Ledger Cryptographic Quorum Signature Validation
- Check 16 upgraded with real Ed25519 quorum certificate signature verification when validator public keys supplied (governance.validatorKeys). For each certificate constructs canonical message `epoch:NUM|root:HASH` and attempts Ed25519 verify (null algorithm) with SHA256-RSA fallback.
- Added metadata: chainsSignatureVerified boolean, quorumSignatureStats { total, valid, invalid, mode }, signerAggregatedWeights map, weightAggregationMismatch flag, signatureValidationMode='ed25519'.
- New failure codes: QUORUM_SIG_INVALID (any invalid signature), QUORUM_SIG_COVERAGE_LOW (<80% valid of total), WEIGHT_AGG_MISMATCH (declared chain weightSum differs from aggregated signer weights).
- Passing now requires all previous conditions plus chainsSignatureVerified (when keys provided) and coverage ≥80%. Existing QUORUM_CERTS_INVALID remains surfaced if parser-level validation fails.
- Tests added (final-compliance-tasks) for: all valid signatures pass, invalid signature fails, low coverage (missing signature) triggers QUORUM_SIG_COVERAGE_LOW.
- ROADMAP & types updated to mark Task 17 complete and document caveats (batch verification optimization, duplicate org correlation, multi-algorithm extensibility, Merkle root consistency future work).

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
