# Roadmap Plans

This file tracks structured improvement plans following the initial performance & diagnostics enhancements.

## Plan 1 (DONE): Performance & Diagnostics Baseline
Implemented:
- Memoized BinaryAnalyzer.analyze() to avoid duplicate external calls (ISSUE-004)
- Added diagnostics: tool availability, analysis time, cache usage (ISSUE-031, ISSUE-032, ISSUE-043)
- Division-by-zero guard for score (ISSUE-015)
- Safe access for diagnostics preventing test breakage

Deferred (optional micro-enhancements):
- Per-check timing capture (data collected but not exported in structured JSON)
- (DONE) Per-command timeout on each capability helper (ISSUE-034 now fully implemented across analyzer + SBOM)
- forceRefresh flag to re-run analysis ignoring cache (implemented via `--force-refresh`)

Rationale for deferral: Each adds marginal value now; can batch into a later "Observability Hardening" step if needed.

## Plan 2 (DONE): Heuristic Precision & False Positive Reduction
Implemented:
- Refined Kyber detection (requires kyber token; removed plain '768' trigger) (ISSUE-006)
- Port 443 detection now boundary-aware (ISSUE-007)
- Added multi-indicator QUIC/TLS/ECH & HTX heuristics (ISSUE-008)
- Strengthened SCION path & IP-transition patterns (ISSUE-009)
- Improved DHT bootstrap & seed heuristics (ISSUE-010)
- Narrowed payment (Lightning) detection to explicit tokens (ISSUE-012)
- Introduced heuristics module `src/heuristics.ts`
- Added negative tests preventing Kyber768 & port 443 false positives (ISSUE-024)

Deferred (future enhancement ideas): scoring weights, confidence metrics per capability.

## Plan 3 (DONE): Architecture Consolidation
Completed:
- Removed duplicate compliance engine (compliance.ts) (ISSUE-001, 013, 014)
- Removed legacy sbom.ts (ISSUE-020 duplicate path eliminated)
- Added centralized check registry (`src/check-registry.ts`) with all metadata & evaluate() functions
- Added analyzer injection (lazy creation) resolving mocking fragility (ISSUE-022)
- Division-by-zero guard leveraged by registry (ISSUE-015)
- Added 11th Privacy Hop Enforcement check (heuristic, 1.1) extending coverage beyond original 10

Pending / Deferred:
- Extract helper utilities from `index.ts` (ISSUE-030)
- Externalize magic strings/dates (ISSUE-028, 029)

Outcome: Severities & names normalized via registry; no second engine remains.

## Plan 4 (DONE): SBOM Quality & Integrity
Implemented:
- Dedicated generator module `sbom/sbom-generator.ts` (ISSUE-017)
- CycloneDX XML & JSON + SPDX tag-value + SPDX JSON export
- Component & binary SHA-256 hashing (ISSUE-018, 039)
- License heuristic detection (ISSUE-019)
- Component dedupe & sanitization (ISSUE-037, 045, 021)
- SBOM shape + strict validators (CycloneDX / SPDX)
- CLI flags: `--sbom`, `--sbom-format`, `--validate-sbom`, `--strict-sbom`
- Exit code 3 for non-strict shape failures
- Severity filtering support (scoring isolation)

Deferred:
- PURL ecosystem enrichment beyond generic/system libs
- Configurable validation policy escalation

## Plan 5 (DONE): Robustness & Error Handling
Implemented:
- `safe-exec` wrapper with configurable timeout (BETANET_TOOL_TIMEOUT_MS) (ISSUE-034)
- Dynamic tool skipping (BETANET_SKIP_TOOLS) & degradation metadata (ISSUE-035)
- Binary existence pre-check (ISSUE-033)
- Analyzer fallback for strings & dependency detection; graceful degradation flags
- Added degradation tests & diagnostics exposure
 - Per-check degradedHints inline markers (ISSUE-035 follow-up)

Deferred:
- Per-check try/catch wrap (current evaluators stable; can harden later) (ISSUE-036)
Completed (moved from deferred): Memory streaming optimization / capped fallback strings (ISSUE-038)

## Plan 6: Security & Trust Enhancements (Partially Addressed)
Goals:
- Hash computation integrated into SBOM (if not already in Plan 4)
- Sanitization & input validation (ISSUE-037)
- Configurable post-quantum date & environment-driven thresholds (ISSUE-029, 030)

## Plan 7: UX & CLI Improvements (Partially Addressed)
Progress:
- Severity threshold flag implemented (`--severity-min`) (ISSUE-041)
- Unified SBOM format flag semantics
Pending:
- More granular diagnostics verbosity levels
- Consistent naming audit
Goals:
- Parity for filters on 'check' command (ISSUE-040)
- Severity threshold flag (ISSUE-041)
- Unified flag naming (--format) (ISSUE-042)
- Diagnostics verbosity levels

## Plan 8: Documentation & Contribution
Goals:
- README heuristic disclaimer (ISSUE-049)
- Contribution guidelines for new checks (ISSUE-050)
- Document deprecated modules (ISSUE-048)

## Plan 9 (Optional): Observability & Performance Deep Dive
(Optional revisit of deferred items)
- Per-check and per-command timing + histogram (export JSON timings artifact)
- forceRefresh / invalidate cache API (DONE in Plan 10)
- Performance regression test (ISSUE-025) if not added earlier
- Structured JSON log output option
 - Parallel check evaluation (moved earlier into implementation; DONE, ISSUE-005/057)

---
## Plan 10: Betanet 1.1 Alignment & Heuristic Refinement (MOSTLY COMPLETE)
Goals:
- Optional WebRTC transport signal surfaced (informational) (ISSUE-051)
- Stronger Rendezvous / BeaconSet rotation heuristic (epoch diversity + rotation verbs) (ISSUE-052)
- Path diversity enhancement for SCION/IP-transition (distinct path/AS tokens) (ISSUE-053)
- Privacy hop enforcement refinement (negative signal suppression, diversity weighting) (ISSUE-054)
- PQ date override flag/env for pre-mandatory testing (ISSUE-055)

Deliverables:
- (DONE) Updated check 5 details to surface optional WebRTC (transport list)
- (DONE) Updated check 6 with rotationHits & BeaconSet evidence in details including hits count
- (DONE) Adjusted check 11 algorithm with weighted token scoring & diversity requirements
- (DONE) New optional config: BETANET_PQ_DATE_OVERRIDE (env) for early PQ enforcement
- (DONE) Path diversity threshold test & enforcement (≥2 markers) for check 4
- (DONE) Negative rotate test (rotate tokens without DHT base no longer passes)
- (DONE) Force refresh flag & analyzer recreation (Plan 1 deferred item realized)
- (DONE) Fail-on-degraded env (BETANET_FAIL_ON_DEGRADED) overriding pass
- (DONE) Multi-license parsing in SBOM (previously deferred in Plan 4)
- (DONE) Spec version matrix (introducedIn/mandatoryIn) & CLI spec coverage summary (ISSUE-052, ISSUE-055)
- (DONE) Parallelized check evaluation + per-check timeout & error isolation (ISSUE-005, 036, 057)

Success Criteria:
- All new heuristic & control flag tests pass (current suite updated to 31 tests) ✅
- No regression in existing tests (verified) ✅
- Diagnostics stable (unchanged apart from env gating) ✅

Residual / Future (optional):
- Additional false-positive suppression heuristics (generic keyword filtering)
- Confidence scoring per heuristic token group
- Structured JSON export for per-check timings (Observability plan)

---
## Plan 11: Structural & Dynamic Escalation (IN PROGRESS / NEXT)
Goals:
- Evidence schema v2 adoption (DONE) – structural augmentation fields consumed by new checks.
- Binary structural meta introspection (DONE) – Check 21 baseline integrity.
- Static ClientHello template hashing (DONE) – Check 12 baseline & Check 22 calibration scaffold.
- Enhanced Noise pattern detail (DONE) – HKDF/message token counts strengthen Check 13.
- Negative assertions (DONE) – Check 23 enumerates forbidden legacy constructs.
- Multi-signal scoring & anti-evasion (DONE) – Check 18 guards against keyword stuffing.
- Simulated dynamic signals (DONE) – Rekey policy (19), HTTP/2 adaptive jitter (20).
- Real TLS/QUIC handshake capture (PENDING) – populate dynamic template evidence & transition Check 22 from scaffold to calibrated enforcement.
- HTTP/3 adaptive + jitter variance (PENDING) – extend dynamic evidence set & new check (future ID TBD).
- Diversity statistical baseline (PENDING) – convert sampling into variance/confidence outputs.
- Governance artifact deep validation (PENDING) – signature set, quorum cert structure.
- Evidence signing (PENDING) – cryptographic signature over emitted JSON / SBOM digests.

Deliverables (Partial Complete):
- Registry expanded to 23 checks (IDs 1–23). ✅
- Schema version bump to 2 with docs (`docs/evidence-schema.md`). ✅
- Analyzer structural pass sets `schemaVersion=2` & populates new fields. ✅

Next Implementation Steps:
1. Real handshake capture: minimal pluggable probe interface (avoid executing target binary until sandbox clarified).
2. Calibration store: persist baseline ClientHello ALPN/extension ordering for drift detection.
3. Jitter statistics: capture distribution (p50/p90/stddev) vs expected adaptive ranges.
4. Governance dataset ingestion: schema + diversity metrics (org, autonomous system, jurisdiction).
5. Evidence signing: detached signature file (.sig) with canonical JSON serialization.
6. Structured timing export: JSON timings artifact for observability (ties back to Plan 9 deferred item).
7. Anti-correlation fallback harness: simulate UDP failure and measure fallback timing threshold.

Risk / Considerations:
- Sandbox & network egress policies for active probes.
- Deterministic ordering of captured extension lists to avoid flaky diffs.
- Time sync & monotonic clock usage for jitter metrics.

Success Criteria:
- ≥2 dynamic-protocol checks rely on real capture (not simulated) without flakiness.
- Check 22 graduates from scaffold to calibrated enforcement.
- Multi-signal scoring shows ≥1 static + ≥1 dynamic + ≥1 artifact category for a fully instrumented binary.

