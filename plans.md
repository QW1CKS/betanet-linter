# Roadmap Plans

This file tracks structured improvement plans following the initial performance & diagnostics enhancements.

## Plan 1 (DONE): Performance & Diagnostics Baseline
Implemented:
- Memoized BinaryAnalyzer.analyze() to avoid duplicate external calls (ISSUE-004)
- Added diagnostics: tool availability, analysis time, cache usage (ISSUE-031, ISSUE-032, ISSUE-043)
- Division-by-zero guard for score (ISSUE-015)
- Safe access for diagnostics preventing test breakage

Deferred (optional micro-enhancements):
- Per-check timing capture
- Per-command timeout on each capability helper (ISSUE-034 partially; only tool detection has timeout)
- forceRefresh flag to re-run analysis ignoring cache

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

Deferred:
- Per-check try/catch wrap (current evaluators stable; can harden later) (ISSUE-036)
- Memory streaming optimization (acceptable for current binary sizes) (ISSUE-038)

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
- Per-check and per-command timing + histogram
- forceRefresh / invalidate cache API (DONE in Plan 10)
- Performance regression test (ISSUE-025) if not added earlier
- Structured JSON log output option

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

Success Criteria:
- All new heuristic & control flag tests pass (current suite updated to 31 tests) ✅
- No regression in existing tests (verified) ✅
- Diagnostics stable (unchanged apart from env gating) ✅

Residual / Future (optional):
- Additional false-positive suppression heuristics (generic keyword filtering)
- Confidence scoring per heuristic token group
- Structured JSON export for per-check timings (Observability plan)

