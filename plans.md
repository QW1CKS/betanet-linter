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

## Plan 3 (IN PROGRESS): Architecture Consolidation
Completed:
- Removed duplicate compliance engine (compliance.ts) (ISSUE-001, 013, 014)
- Removed legacy sbom.ts (ISSUE-020 duplicate path eliminated)
- Added centralized check registry (`src/check-registry.ts`) with all metadata & evaluate() functions
- Added analyzer injection (lazy creation) resolving mocking fragility (ISSUE-022)
- Division-by-zero guard leveraged by registry (ISSUE-015)
- Added 11th Privacy Hop Enforcement check (heuristic, 1.1) extending coverage beyond original 10

Pending / Deferred:
- Migrate basic inline SBOM in `index.ts` to advanced generator (moved to Plan 4)
- Extract helper utilities from `index.ts` (ISSUE-030)
- Externalize magic strings/dates (ISSUE-028, 029)

Outcome: Severities & names normalized via registry; no second engine remains.

## Plan 4: SBOM Quality & Integrity
Goals:
- Consolidate on `sbom/sbom-generator.ts` (retire inline SBOM in index.ts)
- Produce valid SPDX 2.3 (JSON or tag-value with completeness) & CycloneDX (JSON/XML) (ISSUE-017)
- Ensure hashing for binary + components (ISSUE-018, 039)
- License detection heuristics (ISSUE-019)
- Sanitize, dedupe & version quality improvements (ISSUE-037, 045, 021)

Deliverables:
- Unified SBOM service module & adapter in checker
- Hash + license utility functions
- Sanitization & dedupe helpers
- Schema validation tests (SPDX, CycloneDX)

## Plan 5: Robustness & Error Handling
Goals:
- Binary existence pre-check (ISSUE-033)
- Global per-command timeout & graceful fallback (ISSUE-034)
- Always-on concise warnings (ISSUE-035)
- Per-check try/catch safety (ISSUE-036)
- Memory-safe string extraction (ISSUE-038)

Deliverables:
- wrapper exec utility with timeout, error shape
- Updated analyzer extraction logic with streaming fallback

## Plan 6: Security & Trust Enhancements
Goals:
- Hash computation integrated into SBOM (if not already in Plan 4)
- Sanitization & input validation (ISSUE-037)
- Configurable post-quantum date & environment-driven thresholds (ISSUE-029, 030)

## Plan 7: UX & CLI Improvements
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
- forceRefresh/ invalidate cache API
- Performance regression test (ISSUE-025) if not added earlier
- Structured JSON log output option

---
### Recommended Next Step
Finalize Plan 3 by swapping SBOM path or explicitly delegating to advanced generator; then initiate Plan 4 tasks (valid formats, hashing, licensing).

