## Unreleased

### Added
- Evidence schema v2: `binaryMeta`, `clientHelloTemplate`, `noisePatternDetail`, `negative` assertions (see `docs/evidence-schema.md`).
- Multi-signal scoring (artifact=3, dynamic=2, static=1) and anti-evasion keyword stuffing heuristic (Check 18).
- Simulated dynamic harness signals: Noise rekey policy (Check 19), HTTP/2 adaptive jitter (Check 20).
- Structural & calibration groundwork: binary structural meta (Check 21), static ClientHello template hash (Check 12 baseline + Check 22 scaffold), enhanced Noise pattern detail in check 13.
- Negative assertions (forbidden legacy header / deterministic seed) (Check 23).
- Total checks expanded 11 → 23.

### Changed
- Noise XK Pattern (Check 13) now enforces HKDF + message token thresholds.
- Provenance wording clarified; strict mode still excludes heuristic-only passes unless `--allow-heuristic`.

### Fixed
- Exclusion tests updated for new registry size.
- Mitigated false multi-signal inflation via anti-evasion check.

### Deprecated
- Schema v1 (implicit) superseded by schema v2 (backward tolerant for consumers ignoring new fields).

### Pending
- Real TLS/QUIC transcript capture & extension order calibration.
- HTTP/3 adaptive + statistical jitter variance verification.
- Governance historical diversity dataset & deeper alias ledger quorum cert validation.
- Reproducible rebuild signature + full materials graph attestation.
- Evidence signing & trust chain anchoring.

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
