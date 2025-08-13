## Unreleased

This section tracks post‑1.1 optional enhancements and polish items. Core Betanet 1.1 normative coverage is COMPLETE (39 checks: 1–39) with authenticity, adaptive PoW statistics, statistical jitter randomness, PQ boundary, governance diversity, negative assertions, forbidden artifact hash denial, algorithm agility registry validation, aggregated voucher signature placeholder crypto check, multi‑signal anti‑evasion scoring, and reproducible build/SLSA provenance verification all implemented and tested.

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
