## 1.1.0 - 2025-08-11

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
