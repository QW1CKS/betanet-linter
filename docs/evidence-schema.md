# Evidence Schema

Schema Version: 2 (Phases 2–6 additions; Phase 7 signature verification scaffold)

## Overview
The linter ingests structured evidence objects (either via --evidence-file or produced internally by static/dynamic analyzers). Schema v2 introduces structural binary metadata, static ClientHello template extraction, enhanced Noise pattern details, and negative assertions.

## Top-Level Fields (current)
- schemaVersion: number (2)
- provenance: SLSA provenance metadata + validation flags (materials completeness, signatureVerified, signatureError)
- governance / ledger: governance & ledger observation evidence
- governanceHistoricalDiversity: diversity time-series + derived metrics (stable, advancedStable, volatility, maxWindowShare)
- mix: path sampling & diversity metrics (mode, uniquenessRatio, diversityIndex)
- h2Adaptive: HTTP/2 adaptive jitter metrics (mean, p95, stddev, sampleCount, withinTolerance)
- noiseExtended: simulated / dynamic Noise rekey evidence (rekeysObserved, triggers)
- binaryMeta (v2): { format, sections[], importsSample[], hasDebug, sizeBytes }
- clientHelloTemplate (v2): { alpn[], extensions[], extOrderSha256 }
- dynamicClientHelloCapture (planned v3 placeholder currently partially populated when simulated)
- noisePatternDetail (v2): { pattern, hkdfLabelsFound, messageTokensFound }
- bootstrap: rotation & entropy sources evidence
- powAdaptive: PoW difficulty evolution samples & target bits
- rateLimit: bucket definitions, scope counts, variance metrics
- negative (v2): { forbiddenPresent[] }
- network diagnostics (Phase 6): diagnostics.networkAllowed, diagnostics.networkOps[] (url, method, durationMs, blocked, error)
- provenance.signatureVerified (Phase 7) & diagnostics.evidenceSignatureValid

## Version Differences
| Field | v1 | v2 |
|-------|----|----|
| binaryMeta | – | added |
| clientHelloTemplate | – | added |
| noisePatternDetail | – | added |
| negative | – | added |
| schemaVersion | optional (implicit 1) | explicit 2 |

## Negative Assertions
forbiddenPresent lists any detected legacy / unsafe tokens. Current tokens:
- deterministic_seed
- legacy_transition_header

Presence of any causes Check 23 to fail.

## Static TLS Template
clientHelloTemplate captures ALPN list, raw extension numeric ordering (subset) and a stable SHA-256 hash over ordering for later dynamic calibration comparison.

## Noise Pattern Detail
noisePatternDetail supplements basic Noise_XK detection with heuristic counts of HKDF-related labels and message token markers for stronger multi-signal corroboration.

## Future Additions (Planned v3)
- dynamicClientHelloCapture: full raw ClientHello bytes + JA3/JA4 fingerprint
- quicInitial: transport parameters & version negotiation evidence
- statisticalJitter: distribution metrics for padding / PING / PRIORITY
- signedEvidence bundle: canonical hash chain + multiple signatures

This document will evolve; breaking changes will bump schemaVersion. See `ROADMAP.md` for planned additions.
