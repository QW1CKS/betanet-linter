# Evidence Schema

Schema Version: 2 (Step 10)

## Overview
The linter ingests structured evidence objects (either via --evidence-file or produced internally by static/dynamic analyzers). Schema v2 introduces structural binary metadata, static ClientHello template extraction, enhanced Noise pattern details, and negative assertions.

## Top-Level Fields
- schemaVersion: number (2)
- provenance: SLSA provenance metadata + validation flags
- governance / ledger: governance & ledger observation evidence
- mix: path sampling & diversity metrics
- h2Adaptive: HTTP/2 adaptive jitter metrics
- noiseExtended: simulated / dynamic Noise rekey evidence
- binaryMeta (v2): { format, sections[], importsSample[], hasDebug, sizeBytes }
- clientHelloTemplate (v2): { alpn[], extensions[], extOrderSha256 }
- noisePatternDetail (v2): { pattern, hkdfLabelsFound, messageTokensFound }
- negative (v2): { forbiddenPresent[] }

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
- signedEvidence: signature block (public key, signature, digest chain)

This document will evolve; breaking changes will bump schemaVersion. See `ROADMAP.md` for planned additions.
