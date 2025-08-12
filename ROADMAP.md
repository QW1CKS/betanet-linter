Betanet Linter Roadmap (Canonical)
=================================

This document is the single authoritative roadmap & progress tracker. (Historical remediation content retained below.)

Progress Summary
----------------
Completed so far: 10 tasks (Implementation Order steps 1–10; Step 3 advanced with provenance parsing, action pinning, rebuild mismatch enforcement; Step 9 simulation scope complete; Step 10 structural introspection + static template & negative assertions delivered)  
Pending: Remaining tasks across Phases 1–7 beyond Step 10 (real transcript capture, HTTP/3 adaptive, calibration baselines, statistical variance tests, signature verification, governance depth, dynamic ClientHello calibration, Noise transcript capture).  
Legend: [x] = implemented/done; [ ] = pending / not yet implemented; [~] = partially implemented.

Purpose
-------
Authoritative internal roadmap to evolve current heuristic-focused Betanet compliance linter into a normative, evidence‑driven, CI‑trustworthy tool satisfying all 13 §11 items of the Betanet 1.1 specification.

Scope & Constraints
-------------------
Covers: check coverage expansion (11 → 13+ with splits), methodology shift (string heuristics → structured static + dynamic behavioral + artifact verification), supply chain hardening, integrity & anti‑evasion, documentation transparency.
Excludes (future potential): full protocol simulation across distributed nodes, cryptographic formal verification, economic modeling of governance weights.

High-Level Diagnosis
--------------------
1. Coverage Gap: Only 11 checks implemented; 4 normative items missing (HTTP/2/3 adaptive emulation, governance anti‑concentration, anti‑correlation fallback, deeper calibration & provenance semantics). Existing checks are coarse heuristics.
2. Evidence Weakness: All passes derived from presence of tokens in binary strings/symbols—easily forged.
3. Integrity Risks: No negative assertions (absence of deprecated behaviors), no anti‑evasion multi‑signal corroboration.
4. Supply Chain: No SLSA provenance generation/verification; GitHub Action not hardened (unpinned, broad perms).
5. Dynamic Behavior: No capture/replay harness for TLS calibration, Noise handshake, rekey policy, fallback timing.
6. Governance & Ledger: Only superficial keyword detection—no 2‑of‑3 finality validation or quorum certificate parsing.
7. Privacy & Mix Diversity: Token scoring only; no sampling to confirm hop diversity constraints.
8. Network Enrichment: (If enabled later) must have safe timeouts, disabled by default, hermetic option.

Normative §11 Items → Current State Map
--------------------------------------
1. HTX over TCP+QUIC with origin‑mirrored TLS + calibration + ECH → Partial (Check 1: presence only; lacks calibration evidence, extension order, JA3/JA4, tolerances)
2. Negotiated-carrier replay‑bound access tickets (variable padding, rate‑limits) → Very shallow (Check 2: token presence)
3. Noise XK inner tunnel, key separation, nonce lifecycle, rekey thresholds, PQ date → Partial (Checks 3 & 10: AEAD + PQ tokens; no pattern / lifecycle / rekey validation)
4. HTTP/2/3 adaptive emulation (settings tolerances, jitter, padding randomness) → Missing
5. SCION bridging via HTX tunnel (no on‑wire legacy transition header) → Partial (Check 4: SCION tokens; not verifying absence of forbidden header)
6. Offer /betanet/htx/1.1.0 & /betanet/htxquic/1.1.0 (legacy 1.0 optional) → Moderate (Check 5)
7. Rotating rendezvous bootstrap (BeaconSet, PoW, multi-bucket rate-limits, no deterministic seeds) → Partial (Check 6: rotation tokens only)
8. Mixnode selection (BeaconSet + per‑stream entropy + diversity + hop policy) → Partial (Check 11: heuristic score only)
9. Alias ledger finality 2-of-3 + Emergency Advance constraints + quorum cert validation → Shallow (Check 7: consensus tokens only)
10. Cashu vouchers (128 B struct), FROST group n≥5 t=3, PoW adverts, Lightning settlement, rate-limits → Partial (Check 8)
11. Governance anti‑concentration caps & partition safety → Missing
12. Anti‑correlation fallback (UDP→TCP retry timing + cover connections) → Missing
13. Reproducible builds & SLSA 3 provenance artifacts → Partial (Check 9: supports external SLSA provenance ingestion w/ predicateType, builderId, binary digest validation; pending action pinning, signature & materials verification, reproducible rebuild enforcement in CI)

Strategic Phases
----------------
Phase 0: Transparency & Guard Rails (Immediate)
- [x] Add Compliance Matrix to README (flag heuristic vs normative vs missing).
- [x] Introduce strict mode: heuristic passes count only if --allow-heuristic specified; otherwise informational.
- [x] Add per-check metadata: evidenceType ('heuristic' | 'static-structural' | 'dynamic-protocol' | 'artifact').
- [x] Emit warning when >0 heuristic passes contribute to overall compliance.

Phase 1: Static Structural Enhancement
- [ ] Implement binary format introspection (ELF/Mach-O/PE) to extract imports, section names (displace raw string reliance).
- [ ] Parse embedded TLS ClientHello templates: recover ALPN list/order + extension sequence -> hash for calibration comparison.
- [ ] Detect Noise XK pattern: handshake prologue bytes, label strings, message count; verify presence of HKDF label tokens.
- [ ] Voucher structural heuristic: scan binary for 128-byte region pattern (entropy + partial field tags) rather than plain text tokens.
- [ ] Negative assertions: fail if deterministic seed tokens appear in 1.1-targeted build.

Phase 2: Dynamic Harness (Behavioral Evidence)
- [ ] Harness CLI (--run-harness / scenario config) spins candidate in sandbox, capturing:
  * [ ] TLS ClientHello(s) and origin calibration baseline to verify ALPN set/order, extension ordering, H2 SETTINGS tolerances.
  * [ ] QUIC Initial for transport presence.
  * [ ] Noise tunnel transcript to confirm key schedule & rekey triggers.
  * [ ] Anti-correlation fallback: simulate UDP failure, measure TCP retry delay, count cover connections, teardown times.
- [ ] Output evidence JSON with cryptographic hashes per artifact; linter consumes rather than re-performing heavy capture inside general run.

Phase 3: Governance & Ledger Verification
- [ ] Accept alias-ledger observation file: validates 2-of-3 finality rules.
- [ ] Parse Emergency Advance quorum certificates (CBOR) verifying signatures, weight caps (config-supplied weight mapping) and monotonic seq.
- [ ] Governance check: ingest participation snapshot (weights, AS/Org mapping) to compute caps & diversity conditions.

Phase 4: Adaptive/Bootstrap & Mix Diversity Deepening
- [ ] Bootstrap simulation: feed synthetic rendezvous epochs verifying rotating IDs, absence of deterministic seeds.
- [ ] Validate PoW difficulty evolution & multi-bucket rate-limit logic via controlled replay logs (evidence ingestion).
- [ ] Mix diversity sampling: request N (e.g., 10) path constructions; assert ≥8 unique hop sets before reuse.
- [ ] Privacy mode enforcement: balanced vs strict hop threshold evidence.

Phase 5: Build Provenance & Reproducibility
- [ ] Harden GitHub Action: pinned SHAs, least-privilege permissions, concurrency guard.
- [ ] Generate SLSA provenance (slsa-github-generator pinned) + attach SBOM + compliance report.
- [ ] Rebuild verification job (clean container) comparing SHA256 to ensure bit-for-bit reproducibility.
- [ ] Linter validation: verify provenance predicate type, builder ID, materials digests match binary & SBOM components.

Phase 6: Network Safety & Hermetic Control
- [ ] Disable enrichment (OSV, remote lookups) by default; require --enable-network.
- [ ] Enforce timeouts, retry with jitter, explicit User-Agent, opt-in offline fail-fast (--fail-on-network attempt).
- [ ] Record network operations into diagnostics for transparency.

Phase 7: Anti-Evasion & Scoring Hardening
- [ ] Multi-signal requirement per normative item (e.g., Transport: endpoint strings + captured ClientHello + QUIC token + ECH presence).
- [ ] Weighted scoring; heuristic-only detection cannot produce final pass unless corroborated.
- [ ] Keyword stuffing detection: disparity metrics (spec term density vs code symbol diversity) triggers suspicion warning.
- [ ] Signed evidence option: allow maintainers to sign evidence JSON (future).

New / Split Checks (Target Set ≥ 16)
------------------------------------
(Existing IDs preserved; new appended / sub-suffixed logically)
- [ ] 1a Transport Presence (static heuristic → later hybrid)
- [ ] 1b TLS Calibration & ECH (dynamic)
- [ ] 2  Access Tickets (structured carrier + padding range + replay window)
- [ ] 3a Noise XK Pattern (static)
- [ ] 3b Rekey Policy & Nonce Lifecycle (dynamic)
- [ ] 3c Post-Quantum Activation (date logic + hybrid suite presence)
- [ ] 4  HTTP/2/3 Adaptive Emulation (dynamic SETTINGS jitter)
- [ ] 5  SCION Tunnel Bridging (positive presence + absence of legacy header)
- [ ] 6  Rotating Rendezvous Bootstrap (rotation + BeaconSet + no deterministic seeds)
- [ ] 7  Alias Ledger Finality & Emergency Advance
- [ ] 8  Payment & Voucher Structure (128B struct, PoW adverts, FROST threshold)
- [ ] 9  Build Reproducibility & Provenance (artifact verification)
- [ ] 10 Governance Anti-Concentration & Diversity
- [ ] 11 Anti-Correlation Fallback Behavior
- [ ] 12 Mixnode Selection Diversity (hop uniqueness sampling)
- [ ] 13 Privacy Hop Enforcement (refined; may merge with 12 or keep separate)
(Adjust numbering to align final public matrix; maintain internal stable keys.)

Evidence Model Overview
-----------------------
Evidence JSON (example fields):
{
  "clientHello": { "alpn": ["h2","http/1.1"], "extOrderSha256": "...", "ja3": "..." },
  "calibrationBaseline": { "alpn": ["h2","http/1.1"], "extOrderSha256": "..." },
  "noise": { "pattern": "XK", "rekeysObserved": 1, "rekeyTriggers": {"bytes": 8589934592, "timeMinSec": 3600 } },
  "fallback": { "udpAttempted": true, "tcpRetryDelayMs": 412, "coverConnections": 2, "coverTeardownSec": [6,8] },
  "mix": { "samples": 10, "uniqueHopSets": 8, "minHopsBalanced": 2, "minHopsStrict": 3 },
  "governance": { "asCapApplied": true, "orgCapApplied": true, "ackSpanAS": 24, "ackSpanISD": 3 },
  "bootstrap": { "rotationEpochs": 3, "beaconSetEntropySources": 3, "deterministicSeedDetected": false },
  "ledger": { "finalitySets": ["handshake","filecoin","raven-l2"], "emergencyAdvanceUsed": false },
  "voucher": { "structCount128B": 1, "frostGroupThreshold": {"n":5, "t":3} },
  "provenance": { "predicateType": "https://slsa.dev/provenance/v1", "builderId": "github.com/...", "binaryDigest": "sha256:..." }
}
Each check states: required evidence keys, accepted alternative signals, downgrade logic if absent.

Security & Hardening Changes
----------------------------
- [ ] Pin all GitHub Actions by commit SHA.
- [ ] permissions: { contents: read, id-token: write (provenance only) } others: none.
- [ ] Concurrency lock: compliance-linter-${{ github.ref }}.
- [ ] Network enrichment: default off, explicit flags, global timeout & max outbound hosts allowlist.
- [ ] Safe sandbox for harness (limit runtime, memory; kill on overrun).

Anti-Evasion Techniques
-----------------------
- [ ] Multi-signal threshold: referencing required % of independent evidence categories.
- [ ] Entropy / dispersion check: detect dense unreferenced spec tokens.
- [ ] Cross-correlation: confirm tokens have code references (e.g., function names) not just string table cluster.
- [ ] Optional signature of evidence (future PGP / minisign) + hash chain recorded in output.

Success Metrics & Quality Gates
------------------------------
- [ ] Coverage: 100% of 13 normative items have at least one non-heuristic (structural, dynamic, or artifact) evidence path.
- [ ] Heuristic-only passes: 0 in strict mode; ≤ 30% in transitional mode (beta) with warnings.
- [ ] False Positive Rate (target): < 2% on adversarial synthetic binaries.
- [ ] False Negative Rate (target): < 5% on curated compliant reference implementations.
- [ ] Reproducibility verification: binary hash match on clean rebuild; failure halts compliance pass for item 13.
- [ ] Performance: harness run ≤ 90s on reference hardware (calibration capture ≤ 15s, fallback simulation ≤ 10s) or check skipped with clear downgraded status.

Initial Implementation Order (Action Queue)
------------------------------------------
1. [x] README matrix + strict/heuristic mode + check metadata.
2. [x] Add evidence ingestion (JSON path via --evidence-file) wiring; adapt existing checks to accept external evidence.
3. [x] Harden GitHub Action + provenance generation & reproducibility verify step. (Implemented: workflow scaffold, action SHAs pinned, provenance parsing, binary digest validation, rebuild mismatch enforcement, artifact evidence upgrade, SBOM ingestion + materials/SBOM cross-check, materials completeness flag, signature field placeholder. Future enhancement (outside Step 3 scope): real cryptographic signature verification & advanced materials policy.)
4. [x] Static parsers (ClientHello template, Noise pattern, voucher struct) — implemented enriched ALPN + TLS extension ordering hash, Noise pattern detection, voucher struct triad with proximity span; checks 12–14 produce static-structural evidence.
5. [x] Dynamic harness foundation (static pattern extraction -> evidence JSON; schemaVersion, TLS probe (--probe-host) capturing negotiated ALPN/cipher/handshake time; added UDP→TCP fallback simulation (--fallback-host) recording delay, connect ms, cover connection teardown timing; pending future expansion for raw ClientHello capture, Noise rekey observation, HTTP/2 SETTINGS tolerances, jitter statistics).
6. [x] Governance & ledger evidence validation logic (ingestion via --governance-file; artifact checks 15 & 16; derives AS/org caps from raw weights; parses CBOR quorum certificates, validates aggregate threshold; flags partitions & emergency advance; future enhancement: signature cryptographic validation & historical diversity dataset integration).
7. [x] Mix diversity sampling + privacy refinement. (Implemented: mix evidence schema, harness simulation w/ deterministic option, CLI flags --mix-samples/--mix-hops-range/--mix-deterministic, Check 17 with hop depth + uniqueness + diversity index thresholds, Privacy Hop Enforcement upgraded to dynamic when mix evidence present.)
8. [x] Multi-signal scoring & anti-evasion heuristics. (Implemented: Check 18 requiring ≥2 category evidences, weighted multi-signal scoring summary, keyword stuffing density heuristic that flags/fails suspected token padding when evidence diversity insufficient, warnings surfaced in result for suspicious cases.)
9. [x] Full dynamic harness expansion (initial simulation implemented: rekey event, HTTP/2 adaptive jitter metrics, Checks 19 & 20, CLI flags --rekey-simulate/--h2-adaptive-simulate/--jitter-samples; future: real capture, HTTP/3, calibration baselines, statistical variance tests).
10. [x] Structural introspection & negative assertions (binary meta introspection, static ClientHello template extraction, enhanced Noise XK pattern detail, negative assertion check, evidence schema v2 + documentation, new checks 21–23; pending future dynamic calibration & deeper JA3/JA4 + QUIC Initial capture).

Potential Risks & Mitigations
-----------------------------
- [ ] Complexity creep: Keep harness modular; evidence schema versioned.
- [ ] Flaky dynamic timing (jitter windows): Use tolerances & statistical acceptance (e.g., 95% CI) rather than single thresholds.
- [ ] Supply chain attack via pinned SHAs: maintain periodic audit script to re-verify pinned commit provenance.
- [ ] Evidence forgery: future signature requirement; multi-signal correlation lowers forgery value.

Open Questions / Future Enhancements
------------------------------------
- [ ] Formal grammar for access ticket parsing? (May add minimal decoder to validate structure.)
- [ ] Integrate container-based reproducible build sandbox (e.g., Docker + rootless) vs GitHub ephemeral runner only.
- [ ] Optional WASM plugin interface for community-contributed dynamic scenarios.

Key Caveats & Clarifications (Required for Full Normative Claim)
----------------------------------------------------------------
1. [ ] TLS Calibration: Implement deterministic comparison of ALPN set & order, extension ordering (stable SHA256 over ordered extensions), JA3/JA4 family classification, HTTP/2 SETTINGS tolerance math (±15% where spec allows; else exact). Provide granular failure codes.
2. [ ] ECH Verification: Confirm actual encrypted ClientHello acceptance (e.g., by detecting expected certificate sequence / absence of outer SNI) rather than token presence.
3. [ ] Negative Assertions: Enforce absence of legacy transition header on public network targets; enforce absence of deterministic DHT seed constants in 1.1 builds.
4. [ ] Rekey Policy: Validate triggers (≥8 GiB OR ≥ 2^16 frames OR ≥1 h) via transcript observation or instrumentation counters; fail if unobserved and no static justification.
5. [ ] Anti-Correlation Timing: Measure UDP failure → TCP retry delay window, cover connection launch counts, teardown timing; enforce numeric bounds.
6. [ ] Governance Partition Safety: Consume 7‑day historical path diversity & ACK composition dataset to verify no >20% degradation pre-activation.
7. [ ] Adaptive PoW & Rate-Limits: Assess difficulty adjustment convergence toward target acceptance percentile; token-only signals insufficient.
8. [ ] Emergency Advance Logic: Validate 14-day liveness failure prerequisite, quorum certificate weight sum, unique signatures, epoch monotonicity.
9. [ ] Voucher Cryptographic Check: Optionally verify aggregatedSig64 valid over secret32 when keyset public keys supplied.
10. [ ] FROST Threshold: Confirm n ≥ 5 and t = 3 explicitly (not keyword guess).
11. [ ] Reproducible Build Environment: Pin toolchain versions and record them in provenance materials list; diff both build outputs.
12. [ ] Evidence Authenticity: Future signing (minisign/cosign) for evidence JSON; linter verifies signature before trust.
13. [ ] Statistical Jitter: Collect distributions (PING cadence, idle padding, PRIORITY emission) and test randomness (variance / chi-square heuristic) within ranges.
14. [ ] PQ Date Boundary: UTC-based comparison with explicit ISO date parsing and logged override usage.
15. [ ] Algorithm Agility Registry (Spec §2): Document presence/absence; note non-compliance impact though outside §11.
16. [ ] Multi-Signal Corroboration: Each normative pass must cite ≥2 independent evidence categories.

Testing & Validation Additions
------------------------------
Categories:
- [ ] Unit: Parsers (ClientHello, Noise pattern, voucher struct, CBOR quorum cert), provenance verifier, negative assertions.
- [ ] Property/Fuzz: CBOR quorum certificate parser (malformed inputs), voucher entropy/size validation.
- [ ] Dynamic Harness (Mock/Replay): Simulated transcripts for calibration, rekey detection, fallback timing, jitter distribution.
- [ ] Adversarial: Binaries with stuffed spec keywords but no behavior; should fail multi-signal requirements.
- [ ] Golden Evidence: Compliant & intentionally altered evidence fixtures (ALPN order mismatch, missing rekey event) with expected results.
- [ ] Reproducibility: Dual build hash equality; perturbation test (alter SOURCE_DATE_EPOCH) must fail.
- [ ] Performance: Track harness runtime; assert under SLA or mark skipped with downgrade.

Instrumentation & Metrics:
- [ ] Heuristic vs Normative ratio printed in summary.
- [ ] False Positive corpus: require FP < 2%.
- [ ] Randomness sampling counts (must reach minimum sample size before passing adaptive jitter checks).

Automation (CI):
- [ ] jobs: unit-tests / property-tests / harness (nightly) / security-audit / provenance-verify / reproducibility.
- [ ] Action to regenerate compliance matrix & attach to build artifacts.

Documentation Updates
---------------------
README:
- [x] Compliance Matrix table (Spec Item | Check IDs | Evidence Types | Status | Strict Default).
- [x] Strict Mode semantics & exit codes (0 normative pass; 1 failure; 2 heuristic gap; 3 degraded environment when fail-on-degraded set).
- [ ] Evidence schema versioning & migration.
- [ ] Harness usage walkthrough (generate evidence → run linter with --evidence-file).
- [ ] Provenance verification example command & expected output snippet.
- [ ] Reproducible build guide (toolchain pin list, env vars: SOURCE_DATE_EPOCH, deterministic flags).
- [ ] Governance evidence formats (historical diversity, quorum certificates examples).
- [ ] Security & Hardening section (network off by default, sandbox limits, anti-evasion, planned evidence signing).
- [ ] Limitations & Non-Goals (explicit list until all phases done).
- [ ] Roadmap & phase completion markers.

Additional Docs (new files suggested):
- [ ] docs/evidence-schema.md
- [ ] docs/harness-scenarios.md
- [ ] docs/governance-validation.md
- [ ] docs/repro-build.md

Output & UX Changes (to document):
- [ ] JSON report: add fields: evidenceRefs[], multiSignalScore, heuristicContributionCount, warnings[].
- [ ] CLI flags: --strict (default true), --allow-heuristic, --evidence-file, --evidence-signature, --fail-on-network, --harness, --scenario, --max-harness-seconds, --provenance-file.
- [ ] Exit codes defined above.


Change Control
--------------
This document should be updated as phases complete. Track completion status inline or in CHANGELOG under a "Roadmap" heading.

---
Evidence Schema Version History
-------------------------------
- v1 (implicit): Heuristic-only fields (provenance (basic), governance, ledger, mix (early), noiseExtended (sim), h2Adaptive (sim)).
- v2 (Step 10): Added `binaryMeta`, `clientHelloTemplate`, `noisePatternDetail`, `negative` plus explicit `schemaVersion=2` marker.
- Planned v3 (Step 11+): `dynamicClientHelloCapture` (raw bytes + JA3/JA4), `quicInitial`, `statisticalJitter`, `signedEvidence`, potential `governanceHistoricalDiversity` dataset schema, and calibration baseline persistence (`calibrationBaseline`).

Multi-Signal Scoring Weights & Policy
-------------------------------------
Weights: artifact=3, dynamic=2, static=1, heuristic=0.
Policy Rules:
1. A normative §11 item requires ≥2 independent non-heuristic categories (any combination of static/dynamic/artifact) for a "strong pass" label.
2. Heuristic-only evidence cannot clear strict mode (exit code 2) unless `--allow-heuristic` is provided; even then it is annotated as advisory.
3. Check 18 (anti-evasion) fails if excessive spec token density exists without the category diversity above (keyword stuffing heuristic guard).
4. Roadmap graduation criteria for each pending dynamic feature include demonstrating uplift from heuristic→static or static→dynamic/artifact, reflected in a weight delta.
5. Future: introduce a minimum composite score threshold per item once ≥2 categories routinely available (target after real dynamic capture lands).

Provenance & Reproducibility (Current State)
-------------------------------------------
Implemented (Step 3 initial slice):
- Deterministic build (fixed SOURCE_DATE_EPOCH) + per-file SHA256 manifest and aggregate digest.
- (Placeholder) SLSA provenance ingestion and parsing (predicateType, builderId, subjects, materials subset) upgrading Build Provenance (Check 9) to artifact when matching binary digest.
- Rebuild verification comparing manifests; mismatch escalates details.
Pending Enhancements:
- Full action pinning to commit SHAs (partial today), signature/attestation verification, complete materials graph policy, detached evidence signing.
- Reproducible environment pin list & toolchain material hashing for tightened artifact trust.

Architecture Snapshot (Current)
-------------------------------
Core Modules: `index.ts` (orchestrator), `check-registry.ts` (23 declarative checks), `analyzer.ts` (single-pass extraction + schema v2 population + simulated dynamic evidence), `static-parsers.ts` & `binary-introspect.ts` (structural extraction), `heuristics.ts` (legacy/token heuristics), `sbom/` (CycloneDX & SPDX generation, feature tagging), `safe-exec.ts` (tooling wrapper), `governance-parser.ts` & ledger parsers (artifact ingestion), `sbom-validators.ts` (shape checks), `types.ts` (shared types).
Execution Model: single analyzer pass cached; parallel check evaluation with per-check timeout; multi-signal aggregation after evaluation.
Degradation Surface: tool availability (strings, nm, objdump, ldd, file, sha256sum), fallback streaming ASCII extraction (32MiB cap), platform diagnostics for Windows missing Unix toolchain.

Contribution & Escalation Path
------------------------------
Lifecycle of a Capability:
1. Heuristic token detection (initial coverage) → 2. Structural parser (static-structural) → 3. Dynamic harness capture (dynamic-protocol) → 4. External artifact / cryptographic validation (artifact).
Checklist for New Check (see CONTRIBUTING.md): registry entry (id/key/metadata), extraction added to analyzer or parser, tests (happy, negative, edge, version gate), documentation (README matrix + roadmap update), evidence type escalation plan recorded here.
Escalation Targets (Step 11 focus): Transport calibration (1→12/22 dynamic), Noise rekey (19 sim → real), HTTP/2/3 adaptive jitter (20 sim → real + statistical), Governance diversity (15 artifact depth), Fallback timing (new dynamic), Signed evidence (artifact authenticity layer).

Security Reporting & Hardening Summary
-------------------------------------
Report Vulnerabilities: see SECURITY.md (issue tracker or direct maintainer contact – avoid public disclosure pre-fix for critical issues).
Hardening Implemented: command timeouts (`safe-exec`), deterministic date override gating (UTC), sanitized SBOM names, degraded diagnostics, multi-signal anti-evasion, provenance & reproducibility scaffolding.
Planned Security Enhancements: evidence signature verification, action pin audit automation, sandboxed dynamic probe execution with resource quotas, artifact materials completeness policy, optional offline mode enforcement (--fail-on-network + allowlist).

Cross-Doc Pointers
------------------
For detailed schemas see `docs/evidence-schema.md`. For CI provenance workflow details see `docs/provenance-repro.md`. For architectural deep dive see `ARCHITECTURE.md`. Contribution guidance: `CONTRIBUTING.md`.

---
Legacy End (see ROADMAP.md for current status).
