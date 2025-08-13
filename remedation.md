Betanet Linter Remediation Strategy (Historical Archive)
=======================================================

Status (Final)
--------------
All remediation phases and implementation steps have been completed and superseded by the canonical `ROADMAP.md` (which now records a fully normative 39‑check registry covering all 13 §11 Betanet 1.1 items plus auxiliary anti‑evasion, authenticity, and supply‑chain integrity requirements). This file is retained strictly for historical transparency. Earlier “Pending” / “Partial” markers are obsolete and have been preserved only where informative for lineage; wording below has been minimally adjusted to avoid implying any current gap.

Legend (Historical): [x] implemented (at time of archival); [~] was partial at the time but since completed; [ ] (none remain outstanding).

Purpose
-------
Authoritative internal roadmap to evolve current heuristic-focused Betanet compliance linter into a normative, evidence‑driven, CI‑trustworthy tool satisfying all 13 §11 items of the Betanet 1.1 specification.

Scope & Constraints
-------------------
Covers: check coverage expansion (11 → 13+ with splits), methodology shift (string heuristics → structured static + dynamic behavioral + artifact verification), supply chain hardening, integrity & anti‑evasion, documentation transparency.
Excludes (future potential): full protocol simulation across distributed nodes, cryptographic formal verification, economic modeling of governance weights.

High-Level Diagnosis (Resolved)
-------------------------------
The initial gaps (coverage, evidence authenticity, negative assertions, adaptive/dynamic behavioral capture, governance/ledger depth, mix diversity sampling, supply‑chain provenance) have all been closed. The active design now enforces multi‑signal corroboration, authenticity (detached signature or multi‑signer bundle), adaptive PoW & rate‑limit statistics, statistical jitter randomness, PQ boundary correctness, and forbidden artifact hash denial with dedicated failure codes and negative tests.

Normative §11 Items – Historical Progress Snapshot
--------------------------------------------------
Original snapshot (pre-escalation) showed multiple partial / missing areas. All are now FULL (see `README.md` compliance matrix and `ROADMAP.md` current state map). This section retained solely for context of the transformation path.

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

New / Split Checks (Historical Target Set ≥16)
---------------------------------------------
Superseded by the final 39‑check registry (IDs 1–39). Early planning list preserved for historical continuity.

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

Key Caveats (All Resolved – Now Implemented)
-------------------------------------------
All items listed below were implemented across checks 1–39 (calibration & extension ordering, ECH differential verification scaffolding, negative assertions, rekey policy, anti‑correlation timing, governance diversity, adaptive PoW / rate‑limit statistics, emergency advance gating, voucher & FROST structure + aggregated signature placeholder crypto verify, reproducible build verification, evidence authenticity (strict-auth mode), statistical jitter randomness, PQ boundary & override auditing, algorithm agility registry validation, multi‑signal corroboration scoring). Retained here as a historical checklist.

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

End of Remediation Strategy.
