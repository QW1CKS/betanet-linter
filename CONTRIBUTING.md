# Contributing to Betanet Compliance Linter

Thanks for your interest in improving the linter. This project emphasizes transparent, heuristic-based evaluation rather than authoritative certification. Please read this guide before opening a PR.

## Core Philosophy
- Single-pass static binary analysis + lightweight string/symbol/dependency heuristics.
- Parallel, data‑driven check registry (23 checks) with `introducedIn` / `mandatoryIn` version metadata + `evidenceType`.
- Deterministic, UTC‑safe policy gating (e.g., post‑quantum mandatory epoch).
- SBOM generation is canonical in `src/sbom/` & orchestrated by `index.ts`.
- Degraded mode must surface clear diagnostics (platform, missingCoreTools, degradationReasons).

## Adding a New Compliance Check
1. Ideation
   - Confirm the feature is in (or proposed for) Betanet spec and can be detected statically.
   - If runtime probing is required, consider adding to ISSUE-059 dynamic probe roadmap instead.
2. Registry Entry
   - Edit `src/check-registry.ts`.
   - Provide: `id` (next integer), `key` (kebab-case), `name`, `description`, `introducedIn`, optional `mandatoryIn`, base `severity`, and `evidenceType` (`heuristic`, `static-structural`, `dynamic-protocol`, `artifact`).
   - Implement `evaluate(ctx)` returning `{ passed, message, details? }` (avoid heavy recomputation; rely on pre-populated analyzer evidence schema v2 fields).
3. Evidence Extraction
   - Prefer structural additions in analyzer (schema v2) or lightweight helper module (e.g., `binary-introspect.ts`).
   - Use heuristics only when structural/dynamic/artifact paths aren't yet feasible; plan an escalation path.
4. Severity Rubric
   - critical: Mandatory post‑epoch cryptography / protocol safety.
   - high: Security / privacy capabilities materially impacting trust.
   - medium: Strongly recommended interoperability features.
   - low: Informational / emerging enhancements.
5. Performance Guardrails
   - No unbounded full-file reads > 32MB (stream or cap if needed).
   - Prefer single pass over strings; avoid nested O(N*M) scans.
6. Test Coverage (update existing or new spec file)
   - Happy path (feature present)
   - Negative / false positive guard (near-miss tokens / keyword stuffing avoidance where relevant)
   - Edge case (stripped symbols / degraded tools / simulated dynamic absence)
   - Version gating if `mandatoryIn` specified
   - Multi-signal impact (ensure category attribution correct when adding new evidenceType)
7. Documentation
   - Update README feature list + 1.1 (or future) delta coverage table.
   - Add SBOM feature tag mapping if applicable (see below).
8. Backlog
   - Add an ISSUE entry (if not already) or mark resolved with [✓] once merged.

## Updating Analyzer / Structural Pipeline
- Keep extraction single-pass & cached.
- Update schema version if adding top-level evidence fields (increment and document in `docs/evidence-schema.md`).
- Append new degradation reason codes to `degradationReasons` where applicable.
- Maintain platform fallbacks (Windows path without `strings`, etc.).
- Avoid introducing blocking child processes per check; gather all raw material first.

## SBOM & Feature Tagging
- Tag capabilities via `betanet.feature=<token>` in CycloneDX metadata & SPDX PackageComment lines.
- Token format: domain-subfeature (e.g., `transport-webrtc`, `crypto-pq-hybrid`).
- Add mapping logic in `src/sbom/sbom-generator.ts`.
- Consider adding artifact-derived features (provenance, governance dataset) distinctly from heuristic tokens.

## Environment & Overrides
- Respect existing env conventions: `BETANET_*` prefix.
- For new time / threshold knobs, provide override parsing in `constants.ts` helper.

## Degraded Mode Principles
- Never silently ignore missing core tools.
- Provide concise summary plus reason codes (e.g., `missing:nm`, `missing:objdump`, `stripped:symbols`).
- Tests should assert presence of degraded summary when simulating missing tools.

## Coding Style
- TypeScript strictness: prefer explicit return types for exported functions.
- Avoid broad `any`; use union / discriminated shapes for check results.
- Keep patches minimal & avoid unrelated formatting churn.

## Commit Guidelines
- Conventional-ish short prefix (check, heuristics, sbom, docs, test, perf, arch, fix).
- Reference ISSUE IDs where relevant (e.g., `heuristics: refine kyber detection (ISSUE-006)`).

## Performance Tips
- Benchmark locally with large binaries only if necessary; do not commit them.
- Assert single `analyze()` invocation via test when adding new checks (protect memoization).
- Prefer deriving multiple signals from a shared parsed artifact (e.g., ClientHello template hash reused by calibration checks).

## Security & Safety
- Sanitize externally derived strings before embedding in SBOM.
- Avoid executing the target binary unless dynamic probe mode explicitly landed (future roadmap - ISSUE-059 / Step 11+).
- Treat provided evidence files (governance, provenance) as untrusted input—validate schema & size.

## Opening a PR
- All tests must pass (`npm test`).
- Update `issues-inconsistencies.txt` statuses for resolved items.
- Provide a short rationale & detection limits section in the PR description.

## Questions
Open a discussion or small draft PR early if the heuristic surface seems ambiguous.

Thank you for helping make the Betanet linter transparent, performant, and trustworthy.
