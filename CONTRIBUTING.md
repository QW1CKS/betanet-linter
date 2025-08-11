# Contributing to Betanet Compliance Linter

Thanks for your interest in improving the linter. This project emphasizes transparent, heuristic-based evaluation rather than authoritative certification. Please read this guide before opening a PR.

## Core Philosophy
- Single-pass static binary analysis + lightweight string/symbol/dependency heuristics.
- Parallel, data‑driven check registry (11 checks) with `introducedIn` / `mandatoryIn` version metadata.
- Deterministic, UTC‑safe policy gating (e.g., post‑quantum mandatory epoch).
- SBOM generation is canonical in `src/sbom/` & orchestrated by `index.ts`.
- Degraded mode must surface clear diagnostics (platform, missingCoreTools, degradationReasons).

## Adding a New Compliance Check
1. Ideation
   - Confirm the feature is in (or proposed for) Betanet spec and can be detected statically.
   - If runtime probing is required, consider adding to ISSUE-059 dynamic probe roadmap instead.
2. Registry Entry
   - Edit `src/check-registry.ts`.
   - Provide: `id` (next integer), `key` (kebab-case), `name`, `description`, `introducedIn`, optional `mandatoryIn`, and base `severity`.
   - Implement `evaluate(ctx)` returning `{ passed, message, details? }`.
3. Heuristic Extraction
   - Reuse `BinaryAnalyzer` capabilities or extend it minimally (avoid N extra external tool invocations).
   - Add constants / regex to `heuristics.ts` or feature-specific analyzer module.
4. Severity Rubric
   - critical: Mandatory post‑epoch cryptography / protocol safety.
   - high: Security / privacy capabilities materially impacting trust.
   - medium: Strongly recommended interoperability features.
   - low: Informational / emerging enhancements.
5. Performance Guardrails
   - No unbounded full-file reads > 32MB (stream or cap if needed).
   - Prefer single pass over strings; avoid nested O(N*M) scans.
6. Test Coverage (update `tests/compliance-checker.test.ts` or create new file)
   - Happy path (feature present)
   - Negative / false positive guard (near-miss tokens)
   - Edge case (stripped symbols / degraded tools)
   - Version gating if `mandatoryIn` specified
7. Documentation
   - Update README feature list + 1.1 (or future) delta coverage table.
   - Add SBOM feature tag mapping if applicable (see below).
8. Backlog
   - Add an ISSUE entry (if not already) or mark resolved with [✓] once merged.

## Updating BinaryAnalyzer
- Ensure added extraction remains cached (do not bypass memoization).
- Append any new degradation reason codes to `degradationReasons`.
- Keep platform-specific fallbacks behind capability checks (e.g., Windows without `strings`).

## SBOM Feature Tagging
- Tag new capabilities via `betanet.feature=<token>` in CycloneDX metadata & SPDX PackageComment lines.
- Token format: domain-subfeature (e.g., `transport-webrtc`, `crypto-pq-hybrid`).
- Add mapping logic in `src/sbom/sbom-generator.ts`.

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
- Consider adding micro-tests asserting single `analyze()` invocation per run.

## Security & Safety
- Sanitize externally derived strings before embedding in SBOM.
- Avoid executing the target binary unless future dynamic probe mode is explicitly implemented (ISSUE-059).

## Opening a PR
- All tests must pass (`npm test`).
- Update `issues-inconsistencies.txt` statuses for resolved items.
- Provide a short rationale & detection limits section in the PR description.

## Questions
Open a discussion or small draft PR early if the heuristic surface seems ambiguous.

Thank you for helping make the Betanet linter transparent, performant, and trustworthy.
