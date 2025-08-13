Provenance & Reproducibility Workflow (Phase 5 Implemented)
==========================================================

Scope
-----
Implements Phase 5 roadmap: hardened CI producing build hash manifest, provisional SLSA provenance ingestion, reproducible rebuild verification, and materials ↔ SBOM cross‑checks.

Workflow Overview
-----------------
Workflow file: `.github/workflows/provenance-repro.yml` with two jobs (build, rebuild).

Build job steps:
- Checkout (actions/checkout pinned by commit SHA)
- Node setup (actions/setup-node pinned) fixed NODE_VERSION
- `npm ci` then `npm run build`
- Hash manifest: sorted file list of `dist/` -> `dist.sha256sum` + aggregate digest
- Optional SLSA provenance generation via SLSA generator (pinned action) (future cryptographic verification)
- Provenance reference JSON emitted into `evidence/`

Rebuild job steps:
- Repeat clean build & manifest creation
- Diff manifests for reproducibility assertion (repro:verify script)
- Run linter with evidence & SBOM file to upgrade Build Provenance to artifact evidence (materialsValidated/materialsMismatchCount)

Current Status & Next Steps
----------------------------
- Actions pinned by commit SHA (checkout, setup-node, upload-artifact, github-script) – done.
- Rebuild digest mismatch flagged via provenance.rebuildDigestMismatch.
- Materials vs SBOM digests cross-check: sets provenance.materialsValidated & materialsMismatchCount.
- Detached evidence signature verification (Phase 7) marks provenance.signatureVerified (separate from SLSA attestation sig).
- DSSE envelope signer counting & optional key mapping (`--dsse-public-keys`) implemented; multi-signer bundle hashing via `--evidence-bundle` (bundleSha256, threshold flag).
- Next: verify DSSE / SLSA attestation signatures (cryptographic), enforce materials completeness policy (all SBOM components referenced), record toolchain version set in provenance materials, aggregated signature (FROST) voucher validation.

Local Reproduction
------------------
```
export SOURCE_DATE_EPOCH=1700000000
npm ci && npm run build
find dist -type f -print0 | sort -z | xargs -0 sha256sum > dist.sha256sum
sha256sum dist.sha256sum | cut -d' ' -f1
betanet-lint check bin/cli.js --output json --evidence-file dist.sha256sum > compliance.json
jq '.checks[] | select(.id==9) | {id,evidenceType,details}' compliance.json
```

Evidence Parsing & Validation
-----------------------------
Accepted inputs:
1. DSSE envelope containing SLSA predicate (payload base64 JSON) → extracts predicateType, builderId, subjects[], materials[].
2. Raw SLSA provenance JSON (unwrapped) → direct predicate extraction.
3. Simple legacy placeholder JSON (binaryDistDigest / provenance object).

Upgrade to artifact evidence (Check 9) when:
- predicateType starts with https://slsa.dev/
- builderId present
- Subject digest matches analyzed binary sha256
- (Optional) materials digests cross-match SBOM components (materialsValidated=true)

Additional flags: rebuildDigestMismatch, materialsComplete, signatureVerified (detached evidence signature, not DSSE yet).

See `ROADMAP.md` for tracking of remaining provenance hardening tasks.
