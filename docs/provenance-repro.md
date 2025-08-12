Provenance & Reproducibility Workflow (Initial)
=============================================

Scope
-----
Implements the first slice of remediation roadmap step 3: hardened CI producing build hash manifest, provisional SLSA provenance, and rebuild verification.

Workflow Overview
-----------------
Workflow file: `.github/workflows/provenance-repro.yml` with two jobs (build, rebuild).

Build job steps:
- Checkout (actions/checkout@v4)
- Node setup (actions/setup-node@v4) fixed NODE_VERSION
- `npm ci` then `npm run build`
- Hash manifest: sorted file list of `dist/` -> `dist.sha256sum` + aggregate digest
- Optional SLSA provenance generation via slsa-framework generic workflow
- Provenance reference JSON emitted into `evidence/`

Rebuild job steps:
- Repeat clean build & manifest creation
- Diff manifests for reproducibility assertion
- Run linter with evidence file to upgrade Build Provenance heuristic

Next Steps
----------
- Pin actions to exact commit SHAs
- Add provenance predicate parsing & validation in check 9 (predicateType, builder ID, subjects/materials hash match)
- Replace placeholder evidence file with full provenance JSON path
- Add signature verification (future) and record verification status in report

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

See `remedation.md` Implementation Order step 3 for progress tracking.
