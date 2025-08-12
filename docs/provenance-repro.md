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
- Pin actions to exact commit SHAs (currently using major tags with TODO comments).
- Signature / attestation verification (future) and record verification status in report.
- Materials cross-check against package lock digests.

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
The linter now ingests three formats:
1. DSSE envelope containing SLSA predicate (base64 payload) -> extracts predicateType, builderId, subjects[], materials[].
2. Raw SLSA provenance JSON (unwrapped) -> same field extraction.
3. Simple placeholder JSON with binaryDistDigest (legacy interim format).

Normative upgrade (artifact evidence) is granted only if:
- predicateType starts with https://slsa.dev/
- builderId is present
- A subject digest (sha256) matches the analyzed binary's computed sha256

See `ROADMAP.md` (Step 3 and subsequent) for progress tracking.
