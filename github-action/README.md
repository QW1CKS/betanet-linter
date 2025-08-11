# Betanet Compliance GitHub Action

This directory contains GitHub Action templates for automated Betanet specification compliance checking.

## Files

### 1. `betanet-compliance.yml`
A comprehensive workflow that:
- Automatically finds binary files in your repository
- Runs compliance checks on each binary
- Generates SBOM files in both CycloneDX and SPDX formats
- Uploads results as artifacts
- Comments on pull requests with compliance results
- Sets commit status checks

### 2. `reusable-compliance.yml`
A reusable workflow that can be called from other workflows. It provides:
- Flexible input parameters
- Configurable output formats
- Optional SBOM generation
- Artifact uploads
- Summary reporting

### 3. `example-workflow.yml`
An example showing how to use the reusable workflow in your CI/CD pipeline.

## Usage

### Option 1: Using the comprehensive workflow

1. Copy `betanet-compliance.yml` to your repository's `.github/workflows/` directory
2. The workflow will automatically run on pushes, pull requests, and daily schedules
3. It will find and check all executable binaries in your repository. Use `--format` to control SBOM format when `--sbom` is enabled (legacy `--sbom-format` is deprecated).

### Option 2: Using the reusable workflow

1. Copy `reusable-compliance.yml` to your repository's `.github/workflows/` directory
2. Create your own workflow that calls the reusable workflow:

```yaml
name: My Compliance Check

on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Build my application
      run: |
        # Your build commands here
        make build
        
    - name: Upload binary
      uses: actions/upload-artifact@v3
      with:
        name: my-binary
        path: ./my-app
        retention-days: 1

  compliance:
    needs: build
    uses: ./.github/workflows/reusable-compliance.yml
    with:
      binary-path: './my-app'
      generate-sbom: true
      output-format: 'json'
      fail-on-error: true
```

## Input Parameters

### For `reusable-compliance.yml`

| Parameter | Description | Required | Default | Options |
|-----------|-------------|----------|---------|---------|
| `binary-path` | Path to the binary to check | Yes | - | - |
| `generate-sbom` | Generate SBOM files | No | `true` | `true`, `false` |
| `output-format` | Output format for results | No | `json` | `json`, `table`, `console` |
| `fail-on-error` | Fail workflow if compliance check fails | No | `true` | `true`, `false` |

## Outputs

The workflows produce:

1. **Compliance Results**: JSON file with detailed compliance check results
2. **SBOM Files**: CycloneDX and SPDX format software bills of materials
3. **GitHub Summary**: Summary report in the GitHub Actions UI
4. **Pull Request Comments**: For PR workflows, comments with compliance results
5. **Commit Status**: Status checks indicating compliance status

## Artifacts

All workflows upload artifacts with:
- `compliance-results/`: Directory containing all results
- `compliance-report.md`: Human-readable report (comprehensive workflow)
- `sbom.cyclonedx.json`: CycloneDX SBOM
- `sbom.spdx`: SPDX SBOM

## Prerequisites

The workflows require:
- Ubuntu runner (latest)
- Node.js 18+
- Betanet Compliance Linter CLI tool

## Examples

### Basic Usage

```yaml
compliance:
  uses: ./.github/workflows/reusable-compliance.yml
  with:
    binary-path: './my-betanet-app'
```

### With All Options

```yaml
compliance:
  uses: ./.github/workflows/reusable-compliance.yml
  with:
    binary-path: './my-betanet-app'
    generate-sbom: true
    output-format: 'table'
    fail-on-error: false
```

### In a Build Pipeline

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Setup Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    - name: Build
      run: go build -o betanet-app ./cmd/main.go
    - name: Upload
      uses: actions/upload-artifact@v3
      with:
        name: binary
        path: betanet-app

  compliance:
    needs: build
    uses: ./.github/workflows/reusable-compliance.yml
    with:
      binary-path: 'betanet-app'
      generate-sbom: true
```

## Troubleshooting

### Binary Not Found
Ensure the binary path is correct and the binary is built before the compliance check runs.

### Permission Denied
Make sure the binary has execute permissions (`chmod +x binary`).

### Missing Dependencies
The workflow automatically installs the Betanet Compliance Linter. If installation fails, check network connectivity and npm registry access.

### SBOM Generation Fails
SBOM generation requires additional system tools (`strings`, `ldd`, `file`). These are typically available on Ubuntu runners. If tools are missing the run is marked degraded; set `BETANET_FAIL_ON_DEGRADED=1` to enforce failure. Prefer `--format cyclonedx-json` for machine ingestion.

## Support

For issues or questions about the GitHub Action templates, please refer to the main Betanet Compliance Linter documentation or create an issue in the repository.