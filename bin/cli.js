#!/usr/bin/env node

const { program } = require('commander');
const path = require('path');
const fs = require('fs');
// Support running from source in development while using dist in packaged form
let BetanetComplianceChecker;
try {
  ({ BetanetComplianceChecker } = require('../dist/index'));
} catch (e) {
  ({ BetanetComplianceChecker } = require('../src/index'));
}

let pkgVersion = '0.0.0';
try {
  const pkgPath = path.join(__dirname, '..', 'package.json');
  const raw = fs.readFileSync(pkgPath, 'utf8');
  pkgVersion = JSON.parse(raw).version || pkgVersion;
} catch { /* ignore */ }

program
  .name('betanet-lint')
  .description('CLI tool for checking Betanet specification compliance')
  .version(pkgVersion);

program
  .command('version')
  .description('Print version and exit')
  .action(() => {
    console.log(pkgVersion);
  });

program
  .command('check')
  .description('Check a binary for Betanet compliance')
  .argument('<binary>', 'Path to the binary to check')
  .option('-o, --output <format>', 'Output format (json|table|yaml)', 'table')
  .option('-s, --sbom', 'Generate Software Bill of Materials')
    .option('--validate-sbom', 'Validate generated SBOM structure (shape)')
    .option('--strict-sbom', 'Fail if SBOM fails strict schema shape validation (implies --validate-sbom)')
  .option('--severity-min <level>', 'Minimum severity to include in scoring (minor|major|critical)', 'minor')
  .option('--force-refresh', 'Ignore cached analysis and re-run extraction')
  .option('--fail-on-degraded', 'Exit non-zero if analysis degraded (missing/timeout tools)')
  .option('--max-parallel <n>', 'Maximum concurrent check evaluations', v => parseInt(v,10))
  .option('--check-timeout <ms>', 'Per-check timeout in milliseconds', v => parseInt(v,10))
  .option('--dynamic-probe', 'Attempt lightweight runtime probe (e.g. --help) to enrich heuristics')
  .option('--strict', 'Enable strict mode (heuristic passes do not count unless --allow-heuristic)', true)
  .option('--allow-heuristic', 'In strict mode, allow heuristic passes to count toward compliance', false)
  .option('--evidence-file <path>', 'Path to external evidence JSON for normative checks (Phase 1)')
  .option('--sbom-file <path>', 'Path to SBOM file (CycloneDX XML/JSON or SPDX tag/json) for materials cross-check')
  .option('--governance-file <path>', 'Governance & ledger evidence JSON (Phase 6)')
  .option('--enable-network', 'Allow network enrichment operations (default off)')
  .option('--fail-on-network', 'Fail if any network access attempted while disabled')
  .option('--network-allow <hosts>', 'Comma-separated host allowlist when network enabled')
  .option('--evidence-signature <path>', 'Detached evidence JSON signature file (Phase 7)')
  .option('--evidence-public-key <path>', 'Evidence signing public key file (ed25519)')
  .option('--dsse-public-keys <path>', 'JSON map of keyid->public key (PEM or base64) for DSSE envelope verification')
  .option('--dsse-required-keys <csv>', 'Comma-separated list of required DSSE key ids (policy)')
  .option('--dsse-threshold <n>', 'Numeric threshold of distinct verified signers required (default 1)')
  .option('--evidence-bundle <path>', 'Multi-signer evidence bundle JSON (array of {evidence,signature,publicKey,signer})')
  .option('--fail-on-sig-invalid', 'Exit non-zero if evidence signature invalid')
  .option('--strict-auth', 'Require evidence authenticity (detached signature or bundle) for artifact elevation (Task 11)', false)
  // Task 28 supply chain hardening / attestation & manifest flags
  .option('--provenance-attestation-signature <path>', 'Detached signature over raw provenance evidence file (Task 28)')
  .option('--provenance-attestation-public-key <path>', 'Public key for provenance attestation (base64 raw 32B ed25519 or PEM)')
  .option('--sbom-attestation-signature <path>', 'Detached signature over SBOM file (Task 28)')
  .option('--sbom-attestation-public-key <path>', 'Public key for SBOM attestation (base64 raw 32B ed25519 or PEM)')
  .option('--checksum-manifest-file <path>', 'Checksum manifest file (sha256sum style)')
  .option('--checksum-manifest-signature <path>', 'Detached signature over checksum manifest')
  .option('--checksum-manifest-public-key <path>', 'Public key for checksum manifest signature (base64 raw 32B ed25519 or PEM)')
  .option('--environment-lock-file <path>', 'Environment/toolchain lock file (JSON) to record build inputs (Task 28)')
  // Task 29 Security & Sandbox Hardening flags
  .option('--sandbox-cpu-budget-ms <ms>', 'Sandbox CPU elapsed time budget (wall clock) in ms before violation', v => parseInt(v,10))
  .option('--sandbox-memory-budget-mb <mb>', 'Sandbox RSS memory budget in MB before violation', v => parseInt(v,10))
  .option('--sandbox-fs-deny', 'Deny filesystem write operations (records violations)')
  .option('--sandbox-network-deny', 'Force deny network operations even if --enable-network specified (records blocked attempts)')
  .option('-v, --verbose', 'Verbose output')
  .option('--format <format>', 'SBOM format (cyclonedx|cyclonedx-json|spdx|spdx-json)', 'cyclonedx')
  .option('--sbom-format <format>', '[DEPRECATED] SBOM format (use --format)', undefined)
  .option('-c, --checks <checks>', 'Comma-separated list of check IDs to include')
  .option('-x, --exclude <checks>', 'Comma-separated list of check IDs to exclude')
  .action(async (binaryPath, options) => {
    try {
      const checker = new BetanetComplianceChecker();
      console.log('='.repeat(50));
      // Build checkFilters if inclusion/exclusion specified (ISSUE-040)
      let checkFilters = undefined;
      if (options.checks || options.exclude) {
        checkFilters = {};
        if (options.checks) {
          checkFilters.include = options.checks.split(',').map(n => parseInt(n.trim(),10)).filter(n => !isNaN(n));
        }
        if (options.exclude) {
          checkFilters.exclude = options.exclude.split(',').map(n => parseInt(n.trim(),10)).filter(n => !isNaN(n));
        }
      }
      const results = await checker.checkCompliance(binaryPath, {
        checkFilters,
        verbose: options.verbose,
        severityMin: options.severityMin,
        forceRefresh: options.forceRefresh,
        maxParallel: options.maxParallel,
        checkTimeoutMs: options.checkTimeout,
        dynamicProbe: options.dynamicProbe,
        strictMode: options.strict !== undefined ? options.strict : true,
        allowHeuristic: options.allowHeuristic,
    evidenceFile: options.evidenceFile
  , sbomFile: options.sbomFile, governanceFile: options.governanceFile,
  enableNetwork: options.enableNetwork,
  failOnNetwork: options.failOnNetwork,
  networkAllowlist: options.networkAllow ? options.networkAllow.split(',').map(h=>h.trim()).filter(Boolean) : undefined,
  evidenceSignatureFile: options.evidenceSignature,
  evidencePublicKeyFile: options.evidencePublicKey,
  dssePublicKeysFile: options.dssePublicKeys,
  dsseRequiredKeys: options.dsseRequiredKeys,
  dsseThreshold: options.dsseThreshold ? parseInt(options.dsseThreshold,10) : undefined,
  evidenceBundleFile: options.evidenceBundle,
  failOnSignatureInvalid: options.failOnSigInvalid
  , strictAuthMode: options.strictAuth
  , provenanceAttestationSignatureFile: options.provenanceAttestationSignature,
  provenanceAttestationPublicKeyFile: options.provenanceAttestationPublicKey,
  sbomAttestationSignatureFile: options.sbomAttestationSignature,
  sbomAttestationPublicKeyFile: options.sbomAttestationPublicKey,
  checksumManifestFile: options.checksumManifestFile,
  checksumManifestSignatureFile: options.checksumManifestSignature,
  checksumManifestPublicKeyFile: options.checksumManifestPublicKey,
  environmentLockFile: options.environmentLockFile
  , sandboxCpuBudgetMs: options.sandboxCpuBudgetMs,
  sandboxMemoryBudgetMb: options.sandboxMemoryBudgetMb,
  sandboxFsWriteDeny: options.sandboxFsDeny,
  sandboxNetworkDeny: options.sandboxNetworkDeny
      });
      
      if (options.sbom) {
        // Support deprecated --sbom-format; prefer --format
        const deprecatedUsed = options.sbomFormat && !options.format;
        const sbomFormat = options.format || options.sbomFormat || 'cyclonedx';
        if (deprecatedUsed) {
          console.warn('[DEPRECATION] --sbom-format is deprecated and will be removed in a future release. Use --format instead.');
        }
        const sbomPath = await checker.generateSBOM(binaryPath, sbomFormat);
        console.log(`📋 SBOM generated: ${sbomPath}`);
        if (options.validateSbom || options.strictSbom) {
          await require('./validate-sbom')(binaryPath, sbomPath, sbomFormat, options.strictSbom);
        }
      }
      
      checker.displayResults(results, options.output);
      
      // Fail if network attempts occurred while disabled and user requested strict failure
      if (!options.enableNetwork && options.failOnNetwork && results.diagnostics?.networkOps?.some(op => op.blocked)) {
        console.error('❌ Network operations attempted while disabled.');
        process.exit(1);
      }
      // Exit with appropriate code
      if (options.failOnSigInvalid && results?.diagnostics?.evidenceSignatureValid === false) {
        process.exit(1);
      }
      if (options.failOnDegraded && results.diagnostics?.degraded) {
        process.exit(1);
      }
      if (options.failOnDegraded && results.diagnostics?.degraded) {
        process.exit(1);
      }
      // Exit code 2 for heuristic gap in strict mode
      if (results.strictMode && !results.allowHeuristic && results.heuristicContributionCount > 0 && !results.passed) {
        process.exit(2);
      }
      process.exit(results.passed ? 0 : 1);
    } catch (error) {
      console.error('❌ Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('sbom')
  .description('Generate Software Bill of Materials for a binary')
  .argument('<binary>', 'Path to the binary')
  .option('-f, --format <format>', 'SBOM format (cyclonedx|cyclonedx-json|spdx|spdx-json)', 'cyclonedx')
    .option('--validate-sbom', 'Validate SBOM structure (shape)')
    .option('--strict-sbom', 'Fail on strict validation errors (implies --validate-sbom)')
  .option('-o, --output <path>', 'Output file path')
  .action(async (binaryPath, options) => {
    try {
      const checker = new BetanetComplianceChecker();
      const sbomPath = await checker.generateSBOM(binaryPath, options.format, options.output);
      
      console.log(`✅ SBOM generated successfully: ${sbomPath}`);
      if (options.validateSbom || options.strictSbom) {
        await require('./validate-sbom')(binaryPath, sbomPath, options.format, options.strictSbom);
      }
    } catch (error) {
      console.error('❌ Error generating SBOM:', error.message);
      process.exit(1);
    }
  });

program
  .command('validate')
  .description('Validate a Betanet implementation against specific requirements')
  .argument('<binary>', 'Path to the binary')
  .option('-c, --checks <checks>', 'Comma-separated list of checks to run (1-10)')
  .option('-x, --exclude <checks>', 'Comma-separated list of checks to exclude')
  .action(async (binaryPath, options) => {
    try {
      const checker = new BetanetComplianceChecker();
      
      let checkFilters = {};
      if (options.checks) {
        checkFilters.include = options.checks.split(',').map(n => parseInt(n.trim()));
      }
      if (options.exclude) {
        checkFilters.exclude = options.exclude.split(',').map(n => parseInt(n.trim()));
      }
      
      const results = await checker.checkCompliance(binaryPath, { checkFilters });
      checker.displayResults(results, 'table');
      
      process.exit(results.passed ? 0 : 1);
    } catch (error) {
      console.error('❌ Error:', error.message);
      process.exit(1);
    }
  });

program
  .command('harness')
  .description('Run dynamic harness skeleton to generate evidence JSON')
  .argument('<binary>', 'Path to the binary')
  .option('-o, --out <file>', 'Output evidence JSON file', 'harness-evidence.json')
  .option('-s, --scenarios <list>', 'Comma-separated scenario keys', v => v.split(',').map(x=>x.trim()).filter(Boolean))
  .option('--probe-host <host>', 'Perform a TLS probe against host:443 (foundation for dynamic evidence)')
  .option('--probe-port <port>', 'TLS probe port (default 443)', v => parseInt(v,10))
  .option('--probe-timeout <ms>', 'TLS probe timeout ms (default 5000)', v => parseInt(v,10))
  .option('--fallback-host <host>', 'Simulate UDP->TCP fallback against host')
  .option('--fallback-udp-port <port>', 'UDP port for fallback simulation (default 443)', v => parseInt(v,10))
  .option('--fallback-tcp-port <port>', 'TCP port for fallback simulation (default 443)', v => parseInt(v,10))
  .option('--fallback-udp-timeout <ms>', 'UDP wait before TCP retry (default 300)', v => parseInt(v,10))
  .option('--cover-connections <n>', 'Simulated cover TCP connections after main fallback', v => parseInt(v,10))
  .option('--mix-samples <n>', 'Simulate mix path sampling (number of samples)', v => parseInt(v,10))
  .option('--mix-hops-range <a,b>', 'Range of hops per path (e.g. 2,4)', v => v.split(',').map(x=>parseInt(x,10)).slice(0,2))
  .option('--mix-deterministic', 'Deterministic pseudo-random mix sampling for reproducible CI')
  .option('--rekey-simulate', 'Simulate observing a Noise rekey event (Step 9 placeholder)')
  .option('--h2-adaptive-simulate', 'Simulate HTTP/2 adaptive padding/jitter evidence (Step 9 placeholder)')
  .option('--jitter-samples <n>', 'Number of simulated jitter samples (default 20)', v => parseInt(v,10))
  .option('--clienthello-simulate', 'Simulate dynamic ClientHello capture & calibration (Step 11 placeholder)')
  .option('--clienthello-capture <host>', 'Attempt real ClientHello capture against host:port (uses openssl)')
  .option('--clienthello-capture-port <port>', 'Port for real ClientHello capture (default 443)', v => parseInt(v,10))
  .option('--openssl-path <path>', 'Path to openssl binary (default "openssl")')
  .action(async (binaryPath, options) => {
    try {
    const { runHarness } = require('../src/harness');
    const clientHelloCapture = options.clienthelloCapture ? { host: options.clienthelloCapture, port: options.clienthelloCapturePort, opensslPath: options.opensslPath } : undefined;
  const out = await runHarness(binaryPath, options.out, { scenarios: options.scenarios, probeHost: options.probeHost, probePort: options.probePort, probeTimeoutMs: options.probeTimeout, fallbackHost: options.fallbackHost, fallbackUdpPort: options.fallbackUdpPort, fallbackTcpPort: options.fallbackTcpPort, fallbackUdpTimeoutMs: options.fallbackUdpTimeout, coverConnections: options.coverConnections, mixSamples: options.mixSamples, mixHopsRange: options.mixHopsRange, mixDeterministic: options.mixDeterministic, rekeySimulate: options.rekeySimulate, h2AdaptiveSimulate: options.h2AdaptiveSimulate, jitterSamples: options.jitterSamples, clientHelloSimulate: options.clienthelloSimulate, clientHelloCapture });
      console.log(`✅ Harness evidence written to ${out}`);
    } catch (e) {
      console.error('❌ Harness error:', e.message);
      process.exit(1);
    }
  });

program.parse();