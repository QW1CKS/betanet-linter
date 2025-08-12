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
  , sbomFile: options.sbomFile
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
      
      // Exit with appropriate code
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
  .action(async (binaryPath, options) => {
    try {
      const { runHarness } = require('../src/harness');
      const out = await runHarness(binaryPath, options.out, { scenarios: options.scenarios, probeHost: options.probeHost, probePort: options.probePort, probeTimeoutMs: options.probeTimeout });
      console.log(`✅ Harness evidence written to ${out}`);
    } catch (e) {
      console.error('❌ Harness error:', e.message);
      process.exit(1);
    }
  });

program.parse();