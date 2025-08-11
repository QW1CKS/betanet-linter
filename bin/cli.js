#!/usr/bin/env node

const { program } = require('commander');
const path = require('path');
const { BetanetComplianceChecker } = require('../dist/index');

program
  .name('betanet-lint')
  .description('CLI tool for checking Betanet specification compliance')
  .version('1.0.0');

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
  .option('-v, --verbose', 'Verbose output')
  .option('--sbom-format <format>', 'SBOM format (cyclonedx|cyclonedx-json|spdx|spdx-json)', 'cyclonedx')
  .action(async (binaryPath, options) => {
    try {
      const checker = new BetanetComplianceChecker();
      console.log('='.repeat(50));
      
  const results = await checker.checkCompliance(binaryPath, {
        checkFilters: options.checkFilters,
        verbose: options.verbose,
        severityMin: options.severityMin,
        forceRefresh: options.forceRefresh,
        maxParallel: options.maxParallel,
        checkTimeoutMs: options.checkTimeout
      });
      
      if (options.sbom) {
        const sbomPath = await checker.generateSBOM(binaryPath, options.sbomFormat);
        console.log(`📋 SBOM generated: ${sbomPath}`);
        if (options.validateSbom || options.strictSbom) {
          await require('./validate-sbom')(binaryPath, sbomPath, options.sbomFormat, options.strictSbom);
        }
      }
      
      checker.displayResults(results, options.output);
      
      // Exit with appropriate code
      if (options.failOnDegraded && results.diagnostics?.degraded) {
        process.exit(1);
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

program.parse();