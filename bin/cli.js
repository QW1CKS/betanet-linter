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
  .option('-v, --verbose', 'Verbose output')
  .option('--sbom-format <format>', 'SBOM format (cyclonedx|cyclonedx-json|spdx)', 'cyclonedx')
  .action(async (binaryPath, options) => {
    try {
      const checker = new BetanetComplianceChecker();
      
      console.log(`🔍 Checking Betanet compliance for: ${binaryPath}`);
      console.log('='.repeat(50));
      
      const results = await checker.checkCompliance(binaryPath, options);
      
      if (options.sbom) {
        const sbomPath = await checker.generateSBOM(binaryPath, options.sbomFormat);
        console.log(`📋 SBOM generated: ${sbomPath}`);
      }
      
      checker.displayResults(results, options.output);
      
      // Exit with appropriate code
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
  .option('-f, --format <format>', 'SBOM format (cyclonedx|cyclonedx-json|spdx)', 'cyclonedx')
  .option('-o, --output <path>', 'Output file path')
  .action(async (binaryPath, options) => {
    try {
      const checker = new BetanetComplianceChecker();
      const sbomPath = await checker.generateSBOM(binaryPath, options.format, options.output);
      
      console.log(`✅ SBOM generated successfully: ${sbomPath}`);
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