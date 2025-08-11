import { BinaryAnalyzer } from './analyzer';
import { ComplianceCheck, ComplianceResult, CheckOptions, SBOMComponent } from './types';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as xml2js from 'xml2js';
import { CHECK_REGISTRY, getChecksByIds } from './check-registry';

export class BetanetComplianceChecker {
  private _analyzer: BinaryAnalyzer;

  constructor() {
    // Will be initialized when checking compliance
    this._analyzer = null as any;
  }

  // Expose analyzer via getter so tests can spy/mock it safely
  get analyzer(): BinaryAnalyzer {
    return this._analyzer;
  }

  async checkCompliance(binaryPath: string, options: CheckOptions = {}): Promise<ComplianceResult> {
    // Allow tests or callers to pre-inject a mock analyzer; only create if absent
    if (!this._analyzer) {
      this._analyzer = new BinaryAnalyzer(binaryPath, options.verbose);
    }

    if (options.verbose) {
      console.log('🔍 Starting Betanet compliance check...');
    }

    // Resolve registry-based checks with filters
    const allIds = CHECK_REGISTRY.map(c => c.id);
    let checkIdsToRun = allIds;
    if (options.checkFilters?.include) {
      checkIdsToRun = checkIdsToRun.filter(id => options.checkFilters!.include!.includes(id));
    }
    if (options.checkFilters?.exclude) {
      checkIdsToRun = checkIdsToRun.filter(id => !options.checkFilters!.exclude!.includes(id));
    }
    const definitions = getChecksByIds(checkIdsToRun);
    const checks: ComplianceCheck[] = [];
    const now = new Date();
    for (const def of definitions) {
      const result = await def.evaluate(this._analyzer, now);
      checks.push(result);
    }

    // Calculate overall results
    const passedChecks = checks.filter(c => c.passed);
    const criticalChecks = checks.filter(c => c.severity === 'critical' && !c.passed);
    
  // Guard against zero checks (filters may exclude all)
  const overallScore = checks.length === 0 ? 0 : Math.round((passedChecks.length / checks.length) * 100);
  const passed = checks.length > 0 && passedChecks.length === checks.length && criticalChecks.length === 0;

    const diagnostics = ((): any => {
      const a: any = this.analyzer;
      if (a && typeof a.getDiagnostics === 'function') {
        try { return a.getDiagnostics(); } catch { return undefined; }
      }
      return undefined;
    })();

    const result: ComplianceResult = {
      binaryPath,
      timestamp: new Date().toISOString(),
      overallScore,
      passed,
      checks,
      summary: {
        total: checks.length,
        passed: passedChecks.length,
        failed: checks.length - passedChecks.length,
        critical: criticalChecks.length
      },
      diagnostics
    };

    return result;
  }

  // Legacy per-check methods removed (Plan 3 consolidation) in favor of registry-based evaluation

  async generateSBOM(binaryPath: string, format: 'cyclonedx' | 'spdx' = 'cyclonedx', outputPath?: string): Promise<string> {
    if (!this.analyzer) {
  this._analyzer = new BinaryAnalyzer(binaryPath);
    }

    const analysis = await this.analyzer.analyze();
    const components = await this.extractComponents(analysis);

    const defaultOutputPath = path.join(
      path.dirname(binaryPath),
      `${path.basename(binaryPath)}-sbom.${format === 'cyclonedx' ? 'xml' : 'spdx'}`
    );

    const finalOutputPath = outputPath || defaultOutputPath;

    if (format === 'cyclonedx') {
      await this.generateCycloneDXSBOM(components, finalOutputPath, binaryPath);
    } else {
      await this.generateSPDXSBOM(components, finalOutputPath, binaryPath);
    }

    return finalOutputPath;
  }

  private async extractComponents(analysis: any): Promise<SBOMComponent[]> {
    const components: SBOMComponent[] = [];

    // Add detected dependencies
    for (const dep of analysis.dependencies) {
      const name = path.basename(dep);
      const version = this.extractVersionFromPath(dep);
      
      components.push({
        name,
        version: version || 'unknown',
        type: 'library',
        supplier: 'unknown'
      });
    }

    // Add detected cryptographic libraries
    const cryptoCaps = await this.analyzer.checkCryptographicCapabilities();
    if (cryptoCaps.hasChaCha20) {
      components.push({
        name: 'ChaCha20-Poly1305',
        version: '1.0',
        type: 'library',
        license: 'Public Domain'
      });
    }
    if (cryptoCaps.hasEd25519) {
      components.push({
        name: 'Ed25519',
        version: '1.0',
        type: 'library',
        license: 'BSD-3-Clause'
      });
    }

    return components;
  }

  private extractVersionFromPath(path: string): string | null {
    const versionMatch = path.match(/(\d+\.\d+\.\d+)/);
    return versionMatch ? versionMatch[1] : null;
  }

  private async generateCycloneDXSBOM(components: SBOMComponent[], outputPath: string, binaryPath: string): Promise<void> {
    const builder = new xml2js.Builder();
    
    const sbom = {
      'bom': {
        '$': { 'xmlns': 'http://cyclonedx.org/schema/bom/1.4', 'version': '1' },
        'metadata': {
          'timestamp': new Date().toISOString(),
          'component': {
            'name': path.basename(binaryPath),
            'version': '1.0.0',
            'type': 'application',
            'purl': `pkg:generic/${path.basename(binaryPath)}@1.0.0`
          }
        },
        'components': {
          'component': components.map(comp => ({
            'name': comp.name,
            'version': comp.version,
            'type': comp.type,
            'license': comp.license ? [{ 'name': comp.license }] : undefined
          }))
        }
      }
    };

    const xml = builder.buildObject(sbom);
    await fs.writeFile(outputPath, xml);
  }

  private async generateSPDXSBOM(components: SBOMComponent[], outputPath: string, binaryPath: string): Promise<void> {
    const spdxContent = `SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
PackageName: ${path.basename(binaryPath)}
SPDXID: SPDXRef-PACKAGE
PackageVersion: 1.0.0
PackageLicenseDeclared: MIT

${components.map((comp, index) => `
PackageName: ${comp.name}
SPDXID: SPDXRef-COMPONENT-${index}
PackageVersion: ${comp.version}
PackageLicenseDeclared: ${comp.license || 'NOASSERTION'}`).join('\n')}

Relationship: SPDXRef-PACKAGE CONTAINS SPDXRef-COMPONENT-0
${components.slice(1).map((_, index) => `Relationship: SPDXRef-PACKAGE CONTAINS SPDXRef-COMPONENT-${index + 1}`).join('\n')}
`;

    await fs.writeFile(outputPath, spdxContent);
  }

  displayResults(results: ComplianceResult, format: 'json' | 'table' | 'yaml' = 'table'): void {
    console.log('\n' + '='.repeat(60));
    console.log('🎯 BETANET COMPLIANCE REPORT');
    console.log('='.repeat(60));
    console.log(`Binary: ${results.binaryPath}`);
    console.log(`Timestamp: ${results.timestamp}`);
    console.log(`Overall Score: ${results.overallScore}%`);
    console.log(`Status: ${results.passed ? '✅ PASSED' : '❌ FAILED'}`);
    console.log('-'.repeat(60));

    if (format === 'json') {
      console.log(JSON.stringify(results, null, 2));
      return;
    }

    if (format === 'yaml') {
      console.log(yaml.dump(results));
      return;
    }

    // Table format
    console.log('COMPLIANCE CHECKS:');
    console.log('─'.repeat(80));
    
    results.checks.forEach(check => {
      const status = check.passed ? '✅' : '❌';
      const severity = check.severity === 'critical' ? '🔴' : 
                      check.severity === 'major' ? '🟡' : '🟢';
      
      console.log(`${status} ${severity} [${check.id}] ${check.name}`);
      console.log(`   ${check.description}`);
      console.log(`   ${check.details}`);
      console.log();
    });

    console.log('─'.repeat(80));
    console.log('SUMMARY:');
    console.log(`Total Checks: ${results.summary.total}`);
    console.log(`Passed: ${results.summary.passed}`);
    console.log(`Failed: ${results.summary.failed}`);
    console.log(`Critical Failures: ${results.summary.critical}`);
    console.log('─'.repeat(80));
    if (results.diagnostics) {
      console.log('DIAGNOSTICS:');
      console.log(`Analysis invocations: ${results.diagnostics.analyzeInvocations} (cached: ${results.diagnostics.cached})`);
      if (typeof results.diagnostics.totalAnalysisTimeMs === 'number') {
        console.log(`Initial analysis time: ${results.diagnostics.totalAnalysisTimeMs.toFixed(1)} ms`);
      }
      const toolLine = results.diagnostics.tools
        .map(t => `${t.available ? '✅' : '❌'} ${t.name}`)
        .join('  ');
      console.log(toolLine);
      console.log('─'.repeat(80));
    }
  }
}