import { BinaryAnalyzer } from './analyzer';
import { ComplianceCheck, ComplianceResult, CheckOptions } from './types';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as xml2js from 'xml2js';
import { CHECK_REGISTRY, getChecksByIds } from './check-registry';
import { SPEC_VERSION_SUPPORTED_BASE, SPEC_VERSION_PARTIAL, SPEC_11_PENDING_ISSUES, isVersionLE } from './constants';
import { SBOMGenerator } from './sbom/sbom-generator';

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
    // Binary existence pre-check (Plan 5 robustness)
    if (!(await fs.pathExists(binaryPath))) {
      throw new Error(`Binary not found at path: ${binaryPath}`);
    }
    // Allow tests or callers to pre-inject a mock analyzer; only create if absent
    if (!this._analyzer || options.forceRefresh) {
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
    const checkTimings: { id: number; durationMs: number }[] = [];
    for (const def of definitions) {
      const start = performance.now();
      const result = await def.evaluate(this._analyzer, now);
      const duration = performance.now() - start;
      result.durationMs = duration;
      checkTimings.push({ id: result.id, durationMs: duration });
      checks.push(result);
    }

    // Calculate overall results
    // Apply severity minimum filter for scoring (display still shows all for transparency)
    const severityRank = { minor: 1, major: 2, critical: 3 } as const;
    const min = options.severityMin ? severityRank[options.severityMin] : 1;
    const considered = checks.filter(c => severityRank[c.severity] >= min);
    const passedChecks = considered.filter(c => c.passed);
    const criticalChecks = considered.filter(c => c.severity === 'critical' && !c.passed);
    
  // Guard against zero considered checks
  const overallScore = considered.length === 0 ? 0 : Math.round((passedChecks.length / considered.length) * 100);
  const passed = considered.length > 0 && passedChecks.length === considered.length && criticalChecks.length === 0;

    const diagnostics = ((): any => {
      const a: any = this.analyzer;
      if (a && typeof a.getDiagnostics === 'function') {
        try { return a.getDiagnostics(); } catch { return undefined; }
      }
      return undefined;
    })();

    // Spec coverage summary: counts checks introduced up to partial version
    const implementedChecks = CHECK_REGISTRY.filter(c => isVersionLE(c.introducedIn, SPEC_VERSION_PARTIAL)).length;
    const specSummary = {
      baseline: SPEC_VERSION_SUPPORTED_BASE,
      latestKnown: SPEC_VERSION_PARTIAL,
      implementedChecks,
      totalChecks: CHECK_REGISTRY.length,
      pendingIssues: SPEC_11_PENDING_ISSUES
    };

  const result: ComplianceResult = {
      binaryPath,
      timestamp: new Date().toISOString(),
      overallScore,
      passed,
      checks,
      summary: {
        total: considered.length,
        passed: passedChecks.length,
        failed: considered.length - passedChecks.length,
        critical: criticalChecks.length
      },
      specSummary,
      diagnostics
    };
    result.checkTimings = checkTimings;

    // If env BETANET_FAIL_ON_DEGRADED set, override pass/fail (but keep original scoring)
    if (process.env.BETANET_FAIL_ON_DEGRADED === '1' && result.diagnostics?.degraded) {
      result.passed = false;
    }
    return result;
  }

  // Legacy per-check methods removed (Plan 3 consolidation) in favor of registry-based evaluation

  async generateSBOM(binaryPath: string, format: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json' = 'cyclonedx', outputPath?: string): Promise<string> {
    // Ensure analyzer exists for consistency (even though SBOMGenerator operates independently)
  if (!this.analyzer) {
      this._analyzer = new BinaryAnalyzer(binaryPath);
    }

    const generator = new SBOMGenerator();
    const sbom = await generator.generate(binaryPath, format);

    const defaultOutputPath = (() => {
      if (format === 'cyclonedx') return path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.xml`);
      if (format === 'cyclonedx-json') return path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.cdx.json`);
      if (format === 'spdx-json') return path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.spdx.json`);
      return path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.spdx`);
    })();
    const finalOutputPath = outputPath || defaultOutputPath;

  if (format === 'cyclonedx') {
      // Serialize a CycloneDX-style XML (backwards compatible with previous output path & extension)
      const builder = new xml2js.Builder();
      const metaComponent = (sbom as any).data?.metadata?.component || {};
      const components = (sbom as any).data?.components || [];
      const xmlObj = {
        bom: {
          $: { xmlns: 'http://cyclonedx.org/schema/bom/1.4', version: '1' },
          metadata: {
            timestamp: new Date().toISOString(),
            component: {
              name: metaComponent.name || path.basename(binaryPath),
              version: metaComponent.version || '1.0.0',
              type: metaComponent.type || 'application',
              purl: metaComponent.purl || `pkg:generic/${path.basename(binaryPath)}@1.0.0`,
              hashes: metaComponent.hashes ? { hash: metaComponent.hashes.map((h: any) => ({ _: h.content, $: { alg: h.alg } })) } : undefined
            }
          },
          components: components.length ? {
            component: components.map((c: any) => ({
              name: c.name || 'unknown',
              version: c.version || 'unknown',
              type: c.type || 'library',
              purl: c.purl,
              properties: undefined
            }))
          } : undefined
        }
      };
      const xml = builder.buildObject(xmlObj);
      await fs.writeFile(finalOutputPath, xml);
    } else if (format === 'cyclonedx-json') {
      // Write raw JSON structure produced internally (data object)
      await fs.writeFile(finalOutputPath, JSON.stringify((sbom as any).data, null, 2));
    } else if (format === 'spdx-json') {
      await fs.writeFile(finalOutputPath, JSON.stringify((sbom as any).data, null, 2));
    } else {
      // SPDX already text from generator
      await fs.writeFile(finalOutputPath, (sbom as any).data);
    }

    return finalOutputPath;
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
    if (results.specSummary) {
      const s = results.specSummary;
      console.log(`Spec Coverage: baseline ${s.baseline} fully covered; latest known ${s.latestKnown} checks implemented ${s.implementedChecks}/${s.totalChecks}`);
      if (s.pendingIssues && s.pendingIssues.length) {
        console.log('Pending 1.1 refinements: ' + s.pendingIssues.map(p => p.id).join(', '));
      }
      console.log('-'.repeat(60));
    }

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