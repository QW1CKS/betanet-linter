import { BinaryAnalyzer } from './analyzer';
import { ComplianceCheck, ComplianceResult, CheckOptions } from './types';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as xml2js from 'xml2js';
import { CHECK_REGISTRY, getChecksByIds } from './check-registry';
import { SPEC_VERSION_SUPPORTED_BASE, SPEC_VERSION_PARTIAL, SPEC_11_PENDING_ISSUES, isVersionLE } from './constants';
import { SBOMGenerator } from './sbom/sbom-generator';
import { SEVERITY_EMOJI } from './constants';

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
    // Decomposed path (ISSUE-030)
    this.ensureAnalyzer(binaryPath, options);
    const definitions = this.resolveDefinitions(options);
    const { checks, timings, wallMs } = await this.runChecks(definitions, options);
    return this.assembleResult(binaryPath, checks, timings, wallMs, options);
  }

  // === Helper decomposition (ISSUE-030) ===
  private ensureAnalyzer(binaryPath: string, options: CheckOptions) {
    if (!fs.existsSync(binaryPath)) throw new Error(`Binary not found at path: ${binaryPath}`);
    if (!this._analyzer || options.forceRefresh) {
      this._analyzer = new BinaryAnalyzer(binaryPath, options.verbose);
    }
    // Enable dynamic probe if requested or via env toggle
    if ((options.dynamicProbe || process.env.BETANET_DYNAMIC_PROBE === '1') && typeof (this._analyzer as any).setDynamicProbe === 'function') {
      (this._analyzer as any).setDynamicProbe(true);
    }
  }
  private resolveDefinitions(options: CheckOptions) {
    let ids = CHECK_REGISTRY.map(c => c.id);
    if (options.checkFilters?.include) ids = ids.filter(id => options.checkFilters!.include!.includes(id));
    if (options.checkFilters?.exclude) ids = ids.filter(id => !options.checkFilters!.exclude!.includes(id));
    return getChecksByIds(ids);
  }
  private async runChecks(definitions: ReturnType<typeof getChecksByIds>, options: CheckOptions) {
    const now = new Date();
    const checks: ComplianceCheck[] = [];
    const timings: { id: number; durationMs: number }[] = [];
    const maxParallel = options.maxParallel && options.maxParallel > 0 ? options.maxParallel : definitions.length;
    const timeoutMs = options.checkTimeoutMs && options.checkTimeoutMs > 0 ? options.checkTimeoutMs : undefined;
    const queue = [...definitions];
    const running: Promise<void>[] = [];
    const startWall = performance.now();
    const attachHints = (result: ComplianceCheck, defId: number) => {
      try {
        const diag = this._analyzer.getDiagnostics();
        if (!diag?.degraded) return;
        const reasons = diag.degradationReasons || [];
        const hints: string[] = [];
        const stringReasons = reasons.filter(r => r.startsWith('strings-'));
        const symbolReasons = reasons.filter(r => r.startsWith('symbols-'));
        const depReasons = reasons.filter(r => r.startsWith('ldd'));
        const stringChecks = [1,2,4,5,6,8,10,11];
        const symbolChecks = [1,3,4,10];
        if (stringChecks.includes(defId) && stringReasons.length) {
          if (stringReasons.includes('strings-fallback-truncated')) hints.push('string extraction truncated');
          if (stringReasons.includes('strings-missing')) hints.push('strings tool missing');
          if (stringReasons.includes('strings-error')) hints.push('strings invocation error');
          if (stringReasons.includes('strings-fallback-error')) hints.push('string fallback error');
        }
        if (symbolChecks.includes(defId) && symbolReasons.length) hints.push('symbol extraction degraded');
        if (depReasons.length && false) hints.push('dependency resolution degraded'); // placeholder
        if (!hints.length && diag.missingCoreTools?.length) hints.push('core analysis tools missing');
        if (hints.length) result.degradedHints = Array.from(new Set(hints));
      } catch {/* ignore */}
    };
    const runOne = async (def: typeof definitions[number]) => {
      const start = performance.now();
      let timer: any;
      const evalPromise = def.evaluate(this._analyzer, now);
      const wrapped = timeoutMs ? Promise.race([
        evalPromise,
        new Promise<ComplianceCheck>((_, reject) => { timer = setTimeout(() => reject(new Error('CHECK_TIMEOUT')), timeoutMs); })
      ]) : evalPromise;
      try {
        const result = await wrapped;
        const duration = performance.now() - start;
        if (timer) clearTimeout(timer);
        result.durationMs = duration;
        attachHints(result, def.id);
        checks.push(result);
        timings.push({ id: result.id, durationMs: duration });
      } catch (e: any) {
        if (timer) clearTimeout(timer);
        const duration = performance.now() - start;
        timings.push({ id: def.id, durationMs: duration });
        checks.push({ id: def.id, name: def.name, description: def.description, passed: false, details: e && e.message === 'CHECK_TIMEOUT' ? '❌ Check timed out' : `❌ Check error: ${e?.message || e}`, severity: def.severity, durationMs: duration });
      }
    };
    while (queue.length || running.length) {
      while (queue.length && running.length < maxParallel) {
        const def = queue.shift()!;
        const p = runOne(def).finally(() => { const idx = running.indexOf(p); if (idx >= 0) running.splice(idx, 1); });
        running.push(p);
      }
      if (running.length) await Promise.race(running);
    }
    const wallMs = performance.now() - startWall;
    checks.sort((a,b) => a.id - b.id);
    return { checks, timings, wallMs };
  }
  private assembleResult(binaryPath: string, checks: ComplianceCheck[], checkTimings: { id: number; durationMs: number }[], parallelDurationMs: number, options: CheckOptions): ComplianceResult {
    const severityRank = { minor: 1, major: 2, critical: 3 } as const;
    const min = options.severityMin ? severityRank[options.severityMin] : 1;
    const considered = checks.filter(c => severityRank[c.severity] >= min);
    const passedChecks = considered.filter(c => c.passed);
    const criticalChecks = considered.filter(c => c.severity === 'critical' && !c.passed);
    const overallScore = considered.length === 0 ? 0 : Math.round((passedChecks.length / considered.length) * 100);
    const passed = considered.length > 0 && passedChecks.length === considered.length && criticalChecks.length === 0;
    const diagnostics = (() => { const a: any = this.analyzer; if (a && typeof a.getDiagnostics === 'function') { try { return a.getDiagnostics(); } catch { return undefined; } } return undefined; })();
    const implementedChecks = CHECK_REGISTRY.filter(c => isVersionLE(c.introducedIn, SPEC_VERSION_PARTIAL)).length;
    const specSummary = { baseline: SPEC_VERSION_SUPPORTED_BASE, latestKnown: SPEC_VERSION_PARTIAL, implementedChecks, totalChecks: CHECK_REGISTRY.length, pendingIssues: SPEC_11_PENDING_ISSUES };
    const result: ComplianceResult = { binaryPath, timestamp: new Date().toISOString(), overallScore, passed, checks, summary: { total: considered.length, passed: passedChecks.length, failed: considered.length - passedChecks.length, critical: criticalChecks.length }, specSummary, diagnostics };
    result.parallelDurationMs = parallelDurationMs; result.checkTimings = checkTimings; if (process.env.BETANET_FAIL_ON_DEGRADED === '1' && result.diagnostics?.degraded) result.passed = false; return result;
  }

  // Legacy per-check methods removed (Plan 3 consolidation) in favor of registry-based evaluation

  async generateSBOM(binaryPath: string, format: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json' = 'cyclonedx', outputPath?: string): Promise<string> {
    // Ensure analyzer exists for consistency (even though SBOMGenerator operates independently)
  if (!this.analyzer) {
      this._analyzer = new BinaryAnalyzer(binaryPath);
    }

    const generator = new SBOMGenerator();
  const sbom = await generator.generate(binaryPath, format, this.analyzer as any);

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
      let components = (sbom as any).data?.components || [];
      // ISSUE-045: Ensure duplicate components (same name+version) are deduped before XML serialization
      if (Array.isArray(components) && components.length > 1) {
        const seen = new Map<string, any>();
        components.forEach((c: any) => {
          const key = `${(c.name||'').toLowerCase()}@${(c.version||'').toLowerCase()}`;
          if (!seen.has(key)) seen.set(key, c); else {
            const existing = seen.get(key);
            if (!existing.hashes && c.hashes) existing.hashes = c.hashes;
          }
        });
        components = Array.from(seen.values());
      }
      // Streaming threshold (ISSUE-046)
      const streamThreshold = (() => {
        const v = process.env.BETANET_SBOM_STREAM_THRESHOLD;
        const n = v ? parseInt(v, 10) : NaN;
        return Number.isFinite(n) ? n : 1000; // default high threshold
      })();
      const componentCount = Array.isArray(components) ? components.length : 0;
      if (componentCount >= streamThreshold) {
        const ws = fs.createWriteStream(finalOutputPath, { encoding: 'utf8' });
        ws.write('<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">\n');
        ws.write('  <metadata>\n');
        ws.write(`    <timestamp>${new Date().toISOString()}</timestamp>\n`);
        ws.write('    <component>\n');
        ws.write(`      <name>${metaComponent.name || path.basename(binaryPath)}</name>\n`);
        ws.write(`      <version>${metaComponent.version || '1.0.0'}</version>\n`);
        ws.write(`      <type>${metaComponent.type || 'application'}</type>\n`);
        ws.write(`      <purl>${metaComponent.purl || `pkg:generic/${path.basename(binaryPath)}@1.0.0`}</purl>\n`);
        if (metaComponent.hashes && metaComponent.hashes.length) {
          ws.write('      <hashes>\n');
          metaComponent.hashes.forEach((h: any) => { ws.write(`        <hash alg="${h.alg}">${h.content}</hash>\n`); });
          ws.write('      </hashes>\n');
        }
        ws.write('    </component>\n');
        ws.write('  </metadata>\n');
        if (componentCount) {
          ws.write('  <components>\n');
          components.forEach((c: any) => {
            ws.write('    <component>\n');
            ws.write(`      <name>${c.name || 'unknown'}</name>\n`);
            ws.write(`      <version>${c.version || 'unknown'}</version>\n`);
            ws.write(`      <type>${c.type || 'library'}</type>\n`);
            if (c.purl) ws.write(`      <purl>${c.purl}</purl>\n`);
            ws.write('    </component>\n');
          });
          ws.write('  </components>\n');
        }
        ws.write('</bom>');
        await new Promise<void>(res => ws.end(res));
      } else {
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
      }
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
    if (results.diagnostics?.degraded) {
      const reasons = results.diagnostics.degradationReasons?.join(', ') || 'unknown';
      console.log(`⚠️  Degraded analysis: ${reasons}`);
      if (results.diagnostics.missingCoreTools?.length) {
        console.log(`Missing core tools: ${results.diagnostics.missingCoreTools.join(', ')}`);
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
  const severity = SEVERITY_EMOJI[check.severity] || '';
      const degradedMark = check.degradedHints && check.degradedHints.length ? ' (degraded)' : '';
      
      console.log(`${status} ${severity} [${check.id}] ${check.name}${degradedMark}`);
      console.log(`   ${check.description}`);
      console.log(`   ${check.details}`);
      if (check.degradedHints && check.degradedHints.length) {
        console.log(`   Hints: ${check.degradedHints.join('; ')}`);
      }
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