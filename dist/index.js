"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.BetanetComplianceChecker = void 0;
const analyzer_1 = require("./analyzer");
const fs = __importStar(require("fs-extra"));
const path = __importStar(require("path"));
const yaml = __importStar(require("js-yaml"));
const xml2js = __importStar(require("xml2js"));
const check_registry_1 = require("./check-registry");
const constants_1 = require("./constants");
const sbom_generator_1 = require("./sbom/sbom-generator");
const constants_2 = require("./constants");
class BetanetComplianceChecker {
    constructor() {
        // Will be initialized when checking compliance
        this._analyzer = null;
    }
    // Expose analyzer via getter so tests can spy/mock it safely
    get analyzer() {
        return this._analyzer;
    }
    async checkCompliance(binaryPath, options = {}) {
        // Decomposed path (ISSUE-030)
        this.ensureAnalyzer(binaryPath, options);
        const definitions = this.resolveDefinitions(options);
        const { checks, timings, wallMs } = await this.runChecks(definitions, options);
        return this.assembleResult(binaryPath, checks, timings, wallMs, options);
    }
    // === Helper decomposition (ISSUE-030) ===
    ensureAnalyzer(binaryPath, options) {
        if (!fs.existsSync(binaryPath))
            throw new Error(`Binary not found at path: ${binaryPath}`);
        if (!this._analyzer || options.forceRefresh) {
            this._analyzer = new analyzer_1.BinaryAnalyzer(binaryPath, options.verbose);
        }
        // Evidence ingestion (Phase 1 start)
        if (options.evidenceFile && fs.existsSync(options.evidenceFile)) {
            try {
                const raw = fs.readFileSync(options.evidenceFile, 'utf8');
                const parsed = JSON.parse(raw);
                const evidence = {};
                // Accept either direct structured evidence JSON or raw SLSA provenance / DSSE envelope
                // DSSE envelope detection
                if (parsed.payloadType && parsed.payload && typeof parsed.payload === 'string') {
                    try {
                        const decoded = Buffer.from(parsed.payload, 'base64').toString('utf8');
                        const inner = JSON.parse(decoded);
                        // Map SLSA fields
                        if (inner.predicateType) {
                            evidence.provenance = evidence.provenance || {};
                            evidence.provenance.predicateType = inner.predicateType;
                            const pred = inner.predicate || {};
                            if (pred.builder?.id)
                                evidence.provenance.builderId = pred.builder.id;
                            if (Array.isArray(inner.subject)) {
                                evidence.provenance.subjects = inner.subject;
                                // Attempt to locate primary subject digest
                                const first = inner.subject.find((s) => s?.digest?.sha256);
                                if (first?.digest?.sha256)
                                    evidence.provenance.binaryDigest = 'sha256:' + first.digest.sha256;
                            }
                            if (pred.materials) {
                                evidence.provenance.materials = pred.materials.map((m) => ({ uri: m.uri, digest: m.digest?.sha256 ? 'sha256:' + m.digest.sha256 : undefined }));
                            }
                            if (pred.metadata?.buildInvocation?.environment?.SOURCE_DATE_EPOCH) {
                                const sde = parseInt(pred.metadata.buildInvocation.environment.SOURCE_DATE_EPOCH, 10);
                                if (!isNaN(sde))
                                    evidence.provenance.sourceDateEpoch = sde;
                            }
                        }
                        // Minimal detached signature placeholder: if envelope has 'signatures[0].sig', mark present (not cryptographically validated here)
                        if (Array.isArray(parsed.signatures) && parsed.signatures.length) {
                            // Future: integrate cosign/DSSE key verification; here we mark presence only
                            evidence.provenance = evidence.provenance || {};
                            evidence.provenance.signatureVerified = false; // will remain false until real verification added
                        }
                    }
                    catch { /* swallow decoding errors */ }
                }
                else if (parsed.predicateType && parsed.predicate) {
                    // Raw provenance JSON (unwrapped)
                    evidence.provenance = evidence.provenance || {};
                    evidence.provenance.predicateType = parsed.predicateType;
                    if (parsed.predicate?.builder?.id)
                        evidence.provenance.builderId = parsed.predicate.builder.id;
                    if (Array.isArray(parsed.subject)) {
                        evidence.provenance.subjects = parsed.subject;
                        const first = parsed.subject.find((s) => s?.digest?.sha256);
                        if (first?.digest?.sha256)
                            evidence.provenance.binaryDigest = 'sha256:' + first.digest.sha256;
                    }
                    if (parsed.predicate?.materials) {
                        evidence.provenance.materials = parsed.predicate.materials.map((m) => ({ uri: m.uri, digest: m.digest?.sha256 ? 'sha256:' + m.digest.sha256 : undefined }));
                    }
                }
                else if (parsed.binaryDistDigest || parsed.provenance) {
                    // Fallback simple reference format (our earlier placeholder)
                    if (parsed.provenance && typeof parsed.provenance === 'object') {
                        evidence.provenance = { ...parsed.provenance };
                    }
                    else {
                        evidence.provenance = {
                            binaryDigest: parsed.binaryDistDigest,
                            predicateType: parsed.predicateType,
                            builderId: parsed.builderId
                        };
                    }
                }
                else {
                    // Assume already shape of IngestedEvidence
                    Object.assign(evidence, parsed);
                }
                this._analyzer.evidence = evidence; // attach for evaluators
                // Compute materials completeness metric
                try {
                    if (evidence.provenance?.materials) {
                        const mats = evidence.provenance.materials;
                        if (mats.length) {
                            evidence.provenance.materialsComplete = mats.every(m => !!m.digest && m.digest.startsWith('sha256:'));
                        }
                    }
                }
                catch { /* ignore */ }
            }
            catch (e) {
                console.warn(`⚠️  Failed to load evidence file ${options.evidenceFile}: ${e.message}`);
            }
        }
        // Optional SBOM ingestion for materials cross-check (Phase 3 partial)
        if (options.sbomFile && fs.existsSync(options.sbomFile)) {
            try {
                const sbomRaw = fs.readFileSync(options.sbomFile, 'utf8');
                let sbomObj = null;
                if (options.sbomFile.endsWith('.json')) {
                    try {
                        sbomObj = JSON.parse(sbomRaw);
                    }
                    catch { /* ignore */ }
                }
                else if (options.sbomFile.endsWith('.xml')) {
                    try {
                        sbomObj = xml2js.parseStringPromise(sbomRaw);
                    }
                    catch { /* ignore */ }
                }
                else { // attempt tag-value SPDX simplistic parse into map array
                    const lines = sbomRaw.split(/\r?\n/);
                    const pkgs = [];
                    let current = {};
                    for (const l of lines) {
                        if (/^PackageName:\s+/.test(l)) {
                            if (current.name)
                                pkgs.push(current);
                            current = { name: l.replace(/^PackageName:\s+/, '').trim() };
                        }
                        else if (/^PackageVersion:\s+/.test(l)) {
                            current.version = l.replace(/^PackageVersion:\s+/, '').trim();
                        }
                        else if (/^PackageChecksum:\s+SHA256:\s+/.test(l)) {
                            current.checksum = l.replace(/^PackageChecksum:\s+SHA256:\s+/, '').trim();
                        }
                    }
                    if (current.name)
                        pkgs.push(current);
                    sbomObj = { _tagValuePackages: pkgs };
                }
                if (sbomObj) {
                    this._analyzer.ingestedSBOM = sbomObj;
                    // Attempt immediate materials validation if both provenance & SBOM present
                    const evidence = this._analyzer.evidence;
                    if (evidence?.provenance?.materials && evidence.provenance.materials.length) {
                        try {
                            const sbomDigests = new Set();
                            // CycloneDX JSON format
                            const cdxComponents = (sbomObj.components && Array.isArray(sbomObj.components)) ? sbomObj.components : (sbomObj.bom?.components?.component || []);
                            if (Array.isArray(cdxComponents)) {
                                cdxComponents.forEach((c) => {
                                    const hashes = c.hashes || c.hashes?.hash || [];
                                    if (Array.isArray(hashes))
                                        hashes.forEach((h) => { if (h.content)
                                            sbomDigests.add('sha256:' + (h.content || '').toLowerCase()); });
                                });
                            }
                            // SPDX JSON
                            if (Array.isArray(sbomObj.packages)) {
                                sbomObj.packages.forEach((p) => {
                                    if (Array.isArray(p.checksums))
                                        p.checksums.forEach((cs) => { if (cs.algorithm === 'SHA256' && cs.checksumValue)
                                            sbomDigests.add('sha256:' + cs.checksumValue.toLowerCase()); });
                                });
                            }
                            // SPDX tag-value fallback
                            if (Array.isArray(sbomObj._tagValuePackages)) {
                                sbomObj._tagValuePackages.forEach((p) => { if (p.checksum)
                                    sbomDigests.add('sha256:' + p.checksum.toLowerCase()); });
                            }
                            const materials = evidence.provenance.materials;
                            const unmatched = materials.filter(m => m.digest && !sbomDigests.has(m.digest.toLowerCase()));
                            evidence.provenance.materialsMismatchCount = unmatched.length;
                            evidence.provenance.materialsValidated = unmatched.length === 0;
                        }
                        catch { /* ignore validation errors */ }
                    }
                }
            }
            catch (e) {
                console.warn(`⚠️  Failed to ingest SBOM file ${options.sbomFile}: ${e.message}`);
            }
        }
        // Phase 6: Governance & ledger evidence ingestion (single JSON file) if provided
        if (options.governanceFile && fs.existsSync(options.governanceFile)) {
            try {
                const rawGov = fs.readFileSync(options.governanceFile, 'utf8');
                const govObj = JSON.parse(rawGov);
                const analyzerAny = this._analyzer;
                analyzerAny.evidence = analyzerAny.evidence || {};
                if (govObj.governance)
                    analyzerAny.evidence.governance = govObj.governance;
                if (govObj.ledger)
                    analyzerAny.evidence.ledger = govObj.ledger;
            }
            catch (e) {
                console.warn(`⚠️  Failed to ingest governance evidence ${options.governanceFile}: ${e.message}`);
            }
        }
        // Enable dynamic probe if requested or via env toggle
        if ((options.dynamicProbe || process.env.BETANET_DYNAMIC_PROBE === '1') && typeof this._analyzer.setDynamicProbe === 'function') {
            this._analyzer.setDynamicProbe(true);
        }
    }
    resolveDefinitions(options) {
        let ids = check_registry_1.CHECK_REGISTRY.map(c => c.id);
        if (options.checkFilters?.include)
            ids = ids.filter(id => options.checkFilters.include.includes(id));
        if (options.checkFilters?.exclude)
            ids = ids.filter(id => !options.checkFilters.exclude.includes(id));
        return (0, check_registry_1.getChecksByIds)(ids);
    }
    async runChecks(definitions, options) {
        const now = new Date();
        const checks = [];
        const timings = [];
        const maxParallel = options.maxParallel && options.maxParallel > 0 ? options.maxParallel : definitions.length;
        const timeoutMs = options.checkTimeoutMs && options.checkTimeoutMs > 0 ? options.checkTimeoutMs : undefined;
        const queue = [...definitions];
        const running = [];
        const startWall = performance.now();
        const attachHints = (result, defId) => {
            try {
                const diag = this._analyzer.getDiagnostics();
                if (!diag?.degraded)
                    return;
                const reasons = diag.degradationReasons || [];
                const hints = [];
                const stringReasons = reasons.filter(r => r.startsWith('strings-'));
                const symbolReasons = reasons.filter(r => r.startsWith('symbols-'));
                const depReasons = reasons.filter(r => r.startsWith('ldd'));
                const stringChecks = [1, 2, 4, 5, 6, 8, 10, 11];
                const symbolChecks = [1, 3, 4, 10];
                if (stringChecks.includes(defId) && stringReasons.length) {
                    if (stringReasons.includes('strings-fallback-truncated'))
                        hints.push('string extraction truncated');
                    if (stringReasons.includes('strings-missing'))
                        hints.push('strings tool missing');
                    if (stringReasons.includes('strings-error'))
                        hints.push('strings invocation error');
                    if (stringReasons.includes('strings-fallback-error'))
                        hints.push('string fallback error');
                }
                if (symbolChecks.includes(defId) && symbolReasons.length)
                    hints.push('symbol extraction degraded');
                if (depReasons.length && false)
                    hints.push('dependency resolution degraded'); // placeholder
                if (!hints.length && diag.missingCoreTools?.length)
                    hints.push('core analysis tools missing');
                if (hints.length)
                    result.degradedHints = Array.from(new Set(hints));
            }
            catch { /* ignore */ }
        };
        const runOne = async (def) => {
            const start = performance.now();
            let timer;
            const evalPromise = def.evaluate(this._analyzer, now);
            const wrapped = timeoutMs ? Promise.race([
                evalPromise,
                new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('CHECK_TIMEOUT')), timeoutMs); })
            ]) : evalPromise;
            try {
                const result = await wrapped;
                const duration = performance.now() - start;
                if (timer)
                    clearTimeout(timer);
                result.durationMs = duration;
                attachHints(result, def.id);
                checks.push(result);
                timings.push({ id: result.id, durationMs: duration });
            }
            catch (e) {
                if (timer)
                    clearTimeout(timer);
                const duration = performance.now() - start;
                timings.push({ id: def.id, durationMs: duration });
                checks.push({ id: def.id, name: def.name, description: def.description, passed: false, details: e && e.message === 'CHECK_TIMEOUT' ? '❌ Check timed out' : `❌ Check error: ${e?.message || e}`, severity: def.severity, durationMs: duration });
            }
        };
        while (queue.length || running.length) {
            while (queue.length && running.length < maxParallel) {
                const def = queue.shift();
                const p = runOne(def).finally(() => { const idx = running.indexOf(p); if (idx >= 0)
                    running.splice(idx, 1); });
                running.push(p);
            }
            if (running.length)
                await Promise.race(running);
        }
        const wallMs = performance.now() - startWall;
        checks.sort((a, b) => a.id - b.id);
        return { checks, timings, wallMs };
    }
    assembleResult(binaryPath, checks, checkTimings, parallelDurationMs, options) {
        const severityRank = { minor: 1, major: 2, critical: 3 };
        const min = options.severityMin ? severityRank[options.severityMin] : 1;
        const considered = checks.filter(c => severityRank[c.severity] >= min);
        // Strict mode logic: by default treat heuristic passes as informational unless allowHeuristic OR not in strictMode
        const strictMode = options.strictMode !== false; // default true if not specified
        const allowHeuristic = !!options.allowHeuristic;
        const normativePasses = considered.filter(c => c.passed && c.evidenceType && c.evidenceType !== 'heuristic');
        const heuristicPasses = considered.filter(c => c.passed && (c.evidenceType === 'heuristic' || !c.evidenceType));
        const passedChecks = (!strictMode || allowHeuristic) ? considered.filter(c => c.passed) : normativePasses;
        const criticalChecks = considered.filter(c => c.severity === 'critical' && !c.passed);
        const overallScore = considered.length === 0 ? 0 : Math.round((passedChecks.length / considered.length) * 100);
        let passed = considered.length > 0 && passedChecks.length === considered.length && criticalChecks.length === 0;
        // In strict mode if there are any heuristic-only passes counting toward compliance, force non-pass unless allowed
        let heuristicContributionCount = 0;
        if (strictMode && !allowHeuristic) {
            heuristicContributionCount = heuristicPasses.length;
            if (heuristicContributionCount > 0)
                passed = false;
        }
        const diagnostics = (() => { const a = this.analyzer; if (a && typeof a.getDiagnostics === 'function') {
            try {
                return a.getDiagnostics();
            }
            catch {
                return undefined;
            }
        } return undefined; })();
        const implementedChecks = check_registry_1.CHECK_REGISTRY.filter(c => (0, constants_1.isVersionLE)(c.introducedIn, constants_1.SPEC_VERSION_PARTIAL)).length;
        const specSummary = { baseline: constants_1.SPEC_VERSION_SUPPORTED_BASE, latestKnown: constants_1.SPEC_VERSION_PARTIAL, implementedChecks, totalChecks: check_registry_1.CHECK_REGISTRY.length, pendingIssues: constants_1.SPEC_11_PENDING_ISSUES };
        const result = { binaryPath, timestamp: new Date().toISOString(), overallScore, passed, checks, summary: { total: considered.length, passed: passedChecks.length, failed: considered.length - passedChecks.length, critical: criticalChecks.length }, specSummary, diagnostics };
        result.strictMode = strictMode;
        result.allowHeuristic = allowHeuristic;
        result.heuristicContributionCount = heuristicContributionCount;
        // Phase 0 requirement: emit warning when heuristic passes present
        const warnings = [];
        if (heuristicContributionCount > 0 && strictMode && !allowHeuristic) {
            warnings.push(`Heuristic-only evidence: ${heuristicContributionCount} check(s) passed with heuristic evidence and were excluded from compliance scoring. Add normative evidence or use --allow-heuristic to treat them as provisional.`);
        }
        else if (heuristicContributionCount > 0 && allowHeuristic) {
            warnings.push(`Heuristic evidence counted: ${heuristicContributionCount} check(s) rely solely on heuristic signals. Consider providing structural/dynamic/artifact evidence for strict compliance.`);
        }
        if (warnings.length)
            result.warnings = warnings;
        result.parallelDurationMs = parallelDurationMs;
        result.checkTimings = checkTimings;
        if (process.env.BETANET_FAIL_ON_DEGRADED === '1' && result.diagnostics?.degraded)
            result.passed = false;
        return result;
    }
    // Legacy per-check methods removed (Plan 3 consolidation) in favor of registry-based evaluation
    async generateSBOM(binaryPath, format = 'cyclonedx', outputPath) {
        // Ensure analyzer exists for consistency (even though SBOMGenerator operates independently)
        if (!this.analyzer) {
            this._analyzer = new analyzer_1.BinaryAnalyzer(binaryPath);
        }
        const generator = new sbom_generator_1.SBOMGenerator();
        const sbom = await generator.generate(binaryPath, format, this.analyzer);
        const defaultOutputPath = (() => {
            if (format === 'cyclonedx')
                return path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.xml`);
            if (format === 'cyclonedx-json')
                return path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.cdx.json`);
            if (format === 'spdx-json')
                return path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.spdx.json`);
            return path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.spdx`);
        })();
        const finalOutputPath = outputPath || defaultOutputPath;
        if (format === 'cyclonedx') {
            // Serialize a CycloneDX-style XML (backwards compatible with previous output path & extension)
            const builder = new xml2js.Builder();
            const metaComponent = sbom.data?.metadata?.component || {};
            let components = sbom.data?.components || [];
            // ISSUE-045: Ensure duplicate components (same name+version) are deduped before XML serialization
            if (Array.isArray(components) && components.length > 1) {
                const seen = new Map();
                components.forEach((c) => {
                    const key = `${(c.name || '').toLowerCase()}@${(c.version || '').toLowerCase()}`;
                    if (!seen.has(key))
                        seen.set(key, c);
                    else {
                        const existing = seen.get(key);
                        if (!existing.hashes && c.hashes)
                            existing.hashes = c.hashes;
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
                    metaComponent.hashes.forEach((h) => { ws.write(`        <hash alg="${h.alg}">${h.content}</hash>\n`); });
                    ws.write('      </hashes>\n');
                }
                ws.write('    </component>\n');
                ws.write('  </metadata>\n');
                if (componentCount) {
                    ws.write('  <components>\n');
                    components.forEach((c) => {
                        ws.write('    <component>\n');
                        ws.write(`      <name>${c.name || 'unknown'}</name>\n`);
                        ws.write(`      <version>${c.version || 'unknown'}</version>\n`);
                        ws.write(`      <type>${c.type || 'library'}</type>\n`);
                        if (c.purl)
                            ws.write(`      <purl>${c.purl}</purl>\n`);
                        ws.write('    </component>\n');
                    });
                    ws.write('  </components>\n');
                }
                ws.write('</bom>');
                await new Promise(res => ws.end(res));
            }
            else {
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
                                hashes: metaComponent.hashes ? { hash: metaComponent.hashes.map((h) => ({ _: h.content, $: { alg: h.alg } })) } : undefined
                            }
                        },
                        components: components.length ? {
                            component: components.map((c) => ({
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
        }
        else if (format === 'cyclonedx-json') {
            // Write raw JSON structure produced internally (data object)
            await fs.writeFile(finalOutputPath, JSON.stringify(sbom.data, null, 2));
        }
        else if (format === 'spdx-json') {
            await fs.writeFile(finalOutputPath, JSON.stringify(sbom.data, null, 2));
        }
        else {
            // SPDX already text from generator
            await fs.writeFile(finalOutputPath, sbom.data);
        }
        return finalOutputPath;
    }
    displayResults(results, format = 'table') {
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
        if (results.warnings && results.warnings.length) {
            console.log('⚠️  WARNINGS:');
            results.warnings.forEach((w) => console.log(` - ${w}`));
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
            const severity = constants_2.SEVERITY_EMOJI[check.severity] || '';
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
exports.BetanetComplianceChecker = BetanetComplianceChecker;
//# sourceMappingURL=index.js.map