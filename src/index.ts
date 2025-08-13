import { BinaryAnalyzer } from './analyzer';
import { ComplianceCheck, ComplianceResult, CheckOptions, IngestedEvidence } from './types';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as yaml from 'js-yaml';
import * as xml2js from 'xml2js';
import { ALL_CHECKS, getChecksByIds } from './check-registry';
import { SPEC_VERSION_SUPPORTED_BASE, SPEC_VERSION_PARTIAL, SPEC_11_PENDING_ISSUES, isVersionLE } from './constants';
import { SBOMGenerator } from './sbom/sbom-generator';
import { SEVERITY_EMOJI } from './constants';
import * as crypto from 'crypto';

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
  // Phase 6: Apply network allowance (default deny)
  try { (this._analyzer as any).setNetworkAllowed?.(!!options.enableNetwork, options.networkAllowlist); } catch { /* ignore */ }
    // Evidence ingestion (Phase 1 start)
    if (options.evidenceFile && fs.existsSync(options.evidenceFile)) {
      try {
        const raw = fs.readFileSync(options.evidenceFile, 'utf8');
        const parsed: any = JSON.parse(raw);
        const evidence: IngestedEvidence = {};
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
              if (pred.builder?.id) evidence.provenance.builderId = pred.builder.id;
              if (Array.isArray(inner.subject)) {
                evidence.provenance.subjects = inner.subject as any;
                // Attempt to locate primary subject digest
                const first = inner.subject.find((s: any) => s?.digest?.sha256);
                if (first?.digest?.sha256) evidence.provenance.binaryDigest = 'sha256:' + first.digest.sha256;
              }
              if (pred.materials) {
                evidence.provenance.materials = pred.materials.map((m: any) => ({ uri: m.uri, digest: m.digest?.sha256 ? 'sha256:' + m.digest.sha256 : undefined }));
              }
              if (pred.metadata?.buildInvocation?.environment?.SOURCE_DATE_EPOCH) {
                const sde = parseInt(pred.metadata.buildInvocation.environment.SOURCE_DATE_EPOCH, 10);
                if (!isNaN(sde)) evidence.provenance.sourceDateEpoch = sde;
              }
            }
            // Minimal detached signature placeholder: if envelope has 'signatures[0].sig', mark present (not cryptographically validated here)
            if (Array.isArray(parsed.signatures) && parsed.signatures.length) {
              // Future: integrate cosign/DSSE key verification; here we mark presence only
              evidence.provenance = evidence.provenance || {};
              evidence.provenance.signatureVerified = false; // will remain false until real verification added
              evidence.provenance.dsseSignerCount = parsed.signatures.length;
            }
          } catch {/* swallow decoding errors */}
        } else if (parsed.predicateType && parsed.predicate) {
          // Raw provenance JSON (unwrapped)
            evidence.provenance = evidence.provenance || {};
            evidence.provenance.predicateType = parsed.predicateType;
            if (parsed.predicate?.builder?.id) evidence.provenance.builderId = parsed.predicate.builder.id;
            if (Array.isArray(parsed.subject)) {
              evidence.provenance.subjects = parsed.subject;
              const first = parsed.subject.find((s: any) => s?.digest?.sha256);
              if (first?.digest?.sha256) evidence.provenance.binaryDigest = 'sha256:' + first.digest.sha256;
            }
            if (parsed.predicate?.materials) {
              evidence.provenance.materials = parsed.predicate.materials.map((m: any) => ({ uri: m.uri, digest: m.digest?.sha256 ? 'sha256:' + m.digest.sha256 : undefined }));
            }
        } else if (parsed.binaryDistDigest || parsed.provenance) {
          // Fallback simple reference format (our earlier placeholder)
          if (parsed.provenance && typeof parsed.provenance === 'object') {
            evidence.provenance = { ...parsed.provenance } as any;
          } else {
            evidence.provenance = {
              binaryDigest: parsed.binaryDistDigest,
              predicateType: parsed.predicateType,
              builderId: parsed.builderId
            };
          }
        } else {
          // Assume already shape of IngestedEvidence
          Object.assign(evidence, parsed);
        }
        (this._analyzer as any).evidence = evidence; // attach for evaluators
  // Phase 7: if signature & public key provided, verify detached signature over canonical JSON
        if (options.evidenceSignatureFile && options.evidencePublicKeyFile && fs.existsSync(options.evidenceSignatureFile) && fs.existsSync(options.evidencePublicKeyFile)) {
          try {
            const sigB64 = fs.readFileSync(options.evidenceSignatureFile, 'utf8').trim();
            const pubRaw = fs.readFileSync(options.evidencePublicKeyFile, 'utf8').trim();
            const signature = Buffer.from(sigB64, 'base64');
            // Support PEM public key or raw base64 32B
            let pubKey: Buffer;
            if (/BEGIN PUBLIC KEY/.test(pubRaw)) {
              const body = pubRaw.replace(/-----BEGIN PUBLIC KEY-----/,'').replace(/-----END PUBLIC KEY-----/,'').replace(/\s+/g,'');
              pubKey = Buffer.from(body, 'base64');
            } else if (/^[A-Za-z0-9+/=]+$/.test(pubRaw)) {
              pubKey = Buffer.from(pubRaw, 'base64');
            } else {
              throw new Error('Unsupported public key format');
            }
            // Canonical JSON: stable stringify (keys sorted)
            const canonical = JSON.stringify(evidence, Object.keys(evidence).sort());
            let valid = false;
            try {
              // Attempt ed25519 verification via Node 18+ crypto.sign (verify)
              const verify = crypto.verify(null, Buffer.from(canonical), { key: pubKey, format: 'der', type: 'spki' }, signature);
              valid = verify;
            } catch {
              // Fallback: try sodium-style 32B key (ed25519) via subtle if available
            }
            (this._analyzer as any).diagnostics = (this._analyzer as any).diagnostics || {};
            (this._analyzer as any).diagnostics.evidenceSignatureValid = valid;
            if (valid) {
              evidence.provenance = evidence.provenance || {};
              evidence.provenance.signatureVerified = true;
            } else {
              evidence.provenance = evidence.provenance || {};
              evidence.provenance.signatureVerified = false;
              evidence.provenance.signatureError = 'invalid-signature';
            }
          } catch (sigErr: any) {
            (this._analyzer as any).diagnostics = (this._analyzer as any).diagnostics || {};
            (this._analyzer as any).diagnostics.evidenceSignatureValid = false;
            try { (this._analyzer as any).evidence.provenance = (this._analyzer as any).evidence.provenance || {}; (this._analyzer as any).evidence.provenance.signatureError = sigErr.message; } catch {/* ignore */}
          }
        }
        // Compute materials completeness metric
        // Phase 7: DSSE envelope verification & multi-signer policy (enhanced)
        try {
          if (options.dssePublicKeysFile && fs.existsSync(options.dssePublicKeysFile)) {
            const keyMap = JSON.parse(fs.readFileSync(options.dssePublicKeysFile, 'utf8')) as Record<string,string>;
            const evAny: any = (this._analyzer as any).evidence;
            const rawEnv = fs.readFileSync(options.evidenceFile!, 'utf8');
            const parsedEnv = JSON.parse(rawEnv);
            if (parsedEnv.payloadType && parsedEnv.payload && Array.isArray(parsedEnv.signatures)) {
              const payloadBytes = Buffer.from(parsedEnv.payload, 'base64');
              const signerDetails: { keyid?: string; verified: boolean; reason?: string }[] = [];
              let verifiedCount = 0;
              for (const sigObj of parsedEnv.signatures) {
                const keyId = sigObj.keyid || sigObj.keyId || sigObj.kid;
                const sigB64 = sigObj.sig || sigObj.signature;
                if (!keyId) { signerDetails.push({ verified:false, reason:'missing-keyid' }); continue; }
                const pk = keyMap[keyId];
                if (!pk) { signerDetails.push({ keyid:keyId, verified:false, reason:'unknown-keyid' }); continue; }
                if (!sigB64) { signerDetails.push({ keyid:keyId, verified:false, reason:'missing-sig' }); continue; }
                try {
                  const sig = Buffer.from(sigB64, 'base64');
                  let pkBuf: Buffer;
                  if (/BEGIN PUBLIC KEY/.test(pk)) {
                    const body = pk.replace(/-----BEGIN PUBLIC KEY-----/,'').replace(/-----END PUBLIC KEY-----/,'').replace(/\s+/g,'');
                    pkBuf = Buffer.from(body, 'base64');
                  } else { pkBuf = Buffer.from(pk, 'base64'); }
                  // NOTE: Real DSSE verification requires canonical preauthentication encoding; placeholder uses direct payload bytes
                  const ok = crypto.verify(null, payloadBytes, { key: pkBuf, format: 'der', type: 'spki' }, sig);
                  signerDetails.push({ keyid: keyId, verified: ok, reason: ok ? undefined : 'sig-verify-failed' });
                  if (ok) verifiedCount++;
                } catch {
                  signerDetails.push({ keyid:keyId, verified:false, reason:'sig-error' });
                }
              }
              if (!evAny.provenance) evAny.provenance = {};
              evAny.provenance.dsseSignerCount = parsedEnv.signatures.length;
              evAny.provenance.dsseVerifiedSignerCount = verifiedCount;
              if (verifiedCount === parsedEnv.signatures.length && verifiedCount>0) evAny.provenance.dsseEnvelopeVerified = true;
              const requiredKeys = (options.dsseRequiredKeys||'').split(',').map(s=>s.trim()).filter(Boolean);
              const requiredPresent = requiredKeys.every(k => signerDetails.some(d=>d.keyid===k && d.verified));
              evAny.provenance.dsseRequiredKeysPresent = requiredKeys.length===0 ? true : requiredPresent;
              const threshold = options.dsseThreshold || 1;
              evAny.provenance.dsseThresholdMet = verifiedCount >= threshold;
              const policyReasons: string[] = [];
              if (!evAny.provenance.dsseThresholdMet) policyReasons.push('threshold-not-met');
              if (!evAny.provenance.dsseRequiredKeysPresent) policyReasons.push('required-keys-missing');
              if (policyReasons.length) evAny.provenance.dssePolicyReasons = policyReasons;
              evAny.provenance.dsseSignerDetails = signerDetails;
            }
          }
        } catch {/* ignore dsse errors */}

        // Phase 7: multi-signer evidence bundle processing
        try {
          if (options.evidenceBundleFile && fs.existsSync(options.evidenceBundleFile)) {
            const bundleRaw = JSON.parse(fs.readFileSync(options.evidenceBundleFile,'utf8'));
            if (Array.isArray(bundleRaw)) {
              const entries: any[] = [];
              const concatHashes: string[] = [];
              for (const entry of bundleRaw) {
                try {
                  const evPart = entry.evidence;
                  const sigB64 = entry.signature;
                  const pk = entry.publicKey;
                  const signer = entry.signer || 'unknown';
                  if (!evPart || !sigB64 || !pk) continue;
                  const canonical = JSON.stringify(evPart, Object.keys(evPart).sort());
                  const hash = crypto.createHash('sha256').update(canonical).digest('hex');
                  let pkBuf: Buffer;
                  if (/BEGIN PUBLIC KEY/.test(pk)) {
                    const body = pk.replace(/-----BEGIN PUBLIC KEY-----/,'').replace(/-----END PUBLIC KEY-----/,'').replace(/\s+/g,'');
                    pkBuf = Buffer.from(body, 'base64');
                  } else { pkBuf = Buffer.from(pk, 'base64'); }
                  let valid = false;
                  try { valid = crypto.verify(null, Buffer.from(canonical), { key: pkBuf, format: 'der', type: 'spki' }, Buffer.from(sigB64,'base64')); } catch {/* ignore */}
                  entries.push({ canonicalSha256: hash, signatureValid: valid, signer });
                  concatHashes.push(hash);
                } catch {/* per entry */}
              }
              const bundleSha256 = crypto.createHash('sha256').update(concatHashes.join('')).digest('hex');
              const multiSignerThresholdMet = entries.filter(e => e.signatureValid).length >= 2;
              (this._analyzer as any).evidence.signedEvidenceBundle = { entries, bundleSha256, multiSignerThresholdMet };
            }
          }
        } catch {/* ignore bundle errors */}
        try {
          if (evidence.provenance?.materials) {
            const mats = evidence.provenance.materials;
            if (mats.length) {
              evidence.provenance.materialsComplete = mats.every(m => !!m.digest && m.digest.startsWith('sha256:'));
            }
          }
        } catch {/* ignore */}
        // Phase 7: derive statistical variance aggregate if mix or fallbackTiming present
        try {
          const evAny: any = evidence as any;
          if (evAny.mix || evAny.fallback || evAny.fallbackTiming || evAny.statisticalJitter) {
            const variance: any = {};
            if (evAny.statisticalJitter) {
              variance.jitterStdDevMs = evAny.statisticalJitter.stdDevMs;
              variance.jitterMeanMs = evAny.statisticalJitter.meanMs;
              variance.sampleCount = evAny.statisticalJitter.samples;
              variance.jitterWithinTarget = evAny.statisticalJitter.withinTarget === true;
            }
            if (evAny.mix) {
              variance.mixUniquenessRatio = evAny.mix.uniquenessRatio;
              variance.mixDiversityIndex = evAny.mix.diversityIndex;
            }
            if (Object.keys(variance).length) (evidence as any).statisticalVariance = variance;
          }
        } catch {/* ignore */}
      } catch (e: any) {
        console.warn(`⚠️  Failed to load evidence file ${options.evidenceFile}: ${e.message}`);
      }
    }
    // Optional SBOM ingestion for materials cross-check (Phase 3 partial)
    if (options.sbomFile && fs.existsSync(options.sbomFile)) {
      try {
        const sbomRaw = fs.readFileSync(options.sbomFile, 'utf8');
        let sbomObj: any = null;
        if (options.sbomFile.endsWith('.json')) {
          try { sbomObj = JSON.parse(sbomRaw); } catch {/* ignore */}
        } else if (options.sbomFile.endsWith('.xml')) {
          try { sbomObj = xml2js.parseStringPromise(sbomRaw); } catch {/* ignore */}
        } else { // attempt tag-value SPDX simplistic parse into map array
          const lines = sbomRaw.split(/\r?\n/);
          const pkgs: { name: string; version?: string; checksum?: string }[] = [];
          let current: any = {};
          for (const l of lines) {
            if (/^PackageName:\s+/.test(l)) {
              if (current.name) pkgs.push(current); current = { name: l.replace(/^PackageName:\s+/,'').trim() };
            } else if (/^PackageVersion:\s+/.test(l)) {
              current.version = l.replace(/^PackageVersion:\s+/,'').trim();
            } else if (/^PackageChecksum:\s+SHA256:\s+/.test(l)) {
              current.checksum = l.replace(/^PackageChecksum:\s+SHA256:\s+/,'').trim();
            }
          }
          if (current.name) pkgs.push(current);
          sbomObj = { _tagValuePackages: pkgs };
        }
        if (sbomObj) {
          (this._analyzer as any).ingestedSBOM = sbomObj;
          // Attempt immediate materials validation if both provenance & SBOM present
          const evidence: IngestedEvidence | undefined = (this._analyzer as any).evidence;
          if (evidence?.provenance?.materials && evidence.provenance.materials.length) {
            try {
              const sbomDigests = new Set<string>();
              // CycloneDX JSON format
              const cdxComponents = (sbomObj.components && Array.isArray(sbomObj.components)) ? sbomObj.components : (sbomObj.bom?.components?.component || []);
              if (Array.isArray(cdxComponents)) {
                cdxComponents.forEach((c: any) => {
                  const hashes = c.hashes || c.hashes?.hash || [];
                  if (Array.isArray(hashes)) hashes.forEach((h: any) => { if (h.content) sbomDigests.add('sha256:' + (h.content || '').toLowerCase()); });
                });
              }
              // SPDX JSON
              if (Array.isArray(sbomObj.packages)) {
                sbomObj.packages.forEach((p: any) => {
                  if (Array.isArray(p.checksums)) p.checksums.forEach((cs: any) => { if (cs.algorithm === 'SHA256' && cs.checksumValue) sbomDigests.add('sha256:' + cs.checksumValue.toLowerCase()); });
                });
              }
              // SPDX tag-value fallback
              if (Array.isArray(sbomObj._tagValuePackages)) {
                sbomObj._tagValuePackages.forEach((p: any) => { if (p.checksum) sbomDigests.add('sha256:' + p.checksum.toLowerCase()); });
              }
              const materials = evidence.provenance.materials;
              const unmatched = materials.filter(m => m.digest && !sbomDigests.has(m.digest.toLowerCase()));
              evidence.provenance.materialsMismatchCount = unmatched.length;
              evidence.provenance.materialsValidated = unmatched.length === 0;
            } catch {/* ignore validation errors */}
          }
        }
      } catch (e: any) {
        console.warn(`⚠️  Failed to ingest SBOM file ${options.sbomFile}: ${e.message}`);
      }
    }
    // Phase 6: Governance & ledger evidence ingestion (single JSON file) if provided
    if (options.governanceFile && fs.existsSync(options.governanceFile)) {
      try {
        const rawGov = fs.readFileSync(options.governanceFile, 'utf8');
        const govObj = JSON.parse(rawGov);
        const analyzerAny: any = this._analyzer as any;
        analyzerAny.evidence = analyzerAny.evidence || {};
        if (govObj.governance) analyzerAny.evidence.governance = govObj.governance;
        if (govObj.ledger) analyzerAny.evidence.ledger = govObj.ledger;
        if (govObj.governanceHistoricalDiversity) {
          analyzerAny.evidence.governanceHistoricalDiversity = govObj.governanceHistoricalDiversity;
          try {
            const { evaluateHistoricalDiversity, evaluateHistoricalDiversityAdvanced } = require('./governance-parser');
            const result = evaluateHistoricalDiversity(govObj.governanceHistoricalDiversity.series || []);
            analyzerAny.evidence.governanceHistoricalDiversity.stable = result.stable;
            analyzerAny.evidence.governanceHistoricalDiversity.maxASShare = result.maxASShare;
            analyzerAny.evidence.governanceHistoricalDiversity.avgTop3 = result.avgTop3;
            const adv = evaluateHistoricalDiversityAdvanced(govObj.governanceHistoricalDiversity.series || []);
            analyzerAny.evidence.governanceHistoricalDiversity.advancedStable = adv.advancedStable;
            analyzerAny.evidence.governanceHistoricalDiversity.volatility = adv.volatility;
            analyzerAny.evidence.governanceHistoricalDiversity.maxWindowShare = adv.maxWindowShare;
          } catch {/* ignore */}
        }
      } catch (e: any) {
        console.warn(`⚠️  Failed to ingest governance evidence ${options.governanceFile}: ${e.message}`);
      }
    }
    // Enable dynamic probe if requested or via env toggle
    if ((options.dynamicProbe || process.env.BETANET_DYNAMIC_PROBE === '1') && typeof (this._analyzer as any).setDynamicProbe === 'function') {
      (this._analyzer as any).setDynamicProbe(true);
    }
  }
  private resolveDefinitions(options: CheckOptions) {
  let ids = ALL_CHECKS.map(c => c.id);
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
      if (heuristicContributionCount > 0) passed = false;
    }
    const diagnostics = (() => { const a: any = this.analyzer; if (a && typeof a.getDiagnostics === 'function') { try { return a.getDiagnostics(); } catch { return undefined; } } return undefined; })();
  const implementedChecks = ALL_CHECKS.filter((c: any) => isVersionLE(c.introducedIn, SPEC_VERSION_PARTIAL)).length;
  const specSummary = { baseline: SPEC_VERSION_SUPPORTED_BASE, latestKnown: SPEC_VERSION_PARTIAL, implementedChecks, totalChecks: ALL_CHECKS.length, pendingIssues: SPEC_11_PENDING_ISSUES };
    const result: ComplianceResult = { binaryPath, timestamp: new Date().toISOString(), overallScore, passed, checks, summary: { total: considered.length, passed: passedChecks.length, failed: considered.length - passedChecks.length, critical: criticalChecks.length }, specSummary, diagnostics };
    // Multi-signal scoring (Step 8)
    const catCounts = { heuristic: 0, 'static-structural': 0, 'dynamic-protocol': 0, artifact: 0 } as any;
    for (const c of checks) {
      const et = (c.evidenceType || 'heuristic') as keyof typeof catCounts;
      if (catCounts[et] !== undefined && c.passed) catCounts[et]++;
    }
    const weightedScore = (catCounts.artifact * 3) + (catCounts['dynamic-protocol'] * 2) + (catCounts['static-structural'] * 1);
    result.multiSignal = {
      passedHeuristic: catCounts.heuristic,
      passedStatic: catCounts['static-structural'],
      passedDynamic: catCounts['dynamic-protocol'],
      passedArtifact: catCounts.artifact,
      weightedScore
    };
    // Augment multi-signal with category presence & stuffing heuristic summary
    try {
      const evidence: any = (this._analyzer as any).evidence || {};
      const categoriesPresent = ['provenance','governance','ledger','mix','clientHello','noise'].filter(k => !!evidence[k]);
      const SPEC_KEYWORDS = ['betanet','htx','quic','ech','ticket','rotation','scion','chacha20','poly1305','cashu','lightning','federation','slsa','reproducible','provenance','kyber','kyber768','x25519','beacon','diversity','voucher','frost','pow','governance','ledger','quorum','finality','mix','hop'];
      const analysisPromise = this._analyzer.analyze ? this._analyzer.analyze() : Promise.resolve({ strings: [] });
      analysisPromise.then(analysis => {
        const strings: string[] = analysis.strings || [];
        let keywordHits = 0;
        for (const s of strings) { const lower = s.toLowerCase(); if (SPEC_KEYWORDS.some(k => lower.includes(k))) keywordHits++; }
        const stuffingRatio = strings.length ? keywordHits / strings.length : 0;
        const suspicious = stuffingRatio > 0.6 && categoriesPresent.length < 3;
  Object.assign(result.multiSignal!, { categoriesPresent, stuffingRatio, suspiciousStuffing: suspicious });
        if (suspicious) {
          (result as any).warnings = (result as any).warnings || [];
          (result as any).warnings.push(`Potential keyword stuffing detected (density ${(stuffingRatio*100).toFixed(1)}% with only ${categoriesPresent.length} evidence categories). Provide additional independent evidence.`);
        }
      }).catch(()=>{/* ignore */});
    } catch {/* ignore augmentation errors */}
    (result as any).strictMode = strictMode;
    (result as any).allowHeuristic = allowHeuristic;
    (result as any).heuristicContributionCount = heuristicContributionCount;
    // Phase 0 requirement: emit warning when heuristic passes present
    const warnings: string[] = [];
    if (heuristicContributionCount > 0 && strictMode && !allowHeuristic) {
      warnings.push(`Heuristic-only evidence: ${heuristicContributionCount} check(s) passed with heuristic evidence and were excluded from compliance scoring. Add normative evidence or use --allow-heuristic to treat them as provisional.`);
    } else if (heuristicContributionCount > 0 && allowHeuristic) {
      warnings.push(`Heuristic evidence counted: ${heuristicContributionCount} check(s) rely solely on heuristic signals. Consider providing structural/dynamic/artifact evidence for strict compliance.`);
    }
    if (warnings.length) (result as any).warnings = warnings;
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
    if ((results as any).warnings && (results as any).warnings.length) {
      console.log('⚠️  WARNINGS:');
      (results as any).warnings.forEach((w: string) => console.log(` - ${w}`));
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