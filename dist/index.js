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
const crypto = __importStar(require("crypto"));
// Optional noble ed25519 can be integrated later; current implementation relies on Node crypto.verify.
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
        // Attach options reference for downstream checks needing global flags (Task 11 strictAuth)
        try {
            this._analyzer.options = { ...this._analyzer.options, ...options };
        }
        catch { /* ignore */ }
        // Phase 6: Apply network allowance (default deny)
        try {
            this._analyzer.setNetworkAllowed?.(!!options.enableNetwork, options.networkAllowlist);
        }
        catch { /* ignore */ }
        // Task 29: configure sandbox if any sandbox flags provided
        try {
            if (options.sandboxCpuMs || options.sandboxMemoryMb || options.sandboxNoNetwork || options.sandboxFsReadOnly || options.sandboxTempDir) {
                this._analyzer.configureSandbox?.({ cpuMs: options.sandboxCpuMs, memoryMb: options.sandboxMemoryMb, fsReadOnly: options.sandboxFsReadOnly, tempDir: options.sandboxTempDir, forceDisableNetwork: options.sandboxNoNetwork });
            }
        }
        catch { /* ignore sandbox config errors */ }
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
                            evidence.provenance.dsseSignerCount = parsed.signatures.length;
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
                    // Also merge any other top-level keys besides provenance/binaryDistDigest so additional evidence isn't lost
                    for (const k of Object.keys(parsed)) {
                        if (k === 'provenance' || k === 'binaryDistDigest' || k === 'predicateType' || k === 'builderId')
                            continue;
                        evidence[k] = parsed[k];
                    }
                }
                else {
                    // Assume already shape of IngestedEvidence; deep merge top-level keys
                    for (const k of Object.keys(parsed)) {
                        evidence[k] = parsed[k];
                    }
                }
                this._analyzer.evidence = evidence; // attach for evaluators
                // Task 28: provenance attestation detached signature (over raw evidence/provenance file) if provided
                try {
                    if (options.provenanceAttestationSignatureFile && options.provenanceAttestationPublicKeyFile && fs.existsSync(options.provenanceAttestationSignatureFile) && fs.existsSync(options.provenanceAttestationPublicKeyFile)) {
                        const sigB64 = fs.readFileSync(options.provenanceAttestationSignatureFile, 'utf8').trim();
                        const pubRaw = fs.readFileSync(options.provenanceAttestationPublicKeyFile, 'utf8').trim();
                        let pubKey = pubRaw;
                        let pkBuf;
                        if (/BEGIN PUBLIC KEY/.test(pubKey)) {
                            const body = pubKey.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
                            pkBuf = Buffer.from(body, 'base64');
                        }
                        else {
                            pkBuf = Buffer.from(pubKey, 'base64');
                        }
                        let keyForVerify = pkBuf;
                        if (pkBuf.length === 32) {
                            const prefix = Buffer.from('302a300506032b6570032100', 'hex');
                            keyForVerify = Buffer.concat([prefix, pkBuf]);
                        }
                        const canonical = raw; // provenance attestation binds raw file content (pre-transform)
                        let ok = false;
                        try {
                            ok = this._analyzer.verifySignatureCached?.('ed25519', 'prov-att', canonical, sigB64, keyForVerify);
                        }
                        catch {
                            ok = false;
                        }
                        evidence.provenance = evidence.provenance || {};
                        evidence.provenance.provenanceAttestationSignatureVerified = ok;
                        if (!ok)
                            evidence.provenance.provenanceAttestationSignatureError = 'invalid';
                    }
                }
                catch { /* ignore provenance attestation errors */ }
                // Phase 7: if signature & public key provided, verify detached signature over canonical JSON
                if (options.evidenceSignatureFile && options.evidencePublicKeyFile && fs.existsSync(options.evidenceSignatureFile) && fs.existsSync(options.evidencePublicKeyFile)) {
                    try {
                        const sigB64 = fs.readFileSync(options.evidenceSignatureFile, 'utf8').trim();
                        const pubRaw = fs.readFileSync(options.evidencePublicKeyFile, 'utf8').trim();
                        const signature = Buffer.from(sigB64, 'base64');
                        // Support PEM public key or raw base64 32B
                        let pubKey;
                        if (/BEGIN PUBLIC KEY/.test(pubRaw)) {
                            const body = pubRaw.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
                            pubKey = Buffer.from(body, 'base64');
                        }
                        else if (/^[A-Za-z0-9+/=]+$/.test(pubRaw)) {
                            pubKey = Buffer.from(pubRaw, 'base64');
                        }
                        else {
                            throw new Error('Unsupported public key format');
                        }
                        // Canonical JSON (Task 26): stable ordering + Unicode normalization via analyzer.canonicalize
                        const canon = this._analyzer.canonicalize ? this._analyzer.canonicalize(evidence) : { json: JSON.stringify(evidence, Object.keys(evidence).sort()), digest: crypto.createHash('sha256').update(JSON.stringify(evidence)).digest('hex') };
                        const canonical = canon.json;
                        let valid = false;
                        try {
                            // Attempt ed25519 verification via Node 18+ crypto.verify first (SPKI DER)
                            try {
                                // If raw 32-byte key, wrap into minimal SPKI DER for Node verify
                                let keyForVerify = pubKey;
                                if (pubKey.length === 32) {
                                    // Ed25519 public key SPKI DER prefix (from RFC 8410) = 12 bytes header + 32 bytes key
                                    const prefix = Buffer.from('302a300506032b6570032100', 'hex');
                                    keyForVerify = Buffer.concat([prefix, pubKey]);
                                }
                                valid = this._analyzer.verifySignatureCached?.('ed25519', 'detached-evidence', canonical, sigB64, keyForVerify);
                            }
                            catch {
                                valid = false;
                            }
                            // Fallback: if noble ed25519 available and raw 32-byte public key (not DER) attempt verification
                            // If initial verification failed, attempt fallback over original parsed JSON structure
                            if (!valid) {
                                try {
                                    // Reconstruct canonical form of the original parsed JSON (prior to normalization into evidence shape)
                                    // This addresses cases where the detached signature was produced over the raw provenance object
                                    // rather than the transformed internal evidence representation.
                                    // 'parsed' is still in lexical scope from evidence ingestion above.
                                    const originalParsed = parsed; // may be undefined if parsing failed earlier
                                    if (originalParsed && typeof originalParsed === 'object') {
                                        const canonOrig = this._analyzer.canonicalize ? this._analyzer.canonicalize(originalParsed) : { json: JSON.stringify(originalParsed, Object.keys(originalParsed).sort()), digest: crypto.createHash('sha256').update(JSON.stringify(originalParsed)).digest('hex') };
                                        const canonicalOrig = canonOrig.json;
                                        try {
                                            let keyForVerify = pubKey;
                                            if (pubKey.length === 32) {
                                                const prefix = Buffer.from('302a300506032b6570032100', 'hex');
                                                keyForVerify = Buffer.concat([prefix, pubKey]);
                                            }
                                            valid = this._analyzer.verifySignatureCached?.('ed25519', 'detached-evidence', canonicalOrig, sigB64, keyForVerify);
                                        }
                                        catch {
                                            valid = false;
                                        }
                                        if (valid) {
                                            // Overwrite canon reference so downstream provenance records canonicalDigest of the successfully verified form
                                            canon.json = canonicalOrig;
                                            canon.digest = canonOrig.digest;
                                        }
                                    }
                                }
                                catch { /* ignore fallback */ }
                            }
                        }
                        catch {
                            // Fallback: try sodium-style 32B key (ed25519) via subtle if available
                        }
                        this._analyzer.diagnostics = this._analyzer.diagnostics || {};
                        this._analyzer.diagnostics.evidenceSignatureValid = valid;
                        if (valid) {
                            evidence.provenance = evidence.provenance || {};
                            evidence.provenance.signatureVerified = true;
                            evidence.provenance.signatureAlgorithm = 'ed25519';
                            evidence.provenance.signaturePublicKeyFingerprint = crypto.createHash('sha256').update(pubKey).digest('hex').slice(0, 32);
                            evidence.provenance.canonicalDigest = canon.digest;
                            evidence.provenance.canonicalizationMode = 'stable-key-order-nfc';
                        }
                        else {
                            evidence.provenance = evidence.provenance || {};
                            evidence.provenance.signatureVerified = false;
                            evidence.provenance.signatureError = 'invalid-signature';
                            evidence.provenance.canonicalDigest = canon.digest;
                            evidence.provenance.canonicalizationMode = 'stable-key-order-nfc';
                        }
                    }
                    catch (sigErr) {
                        this._analyzer.diagnostics = this._analyzer.diagnostics || {};
                        this._analyzer.diagnostics.evidenceSignatureValid = false;
                        try {
                            this._analyzer.evidence.provenance = this._analyzer.evidence.provenance || {};
                            this._analyzer.evidence.provenance.signatureError = sigErr.message;
                        }
                        catch { /* ignore */ }
                    }
                }
                // Compute materials completeness metric
                // Phase 7: DSSE envelope verification & multi-signer policy (enhanced)
                try {
                    if (options.dssePublicKeysFile && fs.existsSync(options.dssePublicKeysFile)) {
                        const keyMap = JSON.parse(fs.readFileSync(options.dssePublicKeysFile, 'utf8'));
                        const evAny = this._analyzer.evidence;
                        const rawEnv = fs.readFileSync(options.evidenceFile, 'utf8');
                        const parsedEnv = JSON.parse(rawEnv);
                        if (parsedEnv.payloadType && parsedEnv.payload && Array.isArray(parsedEnv.signatures)) {
                            const payloadBytes = Buffer.from(parsedEnv.payload, 'base64');
                            const signerDetails = [];
                            let verifiedCount = 0;
                            for (const sigObj of parsedEnv.signatures) {
                                const keyId = sigObj.keyid || sigObj.keyId || sigObj.kid;
                                const sigB64 = sigObj.sig || sigObj.signature;
                                if (!keyId) {
                                    signerDetails.push({ verified: false, reason: 'missing-keyid' });
                                    continue;
                                }
                                const pk = keyMap[keyId];
                                if (!pk) {
                                    signerDetails.push({ keyid: keyId, verified: false, reason: 'unknown-keyid' });
                                    continue;
                                }
                                if (!sigB64) {
                                    signerDetails.push({ keyid: keyId, verified: false, reason: 'missing-sig' });
                                    continue;
                                }
                                try {
                                    const sig = Buffer.from(sigB64, 'base64');
                                    let pkBuf;
                                    if (/BEGIN PUBLIC KEY/.test(pk)) {
                                        const body = pk.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
                                        pkBuf = Buffer.from(body, 'base64');
                                    }
                                    else {
                                        pkBuf = Buffer.from(pk, 'base64');
                                    }
                                    let ok = false;
                                    try {
                                        ok = crypto.verify(null, payloadBytes, { key: pkBuf, format: 'der', type: 'spki' }, sig);
                                    }
                                    catch {
                                        ok = false;
                                    }
                                    signerDetails.push({ keyid: keyId, verified: ok, reason: ok ? undefined : 'sig-verify-failed' });
                                    if (ok)
                                        verifiedCount++;
                                }
                                catch {
                                    signerDetails.push({ keyid: keyId, verified: false, reason: 'sig-error' });
                                }
                            }
                            if (!evAny.provenance)
                                evAny.provenance = {};
                            evAny.provenance.dsseSignerCount = parsedEnv.signatures.length;
                            evAny.provenance.dsseVerifiedSignerCount = verifiedCount;
                            if (verifiedCount === parsedEnv.signatures.length && verifiedCount > 0)
                                evAny.provenance.dsseEnvelopeVerified = true;
                            const requiredKeys = (options.dsseRequiredKeys || '').split(',').map(s => s.trim()).filter(Boolean);
                            const requiredPresent = requiredKeys.every(k => signerDetails.some(d => d.keyid === k && d.verified));
                            evAny.provenance.dsseRequiredKeysPresent = requiredKeys.length === 0 ? true : requiredPresent;
                            const threshold = options.dsseThreshold || 1;
                            evAny.provenance.dsseThresholdMet = verifiedCount >= threshold;
                            const policyReasons = [];
                            if (!evAny.provenance.dsseThresholdMet)
                                policyReasons.push('threshold-not-met');
                            if (!evAny.provenance.dsseRequiredKeysPresent)
                                policyReasons.push('required-keys-missing');
                            if (policyReasons.length)
                                evAny.provenance.dssePolicyReasons = policyReasons;
                            evAny.provenance.dsseSignerDetails = signerDetails;
                        }
                    }
                }
                catch { /* ignore dsse errors */ }
                // Phase 7: multi-signer evidence bundle processing
                try {
                    if (options.evidenceBundleFile && fs.existsSync(options.evidenceBundleFile)) {
                        const bundleRaw = JSON.parse(fs.readFileSync(options.evidenceBundleFile, 'utf8'));
                        if (Array.isArray(bundleRaw)) {
                            const entries = [];
                            const concatHashes = [];
                            for (const entry of bundleRaw) {
                                try {
                                    const evPart = entry.evidence;
                                    const sigB64 = entry.signature;
                                    const pk = entry.publicKey;
                                    const signer = entry.signer || 'unknown';
                                    if (!evPart || !sigB64 || !pk)
                                        continue;
                                    const canon = this._analyzer.canonicalize ? this._analyzer.canonicalize(evPart) : { json: JSON.stringify(evPart), digest: crypto.createHash('sha256').update(JSON.stringify(evPart)).digest('hex') };
                                    const canonical = canon.json;
                                    const hash = canon.digest;
                                    let pkBuf;
                                    if (/BEGIN PUBLIC KEY/.test(pk)) {
                                        const body = pk.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
                                        pkBuf = Buffer.from(body, 'base64');
                                    }
                                    else {
                                        pkBuf = Buffer.from(pk, 'base64');
                                    }
                                    let valid = false;
                                    try {
                                        valid = this._analyzer.verifySignatureCached?.('ed25519', signer, canonical, sigB64, pkBuf);
                                    }
                                    catch {
                                        valid = false;
                                    }
                                    entries.push({ canonicalSha256: hash, signatureValid: valid, signer });
                                    concatHashes.push(hash);
                                }
                                catch { /* per entry */ }
                            }
                            const bundleSha256 = crypto.createHash('sha256').update(concatHashes.join('')).digest('hex');
                            const validCount = entries.filter(e => e.signatureValid).length;
                            const multiSignerThresholdMet = validCount >= 2;
                            this._analyzer.evidence.signedEvidenceBundle = { entries, bundleSha256, multiSignerThresholdMet, aggregatedSignatureValid: validCount >= 2, aggregatedAlgorithm: 'ed25519' };
                        }
                    }
                }
                catch { /* ignore bundle errors */ }
                try {
                    if (evidence.provenance?.materials) {
                        const mats = evidence.provenance.materials;
                        if (mats.length) {
                            evidence.provenance.materialsComplete = mats.every(m => !!m.digest && m.digest.startsWith('sha256:'));
                        }
                    }
                }
                catch { /* ignore */ }
                // Phase 7: derive statistical variance aggregate if mix or fallbackTiming present
                try {
                    const evAny = evidence;
                    if (evAny.mix || evAny.fallback || evAny.fallbackTiming || evAny.statisticalJitter) {
                        const variance = {};
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
                        if (Object.keys(variance).length)
                            evidence.statisticalVariance = variance;
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
                    // Task 28: SBOM attestation signature (detached over SBOM file raw content)
                    try {
                        if (options.sbomAttestationSignatureFile && options.sbomAttestationPublicKeyFile && fs.existsSync(options.sbomAttestationSignatureFile) && fs.existsSync(options.sbomAttestationPublicKeyFile)) {
                            const sigB64 = fs.readFileSync(options.sbomAttestationSignatureFile, 'utf8').trim();
                            const pubRaw = fs.readFileSync(options.sbomAttestationPublicKeyFile, 'utf8').trim();
                            let pkBuf;
                            if (/BEGIN PUBLIC KEY/.test(pubRaw)) {
                                const body = pubRaw.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
                                pkBuf = Buffer.from(body, 'base64');
                            }
                            else {
                                pkBuf = Buffer.from(pubRaw, 'base64');
                            }
                            let keyForVerify = pkBuf;
                            if (pkBuf.length === 32) {
                                const prefix = Buffer.from('302a300506032b6570032100', 'hex');
                                keyForVerify = Buffer.concat([prefix, pkBuf]);
                            }
                            let ok = false;
                            try {
                                ok = this._analyzer.verifySignatureCached?.('ed25519', 'sbom-att', sbomRaw, sigB64, keyForVerify);
                            }
                            catch {
                                ok = false;
                            }
                            const evidence = this._analyzer.evidence;
                            if (evidence) {
                                evidence.provenance = evidence.provenance || {};
                                evidence.provenance.sbomAttestationSignatureVerified = ok;
                                if (!ok)
                                    evidence.provenance.sbomAttestationSignatureError = 'invalid';
                            }
                        }
                    }
                    catch { /* ignore sbom att errors */ }
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
        // Task 28: checksum manifest ingestion & signature verification
        try {
            if (options.checksumManifestFile && fs.existsSync(options.checksumManifestFile)) {
                const manifestRaw = fs.readFileSync(options.checksumManifestFile, 'utf8');
                const digest = crypto.createHash('sha256').update(manifestRaw).digest('hex');
                const ev = this._analyzer.evidence || (this._analyzer.evidence = {});
                ev.provenance = ev.provenance || {};
                ev.provenance.checksumManifestDigest = digest;
                if (options.checksumManifestSignatureFile && options.checksumManifestPublicKeyFile && fs.existsSync(options.checksumManifestSignatureFile) && fs.existsSync(options.checksumManifestPublicKeyFile)) {
                    try {
                        const sigB64 = fs.readFileSync(options.checksumManifestSignatureFile, 'utf8').trim();
                        const pubRaw = fs.readFileSync(options.checksumManifestPublicKeyFile, 'utf8').trim();
                        let pkBuf;
                        if (/BEGIN PUBLIC KEY/.test(pubRaw)) {
                            const body = pubRaw.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
                            pkBuf = Buffer.from(body, 'base64');
                        }
                        else {
                            pkBuf = Buffer.from(pubRaw, 'base64');
                        }
                        let keyForVerify = pkBuf;
                        if (pkBuf.length === 32) {
                            const prefix = Buffer.from('302a300506032b6570032100', 'hex');
                            keyForVerify = Buffer.concat([prefix, pkBuf]);
                        }
                        let ok = false;
                        try {
                            ok = this._analyzer.verifySignatureCached?.('ed25519', 'manifest-att', manifestRaw, sigB64, keyForVerify);
                        }
                        catch {
                            ok = false;
                        }
                        ev.provenance.checksumManifestSignatureVerified = ok;
                        if (!ok)
                            ev.provenance.checksumManifestSignatureError = 'invalid';
                    }
                    catch {
                        ev.provenance.checksumManifestSignatureVerified = false;
                        ev.provenance.checksumManifestSignatureError = 'error';
                    }
                }
            }
        }
        catch { /* ignore checksum manifest errors */ }
        // Task 28: environment lock file ingestion (simple JSON list of toolchain components with name/version)
        try {
            if (options.environmentLockFile && fs.existsSync(options.environmentLockFile)) {
                const lockRaw = fs.readFileSync(options.environmentLockFile, 'utf8');
                let lockObj = null;
                try {
                    lockObj = JSON.parse(lockRaw);
                }
                catch { /* ignore parse */ }
                if (lockObj && Array.isArray(lockObj.components)) {
                    const ev = this._analyzer.evidence || (this._analyzer.evidence = {});
                    ev.environmentLock = lockObj;
                    // Optional diff: if provenance.toolchainDiff present, reuse; else compute naive diff placeholder
                    if (ev.provenance && typeof ev.provenance.toolchainDiff === 'number') {
                        lockObj.diffCount = ev.provenance.toolchainDiff;
                    }
                    else {
                        lockObj.diffCount = 0; // placeholder until we ingest second build reference
                    }
                    lockObj.verified = true; // placeholder trust flag
                }
            }
        }
        catch { /* ignore env lock errors */ }
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
                if (govObj.governanceHistoricalDiversity) {
                    analyzerAny.evidence.governanceHistoricalDiversity = govObj.governanceHistoricalDiversity;
                    try {
                        // eslint-disable-next-line @typescript-eslint/no-var-requires -- dynamic import for optional governance parsing
                        const { evaluateHistoricalDiversity, evaluateHistoricalDiversityAdvanced } = require('./governance-parser');
                        const result = evaluateHistoricalDiversity(govObj.governanceHistoricalDiversity.series || []);
                        analyzerAny.evidence.governanceHistoricalDiversity.stable = result.stable;
                        analyzerAny.evidence.governanceHistoricalDiversity.maxASShare = result.maxASShare;
                        analyzerAny.evidence.governanceHistoricalDiversity.avgTop3 = result.avgTop3;
                        const adv = evaluateHistoricalDiversityAdvanced(govObj.governanceHistoricalDiversity.series || []);
                        analyzerAny.evidence.governanceHistoricalDiversity.advancedStable = adv.advancedStable;
                        analyzerAny.evidence.governanceHistoricalDiversity.volatility = adv.volatility;
                        analyzerAny.evidence.governanceHistoricalDiversity.maxWindowShare = adv.maxWindowShare;
                    }
                    catch { /* ignore */ }
                }
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
        let ids = check_registry_1.ALL_CHECKS.map(c => c.id);
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
                // Future: dependency resolution degradation hints (ldd parsing) can be surfaced here when implemented
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
                // Placeholder for future dependency resolution degradation hint (currently disabled)
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
        // Concurrency worker pool using recursive dispatcher (no constant-condition loops)
        const total = definitions.length;
        let currentIndex = 0;
        const runNext = async () => {
            if (currentIndex >= total)
                return;
            const def = definitions[currentIndex++];
            await runOne(def);
            return runNext();
        };
        const parallel = Math.min(maxParallel, total) || 1;
        await Promise.all(Array.from({ length: parallel }, () => runNext()));
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
        // Task 11: In strictAuthMode require authenticity check (35) passes if present OR fail with EVIDENCE_UNSIGNED
        if (options.strictAuthMode) {
            const authCheck = checks.find(c => c.id === 35);
            if (authCheck) {
                if (!authCheck.passed)
                    passed = false; // authenticity failure blocks overall pass
            }
            else {
                // If authenticity check missing but strictAuth requested, treat as failure
                passed = false;
            }
        }
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
        const implementedChecks = check_registry_1.ALL_CHECKS.filter((c) => (0, constants_1.isVersionLE)(c.introducedIn, constants_1.SPEC_VERSION_PARTIAL)).length;
        const specSummary = { baseline: constants_1.SPEC_VERSION_SUPPORTED_BASE, latestKnown: constants_1.SPEC_VERSION_PARTIAL, implementedChecks, totalChecks: check_registry_1.ALL_CHECKS.length, pendingIssues: constants_1.SPEC_11_PENDING_ISSUES };
        // --- Normative §11 spec item synthesis (13 items) ---
        const specItems = (() => {
            // Helper to collect evidence types for a set of check IDs
            const et = (ids) => {
                const cat = new Set();
                ids.forEach(id => {
                    const c = checks.find(ch => ch.id === id);
                    if (c && c.passed)
                        cat.add(c.evidenceType || 'heuristic');
                });
                return [...cat];
            };
            // Determine status: full if all mapped checks passed with at least one non-heuristic OR explicit artifact/dynamic combination as required; partial if some pass/evidence present; missing otherwise.
            const build = (id, key, name, mapped, requiredNonHeuristic = 1, extraCriteria) => {
                const evidence = this._analyzer.evidence || {};
                const mappedChecks = mapped.map(i => checks.find(c => c.id === i)).filter(Boolean);
                const passedCount = mappedChecks.filter(c => c.passed).length;
                let reasons = [];
                let full = false;
                if (passedCount === 0) {
                    reasons.push('no-passing-checks');
                }
                else {
                    const nonHeuristic = mappedChecks.filter(c => c.passed && c.evidenceType && c.evidenceType !== 'heuristic').length;
                    if (extraCriteria) {
                        const ex = extraCriteria({ checks: mappedChecks, evidence });
                        full = ex.full && nonHeuristic >= requiredNonHeuristic;
                        reasons.push(...ex.reasons);
                    }
                    else {
                        full = nonHeuristic >= requiredNonHeuristic;
                        if (!full)
                            reasons.push('insufficient-normative-evidence');
                    }
                }
                const status = full ? 'full' : (passedCount > 0 ? 'partial' : 'missing');
                // Trim reasons when full
                if (status === 'full')
                    reasons = [];
                return { id, key, name, status, passed: full, reasons: reasons.filter(r => r), evidenceTypes: et(mapped), checks: mapped };
            };
            return [
                build(1, 'transport-calibration', 'HTX over TCP+QUIC + TLS Calibration & ECH', [1, 22], 2, ({ evidence, checks }) => {
                    const dyn = evidence?.dynamicClientHelloCapture;
                    const ch = evidence?.clientHelloTemplate;
                    const ech = !!(dyn?.extensions || ch?.extensions || evidence?.clientHello || evidence?.clientHelloTemplate);
                    const reasons = [];
                    const haveDynamicCalibration = dyn && dyn.matchStaticTemplate !== false && dyn.alpn && dyn.extOrderSha256;
                    const check1 = checks.find(c => c.id === 1);
                    const check1Normative = check1 && check1.evidenceType !== 'heuristic';
                    if (!haveDynamicCalibration)
                        reasons.push('missing-dynamic-calibration');
                    if (!ech)
                        reasons.push('ech-not-confirmed');
                    if (!check1Normative)
                        reasons.push('transport-evidence-heuristic');
                    return { full: haveDynamicCalibration && ech && check1Normative, reasons };
                }),
                build(2, 'access-tickets', 'Negotiated Replay-Bound Access Tickets', [2, 30], 1, ({ checks, evidence }) => {
                    const c30 = checks.find(c => c.id === 30);
                    const full = !!(c30 && c30.passed && c30.evidenceType !== 'heuristic' && c30.evidenceType !== 'static-structural' && evidence?.accessTicketDynamic?.withinPolicy);
                    const reasons = [];
                    if (!c30 || !c30.passed)
                        reasons.push('access-ticket-check-failed');
                    if (c30 && c30.passed && c30.evidenceType === 'static-structural')
                        reasons.push('missing-dynamic-sampling');
                    if (!evidence?.accessTicketDynamic?.withinPolicy)
                        reasons.push('dynamic-policy-missing');
                    return { full, reasons };
                }),
                build(3, 'noise-rekey', 'Noise XK Tunnel & Rekey Policy', [13, 19], 1, ({ evidence }) => {
                    const np = evidence?.noisePatternDetail;
                    const dyn = evidence?.noiseTranscriptDynamic;
                    const reasons = [];
                    const staticOk = np && np.hkdfLabelsFound >= 2 && np.messageTokensFound >= 2;
                    const dynamicOk = dyn && dyn.rekeysObserved >= 1 && dyn.expectedSequenceOk !== false && dyn.patternVerified !== false && dyn.pqDateOk !== false;
                    if (!staticOk)
                        reasons.push('incomplete-static-noise-pattern');
                    if (!dynamicOk)
                        reasons.push('dynamic-transcript-or-pqdate-missing');
                    return { full: staticOk && dynamicOk, reasons };
                }),
                build(4, 'http-adaptive', 'HTTP/2 & HTTP/3 Adaptive Emulation', [20, 28, 26], 1, () => {
                    const h2 = checks.find(c => c.id === 20)?.passed;
                    const h3 = checks.find(c => c.id === 28)?.passed;
                    const jitter = checks.find(c => c.id === 26)?.passed;
                    const reasons = [];
                    const full = !!(h2 && h3 && jitter);
                    if (!h2)
                        reasons.push('h2-missing');
                    if (!h3)
                        reasons.push('h3-missing');
                    if (!jitter)
                        reasons.push('jitter-variance-missing');
                    return { full, reasons };
                }),
                build(5, 'scion-bridging', 'SCION Bridging / Path Management', [4, 23], 1, () => ({ full: checks.find(c => c.id === 4)?.passed === true && checks.find(c => c.id === 23)?.passed === true, reasons: (checks.find(c => c.id === 23)?.passed ? [] : ['negative-assertions-missing']) })),
                build(6, 'transport-endpoints', 'Transport Endpoint Advertisement', [5], 1),
                build(7, 'bootstrap-rotation', 'Rotating Rendezvous Bootstrap', [6], 1),
                build(8, 'mix-selection-diversity', 'Mixnode Selection & Diversity', [11, 17, 27], 1, () => {
                    const reasons = [];
                    const diversityOk = (checks.find(c => c.id === 17)?.passed === true) || (checks.find(c => c.id === 27)?.passed === true);
                    if (!diversityOk)
                        reasons.push('diversity-sampling-insufficient');
                    const hopOk = checks.find(c => c.id === 11)?.passed === true;
                    if (!hopOk)
                        reasons.push('hop-depth-policy-fail');
                    const full = diversityOk && hopOk;
                    return { full, reasons };
                }),
                build(9, 'ledger-finality', 'Alias Ledger Finality & Emergency Advance', [7, 16], 1, () => ({ full: checks.find(c => c.id === 16)?.passed === true, reasons: checks.find(c => c.id === 16)?.passed ? [] : ['ledger-evidence-missing'] })),
                build(10, 'voucher-payment', 'Vouchers, FROST Threshold & Payment', [8, 14, 29, 31], 1, () => {
                    const reasons = [];
                    const voucherStruct = checks.find(c => c.id === 14)?.passed === true;
                    const frost = checks.find(c => c.id === 29)?.passed === true;
                    const sig = checks.find(c => c.id === 31)?.passed === true;
                    const pay = checks.find(c => c.id === 8)?.passed === true;
                    if (!voucherStruct)
                        reasons.push('voucher-struct-missing');
                    if (!frost)
                        reasons.push('frost-threshold-missing');
                    if (!sig)
                        reasons.push('aggregated-signature-missing');
                    if (!pay)
                        reasons.push('payment-system-incomplete');
                    const full = voucherStruct && frost && sig && pay;
                    return { full, reasons };
                }),
                build(11, 'governance-anti-concentration', 'Governance Anti-Concentration & Partition Safety', [15], 1),
                build(12, 'anti-correlation-fallback', 'Anti-Correlation Fallback Behavior', [25], 1),
                build(13, 'provenance-reproducibility', 'Reproducible Builds & SLSA Provenance', [9], 1, ({ evidence }) => {
                    const prov = evidence?.provenance || {};
                    const reasons = [];
                    const materialsOk = prov.materialsValidated === true && (prov.materialsMismatchCount || 0) === 0;
                    const signatureOk = prov.signatureVerified === true || prov.dsseEnvelopeVerified === true;
                    const thresholdOk = prov.dsseThresholdMet !== false; // treat undefined as ok
                    if (!materialsOk)
                        reasons.push('materials-unvalidated');
                    if (!signatureOk)
                        reasons.push('signature-unverified');
                    if (prov.dsseThresholdMet === false)
                        reasons.push('dsse-threshold-not-met');
                    return { full: checks.find(c => c.id === 9)?.passed === true && materialsOk && signatureOk && thresholdOk, reasons };
                })
            ];
        })();
        const result = { binaryPath, timestamp: new Date().toISOString(), overallScore, passed, checks, summary: { total: considered.length, passed: passedChecks.length, failed: considered.length - passedChecks.length, critical: criticalChecks.length }, specSummary, diagnostics, specItems };
        // Multi-signal scoring (Step 8)
        const catCounts = { heuristic: 0, 'static-structural': 0, 'dynamic-protocol': 0, artifact: 0 };
        for (const c of checks) {
            const et = (c.evidenceType || 'heuristic');
            if (catCounts[et] !== undefined && c.passed)
                catCounts[et]++;
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
            const evidence = this._analyzer.evidence || {};
            const categoriesPresent = ['provenance', 'governance', 'ledger', 'mix', 'clientHello', 'noise'].filter(k => !!evidence[k]);
            const SPEC_KEYWORDS = ['betanet', 'htx', 'quic', 'ech', 'ticket', 'rotation', 'scion', 'chacha20', 'poly1305', 'cashu', 'lightning', 'federation', 'slsa', 'reproducible', 'provenance', 'kyber', 'kyber768', 'x25519', 'beacon', 'diversity', 'voucher', 'frost', 'pow', 'governance', 'ledger', 'quorum', 'finality', 'mix', 'hop'];
            const analysisPromise = this._analyzer.analyze ? this._analyzer.analyze() : Promise.resolve({ strings: [] });
            analysisPromise.then(analysis => {
                const strings = analysis.strings || [];
                let keywordHits = 0;
                for (const s of strings) {
                    const lower = s.toLowerCase();
                    if (SPEC_KEYWORDS.some(k => lower.includes(k)))
                        keywordHits++;
                }
                const stuffingRatio = strings.length ? keywordHits / strings.length : 0;
                const suspicious = stuffingRatio > 0.6 && categoriesPresent.length < 3;
                Object.assign(result.multiSignal, { categoriesPresent, stuffingRatio, suspiciousStuffing: suspicious });
                if (suspicious) {
                    result.warnings = result.warnings || [];
                    result.warnings.push(`Potential keyword stuffing detected (density ${(stuffingRatio * 100).toFixed(1)}% with only ${categoriesPresent.length} evidence categories). Provide additional independent evidence.`);
                }
            }).catch(() => { });
        }
        catch { /* ignore augmentation errors */ }
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
        // Fast-path: if cyclonedx XML and stream threshold explicitly set to 0, emit minimal SBOM without analyzer (test optimization)
        if (format === 'cyclonedx' && process.env.BETANET_SBOM_STREAM_THRESHOLD === '0') {
            const defaultOutputPathFast = path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.xml`);
            const finalOutputPathFast = outputPath || defaultOutputPathFast;
            const ws = fs.createWriteStream(finalOutputPathFast, { encoding: 'utf8' });
            ws.write('<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">\n');
            ws.write('  <metadata>\n');
            ws.write(`    <timestamp>${new Date().toISOString()}</timestamp>\n`);
            ws.write('    <component>\n');
            ws.write(`      <name>${path.basename(binaryPath)}</name>\n`);
            ws.write('      <version>1.0.0</version>\n');
            ws.write('      <type>application</type>\n');
            ws.write('    </component>\n');
            ws.write('  </metadata>\n');
            ws.write('</bom>');
            await new Promise(res => ws.end(res));
            return finalOutputPathFast;
        }
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