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
exports.BinaryAnalyzer = void 0;
const fs = __importStar(require("fs-extra"));
const safe_exec_1 = require("./safe-exec");
const constants_1 = require("./constants");
const heuristics_1 = require("./heuristics");
const crypto = __importStar(require("crypto"));
const static_parsers_1 = require("./static-parsers");
const binary_introspect_1 = require("./binary-introspect");
// Removed unused execa import; all external commands routed through safeExec for centralized timeout control
class BinaryAnalyzer {
    constructor(binaryPath, verbose = false) {
        this.dynamicProbe = false; // enable lightweight runtime '--help' probe enrichment
        this.cachedAnalysis = null;
        this.diagnostics = {
            tools: [],
            analyzeInvocations: 0,
            cached: false
        };
        this.analysisStartHr = null;
        this.binarySha256 = null;
        this.staticPatterns = null;
        this.structuralAugmented = false; // guard to avoid repeating Step 10 augmentation
        this.networkAllowed = false; // Phase 6: default deny network
        this.networkOps = [];
        this.networkAllowlist = null; // host allowlist when network enabled
        this.userAgent = 'betanet-linter/1.x';
        // Task 26: signature verification cache (digest|signer|algo -> boolean)
        this.signatureVerifyCache = new Map();
        // Task 29 sandbox state
        this.sandboxEnabled = false;
        this.sandboxFsReadOnly = false;
        this.sandboxStats = {
            cpuStart: 0,
            cpuUsedMs: 0,
            memoryPeakMb: 0,
            fsWrites: [],
            fsWriteCount: 0,
            fsWriteBytesTotal: 0,
            blockedNetworkAttempts: 0,
            blockedWriteAttempts: 0,
            diagnostics: [],
            violations: []
        };
        this.binaryPath = binaryPath;
        this.verbose = verbose;
        this.toolsReady = this.detectTools();
    }
    // Task 26: canonical JSON normalization (stable key ordering, UTF-8 NFC normalization)
    canonicalize(obj) {
        const normalizeUnicode = (s) => s.normalize('NFC');
        const stableStringify = (value) => {
            if (value === null || typeof value !== 'object') {
                if (typeof value === 'string')
                    return JSON.stringify(normalizeUnicode(value));
                return JSON.stringify(value);
            }
            if (Array.isArray(value)) {
                return '[' + value.map(v => stableStringify(v)).join(',') + ']';
            }
            const keys = Object.keys(value).sort();
            return '{' + keys.map(k => JSON.stringify(normalizeUnicode(k)) + ':' + stableStringify(value[k])).join(',') + '}';
        };
        const json = stableStringify(obj);
        const digest = crypto.createHash('sha256').update(json).digest('hex');
        return { json, digest };
    }
    // Task 26: verify signature with cache support
    verifySignatureCached(algo, signer, canonicalJson, signatureB64, publicKey) {
        const digest = crypto.createHash('sha256').update(canonicalJson).digest('hex');
        const cacheKey = `${algo}|${signer}|${digest}`;
        if (this.signatureVerifyCache.has(cacheKey)) {
            this.diagnostics.signatureCacheHits = (this.diagnostics.signatureCacheHits || 0) + 1;
            return this.signatureVerifyCache.get(cacheKey);
        }
        this.diagnostics.signatureCacheMisses = (this.diagnostics.signatureCacheMisses || 0) + 1;
        let valid = false;
        try {
            if (algo === 'ed25519') {
                let keyForVerify = publicKey;
                if (publicKey.length === 32) {
                    // Wrap raw 32-byte Ed25519 key into SPKI DER (RFC 8410)
                    const prefix = Buffer.from('302a300506032b6570032100', 'hex');
                    keyForVerify = Buffer.concat([prefix, publicKey]);
                }
                valid = crypto.verify(null, Buffer.from(canonicalJson), { key: keyForVerify, format: 'der', type: 'spki' }, Buffer.from(signatureB64, 'base64'));
            }
            else {
                // unsupported algorithms flagged later by check
                valid = false;
            }
        }
        catch {
            valid = false;
        }
        this.signatureVerifyCache.set(cacheKey, valid);
        return valid;
    }
    // Phase 6: allow external enabling of network usage
    setNetworkAllowed(allowed, allowlist) {
        this.networkAllowed = allowed;
        this.networkAllowlist = allowlist && allowlist.length ? allowlist.map(h => h.toLowerCase()) : null;
        this.diagnostics.networkAllowed = allowed;
    }
    // Task 29: enable sandbox with provided budgets
    configureSandbox(opts) {
        this.sandboxEnabled = true;
        this.sandboxCpuBudgetMs = opts.cpuMs;
        this.sandboxMemoryBudgetMb = opts.memoryMb;
        this.sandboxFsReadOnly = !!opts.fsReadOnly;
        this.sandboxTempDir = opts.tempDir;
        if (opts.forceDisableNetwork) {
            this.networkAllowed = false; // override
        }
        this.sandboxStats.cpuStart = performance.now();
    }
    sandboxCheckBudgets() {
        if (!this.sandboxEnabled)
            return;
        // Approximate CPU via wall clock diff (single-threaded assumption)
        const elapsed = performance.now() - this.sandboxStats.cpuStart;
        this.sandboxStats.cpuUsedMs = elapsed;
        if (this.sandboxCpuBudgetMs && elapsed > this.sandboxCpuBudgetMs && !this.sandboxStats.violations.includes('RISK_CPU_BUDGET_EXCEEDED')) {
            this.sandboxStats.violations.push('RISK_CPU_BUDGET_EXCEEDED');
            this.sandboxStats.diagnostics.push(`CPU time budget exceeded: ${Math.round(elapsed)}ms > ${this.sandboxCpuBudgetMs}ms`);
        }
        // Memory rough estimation: process rss (shared for process; coarse)
        try {
            const rssMb = (process.memoryUsage().rss / (1024 * 1024));
            if (rssMb > this.sandboxStats.memoryPeakMb)
                this.sandboxStats.memoryPeakMb = rssMb;
            if (this.sandboxMemoryBudgetMb && rssMb > this.sandboxMemoryBudgetMb && !this.sandboxStats.violations.includes('RISK_MEMORY_BUDGET_EXCEEDED')) {
                this.sandboxStats.violations.push('RISK_MEMORY_BUDGET_EXCEEDED');
                this.sandboxStats.diagnostics.push(`Memory budget exceeded: ${rssMb.toFixed(1)}MB > ${this.sandboxMemoryBudgetMb}MB`);
            }
        }
        catch { /* ignore */ }
    }
    // Placeholder network fetch wrapper to centralize logging if added in future phases
    async attemptNetwork(url, method = 'GET', fn) {
        const start = performance.now();
        const host = (() => { try {
            return new URL(url).hostname.toLowerCase();
        }
        catch {
            return '';
        } })();
        if (!this.networkAllowed) {
            this.networkOps.push({ url, method, durationMs: 0, blocked: true });
            this.diagnostics.networkOps = this.networkOps;
            if (this.verbose)
                console.warn(`⚠️  Blocked network attempt (disabled): ${method} ${url}`);
            if (this.sandboxEnabled) {
                this.sandboxStats.blockedNetworkAttempts++;
                if (!this.sandboxStats.violations.includes('RISK_NETWORK_BLOCKED_ATTEMPT')) {
                    this.sandboxStats.violations.push('RISK_NETWORK_BLOCKED_ATTEMPT');
                    this.sandboxStats.diagnostics.push('Network attempt blocked under sandbox');
                }
            }
            throw new Error('network-disabled');
        }
        if (this.networkAllowlist && host && !this.networkAllowlist.includes(host)) {
            this.networkOps.push({ url, method, durationMs: 0, blocked: true, error: 'host-not-allowlisted' });
            this.diagnostics.networkOps = this.networkOps;
            if (this.verbose)
                console.warn(`⚠️  Blocked network attempt (host not allowlisted): ${host}`);
            if (this.sandboxEnabled) {
                this.sandboxStats.blockedNetworkAttempts++;
                if (!this.sandboxStats.violations.includes('RISK_NETWORK_NOT_ALLOWLISTED')) {
                    this.sandboxStats.violations.push('RISK_NETWORK_NOT_ALLOWLISTED');
                    this.sandboxStats.diagnostics.push(`Network host not allowlisted: ${host}`);
                }
            }
            throw new Error('network-host-blocked');
        }
        const maxRetries = 2;
        let attempt = 0;
        // retry loop (maxRetries bounded)
        // eslint-disable-next-line no-constant-condition
        // Loop bounded by maxRetries
        while (attempt <= maxRetries) {
            try {
                const res = fn ? await fn() : null;
                const dur = performance.now() - start;
                this.networkOps.push({ url, method, durationMs: dur });
                this.diagnostics.networkOps = this.networkOps;
                return res;
            }
            catch (e) {
                const err = e; // network layer or custom error
                attempt++;
                if (attempt > maxRetries) {
                    const dur = performance.now() - start;
                    this.networkOps.push({ url, method, durationMs: dur, error: err?.message });
                    this.diagnostics.networkOps = this.networkOps;
                    throw err;
                }
                // Exponential backoff with jitter (50-150ms * attempt)
                const base = 50 * attempt;
                const jitter = Math.random() * 100;
                await new Promise(r => setTimeout(r, base + jitter));
            }
        }
    }
    // Task 29: expose snapshot of sandbox stats for ingestion
    getSandboxSnapshot() {
        this.sandboxCheckBudgets();
        if (!this.sandboxEnabled)
            return undefined;
        return {
            cpuBudgetMs: this.sandboxCpuBudgetMs,
            memoryBudgetMb: this.sandboxMemoryBudgetMb,
            cpuUsedMs: this.sandboxStats.cpuUsedMs,
            memoryPeakMb: this.sandboxStats.memoryPeakMb,
            fsWrites: this.sandboxStats.fsWrites.slice(0, 50),
            fsWriteCount: this.sandboxStats.fsWriteCount,
            fsWriteBytesTotal: this.sandboxStats.fsWriteBytesTotal,
            blockedNetworkAttempts: this.sandboxStats.blockedNetworkAttempts,
            blockedWriteAttempts: this.sandboxStats.blockedWriteAttempts,
            diagnostics: this.sandboxStats.diagnostics,
            violations: this.sandboxStats.violations,
            enforced: true
        };
    }
    async getBinarySha256() {
        if (this.binarySha256)
            return this.binarySha256;
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(this.binaryPath);
        this.binarySha256 = await new Promise((resolve, reject) => {
            stream.on('data', (d) => {
                if (typeof d === 'string') {
                    hash.update(Buffer.from(d));
                }
                else {
                    hash.update(d);
                }
            });
            stream.on('end', () => resolve(hash.digest('hex')));
            stream.on('error', reject);
        });
        return this.binarySha256;
    }
    async getStaticPatterns() {
        if (this.staticPatterns)
            return this.staticPatterns;
        const analysis = await this.analyze();
        try {
            let raw;
            try {
                raw = await fs.readFile(this.binaryPath);
            }
            catch { /* ignore */ }
            this.staticPatterns = (0, static_parsers_1.extractStaticPatterns)(analysis.strings, raw);
        }
        catch {
            this.staticPatterns = {};
        }
        // Step 10 augmentation: populate structural evidence once
        if (!this.structuralAugmented) {
            try {
                const anySelf = this;
                anySelf.evidence = anySelf.evidence || {};
                anySelf.evidence.schemaVersion = 2;
                // Binary meta introspection
                const meta = await (0, binary_introspect_1.introspectBinary)(this.binaryPath, analysis.strings);
                anySelf.evidence.binaryMeta = {
                    format: meta.format,
                    sections: meta.sections,
                    importsSample: meta.importsSample,
                    hasDebug: meta.hasDebug,
                    sizeBytes: meta.sizeBytes
                };
                // ClientHello & Noise pattern details to new evidence keys
                if (this.staticPatterns?.clientHello) {
                    const ch = this.staticPatterns.clientHello;
                    const extCount = ch.extensions ? ch.extensions.length : undefined;
                    anySelf.evidence.clientHelloTemplate = {
                        alpn: ch.alpn,
                        extensions: ch.extensions,
                        extOrderSha256: ch.extOrderSha256,
                        extensionCount: extCount
                    };
                }
                if (this.staticPatterns?.noise) {
                    const np = this.staticPatterns.noise;
                    // Heuristic count of HKDF labels & message tokens among strings
                    const lower = analysis.strings.map(s => s.toLowerCase());
                    const hkdfLabels = ['hkdf', 'chacha20', 'poly1305', 'hmac'];
                    const messageTokens = ['-> e,', '-> s,', '-> es', '-> se', '-> ee', 'noise_xk'];
                    let hkdfLabelsFound = 0;
                    hkdfLabels.forEach(l => { if (lower.some(s => s.includes(l)))
                        hkdfLabelsFound++; });
                    let messageTokensFound = 0;
                    messageTokens.forEach(t => { if (lower.some(s => s.includes(t.trim())))
                        messageTokensFound++; });
                    anySelf.evidence.noisePatternDetail = {
                        pattern: np.pattern,
                        hkdfLabelsFound,
                        messageTokensFound
                    };
                }
                if (this.staticPatterns?.accessTicket) {
                    anySelf.evidence.accessTicket = this.staticPatterns.accessTicket;
                }
                // accessTicketDynamic is provided only via external harness evidence ingestion; analyzer itself does not simulate it here.
                if (this.staticPatterns?.voucherCrypto) {
                    anySelf.evidence.voucherCrypto = this.staticPatterns.voucherCrypto;
                }
                // Negative assertions: forbidden tokens
                const forbidden = ['deterministic_seed', 'legacy_transition_header'];
                const present = [];
                const lowerAll = analysis.strings.map(s => s.toLowerCase());
                forbidden.forEach(f => { if (lowerAll.some(s => s.includes(f)))
                    present.push(f); });
                anySelf.evidence.negative = { forbiddenPresent: present };
            }
            catch { /* ignore */ }
            this.structuralAugmented = true;
        }
        return this.staticPatterns;
    }
    setDynamicProbe(flag) {
        this.dynamicProbe = !!flag;
    }
    getDiagnostics() {
        this.diagnostics.networkOps = this.networkOps;
        return this.diagnostics;
    }
    async detectTools() {
        const isWindows = process.platform === 'win32';
        this.diagnostics.platform = process.platform;
        const degradationReasons = [];
        const toolCandidates = [
            { name: 'strings', args: ['--version'] },
            { name: 'nm', args: ['--version'] },
            { name: 'objdump', args: ['--version'] },
            { name: 'ldd', args: ['--version'] },
            { name: 'file', args: ['--version'] },
            { name: 'uname', args: ['-m'] }
        ];
        const checks = toolCandidates.map(async (t) => {
            const start = Date.now();
            try {
                if ((0, safe_exec_1.isToolSkipped)(t.name)) {
                    this.diagnostics.tools.push({ name: t.name, available: false, error: 'skipped-by-config' });
                    this.diagnostics.degraded = true;
                    this.diagnostics.skippedTools = [...(this.diagnostics.skippedTools || []), t.name];
                    return;
                }
                const res = await (0, safe_exec_1.safeExec)(t.name, t.args, constants_1.DEFAULT_TOOL_TIMEOUT_MS);
                if (!res.failed) {
                    this.diagnostics.tools.push({ name: t.name, available: true, durationMs: Date.now() - start });
                }
                else {
                    this.diagnostics.tools.push({ name: t.name, available: false, error: res.errorMessage });
                    if (res.timedOut) {
                        this.diagnostics.timedOutTools = [...(this.diagnostics.timedOutTools || []), t.name];
                    }
                }
            }
            catch (e) {
                const err = e;
                this.diagnostics.tools.push({ name: t.name, available: false, error: err?.shortMessage || err?.message });
            }
        });
        await Promise.all(checks);
        const unavailable = this.diagnostics.tools.filter(t => !t.available);
        if (unavailable.length) {
            this.diagnostics.degraded = true;
            this.diagnostics.skippedTools = unavailable.filter(t => t.error === 'skipped-by-config').map(t => t.name);
            this.diagnostics.missingCoreTools = unavailable.map(t => t.name);
            if (isWindows)
                degradationReasons.push('native-windows-missing-unix-tools');
        }
        if (isWindows)
            degradationReasons.push('consider-installing-binutils-or-use-WSL');
        if (this.diagnostics.degraded)
            this.diagnostics.degradationReasons = degradationReasons;
    }
    async analyze() {
        // Ensure tool detection finished (especially for tests manipulating env)
        if (this.toolsReady) {
            try {
                await this.toolsReady;
            }
            catch { /* ignore */ }
        }
        if (this.cachedAnalysis) {
            this.diagnostics.cached = true;
            return this.cachedAnalysis;
        }
        if (this.verbose) {
            console.log(`📊 Analyzing binary: ${this.binaryPath}`);
        }
        this.diagnostics.analyzeInvocations += 1;
        this.analysisStartHr = process.hrtime();
        this.cachedAnalysis = (async () => {
            const [strings, symbols, fileFormat, architecture, dependencies, size] = await Promise.all([
                this.extractStrings(this.dynamicProbe),
                this.extractSymbols(),
                this.detectFileFormat(),
                this.detectArchitecture(),
                this.detectDependencies(),
                this.getFileSize()
            ]);
            if (this.analysisStartHr) {
                const diff = process.hrtime(this.analysisStartHr);
                this.diagnostics.totalAnalysisTimeMs = (diff[0] * 1e3) + (diff[1] / 1e6);
            }
            return { strings, symbols, fileFormat, architecture, dependencies, size };
        })();
        return this.cachedAnalysis;
    }
    async extractStrings(dynamicProbe) {
        const forceFallback = process.env.BETANET_FORCE_FALLBACK_STRINGS === '1';
        if (!forceFallback) {
            // Primary path: external 'strings'
            try {
                const res = await (0, safe_exec_1.safeExec)('strings', [this.binaryPath]);
                if (!res.failed) {
                    let out = res.stdout.split('\n').filter((line) => line.length > 0);
                    if (dynamicProbe) {
                        const probes = [
                            [this.binaryPath, ['--help']],
                            [this.binaryPath, ['--version']]
                        ];
                        for (const [cmd, args] of probes) {
                            try {
                                const probe = await (0, safe_exec_1.safeExec)(cmd, args, constants_1.DEFAULT_TOOL_TIMEOUT_MS);
                                if (!probe.failed && probe.stdout) {
                                    out = out.concat(probe.stdout.split('\n').slice(0, 300));
                                }
                            }
                            catch { /* ignore */ }
                        }
                    }
                    return out;
                }
                else {
                    if (this.verbose)
                        console.warn('⚠️  strings unavailable (', res.errorMessage, ') falling back to streaming scan');
                    this.diagnostics.degraded = true;
                    this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons || []), 'strings-missing'];
                }
            }
            catch {
                if (this.verbose)
                    console.warn('⚠️  strings invocation error, using fallback streaming scan');
                this.diagnostics.degraded = true;
                this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons || []), 'strings-error'];
            }
        }
        // Fallback: streaming scan with size cap & UTF-8 decoding (ISSUE-038 + ISSUE-047)
        const strings = [];
        let current = '';
        let bytesReadTotal = 0;
        let truncated = false;
        const minLen = constants_1.DEFAULT_FALLBACK_STRING_MIN_LEN;
        const maxSegmentLen = 4096; // guard against pathological very long runs
        function flush() {
            if (current.length >= minLen)
                strings.push(current);
            current = '';
        }
        function appendChar(ch) {
            current += ch;
            if (current.length >= maxSegmentLen)
                flush();
        }
        function isAcceptableCodePoint(cp) {
            if (cp < 32)
                return false; // control chars
            if (cp >= 0xD800 && cp <= 0xDFFF)
                return false; // surrogates
            if (cp === 0xFEFF)
                return false; // BOM
            if (cp > 0x10FFFF)
                return false;
            return true;
        }
        try {
            await new Promise((resolve, reject) => {
                const stream = fs.createReadStream(this.binaryPath, { highWaterMark: 64 * 1024 });
                stream.on('data', (chunk) => {
                    if (truncated)
                        return;
                    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
                    bytesReadTotal += buf.length;
                    for (let i = 0; i < buf.length; i++) {
                        const byte = buf[i];
                        if (byte <= 0x7F) { // ASCII
                            if (byte >= 32 && byte <= 126) {
                                appendChar(String.fromCharCode(byte));
                            }
                            else {
                                flush();
                            }
                            continue;
                        }
                        // Multi-byte UTF-8 start? Determine expected length
                        let needed = 0;
                        if (byte >= 0xC2 && byte <= 0xDF)
                            needed = 1; // 2-byte
                        else if (byte >= 0xE0 && byte <= 0xEF)
                            needed = 2; // 3-byte
                        else if (byte >= 0xF0 && byte <= 0xF4)
                            needed = 3; // 4-byte
                        else {
                            // Invalid start byte - treat as delimiter
                            flush();
                            continue;
                        }
                        if (i + needed >= buf.length) {
                            // Incomplete sequence at chunk boundary; flush and break to next chunk
                            flush();
                            break;
                        }
                        let cp = byte & (needed === 1 ? 0x1F : needed === 2 ? 0x0F : 0x07);
                        let valid = true;
                        for (let j = 1; j <= needed; j++) {
                            const nb = buf[i + j];
                            if ((nb & 0xC0) !== 0x80) {
                                valid = false;
                                break;
                            }
                            cp = (cp << 6) | (nb & 0x3F);
                        }
                        if (!valid) {
                            flush();
                            i += needed; // skip attempted bytes
                            continue;
                        }
                        i += needed; // advance past continuation bytes
                        if (isAcceptableCodePoint(cp)) {
                            try {
                                appendChar(String.fromCodePoint(cp));
                            }
                            catch {
                                flush();
                            }
                        }
                        else {
                            flush();
                        }
                    }
                    if (bytesReadTotal >= constants_1.FALLBACK_MAX_BYTES) {
                        truncated = true;
                        stream.destroy();
                    }
                });
                stream.on('end', () => { flush(); resolve(); });
                stream.on('error', err => reject(err));
            });
        }
        catch (e) {
            if (this.verbose)
                console.warn('⚠️  streaming fallback failed:', e?.message);
            this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons || []), 'strings-fallback-error'];
        }
        if (truncated) {
            this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons || []), 'strings-fallback-truncated'];
            this.diagnostics.fallbackStringsTruncated = true;
        }
        this.diagnostics.unicodeEnriched = true;
        if (dynamicProbe) {
            const probes = [
                [this.binaryPath, ['--help']],
                [this.binaryPath, ['--version']]
            ];
            for (const [cmd, args] of probes) {
                try {
                    const probe = await (0, safe_exec_1.safeExec)(cmd, args, constants_1.DEFAULT_TOOL_TIMEOUT_MS);
                    if (!probe.failed && probe.stdout)
                        strings.push(...probe.stdout.split('\n').slice(0, 300));
                }
                catch { /* ignore */ }
            }
        }
        return strings;
    }
    async extractSymbols() {
        try {
            const res = await (0, safe_exec_1.safeExec)('nm', ['-D', this.binaryPath]);
            if (!res.failed) {
                return res.stdout.split('\n')
                    .filter((line) => line.trim())
                    .map((line) => line.split(' ').pop() || '')
                    .filter((symbol) => symbol);
            }
        }
        catch (error) {
            if (this.verbose) {
                console.warn('⚠️  nm command failed, trying objdump');
            }
            try {
                const res2 = await (0, safe_exec_1.safeExec)('objdump', ['-t', this.binaryPath]);
                if (!res2.failed) {
                    return res2.stdout.split('\n')
                        .filter((line) => line.includes('.text'))
                        .map((line) => line.split(' ').pop() || '')
                        .filter((symbol) => symbol);
                }
            }
            catch (error2) {
                if (this.verbose) {
                    console.warn('⚠️  Symbol extraction failed');
                }
                this.diagnostics.degraded = true;
                this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons || []), 'symbols-missing'];
                return [];
            }
        }
        return [];
    }
    async detectFileFormat() {
        try {
            const res = await (0, safe_exec_1.safeExec)('file', [this.binaryPath]);
            return res.failed ? 'unknown' : res.stdout.trim();
        }
        catch {
            return 'unknown';
        }
    }
    async detectArchitecture() {
        try {
            const res = await (0, safe_exec_1.safeExec)('uname', ['-m']);
            return res.failed ? 'unknown' : res.stdout.trim();
        }
        catch {
            return 'unknown';
        }
    }
    async detectDependencies() {
        try {
            const res = await (0, safe_exec_1.safeExec)('ldd', [this.binaryPath]);
            if (res.failed) {
                if (this.verbose) {
                    console.warn('⚠️  ldd unavailable (', res.errorMessage, ')');
                }
                this.diagnostics.degraded = true;
                this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons || []), 'ldd-missing'];
                return [];
            }
            return res.stdout.split('\n')
                .filter((line) => line.includes('=>'))
                .map((line) => line.split('=>')[1]?.split('(')[0]?.trim() || '')
                .filter((dep) => dep && !dep.includes('not found'));
        }
        catch (error) {
            if (this.verbose) {
                console.warn('⚠️  ldd command failed');
            }
            this.diagnostics.degraded = true;
            this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons || []), 'ldd-failed'];
            return [];
        }
    }
    async getFileSize() {
        const stats = await fs.stat(this.binaryPath);
        return stats.size;
    }
    async checkNetworkCapabilities() {
        const analysis = await this.analyze();
        return (0, heuristics_1.detectNetwork)({ strings: analysis.strings, symbols: analysis.symbols });
    }
    async checkCryptographicCapabilities() {
        const analysis = await this.analyze();
        return (0, heuristics_1.detectCrypto)({ strings: analysis.strings, symbols: analysis.symbols });
    }
    async checkSCIONSupport() {
        const analysis = await this.analyze();
        return (0, heuristics_1.detectSCION)({ strings: analysis.strings, symbols: analysis.symbols });
    }
    async checkDHTSupport() {
        const analysis = await this.analyze();
        return (0, heuristics_1.detectDHT)({ strings: analysis.strings, symbols: analysis.symbols });
    }
    async checkLedgerSupport() {
        const analysis = await this.analyze();
        return (0, heuristics_1.detectLedger)({ strings: analysis.strings, symbols: analysis.symbols });
    }
    async checkPaymentSupport() {
        const analysis = await this.analyze();
        return (0, heuristics_1.detectPayment)({ strings: analysis.strings, symbols: analysis.symbols });
    }
    async checkBuildProvenance() {
        const analysis = await this.analyze();
        return (0, heuristics_1.detectBuildProvenance)({ strings: analysis.strings, symbols: analysis.symbols });
    }
}
exports.BinaryAnalyzer = BinaryAnalyzer;
//# sourceMappingURL=analyzer.js.map