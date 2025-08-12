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
        this.binaryPath = binaryPath;
        this.verbose = verbose;
        this.toolsReady = this.detectTools();
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
    setDynamicProbe(flag) {
        this.dynamicProbe = !!flag;
    }
    getDiagnostics() {
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
                this.diagnostics.tools.push({ name: t.name, available: false, error: e?.shortMessage || e?.message });
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