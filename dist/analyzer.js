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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BinaryAnalyzer = void 0;
const fs = __importStar(require("fs-extra"));
const execa_1 = __importDefault(require("execa"));
// Removed unused imports (which, types)
class BinaryAnalyzer {
    constructor(binaryPath, verbose = false) {
        this.cachedAnalysis = null;
        this.diagnostics = {
            tools: [],
            analyzeInvocations: 0,
            cached: false
        };
        this.analysisStartHr = null;
        this.binaryPath = binaryPath;
        this.verbose = verbose;
        void this.detectTools();
    }
    getDiagnostics() {
        return this.diagnostics;
    }
    async detectTools() {
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
                await (0, execa_1.default)(t.name, t.args, { timeout: 2000 });
                this.diagnostics.tools.push({ name: t.name, available: true, durationMs: Date.now() - start });
            }
            catch (e) {
                this.diagnostics.tools.push({ name: t.name, available: false, error: e?.shortMessage || e?.message });
            }
        });
        await Promise.all(checks);
    }
    async analyze() {
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
                this.extractStrings(),
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
    async extractStrings() {
        try {
            const { stdout } = await (0, execa_1.default)('strings', [this.binaryPath]);
            return stdout.split('\n').filter((line) => line.length > 0);
        }
        catch (error) {
            if (this.verbose) {
                console.warn('⚠️  strings command failed, trying fallback method');
            }
            // Fallback: read file and extract printable strings
            const buffer = await fs.readFile(this.binaryPath);
            const strings = [];
            let currentString = '';
            for (let i = 0; i < buffer.length; i++) {
                const byte = buffer[i];
                if (byte >= 32 && byte <= 126) { // Printable ASCII
                    currentString += String.fromCharCode(byte);
                }
                else {
                    if (currentString.length >= 4) { // Minimum string length
                        strings.push(currentString);
                    }
                    currentString = '';
                }
            }
            return strings;
        }
    }
    async extractSymbols() {
        try {
            const { stdout } = await (0, execa_1.default)('nm', ['-D', this.binaryPath]);
            return stdout.split('\n')
                .filter((line) => line.trim())
                .map((line) => line.split(' ').pop() || '')
                .filter((symbol) => symbol);
        }
        catch (error) {
            if (this.verbose) {
                console.warn('⚠️  nm command failed, trying objdump');
            }
            try {
                const { stdout } = await (0, execa_1.default)('objdump', ['-t', this.binaryPath]);
                return stdout.split('\n')
                    .filter((line) => line.includes('.text'))
                    .map((line) => line.split(' ').pop() || '')
                    .filter((symbol) => symbol);
            }
            catch (error2) {
                if (this.verbose) {
                    console.warn('⚠️  Symbol extraction failed');
                }
                return [];
            }
        }
    }
    async detectFileFormat() {
        try {
            const { stdout } = await (0, execa_1.default)('file', [this.binaryPath]);
            return stdout.trim();
        }
        catch (error) {
            return 'unknown';
        }
    }
    async detectArchitecture() {
        try {
            const { stdout } = await (0, execa_1.default)('uname', ['-m']);
            return stdout.trim();
        }
        catch (error) {
            return 'unknown';
        }
    }
    async detectDependencies() {
        try {
            const { stdout } = await (0, execa_1.default)('ldd', [this.binaryPath]);
            return stdout.split('\n')
                .filter((line) => line.includes('=>'))
                .map((line) => line.split('=>')[1]?.split('(')[0]?.trim() || '')
                .filter((dep) => dep && !dep.includes('not found'));
        }
        catch (error) {
            if (this.verbose) {
                console.warn('⚠️  ldd command failed');
            }
            return [];
        }
    }
    async getFileSize() {
        const stats = await fs.stat(this.binaryPath);
        return stats.size;
    }
    async checkNetworkCapabilities() {
        const analysis = await this.analyze();
        const strings = analysis.strings.join(' ').toLowerCase();
        const symbols = analysis.symbols.join(' ').toLowerCase();
        return {
            hasTLS: strings.includes('tls') || strings.includes('ssl') || symbols.includes('tls'),
            hasQUIC: strings.includes('quic') || symbols.includes('quic'),
            hasHTX: strings.includes('htx') || strings.includes('/betanet/htx'),
            hasECH: strings.includes('ech') || strings.includes('encrypted_client_hello'),
            port443: strings.includes('443') || symbols.includes('443')
        };
    }
    async checkCryptographicCapabilities() {
        const analysis = await this.analyze();
        const strings = analysis.strings.join(' ').toLowerCase();
        const symbols = analysis.symbols.join(' ').toLowerCase();
        return {
            hasChaCha20: strings.includes('chacha20') || symbols.includes('chacha'),
            hasPoly1305: strings.includes('poly1305') || symbols.includes('poly'),
            hasEd25519: strings.includes('ed25519') || symbols.includes('ed25519'),
            hasX25519: strings.includes('x25519') || symbols.includes('x25519'),
            hasKyber768: strings.includes('kyber') || strings.includes('768'),
            hasSHA256: strings.includes('sha256') || strings.includes('sha-256'),
            hasHKDF: strings.includes('hkdf') || symbols.includes('hkdf')
        };
    }
    async checkSCIONSupport() {
        const analysis = await this.analyze();
        const strings = analysis.strings.join(' ').toLowerCase();
        const symbols = analysis.symbols.join(' ').toLowerCase();
        return {
            hasSCION: strings.includes('scion') || symbols.includes('scion'),
            pathManagement: strings.includes('path') && (strings.includes('maintenance') || strings.includes('disjoint')),
            hasIPTransition: strings.includes('ip-transition') || strings.includes('transition')
        };
    }
    async checkDHTSupport() {
        const analysis = await this.analyze();
        const strings = analysis.strings.join(' ').toLowerCase();
        const symbols = analysis.symbols.join(' ').toLowerCase();
        return {
            hasDHT: strings.includes('dht') || symbols.includes('dht'),
            deterministicBootstrap: strings.includes('deterministic') && strings.includes('bootstrap'),
            seedManagement: strings.includes('seed') && strings.includes('bootstrap')
        };
    }
    async checkLedgerSupport() {
        const analysis = await this.analyze();
        const strings = analysis.strings.join(' ').toLowerCase();
        const symbols = analysis.symbols.join(' ').toLowerCase();
        return {
            hasAliasLedger: strings.includes('alias') && strings.includes('ledger'),
            hasConsensus: strings.includes('consensus') || strings.includes('2-of-3'),
            chainSupport: strings.includes('chain') && strings.includes('verification')
        };
    }
    async checkPaymentSupport() {
        const analysis = await this.analyze();
        const strings = analysis.strings.join(' ').toLowerCase();
        const symbols = analysis.symbols.join(' ').toLowerCase();
        return {
            hasCashu: strings.includes('cashu') || symbols.includes('cashu'),
            hasLightning: strings.includes('lightning') || strings.includes('ln'),
            hasFederation: strings.includes('federation') || strings.includes('federated')
        };
    }
    async checkBuildProvenance() {
        const analysis = await this.analyze();
        const strings = analysis.strings.join(' ').toLowerCase();
        const symbols = analysis.symbols.join(' ').toLowerCase();
        return {
            hasSLSA: strings.includes('slsa') || strings.includes('provenance'),
            reproducible: strings.includes('reproducible') || strings.includes('deterministic'),
            provenance: strings.includes('build') && strings.includes('provenance')
        };
    }
}
exports.BinaryAnalyzer = BinaryAnalyzer;
//# sourceMappingURL=analyzer.js.map