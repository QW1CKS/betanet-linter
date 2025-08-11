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
        this._analyzer = new analyzer_1.BinaryAnalyzer(binaryPath, options.verbose);
        if (options.verbose) {
            console.log('🔍 Starting Betanet compliance check...');
        }
        // Run all compliance checks
        const checks = [];
        // Filter checks if specified
        const allCheckIds = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let checkIdsToRun = allCheckIds;
        if (options.checkFilters?.include) {
            checkIdsToRun = checkIdsToRun.filter(id => options.checkFilters.include.includes(id));
        }
        if (options.checkFilters?.exclude) {
            checkIdsToRun = checkIdsToRun.filter(id => !options.checkFilters.exclude.includes(id));
        }
        // Run each check
        for (const checkId of checkIdsToRun) {
            const check = await this.runCheck(checkId);
            checks.push(check);
        }
        // Calculate overall results
        const passedChecks = checks.filter(c => c.passed);
        const criticalChecks = checks.filter(c => c.severity === 'critical' && !c.passed);
        // Guard against zero checks (filters may exclude all)
        const overallScore = checks.length === 0 ? 0 : Math.round((passedChecks.length / checks.length) * 100);
        const passed = checks.length > 0 && passedChecks.length === checks.length && criticalChecks.length === 0;
        const diagnostics = (() => {
            const a = this.analyzer;
            if (a && typeof a.getDiagnostics === 'function') {
                try {
                    return a.getDiagnostics();
                }
                catch {
                    return undefined;
                }
            }
            return undefined;
        })();
        const result = {
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
    async runCheck(checkId) {
        switch (checkId) {
            case 1:
                return await this.checkHTXImplementation();
            case 2:
                return await this.checkAccessTickets();
            case 3:
                return await this.checkFrameEncryption();
            case 4:
                return await this.checkSCIONPaths();
            case 5:
                return await this.checkTransportEndpoints();
            case 6:
                return await this.checkDHTBootstrap();
            case 7:
                return await this.checkAliasLedger();
            case 8:
                return await this.checkPaymentSystem();
            case 9:
                return await this.checkBuildProvenance();
            case 10:
                return await this.checkPostQuantum();
            default:
                throw new Error(`Unknown check ID: ${checkId}`);
        }
    }
    async checkHTXImplementation() {
        const networkCaps = await this.analyzer.checkNetworkCapabilities();
        const passed = networkCaps.hasTLS && networkCaps.hasQUIC &&
            networkCaps.hasHTX && networkCaps.hasECH &&
            networkCaps.port443;
        return {
            id: 1,
            name: 'HTX over TCP-443 & QUIC-443',
            description: 'Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH',
            passed,
            details: passed
                ? '✅ Found HTX, QUIC, TLS, ECH, and port 443 support'
                : `❌ Missing: ${[
                    !networkCaps.hasTLS && 'TLS',
                    !networkCaps.hasQUIC && 'QUIC',
                    !networkCaps.hasHTX && 'HTX',
                    !networkCaps.hasECH && 'ECH',
                    !networkCaps.port443 && 'port 443'
                ].filter(Boolean).join(', ')}`,
            severity: 'critical'
        };
    }
    async checkAccessTickets() {
        const analysis = await this.analyzer.analyze();
        const strings = analysis.strings.join(' ').toLowerCase();
        const symbols = analysis.symbols.join(' ').toLowerCase();
        const hasTickets = strings.includes('ticket') || strings.includes('access') || symbols.includes('ticket');
        const hasRotation = strings.includes('rotation') || strings.includes('rotate') || symbols.includes('rotate');
        const passed = hasTickets && hasRotation;
        return {
            id: 2,
            name: 'Rotating Access Tickets',
            description: 'Uses rotating access tickets (§5.2)',
            passed,
            details: passed
                ? '✅ Found access ticket and rotation support'
                : `❌ Missing: ${[
                    !hasTickets && 'access tickets',
                    !hasRotation && 'ticket rotation'
                ].filter(Boolean).join(', ')}`,
            severity: 'major'
        };
    }
    async checkFrameEncryption() {
        const cryptoCaps = await this.analyzer.checkCryptographicCapabilities();
        const passed = cryptoCaps.hasChaCha20 && cryptoCaps.hasPoly1305;
        return {
            id: 3,
            name: 'Inner Frame Encryption',
            description: 'Encrypts inner frames with ChaCha20-Poly1305, 24-bit length, 96-bit nonce',
            passed,
            details: passed
                ? '✅ Found ChaCha20-Poly1305 support'
                : `❌ Missing: ${[
                    !cryptoCaps.hasChaCha20 && 'ChaCha20',
                    !cryptoCaps.hasPoly1305 && 'Poly1305'
                ].filter(Boolean).join(', ')}`,
            severity: 'critical'
        };
    }
    async checkSCIONPaths() {
        const scionSupport = await this.analyzer.checkSCIONSupport();
        const passed = scionSupport.hasSCION && (scionSupport.pathManagement || scionSupport.hasIPTransition);
        return {
            id: 4,
            name: 'SCION Path Management',
            description: 'Maintains ≥ 3 signed SCION paths or attaches a valid IP-transition header',
            passed,
            details: passed
                ? '✅ Found SCION support with path management or IP-transition'
                : `❌ Missing: ${[
                    !scionSupport.hasSCION && 'SCION support',
                    !scionSupport.pathManagement && 'path management',
                    !scionSupport.hasIPTransition && 'IP-transition header'
                ].filter(Boolean).join(', ')}`,
            severity: 'critical'
        };
    }
    async checkTransportEndpoints() {
        const analysis = await this.analyzer.analyze();
        const strings = analysis.strings.join(' ');
        const hasHTXEndpoint = strings.includes('/betanet/htx/1.0.0');
        const hasQUICEndpoint = strings.includes('/betanet/htxquic/1.0.0');
        const passed = hasHTXEndpoint && hasQUICEndpoint;
        return {
            id: 5,
            name: 'Transport Endpoints',
            description: 'Offers /betanet/htx/1.0.0 and /betanet/htxquic/1.0.0 transports',
            passed,
            details: passed
                ? '✅ Found both HTX and QUIC transport endpoints'
                : `❌ Missing: ${[
                    !hasHTXEndpoint && '/betanet/htx/1.0.0',
                    !hasQUICEndpoint && '/betanet/htxquic/1.0.0'
                ].filter(Boolean).join(', ')}`,
            severity: 'major'
        };
    }
    async checkDHTBootstrap() {
        const dhtSupport = await this.analyzer.checkDHTSupport();
        const passed = dhtSupport.hasDHT && dhtSupport.deterministicBootstrap;
        return {
            id: 6,
            name: 'DHT Seed Bootstrap',
            description: 'Implements deterministic DHT seed bootstrap',
            passed,
            details: passed
                ? '✅ Found DHT with deterministic bootstrap'
                : `❌ Missing: ${[
                    !dhtSupport.hasDHT && 'DHT support',
                    !dhtSupport.deterministicBootstrap && 'deterministic bootstrap'
                ].filter(Boolean).join(', ')}`,
            severity: 'major'
        };
    }
    async checkAliasLedger() {
        const ledgerSupport = await this.analyzer.checkLedgerSupport();
        const passed = ledgerSupport.hasAliasLedger && ledgerSupport.hasConsensus && ledgerSupport.chainSupport;
        return {
            id: 7,
            name: 'Alias Ledger Verification',
            description: 'Verifies alias ledger with 2-of-3 chain consensus',
            passed,
            details: passed
                ? '✅ Found alias ledger with consensus and chain support'
                : `❌ Missing: ${[
                    !ledgerSupport.hasAliasLedger && 'alias ledger',
                    !ledgerSupport.hasConsensus && '2-of-3 consensus',
                    !ledgerSupport.chainSupport && 'chain verification'
                ].filter(Boolean).join(', ')}`,
            severity: 'major'
        };
    }
    async checkPaymentSystem() {
        const paymentSupport = await this.analyzer.checkPaymentSupport();
        const passed = paymentSupport.hasCashu && paymentSupport.hasLightning && paymentSupport.hasFederation;
        return {
            id: 8,
            name: 'Payment System',
            description: 'Accepts Cashu vouchers from federated mints & supports Lightning settlement',
            passed,
            details: passed
                ? '✅ Found Cashu, Lightning, and federation support'
                : `❌ Missing: ${[
                    !paymentSupport.hasCashu && 'Cashu support',
                    !paymentSupport.hasLightning && 'Lightning support',
                    !paymentSupport.hasFederation && 'federation support'
                ].filter(Boolean).join(', ')}`,
            severity: 'major'
        };
    }
    async checkBuildProvenance() {
        const buildInfo = await this.analyzer.checkBuildProvenance();
        const passed = buildInfo.hasSLSA && buildInfo.reproducible && buildInfo.provenance;
        return {
            id: 9,
            name: 'Build Provenance',
            description: 'Builds reproducibly and publishes SLSA 3 provenance',
            passed,
            details: passed
                ? '✅ Found SLSA, reproducible builds, and provenance'
                : `❌ Missing: ${[
                    !buildInfo.hasSLSA && 'SLSA support',
                    !buildInfo.reproducible && 'reproducible builds',
                    !buildInfo.provenance && 'build provenance'
                ].filter(Boolean).join(', ')}`,
            severity: 'minor'
        };
    }
    async checkPostQuantum() {
        const cryptoCaps = await this.analyzer.checkCryptographicCapabilities();
        // Check if we're past the mandatory date (2027-01-01)
        const currentDate = new Date();
        const mandatoryDate = new Date('2027-01-01');
        const isPastMandatoryDate = currentDate >= mandatoryDate;
        let passed = true;
        let details = '✅ Post-quantum requirements not yet mandatory';
        if (isPastMandatoryDate) {
            passed = cryptoCaps.hasX25519 && cryptoCaps.hasKyber768;
            details = passed
                ? '✅ Found X25519-Kyber768 hybrid cipher suite'
                : `❌ Missing: ${[
                    !cryptoCaps.hasX25519 && 'X25519',
                    !cryptoCaps.hasKyber768 && 'Kyber768'
                ].filter(Boolean).join(', ')} (mandatory after 2027-01-01)`;
        }
        return {
            id: 10,
            name: 'Post-Quantum Cipher Suites',
            description: 'Presents X25519-Kyber768 suites once the mandatory date is reached',
            passed,
            details,
            severity: isPastMandatoryDate ? 'critical' : 'minor'
        };
    }
    async generateSBOM(binaryPath, format = 'cyclonedx', outputPath) {
        if (!this.analyzer) {
            this._analyzer = new analyzer_1.BinaryAnalyzer(binaryPath);
        }
        const analysis = await this.analyzer.analyze();
        const components = await this.extractComponents(analysis);
        const defaultOutputPath = path.join(path.dirname(binaryPath), `${path.basename(binaryPath)}-sbom.${format === 'cyclonedx' ? 'xml' : 'spdx'}`);
        const finalOutputPath = outputPath || defaultOutputPath;
        if (format === 'cyclonedx') {
            await this.generateCycloneDXSBOM(components, finalOutputPath, binaryPath);
        }
        else {
            await this.generateSPDXSBOM(components, finalOutputPath, binaryPath);
        }
        return finalOutputPath;
    }
    async extractComponents(analysis) {
        const components = [];
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
    extractVersionFromPath(path) {
        const versionMatch = path.match(/(\d+\.\d+\.\d+)/);
        return versionMatch ? versionMatch[1] : null;
    }
    async generateCycloneDXSBOM(components, outputPath, binaryPath) {
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
    async generateSPDXSBOM(components, outputPath, binaryPath) {
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
    displayResults(results, format = 'table') {
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
exports.BetanetComplianceChecker = BetanetComplianceChecker;
//# sourceMappingURL=index.js.map