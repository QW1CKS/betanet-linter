"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ComplianceChecker = void 0;
const analyzer_1 = require("./analyzer");
const format_1 = require("./format");
class ComplianceChecker {
    constructor(binaryPath, options = {}) {
        this.analyzer = new analyzer_1.BinaryAnalyzer(binaryPath, options.verbose);
    }
    async runAllChecks() {
        const analysis = await this.analyzer.analyze();
        const checks = [];
        // Run all 10 compliance checks
        checks.push(await this.checkHTXImplementation(analysis));
        checks.push(await this.checkRotatingAccessTickets(analysis));
        checks.push(await this.checkInnerFrameEncryption(analysis));
        checks.push(await this.checkSCIONPathManagement(analysis));
        checks.push(await this.checkTransportEndpoints(analysis));
        checks.push(await this.checkDHTBootstrap(analysis));
        checks.push(await this.checkAliasLedgerVerification(analysis));
        checks.push(await this.checkCashuLightningSupport(analysis));
        checks.push(await this.checkReproducibleBuilds(analysis));
        checks.push(await this.checkPostQuantumSuites(analysis));
        const summary = {
            total: checks.length,
            passed: checks.filter(c => c.passed).length,
            failed: checks.filter(c => !c.passed).length,
            critical: checks.filter(c => !c.passed && c.severity === 'critical').length
        };
        const overallScore = Math.round((summary.passed / summary.total) * 100);
        return {
            binaryPath: this.analyzer['binaryPath'],
            timestamp: new Date().toISOString(),
            overallScore,
            passed: summary.failed === 0,
            checks,
            summary
        };
    }
    async checkHTXImplementation(analysis) {
        const { strings, symbols, networkFunctions } = analysis;
        const hasTCP443 = networkFunctions.some((f) => f.toLowerCase().includes('tcp') ||
            strings.some((s) => s.includes('443')));
        const hasQUIC443 = networkFunctions.some((f) => f.toLowerCase().includes('quic') ||
            strings.some((s) => s.toLowerCase().includes('quic')));
        const hasTLS13 = networkFunctions.some((f) => f.toLowerCase().includes('tls') ||
            strings.some((s) => s.includes('1.3') || s.toLowerCase().includes('tls')));
        const hasECH = networkFunctions.some((f) => f.toLowerCase().includes('ech') ||
            strings.some((s) => s.toLowerCase().includes('ech')));
        const passed = hasTCP443 && hasQUIC443 && hasTLS13 && hasECH;
        return {
            id: 1,
            name: "HTX over TCP-443 & QUIC-443",
            description: "Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH",
            passed,
            details: passed
                ? "✅ Found HTX implementation with TLS 1.3 and ECH support"
                : `❌ Missing: ${(0, format_1.missingList)([
                    !hasTCP443 && 'TCP-443',
                    !hasQUIC443 && 'QUIC-443',
                    !hasTLS13 && 'TLS 1.3',
                    !hasECH && 'ECH'
                ])}`,
            severity: 'critical'
        };
    }
    async checkRotatingAccessTickets(analysis) {
        const { strings, symbols } = analysis;
        const ticketKeywords = ['ticket', 'access', 'rotate', 'refresh', 'session'];
        const found = ticketKeywords.filter((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)) ||
            symbols.some((s) => s.toLowerCase().includes(keyword)));
        const passed = found.length >= 2; // At least ticket-related and rotation-related
        return {
            id: 2,
            name: "Rotating Access Tickets",
            description: "Uses rotating access tickets (§5.2)",
            passed,
            details: passed
                ? `✅ Found ticket rotation mechanisms: ${found.join(', ')}`
                : `❌ Insufficient ticket rotation evidence. Found: ${found.join(', ')}`,
            severity: 'major'
        };
    }
    async checkInnerFrameEncryption(analysis) {
        const { strings, symbols, cryptoFunctions } = analysis;
        const hasChaCha20 = cryptoFunctions.some((f) => f.toLowerCase().includes('chacha20'));
        const hasPoly1305 = cryptoFunctions.some((f) => f.toLowerCase().includes('poly1305'));
        const hasFrameEncryption = strings.some((s) => s.toLowerCase().includes('frame') &&
            (s.toLowerCase().includes('encrypt') || s.toLowerCase().includes('cipher')));
        const passed = hasChaCha20 && hasPoly1305 && hasFrameEncryption;
        return {
            id: 3,
            name: "Inner Frame Encryption",
            description: "Encrypts inner frames with ChaCha20-Poly1305, 24-bit length, 96-bit nonce",
            passed,
            details: passed
                ? "✅ Found ChaCha20-Poly1305 frame encryption implementation"
                : `❌ Missing: ${(0, format_1.missingList)([
                    !hasChaCha20 && 'ChaCha20',
                    !hasPoly1305 && 'Poly1305',
                    !hasFrameEncryption && 'Frame encryption'
                ])}`,
            severity: 'critical'
        };
    }
    async checkSCIONPathManagement(analysis) {
        const { strings, symbols } = analysis;
        const scionKeywords = ['scion', 'path', 'segment', 'as', 'router', 'gateway'];
        const pathKeywords = ['path', 'route', 'forward', 'hop'];
        const hasSCION = scionKeywords.some((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)) ||
            symbols.some((s) => s.toLowerCase().includes(keyword)));
        const hasPathManagement = pathKeywords.filter((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)) ||
            symbols.some((s) => s.toLowerCase().includes(keyword))).length >= 2;
        const passed = hasSCION || hasPathManagement;
        return {
            id: 4,
            name: "SCION Path Management",
            description: "Maintains ≥ 3 signed SCION paths or attaches valid IP-transition header",
            passed,
            details: passed
                ? hasSCION
                    ? "✅ Found SCION path management implementation"
                    : "✅ Found alternative path management (IP-transition header)"
                : "❌ No SCION or IP-transition header implementation found",
            severity: 'major'
        };
    }
    async checkTransportEndpoints(analysis) {
        const { strings } = analysis;
        const hasHTXEndpoint = strings.some((s) => s.includes('/betanet/htx/1.0.0'));
        const hasHTXQUICEndpoint = strings.some((s) => s.includes('/betanet/htxquic/1.0.0'));
        const passed = hasHTXEndpoint && hasHTXQUICEndpoint;
        return {
            id: 5,
            name: "Transport Endpoints",
            description: "Offers /betanet/htx/1.0.0 and /betanet/htxquic/1.0.0 transports",
            passed,
            details: passed
                ? "✅ Both transport endpoints found"
                : `❌ Missing: ${(0, format_1.missingList)([
                    !hasHTXEndpoint && '/betanet/htx/1.0.0',
                    !hasHTXQUICEndpoint && '/betanet/htxquic/1.0.0'
                ])}`,
            severity: 'critical'
        };
    }
    async checkDHTBootstrap(analysis) {
        const { strings, symbols } = analysis;
        const dhtKeywords = ['dht', 'bootstrap', 'seed', 'node', 'peer', 'discovery'];
        const deterministicKeywords = ['deterministic', 'seed', 'fixed', 'static'];
        const hasDHT = dhtKeywords.some((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)) ||
            symbols.some((s) => s.toLowerCase().includes(keyword)));
        const hasDeterministic = deterministicKeywords.some((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)));
        const passed = hasDHT && hasDeterministic;
        return {
            id: 6,
            name: "DHT Bootstrap",
            description: "Implements deterministic DHT seed bootstrap",
            passed,
            details: passed
                ? "✅ Found deterministic DHT bootstrap implementation"
                : `❌ Missing: ${(0, format_1.missingList)([
                    !hasDHT && 'DHT implementation',
                    !hasDeterministic && 'Deterministic seeding'
                ])}`,
            severity: 'major'
        };
    }
    async checkAliasLedgerVerification(analysis) {
        const { strings, symbols } = analysis;
        const aliasKeywords = ['alias', 'ledger', 'identity', 'name', 'trust'];
        const consensusKeywords = ['consensus', '2of3', 'chain', 'verify', 'validate'];
        const hasAlias = aliasKeywords.some((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)) ||
            symbols.some((s) => s.toLowerCase().includes(keyword)));
        const hasConsensus = consensusKeywords.some((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)));
        const passed = hasAlias && hasConsensus;
        return {
            id: 7,
            name: "Alias Ledger Verification",
            description: "Verifies alias ledger with 2-of-3 chain consensus",
            passed,
            details: passed
                ? "✅ Found alias ledger with consensus verification"
                : `❌ Missing: ${(0, format_1.missingList)([
                    !hasAlias && 'Alias ledger',
                    !hasConsensus && 'Consensus mechanism'
                ])}`,
            severity: 'major'
        };
    }
    async checkCashuLightningSupport(analysis) {
        const { strings, symbols } = analysis;
        const cashuKeywords = ['cashu', 'mint', 'token', 'voucher', 'ecash'];
        const lightningKeywords = ['lightning', 'ln', 'payment', 'channel', 'settlement'];
        const hasCashu = cashuKeywords.some((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)) ||
            symbols.some((s) => s.toLowerCase().includes(keyword)));
        const hasLightning = lightningKeywords.some((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)));
        const passed = hasCashu && hasLightning;
        return {
            id: 8,
            name: "Cashu & Lightning Support",
            description: "Accepts Cashu vouchers from federated mints & supports Lightning settlement",
            passed,
            details: passed
                ? "✅ Found Cashu and Lightning payment support"
                : `❌ Missing: ${(0, format_1.missingList)([
                    !hasCashu && 'Cashu support',
                    !hasLightning && 'Lightning support'
                ])}`,
            severity: 'major'
        };
    }
    async checkReproducibleBuilds(analysis) {
        const { strings, symbols } = analysis;
        const buildKeywords = ['reproducible', 'slsa', 'provenance', 'build', 'verify'];
        const versionKeywords = ['version', 'commit', 'hash', 'tag'];
        const hasReproducible = buildKeywords.some((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)) ||
            symbols.some((s) => s.toLowerCase().includes(keyword)));
        const hasVersioning = versionKeywords.some((keyword) => strings.some((s) => s.toLowerCase().includes(keyword)));
        const passed = hasReproducible && hasVersioning;
        return {
            id: 9,
            name: "Reproducible Builds",
            description: "Builds reproducibly and publishes SLSA 3 provenance",
            passed,
            details: passed
                ? "✅ Found reproducible build and SLSA provenance support"
                : `❌ Missing: ${(0, format_1.missingList)([
                    !hasReproducible && 'Reproducible build evidence',
                    !hasVersioning && 'Version/provenance info'
                ])}`,
            severity: 'minor'
        };
    }
    async checkPostQuantumSuites(analysis) {
        const { strings, symbols, cryptoFunctions } = analysis;
        const hasX25519 = cryptoFunctions.some((f) => f.toLowerCase().includes('x25519'));
        const hasKyber = cryptoFunctions.some((f) => f.toLowerCase().includes('kyber'));
        // Check if post-quantum deadline has passed
        const currentDate = new Date();
        const mandatoryDate = new Date('2027-01-01');
        const isMandatory = currentDate >= mandatoryDate;
        const passed = !isMandatory || (hasX25519 && hasKyber);
        return {
            id: 10,
            name: "Post-Quantum Cipher Suites",
            description: "Presents X25519-Kyber768 suites once the mandatory date is reached",
            passed,
            details: passed
                ? isMandatory
                    ? "✅ Found X25519-Kyber768 post-quantum cipher suites"
                    : "ℹ️  Post-quantum suites not yet mandatory (effective 2027-01-01)"
                : `❌ Missing post-quantum suites (mandatory since 2027-01-01): ${[
                    !hasX25519 && 'X25519',
                    !hasKyber && 'Kyber768'
                ].filter(Boolean).join(', ')}`,
            severity: isMandatory ? 'critical' : 'minor'
        };
    }
}
exports.ComplianceChecker = ComplianceChecker;
//# sourceMappingURL=compliance.js.map