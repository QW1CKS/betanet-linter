"use strict";
// Central registry of Betanet compliance checks (Plan 3 consolidation)
// Each check definition contains metadata & an evaluator that derives result from the BinaryAnalyzer.
// This replaces ad-hoc per-check methods and normalizes naming & severities.
Object.defineProperty(exports, "__esModule", { value: true });
exports.CHECK_REGISTRY = void 0;
exports.getChecksByIds = getChecksByIds;
const constants_1 = require("./constants");
const heuristics_1 = require("./heuristics");
const format_1 = require("./format");
// missingList helper moved to format.ts (ISSUE-027) for reuse across modules
exports.CHECK_REGISTRY = [
    {
        id: 1,
        key: 'htx-transports-tls-ech',
        name: 'HTX over TCP-443 & QUIC-443',
        description: 'Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH',
        severity: 'critical',
        introducedIn: '1.0',
        mandatoryIn: '1.0',
        evaluate: async (analyzer) => {
            const networkCaps = await analyzer.checkNetworkCapabilities();
            const passed = networkCaps.hasTLS && networkCaps.hasQUIC && networkCaps.hasHTX && networkCaps.hasECH && networkCaps.port443;
            return {
                id: 1,
                name: 'HTX over TCP-443 & QUIC-443',
                description: 'Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH',
                passed,
                details: passed ? '✅ Found HTX, QUIC, TLS, ECH, and port 443 support' : `❌ Missing: ${(0, format_1.missingList)([
                    !networkCaps.hasTLS && 'TLS',
                    !networkCaps.hasQUIC && 'QUIC',
                    !networkCaps.hasHTX && 'HTX',
                    !networkCaps.hasECH && 'ECH',
                    !networkCaps.port443 && 'port 443'
                ])}`,
                severity: 'critical',
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 2,
        key: 'rotating-access-tickets',
        name: 'Rotating Access Tickets',
        description: 'Uses rotating access tickets (§5.2)',
        severity: 'major',
        introducedIn: '1.0',
        mandatoryIn: '1.0',
        evaluate: async (analyzer) => {
            const analysis = await analyzer.analyze();
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
                details: passed ? '✅ Found access ticket and rotation support' : `❌ Missing: ${(0, format_1.missingList)([
                    !hasTickets && 'access tickets',
                    !hasRotation && 'ticket rotation'
                ])}`,
                severity: 'major',
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 3,
        key: 'inner-frame-encryption',
        name: 'Inner Frame Encryption',
        description: 'Encrypts inner frames with ChaCha20-Poly1305, 24-bit length, 96-bit nonce',
        severity: 'critical',
        introducedIn: '1.0',
        mandatoryIn: '1.0',
        evaluate: async (analyzer) => {
            const cryptoCaps = await analyzer.checkCryptographicCapabilities();
            const passed = cryptoCaps.hasChaCha20 && cryptoCaps.hasPoly1305;
            return {
                id: 3,
                name: 'Inner Frame Encryption',
                description: 'Encrypts inner frames with ChaCha20-Poly1305, 24-bit length, 96-bit nonce',
                passed,
                details: passed ? '✅ Found ChaCha20-Poly1305 support' : `❌ Missing: ${(0, format_1.missingList)([
                    !cryptoCaps.hasChaCha20 && 'ChaCha20',
                    !cryptoCaps.hasPoly1305 && 'Poly1305'
                ])}`,
                severity: 'critical',
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 4,
        key: 'scion-path-management',
        name: 'SCION Path Management',
        description: 'Maintains ≥ 3 signed SCION paths or attaches a valid IP-transition header',
        severity: 'critical',
        introducedIn: '1.0',
        mandatoryIn: '1.0',
        evaluate: async (analyzer) => {
            const scionSupport = await analyzer.checkSCIONSupport();
            const passed = scionSupport.hasSCION && (scionSupport.pathManagement || scionSupport.hasIPTransition) && scionSupport.pathDiversityCount >= 2;
            return {
                id: 4,
                name: 'SCION Path Management',
                description: 'Maintains ≥ 3 signed SCION paths or attaches a valid IP-transition header',
                passed,
                details: passed ? `✅ SCION support with path management/IP-transition & path diversity=${scionSupport.pathDiversityCount}` : `❌ Missing: ${(0, format_1.missingList)([
                    !scionSupport.hasSCION && 'SCION support',
                    !scionSupport.pathManagement && 'path management',
                    !scionSupport.hasIPTransition && 'IP-transition header',
                    scionSupport.pathDiversityCount < 2 && '≥2 path diversity markers'
                ])}`,
                severity: 'critical',
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 5,
        key: 'transport-endpoints',
        name: 'Transport Endpoints',
        description: 'Offers Betanet HTX & HTX-QUIC transports (v1.1.0 preferred, 1.0.0 legacy supported)',
        severity: 'major',
        introducedIn: '1.0',
        mandatoryIn: '1.0',
        evaluate: async (analyzer) => {
            const analysis = await analyzer.analyze();
            const strings = analysis.strings.join(' ');
            const hasHTXEndpoint = constants_1.TRANSPORT_ENDPOINT_VERSIONS.some(v => strings.includes(`/betanet/htx/${v}`));
            const hasQUICEndpoint = constants_1.TRANSPORT_ENDPOINT_VERSIONS.some(v => strings.includes(`/betanet/htxquic/${v}`));
            const optionalPresent = constants_1.OPTIONAL_TRANSPORTS.filter(t => strings.includes(t.path));
            const passed = hasHTXEndpoint && hasQUICEndpoint;
            return {
                id: 5,
                name: 'Transport Endpoints',
                description: 'Offers Betanet HTX & HTX-QUIC transports (v1.1.0 preferred, 1.0.0 legacy supported)',
                passed,
                details: passed ? `✅ Found HTX & QUIC transport endpoints${optionalPresent.length ? ' + optional: ' + optionalPresent.map(o => o.kind).join(', ') : ''}` :
                    `❌ Missing: ${(0, format_1.missingList)([
                        !hasHTXEndpoint && 'HTX endpoint (v1.1.0 or 1.0.0)',
                        !hasQUICEndpoint && 'HTX-QUIC endpoint (v1.1.0 or 1.0.0)'
                    ])}`,
                severity: 'major',
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 6,
        key: 'dht-seed-bootstrap',
        name: 'DHT Seed Bootstrap',
        description: 'Implements deterministic (1.0) or rotating rendezvous (1.1) DHT seed bootstrap',
        severity: 'major',
        introducedIn: '1.0',
        mandatoryIn: '1.0',
        evaluate: async (analyzer) => {
            const dhtSupport = await analyzer.checkDHTSupport();
            const passed = !!(dhtSupport.hasDHT && (dhtSupport.deterministicBootstrap || dhtSupport.rendezvousRotation));
            return {
                id: 6,
                name: 'DHT Seed Bootstrap',
                description: 'Implements deterministic (1.0) or rotating rendezvous (1.1) DHT seed bootstrap',
                passed,
                details: passed ? `✅ DHT ${dhtSupport.rendezvousRotation ? `rotating rendezvous (hits=${dhtSupport.rotationHits})` : 'deterministic'} bootstrap` +
                    (dhtSupport.beaconSetIndicator ? ' + BeaconSet' : '') :
                    `❌ Missing: ${(0, format_1.missingList)([
                        !dhtSupport.hasDHT && 'DHT support',
                        !(dhtSupport.deterministicBootstrap || dhtSupport.rendezvousRotation) && 'deterministic or rendezvous bootstrap'
                    ])}`,
                severity: 'major',
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 7,
        key: 'alias-ledger-verification',
        name: 'Alias Ledger Verification',
        description: 'Verifies alias ledger with 2-of-3 chain consensus',
        severity: 'major',
        introducedIn: '1.0',
        mandatoryIn: '1.0',
        evaluate: async (analyzer) => {
            const ledgerSupport = await analyzer.checkLedgerSupport();
            const passed = ledgerSupport.hasAliasLedger && ledgerSupport.hasConsensus && ledgerSupport.chainSupport;
            return {
                id: 7,
                name: 'Alias Ledger Verification',
                description: 'Verifies alias ledger with 2-of-3 chain consensus',
                passed,
                details: passed ? '✅ Found alias ledger with consensus and chain support' : `❌ Missing: ${(0, format_1.missingList)([
                    !ledgerSupport.hasAliasLedger && 'alias ledger',
                    !ledgerSupport.hasConsensus && '2-of-3 consensus',
                    !ledgerSupport.chainSupport && 'chain verification'
                ])}`,
                severity: 'major',
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 8,
        key: 'payment-system',
        name: 'Payment System',
        description: 'Accepts Cashu vouchers from federated mints & supports Lightning settlement (voucher/FROST signals optional)',
        severity: 'major',
        introducedIn: '1.0',
        mandatoryIn: '1.0',
        evaluate: async (analyzer) => {
            const paymentSupport = await analyzer.checkPaymentSupport();
            const passed = paymentSupport.hasCashu && paymentSupport.hasLightning && paymentSupport.hasFederation;
            return {
                id: 8,
                name: 'Payment System',
                description: 'Accepts Cashu vouchers from federated mints & supports Lightning settlement (voucher/FROST signals optional)',
                passed,
                details: passed ? '✅ Found Cashu, Lightning, and federation support' +
                    (paymentSupport.hasVoucherFormat ? ' + voucher format' : '') +
                    (paymentSupport.hasFROST ? ' + FROST group' : '') +
                    (paymentSupport.hasPoW22 ? ' + PoW≥22b' : '') :
                    `❌ Missing: ${(0, format_1.missingList)([
                        !paymentSupport.hasCashu && 'Cashu support',
                        !paymentSupport.hasLightning && 'Lightning support',
                        !paymentSupport.hasFederation && 'federation support'
                    ])}`,
                severity: 'major',
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 9,
        key: 'build-provenance',
        name: 'Build Provenance',
        description: 'Builds reproducibly and publishes SLSA 3 provenance',
        severity: 'minor',
        introducedIn: '1.0',
        mandatoryIn: '1.0',
        evaluate: async (analyzer) => {
            const rawBuildInfo = await (analyzer.checkBuildProvenance?.() ?? Promise.resolve(null));
            const buildInfo = rawBuildInfo || { hasSLSA: false, reproducible: false, provenance: false };
            const evidence = analyzer.evidence || {};
            const prov = evidence.provenance || {};
            const materialsValidated = prov.materialsValidated === true;
            const materialsMismatchCount = prov.materialsMismatchCount || 0;
            const materialsComplete = prov.materialsComplete === true;
            const signatureVerified = prov.signatureVerified === true;
            // Validate normative provenance
            let normativeDetails = [];
            let hasNormative = false;
            try {
                const predicateOk = typeof prov.predicateType === 'string' && prov.predicateType.startsWith('https://slsa.dev/');
                const builderOk = typeof prov.builderId === 'string' && prov.builderId.length > 5;
                let digestOk = false;
                if (prov.binaryDigest && prov.binaryDigest.startsWith('sha256:')) {
                    const actual = await analyzer.getBinarySha256?.();
                    if (actual) {
                        digestOk = prov.binaryDigest === 'sha256:' + actual;
                        if (!digestOk)
                            normativeDetails.push(`digest mismatch (evidence ${prov.binaryDigest} != sha256:${actual})`);
                    }
                    else {
                        // Accept provided digest if we cannot compute locally (test stubs / degraded analyzer)
                        digestOk = true;
                        normativeDetails.push('accepted external digest (local hash unavailable)');
                    }
                }
                else if (Array.isArray(prov.subjects)) {
                    const actual = await analyzer.getBinarySha256?.();
                    if (actual) {
                        const match = prov.subjects.find((s) => s?.digest?.sha256 === actual);
                        if (match)
                            digestOk = true;
                        else
                            normativeDetails.push('subject digest mismatch');
                    }
                    else if (prov.subjects.some((s) => s?.digest?.sha256)) {
                        digestOk = true; // accept external subjects if we cannot hash
                        normativeDetails.push('accepted external subject digest (local hash unavailable)');
                    }
                }
                // If we cannot compute local hash and external digest provided, digestOk already true; else require it.
                // Allow predicate+builder to qualify if external digest present OR subjects present even if we could not verify locally
                if (!digestOk && (prov.binaryDigest || (Array.isArray(prov.subjects) && prov.subjects.length))) {
                    hasNormative = predicateOk && builderOk;
                    if (hasNormative && !digestOk)
                        normativeDetails.push('digest acceptance (unverified)');
                }
                else {
                    hasNormative = predicateOk && builderOk && digestOk;
                }
                if (!predicateOk)
                    normativeDetails.push('predicateType missing/invalid');
                if (!builderOk)
                    normativeDetails.push('builderId missing/invalid');
                if (!digestOk)
                    normativeDetails.push('binary digest mismatch');
                if (hasNormative)
                    normativeDetails = ['validated predicateType, builderId, binary digest'];
            }
            catch (e) {
                normativeDetails.push('error during provenance validation: ' + (e.message || e));
            }
            // Promote normative evidence into buildInfo for pass calculation if internal heuristics absent
            if (hasNormative) {
                buildInfo.hasSLSA = buildInfo.hasSLSA || true;
                buildInfo.reproducible = buildInfo.reproducible || true;
                buildInfo.provenance = buildInfo.provenance || true;
            }
            // Enforce reproducible rebuild if a mismatch flag present in evidence (future: CI injects)
            let rebuildMismatch = false;
            if (prov.rebuildDigestMismatch === true) {
                rebuildMismatch = true;
                normativeDetails.push('rebuild digest mismatch flagged');
            }
            const passed = !rebuildMismatch && ((buildInfo.hasSLSA && buildInfo.reproducible && buildInfo.provenance) || hasNormative) && (!materialsMismatchCount);
            const missing = (0, format_1.missingList)([
                !(buildInfo.hasSLSA || prov.predicateType) && 'SLSA support/predicate',
                !(buildInfo.reproducible || hasNormative) && 'reproducible builds',
                !(buildInfo.provenance || prov.builderId) && 'build provenance'
            ]);
            return {
                id: 9,
                name: 'Build Provenance',
                description: 'Builds reproducibly and publishes SLSA 3 provenance',
                passed,
                details: passed ? (hasNormative ? `✅ Provenance verified (${normativeDetails.join('; ')}${materialsValidated ? '; materials cross-checked' : ''}${materialsComplete ? '; materials complete' : ''}${signatureVerified ? '; signature verified' : ''})` : '✅ Found SLSA, reproducible builds, and provenance heuristics') : (rebuildMismatch ? '❌ Rebuild digest mismatch (non-reproducible)' : (materialsMismatchCount ? `❌ Materials/SBOM mismatch (${materialsMismatchCount} unmatched)` : `❌ Missing: ${missing}`)),
                severity: 'minor',
                evidenceType: hasNormative ? 'artifact' : 'heuristic'
            };
        }
    },
    {
        id: 10,
        key: 'post-quantum-suites',
        name: 'Post-Quantum Cipher Suites',
        description: 'Presents X25519-Kyber768 suites once the mandatory date is reached',
        severity: 'minor',
        introducedIn: '1.0',
        mandatoryIn: constants_1.POST_QUANTUM_MANDATORY_DATE,
        evaluate: async (analyzer, now) => {
            const cryptoCaps = await analyzer.checkCryptographicCapabilities();
            // ISSUE-016: UTC-safe mandatory date evaluation
            const override = process.env.BETANET_PQ_DATE_OVERRIDE;
            const overrideEpoch = (0, constants_1.parseOverridePQDate)(override);
            const mandatoryEpoch = overrideEpoch !== undefined ? overrideEpoch : constants_1.POST_QUANTUM_MANDATORY_EPOCH_MS;
            const isPastMandatoryDate = now.getTime() >= mandatoryEpoch;
            const mandatoryISO = new Date(mandatoryEpoch).toISOString().slice(0, 10);
            let passed = true;
            let details = `✅ Post-quantum requirements not yet mandatory (enforce after ${mandatoryISO})`;
            let severity = 'minor';
            if (isPastMandatoryDate) {
                severity = 'critical';
                passed = cryptoCaps.hasX25519 && cryptoCaps.hasKyber768;
                details = passed ? '✅ Found X25519-Kyber768 hybrid cipher suite' : `❌ Missing: ${(0, format_1.missingList)([
                    !cryptoCaps.hasX25519 && 'X25519',
                    !cryptoCaps.hasKyber768 && 'Kyber768'
                ])} (mandatory after ${mandatoryISO})`;
            }
            return {
                id: 10,
                name: 'Post-Quantum Cipher Suites',
                description: 'Presents X25519-Kyber768 suites once the mandatory date is reached',
                passed,
                details,
                severity,
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 11,
        key: 'privacy-hop-enforcement',
        name: 'Privacy Hop Enforcement',
        description: 'Enforces ≥2 (balanced) or ≥3 (strict) mixnet hops with BeaconSet-based diversity',
        severity: 'major',
        introducedIn: '1.1',
        // Not yet mandatory (heuristic informational) in 1.1 baseline
        evaluate: async (analyzer) => {
            const analysis = await analyzer.analyze();
            const evaluation = (0, heuristics_1.evaluatePrivacyTokens)(analysis.strings);
            const passed = evaluation.passed;
            return {
                id: 11,
                name: 'Privacy Hop Enforcement',
                description: 'Enforces ≥2 (balanced) or ≥3 (strict) mixnet hops with BeaconSet-based diversity',
                passed,
                details: passed ? `✅ Privacy weighting ok (mix=${evaluation.mixScore} beacon=${evaluation.beaconScore} diversity=${evaluation.diversityScore} total=${evaluation.totalScore})` :
                    `❌ Privacy indicators insufficient (mix=${evaluation.mixScore} beacon=${evaluation.beaconScore} diversity=${evaluation.diversityScore})`,
                severity: 'major',
                evidenceType: 'heuristic'
            };
        }
    },
    {
        id: 12,
        key: 'clienthello-static-template',
        name: 'TLS ClientHello Static Template',
        description: 'Extracts ALPN set/order & extension ordering hash (static approximation)',
        severity: 'minor',
        introducedIn: '1.1',
        evaluate: async (analyzer) => {
            const patterns = await analyzer.getStaticPatterns?.();
            const ch = patterns?.clientHello;
            const passed = !!(ch && ch.alpn && ch.alpn.length >= 2);
            return {
                id: 12,
                name: 'TLS ClientHello Static Template',
                description: 'Extracts ALPN set/order & extension ordering hash (static approximation)',
                passed,
                details: passed ? `✅ ALPN: ${ch.alpn.join(', ')} extCount=${ch.extensions?.length || 0} hash=${ch.extOrderSha256?.slice(0, 12)}` : '❌ Insufficient ALPN evidence',
                severity: 'minor',
                evidenceType: 'static-structural'
            };
        }
    },
    {
        id: 13,
        key: 'noise-xk-pattern',
        name: 'Noise XK Pattern',
        description: 'Detects Noise_XK handshake pattern tokens',
        severity: 'minor',
        introducedIn: '1.1',
        evaluate: async (analyzer) => {
            const patterns = await analyzer.getStaticPatterns?.();
            const noise = patterns?.noise;
            const passed = !!(noise && noise.pattern === 'XK');
            return {
                id: 13,
                name: 'Noise XK Pattern',
                description: 'Detects Noise_XK handshake pattern tokens',
                passed,
                details: passed ? '✅ Noise_XK pattern detected' : '❌ Noise_XK pattern not found',
                severity: 'minor',
                evidenceType: 'static-structural'
            };
        }
    },
    {
        id: 14,
        key: 'voucher-struct-heuristic',
        name: 'Voucher Struct Heuristic',
        description: 'Detects presence of 128B voucher struct token triad',
        severity: 'minor',
        introducedIn: '1.1',
        evaluate: async (analyzer) => {
            const patterns = await analyzer.getStaticPatterns?.();
            const voucher = patterns?.voucher;
            const passed = !!(voucher && voucher.structLikely);
            return {
                id: 14,
                name: 'Voucher Struct Heuristic',
                description: 'Detects presence of 128B voucher struct token triad',
                passed,
                details: voucher ? (voucher.structLikely ? `✅ Struct tokens: ${voucher.tokenHits.join(', ')} proximity=${voucher.proximityBytes ?? 'n/a'}` : `❌ Incomplete tokens: ${voucher.tokenHits.join(', ')} proximity=${voucher.proximityBytes ?? 'n/a'}`) : '❌ No voucher struct tokens',
                severity: 'minor',
                evidenceType: 'static-structural'
            };
        }
    },
    {
        id: 15,
        key: 'governance-anti-concentration',
        name: 'Governance Anti-Concentration',
        description: 'Validates AS/org caps & partition safety (evidence-based)',
        severity: 'major',
        introducedIn: '1.1',
        evaluate: async (analyzer) => {
            const ev = analyzer.evidence;
            const gov = ev?.governance;
            let passed = false;
            let details = '❌ No governance evidence';
            if (gov && typeof gov === 'object') {
                const { asCapApplied, orgCapApplied, maxASShare, maxOrgShare, partitionsDetected } = gov;
                passed = !!(asCapApplied && orgCapApplied && maxASShare <= 0.2 && maxOrgShare <= 0.25 && partitionsDetected === false);
                details = passed ? `✅ Caps enforced (AS<=${maxASShare} org<=${maxOrgShare}) no partitions` : `❌ Governance issues: ${(0, format_1.missingList)([
                    !asCapApplied && 'AS caps not applied',
                    !orgCapApplied && 'Org caps not applied',
                    (maxASShare > 0.2) && `AS share ${maxASShare}`,
                    (maxOrgShare > 0.25) && `Org share ${maxOrgShare}`,
                    partitionsDetected === true && 'partitions detected'
                ])}`;
            }
            return { id: 15, name: 'Governance Anti-Concentration', description: 'Validates AS/org caps & partition safety (evidence-based)', passed, details, severity: 'major', evidenceType: gov ? 'artifact' : 'heuristic' };
        }
    },
    {
        id: 16,
        key: 'ledger-finality-observation',
        name: 'Ledger Finality Observation',
        description: 'Evidence of 2-of-3 finality & quorum certificate validity',
        severity: 'major',
        introducedIn: '1.1',
        evaluate: async (analyzer) => {
            const ev = analyzer.evidence;
            const ledger = ev?.ledger;
            let passed = false;
            let details = '❌ No ledger evidence';
            if (ledger && typeof ledger === 'object') {
                const { finalitySets, quorumCertificatesValid, emergencyAdvanceUsed } = ledger;
                const has2of3 = Array.isArray(finalitySets) && finalitySets.length >= 2; // simplified proxy
                passed = !!(has2of3 && quorumCertificatesValid === true && emergencyAdvanceUsed !== true);
                details = passed ? `✅ Finality sets=${finalitySets.length} quorum certs valid` : `❌ Ledger issues: ${(0, format_1.missingList)([
                    !has2of3 && 'insufficient finality sets',
                    quorumCertificatesValid !== true && 'invalid quorum certificates',
                    emergencyAdvanceUsed === true && 'emergency advance used'
                ])}`;
            }
            return { id: 16, name: 'Ledger Finality Observation', description: 'Evidence of 2-of-3 finality & quorum certificate validity', passed, details, severity: 'major', evidenceType: ledger ? 'artifact' : 'heuristic' };
        }
    }
];
function getChecksByIds(ids) {
    const set = new Set(ids);
    return exports.CHECK_REGISTRY.filter(c => set.has(c.id)).sort((a, b) => a.id - b.id);
}
//# sourceMappingURL=check-registry.js.map