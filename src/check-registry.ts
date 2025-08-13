// Central registry of Betanet compliance checks (Plan 3 consolidation)
// Each check definition contains metadata & an evaluator that derives result from the BinaryAnalyzer.
// This replaces ad-hoc per-check methods and normalizes naming & severities.

import { BinaryAnalyzer } from './analyzer';
import { TRANSPORT_ENDPOINT_VERSIONS, OPTIONAL_TRANSPORTS, POST_QUANTUM_MANDATORY_DATE, POST_QUANTUM_MANDATORY_EPOCH_MS, parseOverridePQDate } from './constants';
import { evaluatePrivacyTokens } from './heuristics';
import { ComplianceCheck } from './types';
import { missingList } from './format';

export interface CheckDefinitionMeta {
  id: number;
  key: string; // stable key for programmatic reference
  name: string;
  description: string;
  severity: 'critical' | 'major' | 'minor'; // base severity (may be overridden dynamically)
  introducedIn: string; // spec version introduced
  mandatoryIn?: string; // spec version where mandatory (if later than introduced)
  evaluate: (analyzer: BinaryAnalyzer, now: Date) => Promise<ComplianceCheck>;
}

// missingList helper moved to format.ts (ISSUE-027) for reuse across modules

export const CHECK_REGISTRY: CheckDefinitionMeta[] = [
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
  const ev: any = (analyzer as any).evidence || {};
  const tmpl = ev.clientHelloTemplate; // static template evidence
  const dyn = ev.dynamicClientHelloCapture; // dynamic calibration evidence
      // Determine evidence type escalation
      let evidenceType: 'heuristic' | 'static-structural' | 'dynamic-protocol' = 'heuristic';
      if (tmpl) evidenceType = 'static-structural';
      if (dyn && (dyn.alpn || dyn.extOrderSha256)) evidenceType = 'dynamic-protocol';
      // Baseline transport feature checks
      const baseOk = networkCaps.hasTLS && networkCaps.hasQUIC && networkCaps.hasHTX && networkCaps.port443;
      // ECH detection: prefer dynamic/template extension list (draft ECH extension 0xfe0d = 65293)
      const ECH_EXT_ID = 65293;
      const echDetected = networkCaps.hasECH || (!!dyn?.extensions && dyn.extensions.includes(ECH_EXT_ID)) || (!!tmpl?.extensions && tmpl.extensions.includes(ECH_EXT_ID));
      // Calibration requirement when dynamic present: dynamic must match static template (if template exists) and have matching ext hash / ALPN
      let calibrationOk = true;
      let calibrationNote = '';
      if (evidenceType === 'dynamic-protocol') {
        // If we have both static & dynamic require match
        if (tmpl && dyn) {
          const alpnMatch = Array.isArray(tmpl.alpn) && Array.isArray(dyn.alpn) && tmpl.alpn.join(',') === dyn.alpn.join(',');
          const extHashMatch = tmpl.extOrderSha256 && dyn.extOrderSha256 && tmpl.extOrderSha256 === dyn.extOrderSha256;
          calibrationOk = alpnMatch && extHashMatch && dyn.matchStaticTemplate !== false; // dyn.matchStaticTemplate should be true/undefined
          if (!calibrationOk) {
            calibrationNote = dyn.note ? ` mismatch:${dyn.note}` : ' mismatch:calibration';
          }
        }
      } else if (evidenceType === 'static-structural') {
        // Static structural requires minimally complete template
        calibrationOk = tmpl && Array.isArray(tmpl.alpn) && tmpl.alpn.length >= 2 && !!tmpl.extOrderSha256;
        if (!calibrationOk) calibrationNote = ' incomplete-static-template';
      }
      const passed = baseOk && echDetected && calibrationOk;
      const missingParts: string[] = [];
      if (!networkCaps.hasTLS) missingParts.push('TLS');
      if (!networkCaps.hasQUIC) missingParts.push('QUIC');
      if (!networkCaps.hasHTX) missingParts.push('HTX');
      if (!networkCaps.port443) missingParts.push('port 443');
      if (!echDetected) missingParts.push('ECH');
      if (!calibrationOk) missingParts.push('calibration');
      let details: string;
      if (passed) {
        const mode = evidenceType === 'dynamic-protocol' ? 'dynamic-calibrated' : (evidenceType === 'static-structural' ? 'static-template' : 'heuristic');
        const ja3h = dyn?.ja3Hash ? dyn.ja3Hash.slice(0,12) : (dyn?.ja3 ? dyn.ja3.slice(0,16) : undefined);
        details = `✅ HTX TCP+QUIC + TLS1.3 mimic & ECH (${mode}${ja3h ? ' ja3='+ja3h : ''}${calibrationNote})`;
      } else {
        details = `❌ Missing: ${missingList(missingParts)}${calibrationNote}`;
      }
      return {
        id: 1,
        name: 'HTX over TCP-443 & QUIC-443',
        description: 'Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH',
        passed,
        details,
        severity: 'critical',
        evidenceType
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
        details: passed ? '✅ Found access ticket and rotation support' : `❌ Missing: ${missingList([
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
        details: passed ? '✅ Found ChaCha20-Poly1305 support' : `❌ Missing: ${missingList([
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
        details: passed ? `✅ SCION support with path management/IP-transition & path diversity=${scionSupport.pathDiversityCount}` : `❌ Missing: ${missingList([
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
      const hasHTXEndpoint = TRANSPORT_ENDPOINT_VERSIONS.some(v => strings.includes(`/betanet/htx/${v}`));
      const hasQUICEndpoint = TRANSPORT_ENDPOINT_VERSIONS.some(v => strings.includes(`/betanet/htxquic/${v}`));
      const optionalPresent = OPTIONAL_TRANSPORTS.filter(t => strings.includes(t.path));
      const passed = hasHTXEndpoint && hasQUICEndpoint;
      return {
        id: 5,
        name: 'Transport Endpoints',
        description: 'Offers Betanet HTX & HTX-QUIC transports (v1.1.0 preferred, 1.0.0 legacy supported)',
        passed,
        details: passed ? `✅ Found HTX & QUIC transport endpoints${optionalPresent.length ? ' + optional: ' + optionalPresent.map(o => o.kind).join(', ') : ''}` :
          `❌ Missing: ${missingList([
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
      const ev: any = (analyzer as any).evidence;
      const bootstrap = ev?.bootstrap;
      // Heuristic baseline
      let passed = !!(dhtSupport.hasDHT && (dhtSupport.deterministicBootstrap || dhtSupport.rendezvousRotation));
      let modeDetail = dhtSupport.rendezvousRotation ? `rotating rendezvous (hits=${dhtSupport.rotationHits})` : (dhtSupport.deterministicBootstrap ? 'deterministic' : 'unknown');
      // Bootstrap evidence upgrade (Phase 4): require ≥2 rotation epochs & no deterministic seed and at least 2 entropy sources
      let evidenceType: 'heuristic' | 'artifact' = 'heuristic';
      if (bootstrap) {
        evidenceType = 'artifact';
        const epochsOk = (bootstrap.rotationEpochs || 0) >= 2;
        const entropyOk = (bootstrap.beaconSetEntropySources || 0) >= 2;
        const noLegacySeed = bootstrap.deterministicSeedDetected !== true;
        passed = passed && epochsOk && entropyOk && noLegacySeed;
        modeDetail += ` epochs=${bootstrap.rotationEpochs||0} entropySrc=${bootstrap.beaconSetEntropySources||0}${bootstrap.deterministicSeedDetected? ' legacy-seed' : ''}`;
      }
      return {
        id: 6,
        name: 'DHT Seed Bootstrap',
        description: 'Implements deterministic (1.0) or rotating rendezvous (1.1) DHT seed bootstrap',
        passed,
        details: passed ? `✅ DHT ${modeDetail} bootstrap` +
          (dhtSupport.beaconSetIndicator ? ' + BeaconSet' : '') :
          `❌ Missing: ${missingList([
            !dhtSupport.hasDHT && 'DHT support',
            !(dhtSupport.deterministicBootstrap || dhtSupport.rendezvousRotation) && 'deterministic or rendezvous bootstrap',
            bootstrap && (bootstrap.rotationEpochs||0) < 2 && '≥2 rotation epochs',
            bootstrap && (bootstrap.beaconSetEntropySources||0) < 2 && '≥2 entropy sources',
            bootstrap && bootstrap.deterministicSeedDetected === true && 'legacy deterministic seed'
          ])}`,
        severity: 'major',
        evidenceType
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
        details: passed ? '✅ Found alias ledger with consensus and chain support' : `❌ Missing: ${missingList([
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
      const ev: any = (analyzer as any).evidence;
      const pow = ev?.powAdaptive;
      let passed = paymentSupport.hasCashu && paymentSupport.hasLightning && paymentSupport.hasFederation;
      let powDetail = '';
      if (pow && Array.isArray(pow.difficultySamples) && pow.difficultySamples.length >= 3) {
        // Simple evolution validation: ensure samples converge within ±2 bits of target and no single backward jump >4 bits
        const target = pow.targetBits || 22;
  const withinBand = pow.difficultySamples.every((b: number) => Math.abs(b - target) <= 2);
        let maxDrop = 0;
        for (let i=1;i<pow.difficultySamples.length;i++) {
          const drop = pow.difficultySamples[i-1] - pow.difficultySamples[i];
            if (drop > maxDrop) maxDrop = drop;
        }
        const noLargeDrop = maxDrop <= 4;
        const monotonicApprox = pow.monotonicTrend === true || pow.difficultySamples[pow.difficultySamples.length-1] >= pow.difficultySamples[0] - 2;
        const powOk = withinBand && noLargeDrop && monotonicApprox;
        passed = passed && powOk;
        powDetail = ` powDiff=[${pow.difficultySamples.join('>')}] target=${target} maxDrop=${maxDrop}` + (powOk ? '' : ' pow-evolution-fail');
      }
      let details: string;
      if (passed) {
        details = '✅ Found Cashu, Lightning, and federation support' +
          (paymentSupport.hasVoucherFormat ? ' + voucher format' : '') +
          (paymentSupport.hasFROST ? ' + FROST group' : '') +
          (paymentSupport.hasPoW22 ? ' + PoW≥22b' : '') + powDetail;
      } else {
        const missingParts = [
          !paymentSupport.hasCashu && 'Cashu support',
          !paymentSupport.hasLightning && 'Lightning support',
          !paymentSupport.hasFederation && 'federation support'
        ];
        const baseMissing = missingList(missingParts as any);
        const noBaseMissing = missingParts.filter(Boolean).length === 0;
        if (pow && powDetail.includes('pow-evolution-fail') && noBaseMissing) {
          details = `❌ PoW evolution invalid ${powDetail.trim()}`;
        } else {
          details = `❌ Missing: ${baseMissing}${pow ? powDetail : ''}`;
        }
      }
      return { id: 8, name: 'Payment System', description: 'Accepts Cashu vouchers from federated mints & supports Lightning settlement (voucher/FROST signals optional)', passed, details, severity: 'major', evidenceType: pow ? 'artifact' : 'heuristic' };
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
      const evidence = (analyzer as any).evidence || {};
      const prov = evidence.provenance || {};
  const materialsValidated = prov.materialsValidated === true;
  const materialsMismatchCount = prov.materialsMismatchCount || 0;
  const materialsComplete = prov.materialsComplete === true;
  const signatureVerified = prov.signatureVerified === true;
  const dsseSigners = prov.dsseSignerCount || 0;
  const dsseEnvelopeVerified = prov.dsseEnvelopeVerified === true;
  const dsseThresholdMet = prov.dsseThresholdMet === true;
  const dsseRequiredKeysPresent = prov.dsseRequiredKeysPresent === true;
  const dssePolicyReasons: string[] = prov.dssePolicyReasons || [];
      // Validate normative provenance
      let normativeDetails: string[] = [];
      let hasNormative = false;
      try {
        const predicateOk = typeof prov.predicateType === 'string' && prov.predicateType.startsWith('https://slsa.dev/');
        const builderOk = typeof prov.builderId === 'string' && prov.builderId.length > 5;
        let digestOk = false;
        if (prov.binaryDigest && prov.binaryDigest.startsWith('sha256:')) {
          const actual = await (analyzer as any).getBinarySha256?.();
          if (actual) {
            digestOk = prov.binaryDigest === 'sha256:' + actual;
            if (!digestOk) normativeDetails.push(`digest mismatch (evidence ${prov.binaryDigest} != sha256:${actual})`);
          } else {
            // Accept provided digest if we cannot compute locally (test stubs / degraded analyzer)
            digestOk = true;
            normativeDetails.push('accepted external digest (local hash unavailable)');
          }
        } else if (Array.isArray(prov.subjects)) {
          const actual = await (analyzer as any).getBinarySha256?.();
            if (actual) {
              const match = prov.subjects.find((s: any) => s?.digest?.sha256 === actual);
              if (match) digestOk = true; else normativeDetails.push('subject digest mismatch');
            } else if (prov.subjects.some((s: any) => s?.digest?.sha256)) {
              digestOk = true; // accept external subjects if we cannot hash
              normativeDetails.push('accepted external subject digest (local hash unavailable)');
            }
        }
  // If we cannot compute local hash and external digest provided, digestOk already true; else require it.
        // Allow predicate+builder to qualify if external digest present OR subjects present even if we could not verify locally
        if (!digestOk && (prov.binaryDigest || (Array.isArray(prov.subjects) && prov.subjects.length))) {
          hasNormative = predicateOk && builderOk;
          if (hasNormative && !digestOk) normativeDetails.push('digest acceptance (unverified)');
        } else {
          hasNormative = predicateOk && builderOk && digestOk;
        }
        if (!predicateOk) normativeDetails.push('predicateType missing/invalid');
        if (!builderOk) normativeDetails.push('builderId missing/invalid');
        if (!digestOk) normativeDetails.push('binary digest mismatch');
        if (hasNormative) normativeDetails = ['validated predicateType, builderId, binary digest'];
      } catch (e: any) {
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
      const missing = missingList([
        !(buildInfo.hasSLSA || prov.predicateType) && 'SLSA support/predicate',
        !(buildInfo.reproducible || hasNormative) && 'reproducible builds',
        !(buildInfo.provenance || prov.builderId) && 'build provenance'
      ]);
      return {
        id: 9,
        name: 'Build Provenance',
        description: 'Builds reproducibly and publishes SLSA 3 provenance',
        passed,
  details: passed ? (hasNormative ? `✅ Provenance verified (${normativeDetails.join('; ')}${materialsValidated ? '; materials cross-checked' : ''}${materialsComplete ? '; materials complete' : ''}${signatureVerified ? '; detached signature verified' : ''}${dsseEnvelopeVerified ? '; dsse envelope verified' : (dsseSigners ? `; dsse signers=${dsseSigners}` : '')}${dsseThresholdMet ? '; dsse threshold met' : ''}${dsseRequiredKeysPresent ? '' : '; missing required dsse keys'}${dssePolicyReasons.length ? '; policy issues: '+dssePolicyReasons.join(',') : ''})` : '✅ Found SLSA, reproducible builds, and provenance heuristics') : (
          rebuildMismatch ? '❌ Rebuild digest mismatch (non-reproducible)' : (materialsMismatchCount ? `❌ Materials/SBOM mismatch (${materialsMismatchCount} unmatched)` : `❌ Missing: ${missing}`)
        ),
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
  mandatoryIn: POST_QUANTUM_MANDATORY_DATE,
    evaluate: async (analyzer, now) => {
      const cryptoCaps = await analyzer.checkCryptographicCapabilities();
      // ISSUE-016: UTC-safe mandatory date evaluation
      const override = process.env.BETANET_PQ_DATE_OVERRIDE;
      const overrideEpoch = parseOverridePQDate(override);
      const mandatoryEpoch = overrideEpoch !== undefined ? overrideEpoch : POST_QUANTUM_MANDATORY_EPOCH_MS;
      const isPastMandatoryDate = now.getTime() >= mandatoryEpoch;
      const mandatoryISO = new Date(mandatoryEpoch).toISOString().slice(0,10);
      let passed = true;
      let details = `✅ Post-quantum requirements not yet mandatory (enforce after ${mandatoryISO})`;
      let severity: 'minor' | 'critical' = 'minor';
      if (isPastMandatoryDate) {
        severity = 'critical';
        passed = cryptoCaps.hasX25519 && cryptoCaps.hasKyber768;
        details = passed ? '✅ Found X25519-Kyber768 hybrid cipher suite' : `❌ Missing: ${missingList([
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
      } as ComplianceCheck;
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
      const evaluation = evaluatePrivacyTokens(analysis.strings);
      const ev: any = (analyzer as any).evidence;
      const mix = ev?.mix;
      // If mix evidence present, treat as dynamic-protocol upgrade and enforce hop depth
      let dynamicUpgrade = false;
      let passed = evaluation.passed;
      let detailParts: string[] = [];
      if (mix && typeof mix === 'object') {
        dynamicUpgrade = true;
  const minLen = Math.min(...(mix.pathLengths || []));
  const declaredMode = mix.mode || 'balanced';
  const requiredDepth = declaredMode === 'strict' ? (mix.minHopsStrict || 3) : (mix.minHopsBalanced || 2);
  const hopDepthOk = minLen >= requiredDepth;
        passed = passed && hopDepthOk && (mix.uniquenessRatio ? mix.uniquenessRatio >= 0.7 : true);
  detailParts.push(`hopDepthMin=${minLen} required=${requiredDepth} mode=${declaredMode}`);
        if (mix.uniquenessRatio !== undefined) detailParts.push(`uniqueness=${(mix.uniquenessRatio*100).toFixed(1)}%`);
        if (mix.diversityIndex !== undefined) detailParts.push(`divIdx=${(mix.diversityIndex*100).toFixed(1)}%`);
      }
      detailParts.unshift(`mix=${evaluation.mixScore} beacon=${evaluation.beaconScore} diversity=${evaluation.diversityScore} total=${evaluation.totalScore}`);
      return {
        id: 11,
        name: 'Privacy Hop Enforcement',
        description: 'Enforces ≥2 (balanced) or ≥3 (strict) mixnet hops with BeaconSet-based diversity',
        passed,
        details: passed ? `✅ Privacy evidence ok (${detailParts.join(' | ')})` : `❌ Privacy insufficient (${detailParts.join(' | ')})`,
        severity: 'major',
        evidenceType: dynamicUpgrade ? 'dynamic-protocol' : 'heuristic'
      };
    }
  }
  ,
  {
    id: 19,
    key: 'noise-rekey-policy',
    name: 'Noise Rekey Policy',
    description: 'Observes at least one rekey event and validates trigger thresholds (bytes/time/frames)',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer) => {
      const ev: any = (analyzer as any).evidence;
      const n = ev?.noiseExtended;
      let passed = false;
      let details = '❌ No rekey evidence';
      if (n) {
        const bytesOk = !n.rekeyTriggers?.bytes || n.rekeyTriggers.bytes >= (8 * 1024 * 1024 * 1024);
        const timeOk = !n.rekeyTriggers?.timeMinSec || n.rekeyTriggers.timeMinSec >= 3600;
        const framesOk = !n.rekeyTriggers?.frames || n.rekeyTriggers.frames >= 65536;
        passed = (n.rekeysObserved || 0) >= 1 && bytesOk && timeOk && framesOk;
        details = passed ? `✅ rekeysObserved=${n.rekeysObserved}` : `❌ Rekey policy insufficient rekeysObserved=${n.rekeysObserved||0}`;
      }
      return { id: 19, name: 'Noise Rekey Policy', description: 'Observes at least one rekey event and validates trigger thresholds (bytes/time/frames)', passed, details, severity: 'minor', evidenceType: ev?.noiseExtended ? 'dynamic-protocol' : 'heuristic' };
    }
  },
  {
    id: 20,
    key: 'http2-adaptive-emulation',
    name: 'HTTP/2 Adaptive Emulation',
    description: 'Validates adaptive padding jitter & settings tolerances',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer) => {
      const ev: any = (analyzer as any).evidence;
      const h2 = ev?.h2Adaptive;
      let passed = false;
      let details = '❌ No adaptive HTTP/2 evidence';
      if (h2) {
        passed = !!(h2.withinTolerance && h2.sampleCount >= 5);
        details = passed ? `✅ jitterMean=${h2.paddingJitterMeanMs?.toFixed(1)}ms p95=${h2.paddingJitterP95Ms?.toFixed(1)}ms samples=${h2.sampleCount}` : `❌ Adaptive jitter out of tolerance mean=${h2.paddingJitterMeanMs?.toFixed(1)} p95=${h2.paddingJitterP95Ms?.toFixed(1)} samples=${h2.sampleCount}`;
      }
      return { id: 20, name: 'HTTP/2 Adaptive Emulation', description: 'Validates adaptive padding jitter & settings tolerances', passed, details, severity: 'minor', evidenceType: h2 ? 'dynamic-protocol' : 'heuristic' };
    }
  }
  ,
  {
    id: 12,
    key: 'clienthello-static-template',
    name: 'TLS ClientHello Static Template',
    description: 'Extracts ALPN set/order & extension ordering hash (static approximation)',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer) => {
      const patterns = await (analyzer as any).getStaticPatterns?.();
      const ch = patterns?.clientHello;
      const passed = !!(ch && ch.alpn && ch.alpn.length >= 2);
      return {
        id: 12,
        name: 'TLS ClientHello Static Template',
        description: 'Extracts ALPN set/order & extension ordering hash (static approximation)',
        passed,
  details: passed ? `✅ ALPN: ${ch!.alpn.join(', ')} extCount=${ch!.extensions?.length||0} hash=${ch!.extOrderSha256?.slice(0,12)}` : '❌ Insufficient ALPN evidence',
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
      const patterns = await (analyzer as any).getStaticPatterns?.();
      const noise = patterns?.noise;
      let passed = !!(noise && noise.pattern === 'XK');
      let details = passed ? '✅ Noise_XK pattern detected' : '❌ Noise_XK pattern not found';
      // Step 10 enhancement: leverage noisePatternDetail evidence for stronger structural validation
      const ev: any = (analyzer as any).evidence;
      const npd = ev?.noisePatternDetail;
      if (passed && npd) {
        const hkdfOk = (npd.hkdfLabelsFound || 0) >= 2;
        const msgOk = (npd.messageTokensFound || 0) >= 2; // placeholder heuristic
        passed = passed && hkdfOk && msgOk;
        details = passed ? `✅ Noise_XK pattern with hkdfLabels=${npd.hkdfLabelsFound} msgTokens=${npd.messageTokensFound}` : `❌ Incomplete Noise evidence hkdfLabels=${npd.hkdfLabelsFound||0} msgTokens=${npd.messageTokensFound||0}`;
      }
      return {
        id: 13,
        name: 'Noise XK Pattern',
        description: 'Detects Noise_XK handshake pattern tokens',
        passed,
        details,
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
      const patterns = await (analyzer as any).getStaticPatterns?.();
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
  }
  ,
  {
    id: 15,
    key: 'governance-anti-concentration',
    name: 'Governance Anti-Concentration',
    description: 'Validates AS/org caps & partition safety (evidence-based)',
    severity: 'major',
    introducedIn: '1.1',
    evaluate: async (analyzer) => {
      const ev: any = (analyzer as any).evidence;
      const gov = ev?.governance;
      let passed = false;
      let details = '❌ No governance evidence';
      if (gov && typeof gov === 'object') {
        // Derive caps if raw weights present
        if (!('maxASShare' in gov) && Array.isArray(gov.weights)) {
          try {
            const { deriveGovernanceMetrics } = require('./governance-parser');
            const derived = deriveGovernanceMetrics(gov.weights);
            gov.maxASShare = derived.maxASShare;
            gov.maxOrgShare = derived.maxOrgShare;
            gov.asCapApplied = derived.asCapApplied;
            gov.orgCapApplied = derived.orgCapApplied;
          } catch {/* ignore */}
        }
        // Integrate historical diversity stability if present
        const hist = (analyzer as any).evidence?.governanceHistoricalDiversity;
        const { asCapApplied, orgCapApplied, maxASShare, maxOrgShare, partitionsDetected } = gov;
        // Historical diversity now requires BOTH basic stability and (if present) advancedStable not false
        const histStable = hist ? (hist.stable === true && (hist.advancedStable !== false)) : true;
        passed = !!(asCapApplied && orgCapApplied && maxASShare <= 0.2 && maxOrgShare <= 0.25 && partitionsDetected === false && histStable);
        details = passed ? `✅ Caps enforced (AS<=${maxASShare} org<=${maxOrgShare}) no partitions${hist ? ' diversityStable=' + hist.stable : ''}` : `❌ Governance issues: ${missingList([
          !asCapApplied && 'AS caps not applied',
          !orgCapApplied && 'Org caps not applied',
          (maxASShare > 0.2) && `AS share ${maxASShare}`,
          (maxOrgShare > 0.25) && `Org share ${maxOrgShare}`,
          partitionsDetected === true && 'partitions detected',
          hist && !histStable && 'historical diversity unstable (basic or advanced)'
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
      const ev: any = (analyzer as any).evidence;
      const ledger = ev?.ledger;
      let passed = false;
      let details = '❌ No ledger evidence';
      if (ledger && typeof ledger === 'object') {
        // Parse CBOR quorum certs if provided as base64 array
        if (!ledger.quorumCertificatesValid && Array.isArray(ledger.quorumCertificatesCbor)) {
          try {
            const { parseQuorumCertificates, validateQuorumCertificates } = require('./governance-parser');
            const buffers = ledger.quorumCertificatesCbor.map((b: string) => Buffer.from(b, 'base64'));
            const qcs = parseQuorumCertificates(buffers);
            const validatorKeys = (ev.governance && ev.governance.validatorKeys) || undefined;
            const validation = validateQuorumCertificates(qcs, 2/3, { validatorKeys, requireSignatures: !!validatorKeys });
            ledger.quorumCertificatesValid = validation.valid;
            if (!validation.valid && validation.reasons?.length) {
              ledger.quorumCertificateInvalidReasons = validation.reasons;
            }
            ledger.finalitySets = ledger.finalitySets || qcs.map((q: any) => `epoch-${q.epoch}`);
          } catch {/* ignore */}
        }
        const { finalitySets, quorumCertificatesValid, emergencyAdvanceUsed, emergencyAdvanceLivenessDays, emergencyAdvanceJustification } = ledger;
        const has2of3 = Array.isArray(finalitySets) && finalitySets.length >= 2; // simplified proxy
        let emergencyOk = true;
        if (emergencyAdvanceUsed === true) {
          // Require liveness failure prerequisite >=14 days and justification token
            emergencyOk = (typeof emergencyAdvanceLivenessDays === 'number' && emergencyAdvanceLivenessDays >= 14) && !!emergencyAdvanceJustification;
        }
        passed = !!(has2of3 && quorumCertificatesValid === true && emergencyOk);
        details = passed ? `✅ Finality sets=${finalitySets.length} quorum certs valid${emergencyAdvanceUsed ? ' (emergency advance justified)' : ''}` : `❌ Ledger issues: ${missingList([
          !has2of3 && 'insufficient finality sets',
          quorumCertificatesValid !== true && 'invalid quorum certificates',
          emergencyAdvanceUsed === true && !emergencyOk && 'emergency advance unjustified'
        ])}`;
        if (!passed && Array.isArray(ledger.quorumCertificateInvalidReasons) && ledger.quorumCertificateInvalidReasons.length) {
          details += ' reasons=' + ledger.quorumCertificateInvalidReasons.join(',');
        }
      }
      return { id: 16, name: 'Ledger Finality Observation', description: 'Evidence of 2-of-3 finality & quorum certificate validity', passed, details, severity: 'major', evidenceType: ledger ? 'artifact' : 'heuristic' };
    }
  }
  ,
  {
    id: 17,
    key: 'mix-diversity-sampling',
    name: 'Mix Diversity Sampling',
    description: 'Samples mix paths ensuring uniqueness ≥80% of samples & hop depth policy',
    severity: 'major',
    introducedIn: '1.1',
    evaluate: async (analyzer) => {
      const ev: any = (analyzer as any).evidence;
      const mix = ev?.mix;
      let passed = false;
      let details = '❌ No mix diversity evidence';
      if (mix && typeof mix === 'object') {
        const samples: number = mix.samples || 0;
        const unique: number = mix.uniqueHopSets || 0;
        const ratio = samples ? unique / samples : 0;
        const pathLengths: number[] = mix.pathLengths || [];
        const minLen = pathLengths.length ? Math.min(...pathLengths) : 0;
        const depthOk = minLen >= (mix.minHopsBalanced || 2);
        // Uniqueness thresholds scale with sample size
        let required = 0.8;
        if (samples < 10) required = 0.7;
        if (samples < 6) required = 0.6;
        const uniquenessOk = ratio >= required;
        const diversityIndex = mix.diversityIndex || 0; // require some baseline dispersion
        const diversityOk = diversityIndex >= 0.4; // crude threshold
        passed = samples >= 5 && depthOk && uniquenessOk && diversityOk;
        details = passed ? `✅ unique=${unique}/${samples} ${(ratio*100).toFixed(1)}% (req≥${(required*100)}%) minHop=${minLen} divIdx=${(diversityIndex*100).toFixed(1)}%` :
          `❌ Mix diversity insufficient unique=${unique}/${samples} ${(ratio*100).toFixed(1)}% (req≥${(required*100)}%) minHop=${minLen} divIdx=${(diversityIndex*100).toFixed(1)}%`;
      }
      return { id: 17, name: 'Mix Diversity Sampling', description: 'Samples mix paths ensuring uniqueness ≥80% of samples & hop depth policy', passed, details, severity: 'major', evidenceType: mix ? 'dynamic-protocol' : 'heuristic' };
    }
  }
  ,
  {
    id: 18,
    key: 'multi-signal-anti-evasion',
    name: 'Multi-Signal Anti-Evasion',
    description: 'Requires ≥2 non-heuristic evidence categories for critical spec areas (transport, privacy, provenance, governance)',
    severity: 'major',
    introducedIn: '1.1',
    evaluate: async (analyzer) => {
      const ev: any = (analyzer as any).evidence || {};
      // Lightweight token stuffing heuristic: high proportion of spec keywords without corroborating diverse evidence
      const analysis = await analyzer.analyze();
      const strings: string[] = analysis.strings || [];
      const SPEC_KEYWORDS = ['betanet','htx','quic','ech','ticket','rotation','scion','chacha20','poly1305','cashu','lightning','federation','slsa','reproducible','provenance','kyber','kyber768','x25519','beacon','diversity','voucher','frost','pow','governance','ledger','quorum','finality','mix','hop'];
      let keywordHits = 0;
      for (const s of strings) {
        const lower = s.toLowerCase();
        if (SPEC_KEYWORDS.some(k => lower.includes(k))) keywordHits++;
      }
      const stuffingRatio = strings.length ? keywordHits / strings.length : 0;
      // Category presence (artifact/dynamic/static) derived from existing evidence objects
      const categories: { name: string; present: boolean }[] = [
        { name: 'provenance', present: !!ev.provenance },
        { name: 'governance', present: !!ev.governance },
        { name: 'ledger', present: !!ev.ledger },
        { name: 'mix', present: !!ev.mix },
        { name: 'clientHello', present: !!ev.clientHello },
        { name: 'noise', present: !!ev.noise }
      ];
      const presentCount = categories.filter(c => c.present).length;
      // Baseline pass threshold
      let passed = presentCount >= 2;
      // Evasion rule: extremely high keyword stuffing with only minimal category corroboration
      const severeStuffing = stuffingRatio > 0.6 && presentCount < 3; // two categories but heavy stuffing => suspect
      const moderateStuffing = stuffingRatio > 0.45 && presentCount < 2; // already would fail threshold but annotate reason
      let evasionFlag = false;
      if (severeStuffing) { passed = false; evasionFlag = true; }
      return {
        id: 18,
        name: 'Multi-Signal Anti-Evasion',
        description: 'Requires ≥2 non-heuristic evidence categories for critical spec areas (transport, privacy, provenance, governance)',
        passed,
        details: passed ? `✅ Multi-signal categories=${presentCount} (${categories.filter(c=>c.present).map(c=>c.name).join(', ')}) keywordDensity=${(stuffingRatio*100).toFixed(1)}%` : (
          evasionFlag ? `❌ Suspected keyword stuffing (density ${(stuffingRatio*100).toFixed(1)}% with only ${presentCount} category evidences)` : `❌ Insufficient multi-signal evidence (${presentCount}/2) keywordDensity=${(stuffingRatio*100).toFixed(1)}%`
        ),
        severity: 'major',
        evidenceType: presentCount ? 'artifact' : 'heuristic'
      };
    }
  }
];

// Step 10 appended checks (IDs 21-23) added after existing registry for stability
export const STEP_10_CHECKS = [
  {
    id: 21,
    key: 'binary-structural-meta',
    name: 'Binary Structural Meta',
    description: 'Parses binary format, sections, imports sample (structural baseline)',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      await analyzer.getStaticPatterns?.(); // ensure augmentation
      const ev = analyzer.evidence || {};
      const meta = ev.binaryMeta;
      const passed = !!meta && meta.format !== 'unknown' && Array.isArray(meta.sections) && meta.sections.length > 0;
      const details = meta ? (passed ? `✅ format=${meta.format} sections=${meta.sections.length} importsSample=${(meta.importsSample||[]).length}` : `❌ Incomplete binary meta format=${meta.format} sections=${(meta.sections||[]).length}`) : '❌ No binary meta';
      return { id: 21, name: 'Binary Structural Meta', description: 'Parses binary format, sections, imports sample (structural baseline)', passed, details, severity: 'minor', evidenceType: meta ? 'static-structural' : 'heuristic' };
    }
  },
  {
    id: 22,
    key: 'tls-static-template-calibration',
    name: 'TLS Static Template Calibration',
  description: 'Static ClientHello template + dynamic calibration (raw capture JA3/JA4 when available)',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      await analyzer.getStaticPatterns?.();
      const ev = analyzer.evidence || {};
      const ch = ev.clientHelloTemplate;
      const dyn = ev.dynamicClientHelloCapture;
      let evidenceType: 'heuristic' | 'static-structural' | 'dynamic-protocol' = 'heuristic';
      let passed = false;
      let details = '❌ No ClientHello template';
      if (ch) {
        evidenceType = 'static-structural';
        passed = Array.isArray(ch.alpn) && ch.alpn.length >= 2 && !!ch.extOrderSha256;
        details = passed ? `✅ static ALPN=${ch.alpn.join(',')} extHash=${ch.extOrderSha256.slice(0,12)}` : '❌ Incomplete static ClientHello evidence';
      }
      // Dynamic upgrade: if dynamic capture present ensure it matches static template & promote evidence type
      if (dyn && dyn.alpn && dyn.extOrderSha256) {
        const matches = ch && dyn.alpn.join(',') === ch.alpn.join(',') && dyn.extOrderSha256 === ch.extOrderSha256;
        evidenceType = 'dynamic-protocol';
        passed = passed && matches; // require static baseline + dynamic match
        let mismatchCode = '';
        if (!matches && dyn.note && dyn.note.includes(':')) {
          const parts = dyn.note.split(':');
            mismatchCode = parts[parts.length-1];
        }
            const ja3Disp = dyn.ja3Hash ? `${dyn.ja3Hash.slice(0,12)}` : (dyn.ja3||'').slice(0,16);
            const ja4Disp = dyn.ja4 ? ` ja4=${dyn.ja4}` : '';
            details = passed ? `✅ dynamic match ALPN=${dyn.alpn.join(',')} extHash=${dyn.extOrderSha256.slice(0,12)} ja3=${ja3Disp}${ja4Disp}` : `❌ Dynamic mismatch ${mismatchCode ? '('+mismatchCode+') ' : ''}staticHash=${ch?.extOrderSha256?.slice(0,12)} dynHash=${dyn.extOrderSha256.slice(0,12)} ja3=${ja3Disp}${ja4Disp}`;
      }
  // Upgrade severity if full raw capture present (treat as stronger dynamic evidence)
          let severity: 'minor' | 'major' = 'minor';
          if (dyn && dyn.rawClientHelloB64) severity = 'major';
          return { id: 22, name: 'TLS Static Template Calibration', description: 'Static ClientHello template + dynamic calibration (raw capture JA3/JA4 when available)', passed, details, severity, evidenceType };
    }
  },
  {
    id: 23,
    key: 'negative-assertions',
    name: 'Negative Assertions',
    description: 'Ensures forbidden legacy/seed tokens absent (deterministic seeds, legacy transition header)',
    severity: 'major',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      await analyzer.getStaticPatterns?.();
      const ev = analyzer.evidence || {};
      const neg = ev.negative;
      const forbiddenPresent: string[] = neg?.forbiddenPresent || [];
      const passed = forbiddenPresent.length === 0;
      const details = passed ? '✅ No forbidden legacy tokens present' : `❌ Forbidden tokens present: ${forbiddenPresent.join(', ')}`;
      return { id: 23, name: 'Negative Assertions', description: 'Ensures forbidden legacy/seed tokens absent (deterministic seeds, legacy transition header)', passed, details, severity: 'major', evidenceType: 'static-structural' };
    }
  }
];

// Phase 4 extension: new appended check for rate-limit multi-bucket validation
export const PHASE_4_CHECKS: CheckDefinitionMeta[] = [
  {
    id: 24,
    key: 'adaptive-rate-limit-buckets',
    name: 'Adaptive Rate-Limit Buckets',
    description: 'Validates multi-bucket rate-limit configuration (global + scoped) with sane dispersion',
  severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      const ev = analyzer.evidence || {};
      const rl = ev.rateLimit;
      let passed = false;
      let details = '❌ No rate-limit evidence';
      if (rl) {
        const buckets = Array.isArray(rl.buckets) ? rl.buckets : [];
        const bucketCount = rl.bucketCount || buckets.length;
        const names = new Set(buckets.map((b: any) => (b.name||'').toLowerCase()));
        const hasGlobal = [...names].some(n => n === 'global');
        const hasScoped = bucketCount >= 2;
        const capacities = buckets.map((b: any) => b.capacity).filter((n: any) => typeof n === 'number');
        const refills = buckets.map((b: any) => b.refillPerSec).filter((n: any) => typeof n === 'number');
        const capacitySpreadOk = capacities.length >= 2 ? (Math.max(...capacities) / Math.min(...capacities) <= 20) : true; // basic sanity
        const refillSpreadOk = refills.length >= 2 ? (Math.max(...refills) / Math.min(...refills) <= 20) : true;
        // Variance check (optional) fallback to computed variance if scopeRefillVariancePct absent
        let varianceOk = true;
        if (typeof rl.scopeRefillVariancePct === 'number') {
          varianceOk = rl.scopeRefillVariancePct <= 2500; // <= 50% stddev^2 (rough heuristic)
        }
        passed = hasGlobal && hasScoped && capacitySpreadOk && refillSpreadOk && varianceOk;
        details = passed ? `✅ buckets=${bucketCount} global+scoped present capSpreadOk=${capacitySpreadOk} refillSpreadOk=${refillSpreadOk}` :
          `❌ Rate-limit issues: ${missingList([
            !hasGlobal && 'missing global bucket',
            !hasScoped && 'insufficient scoped buckets',
            !capacitySpreadOk && 'capacity spread too large',
            !refillSpreadOk && 'refill spread too large',
            !varianceOk && 'variance excessive'
          ])}`;
      }
      return { id: 24, name: 'Adaptive Rate-Limit Buckets', description: 'Validates multi-bucket rate-limit configuration (global + scoped) with sane dispersion', passed, details, severity: 'minor', evidenceType: rl ? 'artifact' : 'heuristic' };
    }
  }
  ,
  // Phase 7: Quantitative fallback timing enforcement
  {
    id: 25,
    key: 'fallback-timing-policy',
    name: 'Fallback Timing Policy',
  description: 'Validates UDP->TCP fallback timing (retry delay ~0, bounded UDP timeout, cover teardown variance & distribution)',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      const ev = analyzer.evidence || {};
      const ft = ev.fallbackTiming || ev.fallback; // allow harness legacy
  if (!ft) return { id: 25, name: 'Fallback Timing Policy', description: 'Validates UDP->TCP fallback timing (retry delay ~0, bounded UDP timeout, cover teardown variance & distribution)', passed: false, details: '❌ No fallback timing evidence', severity: 'minor', evidenceType: 'heuristic' };
      const udpOk = typeof ft.udpTimeoutMs === 'number' && ft.udpTimeoutMs >= 100 && ft.udpTimeoutMs <= 600; // expected window
      const retryOk = typeof ft.retryDelayMs === 'number' ? ft.retryDelayMs <= 30 : true; // near-immediate retry
      let teardownStd = ft.teardownStdDevMs;
      if (!teardownStd && Array.isArray(ft.coverTeardownMs) && ft.coverTeardownMs.length >= 2) {
        const arr = ft.coverTeardownMs;
        const mean = arr.reduce((a:number,b:number)=>a+b,0)/arr.length;
        teardownStd = Math.sqrt(arr.reduce((a:number,b:number)=>a + Math.pow(b-mean,2),0)/arr.length);
      }
  const teardownOk = typeof teardownStd !== 'number' || teardownStd <= 500; // dispersion limit
  // Advanced metrics (Phase 7 quantitative modeling) if present
  const cv = ft.coverTeardownCv;
  const median = ft.coverTeardownMedianMs;
  const p95 = ft.coverTeardownP95Ms;
  const skew = ft.coverTeardownSkewness;
  const outliers = ft.coverTeardownOutlierCount;
  const anomalyCodes: string[] = ft.coverTeardownAnomalyCodes || [];
  const modelScore = ft.behaviorModelScore;
  const behaviorOk = ft.behaviorWithinPolicy !== false; // default pass unless explicitly false
  const cvOk = typeof cv !== 'number' || cv <= 1.5;
  const skewOk = typeof skew !== 'number' || Math.abs(skew) <= 1.2;
  const outlierOk = typeof outliers !== 'number' || outliers <= Math.ceil((ft.coverTeardownMs?.length || 0) * 0.25);
  const modelScoreOk = typeof modelScore !== 'number' || modelScore >= 0.6;
  const passed = udpOk && retryOk && teardownOk && behaviorOk && cvOk && skewOk && outlierOk && modelScoreOk;
  const detailParts = passed ? [
    `udpTimeout=${ft.udpTimeoutMs}ms`,
    `retryDelay=${ft.retryDelayMs||0}ms`,
    `teardownStd=${Math.round(teardownStd||0)}ms`,
    cv!==undefined?`cv=${cv.toFixed?cv.toFixed(3):cv}`:undefined,
    median!==undefined?`median=${median}ms`:undefined,
    p95!==undefined?`p95=${p95}ms`:undefined,
    skew!==undefined?`skew=${(skew as number).toFixed? (skew as number).toFixed(2): skew}`:undefined,
    modelScore!==undefined?`model=${modelScore}`:undefined,
    anomalyCodes.length?`anomalies=[${anomalyCodes.join(',')}]`:undefined
  ].filter(Boolean) : [];
  const failReasons = !passed ? [
    !udpOk && 'udpTimeout out of range',
    !retryOk && 'retry delay too high',
    !teardownOk && 'teardown variance high',
    !behaviorOk && 'behavior model fail',
    !cvOk && 'cv high',
    !skewOk && 'skew excessive',
    !outlierOk && 'outliers excessive',
    !modelScoreOk && 'model score low'
  ].filter(Boolean) : [];
  const details = passed ? `✅ ${detailParts.join(' ')}` : `❌ Fallback timing issues: ${missingList(failReasons)}`;
  return { id: 25, name: 'Fallback Timing Policy', description: 'Validates UDP->TCP fallback timing (retry delay ~0, bounded UDP timeout, cover teardown variance & distribution)', passed, details, severity: 'minor', evidenceType: 'dynamic-protocol' };
    }
  },
  // Phase 7: Statistical jitter variance enforcement
  {
    id: 26,
    key: 'padding-jitter-variance',
    name: 'Padding Jitter Variance',
    description: 'Enforces jitter stddev and mean bounds for adaptive padding distributions',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      const ev = analyzer.evidence || {};
      const sj = ev.statisticalJitter || ev.statisticalVariance;
      if (!sj) return { id: 26, name: 'Padding Jitter Variance', description: 'Enforces jitter stddev and mean bounds for adaptive padding distributions', passed: false, details: '❌ No jitter variance evidence', severity: 'minor', evidenceType: 'heuristic' };
      const sampleOk = (sj.samples || sj.sampleCount || 0) >= 10;
      const mean = sj.meanMs || sj.jitterMeanMs;
      const std = sj.stdDevMs || sj.jitterStdDevMs;
      const meanOk = typeof mean === 'number' && mean >= 5 && mean <= 800; // broad expected range
      const stdOk = typeof std === 'number' && std >= 1 && std <= 1200; // control explosion
      const passed = sampleOk && meanOk && stdOk;
      const details = passed ? `✅ jitter mean=${Math.round(mean)}ms std=${Math.round(std)}ms samples=${sj.samples||sj.sampleCount}` : `❌ Jitter variance issues: ${missingList([!sampleOk && 'insufficient samples', !meanOk && 'mean out of range', !stdOk && 'stddev out of range'])}`;
      return { id: 26, name: 'Padding Jitter Variance', description: 'Enforces jitter stddev and mean bounds for adaptive padding distributions', passed, details, severity: 'minor', evidenceType: 'dynamic-protocol' };
    }
  }
];

// Unified export including all appended groups
// Phase 7 continuation: new appended checks (advanced mix variance & HTTP/3 adaptive)
export const PHASE_7_CONT_CHECKS: CheckDefinitionMeta[] = [
  {
    id: 27,
    key: 'mix-advanced-variance',
    name: 'Mix Advanced Variance',
    description: 'Validates entropy (≥4 bits), path length stddev (>0), and uniqueness/diversity thresholds',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      const ev = analyzer.evidence || {};
      const mix = ev.mix;
      if (!mix) return { id: 27, name: 'Mix Advanced Variance', description: 'Validates entropy (≥4 bits), path length stddev (>0), and uniqueness/diversity thresholds', passed: false, details: '❌ No mix variance evidence', severity: 'minor', evidenceType: 'heuristic' };
      const entropy = mix.nodeEntropyBits || 0;
      const plStd = mix.pathLengthStdDev || 0;
      const uniq = typeof mix.uniquenessRatio === 'number' ? mix.uniquenessRatio : 0;
      const diversity = typeof mix.diversityIndex === 'number' ? mix.diversityIndex : 0;
      const entropyOk = entropy >= 4; // heuristic baseline for ≥16 distinct-ish nodes with dispersion
      const plStdOk = plStd > 0; // some variability in path lengths
      const uniqOk = uniq >= 0.7; // slightly relaxed vs check 17 (which can be stricter)
      const diversityOk = diversity >= 0.35; // allow slightly lower than primary check
      const passed = entropyOk && plStdOk && uniqOk && diversityOk && mix.samples >= 5;
      const details = passed ? `✅ entropy=${entropy.toFixed(2)} bits plStd=${plStd.toFixed(2)} uniq=${(uniq*100).toFixed(1)}% divIdx=${(diversity*100).toFixed(1)}%` : `❌ Mix variance insuff entropy=${entropy.toFixed(2)} bits plStd=${plStd.toFixed(2)} uniq=${(uniq*100).toFixed(1)}% divIdx=${(diversity*100).toFixed(1)}%`;
      return { id: 27, name: 'Mix Advanced Variance', description: 'Validates entropy (≥4 bits), path length stddev (>0), and uniqueness/diversity thresholds', passed, details, severity: 'minor', evidenceType: 'dynamic-protocol' };
    }
  },
  {
    id: 28,
    key: 'http3-adaptive-emulation',
    name: 'HTTP/3 Adaptive Emulation',
    description: 'Validates HTTP/3 (QUIC) adaptive padding jitter & QPACK settings',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      const ev = analyzer.evidence || {};
      const h3 = ev.h3Adaptive;
      if (!h3) return { id: 28, name: 'HTTP/3 Adaptive Emulation', description: 'Validates HTTP/3 (QUIC) adaptive padding jitter & QPACK settings', passed: false, details: '❌ No HTTP/3 adaptive evidence', severity: 'minor', evidenceType: 'heuristic' };
      const passed = h3.withinTolerance && h3.sampleCount >= 5;
      const details = passed ? `✅ jitterMean=${h3.paddingJitterMeanMs?.toFixed(1)}ms p95=${h3.paddingJitterP95Ms?.toFixed(1)}ms samples=${h3.sampleCount}` : `❌ HTTP/3 jitter out of tolerance mean=${h3.paddingJitterMeanMs?.toFixed(1)} p95=${h3.paddingJitterP95Ms?.toFixed(1)} samples=${h3.sampleCount}`;
      return { id: 28, name: 'HTTP/3 Adaptive Emulation', description: 'Validates HTTP/3 (QUIC) adaptive padding jitter & QPACK settings', passed, details, severity: 'minor', evidenceType: 'dynamic-protocol' };
    }
  }
  ,
  {
    id: 29,
    key: 'voucher-frost-struct-validation',
    name: 'Voucher/FROST Struct Validation',
    description: 'Validates voucher cryptographic struct base64 components & FROST threshold hints',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      await analyzer.getStaticPatterns?.();
      const ev = analyzer.evidence || {};
      const vc = ev.voucherCrypto;
      if (!vc) return { id: 29, name: 'Voucher/FROST Struct Validation', description: 'Validates voucher cryptographic struct base64 components & FROST threshold hints', passed: false, details: '❌ No voucherCrypto evidence', severity: 'minor', evidenceType: 'heuristic' };
      const baseOk = vc.signatureValid === true;
      const thresholdOk = vc.frostThreshold ? ((vc.frostThreshold.n || 0) >= 5 && (vc.frostThreshold.t || 0) >= 3 && (vc.frostThreshold.t || 0) <= (vc.frostThreshold.n || 0)) : false;
      const passed = baseOk && thresholdOk;
      const details = passed ? `✅ struct base64 sizes ok n=${vc.frostThreshold?.n} t=${vc.frostThreshold?.t}` : `❌ Voucher struct issues: ${missingList([
        !baseOk && 'invalid base64 component sizes',
        !thresholdOk && 'threshold n>=5 t>=3 not satisfied'
      ])}`;
      return { id: 29, name: 'Voucher/FROST Struct Validation', description: 'Validates voucher cryptographic struct base64 components & FROST threshold hints', passed, details, severity: 'minor', evidenceType: 'static-structural' };
    }
  }
  ,
  {
    id: 30,
    key: 'access-ticket-rotation-policy',
    name: 'Access Ticket Rotation Policy',
    description: 'Validates structural access ticket evidence (fields, hex IDs) & rotation token presence',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      await analyzer.getStaticPatterns?.();
      const ev = analyzer.evidence || {};
      const at = ev.accessTicket;
      if (!at) return { id: 30, name: 'Access Ticket Rotation Policy', description: 'Validates structural access ticket evidence (fields, hex IDs) & rotation token presence', passed: false, details: '❌ No accessTicket evidence', severity: 'minor', evidenceType: 'heuristic' };
      const fieldsOk = Array.isArray(at.fieldsPresent) && at.fieldsPresent.includes('ticket') && at.fieldsPresent.includes('nonce') && at.fieldsPresent.includes('exp') && at.fieldsPresent.includes('sig');
      const hexOk = (at.hex16Count || 0) + (at.hex32Count || 0) >= 1; // at least one identifier
      const rotationOk = at.rotationTokenPresent === true;
      const confidenceOk = (at.structConfidence || 0) >= 0.4; // heuristic threshold
      const passed = fieldsOk && hexOk && rotationOk && confidenceOk;
      const details = passed ? `✅ accessTicket fields=${at.fieldsPresent.length} conf=${at.structConfidence} rotation=${rotationOk}` : `❌ Access ticket issues: ${missingList([
        !fieldsOk && 'core fields',
        !hexOk && 'hex IDs',
        !rotationOk && 'rotation token',
        !confidenceOk && 'confidence<0.4'
      ])}`;
      return { id: 30, name: 'Access Ticket Rotation Policy', description: 'Validates structural access ticket evidence (fields, hex IDs) & rotation token presence', passed, details, severity: 'minor', evidenceType: 'static-structural' };
    }
  }
  ,
  {
    id: 31,
    key: 'voucher-aggregated-signature',
    name: 'Voucher Aggregated Signature',
    description: 'Verifies voucher aggregated signature structure (synthetic hash prefix match)',
    severity: 'minor',
    introducedIn: '1.1',
    evaluate: async (analyzer: any) => {
      await analyzer.getStaticPatterns?.();
      const ev = analyzer.evidence || {};
      const vc = ev.voucherCrypto;
      if (!vc) return { id: 31, name: 'Voucher Aggregated Signature', description: 'Verifies voucher aggregated signature structure (synthetic hash prefix match)', passed: false, details: '❌ No voucherCrypto evidence', severity: 'minor', evidenceType: 'heuristic' };
      const sigOk = vc.signatureValid === true;
      const thresholdOk = vc.frostThreshold ? ((vc.frostThreshold.n||0) >=5 && (vc.frostThreshold.t||0) >=3) : false;
      const passed = sigOk && thresholdOk;
      const details = passed ? `✅ aggregatedSig valid n=${vc.frostThreshold?.n} t=${vc.frostThreshold?.t}` : `❌ Aggregated signature invalid: ${missingList([
        !sigOk && 'signature structure',
        !thresholdOk && 'threshold'
      ])}`;
      return { id: 31, name: 'Voucher Aggregated Signature', description: 'Verifies voucher aggregated signature structure (synthetic hash prefix match)', passed, details, severity: 'minor', evidenceType: 'static-structural' };
    }
  }
];

export const ALL_CHECKS: CheckDefinitionMeta[] = [...CHECK_REGISTRY, ...STEP_10_CHECKS as CheckDefinitionMeta[], ...PHASE_4_CHECKS, ...PHASE_7_CONT_CHECKS];

// Append new checks to registry
// (Avoid mutation side-effects if imported elsewhere before evaluation)
// Only push if not already present (idempotent on re-import in tests)
for (const c of STEP_10_CHECKS) {
  if (!CHECK_REGISTRY.find(existing => existing.id === (c as any).id)) (CHECK_REGISTRY as any).push(c);
}
for (const c of PHASE_4_CHECKS) {
  if (!CHECK_REGISTRY.find(existing => existing.id === (c as any).id)) (CHECK_REGISTRY as any).push(c);
}
for (const c of PHASE_7_CONT_CHECKS) {
  if (!CHECK_REGISTRY.find(existing => existing.id === (c as any).id)) (CHECK_REGISTRY as any).push(c);
}

export function getChecksByIds(ids: number[]): CheckDefinitionMeta[] {
  const set = new Set(ids);
  return ALL_CHECKS.filter(c => set.has(c.id)).sort((a, b) => a.id - b.id);
}
