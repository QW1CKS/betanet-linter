// Central registry of Betanet compliance checks (Plan 3 consolidation)
// Each check definition contains metadata & an evaluator that derives result from the BinaryAnalyzer.
// This replaces ad-hoc per-check methods and normalizes naming & severities.

import { BinaryAnalyzer } from './analyzer';
import { TRANSPORT_ENDPOINT_VERSIONS, OPTIONAL_TRANSPORTS, POST_QUANTUM_MANDATORY_DATE } from './constants';
import { ComplianceCheck } from './types';

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

// Helper to assemble missing list strings
function missingList(parts: Array<string | false>): string {
  return parts.filter(Boolean).join(', ');
}

export const CHECK_REGISTRY: CheckDefinitionMeta[] = [
  {
    id: 1,
    key: 'htx-transports-tls-ech',
    name: 'HTX over TCP-443 & QUIC-443',
    description: 'Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH',
    severity: 'critical',
    introducedIn: '1.0',
    evaluate: async (analyzer) => {
      const networkCaps = await analyzer.checkNetworkCapabilities();
      const passed = networkCaps.hasTLS && networkCaps.hasQUIC && networkCaps.hasHTX && networkCaps.hasECH && networkCaps.port443;
      return {
        id: 1,
        name: 'HTX over TCP-443 & QUIC-443',
        description: 'Implements HTX over TCP-443 and QUIC-443 with TLS 1.3 mimic + ECH',
        passed,
        details: passed ? '✅ Found HTX, QUIC, TLS, ECH, and port 443 support' : `❌ Missing: ${missingList([
          !networkCaps.hasTLS && 'TLS',
          !networkCaps.hasQUIC && 'QUIC',
          !networkCaps.hasHTX && 'HTX',
          !networkCaps.hasECH && 'ECH',
          !networkCaps.port443 && 'port 443'
        ])}`,
        severity: 'critical'
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
        severity: 'major'
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
        severity: 'critical'
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
    evaluate: async (analyzer) => {
      const scionSupport = await analyzer.checkSCIONSupport();
      const passed = scionSupport.hasSCION && (scionSupport.pathManagement || scionSupport.hasIPTransition);
      return {
        id: 4,
        name: 'SCION Path Management',
        description: 'Maintains ≥ 3 signed SCION paths or attaches a valid IP-transition header',
        passed,
        details: passed ? '✅ Found SCION support with path management or IP-transition' : `❌ Missing: ${missingList([
          !scionSupport.hasSCION && 'SCION support',
          !scionSupport.pathManagement && 'path management',
          !scionSupport.hasIPTransition && 'IP-transition header'
        ])}`,
        severity: 'critical'
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
        severity: 'major'
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
    evaluate: async (analyzer) => {
      const dhtSupport = await analyzer.checkDHTSupport();
      const passed = !!(dhtSupport.hasDHT && (dhtSupport.deterministicBootstrap || dhtSupport.rendezvousRotation));
      return {
        id: 6,
        name: 'DHT Seed Bootstrap',
        description: 'Implements deterministic (1.0) or rotating rendezvous (1.1) DHT seed bootstrap',
        passed,
        details: passed ? `✅ Found DHT with ${dhtSupport.rendezvousRotation ? 'rotating rendezvous' : 'deterministic'} bootstrap` +
          (dhtSupport.beaconSetIndicator ? ' (BeaconSet evidence)' : '') :
          `❌ Missing: ${missingList([
            !dhtSupport.hasDHT && 'DHT support',
            !(dhtSupport.deterministicBootstrap || dhtSupport.rendezvousRotation) && 'deterministic or rendezvous bootstrap'
          ])}`,
        severity: 'major'
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
        severity: 'major'
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
          `❌ Missing: ${missingList([
            !paymentSupport.hasCashu && 'Cashu support',
            !paymentSupport.hasLightning && 'Lightning support',
            !paymentSupport.hasFederation && 'federation support'
          ])}`,
        severity: 'major'
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
    evaluate: async (analyzer) => {
      const buildInfo = await analyzer.checkBuildProvenance();
      const passed = buildInfo.hasSLSA && buildInfo.reproducible && buildInfo.provenance;
      return {
        id: 9,
        name: 'Build Provenance',
        description: 'Builds reproducibly and publishes SLSA 3 provenance',
        passed,
        details: passed ? '✅ Found SLSA, reproducible builds, and provenance' : `❌ Missing: ${missingList([
          !buildInfo.hasSLSA && 'SLSA support',
          !buildInfo.reproducible && 'reproducible builds',
          !buildInfo.provenance && 'build provenance'
        ])}`,
        severity: 'minor'
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
      const mandatoryDate = new Date(POST_QUANTUM_MANDATORY_DATE);
      const isPastMandatoryDate = now >= mandatoryDate;
      let passed = true;
      let details = '✅ Post-quantum requirements not yet mandatory';
      let severity: 'minor' | 'critical' = 'minor';
      if (isPastMandatoryDate) {
        severity = 'critical';
        passed = cryptoCaps.hasX25519 && cryptoCaps.hasKyber768;
        details = passed ? '✅ Found X25519-Kyber768 hybrid cipher suite' : `❌ Missing: ${missingList([
          !cryptoCaps.hasX25519 && 'X25519',
          !cryptoCaps.hasKyber768 && 'Kyber768'
        ])} (mandatory after ${POST_QUANTUM_MANDATORY_DATE})`;
      }
      return {
        id: 10,
        name: 'Post-Quantum Cipher Suites',
        description: 'Presents X25519-Kyber768 suites once the mandatory date is reached',
        passed,
        details,
        severity
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
    evaluate: async (analyzer) => {
      const analysis = await analyzer.analyze();
      const lower = analysis.strings.map((s: string) => s.toLowerCase());
      const joined = lower.join(' ');
      // Token groups
      const mixTokens = ['nym', 'mix', 'mixnode', 'hop', 'hopset'];
      const beaconTokens = ['beaconset', 'epoch', 'drand'];
      const diversityTokens = ['diversity', 'distinct', 'as-group', 'asgroup'];

      const mixHits = mixTokens.filter(t => joined.includes(t));
      const beaconHits = beaconTokens.filter(t => joined.includes(t));
      const diversityHits = diversityTokens.filter(t => joined.includes(t));

      // Heuristic pass rule: at least 2 mix-related + 1 beacon/epoch + 1 diversity indicator
      const passed = mixHits.length >= 2 && beaconHits.length >= 1 && diversityHits.length >= 1;
      return {
        id: 11,
        name: 'Privacy Hop Enforcement',
        description: 'Enforces ≥2 (balanced) or ≥3 (strict) mixnet hops with BeaconSet-based diversity',
        passed,
        details: passed ? `✅ Found mixnet indicators: mix(${mixHits.join('/')}) beacon(${beaconHits.join('/')}) diversity(${diversityHits.join('/')})` :
          `❌ Missing: ${missingList([
            mixHits.length < 2 && '≥2 mix-related tokens',
            beaconHits.length < 1 && 'BeaconSet/epoch token',
            diversityHits.length < 1 && 'diversity indicator'
          ])}`,
        severity: 'major'
      };
    }
  }
];

export function getChecksByIds(ids: number[]): CheckDefinitionMeta[] {
  const set = new Set(ids);
  return CHECK_REGISTRY.filter(c => set.has(c.id)).sort((a, b) => a.id - b.id);
}
