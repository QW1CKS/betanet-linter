import * as fs from 'fs-extra';
import * as path from 'path';
import { BetanetComplianceChecker } from '../src';

/**
 * Integration test for Task 1 (Raw TLS/QUIC Capture & Calibration Engine)
 * Simulates a golden baseline evidence vs perturbed mismatch cases in a single run.
 */

describe('Integration: TLS Calibration golden vs perturbed', () => {
  jest.setTimeout(15000);

  const staticTemplate = { alpn: ['h2','http/1.1'], extOrderSha256: 'cafebabe1234' };
  const goldenDynamic = { alpn: ['h2','http/1.1'], extOrderSha256: 'cafebabe1234', ja3: '771,1-2,1-2,1-2,', ja3Hash: 'deadbeefdeadbeefdeadbeefdeadbeef', ja3Canonical: '771,1-2,1-2,1-2,', ja4: 'TLSH-2a-2e-1c-0g', rawClientHelloB64: 'AA==' };

  function mkAnalyzer(dynamic: any, extra: Record<string,any> = {}) {
    return {
      checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true }),
      analyze: () => Promise.resolve({ strings: ['h2','http/1.1','clienthello'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86_64', size: 1 }),
      checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasX25519: true, hasKyber768: true }),
      checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false }),
      checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: true, seedManagement: true }),
      checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
      checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true }),
      checkBuildProvenance: () => Promise.resolve({ hasSLSA: true, reproducible: true, provenance: true }),
      getStaticPatterns: async () => ({ clientHello: staticTemplate }),
      evidence: { clientHelloTemplate: staticTemplate, dynamicClientHelloCapture: dynamic, ...extra }
    } as any;
  }

  async function run(dynamic: any, extra?: Record<string,any>) {
    const checker = new BetanetComplianceChecker();
    const tmp = path.join(__dirname, 'temp-integ-bin');
    await fs.writeFile(tmp, Buffer.from('integration binary'));
    (checker as any)._analyzer = mkAnalyzer(dynamic, extra || {});
    const result = await checker.checkCompliance(tmp, { allowHeuristic: true });
    await fs.remove(tmp);
    return result.checks.find(c => c.id === 22)!;
  }

  it('golden fixture passes', async () => {
    const check = await run(goldenDynamic);
    expect(check.passed).toBe(true);
  });

  it('perturbed ALPN order fails', async () => {
    const check = await run({ ...goldenDynamic, alpn: ['http/1.1','h2'] });
    expect(check.passed).toBe(false);
    expect(check.details).toMatch(/ALPN_ORDER_MISMATCH/);
  });

  it('perturbed extension hash fails', async () => {
    const check = await run({ ...goldenDynamic, extOrderSha256: 'badd00d12345' });
    expect(check.passed).toBe(false);
    expect(check.details).toMatch(/EXT_SEQUENCE_MISMATCH/);
  });
});
