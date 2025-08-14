import * as fs from 'fs-extra';
import * as path from 'path';
import { BetanetComplianceChecker } from '../src';

// Helper to build a mock analyzer with supplied evidence
function buildMockAnalyzer(staticTemplate: { alpn: string[]; extOrderSha256: string }, dynamic: any, extraEvidence: Record<string, any> = {}) {
  return {
    checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true }),
    analyze: () => Promise.resolve({ strings: ['h2','http/1.1','clienthello'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86_64', size: 1 }),
    checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasX25519: true, hasKyber768: true }),
    checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false, pathDiversityCount: 2 }),
    checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: true, seedManagement: true }),
    checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
    checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true }),
    checkBuildProvenance: () => Promise.resolve({ hasSLSA: true, reproducible: true, provenance: true }),
    getStaticPatterns: async () => ({ clientHello: staticTemplate }),
    evidence: { clientHelloTemplate: staticTemplate, dynamicClientHelloCapture: dynamic, ...extraEvidence }
  } as any;
}

async function runCheck(evidence: { static: { alpn: string[]; extOrderSha256: string }; dynamic: any; extra?: Record<string,any> }) {
  const checker = new BetanetComplianceChecker();
  const tmp = path.join(__dirname, 'temp-calibration-bin');
  await fs.writeFile(tmp, Buffer.from('binary calibration test'));
  (checker as any)._analyzer = buildMockAnalyzer(evidence.static, evidence.dynamic, evidence.extra || {});
  const result = await checker.checkCompliance(tmp, { allowHeuristic: true });
  await fs.remove(tmp);
  return result.checks.find(c => c.id === 22)!;
}

describe('TLS Static Template Calibration (Check 22) mismatch codes', () => {
  const baseStatic = { alpn: ['h2','http/1.1'], extOrderSha256: 'cafebabe1234' };
  const baseDynamic = { alpn: ['h2','http/1.1'], extOrderSha256: 'cafebabe1234', ja3: '771,1-2,1-2,1-2,', ja3Hash: 'deadbeefdeadbeefdeadbeefdeadbeef', ja3Canonical: '771,1-2,1-2,1-2,', ja4: 'TLSH-2a-2e-1c-0g', rawClientHelloB64: 'AA==' };

  it('passes when dynamic matches static template', async () => {
    const check = await runCheck({ static: baseStatic, dynamic: baseDynamic });
    expect(check.passed).toBe(true);
    expect(check.evidenceType).toBe('dynamic-protocol');
    expect(check.details).toMatch(/dynamic match/);
  });

  it('detects ALPN_ORDER_MISMATCH', async () => {
    const dyn = { ...baseDynamic, alpn: ['http/1.1','h2'] }; // order flipped
    const check = await runCheck({ static: baseStatic, dynamic: dyn });
    expect(check.passed).toBe(false);
    expect(check.details).toMatch(/ALPN_ORDER_MISMATCH/);
  });

  it('detects EXT_SEQUENCE_MISMATCH', async () => {
    const dyn = { ...baseDynamic, extOrderSha256: 'badd00d12345' };
    const check = await runCheck({ static: baseStatic, dynamic: dyn });
    expect(check.passed).toBe(false);
    expect(check.details).toMatch(/EXT_SEQUENCE_MISMATCH/);
  });

  it('detects JA3_HASH_MISMATCH', async () => {
    const dyn = { ...baseDynamic, ja3Canonical: '771,9-9,9-9,9-9,' }; // different canonical vs ja3
    const check = await runCheck({ static: baseStatic, dynamic: dyn });
    expect(check.passed).toBe(false);
    expect(check.details).toMatch(/JA3_HASH_MISMATCH/);
  });

  it('detects JA4_CLASS_MISMATCH', async () => {
    const dyn = { ...baseDynamic, ja4: 'TLSH-5a-2e-1c-0g' }; // claims 5 ALPN entries
    const check = await runCheck({ static: baseStatic, dynamic: dyn });
    expect(check.passed).toBe(false);
    expect(check.details).toMatch(/JA4_CLASS_MISMATCH/);
  });

  it('detects SETTINGS_DRIFT', async () => {
    const dyn = { ...baseDynamic };
    const extra = { h2Adaptive: { settings: { INITIAL_WINDOW_SIZE: 1000, MAX_FRAME_SIZE: 42 } } }; // out-of-range
    const check = await runCheck({ static: baseStatic, dynamic: dyn, extra });
    expect(check.passed).toBe(false);
    expect(check.details).toMatch(/SETTINGS_DRIFT/);
  });

  it('detects POP_MISMATCH', async () => {
    const staticWithPop = { ...baseStatic, popId: 'pop-a' } as any;
    const dyn = { ...baseDynamic, popId: 'pop-b' };
    const check = await runCheck({ static: staticWithPop, dynamic: dyn });
    expect(check.passed).toBe(false);
    expect(check.details).toMatch(/POP_MISMATCH/);
  });

  it('accepts SETTINGS within ±15% tolerance', async () => {
    const dyn = { ...baseDynamic };
    // 10% increase still within tolerance window
    const extra = { h2Adaptive: { settings: { INITIAL_WINDOW_SIZE: Math.round(6291456 * 1.10), MAX_FRAME_SIZE: Math.round(16384 * 0.90) } } };
    const check = await runCheck({ static: baseStatic, dynamic: dyn, extra });
    expect(check.passed).toBe(true);
  });
});
