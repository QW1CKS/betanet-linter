import * as fs from 'fs-extra';
import * as path from 'path';
import { BetanetComplianceChecker } from '../src';

function buildAnalyzer(echEvidence: any) {
  return {
    checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true }),
    analyze: () => Promise.resolve({ strings: ['ech','encrypted_client_hello','handshake'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86_64', size: 1 }),
    checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasX25519: true, hasKyber768: true }),
    checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false }),
    checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: true, seedManagement: true }),
    checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
    checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true }),
    checkBuildProvenance: () => Promise.resolve({ hasSLSA: true, reproducible: true, provenance: true }),
    evidence: { echVerification: echEvidence }
  } as any;
}

async function runECH(echEvidence: any) {
  const checker = new BetanetComplianceChecker();
  const tmp = path.join(__dirname, 'temp-ech-bin');
  await fs.writeFile(tmp, Buffer.from('ech test binary'));
  (checker as any)._analyzer = buildAnalyzer(echEvidence);
  const result = await checker.checkCompliance(tmp, { allowHeuristic: true });
  await fs.remove(tmp);
  return result.checks.find(c => c.id === 32)!;
}

describe('ECH Verification (Check 32)', () => {
  it('fails with no evidence', async () => {
    const checker = new BetanetComplianceChecker();
    const tmp = path.join(__dirname, 'temp-ech-bin2');
    await fs.writeFile(tmp, Buffer.from('no evidence binary'));
    (checker as any)._analyzer = buildAnalyzer(undefined);
    const result = await checker.checkCompliance(tmp, { allowHeuristic: true });
    await fs.remove(tmp);
    const ech = result.checks.find(c => c.id === 32)!;
    expect(ech.passed).toBe(false);
    expect(ech.details).toMatch(/No ECH verification evidence/);
  });

  it('fails when extension present but no certificate differential', async () => {
    const ech = await runECH({ extensionPresent: true, outerSni: 'example.com', innerSni: 'example.com', outerCertHash: 'abc', innerCertHash: 'abc', diffIndicators: [] });
    expect(ech.passed).toBe(false);
    expect(ech.details).toMatch(/no cert differential/);
  });

  it('passes with extension present and cert hash differential', async () => {
    const ech = await runECH({ extensionPresent: true, outerSni: 'public.example', innerSni: 'inner.hidden', outerCertHash: 'aaa111', innerCertHash: 'bbb222', certHashesDiffer: true, diffIndicators: ['cert-hash-diff'] });
    expect(ech.passed).toBe(true);
    expect(ech.evidenceType).toBe('dynamic-protocol');
    expect(ech.details).toMatch(/ECH accepted/);
  });

  it('fails when GREASE anomalies reported', async () => {
    const ech = await runECH({ extensionPresent: true, outerSni: 'a', innerSni: 'b', outerCertHash: 'x', innerCertHash: 'y', certHashesDiffer: true, greaseAbsenceObserved: false });
    expect(ech.passed).toBe(false);
    expect(ech.details).toMatch(/GREASE/);
  });
});
