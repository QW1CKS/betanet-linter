import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs-extra';
import * as path from 'path';

describe('Phase 4 bootstrap & PoW evolution', () => {
  const tmpBin = path.join(__dirname, 'temp-existing-bin');
  beforeAll(async () => {
    await fs.writeFile(tmpBin, Buffer.from('binary data ticket rotation /betanet/htx/1.0.0 /betanet/htxquic/1.0.0 dht rendezvous beaconset chacha20 poly1305 cashu lightning federation pow22'));
  });

  it('passes Check 6 with bootstrap evidence (rotating rendezvous)', async () => {
    const checker = new BetanetComplianceChecker();
    (checker as any)._analyzer = {
      checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true }),
  analyze: () => Promise.resolve({ strings: ['ticket','rotation','/betanet/htx/1.0.0','/betanet/htxquic/1.0.0','chacha20','poly1305','cashu','lightning','federation','dht','rendezvous','pow22'], symbols: [] }),
      checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasEd25519: true, hasX25519: true, hasKyber768: true, hasSHA256: true, hasHKDF: true }),
      checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false, pathDiversityCount: 2 }),
      checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: false, rendezvousRotation: true, beaconSetIndicator: true, seedManagement: true, rotationHits: 3 }),
      checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
      checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true }),
      checkBuildProvenance: () => Promise.resolve({ hasSLSA: true, reproducible: true, provenance: true })
    };
    // Inject bootstrap evidence
    const evidencePath = path.join(__dirname, 'temp-phase4-bootstrap.json');
    await fs.writeFile(evidencePath, JSON.stringify({ bootstrap: { rotationEpochs: 3, beaconSetEntropySources: 2, deterministicSeedDetected: false } }));
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check6 = result.checks.find(c => c.id === 6);
    expect(check6?.passed).toBe(true);
    expect(check6?.evidenceType).toBe('artifact');
  });

  it('fails Check 8 when PoW difficulty evolution is erratic', async () => {
    const checker = new BetanetComplianceChecker();
    (checker as any)._analyzer = {
      checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true }),
      analyze: () => Promise.resolve({ strings: ['ticket','rotation','/betanet/htx/1.0.0','/betanet/htxquic/1.0.0','chacha20','poly1305','cashu','lightning','federation','dht','rendezvous','pow22'], symbols: [] }),
      checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasEd25519: true, hasX25519: true, hasKyber768: true, hasSHA256: true, hasHKDF: true }),
      checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false, pathDiversityCount: 2 }),
  checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: true, seedManagement: true, rotationHits: 0 }),
      checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
      checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true }),
      checkBuildProvenance: () => Promise.resolve({ hasSLSA: true, reproducible: true, provenance: true })
    };
    const evidencePath = path.join(__dirname, 'temp-phase4-pow.json');
    // Erratic difficulty samples (big drop)
  await fs.writeFile(evidencePath, JSON.stringify({ powAdaptive: { difficultySamples: [22, 21, 15, 23], targetBits: 22 } }));
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check8 = result.checks.find(c => c.id === 8);
    expect(check8?.passed).toBe(false);
  expect(check8?.details).toMatch(/PoW evolution invalid/);
  });
});
