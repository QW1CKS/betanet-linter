

import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs-extra';
import * as path from 'path';

describe('Normative §11 Items Compliance', () => {
  const tmpBin = path.join(__dirname, 'temp-normative-bin');
  const evidencePath = path.join(__dirname, 'normative-items-fixture.json');
  beforeAll(async () => {
    // Write a binary containing all required tokens for heuristic checks
    await fs.writeFile(tmpBin, Buffer.from([
      'ticket', 'rotation', '/betanet/htx/1.1.0', '/betanet/htxquic/1.1.0',
      'Noise_XK', 'chacha20', 'poly1305', 'cashu', 'lightning', 'federation',
      'dht', 'rendezvous', 'beaconset', 'pow22', 'alias ledger', 'consensus', 'chain',
      'SCION', 'pathManagement', 'IPTransition', 'diversity', 'voucher', 'FROST', 'rateLimit',
  'governance', 'partition', 'fallback', 'UDP', 'TCP', 'cover', 'SLSA', 'provenance', 'reproducible',
  // Added tokens to satisfy check 1 (network capabilities: tls, quic, ech, port 443) and check 4 (SCION path diversity markers)
  'tls', 'quic', 'ech', '443', 'AS123', 'AS456'
  , '-> e,', '-> s,'
    ].join(' ')));
  });
  afterAll(async () => { await fs.remove(tmpBin); });

  it('HTX over TCP+QUIC with origin-mirrored TLS + calibration + ECH', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 1 || c.id === 22);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  it('Negotiated-carrier replay-bound access tickets', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 2 || c.id === 30);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  it('Noise XK inner tunnel, key separation, nonce lifecycle, rekey thresholds, PQ date', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 13 || c.id === 19);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  it('HTTP/2/3 adaptive emulation', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 4 || c.id === 20 || c.id === 28);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  it('SCION bridging via HTX tunnel', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 5 || c.id === 4);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });
});


describe('Normative §11 Items Compliance', () => {
  const tmpBin = path.join(__dirname, 'temp-normative-bin');
  const evidencePath = path.join(__dirname, 'normative-items-fixture.json');
  beforeAll(async () => {
    // Write a binary containing all required tokens for heuristic checks
    await fs.writeFile(tmpBin, Buffer.from([
      'ticket', 'rotation', '/betanet/htx/1.1.0', '/betanet/htxquic/1.1.0',
      'Noise_XK', 'chacha20', 'poly1305', 'cashu', 'lightning', 'federation',
      'dht', 'rendezvous', 'beaconset', 'pow22', 'alias ledger', 'consensus', 'chain',
      'SCION', 'pathManagement', 'IPTransition', 'diversity', 'voucher', 'FROST', 'rateLimit',
  'governance', 'partition', 'fallback', 'UDP', 'TCP', 'cover', 'SLSA', 'provenance', 'reproducible',
  // Added tokens to satisfy check 1 (network capabilities: tls, quic, ech, port 443) and check 4 (SCION path diversity markers)
  'tls', 'quic', 'ech', '443', 'AS123', 'AS456'
  , '-> e,', '-> s,'
    ].join(' ')));
  });
  afterAll(async () => { await fs.remove(tmpBin); });

  it('HTX over TCP+QUIC with origin-mirrored TLS + calibration + ECH', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 1 || c.id === 22);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  it('Negotiated-carrier replay-bound access tickets', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 2 || c.id === 30);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  it('Noise XK inner tunnel, key separation, nonce lifecycle, rekey thresholds, PQ date', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 13 || c.id === 19);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  it('HTTP/2/3 adaptive emulation', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 4 || c.id === 20 || c.id === 28);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

});
