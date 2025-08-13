

import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs-extra';
import * as path from 'path';

describe('Normative §11 Items Compliance', () => {
  jest.setTimeout(20000);
  const tmpBin = path.join(__dirname, 'temp-normative-bin');
  const evidencePath = path.join(__dirname, 'normative-items-fixture.json');
  beforeAll(async () => {
    // Write a binary containing all required tokens for heuristic checks
    await fs.writeFile(tmpBin, Buffer.from([
      'ticket', 'rotation', '/betanet/htx/1.1.0', '/betanet/htxquic/1.1.0',
      'Noise_XK', 'chacha20', 'poly1305', 'cashu', 'lightning', 'federation',
      'dht', 'rendezvous', 'beaconset', 'pow22', 'alias ledger', 'consensus', 'chain',
  'SCION', 'pathManagement', 'IPTransition', 'diversity', 'voucher', 'FROST', 'rateLimit',
  'mixnode', 'hop', 'hopset', 'relay', 'epoch', 'drand', 'distinct',
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
    const check = result.checks.find(c => c.id === 4); // Check 4 covers SCION bridging
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  // New tests for items 6-13
  it('Offer /betanet/htx/1.1.0 & /betanet/htxquic/1.1.0 (legacy 1.0 optional)', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 5); // transport endpoints
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  it('Rotating rendezvous bootstrap (BeaconSet, PoW, multi-bucket rate-limits, no deterministic seeds)', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 6); // bootstrap
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });

  it('Mixnode selection diversity and uniqueness', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    // Checks 11 (privacy hop), 17 (mix diversity), 27 (advanced variance)
    const c11 = result.checks.find(c => c.id === 11);
    const c17 = result.checks.find(c => c.id === 17);
    expect(c11).toBeDefined();
    expect(c11?.passed).toBe(true);
    if (c17) expect(c17.passed).toBe(true);
  });

  it('Alias ledger finality & quorum certificates', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
  const check = result.checks.find(c => c.id === 16); // ledger finality observation
  expect(check).toBeDefined();
  expect(check?.passed).toBe(true);
  });

  it('Cashu vouchers, FROST threshold, PoW, rate-limits', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
  const payment = result.checks.find(c => c.id === 8);
  expect(payment).toBeDefined();
  expect(payment?.passed).toBe(true);
  // Voucher struct & crypto checks
  const voucherStruct = result.checks.find(c => c.id === 14);
  const voucherCrypto = result.checks.find(c => c.id === 29);
  const voucherSig = result.checks.find(c => c.id === 31);
  if (voucherStruct) expect(voucherStruct.passed).toBe(true);
  if (voucherCrypto) expect(voucherCrypto.passed).toBe(true);
  if (voucherSig) expect(voucherSig.passed).toBe(true);
  });

  it('Governance anti-concentration caps & partition safety', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
  const check = result.checks.find(c => c.id === 15); // governance anti-concentration
  expect(check).toBeDefined();
  expect(check?.passed).toBe(true);
  });

  it('Anti-correlation fallback timing & cover connections', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
  const check = result.checks.find(c => c.id === 25); // fallback timing policy
  expect(check).toBeDefined();
  expect(check?.passed).toBe(true);
  });

  it('Reproducible builds & SLSA 3 provenance artifacts', async () => {
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 9); // build provenance
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });
});
