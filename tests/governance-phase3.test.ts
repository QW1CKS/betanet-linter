import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs-extra';
import * as path from 'path';
import * as crypto from 'crypto';

jest.setTimeout(15000);

describe('Phase 3 governance completion', () => {
  const tmpBin = path.join(__dirname, 'temp-existing-bin4');
  beforeAll(async () => {
    await fs.writeFile(tmpBin, Buffer.from('governance ledger quorum certificates test binary'));
  });
  afterAll(async () => { try { await fs.remove(tmpBin); } catch {/* ignore */} });

  it('fails ledger check when root hash repeats or signature missing', async () => {
    const checker = new BetanetComplianceChecker();
    // Create two fake QC CBOR objects base64 (simplified encoding) without varying root hash
    const cbor = require('cbor');
    const qc1 = { epoch: 1, signatures: [{ validator: 'v1', weight: 10 }], rootHash: 'abc' };
    const qc2 = { epoch: 2, signatures: [{ validator: 'v1', weight: 10 }], rootHash: 'abc' }; // repeat root
    const qc1b64 = cbor.encode(qc1).toString('base64');
    const qc2b64 = cbor.encode(qc2).toString('base64');
    const govFile = path.join(__dirname, 'temp-governance-invalid.json');
    await fs.writeFile(govFile, JSON.stringify({ ledger: { quorumCertificatesCbor: [qc1b64, qc2b64], emergencyAdvanceUsed: false } }));
    const result = await checker.checkCompliance(tmpBin, { governanceFile: govFile, allowHeuristic: true });
    const ledgerCheck = result.checks.find(c => c.id === 16);
    expect(ledgerCheck?.passed).toBe(false);
    expect(ledgerCheck?.details).toMatch(/root-hash-repeat|invalid quorum certificates/);
    await fs.remove(govFile);
  });

  it('passes ledger check with valid root hash chain and signatures when keys provided', async () => {
    const checker = new BetanetComplianceChecker();
    // Generate a key pair for validator
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const sign = (epoch: number, root: string) => crypto.sign(null, Buffer.from(`epoch:${epoch}|root:${root}`), privateKey).toString('base64');
    const cbor = require('cbor');
    const qc1 = { epoch: 1, signatures: [{ validator: 'v1', weight: 10, sig: sign(1,'root1') }], rootHash: 'root1' };
    const qc2 = { epoch: 2, signatures: [{ validator: 'v1', weight: 10, sig: sign(2,'root2') }], rootHash: 'root2' };
    const qc1b64 = cbor.encode(qc1).toString('base64');
    const qc2b64 = cbor.encode(qc2).toString('base64');
    const govFile = path.join(__dirname, 'temp-governance-valid.json');
    const pem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
    await fs.writeFile(govFile, JSON.stringify({ governance: { validatorKeys: { v1: pem } }, ledger: { quorumCertificatesCbor: [qc1b64, qc2b64], emergencyAdvanceUsed: false } }));
    const result = await checker.checkCompliance(tmpBin, { governanceFile: govFile, allowHeuristic: true });
    const ledgerCheck = result.checks.find(c => c.id === 16);
    expect(ledgerCheck?.passed).toBe(true);
    await fs.remove(govFile);
  });
});
