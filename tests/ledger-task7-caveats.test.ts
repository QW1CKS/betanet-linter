import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs';
import * as path from 'path';

// Helper to write temporary evidence & support files
function writeTempJSON(obj: any, filename: string): string {
  const p = path.join(__dirname, filename);
  fs.writeFileSync(p, JSON.stringify(obj, null, 2));
  return p;
}

// Minimal dummy binary placeholder (empty file)
const dummyBin = path.join(__dirname, 'dummy-bin-ledger');
if (!fs.existsSync(dummyBin)) fs.writeFileSync(dummyBin, '');

describe('Task 7 Caveat Resolution (Ledger)', () => {
  it('flags weight cap exceeded & org cap exceeded', async () => {
    const evidence = {
      ledger: {
        finalitySets: ['a','b'],
        quorumCertificatesValid: true,
        finalityDepth: 3,
        chains: [
          { name: 'chainA', finalityDepth: 3, weightSum: 0.9, epoch: 10, signatures: [ { signer: 'sig1:AORG', weight: 60, valid: true }, { signer: 'sig2:AORG', weight: 30, valid: true } ] },
          { name: 'chainB', finalityDepth: 3, weightSum: 0.8, epoch: 11, signatures: [ { signer: 'sig1:AORG', weight: 50, valid: true }, { signer: 'sig3:BORG', weight: 20, valid: true } ] }
        ],
        signerAggregatedWeights: { 'sig1:AORG': 110, 'sig2:AORG': 30, 'sig3:BORG': 20 }
      }
    };
    const evidencePath = writeTempJSON(evidence, 'ledger-weightcap-evidence.json');
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(dummyBin, { evidenceFile: evidencePath, ledgerWeightCapPct: 50, ledgerOrgWeightCapPct: 70, ledgerNormalizeWeights: true, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 16);
    expect(check).toBeDefined();
    // Expect failure due to weight cap exceeded (sig1 normalized share > 50%)
    expect(check?.passed).toBe(false);
  });

  it('passes when weights below caps after normalization', async () => {
    const evidence = {
      ledger: {
        finalitySets: ['a','b'],
        quorumCertificatesValid: true,
        finalityDepth: 3,
        chains: [
          // weightSum values align exactly to sum of signature weights to avoid aggregation mismatch
          { name: 'chainA', finalityDepth: 3, weightSum: 50, epoch: 10, signatures: [ { signer: 'sig1:ORG1', weight: 30, valid: true }, { signer: 'sig2:ORG2', weight: 20, valid: true } ] },
          { name: 'chainB', finalityDepth: 3, weightSum: 50, epoch: 11, signatures: [ { signer: 'sig3:ORG3', weight: 25, valid: true }, { signer: 'sig4:ORG4', weight: 25, valid: true } ] }
        ],
  signerAggregatedWeights: { 'sig1:ORG1': 30, 'sig2:ORG2': 20, 'sig3:ORG3': 25, 'sig4:ORG4': 25 },
  weightThresholdPct: 0.5
      }
    };
    const evidencePath = writeTempJSON(evidence, 'ledger-weightcap-pass-evidence.json');
    const checker = new BetanetComplianceChecker();
    const result = await checker.checkCompliance(dummyBin, { evidenceFile: evidencePath, ledgerWeightCapPct: 60, ledgerOrgWeightCapPct: 75, ledgerNormalizeWeights: true, allowHeuristic: true });
    const check = result.checks.find(c => c.id === 16);
    expect(check).toBeDefined();
    expect(check?.passed).toBe(true);
  });
});
