import * as fs from 'fs-extra';
import * as path from 'path';
import { runHarness } from '../src/harness';
import { BetanetComplianceChecker } from '../src';

describe('ECH Harness Integration (Task 2)', () => {
  jest.setTimeout(15000);

  async function runWithHarness(echOpts: { simulateCertDiff: boolean; greaseAnomaly?: boolean }) {
    const tmpBin = path.join(__dirname, 'temp-ech-harness-bin');
    await fs.writeFile(tmpBin, Buffer.from('ech harness bin'));
    const outFile = path.join(__dirname, 'temp-ech-evidence.json');
    await runHarness(tmpBin, outFile, { echSimulate: { outerHost: 'outer.example', innerHost: 'inner.hidden', simulateCertDiff: echOpts.simulateCertDiff, greaseAnomaly: echOpts.greaseAnomaly } });
    const evidence = JSON.parse(await fs.readFile(outFile, 'utf8'));
    const checker = new BetanetComplianceChecker();
    (checker as any)._analyzer = { // minimal analyzer relying on evidence
      getStaticPatterns: async () => ({}),
      evidence
    };
    const result = await checker.checkCompliance(tmpBin, { evidenceFile: outFile, allowHeuristic: true });
    await fs.remove(tmpBin); await fs.remove(outFile);
    return result.checks.find(c => c.id === 32)!;
  }

  it('passes when simulated cert differential and no GREASE anomalies', async () => {
    const ech = await runWithHarness({ simulateCertDiff: true });
    expect(ech.passed).toBe(true);
    expect(ech.details).toMatch(/ECH accepted/);
  });

  it('fails when no cert differential present', async () => {
    const ech = await runWithHarness({ simulateCertDiff: false });
    expect(ech.passed).toBe(false);
    expect(ech.details).toMatch(/no cert differential/);
  });

  it('fails when GREASE anomaly flagged', async () => {
    const ech = await runWithHarness({ simulateCertDiff: true, greaseAnomaly: true });
    expect(ech.passed).toBe(false);
    expect(ech.details).toMatch(/GREASE/);
  });
});
