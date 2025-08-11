import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs-extra';
import * as path from 'path';

describe('SBOM streaming threshold (ISSUE-046)', () => {
  const checker = new BetanetComplianceChecker();
  const tmpBin = path.join(__dirname, 'temp-stream-bin');
  beforeAll(async () => { await fs.writeFile(tmpBin, Buffer.from('test binary data')); });
  afterAll(async () => { await fs.remove(tmpBin); delete process.env.BETANET_SBOM_STREAM_THRESHOLD; });
  it('writes CycloneDX XML via streaming path when threshold low', async () => {
    process.env.BETANET_SBOM_STREAM_THRESHOLD = '0';
    const out = await checker.generateSBOM(tmpBin, 'cyclonedx');
    const content = await fs.readFile(out, 'utf8');
    expect(content.startsWith('<bom ')).toBe(true);
    expect(content.includes('<metadata>')).toBe(true);
  });
});
