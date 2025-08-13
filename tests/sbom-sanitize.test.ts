import { BetanetComplianceChecker } from '../src';
import * as fs from 'fs-extra';
import * as path from 'path';

describe('ISSUE-037 SBOM name sanitization', () => {
  jest.setTimeout(30000);
  const tmpDir = path.join(__dirname, 'temp-sanitize');
  // Use a filename with spaces, traversal tokens, wildcard characters. Avoid null/control bytes which FS rejects.
  const binPath = path.join(tmpDir, 'weird name ..__bin(+)!bin');

  beforeAll(async () => {
    await fs.ensureDir(tmpDir);
    // Create a dummy binary file with minimal content
    await fs.writeFile(binPath, 'dummy-binary-content');
  });

  afterAll(async () => {
    await fs.remove(tmpDir);
  });

  it('sanitizes root binary name and dependency names in SPDX tag-value output', async () => {
    const checker = new BetanetComplianceChecker();
    const outPath = await checker.generateSBOM(binPath, 'spdx');
    const text = await fs.readFile(outPath, 'utf8');
    // Expect no raw spaces or path traversal sequences in PackageName lines
    const packageNameLines = text.split('\n').filter(l => l.startsWith('PackageName:'));
    packageNameLines.forEach(l => {
      const name = l.split(':').slice(1).join(':').trim();
      expect(/^[A-Za-z0-9._-]+$/.test(name)).toBe(true);
    });
  });

  it('sanitizes names in CycloneDX JSON output', async () => {
    const checker = new BetanetComplianceChecker();
    const outPath = await checker.generateSBOM(binPath, 'cyclonedx-json');
    const json = JSON.parse(await fs.readFile(outPath, 'utf8'));
    const rootName = json?.metadata?.component?.name;
    expect(/^[A-Za-z0-9._-]+$/.test(rootName)).toBe(true);
  });
});
