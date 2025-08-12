import * as fs from 'fs-extra';
import * as path from 'path';
import { runHarness } from '../src/harness';

describe('harness skeleton', () => {
  it('produces evidence json with expected static pattern fields', async () => {
    const tmpBin = path.join(__dirname, 'temp-harness-bin');
    await fs.writeFile(tmpBin, Buffer.from('Noise_XK h2 http/1.1 keysetid32 secret32 aggregatedsig64'));
    const out = path.join(__dirname, 'harness-output.json');
    await runHarness(tmpBin, out, { scenarios: ['static-only'] });
    const data = JSON.parse(await fs.readFile(out, 'utf8'));
    expect(data.meta).toBeDefined();
    expect(Array.isArray(data.clientHello.alpn)).toBe(true);
    expect(data.noise.pattern).toBe('XK');
    expect(data.voucher.structLikely).toBe(true);
    await fs.remove(tmpBin); await fs.remove(out);
  });
});
