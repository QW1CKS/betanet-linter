import * as fs from 'fs-extra';
import * as path from 'path';
import { runHarness } from '../src/harness';

describe('harness skeleton', () => {
  jest.setTimeout(15000);
  it('produces evidence json with expected static pattern fields', async () => {
    const tmpBin = path.join(__dirname, 'temp-harness-bin');
    await fs.writeFile(tmpBin, Buffer.from('Noise_XK h2 http/1.1 keysetid32 secret32 aggregatedsig64'));
    const out = path.join(__dirname, 'harness-output.json');
    await runHarness(tmpBin, out, { scenarios: ['static-only'] });
    const data = JSON.parse(await fs.readFile(out, 'utf8'));
    expect(data.schemaVersion).toBeDefined();
    expect(data.meta).toBeDefined();
    expect(Array.isArray(data.clientHello.alpn)).toBe(true);
    expect(data.noise.pattern).toBe('XK');
    expect(data.voucher.structLikely).toBe(true);
    await fs.remove(tmpBin); await fs.remove(out);
  });

  it('can include fallback simulation when host provided (may fail gracefully)', async () => {
    const tmpBin = path.join(__dirname, 'temp-harness-bin2');
    await fs.writeFile(tmpBin, Buffer.from('Noise_XK h2 http/1.1 keysetid32 secret32 aggregatedsig64'));
    const out = path.join(__dirname, 'harness-output2.json');
    await runHarness(tmpBin, out, { fallbackHost: '127.0.0.1', fallbackUdpTimeoutMs: 50, coverConnections: 1 });
    const data = JSON.parse(await fs.readFile(out, 'utf8'));
    expect(data.fallback).toBeDefined();
    expect(data.fallback.udpAttempted).toBe(true);
    // tcpConnected may be false if nothing listening; ensure structure present
    expect(typeof data.fallback.udpTimeoutMs).toBe('number');
    await fs.remove(tmpBin); await fs.remove(out);
  });

  it('simulates rekey and h2 adaptive jitter evidence when flags provided', async () => {
  const tmpBin = path.join(__dirname, 'temp-harness-bin3');
  await fs.writeFile(tmpBin, Buffer.from('Noise_XK h2 http/1.1 keysetid32 secret32 aggregatedsig64'));
  const out = path.join(__dirname, 'harness-output3.json');
  await runHarness(tmpBin, out, { rekeySimulate: true, h2AdaptiveSimulate: true, jitterSamples: 10 });
  const data = JSON.parse(await fs.readFile(out, 'utf8'));
  // Updated schema: noiseTranscript replaces legacy noiseTranscriptDynamic
  expect(data.noiseTranscript || data.noiseTranscriptDynamic).toBeDefined();
  const nt = data.noiseTranscript || data.noiseTranscriptDynamic;
  expect(nt.rekeysObserved).toBeGreaterThanOrEqual(1);
  expect(data.h2Adaptive).toBeDefined();
  expect(data.h2Adaptive.sampleCount).toBeGreaterThanOrEqual(5);
  await fs.remove(tmpBin); await fs.remove(out);
  });
});
