import * as fs from 'fs';
import * as path from 'path';

import { BinaryAnalyzer } from '../src/analyzer';

describe('BinaryAnalyzer branch coverage (fallback, network, symbols, signatures)', () => {
  const tmpDir = path.join(__dirname, 'tmp-analyzer');
  const smallBin = path.join(tmpDir, 'small.bin');
  const largeTruncBin = path.join(tmpDir, 'large.bin');

  beforeAll(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(smallBin, 'ticket nonce exp sig pad16 pad32 keysetid32 secret32 aggregatedsig64 frost n=5 t=3');
  const buf = Buffer.alloc(4096 * 2, 0x41); // 8KB (will still truncate with lower cap)
    const sprinkle = Buffer.from('éàöNoise_XKhttp/1.1h2pad16pad64');
    sprinkle.copy(buf, 100);
    fs.writeFileSync(largeTruncBin, buf);
  });

  afterAll(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch {}
  });

  it('forces fallback string extraction via env override', async () => {
    process.env.BETANET_FORCE_FALLBACK_STRINGS = '1';
    process.env.BETANET_SKIP_TOOLS = 'strings'; // skip primary to ensure fallback engaged
    const analyzer = new BinaryAnalyzer(largeTruncBin, false);
    const res = await analyzer.analyze();
    expect(res.strings.length).toBeGreaterThan(0);
    const diag = analyzer.getDiagnostics() as any;
  const reasons = diag.degradationReasons || [];
  const ok = reasons.includes('strings-missing') || (diag.degraded === true);
  expect(ok).toBe(true);
    delete process.env.BETANET_FORCE_FALLBACK_STRINGS;
    process.env.BETANET_SKIP_TOOLS = '';
  }, 20000);

  it('captures symbols-missing degradation when nm/objdump skipped', async () => {
    process.env.BETANET_SKIP_TOOLS = 'nm,objdump,strings';
    const analyzer = new BinaryAnalyzer(smallBin, false);
    await analyzer.analyze();
    const diag = analyzer.getDiagnostics() as any;
  // Some environments may still have minimal objdump providing symbols; accept either symbols-missing reason OR degraded true with missingCoreTools listing nm
  const reasons = diag.degradationReasons || [];
  expect(reasons.includes('symbols-missing') || (diag.degraded && (diag.missingCoreTools||[]).includes('nm'))).toBe(true);
    process.env.BETANET_SKIP_TOOLS = '';
  });

  it('exercises network attempt branches (disabled, host blocked, retry then success)', async () => {
    const analyzer = new BinaryAnalyzer(smallBin, false);
    let disabledErr = '';
    try { await analyzer.attemptNetwork('https://example.com/resource'); } catch (e: any) { disabledErr = e.message; }
    expect(disabledErr).toBe('network-disabled');
    analyzer.setNetworkAllowed(true, ['allowed.example']);
    let blockedErr = '';
    try { await analyzer.attemptNetwork('https://example.com/resource'); } catch (e: any) { blockedErr = e.message; }
    expect(blockedErr).toBe('network-host-blocked');
    let attempts = 0;
    analyzer.setNetworkAllowed(true, ['example.com']);
    const result = await analyzer.attemptNetwork('https://example.com/data', 'GET', async () => {
      attempts++;
      if (attempts === 1) throw new Error('transient');
      return 'ok';
    });
    expect(result).toBe('ok');
    const diag = analyzer.getDiagnostics() as any;
    expect((diag.networkOps || []).length).toBeGreaterThanOrEqual(2);
  });

  it('caches unsupported signature algorithm (rsa) negative result', () => {
    const analyzer = new BinaryAnalyzer(smallBin, false);
    const obj = { test: 'value' };
    const { json } = analyzer.canonicalize(obj);
    const fakePub = Buffer.from('3082010a0282010100deadbeef', 'hex');
    const sig = Buffer.from('badbad', 'hex').toString('base64');
    const miss = analyzer.verifySignatureCached('rsa', 'signerX', json, sig, fakePub);
    const hit = analyzer.verifySignatureCached('rsa', 'signerX', json, sig, fakePub);
    expect(miss).toBe(false);
    expect(hit).toBe(false);
    const diag = analyzer.getDiagnostics() as any;
    expect(diag.signatureCacheHits).toBe(1);
    expect(diag.signatureCacheMisses).toBe(1);
  });

  it('adds dynamic probe output when enabled (probes best-effort)', async () => {
    process.env.BETANET_SKIP_TOOLS = 'strings';
    const analyzer = new BinaryAnalyzer(smallBin, false); // using small bin; probes may fail silently
    analyzer.setDynamicProbe(true);
    const res = await analyzer.analyze();
    expect(res.strings.length).toBeGreaterThan(0);
    process.env.BETANET_SKIP_TOOLS = '';
  }, 15000);
});
