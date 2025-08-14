import { BinaryAnalyzer } from '../src/analyzer';
import * as fs from 'fs';
import * as path from 'path';

describe('analyzer canonicalization & signature cache', () => {
  const tmpBin = path.join(__dirname,'temp-bin.txt');
  beforeAll(()=>{ fs.writeFileSync(tmpBin, 'Noise_XK h2 http/1.1 keysetid32 secret32 aggregatedsig64 frost n=5 t=3 pad16 pad32 ticket nonce exp sig'); });
  afterAll(()=>{ try { fs.unlinkSync(tmpBin); } catch {} });

  it('produces stable canonical digest and caches signature verification result', async () => {
    const analyzer = new BinaryAnalyzer(tmpBin, false);
    const obj = { b: 2, a: 'z', nested: { y: 1, x: 'é' } };
    const c1 = analyzer.canonicalize(obj);
    const c2 = analyzer.canonicalize({ nested: { x: 'é', y: 1 }, a: 'z', b: 2 });
    expect(c1.json).toBe(c2.json);
    expect(c1.digest).toBe(c2.digest);
    // Fake ed25519 spki public key (not valid) and signature; expect invalid but cached
    const fakePub = Buffer.from('302a300506032b6570032100ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff','hex');
    const sigB64 = Buffer.from('deadbeef','hex').toString('base64');
    const valid1 = analyzer.verifySignatureCached('ed25519','signer1', c1.json, sigB64, fakePub);
    const valid2 = analyzer.verifySignatureCached('ed25519','signer1', c1.json, sigB64, fakePub);
    expect(valid1).toBe(false);
    expect(valid2).toBe(false);
    const diag = (analyzer as any).getDiagnostics();
    expect(diag.signatureCacheHits).toBe(1);
    expect(diag.signatureCacheMisses).toBe(1);
  });
});
