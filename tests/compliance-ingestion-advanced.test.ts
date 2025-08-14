import { BetanetComplianceChecker } from '../src/index';
import { BinaryAnalyzer } from '../src/analyzer';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

function stableCanon(obj: any): string {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) return '[' + obj.map(stableCanon).join(',') + ']';
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + stableCanon(obj[k])).join(',') + '}';
}

describe('advanced evidence ingestion & analyzer edge branches', () => {
  const tmpDir = path.join(__dirname, 'adv-ingestion-fixtures');
  const bin = path.join(tmpDir, 'dummy.bin');
  beforeAll(() => { fs.mkdirSync(tmpDir,{recursive:true}); fs.writeFileSync(bin, 'binarydata'); });
  afterAll(() => { try { fs.rmSync(tmpDir,{recursive:true,force:true}); } catch {} });

  it('processes DSSE envelope with threshold failure and required keys missing then success with both signatures', async () => {
    const { publicKey: pk1, privateKey: sk1 } = crypto.generateKeyPairSync('ed25519');
    const inner1 = { predicateType:'slsa', predicate:{ builder:{ id:'builder://dsse1' } }, subject:[{ name:'a', digest:{ sha256:'1'.repeat(64) } }] };
    const payload1 = Buffer.from(JSON.stringify(inner1));
    const sig1 = crypto.sign(null, payload1, sk1).toString('base64');
    const env1 = { payloadType:'application/vnd.in-toto+json', payload: payload1.toString('base64'), signatures:[{ keyid:'k1', sig: sig1 }] };
    const envFile1 = path.join(tmpDir,'env1.json'); fs.writeFileSync(envFile1, JSON.stringify(env1,null,2));
    const keyMap1 = { k1: pk1.export({format:'der', type:'spki'}).toString('base64') };
    const keyMapFile1 = path.join(tmpDir,'keys1.json'); fs.writeFileSync(keyMapFile1, JSON.stringify(keyMap1,null,2));
    const checker1 = new BetanetComplianceChecker();
    await checker1.checkCompliance(bin,{ evidenceFile: envFile1, dssePublicKeysFile: keyMapFile1, dsseThreshold:2, dsseRequiredKeys:'k1,k2' });
    const prov1 = (checker1.analyzer as any).evidence?.provenance;
    expect(prov1.dsseSignerCount).toBe(1);
    expect(prov1.dsseVerifiedSignerCount).toBe(1);
    expect(prov1.dsseThresholdMet).toBe(false);
    expect(prov1.dsseRequiredKeysPresent).toBe(false);
    expect(Array.isArray(prov1.dssePolicyReasons)).toBe(true);

    const { publicKey: pk2, privateKey: sk2 } = crypto.generateKeyPairSync('ed25519');
    const inner2 = { predicateType:'slsa', predicate:{ builder:{ id:'builder://dsse2' } }, subject:[{ name:'b', digest:{ sha256:'2'.repeat(64) } }] };
    const payload2 = Buffer.from(JSON.stringify(inner2));
    const sig2a = crypto.sign(null, payload2, sk1).toString('base64');
    const sig2b = crypto.sign(null, payload2, sk2).toString('base64');
    const env2 = { payloadType:'application/vnd.in-toto+json', payload: payload2.toString('base64'), signatures:[{ keyid:'k1', sig: sig2a },{ keyid:'k2', sig: sig2b }] };
    const envFile2 = path.join(tmpDir,'env2.json'); fs.writeFileSync(envFile2, JSON.stringify(env2,null,2));
    const keyMap2 = { k1: pk1.export({format:'der', type:'spki'}).toString('base64'), k2: pk2.export({format:'der', type:'spki'}).toString('base64') };
    const keyMapFile2 = path.join(tmpDir,'keys2.json'); fs.writeFileSync(keyMapFile2, JSON.stringify(keyMap2,null,2));
    const checker2 = new BetanetComplianceChecker();
    await checker2.checkCompliance(bin,{ evidenceFile: envFile2, dssePublicKeysFile: keyMapFile2, dsseThreshold:2, dsseRequiredKeys:'k1,k2' });
    const prov2 = (checker2.analyzer as any).evidence?.provenance;
    expect(prov2.dsseSignerCount).toBe(2);
    expect(prov2.dsseVerifiedSignerCount).toBe(2);
    expect(prov2.dsseThresholdMet).toBe(true);
    expect(prov2.dsseRequiredKeysPresent).toBe(true);
    expect(prov2.dssePolicyReasons).toBeUndefined();
  }, 15000);

  it('processes evidence bundle multi-signer aggregated signature validity', async () => {
    const { publicKey: pk1, privateKey: sk1 } = crypto.generateKeyPairSync('ed25519');
    const { publicKey: pk2, privateKey: sk2 } = crypto.generateKeyPairSync('ed25519');
    const part1 = { metric:1, name:'ev1' };
    const part2 = { metric:2, name:'ev2' };
    const c1 = stableCanon(part1);
    const c2 = stableCanon(part2);
    const sig1 = crypto.sign(null, Buffer.from(c1), sk1).toString('base64');
    const sig2 = crypto.sign(null, Buffer.from(c2), sk2).toString('base64');
    const bundle = [
      { evidence: part1, signature: sig1, publicKey: pk1.export({format:'der', type:'spki'}).toString('base64'), signer:'s1' },
      { evidence: part2, signature: sig2, publicKey: pk2.export({format:'der', type:'spki'}).toString('base64'), signer:'s2' }
    ];
    const bundleFile = path.join(tmpDir,'bundle.json'); fs.writeFileSync(bundleFile, JSON.stringify(bundle,null,2));
    const dummyEvidence = { predicateType:'slsa', predicate:{ builder:{ id:'b' } }, subject:[{ name:'x', digest:{ sha256:'3'.repeat(64) } }] };
    const dummyEvidenceFile = path.join(tmpDir,'dummy-evidence.json'); fs.writeFileSync(dummyEvidenceFile, JSON.stringify(dummyEvidence,null,2));
    const checker = new BetanetComplianceChecker();
    await checker.checkCompliance(bin,{ evidenceFile: dummyEvidenceFile, evidenceBundleFile: bundleFile });
    const bundleDiag = (checker.analyzer as any).evidence?.signedEvidenceBundle;
    expect(bundleDiag.entries.length).toBe(2);
    expect(bundleDiag.aggregatedSignatureValid).toBe(true);
    expect(bundleDiag.multiSignerThresholdMet).toBe(true);
  });

  it('detects materials mismatch against SBOM digests', async () => {
    const ev = { predicateType:'slsa', predicate:{ builder:{ id:'b' }, materials:[{ uri:'git+repo1', digest:{ sha256:'a'.repeat(64) } }, { uri:'git+repo2', digest:{ sha256:'b'.repeat(64) } }] }, subject:[{ name:'x', digest:{ sha256:'c'.repeat(64) } }] };
    const evFile = path.join(tmpDir,'prov-mismatch.json'); fs.writeFileSync(evFile, JSON.stringify(ev,null,2));
    const sbom = { components:[ { name:'dep', version:'1', hashes:[{ alg:'SHA256', content:'d'.repeat(64) }] } ] };
    const sbomFile = path.join(tmpDir,'sbom.json'); fs.writeFileSync(sbomFile, JSON.stringify(sbom,null,2));
    const checker = new BetanetComplianceChecker();
    await checker.checkCompliance(bin,{ evidenceFile: evFile, sbomFile });
    const prov = (checker.analyzer as any).evidence?.provenance;
    expect(prov.materialsMismatchCount).toBeGreaterThan(0);
    expect(prov.materialsValidated).toBe(false);
  }, 15000);

  it('covers analyzer attemptNetwork success path and unsupported signature algorithm caching', async () => {
    const analyzer = new BinaryAnalyzer(bin, false);
    analyzer.setNetworkAllowed(true, ['example.com']);
    const result = await analyzer.attemptNetwork('https://example.com/resource','GET', async () => 'ok');
    expect(result).toBe('ok');
    const diag1: any = analyzer.getDiagnostics();
    expect(Array.isArray(diag1.networkOps)).toBe(true);
    const c = analyzer.canonicalize({ a:1 });
    const fakeSig = Buffer.from('deadbeef','hex').toString('base64');
    const fakePub = Buffer.alloc(32,0);
    const v1 = (analyzer as any).verifySignatureCached('rsa','tester', c.json, fakeSig, fakePub);
    const v2 = (analyzer as any).verifySignatureCached('rsa','tester', c.json, fakeSig, fakePub);
    expect(v1).toBe(false); expect(v2).toBe(false);
    const diag2: any = analyzer.getDiagnostics();
    expect(diag2.signatureCacheHits).toBeGreaterThan(0);
  });
});
