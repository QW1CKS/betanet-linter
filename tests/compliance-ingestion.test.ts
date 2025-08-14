import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

function writeJson(file: string, obj: any){ fs.writeFileSync(file, JSON.stringify(obj, null, 2)); }

describe('compliance evidence ingestion paths', () => {
  const tmpDir = path.join(__dirname,'ingestion-fixtures');
  const bin = path.join(tmpDir,'dummy.bin');
  beforeAll(()=>{ fs.mkdirSync(tmpDir,{recursive:true}); fs.writeFileSync(bin,'binary'); });
  afterAll(()=>{ try { fs.rmSync(tmpDir,{recursive:true,force:true}); } catch {} });

  it('ingests DSSE envelope (payloadType/payload/signatures)', async () => {
    const inner = { predicateType:'slsa', predicate:{ builder:{ id:'builder://x' }, materials:[{ uri:'git+https://repo', digest:{ sha256:'a'.repeat(64) } }] }, subject:[{ name:'artifact', digest:{ sha256:'b'.repeat(64) } }] };
    const envelope = { payloadType:'application/vnd.in-toto+json', payload: Buffer.from(JSON.stringify(inner)).toString('base64'), signatures:[{ sig:'deadbeef' }] };
    const evidenceFile = path.join(tmpDir,'dsse.json');
    writeJson(evidenceFile, envelope);
    const checker = new BetanetComplianceChecker();
    const res = await checker.checkCompliance(bin,{ evidenceFile });
    expect(res.diagnostics?.evidenceSignatureValid === false || res.diagnostics?.evidenceSignatureValid === undefined).toBe(true);
    expect((checker.analyzer as any).evidence?.provenance?.dsseSignerCount).toBe(1);
  });

  it('ingests raw provenance JSON (predicateType + predicate)', async () => {
    const rawProv = { predicateType:'slsa', predicate:{ builder:{ id:'builder://y' }, materials:[{ uri:'x', digest:{ sha256:'c'.repeat(64) } }] }, subject:[{ name:'artifact2', digest:{ sha256:'d'.repeat(64) } }] };
    const evidenceFile = path.join(tmpDir,'raw-prov.json');
    writeJson(evidenceFile, rawProv);
    const checker = new BetanetComplianceChecker();
    const res = await checker.checkCompliance(bin,{ evidenceFile });
    expect((checker.analyzer as any).evidence?.provenance?.predicateType).toBe('slsa');
    expect(res.checks.length).toBeGreaterThan(0);
  });

  it('ingests simple reference format (binaryDistDigest)', async () => {
    const simple = { binaryDistDigest:'sha256:'+ 'e'.repeat(64), predicateType:'slsa', builderId:'builder://z', extraField:'keepme' };
    const evidenceFile = path.join(tmpDir,'simple.json');
    writeJson(evidenceFile, simple);
    const checker = new BetanetComplianceChecker();
    await checker.checkCompliance(bin,{ evidenceFile });
    expect((checker.analyzer as any).evidence?.provenance?.binaryDigest).toBe('sha256:'+ 'e'.repeat(64));
    expect((checker.analyzer as any).evidence?.extraField).toBe('keepme');
  });

  it('passes already-shaped evidence object (no special keys)', async () => {
    const shaped = { customMetric: 42, noiseTranscript: { messages:[{ type:'e', nonce:0, keyEpoch:0 }] } };
    const evidenceFile = path.join(tmpDir,'shaped.json'); writeJson(evidenceFile, shaped);
    const checker = new BetanetComplianceChecker();
    await checker.checkCompliance(bin,{ evidenceFile });
    expect((checker.analyzer as any).evidence?.customMetric).toBe(42);
  }, 15000);

  it('verifies detached evidence signature (valid ed25519)', async () => {
    const evidence = { predicateType:'slsa', predicate:{ builder:{ id:'builder://sig' } }, subject:[{ name:'artifact', digest:{ sha256:'f'.repeat(64) } }] };
    const evidenceFile = path.join(tmpDir,'signed.json'); writeJson(evidenceFile, evidence);
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    // Use the same canonicalization logic the checker will use (stable key order + nested ordering)
    const stableCanon = (obj: any): string => {
      if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
      if (Array.isArray(obj)) return '[' + obj.map(stableCanon).join(',') + ']';
      const keys = Object.keys(obj).sort();
      return '{' + keys.map(k => JSON.stringify(k)+ ':' + stableCanon(obj[k])).join(',') + '}';
    };
    const canon = stableCanon(evidence);
    const sig = crypto.sign(null, Buffer.from(canon), privateKey).toString('base64');
    const sigFile = path.join(tmpDir,'signed.sig'); fs.writeFileSync(sigFile, sig);
    const pubDer = publicKey.export({ format:'der', type:'spki' }) as Buffer;
    const pubFile = path.join(tmpDir,'signed.pub'); fs.writeFileSync(pubFile, pubDer.toString('base64'));
    const checker = new BetanetComplianceChecker();
    const res = await checker.checkCompliance(bin,{ evidenceFile, evidenceSignatureFile: sigFile, evidencePublicKeyFile: pubFile });
    expect(res.diagnostics?.evidenceSignatureValid).toBe(true);
    const prov = (checker.analyzer as any).evidence?.provenance;
    expect(prov?.signatureVerified).toBe(true);
    expect(prov?.canonicalDigest).toBeDefined();
  });
});
