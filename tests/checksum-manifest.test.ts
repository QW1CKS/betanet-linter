import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

// Task 28: checksum manifest signature verification contributes to authenticity (Check 35)

describe('Task 28 checksum manifest attestation', () => {
  const tmp = path.join(__dirname,'manifest-fixtures');
  const bin = path.join(tmp,'dummy.bin');
  beforeAll(()=>{ fs.mkdirSync(tmp,{recursive:true}); fs.writeFileSync(bin,'bin'); });
  afterAll(()=>{ try { fs.rmSync(tmp,{recursive:true,force:true}); } catch {} });

  it('accepts valid signed checksum manifest (ed25519 raw 32B key)', async () => {
    const manifest = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  fileA\n';
    const manifestFile = path.join(tmp,'checksums.txt'); fs.writeFileSync(manifestFile, manifest);
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const sig = crypto.sign(null, Buffer.from(manifest), privateKey).toString('base64');
    const sigFile = path.join(tmp,'checksums.sig'); fs.writeFileSync(sigFile, sig);
    // export raw 32B ed25519 key
    const pubDer = publicKey.export({ format:'der', type:'spki' }) as Buffer;
    // strip DER prefix if present (last 32 bytes are raw key) for raw mode test
    const raw32 = pubDer.slice(-32); const pubFile = path.join(tmp,'checksums.pub'); fs.writeFileSync(pubFile, raw32.toString('base64'));
    const checker = new BetanetComplianceChecker();
    const res = await checker.checkCompliance(bin,{ checksumManifestFile: manifestFile, checksumManifestSignatureFile: sigFile, checksumManifestPublicKeyFile: pubFile, strictAuthMode:true });
    const provenance = (checker.analyzer as any).evidence?.provenance;
    expect(provenance?.checksumManifestSignatureVerified).toBe(true);
    const auth = res.checks.find(c=>c.id===35);
    expect(auth?.passed).toBe(true);
    expect(auth?.details).toContain('checksum-manifest');
  }, 15000);

  it('flags invalid checksum manifest signature in strict auth mode', async () => {
    const manifest = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  fileB\n';
    const manifestFile = path.join(tmp,'checksums2.txt'); fs.writeFileSync(manifestFile, manifest);
    const { publicKey } = crypto.generateKeyPairSync('ed25519');
    const wrongSig = 'AAAA'+Buffer.from('not-a-valid-signature').toString('base64');
    const sigFile = path.join(tmp,'checksums2.sig'); fs.writeFileSync(sigFile, wrongSig);
  const pubDer = publicKey.export({ format:'der', type:'spki' }) as Buffer; const pubFile = path.join(tmp,'checksums2.pub'); fs.writeFileSync(pubFile, pubDer.toString('base64'));
    const checker = new BetanetComplianceChecker();
    const res = await checker.checkCompliance(bin,{ checksumManifestFile: manifestFile, checksumManifestSignatureFile: sigFile, checksumManifestPublicKeyFile: pubFile, strictAuthMode:true });
    const provenance = (checker.analyzer as any).evidence?.provenance;
    expect(provenance?.checksumManifestSignatureVerified).toBe(false);
    const auth = res.checks.find(c=>c.id===35);
    expect(auth?.passed).toBe(false);
    expect(auth?.details).toContain('MISSING_AUTH_SIGNALS'); // manifest alone invalid, no other auth signals
  }, 15000);
});
