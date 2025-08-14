import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

describe('Task 28 provenance & SBOM attestations', () => {
  const tmp = path.join(__dirname,'attest-fixtures');
  const bin = path.join(tmp,'dummy.bin');
  beforeAll(()=>{ fs.mkdirSync(tmp,{recursive:true}); fs.writeFileSync(bin,'bin'); });
  afterAll(()=>{ try { fs.rmSync(tmp,{recursive:true,force:true}); } catch {} });

  it('verifies provenance attestation signature over raw evidence file', async () => {
    const evidence = { predicateType:'slsa', predicate:{ builder:{ id:'builder://att' } }, subject:[{ name:'artifact', digest:{ sha256:'a'.repeat(64) } }] };
    const evidenceFile = path.join(tmp,'evidence.json'); fs.writeFileSync(evidenceFile, JSON.stringify(evidence, null, 2));
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const raw = fs.readFileSync(evidenceFile,'utf8');
    const canon = raw; // attestation binds raw file
    const sig = crypto.sign(null, Buffer.from(canon), privateKey).toString('base64');
    const sigFile = path.join(tmp,'evidence.att.sig'); fs.writeFileSync(sigFile, sig);
    const pubDer = publicKey.export({ format:'der', type:'spki' }) as Buffer;
    const pubFile = path.join(tmp,'evidence.att.pub'); fs.writeFileSync(pubFile, pubDer.toString('base64'));
    const checker = new BetanetComplianceChecker();
    const res = await checker.checkCompliance(bin,{ evidenceFile, provenanceAttestationSignatureFile: sigFile, provenanceAttestationPublicKeyFile: pubFile, strictAuthMode:true });
    const prov = (checker.analyzer as any).evidence?.provenance;
    expect(prov?.provenanceAttestationSignatureVerified).toBe(true);
    // Authenticity check should pass (id 35)
    const auth = res.checks.find(c => c.id === 35);
    expect(auth?.passed).toBe(true);
  }, 15000);

  it('flags missing SBOM attestation in strictAuth mode with failure code', async () => {
    const evidence = { predicateType:'slsa', predicate:{ builder:{ id:'builder://att2' } }, subject:[{ name:'artifact', digest:{ sha256:'b'.repeat(64) } }] };
    const evidenceFile = path.join(tmp,'evidence2.json'); fs.writeFileSync(evidenceFile, JSON.stringify(evidence));
    const checker = new BetanetComplianceChecker();
    const res = await checker.checkCompliance(bin,{ evidenceFile, strictAuthMode:true });
    const auth = res.checks.find(c => c.id === 35);
    expect(auth?.passed).toBe(false);
    expect(auth?.details).toContain('SBOM_ATTESTATION_MISSING');
  }, 15000);

  it('verifies SBOM attestation signature and surfaces digest', async () => {
    const sbom = { components:[{ name:'pkg', version:'1.0.0', hashes:[{ alg:'SHA-256', content:'c'.repeat(64) }] }] };
    const sbomFile = path.join(tmp,'sbom.json'); fs.writeFileSync(sbomFile, JSON.stringify(sbom));
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const sig = crypto.sign(null, Buffer.from(fs.readFileSync(sbomFile,'utf8')), privateKey).toString('base64');
    const sigFile = path.join(tmp,'sbom.sig'); fs.writeFileSync(sigFile, sig);
    const pubDer = publicKey.export({ format:'der', type:'spki' }) as Buffer; const pubFile = path.join(tmp,'sbom.pub'); fs.writeFileSync(pubFile, pubDer.toString('base64'));
    const evidence = { predicateType:'slsa', predicate:{ builder:{ id:'builder://att3' } }, subject:[{ name:'artifact', digest:{ sha256:'d'.repeat(64) } }] };
    const evidenceFile = path.join(tmp,'evidence3.json'); fs.writeFileSync(evidenceFile, JSON.stringify(evidence));
    const checker = new BetanetComplianceChecker();
    const res = await checker.checkCompliance(bin,{ evidenceFile, sbomFile, sbomAttestationSignatureFile: sigFile, sbomAttestationPublicKeyFile: pubFile, strictAuthMode:true });
    const prov = (checker.analyzer as any).evidence?.provenance;
    expect(prov?.sbomAttestationSignatureVerified).toBe(true);
    const auth = res.checks.find(c => c.id === 35);
    expect(auth?.passed).toBe(true);
  }, 15000);
});
