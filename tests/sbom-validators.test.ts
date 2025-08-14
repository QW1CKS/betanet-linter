import { validateCycloneDXShape, validateCycloneDXStrict, validateSPDXTagValue, validateSPDXTagValueStrict } from '../src/sbom/sbom-validators';

describe('sbom validators strict & negative branches', () => {
  it('flags missing core CycloneDX fields', () => {
    const res = validateCycloneDXShape({});
    expect(res.valid).toBe(false);
    expect(res.errors.some(e=>/bomFormat/.test(e))).toBe(true);
  });
  it('valid strict CycloneDX with hashes & dependencies', () => {
    const doc:any = {
      bomFormat:'CycloneDX', specVersion:'1.4', metadata:{ component:{ name:'app', version:'1.0.0', purl:'pkg:npm/app@1.0.0', hashes:[{alg:'SHA-256',content:'abc'}] } },
      serialNumber:'urn:uuid:12345678-1234-1234-1234-123456789abc', version:1,
      components:[{ name:'lib', version:'2.0.0', type:'library' }],
      dependencies:[{ ref:'app', dependsOn:['lib'] }]
    };
    const res = validateCycloneDXStrict(doc);
    expect(res.valid).toBe(true);
  });
  it('strict CycloneDX dependency ref mismatch', () => {
    const doc:any = { bomFormat:'CycloneDX', specVersion:'1.4', metadata:{ component:{ name:'root', version:'1', purl:'pkg:generic/root@1' } }, serialNumber:'urn:uuid:12345678-1234-1234-1234-123456789abc', version:1, dependencies:[{ ref:'root', dependsOn:['missing'] }] };
    const res = validateCycloneDXStrict(doc);
    expect(res.valid).toBe(false);
    expect(res.errors.some(e=>/unknown dependsOn/.test(e))).toBe(true);
  });
  it('validates SPDX tag-value basic & strict', () => {
    const base = `SPDXVersion: SPDX-2.3\nDocumentNamespace: https://example.com/spdx/doc\nDocumentName: test\nPackageName: pkg\nPackageLicenseDeclared: MIT`;
    const basic = validateSPDXTagValue(base);
    expect(basic.valid).toBe(true);
    const strict = validateSPDXTagValueStrict(base + "\nPackageChecksum: SHA256: " + 'a'.repeat(64));
    expect(strict.valid).toBe(true);
  });
  it('rejects SPDX strict checksum format', () => {
    const baseInvalid = `SPDXVersion: SPDX-2.3\nDocumentNamespace: https://x\nDocumentName: test\nPackageName: pkg\nPackageLicenseDeclared: MIT\nPackageChecksum: SHA256: short`;
    const res = validateSPDXTagValueStrict(baseInvalid);
    expect(res.valid).toBe(false);
    expect(res.errors.some(e=>/Invalid SHA256/.test(e))).toBe(true);
  });
});
