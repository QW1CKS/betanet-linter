import { introspectBinary } from '../src/binary-introspect';
import * as fs from 'fs';
import * as path from 'path';

describe('binary-introspect format & heuristics', () => {
  const tmp = path.join(__dirname,'tmp-introspect');
  const elf = path.join(tmp,'a.elf');
  const pe = path.join(tmp,'b.exe');
  const macho = path.join(tmp,'c.macho');
  const unknown = path.join(tmp,'d.bin');

  beforeAll(()=>{
    fs.mkdirSync(tmp,{recursive:true});
    fs.writeFileSync(elf, Buffer.from([0x7f,0x45,0x4c,0x46,0x00]));
    fs.writeFileSync(pe, Buffer.from([0x4d,0x5a,0x90,0x00]));
    const machoBuf = Buffer.alloc(8); machoBuf.writeUInt32BE(0xfeedface,0); fs.writeFileSync(macho,machoBuf);
    fs.writeFileSync(unknown, Buffer.from([0x00,0x01,0x02]));
  });
  afterAll(()=>{ try { fs.rmSync(tmp,{recursive:true,force:true}); } catch {} });

  it('detects ELF', async () => {
    const res = await introspectBinary(elf, ['.text','.data']);
    expect(res.format).toBe('elf');
    expect(res.sections).toContain('.text');
  });
  it('detects PE', async () => {
    const res = await introspectBinary(pe, ['betanet_tls_alloc']);
    expect(res.format).toBe('pe');
    expect(res.importsSample.some(s=>/alloc/.test(s))).toBe(true);
  });
  it('detects Mach-O', async () => {
    const res = await introspectBinary(macho, ['__debug']);
    expect(res.format).toBe('macho');
    expect(res.hasDebug).toBe(true);
  });
  it('falls back to unknown', async () => {
    const res = await introspectBinary(unknown, []);
    expect(res.format).toBe('unknown');
  });
});
