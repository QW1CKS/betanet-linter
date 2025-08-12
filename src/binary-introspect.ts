// Step 10: Minimal binary structural introspection (no external heavy deps)
// Extracts format, section names (best-effort), sample of import-like strings and debug indicator.

import * as fs from 'fs-extra';
import * as path from 'path';

export interface BinaryIntrospection {
  format: 'elf' | 'pe' | 'macho' | 'unknown';
  sections: string[];
  importsSample: string[];
  hasDebug: boolean;
  sizeBytes: number;
}

function detectFormat(buf: Buffer): 'elf' | 'pe' | 'macho' | 'unknown' {
  if (buf.length >= 4) {
    if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return 'elf';
    if (buf[0] === 0x4d && buf[1] === 0x5a) return 'pe'; // MZ
    const machoMagics = [0xfeedface,0xfeedfacf,0xcafebabe,0xcebafbaf];
    const magic = buf.readUInt32BE(0);
    if (machoMagics.includes(magic)) return 'macho';
  }
  return 'unknown';
}

export async function introspectBinary(binaryPath: string, extractedStrings: string[]): Promise<BinaryIntrospection> {
  const buf = await fs.readFile(binaryPath);
  const format = detectFormat(buf);
  const sizeBytes = buf.length;
  const sections: string[] = [];
  // Lightweight heuristic: search extracted strings for typical section names
  const sectionNames = ['.text','.data','.rodata','.bss','.rdata','.pdata','.eh_frame','.ctors','.dtors','.init','.fini'];
  for (const n of sectionNames) if (extractedStrings.some(s => s === n) && !sections.includes(n)) sections.push(n);
  // Imports sample: take up to 15 strings that look like function or DLL names
  const importsSample: string[] = [];
  for (const s of extractedStrings) {
    if (/^[A-Za-z_][A-Za-z0-9_@.$-]{3,}$/.test(s) && /alloc|ssl|crypto|http|noise|betanet|tls|quic/i.test(s)) {
      importsSample.push(s);
      if (importsSample.length >= 15) break;
    }
  }
  const hasDebug = extractedStrings.some(s => /debug_info|__debug/.test(s));
  return { format, sections, importsSample, hasDebug, sizeBytes };
}
