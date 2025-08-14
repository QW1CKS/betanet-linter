import * as crypto from 'crypto';

export interface ParsedRawClientHello {
  version?: number;
  ciphers: number[];
  extensions: number[];
  groups: number[];
  ecPointFormats: number[];
  ja3: string;
  ja3Hash: string;
}

// Best-effort TLS ClientHello parser for raw bytes (record + handshake).
// Accepts a Buffer containing at least one TLS record with a ClientHello handshake.
export function parseRawClientHello(buf: Buffer): ParsedRawClientHello {
  const result: ParsedRawClientHello = { ciphers: [], extensions: [], groups: [], ecPointFormats: [], ja3: '', ja3Hash: '' };
  try {
    let offset = 0;
    // TLS record header: 5 bytes (ContentType, Version(2), Length(2))
    if (buf.length < 5 || buf[offset] !== 0x16) return result; // not handshake record
    offset += 5; // skip record header (we trust length for minimal validation)
    if (offset + 4 > buf.length) return result; // need handshake header
    const hsType = buf[offset];
    if (hsType !== 0x01) return result; // not ClientHello
    const hsLen = (buf[offset+1] << 16) | (buf[offset+2] << 8) | buf[offset+3];
    offset += 4;
    if (offset + hsLen > buf.length) return result; // truncated
    const bodyStart = offset;
    // version
    if (offset + 2 > buf.length) return result;
    result.version = (buf[offset] << 8) | (buf[offset+1]);
    offset += 2;
    // random 32 bytes
    offset += 32;
    if (offset > buf.length) return result;
    // session id
    if (offset + 1 > buf.length) return result;
    const sidLen = buf[offset];
    offset += 1 + sidLen;
    // cipher suites
    if (offset + 2 > buf.length) return result;
    const cipherBytes = (buf[offset] << 8) | buf[offset+1];
    offset += 2;
    for (let i = 0; i < cipherBytes; i += 2) {
      if (offset + 2 > buf.length) break;
      const cs = (buf[offset] << 8) | buf[offset+1];
      result.ciphers.push(cs);
      offset += 2;
    }
    // compression methods
    if (offset + 1 > buf.length) return result;
    const compLen = buf[offset];
    offset += 1 + compLen;
    // extensions
    if (offset + 2 > buf.length) return finalize(result);
    const extTotal = (buf[offset] << 8) | buf[offset+1];
    offset += 2;
    let extRead = 0;
    while (extRead + 4 <= extTotal && offset + 4 <= buf.length && offset < bodyStart + hsLen) {
      const extType = (buf[offset] << 8) | buf[offset+1];
      const extLen = (buf[offset+2] << 8) | buf[offset+3];
      offset += 4;
      extRead += 4 + extLen;
      result.extensions.push(extType);
      if (extType === 0x000a && extLen >= 2) { // supported_groups
        const listLen = (buf[offset] << 8) | buf[offset+1];
        let cOff = offset + 2;
        while (cOff + 1 < offset + 2 + listLen && cOff + 1 < buf.length) {
          result.groups.push((buf[cOff] << 8) | buf[cOff+1]);
          cOff += 2;
        }
      } else if (extType === 0x000b && extLen >= 1) { // ec_point_formats
        const fmtLen = buf[offset];
        for (let fOff = offset + 1; fOff < offset + 1 + fmtLen && fOff < buf.length; fOff++) {
          result.ecPointFormats.push(buf[fOff]);
        }
      }
      offset += extLen;
    }
  } catch { /* swallow parse errors */ }
  return finalize(result);
}

function finalize(r: ParsedRawClientHello): ParsedRawClientHello {
  const version = r.version ?? 0;
  const ja3 = [
    version,
    r.ciphers.join('-'),
    r.extensions.join('-'),
    r.groups.join('-'),
    r.ecPointFormats.join('-')
  ].join(',');
  r.ja3 = ja3;
  r.ja3Hash = crypto.createHash('md5').update(ja3).digest('hex');
  return r;
}

export function detectGrease(extensions: number[]): { greasePresent: boolean; greaseValues: number[] } {
  const GREASE = new Set([0x0a0a,0x1a1a,0x2a2a,0x3a3a,0x4a4a,0x5a5a,0x6a6a,0x7a7a,0x8a8a,0x9a9a,0xaaaa,0xbaba,0xcaca,0xdada,0xeaea,0xfafa]);
  const values = extensions.filter(e => GREASE.has(e));
  return { greasePresent: values.length > 0, greaseValues: values };
}
