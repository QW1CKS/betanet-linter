import * as crypto from 'crypto';

export interface CanonicalClientHello {
  ja3: string;
  ja3Hash: string;
  ja3Canonical?: string;
  rawSynthetic?: Buffer; // existing synthetic deterministic struct
  rawCanonical?: Buffer; // improved canonical synthetic handshake record
  extensions: number[];
  ciphers: number[];
  curves: number[];
  ecPointFormats: number[];
}

// NOTE: This is still a placeholder builder; it does not sniff network packets.
// It organizes provided structural elements into a more faithful TLS ClientHello
// layout so later real packet capture can swap in without changing callers.
export function buildCanonicalClientHello(struct: {
  extensions: number[];
  ciphers: number[];
  curves?: number[];
  alpn?: string[];
  host?: string;
  seedHash?: string;
}): CanonicalClientHello {
  const { extensions, ciphers, curves = [], alpn = [], host = 'example.org', seedHash } = struct;
  const version = 771; // TLS1.2 in JA3 format
  const ecPointFormats: number[] = []; // not parsed yet
  // JA3 canonical per spec: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
  const ja3 = [
    version,
    ciphers.join('-'),
    extensions.join('-'),
    curves.join('-'),
    ecPointFormats.join('-')
  ].join(',');
  const ja3Hash = crypto.createHash('md5').update(ja3).digest('hex');
  // Provide ja3Canonical separate to allow future divergence once real capture differs
  const ja3Canonical = ja3;
  // Synthetic raw canonical already produced in harness; we only compute textual here.
  return { ja3, ja3Hash, ja3Canonical, rawSynthetic: undefined, rawCanonical: undefined, extensions, ciphers, curves, ecPointFormats };
}
