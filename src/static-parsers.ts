// Static structural parsers (Phase 1 / Step 4 groundwork)
// Lightweight pattern extraction from already-extracted strings.
// Future enhancements will operate on binary sections / parsed protocol templates.

import * as crypto from 'crypto';

export interface ClientHelloStatic {
  alpn: string[];
  extOrderSha256?: string; // stable hash over detected extension ordering placeholder
  detected: boolean;
  extensions?: number[]; // ordered list of recognized TLS extension numeric codes
  extensionNames?: string[]; // parallel human-friendly names
}

export interface NoiseStatic {
  pattern?: string; // e.g. XK, XX
  messageCount?: number; // placeholder (future real derivation)
  detected: boolean;
}

export interface VoucherStatic {
  structLikely: boolean;
  tokenHits: string[];
  proximityBytes?: number; // span between first and last token occurrence in binary
}

export interface StaticPatterns {
  clientHello?: ClientHelloStatic;
  noise?: NoiseStatic;
  voucher?: VoucherStatic;
}

// Naive ALPN extraction: search for well-known ALPN strings and preserve first-seen order.
export function parseClientHelloStrings(strings: string[]): ClientHelloStatic | undefined {
  const alpnCandidates = ['h2', 'http/1.1', 'hq-29', 'hq-interop', 'betanet-htx'];
  const alpn: string[] = [];
  for (const s of strings) {
    for (const c of alpnCandidates) {
      if ((s === c || s.includes(c)) && !alpn.includes(c)) alpn.push(c);
    }
  }
  if (!alpn.length) return undefined;
  // TLS extension name -> numeric code (subset sufficient for ordering hash)
  const extMap: Record<string, number> = {
    server_name: 0,
    status_request: 5,
    supported_groups: 10,
    ec_point_formats: 11,
    signature_algorithms: 13,
    application_layer_protocol_negotiation: 16,
    signed_certificate_timestamp: 18,
    padding: 21,
    encrypt_then_mac: 22,
    extended_master_secret: 23,
    record_size_limit: 28,
    session_ticket: 35,
    pre_shared_key: 41,
    early_data: 42,
    supported_versions: 43,
    cookie: 44,
    psk_key_exchange_modes: 45,
    key_share: 51,
    renegotiation_info: 0xff01
  };
  const extOrder: number[] = [];
  const extNames: string[] = [];
  const namePatterns = Object.keys(extMap);
  for (const s of strings) {
    for (const n of namePatterns) {
      if (s.includes(n) && !extNames.includes(n)) {
        extNames.push(n);
        extOrder.push(extMap[n]);
      }
    }
  }
  const hashBasis = alpn.join('|') + '::' + extOrder.join('-');
  const extOrderSha256 = crypto.createHash('sha256').update(hashBasis).digest('hex');
  return { alpn, extOrderSha256, detected: true, extensions: extOrder, extensionNames: extNames };
}

// Noise pattern detection: look for tokens like 'Noise_XK', 'Noise_XX', or separate 'noise' + pattern markers.
export function detectNoisePattern(strings: string[]): NoiseStatic | undefined {
  const joined = strings.join('\n');
  const direct = joined.match(/Noise_([A-Z]{2})/);
  if (direct) {
    return { pattern: direct[1], messageCount: undefined, detected: true };
  }
  if (/noise/i.test(joined) && /XK/.test(joined)) {
    return { pattern: 'XK', detected: true };
  }
  return undefined;
}

// Voucher struct heuristic: presence of keysetid32 + secret32 + aggregatedsig64 tokens suggests 128B struct usage.
export function detectVoucherStruct(strings: string[], binary?: Buffer): VoucherStatic | undefined {
  const tokens = ['keysetid32', 'secret32', 'aggregatedsig64'];
  const lowerStrings = strings.map(s => s.toLowerCase());
  const hits = tokens.filter(t => lowerStrings.some(s => s.includes(t)));
  if (!hits.length) return undefined;
  let proximity: number | undefined;
  if (binary) {
    let min = Number.MAX_SAFE_INTEGER;
    let max = 0;
    for (const t of tokens) {
      const idx = binary.indexOf(Buffer.from(t));
      if (idx >= 0) {
        if (idx < min) min = idx;
        if (idx > max) max = idx;
      }
    }
    if (min !== Number.MAX_SAFE_INTEGER && max > 0) proximity = max - min;
  }
  const structLikely = hits.length === tokens.length && (proximity === undefined || proximity <= 512);
  return { structLikely, tokenHits: hits, proximityBytes: proximity };
}

export function extractStaticPatterns(strings: string[], binary?: Buffer): StaticPatterns {
  const result: StaticPatterns = {};
  const ch = parseClientHelloStrings(strings);
  if (ch) result.clientHello = ch;
  const noise = detectNoisePattern(strings);
  if (noise) result.noise = noise;
  const voucher = detectVoucherStruct(strings, binary as any);
  if (voucher) result.voucher = voucher;
  return result;
}
