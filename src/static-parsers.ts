// Static structural parsers (Phase 1 / Step 4 groundwork)
// Lightweight pattern extraction from already-extracted strings.
// Future enhancements will operate on binary sections / parsed protocol templates.

import * as crypto from 'crypto';

export interface ClientHelloStatic {
  alpn: string[];
  extOrderSha256?: string; // stable hash over detected extension ordering placeholder
  detected: boolean;
}

export interface NoiseStatic {
  pattern?: string; // e.g. XK, XX
  messageCount?: number; // placeholder (future real derivation)
  detected: boolean;
}

export interface VoucherStatic {
  structLikely: boolean;
  tokenHits: string[];
}

export interface StaticPatterns {
  clientHello?: ClientHelloStatic;
  noise?: NoiseStatic;
  voucher?: VoucherStatic;
}

// Naive ALPN extraction: search for well-known ALPN strings and preserve first-seen order.
export function parseClientHelloStrings(strings: string[]): ClientHelloStatic | undefined {
  const candidates = ['h2', 'http/1.1', 'hq-29', 'hq-interop', 'betanet-htx'];
  const seen: string[] = [];
  for (const s of strings) {
    for (const c of candidates) {
      if (s === c || s.includes(c)) {
        if (!seen.includes(c)) seen.push(c);
      }
    }
  }
  if (!seen.length) return undefined;
  const extOrderSha256 = crypto.createHash('sha256').update(seen.join('|')).digest('hex');
  return { alpn: seen, extOrderSha256, detected: true };
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
export function detectVoucherStruct(strings: string[]): VoucherStatic | undefined {
  const tokens = ['keysetid32', 'secret32', 'aggregatedsig64'];
  const hits = tokens.filter(t => strings.some(s => s.toLowerCase().includes(t)));
  if (hits.length === tokens.length) {
    return { structLikely: true, tokenHits: hits };
  }
  if (hits.length) {
    return { structLikely: false, tokenHits: hits };
  }
  return undefined;
}

export function extractStaticPatterns(strings: string[]): StaticPatterns {
  const result: StaticPatterns = {};
  const ch = parseClientHelloStrings(strings);
  if (ch) result.clientHello = ch;
  const noise = detectNoisePattern(strings);
  if (noise) result.noise = noise;
  const voucher = detectVoucherStruct(strings);
  if (voucher) result.voucher = voucher;
  return result;
}
