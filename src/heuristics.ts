// Heuristics utility functions for capability detection (Plan 2)
// Focus: reduce false positives via boundary-aware regex and multi-indicator logic.

interface TextSources {
  strings: string[];
  symbols: string[];
}

const toJoinedLower = (arr: string[]) => arr.join(' ').toLowerCase();

// Boundary helpers
const wordBoundary = (term: string) => new RegExp(`(^|[^a-z0-9_])${term}([^a-z0-9_]|$)`, 'i');

export function detectCrypto(src: TextSources) {
  const stringsJoined = toJoinedLower(src.strings);
  const symbolsJoined = toJoinedLower(src.symbols);

  const hasKyber = /\bkyber(512|768|1024)?\b/.test(stringsJoined) || /\bkyber(512|768|1024)?\b/.test(symbolsJoined);
  // Avoid plain '768' triggering: require kyber token above.

  return {
    hasChaCha20: /\bchacha20\b/.test(stringsJoined) || /\bchacha\b/.test(symbolsJoined),
    hasPoly1305: /\bpoly1305\b/.test(stringsJoined) || /\bpoly\b/.test(symbolsJoined),
    hasEd25519: /\bed25519\b/.test(stringsJoined) || /\bed25519\b/.test(symbolsJoined),
    hasX25519: /\bx25519\b/.test(stringsJoined) || /\bx25519\b/.test(symbolsJoined),
    hasKyber768: hasKyber && /768/.test(stringsJoined + symbolsJoined),
    hasSHA256: /\bsha-?256\b/.test(stringsJoined),
    hasHKDF: /\bhkdf\b/.test(stringsJoined) || /\bhkdf\b/.test(symbolsJoined)
  };
}

export function detectNetwork(src: TextSources) {
  const s = toJoinedLower(src.strings);
  const sy = toJoinedLower(src.symbols);
  const blob = s + ' ' + sy;

  const hasTLS = /\btls\b/.test(blob) || /\bssl\b/.test(blob) || /\bALPN:?(?:.*\bhttp\/(1\.1|2|3)\b)/i.test(blob);
  const quicIndicators = [/(^|[^a-z])quic([^a-z]|$)/, /hq-\d/, /http\/3/, /quiche/];
  const quicScore = quicIndicators.reduce((acc, r) => acc + (r.test(blob) ? 1 : 0), 0);
  const hasQUIC = quicScore >= 1; // at least one strong indicator
  const hasHTX = /\/betanet\/htx/.test(blob) || wordBoundary('htx').test(blob);
  const hasECH = /encrypted[_-]?client[_-]?hello/.test(blob) || /\bech\b/.test(blob);
  // Port 443: require separator before & non-digit after
  const port443 = /[:\[\s]443([^0-9]|$)/.test(blob);

  return { hasTLS, hasQUIC, hasHTX, hasECH, port443 };
}

export function detectSCION(src: TextSources) {
  const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
  const hasSCION = /\bscion\b/.test(blob);
  const pathManagement = hasSCION && /(path.*maintenance|path.*resolver|segcache)/.test(blob);
  const hasIPTransition = /(ip-?transition|ipv4.*ipv6|legacy.*ip.*bridge)/.test(blob);
  return { hasSCION, pathManagement, hasIPTransition };
}

export function detectDHT(src: TextSources) {
  const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
  const hasDHT = /\bdht\b/.test(blob) || /(kademlia|kad table)/.test(blob);
  const deterministicBootstrap = hasDHT && /(deterministic.*bootstrap|stable.*seed)/.test(blob);
  const seedManagement = /(seed.*(rotate|management)|bootstrap.*seed)/.test(blob);
  return { hasDHT, deterministicBootstrap, seedManagement };
}

export function detectLedger(src: TextSources) {
  const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
  const hasAliasLedger = /(alias.*ledger|ledger.*alias)/.test(blob);
  const hasConsensus = /(consensus|2-of-3|raft|pbft)/.test(blob);
  const chainSupport = /(chain.*verification|block.*verify|merkle.*root)/.test(blob);
  return { hasAliasLedger, hasConsensus, chainSupport };
}

export function detectPayment(src: TextSources) {
  const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
  const hasCashu = /\bcashu\b/.test(blob);
  // Avoid lone 'ln'; require explicit lightning tokens
  const hasLightning = /(lightning|lnurl|bolt\d|lnd)/.test(blob);
  const hasFederation = /(federation|federated|federation-mode)/.test(blob);
  return { hasCashu, hasLightning, hasFederation };
}

export function detectBuildProvenance(src: TextSources) {
  const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
  const hasSLSA = /\bslsa\b/.test(blob) || /(in-toto|provenance)/.test(blob);
  const reproducible = /(reproducible build|deterministic build|bit-for-bit)/.test(blob);
  const provenance = /(build.*provenance|attestation|slsa\.json)/.test(blob);
  return { hasSLSA, reproducible, provenance };
}
