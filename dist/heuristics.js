"use strict";
// Heuristics utility functions for capability detection (Plan 2)
// Focus: reduce false positives via boundary-aware regex and multi-indicator logic.
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectCrypto = detectCrypto;
exports.detectNetwork = detectNetwork;
exports.detectSCION = detectSCION;
exports.detectDHT = detectDHT;
exports.detectLedger = detectLedger;
exports.detectPayment = detectPayment;
exports.detectBuildProvenance = detectBuildProvenance;
exports.evaluatePrivacyTokens = evaluatePrivacyTokens;
const toJoinedLower = (arr) => arr.join(' ').toLowerCase();
// Boundary helpers
const wordBoundary = (term) => new RegExp(`(^|[^a-z0-9_])${term}([^a-z0-9_]|$)`, 'i');
function detectCrypto(src) {
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
function detectNetwork(src) {
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
    const port443 = /[:\s[]443([^0-9]|$)/.test(blob); // simplified character class without unnecessary escape
    const hasWebRTC = /\/betanet\/webrtc\//.test(blob) || /webrtc/.test(blob);
    return { hasTLS, hasQUIC, hasHTX, hasECH, port443, hasWebRTC };
}
function detectSCION(src) {
    const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
    const hasSCION = /\bscion\b/.test(blob);
    const pathManagement = hasSCION && /(path.*maintenance|path.*resolver|segcache)/.test(blob);
    const hasIPTransition = /(ip-?transition|ipv4.*ipv6|legacy.*ip.*bridge)/.test(blob);
    // Path diversity heuristic: detect multiple AS/path markers (as123, as-1234, pathid:, scion://)
    const diversityMatches = blob.match(/\bas[-]?[0-9]{2,5}\b|pathid[:=][a-f0-9]+|scion:\/\//g) || [];
    const uniqueDiversity = new Set(diversityMatches.map(m => m.toLowerCase()));
    return { hasSCION, pathManagement, hasIPTransition, pathDiversityCount: uniqueDiversity.size };
}
function detectDHT(src) {
    const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
    const hasDHT = /\bdht\b/.test(blob) || /(kademlia|kad table|rendezvous dht)/.test(blob);
    const deterministicBootstrap = hasDHT && /(deterministic.*bootstrap|stable.*seed)/.test(blob); // legacy 1.0 heuristic
    const rotationTokens = /(rendezvous|beaconset|epoch|rotate|rotation|bn-seed|schedule)/g;
    let match;
    let rotationHits = 0;
    const seen = new Set();
    // eslint-disable-next-line no-constant-condition -- deliberate regex iteration using exec until null
    while (true) {
        match = rotationTokens.exec(blob);
        if (!match)
            break;
        const token = match[0];
        if (!seen.has(token + match.index)) {
            rotationHits++;
            seen.add(token + match.index);
        }
    }
    const rendezvousRotation = rotationHits >= 2; // require at least two distinct rotation-related indicators
    const beaconSetIndicator = /beaconset\(/.test(blob) || /bn-seed/.test(blob) || /epoch/.test(blob);
    const seedManagement = /(seed.*(rotate|management)|bootstrap.*seed)/.test(blob);
    return { hasDHT, deterministicBootstrap, rendezvousRotation, beaconSetIndicator, seedManagement, rotationHits };
}
function detectLedger(src) {
    const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
    const hasAliasLedger = /(alias.*ledger|ledger.*alias)/.test(blob);
    const hasConsensus = /(consensus|2-of-3|raft|pbft)/.test(blob);
    const chainSupport = /(chain.*verification|block.*verify|merkle.*root)/.test(blob);
    return { hasAliasLedger, hasConsensus, chainSupport };
}
function detectPayment(src) {
    const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
    const hasCashu = /\bcashu\b/.test(blob);
    // Avoid lone 'ln'; require explicit lightning tokens
    const hasLightning = /(lightning|lnurl|bolt\d|lnd)/.test(blob);
    const hasFederation = /(federation|federated|federation-mode)/.test(blob);
    // Voucher structural heuristic (128 bytes: keysetID32 + secret32 + aggregatedSig64) textual hints
    const voucherRegex = /(keysetid32\s+secret32\s+aggregatedsig64)|(voucher\s*128\s*b)|((?:keysetid|secret|aggregatedsig)32)/;
    const hasVoucherFormat = voucherRegex.test(blob) || /(bn1=)[A-Za-z0-9_-]{10,}/.test(blob);
    const hasFROST = /frost-?ed25519/.test(blob) || /frost group/.test(blob);
    // PoW difficulty context: match pow=22, pow 22-bit, 22-bit pow, difficulty:22 etc.
    const hasPoW22 = /(pow\s*[=:]?\s*22\b|22-?bit\s+pow|pow[^a-z0-9]{0,5}22-?bit|difficulty\s*[:=]\s*22)/.test(blob);
    return { hasCashu, hasLightning, hasFederation, hasVoucherFormat, hasFROST, hasPoW22 };
}
function detectBuildProvenance(src) {
    const blob = toJoinedLower(src.strings).concat(' ', toJoinedLower(src.symbols));
    const hasSLSA = /\bslsa\b/.test(blob) || /(in-toto|provenance)/.test(blob);
    const reproducible = /(reproducible build|deterministic build|bit-for-bit)/.test(blob);
    const provenance = /(build.*provenance|attestation|slsa\.json)/.test(blob);
    return { hasSLSA, reproducible, provenance };
}
// Privacy hop weighting utility for check 11 refinement
function evaluatePrivacyTokens(strings) {
    const blob = toJoinedLower(strings);
    const mixTokens = ['nym', 'mixnode', 'hop', 'hopset', 'relay'];
    const beaconTokens = ['beaconset', 'epoch', 'drand'];
    const diversityTokens = ['diversity', 'distinct', 'as-group', 'asgroup', 'vrf'];
    const scoreCategory = (list) => list.reduce((acc, t) => acc + (new RegExp(`(^|[^a-z0-9])${t}([^a-z0-9]|$)`).test(blob) ? 1 : 0), 0);
    const mixScore = scoreCategory(mixTokens);
    const beaconScore = scoreCategory(beaconTokens);
    const diversityScore = scoreCategory(diversityTokens);
    const totalScore = mixScore * 2 + beaconScore * 2 + diversityScore * 3; // weight diversity highest
    // Require stronger combined signal: either ≥2 mix + ≥1 beacon + ≥1 diversity, OR high diversity (≥2) plus any mix+beacon each
    const passed = (mixScore >= 2 && beaconScore >= 1 && diversityScore >= 1) || (diversityScore >= 2 && mixScore >= 1 && beaconScore >= 1);
    return { mixScore, beaconScore, diversityScore, totalScore, passed };
}
//# sourceMappingURL=heuristics.js.map