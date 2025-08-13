"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildCanonicalClientHello = buildCanonicalClientHello;
const crypto = __importStar(require("crypto"));
// NOTE: This is still a placeholder builder; it does not sniff network packets.
// It organizes provided structural elements into a more faithful TLS ClientHello
// layout so later real packet capture can swap in without changing callers.
function buildCanonicalClientHello(struct) {
    const { extensions, ciphers, curves = [], alpn = [], host = 'example.org', seedHash } = struct;
    const version = 771; // TLS1.2 in JA3 format
    const ecPointFormats = []; // not parsed yet
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
//# sourceMappingURL=tls-capture.js.map