"use strict";
// Step 10: Minimal binary structural introspection (no external heavy deps)
// Extracts format, section names (best-effort), sample of import-like strings and debug indicator.
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
exports.introspectBinary = introspectBinary;
const fs = __importStar(require("fs-extra"));
function detectFormat(buf) {
    if (buf.length >= 4) {
        if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)
            return 'elf';
        if (buf[0] === 0x4d && buf[1] === 0x5a)
            return 'pe'; // MZ
        const machoMagics = [0xfeedface, 0xfeedfacf, 0xcafebabe, 0xcebafbaf];
        const magic = buf.readUInt32BE(0);
        if (machoMagics.includes(magic))
            return 'macho';
    }
    return 'unknown';
}
async function introspectBinary(binaryPath, extractedStrings) {
    const buf = await fs.readFile(binaryPath);
    const format = detectFormat(buf);
    const sizeBytes = buf.length;
    const sections = [];
    // Lightweight heuristic: search extracted strings for typical section names
    const sectionNames = ['.text', '.data', '.rodata', '.bss', '.rdata', '.pdata', '.eh_frame', '.ctors', '.dtors', '.init', '.fini'];
    for (const n of sectionNames)
        if (extractedStrings.some(s => s === n) && !sections.includes(n))
            sections.push(n);
    // Imports sample: take up to 15 strings that look like function or DLL names
    const importsSample = [];
    for (const s of extractedStrings) {
        if (/^[A-Za-z_][A-Za-z0-9_@.$-]{3,}$/.test(s) && /alloc|ssl|crypto|http|noise|betanet|tls|quic/i.test(s)) {
            importsSample.push(s);
            if (importsSample.length >= 15)
                break;
        }
    }
    const hasDebug = extractedStrings.some(s => /debug_info|__debug/.test(s));
    return { format, sections, importsSample, hasDebug, sizeBytes };
}
//# sourceMappingURL=binary-introspect.js.map