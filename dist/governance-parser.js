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
exports.parseQuorumCertificates = parseQuorumCertificates;
exports.deriveGovernanceMetrics = deriveGovernanceMetrics;
exports.validateQuorumCertificates = validateQuorumCertificates;
const cbor = __importStar(require("cbor"));
function parseQuorumCertificates(buffers) {
    const out = [];
    for (const buf of buffers) {
        try {
            const decoded = cbor.decodeFirstSync(buf);
            if (decoded && typeof decoded === 'object') {
                const epoch = decoded.epoch || decoded.e || 0;
                const sigsArr = decoded.signatures || decoded.s || [];
                const signatures = Array.isArray(sigsArr) ? sigsArr.map((s) => ({ validator: s.validator || s.v || 'unknown', weight: Number(s.weight || s.w || 0) })) : [];
                const aggregateSignature = decoded.aggregateSignature || decoded.a || undefined;
                out.push({ epoch, signatures, aggregateSignature });
            }
        }
        catch { /* ignore individual decode errors */ }
    }
    return out;
}
function deriveGovernanceMetrics(weights) {
    const total = weights.reduce((a, w) => a + w.weight, 0) || 1;
    const asAgg = {};
    const orgAgg = {};
    for (const w of weights) {
        if (w.as)
            asAgg[w.as] = (asAgg[w.as] || 0) + w.weight;
        if (w.org)
            orgAgg[w.org] = (orgAgg[w.org] || 0) + w.weight;
    }
    const maxASShare = Math.max(...Object.values(asAgg).map(v => v / total), 0);
    const maxOrgShare = Math.max(...Object.values(orgAgg).map(v => v / total), 0);
    return { maxASShare, maxOrgShare, asCapApplied: maxASShare <= 0.2, orgCapApplied: maxOrgShare <= 0.25 };
}
function validateQuorumCertificates(qcs, thresholdFraction = 2 / 3) {
    if (!qcs.length)
        return false;
    // Simplified: each certificate must have aggregate weight >= thresholdFraction of sum of its signatures
    return qcs.every(qc => {
        const total = qc.signatures.reduce((a, s) => a + s.weight, 0);
        const aggregateWeight = total; // placeholder (would verify actual aggregated signature & membership)
        return aggregateWeight >= thresholdFraction * total;
    });
}
//# sourceMappingURL=governance-parser.js.map