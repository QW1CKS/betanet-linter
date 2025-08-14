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
exports.evaluateHistoricalDiversity = evaluateHistoricalDiversity;
exports.evaluateHistoricalDiversityAdvanced = evaluateHistoricalDiversityAdvanced;
const cbor = __importStar(require("cbor"));
function parseQuorumCertificates(buffers) {
    const out = [];
    for (const buf of buffers) {
        try {
            const decoded = cbor.decodeFirstSync(buf);
            if (decoded && typeof decoded === 'object') {
                const epoch = decoded.epoch || decoded.e || 0;
                const sigsArr = decoded.signatures || decoded.s || [];
                const signatures = Array.isArray(sigsArr) ? sigsArr.map((s) => ({ validator: s.validator || s.v || 'unknown', weight: Number(s.weight || s.w || 0), sig: s.sig || s.sg || undefined })) : [];
                const aggregateSignature = decoded.aggregateSignature || decoded.a || undefined;
                const rootHash = decoded.rootHash || decoded.r || undefined;
                out.push({ epoch, signatures, aggregateSignature, rootHash });
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
function validateQuorumCertificates(qcs, thresholdFraction = 2 / 3, opts) {
    const reasons = [];
    if (!qcs.length)
        return { valid: false, reasons: ['no-certificates'] };
    let lastEpoch = -1;
    let lastRootHash;
    const needRoot = !!opts?.requireSignatures; // only strictly require when signatures enforced
    for (const qc of qcs) {
        if (qc.epoch <= lastEpoch) {
            reasons.push('epoch-not-monotonic');
            return { valid: false, reasons };
        }
        lastEpoch = qc.epoch;
        if (needRoot && !qc.rootHash) {
            reasons.push(`missing-root-hash-epoch-${qc.epoch}`);
            return { valid: false, reasons };
        }
        if (qc.rootHash) {
            if (lastRootHash && qc.rootHash === lastRootHash) {
                reasons.push(`root-hash-repeat-epoch-${qc.epoch}`);
                return { valid: false, reasons };
            }
            lastRootHash = qc.rootHash;
        }
    }
    const totalGov = opts?.governanceTotalWeight || 0;
    const useGovWeight = totalGov > 0;
    // Lazy load crypto via dynamic import pattern to satisfy lint (kept inside for conditional usage)
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require('crypto');
    for (const qc of qcs) {
        const sigTotal = qc.signatures.reduce((a, s) => a + s.weight, 0);
        const base = useGovWeight ? totalGov : sigTotal;
        if (sigTotal < thresholdFraction * base) {
            reasons.push(`threshold-fail-epoch-${qc.epoch}`);
            return { valid: false, reasons };
        }
        if (opts?.requireSignatures) {
            for (const s of qc.signatures) {
                const pkPem = opts.validatorKeys?.[s.validator];
                if (!pkPem || !s.sig) {
                    reasons.push(`missing-sig-${s.validator}`);
                    return { valid: false, reasons };
                }
                const message = Buffer.from(`epoch:${qc.epoch}|root:${qc.rootHash || 'none'}`);
                try {
                    let ok = false;
                    try {
                        ok = crypto.verify(null, message, pkPem, Buffer.from(s.sig, 'base64'));
                    }
                    catch { /* possibly not ed25519 */ }
                    if (!ok) {
                        try {
                            const verifier = crypto.createVerify('SHA256');
                            verifier.update(message);
                            verifier.end();
                            ok = verifier.verify(pkPem, Buffer.from(s.sig, 'base64'));
                        }
                        catch { /* ignore */ }
                    }
                    if (!ok) {
                        reasons.push(`bad-sig-${s.validator}`);
                        return { valid: false, reasons };
                    }
                }
                catch {
                    reasons.push(`sig-error-${s.validator}`);
                    return { valid: false, reasons };
                }
            }
        }
    }
    return { valid: true, reasons };
}
function evaluateHistoricalDiversity(series, cap = 0.2) {
    if (!series || !series.length)
        return { stable: false, maxASShare: 1, avgTop3: 1 };
    let maxASShare = 0;
    let top3Accum = 0;
    for (const point of series) {
        const shares = Object.values(point.asShares || {});
        if (!shares.length)
            continue;
        shares.sort((a, b) => b - a);
        maxASShare = Math.max(maxASShare, shares[0]);
        top3Accum += (shares[0] + (shares[1] || 0) + (shares[2] || 0)) / 3;
    }
    const avgTop3 = top3Accum / series.length;
    const stable = maxASShare <= cap && avgTop3 <= cap * 1.2; // allow slight leeway
    return { stable, maxASShare, avgTop3 };
}
function evaluateHistoricalDiversityAdvanced(series, cap = 0.2, window = 3) {
    if (!series || !series.length)
        return { advancedStable: false, volatility: 1, maxWindowShare: 1, maxDeltaShare: 1 };
    const windows = [];
    let maxDeltaShare = 0;
    // Track per-AS previous share to compute deltas
    let prevPoint;
    for (let i = 0; i < series.length; i++) {
        const point = series[i];
        const slice = series.slice(Math.max(0, i - window + 1), i + 1);
        let localMax = 0;
        for (const p of slice) {
            const shares = Object.values(p.asShares || {});
            if (!shares.length)
                continue;
            localMax = Math.max(localMax, Math.max(...shares));
        }
        windows.push(localMax);
        // Delta computation
        if (prevPoint) {
            const asKeys = new Set([...Object.keys(prevPoint), ...Object.keys(point.asShares || {})]);
            for (const k of asKeys) {
                const prev = prevPoint[k] || 0;
                const curr = (point.asShares || {})[k] || 0;
                maxDeltaShare = Math.max(maxDeltaShare, Math.abs(curr - prev));
            }
        }
        prevPoint = { ...(point.asShares || {}) };
    }
    const maxWindowShare = Math.max(...windows, 0);
    const mean = windows.reduce((a, b) => a + b, 0) / windows.length;
    const variance = windows.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / windows.length;
    const volatility = Math.sqrt(variance);
    // Advanced stability now requires low concentration, low volatility AND controlled per-interval delta (<=5%)
    const advancedStable = maxWindowShare <= cap && volatility <= 0.05 && maxDeltaShare <= 0.05;
    return { advancedStable, volatility, maxWindowShare, maxDeltaShare };
}
//# sourceMappingURL=governance-parser.js.map