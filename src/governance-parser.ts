import * as cbor from 'cbor';

export interface QuorumCertificate {
  epoch: number;
  signatures: { validator: string; weight: number; sig?: string }[]; // sig: base64 (optional)
  aggregateSignature?: string;
  rootHash?: string; // optional state root
}

export interface GovernanceSnapshotDerived {
  maxASShare?: number;
  maxOrgShare?: number;
  asCapApplied?: boolean;
  orgCapApplied?: boolean;
  partitionsDetected?: boolean;
  quorumCertificatesValid?: boolean;
  finalitySets?: string[];
  emergencyAdvanceUsed?: boolean;
}

export function parseQuorumCertificates(buffers: Buffer[]): QuorumCertificate[] {
  const out: QuorumCertificate[] = [];
  for (const buf of buffers) {
    try {
      const decoded: any = cbor.decodeFirstSync(buf);
      if (decoded && typeof decoded === 'object') {
        const epoch = decoded.epoch || decoded.e || 0;
        const sigsArr = decoded.signatures || decoded.s || [];
  const signatures = Array.isArray(sigsArr) ? sigsArr.map((s: any) => ({ validator: s.validator || s.v || 'unknown', weight: Number(s.weight || s.w || 0), sig: s.sig || s.sg || undefined })) : [];
        const aggregateSignature = decoded.aggregateSignature || decoded.a || undefined;
  const rootHash = decoded.rootHash || decoded.r || undefined;
  out.push({ epoch, signatures, aggregateSignature, rootHash });
      }
    } catch {/* ignore individual decode errors */}
  }
  return out;
}

export function deriveGovernanceMetrics(weights: { validator: string; as?: string; org?: string; weight: number }[]): { maxASShare: number; maxOrgShare: number; asCapApplied: boolean; orgCapApplied: boolean } {
  const total = weights.reduce((a, w) => a + w.weight, 0) || 1;
  const asAgg: Record<string, number> = {};
  const orgAgg: Record<string, number> = {};
  for (const w of weights) {
    if (w.as) asAgg[w.as] = (asAgg[w.as] || 0) + w.weight;
    if (w.org) orgAgg[w.org] = (orgAgg[w.org] || 0) + w.weight;
  }
  const maxASShare = Math.max(...Object.values(asAgg).map(v => v / total), 0);
  const maxOrgShare = Math.max(...Object.values(orgAgg).map(v => v / total), 0);
  return { maxASShare, maxOrgShare, asCapApplied: maxASShare <= 0.2, orgCapApplied: maxOrgShare <= 0.25 };
}

export function validateQuorumCertificates(qcs: QuorumCertificate[], thresholdFraction = 2/3, opts?: { governanceTotalWeight?: number; validatorKeys?: Record<string,string>; requireSignatures?: boolean; }): { valid: boolean; reasons: string[] } {
  const reasons: string[] = [];
  if (!qcs.length) return { valid: false, reasons: ['no-certificates'] };
  let lastEpoch = -1;
  let lastRootHash: string | undefined;
  const needRoot = !!opts?.requireSignatures; // only strictly require when signatures enforced
  for (const qc of qcs) {
    if (qc.epoch <= lastEpoch) { reasons.push('epoch-not-monotonic'); return { valid: false, reasons }; }
    lastEpoch = qc.epoch;
    if (needRoot && !qc.rootHash) { reasons.push(`missing-root-hash-epoch-${qc.epoch}`); return { valid: false, reasons }; }
    if (qc.rootHash) {
      if (lastRootHash && qc.rootHash === lastRootHash) { reasons.push(`root-hash-repeat-epoch-${qc.epoch}`); return { valid: false, reasons }; }
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
        if (!pkPem || !s.sig) { reasons.push(`missing-sig-${s.validator}`); return { valid: false, reasons }; }
        const message = Buffer.from(`epoch:${qc.epoch}|root:${qc.rootHash||'none'}`);
        try {
          let ok = false;
          try {
            ok = crypto.verify(null, message, pkPem, Buffer.from(s.sig, 'base64'));
          } catch {/* possibly not ed25519 */}
          if (!ok) {
            try {
              const verifier = crypto.createVerify('SHA256');
              verifier.update(message);
              verifier.end();
              ok = verifier.verify(pkPem, Buffer.from(s.sig, 'base64'));
            } catch {/* ignore */}
          }
          if (!ok) { reasons.push(`bad-sig-${s.validator}`); return { valid: false, reasons }; }
        } catch {
          reasons.push(`sig-error-${s.validator}`);
          return { valid: false, reasons };
        }
      }
    }
  }
  return { valid: true, reasons };
}

export function evaluateHistoricalDiversity(series: { timestamp: string; asShares: Record<string, number> }[], cap = 0.2): { stable: boolean; maxASShare: number; avgTop3: number } {
  if (!series || !series.length) return { stable: false, maxASShare: 1, avgTop3: 1 };
  let maxASShare = 0;
  let top3Accum = 0;
  for (const point of series) {
    const shares = Object.values(point.asShares || {});
    if (!shares.length) continue;
    shares.sort((a,b)=>b-a);
    maxASShare = Math.max(maxASShare, shares[0]);
    top3Accum += (shares[0] + (shares[1]||0) + (shares[2]||0)) / 3;
  }
  const avgTop3 = top3Accum / series.length;
  const stable = maxASShare <= cap && avgTop3 <= cap * 1.2; // allow slight leeway
  return { stable, maxASShare, avgTop3 };
}

export function evaluateHistoricalDiversityAdvanced(series: { timestamp: string; asShares: Record<string, number> }[], cap = 0.2, window = 3) {
  if (!series || !series.length) return { advancedStable: false, volatility: 1, maxWindowShare: 1, maxDeltaShare: 1 };
  const windows: number[] = [];
  let maxDeltaShare = 0;
  // Track per-AS previous share to compute deltas
  let prevPoint: Record<string, number> | undefined;
  for (let i = 0; i < series.length; i++) {
    const point = series[i];
    const slice = series.slice(Math.max(0, i - window + 1), i + 1);
    let localMax = 0;
    for (const p of slice) {
      const shares = Object.values(p.asShares || {});
      if (!shares.length) continue;
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
  const mean = windows.reduce((a,b)=>a+b,0)/windows.length;
  const variance = windows.reduce((a,b)=>a+Math.pow(b-mean,2),0)/windows.length;
  const volatility = Math.sqrt(variance);
  // Advanced stability now requires low concentration, low volatility AND controlled per-interval delta (<=5%)
  const advancedStable = maxWindowShare <= cap && volatility <= 0.05 && maxDeltaShare <= 0.05;
  return { advancedStable, volatility, maxWindowShare, maxDeltaShare };
}
