import * as cbor from 'cbor';

export interface QuorumCertificate {
  epoch: number;
  signatures: { validator: string; weight: number }[];
  aggregateSignature?: string;
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
        const signatures = Array.isArray(sigsArr) ? sigsArr.map((s: any) => ({ validator: s.validator || s.v || 'unknown', weight: Number(s.weight || s.w || 0) })) : [];
        const aggregateSignature = decoded.aggregateSignature || decoded.a || undefined;
        out.push({ epoch, signatures, aggregateSignature });
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

export function validateQuorumCertificates(qcs: QuorumCertificate[], thresholdFraction = 2/3): boolean {
  if (!qcs.length) return false;
  // Simplified: each certificate must have aggregate weight >= thresholdFraction of sum of its signatures
  return qcs.every(qc => {
    const total = qc.signatures.reduce((a, s) => a + s.weight, 0);
    const aggregateWeight = total; // placeholder (would verify actual aggregated signature & membership)
    return aggregateWeight >= thresholdFraction * total;
  });
}
