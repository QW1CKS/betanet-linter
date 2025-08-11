// Centralized constants for Betanet versions & specification metadata
// Introduced during Betanet 1.1 alignment (Plan 3 pre-step)

export const TRANSPORT_ENDPOINT_VERSIONS = ["1.1.0", "1.0.0"]; // prefer newest first
export const OPTIONAL_TRANSPORTS = [
  { path: "/betanet/webrtc/1.0.0", kind: "webrtc", mandatory: false }
];

export const POST_QUANTUM_MANDATORY_DATE = "2027-01-01"; // ISO date string

export const SPEC_VERSION_SUPPORTED_BASE = "1.0"; // baseline fully targeted
export const SPEC_VERSION_PARTIAL = "1.1"; // partially covered heuristically

export const DISCLAIMER_TEXT = `This tool provides heuristic static binary analysis. Some Betanet ${SPEC_VERSION_PARTIAL} requirements (e.g., dynamic TLS calibration, path count enforcement, voucher cryptographic structure) are only partially inferred or not yet implemented.`;

// Pending Betanet 1.1 specific deltas not yet fully implemented as discrete checks.
// Sourced from issues-inconsistencies.txt (spec delta tracking section).
export const SPEC_11_PENDING_ISSUES: { id: string; title: string }[] = []; // All previously pending 1.1 heuristic refinements implemented in v1.1.0 finalization

// Helper to parse dotted semantic-ish spec versions (major.minor[.patch]) into numeric tuple
export function parseSpecVersion(v: string): number[] {
  return v.split('.').map(n => parseInt(n, 10) || 0);
}

export function isVersionLE(a: string, b: string): boolean {
  const pa = parseSpecVersion(a); const pb = parseSpecVersion(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const av = pa[i] || 0; const bv = pb[i] || 0;
    if (av < bv) return true; if (av > bv) return false;
  }
  return true; // equal
}
