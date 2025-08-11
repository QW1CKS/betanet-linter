// Centralized constants for Betanet versions & specification metadata
// Introduced during Betanet 1.1 alignment (Plan 3 pre-step)

export const TRANSPORT_ENDPOINT_VERSIONS = ["1.1.0", "1.0.0"]; // prefer newest first
export const OPTIONAL_TRANSPORTS = [
  { path: "/betanet/webrtc/1.0.0", kind: "webrtc", mandatory: false }
];

// Post-quantum enforcement date expressed as an ISO (UTC) day boundary.
// ISSUE-016 fix: avoid local timezone interpretation by using UTC epoch milliseconds.
export const POST_QUANTUM_MANDATORY_DATE = "2027-01-01"; // canonical ISO date string (UTC midnight)
export const POST_QUANTUM_MANDATORY_EPOCH_MS = Date.UTC(2027, 0, 1, 0, 0, 0, 0);

export function parseOverridePQDate(override?: string): number | undefined {
  if (!override) return undefined;
  // Accept YYYY-MM-DD or full ISO. Always interpret as UTC midnight if only date provided.
  const dateOnlyMatch = override.match(/^\d{4}-\d{2}-\d{2}$/);
  if (dateOnlyMatch) {
    const [y, m, d] = override.split('-').map(n => parseInt(n, 10));
    if (y && m && d) return Date.UTC(y, m - 1, d, 0, 0, 0, 0);
  }
  const parsed = Date.parse(override); // Date.parse treats unspecified TZ as local or UTC depending on format
  if (!isNaN(parsed)) {
    return parsed; // retain given explicit timezone / timestamp
  }
  return undefined; // invalid override ignored by caller
}

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

// Fallback string extraction limits (ISSUE-038)
export const DEFAULT_FALLBACK_STRING_MIN_LEN = 4;
export const FALLBACK_MAX_BYTES = (() => {
  const env = process.env.BETANET_FALLBACK_STRINGS_MAX_BYTES;
  const parsed = env ? parseInt(env, 10) : NaN;
  if (!isNaN(parsed) && parsed > 0) return parsed;
  return 32 * 1024 * 1024; // 32 MiB cap by default
})();

// Component / package name sanitization (ISSUE-037)
// Allow only a conservative safe subset: alphanumerics, dot, underscore, hyphen.
// Replace any other character (including path separators, spaces, control chars) with '-'.
// Collapse consecutive '-' and trim leading/trailing '-'. If result empty, fallback to 'component'.
// Enforce a max length to avoid pathological extremely long names impacting downstream tools.
export const COMPONENT_NAME_MAX_LENGTH = 128;
export function sanitizeName(name: string): string {
  if (!name) return 'component';
  // Normalize to NFC to reduce multi-codepoint equivalence issues, ignore errors silently
  try { name = name.normalize('NFC'); } catch { /* ignore */ }
  // Replace disallowed chars
  let cleaned = name.replace(/[^A-Za-z0-9._-]+/g, '-');
  // Collapse dashes
  cleaned = cleaned.replace(/-+/g, '-');
  // Trim leading/trailing dashes/periods (avoid hidden or awkward names)
  cleaned = cleaned.replace(/^[\-.]+/, '').replace(/[\-.]+$/, '');
  if (!cleaned.length) cleaned = 'component';
  if (cleaned.length > COMPONENT_NAME_MAX_LENGTH) {
    cleaned = cleaned.slice(0, COMPONENT_NAME_MAX_LENGTH);
  }
  return cleaned;
}
