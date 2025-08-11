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
