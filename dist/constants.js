"use strict";
// Centralized constants for Betanet versions & specification metadata
// Introduced during Betanet 1.1 alignment (Plan 3 pre-step)
Object.defineProperty(exports, "__esModule", { value: true });
exports.DISCLAIMER_TEXT = exports.SPEC_VERSION_PARTIAL = exports.SPEC_VERSION_SUPPORTED_BASE = exports.POST_QUANTUM_MANDATORY_DATE = exports.OPTIONAL_TRANSPORTS = exports.TRANSPORT_ENDPOINT_VERSIONS = void 0;
exports.TRANSPORT_ENDPOINT_VERSIONS = ["1.1.0", "1.0.0"]; // prefer newest first
exports.OPTIONAL_TRANSPORTS = [
    { path: "/betanet/webrtc/1.0.0", kind: "webrtc", mandatory: false }
];
exports.POST_QUANTUM_MANDATORY_DATE = "2027-01-01"; // ISO date string
exports.SPEC_VERSION_SUPPORTED_BASE = "1.0"; // baseline fully targeted
exports.SPEC_VERSION_PARTIAL = "1.1"; // partially covered heuristically
exports.DISCLAIMER_TEXT = `This tool provides heuristic static binary analysis. Some Betanet ${exports.SPEC_VERSION_PARTIAL} requirements (e.g., dynamic TLS calibration, path count enforcement, voucher cryptographic structure) are only partially inferred or not yet implemented.`;
//# sourceMappingURL=constants.js.map