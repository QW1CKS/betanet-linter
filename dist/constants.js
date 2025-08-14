"use strict";
// Centralized constants for Betanet versions & specification metadata
// Introduced during Betanet 1.1 alignment (Plan 3 pre-step)
Object.defineProperty(exports, "__esModule", { value: true });
exports.VERSION_KEYWORDS = exports.DEFAULT_HASH_TIMEOUT_MS = exports.DEFAULT_LDD_TIMEOUT_MS = exports.DEFAULT_STRINGS_TIMEOUT_MS = exports.DEFAULT_TOOL_TIMEOUT_MS = exports.SEVERITY_EMOJI = exports.SEVERITY_LEVELS = exports.COMPONENT_NAME_MAX_LENGTH = exports.FALLBACK_MAX_BYTES = exports.DEFAULT_FALLBACK_STRING_MIN_LEN = exports.SPEC_11_PENDING_ISSUES = exports.DISCLAIMER_TEXT = exports.SPEC_VERSION_PARTIAL = exports.SPEC_VERSION_SUPPORTED_BASE = exports.POST_QUANTUM_MANDATORY_EPOCH_MS = exports.POST_QUANTUM_MANDATORY_DATE = exports.OPTIONAL_TRANSPORTS = exports.TRANSPORT_ENDPOINT_VERSIONS = void 0;
exports.parseOverridePQDate = parseOverridePQDate;
exports.parseSpecVersion = parseSpecVersion;
exports.isVersionLE = isVersionLE;
exports.sanitizeName = sanitizeName;
exports.TRANSPORT_ENDPOINT_VERSIONS = ["1.1.0", "1.0.0"]; // prefer newest first
exports.OPTIONAL_TRANSPORTS = [
    { path: "/betanet/webrtc/1.0.0", kind: "webrtc", mandatory: false }
];
// Post-quantum enforcement date expressed as an ISO (UTC) day boundary.
// ISSUE-016 fix: avoid local timezone interpretation by using UTC epoch milliseconds.
exports.POST_QUANTUM_MANDATORY_DATE = "2027-01-01"; // canonical ISO date string (UTC midnight)
exports.POST_QUANTUM_MANDATORY_EPOCH_MS = Date.UTC(2027, 0, 1, 0, 0, 0, 0);
function parseOverridePQDate(override) {
    if (!override)
        return undefined;
    // Accept YYYY-MM-DD or full ISO. Always interpret as UTC midnight if only date provided.
    const dateOnlyMatch = override.match(/^\d{4}-\d{2}-\d{2}$/);
    if (dateOnlyMatch) {
        const [y, m, d] = override.split('-').map(n => parseInt(n, 10));
        if (y && m && d)
            return Date.UTC(y, m - 1, d, 0, 0, 0, 0);
    }
    const parsed = Date.parse(override); // Date.parse treats unspecified TZ as local or UTC depending on format
    if (!isNaN(parsed)) {
        return parsed; // retain given explicit timezone / timestamp
    }
    return undefined; // invalid override ignored by caller
}
exports.SPEC_VERSION_SUPPORTED_BASE = "1.0"; // baseline fully targeted
exports.SPEC_VERSION_PARTIAL = "1.1"; // partially covered heuristically
exports.DISCLAIMER_TEXT = `This tool provides heuristic static binary analysis. Some Betanet ${exports.SPEC_VERSION_PARTIAL} requirements (e.g., dynamic TLS calibration, path count enforcement, voucher cryptographic structure) are only partially inferred or not yet implemented.`;
// Pending Betanet 1.1 specific deltas not yet fully implemented as discrete checks.
// Sourced from issues-inconsistencies.txt (spec delta tracking section).
exports.SPEC_11_PENDING_ISSUES = []; // All previously pending 1.1 heuristic refinements implemented in v1.1.0 finalization
// Helper to parse dotted semantic-ish spec versions (major.minor[.patch]) into numeric tuple
function parseSpecVersion(v) {
    return v.split('.').map(n => parseInt(n, 10) || 0);
}
function isVersionLE(a, b) {
    const pa = parseSpecVersion(a);
    const pb = parseSpecVersion(b);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
        const av = pa[i] || 0;
        const bv = pb[i] || 0;
        if (av < bv)
            return true;
        if (av > bv)
            return false;
    }
    return true; // equal
}
// Fallback string extraction limits (ISSUE-038)
exports.DEFAULT_FALLBACK_STRING_MIN_LEN = 4;
exports.FALLBACK_MAX_BYTES = (() => {
    const env = process.env.BETANET_FALLBACK_STRINGS_MAX_BYTES;
    const parsed = env ? parseInt(env, 10) : NaN;
    if (!isNaN(parsed) && parsed > 0)
        return parsed;
    return 32 * 1024 * 1024; // 32 MiB cap by default
})();
// Component / package name sanitization (ISSUE-037)
// Allow only a conservative safe subset: alphanumerics, dot, underscore, hyphen.
// Replace any other character (including path separators, spaces, control chars) with '-'.
// Collapse consecutive '-' and trim leading/trailing '-'. If result empty, fallback to 'component'.
// Enforce a max length to avoid pathological extremely long names impacting downstream tools.
exports.COMPONENT_NAME_MAX_LENGTH = 128;
function sanitizeName(name) {
    if (!name)
        return 'component';
    // Normalize to NFC to reduce multi-codepoint equivalence issues, ignore errors silently
    try {
        name = name.normalize('NFC');
    }
    catch { /* ignore */ }
    // Replace disallowed chars
    // Hyphen placed at end of class, so no need to escape; remove superfluous escapes triggering lint
    let cleaned = name.replace(/[^A-Za-z0-9._.-]+/g, '-');
    // Collapse dashes
    cleaned = cleaned.replace(/-+/g, '-');
    // Trim leading/trailing dashes/periods (avoid hidden or awkward names)
    cleaned = cleaned.replace(/^[.-]+/, '').replace(/[.-]+$/, '');
    if (!cleaned.length)
        cleaned = 'component';
    if (cleaned.length > exports.COMPONENT_NAME_MAX_LENGTH) {
        cleaned = cleaned.slice(0, exports.COMPONENT_NAME_MAX_LENGTH);
    }
    return cleaned;
}
// ISSUE-028: Extract commonly repeated literals / magic values
exports.SEVERITY_LEVELS = ['critical', 'major', 'minor'];
exports.SEVERITY_EMOJI = { critical: '🔴', major: '🟡', minor: '🟢' };
exports.DEFAULT_TOOL_TIMEOUT_MS = 2000; // baseline tool version/availability checks
exports.DEFAULT_STRINGS_TIMEOUT_MS = 5000; // strings extraction upper bound
exports.DEFAULT_LDD_TIMEOUT_MS = 5000; // dependency resolution
exports.DEFAULT_HASH_TIMEOUT_MS = 4000; // hashing external process
exports.VERSION_KEYWORDS = ['version', 'ver', 'v', 'release', 'rev', 'commit']; // version context detection keywords
//# sourceMappingURL=constants.js.map