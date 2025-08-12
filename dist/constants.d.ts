export declare const TRANSPORT_ENDPOINT_VERSIONS: string[];
export declare const OPTIONAL_TRANSPORTS: {
    path: string;
    kind: string;
    mandatory: boolean;
}[];
export declare const POST_QUANTUM_MANDATORY_DATE = "2027-01-01";
export declare const POST_QUANTUM_MANDATORY_EPOCH_MS: number;
export declare function parseOverridePQDate(override?: string): number | undefined;
export declare const SPEC_VERSION_SUPPORTED_BASE = "1.0";
export declare const SPEC_VERSION_PARTIAL = "1.1";
export declare const DISCLAIMER_TEXT = "This tool provides heuristic static binary analysis. Some Betanet 1.1 requirements (e.g., dynamic TLS calibration, path count enforcement, voucher cryptographic structure) are only partially inferred or not yet implemented.";
export declare const SPEC_11_PENDING_ISSUES: {
    id: string;
    title: string;
}[];
export declare function parseSpecVersion(v: string): number[];
export declare function isVersionLE(a: string, b: string): boolean;
export declare const DEFAULT_FALLBACK_STRING_MIN_LEN = 4;
export declare const FALLBACK_MAX_BYTES: number;
export declare const COMPONENT_NAME_MAX_LENGTH = 128;
export declare function sanitizeName(name: string): string;
export declare const SEVERITY_LEVELS: readonly ["critical", "major", "minor"];
export declare const SEVERITY_EMOJI: Record<string, string>;
export declare const DEFAULT_TOOL_TIMEOUT_MS = 2000;
export declare const DEFAULT_STRINGS_TIMEOUT_MS = 5000;
export declare const DEFAULT_LDD_TIMEOUT_MS = 5000;
export declare const DEFAULT_HASH_TIMEOUT_MS = 4000;
export declare const VERSION_KEYWORDS: string[];
//# sourceMappingURL=constants.d.ts.map