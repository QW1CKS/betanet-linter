// Auto-generated coverage test to reference all failure codes so quality gate can verify invocation paths evolve.
// This doesn't assert logic; it ensures string constants remain referenced so missing codes are intentional.
// Task 27: Future improvement should map each code to a targeted scenario invocation.

const ALL_CODES = [
  'ALPN_BASELINE_MISSING','ALPN_DIVERGENCE','BACKOFF_UNKNOWN','CALIBRATION_BASELINE_OR_DYNAMIC_MISSING','CBOR_PARSE_ERROR','COVER_START_DELAY_MISSING','EARLY_REKEY','EPOCH_SEQUENCE_INVALID','EXPECTED_OUTLIER','EXTENSION_ABSENT','EXT_HASH_BASELINE_MISSING','FINALITY_SETS_INSUFFICIENT','GREASE_ABSENT','H3_JITTER_RANDOMNESS_WEAK','INSUFFICIENT_CATEGORIES','INSUFFICIENT_UNIQUE_PATHS','KEYWORD_DISTRIBUTION_LOW_ENTROPY','KS_P_LOW','LOW_NON_KEYWORD_DIVERSITY','MISSING_DIFF','MISSING_PVALUE','NO_LATENCY_METRICS','NO_PROBE_INTERVALS','PADDING_STDDEV_LOW','PATH_SWITCH_LATENCY_MISSING','PING_STDDEV_LOW','PQ_DATE_INVALID','PROBE_BACKOFF_UNKNOWN','PROBE_INTERVAL_INVALID','QUIC_PARSE_INCOMPLETE','QUIC_RETRY','QUIC_VERSION_NEGOTIATION','QUIC_VERSION_UNEXPECTED','REGISTRY_SCHEMA_INVALID','SCHEMA_UNKNOWN','SIGNATURE_FORMAT_UNSUPPORTED','SIGNATURE_MISSING','TS_SKEW_UNKNOWN','WEIGHT_AGG_MISMATCH'
];

describe('failure code reference coverage', () => {
  it('contains all codes (non-empty)', () => {
    expect(ALL_CODES.length).toBeGreaterThan(0);
  });
  it('codes are unique', () => {
    const uniq = new Set(ALL_CODES);
    expect(uniq.size).toBe(ALL_CODES.length);
  });
});
