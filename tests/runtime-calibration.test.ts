// Helper to run compliance with injected evidence
async function runWith(evidence: any) {
  const analyzer: any = { evidence, checkNetworkCapabilities: async () => ({ hasTLS: true, hasQUIC: true, hasHTX: true, port443: true, hasECH: true }) };
  // Monkey patch: runCompliance normally constructs analyzer; emulate minimal subset
  const { CHECK_REGISTRY, ALL_CHECKS } = require('../src/check-registry');
  const now = new Date();
  const checks = [] as any[];
  for (const def of ALL_CHECKS.filter((c:any)=> c.id === 42)) {
    checks.push(await def.evaluate(analyzer, now));
  }
  return checks[0];
}

describe('Check 42 Runtime Calibration & Behavioral Instrumentation', () => {
  test('passes with matching baseline/dynamic and acceptable latencies/delay', async () => {
    const evidence = {
      calibrationBaseline: { alpn: ['h2','http/1.1'], extOrderSha256: 'abc', popId: 'pop-a' },
      dynamicClientHelloCapture: { alpn: ['h2','http/1.1'], extOrderSha256: 'abc', popId: 'pop-a' },
      scionControl: { pathSwitchLatenciesMs: [120,140,160], rateBackoffOk: true },
      fallbackTiming: { coverStartDelayMs: 200 }
    };
    const check = await runWith(evidence);
    expect(check.passed).toBe(true);
    expect(check.details).toMatch(/runtime calibration ok/);
  });

  test('fails on ALPN mismatch and slow path switch and cover delay', async () => {
    const evidence = {
      calibrationBaseline: { alpn: ['h2','http/1.1'], extOrderSha256: 'abc', popId: 'pop-a' },
      dynamicClientHelloCapture: { alpn: ['http/1.1','h2'], extOrderSha256: 'abc2', popId: 'pop-b' },
      scionControl: { pathSwitchLatenciesMs: [310, 280], rateBackoffOk: false },
      fallbackTiming: { coverStartDelayMs: 1500 }
    };
    const check = await runWith(evidence);
    expect(check.passed).toBe(false);
    expect(check.details).toMatch(/ALPN_CALIBRATION_MISMATCH/);
    expect(check.details).toMatch(/EXT_ORDER_CALIBRATION_MISMATCH/);
    expect(check.details).toMatch(/POP_MISMATCH/);
    expect(check.details).toMatch(/PATH_SWITCH_LATENCY_SLOW/);
    expect(check.details).toMatch(/PROBE_BACKOFF_VIOLATION/);
    expect(check.details).toMatch(/COVER_START_DELAY_OUT_OF_RANGE/);
  });
});
