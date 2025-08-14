#!/usr/bin/env node
/**
 * Performance & Scalability Benchmarking (Task 31)
 * ------------------------------------------------
 * Goals:
 * 1. Measure end-to-end linter wall time and per-check durations on a target binary.
 * 2. Produce a machine-readable JSON report (dist/perf-report.json by default) with:
 *    - nodeVersion, platform, cpuModel, logicalCores, memoryGb
 *    - timestamp, binaryPath, fileSizeBytes, sha256
 *    - totalWallMs, analyzerAnalysisMs, parallelChecksWallMs
 *    - perCheck: { id, name, durationMs, severity, passed, evidenceType }
 *    - aggregate stats (p50/p90/p99 duration, slowestIds[], totalPassed, totalFailed)
 * 3. (Optional) Compare against an existing baseline report to flag regressions.
 *    Regression heuristic: any p90 increase > regressionPctThreshold (default 50%) OR
 *    totalWallMs increase > regressionWallPctThreshold (default 40%).
 * 4. Exit non‑zero if regression threshold exceeded (CI gate opt‑in via --fail-on-regression).
 *
 * Usage:
 *   node scripts/performance-benchmark.js --binary ./path/to/bin [--baseline dist/perf-baseline.json] \
 *        [--out dist/perf-report.json] [--fail-on-regression]
 *
 * NPM Script:
 *   npm run bench:perf -- --binary ./mybin
 */
const fs = require('fs');
const path = require('path');
let BetanetComplianceChecker; try { ({ BetanetComplianceChecker } = require('../dist/index')); } catch { ({ BetanetComplianceChecker } = require('../src/index')); }
const crypto = require('crypto');

function parseArgs() {
  const args = process.argv.slice(2);
  const out = { regressionPctThreshold: 0.5, regressionWallPctThreshold: 0.4 };
  for (let i=0;i<args.length;i++) {
    const a = args[i];
    if (a === '--binary' && args[i+1]) { out.binary = args[++i]; }
    else if (a === '--baseline' && args[i+1]) { out.baseline = args[++i]; }
    else if (a === '--out' && args[i+1]) { out.out = args[++i]; }
    else if (a === '--fail-on-regression') { out.failOnRegression = true; }
    else if (a === '--regression-pct' && args[i+1]) { out.regressionPctThreshold = parseFloat(args[++i]); }
    else if (a === '--regression-wall-pct' && args[i+1]) { out.regressionWallPctThreshold = parseFloat(args[++i]); }
  }
  if (!out.binary) {
    console.error('❌ Missing --binary <path>');
    process.exit(1);
  }
  return out;
}

async function sha256File(file) {
  const hash = crypto.createHash('sha256');
  return new Promise((res, rej) => {
    fs.createReadStream(file).on('data', d=>hash.update(d)).on('end',()=>res(hash.digest('hex'))).on('error',rej);
  });
}

function percentile(values, p) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a,b)=>a-b);
  const idx = Math.min(sorted.length-1, Math.floor(p * (sorted.length-1)));
  return sorted[idx];
}

(async () => {
  const args = parseArgs();
  const checker = new BetanetComplianceChecker();
  const start = performance.now();
  const result = await checker.checkCompliance(args.binary, { strictMode: false, allowHeuristic: true });
  const totalWall = performance.now() - start;
  const fileSize = fs.statSync(args.binary).size;
  const sha256 = await sha256File(args.binary);
  const per = result.checkTimings || [];
  const durations = per.map(p => p.durationMs);
  const stats = {
    p50: percentile(durations, 0.50),
    p90: percentile(durations, 0.90),
    p99: percentile(durations, 0.99),
    max: durations.length ? Math.max(...durations) : 0,
    min: durations.length ? Math.min(...durations) : 0,
    mean: durations.length ? durations.reduce((a,b)=>a+b,0)/durations.length : 0
  };
  const slowest = [...per].sort((a,b)=>b.durationMs-a.durationMs).slice(0,5).map(x=>x.id);

  const report = {
    schema: 1,
    timestamp: new Date().toISOString(),
    nodeVersion: process.version,
    platform: process.platform,
    arch: process.arch,
    cpuModel: (require('os').cpus()||[{model:'?'}])[0].model,
    logicalCores: (require('os').cpus()||[]).length,
    memoryGb: Math.round((require('os').totalmem()/1024/1024/1024)*100)/100,
    binaryPath: path.resolve(args.binary),
    fileSizeBytes: fileSize,
    sha256,
    totalWallMs: totalWall,
    parallelChecksWallMs: result.parallelDurationMs,
    analyzerAnalysisMs: result.diagnostics?.totalAnalysisTimeMs,
    perCheck: per.map(t => {
      const meta = result.checks.find(c=>c.id===t.id) || { name: 'unknown', severity: 'minor', passed: false };
      return { id: t.id, name: meta.name, durationMs: t.durationMs, severity: meta.severity, passed: meta.passed, evidenceType: meta.evidenceType };
    }),
    stats,
    slowestIds: slowest,
    totalPassed: result.summary.passed,
    totalFailed: result.summary.failed,
    regression: undefined
  };

  // Baseline regression comparison
  if (args.baseline && fs.existsSync(args.baseline)) {
    try {
      const base = JSON.parse(fs.readFileSync(args.baseline,'utf8'));
      const reg = {};
      if (base.stats && base.stats.p90 && report.stats.p90) {
        const deltaPct = (report.stats.p90 - base.stats.p90) / base.stats.p90;
        reg.p90DeltaPct = deltaPct;
        reg.p90Regressed = deltaPct > args.regressionPctThreshold;
      }
      if (base.totalWallMs && report.totalWallMs) {
        const wallDeltaPct = (report.totalWallMs - base.totalWallMs) / base.totalWallMs;
        reg.totalWallDeltaPct = wallDeltaPct;
        reg.wallRegressed = wallDeltaPct > args.regressionWallPctThreshold;
      }
      // Per-check regression (identify checks whose duration grew > threshold)
      const baseMap = new Map((base.perCheck||[]).map(c => [c.id, c]));
      const perReg = [];
      for (const c of report.perCheck) {
        const b = baseMap.get(c.id);
        if (b && b.durationMs > 0) {
          const dPct = (c.durationMs - b.durationMs) / b.durationMs;
            if (dPct > args.regressionPctThreshold) perReg.push({ id: c.id, from: b.durationMs, to: c.durationMs, deltaPct: dPct });
        }
      }
      reg.perCheckRegressions = perReg;
      reg.hasRegression = !!(reg.p90Regressed || reg.wallRegressed || (perReg.length>0));
      report.regression = reg;
      if (args.failOnRegression && reg.hasRegression) {
        console.error('❌ Performance regression detected:', JSON.stringify(reg, null, 2));
        // Still write report before exiting
        if (!args.out) args.out = path.join('dist','perf-report.json');
        fs.mkdirSync(path.dirname(args.out), { recursive: true });
        fs.writeFileSync(args.out, JSON.stringify(report, null, 2));
        process.exit(1);
      }
    } catch (e) {
      console.warn('⚠️  Failed to parse baseline for regression comparison:', e.message);
    }
  }

  const outPath = args.out || path.join('dist','perf-report.json');
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2));
  console.log(`✅ Performance benchmark complete. Report: ${outPath}`);
  console.log(`   totalWallMs=${Math.round(report.totalWallMs)} p90=${Math.round(report.stats.p90)} slowest=${report.slowestIds.join(',')}`);
})();
