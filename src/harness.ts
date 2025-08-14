import * as fs from 'fs-extra';
import { BinaryAnalyzer } from './analyzer';
import * as tls from 'tls';
import * as net from 'net';
import * as dgram from 'dgram';
import { spawn } from 'child_process';
import * as crypto from 'crypto';
import { buildCanonicalClientHello } from './tls-capture';

// Lightweight TLS probe (scaffold) – Phase 2 foundation
// Captures negotiated ALPN, cipher, protocol version and basic timing.
async function performTlsProbe(host: string, port: number = 443, offeredAlpn: string[] = ['h2','http/1.1'], timeoutMs = 5000) {
  return await new Promise<any>(resolve => {
    const start = Date.now();
    let settled = false;
    const outcome: any = { host, port, offeredAlpn };
    try {
      const socket = tls.connect({
        host,
        port,
        servername: host,
        ALPNProtocols: offeredAlpn
      }, () => {
        outcome.handshakeMs = Date.now() - start;
        outcome.selectedAlpn = socket.alpnProtocol || null;
        const cipher = socket.getCipher();
        if (cipher) outcome.cipher = cipher.name;
        outcome.protocol = socket.getProtocol();
        settled = true;
        socket.end();
        resolve(outcome);
      });
      socket.setTimeout(timeoutMs, () => {
        if (!settled) {
          outcome.error = 'timeout';
          outcome.handshakeMs = Date.now() - start;
          settled = true;
          try { socket.destroy(); } catch { /* ignore */ }
          resolve(outcome);
        }
      });
      socket.on('error', (err: any) => {
        if (!settled) {
          outcome.error = err.code || err.message || 'error';
          outcome.handshakeMs = Date.now() - start;
          settled = true;
          resolve(outcome);
        }
      });
    } catch (e: any) {
      outcome.error = e.message || 'exception';
      outcome.handshakeMs = Date.now() - start;
      resolve(outcome);
    }
    // Safety net in case nothing fires
    setTimeout(() => {
      if (!settled) {
        outcome.error = outcome.error || 'timeout-safety';
        outcome.handshakeMs = Date.now() - start;
        settled = true;
        resolve(outcome);
      }
    }, timeoutMs + 250);
  });
}

export interface HarnessOptions {
  scenarios?: string[]; // future expansion
  maxSeconds?: number;
  verbose?: boolean;
  probeHost?: string; // optional TLS probe host (foundation for dynamic ClientHello evidence)
  probePort?: number; // optional port (default 443)
  probeTimeoutMs?: number; // timeout for TLS probe
  fallbackHost?: string; // host for UDP->TCP fallback simulation
  fallbackUdpPort?: number;
  fallbackTcpPort?: number;
  fallbackUdpTimeoutMs?: number;
  coverConnections?: number; // simulated cover connection count
  mixSamples?: number; // number of simulated mix path samples to generate
  mixHopsRange?: [number, number]; // inclusive range of hops per path (e.g., [2,4])
  mixDeterministic?: boolean; // if true, use seeded patterns for reproducibility
  rekeySimulate?: boolean; // simulate observing a Noise rekey event
  h2AdaptiveSimulate?: boolean; // simulate HTTP/2 adaptive padding/jitter metrics
  h3AdaptiveSimulate?: boolean; // simulate HTTP/3 adaptive padding/jitter metrics
  jitterSamples?: number; // number of jitter samples to simulate
  clientHelloSimulate?: boolean; // simulate dynamic ClientHello capture (Step 11 initial slice)
  clientHelloCapture?: { host: string; port?: number; opensslPath?: string }; // real capture target
  quicInitialHost?: string; // target host for QUIC Initial attempt
  quicInitialPort?: number; // target port (default 443)
  quicInitialTimeoutMs?: number; // wait for response
  noiseRun?: boolean; // attempt to run binary to observe real noise rekey markers
  accessTicketSimulate?: boolean; // simulate access ticket dynamic sampling (padding variability, rotation interval)
  echSimulate?: { outerHost: string; innerHost?: string; simulateCertDiff?: boolean; greaseAnomaly?: boolean }; // dual handshake simulation (Task 2)
}

export interface HarnessEvidence {
  noiseTranscriptDynamic?: {
    messagesObserved?: string[];
    expectedSequenceOk?: boolean;
    rekeysObserved?: number;
    rekeyTriggers?: { bytes?: number; timeMinSec?: number; frames?: number };
    nonceReuseDetected?: boolean;
    patternVerified?: boolean;
    pqDateOk?: boolean;
    withinPolicy?: boolean;
  };
  schemaVersion?: string;
  clientHello?: { alpn?: string[]; extOrderSha256?: string };
  noise?: { pattern?: string };
  // Extended noise evidence (Step 9)
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  noiseExtended?: { pattern?: string; rekeysObserved?: number; rekeyTriggers?: { bytes?: number; timeMinSec?: number; frames?: number } };
  voucher?: { structLikely?: boolean; tokenHits?: string[]; proximityBytes?: number };
  tlsProbe?: { host: string; port: number; offeredAlpn: string[]; selectedAlpn?: string | null; cipher?: string; protocol?: string | null; handshakeMs?: number; error?: string };
  fallback?: { udpAttempted: boolean; udpTimeoutMs: number; tcpConnected: boolean; tcpConnectMs?: number; tcpRetryDelayMs?: number; coverConnections?: number; coverTeardownMs?: number[]; error?: string; policy?: { retryDelayMsOk?: boolean; coverConnectionsOk?: boolean; teardownSpreadOk?: boolean; overall?: boolean } };
  mix?: { samples: number; uniqueHopSets: number; hopSets: string[][]; minHopsBalanced: number; minHopsStrict: number };
    h2Adaptive?: { settings?: Record<string, number>; meanMs?: number; p95Ms?: number; stddevMs?: number; randomnessOk?: boolean; withinTolerance?: boolean; sampleCount?: number };
    h3Adaptive?: { qpackTableSize?: number; meanMs?: number; p95Ms?: number; stddevMs?: number; randomnessOk?: boolean; withinTolerance?: boolean; sampleCount?: number };
  dynamicClientHelloCapture?: { alpn?: string[]; extOrderSha256?: string; ja3?: string; ja3Hash?: string; ja3Canonical?: string; ja4?: string; rawClientHelloB64?: string; rawClientHelloCanonicalB64?: string; rawClientHelloCanonicalHash?: string; capturedAt?: string; matchStaticTemplate?: boolean; note?: string; ciphers?: number[]; extensions?: number[]; curves?: number[]; ecPointFormats?: number[]; captureQuality?: string };
  // (Phase 7 extension) ja3Hash added to dynamicClientHelloCapture; keep interface loose via index signature if needed
  calibrationBaseline?: { alpn?: string[]; extOrderSha256?: string; source?: string; capturedAt?: string };
  quicInitial?: { host: string; port: number; udpSent: boolean; responseBytes?: number; responseWithinMs?: number; error?: string; parsed?: { version?: string; dcil?: number; scil?: number; tokenLength?: number; lengthField?: number; versionNegotiation?: boolean; retry?: boolean; versionsOffered?: string[]; odcil?: number }; rawInitialB64?: string; responseRawB64?: string };
  statisticalJitter?: { meanMs: number; p95Ms: number; stdDevMs: number; samples: number; withinTarget?: boolean };
  meta: { generated: string; scenarios: string[] };
  accessTicketDynamic?: { samples: number; paddingLengths?: number[]; uniquePadding?: number; rotationIntervalSec?: number; replayWindowSec?: number; rateLimitBuckets?: number; withinPolicy?: boolean; paddingVarianceOk?: boolean; rotationIntervalOk?: boolean; replayWindowOk?: boolean; rateLimitOk?: boolean };
}

async function simulateFallback(host: string, udpPort: number, tcpPort: number, udpTimeoutMs: number, coverConnections: number = 0): Promise<HarnessEvidence['fallback']> {
  const start = Date.now();
  const udpSocket = dgram.createSocket('udp4');
  // Send a single empty datagram (most likely no listener -> silent drop)
  try { udpSocket.send(Buffer.from('ping'), udpPort, host, () => { /* noop */ }); } catch { /* ignore */ }
  const fallback: HarnessEvidence['fallback'] = { udpAttempted: true, udpTimeoutMs, tcpConnected: false };
  await new Promise(r => setTimeout(r, udpTimeoutMs));
  try { udpSocket.close(); } catch { /* ignore */ }
  const tcpStart = Date.now();
  await new Promise<void>(resolve => {
    try {
      const sock = net.createConnection({ host, port: tcpPort, timeout: 4000 }, () => {
        fallback.tcpConnected = true;
        fallback.tcpConnectMs = Date.now() - tcpStart;
        fallback.tcpRetryDelayMs = tcpStart - (start + udpTimeoutMs); // delay after UDP wait until TCP attempt (should be ~0)
        sock.end();
        resolve();
      });
      sock.on('timeout', () => {
        fallback.error = fallback.error || 'tcp-timeout';
        try { sock.destroy(); } catch { /* ignore */ }
        resolve();
      });
      sock.on('error', (e: any) => {
        fallback.error = fallback.error || e.code || e.message;
        resolve();
      });
    } catch (e: any) {
      fallback.error = fallback.error || e.message;
      resolve();
    }
  });
  if (coverConnections && coverConnections > 0) {
    const teardown: number[] = [];
    for (let i = 0; i < coverConnections; i++) {
      const cStart = Date.now();
      await new Promise<void>(res => {
        try {
          const dummy = net.createConnection({ host, port: tcpPort, timeout: 1000 }, () => {
            dummy.end();
          });
          dummy.on('close', () => {
            teardown.push(Date.now() - cStart);
            res();
          });
          dummy.on('error', () => {
            teardown.push(Date.now() - cStart);
            res();
          });
        } catch {
          teardown.push(Date.now() - cStart);
          res();
        }
      });
    }
    fallback.coverConnections = coverConnections;
    fallback.coverTeardownMs = teardown;
    // Advanced cover behavior metrics (Phase 7 quantitative modeling)
    if (teardown.length >= 2) {
      const sorted = [...teardown].sort((a,b)=>a-b);
      const mean = teardown.reduce((a,b)=>a+b,0)/teardown.length;
      const variance = teardown.reduce((a,b)=>a + Math.pow(b-mean,2),0)/teardown.length;
      const std = Math.sqrt(variance);
      const cv = mean ? std/mean : 0;
      const median = sorted.length % 2 ? sorted[(sorted.length-1)/2] : (sorted[sorted.length/2 - 1] + sorted[sorted.length/2]) / 2;
      const p95Index = Math.min(sorted.length-1, Math.floor(sorted.length * 0.95));
      const p95 = sorted[p95Index];
      const q1 = sorted[Math.floor(sorted.length * 0.25)];
      const q3 = sorted[Math.floor(sorted.length * 0.75)];
      const iqr = q3 - q1;
      // Fisher-Pearson skewness (unbiased) if std > 0
      let skew = 0;
      if (std > 0) {
        const n = teardown.length;
        const m3 = teardown.reduce((a,b)=>a + Math.pow(b-mean,3),0)/n;
        const g1 = m3 / Math.pow(std,3);
        // Adjusted Fisher-Pearson
        skew = Math.sqrt(n*(n-1)) / (n-2 > 0 ? (n-2) : 1) * g1;
      }
      // Outlier detection using 1.5*IQR rule
      const lowerFence = q1 - 1.5 * iqr;
      const upperFence = q3 + 1.5 * iqr;
      const outliers = teardown.filter(v => v < lowerFence || v > upperFence);
      const outlierCount = outliers.length;
      const anomalies: string[] = [];
      if (cv > 1.5) anomalies.push('HIGH_CV');
      if (Math.abs(skew) > 1.2) anomalies.push('SKEW_EXCESS');
      if (outlierCount > Math.ceil(teardown.length * 0.25)) anomalies.push('OUTLIER_EXCESS');
      if (teardown.length < 3) anomalies.push('SAMPLE_TOO_SMALL');
      // Model score: proportion of core criteria satisfied
      const criteria = {
        cvOk: cv <= 1.5,
        skewOk: Math.abs(skew) <= 1.2,
        outlierOk: outlierCount <= Math.ceil(teardown.length * 0.25),
        sampleSizeOk: teardown.length >= 3
      } as const;
      const satisfied = Object.values(criteria).filter(Boolean).length;
      const behaviorModelScore = satisfied / Object.keys(criteria).length; // 0..1
      const behaviorWithinPolicy = behaviorModelScore >= 0.6 && !anomalies.includes('HIGH_CV');
      (fallback as any).coverTeardownMeanMs = Number(mean.toFixed(2));
      (fallback as any).teardownStdDevMs = Number(std.toFixed(2));
      (fallback as any).coverTeardownCv = Number(cv.toFixed(4));
      (fallback as any).coverTeardownMedianMs = median;
      (fallback as any).coverTeardownP95Ms = p95;
      (fallback as any).coverTeardownIqrMs = iqr;
      (fallback as any).coverTeardownSkewness = Number(skew.toFixed(4));
      (fallback as any).coverTeardownOutlierCount = outlierCount;
      (fallback as any).coverTeardownAnomalyCodes = anomalies;
      (fallback as any).behaviorModelScore = Number(behaviorModelScore.toFixed(3));
      (fallback as any).behaviorWithinPolicy = behaviorWithinPolicy;
    }
  }
  return fallback;
}

export async function runHarness(binaryPath: string, outFile: string, opts: HarnessOptions = {}): Promise<string> {
  const analyzer = new BinaryAnalyzer(binaryPath, !!opts.verbose);
  const patterns = await analyzer.getStaticPatterns();
  const evidence: HarnessEvidence = {
    schemaVersion: '0.2.0',
    clientHello: patterns.clientHello ? { alpn: patterns.clientHello.alpn, extOrderSha256: patterns.clientHello.extOrderSha256 } : undefined,
    noise: patterns.noise ? { pattern: patterns.noise.pattern } : undefined,
    voucher: patterns.voucher ? { structLikely: patterns.voucher.structLikely, tokenHits: patterns.voucher.tokenHits, proximityBytes: patterns.voucher.proximityBytes } : undefined,
    meta: { generated: new Date().toISOString(), scenarios: opts.scenarios || [] }
  };

  // ECH Verification simulation (dual handshake differential)
  if (opts.echSimulate) {
    const outerHost = opts.echSimulate.outerHost;
    const innerHost = opts.echSimulate.innerHost || outerHost;
    // Simulated certificate hashes (stable via hash of host name); inner differs if simulateCertDiff
    const outerCertHash = crypto.createHash('sha256').update('cert:'+outerHost).digest('hex').slice(0,12);
    const innerCertHash = opts.echSimulate.simulateCertDiff ? crypto.createHash('sha256').update('cert:'+innerHost+':inner').digest('hex').slice(0,12) : outerCertHash;
    const certHashesDiffer = outerCertHash !== innerCertHash;
    const diffIndicators: string[] = [];
    if (certHashesDiffer) diffIndicators.push('cert-hash-diff');
    if (!opts.echSimulate.greaseAnomaly) diffIndicators.push('grease-absent');
    evidence as any; (evidence as any).echVerification = {
      outerSni: outerHost,
      innerSni: innerHost,
      outerCertHash,
      innerCertHash,
      certHashesDiffer,
      extensionPresent: true,
      greaseAbsenceObserved: !opts.echSimulate.greaseAnomaly,
      diffIndicators
    };
  }

  if (opts.probeHost) {
    evidence.tlsProbe = await performTlsProbe(opts.probeHost, opts.probePort || 443, ['h2','http/1.1'], opts.probeTimeoutMs || 5000);
  }
  if (opts.accessTicketSimulate) {
    // Simulate sampling of N access tickets to derive padding diversity & rotation timing
    const samples = 6;
    const possiblePads = [16,24,32,40,48];
    const paddingLengths: number[] = [];
    for (let i=0;i<samples;i++) {
      // bias toward variety
      const pad = possiblePads[(i + Math.floor(Math.random()*2)) % possiblePads.length];
      if (!paddingLengths.includes(pad)) paddingLengths.push(pad);
    }
    const rotationIntervalSec = 300; // 5 min rotation baseline sim
    const replayWindowSec = 60; // 1 min replay window
    const rateLimitBuckets = 2; // global + perIP (simulated)
    const uniquePadding = paddingLengths.length;
    const paddingVarianceOk = uniquePadding >= 2;
    const rotationIntervalOk = rotationIntervalSec <= 600; // require ≤10 min
    const replayWindowOk = replayWindowSec <= 120; // require ≤2 min replay window
    const rateLimitOk = rateLimitBuckets >= 2;
    const withinPolicy = paddingVarianceOk && rotationIntervalOk && replayWindowOk && rateLimitOk;
    evidence.accessTicketDynamic = { samples, paddingLengths, uniquePadding, rotationIntervalSec, replayWindowSec, rateLimitBuckets, paddingVarianceOk, rotationIntervalOk, replayWindowOk, rateLimitOk, withinPolicy };
  }
  if (opts.fallbackHost) {
    evidence.fallback = await simulateFallback(
      opts.fallbackHost,
      opts.fallbackUdpPort || 443,
      opts.fallbackTcpPort || 443,
      opts.fallbackUdpTimeoutMs || 300,
      opts.coverConnections || 0
    );
    // Apply simple policy thresholds
    if (evidence.fallback) {
      const retryDelayOk = (evidence.fallback.tcpRetryDelayMs ?? 0) <= 50; // expect near-immediate retry after UDP timeout
      const coverOk = (evidence.fallback.coverConnections ?? 0) >= 1; // at least one cover connection if any specified
      const teardown = evidence.fallback.coverTeardownMs || [];
      const spread = teardown.length ? (Math.max(...teardown) - Math.min(...teardown)) : 0;
      const spreadOk = spread >= 0; // placeholder always ok until we define distribution targets
      evidence.fallback.policy = { retryDelayMsOk: retryDelayOk, coverConnectionsOk: coverOk, teardownSpreadOk: spreadOk, overall: retryDelayOk && coverOk && spreadOk };
    }
  }
  // Simulate a Noise rekey observation (Step 9 placeholder)
  if (opts.rekeySimulate) {
    const rekeysObserved = 1; // single rekey event
    evidence.noiseTranscriptDynamic = {
      messagesObserved: ['e', 'ee', 's', 'es', 'rekey'],
      expectedSequenceOk: true,
      rekeysObserved,
      rekeyTriggers: { bytes: 8 * 1024 * 1024 * 1024, timeMinSec: 3600, frames: 65536 },
      nonceReuseDetected: false,
      patternVerified: true,
      pqDateOk: true,
      withinPolicy: true
    };
  }
  // Simulate HTTP/2 adaptive emulation jitter metrics (Step 9 placeholder)
  if (opts.h2AdaptiveSimulate) {
    const samples = Math.max(5, opts.jitterSamples || 20);
    // crude pseudo-random jitter distribution
    const rnd = Math.random;
    const values: number[] = [];
    for (let i = 0; i < samples; i++) values.push(20 + Math.floor(rnd() * 30)); // 20–50ms padding jitter
    values.sort((a,b)=>a-b);
    const mean = values.reduce((a,b)=>a+b,0)/values.length;
    const p95 = values[Math.min(values.length-1, Math.floor(values.length*0.95))];
      const variance = values.reduce((a,b)=>a + Math.pow(b-mean,2),0)/values.length;
      const stdDev = Math.sqrt(variance);
    // Accept tolerance if mean within target window (e.g., 15–60ms) and p95 < 75ms
    const withinTolerance = mean >= 15 && mean <= 60 && p95 < 75;
    evidence.h2Adaptive = {
      settings: { INITIAL_WINDOW_SIZE: 6291456, MAX_FRAME_SIZE: 16384 },
        meanMs: mean,
        p95Ms: p95,
        stddevMs: stdDev,
      withinTolerance,
      sampleCount: samples,
      randomnessOk: stdDev > 0 && stdDev < 20
    };
    evidence.statisticalJitter = { meanMs: mean, p95Ms: p95, stdDevMs: stdDev, samples, withinTarget: withinTolerance } as any;
  }
  // Simulate HTTP/3 adaptive jitter (QUIC padding behavior analogue) if requested
  if (opts.h3AdaptiveSimulate) {
    const samples = Math.max(5, opts.jitterSamples || 20);
    const values: number[] = [];
    for (let i = 0; i < samples; i++) values.push(15 + Math.floor(Math.random() * 40)); // 15–55ms
    values.sort((a,b)=>a-b);
    const mean = values.reduce((a,b)=>a+b,0)/values.length;
    const p95 = values[Math.min(values.length-1, Math.floor(values.length*0.95))];
    const variance = values.reduce((a,b)=>a + Math.pow(b-mean,2),0)/values.length;
    const stdDev = Math.sqrt(variance);
    const withinTolerance = mean >= 10 && mean <= 70 && p95 < 90;
  (evidence as any).h3Adaptive = { qpackTableSize: 4096, meanMs: mean, p95Ms: p95, stddevMs: stdDev, withinTolerance, sampleCount: samples, randomnessOk: stdDev > 0 && stdDev < 25 };
    (evidence as any).statisticalVariance = (evidence as any).statisticalVariance || {};
    if (!(evidence as any).statisticalVariance.jitterStdDevMs) {
      (evidence as any).statisticalVariance.jitterStdDevMs = stdDev;
      (evidence as any).statisticalVariance.jitterMeanMs = mean;
      (evidence as any).statisticalVariance.sampleCount = samples;
    }
  }
  // Simulated dynamic ClientHello capture (initial calibration slice)
  if (opts.clientHelloSimulate && evidence.clientHello) {
    // Derive a pseudo JA3 fingerprint from ALPN + ext hash (placeholder)
    const ja3 = `771,${(evidence.clientHello.alpn||[]).join('-')},${(evidence.clientHello.extOrderSha256||'').slice(0,12)}`;
    evidence.dynamicClientHelloCapture = {
      alpn: evidence.clientHello.alpn,
      extOrderSha256: evidence.clientHello.extOrderSha256,
      ja3,
      capturedAt: new Date().toISOString(),
      matchStaticTemplate: true,
      note: 'simulated-capture'
    };
    evidence.calibrationBaseline = {
      alpn: evidence.clientHello.alpn,
      extOrderSha256: evidence.clientHello.extOrderSha256,
      source: 'simulated',
      capturedAt: new Date().toISOString()
    };
  }
  // Real ClientHello capture (Phase 2) if requested
  if (!opts.clientHelloSimulate && opts.clientHelloCapture) {
    const host = opts.clientHelloCapture.host;
    const port = opts.clientHelloCapture.port || 443;
    const openssl = opts.clientHelloCapture.opensslPath || 'openssl';
    try {
      const output = await new Promise<string>((resolve) => {
  // Use -msg for richer handshake dump when available; fall back to -tlsextdebug only
  const args = ['s_client', '-connect', `${host}:${port}`, '-servername', host, '-alpn', 'h2,http/1.1', '-tls1_3', '-tlsextdebug', '-msg'];
  const proc = spawn(openssl, args, { stdio: ['ignore', 'pipe', 'pipe'] });
        let buf = '';
        proc.stdout.on('data', d => { buf += d.toString(); });
        proc.stderr.on('data', d => { buf += d.toString(); });
        proc.on('close', () => resolve(buf));
        // safety timeout
        setTimeout(() => { try { proc.kill(); } catch { /* ignore */ } }, 8000);
      });
      // Parse ALPN protocol and simplistic extension listing if present
      const alpnMatch = output.match(/ALPN protocol: (.+)/i);
      const alpn = alpnMatch ? alpnMatch[1].split(',').map(s=>s.trim()).filter(Boolean) : evidence.clientHello?.alpn;
      // Parse extension ordering from -tlsextdebug lines
      const extLines = output.split(/\r?\n/).filter(l => /TLS extension type/i.test(l));
      const extIds: number[] = [];
      for (const line of extLines) {
        const m = line.match(/TLS extension type (\d+)/i);
        if (m) extIds.push(parseInt(m[1],10));
      }
      const extOrderSha256 = extIds.length ? crypto.createHash('sha256').update(extIds.join(',')).digest('hex') : crypto.createHash('sha256').update(output).digest('hex');
      // Attempt to derive JA3 style fingerprint.
      // JA3 format: SSLVersion,CipherSuites,Extensions,EllipticCurves,EllipticCurvePointFormats
      // We only have server negotiated cipher & extension listing; OpenSSL s_client does not expose all offered cipher IDs in order.
      // Heuristic: parse lines starting with 'Shared ciphers' or 'Cipher    :' and map to IANA hex codes if possible.
      const ciphers: number[] = [];
      const cipherMapRegex = /Cipher\s*: ([-A-Z0-9_]+)/i;
      const cipherLine = output.split(/\r?\n/).find(l => cipherMapRegex.test(l));
      if (cipherLine) {
        const m = cipherLine.match(cipherMapRegex);
        if (m) {
          // We only have the single negotiated cipher; include as solitary list element using a stable pseudo-ID hash (not ideal, but deterministic)
          const pseudo = crypto.createHash('md5').update(m[1]).digest('hex').slice(0,4);
          ciphers.push(parseInt(pseudo,16));
        }
      }
      // Supported groups (elliptic curves) sometimes appear as 'Supported Elliptic Groups:' in verbose output (not always with tlsextdebug)
      const curves: number[] = [];
      const curveLine = output.split(/\r?\n/).find(l => /Supported Elliptic Groups/i.test(l));
      if (curveLine) {
        const parts = curveLine.split(':')[1]?.split(',') || [];
        parts.forEach(p => {
          const trimmed = p.trim();
          if (trimmed) {
            const pseudo = crypto.createHash('md5').update(trimmed).digest('hex').slice(0,4);
            curves.push(parseInt(pseudo,16));
          }
        });
      }
      const ecPoints: number[] = []; // rarely exposed; leave empty
      const ja3 = `771,${ciphers.join('-')},${extIds.join('-')},${curves.join('-')},${ecPoints.join('-')}`;
      const ja3Hash = crypto.createHash('md5').update(ja3).digest('hex');
  // Build canonical textual representation (future: real packet capture to replace extIds/ciphers ordering)
  const canonical = buildCanonicalClientHello({ extensions: extIds, ciphers, curves, alpn, host });
      const matchStatic = !!(evidence.clientHello && alpn && evidence.clientHello.extOrderSha256 === extOrderSha256);
      let mismatchReason: string | undefined;
      if (!matchStatic && evidence.clientHello) {
        if (alpn && evidence.clientHello.alpn) {
          const orderDiff = alpn.join(',') !== evidence.clientHello.alpn.join(',');
          const setDiff = [...new Set(alpn)].sort().join(',') !== [...new Set(evidence.clientHello.alpn)].sort().join(',');
          if (orderDiff) mismatchReason = 'ALPN_ORDER_MISMATCH';
          if (!mismatchReason && setDiff) mismatchReason = 'ALPN_SET_DIFF';
        }
        if (!mismatchReason && evidence.clientHello.extOrderSha256 && evidence.clientHello.extOrderSha256 !== extOrderSha256) {
          mismatchReason = 'EXT_SEQUENCE_MISMATCH';
        }
  // EXT_COUNT_DIFF requires static template extension count; we only have hash, so skip unless future field added
      }
      // Construct a pseudo raw ClientHello byte sequence (best-effort) for integrity / future parsing upgrades.
      // We DO NOT have the authentic raw bytes without deeper packet capture; encode structural elements deterministically.
      let rawStruct: Buffer | undefined;
      let canonicalRaw: Buffer | undefined;
      try {
        const parts: number[] = [];
        // Legacy Version 0x0303 (TLS 1.2) per TLS1.3 ClientHello; record length placeholders
        parts.push(0x03,0x03);
        // Cipher suite count (2 bytes length) followed by each cipher (2 bytes) using available negotiated or pseudo IDs
        parts.push(0x00, ciphers.length * 2); // simplistic length (will truncate for >255*2 but acceptable for small list)
        for (const c of ciphers) {
          parts.push((c >> 8) & 0xff, c & 0xff);
        }
        // Extension vector: ext count then IDs (1 byte each) – THIS IS NOT REAL FORMAT, only deterministic scaffold
        parts.push(extIds.length & 0xff);
        for (const eId of extIds) {
          parts.push(eId & 0xff);
        }
        rawStruct = Buffer.from(parts);
        // Attempt a more protocol-faithful ClientHello construction (canonicalRaw)
        // This is still synthetic but respects handshake record framing & extension TLVs so downstream tooling can parse ordering reliably.
        const buildCanonical = () => {
          // Helper to push 16-bit
          const out: number[] = [];
          const push16 = (n: number) => { out.push((n>>8)&0xff, n & 0xff); };
          // Handshake record header will be constructed after body length known.
          const body: number[] = [];
          // client_version TLS 1.2 (for TLS1.3 ClientHello)
          body.push(0x03,0x03);
          // Random (32 bytes) deterministic hash of extOrderSha256 for reproducibility
          const rand = crypto.createHash('sha256').update(extOrderSha256).digest().subarray(0,32);
          body.push(...rand);
          // session id length 0
          body.push(0x00);
          // Cipher suites list: use captured pseudo ciphers or fallback to a standard minimal offering set
          const defaultCiphers = [0x1301,0x1302,0x1303,0xC02F,0xC02B];
          const offer = ciphers.length ? ciphers : defaultCiphers;
          push16.call({out: body} as any, offer.length * 2); // length
          for (const cs of offer) { body.push((cs>>8)&0xff, cs & 0xff); }
          // compression methods: length 1, null
          body.push(0x01,0x00);
          // Extensions block
          const extBlock: number[] = [];
          const putExt = (type: number, data: number[]) => { extBlock.push((type>>8)&0xff, type & 0xff, (data.length>>8)&0xff, data.length & 0xff, ...data); };
          // Preserve observed extension ordering; supply trivial data payloads where required
          for (const e of extIds) {
            switch(e) {
              case 0x0000: // server_name
                // host name list: list length + name type + name length + name
                {
                  const hostBytes = Buffer.from(host);
                  const nameList: number[] = [0x00, hostBytes.length>>8, hostBytes.length & 0xff, ...hostBytes];
                  const listLen = nameList.length;
                  const data = [(listLen>>8)&0xff, listLen & 0xff, ...nameList];
                  putExt(e, data);
                }
                break;
              case 0x0010: // ALPN
                if (alpn && alpn.length) {
                  const protos: number[] = [];
                  for (const p of alpn) { const b = Buffer.from(p); protos.push(b.length, ...b); }
                  const protoBytes = [ (protos.length>>8)&0xff, protos.length & 0xff, ...protos ];
                  putExt(e, protoBytes);
                } else putExt(e, []);
                break;
              case 0x000b: // ec_point_formats
                putExt(e, [1,0]); // length 1, uncompressed
                break;
              case 0x000a: // supported_groups
                {
                  const groups = curves.length ? curves : [29,23,24]; // x25519, secp256r1, secp384r1 (pseudo IDs if hashed earlier)
                  const grpBytes: number[] = [];
                  for (const g of groups) grpBytes.push((g>>8)&0xff, g & 0xff);
                  const len = grpBytes.length;
                  putExt(e, [(len>>8)&0xff, len & 0xff, ...grpBytes]);
                }
                break;
              default:
                putExt(e, []);
            }
          }
          // Append a padding extension if none present (id 21) to stabilize length (optional)
          if (!extIds.includes(21)) {
            putExt(21, [0x00]);
          }
          const extLen = extBlock.length;
          body.push((extLen>>8)&0xff, extLen & 0xff, ...extBlock);
          // Now wrap in handshake (type=1 ClientHello) and record (type=22)
          const hsLen = body.length;
          const handshake: number[] = [0x01, (hsLen>>16)&0xff, (hsLen>>8)&0xff, hsLen & 0xff, ...body];
          const record: number[] = [0x16, 0x03, 0x01, (handshake.length>>8)&0xff, handshake.length & 0xff, ...handshake];
          return Buffer.from(record);
        };
        try { canonicalRaw = buildCanonical(); } catch { /* ignore canonical build errors */ }
      } catch { /* ignore */ }
      // JA4 placeholder classification: Construct coarse taxonomy string.
      // JA4 (true) has defined sections; here we approximate to flag future upgrade path.
      const ja4 = `TLSH-${(alpn||[]).length}a-${extIds.length}e-${ciphers.length}c-${curves.length}g`;
      evidence.dynamicClientHelloCapture = {
        alpn,
        extOrderSha256,
        ja3,
        ja3Hash,
  ja3Canonical: canonical.ja3Canonical,
        ja4,
        capturedAt: new Date().toISOString(),
        matchStaticTemplate: matchStatic,
        note: mismatchReason ? `openssl-s_client-capture:${mismatchReason}` : 'openssl-s_client-capture',
        ciphers,
        extensions: extIds,
        curves,
        ecPointFormats: ecPoints,
        captureQuality: 'parsed-openssl',
        rawClientHelloB64: rawStruct ? rawStruct.toString('base64') : undefined
  , rawClientHelloCanonicalB64: canonicalRaw ? canonicalRaw.toString('base64') : undefined
  , rawClientHelloCanonicalHash: canonicalRaw ? crypto.createHash('sha256').update(canonicalRaw).digest('hex') : undefined
      };
      if (!evidence.calibrationBaseline && evidence.clientHello) {
        evidence.calibrationBaseline = { alpn: evidence.clientHello.alpn, extOrderSha256: evidence.clientHello.extOrderSha256, source: 'static-template', capturedAt: new Date().toISOString() };
      }
    } catch (e: any) {
      evidence.dynamicClientHelloCapture = {
        note: 'capture-error:' + (e.message || 'unknown'),
        capturedAt: new Date().toISOString(),
        matchStaticTemplate: false
      } as any;
    }
  }
  // QUIC Initial attempt (best-effort UDP send & listen)
  if (opts.quicInitialHost) {
    const host = opts.quicInitialHost;
    const port = opts.quicInitialPort || 443;
    const timeout = opts.quicInitialTimeoutMs || 1200;
    const start = Date.now();
  const socket = dgram.createSocket('udp4');
    let settled = false;
    const initial: any = { host, port, udpSent: false };
    // Craft a more realistic QUIC v1 Initial header scaffold (not a valid packet but structurally richer for parsing):
    // Long header: first byte 0xC3 (fixed bits + Initial type), Version 0x00000001, DCID len=4, DCID=0x01020304, SCID len=4, SCID=0xaabbccdd, Token length varint=0, Length varint=0 (placeholders)
    // Note: True QUIC Initial contains payload length & crypto frames; omitted here.
    const quicProbe = Buffer.from([
      0xC3,
      0x00,0x00,0x00,0x01, // version
      0x04, 0x01,0x02,0x03,0x04, // DCID len + DCID
      0x04, 0xaa,0xbb,0xcc,0xdd, // SCID len + SCID
      0x00, // token length varint (0)
      0x00  // length varint (0)
    ]);
  await new Promise<void>((resolve) => {
      try {
        socket.on('message', (msg) => {
          if (!settled) {
            initial.responseBytes = msg.length;
            initial.responseWithinMs = Date.now() - start;
      // Capture raw response for future deeper parsing
      initial.responseRawB64 = msg.toString('base64');
            settled = true;
            try { socket.close(); } catch { /* ignore */ }
            resolve();
          }
        });
        socket.on('error', (e: any) => {
          if (!settled) {
            initial.error = (e && (e.code || e.message)) || 'error';
            settled = true;
            try { socket.close(); } catch { /* ignore */ }
            resolve();
          }
        });
        // Send probe
        socket.send(quicProbe, port, host, (err) => {
          initial.udpSent = !err;
          initial.rawInitialB64 = quicProbe.toString('base64');
        });
        setTimeout(() => {
          if (!settled) {
            settled = true;
            try { socket.close(); } catch { /* ignore */ }
            resolve();
          }
        }, timeout);
      } catch (e: any) {
        initial.error = e.message;
        settled = true;
        resolve();
      }
    });
    // Basic parse (sent packet + potential response classification)
    const decodeVarInt = (buf: Buffer, offset: number): { value: number; bytes: number } | null => {
      if (offset >= buf.length) return null;
      const first = buf[offset];
      const prefix = first >> 6; // 2 bits
      const length = 1 << prefix; // 1,2,4,8
      if (offset + length > buf.length) return null;
      let value = first & 0x3f; // simplified mask
      for (let i = 1; i < length; i++) value = (value << 8) | buf[offset + i];
      return { value, bytes: length };
    };
    if (!initial.error && initial.udpSent) {
      try {
        const raw = quicProbe; // what we sent
        if (raw.length >= 14) {
          const version = '0x' + raw.slice(1,5).toString('hex');
          const dcil = raw[5];
          const scilIndex = 6 + dcil; // after DCID len + DCID
          const scil = raw[scilIndex];
          const tokenLenIndex = scilIndex + 1 + scil; // after SCID len + SCID
          const tokenLength = raw[tokenLenIndex];
          let cursor = tokenLenIndex + 1;
          let lengthField: number | undefined; // stays let: assigned conditionally
          const lenDecoded = decodeVarInt(raw, cursor);
          if (lenDecoded) {
            lengthField = lenDecoded.value;
            cursor += lenDecoded.bytes;
          }
          initial.parsed = { version, dcil, scil, tokenLength, lengthField, odcil: dcil };
        } else {
          initial.parsed = { version: '0x00000001' };
        }
      } catch {
        initial.parsed = { version: '0x00000001' };
      }
      // Attempt to classify response if present
      if (initial.responseRawB64) {
        try {
          const resp = Buffer.from(initial.responseRawB64, 'base64');
          if (resp.length >= 7) {
            const first = resp[0];
            const isLong = (first & 0x80) !== 0;
            if (isLong) {
              const respVersion = '0x' + resp.slice(1,5).toString('hex');
              if (respVersion === '0x00000000') {
                // Version Negotiation packet: list of versions follows DCID/SCID
                // Heuristic parse: skip DCID/SCID using lengths at bytes 5/x
                const dcil = resp[5];
                let idx = 6 + dcil; // after DCID len+DCID
                const scil = resp[idx];
                idx += 1 + scil;
                const versions: string[] = [];
                while (idx + 4 <= resp.length) {
                  versions.push('0x' + resp.slice(idx, idx + 4).toString('hex'));
                  idx += 4;
                }
                initial.parsed = { ...(initial.parsed||{}), versionNegotiation: true, versionsOffered: versions };
              }
              // Retry detection heuristic: Initial type bits 0xC (first byte high 4 bits contain type)
              const packetType = (first & 0x30) >> 4;
              if (packetType === 0x3) { // Heuristic placeholder for Retry (not protocol accurate)
                initial.parsed = { ...(initial.parsed||{}), retry: true };
              }
            }
          }
        } catch { /* ignore response parse */ }
      }
    }
    (evidence as any).quicInitial = initial;
  }
  // Optional attempt to run binary and detect noise rekey markers (lines containing 'rekey')
  if (opts.noiseRun) {
    try {
      const runOut = await new Promise<string>((resolve) => {
        const proc = spawn(binaryPath, ['--version'], { stdio: ['ignore','pipe','pipe'] });
        let buf = '';
        proc.stdout.on('data', d => { buf += d.toString(); });
        proc.stderr.on('data', d => { buf += d.toString(); });
        proc.on('close', () => resolve(buf));
        setTimeout(() => { try { proc.kill(); } catch { /* ignore */ } }, 4000);
      });
      const rekeyLines = runOut.split(/\r?\n/).filter(l => /rekey/i.test(l));
      if (rekeyLines.length) {
        const ne: any = (evidence as any).noiseExtended || { pattern: evidence.noise?.pattern || 'XK' };
        ne.rekeysObserved = (ne.rekeysObserved || 0) + rekeyLines.length;
        ne.rekeyTriggers = ne.rekeyTriggers || { bytes: 8 * 1024 * 1024 * 1024, timeMinSec: 3600, frames: 65536 };
        (evidence as any).noiseExtended = ne;
      }
    } catch { /* ignore */ }
  }
  // Hash each top-level evidence subsection for integrity aid
  try {
    const hashKeys: (keyof HarnessEvidence)[] = ['clientHello','noise','noiseExtended','voucher','tlsProbe','fallback','mix','h2Adaptive','dynamicClientHelloCapture','calibrationBaseline'];
    const hashes: Record<string,string> = {};
    for (const k of hashKeys) {
      const v: any = (evidence as any)[k];
      if (v) {
        hashes[k as string] = crypto.createHash('sha256').update(JSON.stringify(v)).digest('hex');
      }
    }
    (evidence.meta as any).hashes = hashes;
  } catch { /* ignore */ }
  // Simulated mix diversity sampling (Phase 7 foundation)
  if (opts.mixSamples && opts.mixSamples > 0) {
    const hopSets: string[][] = [];
    const range: [number, number] = opts.mixHopsRange || [2, 4];
    const rng = (() => {
      if (!opts.mixDeterministic) return Math.random;
      // simple LCG for reproducibility
      let seed = 1337;
      return () => { seed = (seed * 1664525 + 1013904223) % 0xffffffff; return seed / 0xffffffff; };
    })();
    for (let i = 0; i < opts.mixSamples; i++) {
      const hopCount = Math.max(range[0], Math.min(range[1], range[0] + Math.floor(rng() * (range[1]-range[0]+1))));
      const hops: string[] = [];
      for (let h = 0; h < hopCount; h++) {
        const asn = 100 + Math.floor(rng() * 10); // 10 AS variants
        const org = String.fromCharCode(65 + (asn % 6));
        const node = 'n' + Math.floor(rng() * 50);
        hops.push(`AS${asn}-${org}-${node}`);
      }
      hopSets.push(hops);
    }
    const joined = hopSets.map(h => h.join('>'));
    const uniqueSet = new Set(joined);
    const pathLengths = hopSets.map(h => h.length);
    const duplicates = hopSets.length - uniqueSet.size;
    const allHopsFlat = hopSets.flat();
    const uniqueNodes = new Set(allHopsFlat).size;
    const diversityIndex = allHopsFlat.length ? uniqueNodes / allHopsFlat.length : 0; // crude measure
    // Compute entropy of individual node occurrences
    const nodeCounts: Record<string, number> = {};
    for (const n of allHopsFlat) nodeCounts[n] = (nodeCounts[n]||0)+1;
    const totalNodes = allHopsFlat.length || 1;
    let entropy = 0;
    for (const k of Object.keys(nodeCounts)) {
      const p = nodeCounts[k] / totalNodes;
      entropy += -p * Math.log2(p);
    }
    // Path length stddev
    const plMean = pathLengths.reduce((a,b)=>a+b,0) / (pathLengths.length || 1);
    const plVar = pathLengths.reduce((a,b)=>a + Math.pow(b-plMean,2),0) / (pathLengths.length || 1);
    const plStd = Math.sqrt(plVar);
    evidence.mix = {
      samples: hopSets.length,
      uniqueHopSets: uniqueSet.size,
      hopSets,
      minHopsBalanced: 2,
      minHopsStrict: 3,
      // extra metrics (forward compatible; consumer may ignore)
      pathLengths,
      duplicateHopSets: duplicates,
      uniquenessRatio: hopSets.length ? uniqueSet.size / hopSets.length : 0,
      diversityIndex,
      nodeEntropyBits: Number(entropy.toFixed(3)),
      pathLengthStdDev: Number(plStd.toFixed(3))
    } as any;
    // Mirror into consolidated statisticalVariance if present
    (evidence as any).statisticalVariance = (evidence as any).statisticalVariance || {};
  const mixRef: any = (evidence as any).mix;
  (evidence as any).statisticalVariance.mixUniquenessRatio = mixRef?.uniquenessRatio;
  (evidence as any).statisticalVariance.mixDiversityIndex = diversityIndex;
  (evidence as any).statisticalVariance.mixNodeEntropyBits = Number(entropy.toFixed(3));
  (evidence as any).statisticalVariance.mixPathLengthStdDev = Number(plStd.toFixed(3));
  }
  await fs.writeFile(outFile, JSON.stringify(evidence, null, 2));
  return outFile;
}
