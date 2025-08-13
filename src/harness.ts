import * as fs from 'fs-extra';
import { BinaryAnalyzer } from './analyzer';
import * as tls from 'tls';
import * as net from 'net';
import * as dgram from 'dgram';
import { spawn } from 'child_process';
import * as crypto from 'crypto';

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
  jitterSamples?: number; // number of jitter samples to simulate
  clientHelloSimulate?: boolean; // simulate dynamic ClientHello capture (Step 11 initial slice)
  clientHelloCapture?: { host: string; port?: number; opensslPath?: string }; // real capture target
  quicInitialHost?: string; // target host for QUIC Initial attempt
  quicInitialPort?: number; // target port (default 443)
  quicInitialTimeoutMs?: number; // wait for response
  noiseRun?: boolean; // attempt to run binary to observe real noise rekey markers
}

export interface HarnessEvidence {
  schemaVersion?: string;
  clientHello?: { alpn?: string[]; extOrderSha256?: string };
  noise?: { pattern?: string };
  // Extended noise evidence (Step 9)
  // eslint-disable-next-line @typescript-eslint/consistent-type-definitions
  noiseExtended?: { pattern?: string; rekeysObserved?: number; rekeyTriggers?: { bytes?: number; timeMinSec?: number; frames?: number } };
  voucher?: { structLikely?: boolean; tokenHits?: string[]; proximityBytes?: number };
  tlsProbe?: { host: string; port: number; offeredAlpn: string[]; selectedAlpn?: string | null; cipher?: string; protocol?: string | null; handshakeMs?: number; error?: string };
  fallback?: { udpAttempted: boolean; udpTimeoutMs: number; tcpConnected: boolean; tcpConnectMs?: number; tcpRetryDelayMs?: number; coverConnections?: number; coverTeardownMs?: number[]; error?: string };
  mix?: { samples: number; uniqueHopSets: number; hopSets: string[][]; minHopsBalanced: number; minHopsStrict: number };
  h2Adaptive?: { settings?: Record<string, number>; paddingJitterMeanMs?: number; paddingJitterP95Ms?: number; withinTolerance?: boolean; sampleCount?: number };
  dynamicClientHelloCapture?: { alpn?: string[]; extOrderSha256?: string; ja3?: string; capturedAt?: string; matchStaticTemplate?: boolean; note?: string };
  calibrationBaseline?: { alpn?: string[]; extOrderSha256?: string; source?: string; capturedAt?: string };
  quicInitial?: { host: string; port: number; udpSent: boolean; responseBytes?: number; responseWithinMs?: number; error?: string };
  meta: { generated: string; scenarios: string[] };
}

async function simulateFallback(host: string, udpPort: number, tcpPort: number, udpTimeoutMs: number, coverConnections: number = 0): Promise<HarnessEvidence['fallback']> {
  const start = Date.now();
  const udpSocket = dgram.createSocket('udp4');
  let udpDone = false;
  // Send a single empty datagram (most likely no listener -> silent drop)
  try { udpSocket.send(Buffer.from('ping'), udpPort, host, () => { /* noop */ }); } catch { /* ignore */ }
  const fallback: HarnessEvidence['fallback'] = { udpAttempted: true, udpTimeoutMs, tcpConnected: false };
  await new Promise(r => setTimeout(r, udpTimeoutMs));
  udpDone = true;
  try { udpSocket.close(); } catch { /* ignore */ }
  const tcpStart = Date.now();
  let tcpConnected = false;
  await new Promise<void>(resolve => {
    try {
      const sock = net.createConnection({ host, port: tcpPort, timeout: 4000 }, () => {
        tcpConnected = true;
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

  if (opts.probeHost) {
    evidence.tlsProbe = await performTlsProbe(opts.probeHost, opts.probePort || 443, ['h2','http/1.1'], opts.probeTimeoutMs || 5000);
  }
  if (opts.fallbackHost) {
    evidence.fallback = await simulateFallback(
      opts.fallbackHost,
      opts.fallbackUdpPort || 443,
      opts.fallbackTcpPort || 443,
      opts.fallbackUdpTimeoutMs || 300,
      opts.coverConnections || 0
    );
  }
  // Simulate a Noise rekey observation (Step 9 placeholder)
  if (opts.rekeySimulate) {
    const rekeysObserved = 1; // single rekey event
    evidence.noiseExtended = {
      pattern: evidence.noise?.pattern || 'XK',
      rekeysObserved,
      rekeyTriggers: { bytes: 8 * 1024 * 1024 * 1024, timeMinSec: 3600, frames: 65536 }
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
    // Accept tolerance if mean within target window (e.g., 15–60ms) and p95 < 75ms
    const withinTolerance = mean >= 15 && mean <= 60 && p95 < 75;
    evidence.h2Adaptive = {
      settings: { INITIAL_WINDOW_SIZE: 6291456, MAX_FRAME_SIZE: 16384 },
      paddingJitterMeanMs: mean,
      paddingJitterP95Ms: p95,
      withinTolerance,
      sampleCount: samples
    };
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
        const proc = spawn(openssl, ['s_client', '-connect', `${host}:${port}`, '-servername', host, '-alpn', 'h2,http/1.1', '-tls1_3', '-tlsextdebug'], { stdio: ['ignore', 'pipe', 'pipe'] });
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
      // Derive pseudo JA3 (not full fidelity without raw ClientHello bytes); we note degraded fidelity
      const ja3 = `sim-${extOrderSha256.slice(0,12)}`;
      evidence.dynamicClientHelloCapture = {
        alpn,
        extOrderSha256,
        ja3,
        capturedAt: new Date().toISOString(),
        matchStaticTemplate: !!(evidence.clientHello && alpn && evidence.clientHello.extOrderSha256 === extOrderSha256),
        note: 'openssl-s_client-capture'
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
    await new Promise<void>((resolve) => {
      try {
        socket.on('message', (msg) => {
          if (!settled) {
            initial.responseBytes = msg.length;
            initial.responseWithinMs = Date.now() - start;
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
        // Craft minimal QUIC long header (not a valid handshake, just presence poke)
        const probe = Buffer.from([0xC3,0,0,0,0, 0,0,0,0, 0]);
        socket.send(probe, port, host, (err) => {
          initial.udpSent = !err;
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
      diversityIndex
    } as any;
  }
  await fs.writeFile(outFile, JSON.stringify(evidence, null, 2));
  return outFile;
}
