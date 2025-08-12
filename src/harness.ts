import * as fs from 'fs-extra';
import { BinaryAnalyzer } from './analyzer';
import * as tls from 'tls';
import * as net from 'net';
import * as dgram from 'dgram';

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
}

export interface HarnessEvidence {
  schemaVersion?: string;
  clientHello?: { alpn?: string[]; extOrderSha256?: string };
  noise?: { pattern?: string };
  voucher?: { structLikely?: boolean; tokenHits?: string[]; proximityBytes?: number };
  tlsProbe?: { host: string; port: number; offeredAlpn: string[]; selectedAlpn?: string | null; cipher?: string; protocol?: string | null; handshakeMs?: number; error?: string };
  fallback?: { udpAttempted: boolean; udpTimeoutMs: number; tcpConnected: boolean; tcpConnectMs?: number; tcpRetryDelayMs?: number; coverConnections?: number; coverTeardownMs?: number[]; error?: string };
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
  await fs.writeFile(outFile, JSON.stringify(evidence, null, 2));
  return outFile;
}
