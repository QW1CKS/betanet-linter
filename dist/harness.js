"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.runHarness = runHarness;
const fs = __importStar(require("fs-extra"));
const analyzer_1 = require("./analyzer");
const tls = __importStar(require("tls"));
const net = __importStar(require("net"));
const dgram = __importStar(require("dgram"));
// Lightweight TLS probe (scaffold) – Phase 2 foundation
// Captures negotiated ALPN, cipher, protocol version and basic timing.
async function performTlsProbe(host, port = 443, offeredAlpn = ['h2', 'http/1.1'], timeoutMs = 5000) {
    return await new Promise(resolve => {
        const start = Date.now();
        let settled = false;
        const outcome = { host, port, offeredAlpn };
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
                if (cipher)
                    outcome.cipher = cipher.name;
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
                    try {
                        socket.destroy();
                    }
                    catch { /* ignore */ }
                    resolve(outcome);
                }
            });
            socket.on('error', (err) => {
                if (!settled) {
                    outcome.error = err.code || err.message || 'error';
                    outcome.handshakeMs = Date.now() - start;
                    settled = true;
                    resolve(outcome);
                }
            });
        }
        catch (e) {
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
async function simulateFallback(host, udpPort, tcpPort, udpTimeoutMs, coverConnections = 0) {
    const start = Date.now();
    const udpSocket = dgram.createSocket('udp4');
    let udpDone = false;
    // Send a single empty datagram (most likely no listener -> silent drop)
    try {
        udpSocket.send(Buffer.from('ping'), udpPort, host, () => { });
    }
    catch { /* ignore */ }
    const fallback = { udpAttempted: true, udpTimeoutMs, tcpConnected: false };
    await new Promise(r => setTimeout(r, udpTimeoutMs));
    udpDone = true;
    try {
        udpSocket.close();
    }
    catch { /* ignore */ }
    const tcpStart = Date.now();
    let tcpConnected = false;
    await new Promise(resolve => {
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
                try {
                    sock.destroy();
                }
                catch { /* ignore */ }
                resolve();
            });
            sock.on('error', (e) => {
                fallback.error = fallback.error || e.code || e.message;
                resolve();
            });
        }
        catch (e) {
            fallback.error = fallback.error || e.message;
            resolve();
        }
    });
    if (coverConnections && coverConnections > 0) {
        const teardown = [];
        for (let i = 0; i < coverConnections; i++) {
            const cStart = Date.now();
            await new Promise(res => {
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
                }
                catch {
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
async function runHarness(binaryPath, outFile, opts = {}) {
    const analyzer = new analyzer_1.BinaryAnalyzer(binaryPath, !!opts.verbose);
    const patterns = await analyzer.getStaticPatterns();
    const evidence = {
        schemaVersion: '0.2.0',
        clientHello: patterns.clientHello ? { alpn: patterns.clientHello.alpn, extOrderSha256: patterns.clientHello.extOrderSha256 } : undefined,
        noise: patterns.noise ? { pattern: patterns.noise.pattern } : undefined,
        voucher: patterns.voucher ? { structLikely: patterns.voucher.structLikely, tokenHits: patterns.voucher.tokenHits, proximityBytes: patterns.voucher.proximityBytes } : undefined,
        meta: { generated: new Date().toISOString(), scenarios: opts.scenarios || [] }
    };
    if (opts.probeHost) {
        evidence.tlsProbe = await performTlsProbe(opts.probeHost, opts.probePort || 443, ['h2', 'http/1.1'], opts.probeTimeoutMs || 5000);
    }
    if (opts.fallbackHost) {
        evidence.fallback = await simulateFallback(opts.fallbackHost, opts.fallbackUdpPort || 443, opts.fallbackTcpPort || 443, opts.fallbackUdpTimeoutMs || 300, opts.coverConnections || 0);
    }
    await fs.writeFile(outFile, JSON.stringify(evidence, null, 2));
    return outFile;
}
//# sourceMappingURL=harness.js.map