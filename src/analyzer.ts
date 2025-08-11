import * as fs from 'fs-extra';
import * as path from 'path';
import { AnalyzerDiagnostics } from './types';
import { safeExec, isToolSkipped } from './safe-exec';
import { FALLBACK_MAX_BYTES, DEFAULT_FALLBACK_STRING_MIN_LEN, DEFAULT_TOOL_TIMEOUT_MS } from './constants';
import { detectNetwork, detectCrypto, detectSCION, detectDHT, detectLedger, detectPayment, detectBuildProvenance } from './heuristics';
// Removed unused execa import; all external commands routed through safeExec for centralized timeout control

export class BinaryAnalyzer {
  private binaryPath: string;
  private verbose: boolean;
  private dynamicProbe: boolean = false; // enable lightweight runtime '--help' probe enrichment
  private cachedAnalysis: Promise<{
    strings: string[];
    symbols: string[];
    fileFormat: string;
    architecture: string;
    dependencies: string[];
    size: number;
  }> | null = null;
  private diagnostics: AnalyzerDiagnostics = {
    tools: [],
    analyzeInvocations: 0,
    cached: false
  };
  private analysisStartHr: [number, number] | null = null;
  private toolsReady: Promise<void>;

  constructor(binaryPath: string, verbose: boolean = false) {
    this.binaryPath = binaryPath;
    this.verbose = verbose;
  this.toolsReady = this.detectTools();
  }

  setDynamicProbe(flag: boolean) {
    this.dynamicProbe = !!flag;
  }

  getDiagnostics(): AnalyzerDiagnostics {
    return this.diagnostics;
  }

  private async detectTools(): Promise<void> {
    const isWindows = process.platform === 'win32';
    this.diagnostics.platform = process.platform;
    const degradationReasons: string[] = [];
    const toolCandidates: { name: string; args: string[] }[] = [
      { name: 'strings', args: ['--version'] },
      { name: 'nm', args: ['--version'] },
      { name: 'objdump', args: ['--version'] },
      { name: 'ldd', args: ['--version'] },
      { name: 'file', args: ['--version'] },
      { name: 'uname', args: ['-m'] }
    ];
    const checks = toolCandidates.map(async t => {
      const start = Date.now();
      try {
        if (isToolSkipped(t.name)) {
          this.diagnostics.tools.push({ name: t.name, available: false, error: 'skipped-by-config' });
          this.diagnostics.degraded = true;
          this.diagnostics.skippedTools = [...(this.diagnostics.skippedTools || []), t.name];
          return;
        }
  const res = await safeExec(t.name, t.args, DEFAULT_TOOL_TIMEOUT_MS);
        if (!res.failed) {
          this.diagnostics.tools.push({ name: t.name, available: true, durationMs: Date.now() - start });
        } else {
          this.diagnostics.tools.push({ name: t.name, available: false, error: res.errorMessage });
          if (res.timedOut) {
            this.diagnostics.timedOutTools = [...(this.diagnostics.timedOutTools || []), t.name];
          }
        }
      } catch (e: any) {
        this.diagnostics.tools.push({ name: t.name, available: false, error: e?.shortMessage || e?.message });
      }
    });
    await Promise.all(checks);
    const unavailable = this.diagnostics.tools.filter(t => !t.available);
    if (unavailable.length) {
      this.diagnostics.degraded = true;
      this.diagnostics.skippedTools = unavailable.filter(t => t.error === 'skipped-by-config').map(t => t.name);
      this.diagnostics.missingCoreTools = unavailable.map(t => t.name);
      if (isWindows) degradationReasons.push('native-windows-missing-unix-tools');
    }
    if (isWindows) degradationReasons.push('consider-installing-binutils-or-use-WSL');
    if (this.diagnostics.degraded) this.diagnostics.degradationReasons = degradationReasons;
  }

  async analyze(): Promise<{ strings: string[]; symbols: string[]; fileFormat: string; architecture: string; dependencies: string[]; size: number; }> {
    // Ensure tool detection finished (especially for tests manipulating env)
    if (this.toolsReady) {
      try { await this.toolsReady; } catch { /* ignore */ }
    }
    if (this.cachedAnalysis) {
      this.diagnostics.cached = true;
      return this.cachedAnalysis;
    }
    if (this.verbose) {
      console.log(`📊 Analyzing binary: ${this.binaryPath}`);
    }
    this.diagnostics.analyzeInvocations += 1;
    this.analysisStartHr = process.hrtime();
    this.cachedAnalysis = (async () => {
      const [strings, symbols, fileFormat, architecture, dependencies, size] = await Promise.all([
        this.extractStrings(this.dynamicProbe),
        this.extractSymbols(),
        this.detectFileFormat(),
        this.detectArchitecture(),
        this.detectDependencies(),
        this.getFileSize()
      ]);
      if (this.analysisStartHr) {
        const diff = process.hrtime(this.analysisStartHr);
        this.diagnostics.totalAnalysisTimeMs = (diff[0] * 1e3) + (diff[1] / 1e6);
      }
      return { strings, symbols, fileFormat, architecture, dependencies, size };
    })();
    return this.cachedAnalysis;
  }

  private async extractStrings(dynamicProbe: boolean): Promise<string[]> {
    const forceFallback = process.env.BETANET_FORCE_FALLBACK_STRINGS === '1';
    if (!forceFallback) {
      // Primary path: external 'strings'
      try {
        const res = await safeExec('strings', [this.binaryPath]);
        if (!res.failed) {
          let out = res.stdout.split('\n').filter((line: string) => line.length > 0);
          if (dynamicProbe) {
            const probes: Array<[string, string[]]> = [
              [this.binaryPath, ['--help']],
              [this.binaryPath, ['--version']]
            ];
            for (const [cmd, args] of probes) {
              try {
                const probe = await safeExec(cmd, args, DEFAULT_TOOL_TIMEOUT_MS);
                if (!probe.failed && probe.stdout) {
                  out = out.concat(probe.stdout.split('\n').slice(0, 300));
                }
              } catch {/* ignore */}
            }
          }
          return out;
        } else {
          if (this.verbose) console.warn('⚠️  strings unavailable (', res.errorMessage, ') falling back to streaming scan');
          this.diagnostics.degraded = true;
          this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons||[]), 'strings-missing'];
        }
      } catch {
        if (this.verbose) console.warn('⚠️  strings invocation error, using fallback streaming scan');
        this.diagnostics.degraded = true;
        this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons||[]), 'strings-error'];
      }
    }

    // Fallback: streaming scan with size cap & UTF-8 decoding (ISSUE-038 + ISSUE-047)
    const strings: string[] = [];
    let current = '';
    let bytesReadTotal = 0;
    let truncated = false;
    const minLen = DEFAULT_FALLBACK_STRING_MIN_LEN;
    const maxSegmentLen = 4096; // guard against pathological very long runs

    function flush() {
      if (current.length >= minLen) strings.push(current);
      current = '';
    }

    function appendChar(ch: string) {
      current += ch;
      if (current.length >= maxSegmentLen) flush();
    }

    function isAcceptableCodePoint(cp: number): boolean {
      if (cp < 32) return false; // control chars
      if (cp >= 0xD800 && cp <= 0xDFFF) return false; // surrogates
      if (cp === 0xFEFF) return false; // BOM
      if (cp > 0x10FFFF) return false;
      return true;
    }

    try {
      await new Promise<void>((resolve, reject) => {
        const stream = fs.createReadStream(this.binaryPath, { highWaterMark: 64 * 1024 });
        stream.on('data', (chunk: any) => {
          if (truncated) return;
          const buf: Buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          bytesReadTotal += buf.length;
          for (let i = 0; i < buf.length; i++) {
            const byte = buf[i];
            if (byte <= 0x7F) { // ASCII
              if (byte >= 32 && byte <= 126) {
                appendChar(String.fromCharCode(byte));
              } else {
                flush();
              }
              continue;
            }
            // Multi-byte UTF-8 start? Determine expected length
            let needed = 0;
            if (byte >= 0xC2 && byte <= 0xDF) needed = 1; // 2-byte
            else if (byte >= 0xE0 && byte <= 0xEF) needed = 2; // 3-byte
            else if (byte >= 0xF0 && byte <= 0xF4) needed = 3; // 4-byte
            else {
              // Invalid start byte - treat as delimiter
              flush();
              continue;
            }
            if (i + needed >= buf.length) {
              // Incomplete sequence at chunk boundary; flush and break to next chunk
              flush();
              break;
            }
            let cp = byte & (needed === 1 ? 0x1F : needed === 2 ? 0x0F : 0x07);
            let valid = true;
            for (let j = 1; j <= needed; j++) {
              const nb = buf[i + j];
              if ((nb & 0xC0) !== 0x80) { valid = false; break; }
              cp = (cp << 6) | (nb & 0x3F);
            }
            if (!valid) {
              flush();
              i += needed; // skip attempted bytes
              continue;
            }
            i += needed; // advance past continuation bytes
            if (isAcceptableCodePoint(cp)) {
              try {
                appendChar(String.fromCodePoint(cp));
              } catch { flush(); }
            } else {
              flush();
            }
          }
          if (bytesReadTotal >= FALLBACK_MAX_BYTES) {
            truncated = true;
            stream.destroy();
          }
        });
        stream.on('end', () => { flush(); resolve(); });
        stream.on('error', err => reject(err));
      });
    } catch (e) {
      if (this.verbose) console.warn('⚠️  streaming fallback failed:', (e as any)?.message);
      this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons||[]), 'strings-fallback-error'];
    }
    if (truncated) {
      this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons||[]), 'strings-fallback-truncated'];
      (this.diagnostics as any).fallbackStringsTruncated = true;
    }
    (this.diagnostics as any).unicodeEnriched = true;
    if (dynamicProbe) {
      const probes: Array<[string, string[]]> = [
        [this.binaryPath, ['--help']],
        [this.binaryPath, ['--version']]
      ];
      for (const [cmd, args] of probes) {
        try {
          const probe = await safeExec(cmd, args, DEFAULT_TOOL_TIMEOUT_MS);
          if (!probe.failed && probe.stdout) strings.push(...probe.stdout.split('\n').slice(0, 300));
        } catch {/* ignore */}
      }
    }
    return strings;
  }

  private async extractSymbols(): Promise<string[]> {
    try {
      const res = await safeExec('nm', ['-D', this.binaryPath]);
      if (!res.failed) {
        return res.stdout.split('\n')
        .filter((line: string) => line.trim())
        .map((line: string) => line.split(' ').pop() || '')
        .filter((symbol: string) => symbol);
      }
    } catch (error) {
      if (this.verbose) {
        console.warn('⚠️  nm command failed, trying objdump');
      }
      
      try {
        const res2 = await safeExec('objdump', ['-t', this.binaryPath]);
        if (!res2.failed) {
          return res2.stdout.split('\n')
          .filter((line: string) => line.includes('.text'))
          .map((line: string) => line.split(' ').pop() || '')
          .filter((symbol: string) => symbol);
        }
      } catch (error2) {
        if (this.verbose) {
          console.warn('⚠️  Symbol extraction failed');
        }
  this.diagnostics.degraded = true;
  this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons||[]), 'symbols-missing'];
        return [];
      }
    }
  return [];
  }

  private async detectFileFormat(): Promise<string> {
    try {
      const res = await safeExec('file', [this.binaryPath]);
      return res.failed ? 'unknown' : res.stdout.trim();
    } catch {
      return 'unknown';
    }
  }

  private async detectArchitecture(): Promise<string> {
    try {
      const res = await safeExec('uname', ['-m']);
      return res.failed ? 'unknown' : res.stdout.trim();
    } catch {
      return 'unknown';
    }
  }

  private async detectDependencies(): Promise<string[]> {
    try {
      const res = await safeExec('ldd', [this.binaryPath]);
      if (res.failed) {
        if (this.verbose) {
          console.warn('⚠️  ldd unavailable (', res.errorMessage, ')');
        }
        this.diagnostics.degraded = true;
        this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons||[]), 'ldd-missing'];
        return [];
      }
      return res.stdout.split('\n')
        .filter((line: string) => line.includes('=>'))
        .map((line: string) => line.split('=>')[1]?.split('(')[0]?.trim() || '')
        .filter((dep: string) => dep && !dep.includes('not found'));
    } catch (error) {
      if (this.verbose) {
        console.warn('⚠️  ldd command failed');
      }
      this.diagnostics.degraded = true;
      this.diagnostics.degradationReasons = [...(this.diagnostics.degradationReasons||[]), 'ldd-failed'];
      return [];
    }
  }

  private async getFileSize(): Promise<number> {
    const stats = await fs.stat(this.binaryPath);
    return stats.size;
  }

  async checkNetworkCapabilities(): Promise<{
    hasTLS: boolean;
    hasQUIC: boolean;
    hasHTX: boolean;
    hasECH: boolean;
    port443: boolean;
  hasWebRTC: boolean;
  }> {
  const analysis = await this.analyze();
  return detectNetwork({ strings: analysis.strings, symbols: analysis.symbols });
  }

  async checkCryptographicCapabilities(): Promise<{
    hasChaCha20: boolean;
    hasPoly1305: boolean;
    hasEd25519: boolean;
    hasX25519: boolean;
    hasKyber768: boolean;
    hasSHA256: boolean;
    hasHKDF: boolean;
  }> {
  const analysis = await this.analyze();
  return detectCrypto({ strings: analysis.strings, symbols: analysis.symbols });
  }

  async checkSCIONSupport(): Promise<{
    hasSCION: boolean;
    pathManagement: boolean;
    hasIPTransition: boolean;
  pathDiversityCount: number;
  }> {
  const analysis = await this.analyze();
  return detectSCION({ strings: analysis.strings, symbols: analysis.symbols });
  }

  async checkDHTSupport(): Promise<{
    hasDHT: boolean;
    deterministicBootstrap: boolean;
  rendezvousRotation?: boolean;
  beaconSetIndicator?: boolean;
    seedManagement: boolean;
  rotationHits?: number;
  }> {
  const analysis = await this.analyze();
  return detectDHT({ strings: analysis.strings, symbols: analysis.symbols });
  }

  async checkLedgerSupport(): Promise<{
    hasAliasLedger: boolean;
    hasConsensus: boolean;
    chainSupport: boolean;
  }> {
  const analysis = await this.analyze();
  return detectLedger({ strings: analysis.strings, symbols: analysis.symbols });
  }

  async checkPaymentSupport(): Promise<{
    hasCashu: boolean;
    hasLightning: boolean;
    hasFederation: boolean;
  hasVoucherFormat?: boolean;
  hasFROST?: boolean;
  hasPoW22?: boolean;
  }> {
  const analysis = await this.analyze();
  return detectPayment({ strings: analysis.strings, symbols: analysis.symbols });
  }

  async checkBuildProvenance(): Promise<{
    hasSLSA: boolean;
    reproducible: boolean;
    provenance: boolean;
  }> {
  const analysis = await this.analyze();
  return detectBuildProvenance({ strings: analysis.strings, symbols: analysis.symbols });
  }
}