import * as fs from 'fs-extra';
import * as path from 'path';
import execa from 'execa';
import { AnalyzerDiagnostics, ToolStatus } from './types';
// Removed unused imports (which, types)

export class BinaryAnalyzer {
  private binaryPath: string;
  private verbose: boolean;
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

  constructor(binaryPath: string, verbose: boolean = false) {
    this.binaryPath = binaryPath;
    this.verbose = verbose;
    void this.detectTools();
  }

  getDiagnostics(): AnalyzerDiagnostics {
    return this.diagnostics;
  }

  private async detectTools(): Promise<void> {
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
        await execa(t.name, t.args, { timeout: 2000 });
        this.diagnostics.tools.push({ name: t.name, available: true, durationMs: Date.now() - start });
      } catch (e: any) {
        this.diagnostics.tools.push({ name: t.name, available: false, error: e?.shortMessage || e?.message });
      }
    });
    await Promise.all(checks);
  }

  async analyze(): Promise<{ strings: string[]; symbols: string[]; fileFormat: string; architecture: string; dependencies: string[]; size: number; }> {
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
        this.extractStrings(),
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

  private async extractStrings(): Promise<string[]> {
    try {
      const { stdout } = await execa('strings', [this.binaryPath]);
  return stdout.split('\n').filter((line: string) => line.length > 0);
    } catch (error) {
      if (this.verbose) {
        console.warn('⚠️  strings command failed, trying fallback method');
      }
      // Fallback: read file and extract printable strings
      const buffer = await fs.readFile(this.binaryPath);
      const strings: string[] = [];
      let currentString = '';
      
      for (let i = 0; i < buffer.length; i++) {
        const byte = buffer[i];
        if (byte >= 32 && byte <= 126) { // Printable ASCII
          currentString += String.fromCharCode(byte);
        } else {
          if (currentString.length >= 4) { // Minimum string length
            strings.push(currentString);
          }
          currentString = '';
        }
      }
      
      return strings;
    }
  }

  private async extractSymbols(): Promise<string[]> {
    try {
      const { stdout } = await execa('nm', ['-D', this.binaryPath]);
      return stdout.split('\n')
        .filter((line: string) => line.trim())
        .map((line: string) => line.split(' ').pop() || '')
        .filter((symbol: string) => symbol);
    } catch (error) {
      if (this.verbose) {
        console.warn('⚠️  nm command failed, trying objdump');
      }
      
      try {
        const { stdout } = await execa('objdump', ['-t', this.binaryPath]);
        return stdout.split('\n')
          .filter((line: string) => line.includes('.text'))
          .map((line: string) => line.split(' ').pop() || '')
          .filter((symbol: string) => symbol);
      } catch (error2) {
        if (this.verbose) {
          console.warn('⚠️  Symbol extraction failed');
        }
        return [];
      }
    }
  }

  private async detectFileFormat(): Promise<string> {
    try {
      const { stdout } = await execa('file', [this.binaryPath]);
      return stdout.trim();
    } catch (error) {
      return 'unknown';
    }
  }

  private async detectArchitecture(): Promise<string> {
    try {
      const { stdout } = await execa('uname', ['-m']);
      return stdout.trim();
    } catch (error) {
      return 'unknown';
    }
  }

  private async detectDependencies(): Promise<string[]> {
    try {
      const { stdout } = await execa('ldd', [this.binaryPath]);
      return stdout.split('\n')
        .filter((line: string) => line.includes('=>'))
        .map((line: string) => line.split('=>')[1]?.split('(')[0]?.trim() || '')
        .filter((dep: string) => dep && !dep.includes('not found'));
    } catch (error) {
      if (this.verbose) {
        console.warn('⚠️  ldd command failed');
      }
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
  }> {
    const analysis = await this.analyze();
    const strings = analysis.strings.join(' ').toLowerCase();
    const symbols = analysis.symbols.join(' ').toLowerCase();

    return {
      hasTLS: strings.includes('tls') || strings.includes('ssl') || symbols.includes('tls'),
      hasQUIC: strings.includes('quic') || symbols.includes('quic'),
      hasHTX: strings.includes('htx') || strings.includes('/betanet/htx'),
      hasECH: strings.includes('ech') || strings.includes('encrypted_client_hello'),
      port443: strings.includes('443') || symbols.includes('443')
    };
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
    const strings = analysis.strings.join(' ').toLowerCase();
    const symbols = analysis.symbols.join(' ').toLowerCase();

    return {
      hasChaCha20: strings.includes('chacha20') || symbols.includes('chacha'),
      hasPoly1305: strings.includes('poly1305') || symbols.includes('poly'),
      hasEd25519: strings.includes('ed25519') || symbols.includes('ed25519'),
      hasX25519: strings.includes('x25519') || symbols.includes('x25519'),
      hasKyber768: strings.includes('kyber') || strings.includes('768'),
      hasSHA256: strings.includes('sha256') || strings.includes('sha-256'),
      hasHKDF: strings.includes('hkdf') || symbols.includes('hkdf')
    };
  }

  async checkSCIONSupport(): Promise<{
    hasSCION: boolean;
    pathManagement: boolean;
    hasIPTransition: boolean;
  }> {
    const analysis = await this.analyze();
    const strings = analysis.strings.join(' ').toLowerCase();
    const symbols = analysis.symbols.join(' ').toLowerCase();

    return {
      hasSCION: strings.includes('scion') || symbols.includes('scion'),
      pathManagement: strings.includes('path') && (strings.includes('maintenance') || strings.includes('disjoint')),
      hasIPTransition: strings.includes('ip-transition') || strings.includes('transition')
    };
  }

  async checkDHTSupport(): Promise<{
    hasDHT: boolean;
    deterministicBootstrap: boolean;
    seedManagement: boolean;
  }> {
    const analysis = await this.analyze();
    const strings = analysis.strings.join(' ').toLowerCase();
    const symbols = analysis.symbols.join(' ').toLowerCase();

    return {
      hasDHT: strings.includes('dht') || symbols.includes('dht'),
      deterministicBootstrap: strings.includes('deterministic') && strings.includes('bootstrap'),
      seedManagement: strings.includes('seed') && strings.includes('bootstrap')
    };
  }

  async checkLedgerSupport(): Promise<{
    hasAliasLedger: boolean;
    hasConsensus: boolean;
    chainSupport: boolean;
  }> {
    const analysis = await this.analyze();
    const strings = analysis.strings.join(' ').toLowerCase();
    const symbols = analysis.symbols.join(' ').toLowerCase();

    return {
      hasAliasLedger: strings.includes('alias') && strings.includes('ledger'),
      hasConsensus: strings.includes('consensus') || strings.includes('2-of-3'),
      chainSupport: strings.includes('chain') && strings.includes('verification')
    };
  }

  async checkPaymentSupport(): Promise<{
    hasCashu: boolean;
    hasLightning: boolean;
    hasFederation: boolean;
  }> {
    const analysis = await this.analyze();
    const strings = analysis.strings.join(' ').toLowerCase();
    const symbols = analysis.symbols.join(' ').toLowerCase();

    return {
      hasCashu: strings.includes('cashu') || symbols.includes('cashu'),
      hasLightning: strings.includes('lightning') || strings.includes('ln'),
      hasFederation: strings.includes('federation') || strings.includes('federated')
    };
  }

  async checkBuildProvenance(): Promise<{
    hasSLSA: boolean;
    reproducible: boolean;
    provenance: boolean;
  }> {
    const analysis = await this.analyze();
    const strings = analysis.strings.join(' ').toLowerCase();
    const symbols = analysis.symbols.join(' ').toLowerCase();

    return {
      hasSLSA: strings.includes('slsa') || strings.includes('provenance'),
      reproducible: strings.includes('reproducible') || strings.includes('deterministic'),
      provenance: strings.includes('build') && strings.includes('provenance')
    };
  }
}