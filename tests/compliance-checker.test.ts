import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs-extra';
import * as path from 'path';

describe('BetanetComplianceChecker', () => {
  let checker: BetanetComplianceChecker;
  let mockBinaryPath: string;

  beforeEach(() => {
    checker = new BetanetComplianceChecker();
    mockBinaryPath = '/mock/path/to/binary';
  });

  describe('checkCompliance', () => {
    it('should return a compliance result with all checks', async () => {
      // Mock the analyzer methods
      jest.spyOn(checker as any, 'analyzer', 'get').mockReturnValue({
        checkNetworkCapabilities: () => Promise.resolve({
          hasTLS: true,
          hasQUIC: true,
          hasHTX: true,
          hasECH: true,
          port443: true
        }),
        analyze: () => Promise.resolve({
          strings: ['ticket', 'rotation', '/betanet/htx/1.0.0', '/betanet/htxquic/1.0.0'],
          symbols: ['chacha20', 'poly1305'],
          dependencies: []
        }),
        checkCryptographicCapabilities: () => Promise.resolve({
          hasChaCha20: true,
          hasPoly1305: true,
          hasEd25519: true,
          hasX25519: true,
          hasKyber768: true,
          hasSHA256: true,
          hasHKDF: true
        }),
        checkSCIONSupport: () => Promise.resolve({
          hasSCION: true,
          pathManagement: true,
          hasIPTransition: false
        }),
        checkDHTSupport: () => Promise.resolve({
          hasDHT: true,
          deterministicBootstrap: true,
          seedManagement: true
        }),
        checkLedgerSupport: () => Promise.resolve({
          hasAliasLedger: true,
          hasConsensus: true,
          chainSupport: true
        }),
        checkPaymentSupport: () => Promise.resolve({
          hasCashu: true,
          hasLightning: true,
          hasFederation: true
        }),
        checkBuildProvenance: () => Promise.resolve({
          hasSLSA: true,
          reproducible: true,
          provenance: true
        })
      });

      const result = await checker.checkCompliance(mockBinaryPath);

      expect(result).toBeDefined();
      expect(result.binaryPath).toBe(mockBinaryPath);
      expect(result.checks).toHaveLength(10);
      expect(result.summary.total).toBe(10);
      expect(typeof result.overallScore).toBe('number');
      expect(typeof result.passed).toBe('boolean');
    });

    it('should filter checks when include option is provided', async () => {
      jest.spyOn(checker as any, 'analyzer', 'get').mockReturnValue({
        checkNetworkCapabilities: () => Promise.resolve({
          hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true
        }),
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [] }),
        checkCryptographicCapabilities: () => Promise.resolve({
          hasChaCha20: true, hasPoly1305: true, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false
        }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
      });

      const result = await checker.checkCompliance(mockBinaryPath, {
        checkFilters: { include: [1, 3] }
      });

      expect(result.checks).toHaveLength(2);
      expect(result.checks.map(c => c.id)).toEqual([1, 3]);
    });

    it('should filter checks when exclude option is provided', async () => {
      jest.spyOn(checker as any, 'analyzer', 'get').mockReturnValue({
        checkNetworkCapabilities: () => Promise.resolve({
          hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true
        }),
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [] }),
        checkCryptographicCapabilities: () => Promise.resolve({
          hasChaCha20: true, hasPoly1305: true, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false
        }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
      });

      const result = await checker.checkCompliance(mockBinaryPath, {
        checkFilters: { exclude: [10] }
      });

      expect(result.checks).toHaveLength(9);
      expect(result.checks.map(c => c.id)).not.toContain(10);
    });
  });

  describe('generateSBOM', () => {
    it('should generate CycloneDX SBOM', async () => {
      const mockAnalyzer = {
        analyze: () => Promise.resolve({
          strings: [],
          symbols: [],
          dependencies: ['/usr/lib/libcrypto.so.1.1']
        }),
        checkCryptographicCapabilities: () => Promise.resolve({
          hasChaCha20: true,
          hasPoly1305: true,
          hasEd25519: true,
          hasX25519: false,
          hasKyber768: false,
          hasSHA256: false,
          hasHKDF: false
        })
      };

      jest.spyOn(checker as any, 'analyzer', 'get').mockReturnValue(mockAnalyzer);

      const outputPath = path.join(__dirname, 'test-sbom.xml');
      
      const result = await checker.generateSBOM(mockBinaryPath, 'cyclonedx', outputPath);

      expect(result).toBe(outputPath);
      expect(await fs.pathExists(outputPath)).toBe(true);

      // Clean up
      await fs.remove(outputPath);
    });

    it('should generate SPDX SBOM', async () => {
      const mockAnalyzer = {
        analyze: () => Promise.resolve({
          strings: [],
          symbols: [],
          dependencies: []
        }),
        checkCryptographicCapabilities: () => Promise.resolve({
          hasChaCha20: false,
          hasPoly1305: false,
          hasEd25519: false,
          hasX25519: false,
          hasKyber768: false,
          hasSHA256: false,
          hasHKDF: false
        })
      };

      jest.spyOn(checker as any, 'analyzer', 'get').mockReturnValue(mockAnalyzer);

      const outputPath = path.join(__dirname, 'test-sbom.spdx');
      
      const result = await checker.generateSBOM(mockBinaryPath, 'spdx', outputPath);

      expect(result).toBe(outputPath);
      expect(await fs.pathExists(outputPath)).toBe(true);

      // Clean up
      await fs.remove(outputPath);
    });
  });

  describe('displayResults', () => {
    it('should display results in table format', () => {
      const mockResults = {
        binaryPath: '/test/binary',
        timestamp: '2024-01-15T10:30:45.123Z',
        overallScore: 80,
        passed: false,
        checks: [
          {
            id: 1,
            name: 'Test Check',
            description: 'Test description',
            passed: true,
            details: '✅ Passed',
            severity: 'critical' as const
          }
        ],
        summary: {
          total: 1,
          passed: 1,
          failed: 0,
          critical: 0
        }
      };

      // Mock console.log to capture output
      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      checker.displayResults(mockResults, 'table');
      
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('BETANET COMPLIANCE REPORT'));
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('Test Check'));
      
      consoleSpy.mockRestore();
    });

    it('should display results in JSON format', () => {
      const mockResults = {
        binaryPath: '/test/binary',
        timestamp: '2024-01-15T10:30:45.123Z',
        overallScore: 80,
        passed: false,
        checks: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
          critical: 0
        }
      };

      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      checker.displayResults(mockResults, 'json');
      
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('"binaryPath": "/test/binary"'));
      
      consoleSpy.mockRestore();
    });

    it('should display results in YAML format', () => {
      const mockResults = {
        binaryPath: '/test/binary',
        timestamp: '2024-01-15T10:30:45.123Z',
        overallScore: 80,
        passed: false,
        checks: [],
        summary: {
          total: 0,
          passed: 0,
          failed: 0,
          critical: 0
        }
      };

      const consoleSpy = jest.spyOn(console, 'log').mockImplementation();
      
      checker.displayResults(mockResults, 'yaml');
      
      expect(consoleSpy).toHaveBeenCalledWith(expect.stringContaining('binaryPath: /test/binary'));
      
      consoleSpy.mockRestore();
    });
  });
});