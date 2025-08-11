import { BetanetComplianceChecker } from '../src/index';
import { validateCycloneDXShape, validateSPDXTagValue, validateCycloneDXStrict, validateSPDXTagValueStrict } from '../src/sbom/sbom-validators';
import { BinaryAnalyzer } from '../src/analyzer';
import * as fs from 'fs-extra';
import * as path from 'path';

describe('BetanetComplianceChecker', () => {
  let checker: BetanetComplianceChecker;
  let mockBinaryPath: string;

  beforeEach(async () => {
    checker = new BetanetComplianceChecker();
    const tmp = path.join(__dirname, 'temp-existing-bin');
    await fs.writeFile(tmp, Buffer.from('test binary data kyber768 mix beaconset diversity lightning cashu federation'));
    mockBinaryPath = tmp;
  });

  describe('checkCompliance', () => {
    it('should return a compliance result with all checks', async () => {
  // Inject mock analyzer directly (private field access via casting)
  (checker as any)._analyzer = {
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
          dependencies: [],
          fileFormat: 'ELF',
          architecture: 'x86_64',
          size: 1000
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
  };

      const result = await checker.checkCompliance(mockBinaryPath);

      expect(result).toBeDefined();
      expect(result.binaryPath).toBe(mockBinaryPath);
  expect(result.checks).toHaveLength(11);
  expect(result.summary.total).toBe(11);
      expect(typeof result.overallScore).toBe('number');
      expect(typeof result.passed).toBe('boolean');
    });

    it('should throw if binary does not exist', async () => {
      const localChecker = new BetanetComplianceChecker();
      await expect(localChecker.checkCompliance('/non/existent/path/binary')).rejects.toThrow(/Binary not found/);
    });

    it('should filter checks when include option is provided', async () => {
  (checker as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({
          hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true
        }),
  analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({
          hasChaCha20: true, hasPoly1305: true, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false
        }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
  };

      const result = await checker.checkCompliance(mockBinaryPath, {
        checkFilters: { include: [1, 3] }
      });

      expect(result.checks).toHaveLength(2);
      expect(result.checks.map(c => c.id)).toEqual([1, 3]);
    });

    it('should filter checks when exclude option is provided', async () => {
  (checker as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({
          hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true
        }),
  analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({
          hasChaCha20: true, hasPoly1305: true, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false
        }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
  };

      const result = await checker.checkCompliance(mockBinaryPath, {
        checkFilters: { exclude: [10] }
      });

      expect(result.checks).toHaveLength(10); // 11 total minus excluded 10
      expect(result.checks.map(c => c.id)).not.toContain(10);
    });

    it('should handle zero selected checks gracefully (overallScore 0, passed false)', async () => {
      (checker as any)._analyzer = {
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkNetworkCapabilities: async () => ({}),
        checkCryptographicCapabilities: async () => ({}),
        checkSCIONSupport: async () => ({}),
        checkDHTSupport: async () => ({}),
        checkLedgerSupport: async () => ({}),
        checkPaymentSupport: async () => ({}),
        checkBuildProvenance: async () => ({})
      };
      const result = await checker.checkCompliance(mockBinaryPath, { checkFilters: { include: [] } });
      expect(result.checks).toHaveLength(0);
      expect(result.overallScore).toBe(0);
      expect(result.passed).toBe(false);
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

  (checker as any)._analyzer = mockAnalyzer;

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

  (checker as any)._analyzer = mockAnalyzer;

      const outputPath = path.join(__dirname, 'test-sbom.spdx');
      
      const result = await checker.generateSBOM(mockBinaryPath, 'spdx', outputPath);

      expect(result).toBe(outputPath);
      expect(await fs.pathExists(outputPath)).toBe(true);

      // Clean up
      await fs.remove(outputPath);
    });

  it('should include license when detected and produce valid SPDX/CycloneDX skeleton', async () => {
      // Create a temporary binary file containing MIT license phrase for detection
      const tempBin = path.join(__dirname, 'temp-binary');
      await fs.writeFile(tempBin, Buffer.from('Permission is hereby granted MIT test binary'));

      const checker2 = new BetanetComplianceChecker();
      (checker2 as any)._analyzer = {
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [] }),
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

      const outCyclone = path.join(__dirname, 'dedupe-sbom.xml');
      await checker2.generateSBOM(tempBin, 'cyclonedx', outCyclone);
  const xmlContent = await fs.readFile(outCyclone, 'utf8');
  expect(xmlContent).toMatch(/CycloneDX|bom/);

      const outSpdx = path.join(__dirname, 'dedupe-sbom.spdx');
      await checker2.generateSBOM(tempBin, 'spdx', outSpdx);
      const spdxContent = await fs.readFile(outSpdx, 'utf8');
      expect(spdxContent).toMatch(/PackageLicenseDeclared: MIT/);

      // Clean up
      await fs.remove(outCyclone);
      await fs.remove(outSpdx);
      await fs.remove(tempBin);
    });

  it('should pass CycloneDX JSON and SPDX shape validators (strict)', async () => {
      const tempBin = path.join(__dirname, 'shape-binary');
      await fs.writeFile(tempBin, Buffer.from('Test SPDXVersion: SPDX-2.3 MIT DocumentNamespace placeholder'));
      const checker3 = new BetanetComplianceChecker();
      (checker3 as any)._analyzer = {
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [] }),
        checkCryptographicCapabilities: () => Promise.resolve({
          hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false
        })
      };

      const cdxJsonPath = path.join(__dirname, 'shape-sbom.cdx.json');
      await checker3.generateSBOM(tempBin, 'cyclonedx-json', cdxJsonPath);
      const cdxJson = JSON.parse(await fs.readFile(cdxJsonPath, 'utf8'));
  const cdxValidation = validateCycloneDXShape(cdxJson);
  expect(cdxValidation.valid).toBe(true);
  const cdxStrict = validateCycloneDXStrict(cdxJson);
  expect(cdxStrict.valid).toBe(true);
  if (!cdxStrict.valid) throw new Error('CycloneDX strict errors: ' + cdxStrict.errors.join(', '));

      const spdxPath = path.join(__dirname, 'shape-sbom.spdx');
      await checker3.generateSBOM(tempBin, 'spdx', spdxPath);
      const spdxText = await fs.readFile(spdxPath, 'utf8');
  const spdxValidation = validateSPDXTagValue(spdxText);
  expect(spdxValidation.valid).toBe(true);
  const spdxStrict = validateSPDXTagValueStrict(spdxText);
  expect(spdxStrict.valid).toBe(true);
  if (!spdxStrict.valid) throw new Error('SPDX strict errors: ' + spdxStrict.errors.join(', '));

      await fs.remove(cdxJsonPath);
      await fs.remove(spdxPath);
      await fs.remove(tempBin);
    });

    it('should fail strict SPDX validation on malformed document', () => {
      const bad = 'SPDXVersion: SPDX-2.3\nDocumentName: MissingNamespace\nPackageName: testpkg\nPackageLicenseDeclared: NOASSERTION';
      const base = validateSPDXTagValue(bad);
      // Base should fail because DocumentNamespace missing
      expect(base.valid).toBe(false);
      const strict = validateSPDXTagValueStrict(bad);
      expect(strict.valid).toBe(false);
    });

    it('should generate SPDX JSON SBOM', async () => {
      const mockAnalyzer = {
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [] }),
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
      (checker as any)._analyzer = mockAnalyzer;
      const outputPath = path.join(__dirname, 'test-sbom.spdx.json');
      const result = await checker.generateSBOM('/tmp/fakebin', 'spdx-json', outputPath);
      expect(result).toBe(outputPath);
      const json = JSON.parse(await fs.readFile(outputPath, 'utf8'));
      expect(json.spdxVersion).toBe('SPDX-2.3');
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

  describe('heuristics false-positive protection', () => {
    it('should not flag Kyber768 when only number 768 appears without kyber token', async () => {
      const checker = new BetanetComplianceChecker();
  const tmp = path.join(__dirname, 'temp-no-kyber');
  await fs.writeFile(tmp, Buffer.from('version768 build data')); 
  (checker as any)._analyzer = {
  analyze: () => Promise.resolve({ strings: ['version768 build'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: false, hasQUIC: false, hasHTX: false, hasECH: false, port443: false }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
  };
  const result = await checker.checkCompliance(tmp);
      // Post-quantum check is ID 10
      const postQuantum = result.checks.find(c => c.id === 10);
      expect(postQuantum).toBeDefined();
      if (postQuantum) {
        expect(postQuantum.details).not.toContain('Kyber');
      }
    });

    it('should not treat random 443 in version string as port indicator (should remain missing)', async () => {
      const checker = new BetanetComplianceChecker();
  const tmp = path.join(__dirname, 'temp-port443');
  await fs.writeFile(tmp, Buffer.from('v1.443.0 build data'));
  (checker as any)._analyzer = {
  analyze: () => Promise.resolve({ strings: ['v1.443.0 build'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: false, hasQUIC: false, hasHTX: false, hasECH: false, port443: false }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
  };
  const result = await checker.checkCompliance(tmp);
      const htxCheck = result.checks.find(c => c.id === 1);
      expect(htxCheck).toBeDefined();
      if (htxCheck) {
        expect(htxCheck.passed).toBe(false);
        // Failure details should list 'port 443' as missing (not falsely detected)
        expect(htxCheck.details).toContain('port 443');
      }
    });

    it('should not pass DHT bootstrap when only beacon/rendezvous tokens appear without DHT base token', async () => {
      const checker = new BetanetComplianceChecker();
  const tmp = path.join(__dirname, 'temp-dht');
  await fs.writeFile(tmp, Buffer.from('beaconset rotate rendezvous'));
  (checker as any)._analyzer = {
  analyze: () => Promise.resolve({ strings: ['beaconset rotate rendezvous'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: false, hasQUIC: false, hasHTX: false, hasECH: false, port443: false }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, rendezvousRotation: true, beaconSetIndicator: true, seedManagement: false }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
  };
  const result = await checker.checkCompliance(tmp);
      const dhtCheck = result.checks.find(c => c.id === 6);
      expect(dhtCheck).toBeDefined();
      if (dhtCheck) {
        expect(dhtCheck.passed).toBe(false);
        expect(dhtCheck.details).toContain('DHT support');
      }
    });

    it('should not pass Payment System when only voucher/FROST/PoW indicators appear without core payment tokens', async () => {
      const checker = new BetanetComplianceChecker();
  const tmp = path.join(__dirname, 'temp-pay');
  await fs.writeFile(tmp, Buffer.from('voucher frost-ed25519 pow22'));
  (checker as any)._analyzer = {
  analyze: () => Promise.resolve({ strings: ['voucher frost-ed25519 pow22'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: false, hasQUIC: false, hasHTX: false, hasECH: false, port443: false }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false, hasVoucherFormat: true, hasFROST: true, hasPoW22: true }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
  };
  const result = await checker.checkCompliance(tmp);
      const paymentCheck = result.checks.find(c => c.id === 8);
      expect(paymentCheck).toBeDefined();
      if (paymentCheck) {
        expect(paymentCheck.passed).toBe(false);
        expect(paymentCheck.details).toContain('Cashu support');
        expect(paymentCheck.details).toContain('Lightning support');
        expect(paymentCheck.details).toContain('federation support');
      }
    });

    it('should pass Privacy Hop Enforcement with sufficient mix/beacon/diversity tokens', async () => {
      const checker = new BetanetComplianceChecker();
      const tmp = path.join(__dirname, 'temp-privacy-pass');
      await fs.writeFile(tmp, Buffer.from('nym mixnode hop beaconset epoch diversity distinct'));
      (checker as any)._analyzer = {
        analyze: () => Promise.resolve({ strings: ['nym mixnode hop beaconset epoch diversity distinct'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkNetworkCapabilities: async () => ({ hasTLS: false, hasQUIC: false, hasHTX: false, hasECH: false, port443: false }),
        checkCryptographicCapabilities: async () => ({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
        checkSCIONSupport: async () => ({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: async () => ({ hasDHT: false, deterministicBootstrap: false, seedManagement: false }),
        checkLedgerSupport: async () => ({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: async () => ({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: async () => ({ hasSLSA: false, reproducible: false, provenance: false })
      };
  const result = await checker.checkCompliance(tmp);
      const privacyCheck = result.checks.find(c => c.id === 11);
      expect(privacyCheck).toBeDefined();
      expect(privacyCheck?.passed).toBe(true);
    });

    it('should fail Privacy Hop Enforcement with insufficient diversity tokens', async () => {
      const checker = new BetanetComplianceChecker();
      const tmp = path.join(__dirname, 'temp-privacy-fail');
      await fs.writeFile(tmp, Buffer.from('mix beaconset'));
      (checker as any)._analyzer = {
        analyze: () => Promise.resolve({ strings: ['mix beaconset'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkNetworkCapabilities: async () => ({ hasTLS: false, hasQUIC: false, hasHTX: false, hasECH: false, port443: false }),
        checkCryptographicCapabilities: async () => ({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
        checkSCIONSupport: async () => ({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: async () => ({ hasDHT: false, deterministicBootstrap: false, seedManagement: false }),
        checkLedgerSupport: async () => ({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: async () => ({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: async () => ({ hasSLSA: false, reproducible: false, provenance: false })
      };
  const result = await checker.checkCompliance(tmp);
      const privacyCheck = result.checks.find(c => c.id === 11);
      expect(privacyCheck).toBeDefined();
      expect(privacyCheck?.passed).toBe(false);
    });
  });

  describe('performance memoization', () => {
    it('should only invoke full analysis once across multiple capability checks', async () => {
      const analyzer = new BinaryAnalyzer('/mock/binary');
      // Mock private extraction methods to avoid external tool calls
      jest.spyOn(analyzer as any, 'extractStrings').mockResolvedValue(['kyber768', 'dht', 'cashu', 'lightning', 'federation']);
      jest.spyOn(analyzer as any, 'extractSymbols').mockResolvedValue([]);
      jest.spyOn(analyzer as any, 'detectFileFormat').mockResolvedValue('ELF 64-bit');
      jest.spyOn(analyzer as any, 'detectArchitecture').mockResolvedValue('x86_64');
      jest.spyOn(analyzer as any, 'detectDependencies').mockResolvedValue([]);
      jest.spyOn(analyzer as any, 'getFileSize').mockResolvedValue(12345);
      // Call multiple capability methods sequentially
      await analyzer.checkNetworkCapabilities();
      await analyzer.checkCryptographicCapabilities();
      await analyzer.checkDHTSupport();
      await analyzer.checkPaymentSupport();
      const diag = analyzer.getDiagnostics();
      expect(diag.analyzeInvocations).toBe(1);
      expect(diag.cached).toBe(true);
    });

    it('should mark diagnostics degraded when core tools are skipped', async () => {
      process.env.BETANET_SKIP_TOOLS = 'strings,nm';
      const analyzer = new BinaryAnalyzer('/mock/binary');
      // Force analyze to trigger tool detection completion
      jest.spyOn(analyzer as any, 'extractStrings').mockResolvedValue(['token']);
      jest.spyOn(analyzer as any, 'extractSymbols').mockResolvedValue([]);
      jest.spyOn(analyzer as any, 'detectFileFormat').mockResolvedValue('ELF');
      jest.spyOn(analyzer as any, 'detectArchitecture').mockResolvedValue('x86');
      jest.spyOn(analyzer as any, 'detectDependencies').mockResolvedValue([]);
      jest.spyOn(analyzer as any, 'getFileSize').mockResolvedValue(10);
  await analyzer.checkNetworkCapabilities();
  // slight delay to allow detectTools promise resolution
  await new Promise(r => setTimeout(r, 10));
      const diag = analyzer.getDiagnostics();
      expect(diag.degraded).toBe(true);
      expect(diag.skippedTools).toEqual(expect.arrayContaining(['strings','nm']));
      delete process.env.BETANET_SKIP_TOOLS;
    });

    it('should fall back when strings tool missing and still return strings via fallback', async () => {
      // Simulate failure by skipping strings
      process.env.BETANET_SKIP_TOOLS = 'strings';
  const analyzer = new BinaryAnalyzer(__filename); // use this source file as pseudo binary
  const network = await analyzer.checkNetworkCapabilities();
  await new Promise(r => setTimeout(r, 10));
      expect(network).toBeDefined();
      const diag = analyzer.getDiagnostics();
      expect(diag.degraded).toBe(true);
      expect(diag.skippedTools).toContain('strings');
      delete process.env.BETANET_SKIP_TOOLS;
    });
  });

  describe('severity filtering', () => {
    it('should adjust scoring based on severityMin', async () => {
      const checker = new BetanetComplianceChecker();
      (checker as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true }),
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
      };
  const tmp = path.join(__dirname, 'temp-severity');
  await fs.writeFile(tmp, Buffer.from('dummy severity test'));
  const full = await checker.checkCompliance(tmp);
  const critOnly = await checker.checkCompliance(tmp, { severityMin: 'critical' });
      expect(full.summary.total).toBeGreaterThanOrEqual(critOnly.summary.total);
      // If only critical considered and one passes, score should differ
      expect(full.overallScore).not.toBe(critOnly.overallScore);
    });
  });
});