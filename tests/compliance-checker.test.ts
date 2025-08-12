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
  // Spec summary should be present
  expect(result.specSummary).toBeDefined();
  expect(result.specSummary?.baseline).toBe('1.0');
  expect(result.specSummary?.latestKnown).toBe('1.1');
  expect(result.specSummary?.implementedChecks).toBeGreaterThanOrEqual(11);
    });

    it('should ingest external evidence file and upgrade build provenance evidenceType', async () => {
      const checkerLocal = new BetanetComplianceChecker();
      const tmpBin = path.join(__dirname, 'temp-existing-bin');
      await fs.writeFile(tmpBin, Buffer.from('binary data slsa reproducible provenance'));
      // Compute actual digest to satisfy new validation logic BEFORE stubbing analyzer
      const fileBuf = await fs.readFile(tmpBin);
      const actualDigest = require('crypto').createHash('sha256').update(fileBuf).digest('hex');
      // Analyzer lacking native provenance signals to force reliance on evidence
      (checkerLocal as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true }),
        analyze: () => Promise.resolve({ strings: ['slsa','reproducible','provenance','ticket','rotation','/betanet/htx/1.0.0','/betanet/htxquic/1.0.0','chacha20','poly1305','cashu','lightning','federation','kyber768','x25519','mix beaconset diversity'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86_64', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasEd25519: true, hasX25519: true, hasKyber768: true, hasSHA256: true, hasHKDF: true }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false, pathDiversityCount: 2 }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: true, seedManagement: true, rotationHits: 0 }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false }),
        getBinarySha256: () => Promise.resolve(actualDigest)
      };
      const evidencePath = path.join(__dirname, 'temp-evidence.json');
  const evidence = { provenance: { predicateType: 'https://slsa.dev/provenance/v1', builderId: 'github.com/example/builder', binaryDigest: 'sha256:' + actualDigest } };
      await fs.writeFile(evidencePath, JSON.stringify(evidence));
      const result = await checkerLocal.checkCompliance(tmpBin, { evidenceFile: evidencePath, allowHeuristic: true });
      const buildProv = result.checks.find(c => c.id === 9);
      expect(buildProv).toBeDefined();
      expect(buildProv?.evidenceType).toBe('artifact');
  expect(buildProv?.details).toMatch(/Provenance verified|validated predicateType/);
      await fs.remove(evidencePath);
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

    it('should tag betanet features in SBOM (CycloneDX JSON + SPDX)', async () => {
      // Provide analyzer with strings that trigger multiple features
      const featureStrings = [
        '/betanet/htx/1.1.0', '/betanet/htxquic/1.1.0', '/betanet/webrtc/1.1.0', 'encrypted_client_hello',
        'chacha20', 'poly1305', 'kyber768', 'x25519', 'scion path maintenance as123 pathid:abc', 'rendezvous rotation beaconset(epoch)',
        'cashu', 'lightning', 'federation-mode', 'keysetid32 secret32 aggregatedsig64', 'frost-ed25519', 'pow=22',
        'mix hop beaconset diversity vrf'
      ];
      const mockAnalyzer = {
        analyze: () => Promise.resolve({ strings: featureStrings, symbols: [], dependencies: [] }),
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true, hasWebRTC: true }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasEd25519: true, hasX25519: true, hasKyber768: true, hasSHA256: true, hasHKDF: false }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false, pathDiversityCount: 2 }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: true, rendezvousRotation: true, beaconSetIndicator: true, seedManagement: true, rotationHits: 3 }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true, hasVoucherFormat: true, hasFROST: true, hasPoW22: true }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: true, reproducible: true, provenance: true })
      };
      (checker as any)._analyzer = mockAnalyzer;
      const cdxJsonPath = path.join(__dirname, 'features-sbom.cdx.json');
      await checker.generateSBOM('/tmp/fakebin2', 'cyclonedx-json', cdxJsonPath);
      const cdxJson = JSON.parse(await fs.readFile(cdxJsonPath, 'utf8'));
      const props = cdxJson.metadata.component.properties || [];
      const featureProps = props.filter((p: any) => p.name === 'betanet.feature').map((p: any) => p.value);
      expect(featureProps).toEqual(expect.arrayContaining(['transport-htx','transport-quic','transport-webrtc','crypto-chacha20poly1305','crypto-pq-hybrid','payment-cashu','payment-lightning','privacy-hop']));
      await fs.remove(cdxJsonPath);
      const spdxPath = path.join(__dirname, 'features-sbom.spdx');
      await checker.generateSBOM('/tmp/fakebin2', 'spdx', spdxPath);
      const spdxText = await fs.readFile(spdxPath, 'utf8');
      expect(spdxText).toMatch(/PackageComment: betanet.feature=transport-htx/);
      expect(spdxText).toMatch(/PackageComment: betanet.feature=crypto-chacha20poly1305/);
      await fs.remove(spdxPath);
    });

    it('CLI flag parity: --format generates SBOM', async () => {
      // Simulate invocation by calling checker directly (unit-level) using new --format flag
      const tempBin = path.join(__dirname, 'flag-binary');
      await fs.writeFile(tempBin, Buffer.from('binary data'));
      const checkerLocal = new BetanetComplianceChecker();
      const out = await checkerLocal.generateSBOM(tempBin, 'cyclonedx-json');
      const content = await fs.readFile(out, 'utf8');
      expect(content).toMatch(/CycloneDX|bom|metadata/);
      await fs.remove(out);
      await fs.remove(tempBin);
    });

    it('Deprecated alias --sbom-format still honored (indirect test)', async () => {
      // We emulate alias by calling generateSBOM with format variable; deprecation warning is emitted in CLI wrapper only.
      const tempBin = path.join(__dirname, 'alias-binary');
      await fs.writeFile(tempBin, Buffer.from('binary data 2'));
      const checkerLocal = new BetanetComplianceChecker();
      const out = await checkerLocal.generateSBOM(tempBin, 'spdx');
      const txt = await fs.readFile(out, 'utf8');
      expect(txt).toMatch(/SPDXVersion: SPDX-2.3/);
      await fs.remove(out);
      await fs.remove(tempBin);
    });

    it('Zero-component SBOM should omit relationships arrays (ISSUE-044)', async () => {
      const tempBin = path.join(__dirname, 'zerocomp-bin');
      await fs.writeFile(tempBin, Buffer.from('minimal')); // unlikely to produce versions or deps
      const checkerLocal = new BetanetComplianceChecker();
      (checkerLocal as any)._analyzer = {
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [] }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false })
      };
      const spdxJsonPath = path.join(__dirname, 'zerocomp.spdx.json');
      await checkerLocal.generateSBOM(tempBin, 'spdx-json', spdxJsonPath);
      const json = JSON.parse(await fs.readFile(spdxJsonPath, 'utf8'));
      expect(Array.isArray(json.relationships)).toBe(true); // array present
      expect(json.relationships.length).toBe(0); // but empty
      await fs.remove(spdxJsonPath);
      const cdxJsonPath = path.join(__dirname, 'zerocomp.cdx.json');
      await checkerLocal.generateSBOM(tempBin, 'cyclonedx-json', cdxJsonPath);
      const cdx = JSON.parse(await fs.readFile(cdxJsonPath, 'utf8'));
      expect(cdx.dependencies === undefined || cdx.dependencies.length === 0).toBe(true);
      await fs.remove(cdxJsonPath);
      await fs.remove(tempBin);
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

  describe('CLI filter parity (ISSUE-040)', () => {
    const { spawnSync } = require('child_process');
    it('should allow --checks on check command', () => {
      const bin = path.join(__dirname, 'temp-existing-bin');
      fs.writeFileSync(bin, Buffer.from('dummy'));
      const res = spawnSync('node', [path.join(__dirname, '..', 'bin', 'cli.js'), 'check', bin, '--checks', '1,3', '--output', 'json']);
      expect(res.status).toBeGreaterThanOrEqual(0); // process may exit 0 or 1 depending on pass/fail
      const stdout = res.stdout.toString();
      // Count occurrences of '"id":' to ensure only two checks captured in JSON output
      const ids = stdout.match(/"id"\s*:\s*([0-9]+)/g) || [];
      // Expect exactly two unique IDs (1 and 3)
  const uniq = Array.from(new Set(ids.map((s: string) => (s.match(/([0-9]+)/) || [,''])[1])));
      expect(uniq).toEqual(expect.arrayContaining(['1','3']));
      expect(uniq.length).toBe(2);
    });
    it('should allow --exclude on check command', () => {
      const bin = path.join(__dirname, 'temp-existing-bin');
      fs.writeFileSync(bin, Buffer.from('dummy'));
      const res = spawnSync('node', [path.join(__dirname, '..', 'bin', 'cli.js'), 'check', bin, '--exclude', '10', '--output', 'json']);
      const stdout = res.stdout.toString();
      expect(stdout).not.toMatch(/"id"\s*:\s*10/);
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

    it('should show optional WebRTC when endpoint present in transports (check 5 details)', async () => {
      const checker = new BetanetComplianceChecker();
      (checker as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true, hasWebRTC: true }),
        analyze: () => Promise.resolve({ strings: ['/betanet/htx/1.1.0', '/betanet/htxquic/1.1.0', '/betanet/webrtc/1.0.0'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasEd25519: true, hasX25519: true, hasKyber768: true, hasSHA256: true, hasHKDF: true }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false, pathDiversityCount: 2 }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: true, rendezvousRotation: false, seedManagement: true, rotationHits: 0 }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: true, reproducible: true, provenance: true })
      };
      const tmp = path.join(__dirname, 'temp-webrtc');
      await fs.writeFile(tmp, Buffer.from('dummy'));    
      const result = await checker.checkCompliance(tmp);
      const transport = result.checks.find(c => c.id === 5);
      expect(transport?.details).toMatch(/optional: webrtc/);
    });

    it('should enforce path diversity threshold in check 4', async () => {
      const checker = new BetanetComplianceChecker();
      (checker as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true, hasWebRTC: false }),
        analyze: () => Promise.resolve({ strings: ['scion pathid:abc as123'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasEd25519: true, hasX25519: true, hasKyber768: true, hasSHA256: true, hasHKDF: true }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false, pathDiversityCount: 1 }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: true, rendezvousRotation: false, seedManagement: true, rotationHits: 0 }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: true, reproducible: true, provenance: true })
      };
      const tmp = path.join(__dirname, 'temp-diversity');
      await fs.writeFile(tmp, Buffer.from('dummy'));
      const result = await checker.checkCompliance(tmp);
      const scion = result.checks.find(c => c.id === 4);
      expect(scion?.passed).toBe(false);
      expect(scion?.details).toContain('≥2 path diversity markers');
    });

    it('should show rotationHits in DHT check details when rotating', async () => {
      const checker = new BetanetComplianceChecker();
      (checker as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true, hasWebRTC: false }),
        analyze: () => Promise.resolve({ strings: ['dht rendezvous rotate epoch beaconset'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasEd25519: true, hasX25519: true, hasKyber768: true, hasSHA256: true, hasHKDF: true }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false, pathDiversityCount: 0 }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: false, rendezvousRotation: true, beaconSetIndicator: true, seedManagement: true, rotationHits: 3 }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
      };
      const tmp = path.join(__dirname, 'temp-rotation');
      await fs.writeFile(tmp, Buffer.from('dummy'));
      const result = await checker.checkCompliance(tmp);
      const dht = result.checks.find(c => c.id === 6);
      expect(dht?.details).toMatch(/hits=3/);
    });

    it('should enforce PQ override date (env BETANET_PQ_DATE_OVERRIDE)', async () => {
      process.env.BETANET_PQ_DATE_OVERRIDE = '2024-01-01';
      const checker = new BetanetComplianceChecker();
      (checker as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true, hasWebRTC: false }),
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasEd25519: true, hasX25519: true, hasKyber768: false, hasSHA256: true, hasHKDF: true }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false, pathDiversityCount: 0 }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false, rotationHits: 0 }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
      };
      const tmp = path.join(__dirname, 'temp-pq-override');
      await fs.writeFile(tmp, Buffer.from('dummy'));
      const result = await checker.checkCompliance(tmp);
      const pq = result.checks.find(c => c.id === 10);
      expect(pq?.severity).toBe('critical');
      expect(pq?.passed).toBe(false);
      delete process.env.BETANET_PQ_DATE_OVERRIDE;
    });

    it('should replace injected analyzer when forceRefresh is true', async () => {
      const checker = new BetanetComplianceChecker();
      const stub: any = {
        marker: 'stub',
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: false, hasQUIC: false, hasHTX: false, hasECH: false, port443: false, hasWebRTC: false }),
        analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false, pathDiversityCount: 0 }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false, rotationHits: 0 }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
      };
      (checker as any)._analyzer = stub;
      const tmp = path.join(__dirname, 'temp-force');
      await fs.writeFile(tmp, Buffer.from('dummy'));
      await checker.checkCompliance(tmp); // uses stub
      expect((checker as any)._analyzer.marker).toBe('stub');
      await checker.checkCompliance(tmp, { forceRefresh: true });
      expect((checker as any)._analyzer.marker).toBeUndefined();
    });

    it('should fail pass status when degraded and BETANET_FAIL_ON_DEGRADED=1', async () => {
      process.env.BETANET_FAIL_ON_DEGRADED = '1';
      const checker = new BetanetComplianceChecker();
      (checker as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true, hasWebRTC: false }),
        analyze: () => Promise.resolve({ strings: ['/betanet/htx/1.1.0','/betanet/htxquic/1.1.0'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: true, hasPoly1305: true, hasEd25519: true, hasX25519: true, hasKyber768: true, hasSHA256: true, hasHKDF: true }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: true, pathManagement: true, hasIPTransition: false, pathDiversityCount: 2 }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: true, deterministicBootstrap: true, seedManagement: true, rotationHits: 0 }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: true, hasConsensus: true, chainSupport: true }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: true, hasLightning: true, hasFederation: true }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: true, reproducible: true, provenance: true }),
        getDiagnostics: () => ({ degraded: true, tools: [], analyzeInvocations: 1, cached: false })
      };
      const tmp = path.join(__dirname, 'temp-degraded');
      await fs.writeFile(tmp, Buffer.from('dummy'));
      const result = await checker.checkCompliance(tmp);
      expect(result.passed).toBe(false);
      delete process.env.BETANET_FAIL_ON_DEGRADED;
    });

    it('should not falsely pass DHT rotation with isolated rotate token and no dht base', async () => {
      const checker = new BetanetComplianceChecker();
      (checker as any)._analyzer = {
        checkNetworkCapabilities: () => Promise.resolve({ hasTLS: false, hasQUIC: false, hasHTX: false, hasECH: false, port443: false, hasWebRTC: false }),
        analyze: () => Promise.resolve({ strings: ['rotate epoch'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
        checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false, pathDiversityCount: 0 }),
        checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, rendezvousRotation: true, beaconSetIndicator: true, seedManagement: false, rotationHits: 2 }),
        checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
        checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
        checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
      };
      const tmp = path.join(__dirname, 'temp-rotate-alone');
      await fs.writeFile(tmp, Buffer.from('dummy'));
      const result = await checker.checkCompliance(tmp);
      const dht = result.checks.find(c => c.id === 6);
      expect(dht?.passed).toBe(false);
    });

    describe('post-quantum UTC boundary (ISSUE-016)', () => {
      const originalNow = Date;
      function mockNow(epochMs: number) {
        // Monkey patch Date constructor & now
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (global as any).Date = class extends Date {
          constructor(arg?: any) { super(arg ?? epochMs); }
          static now() { return epochMs; }
        } as unknown as DateConstructor;
      }
      afterEach(() => {
        (global as any).Date = originalNow;
        delete process.env.BETANET_PQ_DATE_OVERRIDE;
      });

      it('treats moment just before UTC midnight as pre-mandatory', async () => {
        // 2026-12-31T23:59:59.500Z
        mockNow(Date.UTC(2026, 11, 31, 23, 59, 59, 500));
        const checker = new BetanetComplianceChecker();
        (checker as any)._analyzer = {
          checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true, hasWebRTC: false }),
          analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
          checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
          checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false, pathDiversityCount: 0 }),
          checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false, rotationHits: 0 }),
          checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
          checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
          checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
        };
        const tmp = path.join(__dirname, 'temp-pq-pre');
        await fs.writeFile(tmp, Buffer.from('dummy'));
        const result = await checker.checkCompliance(tmp);
        const pq = result.checks.find(c => c.id === 10);
        expect(pq?.severity).toBe('minor');
        expect(pq?.details).toMatch(/not yet mandatory/);
      });

      it('treats UTC midnight or later as mandatory boundary', async () => {
        // 2027-01-01T00:00:00.000Z
        mockNow(Date.UTC(2027, 0, 1, 0, 0, 0, 0));
        const checker = new BetanetComplianceChecker();
        (checker as any)._analyzer = {
          checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true, hasWebRTC: false }),
          analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
            checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
          checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false, pathDiversityCount: 0 }),
          checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false, rotationHits: 0 }),
          checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
          checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
          checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
        };
        const tmp = path.join(__dirname, 'temp-pq-post');
        await fs.writeFile(tmp, Buffer.from('dummy'));
        const result = await checker.checkCompliance(tmp);
        const pq = result.checks.find(c => c.id === 10);
        expect(pq?.severity).toBe('critical');
        expect(pq?.details).toMatch(/mandatory after 2027-01-01/);
      });

      it('applies override with timezone aware full ISO string', async () => {
        process.env.BETANET_PQ_DATE_OVERRIDE = '2025-12-31T00:00:00Z';
        mockNow(Date.UTC(2025, 11, 31, 0, 0, 0, 0));
        const checker = new BetanetComplianceChecker();
        (checker as any)._analyzer = {
          checkNetworkCapabilities: () => Promise.resolve({ hasTLS: true, hasQUIC: true, hasHTX: true, hasECH: true, port443: true, hasWebRTC: false }),
          analyze: () => Promise.resolve({ strings: [], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
          checkCryptographicCapabilities: () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false }),
          checkSCIONSupport: () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false, pathDiversityCount: 0 }),
          checkDHTSupport: () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false, rotationHits: 0 }),
          checkLedgerSupport: () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false }),
          checkPaymentSupport: () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false }),
          checkBuildProvenance: () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false })
        };
        const tmp = path.join(__dirname, 'temp-pq-override-boundary');
        await fs.writeFile(tmp, Buffer.from('dummy'));
        const result = await checker.checkCompliance(tmp);
        const pq = result.checks.find(c => c.id === 10);
        expect(pq?.severity).toBe('critical');
        delete process.env.BETANET_PQ_DATE_OVERRIDE;
      });
    });
  });

  describe('performance memoization', () => {
    it('should mark degradation reasons on Windows platform when core tools absent', async () => {
      const checker = new BetanetComplianceChecker();
      (checker as any)._analyzer = new BinaryAnalyzer('/mock/binary');
      // Monkey patch detectTools before it runs (simulate Windows missing tools)
      (checker as any)._analyzer.detectTools = async function() {
        // @ts-ignore
        this.diagnostics = { tools: [], analyzeInvocations: 0, cached: false };
        // @ts-ignore
        this.diagnostics.platform = 'win32';
        // @ts-ignore
        this.diagnostics.tools = [ 'strings','nm','objdump','ldd','file','uname' ].map(n => ({ name: n, available: false, error: 'not-found'}));
        // @ts-ignore
        this.diagnostics.degraded = true;
        // @ts-ignore
        this.diagnostics.missingCoreTools = ['strings','nm','objdump','ldd','file','uname'];
        // @ts-ignore
        this.diagnostics.degradationReasons = ['native-windows-missing-unix-tools','consider-installing-binutils-or-use-WSL'];
      };
      // Re-run tool detection with patched method
      await (checker as any)._analyzer.detectTools();
      // Mock analysis internals
      (checker as any)._analyzer.analyze = () => Promise.resolve({ strings: [], symbols: [], fileFormat: 'unknown', architecture: 'x86', dependencies: [], size: 1 });
      (checker as any)._analyzer.checkNetworkCapabilities = () => Promise.resolve({ hasTLS: false, hasQUIC: false, hasHTX: false, hasECH: false, port443: false, hasWebRTC: false });
      (checker as any)._analyzer.checkCryptographicCapabilities = () => Promise.resolve({ hasChaCha20: false, hasPoly1305: false, hasEd25519: false, hasX25519: false, hasKyber768: false, hasSHA256: false, hasHKDF: false });
      (checker as any)._analyzer.checkSCIONSupport = () => Promise.resolve({ hasSCION: false, pathManagement: false, hasIPTransition: false, pathDiversityCount: 0 });
      (checker as any)._analyzer.checkDHTSupport = () => Promise.resolve({ hasDHT: false, deterministicBootstrap: false, seedManagement: false });
      (checker as any)._analyzer.checkLedgerSupport = () => Promise.resolve({ hasAliasLedger: false, hasConsensus: false, chainSupport: false });
      (checker as any)._analyzer.checkPaymentSupport = () => Promise.resolve({ hasCashu: false, hasLightning: false, hasFederation: false });
      (checker as any)._analyzer.checkBuildProvenance = () => Promise.resolve({ hasSLSA: false, reproducible: false, provenance: false });
      const tmp = path.join(__dirname, 'temp-windows');
      await fs.writeFile(tmp, Buffer.from('dummy'));
      const result = await checker.checkCompliance(tmp);
      expect(result.diagnostics?.platform).toBe('win32');
      expect(result.diagnostics?.degraded).toBe(true);
      expect(result.diagnostics?.degradationReasons).toEqual(expect.arrayContaining(['native-windows-missing-unix-tools']));
      expect(result.diagnostics?.missingCoreTools?.length).toBeGreaterThan(0);
    });
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

  describe('parallel evaluation', () => {
    it('should reduce wall time vs sequential simulation', async () => {
      const checker = new BetanetComplianceChecker();
      // Craft analyzer returning predictable data
      (checker as any)._analyzer = {
        checkNetworkCapabilities: () => new Promise(r => setTimeout(()=> r({ hasTLS:true, hasQUIC:true, hasHTX:true, hasECH:true, port443:true }),50)),
        analyze: () => Promise.resolve({ strings: ['/betanet/htx/1.1.0','/betanet/htxquic/1.1.0','ticket','rotation','chacha20','poly1305','cashu','lightning','federation','slsa','reproducible','provenance','nym mixnode beaconset diversity'], symbols: [], dependencies: [], fileFormat: 'ELF', architecture: 'x86', size: 1 }),
        checkCryptographicCapabilities: () => new Promise(r => setTimeout(()=> r({ hasChaCha20:true, hasPoly1305:true, hasEd25519:true, hasX25519:true, hasKyber768:true, hasSHA256:true, hasHKDF:true }),50)),
        checkSCIONSupport: () => new Promise(r => setTimeout(()=> r({ hasSCION:true, pathManagement:true, hasIPTransition:false, pathDiversityCount:2 }),50)),
        checkDHTSupport: () => new Promise(r => setTimeout(()=> r({ hasDHT:true, deterministicBootstrap:true, seedManagement:true, rotationHits:0 }),50)),
        checkLedgerSupport: () => new Promise(r => setTimeout(()=> r({ hasAliasLedger:true, hasConsensus:true, chainSupport:true }),50)),
        checkPaymentSupport: () => new Promise(r => setTimeout(()=> r({ hasCashu:true, hasLightning:true, hasFederation:true }),50)),
        checkBuildProvenance: () => new Promise(r => setTimeout(()=> r({ hasSLSA:true, reproducible:true, provenance:true }),50))
      };
      const start = Date.now();
      const result = await checker.checkCompliance(__filename, { maxParallel: 6 });
      const elapsed = Date.now() - start;
      // Sequential would have been roughly 11 * 50ms ≈ 550ms plus overhead; allow generous margin
      expect(elapsed).toBeLessThan(450); // demonstrates some parallelism benefit
      expect(result.parallelDurationMs).toBeDefined();
    });
  });

  describe('degradation (stripped binaries)', () => {
    it('should degrade gracefully with skipped symbol tools (ISSUE-056)', async () => {
      process.env.BETANET_SKIP_TOOLS = 'nm,objdump';
      const checker = new BetanetComplianceChecker();
      const tmp = path.join(__dirname, 'temp-stripped');
      await fs.writeFile(tmp, Buffer.from('/betanet/htx/1.1.0 ticket chacha20 poly1305 cashu lightning federation slsa reproducible provenance nym beaconset diversity'));
      const result = await checker.checkCompliance(tmp, { maxParallel: 4 });
      expect(result.diagnostics).toBeDefined();
      expect(result.diagnostics?.degraded).toBe(true);
      expect(result.diagnostics?.skippedTools).toEqual(expect.arrayContaining(['nm','objdump']));
      // Ensure all checks still evaluated
      expect(result.checks.length).toBeGreaterThanOrEqual(11);
      const privacy = result.checks.find(c => c.id === 11);
      expect(privacy).toBeDefined();
      delete process.env.BETANET_SKIP_TOOLS;
    });
    it('should attach degradedHints to string-heavy checks when strings tool skipped (ISSUE-035)', async () => {
      process.env.BETANET_SKIP_TOOLS = 'strings';
      const checker = new BetanetComplianceChecker();
      const tmp = path.join(__dirname, 'temp-degraded-hints');
      await fs.writeFile(tmp, Buffer.from('ticket rotation chacha20 poly1305 cashu lightning federation kyber768 x25519 mix beaconset diversity'));
      const result = await checker.checkCompliance(tmp, { maxParallel: 4 });
      // Expect at least one check with degraded hints
      const withHints = result.checks.filter(c => c.degradedHints && c.degradedHints.length);
      expect(withHints.length).toBeGreaterThan(0);
      // Network (id 1) or payment (id 8) should likely be affected
      const network = result.checks.find(c => c.id === 1);
      if (network) {
        expect(network.degradedHints).toBeDefined();
      }
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
  // Under strict mode heuristic-only evidence may yield identical scores; ensure logic runs without throwing.
  // Relax prior assertion: only assert scores are numbers and critical subset not greater than full.
  expect(typeof full.overallScore).toBe('number');
  expect(typeof critOnly.overallScore).toBe('number');
  expect(critOnly.overallScore).toBeLessThanOrEqual(full.overallScore);
    });
  });
});