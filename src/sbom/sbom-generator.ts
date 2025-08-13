import * as fs from 'fs-extra';
import * as path from 'path';
import execa from 'execa'; // retained for hash fallback; phased out for core probes
import { SBOM } from '../types';
import { BinaryAnalyzer } from '../analyzer';
import { safeExec } from '../safe-exec';
import { evaluatePrivacyTokens } from '../heuristics';
import { sanitizeName, VERSION_KEYWORDS, DEFAULT_STRINGS_TIMEOUT_MS, DEFAULT_LDD_TIMEOUT_MS, DEFAULT_HASH_TIMEOUT_MS } from '../constants';

export class SBOMGenerator {
  async generate(binaryPath: string, format: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json' = 'cyclonedx', analyzer?: BinaryAnalyzer): Promise<SBOM> {
    const binaryInfo = await this.getBinaryInfo(binaryPath);
    const components = await this.extractComponents(binaryPath);
    const dependencies = await this.extractDependencies(binaryPath);
  // Derive a root version (avoid hard-coded 1.0.0). Prefer first meaningful component semver.
  const rootVersion = this.selectRootVersion(components) || '0.0.0';
  (binaryInfo as any).rootVersion = rootVersion;
    // Derive feature tags (Betanet spec-era capabilities) if we can analyze the binary
    try {
      const features = await this.deriveFeatures(binaryPath, analyzer);
      if (features.length) {
        (binaryInfo as any).betanetFeatures = features.sort();
      }
    } catch {/* non-fatal */}

    // Attempt per-component hashing when a concrete path exists
    await this.addComponentHashes(components);
    // Sanitize & dedupe
    const finalComponents = this.dedupeComponents(components);
    // Detect license for root package
    const rootLicenseInfo = await this.detectLicense(binaryPath);
    if (rootLicenseInfo) {
      (binaryInfo as any).license = rootLicenseInfo.primary;
      if (rootLicenseInfo.all && rootLicenseInfo.all.length > 1) {
        (binaryInfo as any).licenses = rootLicenseInfo.all;
      }
    }

  if (format === 'cyclonedx' || format === 'cyclonedx-json') {
      return {
    format: format === 'cyclonedx-json' ? 'cyclonedx-json' : 'cyclonedx',
        data: this.generateCycloneDX(binaryInfo, finalComponents, dependencies),
        generated: new Date().toISOString()
      };
    } else if (format === 'spdx') {
      return {
        format: 'spdx',
        data: this.generateSPDXTagValue(binaryInfo, finalComponents, dependencies),
        generated: new Date().toISOString()
      };
    } else { // spdx-json
      return {
        format: 'spdx-json',
        data: this.generateSPDXJson(binaryInfo, finalComponents, dependencies),
        generated: new Date().toISOString()
      };
    }
  }

  // Prefer a semver looking version from detected components (score heuristic: presence of dots & digits)
  private selectRootVersion(components: any[]): string | undefined {
    for (const c of components) {
      const v = c.version;
      if (v && v !== 'unknown' && /\d+\.\d+\.\d+/.test(v)) return v;
    }
    for (const c of components) { // fallback any non-unknown
      const v = c.version;
      if (v && v !== 'unknown') return v;
    }
    return undefined;
  }

  private getToolVersion(): string {
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const pkg = require('../../package.json');
      return pkg.version || '0.0.0';
    } catch { return '0.0.0'; }
  }

  private async deriveFeatures(binaryPath: string, analyzer?: BinaryAnalyzer): Promise<string[]> {
    const features: string[] = [];
    let a = analyzer;
    if (!a) {
      try { a = new BinaryAnalyzer(binaryPath); } catch { /* ignore */ }
    }
    if (!a) return features;
    try {
      // Run minimal capability detections leveraging existing analyzer helpers
      const [network, crypto, scion, dht, ledger, payment, build] = await Promise.all([
        a.checkNetworkCapabilities().catch(() => ({} as any)),
        a.checkCryptographicCapabilities().catch(() => ({} as any)),
        a.checkSCIONSupport().catch(() => ({} as any)),
        a.checkDHTSupport().catch(() => ({} as any)),
        a.checkLedgerSupport().catch(() => ({} as any)),
        a.checkPaymentSupport().catch(() => ({} as any)),
        a.checkBuildProvenance().catch(() => ({} as any))
      ]);
      // Analyze strings once for privacy evaluation (avoid double analyze())
      const analysis = await a.analyze();
      const privacy = evaluatePrivacyTokens(analysis.strings);
      // Mapping rules
      if (network.hasHTX) features.push('transport-htx');
      if (network.hasQUIC) features.push('transport-quic');
      if (network.port443) features.push('transport-443');
      if (network.hasWebRTC) features.push('transport-webrtc');
      if (network.hasECH) features.push('security-ech');
      if (crypto.hasChaCha20 && crypto.hasPoly1305) features.push('crypto-chacha20poly1305');
      if (crypto.hasKyber768 && crypto.hasX25519) features.push('crypto-pq-hybrid');
      if (scion.hasSCION) features.push('scion');
      if (scion.pathDiversityCount >= 2) features.push('scion-path-diversity');
      if (dht.rendezvousRotation) features.push('dht-rotation');
      if (dht.deterministicBootstrap) features.push('dht-deterministic');
      if (dht.beaconSetIndicator) features.push('dht-beaconset');
      if (ledger.hasAliasLedger && ledger.hasConsensus) features.push('alias-ledger');
      if (payment.hasCashu) features.push('payment-cashu');
      if (payment.hasLightning) features.push('payment-lightning');
      if (payment.hasVoucherFormat) features.push('payment-voucher-format');
      if (payment.hasFROST) features.push('payment-frost');
      if (payment.hasPoW22) features.push('payment-pow22');
      if (build.hasSLSA && build.reproducible && build.provenance) features.push('build-provenance');
      if (privacy.passed) features.push('privacy-hop');
    } catch {/* ignore feature derivation errors */}
    return Array.from(new Set(features));
  }

  private async getBinaryInfo(binaryPath: string): Promise<any> {
    try {
      const [fileInfoRes, stat] = await Promise.all([
  safeExec('file', [binaryPath], 3000),
        fs.stat(binaryPath)
      ]);
      const fileType = fileInfoRes.failed ? 'Unknown' : fileInfoRes.stdout;

      return {
        name: sanitizeName(path.basename(binaryPath)),
        path: binaryPath,
        size: stat.size,
        modified: stat.mtime.toISOString(),
  type: fileType,
        hash: await this.calculateHash(binaryPath)
      };
  } catch (error: unknown) {
      return {
        name: sanitizeName(path.basename(binaryPath)),
        path: binaryPath,
        size: 0,
        modified: new Date().toISOString(),
        type: 'Unknown',
        hash: '',
    error: (error as any)?.message
      };
    }
  }

  private async calculateHash(binaryPath: string): Promise<string> {
    try {
  const hashRes = await safeExec('sha256sum', [binaryPath], DEFAULT_HASH_TIMEOUT_MS);
      if (!hashRes.failed && hashRes.stdout) {
        return hashRes.stdout.split(' ')[0];
      }
    } catch (error) {
      try {
        // Fallback to Node.js crypto
        const crypto = require('crypto');
        const hash = crypto.createHash('sha256');
        const data = await fs.readFile(binaryPath);
        hash.update(data);
        return hash.digest('hex');
      } catch (e) {
        return '';
      }
    }
  return '';
  }

  private async extractComponents(binaryPath: string): Promise<any[]> {
    const components: any[] = [];
  const versionCandidates: { raw: string; normalized: string; context: string; score: number }[] = [];

    // ISSUE-021: Improved version inference with context & scoring
    // Scoring tiers: semver (3), semver+pre (3), date-like (2), sha/hash near keyword (1)
    const versionRegexes: { re: RegExp; score: number; normalize: (m: RegExpMatchArray) => string }[] = [
      { re: /\b[vV]?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z\.-]+)?)\b/g, score: 3, normalize: m => m[1] }, // semver & prerelease
      { re: /\b(\d{4}\.\d{1,2}\.\d{1,2})\b/g, score: 2, normalize: m => m[1] }, // date style
      { re: /\b([0-9a-f]{7,12})\b/g, score: 1, normalize: m => m[1] } // short git hash
    ];
  const KEYWORD_WINDOW = 24; // chars window to look back for keyword
  const keywords = VERSION_KEYWORDS;

    const collectVersions = (text: string) => {
      versionRegexes.forEach(vr => {
        let match: RegExpExecArray | null;
        while ((match = vr.re.exec(text)) !== null) {
          const norm = vr.normalize(match);
          // Skip improbable all-zero or trivial versions
            if (/^0\.0\.0$/.test(norm)) continue;
          // Context: ensure not part of a longer token already handled (regex boundaries should cover) but validate surrounding chars
          const idx = match.index;
          const contextStart = Math.max(0, idx - KEYWORD_WINDOW);
          const context = text.slice(contextStart, idx + norm.length + KEYWORD_WINDOW);
          const pre = text.slice(Math.max(0, idx - KEYWORD_WINDOW), idx).toLowerCase();
          const hasKeyword = keywords.some(k => pre.includes(k));
          // Git hash style candidates require keyword proximity else ignore (to suppress random hex)
          if (vr.score === 1 && !hasKeyword) continue;
          versionCandidates.push({ raw: match[0], normalized: norm, context, score: vr.score + (hasKeyword ? 1 : 0) });
        }
      });
    };

    const debug = process.env.BETANET_DEBUG_SBOM === '1';

    // On Windows, skip external *nix tools and attempt lightweight fallback
    if (process.platform === 'win32') {
      try {
        if (await fs.pathExists(binaryPath)) {
          const data = await fs.readFile(binaryPath);
          const ascii: string[] = [];
          let current = '';
          for (const byte of data) {
            if (byte >= 32 && byte <= 126) { current += String.fromCharCode(byte); } else { if (current.length >= 4) ascii.push(current); current = ''; }
          }
          if (current.length >= 4) ascii.push(current);
          collectVersions(ascii.join('\n'));
        }
      } catch (e) {
        if (debug) console.warn('SBOM fallback (windows strings) failed:', (e as any)?.message);
      }
      return components;
    }

    // Non-Windows: attempt `strings`
    try {
  const res = await safeExec('strings', [binaryPath], DEFAULT_STRINGS_TIMEOUT_MS);
      if (!res.failed) {
        collectVersions(res.stdout);
      } else {
        throw new Error(res.errorMessage || 'strings-failed');
      }
    } catch (e: any) {
      const msg = (e as any)?.message || '';
      if (debug) console.warn('SBOM strings exec skipped:', msg);
    }

    // Attempt ldd for component library names (best-effort)
    try {
  const lddRes = await safeExec('ldd', [binaryPath], DEFAULT_LDD_TIMEOUT_MS);
      if (lddRes.failed) throw new Error(lddRes.errorMessage || 'ldd-failed');
      const lddLines = lddRes.stdout.split('\n');
      for (const line of lddLines) {
        const libMatch = line.match(/\s+(.+?)\s+=>\s+(.+?)\s+\(/);
        if (libMatch) {
          const libName = sanitizeName(libMatch[1]);
          const libPath = libMatch[2];
          components.push({
            type: 'library',
            name: libName,
            path: libPath,
            purl: `pkg:generic/${libName}`,
            system: true
          });
        }
      }
    } catch (e) {
      // Silent unless debug
      if (debug) console.warn('SBOM ldd exec skipped:', (e as any)?.message);
    }

    // Consolidate collected version candidates into synthetic components (Unknown until better attribution)
    if (versionCandidates.length) {
      // Prefer highest score, then longest (for prerelease richness)
      const byNorm = new Map<string, { normalized: string; score: number; example: string }>();
      versionCandidates.forEach(vc => {
        const existing = byNorm.get(vc.normalized);
        if (!existing || vc.score > existing.score || (vc.score === existing.score && vc.normalized.length > existing.normalized.length)) {
          byNorm.set(vc.normalized, { normalized: vc.normalized, score: vc.score, example: vc.raw });
        }
      });
      Array.from(byNorm.values()).forEach(v => {
        components.push({
          type: 'library',
          name: 'Unknown',
          version: v.normalized,
          purl: `pkg:generic/unknown@${v.normalized}`,
          detected: true,
          _versionScore: v.score
        });
      });
      // Attach versionsDetectedQuality metric (optional quick win)
      (components as any)._versionsDetectedQuality = {
        candidates: versionCandidates.length,
        accepted: byNorm.size,
        suppressionRate: versionCandidates.length ? Number(((versionCandidates.length - byNorm.size) / versionCandidates.length).toFixed(2)) : 0
      };
    }

    return components;
  }

  private async extractDependencies(binaryPath: string): Promise<any[]> {
    const dependencies: any[] = [];

    const debug = process.env.BETANET_DEBUG_SBOM === '1';

    if (process.platform !== 'win32') {
      try {
  const lddRes = await safeExec('ldd', [binaryPath], DEFAULT_LDD_TIMEOUT_MS);
    if (lddRes.failed) throw new Error(lddRes.errorMessage || 'ldd-failed');
    const lddLines = lddRes.stdout.split('\n');
        for (const line of lddLines) {
          const depMatch = line.match(/\s+(.+?)\s+=>\s+(.+?)\s+\(/);
          if (depMatch) {
            const libName = sanitizeName(depMatch[1]);
            const libPath = depMatch[2];
            dependencies.push({ ref: libName, path: libPath, type: 'dynamic' });
          }
        }
      } catch (e) {
        if (debug) console.warn('SBOM dependency ldd skipped:', (e as any)?.message);
      }
    }

    // Local package metadata (works cross-platform)
    try {
      const packageFiles = ['package.json', 'requirements.txt', 'Cargo.toml', 'go.mod'];
      const binaryDir = path.dirname(binaryPath);
      for (const pkgFile of packageFiles) {
        const pkgPath = path.join(binaryDir, pkgFile);
        if (await fs.pathExists(pkgPath)) {
          const pkgDeps = await this.parsePackageFile(pkgPath);
          dependencies.push(...pkgDeps);
        }
      }
    } catch (e) {
      if (debug) console.warn('SBOM package parsing issue:', (e as any)?.message);
    }

    return dependencies;
  }

  private async addComponentHashes(components: any[]): Promise<void> {
    for (const comp of components) {
      if (comp.path && !comp.hash) {
        try {
          const exists = await fs.pathExists(comp.path);
          if (exists) {
            comp.hash = await this.calculateHash(comp.path);
          }
        } catch { /* ignore */ }
      }
    }
  }

  private dedupeComponents(components: any[]): any[] {
    const map = new Map<string, any>();
    for (const c of components) {
      const name = (c.name || 'unknown').trim();
      const version = (c.version || 'unknown').trim();
      const key = `${name.toLowerCase()}@${version}`;
      if (!map.has(key)) {
        map.set(key, { ...c, name, version });
      } else {
        const existing = map.get(key);
        // Merge flags
        existing.system = existing.system || c.system;
        existing.detected = existing.detected || c.detected;
        if (!existing.hash && c.hash) existing.hash = c.hash;
        if (!existing.path && c.path) existing.path = c.path;
      }
    }
    return Array.from(map.values());
  }

  private async detectLicense(binaryPath: string): Promise<{ primary: string; all: string[] } | null> {
    try {
      const maxRead = 64 * 1024; // 64KB
      const fd = await fs.open(binaryPath, 'r');
      const buffer = Buffer.alloc(maxRead);
      const { bytesRead } = await fs.read(fd, buffer, 0, maxRead, 0);
      await fs.close(fd);
      const text = buffer.slice(0, bytesRead).toString('utf8');
      const candidates = [
        'Apache-2.0','MIT','BSD-3-Clause','BSD-2-Clause','GPL-3.0-only','GPL-3.0-or-later',
        'LGPL-3.0-only','LGPL-3.0-or-later','MPL-2.0','AGPL-3.0-only','AGPL-3.0-or-later','Unlicense','ISC'
      ];
      const found: string[] = [];
      // Capture composite expressions like "Apache-2.0 OR MIT" or "Apache-2.0 AND MIT"
      const compositeMatch = text.match(/((?:[A-Za-z0-9\.-]+\s+(?:OR|AND)\s+)+[A-Za-z0-9\.-]+)/);
      if (compositeMatch) {
        const expr = compositeMatch[1];
        expr.split(/\s+(?:OR|AND)\s+/).forEach(token => {
          if (candidates.includes(token) && !found.includes(token)) found.push(token);
        });
      }
      for (const id of candidates) {
        if (text.includes(id) && !found.includes(id)) found.push(id);
      }
      if (found.length === 0 && /permission is hereby granted/i.test(text)) found.push('MIT');
      if (found.length) {
        return { primary: found[0], all: found };
      }
    } catch {/* ignore */}
    return null;
  }

  private async parsePackageFile(packagePath: string): Promise<any[]> {
    const ext = path.extname(packagePath);
    const dependencies: any[] = [];

    try {
      switch (ext) {
        case '.json':
          const pkgJson = await fs.readJSON(packagePath);
          if (pkgJson.dependencies) {
            Object.entries(pkgJson.dependencies).forEach(([name, version]) => {
              const safe = sanitizeName(name);
              dependencies.push({
                ref: safe,
                version: version,
                type: 'npm',
                purl: `pkg:npm/${safe}@${version}`
              });
            });
          }
          break;

        case '.txt':
          const content = await fs.readFile(packagePath, 'utf8');
          const lines = content.split('\n');
          lines.forEach(line => {
            const match = line.match(/^([a-zA-Z0-9\-_]+)==(.+)$/);
            if (match) {
              const safe = sanitizeName(match[1]);
              dependencies.push({
                ref: safe,
                version: match[2],
                type: 'pip',
                purl: `pkg:pypi/${safe}@${match[2]}`
              });
            }
          });
          break;

        case '.toml':
          const tomlContent = await fs.readFile(packagePath, 'utf8');
          // Simple TOML parsing (for basic dependencies)
          const depMatches = tomlContent.match(/dependencies\s*=\s*\{([^}]+)\}/);
          if (depMatches) {
            const depsStr = depMatches[1];
            const depPairs = depsStr.split(',');
            depPairs.forEach(pair => {
              const [name, version] = pair.split('=').map(s => s.trim().replace(/"/g, ''));
              if (name && version) {
                const safe = sanitizeName(name);
                dependencies.push({
                  ref: safe,
                  version: version,
                  type: 'cargo',
                  purl: `pkg:cargo/${safe}@${version}`
                });
              }
            });
          }
          break;

        case '.mod':
          const modContent = await fs.readFile(packagePath, 'utf8');
          const requireMatches = modContent.match(/require\s+([^\s]+)\s+(.+)/g);
          if (requireMatches) {
            requireMatches.forEach(match => {
              const parts = match.split(/\s+/);
              if (parts.length >= 3) {
                const safe = sanitizeName(parts[1]);
                dependencies.push({
                  ref: safe,
                  version: parts[2],
                  type: 'go',
                  purl: `pkg:golang/${safe}@${parts[2]}`
                });
              }
            });
          }
          break;
      }
    } catch (error: unknown) {
      console.warn(`Error parsing package file ${packagePath}:`, (error as any)?.message);
    }

    return dependencies;
  }

  private generateCycloneDX(binaryInfo: any, components: any[], dependencies: any[]): any {
    // Consolidate dependency refs into component set (ensure every dependency has a component w/ bom-ref)
    const componentMap = new Map<string, any>();
    components.forEach(c => componentMap.set(`${c.name}@${c.version || 'unknown'}`.toLowerCase(), c));
    const depBomRefs: string[] = [];
    dependencies.forEach(dep => {
      const name = sanitizeName(dep.ref);
      const version = dep.version || 'unknown';
      const key = `${name}@${version}`.toLowerCase();
      if (!componentMap.has(key)) {
        componentMap.set(key, {
          type: 'library',
          name,
          version,
          purl: dep.purl || `pkg:generic/${name}@${version}`,
          _syntheticDependency: true
        });
      }
      depBomRefs.push(this.computeBomRef(name, version, dep.purl));
    });
    const allComponents = Array.from(componentMap.values());

    const rootName = sanitizeName(binaryInfo.name);
    const rootVersion = binaryInfo.rootVersion || '0.0.0';
    const rootBomRef = this.computeBomRef(rootName, rootVersion, `pkg:generic/${rootName}@${rootVersion}`);

    const depsSection = depBomRefs.length ? [
      { ref: rootBomRef, dependsOn: depBomRefs }
    ] : undefined;

    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      serialNumber: `urn:uuid:${this.generateUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: {
          type: 'application',
          name: rootName,
          version: rootVersion,
          purl: `pkg:generic/${rootName}@${rootVersion}`,
          'bom-ref': rootBomRef,
          hashes: [
            {
              alg: 'SHA-256',
              content: binaryInfo.hash
            }
          ],
          licenses: binaryInfo.licenses ? binaryInfo.licenses.map((l: string) => ({ license: { id: l } })) : (binaryInfo.license ? [{ license: { id: binaryInfo.license } }] : undefined),
          properties: [
            { name: 'binary:size', value: binaryInfo.size.toString() },
            { name: 'binary:type', value: binaryInfo.type },
            ...(binaryInfo.betanetFeatures ? (binaryInfo.betanetFeatures as string[]).map(f => ({ name: 'betanet.feature', value: f })) : [])
          ]
        },
        tools: [
          {
            vendor: 'QW1CKS',
            name: 'betanet-compliance-linter',
            version: this.getToolVersion()
          }
        ]
      },
      components: allComponents.map(comp => ({
        type: comp.type || 'library',
        name: sanitizeName(comp.name),
        version: comp.version || 'unknown',
        purl: comp.purl,
        'bom-ref': this.computeBomRef(sanitizeName(comp.name), comp.version || 'unknown', comp.purl),
        hashes: comp.hash ? [{ alg: 'SHA-256', content: comp.hash }] : undefined,
        licenses: comp.license ? [{ license: { id: comp.license } }] : undefined,
        properties: [
          ...(comp.detected ? [{ name: 'betanet.detected', value: 'true' }] : []),
          ...(comp._syntheticDependency ? [{ name: 'betanet.synthetic', value: 'dependency' }] : [])
        ]
      })),
      dependencies: depsSection
    };
  }

  private generateSPDXTagValue(binaryInfo: any, components: any[], dependencies: any[]): string {
    // Enhanced SPDX Tag-Value output (ISSUE-017)
    const safeDocName = sanitizeName(binaryInfo.name);
    const docNs = `https://spdx.org/spdxdocs/${safeDocName}-${this.generateUUID()}`;
    const lines: string[] = [];
    lines.push('SPDXVersion: SPDX-2.3');
    lines.push('DataLicense: CC0-1.0');
    lines.push('SPDXID: SPDXRef-DOCUMENT');
    lines.push(`DocumentName: ${safeDocName}`);
    lines.push(`DocumentNamespace: ${docNs}`);
    lines.push(`Created: ${new Date().toISOString()}`);
    lines.push('Creator: Tool: betanet-compliance-linter');
    lines.push('');
    const rootSpdxId = 'SPDXRef-Package-Root';
    lines.push(`PackageName: ${safeDocName}`);
    lines.push(`SPDXID: ${rootSpdxId}`);
  lines.push(`PackageVersion: ${(binaryInfo.rootVersion) || 'NOASSERTION'}`);
    lines.push('PackageDownloadLocation: NOASSERTION');
    lines.push('FilesAnalyzed: false');
    lines.push('PackageLicenseConcluded: NOASSERTION');
    lines.push(`PackageLicenseDeclared: ${(binaryInfo.licenses && binaryInfo.licenses.length > 1) ? binaryInfo.licenses.join(' OR ') : (binaryInfo.license || 'NOASSERTION')}`);
    lines.push('PackageCopyrightText: NOASSERTION');
    if (binaryInfo.hash) lines.push(`PackageChecksum: SHA256: ${binaryInfo.hash}`);
    if (binaryInfo.betanetFeatures && binaryInfo.betanetFeatures.length) {
      (binaryInfo.betanetFeatures as string[]).forEach((f: string) => lines.push(`PackageComment: betanet.feature=${f}`));
    }
    const dependencyIds: string[] = [];
    components.forEach((c, idx) => {
      const compId = `SPDXRef-Comp-${idx}`;
      lines.push('');
      lines.push(`PackageName: ${sanitizeName(c.name)}`);
      lines.push(`SPDXID: ${compId}`);
      lines.push(`PackageVersion: ${c.version || 'unknown'}`);
      lines.push('PackageDownloadLocation: NOASSERTION');
      lines.push('FilesAnalyzed: false');
      lines.push('PackageLicenseConcluded: NOASSERTION');
      lines.push(`PackageLicenseDeclared: ${c.license || 'NOASSERTION'}`);
      if (c.hash) lines.push(`PackageChecksum: SHA256: ${c.hash}`);
    });
    if (dependencies.length) {
      dependencies.forEach((d, i) => {
        const depId = `SPDXRef-Dep-${i}`;
        dependencyIds.push(depId);
        lines.push('');
        lines.push(`PackageName: ${sanitizeName(d.ref)}`);
        lines.push(`SPDXID: ${depId}`);
        lines.push(`PackageVersion: ${d.version || 'unknown'}`);
        lines.push('PackageDownloadLocation: NOASSERTION');
        lines.push('FilesAnalyzed: false');
        lines.push('PackageLicenseConcluded: NOASSERTION');
        lines.push('PackageLicenseDeclared: NOASSERTION');
      });
      // Relationships for dependencies
      dependencyIds.forEach(id => {
        lines.push(`Relationship: ${rootSpdxId} DEPENDS_ON ${id}`);
      });
    }
    return lines.join('\n');
  }

  private generateSPDXJson(binaryInfo: any, components: any[], dependencies: any[]): any {
    const docId = `SPDXRef-DOCUMENT`;
    const safeBin = sanitizeName(binaryInfo.name);
    const packageId = `SPDXRef-Package-Root`;
    const relationships: any[] = [];
    return {
      SPDXID: docId,
      spdxVersion: 'SPDX-2.3',
      dataLicense: 'CC0-1.0',
      name: safeBin,
      documentNamespace: `https://spdx.org/spdxdocs/${safeBin}-${this.generateUUID()}`,
      creationInfo: {
        created: new Date().toISOString(),
        creators: ['Tool: betanet-compliance-linter', 'Organization: QW1CKS']
      },
      packages: [
        {
          name: safeBin,
          SPDXID: packageId,
          versionInfo: (binaryInfo.rootVersion) || 'NOASSERTION',
          filesAnalyzed: false,
          downloadLocation: 'NOASSERTION',
          checksums: binaryInfo.hash ? [{ algorithm: 'SHA256', checksumValue: binaryInfo.hash }] : [],
          licenseDeclared: binaryInfo.licenses && binaryInfo.licenses.length > 1 ? binaryInfo.licenses.join(' OR ') : (binaryInfo.license || 'NOASSERTION'),
          licenseConcluded: 'NOASSERTION',
          copyrightText: 'NOASSERTION',
          betanetFeatures: binaryInfo.betanetFeatures && binaryInfo.betanetFeatures.length ? binaryInfo.betanetFeatures : undefined
        },
        ...components.map((c, idx) => ({
          name: sanitizeName(c.name),
          SPDXID: `SPDXRef-Comp-${idx}`,
          versionInfo: c.version || 'unknown',
          filesAnalyzed: false,
          downloadLocation: 'NOASSERTION',
          licenseDeclared: c.license || 'NOASSERTION',
          licenseConcluded: 'NOASSERTION',
          copyrightText: 'NOASSERTION',
          checksums: c.hash ? [{ algorithm: 'SHA256', checksumValue: c.hash }] : []
  })),
        // dependency packages
        ...dependencies.map((d, i) => ({
          name: sanitizeName(d.ref),
          SPDXID: `SPDXRef-Dep-${i}`,
          versionInfo: d.version || 'unknown',
          filesAnalyzed: false,
          downloadLocation: 'NOASSERTION',
          licenseDeclared: 'NOASSERTION',
          licenseConcluded: 'NOASSERTION',
          copyrightText: 'NOASSERTION'
        }))
      ],
      relationships: [
        ...relationships,
        ...dependencies.map((d, i) => ({
          spdxElementId: packageId,
          relationshipType: 'DEPENDS_ON',
          relatedSpdxElement: `SPDXRef-Dep-${i}`
        }))
      ]
    };
  }

  private computeBomRef(name: string, version: string, purl?: string): string {
    if (purl) return purl; // purl is acceptable as bom-ref (common practice)
    return `urn:betanet:component:${name}:${version}`;
  }

  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}