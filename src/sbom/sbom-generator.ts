import * as fs from 'fs-extra';
import * as path from 'path';
import execa from 'execa';
import { SBOM } from '../types';

export class SBOMGenerator {
  async generate(binaryPath: string, format: 'cyclonedx' | 'spdx' = 'cyclonedx'): Promise<SBOM> {
    const binaryInfo = await this.getBinaryInfo(binaryPath);
    const components = await this.extractComponents(binaryPath);
    const dependencies = await this.extractDependencies(binaryPath);

    // Attempt per-component hashing when a concrete path exists
    await this.addComponentHashes(components);
    // Sanitize & dedupe
    const finalComponents = this.dedupeComponents(components);
    // Detect license for root package
    const rootLicense = await this.detectLicense(binaryPath);
    if (rootLicense) {
      (binaryInfo as any).license = rootLicense;
    }

    if (format === 'cyclonedx') {
      return {
        format: 'cyclonedx',
        data: this.generateCycloneDX(binaryInfo, finalComponents, dependencies),
        generated: new Date().toISOString()
      };
    } else {
      return {
        format: 'spdx',
        data: this.generateSPDX(binaryInfo, finalComponents, dependencies),
        generated: new Date().toISOString()
      };
    }
  }

  private async getBinaryInfo(binaryPath: string): Promise<any> {
    try {
      const [fileInfo, stat] = await Promise.all([
        execa('file', [binaryPath]),
        fs.stat(binaryPath)
      ]);

      return {
        name: path.basename(binaryPath),
        path: binaryPath,
        size: stat.size,
        modified: stat.mtime.toISOString(),
        type: fileInfo.stdout,
        hash: await this.calculateHash(binaryPath)
      };
  } catch (error: unknown) {
      return {
        name: path.basename(binaryPath),
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
      const { stdout } = await execa('sha256sum', [binaryPath]);
      return stdout.split(' ')[0];
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
  }

  private async extractComponents(binaryPath: string): Promise<any[]> {
    const components: any[] = [];

    // Helper: add version matches to components
    const addVersions = (text: string) => {
      const lines = text.split('\n');
      const versionPatterns = [
        /(\d+\.\d+\.\d+)/,
        /v(\d+\.\d+\.\d+)/,
        /version\s+(\d+\.\d+\.\d+)/i,
        /(\d+\.\d+\.\d+[-_]\w+)/,
        /([a-zA-Z]+)\s+(\d+\.\d+\.\d+)/i
      ];
      const foundVersions = new Set<string>();
      for (const line of lines) {
        for (const pattern of versionPatterns) {
          const match = line.match(pattern);
            if (match && match[1]) {
              foundVersions.add(match[1]);
            }
        }
      }
      foundVersions.forEach(version => {
        components.push({
          type: 'library',
          name: 'Unknown',
          version,
          purl: `pkg:generic/unknown@${version}`,
          detected: true
        });
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
          addVersions(ascii.join('\n'));
        }
      } catch (e) {
        if (debug) console.warn('SBOM fallback (windows strings) failed:', (e as any)?.message);
      }
      return components;
    }

    // Non-Windows: attempt `strings`
    try {
      const { stdout } = await execa('strings', [binaryPath]);
      addVersions(stdout);
    } catch (e: any) {
      const msg = (e as any)?.message || '';
      if (debug) console.warn('SBOM strings exec skipped:', msg);
    }

    // Attempt ldd for component library names (best-effort)
    try {
      const { stdout: lddOutput } = await execa('ldd', [binaryPath]);
      const lddLines = lddOutput.split('\n');
      for (const line of lddLines) {
        const libMatch = line.match(/\s+(.+?)\s+=>\s+(.+?)\s+\(/);
        if (libMatch) {
          const libName = libMatch[1];
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

    return components;
  }

  private async extractDependencies(binaryPath: string): Promise<any[]> {
    const dependencies: any[] = [];

    const debug = process.env.BETANET_DEBUG_SBOM === '1';

    if (process.platform !== 'win32') {
      try {
        const { stdout: lddOutput } = await execa('ldd', [binaryPath]);
        const lddLines = lddOutput.split('\n');
        for (const line of lddLines) {
          const depMatch = line.match(/\s+(.+?)\s+=>\s+(.+?)\s+\(/);
          if (depMatch) {
            const libName = depMatch[1];
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

  private async detectLicense(binaryPath: string): Promise<string | null> {
    try {
      const maxRead = 64 * 1024; // 64KB
      const fd = await fs.open(binaryPath, 'r');
      const buffer = Buffer.alloc(maxRead);
      const { bytesRead } = await fs.read(fd, buffer, 0, maxRead, 0);
      await fs.close(fd);
      const text = buffer.slice(0, bytesRead).toString('utf8');
      const licenses = [
        'Apache-2.0','MIT','BSD-3-Clause','BSD-2-Clause','GPL-3.0-only','GPL-3.0-or-later',
        'LGPL-3.0-only','LGPL-3.0-or-later','MPL-2.0','AGPL-3.0-only','AGPL-3.0-or-later','Unlicense','ISC'
      ];
      for (const id of licenses) {
        if (text.includes(id)) return id;
      }
      // Secondary simple patterns
      if (/permission is hereby granted/i.test(text)) return 'MIT';
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
              dependencies.push({
                ref: name,
                version: version,
                type: 'npm',
                purl: `pkg:npm/${name}@${version}`
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
              dependencies.push({
                ref: match[1],
                version: match[2],
                type: 'pip',
                purl: `pkg:pypi/${match[1]}@${match[2]}`
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
                dependencies.push({
                  ref: name,
                  version: version,
                  type: 'cargo',
                  purl: `pkg:cargo/${name}@${version}`
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
                dependencies.push({
                  ref: parts[1],
                  version: parts[2],
                  type: 'go',
                  purl: `pkg:golang/${parts[1]}@${parts[2]}`
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
    return {
      bomFormat: 'CycloneDX',
      specVersion: '1.4',
      serialNumber: `urn:uuid:${this.generateUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: {
          type: 'application',
          name: binaryInfo.name,
          version: '1.0.0',
          purl: `pkg:generic/${binaryInfo.name}@1.0.0`,
          hashes: [
            {
              alg: 'SHA-256',
              content: binaryInfo.hash
            }
          ],
          licenses: binaryInfo.license ? [{ license: { id: binaryInfo.license } }] : undefined,
          properties: [
            {
              name: 'binary:size',
              value: binaryInfo.size.toString()
            },
            {
              name: 'binary:type',
              value: binaryInfo.type
            }
          ]
        }
      },
      components: components.map(comp => ({
        type: comp.type || 'library',
        name: comp.name,
        version: comp.version || 'unknown',
        purl: comp.purl,
        hashes: comp.hash ? [{ alg: 'SHA-256', content: comp.hash }] : undefined,
        licenses: comp.license ? [{ license: { id: comp.license } }] : undefined,
        properties: comp.detected ? [{
          name: 'detected',
          value: 'true'
        }] : []
      })),
      dependencies: [
        {
          ref: binaryInfo.name,
          dependsOn: dependencies.map(dep => dep.ref)
        },
        ...dependencies.map(dep => ({
          ref: dep.ref,
          dependsOn: []
        }))
      ]
    };
  }

  private generateSPDX(binaryInfo: any, components: any[], dependencies: any[]): string {
    const spdxContent = {
      SPDXID: 'SPDXRef-DOCUMENT',
      spdxVersion: 'SPDX-2.3',
      creationInfo: {
        created: new Date().toISOString(),
        creators: ['Tool: betanet-compliance-linter']
      },
      name: binaryInfo.name,
      documentNamespace: `https://spdx.org/spdxdocs/${binaryInfo.name}-${this.generateUUID()}`,
      packages: [{
        name: binaryInfo.name,
        SPDXID: 'SPDXRef-PACKAGE',
        versionInfo: '1.0.0',
        downloadLocation: 'NOASSERTION',
        filesAnalyzed: false,
        checksums: [{
          algorithm: 'SHA256',
          checksumValue: binaryInfo.hash
        }],
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION',
        copyrightText: 'NOASSERTION'
      }],
      relationships: dependencies.map(dep => ({
        spdxElementId: 'SPDXRef-PACKAGE',
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: `SPDXRef-${dep.ref.replace(/[^a-zA-Z0-9]/g, '_')}`
      }))
    };

    // Convert to SPDX format
    let spdxText = `SPDXVersion: SPDX-2.3\n`;
    spdxText += `DataLicense: CC0-1.0\n`;
    spdxText += `SPDXID: SPDXRef-DOCUMENT\n`;
    spdxText += `DocumentName: ${binaryInfo.name}\n`;
    spdxText += `DocumentNamespace: https://spdx.org/spdxdocs/${binaryInfo.name}-${this.generateUUID()}\n`;
    spdxText += `Created: ${new Date().toISOString()}\n`;
    spdxText += `Creator: Tool: betanet-compliance-linter\n\n`;

    spdxText += `Package: ${binaryInfo.name}\n`;
    spdxText += `SPDXID: SPDXRef-PACKAGE\n`;
    spdxText += `PackageName: ${binaryInfo.name}\n`;
    spdxText += `PackageVersion: 1.0.0\n`;
    spdxText += `PackageDownloadLocation: NOASSERTION\n`;
    spdxText += `FilesAnalyzed: false\n`;
    spdxText += `PackageLicenseConcluded: NOASSERTION\n`;
  spdxText += `PackageLicenseDeclared: ${binaryInfo.license || 'NOASSERTION'}\n`;
    spdxText += `PackageCopyrightText: NOASSERTION\n`;
    if (binaryInfo.hash) {
      spdxText += `PackageChecksum: SHA256: ${binaryInfo.hash}\n`;
    }

    // Append detected component licenses if any
    components.forEach((c, idx) => {
      if (c.license) {
        spdxText += `PackageName: ${c.name}\n`;
        spdxText += `SPDXID: SPDXRef-COMP-${idx}\n`;
        spdxText += `PackageVersion: ${c.version || 'unknown'}\n`;
        spdxText += `PackageLicenseDeclared: ${c.license}\n`;
      }
    });
    return spdxText;
  }

  private generateUUID(): string {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
      const r = Math.random() * 16 | 0;
      const v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }
}