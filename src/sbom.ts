import * as fs from 'fs-extra';
import * as path from 'path';
import * as xml2js from 'xml2js';
import * as yaml from 'js-yaml';
import { SBOMComponent, SBOMOptions } from './types';
import { BinaryAnalyzer } from './analyzer';

export class SBOMGenerator {
  private analyzer: BinaryAnalyzer;

  constructor(binaryPath: string) {
    this.analyzer = new BinaryAnalyzer(binaryPath);
  }

  async generate(options: SBOMOptions): Promise<string> {
    const analysis = await this.analyzer.analyze();
    const components = await this.extractComponents(analysis);
    
    const outputPath = options.outputPath || 
      path.join(process.cwd(), `sbom-${path.basename(this.analyzer['binaryPath'])}.${options.format === 'cyclonedx' ? 'xml' : 'spdx'}`);

    switch (options.format) {
      case 'cyclonedx':
        await this.generateCycloneDX(components, outputPath);
        break;
      case 'spdx':
        await this.generateSPDX(components, outputPath);
        break;
    }

    return outputPath;
  }

  private async extractComponents(analysis: any): Promise<SBOMComponent[]> {
    const components: SBOMComponent[] = [];

    // Extract from binary analysis
    if (analysis.dependencies.length > 0) {
      analysis.dependencies.forEach((dep: string) => {
        components.push({
          name: dep,
          version: 'dynamic',
          type: 'library'
        });
      });
    }

    // Extract from strings that look like version info
    const versionPatterns = [
      /([a-zA-Z0-9_-]+)\s+([0-9]+\.[0-9]+\.[0-9]+)/g,
      /([a-zA-Z0-9_-]+)-([0-9]+\.[0-9]+\.[0-9]+)/g,
      /([a-zA-Z0-9_-]+)\/v?([0-9]+\.[0-9]+\.[0-9]+)/g
    ];

    analysis.strings.forEach((str: string) => {
      for (const pattern of versionPatterns) {
        const match = pattern.exec(str);
        if (match) {
          components.push({
            name: match[1],
            version: match[2],
            type: 'library'
          });
        }
      }
    });

    // Add common crypto libraries if detected
    const cryptoLibs = ['openssl', 'libsodium', 'nettle', 'gnutls'];
    cryptoLibs.forEach(lib => {
      if (analysis.strings.some((s: string) => s.toLowerCase().includes(lib))) {
        components.push({
          name: lib,
          version: 'detected',
          type: 'library'
        });
      }
    });

    // Remove duplicates
    const unique = components.filter((comp, index, self) =>
      index === self.findIndex(c => c.name === comp.name && c.version === comp.version)
    );

    return unique;
  }

  private async generateCycloneDX(components: SBOMComponent[], outputPath: string): Promise<void> {
    const builder = new xml2js.Builder({
      renderOpts: { pretty: true },
      headless: true
    });

    const cyclonedx = {
      'bom': {
        '$': {
          'xmlns': 'http://cyclonedx.org/schema/bom/1.4',
          'version': '1'
        },
        'metadata': {
          'timestamp': new Date().toISOString(),
          'tools': {
            'tool': {
              'name': 'betanet-compliance-linter',
              'version': '1.0.0'
            }
          },
          'component': {
            '$': { 'type': 'application' },
            'name': path.basename(this.analyzer['binaryPath']),
            'version': '1.0.0'
          }
        },
        'components': {
          'component': components.map(comp => ({
            '$': { 'type': 'library' },
            'name': comp.name,
            'version': comp.version,
            'purl': `pkg:generic/${comp.name}@${comp.version}`
          }))
        }
      }
    };

    const xml = builder.buildObject(cyclonedx);
    await fs.writeFile(outputPath, xml);
  }

  private async generateSPDX(components: SBOMComponent[], outputPath: string): Promise<void> {
    const spdx = {
      SPDXID: 'SPDXRef-DOCUMENT',
      spdxVersion: 'SPDX-2.3',
      creationInfo: {
        created: new Date().toISOString(),
        creators: ['Tool: betanet-compliance-linter-1.0.0']
      },
      name: path.basename(this.analyzer['binaryPath']),
      documentNamespace: `https://spdx.org/spdxdocs/betanet-${Date.now()}`,
      packages: [{
        SPDXID: 'SPDXRef-PACKAGE',
        name: path.basename(this.analyzer['binaryPath']),
        versionInfo: '1.0.0',
        supplier: 'NOASSERTION',
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION'
      }],
      relationships: components.map((comp, index) => ({
        spdxElementId: 'SPDXRef-PACKAGE',
        relationshipType: 'DEPENDS_ON',
        relatedSpdxElement: `SPDXRef-COMPONENT-${index}`
      })),
      hasExtractedLicensingInfos: []
    };

    // Add components as packages
    components.forEach((comp, index) => {
      spdx.packages.push({
        SPDXID: `SPDXRef-COMPONENT-${index}`,
        name: comp.name,
        versionInfo: comp.version,
        supplier: 'NOASSERTION',
        licenseConcluded: 'NOASSERTION',
        licenseDeclared: 'NOASSERTION'
      });
    });

    const yamlContent = yaml.dump(spdx, { 
      lineWidth: -1,
      noRefs: true 
    });
    
    await fs.writeFile(outputPath, yamlContent);
  }
}