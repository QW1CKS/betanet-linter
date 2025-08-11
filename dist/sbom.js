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
exports.SBOMGenerator = void 0;
const fs = __importStar(require("fs-extra"));
const path = __importStar(require("path"));
const xml2js = __importStar(require("xml2js"));
const yaml = __importStar(require("js-yaml"));
const analyzer_1 = require("./analyzer");
class SBOMGenerator {
    constructor(binaryPath) {
        this.analyzer = new analyzer_1.BinaryAnalyzer(binaryPath);
    }
    async generate(options) {
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
    async extractComponents(analysis) {
        const components = [];
        // Extract from binary analysis
        if (analysis.dependencies.length > 0) {
            analysis.dependencies.forEach((dep) => {
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
        analysis.strings.forEach((str) => {
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
            if (analysis.strings.some((s) => s.toLowerCase().includes(lib))) {
                components.push({
                    name: lib,
                    version: 'detected',
                    type: 'library'
                });
            }
        });
        // Remove duplicates
        const unique = components.filter((comp, index, self) => index === self.findIndex(c => c.name === comp.name && c.version === comp.version));
        return unique;
    }
    async generateCycloneDX(components, outputPath) {
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
    async generateSPDX(components, outputPath) {
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
exports.SBOMGenerator = SBOMGenerator;
//# sourceMappingURL=sbom.js.map