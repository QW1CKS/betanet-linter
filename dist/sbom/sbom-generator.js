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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SBOMGenerator = void 0;
const fs = __importStar(require("fs-extra"));
const path = __importStar(require("path"));
const execa_1 = __importDefault(require("execa"));
class SBOMGenerator {
    async generate(binaryPath, format = 'cyclonedx') {
        const binaryInfo = await this.getBinaryInfo(binaryPath);
        const components = await this.extractComponents(binaryPath);
        const dependencies = await this.extractDependencies(binaryPath);
        if (format === 'cyclonedx') {
            return {
                format: 'cyclonedx',
                data: this.generateCycloneDX(binaryInfo, components, dependencies),
                generated: new Date().toISOString()
            };
        }
        else {
            return {
                format: 'spdx',
                data: this.generateSPDX(binaryInfo, components, dependencies),
                generated: new Date().toISOString()
            };
        }
    }
    async getBinaryInfo(binaryPath) {
        try {
            const [fileInfo, stat] = await Promise.all([
                (0, execa_1.default)('file', [binaryPath]),
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
        }
        catch (error) {
            return {
                name: path.basename(binaryPath),
                path: binaryPath,
                size: 0,
                modified: new Date().toISOString(),
                type: 'Unknown',
                hash: '',
                error: error?.message
            };
        }
    }
    async calculateHash(binaryPath) {
        try {
            const { stdout } = await (0, execa_1.default)('sha256sum', [binaryPath]);
            return stdout.split(' ')[0];
        }
        catch (error) {
            try {
                // Fallback to Node.js crypto
                const crypto = require('crypto');
                const hash = crypto.createHash('sha256');
                const data = await fs.readFile(binaryPath);
                hash.update(data);
                return hash.digest('hex');
            }
            catch (e) {
                return '';
            }
        }
    }
    async extractComponents(binaryPath) {
        const components = [];
        try {
            // Extract strings to find version information
            const { stdout } = await (0, execa_1.default)('strings', [binaryPath]);
            const lines = stdout.split('\n');
            // Look for version patterns
            const versionPatterns = [
                /(\d+\.\d+\.\d+)/,
                /v(\d+\.\d+\.\d+)/,
                /version\s+(\d+\.\d+\.\d+)/i,
                /(\d+\.\d+\.\d+[-_]\w+)/,
                /([a-zA-Z]+)\s+(\d+\.\d+\.\d+)/i
            ];
            const foundVersions = new Set();
            for (const line of lines) {
                for (const pattern of versionPatterns) {
                    const match = line.match(pattern);
                    if (match && match[1]) {
                        foundVersions.add(match[1]);
                    }
                }
            }
            // Convert found versions to components
            foundVersions.forEach(version => {
                components.push({
                    type: 'library',
                    name: 'Unknown',
                    version: version,
                    purl: `pkg:generic/unknown@${version}`,
                    detected: true
                });
            });
            // Try to get more detailed component info using ldd
            try {
                const { stdout: lddOutput } = await (0, execa_1.default)('ldd', [binaryPath]);
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
            }
            catch (e) {
                // ldd failed, continue without library info
            }
        }
        catch (error) {
            console.warn('Error extracting components:', error?.message);
        }
        return components;
    }
    async extractDependencies(binaryPath) {
        const dependencies = [];
        try {
            // Try to get dynamic dependencies
            const { stdout: lddOutput } = await (0, execa_1.default)('ldd', [binaryPath]);
            const lddLines = lddOutput.split('\n');
            for (const line of lddLines) {
                const depMatch = line.match(/\s+(.+?)\s+=>\s+(.+?)\s+\(/);
                if (depMatch) {
                    const libName = depMatch[1];
                    const libPath = depMatch[2];
                    dependencies.push({
                        ref: libName,
                        path: libPath,
                        type: 'dynamic'
                    });
                }
            }
            // Try to get package dependencies if this is a packaged binary
            const packageFiles = ['package.json', 'requirements.txt', 'Cargo.toml', 'go.mod'];
            const binaryDir = path.dirname(binaryPath);
            for (const pkgFile of packageFiles) {
                const pkgPath = path.join(binaryDir, pkgFile);
                if (await fs.pathExists(pkgPath)) {
                    const pkgDeps = await this.parsePackageFile(pkgPath);
                    dependencies.push(...pkgDeps);
                }
            }
        }
        catch (error) {
            console.warn('Error extracting dependencies:', error?.message);
        }
        return dependencies;
    }
    async parsePackageFile(packagePath) {
        const ext = path.extname(packagePath);
        const dependencies = [];
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
        }
        catch (error) {
            console.warn(`Error parsing package file ${packagePath}:`, error?.message);
        }
        return dependencies;
    }
    generateCycloneDX(binaryInfo, components, dependencies) {
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
    generateSPDX(binaryInfo, components, dependencies) {
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
        spdxText += `PackageLicenseDeclared: NOASSERTION\n`;
        spdxText += `PackageCopyrightText: NOASSERTION\n`;
        if (binaryInfo.hash) {
            spdxText += `PackageChecksum: SHA256: ${binaryInfo.hash}\n`;
        }
        return spdxText;
    }
    generateUUID() {
        return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
            const r = Math.random() * 16 | 0;
            const v = c === 'x' ? r : (r & 0x3 | 0x8);
            return v.toString(16);
        });
    }
}
exports.SBOMGenerator = SBOMGenerator;
//# sourceMappingURL=sbom-generator.js.map