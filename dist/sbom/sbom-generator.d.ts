import { SBOM } from '../types';
import { BinaryAnalyzer } from '../analyzer';
export declare class SBOMGenerator {
    generate(binaryPath: string, format?: 'cyclonedx' | 'spdx' | 'cyclonedx-json' | 'spdx-json', analyzer?: BinaryAnalyzer): Promise<SBOM>;
    private deriveFeatures;
    private getBinaryInfo;
    private calculateHash;
    private extractComponents;
    private extractDependencies;
    private addComponentHashes;
    private dedupeComponents;
    private detectLicense;
    private parsePackageFile;
    private generateCycloneDX;
    private generateSPDXTagValue;
    private generateSPDXJson;
    private generateUUID;
}
//# sourceMappingURL=sbom-generator.d.ts.map