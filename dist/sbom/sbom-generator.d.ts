import { SBOM } from '../types';
export declare class SBOMGenerator {
    generate(binaryPath: string, format?: 'cyclonedx' | 'spdx'): Promise<SBOM>;
    private getBinaryInfo;
    private calculateHash;
    private extractComponents;
    private extractDependencies;
    private parsePackageFile;
    private generateCycloneDX;
    private generateSPDX;
    private generateUUID;
}
//# sourceMappingURL=sbom-generator.d.ts.map