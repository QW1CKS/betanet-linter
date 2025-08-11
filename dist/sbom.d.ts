import { SBOMOptions } from './types';
export declare class SBOMGenerator {
    private analyzer;
    constructor(binaryPath: string);
    generate(options: SBOMOptions): Promise<string>;
    private extractComponents;
    private generateCycloneDX;
    private generateSPDX;
}
//# sourceMappingURL=sbom.d.ts.map