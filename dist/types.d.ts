export interface ComplianceCheck {
    id: number;
    name: string;
    description: string;
    passed: boolean;
    details: string;
    severity: 'critical' | 'major' | 'minor';
}
export interface ComplianceResult {
    binaryPath: string;
    timestamp: string;
    overallScore: number;
    passed: boolean;
    checks: ComplianceCheck[];
    summary: {
        total: number;
        passed: number;
        failed: number;
        critical: number;
    };
}
export interface SBOMComponent {
    name: string;
    version: string;
    type: 'library' | 'framework' | 'tool';
    license?: string;
    supplier?: string;
    hashes?: string[];
}
export interface SBOM {
    format: 'cyclonedx' | 'spdx';
    data: any;
    generated: string;
}
export interface CheckOptions {
    verbose?: boolean;
    checkFilters?: {
        include?: number[];
        exclude?: number[];
    };
}
export interface SBOMOptions {
    format: 'cyclonedx' | 'spdx';
    outputPath?: string;
}
//# sourceMappingURL=types.d.ts.map