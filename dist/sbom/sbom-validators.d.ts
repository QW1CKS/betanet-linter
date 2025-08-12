export interface ValidationResult {
    valid: boolean;
    errors: string[];
}
export declare function validateCycloneDXShape(doc: any): ValidationResult;
export declare function validateSPDXTagValue(text: string): ValidationResult;
export declare function validateCycloneDXStrict(doc: any): ValidationResult;
export declare function validateSPDXTagValueStrict(text: string): ValidationResult;
//# sourceMappingURL=sbom-validators.d.ts.map