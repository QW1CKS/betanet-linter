import { BinaryAnalyzer } from './analyzer';
import { ComplianceCheck } from './types';
export interface CheckDefinitionMeta {
    id: number;
    key: string;
    name: string;
    description: string;
    severity: 'critical' | 'major' | 'minor';
    introducedIn: string;
    mandatoryIn?: string;
    evaluate: (analyzer: BinaryAnalyzer, now: Date) => Promise<ComplianceCheck>;
}
export declare const CHECK_REGISTRY: CheckDefinitionMeta[];
export declare const STEP_10_CHECKS: {
    id: number;
    key: string;
    name: string;
    description: string;
    severity: string;
    introducedIn: string;
    evaluate: (analyzer: any) => Promise<{
        id: number;
        name: string;
        description: string;
        passed: boolean;
        details: string;
        severity: string;
        evidenceType: string;
    }>;
}[];
export declare const PHASE_4_CHECKS: CheckDefinitionMeta[];
export declare const PHASE_7_CONT_CHECKS: CheckDefinitionMeta[];
export declare const ALL_CHECKS: CheckDefinitionMeta[];
export declare function getChecksByIds(ids: number[]): CheckDefinitionMeta[];
//# sourceMappingURL=check-registry.d.ts.map