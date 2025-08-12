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
export declare function getChecksByIds(ids: number[]): CheckDefinitionMeta[];
//# sourceMappingURL=check-registry.d.ts.map