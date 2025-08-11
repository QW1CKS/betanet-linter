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
  diagnostics?: AnalyzerDiagnostics;
}

export interface SBOMComponent {
  name: string;
  version: string;
  type: 'library' | 'framework' | 'tool';
  license?: string;
  supplier?: string;
  hashes?: string[];
}

// Generic SBOM structure used by sbom-generator.ts
export interface SBOM {
  format: 'cyclonedx' | 'spdx' | 'cyclonedx-json';
  data: any; // Underlying JSON / XML / text representation
  generated: string; // ISO timestamp
}

// Tool availability & performance diagnostics
export interface ToolStatus {
  name: string;
  available: boolean;
  durationMs?: number;
  error?: string;
}

export interface AnalyzerDiagnostics {
  tools: ToolStatus[];
  analyzeInvocations: number; // how many times analyze() logic executed (should be 1 after memoization)
  cached: boolean; // whether subsequent calls used cache
  totalAnalysisTimeMs?: number; // elapsed time for first analysis
}

export interface CheckOptions {
  verbose?: boolean;
  checkFilters?: {
    include?: number[];
    exclude?: number[];
  };
}

export interface SBOMOptions {
  format: 'cyclonedx' | 'spdx' | 'cyclonedx-json';
  outputPath?: string;
}