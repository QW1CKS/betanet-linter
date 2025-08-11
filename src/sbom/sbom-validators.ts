// Lightweight schema shape validators for SBOM outputs (non-exhaustive).
// These intentionally check only structural essentials to catch regressions
// without pulling full JSON schemas or external dependencies.

export interface ValidationResult {
  valid: boolean;
  errors: string[];
}

export function validateCycloneDXShape(doc: any): ValidationResult {
  const errors: string[] = [];
  if (!doc || typeof doc !== 'object') errors.push('Document not an object');
  if (doc.bomFormat !== 'CycloneDX') errors.push('bomFormat must be CycloneDX');
  if (!doc.specVersion) errors.push('specVersion missing');
  if (!doc.metadata) errors.push('metadata missing');
  const comp = doc?.metadata?.component;
  if (!comp) errors.push('metadata.component missing');
  else {
    if (!comp.name) errors.push('component.name missing');
    if (!comp.version) errors.push('component.version missing');
    if (!comp.purl) errors.push('component.purl missing');
  }
  if (doc.components) {
    if (!Array.isArray(doc.components)) errors.push('components must be array');
    else {
      doc.components.forEach((c: any, i: number) => {
        if (!c.name) errors.push(`components[${i}].name missing`);
        if (!c.version) errors.push(`components[${i}].version missing`);
      });
    }
  }
  return { valid: errors.length === 0, errors };
}

export function validateSPDXTagValue(text: string): ValidationResult {
  const errors: string[] = [];
  if (!text || typeof text !== 'string') return { valid: false, errors: ['SPDX text empty'] };
  const lines = text.split(/\r?\n/).filter(l => l.trim().length);
  const requiredKeys = ['SPDXVersion:', 'DocumentNamespace:', 'DocumentName:', 'PackageName:'];
  for (const key of requiredKeys) {
    if (!lines.some(l => l.startsWith(key))) errors.push(`Missing key ${key}`);
  }
  if (!lines.some(l => l.startsWith('PackageLicenseDeclared:'))) {
    errors.push('Missing PackageLicenseDeclared');
  }
  return { valid: errors.length === 0, errors };
}
