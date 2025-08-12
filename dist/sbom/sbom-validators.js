"use strict";
// Lightweight schema shape validators for SBOM outputs (non-exhaustive).
// These intentionally check only structural essentials to catch regressions
// without pulling full JSON schemas or external dependencies.
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateCycloneDXShape = validateCycloneDXShape;
exports.validateSPDXTagValue = validateSPDXTagValue;
exports.validateCycloneDXStrict = validateCycloneDXStrict;
exports.validateSPDXTagValueStrict = validateSPDXTagValueStrict;
function validateCycloneDXShape(doc) {
    const errors = [];
    if (!doc || typeof doc !== 'object')
        errors.push('Document not an object');
    if (doc.bomFormat !== 'CycloneDX')
        errors.push('bomFormat must be CycloneDX');
    if (!doc.specVersion)
        errors.push('specVersion missing');
    if (!doc.metadata)
        errors.push('metadata missing');
    const comp = doc?.metadata?.component;
    if (!comp)
        errors.push('metadata.component missing');
    else {
        if (!comp.name)
            errors.push('component.name missing');
        if (!comp.version)
            errors.push('component.version missing');
        if (!comp.purl)
            errors.push('component.purl missing');
    }
    if (doc.components) {
        if (!Array.isArray(doc.components))
            errors.push('components must be array');
        else {
            doc.components.forEach((c, i) => {
                if (!c.name)
                    errors.push(`components[${i}].name missing`);
                if (!c.version)
                    errors.push(`components[${i}].version missing`);
            });
        }
    }
    return { valid: errors.length === 0, errors };
}
function validateSPDXTagValue(text) {
    const errors = [];
    if (!text || typeof text !== 'string')
        return { valid: false, errors: ['SPDX text empty'] };
    const lines = text.split(/\r?\n/).filter(l => l.trim().length);
    const requiredKeys = ['SPDXVersion:', 'DocumentNamespace:', 'DocumentName:', 'PackageName:'];
    for (const key of requiredKeys) {
        if (!lines.some(l => l.startsWith(key)))
            errors.push(`Missing key ${key}`);
    }
    if (!lines.some(l => l.startsWith('PackageLicenseDeclared:'))) {
        errors.push('Missing PackageLicenseDeclared');
    }
    return { valid: errors.length === 0, errors };
}
// Strict variants with deeper structural assertions (still lightweight, but tighter)
function validateCycloneDXStrict(doc) {
    const base = validateCycloneDXShape(doc);
    const errors = [...base.errors];
    if (!base.valid)
        return { valid: false, errors };
    // serialNumber format (UUID urn)
    if (!/^urn:uuid:[0-9a-fA-F-]{36}$/.test(doc.serialNumber || ''))
        errors.push('serialNumber invalid');
    if (typeof doc.version !== 'number')
        errors.push('version must be number');
    const comp = doc.metadata?.component;
    if (comp?.hashes) {
        if (!Array.isArray(comp.hashes))
            errors.push('component.hashes must be array');
        else
            comp.hashes.forEach((h, i) => {
                if (!h.alg)
                    errors.push(`component.hashes[${i}].alg missing`);
                // Allow empty content (hash may not be computable on some platforms)
                if (h.content === undefined)
                    errors.push(`component.hashes[${i}].content missing`);
            });
    }
    if (Array.isArray(doc.components)) {
        doc.components.forEach((c, i) => {
            if (!['library', 'application', 'framework', 'container', 'platform', 'device'].includes(c.type || ''))
                errors.push(`components[${i}].type invalid`);
            if (c.hashes) {
                if (!Array.isArray(c.hashes))
                    errors.push(`components[${i}].hashes not array`);
            }
        });
    }
    // dependencies refs must exist among component refs or root
    const componentNames = new Set([comp?.name].filter(Boolean));
    if (Array.isArray(doc.components))
        doc.components.forEach((c) => componentNames.add(c.name));
    if (Array.isArray(doc.dependencies)) {
        doc.dependencies.forEach((dep, idx) => {
            if (!dep.ref)
                errors.push(`dependencies[${idx}].ref missing`);
            if (dep.dependsOn && !Array.isArray(dep.dependsOn))
                errors.push(`dependencies[${idx}].dependsOn not array`);
            if (Array.isArray(dep.dependsOn)) {
                dep.dependsOn.forEach((r) => { if (!componentNames.has(r))
                    errors.push(`dependencies[${idx}] unknown dependsOn ref ${r}`); });
            }
        });
    }
    return { valid: errors.length === 0, errors };
}
function validateSPDXTagValueStrict(text) {
    const base = validateSPDXTagValue(text);
    const errors = [...base.errors];
    if (!base.valid)
        return { valid: false, errors };
    // Check SPDXVersion value presence and correctness
    if (!/SPDXVersion:\s*SPDX-2\.3/.test(text))
        errors.push('SPDXVersion not 2.3');
    // DocumentNamespace should look URL-like
    if (!/DocumentNamespace:\s*https?:\/\//.test(text))
        errors.push('DocumentNamespace not URL');
    // Ensure at least one PackageChecksum if hash advertised
    if (/PackageChecksum:/.test(text) && !/PackageChecksum: SHA256: [0-9a-f]{64}/i.test(text))
        errors.push('Invalid SHA256 checksum format');
    return { valid: errors.length === 0, errors };
}
//# sourceMappingURL=sbom-validators.js.map