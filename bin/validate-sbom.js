const fs = require('fs-extra');
const path = require('path');
const { BetanetComplianceChecker } = require('../dist/index');
const { validateCycloneDXShape, validateSPDXTagValue, validateCycloneDXStrict, validateSPDXTagValueStrict } = require('../dist/sbom/sbom-validators');

module.exports = async function validateSBOM(binaryPath, sbomPath, format, strict) {
  try {
    if (format === 'cyclonedx' || format === 'cyclonedx-json') {
      let jsonDoc;
      if (format === 'cyclonedx-json') {
        jsonDoc = JSON.parse(await fs.readFile(sbomPath, 'utf8'));
      } else {
        const checker = new BetanetComplianceChecker();
        const tmpJson = path.join(path.dirname(sbomPath), path.basename(sbomPath) + '.validate.cdx.json');
        await checker.generateSBOM(binaryPath, 'cyclonedx-json', tmpJson);
        jsonDoc = JSON.parse(await fs.readFile(tmpJson, 'utf8'));
        await fs.remove(tmpJson);
      }
      const base = validateCycloneDXShape(jsonDoc);
      if (!base.valid) {
        console.warn('⚠️  CycloneDX shape validation warnings:', base.errors.join(', '));
        if (strict) {
          console.error('❌ SBOM failed strict validation (base shape).');
          process.exit(2);
        } else {
          // Non-strict shape failure => exit code 3 (warning)
          process.exit(3);
        }
      }
      if (strict) {
        const strictRes = validateCycloneDXStrict(jsonDoc);
        if (!strictRes.valid) {
          console.error('❌ CycloneDX strict validation errors:', strictRes.errors.join(', '));
          process.exit(2);
        } else {
          console.log('✅ CycloneDX strict validation passed.');
        }
      } else {
        console.log('✅ CycloneDX shape validation passed.');
      }
    } else if (format === 'spdx') {
      const text = await fs.readFile(sbomPath, 'utf8');
      const base = validateSPDXTagValue(text);
      if (!base.valid) {
        console.warn('⚠️  SPDX shape validation warnings:', base.errors.join(', '));
        if (strict) {
          console.error('❌ SBOM failed strict validation (base shape).');
          process.exit(2);
        } else {
          process.exit(3);
        }
      }
      if (strict) {
        const strictRes = validateSPDXTagValueStrict(text);
        if (!strictRes.valid) {
          console.error('❌ SPDX strict validation errors:', strictRes.errors.join(', '));
          process.exit(2);
        } else {
          console.log('✅ SPDX strict validation passed.');
        }
      } else {
        console.log('✅ SPDX shape validation passed.');
      }
    }
  } catch (e) {
    console.error('❌ SBOM validation error:', e.message);
    if (strict) process.exit(2);
  }
};
