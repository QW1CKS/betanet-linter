/**
 * Task 21: Lint & Type Hygiene Hardening
 * Initial config favors incremental tightening: explicit any => warn (baseline inventory).
 * After Tasks 22–25 finalize evidence schemas, elevate to error and introduce per-module allowlists.
 */
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: { project: ['./tsconfig.json'], sourceType: 'module' },
  plugins: ['@typescript-eslint'],
  env: { node: true, es2022: true, jest: true },
  /**
   * Escalated for Task 21 (Lint & Type Hygiene Hardening):
   *  - Add type-aware rules (recommended-requiring-type-checking)
   *  - Promote previously warning rules to errors (except in a narrowly scoped override allow‑list)
   *  - Enforce promise handling & safer type hygiene
   */
  extends: [
    'eslint:recommended',
    'plugin:@typescript-eslint/recommended',
    'plugin:@typescript-eslint/recommended-requiring-type-checking'
  ],
  rules: {
    // Type hygiene
    '@typescript-eslint/no-explicit-any': ['error', { ignoreRestArgs: false, fixToUnknown: true }],
    '@typescript-eslint/explicit-module-boundary-types': 'error',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports', disallowTypeAnnotations: false }],
    '@typescript-eslint/ban-types': ['error', { extendDefaults: true }],
    // Promise safety
    '@typescript-eslint/no-floating-promises': 'error',
    '@typescript-eslint/no-misused-promises': ['error', { checksVoidReturn: { attributes: false } }],
    // Misc
    'no-console': ['error', { allow: ['warn', 'error'] }]
  },
  overrides: [
    {
      // Transitional dynamic interoperability zones (will be eliminated in Task 22–25 schema refinements)
      files: [
        'src/index.ts',
        'src/analyzer.ts',
        'src/safe-exec.ts',
        'src/static-parsers.ts',
        'src/sbom.ts',
        'src/sbom/sbom-validators.ts'
      ],
      rules: {
        '@typescript-eslint/no-explicit-any': 'off', // Intentional dynamic surfaces (documented for later narrowing)
        '@typescript-eslint/explicit-module-boundary-types': 'off'
      }
    }
  ],
  ignorePatterns: ['dist/', '**/node_modules/**']
};
