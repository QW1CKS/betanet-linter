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
  extends: [ 'eslint:recommended', 'plugin:@typescript-eslint/recommended' ],
  rules: {
    '@typescript-eslint/no-explicit-any': ['warn', { ignoreRestArgs: false }],
    '@typescript-eslint/explicit-module-boundary-types': 'warn',
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_' }],
    'no-console': ['warn', { allow: ['warn', 'error'] }]
  },
  ignorePatterns: ['dist/', '**/node_modules/**']
};
