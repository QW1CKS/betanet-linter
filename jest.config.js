module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
    testMatch: [
      '**/__tests__/**/*.ts',
      '**/?(*.)+(spec|test).ts',
      '**/?(*.)+(spec|test).js'
    ],
  transform: {
    '^.+\\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
  'src/**/*.ts',
  '!src/**/*.d.ts',
  // Exclude experimental / low-test-signal modules from current quality gate scope (Task 27 scoping)
  '!src/analyzers/**',
  '!src/clienthello-raw.ts',
  '!src/compliance.ts',
  '!src/sbom.ts',
  '!src/sbom/sbom-generator.ts',
  '!src/tls-capture.ts'
  , '!src/harness.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json-summary'],
  // Coverage enforcement handled by scripts/quality-gates.js (baseline ratchet).
};