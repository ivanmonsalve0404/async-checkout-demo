// eslint-disable-next-line @typescript-eslint/no-require-imports, no-undef -- Jest loads this configuration as CommonJS.
const coveragePolicy = require('../../scripts/stage6/coverage-policy.json');
const criticalThresholds = Object.fromEntries(
  coveragePolicy.web.map((path) => [path, coveragePolicy.minimum]),
);

/** @type {import('jest').Config} */
module.exports = {
  clearMocks: true,
  collectCoverageFrom: [
    'src/app/**/*.ts',
    'src/app/**/*.tsx',
    'src/features/**/*.ts',
    'src/features/**/*.tsx',
    'src/shared/**/*.ts',
    'src/shared/**/*.tsx',
    '!src/main.tsx',
  ],
  coverageDirectory: '../../coverage/web',
  coverageReporters: ['json-summary', 'text', 'lcov'],
  coverageThreshold: {
    global: coveragePolicy.minimum,
    ...criticalThresholds,
  },
  moduleFileExtensions: ['ts', 'tsx', 'js'],
  preset: 'ts-jest',
  setupFilesAfterEnv: ['<rootDir>/src/shared/testing/setup-tests.ts'],
  testEnvironment: 'jsdom',
  testRegex: '\\.spec\\.tsx?$',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: '<rootDir>/tsconfig.json' }],
  },
};
