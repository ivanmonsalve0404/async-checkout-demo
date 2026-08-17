// eslint-disable-next-line @typescript-eslint/no-require-imports, no-undef -- Jest loads this configuration as CommonJS.
const coveragePolicy = require('../../scripts/stage6/coverage-policy.json');
const criticalThresholds = Object.fromEntries(
  coveragePolicy.api.map((path) => [path, coveragePolicy.minimum]),
);

/** @type {import('jest').Config} */
module.exports = {
  clearMocks: true,
  collectCoverageFrom: [
    'src/application/**/*.ts',
    'src/domain/**/*.ts',
    'src/infrastructure/configuration/**/*.ts',
    'src/infrastructure/logging/**/*.ts',
    'src/infrastructure/payment/**/*.ts',
    'src/infrastructure/security/**/*.ts',
    'src/infrastructure/persistence/**/*.ts',
    'src/interfaces/http/**/*.ts',
    '!src/**/*.integration.spec.ts',
    '!src/**/*.cli.ts',
  ],
  coverageDirectory: '../../coverage/api',
  coverageReporters: ['json-summary', 'text', 'lcov'],
  coveragePathIgnorePatterns: ['/node_modules/', '/dist/', 'src/interfaces/http/request.d.ts'],
  coverageThreshold: {
    global: coveragePolicy.minimum,
    ...criticalThresholds,
  },
  moduleFileExtensions: ['ts', 'js', 'json'],
  preset: 'ts-jest',
  rootDir: '.',
  testEnvironment: 'node',
  testPathIgnorePatterns: ['\\.integration\\.spec\\.ts$'],
  testRegex: '\\.spec\\.ts$',
};
