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
    global: { branches: 85, functions: 85, lines: 85, statements: 85 },
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
