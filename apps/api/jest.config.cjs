/** @type {import('jest').Config} */
module.exports = {
  clearMocks: true,
  collectCoverageFrom: [
    'src/application/**/*.ts',
    'src/domain/**/*.ts',
    'src/infrastructure/configuration/**/*.ts',
    'src/infrastructure/logging/**/*.ts',
    'src/infrastructure/persistence/**/*.ts',
    'src/interfaces/http/**/*.ts',
    '!src/**/*.cli.ts',
  ],
  coverageDirectory: '../../coverage/api',
  coveragePathIgnorePatterns: ['/node_modules/', '/dist/', 'src/interfaces/http/request.d.ts'],
  coverageThreshold: {
    global: { branches: 85, functions: 85, lines: 85, statements: 85 },
  },
  moduleFileExtensions: ['ts', 'js', 'json'],
  preset: 'ts-jest',
  rootDir: '.',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/src/**/*.spec.ts'],
};
