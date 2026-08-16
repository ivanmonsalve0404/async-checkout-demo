/** @type {import('jest').Config} */
module.exports = {
  clearMocks: true,
  moduleFileExtensions: ['ts', 'js', 'json'],
  preset: 'ts-jest',
  rootDir: '.',
  testEnvironment: 'node',
  testMatch: ['<rootDir>/src/infrastructure/persistence/dynamodb-checkout.integration.spec.ts'],
  testTimeout: 120_000,
};
