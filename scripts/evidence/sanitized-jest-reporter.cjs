/* eslint-disable @typescript-eslint/no-require-imports, no-undef -- Jest loads custom reporters through CommonJS. */
const { mkdirSync, renameSync, writeFileSync } = require('node:fs');
const { basename, dirname, resolve } = require('node:path');

class SanitizedJestReporter {
  onRunComplete(_contexts, results) {
    const application = basename(process.cwd());
    if (application !== 'api' && application !== 'web') {
      throw new Error('Sanitized Jest evidence is restricted to api or web');
    }
    const evidencePath = resolve(
      process.cwd(),
      '../..',
      'output',
      'evidence',
      'runtime',
      `${application}-tests.json`,
    );
    const evidence = {
      schemaVersion: 1,
      status:
        results.numFailedTestSuites === 0 &&
        results.numFailedTests === 0 &&
        results.wasInterrupted !== true
          ? 'PASS'
          : 'FAIL',
      application,
      suites: results.numTotalTestSuites,
      passedSuites: results.numPassedTestSuites,
      failedSuites: results.numFailedTestSuites,
      tests: results.numTotalTests,
      passedTests: results.numPassedTests,
      failedTests: results.numFailedTests,
      pendingTests: results.numPendingTests,
      containsTestPayloads: false,
    };
    mkdirSync(dirname(evidencePath), { recursive: true });
    const temporaryEvidence = `${evidencePath}.${process.pid}.tmp`;
    writeFileSync(temporaryEvidence, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
    renameSync(temporaryEvidence, evidencePath);
  }
}

module.exports = SanitizedJestReporter;
