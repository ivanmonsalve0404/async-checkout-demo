/* eslint-disable @typescript-eslint/no-require-imports, no-undef -- Jest loads custom reporters through CommonJS. */
const { basename, resolve } = require('node:path');
const { pathToFileURL } = require('node:url');

const sanitizerModuleUrl = pathToFileURL(
  resolve(__dirname, '..', 'stage6', 'lib', 'artifact-sanitizer.mjs'),
).href;
let sanitizerModulePromise;
const sanitizerModule = () => {
  sanitizerModulePromise ??= import(sanitizerModuleUrl);
  return sanitizerModulePromise;
};

class SanitizedJestReporter {
  async onRunComplete(_contexts, results) {
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
    const { writeSanitizedJsonAtomic } = await sanitizerModule();
    await writeSanitizedJsonAtomic(evidencePath, `${application}-tests.json`, evidence);
  }
}

module.exports = SanitizedJestReporter;

if (require.main === module && process.argv.includes('--self-test')) {
  sanitizerModule()
    .then(({ selfTestArtifactSanitizer }) => {
      selfTestArtifactSanitizer();
      process.stdout.write('sanitized Jest reporter bridge self-test: PASS\n');
    })
    .catch(() => {
      process.stderr.write('sanitized Jest reporter bridge self-test: FAIL\n');
      process.exitCode = 1;
    });
}
