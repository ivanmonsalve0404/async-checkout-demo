#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { existsSync, readFileSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import process from 'node:process';

import { writeSanitizedJsonAtomic } from '../stage6/lib/artifact-sanitizer.mjs';

const application = process.argv[2];
if (application !== 'api' && application !== 'web') {
  throw new Error('Expected exactly one application: api or web');
}

const workspaceRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const applicationRoot = resolve(workspaceRoot, 'apps', application);
const requireFromApplication = createRequire(join(applicationRoot, 'package.json'));
const jestPackage = requireFromApplication.resolve('jest/package.json');
const jestBinary = join(dirname(jestPackage), 'bin', 'jest.js');
const reporterPath = resolve(workspaceRoot, 'scripts', 'evidence', 'sanitized-jest-reporter.cjs');
const evidencePath = resolve(
  workspaceRoot,
  'output',
  'evidence',
  'runtime',
  `${application}-tests.json`,
);
rmSync(evidencePath, { force: true });

const result = spawnSync(
  process.execPath,
  [
    jestBinary,
    '--config',
    'jest.config.cjs',
    '--coverage',
    '--runInBand',
    '--reporters=default',
    `--reporters=${reporterPath}`,
  ],
  { cwd: applicationRoot, encoding: 'utf8', windowsHide: true },
);
if (result.stdout) process.stdout.write(result.stdout);
if (result.stderr) process.stderr.write(result.stderr);

if (!existsSync(evidencePath)) {
  throw new Error(`Sanitized Jest reporter did not create ${evidencePath}`);
}
const evidence = JSON.parse(readFileSync(evidencePath, 'utf8'));
const validEvidence =
  evidence.schemaVersion === 1 &&
  evidence.application === application &&
  evidence.containsTestPayloads === false &&
  Number.isSafeInteger(evidence.suites) &&
  Number.isSafeInteger(evidence.tests);
if (!validEvidence) {
  throw new Error('Sanitized Jest reporter produced invalid evidence');
}

const status = result.status === 0 && evidence.status === 'PASS' ? 'PASS' : 'FAIL';
if (evidence.status !== status) {
  await writeSanitizedJsonAtomic(evidencePath, `${application}-tests.json`, {
    ...evidence,
    status,
  });
}
process.exitCode = status === 'PASS' ? 0 : 1;
