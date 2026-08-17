#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { scanArtifactText } from './lib/artifact-sanitizer.mjs';

export const UPLOAD_ENTRIES = Object.freeze([
  'coverage/api/coverage-summary.json',
  'coverage/web/coverage-summary.json',
  'infra/cdk.out/*.template.json',
  'output/evidence/runtime/stage-5-dynamodb-integration.json',
  'output/evidence/runtime/stage-5-smoke-results.json',
  'output/evidence/runtime/stage-6/',
]);

const ensureDirectory = (directory) => {
  if (!existsSync(directory)) return false;
  if (!lstatSync(directory).isDirectory()) throw new Error('UPLOAD_ARTIFACT_SCAN_SCOPE_INVALID');
  return true;
};

const existingFile = (file) => {
  if (!existsSync(file)) return [];
  if (!lstatSync(file).isFile()) throw new Error('UPLOAD_ARTIFACT_SCAN_SCOPE_INVALID');
  return [file];
};

const recursiveFiles = (directory) => {
  if (!ensureDirectory(directory)) return [];
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const target = path.join(directory, entry.name);
    if (entry.isDirectory()) return recursiveFiles(target);
    if (entry.isFile()) return [target];
    throw new Error('UPLOAD_ARTIFACT_SCAN_SCOPE_INVALID');
  });
};

export const collectUploadFiles = (root) => {
  const cdkDirectory = path.join(root, 'infra', 'cdk.out');
  const templates = ensureDirectory(cdkDirectory)
    ? readdirSync(cdkDirectory, { withFileTypes: true })
        .filter((entry) => entry.name.endsWith('.template.json'))
        .map((entry) => {
          if (!entry.isFile()) throw new Error('UPLOAD_ARTIFACT_SCAN_SCOPE_INVALID');
          return path.join(cdkDirectory, entry.name);
        })
    : [];
  return [
    ...existingFile(path.join(root, 'coverage', 'api', 'coverage-summary.json')),
    ...existingFile(path.join(root, 'coverage', 'web', 'coverage-summary.json')),
    ...templates,
    ...existingFile(
      path.join(root, 'output', 'evidence', 'runtime', 'stage-5-dynamodb-integration.json'),
    ),
    ...existingFile(path.join(root, 'output', 'evidence', 'runtime', 'stage-5-smoke-results.json')),
    ...recursiveFiles(path.join(root, 'output', 'evidence', 'runtime', 'stage-6')),
  ].sort((left, right) => left.localeCompare(right));
};

export const scanUploadArtifacts = (root) => {
  const files = collectUploadFiles(root);
  const findings = files.reduce(
    (count, file) =>
      count +
      scanArtifactText(path.relative(root, file).replaceAll('\\', '/'), readFileSync(file, 'utf8'))
        .length,
    0,
  );
  return { filesScanned: files.length, findings };
};

const selfTest = () => {
  assert.deepEqual(UPLOAD_ENTRIES, [
    'coverage/api/coverage-summary.json',
    'coverage/web/coverage-summary.json',
    'infra/cdk.out/*.template.json',
    'output/evidence/runtime/stage-5-dynamodb-integration.json',
    'output/evidence/runtime/stage-5-smoke-results.json',
    'output/evidence/runtime/stage-6/',
  ]);
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'checkout-e6-upload-scan-'));
  try {
    const safeFiles = [
      'coverage/api/coverage-summary.json',
      'coverage/web/coverage-summary.json',
      'infra/cdk.out/application.template.json',
      'output/evidence/runtime/stage-5-dynamodb-integration.json',
      'output/evidence/runtime/stage-5-smoke-results.json',
      'output/evidence/runtime/stage-6/nested/report.json',
    ];
    for (const relative of safeFiles) {
      const target = path.join(temporary, relative);
      mkdirSync(path.dirname(target), { recursive: true });
      writeFileSync(target, '{"status":"PASS","containsSensitiveData":false}\n', 'utf8');
    }
    assert.deepEqual(scanUploadArtifacts(temporary), { filesScanned: 6, findings: 0 });

    const unsafeTarget = path.join(
      temporary,
      'output',
      'evidence',
      'runtime',
      'stage-6',
      'nested',
      'unsafe.json',
    );
    writeFileSync(
      unsafeTarget,
      JSON.stringify({ paymentMethodToken: ['actual', 'token', 'value'].join('-') }),
      'utf8',
    );
    const unsafe = scanUploadArtifacts(temporary);
    assert.equal(unsafe.filesScanned, 7);
    assert.ok(unsafe.findings > 0);
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
};

const main = () => {
  selfTest();
  const result = scanUploadArtifacts(process.cwd());
  if (result.findings > 0) {
    process.stderr.write(
      `stage-6 upload artifact scan: FAIL (${result.findings} finding(s), ${result.filesScanned} file(s))\n`,
    );
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`stage-6 upload artifact scan: PASS (${result.filesScanned} file(s))\n`);
};

const executedDirectly =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (executedDirectly) {
  if (process.argv.includes('--self-test')) {
    selfTest();
    process.stdout.write('stage-6 upload artifact scan self-test: PASS\n');
  } else {
    main();
  }
}
