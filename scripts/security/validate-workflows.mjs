#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ACTION_REFERENCE = /^\s*uses:\s*([^\s#]+)\s*(?:#.*)?$/gmu;
const PINNED_SHA = /^[0-9a-f]{40}$/u;

export function validateWorkflow(name, source) {
  const errors = [];

  if (!/^\s{0}permissions:\s*\r?\n\s{2}contents:\s*read\s*$/gmu.test(source)) {
    errors.push('top-level permissions must be exactly contents: read');
  }
  if (!/\bpull_request\s*:/u.test(source)) {
    errors.push('pull_request trigger is required');
  }
  if (/\bpull_request_target\s*:/u.test(source)) {
    errors.push('pull_request_target is forbidden');
  }
  if (/\b(?:id-token|contents|packages|pull-requests):\s*write\b/iu.test(source)) {
    errors.push('write permissions are forbidden');
  }
  if (/\bwrite-all\b/iu.test(source)) {
    errors.push('write-all is forbidden');
  }
  if (/\$\{\{\s*secrets\./iu.test(source)) {
    errors.push('secret contexts are forbidden in PR workflows');
  }
  if (/aws-actions\/configure-aws-credentials/iu.test(source)) {
    errors.push('AWS credential actions are forbidden');
  }
  if (/\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)\b/u.test(source)) {
    errors.push('AWS credential environment variables are forbidden');
  }
  if (
    /\b(?:cdk|aws)\s+(?:bootstrap|cloudformation|deploy|destroy|dynamodb|lambda|s3)\b/iu.test(
      source,
    )
  ) {
    errors.push('cloud mutation commands are forbidden');
  }
  if (!/cancel-in-progress:\s*true\b/iu.test(source)) {
    errors.push('concurrency cancellation is required');
  }

  const runnerCount = (source.match(/^\s+runs-on:/gmu) ?? []).length;
  const timeoutCount = (source.match(/^\s+timeout-minutes:/gmu) ?? []).length;
  if (runnerCount === 0 || runnerCount !== timeoutCount) {
    errors.push('every job must define timeout-minutes');
  }

  ACTION_REFERENCE.lastIndex = 0;
  for (const match of source.matchAll(ACTION_REFERENCE)) {
    const reference = match[1];
    if (reference.startsWith('./')) {
      continue;
    }
    const separator = reference.lastIndexOf('@');
    const revision = separator === -1 ? '' : reference.slice(separator + 1);
    if (!PINNED_SHA.test(revision)) {
      errors.push('action must be pinned to a full SHA: ' + reference);
    }
  }

  return errors.map((error) => name + ': ' + error);
}

function selfTest() {
  const valid = [
    'name: Test',
    'on:',
    '  pull_request:',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  cancel-in-progress: true',
    'jobs:',
    '  check:',
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 5',
    '    steps:',
    '      - uses: actions/checkout@0123456789abcdef0123456789abcdef01234567',
  ].join('\n');
  assert.deepEqual(validateWorkflow('valid.yml', valid), []);
  assert.ok(
    validateWorkflow(
      'invalid.yml',
      valid
        .replace('pull_request:', 'pull_request_target:')
        .replace('0123456789abcdef0123456789abcdef01234567', 'v4'),
    ).length >= 2,
  );
  process.stdout.write('workflow-policy self-test: PASS\n');
}

function main() {
  if (process.argv.includes('--self-test')) {
    selfTest();
    return;
  }

  const rootDirectory = path.resolve(process.cwd());
  const workflowDirectory = path.join(rootDirectory, '.github', 'workflows');
  if (!fs.existsSync(workflowDirectory)) {
    throw new Error('.github/workflows is required');
  }

  const workflowFiles = fs
    .readdirSync(workflowDirectory)
    .filter((name) => /\.ya?ml$/iu.test(name))
    .sort();
  if (workflowFiles.length === 0) {
    throw new Error('at least one workflow is required');
  }

  const errors = workflowFiles.flatMap((name) =>
    validateWorkflow(name, fs.readFileSync(path.join(workflowDirectory, name), 'utf8')),
  );
  if (errors.length > 0) {
    process.stderr.write('workflow-policy: FAIL\n');
    for (const error of errors) {
      process.stderr.write(error + '\n');
    }
    process.exitCode = 1;
    return;
  }

  process.stdout.write('workflow-policy: PASS (' + workflowFiles.length + ' workflow(s))\n');
}

main();
