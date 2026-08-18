#!/usr/bin/env node

import { strict as assert } from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { selfTestPrereleaseCleanupRecovery } from '../stage7/prerelease-cleanup-recovery.mjs';

export const PRERELEASE_CLEANUP_WORKFLOW = 'prerelease-cleanup.yml';

const CHECKOUT_SHA = 'fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09';
const SETUP_NODE_SHA = 'a0853c24544627f65ddf259abe73b1d18a591444';
const AWS_CREDENTIALS_SHA = '61815dcd50bd041e203e49132bacad1fd04d2708';
const UPLOAD_ARTIFACT_SHA = 'ea165f8d65b6e75b540449e92b4886f43607fa02';
const EXPECTED_JOBS = ['validate-contract', 'cleanup-expired-prereleases'];
const EXPECTED_TRIGGER = `on:
  schedule:
    - cron: '23 * * * *'
  workflow_dispatch:
`;

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

const normalize = (value) => value.replace(/\r\n?/gu, '\n');

const jobIds = (source) => {
  const lines = normalize(source).split('\n');
  const jobs = lines.indexOf('jobs:');
  if (jobs === -1) return [];
  const result = [];
  for (const line of lines.slice(jobs + 1)) {
    if (line !== '' && !line.startsWith(' ')) break;
    const match = /^ {2}([a-z0-9-]+):$/u.exec(line);
    if (match !== null) result.push(match[1]);
  }
  return result;
};

const jobBlock = (source, id) => {
  const lines = normalize(source).split('\n');
  const start = lines.indexOf(`  ${id}:`);
  if (start === -1) return '';
  const end = lines.findIndex((line, index) => index > start && /^ {2}[a-z0-9-]+:$/u.test(line));
  return lines.slice(start, end === -1 ? lines.length : end).join('\n');
};

const actionReferences = (source) =>
  [...normalize(source).matchAll(/^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*(?:#.*)?$/gmu)].map(
    (match) => match[1],
  );

const exactActionReferences = (source) => {
  const expected = [
    `actions/checkout@${CHECKOUT_SHA}`,
    `actions/setup-node@${SETUP_NODE_SHA}`,
    `actions/upload-artifact@${UPLOAD_ARTIFACT_SHA}`,
    `actions/checkout@${CHECKOUT_SHA}`,
    `actions/setup-node@${SETUP_NODE_SHA}`,
    `aws-actions/configure-aws-credentials@${AWS_CREDENTIALS_SHA}`,
    `actions/upload-artifact@${UPLOAD_ARTIFACT_SHA}`,
  ];
  return JSON.stringify(actionReferences(source)) === JSON.stringify(expected);
};

const triggerBlock = (source) => {
  const normalized = normalize(source);
  const start = normalized.indexOf('on:\n');
  const end = normalized.indexOf('\npermissions:\n', start);
  return start === -1 || end === -1 ? '' : normalized.slice(start, end);
};

const includesExactlyOnce = (source, value) => source.split(value).length === 2;

export function validatePrereleaseCleanupWorkflow(name, source) {
  const normalized = normalize(source);
  const errors = [];
  if (name !== PRERELEASE_CLEANUP_WORKFLOW) errors.push('cleanup workflow filename is not exact');
  if (triggerBlock(normalized) !== EXPECTED_TRIGGER) {
    errors.push('only the fixed schedule and workflow_dispatch triggers are allowed');
  }
  if (
    !normalized.includes('permissions:\n  contents: read\n') ||
    /permissions:\s*(?:write-all|read-all)/iu.test(normalized)
  ) {
    errors.push('top-level permissions must be exactly contents: read');
  }
  if (JSON.stringify(jobIds(normalized)) !== JSON.stringify(EXPECTED_JOBS)) {
    errors.push('cleanup workflow must contain the exact ordered two-job topology');
  }
  if (/^\s*environment:/gmu.test(normalized)) {
    errors.push('cleanup recovery must not depend on a human environment approval');
  }
  if (/\$\{\{\s*secrets\./iu.test(normalized)) {
    errors.push('cleanup workflow must not consume repository secrets');
  }
  if (
    /AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)|STAGE7_AWS_(?:CLEANUP|DEPLOY|READ|ROLLBACK)_ROLE_ARN/u.test(
      normalized,
    )
  ) {
    errors.push('cleanup workflow may use only the dedicated OIDC cleanup role');
  }
  if (/continue-on-error:|pull_request_target:|\bpush:/u.test(normalized)) {
    errors.push('fail-open or unapproved triggers are forbidden');
  }
  if (!exactActionReferences(normalized))
    errors.push('all and only approved actions must be SHA-pinned');
  if (
    (normalized.match(/persist-credentials:\s*false/gu) ?? []).length !== 2 ||
    /persist-credentials:\s*true/gu.test(normalized)
  ) {
    errors.push('both checkouts must keep Git credentials disabled');
  }

  const contract = jobBlock(normalized, 'validate-contract');
  if (
    !contract.includes('    permissions:\n      contents: read\n') ||
    contract.includes('id-token: write') ||
    !contract.includes('node scripts/stage7/prerelease-cleanup-recovery.mjs self-test') ||
    !contract.includes(
      'node scripts/security/validate-prerelease-cleanup-workflow.mjs --self-test',
    ) ||
    !contract.includes(
      'node scripts/security/validate-prerelease-cleanup-workflow.mjs --evidence "${STAGE7_CLEANUP_CONTRACT_EVIDENCE}"',
    )
  ) {
    errors.push('the zero-AWS contract/self-test gate is incomplete');
  }

  const cleanup = jobBlock(normalized, 'cleanup-expired-prereleases');
  if (
    !cleanup.includes('    needs: validate-contract\n') ||
    !cleanup.includes('      contents: read\n      id-token: write\n') ||
    !cleanup.includes('role-to-assume: ${{ vars.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN }}') ||
    !cleanup.includes('role-duration-seconds: 3600') ||
    !cleanup.includes('          allowed-account-ids: ${{ vars.STAGE7_AWS_ACCOUNT_ID }}') ||
    !cleanup.includes('aws-region: ${{ vars.STAGE7_AWS_REGION }}')
  ) {
    errors.push('the dedicated bounded OIDC cleanup session is incomplete');
  }
  if (
    !cleanup.includes('test "${GITHUB_REPOSITORY}" = \'ivanmonsalve0404/async-checkout-demo\'') ||
    !cleanup.includes('test "${GITHUB_REF}" = \'refs/heads/master\'') ||
    !cleanup.includes('[[ "${STAGE7_AWS_ACCOUNT_ID}" =~ ^[0-9]{12}$ ]]') ||
    !cleanup.includes('test -n "${STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN}"') ||
    !normalized.includes(
      'STAGE7_PRERELEASE_CLEANUP_OIDC_SUBJECT: repo:ivanmonsalve0404/async-checkout-demo:ref:refs/heads/master',
    )
  ) {
    errors.push('repository, branch, account, region and role guards are incomplete');
  }
  const commandTokens = [
    'node scripts/stage7/prerelease-cleanup-recovery.mjs run',
    '--execute',
    '--account "${STAGE7_AWS_ACCOUNT_ID}"',
    '--region "${STAGE7_AWS_REGION}"',
    '--role-arn "${STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN}"',
    '--evidence "${STAGE7_CLEANUP_EVIDENCE}"',
    "STAGE7_CLEANUP_OIDC: 'true'",
  ];
  if (commandTokens.some((token) => !cleanup.includes(token))) {
    errors.push('the fail-closed recovery execution command is incomplete');
  }
  if (/\baws\s+(?:cloudformation|iam|resourcegroupstaggingapi|sts)\b/u.test(cleanup)) {
    errors.push('direct AWS commands outside the reviewed recovery script are forbidden');
  }
  if (
    !includesExactlyOnce(normalized, 'concurrency:\n  group: stage7-prerelease-expiry-cleanup') ||
    !normalized.includes('  cancel-in-progress: false\n')
  ) {
    errors.push('cleanup concurrency lock is missing or ambiguous');
  }
  if (
    !normalized.includes('        if: ${{ always() }}\n') ||
    !normalized.includes('          if-no-files-found: error\n') ||
    !normalized.includes('          retention-days: 30\n')
  ) {
    errors.push('sanitized cleanup evidence must be retained even on failure');
  }
  return errors;
}

const replaceOnce = (source, before, after) => {
  assert.ok(source.includes(before), `self-test fixture is missing: ${before}`);
  return source.replace(before, after);
};

const workflowCanaries = (source) => {
  assert.deepEqual(validatePrereleaseCleanupWorkflow(PRERELEASE_CLEANUP_WORKFLOW, source), []);
  const cases = [
    {
      label: 'schedule',
      value: replaceOnce(source, "    - cron: '23 * * * *'", "    - cron: '*/5 * * * *'"),
    },
    {
      label: 'push trigger',
      value: replaceOnce(source, '  workflow_dispatch:', '  push:\n  workflow_dispatch:'),
    },
    {
      label: 'job topology',
      value: replaceOnce(source, '  cleanup-expired-prereleases:', '  cleanup-copy:'),
    },
    {
      label: 'OIDC permission',
      value: replaceOnce(source, '      id-token: write', '      id-token: read'),
    },
    {
      label: 'contract dependency',
      value: replaceOnce(source, '    needs: validate-contract\n', ''),
    },
    {
      label: 'wrong role',
      value: replaceOnce(
        source,
        '${{ vars.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN }}',
        '${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}',
      ),
    },
    {
      label: 'operational cleanup role reuse',
      value: source.replaceAll(
        'STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN',
        'STAGE7_AWS_CLEANUP_ROLE_ARN',
      ),
    },
    {
      label: 'OIDC environment subject',
      value: replaceOnce(
        source,
        'repo:ivanmonsalve0404/async-checkout-demo:ref:refs/heads/master',
        'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-prerelease',
      ),
    },
    {
      label: 'session duration',
      value: replaceOnce(source, 'role-duration-seconds: 3600', 'role-duration-seconds: 43200'),
    },
    {
      label: 'execute guard',
      value: replaceOnce(source, '        --execute \\', '        --dry-run \\'),
    },
    {
      label: 'OIDC runtime binding',
      value: replaceOnce(
        source,
        "          STAGE7_CLEANUP_OIDC: 'true'",
        "          STAGE7_CLEANUP_OIDC: 'false'",
      ),
    },
    {
      label: 'failure evidence',
      value: replaceOnce(source, '        if: ${{ always() }}', '        if: ${{ success() }}'),
    },
    {
      label: 'account allowlist',
      value: replaceOnce(
        source,
        '          allowed-account-ids:',
        '          # allowed-account-ids:',
      ),
    },
    {
      label: 'checkout credentials',
      value: replaceOnce(
        source,
        '          persist-credentials: false',
        '          persist-credentials: true',
      ),
    },
    {
      label: 'human environment',
      value: replaceOnce(
        source,
        '    runs-on: ubuntu-24.04',
        '    environment: cleanup\n    runs-on: ubuntu-24.04',
      ),
    },
    {
      label: 'direct AWS command',
      value: `${source}\n# aws cloudformation delete-stack --stack-name unsafe\n`,
    },
  ];
  for (const testCase of cases) {
    assert.ok(
      validatePrereleaseCleanupWorkflow(PRERELEASE_CLEANUP_WORKFLOW, testCase.value).length > 0,
      `cleanup workflow mutation was accepted: ${testCase.label}`,
    );
  }
  return cases.length;
};

const writeContractEvidence = (root, target, workflow, runtime, validator) => {
  const evidenceRoot = path.resolve(
    root,
    'output',
    'evidence',
    'runtime',
    'stage-7-prerelease-cleanup',
  );
  const resolved = path.resolve(root, target);
  if (
    resolved === evidenceRoot ||
    !resolved.startsWith(`${evidenceRoot}${path.sep}`) ||
    !resolved.endsWith('.json')
  ) {
    throw new Error('cleanup contract evidence path is invalid');
  }
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  fs.writeFileSync(
    resolved,
    `${JSON.stringify(
      {
        schemaVersion: 1,
        stage: 7,
        kind: 'expired-prerelease-cleanup-contract',
        generatedAtUtc: new Date().toISOString(),
        status: 'PASS',
        contractDecision: 'PASS',
        durableRecoveryReady: false,
        runtimeVerification: 'NOT_RUN',
        workflowSha256: sha256(workflow),
        recoveryScriptSha256: sha256(runtime),
        validatorSha256: sha256(validator),
        selfTestAwsCalls: 0,
        containsSensitiveData: false,
      },
      null,
      2,
    )}\n`,
    { encoding: 'utf8', flag: 'wx', mode: 0o600 },
  );
};

const repositoryFiles = () => {
  const root = path.resolve(process.cwd());
  return {
    root,
    runtimePath: path.join(root, 'scripts', 'stage7', 'prerelease-cleanup-recovery.mjs'),
    validatorPath: fileURLToPath(import.meta.url),
    workflowPath: path.join(root, '.github', 'workflows', PRERELEASE_CLEANUP_WORKFLOW),
  };
};

const main = () => {
  const files = repositoryFiles();
  const workflow = fs.readFileSync(files.workflowPath, 'utf8');
  const runtime = fs.readFileSync(files.runtimePath, 'utf8');
  const validator = fs.readFileSync(files.validatorPath, 'utf8');
  if (process.argv.includes('--self-test')) {
    if (process.argv.length !== 3) throw new Error('cleanup validator argument set is invalid');
    const workflowCount = workflowCanaries(workflow);
    const runtimeCount = selfTestPrereleaseCleanupRecovery();
    process.stdout.write(
      `prerelease cleanup workflow self-test: PASS (${workflowCount + runtimeCount} canaries; 0 AWS calls)\n`,
    );
    return;
  }
  const args = process.argv.slice(2);
  if (args.length !== 0 && (args.length !== 2 || args[0] !== '--evidence')) {
    throw new Error('cleanup validator argument set is invalid');
  }
  const errors = validatePrereleaseCleanupWorkflow(PRERELEASE_CLEANUP_WORKFLOW, workflow);
  selfTestPrereleaseCleanupRecovery();
  if (errors.length > 0) {
    process.stderr.write('prerelease cleanup workflow policy: FAIL\n');
    for (const error of errors) process.stderr.write(`${error}\n`);
    process.exitCode = 1;
    return;
  }
  if (args.length === 2) {
    writeContractEvidence(files.root, args[1], workflow, runtime, validator);
  }
  process.stdout.write('prerelease cleanup workflow policy: PASS (runtime NOT_RUN; 0 AWS calls)\n');
};

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    main();
  } catch (error) {
    const reason = error instanceof Error ? error.message : 'unexpected validator failure';
    process.stderr.write(`prerelease cleanup workflow policy: FAIL (${reason})\n`);
    process.exitCode = 1;
  }
}
