#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const RELEASE_WORKFLOW = 'release.yml';
const PRERELEASE_WORKFLOW = 'prerelease.yml';
const ROLLBACK_RESILIENCE_WORKFLOW = './.github/workflows/stage7-rollback-resilience.yml';

const RELEASE_JOBS = [
  'release-metadata',
  'verify-candidate',
  'build-or-fetch',
  'checksums-sbom',
  'secret-scan',
  'aws-auth',
  'infra-synth-test',
  'infra-diff',
  'approval',
  'deploy-data',
  'deploy-api',
  'deploy-observability',
  'deploy-web',
  'postdeploy-smoke',
  'edge-security',
  'quality',
  'sandbox-smoke',
  'emergency-recovery',
  'release-reconciliation-intent',
  'rollback-check',
  'rollback-resilience',
  'release-reconciliation',
  'release-successor-fence',
  'publish-release',
  'summary',
];

const PRERELEASE_JOBS = [
  'prerelease-metadata',
  'verify-candidate',
  'build-once',
  'integrity-security',
  'infra-synth-test',
  'infra-diff',
  'approval',
  'prerelease-safety-readiness',
  'deploy-prerelease',
  'external-verification',
  'external-evidence',
  'cleanup',
  'summary',
];

const sequentialNeeds = (jobs) =>
  new Map(
    jobs.map((job, index) => [
      job,
      index === 0 ? [] : index === jobs.length - 1 ? jobs.slice(0, -1) : [jobs[index - 1]],
    ]),
  );
const RELEASE_NEEDS = sequentialNeeds(RELEASE_JOBS);
const PRERELEASE_NEEDS = sequentialNeeds(PRERELEASE_JOBS);
RELEASE_NEEDS.set('rollback-check', [
  'release-reconciliation-intent',
  'emergency-recovery',
  'postdeploy-smoke',
  'edge-security',
  'quality',
  'sandbox-smoke',
]);
RELEASE_NEEDS.set('release-reconciliation-intent', ['emergency-recovery']);
RELEASE_NEEDS.set('release-reconciliation', [
  'release-reconciliation-intent',
  'rollback-check',
  'rollback-resilience',
]);
RELEASE_NEEDS.set('infra-diff', ['infra-synth-test', 'aws-auth']);
RELEASE_NEEDS.set('emergency-recovery', [
  'postdeploy-smoke',
  'edge-security',
  'quality',
  'sandbox-smoke',
]);
PRERELEASE_NEEDS.set('cleanup', [
  'approval',
  'deploy-prerelease',
  'external-verification',
  'external-evidence',
]);

const ACTIONS = new Set([
  'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',
  'actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444',
  'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
  'actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0',
  'aws-actions/configure-aws-credentials@61815dcd50bd041e203e49132bacad1fd04d2708',
]);
const PINNED_ACTION = /^[a-z0-9_.-]+\/[a-z0-9_.-]+@[0-9a-f]{40}$/u;
const ACTION_REFERENCE = /^\s*(?:-\s*)?uses:\s*([^\s#]+)\s*(?:#.*)?$/gmu;

const RELEASE_AWS = new Map([
  ['build-or-fetch', ['${{ vars.STAGE7_AWS_READ_ROLE_ARN }}', '--pre-freeze-synth']],
  ['aws-auth', ['${{ vars.STAGE7_AWS_READ_ROLE_ARN }}', '--aws-read']],
  ['infra-diff', ['${{ vars.STAGE7_AWS_READ_ROLE_ARN }}', '--aws-read']],
  ['deploy-data', ['${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}', '--aws-deploy']],
  ['deploy-api', ['${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}', '--aws-deploy']],
  ['deploy-observability', ['${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}', '--aws-deploy']],
  ['deploy-web', ['${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}', '--aws-deploy']],
  ['postdeploy-smoke', ['${{ vars.STAGE7_AWS_READ_ROLE_ARN }}', '--aws-read']],
  ['edge-security', ['${{ vars.STAGE7_AWS_READ_ROLE_ARN }}', '--aws-read']],
  ['sandbox-smoke', ['${{ vars.STAGE7_AWS_READ_ROLE_ARN }}', '--sandbox-authorized']],
  ['emergency-recovery', ['${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}', '--aws-rollback']],
  [
    'release-reconciliation-intent',
    ['${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}', 'open-journal'],
  ],
  ['rollback-check', ['${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}', '--aws-rollback']],
  [
    'release-reconciliation',
    ['${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}', 'probe-terminal'],
  ],
  [
    'release-successor-fence',
    ['${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}', 'fence-release'],
  ],
]);
const PRERELEASE_AWS = new Map([
  ['infra-diff', ['${{ vars.STAGE7_PRERELEASE_AWS_READ_ROLE_ARN }}', '--aws-read']],
  [
    'prerelease-safety-readiness',
    ['${{ vars.STAGE7_PRERELEASE_AWS_READ_ROLE_ARN }}', 'release:prerelease-safety -- capture'],
  ],
  ['deploy-prerelease', ['${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}', '--aws-deploy']],
  ['external-verification', ['${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}', '--aws-deploy']],
  ['cleanup', ['${{ vars.STAGE7_PRERELEASE_AWS_CLEANUP_ROLE_ARN }}', '--aws-cleanup']],
]);

const configFragments = (variableName) => [
  'EXPECTED_STAGE7_CONFIG_SHA256: ${{ inputs.config_sha256 }}',
  'STAGE7_CONFIG_B64: ${{ vars.' + variableName + ' }}',
  'test -n "${STAGE7_CONFIG_B64}"',
  '[[ "${EXPECTED_STAGE7_CONFIG_SHA256}" =~ ^[0-9a-f]{64}$ ]]',
  'umask 077',
  'target="${RUNNER_TEMP}/stage7-config.json"',
  'printf \'%s\' "${STAGE7_CONFIG_B64}" | base64 --decode > "${target}"',
  'chmod 600 "${target}"',
  'test "$(stat -c \'%a\' "${target}")" = \'600\'',
  'actual="$(sha256sum "${target}" | cut -d \' \' -f 1)"',
  'test "${actual}" = "${EXPECTED_STAGE7_CONFIG_SHA256}"',
  'node scripts/stage7/cli.mjs config --config "${target}" > /dev/null',
  'printf \'STAGE7_CONFIG=%s\\n\' "${target}" >> "${GITHUB_ENV}"',
];
const STAGE6_DOWNLOAD_FRAGMENTS = [
  'uses: actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0',
  'name: verification-reports',
  'path: .stage7/stage6',
  'github-token: ${{ github.token }}',
  'run-id: ${{ inputs.stage6_run_id }}',
];
const CANONICAL_BUILD_PATHS = [
  'output/release/build/api/',
  'output/release/build/worker/',
  'output/release/build/web/',
  'output/release/build/iac/',
  'output/release/build/public-config.json',
];
const SANDBOX_SECRET_NAMES = [
  'STAGE6_SANDBOX_CARD_CVC',
  'STAGE6_SANDBOX_CARD_EXPIRY',
  'STAGE6_SANDBOX_CARD_HOLDER',
  'STAGE6_SANDBOX_CARD_NUMBER',
  'STAGE6_SANDBOX_CUSTOMER_EMAIL',
  'STAGE6_SANDBOX_INTEGRITY_SECRET',
  'STAGE6_SANDBOX_PRIVATE_KEY',
  'STAGE6_SANDBOX_PUBLIC_KEY',
];
const PRERELEASE_ACCESS_SECRET_NAMES = [
  'STAGE7_CLOUDFRONT_EXPIRED_SIGNED_COOKIE_B64',
  'STAGE7_CLOUDFRONT_SIGNED_COOKIE_B64',
];

const REQUIRED_WORKFLOW_SCRIPT_MAPPINGS = new Map([
  [
    'build',
    'pnpm --filter @checkout/contracts build && pnpm --filter @checkout/api build && pnpm --filter @checkout/web build',
  ],
  ['infra:test', 'pnpm --filter @checkout/infra test'],
  ['infra:synth:release', 'node scripts/stage7/aws-ops.mjs synth'],
  ['infra:diff:release', 'node scripts/stage7/aws-ops.mjs diff'],
  ['release:build', 'node scripts/stage7/build.mjs'],
  ['release:baseline', 'node scripts/stage7/baseline-cli.mjs'],
  ['release:baseline:self-test', 'node scripts/stage7/baseline-cli.mjs self-test'],
  ['release:github-approval', 'node scripts/stage7/github-environment-approval.mjs'],
  [
    'release:github-approval:self-test',
    'node scripts/stage7/github-environment-approval.mjs --self-test',
  ],
  ['release:github-publication', 'node scripts/stage7/github-publication.mjs'],
  [
    'release:github-publication:self-test',
    'node scripts/stage7/github-publication.mjs --self-test',
  ],
  ['release:preflight', 'node scripts/stage7/control.mjs preflight'],
  ['release:verify-candidate', 'node scripts/stage7/control.mjs verify-candidate'],
  ['release:manifest', 'node scripts/stage7/control.mjs manifest'],
  ['release:scan', 'node scripts/stage7/control.mjs scan'],
  ['release:plan', 'node scripts/stage7/control.mjs plan'],
  ['release:smoke', 'node scripts/stage7/control.mjs smoke'],
  ['release:sandbox-claim', 'node scripts/stage7/sandbox-execution-claim.mjs'],
  [
    'release:sandbox-claim:self-test',
    'node scripts/stage7/sandbox-execution-claim.mjs --self-test',
  ],
  ['release:sandbox-smoke', 'node scripts/stage7/control.mjs sandbox-smoke'],
  ['release:prerelease-safety', 'node scripts/stage7/prerelease-safety-readiness.mjs'],
  [
    'release:prerelease-safety:self-test',
    'node scripts/stage7/prerelease-safety-readiness.mjs self-test',
  ],
  ['release:quality', 'node scripts/stage7/control.mjs quality'],
  ['release:iam:self-test', 'node scripts/stage7/iam-effective-permissions.mjs --self-test'],
  ['stage7:prepare-readme', 'node scripts/stage7/control.mjs prepare-readme'],
  ['release:publish', 'node scripts/stage7/control.mjs publish'],
  ['release:verify', 'node scripts/stage7/control.mjs verify'],
  ['release:deploy:data', 'node scripts/stage7/aws-ops.mjs deploy-data'],
  ['release:deploy:api', 'node scripts/stage7/aws-ops.mjs deploy-api'],
  ['release:deploy:observability', 'node scripts/stage7/aws-ops.mjs deploy-observability'],
  ['release:deploy:web', 'node scripts/stage7/aws-ops.mjs deploy-web'],
  ['release:verify:observability', 'node scripts/stage7/aws-ops.mjs verify-observability'],
  ['release:verify:drift', 'node scripts/stage7/aws-ops.mjs verify-drift'],
  ['release:seed', 'node scripts/stage7/aws-ops.mjs seed'],
  ['release:activate', 'node scripts/stage7/aws-ops.mjs activate'],
  ['release:rollback:api', 'node scripts/stage7/aws-ops.mjs rollback-api'],
  ['release:rollback:web', 'node scripts/stage7/aws-ops.mjs rollback-web'],
  ['release:cleanup', 'node scripts/stage7/aws-ops.mjs cleanup'],
  ['release:aws:self-test', 'node scripts/stage7/aws-ops.mjs self-test'],
  ['release:control:self-test', 'node scripts/stage7/control.mjs self-test'],
  [
    'release:publication-recovery:self-test',
    'node scripts/stage7/release-successor-publication-recovery-self-test.mjs && node scripts/security/validate-release-successor-publication-recovery-workflow.mjs',
  ],
]);
const WORKFLOW_PNPM_COMMAND = /\bpnpm\s+([a-z0-9][a-z0-9:-]*)\b/gu;

const normalize = (source) => source.replace(/\r\n?/gu, '\n');
const count = (source, fragment) => source.split(fragment).length - 1;
const same = (left, right) => JSON.stringify(left) === JSON.stringify(right);

const topLevelBlock = (source, key) => {
  const lines = normalize(source).split('\n');
  const start = lines.findIndex((line) => line === `${key}:`);
  if (start === -1) return '';
  const end = lines.findIndex(
    (line, index) => index > start && /^[a-zA-Z][a-zA-Z0-9_-]*:/u.test(line),
  );
  return lines.slice(start, end === -1 ? lines.length : end).join('\n');
};

const workflowJobs = (source) => {
  const lines = normalize(source).split('\n');
  const jobsIndex = lines.findIndex((line) => line === 'jobs:');
  if (jobsIndex === -1) return new Map();
  const starts = lines
    .map((line, index) => {
      if (index <= jobsIndex) return undefined;
      const match = /^ {2}([a-z][a-z0-9-]+):\s*$/u.exec(line);
      return match === null ? undefined : { id: match[1], index };
    })
    .filter(Boolean);
  return new Map(
    starts.map((entry, index) => [
      entry.id,
      lines.slice(entry.index, starts[index + 1]?.index ?? lines.length).join('\n'),
    ]),
  );
};

const jobNeeds = (block) => {
  const lines = block.split('\n');
  const index = lines.findIndex((line) => /^ {4}needs:/u.test(line));
  if (index === -1) return [];
  const scalar = /^ {4}needs:\s*(.+?)\s*$/u.exec(lines[index]);
  if (scalar !== null && scalar[1].length > 0) return [scalar[1].trim()];
  const result = [];
  for (const line of lines.slice(index + 1)) {
    const match = /^ {6}-\s+([a-z][a-z0-9-]+)\s*$/u.exec(line);
    if (match === null) break;
    result.push(match[1]);
  }
  return result;
};

const jobCondition = (block) => {
  const lines = block.split('\n');
  const index = lines.findIndex((line) => /^ {4}if:/u.test(line));
  if (index === -1) return '';
  const scalar = /^ {4}if:\s*(.+?)\s*$/u.exec(lines[index]);
  if (scalar === null) return '';
  if (!['>', '>-', '|', '|-'].includes(scalar[1])) return scalar[1];
  const result = [];
  for (const line of lines.slice(index + 1)) {
    if (!/^ {6}/u.test(line)) break;
    result.push(line.trim());
  }
  return result.join(' ');
};

const hasFailClosedAttemptOneGuard = (condition) => {
  if (condition.includes('||')) return false;
  const expression = condition
    .replace(/^\$\{\{\s*/u, '')
    .replace(/\s*\}\}$/u, '')
    .trim();
  return (
    expression.split(/\s*&&\s*/u).filter((clause) => clause === 'github.run_attempt == 1')
      .length === 1
  );
};

const transitivelyDependsOn = (jobs, jobId, requiredJobId) => {
  const pending = [...jobNeeds(jobs.get(jobId) ?? '')];
  const visited = new Set();
  while (pending.length > 0) {
    const dependency = pending.pop();
    if (dependency === requiredJobId) return true;
    if (dependency === undefined || visited.has(dependency)) continue;
    visited.add(dependency);
    pending.push(...jobNeeds(jobs.get(dependency) ?? ''));
  }
  return false;
};

const jobPermissions = (block) => {
  const lines = block.split('\n');
  const index = lines.findIndex((line) => line === '    permissions:');
  if (index === -1) return [];
  const permissions = [];
  for (const line of lines.slice(index + 1)) {
    const match = /^ {6}([a-z-]+):\s*([^\s]+)\s*$/u.exec(line);
    if (match === null) break;
    permissions.push([match[1], match[2]]);
  }
  return permissions;
};

const stepBlocks = (source) => {
  const lines = normalize(source).split('\n');
  const starts = lines
    .map((line, index) => (/^ {6}-\s/u.test(line) ? index : -1))
    .filter((index) => index !== -1);
  return starts.map((start, index) =>
    lines.slice(start, starts[index + 1] ?? lines.length).join('\n'),
  );
};
const stepShellCommands = (step) => {
  const lines = normalize(step).split('\n');
  const runIndex = lines.findIndex((line) => /^ {8}run:\s*/u.test(line));
  if (runIndex === -1) return [];
  const scalar = /^ {8}run:\s*(.+?)\s*$/u.exec(lines[runIndex]);
  if (scalar !== null && !['|', '|-', '>', '>-'].includes(scalar[1])) return [scalar[1]];
  const commands = [];
  let pending = '';
  for (const line of lines.slice(runIndex + 1)) {
    if (!/^ {10}/u.test(line)) break;
    const fragment = line.trim();
    if (fragment.length === 0 || fragment.startsWith('#')) continue;
    pending = pending.length === 0 ? fragment : `${pending} ${fragment}`;
    if (pending.endsWith('\\')) {
      pending = pending.slice(0, -1).trimEnd();
      continue;
    }
    commands.push(pending);
    pending = '';
  }
  if (pending.length > 0) commands.push(pending);
  return commands;
};
const blockEnvironments = (block) =>
  [...block.matchAll(/^ {4}environment:\s*([^\s]+)\s*$/gmu)].map((match) => match[1]);
const replaceJob = (source, id, transform) => {
  const block = workflowJobs(source).get(id);
  if (block === undefined) throw new Error(`self-test fixture is missing ${id}`);
  return source.replace(block, transform(block));
};
const removeJob = (source, id) => replaceJob(source, id, () => '');
const changed = (source, from, to) => {
  assert.ok(source.includes(from), `self-test fixture is missing: ${from}`);
  return source.replace(from, to);
};

const withoutAttemptOneGuard = (source, id) =>
  replaceJob(source, id, (block) => {
    const scalar = '    if: ${{ github.run_attempt == 1 }}\n';
    if (block.includes(scalar)) return block.replace(scalar, '');
    if (block.includes('github.run_attempt == 1 &&')) {
      return block.replace('github.run_attempt == 1 &&', '');
    }
    return block.replace(' && github.run_attempt == 1', '');
  });

const withoutNamedStep = (source, id, name) =>
  replaceJob(source, id, (block) => {
    const step = stepBlocks(block).find((candidate) => candidate.includes(`name: ${name}`));
    assert.ok(step, `self-test fixture is missing step: ${name}`);
    return block.replace(step, '');
  });

const exactObjectKeys = (value, keys) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');

const exactReleaseReconciliationJournalSessionPolicy = (step) => {
  const source = /^\s*inline-session-policy:\s*>-\s*\n\s*(\{[^\n]+\})\s*$/mu.exec(step)?.[1];
  if (source === undefined) return false;
  let policy;
  try {
    policy = JSON.parse(source);
  } catch {
    return false;
  }
  const root =
    'arn:aws:ssm:${{ env.STAGE7_AWS_REGION }}:${{ env.STAGE7_AWS_ACCOUNT_ID }}:parameter/checkout/stage7/rollback/${{ inputs.candidate_sha }}/release-reconciliation/${{ github.run_id }}';
  const resources = [root, `${root}/*`];
  const expected = [
    {
      Sid: 'ReadOwnRoleDefinition',
      Effect: 'Allow',
      Action: [
        'iam:GetRole',
        'iam:GetRolePolicy',
        'iam:ListAttachedRolePolicies',
        'iam:ListRolePolicies',
      ],
      Resource: '${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
    },
    {
      Sid: 'ReadExactBoundary',
      Effect: 'Allow',
      Action: ['iam:GetPolicy', 'iam:GetPolicyVersion'],
      Resource: '${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN }}',
    },
    {
      Sid: 'ReadExactReleaseReconciliationJournal',
      Effect: 'Allow',
      Action: ['ssm:GetParameter', 'ssm:GetParametersByPath'],
      Resource: resources,
    },
    {
      Sid: 'WriteImmutableReleaseReconciliationJournal',
      Effect: 'Allow',
      Action: 'ssm:PutParameter',
      Resource: resources,
      Condition: { StringEquals: { 'ssm:Overwrite': 'false' } },
    },
  ];
  return (
    exactObjectKeys(policy, ['Version', 'Statement']) &&
    policy.Version === '2012-10-17' &&
    Array.isArray(policy.Statement) &&
    policy.Statement.length === expected.length &&
    policy.Statement.every(
      (statement, index) => JSON.stringify(statement) === JSON.stringify(expected[index]),
    )
  );
};

const exactReleaseSuccessorFenceSessionPolicy = (step) => {
  const source = /^\s*inline-session-policy:\s*>-\s*\n\s*(\{[^\n]+\})\s*$/mu.exec(step)?.[1];
  if (source === undefined) return false;
  let policy;
  try {
    policy = JSON.parse(source);
  } catch {
    return false;
  }
  const fence =
    'arn:aws:ssm:${{ env.STAGE7_AWS_REGION }}:${{ env.STAGE7_AWS_ACCOUNT_ID }}:parameter/checkout/stage7/release-fence/${{ inputs.candidate_sha }}/${{ github.run_id }}';
  const expected = [
    {
      Sid: 'ReadOwnRoleDefinition',
      Effect: 'Allow',
      Action: [
        'iam:GetRole',
        'iam:GetRolePolicy',
        'iam:ListAttachedRolePolicies',
        'iam:ListRolePolicies',
      ],
      Resource: '${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
    },
    {
      Sid: 'ReadExactBoundary',
      Effect: 'Allow',
      Action: ['iam:GetPolicy', 'iam:GetPolicyVersion'],
      Resource: '${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN }}',
    },
    {
      Sid: 'ReadCallerIdentity',
      Effect: 'Allow',
      Action: 'sts:GetCallerIdentity',
      Resource: '*',
    },
    {
      Sid: 'ReadExactImmutableFence',
      Effect: 'Allow',
      Action: 'ssm:GetParameter',
      Resource: fence,
    },
    {
      Sid: 'WriteExactImmutableFence',
      Effect: 'Allow',
      Action: 'ssm:PutParameter',
      Resource: fence,
      Condition: { StringEquals: { 'ssm:Overwrite': 'false' } },
    },
  ];
  return (
    exactObjectKeys(policy, ['Version', 'Statement']) &&
    policy.Version === '2012-10-17' &&
    Array.isArray(policy.Statement) &&
    policy.Statement.length === expected.length &&
    policy.Statement.every(
      (statement, index) => JSON.stringify(statement) === JSON.stringify(expected[index]),
    )
  );
};

const exactReleaseReconciliationLiveJournalCheck = (step, authoritySuffix) => {
  const effective = `.stage7/reconciliation-private/live-${authoritySuffix}-journal-role-effective-permissions.json`;
  const audit = `.stage7/reconciliation-private/live-${authoritySuffix}-journal-role-audit.json`;
  return (
    count(step, 'release-successor-cli.mjs capture-journal-role-authority') === 1 &&
    count(step, 'control.mjs verify-journal-authority') === 1 &&
    step.includes('--journal-role-arn "${STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN}"') &&
    step.includes(
      '--permissions-boundary-arn "${STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN}"',
    ) &&
    step.includes('--aws-region "${STAGE7_AWS_REGION}"') &&
    step.includes(`--output ${effective}`) &&
    step.includes(`--get-role-output ${audit}`) &&
    step.includes('--scope full') &&
    step.includes('--manifest .stage7/candidate-manifest/candidate-manifest.json') &&
    step.includes('--aws-auth .stage7/aws-auth/aws-auth.json') &&
    step.includes(
      '--frozen-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json',
    ) &&
    step.includes(`--live-effective-permissions ${effective}`) &&
    step.indexOf('capture-journal-role-authority') < step.indexOf('verify-journal-authority')
  );
};

export function validateReleaseWorkflowCommands(workflows, packageInput) {
  const errors = [];
  const fail = (message) => errors.push(`package.json: ${message}`);
  let manifest;
  try {
    manifest = JSON.parse(packageInput);
  } catch {
    fail('must be valid JSON before workflow command mappings can be verified');
    return errors;
  }
  if (
    manifest === null ||
    typeof manifest !== 'object' ||
    manifest.scripts === null ||
    typeof manifest.scripts !== 'object' ||
    Array.isArray(manifest.scripts)
  ) {
    fail('scripts must be an object');
    return errors;
  }

  const used = new Set();
  for (const source of workflows) {
    WORKFLOW_PNPM_COMMAND.lastIndex = 0;
    for (const match of normalize(source).matchAll(WORKFLOW_PNPM_COMMAND)) {
      const command = match[1];
      if (command === 'build' || command.startsWith('infra:') || command.startsWith('release:')) {
        used.add(command);
      }
    }
  }

  for (const command of used) {
    if (!Object.hasOwn(manifest.scripts, command)) {
      fail(`workflow command is orphaned: ${command}`);
    }
    if (!REQUIRED_WORKFLOW_SCRIPT_MAPPINGS.has(command)) {
      fail(`workflow command is outside the approved Stage 7 contract: ${command}`);
    }
  }
  for (const [command, expected] of REQUIRED_WORKFLOW_SCRIPT_MAPPINGS) {
    if (!Object.hasOwn(manifest.scripts, command)) {
      fail(`required Stage 7 mapping is missing: ${command}`);
    } else if (manifest.scripts[command] !== expected) {
      fail(`Stage 7 mapping diverges for ${command}`);
    }
  }
  const sandboxMapping = manifest.scripts['release:sandbox-smoke'];
  if (
    typeof sandboxMapping === 'string' &&
    /sandbox:authorized:execute|scripts[\\/]stage6[\\/]sandbox-authorized[\\/]run\.mjs|--execute\b/iu.test(
      sandboxMapping,
    )
  ) {
    fail('release:sandbox-smoke direct Stage 6 execution alias is forbidden');
  }
  const extraStage7Mappings = Object.keys(manifest.scripts).filter(
    (command) =>
      (command.startsWith('release:') ||
        command === 'infra:synth:release' ||
        command === 'infra:diff:release') &&
      !REQUIRED_WORKFLOW_SCRIPT_MAPPINGS.has(command),
  );
  if (extraStage7Mappings.length > 0) {
    fail(`unapproved Stage 7 mappings are forbidden: ${extraStage7Mappings.sort().join(', ')}`);
  }
  return errors;
}

const releaseSpec = {
  jobs: RELEASE_JOBS,
  needs: RELEASE_NEEDS,
  concurrency: 'stage7-assessment-release',
  inputs: [
    'candidate_sha',
    'release_tag',
    'release_id',
    'versioned_update',
    'config_sha256',
    'stage6_run_id',
    'stage6_manifest_sha256',
    'confirm_deploy',
  ],
  crossRun: new Set(['release-metadata', 'verify-candidate', 'build-or-fetch']),
  configJobs: new Set([
    'release-metadata',
    'build-or-fetch',
    'infra-synth-test',
    'approval',
    'quality',
    'release-reconciliation-intent',
    'release-reconciliation',
    'release-successor-fence',
    'publish-release',
    'summary',
    ...RELEASE_AWS.keys(),
  ]),
  aws: RELEASE_AWS,
  protected: new Map(
    [
      'approval',
      'deploy-data',
      'deploy-api',
      'deploy-observability',
      'deploy-web',
      'postdeploy-smoke',
      'edge-security',
      'quality',
      'release-reconciliation-intent',
      'rollback-check',
      'release-reconciliation',
      'release-successor-fence',
      'publish-release',
    ]
      .map((job) => [job, 'assessment-release'])
      .concat([
        ['build-or-fetch', 'assessment-release-read'],
        ['aws-auth', 'assessment-release-read'],
        ['infra-diff', 'assessment-release-read'],
        ['sandbox-smoke', 'assessment-release-sandbox'],
        ['emergency-recovery', 'assessment-release-recovery'],
      ]),
  ),
  reusable: new Map([['rollback-resilience', ROLLBACK_RESILIENCE_WORKFLOW]]),
  publishJob: 'publish-release',
  alertJob: 'deploy-observability',
  configVariable: 'STAGE7_CONFIG_B64',
  regionVariable: 'STAGE7_AWS_REGION',
};
const prereleaseSpec = {
  jobs: PRERELEASE_JOBS,
  needs: PRERELEASE_NEEDS,
  concurrency: 'stage7-assessment-prerelease',
  inputs: [
    'candidate_sha',
    'release_id',
    'config_sha256',
    'stage6_run_id',
    'stage6_manifest_sha256',
    'confirm_deploy',
    'confirm_sandbox_smoke',
  ],
  crossRun: new Set(['prerelease-metadata', 'verify-candidate', 'build-once']),
  configJobs: new Set([
    'prerelease-metadata',
    'build-once',
    'approval',
    'external-evidence',
    'infra-synth-test',
    'summary',
    ...PRERELEASE_AWS.keys(),
  ]),
  aws: PRERELEASE_AWS,
  protected: new Map([
    ['approval', 'assessment-prerelease'],
    ['infra-diff', 'assessment-prerelease-read'],
    ['prerelease-safety-readiness', 'assessment-prerelease'],
    ['deploy-prerelease', 'assessment-prerelease'],
    ['external-verification', 'assessment-prerelease-external'],
    ['external-evidence', 'assessment-prerelease'],
    ['cleanup', 'assessment-prerelease'],
  ]),
  reusable: new Map(),
  publishJob: undefined,
  alertJob: 'deploy-prerelease',
  configVariable: 'STAGE7_PRERELEASE_CONFIG_B64',
  regionVariable: 'STAGE7_PRERELEASE_AWS_REGION',
};

const validateCommon = (name, input, spec) => {
  const source = normalize(input);
  const errors = [];
  const fail = (message) => errors.push(`${name}: ${message}`);
  const onBlock = topLevelBlock(source, 'on');
  const triggers = [...onBlock.matchAll(/^ {2}([a-z][a-z0-9_-]*):\s*$/gmu)].map(
    (match) => match[1],
  );
  if (!same(triggers, ['workflow_dispatch'])) fail('the only trigger must be workflow_dispatch');
  for (const inputName of spec.inputs) {
    if (!new RegExp(`^ {6}${inputName}:\\s*$`, 'mu').test(onBlock)) {
      fail(`required workflow input is missing: ${inputName}`);
    }
  }
  if (
    /\b(?:pull_request|pull_request_target|push|schedule|workflow_run|repository_dispatch)\s*:/u.test(
      onBlock,
    )
  ) {
    fail('automatic, pull-request and cross-workflow release triggers are forbidden');
  }
  if (topLevelBlock(source, 'permissions').trim() !== 'permissions:\n  contents: read') {
    fail('top-level permissions must be exactly contents: read');
  }
  const concurrency = topLevelBlock(source, 'concurrency');
  if (
    !concurrency.includes(`  group: ${spec.concurrency}`) ||
    !concurrency.includes('  cancel-in-progress: false') ||
    concurrency.includes('cancel-in-progress: true')
  ) {
    fail(`concurrency must be the single non-cancelled ${spec.concurrency} lane`);
  }
  if (!topLevelBlock(source, 'defaults').includes('    shell: bash')) {
    fail('bash must be the explicit default shell');
  }
  for (const fragment of [
    'STAGE7_AWS_ACCOUNT_ID: ${{ vars.STAGE7_AWS_ACCOUNT_ID }}',
    'STAGE7_AWS_REGION: ${{ vars.' + spec.regionVariable + ' }}',
    'STAGE7_CANDIDATE_SHA: ${{ inputs.candidate_sha }}',
    'STAGE7_RELEASE_ID: ${{ inputs.release_id }}',
    "github.event_name == 'workflow_dispatch'",
    "github.ref == 'refs/heads/master'",
    "github.repository == 'ivanmonsalve0404/async-checkout-demo'",
    '[[ "${CANDIDATE_SHA}" =~ ^[0-9a-f]{40}$ ]]',
    'test "$(git rev-parse HEAD)" = "${CANDIDATE_SHA}"',
    'test "$(git rev-parse origin/master)" = "${CANDIDATE_SHA}"',
  ]) {
    if (!source.includes(fragment)) fail(`immutable candidate guard is missing: ${fragment}`);
  }
  if (
    prereleaseSpec === spec &&
    [
      '${{ vars.STAGE7_CONFIG_B64 }}',
      '${{ vars.STAGE7_AWS_REGION }}',
      '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
      '${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}',
      '${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
      '${{ vars.STAGE7_AWS_CLEANUP_ROLE_ARN }}',
    ].some((binding) => source.includes(binding))
  ) {
    fail('prerelease must not reuse full-release config, region or role variables');
  }
  const workflowEnvironment = topLevelBlock(source, 'env');
  if (
    releaseSpec === spec &&
    (!workflowEnvironment.includes(
      '  STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN: ${{ vars.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
    ) ||
      !workflowEnvironment.includes(
        '  STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN: ${{ vars.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN }}',
      ))
  ) {
    fail('release journal role and permissions boundary variables are required');
  }
  if (
    !workflowEnvironment.includes('  STAGE7_CANDIDATE_SHA: ${{ inputs.candidate_sha }}') ||
    !workflowEnvironment.includes('  STAGE7_RELEASE_ID: ${{ inputs.release_id }}')
  ) {
    fail('every job must inherit the exact immutable candidate and release identity');
  }
  if (
    releaseSpec === spec &&
    !workflowEnvironment.includes('  STAGE7_RELEASE_TAG: ${{ inputs.release_tag }}')
  ) {
    fail('full release jobs must inherit the exact immutable tag');
  }

  const secretExpressions = [...source.matchAll(/\$\{\{\s*secrets\.([A-Z0-9_]+)\s*\}\}/gu)];
  const expectedSecretNames = [
    'STAGE7_ALERT_EMAIL',
    ...SANDBOX_SECRET_NAMES,
    ...(prereleaseSpec === spec ? PRERELEASE_ACCESS_SECRET_NAMES : []),
    ...(releaseSpec === spec ? ['STAGE7_SMOKE_INPUTS_B64', 'STAGE7_SMOKE_INPUTS_B64'] : []),
  ].sort();
  const actualSecretNames = secretExpressions.map((match) => match[1]).sort();
  if (!same(actualSecretNames, expectedSecretNames)) {
    fail('only the exact alert and one-use sandbox secret set is allowed');
  }
  const alertBlock = workflowJobs(source).get(spec.alertJob) ?? '';
  if (
    !alertBlock.includes('STAGE7_ALERT_EMAIL: ${{ secrets.STAGE7_ALERT_EMAIL }}') ||
    /(?:echo|printf|tee|set\s+-x)[^\n]*STAGE7_ALERT_EMAIL/iu.test(alertBlock)
  ) {
    fail(`${spec.alertJob} must consume STAGE7_ALERT_EMAIL only without logging it`);
  }
  const sandboxJob = releaseSpec === spec ? 'sandbox-smoke' : 'external-verification';
  const sandboxStep = stepBlocks(workflowJobs(source).get(sandboxJob) ?? '').find((step) =>
    step.includes('pnpm release:sandbox-smoke'),
  );
  for (const secret of SANDBOX_SECRET_NAMES) {
    if (
      count(source, `secrets.${secret}`) !== 1 ||
      !sandboxStep?.includes(`${secret}: \${{ secrets.${secret} }}`)
    ) {
      fail(
        `${sandboxJob} must consume ${secret} exactly once and only in the guarded wrapper step`,
      );
    }
  }
  if (prereleaseSpec === spec) {
    const external = workflowJobs(source).get('external-verification') ?? '';
    const materialize = stepBlocks(external).find((step) =>
      step.includes('name: Materialize one-use CloudFront access proofs without disclosure'),
    );
    for (const secret of PRERELEASE_ACCESS_SECRET_NAMES) {
      if (
        count(source, `secrets.${secret}`) !== 1 ||
        !materialize?.includes(`${secret}: \${{ secrets.${secret} }}`) ||
        source.includes(`vars.${secret}`) ||
        workflowEnvironment.includes(`${secret}:`)
      ) {
        fail(`external-verification must consume protected ${secret} exactly once`);
      }
    }
    for (const fragment of [
      'set -euo pipefail',
      'test -n "${STAGE7_CLOUDFRONT_SIGNED_COOKIE_B64}"',
      'test -n "${STAGE7_CLOUDFRONT_EXPIRED_SIGNED_COOKIE_B64}"',
      'umask 077',
      'valid="${RUNNER_TEMP}/stage7-cloudfront-signed-cookie.b64"',
      'expired="${RUNNER_TEMP}/stage7-cloudfront-expired-signed-cookie.b64"',
      'test ! -e "${valid}"',
      'test ! -e "${expired}"',
      'printf \'%s\' "${STAGE7_CLOUDFRONT_SIGNED_COOKIE_B64}" > "${valid}"',
      'printf \'%s\' "${STAGE7_CLOUDFRONT_EXPIRED_SIGNED_COOKIE_B64}" > "${expired}"',
      'chmod 600 "${valid}" "${expired}"',
      'test ! -L "${valid}"',
      'test ! -L "${expired}"',
      'test "$(stat -c \'%a\' "${valid}")" = \'600\'',
      'test "$(stat -c \'%a\' "${expired}")" = \'600\'',
      'printf \'STAGE7_CLOUDFRONT_SIGNED_COOKIE_FILE=%s\\n\' "${valid}" >> "${GITHUB_ENV}"',
      'printf \'STAGE7_CLOUDFRONT_EXPIRED_SIGNED_COOKIE_FILE=%s\\n\' "${expired}" >> "${GITHUB_ENV}"',
    ]) {
      if (!materialize?.includes(fragment)) {
        fail(`one-use CloudFront access materialization is missing: ${fragment}`);
      }
    }
    if (
      materialize === undefined ||
      /(?:echo|tee|set\s+-x)[^\n]*STAGE7_CLOUDFRONT/iu.test(materialize) ||
      /STAGE7_CLOUDFRONT_(?:EXPIRED_)?SIGNED_COOKIE_B64=%s\\n[^\n]*GITHUB_ENV/iu.test(
        materialize,
      ) ||
      stepBlocks(external)
        .filter((step) => step.includes('uses: actions/upload-artifact@'))
        .some((step) => /STAGE7_CLOUDFRONT|stage7-cloudfront/iu.test(step))
    ) {
      fail('one-use CloudFront access proofs must remain undisclosed and outside artifacts');
    }
  }
  let credentialAuditSource = source;
  for (const safeReference of [
    'test -z "${AWS_ACCESS_KEY_ID:-}"',
    'test -z "${AWS_SECRET_ACCESS_KEY:-}"',
    'test -z "${AWS_SESSION_TOKEN:-}"',
    'test -z "${AWS_SECURITY_TOKEN:-}"',
    'unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN',
    "printf 'AWS_ACCESS_KEY_ID=\\n'",
    "printf 'AWS_SECRET_ACCESS_KEY=\\n'",
    "printf 'AWS_SESSION_TOKEN=\\n'",
    "printf 'AWS_SECURITY_TOKEN=\\n'",
  ]) {
    credentialAuditSource = credentialAuditSource.replaceAll(safeReference, '');
  }
  if (
    /\b(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_SECURITY_TOKEN)\b/u.test(
      credentialAuditSource,
    )
  ) {
    fail('long-lived AWS credential variables are forbidden');
  }
  if (/\bcontinue-on-error\s*:/iu.test(source)) fail('continue-on-error is forbidden');
  if (/--hotswap\b|--require-approval\s+never\b/iu.test(source)) {
    fail('hotswap and approval bypass are forbidden');
  }
  if (
    /\bcdk\s+(?:bootstrap|deploy|destroy)\b|\baws\s+(?:cloudformation|dynamodb|lambda|s3|cloudfront|budgets|iam)\b/iu.test(
      source,
    )
  ) {
    fail('raw cloud mutation commands are forbidden; guarded release scripts are required');
  }
  if (/^\s*(?:aws(?:\.exe)?|cdk)\s+|\bpnpm\s+(?:exec\s+)?cdk\s+/gimu.test(source)) {
    fail('direct AWS and CDK CLI commands are forbidden in release YAML');
  }
  if (/\bref:\s*(?:main|master|refs\/heads\/|\$\{\{\s*github\.ref)/iu.test(source)) {
    fail('mutable checkout references are forbidden');
  }
  if (/\bset\s+-x\b/u.test(source)) fail('shell tracing is forbidden in release workflows');
  if (
    /sandbox:authorized:execute|scripts[\\/]stage6[\\/]sandbox-authorized[\\/]run\.mjs\s+--execute/iu.test(
      source,
    )
  ) {
    fail('direct Stage 6 sandbox execution is forbidden; the Stage 7 wrapper is required');
  }

  ACTION_REFERENCE.lastIndex = 0;
  const actionReferences = [...source.matchAll(ACTION_REFERENCE)].map((match) => match[1]);
  for (const reference of actionReferences) {
    if (
      reference !== ROLLBACK_RESILIENCE_WORKFLOW &&
      (!PINNED_ACTION.test(reference) || !ACTIONS.has(reference))
    ) {
      fail(`action must use an approved official full SHA: ${reference}`);
    }
  }
  if (actionReferences.length === 0) fail('at least one pinned action is required');

  const checkoutSteps = stepBlocks(source).filter((step) =>
    step.includes('uses: actions/checkout@'),
  );
  if (checkoutSteps.length !== spec.jobs.length - spec.reusable.size) {
    fail('every workflow job must check out the exact candidate once');
  }
  for (const step of checkoutSteps) {
    if (
      !step.includes('          fetch-depth: 0') ||
      !step.includes('          persist-credentials: false') ||
      !step.includes('          ref: ${{ inputs.candidate_sha }}')
    ) {
      fail('checkout must use full history, no stored token and inputs.candidate_sha');
      break;
    }
  }
  const lines = source.split('\n');
  for (const [index, line] of lines.entries()) {
    if (!/^\s+run:\s*\|\s*$/u.test(line)) continue;
    const next = lines.slice(index + 1).find((candidate) => candidate.trim().length > 0);
    if (next?.trim() !== 'set -euo pipefail') {
      fail('every multiline shell step must begin with set -euo pipefail');
      break;
    }
  }

  const jobs = workflowJobs(source);
  if (releaseSpec === spec) {
    for (const [jobName, block] of jobs) {
      for (const step of stepBlocks(block)) {
        const liveJournalAuthorityCheck =
          (jobName === 'release-reconciliation-intent' &&
            exactReleaseReconciliationLiveJournalCheck(step, 'intent')) ||
          (jobName === 'release-reconciliation' &&
            ['probe-check', 'finalize-check', 'probe-resilience', 'finalize-resilience'].some(
              (suffix) => exactReleaseReconciliationLiveJournalCheck(step, suffix),
            ));
        for (const command of stepShellCommands(step)) {
          if (
            command.includes('pnpm release:preflight -- --aws-read') &&
            command.includes('--manifest .stage7/candidate-manifest/candidate-manifest.json') &&
            (!command.includes('--journal-role-effective-permissions ') ||
              !command.includes('--reconciliation-recovery-role-effective-permissions '))
          ) {
            fail(`${jobName} full aws-read preflight must consume both auxiliary role authorities`);
          }
          const frozenReconciliationAuthorityConsumer = command.includes(
            'release-reconciliation-cli.mjs create-intent',
          );
          if (
            command.includes('--aws-auth .stage7/aws-auth/aws-auth.json') &&
            !liveJournalAuthorityCheck &&
            !command.includes(
              '--journal-role-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json',
            )
          ) {
            fail(`${jobName} full AWS operation must consume the journal role authority`);
          }
          if (
            command.includes('--aws-auth .stage7/aws-auth/aws-auth.json') &&
            !liveJournalAuthorityCheck &&
            !frozenReconciliationAuthorityConsumer &&
            !command.includes(
              '--reconciliation-recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json',
            )
          ) {
            fail(`${jobName} full AWS operation must consume the recovery role authority`);
          }
        }
      }
    }
  }
  if (!same([...jobs.keys()], spec.jobs)) {
    fail(`the exact ordered ${spec.jobs.length}-job workflow contract is required`);
  }
  const metadataJob = spec.jobs[0];
  for (const id of spec.jobs) {
    const block = jobs.get(id) ?? '';
    if (!hasFailClosedAttemptOneGuard(jobCondition(block))) {
      fail(`${id} must reject native reruns before any work`);
    }
    if (id !== metadataJob && !transitivelyDependsOn(jobs, id, metadataJob)) {
      fail(`${id} must depend transitively on ${metadataJob}`);
    }
  }
  for (const id of spec.jobs) {
    const block = jobs.get(id);
    if (block === undefined) continue;
    const reusableWorkflow = spec.reusable.get(id);
    if (reusableWorkflow !== undefined) {
      if (
        !block.includes(`    uses: ${reusableWorkflow}`) ||
        !block.includes(
          "    if: ${{ github.run_attempt == 1 && needs.rollback-check.outputs.base_rehearsal_ready == 'true' }}",
        ) ||
        !block.includes('      candidate_sha: ${{ inputs.candidate_sha }}') ||
        !block.includes('      config_sha256: ${{ inputs.config_sha256 }}') ||
        !block.includes('      release_id: ${{ inputs.release_id }}') ||
        !same(jobPermissions(block), [
          ['contents', 'read'],
          ['id-token', 'write'],
        ]) ||
        block.includes('secrets: inherit')
      ) {
        fail(`${id} must call only the exact protected rollback resilience workflow`);
      }
      if (!same(jobNeeds(block), spec.needs.get(id) ?? [])) {
        fail(`${id} has an invalid fail-closed dependency chain`);
      }
      continue;
    }
    if (!/^ {4}runs-on:\s*ubuntu-24\.04\s*$/mu.test(block)) fail(`${id} must pin ubuntu-24.04`);
    if (!/^ {4}timeout-minutes:\s*[1-9][0-9]*\s*$/mu.test(block))
      fail(`${id} must have a finite timeout`);
    if (!same(jobNeeds(block), spec.needs.get(id) ?? []))
      fail(`${id} has an invalid fail-closed dependency chain`);
    const expectedEnvironment = spec.protected.get(id);
    const actualEnvironments = blockEnvironments(block);
    if (expectedEnvironment !== undefined && !same(actualEnvironments, [expectedEnvironment])) {
      fail(`${id} must use the protected ${expectedEnvironment} environment`);
    }
    if (expectedEnvironment === undefined && actualEnvironments.length > 0) {
      fail(`${id} must not consume a protected deployment environment`);
    }

    const permissions = jobPermissions(block);
    if (spec.aws.has(id)) {
      const expectedPermissions =
        (releaseSpec === spec &&
          ['build-or-fetch', 'infra-diff', 'emergency-recovery', 'sandbox-smoke'].includes(id)) ||
        (prereleaseSpec === spec &&
          ['prerelease-safety-readiness', 'deploy-prerelease', 'external-verification'].includes(
            id,
          ))
          ? [
              ['actions', 'read'],
              ['contents', 'read'],
              ['id-token', 'write'],
            ]
          : [
              ['contents', 'read'],
              ['id-token', 'write'],
            ];
      if (!same(permissions, expectedPermissions)) {
        fail(`${id} must have the exact least-privilege AWS permissions`);
      }
    } else if (spec.crossRun.has(id)) {
      if (
        !same(permissions, [
          ['actions', 'read'],
          ['contents', 'read'],
        ])
      ) {
        fail(`${id} must have exactly actions:read and contents:read`);
      }
    } else if (id === 'approval') {
      if (
        !same(permissions, [
          ['actions', 'read'],
          ['contents', 'read'],
        ])
      ) {
        fail(`${id} must have exactly actions:read and contents:read`);
      }
    } else if (id === spec.publishJob) {
      if (!same(permissions, [['contents', 'write']]))
        fail(`${id} is the only job allowed contents:write`);
      if (!block.includes('GH_TOKEN: ${{ github.token }}'))
        fail(`${id} must use only the ephemeral GitHub token`);
    } else if (permissions.length > 0) {
      fail(`${id} must inherit top-level read-only permissions`);
    }

    const steps = stepBlocks(block);
    const configSteps = steps.filter((step) =>
      step.includes('name: Materialize and validate the approved Stage 7 config'),
    );
    if (spec.configJobs.has(id)) {
      if (configSteps.length !== 1) {
        fail(`${id} must materialize the approved config exactly once`);
      } else {
        for (const fragment of configFragments(spec.configVariable)) {
          if (!configSteps[0].includes(fragment))
            fail(`${id} config channel is missing: ${fragment}`);
        }
        if (/\b(?:echo|tee)\b[^\n]*STAGE7_CONFIG_B64/iu.test(configSteps[0])) {
          fail(`${id} must not print the Stage 7 config payload`);
        }
      }
    } else if (configSteps.length > 0) {
      fail(`${id} must not materialize deployment configuration`);
    }

    const awsSteps = steps.filter((step) =>
      step.includes('uses: aws-actions/configure-aws-credentials@'),
    );
    if (spec.aws.has(id)) {
      const isPrereleaseExternal = prereleaseSpec === spec && id === 'external-verification';
      const isPrereleaseSafety = prereleaseSpec === spec && id === 'prerelease-safety-readiness';
      const isReleaseAwsAuth = releaseSpec === spec && id === 'aws-auth';
      const isReleasePostdeploy = releaseSpec === spec && id === 'postdeploy-smoke';
      const isEmergencyRecovery = releaseSpec === spec && id === 'emergency-recovery';
      const isReleaseReconciliationIntent =
        releaseSpec === spec && id === 'release-reconciliation-intent';
      const isReleaseRollback = releaseSpec === spec && id === 'rollback-check';
      const isReleaseReconciliation = releaseSpec === spec && id === 'release-reconciliation';
      const isReleaseSuccessorFence = releaseSpec === spec && id === 'release-successor-fence';
      const expectedAwsSteps = isPrereleaseExternal
        ? 3
        : isReleaseAwsAuth
          ? 1
          : isReleasePostdeploy
            ? 3
            : isEmergencyRecovery
              ? 3
              : isReleaseReconciliation
                ? 8
                : isReleaseRollback
                  ? 5
                  : 1;
      if (awsSteps.length !== expectedAwsSteps) {
        fail(
          `${id} must configure exactly ${expectedAwsSteps} bounded OIDC session${expectedAwsSteps === 1 ? '' : 's'}`,
        );
      }
      const [role, guard] = spec.aws.get(id);
      const isPrefreezeBuild = releaseSpec === spec && id === 'build-or-fetch';
      if (!isPrefreezeBuild) {
        for (const fragment of [
          prereleaseSpec === spec
            ? 'name: stage7-prerelease-candidate-manifest'
            : 'name: stage7-candidate-manifest',
          'path: .stage7/candidate-manifest',
        ]) {
          if (!block.includes(fragment)) fail(`${id} is missing its OIDC guard: ${fragment}`);
        }
      }
      for (const awsStep of awsSteps) {
        for (const fragment of [
          'uses: aws-actions/configure-aws-credentials@61815dcd50bd041e203e49132bacad1fd04d2708',
          'allowed-account-ids: ${{ env.STAGE7_AWS_ACCOUNT_ID }}',
          'aws-region: ${{ env.STAGE7_AWS_REGION }}',
          'mask-aws-account-id: true',
          'output-credentials: false',
          'unset-current-credentials: true',
        ]) {
          if (!awsStep.includes(fragment)) fail(`${id} is missing its OIDC guard: ${fragment}`);
        }
      }
      const configIndex = steps.indexOf(configSteps[0]);
      const firstAwsIndex = steps.indexOf(awsSteps[0]);
      if (configIndex < 0 || firstAwsIndex < 0 || configIndex >= firstAwsIndex) {
        fail(`${id} must validate config before requesting its OIDC token`);
      }
      if (isPrereleaseSafety) {
        if (!block.includes(`role-to-assume: ${role}`)) {
          fail(`${id} is missing its OIDC guard: role-to-assume: ${role}`);
        }
        const captureStep = steps[firstAwsIndex + 1] ?? '';
        for (const fragment of [
          'GITHUB_TOKEN: ${{ github.token }}',
          'STAGE7_PROTECTED_ENVIRONMENT: assessment-prerelease',
          'pnpm release:prerelease-safety -- capture',
          '--manifest .stage7/candidate-manifest/candidate-manifest.json',
          '--assembly .stage7/candidate/iac',
          '--plan .stage7/infra-diff/infra-diff.json',
          '--raw-diff .stage7/infra-diff/infra-diff.txt',
          '--approval .stage7/approval/approval.json',
          '--aws-auth .stage7/infra-diff/aws-auth.json',
          '--watchdog-role-arn "${STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN}"',
          '--output "${STAGE7_EVIDENCE_ROOT}/prerelease-safety-readiness.json"',
        ]) {
          if (!captureStep.includes(fragment)) {
            fail(`protected prerelease safety producer is missing: ${fragment}`);
          }
        }
        if (
          !block.includes(
            'role-session-name: e7pre-safety-${{ github.run_id }}-${{ github.run_attempt }}',
          )
        ) {
          fail(`${id} must bind read authority to run id and attempt`);
        }
      } else if (isReleaseAwsAuth) {
        if (
          !awsSteps[0]?.includes('role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}') ||
          !awsSteps[0]?.includes('role-session-name: e7-${{ github.job }}-${{ github.run_id }}') ||
          awsSteps[0]?.includes('inline-session-policy:')
        ) {
          fail('aws-auth must use the audited read role for both auxiliary role captures');
        }
        const captureStep = steps[steps.indexOf(awsSteps[0]) + 1] ?? '';
        const recoveryCaptureStep = steps[steps.indexOf(awsSteps[0]) + 2] ?? '';
        const authorityStep = steps[steps.indexOf(awsSteps[0]) + 3] ?? '';
        for (const fragment of [
          'capture-journal-role-authority',
          '--journal-role-arn "${STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN}"',
          '--permissions-boundary-arn "${STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN}"',
          '--output "${STAGE7_EVIDENCE_ROOT}/stage7-release-journal-role-effective-permissions.json"',
          '--get-role-output "${RUNNER_TEMP}/stage7-release-journal-role-audit.json"',
        ]) {
          if (!captureStep.includes(fragment))
            fail(`aws-auth journal capture is missing: ${fragment}`);
        }
        for (const fragment of [
          'release-reconciliation-recovery-cli.mjs capture-base-role-authority',
          'test -n "${STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN}"',
          'test -n "${STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN}"',
          '--config "${STAGE7_CONFIG}"',
          '--output "${STAGE7_EVIDENCE_ROOT}/stage7-release-reconciliation-recovery-role-effective-permissions.json"',
          '--role-audit-output "${RUNNER_TEMP}/stage7-release-reconciliation-recovery-role-audit.json"',
        ]) {
          if (!recoveryCaptureStep.includes(fragment)) {
            fail(`aws-auth recovery BASE capture is missing: ${fragment}`);
          }
        }
        if (
          !authorityStep.includes('pnpm release:preflight') ||
          !authorityStep.includes('--aws-read') ||
          !authorityStep.includes(
            '--journal-role-effective-permissions "${STAGE7_EVIDENCE_ROOT}/stage7-release-journal-role-effective-permissions.json"',
          ) ||
          !authorityStep.includes(
            '--reconciliation-recovery-role-effective-permissions "${STAGE7_EVIDENCE_ROOT}/stage7-release-reconciliation-recovery-role-effective-permissions.json"',
          )
        ) {
          fail('aws-auth must bind both auxiliary authorities under the read session');
        }
      } else if (isReleaseReconciliationIntent) {
        const liveAuthorityStep = steps[firstAwsIndex + 1] ?? '';
        const openStep = steps[firstAwsIndex + 2] ?? '';
        if (
          !awsSteps[0]?.includes(
            'role-to-assume: ${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
          ) ||
          !awsSteps[0]?.includes(
            'role-session-name: e7-release-reconciliation-journal-${{ github.run_id }}',
          ) ||
          !exactReleaseReconciliationJournalSessionPolicy(awsSteps[0]) ||
          !exactReleaseReconciliationLiveJournalCheck(liveAuthorityStep, 'intent') ||
          !openStep.includes(
            'node scripts/stage7/release-reconciliation-cli.mjs open-journal --intent .stage7/reconciliation-private/release-reconciliation-intent.json --output .stage7/reconciliation-private/release-reconciliation-owner.json',
          )
        ) {
          fail('release reconciliation intent must open the exact immutable journal authority');
        }
      } else if (isReleaseReconciliation) {
        const expectedRoles = [
          '${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
          '${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
          '${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
          '${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
        ];
        const expectedSessions = [
          'e7-release-reconciliation-journal-${{ github.run_id }}',
          'e7-release-reconciliation-runtime-${{ github.run_id }}',
          'e7-release-reconciliation-read-check-${{ github.run_id }}',
          'e7-release-reconciliation-journal-${{ github.run_id }}',
          'e7-release-reconciliation-journal-${{ github.run_id }}',
          'e7-release-reconciliation-runtime-${{ github.run_id }}',
          'e7-release-reconciliation-read-resilience-${{ github.run_id }}',
          'e7-release-reconciliation-journal-${{ github.run_id }}',
        ];
        const liveChecks = new Map([
          [0, 'probe-check'],
          [3, 'finalize-check'],
          [4, 'probe-resilience'],
          [7, 'finalize-resilience'],
        ]);
        for (const [index, expectedRole] of expectedRoles.entries()) {
          const awsStep = awsSteps[index] ?? '';
          const awsStepIndex = steps.indexOf(awsStep);
          if (
            !awsStep.includes(`role-to-assume: ${expectedRole}`) ||
            !awsStep.includes(`role-session-name: ${expectedSessions[index]}`) ||
            ([0, 3, 4, 7].includes(index) &&
              !exactReleaseReconciliationJournalSessionPolicy(awsStep)) ||
            (![0, 3, 4, 7].includes(index) && awsStep.includes('inline-session-policy:')) ||
            (liveChecks.has(index) &&
              !exactReleaseReconciliationLiveJournalCheck(
                steps[awsStepIndex + 1] ?? '',
                liveChecks.get(index),
              ))
          ) {
            fail(`release reconciliation OIDC session ${index + 1} is not exact`);
          }
        }
      } else if (isReleaseSuccessorFence) {
        const captureStep = steps[firstAwsIndex + 1] ?? '';
        const fenceStep = steps[firstAwsIndex + 2] ?? '';
        const uploadStep = steps.at(-1) ?? '';
        if (
          !awsSteps[0]?.includes(
            'role-to-assume: ${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
          ) ||
          !awsSteps[0]?.includes('role-session-name: e7-release-fence-${{ github.run_id }}') ||
          !exactReleaseSuccessorFenceSessionPolicy(awsSteps[0])
        ) {
          fail('release successor fence must use the exact bounded journal OIDC session');
        }
        for (const fragment of [
          'release-successor-cli.mjs capture-caller-runtime',
          '--caller-identity-output .stage7/fence-private/caller-identity.json',
          '--aws-version-output .stage7/fence-private/aws-version.txt',
          'release-successor-cli.mjs capture-journal-role-authority',
          '--journal-role-arn "${STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN}"',
          '--permissions-boundary-arn "${STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN}"',
          '--output .stage7/fence-private/live-journal-role-effective-permissions.json',
          '--get-role-output .stage7/fence-private/role-audit.json',
        ]) {
          if (!captureStep.includes(fragment)) {
            fail(`release successor fence live authority capture is missing: ${fragment}`);
          }
        }
        for (const fragment of [
          'release-successor-cli.mjs fence-release',
          '--source-run-id "${GITHUB_RUN_ID}"',
          '--source-run-attempt "${GITHUB_RUN_ATTEMPT}"',
          '--candidate-sha "${{ inputs.candidate_sha }}"',
          '--release-id "${{ inputs.release_id }}"',
          '--config .stage7/fence-private/stage7-config.json',
          '--rb-binding .stage7/rollback-resilience/stage7-rollback-resilience-source-binding.json',
          '--rb-run .stage7/rollback-resilience/stage7-rollback-resilience-protected-run.json',
          '--rb-completion .stage7/rollback-resilience/stage7-rollback-resilience-complete.json',
          '--pre-fence-gate .stage7/reconciliation/stage7-release-pre-fence-gate.json',
          '--aws-auth .stage7/aws-auth/aws-auth.json',
          '--journal-role-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json',
          '--reconciliation-recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json',
          '--live-effective-permissions .stage7/fence-private/live-journal-role-effective-permissions.json',
          '--output .stage7/fence-public/release-successor-completion-fence.json',
          'pnpm release:scan -- --pre-upload .stage7/fence-public/release-successor-completion-fence.json',
        ]) {
          if (!fenceStep.includes(fragment)) {
            fail(`release successor fence producer is missing: ${fragment}`);
          }
        }
        if (
          !uploadStep.includes('uses: actions/upload-artifact@') ||
          !uploadStep.includes('name: stage7-release-successor-fence') ||
          !uploadStep.includes(
            'path: .stage7/fence-public/release-successor-completion-fence.json',
          ) ||
          !uploadStep.includes('if-no-files-found: error')
        ) {
          fail('release successor fence upload must be the final exact artifact step');
        }
      } else if (isReleasePostdeploy) {
        const expectedRoles = [
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
        ];
        const sessionIndexes = awsSteps.map((step) => steps.indexOf(step));
        for (const [index, expectedRole] of expectedRoles.entries()) {
          const awsStep = awsSteps[index] ?? '';
          if (!awsStep.includes(`role-to-assume: ${expectedRole}`)) {
            fail(`${id} OIDC session ${index + 1} must assume ${expectedRole}`);
          }
          const authorityStep = steps[(sessionIndexes[index] ?? -2) + 1] ?? '';
          const expectedGuard = index === 1 ? '--aws-deploy' : '--aws-read';
          if (
            !authorityStep.includes('pnpm release:preflight') ||
            !authorityStep.includes(expectedGuard) ||
            !authorityStep.includes('--manifest .stage7/candidate-manifest/candidate-manifest.json')
          ) {
            fail(
              `${id} must revalidate ${expectedGuard} immediately after OIDC session ${index + 1}`,
            );
          }
          if (
            expectedGuard === '--aws-deploy' &&
            !authorityStep.includes('CONFIRM_DEPLOY: ${{ inputs.confirm_deploy }}')
          ) {
            fail(`${id} must bind the explicit deploy confirmation at OIDC session ${index + 1}`);
          }
        }
      } else if (isEmergencyRecovery) {
        const expectedRoles = [
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
        ];
        const expectedGuards = ['--aws-read', '--aws-rollback', '--aws-read'];
        const expectedSessions = [
          'e7-emergency-observe-${{ github.run_id }}',
          'e7-emergency-recovery-${{ github.run_id }}',
          'e7-emergency-read-${{ github.run_id }}',
        ];
        const expectedOperations = [
          'capture-rollback-candidate-aws',
          '--recover-if-active',
          '--post-versioned-rollback',
        ];
        const sessionIndexes = awsSteps.map((step) => steps.indexOf(step));
        for (const [index, expectedRole] of expectedRoles.entries()) {
          const awsStep = awsSteps[index] ?? '';
          if (
            !awsStep.includes(`role-to-assume: ${expectedRole}`) ||
            !awsStep.includes(`role-session-name: ${expectedSessions[index]}`)
          ) {
            fail(`${id} OIDC session ${index + 1} must assume ${expectedRole}`);
          }
          const authorityStep = steps[(sessionIndexes[index] ?? -2) + 1] ?? '';
          const operationStep = steps[(sessionIndexes[index] ?? -3) + 2] ?? '';
          if (
            !authorityStep.includes('pnpm release:preflight') ||
            !authorityStep.includes(expectedGuards[index])
          ) {
            fail(`${id} must revalidate ${expectedGuards[index]} after OIDC session ${index + 1}`);
          }
          if (!operationStep.includes(expectedOperations[index])) {
            fail(`${id} must perform the bounded operation after OIDC session ${index + 1}`);
          }
          if (
            index === 0 &&
            (!authorityStep.includes('--no-write') ||
              awsStep.includes('STAGE7_AWS_ROLLBACK_ROLE_ARN'))
          ) {
            fail(`${id} healthy observation must remain under read-only authority`);
          }
          if (
            index === 1 &&
            [awsStep, authorityStep, operationStep].some(
              (step) => !step.includes("steps.downstream.outputs.healthy != 'true'"),
            )
          ) {
            fail(`${id} rollback authority must exist only in the unhealthy branch`);
          }
        }
      } else if (isReleaseRollback) {
        const expectedRoles = [
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
        ];
        const expectedGuards = [
          '--aws-read',
          '--aws-rollback',
          '--aws-read',
          '--aws-rollback',
          '--aws-read',
        ];
        const expectedOperations = [
          '--prepare-versioned-rollback-pending',
          'execute-versioned-rollback',
          '--post-versioned-rollback',
          'execute-versioned-rollback',
          '--post-versioned-repromotion',
        ];
        const sessionIndexes = awsSteps.map((step) => steps.indexOf(step));
        for (const [index, expectedRole] of expectedRoles.entries()) {
          if (!awsSteps[index]?.includes(`role-to-assume: ${expectedRole}`)) {
            fail(`${id} OIDC session ${index + 1} must assume ${expectedRole}`);
          }
          const authorityStep = steps[(sessionIndexes[index] ?? -2) + 1] ?? '';
          const operationStep = steps[(sessionIndexes[index] ?? -3) + 2] ?? '';
          if (
            !authorityStep.includes('pnpm release:preflight') ||
            !authorityStep.includes(expectedGuards[index]) ||
            !authorityStep.includes('--manifest .stage7/candidate-manifest/candidate-manifest.json')
          ) {
            fail(`${id} must revalidate ${expectedGuards[index]} after OIDC session ${index + 1}`);
          }
          if (
            expectedGuards[index] === '--aws-rollback' &&
            !authorityStep.includes('CONFIRM_DEPLOY: ${{ inputs.confirm_deploy }}')
          ) {
            fail(`${id} must bind explicit rollback confirmation at OIDC session ${index + 1}`);
          }
          if (!operationStep.includes(expectedOperations[index])) {
            fail(`${id} must perform the bounded operation after OIDC session ${index + 1}`);
          }
        }
      } else if (isPrereleaseExternal) {
        const expectedRoles = [
          '${{ vars.STAGE7_PRERELEASE_AWS_READ_ROLE_ARN }}',
          '${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}',
          '${{ vars.STAGE7_PRERELEASE_AWS_READ_ROLE_ARN }}',
        ];
        const sessionIndexes = awsSteps.map((step) => steps.indexOf(step));
        for (const [index, role] of expectedRoles.entries()) {
          if (!awsSteps[index]?.includes(`role-to-assume: ${role}`)) {
            fail(`${id} OIDC session ${index + 1} must assume ${role}`);
          }
        }
        for (const sessionName of [
          'role-session-name: e7pre-read-${{ github.run_id }}-${{ github.run_attempt }}',
          'role-session-name: e7pre-${{ github.job }}-${{ github.run_id }}',
          'role-session-name: e7pre-external-read-${{ github.run_id }}-${{ github.run_attempt }}',
        ]) {
          if (!block.includes(sessionName)) {
            fail(`${id} must bind every read authority session to run id and attempt`);
          }
        }
        const readAuthority = steps[(sessionIndexes[0] ?? -2) + 1] ?? '';
        const activationCapture = steps[(sessionIndexes[1] ?? 0) - 1] ?? '';
        const deployAuthority = steps[(sessionIndexes[1] ?? -2) + 1] ?? '';
        const accessMaterialization = steps[(sessionIndexes[2] ?? -3) + 1] ?? '';
        const finalReadAuthority = steps[(sessionIndexes[2] ?? -3) + 2] ?? '';
        if (
          !readAuthority.includes('pnpm release:preflight') ||
          !readAuthority.includes('--aws-read') ||
          !readAuthority.includes(
            '--manifest .stage7/candidate-manifest/candidate-manifest.json',
          ) ||
          !readAuthority.includes('pnpm release:verify:observability')
        ) {
          fail(`${id} must verify observability immediately after read-role OIDC`);
        }
        if (
          !activationCapture.includes(
            'name: Capture fresh activation safety under read authority',
          ) ||
          !activationCapture.includes('GITHUB_TOKEN: ${{ github.token }}') ||
          !activationCapture.includes('pnpm release:prerelease-safety -- capture-live') ||
          !activationCapture.includes('--phase activation') ||
          !activationCapture.includes(
            '--output "${STAGE7_EVIDENCE_ROOT}/prerelease-activation-live-safety-recheck.json"',
          ) ||
          !activationCapture.includes(
            '--readiness .stage7/prerelease-safety/prerelease-safety-readiness.json',
          )
        ) {
          fail(
            `${id} activation live safety capture must remain under read authority immediately before deploy-role OIDC`,
          );
        }
        if (
          !deployAuthority.includes('pnpm release:preflight') ||
          !deployAuthority.includes('--aws-deploy') ||
          !deployAuthority.includes(
            '--manifest .stage7/candidate-manifest/candidate-manifest.json',
          ) ||
          !deployAuthority.includes('pnpm release:activate') ||
          !deployAuthority.includes('CONFIRM_DEPLOY: ${{ inputs.confirm_deploy }}')
        ) {
          fail(`${id} must revalidate deploy authority immediately before activation`);
        }
        if (
          !accessMaterialization.includes(
            'name: Materialize one-use CloudFront access proofs without disclosure',
          ) ||
          !finalReadAuthority.includes('pnpm release:preflight') ||
          !finalReadAuthority.includes('--aws-read') ||
          !finalReadAuthority.includes(
            '--manifest .stage7/candidate-manifest/candidate-manifest.json',
          ) ||
          !finalReadAuthority.includes(
            'pnpm release:smoke -- --scope prerelease --manifest .stage7/candidate-manifest/candidate-manifest.json --synthetic-only --external-uat --non-public',
          )
        ) {
          fail(`${id} must re-assume read authority before external smoke`);
        }
      } else {
        if (!block.includes(`role-to-assume: ${role}`)) {
          fail(`${id} is missing its OIDC guard: role-to-assume: ${role}`);
        }
        const authorityStep = steps[firstAwsIndex + 1] ?? '';
        if (
          !authorityStep.includes('pnpm release:preflight') ||
          !authorityStep.includes(guard) ||
          (!isPrefreezeBuild &&
            !authorityStep.includes(
              '--manifest .stage7/candidate-manifest/candidate-manifest.json',
            )) ||
          (isPrefreezeBuild &&
            (!authorityStep.includes('--aws-read') ||
              !authorityStep.includes('--approved-environment') ||
              !authorityStep.includes('--no-write') ||
              !authorityStep.includes('--evidence "${STAGE7_EVIDENCE_ROOT}/prefreeze.json"')))
        ) {
          fail(`${id} must revalidate ${guard} immediately after OIDC`);
        }
        if (
          (guard === '--aws-deploy' || guard === '--aws-rollback') &&
          !authorityStep.includes('CONFIRM_DEPLOY: ${{ inputs.confirm_deploy }}')
        ) {
          fail(`${id} must bind explicit deploy confirmation immediately after OIDC`);
        }
        if (
          guard === '--sandbox-authorized' &&
          !authorityStep.includes("CONFIRM_SANDBOX_SMOKE: 'true'")
        ) {
          fail(`${id} must bind explicit sandbox confirmation immediately after OIDC`);
        }
      }
    } else if (awsSteps.length > 0 || /\bid-token:\s*write\b/u.test(block)) {
      fail(`${id} must not obtain an AWS OIDC token`);
    }
    if (spec.crossRun.has(id)) {
      for (const fragment of STAGE6_DOWNLOAD_FRAGMENTS) {
        if (!block.includes(fragment)) fail(`${id} is missing exact Stage 6 evidence: ${fragment}`);
      }
    }
  }
  if (
    count(source, 'STAGE7_CONFIG_B64: ${{ vars.' + spec.configVariable + ' }}') !==
    spec.configJobs.size
  ) {
    fail('the protected Stage 7 config channel must exist only in its required jobs');
  }
  const executeCount = count(source, '--execute');
  if (releaseSpec === spec && executeCount !== 0) {
    fail('unscoped execute flags are forbidden in the full release workflow');
  }
  if (
    prereleaseSpec === spec &&
    (executeCount !== 1 ||
      !workflowJobs(source).get('cleanup')?.includes('pnpm release:cleanup -- --scope prerelease'))
  ) {
    fail('the only execute flag must be the protected ephemeral cleanup');
  }
  return errors;
};

const validateBuildOnce = (name, source, block, { prerelease }) => {
  const errors = [];
  const fail = (message) => errors.push(`${name}: ${message}`);
  const ordered = [
    'pnpm build',
    'pnpm release:build',
    prerelease
      ? 'pnpm infra:synth:release -- --scope prerelease --initial-release --output output/release/build/iac'
      : 'pnpm infra:synth:release -- --versioned-update --output output/release/build/iac',
    prerelease
      ? 'pnpm release:scan -- --scope prerelease --pre-upload output/release/build/api'
      : 'pnpm release:scan -- --pre-upload output/release/build/api',
    'id: candidate-artifact',
    'SOURCE_ARTIFACT_ID: ${{ steps.candidate-artifact.outputs.artifact-id }}',
    'SOURCE_ARTIFACT_SHA256: ${{ steps.candidate-artifact.outputs.artifact-digest }}',
    'pnpm release:manifest --',
    'name: stage7-',
  ];
  let previous = -1;
  for (const fragment of ordered) {
    const index = block.indexOf(fragment, previous + 1);
    if (index === -1 || index <= previous) {
      fail(`build-once order is invalid at: ${fragment}`);
      break;
    }
    previous = index;
  }
  if (count(source, 'pnpm build') !== 1 || count(source, 'pnpm release:build') !== 1) {
    fail('the application must be built and packaged exactly once');
  }
  for (const buildPath of CANONICAL_BUILD_PATHS) {
    if (!block.includes(buildPath)) fail(`canonical build output is missing: ${buildPath}`);
  }
  if (
    /apps\/(?:api|web)\/dist|stage7-cloud-assembly|output\/release\/build\/iac\/output/iu.test(
      source,
    )
  ) {
    fail('legacy or nested build paths are forbidden');
  }
  const upload = stepBlocks(block).find((step) => step.includes('id: candidate-artifact')) ?? '';
  if (upload.includes('candidate-manifest.json')) {
    fail('candidate upload must precede and exclude the freeze manifest');
  }
  if (!block.includes('--freeze-existing') || !block.includes('--source-artifact-id')) {
    fail('freeze manifest must bind the uploaded artifact ID and digest without rebuilding');
  }
  if (prerelease) {
    if (!block.includes('--scope prerelease --freeze-existing') || /\s--tag(?:\s|$)/u.test(block)) {
      fail('prerelease freeze must use EPHEMERAL_PRERELEASE scope without a tag');
    }
  } else if (
    !block.includes('--tag "${STAGE7_RELEASE_TAG}"') ||
    !block.includes('--pre-freeze-evidence "${STAGE7_EVIDENCE_ROOT}/prefreeze.json"')
  ) {
    fail('full release freeze must bind the immutable release tag and pre-freeze proof');
  }
  if (!prerelease) {
    const steps = stepBlocks(block);
    const buildStep = steps.find((step) =>
      step.includes('name: Build and package the application once without cloud credentials'),
    );
    const awsStep = steps.find((step) =>
      step.includes('uses: aws-actions/configure-aws-credentials@'),
    );
    const synthStep = steps.find((step) =>
      step.includes('name: Synthesize the frozen infrastructure under bounded read authority'),
    );
    const removalStep = steps.find((step) =>
      step.includes('name: Remove the temporary AWS credentials before scanning and freezing'),
    );
    const scanStep = steps.find((step) =>
      step.includes('name: Scan the candidate only after cloud credentials are removed'),
    );
    const buildIndex = steps.indexOf(buildStep);
    const awsIndex = steps.indexOf(awsStep);
    const synthIndex = steps.indexOf(synthStep);
    const removalIndex = steps.indexOf(removalStep);
    const scanIndex = steps.indexOf(scanStep);
    if (
      buildIndex < 0 ||
      awsIndex <= buildIndex ||
      synthIndex <= awsIndex ||
      removalIndex <= synthIndex ||
      scanIndex <= removalIndex ||
      !buildStep?.includes('pnpm build') ||
      !buildStep?.includes('pnpm release:build') ||
      synthStep?.includes('pnpm build') ||
      synthStep?.includes('pnpm release:build')
    ) {
      fail(
        'application build must finish before AWS OIDC and scanning must follow credential removal',
      );
    }
    for (const variable of [
      'AWS_ACCESS_KEY_ID',
      'AWS_SECRET_ACCESS_KEY',
      'AWS_SESSION_TOKEN',
      'AWS_SECURITY_TOKEN',
    ]) {
      const absence = `test -z "\${${variable}:-}"`;
      if (!buildStep?.includes(absence) || !scanStep?.includes(absence)) {
        fail(`build and scan must prove ${variable} is absent`);
      }
      if (
        !removalStep?.includes(
          `unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN`,
        ) ||
        !removalStep?.includes(`printf '${variable}=\\n'`)
      ) {
        fail(`temporary AWS credential must be cleared: ${variable}`);
      }
    }
  }
  return errors;
};

const validatePinnedZap = (name, block, { prerelease }) => {
  const errors = [];
  const fail = (message) => errors.push(`${name}: ${message}`);
  const prepare = prerelease
    ? 'pnpm release:scan -- --scope prerelease --prepare-zap-target "${target}" --deployment "${STAGE7_EVIDENCE_ROOT}" --non-public'
    : 'pnpm release:scan -- --scope full --prepare-zap-target "${target}"';
  const validation = prerelease
    ? '--deployed-edge --headers --zap-passive-only --non-public'
    : '--deployed-edge --headers --zap-passive-only --passive-only';
  for (const fragment of [
    prepare,
    'node scripts/stage7/zap-passive-inventory.mjs create',
    'node scripts/stage7/zap-passive-capture.mjs',
    '--target-file "${target}"',
    '--openapi output/architecture/openapi.yaml',
    '--output "${inventory}"',
    '--inventory "${inventory}"',
    '--report "${report}"',
    '--count "${request_count_file}"',
    '--capture "${capture}"',
    '--rules scripts/stage7/zap-passive-rules.tsv',
    '--image-digest zaproxy/zap-stable@sha256:51dbcc578b217ea7563b22a6948f5f41dd2002936fc5148300077f988663b4aa',
    'test "${request_count}" = \'6\'',
    'STAGE7_ZAP_INVENTORY=%s\\n',
    'STAGE7_ZAP_REPORT=%s\\n',
    'STAGE7_ZAP_CAPTURE=%s\\n',
    'STAGE7_ZAP_REQUEST_COUNT=%s\\n',
    'STAGE7_ZAP_RULESET=%s\\n',
    'STAGE7_ZAP_VERSION=2.16.1\\n',
    validation,
  ]) {
    if (!block.includes(fragment)) fail(`pinned passive ZAP contract is missing: ${fragment}`);
  }
  const preflightIndex = block.indexOf('pnpm release:preflight');
  const inventoryIndex = block.indexOf('node scripts/stage7/zap-passive-inventory.mjs create');
  const captureIndex = block.indexOf('node scripts/stage7/zap-passive-capture.mjs');
  const validationIndex = block.lastIndexOf(validation);
  if (
    preflightIndex === -1 ||
    inventoryIndex <= preflightIndex ||
    captureIndex <= inventoryIndex ||
    validationIndex <= captureIndex
  ) {
    fail('ZAP capture must run after authority and before fail-closed report validation');
  }
  if (/zap-(?:full|api)-scan|--active|\bspider\b|ajaxSpider|ascan/iu.test(block)) {
    fail('active or unbounded ZAP scans are forbidden');
  }
  return errors;
};

const validateSandboxWrapper = (name, block, { prerelease, requestProducer }) => {
  const errors = [];
  const fail = (message) => errors.push(`${name}: ${message}`);
  const materialize = stepBlocks(block).find((step) =>
    step.includes('name: Materialize the original one-use AUTH-E6-02 capability'),
  );
  const wrapper = stepBlocks(block).find((step) => step.includes('pnpm release:sandbox-smoke'));
  const executionClaim = stepBlocks(block).find((step) =>
    step.includes(
      'name: Verify protected approval and mint the exact one-use claim before credentials',
    ),
  );
  const claimScope = prerelease ? 'prerelease' : 'full';
  const protectedEnvironment = prerelease
    ? 'assessment-prerelease-external'
    : 'assessment-release-sandbox';
  for (const fragment of [
    'name: Emit the exact sandbox execution approval request without credentials',
    `pnpm release:sandbox-claim -- --request --scope ${claimScope} --output "\${request}"`,
    'request="${STAGE7_EVIDENCE_ROOT}/sandbox-execution-request.json"',
    'request_sha="$(sha256sum "${request}" | cut -d \' \' -f 1)"',
    `Review sandbox-execution-request.json, then approve ${protectedEnvironment} with this exact comment:`,
    'STAGE7_SANDBOX_CLAIM_REQUEST_SHA256=${request_sha}',
    'sandbox-execution-request.json',
  ]) {
    if (!requestProducer?.includes(fragment)) {
      fail(`sandbox approval request handoff is missing: ${fragment}`);
    }
  }
  const requestStep = stepBlocks(requestProducer ?? '').find((step) =>
    step.includes('name: Emit the exact sandbox execution approval request without credentials'),
  );
  if (
    requestStep === undefined ||
    /secrets\.|GITHUB_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|SANDBOX_(?:PRIVATE|PUBLIC)_KEY|EXECUTION_CLAIM_B64/iu.test(
      requestStep,
    )
  ) {
    fail('sandbox approval request producer must contain no secrets or authority');
  }
  if (!prerelease && !requestStep?.includes('pnpm release:scan -- --pre-upload "${request}"')) {
    fail('full sandbox approval request must be scanned before its internal upload');
  }
  const producerRequestIndex = requestProducer?.indexOf(
    'name: Emit the exact sandbox execution approval request without credentials',
  );
  const producerCredentialIndex = requestProducer?.indexOf(
    'uses: aws-actions/configure-aws-credentials@61815dcd50bd041e203e49132bacad1fd04d2708',
  );
  if (
    producerRequestIndex === undefined ||
    producerRequestIndex < 0 ||
    (producerCredentialIndex !== undefined &&
      producerCredentialIndex >= 0 &&
      producerRequestIndex > producerCredentialIndex)
  ) {
    fail('sandbox approval request must be emitted before credentials');
  }
  for (const fragment of [
    'STAGE6_SANDBOX_AUTHORIZATION_B64: ${{ vars.STAGE6_SANDBOX_AUTHORIZATION_B64 }}',
    'test -n "${STAGE6_SANDBOX_AUTHORIZATION_B64}"',
    'umask 077',
    'target="${RUNNER_TEMP}/stage6-sandbox-authorization.json"',
    'printf \'%s\' "${STAGE6_SANDBOX_AUTHORIZATION_B64}" | base64 --decode > "${target}"',
    'chmod 600 "${target}"',
    'test "$(stat -c \'%a\' "${target}")" = \'600\'',
    "JSON.parse(fs.readFileSync(process.env.AUTHORIZATION_PATH, 'utf8'))",
    'printf \'STAGE6_SANDBOX_AUTHORIZATION=%s\\n\' "${target}" >> "${GITHUB_ENV}"',
  ]) {
    if (!materialize?.includes(fragment)) {
      fail(`one-use AUTH-E6-02 materialization is missing: ${fragment}`);
    }
  }
  if (/(?:echo|tee|set\s+-x)[^\n]*STAGE6_SANDBOX_AUTHORIZATION_B64/iu.test(materialize ?? '')) {
    fail('one-use AUTH-E6-02 payload must never be printed');
  }
  for (const fragment of [
    'EXPECTED_STAGE7_CONFIG_SHA256: ${{ inputs.config_sha256 }}',
    'GITHUB_TOKEN: ${{ github.token }}',
    `STAGE7_PROTECTED_ENVIRONMENT: ${protectedEnvironment}`,
    'test -z "${AWS_ACCESS_KEY_ID:-}"',
    'test -z "${AWS_SECRET_ACCESS_KEY:-}"',
    'test -z "${AWS_SESSION_TOKEN:-}"',
    'test -z "${AWS_SECURITY_TOKEN:-}"',
    'sandbox-execution-request.json"',
    'claim="${RUNNER_TEMP}/stage7-sandbox-execution-claim.capability.json"',
    'receipt="${RUNNER_TEMP}/stage7-sandbox-execution-claim.json"',
    'chmod 600 "${request}"',
    'test ! -e "${claim}"',
    'test ! -e "${receipt}"',
    `pnpm release:sandbox-claim -- --approve --scope ${claimScope} --request "\${request}" --claim "\${claim}" --receipt "\${receipt}"`,
    'chmod 600 "${claim}" "${receipt}"',
    'test "$(stat -c \'%a\' "${claim}")" = \'600\'',
    'test "$(stat -c \'%a\' "${receipt}")" = \'600\'',
    'printf \'STAGE7_SANDBOX_EXECUTION_CLAIM=%s\\n\' "${claim}" >> "${GITHUB_ENV}"',
    'printf \'STAGE7_SANDBOX_CLAIM_RECEIPT=%s\\n\' "${receipt}" >> "${GITHUB_ENV}"',
    `printf 'STAGE7_SANDBOX_CLAIM_SCOPE=${claimScope}\\n' >> "\${GITHUB_ENV}"`,
  ]) {
    if (!executionClaim?.includes(fragment)) {
      fail(`one-use sandbox execution claim preflight is missing: ${fragment}`);
    }
  }
  if (block.includes('STAGE7_SANDBOX_EXECUTION_CLAIM_B64')) {
    fail('mutable protected sandbox claim variables are forbidden');
  }
  if (!block.includes('actions: read')) {
    fail('sandbox claim approval requires read-only GitHub Actions authority');
  }
  if (
    !prerelease &&
    !block.includes('name: Download the exact sandbox execution approval request')
  ) {
    fail('sandbox claim approval must download the exact request artifact');
  }
  const command = prerelease
    ? 'pnpm release:sandbox-smoke -- --scope prerelease --manifest .stage7/candidate-manifest/candidate-manifest.json'
    : 'pnpm release:sandbox-smoke -- --scope full --manifest .stage7/candidate-manifest/candidate-manifest.json --deployment .stage7/web --approved-environment';
  const preflight = prerelease
    ? 'pnpm release:preflight -- --scope prerelease --sandbox-authorized --manifest .stage7/candidate-manifest/candidate-manifest.json'
    : 'pnpm release:preflight -- --scope full --sandbox-authorized --manifest .stage7/candidate-manifest/candidate-manifest.json --approved-environment';
  if (!block.includes(preflight)) fail(`guarded sandbox wrapper is missing: ${preflight}`);
  for (const fragment of [
    command,
    ...(prerelease
      ? [
          '--deployment .stage7/deployment',
          '--safety-readiness .stage7/prerelease-safety/prerelease-safety-readiness.json',
          '--deployment-evidence "${STAGE7_EVIDENCE_ROOT}/deployment.json"',
          '--live-safety-recheck "${STAGE7_EVIDENCE_ROOT}/prerelease-sandbox-live-safety-recheck.json"',
          '--approved-environment --non-public',
        ]
      : []),
    prerelease
      ? 'STAGE7_PROTECTED_ENVIRONMENT: assessment-prerelease-external'
      : 'STAGE7_PROTECTED_ENVIRONMENT: assessment-release-sandbox',
    'STAGE6_SANDBOX_EXECUTION: EXECUTE_AUTH02_ONCE',
    'STAGE6_SANDBOX_KILL_SWITCH: ARMED_AUTH02',
    "STAGE6_SANDBOX_MUTATION_LIMIT: '1'",
    "STAGE6_SANDBOX_FIXTURE_AUTHORIZED: 'YES'",
    'STAGE6_SANDBOX_ORIGIN: https://sandbox.wompi.co',
    'EXPECTED_STAGE7_CONFIG_SHA256: ${{ inputs.config_sha256 }}',
  ]) {
    if (!wrapper?.includes(fragment)) fail(`guarded sandbox wrapper is missing: ${fragment}`);
  }
  for (const secret of SANDBOX_SECRET_NAMES) {
    if (!wrapper?.includes(`${secret}: \${{ secrets.${secret} }}`)) {
      fail(`guarded sandbox wrapper is missing protected ${secret}`);
    }
  }
  if (count(block, 'pnpm release:sandbox-smoke') !== 1) {
    fail('the Stage 7 sandbox wrapper must execute exactly once');
  }
  const materializeIndex = block.indexOf(
    'name: Materialize the original one-use AUTH-E6-02 capability',
  );
  const claimIndex = block.indexOf(
    'name: Verify protected approval and mint the exact one-use claim before credentials',
  );
  const firstCredentialIndex = block.indexOf(
    'uses: aws-actions/configure-aws-credentials@61815dcd50bd041e203e49132bacad1fd04d2708',
  );
  const preflightIndex = block.lastIndexOf('--sandbox-authorized');
  const wrapperIndex = block.indexOf('pnpm release:sandbox-smoke');
  if (
    materializeIndex === -1 ||
    claimIndex <= materializeIndex ||
    firstCredentialIndex <= claimIndex ||
    preflightIndex <= materializeIndex ||
    wrapperIndex <= preflightIndex
  ) {
    fail(
      'AUTH-E6-02 and the exact execution claim must be validated before credentials and sandbox execution',
    );
  }
  return errors;
};

const validatePrivateSmokeInputs = (name, postdeploy, rollback) => {
  const errors = [];
  const fail = (message) => errors.push(`${name}: ${message}`);
  const channels = [
    stepBlocks(postdeploy).find((step) =>
      step.includes('name: Materialize private full-release smoke inputs before activation'),
    ),
    stepBlocks(rollback).find((step) =>
      step.includes('name: Materialize private inputs for the RB-E7-05 pending canary'),
    ),
  ];
  const validations = [
    stepBlocks(postdeploy).find((step) =>
      step.includes('name: Validate private smoke binding locally before candidate activation'),
    ),
    stepBlocks(rollback).find((step) =>
      step.includes('name: Revalidate private smoke binding locally before the pending producer'),
    ),
  ];
  for (const channel of channels) {
    for (const fragment of [
      'STAGE7_SMOKE_INPUTS_B64: ${{ secrets.STAGE7_SMOKE_INPUTS_B64 }}',
      'test -n "${STAGE7_SMOKE_INPUTS_B64}"',
      'umask 077',
      'target="${RUNNER_TEMP}/stage7-private-smoke-inputs.json"',
      'printf \'%s\' "${STAGE7_SMOKE_INPUTS_B64}" | base64 --decode > "${target}"',
      'chmod 600 "${target}"',
      'test "$(stat -c \'%a\' "${target}")" = \'600\'',
      "JSON.parse(fs.readFileSync(process.env.SMOKE_INPUTS_PATH, 'utf8'))",
      'printf \'STAGE7_SMOKE_INPUTS=%s\\n\' "${target}" >> "${GITHUB_ENV}"',
    ]) {
      if (!channel?.includes(fragment)) fail(`private smoke input channel is missing: ${fragment}`);
    }
    if (/(?:echo|tee|set\s+-x)[^\n]*STAGE7_SMOKE_INPUTS_B64/iu.test(channel ?? '')) {
      fail('private smoke inputs must never be printed');
    }
  }
  for (const [index, validation] of validations.entries()) {
    const evidenceName =
      index === 0 ? 'smoke-input-preflight.json' : 'rollback-smoke-input-preflight.json';
    for (const fragment of [
      'STAGE7_PROTECTED_ENVIRONMENT: assessment-release',
      'pnpm release:preflight -- --scope full --smoke-inputs --manifest .stage7/candidate-manifest/candidate-manifest.json --deployment .stage7/web --approved-environment',
      `--evidence "\${STAGE7_EVIDENCE_ROOT}/${evidenceName}"`,
      `pnpm release:scan -- --pre-upload "\${STAGE7_EVIDENCE_ROOT}/${evidenceName}"`,
    ]) {
      if (!validation?.includes(fragment)) {
        fail(`local private smoke input preflight is missing: ${fragment}`);
      }
    }
  }
  const postReadiness = postdeploy.indexOf('pnpm release:verify:observability');
  const postMaterialize = postdeploy.indexOf(
    'name: Materialize private full-release smoke inputs before activation',
  );
  const postValidation = postdeploy.indexOf(
    'pnpm release:preflight -- --scope full --smoke-inputs',
  );
  const postActivation = postdeploy.indexOf('pnpm release:activate');
  const postSmoke = postdeploy.indexOf('pnpm release:smoke');
  if (
    postReadiness === -1 ||
    postMaterialize <= postReadiness ||
    postValidation <= postMaterialize ||
    postActivation <= postValidation ||
    postSmoke <= postActivation
  ) {
    fail(
      'private smoke inputs must be materialized after readiness and before candidate activation',
    );
  }
  const rollbackMaterialize = rollback.indexOf(
    'name: Materialize private inputs for the RB-E7-05 pending canary',
  );
  const rollbackValidation = rollback.indexOf(
    'pnpm release:preflight -- --scope full --smoke-inputs',
  );
  const pendingProducer = rollback.indexOf('--prepare-versioned-rollback-pending');
  const versionedRollback = rollback.indexOf(
    'execute-versioned-rollback --app .stage7/candidate/iac',
  );
  const finalSmoke = rollback.indexOf('--post-versioned-repromotion');
  if (
    rollbackMaterialize === -1 ||
    rollbackValidation <= rollbackMaterialize ||
    pendingProducer <= rollbackValidation ||
    versionedRollback <= pendingProducer ||
    finalSmoke <= versionedRollback
  ) {
    fail('private smoke inputs must be bound before the RB-E7-05 producer and versioned rollback');
  }
  return errors;
};

const RECONCILIATION_INTENT_ARGUMENTS = [
  ['config', '"${STAGE7_RECONCILIATION_CONFIG}"'],
  ['release-metadata', '.stage7/release-metadata/release-metadata.json'],
  ['candidate-manifest', '.stage7/candidate-manifest/candidate-manifest.json'],
  ['release-plan', '.stage7/release-plan/release-plan.json'],
  ['approved-diff', '.stage7/infra-diff/infra-diff.json'],
  ['raw-diff', '.stage7/infra-diff/infra-diff.txt'],
  ['github-environment-approval', '.stage7/approval/github-environment-approval.json'],
  ['approval', '.stage7/approval/approval.json'],
  ['aws-auth', '.stage7/aws-auth/aws-auth.json'],
  [
    'journal-role-effective-permissions',
    '.stage7/aws-auth/stage7-release-journal-role-effective-permissions.json',
  ],
  ['activation', '.stage7/activation/activation.json'],
  ['web-deployment', '.stage7/web/web.json'],
  ['candidate-record', '.stage7/recovery-probe/versioned-rollback-candidate.json'],
  ['external-authorization', '.stage7/external-authorization/external-authorization.json'],
  ['previous-release-manifest', '.stage7/previous/previous-release-manifest.json'],
  ['previous-source-provenance', '.stage7/previous/previous-source-provenance.json'],
  ['previous-target-compatibility', '.stage7/previous/previous-target-compatibility.json'],
  ['previous-final-disable-provenance', '.stage7/previous/previous-final-disable-provenance.json'],
  ['previous-api-contract-evidence', '.stage7/previous/previous-api-contract-evidence.json'],
  ['previous-pending-evidence', '.stage7/previous/previous-pending-evidence.json'],
  ['previous-smoke-evidence', '.stage7/previous/previous-smoke-evidence.json'],
  ['previous-release-projection-index', '.stage7/previous/previous-release-projection-index.json'],
  ['output', '.stage7/reconciliation-private/release-reconciliation-intent.json'],
];

const exactCliArguments = (step, command, expectedArguments) => {
  if (count(step, command) !== 1) return false;
  const flags = [...step.matchAll(/(?:^|\s)--([a-z][a-z0-9-]*)\s+/gu)].map((match) => match[1]);
  return (
    same(
      flags,
      expectedArguments.map(([flag]) => flag),
    ) && expectedArguments.every(([flag, value]) => step.includes(`--${flag} ${value}`))
  );
};

const validateReleaseReconciliationContract = (name, jobs) => {
  const errors = [];
  const fail = (message) => errors.push(`${name}: ${message}`);
  const intent = jobs.get('release-reconciliation-intent') ?? '';
  const reconciliation = jobs.get('release-reconciliation') ?? '';
  const rollback = jobs.get('rollback-check') ?? '';
  const intentSteps = stepBlocks(intent);
  const reconciliationSteps = stepBlocks(reconciliation);
  const rollbackSteps = stepBlocks(rollback);
  const createIntent = intentSteps.find((step) =>
    step.includes('release-reconciliation-cli.mjs create-intent'),
  );
  const recreateIntent = reconciliationSteps.find((step) =>
    step.includes('release-reconciliation-cli.mjs create-intent'),
  );
  const rollbackIntent = rollbackSteps.find((step) =>
    step.includes('release-reconciliation-cli.mjs create-intent'),
  );
  if (
    jobCondition(intent) !==
      "${{ github.run_attempt == 1 && needs.emergency-recovery.outputs.safe_for_rehearsal == 'true' }}" ||
    !exactCliArguments(
      createIntent ?? '',
      'node scripts/stage7/release-reconciliation-cli.mjs create-intent',
      RECONCILIATION_INTENT_ARGUMENTS,
    ) ||
    !exactCliArguments(
      recreateIntent ?? '',
      'node scripts/stage7/release-reconciliation-cli.mjs create-intent',
      RECONCILIATION_INTENT_ARGUMENTS,
    ) ||
    !exactCliArguments(
      rollbackIntent ?? '',
      'node scripts/stage7/release-reconciliation-cli.mjs create-intent',
      RECONCILIATION_INTENT_ARGUMENTS,
    ) ||
    count(
      `${intent}\n${rollback}\n${reconciliation}`,
      'release-reconciliation-cli.mjs create-intent',
    ) !== 3
  ) {
    fail('release reconciliation intent must bind exactly 22 files into 23 immutable bindings');
  }
  const workspaceConfigSteps = [intentSteps, rollbackSteps, reconciliationSteps].map((steps) =>
    steps.find((step) =>
      step.includes('name: Materialize and validate the approved Stage 7 config'),
    ),
  );
  for (const configStep of workspaceConfigSteps) {
    for (const fragment of [
      "private_root='.stage7/reconciliation-private'",
      'workspace_target="${private_root}/stage7-config.json"',
      'test ! -e "${private_root}"',
      'install -d -m 700 "${private_root}"',
      'install -m 600 "${target}" "${workspace_target}"',
      'test "$(stat -c \'%a\' "${workspace_target}")" = \'600\'',
      'test "$(sha256sum "${workspace_target}" | cut -d \' \' -f 1)" = "${EXPECTED_STAGE7_CONFIG_SHA256}"',
      'node scripts/stage7/cli.mjs config --config "${workspace_target}" > /dev/null',
      'printf \'STAGE7_RECONCILIATION_CONFIG=%s\\n\' "${workspace_target}" >> "${GITHUB_ENV}"',
    ]) {
      if (!configStep?.includes(fragment)) {
        fail(
          'release reconciliation config must be copied byte-exactly into the workspace before source binding',
        );
        break;
      }
    }
  }
  if (
    count(rollback, 'STAGE7_AWS_ROLLBACK_ROLE_ARN: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}') !== 1
  ) {
    fail('rollback-check must bind the exact rollback role before guarded mutation');
  }
  const rollbackGuardArguments = (direction, output) => [
    ['app', '.stage7/candidate/iac'],
    ['manifest', '.stage7/candidate-manifest/candidate-manifest.json'],
    ['previous-manifest', '.stage7/previous/previous-release-manifest.json'],
    ['previous-api-contract-evidence', '.stage7/previous/previous-api-contract-evidence.json'],
    ['previous-pending-evidence', '.stage7/previous/previous-pending-evidence.json'],
    ['previous-smoke-evidence', '.stage7/previous/previous-smoke-evidence.json'],
    ['candidate-record', '.stage7/recovery-probe/versioned-rollback-candidate.json'],
    ['approval', '.stage7/approval/approval.json'],
    ['aws-auth', '.stage7/aws-auth/aws-auth.json'],
    [
      'journal-role-effective-permissions',
      '.stage7/aws-auth/stage7-release-journal-role-effective-permissions.json',
    ],
    [
      'reconciliation-recovery-role-effective-permissions',
      '.stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ],
    ['approved-plan', '.stage7/infra-diff/infra-diff.json'],
    ['deployment-evidence', '.stage7/web/web.json'],
    ['successor-guard-mode', 'ROLLBACK_CHECK'],
    ['reconciliation-intent', '.stage7/reconciliation-private/release-reconciliation-intent.json'],
    ['config', '"${STAGE7_RECONCILIATION_CONFIG}"'],
    ['release-metadata', '.stage7/release-metadata/release-metadata.json'],
    ['candidate-manifest', '.stage7/candidate-manifest/candidate-manifest.json'],
    ['release-plan', '.stage7/release-plan/release-plan.json'],
    ['approved-diff', '.stage7/infra-diff/infra-diff.json'],
    ['raw-diff', '.stage7/infra-diff/infra-diff.txt'],
    ['github-environment-approval', '.stage7/approval/github-environment-approval.json'],
    ['activation', '.stage7/activation/activation.json'],
    ['web-deployment', '.stage7/web/web.json'],
    ['external-authorization', '.stage7/external-authorization/external-authorization.json'],
    ['previous-release-manifest', '.stage7/previous/previous-release-manifest.json'],
    ['previous-source-provenance', '.stage7/previous/previous-source-provenance.json'],
    ['previous-target-compatibility', '.stage7/previous/previous-target-compatibility.json'],
    [
      'previous-final-disable-provenance',
      '.stage7/previous/previous-final-disable-provenance.json',
    ],
    [
      'previous-release-projection-index',
      '.stage7/previous/previous-release-projection-index.json',
    ],
    ['direction', direction],
    ['output', output],
  ];
  const rollbackToPrevious = rollbackSteps.find((step) =>
    step.includes('name: Move API worker and mutable web objects from N to N-1'),
  );
  const repromoteCandidate = rollbackSteps.find((step) =>
    step.includes('name: Restore exactly the captured candidate aliases and mutable web objects'),
  );
  if (
    !exactCliArguments(
      rollbackToPrevious ?? '',
      'node scripts/stage7/aws-ops.mjs execute-versioned-rollback',
      rollbackGuardArguments(
        'ROLLBACK_TO_PREVIOUS',
        '"${STAGE7_EVIDENCE_ROOT}/versioned-rollback-aws-transition.json"',
      ),
    ) ||
    !exactCliArguments(
      repromoteCandidate ?? '',
      'node scripts/stage7/aws-ops.mjs execute-versioned-rollback',
      rollbackGuardArguments(
        'REPROMOTE_CANDIDATE',
        '"${STAGE7_EVIDENCE_ROOT}/versioned-repromotion-aws-transition.json"',
      ),
    )
  ) {
    fail('rollback-check mutations must execute inside the exact same-process successor guard');
  }
  const reconciliationSources = [
    ['stage7-release-metadata', '.stage7/release-metadata'],
    ['stage7-candidate-manifest', '.stage7/candidate-manifest'],
    ['stage7-release-plan', '.stage7/release-plan'],
    ['stage7-infra-diff', '.stage7/infra-diff'],
    ['stage7-approval', '.stage7/approval'],
    ['stage7-aws-auth', '.stage7/aws-auth'],
    ['stage7-activation', '.stage7/activation'],
    ['stage7-web', '.stage7/web'],
    ['stage7-recovery-probe', '.stage7/recovery-probe'],
    ['stage7-external-authorization', '.stage7/external-authorization'],
    ['stage7-previous-release', '.stage7/previous'],
  ];
  for (const [block, expectedSources] of [
    [intent, reconciliationSources],
    [
      rollback,
      [
        ['stage7-candidate', '.stage7/candidate'],
        ...reconciliationSources,
        ['stage7-api', '.stage7/api'],
        ['stage7-data', '.stage7/data'],
        ['stage7-observability', '.stage7/observability'],
      ],
    ],
    [
      reconciliation,
      [
        ['stage7-candidate', '.stage7/candidate'],
        ...reconciliationSources,
        ['stage7-rollback', '.stage7/rollback'],
        ['stage7-observability', '.stage7/observability'],
        ['stage7-smoke', '.stage7/smoke'],
        ['stage7-edge-security', '.stage7/edge'],
        ['stage7-quality', '.stage7/quality'],
        ['stage7-sandbox', '.stage7/sandbox'],
        ['stage7-rollback-resilience', '.stage7/rollback-resilience'],
      ],
    ],
  ]) {
    const downloadSteps = stepBlocks(block).filter((step) =>
      step.includes('uses: actions/download-artifact@'),
    );
    if (
      downloadSteps.length !== expectedSources.length ||
      expectedSources.some(
        ([artifact, directory]) =>
          !downloadSteps.some((step) => {
            const lines = step.split('\n');
            return (
              lines.includes(`          name: ${artifact}`) &&
              lines.includes(`          path: ${directory}`)
            );
          }),
      )
    ) {
      fail('release reconciliation must download the exact producer artifacts into isolated paths');
    }
  }
  const intentOidc = intent.indexOf('uses: aws-actions/configure-aws-credentials@');
  const createIndex = intent.indexOf('release-reconciliation-cli.mjs create-intent');
  const openIndex = intent.indexOf('release-reconciliation-cli.mjs open-journal');
  if (
    createIndex === -1 ||
    intentOidc <= createIndex ||
    openIndex <= intentOidc ||
    intent.includes('uses: actions/upload-artifact@') ||
    !intent.includes(
      'open-journal --intent .stage7/reconciliation-private/release-reconciliation-intent.json --output .stage7/reconciliation-private/release-reconciliation-owner.json',
    )
  ) {
    fail('release reconciliation owner must be opened durably before rollback mutation');
  }
  if (
    jobCondition(reconciliation) !==
      "${{ always() && github.run_attempt == 1 && needs.release-reconciliation-intent.result == 'success' }}" ||
    !reconciliation.includes('ROLLBACK_CHECK_RESULT: ${{ needs.rollback-check.result }}') ||
    !reconciliation.includes(
      'ROLLBACK_RESILIENCE_RESULT: ${{ needs.rollback-resilience.result }}',
    ) ||
    !reconciliation.includes("success) printf 'SUCCESS'") ||
    !reconciliation.includes("failure) printf 'FAILURE'") ||
    !reconciliation.includes("cancelled) printf 'CANCELLED'") ||
    !reconciliation.includes("skipped) printf 'SKIPPED'")
  ) {
    fail('release reconciliation must always classify both original protected conclusions');
  }
  const firstOidc = reconciliation.indexOf('uses: aws-actions/configure-aws-credentials@');
  const authorizationPreflight = reconciliation.indexOf(
    'pnpm release:preflight -- --scope full --external-authorization .stage7/web --approved-environment',
  );
  if (
    authorizationPreflight === -1 ||
    firstOidc <= authorizationPreflight ||
    reconciliation.indexOf('release-reconciliation-cli.mjs create-intent') >= authorizationPreflight
  ) {
    fail('reconciliation external authorization must be validated before any AWS session');
  }

  const phases = [
    { name: 'rollback-check', phase: 'ROLLBACK_CHECK' },
    { name: 'rollback-resilience', phase: 'ROLLBACK_RESILIENCE' },
  ];
  for (const phase of phases) {
    const probe = reconciliationSteps.find((step) =>
      step.includes(`name: Probe or resume the durable ${phase.name} terminal`),
    );
    const converge = reconciliationSteps.find((step) =>
      step.includes(`name: Converge ${phase.name} runtime to the exact candidate N`),
    );
    const completedConverge = reconciliationSteps.find((step) =>
      step.includes(
        'name: Converge completed rollback-resilience runtime to the exact candidate N',
      ),
    );
    const incompleteConverge = reconciliationSteps.find((step) =>
      step.includes(
        'name: Converge incomplete rollback-resilience runtime to the exact candidate N',
      ),
    );
    const fresh = reconciliationSteps.find((step) =>
      step.includes(`name: Capture fresh ${phase.name} drift and authorized candidate smoke`),
    );
    const finalize = reconciliationSteps.find((step) =>
      step.includes(`name: Seal the ${phase.name} terminal and public receipt`),
    );
    const privateRoot = `.stage7/reconciliation-private/${phase.name}`;
    const publicReceipt = `.stage7/reconciliation-public/${phase.name}-reconciliation.json`;
    const commonConvergeArguments = [
      ['intent', '.stage7/reconciliation-private/release-reconciliation-intent.json'],
      ['phase', phase.phase],
      [
        'successor-guard-mode',
        phase.phase === 'ROLLBACK_CHECK' ? 'ROLLBACK_CHECK' : 'INCOMPLETE_RECONCILIATION',
      ],
      [
        'reconciliation-intent',
        '.stage7/reconciliation-private/release-reconciliation-intent.json',
      ],
      ['app', '.stage7/candidate/iac'],
      ['manifest', '.stage7/candidate-manifest/candidate-manifest.json'],
      ...RECONCILIATION_INTENT_ARGUMENTS.slice(0, 18),
      ['previous-manifest', '.stage7/previous/previous-release-manifest.json'],
      ...RECONCILIATION_INTENT_ARGUMENTS.slice(18, -1),
      ['approved-plan', '.stage7/infra-diff/infra-diff.json'],
      ['deployment-evidence', '.stage7/web/web.json'],
      [
        'reconciliation-recovery-role-effective-permissions',
        '.stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json',
      ],
      ['transition-output', `${privateRoot}/versioned-rollback-transition.json`],
      ['output', `${privateRoot}/convergence.json`],
    ];
    const completedConvergeArguments = [
      ...commonConvergeArguments
        .slice(0, -2)
        .map(([flag, value]) => [flag, flag === 'successor-guard-mode' ? 'RECONCILIATION' : value]),
      ['rollback', '.stage7/rollback/rollback.json'],
      ['observability', '.stage7/observability/observability.json'],
      ['smoke-input', '.stage7/smoke/smoke-input-preflight.json'],
      ['smoke', '.stage7/smoke/smoke.json'],
      ['edge', '.stage7/edge/edge-security.json'],
      ['quality', '.stage7/quality/quality.json'],
      ['sandbox', '.stage7/sandbox/sandbox-smoke.json'],
      ['rollback-smoke-input', '.stage7/rollback/rollback-smoke-input-preflight.json'],
      ['pending-producer', '.stage7/rollback/rollback-pending-producer.json'],
      ['pending-egress-closeout', '.stage7/rollback/rollback-pending-egress-closeout.json'],
      ['rollback-smoke', '.stage7/rollback/versioned-rollback-smoke.json'],
      ['repromotion-smoke', '.stage7/rollback/versioned-repromotion-smoke.json'],
      ['journal-cleanup-role', '"${STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN}"'],
      ['assembly', '.stage7/candidate/iac'],
      ['max-polls', '30'],
      ['inputs', '.stage7/reconciliation-private/rollback-premutation/inputs.json'],
      ['rb06', '.stage7/reconciliation-private/rollback-premutation/rb-e7-06.json'],
      ['rb08', '.stage7/reconciliation-private/rollback-premutation/rb-e7-08.json'],
      ['source-binding', '.stage7/reconciliation-private/rollback-premutation/source-binding.json'],
      [
        'protected-run',
        '.stage7/rollback-resilience/stage7-rollback-resilience-protected-run.json',
      ],
      ['completion', '.stage7/rollback-resilience/stage7-rollback-resilience-complete.json'],
      ...commonConvergeArguments.slice(-2),
    ];
    if (
      probe === undefined ||
      count(probe, `--phase ${phase.phase}`) !== 2 ||
      !probe.includes('--original-job-conclusion "${ORIGINAL_JOB_CONCLUSION}"') ||
      !probe.includes('case "${status}" in TERMINAL_ABSENT|TERMINAL_PRESENT)') ||
      !probe.includes('if test "${status}" = \'TERMINAL_PRESENT\'; then') ||
      !probe.includes('release-reconciliation-cli.mjs resume-terminal') ||
      !probe.includes(`--output ${publicReceipt}`)
    ) {
      fail(`${phase.name} reconciliation must probe and resume the exact durable terminal`);
    }
    const convergenceIsExact =
      phase.phase === 'ROLLBACK_CHECK'
        ? exactCliArguments(
            converge ?? '',
            'node scripts/stage7/release-reconciliation-cli.mjs converge-runtime',
            commonConvergeArguments,
          ) &&
          converge?.includes(
            `if: \${{ steps.${phase.name}-probe.outputs.status == 'TERMINAL_ABSENT' }}`,
          )
        : exactCliArguments(
            completedConverge ?? '',
            'node scripts/stage7/release-reconciliation-cli.mjs converge-runtime',
            completedConvergeArguments,
          ) &&
          completedConverge?.includes(
            "if: ${{ steps.rollback-resilience-probe.outputs.status == 'TERMINAL_ABSENT' && needs.rollback-resilience.result == 'success' }}",
          ) &&
          exactCliArguments(
            incompleteConverge ?? '',
            'node scripts/stage7/release-reconciliation-cli.mjs converge-runtime',
            commonConvergeArguments,
          ) &&
          incompleteConverge?.includes(
            "if: ${{ steps.rollback-resilience-probe.outputs.status == 'TERMINAL_ABSENT' && needs.rollback-resilience.result != 'success' }}",
          );
    if (!convergenceIsExact) {
      fail(`${phase.name} reconciliation convergence contract is not exact`);
    }
    const driftSource = 'output/evidence/runtime/stage-7/drift.json';
    if (
      fresh === undefined ||
      !fresh.includes(`STAGE7_EVIDENCE_ROOT: .stage7/reconciliation-private/${phase.name}/fresh`) ||
      !fresh.includes('pnpm release:verify:drift -- --scope full --versioned-update') ||
      !fresh.includes(`test -s ${driftSource}`) ||
      !fresh.includes('test ! -e "${STAGE7_EVIDENCE_ROOT}/drift.json"') ||
      !fresh.includes(`mv -- ${driftSource} "\${STAGE7_EVIDENCE_ROOT}/drift.json"`) ||
      !fresh.includes(
        `--reconciliation-convergence ${privateRoot}/convergence.json --external-authorization-evidence .stage7/external-authorization/external-authorization.json`,
      ) ||
      !fresh.includes('--evidence "${STAGE7_EVIDENCE_ROOT}/smoke.json"') ||
      fresh.indexOf('pnpm release:verify:drift') >= fresh.indexOf('pnpm release:smoke') ||
      fresh.indexOf(`mv -- ${driftSource}`) >= fresh.indexOf('pnpm release:smoke')
    ) {
      fail(`${phase.name} reconciliation must capture fresh phase-bound drift and smoke evidence`);
    }
    if (
      finalize === undefined ||
      !finalize.includes(
        `if: \${{ steps.${phase.name}-probe.outputs.status == 'TERMINAL_ABSENT' }}`,
      ) ||
      !finalize.includes(
        `finalize-runtime --convergence ${privateRoot}/convergence.json --original-job-conclusion "\${ORIGINAL_JOB_CONCLUSION}" --drift-evidence ${privateRoot}/fresh/drift.json --smoke-evidence ${privateRoot}/fresh/smoke.json --output ${publicReceipt}`,
      )
    ) {
      fail(`${phase.name} reconciliation must finalize only fresh bound evidence`);
    }
  }

  const gate = reconciliationSteps.find((step) =>
    step.includes('name: Derive the only eligible pre-publication fence gate'),
  );
  const scan = reconciliationSteps.find((step) =>
    step.includes('name: Scan the exact three-file public reconciliation artifact'),
  );
  const upload = reconciliationSteps.find((step) =>
    step.includes('name: Preserve only the hash-bound reconciliation receipts and gate'),
  );
  const publicFiles = [
    'rollback-check-reconciliation.json',
    'rollback-resilience-reconciliation.json',
    'stage7-release-pre-fence-gate.json',
  ];
  if (
    gate === undefined ||
    !gate.includes(
      'pre-fence --rollback-check .stage7/reconciliation-public/rollback-check-reconciliation.json --rollback-resilience .stage7/reconciliation-public/rollback-resilience-reconciliation.json --evaluated-at "${evaluated_at}" --output .stage7/reconciliation-public/stage7-release-pre-fence-gate.json',
    ) ||
    scan === undefined ||
    !publicFiles.every((file) => scan.includes(file)) ||
    !scan.includes('pnpm release:scan -- --pre-upload') ||
    upload === undefined ||
    !upload.includes('name: stage7-release-reconciliation') ||
    !publicFiles.every((file) => upload.includes(`.stage7/reconciliation-public/${file}`)) ||
    upload.includes('.stage7/reconciliation-private') ||
    upload !== reconciliationSteps.at(-1)
  ) {
    fail('release reconciliation artifact must contain only the exact scanned receipts and gate');
  }
  return errors;
};

export function validateReleaseWorkflow(name, input) {
  const source = normalize(input);
  const errors = validateCommon(name, source, releaseSpec);
  const fail = (message) => errors.push(`${name}: ${message}`);
  const jobs = workflowJobs(source);
  errors.push(...validateReleaseReconciliationContract(name, jobs));
  for (const fragment of [
    'STAGE7_ENVIRONMENT: assessment-release',
    '[[ "${RELEASE_TAG}" =~ ^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-rc\\.[1-9][0-9]*)?$ ]]',
    '[[ "${RELEASE_ID}" =~ ^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$ ]]',
    'test "$(git rev-parse "refs/tags/${RELEASE_TAG}^{commit}")" = "${CANDIDATE_SHA}"',
    'pnpm release:preflight',
    'pnpm release:verify-candidate',
    'pnpm release:build',
    'pnpm release:manifest',
    'pnpm release:scan',
    'pnpm release:plan',
    'pnpm infra:test',
    'pnpm infra:synth:release',
    'pnpm infra:diff:release',
    'pnpm release:deploy:data',
    'pnpm release:seed',
    'pnpm release:deploy:api',
    'pnpm release:deploy:observability',
    'pnpm release:deploy:web',
    'pnpm release:activate',
    'pnpm release:smoke',
    'pnpm release:verify:drift',
    'pnpm release:quality',
    'pnpm release:sandbox-smoke',
    'capture-rollback-candidate-aws',
    'execute-versioned-rollback',
    'finalize-versioned-rollback',
    'recover-versioned-release',
    'pnpm release:publish',
    'pnpm release:verify',
  ]) {
    if (!source.includes(fragment)) fail(`required full release contract is missing: ${fragment}`);
  }
  errors.push(
    ...validateBuildOnce(name, source, jobs.get('build-or-fetch') ?? '', { prerelease: false }),
  );
  if (!jobs.get('approval')?.includes('test "${CONFIRM_DEPLOY}" = \'true\'')) {
    fail('approval must require the explicit confirm_deploy input');
  }

  const metadata = jobs.get('release-metadata') ?? '';
  for (const fragment of [
    'VERSIONED_UPDATE: ${{ inputs.versioned_update }}',
    'test "${VERSIONED_UPDATE}" = \'true\'',
  ]) {
    if (!metadata.includes(fragment))
      fail(`versioned-update release guard is missing: ${fragment}`);
  }
  const build = jobs.get('build-or-fetch') ?? '';
  const prefreeze = stepBlocks(build).find((step) =>
    step.includes('name: Bind the exceptional read-only pre-freeze authority'),
  );
  for (const fragment of [
    'STAGE7_CANDIDATE_SHA: ${{ inputs.candidate_sha }}',
    'STAGE7_RELEASE_ID: ${{ inputs.release_id }}',
    'STAGE7_RELEASE_TAG: ${{ inputs.release_tag }}',
    'pnpm release:preflight -- --aws-read --pre-freeze-synth --approved-environment --no-write',
    '--evidence "${STAGE7_EVIDENCE_ROOT}/prefreeze.json"',
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/prefreeze.json"',
  ]) {
    if (!prefreeze?.includes(fragment))
      fail(`pre-freeze synthesis identity is missing: ${fragment}`);
  }
  if (
    count(source, '--pre-freeze-synth') !== 1 ||
    /--(?:aws-deploy|aws-rollback|aws-cleanup|execute|external-authorization)\b|\bpnpm\s+release:(?:deploy|rollback|cleanup|activate)/iu.test(
      prefreeze ?? '',
    )
  ) {
    fail('pre-freeze synthesis must remain a unique read-only exception');
  }
  for (const fragment of [
    'name: stage7-prefreeze',
    'path: output/evidence/runtime/stage-7/prefreeze.json',
    '--pre-freeze-evidence "${STAGE7_EVIDENCE_ROOT}/prefreeze.json"',
  ]) {
    if (!build.includes(fragment)) fail(`frozen pre-freeze proof is missing: ${fragment}`);
  }
  for (const fragment of [
    'pnpm infra:synth:release -- --versioned-update --output output/release/build/iac',
    'pnpm infra:synth:release -- --versioned-update --verify .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
    'pnpm infra:diff:release -- --versioned-update --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
  ]) {
    if (!source.includes(fragment))
      fail(`versioned-update infrastructure plan is missing: ${fragment}`);
  }

  const awsAuth = jobs.get('aws-auth') ?? '';
  for (const fragment of [
    'STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN: ${{ vars.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN }}',
    'STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN: ${{ vars.STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN }}',
  ]) {
    if (!source.includes(fragment)) {
      fail(`release recovery BASE environment binding is missing: ${fragment}`);
    }
  }
  for (const fragment of [
    'pnpm release:preflight -- --aws-read --manifest .stage7/candidate-manifest/candidate-manifest.json --cloud-assembly .stage7/candidate/iac --journal-role-effective-permissions "${STAGE7_EVIDENCE_ROOT}/stage7-release-journal-role-effective-permissions.json" --reconciliation-recovery-role-effective-permissions "${STAGE7_EVIDENCE_ROOT}/stage7-release-reconciliation-recovery-role-effective-permissions.json" --evidence "${STAGE7_EVIDENCE_ROOT}/aws-auth.json"',
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/aws-auth.json" "${STAGE7_EVIDENCE_ROOT}/stage7-release-journal-role-effective-permissions.json" "${STAGE7_EVIDENCE_ROOT}/stage7-release-reconciliation-recovery-role-effective-permissions.json"',
    'name: stage7-aws-auth',
    'output/evidence/runtime/stage-7/aws-auth.json',
    'output/evidence/runtime/stage-7/stage7-release-journal-role-effective-permissions.json',
    'output/evidence/runtime/stage-7/stage7-release-reconciliation-recovery-role-effective-permissions.json',
  ]) {
    if (!awsAuth.includes(fragment)) {
      fail(`ART-REL-06 effective-permissions evidence is missing: ${fragment}`);
    }
  }
  const awsAuthScan = stepBlocks(awsAuth).find((step) =>
    step.includes('name: Scan the complete AWS authority bundle before upload'),
  );
  const expectedAwsAuthScan =
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/aws-auth.json" "${STAGE7_EVIDENCE_ROOT}/stage7-release-journal-role-effective-permissions.json" "${STAGE7_EVIDENCE_ROOT}/stage7-release-reconciliation-recovery-role-effective-permissions.json"';
  if (
    awsAuthScan === undefined ||
    stepShellCommands(awsAuthScan).length !== 1 ||
    stepShellCommands(awsAuthScan)[0] !== expectedAwsAuthScan
  ) {
    fail('stage7-aws-auth must scan exactly its three public authority files');
  }
  const awsAuthUpload = stepBlocks(awsAuth).find((step) =>
    step.includes('name: Preserve sanitized AWS preflight evidence'),
  );
  const awsAuthUploadPaths = (awsAuthUpload ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('output/evidence/runtime/stage-7/'));
  if (
    !same(awsAuthUploadPaths, [
      'output/evidence/runtime/stage-7/aws-auth.json',
      'output/evidence/runtime/stage-7/stage7-release-journal-role-effective-permissions.json',
      'output/evidence/runtime/stage-7/stage7-release-reconciliation-recovery-role-effective-permissions.json',
    ])
  ) {
    fail('stage7-aws-auth upload must contain exactly its three public authority files');
  }

  const deployApi = jobs.get('deploy-api') ?? '';
  const apiVersioned = stepBlocks(deployApi).find((step) =>
    step.includes('name: Deploy the versioned candidate API and reconciler aliases'),
  );
  if (
    !apiVersioned?.includes('--versioned-update') ||
    count(deployApi, 'pnpm release:deploy:api') !== 1
  ) {
    fail('API deployment must be the single staged versioned-update path');
  }

  const deployWeb = jobs.get('deploy-web') ?? '';
  const webVersioned = stepBlocks(deployWeb).find((step) =>
    step.includes('name: Deploy the versioned candidate web assets'),
  );
  if (
    !webVersioned?.includes('--versioned-update') ||
    count(deployWeb, 'pnpm release:deploy:web') !== 1 ||
    deployWeb.includes('pnpm release:activate')
  ) {
    fail('web deployment must be the staged versioned path and remain inactive before readiness');
  }
  for (const fragment of [
    'pnpm release:preflight -- --scope full --external-authorization-request .stage7/web --evidence "${STAGE7_EVIDENCE_ROOT}/external-authorization-request.json"',
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/web.json" "${STAGE7_EVIDENCE_ROOT}/external-authorization-request.json"',
    'output/evidence/runtime/stage-7/external-authorization-request.json',
    'Download release-external-authorization-request and review its only file, external-authorization-request.json',
    'AUTH-E7-EXT-01/02/03',
    'STAGE7_EXTERNAL_AUTHORIZATIONS_B64',
  ]) {
    if (!deployWeb.includes(fragment))
      fail(`full external-authorization handoff is missing: ${fragment}`);
  }
  const deployWebIndex = deployWeb.indexOf('pnpm release:deploy:web');
  const requestIndex = deployWeb.indexOf('--external-authorization-request .stage7/web');
  const webUploadIndex = deployWeb.indexOf('name: Preserve sanitized web evidence');
  if (deployWebIndex === -1 || requestIndex <= deployWebIndex || webUploadIndex <= requestIndex) {
    fail('full authorization request must be emitted only after the inactive web target exists');
  }
  const webUpload = stepBlocks(deployWeb).find((step) =>
    step.includes('name: Preserve sanitized web evidence'),
  );
  const externalRequestUpload = stepBlocks(deployWeb).find((step) =>
    step.includes('name: Preserve the exact external authorization review request'),
  );
  if (
    !webUpload?.includes('name: stage7-web') ||
    !webUpload?.includes('path: output/evidence/runtime/stage-7/web.json') ||
    webUpload.includes('external-authorization-request.json') ||
    !externalRequestUpload?.includes('name: release-external-authorization-request') ||
    !externalRequestUpload?.includes(
      'path: output/evidence/runtime/stage-7/external-authorization-request.json',
    ) ||
    externalRequestUpload.includes('web.json')
  ) {
    fail('web evidence and its review request must use two exact single-entry artifacts');
  }
  const postdeploySmokeRequestConsumer = jobs.get('postdeploy-smoke') ?? '';
  if (
    !postdeploySmokeRequestConsumer.includes('name: release-external-authorization-request') ||
    count(postdeploySmokeRequestConsumer, 'path: .stage7/web') < 2
  ) {
    fail('postdeploy smoke must reconstruct the exact web and review-request directory');
  }

  const fullExternalJobs = [
    ['postdeploy-smoke', 'uses: aws-actions/configure-aws-credentials@'],
    ['edge-security', 'uses: aws-actions/configure-aws-credentials@'],
    ['quality', 'pnpm release:quality'],
    ['sandbox-smoke', 'uses: aws-actions/configure-aws-credentials@'],
    ['emergency-recovery', 'pnpm release:smoke -- --scope full --post-versioned-rollback'],
    ['rollback-check', 'uses: aws-actions/configure-aws-credentials@'],
    ['release-reconciliation', 'uses: aws-actions/configure-aws-credentials@'],
    ['publish-release', 'pnpm release:verify -- --publication-target'],
  ];
  for (const [job, firstAuthorizedOperation] of fullExternalJobs) {
    const block = jobs.get(job) ?? '';
    const authStep = stepBlocks(block).find((step) =>
      step.includes(
        'STAGE7_EXTERNAL_AUTHORIZATIONS_B64: ${{ vars.STAGE7_EXTERNAL_AUTHORIZATIONS_B64 }}',
      ),
    );
    for (const fragment of [
      'name: stage7-web',
      'path: .stage7/web',
      'test -n "${STAGE7_EXTERNAL_AUTHORIZATIONS_B64}"',
      'umask 077',
      'target="${RUNNER_TEMP}/stage7-external-authorizations.json"',
      'printf \'%s\' "${STAGE7_EXTERNAL_AUTHORIZATIONS_B64}" | base64 --decode > "${target}"',
      'chmod 600 "${target}"',
      'test "$(stat -c \'%a\' "${target}")" = \'600\'',
      'export STAGE7_EXTERNAL_AUTHORIZATIONS="${target}"',
      'pnpm release:preflight -- --scope full --external-authorization .stage7/web --approved-environment',
      'STAGE7_EXTERNAL_AUTHORIZATIONS=%s\\n',
    ]) {
      if (!block.includes(fragment))
        fail(`${job} full authorization binding is missing: ${fragment}`);
    }
    if (/(?:echo|tee|set\s+-x)[^\n]*STAGE7_EXTERNAL_AUTHORIZATIONS_B64/iu.test(authStep ?? '')) {
      fail(`${job} must not expose the full external-authorization payload`);
    }
    const configIndex = block.indexOf('name: Materialize and validate the approved Stage 7 config');
    const authIndex = block.indexOf('STAGE7_EXTERNAL_AUTHORIZATIONS_B64:');
    const operationIndex = block.indexOf(firstAuthorizedOperation);
    if (job === 'emergency-recovery') {
      const recoveryIndex = block.indexOf('--recover-if-active');
      if (
        configIndex === -1 ||
        recoveryIndex <= configIndex ||
        authIndex <= recoveryIndex ||
        operationIndex <= authIndex
      ) {
        fail(
          'emergency-recovery must mutate from durable AWS state before binding authorization and READ traffic',
        );
      }
    } else if (configIndex === -1 || authIndex <= configIndex || operationIndex <= authIndex) {
      fail(`${job} must bind full authorization after config and before OIDC or traffic`);
    }
  }
  if (
    count(
      source,
      'STAGE7_EXTERNAL_AUTHORIZATIONS_B64: ${{ vars.STAGE7_EXTERNAL_AUTHORIZATIONS_B64 }}',
    ) !== fullExternalJobs.length
  ) {
    fail('full external-authorization payload must exist only in the target-traffic jobs');
  }
  for (const job of ['deploy-data', 'deploy-api', 'deploy-observability', 'deploy-web']) {
    const block = jobs.get(job) ?? '';
    for (const fragment of [
      'name: stage7-candidate-manifest',
      'name: stage7-infra-diff',
      'path: .stage7/infra-diff',
      'name: stage7-approval',
      'path: .stage7/approval',
      'name: stage7-previous-release',
      'path: .stage7/previous',
      '--versioned-update',
      '--manifest .stage7/candidate-manifest/candidate-manifest.json',
      '--plan .stage7/infra-diff/infra-diff.json',
      '--approval .stage7/approval/approval.json',
      '--previous-manifest .stage7/previous/previous-release-manifest.json',
      '--previous-api-contract-evidence .stage7/previous/previous-api-contract-evidence.json',
      '--previous-pending-evidence .stage7/previous/previous-pending-evidence.json',
      '--previous-smoke-evidence .stage7/previous/previous-smoke-evidence.json',
    ]) {
      if (!block.includes(fragment)) fail(`${job} must bind reviewed immutable input: ${fragment}`);
    }
  }
  const infraDiff = jobs.get('infra-diff') ?? '';
  for (const fragment of [
    'name: Download the exact journal role authority',
    'name: stage7-aws-auth',
    'path: .stage7/aws-auth',
    '--journal-role-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json',
  ]) {
    if (!infraDiff.includes(fragment)) {
      fail(`infra-diff journal authority input is missing: ${fragment}`);
    }
  }
  const previousProjectionFiles = [
    'previous-release-manifest.json',
    'previous-source-provenance.json',
    'previous-target-compatibility.json',
    'previous-final-disable-provenance.json',
    'previous-api-contract-evidence.json',
    'previous-pending-evidence.json',
    'previous-smoke-evidence.json',
    'previous-release-projection-index.json',
  ];
  const previousBind = stepBlocks(infraDiff).find((step) =>
    step.includes('name: Bind and validate the exact immutable N-1 recovery contract'),
  );
  const previousScan = stepBlocks(infraDiff).find((step) =>
    step.includes('name: Preserve the exact immutable N-1 recovery contract'),
  );
  const previousUpload = stepBlocks(infraDiff).find((step) =>
    step.includes('name: Upload the exact immutable N-1 recovery contract'),
  );
  const preOidcRead = stepBlocks(infraDiff).find((step) =>
    step.includes('name: Assume the allowlisted read role through OIDC after config validation'),
  );
  const previousReadinessFlags = [
    '--previous-manifest .stage7/previous/previous-release-manifest.json',
    '--previous-source-provenance .stage7/previous/previous-source-provenance.json',
    '--previous-target-compatibility .stage7/previous/previous-target-compatibility.json',
    '--previous-final-disable-provenance .stage7/previous/previous-final-disable-provenance.json',
    '--previous-api-contract-evidence .stage7/previous/previous-api-contract-evidence.json',
    '--previous-pending-evidence .stage7/previous/previous-pending-evidence.json',
    '--previous-smoke-evidence .stage7/previous/previous-smoke-evidence.json',
    '--previous-release-projection-index .stage7/previous/previous-release-projection-index.json',
  ];
  if (
    !previousBind?.includes('pnpm release:baseline -- bind') ||
    !previousBind.includes('--output-directory .stage7/previous') ||
    !previousBind.includes('node scripts/stage7/aws-ops.mjs validate-previous-release') ||
    previousReadinessFlags.some((fragment) => !previousBind.includes(fragment)) ||
    !previousScan?.includes('pnpm release:scan -- --pre-upload') ||
    !previousUpload?.includes('name: stage7-previous-release') ||
    !previousUpload.includes('include-hidden-files: true') ||
    previousProjectionFiles.some(
      (filename) =>
        !previousScan.includes(`.stage7/previous/${filename}`) ||
        !previousUpload.includes(`.stage7/previous/${filename}`),
    )
  ) {
    fail('infra-diff must materialize, validate, scan, and upload the exact 8-file N-1 projection');
  }
  if (
    !previousBind?.includes('--target-web .stage7/candidate/web') ||
    preOidcRead === undefined ||
    infraDiff.indexOf(previousBind) >= infraDiff.indexOf(preOidcRead)
  ) {
    fail('infra-diff must reject a non-distinct mutable web target before OIDC');
  }
  for (const fragment of [
    'name: stage7-release-plan',
    'path: output/evidence/runtime/stage-7/release-plan.json',
    'name: stage7-infra-diff',
    'output/evidence/runtime/stage-7/infra-diff.json',
    'output/evidence/runtime/stage-7/infra-diff.txt',
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/release-plan.json" "${STAGE7_EVIDENCE_ROOT}/infra-diff.json" "${STAGE7_EVIDENCE_ROOT}/infra-diff.txt"',
  ]) {
    if (!infraDiff.includes(fragment)) fail(`exact review artifact is missing: ${fragment}`);
  }
  const exactDiffArtifact = stepBlocks(infraDiff).find((step) =>
    step.includes('name: Preserve the exact sanitized diff for protected review'),
  );
  for (const fragment of [
    'output/evidence/runtime/stage-7/infra-diff.json',
    'output/evidence/runtime/stage-7/infra-diff.txt',
  ]) {
    if (!exactDiffArtifact?.includes(fragment)) {
      fail(`exact review artifact is missing: ${fragment}`);
    }
  }
  const approvalJob = jobs.get('approval') ?? '';
  for (const fragment of [
    'name: stage7-infra-diff',
    'name: stage7-aws-auth',
    'path: .stage7/infra-diff',
    'GITHUB_TOKEN: ${{ github.token }}',
    'STAGE7_PROTECTED_ENVIRONMENT: assessment-release',
    'pnpm release:github-approval -- --repository "${GITHUB_REPOSITORY}" --run-id "${GITHUB_RUN_ID}" --run-attempt "${GITHUB_RUN_ATTEMPT}" --environment "${STAGE7_PROTECTED_ENVIRONMENT}" --candidate-sha "${STAGE7_CANDIDATE_SHA}" --release-id "${STAGE7_RELEASE_ID}" --diff .stage7/infra-diff/infra-diff.txt --evidence "${STAGE7_EVIDENCE_ROOT}/github-environment-approval.json"',
    'pnpm release:preflight -- --approval .stage7/infra-diff --github-approval-evidence "${STAGE7_EVIDENCE_ROOT}/github-environment-approval.json"',
    'name: stage7-approval',
    'output/evidence/runtime/stage-7/github-environment-approval.json',
    'output/evidence/runtime/stage-7/approval.json',
  ]) {
    if (!approvalJob.includes(fragment))
      fail(`protected diff approval binding is missing: ${fragment}`);
  }
  if (
    approvalJob.indexOf('pnpm release:github-approval') === -1 ||
    approvalJob.indexOf('pnpm release:github-approval') >=
      approvalJob.indexOf('pnpm release:preflight -- --approval')
  ) {
    fail('GitHub Environment review evidence must precede protected approval preflight');
  }
  for (const fragment of [
    'Publish the exact protected-review confirmation',
    'STAGE7_IAM_DIFF_REVIEWED_SHA256=${diff_sha}',
    '>> "${GITHUB_STEP_SUMMARY}"',
  ]) {
    if (!infraDiff.includes(fragment)) {
      fail(`exact IAM review confirmation is missing: ${fragment}`);
    }
  }
  const deployObservability = jobs.get('deploy-observability') ?? '';
  const postdeploySmoke = jobs.get('postdeploy-smoke') ?? '';
  const activateVersioned = stepBlocks(postdeploySmoke).find((step) =>
    step.includes('name: Activate the versioned candidate'),
  );
  for (const fragment of [
    'name: release-observability-pending',
    'Confirm the exact SNS alarm email subscription',
  ]) {
    if (!deployObservability.includes(fragment)) {
      fail(`observability confirmation handoff is missing: ${fragment}`);
    }
  }
  for (const fragment of [
    'name: release-observability-pending',
    'pnpm release:verify:observability -- --record .stage7/observability-pending/observability.json',
    'name: stage7-observability',
    'path: output/evidence/runtime/stage-7/observability.json',
    'pnpm release:smoke -- --scope full --manifest .stage7/candidate-manifest/candidate-manifest.json',
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/activation.json"',
    'name: stage7-activation',
    'path: output/evidence/runtime/stage-7/activation.json',
  ]) {
    if (!postdeploySmoke.includes(fragment)) {
      fail(`confirmed observability readiness is missing before smoke: ${fragment}`);
    }
  }
  if (
    !activateVersioned?.includes('--versioned-update') ||
    count(postdeploySmoke, 'pnpm release:activate') !== 1
  ) {
    fail('post-readiness activation must use only the staged versioned-update path');
  }
  for (const activationStep of [activateVersioned ?? '']) {
    for (const fragment of [
      '--manifest .stage7/candidate-manifest/candidate-manifest.json',
      '--api-record .stage7/api/api.json',
      '--web-record .stage7/web/web.json',
      '--seed-evidence .stage7/data/data.json',
      '--observability-evidence "${STAGE7_EVIDENCE_ROOT}/observability.json"',
      '--previous-manifest .stage7/previous/previous-release-manifest.json',
      '--previous-api-contract-evidence .stage7/previous/previous-api-contract-evidence.json',
      '--previous-pending-evidence .stage7/previous/previous-pending-evidence.json',
      '--previous-smoke-evidence .stage7/previous/previous-smoke-evidence.json',
    ]) {
      if (!activationStep.includes(fragment)) {
        fail(`activation must bind confirmed frozen checkpoints: ${fragment}`);
      }
    }
  }
  const readinessIndex = postdeploySmoke.indexOf('pnpm release:verify:observability');
  const deployRoleIndex = postdeploySmoke.indexOf(
    'role-to-assume: ${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}',
  );
  const activationIndex = postdeploySmoke.indexOf('pnpm release:activate');
  const finalReadRoleIndex = postdeploySmoke.lastIndexOf(
    'role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
  );
  const smokeIndex = postdeploySmoke.indexOf('pnpm release:smoke');
  if (
    readinessIndex === -1 ||
    deployRoleIndex <= readinessIndex ||
    activationIndex <= deployRoleIndex ||
    finalReadRoleIndex <= activationIndex ||
    smokeIndex <= finalReadRoleIndex
  ) {
    fail('confirmed observability must precede deploy-role activation, read-role reset and smoke');
  }

  const emergencyRecovery = jobs.get('emergency-recovery') ?? '';
  const rollback = jobs.get('rollback-check') ?? '';
  for (const fragment of [
    'if: ${{ always() && github.run_attempt == 1 }}',
    'environment: assessment-release-recovery',
    'actions: read',
    'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}/artifacts"',
    'name == "stage7-activation"',
    'Classify only the downstream signal, never AWS state',
    'Assume read authority for the immutable recovery observation',
    'role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
    '--aws-read --manifest .stage7/candidate-manifest/candidate-manifest.json --cloud-assembly .stage7/candidate/iac',
    '--approved-environment --no-write',
    'capture-rollback-candidate-aws',
    '--deployment-evidence .stage7/web/web.json',
    'Verify the healthy candidate with a stable read-only AWS sandwich',
    "if: ${{ always() && steps.downstream.outputs.healthy == 'true' }}",
    'Assume automatic rollback authority only for the unhealthy branch',
    "if: ${{ success() && steps.downstream.outputs.healthy != 'true' }}",
    'role-to-assume: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
    'Recover N-1 from durable AWS state only for the unhealthy branch',
    'recover-versioned-release',
    '--recover-if-active',
    '--verify-candidate-active-no-action',
    '--outcome "${STAGE7_EVIDENCE_ROOT}/emergency-recovery-no-action-outcome.json"',
    'verify-emergency-recovery-no-action-outcome',
    'NO_ACTION_RESULT: ${{ steps.emergency-no-action.outcome }}',
    'RECOVERY_DECISION: ${{ steps.emergency-recovery.outputs.decision }}',
    'test "${NO_ACTION_RESULT}" = \'success\'',
    'test "${RECOVERY_DECISION}" = \'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED\'',
    "if: ${{ steps.emergency-recovery.outputs.decision == 'RECOVERED_TO_PREVIOUS_REQUIRES_READ_SMOKE' }}",
    'pnpm release:verify -- --emergency-recovery-no-action --manifest .stage7/candidate-manifest/candidate-manifest.json --previous-manifest .stage7/previous/previous-release-manifest.json --candidate-record "${STAGE7_EVIDENCE_ROOT}/versioned-rollback-candidate.json" --emergency-recovery "${STAGE7_EVIDENCE_ROOT}/emergency-recovery.json" --approval .stage7/approval/approval.json --approved-plan .stage7/infra-diff/infra-diff.json --deployment-evidence .stage7/web/web.json',
    'recovery_decision="$(RECOVERY_FILE="${STAGE7_EVIDENCE_ROOT}/emergency-recovery.json" node --input-type=module',
    'test "${recovery_decision}" = \'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED\'',
    'role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
    '--post-versioned-rollback',
    'safe_for_rehearsal=%s',
    'Scan the exact automatic recovery evidence before preservation',
    'pnpm release:scan -- --pre-upload "${files[@]}"',
    'output/evidence/runtime/stage-7/versioned-rollback-candidate.json',
    'output/evidence/runtime/stage-7/emergency-recovery.json',
    'output/evidence/runtime/stage-7/emergency-recovery-no-action-outcome.json',
  ]) {
    if (!emergencyRecovery.includes(fragment)) {
      fail(`automatic durable recovery is missing: ${fragment}`);
    }
  }
  if (
    emergencyRecovery.includes('environment: assessment-release\n') ||
    emergencyRecovery.indexOf('recover-versioned-release') >=
      emergencyRecovery.indexOf('STAGE7_EXTERNAL_AUTHORIZATIONS_B64:') ||
    emergencyRecovery.includes('--deployment-evidence .stage7/activation/activation.json') ||
    count(emergencyRecovery, 'recover-versioned-release') !== 2 ||
    count(emergencyRecovery, '--recover-if-active') !== 1 ||
    count(emergencyRecovery, '--verify-candidate-active-no-action') !== 1 ||
    count(emergencyRecovery, 'verify-emergency-recovery-no-action-outcome') !== 1
  ) {
    fail('automatic recovery must not wait on rehearsal approval or trust activation artifacts');
  }
  const emergencySteps = stepBlocks(emergencyRecovery);
  const readAssume = emergencySteps.find((step) =>
    step.includes('name: Assume read authority for the immutable recovery observation'),
  );
  const captureCandidate = emergencySteps.find((step) =>
    step.includes(
      'name: Capture aliases and object versions from AWS before any recovery decision',
    ),
  );
  const noAction = emergencySteps.find((step) =>
    step.includes('name: Verify the healthy candidate with a stable read-only AWS sandwich'),
  );
  const rollbackAssume = emergencySteps.find((step) =>
    step.includes('name: Assume automatic rollback authority only for the unhealthy branch'),
  );
  const unhealthyRecovery = emergencySteps.find((step) =>
    step.includes('name: Recover N-1 from durable AWS state only for the unhealthy branch'),
  );
  const decisionStep = emergencySteps.find((step) =>
    step.includes('name: Publish the exact emergency decision for downstream gates'),
  );
  const outcomeStep = emergencySteps.find((step) =>
    step.includes('name: Publish a fail-closed recovery outcome'),
  );
  const scanStep = emergencySteps.find((step) =>
    step.includes('name: Scan the exact automatic recovery evidence before preservation'),
  );
  const uploadStep = emergencySteps.find((step) =>
    step.includes('name: Preserve sanitized automatic recovery evidence'),
  );
  if (
    readAssume === undefined ||
    captureCandidate === undefined ||
    noAction === undefined ||
    rollbackAssume === undefined ||
    unhealthyRecovery === undefined ||
    decisionStep === undefined ||
    outcomeStep === undefined ||
    scanStep === undefined ||
    uploadStep === undefined ||
    emergencySteps.indexOf(readAssume) >= emergencySteps.indexOf(captureCandidate) ||
    emergencySteps.indexOf(captureCandidate) >= emergencySteps.indexOf(noAction) ||
    emergencySteps.indexOf(noAction) >= emergencySteps.indexOf(rollbackAssume) ||
    emergencySteps.indexOf(rollbackAssume) >= emergencySteps.indexOf(unhealthyRecovery) ||
    !noAction.includes("if: ${{ always() && steps.downstream.outputs.healthy == 'true' }}") ||
    !noAction.includes('--verify-candidate-active-no-action') ||
    !noAction.includes(
      '--outcome "${STAGE7_EVIDENCE_ROOT}/emergency-recovery-no-action-outcome.json"',
    ) ||
    noAction.includes('--recover-if-active') ||
    /(?:update-stack|update-alias|copy-object|create-invalidation|delete-|put-item|update-item)/u.test(
      noAction,
    ) ||
    !rollbackAssume.includes("steps.downstream.outputs.healthy != 'true'") ||
    !unhealthyRecovery.includes("steps.downstream.outputs.healthy != 'true'") ||
    !unhealthyRecovery.includes('--recover-if-active') ||
    unhealthyRecovery.includes('--verify-candidate-active-no-action') ||
    !decisionStep.includes('if: ${{ always() }}') ||
    !outcomeStep.includes('if: ${{ always() }}') ||
    !outcomeStep.includes('verify-emergency-recovery-no-action-outcome') ||
    !scanStep.includes('if: ${{ always() }}') ||
    !scanStep.includes('pnpm release:scan -- --pre-upload "${files[@]}"') ||
    !uploadStep.includes('if: ${{ always() }}') ||
    emergencySteps.indexOf(scanStep) >= emergencySteps.indexOf(uploadStep) ||
    count(uploadStep, 'output/evidence/runtime/stage-7/') !== 3 ||
    uploadStep.includes('*.json') ||
    uploadStep.includes('.private-stage7')
  ) {
    fail('automatic recovery healthy and unhealthy authority branches are not exact');
  }
  for (const fragment of [
    "if: ${{ github.run_attempt == 1 && needs.release-reconciliation-intent.result == 'success' && needs.emergency-recovery.outputs.safe_for_rehearsal == 'true'",
    'name: stage7-recovery-probe',
    'name: stage7-previous-release',
    'path: .stage7/previous',
    'validate-previous-release',
    '--prepare-versioned-rollback-pending',
    '--direction ROLLBACK_TO_PREVIOUS',
    '--post-versioned-rollback',
    '--direction REPROMOTE_CANDIDATE',
    '--post-versioned-repromotion',
    '--close-versioned-rollback-pending-egress',
    'finalize-versioned-rollback',
    'release:verify:drift -- --scope full --versioned-update --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
    'versionedRollbackRehearsal',
    'base_rehearsal_ready=%s',
    'id: scan-public-rollback',
    "if: ${{ steps.scan-public-rollback.outcome == 'success' }}",
  ]) {
    if (!rollback.includes(fragment)) fail(`versioned rollback rehearsal is missing: ${fragment}`);
  }
  if (
    rollback.includes('--initial-release --to-disabled') ||
    rollback.includes('--initial-release --to-unpublished') ||
    rollback.includes('pnpm release:activate') ||
    count(rollback, 'execute-versioned-rollback') !== 2 ||
    count(rollback, 'finalize-versioned-rollback') !== 2
  ) {
    fail('rollback rehearsal must execute exactly N to N-1 to N without disable/unpublish');
  }
  const pendingEgressCloseoutStep = stepBlocks(rollback).find((step) =>
    step.includes('name: Close the pending provider egress ledger with N-1 status evidence'),
  );
  const pendingEgressCloseoutCommand =
    'pnpm release:smoke -- --scope full --close-versioned-rollback-pending-egress --manifest .stage7/candidate-manifest/candidate-manifest.json --previous-manifest .stage7/previous/previous-release-manifest.json --candidate-record .stage7/recovery-probe/versioned-rollback-candidate.json --rollback-evidence "${STAGE7_EVIDENCE_ROOT}/rollback.json" --rollback-checkpoint "${STAGE7_EVIDENCE_ROOT}/versioned-rollback-checkpoint.json" --repromotion-checkpoint "${STAGE7_EVIDENCE_ROOT}/versioned-repromotion-checkpoint.json" --pending-producer "${STAGE7_EVIDENCE_ROOT}/rollback-pending-producer.json" --approved-environment --evidence "${STAGE7_EVIDENCE_ROOT}/rollback-pending-egress-closeout.json"';
  if (
    pendingEgressCloseoutStep === undefined ||
    !pendingEgressCloseoutStep.includes(
      "if: ${{ steps.rollback-mode.outputs.mode == 'HAPPY_REHEARSAL' }}",
    ) ||
    !pendingEgressCloseoutStep.includes('STAGE7_PROTECTED_ENVIRONMENT: assessment-release') ||
    stepShellCommands(pendingEgressCloseoutStep)[0] !== pendingEgressCloseoutCommand ||
    count(rollback, '--close-versioned-rollback-pending-egress') !== 1
  ) {
    fail('rollback pending egress closeout authority and inputs must be exact');
  }
  const candidateActivationUpload = postdeploySmoke.indexOf('name: stage7-activation');
  const candidateActivationScan = postdeploySmoke.indexOf(
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/activation.json"',
  );
  if (
    candidateActivationScan <= activationIndex ||
    candidateActivationUpload <= candidateActivationScan ||
    finalReadRoleIndex <= candidateActivationUpload ||
    smokeIndex <= finalReadRoleIndex
  ) {
    fail('activation ledger must be sealed before any downstream read smoke can fail');
  }
  const initialOrder = [
    '--prepare-versioned-rollback-pending',
    '--direction ROLLBACK_TO_PREVIOUS',
    '--post-versioned-rollback',
    '--direction REPROMOTE_CANDIDATE',
    '--post-versioned-repromotion',
    '--close-versioned-rollback-pending-egress',
    'release:verify:drift -- --scope full',
    'name: Preserve sanitized rollback evidence',
  ];
  let modeIndex = -1;
  for (const fragment of initialOrder) {
    const index = rollback.indexOf(fragment, modeIndex + 1);
    if (index === -1 || index <= modeIndex) {
      fail(`versioned rollback verification order is invalid at: ${fragment}`);
      break;
    }
    modeIndex = index;
  }
  const rollbackPublicPaths = [
    'output/evidence/runtime/stage-7/rollback-smoke-input-preflight.json',
    'output/evidence/runtime/stage-7/rollback-pending-producer.json',
    'output/evidence/runtime/stage-7/rollback-pending-egress-closeout.json',
    'output/evidence/runtime/stage-7/versioned-rollback-aws-transition.json',
    'output/evidence/runtime/stage-7/versioned-rollback-smoke.json',
    'output/evidence/runtime/stage-7/versioned-rollback-checkpoint.json',
    'output/evidence/runtime/stage-7/versioned-repromotion-aws-transition.json',
    'output/evidence/runtime/stage-7/versioned-repromotion-smoke.json',
    'output/evidence/runtime/stage-7/versioned-repromotion-checkpoint.json',
    'output/evidence/runtime/stage-7/rollback.json',
    'output/evidence/runtime/stage-7/drift.json',
  ];
  const rollbackUpload = stepBlocks(rollback).find((step) =>
    step.includes('name: Preserve sanitized rollback evidence'),
  );
  const rollbackUploadPaths = (rollbackUpload ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('output/evidence/runtime/stage-7/'));
  const rollbackScan = stepBlocks(rollback).find((step) =>
    step.includes('name: Scan the complete public rehearsal ledger before upload'),
  );
  const rollbackScanInputs = rollbackPublicPaths
    .map((entry) => `"\${STAGE7_EVIDENCE_ROOT}/${entry.split('/').at(-1)}"`)
    .join(' ');
  if (
    !same(rollbackUploadPaths, rollbackPublicPaths) ||
    stepShellCommands(rollbackScan ?? '')[0] !==
      `pnpm release:scan -- --pre-upload ${rollbackScanInputs}`
  ) {
    fail('stage7-rollback must scan and upload exactly its eleven public root basenames');
  }
  const publication = jobs.get('publish-release') ?? '';
  const quality = jobs.get('quality') ?? '';
  if (
    !publication.includes(
      "if: ${{ github.run_attempt == 1 && needs.release-successor-fence.result == 'success' }}",
    )
  ) {
    fail('publication must require the durable immutable successor fence');
  }
  const fenceVerificationStep = stepBlocks(publication).find((step) =>
    step.includes('name: Revalidate the immutable fence before any GitHub publication'),
  );
  const publicationPreparationStep = stepBlocks(publication).find((step) =>
    step.includes('name: Prepare the immutable publication package without external writes'),
  );
  for (const fragment of [
    'control.mjs verify-successor-fence',
    '--fence .stage7/evidence/stage7-release-successor-fence/release-successor-completion-fence.json',
    '--release-metadata .stage7/evidence/stage7-release-metadata/release-metadata.json',
    '--approval .stage7/evidence/stage7-approval/approval.json',
    '--activation .stage7/evidence/stage7-activation/activation.json',
    '--drift .stage7/evidence/stage7-rollback/drift.json',
    '--protected-run .stage7/evidence/stage7-rollback-resilience/stage7-rollback-resilience-protected-run.json',
    '--completion .stage7/evidence/stage7-rollback-resilience/stage7-rollback-resilience-complete.json',
    '--pre-fence-gate .stage7/evidence/stage7-release-reconciliation/stage7-release-pre-fence-gate.json',
  ]) {
    if (!fenceVerificationStep?.includes(fragment)) {
      fail(`publication immutable successor fence revalidation is missing: ${fragment}`);
    }
  }
  if (
    fenceVerificationStep === undefined ||
    publicationPreparationStep === undefined ||
    publication.indexOf(fenceVerificationStep) >= publication.indexOf(publicationPreparationStep) ||
    count(publication, 'control.mjs verify-successor-fence') !== 1
  ) {
    fail('publication must revalidate the immutable successor fence before all publication work');
  }
  for (const fragment of [
    'environment: assessment-release',
    'name: stage7-candidate-manifest',
    'path: .stage7/candidate-manifest',
    'name: stage7-web',
    'path: .stage7/web',
    'pnpm exec playwright install --with-deps chromium firefox webkit',
    'STAGE7_PROTECTED_ENVIRONMENT: assessment-release',
    'pnpm release:quality -- --scope full --manifest .stage7/candidate-manifest/candidate-manifest.json --deployment .stage7/web --approved-environment',
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/quality.json"',
    'name: stage7-quality',
    'output/evidence/runtime/stage-7/quality.json',
    'pnpm release:scan -- --pre-upload "${request}"',
    'name: release-sandbox-execution-request',
    'path: output/evidence/runtime/stage-7/sandbox-execution-request.json',
  ]) {
    if (!quality.includes(fragment)) fail(`deployed quality contract is missing: ${fragment}`);
  }
  if (
    count(quality, 'pnpm release:quality') !== 1 ||
    quality.includes('uses: aws-actions/configure-aws-credentials@') ||
    quality.includes('id-token: write')
  ) {
    fail('deployed quality must execute exactly once without AWS or OIDC authority');
  }
  const qualityUpload = stepBlocks(quality).find((step) =>
    step.includes('name: Preserve sanitized quality evidence'),
  );
  const sandboxRequestUpload = stepBlocks(quality).find((step) =>
    step.includes('name: Preserve the exact sandbox execution review request'),
  );
  const sandboxSmokeArtifactConsumer = jobs.get('sandbox-smoke') ?? '';
  if (
    !qualityUpload?.includes('name: stage7-quality') ||
    !qualityUpload?.includes('path: output/evidence/runtime/stage-7/quality.json') ||
    qualityUpload.includes('sandbox-execution-request.json') ||
    !sandboxRequestUpload?.includes('name: release-sandbox-execution-request') ||
    !sandboxRequestUpload?.includes(
      'path: output/evidence/runtime/stage-7/sandbox-execution-request.json',
    ) ||
    sandboxRequestUpload.includes('quality.json') ||
    !sandboxSmokeArtifactConsumer.includes('name: release-sandbox-execution-request') ||
    !sandboxSmokeArtifactConsumer.includes('path: .stage7/quality')
  ) {
    fail('quality evidence and sandbox review request must use exact separate artifacts');
  }
  const preparationStep = stepBlocks(publication).find((step) =>
    step.includes('name: Prepare the immutable publication package without external writes'),
  );
  const nativeStep = stepBlocks(publication).find((step) =>
    step.includes('name: Verify candidate README and publish the exact GitHub release recoverably'),
  );
  const publicationArtifact = stepBlocks(publication).find((step) =>
    step.includes('name: Preserve the verified publication package and proof'),
  );
  for (const fragment of [
    'pnpm release:github-publication:self-test',
    'pnpm release:publish -- --evidence .stage7/evidence',
    'pnpm release:scan -- --pre-upload output/release/publication "${STAGE7_EVIDENCE_ROOT}/publication.json"',
  ]) {
    if (!preparationStep?.includes(fragment)) {
      fail(`non-mutating publication preparation is missing: ${fragment}`);
    }
  }
  if (
    preparationStep === undefined ||
    preparationStep.indexOf('pnpm release:github-publication:self-test') >=
      preparationStep.indexOf('pnpm release:publish') ||
    preparationStep.indexOf('pnpm release:publish') >= preparationStep.indexOf('pnpm release:scan')
  ) {
    fail('publication must first prepare a non-mutating package from verified evidence');
  }
  for (const fragment of [
    'GH_TOKEN: ${{ github.token }}',
    'test "${GITHUB_REPOSITORY}" = \'ivanmonsalve0404/async-checkout-demo\'',
    'test "${GITHUB_REF}" = \'refs/heads/master\'',
    'test "$(git rev-parse HEAD)" = "${STAGE7_CANDIDATE_SHA}"',
    'operation="${STAGE7_EVIDENCE_ROOT}/publication-operation.json"',
    'target_proof="${STAGE7_EVIDENCE_ROOT}/publication-target-proof.json"',
    'proof="${STAGE7_EVIDENCE_ROOT}/publication-proof.json"',
    'test ! -e "${target_proof}"',
    'test ! -e "${operation}"',
    'test ! -e "${proof}"',
    'pnpm release:verify -- --publication-target "${plan}" --publication-evidence .stage7/evidence --resilience-app .stage7/candidate/iac --evidence "${target_proof}"',
    'pnpm release:github-publication -- --plan "${plan}" --result "${operation}"',
    'pnpm release:verify -- --publication-native "${plan}" --publication-target-proof "${target_proof}" --publication-operation "${operation}" --evidence "${proof}"',
    "publication_root='output/evidence/stage7-publication'",
    'test ! -e "${publication_root}"',
    'install -d -m 700 "${publication_root}"',
    'install -m 600 "${STAGE7_EVIDENCE_ROOT}/publication.json" "${publication_root}/publication.json"',
    'install -m 600 "${plan}" "${publication_root}/publication-plan.json"',
    'install -m 600 "${target_proof}" "${publication_root}/publication-target-proof.json"',
    'install -m 600 "${operation}" "${publication_root}/publication-operation.json"',
    'install -m 600 "${proof}" "${publication_root}/publication-proof.json"',
    'pnpm release:scan -- --pre-upload "${publication_root}/publication.json" "${publication_root}/publication-plan.json" "${publication_root}/publication-target-proof.json" "${publication_root}/publication-operation.json" "${publication_root}/publication-proof.json"',
  ]) {
    if (!nativeStep?.includes(fragment)) fail(`native publication control is missing: ${fragment}`);
  }
  if (
    count(publication, 'GH_TOKEN: ${{ github.token }}') !== 1 ||
    count(publication, 'pnpm release:verify -- --publication-target "') !== 1 ||
    count(publication, 'pnpm release:verify -- --publication-native "') !== 1 ||
    count(publication, 'pnpm release:github-publication --') !== 1 ||
    count(publication, 'pnpm release:github-publication:self-test') !== 1 ||
    /\bgit\s+push\b|\bgh\s+(?:api|release|pr|repo)\b|--latest\b|--force\b|contents\/README\.md|docs:\s*publish/iu.test(
      publication,
    )
  ) {
    fail(
      'native publication must use only the recoverable two-write engine without mutating protected master',
    );
  }
  for (const fragment of [
    'output/evidence/stage7-publication/publication.json',
    'output/evidence/stage7-publication/publication-plan.json',
    'output/evidence/stage7-publication/publication-target-proof.json',
    'output/evidence/stage7-publication/publication-operation.json',
    'output/evidence/stage7-publication/publication-proof.json',
  ]) {
    if (!publicationArtifact?.includes(fragment)) {
      fail(`verified publication artifact is missing: ${fragment}`);
    }
  }
  const publicationArtifactPaths = (publicationArtifact ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('output/'));
  if (
    !same(publicationArtifactPaths, [
      'output/evidence/stage7-publication/publication.json',
      'output/evidence/stage7-publication/publication-plan.json',
      'output/evidence/stage7-publication/publication-target-proof.json',
      'output/evidence/stage7-publication/publication-operation.json',
      'output/evidence/stage7-publication/publication-proof.json',
    ])
  ) {
    fail('publication artifact must contain exactly five root-level evidence files');
  }
  if (publicationArtifact !== stepBlocks(publication).at(-1)) {
    fail('publication artifact upload must be the final publish-release step');
  }
  const preparationIndex = publication.indexOf('pnpm release:publish');
  const packageScanIndex = publication.indexOf(
    'pnpm release:scan -- --pre-upload output/release/publication',
  );
  const releaseWriteIndex = publication.indexOf('pnpm release:github-publication --');
  const targetPreflightIndex = publication.indexOf('pnpm release:verify -- --publication-target');
  const publicationProofIndex = publication.indexOf('--publication-native');
  const finalScanIndex = publication.lastIndexOf(
    'pnpm release:scan -- --pre-upload "${publication_root}/publication.json"',
  );
  if (
    preparationIndex === -1 ||
    packageScanIndex <= preparationIndex ||
    targetPreflightIndex <= packageScanIndex ||
    releaseWriteIndex <= targetPreflightIndex ||
    publicationProofIndex <= releaseWriteIndex ||
    finalScanIndex <= publicationProofIndex
  ) {
    fail(
      'publication order must be prepare, pre-scan, healthy-target preflight, README verification/release, proof, final scan',
    );
  }
  if (!jobs.get('summary')?.includes('if: ${{ always() && github.run_attempt == 1 }}')) {
    fail('summary must execute even when an earlier gate fails');
  }
  const summary = jobs.get('summary') ?? '';
  for (const stepName of [
    'Set up the pinned Node.js runtime',
    'Activate the pinned package manager',
    'Materialize and validate the approved Stage 7 config',
    'Consolidate all three Stage 7 gates fail-closed',
  ]) {
    const step = stepBlocks(summary).find((candidate) => candidate.includes(`name: ${stepName}`));
    if (!step?.includes('if: ${{ always() }}')) {
      fail(`causal closeout step must run after upstream or download failure: ${stepName}`);
    }
  }
  const exactEvidenceArtifacts = [
    'stage7-release-metadata',
    'stage7-candidate-verification',
    'stage7-prefreeze',
    'stage7-candidate-manifest',
    'stage7-integrity',
    'stage7-security',
    'stage7-aws-auth',
    'stage7-infra-synth',
    'stage7-release-plan',
    'stage7-infra-diff',
    'stage7-previous-release',
    'stage7-approval',
    'stage7-data',
    'stage7-api',
    'stage7-web',
    'stage7-activation',
    'stage7-external-authorization',
    'stage7-observability',
    'stage7-smoke',
    'stage7-edge-security',
    'stage7-quality',
    'stage7-sandbox',
    'stage7-recovery-probe',
    'stage7-rollback',
    'stage7-rollback-resilience',
    'stage7-release-reconciliation',
    'stage7-release-successor-fence',
  ];
  for (const artifact of exactEvidenceArtifacts) {
    for (const [jobName, block] of [
      ['publication', publication],
      ['summary', summary],
    ]) {
      if (
        !block.includes(`name: ${artifact}`) ||
        !block.includes(`path: .stage7/evidence/${artifact}`)
      ) {
        fail(`${jobName} exact evidence download is missing: ${artifact}`);
      }
    }
  }
  if (
    !summary.includes('name: stage7-publication') ||
    !summary.includes('path: .stage7/evidence/stage7-publication') ||
    /pattern:\s*stage7|merge-multiple:\s*true/iu.test(source)
  ) {
    fail('Stage 7 evidence downloads must be exact and isolated by artifact');
  }
  for (const fragment of [
    'output/evidence/runtime/stage-7/stage6-closeout.json',
    '.stage7/previous/previous-release-projection-index.json',
    'name: stage7-release-authorities',
    'name: stage7-release-reports',
    'output/evidence/runtime/stage-7/release-manifest.json',
    'output/evidence/runtime/stage-7/provenance-ledger.json',
    'output/evidence/runtime/stage-7/etapa-7-release-despliegue.md',
  ]) {
    if (!source.includes(fragment)) fail(`causal closeout artifact is missing: ${fragment}`);
  }
  if (
    !summary.includes('id: scan_causal_evidence') ||
    !summary.includes(
      "if: ${{ always() && hashFiles('output/evidence/runtime/stage-7/closeout.json') != '' }}",
    ) ||
    count(summary, "steps.scan_causal_evidence.outcome == 'success'") !== 2
  ) {
    fail('causal closeout uploads must require a successful always-run sanitization scan');
  }
  if (/\bpnpm\s+release:cleanup\b/iu.test(source)) {
    fail('full release cleanup must remain in a separately authorized workflow');
  }
  errors.push(...validatePrivateSmokeInputs(name, postdeploySmoke, rollback));
  errors.push(
    ...validateSandboxWrapper(name, jobs.get('sandbox-smoke') ?? '', {
      prerelease: false,
      requestProducer: jobs.get('quality') ?? '',
    }),
  );
  errors.push(...validatePinnedZap(name, jobs.get('edge-security') ?? '', { prerelease: false }));
  return errors;
}

export function validatePrereleaseWorkflow(name, input) {
  const source = normalize(input);
  const errors = validateCommon(name, source, prereleaseSpec);
  const fail = (message) => errors.push(`${name}: ${message}`);
  const jobs = workflowJobs(source);
  for (const fragment of [
    '[[ "${RELEASE_ID}" =~ ^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$ ]]',
    'test "${RELEASE_ID##*-}" = "${CANDIDATE_SHA:0:7}"',
    '--require-e6-conditional-go',
    'STAGE6_A11Y_MANUAL_EVIDENCE_B64: ${{ vars.STAGE6_A11Y_MANUAL_EVIDENCE_B64 }}',
    '--scope prerelease',
    '--synthetic-only',
    '--non-public',
    '--zap-passive-only',
    '--external-uat',
    '--forbid-e7-pass',
    '--emit-stage6-external-raw',
    'STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN: ${{ vars.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN }}',
    "loadExternalEvidence } from './scripts/stage6/external-evidence.mjs'",
    'stage6-authorized-external-evidence',
    'STAGE6_EXTERNAL_EVIDENCE_B64',
    'pnpm infra:synth:release -- --scope prerelease --initial-release --verify .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
    'pnpm infra:diff:release -- --scope prerelease --initial-release --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
  ]) {
    if (!source.includes(fragment)) {
      fail(`required conditional prerelease contract is missing: ${fragment}`);
    }
  }
  for (const forbidden of [
    'release_tag:',
    'pnpm release:publish',
    'gh release',
    'README.md',
    'contents: write',
    'GATE-E7-03',
  ]) {
    if (source.includes(forbidden)) fail(`conditional prerelease must not publish: ${forbidden}`);
  }
  if (/^\s+STAGE7_ENVIRONMENT:/mu.test(source)) {
    fail('prerelease environment identity must come only from the validated config');
  }
  for (const line of source.split('\n').filter((entry) => entry.includes('pnpm release:scan'))) {
    if (!line.includes('pnpm release:scan -- --scope prerelease')) {
      fail('every prerelease scan must bind the prerelease scope explicitly');
      break;
    }
  }
  errors.push(
    ...validateBuildOnce(name, source, jobs.get('build-once') ?? '', { prerelease: true }),
  );
  const metadata = jobs.get('prerelease-metadata') ?? '';
  const verify = jobs.get('verify-candidate') ?? '';
  if (
    count(metadata, 'Materialize required manual accessibility evidence') !== 1 ||
    count(verify, 'Materialize required manual accessibility evidence') !== 1
  ) {
    fail('manual accessibility evidence must be required in both conditional entry gates');
  }
  if (!jobs.get('approval')?.includes('test "${CONFIRM_DEPLOY}" = \'true\'')) {
    fail('prerelease approval must require explicit confirm_deploy');
  }

  const safety = jobs.get('prerelease-safety-readiness') ?? '';
  for (const fragment of [
    'needs: approval',
    'environment: assessment-prerelease',
    'name: stage7-prerelease-candidate',
    'path: .stage7/candidate',
    'name: stage7-prerelease-candidate-manifest',
    'path: .stage7/candidate-manifest',
    'name: stage7-prerelease-infra-diff',
    'path: .stage7/infra-diff',
    'name: stage7-prerelease-approval',
    'path: .stage7/approval',
    'pnpm release:prerelease-safety -- capture',
    '--raw-diff .stage7/infra-diff/infra-diff.txt',
    '--aws-auth .stage7/infra-diff/aws-auth.json',
    '--watchdog-role-arn "${STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN}"',
    '--output "${STAGE7_EVIDENCE_ROOT}/prerelease-safety-readiness.json"',
    'pnpm release:scan -- --scope prerelease --pre-upload "${STAGE7_EVIDENCE_ROOT}/prerelease-safety-readiness.json"',
    'name: stage7-prerelease-safety-readiness',
    'path: output/evidence/runtime/stage-7-prerelease/prerelease-safety-readiness.json',
  ]) {
    if (!safety.includes(fragment)) {
      fail(`protected prerelease safety producer is missing: ${fragment}`);
    }
  }
  const safetyCaptureIndex = safety.indexOf('pnpm release:prerelease-safety -- capture');
  const safetyScanIndex = safety.indexOf(
    'pnpm release:scan -- --scope prerelease --pre-upload "${STAGE7_EVIDENCE_ROOT}/prerelease-safety-readiness.json"',
  );
  const safetyUploadIndex = safety.indexOf('name: stage7-prerelease-safety-readiness');
  if (
    safetyCaptureIndex < 0 ||
    safetyScanIndex <= safetyCaptureIndex ||
    safetyUploadIndex <= safetyScanIndex
  ) {
    fail('prerelease safety artifact scan/upload chain is invalid');
  }

  const deploy = jobs.get('deploy-prerelease') ?? '';
  const deploySteps = stepBlocks(deploy);
  const deployOidcStepIndex = deploySteps.findIndex((step) =>
    step.includes('role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}'),
  );
  const deployOidcGate = deploySteps[deployOidcStepIndex - 1] ?? '';
  for (const fragment of [
    'name: Revalidate live watchdog authority before deploy-role OIDC',
    'GITHUB_TOKEN: ${{ github.token }}',
    'test -z "${AWS_ACCESS_KEY_ID:-}"',
    'test -z "${AWS_SECRET_ACCESS_KEY:-}"',
    'test -z "${AWS_SESSION_TOKEN:-}"',
    'test -z "${AWS_SECURITY_TOKEN:-}"',
    'pnpm release:prerelease-safety -- verify-watchdog',
    '--phase deploy-gate',
    '--readiness .stage7/prerelease-safety/prerelease-safety-readiness.json',
  ]) {
    if (!deployOidcGate.includes(fragment)) {
      fail(`deploy-role OIDC must remain behind GitHub-only watchdog live gate: ${fragment}`);
    }
  }
  if (deployOidcStepIndex < 1 || deployOidcGate.includes('configure-aws-credentials')) {
    fail('deploy-role OIDC must remain behind GitHub-only watchdog live gate');
  }
  if (
    !deploy.includes('name: stage7-prerelease-safety-readiness') ||
    !deploy.includes('path: .stage7/prerelease-safety')
  ) {
    fail('prerelease deploy must consume protected safety readiness');
  }
  const mutationCommands = [
    'release:deploy:data',
    'release:deploy:api',
    'release:deploy:observability',
    'release:deploy:web',
    'release:seed',
    'release:cleanup -- --scope prerelease --register-expiry',
  ];
  for (const command of mutationCommands) {
    const step = deploySteps.find((candidate) => candidate.includes(`pnpm ${command}`)) ?? '';
    for (const fragment of [
      'GITHUB_TOKEN: ${{ github.token }}',
      '--manifest .stage7/candidate-manifest/candidate-manifest.json',
      '--plan .stage7/infra-diff/infra-diff.json',
      '--raw-diff .stage7/infra-diff/infra-diff.txt',
      '--approval .stage7/approval/approval.json',
      '--aws-auth .stage7/infra-diff/aws-auth.json',
      '--safety-readiness .stage7/prerelease-safety/prerelease-safety-readiness.json',
    ]) {
      if (!step.includes(fragment)) {
        fail(`prerelease mutation safety consumer is missing for ${command}: ${fragment}`);
      }
    }
    if (
      (command === 'release:seed' || command.startsWith('release:cleanup')) &&
      !step.includes('--deployment-evidence "${STAGE7_EVIDENCE_ROOT}/deployment.json"')
    ) {
      fail(`prerelease mutation safety consumer is missing for ${command}: deployment ledger`);
    }
  }
  const deployOrder = [
    'pnpm release:deploy:data',
    'pnpm release:deploy:api',
    'pnpm release:deploy:observability',
    'pnpm release:deploy:web',
    'pnpm release:seed',
    'pnpm release:cleanup -- --scope prerelease --register-expiry',
    '--external-authorization-request',
  ];
  let previous = -1;
  for (const fragment of deployOrder) {
    const index = deploy.indexOf(fragment, previous + 1);
    if (index === -1 || index <= previous) {
      fail(`prerelease deploy/seed/activation order is invalid at: ${fragment}`);
      break;
    }
    previous = index;
  }
  if (
    !deploy.includes('STAGE7_ALERT_EMAIL: ${{ secrets.STAGE7_ALERT_EMAIL }}') ||
    !deploy.includes('name: stage7-prerelease-infra-diff') ||
    !deploy.includes('path: .stage7/infra-diff') ||
    !deploy.includes('name: stage7-prerelease-approval') ||
    !deploy.includes('path: .stage7/approval')
  ) {
    fail('prerelease deploy must use the frozen inputs and protected alert channel');
  }
  for (const command of [
    'release:deploy:data',
    'release:deploy:api',
    'release:deploy:observability',
    'release:deploy:web',
  ]) {
    const step =
      stepBlocks(deploy).find((candidate) => candidate.includes(`pnpm ${command}`)) ?? '';
    for (const fragment of [
      '--scope prerelease',
      '--initial-release',
      '--app .stage7/candidate/iac',
      '--manifest .stage7/candidate-manifest/candidate-manifest.json',
      '--plan .stage7/infra-diff/infra-diff.json',
      '--approval .stage7/approval/approval.json',
      '--synthetic-only',
      '--non-public',
    ]) {
      if (!step.includes(fragment)) fail(`${command} prerelease guard is missing: ${fragment}`);
    }
  }
  if (deploy.includes('pnpm release:activate')) {
    fail('prerelease scheduler activation before external authorization is forbidden');
  }

  const prereleaseDiff = jobs.get('infra-diff') ?? '';
  for (const fragment of [
    '--evidence "${STAGE7_EVIDENCE_ROOT}/aws-auth.json"',
    'name: stage7-prerelease-release-plan',
    'path: output/evidence/runtime/stage-7-prerelease/release-plan.json',
    'name: stage7-prerelease-infra-diff',
    'output/evidence/runtime/stage-7-prerelease/infra-diff.json',
    'output/evidence/runtime/stage-7-prerelease/infra-diff.txt',
    'pnpm release:scan -- --scope prerelease --pre-upload "${STAGE7_EVIDENCE_ROOT}/release-plan.json" "${STAGE7_EVIDENCE_ROOT}/infra-diff.json" "${STAGE7_EVIDENCE_ROOT}/infra-diff.txt"',
  ]) {
    if (!prereleaseDiff.includes(fragment)) {
      fail(`exact prerelease review artifact is missing: ${fragment}`);
    }
  }
  const exactPrereleaseDiffArtifact = stepBlocks(prereleaseDiff).find((step) =>
    step.includes('name: Preserve the exact sanitized prerelease diff for protected review'),
  );
  for (const fragment of [
    'output/evidence/runtime/stage-7-prerelease/aws-auth.json',
    'output/evidence/runtime/stage-7-prerelease/infra-diff.json',
    'output/evidence/runtime/stage-7-prerelease/infra-diff.txt',
  ]) {
    if (!exactPrereleaseDiffArtifact?.includes(fragment)) {
      fail(`exact prerelease review artifact is missing: ${fragment}`);
    }
  }
  const prereleaseApproval = jobs.get('approval') ?? '';
  for (const fragment of [
    'name: stage7-prerelease-infra-diff',
    'path: .stage7/infra-diff',
    'STAGE7_CANDIDATE_SHA: ${{ inputs.candidate_sha }}',
    'GITHUB_TOKEN: ${{ github.token }}',
    'STAGE7_PROTECTED_ENVIRONMENT: assessment-prerelease',
    'pnpm release:github-approval -- --repository "${GITHUB_REPOSITORY}" --run-id "${GITHUB_RUN_ID}" --run-attempt "${GITHUB_RUN_ATTEMPT}" --environment "${STAGE7_PROTECTED_ENVIRONMENT}" --candidate-sha "${STAGE7_CANDIDATE_SHA}" --release-id "${STAGE7_RELEASE_ID}" --diff .stage7/infra-diff/infra-diff.txt --evidence "${STAGE7_EVIDENCE_ROOT}/github-environment-approval.json"',
    'pnpm release:preflight -- --scope prerelease --approval .stage7/infra-diff --github-approval-evidence "${STAGE7_EVIDENCE_ROOT}/github-environment-approval.json"',
    'name: stage7-prerelease-approval',
    'output/evidence/runtime/stage-7-prerelease/github-environment-approval.json',
    'output/evidence/runtime/stage-7-prerelease/approval.json',
  ]) {
    if (!prereleaseApproval.includes(fragment)) {
      fail(`protected prerelease diff approval binding is missing: ${fragment}`);
    }
  }
  if (
    prereleaseApproval.indexOf('pnpm release:github-approval') === -1 ||
    prereleaseApproval.indexOf('pnpm release:github-approval') >=
      prereleaseApproval.indexOf('pnpm release:preflight -- --scope prerelease --approval')
  ) {
    fail('GitHub Environment review evidence must precede prerelease approval preflight');
  }
  for (const fragment of [
    'Publish the exact protected-review confirmation',
    'STAGE7_IAM_DIFF_REVIEWED_SHA256=${diff_sha}',
    '>> "${GITHUB_STEP_SUMMARY}"',
  ]) {
    if (!prereleaseDiff.includes(fragment)) {
      fail(`exact prerelease IAM review confirmation is missing: ${fragment}`);
    }
  }

  const external = jobs.get('external-verification') ?? '';
  for (const fragment of [
    'name: stage7-prerelease-infra-diff',
    'path: .stage7/infra-diff',
    'name: stage7-prerelease-approval',
    'path: .stage7/approval',
    'name: stage7-prerelease-safety-readiness',
    'path: .stage7/prerelease-safety',
  ]) {
    if (!external.includes(fragment)) {
      fail(`external prerelease safety source is missing: ${fragment}`);
    }
  }
  for (const fragment of [
    'name: prerelease-deployment-pending',
    'name: Restore and validate the append-only prerelease deployment ledger',
    "const required=['data','api','observability','web','seed','expiryRegistration']",
    'target="${STAGE7_EVIDENCE_ROOT}/deployment.json"',
    'test ! -e "${target}"',
    'mode:0o600',
    'cmp --silent "${source}" "${target}"',
    'STAGE7_EXTERNAL_AUTHORIZATIONS_B64: ${{ vars.STAGE7_EXTERNAL_AUTHORIZATIONS_B64 }}',
    'test -n "${STAGE7_EXTERNAL_AUTHORIZATIONS_B64}"',
    'umask 077',
    'target="${RUNNER_TEMP}/stage7-external-authorizations.json"',
    'printf \'%s\' "${STAGE7_EXTERNAL_AUTHORIZATIONS_B64}" | base64 --decode > "${target}"',
    'chmod 600 "${target}"',
    'test "$(stat -c \'%a\' "${target}")" = \'600\'',
    'export STAGE7_EXTERNAL_AUTHORIZATIONS="${target}"',
    'role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_READ_ROLE_ARN }}',
    'pnpm release:verify:observability -- --record .stage7/deployment/deployment.json --scope prerelease',
    "const required=['data','api','observability','web','seed','expiryRegistration','observabilityReadiness']",
    'role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}',
    '--api-record "${STAGE7_EVIDENCE_ROOT}/deployment.json"',
    '--seed-evidence "${STAGE7_EVIDENCE_ROOT}/deployment.json"',
    'output/evidence/runtime/stage-7-prerelease/deployment.json',
    'pnpm release:activate -- --scope prerelease --initial-release',
    'pnpm release:smoke -- --scope prerelease --manifest .stage7/candidate-manifest/candidate-manifest.json --synthetic-only --external-uat --non-public',
    '--external-authorization .stage7/deployment',
    '--approved-environment --non-public',
    'STAGE7_EXTERNAL_AUTHORIZATIONS=%s\\n',
  ]) {
    if (!external.includes(fragment))
      fail(`external authorization binding is missing: ${fragment}`);
  }
  const authIndex = external.indexOf(
    'name: Materialize and bind protected external-check authorization',
  );
  const restoreIndex = external.indexOf(
    'name: Restore and validate the append-only prerelease deployment ledger',
  );
  const readOidcIndex = external.indexOf(
    'role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_READ_ROLE_ARN }}',
  );
  const readinessIndex = external.indexOf('pnpm release:verify:observability');
  const mergedLedgerIndex = external.indexOf("'observabilityReadiness']");
  const deployOidcIndex = external.indexOf(
    'role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}',
  );
  const activateIndex = external.indexOf('pnpm release:activate');
  const finalReadOidcIndex = external.lastIndexOf(
    'role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_READ_ROLE_ARN }}',
  );
  const trafficIndex = external.indexOf('pnpm release:smoke');
  if (
    restoreIndex === -1 ||
    authIndex <= restoreIndex ||
    readOidcIndex <= authIndex ||
    readinessIndex <= readOidcIndex ||
    mergedLedgerIndex <= readinessIndex ||
    deployOidcIndex <= mergedLedgerIndex ||
    activateIndex <= deployOidcIndex ||
    finalReadOidcIndex <= activateIndex ||
    trafficIndex <= finalReadOidcIndex ||
    !external.includes('--api-record "${STAGE7_EVIDENCE_ROOT}/deployment.json"') ||
    !external.includes('--seed-evidence "${STAGE7_EVIDENCE_ROOT}/deployment.json"')
  ) {
    fail(
      'external authorization and confirmed observability must precede scheduler activation and all traffic',
    );
  }
  const externalSteps = stepBlocks(external);
  const activationCaptureStepIndex = externalSteps.findIndex((step) =>
    step.includes('name: Capture fresh activation safety under read authority'),
  );
  const activationDeployOidcStepIndex = externalSteps.findIndex((step) =>
    step.includes('role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}'),
  );
  const activationStepIndex = externalSteps.findIndex((step) =>
    step.includes('name: Activate only after authorization and confirmed observability'),
  );
  const activationCaptureStep = externalSteps[activationCaptureStepIndex] ?? '';
  const activationStep = externalSteps[activationStepIndex] ?? '';
  if (
    activationCaptureStepIndex + 1 !== activationDeployOidcStepIndex ||
    activationDeployOidcStepIndex + 1 !== activationStepIndex
  ) {
    fail(
      'activation live safety capture must remain under read authority immediately before deploy-role OIDC',
    );
  }
  for (const fragment of [
    'GITHUB_TOKEN: ${{ github.token }}',
    'pnpm release:prerelease-safety -- capture-live',
    '--phase activation',
    '--raw-diff .stage7/infra-diff/infra-diff.txt',
    '--aws-auth .stage7/infra-diff/aws-auth.json',
    '--readiness .stage7/prerelease-safety/prerelease-safety-readiness.json',
    '--output "${STAGE7_EVIDENCE_ROOT}/prerelease-activation-live-safety-recheck.json"',
  ]) {
    if (!activationCaptureStep.includes(fragment)) {
      fail(`activation live safety capture is missing: ${fragment}`);
    }
  }
  for (const fragment of [
    'GITHUB_TOKEN: ${{ github.token }}',
    'pnpm release:activate -- --scope prerelease --initial-release',
    '--raw-diff .stage7/infra-diff/infra-diff.txt',
    '--aws-auth .stage7/infra-diff/aws-auth.json',
    '--safety-readiness .stage7/prerelease-safety/prerelease-safety-readiness.json',
    '--deployment-evidence "${STAGE7_EVIDENCE_ROOT}/deployment.json"',
    '--live-safety-recheck "${STAGE7_EVIDENCE_ROOT}/prerelease-activation-live-safety-recheck.json"',
  ]) {
    if (!activationStep.includes(fragment)) {
      fail(`activation safety consumer is missing: ${fragment}`);
    }
  }
  const sandboxCaptureStepIndex = externalSteps.findIndex((step) =>
    step.includes('name: Capture fresh sandbox safety immediately before sandbox execution'),
  );
  const sandboxExecutionStepIndex = externalSteps.findIndex((step) =>
    step.includes('name: Run separately authorized sandbox smoke'),
  );
  const sandboxCaptureStep = externalSteps[sandboxCaptureStepIndex] ?? '';
  if (
    sandboxCaptureStepIndex + 1 !== sandboxExecutionStepIndex ||
    !sandboxCaptureStep.includes('if: ${{ inputs.confirm_sandbox_smoke == true }}') ||
    !sandboxCaptureStep.includes('GITHUB_TOKEN: ${{ github.token }}') ||
    !sandboxCaptureStep.includes('pnpm release:prerelease-safety -- capture-live') ||
    !sandboxCaptureStep.includes('--phase sandbox') ||
    !sandboxCaptureStep.includes(
      '--output "${STAGE7_EVIDENCE_ROOT}/prerelease-sandbox-live-safety-recheck.json"',
    )
  ) {
    fail('sandbox live safety capture must be phase-bound immediately before execution');
  }
  const liveScanStepIndex = externalSteps.findIndex((step) =>
    step.includes('name: Scan phase-bound prerelease live safety rechecks before upload'),
  );
  const liveUploadStepIndex = externalSteps.findIndex((step) =>
    step.includes('name: Preserve phase-bound prerelease live safety rechecks'),
  );
  const liveScanStep = externalSteps[liveScanStepIndex] ?? '';
  const liveUploadStep = externalSteps[liveUploadStepIndex] ?? '';
  if (
    liveScanStepIndex <= sandboxExecutionStepIndex ||
    liveUploadStepIndex !== liveScanStepIndex + 1 ||
    !liveScanStep.includes(
      'pnpm release:scan -- --scope prerelease --pre-upload "${STAGE7_EVIDENCE_ROOT}/prerelease-activation-live-safety-recheck.json"',
    ) ||
    !liveScanStep.includes(
      'if [[ -f "${STAGE7_EVIDENCE_ROOT}/prerelease-sandbox-live-safety-recheck.json" ]]; then',
    ) ||
    !liveScanStep.includes(
      'pnpm release:scan -- --scope prerelease --pre-upload "${STAGE7_EVIDENCE_ROOT}/prerelease-sandbox-live-safety-recheck.json"',
    ) ||
    !liveUploadStep.includes('name: stage7-prerelease-live-safety-rechecks') ||
    !liveUploadStep.includes(
      'output/evidence/runtime/stage-7-prerelease/prerelease-activation-live-safety-recheck.json',
    ) ||
    !liveUploadStep.includes(
      'output/evidence/runtime/stage-7-prerelease/prerelease-sandbox-live-safety-recheck.json',
    ) ||
    /(?:touch|printf|cp)\b[^\n]*prerelease-sandbox-live-safety-recheck\.json/iu.test(external)
  ) {
    fail('phase-bound prerelease live safety scan/upload chain is invalid');
  }
  const sandboxStep = stepBlocks(external).find((step) =>
    step.includes('name: Run separately authorized sandbox smoke'),
  );
  if (
    sandboxStep === undefined ||
    !sandboxStep.includes('id: sandbox_execution') ||
    !sandboxStep.includes('if: ${{ inputs.confirm_sandbox_smoke == true }}') ||
    !sandboxStep.includes('test "${CONFIRM_SANDBOX_SMOKE}" = \'true\'') ||
    !sandboxStep.includes('--sandbox-authorized') ||
    !sandboxStep.includes(
      'pnpm release:sandbox-smoke -- --scope prerelease --manifest .stage7/candidate-manifest/candidate-manifest.json',
    ) ||
    !sandboxStep.includes('--deployment .stage7/deployment') ||
    !sandboxStep.includes(
      '--live-safety-recheck "${STAGE7_EVIDENCE_ROOT}/prerelease-sandbox-live-safety-recheck.json"',
    ) ||
    !sandboxStep.includes('printf \'sandbox_executed=true\\n\' >> "${GITHUB_OUTPUT}"') ||
    sandboxStep.indexOf('printf \'sandbox_executed=true\\n\' >> "${GITHUB_OUTPUT}"') <=
      sandboxStep.indexOf('pnpm release:sandbox-smoke') ||
    !external.includes(
      'sandbox_executed: ${{ steps.sandbox_execution.outputs.sandbox_executed }}',
    ) ||
    !jobs
      .get('external-evidence')
      ?.includes('SANDBOX_EXECUTED: ${{ needs.external-verification.outputs.sandbox_executed }}') ||
    jobs.get('external-evidence')?.includes('SANDBOX_EXECUTED: ${{ inputs.confirm_sandbox_smoke }}')
  ) {
    fail('sandbox smoke must remain separately authorized and report success only after execution');
  }

  const cleanup = jobs.get('cleanup') ?? '';
  for (const fragment of [
    "if: ${{ always() && github.run_attempt == 1 && needs.approval.result == 'success' }}",
    'name: stage7-prerelease-candidate',
    'name: stage7-prerelease-candidate-manifest',
    '${{ vars.STAGE7_PRERELEASE_AWS_CLEANUP_ROLE_ARN }}',
    '--aws-cleanup',
    "'DESTROY_EPHEMERAL_STACKS'].join('\\\\0')",
    '--execute',
    '--ephemeral-only',
    '--manifest .stage7/candidate-manifest/candidate-manifest.json',
    '--confirm "${CLEANUP_CONFIRM}"',
  ]) {
    if (!cleanup.includes(fragment)) fail(`mandatory immediate cleanup is missing: ${fragment}`);
  }
  if (cleanup.includes('--enforce-expiry')) {
    fail('immediate cleanup must not pretend the future expiry has elapsed');
  }
  if (!jobs.get('summary')?.includes('if: ${{ always() && github.run_attempt == 1 }}')) {
    fail('prerelease summary must execute even when an earlier check is blocked');
  }
  if (!jobs.get('summary')?.includes('STAGE7_CANDIDATE_SHA: ${{ inputs.candidate_sha }}')) {
    fail('prerelease closeout must bind the exact candidate identity');
  }
  const prereleaseSummary = jobs.get('summary') ?? '';
  for (const stepName of [
    'Set up the pinned Node.js runtime',
    'Activate the pinned package manager',
    'Materialize and validate the approved Stage 7 config',
    'Consolidate prerelease results without promoting Stage 7',
  ]) {
    const step = stepBlocks(prereleaseSummary).find((candidate) =>
      candidate.includes(`name: ${stepName}`),
    );
    if (!step?.includes('if: ${{ always() }}')) {
      fail(`prerelease causal closeout step must run after failure: ${stepName}`);
    }
  }
  for (const artifact of [
    'stage7-prerelease-metadata',
    'stage7-prerelease-candidate-verification',
    'stage7-prerelease-candidate-manifest',
    'stage7-prerelease-integrity-security',
    'stage7-prerelease-infra-synth',
    'stage7-prerelease-release-plan',
    'stage7-prerelease-infra-diff',
    'stage7-prerelease-approval',
    'stage7-prerelease-safety-readiness',
    'stage7-prerelease-live-safety-rechecks',
    'stage7-prerelease-external-checks',
    'stage7-prerelease-cleanup',
  ]) {
    if (
      !prereleaseSummary.includes(`name: ${artifact}`) ||
      !prereleaseSummary.includes(`path: .stage7/evidence/${artifact}`)
    ) {
      fail(`prerelease exact evidence download is missing: ${artifact}`);
    }
  }
  if (
    !prereleaseSummary.includes('path: .stage7/evidence/stage6-authorized-external-evidence') ||
    /pattern:\s*stage7|merge-multiple:\s*true/iu.test(source) ||
    !source.includes('output/evidence/runtime/stage-7-prerelease/stage6-closeout.json')
  ) {
    fail('prerelease evidence downloads and Stage 6 closeout must be exact');
  }
  for (const fragment of [
    'name: stage7-prerelease-authorities',
    'name: stage7-prerelease-reports',
    'output/evidence/runtime/stage-7-prerelease/provenance-ledger.json',
    'output/evidence/runtime/stage-7-prerelease/stage7-report.md',
  ]) {
    if (!prereleaseSummary.includes(fragment)) {
      fail(`prerelease causal closeout artifact is missing: ${fragment}`);
    }
  }
  if (
    !prereleaseSummary.includes('id: scan_causal_evidence') ||
    !prereleaseSummary.includes(
      "if: ${{ always() && hashFiles('output/evidence/runtime/stage-7-prerelease/closeout.json') != '' }}",
    ) ||
    count(prereleaseSummary, "steps.scan_causal_evidence.outcome == 'success'") !== 2
  ) {
    fail('prerelease causal uploads must require a successful always-run sanitization scan');
  }
  errors.push(
    ...validateSandboxWrapper(name, external, {
      prerelease: true,
      requestProducer: jobs.get('deploy-prerelease') ?? '',
    }),
  );
  errors.push(...validatePinnedZap(name, external, { prerelease: true }));
  return errors;
}

const runCanaries = (workflow, source, validate, cases) => {
  assert.deepEqual(validate(workflow, source), []);
  for (const testCase of cases) {
    const mutated = testCase.mutate(source);
    assert.notEqual(mutated, source, `canary made no change: ${testCase.expected}`);
    const errors = validate(workflow, mutated);
    assert.ok(
      errors.some((error) => error.includes(testCase.expected)),
      `missing canary rejection for ${testCase.expected}: ${errors.join('; ')}`,
    );
  }
  return cases.length;
};

const selfTestRelease = (source) =>
  runCanaries(RELEASE_WORKFLOW, source, validateReleaseWorkflow, [
    {
      expected: 'only trigger',
      mutate: (value) =>
        changed(value, 'on:\n  workflow_dispatch:', 'on:\n  pull_request:\n  workflow_dispatch:'),
    },
    ...RELEASE_JOBS.map((id) => ({
      expected: `${id} must reject native reruns before any work`,
      mutate: (value) => withoutAttemptOneGuard(value, id),
    })),
    {
      expected: 'release-metadata must reject native reruns before any work',
      mutate: (value) =>
        replaceJob(value, 'release-metadata', (block) =>
          block.replace('github.run_attempt == 1 &&', 'github.run_attempt == 1 || true &&'),
        ),
    },
    {
      expected: 'verify-candidate must depend transitively on release-metadata',
      mutate: (value) =>
        replaceJob(value, 'verify-candidate', (block) =>
          block.replace('    needs: release-metadata\n', '    needs: detached-origin\n'),
        ),
    },
    {
      expected: 'approved official full SHA',
      mutate: (value) =>
        changed(
          value,
          'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',
          'actions/checkout@v5',
        ),
    },
    {
      expected: 'long-lived AWS credential',
      mutate: (value) =>
        changed(
          value,
          "  AWS_EC2_METADATA_DISABLED: 'true'",
          "  AWS_EC2_METADATA_DISABLED: 'true'\n  AWS_ACCESS_KEY_ID: unsafe",
        ),
    },
    {
      expected: 'one-use sandbox execution claim preflight is missing',
      mutate: (value) =>
        changed(
          value,
          'pnpm release:sandbox-claim -- --approve --scope full --request "${request}" --claim "${claim}" --receipt "${receipt}"',
          'pnpm release:sandbox-claim -- --prepare --scope full',
        ),
    },
    {
      expected: 'sandbox approval request handoff is missing',
      mutate: (value) =>
        changed(
          value,
          'pnpm release:sandbox-claim -- --request --scope full --output "${request}"',
          'pnpm release:sandbox-claim -- --prepare --scope full',
        ),
    },
    {
      expected: 'sandbox approval request handoff is missing',
      mutate: (value) =>
        changed(
          value,
          'Review sandbox-execution-request.json, then approve assessment-release-sandbox with this exact comment:',
          'Review sandbox-execution-request.json, then approve assessment-release with this exact comment:',
        ),
    },
    {
      expected: 'sandbox approval request producer must contain no secrets or authority',
      mutate: (value) =>
        replaceJob(value, 'quality', (block) =>
          block.replace(
            '          STAGE7_RELEASE_TAG: ${{ inputs.release_tag }}\n        run:',
            '          STAGE7_RELEASE_TAG: ${{ inputs.release_tag }}\n          GITHUB_TOKEN: ${{ github.token }}\n        run:',
          ),
        ),
    },
    {
      expected: 'hotswap',
      mutate: (value) =>
        changed(value, 'pnpm release:deploy:web --', 'pnpm release:deploy:web --hotswap --'),
    },
    {
      expected: 'direct AWS and CDK CLI commands are forbidden',
      mutate: (value) =>
        changed(
          value,
          '          pnpm release:scan -- --scope full --prepare-zap-target "${target}"',
          '          aws sts get-caller-identity\n          pnpm release:scan -- --scope full --prepare-zap-target "${target}"',
        ),
    },
    {
      expected: 'unscoped execute flags are forbidden',
      mutate: (value) =>
        changed(
          value,
          'pnpm release:scan -- --candidate .stage7/candidate',
          'pnpm release:scan -- --candidate .stage7/candidate --execute',
        ),
    },
    {
      expected: 'mutable checkout',
      mutate: (value) => changed(value, 'ref: ${{ inputs.candidate_sha }}', 'ref: master'),
    },
    {
      expected: 'exact ordered 25-job',
      mutate: (value) => removeJob(value, 'sandbox-smoke'),
    },
    {
      expected:
        'release reconciliation intent must bind exactly 22 files into 23 immutable bindings',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace(
            '            --previous-release-projection-index .stage7/previous/previous-release-projection-index.json \\\n',
            '',
          ),
        ),
    },
    {
      expected:
        'release reconciliation intent must bind exactly 22 files into 23 immutable bindings',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            '            --previous-target-compatibility .stage7/previous/previous-target-compatibility.json \\\n',
            '',
          ),
        ),
    },
    {
      expected: 'release reconciliation must download the exact producer artifacts',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            '          name: stage7-release-metadata\n',
            '          name: stage7-web\n',
          ),
        ),
    },
    {
      expected:
        'release reconciliation intent must bind exactly 22 files into 23 immutable bindings',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace(
            '            --config "${STAGE7_RECONCILIATION_CONFIG}" \\\n',
            '            --config "${STAGE7_CONFIG}" \\\n',
          ),
        ),
    },
    {
      expected:
        'release reconciliation config must be copied byte-exactly into the workspace before source binding',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace('          install -m 600 "${target}" "${workspace_target}"\n', ''),
        ),
    },
    {
      expected:
        'release reconciliation config must be copied byte-exactly into the workspace before source binding',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            '          printf \'STAGE7_RECONCILIATION_CONFIG=%s\\n\' "${workspace_target}" >> "${GITHUB_ENV}"\n',
            '',
          ),
        ),
    },
    {
      expected: 'rollback-check must bind the exact rollback role before guarded mutation',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            '      STAGE7_AWS_ROLLBACK_ROLE_ARN: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}\n',
            '',
          ),
        ),
    },
    {
      expected:
        'rollback-check mutations must execute inside the exact same-process successor guard',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(' --successor-guard-mode ROLLBACK_CHECK', ''),
        ),
    },
    {
      expected:
        'rollback-check mutations must execute inside the exact same-process successor guard',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            '--direction REPROMOTE_CANDIDATE --output "${STAGE7_EVIDENCE_ROOT}/versioned-repromotion-aws-transition.json"',
            '--direction ROLLBACK_TO_PREVIOUS --output "${STAGE7_EVIDENCE_ROOT}/versioned-repromotion-aws-transition.json"',
          ),
        ),
    },
    {
      expected:
        'release reconciliation config must be copied byte-exactly into the workspace before source binding',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            '          test "$(sha256sum "${workspace_target}" | cut -d \' \' -f 1)" = "${EXPECTED_STAGE7_CONFIG_SHA256}"\n',
            '',
          ),
        ),
    },
    {
      expected: 'release reconciliation must download the exact producer artifacts',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            '          name: stage7-previous-release\n',
            '          name: stage7-web\n',
          ),
        ),
    },
    {
      expected: 'release reconciliation intent must open the exact immutable journal authority',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace('/${{ github.run_id }}"', '/unrelated-run"'),
        ),
    },
    {
      expected: 'release reconciliation intent must open the exact immutable journal authority',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace(
            '"Action":["ssm:GetParameter","ssm:GetParametersByPath"]',
            '"Action":"ssm:PutParameter"',
          ),
        ),
    },
    {
      expected: 'release reconciliation intent must open the exact immutable journal authority',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace(
            '"Action":["ssm:GetParameter","ssm:GetParametersByPath"]',
            '"Action":["ssm:GetParameter","ssm:GetParametersByPath","ssm:DeleteParameter"]',
          ),
        ),
    },
    {
      expected: 'release reconciliation intent must open the exact immutable journal authority',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace(
            '"Condition":{"StringEquals":{"ssm:Overwrite":"false"}}}]}',
            '"Condition":{"StringEquals":{"ssm:Overwrite":"false"}}},{"Sid":"Extra","Effect":"Allow","Action":"ssm:GetParameter","Resource":"*"}]}',
          ),
        ),
    },
    {
      expected: 'release reconciliation intent must open the exact immutable journal authority',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace(
            '--live-effective-permissions .stage7/reconciliation-private/live-intent-journal-role-effective-permissions.json',
            '--live-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json',
          ),
        ),
    },
    {
      expected: 'release reconciliation intent must open the exact immutable journal authority',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace('node scripts/stage7/control.mjs verify-journal-authority', 'true'),
        ),
    },
    {
      expected: 'release reconciliation intent must open the exact immutable journal authority',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation-intent', (block) =>
          block.replace(
            '"Resource":"${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}"',
            '"Resource":"arn:aws:iam::111122223333:role/unrelated-journal-role"',
          ),
        ),
    },
    {
      expected: 'deploy-data full AWS operation must consume the journal role authority',
      mutate: (value) =>
        replaceJob(value, 'deploy-data', (block) =>
          block.replace(
            '--aws-auth .stage7/aws-auth/aws-auth.json --journal-role-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json --reconciliation-recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json --previous-manifest',
            '--aws-auth .stage7/aws-auth/aws-auth.json --reconciliation-recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json --previous-manifest',
          ),
        ),
    },
    {
      expected: 'deploy-data full AWS operation must consume the recovery role authority',
      mutate: (value) =>
        replaceJob(value, 'deploy-data', (block) =>
          block.replace(
            '--journal-role-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json --reconciliation-recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json --previous-manifest',
            '--journal-role-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json --previous-manifest',
          ),
        ),
    },
    {
      expected: 'release reconciliation must always classify both original protected conclusions',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            'if: ${{ always() && github.run_attempt == 1',
            'if: ${{ github.run_attempt == 1',
          ),
        ),
    },
    {
      expected: 'release reconciliation OIDC session 4 is not exact',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            '--live-effective-permissions .stage7/reconciliation-private/live-finalize-check-journal-role-effective-permissions.json',
            '--live-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json',
          ),
        ),
    },
    {
      expected: 'rollback-check reconciliation must probe and resume the exact durable terminal',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            'probe-terminal --intent .stage7/reconciliation-private/release-reconciliation-intent.json --phase ROLLBACK_CHECK',
            'probe-terminal --intent .stage7/reconciliation-private/release-reconciliation-intent.json --phase ROLLBACK_RESILIENCE',
          ),
        ),
    },
    {
      expected:
        'release-reconciliation full AWS operation must consume the recovery role authority',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            '            --reconciliation-recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json \\\n',
            '',
          ),
        ),
    },
    {
      expected: 'rollback-check reconciliation convergence contract is not exact',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            '            --transition-output .stage7/reconciliation-private/rollback-check/versioned-rollback-transition.json \\\n',
            '            --unexpected-argument forbidden \\\n            --transition-output .stage7/reconciliation-private/rollback-check/versioned-rollback-transition.json \\\n',
          ),
        ),
    },
    {
      expected: 'rollback-resilience reconciliation convergence contract is not exact',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            '            --transition-output .stage7/reconciliation-private/rollback-resilience/versioned-rollback-transition.json \\\n',
            '            --rollback .stage7/rollback/rollback.json \\\n            --transition-output .stage7/reconciliation-private/rollback-resilience/versioned-rollback-transition.json \\\n',
          ),
        ),
    },
    {
      expected:
        'rollback-check reconciliation must capture fresh phase-bound drift and smoke evidence',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            '          mv -- output/evidence/runtime/stage-7/drift.json "${STAGE7_EVIDENCE_ROOT}/drift.json"\n',
            '',
          ),
        ),
    },
    {
      expected:
        'rollback-resilience reconciliation must capture fresh phase-bound drift and smoke evidence',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            '--reconciliation-convergence .stage7/reconciliation-private/rollback-resilience/convergence.json',
            '--reconciliation-convergence .stage7/reconciliation-private/rollback-check/convergence.json',
          ),
        ),
    },
    {
      expected:
        'release reconciliation artifact must contain only the exact scanned receipts and gate',
      mutate: (value) =>
        replaceJob(value, 'release-reconciliation', (block) =>
          block.replace(
            '            .stage7/reconciliation-public/stage7-release-pre-fence-gate.json\n',
            '            .stage7/reconciliation-public/stage7-release-pre-fence-gate.json\n            .stage7/reconciliation-private/release-reconciliation-intent.json\n',
          ),
        ),
    },
    {
      expected: 'protected assessment-release',
      mutate: (value) =>
        replaceJob(value, 'deploy-web', (block) =>
          block.replace('    environment: assessment-release\n', ''),
        ),
    },
    {
      expected: 'build-or-fetch must use the protected assessment-release-read environment',
      mutate: (value) =>
        replaceJob(value, 'build-or-fetch', (block) =>
          block.replace(
            '    environment: assessment-release-read\n',
            '    environment: assessment-release\n',
          ),
        ),
    },
    {
      expected: 'aws-auth must use the protected assessment-release-read environment',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace(
            '    environment: assessment-release-read\n',
            '    environment: assessment-release\n',
          ),
        ),
    },
    {
      expected: 'infra-diff must use the protected assessment-release-read environment',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(
            '    environment: assessment-release-read\n',
            '    environment: assessment-release\n',
          ),
        ),
    },
    {
      expected: 'sandbox-smoke must use the protected assessment-release-sandbox environment',
      mutate: (value) =>
        replaceJob(value, 'sandbox-smoke', (block) =>
          block.replaceAll('assessment-release-sandbox', 'assessment-release'),
        ),
    },
    {
      expected: 'approval must use the protected assessment-release environment',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) =>
          block.replace(
            '    environment: assessment-release\n',
            '    environment: assessment-release-read\n',
          ),
        ),
    },
    {
      expected: 'must not obtain an AWS OIDC token',
      mutate: (value) =>
        replaceJob(value, 'secret-scan', (block) =>
          block.replace(
            '    runs-on: ubuntu-24.04',
            '    permissions:\n      contents: read\n      id-token: write\n    runs-on: ubuntu-24.04',
          ),
        ),
    },
    {
      expected: 'infra-synth-test must not obtain an AWS OIDC token',
      mutate: (value) =>
        replaceJob(value, 'infra-synth-test', (block) =>
          block.replace(
            '    runs-on: ubuntu-24.04',
            '    permissions:\n      contents: read\n      id-token: write\n    runs-on: ubuntu-24.04',
          ),
        ),
    },
    {
      expected: 'build-or-fetch must have the exact least-privilege AWS permissions',
      mutate: (value) =>
        replaceJob(value, 'build-or-fetch', (block) =>
          block.replace('      id-token: write\n', ''),
        ),
    },
    {
      expected: 'OIDC guard',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace('          allowed-account-ids: ${{ env.STAGE7_AWS_ACCOUNT_ID }}\n', ''),
        ),
    },
    {
      expected: 'aws-auth must use the audited read role for both auxiliary role captures',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace(
            'role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
            'role-to-assume: ${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
          ),
        ),
    },
    {
      expected: 'aws-auth must use the audited read role for both auxiliary role captures',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace(
            '          mask-aws-account-id: true\n',
            '          inline-session-policy: "{}"\n          mask-aws-account-id: true\n',
          ),
        ),
    },
    {
      expected: 'aws-auth recovery BASE capture is missing',
      mutate: (value) =>
        withoutNamedStep(
          value,
          'aws-auth',
          'Capture the exact reconciliation recovery role base permissions',
        ),
    },
    {
      expected: 'aws-auth recovery BASE capture is missing',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace(
            '--role-audit-output "${RUNNER_TEMP}/stage7-release-reconciliation-recovery-role-audit.json"',
            '--role-audit-output "${RUNNER_TEMP}/wrong-recovery-role-audit.json"',
          ),
        ),
    },
    {
      expected: 'release recovery BASE environment binding is missing',
      mutate: (value) =>
        value.replace(
          '  STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN: ${{ vars.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN }}\n',
          '',
        ),
    },
    {
      expected: 'aws-auth must bind both auxiliary authorities under the read session',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace(
            ' --reconciliation-recovery-role-effective-permissions "${STAGE7_EVIDENCE_ROOT}/stage7-release-reconciliation-recovery-role-effective-permissions.json" --evidence',
            ' --evidence',
          ),
        ),
    },
    {
      expected: 'aws-auth recovery BASE capture is missing',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace(
            '          test -n "${STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN}"\n',
            '',
          ),
        ),
    },
    {
      expected: 'stage7-aws-auth must scan exactly its three public authority files',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace(
            'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/aws-auth.json" "${STAGE7_EVIDENCE_ROOT}/stage7-release-journal-role-effective-permissions.json" "${STAGE7_EVIDENCE_ROOT}/stage7-release-reconciliation-recovery-role-effective-permissions.json"',
            'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/aws-auth.json" "${STAGE7_EVIDENCE_ROOT}/stage7-release-journal-role-effective-permissions.json" "${STAGE7_EVIDENCE_ROOT}/stage7-release-reconciliation-recovery-role-effective-permissions.json" "${STAGE7_EVIDENCE_ROOT}/unexpected.json"',
          ),
        ),
    },
    {
      expected: 'stage7-aws-auth upload must contain exactly its three public authority files',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace(
            '            output/evidence/runtime/stage-7/stage7-release-reconciliation-recovery-role-effective-permissions.json\n',
            '            output/evidence/runtime/stage-7/stage7-release-reconciliation-recovery-role-effective-permissions.json\n            output/evidence/runtime/stage-7/unexpected.json\n',
          ),
        ),
    },
    {
      expected: 'infra-diff full aws-read preflight must consume both auxiliary role authorities',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(
            ' --reconciliation-recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json --no-write',
            ' --no-write',
          ),
        ),
    },
    {
      expected: 'config channel is missing',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace('          chmod 600 "${target}"\n', ''),
        ),
    },
    {
      expected: 'summary config channel is missing',
      mutate: (value) =>
        replaceJob(value, 'summary', (block) =>
          block.replace('          chmod 600 "${target}"\n', ''),
        ),
    },
    {
      expected: 'candidate upload must precede',
      mutate: (value) =>
        replaceJob(value, 'build-or-fetch', (block) =>
          block.replace(
            '            output/release/build/public-config.json',
            '            output/release/build/public-config.json\n            output/evidence/runtime/stage-7/candidate-manifest.json',
          ),
        ),
    },
    {
      expected: 'build-once order',
      mutate: (value) =>
        replaceJob(value, 'build-or-fetch', (block) =>
          block.replace(
            '          pnpm build\n          pnpm release:build',
            '          pnpm release:build\n          pnpm build',
          ),
        ),
    },
    {
      expected: 'application build must finish before AWS OIDC',
      mutate: (value) =>
        replaceJob(value, 'build-or-fetch', (block) => {
          const withoutEarlyBuild = block.replace(
            '          pnpm build\n          pnpm release:build\n',
            '',
          );
          return withoutEarlyBuild.replace(
            '        run: pnpm infra:synth:release -- --versioned-update --output output/release/build/iac',
            '        run: |\n          set -euo pipefail\n          pnpm build\n          pnpm release:build\n          pnpm infra:synth:release -- --versioned-update --output output/release/build/iac',
          );
        }),
    },
    {
      expected: 'build and scan must prove AWS_ACCESS_KEY_ID is absent',
      mutate: (value) =>
        replaceJob(value, 'build-or-fetch', (block) =>
          block.replace('          test -z "${AWS_ACCESS_KEY_ID:-}"\n', ''),
        ),
    },
    {
      expected: 'temporary AWS credential must be cleared: AWS_SESSION_TOKEN',
      mutate: (value) =>
        replaceJob(value, 'build-or-fetch', (block) =>
          block.replace("            printf 'AWS_SESSION_TOKEN=\\n'\n", ''),
        ),
    },
    {
      expected: 'legacy or nested build paths',
      mutate: (value) => changed(value, 'output/release/build/api/', 'apps/api/dist/'),
    },
    {
      expected: 'exact review artifact is missing',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace('            output/evidence/runtime/stage-7/infra-diff.txt\n', ''),
        ),
    },
    {
      expected: 'infra-diff has an invalid fail-closed dependency chain',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) => block.replace('      - aws-auth\n', '')),
    },
    {
      expected: 'infra-diff journal authority input is missing',
      mutate: (value) =>
        withoutNamedStep(value, 'infra-diff', 'Download the exact journal role authority'),
    },
    {
      expected: 'infra-diff journal authority input is missing',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(
            '          path: .stage7/aws-auth\n',
            '          path: .stage7/wrong-auth\n',
          ),
        ),
    },
    {
      expected: 'infra-diff journal authority input is missing',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(
            '--journal-role-effective-permissions .stage7/aws-auth/stage7-release-journal-role-effective-permissions.json',
            '--journal-role-effective-permissions .stage7/infra-diff/stage7-release-journal-role-effective-permissions.json',
          ),
        ),
    },
    {
      expected: 'exact 8-file N-1 projection',
      mutate: (value) =>
        withoutNamedStep(value, 'infra-diff', 'Preserve the exact immutable N-1 recovery contract'),
    },
    {
      expected: 'exact 8-file N-1 projection',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(
            '            .stage7/previous/previous-release-projection-index.json\n',
            '',
          ),
        ),
    },
    {
      expected: 'exact 8-file N-1 projection',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(
            ' --previous-target-compatibility .stage7/previous/previous-target-compatibility.json',
            '',
          ),
        ),
    },
    {
      expected: 'non-distinct mutable web target before OIDC',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(' --target-web .stage7/candidate/web', ''),
        ),
    },
    {
      expected: 'deploy-data must bind reviewed immutable input',
      mutate: (value) =>
        replaceJob(value, 'deploy-data', (block) =>
          block.replaceAll(' --approval .stage7/approval/approval.json', ''),
        ),
    },
    {
      expected: 'protected diff approval binding is missing',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) =>
          block.replaceAll('          STAGE7_PROTECTED_ENVIRONMENT: assessment-release\n', ''),
        ),
    },
    {
      expected: 'approval must have exactly actions:read and contents:read',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) => block.replace('      actions: read\n', '')),
    },
    {
      expected: 'protected diff approval binding is missing',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) =>
          block.replace(
            ' --github-approval-evidence "${STAGE7_EVIDENCE_ROOT}/github-environment-approval.json"',
            '',
          ),
        ),
    },
    {
      expected: 'exact IAM review confirmation is missing',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(' "STAGE7_IAM_DIFF_REVIEWED_SHA256=${diff_sha}"', ' "UNBOUND"'),
        ),
    },
    {
      expected: 'versioned rollback rehearsal is missing',
      mutate: (value) =>
        changed(value, '--direction ROLLBACK_TO_PREVIOUS', '--direction UNKNOWN_TARGET'),
    },
    {
      expected: 'activation ledger must be sealed',
      mutate: (value) =>
        replaceJob(value, 'postdeploy-smoke', (block) =>
          block.replace('          name: stage7-activation\n', ''),
        ),
    },
    {
      expected: 'automatic durable recovery is missing',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace('name == "stage7-activation"', 'name == "ignored"'),
        ),
    },
    {
      expected: 'automatic durable recovery is missing',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace('pnpm release:verify -- --emergency-recovery-no-action', 'true #'),
        ),
    },
    {
      expected: 'automatic durable recovery is missing',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace(
            '--verify-candidate-active-no-action --outcome',
            '--recover-if-active --outcome',
          ),
        ),
    },
    {
      expected: 'automatic durable recovery is missing',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace('verify-emergency-recovery-no-action-outcome', 'disabled-outcome-check'),
        ),
    },
    {
      expected: 'OIDC session 1 must assume',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace(
            'role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
            'role-to-assume: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          ),
        ),
    },
    {
      expected: 'healthy and unhealthy authority branches are not exact',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace(
            "if: ${{ always() && steps.downstream.outputs.healthy == 'true' }}",
            "if: ${{ always() && steps.downstream.outputs.healthy != 'true' }}",
          ),
        ),
    },
    {
      expected: 'healthy and unhealthy authority branches are not exact',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace('pnpm release:scan -- --pre-upload "${files[@]}"', 'true # scan removed'),
        ),
    },
    {
      expected: 'healthy and unhealthy authority branches are not exact',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace(
            '--verify-candidate-active-no-action --outcome',
            '--verify-candidate-active-no-action update-stack --outcome',
          ),
        ),
    },
    {
      expected: 'automatic durable recovery is missing',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace(
            'test "${recovery_decision}" = \'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED\'',
            'test "${recovery_decision}" = \'PASS\'',
          ),
        ),
    },
    {
      expected: 'must not wait on rehearsal approval or trust activation artifacts',
      mutate: (value) =>
        replaceJob(value, 'emergency-recovery', (block) =>
          block.replace(
            '--deployment-evidence .stage7/web/web.json',
            '--deployment-evidence .stage7/activation/activation.json',
          ),
        ),
    },
    {
      expected: 'versioned rollback rehearsal is missing',
      mutate: (value) =>
        changed(
          value,
          'pnpm release:verify:drift -- --scope full --versioned-update --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
          'pnpm disabled:verify:drift -- --scope full --versioned-update --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
        ),
    },
    {
      expected: 'versioned rollback rehearsal is missing',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace('        id: scan-public-rollback\n', '        id: unbound-scan\n'),
        ),
    },
    {
      expected: 'rollback pending egress closeout authority and inputs must be exact',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            '--repromotion-checkpoint "${STAGE7_EVIDENCE_ROOT}/versioned-repromotion-checkpoint.json"',
            '--repromotion-checkpoint "${STAGE7_EVIDENCE_ROOT}/versioned-rollback-checkpoint.json"',
          ),
        ),
    },
    {
      expected: 'stage7-rollback must scan and upload exactly its eleven public root basenames',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            '            output/evidence/runtime/stage-7/drift.json\n',
            '            output/evidence/runtime/stage-7/drift.json\n            output/evidence/runtime/stage-7/emergency-recovery.json\n',
          ),
        ),
    },
    {
      expected: 'stage7-rollback must scan and upload exactly its eleven public root basenames',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            '"${STAGE7_EVIDENCE_ROOT}/versioned-repromotion-smoke.json" "${STAGE7_EVIDENCE_ROOT}/versioned-repromotion-checkpoint.json" "${STAGE7_EVIDENCE_ROOT}/rollback.json"',
            '"${STAGE7_EVIDENCE_ROOT}/versioned-repromotion-smoke.json" "${STAGE7_EVIDENCE_ROOT}/rollback.json"',
          ),
        ),
    },
    {
      expected: 'versioned-update release guard',
      mutate: (value) =>
        changed(
          value,
          'test "${VERSIONED_UPDATE}" = \'true\'',
          'test "${VERSIONED_UPDATE}" = \'false\'',
        ),
    },
    {
      expected: 'deploy-data must bind reviewed immutable input',
      mutate: (value) =>
        replaceJob(value, 'deploy-data', (block) =>
          block.replace(
            '          name: stage7-previous-release\n',
            '          name: ignored-previous-release\n',
          ),
        ),
    },
    {
      expected: 'pre-freeze synthesis identity is missing',
      mutate: (value) =>
        replaceJob(value, 'build-or-fetch', (block) => {
          const marker = '      - name: Bind the exceptional read-only pre-freeze authority';
          const index = block.indexOf(marker);
          if (index < 0) return block;
          return `${block.slice(0, index)}${block
            .slice(index)
            .replace('          STAGE7_RELEASE_TAG: ${{ inputs.release_tag }}\n', '')}`;
        }),
    },
    {
      expected: 'pre-freeze synthesis must remain a unique read-only exception',
      mutate: (value) =>
        replaceJob(value, 'build-or-fetch', (block) =>
          block.replace('--aws-read --pre-freeze-synth', '--aws-deploy --pre-freeze-synth'),
        ),
    },
    {
      expected: 'remain inactive before readiness',
      mutate: (value) =>
        replaceJob(value, 'deploy-web', (block) =>
          block.replace(
            '      - name: Preserve sanitized web evidence',
            '      - name: Premature activation\n        run: pnpm release:activate -- --versioned-update\n      - name: Preserve sanitized web evidence',
          ),
        ),
    },
    {
      expected: 'web evidence and its review request must use two exact single-entry artifacts',
      mutate: (value) =>
        replaceJob(value, 'deploy-web', (block) =>
          block.replace(
            '          path: output/evidence/runtime/stage-7/web.json\n',
            '          path: |\n            output/evidence/runtime/stage-7/web.json\n            output/evidence/runtime/stage-7/external-authorization-request.json\n',
          ),
        ),
    },
    {
      expected: 'web evidence and its review request must use two exact single-entry artifacts',
      mutate: (value) =>
        replaceJob(value, 'deploy-web', (block) =>
          block.replace(
            '          name: release-external-authorization-request\n',
            '          name: stage7-web-review-request\n',
          ),
        ),
    },
    {
      expected: 'postdeploy smoke must reconstruct the exact web and review-request directory',
      mutate: (value) =>
        replaceJob(value, 'postdeploy-smoke', (block) =>
          block.replace(
            '          name: release-external-authorization-request\n',
            '          name: ignored-external-authorization-request\n',
          ),
        ),
    },
    {
      expected: 'confirmed observability readiness is missing before smoke',
      mutate: (value) =>
        replaceJob(value, 'postdeploy-smoke', (block) =>
          block.replace(
            '        run: pnpm release:verify:observability -- --record .stage7/observability-pending/observability.json\n',
            '',
          ),
        ),
    },
    {
      expected: 'private smoke input channel is missing',
      mutate: (value) =>
        replaceJob(value, 'postdeploy-smoke', (block) =>
          block.replace(
            'STAGE7_SMOKE_INPUTS_B64: ${{ secrets.STAGE7_SMOKE_INPUTS_B64 }}',
            'STAGE7_SMOKE_INPUTS_B64: disabled',
          ),
        ),
    },
    {
      expected: 'must bind explicit deploy confirmation immediately after OIDC',
      mutate: (value) =>
        replaceJob(value, 'deploy-data', (block) =>
          block.replace('          CONFIRM_DEPLOY: ${{ inputs.confirm_deploy }}\n', ''),
        ),
    },
    {
      expected: 'OIDC session 1 must assume',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            'role-session-name: e7-rollback-read-one-${{ github.run_id }}\n          role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
            'role-session-name: e7-rollback-read-one-${{ github.run_id }}\n          role-to-assume: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          ),
        ),
    },
    {
      expected: 'non-mutating publication preparation is missing',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace('          pnpm release:github-publication:self-test\n', ''),
        ),
    },
    {
      expected: 'publication must require the durable immutable successor fence',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace(
            "    if: ${{ github.run_attempt == 1 && needs.release-successor-fence.result == 'success' }}\n",
            '',
          ),
        ),
    },
    {
      expected: 'release successor fence must use the exact bounded journal OIDC session',
      mutate: (value) =>
        replaceJob(value, 'release-successor-fence', (block) =>
          block.replace(
            'parameter/checkout/stage7/release-fence/${{ inputs.candidate_sha }}/${{ github.run_id }}',
            'parameter/checkout/stage7/release-fence/${{ inputs.candidate_sha }}/*',
          ),
        ),
    },
    {
      expected: 'release successor fence live authority capture is missing',
      mutate: (value) =>
        replaceJob(value, 'release-successor-fence', (block) =>
          block.replace(
            'node scripts/stage7/release-successor-cli.mjs capture-caller-runtime',
            'node scripts/stage7/release-successor-cli.mjs disabled-caller-runtime',
          ),
        ),
    },
    {
      expected: 'release successor fence producer is missing',
      mutate: (value) =>
        replaceJob(value, 'release-successor-fence', (block) =>
          block.replace(
            '--pre-fence-gate .stage7/reconciliation/stage7-release-pre-fence-gate.json \\\n',
            '',
          ),
        ),
    },
    {
      expected: 'release successor fence upload must be the final exact artifact step',
      mutate: (value) =>
        replaceJob(
          value,
          'release-successor-fence',
          (block) =>
            `${block.trimEnd()}\n      - name: Invalid work after fence upload\n        run: exit 1\n`,
        ),
    },
    {
      expected: 'publication immutable successor fence revalidation is missing',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace('control.mjs verify-successor-fence', 'control.mjs disabled-fence'),
        ),
    },
    {
      expected: 'publication artifact upload must be the final publish-release step',
      mutate: (value) =>
        replaceJob(
          value,
          'publish-release',
          (block) =>
            `${block.trimEnd()}\n      - name: Invalid work after publication upload\n        run: exit 1\n`,
        ),
    },
    {
      expected: 'native publication control is missing',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace('--result "${operation}"', '--unsafe-overwrite "${operation}"'),
        ),
    },
    {
      expected:
        'verified publication artifact is missing: output/evidence/stage7-publication/publication-target-proof.json',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace(
            '            output/evidence/stage7-publication/publication-target-proof.json\n',
            '',
          ),
        ),
    },
    {
      expected: 'publication artifact must contain exactly five root-level evidence files',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace(
            '            output/evidence/stage7-publication/publication-proof.json\n',
            '            output/evidence/stage7-publication/publication-proof.json\n            output/release/publication/README.md\n',
          ),
        ),
    },
    {
      expected:
        'verified publication artifact is missing: output/evidence/stage7-publication/publication-operation.json',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace(
            '            output/evidence/stage7-publication/publication-operation.json\n',
            '            output/evidence/stage7-publication/nested/publication-operation.json\n',
          ),
        ),
    },
    {
      expected: 'native publication control is missing',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace(
            '          pnpm release:verify -- --publication-target "${plan}" --publication-evidence .stage7/evidence --resilience-app .stage7/candidate/iac --evidence "${target_proof}"\n',
            '',
          ),
        ),
    },
    {
      expected: 'publication order must be prepare, pre-scan, healthy-target preflight',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace(
            '          pnpm release:verify -- --publication-target "${plan}" --publication-evidence .stage7/evidence --resilience-app .stage7/candidate/iac --evidence "${target_proof}"\n          pnpm release:github-publication -- --plan "${plan}" --result "${operation}"',
            '          pnpm release:github-publication -- --plan "${plan}" --result "${operation}"\n          pnpm release:verify -- --publication-target "${plan}" --publication-evidence .stage7/evidence --resilience-app .stage7/candidate/iac --evidence "${target_proof}"',
          ),
        ),
    },
    {
      expected: 'without mutating protected master',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace(
            '          pnpm release:github-publication --',
            '          gh api --method PUT "/repos/x/contents/README.md"\n          pnpm release:github-publication --',
          ),
        ),
    },
    {
      expected: 'deployed quality contract is missing',
      mutate: (value) =>
        replaceJob(value, 'quality', (block) =>
          block.replace(
            'pnpm exec playwright install --with-deps chromium firefox webkit',
            'pnpm exec playwright install --with-deps chromium',
          ),
        ),
    },
    {
      expected: 'deployed quality contract is missing',
      mutate: (value) =>
        replaceJob(value, 'quality', (block) =>
          block.replace('          pnpm release:scan -- --pre-upload "${request}"\n', ''),
        ),
    },
    {
      expected: 'quality evidence and sandbox review request must use exact separate artifacts',
      mutate: (value) =>
        replaceJob(value, 'quality', (block) =>
          block.replace(
            '          path: output/evidence/runtime/stage-7/quality.json\n',
            '          path: |\n            output/evidence/runtime/stage-7/quality.json\n            output/evidence/runtime/stage-7/sandbox-execution-request.json\n',
          ),
        ),
    },
    {
      expected: 'deployed quality contract is missing',
      mutate: (value) =>
        replaceJob(value, 'quality', (block) =>
          block.replace(
            '          name: release-sandbox-execution-request\n',
            '          name: stage7-quality-request\n',
          ),
        ),
    },
    {
      expected: 'quality evidence and sandbox review request must use exact separate artifacts',
      mutate: (value) =>
        replaceJob(value, 'sandbox-smoke', (block) =>
          block.replace(
            '          name: release-sandbox-execution-request\n',
            '          name: ignored-sandbox-execution-request\n',
          ),
        ),
    },
    {
      expected: 'must not obtain an AWS OIDC token',
      mutate: (value) =>
        replaceJob(value, 'quality', (block) =>
          block.replace(
            '    runs-on: ubuntu-24.04',
            '    permissions:\n      contents: read\n      id-token: write\n    runs-on: ubuntu-24.04',
          ),
        ),
    },
    {
      expected: 'full external-authorization handoff is missing',
      mutate: (value) =>
        replaceJob(value, 'deploy-web', (block) =>
          block.replace(
            '--external-authorization-request .stage7/web',
            '--external-authorization-request output',
          ),
        ),
    },
    {
      expected: 'postdeploy-smoke full authorization binding is missing',
      mutate: (value) =>
        replaceJob(value, 'postdeploy-smoke', (block) =>
          block.replace('          test -n "${STAGE7_EXTERNAL_AUTHORIZATIONS_B64}"\n', ''),
        ),
    },
    {
      expected: 'must not expose the full external-authorization payload',
      mutate: (value) =>
        replaceJob(value, 'edge-security', (block) =>
          block.replace(
            '          test -n "${STAGE7_EXTERNAL_AUTHORIZATIONS_B64}"',
            '          echo "${STAGE7_EXTERNAL_AUTHORIZATIONS_B64}"',
          ),
        ),
    },
    {
      expected: 'pinned passive ZAP contract is missing',
      mutate: (value) =>
        replaceJob(value, 'edge-security', (block) =>
          block.replace('node scripts/stage7/zap-passive-inventory.mjs create', 'true'),
        ),
    },
    {
      expected: 'active or unbounded ZAP scans are forbidden',
      mutate: (value) =>
        replaceJob(value, 'edge-security', (block) =>
          block.replace(
            'node scripts/stage7/zap-passive-capture.mjs',
            'node scripts/stage7/zap-passive-capture.mjs --active',
          ),
        ),
    },
    {
      expected: 'native publication control is missing',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace(
            '"${publication_root}/publication-target-proof.json" "${publication_root}/publication-operation.json" "${publication_root}/publication-proof.json"',
            '"${publication_root}/publication-target-proof.json" "${publication_root}/publication-proof.json"',
          ),
        ),
    },
    {
      expected: 'causal closeout uploads must require a successful always-run sanitization scan',
      mutate: (value) =>
        replaceJob(value, 'summary', (block) =>
          block.replace(" && steps.scan_causal_evidence.outcome == 'success'", ''),
        ),
    },
    {
      expected: 'causal closeout artifact is missing: name: stage7-release-reports',
      mutate: (value) => withoutNamedStep(value, 'summary', 'Preserve sanitized Stage 7 reports'),
    },
    {
      expected: 'causal closeout step must run after upstream or download failure',
      mutate: (value) =>
        replaceJob(value, 'summary', (block) =>
          block.replace(
            '      - name: Consolidate all three Stage 7 gates fail-closed\n        if: ${{ always() }}\n',
            '      - name: Consolidate all three Stage 7 gates fail-closed\n',
          ),
        ),
    },
    {
      expected: 'only the exact alert and one-use sandbox secret set',
      mutate: (value) =>
        changed(
          value,
          'STAGE7_ALERT_EMAIL: ${{ secrets.STAGE7_ALERT_EMAIL }}',
          'STAGE7_ALERT_EMAIL: ${{ secrets.UNAPPROVED_SECRET }}',
        ),
    },
  ]);

const selfTestPrerelease = (source) =>
  runCanaries(PRERELEASE_WORKFLOW, source, validatePrereleaseWorkflow, [
    {
      expected: 'prerelease must not reuse full-release config, region or role variables',
      mutate: (value) =>
        changed(value, '${{ vars.STAGE7_PRERELEASE_CONFIG_B64 }}', '${{ vars.STAGE7_CONFIG_B64 }}'),
    },
    {
      expected: 'only trigger',
      mutate: (value) =>
        changed(value, 'on:\n  workflow_dispatch:', 'on:\n  push:\n  workflow_dispatch:'),
    },
    ...PRERELEASE_JOBS.map((id) => ({
      expected: `${id} must reject native reruns before any work`,
      mutate: (value) => withoutAttemptOneGuard(value, id),
    })),
    {
      expected: 'prerelease-metadata must reject native reruns before any work',
      mutate: (value) =>
        replaceJob(value, 'prerelease-metadata', (block) =>
          block.replace('github.run_attempt == 1 &&', 'github.run_attempt == 1 || true &&'),
        ),
    },
    {
      expected: 'verify-candidate must depend transitively on prerelease-metadata',
      mutate: (value) =>
        replaceJob(value, 'verify-candidate', (block) =>
          block.replace('    needs: prerelease-metadata\n', '    needs: detached-origin\n'),
        ),
    },
    {
      expected: 'exact ordered 13-job',
      mutate: (value) => removeJob(value, 'external-evidence'),
    },
    {
      expected: 'protected prerelease safety producer is missing',
      mutate: (value) =>
        replaceJob(value, 'prerelease-safety-readiness', (block) =>
          block.replace(' --raw-diff .stage7/infra-diff/infra-diff.txt', ''),
        ),
    },
    {
      expected: 'prerelease safety artifact scan/upload chain is invalid',
      mutate: (value) =>
        replaceJob(value, 'prerelease-safety-readiness', (block) =>
          block.replace(
            'pnpm release:scan -- --scope prerelease --pre-upload "${STAGE7_EVIDENCE_ROOT}/prerelease-safety-readiness.json"',
            'pnpm disabled:scan -- --scope prerelease',
          ),
        ),
    },
    {
      expected: 'must bind read authority to run id and attempt',
      mutate: (value) =>
        replaceJob(value, 'prerelease-safety-readiness', (block) =>
          block.replace(
            'role-session-name: e7pre-safety-${{ github.run_id }}-${{ github.run_attempt }}',
            'role-session-name: e7pre-safety-${{ github.run_id }}',
          ),
        ),
    },
    {
      expected: 'deploy-role OIDC must remain behind GitHub-only watchdog live gate',
      mutate: (value) =>
        replaceJob(value, 'deploy-prerelease', (block) => {
          const steps = stepBlocks(block);
          const gate = steps.find((step) =>
            step.includes('name: Revalidate live watchdog authority before deploy-role OIDC'),
          );
          const oidc = steps.find((step) =>
            step.includes('role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}'),
          );
          assert.ok(gate && oidc);
          return block.replace(`${gate}\n${oidc}`, `${oidc}\n${gate}`);
        }),
    },
    {
      expected: 'prerelease mutation safety consumer is missing for release:deploy:data',
      mutate: (value) =>
        replaceJob(value, 'deploy-prerelease', (block) => {
          const step = stepBlocks(block).find((candidate) =>
            candidate.includes('pnpm release:deploy:data'),
          );
          assert.ok(step);
          return block.replace(
            step,
            step.replace('          GITHUB_TOKEN: ${{ github.token }}\n', ''),
          );
        }),
    },
    {
      expected:
        'activation live safety capture must remain under read authority immediately before deploy-role OIDC',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) => {
          const steps = stepBlocks(block);
          const capture = steps.find((step) =>
            step.includes('name: Capture fresh activation safety under read authority'),
          );
          const oidc = steps.find((step) =>
            step.includes('role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}'),
          );
          assert.ok(capture && oidc);
          return block.replace(`${capture}\n${oidc}`, `${oidc}\n${capture}`);
        }),
    },
    {
      expected: 'activation live safety capture is missing: GITHUB_TOKEN',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) => {
          const step = stepBlocks(block).find((candidate) =>
            candidate.includes('name: Capture fresh activation safety under read authority'),
          );
          assert.ok(step);
          return block.replace(
            step,
            step.replace('          GITHUB_TOKEN: ${{ github.token }}\n', ''),
          );
        }),
    },
    {
      expected: 'sandbox live safety capture must be phase-bound immediately before execution',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace(
            '      - name: Capture fresh sandbox safety immediately before sandbox execution',
            '      - name: Disabled fresh sandbox safety capture',
          ),
        ),
    },
    {
      expected: 'phase-bound prerelease live safety scan/upload chain is invalid',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace(
            'pnpm release:scan -- --scope prerelease --pre-upload "${STAGE7_EVIDENCE_ROOT}/prerelease-activation-live-safety-recheck.json"',
            'pnpm disabled:scan -- --scope prerelease',
          ),
        ),
    },
    {
      expected: 'phase-bound prerelease live safety scan/upload chain is invalid',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace(
            '      - name: Scan phase-bound prerelease live safety rechecks before upload',
            '      - name: Fabricate optional sandbox recheck\n        run: touch output/evidence/runtime/stage-7-prerelease/prerelease-sandbox-live-safety-recheck.json\n      - name: Scan phase-bound prerelease live safety rechecks before upload',
          ),
        ),
    },
    {
      expected: 'must not publish',
      mutate: (value) => `${value}\n# pnpm release:publish\n`,
    },
    {
      expected: 'one-use sandbox execution claim preflight is missing',
      mutate: (value) =>
        changed(
          value,
          'pnpm release:sandbox-claim -- --approve --scope prerelease --request "${request}" --claim "${claim}" --receipt "${receipt}"',
          'pnpm release:sandbox-claim -- --prepare --scope prerelease',
        ),
    },
    {
      expected: 'sandbox approval request handoff is missing',
      mutate: (value) =>
        changed(
          value,
          'pnpm release:sandbox-claim -- --request --scope prerelease --output "${request}"',
          'pnpm release:sandbox-claim -- --prepare --scope prerelease',
        ),
    },
    {
      expected: 'infra-diff must use the protected assessment-prerelease-read environment',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(
            '    environment: assessment-prerelease-read\n',
            '    environment: assessment-prerelease\n',
          ),
        ),
    },
    {
      expected: 'approval must use the protected assessment-prerelease environment',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) =>
          block.replace(
            '    environment: assessment-prerelease\n',
            '    environment: assessment-prerelease-read\n',
          ),
        ),
    },
    {
      expected: 'every prerelease scan must bind the prerelease scope explicitly',
      mutate: (value) =>
        changed(
          value,
          'pnpm release:scan -- --scope prerelease --cloud-assembly .stage7/candidate/iac',
          'pnpm release:scan -- --cloud-assembly .stage7/candidate/iac',
        ),
    },
    {
      expected: 'external authorization binding is missing',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace(
            "const required=['data','api','observability','web','seed','expiryRegistration']",
            "const required=['data','observability','web','seed','expiryRegistration']",
          ),
        ),
    },
    {
      expected: 'protected assessment-prerelease-external',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace('    environment: assessment-prerelease-external\n', ''),
        ),
    },
    {
      expected: 'config channel is missing',
      mutate: (value) =>
        replaceJob(value, 'deploy-prerelease', (block) =>
          block.replace('          umask 077\n', ''),
        ),
    },
    {
      expected: 'summary config channel is missing',
      mutate: (value) =>
        replaceJob(value, 'summary', (block) =>
          block.replace('          chmod 600 "${target}"\n', ''),
        ),
    },
    {
      expected: 'EPHEMERAL_PRERELEASE scope without a tag',
      mutate: (value) =>
        replaceJob(value, 'build-once', (block) =>
          block.replace(
            '--source-artifact-sha256 "${SOURCE_ARTIFACT_SHA256}"',
            '--source-artifact-sha256 "${SOURCE_ARTIFACT_SHA256}" --tag v1.0.0',
          ),
        ),
    },
    {
      expected: 'candidate upload must precede',
      mutate: (value) =>
        replaceJob(value, 'build-once', (block) =>
          block.replace(
            '            output/release/build/public-config.json',
            '            output/release/build/public-config.json\n            output/evidence/runtime/stage-7-prerelease/candidate-manifest.json',
          ),
        ),
    },
    {
      expected: 'deploy/seed/activation order',
      mutate: (value) =>
        replaceJob(value, 'deploy-prerelease', (block) =>
          block.replace('pnpm release:seed --', 'pnpm disabled:seed --'),
        ),
    },
    {
      expected: 'exact prerelease review artifact is missing',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(
            '            output/evidence/runtime/stage-7-prerelease/infra-diff.txt\n',
            '',
          ),
        ),
    },
    {
      expected: 'release:deploy:data prerelease guard is missing',
      mutate: (value) =>
        replaceJob(value, 'deploy-prerelease', (block) => {
          const step = stepBlocks(block).find((candidate) =>
            candidate.includes('pnpm release:deploy:data'),
          );
          assert.ok(step);
          return block.replace(
            step,
            step.replace(' --approval .stage7/approval/approval.json', ''),
          );
        }),
    },
    {
      expected: 'protected prerelease diff approval binding is missing',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) =>
          block.replaceAll('          STAGE7_PROTECTED_ENVIRONMENT: assessment-prerelease\n', ''),
        ),
    },
    {
      expected: 'approval must have exactly actions:read and contents:read',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) => block.replace('      actions: read\n', '')),
    },
    {
      expected: 'protected prerelease diff approval binding is missing',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) =>
          block.replace(
            ' --github-approval-evidence "${STAGE7_EVIDENCE_ROOT}/github-environment-approval.json"',
            '',
          ),
        ),
    },
    {
      expected: 'exact prerelease IAM review confirmation is missing',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace(' "STAGE7_IAM_DIFF_REVIEWED_SHA256=${diff_sha}"', ' "UNBOUND"'),
        ),
    },
    {
      expected: 'scheduler activation before external authorization is forbidden',
      mutate: (value) =>
        replaceJob(value, 'deploy-prerelease', (block) =>
          block.replace(
            '      - name: Emit a sanitized request for the three external authorizations',
            '      - name: Premature scheduler activation\n        run: pnpm release:activate -- --scope prerelease --initial-release\n      - name: Emit a sanitized request for the three external authorizations',
          ),
        ),
    },
    {
      expected: 'external authorization binding is missing',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace('          test -n "${STAGE7_EXTERNAL_AUTHORIZATIONS_B64}"\n', ''),
        ),
    },
    {
      expected: 'external authorization and confirmed observability',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace(
            '      - name: Materialize and bind protected external-check authorization',
            '      - name: Unauthorized traffic\n        run: pnpm release:smoke\n      - name: Materialize and bind protected external-check authorization',
          ),
        ),
    },
    {
      expected: 'must verify observability immediately after read-role OIDC',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace(
            '          pnpm release:verify:observability -- --record .stage7/deployment/deployment.json --scope prerelease\n',
            '',
          ),
        ),
    },
    {
      expected: 'OIDC session 3 must assume',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace(
            'role-session-name: e7pre-external-read-${{ github.run_id }}-${{ github.run_attempt }}\n          role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_READ_ROLE_ARN }}',
            'role-session-name: e7pre-external-read-${{ github.run_id }}-${{ github.run_attempt }}\n          role-to-assume: ${{ vars.STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN }}',
          ),
        ),
    },
    {
      expected: 'sandbox smoke must remain separately',
      mutate: (value) =>
        replaceJob(value, 'external-verification', (block) =>
          block.replace(
            '        id: sandbox_execution\n        if: ${{ inputs.confirm_sandbox_smoke == true }}\n',
            '        id: sandbox_execution\n',
          ),
        ),
    },
    {
      expected: 'mandatory immediate cleanup is missing',
      mutate: (value) =>
        replaceJob(value, 'cleanup', (block) =>
          block.replace(
            "    if: ${{ always() && github.run_attempt == 1 && needs.approval.result == 'success' }}\n",
            '',
          ),
        ),
    },
    {
      expected: 'future expiry',
      mutate: (value) =>
        replaceJob(value, 'cleanup', (block) =>
          block.replace(
            '--execute --ephemeral-only',
            '--execute --ephemeral-only --enforce-expiry',
          ),
        ),
    },
    {
      expected: 'OIDC guard',
      mutate: (value) =>
        replaceJob(value, 'cleanup', (block) =>
          block.replace('          allowed-account-ids: ${{ env.STAGE7_AWS_ACCOUNT_ID }}\n', ''),
        ),
    },
    {
      expected: 'external-verification must consume protected',
      mutate: (value) =>
        changed(
          value,
          'STAGE7_CLOUDFRONT_SIGNED_COOKIE_B64: ${{ secrets.STAGE7_CLOUDFRONT_SIGNED_COOKIE_B64 }}',
          'STAGE7_CLOUDFRONT_SIGNED_COOKIE_B64: ${{ vars.STAGE7_CLOUDFRONT_SIGNED_COOKIE_B64 }}',
        ),
    },
    {
      expected: 'external-verification must consume protected',
      mutate: (value) =>
        changed(
          value,
          '          STAGE7_CLOUDFRONT_EXPIRED_SIGNED_COOKIE_B64: ${{ secrets.STAGE7_CLOUDFRONT_EXPIRED_SIGNED_COOKIE_B64 }}\n',
          '',
        ),
    },
    {
      expected: 'prerelease causal uploads must require a successful always-run sanitization scan',
      mutate: (value) =>
        replaceJob(value, 'summary', (block) =>
          block.replace(" && steps.scan_causal_evidence.outcome == 'success'", ''),
        ),
    },
    {
      expected: 'prerelease causal closeout artifact is missing: name: stage7-prerelease-reports',
      mutate: (value) =>
        withoutNamedStep(value, 'summary', 'Preserve sanitized prerelease reports'),
    },
    {
      expected: 'prerelease causal closeout step must run after failure',
      mutate: (value) =>
        replaceJob(value, 'summary', (block) =>
          block.replace(
            '      - name: Consolidate prerelease results without promoting Stage 7\n        if: ${{ always() }}\n',
            '      - name: Consolidate prerelease results without promoting Stage 7\n',
          ),
        ),
    },
    {
      expected: 'only the exact alert and one-use sandbox secret set',
      mutate: (value) =>
        changed(
          value,
          'STAGE7_ALERT_EMAIL: ${{ secrets.STAGE7_ALERT_EMAIL }}',
          'STAGE7_ALERT_EMAIL: ${{ secrets.AWS_SECRET_ACCESS_KEY }}',
        ),
    },
  ]);

const selfTestWorkflowCommands = (release, prerelease, packageSource) => {
  assert.deepEqual(validateReleaseWorkflowCommands([release, prerelease], packageSource), []);
  const cases = [
    {
      expected: 'workflow command is orphaned: release:orphan',
      workflows: [changed(release, 'pnpm release:seed --', 'pnpm release:orphan --'), prerelease],
      packageSource,
    },
    {
      expected: 'required Stage 7 mapping is missing: release:sandbox-smoke',
      workflows: [release, prerelease],
      packageSource: JSON.stringify(
        (() => {
          const value = JSON.parse(packageSource);
          delete value.scripts['release:sandbox-smoke'];
          return value;
        })(),
      ),
    },
    {
      expected: 'required Stage 7 mapping is missing: release:prerelease-safety',
      workflows: [release, prerelease],
      packageSource: JSON.stringify(
        (() => {
          const value = JSON.parse(packageSource);
          delete value.scripts['release:prerelease-safety'];
          return value;
        })(),
      ),
    },
    {
      expected: 'Stage 7 mapping diverges for release:prerelease-safety:self-test',
      workflows: [release, prerelease],
      packageSource: changed(
        packageSource,
        '"release:prerelease-safety:self-test": "node scripts/stage7/prerelease-safety-readiness.mjs self-test"',
        '"release:prerelease-safety:self-test": "node scripts/stage7/prerelease-safety-readiness.mjs --self-test"',
      ),
    },
    {
      expected: 'required Stage 7 mapping is missing: release:github-publication',
      workflows: [release, prerelease],
      packageSource: JSON.stringify(
        (() => {
          const value = JSON.parse(packageSource);
          delete value.scripts['release:github-publication'];
          return value;
        })(),
      ),
    },
    {
      expected: 'Stage 7 mapping diverges for release:github-publication:self-test',
      workflows: [release, prerelease],
      packageSource: changed(
        packageSource,
        '"release:github-publication:self-test": "node scripts/stage7/github-publication.mjs --self-test"',
        '"release:github-publication:self-test": "node scripts/stage7/github-publication.mjs"',
      ),
    },
    {
      expected: 'Stage 7 mapping diverges for stage7:prepare-readme',
      workflows: [release, prerelease],
      packageSource: changed(
        packageSource,
        '"stage7:prepare-readme": "node scripts/stage7/control.mjs prepare-readme"',
        '"stage7:prepare-readme": "node scripts/stage7/control.mjs publish"',
      ),
    },
    {
      expected: 'Stage 7 mapping diverges for release:smoke',
      workflows: [release, prerelease],
      packageSource: changed(
        packageSource,
        '"release:smoke": "node scripts/stage7/control.mjs smoke"',
        '"release:smoke": "node scripts/stage7/control.mjs verify"',
      ),
    },
    {
      expected: 'direct Stage 6 execution alias is forbidden',
      workflows: [release, prerelease],
      packageSource: changed(
        packageSource,
        '"release:sandbox-smoke": "node scripts/stage7/control.mjs sandbox-smoke"',
        '"release:sandbox-smoke": "pnpm sandbox:authorized:execute"',
      ),
    },
  ];
  for (const testCase of cases) {
    const errors = validateReleaseWorkflowCommands(testCase.workflows, testCase.packageSource);
    assert.ok(
      errors.some((error) => error.includes(testCase.expected)),
      `missing package mapping canary rejection for ${testCase.expected}: ${errors.join('; ')}`,
    );
  }
  return cases.length;
};

function main() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = path.resolve(here, '..', '..');
  const releasePath = path.join(root, '.github', 'workflows', RELEASE_WORKFLOW);
  const prereleasePath = path.join(root, '.github', 'workflows', PRERELEASE_WORKFLOW);
  if (!fs.existsSync(releasePath) || !fs.existsSync(prereleasePath)) {
    process.stderr.write(
      'release-workflow policy: FAIL (release.yml and prerelease.yml are required)\n',
    );
    process.exitCode = 1;
    return;
  }
  const release = fs.readFileSync(releasePath, 'utf8');
  const prerelease = fs.readFileSync(prereleasePath, 'utf8');
  const packageSource = fs.readFileSync(path.join(root, 'package.json'), 'utf8');
  if (process.argv.includes('--self-test')) {
    const total =
      selfTestRelease(release) +
      selfTestPrerelease(prerelease) +
      selfTestWorkflowCommands(release, prerelease, packageSource);
    process.stdout.write(`release-workflow policy self-test: PASS (${total} canaries)\n`);
    return;
  }
  const errors = [
    ...validateReleaseWorkflow(RELEASE_WORKFLOW, release),
    ...validatePrereleaseWorkflow(PRERELEASE_WORKFLOW, prerelease),
    ...validateReleaseWorkflowCommands([release, prerelease], packageSource),
  ];
  if (errors.length > 0) {
    process.stderr.write('release-workflow policy: FAIL\n');
    for (const error of errors) process.stderr.write(`${error}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(
    `release-workflow policy: PASS (${RELEASE_JOBS.length} release jobs; ${PRERELEASE_JOBS.length} prerelease jobs)\n`,
  );
}

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main();
}
