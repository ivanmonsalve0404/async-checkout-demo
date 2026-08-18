#!/usr/bin/env node
import { strict as assert } from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const RELEASE_WORKFLOW = 'release.yml';
const PRERELEASE_WORKFLOW = 'prerelease.yml';

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
  'rollback-check',
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
  ['rollback-check', ['${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}', '--aws-rollback']],
]);
const PRERELEASE_AWS = new Map([
  ['infra-diff', ['${{ vars.STAGE7_AWS_READ_ROLE_ARN }}', '--aws-read']],
  ['deploy-prerelease', ['${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}', '--aws-deploy']],
  ['external-verification', ['${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}', '--aws-deploy']],
  ['cleanup', ['${{ vars.STAGE7_AWS_CLEANUP_ROLE_ARN }}', '--aws-cleanup']],
]);

const CONFIG_FRAGMENTS = [
  'EXPECTED_STAGE7_CONFIG_SHA256: ${{ inputs.config_sha256 }}',
  'STAGE7_CONFIG_B64: ${{ vars.STAGE7_CONFIG_B64 }}',
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

const REQUIRED_WORKFLOW_SCRIPT_MAPPINGS = new Map([
  [
    'build',
    'pnpm --filter @checkout/contracts build && pnpm --filter @checkout/api build && pnpm --filter @checkout/web build',
  ],
  ['infra:test', 'pnpm --filter @checkout/infra test'],
  ['infra:synth:release', 'node scripts/stage7/aws-ops.mjs synth'],
  ['infra:diff:release', 'node scripts/stage7/aws-ops.mjs diff'],
  ['release:build', 'node scripts/stage7/build.mjs'],
  ['release:preflight', 'node scripts/stage7/control.mjs preflight'],
  ['release:verify-candidate', 'node scripts/stage7/control.mjs verify-candidate'],
  ['release:manifest', 'node scripts/stage7/control.mjs manifest'],
  ['release:scan', 'node scripts/stage7/control.mjs scan'],
  ['release:plan', 'node scripts/stage7/control.mjs plan'],
  ['release:smoke', 'node scripts/stage7/control.mjs smoke'],
  ['release:sandbox-smoke', 'node scripts/stage7/control.mjs sandbox-smoke'],
  ['release:quality', 'node scripts/stage7/control.mjs quality'],
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
const blockEnvironment = (block) => /^ {4}environment:\s*([^\s]+)\s*$/mu.exec(block)?.[1];
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
    'initial_release',
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
    'publish-release',
    'summary',
    ...RELEASE_AWS.keys(),
  ]),
  aws: RELEASE_AWS,
  protected: new Map(
    [
      'approval',
      'build-or-fetch',
      'aws-auth',
      'infra-diff',
      'deploy-data',
      'deploy-api',
      'deploy-observability',
      'deploy-web',
      'postdeploy-smoke',
      'edge-security',
      'quality',
      'sandbox-smoke',
      'rollback-check',
      'publish-release',
    ].map((job) => [job, 'assessment-release']),
  ),
  publishJob: 'publish-release',
  alertJob: 'deploy-observability',
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
    ['infra-diff', 'assessment-prerelease'],
    ['deploy-prerelease', 'assessment-prerelease'],
    ['external-verification', 'assessment-prerelease-external'],
    ['external-evidence', 'assessment-prerelease'],
    ['cleanup', 'assessment-prerelease'],
  ]),
  publishJob: undefined,
  alertJob: 'deploy-prerelease',
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
    'STAGE7_AWS_REGION: ${{ vars.STAGE7_AWS_REGION }}',
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
  const workflowEnvironment = topLevelBlock(source, 'env');
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
    if (!PINNED_ACTION.test(reference) || !ACTIONS.has(reference)) {
      fail(`action must use an approved official full SHA: ${reference}`);
    }
  }
  if (actionReferences.length === 0) fail('at least one pinned action is required');

  const checkoutSteps = stepBlocks(source).filter((step) =>
    step.includes('uses: actions/checkout@'),
  );
  if (checkoutSteps.length !== spec.jobs.length) {
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
  if (!same([...jobs.keys()], spec.jobs)) {
    fail(`the exact ordered ${spec.jobs.length}-job workflow contract is required`);
  }
  for (const id of spec.jobs) {
    const block = jobs.get(id);
    if (block === undefined) continue;
    if (!/^ {4}runs-on:\s*ubuntu-24\.04\s*$/mu.test(block)) fail(`${id} must pin ubuntu-24.04`);
    if (!/^ {4}timeout-minutes:\s*[1-9][0-9]*\s*$/mu.test(block))
      fail(`${id} must have a finite timeout`);
    if (!same(jobNeeds(block), spec.needs.get(id) ?? []))
      fail(`${id} has an invalid fail-closed dependency chain`);
    const expectedEnvironment = spec.protected.get(id);
    const actualEnvironment = blockEnvironment(block);
    if (expectedEnvironment !== undefined && actualEnvironment !== expectedEnvironment) {
      fail(`${id} must use the protected ${expectedEnvironment} environment`);
    }
    if (expectedEnvironment === undefined && actualEnvironment !== undefined) {
      fail(`${id} must not consume a protected deployment environment`);
    }

    const permissions = jobPermissions(block);
    if (spec.aws.has(id)) {
      const expectedPermissions =
        releaseSpec === spec && id === 'build-or-fetch'
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
        fail(`${id} must have exactly contents:read and id-token:write`);
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
        for (const fragment of CONFIG_FRAGMENTS) {
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
      const isReleasePostdeploy = releaseSpec === spec && id === 'postdeploy-smoke';
      const isReleaseRollback = releaseSpec === spec && id === 'rollback-check';
      const expectedAwsSteps = isPrereleaseExternal
        ? 3
        : isReleasePostdeploy
          ? 3
          : isReleaseRollback
            ? 4
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
      if (isReleasePostdeploy) {
        const expectedRoles = [
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
        ];
        const sessionIndexes = awsSteps.map((step) => steps.indexOf(step));
        for (const [index, expectedRole] of expectedRoles.entries()) {
          if (!awsSteps[index]?.includes(`role-to-assume: ${expectedRole}`)) {
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
      } else if (isReleaseRollback) {
        const expectedRoles = [
          '${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
        ];
        const expectedGuards = ['--aws-rollback', '--aws-read', '--aws-rollback', '--aws-read'];
        const expectedOperations = [
          'pnpm release:rollback:api',
          'pnpm release:smoke -- --scope full --post-rollback',
          'pnpm release:activate --',
          'pnpm release:smoke -- --scope full --post-repromotion',
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
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}',
          '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
        ];
        const sessionIndexes = awsSteps.map((step) => steps.indexOf(step));
        for (const [index, role] of expectedRoles.entries()) {
          if (!awsSteps[index]?.includes(`role-to-assume: ${role}`)) {
            fail(`${id} OIDC session ${index + 1} must assume ${role}`);
          }
        }
        const readAuthority = steps[(sessionIndexes[0] ?? -2) + 1] ?? '';
        const deployAuthority = steps[(sessionIndexes[1] ?? -2) + 1] ?? '';
        const finalReadAuthority = steps[(sessionIndexes[2] ?? -2) + 1] ?? '';
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
  if (count(source, 'STAGE7_CONFIG_B64: ${{ vars.STAGE7_CONFIG_B64 }}') !== spec.configJobs.size) {
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
      : 'pnpm infra:synth:release -- --initial-release --output output/release/build/iac',
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
    'node scripts/stage7/zap-passive-capture.mjs',
    '--target-file "${target}"',
    '--report "${report}"',
    '--count "${request_count_file}"',
    '--rules scripts/stage7/zap-passive-rules.tsv',
    '--image-digest zaproxy/zap-stable@sha256:51dbcc578b217ea7563b22a6948f5f41dd2002936fc5148300077f988663b4aa',
    'STAGE7_ZAP_REPORT=%s\\n',
    'STAGE7_ZAP_REQUEST_COUNT=%s\\n',
    'STAGE7_ZAP_RULESET=%s\\n',
    'STAGE7_ZAP_VERSION=2.16.1\\n',
    validation,
  ]) {
    if (!block.includes(fragment)) fail(`pinned passive ZAP contract is missing: ${fragment}`);
  }
  const preflightIndex = block.indexOf('pnpm release:preflight');
  const captureIndex = block.indexOf('node scripts/stage7/zap-passive-capture.mjs');
  const validationIndex = block.lastIndexOf(validation);
  if (preflightIndex === -1 || captureIndex <= preflightIndex || validationIndex <= captureIndex) {
    fail('ZAP capture must run after authority and before fail-closed report validation');
  }
  if (/zap-(?:full|api)-scan|--active|ajaxSpider|ascan/iu.test(block)) {
    fail('active or unbounded ZAP scans are forbidden');
  }
  return errors;
};

const validateSandboxWrapper = (name, block, { prerelease }) => {
  const errors = [];
  const fail = (message) => errors.push(`${name}: ${message}`);
  const materialize = stepBlocks(block).find((step) =>
    step.includes('name: Materialize the original one-use AUTH-E6-02 capability'),
  );
  const wrapper = stepBlocks(block).find((step) => step.includes('pnpm release:sandbox-smoke'));
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
  const command = prerelease
    ? 'pnpm release:sandbox-smoke -- --scope prerelease --manifest .stage7/candidate-manifest/candidate-manifest.json --deployment .stage7/deployment --approved-environment --non-public'
    : 'pnpm release:sandbox-smoke -- --scope full --manifest .stage7/candidate-manifest/candidate-manifest.json --deployment .stage7/web --approved-environment';
  const preflight = prerelease
    ? 'pnpm release:preflight -- --scope prerelease --sandbox-authorized --manifest .stage7/candidate-manifest/candidate-manifest.json --approved-environment'
    : 'pnpm release:preflight -- --scope full --sandbox-authorized --manifest .stage7/candidate-manifest/candidate-manifest.json --approved-environment';
  if (!block.includes(preflight)) fail(`guarded sandbox wrapper is missing: ${preflight}`);
  for (const fragment of [
    command,
    prerelease
      ? 'STAGE7_PROTECTED_ENVIRONMENT: assessment-prerelease-external'
      : 'STAGE7_PROTECTED_ENVIRONMENT: assessment-release',
    'STAGE6_SANDBOX_EXECUTION: EXECUTE_AUTH02_ONCE',
    'STAGE6_SANDBOX_KILL_SWITCH: ARMED_AUTH02',
    "STAGE6_SANDBOX_MUTATION_LIMIT: '1'",
    "STAGE6_SANDBOX_FIXTURE_AUTHORIZED: 'YES'",
    'STAGE6_SANDBOX_ORIGIN: https://sandbox.wompi.co',
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
  const preflightIndex = block.lastIndexOf('--sandbox-authorized');
  const wrapperIndex = block.indexOf('pnpm release:sandbox-smoke');
  if (
    materializeIndex === -1 ||
    preflightIndex <= materializeIndex ||
    wrapperIndex <= preflightIndex
  ) {
    fail('AUTH-E6-02 materialization and Stage 7 preflight must precede sandbox execution');
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
      step.includes('name: Materialize private full-release smoke inputs before re-promotion'),
    ),
  ];
  const validations = [
    stepBlocks(postdeploy).find((step) =>
      step.includes('name: Validate private smoke binding locally before initial activation'),
    ),
    stepBlocks(rollback).find((step) =>
      step.includes('name: Revalidate private smoke binding locally before re-promotion'),
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
      index === 0 ? 'smoke-input-preflight.json' : 'repromotion-smoke-input-preflight.json';
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
    fail('private smoke inputs must be materialized after readiness and before initial activation');
  }
  const unavailableSmoke = rollback.indexOf('pnpm release:smoke -- --scope full --post-rollback');
  const rollbackMaterialize = rollback.indexOf(
    'name: Materialize private full-release smoke inputs before re-promotion',
  );
  const rollbackValidation = rollback.indexOf(
    'pnpm release:preflight -- --scope full --smoke-inputs',
  );
  const repromotion = rollback.indexOf('pnpm release:activate');
  const finalSmoke = rollback.indexOf('pnpm release:smoke -- --scope full --post-repromotion');
  if (
    unavailableSmoke === -1 ||
    rollbackMaterialize <= unavailableSmoke ||
    rollbackValidation <= rollbackMaterialize ||
    repromotion <= rollbackValidation ||
    finalSmoke <= repromotion
  ) {
    fail(
      'private smoke inputs must be materialized only after unavailable smoke and before re-promotion',
    );
  }
  return errors;
};

export function validateReleaseWorkflow(name, input) {
  const source = normalize(input);
  const errors = validateCommon(name, source, releaseSpec);
  const fail = (message) => errors.push(`${name}: ${message}`);
  const jobs = workflowJobs(source);
  for (const fragment of [
    'STAGE7_ENVIRONMENT: assessment-release',
    '[[ "${RELEASE_TAG}" =~ ^v[0-9]+\\.[0-9]+\\.[0-9]+-rc\\.[1-9][0-9]*$ ]]',
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
    'pnpm release:rollback:web',
    'pnpm release:rollback:api',
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
    'INITIAL_RELEASE: ${{ inputs.initial_release }}',
    'test "${INITIAL_RELEASE}" = \'true\'',
  ]) {
    if (!metadata.includes(fragment)) fail(`initial-only release guard is missing: ${fragment}`);
  }
  if (
    /previous_release_run_id|previous_manifest_sha256|--previous-manifest|--verify-previous-manifest|stage7-approved-previous-manifest/iu.test(
      source,
    )
  ) {
    fail('update and previous-manifest release paths are forbidden in the initial-only workflow');
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
    'pnpm infra:synth:release -- --initial-release --output output/release/build/iac',
    'pnpm infra:synth:release -- --initial-release --verify .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
    'pnpm infra:diff:release -- --initial-release --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
  ]) {
    if (!source.includes(fragment))
      fail(`initial-only infrastructure plan is missing: ${fragment}`);
  }

  const deployApi = jobs.get('deploy-api') ?? '';
  const apiInitial = stepBlocks(deployApi).find((step) =>
    step.includes('name: Deploy the initial versioned API and reconciler aliases'),
  );
  if (
    !apiInitial?.includes('--initial-release') ||
    count(deployApi, 'pnpm release:deploy:api') !== 1
  ) {
    fail('API deployment must be the single staged initial-release path');
  }

  const deployWeb = jobs.get('deploy-web') ?? '';
  const webInitial = stepBlocks(deployWeb).find((step) =>
    step.includes('name: Deploy the initial versioned web assets'),
  );
  if (
    !webInitial?.includes('--initial-release') ||
    count(deployWeb, 'pnpm release:deploy:web') !== 1 ||
    deployWeb.includes('pnpm release:activate')
  ) {
    fail(
      'web deployment must be the single staged initial path and remain inactive before readiness',
    );
  }
  for (const fragment of [
    'pnpm release:preflight -- --scope full --external-authorization-request .stage7/web --evidence "${STAGE7_EVIDENCE_ROOT}/external-authorization-request.json"',
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/web.json" "${STAGE7_EVIDENCE_ROOT}/external-authorization-request.json"',
    'output/evidence/runtime/stage-7/external-authorization-request.json',
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

  const fullExternalJobs = [
    ['postdeploy-smoke', 'uses: aws-actions/configure-aws-credentials@'],
    ['edge-security', 'uses: aws-actions/configure-aws-credentials@'],
    ['quality', 'pnpm release:quality'],
    ['sandbox-smoke', 'uses: aws-actions/configure-aws-credentials@'],
    ['rollback-check', 'uses: aws-actions/configure-aws-credentials@'],
    ['publish-release', 'remote_master="$(gh api'],
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
    if (configIndex === -1 || authIndex <= configIndex || operationIndex <= authIndex) {
      fail(`${job} must bind full authorization after config and before OIDC or traffic`);
    }
  }
  if (
    count(
      source,
      'STAGE7_EXTERNAL_AUTHORIZATIONS_B64: ${{ vars.STAGE7_EXTERNAL_AUTHORIZATIONS_B64 }}',
    ) !== fullExternalJobs.length
  ) {
    fail('full external-authorization payload must exist only in the six target-traffic jobs');
  }
  for (const job of ['deploy-data', 'deploy-api', 'deploy-observability', 'deploy-web']) {
    const block = jobs.get(job) ?? '';
    for (const fragment of [
      'name: stage7-candidate-manifest',
      'name: stage7-infra-diff',
      'path: .stage7/infra-diff',
      'name: stage7-approval',
      'path: .stage7/approval',
      '--initial-release',
      '--manifest .stage7/candidate-manifest/candidate-manifest.json',
      '--plan .stage7/infra-diff/infra-diff.json',
      '--approval .stage7/approval/approval.json',
    ]) {
      if (!block.includes(fragment)) fail(`${job} must bind reviewed immutable input: ${fragment}`);
    }
  }
  const infraDiff = jobs.get('infra-diff') ?? '';
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
    'path: .stage7/infra-diff',
    'STAGE7_PROTECTED_ENVIRONMENT: assessment-release',
    'pnpm release:preflight -- --approval .stage7/infra-diff',
    'name: stage7-approval',
    'path: output/evidence/runtime/stage-7/approval.json',
  ]) {
    if (!approvalJob.includes(fragment))
      fail(`protected diff approval binding is missing: ${fragment}`);
  }
  const deployObservability = jobs.get('deploy-observability') ?? '';
  const postdeploySmoke = jobs.get('postdeploy-smoke') ?? '';
  const activateInitial = stepBlocks(postdeploySmoke).find((step) =>
    step.includes('name: Activate the initial candidate'),
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
    'name: internal-stage7-initial-activation',
    'path: output/evidence/runtime/stage-7/activation.json',
  ]) {
    if (!postdeploySmoke.includes(fragment)) {
      fail(`confirmed observability readiness is missing before smoke: ${fragment}`);
    }
  }
  if (
    !activateInitial?.includes('--initial-release') ||
    count(postdeploySmoke, 'pnpm release:activate') !== 1
  ) {
    fail('post-readiness activation must use only the staged initial-release path');
  }
  for (const activationStep of [activateInitial ?? '']) {
    for (const fragment of [
      '--manifest .stage7/candidate-manifest/candidate-manifest.json',
      '--api-record .stage7/api/api.json',
      '--web-record .stage7/web/web.json',
      '--seed-evidence .stage7/data/data.json',
      '--observability-evidence "${STAGE7_EVIDENCE_ROOT}/observability.json"',
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

  const rollback = jobs.get('rollback-check') ?? '';
  for (const fragment of [
    'name: internal-stage7-initial-activation',
    'path: output/evidence/runtime/stage-7',
    'release:rollback:api -- --record .stage7/api/api.json --initial-release --to-disabled',
    'release:rollback:web -- --record .stage7/web/web.json --initial-release --to-unpublished',
    'release:smoke -- --scope full --post-rollback --initial-release --expected-manifest .stage7/candidate-manifest/candidate-manifest.json',
    '--observability-evidence .stage7/observability/observability.json --re-promote --initial-release',
    'release:smoke -- --scope full --post-repromotion --expected-manifest .stage7/candidate-manifest/candidate-manifest.json',
    'release:verify:drift -- --scope full --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
    'release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/activation.json" "${STAGE7_EVIDENCE_ROOT}/drift.json"',
    'output/evidence/runtime/stage-7/activation.json',
    'output/evidence/runtime/stage-7/drift.json',
  ]) {
    if (!rollback.includes(fragment)) fail(`initial rollback rehearsal is missing: ${fragment}`);
  }
  const initialActivationUpload = postdeploySmoke.indexOf(
    'name: internal-stage7-initial-activation',
  );
  const initialActivationScan = postdeploySmoke.indexOf(
    'pnpm release:scan -- --pre-upload "${STAGE7_EVIDENCE_ROOT}/activation.json"',
  );
  if (initialActivationScan <= smokeIndex || initialActivationUpload <= initialActivationScan) {
    fail('initial activation ledger handoff must follow smoke and sanitized scanning');
  }
  if (postdeploySmoke.includes('name: stage7-initial-activation')) {
    fail('internal activation ledger must not collide with final stage7-* evidence downloads');
  }
  const initialOrder = [
    'release:rollback:api',
    'release:rollback:web',
    'release:smoke -- --scope full --post-rollback',
    'release:activate --',
    'release:smoke -- --scope full --post-repromotion',
    'release:verify:drift -- --scope full',
    'name: Preserve sanitized rollback evidence',
  ];
  let modeIndex = -1;
  for (const fragment of initialOrder) {
    const index = rollback.indexOf(fragment, modeIndex + 1);
    if (index === -1 || index <= modeIndex) {
      fail(`initial rollback verification order is invalid at: ${fragment}`);
      break;
    }
    modeIndex = index;
  }
  const publication = jobs.get('publish-release') ?? '';
  const quality = jobs.get('quality') ?? '';
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
    'path: output/evidence/runtime/stage-7/quality.json',
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
  const preparationStep = stepBlocks(publication).find((step) =>
    step.includes('name: Prepare the immutable publication package without external writes'),
  );
  const nativeStep = stepBlocks(publication).find((step) =>
    step.includes('name: Publish README and the verified release candidate natively'),
  );
  const publicationArtifact = stepBlocks(publication).find((step) =>
    step.includes('name: Preserve the verified publication package and proof'),
  );
  if (!preparationStep?.includes('pnpm release:publish -- --evidence .stage7/evidence')) {
    fail('publication must first prepare a non-mutating package from verified evidence');
  }
  for (const fragment of [
    'GH_TOKEN: ${{ github.token }}',
    'test "${GITHUB_REPOSITORY}" = \'ivanmonsalve0404/async-checkout-demo\'',
    'test "${GITHUB_REF}" = \'refs/heads/master\'',
    'test "${remote_master}" = "${STAGE7_CANDIDATE_SHA}"',
    'test "${remote_tag}" = "${STAGE7_CANDIDATE_SHA}"',
    'if gh release view "${STAGE7_RELEASE_TAG}"',
    'sha:p.expectedReadmeGitBlobSha',
    'gh api --method PUT "/repos/${GITHUB_REPOSITORY}/contents/README.md"',
    'r.content?.sha!==p.desiredReadmeGitBlobSha',
    'r.commit?.parents?.[0]?.sha!==process.env.CANDIDATE_SHA',
    'gh release create "${STAGE7_RELEASE_TAG}"',
    '--verify-tag --target "${STAGE7_CANDIDATE_SHA}"',
    '--notes-file "${notes}" --prerelease',
    'pnpm release:verify -- --publication-native "${plan}"',
    '--evidence "${STAGE7_EVIDENCE_ROOT}/publication-proof.json" --external-writes-performed 2',
    'pnpm release:scan -- --pre-upload output/release/publication',
  ]) {
    if (!nativeStep?.includes(fragment)) fail(`native publication control is missing: ${fragment}`);
  }
  if (
    count(publication, 'GH_TOKEN: ${{ github.token }}') !== 1 ||
    /\bgit\s+push\b|\bgh\s+(?:pr|repo)\b|--latest\b/iu.test(publication)
  ) {
    fail('native publication must use only two bounded ephemeral-token writes');
  }
  for (const fragment of [
    'output/release/publication/README.md',
    'output/release/publication/release-notes.md',
    'output/release/publication/publication-plan.json',
    'output/evidence/runtime/stage-7/publication.json',
    'output/evidence/runtime/stage-7/publication-proof.json',
  ]) {
    if (!publicationArtifact?.includes(fragment)) {
      fail(`verified publication artifact is missing: ${fragment}`);
    }
  }
  if (publicationArtifact?.includes('output/release/publication/candidate-manifest.json')) {
    fail('publication artifact must not duplicate the canonical candidate-manifest basename');
  }
  const preparationIndex = publication.indexOf('pnpm release:publish');
  const readmeWriteIndex = publication.indexOf('gh api --method PUT');
  const releaseWriteIndex = publication.indexOf('gh release create');
  const publicationProofIndex = publication.indexOf('--publication-native');
  if (
    preparationIndex === -1 ||
    readmeWriteIndex <= preparationIndex ||
    releaseWriteIndex <= readmeWriteIndex ||
    publicationProofIndex <= releaseWriteIndex
  ) {
    fail('publication order must be prepare, guarded README write, release write, remote proof');
  }
  if (!jobs.get('summary')?.includes('if: ${{ always() }}')) {
    fail('summary must execute even when an earlier gate fails');
  }
  if (/\bpnpm\s+release:cleanup\b/iu.test(source)) {
    fail('full release cleanup must remain in a separately authorized workflow');
  }
  errors.push(...validatePrivateSmokeInputs(name, postdeploySmoke, rollback));
  errors.push(
    ...validateSandboxWrapper(name, jobs.get('sandbox-smoke') ?? '', { prerelease: false }),
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

  const deploy = jobs.get('deploy-prerelease') ?? '';
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
    'STAGE7_PROTECTED_ENVIRONMENT: assessment-prerelease',
    'pnpm release:preflight -- --scope prerelease --approval .stage7/infra-diff',
    'name: stage7-prerelease-approval',
    'path: output/evidence/runtime/stage-7-prerelease/approval.json',
  ]) {
    if (!prereleaseApproval.includes(fragment)) {
      fail(`protected prerelease diff approval binding is missing: ${fragment}`);
    }
  }

  const external = jobs.get('external-verification') ?? '';
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
    'role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
    'pnpm release:verify:observability -- --record .stage7/deployment/deployment.json --scope prerelease',
    "const required=['data','api','observability','web','seed','expiryRegistration','observabilityReadiness']",
    'role-to-assume: ${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}',
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
  const readOidcIndex = external.indexOf('role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}');
  const readinessIndex = external.indexOf('pnpm release:verify:observability');
  const mergedLedgerIndex = external.indexOf("'observabilityReadiness']");
  const deployOidcIndex = external.indexOf(
    'role-to-assume: ${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}',
  );
  const activateIndex = external.indexOf('pnpm release:activate');
  const finalReadOidcIndex = external.lastIndexOf(
    'role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
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
      'pnpm release:sandbox-smoke -- --scope prerelease --manifest .stage7/candidate-manifest/candidate-manifest.json --deployment .stage7/deployment --approved-environment --non-public',
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
    "if: ${{ always() && needs.approval.result == 'success' }}",
    'name: stage7-prerelease-candidate',
    'name: stage7-prerelease-candidate-manifest',
    '${{ vars.STAGE7_AWS_CLEANUP_ROLE_ARN }}',
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
  if (!jobs.get('summary')?.includes('if: ${{ always() }}')) {
    fail('prerelease summary must execute even when an earlier check is blocked');
  }
  if (!jobs.get('summary')?.includes('STAGE7_CANDIDATE_SHA: ${{ inputs.candidate_sha }}')) {
    fail('prerelease closeout must bind the exact candidate identity');
  }
  errors.push(...validateSandboxWrapper(name, external, { prerelease: true }));
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
      expected: 'exact ordered 20-job',
      mutate: (value) => removeJob(value, 'sandbox-smoke'),
    },
    {
      expected: 'protected assessment-release',
      mutate: (value) =>
        replaceJob(value, 'deploy-web', (block) =>
          block.replace('    environment: assessment-release\n', ''),
        ),
    },
    {
      expected: 'aws-auth must use the protected assessment-release environment',
      mutate: (value) =>
        replaceJob(value, 'aws-auth', (block) =>
          block.replace('    environment: assessment-release\n', ''),
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
      expected: 'build-or-fetch must have exactly contents:read and id-token:write',
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
            '        run: pnpm infra:synth:release -- --initial-release --output output/release/build/iac',
            '        run: |\n          set -euo pipefail\n          pnpm build\n          pnpm release:build\n          pnpm infra:synth:release -- --initial-release --output output/release/build/iac',
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
      expected: 'deploy-data must bind reviewed immutable input',
      mutate: (value) =>
        replaceJob(value, 'deploy-data', (block) =>
          block.replace(' --approval .stage7/approval/approval.json', ''),
        ),
    },
    {
      expected: 'protected diff approval binding is missing',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) =>
          block.replace('          STAGE7_PROTECTED_ENVIRONMENT: assessment-release\n', ''),
        ),
    },
    {
      expected: 'initial rollback rehearsal is missing',
      mutate: (value) =>
        changed(
          value,
          'release:rollback:web -- --record .stage7/web/web.json --initial-release --to-unpublished',
          'release:rollback:web -- --record .stage7/web/web.json --initial-release',
        ),
    },
    {
      expected: 'confirmed observability readiness is missing before smoke',
      mutate: (value) =>
        replaceJob(value, 'postdeploy-smoke', (block) =>
          block.replace('          name: internal-stage7-initial-activation\n', ''),
        ),
    },
    {
      expected: 'initial rollback rehearsal is missing',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace('          name: internal-stage7-initial-activation\n', ''),
        ),
    },
    {
      expected: 'initial rollback rehearsal is missing',
      mutate: (value) =>
        changed(
          value,
          'pnpm release:verify:drift -- --scope full --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
          'pnpm disabled:verify:drift -- --scope full --app .stage7/candidate/iac --manifest .stage7/candidate-manifest/candidate-manifest.json',
        ),
    },
    {
      expected: 'initial rollback rehearsal is missing',
      mutate: (value) =>
        changed(value, '            output/evidence/runtime/stage-7/activation.json\n', ''),
    },
    {
      expected: 'initial-only release guard',
      mutate: (value) =>
        changed(
          value,
          'test "${INITIAL_RELEASE}" = \'true\'',
          'test "${INITIAL_RELEASE}" = \'false\'',
        ),
    },
    {
      expected: 'update and previous-manifest release paths are forbidden',
      mutate: (value) => `${value}\n# --previous-manifest forbidden.json\n`,
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
            '      - name: Premature activation\n        run: pnpm release:activate -- --initial-release\n      - name: Preserve sanitized web evidence',
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
      expected: 'OIDC session 2 must assume',
      mutate: (value) =>
        replaceJob(value, 'rollback-check', (block) =>
          block.replace(
            'role-session-name: e7-rollback-read-${{ github.run_id }}\n          role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
            'role-session-name: e7-rollback-read-${{ github.run_id }}\n          role-to-assume: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
          ),
        ),
    },
    {
      expected: 'native publication control is missing',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace('sha:p.expectedReadmeGitBlobSha', 'sha:p.desiredReadmeGitBlobSha'),
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
      expected: 'native publication control is missing',
      mutate: (value) =>
        replaceJob(value, 'publish-release', (block) =>
          block.replace('--external-writes-performed 2', '--external-writes-performed 3'),
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
      expected: 'only trigger',
      mutate: (value) =>
        changed(value, 'on:\n  workflow_dispatch:', 'on:\n  push:\n  workflow_dispatch:'),
    },
    {
      expected: 'exact ordered 12-job',
      mutate: (value) => removeJob(value, 'external-evidence'),
    },
    {
      expected: 'must not publish',
      mutate: (value) => `${value}\n# pnpm release:publish\n`,
    },
    {
      expected: 'infra-diff must use the protected assessment-prerelease environment',
      mutate: (value) =>
        replaceJob(value, 'infra-diff', (block) =>
          block.replace('    environment: assessment-prerelease\n', ''),
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
        replaceJob(value, 'deploy-prerelease', (block) =>
          block.replace(' --approval .stage7/approval/approval.json', ''),
        ),
    },
    {
      expected: 'protected prerelease diff approval binding is missing',
      mutate: (value) =>
        replaceJob(value, 'approval', (block) =>
          block.replace('          STAGE7_PROTECTED_ENVIRONMENT: assessment-prerelease\n', ''),
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
            'role-session-name: e7pre-external-read-${{ github.run_id }}\n          role-to-assume: ${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
            'role-session-name: e7pre-external-read-${{ github.run_id }}\n          role-to-assume: ${{ vars.STAGE7_AWS_DEPLOY_ROLE_ARN }}',
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
          block.replace("    if: ${{ always() && needs.approval.result == 'success' }}\n", ''),
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
