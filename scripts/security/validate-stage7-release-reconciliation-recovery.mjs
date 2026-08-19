#!/usr/bin/env node

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const STAGE7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW =
  'stage7-release-reconciliation-recovery.yml';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const workflowPath = path.join(
  root,
  '.github',
  'workflows',
  STAGE7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW,
);
const ACTIONS = new Set([
  'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',
  'actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444',
  'actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0',
  'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
  'aws-actions/configure-aws-credentials@61815dcd50bd041e203e49132bacad1fd04d2708',
]);

const fail = (message) => {
  throw new Error(`stage7 release reconciliation recovery workflow policy: ${message}`);
};
const requireFragments = (source, fragments) => {
  for (const fragment of fragments) {
    if (!source.includes(fragment)) fail(`missing required contract: ${fragment}`);
  }
};
const requireOrder = (source, fragments) => {
  let prior = -1;
  for (const fragment of fragments) {
    const index = source.indexOf(fragment);
    if (index <= prior) fail(`causal order invalid at: ${fragment}`);
    prior = index;
  }
};

export const validateStage7ReleaseReconciliationRecoveryWorkflow = (source) => {
  if (typeof source !== 'string' || source.length < 1000) fail('workflow source missing');
  requireFragments(source, [
    'name: Stage 7 release reconciliation recovery',
    '  workflow_dispatch:',
    'permissions: {}',
    'group: stage7-assessment-release',
    'cancel-in-progress: false',
    "NODE_VERSION: '24.19.0'",
    "PNPM_VERSION: '11.19.0'",
    'STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN',
    'STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN',
    'STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN',
    'STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN',
    'environment: assessment-release-reconciliation-recovery',
    'STAGE7_CONFIG: .stage7/recovery-private/stage7-config.json',
    'id-token: write',
    'gh api --paginate --slurp "/repos/${GITHUB_REPOSITORY}/actions/runs/${ORIGINAL_RUN_ID}/jobs?filter=all&per_page=100"',
    '--original-run .stage7/recovery-private/original-run.json',
    '--original-jobs .stage7/recovery-private/original-jobs.json',
    '--aws-auth .stage7/aws-auth/aws-auth.json',
    '--candidate-manifest .stage7/candidate-manifest/candidate-manifest.json',
    '--recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json',
    '--candidate-record .stage7/recovery-probe/versioned-rollback-candidate.json',
    '--previous-manifest .stage7/previous/previous-release-manifest.json',
    "jq -cer '.recoveryRoleAuthority.sessionPolicy'",
    'inline-session-policy: ${{ steps.recovery-session-policy.outputs.policy }}',
    'role-session-name: e7-reconciliation-recovery-${{ github.run_id }}-${{ github.run_attempt }}',
    'role-session-name: e7-reconciliation-recovery-read-${{ github.run_id }}-${{ github.run_attempt }}',
    'role-session-name: e7-reconciliation-recovery-cleanup-${{ github.run_id }}-${{ github.run_attempt }}',
    'capture-role-authority',
    'live-recovery-role-effective-permissions.json',
    'verify-live-role-authority',
    'node scripts/stage7/release-reconciliation-recovery-cli.mjs inspect',
    'node scripts/stage7/release-reconciliation-recovery-cli.mjs resume-terminal',
    'node scripts/stage7/release-reconciliation-recovery-cli.mjs converge-forward',
    '--scope full',
    '--reconciliation-intent .stage7/recovery-private/release-reconciliation-intent.json',
    '--reconciliation-recovery-actor .stage7/recovery-private/recovery-actor.json',
    'node scripts/stage7/release-reconciliation-recovery-cli.mjs finalize-forward',
    'output/evidence/runtime/stage-7/drift.json',
    'cmp --silent "${source_drift}" "${target_drift}"',
    'stage7-release-reconciliation-recovery-role-effective-permissions.json',
    'node scripts/stage7/release-reconciliation-recovery-cli.mjs create-preservation-index',
    'gh api "/repos/${GITHUB_REPOSITORY}/actions/artifacts/${artifact_id}/zip"',
    'actual_digest="sha256:$(sha256sum .stage7/recovery-private/preservation-artifact.zip',
    'test "${actual_digest}" = "${expected_digest}"',
    'extract-preservation-archive',
    '--archive .stage7/recovery-private/preservation-artifact.zip',
    'capture-journal-role-authority',
    '--frozen-cleanup-role-effective-permissions',
    '--live-cleanup-role-effective-permissions',
    'Action":"ssm:DeleteParameter"',
    '/release-reconciliation/${{ inputs.original_run_id }}/*',
    'release-reconciliation-recovery-closure-${{ github.run_id }}-${{ github.run_attempt }}',
  ]);
  if (
    source.includes('pull_request:') ||
    source.includes('pull_request_target:') ||
    source.includes('schedule:') ||
    source.includes('workflow_run:') ||
    source.includes('merge-multiple: true') ||
    source.includes('STAGE7_AWS_ROLLBACK_ROLE_ARN') ||
    source.includes('role-to-assume: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}') ||
    source.includes('secrets: inherit') ||
    /\bunzip\b|\bzipinfo\b/iu.test(source)
  ) {
    fail('trigger, artifact merge, rollback role or unsafe ZIP bypass detected');
  }
  const actionReferences = [...source.matchAll(/^\s*uses:\s*([^\s#]+).*$/gmu)].map(
    (match) => match[1],
  );
  if (
    actionReferences.length < 10 ||
    actionReferences.some((reference) => !ACTIONS.has(reference))
  ) {
    fail('every action must be one of the exact immutable references');
  }
  const roles = [...source.matchAll(/^\s*role-to-assume:\s*(.+)$/gmu)].map((match) =>
    match[1].trim(),
  );
  const expectedRoles = [
    '${{ env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN }}',
    '${{ vars.STAGE7_AWS_READ_ROLE_ARN }}',
    '${{ env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN }}',
    '${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
  ];
  if (roles.join('\0') !== expectedRoles.join('\0')) {
    fail('role assumption order or least-privilege role set invalid');
  }
  if (
    (source.match(/include-hidden-files: true/gu) ?? []).length !== 3 ||
    (source.match(/retention-days: 30/gu) ?? []).length !== 3 ||
    (source.match(/release:scan -- --pre-upload/gu) ?? []).length !== 3
  ) {
    fail('all three artifacts require hidden files, scan and explicit retention');
  }
  if ((source.match(/Action":"ssm:DeleteParameter"/gu) ?? []).length !== 1) {
    fail('DeleteParameter must exist only in the cleanup session');
  }
  requireOrder(source, [
    'Observe the exact completed attempt-1 source run before AWS',
    'Rebuild the exact original 23-binding intent without replacing GitHub identity',
    'Create the exact protected recovery request',
    'Scan the exact request-context allowlist before upload',
    'Preserve attempt-suffixed request context',
    'Capture the exact protected environment approval response',
    'Derive the exact approved recovery session policy',
    'Assume the dedicated recovery role with the approved exact session policy',
    'Capture and compare the dedicated recovery role before any SSM access',
    'Create the exact current recovery actor after live IAM equality',
    'Probe terminal before any recovery mutation',
    'Resume durable terminal without rollback or Put',
    'Converge forward to candidate N only',
    'Capture fresh drift and actor-bound smoke under read authority',
    'Re-assume recovery role to seal fresh proofs and terminal',
    'Re-capture and compare recovery role immediately before terminal Put',
    'Finalize forward recovery with fresh actor-bound proof',
    'Preserve exact raw SSM authority before deletion',
    'Scan the exact raw preservation allowlist before upload',
    'Upload attempt-suffixed raw preservation authority',
    'Requery and reopen the exact preservation ZIP by artifact ID',
    'Assume the separately audited journal role for deletion only',
    'Re-capture and compare cleanup role immediately before DeleteParameter',
    'Delete only the fully preserved journal and prove residual zero',
    'Scan the residual-zero closure before upload',
    'Upload attempt-suffixed residual-zero closure',
  ]);
  return { status: 'PASS', actions: actionReferences.length, uploads: 3, scans: 3 };
};

export const selfTestStage7ReleaseReconciliationRecoveryWorkflow = () => {
  const source = readFileSync(workflowPath, 'utf8');
  validateStage7ReleaseReconciliationRecoveryWorkflow(source);
  const mutations = [
    ['group: stage7-assessment-release', 'group: per-candidate-race'],
    ['cancel-in-progress: false', 'cancel-in-progress: true'],
    ['--paginate --slurp', '--paginate'],
    ['--aws-auth .stage7/aws-auth/aws-auth.json', '--aws-auth .stage7/aws-auth/foreign.json'],
    [
      'STAGE7_CONFIG: .stage7/recovery-private/stage7-config.json',
      'STAGE7_CONFIG: .stage7/recovery-private/foreign-config.json',
    ],
    [
      '--reconciliation-intent .stage7/recovery-private/release-reconciliation-intent.json',
      '--reconciliation-intent .stage7/recovery-private/foreign-intent.json',
    ],
    ['--scope full', '--scope production'],
    [
      '--reconciliation-recovery-actor .stage7/recovery-private/recovery-actor.json',
      '--reconciliation-recovery-actor .stage7/recovery-private/foreign-actor.json',
    ],
    [
      'role-session-name: e7-reconciliation-recovery-read-${{ github.run_id }}-${{ github.run_attempt }}',
      'role-session-name: e7-reconciliation-recovery-${{ github.run_id }}-${{ github.run_attempt }}',
    ],
    ['include-hidden-files: true', 'include-hidden-files: false'],
    ['test "${actual_digest}" = "${expected_digest}"', 'true'],
    ['capture-role-authority', 'skip-role-authority'],
    ['Action":"ssm:DeleteParameter"', 'Action":"ssm:PutParameter"'],
    [
      'role-to-assume: ${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
      'role-to-assume: ${{ env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN }}',
    ],
  ];
  for (const [from, to] of mutations) {
    assert.throws(() =>
      validateStage7ReleaseReconciliationRecoveryWorkflow(source.replaceAll(from, to)),
    );
  }
  assert.throws(() =>
    validateStage7ReleaseReconciliationRecoveryWorkflow(`${source}\npull_request:\n`),
  );
  return { status: 'PASS', canaries: mutations.length + 1 };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = process.argv.includes('--self-test')
    ? selfTestStage7ReleaseReconciliationRecoveryWorkflow()
    : validateStage7ReleaseReconciliationRecoveryWorkflow(readFileSync(workflowPath, 'utf8'));
  process.stdout.write(`${JSON.stringify(result)}\n`);
}
