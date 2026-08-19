import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const ROLLBACK_RESILIENCE_WORKFLOW = 'stage7-rollback-resilience.yml';
const workflowPath = path.join(root, '.github', 'workflows', ROLLBACK_RESILIENCE_WORKFLOW);
const releasePath = path.join(root, '.github', 'workflows', 'release.yml');

const fail = (message) => {
  throw new Error(`rollback-resilience-workflow policy: ${message}`);
};

const occurrences = (source, fragment) => source.split(fragment).length - 1;
const escaped = (value) => value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
const exactNameOccurrences = (source, name) =>
  [...source.matchAll(new RegExp(`^\\s*name: ${escaped(name)}\\s*$`, 'gmu'))].length;

const requireFragments = (source, fragments) => {
  for (const fragment of fragments) {
    if (!source.includes(fragment)) fail(`missing required contract: ${fragment}`);
  }
};

export const validateRollbackResilienceWorkflow = ({ workflow, release }) => {
  requireFragments(workflow, [
    'workflow_call:',
    'environment: assessment-release-recovery',
    'id-token: write',
    'name: stage7-rollback-resilience',
    'role-to-assume: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
    'node scripts/stage7/rollback-resilience-cli.mjs prepare',
    'node scripts/stage7/rollback-resilience-cli.mjs run-protected',
    'node scripts/stage7/rollback-resilience-cli.mjs validate-completion',
    'node scripts/stage7/release-reconciliation-cli.mjs create-intent',
    'workspace_target="${private_root}/stage7-config.json"',
    'install -m 600 "${target}" "${workspace_target}"',
    'printf \'STAGE7_RECONCILIATION_CONFIG=%s\\n\' "${workspace_target}" >> "${GITHUB_ENV}"',
    'STAGE7_JOB_WORKFLOW_REF: ${{ job.workflow_ref }}',
    'STAGE7_AUTHORIZED_FREEZE_SHA256',
    'STAGE7_AUTHORIZED_APPROVAL_SHA256',
    'STAGE7_AUTHORIZED_AWS_AUTH_SHA256',
    'STAGE7_AUTHORIZED_PLAN_SHA256',
    'STAGE7_AUTHORIZED_DEPLOYMENT_SHA256',
    'STAGE7_AUTHORIZED_OBSERVABILITY_SHA256',
    'STAGE7_AUTHORIZED_ACTIVATION_SHA256',
    'STAGE7_AUTHORIZED_EXTERNAL_AUTHORIZATION_SHA256',
    'STAGE7_AUTHORIZED_AUTHORIZATION_BUDGET_SHA256',
    'STAGE7_AUTHORIZED_REHEARSAL_SHA256',
    'STAGE7_AUTHORIZED_JOURNAL_CLEANUP_ROLE_SHA256',
    'STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN: ${{ vars.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
    '--journal-cleanup-role "${STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN}"',
    '--reconciliation-recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json',
    'stage7-rollback-resilience-source-binding.json',
    'stage7-rollback-resilience-protected-run.json',
    'stage7-rollback-resilience-complete.json',
    'rehearsal_pass=true',
  ]);
  for (const artifactName of [
    'stage7-candidate',
    'stage7-candidate-manifest',
    'stage7-release-metadata',
    'stage7-release-plan',
    'stage7-previous-release',
    'stage7-infra-diff',
    'stage7-approval',
    'stage7-aws-auth',
    'stage7-web',
    'stage7-observability',
    'stage7-activation',
    'stage7-rollback',
    'stage7-recovery-probe',
    'stage7-external-authorization',
    'stage7-smoke',
    'stage7-edge-security',
    'stage7-quality',
    'stage7-sandbox',
  ]) {
    if (exactNameOccurrences(workflow, artifactName) !== 1) {
      fail(`artifact ${artifactName} must be downloaded exactly once`);
    }
  }
  if (
    workflow.includes('workflow_dispatch:') ||
    workflow.includes('pull_request:') ||
    workflow.includes('merge-multiple:') ||
    workflow.includes('pattern:') ||
    workflow.includes('include-hidden-files: true') ||
    workflow.includes('output/evidence/runtime/.private-stage7')
  ) {
    fail('workflow trigger, merged download or private upload is not fail-closed');
  }
  const actionUses = [...workflow.matchAll(/^\s*uses:\s*([^\s#]+).*$/gmu)].map((match) => match[1]);
  if (
    actionUses.length !== 22 ||
    actionUses.some((reference) => reference.startsWith('./') || !/@[0-9a-f]{40}$/u.test(reference))
  ) {
    fail('every external action must be pinned to one exact commit');
  }
  const protectedStart = workflow.indexOf(
    'node scripts/stage7/rollback-resilience-cli.mjs run-protected',
  );
  const protectedEnd = workflow.indexOf('\n      - name:', protectedStart);
  const protectedCommand = workflow.slice(protectedStart, protectedEnd);
  const exactIntentFlags = [
    'config',
    'release-metadata',
    'candidate-manifest',
    'release-plan',
    'approved-diff',
    'raw-diff',
    'github-environment-approval',
    'approval',
    'aws-auth',
    'journal-role-effective-permissions',
    'activation',
    'web-deployment',
    'candidate-record',
    'external-authorization',
    'previous-release-manifest',
    'previous-source-provenance',
    'previous-target-compatibility',
    'previous-final-disable-provenance',
    'previous-api-contract-evidence',
    'previous-pending-evidence',
    'previous-smoke-evidence',
    'previous-release-projection-index',
  ];
  const exactPreparationFlags = [
    'rollback',
    'reconciliation-recovery-role-effective-permissions',
    'observability',
    'smoke-input',
    'smoke',
    'edge',
    'quality',
    'sandbox',
    'rollback-smoke-input',
    'pending-producer',
    'rollback-smoke',
    'repromotion-smoke',
    'journal-cleanup-role',
    'assembly',
    'max-polls',
  ];
  if (
    protectedStart < 0 ||
    protectedEnd < 0 ||
    occurrences(workflow, '--config "${STAGE7_RECONCILIATION_CONFIG}"') !== 3 ||
    workflow.includes('--config "${STAGE7_CONFIG}"') ||
    occurrences(protectedCommand, '--intent ') !== 1 ||
    [...exactIntentFlags, ...exactPreparationFlags].some(
      (flag) => occurrences(protectedCommand, `--${flag} `) !== 1,
    ) ||
    occurrences(workflow, 'STAGE7_JOB_WORKFLOW_REF: ${{ job.workflow_ref }}') !== 1 ||
    workflow.includes('STAGE7_JOB_WORKFLOW_REF: ${{ github.workflow_ref }}')
  ) {
    fail('same-process rollback guard source contract is incomplete or ambiguous');
  }
  const uploadStart = workflow.indexOf('name: Preserve only the hash-bound resilience evidence');
  if (uploadStart < 0) fail('public upload step missing');
  const upload = workflow.slice(uploadStart);
  const publicPaths = [
    'output/evidence/runtime/stage-7-resilience/stage7-rollback-resilience-source-binding.json',
    'output/evidence/runtime/stage-7-resilience/stage7-rollback-resilience-protected-run.json',
    'output/evidence/runtime/stage-7-resilience/stage7-rollback-resilience-complete.json',
  ];
  if (
    publicPaths.some((filename) => occurrences(upload, filename) !== 1) ||
    ['*', '?', '!', '[', ']'].some((character) =>
      upload
        .split('\n')
        .filter((line) => line.trimStart().startsWith('output/'))
        .join('\n')
        .includes(character),
    )
  ) {
    fail('public upload must contain exactly three literal files');
  }
  requireFragments(release, [
    'uses: ./.github/workflows/stage7-rollback-resilience.yml',
    "if: ${{ github.run_attempt == 1 && needs.rollback-check.outputs.base_rehearsal_ready == 'true' }}",
    "if: ${{ always() && github.run_attempt == 1 && needs.release-reconciliation-intent.result == 'success' }}",
    'node scripts/stage7/release-reconciliation-cli.mjs pre-fence',
    'name: stage7-release-reconciliation',
    "if: ${{ github.run_attempt == 1 && needs.release-successor-fence.result == 'success' }}",
    'needs: release-successor-fence',
  ]);
  const activationProducerStart = release.indexOf('  postdeploy-smoke:');
  const activationProducerEnd = release.indexOf('\n  edge-security:', activationProducerStart);
  const activationProducer = release.slice(activationProducerStart, activationProducerEnd);
  const activationUploadContract =
    /- name: Hand off the activation checkpoint for fail-closed recovery\s+uses: actions\/upload-artifact@[0-9a-f]{40}[^\n]*\s+with:\s+name: stage7-activation\s+if-no-files-found: error\s+path: output\/evidence\/runtime\/stage-7\/activation\.json/u;
  if (
    activationProducerStart < 0 ||
    activationProducerEnd < 0 ||
    exactNameOccurrences(activationProducer, 'stage7-activation') !== 1 ||
    !activationUploadContract.test(activationProducer) ||
    workflow.includes('internal-stage7-candidate-activation') ||
    release.includes("needs.rollback-check.outputs.rehearsal_pass == 'true'") ||
    /uses: \.\/\.github\/workflows\/stage7-rollback-resilience\.yml[\s\S]{0,600}secrets:\s*inherit/u.test(
      release,
    )
  ) {
    fail('publication still bypasses the protected resilience completion');
  }
  const resilienceConsumerStart = release.indexOf('  release-reconciliation:');
  const resilienceConsumerEnd = release.indexOf(
    '\n  release-successor-fence:',
    resilienceConsumerStart,
  );
  const resilienceConsumer = release.slice(resilienceConsumerStart, resilienceConsumerEnd);
  const fenceStart = release.indexOf('  release-successor-fence:', resilienceConsumerEnd);
  const fenceEnd = release.indexOf('\n  publish-release:', fenceStart);
  const fence = release.slice(fenceStart, fenceEnd);
  const publicationStart = release.indexOf('  publish-release:');
  const publicationEnd = release.indexOf('\n  summary:', publicationStart);
  const publication = release.slice(publicationStart, publicationEnd);
  if (
    resilienceConsumerStart < 0 ||
    resilienceConsumerEnd < 0 ||
    fenceStart < 0 ||
    fenceEnd < 0 ||
    publicationStart < 0 ||
    publicationEnd < 0 ||
    !/(?:^|\n)\s+- release-reconciliation-intent\s*(?:\n|$)/u.test(resilienceConsumer) ||
    !/(?:^|\n)\s+- rollback-check\s*(?:\n|$)/u.test(resilienceConsumer) ||
    !/(?:^|\n)\s+- rollback-resilience\s*(?:\n|$)/u.test(resilienceConsumer) ||
    !resilienceConsumer.includes(
      'pre-fence --rollback-check .stage7/reconciliation-public/rollback-check-reconciliation.json --rollback-resilience .stage7/reconciliation-public/rollback-resilience-reconciliation.json',
    ) ||
    !resilienceConsumer.includes(
      'pnpm release:scan -- --pre-upload .stage7/reconciliation-public/rollback-check-reconciliation.json .stage7/reconciliation-public/rollback-resilience-reconciliation.json .stage7/reconciliation-public/stage7-release-pre-fence-gate.json',
    ) ||
    exactNameOccurrences(resilienceConsumer, 'stage7-release-reconciliation') !== 1 ||
    !fence.includes(
      "if: ${{ github.run_attempt == 1 && needs.release-reconciliation.result == 'success' }}",
    ) ||
    !fence.includes('needs: release-reconciliation') ||
    !publication.includes(
      "if: ${{ github.run_attempt == 1 && needs.release-successor-fence.result == 'success' }}",
    ) ||
    !publication.includes('needs: release-successor-fence') ||
    publication.includes('needs: release-reconciliation') ||
    publication.includes('needs: rollback-resilience') ||
    publication.includes('needs.rollback-resilience.outputs.rehearsal_pass') ||
    release.indexOf('node scripts/stage7/release-reconciliation-cli.mjs pre-fence') >
      publicationStart
  ) {
    fail('publication still bypasses the protected reconciliation pre-fence chain');
  }
  return { jobs: 1, publicFiles: publicPaths.length, status: 'PASS' };
};

export const selfTestRollbackResilienceWorkflow = () => {
  const workflow = readFileSync(workflowPath, 'utf8');
  const release = readFileSync(releasePath, 'utf8');
  const valid = validateRollbackResilienceWorkflow({ workflow, release });
  for (const [from, to] of [
    [
      'STAGE7_JOB_WORKFLOW_REF: ${{ job.workflow_ref }}',
      'STAGE7_JOB_WORKFLOW_REF: ${{ github.workflow_ref }}',
    ],
    ['--raw-diff .stage7/infra-diff/infra-diff.txt', '--diff .stage7/infra-diff/infra-diff.txt'],
    [
      '--candidate-record .stage7/recovery-probe/versioned-rollback-candidate.json',
      '--candidate .stage7/rollback/versioned-rollback-candidate.json',
    ],
    [
      '--reconciliation-recovery-role-effective-permissions .stage7/aws-auth/stage7-release-reconciliation-recovery-role-effective-permissions.json',
      '--reconciliation-recovery-role-effective-permissions .stage7/aws-auth/aws-auth.json',
    ],
    ['name: stage7-recovery-probe', 'name: stage7-rollback'],
    ['install -m 600 "${target}" "${workspace_target}"', 'cp "${target}" "${workspace_target}"'],
    ['--config "${STAGE7_RECONCILIATION_CONFIG}"', '--config "${STAGE7_CONFIG}"'],
  ]) {
    assert.throws(() =>
      validateRollbackResilienceWorkflow({ workflow: workflow.replaceAll(from, to), release }),
    );
  }
  for (const [from, to] of [
    ['needs: release-successor-fence', 'needs: release-reconciliation'],
    [
      "needs.release-successor-fence.result == 'success'",
      "needs.release-reconciliation.result == 'success'",
    ],
  ]) {
    assert.throws(() =>
      validateRollbackResilienceWorkflow({ workflow, release: release.replace(from, to) }),
    );
  }
  return { ...valid, canaries: 9, externalRequests: 0 };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = selfTestRollbackResilienceWorkflow();
  assert.equal(result.status, 'PASS');
  process.stdout.write(
    `rollback-resilience-workflow policy: PASS (${result.jobs} protected job; ${result.publicFiles} exact public files; ${result.canaries} tamper canaries)\n`,
  );
}
