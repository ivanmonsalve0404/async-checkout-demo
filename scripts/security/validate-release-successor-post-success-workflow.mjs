import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  RELEASE_SUCCESSOR_INTERNAL_ARTIFACTS,
  RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS,
} from '../stage7/release-successor-handoff.mjs';
import {
  RECOVERY_CRASH_WINDOWS,
  RECOVERY_SOURCE_ARTIFACTS,
} from '../stage7/release-successor-publication-recovery-contract.mjs';
import {
  RELEASE_SUCCESSOR_RECOVERY_COMPOSITE_STATUS,
  RELEASE_SUCCESSOR_RECOVERY_JOB_IDS,
  RELEASE_SUCCESSOR_RECOVERY_SHARED_CONTRACT,
} from '../stage7/release-successor-recovery-integration.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW = 'stage7-release-successor-post-success.yml';
const workflowPath = path.join(
  root,
  '.github',
  'workflows',
  RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW,
);

const fail = (message) => {
  throw new Error(`release-successor-post-success workflow policy: ${message}`);
};
const requireFragments = (source, fragments) => {
  for (const fragment of fragments) {
    if (!source.includes(fragment)) fail(`missing required contract: ${fragment}`);
  }
};
const indexInOrder = (source, fragments) => {
  let previous = -1;
  for (const fragment of fragments) {
    const index = source.indexOf(fragment);
    if (index <= previous) fail(`causal order invalid at: ${fragment}`);
    previous = index;
  }
};

export const validateReleaseSuccessorPostSuccessWorkflow = (source) => {
  if (
    RELEASE_SUCCESSOR_INTERNAL_ARTIFACTS.join('\0') !==
    [
      'release-external-authorization-request',
      'release-observability-pending',
      'release-sandbox-execution-request',
    ].join('\0')
  ) {
    fail('release run must expose exactly three approved non-source artifacts');
  }
  if (
    RELEASE_SUCCESSOR_RECOVERY_COMPOSITE_STATUS !== 'POST_SUCCESS_COMPOSITE_REQUIRED' ||
    RELEASE_SUCCESSOR_RECOVERY_SHARED_CONTRACT !== 'WIRED_CONTRACT' ||
    RELEASE_SUCCESSOR_RECOVERY_JOB_IDS.join('\0') !==
      ['forward-publication', 'preflight-read-only', 'validate-contract'].join('\0') ||
    RECOVERY_CRASH_WINDOWS.join('\0') !==
      [
        'FENCE_DURABLE_SOURCE_ARTIFACT_MISSING',
        'SOURCE_FENCE_PRESENT_PUBLICATION_INCOMPLETE',
        'SOURCE_PUBLICATION_PRESENT_SUMMARY_INCOMPLETE',
      ].join('\0') ||
    RECOVERY_SOURCE_ARTIFACTS.length !== 27 ||
    RECOVERY_SOURCE_ARTIFACTS.some((name) =>
      [
        'stage7-publication',
        'stage7-release-successor-fence',
        'stage7-release-authorities',
        'stage7-release-reports',
      ].includes(name),
    )
  ) {
    fail('publication recovery shared contract is not frozen');
  }
  requireFragments(source, [
    'name: Stage 7 Release Successor Post-Success',
    'workflow_run:',
    '      - Stage 7 Release\n',
    '- Stage 7 Release Successor Publication Recovery',
    '- master',
    '- completed',
    'group: stage7-assessment-release',
    'cancel-in-progress: false',
    "github.event.workflow_run.status == 'completed'",
    "github.event.workflow_run.conclusion == 'success'",
    "github.event.workflow_run.head_branch == 'master'",
    'github.event.workflow_run.run_attempt == 1',
    'ref: ${{ github.event.workflow_run.head_sha }}',
    'environment: assessment-release-successor-post-success',
    'id-token: write',
    'STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN',
    'STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN',
    'role-to-assume: ${{ vars.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
    "AWS_EC2_METADATA_DISABLED: 'true'",
    "Action:'ssm:PutParameter'",
    "Condition:{StringEquals:{'ssm:Overwrite':'false'}}",
    "Action:'ssm:GetParameter'",
    "Action:'ssm:GetParametersByPath'",
    "Action:'ssm:DeleteParameter'",
    'iam:GetRole',
    'Resource:arn(finalization)',
    'Resource:arn(fence)',
    'arn(reconciliation),arn(`${reconciliation}/*`)',
    'arn(`${reconciliation}/owner`)',
    'arn(`${reconciliation}/intent/*`)',
    'arn(`${reconciliation}/runtime-proofs/*`)',
    'Resource:journalRole',
    '/checkout/stage7/release-finalization/${candidate}/${run}',
    '/checkout/stage7/release-fence/${candidate}/${run}',
    '/checkout/stage7/rollback/${candidate}/RB-E7-06',
    '/checkout/stage7/rollback/${candidate}/RB-E7-08',
    'node scripts/stage7/release-successor-cli.mjs observe-release',
    'node scripts/stage7/release-successor-publication-recovery-cli.mjs source-id',
    '--plan-archive .stage7/post-success/recovery-plan.zip',
    '--recovery-plan-archive .stage7/post-success/recovery-plan.zip',
    'node scripts/stage7/release-successor-publication-recovery-cli.mjs intake',
    'node scripts/stage7/release-successor-cli.mjs manifest-recovered-release',
    'node scripts/stage7/release-successor-cli.mjs authorize-recovered-release',
    '--source-jobs .stage7/post-success/api/source-jobs.json',
    'node scripts/stage7/release-successor-cli.mjs extract-recovered-release',
    'node scripts/stage7/control.mjs verify',
    '--publication-recovery-intake .stage7/post-success/recovery-intake.json',
    '--publication-recovery-closeout-authority .stage7/post-success/recovery-closeout-authority.json',
    '--publication-recovery-plan .stage7/post-success/recovery-plan.zip',
    '--publication-recovery-result .stage7/post-success/recovery-result.zip',
    'node scripts/stage7/release-successor-cli.mjs observe-recovered-release',
    'gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/actions/runs/${EVENT_RUN_ID}/jobs?filter=all&per_page=100"',
    'gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/actions/runs/${EVENT_RUN_ID}/artifacts?per_page=100"',
    'gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/actions/runs/${source_run_id}/jobs?filter=all&per_page=100"',
    'gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/actions/runs/${source_run_id}/artifacts?per_page=100"',
    'gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/actions/runs/${SOURCE_RUN_ID}/artifacts?per_page=100"',
    'test "$(wc -l < .stage7/post-success/source-manifest.tsv)" = \'27\'',
    'const artifacts = value.flatMap((page) => page?.artifacts ?? []);',
    'if (!Array.isArray(value) || value.length !== 1) process.exit(1);',
    'if (value[0]?.total_count !== 2 || artifacts.length !== 2) process.exit(1);',
    "const plan = select('plan');",
    "const result = select('result');",
    'if (plan.sourceRunId !== result.sourceRunId) process.exit(1);',
    'actions/artifacts/${plan_artifact_id}/zip',
    'actions/artifacts/${result_artifact_id}/zip',
    'pages.length !== 1 || !Array.isArray(pages[0]?.[field]) || pages[0].total_count !== pages[0][field].length',
    'if(v.length!==1||v[0].total_count!==a.length||m.length!==1',
    'node scripts/stage7/release-successor-cli.mjs select-retry-source',
    'node scripts/stage7/release-successor-cli.mjs reuse-retry-source',
    'node scripts/stage7/release-successor-cli.mjs extract-release',
    'node scripts/stage7/rollback-resilience-cli.mjs prepare',
    'node scripts/stage7/release-successor-cli.mjs commit',
    'node scripts/stage7/release-successor-cli.mjs capture-journal-role-authority',
    'node scripts/stage7/release-successor-cli.mjs finalize',
    'node scripts/stage7/release-successor-cli.mjs build-source',
    'node scripts/stage7/release-successor-cli.mjs capture-journal-snapshot',
    'node scripts/stage7/release-successor-cli.mjs preserve',
    'node scripts/stage7/release-successor-cli.mjs cleanup-journal',
    'release-manifest.json',
    'provenance-ledger.json',
    'stage7-rollback-resilience-source-binding.json',
    'stage7-rollback-resilience-protected-run.json',
    'stage7-rollback-resilience-complete.json',
    'previous-release-projection-index.json',
    '--release-metadata .stage7/post-success/artifacts/stage7-release-metadata/release-metadata.json',
    '--stage6-closeout .stage7/post-success/artifacts/stage7-release-metadata/stage6-closeout.json',
    '--candidate-record .stage7/post-success/artifacts/stage7-recovery-probe/versioned-rollback-candidate.json',
    '--emergency-recovery .stage7/post-success/artifacts/stage7-recovery-probe/emergency-recovery.json',
    '--emergency-recovery-no-action-outcome .stage7/post-success/artifacts/stage7-recovery-probe/emergency-recovery-no-action-outcome.json',
    '--release-handoff .stage7/post-success/artifacts/stage7-release-authorities/handoff-payload.json',
    '--fence .stage7/post-success/artifacts/stage7-release-successor-fence/release-successor-completion-fence.json',
    '--pre-fence-gate .stage7/post-success/artifacts/stage7-release-reconciliation/stage7-release-pre-fence-gate.json',
    '--pending-egress-closeout .stage7/post-success/artifacts/stage7-rollback/rollback-pending-egress-closeout.json',
    '--journal-role-effective-permissions .stage7/post-success/artifacts/stage7-aws-auth/stage7-release-journal-role-effective-permissions.json',
    '--live-effective-permissions .stage7/post-success/live-journal-role-effective-permissions.json',
    '--post-run-id "${GITHUB_RUN_ID}"',
    '--post-attempt "${GITHUB_RUN_ATTEMPT}"',
    'aws sts get-caller-identity',
    'aws --version',
    '--output .stage7/post-success/live-journal-role-effective-permissions.json',
    '--get-role-output .stage7/post-success/role-audit.json',
    '--output .stage7/post-success/cleanup-live-journal-role-effective-permissions.json',
    '--get-role-output .stage7/post-success/cleanup-role-audit.json',
    '--caller-identity .stage7/post-success/caller-identity.json',
    '--role-audit .stage7/post-success/role-audit.json',
    '--permissions-boundary "${PERMISSIONS_BOUNDARY_ARN}"',
    'node scripts/stage7/control.mjs scan --scope full --pre-upload',
    "steps.cleanup-receipt-scan.outcome == 'success'",
    'case "${EVENT_WORKFLOW_NAME}" in',
    "'Stage 7 Release')",
    "'Stage 7 Release Successor Publication Recovery')",
    "printf 'mode=NORMAL\\n'",
    "printf 'mode=RECOVERY\\n'",
    "if: ${{ steps.trigger-source.outputs.mode == 'NORMAL' }}",
    "if: ${{ steps.trigger-source.outputs.mode == 'RECOVERY' }}",
    'SOURCE_RUN_ID: ${{ steps.trigger-source.outputs.source_run_id }}',
    'name: stage7-release-successor-source-r${{ steps.trigger-source.outputs.source_run_id }}-a${{ github.run_attempt }}',
    'name: stage7-release-successor-preservation-r${{ steps.trigger-source.outputs.source_run_id }}-a${{ github.run_attempt }}',
    'name: stage7-release-successor-cleanup-receipt-r${{ steps.trigger-source.outputs.source_run_id }}-a${{ github.run_attempt }}',
    'retention-days: 90',
  ]);
  if (
    !source.includes('RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS') ||
    !source.includes('RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.join(')
  ) {
    fail('raw artifact downloads must derive from the executable catalog');
  }
  if (
    source.split(
      '--pending-egress-closeout .stage7/post-success/artifacts/stage7-rollback/rollback-pending-egress-closeout.json',
    ).length -
      1 !==
    2
  ) {
    fail('pending egress closeout must bind rollback recomputation and successor source exactly');
  }
  indexInOrder(source, [
    'Resolve and bind the exact normal or recovered release source',
    'Select an earlier durable source before any AWS access',
    'Redownload and validate the earlier durable source and preservation receipt',
    'Requery the exact release run, workflow, artifacts and raw ZIP bytes',
    'Extract each hash-verified release artifact without merged paths',
    'Materialize the composite recovery authorities and exact observation',
    'Validate every authority and commit the pre-marker evidence set',
    'Verify exact caller, pinned AWS CLI and immutable role profile before SSM',
    'Seal same-candidate recovery with an immutable no-overwrite marker',
    'Build only the target-independent release N source bundle',
    'Scan the target-independent source before publication',
    'Upload the unique immutable successor source before any deletion',
    'Requery and redownload the uploaded source by exact artifact ID',
    'Scan the durable-handoff receipt before publication',
    'Preserve the durable-handoff receipt before journal cleanup',
    'Reverify caller and role immediately before any journal deletion',
    'Delete only paginated RB-E7-06, RB-E7-08 and reconciliation journal parameters',
    'Scan the cleanup receipt even after a partial deletion failure',
    'Upload the separate post-cleanup receipt without overwrite',
  ]);
  indexInOrder(source, [
    'node scripts/stage7/release-successor-cli.mjs authorize-recovered-release',
    'Materialize the composite recovery authorities and exact observation',
    'Assume only the dedicated release-journal cleanup role',
  ]);
  indexInOrder(source, [
    'node scripts/stage7/release-successor-cli.mjs authorize-recovered-release',
    'node scripts/stage7/control.mjs verify',
    'node scripts/stage7/release-successor-cli.mjs observe-recovered-release',
    'node scripts/stage7/release-successor-cli.mjs commit',
    'node scripts/stage7/release-successor-cli.mjs finalize',
    'node scripts/stage7/release-successor-cli.mjs build-source',
    'node scripts/stage7/release-successor-cli.mjs preserve',
    'node scripts/stage7/release-successor-cli.mjs cleanup-journal',
  ]);
  const actionUses = [...source.matchAll(/^\s*uses:\s*([^\s#]+).*$/gmu)].map((match) => match[1]);
  if (
    actionUses.length !== 6 ||
    actionUses.some((reference) => reference.startsWith('./') || !/@[0-9a-f]{40}$/u.test(reference))
  ) {
    fail('every action must be one of six exact immutable commit references');
  }
  const assumedRoles = [...source.matchAll(/^\s*role-to-assume:\s*(.+)$/gmu)].map((match) =>
    match[1].trim(),
  );
  if (
    assumedRoles.length !== 1 ||
    assumedRoles[0] !== '${{ vars.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}'
  ) {
    fail('only the dedicated journal role may be assumed');
  }
  const policyStart = source.indexOf("const policy = {Version:'2012-10-17'");
  const policyEnd = source.indexOf('fs.appendFileSync(process.env.GITHUB_OUTPUT', policyStart);
  const policy = source.slice(policyStart, policyEnd);
  const expectedPolicy = [
    "const policy = {Version:'2012-10-17',Statement:[",
    "{Sid:'ImmutableFinalizationWrite',Effect:'Allow',Action:'ssm:PutParameter',Resource:arn(finalization),Condition:{StringEquals:{'ssm:Overwrite':'false'}}},",
    "{Sid:'ExactFinalizationRead',Effect:'Allow',Action:'ssm:GetParameter',Resource:arn(finalization)},",
    "{Sid:'ExactCompletionFenceRead',Effect:'Allow',Action:'ssm:GetParameter',Resource:arn(fence)},",
    "{Sid:'ExactJournalList',Effect:'Allow',Action:'ssm:GetParametersByPath',Resource:[arn(rb06),arn(`${rb06}/*`),arn(rb08),arn(`${rb08}/*`),arn(reconciliation),arn(`${reconciliation}/*`)]},",
    "{Sid:'ExactJournalDelete',Effect:'Allow',Action:'ssm:DeleteParameter',Resource:[arn(`${rb06}/*`),arn(`${rb08}/*`),arn(`${reconciliation}/owner`),arn(`${reconciliation}/intent/*`),arn(`${reconciliation}/runtime-proofs/*`),arn(`${reconciliation}/rollback-check/terminal`),arn(`${reconciliation}/rollback-resilience/terminal`)]},",
    "{Sid:'ExactJournalRoleAudit',Effect:'Allow',Action:['iam:GetRole','iam:GetRolePolicy','iam:ListAttachedRolePolicies','iam:ListRolePolicies'],Resource:journalRole},",
    "{Sid:'ExactJournalPolicyAudit',Effect:'Allow',Action:['iam:GetPolicy','iam:GetPolicyVersion'],Resource:policyArns},",
    ']};',
  ].join('');
  if (
    policyStart < 0 ||
    policyEnd < 0 ||
    policy.replaceAll(/\s+/gu, '') !== expectedPolicy.replaceAll(/\s+/gu, '') ||
    /DeleteParameter[^\n]*finalization|finalization[^\n]*DeleteParameter/u.test(policy) ||
    /Resource\s*:\s*['"]\*['"]/u.test(policy) ||
    /Action\s*:\s*['"](?:ssm:\*|iam:\*)['"]/u.test(policy)
  ) {
    fail('finalization marker must never be deletable');
  }
  if (
    source.includes('workflow_dispatch:') ||
    source.includes('pull_request:') ||
    source.includes('overwrite: true') ||
    source.includes('name: stage7-previous-release\n') ||
    source.includes('--target-config') ||
    source.includes('--target-freeze') ||
    source.includes('role-to-assume: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}') ||
    source.includes('role-to-assume: ${{ vars.STAGE7_AWS_CLEANUP_ROLE_ARN }}') ||
    source.includes('pnpm release:publish') ||
    source.includes('pnpm release:github-publication') ||
    /\bunzip\b|\bzipinfo\b/u.test(source)
  ) {
    fail('trigger, target projection, overwrite, artifact collision or role reuse detected');
  }
  if ((source.match(/aws sts get-caller-identity/gu) ?? []).length !== 2) {
    fail('STS caller identity must be revalidated before finalization and cleanup');
  }
  if (
    (source.match(/capture-journal-role-authority/gu) ?? []).length !== 2 ||
    source.includes('aws iam get-role')
  ) {
    fail('the single normalized IAM authority capturer must run before both mutation phases');
  }
  if ((source.match(/aws --version/gu) ?? []).length !== 2) {
    fail('the pinned AWS CLI must be rechecked before each AWS mutation phase');
  }
  if ((source.match(/control\.mjs scan --scope full --pre-upload/gu) ?? []).length !== 3) {
    fail('all three public post-success artifacts require a pre-upload scan');
  }
  if ((source.match(/retention-days: 90/gu) ?? []).length !== 3) {
    fail('all post-success handoff artifacts require the explicit 90-day maximum window');
  }
  if (
    (source.match(/--plan-archive \.stage7\/post-success\/recovery-plan\.zip/gu) ?? []).length !==
      5 ||
    (source.match(/--result-archive \.stage7\/post-success\/recovery-result\.zip/gu) ?? [])
      .length !== 6 ||
    (source.match(/--recovery-plan-archive \.stage7\/post-success\/recovery-plan\.zip/gu) ?? [])
      .length !== 1 ||
    (source.match(/actions\/artifacts\/\$\{plan_artifact_id\}\/zip/gu) ?? []).length !== 1 ||
    (source.match(/actions\/artifacts\/\$\{result_artifact_id\}\/zip/gu) ?? []).length !== 1
  ) {
    fail('both recovery archives must be downloaded and consumed exactly once per binding');
  }
  return {
    status: 'PASS',
    pinnedActions: 6,
    sourceArtifacts: RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.length,
    observedRunArtifacts:
      RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.length + RELEASE_SUCCESSOR_INTERNAL_ARTIFACTS.length,
    publicArtifacts: 3,
  };
};

export const selfTestReleaseSuccessorPostSuccessWorkflow = () => {
  const source = readFileSync(workflowPath, 'utf8');
  const valid = validateReleaseSuccessorPostSuccessWorkflow(source);
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        "Condition:{StringEquals:{'ssm:Overwrite':'false'}}",
        "Condition:{Bool:{'ssm:Overwrite':'false'}}",
      ),
    ),
  );
  for (const exactResource of [
    'Resource:arn(finalization)',
    'arn(`${reconciliation}/owner`)',
    'arn(`${reconciliation}/runtime-proofs/*`)',
    'arn(reconciliation),arn(`${reconciliation}/*`)',
  ]) {
    assert.throws(() =>
      validateReleaseSuccessorPostSuccessWorkflow(source.replace(exactResource, "Resource:'*'")),
    );
  }
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'node scripts/stage7/release-successor-cli.mjs extract-release',
        'unzip -qq .stage7/post-success/archives/*.zip',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'role-to-assume: ${{ vars.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
        'role-to-assume: ${{ vars.STAGE7_AWS_ROLLBACK_ROLE_ARN }}',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'node scripts/stage7/release-successor-cli.mjs capture-journal-role-authority',
        'aws iam get-role',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'Upload the unique immutable successor source before any deletion',
        'Upload the unique immutable successor source after any deletion',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'github.event.workflow_run.run_attempt == 1',
        'github.event.workflow_run.run_attempt >= 1',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'node scripts/stage7/release-successor-cli.mjs select-retry-source',
        'node scripts/stage7/release-successor-cli.mjs observe-release',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'arn(`${reconciliation}/runtime-proofs/*`)',
        'arn(`/checkout/stage7/rollback/*/release-reconciliation/*/runtime-proofs/*`)',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        '--emergency-recovery-no-action-outcome .stage7/post-success/artifacts/stage7-recovery-probe/emergency-recovery-no-action-outcome.json',
        '--emergency-recovery-no-action-outcome .stage7/post-success/artifacts/stage7-rollback/emergency-recovery-no-action-outcome.json',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        '--pending-egress-closeout .stage7/post-success/artifacts/stage7-rollback/rollback-pending-egress-closeout.json',
        '--pending-egress-closeout .stage7/post-success/artifacts/stage7-rollback/rollback-pending-producer.json',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace('      - Stage 7 Release Successor Publication Recovery\n', ''),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'gh api --paginate --slurp "repos/${GITHUB_REPOSITORY}/actions/runs/${source_run_id}/artifacts?per_page=100"',
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${source_run_id}/artifacts?per_page=100"',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'node scripts/stage7/release-successor-cli.mjs authorize-recovered-release',
        'node scripts/stage7/release-successor-cli.mjs authorize-unbound-release',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(`${source}\n      - run: pnpm release:publish\n`),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'stage7-release-successor-source-r${{ steps.trigger-source.outputs.source_run_id }}',
        'stage7-release-successor-source-r${{ github.event.workflow_run.id }}',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'if (value[0]?.total_count !== 2 || artifacts.length !== 2) process.exit(1);',
        'if (value[0]?.total_count < 2 || artifacts.length < 2) process.exit(1);',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'actions/artifacts/${plan_artifact_id}/zip',
        'actions/artifacts/${result_artifact_id}/zip',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(source.replace('      - Stage 7 Release\n', '')),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace('value.length !== 1', 'value.length < 1'),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace('pages.length !== 1', 'pages.length < 1'),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        'pages[0].total_count !== pages[0][field].length',
        'pages[0].total_count < pages[0][field].length',
      ),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(source.replace('v.length!==1', 'v.length<1')),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace('v[0].total_count!==a.length', 'v[0].total_count<a.length'),
    ),
  );
  assert.throws(() =>
    validateReleaseSuccessorPostSuccessWorkflow(
      source.replace(
        '--result-archive .stage7/post-success/recovery-result.zip',
        '--result-archive .stage7/post-success/recovery-plan.zip',
      ),
    ),
  );
  return { ...valid, canaries: 27, externalRequests: 0 };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = selfTestReleaseSuccessorPostSuccessWorkflow();
  process.stdout.write(
    `release-successor-post-success workflow policy: PASS (${result.pinnedActions} pinned actions; ${result.sourceArtifacts} raw source artifacts; ${result.observedRunArtifacts} exact observed run artifacts; ${result.canaries} tamper canaries)\n`,
  );
}
