import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  RECOVERY_ENVIRONMENT,
  RECOVERY_SOURCE_ARTIFACTS,
} from '../stage7/release-successor-publication-recovery-contract.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
export const PUBLICATION_RECOVERY_WORKFLOW = 'stage7-release-successor-publication-recovery.yml';
const workflowPath = path.join(root, '.github', 'workflows', PUBLICATION_RECOVERY_WORKFLOW);

const fail = (message) => {
  throw new Error(`release-successor publication recovery workflow policy: ${message}`);
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

export const validatePublicationRecoveryWorkflow = (source) => {
  requireFragments(source, [
    'name: Stage 7 Release Successor Publication Recovery',
    'workflow_dispatch:',
    'confirm_forward_publication:',
    'permissions: {}',
    'group: stage7-assessment-release',
    'cancel-in-progress: false',
    'github.run_attempt == 1',
    "github.event_name == 'workflow_dispatch'",
    "github.ref == 'refs/heads/master'",
    "github.repository == 'ivanmonsalve0404/async-checkout-demo'",
    'inputs.confirm_forward_publication == true',
    `environment: ${RECOVERY_ENVIRONMENT}`,
    'preflight-read-only:',
    'forward-publication:',
    'needs.preflight-read-only.outputs.github-publication-policy',
    "'VERIFY_EXACT_OR_CREATE_MISSING'",
    'actions: read',
    'contents: read',
    'contents: write',
    'id-token: write',
    'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_ROLE_ARN',
    'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN',
    'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_AUTHORITY_B64',
    "--policy-name 'stage7-release-successor-publication-recovery-base'",
    'role-to-assume: ${{ env.STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_ROLE_ARN }}',
    'role-session-name: e7-pub-recovery-${{ github.run_id }}-a${{ github.run_attempt }}',
    'ref: ${{ inputs.candidate_sha }}',
    'persist-credentials: false',
    'sourceRunAttempt: 1',
    'recoveryRunAttempt: Number(process.env.GITHUB_RUN_ATTEMPT)',
    'expectedFenceSha256: process.env.FENCE_SHA256',
    'journalCleanupRoleSha256: process.env.JOURNAL_CLEANUP_ROLE_SHA256',
    'journalRoleAuthoritySha256: process.env.JOURNAL_ROLE_AUTHORITY_SHA256',
    'aws sts get-caller-identity',
    'aws iam get-role',
    'aws iam list-role-policies',
    'aws iam get-role-policy',
    'aws iam list-attached-role-policies',
    'aws iam get-policy',
    'aws iam get-policy-version',
    'aws ssm get-parameter',
    'node recovery-control/scripts/stage7/release-successor-publication-recovery-cli.mjs assess',
    'node "${cli}" crash-window',
    'node "${cli}" route-manifest',
    'release-successor-publication-recovery-cli.mjs extract-route',
    '--route-archives recovery-private/route-archives',
    'node recovery-control/scripts/stage7/release-successor-publication-recovery-cli.mjs validate-authority',
    '--observed-at "${authority_observed_at}"',
    'node recovery-control/scripts/stage7/release-successor-publication-recovery-cli.mjs assert-ready',
    'node recovery-control/scripts/stage7/release-successor-publication-recovery-cli.mjs manifest',
    'node recovery-control/scripts/stage7/release-successor-publication-recovery-cli.mjs extract',
    'node recovery-control/scripts/stage7/release-successor-publication-recovery-cli.mjs complete',
    'release-successor-publication-recovery-cli.mjs" verify-only-operation',
    '--recovery-operation recovery-public/release-successor-publication-recovery-operation.json',
    '--recovery-operation candidate/output/evidence/runtime/stage-7-publication-recovery/publication-operation.json',
    '--role-policies recovery-private/role-policies.json',
    '--role-policy recovery-private/role-policy.json',
    '--attached-policies recovery-private/attached-policies.json',
    '--boundary-metadata recovery-private/boundary-metadata.json',
    'node scripts/stage7/control.mjs verify-successor-fence',
    'pnpm release:github-publication:self-test',
    'pnpm release:publish',
    'pnpm release:preflight',
    'pnpm release:github-publication -- --plan',
    'pnpm release:verify',
    'sha256sum "${target}"',
    'SOURCE_PUBLICATION_PRESENT_SUMMARY_INCOMPLETE',
    'VERIFY_EXACT_NO_MUTATION',
    'path: recovery-upload/plan/',
    'path: recovery-upload/result/',
    "'release-successor-completion-fence.json'",
    "'release-successor-publication-recovery-plan.json'",
    "'release-successor-publication-recovery-receipt.json'",
    'stage7-release-successor-publication-recovery-plan-s${{ inputs.source_run_id }}-r${{ github.run_id }}-a${{ github.run_attempt }}',
    'stage7-release-successor-publication-recovery-result-s${{ inputs.source_run_id }}-r${{ github.run_id }}-a${{ github.run_attempt }}',
    'retention-days: 30',
  ]);
  const preflightStart = source.indexOf('  preflight-read-only:');
  const forwardStart = source.indexOf('  forward-publication:');
  if (preflightStart < 0 || forwardStart <= preflightStart) {
    fail('read-only preflight must causally precede the write-capable forward job');
  }
  const preflight = source.slice(preflightStart, forwardStart);
  const forward = source.slice(forwardStart);
  indexInOrder(preflight, [
    'Fail closed on missing protected authority, IAM, environment or identity',
    'Observe the exact failed attempt-1 source, jobs and artifact inventory',
    'Classify A B or C and download only route-specific validation evidence',
    'Assume only the dedicated read-only publication recovery role',
    'Observe exact live caller, trust, boundary and immutable fence version 1',
    'Build and authorize the deterministic forward-only recovery plan',
    'Stage the exact two root basenames for the pre-mutation plan artifact',
    'Preserve the authorized plan before any GitHub publication',
    'Redownload every exact source artifact and verify raw GitHub digests',
    'Revalidate the exact immutable fence and publication contract without mutation',
    'Rebind fresh protected authorization before deployed URL verification',
    'Verify C source publication exactly with no write-capable token path',
    'Emit a receipt that cannot claim Stage 7 closure',
    'Stage the exact eight root basenames for the C result supplement',
    'Preserve the exact C result supplement without duplicating source artifacts',
  ]);
  indexInOrder(forward, [
    'Download only the sealed pre-mutation plan artifact from this run',
    'Revalidate the exact plan root set route authority and expiry',
    'Redownload and verify only the 27 source artifacts sealed by the plan',
    'Revalidate and prepare the exact publication locally',
    'Verify exact remote state or create only the missing GitHub publication',
    'Emit the non-closing A or B recovery receipt',
    'Stage the exact eight root basenames for the A or B result supplement',
    'Preserve the exact A or B result supplement',
  ]);

  const uses = [...source.matchAll(/^\s*uses:\s*([^\s#]+).*$/gmu)].map((match) => match[1]);
  if (
    uses.length !== 13 ||
    uses.some((reference) => reference.startsWith('./') || !/@[0-9a-f]{40}$/u.test(reference))
  ) {
    fail('all thirteen actions must be exact immutable commit references');
  }
  const assumedRoles = [...source.matchAll(/^\s*role-to-assume:\s*(.+)$/gmu)].map((match) =>
    match[1].trim(),
  );
  if (
    assumedRoles.length !== 1 ||
    assumedRoles[0] !== '${{ env.STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_ROLE_ARN }}'
  ) {
    fail('only the dedicated publication recovery role may be assumed');
  }
  if (
    !preflight.includes('contents: read') ||
    preflight.includes('contents: write') ||
    !preflight.includes('id-token: write') ||
    !preflight.includes(
      "if: steps.route.outputs.github-publication-policy == 'VERIFY_EXACT_NO_MUTATION'",
    ) ||
    preflight.includes('pnpm release:github-publication -- --plan') ||
    !preflight.includes('verify-only-operation')
  ) {
    fail('C must terminate inside the read-only preflight without a publication adapter');
  }
  if (
    !forward.includes('contents: write') ||
    forward.includes('id-token: write') ||
    !forward.includes(
      "needs.preflight-read-only.outputs.github-publication-policy ==\n      'VERIFY_EXACT_OR_CREATE_MISSING'",
    ) ||
    !forward.includes('VERIFY_EXACT_OR_CREATE_MISSING') ||
    !forward.includes('pnpm release:github-publication -- --plan') ||
    forward.includes('VERIFY_EXACT_NO_MUTATION')
  ) {
    fail('only A or B may enter the physically separate write-capable job');
  }
  const sessionPolicyStart = source.indexOf('{"Version":"2012-10-17","Statement":[');
  const sessionPolicyEnd = source.indexOf('\n          mask-aws-account-id:', sessionPolicyStart);
  const sessionPolicy = source.slice(sessionPolicyStart, sessionPolicyEnd);
  requireFragments(sessionPolicy, [
    '"Sid":"ReadCallerIdentity"',
    '"Action":"sts:GetCallerIdentity","Resource":"*"',
    '"Sid":"ReadOwnRecoveryRole"',
    '"Action":["iam:GetRole","iam:GetRolePolicy","iam:ListAttachedRolePolicies","iam:ListRolePolicies"]',
    '"Sid":"ReadExactRecoveryBoundary"',
    '"Action":["iam:GetPolicy","iam:GetPolicyVersion"]',
    '"Sid":"ReadExactImmutableFence"',
    '"Action":"ssm:GetParameter"',
    'parameter/checkout/stage7/release-fence/${{ inputs.candidate_sha }}/${{ inputs.source_run_id }}',
  ]);
  if (
    sessionPolicyStart < 0 ||
    sessionPolicyEnd < 0 ||
    /PutParameter|DeleteParameter|GetParametersByPath|ssm:\*|iam:\*/u.test(sessionPolicy) ||
    (sessionPolicy.match(/"Resource":"\*"/gu) ?? []).length !== 1
  ) {
    fail('session policy must be read-only and exact except STS caller identity');
  }
  if (
    source.includes('workflow_run:') ||
    source.includes('pull_request:') ||
    source.includes('overwrite: true') ||
    source.includes('aws ssm put-parameter') ||
    source.includes('aws ssm delete-parameter') ||
    source.includes('aws cloudformation deploy') ||
    source.includes('aws cloudformation delete-stack') ||
    source.includes('aws lambda update-') ||
    source.includes('aws s3 rm') ||
    source.includes('gh release delete') ||
    source.includes('git push --force') ||
    source.includes('sourceRunConclusionMutable: true') ||
    source.includes('stage7GateClaimed: true')
  ) {
    fail('alternate trigger, destructive mutation, overwrite or false closure detected');
  }
  if ((source.match(/contents: write/gu) ?? []).length !== 1) {
    fail('only the protected recovery job may receive GitHub publication authority');
  }
  if ((source.match(new RegExp(`environment: ${RECOVERY_ENVIRONMENT}`, 'gu')) ?? []).length !== 2) {
    fail('both and only the preflight and forward jobs must use the protected environment');
  }
  if ((source.match(/id-token: write/gu) ?? []).length !== 1) {
    fail('only the protected recovery job may request OIDC authority');
  }
  if ((source.match(/pnpm release:github-publication -- --plan/gu) ?? []).length !== 1) {
    fail('exactly one recoverable GitHub publication adapter is permitted');
  }
  if ((source.match(/retention-days: 30/gu) ?? []).length !== 3) {
    fail('the plan and both mutually exclusive result producers require retention');
  }
  if ((source.match(/path: recovery-upload\/plan\//gu) ?? []).length !== 1) {
    fail('the plan upload must use one staged root directory');
  }
  if ((source.match(/path: recovery-upload\/result\//gu) ?? []).length !== 2) {
    fail('both mutually exclusive result producers must use the staged result root');
  }
  if ((source.match(/uses: actions\/download-artifact@/gu) ?? []).length !== 1) {
    fail('the forward job must consume exactly the sealed plan artifact');
  }
  if (
    (source.match(/release-successor-publication-recovery-cli\.mjs assert-ready/gu) ?? [])
      .length !== 2
  ) {
    fail('both the preflight and forward boundary must revalidate route authority');
  }
  if ((source.match(/sha256sum "\$\{target\}"/gu) ?? []).length !== 3) {
    fail('route and both 27-artifact downloads must verify raw GitHub digests');
  }
  if (
    (
      source.match(
        /if: steps\.route\.outputs\.github-publication-policy == 'VERIFY_EXACT_NO_MUTATION'/gu,
      ) ?? []
    ).length !== 4
  ) {
    fail('all four C-only steps must remain physically gated by the no-mutation policy');
  }
  if (!source.includes('release-successor-publication-recovery-cli.mjs manifest')) {
    fail('artifact download set must derive from the validated recovery plan');
  }
  for (const command of [
    'aws iam list-role-policies',
    'aws iam get-role-policy',
    'aws iam list-attached-role-policies',
  ]) {
    if ((source.match(new RegExp(command, 'gu')) ?? []).length !== 1) {
      fail(`live role profile must capture exactly once: ${command}`);
    }
  }
  return {
    status: 'PASS',
    pinnedActions: uses.length,
    sourceArtifacts: RECOVERY_SOURCE_ARTIFACTS.length,
    publicRecoveryArtifacts: 2,
  };
};

export const selfTestPublicationRecoveryWorkflow = () => {
  const source = readFileSync(workflowPath, 'utf8');
  const valid = validatePublicationRecoveryWorkflow(source);
  const canaries = [
    ['github.run_attempt == 1', 'github.run_attempt >= 1'],
    [`environment: ${RECOVERY_ENVIRONMENT}`, 'environment: assessment-release'],
    [
      'role-to-assume: ${{ env.STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_ROLE_ARN }}',
      'role-to-assume: ${{ env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN }}',
    ],
    ['"Action":"ssm:GetParameter"', '"Action":"ssm:PutParameter"'],
    [
      'pnpm release:github-publication -- --plan',
      'gh release delete v1.2.3 && pnpm release:github-publication -- --plan',
    ],
    ['contents: write', 'contents: read'],
    ['id-token: write', 'id-token: read'],
    [
      'Preserve the authorized plan before any GitHub publication',
      'Preserve the authorized plan after any GitHub publication',
    ],
    [
      'node recovery-control/scripts/stage7/release-successor-publication-recovery-cli.mjs assert-ready',
      'node -e "process.exit(0)"',
    ],
    [
      'node recovery-control/scripts/stage7/release-successor-publication-recovery-cli.mjs validate-authority',
      'node -e "process.exit(0)"',
    ],
    ['--observed-at "${authority_observed_at}"', '--observed-at "2099-01-01T00:00:00.000Z"'],
    ['sha256sum "${target}"', 'wc -c "${target}"'],
    ['preflight-read-only:', 'preflight-write-capable:'],
    ['path: recovery-upload/plan/', 'path: recovery-public/'],
    [
      "if: steps.route.outputs.github-publication-policy == 'VERIFY_EXACT_NO_MUTATION'",
      "if: steps.route.outputs.github-publication-policy == 'VERIFY_EXACT_OR_CREATE_MISSING'",
    ],
    [
      'needs.preflight-read-only.outputs.github-publication-policy ==',
      'needs.preflight-read-only.outputs.github-publication-policy !=',
    ],
  ];
  for (const [from, to] of canaries) {
    assert.notEqual(source.indexOf(from), -1);
    assert.throws(
      () => validatePublicationRecoveryWorkflow(source.replace(from, to)),
      undefined,
      `tamper must fail: ${from}`,
    );
  }
  return { ...valid, canaries: canaries.length, externalRequests: 0, mutations: 0 };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = selfTestPublicationRecoveryWorkflow();
  process.stdout.write(
    `release-successor publication recovery workflow: PASS (${result.pinnedActions} pinned ` +
      `actions; ${result.sourceArtifacts} source artifacts; ${result.canaries} tamper canaries)\n`,
  );
}
