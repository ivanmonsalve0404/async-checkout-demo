import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { sha256 } from '../stage6/lib/evidence.mjs';
import { objectSha256 } from './core.mjs';
import {
  RECOVERY_ALLOWED_ACTIONS,
  RECOVERY_CRASH_WINDOWS,
  RECOVERY_FORBIDDEN_ACTIONS,
  RECOVERY_INTERNAL_ARTIFACTS,
  RECOVERY_OPTIONAL_INCOMPLETE_SUMMARY_ARTIFACTS,
  RECOVERY_ROLE_INLINE_POLICY_NAME,
  RECOVERY_SOURCE_FENCE_ARTIFACT,
  RECOVERY_SOURCE_PUBLICATION_ARTIFACT,
  RECOVERY_SOURCE_ARTIFACTS,
  RECOVERY_WORKFLOW,
  RECOVERY_ENVIRONMENT,
  createPublicationRecoveryPlan,
  createPublicationRecoveryPostSuccessIntake,
  createPublicationRecoveryReceipt,
  createPublicationRecoveryVerifyOnlyOperation,
  expectedRecoveryBoundaryPolicy,
  expectedRecoverySessionPolicy,
  expectedRecoveryTrustPolicy,
  readPublicationRecoveryResultArchive,
  recoverySessionIsSubsetOfBase,
  validatePublicationRecoveryPlan,
  validatePublicationRecoveryReceipt,
} from './release-successor-publication-recovery-contract.mjs';
import { createReleaseSuccessorStoredZipFixture } from './release-successor-zip.mjs';

const H = (character) => character.repeat(64);
const candidateSha = 'a'.repeat(40);
const sourceRunId = '7001';
const recoveryRunId = '7002';
const releaseId = 'rel-20260818-1200-aaaaaaa';
const releaseTag = 'v1.2.3';
const awsAccountId = '111122223333';
const awsRegion = 'us-east-1';
const recoveryRoleArn = `arn:aws:iam::${awsAccountId}:role/stage7-release-successor-publication-recovery`;
const permissionsBoundaryArn = `arn:aws:iam::${awsAccountId}:policy/stage7-release-successor-publication-recovery-boundary`;

const withDigest = (value, key) => ({ ...value, [key]: objectSha256(value) });
const clone = (value) => JSON.parse(JSON.stringify(value));

const fenceBody = {
  schemaVersion: 1,
  stage: 7,
  kind: 'RELEASE_SUCCESSOR_RELEASE_COMPLETION_FENCE',
  status: 'RELEASE_EVIDENCE_FENCED_IMMUTABLE',
  repository: 'ivanmonsalve0404/async-checkout-demo',
  sourceWorkflowPath: '.github/workflows/release.yml',
  sourceRunId,
  sourceRunAttempt: 1,
  candidateSha,
  releaseId,
  journalLifecycleSha256: H('1'),
  journalCleanupRoleSha256: H('2'),
  journalRoleAuthoritySha256: H('3'),
  evidenceBindings: Object.fromEntries(
    ['approval', 'activation', 'drift', 'rollbackCompletion', 'preFenceGate'].map((name, index) => [
      name,
      {
        rawSha256: String(index + 4).repeat(64),
        canonicalSha256: String(index + 4).repeat(64),
        bytes: 100 + index,
      },
    ]),
  ),
  authoritySetSha256: H('9'),
  mutationsBlocked: true,
  orphanedFailurePolicy: 'BLOCKED_FENCE_REQUIRES_SEPARATE_AUTHORIZED_RECOVERY',
  containsSensitiveData: false,
};
const fence = withDigest(fenceBody, 'fenceSha256');

const authorityBody = {
  schemaVersion: 1,
  stage: 7,
  kind: 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_AUTHORITY',
  status: 'APPROVED',
  repository: 'ivanmonsalve0404/async-checkout-demo',
  recoveryWorkflowPath: RECOVERY_WORKFLOW,
  protectedEnvironment: RECOVERY_ENVIRONMENT,
  sourceRunId,
  sourceRunAttempt: 1,
  candidateSha,
  releaseId,
  releaseTag,
  crashWindow: RECOVERY_CRASH_WINDOWS[0],
  fenceSha256: fence.fenceSha256,
  journalCleanupRoleSha256: fence.journalCleanupRoleSha256,
  journalRoleAuthoritySha256: fence.journalRoleAuthoritySha256,
  recoveryRoleArnSha256: sha256(recoveryRoleArn),
  permissionsBoundaryArnSha256: sha256(permissionsBoundaryArn),
  allowedActions: [...RECOVERY_ALLOWED_ACTIONS],
  forbiddenActions: [...RECOVERY_FORBIDDEN_ACTIONS],
  approvedByAlias: 'release-operator',
  approvalReferenceSha256: H('b'),
  approvedAtUtc: '2026-08-18T12:00:00.000Z',
  expiresAtUtc: '2026-08-18T18:00:00.000Z',
  containsSensitiveData: false,
};
const authority = withDigest(authorityBody, 'authoritySha256');

const expected = {
  sourceRunId,
  sourceRunAttempt: 1,
  recoveryRunId,
  recoveryRunAttempt: 1,
  candidateSha,
  releaseId,
  releaseTag,
  expectedFenceSha256: fence.fenceSha256,
  expectedAuthoritySha256: authority.authoritySha256,
  journalCleanupRoleSha256: fence.journalCleanupRoleSha256,
  journalRoleAuthoritySha256: fence.journalRoleAuthoritySha256,
  awsAccountId,
  awsRegion,
  recoveryRoleArn,
  permissionsBoundaryArn,
};

const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const publicationDocuments = ({ externalWritesPerformed = 0 } = {}) => {
  const plan = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PUBLICATION_PLAN',
    status: 'READY_FOR_EXTERNAL_PUBLICATION',
    candidateSha,
    releaseId,
    releaseTag,
    repository: 'ivanmonsalve0404/async-checkout-demo',
    retryPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
  };
  const publication = {
    ...plan,
    kind: 'PUBLICATION_PREPARATION',
    packageSha256: H('c'),
  };
  const target = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PUBLICATION_TARGET_PREFLIGHT',
    status: 'PASS',
    candidateSha,
    releaseId,
    releaseTag,
    publicationPlanSha256: objectSha256(plan),
  };
  const operation = {
    schemaVersion: 1,
    stage: 7,
    kind: 'GITHUB_PUBLICATION_OPERATION',
    status: 'PASS',
    candidateSha,
    releaseId,
    releaseTag,
    repository: 'ivanmonsalve0404/async-checkout-demo',
    publicationPlanSha256: objectSha256(plan),
    releaseState: 'COMPLETE',
    externalRequests: 10,
    externalWritesPerformed,
  };
  const proof = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PUBLICATION_PROOF',
    status: 'PASS',
    candidateSha,
    releaseId,
    releaseTag,
    repository: 'ivanmonsalve0404/async-checkout-demo',
    releasePresent: true,
    releaseVerifiedExact: true,
    publicationPlanSha256: objectSha256(plan),
    publicationTargetProofSha256: objectSha256(target),
    publicationOperationSha256: objectSha256(operation),
    externalRequests: 13,
  };
  return {
    'publication.json': publication,
    'publication-operation.json': operation,
    'publication-plan.json': plan,
    'publication-proof.json': proof,
    'publication-target-proof.json': target,
  };
};

const publicationSources = (options) =>
  Object.fromEntries(
    Object.entries(publicationDocuments(options)).map(([name, value]) => [name, jsonBytes(value)]),
  );

const fixture = ({ crashWindow = RECOVERY_CRASH_WINDOWS[0], routeArchiveDirectory } = {}) => {
  if (typeof routeArchiveDirectory !== 'string') throw new Error('TEST_ROUTE_DIRECTORY_REQUIRED');
  mkdirSync(routeArchiveDirectory, { recursive: true });
  const fenceArchive = createReleaseSuccessorStoredZipFixture({
    'release-successor-completion-fence.json': `${JSON.stringify(fence)}\n`,
  });
  const publicationFiles = publicationSources({ externalWritesPerformed: 1 });
  const publicationArchive = createReleaseSuccessorStoredZipFixture(publicationFiles);
  const routeArtifacts = [];
  if (crashWindow !== RECOVERY_CRASH_WINDOWS[0]) {
    writeFileSync(
      path.join(routeArchiveDirectory, `${RECOVERY_SOURCE_FENCE_ARTIFACT}.zip`),
      fenceArchive,
    );
    routeArtifacts.push({
      name: RECOVERY_SOURCE_FENCE_ARTIFACT,
      digest: `sha256:${sha256(fenceArchive)}`,
    });
  }
  if (crashWindow === RECOVERY_CRASH_WINDOWS[2]) {
    writeFileSync(
      path.join(routeArchiveDirectory, `${RECOVERY_SOURCE_PUBLICATION_ARTIFACT}.zip`),
      publicationArchive,
    );
    routeArtifacts.push({
      name: RECOVERY_SOURCE_PUBLICATION_ARTIFACT,
      digest: `sha256:${sha256(publicationArchive)}`,
    });
  }
  const fenceConclusion = crashWindow === RECOVERY_CRASH_WINDOWS[0] ? 'failure' : 'success';
  const publicationConclusion =
    crashWindow === RECOVERY_CRASH_WINDOWS[0]
      ? 'skipped'
      : crashWindow === RECOVERY_CRASH_WINDOWS[1]
        ? 'failure'
        : 'success';
  const routeAuthorityBody = {
    ...authorityBody,
    crashWindow,
    allowedActions:
      crashWindow === RECOVERY_CRASH_WINDOWS[2]
        ? RECOVERY_ALLOWED_ACTIONS.filter(
            (action) => action !== 'VERIFY_OR_CREATE_MISSING_GITHUB_PUBLICATION',
          )
        : [...RECOVERY_ALLOWED_ACTIONS],
  };
  const routeAuthority = withDigest(routeAuthorityBody, 'authoritySha256');
  const routeExpected = {
    ...clone(expected),
    expectedAuthoritySha256: routeAuthority.authoritySha256,
  };
  return {
    expected: routeExpected,
    run: {
      id: Number(sourceRunId),
      run_attempt: 1,
      repository: { full_name: 'ivanmonsalve0404/async-checkout-demo' },
      event: 'workflow_dispatch',
      head_branch: 'master',
      head_sha: candidateSha,
      status: 'completed',
      conclusion: 'failure',
    },
    workflow: {
      name: 'Stage 7 Release',
      path: '.github/workflows/release.yml',
      state: 'active',
    },
    jobs: {
      jobs: [
        {
          id: 7101,
          run_attempt: 1,
          name: '23 Seal immutable pre-publication fence',
          status: 'completed',
          conclusion: fenceConclusion,
        },
        {
          id: 7102,
          run_attempt: 1,
          name: '24 Publish release',
          status: 'completed',
          conclusion: publicationConclusion,
        },
        {
          id: 7103,
          run_attempt: 1,
          name: '25 Release summary and gates',
          status: 'completed',
          conclusion: 'failure',
        },
      ],
    },
    artifacts: {
      artifacts: [
        ...[
          ...RECOVERY_SOURCE_ARTIFACTS,
          ...RECOVERY_INTERNAL_ARTIFACTS,
          ...RECOVERY_OPTIONAL_INCOMPLETE_SUMMARY_ARTIFACTS,
        ].map((name, index) => ({
          id: 8000 + index,
          name,
          expired: false,
          digest: `sha256:${index.toString(16).padStart(64, '0')}`,
          workflow_run: { id: Number(sourceRunId) },
        })),
        ...routeArtifacts.map(({ name, digest }, index) => ({
          id: 9000 + index,
          name,
          expired: false,
          digest,
          workflow_run: { id: Number(sourceRunId) },
        })),
      ],
    },
    caller: {
      Account: awsAccountId,
      Arn:
        `arn:aws:sts::${awsAccountId}:assumed-role/` +
        `stage7-release-successor-publication-recovery/e7-pub-recovery-${recoveryRunId}-a1`,
    },
    role: {
      Role: {
        Arn: recoveryRoleArn,
        RoleName: 'stage7-release-successor-publication-recovery',
        PermissionsBoundary: { PermissionsBoundaryArn: permissionsBoundaryArn },
        AssumeRolePolicyDocument: expectedRecoveryTrustPolicy({ awsAccountId }),
      },
    },
    rolePolicies: {
      PolicyNames: [RECOVERY_ROLE_INLINE_POLICY_NAME],
      IsTruncated: false,
    },
    rolePolicy: {
      RoleName: 'stage7-release-successor-publication-recovery',
      PolicyName: RECOVERY_ROLE_INLINE_POLICY_NAME,
      PolicyDocument: expectedRecoveryBoundaryPolicy({
        awsAccountId,
        awsRegion,
        recoveryRoleArn,
        permissionsBoundaryArn,
      }),
    },
    attachedPolicies: {
      AttachedPolicies: [],
      IsTruncated: false,
    },
    boundaryMetadata: {
      Policy: {
        Arn: permissionsBoundaryArn,
        DefaultVersionId: 'v1',
      },
    },
    boundary: {
      PolicyVersion: {
        VersionId: 'v1',
        IsDefaultVersion: true,
        Document: expectedRecoveryBoundaryPolicy({
          awsAccountId,
          awsRegion,
          recoveryRoleArn,
          permissionsBoundaryArn,
        }),
      },
    },
    parameterResponse: {
      Parameter: {
        Name: `/checkout/stage7/release-fence/${candidateSha}/${sourceRunId}`,
        Type: 'String',
        Value: `${JSON.stringify(fence)}\n`,
        Version: 1,
        ARN:
          `arn:aws:ssm:${awsRegion}:${awsAccountId}:parameter/checkout/stage7/` +
          `release-fence/${candidateSha}/${sourceRunId}`,
        DataType: 'text',
      },
    },
    authority: routeAuthority,
    routeArchiveDirectory,
    observedAtUtc: '2026-08-18T13:00:00.000Z',
  };
};

const withFixture = (options, callback) => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'e7-publication-route-'));
  try {
    return callback(fixture({ ...options, routeArchiveDirectory: path.join(root, 'route') }));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};
const createPlan = (crashWindow = RECOVERY_CRASH_WINDOWS[0]) =>
  withFixture({ crashWindow }, (input) => createPublicationRecoveryPlan(input).plan);
const mustReject = (mutate, crashWindow = RECOVERY_CRASH_WINDOWS[0]) => {
  withFixture({ crashWindow }, (input) => {
    mutate(input);
    assert.throws(() => createPublicationRecoveryPlan(input));
  });
};

export const createPublicationRecoveryPostSuccessFixture = ({
  crashWindow = RECOVERY_CRASH_WINDOWS[0],
} = {}) => {
  if (!RECOVERY_CRASH_WINDOWS.includes(crashWindow)) {
    throw new Error('TEST_CRASH_WINDOW_INVALID');
  }
  const root = mkdtempSync(path.join(os.tmpdir(), 'e7-publication-post-success-'));
  try {
    const source = fixture({
      crashWindow,
      routeArchiveDirectory: path.join(root, 'route'),
    });
    const plan = createPublicationRecoveryPlan(source).plan;
    const publicationDirectory = path.join(root, 'publication');
    mkdirSync(publicationDirectory, { recursive: false });
    const publicationFiles = publicationSources({ externalWritesPerformed: 1 });
    for (const [name, bytes] of Object.entries(publicationFiles)) {
      writeFileSync(path.join(publicationDirectory, name), bytes);
    }
    const recoveryOperation =
      crashWindow === RECOVERY_CRASH_WINDOWS[2]
        ? createPublicationRecoveryVerifyOnlyOperation({
            plan,
            publicationDirectory,
            liveProofSource: publicationFiles['publication-proof.json'],
          })
        : JSON.parse(publicationFiles['publication-operation.json'].toString('utf8'));
    const recoveryOperationSource = jsonBytes(recoveryOperation);
    const receipt = createPublicationRecoveryReceipt({
      plan,
      publicationDirectory,
      recoveryOperationSource,
      completedAtUtc: '2026-08-18T13:30:00.000Z',
    });
    const fenceSource = Buffer.from(source.parameterResponse.Parameter.Value, 'utf8');
    const planSource = jsonBytes(plan);
    const receiptSource = jsonBytes(receipt);
    const planArchive = createReleaseSuccessorStoredZipFixture({
      'release-successor-completion-fence.json': fenceSource,
      'release-successor-publication-recovery-plan.json': planSource,
    });
    const resultArchive = createReleaseSuccessorStoredZipFixture({
      'release-successor-completion-fence.json': fenceSource,
      'release-successor-publication-recovery-plan.json': planSource,
      'release-successor-publication-recovery-receipt.json': receiptSource,
      ...publicationFiles,
    });
    const planArtifactName = receipt.artifactExpectations.planArtifactName;
    const resultArtifactName = receipt.artifactExpectations.resultArtifactName;
    const recoveryArtifacts = {
      artifacts: [
        {
          id: 9901,
          name: planArtifactName,
          expired: false,
          digest: `sha256:${sha256(planArchive)}`,
          workflow_run: { id: Number(recoveryRunId) },
        },
        {
          id: 9902,
          name: resultArtifactName,
          expired: false,
          digest: `sha256:${sha256(resultArchive)}`,
          workflow_run: { id: Number(recoveryRunId) },
        },
      ],
    };
    const intakeArguments = {
      recoveryRun: {
        id: Number(recoveryRunId),
        run_attempt: 1,
        repository: { full_name: 'ivanmonsalve0404/async-checkout-demo' },
        event: 'workflow_dispatch',
        head_branch: 'master',
        status: 'completed',
        conclusion: 'success',
      },
      recoveryWorkflow: {
        name: 'Stage 7 Release Successor Publication Recovery',
        path: RECOVERY_WORKFLOW,
        state: 'active',
      },
      recoveryArtifacts,
      planArchive,
      resultArchive,
      sourceRun: source.run,
      sourceWorkflow: source.workflow,
      sourceJobs: source.jobs,
      sourceArtifacts: source.artifacts,
      observedAtUtc: '2026-08-18T14:00:00.000Z',
    };
    return {
      crashWindow,
      source,
      plan,
      receipt,
      recoveryOperation,
      publicationFiles,
      fenceSource,
      planSource,
      receiptSource,
      planArchive,
      resultArchive,
      recoveryArtifacts,
      intakeArguments,
    };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
};

export const selfTestPublicationRecovery = () => {
  const first = createPlan();
  const second = createPlan();
  assert.deepEqual(first, second);
  assert.equal(first.status, 'READY_FOR_AUTHORIZED_RECOVERY_ROUTE');
  assert.equal(first.route.githubPublicationPolicy, 'VERIFY_EXACT_OR_CREATE_MISSING');
  assert.equal(first.source.crashWindow, RECOVERY_CRASH_WINDOWS[0]);
  assert.equal(first.sharedIntegration.catalog, 'RECOVERY_SUPPLEMENT_CATALOG_V1');
  assert.equal(first.sharedIntegration.postSuccessConsumer, 'WIRED_CONTRACT');
  assert.equal(first.sharedIntegration.closureStatus, 'POST_SUCCESS_COMPOSITE_REQUIRED');
  assert.equal(first.sharedIntegration.stage7GateClaimed, false);
  assert.equal(first.source.runAttempt, 1);
  assert.equal(first.owner.recoveryRunAttempt, 1);
  assert.equal(first.fence.parameterVersion, 1);
  assert.deepEqual(first.route.forbiddenActions, RECOVERY_FORBIDDEN_ACTIONS);
  const basePolicy = expectedRecoveryBoundaryPolicy({
    awsAccountId,
    awsRegion,
    recoveryRoleArn,
    permissionsBoundaryArn,
  });
  const sessionPolicy = expectedRecoverySessionPolicy({
    awsAccountId,
    awsRegion,
    candidateSha,
    sourceRunId,
    recoveryRoleArn,
    permissionsBoundaryArn,
  });
  assert.equal(recoverySessionIsSubsetOfBase({ basePolicy, sessionPolicy }), true);
  const widenedSession = clone(sessionPolicy);
  widenedSession.Statement.at(-1).Resource =
    `arn:aws:ssm:${awsRegion}:${awsAccountId}:parameter/checkout/stage7/release-fence/*`;
  assert.equal(recoverySessionIsSubsetOfBase({ basePolicy, sessionPolicy: widenedSession }), false);
  assert.equal(first.artifactInventory.observedCount, 32);
  const subsetPlan = withFixture({}, (withoutIncompleteSummary) => {
    withoutIncompleteSummary.artifacts.artifacts =
      withoutIncompleteSummary.artifacts.artifacts.filter(
        ({ name }) => !RECOVERY_OPTIONAL_INCOMPLETE_SUMMARY_ARTIFACTS.includes(name),
      );
    return createPublicationRecoveryPlan(withoutIncompleteSummary).plan;
  });
  assert.equal(subsetPlan.artifactInventory.observedCount, 30);
  assert.equal(subsetPlan.artifactInventory.optionalIncompleteSummaryCount, 0);
  const routeB = createPlan(RECOVERY_CRASH_WINDOWS[1]);
  assert.equal(routeB.source.crashWindow, RECOVERY_CRASH_WINDOWS[1]);
  assert.equal(routeB.artifactInventory.observedCount, 33);
  assert.equal(routeB.artifactInventory.downloadManifest.length, 27);
  assert.equal(routeB.artifactInventory.sourceFenceManifest.length, 1);
  assert.equal(routeB.artifactInventory.sourcePublicationManifest.length, 0);
  const routeC = createPlan(RECOVERY_CRASH_WINDOWS[2]);
  assert.equal(routeC.source.crashWindow, RECOVERY_CRASH_WINDOWS[2]);
  assert.equal(routeC.route.mode, 'VERIFY_EXACT_NOOP');
  assert.equal(routeC.route.githubPublicationPolicy, 'VERIFY_EXACT_NO_MUTATION');
  assert.equal(routeC.artifactInventory.observedCount, 34);
  assert.equal(routeC.artifactInventory.downloadManifest.length, 27);
  assert.equal(routeC.artifactInventory.sourceFenceManifest.length, 1);
  assert.equal(routeC.artifactInventory.sourcePublicationManifest.length, 1);

  mustReject((input) => {
    input.run.run_attempt = 2;
  });
  mustReject((input) => {
    input.run.conclusion = 'success';
  });
  mustReject((input) => {
    input.jobs.jobs[0].conclusion = 'success';
  });
  mustReject((input) => {
    input.jobs.jobs[1].conclusion = 'success';
  });
  mustReject((input) => {
    input.jobs.jobs[2].conclusion = 'success';
  });
  mustReject((input) => {
    input.artifacts.artifacts.push({
      id: 9999,
      name: 'stage7-release-successor-fence',
      expired: false,
      digest: `sha256:${H('c')}`,
      workflow_run: { id: Number(sourceRunId) },
    });
  });
  mustReject((input) => {
    input.artifacts.artifacts = input.artifacts.artifacts.filter(
      ({ name }) => name !== RECOVERY_SOURCE_ARTIFACTS[0],
    );
  });
  mustReject((input) => {
    input.artifacts.artifacts = input.artifacts.artifacts.filter(
      ({ name }) => name !== RECOVERY_INTERNAL_ARTIFACTS[0],
    );
  });
  mustReject((input) => {
    input.artifacts.artifacts.push({
      id: 9997,
      name: 'stage7-unknown-artifact',
      expired: false,
      digest: `sha256:${H('d')}`,
      workflow_run: { id: Number(sourceRunId) },
    });
  });
  mustReject((input) => {
    input.artifacts.artifacts.push(clone(input.artifacts.artifacts[0]));
  });
  mustReject((input) => {
    input.artifacts.artifacts = input.artifacts.artifacts.filter(
      ({ name }) => name !== RECOVERY_SOURCE_FENCE_ARTIFACT,
    );
  }, RECOVERY_CRASH_WINDOWS[1]);
  mustReject((input) => {
    const target = path.join(input.routeArchiveDirectory, `${RECOVERY_SOURCE_FENCE_ARTIFACT}.zip`);
    const bytes = readFileSync(target);
    bytes[10] ^= 1;
    writeFileSync(target, bytes);
  }, RECOVERY_CRASH_WINDOWS[1]);
  mustReject((input) => {
    const target = path.join(input.routeArchiveDirectory, `${RECOVERY_SOURCE_FENCE_ARTIFACT}.zip`);
    const archive = createReleaseSuccessorStoredZipFixture({
      'release-successor-completion-fence.json': jsonBytes(fence),
    });
    writeFileSync(target, archive);
    input.artifacts.artifacts.find(({ name }) => name === RECOVERY_SOURCE_FENCE_ARTIFACT).digest =
      `sha256:${sha256(archive)}`;
  }, RECOVERY_CRASH_WINDOWS[1]);
  mustReject((input) => {
    input.artifacts.artifacts = input.artifacts.artifacts.filter(
      ({ name }) => name !== RECOVERY_SOURCE_PUBLICATION_ARTIFACT,
    );
  }, RECOVERY_CRASH_WINDOWS[2]);
  mustReject((input) => {
    const target = path.join(
      input.routeArchiveDirectory,
      `${RECOVERY_SOURCE_PUBLICATION_ARTIFACT}.zip`,
    );
    const bytes = readFileSync(target);
    bytes[10] ^= 1;
    writeFileSync(target, bytes);
  }, RECOVERY_CRASH_WINDOWS[2]);
  mustReject((input) => {
    input.parameterResponse.Parameter.Version = 2;
  });
  mustReject((input) => {
    input.parameterResponse.Parameter.Value = input.parameterResponse.Parameter.Value.replace(
      'RELEASE_EVIDENCE_FENCED_IMMUTABLE',
      'RELEASE_EVIDENCE_FENCED_MUTABLE',
    );
  });
  mustReject((input) => {
    input.expected.journalRoleAuthoritySha256 = H('c');
  });
  mustReject((input) => {
    input.authority.expiresAtUtc = '2026-08-18T12:30:00.000Z';
    const body = { ...input.authority };
    delete body.authoritySha256;
    input.authority.authoritySha256 = objectSha256(body);
    input.expected.expectedAuthoritySha256 = input.authority.authoritySha256;
  });
  mustReject((input) => {
    input.role.Role.AssumeRolePolicyDocument.Statement[0].Condition.StringEquals[
      'token.actions.githubusercontent.com:sub'
    ] = 'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release';
  });
  mustReject((input) => {
    input.role.Role.AssumeRolePolicyDocument.Statement.push(
      clone(input.role.Role.AssumeRolePolicyDocument.Statement[0]),
    );
  });
  mustReject((input) => {
    input.rolePolicies.PolicyNames.push('foreign-inline-policy');
  });
  mustReject((input) => {
    input.attachedPolicies.AttachedPolicies.push({
      PolicyName: 'foreign-attached-policy',
      PolicyArn: `arn:aws:iam::${awsAccountId}:policy/foreign-attached-policy`,
    });
  });
  mustReject((input) => {
    input.rolePolicy.PolicyDocument.Statement.push({
      Sid: 'ForeignRead',
      Effect: 'Allow',
      Action: 'ssm:GetParametersByPath',
      Resource: '*',
    });
  });
  mustReject((input) => {
    input.boundary.PolicyVersion.Document.Statement.push({
      Sid: 'ForbiddenWrite',
      Effect: 'Allow',
      Action: 'ssm:PutParameter',
      Resource: '*',
    });
  });
  mustReject((input) => {
    input.caller.Arn += '-foreign';
  });

  const forgedRoute = clone(first);
  forgedRoute.route.forbiddenActions = forgedRoute.route.forbiddenActions.filter(
    (action) => action !== 'WRITE_ANY_AWS_RESOURCE',
  );
  const forgedRouteBody = { ...forgedRoute };
  delete forgedRouteBody.planSha256;
  forgedRoute.planSha256 = objectSha256(forgedRouteBody);
  assert.throws(() => validatePublicationRecoveryPlan(forgedRoute));

  const confusedClosure = clone(first);
  confusedClosure.sharedIntegration.stage7GateClaimed = true;
  const confusedClosureBody = { ...confusedClosure };
  delete confusedClosureBody.planSha256;
  confusedClosure.planSha256 = objectSha256(confusedClosureBody);
  assert.throws(() => validatePublicationRecoveryPlan(confusedClosure));

  const postSuccessFixtures = RECOVERY_CRASH_WINDOWS.map((crashWindow) =>
    createPublicationRecoveryPostSuccessFixture({ crashWindow }),
  );
  for (const postSuccess of postSuccessFixtures) {
    const intake = createPublicationRecoveryPostSuccessIntake(postSuccess.intakeArguments);
    assert.equal(intake.status, 'BLOCKED_CLOSEOUT_AUTHORITY');
    assert.equal(intake.source.crashWindow, postSuccess.crashWindow);
    assert.equal(intake.sourceRunConclusionUnchanged, true);
    assert.equal(intake.compositeGateClaimed, false);
    assert.equal(intake.closeoutAuthority.present, false);
    assert.equal(intake.recovery.planArtifactId, '9901');
    assert.equal(intake.recovery.resultArtifactId, '9902');
    if (postSuccess.crashWindow === RECOVERY_CRASH_WINDOWS[2]) {
      assert.equal(postSuccess.receipt.recoveryOperation.externalWritesPerformed, 0);
      assert.equal(
        postSuccess.receipt.recoveryOperation.writeCapability,
        'ABSENT_CONTENTS_READ_JOB',
      );
    }
  }
  const verifyOnlyDirectory = mkdtempSync(path.join(os.tmpdir(), 'e7-publication-no-write-'));
  try {
    const routeC = postSuccessFixtures[2];
    for (const [name, bytes] of Object.entries(routeC.publicationFiles)) {
      writeFileSync(path.join(verifyOnlyDirectory, name), bytes);
    }
    const forgedWriteOperationBody = {
      ...routeC.recoveryOperation,
      externalWritesPerformed: 1,
    };
    delete forgedWriteOperationBody.operationSha256;
    const forgedWriteOperation = {
      ...forgedWriteOperationBody,
      operationSha256: objectSha256(forgedWriteOperationBody),
    };
    assert.throws(() =>
      createPublicationRecoveryReceipt({
        plan: routeC.plan,
        publicationDirectory: verifyOnlyDirectory,
        recoveryOperationSource: jsonBytes(forgedWriteOperation),
        completedAtUtc: '2026-08-18T13:30:00.000Z',
      }),
    );
  } finally {
    rmSync(verifyOnlyDirectory, { recursive: true, force: true });
  }
  const postSuccess = postSuccessFixtures[0];
  const { intakeArguments, recoveryArtifacts, planArchive, resultArchive } = postSuccess;
  for (const maliciousRecoveryRunId of ['7002|9999', '7002.*', '(?:7002)']) {
    assert.throws(
      () =>
        readPublicationRecoveryResultArchive({
          recoveryRunId: maliciousRecoveryRunId,
          recoveryArtifacts,
          planArchive,
          resultArchive,
        }),
      (error) => error?.code === 'E7_PUBLICATION_RECOVERY_RESULT_RUN_INVALID',
    );
  }
  const forgedReceipt = clone(postSuccess.receipt);
  forgedReceipt.stage7GateClaimed = true;
  const forgedReceiptBody = { ...forgedReceipt };
  delete forgedReceiptBody.receiptSha256;
  forgedReceipt.receiptSha256 = objectSha256(forgedReceiptBody);
  assert.throws(() => validatePublicationRecoveryReceipt(forgedReceipt));
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      recoveryRun: { ...intakeArguments.recoveryRun, conclusion: 'failure' },
    }),
  );
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      recoveryArtifacts: { artifacts: [recoveryArtifacts.artifacts[1]] },
    }),
  );
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      recoveryArtifacts: {
        artifacts: [
          ...recoveryArtifacts.artifacts,
          { ...recoveryArtifacts.artifacts[0], id: 9999, name: 'unexpected-recovery-artifact' },
        ],
      },
    }),
  );
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      recoveryArtifacts: {
        artifacts: [
          recoveryArtifacts.artifacts[0],
          { ...recoveryArtifacts.artifacts[1], id: recoveryArtifacts.artifacts[0].id },
        ],
      },
    }),
  );
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      recoveryArtifacts: {
        artifacts: [
          recoveryArtifacts.artifacts[0],
          { ...recoveryArtifacts.artifacts[0], id: 9998 },
        ],
      },
    }),
  );
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      recoveryArtifacts: {
        artifacts: [
          { ...recoveryArtifacts.artifacts[0], workflow_run: undefined },
          recoveryArtifacts.artifacts[1],
        ],
      },
    }),
  );
  const prefixedPlanArchive = createReleaseSuccessorStoredZipFixture({
    'plan/release-successor-completion-fence.json': postSuccess.fenceSource,
    'plan/release-successor-publication-recovery-plan.json': postSuccess.planSource,
  });
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      planArchive: prefixedPlanArchive,
      recoveryArtifacts: {
        artifacts: [
          {
            ...recoveryArtifacts.artifacts[0],
            digest: `sha256:${sha256(prefixedPlanArchive)}`,
          },
          recoveryArtifacts.artifacts[1],
        ],
      },
    }),
  );
  const mismatchedPlanSource = Buffer.from(`${postSuccess.planSource.toString('utf8').trim()} \n`);
  const mismatchedPlanArchive = createReleaseSuccessorStoredZipFixture({
    'release-successor-completion-fence.json': postSuccess.fenceSource,
    'release-successor-publication-recovery-plan.json': mismatchedPlanSource,
  });
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      planArchive: mismatchedPlanArchive,
      recoveryArtifacts: {
        artifacts: [
          {
            ...recoveryArtifacts.artifacts[0],
            digest: `sha256:${sha256(mismatchedPlanArchive)}`,
          },
          recoveryArtifacts.artifacts[1],
        ],
      },
    }),
  );
  const tamperedResultArchive = Buffer.from(resultArchive);
  tamperedResultArchive[10] ^= 1;
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      resultArchive: tamperedResultArchive,
    }),
  );
  const tamperedPlanArchive = Buffer.from(planArchive);
  tamperedPlanArchive[10] ^= 1;
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...intakeArguments,
      planArchive: tamperedPlanArchive,
    }),
  );
  const routeCPostSuccess = postSuccessFixtures[2];
  const mismatchedSourcePublicationArchive = createReleaseSuccessorStoredZipFixture({
    'release-successor-completion-fence.json': routeCPostSuccess.fenceSource,
    'release-successor-publication-recovery-plan.json': routeCPostSuccess.planSource,
    'release-successor-publication-recovery-receipt.json': routeCPostSuccess.receiptSource,
    ...routeCPostSuccess.publicationFiles,
    'publication.json': Buffer.from(
      `${routeCPostSuccess.publicationFiles['publication.json'].toString('utf8').trim()} \n`,
    ),
  });
  assert.throws(() =>
    createPublicationRecoveryPostSuccessIntake({
      ...routeCPostSuccess.intakeArguments,
      resultArchive: mismatchedSourcePublicationArchive,
      recoveryArtifacts: {
        artifacts: [
          routeCPostSuccess.recoveryArtifacts.artifacts[0],
          {
            ...routeCPostSuccess.recoveryArtifacts.artifacts[1],
            digest: `sha256:${sha256(mismatchedSourcePublicationArchive)}`,
          },
        ],
      },
    }),
  );

  const schema = JSON.parse(
    readFileSync(
      path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        'release-successor-publication-recovery.schema.json',
      ),
      'utf8',
    ),
  );
  assert.equal(schema.oneOf.length, 4);
  assert.equal(schema.$defs.authority.additionalProperties, false);
  assert.equal(schema.$defs.plan.additionalProperties, false);
  assert.equal(schema.$defs.receipt.additionalProperties, false);
  assert.equal(schema.$defs.postSuccessIntake.additionalProperties, false);
  assert.equal(schema.$defs.plan.properties.artifactInventory.properties.requiredCount.const, 27);

  return {
    status: 'PASS',
    canaries: 47,
    sourceArtifacts: RECOVERY_SOURCE_ARTIFACTS.length,
    externalRequests: 0,
    awsMutations: 0,
    githubMutations: 0,
  };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const result = selfTestPublicationRecovery();
  process.stdout.write(
    `release-successor publication recovery: PASS (${result.canaries} canaries; ` +
      `${result.sourceArtifacts} source artifacts; 0 external requests; 0 mutations)\n`,
  );
}
