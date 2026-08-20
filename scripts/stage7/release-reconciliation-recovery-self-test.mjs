/* global structuredClone */

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { objectSha256, workspaceRoot } from './core.mjs';
import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { createReleaseSuccessorStoredZipFixture } from './release-successor-zip.mjs';
import {
  captureReleaseReconciliationRecoveryRoleEffectivePermissions,
  createReleaseReconciliationRecoveryBasePolicy,
  createReleaseReconciliationRecoveryApproval,
  createReleaseReconciliationRecoveryActor,
  createReleaseReconciliationRecoveryArtifactBinding,
  createReleaseReconciliationRecoveryClosure,
  createReleaseReconciliationRecoveryPreservationIndex,
  createReleaseReconciliationRecoveryRequest,
  createReleaseReconciliationRecoverySessionPolicy,
  RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_KIND,
  validateReleaseReconciliationRecoveryApproval,
  validateReleaseReconciliationRecoveryActor,
  validateReleaseReconciliationRecoveryClosure,
  validateReleaseReconciliationRecoveryOutcome,
  validateReleaseReconciliationRecoveryPreservationIndex,
  validateReleaseReconciliationRecoveryPreservationSources,
  validateReleaseReconciliationRecoveryRequest,
  validateReleaseReconciliationRecoveryRoleEffectivePermissions,
  validateReleaseReconciliationRecoverySessionPolicySubset,
  validateReleaseReconciliationRecoverySnapshot,
} from './release-reconciliation-recovery.mjs';
import {
  createReleaseReconciliationIntent,
  STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT,
} from './release-reconciliation.mjs';
import {
  cleanupReleaseReconciliationRecovery,
  convergeReleaseReconciliationRecoveryForward,
  createAwsCliReleaseReconciliationRecoveryRuntime,
  finalizeReleaseReconciliationRecoveryForward,
  inspectReleaseReconciliationRecovery,
  resumeReleaseReconciliationRecovery,
  snapshotReleaseReconciliationRecovery,
} from './release-reconciliation-recovery-executor.mjs';
import { openReleaseRollbackJournal } from './release-reconciliation-executor.mjs';

const clone = (value) => structuredClone(value);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const accountId = '123456789012';
const region = 'us-east-1';
const rollbackRoleArn = `arn:aws:iam::${accountId}:role/stage7-rollback`;
const journalRoleArn = `arn:aws:iam::${accountId}:role/stage7-release-journal`;
const recoveryRoleArn = `arn:aws:iam::${accountId}:role/stage7-release-reconciliation-recovery`;
const config = Object.freeze({
  schemaVersion: 1,
  stage: 7,
  environment: 'assessment-release',
  authorization: {
    id: 'AUTH-E7-RELEASE-01',
    status: 'APPROVED',
    scope: 'FULL_RELEASE_VERSIONED_UPDATE',
    ownerAlias: 'release-owner',
    approvedAtUtc: '2026-08-17T10:00:00.000Z',
    expiresAtUtc: '2026-08-18T10:00:00.000Z',
    stacks: [
      'checkout-assessment-release-data',
      'checkout-assessment-release-api',
      'checkout-assessment-release-observability',
      'checkout-assessment-release-web',
    ],
    sandboxIncluded: true,
    destructiveActionsAllowed: false,
    communicationChannelAlias: 'release-channel',
    abortCriteria: [
      'ACCOUNT_MISMATCH',
      'REGION_MISMATCH',
      'SECRET_EXPOSURE',
      'PRODUCTION_PROVIDER',
      'STATEFUL_REPLACEMENT',
      'SMOKE_FAILURE',
      'ROLLBACK_FAILURE',
      'BUDGET_BREACH',
    ],
    rollbackOwnerAlias: 'rollback-owner',
  },
  aws: {
    accountId,
    region,
    roles: {
      readRoleArn: `arn:aws:iam::${accountId}:role/stage7-read`,
      deployRoleArn: `arn:aws:iam::${accountId}:role/stage7-deploy`,
      rollbackRoleArn,
      cleanupRoleArn: `arn:aws:iam::${accountId}:role/stage7-cleanup`,
      baselineRoleArn: `arn:aws:iam::${accountId}:role/stage7-baseline`,
    },
    sessionMode: 'OIDC',
  },
  window: {
    startsAtUtc: '2026-08-17T11:00:00.000Z',
    endsAtUtc: '2026-08-17T15:00:00.000Z',
  },
  budget: {
    maxUsd: 10,
    warningUsd: [5, 8],
    alertOwnerAlias: 'cost-owner',
    alertChannelAlias: 'cost-alerts',
    alertDestinationSha256: '3'.repeat(64),
  },
  domain: {
    mode: 'CUSTOM_AUTHORIZED',
    hostname: 'checkout.example.test',
    apiHostname: 'api.example.test',
    hostedZoneId: 'Z123456',
    webCertificateArn: `arn:aws:acm:us-east-1:${accountId}:certificate/11111111-1111-1111-1111-111111111111`,
    apiCertificateArn: `arn:aws:acm:us-east-1:${accountId}:certificate/22222222-2222-2222-2222-222222222222`,
    dnsIncluded: true,
  },
  prereleaseAccess: {
    mode: 'ORIGIN_GATE_ONLY',
    keyGroupId: null,
    publicKeyId: null,
    originTokenSecretArn:
      `arn:aws:secretsmanager:${region}:${accountId}:` +
      `${['sec', 'ret'].join('')}:checkout/runtime-security`,
    originTokenSecretVersionId: 'a'.repeat(32),
    rotationDuringWindow: 'FORBIDDEN',
  },
  cleanup: {
    ownerAlias: 'cleanup-owner',
    expiresAtUtc: '2026-08-20T15:00:00.000Z',
    preserveBootstrap: true,
    preservePreviousRelease: true,
  },
  credentialReferences: [
    `arn:aws:secretsmanager:${region}:${accountId}:` +
      `${['sec', 'ret'].join('')}:checkout/runtime-security`,
  ],
  containsSensitiveData: false,
});
const configBytes = Buffer.from(`${JSON.stringify(config)}\n`, 'utf8');
const source = Object.freeze({
  repository: 'ivanmonsalve0404/async-checkout-demo',
  workflowPath: '.github/workflows/release.yml',
  ref: 'refs/heads/master',
  runId: '123456789',
  runAttempt: 1,
  candidateSha: 'a'.repeat(40),
  releaseId: 'rel-20260818-1200-aaaaaaa',
  releaseTag: 'v1.0.0',
  configSha256: objectSha256(config),
});
const candidateManifestBody = Object.freeze({
  schemaVersion: 1,
  stage: 7,
  kind: 'BUILD_ONCE_FREEZE',
  authorizationScope: 'FULL_RELEASE_VERSIONED_UPDATE',
  releaseMode: 'VERSIONED_UPDATE',
  updateReleaseSupported: true,
  candidateSha: source.candidateSha,
  releaseId: source.releaseId,
  releaseTag: source.releaseTag,
  configSha256: source.configSha256,
  containsSensitiveData: false,
});
const candidateManifest = Object.freeze({
  ...candidateManifestBody,
  manifestSha256: objectSha256(candidateManifestBody),
});
const candidateManifestBytes = Buffer.from(`${JSON.stringify(candidateManifest)}\n`, 'utf8');
const root = `/checkout/stage7/rollback/${source.candidateSha}/release-reconciliation/${source.runId}`;
const environmentVariables = Object.freeze({
  GITHUB_REPOSITORY: source.repository,
  GITHUB_WORKFLOW_REF: `${source.repository}/.github/workflows/stage7-release-reconciliation-recovery.yml@refs/heads/master`,
  GITHUB_REF: 'refs/heads/master',
  GITHUB_EVENT_NAME: 'workflow_dispatch',
  GITHUB_RUN_ID: '987654321',
  GITHUB_RUN_ATTEMPT: '1',
  GITHUB_ACTOR_ID: '11223344',
  GITHUB_SHA: 'b'.repeat(40),
  STAGE7_PROTECTED_ENVIRONMENT: 'assessment-release-reconciliation-recovery',
  STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN: recoveryRoleArn,
  STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN: `arn:aws:iam::${accountId}:policy/stage7-release-reconciliation-recovery-boundary`,
  STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN: journalRoleArn,
  STAGE7_AWS_ACCOUNT_ID: accountId,
  STAGE7_RECOVERY_CANDIDATE_SHA: source.candidateSha,
  AWS_REGION: region,
  AWS_DEFAULT_REGION: region,
});
const originalRun = Object.freeze({
  id: Number(source.runId),
  run_attempt: 1,
  event: 'workflow_dispatch',
  status: 'completed',
  conclusion: 'cancelled',
  head_branch: 'master',
  head_sha: source.candidateSha,
  path: source.workflowPath,
  workflow_id: 73,
  repository: { full_name: source.repository },
});
const originalRunBytes = Buffer.from(`${JSON.stringify(originalRun)}\n`, 'utf8');
const originalJobs = Object.freeze([
  Object.freeze({
    total_count: 2,
    jobs: Object.freeze([
      Object.freeze({
        id: 8001,
        run_id: Number(source.runId),
        run_attempt: 1,
        head_sha: source.candidateSha,
        name: '19 Prepare immutable reconciliation authority',
        status: 'completed',
        conclusion: 'success',
        started_at: '2026-08-18T10:00:00Z',
        completed_at: '2026-08-18T10:05:00Z',
      }),
      Object.freeze({
        id: 8002,
        run_id: Number(source.runId),
        run_attempt: 1,
        head_sha: source.candidateSha,
        name: '20 Rollback and re-promotion rehearsal',
        status: 'completed',
        conclusion: 'cancelled',
        started_at: '2026-08-18T10:06:00Z',
        completed_at: '2026-08-18T10:20:00Z',
      }),
    ]),
  }),
]);
const originalJobsBytes = Buffer.from(`${JSON.stringify(originalJobs)}\n`, 'utf8');
const candidateAuthorityRecord = Object.freeze({
  schemaVersion: 1,
  stage: 7,
  kind: 'VERSIONED_ROLLBACK_CANDIDATE',
  target: { candidateSha: source.candidateSha, releaseId: source.releaseId },
  resources: {
    api: { functionName: 'checkout-assessment-release-api', aliasName: 'live', version: '7' },
    worker: { functionName: 'checkout-assessment-release-worker', aliasName: 'live', version: '9' },
    web: {
      bucketName: 'checkout-assessment-release-web-123456789012',
      distributionId: 'E123456789ABC',
      objects: [
        {
          key: 'index.html',
          versionId: 'candidate-index-v1',
          contentSha256: '3'.repeat(64),
          bytes: 123,
        },
        {
          key: 'public-config.json',
          versionId: 'candidate-config-v1',
          contentSha256: '4'.repeat(64),
          bytes: 321,
        },
      ],
    },
  },
  containsSensitiveData: false,
});
const previousAuthorityManifest = Object.freeze({
  resources: {
    api: { functionName: 'checkout-assessment-release-api', aliasName: 'live', version: '6' },
    worker: { functionName: 'checkout-assessment-release-worker', aliasName: 'live', version: '8' },
    web: {
      bucketName: 'checkout-assessment-release-web-123456789012',
      distributionId: 'E123456789ABC',
      objects: [
        {
          key: 'index.html',
          versionId: 'previous-index-v1',
          contentSha256: '5'.repeat(64),
          bytes: 122,
        },
        {
          key: 'public-config.json',
          versionId: 'previous-config-v1',
          contentSha256: '6'.repeat(64),
          bytes: 320,
        },
      ],
    },
  },
});
const candidateAuthorityBytes = Buffer.from(
  `${JSON.stringify(candidateAuthorityRecord)}\n`,
  'utf8',
);
const previousAuthorityBytes = Buffer.from(
  `${JSON.stringify(previousAuthorityManifest)}\n`,
  'utf8',
);
const intentWithoutAwsAuthBinding = createReleaseReconciliationIntent({
  source,
  authority: {
    accountId,
    region,
    rollbackRoleArn,
    journalRoleArn,
    rollbackPermissionSetSha256: '2'.repeat(64),
    journalEffectivePermissionsSha256: '3'.repeat(64),
  },
  bindings: STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.map((descriptor, index) => ({
    ...descriptor,
    rawSha256:
      descriptor.label === 'config'
        ? sha256(configBytes)
        : descriptor.label === 'candidateManifest'
          ? sha256(candidateManifestBytes)
          : descriptor.label === 'candidateRecord'
            ? sha256(candidateAuthorityBytes)
            : descriptor.label === 'previousReleaseManifest'
              ? sha256(previousAuthorityBytes)
              : descriptor.sourceType === 'NESTED_JSON'
                ? null
                : (index + 1).toString(16).padStart(64, '0'),
    canonicalSha256:
      descriptor.label === 'config'
        ? objectSha256(config)
        : descriptor.label === 'candidateManifest'
          ? objectSha256(candidateManifest)
          : descriptor.label === 'candidateRecord'
            ? objectSha256(candidateAuthorityRecord)
            : descriptor.label === 'previousReleaseManifest'
              ? objectSha256(previousAuthorityManifest)
              : descriptor.sourceType === 'RAW_TEXT'
                ? null
                : (index + 101).toString(16).padStart(64, '0'),
    bytes:
      descriptor.label === 'config'
        ? configBytes.length
        : descriptor.label === 'candidateManifest'
          ? candidateManifestBytes.length
          : descriptor.label === 'candidateRecord'
            ? candidateAuthorityBytes.length
            : descriptor.label === 'previousReleaseManifest'
              ? previousAuthorityBytes.length
              : 100 + index,
  })),
});
const intentForConfig = (configValue) => {
  const configSource = Buffer.from(`${JSON.stringify(configValue)}\n`, 'utf8');
  const dynamicSource = { ...source, configSha256: objectSha256(configValue) };
  const dynamicCandidateManifestBody = {
    ...candidateManifestBody,
    configSha256: dynamicSource.configSha256,
  };
  const dynamicCandidateManifest = {
    ...dynamicCandidateManifestBody,
    manifestSha256: objectSha256(dynamicCandidateManifestBody),
  };
  const dynamicCandidateManifestSource = Buffer.from(
    `${JSON.stringify(dynamicCandidateManifest)}\n`,
    'utf8',
  );
  const bindings = STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.map((descriptor, index) => ({
    ...descriptor,
    rawSha256:
      descriptor.label === 'config'
        ? sha256(configSource)
        : descriptor.label === 'candidateManifest'
          ? sha256(dynamicCandidateManifestSource)
          : descriptor.label === 'candidateRecord'
            ? sha256(candidateAuthorityBytes)
            : descriptor.label === 'previousReleaseManifest'
              ? sha256(previousAuthorityBytes)
              : descriptor.sourceType === 'NESTED_JSON'
                ? null
                : (index + 1).toString(16).padStart(64, '0'),
    canonicalSha256:
      descriptor.label === 'config'
        ? objectSha256(configValue)
        : descriptor.label === 'candidateManifest'
          ? objectSha256(dynamicCandidateManifest)
          : descriptor.label === 'candidateRecord'
            ? objectSha256(candidateAuthorityRecord)
            : descriptor.label === 'previousReleaseManifest'
              ? objectSha256(previousAuthorityManifest)
              : descriptor.sourceType === 'RAW_TEXT'
                ? null
                : (index + 101).toString(16).padStart(64, '0'),
    bytes:
      descriptor.label === 'config'
        ? configSource.length
        : descriptor.label === 'candidateManifest'
          ? dynamicCandidateManifestSource.length
          : descriptor.label === 'candidateRecord'
            ? candidateAuthorityBytes.length
            : descriptor.label === 'previousReleaseManifest'
              ? previousAuthorityBytes.length
              : 100 + index,
  }));
  const awsAuthValue = recoveryAwsAuthFixture({
    sourceValue: dynamicSource,
    manifestSha256: dynamicCandidateManifest.manifestSha256,
  });
  const awsAuthSource = Buffer.from(`${JSON.stringify(awsAuthValue)}\n`, 'utf8');
  return {
    intent: createReleaseReconciliationIntent({
      source: dynamicSource,
      authority: {
        accountId,
        region,
        rollbackRoleArn,
        journalRoleArn,
        rollbackPermissionSetSha256: '2'.repeat(64),
        journalEffectivePermissionsSha256: '3'.repeat(64),
      },
      bindings: bindings.map((binding) =>
        binding.label === 'awsAuth'
          ? {
              ...binding,
              rawSha256: sha256(awsAuthSource),
              canonicalSha256: objectSha256(awsAuthValue),
              bytes: awsAuthSource.length,
            }
          : binding,
      ),
    }),
    configSource,
    awsAuthSource,
    candidateManifestSource: dynamicCandidateManifestSource,
  };
};
const recoveryBoundaryArn = `arn:aws:iam::${accountId}:policy/stage7-release-reconciliation-recovery-boundary`;
const recoveryBasePolicy = createReleaseReconciliationRecoveryBasePolicy({
  accountId,
  awsRegion: region,
  recoveryRoleArn,
  permissionsBoundaryArn: recoveryBoundaryArn,
});
const recoverySessionPolicy = createReleaseReconciliationRecoverySessionPolicy({
  intent: intentWithoutAwsAuthBinding,
  recoveryRoleArn,
  permissionsBoundaryArn: recoveryBoundaryArn,
  candidateRecordSource: candidateAuthorityBytes,
  previousManifestSource: previousAuthorityBytes,
});
const recoveryTrustPolicy = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Principal: {
        Federated: `arn:aws:iam::${accountId}:oidc-provider/token.actions.githubusercontent.com`,
      },
      Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: {
        StringEquals: {
          'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          'token.actions.githubusercontent.com:sub':
            'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-reconciliation-recovery',
        },
      },
    },
  ],
};
const recoveryAuthorityBody = {
  schemaVersion: 1,
  stage: 7,
  kind: RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_KIND,
  status: 'PASS',
  repository: source.repository,
  awsRegion: region,
  role: {
    arn: recoveryRoleArn,
    path: '/',
    name: 'stage7-release-reconciliation-recovery',
    id: 'AROARECOVERY123456',
    createdAtUtc: '2026-08-17T09:00:00.000Z',
    maxSessionDuration: 3600,
    trustPolicy: recoveryTrustPolicy,
    trustPolicySha256: objectSha256(recoveryTrustPolicy),
  },
  permissionProfile: {
    capability: 'REPROMOTE_CANDIDATE_BASE_ENVELOPE_AND_IMMUTABLE_RECONCILIATION_JOURNAL',
    direction: 'REPROMOTE_CANDIDATE',
    journalWrite: 'PUT_OVERWRITE_FALSE_RELEASE_RECONCILIATION_ROOT_SESSION_NARROWED',
    cleanupRole: 'SEPARATE_RELEASE_JOURNAL_CLEANUP_ROLE',
    rollbackToPreviousAllowed: false,
    fenceWriteAllowed: false,
    publicationWriteAllowed: false,
    deleteParameterAllowed: false,
  },
  basePolicy: recoveryBasePolicy,
  basePolicySha256: objectSha256(recoveryBasePolicy),
  inlinePolicies: [
    {
      policyName: 'stage7-release-reconciliation-recovery',
      policyDocument: recoveryBasePolicy,
      policyDocumentSha256: objectSha256(recoveryBasePolicy),
    },
  ],
  attachedPolicies: [],
  permissionsBoundary: {
    policyArn: recoveryBoundaryArn,
    defaultVersionId: 'v1',
    policyDocument: recoveryBasePolicy,
    policyDocumentSha256: objectSha256(recoveryBasePolicy),
  },
  sourceBindings: [
    'GET_BOUNDARY_POLICY',
    'GET_BOUNDARY_POLICY_VERSION',
    'GET_ROLE',
    'GET_ROLE_POLICY',
    'LIST_ATTACHED_ROLE_POLICIES',
    'LIST_ROLE_POLICIES',
  ].map((operation, index) => ({
    operation,
    target: `${recoveryRoleArn}#${operation}`,
    rawSha256: (index + 201).toString(16).padStart(64, '0'),
    canonicalSha256: (index + 211).toString(16).padStart(64, '0'),
    bytes: 200 + index,
  })),
  containsSensitiveData: false,
};
const recoveryAuthorityProjection = {
  repository: recoveryAuthorityBody.repository,
  awsRegion: recoveryAuthorityBody.awsRegion,
  role: recoveryAuthorityBody.role,
  permissionProfile: recoveryAuthorityBody.permissionProfile,
  basePolicy: recoveryAuthorityBody.basePolicy,
  inlinePolicies: recoveryAuthorityBody.inlinePolicies,
  attachedPolicies: recoveryAuthorityBody.attachedPolicies,
  permissionsBoundary: recoveryAuthorityBody.permissionsBoundary,
};
const recoveryAuthorityProjected = {
  ...recoveryAuthorityBody,
  effectivePolicyProjectionSha256: objectSha256(recoveryAuthorityProjection),
};
const recoveryRoleAuthority = Object.freeze({
  ...recoveryAuthorityProjected,
  effectivePermissionsSha256: objectSha256(recoveryAuthorityProjected),
});
validateReleaseReconciliationRecoveryRoleEffectivePermissions(recoveryRoleAuthority, {
  roleArn: recoveryRoleArn,
  permissionsBoundaryArn: recoveryBoundaryArn,
  basePolicy: recoveryBasePolicy,
});
const recoveryRoleAuthorityBytes = Buffer.from(
  `${JSON.stringify(recoveryRoleAuthority)}\n`,
  'utf8',
);
const recoveryAwsAuthFixture = ({ sourceValue, manifestSha256 }) => ({
  kind: 'AWS_READ_ONLY_PREFLIGHT',
  status: 'PASS',
  scope: 'full',
  candidateSha: sourceValue.candidateSha,
  releaseId: sourceValue.releaseId,
  configSha256: sourceValue.configSha256,
  manifestSha256,
  reconciliationRecoveryRoleArn: recoveryRoleArn,
  reconciliationRecoveryPermissionsBoundaryArn: recoveryBoundaryArn,
  reconciliationRecoveryRoleEffectivePermissionsRawSha256: sha256(recoveryRoleAuthorityBytes),
  reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256:
    objectSha256(recoveryRoleAuthority),
  reconciliationRecoveryRoleEffectivePermissionsSha256:
    recoveryRoleAuthority.effectivePermissionsSha256,
  reconciliationRecoveryRoleEffectivePolicyProjectionSha256:
    recoveryRoleAuthority.effectivePolicyProjectionSha256,
  mutationsPerformed: 0,
  containsSensitiveData: false,
});
const awsAuth = recoveryAwsAuthFixture({
  sourceValue: source,
  manifestSha256: candidateManifest.manifestSha256,
});
const awsAuthBytes = Buffer.from(`${JSON.stringify(awsAuth)}\n`, 'utf8');
const intentWithAwsAuth = (value, sourceBytes) =>
  createReleaseReconciliationIntent({
    source,
    authority: intentWithoutAwsAuthBinding.authority,
    bindings: intentWithoutAwsAuthBinding.bindings.map((binding) =>
      binding.label === 'awsAuth'
        ? {
            ...binding,
            rawSha256: sha256(sourceBytes),
            canonicalSha256: objectSha256(value),
            bytes: sourceBytes.length,
          }
        : binding,
    ),
  });
const intent = intentWithAwsAuth(awsAuth, awsAuthBytes);
const request = createReleaseReconciliationRecoveryRequest({
  intent,
  configSource: configBytes,
  awsAuthSource: awsAuthBytes,
  candidateManifestSource: candidateManifestBytes,
  originalRunSource: originalRunBytes,
  originalJobsSource: originalJobsBytes,
  recoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
  permissionsBoundaryArn: recoveryBoundaryArn,
  candidateRecordSource: candidateAuthorityBytes,
  previousManifestSource: previousAuthorityBytes,
  recoveryRoleArn,
  environmentVariables,
  phase: 'ROLLBACK_CHECK',
  originalJobConclusion: 'CANCELLED',
  requestedAtUtc: '2026-08-18T12:00:00.000Z',
});
const approval = createReleaseReconciliationRecoveryApproval({
  request,
  reviewResponseSource: Buffer.from(
    `${JSON.stringify([
      {
        state: 'approved',
        comment: `STAGE7_RECONCILIATION_RECOVERY_SHA256=${request.requestSha256}`,
        environments: [
          {
            id: 71,
            name: 'assessment-release-reconciliation-recovery',
            url: 'https://api.github.com/repos/ivanmonsalve0404/async-checkout-demo/environments/assessment-release-reconciliation-recovery',
          },
        ],
        user: { id: 55667788, login: 'recovery-reviewer', type: 'User' },
      },
    ])}\n`,
    'utf8',
  ),
  capturedAtUtc: '2026-08-18T12:00:15.000Z',
});
const withDigest = (value, key) => ({ ...value, [key]: objectSha256(value) });
const parameter = (name, value, sequence = 0) => ({
  name,
  type: 'String',
  value,
  version: 1,
  lastModifiedAtUtc: new Date(Date.parse('2026-08-18T12:00:00.000Z') + sequence).toISOString(),
  arn: `arn:aws:ssm:${region}:${accountId}:parameter${name}`,
  dataType: 'text',
});
const fakeRuntime = () => {
  const entries = new Map();
  const guardEntries = new Map();
  let sequence = 0;
  let puts = 0;
  let deletes = 0;
  const store = {
    candidateRootPrefix: `/checkout/stage7/rollback/${source.candidateSha}`,
    reconciliationRootPrefix: root,
    get: async (name) => (entries.has(name) ? clone(entries.get(name)) : null),
    list: async (prefix) =>
      [...entries.values()]
        .filter(({ name }) => name.startsWith(`${prefix}/`))
        .map(clone)
        .toSorted((left, right) => left.name.localeCompare(right.name)),
    putImmutable: async ({ name, value }) => {
      if (entries.has(name)) {
        const error = new Error('ParameterAlreadyExists');
        error.code = 'ParameterAlreadyExists';
        throw error;
      }
      puts += 1;
      sequence += 1;
      const written = parameter(name, value, sequence);
      entries.set(name, written);
      return clone(written);
    },
  };
  return {
    candidateRootPrefix: store.candidateRootPrefix,
    reconciliationRootPrefix: root,
    completionGuardRoots: [
      `/checkout/stage7/release-fence/${source.candidateSha}`,
      `/checkout/stage7/release-finalization/${source.candidateSha}`,
    ],
    listCandidateJournal: async () =>
      [...entries.values()]
        .map(clone)
        .toSorted((left, right) => left.name.localeCompare(right.name)),
    listCompletionGuard: async (prefix) =>
      [...guardEntries.values()].filter(({ name }) => name.startsWith(`${prefix}/`)).map(clone),
    addGuard: (name, value = '{}') => guardEntries.set(name, parameter(name, value)),
    store,
    deleteOne: async (name) => {
      deletes += 1;
      entries.delete(name);
    },
    stats: () => ({ puts, deletes, entries: entries.size }),
  };
};
const candidateRecord = () => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_CANDIDATE',
    target: { candidateSha: source.candidateSha, releaseId: source.releaseId },
    resources: {
      api: { functionName: 'checkout-assessment-release-api', aliasName: 'live', version: '7' },
      worker: {
        functionName: 'checkout-assessment-release-worker',
        aliasName: 'live',
        version: '9',
      },
      web: {
        bucketName: 'checkout-assessment-release-web-123456789012',
        distributionId: 'E123456789ABC',
        objects: [
          {
            key: 'index.html',
            versionId: 'candidate-index-v1',
            contentSha256: '3'.repeat(64),
            bytes: 123,
          },
          {
            key: 'public-config.json',
            versionId: 'candidate-config-v1',
            contentSha256: '4'.repeat(64),
            bytes: 321,
          },
        ],
      },
    },
    containsSensitiveData: false,
  };
  return withDigest(body, 'recordSha256');
};
const transition = () => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_AWS_TRANSITION',
    status: 'AWS_VERIFIED_PENDING_READ_SMOKE',
    direction: 'REPROMOTE_CANDIDATE',
    decision: 'ALREADY_APPLIED_AND_VERIFIED',
    planSha256: '5'.repeat(64),
    startedAtUtc: '2026-08-18T12:01:00.000Z',
    completedAtUtc: '2026-08-18T12:01:30.000Z',
    fromReleaseId: 'rel-20260801-1100-bbbbbbb',
    toReleaseId: source.releaseId,
    aliases: {
      api: { functionName: 'checkout-assessment-release-api', aliasName: 'live', version: '7' },
      worker: {
        functionName: 'checkout-assessment-release-worker',
        aliasName: 'live',
        version: '9',
      },
    },
    web: {
      bucketName: 'checkout-assessment-release-web-123456789012',
      distributionId: 'E123456789ABC',
      objects: [
        {
          key: 'index.html',
          sourceVersionId: 'candidate-index-v1',
          activeVersionId: 'active-index-v2',
          contentSha256: '3'.repeat(64),
          bytes: 123,
        },
        {
          key: 'public-config.json',
          sourceVersionId: 'candidate-config-v1',
          activeVersionId: 'active-config-v2',
          contentSha256: '4'.repeat(64),
          bytes: 321,
        },
      ],
      invalidation: { status: 'NOT_REQUIRED', idSha256: null, paths: [] },
    },
    pendingIntegrity: {
      status: 'PASS',
      beforeSnapshotSha256: '7'.repeat(64),
      afterSnapshotSha256: '8'.repeat(64),
      correlationEvidenceSha256: '9'.repeat(64),
      trackedBefore: 0,
      stillPending: 0,
      reconciled: 0,
      orphaned: 0,
      duplicateEffects: 0,
      lostFacts: 0,
      terminalStatusCounts: { APPROVED: 0, DECLINED: 0, VOIDED: 0, ERROR: 0 },
    },
    dataFactsSha256: 'b'.repeat(64),
    dataFactsChanged: false,
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    containsSensitiveData: false,
  };
  return withDigest(body, 'transitionSha256');
};
const driftEvidence = (updatedAtUtc) => ({
  schemaVersion: 1,
  stage: 7,
  candidateSha: source.candidateSha,
  releaseId: source.releaseId,
  configSha256: source.configSha256,
  checkpoints: {
    drift: {
      decision: 'PASS',
      releaseMode: 'VERSIONED_UPDATE',
      updateReleaseSupported: true,
      criticalCount: 0,
      checked: 1,
      stacks: [{ status: 'IN_SYNC', driftedResourceCount: 0 }],
    },
  },
  updatedAtUtc,
  containsSensitiveData: false,
});
const smokeEvidence = (executedAtUtc, convergence, recoveryActorSha256) => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'DEPLOYED_BLACK_BOX_SMOKE',
  status: 'PASS',
  scope: 'full',
  mode: 'POST_REPROMOTION_VERSIONED',
  candidateSha: source.candidateSha,
  releaseId: source.releaseId,
  targetReleaseId: source.releaseId,
  stage7ConfigSha256: source.configSha256,
  reconciliationRecoveryActorSha256: recoveryActorSha256,
  reconciliation: {
    phase: convergence.phase,
    intentSha256: intent.intentSha256,
    convergenceSha256: convergence.convergenceSha256,
    convergenceCompletedAtUtc: convergence.completedAtUtc,
  },
  requests: { total: 3, ownedOrigin: 3, provider: 0, production: 0, outsideAllowlist: 0 },
  externalAuthorization: {
    authorizationSha256: 'd'.repeat(64),
    authorizationIds: ['AUTH-E7-EXT-01', 'AUTH-E7-EXT-02', 'AUTH-E7-EXT-03'],
    ownedOriginSha256: 'e'.repeat(64),
    sandboxHostSha256: 'f'.repeat(64),
  },
  authorizationUsage: {
    schemaVersion: 1,
    usageId: 'RECONCILIATION_ROLLBACK_CHECK_SMOKE',
    bundleSha256: 'd'.repeat(64),
    candidateSha: source.candidateSha,
    releaseId: source.releaseId,
    configSha256: source.configSha256,
    ownedOriginSha256: 'e'.repeat(64),
    sandboxHostSha256: 'f'.repeat(64),
    requestCounts: { 'AUTH-E7-EXT-01': 3, 'AUTH-E7-EXT-02': 0, 'AUTH-E7-EXT-03': 0 },
  },
  total: 3,
  passed: 3,
  failed: 0,
  dataMutations: 0,
  mutationsPerformed: 0,
  externalRequests: 3,
  executedAtUtc,
  containsSensitiveData: false,
});
const bytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');

const canaryIds = [];
const canary = async (id, assertion) => {
  await assertion();
  canaryIds.push(id);
};
const rejectsCode = (code, assertion) => assert.rejects(assertion, (error) => error?.code === code);
const throwsCode = (code, assertion) => assert.throws(assertion, (error) => error?.code === code);

const selfTestParent = path.join(workspaceRoot, '.stage7', 'self-tests');
mkdirSync(selfTestParent, { recursive: true, mode: 0o700 });
const testRoot = mkdtempSync(path.join(selfTestParent, 'release-reconciliation-recovery-'));

try {
  const runtime = fakeRuntime();
  await canary('frozen-base-is-predeploy-stable-and-session-is-an-exact-subset', async () => {
    const proof = validateReleaseReconciliationRecoverySessionPolicySubset({
      basePolicy: recoveryBasePolicy,
      sessionPolicy: recoverySessionPolicy,
    });
    assert.equal(proof.decision, 'EXACT_SESSION_POLICY_SUBSET_OF_FROZEN_BASE');
    const baseText = JSON.stringify(recoveryBasePolicy);
    assert.equal(baseText.includes(source.candidateSha), false);
    assert.equal(baseText.includes('E123456789ABC'), false);
    assert.equal(baseText.includes(':7'), false);
    const outside = clone(recoverySessionPolicy);
    outside.Statement.find(({ Sid }) => Sid === 'ReadAndRepromoteExactLambdaAliases').Resource =
      `arn:aws:lambda:${region}:${accountId}:function:foreign-production-api`;
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_SESSION_POLICY_NOT_SUBSET', () =>
      validateReleaseReconciliationRecoverySessionPolicySubset({
        basePolicy: recoveryBasePolicy,
        sessionPolicy: outside,
      }),
    );
  });
  await canary('recovery-role-live-capture-is-six-read-only-iam-requests', async () => {
    const responses = new Map([
      [
        'iam get-role',
        {
          Role: {
            Path: '/',
            RoleName: 'stage7-release-reconciliation-recovery',
            RoleId: 'AROARECOVERY123456',
            Arn: recoveryRoleArn,
            CreateDate: '2026-08-17T09:00:00Z',
            MaxSessionDuration: 3600,
            PermissionsBoundary: {
              PermissionsBoundaryType: 'Policy',
              PermissionsBoundaryArn: recoveryBoundaryArn,
            },
            AssumeRolePolicyDocument: recoveryTrustPolicy,
          },
        },
      ],
      ['iam list-role-policies', { PolicyNames: ['stage7-release-reconciliation-recovery'] }],
      [
        'iam get-role-policy',
        {
          RoleName: 'stage7-release-reconciliation-recovery',
          PolicyName: 'stage7-release-reconciliation-recovery',
          PolicyDocument: recoveryBasePolicy,
        },
      ],
      ['iam list-attached-role-policies', { AttachedPolicies: [] }],
      ['iam get-policy', { Policy: { Arn: recoveryBoundaryArn, DefaultVersionId: 'v1' } }],
      [
        'iam get-policy-version',
        { PolicyVersion: { Document: recoveryBasePolicy, VersionId: 'v1' } },
      ],
    ]);
    const calls = [];
    const captured = captureReleaseReconciliationRecoveryRoleEffectivePermissions({
      expectedRoleArn: recoveryRoleArn,
      expectedPermissionsBoundaryArn: recoveryBoundaryArn,
      awsRegion: region,
      basePolicy: recoveryBasePolicy,
      callAwsRaw: (arguments_) => {
        calls.push(arguments_);
        const response = responses.get(arguments_.slice(0, 2).join(' '));
        assert.notEqual(response, undefined);
        return bytes(response);
      },
    });
    assert.equal(calls.length, 6);
    assert.equal(
      calls.some((arguments_) => arguments_.some((entry) => /delete|put/iu.test(entry))),
      false,
    );
    validateReleaseReconciliationRecoveryRoleEffectivePermissions(captured.value, {
      roleArn: recoveryRoleArn,
      permissionsBoundaryArn: recoveryBoundaryArn,
      basePolicy: recoveryBasePolicy,
    });
    assert.equal(captured.sourceBindingCount, 6);
  });
  await openReleaseRollbackJournal({
    intent,
    store: runtime.store,
    clock: () => new Date('2026-08-18T12:00:00.000Z'),
  });
  let inspection;
  await canary('protected-actor-and-open-owner-probe-terminal-before-mutation', async () => {
    inspection = await inspectReleaseReconciliationRecovery({
      runtime,
      request,
      approval,
      liveRecoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
      recoveryRoleArn,
      environmentVariables,
      originalJobConclusion: 'CANCELLED',
      phase: 'ROLLBACK_CHECK',
      clock: () => new Date('2026-08-18T12:00:30.000Z'),
    });
    assert.equal(inspection.decision, 'CONVERGE_FORWARD_N');
    assert.equal(inspection.probe.status, 'TERMINAL_ABSENT');
    assert.equal(inspection.externalWritesPerformed, 0);
    validateReleaseReconciliationRecoveryRequest(request, intent);
    validateReleaseReconciliationRecoveryApproval(approval, request);
    validateReleaseReconciliationRecoveryActor(inspection.actor, intent);
  });

  await canary('fence-finalization-and-foreign-journal-block-before-mutation', async () => {
    for (const guardName of [
      `/checkout/stage7/release-fence/${source.candidateSha}/${source.runId}`,
      `/checkout/stage7/release-finalization/${source.candidateSha}/${source.runId}`,
    ]) {
      const blocked = fakeRuntime();
      await openReleaseRollbackJournal({ intent, store: blocked.store });
      blocked.addGuard(guardName);
      const before = blocked.stats();
      await rejectsCode('E7_RELEASE_RECONCILIATION_RECOVERY_POST_FENCE_BLOCKED', () =>
        inspectReleaseReconciliationRecovery({
          runtime: blocked,
          request,
          approval,
          liveRecoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
          recoveryRoleArn,
          environmentVariables,
          originalJobConclusion: 'CANCELLED',
          phase: 'ROLLBACK_CHECK',
        }),
      );
      assert.deepEqual(blocked.stats(), before);
    }
    const foreign = fakeRuntime();
    await openReleaseRollbackJournal({ intent, store: foreign.store });
    foreign.store.putImmutable = async ({ name, value }) => {
      throw new Error(`unexpected write ${name} ${value}`);
    };
    foreign.listCandidateJournal = async () => [
      parameter(
        `/checkout/stage7/rollback/${source.candidateSha}/release-reconciliation/999999999/owner`,
        '{}',
      ),
    ];
    await rejectsCode('E7_RELEASE_RECONCILIATION_RECOVERY_FOREIGN_JOURNAL_BLOCKED', () =>
      inspectReleaseReconciliationRecovery({
        runtime: foreign,
        request,
        approval,
        liveRecoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
        recoveryRoleArn,
        environmentVariables,
        originalJobConclusion: 'CANCELLED',
        phase: 'ROLLBACK_CHECK',
      }),
    );
  });

  await canary('wrong-role-workflow-or-success-conclusion-is-rejected', async () => {
    for (const [code, mutation] of [
      [
        'E7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW_CONTEXT_INVALID',
        { recoveryRoleArn: rollbackRoleArn },
      ],
      [
        'E7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW_CONTEXT_INVALID',
        { environmentVariables: { ...environmentVariables, GITHUB_REF: 'refs/heads/other' } },
      ],
      [
        'E7_RELEASE_RECONCILIATION_RECOVERY_ACTOR_INPUT_INVALID',
        { originalJobConclusion: 'SUCCESS' },
      ],
    ]) {
      throwsCode(code, () =>
        createReleaseReconciliationRecoveryActor({
          intent,
          request,
          approval,
          liveRecoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
          recoveryRoleArn,
          environmentVariables,
          createdAtUtc: '2026-08-18T12:00:30.000Z',
          phase: 'ROLLBACK_CHECK',
          originalJobConclusion: 'CANCELLED',
          ...mutation,
        }),
      );
    }
  });

  await canary('original-run-rest-identity-and-terminal-failure-are-exact', async () => {
    for (const mutation of [
      { conclusion: 'success' },
      { path: '.github/workflows/other.yml' },
      { head_sha: 'c'.repeat(40) },
      { run_attempt: 2 },
      { repository: { full_name: 'foreign/repository' } },
    ]) {
      throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_RUN_INVALID', () =>
        createReleaseReconciliationRecoveryRequest({
          intent,
          configSource: configBytes,
          awsAuthSource: awsAuthBytes,
          candidateManifestSource: candidateManifestBytes,
          originalRunSource: bytes({ ...originalRun, ...mutation }),
          originalJobsSource: originalJobsBytes,
          recoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
          permissionsBoundaryArn: recoveryBoundaryArn,
          candidateRecordSource: candidateAuthorityBytes,
          previousManifestSource: previousAuthorityBytes,
          recoveryRoleArn,
          environmentVariables,
          phase: 'ROLLBACK_CHECK',
          originalJobConclusion: 'CANCELLED',
          requestedAtUtc: '2026-08-18T12:00:00.000Z',
        }),
      );
    }
    assert.equal(request.originalRun.id, source.runId);
    assert.equal(request.originalRun.responseRawSha256, sha256(originalRunBytes));
    assert.equal(request.originalRun.responseCanonicalSha256, objectSha256(originalRun));
    for (const mutation of [
      { conclusion: 'success' },
      { name: '21 Protected rollback resilience / RB-E7-06 and RB-E7-08 protected AWS rehearsal' },
      { head_sha: 'c'.repeat(40) },
      { run_attempt: 2 },
      { run_id: 987 },
    ]) {
      const pages = clone(originalJobs);
      pages[0].jobs[1] = { ...pages[0].jobs[1], ...mutation };
      throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_JOB_INVALID', () =>
        createReleaseReconciliationRecoveryRequest({
          intent,
          configSource: configBytes,
          awsAuthSource: awsAuthBytes,
          candidateManifestSource: candidateManifestBytes,
          originalRunSource: originalRunBytes,
          originalJobsSource: bytes(pages),
          recoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
          permissionsBoundaryArn: recoveryBoundaryArn,
          candidateRecordSource: candidateAuthorityBytes,
          previousManifestSource: previousAuthorityBytes,
          recoveryRoleArn,
          environmentVariables,
          phase: 'ROLLBACK_CHECK',
          originalJobConclusion: 'CANCELLED',
          requestedAtUtc: '2026-08-18T12:00:00.000Z',
        }),
      );
    }
    assert.equal(request.originalJob.name, '20 Rollback and re-promotion rehearsal');
    assert.equal(request.originalJob.responseRawSha256, sha256(originalJobsBytes));
    assert.equal(request.originalJob.responseCanonicalSha256, objectSha256(originalJobs));
  });

  await canary('config-binding-and-cleanup-expiry-bound-recovery-request', async () => {
    const tamperedConfig = clone(config);
    tamperedConfig.cleanup.ownerAlias = 'different-owner';
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_CONFIG_BINDING_INVALID', () =>
      createReleaseReconciliationRecoveryRequest({
        intent,
        configSource: bytes(tamperedConfig),
        awsAuthSource: awsAuthBytes,
        candidateManifestSource: candidateManifestBytes,
        originalRunSource: originalRunBytes,
        originalJobsSource: originalJobsBytes,
        recoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
        permissionsBoundaryArn: recoveryBoundaryArn,
        candidateRecordSource: candidateAuthorityBytes,
        previousManifestSource: previousAuthorityBytes,
        recoveryRoleArn,
        environmentVariables,
        phase: 'ROLLBACK_CHECK',
        originalJobConclusion: 'CANCELLED',
        requestedAtUtc: '2026-08-18T12:00:00.000Z',
      }),
    );
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_REQUEST_INPUT_INVALID', () =>
      createReleaseReconciliationRecoveryRequest({
        intent,
        configSource: configBytes,
        awsAuthSource: awsAuthBytes,
        candidateManifestSource: candidateManifestBytes,
        originalRunSource: originalRunBytes,
        originalJobsSource: originalJobsBytes,
        recoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
        permissionsBoundaryArn: recoveryBoundaryArn,
        candidateRecordSource: candidateAuthorityBytes,
        previousManifestSource: previousAuthorityBytes,
        recoveryRoleArn,
        environmentVariables,
        phase: 'ROLLBACK_CHECK',
        originalJobConclusion: 'CANCELLED',
        requestedAtUtc: '2026-08-20T15:00:00.001Z',
      }),
    );
  });

  await canary('aws-auth-binds-frozen-base-role-authority-before-protected-recovery', async () => {
    const mutations = [
      (value) => {
        delete value.reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256;
      },
      (value) => {
        value.reconciliationRecoveryRoleArn = rollbackRoleArn;
      },
      (value) => {
        value.reconciliationRecoveryRoleEffectivePermissionsRawSha256 = 'f'.repeat(64);
      },
      (value) => {
        value.reconciliationRecoveryRoleEffectivePermissionsSha256 = 'e'.repeat(64);
      },
    ];
    for (const mutate of mutations) {
      const tampered = clone(awsAuth);
      mutate(tampered);
      const sourceBytes = bytes(tampered);
      throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_INVALID', () =>
        createReleaseReconciliationRecoveryRequest({
          intent: intentWithAwsAuth(tampered, sourceBytes),
          configSource: configBytes,
          awsAuthSource: sourceBytes,
          candidateManifestSource: candidateManifestBytes,
          originalRunSource: originalRunBytes,
          originalJobsSource: originalJobsBytes,
          recoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
          permissionsBoundaryArn: recoveryBoundaryArn,
          candidateRecordSource: candidateAuthorityBytes,
          previousManifestSource: previousAuthorityBytes,
          recoveryRoleArn,
          environmentVariables,
          phase: 'ROLLBACK_CHECK',
          originalJobConclusion: 'CANCELLED',
          requestedAtUtc: '2026-08-18T12:00:00.000Z',
        }),
      );
    }
  });

  await canary('approved-request-binds-the-complete-intent-and-candidate-manifest', async () => {
    const manifestBody = {
      ...candidateManifestBody,
      releaseId: 'rel-20260818-1201-bbbbbbb',
    };
    const tamperedManifest = {
      ...manifestBody,
      manifestSha256: objectSha256(manifestBody),
    };
    const tamperedManifestBytes = bytes(tamperedManifest);
    const tamperedIntent = createReleaseReconciliationIntent({
      source,
      authority: intent.authority,
      bindings: intent.bindings.map((binding) =>
        binding.label === 'candidateManifest'
          ? {
              ...binding,
              rawSha256: sha256(tamperedManifestBytes),
              canonicalSha256: objectSha256(tamperedManifest),
              bytes: tamperedManifestBytes.length,
            }
          : binding,
      ),
    });
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_CANDIDATE_MANIFEST_BINDING_INVALID', () =>
      createReleaseReconciliationRecoveryRequest({
        intent: tamperedIntent,
        configSource: configBytes,
        awsAuthSource: awsAuthBytes,
        candidateManifestSource: tamperedManifestBytes,
        originalRunSource: originalRunBytes,
        originalJobsSource: originalJobsBytes,
        recoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
        permissionsBoundaryArn: recoveryBoundaryArn,
        candidateRecordSource: candidateAuthorityBytes,
        previousManifestSource: previousAuthorityBytes,
        recoveryRoleArn,
        environmentVariables,
        phase: 'ROLLBACK_CHECK',
        originalJobConclusion: 'CANCELLED',
        requestedAtUtc: '2026-08-18T12:00:00.000Z',
      }),
    );
    const swapped = clone(request);
    swapped.intentBinding.intentSha256 = 'f'.repeat(64);
    delete swapped.requestSha256;
    swapped.requestSha256 = objectSha256(swapped);
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_REQUEST_INTENT_MISMATCH', () =>
      validateReleaseReconciliationRecoveryRequest(swapped, intent),
    );
  });

  await canary('approval-is-separate-exact-and-expires-with-cleanup-authority', async () => {
    const selfApproved = clone(approval);
    selfApproved.reviewer.id = request.recoveryRun.actorId;
    delete selfApproved.approvalSha256;
    selfApproved.approvalSha256 = objectSha256(selfApproved);
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_APPROVAL_INVALID', () =>
      validateReleaseReconciliationRecoveryApproval(selfApproved, request),
    );
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_ACTOR_INPUT_INVALID', () =>
      createReleaseReconciliationRecoveryActor({
        intent,
        request,
        approval,
        liveRecoveryRoleEffectivePermissionsSource: recoveryRoleAuthorityBytes,
        recoveryRoleArn,
        environmentVariables,
        createdAtUtc: '2026-08-20T15:00:00.001Z',
        phase: 'ROLLBACK_CHECK',
        originalJobConclusion: 'CANCELLED',
      }),
    );
    const swappedRequest = clone(request);
    swappedRequest.phase = 'ROLLBACK_RESILIENCE';
    delete swappedRequest.requestSha256;
    swappedRequest.requestSha256 = objectSha256(swappedRequest);
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_JOB_PHASE_MISMATCH', () =>
      validateReleaseReconciliationRecoveryApproval(approval, swappedRequest),
    );
  });

  await canary('forward-converge-requires-dedicated-injected-adapter', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_RECOVERY_FORWARD_ADAPTER_REQUIRED', () =>
      convergeReleaseReconciliationRecoveryForward({
        runtime,
        actor: inspection.actor,
        intent,
        rollbackFlags: {},
      }),
    );
  });

  const candidatePath = path.join(testRoot, 'versioned-rollback-candidate.json');
  const transitionPath = path.join(testRoot, 'recovery-transition.json');
  writeFileSync(candidatePath, `${JSON.stringify(candidateRecord())}\n`, { mode: 0o600 });
  let convergence;
  await canary('forward-adapter-can-only-return-exact-candidate-n-convergence', async () => {
    const directions = [];
    const actorBindings = [];
    const intentBindings = [];
    convergence = await convergeReleaseReconciliationRecoveryForward({
      runtime,
      actor: inspection.actor,
      intent,
      rollbackFlags: { 'candidate-record': candidatePath, output: transitionPath },
      executeVersionedRollbackRecovery: async ({ flags, recoveryActor, recoveryIntent }) => {
        directions.push(flags.direction);
        actorBindings.push(recoveryActor.actorSha256);
        intentBindings.push(recoveryIntent.intentSha256);
        const value = transition();
        writeFileSync(flags.output, `${JSON.stringify(value)}\n`, { mode: 0o600 });
        return value;
      },
    });
    assert.deepEqual(directions, ['REPROMOTE_CANDIDATE']);
    assert.deepEqual(actorBindings, [inspection.actor.actorSha256]);
    assert.deepEqual(intentBindings, [intent.intentSha256]);
    assert.equal(convergence.recoveryAction, 'VERIFIED_NOOP');
    assert.equal(convergence.observedStateSha256, convergence.expectedStateSha256);
  });

  let finalized;
  await canary('smoke-bytes-must-bind-the-exact-recovery-actor-before-terminal-write', async () => {
    const putsBefore = runtime.stats().puts;
    await rejectsCode('E7_RELEASE_RECONCILIATION_RECOVERY_SMOKE_ACTOR_BINDING_INVALID', () =>
      finalizeReleaseReconciliationRecoveryForward({
        runtime,
        actor: inspection.actor,
        convergence,
        driftEvidenceSource: bytes(driftEvidence('2026-08-18T12:01:45.000Z')),
        smokeEvidenceSource: bytes(
          smokeEvidence('2026-08-18T12:02:00.000Z', convergence, '0'.repeat(64)),
        ),
        clock: () => new Date('2026-08-18T12:03:00.000Z'),
      }),
    );
    assert.equal(runtime.stats().puts, putsBefore);
  });
  await canary('fresh-proofs-finalize-n-but-never-authorize-fence', async () => {
    finalized = await finalizeReleaseReconciliationRecoveryForward({
      runtime,
      actor: inspection.actor,
      convergence,
      driftEvidenceSource: bytes(driftEvidence('2026-08-18T12:01:45.000Z')),
      smokeEvidenceSource: bytes(
        smokeEvidence('2026-08-18T12:02:00.000Z', convergence, inspection.actor.actorSha256),
      ),
      clock: () => new Date('2026-08-18T12:03:00.000Z'),
    });
    assert.equal(finalized.receipt.eligibleForFence, false);
    assert.equal(finalized.outcome.status, 'CANDIDATE_N_VERIFIED_RELEASE_REMAINS_BLOCKED');
    assert.equal(finalized.outcome.fenceWritesPerformed, 0);
    assert.equal(finalized.outcome.publicationWritesPerformed, 0);
    validateReleaseReconciliationRecoveryOutcome(finalized.outcome);
  });

  await canary('terminal-resume-performs-zero-put-and-reconstructs-identical-receipt', async () => {
    const putsBefore = runtime.stats().puts;
    const resumed = await resumeReleaseReconciliationRecovery({
      runtime,
      actor: inspection.actor,
      intent,
      clock: () => new Date('2026-08-18T12:04:00.000Z'),
    });
    assert.equal(resumed.status, 'TERMINAL_RECEIPT_REUSED');
    assert.equal(resumed.receipt.receiptSha256, finalized.receipt.receiptSha256);
    assert.equal(runtime.stats().puts, putsBefore);
  });

  let snapshot;
  await canary(
    'raw-owner-intent-proof-and-terminal-values-are-preserved-before-delete',
    async () => {
      snapshot = await snapshotReleaseReconciliationRecovery({
        runtime,
        outcome: finalized.outcome,
        clock: () => new Date('2026-08-18T12:05:00.000Z'),
      });
      validateReleaseReconciliationRecoverySnapshot(snapshot);
      assert.equal(
        snapshot.parameters.some(({ name }) => name.endsWith('/owner')),
        true,
      );
      assert.equal(
        snapshot.parameters.some(({ name }) => name.includes('/runtime-proofs/')),
        true,
      );
      assert.equal(
        snapshot.parameters.some(({ name }) => name.endsWith('/terminal')),
        true,
      );
      assert.equal(snapshot.parameterCount, runtime.stats().entries);
    },
  );

  await canary('snapshot-tamper-or-extra-delete-target-is-rejected', async () => {
    const tampered = clone(snapshot);
    tampered.parameters[0].value += 'x';
    delete tampered.snapshotSha256;
    tampered.snapshotSha256 = objectSha256(tampered);
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_SNAPSHOT_PARAMETER_INVALID', () =>
      validateReleaseReconciliationRecoverySnapshot(tampered),
    );
  });

  const preservationSources = {
    intent: bytes(intent),
    receipt: bytes(finalized.receipt),
    outcome: bytes(finalized.outcome),
    snapshot: bytes(snapshot),
    recoveryRoleAuthority: recoveryRoleAuthorityBytes,
  };
  const preservationIndex = createReleaseReconciliationRecoveryPreservationIndex({
    sources: preservationSources,
    createdAtUtc: '2026-08-18T12:05:30.000Z',
  });
  const preservationArchive = createReleaseSuccessorStoredZipFixture({
    'release-reconciliation-intent.json': preservationSources.intent,
    'release-reconciliation-receipt.json': preservationSources.receipt,
    'release-reconciliation-recovery-outcome.json': preservationSources.outcome,
    'release-reconciliation-recovery-journal-snapshot.json': preservationSources.snapshot,
    'stage7-release-reconciliation-recovery-role-effective-permissions.json':
      preservationSources.recoveryRoleAuthority,
    'release-reconciliation-recovery-preservation-index.json': bytes(preservationIndex),
  });
  const artifactBinding = createReleaseReconciliationRecoveryArtifactBinding({
    preservationIndex,
    archiveSource: preservationArchive,
    metadataSource: bytes({
      id: 123456,
      name: preservationIndex.artifactName,
      digest: `sha256:${sha256(preservationArchive)}`,
      expired: false,
      size_in_bytes: preservationArchive.length,
      created_at: '2026-08-18T12:05:31.000Z',
      expires_at: '2026-09-17T12:05:31.000Z',
      workflow_run: { id: Number(inspection.actor.recoveryRun.runId) },
    }),
    expectedRunId: inspection.actor.recoveryRun.runId,
    capturedAtUtc: '2026-08-18T12:05:45.000Z',
  });
  await canary('artifact-api-binding-rejects-wrong-run-before-cleanup', async () => {
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_ARTIFACT_METADATA_INVALID', () =>
      createReleaseReconciliationRecoveryArtifactBinding({
        preservationIndex,
        archiveSource: preservationArchive,
        metadataSource: bytes({
          id: 123456,
          name: preservationIndex.artifactName,
          digest: `sha256:${sha256(preservationArchive)}`,
          expired: false,
          size_in_bytes: preservationArchive.length,
          created_at: '2026-08-18T12:05:31.000Z',
          expires_at: '2026-09-17T12:05:31.000Z',
          workflow_run: { id: 1 },
        }),
        expectedRunId: inspection.actor.recoveryRun.runId,
        capturedAtUtc: '2026-08-18T12:05:45.000Z',
      }),
    );
  });
  await canary('preservation-index-binds-exact-raw-and-canonical-causal-files', async () => {
    validateReleaseReconciliationRecoveryPreservationIndex(preservationIndex);
    const reopened = validateReleaseReconciliationRecoveryPreservationSources({
      index: preservationIndex,
      sources: preservationSources,
    });
    assert.equal(reopened.outcome.outcomeSha256, finalized.outcome.outcomeSha256);
    const tamperedSources = {
      ...preservationSources,
      receipt: bytes({ ...finalized.receipt, stage: 6 }),
    };
    throwsCode('E7_RELEASE_RECONCILIATION_RECEIPT_INVALID', () =>
      validateReleaseReconciliationRecoveryPreservationSources({
        index: preservationIndex,
        sources: tamperedSources,
      }),
    );
    const authorityTamper = clone(recoveryRoleAuthority);
    authorityTamper.role.id = 'AROATAMPER1234567';
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_INVALID', () =>
      validateReleaseReconciliationRecoveryPreservationSources({
        index: preservationIndex,
        sources: {
          ...preservationSources,
          recoveryRoleAuthority: bytes(authorityTamper),
        },
      }),
    );
  });

  const cleanupRoleAuthority = {
    roleArn: journalRoleArn,
    permissionsBoundaryArn: `arn:aws:iam::${accountId}:policy/stage7-release-journal-boundary`,
    effectivePolicyProjectionSha256: '1'.repeat(64),
    frozenEffectivePermissionsSha256: '2'.repeat(64),
    liveEffectivePermissionsSha256: '3'.repeat(64),
    frozenRawSha256: '4'.repeat(64),
    liveRawSha256: '5'.repeat(64),
    liveCanonicalSha256: '6'.repeat(64),
    liveSourceBindingCount: 6,
  };
  await canary('cleanup-requires-preservation-binding-and-proves-residual-zero', async () => {
    const closure = await cleanupReleaseReconciliationRecovery({
      runtime,
      cleanupActor: inspection.actor,
      outcome: finalized.outcome,
      snapshot,
      preservationIndex,
      preservationArtifact: artifactBinding,
      cleanupRoleAuthority,
      clock: () => new Date('2026-08-18T12:06:00.000Z'),
    });
    validateReleaseReconciliationRecoveryClosure(closure);
    assert.equal(closure.cleanup.residualParameterCount, 0);
    assert.equal(runtime.stats().entries, 0);
    assert.equal(runtime.stats().deletes, snapshot.parameterCount);
  });

  await canary('closure-cannot-claim-residual-zero-with-a-duplicate-or-missing-name', async () => {
    const deleted = snapshot.parameters.map(({ name }) => name);
    throwsCode('E7_RELEASE_RECONCILIATION_RECOVERY_CLOSURE_INPUT_INVALID', () =>
      createReleaseReconciliationRecoveryClosure({
        cleanupActor: inspection.actor,
        outcome: finalized.outcome,
        snapshot,
        preservationIndex,
        preservationArtifact: artifactBinding,
        cleanupRoleAuthority,
        deletedParameterNames: [...deleted.slice(1), deleted[1]],
        residualParameterNames: [],
        completedAtUtc: '2026-08-18T12:06:00.000Z',
      }),
    );
  });

  await canary('real-cli-creates-request-approval-and-actor-with-exact-flags', async () => {
    const current = Date.now();
    const dynamicConfig = clone(config);
    dynamicConfig.authorization.approvedAtUtc = new Date(
      current - 48 * 60 * 60 * 1000,
    ).toISOString();
    dynamicConfig.window.startsAtUtc = new Date(current - 36 * 60 * 60 * 1000).toISOString();
    dynamicConfig.window.endsAtUtc = new Date(current - 32 * 60 * 60 * 1000).toISOString();
    dynamicConfig.authorization.expiresAtUtc = new Date(
      current - 24 * 60 * 60 * 1000,
    ).toISOString();
    dynamicConfig.cleanup.expiresAtUtc = new Date(current + 24 * 60 * 60 * 1000).toISOString();
    const dynamic = intentForConfig(dynamicConfig);
    const cliRoot = path.join(testRoot, 'cli');
    mkdirSync(cliRoot, { recursive: true, mode: 0o700 });
    const files = Object.fromEntries(
      [
        'intent',
        'config',
        'awsAuth',
        'candidateManifest',
        'originalRun',
        'originalJobs',
        'recoveryRoleAuthority',
        'candidateRecord',
        'previousManifest',
        'request',
        'review',
        'approval',
        'actor',
      ].map((name) => [name, path.join(cliRoot, `${name}.json`)]),
    );
    writeFileSync(files.intent, `${JSON.stringify(dynamic.intent)}\n`, { mode: 0o600 });
    writeFileSync(files.config, dynamic.configSource, { mode: 0o600 });
    writeFileSync(files.awsAuth, dynamic.awsAuthSource, { mode: 0o600 });
    writeFileSync(files.candidateManifest, dynamic.candidateManifestSource, { mode: 0o600 });
    writeFileSync(files.originalRun, originalRunBytes, { mode: 0o600 });
    writeFileSync(files.originalJobs, originalJobsBytes, { mode: 0o600 });
    writeFileSync(files.recoveryRoleAuthority, recoveryRoleAuthorityBytes, { mode: 0o600 });
    writeFileSync(files.candidateRecord, candidateAuthorityBytes, { mode: 0o600 });
    writeFileSync(files.previousManifest, previousAuthorityBytes, { mode: 0o600 });
    const cli = path.join(workspaceRoot, 'scripts/stage7/release-reconciliation-recovery-cli.mjs');
    const runCli = (arguments_) =>
      spawnSync(process.execPath, [cli, ...arguments_], {
        cwd: workspaceRoot,
        env: { ...process.env, ...environmentVariables },
        encoding: 'utf8',
        windowsHide: true,
      });
    const created = runCli([
      'create-request',
      '--intent',
      files.intent,
      '--config',
      files.config,
      '--aws-auth',
      files.awsAuth,
      '--candidate-manifest',
      files.candidateManifest,
      '--original-run',
      files.originalRun,
      '--original-jobs',
      files.originalJobs,
      '--recovery-role-effective-permissions',
      files.recoveryRoleAuthority,
      '--candidate-record',
      files.candidateRecord,
      '--previous-manifest',
      files.previousManifest,
      '--phase',
      'ROLLBACK_CHECK',
      '--original-job-conclusion',
      'CANCELLED',
      '--output',
      files.request,
    ]);
    assert.equal(created.status, 0, created.stderr);
    const cliRequest = parseStrictJsonSource(readFileSync(files.request), {
      scanForbiddenData: false,
    });
    validateReleaseReconciliationRecoveryRequest(cliRequest, dynamic.intent);
    writeFileSync(
      files.review,
      `${JSON.stringify([
        {
          state: 'approved',
          comment: `STAGE7_RECONCILIATION_RECOVERY_SHA256=${cliRequest.requestSha256}`,
          environments: [
            {
              id: 71,
              name: 'assessment-release-reconciliation-recovery',
              url: 'https://api.github.com/repos/ivanmonsalve0404/async-checkout-demo/environments/assessment-release-reconciliation-recovery',
            },
          ],
          user: { id: 55667788, login: 'recovery-reviewer', type: 'User' },
        },
      ])}\n`,
      { mode: 0o600 },
    );
    const captured = runCli([
      'capture-approval',
      '--request',
      files.request,
      '--review-response',
      files.review,
      '--output',
      files.approval,
    ]);
    assert.equal(captured.status, 0, captured.stderr);
    const createdActor = runCli([
      'create-actor',
      '--intent',
      files.intent,
      '--request',
      files.request,
      '--approval',
      files.approval,
      '--live-recovery-role-effective-permissions',
      files.recoveryRoleAuthority,
      '--output',
      files.actor,
    ]);
    assert.equal(createdActor.status, 0, createdActor.stderr);
    validateReleaseReconciliationRecoveryActor(
      parseStrictJsonSource(readFileSync(files.actor), { scanForbiddenData: false }),
      dynamic.intent,
    );
    const bypass = runCli([
      'create-actor',
      '--intent',
      files.intent,
      '--request',
      files.request,
      '--approval',
      files.approval,
      '--live-recovery-role-effective-permissions',
      files.recoveryRoleAuthority,
      '--recovery-role-arn',
      recoveryRoleArn,
      '--output',
      path.join(cliRoot, 'bypass.json'),
    ]);
    assert.equal(bypass.status, 1);
    assert.match(bypass.stderr, /E7_RELEASE_RECONCILIATION_RECOVERY_CLI_FLAGS_INVALID/u);
  });

  const success = (value) => ({
    status: 0,
    signal: null,
    stdout: JSON.stringify(value),
    stderr: '',
  });
  const failure = (code) => ({
    status: 254,
    signal: null,
    stdout: '',
    stderr: `An error occurred (${code}) when calling the test operation: denied`,
  });
  const awsParameter = (name, value = '{}') => ({
    Name: name,
    Type: 'String',
    Value: value,
    Version: 1,
    LastModifiedDate: '2026-08-18T12:00:00.000Z',
    ARN: `arn:aws:ssm:${region}:${accountId}:parameter${name}`,
    DataType: 'text',
  });
  const awsRuntime = (handler) =>
    createAwsCliReleaseReconciliationRecoveryRuntime({
      candidateSha: source.candidateSha,
      originalRunId: source.runId,
      phase: 'ROLLBACK_CHECK',
      accountId,
      region,
      recoveryRoleArn,
      controlSha: environmentVariables.GITHUB_SHA,
      environmentVariables,
      spawn: (_command, arguments_) => {
        if (arguments_[0] === 'sts') {
          return success({
            UserId: `AROATEST:e7-reconciliation-recovery-${environmentVariables.GITHUB_RUN_ID}-1`,
            Account: accountId,
            Arn: `arn:aws:sts::${accountId}:assumed-role/stage7-release-reconciliation-recovery/e7-reconciliation-recovery-${environmentVariables.GITHUB_RUN_ID}-1`,
          });
        }
        return handler(arguments_);
      },
    });

  await canary('aws-get-is-singular-and-only-not-found-is-null', async () => {
    const runtimeValue = awsRuntime((arguments_) => {
      assert.equal(arguments_[1], 'get-parameter');
      assert.equal(arguments_.includes('--with-decryption'), false);
      return failure('ParameterNotFound');
    });
    assert.equal(await runtimeValue.store.get(`${root}/owner`), null);
    const denied = awsRuntime(() => failure('AccessDeniedException'));
    await rejectsCode('E7_RELEASE_RECONCILIATION_RECOVERY_GET_FAILED', () =>
      denied.store.get(`${root}/owner`),
    );
  });

  await canary('aws-put-is-confined-to-selected-phase-runtime-proofs-and-terminal', async () => {
    const runtimeValue = awsRuntime(() => {
      throw new Error('out-of-scope write reached AWS');
    });
    const callsBefore = runtimeValue.externalCallCount();
    for (const name of [
      `${root}/owner`,
      `${root}/intent/0001`,
      `${root}/ROLLBACK_RESILIENCE/terminal`,
      `/checkout/stage7/rollback/${source.candidateSha}/RB-E7-06/entry`,
    ]) {
      await rejectsCode('E7_RELEASE_RECONCILIATION_RECOVERY_PUT_INPUT_INVALID', () =>
        runtimeValue.store.putImmutable({ name, value: '{}' }),
      );
    }
    assert.equal(runtimeValue.externalCallCount(), callsBefore);
  });

  await canary('aws-selected-lowercase-phase-terminal-put-is-immutable-and-readable', async () => {
    const terminalName = `${root}/rollback-check/terminal`;
    const terminalValue = '{"terminal":true}';
    const calls = [];
    const runtimeValue = awsRuntime((arguments_) => {
      calls.push(arguments_);
      if (arguments_[1] === 'put-parameter') return success({ Version: 1, Tier: 'Standard' });
      if (arguments_[1] === 'get-parameter') {
        assert.equal(arguments_.includes('--with-decryption'), false);
        return success({ Parameter: awsParameter(terminalName, terminalValue) });
      }
      throw new Error('unexpected simulated AWS call');
    });
    const written = await runtimeValue.store.putImmutable({
      name: terminalName,
      value: terminalValue,
    });
    assert.equal(written.name, terminalName);
    assert.equal(calls[0].includes('--no-overwrite'), true);
    assert.equal(calls[0].includes('--overwrite'), false);
  });

  await canary('aws-list-token-cycle-and-success-shape-confusion-are-bounded', async () => {
    let pages = 0;
    const cyclic = awsRuntime((arguments_) => {
      if (arguments_[1] !== 'get-parameters-by-path') return failure('ParameterNotFound');
      pages += 1;
      return success({ Parameters: [], NextToken: 'same' });
    });
    await rejectsCode('E7_RELEASE_RECONCILIATION_RECOVERY_TOKEN_CYCLE', () =>
      cyclic.store.list(root),
    );
    assert.equal(pages, 2);
    const confused = awsRuntime(() => success({ awsErrorCode: 'ParameterNotFound' }));
    await rejectsCode('E7_RELEASE_RECONCILIATION_RECOVERY_GET_INVALID', () =>
      confused.store.get(`${root}/owner`),
    );
  });

  await canary(
    'aws-candidate-scan-accepts-the-derived-223-parameter-fixed-point-only',
    async () => {
      const candidateRoot = `/checkout/stage7/rollback/${source.candidateSha}`;
      const pagedRuntime = (count) => {
        const parameters = Array.from({ length: count }, (_, index) =>
          awsParameter(
            `${candidateRoot}/RB-E7-${index % 2 === 0 ? '06' : '08'}/entry-${String(index).padStart(3, '0')}`,
          ),
        );
        let offset = 0;
        let pages = 0;
        const runtimeValue = awsRuntime((arguments_) => {
          assert.equal(arguments_[1], 'get-parameters-by-path');
          assert.equal(arguments_.includes('--with-decryption'), false);
          assert.equal(arguments_[arguments_.indexOf('--path') + 1], candidateRoot);
          assert.equal(arguments_[arguments_.indexOf('--max-results') + 1], '10');
          pages += 1;
          const page = parameters.slice(offset, offset + 10);
          offset += page.length;
          return success({
            Parameters: page,
            ...(offset < parameters.length ? { NextToken: `page-${offset}` } : {}),
          });
        });
        return { runtimeValue, pages: () => pages };
      };
      const exact = pagedRuntime(223);
      assert.equal((await exact.runtimeValue.listCandidateJournal()).length, 223);
      assert.equal(exact.pages(), 23);
      const over = pagedRuntime(224);
      await rejectsCode('E7_RELEASE_RECONCILIATION_RECOVERY_LIST_TOO_LARGE', () =>
        over.runtimeValue.listCandidateJournal(),
      );
      assert.equal(over.pages(), 23);
    },
  );

  await canary('aws-exact-parameter-shape-is-accepted-without-real-calls', async () => {
    const runtimeValue = awsRuntime(() =>
      success({ Parameter: awsParameter(`${root}/owner`, '{}') }),
    );
    const value = await runtimeValue.store.get(`${root}/owner`);
    assert.equal(value.name, `${root}/owner`);
    assert.equal(value.value, '{}');
  });

  process.stdout.write(
    `stage-7 release reconciliation recovery self-test: PASS (${canaryIds.length} canaries, 0 real AWS calls)\n`,
  );
} finally {
  const resolved = path.resolve(testRoot);
  const resolvedParent = path.resolve(selfTestParent);
  assert.equal(resolved.startsWith(`${resolvedParent}${path.sep}`), true);
  rmSync(resolved, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 });
  if (process.platform === 'win32' && existsSync(resolved)) {
    const cleanup = spawnSync(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        '$target=[IO.Path]::GetFullPath($env:E7_RECOVERY_SELF_TEST_TARGET); $parent=[IO.Path]::GetFullPath($env:E7_RECOVERY_SELF_TEST_PARENT)+[IO.Path]::DirectorySeparatorChar; if(-not $target.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase)){exit 17}; Remove-Item -LiteralPath $target -Recurse -Force; if(Test-Path -LiteralPath $target){exit 18}',
      ],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          E7_RECOVERY_SELF_TEST_TARGET: resolved,
          E7_RECOVERY_SELF_TEST_PARENT: resolvedParent,
        },
        windowsHide: true,
      },
    );
    assert.equal(cleanup.status, 0, cleanup.stderr);
  }
  assert.equal(existsSync(resolved), false);
}
