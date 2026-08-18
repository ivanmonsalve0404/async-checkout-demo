/* global structuredClone */

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { objectSha256, workspaceRoot } from './core.mjs';
import {
  STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT,
  createReleasePreFenceGate,
  createReleaseReconciliationIntent,
  validateReleasePreFenceGate,
  validateReleasePublicationClassification,
  validateReleaseReconciliationReceipt,
} from './release-reconciliation.mjs';
import { RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS } from './release-reconciliation-authority.mjs';
import { createReleaseSuccessorIamAuthoritySelfTestFixture } from './release-successor-iam-authority.mjs';
import {
  RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS,
  RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
  RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
} from './release-successor-rollback-authority.mjs';
import { createRollbackResilienceSelfTestFixture } from './rollback-resilience-producer.mjs';
import {
  convergeVersionedReleaseRuntime,
  createAwsCliReleaseReconciliationRuntime,
  createReleaseReconciliationIntentFromSources,
  executeReleasePublicationForwardReconciliation,
  finalizeVersionedReleaseRuntimeReconciliation,
  openReleaseRollbackJournal,
  probeVersionedReleaseRuntimeTerminal,
  recoverVersionedReleaseRuntimeConvergenceCheckpoint,
  requireReleaseRollbackJournalOwner,
  resumeVersionedReleaseRuntimeReconciliation,
  validateReleaseRuntimeConvergence,
  validateReleaseRuntimeTerminalProbe,
  validateReleaseReconciliationTerminal,
} from './release-reconciliation-executor.mjs';

const source = Object.freeze({
  repository: 'ivanmonsalve0404/async-checkout-demo',
  workflowPath: '.github/workflows/release.yml',
  ref: 'refs/heads/master',
  runId: '123456789',
  runAttempt: 1,
  candidateSha: 'a'.repeat(40),
  releaseId: 'rel-20260818-1200-aaaaaaa',
  releaseTag: 'v1.0.0',
  configSha256: '1'.repeat(64),
});
const accountId = '123456789012';
const region = 'us-east-1';
const rollbackRoleArn = `arn:aws:iam::${accountId}:role/stage7-release-reconciliation`;
const journalRoleArn = `arn:aws:iam::${accountId}:role/stage7-release-journal-cleanup`;
const sessionName = (capability) =>
  capability === 'JOURNAL'
    ? `e7-release-reconciliation-journal-${source.runId}`
    : `e7-release-reconciliation-runtime-${source.runId}`;
const candidateRootPrefix = `/checkout/stage7/rollback/${source.candidateSha}`;
const reconciliationRootPrefix = `${candidateRootPrefix}/release-reconciliation/${source.runId}`;
const ownerName = `${reconciliationRootPrefix}/owner`;
const digest = (label, type) => objectSha256({ label, type });
const intentBindings = STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.map((descriptor, index) => ({
  ...descriptor,
  rawSha256: descriptor.sourceType === 'NESTED_JSON' ? null : digest(descriptor.label, 'raw'),
  canonicalSha256:
    descriptor.sourceType === 'RAW_TEXT' ? null : digest(descriptor.label, 'canonical'),
  bytes: 100 + index,
}));
const intent = Object.freeze(
  createReleaseReconciliationIntent({
    source,
    authority: {
      accountId,
      region,
      rollbackRoleArn,
      journalRoleArn,
      rollbackPermissionSetSha256: '2'.repeat(64),
      journalEffectivePermissionsSha256: '3'.repeat(64),
    },
    bindings: intentBindings,
  }),
);
const node = process.execPath;
const cli = path.join(workspaceRoot, 'scripts/stage7/release-reconciliation-cli.mjs');

let canaries = 0;
let simulatedAwsCalls = 0;
const canary = async (name, implementation) => {
  await implementation();
  canaries += 1;
  return name;
};
const rejectsCode = async (code, implementation) => {
  await assert.rejects(implementation, (error) => error?.code === code);
};
const bodyWithDigest = (body, field) => ({ ...body, [field]: objectSha256(body) });
const clone = (value) => structuredClone(value);
const rawSha256 = (value) => createHash('sha256').update(value).digest('hex');
const parameter = (name, value, sequence = 0) => ({
  name,
  type: 'String',
  value,
  version: 1,
  lastModifiedAtUtc: new Date(Date.parse('2026-08-18T12:00:00.000Z') + sequence).toISOString(),
  arn: `arn:aws:ssm:${region}:${accountId}:parameter${name}`,
  dataType: 'text',
});
const fakeStoreEntries = new WeakMap();
const fakeStoreStats = new WeakMap();
const fakeStore = (initial = [], storeSource = source) => {
  const entries = new Map(initial.map((entry) => [entry.name, clone(entry)]));
  const stats = { puts: 0 };
  let sequence = entries.size;
  const candidatePrefix = `/checkout/stage7/rollback/${storeSource.candidateSha}`;
  const reconciliationPrefix = `${candidatePrefix}/release-reconciliation/${storeSource.runId}`;
  const store = {
    candidateRootPrefix: candidatePrefix,
    reconciliationRootPrefix: reconciliationPrefix,
    get: async (name) => (entries.has(name) ? clone(entries.get(name)) : null),
    putImmutable: async ({ name, value }) => {
      stats.puts += 1;
      if (entries.has(name)) {
        const error = new Error('ParameterAlreadyExists');
        error.code = 'ParameterAlreadyExists';
        throw error;
      }
      sequence += 1;
      const written = parameter(name, value, sequence);
      entries.set(name, written);
      return clone(written);
    },
    list: async (prefix) =>
      [...entries.values()].filter(({ name }) => name.startsWith(`${prefix}/`)).map(clone),
  };
  fakeStoreEntries.set(store, entries);
  fakeStoreStats.set(store, stats);
  return store;
};
const failOnPut = (store, targetPut) => {
  let puts = 0;
  return {
    candidateRootPrefix: store.candidateRootPrefix,
    reconciliationRootPrefix: store.reconciliationRootPrefix,
    get: store.get,
    list: store.list,
    putImmutable: async (request) => {
      puts += 1;
      if (puts === targetPut) {
        const error = new Error('simulated crash');
        error.code = 'SIMULATED_CRASH';
        throw error;
      }
      return store.putImmutable(request);
    },
  };
};

const candidateRecord = () => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_CANDIDATE',
    target: {
      candidateSha: source.candidateSha,
      releaseId: source.releaseId,
    },
    resources: {
      api: {
        functionName: 'checkout-api',
        aliasName: 'live',
        version: '7',
      },
      worker: {
        functionName: 'checkout-worker',
        aliasName: 'live',
        version: '9',
      },
      web: {
        bucketName: 'checkout-production-web',
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
  return bodyWithDigest(body, 'recordSha256');
};
const transition = ({
  decision = 'ALREADY_APPLIED_AND_VERIFIED',
  startedAtUtc = '2026-08-18T12:01:00.000Z',
  completedAtUtc = '2026-08-18T12:01:30.000Z',
  apiVersion = '7',
} = {}) => {
  const applied = decision === 'APPLIED_AND_VERIFIED';
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_AWS_TRANSITION',
    status: 'AWS_VERIFIED_PENDING_READ_SMOKE',
    direction: 'REPROMOTE_CANDIDATE',
    decision,
    planSha256: '5'.repeat(64),
    startedAtUtc,
    completedAtUtc,
    fromReleaseId: 'rel-20260801-1100-bbbbbbb',
    toReleaseId: source.releaseId,
    aliases: {
      api: { functionName: 'checkout-api', aliasName: 'live', version: apiVersion },
      worker: { functionName: 'checkout-worker', aliasName: 'live', version: '9' },
    },
    web: {
      bucketName: 'checkout-production-web',
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
      invalidation: {
        status: applied ? 'COMPLETED' : 'NOT_REQUIRED',
        idSha256: applied ? '6'.repeat(64) : null,
        paths: applied ? ['/index.html', '/public-config.json'] : [],
      },
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
    },
    dataFactsSha256: 'b'.repeat(64),
    dataFactsChanged: false,
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    containsSensitiveData: false,
  };
  return bodyWithDigest(body, 'transitionSha256');
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
const smokeEvidence = (executedAtUtc, convergence) => ({
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
  reconciliation: {
    phase: convergence.phase,
    intentSha256: convergence.intent.intentSha256,
    convergenceSha256: convergence.convergenceSha256,
    convergenceCompletedAtUtc: convergence.completedAtUtc,
  },
  authorizationUsage: {
    schemaVersion: 1,
    usageId:
      convergence.phase === 'ROLLBACK_CHECK'
        ? 'RECONCILIATION_ROLLBACK_CHECK_SMOKE'
        : 'RECONCILIATION_ROLLBACK_RESILIENCE_SMOKE',
    bundleSha256: 'd'.repeat(64),
    candidateSha: source.candidateSha,
    releaseId: source.releaseId,
    configSha256: source.configSha256,
    ownedOriginSha256: 'e'.repeat(64),
    sandboxHostSha256: 'f'.repeat(64),
    requestCounts: {
      'AUTH-E7-EXT-01': 3,
      'AUTH-E7-EXT-02': 0,
      'AUTH-E7-EXT-03': 0,
    },
  },
  requests: {
    total: 3,
    ownedOrigin: 3,
    provider: 0,
    production: 0,
    outsideAllowlist: 0,
  },
  externalAuthorization: {
    authorizationSha256: 'd'.repeat(64),
    authorizationIds: ['AUTH-E7-EXT-01', 'AUTH-E7-EXT-02', 'AUTH-E7-EXT-03'],
    ownedOriginSha256: 'e'.repeat(64),
    sandboxHostSha256: 'f'.repeat(64),
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
const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
const artifactJsonBytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const createIntentSourceFixture = () => {
  const journalPermissions = createReleaseSuccessorIamAuthoritySelfTestFixture();
  const config = clone(createRollbackResilienceSelfTestFixture().inputs.config);
  const current = Date.now();
  config.authorization.approvedAtUtc = new Date(current - 60 * 60 * 1000).toISOString();
  config.authorization.expiresAtUtc = new Date(current + 2 * 60 * 60 * 1000).toISOString();
  config.window.startsAtUtc = new Date(current - 30 * 60 * 1000).toISOString();
  config.window.endsAtUtc = new Date(current + 60 * 60 * 1000).toISOString();
  config.prereleaseAccess.originTokenSecretVersionId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
  const fixtureRollbackRoleArn = config.aws.roles.rollbackRoleArn;
  const configSha256 = objectSha256(config);
  const fixtureSource = {
    ...source,
    configSha256,
  };
  const freezeBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'BUILD_ONCE_FREEZE',
    authorizationScope: 'FULL_RELEASE_VERSIONED_UPDATE',
    releaseMode: 'VERSIONED_UPDATE',
    updateReleaseSupported: true,
    candidateSha: fixtureSource.candidateSha,
    releaseId: fixtureSource.releaseId,
    releaseTag: fixtureSource.releaseTag,
    configSha256,
    containsSensitiveData: false,
  };
  const candidateManifest = bodyWithDigest(freezeBody, 'manifestSha256');
  const releaseMetadata = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_ENTRY_PREFLIGHT',
    status: 'PASS',
    scope: 'full',
    decision: 'READY_FOR_BUILD_FREEZE',
    releaseRunId: fixtureSource.runId,
    releaseRunAttempt: 1,
    candidateSha: fixtureSource.candidateSha,
    releaseId: fixtureSource.releaseId,
    configSha256,
    containsSensitiveData: false,
  };
  const releasePlan = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_PLAN',
    candidateSha: fixtureSource.candidateSha,
    releaseId: fixtureSource.releaseId,
    configSha256,
    containsSensitiveData: false,
  };
  const approvedDiff = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_DIFF_REVIEW',
    candidateSha: fixtureSource.candidateSha,
    releaseId: fixtureSource.releaseId,
    configSha256,
    containsSensitiveData: false,
  };
  const rawDiff = Buffer.from('Stack checkout-release\nNo destructive changes\n', 'utf8');
  const githubEnvironmentApproval = {
    schemaVersion: 1,
    stage: 7,
    kind: 'GITHUB_ENVIRONMENT_APPROVAL',
    candidateSha: fixtureSource.candidateSha,
    releaseId: fixtureSource.releaseId,
    configSha256,
    iamReviewedDiffSha256: rawSha256(rawDiff),
    containsSensitiveData: false,
  };
  const iamEffectivePermissions = {
    kind: 'IAM_EFFECTIVE_PERMISSIONS',
    status: 'PASS',
    scope: 'full',
    candidateSha: fixtureSource.candidateSha,
    releaseId: fixtureSource.releaseId,
    manifestSha256: candidateManifest.manifestSha256,
    configSha256,
    bindingSha256: '4'.repeat(64),
    roles: {
      rollbackRoleArn: {
        roleArnSha256: rawSha256(fixtureRollbackRoleArn),
        permissionSetSha256: '5'.repeat(64),
      },
    },
  };
  const journalBytes = artifactJsonBytes(journalPermissions);
  const recoveryRoleAuthority = {
    reconciliationRecoveryRoleArn: `arn:aws:iam::${config.aws.accountId}:role/stage7-release-reconciliation-recovery`,
    reconciliationRecoveryPermissionsBoundaryArn: `arn:aws:iam::${config.aws.accountId}:policy/stage7-release-reconciliation-recovery-boundary`,
    reconciliationRecoveryRoleEffectivePermissionsRawSha256: '6'.repeat(64),
    reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256: '7'.repeat(64),
    reconciliationRecoveryRoleEffectivePermissionsSha256: '8'.repeat(64),
    reconciliationRecoveryRoleEffectivePolicyProjectionSha256: '9'.repeat(64),
  };
  const awsAuth = {
    schemaVersion: 1,
    stage: 7,
    kind: 'AWS_READ_ONLY_PREFLIGHT',
    status: 'PASS',
    scope: 'full',
    candidateSha: fixtureSource.candidateSha,
    releaseId: fixtureSource.releaseId,
    manifestSha256: candidateManifest.manifestSha256,
    configSha256,
    iamEffectivePermissions,
    journalRoleEffectivePermissionsRawSha256: rawSha256(journalBytes),
    journalRoleEffectivePermissionsSha256: journalPermissions.effectivePermissionsSha256,
    ...recoveryRoleAuthority,
    containsSensitiveData: false,
  };
  const approvedDiffBytes = artifactJsonBytes(approvedDiff);
  const awsAuthBytes = artifactJsonBytes(awsAuth);
  const approval = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PROTECTED_RELEASE_APPROVAL',
    candidateSha: fixtureSource.candidateSha,
    releaseId: fixtureSource.releaseId,
    releaseTag: fixtureSource.releaseTag,
    configSha256,
    approvedPlanSha256: rawSha256(approvedDiffBytes),
    approvedDiffSha256: rawSha256(rawDiff),
    iamEffectivePermissionsBindingSha256: iamEffectivePermissions.bindingSha256,
    iamEffectivePermissionsEvidenceSha256: rawSha256(awsAuthBytes),
    journalRoleEffectivePermissionsRawSha256: rawSha256(journalBytes),
    journalRoleEffectivePermissionsSha256: journalPermissions.effectivePermissionsSha256,
    ...recoveryRoleAuthority,
    freezeManifestSha256: candidateManifest.manifestSha256,
    containsSensitiveData: false,
  };
  const webDeployment = {
    schemaVersion: 1,
    stage: 7,
    kind: 'WEB_DEPLOYMENT',
    candidateSha: fixtureSource.candidateSha,
    releaseId: fixtureSource.releaseId,
    configSha256,
    containsSensitiveData: false,
  };
  const previousReleaseManifestBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PREVIOUS_APPROVED_RELEASE',
    status: 'APPROVED_IMMUTABLE',
    containsSensitiveData: false,
  };
  const previousReleaseManifest = bodyWithDigest(previousReleaseManifestBody, 'manifestSha256');
  const approvalBytes = artifactJsonBytes(approval);
  const webBytes = artifactJsonBytes(webDeployment);
  const candidateRecordBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_CANDIDATE',
    target: {
      candidateSha: fixtureSource.candidateSha,
      releaseId: fixtureSource.releaseId,
    },
    previousReleaseManifestSha256: previousReleaseManifest.manifestSha256,
    approvalSha256: rawSha256(approvalBytes),
    planSha256: rawSha256(approvedDiffBytes),
    deploymentEvidenceSha256: rawSha256(webBytes),
    containsSensitiveData: false,
  };
  const candidateRecordValue = bodyWithDigest(candidateRecordBody, 'recordSha256');
  const ordinary = (kind) => ({
    schemaVersion: 1,
    stage: 7,
    kind,
    containsSensitiveData: false,
  });
  const documents = {
    config,
    releaseMetadata,
    candidateManifest,
    releasePlan,
    approvedDiff,
    githubEnvironmentApproval,
    approval,
    awsAuth,
    journalRoleEffectivePermissions: journalPermissions,
    activation: ordinary('ACTIVATION'),
    webDeployment,
    candidateRecord: candidateRecordValue,
    externalAuthorization: {
      ...ordinary('EXTERNAL_AUTHORIZATION_PREFLIGHT'),
      stage7ConfigSha256: configSha256,
    },
    previousReleaseManifest,
    previousSourceProvenance: ordinary('PREVIOUS_SOURCE_PROVENANCE'),
    previousTargetCompatibility: ordinary('PREVIOUS_TARGET_COMPATIBILITY'),
    previousFinalDisableProvenance: ordinary('PREVIOUS_FINAL_DISABLE_PROVENANCE'),
    previousApiContractEvidence: ordinary('PREVIOUS_API_CONTRACT_EVIDENCE'),
    previousPendingEvidence: ordinary('PREVIOUS_PENDING_EVIDENCE'),
    previousSmokeEvidence: ordinary('PREVIOUS_SMOKE_EVIDENCE'),
  };
  const sources = Object.fromEntries(
    Object.entries(documents).map(([label, value]) => [label, artifactJsonBytes(value)]),
  );
  sources.rawDiff = rawDiff;
  const projectionPaths = [
    ['previousReleaseManifest', 'previous-release-manifest.json'],
    ['previousSourceProvenance', 'previous-source-provenance.json'],
    ['previousTargetCompatibility', 'previous-target-compatibility.json'],
    ['previousFinalDisableProvenance', 'previous-final-disable-provenance.json'],
    ['previousApiContractEvidence', 'previous-api-contract-evidence.json'],
    ['previousPendingEvidence', 'previous-pending-evidence.json'],
    ['previousSmokeEvidence', 'previous-smoke-evidence.json'],
  ];
  const projectionBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PREVIOUS_RELEASE_PROJECTION_INDEX',
    identity: {
      targetCandidateSha: fixtureSource.candidateSha,
      targetReleaseId: fixtureSource.releaseId,
      targetFreezeManifestSha256: candidateManifest.manifestSha256,
    },
    files: projectionPaths.map(([label, pathName]) => ({
      path: pathName,
      sha256: rawSha256(sources[label]),
      bytes: sources[label].length,
    })),
    containsSensitiveData: false,
  };
  sources.previousReleaseProjectionIndex = artifactJsonBytes(
    bodyWithDigest(projectionBody, 'projectionIndexSha256'),
  );
  return {
    sources,
    expectedRollbackRoleArn: fixtureRollbackRoleArn,
    githubIdentity: {
      repository: fixtureSource.repository,
      workflowRef: `${fixtureSource.repository}/${fixtureSource.workflowPath}@${fixtureSource.ref}`,
      ref: fixtureSource.ref,
      runId: fixtureSource.runId,
      runAttempt: 1,
      candidateSha: fixtureSource.candidateSha,
    },
  };
};

const expectedPublication = Object.freeze({
  source,
  publicationPlanSha256: 'c'.repeat(64),
  releaseName: source.releaseTag,
  notesSha256: 'd'.repeat(64),
  prerelease: false,
  asset: {
    name: 'candidate-manifest.json',
    sha256: 'e'.repeat(64),
    bytes: 123,
    contentType: 'application/json',
  },
});
const exactTag = Object.freeze({
  name: source.releaseTag,
  objectType: 'commit',
  commitSha: source.candidateSha,
});
const exactRelease = (
  assets = [
    {
      id: 42,
      name: expectedPublication.asset.name,
      state: 'uploaded',
      digest: `sha256:${expectedPublication.asset.sha256}`,
      size: expectedPublication.asset.bytes,
      contentType: expectedPublication.asset.contentType,
    },
  ],
) => ({
  id: 41,
  tagName: source.releaseTag,
  targetCommitish: source.candidateSha,
  name: source.releaseTag,
  bodySha256: expectedPublication.notesSha256,
  draft: false,
  prerelease: false,
  assets,
});
const operation = (performedOperations) => {
  const body = {
    performedOperations,
    externalWritesPerformed: performedOperations.length,
  };
  return bodyWithDigest(body, 'operationSha256');
};

const awsEnvironment = (
  workflowRef = `${source.repository}/${source.workflowPath}@${source.ref}`,
) => ({
  AWS_REGION: region,
  AWS_DEFAULT_REGION: region,
  STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN: journalRoleArn,
  STAGE7_AWS_ROLLBACK_ROLE_ARN: rollbackRoleArn,
  GITHUB_REPOSITORY: source.repository,
  GITHUB_RUN_ID: source.runId,
  GITHUB_RUN_ATTEMPT: String(source.runAttempt),
  GITHUB_SHA: source.candidateSha,
  GITHUB_REF: source.ref,
  GITHUB_WORKFLOW_REF: workflowRef,
});
const success = (value) => ({
  status: 0,
  signal: null,
  stdout: JSON.stringify(value),
  stderr: '',
});
const failure = (errorCode, { processError = undefined } = {}) => ({
  status: processError === undefined ? 254 : null,
  signal: null,
  stdout: '',
  stderr:
    processError === undefined
      ? `An error occurred (${errorCode}) when calling the test operation: denied`
      : '',
  ...(processError === undefined ? {} : { error: processError }),
});
const fakeSpawn = (handler, capability) => (_command, arguments_) => {
  simulatedAwsCalls += 1;
  if (arguments_[0] === 'sts') {
    const roleName =
      capability === 'JOURNAL' ? 'stage7-release-journal-cleanup' : 'stage7-release-reconciliation';
    return success({
      UserId: `AROATEST:${sessionName(capability)}`,
      Account: accountId,
      Arn: `arn:aws:sts::${accountId}:assumed-role/${roleName}/${sessionName(capability)}`,
    });
  }
  return handler(arguments_);
};
const awsParameter = (name, value = '{}', overrides = {}) => ({
  Name: name,
  Type: 'String',
  Value: value,
  Version: 1,
  LastModifiedDate: '2026-08-18T12:00:00.000Z',
  ARN: `arn:aws:ssm:${region}:${accountId}:parameter${name}`,
  DataType: 'text',
  ...overrides,
});
const runtimeWith = (
  handler,
  workflowRef = undefined,
  capability = 'JOURNAL',
  environmentOverrides = {},
) =>
  createAwsCliReleaseReconciliationRuntime({
    intent,
    capability,
    environmentVariables: {
      ...awsEnvironment(workflowRef),
      ...environmentOverrides,
    },
    awsCommand: 'aws-fixture',
    spawn: fakeSpawn(handler, capability),
  });

const writeJson = (filename, value) =>
  writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
const relative = (filename) => path.relative(workspaceRoot, filename);
const runCli = (arguments_, environmentOverrides = {}) =>
  spawnSync(node, [cli, ...arguments_], {
    cwd: workspaceRoot,
    encoding: 'utf8',
    env: { ...process.env, ...environmentOverrides },
    maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });

const selfTestParent = path.join(workspaceRoot, '.stage7', 'self-tests');
mkdirSync(selfTestParent, { recursive: true, mode: 0o700 });
const testRoot = mkdtempSync(path.join(selfTestParent, 'release-reconciliation-'));
const removeTestTree = (root) => {
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const child = path.join(root, entry.name);
    if (entry.isDirectory() && !entry.isSymbolicLink()) removeTestTree(child);
    else unlinkSync(child);
  }
  rmdirSync(root);
};
try {
  const semanticFixture = createIntentSourceFixture();
  let semanticIntent;
  await canary('semantic-intent-producer-derives-exact-23-bindings-and-authority', async () => {
    semanticIntent = createReleaseReconciliationIntentFromSources(semanticFixture);
    assert.equal(semanticIntent.bindings.length, 23);
    assert.equal(semanticIntent.source.runAttempt, 1);
    assert.equal(semanticIntent.authority.region, region);
    assert.equal(semanticIntent.authority.rollbackRoleArn, semanticFixture.expectedRollbackRoleArn);
    assert.equal(semanticIntent.authority.journalRoleArn, journalRoleArn);
  });

  await canary('semantic-intent-producer-rejects-missing-source', async () => {
    const missing = { ...semanticFixture, sources: { ...semanticFixture.sources } };
    delete missing.sources.approval;
    assert.throws(
      () => createReleaseReconciliationIntentFromSources(missing),
      (error) => error?.code === 'E7_RELEASE_RECONCILIATION_INTENT_SOURCE_SET_INVALID',
    );
  });

  await canary('semantic-intent-producer-rejects-reviewed-diff-tamper', async () => {
    const tampered = { ...semanticFixture, sources: { ...semanticFixture.sources } };
    const approval = JSON.parse(tampered.sources.githubEnvironmentApproval.toString('utf8'));
    approval.iamReviewedDiffSha256 = 'f'.repeat(64);
    tampered.sources.githubEnvironmentApproval = artifactJsonBytes(approval);
    assert.throws(
      () => createReleaseReconciliationIntentFromSources(tampered),
      (error) => error?.code === 'E7_RELEASE_RECONCILIATION_INTENT_APPROVAL_CHAIN_INVALID',
    );
  });
  await canary('semantic-intent-producer-rejects-recovery-authority-mismatch', async () => {
    const tampered = { ...semanticFixture, sources: { ...semanticFixture.sources } };
    const approval = JSON.parse(tampered.sources.approval.toString('utf8'));
    approval.reconciliationRecoveryRoleEffectivePermissionsSha256 = '0'.repeat(64);
    tampered.sources.approval = artifactJsonBytes(approval);
    assert.throws(
      () => createReleaseReconciliationIntentFromSources(tampered),
      (error) => error.code === 'E7_RELEASE_RECONCILIATION_INTENT_APPROVAL_CHAIN_INVALID',
    );
  });

  await canary('semantic-intent-producer-rejects-previous-file-swap', async () => {
    const swapped = { ...semanticFixture, sources: { ...semanticFixture.sources } };
    const left = swapped.sources.previousPendingEvidence;
    swapped.sources.previousPendingEvidence = swapped.sources.previousSmokeEvidence;
    swapped.sources.previousSmokeEvidence = left;
    assert.throws(
      () => createReleaseReconciliationIntentFromSources(swapped),
      (error) => error?.code === 'E7_RELEASE_RECONCILIATION_INTENT_PREVIOUS_PROJECTION_INVALID',
    );
  });

  const intentFlagLayout = [
    ['config', 'config'],
    ['releaseMetadata', 'release-metadata'],
    ['candidateManifest', 'candidate-manifest'],
    ['releasePlan', 'release-plan'],
    ['approvedDiff', 'approved-diff'],
    ['rawDiff', 'raw-diff'],
    ['githubEnvironmentApproval', 'github-environment-approval'],
    ['approval', 'approval'],
    ['awsAuth', 'aws-auth'],
    ['journalRoleEffectivePermissions', 'journal-role-effective-permissions'],
    ['activation', 'activation'],
    ['webDeployment', 'web-deployment'],
    ['candidateRecord', 'candidate-record'],
    ['externalAuthorization', 'external-authorization'],
    ['previousReleaseManifest', 'previous-release-manifest'],
    ['previousSourceProvenance', 'previous-source-provenance'],
    ['previousTargetCompatibility', 'previous-target-compatibility'],
    ['previousFinalDisableProvenance', 'previous-final-disable-provenance'],
    ['previousApiContractEvidence', 'previous-api-contract-evidence'],
    ['previousPendingEvidence', 'previous-pending-evidence'],
    ['previousSmokeEvidence', 'previous-smoke-evidence'],
    ['previousReleaseProjectionIndex', 'previous-release-projection-index'],
  ];
  const intentSourcePaths = {};
  for (const [label] of intentFlagLayout) {
    const descriptor = STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.find(
      (entry) => entry.label === label,
    );
    const directory = path.join(testRoot, 'intent-sources', label);
    mkdirSync(directory, { recursive: true });
    const filename = path.join(directory, descriptor.path);
    writeFileSync(filename, semanticFixture.sources[label], { mode: 0o600 });
    intentSourcePaths[label] = filename;
  }
  const intentOutputPath = path.join(testRoot, 'release-reconciliation-intent.json');
  const createIntentArguments = [
    'create-intent',
    ...intentFlagLayout.flatMap(([label, flag]) => [
      `--${flag}`,
      relative(intentSourcePaths[label]),
    ]),
    '--output',
    relative(intentOutputPath),
  ];
  const intentEnvironment = {
    GITHUB_REPOSITORY: semanticFixture.githubIdentity.repository,
    GITHUB_WORKFLOW_REF: semanticFixture.githubIdentity.workflowRef,
    GITHUB_REF: semanticFixture.githubIdentity.ref,
    GITHUB_RUN_ID: semanticFixture.githubIdentity.runId,
    GITHUB_RUN_ATTEMPT: String(semanticFixture.githubIdentity.runAttempt),
    GITHUB_SHA: semanticFixture.githubIdentity.candidateSha,
  };
  await canary('create-intent-cli-consumes-exact-files-and-emits-validated-intent', async () => {
    const result = runCli(createIntentArguments, intentEnvironment);
    assert.equal(result.status, 0, result.stderr);
    const value = JSON.parse(readFileSync(intentOutputPath, 'utf8'));
    assert.deepEqual(value, semanticIntent);
  });

  await canary('create-intent-cli-rejects-swapped-basename', async () => {
    const arguments_ = [...createIntentArguments];
    const approvalFlagIndex = arguments_.indexOf('--approval');
    arguments_[approvalFlagIndex + 1] = relative(intentSourcePaths.activation);
    arguments_[arguments_.length - 1] = relative(path.join(testRoot, 'swapped-intent.json'));
    const result = runCli(arguments_, intentEnvironment);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /E7_RELEASE_RECONCILIATION_CLI_INTENT_BASENAME_INVALID/u);
  });

  await canary('create-intent-cli-rejects-attempt-two-without-aws', async () => {
    const arguments_ = [...createIntentArguments];
    arguments_[arguments_.length - 1] = relative(path.join(testRoot, 'attempt-two-intent.json'));
    const result = runCli(arguments_, {
      ...intentEnvironment,
      GITHUB_RUN_ATTEMPT: '2',
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /E7_RELEASE_RECONCILIATION_INTENT_IDENTITY_INVALID/u);
  });

  const store = fakeStore();
  let owner;
  await canary('owner-created-before-mutation', async () => {
    const result = await openReleaseRollbackJournal({
      intent,
      store,
      clock: () => new Date('2026-08-18T12:00:00.000Z'),
    });
    owner = result.owner;
    assert.equal(result.idempotent, false);
    assert.equal(result.journalEntryCount, 1 + owner.intentChunks.length);
    assert.equal(result.owner.parameterName, ownerName);
    assert.equal(result.owner.candidateRootPrefix, candidateRootPrefix);
    assert.equal(result.owner.reconciliationRootPrefix, reconciliationRootPrefix);
  });

  await canary('owner-idempotent-same-run-attempt-one', async () => {
    const result = await openReleaseRollbackJournal({
      intent,
      store,
      clock: () => new Date('2026-08-18T13:00:00.000Z'),
    });
    assert.equal(result.idempotent, true);
    assert.equal(result.owner.ownerSha256, owner.ownerSha256);
  });

  await canary('crash-after-owner-resumes-missing-intent-chunks', async () => {
    const interruptedStore = fakeStore();
    await assert.rejects(
      () =>
        openReleaseRollbackJournal({
          intent,
          store: failOnPut(interruptedStore, 2),
          clock: () => new Date('2026-08-18T12:00:00.000Z'),
        }),
      /simulated crash/u,
    );
    assert.deepEqual([...fakeStoreEntries.get(interruptedStore).keys()], [ownerName]);
    const resumed = await openReleaseRollbackJournal({ intent, store: interruptedStore });
    assert.equal(resumed.idempotent, true);
    assert.equal(resumed.journalEntryCount, 1 + resumed.owner.intentChunks.length);
  });

  await canary('crash-after-intent-chunk-k-resumes-exactly', async () => {
    const interruptedStore = fakeStore();
    await assert.rejects(
      () =>
        openReleaseRollbackJournal({
          intent,
          store: failOnPut(interruptedStore, 3),
          clock: () => new Date('2026-08-18T12:00:00.000Z'),
        }),
      /simulated crash/u,
    );
    assert.equal(fakeStoreEntries.get(interruptedStore).size, 2);
    const resumed = await openReleaseRollbackJournal({ intent, store: interruptedStore });
    assert.equal(resumed.idempotent, true);
    assert.equal(resumed.journalEntryCount, 1 + resumed.owner.intentChunks.length);
  });

  await canary('unexpected-entry-inside-owned-reconciliation-subtree-blocks', async () => {
    const unexpectedStore = fakeStore();
    await openReleaseRollbackJournal({ intent, store: unexpectedStore });
    const unexpectedName = `${reconciliationRootPrefix}/unexpected`;
    fakeStoreEntries.get(unexpectedStore).set(unexpectedName, parameter(unexpectedName, '{}', 99));
    await rejectsCode('E7_RELEASE_RECONCILIATION_JOURNAL_UNEXPECTED_ENTRY', () =>
      requireReleaseRollbackJournalOwner({ intent, store: unexpectedStore }),
    );
  });

  await canary('malformed-orphan-proof-parameter-is-rejected', async () => {
    const malformedStore = fakeStore();
    await openReleaseRollbackJournal({ intent, store: malformedStore });
    const malformedName = `${reconciliationRootPrefix}/runtime-proofs/rollback-check/drift/${'a'.repeat(64)}/chunk/0001-${'b'.repeat(64)}`;
    fakeStoreEntries.get(malformedStore).set(malformedName, parameter(malformedName, '{}', 99));
    await rejectsCode('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_CHUNK_MISMATCH', () =>
      requireReleaseRollbackJournalOwner({ intent, store: malformedStore }),
    );
  });

  await canary('malformed-known-terminal-entry-blocks-before-runtime-mutation', async () => {
    const malformedStore = fakeStore();
    await openReleaseRollbackJournal({ intent, store: malformedStore });
    const malformedName = `${reconciliationRootPrefix}/rollback-check/terminal`;
    fakeStoreEntries.get(malformedStore).set(malformedName, parameter(malformedName, '{}', 99));
    await rejectsCode('E7_RELEASE_RECONCILIATION_TERMINAL_INVALID', () =>
      requireReleaseRollbackJournalOwner({ intent, store: malformedStore }),
    );
  });

  await canary('owner-binding-conflict-blocked', async () => {
    const conflictingIntent = createReleaseReconciliationIntent({
      source,
      authority: intent.authority,
      bindings: intentBindings.map((binding, index) =>
        index === 0 ? { ...binding, rawSha256: 'f'.repeat(64) } : binding,
      ),
    });
    await rejectsCode('E7_RELEASE_RECONCILIATION_OWNER_CONFLICT', () =>
      requireReleaseRollbackJournalOwner({
        intent: conflictingIntent,
        store,
      }),
    );
  });

  await canary('existing-rb-journal-outside-reconciliation-does-not-block', async () => {
    const foreignName = `${candidateRootPrefix}/RB-E7-06/000001-${'1'.repeat(64)}/manifest`;
    const blockedStore = fakeStore([parameter(foreignName, '{}')]);
    const result = await openReleaseRollbackJournal({ intent, store: blockedStore });
    assert.equal(result.idempotent, false);
  });

  await canary('foreign-or-unowned-reconciliation-entry-is-blocked', async () => {
    const foreignName = `${reconciliationRootPrefix}/foreign`;
    const blockedStore = fakeStore([parameter(foreignName, '{}')]);
    await rejectsCode('E7_RELEASE_RECONCILIATION_UNOWNED_JOURNAL_BLOCKED', () =>
      openReleaseRollbackJournal({
        intent,
        store: blockedStore,
      }),
    );
  });

  const candidatePath = path.join(testRoot, 'candidate.json');
  const transitionPath = path.join(testRoot, 'transition.json');
  writeJson(candidatePath, candidateRecord());
  const converge = async (phase, transitionValue) =>
    convergeVersionedReleaseRuntime({
      phase,
      intent,
      store,
      rollbackFlags: { 'candidate-record': candidatePath, output: transitionPath },
      clock: () => new Date(transitionValue.startedAtUtc),
      executeRollback: async ({ flags }) => {
        assert.equal(flags.direction, 'REPROMOTE_CANDIDATE');
        writeJson(flags.output, transitionValue);
        return clone(transitionValue);
      },
    });

  await canary('terminal-probe-is-absent-before-runtime-mutation', async () => {
    const probe = await probeVersionedReleaseRuntimeTerminal({
      phase: 'ROLLBACK_CHECK',
      intent,
      originalJobConclusion: 'SUCCESS',
      store,
    });
    assert.equal(probe.status, 'TERMINAL_ABSENT');
    assert.equal(probe.externalWritesPerformed, 0);
    assert.equal(validateReleaseRuntimeTerminalProbe(probe), probe);
  });

  let rollbackCheckConvergence;
  await canary('exact-candidate-n-noop-convergence', async () => {
    rollbackCheckConvergence = await converge('ROLLBACK_CHECK', transition());
    assert.equal(rollbackCheckConvergence.recoveryAction, 'VERIFIED_NOOP');
    assert.equal(
      validateReleaseRuntimeConvergence(rollbackCheckConvergence),
      rollbackCheckConvergence,
    );
  });

  await canary('lost-convergence-checkpoint-is-rebuilt-from-sealed-transition', async () => {
    const putsBefore = fakeStoreStats.get(store).puts;
    const recovered = await recoverVersionedReleaseRuntimeConvergenceCheckpoint({
      phase: 'ROLLBACK_CHECK',
      intent,
      candidateRecordSource: readFileSync(candidatePath),
      transitionSource: readFileSync(transitionPath),
      store,
    });
    assert.deepEqual(recovered, rollbackCheckConvergence);
    assert.equal(fakeStoreStats.get(store).puts, putsBefore);
  });

  await canary('existing-convergence-revalidates-original-transition-bytes', async () => {
    const putsBefore = fakeStoreStats.get(store).puts;
    const recovered = await recoverVersionedReleaseRuntimeConvergenceCheckpoint({
      phase: 'ROLLBACK_CHECK',
      intent,
      candidateRecordSource: readFileSync(candidatePath),
      transitionSource: readFileSync(transitionPath),
      expectedConvergence: rollbackCheckConvergence,
      store,
    });
    assert.equal(recovered.convergenceSha256, rollbackCheckConvergence.convergenceSha256);
    assert.equal(fakeStoreStats.get(store).puts, putsBefore);
  });

  await canary('convergence-transition-raw-byte-swap-is-rejected', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_CONVERGENCE_CHECKPOINT_CONFLICT', () =>
      recoverVersionedReleaseRuntimeConvergenceCheckpoint({
        phase: 'ROLLBACK_CHECK',
        intent,
        candidateRecordSource: readFileSync(candidatePath),
        transitionSource: jsonBytes(transition()),
        expectedConvergence: rollbackCheckConvergence,
        store,
      }),
    );
  });

  await canary('mixed-runtime-state-blocked', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_RUNTIME_NOT_CANDIDATE_N', () =>
      converge('ROLLBACK_CHECK', transition({ apiVersion: '8' })),
    );
  });

  await canary('transition-shape-and-digest-bound', async () => {
    const tampered = clone(rollbackCheckConvergence);
    tampered.transition.pendingIntegrity.lostFacts = 1;
    tampered.transition.transitionSha256 = objectSha256({
      ...tampered.transition,
      transitionSha256: undefined,
    });
    await rejectsCode('E7_RELEASE_RECONCILIATION_CONVERGENCE_INVALID', async () =>
      validateReleaseRuntimeConvergence(tampered),
    );
  });

  const rollbackCheckDriftSource = jsonBytes(driftEvidence('2026-08-18T12:01:45.000Z'));
  const rollbackCheckSmokeSource = jsonBytes(
    smokeEvidence('2026-08-18T12:02:00.000Z', rollbackCheckConvergence),
  );

  await canary('missing-drift-evidence-blocks-finalize', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_DRIFT_EVIDENCE_INVALID', () =>
      finalizeVersionedReleaseRuntimeReconciliation({
        convergence: rollbackCheckConvergence,
        originalJobConclusion: 'SUCCESS',
        driftEvidenceSource: Buffer.from('missing'),
        smokeEvidenceSource: rollbackCheckSmokeSource,
        store,
      }),
    );
  });

  await canary('missing-smoke-evidence-blocks-finalize', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_SMOKE_EVIDENCE_INVALID', () =>
      finalizeVersionedReleaseRuntimeReconciliation({
        convergence: rollbackCheckConvergence,
        originalJobConclusion: 'SUCCESS',
        driftEvidenceSource: rollbackCheckDriftSource,
        smokeEvidenceSource: Buffer.from('missing'),
        store,
      }),
    );
  });

  await canary('stale-drift-evidence-blocks-finalize', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_DRIFT_EVIDENCE_STALE', () =>
      finalizeVersionedReleaseRuntimeReconciliation({
        convergence: rollbackCheckConvergence,
        originalJobConclusion: 'SUCCESS',
        driftEvidenceSource: jsonBytes(driftEvidence('2026-08-18T12:01:29.999Z')),
        smokeEvidenceSource: rollbackCheckSmokeSource,
        store,
      }),
    );
  });

  await canary('stale-smoke-evidence-blocks-finalize', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_SMOKE_EVIDENCE_STALE', () =>
      finalizeVersionedReleaseRuntimeReconciliation({
        convergence: rollbackCheckConvergence,
        originalJobConclusion: 'SUCCESS',
        driftEvidenceSource: rollbackCheckDriftSource,
        smokeEvidenceSource: jsonBytes(
          smokeEvidence('2026-08-18T12:01:29.999Z', rollbackCheckConvergence),
        ),
        store,
      }),
    );
  });

  await canary('smoke-phase-intent-convergence-and-usage-bindings-are-exact', async () => {
    const mutations = [
      (value) => {
        value.reconciliation.phase = 'ROLLBACK_RESILIENCE';
      },
      (value) => {
        value.reconciliation.intentSha256 = 'f'.repeat(64);
      },
      (value) => {
        value.reconciliation.convergenceSha256 = 'e'.repeat(64);
      },
      (value) => {
        value.authorizationUsage.usageId = 'POST_REPROMOTION_VERSIONED';
      },
      (value) => {
        value.authorizationUsage.bundleSha256 = '0'.repeat(64);
      },
      (value) => {
        value.authorizationUsage.requestCounts['AUTH-E7-EXT-01'] = 2;
      },
      (value) => {
        value.authorizationUsage.unexpectedField = false;
      },
    ];
    const putsBefore = fakeStoreStats.get(store).puts;
    for (const mutate of mutations) {
      const value = smokeEvidence('2026-08-18T12:02:00.000Z', rollbackCheckConvergence);
      mutate(value);
      await rejectsCode('E7_RELEASE_RECONCILIATION_SMOKE_EVIDENCE_INVALID', () =>
        finalizeVersionedReleaseRuntimeReconciliation({
          convergence: rollbackCheckConvergence,
          originalJobConclusion: 'SUCCESS',
          driftEvidenceSource: rollbackCheckDriftSource,
          smokeEvidenceSource: jsonBytes(value),
          store,
          clock: () => new Date('2026-08-18T12:03:00.000Z'),
        }),
      );
    }
    assert.equal(fakeStoreStats.get(store).puts, putsBefore);
  });

  await canary('terminal-time-must-follow-both-fresh-proofs', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_TERMINAL_TIME_INVALID', () =>
      finalizeVersionedReleaseRuntimeReconciliation({
        convergence: rollbackCheckConvergence,
        originalJobConclusion: 'SUCCESS',
        driftEvidenceSource: rollbackCheckDriftSource,
        smokeEvidenceSource: rollbackCheckSmokeSource,
        store,
        clock: () => new Date('2026-08-18T12:01:59.999Z'),
      }),
    );
  });

  let rollbackCheckReceipt;
  let rollbackCheckTerminal;
  await canary('rollback-check-terminal-n-created', async () => {
    const result = await finalizeVersionedReleaseRuntimeReconciliation({
      convergence: rollbackCheckConvergence,
      originalJobConclusion: 'SUCCESS',
      driftEvidenceSource: rollbackCheckDriftSource,
      smokeEvidenceSource: rollbackCheckSmokeSource,
      store,
      clock: () => new Date('2026-08-18T12:03:00.000Z'),
    });
    rollbackCheckReceipt = result.receipt;
    rollbackCheckTerminal = result.terminal;
    assert.equal(result.idempotent, false);
    assert.equal(result.receipt.eligibleForFence, true);
    validateReleaseReconciliationReceipt(result.receipt);
  });

  await canary('smoke-authorization-ledger-is-sanitized-and-terminal-bound', async () => {
    assert.deepEqual(rollbackCheckReceipt.runtime.smokeAuthorizationUsage, {
      schemaVersion: 1,
      phase: 'ROLLBACK_CHECK',
      usageId: 'RECONCILIATION_ROLLBACK_CHECK_SMOKE',
      authorizationSha256: 'd'.repeat(64),
      bundleSha256: 'd'.repeat(64),
      configSha256: source.configSha256,
      candidateSha: source.candidateSha,
      releaseId: source.releaseId,
      ownedOriginSha256: 'e'.repeat(64),
      sandboxHostSha256: 'f'.repeat(64),
      requestCounts: {
        'AUTH-E7-EXT-01': 3,
        'AUTH-E7-EXT-02': 0,
        'AUTH-E7-EXT-03': 0,
      },
      total: 3,
      passed: 3,
      failed: 0,
      containsSensitiveData: false,
    });
    assert.equal(
      rollbackCheckTerminal.smokeAuthorizationUsageSha256,
      objectSha256(rollbackCheckReceipt.runtime.smokeAuthorizationUsage),
    );
    assert.equal(
      JSON.stringify(rollbackCheckReceipt.runtime.smokeAuthorizationUsage).includes('token'),
      false,
    );
  });

  await canary('rehashed-terminal-cannot-move-convergence-after-fresh-proofs', async () => {
    const tampered = clone(rollbackCheckTerminal);
    tampered.convergenceCompletedAtUtc = '2026-08-18T12:02:00.001Z';
    tampered.observedAtUtc = '2026-08-18T12:02:00.001Z';
    delete tampered.terminalSha256;
    tampered.terminalSha256 = objectSha256(tampered);
    assert.throws(
      () => validateReleaseReconciliationTerminal(tampered),
      (error) => error?.code === 'E7_RELEASE_RECONCILIATION_TERMINAL_INVALID',
    );
  });

  await canary('terminal-lost-response-retry-is-idempotent', async () => {
    const result = await finalizeVersionedReleaseRuntimeReconciliation({
      convergence: rollbackCheckConvergence,
      originalJobConclusion: 'SUCCESS',
      driftEvidenceSource: rollbackCheckDriftSource,
      smokeEvidenceSource: rollbackCheckSmokeSource,
      store,
      clock: () => new Date('2026-08-18T14:00:00.000Z'),
    });
    assert.equal(result.idempotent, true);
    assert.equal(result.receipt.receiptSha256, rollbackCheckReceipt.receiptSha256);
  });

  await canary('terminal-evidence-tamper-cannot-reconstruct-receipt', async () => {
    const tampered = driftEvidence('2026-08-18T12:01:45.000Z');
    tampered.untrusted = true;
    await rejectsCode('E7_RELEASE_RECONCILIATION_RESUME_EVIDENCE_MISMATCH', () =>
      resumeVersionedReleaseRuntimeReconciliation({
        phase: 'ROLLBACK_CHECK',
        intent,
        originalJobConclusion: 'SUCCESS',
        driftEvidenceSource: jsonBytes(tampered),
        smokeEvidenceSource: rollbackCheckSmokeSource,
        store,
      }),
    );
  });

  await canary('terminal-evidence-raw-bytes-are-bound-on-resume', async () => {
    const sameDriftDifferentBytes = artifactJsonBytes(driftEvidence('2026-08-18T12:01:45.000Z'));
    assert.equal(
      objectSha256(JSON.parse(sameDriftDifferentBytes.toString('utf8'))),
      objectSha256(JSON.parse(rollbackCheckDriftSource.toString('utf8'))),
    );
    await rejectsCode('E7_RELEASE_RECONCILIATION_RESUME_EVIDENCE_MISMATCH', () =>
      resumeVersionedReleaseRuntimeReconciliation({
        phase: 'ROLLBACK_CHECK',
        intent,
        originalJobConclusion: 'SUCCESS',
        driftEvidenceSource: sameDriftDifferentBytes,
        smokeEvidenceSource: rollbackCheckSmokeSource,
        store,
      }),
    );
  });

  await canary('existing-terminal-blocks-reconvergence-before-rollback', async () => {
    let rollbackExecutions = 0;
    await rejectsCode('E7_RELEASE_RECONCILIATION_TERMINAL_ALREADY_EXISTS', () =>
      convergeVersionedReleaseRuntime({
        phase: 'ROLLBACK_CHECK',
        intent,
        store,
        rollbackFlags: { 'candidate-record': candidatePath, output: transitionPath },
        executeRollback: async () => {
          rollbackExecutions += 1;
        },
      }),
    );
    assert.equal(rollbackExecutions, 0);
  });

  let rollbackResilienceReceipt;
  await canary('rollback-resilience-terminal-n-created', async () => {
    const convergence = await converge(
      'ROLLBACK_RESILIENCE',
      transition({
        startedAtUtc: '2026-08-18T12:04:00.000Z',
        completedAtUtc: '2026-08-18T12:05:00.000Z',
      }),
    );
    const rollbackResilienceDriftSource = jsonBytes(driftEvidence('2026-08-18T12:06:30.000Z'));
    const result = await finalizeVersionedReleaseRuntimeReconciliation({
      convergence,
      originalJobConclusion: 'SUCCESS',
      driftEvidenceSource: rollbackResilienceDriftSource,
      smokeEvidenceSource: jsonBytes(smokeEvidence('2026-08-18T12:06:00.000Z', convergence)),
      store,
      clock: () => new Date('2026-08-18T12:07:00.000Z'),
    });
    rollbackResilienceReceipt = result.receipt;
    assert.equal(result.receipt.eligibleForFence, true);
  });

  await canary('crash-after-terminal-put-probes-and-resumes-with-zero-writes', async () => {
    const before = fakeStoreEntries.get(store).size;
    const putsBefore = fakeStoreStats.get(store).puts;
    const probe = await probeVersionedReleaseRuntimeTerminal({
      phase: 'ROLLBACK_CHECK',
      intent,
      originalJobConclusion: 'SUCCESS',
      store,
    });
    assert.equal(probe.status, 'TERMINAL_PRESENT');
    const result = await resumeVersionedReleaseRuntimeReconciliation({
      phase: 'ROLLBACK_CHECK',
      intent,
      originalJobConclusion: 'SUCCESS',
      driftEvidenceSource: rollbackCheckDriftSource,
      smokeEvidenceSource: rollbackCheckSmokeSource,
      store,
    });
    assert.equal(result.status, 'TERMINAL_RECEIPT_REUSED');
    assert.equal(result.receipt.receiptSha256, rollbackCheckReceipt.receiptSha256);
    assert.equal(fakeStoreEntries.get(store).size, before);
    assert.equal(fakeStoreStats.get(store).puts, putsBefore);
    assert.equal(result.rollbackExecutionPerformed, false);
    assert.equal(result.terminalWritePerformed, false);
  });

  await canary('terminal-probe-rejects-different-original-conclusion-before-mutation', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_TERMINAL_CONFLICT', () =>
      probeVersionedReleaseRuntimeTerminal({
        phase: 'ROLLBACK_CHECK',
        intent,
        originalJobConclusion: 'FAILURE',
        store,
      }),
    );
  });

  await canary('lost-terminal-put-response-resumes-identical-receipt-with-zero-put', async () => {
    const crashSource = { ...source, runId: '123456791' };
    const crashIntent = createReleaseReconciliationIntent({
      source: crashSource,
      authority: intent.authority,
      bindings: intent.bindings,
    });
    const crashStore = fakeStore([], crashSource);
    await openReleaseRollbackJournal({
      intent: crashIntent,
      store: crashStore,
      clock: () => new Date('2026-08-18T12:00:00.000Z'),
    });
    const convergence = await convergeVersionedReleaseRuntime({
      phase: 'ROLLBACK_CHECK',
      intent: crashIntent,
      store: crashStore,
      rollbackFlags: { 'candidate-record': candidatePath, output: transitionPath },
      executeRollback: async ({ flags }) => {
        const value = transition();
        writeJson(flags.output, value);
        return value;
      },
    });
    const crashSmokeSource = jsonBytes(smokeEvidence('2026-08-18T12:02:00.000Z', convergence));
    const lostResponseStore = {
      candidateRootPrefix: crashStore.candidateRootPrefix,
      reconciliationRootPrefix: crashStore.reconciliationRootPrefix,
      get: crashStore.get,
      list: crashStore.list,
      putImmutable: async (request) => {
        const written = await crashStore.putImmutable(request);
        if (request.name.endsWith('/rollback-check/terminal')) {
          const error = new Error('simulated terminal put response loss');
          error.code = 'SIMULATED_TERMINAL_PUT_RESPONSE_LOSS';
          throw error;
        }
        return written;
      },
    };
    await assert.rejects(
      () =>
        finalizeVersionedReleaseRuntimeReconciliation({
          convergence,
          originalJobConclusion: 'SUCCESS',
          driftEvidenceSource: rollbackCheckDriftSource,
          smokeEvidenceSource: crashSmokeSource,
          store: lostResponseStore,
          clock: () => new Date('2026-08-18T12:03:00.000Z'),
        }),
      (error) => error?.code === 'SIMULATED_TERMINAL_PUT_RESPONSE_LOSS',
    );
    const writesAfterCrash = fakeStoreStats.get(crashStore).puts;
    const probe = await probeVersionedReleaseRuntimeTerminal({
      phase: 'ROLLBACK_CHECK',
      intent: crashIntent,
      originalJobConclusion: 'SUCCESS',
      store: crashStore,
    });
    assert.equal(probe.status, 'TERMINAL_PRESENT');
    const resumed = await resumeVersionedReleaseRuntimeReconciliation({
      phase: 'ROLLBACK_CHECK',
      intent: crashIntent,
      originalJobConclusion: 'SUCCESS',
      store: crashStore,
    });
    assert.equal(resumed.status, 'TERMINAL_RECEIPT_REUSED');
    assert.equal(resumed.receipt.runtime.driftObservedAtUtc, '2026-08-18T12:01:45.000Z');
    assert.equal(resumed.receipt.runtime.smokeObservedAtUtc, '2026-08-18T12:02:00.000Z');
    assert.equal(
      resumed.receipt.runtime.smokeAuthorizationUsage.usageId,
      'RECONCILIATION_ROLLBACK_CHECK_SMOKE',
    );
    assert.equal(fakeStoreStats.get(crashStore).puts, writesAfterCrash);
  });

  await canary('crash-after-partial-proof-chunks-resumes-before-terminal', async () => {
    const chunkSource = { ...source, runId: '123456792' };
    const chunkIntent = createReleaseReconciliationIntent({
      source: chunkSource,
      authority: intent.authority,
      bindings: intent.bindings,
    });
    const chunkStore = fakeStore([], chunkSource);
    await openReleaseRollbackJournal({
      intent: chunkIntent,
      store: chunkStore,
      clock: () => new Date('2026-08-18T12:00:00.000Z'),
    });
    const convergence = await convergeVersionedReleaseRuntime({
      phase: 'ROLLBACK_CHECK',
      intent: chunkIntent,
      store: chunkStore,
      rollbackFlags: { 'candidate-record': candidatePath, output: transitionPath },
      executeRollback: async ({ flags }) => {
        const value = transition();
        writeJson(flags.output, value);
        return value;
      },
    });
    const chunkSmokeSource = jsonBytes(smokeEvidence('2026-08-18T12:02:00.000Z', convergence));
    const largeDrift = driftEvidence('2026-08-18T12:01:45.000Z');
    largeDrift.padding = 'x'.repeat(6500);
    const largeDriftSource = jsonBytes(largeDrift);
    const partialDriftRawSha256 = createHash('sha256').update(largeDriftSource).digest('hex');
    let proofChunkWrites = 0;
    const interruptedStore = {
      candidateRootPrefix: chunkStore.candidateRootPrefix,
      reconciliationRootPrefix: chunkStore.reconciliationRootPrefix,
      get: chunkStore.get,
      list: chunkStore.list,
      putImmutable: async (request) => {
        if (request.name.includes('/runtime-proofs/') && request.name.includes('/chunk/')) {
          proofChunkWrites += 1;
          if (proofChunkWrites === 2) {
            const error = new Error('simulated partial proof crash');
            error.code = 'SIMULATED_PARTIAL_PROOF_CRASH';
            throw error;
          }
        }
        return chunkStore.putImmutable(request);
      },
    };
    await assert.rejects(
      () =>
        finalizeVersionedReleaseRuntimeReconciliation({
          convergence,
          originalJobConclusion: 'SUCCESS',
          driftEvidenceSource: largeDriftSource,
          smokeEvidenceSource: chunkSmokeSource,
          store: interruptedStore,
          clock: () => new Date('2026-08-18T12:03:00.000Z'),
        }),
      (error) => error?.code === 'SIMULATED_PARTIAL_PROOF_CRASH',
    );
    const partialEntries = [...fakeStoreEntries.get(chunkStore).values()].filter(({ name }) =>
      name.includes('/runtime-proofs/'),
    );
    assert.equal(partialEntries.length, 1);
    assert.equal(
      [...fakeStoreEntries.get(chunkStore).keys()].some((name) => name.endsWith('/terminal')),
      false,
    );
    const freshLargeDrift = driftEvidence('2026-08-18T12:01:46.000Z');
    freshLargeDrift.padding = 'y'.repeat(6500);
    const freshLargeDriftSource = jsonBytes(freshLargeDrift);
    const freshDriftRawSha256 = createHash('sha256').update(freshLargeDriftSource).digest('hex');
    const recovered = await finalizeVersionedReleaseRuntimeReconciliation({
      convergence,
      originalJobConclusion: 'SUCCESS',
      driftEvidenceSource: freshLargeDriftSource,
      smokeEvidenceSource: chunkSmokeSource,
      store: chunkStore,
      clock: () => new Date('2026-08-18T12:03:00.000Z'),
    });
    assert.equal(recovered.receipt.status, 'TERMINAL_CANDIDATE_N_VERIFIED');
    assert.ok(recovered.receipt.journal.runtimeProofParameters.length >= 6);
    const recoveredProofNames = recovered.receipt.journal.runtimeProofParameters.map(
      ({ name }) => name,
    );
    assert.ok(
      recoveredProofNames.some((name) => name.includes(`/drift/${partialDriftRawSha256}/chunk/`)),
    );
    assert.equal(
      recovered.receipt.runtime.driftProofJournal.indexParameterName.includes(
        `/drift/${freshDriftRawSha256}/index`,
      ),
      true,
    );
    assert.equal(recovered.receipt.journal.runtimeProofParameterCount, recoveredProofNames.length);
    assert.equal(
      recovered.receipt.journal.runtimeProofParametersSha256,
      objectSha256(recovered.receipt.journal.runtimeProofParameters),
    );
    const resilienceConvergence = await convergeVersionedReleaseRuntime({
      phase: 'ROLLBACK_RESILIENCE',
      intent: chunkIntent,
      store: chunkStore,
      rollbackFlags: { 'candidate-record': candidatePath, output: transitionPath },
      executeRollback: async ({ flags }) => {
        const value = transition({
          startedAtUtc: '2026-08-18T12:04:00.000Z',
          completedAtUtc: '2026-08-18T12:05:00.000Z',
        });
        writeJson(flags.output, value);
        return value;
      },
    });
    const resilience = await finalizeVersionedReleaseRuntimeReconciliation({
      convergence: resilienceConvergence,
      originalJobConclusion: 'SUCCESS',
      driftEvidenceSource: jsonBytes(driftEvidence('2026-08-18T12:06:30.000Z')),
      smokeEvidenceSource: jsonBytes(
        smokeEvidence('2026-08-18T12:06:00.000Z', resilienceConvergence),
      ),
      store: chunkStore,
      clock: () => new Date('2026-08-18T12:07:00.000Z'),
    });
    const gate = createReleasePreFenceGate({
      rollbackCheckSource: jsonBytes(recovered.receipt),
      rollbackResilienceSource: jsonBytes(resilience.receipt),
      evaluatedAtUtc: '2026-08-18T12:08:00.000Z',
    });
    assert.equal(
      recoveredProofNames.every((name) =>
        gate.reconciliationJournalAuthority.cleanupParameterNames.includes(name),
      ),
      true,
    );
  });

  await canary('recovered-original-failure-remains-fence-ineligible', async () => {
    const failureSource = { ...source, runId: '123456790' };
    const failureIntent = createReleaseReconciliationIntent({
      source: failureSource,
      authority: intent.authority,
      bindings: intent.bindings,
    });
    const failureStore = fakeStore([], failureSource);
    await openReleaseRollbackJournal({
      intent: failureIntent,
      store: failureStore,
      clock: () => new Date('2026-08-18T12:00:00.000Z'),
    });
    const applied = transition({ decision: 'APPLIED_AND_VERIFIED' });
    const convergence = await convergeVersionedReleaseRuntime({
      phase: 'ROLLBACK_CHECK',
      intent: failureIntent,
      store: failureStore,
      rollbackFlags: { 'candidate-record': candidatePath, output: transitionPath },
      executeRollback: async ({ flags }) => {
        const value = {
          ...applied,
          toReleaseId: failureSource.releaseId,
        };
        value.transitionSha256 = objectSha256(
          Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'transitionSha256')),
        );
        writeJson(flags.output, value);
        return value;
      },
    });
    const result = await finalizeVersionedReleaseRuntimeReconciliation({
      convergence,
      originalJobConclusion: 'FAILURE',
      driftEvidenceSource: jsonBytes(driftEvidence('2026-08-18T12:01:45.000Z')),
      smokeEvidenceSource: jsonBytes(smokeEvidence('2026-08-18T12:02:00.000Z', convergence)),
      store: failureStore,
      clock: () => new Date('2026-08-18T12:03:00.000Z'),
    });
    assert.equal(result.receipt.recoveryAction, 'REPROMOTED_CANDIDATE');
    assert.equal(result.receipt.eligibleForFence, false);
  });

  await canary('publication-absent-converges-forward-only', async () => {
    let observation = { tag: exactTag, release: null };
    const result = await executeReleasePublicationForwardReconciliation({
      expected: expectedPublication,
      observe: async () => clone(observation),
      publish: async ({ permittedOperations }) => {
        observation = { tag: exactTag, release: exactRelease() };
        return operation(permittedOperations);
      },
    });
    assert.equal(result.before.state, 'ABSENT');
    assert.equal(result.after.state, 'EXACT');
    assert.equal(result.externalWritesPerformed, 2);
    assert.equal(result.destructiveOperationsPerformed, 0);
  });

  await canary('publication-partial-uploads-only-missing-asset', async () => {
    let observation = { tag: exactTag, release: exactRelease([]) };
    const result = await executeReleasePublicationForwardReconciliation({
      expected: expectedPublication,
      observe: async () => clone(observation),
      publish: async ({ permittedOperations }) => {
        assert.deepEqual(permittedOperations, ['UPLOAD_EXACT_ASSET']);
        observation = { tag: exactTag, release: exactRelease() };
        return operation(permittedOperations);
      },
    });
    assert.equal(result.externalWritesPerformed, 1);
  });

  await canary('publication-exact-is-zero-write-noop', async () => {
    let publishCalls = 0;
    const result = await executeReleasePublicationForwardReconciliation({
      expected: expectedPublication,
      observe: async () => ({ tag: exactTag, release: exactRelease() }),
      publish: async () => {
        publishCalls += 1;
        throw new Error('must not publish');
      },
    });
    assert.equal(result.before.state, 'EXACT');
    assert.equal(result.externalWritesPerformed, 0);
    assert.equal(publishCalls, 0);
  });

  await canary('publication-conflict-blocks-with-zero-writes', async () => {
    let publishCalls = 0;
    const conflicting = exactRelease();
    conflicting.assets[0].digest = `sha256:${'f'.repeat(64)}`;
    const result = await executeReleasePublicationForwardReconciliation({
      expected: expectedPublication,
      observe: async () => ({ tag: exactTag, release: conflicting }),
      publish: async () => {
        publishCalls += 1;
      },
    });
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.before.state, 'CONFLICT');
    assert.equal(publishCalls, 0);
  });

  await canary('publication-operation-is-hash-and-set-bound', async () => {
    await rejectsCode('E7_RELEASE_RECONCILIATION_PUBLICATION_OPERATION_INVALID', () =>
      executeReleasePublicationForwardReconciliation({
        expected: expectedPublication,
        observe: async () => ({ tag: exactTag, release: null }),
        publish: async ({ permittedOperations }) => ({
          ...operation(permittedOperations),
          operationSha256: '0'.repeat(64),
        }),
      }),
    );
  });

  await canary('publication-lost-response-retries-as-exact-noop', async () => {
    let observation = { tag: exactTag, release: null };
    await assert.rejects(() =>
      executeReleasePublicationForwardReconciliation({
        expected: expectedPublication,
        observe: async () => clone(observation),
        publish: async () => {
          observation = { tag: exactTag, release: exactRelease() };
          throw new Error('ambiguous response');
        },
      }),
    );
    const retry = await executeReleasePublicationForwardReconciliation({
      expected: expectedPublication,
      observe: async () => clone(observation),
      publish: async () => {
        throw new Error('must not publish on retry');
      },
    });
    assert.equal(retry.before.state, 'EXACT');
    assert.equal(retry.externalWritesPerformed, 0);
  });

  await canary('workflow-ref-suffix-is-rejected-before-aws', async () => {
    const before = simulatedAwsCalls;
    assert.throws(
      () =>
        runtimeWith(
          () => success({}),
          `${source.repository}/${source.workflowPath}@${source.ref}-attacker`,
        ),
      (error) => error?.code === 'E7_RELEASE_RECONCILIATION_GITHUB_IDENTITY_INVALID',
    );
    assert.equal(simulatedAwsCalls, before);
  });

  await canary('wrong-region-is-rejected-before-aws', async () => {
    const before = simulatedAwsCalls;
    assert.throws(
      () => runtimeWith(() => success({}), undefined, 'JOURNAL', { AWS_REGION: 'us-west-2' }),
      (error) => error?.code === 'E7_RELEASE_RECONCILIATION_AWS_RUNTIME_INPUT_INVALID',
    );
    assert.equal(simulatedAwsCalls, before);
  });

  await canary('wrong-role-is-rejected-before-aws', async () => {
    const before = simulatedAwsCalls;
    assert.throws(
      () =>
        runtimeWith(() => success({}), undefined, 'JOURNAL', {
          STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN: rollbackRoleArn,
        }),
      (error) => error?.code === 'E7_RELEASE_RECONCILIATION_AWS_RUNTIME_INPUT_INVALID',
    );
    assert.equal(simulatedAwsCalls, before);
  });

  await canary('native-rerun-attempt-two-is-rejected-before-aws', async () => {
    const before = simulatedAwsCalls;
    assert.throws(
      () =>
        runtimeWith(() => success({}), undefined, 'JOURNAL', {
          GITHUB_RUN_ATTEMPT: '2',
        }),
      (error) => error?.code === 'E7_RELEASE_RECONCILIATION_GITHUB_IDENTITY_INVALID',
    );
    assert.equal(simulatedAwsCalls, before);
  });

  await canary('ssm-missing-is-only-exact-parameter-not-found', async () => {
    const { store: awsStore } = runtimeWith((arguments_) => {
      assert.equal(arguments_[1], 'get-parameter');
      assert.equal(arguments_[3], ownerName);
      return failure('ParameterNotFound');
    });
    assert.equal(await awsStore.get(ownerName), null);
  });

  await canary('ssm-access-denied-is-never-treated-as-absent', async () => {
    const { store: awsStore } = runtimeWith(() => failure('AccessDeniedException'));
    await rejectsCode('E7_RELEASE_RECONCILIATION_SSM_GET_FAILED', () => awsStore.get(ownerName));
  });

  await canary('ssm-timeout-is-never-treated-as-absent', async () => {
    const timeout = Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' });
    const { store: awsStore } = runtimeWith(() => failure('Timeout', { processError: timeout }));
    await rejectsCode('E7_RELEASE_RECONCILIATION_SSM_GET_FAILED', () => awsStore.get(ownerName));
  });

  await canary('ssm-parameter-arn-is-account-and-region-bound', async () => {
    const { store: awsStore } = runtimeWith(() =>
      success({
        Parameter: awsParameter(ownerName, '{}', {
          ARN: `arn:aws:ssm:us-west-2:${accountId}:parameter${ownerName}`,
        }),
      }),
    );
    await rejectsCode('E7_RELEASE_RECONCILIATION_AWS_PARAMETER_ARN_INVALID', () =>
      awsStore.get(ownerName),
    );
  });

  await canary('ssm-success-shape-cannot-impersonate-not-found', async () => {
    for (const value of [
      { Parameters: [], InvalidParameters: [ownerName] },
      { awsErrorCode: 'ParameterNotFound' },
      { Parameter: null },
    ]) {
      const { store: awsStore } = runtimeWith(() => success(value));
      await rejectsCode('E7_RELEASE_RECONCILIATION_SSM_GET_INVALID', () => awsStore.get(ownerName));
    }
  });

  await canary('ssm-pagination-token-cycle-is-bounded', async () => {
    let listCalls = 0;
    const { store: awsStore } = runtimeWith(() => {
      listCalls += 1;
      return success({ Parameters: [], NextToken: 'same-token' });
    });
    await rejectsCode('E7_RELEASE_RECONCILIATION_SSM_TOKEN_CYCLE', () =>
      awsStore.list(reconciliationRootPrefix),
    );
    assert.equal(listCalls, 2);
  });

  await canary('ssm-page-cardinality-is-exactly-bounded', async () => {
    const values = Array.from({ length: 11 }, (_, index) =>
      awsParameter(`${reconciliationRootPrefix}/fixture/${index}`, '{}'),
    );
    const { store: awsStore } = runtimeWith(() => success({ Parameters: values }));
    await rejectsCode('E7_RELEASE_RECONCILIATION_SSM_LIST_INVALID', () =>
      awsStore.list(reconciliationRootPrefix),
    );
  });

  await canary('ssm-total-cardinality-is-contract-bounded', async () => {
    let listCalls = 0;
    const { store: awsStore } = runtimeWith(() => {
      listCalls += 1;
      return success({
        Parameters: Array.from({ length: 10 }, (_, index) =>
          awsParameter(
            `${reconciliationRootPrefix}/fixture/${String(listCalls).padStart(2, '0')}-${String(index).padStart(2, '0')}`,
          ),
        ),
        NextToken: `page-${listCalls}`,
      });
    });
    await rejectsCode('E7_RELEASE_RECONCILIATION_SSM_LIST_TOO_LARGE', () =>
      awsStore.list(reconciliationRootPrefix),
    );
    assert.equal(listCalls, 16);
  });

  await canary('ssm-put-is-confined-to-this-run-reconciliation-root', async () => {
    const { store: awsStore } = runtimeWith(() => {
      throw new Error('out-of-scope put reached AWS');
    });
    const before = simulatedAwsCalls;
    for (const name of [
      `${candidateRootPrefix}/RB-E7-06/000001-${'1'.repeat(64)}/manifest`,
      `${candidateRootPrefix}/RB-E7-08/000001-${'2'.repeat(64)}/manifest`,
      `${candidateRootPrefix}/release-reconciliation/987654321/owner`,
    ]) {
      await rejectsCode('E7_RELEASE_RECONCILIATION_SSM_PUT_INPUT_INVALID', () =>
        awsStore.putImmutable({ name, value: '{}' }),
      );
    }
    assert.equal(simulatedAwsCalls, before);
  });

  await canary('journal-duplicate-physical-name-is-rejected', async () => {
    const duplicateName = `${reconciliationRootPrefix}/fixture/one`;
    const { store: awsStore } = runtimeWith(() =>
      success({
        Parameters: [awsParameter(duplicateName), awsParameter(duplicateName)],
      }),
    );
    await rejectsCode('E7_RELEASE_RECONCILIATION_JOURNAL_SCAN_DUPLICATE', () =>
      openReleaseRollbackJournal({
        intent,
        store: awsStore,
      }),
    );
  });

  await canary('parameter-already-exists-is-resolved-by-exact-readback', async () => {
    const value = JSON.stringify(owner);
    const { store: awsStore } = runtimeWith((arguments_) => {
      if (arguments_[1] === 'put-parameter') return failure('ParameterAlreadyExists');
      if (arguments_[1] === 'get-parameter') {
        return success({
          Parameter: awsParameter(ownerName, value),
        });
      }
      throw new Error(`unexpected command ${arguments_.join(' ')}`);
    });
    const readback = await awsStore.putImmutable({ name: ownerName, value });
    assert.equal(readback.value, value);
  });

  const expectationPath = path.join(testRoot, 'expectation.json');
  const observationPath = path.join(testRoot, 'observation.json');
  const classificationPath = path.join(testRoot, 'classification.json');
  writeJson(expectationPath, expectedPublication);
  writeJson(observationPath, { tag: exactTag, release: null });
  await canary('pure-publication-classifier-cli-is-deterministic', async () => {
    const arguments_ = [
      'classify-publication',
      '--expectation',
      relative(expectationPath),
      '--observation',
      relative(observationPath),
      '--output',
      relative(classificationPath),
    ];
    const first = runCli(arguments_);
    assert.equal(first.status, 0, first.stderr);
    const second = runCli(arguments_);
    assert.equal(second.status, 0, second.stderr);
    const value = JSON.parse(readFileSync(classificationPath, 'utf8'));
    assert.equal(value.state, 'ABSENT');
    validateReleasePublicationClassification(value, {
      expected: expectedPublication,
      observation: { tag: exactTag, release: null },
    });
  });

  const rollbackCheckPath = path.join(testRoot, 'rollback-check-reconciliation.json');
  const rollbackResiliencePath = path.join(testRoot, 'rollback-resilience-reconciliation.json');
  const gatePath = path.join(testRoot, 'stage7-release-pre-fence-gate.json');
  writeJson(rollbackCheckPath, rollbackCheckReceipt);
  writeJson(rollbackResiliencePath, rollbackResilienceReceipt);
  await canary('pre-fence-cli-binds-both-terminal-receipt-bytes', async () => {
    const result = runCli([
      'pre-fence',
      '--rollback-check',
      relative(rollbackCheckPath),
      '--rollback-resilience',
      relative(rollbackResiliencePath),
      '--evaluated-at',
      '2026-08-18T12:08:00.000Z',
      '--output',
      relative(gatePath),
    ]);
    assert.equal(result.status, 0, result.stderr);
    const gate = JSON.parse(readFileSync(gatePath, 'utf8'));
    assert.equal(gate.status, 'ALLOW_FENCE');
    validateReleasePreFenceGate(gate, {
      rollbackCheckSource: readFileSync(rollbackCheckPath),
      rollbackResilienceSource: readFileSync(rollbackResiliencePath),
    });
    const expectedProofNames = [rollbackCheckReceipt, rollbackResilienceReceipt]
      .flatMap((receipt) => receipt.journal.runtimeProofParameters)
      .map(({ name }) => name)
      .toSorted((left, right) => left.localeCompare(right));
    assert.deepEqual(
      gate.reconciliationJournalAuthority.runtimeProofParameters.map(({ name }) => name),
      expectedProofNames,
    );
    assert.equal(
      expectedProofNames.every((name) =>
        gate.reconciliationJournalAuthority.cleanupParameterNames.includes(name),
      ),
      true,
    );
  });

  await canary('cli-rejects-duplicate-and-unpaired-flags', async () => {
    const duplicate = runCli([
      'classify-publication',
      '--expectation',
      relative(expectationPath),
      '--expectation',
      relative(expectationPath),
      '--observation',
      relative(observationPath),
      '--output',
      relative(classificationPath),
    ]);
    assert.notEqual(duplicate.status, 0);
    assert.match(duplicate.stderr, /E7_RELEASE_RECONCILIATION_CLI_FLAGS_INVALID/u);
  });

  await canary('cli-rejects-free-role-session-and-digest-authority-flags', async () => {
    const rejected = runCli([
      'open-journal',
      '--intent',
      relative(intentOutputPath),
      '--expected-role-arn',
      rollbackRoleArn,
      '--intent-bindings-sha256',
      'a'.repeat(64),
      '--output',
      relative(path.join(testRoot, 'owner.json')),
    ]);
    assert.notEqual(rejected.status, 0);
    assert.match(rejected.stderr, /E7_RELEASE_RECONCILIATION_CLI_FLAGS_INVALID/u);
  });

  await canary('cli-exposes-only-the-split-runtime-entrypoints', async () => {
    const removed = runCli(['reconcile-runtime']);
    assert.notEqual(removed.status, 0);
    assert.match(removed.stderr, /E7_RELEASE_RECONCILIATION_CLI_COMMAND_INVALID/u);
    for (const command of [
      'probe-terminal',
      'resume-terminal',
      'converge-runtime',
      'finalize-runtime',
    ]) {
      const recognized = runCli([command]);
      assert.notEqual(recognized.status, 0);
      assert.match(recognized.stderr, /E7_RELEASE_RECONCILIATION_CLI_FLAGS_INVALID/u);
    }
  });

  await canary('converge-cli-propagates-the-raw-recovery-role-authority', async () => {
    const cliSource = readFileSync(cli, 'utf8');
    const rollbackFlags = /const ROLLBACK_FILE_FLAGS = Object\.freeze\(\[([\s\S]*?)\]\);/u.exec(
      cliSource,
    );
    assert.notEqual(rollbackFlags, null);
    assert.equal(
      (rollbackFlags[1].match(/'reconciliation-recovery-role-effective-permissions'/gu) ?? [])
        .length,
      1,
    );
    assert.match(
      cliSource,
      /const rollbackFlags = Object\.fromEntries\([\s\S]*ROLLBACK_FILE_FLAGS\.map/u,
    );
  });

  await canary('converge-cli-shares-the-exact-successor-guard-source-contract', async () => {
    const cliSource = readFileSync(cli, 'utf8');
    const intentFlags = RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS.map(([, flag]) => flag);
    assert.equal(intentFlags.length, 22);
    assert.equal(new Set(intentFlags).size, 22);
    assert.deepEqual(RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS, [
      'inputs',
      'rb06',
      'rb08',
      'source-binding',
    ]);
    assert.deepEqual(RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS, [
      'protected-run',
      'completion',
    ]);
    assert.equal(RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS.length, 15);
    assert.match(cliSource, /ROLLBACK_CHECK: 'ROLLBACK_CHECK'/u);
    assert.match(cliSource, /ROLLBACK_RESILIENCE_COMPLETED: 'RECONCILIATION'/u);
    assert.match(cliSource, /ROLLBACK_RESILIENCE_INCOMPLETE: 'INCOMPLETE_RECONCILIATION'/u);
    assert.match(
      cliSource,
      /required:[\s\S]*SUCCESSOR_GUARD_COMMON_FLAGS[\s\S]*allowed: SUCCESSOR_GUARD_RECONCILIATION_EXTRA_FLAGS/u,
    );
    assert.match(
      cliSource,
      /completedReconciliationMode[\s\S]*completionExtraFlags\.some\(\(key\) => !Object\.hasOwn\(flags, key\)\)/u,
    );
    assert.match(
      cliSource,
      /incompleteReconciliationMode[\s\S]*\.\.\.premutationExtraFlags, \.\.\.completionExtraFlags[\s\S]*Object\.hasOwn\(flags, key\)/u,
    );
  });

  await canary('converge-cli-rejects-byte-distinct-intents-before-aws', async () => {
    const resignedIntentPath = path.join(testRoot, 'release-reconciliation-intent-resigned.json');
    writeFileSync(
      resignedIntentPath,
      `${JSON.stringify(JSON.parse(readFileSync(intentOutputPath, 'utf8')))}\n`,
      { mode: 0o600 },
    );
    assert.equal(readFileSync(intentOutputPath).equals(readFileSync(resignedIntentPath)), false);
    const requiredPlaceholderFlags = [
      'app',
      'manifest',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'candidate-record',
      'approval',
      'approved-plan',
      'deployment-evidence',
      'aws-auth',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
      ...RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS.map(([, flag]) => flag),
    ];
    const beforeAwsCalls = simulatedAwsCalls;
    const result = runCli(
      [
        'converge-runtime',
        '--intent',
        relative(intentOutputPath),
        '--phase',
        'ROLLBACK_CHECK',
        '--successor-guard-mode',
        'ROLLBACK_CHECK',
        '--reconciliation-intent',
        relative(resignedIntentPath),
        ...[...new Set(requiredPlaceholderFlags)].flatMap((flag) => [`--${flag}`, 'not-read']),
        '--transition-output',
        relative(path.join(testRoot, 'intent-mismatch-transition.json')),
        '--output',
        relative(path.join(testRoot, 'intent-mismatch-convergence.json')),
      ],
      intentEnvironment,
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /E7_RELEASE_RECONCILIATION_CLI_INTENT_SOURCE_MISMATCH/u);
    assert.equal(simulatedAwsCalls, beforeAwsCalls);
  });

  const convergenceCommonRequiredPlaceholderFlags = [
    'app',
    'manifest',
    'previous-manifest',
    'previous-api-contract-evidence',
    'previous-pending-evidence',
    'previous-smoke-evidence',
    'candidate-record',
    'approval',
    'approved-plan',
    'deployment-evidence',
    'aws-auth',
    'journal-role-effective-permissions',
    'reconciliation-recovery-role-effective-permissions',
    ...RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS.map(([, flag]) => flag),
  ];
  const convergenceGuardArguments = (mode, extraFlags = []) => [
    'converge-runtime',
    '--intent',
    relative(intentOutputPath),
    '--phase',
    'ROLLBACK_RESILIENCE',
    '--successor-guard-mode',
    mode,
    '--reconciliation-intent',
    relative(intentOutputPath),
    ...[
      ...new Set([
        ...convergenceCommonRequiredPlaceholderFlags,
        ...(mode === 'RECONCILIATION'
          ? [
              ...RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
              ...RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
            ]
          : []),
      ]),
    ].flatMap((flag) => [`--${flag}`, 'not-read']),
    ...extraFlags.flatMap((flag) => [`--${flag}`, 'not-read']),
    '--transition-output',
    relative(path.join(testRoot, `${mode.toLowerCase()}-transition.json`)),
    '--output',
    relative(path.join(testRoot, `${mode.toLowerCase()}-convergence.json`)),
  ];

  await canary('completed-reconciliation-keeps-both-completion-sources-mandatory', async () => {
    const beforeAwsCalls = simulatedAwsCalls;
    const result = runCli(convergenceGuardArguments('RECONCILIATION'), intentEnvironment);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /E7_RELEASE_RECONCILIATION_CLI_SUCCESSOR_GUARD_FLAGS_INVALID/u);
    assert.equal(simulatedAwsCalls, beforeAwsCalls);
  });

  await canary('incomplete-reconciliation-forbids-completion-source-substitution', async () => {
    const beforeAwsCalls = simulatedAwsCalls;
    const result = runCli(
      convergenceGuardArguments(
        'INCOMPLETE_RECONCILIATION',
        RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS,
      ),
      intentEnvironment,
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /E7_RELEASE_RECONCILIATION_CLI_SUCCESSOR_GUARD_FLAGS_INVALID/u);
    assert.equal(simulatedAwsCalls, beforeAwsCalls);
  });

  await canary('incomplete-reconciliation-forbids-eventual-premutation-artifacts', async () => {
    const beforeAwsCalls = simulatedAwsCalls;
    const result = runCli(
      convergenceGuardArguments(
        'INCOMPLETE_RECONCILIATION',
        [
          ...RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
          ...RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
        ].filter((flag) => !convergenceCommonRequiredPlaceholderFlags.includes(flag)),
      ),
      intentEnvironment,
    );
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /E7_RELEASE_RECONCILIATION_CLI_SUCCESSOR_GUARD_FLAGS_INVALID/u);
    assert.equal(simulatedAwsCalls, beforeAwsCalls);
  });

  process.stdout.write(
    `stage-7 release reconciliation executor self-test: PASS (${canaries} canaries, 0 real external calls, ${simulatedAwsCalls} simulated AWS calls)\n`,
  );
} finally {
  const resolvedSelfTestParent = path.resolve(selfTestParent);
  const resolvedTestRoot = path.resolve(testRoot);
  assert.equal(path.dirname(resolvedTestRoot).toLowerCase(), resolvedSelfTestParent.toLowerCase());
  assert.equal(path.basename(resolvedTestRoot).startsWith('release-reconciliation-'), true);
  removeTestTree(resolvedTestRoot);
  assert.equal(existsSync(resolvedTestRoot), false);
}
