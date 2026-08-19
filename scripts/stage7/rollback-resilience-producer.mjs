#!/usr/bin/env node

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import {
  STAGE7_ARTIFACTS,
  STAGE7_AUDITS,
  STAGE7_EVIDENCE,
  canonicalJson,
  createStage7CandidateRollbackRecord,
  createStage7PreviousReleaseManifest,
  createStage7VersionedRollbackPlan,
  createStage7VersionedRollbackRehearsal,
  expectedStage7Stacks,
  objectSha256,
  validateFreezeManifest,
  validateStage7CandidateRollbackRecord,
  validateStage7Config,
  validateStage7PreviousReleaseForTarget,
  validateStage7VersionedRollbackRehearsal,
} from './core.mjs';
import {
  IamEffectivePermissionsError,
  validateIamEffectivePermissionsEvidence,
} from './iam-effective-permissions.mjs';
import {
  createRollbackJournalLifecycle,
  createProtectedRollbackRuntime,
  selfTestProtectedRollbackRuntime,
  validateRollbackJournalLifecycle,
} from './rollback-resilience-protected-runtime.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const AWS_REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$/u;
const IAM_ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/[A-Za-z0-9+=,.@_/-]{1,512}$/u;
const IAM_POLICY_ARN = /^arn:aws:iam::([0-9]{12}):policy\/[A-Za-z0-9+=,.@_/-]{1,512}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const SAFE_NAME = /^[A-Za-z0-9][A-Za-z0-9._:/+=,@-]{0,255}$/u;
const STACK_STATUS = new Set([
  'UPDATE_COMPLETE',
  'UPDATE_IN_PROGRESS',
  'UPDATE_FAILED',
  'UPDATE_ROLLBACK_IN_PROGRESS',
  'UPDATE_ROLLBACK_COMPLETE',
  'UPDATE_ROLLBACK_FAILED',
]);
const FAILURE_RESOURCE_TYPE = 'AWS::CloudFormation::WaitCondition';
const FAILURE_LOGICAL_ID = 'Stage7RollbackFailureCanary';
const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;
const MAX_TRANSCRIPT_ENTRIES = 256;
const RECONCILIATION_RECOVERY_ROLE_AUTHORITY_KEYS = Object.freeze([
  'reconciliationRecoveryRoleArn',
  'reconciliationRecoveryPermissionsBoundaryArn',
  'reconciliationRecoveryRoleEffectivePermissionsRawSha256',
  'reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256',
  'reconciliationRecoveryRoleEffectivePermissionsSha256',
  'reconciliationRecoveryRoleEffectivePolicyProjectionSha256',
]);
const AWS_AUTH_KEYS = [
  'schemaVersion',
  'stage',
  'kind',
  'status',
  'scope',
  'candidateSha',
  'releaseId',
  'manifestSha256',
  'configSha256',
  'accountSha256',
  'accountSuffix',
  'callerArnSha256',
  'expectedRoleArnSha256',
  'region',
  'sessionMode',
  'roleTrust',
  'bootstrapVersion',
  'bootstrapStackIdSha256',
  'bootstrapStackStatus',
  'quotaCapacity',
  'stackInventory',
  'authorizedStacks',
  'iamEffectivePermissions',
  'journalRoleEffectivePermissionsRawSha256',
  'journalRoleEffectivePermissionsSha256',
  ...RECONCILIATION_RECOVERY_ROLE_AUTHORITY_KEYS,
  'capacityProven',
  'decision',
  'preFreezeException',
  'longLivedCredentials',
  'externalRequests',
  'mutationsPerformed',
  'containsSensitiveData',
];
const PROTECTED_APPROVAL_KEYS = [
  'schemaVersion',
  'stage',
  'kind',
  'status',
  'scope',
  'candidateSha',
  'releaseId',
  'releaseTag',
  'configSha256',
  'cloudAssemblySha256',
  'freezeManifestSha256',
  'previousReleaseManifestSha256',
  'approvedPlanSha256',
  'approvedDiffSha256',
  'iamEffectivePermissionsBindingSha256',
  'iamEffectivePermissionsEvidenceSha256',
  'journalRoleEffectivePermissionsRawSha256',
  'journalRoleEffectivePermissionsSha256',
  ...RECONCILIATION_RECOVERY_ROLE_AUTHORITY_KEYS,
  'approvedAtUtc',
  'statefulReplacements',
  'destructiveChanges',
  'iamBroadeningDetected',
  'iamBroadeningReviewed',
  'humanReviewConfirmed',
  'explicitDispatchConfirmation',
  'protectedEnvironment',
  'protectedEnvironmentName',
  'nonPublic',
  'accountSha256',
  'accountSuffix',
  'region',
  'stacks',
  'budget',
  'approvalOwnerAlias',
  'reviewerAlias',
  'authorizedWindow',
  'externalRequests',
  'mutationsPerformed',
  'containsSensitiveData',
];
const SELF_TEST_EXECUTOR_CAPABILITY = Symbol('stage7-rb-self-test');
const PROTECTED_AWS_EXECUTOR_CAPABILITY = Symbol('stage7-rb-protected-aws');
const PROTECTED_AWS_EVIDENCE_AUTHORITY = Symbol('stage7-rb-protected-evidence');
const SELF_TEST_REAL_INPUTS = new WeakSet();
const PROTECTED_WORKFLOW = 'stage7-rollback-resilience.yml';
const PROTECTED_ENVIRONMENT = 'assessment-release-recovery';
const RUNTIME_IDENTITY_KEYS = [
  'accountSha256',
  'accountSuffix',
  'roleSha256',
  'sessionArnSha256',
  'observedAtUtc',
];
const RUNTIME_ATTESTATION_KEYS = [
  'schemaVersion',
  'stage',
  'kind',
  'status',
  'repository',
  'workflow',
  'runId',
  'runAttempt',
  'githubSha',
  'protectedEnvironment',
  'protectedBindingSha256',
  'executionSha256',
  'identity',
  'awsCliVersionSha256',
  'journalPrefixSha256',
  'journalLifecycle',
  'stateBackend',
  'executorConstruction',
  'injectedExecutorAccepted',
  'containsSensitiveData',
  'attestationSha256',
];
const AUTHORIZATION_IDS = ['AUTH-E7-EXT-01', 'AUTH-E7-EXT-02', 'AUTH-E7-EXT-03'];
const PRIOR_AUTHORIZATION_USAGE_IDS = [
  'EXTERNAL_AUTHORIZATION_PREFLIGHT',
  'SMOKE_INPUT_PREFLIGHT_CANDIDATE',
  'ACTIVATION_CANDIDATE',
  'SMOKE_POST_DEPLOY',
  'QUALITY_FOCAL',
  'EDGE_PASSIVE',
  'SANDBOX_ONE_USE',
  'ROLLBACK_PENDING_INPUT_PREFLIGHT',
  'RB_E7_05_PENDING_PRODUCER',
  'POST_ROLLBACK_VERSIONED',
  'ACTIVATION_REPROMOTION',
  'POST_REPROMOTION_VERSIONED',
];
const AUTHORIZATION_USAGE_KEYS = [
  'schemaVersion',
  'usageId',
  'bundleSha256',
  'candidateSha',
  'releaseId',
  'configSha256',
  'ownedOriginSha256',
  'sandboxHostSha256',
  'requestCounts',
];
const RESILIENCE_COMPLETION_KEYS = [
  'schemaVersion',
  'stage',
  'kind',
  'status',
  'baseRehearsalSha256',
  'scenarioIds',
  'pendingScenarioIds',
  'rb06CheckpointSha256',
  'rb08CheckpointSha256',
  'extensionSha256',
  'originProtectionContractSha256',
  'authorizationUsageSha256',
  'journalLifecycleSha256',
  'reconciliationRecoveryRoleAuthoritySha256',
  'finalReleaseId',
  'finalCandidateSha',
  'completedAtUtc',
  'dataPolicy',
  'dataRollbackPerformed',
  'stacksDeleted',
  'containsSensitiveData',
  'completionSha256',
];

const cloudFormationExecutionRoleArn = (inputs) =>
  `arn:aws:iam::${inputs.config.aws.accountId}:role/cdk-hnb659fds-cfn-exec-role-${inputs.config.aws.accountId}-${inputs.config.aws.region}`;

const protectedBindingSha256 = ({ inputsWithoutExecution, execution }) =>
  objectSha256({
    STAGE7_AUTHORIZED_RUN_ID: execution.runId,
    STAGE7_AUTHORIZED_RUN_ATTEMPT: execution.runAttempt,
    STAGE7_AUTHORIZED_CANDIDATE_SHA: inputsWithoutExecution.freezeManifest.candidateSha,
    STAGE7_AUTHORIZED_FREEZE_SHA256: inputsWithoutExecution.freezeManifest.manifestSha256,
    STAGE7_AUTHORIZED_APPROVAL_SHA256: inputsWithoutExecution.candidateRecord.approvalSha256,
    STAGE7_AUTHORIZED_AWS_AUTH_SHA256: inputsWithoutExecution.documents.awsAuth.sha256,
    STAGE7_AUTHORIZED_PLAN_SHA256: inputsWithoutExecution.candidateRecord.planSha256,
    STAGE7_AUTHORIZED_DEPLOYMENT_SHA256:
      inputsWithoutExecution.candidateRecord.deploymentEvidenceSha256,
    STAGE7_AUTHORIZED_OBSERVABILITY_SHA256:
      inputsWithoutExecution.documents.observabilityEvidence.sha256,
    STAGE7_AUTHORIZED_ACTIVATION_SHA256: inputsWithoutExecution.documents.activationEvidence.sha256,
    STAGE7_AUTHORIZED_EXTERNAL_AUTHORIZATION_SHA256:
      inputsWithoutExecution.documents.externalAuthorizationEvidence.sha256,
    STAGE7_AUTHORIZED_AUTHORIZATION_BUDGET_SHA256:
      inputsWithoutExecution.documents.authorizationBudget.sha256,
    STAGE7_AUTHORIZED_REHEARSAL_SHA256: inputsWithoutExecution.baseRehearsal.rehearsalSha256,
    STAGE7_AUTHORIZED_JOURNAL_CLEANUP_ROLE_SHA256: sha256(
      inputsWithoutExecution.journalCleanupRoleArn,
    ),
  });

export class Stage7RollbackResilienceError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7RollbackResilienceError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7RollbackResilienceError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const reconciliationRecoveryRoleAuthority = (value) =>
  Object.fromEntries(RECONCILIATION_RECOVERY_ROLE_AUTHORITY_KEYS.map((key) => [key, value?.[key]]));
const reconciliationRecoveryRoleAuthoritySha256 = (value) =>
  objectSha256(reconciliationRecoveryRoleAuthority(value));

const validateAwsAuthAuxiliaryRoleBindings = ({ value, config, journalCleanupRoleArn }) => {
  const recoveryRole = IAM_ROLE_ARN.exec(value?.reconciliationRecoveryRoleArn ?? '');
  const recoveryBoundary = IAM_POLICY_ARN.exec(
    value?.reconciliationRecoveryPermissionsBoundaryArn ?? '',
  );
  if (
    ![
      value?.journalRoleEffectivePermissionsRawSha256,
      value?.journalRoleEffectivePermissionsSha256,
      value?.reconciliationRecoveryRoleEffectivePermissionsRawSha256,
      value?.reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256,
      value?.reconciliationRecoveryRoleEffectivePermissionsSha256,
      value?.reconciliationRecoveryRoleEffectivePolicyProjectionSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    recoveryRole?.[1] !== config.aws.accountId ||
    recoveryBoundary?.[1] !== config.aws.accountId ||
    value.reconciliationRecoveryRoleArn === journalCleanupRoleArn ||
    Object.values(config.aws.roles).includes(value.reconciliationRecoveryRoleArn)
  ) {
    fail('E7_RESILIENCE_AWS_AUTH_AUXILIARY_ROLE_BINDING_INVALID');
  }
  return value;
};
const utc = (value) =>
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
  !Number.isNaN(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const nonNegativeInteger = (value) => Number.isSafeInteger(value) && value >= 0;
const positiveInteger = (value) => Number.isSafeInteger(value) && value > 0;

const withoutDigest = (value, field) => {
  const body = { ...value };
  delete body[field];
  return body;
};

const assertSanitizedJsonDocument = (document, expectedSha256, code) => {
  if (
    !exactKeys(document, ['content', 'sha256']) ||
    typeof document.content !== 'string' ||
    Buffer.byteLength(document.content, 'utf8') < 2 ||
    Buffer.byteLength(document.content, 'utf8') > MAX_DOCUMENT_BYTES ||
    document.sha256 !== expectedSha256 ||
    sha256(document.content) !== expectedSha256 ||
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/u.test(document.content) ||
    /\b(?:A3T|AKIA|ASIA)[A-Z0-9]{16}\b/u.test(document.content)
  ) {
    fail(code);
  }
  let parsed;
  try {
    parsed = JSON.parse(document.content);
  } catch {
    fail(code);
  }
  if (!object(parsed) || parsed.containsSensitiveData !== false) fail(code);
  return parsed;
};

const validateExecution = (execution, { config, candidateSha }) => {
  if (
    !exactKeys(execution, [
      'mode',
      'repository',
      'workflow',
      'runId',
      'runAttempt',
      'githubActions',
      'githubRef',
      'githubSha',
      'protectedEnvironment',
      'accountId',
      'region',
      'roleArn',
      'startedAtUtc',
    ]) ||
    !['AWS_REAL', 'LOCAL_SIMULATION'].includes(execution.mode) ||
    execution.repository !== REPOSITORY ||
    typeof execution.workflow !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$/u.test(execution.workflow) ||
    !RUN_ID.test(execution.runId ?? '') ||
    !RUN_ID.test(execution.runAttempt ?? '') ||
    execution.githubSha !== candidateSha ||
    execution.accountId !== config.aws.accountId ||
    execution.region !== config.aws.region ||
    !utc(execution.startedAtUtc) ||
    Date.parse(execution.startedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(execution.startedAtUtc) > Date.parse(config.window.endsAtUtc)
  ) {
    fail('E7_RESILIENCE_EXECUTION_INVALID');
  }
  if (
    execution.mode === 'AWS_REAL' &&
    (execution.githubActions !== true ||
      execution.githubRef !== 'refs/heads/master' ||
      execution.protectedEnvironment !== 'assessment-release-recovery' ||
      execution.roleArn !== config.aws.roles.rollbackRoleArn)
  ) {
    fail('E7_RESILIENCE_REAL_EXECUTION_CONTEXT_INVALID');
  }
  if (
    execution.mode === 'LOCAL_SIMULATION' &&
    (execution.githubActions !== false ||
      execution.githubRef !== 'refs/heads/test' ||
      execution.protectedEnvironment !== 'LOCAL_SELF_TEST' ||
      execution.roleArn !== null)
  ) {
    fail('E7_RESILIENCE_SIMULATION_CONTEXT_INVALID');
  }
  return execution;
};

const validateAuthorizationUsage = ({ usage, authorization, inputs }) => {
  if (
    !exactKeys(usage, AUTHORIZATION_USAGE_KEYS) ||
    usage.schemaVersion !== 1 ||
    typeof usage.usageId !== 'string' ||
    usage.bundleSha256 !== authorization.authorizationSha256 ||
    usage.candidateSha !== inputs.freezeManifest.candidateSha ||
    usage.releaseId !== inputs.freezeManifest.releaseId ||
    usage.configSha256 !== objectSha256(inputs.config) ||
    usage.ownedOriginSha256 !== authorization.ownedOriginSha256 ||
    usage.sandboxHostSha256 !== authorization.sandboxHostSha256 ||
    !exactKeys(usage.requestCounts, AUTHORIZATION_IDS) ||
    AUTHORIZATION_IDS.some((id) => !nonNegativeInteger(usage.requestCounts[id]))
  ) {
    fail('E7_RESILIENCE_AUTHORIZATION_USAGE_INVALID');
  }
  return usage;
};

const validateAuthorizationBudget = ({ authorization, budget, inputs }) => {
  if (
    !exactKeys(authorization, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'stage7ConfigSha256',
      'ownedOriginSha256',
      'sandboxHostSha256',
      'authorizationSha256',
      'authorizationIds',
      'requestLimits',
      'authorizationUsage',
      'targetValuesCaptured',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    authorization.schemaVersion !== 1 ||
    authorization.stage !== 7 ||
    authorization.kind !== 'EXTERNAL_AUTHORIZATION_PREFLIGHT' ||
    authorization.status !== 'PASS' ||
    authorization.scope !== 'full' ||
    authorization.candidateSha !== inputs.freezeManifest.candidateSha ||
    authorization.releaseId !== inputs.freezeManifest.releaseId ||
    authorization.stage7ConfigSha256 !== objectSha256(inputs.config) ||
    authorization.authorizationIds?.join('\0') !== AUTHORIZATION_IDS.join('\0') ||
    !exactKeys(authorization.requestLimits, AUTHORIZATION_IDS) ||
    AUTHORIZATION_IDS.some((id) => !positiveInteger(authorization.requestLimits[id])) ||
    !SHA256.test(authorization.authorizationSha256 ?? '') ||
    !SHA256.test(authorization.ownedOriginSha256 ?? '') ||
    !SHA256.test(authorization.sandboxHostSha256 ?? '') ||
    authorization.targetValuesCaptured !== false ||
    authorization.externalRequests !== 0 ||
    authorization.mutationsPerformed !== 0 ||
    authorization.containsSensitiveData !== false ||
    !exactKeys(budget, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'configSha256',
      'externalAuthorizationEvidenceSha256',
      'externalAuthorizationObjectSha256',
      'authorizationSha256',
      'authorizationIds',
      'requestLimits',
      'priorUsages',
      'priorTotals',
      'reservedUsage',
      'finalTotals',
      'reservedExternalRequests',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'budgetSha256',
    ]) ||
    budget.schemaVersion !== 1 ||
    budget.stage !== 7 ||
    budget.kind !== 'ROLLBACK_RESILIENCE_AUTHORIZATION_BUDGET' ||
    budget.status !== 'RESERVED_BEFORE_EXTERNAL_REQUESTS' ||
    budget.candidateSha !== inputs.freezeManifest.candidateSha ||
    budget.releaseId !== inputs.freezeManifest.releaseId ||
    budget.configSha256 !== objectSha256(inputs.config) ||
    budget.externalAuthorizationEvidenceSha256 !==
      inputs.documents.externalAuthorizationEvidence.sha256 ||
    budget.externalAuthorizationObjectSha256 !== objectSha256(authorization) ||
    budget.authorizationSha256 !== authorization.authorizationSha256 ||
    budget.authorizationIds?.join('\0') !== AUTHORIZATION_IDS.join('\0') ||
    canonicalJson(budget.requestLimits) !== canonicalJson(authorization.requestLimits) ||
    !Array.isArray(budget.priorUsages) ||
    budget.priorUsages.length !== PRIOR_AUTHORIZATION_USAGE_IDS.length ||
    !exactKeys(budget.priorTotals, AUTHORIZATION_IDS) ||
    !exactKeys(budget.finalTotals, AUTHORIZATION_IDS) ||
    budget.reservedExternalRequests !== 11 ||
    budget.externalRequests !== 0 ||
    budget.mutationsPerformed !== 0 ||
    budget.containsSensitiveData !== false ||
    budget.budgetSha256 !== objectSha256(withoutDigest(budget, 'budgetSha256'))
  ) {
    fail('E7_RESILIENCE_AUTHORIZATION_BUDGET_INVALID');
  }
  const seen = new Set();
  const totals = Object.fromEntries(AUTHORIZATION_IDS.map((id) => [id, 0]));
  for (const entry of budget.priorUsages) {
    if (
      !exactKeys(entry, [
        'basename',
        'rawSha256',
        'objectSha256',
        'usageId',
        'usageSha256',
        'requestCounts',
      ]) ||
      typeof entry.basename !== 'string' ||
      !SHA256.test(entry.rawSha256 ?? '') ||
      !SHA256.test(entry.objectSha256 ?? '') ||
      !SHA256.test(entry.usageSha256 ?? '') ||
      seen.has(entry.usageId) ||
      !exactKeys(entry.requestCounts, AUTHORIZATION_IDS) ||
      AUTHORIZATION_IDS.some((id) => !nonNegativeInteger(entry.requestCounts[id]))
    ) {
      fail('E7_RESILIENCE_AUTHORIZATION_BUDGET_INVALID');
    }
    seen.add(entry.usageId);
    for (const id of AUTHORIZATION_IDS) totals[id] += entry.requestCounts[id];
  }
  validateAuthorizationUsage({ usage: budget.reservedUsage, authorization, inputs });
  if (
    [...seen].toSorted().join('\0') !== [...PRIOR_AUTHORIZATION_USAGE_IDS].toSorted().join('\0') ||
    budget.reservedUsage.usageId !== 'ROLLBACK_RESILIENCE' ||
    budget.reservedUsage.requestCounts['AUTH-E7-EXT-01'] !== 11 ||
    budget.reservedUsage.requestCounts['AUTH-E7-EXT-02'] !== 0 ||
    budget.reservedUsage.requestCounts['AUTH-E7-EXT-03'] !== 0 ||
    AUTHORIZATION_IDS.some(
      (id) =>
        budget.priorTotals[id] !== totals[id] ||
        budget.finalTotals[id] !== totals[id] + budget.reservedUsage.requestCounts[id] ||
        budget.finalTotals[id] > budget.requestLimits[id],
    )
  ) {
    fail('E7_RESILIENCE_AUTHORIZATION_LIMIT_EXCEEDED');
  }
  return budget;
};

const validateBoundInputs = (inputs) => {
  if (
    !exactKeys(inputs, [
      'config',
      'freezeManifest',
      'previousReleaseManifest',
      'candidateRecord',
      'baseRehearsal',
      'journalCleanupRoleArn',
      'documents',
      'execution',
    ]) ||
    !exactKeys(inputs.documents, [
      'approval',
      'awsAuth',
      'approvedPlan',
      'deploymentEvidence',
      'observabilityEvidence',
      'activationEvidence',
      'externalAuthorizationEvidence',
      'authorizationBudget',
    ])
  ) {
    fail('E7_RESILIENCE_BINDING_INPUT_INVALID');
  }
  validateStage7Config(inputs.config, {
    now: new Date(inputs.execution?.startedAtUtc ?? Number.NaN),
  });
  validateFreezeManifest(inputs.freezeManifest);
  validateStage7PreviousReleaseForTarget(inputs.previousReleaseManifest, {
    config: inputs.config,
    freezeManifest: inputs.freezeManifest,
  });
  validateStage7CandidateRollbackRecord(inputs.candidateRecord, {
    previousManifest: inputs.previousReleaseManifest,
  });
  validateStage7VersionedRollbackRehearsal(inputs.baseRehearsal, {
    previousManifest: inputs.previousReleaseManifest,
    candidateRecord: inputs.candidateRecord,
  });
  validateExecution(inputs.execution, {
    config: inputs.config,
    candidateSha: inputs.freezeManifest.candidateSha,
  });
  const journalRoleMatch = IAM_ROLE_ARN.exec(inputs.journalCleanupRoleArn ?? '');
  if (
    journalRoleMatch === null ||
    journalRoleMatch[1] !== inputs.config.aws.accountId ||
    Object.values(inputs.config.aws.roles).includes(inputs.journalCleanupRoleArn)
  ) {
    fail('E7_RESILIENCE_JOURNAL_CLEANUP_ROLE_INVALID');
  }
  const approval = assertSanitizedJsonDocument(
    inputs.documents.approval,
    inputs.candidateRecord.approvalSha256,
    'E7_RESILIENCE_APPROVAL_DOCUMENT_INVALID',
  );
  const awsAuth = assertSanitizedJsonDocument(
    inputs.documents.awsAuth,
    inputs.documents.awsAuth.sha256,
    'E7_RESILIENCE_AWS_AUTH_DOCUMENT_INVALID',
  );
  validateAwsAuthAuxiliaryRoleBindings({
    value: awsAuth,
    config: inputs.config,
    journalCleanupRoleArn: inputs.journalCleanupRoleArn,
  });
  const plan = assertSanitizedJsonDocument(
    inputs.documents.approvedPlan,
    inputs.candidateRecord.planSha256,
    'E7_RESILIENCE_PLAN_DOCUMENT_INVALID',
  );
  const deployment = assertSanitizedJsonDocument(
    inputs.documents.deploymentEvidence,
    inputs.candidateRecord.deploymentEvidenceSha256,
    'E7_RESILIENCE_DEPLOYMENT_DOCUMENT_INVALID',
  );
  const observability = assertSanitizedJsonDocument(
    inputs.documents.observabilityEvidence,
    inputs.documents.observabilityEvidence.sha256,
    'E7_RESILIENCE_OBSERVABILITY_DOCUMENT_INVALID',
  );
  const activation = assertSanitizedJsonDocument(
    inputs.documents.activationEvidence,
    inputs.documents.activationEvidence.sha256,
    'E7_RESILIENCE_ACTIVATION_DOCUMENT_INVALID',
  );
  const externalAuthorization = assertSanitizedJsonDocument(
    inputs.documents.externalAuthorizationEvidence,
    inputs.documents.externalAuthorizationEvidence.sha256,
    'E7_RESILIENCE_EXTERNAL_AUTHORIZATION_DOCUMENT_INVALID',
  );
  const authorizationBudget = assertSanitizedJsonDocument(
    inputs.documents.authorizationBudget,
    inputs.documents.authorizationBudget.sha256,
    'E7_RESILIENCE_AUTHORIZATION_BUDGET_DOCUMENT_INVALID',
  );
  validateAuthorizationBudget({
    authorization: externalAuthorization,
    budget: authorizationBudget,
    inputs,
  });
  let iamEffectivePermissions;
  try {
    iamEffectivePermissions =
      inputs.execution.mode === 'LOCAL_SIMULATION' || SELF_TEST_REAL_INPUTS.has(inputs)
        ? awsAuth.iamEffectivePermissions
        : validateIamEffectivePermissionsEvidence({
            value: awsAuth.iamEffectivePermissions,
            config: inputs.config,
            scope: 'full',
            candidateSha: inputs.freezeManifest.candidateSha,
            releaseId: inputs.freezeManifest.releaseId,
            manifestSha256: inputs.freezeManifest.manifestSha256,
            bootstrapAssetInventory:
              awsAuth.iamEffectivePermissions?.bootstrapRoles?.assetInventory?.inventory,
            cleanupWatchdogRoleArn: null,
            baselineRoleArn: null,
          });
  } catch (error) {
    if (error instanceof IamEffectivePermissionsError) {
      fail('E7_RESILIENCE_IAM_EFFECTIVE_PERMISSIONS_INVALID');
    }
    throw error;
  }
  if (
    inputs.config.authorization.scope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    inputs.config.prereleaseAccess.mode !== 'ORIGIN_GATE_ONLY' ||
    inputs.freezeManifest.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    inputs.baseRehearsal.status !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    inputs.baseRehearsal.pendingScenarioIds?.join('\0') !== ['RB-E7-06', 'RB-E7-08'].join('\0') ||
    !exactKeys(approval, PROTECTED_APPROVAL_KEYS) ||
    approval.kind !== 'PROTECTED_RELEASE_APPROVAL' ||
    approval.status !== 'PASS' ||
    approval.scope !== 'full' ||
    approval.releaseTag !== inputs.freezeManifest.releaseTag ||
    approval.cloudAssemblySha256 !==
      inputs.freezeManifest.artifacts.find(({ name }) => name === 'iac')?.sha256 ||
    approval.freezeManifestSha256 !== inputs.freezeManifest.manifestSha256 ||
    approval.approvedPlanSha256 !== inputs.documents.approvedPlan.sha256 ||
    approval.statefulReplacements !== 0 ||
    approval.destructiveChanges !== 0 ||
    approval.iamBroadeningReviewed !== true ||
    approval.humanReviewConfirmed !== true ||
    approval.explicitDispatchConfirmation !== true ||
    approval.protectedEnvironment !== true ||
    approval.protectedEnvironmentName !== 'assessment-release' ||
    approval.nonPublic !== false ||
    approval.accountSha256 !== sha256(inputs.config.aws.accountId) ||
    approval.accountSuffix !== inputs.config.aws.accountId.slice(-4) ||
    approval.region !== inputs.config.aws.region ||
    canonicalJson(approval.stacks) !== canonicalJson(inputs.config.authorization.stacks) ||
    canonicalJson(approval.authorizedWindow) !== canonicalJson(inputs.config.window) ||
    approval.approvalOwnerAlias !== inputs.config.authorization.ownerAlias ||
    approval.externalRequests !== 0 ||
    approval.mutationsPerformed !== 0 ||
    !exactKeys(awsAuth, AWS_AUTH_KEYS) ||
    awsAuth.kind !== 'AWS_READ_ONLY_PREFLIGHT' ||
    awsAuth.status !== 'PASS' ||
    awsAuth.scope !== 'full' ||
    awsAuth.manifestSha256 !== inputs.freezeManifest.manifestSha256 ||
    awsAuth.configSha256 !== objectSha256(inputs.config) ||
    awsAuth.mutationsPerformed !== 0 ||
    approval.iamEffectivePermissionsBindingSha256 !== iamEffectivePermissions?.bindingSha256 ||
    approval.iamEffectivePermissionsEvidenceSha256 !== inputs.documents.awsAuth.sha256 ||
    approval.journalRoleEffectivePermissionsRawSha256 !==
      awsAuth.journalRoleEffectivePermissionsRawSha256 ||
    approval.journalRoleEffectivePermissionsSha256 !==
      awsAuth.journalRoleEffectivePermissionsSha256 ||
    canonicalJson(reconciliationRecoveryRoleAuthority(approval)) !==
      canonicalJson(reconciliationRecoveryRoleAuthority(awsAuth)) ||
    plan.kind !== 'RELEASE_DIFF_REVIEW' ||
    plan.status !== 'READY_FOR_PROTECTED_REVIEW' ||
    !object(deployment.checkpoints?.web) ||
    !object(observability.checkpoints?.observability) ||
    !object(activation.checkpoints?.activation) ||
    [approval, awsAuth, plan, deployment, observability, activation].some(
      (value) =>
        value.schemaVersion !== 1 ||
        value.stage !== 7 ||
        value.candidateSha !== inputs.freezeManifest.candidateSha ||
        value.releaseId !== inputs.freezeManifest.releaseId ||
        value.containsSensitiveData !== false,
    ) ||
    approval.previousReleaseManifestSha256 !== inputs.previousReleaseManifest.manifestSha256 ||
    plan.previousReleaseManifestSha256 !== inputs.previousReleaseManifest.manifestSha256 ||
    deployment.checkpoints.web.previousReleaseManifestSha256 !==
      inputs.previousReleaseManifest.manifestSha256 ||
    observability.checkpoints.observability.previousReleaseManifestSha256 !==
      inputs.previousReleaseManifest.manifestSha256 ||
    activation.checkpoints.activation.previousReleaseManifestSha256 !==
      inputs.previousReleaseManifest.manifestSha256
  ) {
    fail('E7_RESILIENCE_BINDING_MISMATCH');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_BINDING',
    candidateSha: inputs.freezeManifest.candidateSha,
    releaseId: inputs.freezeManifest.releaseId,
    configSha256: objectSha256(inputs.config),
    freezeManifestSha256: inputs.freezeManifest.manifestSha256,
    previousReleaseManifestSha256: inputs.previousReleaseManifest.manifestSha256,
    candidateRecordSha256: inputs.candidateRecord.recordSha256,
    approvalSha256: inputs.candidateRecord.approvalSha256,
    awsAuthEvidenceSha256: inputs.documents.awsAuth.sha256,
    iamEffectivePermissionsBindingSha256: iamEffectivePermissions.bindingSha256,
    approvedPlanSha256: inputs.candidateRecord.planSha256,
    deploymentEvidenceSha256: inputs.candidateRecord.deploymentEvidenceSha256,
    observabilityEvidenceSha256: inputs.documents.observabilityEvidence.sha256,
    activationEvidenceSha256: inputs.documents.activationEvidence.sha256,
    externalAuthorizationEvidenceSha256: inputs.documents.externalAuthorizationEvidence.sha256,
    authorizationBudgetSha256: inputs.documents.authorizationBudget.sha256,
    journalCleanupRoleSha256: sha256(inputs.journalCleanupRoleArn),
    reconciliationRecoveryRoleAuthoritySha256: reconciliationRecoveryRoleAuthoritySha256(awsAuth),
    baseRehearsalSha256: inputs.baseRehearsal.rehearsalSha256,
    executionSha256: objectSha256(inputs.execution),
    containsSensitiveData: false,
  };
  return {
    binding: { ...body, bindingSha256: objectSha256(body) },
    parsedDocuments: {
      approval,
      awsAuth,
      plan,
      deployment,
      observability,
      activation,
      externalAuthorization,
      authorizationBudget,
    },
  };
};

const transcriptEntry = ({ request, response }) => ({
  sequence: request.sequence,
  scenarioId: request.scenarioId,
  service: request.service,
  operation: request.operation,
  inputSha256: objectSha256(request.input),
  requestIdSha256: sha256(response.requestId),
  observedAtUtc: response.observedAtUtc,
  responseSha256: objectSha256(response.payload),
});

const validateTranscript = (entries, { scenarioId, execution }) => {
  if (!Array.isArray(entries) || entries.length > MAX_TRANSCRIPT_ENTRIES) {
    fail('E7_RESILIENCE_TRANSCRIPT_INVALID');
  }
  const requestIds = new Set();
  for (const [index, entry] of entries.entries()) {
    if (
      !exactKeys(entry, [
        'sequence',
        'scenarioId',
        'service',
        'operation',
        'inputSha256',
        'requestIdSha256',
        'observedAtUtc',
        'responseSha256',
      ]) ||
      entry.sequence !== index + 1 ||
      entry.scenarioId !== scenarioId ||
      !SAFE_NAME.test(entry.service ?? '') ||
      !SAFE_NAME.test(entry.operation ?? '') ||
      !SHA256.test(entry.inputSha256 ?? '') ||
      !SHA256.test(entry.requestIdSha256 ?? '') ||
      !SHA256.test(entry.responseSha256 ?? '') ||
      !utc(entry.observedAtUtc) ||
      Date.parse(entry.observedAtUtc) < Date.parse(execution.startedAtUtc) ||
      requestIds.has(entry.requestIdSha256) ||
      (index > 0 && Date.parse(entry.observedAtUtc) < Date.parse(entries[index - 1].observedAtUtc))
    ) {
      fail('E7_RESILIENCE_TRANSCRIPT_INVALID');
    }
    requestIds.add(entry.requestIdSha256);
  }
  return entries;
};

const invoke = async ({
  executor,
  state,
  inputs,
  binding,
  scenarioId,
  service,
  operation,
  input,
}) => {
  if (typeof executor !== 'function') fail('E7_RESILIENCE_EXECUTOR_INVALID');
  const request = {
    bindingSha256: binding.bindingSha256,
    scenarioId,
    sequence: state.transcript.length + 1,
    service,
    operation,
    region: inputs.config.aws.region,
    input,
  };
  const response = await executor(request);
  const expectedSource = service.startsWith('stage7-')
    ? 'DEPLOYED_OBSERVATION_RESPONSE'
    : inputs.execution.mode === 'AWS_REAL'
      ? 'AWS_CLI_RESPONSE'
      : 'AWS_SDK_RESPONSE';
  if (
    !exactKeys(response, ['source', 'requestId', 'observedAtUtc', 'payload']) ||
    response.source !== expectedSource ||
    typeof response.requestId !== 'string' ||
    !/^[A-Za-z0-9][A-Za-z0-9-]{15,127}$/u.test(response.requestId) ||
    !utc(response.observedAtUtc) ||
    Date.parse(response.observedAtUtc) < Date.parse(inputs.execution.startedAtUtc) ||
    Date.parse(response.observedAtUtc) > Date.parse(inputs.config.window.endsAtUtc) ||
    !object(response.payload)
  ) {
    fail('E7_RESILIENCE_EXECUTOR_RESPONSE_INVALID');
  }
  state.transcript.push(transcriptEntry({ request, response }));
  validateTranscript(state.transcript, { scenarioId, execution: inputs.execution });
  return response.payload;
};

const stateBody = (state) => {
  const body = { ...state };
  delete body.stateSha256;
  return body;
};

const sealState = (state) => ({ ...stateBody(state), stateSha256: objectSha256(stateBody(state)) });

const validateState = (state, { scenarioId, binding, execution }) => {
  if (
    !exactKeys(state, [
      'schemaVersion',
      'stage',
      'kind',
      'scenarioId',
      'bindingSha256',
      'phase',
      'resumptions',
      'progress',
      'transcript',
      'checkpoint',
      'containsSensitiveData',
      'stateSha256',
    ]) ||
    state.schemaVersion !== 1 ||
    state.stage !== 7 ||
    state.kind !== 'ROLLBACK_RESILIENCE_DURABLE_STATE' ||
    state.scenarioId !== scenarioId ||
    state.bindingSha256 !== binding.bindingSha256 ||
    typeof state.phase !== 'string' ||
    !nonNegativeInteger(state.resumptions) ||
    !object(state.progress) ||
    state.containsSensitiveData !== false ||
    state.stateSha256 !== objectSha256(stateBody(state))
  ) {
    fail('E7_RESILIENCE_DURABLE_STATE_INVALID');
  }
  validateTranscript(state.transcript, { scenarioId, execution });
  return state;
};

const initialState = ({ scenarioId, binding, progress }) =>
  sealState({
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_DURABLE_STATE',
    scenarioId,
    bindingSha256: binding.bindingSha256,
    phase: 'NEW',
    resumptions: 0,
    progress,
    transcript: [],
    checkpoint: null,
    containsSensitiveData: false,
  });

const loadState = async ({ stateStore, scenarioId, binding, execution, progress }) => {
  if (
    !object(stateStore) ||
    typeof stateStore.load !== 'function' ||
    typeof stateStore.save !== 'function'
  ) {
    fail('E7_RESILIENCE_STATE_STORE_INVALID');
  }
  const loaded = await stateStore.load(scenarioId, binding.bindingSha256);
  if (loaded === null) return initialState({ scenarioId, binding, progress });
  const state = validateState(loaded, { scenarioId, binding, execution });
  state.resumptions += 1;
  return sealState(state);
};

const persist = async ({ stateStore, state, phase, checkpoint = state.checkpoint }) => {
  const sealed = sealState({ ...stateBody(state), phase, checkpoint });
  await stateStore.save(sealed.scenarioId, sealed);
  return sealed;
};

/**
 * Append-only, atomic state journal. It stores hashes and resource coordinates,
 * never raw executor responses or payment identifiers.
 */
export const createRollbackResilienceFileStateStore = ({
  directory,
  rootDirectory = process.cwd(),
}) => {
  const root = path.resolve(rootDirectory);
  const target = path.resolve(directory);
  const relative = path.relative(root, target);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('E7_RESILIENCE_STATE_PATH_OUTSIDE_ROOT');
  }
  mkdirSync(target, { recursive: true });
  if (!lstatSync(target).isDirectory() || realpathSync(target) !== target) {
    fail('E7_RESILIENCE_STATE_PATH_INVALID');
  }
  const filesFor = (scenarioId) =>
    readdirSync(target)
      .filter((name) => new RegExp(`^[0-9]{6}-${scenarioId}-[0-9a-f]{64}\\.json$`, 'u').test(name))
      .toSorted();
  return {
    async load(scenarioId) {
      const files = filesFor(scenarioId);
      if (files.length === 0) return null;
      const filename = path.join(target, files.at(-1));
      if (!lstatSync(filename).isFile() || realpathSync(filename) !== filename) {
        fail('E7_RESILIENCE_STATE_PATH_INVALID');
      }
      try {
        return JSON.parse(readFileSync(filename, 'utf8'));
      } catch {
        fail('E7_RESILIENCE_STATE_FILE_INVALID');
      }
    },
    async save(scenarioId, state) {
      const files = filesFor(scenarioId);
      const sequence = String(files.length + 1).padStart(6, '0');
      const basename = `${sequence}-${scenarioId}-${state.stateSha256}.json`;
      const filename = path.join(target, basename);
      const temporary = `${filename}.${process.pid}.tmp`;
      writeFileSync(temporary, `${JSON.stringify(state, null, 2)}\n`, {
        encoding: 'utf8',
        flag: 'wx',
        mode: 0o600,
      });
      renameSync(temporary, filename);
    },
  };
};

const pendingObservation = (value, { before, rehearsal }) => {
  const baseline = rehearsal.rollback.plan.pendingBaseline;
  if (
    !exactKeys(value, [
      'status',
      'trackedBefore',
      'stillPending',
      'reconciled',
      'orphaned',
      'duplicateEffects',
      'lostFacts',
      'snapshotSha256',
      'baselineEvidenceSha256',
      'correlationEvidenceSha256',
      'dataFactsSha256',
      'dataRollbackPerformed',
    ]) ||
    value.status !== (before ? 'PENDING_OBSERVED' : 'PASS') ||
    value.trackedBefore !== baseline.trackedCount ||
    value.trackedBefore < 1 ||
    !nonNegativeInteger(value.stillPending) ||
    !nonNegativeInteger(value.reconciled) ||
    value.trackedBefore !== value.stillPending + value.reconciled ||
    value.orphaned !== 0 ||
    value.duplicateEffects !== 0 ||
    value.lostFacts !== 0 ||
    !SHA256.test(value.snapshotSha256 ?? '') ||
    value.baselineEvidenceSha256 !== baseline.snapshotSha256 ||
    !SHA256.test(value.correlationEvidenceSha256 ?? '') ||
    value.dataFactsSha256 !== rehearsal.rollback.plan.dataFactsSha256 ||
    value.dataRollbackPerformed !== false ||
    (before && (value.stillPending !== value.trackedBefore || value.reconciled !== 0))
  ) {
    fail('E7_RESILIENCE_PENDING_OBSERVATION_INVALID');
  }
  return value;
};

const readSmoke = (value, releaseId) => {
  if (
    !exactKeys(value, [
      'status',
      'releaseId',
      'total',
      'passed',
      'failed',
      'dataMutations',
      'externalRequests',
      'authorizationUsageId',
      'evidenceSha256',
    ]) ||
    value.status !== 'PASS' ||
    value.releaseId !== releaseId ||
    value.total !== 3 ||
    value.passed !== 3 ||
    value.failed !== 0 ||
    value.dataMutations !== 0 ||
    value.externalRequests !== 3 ||
    value.authorizationUsageId !== 'ROLLBACK_RESILIENCE' ||
    !SHA256.test(value.evidenceSha256 ?? '')
  ) {
    fail('E7_RESILIENCE_READ_SMOKE_INVALID');
  }
  return value;
};

const originProtectionBody = (value) => withoutDigest(value, 'evidenceSha256');

const validateOriginProtection = (value, { inputs, runtimeSecretReferenceSha256 }) => {
  const headerNameSha256 = sha256('x-stage7-origin-verify');
  if (
    !exactKeys(value, [
      'status',
      'candidateReleaseId',
      'previousReleaseId',
      'headerNameSha256',
      'candidateSecretReferenceSha256',
      'previousSecretReferenceSha256',
      'candidateSecretVersionIdSha256',
      'previousSecretVersionIdSha256',
      'candidateContractSha256',
      'previousContractSha256',
      'candidateDirectApiStatus',
      'previousDirectApiStatus',
      'candidateViaCloudFrontStatus',
      'previousViaCloudFrontStatus',
      'externalRequests',
      'authorizationUsageId',
      'evidenceSha256',
    ]) ||
    value.status !== 'PASS' ||
    value.candidateReleaseId !== inputs.freezeManifest.releaseId ||
    value.previousReleaseId !== inputs.previousReleaseManifest.previous.releaseId ||
    value.headerNameSha256 !== headerNameSha256 ||
    value.candidateSecretReferenceSha256 !== runtimeSecretReferenceSha256 ||
    value.previousSecretReferenceSha256 !== runtimeSecretReferenceSha256 ||
    !SHA256.test(value.candidateSecretVersionIdSha256 ?? '') ||
    value.previousSecretVersionIdSha256 !== value.candidateSecretVersionIdSha256 ||
    !SHA256.test(value.candidateContractSha256 ?? '') ||
    value.previousContractSha256 !== value.candidateContractSha256 ||
    value.candidateDirectApiStatus !== 403 ||
    value.previousDirectApiStatus !== 403 ||
    value.candidateViaCloudFrontStatus !== 200 ||
    value.previousViaCloudFrontStatus !== 200 ||
    value.externalRequests !== 1 ||
    value.authorizationUsageId !== 'ROLLBACK_RESILIENCE' ||
    value.evidenceSha256 !== objectSha256(originProtectionBody(value))
  ) {
    fail('E7_RESILIENCE_ORIGIN_PROTECTION_DRIFT');
  }
  return value;
};

const rb06Progress = () => ({
  changeSetIntent: null,
  changeSet: null,
  preStack: null,
  originProtection: null,
  pendingBefore: null,
  clientRequestTokenSha256: null,
  mutationIntentRecorded: false,
  mutationRequestObserved: false,
  failureEventSha256: null,
  rollbackEventChainSha256: null,
  finalStack: null,
  pendingAfter: null,
  smoke: null,
  polls: 0,
});

const validateRb06Descriptor = (descriptor, { inputs, binding, parsedDocuments }) => {
  const deploymentBinding =
    parsedDocuments?.observability?.checkpoints?.observability?.rollbackResilience;
  if (
    !exactKeys(descriptor, [
      'stackName',
      'failureLogicalResourceId',
      'failureResourceType',
      'failureTimeoutSeconds',
      'frozenTemplateSha256',
      'cloudFormationExecutionRoleArn',
      'runtimeSecretReferenceSha256',
      'maxPolls',
    ]) ||
    !inputs.config.authorization.stacks.includes(descriptor.stackName) ||
    descriptor.failureLogicalResourceId !== FAILURE_LOGICAL_ID ||
    descriptor.failureResourceType !== FAILURE_RESOURCE_TYPE ||
    descriptor.failureTimeoutSeconds !== 60 ||
    !SHA256.test(descriptor.frozenTemplateSha256 ?? '') ||
    deploymentBinding?.templateSha256 !== descriptor.frozenTemplateSha256 ||
    descriptor.cloudFormationExecutionRoleArn !== cloudFormationExecutionRoleArn(inputs) ||
    deploymentBinding?.cloudFormationExecutionRoleArn !==
      descriptor.cloudFormationExecutionRoleArn ||
    !SHA256.test(descriptor.runtimeSecretReferenceSha256 ?? '') ||
    !inputs.config.credentialReferences.some(
      (reference) => sha256(reference) === descriptor.runtimeSecretReferenceSha256,
    ) ||
    !Number.isSafeInteger(descriptor.maxPolls) ||
    descriptor.maxPolls < 3 ||
    descriptor.maxPolls > 60
  ) {
    fail('E7_RB06_DESCRIPTOR_INVALID');
  }
  return {
    ...descriptor,
    changeSetName: `e7-rb06-${binding.bindingSha256.slice(0, 24)}-${inputs.execution.runId}`,
    description: `stage7-rb06-${binding.bindingSha256}`,
  };
};

const stackObservation = (payload, { descriptor, inputs, clientRequestToken, allowNoToken }) => {
  if (
    !exactKeys(payload, ['stack', 'events']) ||
    !object(payload.stack) ||
    payload.stack.stackName !== descriptor.stackName ||
    typeof payload.stack.stackId !== 'string' ||
    !payload.stack.stackId.startsWith(
      `arn:aws:cloudformation:${inputs.config.aws.region}:${inputs.config.aws.accountId}:stack/${descriptor.stackName}/`,
    ) ||
    !STACK_STATUS.has(payload.stack.stackStatus) ||
    !Array.isArray(payload.stack.parameters) ||
    !payload.stack.parameters.every(
      (entry) =>
        exactKeys(entry, ['key', 'value']) &&
        typeof entry.key === 'string' &&
        SAFE_NAME.test(entry.key) &&
        typeof entry.value === 'string' &&
        entry.value.length <= 4096,
    ) ||
    !Array.isArray(payload.stack.capabilities) ||
    !payload.stack.capabilities.every((entry) =>
      ['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM', 'CAPABILITY_AUTO_EXPAND'].includes(entry),
    ) ||
    payload.stack.roleArn !== descriptor.cloudFormationExecutionRoleArn ||
    !Array.isArray(payload.stack.tags) ||
    !Array.isArray(payload.events)
  ) {
    fail('E7_RB06_STACK_OBSERVATION_INVALID');
  }
  const tags = Object.fromEntries(payload.stack.tags.map((entry) => [entry.key, entry.value]));
  if (
    tags.CandidateSha !== inputs.freezeManifest.candidateSha ||
    tags.ReleaseId !== inputs.freezeManifest.releaseId ||
    tags.Environment !== inputs.config.environment ||
    tags.ManagedBy !== 'cdk'
  ) {
    fail('E7_RB06_STACK_IDENTITY_MISMATCH');
  }
  for (const event of payload.events) {
    if (
      !exactKeys(event, [
        'eventId',
        'timestamp',
        'logicalResourceId',
        'resourceType',
        'resourceStatus',
        'resourceStatusReason',
        'clientRequestToken',
      ]) ||
      typeof event.eventId !== 'string' ||
      !SAFE_NAME.test(event.eventId) ||
      !utc(event.timestamp) ||
      typeof event.logicalResourceId !== 'string' ||
      !SAFE_NAME.test(event.logicalResourceId) ||
      typeof event.resourceType !== 'string' ||
      !SAFE_NAME.test(event.resourceType) ||
      typeof event.resourceStatus !== 'string' ||
      !SAFE_NAME.test(event.resourceStatus) ||
      (event.resourceStatusReason !== null &&
        (typeof event.resourceStatusReason !== 'string' ||
          event.resourceStatusReason.length < 3 ||
          event.resourceStatusReason.length > 1024)) ||
      (event.clientRequestToken !== null && event.clientRequestToken !== clientRequestToken)
    ) {
      fail('E7_RB06_STACK_EVENT_INVALID');
    }
  }
  if (
    !allowNoToken &&
    !payload.events.some((event) => event.clientRequestToken === clientRequestToken)
  ) {
    fail('E7_RB06_TOKEN_EVENT_MISSING');
  }
  return { payload, tags };
};

const validateChangeSet = (value, { descriptor, inputs, preStack, derivedTemplateSha256 }) => {
  const changeSetPattern = new RegExp(
    `^arn:aws:cloudformation:${inputs.config.aws.region}:${inputs.config.aws.accountId}:changeSet/${descriptor.changeSetName}/[A-Za-z0-9-]{16,128}$`,
    'u',
  );
  if (
    !changeSetPattern.test(value.changeSetId ?? '') ||
    value.changeSetName !== descriptor.changeSetName ||
    value.stackName !== descriptor.stackName ||
    typeof value.stackId !== 'string' ||
    !value.stackId.startsWith(
      `arn:aws:cloudformation:${inputs.config.aws.region}:${inputs.config.aws.accountId}:stack/${descriptor.stackName}/`,
    ) ||
    value.status !== 'CREATE_COMPLETE' ||
    value.executionStatus !== 'AVAILABLE' ||
    value.changeSetType !== 'UPDATE' ||
    value.description !== descriptor.description ||
    value.includeNestedStacks !== false ||
    value.templateSha256 !== derivedTemplateSha256 ||
    canonicalJson(value.parameters) !== canonicalJson(preStack.parameters) ||
    value.capabilities?.join('\0') !== preStack.capabilities.join('\0') ||
    value.roleArn !== preStack.roleArn ||
    !Array.isArray(value.changes) ||
    value.changes.length !== 1
  ) {
    fail('E7_RB06_CHANGE_SET_INVALID');
  }
  const [change] = value.changes;
  if (
    !exactKeys(change, ['action', 'logicalResourceId', 'resourceType', 'replacement']) ||
    change.action !== 'Add' ||
    change.logicalResourceId !== descriptor.failureLogicalResourceId ||
    change.resourceType !== descriptor.failureResourceType ||
    change.replacement !== 'False'
  ) {
    fail('E7_RB06_CHANGE_SET_UNSAFE');
  }
  return value;
};

const deriveFailureTemplate = (template, descriptor) => {
  if (
    !object(template) ||
    !object(template.Resources) ||
    Object.hasOwn(template.Resources, descriptor.failureLogicalResourceId)
  ) {
    fail('E7_RB06_LIVE_TEMPLATE_INVALID');
  }
  const derived = JSON.parse(JSON.stringify(template));
  derived.Resources[descriptor.failureLogicalResourceId] = {
    Type: descriptor.failureResourceType,
    Properties: { Count: 1, Timeout: String(descriptor.failureTimeoutSeconds) },
  };
  const beforeKeys = Object.keys(template.Resources).toSorted();
  const afterKeys = Object.keys(derived.Resources).toSorted();
  if (
    afterKeys.length !== beforeKeys.length + 1 ||
    afterKeys.filter((key) => key !== descriptor.failureLogicalResourceId).join('\0') !==
      beforeKeys.join('\0') ||
    canonicalJson({ ...derived, Resources: template.Resources }) !== canonicalJson(template)
  ) {
    fail('E7_RB06_DERIVED_TEMPLATE_UNSAFE');
  }
  return derived;
};

const rb06FailureEvent = (events, descriptor, token) =>
  events.find(
    (event) =>
      event.clientRequestToken === token &&
      event.logicalResourceId === descriptor.failureLogicalResourceId &&
      event.resourceType === descriptor.failureResourceType &&
      event.resourceStatus === 'CREATE_FAILED' &&
      typeof event.resourceStatusReason === 'string' &&
      event.resourceStatusReason.length >= 8,
  );

const rb06RollbackCompleteEvent = (events, descriptor, token) =>
  events.find(
    (event) =>
      event.clientRequestToken === token &&
      event.logicalResourceId === descriptor.stackName &&
      event.resourceType === 'AWS::CloudFormation::Stack' &&
      event.resourceStatus === 'UPDATE_ROLLBACK_COMPLETE',
  );

const rb06CheckpointBody = ({
  inputs,
  binding,
  descriptor,
  state,
  startedAtUtc,
  completedAtUtc,
}) => {
  const real = inputs.execution.mode === 'AWS_REAL';
  const progress = state.progress;
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'RB_E7_06_CLOUDFORMATION_FAILURE_RECOVERY',
    status: real ? 'AWS_VERIFIED' : 'BLOCKED_REAL_AWS_REQUIRED',
    scenarioId: 'RB-E7-06',
    gateEffect: real ? 'ELIGIBLE_FOR_REHEARSAL_ADAPTER' : 'KEEP_GATE_BLOCKED',
    executionMode: inputs.execution.mode,
    binding,
    scenarioInputSha256: objectSha256(descriptor),
    startedAtUtc,
    completedAtUtc,
    stack: {
      stackName: descriptor.stackName,
      stackIdSha256: progress.finalStack.stackIdSha256,
      changeSetIdSha256: progress.changeSet.changeSetIdSha256,
      liveTemplateSha256: progress.changeSet.liveTemplateSha256,
      failureTemplateSha256: progress.changeSet.derivedTemplateSha256,
      initialStatus: 'UPDATE_COMPLETE',
      failureStatus: 'UPDATE_ROLLBACK_IN_PROGRESS',
      finalStatus: 'UPDATE_ROLLBACK_COMPLETE',
    },
    failure: {
      mutationAttempted: true,
      failureObserved: true,
      failureLogicalResourceId: descriptor.failureLogicalResourceId,
      failureResourceType: descriptor.failureResourceType,
      failureEventSha256: progress.failureEventSha256,
      clientRequestTokenSha256: progress.clientRequestTokenSha256,
    },
    recovery: {
      mechanism: 'CLOUDFORMATION_AUTOMATIC_ROLLBACK',
      continueUpdateRollbackInvoked: false,
      rollbackEventChainSha256: progress.rollbackEventChainSha256,
      resumeSafe: true,
      resumptions: state.resumptions,
      pollCount: progress.polls,
      retryDecision: 'NOOP_AFTER_VERIFIED_RECOVERY',
    },
    pendingIntegrity: { ...progress.pendingAfter },
    originProtection: { ...progress.originProtection },
    smoke: { ...progress.smoke },
    dataPolicy: 'NO_ROLLBACK_FORWARD_ONLY',
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    mutationCount: 2,
    transcript: [...state.transcript],
    containsSensitiveData: false,
  };
};

export const validateRbE706Checkpoint = (checkpoint, { inputs, descriptor, authority }) => {
  const real = inputs?.execution?.mode === 'AWS_REAL';
  if (real && authority !== PROTECTED_AWS_EVIDENCE_AUTHORITY) {
    fail('E7_RESILIENCE_AWS_EVIDENCE_AUTHORITY_REQUIRED');
  }
  const { binding, parsedDocuments } = validateBoundInputs(inputs);
  const checkedDescriptor = validateRb06Descriptor(descriptor, {
    inputs,
    binding,
    parsedDocuments,
  });
  if (
    !exactKeys(checkpoint, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scenarioId',
      'gateEffect',
      'executionMode',
      'binding',
      'scenarioInputSha256',
      'startedAtUtc',
      'completedAtUtc',
      'stack',
      'failure',
      'recovery',
      'pendingIntegrity',
      'originProtection',
      'smoke',
      'dataPolicy',
      'dataRollbackPerformed',
      'stacksDeleted',
      'mutationCount',
      'transcript',
      'containsSensitiveData',
      'checkpointSha256',
    ]) ||
    checkpoint.schemaVersion !== 1 ||
    checkpoint.stage !== 7 ||
    checkpoint.kind !== 'RB_E7_06_CLOUDFORMATION_FAILURE_RECOVERY' ||
    checkpoint.status !== (real ? 'AWS_VERIFIED' : 'BLOCKED_REAL_AWS_REQUIRED') ||
    checkpoint.scenarioId !== 'RB-E7-06' ||
    checkpoint.gateEffect !== (real ? 'ELIGIBLE_FOR_REHEARSAL_ADAPTER' : 'KEEP_GATE_BLOCKED') ||
    checkpoint.executionMode !== inputs.execution.mode ||
    canonicalJson(checkpoint.binding) !== canonicalJson(binding) ||
    checkpoint.scenarioInputSha256 !== objectSha256(checkedDescriptor) ||
    !utc(checkpoint.startedAtUtc) ||
    checkpoint.startedAtUtc !== inputs.execution.startedAtUtc ||
    !utc(checkpoint.completedAtUtc) ||
    Date.parse(checkpoint.completedAtUtc) < Date.parse(checkpoint.startedAtUtc) ||
    !exactKeys(checkpoint.stack, [
      'stackName',
      'stackIdSha256',
      'changeSetIdSha256',
      'liveTemplateSha256',
      'failureTemplateSha256',
      'initialStatus',
      'failureStatus',
      'finalStatus',
    ]) ||
    checkpoint.stack.stackName !== checkedDescriptor.stackName ||
    !SHA256.test(checkpoint.stack.stackIdSha256 ?? '') ||
    !SHA256.test(checkpoint.stack.changeSetIdSha256 ?? '') ||
    !SHA256.test(checkpoint.stack.liveTemplateSha256 ?? '') ||
    !SHA256.test(checkpoint.stack.failureTemplateSha256 ?? '') ||
    checkpoint.stack.liveTemplateSha256 === checkpoint.stack.failureTemplateSha256 ||
    checkpoint.stack.liveTemplateSha256 !== checkedDescriptor.frozenTemplateSha256 ||
    checkpoint.stack.initialStatus !== 'UPDATE_COMPLETE' ||
    checkpoint.stack.failureStatus !== 'UPDATE_ROLLBACK_IN_PROGRESS' ||
    checkpoint.stack.finalStatus !== 'UPDATE_ROLLBACK_COMPLETE' ||
    !exactKeys(checkpoint.failure, [
      'mutationAttempted',
      'failureObserved',
      'failureLogicalResourceId',
      'failureResourceType',
      'failureEventSha256',
      'clientRequestTokenSha256',
    ]) ||
    checkpoint.failure.mutationAttempted !== true ||
    checkpoint.failure.failureObserved !== true ||
    checkpoint.failure.failureLogicalResourceId !== FAILURE_LOGICAL_ID ||
    checkpoint.failure.failureResourceType !== FAILURE_RESOURCE_TYPE ||
    !SHA256.test(checkpoint.failure.failureEventSha256 ?? '') ||
    !SHA256.test(checkpoint.failure.clientRequestTokenSha256 ?? '') ||
    !exactKeys(checkpoint.recovery, [
      'mechanism',
      'continueUpdateRollbackInvoked',
      'rollbackEventChainSha256',
      'resumeSafe',
      'resumptions',
      'pollCount',
      'retryDecision',
    ]) ||
    checkpoint.recovery.mechanism !== 'CLOUDFORMATION_AUTOMATIC_ROLLBACK' ||
    checkpoint.recovery.continueUpdateRollbackInvoked !== false ||
    !SHA256.test(checkpoint.recovery.rollbackEventChainSha256 ?? '') ||
    checkpoint.recovery.resumeSafe !== true ||
    !nonNegativeInteger(checkpoint.recovery.resumptions) ||
    !positiveInteger(checkpoint.recovery.pollCount) ||
    checkpoint.recovery.retryDecision !== 'NOOP_AFTER_VERIFIED_RECOVERY' ||
    checkpoint.dataPolicy !== 'NO_ROLLBACK_FORWARD_ONLY' ||
    checkpoint.dataRollbackPerformed !== false ||
    checkpoint.stacksDeleted !== 0 ||
    checkpoint.mutationCount !== 2 ||
    checkpoint.containsSensitiveData !== false
  ) {
    fail('E7_RB06_CHECKPOINT_INVALID');
  }
  pendingObservation(checkpoint.pendingIntegrity, {
    before: false,
    rehearsal: inputs.baseRehearsal,
  });
  validateOriginProtection(checkpoint.originProtection, {
    inputs,
    runtimeSecretReferenceSha256: checkedDescriptor.runtimeSecretReferenceSha256,
  });
  readSmoke(checkpoint.smoke, inputs.freezeManifest.releaseId);
  validateTranscript(checkpoint.transcript, {
    scenarioId: 'RB-E7-06',
    execution: inputs.execution,
  });
  if (checkpoint.checkpointSha256 !== objectSha256(withoutDigest(checkpoint, 'checkpointSha256'))) {
    fail('E7_RB06_CHECKPOINT_DIGEST_INVALID');
  }
  return checkpoint;
};

const produceRbE706 = async ({ inputs, descriptor, executor, stateStore, capability }) => {
  if (
    (inputs.execution.mode === 'LOCAL_SIMULATION' &&
      capability !== SELF_TEST_EXECUTOR_CAPABILITY) ||
    (inputs.execution.mode === 'AWS_REAL' && capability !== PROTECTED_AWS_EXECUTOR_CAPABILITY)
  ) {
    fail('E7_RESILIENCE_EXECUTOR_CAPABILITY_INVALID');
  }
  const { binding, parsedDocuments } = validateBoundInputs(inputs);
  const checkedDescriptor = validateRb06Descriptor(descriptor, {
    inputs,
    binding,
    parsedDocuments,
  });
  let state = await loadState({
    stateStore,
    scenarioId: 'RB-E7-06',
    binding,
    execution: inputs.execution,
    progress: rb06Progress(),
  });
  if (state.phase === 'COMPLETE') {
    return validateRbE706Checkpoint(state.checkpoint, {
      inputs,
      descriptor,
      authority:
        inputs.execution.mode === 'AWS_REAL' ? PROTECTED_AWS_EVIDENCE_AUTHORITY : undefined,
    });
  }
  const progress = state.progress;
  const startedAtUtc = inputs.execution.startedAtUtc;
  const clientRequestToken = `e7rb06-${binding.bindingSha256.slice(0, 24)}-${inputs.execution.runId}`;

  if (progress.changeSet === null) {
    const pre = stackObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-06',
        service: 'cloudformation',
        operation: 'DescribeStacks',
        input: { stackName: checkedDescriptor.stackName },
      }),
      { descriptor: checkedDescriptor, inputs, clientRequestToken, allowNoToken: true },
    ).payload;
    if (pre.stack.stackStatus !== 'UPDATE_COMPLETE' || pre.events.length !== 0) {
      fail('E7_RB06_PRECONDITION_NOT_STABLE');
    }
    const liveTemplateResponse = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-06',
      service: 'cloudformation',
      operation: 'GetTemplate',
      input: { stackName: checkedDescriptor.stackName, templateStage: 'Original' },
    });
    if (
      !exactKeys(liveTemplateResponse, ['templateBody']) ||
      !object(liveTemplateResponse.templateBody)
    ) {
      fail('E7_RB06_LIVE_TEMPLATE_INVALID');
    }
    const derivedTemplate = deriveFailureTemplate(
      liveTemplateResponse.templateBody,
      checkedDescriptor,
    );
    const liveTemplateSha256 = objectSha256(liveTemplateResponse.templateBody);
    const derivedTemplateSha256 = objectSha256(derivedTemplate);
    if (liveTemplateSha256 !== checkedDescriptor.frozenTemplateSha256) {
      fail('E7_RB06_LIVE_TEMPLATE_NOT_FROZEN');
    }
    const createClientToken = `e7rb06-create-${binding.bindingSha256.slice(0, 20)}-${inputs.execution.runId}`;
    const intent = {
      changeSetName: checkedDescriptor.changeSetName,
      liveTemplateSha256,
      derivedTemplateSha256,
      parametersSha256: objectSha256(pre.stack.parameters),
      capabilitiesSha256: objectSha256(pre.stack.capabilities),
      roleArnSha256: pre.stack.roleArn === null ? null : sha256(pre.stack.roleArn),
      createClientTokenSha256: sha256(createClientToken),
    };
    if (
      progress.changeSetIntent !== null &&
      canonicalJson(progress.changeSetIntent) !== canonicalJson(intent)
    ) {
      fail('E7_RB06_CHANGE_SET_INTENT_DRIFT');
    }
    progress.changeSetIntent = intent;
    progress.preStack = {
      stackIdSha256: sha256(pre.stack.stackId),
      stackStatus: pre.stack.stackStatus,
      observationSha256: objectSha256(pre),
    };
    state = await persist({ stateStore, state, phase: 'CHANGE_SET_INTENT_RECORDED' });
    const created = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-06',
      service: 'cloudformation',
      operation: 'CreateChangeSet',
      input: {
        stackName: checkedDescriptor.stackName,
        changeSetName: checkedDescriptor.changeSetName,
        description: checkedDescriptor.description,
        changeSetType: 'UPDATE',
        includeNestedStacks: false,
        templateBody: derivedTemplate,
        parameters: pre.stack.parameters.map(({ key }) => ({ key, usePreviousValue: true })),
        capabilities: pre.stack.capabilities,
        roleArn: pre.stack.roleArn,
        clientToken: createClientToken,
      },
    });
    if (
      !exactKeys(created, ['changeSetId', 'stackId']) ||
      typeof created.changeSetId !== 'string' ||
      typeof created.stackId !== 'string'
    ) {
      fail('E7_RB06_CHANGE_SET_CREATE_INVALID');
    }
    const changeSet = validateChangeSet(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-06',
        service: 'cloudformation',
        operation: 'DescribeChangeSet',
        input: { changeSetName: created.changeSetId, stackName: checkedDescriptor.stackName },
      }),
      { descriptor: checkedDescriptor, inputs, preStack: pre.stack, derivedTemplateSha256 },
    );
    const changeSetTemplateResponse = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-06',
      service: 'cloudformation',
      operation: 'GetTemplateForChangeSet',
      input: { stackName: checkedDescriptor.stackName, changeSetName: changeSet.changeSetId },
    });
    if (
      !exactKeys(changeSetTemplateResponse, ['templateBody']) ||
      objectSha256(changeSetTemplateResponse.templateBody) !== derivedTemplateSha256
    ) {
      fail('E7_RB06_CHANGE_SET_TEMPLATE_MISMATCH');
    }
    progress.changeSet = {
      changeSetIdSha256: sha256(changeSet.changeSetId),
      stackIdSha256: sha256(changeSet.stackId),
      liveTemplateSha256,
      derivedTemplateSha256,
      responseSha256: objectSha256(changeSet),
    };
    if (progress.preStack.stackIdSha256 !== progress.changeSet.stackIdSha256) {
      fail('E7_RB06_CHANGE_SET_STACK_MISMATCH');
    }
    progress.pendingBefore = pendingObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-06',
        service: 'stage7-pending-integrity',
        operation: 'ReadBeforeFailureMutation',
        input: {
          releaseId: inputs.freezeManifest.releaseId,
          pendingBaselineSha256: inputs.baseRehearsal.rollback.plan.pendingBaseline.snapshotSha256,
        },
      }),
      { before: true, rehearsal: inputs.baseRehearsal },
    );
    if (
      progress.pendingBefore.snapshotSha256 !==
      inputs.baseRehearsal.rollback.plan.pendingBaseline.snapshotSha256
    ) {
      fail('E7_RB06_PENDING_BASELINE_DRIFT');
    }
    progress.originProtection = validateOriginProtection(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-06',
        service: 'stage7-origin-protection',
        operation: 'VerifyNAndNMinus1Compatibility',
        input: {
          candidateReleaseId: inputs.freezeManifest.releaseId,
          previousReleaseId: inputs.previousReleaseManifest.previous.releaseId,
          runtimeSecretReferenceSha256: checkedDescriptor.runtimeSecretReferenceSha256,
        },
      }),
      { inputs, runtimeSecretReferenceSha256: checkedDescriptor.runtimeSecretReferenceSha256 },
    );
    state = await persist({ stateStore, state, phase: 'PREFLIGHT_VERIFIED' });
  }

  if (!progress.mutationIntentRecorded) {
    progress.clientRequestTokenSha256 = sha256(clientRequestToken);
    progress.mutationIntentRecorded = true;
    state = await persist({ stateStore, state, phase: 'MUTATION_INTENT_RECORDED' });
  }

  let observation = stackObservation(
    await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-06',
      service: 'cloudformation',
      operation: 'DescribeStackEvents',
      input: { stackName: checkedDescriptor.stackName, clientRequestToken },
    }),
    { descriptor: checkedDescriptor, inputs, clientRequestToken, allowNoToken: true },
  ).payload;
  const tokenAlreadyObserved = observation.events.some(
    (event) => event.clientRequestToken === clientRequestToken,
  );
  if (!progress.mutationRequestObserved && !tokenAlreadyObserved) {
    if (observation.stack.stackStatus !== 'UPDATE_COMPLETE') {
      fail('E7_RB06_UNRELATED_MUTATION_IN_PROGRESS');
    }
    const accepted = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-06',
      service: 'cloudformation',
      operation: 'ExecuteChangeSet',
      input: {
        changeSetName: checkedDescriptor.changeSetName,
        stackName: checkedDescriptor.stackName,
        clientRequestToken,
      },
    });
    if (Object.keys(accepted).length !== 0) fail('E7_RB06_EXECUTE_RESPONSE_INVALID');
    progress.mutationRequestObserved = true;
    state = await persist({ stateStore, state, phase: 'MUTATION_REQUEST_ACCEPTED' });
  } else if (tokenAlreadyObserved) {
    progress.mutationRequestObserved = true;
  }

  let currentObservationUsable = tokenAlreadyObserved;
  for (; progress.polls < checkedDescriptor.maxPolls;) {
    if (!currentObservationUsable) {
      observation = stackObservation(
        await invoke({
          executor,
          state,
          inputs,
          binding,
          scenarioId: 'RB-E7-06',
          service: 'cloudformation',
          operation: 'DescribeStackEvents',
          input: { stackName: checkedDescriptor.stackName, clientRequestToken },
        }),
        { descriptor: checkedDescriptor, inputs, clientRequestToken, allowNoToken: false },
      ).payload;
    }
    currentObservationUsable = false;
    progress.polls += 1;
    if (observation.stack.stackStatus === 'UPDATE_ROLLBACK_FAILED') {
      state = await persist({ stateStore, state, phase: 'MANUAL_DIAGNOSIS_REQUIRED' });
      fail('E7_RB06_CONTINUE_UPDATE_ROLLBACK_FORBIDDEN_WITHOUT_DIAGNOSIS');
    }
    const failureEvent = rb06FailureEvent(
      observation.events,
      checkedDescriptor,
      clientRequestToken,
    );
    if (
      ['UPDATE_FAILED', 'UPDATE_ROLLBACK_IN_PROGRESS', 'UPDATE_ROLLBACK_COMPLETE'].includes(
        observation.stack.stackStatus,
      ) &&
      failureEvent === undefined
    ) {
      fail('E7_RB06_FAILURE_EVENT_MISSING');
    }
    if (failureEvent !== undefined && progress.failureEventSha256 === null) {
      progress.failureEventSha256 = objectSha256(failureEvent);
      state = await persist({ stateStore, state, phase: 'FAILURE_OBSERVED' });
    } else {
      state = await persist({ stateStore, state, phase: 'ROLLBACK_MONITORING' });
    }
    if (observation.stack.stackStatus === 'UPDATE_ROLLBACK_COMPLETE') {
      const completeEvent = rb06RollbackCompleteEvent(
        observation.events,
        checkedDescriptor,
        clientRequestToken,
      );
      if (completeEvent === undefined) fail('E7_RB06_ROLLBACK_COMPLETE_EVENT_MISSING');
      progress.rollbackEventChainSha256 = objectSha256(
        observation.events.filter((event) => event.clientRequestToken === clientRequestToken),
      );
      progress.finalStack = {
        stackIdSha256: sha256(observation.stack.stackId),
        stackStatus: observation.stack.stackStatus,
        observationSha256: objectSha256(observation),
      };
      break;
    }
  }
  if (progress.finalStack === null) fail('E7_RB06_ROLLBACK_TIMEOUT');

  progress.pendingAfter = pendingObservation(
    await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-06',
      service: 'stage7-pending-integrity',
      operation: 'ReadAfterCloudFormationRecovery',
      input: {
        releaseId: inputs.freezeManifest.releaseId,
        beforeSnapshotSha256: progress.pendingBefore.snapshotSha256,
      },
    }),
    { before: false, rehearsal: inputs.baseRehearsal },
  );
  if (
    progress.pendingAfter.snapshotSha256 !== progress.pendingBefore.snapshotSha256 ||
    progress.pendingAfter.stillPending !== progress.pendingAfter.trackedBefore ||
    progress.pendingAfter.reconciled !== 0
  ) {
    fail('E7_RB06_PENDING_NOT_PRESERVED');
  }
  progress.smoke = readSmoke(
    await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-06',
      service: 'stage7-read-smoke',
      operation: 'RunAfterCloudFormationRecovery',
      input: { releaseId: inputs.freezeManifest.releaseId, expectedRequests: 3 },
    }),
    inputs.freezeManifest.releaseId,
  );
  const completedAtUtc = state.transcript.at(-1).observedAtUtc;
  const body = rb06CheckpointBody({
    inputs,
    binding,
    descriptor: checkedDescriptor,
    state,
    startedAtUtc,
    completedAtUtc,
  });
  const checkpoint = { ...body, checkpointSha256: objectSha256(body) };
  validateRbE706Checkpoint(checkpoint, {
    inputs,
    descriptor,
    authority: inputs.execution.mode === 'AWS_REAL' ? PROTECTED_AWS_EVIDENCE_AUTHORITY : undefined,
  });
  state = await persist({ stateStore, state, phase: 'COMPLETE', checkpoint });
  return state.checkpoint;
};

const rb08Progress = () => ({
  originProtection: null,
  pendingBefore: null,
  baselineAlarm: null,
  stimulus: null,
  breachedAlarm: null,
  decisionRecorded: false,
  api: null,
  worker: null,
  web: [],
  invalidation: null,
  pendingAfter: null,
  smoke: null,
  recoveryStimulus: null,
  recoveredAlarm: null,
  repromotion: {
    api: null,
    worker: null,
    web: [],
    invalidation: null,
    smoke: null,
    pendingIntegrity: null,
  },
  alarmPolls: 0,
  recoveryPolls: 0,
  mutationCount: 0,
});

const validateRb08Descriptor = (descriptor, { inputs, parsedDocuments }) => {
  const expectedStack = expectedStage7Stacks(inputs.config.environment)[2];
  const expectedAlarmName = `checkout-${inputs.config.environment}-rollback-rehearsal`;
  const expectedDimensions = [
    { name: 'Environment', value: inputs.config.environment },
    { name: 'ReleaseId', value: inputs.freezeManifest.releaseId },
    { name: 'Scenario', value: 'RB-E7-08' },
  ];
  const alarmArnPattern = new RegExp(
    `^arn:aws:cloudwatch:${inputs.config.aws.region}:${inputs.config.aws.accountId}:alarm:[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$`,
    'u',
  );
  const expectedDeploymentBinding = {
    stackName: expectedStack,
    templateSha256: descriptor.observabilityTemplateSha256,
    cloudFormationExecutionRoleArn: cloudFormationExecutionRoleArn(inputs),
    rollbackRehearsalAlarm: {
      alarmName: descriptor.alarmName,
      alarmArn: descriptor.alarmArn,
      metricNamespace: descriptor.metricNamespace,
      metricName: descriptor.metricName,
      dimensions: descriptor.dimensions,
      statistic: descriptor.statistic,
      unit: descriptor.unit,
      periodSeconds: descriptor.periodSeconds,
      evaluationPeriods: descriptor.evaluationPeriods,
      threshold: descriptor.threshold,
      comparisonOperator: descriptor.comparisonOperator,
      treatMissingData: descriptor.treatMissingData,
      actionsEnabled: descriptor.actionsEnabled,
      alarmActions: descriptor.alarmActions,
      okActions: descriptor.okActions,
      insufficientDataActions: descriptor.insufficientDataActions,
    },
  };
  const deployedBinding =
    parsedDocuments?.observability?.checkpoints?.observability?.rollbackResilience;
  if (
    !exactKeys(descriptor, [
      'alarmName',
      'alarmArn',
      'observabilityStackName',
      'observabilityTemplateSha256',
      'metricNamespace',
      'metricName',
      'dimensions',
      'statistic',
      'unit',
      'periodSeconds',
      'evaluationPeriods',
      'threshold',
      'comparisonOperator',
      'treatMissingData',
      'actionsEnabled',
      'alarmActions',
      'okActions',
      'insufficientDataActions',
      'activationAtUtc',
      'runtimeSecretReferenceSha256',
      'maxPolls',
    ]) ||
    descriptor.alarmName !== expectedAlarmName ||
    !alarmArnPattern.test(descriptor.alarmArn ?? '') ||
    !descriptor.alarmArn.endsWith(`:${descriptor.alarmName}`) ||
    descriptor.observabilityStackName !== expectedStack ||
    !SHA256.test(descriptor.observabilityTemplateSha256 ?? '') ||
    canonicalJson(deployedBinding) !== canonicalJson(expectedDeploymentBinding) ||
    descriptor.metricNamespace !== 'Checkout/Stage7Rehearsal' ||
    descriptor.metricName !== 'RollbackRehearsalFailure' ||
    canonicalJson(descriptor.dimensions) !== canonicalJson(expectedDimensions) ||
    descriptor.statistic !== 'Maximum' ||
    descriptor.unit !== 'Count' ||
    descriptor.periodSeconds !== 60 ||
    descriptor.evaluationPeriods !== 1 ||
    descriptor.threshold !== 1 ||
    descriptor.comparisonOperator !== 'GreaterThanOrEqualToThreshold' ||
    descriptor.treatMissingData !== 'notBreaching' ||
    descriptor.actionsEnabled !== false ||
    !Array.isArray(descriptor.alarmActions) ||
    descriptor.alarmActions.length !== 0 ||
    !Array.isArray(descriptor.okActions) ||
    descriptor.okActions.length !== 0 ||
    !Array.isArray(descriptor.insufficientDataActions) ||
    descriptor.insufficientDataActions.length !== 0 ||
    !utc(descriptor.activationAtUtc) ||
    Date.parse(descriptor.activationAtUtc) < Date.parse(inputs.config.window.startsAtUtc) ||
    Date.parse(descriptor.activationAtUtc) > Date.parse(inputs.execution.startedAtUtc) ||
    parsedDocuments.activation.updatedAtUtc !== descriptor.activationAtUtc ||
    !SHA256.test(descriptor.runtimeSecretReferenceSha256 ?? '') ||
    !inputs.config.credentialReferences.some(
      (reference) => sha256(reference) === descriptor.runtimeSecretReferenceSha256,
    ) ||
    !Number.isSafeInteger(descriptor.maxPolls) ||
    descriptor.maxPolls < 3 ||
    descriptor.maxPolls > 60
  ) {
    fail('E7_RB08_DESCRIPTOR_INVALID');
  }
  return descriptor;
};

const alarmObservation = (value, { descriptor, expectedState, afterUtc, beforeOrAtUtc }) => {
  if (
    !exactKeys(value, [
      'alarmName',
      'alarmArn',
      'stateValue',
      'stateUpdatedAtUtc',
      'stateReason',
      'stateReasonData',
      'namespace',
      'metricName',
      'dimensions',
      'statistic',
      'unit',
      'periodSeconds',
      'evaluationPeriods',
      'threshold',
      'comparisonOperator',
      'treatMissingData',
      'actionsEnabled',
      'alarmActions',
      'okActions',
      'insufficientDataActions',
    ]) ||
    value.alarmName !== descriptor.alarmName ||
    value.alarmArn !== descriptor.alarmArn ||
    value.stateValue !== expectedState ||
    !utc(value.stateUpdatedAtUtc) ||
    (afterUtc !== undefined && Date.parse(value.stateUpdatedAtUtc) < Date.parse(afterUtc)) ||
    (beforeOrAtUtc !== undefined &&
      Date.parse(value.stateUpdatedAtUtc) > Date.parse(beforeOrAtUtc)) ||
    typeof value.stateReason !== 'string' ||
    value.stateReason.length < 8 ||
    value.stateReason.length > 1024 ||
    !object(value.stateReasonData) ||
    !utc(value.stateReasonData.queryDate) ||
    !Array.isArray(value.stateReasonData.recentDatapoints) ||
    (expectedState === 'ALARM' && value.stateReasonData.recentDatapoints.length < 1) ||
    !value.stateReasonData.recentDatapoints.every(
      (point) =>
        exactKeys(point, ['timestamp', 'value']) &&
        utc(point.timestamp) &&
        typeof point.value === 'number' &&
        Number.isFinite(point.value),
    ) ||
    value.stateReasonData.threshold !== descriptor.threshold ||
    value.namespace !== descriptor.metricNamespace ||
    value.metricName !== descriptor.metricName ||
    canonicalJson(value.dimensions) !== canonicalJson(descriptor.dimensions) ||
    value.statistic !== descriptor.statistic ||
    value.unit !== descriptor.unit ||
    value.periodSeconds !== descriptor.periodSeconds ||
    value.evaluationPeriods !== descriptor.evaluationPeriods ||
    value.threshold !== descriptor.threshold ||
    value.comparisonOperator !== descriptor.comparisonOperator ||
    value.treatMissingData !== descriptor.treatMissingData ||
    value.actionsEnabled !== descriptor.actionsEnabled ||
    canonicalJson(value.alarmActions) !== canonicalJson(descriptor.alarmActions) ||
    canonicalJson(value.okActions) !== canonicalJson(descriptor.okActions) ||
    canonicalJson(value.insufficientDataActions) !==
      canonicalJson(descriptor.insufficientDataActions) ||
    (expectedState === 'ALARM' &&
      (!/threshold crossed/iu.test(value.stateReason) ||
        !value.stateReasonData.recentDatapoints.some(
          (point) =>
            Date.parse(point.timestamp) >= Date.parse(descriptor.activationAtUtc) &&
            point.value >= descriptor.threshold,
        )))
  ) {
    fail('E7_RB08_ALARM_OBSERVATION_INVALID');
  }
  return {
    state: value.stateValue,
    stateUpdatedAtUtc: value.stateUpdatedAtUtc,
    stateReasonSha256: sha256(value.stateReason),
    stateReasonDataSha256: objectSha256(value.stateReasonData),
    responseSha256: objectSha256(value),
  };
};

const validateSanitizedAlarmObservation = (value, expectedState) => {
  if (
    !exactKeys(value, [
      'state',
      'stateUpdatedAtUtc',
      'stateReasonSha256',
      'stateReasonDataSha256',
      'responseSha256',
    ]) ||
    value.state !== expectedState ||
    !utc(value.stateUpdatedAtUtc) ||
    !SHA256.test(value.stateReasonSha256 ?? '') ||
    !SHA256.test(value.stateReasonDataSha256 ?? '') ||
    !SHA256.test(value.responseSha256 ?? '')
  ) {
    fail('E7_RB08_SANITIZED_ALARM_OBSERVATION_INVALID');
  }
  return value;
};

const aliasObservation = (value, expected) => {
  if (
    !exactKeys(value, ['functionName', 'aliasName', 'functionVersion', 'revisionId']) ||
    value.functionName !== expected.functionName ||
    value.aliasName !== expected.aliasName ||
    !/^[1-9][0-9]*$/u.test(value.functionVersion ?? '') ||
    typeof value.revisionId !== 'string' ||
    !/^[A-Za-z0-9+/=_-]{8,256}$/u.test(value.revisionId)
  ) {
    fail('E7_RB08_ALIAS_OBSERVATION_INVALID');
  }
  return value;
};

const objectObservation = (value, { bucketName, key, expected }) => {
  if (
    !exactKeys(value, [
      'bucketName',
      'key',
      'activeVersionId',
      'sourceVersionId',
      'contentSha256',
      'bytes',
    ]) ||
    value.bucketName !== bucketName ||
    value.key !== key ||
    typeof value.activeVersionId !== 'string' ||
    value.activeVersionId.length < 3 ||
    typeof value.sourceVersionId !== 'string' ||
    value.sourceVersionId.length < 3 ||
    !SHA256.test(value.contentSha256 ?? '') ||
    !positiveInteger(value.bytes) ||
    (expected !== undefined &&
      (value.sourceVersionId !== expected.versionId ||
        value.contentSha256 !== expected.contentSha256 ||
        value.bytes !== expected.bytes))
  ) {
    fail('E7_RB08_WEB_OBJECT_OBSERVATION_INVALID');
  }
  return value;
};

const withoutIntent = (value) => {
  const output = { ...value };
  delete output.intentRecorded;
  return output;
};

const rb08CheckpointBody = ({ inputs, binding, descriptor, state, completedAtUtc }) => {
  const progress = state.progress;
  const real = inputs.execution.mode === 'AWS_REAL';
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'RB_E7_08_ALARM_NO_GO_RECOVERY',
    status: real ? 'AWS_VERIFIED' : 'BLOCKED_REAL_AWS_REQUIRED',
    scenarioId: 'RB-E7-08',
    gateEffect: real ? 'ELIGIBLE_FOR_REHEARSAL_ADAPTER' : 'KEEP_GATE_BLOCKED',
    executionMode: inputs.execution.mode,
    binding,
    scenarioInputSha256: objectSha256(descriptor),
    startedAtUtc: inputs.execution.startedAtUtc,
    activatedAtUtc: descriptor.activationAtUtc,
    completedAtUtc,
    originProtection: { ...progress.originProtection },
    alarm: {
      observabilityStackName: descriptor.observabilityStackName,
      observabilityTemplateSha256: descriptor.observabilityTemplateSha256,
      alarmArnSha256: sha256(descriptor.alarmArn),
      alarmNameSha256: sha256(descriptor.alarmName),
      baseline: { ...progress.baselineAlarm },
      breached: { ...progress.breachedAlarm },
      recovered: { ...progress.recoveredAlarm },
      transition: 'OK_TO_ALARM_TO_OK',
      stimulus: { ...progress.stimulus },
      recoveryStimulus: { ...progress.recoveryStimulus },
      alarmPolls: progress.alarmPolls,
      recoveryPolls: progress.recoveryPolls,
    },
    decision: {
      value: 'NO_GO_ROLLBACK',
      derivedFrom: 'REAL_METRIC_ALARM_STATE',
      manualOverrideAccepted: false,
      decisionAtUtc: progress.breachedAlarm.stateUpdatedAtUtc,
    },
    rollback: {
      fromReleaseId: inputs.freezeManifest.releaseId,
      toReleaseId: inputs.previousReleaseManifest.previous.releaseId,
      api: withoutIntent(progress.api),
      worker: withoutIntent(progress.worker),
      web: progress.web.map(withoutIntent),
      invalidation: { ...progress.invalidation },
      versionedAssetsOnly: true,
      stacksDeleted: 0,
    },
    repromotion: {
      fromReleaseId: inputs.previousReleaseManifest.previous.releaseId,
      toReleaseId: inputs.freezeManifest.releaseId,
      api: withoutIntent(progress.repromotion.api),
      worker: withoutIntent(progress.repromotion.worker),
      web: progress.repromotion.web.map(withoutIntent),
      invalidation: { ...progress.repromotion.invalidation },
      smoke: { ...progress.repromotion.smoke },
      pendingIntegrity: { ...progress.repromotion.pendingIntegrity },
      finalReleaseId: inputs.freezeManifest.releaseId,
      versionedAssetsOnly: true,
    },
    pendingIntegrity: { ...progress.pendingAfter },
    smoke: { ...progress.smoke },
    dataPolicy: 'NO_ROLLBACK_FORWARD_ONLY',
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    mutationCount: progress.mutationCount,
    resumptions: state.resumptions,
    transcript: [...state.transcript],
    containsSensitiveData: false,
  };
};

export const validateRbE708Checkpoint = (checkpoint, { inputs, descriptor, authority }) => {
  const real = inputs?.execution?.mode === 'AWS_REAL';
  if (real && authority !== PROTECTED_AWS_EVIDENCE_AUTHORITY) {
    fail('E7_RESILIENCE_AWS_EVIDENCE_AUTHORITY_REQUIRED');
  }
  const { binding, parsedDocuments } = validateBoundInputs(inputs);
  const checkedDescriptor = validateRb08Descriptor(descriptor, { inputs, parsedDocuments });
  if (
    !exactKeys(checkpoint, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scenarioId',
      'gateEffect',
      'executionMode',
      'binding',
      'scenarioInputSha256',
      'startedAtUtc',
      'activatedAtUtc',
      'completedAtUtc',
      'originProtection',
      'alarm',
      'decision',
      'rollback',
      'repromotion',
      'pendingIntegrity',
      'smoke',
      'dataPolicy',
      'dataRollbackPerformed',
      'stacksDeleted',
      'mutationCount',
      'resumptions',
      'transcript',
      'containsSensitiveData',
      'checkpointSha256',
    ]) ||
    checkpoint.schemaVersion !== 1 ||
    checkpoint.stage !== 7 ||
    checkpoint.kind !== 'RB_E7_08_ALARM_NO_GO_RECOVERY' ||
    checkpoint.status !== (real ? 'AWS_VERIFIED' : 'BLOCKED_REAL_AWS_REQUIRED') ||
    checkpoint.scenarioId !== 'RB-E7-08' ||
    checkpoint.gateEffect !== (real ? 'ELIGIBLE_FOR_REHEARSAL_ADAPTER' : 'KEEP_GATE_BLOCKED') ||
    checkpoint.executionMode !== inputs.execution.mode ||
    canonicalJson(checkpoint.binding) !== canonicalJson(binding) ||
    checkpoint.scenarioInputSha256 !== objectSha256(checkedDescriptor) ||
    checkpoint.startedAtUtc !== inputs.execution.startedAtUtc ||
    checkpoint.activatedAtUtc !== descriptor.activationAtUtc ||
    !utc(checkpoint.completedAtUtc) ||
    Date.parse(checkpoint.completedAtUtc) < Date.parse(checkpoint.activatedAtUtc) ||
    !exactKeys(checkpoint.alarm, [
      'alarmArnSha256',
      'observabilityStackName',
      'observabilityTemplateSha256',
      'alarmNameSha256',
      'baseline',
      'breached',
      'recovered',
      'transition',
      'stimulus',
      'recoveryStimulus',
      'alarmPolls',
      'recoveryPolls',
    ]) ||
    checkpoint.alarm.observabilityStackName !== descriptor.observabilityStackName ||
    checkpoint.alarm.observabilityTemplateSha256 !== descriptor.observabilityTemplateSha256 ||
    checkpoint.alarm.alarmArnSha256 !== sha256(descriptor.alarmArn) ||
    checkpoint.alarm.alarmNameSha256 !== sha256(descriptor.alarmName) ||
    checkpoint.alarm.baseline?.state !== 'OK' ||
    checkpoint.alarm.breached?.state !== 'ALARM' ||
    checkpoint.alarm.recovered?.state !== 'OK' ||
    checkpoint.alarm.transition !== 'OK_TO_ALARM_TO_OK' ||
    !exactKeys(checkpoint.alarm.stimulus, [
      'namespace',
      'metricName',
      'dimensionsSha256',
      'timestampUtc',
      'value',
      'unit',
      'emitted',
    ]) ||
    checkpoint.alarm.stimulus.namespace !== descriptor.metricNamespace ||
    checkpoint.alarm.stimulus.metricName !== descriptor.metricName ||
    checkpoint.alarm.stimulus.dimensionsSha256 !== objectSha256(descriptor.dimensions) ||
    !utc(checkpoint.alarm.stimulus.timestampUtc) ||
    Date.parse(checkpoint.alarm.stimulus.timestampUtc) < Date.parse(checkpoint.activatedAtUtc) ||
    checkpoint.alarm.stimulus.value !== descriptor.threshold ||
    checkpoint.alarm.stimulus.unit !== descriptor.unit ||
    checkpoint.alarm.stimulus.emitted !== true ||
    !exactKeys(checkpoint.alarm.recoveryStimulus, [
      'namespace',
      'metricName',
      'dimensionsSha256',
      'timestampUtc',
      'value',
      'unit',
      'emitted',
    ]) ||
    checkpoint.alarm.recoveryStimulus.namespace !== descriptor.metricNamespace ||
    checkpoint.alarm.recoveryStimulus.metricName !== descriptor.metricName ||
    checkpoint.alarm.recoveryStimulus.dimensionsSha256 !== objectSha256(descriptor.dimensions) ||
    !utc(checkpoint.alarm.recoveryStimulus.timestampUtc) ||
    Date.parse(checkpoint.alarm.recoveryStimulus.timestampUtc) <
      Date.parse(checkpoint.alarm.breached.stateUpdatedAtUtc) ||
    checkpoint.alarm.recoveryStimulus.value !== 0 ||
    checkpoint.alarm.recoveryStimulus.unit !== descriptor.unit ||
    checkpoint.alarm.recoveryStimulus.emitted !== true ||
    !positiveInteger(checkpoint.alarm.alarmPolls) ||
    !positiveInteger(checkpoint.alarm.recoveryPolls) ||
    Date.parse(checkpoint.alarm.baseline.stateUpdatedAtUtc) >
      Date.parse(checkpoint.activatedAtUtc) ||
    Date.parse(checkpoint.alarm.breached.stateUpdatedAtUtc) <
      Date.parse(checkpoint.activatedAtUtc) ||
    Date.parse(checkpoint.alarm.recovered.stateUpdatedAtUtc) <
      Date.parse(checkpoint.alarm.breached.stateUpdatedAtUtc) ||
    !exactKeys(checkpoint.decision, [
      'value',
      'derivedFrom',
      'manualOverrideAccepted',
      'decisionAtUtc',
    ]) ||
    checkpoint.decision.value !== 'NO_GO_ROLLBACK' ||
    checkpoint.decision.derivedFrom !== 'REAL_METRIC_ALARM_STATE' ||
    checkpoint.decision.manualOverrideAccepted !== false ||
    checkpoint.decision.decisionAtUtc !== checkpoint.alarm.breached.stateUpdatedAtUtc ||
    !exactKeys(checkpoint.rollback, [
      'fromReleaseId',
      'toReleaseId',
      'api',
      'worker',
      'web',
      'invalidation',
      'versionedAssetsOnly',
      'stacksDeleted',
    ]) ||
    checkpoint.rollback.fromReleaseId !== inputs.freezeManifest.releaseId ||
    checkpoint.rollback.toReleaseId !== inputs.previousReleaseManifest.previous.releaseId ||
    checkpoint.rollback.api?.toVersion !== inputs.previousReleaseManifest.resources.api.version ||
    checkpoint.rollback.worker?.toVersion !==
      inputs.previousReleaseManifest.resources.worker.version ||
    !Array.isArray(checkpoint.rollback.web) ||
    checkpoint.rollback.web.length !==
      inputs.previousReleaseManifest.resources.web.objects.length ||
    checkpoint.rollback.versionedAssetsOnly !== true ||
    checkpoint.rollback.stacksDeleted !== 0 ||
    !exactKeys(checkpoint.repromotion, [
      'fromReleaseId',
      'toReleaseId',
      'api',
      'worker',
      'web',
      'invalidation',
      'smoke',
      'pendingIntegrity',
      'finalReleaseId',
      'versionedAssetsOnly',
    ]) ||
    checkpoint.repromotion.fromReleaseId !== inputs.previousReleaseManifest.previous.releaseId ||
    checkpoint.repromotion.toReleaseId !== inputs.freezeManifest.releaseId ||
    checkpoint.repromotion.finalReleaseId !== inputs.freezeManifest.releaseId ||
    checkpoint.repromotion.versionedAssetsOnly !== true ||
    !Array.isArray(checkpoint.repromotion.web) ||
    checkpoint.repromotion.web.length !== inputs.candidateRecord.resources.web.objects.length ||
    checkpoint.pendingIntegrity?.orphaned !== 0 ||
    checkpoint.pendingIntegrity?.duplicateEffects !== 0 ||
    checkpoint.pendingIntegrity?.lostFacts !== 0 ||
    checkpoint.dataPolicy !== 'NO_ROLLBACK_FORWARD_ONLY' ||
    checkpoint.dataRollbackPerformed !== false ||
    checkpoint.stacksDeleted !== 0 ||
    checkpoint.mutationCount !== 12 ||
    !nonNegativeInteger(checkpoint.resumptions) ||
    checkpoint.containsSensitiveData !== false
  ) {
    fail('E7_RB08_CHECKPOINT_INVALID');
  }
  validateOriginProtection(checkpoint.originProtection, {
    inputs,
    runtimeSecretReferenceSha256: descriptor.runtimeSecretReferenceSha256,
  });
  validateSanitizedAlarmObservation(checkpoint.alarm.baseline, 'OK');
  validateSanitizedAlarmObservation(checkpoint.alarm.breached, 'ALARM');
  validateSanitizedAlarmObservation(checkpoint.alarm.recovered, 'OK');
  for (const [name, expected] of [
    ['api', inputs.previousReleaseManifest.resources.api],
    ['worker', inputs.previousReleaseManifest.resources.worker],
  ]) {
    const value = checkpoint.rollback[name];
    if (
      !exactKeys(value, [
        'functionName',
        'aliasName',
        'fromVersion',
        'toVersion',
        'finalRevisionIdSha256',
        'changed',
      ]) ||
      value.functionName !== expected.functionName ||
      value.aliasName !== expected.aliasName ||
      value.fromVersion !== inputs.candidateRecord.resources[name].version ||
      value.toVersion !== expected.version ||
      !SHA256.test(value.finalRevisionIdSha256 ?? '') ||
      value.changed !== true
    ) {
      fail('E7_RB08_CHECKPOINT_ALIAS_INVALID');
    }
  }
  for (const [name, expected] of [
    ['api', inputs.candidateRecord.resources.api],
    ['worker', inputs.candidateRecord.resources.worker],
  ]) {
    const value = checkpoint.repromotion[name];
    if (
      !exactKeys(value, [
        'functionName',
        'aliasName',
        'fromVersion',
        'toVersion',
        'finalRevisionIdSha256',
        'changed',
      ]) ||
      value.functionName !== expected.functionName ||
      value.aliasName !== expected.aliasName ||
      value.fromVersion !== inputs.previousReleaseManifest.resources[name].version ||
      value.toVersion !== expected.version ||
      !SHA256.test(value.finalRevisionIdSha256 ?? '') ||
      value.changed !== true
    ) {
      fail('E7_RB08_CHECKPOINT_REPROMOTION_ALIAS_INVALID');
    }
  }
  for (const [index, value] of checkpoint.rollback.web.entries()) {
    const expected = inputs.previousReleaseManifest.resources.web.objects[index];
    if (
      !exactKeys(value, [
        'key',
        'sourceVersionId',
        'activeVersionId',
        'contentSha256',
        'bytes',
        'changed',
      ]) ||
      value.key !== expected.key ||
      value.sourceVersionId !== expected.versionId ||
      typeof value.activeVersionId !== 'string' ||
      value.activeVersionId.length < 3 ||
      value.contentSha256 !== expected.contentSha256 ||
      value.bytes !== expected.bytes ||
      value.changed !== true
    ) {
      fail('E7_RB08_CHECKPOINT_WEB_INVALID');
    }
  }
  for (const [index, value] of checkpoint.repromotion.web.entries()) {
    const expected = inputs.candidateRecord.resources.web.objects[index];
    if (
      !exactKeys(value, [
        'key',
        'sourceVersionId',
        'activeVersionId',
        'contentSha256',
        'bytes',
        'changed',
      ]) ||
      value.key !== expected.key ||
      value.sourceVersionId !== expected.versionId ||
      typeof value.activeVersionId !== 'string' ||
      value.activeVersionId.length < 3 ||
      value.contentSha256 !== expected.contentSha256 ||
      value.bytes !== expected.bytes ||
      value.changed !== true
    ) {
      fail('E7_RB08_CHECKPOINT_REPROMOTION_WEB_INVALID');
    }
  }
  if (
    !exactKeys(checkpoint.rollback.invalidation, [
      'distributionId',
      'idSha256',
      'callerReferenceSha256',
      'paths',
      'status',
    ]) ||
    checkpoint.rollback.invalidation.distributionId !==
      inputs.previousReleaseManifest.resources.web.distributionId ||
    !SHA256.test(checkpoint.rollback.invalidation.idSha256 ?? '') ||
    !SHA256.test(checkpoint.rollback.invalidation.callerReferenceSha256 ?? '') ||
    checkpoint.rollback.invalidation.paths?.join('\0') !==
      inputs.previousReleaseManifest.resources.web.mutableInvalidationPaths.join('\0') ||
    checkpoint.rollback.invalidation.status !== 'Completed'
  ) {
    fail('E7_RB08_CHECKPOINT_INVALIDATION_INVALID');
  }
  if (
    !exactKeys(checkpoint.repromotion.invalidation, [
      'distributionId',
      'idSha256',
      'callerReferenceSha256',
      'paths',
      'status',
    ]) ||
    checkpoint.repromotion.invalidation.distributionId !==
      inputs.candidateRecord.resources.web.distributionId ||
    !SHA256.test(checkpoint.repromotion.invalidation.idSha256 ?? '') ||
    !SHA256.test(checkpoint.repromotion.invalidation.callerReferenceSha256 ?? '') ||
    checkpoint.repromotion.invalidation.paths?.join('\0') !==
      inputs.candidateRecord.resources.web.mutableInvalidationPaths.join('\0') ||
    checkpoint.repromotion.invalidation.status !== 'Completed'
  ) {
    fail('E7_RB08_CHECKPOINT_REPROMOTION_INVALIDATION_INVALID');
  }
  pendingObservation(checkpoint.pendingIntegrity, {
    before: false,
    rehearsal: inputs.baseRehearsal,
  });
  pendingObservation(checkpoint.repromotion.pendingIntegrity, {
    before: false,
    rehearsal: inputs.baseRehearsal,
  });
  if (
    checkpoint.repromotion.pendingIntegrity.snapshotSha256 !==
      checkpoint.pendingIntegrity.snapshotSha256 ||
    checkpoint.repromotion.pendingIntegrity.stillPending !==
      checkpoint.repromotion.pendingIntegrity.trackedBefore ||
    checkpoint.repromotion.pendingIntegrity.reconciled !== 0
  ) {
    fail('E7_RB08_REPROMOTION_PENDING_NOT_PRESERVED');
  }
  readSmoke(checkpoint.smoke, inputs.previousReleaseManifest.previous.releaseId);
  readSmoke(checkpoint.repromotion.smoke, inputs.freezeManifest.releaseId);
  validateTranscript(checkpoint.transcript, {
    scenarioId: 'RB-E7-08',
    execution: inputs.execution,
  });
  if (checkpoint.checkpointSha256 !== objectSha256(withoutDigest(checkpoint, 'checkpointSha256'))) {
    fail('E7_RB08_CHECKPOINT_DIGEST_INVALID');
  }
  return checkpoint;
};

const describeAlarm = async ({ executor, state, inputs, binding, descriptor, operation }) => {
  const payload = await invoke({
    executor,
    state,
    inputs,
    binding,
    scenarioId: 'RB-E7-08',
    service: 'cloudwatch',
    operation,
    input: { alarmNames: [descriptor.alarmName] },
  });
  if (!exactKeys(payload, ['metricAlarms']) || payload.metricAlarms?.length !== 1) {
    fail('E7_RB08_ALARM_RESPONSE_INVALID');
  }
  return payload.metricAlarms[0];
};

const rollbackAlias = async ({ name, executor, stateStore, state, inputs, binding }) => {
  const source = inputs.candidateRecord.resources[name];
  const target = inputs.previousReleaseManifest.resources[name];
  let current = aliasObservation(
    await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-08',
      service: 'lambda',
      operation: 'GetAlias',
      input: { functionName: target.functionName, aliasName: target.aliasName },
    }),
    target,
  );
  if (state.progress[name] === null) {
    if (current.functionVersion !== source.version) fail('E7_RB08_ALIAS_NOT_AT_CANDIDATE');
    state.progress[name] = {
      functionName: target.functionName,
      aliasName: target.aliasName,
      fromVersion: source.version,
      toVersion: target.version,
      finalRevisionIdSha256: null,
      changed: false,
      intentRecorded: true,
    };
    state.progress.mutationCount += 1;
    state = await persist({ stateStore, state, phase: `${name.toUpperCase()}_INTENT_RECORDED` });
  }
  if (current.functionVersion === source.version) {
    current = aliasObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'lambda',
        operation: 'UpdateAlias',
        input: {
          functionName: target.functionName,
          aliasName: target.aliasName,
          functionVersion: target.version,
          revisionId: current.revisionId,
        },
      }),
      target,
    );
  }
  if (current.functionVersion !== target.version) fail('E7_RB08_ALIAS_ROLLBACK_FAILED');
  state.progress[name] = {
    functionName: target.functionName,
    aliasName: target.aliasName,
    fromVersion: source.version,
    toVersion: target.version,
    finalRevisionIdSha256: sha256(current.revisionId),
    changed: true,
    intentRecorded: true,
  };
  state = await persist({ stateStore, state, phase: `${name.toUpperCase()}_ROLLED_BACK` });
  return state;
};

const repromoteAlias = async ({ name, executor, stateStore, state, inputs, binding }) => {
  const source = inputs.previousReleaseManifest.resources[name];
  const target = inputs.candidateRecord.resources[name];
  let current = aliasObservation(
    await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-08',
      service: 'lambda',
      operation: 'GetAliasForRepromotion',
      input: { functionName: target.functionName, aliasName: target.aliasName },
    }),
    target,
  );
  if (state.progress.repromotion[name] === null) {
    if (current.functionVersion !== source.version) fail('E7_RB08_ALIAS_NOT_AT_PREVIOUS');
    state.progress.repromotion[name] = {
      functionName: target.functionName,
      aliasName: target.aliasName,
      fromVersion: source.version,
      toVersion: target.version,
      finalRevisionIdSha256: null,
      changed: false,
      intentRecorded: true,
    };
    state.progress.mutationCount += 1;
    state = await persist({
      stateStore,
      state,
      phase: `REPROMOTE_${name.toUpperCase()}_INTENT_RECORDED`,
    });
  }
  if (current.functionVersion === source.version) {
    current = aliasObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'lambda',
        operation: 'UpdateAliasForRepromotion',
        input: {
          functionName: target.functionName,
          aliasName: target.aliasName,
          functionVersion: target.version,
          revisionId: current.revisionId,
        },
      }),
      target,
    );
  }
  if (current.functionVersion !== target.version) fail('E7_RB08_ALIAS_REPROMOTION_FAILED');
  state.progress.repromotion[name] = {
    functionName: target.functionName,
    aliasName: target.aliasName,
    fromVersion: source.version,
    toVersion: target.version,
    finalRevisionIdSha256: sha256(current.revisionId),
    changed: true,
    intentRecorded: true,
  };
  return persist({
    stateStore,
    state,
    phase: `REPROMOTE_${name.toUpperCase()}_COMPLETE`,
  });
};

const produceRbE708 = async ({ inputs, descriptor, executor, stateStore, capability }) => {
  if (
    (inputs.execution.mode === 'LOCAL_SIMULATION' &&
      capability !== SELF_TEST_EXECUTOR_CAPABILITY) ||
    (inputs.execution.mode === 'AWS_REAL' && capability !== PROTECTED_AWS_EXECUTOR_CAPABILITY)
  ) {
    fail('E7_RESILIENCE_EXECUTOR_CAPABILITY_INVALID');
  }
  const { binding, parsedDocuments } = validateBoundInputs(inputs);
  const checkedDescriptor = validateRb08Descriptor(descriptor, { inputs, parsedDocuments });
  let state = await loadState({
    stateStore,
    scenarioId: 'RB-E7-08',
    binding,
    execution: inputs.execution,
    progress: rb08Progress(),
  });
  if (state.phase === 'COMPLETE') {
    return validateRbE708Checkpoint(state.checkpoint, {
      inputs,
      descriptor,
      authority:
        inputs.execution.mode === 'AWS_REAL' ? PROTECTED_AWS_EVIDENCE_AUTHORITY : undefined,
    });
  }
  const progress = state.progress;
  if (progress.pendingBefore === null) {
    progress.pendingBefore = pendingObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'stage7-pending-integrity',
        operation: 'ReadBeforeAlarmDecision',
        input: {
          releaseId: inputs.freezeManifest.releaseId,
          pendingBaselineSha256: inputs.baseRehearsal.rollback.plan.pendingBaseline.snapshotSha256,
        },
      }),
      { before: true, rehearsal: inputs.baseRehearsal },
    );
    if (
      progress.pendingBefore.snapshotSha256 !==
      inputs.baseRehearsal.rollback.plan.pendingBaseline.snapshotSha256
    ) {
      fail('E7_RB08_PENDING_BASELINE_DRIFT');
    }
    progress.originProtection = validateOriginProtection(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'stage7-origin-protection',
        operation: 'VerifyNAndNMinus1Compatibility',
        input: {
          candidateReleaseId: inputs.freezeManifest.releaseId,
          previousReleaseId: inputs.previousReleaseManifest.previous.releaseId,
          runtimeSecretReferenceSha256: descriptor.runtimeSecretReferenceSha256,
        },
      }),
      { inputs, runtimeSecretReferenceSha256: descriptor.runtimeSecretReferenceSha256 },
    );
    const baselineAlarm = await describeAlarm({
      executor,
      state,
      inputs,
      binding,
      descriptor: checkedDescriptor,
      operation: 'DescribeAlarmsBeforeActivation',
    });
    progress.baselineAlarm = alarmObservation(baselineAlarm, {
      descriptor: checkedDescriptor,
      expectedState: 'OK',
      beforeOrAtUtc: descriptor.activationAtUtc,
    });
    state = await persist({ stateStore, state, phase: 'ALARM_BASELINE_VERIFIED' });
  }

  if (progress.stimulus?.emitted !== true) {
    if (progress.stimulus === null) {
      const observedAtUtc = state.transcript.at(-1).observedAtUtc;
      const timestampUtc = new Date(
        Math.max(Date.parse(descriptor.activationAtUtc), Date.parse(observedAtUtc)),
      ).toISOString();
      progress.stimulus = {
        namespace: descriptor.metricNamespace,
        metricName: descriptor.metricName,
        dimensionsSha256: objectSha256(descriptor.dimensions),
        timestampUtc,
        value: descriptor.threshold,
        unit: descriptor.unit,
        emitted: false,
      };
      progress.mutationCount += 1;
      state = await persist({ stateStore, state, phase: 'ALARM_STIMULUS_INTENT_RECORDED' });
    }
    const putMetric = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-08',
      service: 'cloudwatch',
      operation: 'PutMetricData',
      input: {
        namespace: descriptor.metricNamespace,
        metricData: [
          {
            metricName: descriptor.metricName,
            dimensions: descriptor.dimensions,
            timestampUtc: progress.stimulus.timestampUtc,
            value: descriptor.threshold,
            unit: descriptor.unit,
          },
        ],
      },
    });
    if (Object.keys(putMetric).length !== 0) fail('E7_RB08_PUT_METRIC_RESPONSE_INVALID');
    progress.stimulus.emitted = true;
    state = await persist({ stateStore, state, phase: 'ALARM_STIMULUS_EMITTED' });
  }

  for (; progress.alarmPolls < checkedDescriptor.maxPolls && progress.breachedAlarm === null;) {
    const observed = await describeAlarm({
      executor,
      state,
      inputs,
      binding,
      descriptor: checkedDescriptor,
      operation: 'DescribeAlarmsAfterActivation',
    });
    progress.alarmPolls += 1;
    if (observed.stateValue === 'ALARM') {
      progress.breachedAlarm = alarmObservation(observed, {
        descriptor: checkedDescriptor,
        expectedState: 'ALARM',
        afterUtc: descriptor.activationAtUtc,
      });
      break;
    }
    alarmObservation(observed, {
      descriptor: checkedDescriptor,
      expectedState: 'OK',
      afterUtc: descriptor.activationAtUtc,
    });
    state = await persist({ stateStore, state, phase: 'WAITING_FOR_REAL_ALARM' });
  }
  if (progress.breachedAlarm === null) fail('E7_RB08_ALARM_NOT_OBSERVED');
  if (!progress.decisionRecorded) {
    progress.decisionRecorded = true;
    state = await persist({ stateStore, state, phase: 'NO_GO_DECISION_RECORDED' });
  }

  if (progress.api?.changed !== true) {
    state = await rollbackAlias({
      name: 'api',
      executor,
      stateStore,
      state,
      inputs,
      binding,
    });
  }
  if (state.progress.worker?.changed !== true) {
    state = await rollbackAlias({
      name: 'worker',
      executor,
      stateStore,
      state,
      inputs,
      binding,
    });
  }

  const bucketName = inputs.previousReleaseManifest.resources.web.bucketName;
  for (const [index, target] of inputs.previousReleaseManifest.resources.web.objects.entries()) {
    if (state.progress.web[index]?.changed === true) continue;
    const source = inputs.candidateRecord.resources.web.objects[index];
    let active = objectObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'stage7-s3-integrity',
        operation: 'InspectActiveObject',
        input: { bucketName, key: target.key },
      }),
      { bucketName, key: target.key },
    );
    const prior = state.progress.web[index];
    if (
      active.contentSha256 === target.contentSha256 &&
      active.sourceVersionId === target.versionId &&
      prior?.intentRecorded === true
    ) {
      state.progress.web[index] = {
        key: target.key,
        sourceVersionId: target.versionId,
        activeVersionId: active.activeVersionId,
        contentSha256: active.contentSha256,
        bytes: active.bytes,
        changed: true,
        intentRecorded: true,
      };
      state = await persist({ stateStore, state, phase: `WEB_${index + 1}_ROLLED_BACK` });
      continue;
    }
    if (active.contentSha256 !== source.contentSha256 || prior !== undefined) {
      fail('E7_RB08_WEB_OBJECT_NOT_AT_CANDIDATE');
    }
    state.progress.web[index] = {
      key: target.key,
      sourceVersionId: target.versionId,
      activeVersionId: null,
      contentSha256: target.contentSha256,
      bytes: target.bytes,
      changed: false,
      intentRecorded: true,
    };
    state.progress.mutationCount += 1;
    state = await persist({ stateStore, state, phase: `WEB_${index + 1}_INTENT_RECORDED` });
    active = objectObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 's3',
        operation: 'RestoreVersionedObject',
        input: {
          bucketName,
          key: target.key,
          sourceVersionId: target.versionId,
          expectedContentSha256: target.contentSha256,
        },
      }),
      { bucketName, key: target.key, expected: target },
    );
    state.progress.web[index] = {
      key: target.key,
      sourceVersionId: target.versionId,
      activeVersionId: active.activeVersionId,
      contentSha256: active.contentSha256,
      bytes: active.bytes,
      changed: true,
      intentRecorded: true,
    };
    state = await persist({ stateStore, state, phase: `WEB_${index + 1}_ROLLED_BACK` });
  }

  const distributionId = inputs.previousReleaseManifest.resources.web.distributionId;
  const paths = inputs.previousReleaseManifest.resources.web.mutableInvalidationPaths;
  const callerReference = `e7rb08-${binding.bindingSha256.slice(0, 24)}-${inputs.execution.runId}`;
  if (state.progress.invalidation === null) {
    state.progress.invalidation = {
      distributionId,
      idSha256: null,
      callerReferenceSha256: sha256(callerReference),
      paths,
      status: 'INTENT_RECORDED',
      rawId: null,
    };
    state.progress.mutationCount += 1;
    state = await persist({ stateStore, state, phase: 'INVALIDATION_INTENT_RECORDED' });
  }
  if (state.progress.invalidation.status === 'INTENT_RECORDED') {
    const created = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-08',
      service: 'cloudfront',
      operation: 'CreateInvalidation',
      input: { distributionId, paths, callerReference },
    });
    if (
      !exactKeys(created, [
        'distributionId',
        'invalidationId',
        'callerReference',
        'paths',
        'status',
      ]) ||
      created.distributionId !== distributionId ||
      typeof created.invalidationId !== 'string' ||
      !SAFE_NAME.test(created.invalidationId) ||
      created.callerReference !== callerReference ||
      created.paths?.join('\0') !== paths.join('\0') ||
      !['InProgress', 'Completed'].includes(created.status)
    ) {
      fail('E7_RB08_INVALIDATION_CREATE_INVALID');
    }
    state.progress.invalidation = {
      ...state.progress.invalidation,
      idSha256: sha256(created.invalidationId),
      rawId: created.invalidationId,
      status: created.status,
    };
    state = await persist({ stateStore, state, phase: 'INVALIDATION_CREATED' });
  }
  while (state.progress.invalidation.status !== 'Completed') {
    const invalidation = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-08',
      service: 'cloudfront',
      operation: 'GetInvalidation',
      input: { distributionId, invalidationId: state.progress.invalidation.rawId },
    });
    if (
      !exactKeys(invalidation, [
        'distributionId',
        'invalidationId',
        'callerReference',
        'paths',
        'status',
      ]) ||
      invalidation.distributionId !== distributionId ||
      sha256(invalidation.invalidationId ?? '') !== state.progress.invalidation.idSha256 ||
      invalidation.callerReference !== callerReference ||
      invalidation.paths?.join('\0') !== paths.join('\0') ||
      !['InProgress', 'Completed'].includes(invalidation.status)
    ) {
      fail('E7_RB08_INVALIDATION_OBSERVATION_INVALID');
    }
    state.progress.invalidation.status = invalidation.status;
    state = await persist({ stateStore, state, phase: 'INVALIDATION_MONITORING' });
  }

  if (state.progress.pendingAfter === null) {
    state.progress.pendingAfter = pendingObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'stage7-pending-integrity',
        operation: 'ReadAfterAlarmRollback',
        input: {
          previousReleaseId: inputs.previousReleaseManifest.previous.releaseId,
          beforeSnapshotSha256: state.progress.pendingBefore.snapshotSha256,
        },
      }),
      { before: false, rehearsal: inputs.baseRehearsal },
    );
    if (
      state.progress.pendingAfter.snapshotSha256 !== state.progress.pendingBefore.snapshotSha256 ||
      state.progress.pendingAfter.stillPending !== state.progress.pendingAfter.trackedBefore ||
      state.progress.pendingAfter.reconciled !== 0
    ) {
      fail('E7_RB08_PENDING_NOT_PRESERVED');
    }
    state.progress.smoke = readSmoke(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'stage7-read-smoke',
        operation: 'RunAfterAlarmRollback',
        input: {
          releaseId: inputs.previousReleaseManifest.previous.releaseId,
          expectedRequests: 3,
        },
      }),
      inputs.previousReleaseManifest.previous.releaseId,
    );
    state = await persist({ stateStore, state, phase: 'RECOVERY_READS_VERIFIED' });
  }

  if (state.progress.recoveryStimulus?.emitted !== true) {
    if (state.progress.recoveryStimulus === null) {
      const observedAtUtc = state.transcript.at(-1).observedAtUtc;
      const timestampUtc = new Date(
        Math.max(
          Date.parse(observedAtUtc),
          Date.parse(state.progress.breachedAlarm.stateUpdatedAtUtc) +
            checkedDescriptor.periodSeconds * 1000,
        ),
      ).toISOString();
      state.progress.recoveryStimulus = {
        namespace: checkedDescriptor.metricNamespace,
        metricName: checkedDescriptor.metricName,
        dimensionsSha256: objectSha256(checkedDescriptor.dimensions),
        timestampUtc,
        value: 0,
        unit: checkedDescriptor.unit,
        emitted: false,
      };
      state.progress.mutationCount += 1;
      state = await persist({
        stateStore,
        state,
        phase: 'ALARM_RECOVERY_STIMULUS_INTENT_RECORDED',
      });
    }
    const putMetric = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-08',
      service: 'cloudwatch',
      operation: 'PutRecoveryMetricData',
      input: {
        namespace: checkedDescriptor.metricNamespace,
        metricData: [
          {
            metricName: checkedDescriptor.metricName,
            dimensions: checkedDescriptor.dimensions,
            timestampUtc: state.progress.recoveryStimulus.timestampUtc,
            value: 0,
            unit: checkedDescriptor.unit,
          },
        ],
      },
    });
    if (Object.keys(putMetric).length !== 0) {
      fail('E7_RB08_PUT_RECOVERY_METRIC_RESPONSE_INVALID');
    }
    state.progress.recoveryStimulus.emitted = true;
    state = await persist({ stateStore, state, phase: 'ALARM_RECOVERY_STIMULUS_EMITTED' });
  }

  for (
    ;
    state.progress.recoveryPolls < checkedDescriptor.maxPolls &&
    state.progress.recoveredAlarm === null;
  ) {
    const observed = await describeAlarm({
      executor,
      state,
      inputs,
      binding,
      descriptor: checkedDescriptor,
      operation: 'DescribeAlarmsAfterRollback',
    });
    state.progress.recoveryPolls += 1;
    if (observed.stateValue === 'OK') {
      state.progress.recoveredAlarm = alarmObservation(observed, {
        descriptor: checkedDescriptor,
        expectedState: 'OK',
        afterUtc: state.progress.breachedAlarm.stateUpdatedAtUtc,
      });
      break;
    }
    alarmObservation(observed, {
      descriptor: checkedDescriptor,
      expectedState: 'ALARM',
      afterUtc: state.progress.breachedAlarm.stateUpdatedAtUtc,
    });
    state = await persist({ stateStore, state, phase: 'WAITING_FOR_ALARM_RECOVERY' });
  }
  if (state.progress.recoveredAlarm === null) fail('E7_RB08_ALARM_RECOVERY_TIMEOUT');

  if (state.progress.repromotion.api?.changed !== true) {
    state = await repromoteAlias({
      name: 'api',
      executor,
      stateStore,
      state,
      inputs,
      binding,
    });
  }
  if (state.progress.repromotion.worker?.changed !== true) {
    state = await repromoteAlias({
      name: 'worker',
      executor,
      stateStore,
      state,
      inputs,
      binding,
    });
  }
  for (const [index, target] of inputs.candidateRecord.resources.web.objects.entries()) {
    if (state.progress.repromotion.web[index]?.changed === true) continue;
    const source = inputs.previousReleaseManifest.resources.web.objects[index];
    let active = objectObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'stage7-s3-integrity',
        operation: 'InspectActiveObjectForRepromotion',
        input: { bucketName, key: target.key },
      }),
      { bucketName, key: target.key },
    );
    const prior = state.progress.repromotion.web[index];
    if (
      active.contentSha256 === target.contentSha256 &&
      active.sourceVersionId === target.versionId &&
      prior?.intentRecorded === true
    ) {
      state.progress.repromotion.web[index] = {
        key: target.key,
        sourceVersionId: target.versionId,
        activeVersionId: active.activeVersionId,
        contentSha256: active.contentSha256,
        bytes: active.bytes,
        changed: true,
        intentRecorded: true,
      };
      state = await persist({
        stateStore,
        state,
        phase: `REPROMOTE_WEB_${index + 1}_COMPLETE`,
      });
      continue;
    }
    if (active.contentSha256 !== source.contentSha256 || prior !== undefined) {
      fail('E7_RB08_WEB_OBJECT_NOT_AT_PREVIOUS');
    }
    state.progress.repromotion.web[index] = {
      key: target.key,
      sourceVersionId: target.versionId,
      activeVersionId: null,
      contentSha256: target.contentSha256,
      bytes: target.bytes,
      changed: false,
      intentRecorded: true,
    };
    state.progress.mutationCount += 1;
    state = await persist({
      stateStore,
      state,
      phase: `REPROMOTE_WEB_${index + 1}_INTENT_RECORDED`,
    });
    active = objectObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 's3',
        operation: 'RestoreVersionedObjectForRepromotion',
        input: {
          bucketName,
          key: target.key,
          sourceVersionId: target.versionId,
          expectedContentSha256: target.contentSha256,
        },
      }),
      { bucketName, key: target.key, expected: target },
    );
    state.progress.repromotion.web[index] = {
      key: target.key,
      sourceVersionId: target.versionId,
      activeVersionId: active.activeVersionId,
      contentSha256: active.contentSha256,
      bytes: active.bytes,
      changed: true,
      intentRecorded: true,
    };
    state = await persist({
      stateStore,
      state,
      phase: `REPROMOTE_WEB_${index + 1}_COMPLETE`,
    });
  }

  const repromotionCallerReference = `e7rb08-repromote-${binding.bindingSha256.slice(0, 20)}-${inputs.execution.runId}`;
  if (state.progress.repromotion.invalidation === null) {
    state.progress.repromotion.invalidation = {
      distributionId,
      idSha256: null,
      callerReferenceSha256: sha256(repromotionCallerReference),
      paths,
      status: 'INTENT_RECORDED',
      rawId: null,
    };
    state.progress.mutationCount += 1;
    state = await persist({
      stateStore,
      state,
      phase: 'REPROMOTE_INVALIDATION_INTENT_RECORDED',
    });
  }
  if (state.progress.repromotion.invalidation.status === 'INTENT_RECORDED') {
    const created = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-08',
      service: 'cloudfront',
      operation: 'CreateInvalidationForRepromotion',
      input: { distributionId, paths, callerReference: repromotionCallerReference },
    });
    if (
      !exactKeys(created, [
        'distributionId',
        'invalidationId',
        'callerReference',
        'paths',
        'status',
      ]) ||
      created.distributionId !== distributionId ||
      typeof created.invalidationId !== 'string' ||
      !SAFE_NAME.test(created.invalidationId) ||
      created.callerReference !== repromotionCallerReference ||
      created.paths?.join('\0') !== paths.join('\0') ||
      !['InProgress', 'Completed'].includes(created.status)
    ) {
      fail('E7_RB08_REPROMOTION_INVALIDATION_CREATE_INVALID');
    }
    state.progress.repromotion.invalidation = {
      ...state.progress.repromotion.invalidation,
      idSha256: sha256(created.invalidationId),
      rawId: created.invalidationId,
      status: created.status,
    };
    state = await persist({ stateStore, state, phase: 'REPROMOTE_INVALIDATION_CREATED' });
  }
  while (state.progress.repromotion.invalidation.status !== 'Completed') {
    const invalidation = await invoke({
      executor,
      state,
      inputs,
      binding,
      scenarioId: 'RB-E7-08',
      service: 'cloudfront',
      operation: 'GetInvalidationForRepromotion',
      input: {
        distributionId,
        invalidationId: state.progress.repromotion.invalidation.rawId,
      },
    });
    if (
      !exactKeys(invalidation, [
        'distributionId',
        'invalidationId',
        'callerReference',
        'paths',
        'status',
      ]) ||
      invalidation.distributionId !== distributionId ||
      sha256(invalidation.invalidationId ?? '') !==
        state.progress.repromotion.invalidation.idSha256 ||
      invalidation.callerReference !== repromotionCallerReference ||
      invalidation.paths?.join('\0') !== paths.join('\0') ||
      !['InProgress', 'Completed'].includes(invalidation.status)
    ) {
      fail('E7_RB08_REPROMOTION_INVALIDATION_OBSERVATION_INVALID');
    }
    state.progress.repromotion.invalidation.status = invalidation.status;
    state = await persist({
      stateStore,
      state,
      phase: 'REPROMOTE_INVALIDATION_MONITORING',
    });
  }
  if (state.progress.repromotion.smoke === null) {
    state.progress.repromotion.smoke = readSmoke(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'stage7-read-smoke',
        operation: 'RunAfterAlarmRepromotion',
        input: { releaseId: inputs.freezeManifest.releaseId, expectedRequests: 3 },
      }),
      inputs.freezeManifest.releaseId,
    );
    state = await persist({ stateStore, state, phase: 'REPROMOTION_VERIFIED' });
  }
  if (state.progress.repromotion.pendingIntegrity === null) {
    state.progress.repromotion.pendingIntegrity = pendingObservation(
      await invoke({
        executor,
        state,
        inputs,
        binding,
        scenarioId: 'RB-E7-08',
        service: 'stage7-pending-integrity',
        operation: 'ReadAfterAlarmRepromotion',
        input: {
          releaseId: inputs.freezeManifest.releaseId,
          beforeSnapshotSha256: state.progress.pendingBefore.snapshotSha256,
        },
      }),
      { before: false, rehearsal: inputs.baseRehearsal },
    );
    if (
      state.progress.repromotion.pendingIntegrity.snapshotSha256 !==
        state.progress.pendingBefore.snapshotSha256 ||
      state.progress.repromotion.pendingIntegrity.stillPending !==
        state.progress.repromotion.pendingIntegrity.trackedBefore ||
      state.progress.repromotion.pendingIntegrity.reconciled !== 0
    ) {
      fail('E7_RB08_REPROMOTION_PENDING_NOT_PRESERVED');
    }
    state = await persist({ stateStore, state, phase: 'REPROMOTION_PENDING_VERIFIED' });
  }
  const finalInvalidation = { ...state.progress.invalidation };
  delete finalInvalidation.rawId;
  state.progress.invalidation = finalInvalidation;
  const finalRepromotionInvalidation = { ...state.progress.repromotion.invalidation };
  delete finalRepromotionInvalidation.rawId;
  state.progress.repromotion.invalidation = finalRepromotionInvalidation;
  const completedAtUtc = state.transcript.at(-1).observedAtUtc;
  const body = rb08CheckpointBody({
    inputs,
    binding,
    descriptor: checkedDescriptor,
    state,
    completedAtUtc,
  });
  const checkpoint = { ...body, checkpointSha256: objectSha256(body) };
  validateRbE708Checkpoint(checkpoint, {
    inputs,
    descriptor,
    authority: inputs.execution.mode === 'AWS_REAL' ? PROTECTED_AWS_EVIDENCE_AUTHORITY : undefined,
  });
  state = await persist({ stateStore, state, phase: 'COMPLETE', checkpoint });
  return state.checkpoint;
};

const ALL_ROLLBACK_SCENARIOS = [
  'RB-E7-01',
  'RB-E7-02',
  'RB-E7-03',
  'RB-E7-04',
  'RB-E7-05',
  'RB-E7-06',
  'RB-E7-07',
  'RB-E7-08',
];

export const createRollbackResilienceExtension = ({
  inputs,
  rb06Descriptor,
  rb08Descriptor,
  rb06Checkpoint,
  rb08Checkpoint,
  authority,
}) => {
  const { binding, parsedDocuments } = validateBoundInputs(inputs);
  validateRbE706Checkpoint(rb06Checkpoint, {
    inputs,
    descriptor: rb06Descriptor,
    authority,
  });
  validateRbE708Checkpoint(rb08Checkpoint, {
    inputs,
    descriptor: rb08Descriptor,
    authority,
  });
  if (
    rb06Checkpoint.binding.bindingSha256 !== binding.bindingSha256 ||
    rb08Checkpoint.binding.bindingSha256 !== binding.bindingSha256 ||
    rb06Checkpoint.originProtection.candidateContractSha256 !==
      rb08Checkpoint.originProtection.candidateContractSha256 ||
    rb06Checkpoint.originProtection.previousContractSha256 !==
      rb08Checkpoint.originProtection.previousContractSha256
  ) {
    fail('E7_RESILIENCE_EXTENSION_BINDING_MISMATCH');
  }
  const real = inputs.execution.mode === 'AWS_REAL';
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_REHEARSAL_SCENARIO_EXTENSION',
    status: real ? 'AWS_VERIFIED_PENDING_CORE_ADAPTER' : 'BLOCKED_REAL_AWS_REQUIRED',
    binding,
    baseRehearsalSha256: inputs.baseRehearsal.rehearsalSha256,
    baseRehearsalStatus: inputs.baseRehearsal.status,
    supplementalScenarioIds: ['RB-E7-06', 'RB-E7-08'],
    combinedScenarioIds: ALL_ROLLBACK_SCENARIOS,
    remainingScenarioIds: real ? [] : ['RB-E7-06', 'RB-E7-08'],
    rb06CheckpointSha256: rb06Checkpoint.checkpointSha256,
    rb08CheckpointSha256: rb08Checkpoint.checkpointSha256,
    originProtectionContractSha256: rb06Checkpoint.originProtection.candidateContractSha256,
    authorizationUsage: parsedDocuments.authorizationBudget.reservedUsage,
    adaptation: {
      targetKind: 'VERSIONED_ROLLBACK_REHEARSAL',
      requiredBaseStatus: 'BLOCKED_REQUIRED_SCENARIOS',
      resultingStatus: real ? 'PASS' : 'BLOCKED_REQUIRED_SCENARIOS',
      resultingPendingScenarioIds: real ? [] : ['RB-E7-06', 'RB-E7-08'],
      preservesBaseCheckpoints: true,
    },
    dataPolicy: 'NO_ROLLBACK_FORWARD_ONLY',
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    gateE703: real ? 'BLOCKED_PENDING_REHEARSAL_CORE_INTEGRATION' : 'BLOCKED_REAL_AWS_REQUIRED',
    containsSensitiveData: false,
  };
  return validateRollbackResilienceExtension(
    { ...body, extensionSha256: objectSha256(body) },
    {
      inputs,
      rb06Descriptor,
      rb08Descriptor,
      rb06Checkpoint,
      rb08Checkpoint,
      authority,
    },
  );
};

export const validateRollbackResilienceExtension = (
  extension,
  { inputs, rb06Descriptor, rb08Descriptor, rb06Checkpoint, rb08Checkpoint, authority },
) => {
  const { binding } = validateBoundInputs(inputs);
  validateRbE706Checkpoint(rb06Checkpoint, {
    inputs,
    descriptor: rb06Descriptor,
    authority,
  });
  validateRbE708Checkpoint(rb08Checkpoint, {
    inputs,
    descriptor: rb08Descriptor,
    authority,
  });
  const real = inputs.execution.mode === 'AWS_REAL';
  if (
    !exactKeys(extension, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'binding',
      'baseRehearsalSha256',
      'baseRehearsalStatus',
      'supplementalScenarioIds',
      'combinedScenarioIds',
      'remainingScenarioIds',
      'rb06CheckpointSha256',
      'rb08CheckpointSha256',
      'originProtectionContractSha256',
      'authorizationUsage',
      'adaptation',
      'dataPolicy',
      'dataRollbackPerformed',
      'stacksDeleted',
      'gateE703',
      'containsSensitiveData',
      'extensionSha256',
    ]) ||
    extension.schemaVersion !== 1 ||
    extension.stage !== 7 ||
    extension.kind !== 'VERSIONED_ROLLBACK_REHEARSAL_SCENARIO_EXTENSION' ||
    extension.status !==
      (real ? 'AWS_VERIFIED_PENDING_CORE_ADAPTER' : 'BLOCKED_REAL_AWS_REQUIRED') ||
    canonicalJson(extension.binding) !== canonicalJson(binding) ||
    extension.baseRehearsalSha256 !== inputs.baseRehearsal.rehearsalSha256 ||
    extension.baseRehearsalStatus !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    extension.supplementalScenarioIds?.join('\0') !== ['RB-E7-06', 'RB-E7-08'].join('\0') ||
    extension.combinedScenarioIds?.join('\0') !== ALL_ROLLBACK_SCENARIOS.join('\0') ||
    extension.remainingScenarioIds?.join('\0') !==
      (real ? [] : ['RB-E7-06', 'RB-E7-08']).join('\0') ||
    extension.rb06CheckpointSha256 !== rb06Checkpoint.checkpointSha256 ||
    extension.rb08CheckpointSha256 !== rb08Checkpoint.checkpointSha256 ||
    extension.originProtectionContractSha256 !==
      rb06Checkpoint.originProtection.candidateContractSha256 ||
    extension.originProtectionContractSha256 !==
      rb08Checkpoint.originProtection.candidateContractSha256 ||
    validateAuthorizationUsage({
      usage: extension.authorizationUsage,
      authorization: validateBoundInputs(inputs).parsedDocuments.externalAuthorization,
      inputs,
    }) !== extension.authorizationUsage ||
    extension.authorizationUsage.usageId !== 'ROLLBACK_RESILIENCE' ||
    extension.authorizationUsage.requestCounts['AUTH-E7-EXT-01'] !==
      rb06Checkpoint.originProtection.externalRequests +
        rb06Checkpoint.smoke.externalRequests +
        rb08Checkpoint.originProtection.externalRequests +
        rb08Checkpoint.smoke.externalRequests +
        rb08Checkpoint.repromotion.smoke.externalRequests ||
    extension.authorizationUsage.requestCounts['AUTH-E7-EXT-01'] !== 11 ||
    extension.authorizationUsage.requestCounts['AUTH-E7-EXT-02'] !== 0 ||
    extension.authorizationUsage.requestCounts['AUTH-E7-EXT-03'] !== 0 ||
    !exactKeys(extension.adaptation, [
      'targetKind',
      'requiredBaseStatus',
      'resultingStatus',
      'resultingPendingScenarioIds',
      'preservesBaseCheckpoints',
    ]) ||
    extension.adaptation.targetKind !== 'VERSIONED_ROLLBACK_REHEARSAL' ||
    extension.adaptation.requiredBaseStatus !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    extension.adaptation.resultingStatus !== (real ? 'PASS' : 'BLOCKED_REQUIRED_SCENARIOS') ||
    extension.adaptation.resultingPendingScenarioIds?.join('\0') !==
      (real ? [] : ['RB-E7-06', 'RB-E7-08']).join('\0') ||
    extension.adaptation.preservesBaseCheckpoints !== true ||
    extension.dataPolicy !== 'NO_ROLLBACK_FORWARD_ONLY' ||
    extension.dataRollbackPerformed !== false ||
    extension.stacksDeleted !== 0 ||
    extension.gateE703 !==
      (real ? 'BLOCKED_PENDING_REHEARSAL_CORE_INTEGRATION' : 'BLOCKED_REAL_AWS_REQUIRED') ||
    extension.containsSensitiveData !== false ||
    extension.extensionSha256 !== objectSha256(withoutDigest(extension, 'extensionSha256'))
  ) {
    fail('E7_RESILIENCE_EXTENSION_INVALID');
  }
  return extension;
};

const createRollbackResilienceCompletion = ({
  inputs,
  extension,
  rb06Checkpoint,
  rb08Checkpoint,
  journalLifecycle,
  authority,
}) => {
  if (
    inputs.execution.mode !== 'AWS_REAL' ||
    authority !== PROTECTED_AWS_EVIDENCE_AUTHORITY ||
    extension.status !== 'AWS_VERIFIED_PENDING_CORE_ADAPTER' ||
    rb06Checkpoint.status !== 'AWS_VERIFIED' ||
    rb08Checkpoint.status !== 'AWS_VERIFIED' ||
    validateRollbackJournalLifecycle(journalLifecycle, { inputs }) !== journalLifecycle
  ) {
    fail('E7_RESILIENCE_COMPLETION_AUTHORITY_REQUIRED');
  }
  const completedAtUtc =
    Date.parse(rb06Checkpoint.completedAtUtc) > Date.parse(rb08Checkpoint.completedAtUtc)
      ? rb06Checkpoint.completedAtUtc
      : rb08Checkpoint.completedAtUtc;
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_COMPLETION',
    status: 'AWS_VERIFIED',
    baseRehearsalSha256: inputs.baseRehearsal.rehearsalSha256,
    scenarioIds: ALL_ROLLBACK_SCENARIOS,
    pendingScenarioIds: [],
    rb06CheckpointSha256: rb06Checkpoint.checkpointSha256,
    rb08CheckpointSha256: rb08Checkpoint.checkpointSha256,
    extensionSha256: extension.extensionSha256,
    originProtectionContractSha256: extension.originProtectionContractSha256,
    authorizationUsageSha256: objectSha256(extension.authorizationUsage),
    journalLifecycleSha256: journalLifecycle.lifecycleSha256,
    reconciliationRecoveryRoleAuthoritySha256: reconciliationRecoveryRoleAuthoritySha256(
      JSON.parse(inputs.documents.awsAuth.content),
    ),
    finalReleaseId: inputs.freezeManifest.releaseId,
    finalCandidateSha: inputs.freezeManifest.candidateSha,
    completedAtUtc,
    dataPolicy: 'NO_ROLLBACK_FORWARD_ONLY',
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    containsSensitiveData: false,
  };
  return { ...body, completionSha256: objectSha256(body) };
};

const validateProtectedRollbackResilienceRun = (
  run,
  { inputs, rb06Descriptor, rb08Descriptor, authority },
) => {
  if (authority !== PROTECTED_AWS_EVIDENCE_AUTHORITY) {
    fail('E7_RESILIENCE_AWS_EVIDENCE_AUTHORITY_REQUIRED');
  }
  if (
    !exactKeys(run, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'executionSha256',
      'runtimeAttestation',
      'rb06Checkpoint',
      'rb08Checkpoint',
      'extension',
      'completion',
      'gateE703',
      'containsSensitiveData',
      'runSha256',
    ]) ||
    run.schemaVersion !== 1 ||
    run.stage !== 7 ||
    run.kind !== 'PROTECTED_ROLLBACK_RESILIENCE_RUN' ||
    run.status !== 'AWS_VERIFIED' ||
    run.executionSha256 !== objectSha256(inputs.execution) ||
    run.runtimeAttestation?.status !== 'AWS_IDENTITY_REVALIDATED' ||
    run.runtimeAttestation?.executionSha256 !== run.executionSha256 ||
    !SHA256.test(run.runtimeAttestation?.awsCliVersionSha256 ?? '') ||
    validateRollbackJournalLifecycle(run.runtimeAttestation?.journalLifecycle, { inputs }) !==
      run.runtimeAttestation?.journalLifecycle ||
    run.runtimeAttestation?.stateBackend !== 'SSM_APPEND_ONLY_HASH_CHAIN' ||
    run.runtimeAttestation?.executorConstruction !== 'INTERNAL_AWS_CLI_ONLY' ||
    run.runtimeAttestation?.injectedExecutorAccepted !== false ||
    run.runtimeAttestation?.containsSensitiveData !== false ||
    run.runtimeAttestation?.attestationSha256 !==
      objectSha256(withoutDigest(run.runtimeAttestation, 'attestationSha256')) ||
    !exactKeys(run.completion, RESILIENCE_COMPLETION_KEYS) ||
    run.completion?.schemaVersion !== 1 ||
    run.completion?.stage !== 7 ||
    run.completion?.kind !== 'ROLLBACK_RESILIENCE_COMPLETION' ||
    run.completion?.status !== 'AWS_VERIFIED' ||
    run.completion?.baseRehearsalSha256 !== inputs.baseRehearsal.rehearsalSha256 ||
    run.completion?.rb06CheckpointSha256 !== run.rb06Checkpoint?.checkpointSha256 ||
    run.completion?.rb08CheckpointSha256 !== run.rb08Checkpoint?.checkpointSha256 ||
    run.completion?.extensionSha256 !== run.extension?.extensionSha256 ||
    run.completion?.authorizationUsageSha256 !== objectSha256(run.extension?.authorizationUsage) ||
    run.completion?.journalLifecycleSha256 !==
      run.runtimeAttestation?.journalLifecycle?.lifecycleSha256 ||
    run.completion?.reconciliationRecoveryRoleAuthoritySha256 !==
      reconciliationRecoveryRoleAuthoritySha256(JSON.parse(inputs.documents.awsAuth.content)) ||
    run.completion?.originProtectionContractSha256 !==
      run.extension?.originProtectionContractSha256 ||
    run.completion?.finalReleaseId !== inputs.freezeManifest.releaseId ||
    run.completion?.finalCandidateSha !== inputs.freezeManifest.candidateSha ||
    run.completion?.dataPolicy !== 'NO_ROLLBACK_FORWARD_ONLY' ||
    run.completion?.dataRollbackPerformed !== false ||
    run.completion?.stacksDeleted !== 0 ||
    run.completion?.containsSensitiveData !== false ||
    run.completion?.completionSha256 !==
      objectSha256(withoutDigest(run.completion, 'completionSha256')) ||
    run.gateE703 !== 'ELIGIBLE_PENDING_RELEASE_CLOSEOUT' ||
    run.containsSensitiveData !== false ||
    run.runSha256 !== objectSha256(withoutDigest(run, 'runSha256'))
  ) {
    fail('E7_RESILIENCE_PROTECTED_RUN_INVALID');
  }
  validateRbE706Checkpoint(run.rb06Checkpoint, {
    inputs,
    descriptor: rb06Descriptor,
    authority,
  });
  validateRbE708Checkpoint(run.rb08Checkpoint, {
    inputs,
    descriptor: rb08Descriptor,
    authority,
  });
  validateRollbackResilienceExtension(run.extension, {
    inputs,
    rb06Descriptor,
    rb08Descriptor,
    rb06Checkpoint: run.rb06Checkpoint,
    rb08Checkpoint: run.rb08Checkpoint,
    authority,
  });
  return run;
};

const reconstructProtectedExecution = ({ run, inputsWithoutExecution, capability }) => {
  const attestation = run?.runtimeAttestation;
  const identity = attestation?.identity;
  const startedAtUtc = run?.rb08Checkpoint?.startedAtUtc;
  const completedAtUtc = run?.completion?.completedAtUtc;
  const execution = {
    mode: 'AWS_REAL',
    repository: attestation?.repository,
    workflow: attestation?.workflow,
    runId: attestation?.runId,
    runAttempt: attestation?.runAttempt,
    githubActions: true,
    githubRef: 'refs/heads/master',
    githubSha: attestation?.githubSha,
    protectedEnvironment: attestation?.protectedEnvironment,
    accountId: inputsWithoutExecution?.config?.aws?.accountId,
    region: inputsWithoutExecution?.config?.aws?.region,
    roleArn: inputsWithoutExecution?.config?.aws?.roles?.rollbackRoleArn,
    startedAtUtc,
  };
  const inputs = { ...inputsWithoutExecution, execution };
  if (capability === SELF_TEST_EXECUTOR_CAPABILITY) SELF_TEST_REAL_INPUTS.add(inputs);
  if (
    !exactKeys(inputsWithoutExecution, [
      'config',
      'freezeManifest',
      'previousReleaseManifest',
      'candidateRecord',
      'baseRehearsal',
      'documents',
      'journalCleanupRoleArn',
    ]) ||
    Object.hasOwn(inputsWithoutExecution, 'execution') ||
    !exactKeys(attestation, RUNTIME_ATTESTATION_KEYS) ||
    !exactKeys(identity, RUNTIME_IDENTITY_KEYS) ||
    attestation.schemaVersion !== 1 ||
    attestation.stage !== 7 ||
    attestation.kind !== 'ROLLBACK_RESILIENCE_PROTECTED_RUNTIME_ATTESTATION' ||
    attestation.status !== 'AWS_IDENTITY_REVALIDATED' ||
    attestation.repository !== REPOSITORY ||
    attestation.workflow !== PROTECTED_WORKFLOW ||
    attestation.githubSha !== inputsWithoutExecution.freezeManifest?.candidateSha ||
    attestation.protectedEnvironment !== PROTECTED_ENVIRONMENT ||
    attestation.protectedBindingSha256 !==
      protectedBindingSha256({ inputsWithoutExecution, execution }) ||
    attestation.executionSha256 !== objectSha256(execution) ||
    identity.accountSha256 !== sha256(inputsWithoutExecution.config?.aws?.accountId ?? '') ||
    identity.accountSuffix !== inputsWithoutExecution.config?.aws?.accountId?.slice(-4) ||
    identity.roleSha256 !==
      sha256(inputsWithoutExecution.config?.aws?.roles?.rollbackRoleArn ?? '') ||
    !SHA256.test(identity.sessionArnSha256 ?? '') ||
    !utc(identity.observedAtUtc) ||
    !utc(completedAtUtc) ||
    Date.parse(identity.observedAtUtc) < Date.parse(startedAtUtc) ||
    Date.parse(identity.observedAtUtc) > Date.parse(completedAtUtc) ||
    attestation.awsCliVersionSha256 !==
      sha256(inputsWithoutExecution.freezeManifest?.toolchain?.awsCli ?? '') ||
    attestation.journalPrefixSha256 !==
      sha256(`/checkout/stage7/rollback/${inputsWithoutExecution.freezeManifest?.candidateSha}`) ||
    attestation.stateBackend !== 'SSM_APPEND_ONLY_HASH_CHAIN' ||
    attestation.executorConstruction !== 'INTERNAL_AWS_CLI_ONLY' ||
    attestation.injectedExecutorAccepted !== false ||
    attestation.containsSensitiveData !== false ||
    attestation.attestationSha256 !== objectSha256(withoutDigest(attestation, 'attestationSha256'))
  ) {
    fail('E7_RESILIENCE_RUNTIME_ATTESTATION_INVALID');
  }
  validateRollbackJournalLifecycle(attestation.journalLifecycle, { inputs });
  validateBoundInputs(inputs);
  return inputs;
};

/**
 * Revalidates a protected artifact from immutable source inputs. This public
 * reader cannot construct AWS evidence: it only grants the private validation
 * authority after the runtime attestation, execution, descriptors and every
 * nested RB-E7-06/RB-E7-08 observation have been recomputed from their sources.
 */
const validatePublicProtectedRollbackResilienceRunInternal = (
  { run, inputsWithoutExecution, rb06Descriptor, rb08Descriptor },
  capability,
) => {
  const inputs = reconstructProtectedExecution({ run, inputsWithoutExecution, capability });
  return validateProtectedRollbackResilienceRun(run, {
    inputs,
    rb06Descriptor,
    rb08Descriptor,
    authority: PROTECTED_AWS_EVIDENCE_AUTHORITY,
  });
};

export const validatePublicProtectedRollbackResilienceRun = (options) =>
  validatePublicProtectedRollbackResilienceRunInternal(options);

/**
 * The only production entry point. It builds the authenticated AWS executor and
 * SSM journal internally; callers cannot supply either dependency or assert an
 * AWS_REAL mode in an input document.
 */
const validateProtectedRollbackOptions = (options) => {
  if (
    !exactKeys(options, ['inputsWithoutExecution', 'rb06Descriptor', 'rb08Descriptor']) ||
    !exactKeys(options.inputsWithoutExecution, [
      'config',
      'freezeManifest',
      'previousReleaseManifest',
      'candidateRecord',
      'baseRehearsal',
      'documents',
      'journalCleanupRoleArn',
    ])
  ) {
    fail('E7_RESILIENCE_PROTECTED_OPTIONS_INVALID');
  }
  return options;
};

export const runProtectedAwsRollbackResilience = async (options) => {
  validateProtectedRollbackOptions(options);
  const runtime = await createProtectedRollbackRuntime(options);
  if (
    !exactKeys(runtime, ['inputs', 'executor', 'stateStore', 'attestation']) ||
    runtime.inputs.execution?.mode !== 'AWS_REAL' ||
    typeof runtime.executor !== 'function' ||
    !object(runtime.stateStore) ||
    runtime.attestation?.status !== 'AWS_IDENTITY_REVALIDATED' ||
    runtime.attestation?.containsSensitiveData !== false
  ) {
    fail('E7_RESILIENCE_PROTECTED_RUNTIME_INVALID');
  }
  validateBoundInputs(runtime.inputs);
  const rb06Checkpoint = await produceRbE706({
    inputs: runtime.inputs,
    descriptor: options.rb06Descriptor,
    executor: runtime.executor,
    stateStore: runtime.stateStore,
    capability: PROTECTED_AWS_EXECUTOR_CAPABILITY,
  });
  const rb08Checkpoint = await produceRbE708({
    inputs: runtime.inputs,
    descriptor: options.rb08Descriptor,
    executor: runtime.executor,
    stateStore: runtime.stateStore,
    capability: PROTECTED_AWS_EXECUTOR_CAPABILITY,
  });
  const extension = createRollbackResilienceExtension({
    inputs: runtime.inputs,
    rb06Descriptor: options.rb06Descriptor,
    rb08Descriptor: options.rb08Descriptor,
    rb06Checkpoint,
    rb08Checkpoint,
    authority: PROTECTED_AWS_EVIDENCE_AUTHORITY,
  });
  const completion = createRollbackResilienceCompletion({
    inputs: runtime.inputs,
    extension,
    rb06Checkpoint,
    rb08Checkpoint,
    journalLifecycle: runtime.attestation.journalLifecycle,
    authority: PROTECTED_AWS_EVIDENCE_AUTHORITY,
  });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PROTECTED_ROLLBACK_RESILIENCE_RUN',
    status: 'AWS_VERIFIED',
    executionSha256: objectSha256(runtime.inputs.execution),
    runtimeAttestation: runtime.attestation,
    rb06Checkpoint,
    rb08Checkpoint,
    extension,
    completion,
    gateE703: 'ELIGIBLE_PENDING_RELEASE_CLOSEOUT',
    containsSensitiveData: false,
  };
  return validateProtectedRollbackResilienceRun(
    { ...body, runSha256: objectSha256(body) },
    {
      inputs: runtime.inputs,
      rb06Descriptor: options.rb06Descriptor,
      rb08Descriptor: options.rb08Descriptor,
      authority: PROTECTED_AWS_EVIDENCE_AUTHORITY,
    },
  );
};

const selfTestConfig = () => {
  const environment = 'assessment-release';
  return {
    schemaVersion: 1,
    stage: 7,
    environment,
    authorization: {
      id: 'AUTH-E7-RB-01',
      status: 'APPROVED',
      scope: 'FULL_RELEASE_VERSIONED_UPDATE',
      ownerAlias: 'release-owner',
      approvedAtUtc: '2026-08-17T10:00:00.000Z',
      expiresAtUtc: '2026-08-18T10:00:00.000Z',
      stacks: expectedStage7Stacks(environment),
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
      accountId: '123456789012',
      region: 'us-east-1',
      roles: {
        readRoleArn: 'arn:aws:iam::123456789012:role/checkout-read',
        deployRoleArn: 'arn:aws:iam::123456789012:role/checkout-deploy',
        rollbackRoleArn: 'arn:aws:iam::123456789012:role/checkout-rollback',
        cleanupRoleArn: 'arn:aws:iam::123456789012:role/checkout-cleanup',
        baselineRoleArn: 'arn:aws:iam::123456789012:role/checkout-baseline',
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
      hostedZoneId: 'Z1234567890ABC',
      webCertificateArn: [
        'arn:aws:acm:us-east-1:123456789012:certificate',
        '11111111-1111-1111-1111-111111111111',
      ].join('/'),
      apiCertificateArn: [
        'arn:aws:acm:us-east-1:123456789012:certificate',
        '22222222-2222-2222-2222-222222222222',
      ].join('/'),
      dnsIncluded: true,
    },
    prereleaseAccess: {
      mode: 'ORIGIN_GATE_ONLY',
      keyGroupId: null,
      publicKeyId: null,
      originTokenSecretArn: [
        'arn:aws:secretsmanager:us-east-1:123456789012:secret:checkout',
        'runtime-security',
      ].join('/'),
      originTokenSecretVersionId: ['11111111', '2222', '3333', '4444', '555555555555'].join('-'),
      rotationDuringWindow: 'FORBIDDEN',
    },
    cleanup: {
      ownerAlias: 'cleanup-owner',
      expiresAtUtc: '2026-08-20T15:00:00.000Z',
      preserveBootstrap: true,
      preservePreviousRelease: true,
    },
    credentialReferences: [
      ['arn:aws:secretsmanager:us-east-1:123456789012:secret:checkout', 'runtime-security'].join(
        '/',
      ),
    ],
    containsSensitiveData: false,
  };
};

const selfTestDocument = (value) => {
  const content = `${JSON.stringify(value)}\n`;
  return { content, sha256: sha256(content) };
};

const selfTestObservabilityTemplate = () => ({
  AWSTemplateFormatVersion: '2010-09-09',
  Description: 'Frozen candidate observability stack',
  Parameters: { PublicationState: { Type: 'String', Default: 'ENABLED' } },
  Resources: { ExistingLogGroup: { Type: 'AWS::Logs::LogGroup' } },
});

const selfTestCheckpoint = ({ plan, destination, startedAtUtc, completedAtUtc }) => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_CHECKPOINT',
    status: 'PASS',
    direction: plan.direction,
    decision: 'APPLIED_AND_VERIFIED',
    scenarioIds:
      plan.direction === 'ROLLBACK_TO_PREVIOUS'
        ? ['RB-E7-01', 'RB-E7-03', 'RB-E7-05', 'RB-E7-07']
        : ['RB-E7-02', 'RB-E7-04', 'RB-E7-05', 'RB-E7-07'],
    planSha256: plan.planSha256,
    startedAtUtc,
    completedAtUtc,
    fromReleaseId: plan.fromReleaseId,
    toReleaseId: plan.toReleaseId,
    aliases: {
      api: {
        functionName: destination.api.functionName,
        aliasName: destination.api.aliasName,
        version: destination.api.version,
      },
      worker: {
        functionName: destination.worker.functionName,
        aliasName: destination.worker.aliasName,
        version: destination.worker.version,
      },
    },
    web: {
      bucketName: destination.web.bucketName,
      distributionId: destination.web.distributionId,
      objects: destination.web.objects.map((entry, index) => ({
        key: entry.key,
        sourceVersionId: entry.versionId,
        activeVersionId: `active-${plan.direction.toLowerCase()}-${index + 1}`,
        contentSha256: entry.contentSha256,
        bytes: entry.bytes,
      })),
      invalidation: {
        status: 'COMPLETED',
        idSha256: 'a'.repeat(64),
        paths: destination.web.mutableInvalidationPaths,
      },
    },
    pendingIntegrity: {
      status: 'PASS',
      beforeSnapshotSha256: plan.pendingBaseline.snapshotSha256,
      afterSnapshotSha256: 'b'.repeat(64),
      correlationEvidenceSha256: 'c'.repeat(64),
      trackedBefore: plan.pendingBaseline.trackedCount,
      stillPending: 0,
      reconciled: plan.pendingBaseline.trackedCount,
      orphaned: 0,
      duplicateEffects: 0,
      lostFacts: 0,
    },
    dataFactsSha256: plan.dataFactsSha256,
    dataFactsChanged: false,
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    smoke: {
      status: 'PASS',
      releaseId: plan.toReleaseId,
      evidenceSha256: 'd'.repeat(64),
    },
    containsSensitiveData: false,
  };
  return { ...body, checkpointSha256: objectSha256(body) };
};

const selfTestInputs = () => {
  const config = selfTestConfig();
  const candidateSha = 'a'.repeat(40);
  const artifacts = ['web', 'api', 'worker', 'iac'].map((name, index) => ({
    name,
    sourcePath: `dist/${name}.bin`,
    kind: 'FILE',
    files: 1,
    bytes: index + 10,
    sha256: String(index + 1).repeat(64),
  }));
  const freezeBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'BUILD_ONCE_FREEZE',
    releaseId: 'rel-20260817-1100-aaaaaaa',
    candidateSha,
    candidateTreeSha: 'b'.repeat(40),
    releaseTag: 'v1.0.0-rc.1',
    environment: config.environment,
    authorizationScope: config.authorization.scope,
    region: config.aws.region,
    sourceRunId: 'e6-20260817t100000z-deadbeef',
    sourceArtifactId: '123456789',
    sourceArtifactSha256: '5'.repeat(64),
    preFreezeEvidenceSha256: '6'.repeat(64),
    builtAt: '2026-08-17T11:00:00.000Z',
    configSha256: objectSha256(config),
    lockfileSha256: '7'.repeat(64),
    openApiSha256: '8'.repeat(64),
    generatedClientSha256: '9'.repeat(64),
    publicConfigSha256: 'a'.repeat(64),
    templateSha256: artifacts[3].sha256,
    stage6Gates: { 'GATE-E6-01': 'PASS', 'GATE-E6-02': 'PASS', 'GATE-E6-03': 'PASS' },
    toolchain: {
      node: 'v24.19.0',
      packageManager: 'pnpm@11.19.0',
      cdkCli: '2.1136.0',
      cdkLibrary: '2.265.0',
      awsCli: '2.31.0',
    },
    artifacts,
    controlInventory: {
      artifacts: {
        total: STAGE7_ARTIFACTS.length,
        idsSha256: objectSha256(STAGE7_ARTIFACTS.map(({ id }) => id)),
      },
      evidence: {
        total: STAGE7_EVIDENCE.length,
        idsSha256: objectSha256(STAGE7_EVIDENCE.map(({ id }) => id)),
      },
      audits: {
        total: STAGE7_AUDITS.length,
        idsSha256: objectSha256(STAGE7_AUDITS.map(({ id }) => id)),
      },
    },
    releaseMode: 'VERSIONED_UPDATE',
    updateReleaseSupported: true,
    updateReleaseUnsupportedReason: null,
    buildOnce: { immutable: true, rebuilt: false },
    containsSensitiveData: false,
  };
  const freezeManifest = validateFreezeManifest({
    ...freezeBody,
    manifestSha256: objectSha256(freezeBody),
  });
  const previousObjects = [
    ['index.html', 'previous-index-version'],
    ['public-config.json', 'previous-config-version'],
  ].map(([key, versionId], index) => ({
    key,
    versionId,
    etagSha256: String(index + 1).repeat(64),
    contentSha256: String(index + 4).repeat(64),
    bytes: index + 100,
  }));
  const previousReleaseManifest = createStage7PreviousReleaseManifest({
    schemaVersion: 1,
    stage: 7,
    kind: 'PREVIOUS_APPROVED_RELEASE',
    status: 'APPROVED_IMMUTABLE',
    capturedAtUtc: '2026-08-17T10:30:00.000Z',
    approvedAtUtc: '2026-08-17T10:00:00.000Z',
    environment: config.environment,
    region: config.aws.region,
    previous: {
      candidateSha: 'c'.repeat(40),
      candidateTreeSha: 'd'.repeat(40),
      releaseId: 'rel-20260816-1000-ccccccc',
      releaseTag: 'v0.9.0',
      configSha256: '1'.repeat(64),
      freezeManifestSha256: '2'.repeat(64),
      assemblySha256: '3'.repeat(64),
    },
    target: {
      candidateSha: freezeManifest.candidateSha,
      candidateTreeSha: freezeManifest.candidateTreeSha,
      releaseId: freezeManifest.releaseId,
      releaseTag: freezeManifest.releaseTag,
      configSha256: objectSha256(config),
      freezeManifestSha256: freezeManifest.manifestSha256,
      assemblySha256: artifacts[3].sha256,
    },
    resources: {
      api: {
        functionName: 'checkout-release-api',
        aliasName: 'live',
        version: '7',
        codeSha256: '4'.repeat(64),
      },
      worker: {
        functionName: 'checkout-release-worker',
        aliasName: 'live',
        version: '11',
        codeSha256: '5'.repeat(64),
      },
      web: {
        bucketName: 'checkout-release-web-123456789012',
        distributionId: 'EDFDVBD6EXAMPLE',
        objects: previousObjects,
        mutableInvalidationPaths: ['/index.html', '/public-config.json'],
      },
    },
    compatibility: {
      status: 'PASS',
      schemaStrategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
      dataRollback: 'FORBIDDEN_FORWARD_ONLY',
      apiContractEvidenceSha256: '6'.repeat(64),
      pendingReconciliationEvidenceSha256: '7'.repeat(64),
      smokeEvidenceSha256: '8'.repeat(64),
      smokeVerifiedAtUtc: '2026-08-17T10:15:00.000Z',
    },
    handoff: {
      sourceKind: 'BASELINE_BOOTSTRAP',
      sourceBundleSha256: 'e'.repeat(64),
      sourceArtifactProvenanceSha256: 'f'.repeat(64),
      targetCompatibilityEvidenceSha256: '0'.repeat(64),
      finalDisableEvidenceSha256: '1'.repeat(64),
      predecessorManifestSha256: null,
    },
    approval: {
      status: 'APPROVED',
      reviewerAlias: 'release-reviewer',
      approvalEvidenceSha256: '9'.repeat(64),
      releaseEvidenceSha256: 'a'.repeat(64),
    },
    containsSensitiveData: false,
  });
  const observabilityTemplateSha256 = objectSha256(selfTestObservabilityTemplate());
  const alarmName = `checkout-${config.environment}-rollback-rehearsal`;
  const alarmArn = `arn:aws:cloudwatch:${config.aws.region}:${config.aws.accountId}:alarm:${alarmName}`;
  const alarmDimensions = [
    { name: 'Environment', value: config.environment },
    { name: 'ReleaseId', value: freezeManifest.releaseId },
    { name: 'Scenario', value: 'RB-E7-08' },
  ];
  const rollbackResilience = {
    stackName: expectedStage7Stacks(config.environment)[2],
    templateSha256: observabilityTemplateSha256,
    cloudFormationExecutionRoleArn: cloudFormationExecutionRoleArn({ config }),
    rollbackRehearsalAlarm: {
      alarmName,
      alarmArn,
      metricNamespace: 'Checkout/Stage7Rehearsal',
      metricName: 'RollbackRehearsalFailure',
      dimensions: alarmDimensions,
      statistic: 'Maximum',
      unit: 'Count',
      periodSeconds: 60,
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: 'GreaterThanOrEqualToThreshold',
      treatMissingData: 'notBreaching',
      actionsEnabled: false,
      alarmActions: [],
      okActions: [],
      insufficientDataActions: [],
    },
  };
  const iamEffectivePermissionsBindingSha256 = 'f'.repeat(64);
  const journalRoleEffectivePermissionsRawSha256 = 'a'.repeat(64);
  const journalRoleEffectivePermissionsSha256 = 'b'.repeat(64);
  const reconciliationRecoveryRoleArn =
    'arn:aws:iam::123456789012:role/stage7-release-reconciliation-recovery';
  const awsAuthDocument = selfTestDocument({
    schemaVersion: 1,
    stage: 7,
    kind: 'AWS_READ_ONLY_PREFLIGHT',
    status: 'PASS',
    scope: 'full',
    candidateSha,
    releaseId: freezeManifest.releaseId,
    manifestSha256: freezeManifest.manifestSha256,
    configSha256: objectSha256(config),
    accountSha256: sha256(config.aws.accountId),
    accountSuffix: config.aws.accountId.slice(-4),
    callerArnSha256: '1'.repeat(64),
    expectedRoleArnSha256: sha256(config.aws.roles.readRoleArn),
    region: config.aws.region,
    sessionMode: 'OIDC',
    roleTrust: 'PASS',
    bootstrapVersion: 25,
    bootstrapStackIdSha256: '2'.repeat(64),
    bootstrapStackStatus: 'CREATE_COMPLETE',
    quotaCapacity: {},
    stackInventory: {},
    authorizedStacks: {},
    mutationsPerformed: 0,
    iamEffectivePermissions: {
      bindingSha256: iamEffectivePermissionsBindingSha256,
    },
    journalRoleEffectivePermissionsRawSha256,
    journalRoleEffectivePermissionsSha256,
    reconciliationRecoveryRoleArn,
    reconciliationRecoveryPermissionsBoundaryArn:
      'arn:aws:iam::123456789012:policy/stage7-release-reconciliation-recovery-boundary',
    reconciliationRecoveryRoleEffectivePermissionsRawSha256: 'c'.repeat(64),
    reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256: 'd'.repeat(64),
    reconciliationRecoveryRoleEffectivePermissionsSha256: 'e'.repeat(64),
    reconciliationRecoveryRoleEffectivePolicyProjectionSha256: '0'.repeat(64),
    capacityProven: true,
    decision: 'READY_FOR_CLOUD_OPERATIONS',
    preFreezeException: false,
    longLivedCredentials: false,
    externalRequests: 1,
    containsSensitiveData: false,
  });
  const approvedPlanDocument = selfTestDocument({
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_DIFF_REVIEW',
    status: 'READY_FOR_PROTECTED_REVIEW',
    candidateSha,
    releaseId: freezeManifest.releaseId,
    configSha256: objectSha256(config),
    previousReleaseManifestSha256: previousReleaseManifest.manifestSha256,
    rawDiffArtifactSha256: '4'.repeat(64),
    iamBroadeningDetected: false,
    containsSensitiveData: false,
  });
  const documents = {
    approval: selfTestDocument({
      schemaVersion: 1,
      stage: 7,
      kind: 'PROTECTED_RELEASE_APPROVAL',
      status: 'PASS',
      scope: 'full',
      candidateSha,
      releaseId: freezeManifest.releaseId,
      releaseTag: freezeManifest.releaseTag,
      configSha256: objectSha256(config),
      cloudAssemblySha256: freezeManifest.artifacts.find(({ name }) => name === 'iac').sha256,
      freezeManifestSha256: freezeManifest.manifestSha256,
      previousReleaseManifestSha256: previousReleaseManifest.manifestSha256,
      approvedPlanSha256: approvedPlanDocument.sha256,
      approvedDiffSha256: '4'.repeat(64),
      iamEffectivePermissionsBindingSha256,
      iamEffectivePermissionsEvidenceSha256: awsAuthDocument.sha256,
      journalRoleEffectivePermissionsRawSha256,
      journalRoleEffectivePermissionsSha256,
      reconciliationRecoveryRoleArn,
      reconciliationRecoveryPermissionsBoundaryArn:
        'arn:aws:iam::123456789012:policy/stage7-release-reconciliation-recovery-boundary',
      reconciliationRecoveryRoleEffectivePermissionsRawSha256: 'c'.repeat(64),
      reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256: 'd'.repeat(64),
      reconciliationRecoveryRoleEffectivePermissionsSha256: 'e'.repeat(64),
      reconciliationRecoveryRoleEffectivePolicyProjectionSha256: '0'.repeat(64),
      approvedAtUtc: '2026-08-17T11:01:00.000Z',
      statefulReplacements: 0,
      destructiveChanges: 0,
      iamBroadeningDetected: false,
      iamBroadeningReviewed: true,
      humanReviewConfirmed: true,
      explicitDispatchConfirmation: true,
      protectedEnvironment: true,
      protectedEnvironmentName: 'assessment-release',
      nonPublic: false,
      accountSha256: sha256(config.aws.accountId),
      accountSuffix: config.aws.accountId.slice(-4),
      region: config.aws.region,
      stacks: config.authorization.stacks,
      budget: {
        maxUsd: config.budget.maxUsd,
        warningUsd: config.budget.warningUsd,
        alertDestinationSha256: config.budget.alertDestinationSha256,
      },
      approvalOwnerAlias: config.authorization.ownerAlias,
      reviewerAlias: 'release-reviewer',
      authorizedWindow: config.window,
      externalRequests: 0,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    }),
    awsAuth: awsAuthDocument,
    approvedPlan: approvedPlanDocument,
    deploymentEvidence: selfTestDocument({
      schemaVersion: 1,
      stage: 7,
      environment: config.environment,
      authorizationId: config.authorization.id,
      authorizationScope: config.authorization.scope,
      status: 'IN_PROGRESS',
      candidateSha,
      releaseId: freezeManifest.releaseId,
      configSha256: objectSha256(config),
      region: config.aws.region,
      checkpoints: {
        web: {
          decision: 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION',
          releaseMode: 'VERSIONED_UPDATE',
          freezeManifestSha256: freezeManifest.manifestSha256,
          previousReleaseManifestSha256: previousReleaseManifest.manifestSha256,
          outputs: {
            CandidateSha: candidateSha,
            ReleaseId: freezeManifest.releaseId,
            WebPublicationStatus: 'DISABLED',
          },
        },
      },
      updatedAtUtc: '2026-08-17T11:00:00.000Z',
      containsSensitiveData: false,
    }),
    observabilityEvidence: selfTestDocument({
      schemaVersion: 1,
      stage: 7,
      environment: config.environment,
      authorizationId: config.authorization.id,
      authorizationScope: config.authorization.scope,
      status: 'IN_PROGRESS',
      candidateSha,
      releaseId: freezeManifest.releaseId,
      configSha256: objectSha256(config),
      region: config.aws.region,
      checkpoints: {
        observability: {
          decision: 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION',
          releaseMode: 'VERSIONED_UPDATE',
          freezeManifestSha256: freezeManifest.manifestSha256,
          previousReleaseManifestSha256: previousReleaseManifest.manifestSha256,
          rollbackResilience,
        },
        observabilityReadiness: {
          decision: 'PASS',
          status: 'CONFIRMED',
          alertDestinationSha256: config.budget.alertDestinationSha256,
          rawDestinationCaptured: false,
        },
      },
      updatedAtUtc: '2026-08-17T11:00:00.000Z',
      containsSensitiveData: false,
    }),
    activationEvidence: selfTestDocument({
      schemaVersion: 1,
      stage: 7,
      environment: config.environment,
      authorizationId: config.authorization.id,
      authorizationScope: config.authorization.scope,
      status: 'IN_PROGRESS',
      candidateSha,
      releaseId: freezeManifest.releaseId,
      configSha256: objectSha256(config),
      region: config.aws.region,
      checkpoints: {
        activation: {
          decision: 'ACTIVATED_REQUIRES_SMOKE',
          previousReleaseManifestSha256: previousReleaseManifest.manifestSha256,
        },
      },
      updatedAtUtc: '2026-08-17T11:00:00.000Z',
      containsSensitiveData: false,
    }),
  };
  const authorizationSha256 = '6'.repeat(64);
  const authorization = {
    schemaVersion: 1,
    stage: 7,
    kind: 'EXTERNAL_AUTHORIZATION_PREFLIGHT',
    status: 'PASS',
    scope: 'full',
    candidateSha,
    releaseId: freezeManifest.releaseId,
    stage7ConfigSha256: objectSha256(config),
    ownedOriginSha256: '7'.repeat(64),
    sandboxHostSha256: '8'.repeat(64),
    authorizationSha256,
    authorizationIds: AUTHORIZATION_IDS,
    requestLimits: {
      'AUTH-E7-EXT-01': 64,
      'AUTH-E7-EXT-02': 64,
      'AUTH-E7-EXT-03': 64,
    },
    authorizationUsage: null,
    targetValuesCaptured: false,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const usage = (usageId, requestCounts = {}) => ({
    schemaVersion: 1,
    usageId,
    bundleSha256: authorizationSha256,
    candidateSha,
    releaseId: freezeManifest.releaseId,
    configSha256: objectSha256(config),
    ownedOriginSha256: authorization.ownedOriginSha256,
    sandboxHostSha256: authorization.sandboxHostSha256,
    requestCounts: Object.fromEntries(AUTHORIZATION_IDS.map((id) => [id, requestCounts[id] ?? 0])),
  });
  authorization.authorizationUsage = usage('EXTERNAL_AUTHORIZATION_PREFLIGHT');
  documents.externalAuthorizationEvidence = selfTestDocument(authorization);
  const activationValue = JSON.parse(documents.activationEvidence.content);
  activationValue.checkpoints.activation.transitions = [
    { authorizationUsage: usage('ACTIVATION_CANDIDATE') },
    { authorizationUsage: usage('ACTIVATION_REPROMOTION') },
  ];
  documents.activationEvidence = selfTestDocument(activationValue);
  const authorizationSourceDocument = (kind, usageId) =>
    selfTestDocument({
      schemaVersion: 1,
      stage: 7,
      kind,
      status: 'PASS',
      candidateSha,
      releaseId: freezeManifest.releaseId,
      authorizationUsage: usage(usageId),
      containsSensitiveData: false,
    });
  const authorizationSources = {
    smokeInput: authorizationSourceDocument(
      'PRIVATE_SMOKE_INPUT_PREFLIGHT',
      'SMOKE_INPUT_PREFLIGHT_CANDIDATE',
    ),
    smoke: authorizationSourceDocument('DEPLOYED_SMOKE', 'SMOKE_POST_DEPLOY'),
    quality: authorizationSourceDocument('DEPLOYED_FOCAL_QUALITY', 'QUALITY_FOCAL'),
    edge: authorizationSourceDocument('EDGE_SECURITY', 'EDGE_PASSIVE'),
    sandbox: authorizationSourceDocument('SANDBOX_SMOKE', 'SANDBOX_ONE_USE'),
    rollbackSmokeInput: authorizationSourceDocument(
      'PRIVATE_SMOKE_INPUT_PREFLIGHT',
      'ROLLBACK_PENDING_INPUT_PREFLIGHT',
    ),
    pendingProducer: authorizationSourceDocument(
      'VERSIONED_ROLLBACK_PENDING_PRODUCER',
      'RB_E7_05_PENDING_PRODUCER',
    ),
    rollbackSmoke: authorizationSourceDocument(
      'DEPLOYED_BLACK_BOX_SMOKE',
      'POST_ROLLBACK_VERSIONED',
    ),
    repromotionSmoke: authorizationSourceDocument(
      'DEPLOYED_BLACK_BOX_SMOKE',
      'POST_REPROMOTION_VERSIONED',
    ),
  };
  const priorSources = [
    [
      'external-authorization.json',
      documents.externalAuthorizationEvidence,
      authorization.authorizationUsage,
    ],
    [
      'smoke-input-preflight.json',
      authorizationSources.smokeInput,
      usage('SMOKE_INPUT_PREFLIGHT_CANDIDATE'),
    ],
    ['activation.json', documents.activationEvidence, usage('ACTIVATION_CANDIDATE')],
    ['smoke.json', authorizationSources.smoke, usage('SMOKE_POST_DEPLOY')],
    ['quality.json', authorizationSources.quality, usage('QUALITY_FOCAL')],
    ['edge-security.json', authorizationSources.edge, usage('EDGE_PASSIVE')],
    ['sandbox-smoke.json', authorizationSources.sandbox, usage('SANDBOX_ONE_USE')],
    [
      'rollback-smoke-input-preflight.json',
      authorizationSources.rollbackSmokeInput,
      usage('ROLLBACK_PENDING_INPUT_PREFLIGHT'),
    ],
    [
      'rollback-pending-producer.json',
      authorizationSources.pendingProducer,
      usage('RB_E7_05_PENDING_PRODUCER'),
    ],
    [
      'versioned-rollback-smoke.json',
      authorizationSources.rollbackSmoke,
      usage('POST_ROLLBACK_VERSIONED'),
    ],
    ['activation.json', documents.activationEvidence, usage('ACTIVATION_REPROMOTION')],
    [
      'versioned-repromotion-smoke.json',
      authorizationSources.repromotionSmoke,
      usage('POST_REPROMOTION_VERSIONED'),
    ],
  ];
  const priorUsages = priorSources.map(([basename, document, value]) => {
    return {
      basename,
      rawSha256: document.sha256,
      objectSha256: objectSha256(JSON.parse(document.content)),
      usageId: value.usageId,
      usageSha256: objectSha256(value),
      requestCounts: value.requestCounts,
    };
  });
  const reservedUsage = usage('ROLLBACK_RESILIENCE', { 'AUTH-E7-EXT-01': 11 });
  const zeroTotals = Object.fromEntries(AUTHORIZATION_IDS.map((id) => [id, 0]));
  const finalTotals = { ...zeroTotals, 'AUTH-E7-EXT-01': 11 };
  const budgetBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_AUTHORIZATION_BUDGET',
    status: 'RESERVED_BEFORE_EXTERNAL_REQUESTS',
    candidateSha,
    releaseId: freezeManifest.releaseId,
    configSha256: objectSha256(config),
    externalAuthorizationEvidenceSha256: documents.externalAuthorizationEvidence.sha256,
    externalAuthorizationObjectSha256: objectSha256(authorization),
    authorizationSha256,
    authorizationIds: AUTHORIZATION_IDS,
    requestLimits: authorization.requestLimits,
    priorUsages,
    priorTotals: zeroTotals,
    reservedUsage,
    finalTotals,
    reservedExternalRequests: 11,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  documents.authorizationBudget = selfTestDocument({
    ...budgetBody,
    budgetSha256: objectSha256(budgetBody),
  });
  const candidateObjects = previousObjects.map((entry, index) => ({
    ...entry,
    versionId: `candidate-${index + 1}-version`,
    etagSha256: String(index + 2).repeat(64),
    contentSha256: String(index + 6).repeat(64),
  }));
  const candidateRecord = createStage7CandidateRollbackRecord({
    previousManifest: previousReleaseManifest,
    createdAtUtc: '2026-08-17T11:05:00.000Z',
    approvalSha256: documents.approval.sha256,
    planSha256: documents.approvedPlan.sha256,
    deploymentEvidenceSha256: documents.deploymentEvidence.sha256,
    resources: {
      api: {
        ...previousReleaseManifest.resources.api,
        version: '8',
        codeSha256: 'b'.repeat(64),
      },
      worker: {
        ...previousReleaseManifest.resources.worker,
        version: '12',
        codeSha256: 'c'.repeat(64),
      },
      web: { ...previousReleaseManifest.resources.web, objects: candidateObjects },
    },
  });
  const pending = {
    observedAtUtc: '2026-08-17T11:06:00.000Z',
    trackedCount: 1,
    oldestAgeSeconds: 30,
    snapshotSha256: 'd'.repeat(64),
  };
  const dataFactsSha256 = 'f'.repeat(64);
  const observed = (resources) => ({
    api: {
      functionName: resources.api.functionName,
      aliasName: resources.api.aliasName,
      version: resources.api.version,
    },
    worker: {
      functionName: resources.worker.functionName,
      aliasName: resources.worker.aliasName,
      version: resources.worker.version,
    },
    web: {
      bucketName: resources.web.bucketName,
      distributionId: resources.web.distributionId,
      objects: resources.web.objects.map(({ key, versionId, contentSha256 }) => ({
        key,
        versionId,
        contentSha256,
      })),
    },
    pending,
    dataFactsSha256,
  });
  const rollbackPlan = createStage7VersionedRollbackPlan({
    direction: 'ROLLBACK_TO_PREVIOUS',
    previousManifest: previousReleaseManifest,
    candidateRecord,
    currentState: observed(candidateRecord.resources),
  });
  const rollbackCheckpoint = selfTestCheckpoint({
    plan: rollbackPlan,
    destination: previousReleaseManifest.resources,
    startedAtUtc: '2026-08-17T11:10:00.000Z',
    completedAtUtc: '2026-08-17T11:11:00.000Z',
  });
  const repromotionPlan = createStage7VersionedRollbackPlan({
    direction: 'REPROMOTE_CANDIDATE',
    previousManifest: previousReleaseManifest,
    candidateRecord,
    currentState: observed(previousReleaseManifest.resources),
  });
  const repromotionCheckpoint = selfTestCheckpoint({
    plan: repromotionPlan,
    destination: candidateRecord.resources,
    startedAtUtc: '2026-08-17T11:12:00.000Z',
    completedAtUtc: '2026-08-17T11:13:00.000Z',
  });
  const baseRehearsal = createStage7VersionedRollbackRehearsal({
    previousManifest: previousReleaseManifest,
    candidateRecord,
    rollbackPlan,
    rollbackCheckpoint,
    repromotionPlan,
    repromotionCheckpoint,
  });
  const execution = {
    mode: 'LOCAL_SIMULATION',
    repository: REPOSITORY,
    workflow: 'rollback-resilience-self-test',
    runId: '123456789',
    runAttempt: '1',
    githubActions: false,
    githubRef: 'refs/heads/test',
    githubSha: candidateSha,
    protectedEnvironment: 'LOCAL_SELF_TEST',
    accountId: config.aws.accountId,
    region: config.aws.region,
    roleArn: null,
    startedAtUtc: '2026-08-17T11:00:00.000Z',
  };
  const inputs = {
    config,
    freezeManifest,
    previousReleaseManifest,
    candidateRecord,
    baseRehearsal,
    documents,
    journalCleanupRoleArn: 'arn:aws:iam::123456789012:role/stage7-release-journal-cleanup',
    execution,
  };
  return {
    inputs,
    observabilityTemplate: selfTestObservabilityTemplate(),
    observabilityTemplateSha256,
    alarmName,
    alarmArn,
    authorizationSources,
  };
};

export const createRollbackResilienceSelfTestFixture = selfTestInputs;

const memoryStateStore = (interruptPhase = null) => {
  const values = new Map();
  let interrupted = false;
  return {
    async load(scenarioId) {
      const value = values.get(scenarioId);
      return value === undefined ? null : JSON.parse(JSON.stringify(value));
    },
    async save(scenarioId, value) {
      values.set(scenarioId, JSON.parse(JSON.stringify(value)));
      if (!interrupted && value.phase === interruptPhase) {
        interrupted = true;
        const error = new Error('SELF_TEST_INTERRUPT');
        error.code = 'SELF_TEST_INTERRUPT';
        throw error;
      }
    },
    size() {
      return values.size;
    },
  };
};

const scriptedExecutor = (steps, { startSecond = 1 } = {}) => {
  let calls = 0;
  const executor = async (request) => {
    const step = steps.shift();
    assert.ok(step, `unexpected executor call ${request.service}.${request.operation}`);
    assert.equal(request.service, step.service);
    assert.equal(request.operation, step.operation);
    calls += 1;
    return {
      source: request.service.startsWith('stage7-')
        ? 'DEPLOYED_OBSERVATION_RESPONSE'
        : 'AWS_SDK_RESPONSE',
      requestId: `self-test-request-${String(startSecond + calls).padStart(6, '0')}`,
      observedAtUtc: `2026-08-17T11:${String(Math.floor((startSecond + calls) / 60)).padStart(2, '0')}:${String((startSecond + calls) % 60).padStart(2, '0')}.000Z`,
      payload: typeof step.payload === 'function' ? step.payload(request) : step.payload,
    };
  };
  executor.calls = () => calls;
  executor.remaining = () => steps.length;
  return executor;
};

const selfTestPending = ({ before, rehearsal }) => ({
  status: before ? 'PENDING_OBSERVED' : 'PASS',
  trackedBefore: rehearsal.rollback.plan.pendingBaseline.trackedCount,
  stillPending: 1,
  reconciled: 0,
  orphaned: 0,
  duplicateEffects: 0,
  lostFacts: 0,
  snapshotSha256: rehearsal.rollback.plan.pendingBaseline.snapshotSha256,
  baselineEvidenceSha256: rehearsal.rollback.plan.pendingBaseline.snapshotSha256,
  correlationEvidenceSha256: '2'.repeat(64),
  dataFactsSha256: rehearsal.rollback.plan.dataFactsSha256,
  dataRollbackPerformed: false,
});

const selfTestSmoke = (releaseId, digest = '3') => ({
  status: 'PASS',
  releaseId,
  total: 3,
  passed: 3,
  failed: 0,
  dataMutations: 0,
  externalRequests: 3,
  authorizationUsageId: 'ROLLBACK_RESILIENCE',
  evidenceSha256: digest.repeat(64),
});

const selfTestOriginProtection = ({ inputs, runtimeSecretReferenceSha256 }) => {
  const body = {
    status: 'PASS',
    candidateReleaseId: inputs.freezeManifest.releaseId,
    previousReleaseId: inputs.previousReleaseManifest.previous.releaseId,
    headerNameSha256: sha256('x-stage7-origin-verify'),
    candidateSecretReferenceSha256: runtimeSecretReferenceSha256,
    previousSecretReferenceSha256: runtimeSecretReferenceSha256,
    candidateSecretVersionIdSha256: '4'.repeat(64),
    previousSecretVersionIdSha256: '4'.repeat(64),
    candidateContractSha256: '5'.repeat(64),
    previousContractSha256: '5'.repeat(64),
    candidateDirectApiStatus: 403,
    previousDirectApiStatus: 403,
    candidateViaCloudFrontStatus: 200,
    previousViaCloudFrontStatus: 200,
    externalRequests: 1,
    authorizationUsageId: 'ROLLBACK_RESILIENCE',
  };
  return { ...body, evidenceSha256: objectSha256(body) };
};

const selfTestStack = ({ inputs, descriptor, status, events = [] }) => ({
  stack: {
    stackName: descriptor.stackName,
    stackId: `arn:aws:cloudformation:${inputs.config.aws.region}:${inputs.config.aws.accountId}:stack/${descriptor.stackName}/12345678-1234-1234-1234-123456789012`,
    stackStatus: status,
    parameters: [{ key: 'PublicationState', value: 'ENABLED' }],
    capabilities: ['CAPABILITY_IAM'],
    roleArn: cloudFormationExecutionRoleArn(inputs),
    tags: [
      { key: 'CandidateSha', value: inputs.freezeManifest.candidateSha },
      { key: 'ReleaseId', value: inputs.freezeManifest.releaseId },
      { key: 'Environment', value: inputs.config.environment },
      { key: 'ManagedBy', value: 'cdk' },
    ],
  },
  events,
});

const selfTestEvent = ({ token, status, logicalId, type, second, reason = null }) => ({
  eventId: `event-${second}-${status.toLowerCase()}`,
  timestamp: `2026-08-17T11:01:${String(second).padStart(2, '0')}.000Z`,
  logicalResourceId: logicalId,
  resourceType: type,
  resourceStatus: status,
  resourceStatusReason: reason,
  clientRequestToken: token,
});

const selfTestAlarm = ({ descriptor, state, stateUpdatedAtUtc, datapointAtUtc, value }) => ({
  alarmName: descriptor.alarmName,
  alarmArn: descriptor.alarmArn,
  stateValue: state,
  stateUpdatedAtUtc,
  stateReason:
    state === 'ALARM'
      ? 'Threshold Crossed: one datapoint reached the rehearsal threshold.'
      : 'Rehearsal metric remains within the configured threshold.',
  stateReasonData: {
    queryDate: stateUpdatedAtUtc,
    recentDatapoints: [{ timestamp: datapointAtUtc, value }],
    threshold: descriptor.threshold,
  },
  namespace: descriptor.metricNamespace,
  metricName: descriptor.metricName,
  dimensions: descriptor.dimensions,
  statistic: descriptor.statistic,
  unit: descriptor.unit,
  periodSeconds: descriptor.periodSeconds,
  evaluationPeriods: descriptor.evaluationPeriods,
  threshold: descriptor.threshold,
  comparisonOperator: descriptor.comparisonOperator,
  treatMissingData: descriptor.treatMissingData,
  actionsEnabled: descriptor.actionsEnabled,
  alarmActions: descriptor.alarmActions,
  okActions: descriptor.okActions,
  insufficientDataActions: descriptor.insufficientDataActions,
});

const selfTestAlias = (resource, version, revision) => ({
  functionName: resource.functionName,
  aliasName: resource.aliasName,
  functionVersion: version,
  revisionId: `revision-${revision}-value`,
});

const selfTestObject = ({ bucketName, entry, activeVersionId }) => ({
  bucketName,
  key: entry.key,
  activeVersionId,
  sourceVersionId: entry.versionId,
  contentSha256: entry.contentSha256,
  bytes: entry.bytes,
});

export const selfTestRollbackResilienceProducer = async () => {
  const protectedRuntimeSelfTest = selfTestProtectedRollbackRuntime();
  assert.equal(protectedRuntimeSelfTest.status, 'PASS');
  assert.equal(protectedRuntimeSelfTest.externalRequests, 0);
  for (const [filename, expectedId] of [
    [
      'rollback-resilience-evidence.schema.json',
      'https://checkout.example.invalid/schemas/stage7/rollback-resilience-evidence.schema.json',
    ],
    [
      'rollback-resilience-journal.schema.json',
      'https://checkout.example.invalid/schemas/stage7/rollback-resilience-journal.schema.json',
    ],
  ]) {
    const schema = JSON.parse(readFileSync(new URL(filename, import.meta.url), 'utf8'));
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
    assert.equal(schema.$id, expectedId);
  }
  const { inputs, observabilityTemplateSha256, alarmName, alarmArn } = selfTestInputs();
  assert.ok(SHA.test(inputs.freezeManifest.candidateSha));
  assert.ok(RELEASE_ID.test(inputs.freezeManifest.releaseId));
  assert.ok(AWS_REGION.test(inputs.config.aws.region));
  const runtimeSecretReferenceSha256 = sha256(inputs.config.credentialReferences[0]);
  const rb06Descriptor = {
    stackName: expectedStage7Stacks(inputs.config.environment)[2],
    failureLogicalResourceId: FAILURE_LOGICAL_ID,
    failureResourceType: FAILURE_RESOURCE_TYPE,
    failureTimeoutSeconds: 60,
    frozenTemplateSha256: observabilityTemplateSha256,
    cloudFormationExecutionRoleArn: cloudFormationExecutionRoleArn(inputs),
    runtimeSecretReferenceSha256,
    maxPolls: 10,
  };
  const { binding, parsedDocuments } = validateBoundInputs(inputs);
  const checkedRb06 = validateRb06Descriptor(rb06Descriptor, {
    inputs,
    binding,
    parsedDocuments,
  });
  const clientRequestToken = `e7rb06-${binding.bindingSha256.slice(0, 24)}-${inputs.execution.runId}`;
  const liveTemplate = selfTestObservabilityTemplate();
  const derivedTemplate = deriveFailureTemplate(liveTemplate, checkedRb06);
  const stackId = `arn:aws:cloudformation:${inputs.config.aws.region}:${inputs.config.aws.accountId}:stack/${checkedRb06.stackName}/12345678-1234-1234-1234-123456789012`;
  const changeSetId = `arn:aws:cloudformation:${inputs.config.aws.region}:${inputs.config.aws.accountId}:changeSet/${checkedRb06.changeSetName}/12345678-1234-1234-1234-123456789012`;
  const updateEvent = selfTestEvent({
    descriptor: checkedRb06,
    token: clientRequestToken,
    status: 'UPDATE_IN_PROGRESS',
    logicalId: checkedRb06.stackName,
    type: 'AWS::CloudFormation::Stack',
    second: 10,
  });
  const failureEvent = selfTestEvent({
    descriptor: checkedRb06,
    token: clientRequestToken,
    status: 'CREATE_FAILED',
    logicalId: FAILURE_LOGICAL_ID,
    type: FAILURE_RESOURCE_TYPE,
    second: 20,
    reason: 'WaitCondition timed out without the deliberately omitted signal.',
  });
  const rollbackEvent = selfTestEvent({
    descriptor: checkedRb06,
    token: clientRequestToken,
    status: 'UPDATE_ROLLBACK_IN_PROGRESS',
    logicalId: checkedRb06.stackName,
    type: 'AWS::CloudFormation::Stack',
    second: 21,
  });
  const completeEvent = selfTestEvent({
    descriptor: checkedRb06,
    token: clientRequestToken,
    status: 'UPDATE_ROLLBACK_COMPLETE',
    logicalId: checkedRb06.stackName,
    type: 'AWS::CloudFormation::Stack',
    second: 30,
  });
  const rb06Steps = [
    {
      service: 'cloudformation',
      operation: 'DescribeStacks',
      payload: selfTestStack({
        inputs,
        descriptor: checkedRb06,
        status: 'UPDATE_COMPLETE',
      }),
    },
    {
      service: 'cloudformation',
      operation: 'GetTemplate',
      payload: { templateBody: liveTemplate },
    },
    {
      service: 'cloudformation',
      operation: 'CreateChangeSet',
      payload: { changeSetId, stackId },
    },
    {
      service: 'cloudformation',
      operation: 'DescribeChangeSet',
      payload: {
        changeSetId,
        changeSetName: checkedRb06.changeSetName,
        stackName: checkedRb06.stackName,
        stackId,
        status: 'CREATE_COMPLETE',
        executionStatus: 'AVAILABLE',
        changeSetType: 'UPDATE',
        description: checkedRb06.description,
        includeNestedStacks: false,
        templateSha256: objectSha256(derivedTemplate),
        parameters: [{ key: 'PublicationState', value: 'ENABLED' }],
        capabilities: ['CAPABILITY_IAM'],
        roleArn: cloudFormationExecutionRoleArn(inputs),
        changes: [
          {
            action: 'Add',
            logicalResourceId: FAILURE_LOGICAL_ID,
            resourceType: FAILURE_RESOURCE_TYPE,
            replacement: 'False',
          },
        ],
      },
    },
    {
      service: 'cloudformation',
      operation: 'GetTemplateForChangeSet',
      payload: { templateBody: derivedTemplate },
    },
    {
      service: 'stage7-pending-integrity',
      operation: 'ReadBeforeFailureMutation',
      payload: selfTestPending({ before: true, rehearsal: inputs.baseRehearsal }),
    },
    {
      service: 'stage7-origin-protection',
      operation: 'VerifyNAndNMinus1Compatibility',
      payload: selfTestOriginProtection({ inputs, runtimeSecretReferenceSha256 }),
    },
    {
      service: 'cloudformation',
      operation: 'DescribeStackEvents',
      payload: selfTestStack({
        inputs,
        descriptor: checkedRb06,
        status: 'UPDATE_COMPLETE',
      }),
    },
    { service: 'cloudformation', operation: 'ExecuteChangeSet', payload: {} },
    {
      service: 'cloudformation',
      operation: 'DescribeStackEvents',
      payload: selfTestStack({
        inputs,
        descriptor: checkedRb06,
        status: 'UPDATE_IN_PROGRESS',
        events: [updateEvent],
      }),
    },
    {
      service: 'cloudformation',
      operation: 'DescribeStackEvents',
      payload: selfTestStack({
        inputs,
        descriptor: checkedRb06,
        status: 'UPDATE_ROLLBACK_IN_PROGRESS',
        events: [failureEvent, rollbackEvent],
      }),
    },
    {
      service: 'cloudformation',
      operation: 'DescribeStackEvents',
      payload: selfTestStack({
        inputs,
        descriptor: checkedRb06,
        status: 'UPDATE_ROLLBACK_COMPLETE',
        events: [failureEvent, completeEvent],
      }),
    },
    {
      service: 'stage7-pending-integrity',
      operation: 'ReadAfterCloudFormationRecovery',
      payload: selfTestPending({ before: false, rehearsal: inputs.baseRehearsal }),
    },
    {
      service: 'stage7-read-smoke',
      operation: 'RunAfterCloudFormationRecovery',
      payload: selfTestSmoke(inputs.freezeManifest.releaseId),
    },
  ];
  const rb06Executor = scriptedExecutor(rb06Steps, { startSecond: 1 });
  const rb06Store = memoryStateStore('FAILURE_OBSERVED');
  await assert.rejects(
    produceRbE706({
      inputs,
      descriptor: rb06Descriptor,
      executor: rb06Executor,
      stateStore: rb06Store,
      capability: SELF_TEST_EXECUTOR_CAPABILITY,
    }),
    (error) => error.code === 'SELF_TEST_INTERRUPT',
  );
  const rb06 = await produceRbE706({
    inputs,
    descriptor: rb06Descriptor,
    executor: rb06Executor,
    stateStore: rb06Store,
    capability: SELF_TEST_EXECUTOR_CAPABILITY,
  });
  assert.equal(rb06.status, 'BLOCKED_REAL_AWS_REQUIRED');
  assert.equal(rb06.recovery.resumptions, 1);
  assert.equal(rb06.recovery.continueUpdateRollbackInvoked, false);
  assert.equal(rb06.pendingIntegrity.orphaned, 0);
  assert.equal(rb06Executor.remaining(), 0);
  const rb06Calls = rb06Executor.calls();
  assert.deepEqual(
    await produceRbE706({
      inputs,
      descriptor: rb06Descriptor,
      executor: rb06Executor,
      stateStore: rb06Store,
      capability: SELF_TEST_EXECUTOR_CAPABILITY,
    }),
    rb06,
  );
  assert.equal(rb06Executor.calls(), rb06Calls, 'completed retry must perform no calls');

  const dimensions = [
    { name: 'Environment', value: inputs.config.environment },
    { name: 'ReleaseId', value: inputs.freezeManifest.releaseId },
    { name: 'Scenario', value: 'RB-E7-08' },
  ];
  const rb08Descriptor = {
    alarmName,
    alarmArn,
    observabilityStackName: expectedStage7Stacks(inputs.config.environment)[2],
    observabilityTemplateSha256,
    metricNamespace: 'Checkout/Stage7Rehearsal',
    metricName: 'RollbackRehearsalFailure',
    dimensions,
    statistic: 'Maximum',
    unit: 'Count',
    periodSeconds: 60,
    evaluationPeriods: 1,
    threshold: 1,
    comparisonOperator: 'GreaterThanOrEqualToThreshold',
    treatMissingData: 'notBreaching',
    actionsEnabled: false,
    alarmActions: [],
    okActions: [],
    insufficientDataActions: [],
    activationAtUtc: '2026-08-17T11:00:00.000Z',
    runtimeSecretReferenceSha256,
    maxPolls: 10,
  };
  const protectedInputsWithoutExecution = { ...inputs };
  delete protectedInputsWithoutExecution.execution;
  const protectedOptions = {
    inputsWithoutExecution: protectedInputsWithoutExecution,
    rb06Descriptor,
    rb08Descriptor,
  };
  assert.equal(validateProtectedRollbackOptions(protectedOptions), protectedOptions);
  const missingJournalRole = { ...protectedInputsWithoutExecution };
  delete missingJournalRole.journalCleanupRoleArn;
  assert.throws(
    () =>
      validateProtectedRollbackOptions({
        inputsWithoutExecution: missingJournalRole,
        rb06Descriptor,
        rb08Descriptor,
      }),
    (error) => error.code === 'E7_RESILIENCE_PROTECTED_OPTIONS_INVALID',
  );
  const awsAuthAuxiliaryFixture = JSON.parse(inputs.documents.awsAuth.content);
  assert.equal(
    validateAwsAuthAuxiliaryRoleBindings({
      value: awsAuthAuxiliaryFixture,
      config: inputs.config,
      journalCleanupRoleArn: inputs.journalCleanupRoleArn,
    }),
    awsAuthAuxiliaryFixture,
  );
  const missingRecoveryBinding = { ...awsAuthAuxiliaryFixture };
  delete missingRecoveryBinding.reconciliationRecoveryRoleEffectivePermissionsSha256;
  assert.throws(
    () =>
      validateAwsAuthAuxiliaryRoleBindings({
        value: missingRecoveryBinding,
        config: inputs.config,
        journalCleanupRoleArn: inputs.journalCleanupRoleArn,
      }),
    (error) => error.code === 'E7_RESILIENCE_AWS_AUTH_AUXILIARY_ROLE_BINDING_INVALID',
  );
  assert.throws(
    () =>
      validateAwsAuthAuxiliaryRoleBindings({
        value: {
          ...awsAuthAuxiliaryFixture,
          reconciliationRecoveryRoleArn:
            'arn:aws:iam::210987654321:role/stage7-release-reconciliation-recovery',
        },
        config: inputs.config,
        journalCleanupRoleArn: inputs.journalCleanupRoleArn,
      }),
    (error) => error.code === 'E7_RESILIENCE_AWS_AUTH_AUXILIARY_ROLE_BINDING_INVALID',
  );
  const previous = inputs.previousReleaseManifest.resources;
  const candidate = inputs.candidateRecord.resources;
  const bucketName = previous.web.bucketName;
  const distributionId = previous.web.distributionId;
  const paths = previous.web.mutableInvalidationPaths;
  const rb08Steps = [
    {
      service: 'stage7-pending-integrity',
      operation: 'ReadBeforeAlarmDecision',
      payload: selfTestPending({ before: true, rehearsal: inputs.baseRehearsal }),
    },
    {
      service: 'stage7-origin-protection',
      operation: 'VerifyNAndNMinus1Compatibility',
      payload: selfTestOriginProtection({ inputs, runtimeSecretReferenceSha256 }),
    },
    {
      service: 'cloudwatch',
      operation: 'DescribeAlarmsBeforeActivation',
      payload: {
        metricAlarms: [
          selfTestAlarm({
            descriptor: rb08Descriptor,
            state: 'OK',
            stateUpdatedAtUtc: '2026-08-17T11:00:00.000Z',
            datapointAtUtc: '2026-08-17T11:00:00.000Z',
            value: 0,
          }),
        ],
      },
    },
    { service: 'cloudwatch', operation: 'PutMetricData', payload: {} },
    {
      service: 'cloudwatch',
      operation: 'DescribeAlarmsAfterActivation',
      payload: {
        metricAlarms: [
          selfTestAlarm({
            descriptor: rb08Descriptor,
            state: 'ALARM',
            stateUpdatedAtUtc: '2026-08-17T11:07:10.000Z',
            datapointAtUtc: '2026-08-17T11:07:00.000Z',
            value: 1,
          }),
        ],
      },
    },
    {
      service: 'lambda',
      operation: 'GetAlias',
      payload: selfTestAlias(candidate.api, candidate.api.version, 'api-candidate'),
    },
    {
      service: 'lambda',
      operation: 'UpdateAlias',
      payload: selfTestAlias(previous.api, previous.api.version, 'api-previous'),
    },
    {
      service: 'lambda',
      operation: 'GetAlias',
      payload: selfTestAlias(candidate.worker, candidate.worker.version, 'worker-candidate'),
    },
    {
      service: 'lambda',
      operation: 'UpdateAlias',
      payload: selfTestAlias(previous.worker, previous.worker.version, 'worker-previous'),
    },
    ...candidate.web.objects.flatMap((entry, index) => [
      {
        service: 'stage7-s3-integrity',
        operation: 'InspectActiveObject',
        payload: selfTestObject({
          bucketName,
          entry,
          activeVersionId: `candidate-active-${index + 1}`,
        }),
      },
      {
        service: 's3',
        operation: 'RestoreVersionedObject',
        payload: selfTestObject({
          bucketName,
          entry: previous.web.objects[index],
          activeVersionId: `rollback-active-${index + 1}`,
        }),
      },
    ]),
    {
      service: 'cloudfront',
      operation: 'CreateInvalidation',
      payload: (request) => ({
        distributionId,
        invalidationId: 'invalidation-rb08-rollback',
        callerReference: request.input.callerReference,
        paths,
        status: 'InProgress',
      }),
    },
    {
      service: 'cloudfront',
      operation: 'GetInvalidation',
      payload: (request) => ({
        distributionId,
        invalidationId: request.input.invalidationId,
        callerReference: `e7rb08-${binding.bindingSha256.slice(0, 24)}-${inputs.execution.runId}`,
        paths,
        status: 'Completed',
      }),
    },
    {
      service: 'stage7-pending-integrity',
      operation: 'ReadAfterAlarmRollback',
      payload: selfTestPending({ before: false, rehearsal: inputs.baseRehearsal }),
    },
    {
      service: 'stage7-read-smoke',
      operation: 'RunAfterAlarmRollback',
      payload: selfTestSmoke(inputs.previousReleaseManifest.previous.releaseId, '6'),
    },
    { service: 'cloudwatch', operation: 'PutRecoveryMetricData', payload: {} },
    {
      service: 'cloudwatch',
      operation: 'DescribeAlarmsAfterRollback',
      payload: {
        metricAlarms: [
          selfTestAlarm({
            descriptor: rb08Descriptor,
            state: 'OK',
            stateUpdatedAtUtc: '2026-08-17T11:09:00.000Z',
            datapointAtUtc: '2026-08-17T11:09:00.000Z',
            value: 0,
          }),
        ],
      },
    },
    {
      service: 'lambda',
      operation: 'GetAliasForRepromotion',
      payload: selfTestAlias(previous.api, previous.api.version, 'api-previous-2'),
    },
    {
      service: 'lambda',
      operation: 'UpdateAliasForRepromotion',
      payload: selfTestAlias(candidate.api, candidate.api.version, 'api-candidate-2'),
    },
    {
      service: 'lambda',
      operation: 'GetAliasForRepromotion',
      payload: selfTestAlias(previous.worker, previous.worker.version, 'worker-previous-2'),
    },
    {
      service: 'lambda',
      operation: 'UpdateAliasForRepromotion',
      payload: selfTestAlias(candidate.worker, candidate.worker.version, 'worker-candidate-2'),
    },
    ...previous.web.objects.flatMap((entry, index) => [
      {
        service: 'stage7-s3-integrity',
        operation: 'InspectActiveObjectForRepromotion',
        payload: selfTestObject({
          bucketName,
          entry,
          activeVersionId: `rollback-active-${index + 1}`,
        }),
      },
      {
        service: 's3',
        operation: 'RestoreVersionedObjectForRepromotion',
        payload: selfTestObject({
          bucketName,
          entry: candidate.web.objects[index],
          activeVersionId: `repromotion-active-${index + 1}`,
        }),
      },
    ]),
    {
      service: 'cloudfront',
      operation: 'CreateInvalidationForRepromotion',
      payload: (request) => ({
        distributionId,
        invalidationId: 'invalidation-rb08-repromotion',
        callerReference: request.input.callerReference,
        paths,
        status: 'Completed',
      }),
    },
    {
      service: 'stage7-read-smoke',
      operation: 'RunAfterAlarmRepromotion',
      payload: selfTestSmoke(inputs.freezeManifest.releaseId, '7'),
    },
    {
      service: 'stage7-pending-integrity',
      operation: 'ReadAfterAlarmRepromotion',
      payload: selfTestPending({ before: false, rehearsal: inputs.baseRehearsal }),
    },
  ];
  const rb08Executor = scriptedExecutor(rb08Steps, { startSecond: 420 });
  const rb08Store = memoryStateStore('NO_GO_DECISION_RECORDED');
  await assert.rejects(
    produceRbE708({
      inputs,
      descriptor: rb08Descriptor,
      executor: rb08Executor,
      stateStore: rb08Store,
      capability: SELF_TEST_EXECUTOR_CAPABILITY,
    }),
    (error) => error.code === 'SELF_TEST_INTERRUPT',
  );
  const rb08 = await produceRbE708({
    inputs,
    descriptor: rb08Descriptor,
    executor: rb08Executor,
    stateStore: rb08Store,
    capability: SELF_TEST_EXECUTOR_CAPABILITY,
  });
  assert.equal(rb08.status, 'BLOCKED_REAL_AWS_REQUIRED');
  assert.equal(rb08.decision.value, 'NO_GO_ROLLBACK');
  assert.equal(rb08.alarm.transition, 'OK_TO_ALARM_TO_OK');
  assert.equal(rb08.rollback.toReleaseId, inputs.previousReleaseManifest.previous.releaseId);
  assert.equal(rb08.repromotion.finalReleaseId, inputs.freezeManifest.releaseId);
  assert.equal(rb08.pendingIntegrity.orphaned, 0);
  assert.equal(rb08.dataRollbackPerformed, false);
  assert.equal(rb08.mutationCount, 12);
  assert.equal(rb08Executor.remaining(), 0);
  const rb08Calls = rb08Executor.calls();
  assert.deepEqual(
    await produceRbE708({
      inputs,
      descriptor: rb08Descriptor,
      executor: rb08Executor,
      stateStore: rb08Store,
      capability: SELF_TEST_EXECUTOR_CAPABILITY,
    }),
    rb08,
  );
  assert.equal(rb08Executor.calls(), rb08Calls, 'completed retry must perform no calls');

  const extension = createRollbackResilienceExtension({
    inputs,
    rb06Descriptor,
    rb08Descriptor,
    rb06Checkpoint: rb06,
    rb08Checkpoint: rb08,
  });
  assert.equal(extension.status, 'BLOCKED_REAL_AWS_REQUIRED');
  assert.equal(extension.gateE703, 'BLOCKED_REAL_AWS_REQUIRED');
  assert.deepEqual(extension.remainingScenarioIds, ['RB-E7-06', 'RB-E7-08']);

  const realExecution = {
    ...inputs.execution,
    mode: 'AWS_REAL',
    workflow: PROTECTED_WORKFLOW,
    githubActions: true,
    githubRef: 'refs/heads/master',
    protectedEnvironment: PROTECTED_ENVIRONMENT,
    roleArn: inputs.config.aws.roles.rollbackRoleArn,
  };
  const realInputs = { ...inputs, execution: realExecution };
  SELF_TEST_REAL_INPUTS.add(realInputs);
  const realBoundInputs = validateBoundInputs(realInputs);
  const realBinding = realBoundInputs.binding;
  const realCheckedRb06 = validateRb06Descriptor(rb06Descriptor, {
    inputs: realInputs,
    binding: realBinding,
    parsedDocuments: realBoundInputs.parsedDocuments,
  });
  const realCheckedRb08 = validateRb08Descriptor(rb08Descriptor, {
    inputs: realInputs,
    parsedDocuments: realBoundInputs.parsedDocuments,
  });
  const realCheckpoint = (checkpoint, checkedDescriptor) => {
    const body = {
      ...withoutDigest(checkpoint, 'checkpointSha256'),
      status: 'AWS_VERIFIED',
      gateEffect: 'ELIGIBLE_FOR_REHEARSAL_ADAPTER',
      executionMode: 'AWS_REAL',
      binding: realBinding,
      scenarioInputSha256: objectSha256(checkedDescriptor),
    };
    return { ...body, checkpointSha256: objectSha256(body) };
  };
  const realRb06 = realCheckpoint(rb06, realCheckedRb06);
  const realRb08 = realCheckpoint(rb08, realCheckedRb08);
  const realExtension = createRollbackResilienceExtension({
    inputs: realInputs,
    rb06Descriptor,
    rb08Descriptor,
    rb06Checkpoint: realRb06,
    rb08Checkpoint: realRb08,
    authority: PROTECTED_AWS_EVIDENCE_AUTHORITY,
  });
  const realCompletion = createRollbackResilienceCompletion({
    inputs: realInputs,
    extension: realExtension,
    rb06Checkpoint: realRb06,
    rb08Checkpoint: realRb08,
    journalLifecycle: createRollbackJournalLifecycle(realInputs),
    authority: PROTECTED_AWS_EVIDENCE_AUTHORITY,
  });
  const inputsWithoutExecution = withoutDigest(realInputs, 'execution');
  const runtimeIdentity = {
    accountSha256: sha256(inputs.config.aws.accountId),
    accountSuffix: inputs.config.aws.accountId.slice(-4),
    roleSha256: sha256(inputs.config.aws.roles.rollbackRoleArn),
    sessionArnSha256: '8'.repeat(64),
    observedAtUtc: '2026-08-17T11:00:01.000Z',
  };
  const runtimeAttestationBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_PROTECTED_RUNTIME_ATTESTATION',
    status: 'AWS_IDENTITY_REVALIDATED',
    repository: REPOSITORY,
    workflow: PROTECTED_WORKFLOW,
    runId: realExecution.runId,
    runAttempt: realExecution.runAttempt,
    githubSha: realExecution.githubSha,
    protectedEnvironment: PROTECTED_ENVIRONMENT,
    protectedBindingSha256: protectedBindingSha256({
      inputsWithoutExecution,
      execution: realExecution,
    }),
    executionSha256: objectSha256(realExecution),
    identity: runtimeIdentity,
    awsCliVersionSha256: sha256(inputs.freezeManifest.toolchain.awsCli),
    journalPrefixSha256: sha256(`/checkout/stage7/rollback/${inputs.freezeManifest.candidateSha}`),
    journalLifecycle: createRollbackJournalLifecycle(realInputs),
    stateBackend: 'SSM_APPEND_ONLY_HASH_CHAIN',
    executorConstruction: 'INTERNAL_AWS_CLI_ONLY',
    injectedExecutorAccepted: false,
    containsSensitiveData: false,
  };
  const runtimeAttestation = {
    ...runtimeAttestationBody,
    attestationSha256: objectSha256(runtimeAttestationBody),
  };
  const protectedRunBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PROTECTED_ROLLBACK_RESILIENCE_RUN',
    status: 'AWS_VERIFIED',
    executionSha256: objectSha256(realExecution),
    runtimeAttestation,
    rb06Checkpoint: realRb06,
    rb08Checkpoint: realRb08,
    extension: realExtension,
    completion: realCompletion,
    gateE703: 'ELIGIBLE_PENDING_RELEASE_CLOSEOUT',
    containsSensitiveData: false,
  };
  const protectedRun = { ...protectedRunBody, runSha256: objectSha256(protectedRunBody) };
  const publicValidationContext = {
    inputsWithoutExecution,
    rb06Descriptor,
    rb08Descriptor,
  };
  assert.equal(
    validatePublicProtectedRollbackResilienceRunInternal(
      {
        run: protectedRun,
        ...publicValidationContext,
      },
      SELF_TEST_EXECUTOR_CAPABILITY,
    ).runSha256,
    protectedRun.runSha256,
  );
  const resealRunWithRb06 = (rb06Checkpoint) => {
    const extensionBody = {
      ...withoutDigest(realExtension, 'extensionSha256'),
      rb06CheckpointSha256: rb06Checkpoint.checkpointSha256,
    };
    const changedExtension = {
      ...extensionBody,
      extensionSha256: objectSha256(extensionBody),
    };
    const completionBody = {
      ...withoutDigest(realCompletion, 'completionSha256'),
      rb06CheckpointSha256: rb06Checkpoint.checkpointSha256,
      extensionSha256: changedExtension.extensionSha256,
    };
    const changedCompletion = {
      ...completionBody,
      completionSha256: objectSha256(completionBody),
    };
    const runBody = {
      ...withoutDigest(protectedRun, 'runSha256'),
      rb06Checkpoint,
      extension: changedExtension,
      completion: changedCompletion,
    };
    return { ...runBody, runSha256: objectSha256(runBody) };
  };
  const rb06WithNestedExtraBody = {
    ...withoutDigest(realRb06, 'checkpointSha256'),
    failure: { ...realRb06.failure, fabricated: false },
  };
  assert.throws(
    () =>
      validatePublicProtectedRollbackResilienceRunInternal(
        {
          run: resealRunWithRb06({
            ...rb06WithNestedExtraBody,
            checkpointSha256: objectSha256(rb06WithNestedExtraBody),
          }),
          ...publicValidationContext,
        },
        SELF_TEST_EXECUTOR_CAPABILITY,
      ),
    (error) => error.code === 'E7_RB06_CHECKPOINT_INVALID',
  );
  const rb06WithFabricatedObservationBody = {
    ...withoutDigest(realRb06, 'checkpointSha256'),
    failure: { ...realRb06.failure, failureObserved: false },
  };
  assert.throws(
    () =>
      validatePublicProtectedRollbackResilienceRunInternal(
        {
          run: resealRunWithRb06({
            ...rb06WithFabricatedObservationBody,
            checkpointSha256: objectSha256(rb06WithFabricatedObservationBody),
          }),
          ...publicValidationContext,
        },
        SELF_TEST_EXECUTOR_CAPABILITY,
      ),
    (error) => error.code === 'E7_RB06_CHECKPOINT_INVALID',
  );
  const extraAttestationBody = {
    ...withoutDigest(runtimeAttestation, 'attestationSha256'),
    fabricated: false,
  };
  const extraAttestation = {
    ...extraAttestationBody,
    attestationSha256: objectSha256(extraAttestationBody),
  };
  const extraAttestationRunBody = {
    ...withoutDigest(protectedRun, 'runSha256'),
    runtimeAttestation: extraAttestation,
  };
  assert.throws(
    () =>
      validatePublicProtectedRollbackResilienceRunInternal(
        {
          run: {
            ...extraAttestationRunBody,
            runSha256: objectSha256(extraAttestationRunBody),
          },
          ...publicValidationContext,
        },
        SELF_TEST_EXECUTOR_CAPABILITY,
      ),
    (error) => error.code === 'E7_RESILIENCE_RUNTIME_ATTESTATION_INVALID',
  );
  const staleLifecycleBody = {
    ...withoutDigest(runtimeAttestation.journalLifecycle, 'lifecycleSha256'),
    cleanupAttempted: true,
  };
  const staleLifecycle = {
    ...staleLifecycleBody,
    lifecycleSha256: objectSha256(staleLifecycleBody),
  };
  const staleLifecycleAttestationBody = {
    ...withoutDigest(runtimeAttestation, 'attestationSha256'),
    journalLifecycle: staleLifecycle,
  };
  const staleLifecycleRunBody = {
    ...withoutDigest(protectedRun, 'runSha256'),
    runtimeAttestation: {
      ...staleLifecycleAttestationBody,
      attestationSha256: objectSha256(staleLifecycleAttestationBody),
    },
  };
  assert.throws(
    () =>
      validatePublicProtectedRollbackResilienceRunInternal(
        {
          run: {
            ...staleLifecycleRunBody,
            runSha256: objectSha256(staleLifecycleRunBody),
          },
          ...publicValidationContext,
        },
        SELF_TEST_EXECUTOR_CAPABILITY,
      ),
    (error) => error.code === 'E7_PROTECTED_SSM_LIFECYCLE_INVALID',
  );

  const tamperedInputs = {
    ...inputs,
    documents: {
      ...inputs.documents,
      approval: { ...inputs.documents.approval, content: `${inputs.documents.approval.content} ` },
    },
  };
  let callsBeforeValidation = 0;
  await assert.rejects(
    produceRbE706({
      inputs: tamperedInputs,
      descriptor: rb06Descriptor,
      executor: async () => {
        callsBeforeValidation += 1;
        return {};
      },
      stateStore: memoryStateStore(),
      capability: SELF_TEST_EXECUTOR_CAPABILITY,
    }),
    (error) => error.code === 'E7_RESILIENCE_APPROVAL_DOCUMENT_INVALID',
  );
  assert.equal(callsBeforeValidation, 0, 'binding tamper must fail before executor');
  await assert.rejects(
    produceRbE706({
      inputs,
      descriptor: rb06Descriptor,
      executor: async () => ({}),
      stateStore: memoryStateStore(),
      capability: PROTECTED_AWS_EXECUTOR_CAPABILITY,
    }),
    (error) => error.code === 'E7_RESILIENCE_EXECUTOR_CAPABILITY_INVALID',
  );
  const forgedRealInputs = {
    ...inputs,
    execution: {
      ...inputs.execution,
      mode: 'AWS_REAL',
      workflow: 'stage7-rollback-resilience.yml',
      githubActions: true,
      githubRef: 'refs/heads/master',
      protectedEnvironment: 'assessment-release-recovery',
      roleArn: inputs.config.aws.roles.rollbackRoleArn,
    },
  };
  assert.throws(
    () =>
      validateRbE706Checkpoint(rb06, {
        inputs: forgedRealInputs,
        descriptor: rb06Descriptor,
      }),
    (error) => error.code === 'E7_RESILIENCE_AWS_EVIDENCE_AUTHORITY_REQUIRED',
  );
  assert.throws(
    () =>
      validateRbE708Checkpoint(
        {
          ...rb08,
          status: 'AWS_VERIFIED',
          checkpointSha256: objectSha256({
            ...withoutDigest(rb08, 'checkpointSha256'),
            status: 'AWS_VERIFIED',
          }),
        },
        { inputs, descriptor: rb08Descriptor },
      ),
    (error) => error.code === 'E7_RB08_CHECKPOINT_INVALID',
  );
  const driftedOrigin = selfTestOriginProtection({ inputs, runtimeSecretReferenceSha256 });
  driftedOrigin.previousContractSha256 = '0'.repeat(64);
  driftedOrigin.evidenceSha256 = objectSha256(originProtectionBody(driftedOrigin));
  assert.throws(
    () => validateOriginProtection(driftedOrigin, { inputs, runtimeSecretReferenceSha256 }),
    (error) => error.code === 'E7_RESILIENCE_ORIGIN_PROTECTION_DRIFT',
  );
  assert.throws(
    () =>
      validateRb06Descriptor(
        {
          ...rb06Descriptor,
          cloudFormationExecutionRoleArn: inputs.config.aws.roles.deployRoleArn,
        },
        { inputs, binding, parsedDocuments },
      ),
    (error) => error.code === 'E7_RB06_DESCRIPTOR_INVALID',
  );
  assert.throws(
    () =>
      validateRb06Descriptor(
        { ...rb06Descriptor, frozenTemplateSha256: '0'.repeat(64) },
        { inputs, binding, parsedDocuments },
      ),
    (error) => error.code === 'E7_RB06_DESCRIPTOR_INVALID',
  );
  assert.throws(
    () =>
      validateRb08Descriptor(
        { ...rb08Descriptor, alarmName: `${rb08Descriptor.alarmName}-sibling` },
        { inputs, parsedDocuments },
      ),
    (error) => error.code === 'E7_RB08_DESCRIPTOR_INVALID',
  );
  assert.throws(
    () =>
      validateRb08Descriptor(
        { ...rb08Descriptor, alarmActions: ['arn:aws:sns:us-east-1:123456789012:forbidden'] },
        { inputs, parsedDocuments },
      ),
    (error) => error.code === 'E7_RB08_DESCRIPTOR_INVALID',
  );
  return {
    status: 'PASS',
    canaries: 26 + protectedRuntimeSelfTest.canaries,
    simulatedAwsMutations: rb06.mutationCount + rb08.mutationCount,
    externalRequests: 0,
    rb06CheckpointSha256: rb06.checkpointSha256,
    rb08CheckpointSha256: rb08.checkpointSha256,
    extensionSha256: extension.extensionSha256,
    gateE703: extension.gateE703,
  };
};
