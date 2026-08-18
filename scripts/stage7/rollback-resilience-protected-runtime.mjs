import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';
import { gunzipSync, gzipSync } from 'node:zlib';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256, workspaceRoot } from './core.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const AWS_ACCOUNT = /^[0-9]{12}$/u;
const AWS_REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$/u;
const IAM_ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/[A-Za-z0-9+=,.@_/-]{1,512}$/u;
const MAX_AWS_OUTPUT_BYTES = 32 * 1024 * 1024;
const MAX_JOURNAL_VALUE_BYTES = 3900;
const JOURNAL_CHUNK_CHARACTERS = 3200;
const MAX_JOURNAL_CHUNKS = 32;
const AWS_TIMEOUT_MS = 20 * 60 * 1000;
const PROTECTED_WORKFLOW = 'stage7-rollback-resilience.yml';
const PROTECTED_ENVIRONMENT = 'assessment-release-recovery';
const PENDING_INDEX_NAME = 'GSI2-PendingAge';
const PENDING_INDEX_PARTITION = 'PAYMENT#PENDING';
const ORIGIN_HEADER = 'x-stage7-origin-verify';
const JOURNAL_SCENARIO_IDS = ['RB-E7-06', 'RB-E7-08'];
const ROLLBACK_PREMUTATION_EXECUTION_KEYS = Object.freeze([
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
]);
export const ROLLBACK_SSM_PREMUTATION_BINDING_PREIMAGE_KEYS = Object.freeze([
  'freezeManifestSha256',
  'previousReleaseManifestSha256',
  'candidateRecordSha256',
  'approvalSha256',
  'awsAuthEvidenceSha256',
  'iamEffectivePermissionsBindingSha256',
  'approvedPlanSha256',
  'deploymentEvidenceSha256',
  'observabilityEvidenceSha256',
  'activationEvidenceSha256',
  'externalAuthorizationEvidenceSha256',
  'authorizationBudgetSha256',
  'reconciliationRecoveryRoleAuthoritySha256',
  'baseRehearsalSha256',
]);
const RECOVERY_ROLE_AUTHORITY_KEYS = Object.freeze([
  'reconciliationRecoveryRoleArn',
  'reconciliationRecoveryPermissionsBoundaryArn',
  'reconciliationRecoveryRoleEffectivePermissionsRawSha256',
  'reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256',
  'reconciliationRecoveryRoleEffectivePermissionsSha256',
  'reconciliationRecoveryRoleEffectivePolicyProjectionSha256',
]);
const JOURNAL_LIFECYCLE_KEYS = [
  'schemaVersion',
  'stage',
  'kind',
  'status',
  'ownerAlias',
  'cleanupRoleSha256',
  'rootPrefix',
  'scenarioPrefixes',
  'cleanupScopeSha256',
  'retentionBoundary',
  'expiresAtUtc',
  'evidenceRetentionDays',
  'cleanupMode',
  'cleanupRequired',
  'cleanupAttempted',
  'deleteBeforeBoundaryAllowed',
  'containsSensitiveData',
  'lifecycleSha256',
];
const originModeCompatible = ({ actual, previous }) =>
  previous
    ? ['origin_gate', 'cloudfront_signed_cookie'].includes(actual)
    : actual === 'origin_gate';

class ProtectedRuntimeError extends Error {
  constructor(code) {
    super(code);
    this.name = 'ProtectedRuntimeError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new ProtectedRuntimeError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const utc = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return null;
  return new Date(value).toISOString();
};
const awsCommand = process.platform === 'win32' ? 'aws.cmd' : 'aws';
const cloudFormationExecutionRoleArn = (inputs) =>
  `arn:aws:iam::${inputs.config.aws.accountId}:role/cdk-hnb659fds-cfn-exec-role-${inputs.config.aws.accountId}-${inputs.config.aws.region}`;

const dedicatedJournalCleanupRoleArn = (inputs) => {
  const roleArn = inputs?.journalCleanupRoleArn;
  const match = IAM_ROLE_ARN.exec(roleArn ?? '');
  if (
    match === null ||
    match[1] !== inputs?.config?.aws?.accountId ||
    Object.values(inputs?.config?.aws?.roles ?? {}).includes(roleArn)
  ) {
    fail('E7_PROTECTED_SSM_JOURNAL_ROLE_INVALID');
  }
  return roleArn;
};

export const createRollbackJournalLifecycle = (inputs) => {
  const candidateSha = inputs?.freezeManifest?.candidateSha;
  const rootPrefix = `/checkout/stage7/rollback/${candidateSha}`;
  const scenarioPrefixes = Object.fromEntries(
    JOURNAL_SCENARIO_IDS.map((scenarioId) => [scenarioId, `${rootPrefix}/${scenarioId}`]),
  );
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_SSM_JOURNAL_LIFECYCLE',
    status: 'PENDING_POST_CLOSEOUT_CLEANUP',
    ownerAlias: inputs?.config?.cleanup?.ownerAlias,
    cleanupRoleSha256: sha256(dedicatedJournalCleanupRoleArn(inputs)),
    rootPrefix,
    scenarioPrefixes,
    cleanupScopeSha256: objectSha256({ rootPrefix, scenarioPrefixes }),
    retentionBoundary: 'FINAL_EVIDENCE_AND_SUCCESSOR_HANDOFF_PRESERVED',
    expiresAtUtc: inputs?.config?.cleanup?.expiresAtUtc,
    evidenceRetentionDays: 30,
    cleanupMode: 'SEPARATE_IDEMPOTENT_PROTECTED_RUN',
    cleanupRequired: true,
    cleanupAttempted: false,
    deleteBeforeBoundaryAllowed: false,
    containsSensitiveData: false,
  };
  return validateRollbackJournalLifecycle(
    { ...body, lifecycleSha256: objectSha256(body) },
    { inputs },
  );
};

export const validateRollbackJournalLifecycle = (value, { inputs }) => {
  const candidateSha = inputs?.freezeManifest?.candidateSha;
  const rootPrefix = `/checkout/stage7/rollback/${candidateSha}`;
  const scenarioPrefixes = Object.fromEntries(
    JOURNAL_SCENARIO_IDS.map((scenarioId) => [scenarioId, `${rootPrefix}/${scenarioId}`]),
  );
  if (
    !SHA.test(candidateSha ?? '') ||
    !exactKeys(value, JOURNAL_LIFECYCLE_KEYS) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'ROLLBACK_RESILIENCE_SSM_JOURNAL_LIFECYCLE' ||
    value.status !== 'PENDING_POST_CLOSEOUT_CLEANUP' ||
    value.ownerAlias !== inputs?.config?.cleanup?.ownerAlias ||
    value.cleanupRoleSha256 !== sha256(dedicatedJournalCleanupRoleArn(inputs)) ||
    value.rootPrefix !== rootPrefix ||
    !exactKeys(value.scenarioPrefixes, JOURNAL_SCENARIO_IDS) ||
    canonicalJson(value.scenarioPrefixes) !== canonicalJson(scenarioPrefixes) ||
    value.cleanupScopeSha256 !== objectSha256({ rootPrefix, scenarioPrefixes }) ||
    value.retentionBoundary !== 'FINAL_EVIDENCE_AND_SUCCESSOR_HANDOFF_PRESERVED' ||
    utc(value.expiresAtUtc) !== value.expiresAtUtc ||
    value.expiresAtUtc !== inputs?.config?.cleanup?.expiresAtUtc ||
    Date.parse(value.expiresAtUtc) <= Date.parse(inputs?.config?.window?.endsAtUtc ?? '') ||
    value.evidenceRetentionDays !== 30 ||
    value.cleanupMode !== 'SEPARATE_IDEMPOTENT_PROTECTED_RUN' ||
    value.cleanupRequired !== true ||
    value.cleanupAttempted !== false ||
    value.deleteBeforeBoundaryAllowed !== false ||
    value.containsSensitiveData !== false ||
    value.lifecycleSha256 !==
      objectSha256(
        Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'lifecycleSha256')),
      )
  ) {
    fail('E7_PROTECTED_SSM_LIFECYCLE_INVALID');
  }
  return value;
};

const ROLLBACK_PREMUTATION_AUTHORITY_KEYS = Object.freeze([
  'schemaVersion',
  'stage',
  'kind',
  'status',
  'candidateSha',
  'scenarioId',
  'releaseId',
  'releaseTag',
  'configSha256',
  'rollbackBindingPreimage',
  'execution',
  'executionSha256',
  'bindingSha256',
  'protectedBindingSha256',
  'rollbackRoleSha256',
  'journalCleanupRoleSha256',
  'journalLifecycleSha256',
  'parameterName',
  'containsSensitiveData',
  'authoritySha256',
]);

const rollbackBindingPreimageFromInputs = (inputs) => {
  const awsAuth = parseStrictJsonSource(
    Buffer.from(inputs?.documents?.awsAuth?.content ?? '', 'utf8'),
    { scanForbiddenData: false },
  );
  return {
    freezeManifestSha256: inputs?.freezeManifest?.manifestSha256,
    previousReleaseManifestSha256: inputs?.previousReleaseManifest?.manifestSha256,
    candidateRecordSha256: inputs?.candidateRecord?.recordSha256,
    approvalSha256: inputs?.candidateRecord?.approvalSha256,
    awsAuthEvidenceSha256: inputs?.documents?.awsAuth?.sha256,
    iamEffectivePermissionsBindingSha256: awsAuth?.iamEffectivePermissions?.bindingSha256,
    approvedPlanSha256: inputs?.candidateRecord?.planSha256,
    deploymentEvidenceSha256: inputs?.candidateRecord?.deploymentEvidenceSha256,
    observabilityEvidenceSha256: inputs?.documents?.observabilityEvidence?.sha256,
    activationEvidenceSha256: inputs?.documents?.activationEvidence?.sha256,
    externalAuthorizationEvidenceSha256: inputs?.documents?.externalAuthorizationEvidence?.sha256,
    authorizationBudgetSha256: inputs?.documents?.authorizationBudget?.sha256,
    reconciliationRecoveryRoleAuthoritySha256: objectSha256(
      Object.fromEntries(RECOVERY_ROLE_AUTHORITY_KEYS.map((key) => [key, awsAuth?.[key]])),
    ),
    baseRehearsalSha256: inputs?.baseRehearsal?.rehearsalSha256,
  };
};

const rollbackBindingBodyFromPremutationAuthority = (value) => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'ROLLBACK_RESILIENCE_BINDING',
  candidateSha: value.candidateSha,
  releaseId: value.releaseId,
  configSha256: value.configSha256,
  ...value.rollbackBindingPreimage,
  journalCleanupRoleSha256: value.journalCleanupRoleSha256,
  executionSha256: value.executionSha256,
  containsSensitiveData: false,
});

const protectedBindingPreimageFromPremutationAuthority = (value) => ({
  STAGE7_AUTHORIZED_RUN_ID: value.execution.runId,
  STAGE7_AUTHORIZED_RUN_ATTEMPT: value.execution.runAttempt,
  STAGE7_AUTHORIZED_CANDIDATE_SHA: value.candidateSha,
  STAGE7_AUTHORIZED_FREEZE_SHA256: value.rollbackBindingPreimage.freezeManifestSha256,
  STAGE7_AUTHORIZED_APPROVAL_SHA256: value.rollbackBindingPreimage.approvalSha256,
  STAGE7_AUTHORIZED_AWS_AUTH_SHA256: value.rollbackBindingPreimage.awsAuthEvidenceSha256,
  STAGE7_AUTHORIZED_PLAN_SHA256: value.rollbackBindingPreimage.approvedPlanSha256,
  STAGE7_AUTHORIZED_DEPLOYMENT_SHA256: value.rollbackBindingPreimage.deploymentEvidenceSha256,
  STAGE7_AUTHORIZED_OBSERVABILITY_SHA256: value.rollbackBindingPreimage.observabilityEvidenceSha256,
  STAGE7_AUTHORIZED_ACTIVATION_SHA256: value.rollbackBindingPreimage.activationEvidenceSha256,
  STAGE7_AUTHORIZED_EXTERNAL_AUTHORIZATION_SHA256:
    value.rollbackBindingPreimage.externalAuthorizationEvidenceSha256,
  STAGE7_AUTHORIZED_AUTHORIZATION_BUDGET_SHA256:
    value.rollbackBindingPreimage.authorizationBudgetSha256,
  STAGE7_AUTHORIZED_REHEARSAL_SHA256: value.rollbackBindingPreimage.baseRehearsalSha256,
  STAGE7_AUTHORIZED_JOURNAL_CLEANUP_ROLE_SHA256: value.journalCleanupRoleSha256,
});

export const validateRollbackSsmPremutationAuthority = (value, expected = {}) => {
  const parameterName = `/checkout/stage7/rollback/${value?.candidateSha}/${value?.scenarioId}/premutation-authority`;
  const execution = value?.execution;
  const rollbackBindingPreimage = value?.rollbackBindingPreimage;
  if (
    !exactKeys(value, ROLLBACK_PREMUTATION_AUTHORITY_KEYS) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'ROLLBACK_RESILIENCE_SSM_PREMUTATION_AUTHORITY' ||
    value.status !== 'PREMUTATION_PREIMAGE_BOUND_IMMUTABLE' ||
    !SHA.test(value.candidateSha ?? '') ||
    !JOURNAL_SCENARIO_IDS.includes(value.scenarioId) ||
    !RELEASE_ID.test(value.releaseId ?? '') ||
    !value.releaseId.endsWith(value.candidateSha.slice(0, 7)) ||
    !RELEASE_TAG.test(value.releaseTag ?? '') ||
    !SHA256.test(value.configSha256 ?? '') ||
    !exactKeys(rollbackBindingPreimage, ROLLBACK_SSM_PREMUTATION_BINDING_PREIMAGE_KEYS) ||
    !Object.values(rollbackBindingPreimage ?? {}).every((digest) => SHA256.test(digest ?? '')) ||
    !exactKeys(execution, ROLLBACK_PREMUTATION_EXECUTION_KEYS) ||
    execution.mode !== 'AWS_REAL' ||
    execution.repository !== 'ivanmonsalve0404/async-checkout-demo' ||
    execution.workflow !== PROTECTED_WORKFLOW ||
    !RUN_ID.test(execution.runId ?? '') ||
    execution.runAttempt !== '1' ||
    execution.githubActions !== true ||
    execution.githubRef !== 'refs/heads/master' ||
    execution.githubSha !== value.candidateSha ||
    execution.protectedEnvironment !== PROTECTED_ENVIRONMENT ||
    !AWS_ACCOUNT.test(execution.accountId ?? '') ||
    !AWS_REGION.test(execution.region ?? '') ||
    IAM_ROLE_ARN.exec(execution.roleArn ?? '')?.[1] !== execution.accountId ||
    utc(execution.startedAtUtc) !== execution.startedAtUtc ||
    value.executionSha256 !== objectSha256(execution) ||
    value.rollbackRoleSha256 !== sha256(execution.roleArn) ||
    value.bindingSha256 !== objectSha256(rollbackBindingBodyFromPremutationAuthority(value)) ||
    value.protectedBindingSha256 !==
      objectSha256(protectedBindingPreimageFromPremutationAuthority(value)) ||
    ![
      value.bindingSha256,
      value.protectedBindingSha256,
      value.rollbackRoleSha256,
      value.journalCleanupRoleSha256,
      value.journalLifecycleSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    value.parameterName !== parameterName ||
    value.containsSensitiveData !== false ||
    value.authoritySha256 !==
      objectSha256(
        Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'authoritySha256')),
      ) ||
    (expected.candidateSha !== undefined && value.candidateSha !== expected.candidateSha) ||
    (expected.scenarioId !== undefined && value.scenarioId !== expected.scenarioId) ||
    (expected.releaseId !== undefined && value.releaseId !== expected.releaseId) ||
    (expected.releaseTag !== undefined && value.releaseTag !== expected.releaseTag) ||
    (expected.configSha256 !== undefined && value.configSha256 !== expected.configSha256) ||
    (expected.sourceRunId !== undefined && execution.runId !== expected.sourceRunId) ||
    (expected.sourceRunAttempt !== undefined &&
      Number(execution.runAttempt) !== expected.sourceRunAttempt) ||
    (expected.accountId !== undefined && execution.accountId !== expected.accountId) ||
    (expected.region !== undefined && execution.region !== expected.region) ||
    (expected.roleArn !== undefined && execution.roleArn !== expected.roleArn) ||
    (expected.startedAtUtc !== undefined && execution.startedAtUtc !== expected.startedAtUtc) ||
    (expected.executionSha256 !== undefined &&
      value.executionSha256 !== expected.executionSha256) ||
    (expected.bindingSha256 !== undefined && value.bindingSha256 !== expected.bindingSha256) ||
    (expected.protectedBindingSha256 !== undefined &&
      value.protectedBindingSha256 !== expected.protectedBindingSha256) ||
    (expected.rollbackRoleSha256 !== undefined &&
      value.rollbackRoleSha256 !== expected.rollbackRoleSha256) ||
    (expected.journalCleanupRoleSha256 !== undefined &&
      value.journalCleanupRoleSha256 !== expected.journalCleanupRoleSha256) ||
    (expected.journalLifecycleSha256 !== undefined &&
      value.journalLifecycleSha256 !== expected.journalLifecycleSha256)
  ) {
    fail('E7_PROTECTED_SSM_PREMUTATION_AUTHORITY_INVALID');
  }
  return value;
};

export const createRollbackSsmPremutationAuthority = ({
  inputs,
  scenarioId,
  bindingSha256,
  protectedBindingSha256,
  journalLifecycle,
}) => {
  const execution = { ...inputs?.execution };
  const rollbackBindingPreimage = rollbackBindingPreimageFromInputs(inputs);
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_SSM_PREMUTATION_AUTHORITY',
    status: 'PREMUTATION_PREIMAGE_BOUND_IMMUTABLE',
    candidateSha: inputs?.freezeManifest?.candidateSha,
    scenarioId,
    releaseId: inputs?.freezeManifest?.releaseId,
    releaseTag: inputs?.freezeManifest?.releaseTag,
    configSha256: objectSha256(inputs?.config),
    rollbackBindingPreimage,
    execution,
    executionSha256: objectSha256(execution),
    bindingSha256,
    protectedBindingSha256,
    rollbackRoleSha256: sha256(inputs?.config?.aws?.roles?.rollbackRoleArn ?? ''),
    journalCleanupRoleSha256: journalLifecycle?.cleanupRoleSha256,
    journalLifecycleSha256: journalLifecycle?.lifecycleSha256,
    parameterName: `${journalLifecycle?.scenarioPrefixes?.[scenarioId]}/premutation-authority`,
    containsSensitiveData: false,
  };
  return validateRollbackSsmPremutationAuthority(
    { ...body, authoritySha256: objectSha256(body) },
    {
      candidateSha: inputs?.freezeManifest?.candidateSha,
      scenarioId,
      releaseId: inputs?.freezeManifest?.releaseId,
      releaseTag: inputs?.freezeManifest?.releaseTag,
      configSha256: objectSha256(inputs?.config),
      sourceRunId: inputs?.execution?.runId,
      sourceRunAttempt: Number(inputs?.execution?.runAttempt),
      accountId: inputs?.config?.aws?.accountId,
      region: inputs?.config?.aws?.region,
      roleArn: inputs?.config?.aws?.roles?.rollbackRoleArn,
      startedAtUtc: inputs?.execution?.startedAtUtc,
      bindingSha256,
      protectedBindingSha256,
      journalLifecycleSha256: journalLifecycle?.lifecycleSha256,
    },
  );
};

const ROLLBACK_JOURNAL_OWNER_KEYS = Object.freeze([
  'schemaVersion',
  'stage',
  'kind',
  'status',
  'candidateSha',
  'scenarioId',
  'sourceRunId',
  'sourceRunAttempt',
  'bindingSha256',
  'protectedBindingSha256',
  'rollbackRoleSha256',
  'journalCleanupRoleSha256',
  'journalLifecycleSha256',
  'premutationAuthorityParameterName',
  'premutationAuthorityRawSha256',
  'premutationAuthorityCanonicalSha256',
  'premutationAuthorityBytes',
  'parameterName',
  'containsSensitiveData',
  'ownerSha256',
]);

export const validateRollbackJournalOwner = (value, expected = {}) => {
  const parameterName = `/checkout/stage7/rollback/${value?.candidateSha}/${value?.scenarioId}/owner`;
  const premutationAuthorityParameterName = `/checkout/stage7/rollback/${value?.candidateSha}/${value?.scenarioId}/premutation-authority`;
  if (
    !exactKeys(value, ROLLBACK_JOURNAL_OWNER_KEYS) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'ROLLBACK_RESILIENCE_SSM_JOURNAL_OWNER' ||
    value.status !== 'OWNED_IMMUTABLE' ||
    !SHA.test(value.candidateSha ?? '') ||
    !JOURNAL_SCENARIO_IDS.includes(value.scenarioId) ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    value.sourceRunAttempt !== 1 ||
    ![
      value.bindingSha256,
      value.protectedBindingSha256,
      value.rollbackRoleSha256,
      value.journalCleanupRoleSha256,
      value.journalLifecycleSha256,
      value.premutationAuthorityRawSha256,
      value.premutationAuthorityCanonicalSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    value.premutationAuthorityParameterName !== premutationAuthorityParameterName ||
    !Number.isSafeInteger(value.premutationAuthorityBytes) ||
    value.premutationAuthorityBytes < 2 ||
    value.premutationAuthorityBytes > MAX_JOURNAL_VALUE_BYTES ||
    value.parameterName !== parameterName ||
    value.containsSensitiveData !== false ||
    value.ownerSha256 !==
      objectSha256(
        Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'ownerSha256')),
      ) ||
    (expected.candidateSha !== undefined && value.candidateSha !== expected.candidateSha) ||
    (expected.scenarioId !== undefined && value.scenarioId !== expected.scenarioId) ||
    (expected.sourceRunId !== undefined && value.sourceRunId !== expected.sourceRunId) ||
    (expected.bindingSha256 !== undefined && value.bindingSha256 !== expected.bindingSha256) ||
    (expected.protectedBindingSha256 !== undefined &&
      value.protectedBindingSha256 !== expected.protectedBindingSha256) ||
    (expected.rollbackRoleSha256 !== undefined &&
      value.rollbackRoleSha256 !== expected.rollbackRoleSha256) ||
    (expected.journalCleanupRoleSha256 !== undefined &&
      value.journalCleanupRoleSha256 !== expected.journalCleanupRoleSha256) ||
    (expected.journalLifecycleSha256 !== undefined &&
      value.journalLifecycleSha256 !== expected.journalLifecycleSha256) ||
    (expected.premutationAuthority !== undefined &&
      (validateRollbackSsmPremutationAuthority(expected.premutationAuthority, {
        candidateSha: value.candidateSha,
        scenarioId: value.scenarioId,
        sourceRunId: value.sourceRunId,
        sourceRunAttempt: value.sourceRunAttempt,
        bindingSha256: value.bindingSha256,
        protectedBindingSha256: value.protectedBindingSha256,
        rollbackRoleSha256: value.rollbackRoleSha256,
        journalCleanupRoleSha256: value.journalCleanupRoleSha256,
        journalLifecycleSha256: value.journalLifecycleSha256,
      }) !== expected.premutationAuthority ||
        value.premutationAuthorityParameterName !== expected.premutationAuthority.parameterName ||
        value.premutationAuthorityRawSha256 !==
          sha256(JSON.stringify(expected.premutationAuthority)) ||
        value.premutationAuthorityCanonicalSha256 !== objectSha256(expected.premutationAuthority) ||
        value.premutationAuthorityBytes !==
          Buffer.byteLength(JSON.stringify(expected.premutationAuthority), 'utf8')))
  ) {
    fail('E7_PROTECTED_SSM_JOURNAL_OWNER_INVALID');
  }
  return value;
};

export const createRollbackJournalOwner = ({
  inputs,
  scenarioId,
  premutationAuthority,
  journalLifecycle,
}) => {
  validateRollbackSsmPremutationAuthority(premutationAuthority, {
    candidateSha: inputs?.freezeManifest?.candidateSha,
    scenarioId,
    releaseId: inputs?.freezeManifest?.releaseId,
    releaseTag: inputs?.freezeManifest?.releaseTag,
    configSha256: objectSha256(inputs?.config),
    sourceRunId: inputs?.execution?.runId,
    sourceRunAttempt: Number(inputs?.execution?.runAttempt),
    accountId: inputs?.config?.aws?.accountId,
    region: inputs?.config?.aws?.region,
    roleArn: inputs?.config?.aws?.roles?.rollbackRoleArn,
    startedAtUtc: inputs?.execution?.startedAtUtc,
    rollbackRoleSha256: sha256(inputs?.config?.aws?.roles?.rollbackRoleArn ?? ''),
    journalCleanupRoleSha256: journalLifecycle?.cleanupRoleSha256,
    journalLifecycleSha256: journalLifecycle?.lifecycleSha256,
  });
  const premutationAuthorityValue = JSON.stringify(premutationAuthority);
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_SSM_JOURNAL_OWNER',
    status: 'OWNED_IMMUTABLE',
    candidateSha: inputs.freezeManifest.candidateSha,
    scenarioId,
    sourceRunId: inputs.execution.runId,
    sourceRunAttempt: Number(inputs.execution.runAttempt),
    bindingSha256: premutationAuthority.bindingSha256,
    protectedBindingSha256: premutationAuthority.protectedBindingSha256,
    rollbackRoleSha256: sha256(inputs.config.aws.roles.rollbackRoleArn),
    journalCleanupRoleSha256: journalLifecycle.cleanupRoleSha256,
    journalLifecycleSha256: journalLifecycle.lifecycleSha256,
    premutationAuthorityParameterName: premutationAuthority.parameterName,
    premutationAuthorityRawSha256: sha256(premutationAuthorityValue),
    premutationAuthorityCanonicalSha256: objectSha256(premutationAuthority),
    premutationAuthorityBytes: Buffer.byteLength(premutationAuthorityValue, 'utf8'),
    parameterName: journalLifecycle.scenarioPrefixes[scenarioId] + '/owner',
    containsSensitiveData: false,
  };
  return validateRollbackJournalOwner(
    { ...body, ownerSha256: objectSha256(body) },
    {
      candidateSha: inputs.freezeManifest.candidateSha,
      scenarioId,
      sourceRunId: inputs.execution.runId,
      bindingSha256: premutationAuthority.bindingSha256,
      protectedBindingSha256: premutationAuthority.protectedBindingSha256,
      journalLifecycleSha256: journalLifecycle.lifecycleSha256,
      premutationAuthority,
    },
  );
};

const resolveProtectedDirectory = (candidateSha) => {
  if (!SHA.test(candidateSha ?? '')) fail('E7_PROTECTED_CANDIDATE_SHA_INVALID');
  const target = path.resolve(
    workspaceRoot,
    'output/evidence/runtime/.private-stage7/rollback-resilience',
    candidateSha,
  );
  const relative = path.relative(workspaceRoot, target);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('E7_PROTECTED_DIRECTORY_OUTSIDE_WORKSPACE');
  }
  mkdirSync(target, { recursive: true });
  if (!lstatSync(target).isDirectory() || realpathSync(target) !== target) {
    fail('E7_PROTECTED_DIRECTORY_INVALID');
  }
  return target;
};

const runAws = (arguments_, code, { allowFailure = false, outputFile, input } = {}) => {
  if (
    !Array.isArray(arguments_) ||
    arguments_.some((entry) => typeof entry !== 'string' || entry.includes('\0'))
  ) {
    fail('E7_PROTECTED_AWS_ARGUMENT_INVALID');
  }
  const args = [...arguments_];
  if (!args.includes('--region')) args.push('--region', process.env.AWS_REGION ?? '');
  args.push('--no-cli-pager');
  if (outputFile === undefined) args.push('--output', 'json');
  else args.push(outputFile);
  const result = spawnSync(awsCommand, args, {
    cwd: workspaceRoot,
    encoding: outputFile === undefined ? 'utf8' : undefined,
    env: process.env,
    input,
    maxBuffer: MAX_AWS_OUTPUT_BYTES,
    shell: false,
    timeout: AWS_TIMEOUT_MS,
    windowsHide: true,
  });
  if (result.error !== undefined || result.status !== 0) {
    if (allowFailure) return null;
    fail(code);
  }
  if (outputFile !== undefined) return {};
  const stdout = String(result.stdout ?? '').trim();
  if (stdout === '') return {};
  try {
    const parsed = JSON.parse(stdout);
    if (!object(parsed)) fail(code);
    return parsed;
  } catch {
    fail(code);
  }
};

const verifyAwsCliVersion = (expected) => {
  const result = spawnSync(awsCommand, ['--version'], {
    cwd: workspaceRoot,
    encoding: 'utf8',
    env: process.env,
    maxBuffer: 1024 * 1024,
    shell: false,
    timeout: 30_000,
    windowsHide: true,
  });
  const output = `${result.stdout ?? ''} ${result.stderr ?? ''}`.trim();
  const match = /(?:^|\s)aws-cli\/([0-9]+\.[0-9]+\.[0-9]+)(?=\s|$)/u.exec(output);
  if (result.error !== undefined || result.status !== 0 || match?.[1] !== expected) {
    fail('E7_PROTECTED_AWS_CLI_VERSION_MISMATCH');
  }
  return sha256(match[1]);
};

const assumedRoleMatches = (sessionArn, roleArn) => {
  if (typeof sessionArn !== 'string' || typeof roleArn !== 'string') return false;
  const role = /^arn:aws:iam::([0-9]{12}):role\/(.+)$/u.exec(roleArn);
  const session = /^arn:aws:sts::([0-9]{12}):assumed-role\/(.+)\/([^/]+)$/u.exec(sessionArn);
  return role !== null && session !== null && role[1] === session[1] && role[2] === session[2];
};

const protectedWorkflowName = (workflowReference) => {
  if (typeof workflowReference !== 'string') fail('E7_PROTECTED_WORKFLOW_CONTEXT_INVALID');
  const match =
    /^ivanmonsalve0404\/async-checkout-demo\/.github\/workflows\/([^@/]+)@refs\/heads\/master$/u.exec(
      workflowReference,
    );
  if (match === null || match[1] !== PROTECTED_WORKFLOW) {
    fail('E7_PROTECTED_WORKFLOW_CONTEXT_INVALID');
  }
  return match[1];
};

const requireProtectedBindingEnvironment = ({ inputsWithoutExecution, execution }) => {
  const expected = {
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
      dedicatedJournalCleanupRoleArn(inputsWithoutExecution),
    ),
  };
  if (Object.entries(expected).some(([name, value]) => process.env[name] !== value)) {
    fail('E7_PROTECTED_BINDING_ENVIRONMENT_MISMATCH');
  }
  return objectSha256(expected);
};

const executionFromProtectedEnvironment = (inputsWithoutExecution) => {
  const config = inputsWithoutExecution.config;
  const startedAtUtc = utc(process.env.STAGE7_ROLLBACK_STARTED_AT_UTC);
  const workflow = protectedWorkflowName(process.env.GITHUB_WORKFLOW_REF);
  const execution = {
    mode: 'AWS_REAL',
    repository: process.env.GITHUB_REPOSITORY,
    workflow,
    runId: process.env.GITHUB_RUN_ID,
    runAttempt: process.env.GITHUB_RUN_ATTEMPT,
    githubActions: process.env.GITHUB_ACTIONS === 'true',
    githubRef: process.env.GITHUB_REF,
    githubSha: process.env.GITHUB_SHA,
    protectedEnvironment: process.env.STAGE7_PROTECTED_ENVIRONMENT,
    accountId: config?.aws?.accountId,
    region: process.env.AWS_REGION,
    roleArn: config?.aws?.roles?.rollbackRoleArn,
    startedAtUtc,
  };
  if (
    execution.repository !== 'ivanmonsalve0404/async-checkout-demo' ||
    !RUN_ID.test(execution.runId ?? '') ||
    !RUN_ID.test(execution.runAttempt ?? '') ||
    execution.githubActions !== true ||
    execution.githubRef !== 'refs/heads/master' ||
    execution.githubSha !== inputsWithoutExecution.freezeManifest?.candidateSha ||
    execution.protectedEnvironment !== PROTECTED_ENVIRONMENT ||
    !AWS_ACCOUNT.test(execution.accountId ?? '') ||
    execution.region !== config?.aws?.region ||
    startedAtUtc === null ||
    Date.parse(startedAtUtc) < Date.parse(config?.window?.startsAtUtc ?? '') ||
    Date.parse(startedAtUtc) > Date.parse(config?.window?.endsAtUtc ?? '') ||
    config?.aws?.sessionMode !== 'OIDC' ||
    !/^ASIA[A-Z0-9]{16}$/u.test(process.env.AWS_ACCESS_KEY_ID ?? '') ||
    typeof process.env.AWS_SECRET_ACCESS_KEY !== 'string' ||
    process.env.AWS_SECRET_ACCESS_KEY.length < 32 ||
    typeof process.env.AWS_SESSION_TOKEN !== 'string' ||
    process.env.AWS_SESSION_TOKEN.length < 32
  ) {
    fail('E7_PROTECTED_EXECUTION_CONTEXT_INVALID');
  }
  return execution;
};

const revalidateProtectedIdentity = ({ inputs, protectedBindingSha256 }) => {
  const now = new Date();
  if (
    now.getTime() < Date.parse(inputs.config.window.startsAtUtc) ||
    now.getTime() > Date.parse(inputs.config.window.endsAtUtc) ||
    process.env.GITHUB_RUN_ID !== inputs.execution.runId ||
    process.env.GITHUB_RUN_ATTEMPT !== inputs.execution.runAttempt ||
    process.env.GITHUB_SHA !== inputs.freezeManifest.candidateSha ||
    process.env.GITHUB_REF !== 'refs/heads/master' ||
    process.env.GITHUB_REPOSITORY !== 'ivanmonsalve0404/async-checkout-demo' ||
    process.env.GITHUB_ACTIONS !== 'true' ||
    protectedWorkflowName(process.env.GITHUB_WORKFLOW_REF) !== PROTECTED_WORKFLOW ||
    process.env.STAGE7_PROTECTED_ENVIRONMENT !== PROTECTED_ENVIRONMENT ||
    process.env.AWS_REGION !== inputs.config.aws.region ||
    !/^ASIA[A-Z0-9]{16}$/u.test(process.env.AWS_ACCESS_KEY_ID ?? '') ||
    typeof process.env.AWS_SESSION_TOKEN !== 'string' ||
    process.env.AWS_SESSION_TOKEN.length < 32 ||
    requireProtectedBindingEnvironment({
      inputsWithoutExecution: {
        config: inputs.config,
        freezeManifest: inputs.freezeManifest,
        candidateRecord: inputs.candidateRecord,
        baseRehearsal: inputs.baseRehearsal,
        documents: inputs.documents,
        journalCleanupRoleArn: inputs.journalCleanupRoleArn,
      },
      execution: inputs.execution,
    }) !== protectedBindingSha256
  ) {
    fail('E7_PROTECTED_CONTEXT_DRIFT');
  }
  const caller = runAws(['sts', 'get-caller-identity'], 'E7_PROTECTED_STS_FAILED');
  if (
    caller.Account !== inputs.config.aws.accountId ||
    !assumedRoleMatches(caller.Arn, inputs.config.aws.roles.rollbackRoleArn)
  ) {
    fail('E7_PROTECTED_AWS_IDENTITY_MISMATCH');
  }
  return {
    accountSha256: sha256(caller.Account),
    accountSuffix: caller.Account.slice(-4),
    roleSha256: sha256(inputs.config.aws.roles.rollbackRoleArn),
    sessionArnSha256: sha256(caller.Arn),
    observedAtUtc: now.toISOString(),
  };
};

const listParametersByPath = (prefix) => {
  const output = [];
  let nextToken = null;
  do {
    const args = [
      'ssm',
      'get-parameters-by-path',
      '--path',
      prefix,
      '--recursive',
      '--with-decryption',
      '--max-results',
      '10',
      '--no-paginate',
    ];
    if (nextToken !== null) args.push('--next-token', nextToken);
    const response = runAws(args, 'E7_PROTECTED_SSM_LIST_FAILED');
    if (!Array.isArray(response.Parameters)) fail('E7_PROTECTED_SSM_LIST_INVALID');
    output.push(...response.Parameters);
    nextToken = response.NextToken ?? null;
    if (nextToken !== null && (typeof nextToken !== 'string' || nextToken === '')) {
      fail('E7_PROTECTED_SSM_TOKEN_INVALID');
    }
  } while (nextToken !== null);
  return output;
};

const journalGroups = ({ prefix, parameters }) => {
  const escaped = prefix.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const pattern = new RegExp(
    `^${escaped}/([0-9]{6})-([0-9a-f]{64})/(manifest|abandoned|chunk-[0-9]{4})$`,
    'u',
  );
  const groups = new Map();
  for (const parameter of parameters) {
    const match = pattern.exec(parameter?.Name ?? '');
    if (
      match === null ||
      typeof parameter.Value !== 'string' ||
      Buffer.byteLength(parameter.Value, 'utf8') >= 4096
    ) {
      fail('E7_PROTECTED_SSM_ENTRY_INVALID');
    }
    const sequence = Number(match[1]);
    const stateSha256 = match[2];
    const key = `${match[1]}-${stateSha256}`;
    const group = groups.get(key) ?? {
      sequence,
      stateSha256,
      entries: new Map(),
    };
    if (group.entries.has(match[3])) fail('E7_PROTECTED_SSM_ENTRY_DUPLICATE');
    group.entries.set(match[3], parameter.Value);
    groups.set(key, group);
  }
  return [...groups.values()].toSorted((left, right) => left.sequence - right.sequence);
};

const decodeJournalGroup = (group, previousStateSha256) => {
  const manifestText = group.entries.get('manifest');
  if (manifestText === undefined) return null;
  let manifest;
  try {
    manifest = JSON.parse(manifestText);
  } catch {
    fail('E7_PROTECTED_SSM_MANIFEST_INVALID');
  }
  if (
    !exactKeys(manifest, [
      'schemaVersion',
      'kind',
      'sequence',
      'stateSha256',
      'previousStateSha256',
      'encoding',
      'chunks',
      'payloadBytes',
      'payloadSha256',
      'containsSensitiveData',
    ]) ||
    manifest.schemaVersion !== 1 ||
    manifest.kind !== 'ROLLBACK_RESILIENCE_SSM_JOURNAL_ENTRY' ||
    manifest.sequence !== group.sequence ||
    manifest.stateSha256 !== group.stateSha256 ||
    manifest.previousStateSha256 !== previousStateSha256 ||
    manifest.encoding !== 'gzip-base64' ||
    !Number.isSafeInteger(manifest.chunks) ||
    manifest.chunks < 1 ||
    manifest.chunks > MAX_JOURNAL_CHUNKS ||
    !Number.isSafeInteger(manifest.payloadBytes) ||
    manifest.payloadBytes < 2 ||
    !SHA256.test(manifest.payloadSha256 ?? '') ||
    manifest.containsSensitiveData !== false
  ) {
    fail('E7_PROTECTED_SSM_MANIFEST_INVALID');
  }
  const pieces = [];
  for (let index = 1; index <= manifest.chunks; index += 1) {
    const name = `chunk-${String(index).padStart(4, '0')}`;
    const value = group.entries.get(name);
    if (typeof value !== 'string') fail('E7_PROTECTED_SSM_CHUNK_MISSING');
    pieces.push(value);
  }
  if (group.entries.size !== manifest.chunks + 1) fail('E7_PROTECTED_SSM_CHUNK_EXTRA');
  const encoded = pieces.join('');
  if (sha256(encoded) !== manifest.payloadSha256) fail('E7_PROTECTED_SSM_PAYLOAD_DIGEST');
  let decoded;
  try {
    decoded = gunzipSync(Buffer.from(encoded, 'base64')).toString('utf8');
  } catch {
    fail('E7_PROTECTED_SSM_PAYLOAD_INVALID');
  }
  if (Buffer.byteLength(decoded, 'utf8') !== manifest.payloadBytes) {
    fail('E7_PROTECTED_SSM_PAYLOAD_SIZE');
  }
  let state;
  try {
    state = JSON.parse(decoded);
  } catch {
    fail('E7_PROTECTED_SSM_STATE_INVALID');
  }
  if (
    !object(state) ||
    state.containsSensitiveData !== false ||
    state.stateSha256 !== group.stateSha256
  ) {
    fail('E7_PROTECTED_SSM_STATE_INVALID');
  }
  return state;
};

const validateAbandonedJournalGroup = (group, previousStateSha256) => {
  const text = group.entries.get('abandoned');
  if (text === undefined || group.entries.has('manifest')) {
    fail('E7_PROTECTED_SSM_ABANDONED_INVALID');
  }
  let marker;
  try {
    marker = JSON.parse(text);
  } catch {
    fail('E7_PROTECTED_SSM_ABANDONED_INVALID');
  }
  if (
    !exactKeys(marker, [
      'schemaVersion',
      'kind',
      'sequence',
      'stateSha256',
      'previousStateSha256',
      'replacementStateSha256',
      'containsSensitiveData',
    ]) ||
    marker.schemaVersion !== 1 ||
    marker.kind !== 'ROLLBACK_RESILIENCE_SSM_JOURNAL_ABANDONED' ||
    marker.sequence !== group.sequence ||
    marker.stateSha256 !== group.stateSha256 ||
    marker.previousStateSha256 !== previousStateSha256 ||
    !SHA256.test(marker.replacementStateSha256 ?? '') ||
    marker.replacementStateSha256 === marker.stateSha256 ||
    marker.containsSensitiveData !== false
  ) {
    fail('E7_PROTECTED_SSM_ABANDONED_INVALID');
  }
  return marker;
};

const putParameterWithoutOverwrite = ({ name, value }) => {
  if (
    typeof value !== 'string' ||
    Buffer.byteLength(value, 'utf8') >= 4096 ||
    Buffer.byteLength(value, 'utf8') > MAX_JOURNAL_VALUE_BYTES
  ) {
    fail('E7_PROTECTED_SSM_VALUE_TOO_LARGE');
  }
  const existing = runAws(
    ['ssm', 'get-parameter', '--name', name, '--with-decryption'],
    'E7_PROTECTED_SSM_GET_FAILED',
    { allowFailure: true },
  );
  if (existing !== null) {
    if (existing.Parameter?.Name !== name || existing.Parameter?.Value !== value) {
      fail('E7_PROTECTED_SSM_EXISTING_VALUE_MISMATCH');
    }
    return;
  }
  const written = runAws(
    [
      'ssm',
      'put-parameter',
      '--name',
      name,
      '--type',
      'String',
      '--value',
      value,
      '--tier',
      'Standard',
      '--no-overwrite',
    ],
    'E7_PROTECTED_SSM_PUT_FAILED',
  );
  if (!Number.isSafeInteger(written.Version) || written.Version < 1) {
    fail('E7_PROTECTED_SSM_PUT_INVALID');
  }
};

const putImmutablePremutationAuthority = ({ premutationAuthority, inputs }) => {
  validateRollbackSsmPremutationAuthority(premutationAuthority);
  const value = JSON.stringify(premutationAuthority);
  if (Buffer.byteLength(value, 'utf8') > MAX_JOURNAL_VALUE_BYTES) {
    fail('E7_PROTECTED_SSM_PREMUTATION_AUTHORITY_TOO_LARGE');
  }
  const existing = runAws(
    ['ssm', 'get-parameter', '--name', premutationAuthority.parameterName, '--with-decryption'],
    'E7_PROTECTED_SSM_PREMUTATION_AUTHORITY_GET_FAILED',
    { allowFailure: true },
  );
  if (existing === null) {
    const written = runAws(
      [
        'ssm',
        'put-parameter',
        '--name',
        premutationAuthority.parameterName,
        '--type',
        'String',
        '--value',
        value,
        '--tier',
        'Standard',
        '--no-overwrite',
      ],
      'E7_PROTECTED_SSM_PREMUTATION_AUTHORITY_PUT_FAILED',
    );
    if (written?.Version !== 1) fail('E7_PROTECTED_SSM_PREMUTATION_AUTHORITY_PUT_INVALID');
  }
  const readback = runAws(
    ['ssm', 'get-parameter', '--name', premutationAuthority.parameterName, '--with-decryption'],
    'E7_PROTECTED_SSM_PREMUTATION_AUTHORITY_GET_FAILED',
  )?.Parameter;
  const expectedArn = `arn:aws:ssm:${inputs.config.aws.region}:${inputs.config.aws.accountId}:parameter${premutationAuthority.parameterName}`;
  if (
    !object(readback) ||
    readback.Name !== premutationAuthority.parameterName ||
    readback.Type !== 'String' ||
    readback.Value !== value ||
    readback.Version !== 1 ||
    readback.ARN !== expectedArn ||
    readback.DataType !== 'text'
  ) {
    fail('E7_PROTECTED_SSM_PREMUTATION_AUTHORITY_READBACK_INVALID');
  }
  return premutationAuthority;
};

const putImmutableJournalOwner = ({ owner, premutationAuthority, inputs }) => {
  validateRollbackSsmPremutationAuthority(premutationAuthority);
  validateRollbackJournalOwner(owner, { premutationAuthority });
  const value = JSON.stringify(owner);
  if (Buffer.byteLength(value, 'utf8') > MAX_JOURNAL_VALUE_BYTES) {
    fail('E7_PROTECTED_SSM_JOURNAL_OWNER_TOO_LARGE');
  }
  const existing = runAws(
    ['ssm', 'get-parameter', '--name', owner.parameterName, '--with-decryption'],
    'E7_PROTECTED_SSM_JOURNAL_OWNER_GET_FAILED',
    { allowFailure: true },
  );
  if (existing === null) {
    const written = runAws(
      [
        'ssm',
        'put-parameter',
        '--name',
        owner.parameterName,
        '--type',
        'String',
        '--value',
        value,
        '--tier',
        'Standard',
        '--no-overwrite',
      ],
      'E7_PROTECTED_SSM_JOURNAL_OWNER_PUT_FAILED',
    );
    if (written?.Version !== 1) fail('E7_PROTECTED_SSM_JOURNAL_OWNER_PUT_INVALID');
  }
  const readback = runAws(
    ['ssm', 'get-parameter', '--name', owner.parameterName, '--with-decryption'],
    'E7_PROTECTED_SSM_JOURNAL_OWNER_GET_FAILED',
  )?.Parameter;
  const expectedArn = `arn:aws:ssm:${inputs.config.aws.region}:${inputs.config.aws.accountId}:parameter${owner.parameterName}`;
  if (
    !object(readback) ||
    readback.Name !== owner.parameterName ||
    readback.Type !== 'String' ||
    readback.Value !== value ||
    readback.Version !== 1 ||
    readback.ARN !== expectedArn ||
    readback.DataType !== 'text'
  ) {
    fail('E7_PROTECTED_SSM_JOURNAL_OWNER_READBACK_INVALID');
  }
  return owner;
};

const requireExistingJournalAuthority = ({
  parameters,
  ownerParameterName,
  premutationAuthorityParameterName,
}) => {
  const authorityNames = new Set([ownerParameterName, premutationAuthorityParameterName]);
  const hasOwner =
    Array.isArray(parameters) && parameters.some(({ Name }) => Name === ownerParameterName);
  const hasPremutationAuthority =
    Array.isArray(parameters) &&
    parameters.some(({ Name }) => Name === premutationAuthorityParameterName);
  const hasJournalState =
    Array.isArray(parameters) && parameters.some(({ Name }) => !authorityNames.has(Name));
  if (
    !Array.isArray(parameters) ||
    typeof ownerParameterName !== 'string' ||
    parameters.some(({ Name }) => typeof Name !== 'string') ||
    parameters.some(
      ({ Name }) =>
        !authorityNames.has(Name) &&
        !/^\/checkout\/stage7\/rollback\/[0-9a-f]{40}\/RB-E7-(?:06|08)\/[0-9]{6}-[0-9a-f]{64}\/(?:manifest|abandoned|chunk-[0-9]{4})$/u.test(
          Name,
        ),
    ) ||
    parameters.filter(({ Name }) => Name === ownerParameterName).length > 1 ||
    parameters.filter(({ Name }) => Name === premutationAuthorityParameterName).length > 1 ||
    (hasOwner && !hasPremutationAuthority) ||
    (hasJournalState && (!hasOwner || !hasPremutationAuthority))
  ) {
    fail('E7_PROTECTED_SSM_UNOWNED_JOURNAL_BLOCKED');
  }
};

const encodeJournalState = ({ state, sequence, previousStateSha256 }) => {
  const serialized = JSON.stringify(state);
  const encoded = gzipSync(Buffer.from(serialized, 'utf8'), { level: 9 }).toString('base64');
  const chunks = [];
  for (let offset = 0; offset < encoded.length; offset += JOURNAL_CHUNK_CHARACTERS) {
    chunks.push(encoded.slice(offset, offset + JOURNAL_CHUNK_CHARACTERS));
  }
  if (chunks.length < 1 || chunks.length > MAX_JOURNAL_CHUNKS) {
    fail('E7_PROTECTED_SSM_STATE_TOO_LARGE');
  }
  const basename = `${String(sequence).padStart(6, '0')}-${state.stateSha256}`;
  const manifest = {
    schemaVersion: 1,
    kind: 'ROLLBACK_RESILIENCE_SSM_JOURNAL_ENTRY',
    sequence,
    stateSha256: state.stateSha256,
    previousStateSha256,
    encoding: 'gzip-base64',
    chunks: chunks.length,
    payloadBytes: Buffer.byteLength(serialized, 'utf8'),
    payloadSha256: sha256(encoded),
    containsSensitiveData: false,
  };
  return { basename, chunks, manifest };
};

const createProtectedSsmStateStore = ({ inputs, protectedBindingSha256, journalLifecycle }) => {
  const candidateSha = inputs.freezeManifest.candidateSha;
  const states = new Map();
  const journals = new Map();
  const loadJournal = (scenarioId, bindingSha256) => {
    if (!/^RB-E7-(?:06|08)$/u.test(scenarioId)) fail('E7_PROTECTED_SCENARIO_INVALID');
    if (!SHA256.test(bindingSha256 ?? '')) fail('E7_PROTECTED_SSM_JOURNAL_BINDING_INVALID');
    revalidateProtectedIdentity({ inputs, protectedBindingSha256 });
    const prefix = `/checkout/stage7/rollback/${candidateSha}/${scenarioId}`;
    const beforeOwnership = listParametersByPath(prefix);
    const ownerParameterName = `${prefix}/owner`;
    const premutationAuthorityParameterName = `${prefix}/premutation-authority`;
    requireExistingJournalAuthority({
      parameters: beforeOwnership,
      ownerParameterName,
      premutationAuthorityParameterName,
    });
    const premutationAuthority = putImmutablePremutationAuthority({
      premutationAuthority: createRollbackSsmPremutationAuthority({
        inputs,
        scenarioId,
        bindingSha256,
        protectedBindingSha256,
        journalLifecycle,
      }),
      inputs,
    });
    const owner = putImmutableJournalOwner({
      owner: createRollbackJournalOwner({
        inputs,
        scenarioId,
        premutationAuthority,
        journalLifecycle,
      }),
      premutationAuthority,
      inputs,
    });
    const groups = journalGroups({
      prefix,
      parameters: listParametersByPath(prefix).filter(
        ({ Name }) => Name !== owner.parameterName && Name !== premutationAuthority.parameterName,
      ),
    });
    let previousStateSha256 = null;
    let lastState = null;
    let expectedSequence = 1;
    let incomplete = null;
    for (const group of groups) {
      if (group.sequence !== expectedSequence) fail('E7_PROTECTED_SSM_SEQUENCE_GAP');
      if (group.entries.has('abandoned')) {
        validateAbandonedJournalGroup(group, previousStateSha256);
        expectedSequence += 1;
        continue;
      }
      const state = decodeJournalGroup(group, previousStateSha256);
      if (state === null) {
        if (group !== groups.at(-1)) fail('E7_PROTECTED_SSM_INCOMPLETE_NOT_LAST');
        incomplete = group;
        break;
      }
      previousStateSha256 = state.stateSha256;
      lastState = state;
      expectedSequence += 1;
    }
    const journal = {
      prefix,
      nextSequence: expectedSequence,
      previousStateSha256,
      incomplete,
    };
    journals.set(scenarioId, journal);
    states.set(scenarioId, lastState);
    return lastState;
  };
  return {
    async load(scenarioId, bindingSha256) {
      return loadJournal(scenarioId, bindingSha256);
    },
    async save(scenarioId, state) {
      revalidateProtectedIdentity({ inputs, protectedBindingSha256 });
      const journal = journals.get(scenarioId);
      if (journal === undefined) fail('E7_PROTECTED_SSM_LOAD_REQUIRED');
      if (
        !object(state) ||
        state.scenarioId !== scenarioId ||
        state.containsSensitiveData !== false ||
        !SHA256.test(state.stateSha256 ?? '')
      ) {
        fail('E7_PROTECTED_SSM_STATE_INVALID');
      }
      const serialized = JSON.stringify(state);
      if (
        /(?:SecretString|SecretBinary|BEGIN [A-Z ]*PRIVATE KEY|(?:A3T|AKIA|ASIA)[A-Z0-9]{16})/u.test(
          serialized,
        )
      ) {
        fail('E7_PROTECTED_SSM_STATE_SENSITIVE');
      }
      const sequence = journal.nextSequence;
      const encodedEntry = encodeJournalState({
        state,
        sequence,
        previousStateSha256: journal.previousStateSha256,
      });
      const { basename, chunks, manifest } = encodedEntry;
      if (
        journal.incomplete !== null &&
        journal.incomplete.sequence === sequence &&
        journal.incomplete.stateSha256 !== state.stateSha256
      ) {
        const abandoned = {
          schemaVersion: 1,
          kind: 'ROLLBACK_RESILIENCE_SSM_JOURNAL_ABANDONED',
          sequence,
          stateSha256: journal.incomplete.stateSha256,
          previousStateSha256: journal.previousStateSha256,
          replacementStateSha256: state.stateSha256,
          containsSensitiveData: false,
        };
        putParameterWithoutOverwrite({
          name: `${journal.prefix}/${String(sequence).padStart(6, '0')}-${journal.incomplete.stateSha256}/abandoned`,
          value: JSON.stringify(abandoned),
        });
        journal.nextSequence += 1;
        journal.incomplete = null;
        return this.save(scenarioId, state);
      }
      if (
        journal.incomplete !== null &&
        (journal.incomplete.sequence !== sequence ||
          journal.incomplete.stateSha256 !== state.stateSha256)
      ) {
        fail('E7_PROTECTED_SSM_INCOMPLETE_STATE_CONFLICT');
      }
      for (const [index, value] of chunks.entries()) {
        putParameterWithoutOverwrite({
          name: `${journal.prefix}/${basename}/chunk-${String(index + 1).padStart(4, '0')}`,
          value,
        });
      }
      putParameterWithoutOverwrite({
        name: `${journal.prefix}/${basename}/manifest`,
        value: JSON.stringify(manifest),
      });
      journal.nextSequence += 1;
      journal.previousStateSha256 = state.stateSha256;
      journal.incomplete = null;
      states.set(scenarioId, state);
    },
  };
};

const normalizeStack = (stack) => {
  if (!object(stack)) fail('E7_PROTECTED_STACK_INVALID');
  return {
    stackName: stack.StackName,
    stackId: stack.StackId,
    stackStatus: stack.StackStatus,
    parameters: (stack.Parameters ?? []).map((entry) => ({
      key: entry.ParameterKey,
      value: entry.ParameterValue,
    })),
    capabilities: stack.Capabilities ?? [],
    roleArn: stack.RoleARN ?? null,
    tags: (stack.Tags ?? []).map((entry) => ({ key: entry.Key, value: entry.Value })),
  };
};

const describeStack = (stackName) => {
  const response = runAws(
    ['cloudformation', 'describe-stacks', '--stack-name', stackName],
    'E7_PROTECTED_STACK_DESCRIBE_FAILED',
  );
  if (!Array.isArray(response.Stacks) || response.Stacks.length !== 1) {
    fail('E7_PROTECTED_STACK_DESCRIBE_INVALID');
  }
  return { raw: response.Stacks[0], normalized: normalizeStack(response.Stacks[0]) };
};

const parseTemplateBody = (value) => {
  if (object(value)) return value;
  if (typeof value !== 'string' || value.length < 2 || value.length > MAX_AWS_OUTPUT_BYTES) {
    fail('E7_PROTECTED_TEMPLATE_INVALID');
  }
  try {
    const parsed = JSON.parse(value);
    if (!object(parsed)) fail('E7_PROTECTED_TEMPLATE_INVALID');
    return parsed;
  } catch {
    fail('E7_PROTECTED_TEMPLATE_NOT_JSON');
  }
};

const getTemplate = ({ stackName, changeSetName }) => {
  const args = ['cloudformation', 'get-template', '--stack-name', stackName];
  if (changeSetName !== undefined) args.push('--change-set-name', changeSetName);
  const response = runAws(args, 'E7_PROTECTED_GET_TEMPLATE_FAILED');
  return parseTemplateBody(response.TemplateBody);
};

const normalizedStackEvents = ({ stackName, clientRequestToken }) => {
  const response = runAws(
    ['cloudformation', 'describe-stack-events', '--stack-name', stackName],
    'E7_PROTECTED_STACK_EVENTS_FAILED',
  );
  if (!Array.isArray(response.StackEvents)) fail('E7_PROTECTED_STACK_EVENTS_INVALID');
  return response.StackEvents.filter(
    (event) => event.ClientRequestToken === clientRequestToken,
  ).map((event) => ({
    eventId: event.EventId,
    timestamp: utc(event.Timestamp),
    logicalResourceId: event.LogicalResourceId,
    resourceType: event.ResourceType,
    resourceStatus: event.ResourceStatus,
    resourceStatusReason: event.ResourceStatusReason ?? null,
    clientRequestToken: event.ClientRequestToken ?? null,
  }));
};

const preexistingChangeSet = ({ stackName, changeSetName, description }) => {
  const response = runAws(
    [
      'cloudformation',
      'describe-change-set',
      '--stack-name',
      stackName,
      '--change-set-name',
      changeSetName,
    ],
    'E7_PROTECTED_CHANGE_SET_DESCRIBE_FAILED',
    { allowFailure: true },
  );
  if (response === null) return null;
  if (response.Description !== description) fail('E7_PROTECTED_CHANGE_SET_NAME_COLLISION');
  return response;
};

const createChangeSet = ({ input, protectedDirectory }) => {
  const existing = preexistingChangeSet(input);
  if (existing !== null) return { changeSetId: existing.ChangeSetId, stackId: existing.StackId };
  const templateFilename = path.join(
    protectedDirectory,
    `rb06-${sha256(canonicalJson(input.templateBody))}.template.json`,
  );
  if (!lstatSafe(templateFilename)) {
    writeFileSync(templateFilename, canonicalJson(input.templateBody), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
  } else if (sha256(readFileSync(templateFilename)) !== sha256(canonicalJson(input.templateBody))) {
    fail('E7_PROTECTED_TEMPLATE_FILE_COLLISION');
  }
  const args = [
    'cloudformation',
    'create-change-set',
    '--stack-name',
    input.stackName,
    '--change-set-name',
    input.changeSetName,
    '--description',
    input.description,
    '--change-set-type',
    input.changeSetType,
    '--template-body',
    `file://${templateFilename}`,
    '--client-token',
    input.clientToken,
    '--no-include-nested-stacks',
  ];
  if (input.parameters.length > 0) {
    args.push(
      '--parameters',
      ...input.parameters.map((parameter) => `ParameterKey=${parameter.key},UsePreviousValue=true`),
    );
  }
  if (input.capabilities.length > 0) args.push('--capabilities', ...input.capabilities);
  if (input.roleArn !== null) args.push('--role-arn', input.roleArn);
  const response = runAws(args, 'E7_PROTECTED_CHANGE_SET_CREATE_FAILED');
  if (typeof response.Id !== 'string' || typeof response.StackId !== 'string') {
    fail('E7_PROTECTED_CHANGE_SET_CREATE_INVALID');
  }
  return { changeSetId: response.Id, stackId: response.StackId };
};

const lstatSafe = (filename) => {
  try {
    return lstatSync(filename).isFile();
  } catch {
    return false;
  }
};

const describeChangeSet = async ({ input }) => {
  let response;
  for (let poll = 0; poll < 24; poll += 1) {
    response = runAws(
      [
        'cloudformation',
        'describe-change-set',
        '--stack-name',
        input.stackName,
        '--change-set-name',
        input.changeSetName,
      ],
      'E7_PROTECTED_CHANGE_SET_DESCRIBE_FAILED',
    );
    if (response.Status === 'CREATE_COMPLETE') break;
    if (response.Status === 'FAILED' || poll === 23) {
      fail('E7_PROTECTED_CHANGE_SET_NOT_AVAILABLE');
    }
    await delay(5_000);
  }
  const template = getTemplate({
    stackName: input.stackName,
    changeSetName: response.ChangeSetId,
  });
  return {
    changeSetId: response.ChangeSetId,
    changeSetName: response.ChangeSetName,
    stackName: response.StackName,
    stackId: response.StackId,
    status: response.Status,
    executionStatus: response.ExecutionStatus,
    changeSetType: response.ChangeSetType,
    description: response.Description,
    includeNestedStacks: response.IncludeNestedStacks ?? false,
    templateSha256: objectSha256(template),
    parameters: (response.Parameters ?? []).map((entry) => ({
      key: entry.ParameterKey,
      value: entry.ParameterValue,
    })),
    capabilities: response.Capabilities ?? [],
    roleArn: response.RoleARN ?? null,
    changes: (response.Changes ?? []).map(({ ResourceChange }) => ({
      action: ResourceChange.Action,
      logicalResourceId: ResourceChange.LogicalResourceId,
      resourceType: ResourceChange.ResourceType,
      replacement: ResourceChange.Replacement ?? 'False',
    })),
  };
};

const normalizeAlarm = (alarm, descriptor) => {
  let reasonData;
  try {
    reasonData = JSON.parse(alarm.StateReasonData);
  } catch {
    fail('E7_PROTECTED_ALARM_REASON_DATA_INVALID');
  }
  const evaluated = Array.isArray(reasonData.evaluatedDatapoints)
    ? reasonData.evaluatedDatapoints
    : [];
  const recentDatapoints = evaluated.map((point) => ({
    timestamp: utc(point.timestamp),
    value: Number(point.value),
  }));
  if (alarm.StateValue === 'ALARM' && recentDatapoints.length === 0) {
    fail('E7_PROTECTED_ALARM_EVALUATED_DATAPOINT_MISSING');
  }
  const dimensionMap = new Map((alarm.Dimensions ?? []).map(({ Name, Value }) => [Name, Value]));
  return {
    alarmName: alarm.AlarmName,
    alarmArn: alarm.AlarmArn,
    stateValue: alarm.StateValue,
    stateUpdatedAtUtc: utc(alarm.StateUpdatedTimestamp),
    stateReason: alarm.StateReason,
    stateReasonData: {
      queryDate: utc(reasonData.queryDate),
      recentDatapoints,
      threshold: Number(reasonData.threshold),
    },
    namespace: alarm.Namespace,
    metricName: alarm.MetricName,
    dimensions: descriptor.dimensions.map(({ name }) => ({ name, value: dimensionMap.get(name) })),
    statistic: alarm.Statistic,
    unit: alarm.Unit,
    periodSeconds: alarm.Period,
    evaluationPeriods: alarm.EvaluationPeriods,
    threshold: alarm.Threshold,
    comparisonOperator: alarm.ComparisonOperator,
    treatMissingData: alarm.TreatMissingData,
    actionsEnabled: alarm.ActionsEnabled,
    alarmActions: alarm.AlarmActions ?? [],
    okActions: alarm.OKActions ?? [],
    insufficientDataActions: alarm.InsufficientDataActions ?? [],
  };
};

const verifyObservabilityBinding = ({ inputs, descriptor }) => {
  const observed = describeStack(descriptor.observabilityStackName).normalized;
  const tags = Object.fromEntries(observed.tags.map(({ key, value }) => [key, value]));
  const template = getTemplate({ stackName: descriptor.observabilityStackName });
  if (
    observed.stackStatus !== 'UPDATE_COMPLETE' ||
    tags.CandidateSha !== inputs.freezeManifest.candidateSha ||
    tags.ReleaseId !== inputs.freezeManifest.releaseId ||
    tags.Environment !== inputs.config.environment ||
    tags.ManagedBy !== 'cdk' ||
    observed.roleArn !== cloudFormationExecutionRoleArn(inputs) ||
    objectSha256(template) !== descriptor.observabilityTemplateSha256
  ) {
    fail('E7_PROTECTED_OBSERVABILITY_BINDING_DRIFT');
  }
};

const dynamoString = (item, name) => {
  const value = item?.[name];
  if (!exactKeys(value, ['S']) || typeof value.S !== 'string' || value.S === '') {
    fail('E7_PROTECTED_PENDING_ITEM_INVALID');
  }
  return value.S;
};

const checkoutTableName = (inputs) => {
  const stackName = `checkout-${inputs.config.environment}-data`;
  const { raw } = describeStack(stackName);
  const outputs = Object.fromEntries(
    (raw.Outputs ?? []).map(({ OutputKey, OutputValue }) => [OutputKey, OutputValue]),
  );
  if (
    typeof outputs.CheckoutTableName !== 'string' ||
    outputs.CandidateSha !== inputs.freezeManifest.candidateSha ||
    outputs.ReleaseId !== inputs.freezeManifest.releaseId
  ) {
    fail('E7_PROTECTED_PENDING_STACK_BINDING_INVALID');
  }
  return outputs.CheckoutTableName;
};

const capturePending = ({ inputs, bindingSha256, requestInput, before }) => {
  const tableName = checkoutTableName(inputs);
  const response = runAws(
    [
      'dynamodb',
      'query',
      '--table-name',
      tableName,
      '--index-name',
      PENDING_INDEX_NAME,
      '--key-condition-expression',
      '#pending = :pending',
      '--expression-attribute-names',
      JSON.stringify({ '#pending': 'GSI2PK' }),
      '--expression-attribute-values',
      JSON.stringify({ ':pending': { S: PENDING_INDEX_PARTITION } }),
      '--projection-expression',
      'PK, SK, acceptedAt, paymentStatus',
      '--scan-index-forward',
    ],
    'E7_PROTECTED_PENDING_QUERY_FAILED',
  );
  if (
    !Array.isArray(response.Items) ||
    response.LastEvaluatedKey !== undefined ||
    response.NextToken !== undefined
  ) {
    fail('E7_PROTECTED_PENDING_QUERY_INCOMPLETE');
  }
  const privateItems = response.Items.map((item) => {
    if (dynamoString(item, 'paymentStatus') !== 'PENDING') {
      fail('E7_PROTECTED_PENDING_STATUS_INVALID');
    }
    return {
      PK: dynamoString(item, 'PK'),
      SK: dynamoString(item, 'SK'),
      acceptedAt: utc(dynamoString(item, 'acceptedAt')),
    };
  });
  if (privateItems.some(({ acceptedAt }) => acceptedAt === null)) {
    fail('E7_PROTECTED_PENDING_TIMESTAMP_INVALID');
  }
  privateItems.sort((left, right) =>
    `${left.PK}\0${left.SK}`.localeCompare(`${right.PK}\0${right.SK}`),
  );
  if (new Set(privateItems.map(({ PK, SK }) => `${PK}\0${SK}`)).size !== privateItems.length) {
    fail('E7_PROTECTED_PENDING_DUPLICATE');
  }
  const publicItems = privateItems.map(({ PK, SK, acceptedAt }) => ({
    keySha256: sha256(`${PK}\0${SK}`),
    acceptedAt,
  }));
  const snapshotSha256 = objectSha256(publicItems);
  const baseline = inputs.baseRehearsal.rollback.plan.pendingBaseline;
  if (
    privateItems.length !== baseline.trackedCount ||
    snapshotSha256 !== baseline.snapshotSha256 ||
    (before
      ? requestInput.pendingBaselineSha256 !== baseline.snapshotSha256
      : requestInput.beforeSnapshotSha256 !== snapshotSha256)
  ) {
    fail('E7_PROTECTED_PENDING_BASELINE_DRIFT');
  }
  return {
    status: before ? 'PENDING_OBSERVED' : 'PASS',
    trackedBefore: privateItems.length,
    stillPending: privateItems.length,
    reconciled: 0,
    orphaned: 0,
    duplicateEffects: 0,
    lostFacts: 0,
    snapshotSha256,
    baselineEvidenceSha256: baseline.snapshotSha256,
    correlationEvidenceSha256: objectSha256({
      bindingSha256,
      tableNameSha256: sha256(tableName),
      snapshotSha256,
      keys: publicItems.map(({ keySha256 }) => keySha256),
    }),
    dataFactsSha256: inputs.baseRehearsal.rollback.plan.dataFactsSha256,
    dataRollbackPerformed: false,
  };
};

const bodyBytes = async (response) => {
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length < 1 || bytes.length > 2 * 1024 * 1024) {
    fail('E7_PROTECTED_HTTP_BODY_INVALID');
  }
  return bytes;
};

const requiredSecurityHeaders = (response) => {
  const headers = {
    cacheControl: response.headers.get('cache-control'),
    contentSecurityPolicy: response.headers.get('content-security-policy'),
    contentTypeOptions: response.headers.get('x-content-type-options'),
    frameOptions: response.headers.get('x-frame-options'),
    permissionsPolicy: response.headers.get('permissions-policy'),
    referrerPolicy: response.headers.get('referrer-policy'),
    strictTransportSecurity: response.headers.get('strict-transport-security'),
  };
  if (
    !/^no-store(?:,|$)/iu.test(headers.cacheControl ?? '') ||
    !/default-src 'self'/u.test(headers.contentSecurityPolicy ?? '') ||
    headers.contentTypeOptions?.toLowerCase() !== 'nosniff' ||
    headers.frameOptions?.toUpperCase() !== 'DENY' ||
    headers.permissionsPolicy !== 'camera=(), geolocation=(), microphone=(), payment=()' ||
    headers.referrerPolicy?.toLowerCase() !== 'same-origin' ||
    !/^max-age=31536000;\s*includeSubDomains$/iu.test(headers.strictTransportSecurity ?? '')
  ) {
    fail('E7_PROTECTED_STATIC_SECURITY_HEADERS_INVALID');
  }
  return headers;
};

const validateReadinessResponse = ({ response, bytes }) => {
  let body;
  try {
    body = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('E7_PROTECTED_READINESS_BODY_INVALID');
  }
  const contentType = response.headers.get('content-type');
  const cacheControl = response.headers.get('cache-control');
  const correlationId = response.headers.get('x-correlation-id');
  if (
    response.status !== 200 ||
    !/^application\/json(?:;|$)/iu.test(contentType ?? '') ||
    !/^no-store(?:,|$)/iu.test(cacheControl ?? '') ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(
      correlationId ?? '',
    ) ||
    !exactKeys(body, ['status', 'checkedAt']) ||
    body.status !== 'ok' ||
    utc(body.checkedAt) !== body.checkedAt
  ) {
    fail('E7_PROTECTED_READINESS_RESPONSE_INVALID');
  }
  return {
    contentType,
    cacheControl,
    correlationIdSha256: sha256(correlationId),
    checkedAtUtc: body.checkedAt,
  };
};

const validateStaticResponse = ({ response, bytes, path: pathname }) => {
  const contentType = response.headers.get('content-type');
  const headers = requiredSecurityHeaders(response);
  if (response.status !== 200) fail('E7_PROTECTED_STATIC_RESPONSE_INVALID');
  if (pathname === '/index.html') {
    const body = bytes.toString('utf8');
    if (
      !/^text\/html(?:;|$)/iu.test(contentType ?? '') ||
      !/<div[^>]+id=["']root["']/iu.test(body)
    ) {
      fail('E7_PROTECTED_STATIC_RESPONSE_INVALID');
    }
  } else {
    let body;
    try {
      body = JSON.parse(bytes.toString('utf8'));
    } catch {
      fail('E7_PROTECTED_STATIC_RESPONSE_INVALID');
    }
    if (
      !/^application\/json(?:;|$)/iu.test(contentType ?? '') ||
      !exactKeys(body, ['apiBaseUrl', 'productId']) ||
      body.apiBaseUrl !== '/api/v1' ||
      body.productId !== 'product-demo-001'
    ) {
      fail('E7_PROTECTED_STATIC_RESPONSE_INVALID');
    }
  }
  return { contentType, headersSha256: objectSha256(headers) };
};

const runReadSmoke = async ({ inputs, releaseId, registerExternalRequest }) => {
  const expected =
    releaseId === inputs.freezeManifest.releaseId
      ? inputs.candidateRecord.resources
      : releaseId === inputs.previousReleaseManifest.previous.releaseId
        ? inputs.previousReleaseManifest.resources
        : null;
  if (expected === null) fail('E7_PROTECTED_SMOKE_RELEASE_INVALID');
  const expectedObjects = new Map(expected.web.objects.map((entry) => [entry.key, entry]));
  const checks = [
    { path: '/index.html', object: expectedObjects.get('index.html') },
    { path: '/public-config.json', object: expectedObjects.get('public-config.json') },
    { path: '/api/health/ready', object: null },
  ];
  if (checks.slice(0, 2).some((entry) => entry.object === undefined)) {
    fail('E7_PROTECTED_SMOKE_OBJECT_BINDING_MISSING');
  }
  const observations = [];
  for (const check of checks) {
    registerExternalRequest();
    const response = await globalThis.fetch(
      `https://${inputs.config.domain.hostname}${check.path}`,
      {
        headers: { accept: check.object === null ? 'application/json' : '*/*' },
        method: 'GET',
        redirect: 'error',
        signal: globalThis.AbortSignal.timeout(15_000),
      },
    );
    const bytes = await bodyBytes(response);
    const bodySha256 = sha256(bytes);
    const responseContract =
      check.object === null
        ? validateReadinessResponse({ response, bytes })
        : validateStaticResponse({ response, bytes, path: check.path });
    if (
      response.status !== 200 ||
      (check.object !== null &&
        (bodySha256 !== check.object.contentSha256 || bytes.length !== check.object.bytes))
    ) {
      fail('E7_PROTECTED_SMOKE_FAILED');
    }
    observations.push({
      path: check.path,
      status: response.status,
      bytes: bytes.length,
      bodySha256,
      responseContract,
    });
  }
  return {
    status: 'PASS',
    releaseId,
    total: 3,
    passed: 3,
    failed: 0,
    dataMutations: 0,
    externalRequests: 3,
    authorizationUsageId: 'ROLLBACK_RESILIENCE',
    evidenceSha256: objectSha256(observations),
  };
};

const invokeVersion = ({ protectedDirectory, functionName, version, token }) => {
  const nonce = sha256(
    `${functionName}\0${version}\0${token === null ? 'direct' : 'origin'}`,
  ).slice(0, 24);
  const requestFile = path.join(protectedDirectory, `lambda-request-${nonce}.json`);
  const responseFile = path.join(protectedDirectory, `lambda-response-${nonce}.json`);
  const event = {
    version: '2.0',
    routeKey: 'GET /api/health/ready',
    rawPath: '/api/health/ready',
    rawQueryString: '',
    headers: token === null ? {} : { [ORIGIN_HEADER]: token },
    requestContext: {
      accountId: 'anonymous',
      apiId: 'stage7-rehearsal',
      domainName: 'stage7-rehearsal',
      domainPrefix: 'stage7-rehearsal',
      http: {
        method: 'GET',
        path: '/api/health/ready',
        protocol: 'HTTP/1.1',
        sourceIp: '127.0.0.1',
        userAgent: 'stage7-rollback-rehearsal',
      },
      requestId: `stage7-${nonce}`,
      routeKey: 'GET /api/health/ready',
      stage: '$default',
      time: '01/Jan/1970:00:00:00 +0000',
      timeEpoch: 0,
    },
    isBase64Encoded: false,
  };
  try {
    writeFileSync(requestFile, JSON.stringify(event), {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    const metadata = runAws(
      [
        'lambda',
        'invoke',
        '--function-name',
        functionName,
        '--qualifier',
        version,
        '--cli-binary-format',
        'raw-in-base64-out',
        '--payload',
        `fileb://${requestFile}`,
      ],
      'E7_PROTECTED_LAMBDA_INVOKE_FAILED',
      { outputFile: responseFile },
    );
    void metadata;
    const response = JSON.parse(readFileSync(responseFile, 'utf8'));
    if (!Number.isSafeInteger(response.statusCode)) fail('E7_PROTECTED_LAMBDA_RESPONSE_INVALID');
    return response.statusCode;
  } finally {
    rmSync(requestFile, { force: true });
    rmSync(responseFile, { force: true });
  }
};

const originConfiguration = ({ inputs, resource, previous }) => {
  const response = runAws(
    [
      'lambda',
      'get-function-configuration',
      '--function-name',
      resource.functionName,
      '--qualifier',
      resource.version,
    ],
    'E7_PROTECTED_ORIGIN_FUNCTION_CONFIG_FAILED',
  );
  const variables = response.Environment?.Variables;
  const modeValid = originModeCompatible({
    actual: variables?.PRERELEASE_ACCESS_MODE,
    previous,
  });
  if (
    !object(variables) ||
    !modeValid ||
    variables.RUNTIME_SECRET_ARN !== inputs.config.prereleaseAccess.originTokenSecretArn ||
    variables.RUNTIME_SECRET_VERSION_ID !==
      inputs.config.prereleaseAccess.originTokenSecretVersionId
  ) {
    fail('E7_PROTECTED_ORIGIN_FUNCTION_DRIFT');
  }
  return {
    originGateRequired: true,
    headerNameSha256: sha256(ORIGIN_HEADER),
    secretReferenceSha256: sha256(variables.RUNTIME_SECRET_ARN),
    secretVersionIdSha256: sha256(variables.RUNTIME_SECRET_VERSION_ID),
  };
};

const getOriginToken = (inputs) => {
  const secretArn = inputs.config.prereleaseAccess.originTokenSecretArn;
  const versionId = inputs.config.prereleaseAccess.originTokenSecretVersionId;
  const described = runAws(
    ['secretsmanager', 'describe-secret', '--secret-id', secretArn],
    'E7_PROTECTED_ORIGIN_SECRET_DESCRIBE_FAILED',
  );
  const current = Object.entries(described.VersionIdsToStages ?? {}).filter(([, stages]) =>
    stages.includes('AWSCURRENT'),
  );
  if (described.ARN !== secretArn || current.length !== 1 || current[0][0] !== versionId) {
    fail('E7_PROTECTED_ORIGIN_SECRET_VERSION_DRIFT');
  }
  const value = runAws(
    [
      'secretsmanager',
      'get-secret-value',
      '--secret-id',
      secretArn,
      '--version-id',
      versionId,
      '--version-stage',
      'AWSCURRENT',
    ],
    'E7_PROTECTED_ORIGIN_SECRET_READ_FAILED',
  );
  if (
    value.ARN !== secretArn ||
    value.VersionId !== versionId ||
    typeof value.SecretString !== 'string' ||
    value.SecretString.length < 16 ||
    value.SecretString.length > 65_536
  ) {
    fail('E7_PROTECTED_ORIGIN_SECRET_VALUE_INVALID');
  }
  let parsed;
  try {
    parsed = JSON.parse(value.SecretString);
  } catch {
    parsed = null;
  }
  const token = parsed?.prereleaseOriginToken;
  if (typeof token !== 'string' || token.length < 32 || token.length > 4096) {
    fail('E7_PROTECTED_ORIGIN_TOKEN_INVALID');
  }
  return token;
};

const verifyOriginProtection = async ({ inputs, protectedDirectory, registerExternalRequest }) => {
  const candidate = inputs.candidateRecord.resources.api;
  const previous = inputs.previousReleaseManifest.resources.api;
  if (
    candidate.functionName !== previous.functionName ||
    candidate.aliasName !== previous.aliasName
  ) {
    fail('E7_PROTECTED_ORIGIN_FUNCTION_IDENTITY_DRIFT');
  }
  const candidateContract = originConfiguration({ inputs, resource: candidate, previous: false });
  const previousContract = originConfiguration({ inputs, resource: previous, previous: true });
  if (canonicalJson(candidateContract) !== canonicalJson(previousContract)) {
    fail('E7_PROTECTED_ORIGIN_CONTRACT_DRIFT');
  }
  const token = getOriginToken(inputs);
  const candidateDirectApiStatus = invokeVersion({
    protectedDirectory,
    functionName: candidate.functionName,
    version: candidate.version,
    token: null,
  });
  const previousDirectApiStatus = invokeVersion({
    protectedDirectory,
    functionName: previous.functionName,
    version: previous.version,
    token: null,
  });
  const candidateViaCloudFrontStatus = invokeVersion({
    protectedDirectory,
    functionName: candidate.functionName,
    version: candidate.version,
    token,
  });
  const previousViaCloudFrontStatus = invokeVersion({
    protectedDirectory,
    functionName: previous.functionName,
    version: previous.version,
    token,
  });
  registerExternalRequest();
  const publicResponse = await globalThis.fetch(
    `https://${inputs.config.domain.hostname}/api/health/ready`,
    {
      headers: { accept: 'application/json' },
      method: 'GET',
      redirect: 'error',
      signal: globalThis.AbortSignal.timeout(15_000),
    },
  );
  const publicBytes = await bodyBytes(publicResponse);
  validateReadinessResponse({ response: publicResponse, bytes: publicBytes });
  const contractSha256 = objectSha256({
    ...candidateContract,
    actualCloudFrontStatus: publicResponse.status,
  });
  const body = {
    status: 'PASS',
    candidateReleaseId: inputs.freezeManifest.releaseId,
    previousReleaseId: inputs.previousReleaseManifest.previous.releaseId,
    headerNameSha256: sha256(ORIGIN_HEADER),
    candidateSecretReferenceSha256: candidateContract.secretReferenceSha256,
    previousSecretReferenceSha256: previousContract.secretReferenceSha256,
    candidateSecretVersionIdSha256: candidateContract.secretVersionIdSha256,
    previousSecretVersionIdSha256: previousContract.secretVersionIdSha256,
    candidateContractSha256: contractSha256,
    previousContractSha256: contractSha256,
    candidateDirectApiStatus,
    previousDirectApiStatus,
    candidateViaCloudFrontStatus,
    previousViaCloudFrontStatus,
    externalRequests: 1,
    authorizationUsageId: 'ROLLBACK_RESILIENCE',
  };
  return { ...body, evidenceSha256: objectSha256(body) };
};

const readActiveObject = ({ inputs, protectedDirectory, bucketName, key }) => {
  const target = path.join(protectedDirectory, `s3-${sha256(`${bucketName}\0${key}`)}.body`);
  rmSync(target, { force: true });
  let response;
  let bytes;
  try {
    response = runAws(
      ['s3api', 'get-object', '--bucket', bucketName, '--key', key],
      'E7_PROTECTED_S3_GET_FAILED',
      { outputFile: target },
    );
    void response;
    bytes = readFileSync(target);
  } finally {
    rmSync(target, { force: true });
  }
  if (bytes === undefined || bytes.length < 1) fail('E7_PROTECTED_S3_BODY_INVALID');
  const contentSha256 = sha256(bytes);
  const candidates = [
    ...inputs.previousReleaseManifest.resources.web.objects,
    ...inputs.candidateRecord.resources.web.objects,
  ].filter(
    (entry) =>
      entry.key === key && entry.contentSha256 === contentSha256 && entry.bytes === bytes.length,
  );
  const sourceVersionIds = [...new Set(candidates.map((entry) => entry.versionId))];
  if (sourceVersionIds.length !== 1) fail('E7_PROTECTED_S3_SOURCE_VERSION_AMBIGUOUS');
  const head = runAws(
    ['s3api', 'head-object', '--bucket', bucketName, '--key', key],
    'E7_PROTECTED_S3_HEAD_FAILED',
  );
  if (typeof head.VersionId !== 'string' || head.VersionId.length < 3) {
    fail('E7_PROTECTED_S3_ACTIVE_VERSION_INVALID');
  }
  return {
    bucketName,
    key,
    activeVersionId: head.VersionId,
    sourceVersionId: sourceVersionIds[0],
    contentSha256,
    bytes: bytes.length,
  };
};

const restoreVersionedObject = ({ inputs, protectedDirectory, input }) => {
  const encodedKey = input.key.split('/').map(encodeURIComponent).join('/');
  const copySource = `${input.bucketName}/${encodedKey}?versionId=${encodeURIComponent(input.sourceVersionId)}`;
  const response = runAws(
    [
      's3api',
      'copy-object',
      '--bucket',
      input.bucketName,
      '--key',
      input.key,
      '--copy-source',
      copySource,
      '--metadata-directive',
      'COPY',
    ],
    'E7_PROTECTED_S3_COPY_FAILED',
  );
  if (typeof response.VersionId !== 'string' || response.VersionId.length < 3) {
    fail('E7_PROTECTED_S3_COPY_VERSION_INVALID');
  }
  const observed = readActiveObject({
    inputs,
    protectedDirectory,
    bucketName: input.bucketName,
    key: input.key,
  });
  if (
    observed.activeVersionId !== response.VersionId ||
    observed.sourceVersionId !== input.sourceVersionId ||
    observed.contentSha256 !== input.expectedContentSha256
  ) {
    fail('E7_PROTECTED_S3_COPY_VERIFY_FAILED');
  }
  return observed;
};

const describeAlias = (input) => {
  const response = runAws(
    ['lambda', 'get-alias', '--function-name', input.functionName, '--name', input.aliasName],
    'E7_PROTECTED_ALIAS_GET_FAILED',
  );
  return {
    functionName: input.functionName,
    aliasName: response.Name,
    functionVersion: response.FunctionVersion,
    revisionId: response.RevisionId,
  };
};

const updateAlias = (input) => {
  const response = runAws(
    [
      'lambda',
      'update-alias',
      '--function-name',
      input.functionName,
      '--name',
      input.aliasName,
      '--function-version',
      input.functionVersion,
      '--revision-id',
      input.revisionId,
    ],
    'E7_PROTECTED_ALIAS_UPDATE_FAILED',
  );
  return {
    functionName: input.functionName,
    aliasName: response.Name,
    functionVersion: response.FunctionVersion,
    revisionId: response.RevisionId,
  };
};

const matchingInvalidation = (input) => {
  const listed = runAws(
    ['cloudfront', 'list-invalidations', '--distribution-id', input.distributionId],
    'E7_PROTECTED_INVALIDATION_LIST_FAILED',
  );
  const summaries = listed.InvalidationList?.Items ?? [];
  if (!Array.isArray(summaries) || summaries.length > 1000) {
    fail('E7_PROTECTED_INVALIDATION_LIST_INVALID');
  }
  for (const summary of summaries) {
    if (typeof summary.Id !== 'string') fail('E7_PROTECTED_INVALIDATION_LIST_INVALID');
    const observed = getInvalidation({
      distributionId: input.distributionId,
      invalidationId: summary.Id,
    });
    if (observed.callerReference === input.callerReference) {
      if (observed.paths.join('\0') !== input.paths.join('\0')) {
        fail('E7_PROTECTED_INVALIDATION_CALLER_COLLISION');
      }
      return observed;
    }
  }
  return null;
};

const createInvalidation = (input) => {
  const existing = matchingInvalidation(input);
  if (existing !== null) return existing;
  const response = runAws(
    [
      'cloudfront',
      'create-invalidation',
      '--distribution-id',
      input.distributionId,
      '--invalidation-batch',
      JSON.stringify({
        CallerReference: input.callerReference,
        Paths: { Quantity: input.paths.length, Items: input.paths },
      }),
    ],
    'E7_PROTECTED_INVALIDATION_CREATE_FAILED',
    { allowFailure: true },
  );
  if (response === null) {
    const raced = matchingInvalidation(input);
    if (raced !== null) return raced;
    fail('E7_PROTECTED_INVALIDATION_CREATE_FAILED');
  }
  const invalidation = response.Invalidation;
  return {
    distributionId: input.distributionId,
    invalidationId: invalidation?.Id,
    callerReference: invalidation?.InvalidationBatch?.CallerReference,
    paths: invalidation?.InvalidationBatch?.Paths?.Items ?? [],
    status: invalidation?.Status,
  };
};

const getInvalidation = (input) => {
  const response = runAws(
    [
      'cloudfront',
      'get-invalidation',
      '--distribution-id',
      input.distributionId,
      '--id',
      input.invalidationId,
    ],
    'E7_PROTECTED_INVALIDATION_GET_FAILED',
  );
  const invalidation = response.Invalidation;
  return {
    distributionId: input.distributionId,
    invalidationId: invalidation?.Id,
    callerReference: invalidation?.InvalidationBatch?.CallerReference,
    paths: invalidation?.InvalidationBatch?.Paths?.Items ?? [],
    status: invalidation?.Status,
  };
};

const waitUntilTimestamp = async (timestampUtc) => {
  while (Date.now() < Date.parse(timestampUtc)) {
    await delay(Math.min(15_000, Date.parse(timestampUtc) - Date.now()));
  }
};

const metricDatapointAlreadyPresent = (input) => {
  const [datum] = input.metricData;
  const timestamp = Date.parse(datum.timestampUtc);
  const response = runAws(
    [
      'cloudwatch',
      'get-metric-statistics',
      '--namespace',
      input.namespace,
      '--metric-name',
      datum.metricName,
      '--dimensions',
      JSON.stringify(datum.dimensions.map(({ name, value }) => ({ Name: name, Value: value }))),
      '--start-time',
      new Date(timestamp - 60_000).toISOString(),
      '--end-time',
      new Date(timestamp + 60_000).toISOString(),
      '--period',
      '60',
      '--statistics',
      'Maximum',
      'Minimum',
      'SampleCount',
      'Sum',
    ],
    'E7_PROTECTED_METRIC_READ_FAILED',
  );
  if (!Array.isArray(response.Datapoints)) fail('E7_PROTECTED_METRIC_READ_INVALID');
  return response.Datapoints.some(
    (point) =>
      Math.abs(Date.parse(point.Timestamp) - timestamp) < 60_000 &&
      point.Maximum === datum.value &&
      point.Minimum === datum.value &&
      Number(point.SampleCount) >= 1 &&
      Number(point.Sum) === datum.value * Number(point.SampleCount),
  );
};

const putMetricData = async (input) => {
  const [datum] = input.metricData;
  await waitUntilTimestamp(datum.timestampUtc);
  if (metricDatapointAlreadyPresent(input)) return {};
  const response = runAws(
    [
      'cloudwatch',
      'put-metric-data',
      '--namespace',
      input.namespace,
      '--metric-data',
      JSON.stringify(
        input.metricData.map((entry) => ({
          MetricName: entry.metricName,
          Dimensions: entry.dimensions.map(({ name, value }) => ({ Name: name, Value: value })),
          Timestamp: entry.timestampUtc,
          Value: entry.value,
          Unit: entry.unit,
        })),
      ),
    ],
    'E7_PROTECTED_PUT_METRIC_DATA_FAILED',
  );
  if (Object.keys(response).length !== 0) fail('E7_PROTECTED_PUT_METRIC_DATA_INVALID');
  return {};
};

const createProtectedExecutor = ({
  inputs,
  rb08Descriptor,
  protectedDirectory,
  protectedBindingSha256,
}) => {
  let observations = 0;
  let observabilityBound = false;
  let authorizationBudget;
  try {
    authorizationBudget = JSON.parse(inputs.documents.authorizationBudget.content);
  } catch {
    fail('E7_PROTECTED_AUTHORIZATION_BUDGET_INVALID');
  }
  if (
    authorizationBudget?.status !== 'RESERVED_BEFORE_EXTERNAL_REQUESTS' ||
    authorizationBudget?.reservedUsage?.usageId !== 'ROLLBACK_RESILIENCE' ||
    authorizationBudget?.reservedUsage?.requestCounts?.['AUTH-E7-EXT-01'] !== 11 ||
    authorizationBudget?.reservedExternalRequests !== 11 ||
    Object.entries(authorizationBudget?.finalTotals ?? {}).some(
      ([id, count]) => count > authorizationBudget.requestLimits?.[id],
    )
  ) {
    fail('E7_PROTECTED_AUTHORIZATION_BUDGET_INVALID');
  }
  let ownedExternalRequests = 0;
  const registerExternalRequest = () => {
    if (ownedExternalRequests >= authorizationBudget.reservedExternalRequests) {
      fail('E7_PROTECTED_EXTERNAL_AUTHORIZATION_EXHAUSTED');
    }
    ownedExternalRequests += 1;
  };
  return async (request) => {
    revalidateProtectedIdentity({ inputs, protectedBindingSha256 });
    let payload;
    const key = `${request.service}.${request.operation}`;
    switch (key) {
      case 'cloudformation.DescribeStacks': {
        const stack = describeStack(request.input.stackName).normalized;
        payload = { stack, events: [] };
        break;
      }
      case 'cloudformation.GetTemplate':
        payload = {
          templateBody: getTemplate({ stackName: request.input.stackName }),
        };
        break;
      case 'cloudformation.CreateChangeSet':
        payload = createChangeSet({ input: request.input, protectedDirectory });
        break;
      case 'cloudformation.DescribeChangeSet':
        payload = await describeChangeSet({ input: request.input });
        break;
      case 'cloudformation.GetTemplateForChangeSet':
        payload = {
          templateBody: getTemplate({
            stackName: request.input.stackName,
            changeSetName: request.input.changeSetName,
          }),
        };
        break;
      case 'cloudformation.DescribeStackEvents': {
        await delay(5_000);
        const stack = describeStack(request.input.stackName).normalized;
        const events = normalizedStackEvents(request.input);
        payload = { stack, events };
        break;
      }
      case 'cloudformation.ExecuteChangeSet': {
        const response = runAws(
          [
            'cloudformation',
            'execute-change-set',
            '--change-set-name',
            request.input.changeSetName,
            '--stack-name',
            request.input.stackName,
            '--client-request-token',
            request.input.clientRequestToken,
          ],
          'E7_PROTECTED_CHANGE_SET_EXECUTE_FAILED',
        );
        if (Object.keys(response).length !== 0) fail('E7_PROTECTED_CHANGE_SET_EXECUTE_INVALID');
        payload = {};
        break;
      }
      case 'cloudwatch.DescribeAlarmsBeforeActivation':
      case 'cloudwatch.DescribeAlarmsAfterActivation':
      case 'cloudwatch.DescribeAlarmsAfterRollback': {
        if (!observabilityBound) {
          verifyObservabilityBinding({ inputs, descriptor: rb08Descriptor });
          observabilityBound = true;
        }
        if (request.operation !== 'DescribeAlarmsBeforeActivation') await delay(15_000);
        const response = runAws(
          ['cloudwatch', 'describe-alarms', '--alarm-names', ...request.input.alarmNames],
          'E7_PROTECTED_ALARM_DESCRIBE_FAILED',
        );
        if (!Array.isArray(response.MetricAlarms) || response.MetricAlarms.length !== 1) {
          fail('E7_PROTECTED_ALARM_DESCRIBE_INVALID');
        }
        payload = { metricAlarms: [normalizeAlarm(response.MetricAlarms[0], rb08Descriptor)] };
        break;
      }
      case 'cloudwatch.PutMetricData':
      case 'cloudwatch.PutRecoveryMetricData':
        payload = await putMetricData(request.input);
        break;
      case 'lambda.GetAlias':
      case 'lambda.GetAliasForRepromotion':
        payload = describeAlias(request.input);
        break;
      case 'lambda.UpdateAlias':
      case 'lambda.UpdateAliasForRepromotion':
        payload = updateAlias(request.input);
        break;
      case 'stage7-s3-integrity.InspectActiveObject':
      case 'stage7-s3-integrity.InspectActiveObjectForRepromotion':
        payload = readActiveObject({
          inputs,
          protectedDirectory,
          bucketName: request.input.bucketName,
          key: request.input.key,
        });
        break;
      case 's3.RestoreVersionedObject':
      case 's3.RestoreVersionedObjectForRepromotion':
        payload = restoreVersionedObject({ inputs, protectedDirectory, input: request.input });
        break;
      case 'cloudfront.CreateInvalidation':
      case 'cloudfront.CreateInvalidationForRepromotion':
        payload = createInvalidation(request.input);
        break;
      case 'cloudfront.GetInvalidation':
      case 'cloudfront.GetInvalidationForRepromotion':
        await delay(5_000);
        payload = getInvalidation(request.input);
        break;
      case 'stage7-pending-integrity.ReadBeforeFailureMutation':
      case 'stage7-pending-integrity.ReadBeforeAlarmDecision':
        payload = capturePending({
          inputs,
          bindingSha256: request.bindingSha256,
          requestInput: request.input,
          before: true,
        });
        break;
      case 'stage7-pending-integrity.ReadAfterCloudFormationRecovery':
      case 'stage7-pending-integrity.ReadAfterAlarmRollback':
      case 'stage7-pending-integrity.ReadAfterAlarmRepromotion':
        payload = capturePending({
          inputs,
          bindingSha256: request.bindingSha256,
          requestInput: request.input,
          before: false,
        });
        break;
      case 'stage7-read-smoke.RunAfterCloudFormationRecovery':
      case 'stage7-read-smoke.RunAfterAlarmRollback':
      case 'stage7-read-smoke.RunAfterAlarmRepromotion':
        payload = await runReadSmoke({
          inputs,
          releaseId: request.input.releaseId,
          registerExternalRequest,
        });
        break;
      case 'stage7-origin-protection.VerifyNAndNMinus1Compatibility':
        payload = await verifyOriginProtection({
          inputs,
          protectedDirectory,
          registerExternalRequest,
        });
        break;
      default:
        fail('E7_PROTECTED_EXECUTOR_OPERATION_FORBIDDEN');
    }
    observations += 1;
    const observedAtUtc = new Date().toISOString();
    if (
      Date.parse(observedAtUtc) < Date.parse(inputs.execution.startedAtUtc) ||
      Date.parse(observedAtUtc) > Date.parse(inputs.config.window.endsAtUtc)
    ) {
      fail('E7_PROTECTED_OBSERVATION_OUTSIDE_WINDOW');
    }
    return {
      source: request.service.startsWith('stage7-')
        ? 'DEPLOYED_OBSERVATION_RESPONSE'
        : 'AWS_CLI_RESPONSE',
      requestId: `protected-observation-${String(observations).padStart(6, '0')}-${objectSha256(payload).slice(0, 16)}`,
      observedAtUtc,
      payload,
    };
  };
};

export const createProtectedRollbackRuntime = async (options) => {
  if (
    !exactKeys(options, ['inputsWithoutExecution', 'rb06Descriptor', 'rb08Descriptor']) ||
    !object(options.inputsWithoutExecution) ||
    Object.hasOwn(options.inputsWithoutExecution, 'execution') ||
    !object(options.rb06Descriptor) ||
    !object(options.rb08Descriptor)
  ) {
    fail('E7_PROTECTED_RUNTIME_OPTIONS_INVALID');
  }
  const execution = executionFromProtectedEnvironment(options.inputsWithoutExecution);
  const protectedBindingSha256 = requireProtectedBindingEnvironment({
    inputsWithoutExecution: options.inputsWithoutExecution,
    execution,
  });
  const inputs = { ...options.inputsWithoutExecution, execution };
  const awsCliVersionSha256 = verifyAwsCliVersion(inputs.freezeManifest.toolchain.awsCli);
  const identity = revalidateProtectedIdentity({ inputs, protectedBindingSha256 });
  const journalLifecycle = createRollbackJournalLifecycle(inputs);
  const protectedDirectory = resolveProtectedDirectory(inputs.freezeManifest.candidateSha);
  const stateStore = createProtectedSsmStateStore({
    inputs,
    protectedBindingSha256,
    journalLifecycle,
  });
  const executor = createProtectedExecutor({
    inputs,
    rb08Descriptor: options.rb08Descriptor,
    protectedDirectory,
    protectedBindingSha256,
  });
  const attestationBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_PROTECTED_RUNTIME_ATTESTATION',
    status: 'AWS_IDENTITY_REVALIDATED',
    repository: execution.repository,
    workflow: execution.workflow,
    runId: execution.runId,
    runAttempt: execution.runAttempt,
    githubSha: execution.githubSha,
    protectedEnvironment: execution.protectedEnvironment,
    protectedBindingSha256,
    executionSha256: objectSha256(execution),
    identity,
    awsCliVersionSha256,
    journalPrefixSha256: sha256(`/checkout/stage7/rollback/${inputs.freezeManifest.candidateSha}`),
    journalLifecycle,
    stateBackend: 'SSM_APPEND_ONLY_HASH_CHAIN',
    executorConstruction: 'INTERNAL_AWS_CLI_ONLY',
    injectedExecutorAccepted: false,
    containsSensitiveData: false,
  };
  return {
    inputs,
    executor,
    stateStore,
    attestation: {
      ...attestationBody,
      attestationSha256: objectSha256(attestationBody),
    },
  };
};

export const selfTestProtectedRollbackRuntime = () => {
  assert.equal(originModeCompatible({ actual: 'origin_gate', previous: false }), true);
  assert.equal(originModeCompatible({ actual: 'cloudfront_signed_cookie', previous: true }), true);
  assert.equal(originModeCompatible({ actual: 'disabled', previous: true }), false);
  const response = (status, values) => ({
    status,
    headers: { get: (name) => values[name.toLowerCase()] ?? null },
  });
  const securityHeaders = {
    'cache-control': 'no-store',
    'content-security-policy': "default-src 'self'; object-src 'none'",
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'permissions-policy': 'camera=(), geolocation=(), microphone=(), payment=()',
    'referrer-policy': 'same-origin',
    'strict-transport-security': 'max-age=31536000; includeSubDomains',
  };
  const readinessHeaders = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-correlation-id': 'deadbeef-dead-4bee-8bad-feedfacecafe',
  };
  const readinessBytes = Buffer.from(
    JSON.stringify({ status: 'ok', checkedAt: '2026-08-17T11:00:01.000Z' }),
  );
  assert.equal(
    validateReadinessResponse({ response: response(200, readinessHeaders), bytes: readinessBytes })
      .checkedAtUtc,
    '2026-08-17T11:00:01.000Z',
  );
  assert.throws(
    () =>
      validateReadinessResponse({
        response: response(200, { ...readinessHeaders, 'content-type': 'text/html' }),
        bytes: readinessBytes,
      }),
    (error) => error.code === 'E7_PROTECTED_READINESS_RESPONSE_INVALID',
  );
  assert.throws(
    () =>
      validateReadinessResponse({
        response: response(200, readinessHeaders),
        bytes: Buffer.from(
          JSON.stringify({
            status: 'ok',
            checkedAt: '2026-08-17T11:00:01.000Z',
            internal: true,
          }),
        ),
      }),
    (error) => error.code === 'E7_PROTECTED_READINESS_RESPONSE_INVALID',
  );
  assert.equal(
    validateStaticResponse({
      response: response(200, { ...securityHeaders, 'content-type': 'text/html; charset=utf-8' }),
      bytes: Buffer.from('<!doctype html><div id="root"></div>'),
      path: '/index.html',
    }).contentType,
    'text/html; charset=utf-8',
  );
  assert.equal(
    validateStaticResponse({
      response: response(200, { ...securityHeaders, 'content-type': 'application/json' }),
      bytes: Buffer.from(JSON.stringify({ apiBaseUrl: '/api/v1', productId: 'product-demo-001' })),
      path: '/public-config.json',
    }).contentType,
    'application/json',
  );
  assert.throws(
    () =>
      validateStaticResponse({
        response: response(200, { ...securityHeaders, 'cache-control': 'public,max-age=60' }),
        bytes: Buffer.from('<div id="root"></div>'),
        path: '/index.html',
      }),
    (error) => error.code === 'E7_PROTECTED_STATIC_SECURITY_HEADERS_INVALID',
  );
  const stateBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_DURABLE_STATE',
    scenarioId: 'RB-E7-08',
    bindingSha256: '1'.repeat(64),
    phase: 'SELF_TEST',
    resumptions: 1,
    progress: {
      entries: Array.from({ length: 240 }, (_, index) => sha256(`journal-self-test-${index}`)),
    },
    transcript: [],
    checkpoint: null,
    containsSensitiveData: false,
  };
  const state = { ...stateBody, stateSha256: objectSha256(stateBody) };
  const entry = encodeJournalState({ state, sequence: 1, previousStateSha256: null });
  assert.ok(entry.chunks.length > 1);
  assert.ok(entry.chunks.every((value) => Buffer.byteLength(value, 'utf8') < 4096));
  const prefix = `/${['checkout', 'stage7', 'rollback'].join('/')}/${'a'.repeat(40)}/RB-E7-08`;
  const parameters = entry.chunks.map((value, index) => ({
    Name: `${prefix}/${entry.basename}/chunk-${String(index + 1).padStart(4, '0')}`,
    Value: value,
  }));
  parameters.push({
    Name: `${prefix}/${entry.basename}/manifest`,
    Value: JSON.stringify(entry.manifest),
  });
  const [group] = journalGroups({ prefix, parameters });
  assert.deepEqual(decodeJournalGroup(group, null), state);
  const incomplete = {
    ...group,
    entries: new Map([...group.entries].filter(([name]) => name !== 'manifest')),
  };
  assert.equal(decodeJournalGroup(incomplete, null), null);
  const tampered = {
    ...group,
    entries: new Map(group.entries),
  };
  tampered.entries.set('chunk-0001', `${tampered.entries.get('chunk-0001').slice(0, -1)}A`);
  assert.throws(
    () => decodeJournalGroup(tampered, null),
    (error) => error.code === 'E7_PROTECTED_SSM_PAYLOAD_DIGEST',
  );
  assert.throws(
    () => decodeJournalGroup(group, '2'.repeat(64)),
    (error) => error.code === 'E7_PROTECTED_SSM_MANIFEST_INVALID',
  );
  const replacementStateSha256 = '3'.repeat(64);
  const abandoned = {
    ...incomplete,
    entries: new Map(incomplete.entries),
  };
  abandoned.entries.set(
    'abandoned',
    JSON.stringify({
      schemaVersion: 1,
      kind: 'ROLLBACK_RESILIENCE_SSM_JOURNAL_ABANDONED',
      sequence: 1,
      stateSha256: state.stateSha256,
      previousStateSha256: null,
      replacementStateSha256,
      containsSensitiveData: false,
    }),
  );
  assert.equal(
    validateAbandonedJournalGroup(abandoned, null).replacementStateSha256,
    replacementStateSha256,
  );
  const corruptedAbandoned = { ...abandoned, entries: new Map(abandoned.entries) };
  corruptedAbandoned.entries.set('manifest', JSON.stringify(entry.manifest));
  assert.throws(
    () => validateAbandonedJournalGroup(corruptedAbandoned, null),
    (error) => error.code === 'E7_PROTECTED_SSM_ABANDONED_INVALID',
  );
  assert.throws(
    () =>
      requireExistingJournalAuthority({
        parameters: [{ Name: `${prefix}/${entry.basename}/manifest` }],
        ownerParameterName: `${prefix}/owner`,
        premutationAuthorityParameterName: `${prefix}/premutation-authority`,
      }),
    (error) => error.code === 'E7_PROTECTED_SSM_UNOWNED_JOURNAL_BLOCKED',
  );
  assert.doesNotThrow(() =>
    requireExistingJournalAuthority({
      parameters: [{ Name: `${prefix}/premutation-authority` }],
      ownerParameterName: `${prefix}/owner`,
      premutationAuthorityParameterName: `${prefix}/premutation-authority`,
    }),
  );
  assert.throws(
    () =>
      requireExistingJournalAuthority({
        parameters: [{ Name: `${prefix}/owner` }],
        ownerParameterName: `${prefix}/owner`,
        premutationAuthorityParameterName: `${prefix}/premutation-authority`,
      }),
    (error) => error.code === 'E7_PROTECTED_SSM_UNOWNED_JOURNAL_BLOCKED',
  );
  return {
    status: 'PASS',
    canaries: 19,
    chunks: entry.chunks.length,
    externalRequests: 0,
    stateSha256: state.stateSha256,
  };
};
