import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { objectSha256 } from './core.mjs';
import {
  STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT,
  createReleaseReconciliationIntent,
  createReleaseRollbackJournalOwner,
  validateReleaseReconciliationIntent,
  validateReleaseRollbackJournalOwner as validateReleaseReconciliationJournalOwner,
} from './release-reconciliation.mjs';
import {
  isValidatedReleaseReconciliationIntentAuthority,
  validateReleaseReconciliationIntentAuthority,
} from './release-reconciliation-authority.mjs';
import {
  validateRollbackJournalOwner,
  validateRollbackSsmPremutationAuthority,
} from './rollback-resilience-protected-runtime.mjs';
import {
  RELEASE_SUCCESSOR_FENCE_AUTHORITY_BINDING_KEYS,
  isValidatedReleaseSuccessorFenceAuthority,
  validateReleaseSuccessorCompletionFence,
  validateReleaseSuccessorFenceAuthorityBindings,
  validateReleaseSuccessorFinalDisableProvenance,
  validateReleaseSuccessorFinalizationMarker,
} from './release-successor-handoff.mjs';
import {
  RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT,
  RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT,
} from './release-successor-parameter-roots.mjs';
import {
  compareReleaseJournalRoleEffectivePermissions,
  createReleaseSuccessorIamAuthoritySelfTestFixture,
  validateReleaseJournalRoleEffectivePermissionsBinding,
} from './release-successor-iam-authority.mjs';
import {
  createReleaseSuccessorRollbackPremutationRecords,
  isValidatedReleaseSuccessorRollbackAuthority,
  reconstructReleaseSuccessorRollbackPremutationAuthority,
  validateReleaseSuccessorRollbackCompletionAuthority,
  validateReleaseSuccessorRollbackPremutationAuthority,
} from './release-successor-rollback-authority.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const RELEASE_WORKFLOW_PATH = '.github/workflows/release.yml';
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const ROLE_ARN = /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/u;
const ACCOUNT_ID = /^[0-9]{12}$/u;
const SESSION_NAME = /^[A-Za-z0-9+=,.@_-]{2,64}$/u;
const SEMVER = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const AWS_REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$/u;
const EVIDENCE_BINDING_KEYS = Object.freeze([
  'approval',
  'activation',
  'drift',
  'rollbackCompletion',
  'preFenceGate',
]);
const STANDARD_PARAMETER_MAX_BYTES = 4096;
const OIDC_HOST = 'token.actions.githubusercontent.com';
const RELEASE_FENCE_SUBJECT =
  'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release';
const POST_SUCCESS_SUBJECT =
  'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-successor-post-success';
const RECONCILIATION_RECOVERY_SUBJECT =
  'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-reconciliation-recovery';
const VALIDATED_CALLER_AUTHORITIES = new WeakSet();
const SELF_TEST_INTENT_AUTHORITIES = new WeakSet();
const SELF_TEST_ROLLBACK_AUTHORITIES = new WeakSet();

export {
  RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT,
  RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT,
} from './release-successor-parameter-roots.mjs';
export const RELEASE_SUCCESSOR_JOURNAL_CLEANUP_ROLE_KEY = 'journalCleanupRoleArn';

export class Stage7ReleaseSuccessorFinalizationError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseSuccessorFinalizationError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseSuccessorFinalizationError(
    code,
    cause === undefined ? undefined : { cause },
  );
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const utc = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return false;
  return new Date(value).toISOString() === value;
};
const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');

const isMutationIntentAuthority = (value) =>
  isValidatedReleaseReconciliationIntentAuthority(value) || SELF_TEST_INTENT_AUTHORITIES.has(value);
const isMutationRollbackAuthority = (value, { kind } = {}) =>
  (isValidatedReleaseSuccessorRollbackAuthority(value, { kind }) ||
    SELF_TEST_ROLLBACK_AUTHORITIES.has(value)) &&
  (kind === undefined || value?.kind === kind);

const createSelfTestIntentAuthority = (intent) => {
  validateReleaseReconciliationIntent(intent);
  const bytes = Buffer.from(JSON.stringify(intent), 'utf8');
  const authority = Object.freeze({
    intent,
    source: Object.freeze({ ...intent.source }),
    authority: Object.freeze({ ...intent.authority }),
    rawSha256: sha256(bytes),
    canonicalSha256: objectSha256(intent),
    bytes: bytes.length,
    sourceSetSha256: objectSha256(
      Object.fromEntries(
        intent.bindings.map(({ label, rawSha256, canonicalSha256, bytes: bindingBytes }) => [
          label,
          { rawSha256, canonicalSha256, bytes: bindingBytes },
        ]),
      ),
    ),
  });
  SELF_TEST_INTENT_AUTHORITIES.add(authority);
  return authority;
};

const createSelfTestRollbackAuthority = ({
  kind = 'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY',
  source,
  rollbackRoleArn,
  journalCleanupRoleArn,
  journalLifecycleSha256,
  rollbackBindingSha256,
  protectedBindingSha256,
}) => {
  if (
    ![
      'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY',
      'ROLLBACK_RESILIENCE_COMPLETION_AUTHORITY',
    ].includes(kind) ||
    !object(source) ||
    !SHA.test(source.candidateSha ?? '') ||
    !RUN_ID.test(source.runId ?? '') ||
    source.runAttempt !== 1 ||
    ![journalLifecycleSha256, rollbackBindingSha256, protectedBindingSha256].every((value) =>
      SHA256.test(value ?? ''),
    )
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_SELF_TEST_AUTHORITY_INVALID');
  }
  const contextSetSha256 = objectSha256({ source, rollbackBindingSha256 });
  const authority = Object.freeze({
    kind,
    candidateSha: source.candidateSha,
    releaseId: source.releaseId,
    releaseTag: source.releaseTag,
    configSha256: source.configSha256,
    sourceRunId: source.runId,
    sourceRunAttempt: source.runAttempt,
    accountId: rollbackRoleArn.split(':')[4],
    awsRegion: 'us-east-1',
    rollbackRoleArn,
    journalCleanupRoleArn,
    rollbackRoleSha256: sha256(rollbackRoleArn),
    journalCleanupRoleSha256: sha256(journalCleanupRoleArn),
    journalLifecycleSha256,
    rollbackBindingSha256,
    protectedBindingSha256,
    sourceBindingSha256: 'f'.repeat(64),
    contextBindings: {},
    contextSetSha256,
    ...(kind === 'ROLLBACK_RESILIENCE_COMPLETION_AUTHORITY'
      ? { completionBindings: {}, completionSetSha256: objectSha256({ contextSetSha256 }) }
      : {}),
  });
  SELF_TEST_ROLLBACK_AUTHORITIES.add(authority);
  return authority;
};
const strictExternalJson = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  let value;
  try {
    value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
  } catch (error) {
    fail(code, error);
  }
  if (!object(value)) fail(code);
  return {
    value,
    bytes,
    rawSha256: sha256(bytes),
    canonicalSha256: objectSha256(value),
  };
};

const validateCommitment = (commitment) => {
  if (
    !exactKeys(commitment, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'repository',
      'sourceRunId',
      'sourceRunAttempt',
      'candidateSha',
      'releaseId',
      'journalLifecycleSha256',
      'releaseEvidenceSetSha256',
      'awsCliVersion',
      'awsRegion',
      'evidenceBindings',
      'releaseFenceSha256',
      'journalCleanupRoleSha256',
      'journalRoleAuthoritySha256',
      'containsSensitiveData',
    ]) ||
    commitment.schemaVersion !== 1 ||
    commitment.stage !== 7 ||
    commitment.kind !== 'RELEASE_SUCCESSOR_EVIDENCE_SET_COMMITMENT' ||
    commitment.status !== 'PASS' ||
    commitment.repository !== REPOSITORY ||
    !RUN_ID.test(commitment.sourceRunId ?? '') ||
    commitment.sourceRunAttempt !== 1 ||
    !SHA.test(commitment.candidateSha ?? '') ||
    !RELEASE_ID.test(commitment.releaseId ?? '') ||
    !SHA256.test(commitment.journalLifecycleSha256 ?? '') ||
    !SHA256.test(commitment.releaseEvidenceSetSha256 ?? '') ||
    !SEMVER.test(commitment.awsCliVersion ?? '') ||
    !AWS_REGION.test(commitment.awsRegion ?? '') ||
    !SHA256.test(commitment.releaseFenceSha256 ?? '') ||
    !SHA256.test(commitment.journalCleanupRoleSha256 ?? '') ||
    !SHA256.test(commitment.journalRoleAuthoritySha256 ?? '') ||
    !exactKeys(commitment.evidenceBindings, EVIDENCE_BINDING_KEYS) ||
    Object.values(commitment.evidenceBindings).some(
      (binding) =>
        !exactKeys(binding, ['rawSha256', 'canonicalSha256', 'bytes']) ||
        !SHA256.test(binding.rawSha256 ?? '') ||
        !SHA256.test(binding.canonicalSha256 ?? '') ||
        !Number.isSafeInteger(binding.bytes) ||
        binding.bytes < 2,
    ) ||
    commitment.containsSensitiveData !== false
  ) {
    fail('E7_RELEASE_SUCCESSOR_EVIDENCE_COMMITMENT_INVALID');
  }
  return commitment;
};

export const validateReleaseSuccessorFinalizationAuthority = ({
  journalCleanupRoleArn,
  rollbackRoleArn,
  ephemeralCleanupRoleArn,
  lifecycleCleanupRoleSha256,
}) => {
  if (
    ![journalCleanupRoleArn, rollbackRoleArn, ephemeralCleanupRoleArn].every((value) =>
      ROLE_ARN.test(value ?? ''),
    ) ||
    journalCleanupRoleArn === rollbackRoleArn ||
    journalCleanupRoleArn === ephemeralCleanupRoleArn ||
    rollbackRoleArn === ephemeralCleanupRoleArn ||
    !SHA256.test(lifecycleCleanupRoleSha256 ?? '') ||
    sha256(journalCleanupRoleArn) !== lifecycleCleanupRoleSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_DEDICATED_ROLE_REQUIRED');
  }
  return {
    journalCleanupRoleSha256: sha256(journalCleanupRoleArn),
    rollbackRoleSha256: sha256(rollbackRoleArn),
    ephemeralCleanupRoleSha256: sha256(ephemeralCleanupRoleArn),
  };
};

export const validateReleaseSuccessorCallerAuthority = ({
  callerIdentitySource,
  awsVersionSource,
  roleAuditSource,
  awsAuthSource,
  frozenEffectivePermissionsSource,
  liveEffectivePermissionsSource,
  journalCleanupRoleArn,
  expectedSessionName,
  expectedAwsCliVersion,
  expectedPermissionsBoundaryArn,
}) => {
  if (
    !ROLE_ARN.test(journalCleanupRoleArn ?? '') ||
    !SESSION_NAME.test(expectedSessionName ?? '') ||
    !SEMVER.test(expectedAwsCliVersion ?? '') ||
    typeof expectedPermissionsBoundaryArn !== 'string' ||
    !/^arn:aws:iam::[0-9]{12}:policy\/[A-Za-z0-9+=,.@_/-]{1,512}$/u.test(
      expectedPermissionsBoundaryArn,
    )
  ) {
    fail('E7_RELEASE_SUCCESSOR_CALLER_AUTHORITY_INPUT_INVALID');
  }
  const caller = strictExternalJson(
    callerIdentitySource,
    'E7_RELEASE_SUCCESSOR_CALLER_IDENTITY_INVALID',
  );
  const awsVersionBytes = Buffer.isBuffer(awsVersionSource)
    ? Buffer.from(awsVersionSource)
    : Buffer.from(awsVersionSource ?? '', 'utf8');
  const awsVersionText = awsVersionBytes.toString('utf8').trim();
  const awsVersionMatch = /^aws-cli\/([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)/u.exec(awsVersionText);
  const accountId = journalCleanupRoleArn.split(':')[4];
  const roleName = journalCleanupRoleArn.slice(journalCleanupRoleArn.lastIndexOf('/') + 1);
  const expectedArn = `arn:aws:sts::${accountId}:assumed-role/${roleName}/${expectedSessionName}`;
  const roleAudit = strictExternalJson(roleAuditSource, 'E7_RELEASE_SUCCESSOR_ROLE_AUDIT_INVALID');
  let frozenBinding;
  let effectivePermissions;
  try {
    frozenBinding = validateReleaseJournalRoleEffectivePermissionsBinding({
      awsAuthSource,
      effectivePermissionsSource: frozenEffectivePermissionsSource,
    });
    effectivePermissions = compareReleaseJournalRoleEffectivePermissions({
      frozenSource: frozenEffectivePermissionsSource,
      liveSource: liveEffectivePermissionsSource,
      expectedRoleArn: journalCleanupRoleArn,
      expectedPermissionsBoundaryArn,
    });
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_EFFECTIVE_PERMISSIONS_AUTHORITY_INVALID', error);
  }
  const trust = roleAudit.value.AssumeRolePolicyDocument;
  const statement = trust?.Statement?.[0];
  const expectedProviderArn = `arn:aws:iam::${accountId}:oidc-provider/${OIDC_HOST}`;
  const expectedSubjects = [
    RELEASE_FENCE_SUBJECT,
    POST_SUCCESS_SUBJECT,
    RECONCILIATION_RECOVERY_SUBJECT,
  ].toSorted();
  const roleResource = journalCleanupRoleArn.split(':role/')[1];
  const rolePathSeparator = roleResource.lastIndexOf('/');
  const expectedRolePath =
    rolePathSeparator < 0 ? '/' : `/${roleResource.slice(0, rolePathSeparator + 1)}`;
  const roleCreatedAtUtc =
    typeof roleAudit.value.CreateDate === 'string' &&
    !Number.isNaN(Date.parse(roleAudit.value.CreateDate))
      ? new Date(roleAudit.value.CreateDate).toISOString()
      : null;
  if (
    !exactKeys(caller.value, ['UserId', 'Account', 'Arn']) ||
    !ACCOUNT_ID.test(caller.value.Account ?? '') ||
    caller.value.Account !== accountId ||
    caller.value.Arn !== expectedArn ||
    typeof caller.value.UserId !== 'string' ||
    !caller.value.UserId.endsWith(`:${expectedSessionName}`) ||
    awsVersionMatch?.[1] !== expectedAwsCliVersion ||
    !exactKeys(roleAudit.value, [
      'Path',
      'RoleName',
      'RoleId',
      'Arn',
      'CreateDate',
      'MaxSessionDuration',
      'PermissionsBoundary',
      'AssumeRolePolicyDocument',
    ]) ||
    roleAudit.value.Path !== expectedRolePath ||
    roleAudit.value.RoleName !== roleName ||
    roleAudit.value.Arn !== journalCleanupRoleArn ||
    typeof roleAudit.value.RoleId !== 'string' ||
    roleAudit.value.RoleId.length < 16 ||
    !utc(roleCreatedAtUtc) ||
    roleAudit.value.MaxSessionDuration !== 3600 ||
    !exactKeys(roleAudit.value.PermissionsBoundary, [
      'PermissionsBoundaryType',
      'PermissionsBoundaryArn',
    ]) ||
    roleAudit.value.PermissionsBoundary.PermissionsBoundaryType !== 'Policy' ||
    roleAudit.value.PermissionsBoundary.PermissionsBoundaryArn !== expectedPermissionsBoundaryArn ||
    !exactKeys(trust, ['Version', 'Statement']) ||
    trust.Version !== '2012-10-17' ||
    !Array.isArray(trust.Statement) ||
    trust.Statement.length !== 1 ||
    !exactKeys(statement, ['Effect', 'Principal', 'Action', 'Condition']) ||
    statement.Effect !== 'Allow' ||
    statement.Action !== 'sts:AssumeRoleWithWebIdentity' ||
    !exactKeys(statement.Principal, ['Federated']) ||
    statement.Principal.Federated !== expectedProviderArn ||
    !exactKeys(statement.Condition, ['StringEquals']) ||
    !exactKeys(statement.Condition.StringEquals, [`${OIDC_HOST}:aud`, `${OIDC_HOST}:sub`]) ||
    statement.Condition.StringEquals[`${OIDC_HOST}:aud`] !== 'sts.amazonaws.com' ||
    !Array.isArray(statement.Condition.StringEquals[`${OIDC_HOST}:sub`]) ||
    statement.Condition.StringEquals[`${OIDC_HOST}:sub`].toSorted().join('\0') !==
      expectedSubjects.join('\0') ||
    objectSha256(trust) !== frozenBinding.effectivePermissions.value.role.trustPolicySha256 ||
    roleAudit.value.RoleId !== frozenBinding.effectivePermissions.value.role.id ||
    roleAudit.value.Path !== frozenBinding.effectivePermissions.value.role.path ||
    roleAudit.value.MaxSessionDuration !==
      frozenBinding.effectivePermissions.value.role.maxSessionDuration
  ) {
    fail('E7_RELEASE_SUCCESSOR_CALLER_IDENTITY_MISMATCH');
  }
  const roleAuthority = {
    accountIdSha256: sha256(accountId),
    awsCliVersion: expectedAwsCliVersion,
    awsCliVersionSha256: sha256(expectedAwsCliVersion),
    roleAuditCanonicalSha256: roleAudit.canonicalSha256,
    trustPolicySha256: objectSha256(trust),
    permissionsBoundaryArnSha256: sha256(expectedPermissionsBoundaryArn),
    trustSubjectsSha256: objectSha256(expectedSubjects),
    effectivePolicyProjectionSha256: effectivePermissions.effectivePolicyProjectionSha256,
  };
  const callerAttemptAuthority = {
    assumedRoleArnSha256: sha256(expectedArn),
    sessionNameSha256: sha256(expectedSessionName),
    callerIdentityRawSha256: caller.rawSha256,
    callerIdentityCanonicalSha256: caller.canonicalSha256,
  };
  const auditEvidence = {
    awsVersionRawSha256: sha256(awsVersionBytes),
    roleAuditRawSha256: roleAudit.rawSha256,
    awsAuthRawSha256: frozenBinding.awsAuth.rawSha256,
    awsAuthCanonicalSha256: frozenBinding.awsAuth.canonicalSha256,
    effectivePermissionsFrozenRawSha256: effectivePermissions.frozenRawSha256,
    effectivePermissionsLiveRawSha256: effectivePermissions.liveRawSha256,
    effectivePermissionsLiveCanonicalSha256: effectivePermissions.liveCanonicalSha256,
    effectivePermissionsFrozenSha256: effectivePermissions.frozenEffectivePermissionsSha256,
    effectivePermissionsLiveSha256: effectivePermissions.liveEffectivePermissionsSha256,
  };
  const authority = Object.freeze({
    roleAuthority,
    roleAuthoritySha256: objectSha256(roleAuthority),
    callerAttemptAuthority,
    callerAttemptAuthoritySha256: objectSha256(callerAttemptAuthority),
    auditEvidence,
    auditEvidenceSha256: objectSha256(auditEvidence),
    authorityReadRequests: 2 + effectivePermissions.liveSourceBindingCount,
  });
  VALIDATED_CALLER_AUTHORITIES.add(authority);
  return authority;
};

const createReleaseSuccessorCompletionFenceUnchecked = ({
  sourceRunId,
  sourceRunAttempt,
  candidateSha,
  releaseId,
  journalLifecycleSha256,
  evidenceBindings,
  authorityBindings,
  authoritySetSha256,
  journalCleanupRoleArn,
  journalRoleAuthoritySha256,
}) => {
  if (
    !RUN_ID.test(sourceRunId ?? '') ||
    sourceRunAttempt !== 1 ||
    !SHA.test(candidateSha ?? '') ||
    !RELEASE_ID.test(releaseId ?? '') ||
    !SHA256.test(journalLifecycleSha256 ?? '') ||
    !exactKeys(evidenceBindings, EVIDENCE_BINDING_KEYS) ||
    Object.values(evidenceBindings).some(
      (binding) =>
        !exactKeys(binding, ['rawSha256', 'canonicalSha256', 'bytes']) ||
        !SHA256.test(binding.rawSha256 ?? '') ||
        !SHA256.test(binding.canonicalSha256 ?? '') ||
        !Number.isSafeInteger(binding.bytes) ||
        binding.bytes < 2,
    ) ||
    validateReleaseSuccessorFenceAuthorityBindings(authorityBindings) !== authorityBindings ||
    authoritySetSha256 !== objectSha256(authorityBindings) ||
    !ROLE_ARN.test(journalCleanupRoleArn ?? '') ||
    !SHA256.test(journalRoleAuthoritySha256 ?? '')
  ) {
    fail('E7_RELEASE_SUCCESSOR_DEDICATED_ROLE_REQUIRED');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_RELEASE_COMPLETION_FENCE',
    status: 'RELEASE_EVIDENCE_FENCED_IMMUTABLE',
    repository: REPOSITORY,
    sourceWorkflowPath: RELEASE_WORKFLOW_PATH,
    sourceRunId,
    sourceRunAttempt,
    candidateSha,
    releaseId,
    journalLifecycleSha256,
    journalCleanupRoleSha256: sha256(journalCleanupRoleArn),
    journalRoleAuthoritySha256,
    evidenceBindings,
    authoritySetSha256,
    mutationsBlocked: true,
    orphanedFailurePolicy: 'BLOCKED_FENCE_REQUIRES_SEPARATE_AUTHORIZED_RECOVERY',
    containsSensitiveData: false,
  };
  return validateReleaseSuccessorCompletionFence({
    ...body,
    fenceSha256: objectSha256(body),
  });
};

export const createReleaseSuccessorCompletionFence = ({
  validatedAuthorities,
  validatedCallerAuthority,
  ...options
}) => {
  if (
    !isValidatedReleaseSuccessorFenceAuthority(validatedAuthorities) ||
    !object(validatedCallerAuthority) ||
    !VALIDATED_CALLER_AUTHORITIES.has(validatedCallerAuthority) ||
    validatedCallerAuthority.roleAuthoritySha256 !== options.journalRoleAuthoritySha256 ||
    validatedAuthorities.freeze.candidateSha !== options.candidateSha ||
    validatedAuthorities.freeze.releaseId !== options.releaseId ||
    validatedAuthorities.lifecycle.lifecycleSha256 !== options.journalLifecycleSha256 ||
    objectSha256(validatedAuthorities.evidenceBindings) !==
      objectSha256(options.evidenceBindings) ||
    objectSha256(validatedAuthorities.authorityBindings) !==
      objectSha256(options.authorityBindings) ||
    validatedAuthorities.authoritySetSha256 !== options.authoritySetSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_SEMANTIC_AUTHORITY_REQUIRED');
  }
  return createReleaseSuccessorCompletionFenceUnchecked(options);
};

export const putReleaseSuccessorCompletionFence = async ({
  fence,
  journalCleanupRoleArn,
  awsRegion,
  putParameter,
  getParameter,
}) => {
  validateReleaseSuccessorCompletionFence(fence);
  if (
    typeof putParameter !== 'function' ||
    typeof getParameter !== 'function' ||
    !ROLE_ARN.test(journalCleanupRoleArn ?? '') ||
    sha256(journalCleanupRoleArn) !== fence.journalCleanupRoleSha256 ||
    !AWS_REGION.test(awsRegion ?? '')
  ) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_ADAPTER_REQUIRED');
  }
  const parameterName = `${RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT}/${fence.candidateSha}/${fence.sourceRunId}`;
  const fenceBytes = jsonBytes(fence);
  if (fenceBytes.length > STANDARD_PARAMETER_MAX_BYTES) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_STANDARD_PARAMETER_TOO_LARGE');
  }
  let idempotent = false;
  let putVersion;
  try {
    const result = await putParameter({
      name: parameterName,
      type: 'String',
      tier: 'Standard',
      value: fenceBytes.toString('utf8'),
      overwrite: false,
    });
    putVersion = result?.Version;
    if (putVersion !== 1) {
      fail('E7_RELEASE_SUCCESSOR_FENCE_PUT_RESPONSE_INVALID');
    }
  } catch (error) {
    if (!parameterAlreadyExists(error)) throw error;
    idempotent = true;
  }
  const response = await getParameter({ name: parameterName, withDecryption: false });
  const parameter = response?.Parameter;
  const expectedArn = `arn:aws:ssm:${awsRegion}:${journalCleanupRoleArn.split(':')[4]}:parameter${parameterName}`;
  if (
    !object(parameter) ||
    parameter.Name !== parameterName ||
    parameter.Type !== 'String' ||
    parameter.Value !== fenceBytes.toString('utf8') ||
    parameter.Version !== 1 ||
    parameter.ARN !== expectedArn ||
    parameter.DataType !== 'text' ||
    (!idempotent && parameter.Version !== putVersion)
  ) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_GET_MISMATCH');
  }
  return { fence, fenceBytes, parameterName, parameterVersion: parameter.Version, idempotent };
};

export const createReleaseSuccessorFinalizationMarker = ({
  commitment,
  releaseFence,
  callerAuthority,
}) => {
  validateCommitment(commitment);
  if (!object(callerAuthority) || !SHA256.test(callerAuthority.roleAuthoritySha256 ?? '')) {
    fail('E7_RELEASE_SUCCESSOR_CALLER_AUTHORITY_INVALID');
  }
  validateReleaseSuccessorCompletionFence(releaseFence, {
    candidateSha: commitment.candidateSha,
    releaseId: commitment.releaseId,
    sourceRunId: commitment.sourceRunId,
    sourceRunAttempt: commitment.sourceRunAttempt,
    journalLifecycleSha256: commitment.journalLifecycleSha256,
    evidenceBindings: commitment.evidenceBindings,
    journalCleanupRoleSha256: commitment.journalCleanupRoleSha256,
    journalRoleAuthoritySha256: commitment.journalRoleAuthoritySha256,
  });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_RECOVERY_FINALIZATION_MARKER',
    status: 'FINALIZED_IMMUTABLE',
    repository: REPOSITORY,
    sourceWorkflowPath: RELEASE_WORKFLOW_PATH,
    sourceRunId: commitment.sourceRunId,
    sourceRunAttempt: commitment.sourceRunAttempt,
    candidateSha: commitment.candidateSha,
    releaseId: commitment.releaseId,
    releaseEvidenceSetSha256: commitment.releaseEvidenceSetSha256,
    journalLifecycleSha256: commitment.journalLifecycleSha256,
    releaseFenceSha256: releaseFence.fenceSha256,
    journalRoleAuthoritySha256: callerAuthority.roleAuthoritySha256,
    containsSensitiveData: false,
  };
  return validateReleaseSuccessorFinalizationMarker(
    { ...body, markerSha256: objectSha256(body) },
    {
      candidateSha: commitment.candidateSha,
      releaseId: commitment.releaseId,
      sourceRunId: commitment.sourceRunId,
      sourceRunAttempt: commitment.sourceRunAttempt,
      releaseEvidenceSetSha256: commitment.releaseEvidenceSetSha256,
      journalLifecycleSha256: commitment.journalLifecycleSha256,
      releaseFenceSha256: releaseFence.fenceSha256,
      journalRoleAuthoritySha256: callerAuthority.roleAuthoritySha256,
    },
  );
};

const parameterAlreadyExists = (error) =>
  error?.code === 'ParameterAlreadyExists' ||
  error?.name === 'ParameterAlreadyExists' ||
  /ParameterAlreadyExists/u.test(error?.message ?? '');
export const FULL_RELEASE_MUTATION_GUARD_OPERATIONS = Object.freeze([
  'DEPLOY_DATA',
  'SEED_DATA',
  'DEPLOY_API',
  'DEPLOY_OBSERVABILITY',
  'DEPLOY_WEB',
  'ACTIVATE_CANDIDATE',
  'EMERGENCY_RECOVERY',
]);
const DEDICATED_MUTATION_GUARD_OPERATIONS = Object.freeze([
  'RUN_VERSIONED_ROLLBACK_CHECK',
  'OPEN_ROLLBACK_RESILIENCE',
  'RESUME_ROLLBACK_RESILIENCE',
  'RESUME_RELEASE_RECONCILIATION',
  'RESUME_INCOMPLETE_RECONCILIATION',
]);
const ALL_MUTATION_GUARD_OPERATIONS = Object.freeze([
  ...FULL_RELEASE_MUTATION_GUARD_OPERATIONS,
  ...DEDICATED_MUTATION_GUARD_OPERATIONS,
]);
const MUTATION_AUTHORITY_CAPABILITY = Symbol('release-successor-mutation-authority');
const mutationAuthorityCapabilities = new WeakSet();
const MAX_GUARD_PAGES_PER_SCOPE = 16;
const MAX_GUARD_PARAMETERS_PER_PAGE = 10;
const MAX_GUARD_PARAMETERS = 3 * MAX_GUARD_PAGES_PER_SCOPE * MAX_GUARD_PARAMETERS_PER_PAGE;

const createMutationAuthorityCapability = ({
  operation,
  owner,
  intent,
  rbOwners,
  intentAuthority,
  rollbackAuthority,
}) => {
  validateReleaseReconciliationJournalOwner(owner);
  validateReleaseReconciliationIntent(intent);
  if (
    !DEDICATED_MUTATION_GUARD_OPERATIONS.includes(operation) ||
    !isMutationIntentAuthority(intentAuthority) ||
    !Array.isArray(rbOwners) ||
    rbOwners.length > 2 ||
    (operation === 'RUN_VERSIONED_ROLLBACK_CHECK' && rbOwners.length !== 0) ||
    (operation === 'OPEN_ROLLBACK_RESILIENCE' &&
      !isMutationRollbackAuthority(rollbackAuthority, {
        kind: 'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY',
      })) ||
    (operation === 'RESUME_ROLLBACK_RESILIENCE' &&
      (!isMutationRollbackAuthority(rollbackAuthority, {
        kind: 'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY',
      }) ||
        rbOwners.length < 1)) ||
    (operation === 'RESUME_RELEASE_RECONCILIATION' && rbOwners.length !== 2) ||
    (operation === 'RESUME_RELEASE_RECONCILIATION' &&
      !isMutationRollbackAuthority(rollbackAuthority, {
        kind: 'ROLLBACK_RESILIENCE_COMPLETION_AUTHORITY',
      })) ||
    (operation === 'RESUME_INCOMPLETE_RECONCILIATION' && rbOwners.length !== 2) ||
    (operation === 'RESUME_INCOMPLETE_RECONCILIATION' &&
      !isMutationRollbackAuthority(rollbackAuthority, {
        kind: 'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY',
      })) ||
    new Set(rbOwners.map(({ scenarioId }) => scenarioId)).size !== rbOwners.length
  ) {
    fail('E7_RELEASE_SUCCESSOR_MUTATION_AUTHORITY_CAPABILITY_INVALID');
  }
  const source = intentAuthority.source;
  for (const rbOwner of rbOwners) {
    validateRollbackJournalOwner(rbOwner, {
      candidateSha: source.candidateSha,
      scenarioId: rbOwner.scenarioId,
      sourceRunId: source.runId,
      bindingSha256: rollbackAuthority.rollbackBindingSha256,
      protectedBindingSha256: rollbackAuthority.protectedBindingSha256,
      rollbackRoleSha256: rollbackAuthority.rollbackRoleSha256,
      journalCleanupRoleSha256: rollbackAuthority.journalCleanupRoleSha256,
      journalLifecycleSha256: rollbackAuthority.journalLifecycleSha256,
    });
  }
  if (
    intent.bindings.length !== STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.length ||
    objectSha256(intent.source) !== objectSha256(owner.source) ||
    objectSha256(intent) !== objectSha256(intentAuthority.intent) ||
    intent.intentSha256 !== owner.intentSha256 ||
    intent.bindingsSha256 !== owner.intentBindingsSha256 ||
    owner.source.candidateSha !== source.candidateSha ||
    owner.source.releaseId !== source.releaseId ||
    owner.source.releaseTag !== source.releaseTag ||
    owner.source.configSha256 !== source.configSha256 ||
    owner.source.runId !== source.runId ||
    owner.source.runAttempt !== 1 ||
    (rollbackAuthority !== null &&
      (rollbackAuthority.candidateSha !== source.candidateSha ||
        rollbackAuthority.releaseId !== source.releaseId ||
        rollbackAuthority.releaseTag !== source.releaseTag ||
        rollbackAuthority.configSha256 !== source.configSha256 ||
        rollbackAuthority.sourceRunId !== source.runId ||
        rollbackAuthority.sourceRunAttempt !== 1))
  ) {
    fail('E7_RELEASE_SUCCESSOR_MUTATION_AUTHORITY_CAPABILITY_INVALID');
  }
  const capability = Object.freeze({
    operation,
    candidateSha: source.candidateSha,
    releaseId: source.releaseId,
    releaseTag: source.releaseTag,
    configSha256: source.configSha256,
    sourceRunId: source.runId,
    sourceRunAttempt: source.runAttempt,
    ownerSha256: owner.ownerSha256,
    intentSha256: intent.intentSha256,
    intentBindingsSha256: intent.bindingsSha256,
    intentBindingCount: intent.bindings.length,
    rbOwnerSha256s: rbOwners.map(({ ownerSha256 }) => ownerSha256).toSorted(),
    intentAuthoritySetSha256: intentAuthority.sourceSetSha256,
    rollbackAuthoritySetSha256:
      rollbackAuthority === null
        ? null
        : (rollbackAuthority.completionSetSha256 ?? rollbackAuthority.contextSetSha256),
    capabilitySha256: objectSha256({
      ownerSha256: owner.ownerSha256,
      intentSha256: intent.intentSha256,
      intentBindingsSha256: intent.bindingsSha256,
      intentBindingCount: intent.bindings.length,
      operation,
      sourceRunId: source.runId,
      candidateSha: source.candidateSha,
      releaseId: source.releaseId,
      releaseTag: source.releaseTag,
      configSha256: source.configSha256,
      intentAuthoritySetSha256: intentAuthority.sourceSetSha256,
      rollbackAuthoritySetSha256:
        rollbackAuthority === null
          ? null
          : (rollbackAuthority.completionSetSha256 ?? rollbackAuthority.contextSetSha256),
      rbOwnerSha256s: rbOwners.map(({ ownerSha256 }) => ownerSha256).toSorted(),
    }),
  });
  mutationAuthorityCapabilities.add(capability);
  return capability;
};

const guardReleaseSuccessorMutation = async ({
  candidateSha,
  sourceRunId,
  authoritativeSourceRunId,
  operation,
  getParametersByPath,
  expectedReleaseId: requestedReleaseId,
  expectedReleaseTag: requestedReleaseTag,
  expectedConfigSha256: requestedConfigSha256,
  expectedReleaseEvidenceSetSha256,
  expectedJournalLifecycleSha256: requestedJournalLifecycleSha256,
  expectedJournalCleanupRoleSha256: requestedJournalCleanupRoleSha256,
  expectedRollbackRoleSha256: requestedRollbackRoleSha256,
  expectedRollbackBindingSha256: requestedRollbackBindingSha256,
  expectedProtectedBindingSha256: requestedProtectedBindingSha256,
  intentAuthority = null,
  rollbackAuthority = null,
}) => {
  const dedicatedOperation = DEDICATED_MUTATION_GUARD_OPERATIONS.includes(operation);
  if (
    dedicatedOperation &&
    (!isMutationIntentAuthority(intentAuthority) ||
      (operation === 'RUN_VERSIONED_ROLLBACK_CHECK'
        ? rollbackAuthority !== null
        : !isMutationRollbackAuthority(rollbackAuthority) ||
          (operation === 'RESUME_RELEASE_RECONCILIATION'
            ? rollbackAuthority.kind !== 'ROLLBACK_RESILIENCE_COMPLETION_AUTHORITY'
            : rollbackAuthority.kind !== 'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY')))
  ) {
    fail('E7_RELEASE_SUCCESSOR_MUTATION_AUTHORITY_REQUIRED');
  }
  const authoritySource = dedicatedOperation ? intentAuthority.source : null;
  const expectedReleaseId = dedicatedOperation ? authoritySource.releaseId : requestedReleaseId;
  const expectedReleaseTag = dedicatedOperation ? authoritySource.releaseTag : requestedReleaseTag;
  const expectedConfigSha256 = dedicatedOperation
    ? authoritySource.configSha256
    : requestedConfigSha256;
  const expectedJournalLifecycleSha256 =
    dedicatedOperation && rollbackAuthority !== null
      ? rollbackAuthority.journalLifecycleSha256
      : requestedJournalLifecycleSha256;
  const expectedJournalCleanupRoleSha256 =
    dedicatedOperation && rollbackAuthority !== null
      ? rollbackAuthority.journalCleanupRoleSha256
      : requestedJournalCleanupRoleSha256;
  const expectedRollbackRoleSha256 =
    dedicatedOperation && rollbackAuthority !== null
      ? rollbackAuthority.rollbackRoleSha256
      : requestedRollbackRoleSha256;
  const expectedRollbackBindingSha256 =
    dedicatedOperation && rollbackAuthority !== null
      ? rollbackAuthority.rollbackBindingSha256
      : requestedRollbackBindingSha256;
  const expectedProtectedBindingSha256 =
    dedicatedOperation && rollbackAuthority !== null
      ? rollbackAuthority.protectedBindingSha256
      : requestedProtectedBindingSha256;
  if (
    !SHA.test(candidateSha ?? '') ||
    !RUN_ID.test(sourceRunId ?? '') ||
    authoritativeSourceRunId !== sourceRunId ||
    !ALL_MUTATION_GUARD_OPERATIONS.includes(operation) ||
    typeof getParametersByPath !== 'function' ||
    (expectedReleaseId !== undefined && !RELEASE_ID.test(expectedReleaseId)) ||
    (expectedReleaseTag !== undefined && !RELEASE_TAG.test(expectedReleaseTag)) ||
    (expectedConfigSha256 !== undefined && !SHA256.test(expectedConfigSha256)) ||
    (expectedReleaseEvidenceSetSha256 !== undefined &&
      !SHA256.test(expectedReleaseEvidenceSetSha256)) ||
    (expectedJournalLifecycleSha256 !== undefined &&
      !SHA256.test(expectedJournalLifecycleSha256)) ||
    (expectedJournalCleanupRoleSha256 !== undefined &&
      !SHA256.test(expectedJournalCleanupRoleSha256)) ||
    (expectedRollbackRoleSha256 !== undefined && !SHA256.test(expectedRollbackRoleSha256)) ||
    (expectedRollbackBindingSha256 !== undefined && !SHA256.test(expectedRollbackBindingSha256)) ||
    (expectedProtectedBindingSha256 !== undefined &&
      !SHA256.test(expectedProtectedBindingSha256)) ||
    (dedicatedOperation &&
      (authoritySource.candidateSha !== candidateSha ||
        authoritySource.runId !== sourceRunId ||
        authoritySource.runAttempt !== 1)) ||
    (dedicatedOperation &&
      operation !== 'RUN_VERSIONED_ROLLBACK_CHECK' &&
      ![
        expectedReleaseId,
        expectedReleaseTag,
        expectedConfigSha256,
        expectedJournalLifecycleSha256,
        expectedJournalCleanupRoleSha256,
        expectedRollbackRoleSha256,
        expectedRollbackBindingSha256,
        expectedProtectedBindingSha256,
      ].every((value, index) =>
        index === 0
          ? RELEASE_ID.test(value ?? '')
          : index === 1
            ? RELEASE_TAG.test(value ?? '')
            : SHA256.test(value ?? ''),
      ))
  ) {
    fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_INPUT_INVALID');
  }
  const candidatePaths = [
    {
      path: `${RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT}/${candidateSha}`,
      recursive: false,
      kind: 'FENCE',
    },
    {
      path: `${RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT}/${candidateSha}`,
      recursive: false,
      kind: 'FINALIZATION',
    },
    {
      path: `/checkout/stage7/rollback/${candidateSha}`,
      recursive: true,
      kind: 'ROLLBACK_JOURNAL',
    },
  ];
  const parameters = [];
  let externalRequests = 0;
  for (const candidateScope of candidatePaths) {
    const seenTokens = new Set();
    let pageCount = 0;
    let nextToken;
    do {
      if (nextToken !== undefined) {
        if (seenTokens.has(nextToken)) {
          fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_TOKEN_LOOP');
        }
        seenTokens.add(nextToken);
      }
      const response = await getParametersByPath({
        path: candidateScope.path,
        recursive: candidateScope.recursive,
        withDecryption: false,
        maxResults: MAX_GUARD_PARAMETERS_PER_PAGE,
        ...(nextToken === undefined ? {} : { nextToken }),
      });
      externalRequests += 1;
      pageCount += 1;
      const hasNextToken = object(response) && Object.hasOwn(response, 'NextToken');
      if (
        pageCount > MAX_GUARD_PAGES_PER_SCOPE ||
        !object(response) ||
        !exactKeys(response, hasNextToken ? ['Parameters', 'NextToken'] : ['Parameters']) ||
        !Array.isArray(response.Parameters) ||
        response.Parameters.length > MAX_GUARD_PARAMETERS_PER_PAGE
      ) {
        fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_LIST_INVALID');
      }
      parameters.push(...response.Parameters.map((parameter) => ({ parameter, candidateScope })));
      if (parameters.length > MAX_GUARD_PARAMETERS) {
        fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_LIST_INVALID');
      }
      nextToken = response.NextToken;
      if (
        nextToken !== undefined &&
        (typeof nextToken !== 'string' || nextToken.length < 1 || nextToken.length > 4096)
      ) {
        fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_TOKEN_INVALID');
      }
      if (pageCount === MAX_GUARD_PAGES_PER_SCOPE && nextToken !== undefined) {
        fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_LIST_INVALID');
      }
    } while (nextToken !== undefined);
  }
  const names = new Set();
  const authorityParameters = parameters.filter(
    ({ candidateScope }) => candidateScope.kind !== 'ROLLBACK_JOURNAL',
  );
  const journalParameters = parameters.filter(
    ({ candidateScope }) => candidateScope.kind === 'ROLLBACK_JOURNAL',
  );
  const rbJournalParameters = [];
  const reconciliationJournalParameters = [];
  for (const { parameter, candidateScope } of journalParameters) {
    const expectedPrefix = `${candidateScope.path}/`;
    const relativeName = parameter?.Name?.slice(expectedPrefix.length);
    if (
      !object(parameter) ||
      typeof parameter.Name !== 'string' ||
      !parameter.Name.startsWith(expectedPrefix) ||
      parameter.Type !== 'String' ||
      typeof parameter.Value !== 'string' ||
      parameter.Version !== 1 ||
      names.has(parameter.Name)
    ) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_JOURNAL_INVALID');
    }
    names.add(parameter.Name);
    if (/^RB-E7-(?:06|08)\/.+/u.test(relativeName ?? '')) {
      rbJournalParameters.push(parameter);
    } else if (/^release-reconciliation\/[1-9][0-9]{0,19}\/.+/u.test(relativeName ?? '')) {
      reconciliationJournalParameters.push(parameter);
    } else {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_JOURNAL_INVALID');
    }
  }

  const rbOwners = [];
  const rbPremutationAuthorities = [];
  for (const scenarioId of ['RB-E7-06', 'RB-E7-08']) {
    const scenarioPrefix = `/checkout/stage7/rollback/${candidateSha}/${scenarioId}`;
    const scenarioParameters = rbJournalParameters.filter(({ Name }) =>
      Name.startsWith(`${scenarioPrefix}/`),
    );
    if (scenarioParameters.length === 0) continue;
    const ownerParameter = scenarioParameters.find(
      ({ Name }) => Name === `${scenarioPrefix}/owner`,
    );
    const premutationAuthorityParameter = scenarioParameters.find(
      ({ Name }) => Name === `${scenarioPrefix}/premutation-authority`,
    );
    if (
      premutationAuthorityParameter === undefined ||
      (ownerParameter === undefined && operation !== 'OPEN_ROLLBACK_RESILIENCE') ||
      scenarioParameters.filter(({ Name }) => Name === `${scenarioPrefix}/owner`).length > 1 ||
      scenarioParameters.filter(({ Name }) => Name === `${scenarioPrefix}/premutation-authority`)
        .length !== 1 ||
      scenarioParameters
        .filter(
          ({ Name }) =>
            ![`${scenarioPrefix}/owner`, `${scenarioPrefix}/premutation-authority`].includes(Name),
        )
        .some(
          ({ Name }) =>
            !new RegExp(
              `^${scenarioPrefix}/[0-9]{6}-[0-9a-f]{64}/(?:manifest|abandoned|chunk-[0-9]{4})$`,
              'u',
            ).test(Name),
        )
    ) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RB_OWNER_INVALID');
    }
    let owner;
    let premutationAuthority;
    try {
      premutationAuthority = validateRollbackSsmPremutationAuthority(
        JSON.parse(premutationAuthorityParameter.Value),
        {
          candidateSha,
          scenarioId,
          ...(expectedReleaseId === undefined ? {} : { releaseId: expectedReleaseId }),
          ...(expectedReleaseTag === undefined ? {} : { releaseTag: expectedReleaseTag }),
          ...(expectedConfigSha256 === undefined ? {} : { configSha256: expectedConfigSha256 }),
          sourceRunId,
          sourceRunAttempt: 1,
          ...(expectedRollbackBindingSha256 === undefined
            ? {}
            : { bindingSha256: expectedRollbackBindingSha256 }),
          ...(expectedProtectedBindingSha256 === undefined
            ? {}
            : { protectedBindingSha256: expectedProtectedBindingSha256 }),
          ...(expectedRollbackRoleSha256 === undefined
            ? {}
            : { rollbackRoleSha256: expectedRollbackRoleSha256 }),
          ...(expectedJournalCleanupRoleSha256 === undefined
            ? {}
            : { journalCleanupRoleSha256: expectedJournalCleanupRoleSha256 }),
          ...(expectedJournalLifecycleSha256 === undefined
            ? {}
            : { journalLifecycleSha256: expectedJournalLifecycleSha256 }),
        },
      );
      if (JSON.stringify(premutationAuthority) !== premutationAuthorityParameter.Value) {
        fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RB_OWNER_INVALID');
      }
      if (ownerParameter === undefined) {
        if (scenarioParameters.length !== 1) {
          fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RB_OWNER_INVALID');
        }
        rbPremutationAuthorities.push(premutationAuthority);
        continue;
      }
      owner = JSON.parse(ownerParameter.Value);
      validateRollbackJournalOwner(owner, {
        candidateSha,
        scenarioId,
        sourceRunId,
        ...(expectedRollbackBindingSha256 === undefined
          ? {}
          : { bindingSha256: expectedRollbackBindingSha256 }),
        ...(expectedProtectedBindingSha256 === undefined
          ? {}
          : { protectedBindingSha256: expectedProtectedBindingSha256 }),
        ...(expectedRollbackRoleSha256 === undefined
          ? {}
          : { rollbackRoleSha256: expectedRollbackRoleSha256 }),
        ...(expectedJournalCleanupRoleSha256 === undefined
          ? {}
          : { journalCleanupRoleSha256: expectedJournalCleanupRoleSha256 }),
        ...(expectedJournalLifecycleSha256 === undefined
          ? {}
          : { journalLifecycleSha256: expectedJournalLifecycleSha256 }),
        premutationAuthority,
      });
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RB_OWNER_INVALID', error);
    }
    if (
      JSON.stringify(owner) !== ownerParameter.Value ||
      (expectedJournalCleanupRoleSha256 !== undefined &&
        owner.journalCleanupRoleSha256 !== expectedJournalCleanupRoleSha256)
    ) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RB_OWNER_INVALID');
    }
    rbOwners.push(owner);
    rbPremutationAuthorities.push(premutationAuthority);
  }

  const reconciliationOwners = [];
  const reconciliationRunIds = [
    ...new Set(
      reconciliationJournalParameters.map(
        ({ Name }) =>
          /^\/checkout\/stage7\/rollback\/[0-9a-f]{40}\/release-reconciliation\/([1-9][0-9]{0,19})\//u.exec(
            Name,
          )?.[1],
      ),
    ),
  ];
  for (const reconciliationRunId of reconciliationRunIds) {
    if (reconciliationRunId === undefined) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RECONCILIATION_INVALID');
    }
    const reconciliationPrefix = `/checkout/stage7/rollback/${candidateSha}/release-reconciliation/${reconciliationRunId}`;
    const scoped = reconciliationJournalParameters.filter(({ Name }) =>
      Name.startsWith(`${reconciliationPrefix}/`),
    );
    const ownerParameter = scoped.find(({ Name }) => Name === `${reconciliationPrefix}/owner`);
    if (
      ownerParameter === undefined ||
      scoped.filter(({ Name }) => Name === `${reconciliationPrefix}/owner`).length !== 1 ||
      scoped.some(
        ({ Name }) =>
          Name !== `${reconciliationPrefix}/owner` &&
          !new RegExp(
            `^${reconciliationPrefix}/(?:intent/[0-9]{4}|runtime-proofs/(?:rollback-check|rollback-resilience)/(?:drift|smoke)/[0-9a-f]{64}/(?:index|chunk/[0-9]{4}-[0-9a-f]{64})|(?:rollback-check|rollback-resilience)/terminal)$`,
            'u',
          ).test(Name),
      )
    ) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RECONCILIATION_INVALID');
    }
    let owner;
    let intent;
    try {
      owner = validateReleaseReconciliationJournalOwner(JSON.parse(ownerParameter.Value));
      const expectedIntentNames = new Set(
        owner.intentChunks.map(({ parameterName }) => parameterName),
      );
      if (
        scoped.some(
          ({ Name }) =>
            Name.startsWith(`${reconciliationPrefix}/intent/`) && !expectedIntentNames.has(Name),
        )
      ) {
        fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RECONCILIATION_INTENT_INVALID');
      }
      const chunks = owner.intentChunks.map((binding) => {
        const parameter = scoped.find(({ Name }) => Name === binding.parameterName);
        if (
          parameter === undefined ||
          sha256(parameter.Value) !== binding.rawSha256 ||
          Buffer.byteLength(parameter.Value, 'utf8') !== binding.bytes
        ) {
          fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RECONCILIATION_INTENT_INVALID');
        }
        return parameter.Value;
      });
      const intentText = chunks.join('');
      intent = validateReleaseReconciliationIntent(JSON.parse(intentText));
      if (
        JSON.stringify(owner) !== ownerParameter.Value ||
        sha256(intentText) !== owner.intentRawSha256 ||
        Buffer.byteLength(intentText, 'utf8') !== owner.intentBytes ||
        intent.intentSha256 !== owner.intentSha256 ||
        intent.bindingsSha256 !== owner.intentBindingsSha256 ||
        objectSha256(intent.source) !== objectSha256(owner.source)
      ) {
        fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RECONCILIATION_INTENT_INVALID');
      }
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RECONCILIATION_INVALID', error);
    }
    reconciliationOwners.push({ owner, intent });
  }
  for (const { parameter, candidateScope } of authorityParameters) {
    const expectedPrefix = `${candidateScope.path}/`;
    const parameterRunId = parameter?.Name?.slice(expectedPrefix.length);
    if (
      !object(parameter) ||
      typeof parameter.Name !== 'string' ||
      !parameter.Name.startsWith(expectedPrefix) ||
      parameter.Name.slice(expectedPrefix.length).includes('/') ||
      !RUN_ID.test(parameterRunId ?? '') ||
      names.has(parameter.Name) ||
      parameter.Type !== 'String' ||
      !Number.isSafeInteger(parameter.Version) ||
      parameter.Version !== 1
    ) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_MARKER_INVALID');
    }
    names.add(parameter.Name);
    let authority;
    try {
      authority = JSON.parse(parameter.Value ?? '');
      if (candidateScope.kind === 'FENCE') {
        validateReleaseSuccessorCompletionFence(authority, {
          candidateSha,
          sourceRunId: parameterRunId,
          sourceRunAttempt: 1,
          ...(expectedReleaseId === undefined ? {} : { releaseId: expectedReleaseId }),
          ...(expectedJournalLifecycleSha256 === undefined
            ? {}
            : { journalLifecycleSha256: expectedJournalLifecycleSha256 }),
          ...(expectedJournalCleanupRoleSha256 === undefined
            ? {}
            : { journalCleanupRoleSha256: expectedJournalCleanupRoleSha256 }),
        });
      } else {
        validateReleaseSuccessorFinalizationMarker(authority, {
          candidateSha,
          releaseId: authority.releaseId,
          sourceRunId: parameterRunId,
          sourceRunAttempt: authority.sourceRunAttempt,
          releaseEvidenceSetSha256: authority.releaseEvidenceSetSha256,
          journalLifecycleSha256: authority.journalLifecycleSha256,
          releaseFenceSha256: authority.releaseFenceSha256,
          journalRoleAuthoritySha256: authority.journalRoleAuthoritySha256,
        });
      }
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_MARKER_INVALID', error);
    }
    if (
      (expectedReleaseId !== undefined && authority.releaseId !== expectedReleaseId) ||
      (expectedReleaseEvidenceSetSha256 !== undefined &&
        authority.kind === 'RELEASE_SUCCESSOR_RECOVERY_FINALIZATION_MARKER' &&
        authority.releaseEvidenceSetSha256 !== expectedReleaseEvidenceSetSha256) ||
      (expectedJournalLifecycleSha256 !== undefined &&
        authority.journalLifecycleSha256 !== expectedJournalLifecycleSha256)
    ) {
      fail('E7_RELEASE_SUCCESSOR_MUTATION_GUARD_AUTHORITY_MISMATCH');
    }
  }
  if (authorityParameters.length > 0) fail('E7_RELEASE_CANDIDATE_FINALIZED');
  let mutationAuthorityCapability = null;
  const reconciliationOwnerMatches =
    reconciliationOwners.length === 1 &&
    reconciliationOwners[0].owner.source.runId === sourceRunId &&
    reconciliationOwners[0].owner.source.runAttempt === 1 &&
    reconciliationOwners[0].owner.source.candidateSha === candidateSha &&
    reconciliationOwners[0].owner.source.releaseId === expectedReleaseId &&
    reconciliationOwners[0].owner.source.releaseTag === expectedReleaseTag &&
    reconciliationOwners[0].owner.source.configSha256 === expectedConfigSha256 &&
    (!dedicatedOperation ||
      objectSha256(reconciliationOwners[0].intent) === objectSha256(intentAuthority.intent));
  if (operation === 'RUN_VERSIONED_ROLLBACK_CHECK') {
    if (
      rbJournalParameters.length !== 0 ||
      rbOwners.length !== 0 ||
      reconciliationJournalParameters.length === 0 ||
      !reconciliationOwnerMatches
    ) {
      fail('E7_RELEASE_SUCCESSOR_ROLLBACK_CHECK_JOURNAL_INVALID');
    }
    mutationAuthorityCapability = createMutationAuthorityCapability({
      operation,
      ...reconciliationOwners[0],
      rbOwners,
      intentAuthority,
      rollbackAuthority: null,
    });
  } else if (operation === 'OPEN_ROLLBACK_RESILIENCE') {
    if (reconciliationJournalParameters.length === 0 || !reconciliationOwnerMatches) {
      fail('E7_RELEASE_SUCCESSOR_ROLLBACK_OPEN_JOURNAL_REQUIRED');
    }
    mutationAuthorityCapability = createMutationAuthorityCapability({
      operation,
      ...reconciliationOwners[0],
      rbOwners,
      intentAuthority,
      rollbackAuthority,
    });
  } else if (operation === 'RESUME_ROLLBACK_RESILIENCE') {
    if (
      rbJournalParameters.length === 0 ||
      rbOwners.length === 0 ||
      reconciliationJournalParameters.length === 0 ||
      !reconciliationOwnerMatches
    ) {
      fail('E7_RELEASE_SUCCESSOR_ROLLBACK_RESUME_JOURNAL_REQUIRED');
    }
    mutationAuthorityCapability = createMutationAuthorityCapability({
      operation,
      ...reconciliationOwners[0],
      rbOwners,
      intentAuthority,
      rollbackAuthority,
    });
  } else if (
    operation === 'RESUME_RELEASE_RECONCILIATION' ||
    operation === 'RESUME_INCOMPLETE_RECONCILIATION'
  ) {
    if (
      rbJournalParameters.length === 0 ||
      rbOwners.length !== 2 ||
      reconciliationJournalParameters.length === 0 ||
      !reconciliationOwnerMatches
    ) {
      fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_RESUME_JOURNAL_REQUIRED');
    }
    mutationAuthorityCapability = createMutationAuthorityCapability({
      operation,
      ...reconciliationOwners[0],
      rbOwners,
      intentAuthority,
      rollbackAuthority,
    });
  } else if (journalParameters.length > 0) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_JOURNAL_BLOCKS_MUTATION');
  }
  const guard = {
    status: 'OPEN_FOR_CANDIDATE_MUTATION',
    operation,
    candidateSha,
    authoritativeSourceRunId,
    candidatePathSha256: objectSha256(
      candidatePaths.map(({ path: candidatePath }) => sha256(candidatePath)),
    ),
    journalParameterSetSha256: objectSha256(
      journalParameters.map(({ parameter }) => sha256(parameter.Name)).toSorted(),
    ),
    externalRequests,
    mutationsPerformed: 0,
  };
  if (mutationAuthorityCapability !== null) {
    Object.defineProperty(guard, MUTATION_AUTHORITY_CAPABILITY, {
      value: mutationAuthorityCapability,
      enumerable: false,
      writable: false,
      configurable: false,
    });
  }
  Object.defineProperty(guard, 'rbPremutationAuthoritySha256s', {
    value: Object.freeze(
      rbPremutationAuthorities.map(({ authoritySha256 }) => authoritySha256).toSorted(),
    ),
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return Object.freeze(guard);
};

export const runGuardedFullReleaseMutation = async ({ mutation, ...options }) => {
  if (
    typeof mutation !== 'function' ||
    DEDICATED_MUTATION_GUARD_OPERATIONS.includes(options.operation)
  ) {
    fail('E7_RELEASE_SUCCESSOR_MUTATION_CALLBACK_REQUIRED');
  }
  const guard = await guardReleaseSuccessorMutation(options);
  return { guard, result: await mutation() };
};

const dedicatedGuardOptions = ({
  intentAuthority,
  rollbackAuthority,
  operation,
  getParametersByPath,
}) => ({
  candidateSha: intentAuthority.source.candidateSha,
  sourceRunId: intentAuthority.source.runId,
  authoritativeSourceRunId: intentAuthority.source.runId,
  operation,
  getParametersByPath,
  intentAuthority,
  rollbackAuthority,
});

const requireMutationCapability = (guard, operation) => {
  const capability = guard?.[MUTATION_AUTHORITY_CAPABILITY];
  if (
    !object(capability) ||
    !mutationAuthorityCapabilities.has(capability) ||
    capability.operation !== operation
  ) {
    fail('E7_RELEASE_SUCCESSOR_MUTATION_AUTHORITY_CAPABILITY_REQUIRED');
  }
  return capability;
};

const runGuardedVersionedRollbackCheckWithAuthority = async ({
  intentAuthority,
  getParametersByPath,
  mutation,
}) => {
  if (typeof mutation !== 'function') fail('E7_RELEASE_SUCCESSOR_MUTATION_CALLBACK_REQUIRED');
  const operation = 'RUN_VERSIONED_ROLLBACK_CHECK';
  const guard = await guardReleaseSuccessorMutation(
    dedicatedGuardOptions({
      intentAuthority,
      rollbackAuthority: null,
      operation,
      getParametersByPath,
    }),
  );
  requireMutationCapability(guard, operation);
  return { guard, result: await mutation() };
};

export const RELEASE_SUCCESSOR_VERSIONED_ROLLBACK_CHECK_WRAPPER_KEYS = Object.freeze([
  'intentAuthoritySources',
  'getParametersByPath',
  'mutation',
]);

export const runGuardedVersionedRollbackCheckMutation = async (options) => {
  if (!exactKeys(options, RELEASE_SUCCESSOR_VERSIONED_ROLLBACK_CHECK_WRAPPER_KEYS)) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_CHECK_WRAPPER_INPUT_INVALID');
  }
  const { intentAuthoritySources, getParametersByPath, mutation } = options;
  return runGuardedVersionedRollbackCheckWithAuthority({
    getParametersByPath,
    mutation,
    intentAuthority: validateReleaseReconciliationIntentAuthority(intentAuthoritySources),
  });
};

const validateRollbackPremutationRecords = ({ records, intentAuthority, rollbackAuthority }) => {
  if (
    !Array.isArray(records) ||
    records.length !== 2 ||
    records.some((record) => !exactKeys(record, ['premutationAuthority', 'owner'])) ||
    records.map(({ owner }) => owner?.scenarioId).join('\0') !== ['RB-E7-06', 'RB-E7-08'].join('\0')
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID');
  }
  for (const { premutationAuthority, owner } of records) {
    try {
      validateRollbackSsmPremutationAuthority(premutationAuthority, {
        candidateSha: intentAuthority.source.candidateSha,
        scenarioId: owner.scenarioId,
        releaseId: intentAuthority.source.releaseId,
        releaseTag: intentAuthority.source.releaseTag,
        configSha256: intentAuthority.source.configSha256,
        sourceRunId: intentAuthority.source.runId,
        sourceRunAttempt: 1,
        accountId: rollbackAuthority.accountId,
        region: rollbackAuthority.awsRegion,
        roleArn: rollbackAuthority.rollbackRoleArn,
        bindingSha256: rollbackAuthority.rollbackBindingSha256,
        protectedBindingSha256: rollbackAuthority.protectedBindingSha256,
        rollbackRoleSha256: rollbackAuthority.rollbackRoleSha256,
        journalCleanupRoleSha256: rollbackAuthority.journalCleanupRoleSha256,
        journalLifecycleSha256: rollbackAuthority.journalLifecycleSha256,
      });
      validateRollbackJournalOwner(owner, {
        candidateSha: intentAuthority.source.candidateSha,
        scenarioId: owner.scenarioId,
        sourceRunId: intentAuthority.source.runId,
        bindingSha256: rollbackAuthority.rollbackBindingSha256,
        protectedBindingSha256: rollbackAuthority.protectedBindingSha256,
        rollbackRoleSha256: rollbackAuthority.rollbackRoleSha256,
        journalCleanupRoleSha256: rollbackAuthority.journalCleanupRoleSha256,
        journalLifecycleSha256: rollbackAuthority.journalLifecycleSha256,
        premutationAuthority,
      });
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID', error);
    }
  }
  return records;
};

const putRollbackPremutationRecords = async ({
  records,
  rollbackAuthority,
  putParameter,
  getParameter,
}) => {
  if (typeof putParameter !== 'function' || typeof getParameter !== 'function') {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_ADAPTER_REQUIRED');
  }
  const results = [];
  for (const { premutationAuthority, owner } of records) {
    validateRollbackSsmPremutationAuthority(premutationAuthority);
    validateRollbackJournalOwner(owner, { premutationAuthority });
    const putRecord = async ({ value: record, kind }) => {
      const value = JSON.stringify(record);
      if (Buffer.byteLength(value, 'utf8') > STANDARD_PARAMETER_MAX_BYTES) {
        fail(`E7_RELEASE_SUCCESSOR_ROLLBACK_${kind}_TOO_LARGE`);
      }
      let idempotent = false;
      try {
        const written = await putParameter({
          name: record.parameterName,
          type: 'String',
          tier: 'Standard',
          value,
          overwrite: false,
        });
        if (written?.Version !== 1) {
          fail(`E7_RELEASE_SUCCESSOR_ROLLBACK_${kind}_PUT_INVALID`);
        }
      } catch (error) {
        if (!parameterAlreadyExists(error)) throw error;
        idempotent = true;
      }
      const readback = (await getParameter({ name: record.parameterName, withDecryption: false }))
        ?.Parameter;
      const expectedArn = `arn:aws:ssm:${rollbackAuthority.awsRegion}:${rollbackAuthority.accountId}:parameter${record.parameterName}`;
      if (
        !object(readback) ||
        readback.Name !== record.parameterName ||
        readback.Type !== 'String' ||
        readback.Value !== value ||
        readback.Version !== 1 ||
        readback.ARN !== expectedArn ||
        readback.DataType !== 'text'
      ) {
        fail(`E7_RELEASE_SUCCESSOR_ROLLBACK_${kind}_READBACK_INVALID`);
      }
      return idempotent;
    };
    const premutationIdempotent = await putRecord({
      value: premutationAuthority,
      kind: 'PREMUTATION_AUTHORITY',
    });
    const ownerIdempotent = await putRecord({ value: owner, kind: 'OWNER' });
    results.push({
      ownerSha256: owner.ownerSha256,
      premutationAuthoritySha256: premutationAuthority.authoritySha256,
      parameterName: owner.parameterName,
      premutationAuthorityParameterName: premutationAuthority.parameterName,
      idempotent: premutationIdempotent && ownerIdempotent,
    });
  }
  return results;
};

const runGuardedRollbackResilienceWithAuthorities = async ({
  intentAuthority,
  rollbackAuthority,
  rollbackJournalRecords,
  getParametersByPath,
  putParameter,
  getParameter,
  mutation,
}) => {
  if (typeof mutation !== 'function') fail('E7_RELEASE_SUCCESSOR_MUTATION_CALLBACK_REQUIRED');
  const records = validateRollbackPremutationRecords({
    records: rollbackJournalRecords,
    intentAuthority,
    rollbackAuthority,
  });
  const owners = records.map(({ owner }) => owner);
  const openOperation = 'OPEN_ROLLBACK_RESILIENCE';
  const openGuard = await guardReleaseSuccessorMutation(
    dedicatedGuardOptions({
      intentAuthority,
      rollbackAuthority,
      operation: openOperation,
      getParametersByPath,
    }),
  );
  const openCapability = requireMutationCapability(openGuard, openOperation);
  const ownerHashes = new Set(owners.map(({ ownerSha256 }) => ownerSha256));
  if (openCapability.rbOwnerSha256s.some((digest) => !ownerHashes.has(digest))) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID');
  }
  const ownerWrites = await putRollbackPremutationRecords({
    records,
    rollbackAuthority,
    putParameter,
    getParameter,
  });
  const resumeOperation = 'RESUME_ROLLBACK_RESILIENCE';
  const resumeGuard = await guardReleaseSuccessorMutation(
    dedicatedGuardOptions({
      intentAuthority,
      rollbackAuthority,
      operation: resumeOperation,
      getParametersByPath,
    }),
  );
  const resumeCapability = requireMutationCapability(resumeGuard, resumeOperation);
  const expectedPremutationAuthoritySha256s = records
    .map(({ premutationAuthority }) => premutationAuthority.authoritySha256)
    .toSorted();
  if (
    resumeCapability.rbOwnerSha256s.join('\0') !== [...ownerHashes].toSorted().join('\0') ||
    resumeGuard.rbPremutationAuthoritySha256s.join('\0') !==
      expectedPremutationAuthoritySha256s.join('\0')
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID');
  }
  return { openGuard, resumeGuard, ownerWrites, result: await mutation() };
};

export const RELEASE_SUCCESSOR_ROLLBACK_RESILIENCE_WRAPPER_KEYS = Object.freeze([
  'intentAuthoritySources',
  'rollbackPremutationAuthoritySources',
  'getParametersByPath',
  'putParameter',
  'getParameter',
  'mutation',
]);

export const runGuardedRollbackResilienceMutation = async (options) => {
  if (!exactKeys(options, RELEASE_SUCCESSOR_ROLLBACK_RESILIENCE_WRAPPER_KEYS)) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_RESILIENCE_WRAPPER_INPUT_INVALID');
  }
  const {
    intentAuthoritySources,
    rollbackPremutationAuthoritySources,
    getParametersByPath,
    putParameter,
    getParameter,
    mutation,
  } = options;
  const intentAuthority = validateReleaseReconciliationIntentAuthority(intentAuthoritySources);
  const rollbackAuthority = validateReleaseSuccessorRollbackPremutationAuthority(
    rollbackPremutationAuthoritySources,
  );
  return runGuardedRollbackResilienceWithAuthorities({
    getParametersByPath,
    putParameter,
    getParameter,
    mutation,
    intentAuthority,
    rollbackAuthority,
    rollbackJournalRecords: createReleaseSuccessorRollbackPremutationRecords(rollbackAuthority),
  });
};

const runGuardedReleaseReconciliationWithAuthorities = async ({
  intentAuthority,
  rollbackAuthority,
  rollbackJournalRecords,
  getParametersByPath,
  mutation,
}) => {
  if (typeof mutation !== 'function') fail('E7_RELEASE_SUCCESSOR_MUTATION_CALLBACK_REQUIRED');
  const records = validateRollbackPremutationRecords({
    records: rollbackJournalRecords,
    intentAuthority,
    rollbackAuthority,
  });
  const owners = records.map(({ owner }) => owner);
  const operation = 'RESUME_RELEASE_RECONCILIATION';
  const guard = await guardReleaseSuccessorMutation(
    dedicatedGuardOptions({
      intentAuthority,
      rollbackAuthority,
      operation,
      getParametersByPath,
    }),
  );
  const capability = requireMutationCapability(guard, operation);
  const expectedOwnerSha256s = owners.map(({ ownerSha256 }) => ownerSha256).toSorted();
  const expectedPremutationAuthoritySha256s = records
    .map(({ premutationAuthority }) => premutationAuthority.authoritySha256)
    .toSorted();
  if (
    capability.rbOwnerSha256s.join('\0') !== expectedOwnerSha256s.join('\0') ||
    guard.rbPremutationAuthoritySha256s.join('\0') !==
      expectedPremutationAuthoritySha256s.join('\0')
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID');
  }
  return { guard, result: await mutation() };
};

const runGuardedIncompleteReleaseReconciliationWithAuthorities = async ({
  direction,
  intentAuthority,
  rollbackAuthority,
  rollbackJournalRecords,
  getParametersByPath,
  mutation,
}) => {
  if (direction !== 'REPROMOTE_CANDIDATE' || typeof mutation !== 'function') {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_INPUT_INVALID');
  }
  const records = validateRollbackPremutationRecords({
    records: rollbackJournalRecords,
    intentAuthority,
    rollbackAuthority,
  });
  const operation = 'RESUME_INCOMPLETE_RECONCILIATION';
  const guard = await guardReleaseSuccessorMutation(
    dedicatedGuardOptions({
      intentAuthority,
      rollbackAuthority,
      operation,
      getParametersByPath,
    }),
  );
  const capability = requireMutationCapability(guard, operation);
  const expectedOwnerSha256s = records.map(({ owner }) => owner.ownerSha256).toSorted();
  const expectedPremutationAuthoritySha256s = records
    .map(({ premutationAuthority }) => premutationAuthority.authoritySha256)
    .toSorted();
  if (
    capability.rbOwnerSha256s.join('\0') !== expectedOwnerSha256s.join('\0') ||
    guard.rbPremutationAuthoritySha256s.join('\0') !==
      expectedPremutationAuthoritySha256s.join('\0')
  ) {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_REREAD_MISMATCH');
  }
  return { guard, result: await mutation() };
};

export const RELEASE_SUCCESSOR_RECONCILIATION_WRAPPER_KEYS = Object.freeze([
  'intentAuthoritySources',
  'rollbackPremutationAuthoritySources',
  'rollbackCompletionAuthoritySources',
  'getParametersByPath',
  'mutation',
]);

export const runGuardedReleaseReconciliationMutation = async (options) => {
  if (!exactKeys(options, RELEASE_SUCCESSOR_RECONCILIATION_WRAPPER_KEYS)) {
    fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_WRAPPER_INPUT_INVALID');
  }
  const {
    intentAuthoritySources,
    rollbackPremutationAuthoritySources,
    rollbackCompletionAuthoritySources,
    getParametersByPath,
    mutation,
  } = options;
  const intentAuthority = validateReleaseReconciliationIntentAuthority(intentAuthoritySources);
  const premutationAuthority = validateReleaseSuccessorRollbackPremutationAuthority(
    rollbackPremutationAuthoritySources,
  );
  return runGuardedReleaseReconciliationWithAuthorities({
    getParametersByPath,
    mutation,
    intentAuthority,
    rollbackAuthority: validateReleaseSuccessorRollbackCompletionAuthority({
      premutationAuthority,
      ...rollbackCompletionAuthoritySources,
    }),
    rollbackJournalRecords: createReleaseSuccessorRollbackPremutationRecords(premutationAuthority),
  });
};

export const RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_WRAPPER_KEYS = Object.freeze([
  'direction',
  'intentAuthoritySources',
  'getParametersByPath',
  'mutation',
]);

const loadLiveRollbackPremutationRecords = async ({ intentAuthority, getParametersByPath }) => {
  if (typeof getParametersByPath !== 'function') {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_ADAPTER_REQUIRED');
  }
  const candidateRoot = `/checkout/stage7/rollback/${intentAuthority.source.candidateSha}`;
  const parameters = [];
  const tokens = new Set();
  let nextToken;
  let externalRequests = 0;
  do {
    if (externalRequests >= MAX_GUARD_PAGES_PER_SCOPE) {
      fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_LIST_INVALID');
    }
    const response = await getParametersByPath({
      path: candidateRoot,
      recursive: true,
      withDecryption: false,
      maxResults: MAX_GUARD_PARAMETERS_PER_PAGE,
      ...(nextToken === undefined ? {} : { nextToken }),
    });
    externalRequests += 1;
    const hasNextToken = object(response) && Object.hasOwn(response, 'NextToken');
    if (
      !object(response) ||
      !exactKeys(response, hasNextToken ? ['Parameters', 'NextToken'] : ['Parameters']) ||
      !Array.isArray(response.Parameters) ||
      response.Parameters.length > MAX_GUARD_PARAMETERS_PER_PAGE
    ) {
      fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_LIST_INVALID');
    }
    parameters.push(...response.Parameters);
    nextToken = response.NextToken;
    if (nextToken !== undefined) {
      if (
        typeof nextToken !== 'string' ||
        nextToken.length < 1 ||
        nextToken.length > 4096 ||
        tokens.has(nextToken)
      ) {
        fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_TOKEN_INVALID');
      }
      tokens.add(nextToken);
    }
  } while (nextToken !== undefined);
  const authorityParameters = parameters.filter((parameter) =>
    /^\/checkout\/stage7\/rollback\/[0-9a-f]{40}\/RB-E7-(?:06|08)\/(?:owner|premutation-authority)$/u.test(
      parameter?.Name ?? '',
    ),
  );
  if (
    authorityParameters.length !== 4 ||
    new Set(authorityParameters.map(({ Name }) => Name)).size !== 4 ||
    authorityParameters.some(
      (parameter) =>
        !object(parameter) ||
        parameter.Type !== 'String' ||
        typeof parameter.Value !== 'string' ||
        parameter.Version !== 1,
    )
  ) {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_AUTHORITY_SET_INVALID');
  }
  const records = ['RB-E7-06', 'RB-E7-08'].map((scenarioId) => {
    const prefix = `${candidateRoot}/${scenarioId}`;
    const premutationParameter = authorityParameters.find(
      ({ Name }) => Name === `${prefix}/premutation-authority`,
    );
    const ownerParameter = authorityParameters.find(({ Name }) => Name === `${prefix}/owner`);
    try {
      const premutationAuthority = validateRollbackSsmPremutationAuthority(
        JSON.parse(premutationParameter.Value),
        {
          candidateSha: intentAuthority.source.candidateSha,
          scenarioId,
          releaseId: intentAuthority.source.releaseId,
          releaseTag: intentAuthority.source.releaseTag,
          configSha256: intentAuthority.source.configSha256,
          sourceRunId: intentAuthority.source.runId,
          sourceRunAttempt: 1,
        },
      );
      const owner = validateRollbackJournalOwner(JSON.parse(ownerParameter.Value), {
        candidateSha: intentAuthority.source.candidateSha,
        scenarioId,
        sourceRunId: intentAuthority.source.runId,
        premutationAuthority,
      });
      if (
        JSON.stringify(premutationAuthority) !== premutationParameter.Value ||
        JSON.stringify(owner) !== ownerParameter.Value
      ) {
        fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_AUTHORITY_BYTES_INVALID');
      }
      return Object.freeze({ premutationAuthority, owner });
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_AUTHORITY_INVALID', error);
    }
  });
  const [first, second] = records.map(({ premutationAuthority }) => premutationAuthority);
  const sharedProjection = (value) => ({
    candidateSha: value.candidateSha,
    releaseId: value.releaseId,
    releaseTag: value.releaseTag,
    configSha256: value.configSha256,
    execution: value.execution,
    executionSha256: value.executionSha256,
    rollbackBindingPreimage: value.rollbackBindingPreimage,
    bindingSha256: value.bindingSha256,
    protectedBindingSha256: value.protectedBindingSha256,
    rollbackRoleSha256: value.rollbackRoleSha256,
    journalCleanupRoleSha256: value.journalCleanupRoleSha256,
    journalLifecycleSha256: value.journalLifecycleSha256,
  });
  if (objectSha256(sharedProjection(first)) !== objectSha256(sharedProjection(second))) {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_AUTHORITY_SWAP');
  }
  return { records: Object.freeze(records), externalRequests };
};

const runGuardedIncompleteReleaseReconciliationFromIntentAuthority = async ({
  direction,
  intentAuthority,
  getParametersByPath,
  mutation,
}) => {
  if (direction !== 'REPROMOTE_CANDIDATE' || typeof mutation !== 'function') {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_INPUT_INVALID');
  }
  const bootstrap = await loadLiveRollbackPremutationRecords({
    intentAuthority,
    getParametersByPath,
  });
  const rollbackAuthority = reconstructReleaseSuccessorRollbackPremutationAuthority({
    premutationAuthorities: bootstrap.records.map(
      ({ premutationAuthority }) => premutationAuthority,
    ),
    expected: {
      candidateSha: intentAuthority.source.candidateSha,
      releaseId: intentAuthority.source.releaseId,
      releaseTag: intentAuthority.source.releaseTag,
      configSha256: intentAuthority.source.configSha256,
      sourceRunId: intentAuthority.source.runId,
      sourceRunAttempt: 1,
      accountId: intentAuthority.authority.accountId,
      awsRegion: intentAuthority.authority.region,
      rollbackRoleArn: intentAuthority.authority.rollbackRoleArn,
      journalCleanupRoleArn: intentAuthority.authority.journalRoleArn,
    },
  });
  const resumed = await runGuardedIncompleteReleaseReconciliationWithAuthorities({
    direction,
    intentAuthority,
    rollbackAuthority,
    rollbackJournalRecords: bootstrap.records,
    getParametersByPath,
    mutation,
  });
  return {
    ...resumed,
    bootstrapExternalRequests: bootstrap.externalRequests,
  };
};

export const runGuardedIncompleteReleaseReconciliationMutation = async (options) => {
  if (!exactKeys(options, RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_WRAPPER_KEYS)) {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_WRAPPER_INPUT_INVALID');
  }
  const { direction, intentAuthoritySources, getParametersByPath, mutation } = options;
  if (direction !== 'REPROMOTE_CANDIDATE' || typeof mutation !== 'function') {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_INPUT_INVALID');
  }
  return runGuardedIncompleteReleaseReconciliationFromIntentAuthority({
    direction,
    intentAuthority: validateReleaseReconciliationIntentAuthority(intentAuthoritySources),
    getParametersByPath,
    mutation,
  });
};

export const finalizeReleaseSuccessorRecovery = async ({
  commitment,
  journalCleanupRoleArn,
  rollbackRoleArn,
  ephemeralCleanupRoleArn,
  lifecycleCleanupRoleSha256,
  callerIdentitySource,
  awsVersionSource,
  roleAuditSource,
  awsAuthSource,
  frozenEffectivePermissionsSource,
  liveEffectivePermissionsSource,
  expectedSessionName,
  expectedPermissionsBoundaryArn,
  putParameter,
  getParameter,
}) => {
  if (typeof putParameter !== 'function' || typeof getParameter !== 'function') {
    fail('E7_RELEASE_SUCCESSOR_FINALIZATION_ADAPTER_REQUIRED');
  }
  const roles = validateReleaseSuccessorFinalizationAuthority({
    journalCleanupRoleArn,
    rollbackRoleArn,
    ephemeralCleanupRoleArn,
    lifecycleCleanupRoleSha256,
  });
  validateCommitment(commitment);
  const callerAuthority = validateReleaseSuccessorCallerAuthority({
    callerIdentitySource,
    awsVersionSource,
    roleAuditSource,
    awsAuthSource,
    frozenEffectivePermissionsSource,
    liveEffectivePermissionsSource,
    journalCleanupRoleArn,
    expectedSessionName,
    expectedAwsCliVersion: commitment.awsCliVersion,
    expectedPermissionsBoundaryArn,
  });
  const fenceParameterName = `${RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT}/${commitment.candidateSha}/${commitment.sourceRunId}`;
  const fenceResponse = await getParameter({
    name: fenceParameterName,
    withDecryption: false,
  });
  const fenceParameter = fenceResponse?.Parameter;
  const fenceDocument = strictExternalJson(
    fenceParameter?.Value ?? '',
    'E7_RELEASE_SUCCESSOR_FENCE_VALUE_INVALID',
  );
  const releaseFence = validateReleaseSuccessorCompletionFence(fenceDocument.value, {
    candidateSha: commitment.candidateSha,
    releaseId: commitment.releaseId,
    sourceRunId: commitment.sourceRunId,
    sourceRunAttempt: commitment.sourceRunAttempt,
    journalLifecycleSha256: commitment.journalLifecycleSha256,
    journalCleanupRoleSha256: roles.journalCleanupRoleSha256,
    journalRoleAuthoritySha256: callerAuthority.roleAuthoritySha256,
    evidenceBindings: commitment.evidenceBindings,
  });
  if (
    releaseFence.fenceSha256 !== commitment.releaseFenceSha256 ||
    commitment.journalCleanupRoleSha256 !== roles.journalCleanupRoleSha256 ||
    commitment.journalRoleAuthoritySha256 !== callerAuthority.roleAuthoritySha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_COMMITMENT_MISMATCH');
  }
  const releaseFenceBytes = jsonBytes(releaseFence);
  const expectedFenceArn = `arn:aws:ssm:${commitment.awsRegion}:${journalCleanupRoleArn.split(':')[4]}:parameter${fenceParameterName}`;
  if (
    !object(fenceParameter) ||
    fenceParameter.Name !== fenceParameterName ||
    fenceParameter.Type !== 'String' ||
    !releaseFenceBytes.equals(fenceDocument.bytes) ||
    fenceParameter.Version !== 1 ||
    fenceParameter.ARN !== expectedFenceArn ||
    fenceParameter.DataType !== 'text' ||
    !utc(fenceParameter.LastModifiedDate)
  ) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_GET_MISMATCH');
  }
  const marker = createReleaseSuccessorFinalizationMarker({
    commitment,
    releaseFence,
    callerAuthority,
  });
  const markerBytes = jsonBytes(marker);
  if (markerBytes.length > STANDARD_PARAMETER_MAX_BYTES) {
    fail('E7_RELEASE_SUCCESSOR_MARKER_STANDARD_PARAMETER_TOO_LARGE');
  }
  const parameterName = `${RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT}/${commitment.candidateSha}/${commitment.sourceRunId}`;
  let idempotent = false;
  let putVersion;
  try {
    const put = await putParameter({
      name: parameterName,
      type: 'String',
      tier: 'Standard',
      value: markerBytes.toString('utf8'),
      overwrite: false,
    });
    putVersion = put?.Version;
    if (putVersion !== 1) {
      fail('E7_RELEASE_SUCCESSOR_FINALIZATION_PUT_RESPONSE_INVALID');
    }
  } catch (error) {
    if (!parameterAlreadyExists(error)) throw error;
    idempotent = true;
  }
  const response = await getParameter({ name: parameterName, withDecryption: false });
  const parameter = response?.Parameter;
  const expectedMarkerArn = `arn:aws:ssm:${commitment.awsRegion}:${journalCleanupRoleArn.split(':')[4]}:parameter${parameterName}`;
  if (
    !object(parameter) ||
    parameter.Name !== parameterName ||
    parameter.Type !== 'String' ||
    parameter.Value !== markerBytes.toString('utf8') ||
    parameter.Version !== 1 ||
    parameter.ARN !== expectedMarkerArn ||
    parameter.DataType !== 'text' ||
    (!idempotent && parameter.Version !== putVersion) ||
    !utc(parameter.LastModifiedDate)
  ) {
    fail('E7_RELEASE_SUCCESSOR_FINALIZATION_GET_MISMATCH');
  }
  const provenanceBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_FINAL_DISABLE_PROVENANCE',
    status: 'PASS',
    candidateSha: commitment.candidateSha,
    releaseId: commitment.releaseId,
    sourceRunId: commitment.sourceRunId,
    sourceRunAttempt: commitment.sourceRunAttempt,
    decision: 'SAME_RUN_RECOVERY_FINALIZED',
    safeToHandoff: true,
    releaseEvidenceSetSha256: commitment.releaseEvidenceSetSha256,
    journalLifecycleSha256: commitment.journalLifecycleSha256,
    releaseFence: {
      parameterName: fenceParameterName,
      parameterNameSha256: sha256(fenceParameterName),
      version: fenceParameter.Version,
      valueRawSha256: sha256(releaseFenceBytes),
      valueCanonicalSha256: objectSha256(releaseFence),
      fenceSha256: releaseFence.fenceSha256,
    },
    marker: {
      parameterName,
      parameterNameSha256: sha256(parameterName),
      version: parameter.Version,
      valueRawSha256: sha256(markerBytes),
      valueCanonicalSha256: objectSha256(marker),
      markerSha256: marker.markerSha256,
    },
    authority: {
      journalCleanupRoleSha256: roles.journalCleanupRoleSha256,
      rollbackRoleSha256: roles.rollbackRoleSha256,
      ephemeralCleanupRoleSha256: roles.ephemeralCleanupRoleSha256,
      roleAuthority: callerAuthority.roleAuthority,
      roleAuthoritySha256: callerAuthority.roleAuthoritySha256,
      callerAttemptAuthority: callerAuthority.callerAttemptAuthority,
      callerAttemptAuthoritySha256: callerAuthority.callerAttemptAuthoritySha256,
      auditEvidence: callerAuthority.auditEvidence,
      auditEvidenceSha256: callerAuthority.auditEvidenceSha256,
      rolesDistinct: true,
    },
    writeMode: 'SSM_PUT_PARAMETER_OVERWRITE_FALSE_THEN_GET',
    idempotent,
    completedAtUtc: parameter.LastModifiedDate,
    authorityReadRequests: callerAuthority.authorityReadRequests,
    externalRequests: 3 + callerAuthority.authorityReadRequests,
    mutationsPerformed: idempotent ? 0 : 1,
    containsSensitiveData: false,
  };
  const provenance = {
    ...provenanceBody,
    provenanceSha256: objectSha256(provenanceBody),
  };
  validateReleaseSuccessorFinalDisableProvenance(provenance, {
    candidateSha: commitment.candidateSha,
    releaseId: commitment.releaseId,
    sourceRunId: commitment.sourceRunId,
    sourceRunAttempt: commitment.sourceRunAttempt,
    releaseEvidenceSetSha256: commitment.releaseEvidenceSetSha256,
    journalLifecycleSha256: commitment.journalLifecycleSha256,
    releaseFenceDocument: {
      value: releaseFence,
      bytes: releaseFenceBytes,
      canonicalSha256: objectSha256(releaseFence),
    },
    markerDocument: {
      value: marker,
      bytes: markerBytes,
      canonicalSha256: objectSha256(marker),
    },
    earliestUtc: parameter.LastModifiedDate,
  });
  return {
    releaseFence,
    releaseFenceBytes,
    marker,
    markerBytes,
    provenance,
    parameterName,
  };
};

export const selfTestReleaseSuccessorFinalization = async () => {
  const journalRole = 'arn:aws:iam::123456789012:role/stage7-release-journal-cleanup';
  const rollbackRole = 'arn:aws:iam::123456789012:role/stage7-release-rollback';
  const ephemeralRole = 'arn:aws:iam::123456789012:role/stage7-prerelease-cleanup';
  const region = 'us-east-1';
  const boundary = 'arn:aws:iam::123456789012:policy/stage7-release-journal-boundary';
  const roleAudit = {
    Path: '/',
    RoleName: 'stage7-release-journal-cleanup',
    RoleId: 'AROAEXAMPLEROLE1234',
    Arn: journalRole,
    CreateDate: '2026-08-18T00:00:00Z',
    MaxSessionDuration: 3600,
    PermissionsBoundary: {
      PermissionsBoundaryType: 'Policy',
      PermissionsBoundaryArn: boundary,
    },
    AssumeRolePolicyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: {
            Federated:
              'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com',
          },
          Action: 'sts:AssumeRoleWithWebIdentity',
          Condition: {
            StringEquals: {
              'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
              'token.actions.githubusercontent.com:sub': [
                'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release',
                'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-reconciliation-recovery',
                'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-successor-post-success',
              ],
            },
          },
        },
      ],
    },
  };
  const callerSource = (sessionName) =>
    jsonBytes({
      UserId: `AROAEXAMPLEROLE1234:${sessionName}`,
      Account: '123456789012',
      Arn: `arn:aws:sts::123456789012:assumed-role/stage7-release-journal-cleanup/${sessionName}`,
    });
  const roleAuditSource = jsonBytes(roleAudit);
  const awsVersionSource = Buffer.from('aws-cli/2.31.0 Python/3.13 Linux/6.8\n', 'utf8');
  const effectivePermissions = createReleaseSuccessorIamAuthoritySelfTestFixture();
  const effectivePermissionsSource = jsonBytes(effectivePermissions);
  const awsAuthSource = jsonBytes({
    kind: 'AWS_READ_ONLY_PREFLIGHT',
    status: 'PASS',
    scope: 'full',
    candidateSha: 'a'.repeat(40),
    releaseId: 'rel-20260817-1100-aaaaaaa',
    configSha256: 'b'.repeat(64),
    manifestSha256: 'c'.repeat(64),
    mutationsPerformed: 0,
    journalRoleEffectivePermissionsRawSha256: sha256(effectivePermissionsSource),
    journalRoleEffectivePermissionsSha256: effectivePermissions.effectivePermissionsSha256,
    containsSensitiveData: false,
  });
  const sessionOne = 'e7-release-journal-999-1';
  const sessionTwo = 'e7-release-journal-999-2';
  const callerAuthority = validateReleaseSuccessorCallerAuthority({
    callerIdentitySource: callerSource(sessionOne),
    awsVersionSource,
    roleAuditSource,
    awsAuthSource,
    frozenEffectivePermissionsSource: effectivePermissionsSource,
    liveEffectivePermissionsSource: effectivePermissionsSource,
    journalCleanupRoleArn: journalRole,
    expectedSessionName: sessionOne,
    expectedAwsCliVersion: '2.31.0',
    expectedPermissionsBoundaryArn: boundary,
  });
  const evidenceBindings = Object.fromEntries(
    EVIDENCE_BINDING_KEYS.map((name, index) => [
      name,
      {
        rawSha256: (index + 3).toString(16).repeat(64),
        canonicalSha256: (index + 10).toString(16).repeat(64),
        bytes: 100 + index,
      },
    ]),
  );
  const authorityBindings = Object.fromEntries(
    RELEASE_SUCCESSOR_FENCE_AUTHORITY_BINDING_KEYS.map((name, index) => [
      name,
      {
        rawSha256: (index + 20).toString(16).at(-1).repeat(64),
        canonicalSha256: name === 'rawDiff' ? null : (index + 40).toString(16).at(-1).repeat(64),
        bytes: 200 + index,
      },
    ]),
  );
  const authoritySetSha256 = objectSha256(authorityBindings);
  const parameters = new Map();
  const parameterWrites = [];
  const putParameter = async ({ name, value, overwrite, tier }) => {
    assert.equal(overwrite, false);
    assert.equal(tier, 'Standard');
    if (parameters.has(name)) {
      const error = new Error('ParameterAlreadyExists');
      error.code = 'ParameterAlreadyExists';
      throw error;
    }
    parameterWrites.push(name);
    parameters.set(name, { value, version: 1, modified: '2026-08-18T05:00:00.000Z' });
    return { Version: 1 };
  };
  const getParameter = async ({ name }) => {
    const entry = parameters.get(name);
    return {
      Parameter: {
        Name: name,
        Type: 'String',
        Value: entry.value,
        Version: entry.version,
        LastModifiedDate: entry.modified,
        ARN: `arn:aws:ssm:${region}:123456789012:parameter${name}`,
        DataType: 'text',
      },
    };
  };
  const getParametersByPath = async (request) => {
    assert.equal(
      exactKeys(
        request,
        request.nextToken === undefined
          ? ['path', 'recursive', 'withDecryption', 'maxResults']
          : ['path', 'recursive', 'withDecryption', 'maxResults', 'nextToken'],
      ),
      true,
    );
    assert.equal(request.withDecryption, false);
    assert.equal(request.maxResults, MAX_GUARD_PARAMETERS_PER_PAGE);
    const { path: candidatePath, nextToken } = request;
    const pageOffset = nextToken === undefined ? 0 : Number(nextToken.slice('offset-'.length));
    const matches = [...parameters.entries()]
      .filter(([name]) => name.startsWith(`${candidatePath}/`))
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([Name, entry]) => ({
        Name,
        Type: 'String',
        Value: entry.value,
        Version: entry.version,
      }));
    const Parameters = matches.slice(pageOffset, pageOffset + MAX_GUARD_PARAMETERS_PER_PAGE);
    const followingOffset = pageOffset + Parameters.length;
    return followingOffset < matches.length
      ? { Parameters, NextToken: `offset-${followingOffset}` }
      : { Parameters };
  };
  for (const [index, authorityName] of EVIDENCE_BINDING_KEYS.entries()) {
    const rehashedBindings = {
      ...evidenceBindings,
      [authorityName]: {
        ...evidenceBindings[authorityName],
        rawSha256: (index + 12).toString(16).repeat(64),
        canonicalSha256: (index + 17).toString(16).repeat(64),
      },
    };
    assert.throws(
      () =>
        createReleaseSuccessorCompletionFence({
          sourceRunId: '123456789',
          sourceRunAttempt: 1,
          candidateSha: 'a'.repeat(40),
          releaseId: 'rel-20260817-1100-aaaaaaa',
          journalLifecycleSha256: '1'.repeat(64),
          evidenceBindings: rehashedBindings,
          journalCleanupRoleArn: journalRole,
          journalRoleAuthoritySha256: callerAuthority.roleAuthoritySha256,
        }),
      (error) => error.code === 'E7_RELEASE_SUCCESSOR_FENCE_SEMANTIC_AUTHORITY_REQUIRED',
    );
  }
  assert.equal(parameters.size, 0);
  const fence = createReleaseSuccessorCompletionFenceUnchecked({
    sourceRunId: '123456789',
    sourceRunAttempt: 1,
    candidateSha: 'a'.repeat(40),
    releaseId: 'rel-20260817-1100-aaaaaaa',
    journalLifecycleSha256: '1'.repeat(64),
    evidenceBindings,
    authorityBindings,
    authoritySetSha256,
    journalCleanupRoleArn: journalRole,
    journalRoleAuthoritySha256: callerAuthority.roleAuthoritySha256,
  });
  await putReleaseSuccessorCompletionFence({
    fence,
    journalCleanupRoleArn: journalRole,
    awsRegion: region,
    putParameter,
    getParameter,
  });
  const commitment = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_EVIDENCE_SET_COMMITMENT',
    status: 'PASS',
    repository: REPOSITORY,
    sourceRunId: '123456789',
    sourceRunAttempt: 1,
    candidateSha: 'a'.repeat(40),
    releaseId: 'rel-20260817-1100-aaaaaaa',
    journalLifecycleSha256: '1'.repeat(64),
    releaseEvidenceSetSha256: '2'.repeat(64),
    awsCliVersion: '2.31.0',
    awsRegion: region,
    evidenceBindings,
    releaseFenceSha256: fence.fenceSha256,
    journalCleanupRoleSha256: sha256(journalRole),
    journalRoleAuthoritySha256: callerAuthority.roleAuthoritySha256,
    containsSensitiveData: false,
  };
  const options = (sessionName) => ({
    commitment,
    journalCleanupRoleArn: journalRole,
    rollbackRoleArn: rollbackRole,
    ephemeralCleanupRoleArn: ephemeralRole,
    lifecycleCleanupRoleSha256: sha256(journalRole),
    callerIdentitySource: callerSource(sessionName),
    awsVersionSource,
    roleAuditSource,
    awsAuthSource,
    frozenEffectivePermissionsSource: effectivePermissionsSource,
    liveEffectivePermissionsSource: effectivePermissionsSource,
    expectedSessionName: sessionName,
    expectedPermissionsBoundaryArn: boundary,
    putParameter,
    getParameter,
  });
  const first = await finalizeReleaseSuccessorRecovery(options(sessionOne));
  const second = await finalizeReleaseSuccessorRecovery(options(sessionTwo));
  assert.equal(first.provenance.idempotent, false);
  assert.equal(second.provenance.idempotent, true);
  assert.equal(first.marker.markerSha256, second.marker.markerSha256);
  assert.throws(
    () =>
      validateReleaseSuccessorFinalizationAuthority({
        journalCleanupRoleArn: journalRole,
        rollbackRoleArn: rollbackRole,
        ephemeralCleanupRoleArn: ephemeralRole,
        lifecycleCleanupRoleSha256: sha256(ephemeralRole),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_DEDICATED_ROLE_REQUIRED',
  );
  await assert.rejects(
    finalizeReleaseSuccessorRecovery({
      ...options(sessionTwo),
      commitment: { ...commitment, releaseEvidenceSetSha256: '3'.repeat(64) },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_FINALIZATION_GET_MISMATCH',
  );
  let mutations = 0;
  await assert.rejects(
    runGuardedFullReleaseMutation({
      candidateSha: commitment.candidateSha,
      sourceRunId: commitment.sourceRunId,
      authoritativeSourceRunId: commitment.sourceRunId,
      operation: 'DEPLOY_API',
      getParametersByPath,
      expectedReleaseId: commitment.releaseId,
      expectedReleaseEvidenceSetSha256: commitment.releaseEvidenceSetSha256,
      expectedJournalLifecycleSha256: commitment.journalLifecycleSha256,
      mutation: async () => {
        mutations += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_CANDIDATE_FINALIZED',
  );
  assert.equal(mutations, 0);
  await assert.rejects(
    runGuardedFullReleaseMutation({
      candidateSha: commitment.candidateSha,
      sourceRunId: '987654321',
      authoritativeSourceRunId: '987654321',
      operation: 'SEED_DATA',
      getParametersByPath,
      expectedReleaseId: commitment.releaseId,
      mutation: async () => {
        mutations += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_CANDIDATE_FINALIZED',
  );
  assert.equal(mutations, 0);
  const open = await runGuardedFullReleaseMutation({
    candidateSha: 'b'.repeat(40),
    sourceRunId: '987654321',
    authoritativeSourceRunId: '987654321',
    operation: 'ACTIVATE_CANDIDATE',
    getParametersByPath,
    mutation: async () => {
      mutations += 1;
      return 'MUTATED';
    },
  });
  assert.equal(open.result, 'MUTATED');
  assert.equal(mutations, 1);
  const paginationGuardOptions = {
    sourceRunId: '987654321',
    authoritativeSourceRunId: '987654321',
    operation: 'DEPLOY_API',
    mutation: async () => {
      mutations += 1;
    },
  };
  assert.equal(MAX_GUARD_PARAMETERS, 480);
  let paginationCalls = 0;
  await assert.rejects(
    runGuardedFullReleaseMutation({
      ...paginationGuardOptions,
      candidateSha: 'd'.repeat(40),
      getParametersByPath: async () => {
        paginationCalls += 1;
        return { Parameters: [], NextToken: `page-${paginationCalls}` };
      },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_MUTATION_GUARD_LIST_INVALID',
  );
  assert.equal(paginationCalls, MAX_GUARD_PAGES_PER_SCOPE);
  await assert.rejects(
    runGuardedFullReleaseMutation({
      ...paginationGuardOptions,
      candidateSha: 'e'.repeat(40),
      getParametersByPath: async () => ({
        Parameters: Array.from({ length: MAX_GUARD_PARAMETERS_PER_PAGE + 1 }, () => ({})),
      }),
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_MUTATION_GUARD_LIST_INVALID',
  );
  await assert.rejects(
    runGuardedFullReleaseMutation({
      ...paginationGuardOptions,
      candidateSha: 'f'.repeat(40),
      getParametersByPath: async () => ({ Parameters: [], unexpected: true }),
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_MUTATION_GUARD_LIST_INVALID',
  );
  assert.equal(mutations, 1);
  const journalCandidate = 'c'.repeat(40);
  const journalLifecycleSha256 = '5'.repeat(64);
  const rbPremutationExecution = {
    mode: 'AWS_REAL',
    repository: REPOSITORY,
    workflow: 'stage7-rollback-resilience.yml',
    runId: '777777777',
    runAttempt: '1',
    githubActions: true,
    githubRef: 'refs/heads/master',
    githubSha: journalCandidate,
    protectedEnvironment: 'assessment-release-recovery',
    accountId: '123456789012',
    region,
    roleArn: rollbackRole,
    startedAtUtc: '2026-08-18T04:59:00.000Z',
  };
  const rollbackBindingPreimage = {
    freezeManifestSha256: '1'.repeat(64),
    previousReleaseManifestSha256: '2'.repeat(64),
    candidateRecordSha256: '3'.repeat(64),
    approvalSha256: '4'.repeat(64),
    awsAuthEvidenceSha256: '5'.repeat(64),
    iamEffectivePermissionsBindingSha256: '6'.repeat(64),
    approvedPlanSha256: '7'.repeat(64),
    deploymentEvidenceSha256: '8'.repeat(64),
    observabilityEvidenceSha256: '9'.repeat(64),
    activationEvidenceSha256: 'a'.repeat(64),
    externalAuthorizationEvidenceSha256: 'b'.repeat(64),
    authorizationBudgetSha256: 'c'.repeat(64),
    reconciliationRecoveryRoleAuthoritySha256: 'd'.repeat(64),
    baseRehearsalSha256: 'e'.repeat(64),
  };
  const rbPremutationExecutionSha256 = objectSha256(rbPremutationExecution);
  const rollbackBindingSha256 = objectSha256({
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_BINDING',
    candidateSha: journalCandidate,
    releaseId: 'rel-20260817-1100-ccccccc',
    configSha256: '8'.repeat(64),
    ...rollbackBindingPreimage,
    journalCleanupRoleSha256: sha256(journalRole),
    executionSha256: rbPremutationExecutionSha256,
    containsSensitiveData: false,
  });
  const protectedBindingSha256 = objectSha256({
    STAGE7_AUTHORIZED_RUN_ID: rbPremutationExecution.runId,
    STAGE7_AUTHORIZED_RUN_ATTEMPT: rbPremutationExecution.runAttempt,
    STAGE7_AUTHORIZED_CANDIDATE_SHA: journalCandidate,
    STAGE7_AUTHORIZED_FREEZE_SHA256: rollbackBindingPreimage.freezeManifestSha256,
    STAGE7_AUTHORIZED_APPROVAL_SHA256: rollbackBindingPreimage.approvalSha256,
    STAGE7_AUTHORIZED_AWS_AUTH_SHA256: rollbackBindingPreimage.awsAuthEvidenceSha256,
    STAGE7_AUTHORIZED_PLAN_SHA256: rollbackBindingPreimage.approvedPlanSha256,
    STAGE7_AUTHORIZED_DEPLOYMENT_SHA256: rollbackBindingPreimage.deploymentEvidenceSha256,
    STAGE7_AUTHORIZED_OBSERVABILITY_SHA256: rollbackBindingPreimage.observabilityEvidenceSha256,
    STAGE7_AUTHORIZED_ACTIVATION_SHA256: rollbackBindingPreimage.activationEvidenceSha256,
    STAGE7_AUTHORIZED_EXTERNAL_AUTHORIZATION_SHA256:
      rollbackBindingPreimage.externalAuthorizationEvidenceSha256,
    STAGE7_AUTHORIZED_AUTHORIZATION_BUDGET_SHA256:
      rollbackBindingPreimage.authorizationBudgetSha256,
    STAGE7_AUTHORIZED_REHEARSAL_SHA256: rollbackBindingPreimage.baseRehearsalSha256,
    STAGE7_AUTHORIZED_JOURNAL_CLEANUP_ROLE_SHA256: sha256(journalRole),
  });
  const selfTestRbPremutationAuthority = (scenarioId) => {
    const body = {
      schemaVersion: 1,
      stage: 7,
      kind: 'ROLLBACK_RESILIENCE_SSM_PREMUTATION_AUTHORITY',
      status: 'PREMUTATION_PREIMAGE_BOUND_IMMUTABLE',
      candidateSha: journalCandidate,
      scenarioId,
      releaseId: 'rel-20260817-1100-ccccccc',
      releaseTag: 'v2026.8.17',
      configSha256: '8'.repeat(64),
      rollbackBindingPreimage,
      execution: rbPremutationExecution,
      executionSha256: rbPremutationExecutionSha256,
      bindingSha256: rollbackBindingSha256,
      protectedBindingSha256,
      rollbackRoleSha256: sha256(rollbackRole),
      journalCleanupRoleSha256: sha256(journalRole),
      journalLifecycleSha256,
      parameterName: `/checkout/stage7/rollback/${journalCandidate}/${scenarioId}/premutation-authority`,
      containsSensitiveData: false,
    };
    return { ...body, authoritySha256: objectSha256(body) };
  };
  const rb06PremutationAuthority = selfTestRbPremutationAuthority('RB-E7-06');
  const rb08PremutationAuthority = selfTestRbPremutationAuthority('RB-E7-08');
  const premutationBinding = (value) => ({
    premutationAuthorityParameterName: value.parameterName,
    premutationAuthorityRawSha256: sha256(JSON.stringify(value)),
    premutationAuthorityCanonicalSha256: objectSha256(value),
    premutationAuthorityBytes: Buffer.byteLength(JSON.stringify(value), 'utf8'),
  });
  const rbOwnerBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_SSM_JOURNAL_OWNER',
    status: 'OWNED_IMMUTABLE',
    candidateSha: journalCandidate,
    scenarioId: 'RB-E7-06',
    sourceRunId: '777777777',
    sourceRunAttempt: 1,
    bindingSha256: rollbackBindingSha256,
    protectedBindingSha256,
    rollbackRoleSha256: sha256(rollbackRole),
    journalCleanupRoleSha256: sha256(journalRole),
    journalLifecycleSha256,
    ...premutationBinding(rb06PremutationAuthority),
    parameterName: `/checkout/stage7/rollback/${journalCandidate}/RB-E7-06/owner`,
    containsSensitiveData: false,
  };
  const rbOwner = { ...rbOwnerBody, ownerSha256: objectSha256(rbOwnerBody) };
  const rb08OwnerBody = {
    ...rbOwnerBody,
    scenarioId: 'RB-E7-08',
    ...premutationBinding(rb08PremutationAuthority),
    parameterName: `/checkout/stage7/rollback/${journalCandidate}/RB-E7-08/owner`,
  };
  const rb08Owner = { ...rb08OwnerBody, ownerSha256: objectSha256(rb08OwnerBody) };
  const rbJournalRecords = [
    { premutationAuthority: rb06PremutationAuthority, owner: rbOwner },
    { premutationAuthority: rb08PremutationAuthority, owner: rb08Owner },
  ];
  parameters.set(rbOwner.parameterName, {
    value: JSON.stringify(rbOwner),
    version: 1,
    modified: '2026-08-18T05:00:00.000Z',
  });
  parameters.set(rb06PremutationAuthority.parameterName, {
    value: JSON.stringify(rb06PremutationAuthority),
    version: 1,
    modified: '2026-08-18T05:00:00.000Z',
  });
  parameters.set(
    `/checkout/stage7/rollback/${journalCandidate}/RB-E7-06/000001-${'4'.repeat(64)}/manifest`,
    { value: '{}', version: 1, modified: '2026-08-18T05:00:00.000Z' },
  );
  await assert.rejects(
    runGuardedFullReleaseMutation({
      candidateSha: journalCandidate,
      sourceRunId: '777777777',
      authoritativeSourceRunId: '777777777',
      operation: 'DEPLOY_DATA',
      getParametersByPath,
      mutation: async () => {
        mutations += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ROLLBACK_JOURNAL_BLOCKS_MUTATION',
  );
  assert.equal(mutations, 1);
  const reconciliationSource = {
    repository: REPOSITORY,
    workflowPath: RELEASE_WORKFLOW_PATH,
    ref: 'refs/heads/master',
    runId: '777777777',
    runAttempt: 1,
    candidateSha: journalCandidate,
    releaseId: 'rel-20260817-1100-ccccccc',
    releaseTag: 'v2026.8.17',
    configSha256: '8'.repeat(64),
  };
  const reconciliationIntent = createReleaseReconciliationIntent({
    source: reconciliationSource,
    authority: {
      accountId: '123456789012',
      region,
      rollbackRoleArn: rollbackRole,
      journalRoleArn: journalRole,
      rollbackPermissionSetSha256: '9'.repeat(64),
      journalEffectivePermissionsSha256: 'a'.repeat(64),
    },
    bindings: STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.map(
      ({ label, path: pathName, sourceType }, index) => ({
        label,
        path: pathName,
        sourceType,
        rawSha256: sourceType === 'NESTED_JSON' ? null : (index + 1).toString(16).at(-1).repeat(64),
        canonicalSha256:
          sourceType === 'RAW_TEXT' ? null : (index + 2).toString(16).at(-1).repeat(64),
        bytes: 100 + index,
      }),
    ),
  });
  const reconciliationIntentText = JSON.stringify(reconciliationIntent);
  const reconciliationIntentValues = [];
  let reconciliationIntentChunk = '';
  for (const character of reconciliationIntentText) {
    if (Buffer.byteLength(reconciliationIntentChunk + character, 'utf8') > 3000) {
      reconciliationIntentValues.push(reconciliationIntentChunk);
      reconciliationIntentChunk = character;
    } else {
      reconciliationIntentChunk += character;
    }
  }
  if (reconciliationIntentChunk !== '') reconciliationIntentValues.push(reconciliationIntentChunk);
  const reconciliationRoot = `/checkout/stage7/rollback/${journalCandidate}/release-reconciliation/777777777`;
  const reconciliationOwner = createReleaseRollbackJournalOwner({
    source: reconciliationSource,
    intent: reconciliationIntent,
    intentRawSha256: sha256(reconciliationIntentText),
    intentBytes: Buffer.byteLength(reconciliationIntentText, 'utf8'),
    intentChunks: reconciliationIntentValues.map((value, index) => ({
      index: index + 1,
      parameterName: `${reconciliationRoot}/intent/${String(index + 1).padStart(4, '0')}`,
      rawSha256: sha256(value),
      bytes: Buffer.byteLength(value, 'utf8'),
    })),
    createdAtUtc: '2026-08-18T05:00:00.000Z',
  });
  parameters.set(reconciliationOwner.parameterName, {
    value: JSON.stringify(reconciliationOwner),
    version: 1,
    modified: '2026-08-18T05:00:00.000Z',
  });
  for (const [index, value] of reconciliationIntentValues.entries()) {
    parameters.set(reconciliationOwner.intentChunks[index].parameterName, {
      value,
      version: 1,
      modified: '2026-08-18T05:00:00.000Z',
    });
  }
  const intentAuthority = createSelfTestIntentAuthority(reconciliationIntent);
  const rollbackAuthority = createSelfTestRollbackAuthority({
    source: reconciliationSource,
    rollbackRoleArn: rollbackRole,
    journalCleanupRoleArn: journalRole,
    journalLifecycleSha256,
    rollbackBindingSha256,
    protectedBindingSha256,
  });
  const completionAuthority = createSelfTestRollbackAuthority({
    kind: 'ROLLBACK_RESILIENCE_COMPLETION_AUTHORITY',
    source: reconciliationSource,
    rollbackRoleArn: rollbackRole,
    journalCleanupRoleArn: journalRole,
    journalLifecycleSha256,
    rollbackBindingSha256,
    protectedBindingSha256,
  });
  const rb06StateName = `/checkout/stage7/rollback/${journalCandidate}/RB-E7-06/000001-${'4'.repeat(64)}/manifest`;
  const savedRbOwner = parameters.get(rbOwner.parameterName);
  const savedRbPremutationAuthority = parameters.get(rb06PremutationAuthority.parameterName);
  const savedRbState = parameters.get(rb06StateName);
  parameters.delete(rbOwner.parameterName);
  parameters.delete(rb06PremutationAuthority.parameterName);
  parameters.delete(rb06StateName);
  const rollbackCheck = await runGuardedVersionedRollbackCheckWithAuthority({
    intentAuthority,
    getParametersByPath,
    mutation: async () => {
      mutations += 1;
      return 'ROLLBACK_CHECK_MUTATED';
    },
  });
  assert.equal(rollbackCheck.result, 'ROLLBACK_CHECK_MUTATED');
  assert.equal(mutations, 2);
  parameters.set(rbOwner.parameterName, savedRbOwner);
  parameters.set(rb06PremutationAuthority.parameterName, savedRbPremutationAuthority);
  parameters.set(rb06StateName, savedRbState);
  await assert.rejects(
    runGuardedFullReleaseMutation({
      candidateSha: journalCandidate,
      sourceRunId: '777777777',
      authoritativeSourceRunId: '777777777',
      operation: 'RESUME_ROLLBACK_RESILIENCE',
      getParametersByPath,
      mutation: async () => {
        mutations += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_MUTATION_CALLBACK_REQUIRED',
  );
  let crashBeforeArtifactCallbacks = 0;
  await assert.rejects(
    runGuardedRollbackResilienceWithAuthorities({
      intentAuthority,
      rollbackAuthority,
      rollbackJournalRecords: rbJournalRecords,
      getParametersByPath,
      putParameter,
      getParameter,
      mutation: async () => {
        crashBeforeArtifactCallbacks += 1;
        const error = new Error('CRASH_AFTER_PREMUTATION_AUTHORITY_BEFORE_ARTIFACT');
        error.code = 'SELF_TEST_CRASH_AFTER_PREMUTATION_AUTHORITY_BEFORE_ARTIFACT';
        throw error;
      },
    }),
    (error) => error.code === 'SELF_TEST_CRASH_AFTER_PREMUTATION_AUTHORITY_BEFORE_ARTIFACT',
  );
  assert.equal(crashBeforeArtifactCallbacks, 1);
  assert.equal(mutations, 2);
  assert.deepEqual(
    parameterWrites.filter((name) => name.includes(`/rollback/${journalCandidate}/`)).slice(-2),
    [rb08PremutationAuthority.parameterName, rb08Owner.parameterName],
  );
  const resumed = await runGuardedRollbackResilienceWithAuthorities({
    intentAuthority,
    rollbackAuthority,
    rollbackJournalRecords: rbJournalRecords,
    getParametersByPath,
    putParameter,
    getParameter,
    mutation: async () => {
      mutations += 1;
      return 'RESUMED';
    },
  });
  assert.equal(resumed.result, 'RESUMED');
  assert.equal(mutations, 3);
  assert.equal(
    Object.getOwnPropertySymbols(resumed.resumeGuard).some(
      (symbol) =>
        resumed.resumeGuard[symbol]?.operation === 'RESUME_ROLLBACK_RESILIENCE' &&
        resumed.resumeGuard[symbol]?.ownerSha256 === reconciliationOwner.ownerSha256 &&
        resumed.resumeGuard[symbol]?.rbOwnerSha256s?.includes(rbOwner.ownerSha256),
    ),
    true,
  );
  assert.equal(JSON.stringify(resumed.resumeGuard).includes('rbOwnerSha256s'), false);
  await assert.rejects(
    runGuardedRollbackResilienceWithAuthorities({
      intentAuthority,
      rollbackAuthority,
      rollbackJournalRecords: [
        {
          premutationAuthority: rb06PremutationAuthority,
          owner: { ...rbOwner, sourceRunId: '888888888' },
        },
        { premutationAuthority: rb08PremutationAuthority, owner: rb08Owner },
      ],
      getParametersByPath,
      putParameter,
      getParameter,
      mutation: async () => {
        mutations += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID',
  );
  assert.equal(mutations, 3);
  let rejectedIncompleteReads = 0;
  let rejectedIncompleteMutations = 0;
  const rejectedIncompleteGetParametersByPath = async () => {
    rejectedIncompleteReads += 1;
    return { Parameters: [] };
  };
  const foreignOwnerBody = { ...rbOwner, sourceRunId: '888888888' };
  delete foreignOwnerBody.ownerSha256;
  const foreignRecord = {
    premutationAuthority: rb06PremutationAuthority,
    owner: { ...foreignOwnerBody, ownerSha256: objectSha256(foreignOwnerBody) },
  };
  const tamperedPremutationBody = {
    ...rb06PremutationAuthority,
    execution: {
      ...rb06PremutationAuthority.execution,
      startedAtUtc: '2026-08-18T04:58:00.000Z',
    },
  };
  delete tamperedPremutationBody.executionSha256;
  delete tamperedPremutationBody.authoritySha256;
  tamperedPremutationBody.executionSha256 = objectSha256(tamperedPremutationBody.execution);
  const tamperedPremutationAuthority = {
    ...tamperedPremutationBody,
    authoritySha256: objectSha256(tamperedPremutationBody),
  };
  for (const rejected of [
    {
      code: 'E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_INPUT_INVALID',
      direction: 'ROLLBACK_TO_PREVIOUS',
      records: rbJournalRecords,
    },
    {
      code: 'E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID',
      direction: 'REPROMOTE_CANDIDATE',
      records: [rbJournalRecords[1], rbJournalRecords[0]],
    },
    {
      code: 'E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID',
      direction: 'REPROMOTE_CANDIDATE',
      records: [foreignRecord, rbJournalRecords[1]],
    },
    {
      code: 'E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID',
      direction: 'REPROMOTE_CANDIDATE',
      records: [
        { premutationAuthority: tamperedPremutationAuthority, owner: rbOwner },
        rbJournalRecords[1],
      ],
    },
  ]) {
    await assert.rejects(
      runGuardedIncompleteReleaseReconciliationWithAuthorities({
        direction: rejected.direction,
        intentAuthority,
        rollbackAuthority,
        rollbackJournalRecords: rejected.records,
        getParametersByPath: rejectedIncompleteGetParametersByPath,
        mutation: async () => {
          rejectedIncompleteMutations += 1;
        },
      }),
      (error) => error.code === rejected.code,
    );
  }
  assert.equal(rejectedIncompleteReads, 0);
  assert.equal(rejectedIncompleteMutations, 0);
  assert.equal(
    rbJournalRecords.every(
      ({ premutationAuthority }) =>
        Buffer.byteLength(JSON.stringify(premutationAuthority), 'utf8') <= 3900,
    ),
    true,
  );
  let rejectedLiveIncompleteMutations = 0;
  for (const { parameterName, value } of [
    {
      parameterName: rb06PremutationAuthority.parameterName,
      value: rb08PremutationAuthority,
    },
    { parameterName: rbOwner.parameterName, value: foreignRecord.owner },
    {
      parameterName: rb06PremutationAuthority.parameterName,
      value: tamperedPremutationAuthority,
    },
  ]) {
    const saved = parameters.get(parameterName);
    parameters.set(parameterName, { ...saved, value: JSON.stringify(value) });
    await assert.rejects(
      runGuardedIncompleteReleaseReconciliationFromIntentAuthority({
        direction: 'REPROMOTE_CANDIDATE',
        intentAuthority,
        getParametersByPath,
        mutation: async () => {
          rejectedLiveIncompleteMutations += 1;
        },
      }),
      (error) => error.code === 'E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_AUTHORITY_INVALID',
    );
    parameters.set(parameterName, saved);
  }
  assert.equal(rejectedLiveIncompleteMutations, 0);
  const incompleteResume = await runGuardedIncompleteReleaseReconciliationFromIntentAuthority({
    direction: 'REPROMOTE_CANDIDATE',
    intentAuthority,
    getParametersByPath,
    mutation: async () => {
      mutations += 1;
      return 'INCOMPLETE_RECONCILIATION_REPROMOTED_N';
    },
  });
  assert.equal(incompleteResume.result, 'INCOMPLETE_RECONCILIATION_REPROMOTED_N');
  assert.equal(mutations, 4);
  assert.equal(
    Object.getOwnPropertySymbols(incompleteResume.guard).some(
      (symbol) =>
        incompleteResume.guard[symbol]?.operation === 'RESUME_INCOMPLETE_RECONCILIATION' &&
        incompleteResume.guard[symbol]?.rbOwnerSha256s?.length === 2,
    ),
    true,
  );
  parameters.set(
    `/checkout/stage7/rollback/${journalCandidate}/RB-E7-08/000001-${'3'.repeat(64)}/manifest`,
    { value: '{}', version: 1, modified: '2026-08-18T05:00:00.000Z' },
  );
  const reconciliationResume = await runGuardedReleaseReconciliationWithAuthorities({
    intentAuthority,
    rollbackAuthority: completionAuthority,
    rollbackJournalRecords: rbJournalRecords,
    getParametersByPath,
    mutation: async () => {
      mutations += 1;
      return 'RECONCILIATION_RESUMED';
    },
  });
  assert.equal(reconciliationResume.result, 'RECONCILIATION_RESUMED');
  assert.equal(mutations, 5);
  assert.equal(
    Object.getOwnPropertySymbols(reconciliationResume.guard).some(
      (symbol) =>
        reconciliationResume.guard[symbol]?.ownerSha256 === reconciliationOwner.ownerSha256,
    ),
    true,
  );
  assert.equal(JSON.stringify(reconciliationResume.guard).includes('ownerSha256'), false);
  const mismatchAuthority = (sourcePatch) => {
    const source = { ...reconciliationSource, ...sourcePatch };
    const intent = createReleaseReconciliationIntent({
      source,
      authority: reconciliationIntent.authority,
      bindings: reconciliationIntent.bindings,
    });
    return {
      intentAuthority: createSelfTestIntentAuthority(intent),
      rollbackAuthority: createSelfTestRollbackAuthority({
        kind: 'ROLLBACK_RESILIENCE_COMPLETION_AUTHORITY',
        source,
        rollbackRoleArn: rollbackRole,
        journalCleanupRoleArn: journalRole,
        journalLifecycleSha256,
        rollbackBindingSha256,
        protectedBindingSha256,
      }),
    };
  };
  for (const mismatch of [
    { releaseId: 'rel-20260818-1100-ccccccc' },
    { releaseTag: 'v2026.8.18' },
    { configSha256: 'c'.repeat(64) },
  ]) {
    const mismatched = mismatchAuthority(mismatch);
    await assert.rejects(
      runGuardedReleaseReconciliationWithAuthorities({
        ...mismatched,
        rollbackJournalRecords: rbJournalRecords,
        getParametersByPath,
        mutation: async () => {
          mutations += 1;
        },
      }),
      (error) => error.code === 'E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID',
    );
  }
  assert.equal(mutations, 5);
  const foreignRunAuthorities = mismatchAuthority({ runId: '888888888' });
  await assert.rejects(
    runGuardedReleaseReconciliationWithAuthorities({
      ...foreignRunAuthorities,
      rollbackJournalRecords: rbJournalRecords,
      getParametersByPath,
      mutation: async () => {
        mutations += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ROLLBACK_OWNER_SET_INVALID',
  );
  const attemptTwoOwnerBody = {
    ...reconciliationOwner,
    source: { ...reconciliationOwner.source, runAttempt: 2 },
  };
  delete attemptTwoOwnerBody.ownerSha256;
  const attemptTwoOwner = {
    ...attemptTwoOwnerBody,
    ownerSha256: objectSha256(attemptTwoOwnerBody),
  };
  parameters.set(reconciliationOwner.parameterName, {
    value: JSON.stringify(attemptTwoOwner),
    version: 1,
    modified: '2026-08-18T05:00:00.000Z',
  });
  await assert.rejects(
    runGuardedReleaseReconciliationWithAuthorities({
      intentAuthority,
      rollbackAuthority: completionAuthority,
      rollbackJournalRecords: rbJournalRecords,
      getParametersByPath,
      mutation: async () => {
        mutations += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RECONCILIATION_INVALID',
  );
  parameters.set(reconciliationOwner.parameterName, {
    value: JSON.stringify(reconciliationOwner),
    version: 1,
    modified: '2026-08-18T05:00:00.000Z',
  });
  parameters.set(reconciliationOwner.parameterName, {
    value: JSON.stringify({
      ...reconciliationOwner,
      intentRawSha256: 'b'.repeat(64),
    }),
    version: 1,
    modified: '2026-08-18T05:00:00.000Z',
  });
  await assert.rejects(
    runGuardedReleaseReconciliationWithAuthorities({
      intentAuthority,
      rollbackAuthority: completionAuthority,
      rollbackJournalRecords: rbJournalRecords,
      getParametersByPath,
      mutation: async () => {
        mutations += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RECONCILIATION_INVALID',
  );
  assert.equal(mutations, 5);
  parameters.set(reconciliationOwner.parameterName, {
    value: JSON.stringify(reconciliationOwner),
    version: 1,
    modified: '2026-08-18T05:00:00.000Z',
  });
  const foreignRbOwnerBody = { ...rbOwner, sourceRunId: '888888888' };
  delete foreignRbOwnerBody.ownerSha256;
  const foreignRbOwner = {
    ...foreignRbOwnerBody,
    ownerSha256: objectSha256(foreignRbOwnerBody),
  };
  parameters.set(rbOwner.parameterName, {
    value: JSON.stringify(foreignRbOwner),
    version: 1,
    modified: '2026-08-18T05:00:00.000Z',
  });
  await assert.rejects(
    runGuardedReleaseReconciliationWithAuthorities({
      intentAuthority,
      rollbackAuthority: completionAuthority,
      rollbackJournalRecords: rbJournalRecords,
      getParametersByPath,
      mutation: async () => {
        mutations += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_MUTATION_GUARD_RB_OWNER_INVALID',
  );
  assert.equal(mutations, 5);
  await assert.rejects(
    runGuardedVersionedRollbackCheckMutation({ unexpected: true }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ROLLBACK_CHECK_WRAPPER_INPUT_INVALID',
  );
  await assert.rejects(
    runGuardedRollbackResilienceMutation({ unexpected: true }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ROLLBACK_RESILIENCE_WRAPPER_INPUT_INVALID',
  );
  await assert.rejects(
    runGuardedReleaseReconciliationMutation({ unexpected: true }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_RECONCILIATION_WRAPPER_INPUT_INVALID',
  );
  await assert.rejects(
    runGuardedIncompleteReleaseReconciliationMutation({ unexpected: true }),
    (error) =>
      error.code === 'E7_RELEASE_SUCCESSOR_INCOMPLETE_RECONCILIATION_WRAPPER_INPUT_INVALID',
  );
  assert.equal(mutations, 5);
  return {
    status: 'PASS',
    canaries: 42,
    externalRequests: 0,
    markerSha256: first.marker.markerSha256,
    provenanceSha256: first.provenance.provenanceSha256,
  };
};
