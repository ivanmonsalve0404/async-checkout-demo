import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256 } from './core.mjs';
import {
  prepareRollbackResilienceArtifacts,
  validateRollbackResilienceCompletionEnvelope,
} from './rollback-resilience-integration.mjs';
import {
  createRollbackSsmPremutationAuthority,
  createRollbackJournalLifecycle,
  createRollbackJournalOwner,
  validateRollbackSsmPremutationAuthority,
} from './rollback-resilience-protected-runtime.mjs';
import { validateReleaseJournalRoleEffectivePermissionsBinding } from './release-successor-iam-authority.mjs';
import { parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource } from './release-reconciliation-recovery.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const REF = 'refs/heads/master';
const WORKFLOW_REF = `${REPOSITORY}/.github/workflows/stage7-rollback-resilience.yml@${REF}`;
const PROTECTED_ENVIRONMENT = 'assessment-release-recovery';
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const MAX_SOURCE_BYTES = 32 * 1024 * 1024;
const RECOVERY_ROLE_AUTHORITY_KEYS = Object.freeze([
  'reconciliationRecoveryRoleArn',
  'reconciliationRecoveryPermissionsBoundaryArn',
  'reconciliationRecoveryRoleEffectivePermissionsRawSha256',
  'reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256',
  'reconciliationRecoveryRoleEffectivePermissionsSha256',
  'reconciliationRecoveryRoleEffectivePolicyProjectionSha256',
]);
export const RELEASE_SUCCESSOR_ROLLBACK_PREMUTATION_PREPARATION_KEYS = Object.freeze([
  'config',
  'freezeManifest',
  'previousReleaseManifest',
  'candidateRecord',
  'rollbackSource',
  'awsAuthSource',
  'approvalSource',
  'journalRoleEffectivePermissionsSource',
  'reconciliationRecoveryRoleEffectivePermissionsSource',
  'approvedPlanSource',
  'deploymentEvidenceSource',
  'observabilityEvidenceSource',
  'activationEvidenceSource',
  'externalAuthorizationSource',
  'smokeInputSource',
  'smokeEvidenceSource',
  'edgeEvidenceSource',
  'qualityEvidenceSource',
  'sandboxEvidenceSource',
  'rollbackSmokeInputSource',
  'pendingProducerSource',
  'pendingEgressCloseoutSource',
  'rollbackSmokeSource',
  'repromotionSmokeSource',
  'journalCleanupRoleArn',
  'assemblyDirectory',
  'maxPolls',
]);
export const RELEASE_SUCCESSOR_ROLLBACK_GITHUB_IDENTITY_KEYS = Object.freeze([
  'repository',
  'workflowRef',
  'ref',
  'runId',
  'runAttempt',
  'candidateSha',
  'startedAtUtc',
]);
const VALIDATED_ROLLBACK_AUTHORITIES = new WeakSet();
const ROLLBACK_AUTHORITY_CONTEXTS = new WeakMap();
export const RELEASE_SUCCESSOR_ROLLBACK_PREMUTATION_AUTHORITY_SOURCE_KEYS = Object.freeze([
  'preparation',
  'preparedInputsSource',
  'rb06DescriptorSource',
  'rb08DescriptorSource',
  'sourceBindingSource',
  'githubIdentity',
]);
export const RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS = Object.freeze([
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
  'pending-egress-closeout',
  'rollback-smoke',
  'repromotion-smoke',
  'journal-cleanup-role',
  'assembly',
  'max-polls',
]);
export const RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS = Object.freeze([
  'inputs',
  'rb06',
  'rb08',
  'source-binding',
]);
export const RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS = Object.freeze([
  'protected-run',
  'completion',
]);

export class Stage7ReleaseSuccessorRollbackAuthorityError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseSuccessorRollbackAuthorityError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseSuccessorRollbackAuthorityError(
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
const document = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_SOURCE_BYTES) fail(code);
  try {
    const value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
    if (!object(value)) fail(code);
    return { value, bytes, rawSha256: sha256(bytes), canonicalSha256: objectSha256(value) };
  } catch (error) {
    if (error instanceof Stage7ReleaseSuccessorRollbackAuthorityError) throw error;
    fail(code, error);
  }
};
const same = (left, right) => canonicalJson(left) === canonicalJson(right);
const recoveryRoleAuthoritySha256 = (value) =>
  objectSha256(Object.fromEntries(RECOVERY_ROLE_AUTHORITY_KEYS.map((key) => [key, value?.[key]])));

const validateAuxiliaryRoleAuthorities = (preparation) => {
  const awsAuth = document(
    preparation.awsAuthSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_AWS_AUTH_SOURCE_INVALID',
  );
  const approval = document(
    preparation.approvalSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_APPROVAL_SOURCE_INVALID',
  );
  const journalRole = document(
    preparation.journalRoleEffectivePermissionsSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_JOURNAL_ROLE_AUTHORITY_SOURCE_INVALID',
  );
  const recoveryRole = document(
    preparation.reconciliationRecoveryRoleEffectivePermissionsSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_RECOVERY_ROLE_AUTHORITY_SOURCE_INVALID',
  );
  try {
    validateReleaseJournalRoleEffectivePermissionsBinding({
      awsAuthSource: awsAuth.bytes,
      effectivePermissionsSource: journalRole.bytes,
      expected: {
        candidateSha: preparation.freezeManifest.candidateSha,
        releaseId: preparation.freezeManifest.releaseId,
        configSha256: preparation.freezeManifest.configSha256,
        manifestSha256: preparation.freezeManifest.manifestSha256,
      },
    });
    const recovery = parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource(
      recoveryRole.bytes,
      {
        roleArn: awsAuth.value.reconciliationRecoveryRoleArn,
        permissionsBoundaryArn: awsAuth.value.reconciliationRecoveryPermissionsBoundaryArn,
      },
    );
    if (
      approval.value.journalRoleEffectivePermissionsRawSha256 !==
        awsAuth.value.journalRoleEffectivePermissionsRawSha256 ||
      approval.value.journalRoleEffectivePermissionsSha256 !==
        awsAuth.value.journalRoleEffectivePermissionsSha256 ||
      canonicalJson(
        Object.fromEntries(RECOVERY_ROLE_AUTHORITY_KEYS.map((key) => [key, approval.value?.[key]])),
      ) !==
        canonicalJson(
          Object.fromEntries(
            RECOVERY_ROLE_AUTHORITY_KEYS.map((key) => [key, awsAuth.value?.[key]]),
          ),
        ) ||
      awsAuth.value.reconciliationRecoveryRoleEffectivePermissionsRawSha256 !==
        recovery.rawSha256 ||
      awsAuth.value.reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256 !==
        recovery.canonicalSha256 ||
      awsAuth.value.reconciliationRecoveryRoleEffectivePermissionsSha256 !==
        recovery.value.effectivePermissionsSha256 ||
      awsAuth.value.reconciliationRecoveryRoleEffectivePolicyProjectionSha256 !==
        recovery.value.effectivePolicyProjectionSha256
    ) {
      fail('E7_RELEASE_SUCCESSOR_ROLLBACK_AUXILIARY_ROLE_BINDING_INVALID');
    }
  } catch (error) {
    if (error instanceof Stage7ReleaseSuccessorRollbackAuthorityError) throw error;
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_AUXILIARY_ROLE_AUTHORITY_INVALID', error);
  }
  return { awsAuth, approval, journalRole, recoveryRole };
};

const protectedExecution = ({ preparation, githubIdentity }) => {
  const { config, freezeManifest } = preparation;
  if (
    !exactKeys(githubIdentity, RELEASE_SUCCESSOR_ROLLBACK_GITHUB_IDENTITY_KEYS) ||
    githubIdentity.repository !== REPOSITORY ||
    githubIdentity.workflowRef !== WORKFLOW_REF ||
    githubIdentity.ref !== REF ||
    !RUN_ID.test(githubIdentity.runId ?? '') ||
    githubIdentity.runAttempt !== 1 ||
    githubIdentity.candidateSha !== freezeManifest?.candidateSha ||
    !SHA.test(githubIdentity.candidateSha ?? '') ||
    !utc(githubIdentity.startedAtUtc) ||
    Date.parse(githubIdentity.startedAtUtc) < Date.parse(config?.window?.startsAtUtc ?? '') ||
    Date.parse(githubIdentity.startedAtUtc) > Date.parse(config?.window?.endsAtUtc ?? '')
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_GITHUB_IDENTITY_INVALID');
  }
  return {
    mode: 'AWS_REAL',
    repository: githubIdentity.repository,
    workflow: 'stage7-rollback-resilience.yml',
    runId: githubIdentity.runId,
    runAttempt: String(githubIdentity.runAttempt),
    githubActions: true,
    githubRef: githubIdentity.ref,
    githubSha: githubIdentity.candidateSha,
    protectedEnvironment: PROTECTED_ENVIRONMENT,
    accountId: config.aws.accountId,
    region: config.aws.region,
    roleArn: config.aws.roles.rollbackRoleArn,
    startedAtUtc: githubIdentity.startedAtUtc,
  };
};

const protectedBinding = ({ inputsWithoutExecution, execution }) => {
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
      inputsWithoutExecution.journalCleanupRoleArn,
    ),
  };
  return objectSha256(expected);
};

const rollbackBinding = ({ inputsWithoutExecution, execution }) => {
  const inputs = { ...inputsWithoutExecution, execution };
  const awsAuth = parseStrictJsonSource(Buffer.from(inputs.documents.awsAuth.content, 'utf8'), {
    scanForbiddenData: false,
  });
  const iamBindingSha256 = awsAuth?.iamEffectivePermissions?.bindingSha256;
  if (!SHA256.test(iamBindingSha256 ?? '')) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_IAM_BINDING_INVALID');
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
    iamEffectivePermissionsBindingSha256: iamBindingSha256,
    approvedPlanSha256: inputs.candidateRecord.planSha256,
    deploymentEvidenceSha256: inputs.candidateRecord.deploymentEvidenceSha256,
    observabilityEvidenceSha256: inputs.documents.observabilityEvidence.sha256,
    activationEvidenceSha256: inputs.documents.activationEvidence.sha256,
    externalAuthorizationEvidenceSha256: inputs.documents.externalAuthorizationEvidence.sha256,
    authorizationBudgetSha256: inputs.documents.authorizationBudget.sha256,
    journalCleanupRoleSha256: sha256(inputs.journalCleanupRoleArn),
    reconciliationRecoveryRoleAuthoritySha256: recoveryRoleAuthoritySha256(awsAuth),
    baseRehearsalSha256: inputs.baseRehearsal.rehearsalSha256,
    executionSha256: objectSha256(inputs.execution),
    containsSensitiveData: false,
  };
  return { binding: { ...body, bindingSha256: objectSha256(body) }, inputs };
};

export const validateReleaseSuccessorRollbackPremutationAuthority = (options) => {
  if (!exactKeys(options, RELEASE_SUCCESSOR_ROLLBACK_PREMUTATION_AUTHORITY_SOURCE_KEYS)) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_PREMUTATION_SOURCE_SET_INVALID');
  }
  const {
    preparation,
    preparedInputsSource,
    rb06DescriptorSource,
    rb08DescriptorSource,
    sourceBindingSource,
    githubIdentity,
  } = options;
  if (
    !exactKeys(preparation, RELEASE_SUCCESSOR_ROLLBACK_PREMUTATION_PREPARATION_KEYS) ||
    preparation.maxPolls !== 30
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_INVALID');
  }
  const auxiliaryRoleAuthorities = validateAuxiliaryRoleAuthorities(preparation);
  let prepared;
  try {
    prepared = prepareRollbackResilienceArtifacts(preparation);
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_INVALID', error);
  }
  const suppliedInputs = document(
    preparedInputsSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_INPUTS_SOURCE_INVALID',
  );
  const suppliedRb06 = document(
    rb06DescriptorSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_RB06_SOURCE_INVALID',
  );
  const suppliedRb08 = document(
    rb08DescriptorSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_RB08_SOURCE_INVALID',
  );
  const suppliedBinding = document(
    sourceBindingSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_BINDING_SOURCE_INVALID',
  );
  if (
    !same(suppliedInputs.value, prepared.inputsWithoutExecution) ||
    !same(suppliedRb06.value, prepared.rb06Descriptor) ||
    !same(suppliedRb08.value, prepared.rb08Descriptor) ||
    !same(suppliedBinding.value, prepared.sourceBinding)
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CONTEXT_MISMATCH');
  }
  const execution = protectedExecution({ preparation, githubIdentity });
  const { binding, inputs } = rollbackBinding({
    inputsWithoutExecution: prepared.inputsWithoutExecution,
    execution,
  });
  const protectedBindingSha256 = protectedBinding({
    inputsWithoutExecution: prepared.inputsWithoutExecution,
    execution,
  });
  let lifecycle;
  try {
    lifecycle = createRollbackJournalLifecycle(inputs);
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_LIFECYCLE_INVALID', error);
  }
  const contextBindings = {
    preparedInputs: {
      rawSha256: suppliedInputs.rawSha256,
      canonicalSha256: suppliedInputs.canonicalSha256,
      bytes: suppliedInputs.bytes.length,
    },
    rb06Descriptor: {
      rawSha256: suppliedRb06.rawSha256,
      canonicalSha256: suppliedRb06.canonicalSha256,
      bytes: suppliedRb06.bytes.length,
    },
    rb08Descriptor: {
      rawSha256: suppliedRb08.rawSha256,
      canonicalSha256: suppliedRb08.canonicalSha256,
      bytes: suppliedRb08.bytes.length,
    },
    sourceBinding: {
      rawSha256: suppliedBinding.rawSha256,
      canonicalSha256: suppliedBinding.canonicalSha256,
      bytes: suppliedBinding.bytes.length,
    },
    journalRoleEffectivePermissions: {
      rawSha256: auxiliaryRoleAuthorities.journalRole.rawSha256,
      canonicalSha256: auxiliaryRoleAuthorities.journalRole.canonicalSha256,
      bytes: auxiliaryRoleAuthorities.journalRole.bytes.length,
    },
    reconciliationRecoveryRoleEffectivePermissions: {
      rawSha256: auxiliaryRoleAuthorities.recoveryRole.rawSha256,
      canonicalSha256: auxiliaryRoleAuthorities.recoveryRole.canonicalSha256,
      bytes: auxiliaryRoleAuthorities.recoveryRole.bytes.length,
    },
  };
  const authority = Object.freeze({
    kind: 'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY',
    candidateSha: inputs.freezeManifest.candidateSha,
    releaseId: inputs.freezeManifest.releaseId,
    releaseTag: inputs.freezeManifest.releaseTag,
    configSha256: objectSha256(inputs.config),
    sourceRunId: execution.runId,
    sourceRunAttempt: Number(execution.runAttempt),
    accountId: inputs.config.aws.accountId,
    awsRegion: inputs.config.aws.region,
    rollbackRoleArn: inputs.config.aws.roles.rollbackRoleArn,
    journalCleanupRoleArn: inputs.journalCleanupRoleArn,
    rollbackRoleSha256: sha256(inputs.config.aws.roles.rollbackRoleArn),
    journalCleanupRoleSha256: sha256(inputs.journalCleanupRoleArn),
    reconciliationRecoveryRoleAuthoritySha256: binding.reconciliationRecoveryRoleAuthoritySha256,
    journalLifecycleSha256: lifecycle.lifecycleSha256,
    rollbackBindingSha256: binding.bindingSha256,
    protectedBindingSha256,
    sourceBindingSha256: prepared.sourceBinding.sourceBindingSha256,
    contextBindings,
    contextSetSha256: objectSha256(contextBindings),
  });
  VALIDATED_ROLLBACK_AUTHORITIES.add(authority);
  ROLLBACK_AUTHORITY_CONTEXTS.set(authority, {
    rollbackSource: preparation.rollbackSource,
    sourceBindingSource: suppliedBinding.bytes,
    inputsWithoutExecution: prepared.inputsWithoutExecution,
    rb06Descriptor: prepared.rb06Descriptor,
    rb08Descriptor: prepared.rb08Descriptor,
    inputs,
    binding,
    lifecycle,
  });
  return authority;
};

export const createReleaseSuccessorRollbackPremutationRecords = (premutationAuthority) => {
  if (
    !object(premutationAuthority) ||
    !VALIDATED_ROLLBACK_AUTHORITIES.has(premutationAuthority) ||
    premutationAuthority.kind !== 'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY'
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_PREMUTATION_AUTHORITY_REQUIRED');
  }
  const context = ROLLBACK_AUTHORITY_CONTEXTS.get(premutationAuthority);
  if (
    !object(context?.inputs) ||
    context.binding?.bindingSha256 !== premutationAuthority.rollbackBindingSha256 ||
    context.lifecycle?.lifecycleSha256 !== premutationAuthority.journalLifecycleSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_PREMUTATION_CONTEXT_INVALID');
  }
  return Object.freeze(
    ['RB-E7-06', 'RB-E7-08'].map((scenarioId) => {
      const premutation = createRollbackSsmPremutationAuthority({
        inputs: context.inputs,
        scenarioId,
        bindingSha256: premutationAuthority.rollbackBindingSha256,
        protectedBindingSha256: premutationAuthority.protectedBindingSha256,
        journalLifecycle: context.lifecycle,
      });
      return Object.freeze({
        premutationAuthority: Object.freeze(premutation),
        owner: Object.freeze(
          createRollbackJournalOwner({
            inputs: context.inputs,
            scenarioId,
            premutationAuthority: premutation,
            journalLifecycle: context.lifecycle,
          }),
        ),
      });
    }),
  );
};

export const createReleaseSuccessorRollbackJournalOwners = (premutationAuthority) =>
  Object.freeze(
    createReleaseSuccessorRollbackPremutationRecords(premutationAuthority).map(
      ({ owner }) => owner,
    ),
  );

export const RELEASE_SUCCESSOR_INCOMPLETE_ROLLBACK_EXPECTED_KEYS = Object.freeze([
  'candidateSha',
  'releaseId',
  'releaseTag',
  'configSha256',
  'sourceRunId',
  'sourceRunAttempt',
  'accountId',
  'awsRegion',
  'rollbackRoleArn',
  'journalCleanupRoleArn',
]);
const RELEASE_SUCCESSOR_INCOMPLETE_ROLLBACK_AUTHORITY_KEYS = Object.freeze([
  'premutationAuthorities',
  'expected',
]);

export const reconstructReleaseSuccessorRollbackPremutationAuthority = (options) => {
  if (!exactKeys(options, RELEASE_SUCCESSOR_INCOMPLETE_ROLLBACK_AUTHORITY_KEYS)) {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_ROLLBACK_AUTHORITY_INPUT_INVALID');
  }
  const { premutationAuthorities, expected } = options;
  if (
    !Array.isArray(premutationAuthorities) ||
    premutationAuthorities.length !== 2 ||
    premutationAuthorities.map((value) => value?.scenarioId).join('\0') !==
      ['RB-E7-06', 'RB-E7-08'].join('\0') ||
    !exactKeys(expected, RELEASE_SUCCESSOR_INCOMPLETE_ROLLBACK_EXPECTED_KEYS) ||
    expected.sourceRunAttempt !== 1
  ) {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_ROLLBACK_AUTHORITY_INPUT_INVALID');
  }
  const validated = premutationAuthorities.map((premutationAuthority) => {
    try {
      return validateRollbackSsmPremutationAuthority(premutationAuthority, {
        candidateSha: expected.candidateSha,
        scenarioId: premutationAuthority.scenarioId,
        releaseId: expected.releaseId,
        releaseTag: expected.releaseTag,
        configSha256: expected.configSha256,
        sourceRunId: expected.sourceRunId,
        sourceRunAttempt: expected.sourceRunAttempt,
        accountId: expected.accountId,
        region: expected.awsRegion,
        roleArn: expected.rollbackRoleArn,
      });
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_ROLLBACK_AUTHORITY_INVALID', error);
    }
  });
  const sharedProjection = (value) => ({
    candidateSha: value.candidateSha,
    releaseId: value.releaseId,
    releaseTag: value.releaseTag,
    configSha256: value.configSha256,
    rollbackBindingPreimage: value.rollbackBindingPreimage,
    execution: value.execution,
    executionSha256: value.executionSha256,
    bindingSha256: value.bindingSha256,
    protectedBindingSha256: value.protectedBindingSha256,
    rollbackRoleSha256: value.rollbackRoleSha256,
    journalCleanupRoleSha256: value.journalCleanupRoleSha256,
    journalLifecycleSha256: value.journalLifecycleSha256,
  });
  const [first, second] = validated;
  if (
    objectSha256(sharedProjection(first)) !== objectSha256(sharedProjection(second)) ||
    first.rollbackRoleSha256 !== sha256(expected.rollbackRoleArn) ||
    first.journalCleanupRoleSha256 !== sha256(expected.journalCleanupRoleArn)
  ) {
    fail('E7_RELEASE_SUCCESSOR_INCOMPLETE_ROLLBACK_AUTHORITY_MISMATCH');
  }
  const contextBindings = {
    ssmPremutationAuthorities: validated.map(({ scenarioId, parameterName, authoritySha256 }) => ({
      scenarioId,
      parameterName,
      authoritySha256,
    })),
  };
  const authority = Object.freeze({
    kind: 'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY',
    candidateSha: expected.candidateSha,
    releaseId: expected.releaseId,
    releaseTag: expected.releaseTag,
    configSha256: expected.configSha256,
    sourceRunId: expected.sourceRunId,
    sourceRunAttempt: expected.sourceRunAttempt,
    accountId: expected.accountId,
    awsRegion: expected.awsRegion,
    rollbackRoleArn: expected.rollbackRoleArn,
    journalCleanupRoleArn: expected.journalCleanupRoleArn,
    rollbackRoleSha256: first.rollbackRoleSha256,
    journalCleanupRoleSha256: first.journalCleanupRoleSha256,
    reconciliationRecoveryRoleAuthoritySha256:
      first.rollbackBindingPreimage.reconciliationRecoveryRoleAuthoritySha256,
    journalLifecycleSha256: first.journalLifecycleSha256,
    rollbackBindingSha256: first.bindingSha256,
    protectedBindingSha256: first.protectedBindingSha256,
    contextBindings,
    contextSetSha256: objectSha256(contextBindings),
  });
  VALIDATED_ROLLBACK_AUTHORITIES.add(authority);
  return authority;
};

export const RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_AUTHORITY_SOURCE_KEYS = Object.freeze([
  'premutationAuthority',
  'protectedRunSource',
  'completionSource',
]);

export const validateReleaseSuccessorRollbackCompletionAuthority = (options) => {
  if (!exactKeys(options, RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_AUTHORITY_SOURCE_KEYS)) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_SOURCE_SET_INVALID');
  }
  const { premutationAuthority, protectedRunSource, completionSource } = options;
  if (
    !object(premutationAuthority) ||
    !VALIDATED_ROLLBACK_AUTHORITIES.has(premutationAuthority) ||
    premutationAuthority.kind !== 'ROLLBACK_RESILIENCE_PREMUTATION_AUTHORITY'
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_PREMUTATION_AUTHORITY_REQUIRED');
  }
  const context = ROLLBACK_AUTHORITY_CONTEXTS.get(premutationAuthority);
  const protectedRun = document(
    protectedRunSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_PROTECTED_RUN_SOURCE_INVALID',
  );
  const completion = document(
    completionSource,
    'E7_RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_SOURCE_INVALID',
  );
  try {
    validateRollbackResilienceCompletionEnvelope({
      envelope: completion.value,
      rollbackSource: context.rollbackSource,
      sourceBindingSource: context.sourceBindingSource,
      protectedRunSource: protectedRun.bytes,
      validationContext: {
        inputsWithoutExecution: context.inputsWithoutExecution,
        rb06Descriptor: context.rb06Descriptor,
        rb08Descriptor: context.rb08Descriptor,
      },
    });
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_AUTHORITY_INVALID', error);
  }
  const attestation = protectedRun.value.runtimeAttestation;
  const lifecycle = attestation?.journalLifecycle;
  if (
    attestation?.runId !== premutationAuthority.sourceRunId ||
    Number(attestation?.runAttempt) !== premutationAuthority.sourceRunAttempt ||
    attestation?.protectedBindingSha256 !== premutationAuthority.protectedBindingSha256 ||
    lifecycle?.lifecycleSha256 !== premutationAuthority.journalLifecycleSha256 ||
    completion.value?.sourceBindingSha256 !== premutationAuthority.sourceBindingSha256 ||
    completion.value?.journalLifecycleSha256 !== premutationAuthority.journalLifecycleSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_AUTHORITY_MISMATCH');
  }
  const completionBindings = {
    protectedRun: {
      rawSha256: protectedRun.rawSha256,
      canonicalSha256: protectedRun.canonicalSha256,
      bytes: protectedRun.bytes.length,
    },
    completion: {
      rawSha256: completion.rawSha256,
      canonicalSha256: completion.canonicalSha256,
      bytes: completion.bytes.length,
    },
  };
  const authority = Object.freeze({
    ...premutationAuthority,
    kind: 'ROLLBACK_RESILIENCE_COMPLETION_AUTHORITY',
    completionBindings,
    completionSetSha256: objectSha256(completionBindings),
  });
  VALIDATED_ROLLBACK_AUTHORITIES.add(authority);
  ROLLBACK_AUTHORITY_CONTEXTS.set(authority, context);
  return authority;
};

export const isValidatedReleaseSuccessorRollbackAuthority = (value, { kind } = {}) =>
  object(value) &&
  VALIDATED_ROLLBACK_AUTHORITIES.has(value) &&
  (kind === undefined || value.kind === kind);
