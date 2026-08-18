import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import {
  canonicalJson,
  expectedStage7Stacks,
  objectSha256,
  validateStage7ActivationCheckpoint,
  validateFreezeManifest,
  validateStage7CandidateRollbackRecord,
  validateStage7Config,
  validateStage7PreviousReleaseForTarget,
  validateStage7VersionedRollbackRehearsal,
  workspaceRoot,
} from './core.mjs';
import {
  IamEffectivePermissionsError,
  validateIamEffectivePermissionsEvidence,
} from './iam-effective-permissions.mjs';
import {
  createRollbackResilienceSelfTestFixture,
  validatePublicProtectedRollbackResilienceRun,
} from './rollback-resilience-producer.mjs';

const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;
const IAM_ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/[A-Za-z0-9+=,.@_/-]{1,512}$/u;
const IAM_POLICY_ARN = /^arn:aws:iam::([0-9]{12}):policy\/[A-Za-z0-9+=,.@_/-]{1,512}$/u;
const SELF_TEST_ASSEMBLY_CAPABILITY = Symbol('stage7-rb-integration-self-test');
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
const OPERATION_EVIDENCE_KEYS = [
  'schemaVersion',
  'stage',
  'environment',
  'authorizationId',
  'authorizationScope',
  'configSha256',
  'releaseId',
  'candidateSha',
  'region',
  'status',
  'checkpoints',
  'containsSensitiveData',
  'updatedAtUtc',
];
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
const PROTECTED_RUN_KEYS = [
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

export class Stage7RollbackResilienceIntegrationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7RollbackResilienceIntegrationError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7RollbackResilienceIntegrationError(code);
};

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const assertAwsAuthEnvelopeShape = (value) => {
  if (!exactKeys(value, AWS_AUTH_KEYS)) fail('E7_RESILIENCE_AWS_AUTH_SOURCE_INVALID');
  return value;
};
const validateOperationEvidenceEnvelope = ({ value, config, freezeManifest, checkpoint }) => {
  if (
    !exactKeys(value, OPERATION_EVIDENCE_KEYS) ||
    value.environment !== config.environment ||
    value.authorizationId !== config.authorization.id ||
    value.authorizationScope !== config.authorization.scope ||
    value.region !== config.aws.region ||
    value.status !== 'IN_PROGRESS' ||
    !object(value.checkpoints?.[checkpoint]) ||
    !utc(value.updatedAtUtc) ||
    Date.parse(value.updatedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(value.updatedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    value.releaseId !== freezeManifest.releaseId ||
    value.candidateSha !== freezeManifest.candidateSha ||
    value.configSha256 !== objectSha256(config) ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_RESILIENCE_OPERATION_EVIDENCE_INVALID');
  }
  return value;
};
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
    ].every((digest) => /^[0-9a-f]{64}$/u.test(digest ?? '')) ||
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
const withoutDigest = (value, field) => {
  const body = { ...value };
  delete body[field];
  return body;
};
const publicJsonSource = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');

const cloudFormationExecutionRoleArn = (config) =>
  `arn:aws:iam::${config.aws.accountId}:role/cdk-hnb659fds-cfn-exec-role-${config.aws.accountId}-${config.aws.region}`;

const sourceDocument = (source, code) => {
  const buffer = Buffer.isBuffer(source) ? source : Buffer.from(source ?? '', 'utf8');
  if (buffer.length < 2 || buffer.length > MAX_DOCUMENT_BYTES) fail(code);
  let value;
  try {
    value = parseStrictJsonSource(buffer, { scanForbiddenData: false });
  } catch {
    fail(code);
  }
  if (!object(value) || value.containsSensitiveData !== false) fail(code);
  const rawSha256 = sha256(buffer);
  const canonicalSha256 = objectSha256(value);
  return {
    document: { content: buffer.toString('utf8'), sha256: rawSha256 },
    value,
    rawSha256,
    canonicalSha256,
  };
};

const validateAuthorizationUsage = ({ usage, authorization, config, freezeManifest }) => {
  if (
    !exactKeys(usage, AUTHORIZATION_USAGE_KEYS) ||
    usage.schemaVersion !== 1 ||
    typeof usage.usageId !== 'string' ||
    usage.bundleSha256 !== authorization.authorizationSha256 ||
    usage.candidateSha !== freezeManifest.candidateSha ||
    usage.releaseId !== freezeManifest.releaseId ||
    usage.configSha256 !== objectSha256(config) ||
    usage.ownedOriginSha256 !== authorization.ownedOriginSha256 ||
    usage.sandboxHostSha256 !== authorization.sandboxHostSha256 ||
    !exactKeys(usage.requestCounts, AUTHORIZATION_IDS) ||
    AUTHORIZATION_IDS.some(
      (id) => !Number.isSafeInteger(usage.requestCounts[id]) || usage.requestCounts[id] < 0,
    )
  ) {
    fail('E7_RESILIENCE_AUTHORIZATION_USAGE_INVALID');
  }
  return usage;
};

const createAuthorizationBudget = ({
  config,
  freezeManifest,
  externalAuthorization,
  usageSources,
}) => {
  const authorization = externalAuthorization.value;
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
    authorization.candidateSha !== freezeManifest.candidateSha ||
    authorization.releaseId !== freezeManifest.releaseId ||
    authorization.stage7ConfigSha256 !== objectSha256(config) ||
    authorization.authorizationIds?.join('\0') !== AUTHORIZATION_IDS.join('\0') ||
    !exactKeys(authorization.requestLimits, AUTHORIZATION_IDS) ||
    AUTHORIZATION_IDS.some(
      (id) =>
        !Number.isSafeInteger(authorization.requestLimits[id]) ||
        authorization.requestLimits[id] < 1,
    ) ||
    !/^[0-9a-f]{64}$/u.test(authorization.authorizationSha256 ?? '') ||
    !/^[0-9a-f]{64}$/u.test(authorization.ownedOriginSha256 ?? '') ||
    !/^[0-9a-f]{64}$/u.test(authorization.sandboxHostSha256 ?? '') ||
    authorization.targetValuesCaptured !== false ||
    authorization.externalRequests !== 0 ||
    authorization.mutationsPerformed !== 0 ||
    authorization.containsSensitiveData !== false ||
    !Array.isArray(usageSources) ||
    usageSources.length !== PRIOR_AUTHORIZATION_USAGE_IDS.length
  ) {
    fail('E7_RESILIENCE_EXTERNAL_AUTHORIZATION_INVALID');
  }
  const seen = new Set();
  const totals = Object.fromEntries(AUTHORIZATION_IDS.map((id) => [id, 0]));
  const priorUsages = usageSources.map(({ basename, document, usage }) => {
    validateAuthorizationUsage({ usage, authorization, config, freezeManifest });
    if (
      typeof basename !== 'string' ||
      !/^[a-z0-9][a-z0-9.-]{2,127}\.json$/u.test(basename) ||
      seen.has(usage.usageId)
    ) {
      fail('E7_RESILIENCE_AUTHORIZATION_USAGE_INVALID');
    }
    seen.add(usage.usageId);
    for (const id of AUTHORIZATION_IDS) totals[id] += usage.requestCounts[id];
    return {
      basename,
      rawSha256: document.rawSha256,
      objectSha256: document.canonicalSha256,
      usageId: usage.usageId,
      usageSha256: objectSha256(usage),
      requestCounts: usage.requestCounts,
    };
  });
  if (
    [...seen].toSorted().join('\0') !== [...PRIOR_AUTHORIZATION_USAGE_IDS].toSorted().join('\0')
  ) {
    fail('E7_RESILIENCE_AUTHORIZATION_USAGE_SET_INVALID');
  }
  const reservedUsage = {
    schemaVersion: 1,
    usageId: 'ROLLBACK_RESILIENCE',
    bundleSha256: authorization.authorizationSha256,
    candidateSha: freezeManifest.candidateSha,
    releaseId: freezeManifest.releaseId,
    configSha256: objectSha256(config),
    ownedOriginSha256: authorization.ownedOriginSha256,
    sandboxHostSha256: authorization.sandboxHostSha256,
    requestCounts: {
      'AUTH-E7-EXT-01': 11,
      'AUTH-E7-EXT-02': 0,
      'AUTH-E7-EXT-03': 0,
    },
  };
  const finalTotals = Object.fromEntries(
    AUTHORIZATION_IDS.map((id) => [id, totals[id] + reservedUsage.requestCounts[id]]),
  );
  if (AUTHORIZATION_IDS.some((id) => finalTotals[id] > authorization.requestLimits[id])) {
    fail('E7_RESILIENCE_AUTHORIZATION_LIMIT_EXCEEDED');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_AUTHORIZATION_BUDGET',
    status: 'RESERVED_BEFORE_EXTERNAL_REQUESTS',
    candidateSha: freezeManifest.candidateSha,
    releaseId: freezeManifest.releaseId,
    configSha256: objectSha256(config),
    externalAuthorizationEvidenceSha256: externalAuthorization.rawSha256,
    externalAuthorizationObjectSha256: externalAuthorization.canonicalSha256,
    authorizationSha256: authorization.authorizationSha256,
    authorizationIds: AUTHORIZATION_IDS,
    requestLimits: authorization.requestLimits,
    priorUsages,
    priorTotals: totals,
    reservedUsage,
    finalTotals,
    reservedExternalRequests: 11,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const value = { ...body, budgetSha256: objectSha256(body) };
  return {
    value,
    document: sourceDocument(publicJsonSource(value), 'E7_RESILIENCE_BUDGET_INVALID').document,
  };
};

const checkedAssemblyDirectory = (directory, capability) => {
  const selfTest = capability === SELF_TEST_ASSEMBLY_CAPABILITY;
  const root = realpathSync(selfTest ? os.tmpdir() : workspaceRoot);
  const resolved = path.resolve(directory);
  const relative = path.relative(root, resolved);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative) ||
    !lstatSync(resolved).isDirectory() ||
    lstatSync(resolved).isSymbolicLink() ||
    realpathSync(resolved) !== resolved ||
    (selfTest && !path.basename(resolved).startsWith('stage7-rb-integration-selftest-'))
  ) {
    fail('E7_RESILIENCE_ASSEMBLY_PATH_INVALID');
  }
  return resolved;
};

const readFrozenObservabilityTemplate = ({ assemblyDirectory, stackName, capability }) => {
  const directory = checkedAssemblyDirectory(assemblyDirectory, capability);
  const manifestPath = path.join(directory, 'manifest.json');
  if (lstatSync(manifestPath).isSymbolicLink()) fail('E7_RESILIENCE_ASSEMBLY_MANIFEST_INVALID');
  let manifest;
  try {
    manifest = parseStrictJsonSource(readFileSync(manifestPath), { scanForbiddenData: false });
  } catch {
    fail('E7_RESILIENCE_ASSEMBLY_MANIFEST_INVALID');
  }
  const artifact = manifest?.artifacts?.[stackName];
  const templateFile = artifact?.properties?.templateFile;
  if (
    artifact?.type !== 'aws:cloudformation:stack' ||
    typeof templateFile !== 'string' ||
    templateFile === '' ||
    path.isAbsolute(templateFile) ||
    templateFile.split(/[\\/]/u).includes('..')
  ) {
    fail('E7_RESILIENCE_OBSERVABILITY_ARTIFACT_INVALID');
  }
  const templatePath = path.resolve(directory, templateFile);
  if (
    !templatePath.startsWith(`${directory}${path.sep}`) ||
    lstatSync(templatePath).isSymbolicLink()
  ) {
    fail('E7_RESILIENCE_OBSERVABILITY_TEMPLATE_PATH_INVALID');
  }
  let template;
  try {
    template = parseStrictJsonSource(readFileSync(templatePath), { scanForbiddenData: false });
  } catch {
    fail('E7_RESILIENCE_OBSERVABILITY_TEMPLATE_INVALID');
  }
  if (!object(template?.Resources)) {
    fail('E7_RESILIENCE_OBSERVABILITY_TEMPLATE_INVALID');
  }
  return { template, templateSha256: objectSha256(template) };
};

const validateDeploymentBinding = ({ binding, config, freezeManifest, templateSha256 }) => {
  const alarmName = `checkout-${config.environment}-rollback-rehearsal`;
  const alarmArn = `arn:aws:cloudwatch:${config.aws.region}:${config.aws.accountId}:alarm:${alarmName}`;
  const expected = {
    stackName: expectedStage7Stacks(config.environment)[2],
    templateSha256,
    cloudFormationExecutionRoleArn: cloudFormationExecutionRoleArn(config),
    rollbackRehearsalAlarm: {
      alarmName,
      alarmArn,
      metricNamespace: 'Checkout/Stage7Rehearsal',
      metricName: 'RollbackRehearsalFailure',
      dimensions: [
        { name: 'Environment', value: config.environment },
        { name: 'ReleaseId', value: freezeManifest.releaseId },
        { name: 'Scenario', value: 'RB-E7-08' },
      ],
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
  if (canonicalJson(binding) !== canonicalJson(expected)) {
    fail('E7_RESILIENCE_DEPLOYMENT_BINDING_INVALID');
  }
  return expected;
};

const evidenceIdentity = ({
  value,
  config,
  freezeManifest,
  previousReleaseManifest,
  checkpoint,
}) => {
  if (
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.candidateSha !== freezeManifest.candidateSha ||
    value.releaseId !== freezeManifest.releaseId ||
    value.configSha256 !== objectSha256(config) ||
    value.containsSensitiveData !== false ||
    checkpoint?.previousReleaseManifestSha256 !== previousReleaseManifest.manifestSha256
  ) {
    fail('E7_RESILIENCE_SOURCE_EVIDENCE_IDENTITY_INVALID');
  }
};

const validateCriticalSourceCheckpoints = ({
  deployment,
  observability,
  activation,
  config,
  freezeManifest,
  previousReleaseManifest,
}) => {
  const webCheckpoint = deployment.checkpoints?.web;
  const observabilityCheckpoint = observability.checkpoints?.observability;
  const observabilityReadiness = observability.checkpoints?.observabilityReadiness;
  const activationCheckpoint = activation.checkpoints?.activation;
  if (
    webCheckpoint?.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    webCheckpoint.releaseMode !== 'VERSIONED_UPDATE' ||
    webCheckpoint.freezeManifestSha256 !== freezeManifest.manifestSha256 ||
    webCheckpoint.outputs?.CandidateSha !== freezeManifest.candidateSha ||
    webCheckpoint.outputs?.ReleaseId !== freezeManifest.releaseId ||
    webCheckpoint.outputs?.WebPublicationStatus !== 'DISABLED' ||
    observabilityCheckpoint?.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    observabilityCheckpoint.releaseMode !== 'VERSIONED_UPDATE' ||
    observabilityCheckpoint.freezeManifestSha256 !== freezeManifest.manifestSha256 ||
    observabilityReadiness?.decision !== 'PASS' ||
    observabilityReadiness.status !== 'CONFIRMED' ||
    observabilityReadiness.alertDestinationSha256 !== config.budget.alertDestinationSha256 ||
    observabilityReadiness.rawDestinationCaptured !== false ||
    activationCheckpoint?.decision !== 'ACTIVATED_REQUIRES_SMOKE' ||
    activationCheckpoint.previousReleaseManifestSha256 !== previousReleaseManifest.manifestSha256
  ) {
    fail('E7_RESILIENCE_SOURCE_CHECKPOINT_INVALID');
  }
  return activationCheckpoint;
};

export const prepareRollbackResilienceArtifacts = ({
  config,
  freezeManifest,
  previousReleaseManifest,
  candidateRecord,
  rollbackSource,
  awsAuthSource,
  approvalSource,
  approvedPlanSource,
  deploymentEvidenceSource,
  observabilityEvidenceSource,
  activationEvidenceSource,
  externalAuthorizationSource,
  smokeInputSource,
  smokeEvidenceSource,
  edgeEvidenceSource,
  qualityEvidenceSource,
  sandboxEvidenceSource,
  rollbackSmokeInputSource,
  pendingProducerSource,
  rollbackSmokeSource,
  repromotionSmokeSource,
  journalCleanupRoleArn,
  assemblyDirectory,
  maxPolls = 30,
  capability,
}) => {
  const journalRoleMatch = IAM_ROLE_ARN.exec(journalCleanupRoleArn ?? '');
  if (
    journalRoleMatch === null ||
    journalRoleMatch[1] !== config?.aws?.accountId ||
    Object.values(config?.aws?.roles ?? {}).includes(journalCleanupRoleArn)
  ) {
    fail('E7_RESILIENCE_JOURNAL_CLEANUP_ROLE_INVALID');
  }
  if (!Number.isSafeInteger(maxPolls) || maxPolls < 3 || maxPolls > 60) {
    fail('E7_RESILIENCE_MAX_POLLS_INVALID');
  }
  validateStage7Config(config, { now: new Date(config.window.startsAtUtc) });
  validateFreezeManifest(freezeManifest);
  validateStage7PreviousReleaseForTarget(previousReleaseManifest, { config, freezeManifest });
  validateStage7CandidateRollbackRecord(candidateRecord, {
    previousManifest: previousReleaseManifest,
  });
  const rollback = sourceDocument(rollbackSource, 'E7_RESILIENCE_ROLLBACK_SOURCE_INVALID');
  const rollbackEvidence = rollback.value;
  const baseRehearsal = rollbackEvidence?.checkpoints?.versionedRollbackRehearsal;
  validateStage7VersionedRollbackRehearsal(baseRehearsal, {
    previousManifest: previousReleaseManifest,
    candidateRecord,
  });
  if (
    rollbackEvidence?.status !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    baseRehearsal.status !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    baseRehearsal.pendingScenarioIds?.join('\0') !== ['RB-E7-06', 'RB-E7-08'].join('\0')
  ) {
    fail('E7_RESILIENCE_BASE_REHEARSAL_INVALID');
  }

  const approval = sourceDocument(approvalSource, 'E7_RESILIENCE_APPROVAL_SOURCE_INVALID');
  const awsAuth = sourceDocument(awsAuthSource, 'E7_RESILIENCE_AWS_AUTH_SOURCE_INVALID');
  const plan = sourceDocument(approvedPlanSource, 'E7_RESILIENCE_PLAN_SOURCE_INVALID');
  const deployment = sourceDocument(
    deploymentEvidenceSource,
    'E7_RESILIENCE_DEPLOYMENT_SOURCE_INVALID',
  );
  const observability = sourceDocument(
    observabilityEvidenceSource,
    'E7_RESILIENCE_OBSERVABILITY_SOURCE_INVALID',
  );
  const activation = sourceDocument(
    activationEvidenceSource,
    'E7_RESILIENCE_ACTIVATION_SOURCE_INVALID',
  );
  const authorizationDocuments = {
    externalAuthorization: sourceDocument(
      externalAuthorizationSource,
      'E7_RESILIENCE_EXTERNAL_AUTHORIZATION_SOURCE_INVALID',
    ),
    smokeInput: sourceDocument(smokeInputSource, 'E7_RESILIENCE_SMOKE_INPUT_SOURCE_INVALID'),
    smoke: sourceDocument(smokeEvidenceSource, 'E7_RESILIENCE_SMOKE_SOURCE_INVALID'),
    edge: sourceDocument(edgeEvidenceSource, 'E7_RESILIENCE_EDGE_SOURCE_INVALID'),
    quality: sourceDocument(qualityEvidenceSource, 'E7_RESILIENCE_QUALITY_SOURCE_INVALID'),
    sandbox: sourceDocument(sandboxEvidenceSource, 'E7_RESILIENCE_SANDBOX_SOURCE_INVALID'),
    rollbackSmokeInput: sourceDocument(
      rollbackSmokeInputSource,
      'E7_RESILIENCE_ROLLBACK_SMOKE_INPUT_SOURCE_INVALID',
    ),
    pendingProducer: sourceDocument(
      pendingProducerSource,
      'E7_RESILIENCE_PENDING_PRODUCER_SOURCE_INVALID',
    ),
    rollbackSmoke: sourceDocument(
      rollbackSmokeSource,
      'E7_RESILIENCE_ROLLBACK_SMOKE_SOURCE_INVALID',
    ),
    repromotionSmoke: sourceDocument(
      repromotionSmokeSource,
      'E7_RESILIENCE_REPROMOTION_SMOKE_SOURCE_INVALID',
    ),
  };
  let iamEffectivePermissions;
  try {
    if (
      assertAwsAuthEnvelopeShape(awsAuth.value) !== awsAuth.value ||
      awsAuth.value.kind !== 'AWS_READ_ONLY_PREFLIGHT' ||
      awsAuth.value.status !== 'PASS' ||
      awsAuth.value.scope !== 'full' ||
      awsAuth.value.candidateSha !== freezeManifest.candidateSha ||
      awsAuth.value.releaseId !== freezeManifest.releaseId ||
      awsAuth.value.manifestSha256 !== freezeManifest.manifestSha256 ||
      awsAuth.value.configSha256 !== objectSha256(config) ||
      awsAuth.value.mutationsPerformed !== 0 ||
      awsAuth.value.containsSensitiveData !== false
    ) {
      fail('E7_RESILIENCE_AWS_AUTH_SOURCE_INVALID');
    }
    validateAwsAuthAuxiliaryRoleBindings({
      value: awsAuth.value,
      config,
      journalCleanupRoleArn,
    });
    iamEffectivePermissions =
      capability === SELF_TEST_ASSEMBLY_CAPABILITY
        ? awsAuth.value.iamEffectivePermissions
        : validateIamEffectivePermissionsEvidence({
            value: awsAuth.value.iamEffectivePermissions,
            config,
            scope: 'full',
            candidateSha: freezeManifest.candidateSha,
            releaseId: freezeManifest.releaseId,
            manifestSha256: freezeManifest.manifestSha256,
            bootstrapAssetInventory:
              awsAuth.value.iamEffectivePermissions?.bootstrapRoles?.assetInventory?.inventory,
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
    approval.document.sha256 !== candidateRecord.approvalSha256 ||
    plan.document.sha256 !== candidateRecord.planSha256 ||
    deployment.document.sha256 !== candidateRecord.deploymentEvidenceSha256 ||
    !exactKeys(approval.value, PROTECTED_APPROVAL_KEYS) ||
    approval.value.kind !== 'PROTECTED_RELEASE_APPROVAL' ||
    approval.value.status !== 'PASS' ||
    approval.value.scope !== 'full' ||
    approval.value.releaseTag !== freezeManifest.releaseTag ||
    approval.value.cloudAssemblySha256 !==
      freezeManifest.artifacts.find(({ name }) => name === 'iac')?.sha256 ||
    approval.value.freezeManifestSha256 !== freezeManifest.manifestSha256 ||
    approval.value.approvedPlanSha256 !== plan.document.sha256 ||
    approval.value.approvedDiffSha256 !== plan.value.rawDiffArtifactSha256 ||
    approval.value.statefulReplacements !== 0 ||
    approval.value.destructiveChanges !== 0 ||
    approval.value.iamBroadeningDetected !== plan.value.iamBroadeningDetected ||
    approval.value.iamBroadeningReviewed !== true ||
    approval.value.humanReviewConfirmed !== true ||
    approval.value.explicitDispatchConfirmation !== true ||
    approval.value.protectedEnvironment !== true ||
    approval.value.protectedEnvironmentName !== 'assessment-release' ||
    approval.value.nonPublic !== false ||
    approval.value.accountSha256 !== sha256(config.aws.accountId) ||
    approval.value.accountSuffix !== config.aws.accountId.slice(-4) ||
    approval.value.region !== config.aws.region ||
    canonicalJson(approval.value.stacks) !== canonicalJson(config.authorization.stacks) ||
    canonicalJson(approval.value.authorizedWindow) !== canonicalJson(config.window) ||
    approval.value.approvalOwnerAlias !== config.authorization.ownerAlias ||
    approval.value.externalRequests !== 0 ||
    approval.value.mutationsPerformed !== 0 ||
    approval.value.iamEffectivePermissionsBindingSha256 !==
      iamEffectivePermissions?.bindingSha256 ||
    approval.value.iamEffectivePermissionsEvidenceSha256 !== awsAuth.document.sha256 ||
    approval.value.journalRoleEffectivePermissionsRawSha256 !==
      awsAuth.value.journalRoleEffectivePermissionsRawSha256 ||
    approval.value.journalRoleEffectivePermissionsSha256 !==
      awsAuth.value.journalRoleEffectivePermissionsSha256 ||
    canonicalJson(reconciliationRecoveryRoleAuthority(approval.value)) !==
      canonicalJson(reconciliationRecoveryRoleAuthority(awsAuth.value)) ||
    plan.value.kind !== 'RELEASE_DIFF_REVIEW' ||
    plan.value.status !== 'READY_FOR_PROTECTED_REVIEW'
  ) {
    fail('E7_RESILIENCE_SOURCE_DIGEST_BINDING_INVALID');
  }
  validateOperationEvidenceEnvelope({
    value: deployment.value,
    config,
    freezeManifest,
    checkpoint: 'web',
  });
  validateOperationEvidenceEnvelope({
    value: observability.value,
    config,
    freezeManifest,
    checkpoint: 'observability',
  });
  validateOperationEvidenceEnvelope({
    value: activation.value,
    config,
    freezeManifest,
    checkpoint: 'activation',
  });
  evidenceIdentity({
    value: approval.value,
    config,
    freezeManifest,
    previousReleaseManifest,
    checkpoint: approval.value,
  });
  evidenceIdentity({
    value: plan.value,
    config,
    freezeManifest,
    previousReleaseManifest,
    checkpoint: plan.value,
  });
  evidenceIdentity({
    value: deployment.value,
    config,
    freezeManifest,
    previousReleaseManifest,
    checkpoint: deployment.value.checkpoints?.web,
  });
  evidenceIdentity({
    value: observability.value,
    config,
    freezeManifest,
    previousReleaseManifest,
    checkpoint: observability.value.checkpoints?.observability,
  });
  evidenceIdentity({
    value: activation.value,
    config,
    freezeManifest,
    previousReleaseManifest,
    checkpoint: activation.value.checkpoints?.activation,
  });

  const activationCheckpoint = validateCriticalSourceCheckpoints({
    deployment: deployment.value,
    observability: observability.value,
    activation: activation.value,
    config,
    freezeManifest,
    previousReleaseManifest,
  });
  const activationTransitions = activationCheckpoint.transitions;
  if (
    !Array.isArray(activationTransitions) ||
    activationTransitions.length !== 2 ||
    activationTransitions.some((transition) => !object(transition?.authorizationUsage))
  ) {
    fail('E7_RESILIENCE_ACTIVATION_AUTHORIZATION_USAGE_INVALID');
  }
  const authorizationBudget = createAuthorizationBudget({
    config,
    freezeManifest,
    externalAuthorization: authorizationDocuments.externalAuthorization,
    usageSources: [
      {
        basename: 'external-authorization.json',
        document: authorizationDocuments.externalAuthorization,
        usage: authorizationDocuments.externalAuthorization.value.authorizationUsage,
      },
      {
        basename: 'smoke-input-preflight.json',
        document: authorizationDocuments.smokeInput,
        usage: authorizationDocuments.smokeInput.value.authorizationUsage,
      },
      {
        basename: 'activation.json',
        document: activation,
        usage: activationTransitions[0].authorizationUsage,
      },
      {
        basename: 'smoke.json',
        document: authorizationDocuments.smoke,
        usage: authorizationDocuments.smoke.value.authorizationUsage,
      },
      {
        basename: 'quality.json',
        document: authorizationDocuments.quality,
        usage: authorizationDocuments.quality.value.authorizationUsage,
      },
      {
        basename: 'edge-security.json',
        document: authorizationDocuments.edge,
        usage: authorizationDocuments.edge.value.authorizationUsage,
      },
      {
        basename: 'sandbox-smoke.json',
        document: authorizationDocuments.sandbox,
        usage: authorizationDocuments.sandbox.value.authorizationUsage,
      },
      {
        basename: 'rollback-smoke-input-preflight.json',
        document: authorizationDocuments.rollbackSmokeInput,
        usage: authorizationDocuments.rollbackSmokeInput.value.authorizationUsage,
      },
      {
        basename: 'rollback-pending-producer.json',
        document: authorizationDocuments.pendingProducer,
        usage: authorizationDocuments.pendingProducer.value.authorizationUsage,
      },
      {
        basename: 'versioned-rollback-smoke.json',
        document: authorizationDocuments.rollbackSmoke,
        usage: authorizationDocuments.rollbackSmoke.value.authorizationUsage,
      },
      {
        basename: 'activation.json',
        document: activation,
        usage: activationTransitions[1].authorizationUsage,
      },
      {
        basename: 'versioned-repromotion-smoke.json',
        document: authorizationDocuments.repromotionSmoke,
        usage: authorizationDocuments.repromotionSmoke.value.authorizationUsage,
      },
    ],
  });
  if (capability !== SELF_TEST_ASSEMBLY_CAPABILITY) {
    validateStage7ActivationCheckpoint(activationCheckpoint, {
      config,
      candidateSha: freezeManifest.candidateSha,
      releaseId: freezeManifest.releaseId,
      manifestSha256: freezeManifest.manifestSha256,
      complete: false,
    });
  }

  const stackName = expectedStage7Stacks(config.environment)[2];
  const frozen = readFrozenObservabilityTemplate({ assemblyDirectory, stackName, capability });
  const deploymentBinding = validateDeploymentBinding({
    binding: observability.value.checkpoints.observability.rollbackResilience,
    config,
    freezeManifest,
    templateSha256: frozen.templateSha256,
  });
  const activationAtUtc = activation.value.updatedAtUtc;
  if (
    !utc(activationAtUtc) ||
    Date.parse(activationAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(activationAtUtc) > Date.parse(config.window.endsAtUtc)
  ) {
    fail('E7_RESILIENCE_ACTIVATION_TIME_INVALID');
  }
  const runtimeSecretReferenceSha256 = sha256(config.prereleaseAccess.originTokenSecretArn);
  const inputsWithoutExecution = {
    config,
    freezeManifest,
    previousReleaseManifest,
    candidateRecord,
    baseRehearsal,
    journalCleanupRoleArn,
    documents: {
      approval: approval.document,
      awsAuth: awsAuth.document,
      approvedPlan: plan.document,
      deploymentEvidence: deployment.document,
      observabilityEvidence: observability.document,
      activationEvidence: activation.document,
      externalAuthorizationEvidence: authorizationDocuments.externalAuthorization.document,
      authorizationBudget: authorizationBudget.document,
    },
  };
  const rb06Descriptor = {
    stackName,
    failureLogicalResourceId: 'Stage7RollbackFailureCanary',
    failureResourceType: 'AWS::CloudFormation::WaitCondition',
    failureTimeoutSeconds: 60,
    frozenTemplateSha256: frozen.templateSha256,
    cloudFormationExecutionRoleArn: deploymentBinding.cloudFormationExecutionRoleArn,
    runtimeSecretReferenceSha256,
    maxPolls,
  };
  const rb08Descriptor = {
    ...deploymentBinding.rollbackRehearsalAlarm,
    observabilityStackName: stackName,
    observabilityTemplateSha256: frozen.templateSha256,
    activationAtUtc,
    runtimeSecretReferenceSha256,
    maxPolls,
  };
  const sourceBindingBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_SOURCE_BINDING',
    candidateSha: freezeManifest.candidateSha,
    releaseId: freezeManifest.releaseId,
    previousReleaseManifestSha256: previousReleaseManifest.manifestSha256,
    candidateRecordSha256: candidateRecord.recordSha256,
    approvalSha256: approval.document.sha256,
    awsAuthEvidenceSha256: awsAuth.document.sha256,
    iamEffectivePermissionsBindingSha256: iamEffectivePermissions.bindingSha256,
    approvedPlanSha256: plan.document.sha256,
    deploymentEvidenceSha256: deployment.document.sha256,
    observabilityEvidenceSha256: observability.document.sha256,
    activationEvidenceSha256: activation.document.sha256,
    externalAuthorizationEvidenceSha256:
      authorizationDocuments.externalAuthorization.document.sha256,
    authorizationBudgetSha256: authorizationBudget.document.sha256,
    journalCleanupRoleSha256: sha256(journalCleanupRoleArn),
    reconciliationRecoveryRoleAuthoritySha256: reconciliationRecoveryRoleAuthoritySha256(
      awsAuth.value,
    ),
    rollbackEvidenceSha256: rollback.document.sha256,
    baseRehearsalSha256: baseRehearsal.rehearsalSha256,
    observabilityTemplateSha256: frozen.templateSha256,
    containsSensitiveData: false,
  };
  return {
    inputsWithoutExecution,
    rb06Descriptor,
    rb08Descriptor,
    sourceBinding: {
      ...sourceBindingBody,
      sourceBindingSha256: objectSha256(sourceBindingBody),
    },
  };
};

const validateCompletionSources = ({
  rollback,
  sourceBinding,
  protectedRun,
  validationContext,
}) => {
  const baseRehearsal = rollback.value?.checkpoints?.versionedRollbackRehearsal;
  const completion = protectedRun.value?.completion;
  if (
    !exactKeys(validationContext, ['inputsWithoutExecution', 'rb06Descriptor', 'rb08Descriptor'])
  ) {
    fail('E7_RESILIENCE_COMPLETION_VALIDATION_CONTEXT_INVALID');
  }
  try {
    validatePublicProtectedRollbackResilienceRun({
      run: protectedRun.value,
      ...validationContext,
    });
  } catch {
    fail('E7_RESILIENCE_COMPLETION_PROTECTED_RUN_INVALID');
  }
  if (
    !exactKeys(sourceBinding.value, [
      'schemaVersion',
      'stage',
      'kind',
      'candidateSha',
      'releaseId',
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
      'journalCleanupRoleSha256',
      'reconciliationRecoveryRoleAuthoritySha256',
      'rollbackEvidenceSha256',
      'baseRehearsalSha256',
      'observabilityTemplateSha256',
      'containsSensitiveData',
      'sourceBindingSha256',
    ]) ||
    sourceBinding.value.kind !== 'ROLLBACK_RESILIENCE_SOURCE_BINDING' ||
    sourceBinding.value.rollbackEvidenceSha256 !== rollback.rawSha256 ||
    sourceBinding.value.baseRehearsalSha256 !== baseRehearsal?.rehearsalSha256 ||
    sourceBinding.value.approvalSha256 !==
      validationContext.inputsWithoutExecution.candidateRecord.approvalSha256 ||
    sourceBinding.value.awsAuthEvidenceSha256 !==
      validationContext.inputsWithoutExecution.documents.awsAuth.sha256 ||
    sourceBinding.value.approvedPlanSha256 !==
      validationContext.inputsWithoutExecution.candidateRecord.planSha256 ||
    sourceBinding.value.deploymentEvidenceSha256 !==
      validationContext.inputsWithoutExecution.candidateRecord.deploymentEvidenceSha256 ||
    sourceBinding.value.observabilityEvidenceSha256 !==
      validationContext.inputsWithoutExecution.documents.observabilityEvidence.sha256 ||
    sourceBinding.value.activationEvidenceSha256 !==
      validationContext.inputsWithoutExecution.documents.activationEvidence.sha256 ||
    sourceBinding.value.externalAuthorizationEvidenceSha256 !==
      validationContext.inputsWithoutExecution.documents.externalAuthorizationEvidence.sha256 ||
    sourceBinding.value.authorizationBudgetSha256 !==
      validationContext.inputsWithoutExecution.documents.authorizationBudget.sha256 ||
    sourceBinding.value.journalCleanupRoleSha256 !==
      sha256(validationContext.inputsWithoutExecution.journalCleanupRoleArn) ||
    sourceBinding.value.reconciliationRecoveryRoleAuthoritySha256 !==
      reconciliationRecoveryRoleAuthoritySha256(
        parseStrictJsonSource(
          Buffer.from(validationContext.inputsWithoutExecution.documents.awsAuth.content, 'utf8'),
          { scanForbiddenData: false },
        ),
      ) ||
    sourceBinding.value.sourceBindingSha256 !==
      objectSha256(withoutDigest(sourceBinding.value, 'sourceBindingSha256')) ||
    rollback.value?.status !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    baseRehearsal?.kind !== 'VERSIONED_ROLLBACK_REHEARSAL' ||
    baseRehearsal?.status !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    baseRehearsal?.pendingScenarioIds?.join('\0') !== ['RB-E7-06', 'RB-E7-08'].join('\0') ||
    !exactKeys(protectedRun.value, PROTECTED_RUN_KEYS) ||
    protectedRun.value?.kind !== 'PROTECTED_ROLLBACK_RESILIENCE_RUN' ||
    protectedRun.value?.status !== 'AWS_VERIFIED' ||
    protectedRun.value?.gateE703 !== 'ELIGIBLE_PENDING_RELEASE_CLOSEOUT' ||
    protectedRun.value?.runtimeAttestation?.status !== 'AWS_IDENTITY_REVALIDATED' ||
    protectedRun.value?.runtimeAttestation?.stateBackend !== 'SSM_APPEND_ONLY_HASH_CHAIN' ||
    protectedRun.value?.runtimeAttestation?.executorConstruction !== 'INTERNAL_AWS_CLI_ONLY' ||
    protectedRun.value?.runtimeAttestation?.injectedExecutorAccepted !== false ||
    protectedRun.value?.rb06Checkpoint?.status !== 'AWS_VERIFIED' ||
    protectedRun.value?.rb06Checkpoint?.executionMode !== 'AWS_REAL' ||
    protectedRun.value?.rb08Checkpoint?.status !== 'AWS_VERIFIED' ||
    protectedRun.value?.rb08Checkpoint?.executionMode !== 'AWS_REAL' ||
    protectedRun.value?.rb06Checkpoint?.binding?.candidateSha !==
      sourceBinding.value.candidateSha ||
    protectedRun.value?.rb08Checkpoint?.binding?.candidateSha !==
      sourceBinding.value.candidateSha ||
    protectedRun.value?.rb06Checkpoint?.binding?.baseRehearsalSha256 !==
      sourceBinding.value.baseRehearsalSha256 ||
    protectedRun.value?.rb08Checkpoint?.binding?.baseRehearsalSha256 !==
      sourceBinding.value.baseRehearsalSha256 ||
    protectedRun.value?.rb06Checkpoint?.checkpointSha256 !==
      objectSha256(withoutDigest(protectedRun.value.rb06Checkpoint, 'checkpointSha256')) ||
    protectedRun.value?.rb08Checkpoint?.checkpointSha256 !==
      objectSha256(withoutDigest(protectedRun.value.rb08Checkpoint, 'checkpointSha256')) ||
    protectedRun.value?.extension?.extensionSha256 !==
      objectSha256(withoutDigest(protectedRun.value.extension, 'extensionSha256')) ||
    !exactKeys(completion, RESILIENCE_COMPLETION_KEYS) ||
    completion?.schemaVersion !== 1 ||
    completion?.stage !== 7 ||
    completion?.kind !== 'ROLLBACK_RESILIENCE_COMPLETION' ||
    completion?.status !== 'AWS_VERIFIED' ||
    completion?.scenarioIds?.join('\0') !== ALL_ROLLBACK_SCENARIOS.join('\0') ||
    completion?.pendingScenarioIds?.length !== 0 ||
    completion?.finalReleaseId !== sourceBinding.value.releaseId ||
    completion?.finalCandidateSha !== sourceBinding.value.candidateSha ||
    completion?.dataPolicy !== 'NO_ROLLBACK_FORWARD_ONLY' ||
    completion?.dataRollbackPerformed !== false ||
    completion?.stacksDeleted !== 0 ||
    completion?.containsSensitiveData !== false ||
    !utc(completion?.completedAtUtc) ||
    completion?.completedAtUtc !==
      (Date.parse(protectedRun.value.rb06Checkpoint.completedAtUtc) >
      Date.parse(protectedRun.value.rb08Checkpoint.completedAtUtc)
        ? protectedRun.value.rb06Checkpoint.completedAtUtc
        : protectedRun.value.rb08Checkpoint.completedAtUtc) ||
    completion?.completionSha256 !== objectSha256(withoutDigest(completion, 'completionSha256')) ||
    completion?.baseRehearsalSha256 !== sourceBinding.value.baseRehearsalSha256 ||
    completion?.rb06CheckpointSha256 !== protectedRun.value.rb06Checkpoint.checkpointSha256 ||
    completion?.rb08CheckpointSha256 !== protectedRun.value.rb08Checkpoint.checkpointSha256 ||
    completion?.extensionSha256 !== protectedRun.value.extension.extensionSha256 ||
    completion?.authorizationUsageSha256 !==
      objectSha256(protectedRun.value.extension.authorizationUsage) ||
    completion?.journalLifecycleSha256 !==
      protectedRun.value.runtimeAttestation?.journalLifecycle?.lifecycleSha256 ||
    completion?.reconciliationRecoveryRoleAuthoritySha256 !==
      sourceBinding.value.reconciliationRecoveryRoleAuthoritySha256 ||
    protectedRun.value?.runSha256 !== objectSha256(withoutDigest(protectedRun.value, 'runSha256'))
  ) {
    fail('E7_RESILIENCE_COMPLETION_SOURCE_INVALID');
  }
  return baseRehearsal;
};

const buildCompletionEnvelope = ({ rollback, sourceBinding, protectedRun, validationContext }) => {
  const baseRehearsal = validateCompletionSources({
    rollback,
    sourceBinding,
    protectedRun,
    validationContext,
  });
  const completion = protectedRun.value.completion;
  const finalRehearsalBody = {
    ...withoutDigest(baseRehearsal, 'rehearsalSha256'),
    status: 'PASS',
    scenarioIds: completion.scenarioIds,
    pendingScenarioIds: [],
    resilience: {
      sourceBindingSha256: sourceBinding.value.sourceBindingSha256,
      protectedRunSha256: protectedRun.value.runSha256,
      extensionSha256: completion.extensionSha256,
      rb06CheckpointSha256: completion.rb06CheckpointSha256,
      rb08CheckpointSha256: completion.rb08CheckpointSha256,
      originProtectionContractSha256: completion.originProtectionContractSha256,
      journalLifecycleSha256: completion.journalLifecycleSha256,
      authorizationUsage: protectedRun.value.extension.authorizationUsage,
    },
    completedAtUtc: completion.completedAtUtc,
  };
  const versionedRollbackRehearsal = {
    ...finalRehearsalBody,
    rehearsalSha256: objectSha256(finalRehearsalBody),
  };
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_COMPLETION_ENVELOPE',
    status: 'PASS',
    candidateSha: sourceBinding.value.candidateSha,
    releaseId: sourceBinding.value.releaseId,
    baseRollbackEvidenceRawSha256: rollback.rawSha256,
    baseRollbackEvidenceObjectSha256: rollback.canonicalSha256,
    sourceBindingRawSha256: sourceBinding.rawSha256,
    sourceBindingObjectSha256: sourceBinding.canonicalSha256,
    sourceBindingSha256: sourceBinding.value.sourceBindingSha256,
    protectedRunRawSha256: protectedRun.rawSha256,
    protectedRunObjectSha256: protectedRun.canonicalSha256,
    protectedRunSha256: protectedRun.value.runSha256,
    journalLifecycleSha256: completion.journalLifecycleSha256,
    reconciliationRecoveryRoleAuthoritySha256:
      sourceBinding.value.reconciliationRecoveryRoleAuthoritySha256,
    versionedRollbackRehearsal,
    gateE703: 'ELIGIBLE_PENDING_RELEASE_CLOSEOUT',
    containsSensitiveData: false,
  };
  return { ...body, envelopeSha256: objectSha256(body) };
};

export const createRollbackResilienceCompletionEnvelope = ({
  rollbackSource,
  sourceBinding,
  protectedRun,
  validationContext,
}) =>
  buildCompletionEnvelope({
    rollback: sourceDocument(rollbackSource, 'E7_RESILIENCE_COMPLETION_ROLLBACK_INVALID'),
    sourceBinding: sourceDocument(
      publicJsonSource(sourceBinding),
      'E7_RESILIENCE_COMPLETION_BINDING_INVALID',
    ),
    protectedRun: sourceDocument(
      publicJsonSource(protectedRun),
      'E7_RESILIENCE_COMPLETION_RUN_INVALID',
    ),
    validationContext,
  });

export const validateRollbackResilienceCompletionEnvelope = ({
  envelope,
  rollbackSource,
  sourceBindingSource,
  protectedRunSource,
  validationContext,
}) => {
  const expected = buildCompletionEnvelope({
    rollback: sourceDocument(rollbackSource, 'E7_RESILIENCE_COMPLETION_ROLLBACK_INVALID'),
    sourceBinding: sourceDocument(sourceBindingSource, 'E7_RESILIENCE_COMPLETION_BINDING_INVALID'),
    protectedRun: sourceDocument(protectedRunSource, 'E7_RESILIENCE_COMPLETION_RUN_INVALID'),
    validationContext,
  });
  if (canonicalJson(envelope) !== canonicalJson(expected)) {
    fail('E7_RESILIENCE_COMPLETION_ENVELOPE_INVALID');
  }
  return envelope;
};

export const selfTestRollbackResilienceIntegration = () => {
  const fixture = createRollbackResilienceSelfTestFixture();
  const authorizationSourceInputs = {
    externalAuthorizationSource: fixture.inputs.documents.externalAuthorizationEvidence.content,
    smokeInputSource: fixture.authorizationSources.smokeInput.content,
    smokeEvidenceSource: fixture.authorizationSources.smoke.content,
    edgeEvidenceSource: fixture.authorizationSources.edge.content,
    qualityEvidenceSource: fixture.authorizationSources.quality.content,
    sandboxEvidenceSource: fixture.authorizationSources.sandbox.content,
    rollbackSmokeInputSource: fixture.authorizationSources.rollbackSmokeInput.content,
    pendingProducerSource: fixture.authorizationSources.pendingProducer.content,
    rollbackSmokeSource: fixture.authorizationSources.rollbackSmoke.content,
    repromotionSmokeSource: fixture.authorizationSources.repromotionSmoke.content,
  };
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'stage7-rb-integration-selftest-'));
  try {
    const stackName = expectedStage7Stacks(fixture.inputs.config.environment)[2];
    const templateFile = `${stackName}.template.json`;
    mkdirSync(temporary, { recursive: true });
    writeFileSync(
      path.join(temporary, 'manifest.json'),
      `${JSON.stringify({
        artifacts: {
          [stackName]: {
            type: 'aws:cloudformation:stack',
            properties: { templateFile },
          },
        },
      })}\n`,
      { encoding: 'utf8', mode: 0o600 },
    );
    const template = fixture.observabilityTemplate;
    assert.equal(objectSha256(template), fixture.observabilityTemplateSha256);
    writeFileSync(path.join(temporary, templateFile), `${JSON.stringify(template)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
    const rollbackEvidence = {
      status: 'BLOCKED_REQUIRED_SCENARIOS',
      checkpoints: { versionedRollbackRehearsal: fixture.inputs.baseRehearsal },
      containsSensitiveData: false,
    };
    const prepared = prepareRollbackResilienceArtifacts({
      config: fixture.inputs.config,
      freezeManifest: fixture.inputs.freezeManifest,
      previousReleaseManifest: fixture.inputs.previousReleaseManifest,
      candidateRecord: fixture.inputs.candidateRecord,
      journalCleanupRoleArn: fixture.inputs.journalCleanupRoleArn,
      rollbackSource: `${JSON.stringify(rollbackEvidence)}\n`,
      awsAuthSource: fixture.inputs.documents.awsAuth.content,
      approvalSource: fixture.inputs.documents.approval.content,
      approvedPlanSource: fixture.inputs.documents.approvedPlan.content,
      deploymentEvidenceSource: fixture.inputs.documents.deploymentEvidence.content,
      observabilityEvidenceSource: fixture.inputs.documents.observabilityEvidence.content,
      activationEvidenceSource: fixture.inputs.documents.activationEvidence.content,
      ...authorizationSourceInputs,
      assemblyDirectory: temporary,
      maxPolls: 10,
      capability: SELF_TEST_ASSEMBLY_CAPABILITY,
    });
    assert.equal(prepared.rb06Descriptor.stackName, stackName);
    assert.equal(prepared.rb08Descriptor.alarmName, fixture.alarmName);
    assert.equal(prepared.rb08Descriptor.activationAtUtc, '2026-08-17T11:00:00.000Z');
    assert.equal(
      prepared.sourceBinding.observabilityTemplateSha256,
      fixture.observabilityTemplateSha256,
    );
    assert.equal(
      prepared.sourceBinding.awsAuthEvidenceSha256,
      fixture.inputs.documents.awsAuth.sha256,
    );
    const deploymentValue = JSON.parse(fixture.inputs.documents.deploymentEvidence.content);
    const observabilityValue = JSON.parse(fixture.inputs.documents.observabilityEvidence.content);
    const activationValue = JSON.parse(fixture.inputs.documents.activationEvidence.content);
    assert.throws(
      () =>
        validateOperationEvidenceEnvelope({
          value: { ...deploymentValue, status: 'PASS' },
          config: fixture.inputs.config,
          freezeManifest: fixture.inputs.freezeManifest,
          checkpoint: 'web',
        }),
      (error) => error.code === 'E7_RESILIENCE_OPERATION_EVIDENCE_INVALID',
    );
    assert.throws(
      () =>
        validateOperationEvidenceEnvelope({
          value: { ...deploymentValue, updatedAtUtc: '2026-08-17T10:59:59.000Z' },
          config: fixture.inputs.config,
          freezeManifest: fixture.inputs.freezeManifest,
          checkpoint: 'web',
        }),
      (error) => error.code === 'E7_RESILIENCE_OPERATION_EVIDENCE_INVALID',
    );
    assert.throws(
      () =>
        validateCriticalSourceCheckpoints({
          deployment: {
            ...deploymentValue,
            checkpoints: {
              web: {
                ...deploymentValue.checkpoints.web,
                outputs: {
                  ...deploymentValue.checkpoints.web.outputs,
                  WebPublicationStatus: 'ENABLED',
                },
              },
            },
          },
          observability: observabilityValue,
          activation: activationValue,
          config: fixture.inputs.config,
          freezeManifest: fixture.inputs.freezeManifest,
          previousReleaseManifest: fixture.inputs.previousReleaseManifest,
        }),
      (error) => error.code === 'E7_RESILIENCE_SOURCE_CHECKPOINT_INVALID',
    );
    assert.throws(
      () =>
        evidenceIdentity({
          value: deploymentValue,
          config: fixture.inputs.config,
          freezeManifest: fixture.inputs.freezeManifest,
          previousReleaseManifest: fixture.inputs.previousReleaseManifest,
          checkpoint: {
            ...deploymentValue.checkpoints.web,
            previousReleaseManifestSha256: '0'.repeat(64),
          },
        }),
      (error) => error.code === 'E7_RESILIENCE_SOURCE_EVIDENCE_IDENTITY_INVALID',
    );
    const awsAuthValue = JSON.parse(fixture.inputs.documents.awsAuth.content);
    const approvalValue = JSON.parse(fixture.inputs.documents.approval.content);
    assert.equal(
      exactKeys({ ...approvalValue, unexpectedApprovalField: true }, PROTECTED_APPROVAL_KEYS),
      false,
    );
    assert.throws(
      () => assertAwsAuthEnvelopeShape({ ...awsAuthValue, unexpectedAuthority: true }),
      (error) => error.code === 'E7_RESILIENCE_AWS_AUTH_SOURCE_INVALID',
    );
    assert.throws(
      () =>
        prepareRollbackResilienceArtifacts({
          config: fixture.inputs.config,
          freezeManifest: fixture.inputs.freezeManifest,
          previousReleaseManifest: fixture.inputs.previousReleaseManifest,
          candidateRecord: fixture.inputs.candidateRecord,
          journalCleanupRoleArn: fixture.inputs.journalCleanupRoleArn,
          rollbackSource: `${JSON.stringify(rollbackEvidence)}\n`,
          approvalSource: fixture.inputs.documents.approval.content,
          approvedPlanSource: fixture.inputs.documents.approvedPlan.content,
          deploymentEvidenceSource: fixture.inputs.documents.deploymentEvidence.content,
          observabilityEvidenceSource: fixture.inputs.documents.observabilityEvidence.content,
          activationEvidenceSource: fixture.inputs.documents.activationEvidence.content,
          ...authorizationSourceInputs,
          assemblyDirectory: temporary,
          maxPolls: 10,
          capability: SELF_TEST_ASSEMBLY_CAPABILITY,
        }),
      (error) => error.code === 'E7_RESILIENCE_AWS_AUTH_SOURCE_INVALID',
    );
    assert.throws(
      () =>
        prepareRollbackResilienceArtifacts({
          config: fixture.inputs.config,
          freezeManifest: fixture.inputs.freezeManifest,
          previousReleaseManifest: fixture.inputs.previousReleaseManifest,
          candidateRecord: fixture.inputs.candidateRecord,
          journalCleanupRoleArn: fixture.inputs.journalCleanupRoleArn,
          rollbackSource: `${JSON.stringify(rollbackEvidence)}\n`,
          awsAuthSource: `${fixture.inputs.documents.awsAuth.content} `,
          approvalSource: fixture.inputs.documents.approval.content,
          approvedPlanSource: fixture.inputs.documents.approvedPlan.content,
          deploymentEvidenceSource: fixture.inputs.documents.deploymentEvidence.content,
          observabilityEvidenceSource: fixture.inputs.documents.observabilityEvidence.content,
          activationEvidenceSource: fixture.inputs.documents.activationEvidence.content,
          ...authorizationSourceInputs,
          assemblyDirectory: temporary,
          maxPolls: 10,
          capability: SELF_TEST_ASSEMBLY_CAPABILITY,
        }),
      (error) => error.code === 'E7_RESILIENCE_SOURCE_DIGEST_BINDING_INVALID',
    );
    const tampered = JSON.parse(fixture.inputs.documents.observabilityEvidence.content);
    tampered.checkpoints.observability.rollbackResilience.rollbackRehearsalAlarm.threshold = 2;
    assert.throws(
      () =>
        prepareRollbackResilienceArtifacts({
          config: fixture.inputs.config,
          freezeManifest: fixture.inputs.freezeManifest,
          previousReleaseManifest: fixture.inputs.previousReleaseManifest,
          candidateRecord: fixture.inputs.candidateRecord,
          journalCleanupRoleArn: fixture.inputs.journalCleanupRoleArn,
          rollbackSource: `${JSON.stringify(rollbackEvidence)}\n`,
          awsAuthSource: fixture.inputs.documents.awsAuth.content,
          approvalSource: fixture.inputs.documents.approval.content,
          approvedPlanSource: fixture.inputs.documents.approvedPlan.content,
          deploymentEvidenceSource: fixture.inputs.documents.deploymentEvidence.content,
          observabilityEvidenceSource: `${JSON.stringify(tampered)}\n`,
          activationEvidenceSource: fixture.inputs.documents.activationEvidence.content,
          ...authorizationSourceInputs,
          assemblyDirectory: temporary,
          maxPolls: 10,
          capability: SELF_TEST_ASSEMBLY_CAPABILITY,
        }),
      (error) => error.code === 'E7_RESILIENCE_DEPLOYMENT_BINDING_INVALID',
    );
    const prepareAuthorizationCanary = (overrides) =>
      prepareRollbackResilienceArtifacts({
        config: fixture.inputs.config,
        freezeManifest: fixture.inputs.freezeManifest,
        previousReleaseManifest: fixture.inputs.previousReleaseManifest,
        candidateRecord: fixture.inputs.candidateRecord,
        journalCleanupRoleArn: fixture.inputs.journalCleanupRoleArn,
        rollbackSource: `${JSON.stringify(rollbackEvidence)}\n`,
        awsAuthSource: fixture.inputs.documents.awsAuth.content,
        approvalSource: fixture.inputs.documents.approval.content,
        approvedPlanSource: fixture.inputs.documents.approvedPlan.content,
        deploymentEvidenceSource: fixture.inputs.documents.deploymentEvidence.content,
        observabilityEvidenceSource: fixture.inputs.documents.observabilityEvidence.content,
        activationEvidenceSource: fixture.inputs.documents.activationEvidence.content,
        ...authorizationSourceInputs,
        ...overrides,
        assemblyDirectory: temporary,
        maxPolls: 10,
        capability: SELF_TEST_ASSEMBLY_CAPABILITY,
      });
    const missingRecoveryAuthority = { ...awsAuthValue };
    delete missingRecoveryAuthority.reconciliationRecoveryRoleEffectivePermissionsSha256;
    assert.throws(
      () =>
        prepareAuthorizationCanary({
          awsAuthSource: `${JSON.stringify(missingRecoveryAuthority)}\n`,
        }),
      (error) => error.code === 'E7_RESILIENCE_AWS_AUTH_SOURCE_INVALID',
    );
    assert.throws(
      () =>
        prepareAuthorizationCanary({
          awsAuthSource: `${JSON.stringify({
            ...awsAuthValue,
            reconciliationRecoveryPermissionsBoundaryArn:
              'arn:aws:iam::210987654321:policy/stage7-release-reconciliation-recovery-boundary',
          })}\n`,
        }),
      (error) => error.code === 'E7_RESILIENCE_AWS_AUTH_AUXILIARY_ROLE_BINDING_INVALID',
    );
    const exhaustedAuthorization = JSON.parse(
      fixture.inputs.documents.externalAuthorizationEvidence.content,
    );
    exhaustedAuthorization.requestLimits['AUTH-E7-EXT-01'] = 10;
    assert.throws(
      () =>
        prepareAuthorizationCanary({
          externalAuthorizationSource: `${JSON.stringify(exhaustedAuthorization)}\n`,
        }),
      (error) => error.code === 'E7_RESILIENCE_AUTHORIZATION_LIMIT_EXCEEDED',
    );
    const duplicateUsage = JSON.parse(fixture.authorizationSources.quality.content);
    duplicateUsage.authorizationUsage.usageId = 'EDGE_PASSIVE';
    assert.throws(
      () =>
        prepareAuthorizationCanary({
          qualityEvidenceSource: `${JSON.stringify(duplicateUsage)}\n`,
        }),
      (error) => error.code === 'E7_RESILIENCE_AUTHORIZATION_USAGE_INVALID',
    );
    const wrongAuthority = JSON.parse(fixture.authorizationSources.smoke.content);
    wrongAuthority.authorizationUsage.bundleSha256 = '0'.repeat(64);
    assert.throws(
      () =>
        prepareAuthorizationCanary({
          smokeEvidenceSource: `${JSON.stringify(wrongAuthority)}\n`,
        }),
      (error) => error.code === 'E7_RESILIENCE_AUTHORIZATION_USAGE_INVALID',
    );
    for (const reusedRoleArn of [
      fixture.inputs.config.aws.roles.rollbackRoleArn,
      fixture.inputs.config.aws.roles.cleanupRoleArn,
    ]) {
      assert.throws(
        () => prepareAuthorizationCanary({ journalCleanupRoleArn: reusedRoleArn }),
        (error) => error.code === 'E7_RESILIENCE_JOURNAL_CLEANUP_ROLE_INVALID',
      );
    }
    return {
      status: 'PASS',
      canaries: 18,
      externalRequests: 0,
      sourceBindingSha256: prepared.sourceBinding.sourceBindingSha256,
    };
  } finally {
    rmSync(temporary, { force: true, recursive: true });
    assert.equal(existsSync(temporary), false, 'self-test workspace must be removed');
  }
};
