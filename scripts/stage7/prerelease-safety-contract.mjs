import { createHash } from 'node:crypto';

import { GITHUB_OIDC_REPOSITORY, githubOidcRefSubject } from './github-oidc-subject-contract.mjs';

export const WATCHDOG_WORKFLOW_RELATIVE = '.github/workflows/prerelease-cleanup.yml';
export const WATCHDOG_CRON = '23 * * * *';
export const WATCHDOG_OIDC_SUBJECT = githubOidcRefSubject('refs/heads/master');
export const EXPECTED_REPOSITORY = GITHUB_OIDC_REPOSITORY;
export const EXPECTED_DEFAULT_BRANCH = 'master';

const SHA256 = /^[0-9a-f]{64}$/u;
const GITHUB_RUN_ID = /^[1-9][0-9]{0,19}$/u;
const GITHUB_RUN_ATTEMPT = /^[1-9][0-9]{0,5}$/u;
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, expected) =>
  object(value) && Object.keys(value).toSorted().join('\0') === expected.toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const isoUtc = (value) =>
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
  !Number.isNaN(Date.parse(value)) &&
  new Date(value).toISOString() === value;
const canonicalize = (value) => {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (!object(value)) return value;
  return Object.fromEntries(
    Object.keys(value)
      .toSorted()
      .map((key) => [key, canonicalize(value[key])]),
  );
};
const canonicalJson = (value) => JSON.stringify(canonicalize(value));
const objectSha256 = (value) => sha256(canonicalJson(value));
const READ_IDENTITY_KEYS = [
  'status',
  'decision',
  'runId',
  'runAttempt',
  'sessionKind',
  'sessionPrefix',
  'accountSha256',
  'accountSuffix',
  'roleArnSha256',
  'sessionArnSha256',
  'principalIdSha256',
  'sessionNameSha256',
  'sessionBindingSha256',
  'rawIdentityCaptured',
];
const SAFETY_SESSION_PREFIX = 'e7pre-safety';

export class PrereleaseSafetyContractError extends Error {
  constructor(code) {
    super(code);
    this.name = 'PrereleaseSafetyContractError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new PrereleaseSafetyContractError(code);
};

export const validatePrereleaseSafetyReadiness = (
  value,
  {
    config,
    freeze,
    sourceBindings,
    watchdogRoleArn,
    iamEffectivePermissions,
    expectedGithubRunId,
    expectedGithubRunAttempt,
    now = new Date(),
  },
) => {
  if (
    !object(value) ||
    !object(config) ||
    !object(config.authorization) ||
    !object(config.window) ||
    !object(config.cleanup) ||
    !object(config.prereleaseAccess) ||
    !object(freeze) ||
    !object(sourceBindings) ||
    !object(iamEffectivePermissions) ||
    typeof watchdogRoleArn !== 'string'
  ) {
    fail('E7_PRERELEASE_SAFETY_READINESS_INVALID');
  }
  const body = { ...value };
  delete body.readinessSha256;
  const expectedSourceKeys = [
    'configSha256',
    'freezeManifestSha256',
    'cloudAssemblySha256',
    'approvedPlanSha256',
    'approvedRawDiffSha256',
    'approvalSha256',
    'awsAuthSha256',
    'watchdogWorkflowSha256',
    'watchdogCandidateBlobSha256',
  ];
  const expectedIamKeys = [
    'status',
    'effectivePermissionsBindingSha256',
    'effectivePermissionsEvidenceSha256',
    'watchdogRoleArnSha256',
    'watchdogTrustPolicySha256',
    'watchdogOidcSubjectsSha256',
    'watchdogPermissionSetSha256',
    'expectedOidcSubjectSha256',
  ];
  const expectedAccessKeys = [
    'status',
    'mode',
    'bindingSha256',
    'keyGroupIdSha256',
    'keyGroupEtagSha256',
    'keyGroupPublicKeyCount',
    'publicKeyIdSha256',
    'publicKeyEtagSha256',
    'publicKeyMaterialSha256',
    'publicKeyAlgorithm',
    'originTokenSecretArnSha256',
    'originTokenSecretVersionIdSha256',
    'originSecretBindingSha256',
    'currentVersionCount',
    'rotationEnabled',
    'customerManagedKmsKeyUsed',
    'rawAccessMaterialCaptured',
  ];
  const expectedCleanupKeys = [
    'status',
    'decision',
    'workflowPath',
    'workflowSha256',
    'candidateBlobSha256',
    'cron',
    'oidcSubject',
    'roleArnSha256',
    'roleTrustPolicySha256',
    'rolePermissionSetSha256',
    'apiStatus',
    'repository',
    'defaultBranch',
    'workflowState',
    'defaultBranchHeadSha256',
    'workflowIdSha256',
    'repositoryResponseSha256',
    'workflowResponseSha256',
    'refResponseSha256',
    'apiRequests',
    'rawApiResponseCaptured',
    'independentOfPrereleaseRun',
    'humanApprovalRequired',
    'scheduleEnabledByContract',
  ];
  const access = config.prereleaseAccess;
  const watchdogRole = iamEffectivePermissions.cleanupWatchdog?.role;
  const readIdentity = value.readIdentity;
  const readRoleArn = config.aws?.roles?.readRoleArn ?? '';
  const readRoleName = readRoleArn.slice(readRoleArn.lastIndexOf('/') + 1);
  const safetySessionName = `${SAFETY_SESSION_PREFIX}-${expectedGithubRunId}-${expectedGithubRunAttempt}`;
  const expectedSessionArn = `arn:aws:sts::${config.aws?.accountId}:assumed-role/${readRoleName}/${safetySessionName}`;
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'decision',
      'scope',
      'generatedAtUtc',
      'environment',
      'authorizationId',
      'candidateSha',
      'releaseId',
      'authorizedWindow',
      'sources',
      'iam',
      'readIdentity',
      'accessControl',
      'durableCleanup',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'readinessSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'PRERELEASE_SAFETY_READINESS' ||
    value.status !== 'PASS' ||
    value.decision !== 'READY_FOR_PROTECTED_PRERELEASE_MUTATION' ||
    value.scope !== 'prerelease' ||
    !isoUtc(value.generatedAtUtc) ||
    !(now instanceof Date) ||
    !Number.isFinite(now.getTime()) ||
    Date.parse(value.generatedAtUtc) > now.getTime() ||
    Date.parse(value.generatedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(value.generatedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    value.environment !== config.environment ||
    value.authorizationId !== config.authorization.id ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    !exactKeys(value.authorizedWindow, ['startsAtUtc', 'endsAtUtc', 'cleanupExpiresAtUtc']) ||
    value.authorizedWindow.startsAtUtc !== config.window.startsAtUtc ||
    value.authorizedWindow.endsAtUtc !== config.window.endsAtUtc ||
    value.authorizedWindow.cleanupExpiresAtUtc !== config.cleanup.expiresAtUtc ||
    !exactKeys(value.sources, expectedSourceKeys) ||
    canonicalJson(value.sources) !== canonicalJson(sourceBindings) ||
    value.sources.configSha256 !== objectSha256(config) ||
    value.sources.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.sources.watchdogWorkflowSha256 !== value.sources.watchdogCandidateBlobSha256 ||
    Object.values(value.sources).some((digest) => !SHA256.test(digest ?? '')) ||
    !exactKeys(value.iam, expectedIamKeys) ||
    value.iam.status !== 'PASS' ||
    value.iam.effectivePermissionsBindingSha256 !== iamEffectivePermissions.bindingSha256 ||
    value.iam.effectivePermissionsEvidenceSha256 !== value.sources.awsAuthSha256 ||
    value.iam.watchdogRoleArnSha256 !== sha256(watchdogRoleArn) ||
    value.iam.watchdogTrustPolicySha256 !== watchdogRole?.trustPolicySha256 ||
    value.iam.watchdogOidcSubjectsSha256 !== watchdogRole?.oidcSubjectsSha256 ||
    value.iam.watchdogPermissionSetSha256 !== watchdogRole?.permissionSetSha256 ||
    value.iam.expectedOidcSubjectSha256 !== sha256(WATCHDOG_OIDC_SUBJECT) ||
    !exactKeys(readIdentity, READ_IDENTITY_KEYS) ||
    readIdentity.status !== 'PASS' ||
    readIdentity.decision !== 'READ_ROLE_ACCOUNT_CONFIRMED' ||
    !GITHUB_RUN_ID.test(expectedGithubRunId ?? '') ||
    !GITHUB_RUN_ATTEMPT.test(expectedGithubRunAttempt ?? '') ||
    readIdentity.runId !== expectedGithubRunId ||
    readIdentity.runAttempt !== expectedGithubRunAttempt ||
    readIdentity.sessionKind !== 'safety' ||
    readIdentity.sessionPrefix !== SAFETY_SESSION_PREFIX ||
    readIdentity.accountSha256 !== sha256(config.aws?.accountId ?? '') ||
    readIdentity.accountSuffix !== config.aws?.accountId?.slice(-4) ||
    readIdentity.roleArnSha256 !== sha256(readRoleArn) ||
    readIdentity.sessionArnSha256 !== sha256(expectedSessionArn) ||
    !SHA256.test(readIdentity.principalIdSha256 ?? '') ||
    readIdentity.sessionNameSha256 !== sha256(safetySessionName) ||
    readIdentity.sessionBindingSha256 !== sha256(`${readRoleArn}\n${safetySessionName}`) ||
    readIdentity.rawIdentityCaptured !== false ||
    !exactKeys(value.accessControl, expectedAccessKeys) ||
    value.accessControl.status !== 'PASS' ||
    value.accessControl.mode !== 'CLOUDFRONT_SIGNED_COOKIE' ||
    value.accessControl.bindingSha256 !==
      sha256(
        [
          access.mode,
          access.keyGroupId,
          access.publicKeyId,
          access.originTokenSecretArn,
          access.originTokenSecretVersionId,
        ].join('\n'),
      ) ||
    value.accessControl.keyGroupIdSha256 !== sha256(access.keyGroupId) ||
    value.accessControl.keyGroupPublicKeyCount !== 1 ||
    value.accessControl.publicKeyIdSha256 !== sha256(access.publicKeyId) ||
    value.accessControl.publicKeyAlgorithm !== 'RSA' ||
    value.accessControl.originTokenSecretArnSha256 !== sha256(access.originTokenSecretArn) ||
    value.accessControl.originTokenSecretVersionIdSha256 !==
      sha256(access.originTokenSecretVersionId) ||
    value.accessControl.originSecretBindingSha256 !==
      sha256(`${access.originTokenSecretArn}\n${access.originTokenSecretVersionId}`) ||
    value.accessControl.currentVersionCount !== 1 ||
    value.accessControl.rotationEnabled !== false ||
    value.accessControl.customerManagedKmsKeyUsed !== false ||
    value.accessControl.rawAccessMaterialCaptured !== false ||
    [
      value.accessControl.keyGroupEtagSha256,
      value.accessControl.publicKeyEtagSha256,
      value.accessControl.publicKeyMaterialSha256,
    ].some((digest) => !SHA256.test(digest ?? '')) ||
    !exactKeys(value.durableCleanup, expectedCleanupKeys) ||
    value.durableCleanup.status !== 'PASS' ||
    value.durableCleanup.decision !== 'DURABLE_RECOVERY_READY' ||
    value.durableCleanup.workflowPath !== WATCHDOG_WORKFLOW_RELATIVE ||
    value.durableCleanup.workflowSha256 !== value.sources.watchdogWorkflowSha256 ||
    value.durableCleanup.candidateBlobSha256 !== value.sources.watchdogCandidateBlobSha256 ||
    value.durableCleanup.cron !== WATCHDOG_CRON ||
    value.durableCleanup.oidcSubject !== WATCHDOG_OIDC_SUBJECT ||
    value.durableCleanup.roleArnSha256 !== sha256(watchdogRoleArn) ||
    value.durableCleanup.roleTrustPolicySha256 !== watchdogRole?.trustPolicySha256 ||
    value.durableCleanup.rolePermissionSetSha256 !== watchdogRole?.permissionSetSha256 ||
    value.durableCleanup.apiStatus !== 'ACTIVE_ON_DEFAULT_BRANCH' ||
    value.durableCleanup.repository !== EXPECTED_REPOSITORY ||
    value.durableCleanup.defaultBranch !== EXPECTED_DEFAULT_BRANCH ||
    value.durableCleanup.workflowState !== 'active' ||
    value.durableCleanup.defaultBranchHeadSha256 !== sha256(freeze.candidateSha) ||
    [
      value.durableCleanup.workflowIdSha256,
      value.durableCleanup.repositoryResponseSha256,
      value.durableCleanup.workflowResponseSha256,
      value.durableCleanup.refResponseSha256,
    ].some((digest) => !SHA256.test(digest ?? '')) ||
    value.durableCleanup.apiRequests !== 3 ||
    value.durableCleanup.rawApiResponseCaptured !== false ||
    value.durableCleanup.independentOfPrereleaseRun !== true ||
    value.durableCleanup.humanApprovalRequired !== false ||
    value.durableCleanup.scheduleEnabledByContract !== true ||
    value.externalRequests !== 7 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.readinessSha256 !== objectSha256(body)
  ) {
    fail('E7_PRERELEASE_SAFETY_READINESS_INVALID');
  }
  return value;
};
