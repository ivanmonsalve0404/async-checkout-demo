import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import { assertSanitizedArtifactText } from '../stage6/lib/artifact-sanitizer.mjs';
import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256, validateStage7Config } from './core.mjs';
import {
  GITHUB_OIDC_REPOSITORY,
  githubOidcEnvironmentSubject,
} from './github-oidc-subject-contract.mjs';
import {
  validateReleaseReconciliationIntent,
  validateReleaseReconciliationReceipt,
  validateReleaseReconciliationSource,
} from './release-reconciliation.mjs';
import {
  RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT,
  RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT,
} from './release-successor-parameter-roots.mjs';

const REPOSITORY = GITHUB_OIDC_REPOSITORY;
const WORKFLOW_PATH = '.github/workflows/stage7-release-reconciliation-recovery.yml';
const REF = 'refs/heads/master';
const PROTECTED_ENVIRONMENT = 'assessment-release-reconciliation-recovery';
const PROTECTED_OIDC_SUBJECT = githubOidcEnvironmentSubject(PROTECTED_ENVIRONMENT);
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const ATTEMPT = /^[1-9][0-9]{0,2}$/u;
const ACCOUNT_ID = /^[0-9]{12}$/u;
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$/u;
const ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/([A-Za-z0-9+=,.@_/-]{1,512})$/u;
const POLICY_ARN = /^arn:aws:iam::([0-9]{12}):policy\/([A-Za-z0-9+=,.@_/-]{1,512})$/u;
const POLICY_NAME = /^[\w+=,.@-]{1,128}$/u;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ARTIFACT_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const REVIEWER_ALIAS = /^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u;
const PHASES = Object.freeze(['ROLLBACK_CHECK', 'ROLLBACK_RESILIENCE']);
const ORIGINAL_CONCLUSIONS = Object.freeze(['FAILURE', 'CANCELLED', 'TIMED_OUT']);
const ORIGINAL_RUN_CONCLUSIONS = Object.freeze({
  FAILURE: 'failure',
  CANCELLED: 'cancelled',
  TIMED_OUT: 'timed_out',
});
const ORIGINAL_PHASE_JOB_NAMES = Object.freeze({
  ROLLBACK_CHECK: '20 Rollback and re-promotion rehearsal',
  ROLLBACK_RESILIENCE:
    '21 Protected rollback resilience / RB-E7-06 and RB-E7-08 protected AWS rehearsal',
});
const RECOVERY_MODES = Object.freeze(['TERMINAL_RESUMED', 'FORWARD_CONVERGED']);
const PROHIBITED_ACTIONS = Object.freeze([
  'FENCE',
  'PUBLISH',
  'ROLLBACK_TO_PREVIOUS',
  'DELETE_BEFORE_PRESERVATION',
]);
const MAX_PARAMETER_BYTES = 3900;
const MAX_PARAMETERS = 155;
const MAX_DOCUMENT_BYTES = 32 * 1024 * 1024;
const MAX_REVIEW_RESPONSE_BYTES = 1024 * 1024;
const PRESERVATION_FILES = Object.freeze([
  Object.freeze({ label: 'intent', path: 'release-reconciliation-intent.json' }),
  Object.freeze({ label: 'receipt', path: 'release-reconciliation-receipt.json' }),
  Object.freeze({ label: 'outcome', path: 'release-reconciliation-recovery-outcome.json' }),
  Object.freeze({
    label: 'snapshot',
    path: 'release-reconciliation-recovery-journal-snapshot.json',
  }),
  Object.freeze({
    label: 'recoveryRoleAuthority',
    path: 'stage7-release-reconciliation-recovery-role-effective-permissions.json',
  }),
]);

export const STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT = Object.freeze({
  schemaVersion: 1,
  workflowPath: WORKFLOW_PATH,
  protectedEnvironment: PROTECTED_ENVIRONMENT,
  policy: 'TERMINAL_RESUME_OR_FORWARD_CANDIDATE_N_ONLY',
  prohibitedActions: PROHIBITED_ACTIONS,
  preservationArtifactPrefix: 'stage7-release-reconciliation-recovery-preservation',
  closureArtifactPrefix: 'stage7-release-reconciliation-recovery-closure',
  sourceRunAttempt: 1,
  requiredResidualCount: 0,
  preservationFiles: Object.freeze([
    ...PRESERVATION_FILES.map(({ path }) => path),
    'release-reconciliation-recovery-preservation-index.json',
  ]),
  sharedAdapters: Object.freeze({
    rollbackExport: 'executeVersionedRollbackRecovery',
    rollbackDirection: 'REPROMOTE_CANDIDATE',
    rollbackActorProperty: 'recoveryActor',
    rollbackIntentProperty: 'recoveryIntent',
    smokeActorFlag: '--reconciliation-recovery-actor',
    smokeActorOutputField: 'reconciliationRecoveryActorSha256',
    smokeRoleSource: 'config.aws.roles.readRoleArn',
  }),
});
export const RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME =
  'stage7-release-reconciliation-recovery-role-effective-permissions.json';
export const RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_KIND =
  'STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS';
export const RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS = Object.freeze([
  'reconciliationRecoveryRoleArn',
  'reconciliationRecoveryPermissionsBoundaryArn',
  'reconciliationRecoveryRoleEffectivePermissionsRawSha256',
  'reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256',
  'reconciliationRecoveryRoleEffectivePermissionsSha256',
  'reconciliationRecoveryRoleEffectivePolicyProjectionSha256',
]);

export class Stage7ReleaseReconciliationRecoveryError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseReconciliationRecoveryError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseReconciliationRecoveryError(
    code,
    cause === undefined ? undefined : { cause },
  );
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sameObject = (left, right) => canonicalJson(left) === canonicalJson(right);
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const utc = (value) => {
  if (!UTC.test(value ?? '') || Number.isNaN(Date.parse(value))) return false;
  return new Date(value).toISOString() === value;
};
const normalizeApiUtc = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return null;
  const normalized = new Date(value).toISOString();
  return normalized.startsWith(value.replace(/Z$/u, '')) ? normalized : null;
};
const withoutDigest = (value, key) => {
  const body = { ...value };
  delete body[key];
  return body;
};
const recoveryRoot = (source) =>
  `/checkout/stage7/rollback/${source.candidateSha}/release-reconciliation/${source.runId}`;
const preservationArtifactName = (actor) =>
  `${STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT.preservationArtifactPrefix}-${actor.recoveryRun.runId}-${actor.recoveryRun.runAttempt}`;
const closureArtifactName = (actor) =>
  `${STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT.closureArtifactPrefix}-${actor.recoveryRun.runId}-${actor.recoveryRun.runAttempt}`;

const recoveryWorkflowContext = ({ environmentVariables, source, recoveryRoleArn }) => {
  const role = ROLE_ARN.exec(recoveryRoleArn ?? '');
  const runId = environmentVariables?.GITHUB_RUN_ID;
  const runAttemptText = environmentVariables?.GITHUB_RUN_ATTEMPT;
  const runAttempt = Number(runAttemptText);
  const workflowRef = `${REPOSITORY}/${WORKFLOW_PATH}@${REF}`;
  const roleSessionName = `e7-reconciliation-recovery-${runId}-${runAttemptText}`;
  const oidcSubject = PROTECTED_OIDC_SUBJECT;
  if (
    role === null ||
    environmentVariables?.GITHUB_REPOSITORY !== REPOSITORY ||
    environmentVariables?.GITHUB_WORKFLOW_REF !== workflowRef ||
    environmentVariables?.GITHUB_REF !== REF ||
    environmentVariables?.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    environmentVariables?.STAGE7_PROTECTED_ENVIRONMENT !== PROTECTED_ENVIRONMENT ||
    environmentVariables?.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN !== recoveryRoleArn ||
    environmentVariables?.STAGE7_AWS_ACCOUNT_ID !== role[1] ||
    environmentVariables?.STAGE7_RECOVERY_CANDIDATE_SHA !== source.candidateSha ||
    !RUN_ID.test(runId ?? '') ||
    !ATTEMPT.test(runAttemptText ?? '') ||
    !Number.isSafeInteger(runAttempt) ||
    !RUN_ID.test(environmentVariables?.GITHUB_ACTOR_ID ?? '') ||
    !/^[0-9a-f]{40}$/u.test(environmentVariables?.GITHUB_SHA ?? '') ||
    roleSessionName.length > 64
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_WORKFLOW_CONTEXT_INVALID');
  }
  return {
    recoveryRun: {
      repository: REPOSITORY,
      workflowPath: WORKFLOW_PATH,
      workflowRef,
      ref: REF,
      eventName: 'workflow_dispatch',
      runId,
      runAttempt,
      actorId: environmentVariables.GITHUB_ACTOR_ID,
      controlSha: environmentVariables.GITHUB_SHA,
      protectedEnvironment: PROTECTED_ENVIRONMENT,
      candidateSha: source.candidateSha,
    },
    authority: {
      accountId: role[1],
      region: environmentVariables.AWS_REGION,
      recoveryRoleArn,
      roleSessionName,
      oidcSubject,
    },
  };
};

const configForRecovery = ({ intent, configSource }) => {
  validateReleaseReconciliationIntent(intent);
  const parsed = parseReleaseReconciliationRecoveryJson(
    configSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_CONFIG_INVALID',
  );
  const config = parsed.value;
  try {
    validateStage7Config(config, { now: new Date(config?.window?.startsAtUtc) });
  } catch (error) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CONFIG_INVALID', error);
  }
  const binding = intent.bindings.find(({ label }) => label === 'config');
  if (
    binding?.sourceType !== 'JSON' ||
    binding.path !== 'stage7-config.json' ||
    binding.rawSha256 !== sha256(parsed.bytes) ||
    binding.canonicalSha256 !== objectSha256(config) ||
    binding.bytes !== parsed.bytes.length ||
    intent.source.configSha256 !== objectSha256(config) ||
    config.aws.accountId !== intent.authority.accountId ||
    config.aws.region !== intent.authority.region ||
    config.aws.roles.rollbackRoleArn !== intent.authority.rollbackRoleArn ||
    config.environment !== 'assessment-release'
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CONFIG_BINDING_INVALID');
  }
  return { config, binding };
};

export const createReleaseReconciliationRecoveryTrustPolicy = (accountId) => {
  if (!ACCOUNT_ID.test(accountId ?? '')) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_TRUST_POLICY_INPUT_INVALID');
  }
  return {
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
            'token.actions.githubusercontent.com:sub': PROTECTED_OIDC_SUBJECT,
          },
        },
      },
    ],
  };
};

const bindingByLabel = (intent, label) =>
  intent.bindings.find((binding) => binding.label === label);
const validateRecoveryPolicyInputDocument = ({ value, rawSource, binding, validator, code }) => {
  const raw = Buffer.isBuffer(rawSource)
    ? Buffer.from(rawSource)
    : Buffer.from(rawSource ?? '', 'utf8');
  try {
    validator(value);
  } catch (error) {
    fail(code, error);
  }
  if (
    binding?.sourceType !== 'JSON' ||
    binding.rawSha256 !== sha256(raw) ||
    binding.canonicalSha256 !== objectSha256(value) ||
    binding.bytes !== raw.length
  ) {
    fail(code);
  }
};
const validateRecoveryVersionedResources = (resources, code) => {
  const validLambda = (value) =>
    object(value) &&
    Object.keys(value).every((key) =>
      ['functionName', 'aliasName', 'version', 'codeSha256'].includes(key),
    ) &&
    /^[A-Za-z0-9-_]{1,64}$/u.test(value.functionName ?? '') &&
    /^[A-Za-z0-9-_]{1,128}$/u.test(value.aliasName ?? '') &&
    /^(?:[1-9][0-9]{0,9})$/u.test(value.version ?? '');
  if (
    !exactKeys(resources, ['api', 'worker', 'web']) ||
    !validLambda(resources.api) ||
    !validLambda(resources.worker) ||
    !object(resources.web) ||
    !Object.keys(resources.web).every((key) =>
      ['bucketName', 'distributionId', 'objects', 'mutableInvalidationPaths'].includes(key),
    ) ||
    !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(resources.web.bucketName ?? '') ||
    !/^[A-Z0-9]{8,32}$/u.test(resources.web.distributionId ?? '') ||
    !Array.isArray(resources.web.objects) ||
    resources.web.objects.length !== 2 ||
    resources.web.objects
      .map(({ key }) => key)
      .toSorted()
      .join('\0') !== ['index.html', 'public-config.json'].join('\0') ||
    resources.web.objects.some(
      (entry) =>
        !object(entry) ||
        typeof entry.versionId !== 'string' ||
        entry.versionId.length < 1 ||
        !SHA256.test(entry.contentSha256 ?? '') ||
        !Number.isSafeInteger(entry.bytes) ||
        entry.bytes < 1,
    )
  ) {
    fail(code);
  }
  return resources;
};

export const createReleaseReconciliationRecoveryBasePolicy = ({
  accountId,
  awsRegion,
  recoveryRoleArn,
  permissionsBoundaryArn,
}) => {
  const role = ROLE_ARN.exec(recoveryRoleArn ?? '');
  const boundary = POLICY_ARN.exec(permissionsBoundaryArn ?? '');
  if (
    !ACCOUNT_ID.test(accountId ?? '') ||
    !REGION.test(awsRegion ?? '') ||
    role?.[1] !== accountId ||
    boundary?.[1] !== accountId
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_BASE_POLICY_INPUT_INVALID');
  }
  const releasePrefix = 'checkout-assessment-release';
  const ssmArn = (parameterPath) =>
    `arn:aws:ssm:${awsRegion}:${accountId}:parameter${parameterPath}`;
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AuditOnlyThisRecoveryRole',
        Effect: 'Allow',
        Action: [
          'iam:GetRole',
          'iam:GetRolePolicy',
          'iam:ListAttachedRolePolicies',
          'iam:ListRolePolicies',
        ],
        Resource: recoveryRoleArn,
      },
      {
        Sid: 'AuditOnlyRecoveryBoundary',
        Effect: 'Allow',
        Action: ['iam:GetPolicy', 'iam:GetPolicyVersion'],
        Resource: permissionsBoundaryArn,
      },
      {
        Sid: 'ReadExactVersionedReleaseState',
        Effect: 'Allow',
        Action: ['cloudformation:DescribeStacks'],
        Resource: ['api', 'data', 'web'].map(
          (component) =>
            `arn:aws:cloudformation:${awsRegion}:${accountId}:stack/${releasePrefix}-${component}/*`,
        ),
      },
      {
        Sid: 'ReadAndRepromoteExactLambdaAliases',
        Effect: 'Allow',
        Action: ['lambda:GetAlias', 'lambda:GetFunctionConfiguration', 'lambda:UpdateAlias'],
        Resource: `arn:aws:lambda:${awsRegion}:${accountId}:function:${releasePrefix}-*`,
      },
      {
        Sid: 'ReadExactForwardOnlyData',
        Effect: 'Allow',
        Action: ['dynamodb:DescribeTable', 'dynamodb:GetItem', 'dynamodb:Query'],
        Resource: [
          `arn:aws:dynamodb:${awsRegion}:${accountId}:table/${releasePrefix}-catalog`,
          `arn:aws:dynamodb:${awsRegion}:${accountId}:table/${releasePrefix}-checkout`,
          `arn:aws:dynamodb:${awsRegion}:${accountId}:table/${releasePrefix}-checkout/index/GSI2`,
        ],
      },
      {
        Sid: 'ReadExactVersionedWebObjects',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:GetObjectVersion'],
        Resource: `arn:aws:s3:::${releasePrefix}-web*/*`,
      },
      {
        Sid: 'ListExactVersionedWebBuckets',
        Effect: 'Allow',
        Action: 's3:ListBucketVersions',
        Resource: `arn:aws:s3:::${releasePrefix}-web*`,
      },
      {
        Sid: 'RepromoteExactMutableWebObjects',
        Effect: 'Allow',
        Action: 's3:PutObject',
        Resource: `arn:aws:s3:::${releasePrefix}-web*/*`,
      },
      {
        Sid: 'InvalidateExactCandidateDistributions',
        Effect: 'Allow',
        Action: ['cloudfront:CreateInvalidation', 'cloudfront:GetInvalidation'],
        Resource: `arn:aws:cloudfront::${accountId}:distribution/*`,
      },
      {
        Sid: 'ReadExactRecoveryAndCompletionGuards',
        Effect: 'Allow',
        Action: ['ssm:GetParameter', 'ssm:GetParametersByPath'],
        Resource: [
          ssmArn('/checkout/stage7/rollback/*'),
          ssmArn(`${RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT}/*`),
          ssmArn(`${RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT}/*`),
        ],
      },
      {
        Sid: 'WriteOnlyImmutableOriginalRecoveryJournal',
        Effect: 'Allow',
        Action: 'ssm:PutParameter',
        Resource: ssmArn('/checkout/stage7/rollback/*/release-reconciliation/*'),
        Condition: { StringEquals: { 'ssm:Overwrite': 'false' } },
      },
      {
        Sid: 'ReadCallerIdentity',
        Effect: 'Allow',
        Action: 'sts:GetCallerIdentity',
        Resource: '*',
      },
    ],
  };
};

export const createReleaseReconciliationRecoverySessionPolicy = ({
  intent,
  recoveryRoleArn,
  permissionsBoundaryArn,
  candidateRecordSource,
  previousManifestSource,
}) => {
  validateReleaseReconciliationIntent(intent);
  const recoveryRole = ROLE_ARN.exec(recoveryRoleArn ?? '');
  const boundary = POLICY_ARN.exec(permissionsBoundaryArn ?? '');
  if (
    recoveryRole?.[1] !== intent.authority.accountId ||
    boundary?.[1] !== intent.authority.accountId ||
    [intent.authority.rollbackRoleArn, intent.authority.journalRoleArn].includes(recoveryRoleArn)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_POLICY_INPUT_INVALID');
  }
  const candidateDocument = parseReleaseReconciliationRecoveryJson(
    candidateRecordSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_POLICY_CANDIDATE_INVALID',
  );
  const previousDocument = parseReleaseReconciliationRecoveryJson(
    previousManifestSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_POLICY_PREVIOUS_INVALID',
  );
  const previousManifest = previousDocument.value;
  const candidateRecord = candidateDocument.value;
  validateRecoveryPolicyInputDocument({
    value: previousManifest,
    rawSource: previousDocument.bytes,
    binding: bindingByLabel(intent, 'previousReleaseManifest'),
    validator: (value) =>
      validateRecoveryVersionedResources(
        value?.resources,
        'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_POLICY_PREVIOUS_INVALID',
      ),
    code: 'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_POLICY_PREVIOUS_INVALID',
  });
  validateRecoveryPolicyInputDocument({
    value: candidateRecord,
    rawSource: candidateDocument.bytes,
    binding: bindingByLabel(intent, 'candidateRecord'),
    validator: (value) =>
      validateRecoveryVersionedResources(
        value?.resources,
        'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_POLICY_CANDIDATE_INVALID',
      ),
    code: 'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_POLICY_CANDIDATE_INVALID',
  });
  const accountId = intent.authority.accountId;
  const region = intent.authority.region;
  const sources = [candidateRecord.resources, previousManifest.resources];
  const lambdaResources = [
    ...new Set(
      sources
        .flatMap(({ api, worker }) => [api, worker])
        .flatMap(({ functionName, aliasName, version }) => {
          const base = `arn:aws:lambda:${region}:${accountId}:function:${functionName}`;
          return [base, `${base}:${aliasName}`, `${base}:${version}`];
        }),
    ),
  ].toSorted();
  const buckets = [...new Set(sources.map(({ web }) => web.bucketName))].toSorted();
  const objectResources = [
    ...new Set(
      sources.flatMap(({ web }) =>
        web.objects.map(({ key }) => `arn:aws:s3:::${web.bucketName}/${key}`),
      ),
    ),
  ].toSorted();
  const distributionResources = [
    ...new Set(
      sources.map(
        ({ web }) => `arn:aws:cloudfront::${accountId}:distribution/${web.distributionId}`,
      ),
    ),
  ].toSorted();
  const recoveryRootPath = recoveryRoot(intent.source);
  const candidateRootPath = `/checkout/stage7/rollback/${intent.source.candidateSha}`;
  const ssmArn = (parameterPath) => `arn:aws:ssm:${region}:${accountId}:parameter${parameterPath}`;
  return {
    Version: '2012-10-17',
    Statement: [
      {
        Sid: 'AuditOnlyThisRecoveryRole',
        Effect: 'Allow',
        Action: [
          'iam:GetRole',
          'iam:GetRolePolicy',
          'iam:ListAttachedRolePolicies',
          'iam:ListRolePolicies',
        ],
        Resource: recoveryRoleArn,
      },
      {
        Sid: 'AuditOnlyRecoveryBoundary',
        Effect: 'Allow',
        Action: ['iam:GetPolicy', 'iam:GetPolicyVersion'],
        Resource: permissionsBoundaryArn,
      },
      {
        Sid: 'ReadExactVersionedReleaseState',
        Effect: 'Allow',
        Action: ['cloudformation:DescribeStacks'],
        Resource: ['api', 'data', 'web'].map(
          (component) =>
            `arn:aws:cloudformation:${region}:${accountId}:stack/checkout-assessment-release-${component}/*`,
        ),
      },
      {
        Sid: 'ReadAndRepromoteExactLambdaAliases',
        Effect: 'Allow',
        Action: ['lambda:GetAlias', 'lambda:GetFunctionConfiguration', 'lambda:UpdateAlias'],
        Resource: lambdaResources,
      },
      {
        Sid: 'ReadExactForwardOnlyData',
        Effect: 'Allow',
        Action: ['dynamodb:DescribeTable', 'dynamodb:GetItem', 'dynamodb:Query'],
        Resource: [
          `arn:aws:dynamodb:${region}:${accountId}:table/checkout-assessment-release-catalog`,
          `arn:aws:dynamodb:${region}:${accountId}:table/checkout-assessment-release-checkout`,
          `arn:aws:dynamodb:${region}:${accountId}:table/checkout-assessment-release-checkout/index/GSI2`,
        ],
      },
      {
        Sid: 'ReadExactVersionedWebObjects',
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:GetObjectVersion'],
        Resource: objectResources,
      },
      {
        Sid: 'ListExactVersionedWebBuckets',
        Effect: 'Allow',
        Action: 's3:ListBucketVersions',
        Resource: buckets.map((bucket) => `arn:aws:s3:::${bucket}`),
      },
      {
        Sid: 'RepromoteExactMutableWebObjects',
        Effect: 'Allow',
        Action: 's3:PutObject',
        Resource: objectResources,
      },
      {
        Sid: 'InvalidateExactCandidateDistributions',
        Effect: 'Allow',
        Action: ['cloudfront:CreateInvalidation', 'cloudfront:GetInvalidation'],
        Resource: distributionResources,
      },
      {
        Sid: 'ReadExactRecoveryAndCompletionGuards',
        Effect: 'Allow',
        Action: ['ssm:GetParameter', 'ssm:GetParametersByPath'],
        Resource: [
          ssmArn(candidateRootPath),
          ssmArn(`${candidateRootPath}/*`),
          ssmArn(`${RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT}/${intent.source.candidateSha}`),
          ssmArn(`${RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT}/${intent.source.candidateSha}/*`),
          ssmArn(`${RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT}/${intent.source.candidateSha}`),
          ssmArn(
            `${RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT}/${intent.source.candidateSha}/*`,
          ),
        ],
      },
      {
        Sid: 'WriteOnlyImmutableOriginalRecoveryJournal',
        Effect: 'Allow',
        Action: 'ssm:PutParameter',
        Resource: [ssmArn(recoveryRootPath), ssmArn(`${recoveryRootPath}/*`)],
        Condition: { StringEquals: { 'ssm:Overwrite': 'false' } },
      },
      {
        Sid: 'ReadCallerIdentity',
        Effect: 'Allow',
        Action: 'sts:GetCallerIdentity',
        Resource: '*',
      },
    ],
  };
};

const policyValues = (value) => (Array.isArray(value) ? value : [value]);
const baseResourceCovers = (baseResource, sessionResource) => {
  if (baseResource === '*' || baseResource === sessionResource) return true;
  if (!baseResource.includes('*')) return false;
  const basePattern = new RegExp(
    `^${baseResource.replace(/[.+?^${}()|[\]\\]/gu, '\\$&').replaceAll('*', '.*')}$`,
    'u',
  );
  if (!sessionResource.includes('*')) return basePattern.test(sessionResource);
  const wildcardIndex = sessionResource.indexOf('*');
  if (wildcardIndex !== sessionResource.length - 1) return false;
  const prefix = sessionResource.slice(0, -1);
  return basePattern.test(prefix) && basePattern.test(`${prefix}E7_SUBSET_SENTINEL`);
};

export const validateReleaseReconciliationRecoverySessionPolicySubset = ({
  basePolicy,
  sessionPolicy,
}) => {
  if (
    !object(basePolicy) ||
    !object(sessionPolicy) ||
    basePolicy.Version !== '2012-10-17' ||
    sessionPolicy.Version !== '2012-10-17' ||
    !Array.isArray(basePolicy.Statement) ||
    !Array.isArray(sessionPolicy.Statement) ||
    basePolicy.Statement.length !== 12 ||
    sessionPolicy.Statement.length !== 12
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SESSION_POLICY_SUBSET_INVALID');
  }
  const baseBySid = new Map(basePolicy.Statement.map((statement) => [statement.Sid, statement]));
  if (
    baseBySid.size !== basePolicy.Statement.length ||
    sessionPolicy.Statement.some((statement) => {
      const base = baseBySid.get(statement?.Sid);
      if (
        !object(base) ||
        statement.Effect !== 'Allow' ||
        base.Effect !== 'Allow' ||
        !sameObject(statement.Condition ?? null, base.Condition ?? null)
      ) {
        return true;
      }
      const baseActions = new Set(policyValues(base.Action));
      const sessionActions = policyValues(statement.Action);
      const baseResources = policyValues(base.Resource);
      const sessionResources = policyValues(statement.Resource);
      return (
        sessionActions.length < 1 ||
        sessionActions.some((action) => !baseActions.has(action)) ||
        sessionResources.length < 1 ||
        sessionResources.some(
          (resource) =>
            typeof resource !== 'string' ||
            !baseResources.some(
              (baseResource) =>
                typeof baseResource === 'string' && baseResourceCovers(baseResource, resource),
            ),
        )
      );
    })
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SESSION_POLICY_NOT_SUBSET');
  }
  return {
    decision: 'EXACT_SESSION_POLICY_SUBSET_OF_FROZEN_BASE',
    basePolicySha256: objectSha256(basePolicy),
    sessionPolicySha256: objectSha256(sessionPolicy),
    subsetSha256: objectSha256({
      decision: 'EXACT_SESSION_POLICY_SUBSET_OF_FROZEN_BASE',
      basePolicySha256: objectSha256(basePolicy),
      sessionPolicySha256: objectSha256(sessionPolicy),
    }),
  };
};

const RECOVERY_ROLE_SOURCE_OPERATIONS = Object.freeze([
  'GET_BOUNDARY_POLICY',
  'GET_BOUNDARY_POLICY_VERSION',
  'GET_ROLE',
  'GET_ROLE_POLICY',
  'LIST_ATTACHED_ROLE_POLICIES',
  'LIST_ROLE_POLICIES',
]);
const recoveryRoleStableProjection = (value) => ({
  repository: value.repository,
  awsRegion: value.awsRegion,
  role: value.role,
  permissionProfile: value.permissionProfile,
  basePolicy: value.basePolicy,
  inlinePolicies: value.inlinePolicies,
  attachedPolicies: value.attachedPolicies,
  permissionsBoundary: value.permissionsBoundary,
});

export const validateReleaseReconciliationRecoveryRoleEffectivePermissions = (
  value,
  { roleArn, permissionsBoundaryArn, basePolicy } = {},
) => {
  const role = ROLE_ARN.exec(value?.role?.arn ?? '');
  const boundary = POLICY_ARN.exec(value?.permissionsBoundary?.policyArn ?? '');
  const expectedTrust =
    role === null ? null : createReleaseReconciliationRecoveryTrustPolicy(role[1]);
  const expectedBasePolicy =
    role === null || boundary === null || !REGION.test(value?.awsRegion ?? '')
      ? null
      : createReleaseReconciliationRecoveryBasePolicy({
          accountId: role[1],
          awsRegion: value.awsRegion,
          recoveryRoleArn: value.role.arn,
          permissionsBoundaryArn: value.permissionsBoundary.policyArn,
        });
  const inline = value?.inlinePolicies?.[0];
  const expectedSourceKeys = RECOVERY_ROLE_SOURCE_OPERATIONS.join('\0');
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'repository',
      'awsRegion',
      'role',
      'permissionProfile',
      'basePolicy',
      'basePolicySha256',
      'inlinePolicies',
      'attachedPolicies',
      'permissionsBoundary',
      'sourceBindings',
      'effectivePolicyProjectionSha256',
      'containsSensitiveData',
      'effectivePermissionsSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_KIND ||
    value.status !== 'PASS' ||
    value.repository !== REPOSITORY ||
    !REGION.test(value.awsRegion ?? '') ||
    !exactKeys(value.role, [
      'arn',
      'path',
      'name',
      'id',
      'createdAtUtc',
      'maxSessionDuration',
      'trustPolicy',
      'trustPolicySha256',
    ]) ||
    role === null ||
    typeof value.role.path !== 'string' ||
    !value.role.arn.endsWith(`/${value.role.name}`) ||
    typeof value.role.id !== 'string' ||
    value.role.id.length < 8 ||
    !utc(value.role.createdAtUtc) ||
    value.role.maxSessionDuration !== 3600 ||
    !sameObject(value.role.trustPolicy, expectedTrust) ||
    value.role.trustPolicySha256 !== objectSha256(value.role.trustPolicy) ||
    !exactKeys(value.permissionProfile, [
      'capability',
      'direction',
      'journalWrite',
      'cleanupRole',
      'rollbackToPreviousAllowed',
      'fenceWriteAllowed',
      'publicationWriteAllowed',
      'deleteParameterAllowed',
    ]) ||
    value.permissionProfile.capability !==
      'REPROMOTE_CANDIDATE_BASE_ENVELOPE_AND_IMMUTABLE_RECONCILIATION_JOURNAL' ||
    value.permissionProfile.direction !== 'REPROMOTE_CANDIDATE' ||
    value.permissionProfile.journalWrite !==
      'PUT_OVERWRITE_FALSE_RELEASE_RECONCILIATION_ROOT_SESSION_NARROWED' ||
    value.permissionProfile.cleanupRole !== 'SEPARATE_RELEASE_JOURNAL_CLEANUP_ROLE' ||
    [
      value.permissionProfile.rollbackToPreviousAllowed,
      value.permissionProfile.fenceWriteAllowed,
      value.permissionProfile.publicationWriteAllowed,
      value.permissionProfile.deleteParameterAllowed,
    ].some((entry) => entry !== false) ||
    !object(value.basePolicy) ||
    !sameObject(value.basePolicy, expectedBasePolicy) ||
    value.basePolicy.Version !== '2012-10-17' ||
    !Array.isArray(value.basePolicy.Statement) ||
    value.basePolicy.Statement.length !== 12 ||
    value.basePolicy.Statement.some(
      (statement) =>
        statement.Effect !== 'Allow' ||
        canonicalJson(statement.Action).includes('Delete') ||
        canonicalJson(statement).includes('ROLLBACK_TO_PREVIOUS') ||
        (canonicalJson(statement).includes('/release-fence/') &&
          canonicalJson(statement.Action).includes('PutParameter')),
    ) ||
    value.basePolicySha256 !== objectSha256(value.basePolicy) ||
    !Array.isArray(value.inlinePolicies) ||
    value.inlinePolicies.length !== 1 ||
    !exactKeys(inline, ['policyName', 'policyDocument', 'policyDocumentSha256']) ||
    inline.policyName !== 'stage7-release-reconciliation-recovery' ||
    !sameObject(inline.policyDocument, value.basePolicy) ||
    inline.policyDocumentSha256 !== value.basePolicySha256 ||
    !Array.isArray(value.attachedPolicies) ||
    value.attachedPolicies.length !== 0 ||
    !exactKeys(value.permissionsBoundary, [
      'policyArn',
      'defaultVersionId',
      'policyDocument',
      'policyDocumentSha256',
    ]) ||
    boundary?.[1] !== role[1] ||
    !/^v[1-9][0-9]{0,3}$/u.test(value.permissionsBoundary.defaultVersionId ?? '') ||
    !sameObject(value.permissionsBoundary.policyDocument, value.basePolicy) ||
    value.permissionsBoundary.policyDocumentSha256 !== value.basePolicySha256 ||
    !Array.isArray(value.sourceBindings) ||
    value.sourceBindings.length !== RECOVERY_ROLE_SOURCE_OPERATIONS.length ||
    value.sourceBindings
      .map(({ operation }) => operation)
      .toSorted()
      .join('\0') !== expectedSourceKeys ||
    value.sourceBindings.some(
      (binding) =>
        !exactKeys(binding, ['operation', 'target', 'rawSha256', 'canonicalSha256', 'bytes']) ||
        !RECOVERY_ROLE_SOURCE_OPERATIONS.includes(binding.operation) ||
        typeof binding.target !== 'string' ||
        binding.target.length < 1 ||
        !SHA256.test(binding.rawSha256 ?? '') ||
        !SHA256.test(binding.canonicalSha256 ?? '') ||
        !Number.isSafeInteger(binding.bytes) ||
        binding.bytes < 2 ||
        binding.bytes > MAX_DOCUMENT_BYTES,
    ) ||
    value.effectivePolicyProjectionSha256 !== objectSha256(recoveryRoleStableProjection(value)) ||
    value.containsSensitiveData !== false ||
    value.effectivePermissionsSha256 !==
      objectSha256(withoutDigest(value, 'effectivePermissionsSha256')) ||
    (roleArn !== undefined && value.role.arn !== roleArn) ||
    (permissionsBoundaryArn !== undefined &&
      value.permissionsBoundary.policyArn !== permissionsBoundaryArn) ||
    (basePolicy !== undefined && !sameObject(value.basePolicy, basePolicy))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_INVALID');
  }
  return value;
};

export const parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource = (
  source,
  expected = {},
) => {
  const document = parseReleaseReconciliationRecoveryJson(
    source,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_SOURCE_INVALID',
  );
  return {
    value: validateReleaseReconciliationRecoveryRoleEffectivePermissions(document.value, expected),
    rawSha256: sha256(document.bytes),
    canonicalSha256: objectSha256(document.value),
    bytes: document.bytes.length,
  };
};

const iamPolicyDocument = (value, code) => {
  if (object(value)) return value;
  if (typeof value !== 'string' || value.length < 2 || value.length > MAX_DOCUMENT_BYTES) {
    fail(code);
  }
  try {
    return parseStrictJsonSource(Buffer.from(decodeURIComponent(value), 'utf8'), {
      scanForbiddenData: false,
    });
  } catch (error) {
    fail(code, error);
  }
};

const rawIamResponse = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  const document = parseReleaseReconciliationRecoveryJson(bytes, code);
  return { ...document, rawSha256: sha256(bytes), canonicalSha256: objectSha256(document.value) };
};

export const captureReleaseReconciliationRecoveryRoleEffectivePermissions = ({
  expectedRoleArn,
  expectedPermissionsBoundaryArn,
  awsRegion,
  basePolicy,
  callAwsRaw,
}) => {
  const role = ROLE_ARN.exec(expectedRoleArn ?? '');
  const boundary = POLICY_ARN.exec(expectedPermissionsBoundaryArn ?? '');
  const roleName = role?.[2]?.split('/').at(-1);
  if (
    typeof callAwsRaw !== 'function' ||
    role === null ||
    boundary?.[1] !== role[1] ||
    !REGION.test(awsRegion ?? '') ||
    !POLICY_NAME.test(roleName ?? '') ||
    !object(basePolicy) ||
    basePolicy.Version !== '2012-10-17' ||
    !Array.isArray(basePolicy.Statement) ||
    basePolicy.Statement.length !== 12 ||
    !sameObject(
      basePolicy,
      createReleaseReconciliationRecoveryBasePolicy({
        accountId: role[1],
        awsRegion,
        recoveryRoleArn: expectedRoleArn,
        permissionsBoundaryArn: expectedPermissionsBoundaryArn,
      }),
    )
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_INPUT_INVALID');
  }
  const call = (operation, target, arguments_) => {
    let source;
    try {
      source = callAwsRaw(arguments_);
    } catch (error) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_AWS_FAILED', error);
    }
    const response = rawIamResponse(
      source,
      'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_RESPONSE_INVALID',
    );
    return {
      ...response,
      binding: {
        operation,
        target,
        rawSha256: response.rawSha256,
        canonicalSha256: response.canonicalSha256,
        bytes: response.bytes.length,
      },
    };
  };
  const getRole = call('GET_ROLE', expectedRoleArn, ['iam', 'get-role', '--role-name', roleName]);
  const listRolePolicies = call('LIST_ROLE_POLICIES', expectedRoleArn, [
    'iam',
    'list-role-policies',
    '--role-name',
    roleName,
    '--page-size',
    '100',
    '--max-items',
    '100',
  ]);
  const inlinePolicyNames = listRolePolicies.value?.PolicyNames;
  if (
    !Array.isArray(inlinePolicyNames) ||
    inlinePolicyNames.length !== 1 ||
    inlinePolicyNames[0] !== 'stage7-release-reconciliation-recovery' ||
    listRolePolicies.value.NextToken !== undefined ||
    listRolePolicies.value.IsTruncated === true
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_INLINE_SET_INVALID');
  }
  const getRolePolicy = call('GET_ROLE_POLICY', `${expectedRoleArn}/${inlinePolicyNames[0]}`, [
    'iam',
    'get-role-policy',
    '--role-name',
    roleName,
    '--policy-name',
    inlinePolicyNames[0],
  ]);
  const listAttached = call('LIST_ATTACHED_ROLE_POLICIES', expectedRoleArn, [
    'iam',
    'list-attached-role-policies',
    '--role-name',
    roleName,
    '--page-size',
    '100',
    '--max-items',
    '100',
  ]);
  if (
    !Array.isArray(listAttached.value?.AttachedPolicies) ||
    listAttached.value.AttachedPolicies.length !== 0 ||
    listAttached.value.NextToken !== undefined ||
    listAttached.value.IsTruncated === true
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_ATTACHED_SET_INVALID');
  }
  const getPolicy = call('GET_BOUNDARY_POLICY', expectedPermissionsBoundaryArn, [
    'iam',
    'get-policy',
    '--policy-arn',
    expectedPermissionsBoundaryArn,
  ]);
  const defaultVersionId = getPolicy.value?.Policy?.DefaultVersionId;
  if (!/^v[1-9][0-9]{0,3}$/u.test(defaultVersionId ?? '')) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_BOUNDARY_INVALID');
  }
  const getPolicyVersion = call(
    'GET_BOUNDARY_POLICY_VERSION',
    `${expectedPermissionsBoundaryArn}:${defaultVersionId}`,
    [
      'iam',
      'get-policy-version',
      '--policy-arn',
      expectedPermissionsBoundaryArn,
      '--version-id',
      defaultVersionId,
    ],
  );
  const roleValue = getRole.value?.Role;
  const trustPolicy = iamPolicyDocument(
    roleValue?.AssumeRolePolicyDocument,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_TRUST_INVALID',
  );
  const inlineDocument = iamPolicyDocument(
    getRolePolicy.value?.PolicyDocument,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_INLINE_INVALID',
  );
  const boundaryDocument = iamPolicyDocument(
    getPolicyVersion.value?.PolicyVersion?.Document,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_BOUNDARY_INVALID',
  );
  const createdAtUtc = normalizeApiUtc(roleValue?.CreateDate);
  if (
    roleValue?.Arn !== expectedRoleArn ||
    roleValue?.RoleName !== roleName ||
    typeof roleValue?.Path !== 'string' ||
    typeof roleValue?.RoleId !== 'string' ||
    roleValue.RoleId.length < 8 ||
    createdAtUtc === null ||
    roleValue?.MaxSessionDuration !== 3600 ||
    roleValue?.PermissionsBoundary?.PermissionsBoundaryArn !== expectedPermissionsBoundaryArn ||
    roleValue?.PermissionsBoundary?.PermissionsBoundaryType !== 'Policy' ||
    getRolePolicy.value?.RoleName !== roleName ||
    getRolePolicy.value?.PolicyName !== inlinePolicyNames[0] ||
    getPolicy.value?.Policy?.Arn !== expectedPermissionsBoundaryArn ||
    !sameObject(trustPolicy, createReleaseReconciliationRecoveryTrustPolicy(role[1])) ||
    !sameObject(inlineDocument, basePolicy) ||
    !sameObject(boundaryDocument, basePolicy)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_CAPTURE_DRIFT');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_KIND,
    status: 'PASS',
    repository: REPOSITORY,
    awsRegion,
    role: {
      arn: expectedRoleArn,
      path: roleValue.Path,
      name: roleValue.RoleName,
      id: roleValue.RoleId,
      createdAtUtc,
      maxSessionDuration: roleValue.MaxSessionDuration,
      trustPolicy,
      trustPolicySha256: objectSha256(trustPolicy),
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
    basePolicy,
    basePolicySha256: objectSha256(basePolicy),
    inlinePolicies: [
      {
        policyName: inlinePolicyNames[0],
        policyDocument: inlineDocument,
        policyDocumentSha256: objectSha256(inlineDocument),
      },
    ],
    attachedPolicies: [],
    permissionsBoundary: {
      policyArn: expectedPermissionsBoundaryArn,
      defaultVersionId,
      policyDocument: boundaryDocument,
      policyDocumentSha256: objectSha256(boundaryDocument),
    },
    sourceBindings: [
      getPolicy.binding,
      getPolicyVersion.binding,
      getRole.binding,
      getRolePolicy.binding,
      listAttached.binding,
      listRolePolicies.binding,
    ].toSorted((left, right) => left.operation.localeCompare(right.operation)),
    containsSensitiveData: false,
  };
  const projected = {
    ...body,
    effectivePolicyProjectionSha256: objectSha256(recoveryRoleStableProjection(body)),
  };
  const value = validateReleaseReconciliationRecoveryRoleEffectivePermissions(
    {
      ...projected,
      effectivePermissionsSha256: objectSha256(projected),
    },
    {
      roleArn: expectedRoleArn,
      permissionsBoundaryArn: expectedPermissionsBoundaryArn,
      basePolicy,
    },
  );
  return {
    value,
    bytes: Buffer.from(`${JSON.stringify(value)}\n`, 'utf8'),
    roleAuditBytes: Buffer.from(`${JSON.stringify(roleValue)}\n`, 'utf8'),
    sourceBindingCount: value.sourceBindings.length,
  };
};

export const createReleaseReconciliationRecoveryOriginalRunObservation = ({
  source,
  originalJobConclusion,
  originalRunSource,
  observedAtUtc,
}) => {
  validateReleaseReconciliationSource(source);
  const document = parseReleaseReconciliationRecoveryJson(
    originalRunSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_RUN_RESPONSE_INVALID',
  );
  const run = document.value;
  const expectedConclusion = ORIGINAL_RUN_CONCLUSIONS[originalJobConclusion];
  if (
    expectedConclusion === undefined ||
    !object(run) ||
    !Number.isSafeInteger(run.id) ||
    run.id < 1 ||
    String(run.id) !== source.runId ||
    run.run_attempt !== 1 ||
    run.event !== 'workflow_dispatch' ||
    run.status !== 'completed' ||
    run.conclusion !== expectedConclusion ||
    run.head_branch !== 'master' ||
    run.head_sha !== source.candidateSha ||
    run.path !== source.workflowPath ||
    !Number.isSafeInteger(run.workflow_id) ||
    run.workflow_id < 1 ||
    run.repository?.full_name !== source.repository ||
    !utc(observedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_RUN_INVALID');
  }
  return validateReleaseReconciliationRecoveryOriginalRunObservation(
    {
      id: source.runId,
      runAttempt: 1,
      repository: source.repository,
      workflowPath: source.workflowPath,
      ref: source.ref,
      event: 'workflow_dispatch',
      headBranch: 'master',
      headSha: source.candidateSha,
      status: 'completed',
      conclusion: expectedConclusion,
      workflowId: run.workflow_id,
      responseRawSha256: sha256(document.bytes),
      responseCanonicalSha256: objectSha256(run),
      responseBytes: document.bytes.length,
      observedAtUtc,
    },
    { source, originalJobConclusion },
  );
};

export const validateReleaseReconciliationRecoveryOriginalRunObservation = (
  value,
  { source, originalJobConclusion } = {},
) => {
  if (
    !exactKeys(value, [
      'id',
      'runAttempt',
      'repository',
      'workflowPath',
      'ref',
      'event',
      'headBranch',
      'headSha',
      'status',
      'conclusion',
      'workflowId',
      'responseRawSha256',
      'responseCanonicalSha256',
      'responseBytes',
      'observedAtUtc',
    ]) ||
    !RUN_ID.test(value.id ?? '') ||
    value.runAttempt !== 1 ||
    value.repository !== REPOSITORY ||
    value.workflowPath !== '.github/workflows/release.yml' ||
    value.ref !== REF ||
    value.event !== 'workflow_dispatch' ||
    value.headBranch !== 'master' ||
    !/^[0-9a-f]{40}$/u.test(value.headSha ?? '') ||
    value.status !== 'completed' ||
    !Object.values(ORIGINAL_RUN_CONCLUSIONS).includes(value.conclusion) ||
    !Number.isSafeInteger(value.workflowId) ||
    value.workflowId < 1 ||
    !SHA256.test(value.responseRawSha256 ?? '') ||
    !SHA256.test(value.responseCanonicalSha256 ?? '') ||
    !Number.isSafeInteger(value.responseBytes) ||
    value.responseBytes < 2 ||
    value.responseBytes > MAX_DOCUMENT_BYTES ||
    !utc(value.observedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_RUN_OBSERVATION_INVALID');
  }
  if (
    source !== undefined &&
    (validateReleaseReconciliationSource(source) !== source ||
      value.id !== source.runId ||
      value.repository !== source.repository ||
      value.workflowPath !== source.workflowPath ||
      value.ref !== source.ref ||
      value.headSha !== source.candidateSha ||
      value.conclusion !== ORIGINAL_RUN_CONCLUSIONS[originalJobConclusion])
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_RUN_SOURCE_MISMATCH');
  }
  return value;
};

export const createReleaseReconciliationRecoveryOriginalJobObservation = ({
  source,
  phase,
  originalJobConclusion,
  originalJobsSource,
  observedAtUtc,
}) => {
  validateReleaseReconciliationSource(source);
  const document = parseReleaseReconciliationRecoveryJson(
    originalJobsSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_JOBS_RESPONSE_INVALID',
  );
  const pages = document.value;
  const expectedName = ORIGINAL_PHASE_JOB_NAMES[phase];
  const expectedConclusion = ORIGINAL_RUN_CONCLUSIONS[originalJobConclusion];
  if (
    expectedName === undefined ||
    expectedConclusion === undefined ||
    !Array.isArray(pages) ||
    pages.length < 1 ||
    pages.length > 10 ||
    !utc(observedAtUtc) ||
    pages.some(
      (page) =>
        !object(page) ||
        !Number.isSafeInteger(page.total_count) ||
        page.total_count < 1 ||
        !Array.isArray(page.jobs) ||
        page.jobs.length < 1 ||
        page.jobs.length > 100,
    )
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_JOBS_INVALID');
  }
  const totalCount = pages[0].total_count;
  const jobs = pages.flatMap(({ jobs }) => jobs);
  const jobIds = jobs.map(({ id }) => id);
  const targetJobs = jobs.filter(({ name }) => name === expectedName);
  const job = targetJobs[0];
  const startedAtUtc = normalizeApiUtc(job?.started_at);
  const completedAtUtc = normalizeApiUtc(job?.completed_at);
  if (
    pages.some(({ total_count: pageTotal }) => pageTotal !== totalCount) ||
    jobs.length !== totalCount ||
    new Set(jobIds).size !== jobs.length ||
    jobIds.some((id) => !Number.isSafeInteger(id) || id < 1) ||
    targetJobs.length !== 1 ||
    String(job.run_id) !== source.runId ||
    job.run_attempt !== 1 ||
    job.head_sha !== source.candidateSha ||
    job.status !== 'completed' ||
    job.conclusion !== expectedConclusion ||
    startedAtUtc === null ||
    completedAtUtc === null ||
    Date.parse(completedAtUtc) < Date.parse(startedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_JOB_INVALID');
  }
  return validateReleaseReconciliationRecoveryOriginalJobObservation(
    {
      phase,
      name: expectedName,
      id: job.id,
      runId: source.runId,
      runAttempt: 1,
      headSha: source.candidateSha,
      status: 'completed',
      conclusion: expectedConclusion,
      startedAtUtc,
      completedAtUtc,
      totalCount,
      pageCount: pages.length,
      responseRawSha256: sha256(document.bytes),
      responseCanonicalSha256: objectSha256(pages),
      responseBytes: document.bytes.length,
      observedAtUtc,
    },
    { source, phase, originalJobConclusion },
  );
};

export const validateReleaseReconciliationRecoveryOriginalJobObservation = (
  value,
  { source, phase, originalJobConclusion } = {},
) => {
  if (
    !exactKeys(value, [
      'phase',
      'name',
      'id',
      'runId',
      'runAttempt',
      'headSha',
      'status',
      'conclusion',
      'startedAtUtc',
      'completedAtUtc',
      'totalCount',
      'pageCount',
      'responseRawSha256',
      'responseCanonicalSha256',
      'responseBytes',
      'observedAtUtc',
    ]) ||
    !PHASES.includes(value.phase) ||
    value.name !== ORIGINAL_PHASE_JOB_NAMES[value.phase] ||
    !Number.isSafeInteger(value.id) ||
    value.id < 1 ||
    !RUN_ID.test(value.runId ?? '') ||
    value.runAttempt !== 1 ||
    !/^[0-9a-f]{40}$/u.test(value.headSha ?? '') ||
    value.status !== 'completed' ||
    !Object.values(ORIGINAL_RUN_CONCLUSIONS).includes(value.conclusion) ||
    !utc(value.startedAtUtc) ||
    !utc(value.completedAtUtc) ||
    Date.parse(value.completedAtUtc) < Date.parse(value.startedAtUtc) ||
    !Number.isSafeInteger(value.totalCount) ||
    value.totalCount < 1 ||
    !Number.isSafeInteger(value.pageCount) ||
    value.pageCount < 1 ||
    value.pageCount > 10 ||
    !SHA256.test(value.responseRawSha256 ?? '') ||
    !SHA256.test(value.responseCanonicalSha256 ?? '') ||
    !Number.isSafeInteger(value.responseBytes) ||
    value.responseBytes < 2 ||
    value.responseBytes > MAX_DOCUMENT_BYTES ||
    !utc(value.observedAtUtc) ||
    Date.parse(value.observedAtUtc) < Date.parse(value.completedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_JOB_OBSERVATION_INVALID');
  }
  if (
    source !== undefined &&
    (validateReleaseReconciliationSource(source) !== source ||
      value.runId !== source.runId ||
      value.headSha !== source.candidateSha)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_JOB_SOURCE_MISMATCH');
  }
  if (
    phase !== undefined &&
    (value.phase !== phase || value.name !== ORIGINAL_PHASE_JOB_NAMES[phase])
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_JOB_PHASE_MISMATCH');
  }
  if (
    originalJobConclusion !== undefined &&
    value.conclusion !== ORIGINAL_RUN_CONCLUSIONS[originalJobConclusion]
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ORIGINAL_JOB_CONCLUSION_MISMATCH');
  }
  return value;
};

const awsAuthForRecovery = ({
  intent,
  awsAuthSource,
  candidateManifest,
  frozenRoleAuthority,
  recoveryRoleArn,
  permissionsBoundaryArn,
}) => {
  const document = parseReleaseReconciliationRecoveryJson(
    awsAuthSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_INVALID',
  );
  const value = document.value;
  const binding = bindingByLabel(intent, 'awsAuth');
  if (
    binding?.sourceType !== 'JSON' ||
    binding.path !== 'aws-auth.json' ||
    binding.rawSha256 !== sha256(document.bytes) ||
    binding.canonicalSha256 !== objectSha256(value) ||
    binding.bytes !== document.bytes.length ||
    value?.kind !== 'AWS_READ_ONLY_PREFLIGHT' ||
    value.status !== 'PASS' ||
    value.scope !== 'full' ||
    value.candidateSha !== intent.source.candidateSha ||
    value.releaseId !== intent.source.releaseId ||
    value.configSha256 !== intent.source.configSha256 ||
    value.manifestSha256 !== candidateManifest.manifestSha256 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.reconciliationRecoveryRoleArn !== recoveryRoleArn ||
    value.reconciliationRecoveryPermissionsBoundaryArn !== permissionsBoundaryArn ||
    value.reconciliationRecoveryRoleEffectivePermissionsRawSha256 !==
      frozenRoleAuthority.rawSha256 ||
    value.reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256 !==
      frozenRoleAuthority.canonicalSha256 ||
    value.reconciliationRecoveryRoleEffectivePermissionsSha256 !==
      frozenRoleAuthority.value.effectivePermissionsSha256 ||
    value.reconciliationRecoveryRoleEffectivePolicyProjectionSha256 !==
      frozenRoleAuthority.value.effectivePolicyProjectionSha256
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_INVALID');
  }
  return { binding };
};

const candidateManifestForRecovery = ({ intent, candidateManifestSource }) => {
  const document = parseReleaseReconciliationRecoveryJson(
    candidateManifestSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_CANDIDATE_MANIFEST_INVALID',
  );
  const value = document.value;
  const binding = bindingByLabel(intent, 'candidateManifest');
  const body = { ...value };
  delete body.manifestSha256;
  if (
    binding?.sourceType !== 'JSON' ||
    binding.path !== 'candidate-manifest.json' ||
    binding.rawSha256 !== sha256(document.bytes) ||
    binding.canonicalSha256 !== objectSha256(value) ||
    binding.bytes !== document.bytes.length ||
    value?.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'BUILD_ONCE_FREEZE' ||
    value.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    value.releaseMode !== 'VERSIONED_UPDATE' ||
    value.updateReleaseSupported !== true ||
    value.candidateSha !== intent.source.candidateSha ||
    value.releaseId !== intent.source.releaseId ||
    value.releaseTag !== intent.source.releaseTag ||
    value.configSha256 !== intent.source.configSha256 ||
    value.containsSensitiveData !== false ||
    value.manifestSha256 !== objectSha256(body)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CANDIDATE_MANIFEST_BINDING_INVALID');
  }
  return { value, binding };
};

export const createReleaseReconciliationRecoveryRequest = ({
  intent,
  configSource,
  awsAuthSource,
  candidateManifestSource,
  originalRunSource,
  originalJobsSource,
  recoveryRoleEffectivePermissionsSource,
  permissionsBoundaryArn,
  candidateRecordSource,
  previousManifestSource,
  recoveryRoleArn,
  environmentVariables,
  phase,
  originalJobConclusion,
  requestedAtUtc,
}) => {
  const { config, binding } = configForRecovery({ intent, configSource });
  const source = intent.source;
  const context = recoveryWorkflowContext({ environmentVariables, source, recoveryRoleArn });
  const sessionPolicy = createReleaseReconciliationRecoverySessionPolicy({
    intent,
    recoveryRoleArn,
    permissionsBoundaryArn,
    candidateRecordSource,
    previousManifestSource,
  });
  const basePolicy = createReleaseReconciliationRecoveryBasePolicy({
    accountId: context.authority.accountId,
    awsRegion: context.authority.region,
    recoveryRoleArn,
    permissionsBoundaryArn,
  });
  const sessionPolicySubset = validateReleaseReconciliationRecoverySessionPolicySubset({
    basePolicy,
    sessionPolicy,
  });
  const frozenRoleAuthority = parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource(
    recoveryRoleEffectivePermissionsSource,
    { roleArn: recoveryRoleArn, permissionsBoundaryArn, basePolicy },
  );
  const candidateManifest = candidateManifestForRecovery({
    intent,
    candidateManifestSource,
  });
  const awsAuth = awsAuthForRecovery({
    intent,
    awsAuthSource,
    candidateManifest: candidateManifest.value,
    frozenRoleAuthority,
    recoveryRoleArn,
    permissionsBoundaryArn,
  });
  const originalRun = createReleaseReconciliationRecoveryOriginalRunObservation({
    source,
    originalJobConclusion,
    originalRunSource,
    observedAtUtc: requestedAtUtc,
  });
  const originalJob = createReleaseReconciliationRecoveryOriginalJobObservation({
    source,
    phase,
    originalJobConclusion,
    originalJobsSource,
    observedAtUtc: requestedAtUtc,
  });
  if (
    !PHASES.includes(phase) ||
    !ORIGINAL_CONCLUSIONS.includes(originalJobConclusion) ||
    context.authority.accountId !== intent.authority.accountId ||
    context.authority.region !== intent.authority.region ||
    [intent.authority.rollbackRoleArn, intent.authority.journalRoleArn].includes(recoveryRoleArn) ||
    environmentVariables?.AWS_DEFAULT_REGION !== context.authority.region ||
    !utc(requestedAtUtc) ||
    Date.parse(requestedAtUtc) > Date.parse(config.cleanup.expiresAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_REQUEST_INPUT_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_REQUEST',
    status: 'PENDING_PROTECTED_APPROVAL',
    recoveryRun: context.recoveryRun,
    originalSource: { ...source },
    originalRun,
    originalJob,
    phase,
    originalJobConclusion,
    authority: context.authority,
    recoveryRoleAuthority: {
      roleArn: recoveryRoleArn,
      permissionsBoundaryArn,
      basePolicy,
      basePolicySha256: objectSha256(basePolicy),
      sessionPolicy,
      sessionPolicySha256: objectSha256(sessionPolicy),
      sessionPolicySubset,
      frozen: {
        value: frozenRoleAuthority.value,
        rawSha256: frozenRoleAuthority.rawSha256,
        canonicalSha256: frozenRoleAuthority.canonicalSha256,
        bytes: frozenRoleAuthority.bytes,
        effectivePermissionsSha256: frozenRoleAuthority.value.effectivePermissionsSha256,
        effectivePolicyProjectionSha256: frozenRoleAuthority.value.effectivePolicyProjectionSha256,
      },
    },
    intentBinding: {
      intentSha256: intent.intentSha256,
      bindingsSha256: intent.bindingsSha256,
      bindingCount: intent.bindings.length,
      candidateManifestSha256: candidateManifest.value.manifestSha256,
      candidateManifestRawSha256: candidateManifest.binding.rawSha256,
      candidateManifestCanonicalSha256: candidateManifest.binding.canonicalSha256,
      candidateManifestBytes: candidateManifest.binding.bytes,
    },
    awsAuthBinding: {
      rawSha256: awsAuth.binding.rawSha256,
      canonicalSha256: awsAuth.binding.canonicalSha256,
      bytes: awsAuth.binding.bytes,
      recoveryRoleArn,
      permissionsBoundaryArn,
      recoveryRoleEffectivePermissionsRawSha256: frozenRoleAuthority.rawSha256,
      recoveryRoleEffectivePermissionsCanonicalSha256: frozenRoleAuthority.canonicalSha256,
      recoveryRoleEffectivePermissionsSha256: frozenRoleAuthority.value.effectivePermissionsSha256,
      recoveryRoleEffectivePolicyProjectionSha256:
        frozenRoleAuthority.value.effectivePolicyProjectionSha256,
    },
    configBinding: {
      rawSha256: binding.rawSha256,
      canonicalSha256: binding.canonicalSha256,
      bytes: binding.bytes,
      cleanupExpiresAtUtc: config.cleanup.expiresAtUtc,
      readRoleArn: config.aws.roles.readRoleArn,
    },
    policy: STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT.policy,
    prohibitedActions: [...PROHIBITED_ACTIONS],
    requestedAtUtc,
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationRecoveryRequest({
    ...body,
    requestSha256: objectSha256(body),
  });
};

export const validateReleaseReconciliationRecoveryRequest = (value, intent = undefined) => {
  const role = ROLE_ARN.exec(value?.authority?.recoveryRoleArn ?? '');
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'recoveryRun',
      'originalSource',
      'originalRun',
      'originalJob',
      'phase',
      'originalJobConclusion',
      'authority',
      'recoveryRoleAuthority',
      'intentBinding',
      'awsAuthBinding',
      'configBinding',
      'policy',
      'prohibitedActions',
      'requestedAtUtc',
      'containsSensitiveData',
      'requestSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_REQUEST' ||
    value.status !== 'PENDING_PROTECTED_APPROVAL' ||
    validateReleaseReconciliationSource(value.originalSource) !== value.originalSource ||
    validateReleaseReconciliationRecoveryOriginalRunObservation(value.originalRun, {
      source: value.originalSource,
      originalJobConclusion: value.originalJobConclusion,
    }) !== value.originalRun ||
    validateReleaseReconciliationRecoveryOriginalJobObservation(value.originalJob, {
      source: value.originalSource,
      phase: value.phase,
      originalJobConclusion: value.originalJobConclusion,
    }) !== value.originalJob ||
    value.originalSource.runAttempt !== 1 ||
    !PHASES.includes(value.phase) ||
    !ORIGINAL_CONCLUSIONS.includes(value.originalJobConclusion) ||
    !exactKeys(value.recoveryRun, [
      'repository',
      'workflowPath',
      'workflowRef',
      'ref',
      'eventName',
      'runId',
      'runAttempt',
      'actorId',
      'controlSha',
      'protectedEnvironment',
      'candidateSha',
    ]) ||
    value.recoveryRun.repository !== REPOSITORY ||
    value.recoveryRun.workflowPath !== WORKFLOW_PATH ||
    value.recoveryRun.workflowRef !== `${REPOSITORY}/${WORKFLOW_PATH}@${REF}` ||
    value.recoveryRun.ref !== REF ||
    value.recoveryRun.eventName !== 'workflow_dispatch' ||
    !RUN_ID.test(value.recoveryRun.runId ?? '') ||
    !Number.isSafeInteger(value.recoveryRun.runAttempt) ||
    value.recoveryRun.runAttempt < 1 ||
    value.recoveryRun.runAttempt > 999 ||
    !RUN_ID.test(value.recoveryRun.actorId ?? '') ||
    !/^[0-9a-f]{40}$/u.test(value.recoveryRun.controlSha ?? '') ||
    value.recoveryRun.protectedEnvironment !== PROTECTED_ENVIRONMENT ||
    value.recoveryRun.candidateSha !== value.originalSource.candidateSha ||
    !exactKeys(value.authority, [
      'accountId',
      'region',
      'recoveryRoleArn',
      'roleSessionName',
      'oidcSubject',
    ]) ||
    !ACCOUNT_ID.test(value.authority.accountId ?? '') ||
    !REGION.test(value.authority.region ?? '') ||
    role?.[1] !== value.authority.accountId ||
    value.authority.roleSessionName !==
      `e7-reconciliation-recovery-${value.recoveryRun.runId}-${value.recoveryRun.runAttempt}` ||
    value.authority.oidcSubject !== PROTECTED_OIDC_SUBJECT ||
    !exactKeys(value.recoveryRoleAuthority, [
      'roleArn',
      'permissionsBoundaryArn',
      'basePolicy',
      'basePolicySha256',
      'sessionPolicy',
      'sessionPolicySha256',
      'sessionPolicySubset',
      'frozen',
    ]) ||
    value.recoveryRoleAuthority.roleArn !== value.authority.recoveryRoleArn ||
    POLICY_ARN.exec(value.recoveryRoleAuthority.permissionsBoundaryArn ?? '')?.[1] !==
      value.authority.accountId ||
    value.recoveryRoleAuthority.basePolicySha256 !==
      objectSha256(value.recoveryRoleAuthority.basePolicy) ||
    value.recoveryRoleAuthority.sessionPolicySha256 !==
      objectSha256(value.recoveryRoleAuthority.sessionPolicy) ||
    !sameObject(
      value.recoveryRoleAuthority.sessionPolicySubset,
      validateReleaseReconciliationRecoverySessionPolicySubset({
        basePolicy: value.recoveryRoleAuthority.basePolicy,
        sessionPolicy: value.recoveryRoleAuthority.sessionPolicy,
      }),
    ) ||
    !exactKeys(value.recoveryRoleAuthority.frozen, [
      'value',
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'effectivePermissionsSha256',
      'effectivePolicyProjectionSha256',
    ]) ||
    validateReleaseReconciliationRecoveryRoleEffectivePermissions(
      value.recoveryRoleAuthority.frozen.value,
      {
        roleArn: value.authority.recoveryRoleArn,
        permissionsBoundaryArn: value.recoveryRoleAuthority.permissionsBoundaryArn,
        basePolicy: value.recoveryRoleAuthority.basePolicy,
      },
    ) !== value.recoveryRoleAuthority.frozen.value ||
    !SHA256.test(value.recoveryRoleAuthority.frozen.rawSha256 ?? '') ||
    value.recoveryRoleAuthority.frozen.canonicalSha256 !==
      objectSha256(value.recoveryRoleAuthority.frozen.value) ||
    !Number.isSafeInteger(value.recoveryRoleAuthority.frozen.bytes) ||
    value.recoveryRoleAuthority.frozen.bytes < 2 ||
    value.recoveryRoleAuthority.frozen.bytes > MAX_DOCUMENT_BYTES ||
    value.recoveryRoleAuthority.frozen.effectivePermissionsSha256 !==
      value.recoveryRoleAuthority.frozen.value.effectivePermissionsSha256 ||
    value.recoveryRoleAuthority.frozen.effectivePolicyProjectionSha256 !==
      value.recoveryRoleAuthority.frozen.value.effectivePolicyProjectionSha256 ||
    !exactKeys(value.intentBinding, [
      'intentSha256',
      'bindingsSha256',
      'bindingCount',
      'candidateManifestSha256',
      'candidateManifestRawSha256',
      'candidateManifestCanonicalSha256',
      'candidateManifestBytes',
    ]) ||
    !SHA256.test(value.intentBinding.intentSha256 ?? '') ||
    !SHA256.test(value.intentBinding.bindingsSha256 ?? '') ||
    value.intentBinding.bindingCount !== 23 ||
    !SHA256.test(value.intentBinding.candidateManifestSha256 ?? '') ||
    !SHA256.test(value.intentBinding.candidateManifestRawSha256 ?? '') ||
    !SHA256.test(value.intentBinding.candidateManifestCanonicalSha256 ?? '') ||
    !Number.isSafeInteger(value.intentBinding.candidateManifestBytes) ||
    value.intentBinding.candidateManifestBytes < 2 ||
    value.intentBinding.candidateManifestBytes > MAX_DOCUMENT_BYTES ||
    !exactKeys(value.awsAuthBinding, [
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'recoveryRoleArn',
      'permissionsBoundaryArn',
      'recoveryRoleEffectivePermissionsRawSha256',
      'recoveryRoleEffectivePermissionsCanonicalSha256',
      'recoveryRoleEffectivePermissionsSha256',
      'recoveryRoleEffectivePolicyProjectionSha256',
    ]) ||
    !SHA256.test(value.awsAuthBinding.rawSha256 ?? '') ||
    !SHA256.test(value.awsAuthBinding.canonicalSha256 ?? '') ||
    !Number.isSafeInteger(value.awsAuthBinding.bytes) ||
    value.awsAuthBinding.bytes < 2 ||
    value.awsAuthBinding.bytes > MAX_DOCUMENT_BYTES ||
    value.awsAuthBinding.recoveryRoleArn !== value.authority.recoveryRoleArn ||
    value.awsAuthBinding.permissionsBoundaryArn !==
      value.recoveryRoleAuthority.permissionsBoundaryArn ||
    value.awsAuthBinding.recoveryRoleEffectivePermissionsRawSha256 !==
      value.recoveryRoleAuthority.frozen.rawSha256 ||
    value.awsAuthBinding.recoveryRoleEffectivePermissionsCanonicalSha256 !==
      value.recoveryRoleAuthority.frozen.canonicalSha256 ||
    value.awsAuthBinding.recoveryRoleEffectivePermissionsSha256 !==
      value.recoveryRoleAuthority.frozen.effectivePermissionsSha256 ||
    value.awsAuthBinding.recoveryRoleEffectivePolicyProjectionSha256 !==
      value.recoveryRoleAuthority.frozen.effectivePolicyProjectionSha256 ||
    !exactKeys(value.configBinding, [
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'cleanupExpiresAtUtc',
      'readRoleArn',
    ]) ||
    !SHA256.test(value.configBinding.rawSha256 ?? '') ||
    value.configBinding.canonicalSha256 !== value.originalSource.configSha256 ||
    !Number.isSafeInteger(value.configBinding.bytes) ||
    value.configBinding.bytes < 2 ||
    value.configBinding.bytes > MAX_DOCUMENT_BYTES ||
    !utc(value.configBinding.cleanupExpiresAtUtc) ||
    ROLE_ARN.exec(value.configBinding.readRoleArn ?? '')?.[1] !== value.authority.accountId ||
    value.configBinding.readRoleArn === value.authority.recoveryRoleArn ||
    !utc(value.requestedAtUtc) ||
    Date.parse(value.requestedAtUtc) > Date.parse(value.configBinding.cleanupExpiresAtUtc) ||
    value.policy !== STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT.policy ||
    value.prohibitedActions?.join('\0') !== PROHIBITED_ACTIONS.join('\0') ||
    value.containsSensitiveData !== false ||
    value.requestSha256 !== objectSha256(withoutDigest(value, 'requestSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_REQUEST_INVALID');
  }
  if (
    intent !== undefined &&
    (validateReleaseReconciliationIntent(intent) !== intent ||
      !sameObject(intent.source, value.originalSource) ||
      intent.authority.accountId !== value.authority.accountId ||
      intent.authority.region !== value.authority.region ||
      value.intentBinding.intentSha256 !== intent.intentSha256 ||
      value.intentBinding.bindingsSha256 !== intent.bindingsSha256 ||
      value.intentBinding.bindingCount !== intent.bindings.length ||
      value.intentBinding.candidateManifestRawSha256 !==
        bindingByLabel(intent, 'candidateManifest')?.rawSha256 ||
      value.intentBinding.candidateManifestCanonicalSha256 !==
        bindingByLabel(intent, 'candidateManifest')?.canonicalSha256 ||
      value.intentBinding.candidateManifestBytes !==
        bindingByLabel(intent, 'candidateManifest')?.bytes ||
      value.awsAuthBinding.rawSha256 !== bindingByLabel(intent, 'awsAuth')?.rawSha256 ||
      value.awsAuthBinding.canonicalSha256 !== bindingByLabel(intent, 'awsAuth')?.canonicalSha256 ||
      value.awsAuthBinding.bytes !== bindingByLabel(intent, 'awsAuth')?.bytes ||
      [intent.authority.rollbackRoleArn, intent.authority.journalRoleArn].includes(
        value.authority.recoveryRoleArn,
      ))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_REQUEST_INTENT_MISMATCH');
  }
  return value;
};

export const createReleaseReconciliationRecoveryApproval = ({
  request,
  reviewResponseSource,
  capturedAtUtc,
}) => {
  validateReleaseReconciliationRecoveryRequest(request);
  const response = parseReleaseReconciliationRecoveryJson(
    reviewResponseSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_APPROVAL_RESPONSE_INVALID',
  );
  if (response.bytes.length > MAX_REVIEW_RESPONSE_BYTES || !Array.isArray(response.value)) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_APPROVAL_RESPONSE_INVALID');
  }
  const expectedEnvironmentUrl = `https://api.github.com/repos/${REPOSITORY}/environments/${PROTECTED_ENVIRONMENT}`;
  const expectedComment = `STAGE7_RECONCILIATION_RECOVERY_SHA256=${request.requestSha256}`;
  const matches = response.value.filter((review) =>
    review?.environments?.some?.(({ name }) => name === PROTECTED_ENVIRONMENT),
  );
  const review = matches[0];
  const environment = review?.environments?.[0];
  const reviewerAlias = review?.user?.login?.toLowerCase();
  if (
    matches.length !== 1 ||
    review?.state !== 'approved' ||
    review?.comment !== expectedComment ||
    !Array.isArray(review.environments) ||
    review.environments.length !== 1 ||
    !exactKeys(environment, ['id', 'name', 'url']) ||
    !Number.isSafeInteger(environment.id) ||
    environment.id < 1 ||
    environment.name !== PROTECTED_ENVIRONMENT ||
    environment.url !== expectedEnvironmentUrl ||
    !exactKeys(review.user, ['id', 'login', 'type']) ||
    !Number.isSafeInteger(review.user.id) ||
    review.user.id < 1 ||
    review.user.type !== 'User' ||
    !REVIEWER_ALIAS.test(reviewerAlias ?? '') ||
    reviewerAlias === 'github-actions' ||
    String(review.user.id) === request.recoveryRun.actorId ||
    !utc(capturedAtUtc) ||
    Date.parse(capturedAtUtc) < Date.parse(request.requestedAtUtc) ||
    Date.parse(capturedAtUtc) > Date.parse(request.configBinding.cleanupExpiresAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_APPROVAL_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_APPROVAL',
    status: 'APPROVED',
    requestSha256: request.requestSha256,
    recoveryRun: request.recoveryRun,
    environment: PROTECTED_ENVIRONMENT,
    reviewer: { id: String(review.user.id), alias: reviewerAlias, type: 'User' },
    reviewState: 'approved',
    reviewCommentSha256: sha256(Buffer.from(expectedComment, 'utf8')),
    responseRawSha256: sha256(response.bytes),
    approvedAtUtc: capturedAtUtc,
    expiresAtUtc: request.configBinding.cleanupExpiresAtUtc,
    externalRequests: 1,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationRecoveryApproval(
    {
      ...body,
      approvalSha256: objectSha256(body),
    },
    request,
  );
};

export const validateReleaseReconciliationRecoveryApproval = (value, request = undefined) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'requestSha256',
      'recoveryRun',
      'environment',
      'reviewer',
      'reviewState',
      'reviewCommentSha256',
      'responseRawSha256',
      'approvedAtUtc',
      'expiresAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'approvalSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_APPROVAL' ||
    value.status !== 'APPROVED' ||
    !SHA256.test(value.requestSha256 ?? '') ||
    !exactKeys(value.recoveryRun, [
      'repository',
      'workflowPath',
      'workflowRef',
      'ref',
      'eventName',
      'runId',
      'runAttempt',
      'actorId',
      'controlSha',
      'protectedEnvironment',
      'candidateSha',
    ]) ||
    value.recoveryRun.repository !== REPOSITORY ||
    value.recoveryRun.workflowPath !== WORKFLOW_PATH ||
    value.recoveryRun.workflowRef !== `${REPOSITORY}/${WORKFLOW_PATH}@${REF}` ||
    value.recoveryRun.ref !== REF ||
    value.recoveryRun.eventName !== 'workflow_dispatch' ||
    !RUN_ID.test(value.recoveryRun.runId ?? '') ||
    !Number.isSafeInteger(value.recoveryRun.runAttempt) ||
    value.recoveryRun.runAttempt < 1 ||
    value.recoveryRun.runAttempt > 999 ||
    !RUN_ID.test(value.recoveryRun.actorId ?? '') ||
    !/^[0-9a-f]{40}$/u.test(value.recoveryRun.controlSha ?? '') ||
    value.recoveryRun.protectedEnvironment !== PROTECTED_ENVIRONMENT ||
    !/^[0-9a-f]{40}$/u.test(value.recoveryRun.candidateSha ?? '') ||
    value.environment !== PROTECTED_ENVIRONMENT ||
    !exactKeys(value.reviewer, ['id', 'alias', 'type']) ||
    !RUN_ID.test(value.reviewer.id ?? '') ||
    !REVIEWER_ALIAS.test(value.reviewer.alias ?? '') ||
    value.reviewer.alias === 'github-actions' ||
    value.reviewer.type !== 'User' ||
    value.reviewer.id === value.recoveryRun.actorId ||
    value.reviewState !== 'approved' ||
    !SHA256.test(value.reviewCommentSha256 ?? '') ||
    !SHA256.test(value.responseRawSha256 ?? '') ||
    !utc(value.approvedAtUtc) ||
    !utc(value.expiresAtUtc) ||
    Date.parse(value.approvedAtUtc) > Date.parse(value.expiresAtUtc) ||
    value.externalRequests !== 1 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.approvalSha256 !== objectSha256(withoutDigest(value, 'approvalSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_APPROVAL_INVALID');
  }
  if (
    request !== undefined &&
    (validateReleaseReconciliationRecoveryRequest(request) !== request ||
      value.requestSha256 !== request.requestSha256 ||
      !sameObject(value.recoveryRun, request.recoveryRun) ||
      value.expiresAtUtc !== request.configBinding.cleanupExpiresAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_APPROVAL_REQUEST_MISMATCH');
  }
  return value;
};

export const parseReleaseReconciliationRecoveryJson = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_DOCUMENT_BYTES) fail(code);
  try {
    return { value: parseStrictJsonSource(bytes, { scanForbiddenData: false }), bytes };
  } catch (error) {
    fail(code, error);
  }
};

export const createReleaseReconciliationRecoveryActor = ({
  intent,
  request,
  approval,
  liveRecoveryRoleEffectivePermissionsSource,
  recoveryRoleArn,
  environmentVariables,
  createdAtUtc,
  phase,
  originalJobConclusion,
}) => {
  validateReleaseReconciliationIntent(intent);
  validateReleaseReconciliationRecoveryRequest(request, intent);
  validateReleaseReconciliationRecoveryApproval(approval, request);
  const source = intent.source;
  const context = recoveryWorkflowContext({ environmentVariables, source, recoveryRoleArn });
  const liveRoleAuthority = parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource(
    liveRecoveryRoleEffectivePermissionsSource,
    {
      roleArn: request.authority.recoveryRoleArn,
      permissionsBoundaryArn: request.recoveryRoleAuthority.permissionsBoundaryArn,
      basePolicy: request.recoveryRoleAuthority.basePolicy,
    },
  );
  if (
    phase !== request.phase ||
    originalJobConclusion !== request.originalJobConclusion ||
    !sameObject(context.recoveryRun, request.recoveryRun) ||
    !sameObject(context.authority, request.authority) ||
    context.authority.accountId !== intent.authority.accountId ||
    recoveryRoleArn !== request.authority.recoveryRoleArn ||
    environmentVariables?.AWS_REGION !== intent.authority.region ||
    environmentVariables?.AWS_DEFAULT_REGION !== intent.authority.region ||
    !utc(createdAtUtc) ||
    Date.parse(createdAtUtc) < Date.parse(approval.approvedAtUtc) ||
    Date.parse(createdAtUtc) > Date.parse(approval.expiresAtUtc) ||
    liveRoleAuthority.value.effectivePermissionsSha256 !==
      request.recoveryRoleAuthority.frozen.effectivePermissionsSha256 ||
    liveRoleAuthority.value.effectivePolicyProjectionSha256 !==
      request.recoveryRoleAuthority.frozen.effectivePolicyProjectionSha256
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ACTOR_INPUT_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_ACTOR',
    status: 'AUTHORIZED_FORWARD_N_ONLY',
    request: { ...request },
    approval: { ...approval },
    recoveryRun: context.recoveryRun,
    originalSource: { ...source },
    phase,
    originalJobConclusion,
    authority: context.authority,
    liveRecoveryRoleAuthority: {
      value: liveRoleAuthority.value,
      rawSha256: liveRoleAuthority.rawSha256,
      canonicalSha256: liveRoleAuthority.canonicalSha256,
      bytes: liveRoleAuthority.bytes,
      frozenRawSha256: request.recoveryRoleAuthority.frozen.rawSha256,
      frozenCanonicalSha256: request.recoveryRoleAuthority.frozen.canonicalSha256,
      effectivePermissionsSha256: liveRoleAuthority.value.effectivePermissionsSha256,
      effectivePolicyProjectionSha256: liveRoleAuthority.value.effectivePolicyProjectionSha256,
    },
    policy: STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT.policy,
    prohibitedActions: [...PROHIBITED_ACTIONS],
    createdAtUtc,
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationRecoveryActor({
    ...body,
    actorSha256: objectSha256(body),
  });
};

export const compareReleaseReconciliationRecoveryRoleEffectivePermissions = ({
  request,
  actor,
  liveSource,
}) => {
  validateReleaseReconciliationRecoveryRequest(request);
  if (actor !== undefined) validateReleaseReconciliationRecoveryActor(actor);
  const live = parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource(liveSource, {
    roleArn: request.authority.recoveryRoleArn,
    permissionsBoundaryArn: request.recoveryRoleAuthority.permissionsBoundaryArn,
    basePolicy: request.recoveryRoleAuthority.basePolicy,
  });
  if (
    live.value.effectivePermissionsSha256 !==
      request.recoveryRoleAuthority.frozen.effectivePermissionsSha256 ||
    live.value.effectivePolicyProjectionSha256 !==
      request.recoveryRoleAuthority.frozen.effectivePolicyProjectionSha256 ||
    (actor !== undefined &&
      (actor.request.requestSha256 !== request.requestSha256 ||
        actor.liveRecoveryRoleAuthority.effectivePermissionsSha256 !==
          live.value.effectivePermissionsSha256 ||
        actor.liveRecoveryRoleAuthority.effectivePolicyProjectionSha256 !==
          live.value.effectivePolicyProjectionSha256 ||
        !sameObject(actor.liveRecoveryRoleAuthority.value, live.value)))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_DRIFT');
  }
  return {
    rawSha256: live.rawSha256,
    canonicalSha256: live.canonicalSha256,
    bytes: live.bytes,
    effectivePermissionsSha256: live.value.effectivePermissionsSha256,
    effectivePolicyProjectionSha256: live.value.effectivePolicyProjectionSha256,
  };
};

export const validateReleaseReconciliationRecoveryActor = (value, intent = undefined) => {
  const source = value?.originalSource;
  const role = ROLE_ARN.exec(value?.authority?.recoveryRoleArn ?? '');
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'request',
      'approval',
      'recoveryRun',
      'originalSource',
      'phase',
      'originalJobConclusion',
      'authority',
      'liveRecoveryRoleAuthority',
      'policy',
      'prohibitedActions',
      'createdAtUtc',
      'containsSensitiveData',
      'actorSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_ACTOR' ||
    value.status !== 'AUTHORIZED_FORWARD_N_ONLY' ||
    validateReleaseReconciliationRecoveryRequest(value.request) !== value.request ||
    validateReleaseReconciliationRecoveryApproval(value.approval, value.request) !==
      value.approval ||
    validateReleaseReconciliationSource(source) !== source ||
    !sameObject(value.request.originalSource, source) ||
    value.request.phase !== value.phase ||
    value.request.originalJobConclusion !== value.originalJobConclusion ||
    !sameObject(value.request.recoveryRun, value.recoveryRun) ||
    source.runAttempt !== STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT.sourceRunAttempt ||
    !PHASES.includes(value.phase) ||
    !ORIGINAL_CONCLUSIONS.includes(value.originalJobConclusion) ||
    !exactKeys(value.recoveryRun, [
      'repository',
      'workflowPath',
      'workflowRef',
      'ref',
      'eventName',
      'runId',
      'runAttempt',
      'actorId',
      'controlSha',
      'protectedEnvironment',
      'candidateSha',
    ]) ||
    value.recoveryRun.repository !== REPOSITORY ||
    value.recoveryRun.workflowPath !== WORKFLOW_PATH ||
    value.recoveryRun.workflowRef !== `${REPOSITORY}/${WORKFLOW_PATH}@${REF}` ||
    value.recoveryRun.ref !== REF ||
    value.recoveryRun.eventName !== 'workflow_dispatch' ||
    !RUN_ID.test(value.recoveryRun.runId ?? '') ||
    !Number.isSafeInteger(value.recoveryRun.runAttempt) ||
    value.recoveryRun.runAttempt < 1 ||
    value.recoveryRun.runAttempt > 999 ||
    !RUN_ID.test(value.recoveryRun.actorId ?? '') ||
    !/^[0-9a-f]{40}$/u.test(value.recoveryRun.controlSha ?? '') ||
    value.recoveryRun.protectedEnvironment !== PROTECTED_ENVIRONMENT ||
    value.recoveryRun.candidateSha !== source.candidateSha ||
    !exactKeys(value.authority, [
      'accountId',
      'region',
      'recoveryRoleArn',
      'roleSessionName',
      'oidcSubject',
    ]) ||
    !ACCOUNT_ID.test(value.authority.accountId ?? '') ||
    !REGION.test(value.authority.region ?? '') ||
    role?.[1] !== value.authority.accountId ||
    value.authority.roleSessionName !==
      `e7-reconciliation-recovery-${value.recoveryRun.runId}-${value.recoveryRun.runAttempt}` ||
    value.authority.roleSessionName.length > 64 ||
    value.authority.oidcSubject !== PROTECTED_OIDC_SUBJECT ||
    !sameObject(value.request.authority, value.authority) ||
    !exactKeys(value.liveRecoveryRoleAuthority, [
      'value',
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'frozenRawSha256',
      'frozenCanonicalSha256',
      'effectivePermissionsSha256',
      'effectivePolicyProjectionSha256',
    ]) ||
    validateReleaseReconciliationRecoveryRoleEffectivePermissions(
      value.liveRecoveryRoleAuthority.value,
      {
        roleArn: value.authority.recoveryRoleArn,
        permissionsBoundaryArn: value.request.recoveryRoleAuthority.permissionsBoundaryArn,
        basePolicy: value.request.recoveryRoleAuthority.basePolicy,
      },
    ) !== value.liveRecoveryRoleAuthority.value ||
    !SHA256.test(value.liveRecoveryRoleAuthority.rawSha256 ?? '') ||
    value.liveRecoveryRoleAuthority.canonicalSha256 !==
      objectSha256(value.liveRecoveryRoleAuthority.value) ||
    !Number.isSafeInteger(value.liveRecoveryRoleAuthority.bytes) ||
    value.liveRecoveryRoleAuthority.bytes < 2 ||
    value.liveRecoveryRoleAuthority.bytes > MAX_DOCUMENT_BYTES ||
    value.liveRecoveryRoleAuthority.frozenRawSha256 !==
      value.request.recoveryRoleAuthority.frozen.rawSha256 ||
    value.liveRecoveryRoleAuthority.frozenCanonicalSha256 !==
      value.request.recoveryRoleAuthority.frozen.canonicalSha256 ||
    value.liveRecoveryRoleAuthority.effectivePermissionsSha256 !==
      value.request.recoveryRoleAuthority.frozen.effectivePermissionsSha256 ||
    value.liveRecoveryRoleAuthority.effectivePermissionsSha256 !==
      value.liveRecoveryRoleAuthority.value.effectivePermissionsSha256 ||
    value.liveRecoveryRoleAuthority.effectivePolicyProjectionSha256 !==
      value.request.recoveryRoleAuthority.frozen.effectivePolicyProjectionSha256 ||
    value.liveRecoveryRoleAuthority.effectivePolicyProjectionSha256 !==
      value.liveRecoveryRoleAuthority.value.effectivePolicyProjectionSha256 ||
    value.policy !== STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT.policy ||
    value.prohibitedActions?.join('\0') !== PROHIBITED_ACTIONS.join('\0') ||
    !utc(value.createdAtUtc) ||
    Date.parse(value.createdAtUtc) < Date.parse(value.approval.approvedAtUtc) ||
    Date.parse(value.createdAtUtc) > Date.parse(value.approval.expiresAtUtc) ||
    value.containsSensitiveData !== false ||
    value.actorSha256 !== objectSha256(withoutDigest(value, 'actorSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ACTOR_INVALID');
  }
  if (
    intent !== undefined &&
    (validateReleaseReconciliationIntent(intent) !== intent ||
      !sameObject(intent.source, source) ||
      intent.authority.accountId !== value.authority.accountId ||
      intent.authority.region !== value.authority.region ||
      [intent.authority.rollbackRoleArn, intent.authority.journalRoleArn].includes(
        value.authority.recoveryRoleArn,
      ))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ACTOR_INTENT_MISMATCH');
  }
  return value;
};

export const createReleaseReconciliationRecoveryOutcome = ({
  actor,
  receiptSource,
  mode,
  completedAtUtc,
}) => {
  validateReleaseReconciliationRecoveryActor(actor);
  if (!RECOVERY_MODES.includes(mode) || !utc(completedAtUtc)) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_OUTCOME_INPUT_INVALID');
  }
  const receiptDocument = parseReleaseReconciliationRecoveryJson(
    receiptSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_RECEIPT_DOCUMENT_INVALID',
  );
  const receipt = validateReleaseReconciliationReceipt(receiptDocument.value);
  if (
    receipt.phase !== actor.phase ||
    !sameObject(receipt.source, actor.originalSource) ||
    receipt.originalJobConclusion !== actor.originalJobConclusion ||
    receipt.status !== 'TERMINAL_CANDIDATE_N_VERIFIED' ||
    receipt.eligibleForFence !== false ||
    Date.parse(completedAtUtc) < Date.parse(receipt.completedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_OUTCOME_RECEIPT_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_OUTCOME',
    status: 'CANDIDATE_N_VERIFIED_RELEASE_REMAINS_BLOCKED',
    mode,
    actor: { ...actor },
    originalSource: { ...actor.originalSource },
    receipt: {
      value: receipt,
      rawSha256: sha256(receiptDocument.bytes),
      canonicalSha256: objectSha256(receipt),
      bytes: receiptDocument.bytes.length,
    },
    proofExecutionBinding: {
      status:
        mode === 'FORWARD_CONVERGED'
          ? 'RECOVERY_ACTOR_BOUND_READ_ROLE_VERIFIED'
          : 'ORIGINAL_TERMINAL_REVALIDATED',
      recoveryActorSha256: mode === 'FORWARD_CONVERGED' ? actor.actorSha256 : null,
      readRoleArn: mode === 'FORWARD_CONVERGED' ? actor.request.configBinding.readRoleArn : null,
      phase: receipt.phase,
      intentSha256: receipt.journal.intentIndex.intentSha256,
      convergenceCompletedAtUtc: receipt.runtime.convergenceCompletedAtUtc,
      driftProofSha256: receipt.runtime.driftProofSha256,
      smokeProofSha256: receipt.runtime.smokeProofSha256,
      smokeAuthorizationUsageSha256: objectSha256(receipt.runtime.smokeAuthorizationUsage),
    },
    runtimeState: 'EXACT_CANDIDATE_N',
    fenceWritesPerformed: 0,
    publicationWritesPerformed: 0,
    rollbackToPreviousOperationsPerformed: 0,
    guardDecision: 'BLOCK_UNTIL_PRESERVATION_AND_CLEANUP_CLOSE',
    completedAtUtc,
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationRecoveryOutcome({
    ...body,
    outcomeSha256: objectSha256(body),
  });
};

export const validateReleaseReconciliationRecoveryOutcome = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'mode',
      'actor',
      'originalSource',
      'receipt',
      'proofExecutionBinding',
      'runtimeState',
      'fenceWritesPerformed',
      'publicationWritesPerformed',
      'rollbackToPreviousOperationsPerformed',
      'guardDecision',
      'completedAtUtc',
      'containsSensitiveData',
      'outcomeSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_OUTCOME' ||
    value.status !== 'CANDIDATE_N_VERIFIED_RELEASE_REMAINS_BLOCKED' ||
    !RECOVERY_MODES.includes(value.mode) ||
    validateReleaseReconciliationRecoveryActor(value.actor) !== value.actor ||
    !sameObject(value.originalSource, value.actor.originalSource) ||
    !exactKeys(value.receipt, ['value', 'rawSha256', 'canonicalSha256', 'bytes']) ||
    validateReleaseReconciliationReceipt(value.receipt.value) !== value.receipt.value ||
    value.receipt.value.phase !== value.actor.phase ||
    value.receipt.value.originalJobConclusion !== value.actor.originalJobConclusion ||
    value.receipt.value.eligibleForFence !== false ||
    !SHA256.test(value.receipt.rawSha256 ?? '') ||
    value.receipt.canonicalSha256 !== objectSha256(value.receipt.value) ||
    !Number.isSafeInteger(value.receipt.bytes) ||
    value.receipt.bytes < 2 ||
    value.receipt.bytes > MAX_DOCUMENT_BYTES ||
    !exactKeys(value.proofExecutionBinding, [
      'status',
      'recoveryActorSha256',
      'readRoleArn',
      'phase',
      'intentSha256',
      'convergenceCompletedAtUtc',
      'driftProofSha256',
      'smokeProofSha256',
      'smokeAuthorizationUsageSha256',
    ]) ||
    !(
      (value.mode === 'FORWARD_CONVERGED' &&
        value.proofExecutionBinding.status === 'RECOVERY_ACTOR_BOUND_READ_ROLE_VERIFIED' &&
        value.proofExecutionBinding.recoveryActorSha256 === value.actor.actorSha256 &&
        value.proofExecutionBinding.readRoleArn ===
          value.actor.request.configBinding.readRoleArn) ||
      (value.mode === 'TERMINAL_RESUMED' &&
        value.proofExecutionBinding.status === 'ORIGINAL_TERMINAL_REVALIDATED' &&
        value.proofExecutionBinding.recoveryActorSha256 === null &&
        value.proofExecutionBinding.readRoleArn === null)
    ) ||
    value.proofExecutionBinding.phase !== value.receipt.value.phase ||
    value.proofExecutionBinding.intentSha256 !==
      value.receipt.value.journal.intentIndex.intentSha256 ||
    value.proofExecutionBinding.convergenceCompletedAtUtc !==
      value.receipt.value.runtime.convergenceCompletedAtUtc ||
    value.proofExecutionBinding.driftProofSha256 !== value.receipt.value.runtime.driftProofSha256 ||
    value.proofExecutionBinding.smokeProofSha256 !== value.receipt.value.runtime.smokeProofSha256 ||
    value.proofExecutionBinding.smokeAuthorizationUsageSha256 !==
      objectSha256(value.receipt.value.runtime.smokeAuthorizationUsage) ||
    value.runtimeState !== 'EXACT_CANDIDATE_N' ||
    value.fenceWritesPerformed !== 0 ||
    value.publicationWritesPerformed !== 0 ||
    value.rollbackToPreviousOperationsPerformed !== 0 ||
    value.guardDecision !== 'BLOCK_UNTIL_PRESERVATION_AND_CLEANUP_CLOSE' ||
    !utc(value.completedAtUtc) ||
    Date.parse(value.completedAtUtc) < Date.parse(value.receipt.value.completedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.outcomeSha256 !== objectSha256(withoutDigest(value, 'outcomeSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_OUTCOME_INVALID');
  }
  return value;
};

const validateSnapshotParameter = (value, root) => {
  const escapedRoot = root.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const allowedName = new RegExp(
    `^${escapedRoot}/(?:owner|intent/[0-9]{4}|(?:rollback-check|rollback-resilience)/terminal|runtime-proofs/(?:rollback-check|rollback-resilience)/(?:drift|smoke)/[0-9a-f]{64}/(?:index|chunk/[0-9]{4}-[0-9a-f]{64}))$`,
    'u',
  );
  if (
    !exactKeys(value, ['name', 'value', 'version', 'rawSha256', 'bytes']) ||
    typeof value.name !== 'string' ||
    !allowedName.test(value.name) ||
    typeof value.value !== 'string' ||
    Buffer.byteLength(value.value, 'utf8') !== value.bytes ||
    value.bytes < 1 ||
    value.bytes > MAX_PARAMETER_BYTES ||
    value.version !== 1 ||
    value.rawSha256 !== sha256(Buffer.from(value.value, 'utf8'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SNAPSHOT_PARAMETER_INVALID');
  }
  try {
    assertSanitizedArtifactText(value.value, value.name);
  } catch (error) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SNAPSHOT_SENSITIVE', error);
  }
  return value;
};

export const createReleaseReconciliationRecoverySnapshot = ({
  outcome,
  parameters,
  capturedAtUtc,
}) => {
  validateReleaseReconciliationRecoveryOutcome(outcome);
  const root = recoveryRoot(outcome.originalSource);
  if (
    !Array.isArray(parameters) ||
    parameters.length < 3 ||
    parameters.length > MAX_PARAMETERS ||
    !utc(capturedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SNAPSHOT_INPUT_INVALID');
  }
  const normalized = parameters
    .map((parameter) => ({
      name: parameter.name,
      value: parameter.value,
      version: parameter.version,
      rawSha256: sha256(Buffer.from(parameter.value ?? '', 'utf8')),
      bytes: Buffer.byteLength(parameter.value ?? '', 'utf8'),
    }))
    .toSorted((left, right) => left.name.localeCompare(right.name));
  normalized.forEach((parameter) => validateSnapshotParameter(parameter, root));
  const names = normalized.map(({ name }) => name);
  const receipt = outcome.receipt.value;
  const requiredNames = [
    receipt.journal.ownerParameterName,
    ...receipt.journal.ownerIndex.intentChunks.map(({ parameterName }) => parameterName),
    ...receipt.journal.runtimeProofParameters.map(({ name }) => name),
    receipt.journal.terminalParameterName,
  ];
  if (
    new Set(names).size !== names.length ||
    requiredNames.some((name) => !names.includes(name)) ||
    Date.parse(capturedAtUtc) < Date.parse(outcome.completedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SNAPSHOT_SET_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_JOURNAL_SNAPSHOT',
    status: 'RAW_VALUES_PRESERVED_BEFORE_DELETE',
    actor: outcome.actor,
    originalSource: outcome.originalSource,
    outcomeSha256: outcome.outcomeSha256,
    reconciliationRootPrefix: root,
    parameters: normalized,
    parameterCount: normalized.length,
    parameterBindingsSha256: objectSha256(
      normalized.map(({ name, version, rawSha256, bytes }) => ({
        name,
        version,
        rawSha256,
        bytes,
      })),
    ),
    preservationArtifactName: preservationArtifactName(outcome.actor),
    capturedAtUtc,
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationRecoverySnapshot({
    ...body,
    snapshotSha256: objectSha256(body),
  });
};

export const validateReleaseReconciliationRecoverySnapshot = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'actor',
      'originalSource',
      'outcomeSha256',
      'reconciliationRootPrefix',
      'parameters',
      'parameterCount',
      'parameterBindingsSha256',
      'preservationArtifactName',
      'capturedAtUtc',
      'containsSensitiveData',
      'snapshotSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_JOURNAL_SNAPSHOT' ||
    value.status !== 'RAW_VALUES_PRESERVED_BEFORE_DELETE' ||
    validateReleaseReconciliationRecoveryActor(value.actor) !== value.actor ||
    !sameObject(value.originalSource, value.actor.originalSource) ||
    !SHA256.test(value.outcomeSha256 ?? '') ||
    value.reconciliationRootPrefix !== recoveryRoot(value.originalSource) ||
    !Array.isArray(value.parameters) ||
    value.parameters.length < 3 ||
    value.parameters.length > MAX_PARAMETERS ||
    value.parameterCount !== value.parameters.length ||
    value.parameters.map(({ name }) => name).join('\0') !==
      value.parameters
        .map(({ name }) => name)
        .toSorted((left, right) => left.localeCompare(right))
        .join('\0') ||
    new Set(value.parameters.map(({ name }) => name)).size !== value.parameters.length ||
    value.parameterBindingsSha256 !==
      objectSha256(
        value.parameters.map(({ name, version, rawSha256, bytes }) => ({
          name,
          version,
          rawSha256,
          bytes,
        })),
      ) ||
    value.preservationArtifactName !== preservationArtifactName(value.actor) ||
    !utc(value.capturedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.snapshotSha256 !== objectSha256(withoutDigest(value, 'snapshotSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SNAPSHOT_INVALID');
  }
  value.parameters.forEach((parameter) =>
    validateSnapshotParameter(parameter, value.reconciliationRootPrefix),
  );
  return value;
};

export const validateReleaseReconciliationRecoverySnapshotForOutcome = (snapshot, outcome) => {
  validateReleaseReconciliationRecoverySnapshot(snapshot);
  validateReleaseReconciliationRecoveryOutcome(outcome);
  const receipt = outcome.receipt.value;
  const snapshotNames = new Set(snapshot.parameters.map(({ name }) => name));
  const requiredNames = [
    receipt.journal.ownerParameterName,
    ...receipt.journal.ownerIndex.intentChunks.map(({ parameterName }) => parameterName),
    ...receipt.journal.runtimeProofParameters.map(({ name }) => name),
    receipt.journal.terminalParameterName,
  ];
  if (
    snapshot.outcomeSha256 !== outcome.outcomeSha256 ||
    !sameObject(snapshot.actor, outcome.actor) ||
    requiredNames.some((name) => !snapshotNames.has(name))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SNAPSHOT_OUTCOME_MISMATCH');
  }
  return snapshot;
};

const parsePreservationSources = (sources) => {
  if (
    !exactKeys(
      sources,
      PRESERVATION_FILES.map(({ label }) => label),
    )
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_PRESERVATION_SOURCES_INVALID');
  }
  return Object.fromEntries(
    PRESERVATION_FILES.map(({ label }) => [
      label,
      parseReleaseReconciliationRecoveryJson(
        sources[label],
        `E7_RELEASE_RECONCILIATION_RECOVERY_PRESERVATION_${label.toUpperCase()}_INVALID`,
      ),
    ]),
  );
};

const validatePreservationDocuments = (documents) => {
  const intent = validateReleaseReconciliationIntent(documents.intent.value);
  const receipt = validateReleaseReconciliationReceipt(documents.receipt.value);
  const outcome = validateReleaseReconciliationRecoveryOutcome(documents.outcome.value);
  const snapshot = validateReleaseReconciliationRecoverySnapshotForOutcome(
    documents.snapshot.value,
    outcome,
  );
  const recoveryRoleAuthority = validateReleaseReconciliationRecoveryRoleEffectivePermissions(
    documents.recoveryRoleAuthority.value,
    {
      roleArn: outcome.actor.authority.recoveryRoleArn,
      permissionsBoundaryArn: outcome.actor.request.recoveryRoleAuthority.permissionsBoundaryArn,
      basePolicy: outcome.actor.request.recoveryRoleAuthority.basePolicy,
    },
  );
  if (
    !sameObject(receipt, outcome.receipt.value) ||
    !sameObject(intent, receipt.journal.intentIndex) ||
    !sameObject(intent.source, outcome.originalSource) ||
    snapshot.outcomeSha256 !== outcome.outcomeSha256 ||
    sha256(documents.recoveryRoleAuthority.bytes) !==
      outcome.actor.liveRecoveryRoleAuthority.rawSha256 ||
    objectSha256(recoveryRoleAuthority) !==
      outcome.actor.liveRecoveryRoleAuthority.canonicalSha256 ||
    documents.recoveryRoleAuthority.bytes.length !==
      outcome.actor.liveRecoveryRoleAuthority.bytes ||
    recoveryRoleAuthority.effectivePermissionsSha256 !==
      outcome.actor.liveRecoveryRoleAuthority.effectivePermissionsSha256 ||
    recoveryRoleAuthority.effectivePolicyProjectionSha256 !==
      outcome.actor.liveRecoveryRoleAuthority.effectivePolicyProjectionSha256
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_PRESERVATION_CAUSAL_MISMATCH');
  }
  return { intent, receipt, outcome, snapshot, recoveryRoleAuthority };
};

export const createReleaseReconciliationRecoveryPreservationIndex = ({ sources, createdAtUtc }) => {
  const documents = parsePreservationSources(sources);
  const { intent, receipt, outcome, snapshot } = validatePreservationDocuments(documents);
  if (!utc(createdAtUtc) || Date.parse(createdAtUtc) < Date.parse(snapshot.capturedAtUtc)) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_PRESERVATION_INPUT_INVALID');
  }
  const entries = PRESERVATION_FILES.map(({ label, path }) => ({
    label,
    path,
    rawSha256: sha256(documents[label].bytes),
    canonicalSha256: objectSha256(documents[label].value),
    bytes: documents[label].bytes.length,
  }));
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_PRESERVATION_INDEX',
    status: 'EXACT_RAW_JOURNAL_AND_CAUSAL_AUTHORITY_PRESERVED',
    originalSource: outcome.originalSource,
    recoveryActorSha256: outcome.actor.actorSha256,
    intentSha256: intent.intentSha256,
    receiptSha256: receipt.receiptSha256,
    outcomeSha256: outcome.outcomeSha256,
    snapshotSha256: snapshot.snapshotSha256,
    entries,
    entryCount: entries.length,
    entriesSha256: objectSha256(entries),
    artifactName: snapshot.preservationArtifactName,
    createdAtUtc,
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationRecoveryPreservationIndex({
    ...body,
    preservationIndexSha256: objectSha256(body),
  });
};

export const validateReleaseReconciliationRecoveryPreservationIndex = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'originalSource',
      'recoveryActorSha256',
      'intentSha256',
      'receiptSha256',
      'outcomeSha256',
      'snapshotSha256',
      'entries',
      'entryCount',
      'entriesSha256',
      'artifactName',
      'createdAtUtc',
      'containsSensitiveData',
      'preservationIndexSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_PRESERVATION_INDEX' ||
    value.status !== 'EXACT_RAW_JOURNAL_AND_CAUSAL_AUTHORITY_PRESERVED' ||
    validateReleaseReconciliationSource(value.originalSource) !== value.originalSource ||
    ![
      value.recoveryActorSha256,
      value.intentSha256,
      value.receiptSha256,
      value.outcomeSha256,
      value.snapshotSha256,
      value.entriesSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !Array.isArray(value.entries) ||
    value.entries.length !== PRESERVATION_FILES.length ||
    value.entries.some((entry, index) => {
      const descriptor = PRESERVATION_FILES[index];
      return (
        !exactKeys(entry, ['label', 'path', 'rawSha256', 'canonicalSha256', 'bytes']) ||
        entry.label !== descriptor.label ||
        entry.path !== descriptor.path ||
        !SHA256.test(entry.rawSha256 ?? '') ||
        !SHA256.test(entry.canonicalSha256 ?? '') ||
        !Number.isSafeInteger(entry.bytes) ||
        entry.bytes < 2 ||
        entry.bytes > MAX_DOCUMENT_BYTES
      );
    }) ||
    value.entryCount !== value.entries.length ||
    value.entriesSha256 !== objectSha256(value.entries) ||
    !/^stage7-release-reconciliation-recovery-preservation-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}$/u.test(
      value.artifactName ?? '',
    ) ||
    !utc(value.createdAtUtc) ||
    value.containsSensitiveData !== false ||
    value.preservationIndexSha256 !== objectSha256(withoutDigest(value, 'preservationIndexSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_PRESERVATION_INDEX_INVALID');
  }
  return value;
};

export const validateReleaseReconciliationRecoveryPreservationSources = ({ index, sources }) => {
  validateReleaseReconciliationRecoveryPreservationIndex(index);
  const documents = parsePreservationSources(sources);
  const { intent, receipt, outcome, snapshot } = validatePreservationDocuments(documents);
  const entries = PRESERVATION_FILES.map(({ label, path }) => ({
    label,
    path,
    rawSha256: sha256(documents[label].bytes),
    canonicalSha256: objectSha256(documents[label].value),
    bytes: documents[label].bytes.length,
  }));
  if (
    !sameObject(entries, index.entries) ||
    !sameObject(index.originalSource, outcome.originalSource) ||
    index.recoveryActorSha256 !== outcome.actor.actorSha256 ||
    index.intentSha256 !== intent.intentSha256 ||
    index.receiptSha256 !== receipt.receiptSha256 ||
    index.outcomeSha256 !== outcome.outcomeSha256 ||
    index.snapshotSha256 !== snapshot.snapshotSha256 ||
    index.artifactName !== snapshot.preservationArtifactName ||
    Date.parse(index.createdAtUtc) < Date.parse(snapshot.capturedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_PRESERVATION_INDEX_MISMATCH');
  }
  return { intent, receipt, outcome, snapshot };
};

export const createReleaseReconciliationRecoveryArtifactBinding = ({
  preservationIndex,
  metadataSource,
  archiveSource,
  expectedRunId,
  capturedAtUtc,
}) => {
  validateReleaseReconciliationRecoveryPreservationIndex(preservationIndex);
  const metadata = parseReleaseReconciliationRecoveryJson(
    metadataSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ARTIFACT_METADATA_INVALID',
  );
  const value = metadata.value;
  const archive = Buffer.isBuffer(archiveSource)
    ? Buffer.from(archiveSource)
    : Buffer.from(archiveSource ?? '');
  const createdAtUtc = normalizeApiUtc(value?.created_at);
  const expiresAtUtc = normalizeApiUtc(value?.expires_at);
  if (
    !RUN_ID.test(expectedRunId ?? '') ||
    !utc(capturedAtUtc) ||
    !Number.isSafeInteger(value?.id) ||
    value.id < 1 ||
    value.name !== preservationIndex.artifactName ||
    !ARTIFACT_DIGEST.test(value.digest ?? '') ||
    archive.length < 22 ||
    archive.length > MAX_DOCUMENT_BYTES ||
    value.digest !== `sha256:${sha256(archive)}` ||
    value.expired !== false ||
    !Number.isSafeInteger(value.size_in_bytes) ||
    value.size_in_bytes < 1 ||
    value.size_in_bytes !== archive.length ||
    createdAtUtc === null ||
    expiresAtUtc === null ||
    Date.parse(expiresAtUtc) <= Date.parse(createdAtUtc) ||
    String(value.workflow_run?.id) !== expectedRunId ||
    Date.parse(capturedAtUtc) < Date.parse(createdAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ARTIFACT_METADATA_INVALID');
  }
  const body = {
    name: value.name,
    id: value.id,
    digest: value.digest,
    workflowRunId: expectedRunId,
    sizeInBytes: value.size_in_bytes,
    createdAtUtc,
    expiresAtUtc,
    metadataRawSha256: sha256(metadata.bytes),
    archiveRawSha256: sha256(archive),
    archiveBytes: archive.length,
    capturedAtUtc,
    externalRequests: 1,
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationRecoveryArtifactBinding(
    {
      ...body,
      bindingSha256: objectSha256(body),
    },
    preservationIndex.artifactName,
  );
};

export const validateReleaseReconciliationRecoveryArtifactBinding = (
  value,
  expectedName = undefined,
) => {
  if (
    !exactKeys(value, [
      'name',
      'id',
      'digest',
      'workflowRunId',
      'sizeInBytes',
      'createdAtUtc',
      'expiresAtUtc',
      'metadataRawSha256',
      'archiveRawSha256',
      'archiveBytes',
      'capturedAtUtc',
      'externalRequests',
      'containsSensitiveData',
      'bindingSha256',
    ]) ||
    (expectedName !== undefined && value.name !== expectedName) ||
    !/^stage7-release-reconciliation-recovery-preservation-[1-9][0-9]{0,19}-[1-9][0-9]{0,2}$/u.test(
      value.name ?? '',
    ) ||
    !Number.isSafeInteger(value.id) ||
    value.id < 1 ||
    !ARTIFACT_DIGEST.test(value.digest ?? '') ||
    !RUN_ID.test(value.workflowRunId ?? '') ||
    !Number.isSafeInteger(value.sizeInBytes) ||
    value.sizeInBytes < 1 ||
    !utc(value.createdAtUtc) ||
    !utc(value.expiresAtUtc) ||
    Date.parse(value.expiresAtUtc) <= Date.parse(value.createdAtUtc) ||
    !SHA256.test(value.metadataRawSha256 ?? '') ||
    !SHA256.test(value.archiveRawSha256 ?? '') ||
    value.digest !== `sha256:${value.archiveRawSha256}` ||
    !Number.isSafeInteger(value.archiveBytes) ||
    value.archiveBytes < 22 ||
    value.archiveBytes > MAX_DOCUMENT_BYTES ||
    !utc(value.capturedAtUtc) ||
    Date.parse(value.capturedAtUtc) < Date.parse(value.createdAtUtc) ||
    value.externalRequests !== 1 ||
    value.containsSensitiveData !== false ||
    value.bindingSha256 !== objectSha256(withoutDigest(value, 'bindingSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ARTIFACT_BINDING_INVALID');
  }
  return value;
};

const validateCleanupRoleAuthority = (value, actor, expectedRoleArn) => {
  const role = ROLE_ARN.exec(value?.roleArn ?? '');
  const boundary = POLICY_ARN.exec(value?.permissionsBoundaryArn ?? '');
  if (
    !exactKeys(value, [
      'roleArn',
      'permissionsBoundaryArn',
      'effectivePolicyProjectionSha256',
      'frozenEffectivePermissionsSha256',
      'liveEffectivePermissionsSha256',
      'frozenRawSha256',
      'liveRawSha256',
      'liveCanonicalSha256',
      'liveSourceBindingCount',
    ]) ||
    role?.[1] !== actor.authority.accountId ||
    boundary?.[1] !== actor.authority.accountId ||
    value.roleArn !== expectedRoleArn ||
    value.roleArn === actor.authority.recoveryRoleArn ||
    [
      value.effectivePolicyProjectionSha256,
      value.frozenEffectivePermissionsSha256,
      value.liveEffectivePermissionsSha256,
      value.frozenRawSha256,
      value.liveRawSha256,
      value.liveCanonicalSha256,
    ].some((digest) => !SHA256.test(digest ?? '')) ||
    !Number.isSafeInteger(value.liveSourceBindingCount) ||
    value.liveSourceBindingCount < 6 ||
    value.liveSourceBindingCount > 100
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLEANUP_ROLE_AUTHORITY_INVALID');
  }
  return value;
};

export const createReleaseReconciliationRecoveryClosure = ({
  cleanupActor,
  outcome,
  snapshot,
  preservationIndex,
  preservationArtifact,
  cleanupRoleAuthority,
  deletedParameterNames,
  residualParameterNames,
  completedAtUtc,
}) => {
  validateReleaseReconciliationRecoveryActor(cleanupActor);
  validateReleaseReconciliationRecoveryOutcome(outcome);
  validateReleaseReconciliationRecoverySnapshotForOutcome(snapshot, outcome);
  validateReleaseReconciliationRecoveryPreservationIndex(preservationIndex);
  validateCleanupRoleAuthority(
    cleanupRoleAuthority,
    cleanupActor,
    outcome.receipt.value.journal.intentIndex.authority.journalRoleArn,
  );
  if (
    !sameObject(cleanupActor.originalSource, outcome.originalSource) ||
    cleanupActor.phase !== outcome.actor.phase ||
    cleanupActor.originalJobConclusion !== outcome.actor.originalJobConclusion ||
    snapshot.outcomeSha256 !== outcome.outcomeSha256 ||
    preservationIndex.outcomeSha256 !== outcome.outcomeSha256 ||
    preservationIndex.snapshotSha256 !== snapshot.snapshotSha256 ||
    preservationIndex.artifactName !== snapshot.preservationArtifactName ||
    validateReleaseReconciliationRecoveryArtifactBinding(
      preservationArtifact,
      snapshot.preservationArtifactName,
    ) !== preservationArtifact ||
    !Array.isArray(deletedParameterNames) ||
    deletedParameterNames.join('\0') !== snapshot.parameters.map(({ name }) => name).join('\0') ||
    !Array.isArray(residualParameterNames) ||
    residualParameterNames.length !== 0 ||
    !utc(completedAtUtc) ||
    Date.parse(completedAtUtc) < Date.parse(snapshot.capturedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLOSURE_INPUT_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_CLOSURE',
    status: 'CANDIDATE_N_VERIFIED_JOURNAL_PRESERVED_AND_CLEANED',
    cleanupActor,
    originalRecoveryActor: outcome.actor,
    originalSource: outcome.originalSource,
    phase: outcome.actor.phase,
    outcomeSha256: outcome.outcomeSha256,
    receiptSha256: outcome.receipt.value.receiptSha256,
    snapshotSha256: snapshot.snapshotSha256,
    preservationIndexSha256: preservationIndex.preservationIndexSha256,
    preservationArtifact,
    journalCleanupRoleArn: outcome.receipt.value.journal.intentIndex.authority.journalRoleArn,
    cleanupRoleAuthority,
    cleanup: {
      deletedParameterNames,
      deletedParameterCount: deletedParameterNames.length,
      residualParameterNames,
      residualParameterCount: 0,
    },
    fenceWritesPerformed: 0,
    publicationWritesPerformed: 0,
    rollbackToPreviousOperationsPerformed: 0,
    releaseDecision: 'ORIGINAL_RELEASE_REMAINS_BLOCKED_NEW_DISPATCH_MAY_REEVALUATE',
    closureArtifactName: closureArtifactName(cleanupActor),
    completedAtUtc,
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationRecoveryClosure({
    ...body,
    closureSha256: objectSha256(body),
  });
};

export const validateReleaseReconciliationRecoveryClosure = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'cleanupActor',
      'originalRecoveryActor',
      'originalSource',
      'phase',
      'outcomeSha256',
      'receiptSha256',
      'snapshotSha256',
      'preservationIndexSha256',
      'preservationArtifact',
      'journalCleanupRoleArn',
      'cleanupRoleAuthority',
      'cleanup',
      'fenceWritesPerformed',
      'publicationWritesPerformed',
      'rollbackToPreviousOperationsPerformed',
      'releaseDecision',
      'closureArtifactName',
      'completedAtUtc',
      'containsSensitiveData',
      'closureSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_RECOVERY_CLOSURE' ||
    value.status !== 'CANDIDATE_N_VERIFIED_JOURNAL_PRESERVED_AND_CLEANED' ||
    validateReleaseReconciliationRecoveryActor(value.cleanupActor) !== value.cleanupActor ||
    validateReleaseReconciliationRecoveryActor(value.originalRecoveryActor) !==
      value.originalRecoveryActor ||
    !sameObject(value.originalSource, value.originalRecoveryActor.originalSource) ||
    !sameObject(value.originalSource, value.cleanupActor.originalSource) ||
    value.phase !== value.originalRecoveryActor.phase ||
    value.phase !== value.cleanupActor.phase ||
    ![
      value.outcomeSha256,
      value.receiptSha256,
      value.snapshotSha256,
      value.preservationIndexSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    validateReleaseReconciliationRecoveryArtifactBinding(
      value.preservationArtifact,
      preservationArtifactName(value.originalRecoveryActor),
    ) !== value.preservationArtifact ||
    ROLE_ARN.exec(value.journalCleanupRoleArn ?? '')?.[1] !==
      value.cleanupActor.authority.accountId ||
    value.journalCleanupRoleArn === value.cleanupActor.authority.recoveryRoleArn ||
    validateCleanupRoleAuthority(
      value.cleanupRoleAuthority,
      value.cleanupActor,
      value.journalCleanupRoleArn,
    ) !== value.cleanupRoleAuthority ||
    !exactKeys(value.cleanup, [
      'deletedParameterNames',
      'deletedParameterCount',
      'residualParameterNames',
      'residualParameterCount',
    ]) ||
    !Array.isArray(value.cleanup.deletedParameterNames) ||
    value.cleanup.deletedParameterCount !== value.cleanup.deletedParameterNames.length ||
    new Set(value.cleanup.deletedParameterNames).size !==
      value.cleanup.deletedParameterNames.length ||
    !Array.isArray(value.cleanup.residualParameterNames) ||
    value.cleanup.residualParameterNames.length !== 0 ||
    value.cleanup.residualParameterCount !== 0 ||
    value.fenceWritesPerformed !== 0 ||
    value.publicationWritesPerformed !== 0 ||
    value.rollbackToPreviousOperationsPerformed !== 0 ||
    value.releaseDecision !== 'ORIGINAL_RELEASE_REMAINS_BLOCKED_NEW_DISPATCH_MAY_REEVALUATE' ||
    value.closureArtifactName !== closureArtifactName(value.cleanupActor) ||
    !utc(value.completedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.closureSha256 !== objectSha256(withoutDigest(value, 'closureSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLOSURE_INVALID');
  }
  return value;
};

export const releaseReconciliationRecoveryArtifactNames = (actor) => {
  validateReleaseReconciliationRecoveryActor(actor);
  return {
    preservation: preservationArtifactName(actor),
    closure: closureArtifactName(actor),
  };
};
