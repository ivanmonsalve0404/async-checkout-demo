import { Buffer } from 'node:buffer';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { sha256 } from '../stage6/lib/evidence.mjs';
import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256 } from './core.mjs';
import { validateReleaseSuccessorCompletionFence } from './release-successor-fence-contract.mjs';
import { readReleaseSuccessorZipEntries } from './release-successor-zip.mjs';

export const RECOVERY_REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
export const RECOVERY_SOURCE_WORKFLOW = '.github/workflows/release.yml';
export const RECOVERY_SOURCE_WORKFLOW_NAME = 'Stage 7 Release';
export const RECOVERY_WORKFLOW =
  '.github/workflows/stage7-release-successor-publication-recovery.yml';
export const RECOVERY_ENVIRONMENT = 'assessment-release-successor-publication-recovery';
export const RECOVERY_BLOCKER = 'BLK-E7-RELEASE-SUCCESSOR-PUBLICATION-ATOMICITY';
export const RECOVERY_CLOSEOUT_BLOCKER = 'BLK-E7-RELEASE-SUCCESSOR-RECOVERY-CLOSEOUT-AUTHORITY';
export const RECOVERY_AUTHORITY_KIND = 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_AUTHORITY';
export const RECOVERY_AUTHORITY_BASENAME = 'release-successor-publication-recovery-authority.json';
export const RECOVERY_PLAN_BASENAME = 'release-successor-publication-recovery-plan.json';
export const RECOVERY_RECEIPT_BASENAME = 'release-successor-publication-recovery-receipt.json';
export const RECOVERY_INTAKE_BASENAME =
  'release-successor-publication-recovery-post-success-intake.json';
export const RECOVERY_REQUIRED_PROTECTED_VARIABLES = Object.freeze([
  'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_ROLE_ARN',
  'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN',
  'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_AUTHORITY_B64',
  'STAGE7_CONFIG_B64',
  'STAGE7_EXTERNAL_AUTHORIZATIONS_B64',
]);
export const RECOVERY_IAM_READ_ACTIONS = Object.freeze([
  'iam:GetPolicy',
  'iam:GetPolicyVersion',
  'iam:GetRole',
  'iam:GetRolePolicy',
  'iam:ListAttachedRolePolicies',
  'iam:ListRolePolicies',
  'ssm:GetParameter',
  'sts:GetCallerIdentity',
]);
export const RECOVERY_ROLE_INLINE_POLICY_NAME =
  'stage7-release-successor-publication-recovery-base';
export const RECOVERY_INTERNAL_ARTIFACTS = Object.freeze(
  [
    'release-external-authorization-request',
    'release-observability-pending',
    'release-sandbox-execution-request',
  ].toSorted(),
);
export const RECOVERY_OPTIONAL_INCOMPLETE_SUMMARY_ARTIFACTS = Object.freeze([
  'stage7-release-authorities',
  'stage7-release-reports',
]);
export const RECOVERY_SOURCE_FENCE_ARTIFACT = 'stage7-release-successor-fence';
export const RECOVERY_SOURCE_PUBLICATION_ARTIFACT = 'stage7-publication';
export const RECOVERY_CRASH_WINDOWS = Object.freeze([
  'FENCE_DURABLE_SOURCE_ARTIFACT_MISSING',
  'SOURCE_FENCE_PRESENT_PUBLICATION_INCOMPLETE',
  'SOURCE_PUBLICATION_PRESENT_SUMMARY_INCOMPLETE',
]);
export const RECOVERY_PUBLICATION_FILES = Object.freeze(
  [
    'publication.json',
    'publication-operation.json',
    'publication-plan.json',
    'publication-proof.json',
    'publication-target-proof.json',
  ].toSorted(),
);

export const RECOVERY_SOURCE_ARTIFACTS = Object.freeze(
  [
    'stage7-activation',
    'stage7-api',
    'stage7-approval',
    'stage7-aws-auth',
    'stage7-candidate',
    'stage7-candidate-manifest',
    'stage7-candidate-verification',
    'stage7-data',
    'stage7-edge-security',
    'stage7-external-authorization',
    'stage7-infra-diff',
    'stage7-infra-synth',
    'stage7-integrity',
    'stage7-observability',
    'stage7-prefreeze',
    'stage7-previous-release',
    'stage7-quality',
    'stage7-recovery-probe',
    'stage7-release-metadata',
    'stage7-release-plan',
    'stage7-release-reconciliation',
    'stage7-rollback',
    'stage7-rollback-resilience',
    'stage7-sandbox',
    'stage7-security',
    'stage7-smoke',
    'stage7-web',
  ].toSorted(),
);

export const RECOVERY_ALLOWED_ACTIONS = Object.freeze([
  'READ_EXACT_IMMUTABLE_FENCE',
  'REHYDRATE_EXACT_FENCE_EVIDENCE',
  'PRESERVE_RECOVERY_EVIDENCE',
  'VERIFY_OR_CREATE_MISSING_GITHUB_PUBLICATION',
  'VERIFY_EXACT_GITHUB_PUBLICATION',
  'EMIT_RECOVERY_RECEIPT',
]);

export const RECOVERY_FORBIDDEN_ACTIONS = Object.freeze([
  'DELETE_ANY_AWS_RESOURCE',
  'DELETE_OR_OVERWRITE_IMMUTABLE_FENCE',
  'DEPLOY_OR_ROLL_BACK_AWS',
  'FABRICATE_SOURCE_RUN_SUCCESS',
  'MUTATE_RELEASE_IDENTITY',
  'WRITE_ANY_AWS_RESOURCE',
]);

export const RECOVERY_FORWARD_STEPS = Object.freeze([
  'VALIDATE_SEPARATE_RECOVERY_AUTHORITY_BEFORE_EXTERNAL_ACCESS',
  'OBSERVE_EXACT_FAILED_SOURCE_ATTEMPT',
  'VERIFY_EXACT_LIVE_IAM_BASE_AND_SESSION_SUBSET',
  'READ_AND_VERIFY_IMMUTABLE_FENCE_VERSION_1',
  'REHYDRATE_EXACT_FENCE_BYTES',
  'PRESERVE_AUTHORIZED_RECOVERY_PLAN',
  'VALIDATE_ROUTE_SPECIFIC_SOURCE_EVIDENCE',
  'REDOWNLOAD_AND_HASH_VERIFY_27_SOURCE_ARTIFACTS',
  'REVALIDATE_ORIGINAL_PUBLICATION_PRECONDITIONS',
  'VERIFY_EXACT_OR_CREATE_ONLY_WHEN_ROUTE_AUTHORIZES',
  'VERIFY_EXACT_PUBLICATION_RESULT',
  'EMIT_IMMUTABLE_RECOVERY_RECEIPT',
  'PRESERVE_RECOVERY_RESULT_SUPPLEMENT',
]);

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const DIGEST = /^sha256:[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const AWS_ACCOUNT = /^[0-9]{12}$/u;
const AWS_REGION =
  /^(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9]$/u;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/u;
const ALIAS = /^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$/u;
const ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/([A-Za-z0-9+=,.@_/-]{1,512})$/u;
const BOUNDARY_ARN = /^arn:aws:iam::([0-9]{12}):policy\/([A-Za-z0-9+=,.@_/-]{1,512})$/u;

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const exactArray = (actual, expected) =>
  Array.isArray(actual) && canonicalJson(actual) === canonicalJson(expected);
const parseJson = (source, code) => {
  try {
    const bytes = Buffer.isBuffer(source) ? source : Buffer.from(source ?? '', 'utf8');
    return { bytes, value: parseStrictJsonSource(bytes, { scanForbiddenData: false }) };
  } catch {
    throw new Stage7PublicationRecoveryContractError(code);
  }
};
const withoutDigest = (value, key) => {
  const body = { ...value };
  delete body[key];
  return body;
};
const asRunId = (value) => String(value ?? '');
const normalizeJobs = (value) => {
  if (Array.isArray(value)) return value.flatMap(normalizeJobs);
  if (Array.isArray(value?.jobs)) return value.jobs;
  return [];
};
const normalizeArtifacts = (value) => {
  if (Array.isArray(value)) return value.flatMap(normalizeArtifacts);
  if (Array.isArray(value?.artifacts)) return value.artifacts;
  return [];
};
const dateMillis = (value) => (ISO_UTC.test(value ?? '') ? Date.parse(value) : Number.NaN);

export class Stage7PublicationRecoveryContractError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7PublicationRecoveryContractError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7PublicationRecoveryContractError(code);
};

export const recoveryFenceParameterName = ({ candidateSha, sourceRunId }) =>
  `/checkout/stage7/release-fence/${candidateSha}/${sourceRunId}`;

export const recoveryIdempotencyKey = ({ candidateSha, releaseId, sourceRunId, fenceSha256 }) =>
  sha256(
    canonicalJson({
      candidateSha,
      fenceSha256,
      releaseId,
      repository: RECOVERY_REPOSITORY,
      sourceRunAttempt: 1,
      sourceRunId: String(sourceRunId),
    }),
  );

export const expectedRecoveryTrustPolicy = ({ awsAccountId }) => ({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'GitHubProtectedPublicationRecoveryOnly',
      Effect: 'Allow',
      Principal: {
        Federated: `arn:aws:iam::${awsAccountId}:oidc-provider/token.actions.githubusercontent.com`,
      },
      Action: 'sts:AssumeRoleWithWebIdentity',
      Condition: {
        StringEquals: {
          'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          'token.actions.githubusercontent.com:sub': `repo:${RECOVERY_REPOSITORY}:environment:${RECOVERY_ENVIRONMENT}`,
        },
      },
    },
  ],
});

export const expectedRecoveryBoundaryPolicy = ({
  awsAccountId,
  awsRegion,
  recoveryRoleArn,
  permissionsBoundaryArn,
}) => ({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'ReadCallerIdentity',
      Effect: 'Allow',
      Action: 'sts:GetCallerIdentity',
      Resource: '*',
    },
    {
      Sid: 'ReadOwnRecoveryRole',
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
      Sid: 'ReadExactRecoveryBoundary',
      Effect: 'Allow',
      Action: ['iam:GetPolicy', 'iam:GetPolicyVersion'],
      Resource: permissionsBoundaryArn,
    },
    {
      Sid: 'ReadExactImmutableFence',
      Effect: 'Allow',
      Action: 'ssm:GetParameter',
      Resource: `arn:aws:ssm:${awsRegion}:${awsAccountId}:parameter/checkout/stage7/release-fence/*`,
    },
  ],
});

export const expectedRecoverySessionPolicy = ({
  awsAccountId,
  awsRegion,
  candidateSha,
  sourceRunId,
  recoveryRoleArn,
  permissionsBoundaryArn,
}) => ({
  Version: '2012-10-17',
  Statement: [
    {
      Sid: 'ReadCallerIdentity',
      Effect: 'Allow',
      Action: 'sts:GetCallerIdentity',
      Resource: '*',
    },
    {
      Sid: 'ReadOwnRecoveryRole',
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
      Sid: 'ReadExactRecoveryBoundary',
      Effect: 'Allow',
      Action: ['iam:GetPolicy', 'iam:GetPolicyVersion'],
      Resource: permissionsBoundaryArn,
    },
    {
      Sid: 'ReadExactImmutableFence',
      Effect: 'Allow',
      Action: 'ssm:GetParameter',
      Resource: `arn:aws:ssm:${awsRegion}:${awsAccountId}:parameter${recoveryFenceParameterName({ candidateSha, sourceRunId })}`,
    },
  ],
});

export const recoverySessionIsSubsetOfBase = ({ basePolicy, sessionPolicy }) => {
  const base = new Map(
    (basePolicy?.Statement ?? []).map((statement) => [statement.Sid, statement]),
  );
  if (
    !Array.isArray(sessionPolicy?.Statement) ||
    sessionPolicy.Statement.length !== base.size ||
    sessionPolicy.Version !== basePolicy?.Version
  ) {
    return false;
  }
  return sessionPolicy.Statement.every((statement) => {
    const parent = base.get(statement.Sid);
    if (
      parent?.Effect !== 'Allow' ||
      statement.Effect !== 'Allow' ||
      canonicalJson(statement.Action) !== canonicalJson(parent.Action)
    ) {
      return false;
    }
    if (statement.Sid !== 'ReadExactImmutableFence') {
      return canonicalJson(statement.Resource) === canonicalJson(parent.Resource);
    }
    return (
      typeof parent.Resource === 'string' &&
      parent.Resource.endsWith('/*') &&
      typeof statement.Resource === 'string' &&
      !statement.Resource.includes('*') &&
      statement.Resource.startsWith(parent.Resource.slice(0, -1))
    );
  });
};

export const validateRecoveryAuthority = (value, expected = {}) => {
  const routeAllowedActions =
    value?.crashWindow === RECOVERY_CRASH_WINDOWS[2]
      ? RECOVERY_ALLOWED_ACTIONS.filter(
          (action) => action !== 'VERIFY_OR_CREATE_MISSING_GITHUB_PUBLICATION',
        )
      : RECOVERY_ALLOWED_ACTIONS;
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'repository',
      'recoveryWorkflowPath',
      'protectedEnvironment',
      'sourceRunId',
      'sourceRunAttempt',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'crashWindow',
      'fenceSha256',
      'journalCleanupRoleSha256',
      'journalRoleAuthoritySha256',
      'recoveryRoleArnSha256',
      'permissionsBoundaryArnSha256',
      'allowedActions',
      'forbiddenActions',
      'approvedByAlias',
      'approvalReferenceSha256',
      'approvedAtUtc',
      'expiresAtUtc',
      'containsSensitiveData',
      'authoritySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== RECOVERY_AUTHORITY_KIND ||
    value.status !== 'APPROVED' ||
    value.repository !== RECOVERY_REPOSITORY ||
    value.recoveryWorkflowPath !== RECOVERY_WORKFLOW ||
    value.protectedEnvironment !== RECOVERY_ENVIRONMENT ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    value.sourceRunAttempt !== 1 ||
    !SHA.test(value.candidateSha ?? '') ||
    !RELEASE_ID.test(value.releaseId ?? '') ||
    !RELEASE_TAG.test(value.releaseTag ?? '') ||
    !RECOVERY_CRASH_WINDOWS.includes(value.crashWindow) ||
    !SHA256.test(value.fenceSha256 ?? '') ||
    !SHA256.test(value.journalCleanupRoleSha256 ?? '') ||
    !SHA256.test(value.journalRoleAuthoritySha256 ?? '') ||
    !SHA256.test(value.recoveryRoleArnSha256 ?? '') ||
    !SHA256.test(value.permissionsBoundaryArnSha256 ?? '') ||
    !exactArray(value.allowedActions, routeAllowedActions) ||
    !exactArray(value.forbiddenActions, RECOVERY_FORBIDDEN_ACTIONS) ||
    !ALIAS.test(value.approvedByAlias ?? '') ||
    !SHA256.test(value.approvalReferenceSha256 ?? '') ||
    !ISO_UTC.test(value.approvedAtUtc ?? '') ||
    !ISO_UTC.test(value.expiresAtUtc ?? '') ||
    dateMillis(value.expiresAtUtc) <= dateMillis(value.approvedAtUtc) ||
    dateMillis(value.expiresAtUtc) - dateMillis(value.approvedAtUtc) > 24 * 60 * 60 * 1000 ||
    value.containsSensitiveData !== false ||
    value.authoritySha256 !== objectSha256(withoutDigest(value, 'authoritySha256'))
  ) {
    fail('E7_PUBLICATION_RECOVERY_AUTHORITY_INVALID');
  }
  const { observedAtUtc, ...bindings } = expected;
  if (
    observedAtUtc !== undefined &&
    (!ISO_UTC.test(observedAtUtc) ||
      dateMillis(value.approvedAtUtc) > dateMillis(observedAtUtc) ||
      dateMillis(value.expiresAtUtc) <= dateMillis(observedAtUtc))
  ) {
    fail('E7_PUBLICATION_RECOVERY_AUTHORITY_NOT_CURRENT');
  }
  for (const [key, expectedValue] of Object.entries(bindings)) {
    if (expectedValue !== undefined && value[key] !== expectedValue) {
      fail('E7_PUBLICATION_RECOVERY_AUTHORITY_BINDING_MISMATCH');
    }
  }
  return value;
};

const validateSourceRun = ({ run, workflow, jobs, expected }) => {
  const sourceRunId = String(expected.sourceRunId);
  if (
    asRunId(run?.id) !== sourceRunId ||
    run?.run_attempt !== 1 ||
    run?.repository?.full_name !== RECOVERY_REPOSITORY ||
    run?.event !== 'workflow_dispatch' ||
    run?.head_branch !== 'master' ||
    run?.head_sha !== expected.candidateSha ||
    run?.status !== 'completed' ||
    !['failure', 'cancelled', 'timed_out'].includes(run?.conclusion) ||
    workflow?.name !== RECOVERY_SOURCE_WORKFLOW_NAME ||
    workflow?.path !== RECOVERY_SOURCE_WORKFLOW ||
    workflow?.state !== 'active'
  ) {
    fail('E7_PUBLICATION_RECOVERY_SOURCE_IDENTITY_INVALID');
  }
  const sourceJobs = normalizeJobs(jobs).filter((job) => job?.run_attempt === 1);
  const fenceJobs = sourceJobs.filter(
    (job) => job?.name === '23 Seal immutable pre-publication fence',
  );
  const publicationJobs = sourceJobs.filter((job) => job?.name === '24 Publish release');
  const summaryJobs = sourceJobs.filter((job) => job?.name === '25 Release summary and gates');
  const nonSuccess = (conclusion) => ['failure', 'cancelled', 'timed_out'].includes(conclusion);
  if (
    fenceJobs.length !== 1 ||
    publicationJobs.length !== 1 ||
    summaryJobs.length !== 1 ||
    fenceJobs[0].status !== 'completed' ||
    publicationJobs[0].status !== 'completed' ||
    summaryJobs[0].status !== 'completed' ||
    !nonSuccess(summaryJobs[0].conclusion)
  ) {
    fail('E7_PUBLICATION_RECOVERY_CRASH_WINDOW_NOT_PROVEN');
  }
  let crashWindow;
  if (nonSuccess(fenceJobs[0].conclusion) && publicationJobs[0].conclusion === 'skipped') {
    crashWindow = RECOVERY_CRASH_WINDOWS[0];
  } else if (fenceJobs[0].conclusion === 'success' && nonSuccess(publicationJobs[0].conclusion)) {
    crashWindow = RECOVERY_CRASH_WINDOWS[1];
  } else if (fenceJobs[0].conclusion === 'success' && publicationJobs[0].conclusion === 'success') {
    crashWindow = RECOVERY_CRASH_WINDOWS[2];
  } else {
    fail('E7_PUBLICATION_RECOVERY_CRASH_WINDOW_NOT_PROVEN');
  }
  const jobBinding = (job) => ({ id: String(job.id), conclusion: job.conclusion });
  return {
    conclusion: run.conclusion,
    crashWindow,
    fenceJob: jobBinding(fenceJobs[0]),
    publicationJob: jobBinding(publicationJobs[0]),
    summaryJob: jobBinding(summaryJobs[0]),
  };
};

const validateArtifactInventory = ({ artifacts, sourceRunId, crashWindow }) => {
  const observed = normalizeArtifacts(artifacts);
  const byName = new Map();
  for (const artifact of observed) {
    if (!byName.has(artifact?.name)) byName.set(artifact?.name, []);
    byName.get(artifact?.name).push(artifact);
  }
  const allowed = new Set([
    ...RECOVERY_SOURCE_ARTIFACTS,
    ...RECOVERY_INTERNAL_ARTIFACTS,
    ...RECOVERY_OPTIONAL_INCOMPLETE_SUMMARY_ARTIFACTS,
    RECOVERY_SOURCE_FENCE_ARTIFACT,
    RECOVERY_SOURCE_PUBLICATION_ARTIFACT,
  ]);
  const expectedFenceCount = crashWindow === RECOVERY_CRASH_WINDOWS[0] ? 0 : 1;
  const expectedPublicationCount = crashWindow === RECOVERY_CRASH_WINDOWS[2] ? 1 : 0;
  if (
    observed.length !== byName.size ||
    new Set(observed.map(({ id }) => id)).size !== observed.length ||
    [...byName.keys()].some((name) => typeof name !== 'string' || !allowed.has(name)) ||
    (byName.get(RECOVERY_SOURCE_FENCE_ARTIFACT) ?? []).length !== expectedFenceCount ||
    (byName.get(RECOVERY_SOURCE_PUBLICATION_ARTIFACT) ?? []).length !== expectedPublicationCount
  ) {
    fail('E7_PUBLICATION_RECOVERY_ROUTE_CONFUSION');
  }
  const binding = (name) => {
    const matches = byName.get(name) ?? [];
    const artifact = matches[0];
    if (
      matches.length !== 1 ||
      !Number.isSafeInteger(artifact?.id) ||
      artifact.id <= 0 ||
      artifact.expired !== false ||
      !DIGEST.test(artifact.digest ?? '') ||
      asRunId(artifact.workflow_run?.id) !== sourceRunId
    ) {
      fail('E7_PUBLICATION_RECOVERY_SOURCE_ARTIFACT_INVALID');
    }
    return {
      name,
      artifactId: String(artifact.id),
      digest: artifact.digest,
    };
  };
  const downloadManifest = RECOVERY_SOURCE_ARTIFACTS.map(binding);
  const internalManifest = RECOVERY_INTERNAL_ARTIFACTS.map(binding);
  const incompleteSummaryManifest = RECOVERY_OPTIONAL_INCOMPLETE_SUMMARY_ARTIFACTS.filter((name) =>
    byName.has(name),
  ).map(binding);
  const routeBinding = (name) => ({ ...binding(name), workflowRunId: sourceRunId });
  const sourceFenceManifest =
    expectedFenceCount === 1 ? [routeBinding(RECOVERY_SOURCE_FENCE_ARTIFACT)] : [];
  const sourcePublicationManifest =
    expectedPublicationCount === 1 ? [routeBinding(RECOVERY_SOURCE_PUBLICATION_ARTIFACT)] : [];
  return {
    observedCount: observed.length,
    downloadManifest,
    internalManifest,
    incompleteSummaryManifest,
    sourceFenceManifest,
    sourcePublicationManifest,
  };
};

export const assessPublicationRecoverySource = ({ expected, run, workflow, jobs, artifacts }) => {
  if (
    !RUN_ID.test(String(expected?.sourceRunId ?? '')) ||
    expected?.sourceRunAttempt !== 1 ||
    !SHA.test(expected?.candidateSha ?? '')
  ) {
    fail('E7_PUBLICATION_RECOVERY_SOURCE_EXPECTATION_INVALID');
  }
  const sourceRunId = String(expected.sourceRunId);
  const source = validateSourceRun({ run, workflow, jobs, expected });
  const artifactInventory = validateArtifactInventory({
    artifacts,
    sourceRunId,
    crashWindow: source.crashWindow,
  });
  return { source, artifactInventory };
};

const exactArchiveFiles = (archive, expectedNames, code) => {
  const entries = readReleaseSuccessorZipEntries(archive);
  const byBasename = new Map();
  for (const [entryPath, bytes] of entries) {
    const basename = path.posix.basename(entryPath);
    if (!byBasename.has(basename)) byBasename.set(basename, []);
    byBasename.get(basename).push(bytes);
  }
  if (
    entries.size !== expectedNames.length ||
    [...entries.keys()].some(
      (entryPath) =>
        entryPath !== entryPath.normalize('NFC') ||
        path.posix.basename(entryPath) !== entryPath ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(entryPath),
    ) ||
    [...byBasename.keys()].toSorted().join('\0') !== expectedNames.toSorted().join('\0') ||
    [...byBasename.values()].some((matches) => matches.length !== 1)
  ) {
    fail(code);
  }
  return new Map([...byBasename].map(([name, matches]) => [name, matches[0]]));
};

const fileBindings = (files, expectedNames, code) =>
  expectedNames.map((name) => {
    const bytes = files.get(name);
    const document = parseJson(bytes, code);
    return {
      name,
      bytes: bytes.length,
      rawSha256: sha256(bytes),
      canonicalSha256: objectSha256(document.value),
    };
  });

const validateSourcePublicationDocuments = (files, expected) => {
  const publication = parseJson(
    files.get('publication.json'),
    'E7_PUBLICATION_RECOVERY_SOURCE_PUBLICATION_INVALID',
  ).value;
  const plan = parseJson(
    files.get('publication-plan.json'),
    'E7_PUBLICATION_RECOVERY_SOURCE_PUBLICATION_INVALID',
  ).value;
  const target = parseJson(
    files.get('publication-target-proof.json'),
    'E7_PUBLICATION_RECOVERY_SOURCE_PUBLICATION_INVALID',
  ).value;
  const operation = parseJson(
    files.get('publication-operation.json'),
    'E7_PUBLICATION_RECOVERY_SOURCE_PUBLICATION_INVALID',
  ).value;
  const proof = parseJson(
    files.get('publication-proof.json'),
    'E7_PUBLICATION_RECOVERY_SOURCE_PUBLICATION_INVALID',
  ).value;
  const identityMatches = (value) =>
    value?.candidateSha === expected.candidateSha &&
    value?.releaseId === expected.releaseId &&
    value?.releaseTag === expected.releaseTag;
  if (
    publication?.kind !== 'PUBLICATION_PREPARATION' ||
    publication?.status !== 'READY_FOR_EXTERNAL_PUBLICATION' ||
    !identityMatches(publication) ||
    plan?.kind !== 'PUBLICATION_PLAN' ||
    plan?.status !== 'READY_FOR_EXTERNAL_PUBLICATION' ||
    plan?.repository !== RECOVERY_REPOSITORY ||
    plan?.retryPolicy !== 'VERIFY_EXACT_OR_CREATE_MISSING' ||
    !identityMatches(plan) ||
    target?.kind !== 'PUBLICATION_TARGET_PREFLIGHT' ||
    target?.status !== 'PASS' ||
    target?.publicationPlanSha256 !== objectSha256(plan) ||
    !identityMatches(target) ||
    operation?.kind !== 'GITHUB_PUBLICATION_OPERATION' ||
    operation?.status !== 'PASS' ||
    operation?.repository !== RECOVERY_REPOSITORY ||
    operation?.publicationPlanSha256 !== objectSha256(plan) ||
    operation?.releaseState !== 'COMPLETE' ||
    !Number.isSafeInteger(operation?.externalWritesPerformed) ||
    operation.externalWritesPerformed < 0 ||
    operation.externalWritesPerformed > 2 ||
    !identityMatches(operation) ||
    proof?.kind !== 'PUBLICATION_PROOF' ||
    proof?.status !== 'PASS' ||
    proof?.repository !== RECOVERY_REPOSITORY ||
    proof?.publicationPlanSha256 !== objectSha256(plan) ||
    proof?.publicationTargetProofSha256 !== objectSha256(target) ||
    proof?.publicationOperationSha256 !== objectSha256(operation) ||
    proof?.releasePresent !== true ||
    proof?.releaseVerifiedExact !== true ||
    !identityMatches(proof)
  ) {
    fail('E7_PUBLICATION_RECOVERY_SOURCE_PUBLICATION_INVALID');
  }
};

const validateRouteArchives = ({
  archiveDirectory,
  artifactInventory,
  crashWindow,
  expected,
  fence,
  fenceBytes,
}) => {
  let entries;
  try {
    entries = readdirSync(archiveDirectory, { withFileTypes: true });
  } catch {
    fail('E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_SET_INVALID');
  }
  const routeMetadata = [
    ...artifactInventory.sourceFenceManifest,
    ...artifactInventory.sourcePublicationManifest,
  ];
  if (
    entries.some((entry) => !entry.isFile()) ||
    entries
      .map(({ name }) => name)
      .toSorted()
      .join('\0') !==
      routeMetadata
        .map(({ name }) => `${name}.zip`)
        .toSorted()
        .join('\0')
  ) {
    fail('E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_SET_INVALID');
  }
  const bindArchive = (metadata, expectedFiles) => {
    const archive = readFileSync(path.join(archiveDirectory, `${metadata.name}.zip`));
    if (`sha256:${sha256(archive)}` !== metadata.digest) {
      fail('E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_DIGEST_MISMATCH');
    }
    const files = exactArchiveFiles(
      archive,
      expectedFiles,
      'E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_FILE_SET_INVALID',
    );
    return {
      ...metadata,
      files,
      bindings: fileBindings(
        files,
        expectedFiles,
        'E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_JSON_INVALID',
      ),
    };
  };
  const sourceFenceManifest = artifactInventory.sourceFenceManifest.map((metadata) => {
    const bound = bindArchive(metadata, ['release-successor-completion-fence.json']);
    const source = bound.files.get('release-successor-completion-fence.json');
    const document = validateReleaseSuccessorCompletionFence(
      parseJson(source, 'E7_PUBLICATION_RECOVERY_SOURCE_FENCE_INVALID').value,
      {
        candidateSha: expected.candidateSha,
        releaseId: expected.releaseId,
        sourceRunId: String(expected.sourceRunId),
        sourceRunAttempt: 1,
        journalCleanupRoleSha256: expected.journalCleanupRoleSha256,
        journalRoleAuthoritySha256: expected.journalRoleAuthoritySha256,
      },
    );
    if (document.fenceSha256 !== fence.fenceSha256 || !source.equals(fenceBytes)) {
      fail('E7_PUBLICATION_RECOVERY_SOURCE_FENCE_SSM_MISMATCH');
    }
    return { ...metadata, files: bound.bindings };
  });
  const sourcePublicationManifest = artifactInventory.sourcePublicationManifest.map((metadata) => {
    const bound = bindArchive(metadata, RECOVERY_PUBLICATION_FILES);
    validateSourcePublicationDocuments(bound.files, expected);
    return { ...metadata, files: bound.bindings };
  });
  if (
    sourceFenceManifest.length !== (crashWindow === RECOVERY_CRASH_WINDOWS[0] ? 0 : 1) ||
    sourcePublicationManifest.length !== (crashWindow === RECOVERY_CRASH_WINDOWS[2] ? 1 : 0)
  ) {
    fail('E7_PUBLICATION_RECOVERY_ROUTE_CONFUSION');
  }
  const fullInventory = [
    ...artifactInventory.downloadManifest,
    ...artifactInventory.internalManifest,
    ...artifactInventory.incompleteSummaryManifest,
    ...sourceFenceManifest,
    ...sourcePublicationManifest,
  ].toSorted((left, right) => left.name.localeCompare(right.name));
  const metadataInventory = [
    ...artifactInventory.downloadManifest,
    ...artifactInventory.internalManifest,
    ...artifactInventory.incompleteSummaryManifest,
    ...artifactInventory.sourceFenceManifest,
    ...artifactInventory.sourcePublicationManifest,
  ].toSorted((left, right) => left.name.localeCompare(right.name));
  return {
    sourceFenceManifest,
    sourcePublicationManifest,
    inventoryMetadataSha256: objectSha256(metadataInventory),
    inventorySha256: objectSha256(fullInventory),
  };
};

const validateIam = ({
  caller,
  role,
  rolePolicies,
  rolePolicy,
  attachedPolicies,
  boundaryMetadata,
  boundary,
  expected,
}) => {
  const roleMatch = ROLE_ARN.exec(expected.recoveryRoleArn ?? '');
  const boundaryMatch = BOUNDARY_ARN.exec(expected.permissionsBoundaryArn ?? '');
  if (
    !roleMatch ||
    !boundaryMatch ||
    roleMatch[1] !== expected.awsAccountId ||
    boundaryMatch[1] !== expected.awsAccountId ||
    !AWS_ACCOUNT.test(expected.awsAccountId ?? '') ||
    !AWS_REGION.test(expected.awsRegion ?? '')
  ) {
    fail('E7_PUBLICATION_RECOVERY_IAM_EXPECTATION_INVALID');
  }
  const roleName = roleMatch[2].split('/').at(-1);
  const sessionName = `e7-pub-recovery-${expected.recoveryRunId}-a${expected.recoveryRunAttempt}`;
  const callerArn = `arn:aws:sts::${expected.awsAccountId}:assumed-role/${roleName}/${sessionName}`;
  const roleValue = role?.Role;
  const boundaryValue = boundary?.PolicyVersion?.Document;
  const basePolicy = expectedRecoveryBoundaryPolicy({
    awsAccountId: expected.awsAccountId,
    awsRegion: expected.awsRegion,
    recoveryRoleArn: expected.recoveryRoleArn,
    permissionsBoundaryArn: expected.permissionsBoundaryArn,
  });
  const sessionPolicy = expectedRecoverySessionPolicy({
    awsAccountId: expected.awsAccountId,
    awsRegion: expected.awsRegion,
    candidateSha: expected.candidateSha,
    sourceRunId: expected.sourceRunId,
    recoveryRoleArn: expected.recoveryRoleArn,
    permissionsBoundaryArn: expected.permissionsBoundaryArn,
  });
  if (
    caller?.Account !== expected.awsAccountId ||
    caller?.Arn !== callerArn ||
    roleValue?.Arn !== expected.recoveryRoleArn ||
    roleValue?.RoleName !== roleName ||
    roleValue?.PermissionsBoundary?.PermissionsBoundaryArn !== expected.permissionsBoundaryArn ||
    canonicalJson(roleValue?.AssumeRolePolicyDocument) !==
      canonicalJson(expectedRecoveryTrustPolicy({ awsAccountId: expected.awsAccountId })) ||
    rolePolicies?.IsTruncated !== false ||
    canonicalJson(rolePolicies?.PolicyNames) !==
      canonicalJson([RECOVERY_ROLE_INLINE_POLICY_NAME]) ||
    rolePolicy?.RoleName !== roleName ||
    rolePolicy?.PolicyName !== RECOVERY_ROLE_INLINE_POLICY_NAME ||
    canonicalJson(rolePolicy?.PolicyDocument) !== canonicalJson(basePolicy) ||
    attachedPolicies?.IsTruncated !== false ||
    !Array.isArray(attachedPolicies?.AttachedPolicies) ||
    attachedPolicies.AttachedPolicies.length !== 0 ||
    boundaryMetadata?.Policy?.Arn !== expected.permissionsBoundaryArn ||
    typeof boundaryMetadata?.Policy?.DefaultVersionId !== 'string' ||
    boundary?.PolicyVersion?.VersionId !== boundaryMetadata.Policy.DefaultVersionId ||
    boundary?.PolicyVersion?.IsDefaultVersion !== true ||
    canonicalJson(boundaryValue) !== canonicalJson(basePolicy) ||
    !recoverySessionIsSubsetOfBase({ basePolicy, sessionPolicy }) ||
    /(?:PutParameter|DeleteParameter|ssm:\*|iam:\*)/u.test(
      canonicalJson({ basePolicy, sessionPolicy }),
    )
  ) {
    fail('E7_PUBLICATION_RECOVERY_LIVE_IAM_INVALID');
  }
  return {
    awsAccountId: expected.awsAccountId,
    awsRegion: expected.awsRegion,
    callerArnSha256: sha256(caller.Arn),
    recoveryRoleArnSha256: sha256(expected.recoveryRoleArn),
    permissionsBoundaryArnSha256: sha256(expected.permissionsBoundaryArn),
    trustPolicySha256: objectSha256(roleValue.AssumeRolePolicyDocument),
    roleBasePolicySha256: objectSha256(rolePolicy.PolicyDocument),
    boundaryPolicySha256: objectSha256(boundaryValue),
    sessionPolicySha256: objectSha256(sessionPolicy),
  };
};

const validateParameter = ({ parameterResponse, expected }) => {
  const parameter = parameterResponse?.Parameter;
  const parameterName = recoveryFenceParameterName(expected);
  const expectedArn = `arn:aws:ssm:${expected.awsRegion}:${expected.awsAccountId}:parameter${parameterName}`;
  if (
    parameter?.Name !== parameterName ||
    parameter?.Type !== 'String' ||
    parameter?.Version !== 1 ||
    parameter?.ARN !== expectedArn ||
    parameter?.DataType !== 'text' ||
    typeof parameter?.Value !== 'string'
  ) {
    fail('E7_PUBLICATION_RECOVERY_FENCE_PARAMETER_INVALID');
  }
  const parsed = parseJson(parameter.Value, 'E7_PUBLICATION_RECOVERY_FENCE_JSON_INVALID');
  const fence = validateReleaseSuccessorCompletionFence(parsed.value, {
    candidateSha: expected.candidateSha,
    releaseId: expected.releaseId,
    sourceRunId: expected.sourceRunId,
    sourceRunAttempt: 1,
    journalCleanupRoleSha256: expected.journalCleanupRoleSha256,
    journalRoleAuthoritySha256: expected.journalRoleAuthoritySha256,
  });
  if (
    fence.fenceSha256 !== expected.expectedFenceSha256 ||
    parameter.Value !== `${JSON.stringify(fence)}\n`
  ) {
    fail('E7_PUBLICATION_RECOVERY_FENCE_BYTES_MISMATCH');
  }
  return {
    fence,
    rawBytes: parsed.bytes,
    binding: {
      parameterName,
      parameterArn: expectedArn,
      parameterVersion: 1,
      parameterValueRawSha256: sha256(parsed.bytes),
      fenceSha256: fence.fenceSha256,
    },
  };
};

export const createPublicationRecoveryPlan = ({
  expected,
  run,
  workflow,
  jobs,
  artifacts,
  caller,
  role,
  rolePolicies,
  rolePolicy,
  attachedPolicies,
  boundaryMetadata,
  boundary,
  parameterResponse,
  authority,
  routeArchiveDirectory,
  observedAtUtc,
}) => {
  if (
    !RUN_ID.test(String(expected?.sourceRunId ?? '')) ||
    expected?.sourceRunAttempt !== 1 ||
    !RUN_ID.test(String(expected?.recoveryRunId ?? '')) ||
    expected?.recoveryRunAttempt !== 1 ||
    !SHA.test(expected?.candidateSha ?? '') ||
    !RELEASE_ID.test(expected?.releaseId ?? '') ||
    !RELEASE_TAG.test(expected?.releaseTag ?? '') ||
    !SHA256.test(expected?.expectedFenceSha256 ?? '') ||
    !SHA256.test(expected?.journalCleanupRoleSha256 ?? '') ||
    !SHA256.test(expected?.journalRoleAuthoritySha256 ?? '') ||
    !ISO_UTC.test(observedAtUtc ?? '')
  ) {
    fail('E7_PUBLICATION_RECOVERY_EXPECTATION_INVALID');
  }
  const sourceRunId = String(expected.sourceRunId);
  const { source, artifactInventory } = assessPublicationRecoverySource({
    expected,
    run,
    workflow,
    jobs,
    artifacts,
  });
  const iam = validateIam({
    caller,
    role,
    rolePolicies,
    rolePolicy,
    attachedPolicies,
    boundaryMetadata,
    boundary,
    expected,
  });
  const {
    fence,
    rawBytes: fenceBytes,
    binding: fenceBinding,
  } = validateParameter({
    parameterResponse,
    expected,
  });
  const approvedAuthority = validateRecoveryAuthority(authority, {
    sourceRunId,
    sourceRunAttempt: 1,
    candidateSha: expected.candidateSha,
    releaseId: expected.releaseId,
    releaseTag: expected.releaseTag,
    crashWindow: source.crashWindow,
    fenceSha256: expected.expectedFenceSha256,
    journalCleanupRoleSha256: expected.journalCleanupRoleSha256,
    journalRoleAuthoritySha256: expected.journalRoleAuthoritySha256,
    recoveryRoleArnSha256: iam.recoveryRoleArnSha256,
    permissionsBoundaryArnSha256: iam.permissionsBoundaryArnSha256,
    observedAtUtc,
  });
  if (authority.authoritySha256 !== expected.expectedAuthoritySha256) {
    fail('E7_PUBLICATION_RECOVERY_AUTHORITY_NOT_CURRENT');
  }
  const idempotencyKey = recoveryIdempotencyKey({
    candidateSha: expected.candidateSha,
    releaseId: expected.releaseId,
    sourceRunId,
    fenceSha256: fence.fenceSha256,
  });
  const routeEvidence = validateRouteArchives({
    archiveDirectory: routeArchiveDirectory,
    artifactInventory,
    crashWindow: source.crashWindow,
    expected,
    fence,
    fenceBytes,
  });
  const verifyOnly = source.crashWindow === RECOVERY_CRASH_WINDOWS[2];
  const githubPublicationPolicy = verifyOnly
    ? 'VERIFY_EXACT_NO_MUTATION'
    : 'VERIFY_EXACT_OR_CREATE_MISSING';
  const planBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_PLAN',
    status: 'READY_FOR_AUTHORIZED_RECOVERY_ROUTE',
    blockerId: RECOVERY_BLOCKER,
    repository: RECOVERY_REPOSITORY,
    recoveryWorkflowPath: RECOVERY_WORKFLOW,
    protectedEnvironment: RECOVERY_ENVIRONMENT,
    observedAtUtc,
    source: {
      workflowPath: RECOVERY_SOURCE_WORKFLOW,
      workflowName: RECOVERY_SOURCE_WORKFLOW_NAME,
      runId: sourceRunId,
      runAttempt: 1,
      conclusion: source.conclusion,
      candidateSha: expected.candidateSha,
      releaseId: expected.releaseId,
      releaseTag: expected.releaseTag,
      crashWindow: source.crashWindow,
      fenceJob: source.fenceJob,
      publicationJob: source.publicationJob,
      summaryJob: source.summaryJob,
    },
    owner: {
      journalCleanupRoleSha256: fence.journalCleanupRoleSha256,
      journalRoleAuthoritySha256: fence.journalRoleAuthoritySha256,
      recoveryRunId: String(expected.recoveryRunId),
      recoveryRunAttempt: 1,
    },
    fence: fenceBinding,
    iam,
    authority: {
      status: approvedAuthority.status,
      approvedByAlias: approvedAuthority.approvedByAlias,
      approvedAtUtc: approvedAuthority.approvedAtUtc,
      expiresAtUtc: approvedAuthority.expiresAtUtc,
      authoritySha256: approvedAuthority.authoritySha256,
    },
    artifactInventory: {
      requiredCount: RECOVERY_SOURCE_ARTIFACTS.length,
      internalCount: RECOVERY_INTERNAL_ARTIFACTS.length,
      optionalIncompleteSummaryCount: artifactInventory.incompleteSummaryManifest.length,
      observedCount: artifactInventory.observedCount,
      sourceFenceArtifactCount: routeEvidence.sourceFenceManifest.length,
      sourcePublicationArtifactCount: routeEvidence.sourcePublicationManifest.length,
      downloadManifest: artifactInventory.downloadManifest,
      internalManifest: artifactInventory.internalManifest,
      incompleteSummaryManifest: artifactInventory.incompleteSummaryManifest,
      sourceFenceManifest: routeEvidence.sourceFenceManifest,
      sourcePublicationManifest: routeEvidence.sourcePublicationManifest,
      inventoryMetadataSha256: routeEvidence.inventoryMetadataSha256,
      inventorySha256: routeEvidence.inventorySha256,
    },
    route: {
      crashWindow: source.crashWindow,
      mode: verifyOnly ? 'VERIFY_EXACT_NOOP' : 'FORWARD_ONLY_IDEMPOTENT',
      githubPublicationPolicy,
      fenceEvidenceOrigin:
        source.crashWindow === RECOVERY_CRASH_WINDOWS[0]
          ? 'SSM_REHYDRATED'
          : 'SOURCE_ARTIFACT_BYTE_EQUAL_SSM',
      publicationEvidenceOrigin: verifyOnly
        ? 'SOURCE_ARTIFACT_LIVE_VERIFIED'
        : 'RECOVERY_VERIFIED_OUTPUT',
      canonicalSupplementPolicy: 'COPY_EXACT_WITHOUT_SOURCE_DUPLICATION',
      idempotencyKey,
      steps: [...RECOVERY_FORWARD_STEPS],
      allowedActions: verifyOnly
        ? RECOVERY_ALLOWED_ACTIONS.filter(
            (action) => action !== 'VERIFY_OR_CREATE_MISSING_GITHUB_PUBLICATION',
          )
        : [...RECOVERY_ALLOWED_ACTIONS],
      forbiddenActions: [...RECOVERY_FORBIDDEN_ACTIONS],
    },
    sharedIntegration: {
      catalog: 'RECOVERY_SUPPLEMENT_CATALOG_V1',
      postSuccessConsumer: 'WIRED_CONTRACT',
      sourceRunConclusionMutable: false,
      stage7GateClaimed: false,
      closureStatus: 'POST_SUCCESS_COMPOSITE_REQUIRED',
    },
    containsSensitiveData: false,
  };
  const plan = { ...planBody, planSha256: objectSha256(planBody) };
  validatePublicationRecoveryPlan(plan);
  return { plan, fence, fenceBytes };
};

const validArtifactBindings = (value, expectedNames) =>
  exactArray(
    value?.map(({ name }) => name),
    expectedNames,
  ) &&
  value.every(
    (artifact) =>
      exactKeys(artifact, ['name', 'artifactId', 'digest']) &&
      RUN_ID.test(artifact.artifactId ?? '') &&
      DIGEST.test(artifact.digest ?? ''),
  );

const validFileBindings = (value, expectedNames) =>
  exactArray(
    value?.map(({ name }) => name),
    expectedNames,
  ) &&
  value.every(
    (file) =>
      exactKeys(file, ['name', 'bytes', 'rawSha256', 'canonicalSha256']) &&
      Number.isSafeInteger(file.bytes) &&
      file.bytes >= 2 &&
      SHA256.test(file.rawSha256 ?? '') &&
      SHA256.test(file.canonicalSha256 ?? ''),
  );

const validRouteArtifactBindings = (value, expectedName, expectedFiles) =>
  Array.isArray(value) &&
  value.length === (expectedName === null ? 0 : 1) &&
  (expectedName === null ||
    (exactKeys(value[0], ['name', 'artifactId', 'digest', 'workflowRunId', 'files']) &&
      value[0].name === expectedName &&
      RUN_ID.test(value[0].artifactId ?? '') &&
      DIGEST.test(value[0].digest ?? '') &&
      RUN_ID.test(value[0].workflowRunId ?? '') &&
      validFileBindings(value[0].files, expectedFiles)));

const expectedRoute = (crashWindow) => {
  if (crashWindow === RECOVERY_CRASH_WINDOWS[0]) {
    return {
      fenceConclusion: ['failure', 'cancelled', 'timed_out'],
      publicationConclusion: ['skipped'],
      sourceFenceArtifactCount: 0,
      sourcePublicationArtifactCount: 0,
      mode: 'FORWARD_ONLY_IDEMPOTENT',
      githubPublicationPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
      fenceEvidenceOrigin: 'SSM_REHYDRATED',
      publicationEvidenceOrigin: 'RECOVERY_VERIFIED_OUTPUT',
    };
  }
  if (crashWindow === RECOVERY_CRASH_WINDOWS[1]) {
    return {
      fenceConclusion: ['success'],
      publicationConclusion: ['failure', 'cancelled', 'timed_out'],
      sourceFenceArtifactCount: 1,
      sourcePublicationArtifactCount: 0,
      mode: 'FORWARD_ONLY_IDEMPOTENT',
      githubPublicationPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
      fenceEvidenceOrigin: 'SOURCE_ARTIFACT_BYTE_EQUAL_SSM',
      publicationEvidenceOrigin: 'RECOVERY_VERIFIED_OUTPUT',
    };
  }
  if (crashWindow === RECOVERY_CRASH_WINDOWS[2]) {
    return {
      fenceConclusion: ['success'],
      publicationConclusion: ['success'],
      sourceFenceArtifactCount: 1,
      sourcePublicationArtifactCount: 1,
      mode: 'VERIFY_EXACT_NOOP',
      githubPublicationPolicy: 'VERIFY_EXACT_NO_MUTATION',
      fenceEvidenceOrigin: 'SOURCE_ARTIFACT_BYTE_EQUAL_SSM',
      publicationEvidenceOrigin: 'SOURCE_ARTIFACT_LIVE_VERIFIED',
    };
  }
  return null;
};

export const validatePublicationRecoveryPlan = (value) => {
  const routeExpectation = expectedRoute(value?.source?.crashWindow);
  const routeAllowedActions =
    value?.source?.crashWindow === RECOVERY_CRASH_WINDOWS[2]
      ? RECOVERY_ALLOWED_ACTIONS.filter(
          (action) => action !== 'VERIFY_OR_CREATE_MISSING_GITHUB_PUBLICATION',
        )
      : RECOVERY_ALLOWED_ACTIONS;
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'blockerId',
      'repository',
      'recoveryWorkflowPath',
      'protectedEnvironment',
      'observedAtUtc',
      'source',
      'owner',
      'fence',
      'iam',
      'authority',
      'artifactInventory',
      'route',
      'sharedIntegration',
      'containsSensitiveData',
      'planSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_PLAN' ||
    value.status !== 'READY_FOR_AUTHORIZED_RECOVERY_ROUTE' ||
    value.blockerId !== RECOVERY_BLOCKER ||
    value.repository !== RECOVERY_REPOSITORY ||
    value.recoveryWorkflowPath !== RECOVERY_WORKFLOW ||
    value.protectedEnvironment !== RECOVERY_ENVIRONMENT ||
    !ISO_UTC.test(value.observedAtUtc ?? '') ||
    !exactKeys(value.source, [
      'workflowPath',
      'workflowName',
      'runId',
      'runAttempt',
      'conclusion',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'crashWindow',
      'fenceJob',
      'publicationJob',
      'summaryJob',
    ]) ||
    value.source.workflowPath !== RECOVERY_SOURCE_WORKFLOW ||
    value.source.workflowName !== RECOVERY_SOURCE_WORKFLOW_NAME ||
    !RUN_ID.test(value.source.runId ?? '') ||
    value.source.runAttempt !== 1 ||
    !['failure', 'cancelled', 'timed_out'].includes(value.source.conclusion) ||
    !SHA.test(value.source.candidateSha ?? '') ||
    !RELEASE_ID.test(value.source.releaseId ?? '') ||
    !RELEASE_TAG.test(value.source.releaseTag ?? '') ||
    routeExpectation === null ||
    !exactKeys(value.source.fenceJob, ['id', 'conclusion']) ||
    !RUN_ID.test(value.source.fenceJob.id ?? '') ||
    !routeExpectation?.fenceConclusion.includes(value.source.fenceJob.conclusion) ||
    !exactKeys(value.source.publicationJob, ['id', 'conclusion']) ||
    !RUN_ID.test(value.source.publicationJob.id ?? '') ||
    !routeExpectation?.publicationConclusion.includes(value.source.publicationJob.conclusion) ||
    !exactKeys(value.source.summaryJob, ['id', 'conclusion']) ||
    !RUN_ID.test(value.source.summaryJob.id ?? '') ||
    !['failure', 'cancelled', 'timed_out'].includes(value.source.summaryJob.conclusion) ||
    !exactKeys(value.owner, [
      'journalCleanupRoleSha256',
      'journalRoleAuthoritySha256',
      'recoveryRunId',
      'recoveryRunAttempt',
    ]) ||
    !SHA256.test(value.owner.journalCleanupRoleSha256 ?? '') ||
    !SHA256.test(value.owner.journalRoleAuthoritySha256 ?? '') ||
    !RUN_ID.test(value.owner.recoveryRunId ?? '') ||
    value.owner.recoveryRunAttempt !== 1 ||
    !exactKeys(value.fence, [
      'parameterName',
      'parameterArn',
      'parameterVersion',
      'parameterValueRawSha256',
      'fenceSha256',
    ]) ||
    value.fence.parameterName !==
      recoveryFenceParameterName({
        candidateSha: value.source.candidateSha,
        sourceRunId: value.source.runId,
      }) ||
    !value.fence.parameterArn.endsWith(`:parameter${value.fence.parameterName}`) ||
    value.fence.parameterVersion !== 1 ||
    !SHA256.test(value.fence.parameterValueRawSha256 ?? '') ||
    !SHA256.test(value.fence.fenceSha256 ?? '') ||
    !exactKeys(value.iam, [
      'awsAccountId',
      'awsRegion',
      'callerArnSha256',
      'recoveryRoleArnSha256',
      'permissionsBoundaryArnSha256',
      'trustPolicySha256',
      'roleBasePolicySha256',
      'boundaryPolicySha256',
      'sessionPolicySha256',
    ]) ||
    !AWS_ACCOUNT.test(value.iam.awsAccountId ?? '') ||
    !AWS_REGION.test(value.iam.awsRegion ?? '') ||
    [
      'callerArnSha256',
      'recoveryRoleArnSha256',
      'permissionsBoundaryArnSha256',
      'trustPolicySha256',
      'roleBasePolicySha256',
      'boundaryPolicySha256',
      'sessionPolicySha256',
    ].some((key) => !SHA256.test(value.iam[key] ?? '')) ||
    !exactKeys(value.authority, [
      'status',
      'approvedByAlias',
      'approvedAtUtc',
      'expiresAtUtc',
      'authoritySha256',
    ]) ||
    value.authority.status !== 'APPROVED' ||
    !ALIAS.test(value.authority.approvedByAlias ?? '') ||
    !ISO_UTC.test(value.authority.approvedAtUtc ?? '') ||
    !ISO_UTC.test(value.authority.expiresAtUtc ?? '') ||
    !SHA256.test(value.authority.authoritySha256 ?? '') ||
    !exactKeys(value.route, [
      'crashWindow',
      'mode',
      'githubPublicationPolicy',
      'fenceEvidenceOrigin',
      'publicationEvidenceOrigin',
      'canonicalSupplementPolicy',
      'idempotencyKey',
      'steps',
      'allowedActions',
      'forbiddenActions',
    ]) ||
    value.route?.crashWindow !== value.source.crashWindow ||
    value.route?.mode !== routeExpectation?.mode ||
    value.route?.githubPublicationPolicy !== routeExpectation?.githubPublicationPolicy ||
    value.route?.fenceEvidenceOrigin !== routeExpectation?.fenceEvidenceOrigin ||
    value.route?.publicationEvidenceOrigin !== routeExpectation?.publicationEvidenceOrigin ||
    value.route?.canonicalSupplementPolicy !== 'COPY_EXACT_WITHOUT_SOURCE_DUPLICATION' ||
    !SHA256.test(value.route?.idempotencyKey ?? '') ||
    !exactArray(value.route?.steps, RECOVERY_FORWARD_STEPS) ||
    !exactArray(value.route?.allowedActions, routeAllowedActions) ||
    !exactArray(value.route?.forbiddenActions, RECOVERY_FORBIDDEN_ACTIONS) ||
    value.sharedIntegration?.catalog !== 'RECOVERY_SUPPLEMENT_CATALOG_V1' ||
    value.sharedIntegration?.postSuccessConsumer !== 'WIRED_CONTRACT' ||
    value.sharedIntegration?.sourceRunConclusionMutable !== false ||
    value.sharedIntegration?.stage7GateClaimed !== false ||
    value.sharedIntegration?.closureStatus !== 'POST_SUCCESS_COMPOSITE_REQUIRED' ||
    !exactKeys(value.artifactInventory, [
      'requiredCount',
      'internalCount',
      'optionalIncompleteSummaryCount',
      'observedCount',
      'sourceFenceArtifactCount',
      'sourcePublicationArtifactCount',
      'downloadManifest',
      'internalManifest',
      'incompleteSummaryManifest',
      'sourceFenceManifest',
      'sourcePublicationManifest',
      'inventoryMetadataSha256',
      'inventorySha256',
    ]) ||
    value.artifactInventory?.requiredCount !== RECOVERY_SOURCE_ARTIFACTS.length ||
    value.artifactInventory?.internalCount !== RECOVERY_INTERNAL_ARTIFACTS.length ||
    !Number.isSafeInteger(value.artifactInventory?.optionalIncompleteSummaryCount) ||
    value.artifactInventory.optionalIncompleteSummaryCount < 0 ||
    value.artifactInventory.optionalIncompleteSummaryCount >
      RECOVERY_OPTIONAL_INCOMPLETE_SUMMARY_ARTIFACTS.length ||
    value.artifactInventory?.sourceFenceArtifactCount !==
      routeExpectation?.sourceFenceArtifactCount ||
    value.artifactInventory?.sourcePublicationArtifactCount !==
      routeExpectation?.sourcePublicationArtifactCount ||
    value.artifactInventory?.observedCount !==
      RECOVERY_SOURCE_ARTIFACTS.length +
        RECOVERY_INTERNAL_ARTIFACTS.length +
        value.artifactInventory.optionalIncompleteSummaryCount +
        value.artifactInventory.sourceFenceArtifactCount +
        value.artifactInventory.sourcePublicationArtifactCount ||
    !validArtifactBindings(value.artifactInventory?.downloadManifest, RECOVERY_SOURCE_ARTIFACTS) ||
    !validArtifactBindings(
      value.artifactInventory?.internalManifest,
      RECOVERY_INTERNAL_ARTIFACTS,
    ) ||
    !validArtifactBindings(
      value.artifactInventory?.incompleteSummaryManifest,
      RECOVERY_OPTIONAL_INCOMPLETE_SUMMARY_ARTIFACTS.filter((name) =>
        value.artifactInventory.incompleteSummaryManifest.some(
          (artifact) => artifact.name === name,
        ),
      ),
    ) ||
    value.artifactInventory.optionalIncompleteSummaryCount !==
      value.artifactInventory.incompleteSummaryManifest.length ||
    !validRouteArtifactBindings(
      value.artifactInventory.sourceFenceManifest,
      routeExpectation?.sourceFenceArtifactCount === 1 ? RECOVERY_SOURCE_FENCE_ARTIFACT : null,
      ['release-successor-completion-fence.json'],
    ) ||
    !validRouteArtifactBindings(
      value.artifactInventory.sourcePublicationManifest,
      routeExpectation?.sourcePublicationArtifactCount === 1
        ? RECOVERY_SOURCE_PUBLICATION_ARTIFACT
        : null,
      RECOVERY_PUBLICATION_FILES,
    ) ||
    value.artifactInventory.sourceFenceManifest.some(
      ({ workflowRunId }) => workflowRunId !== value.source.runId,
    ) ||
    value.artifactInventory.sourcePublicationManifest.some(
      ({ workflowRunId }) => workflowRunId !== value.source.runId,
    ) ||
    !SHA256.test(value.artifactInventory.inventoryMetadataSha256 ?? '') ||
    value.artifactInventory.inventoryMetadataSha256 !==
      objectSha256(
        [
          ...value.artifactInventory.downloadManifest,
          ...value.artifactInventory.internalManifest,
          ...value.artifactInventory.incompleteSummaryManifest,
          ...value.artifactInventory.sourceFenceManifest.map(({ files: ignored, ...metadata }) => {
            void ignored;
            return metadata;
          }),
          ...value.artifactInventory.sourcePublicationManifest.map(
            ({ files: ignored, ...metadata }) => {
              void ignored;
              return metadata;
            },
          ),
        ].toSorted((left, right) => left.name.localeCompare(right.name)),
      ) ||
    !SHA256.test(value.artifactInventory.inventorySha256 ?? '') ||
    value.artifactInventory.inventorySha256 !==
      objectSha256(
        [
          ...value.artifactInventory.downloadManifest,
          ...value.artifactInventory.internalManifest,
          ...value.artifactInventory.incompleteSummaryManifest,
          ...value.artifactInventory.sourceFenceManifest,
          ...value.artifactInventory.sourcePublicationManifest,
        ].toSorted((left, right) => left.name.localeCompare(right.name)),
      ) ||
    value.route.idempotencyKey !==
      recoveryIdempotencyKey({
        candidateSha: value.source.candidateSha,
        releaseId: value.source.releaseId,
        sourceRunId: value.source.runId,
        fenceSha256: value.fence.fenceSha256,
      }) ||
    value.containsSensitiveData !== false ||
    value.planSha256 !== objectSha256(withoutDigest(value, 'planSha256'))
  ) {
    fail('E7_PUBLICATION_RECOVERY_PLAN_INVALID');
  }
  return value;
};

export const extractPublicationRecoveryArtifacts = ({
  plan,
  archiveDirectory,
  outputDirectory,
}) => {
  validatePublicationRecoveryPlan(plan);
  const expectedNames = plan.artifactInventory.downloadManifest.map(({ name }) => name);
  const entries = readdirSync(archiveDirectory, { withFileTypes: true });
  if (
    existsSync(outputDirectory) ||
    entries.some((entry) => !entry.isFile()) ||
    entries
      .map(({ name }) => name)
      .toSorted()
      .join('\0') !==
      expectedNames
        .map((name) => `${name}.zip`)
        .toSorted()
        .join('\0')
  ) {
    fail('E7_PUBLICATION_RECOVERY_ARCHIVE_SET_INVALID');
  }
  mkdirSync(outputDirectory, { recursive: false, mode: 0o700 });
  try {
    for (const expected of plan.artifactInventory.downloadManifest) {
      const archive = readFileSync(path.join(archiveDirectory, `${expected.name}.zip`));
      if (`sha256:${sha256(archive)}` !== expected.digest) {
        fail('E7_PUBLICATION_RECOVERY_ARCHIVE_DIGEST_MISMATCH');
      }
      const files = readReleaseSuccessorZipEntries(archive);
      if (files.size === 0) fail('E7_PUBLICATION_RECOVERY_ARCHIVE_EMPTY');
      const artifactDirectory = path.join(outputDirectory, expected.name);
      mkdirSync(artifactDirectory, { recursive: false, mode: 0o700 });
      for (const [relative, bytes] of files) {
        const filename = path.join(artifactDirectory, ...relative.split('/'));
        mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
        writeFileSync(filename, bytes, { flag: 'wx', mode: 0o600 });
      }
    }
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    throw error;
  }
  return plan;
};

export const extractPublicationRecoveryRouteArtifacts = ({
  plan,
  archiveDirectory,
  outputDirectory,
}) => {
  validatePublicationRecoveryPlan(plan);
  const manifests = [
    ...plan.artifactInventory.sourceFenceManifest,
    ...plan.artifactInventory.sourcePublicationManifest,
  ];
  const entries = readdirSync(archiveDirectory, { withFileTypes: true });
  if (
    existsSync(outputDirectory) ||
    entries.some((entry) => !entry.isFile()) ||
    entries
      .map(({ name }) => name)
      .toSorted()
      .join('\0') !==
      manifests
        .map(({ name }) => `${name}.zip`)
        .toSorted()
        .join('\0')
  ) {
    fail('E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_SET_INVALID');
  }
  mkdirSync(outputDirectory, { recursive: false, mode: 0o700 });
  try {
    for (const manifest of manifests) {
      const archive = readFileSync(path.join(archiveDirectory, `${manifest.name}.zip`));
      if (`sha256:${sha256(archive)}` !== manifest.digest) {
        fail('E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_DIGEST_MISMATCH');
      }
      const expectedNames = manifest.files.map(({ name }) => name);
      const files = exactArchiveFiles(
        archive,
        expectedNames,
        'E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_FILE_SET_INVALID',
      );
      if (
        canonicalJson(
          fileBindings(files, expectedNames, 'E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_JSON_INVALID'),
        ) !== canonicalJson(manifest.files)
      ) {
        fail('E7_PUBLICATION_RECOVERY_ROUTE_ARCHIVE_BINDING_MISMATCH');
      }
      const artifactDirectory = path.join(outputDirectory, manifest.name);
      mkdirSync(artifactDirectory, { recursive: false, mode: 0o700 });
      for (const [name, bytes] of files) {
        writeFileSync(path.join(artifactDirectory, name), bytes, { flag: 'wx', mode: 0o600 });
      }
    }
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    throw error;
  }
  return plan;
};

export const createPublicationRecoveryVerifyOnlyOperation = ({
  plan,
  publicationDirectory,
  liveProofSource,
}) => {
  validatePublicationRecoveryPlan(plan);
  if (plan.route.githubPublicationPolicy !== 'VERIFY_EXACT_NO_MUTATION') {
    fail('E7_PUBLICATION_RECOVERY_VERIFY_ONLY_ROUTE_INVALID');
  }
  const publicationFiles = new Map(
    RECOVERY_PUBLICATION_FILES.map((name) => [
      name,
      readFileSync(path.join(publicationDirectory, name)),
    ]),
  );
  validateSourcePublicationDocuments(publicationFiles, plan.source);
  const sourceOperation = parseJson(
    publicationFiles.get('publication-operation.json'),
    'E7_PUBLICATION_RECOVERY_SOURCE_PUBLICATION_INVALID',
  ).value;
  const liveProofDocument = parseJson(
    liveProofSource,
    'E7_PUBLICATION_RECOVERY_VERIFY_ONLY_PROOF_INVALID',
  );
  const liveProof = liveProofDocument.value;
  const publicationPlan = parseJson(
    publicationFiles.get('publication-plan.json'),
    'E7_PUBLICATION_RECOVERY_SOURCE_PUBLICATION_INVALID',
  ).value;
  if (
    liveProof?.kind !== 'PUBLICATION_PROOF' ||
    liveProof?.status !== 'PASS' ||
    liveProof?.candidateSha !== plan.source.candidateSha ||
    liveProof?.releaseId !== plan.source.releaseId ||
    liveProof?.releaseTag !== plan.source.releaseTag ||
    liveProof?.repository !== RECOVERY_REPOSITORY ||
    liveProof?.releaseVerifiedExact !== true ||
    liveProof?.publicationPlanSha256 !== objectSha256(publicationPlan) ||
    liveProof?.publicationOperationSha256 !== objectSha256(sourceOperation) ||
    !Number.isSafeInteger(liveProof?.externalRequests) ||
    liveProof.externalRequests < 1
  ) {
    fail('E7_PUBLICATION_RECOVERY_VERIFY_ONLY_PROOF_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PUBLICATION_RECOVERY_VERIFY_ONLY_OPERATION',
    status: 'PASS',
    candidateSha: plan.source.candidateSha,
    releaseId: plan.source.releaseId,
    releaseTag: plan.source.releaseTag,
    repository: RECOVERY_REPOSITORY,
    publicationPlanSha256: objectSha256(publicationPlan),
    sourcePublicationOperationSha256: objectSha256(sourceOperation),
    liveProofRawSha256: sha256(liveProofDocument.bytes),
    liveProofCanonicalSha256: objectSha256(liveProof),
    externalRequests: liveProof.externalRequests,
    externalWritesPerformed: 0,
    writeCapability: 'ABSENT_CONTENTS_READ_JOB',
    containsSensitiveData: false,
  };
  return { ...body, operationSha256: objectSha256(body) };
};

const recoveryOperationBinding = ({ source, plan }) => {
  const document = parseJson(source, 'E7_PUBLICATION_RECOVERY_OPERATION_INVALID');
  const operation = document.value;
  const commonValid =
    operation?.status === 'PASS' &&
    operation?.candidateSha === plan.source.candidateSha &&
    operation?.releaseId === plan.source.releaseId &&
    operation?.releaseTag === plan.source.releaseTag &&
    operation?.repository === RECOVERY_REPOSITORY &&
    SHA256.test(operation?.publicationPlanSha256 ?? '') &&
    Number.isSafeInteger(operation?.externalRequests) &&
    operation.externalRequests >= 1 &&
    Number.isSafeInteger(operation?.externalWritesPerformed) &&
    operation.externalWritesPerformed >= 0;
  const verifyOnly = plan.route.githubPublicationPolicy === 'VERIFY_EXACT_NO_MUTATION';
  if (
    !commonValid ||
    (verifyOnly &&
      (operation.kind !== 'PUBLICATION_RECOVERY_VERIFY_ONLY_OPERATION' ||
        operation.externalWritesPerformed !== 0 ||
        operation.writeCapability !== 'ABSENT_CONTENTS_READ_JOB' ||
        operation.operationSha256 !== objectSha256(withoutDigest(operation, 'operationSha256')))) ||
    (!verifyOnly &&
      (operation.kind !== 'GITHUB_PUBLICATION_OPERATION' ||
        operation.releaseState !== 'COMPLETE' ||
        operation.externalWritesPerformed > 2))
  ) {
    fail('E7_PUBLICATION_RECOVERY_OPERATION_INVALID');
  }
  return {
    kind: operation.kind,
    status: operation.status,
    rawSha256: sha256(document.bytes),
    canonicalSha256: objectSha256(operation),
    externalRequests: operation.externalRequests,
    externalWritesPerformed: operation.externalWritesPerformed,
    writeCapability: verifyOnly ? 'ABSENT_CONTENTS_READ_JOB' : 'PROTECTED_CONTENTS_WRITE_JOB',
  };
};

export const createPublicationRecoveryReceipt = ({
  plan,
  publicationDirectory,
  recoveryOperationSource,
  completedAtUtc,
}) => {
  validatePublicationRecoveryPlan(plan);
  if (
    !ISO_UTC.test(completedAtUtc ?? '') ||
    dateMillis(completedAtUtc) < dateMillis(plan.observedAtUtc)
  ) {
    fail('E7_PUBLICATION_RECOVERY_COMPLETION_TIME_INVALID');
  }
  const actual = readdirSync(publicationDirectory, { withFileTypes: true });
  if (
    actual.some((entry) => !entry.isFile()) ||
    actual
      .map(({ name }) => name)
      .toSorted()
      .join('\0') !== RECOVERY_PUBLICATION_FILES.join('\0')
  ) {
    fail('E7_PUBLICATION_RECOVERY_PUBLICATION_FILE_SET_INVALID');
  }
  const files = RECOVERY_PUBLICATION_FILES.map((name) => {
    const bytes = readFileSync(path.join(publicationDirectory, name));
    const document = parseJson(bytes, 'E7_PUBLICATION_RECOVERY_PUBLICATION_JSON_INVALID');
    return {
      name,
      bytes: bytes.length,
      rawSha256: sha256(bytes),
      canonicalSha256: objectSha256(document.value),
    };
  });
  const publicationSources = new Map(
    RECOVERY_PUBLICATION_FILES.map((name) => [
      name,
      readFileSync(path.join(publicationDirectory, name)),
    ]),
  );
  validateSourcePublicationDocuments(publicationSources, plan.source);
  if (
    plan.route.githubPublicationPolicy === 'VERIFY_EXACT_NO_MUTATION' &&
    canonicalJson(files) !==
      canonicalJson(plan.artifactInventory.sourcePublicationManifest[0]?.files)
  ) {
    fail('E7_PUBLICATION_RECOVERY_SOURCE_PUBLICATION_COPY_MISMATCH');
  }
  const recoveryOperation = recoveryOperationBinding({ source: recoveryOperationSource, plan });
  const planBytes = Buffer.from(`${JSON.stringify(plan, null, 2)}\n`, 'utf8');
  const preMutationFiles = [
    {
      name: 'release-successor-completion-fence.json',
      rawSha256: plan.fence.parameterValueRawSha256,
      canonicalSha256: plan.fence.fenceSha256,
    },
    {
      name: RECOVERY_PLAN_BASENAME,
      rawSha256: sha256(planBytes),
      canonicalSha256: objectSha256(plan),
    },
  ].toSorted((left, right) => left.name.localeCompare(right.name));
  const resultPayloadFiles = [
    ...preMutationFiles,
    ...files.map(({ name, rawSha256, canonicalSha256 }) => ({
      name,
      rawSha256,
      canonicalSha256,
    })),
  ].toSorted((left, right) => left.name.localeCompare(right.name));
  const receiptBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_RECEIPT',
    status: 'PUBLICATION_RECOVERED_PENDING_CLOSEOUT_AUTHORITY',
    blockerId: RECOVERY_BLOCKER,
    repository: RECOVERY_REPOSITORY,
    sourceRunId: plan.source.runId,
    sourceRunAttempt: 1,
    recoveryRunId: plan.owner.recoveryRunId,
    recoveryRunAttempt: 1,
    candidateSha: plan.source.candidateSha,
    releaseId: plan.source.releaseId,
    releaseTag: plan.source.releaseTag,
    fenceSha256: plan.fence.fenceSha256,
    planSha256: plan.planSha256,
    authoritySha256: plan.authority.authoritySha256,
    idempotencyKey: plan.route.idempotencyKey,
    crashWindow: plan.route.crashWindow,
    executionMode: plan.route.mode,
    githubPublicationPolicy: plan.route.githubPublicationPolicy,
    fenceEvidenceOrigin: plan.route.fenceEvidenceOrigin,
    publicationEvidenceOrigin: plan.route.publicationEvidenceOrigin,
    canonicalSupplementPolicy: plan.route.canonicalSupplementPolicy,
    publicationFiles: files,
    recoveryOperation,
    artifactExpectations: {
      planArtifactName:
        `stage7-release-successor-publication-recovery-plan-s${plan.source.runId}` +
        `-r${plan.owner.recoveryRunId}-a1`,
      resultArtifactName:
        `stage7-release-successor-publication-recovery-result-s${plan.source.runId}` +
        `-r${plan.owner.recoveryRunId}-a1`,
      preMutationFiles,
      preMutationFilesSha256: objectSha256(preMutationFiles),
      resultPayloadFiles,
      resultPayloadFilesSha256: objectSha256(resultPayloadFiles),
    },
    completedAtUtc,
    sourceRunConclusionUnchanged: true,
    recoveryIntakeWired: true,
    closeoutAuthorityRequired: true,
    stage7GateClaimed: false,
    containsSensitiveData: false,
  };
  const receipt = { ...receiptBody, receiptSha256: objectSha256(receiptBody) };
  validatePublicationRecoveryReceipt(receipt);
  return receipt;
};

export const validatePublicationRecoveryReceipt = (value) => {
  const routeExpectation = expectedRoute(value?.crashWindow);
  const expectedPreMutationFiles = [
    {
      name: 'release-successor-completion-fence.json',
      rawSha256: value?.artifactExpectations?.preMutationFiles?.find(
        ({ name }) => name === 'release-successor-completion-fence.json',
      )?.rawSha256,
      canonicalSha256: value?.fenceSha256,
    },
    {
      name: RECOVERY_PLAN_BASENAME,
      rawSha256: value?.artifactExpectations?.preMutationFiles?.find(
        ({ name }) => name === RECOVERY_PLAN_BASENAME,
      )?.rawSha256,
      canonicalSha256: value?.artifactExpectations?.preMutationFiles?.find(
        ({ name }) => name === RECOVERY_PLAN_BASENAME,
      )?.canonicalSha256,
    },
  ].toSorted((left, right) => left.name.localeCompare(right.name));
  const expectedResultPayloadFiles = [
    ...expectedPreMutationFiles,
    ...(value?.publicationFiles ?? []).map(({ name, rawSha256, canonicalSha256 }) => ({
      name,
      rawSha256,
      canonicalSha256,
    })),
  ].toSorted((left, right) => left.name.localeCompare(right.name));
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'blockerId',
      'repository',
      'sourceRunId',
      'sourceRunAttempt',
      'recoveryRunId',
      'recoveryRunAttempt',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'fenceSha256',
      'planSha256',
      'authoritySha256',
      'idempotencyKey',
      'crashWindow',
      'executionMode',
      'githubPublicationPolicy',
      'fenceEvidenceOrigin',
      'publicationEvidenceOrigin',
      'canonicalSupplementPolicy',
      'publicationFiles',
      'recoveryOperation',
      'artifactExpectations',
      'completedAtUtc',
      'sourceRunConclusionUnchanged',
      'recoveryIntakeWired',
      'closeoutAuthorityRequired',
      'stage7GateClaimed',
      'containsSensitiveData',
      'receiptSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_RECEIPT' ||
    value.status !== 'PUBLICATION_RECOVERED_PENDING_CLOSEOUT_AUTHORITY' ||
    value.blockerId !== RECOVERY_BLOCKER ||
    value.repository !== RECOVERY_REPOSITORY ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    value.sourceRunAttempt !== 1 ||
    !RUN_ID.test(value.recoveryRunId ?? '') ||
    value.recoveryRunAttempt !== 1 ||
    !SHA.test(value.candidateSha ?? '') ||
    !RELEASE_ID.test(value.releaseId ?? '') ||
    !RELEASE_TAG.test(value.releaseTag ?? '') ||
    !SHA256.test(value.fenceSha256 ?? '') ||
    !SHA256.test(value.planSha256 ?? '') ||
    !SHA256.test(value.authoritySha256 ?? '') ||
    !SHA256.test(value.idempotencyKey ?? '') ||
    routeExpectation === null ||
    value.executionMode !== routeExpectation?.mode ||
    value.githubPublicationPolicy !== routeExpectation?.githubPublicationPolicy ||
    value.fenceEvidenceOrigin !== routeExpectation?.fenceEvidenceOrigin ||
    value.publicationEvidenceOrigin !== routeExpectation?.publicationEvidenceOrigin ||
    value.canonicalSupplementPolicy !== 'COPY_EXACT_WITHOUT_SOURCE_DUPLICATION' ||
    !exactArray(
      value.publicationFiles?.map(({ name }) => name),
      RECOVERY_PUBLICATION_FILES,
    ) ||
    value.publicationFiles.some(
      (file) =>
        !exactKeys(file, ['name', 'bytes', 'rawSha256', 'canonicalSha256']) ||
        !Number.isSafeInteger(file.bytes) ||
        file.bytes < 2 ||
        !SHA256.test(file.rawSha256 ?? '') ||
        !SHA256.test(file.canonicalSha256 ?? ''),
    ) ||
    !exactKeys(value.recoveryOperation, [
      'kind',
      'status',
      'rawSha256',
      'canonicalSha256',
      'externalRequests',
      'externalWritesPerformed',
      'writeCapability',
    ]) ||
    value.recoveryOperation?.status !== 'PASS' ||
    !SHA256.test(value.recoveryOperation?.rawSha256 ?? '') ||
    !SHA256.test(value.recoveryOperation?.canonicalSha256 ?? '') ||
    !Number.isSafeInteger(value.recoveryOperation?.externalRequests) ||
    value.recoveryOperation.externalRequests < 1 ||
    !Number.isSafeInteger(value.recoveryOperation?.externalWritesPerformed) ||
    value.recoveryOperation.externalWritesPerformed < 0 ||
    (value.githubPublicationPolicy === 'VERIFY_EXACT_NO_MUTATION' &&
      (value.recoveryOperation.kind !== 'PUBLICATION_RECOVERY_VERIFY_ONLY_OPERATION' ||
        value.recoveryOperation.externalWritesPerformed !== 0 ||
        value.recoveryOperation.writeCapability !== 'ABSENT_CONTENTS_READ_JOB')) ||
    (value.githubPublicationPolicy === 'VERIFY_EXACT_OR_CREATE_MISSING' &&
      (value.recoveryOperation.kind !== 'GITHUB_PUBLICATION_OPERATION' ||
        value.recoveryOperation.externalWritesPerformed > 2 ||
        value.recoveryOperation.writeCapability !== 'PROTECTED_CONTENTS_WRITE_JOB')) ||
    !exactKeys(value.artifactExpectations, [
      'planArtifactName',
      'resultArtifactName',
      'preMutationFiles',
      'preMutationFilesSha256',
      'resultPayloadFiles',
      'resultPayloadFilesSha256',
    ]) ||
    value.artifactExpectations?.planArtifactName !==
      `stage7-release-successor-publication-recovery-plan-s${value.sourceRunId}` +
        `-r${value.recoveryRunId}-a1` ||
    value.artifactExpectations?.resultArtifactName !==
      `stage7-release-successor-publication-recovery-result-s${value.sourceRunId}` +
        `-r${value.recoveryRunId}-a1` ||
    !Array.isArray(value.artifactExpectations?.preMutationFiles) ||
    value.artifactExpectations.preMutationFiles.length !== 2 ||
    !Array.isArray(value.artifactExpectations?.resultPayloadFiles) ||
    value.artifactExpectations.resultPayloadFiles.length !== 7 ||
    [
      ...value.artifactExpectations.preMutationFiles,
      ...value.artifactExpectations.resultPayloadFiles,
    ].some(
      (file) =>
        !exactKeys(file, ['name', 'rawSha256', 'canonicalSha256']) ||
        !SHA256.test(file.rawSha256 ?? '') ||
        !SHA256.test(file.canonicalSha256 ?? ''),
    ) ||
    value.artifactExpectations.preMutationFilesSha256 !==
      objectSha256(value.artifactExpectations.preMutationFiles) ||
    value.artifactExpectations.resultPayloadFilesSha256 !==
      objectSha256(value.artifactExpectations.resultPayloadFiles) ||
    canonicalJson(value.artifactExpectations.preMutationFiles) !==
      canonicalJson(expectedPreMutationFiles) ||
    canonicalJson(value.artifactExpectations.resultPayloadFiles) !==
      canonicalJson(expectedResultPayloadFiles) ||
    !ISO_UTC.test(value.completedAtUtc ?? '') ||
    value.sourceRunConclusionUnchanged !== true ||
    value.recoveryIntakeWired !== true ||
    value.closeoutAuthorityRequired !== true ||
    value.stage7GateClaimed !== false ||
    value.containsSensitiveData !== false ||
    value.receiptSha256 !== objectSha256(withoutDigest(value, 'receiptSha256'))
  ) {
    fail('E7_PUBLICATION_RECOVERY_RECEIPT_INVALID');
  }
  return value;
};

const recoveryResultArtifactPattern = (recoveryRunId) =>
  new RegExp(
    `^stage7-release-successor-publication-recovery-result-s([1-9][0-9]{0,19})-r${recoveryRunId}-a1$`,
    'u',
  );

const recoveryPlanArtifactPattern = (recoveryRunId) =>
  new RegExp(
    `^stage7-release-successor-publication-recovery-plan-s([1-9][0-9]{0,19})-r${recoveryRunId}-a1$`,
    'u',
  );

const exactArchiveRootFiles = (entries, expected) => {
  if (
    entries.size !== expected.length ||
    [...entries.keys()].some(
      (entryPath) =>
        entryPath !== entryPath.normalize('NFC') ||
        path.posix.basename(entryPath) !== entryPath ||
        !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(entryPath),
    ) ||
    [...entries.keys()].toSorted().join('\0') !== expected.toSorted().join('\0')
  ) {
    fail('E7_PUBLICATION_RECOVERY_RESULT_FILE_SET_INVALID');
  }
  return entries;
};

export const readPublicationRecoveryResultArchive = ({
  recoveryRunId,
  recoveryArtifacts,
  planArchive,
  resultArchive,
}) => {
  const runId = String(recoveryRunId);
  if (!RUN_ID.test(runId)) fail('E7_PUBLICATION_RECOVERY_RESULT_RUN_INVALID');
  const resultPattern = recoveryResultArtifactPattern(runId);
  const planPattern = recoveryPlanArtifactPattern(runId);
  const observedArtifacts = normalizeArtifacts(recoveryArtifacts);
  const resultMatches = observedArtifacts.filter((artifact) =>
    resultPattern.test(artifact?.name ?? ''),
  );
  const planMatches = observedArtifacts.filter((artifact) =>
    planPattern.test(artifact?.name ?? ''),
  );
  if (
    observedArtifacts.length !== 2 ||
    new Set(observedArtifacts.map(({ name }) => name)).size !== 2 ||
    new Set(observedArtifacts.map(({ id }) => id)).size !== 2 ||
    resultMatches.length !== 1 ||
    planMatches.length !== 1
  ) {
    fail('E7_PUBLICATION_RECOVERY_RESULT_ARTIFACT_INVALID');
  }
  const resultArtifact = resultMatches[0];
  const planArtifact = planMatches[0];
  const resultNameMatch = resultPattern.exec(resultArtifact.name);
  const planNameMatch = planPattern.exec(planArtifact.name);
  const resultArchiveBytes = Buffer.isBuffer(resultArchive)
    ? Buffer.from(resultArchive)
    : Buffer.from(resultArchive ?? '');
  const planArchiveBytes = Buffer.isBuffer(planArchive)
    ? Buffer.from(planArchive)
    : Buffer.from(planArchive ?? '');
  const validateRecoveryArtifact = (artifact, archive) => {
    if (
      !Number.isSafeInteger(artifact?.id) ||
      artifact.id <= 0 ||
      artifact.expired !== false ||
      !DIGEST.test(artifact.digest ?? '') ||
      `sha256:${sha256(archive)}` !== artifact.digest ||
      asRunId(artifact.workflow_run?.id) !== runId
    ) {
      fail('E7_PUBLICATION_RECOVERY_RESULT_ARTIFACT_INVALID');
    }
    return {
      id: String(artifact.id),
      name: artifact.name,
      digest: artifact.digest,
      archiveBytes: archive.length,
      archiveRawSha256: sha256(archive),
    };
  };
  const planArtifactBinding = validateRecoveryArtifact(planArtifact, planArchiveBytes);
  const resultArtifactBinding = validateRecoveryArtifact(resultArtifact, resultArchiveBytes);
  if (resultNameMatch?.[1] !== planNameMatch?.[1]) {
    fail('E7_PUBLICATION_RECOVERY_RESULT_ARTIFACT_INVALID');
  }
  const preMutationFiles = exactArchiveRootFiles(readReleaseSuccessorZipEntries(planArchiveBytes), [
    'release-successor-completion-fence.json',
    'release-successor-publication-recovery-plan.json',
  ]);
  const files = exactArchiveRootFiles(readReleaseSuccessorZipEntries(resultArchiveBytes), [
    'release-successor-completion-fence.json',
    'release-successor-publication-recovery-plan.json',
    'release-successor-publication-recovery-receipt.json',
    ...RECOVERY_PUBLICATION_FILES,
  ]);
  if (
    !preMutationFiles
      .get('release-successor-completion-fence.json')
      .equals(files.get('release-successor-completion-fence.json')) ||
    !preMutationFiles
      .get('release-successor-publication-recovery-plan.json')
      .equals(files.get('release-successor-publication-recovery-plan.json'))
  ) {
    fail('E7_PUBLICATION_RECOVERY_PREMUTATION_RESULT_MISMATCH');
  }
  const plan = validatePublicationRecoveryPlan(
    parseJson(
      files.get('release-successor-publication-recovery-plan.json'),
      'E7_PUBLICATION_RECOVERY_RESULT_PLAN_INVALID',
    ).value,
  );
  const receipt = validatePublicationRecoveryReceipt(
    parseJson(
      files.get('release-successor-publication-recovery-receipt.json'),
      'E7_PUBLICATION_RECOVERY_RESULT_RECEIPT_INVALID',
    ).value,
  );
  const fenceSource = files.get('release-successor-completion-fence.json');
  const fence = validateReleaseSuccessorCompletionFence(
    parseJson(fenceSource, 'E7_PUBLICATION_RECOVERY_RESULT_FENCE_INVALID').value,
    {
      sourceRunId: plan.source.runId,
      sourceRunAttempt: 1,
      candidateSha: plan.source.candidateSha,
      releaseId: plan.source.releaseId,
      journalCleanupRoleSha256: plan.owner.journalCleanupRoleSha256,
      journalRoleAuthoritySha256: plan.owner.journalRoleAuthoritySha256,
    },
  );
  const planSource = files.get(RECOVERY_PLAN_BASENAME);
  const actualPreMutationFiles = [
    {
      name: 'release-successor-completion-fence.json',
      rawSha256: sha256(fenceSource),
      canonicalSha256: fence.fenceSha256,
    },
    {
      name: RECOVERY_PLAN_BASENAME,
      rawSha256: sha256(planSource),
      canonicalSha256: objectSha256(plan),
    },
  ].toSorted((left, right) => left.name.localeCompare(right.name));
  const actualResultPayloadFiles = [
    ...actualPreMutationFiles,
    ...receipt.publicationFiles.map(({ name, rawSha256, canonicalSha256 }) => ({
      name,
      rawSha256,
      canonicalSha256,
    })),
  ].toSorted((left, right) => left.name.localeCompare(right.name));
  if (
    plan.owner.recoveryRunId !== runId ||
    plan.source.runId !== resultNameMatch?.[1] ||
    plan.fence.fenceSha256 !== fence.fenceSha256 ||
    plan.fence.parameterValueRawSha256 !== sha256(fenceSource) ||
    receipt.sourceRunId !== plan.source.runId ||
    receipt.recoveryRunId !== runId ||
    receipt.candidateSha !== plan.source.candidateSha ||
    receipt.releaseId !== plan.source.releaseId ||
    receipt.releaseTag !== plan.source.releaseTag ||
    receipt.fenceSha256 !== fence.fenceSha256 ||
    receipt.planSha256 !== plan.planSha256 ||
    receipt.authoritySha256 !== plan.authority.authoritySha256 ||
    receipt.idempotencyKey !== plan.route.idempotencyKey ||
    receipt.crashWindow !== plan.route.crashWindow ||
    receipt.executionMode !== plan.route.mode ||
    receipt.githubPublicationPolicy !== plan.route.githubPublicationPolicy ||
    receipt.fenceEvidenceOrigin !== plan.route.fenceEvidenceOrigin ||
    receipt.publicationEvidenceOrigin !== plan.route.publicationEvidenceOrigin ||
    receipt.canonicalSupplementPolicy !== plan.route.canonicalSupplementPolicy ||
    receipt.artifactExpectations.planArtifactName !== planArtifactBinding.name ||
    receipt.artifactExpectations.resultArtifactName !== resultArtifactBinding.name ||
    canonicalJson(receipt.artifactExpectations.preMutationFiles) !==
      canonicalJson(actualPreMutationFiles) ||
    canonicalJson(receipt.artifactExpectations.resultPayloadFiles) !==
      canonicalJson(actualResultPayloadFiles)
  ) {
    fail('E7_PUBLICATION_RECOVERY_RESULT_BINDING_INVALID');
  }
  const sourceFenceFiles = plan.artifactInventory.sourceFenceManifest[0]?.files ?? [];
  if (
    sourceFenceFiles.length === 1 &&
    (sourceFenceFiles[0].name !== 'release-successor-completion-fence.json' ||
      sourceFenceFiles[0].bytes !== fenceSource.length ||
      sourceFenceFiles[0].rawSha256 !== sha256(fenceSource) ||
      sourceFenceFiles[0].canonicalSha256 !== objectSha256(fence))
  ) {
    fail('E7_PUBLICATION_RECOVERY_RESULT_SOURCE_FENCE_BINDING_INVALID');
  }
  if (
    plan.route.githubPublicationPolicy === 'VERIFY_EXACT_NO_MUTATION' &&
    canonicalJson(receipt.publicationFiles) !==
      canonicalJson(plan.artifactInventory.sourcePublicationManifest[0]?.files)
  ) {
    fail('E7_PUBLICATION_RECOVERY_RESULT_SOURCE_PUBLICATION_BINDING_INVALID');
  }
  for (const binding of receipt.publicationFiles) {
    const bytes = files.get(binding.name);
    const parsed = parseJson(bytes, 'E7_PUBLICATION_RECOVERY_RESULT_PUBLICATION_INVALID');
    if (
      bytes.length !== binding.bytes ||
      sha256(bytes) !== binding.rawSha256 ||
      objectSha256(parsed.value) !== binding.canonicalSha256
    ) {
      fail('E7_PUBLICATION_RECOVERY_RESULT_PUBLICATION_INVALID');
    }
  }
  return {
    artifacts: {
      plan: planArtifactBinding,
      result: resultArtifactBinding,
    },
    plan,
    receipt,
    fence,
  };
};

export const createPublicationRecoveryPostSuccessIntake = ({
  recoveryRun,
  recoveryWorkflow,
  recoveryArtifacts,
  planArchive,
  resultArchive,
  sourceRun,
  sourceWorkflow,
  sourceJobs,
  sourceArtifacts,
  observedAtUtc,
}) => {
  if (!ISO_UTC.test(observedAtUtc ?? '')) {
    fail('E7_PUBLICATION_RECOVERY_INTAKE_TIME_INVALID');
  }
  const recoveryRunId = asRunId(recoveryRun?.id);
  const result = readPublicationRecoveryResultArchive({
    recoveryRunId,
    recoveryArtifacts,
    planArchive,
    resultArchive,
  });
  if (
    recoveryRun?.run_attempt !== 1 ||
    recoveryRun?.repository?.full_name !== RECOVERY_REPOSITORY ||
    recoveryRun?.event !== 'workflow_dispatch' ||
    recoveryRun?.head_branch !== 'master' ||
    recoveryRun?.status !== 'completed' ||
    recoveryRun?.conclusion !== 'success' ||
    recoveryWorkflow?.name !== 'Stage 7 Release Successor Publication Recovery' ||
    recoveryWorkflow?.path !== RECOVERY_WORKFLOW ||
    recoveryWorkflow?.state !== 'active'
  ) {
    fail('E7_PUBLICATION_RECOVERY_INTAKE_RECOVERY_RUN_INVALID');
  }
  const source = validateSourceRun({
    run: sourceRun,
    workflow: sourceWorkflow,
    jobs: sourceJobs,
    expected: {
      sourceRunId: result.plan.source.runId,
      candidateSha: result.plan.source.candidateSha,
    },
  });
  const sourceManifest = validateArtifactInventory({
    artifacts: sourceArtifacts,
    sourceRunId: result.plan.source.runId,
    crashWindow: source.crashWindow,
  });
  const stripFiles = (manifest) =>
    manifest.map(({ files: ignored, ...metadata }) => {
      void ignored;
      return metadata;
    });
  const plannedInventory = {
    observedCount: result.plan.artifactInventory.observedCount,
    downloadManifest: result.plan.artifactInventory.downloadManifest,
    internalManifest: result.plan.artifactInventory.internalManifest,
    incompleteSummaryManifest: result.plan.artifactInventory.incompleteSummaryManifest,
    sourceFenceManifest: stripFiles(result.plan.artifactInventory.sourceFenceManifest),
    sourcePublicationManifest: stripFiles(result.plan.artifactInventory.sourcePublicationManifest),
  };
  if (
    canonicalJson(sourceManifest) !== canonicalJson(plannedInventory) ||
    source.conclusion !== result.plan.source.conclusion ||
    source.crashWindow !== result.plan.source.crashWindow ||
    canonicalJson(source.fenceJob) !== canonicalJson(result.plan.source.fenceJob) ||
    canonicalJson(source.publicationJob) !== canonicalJson(result.plan.source.publicationJob) ||
    canonicalJson(source.summaryJob) !== canonicalJson(result.plan.source.summaryJob) ||
    result.receipt.crashWindow !== result.plan.route.crashWindow ||
    result.receipt.githubPublicationPolicy !== result.plan.route.githubPublicationPolicy
  ) {
    fail('E7_PUBLICATION_RECOVERY_INTAKE_SOURCE_REQUERY_MISMATCH');
  }
  const intakeBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_POST_SUCCESS_INTAKE',
    status: 'BLOCKED_CLOSEOUT_AUTHORITY',
    blockerId: RECOVERY_CLOSEOUT_BLOCKER,
    repository: RECOVERY_REPOSITORY,
    recoveryWorkflowPath: RECOVERY_WORKFLOW,
    protectedEnvironment: RECOVERY_ENVIRONMENT,
    observedAtUtc,
    source: {
      runId: result.plan.source.runId,
      runAttempt: 1,
      conclusion: result.plan.source.conclusion,
      candidateSha: result.plan.source.candidateSha,
      releaseId: result.plan.source.releaseId,
      releaseTag: result.plan.source.releaseTag,
      crashWindow: result.plan.source.crashWindow,
    },
    recovery: {
      runId: recoveryRunId,
      runAttempt: 1,
      conclusion: 'success',
      planArtifactId: result.artifacts.plan.id,
      planArtifactName: result.artifacts.plan.name,
      planArtifactDigest: result.artifacts.plan.digest,
      planArchiveRawSha256: result.artifacts.plan.archiveRawSha256,
      resultArtifactId: result.artifacts.result.id,
      resultArtifactName: result.artifacts.result.name,
      resultArtifactDigest: result.artifacts.result.digest,
      resultArchiveRawSha256: result.artifacts.result.archiveRawSha256,
      executionMode: result.plan.route.mode,
      githubPublicationPolicy: result.plan.route.githubPublicationPolicy,
      recoveryGithubWritesPerformed: result.receipt.recoveryOperation.externalWritesPerformed,
    },
    bindings: {
      fenceSha256: result.fence.fenceSha256,
      planSha256: result.plan.planSha256,
      receiptSha256: result.receipt.receiptSha256,
      authoritySha256: result.receipt.authoritySha256,
      idempotencyKey: result.receipt.idempotencyKey,
      sourceInventoryMetadataSha256: result.plan.artifactInventory.inventoryMetadataSha256,
      sourceInventorySha256: result.plan.artifactInventory.inventorySha256,
    },
    closeoutAuthority: {
      requiredKind: 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_CLOSEOUT_AUTHORITY',
      present: false,
      derivableFromPublicationAuthority: false,
      requiredAction: 'AUTHORIZE_COMPOSITE_STAGE7_CLOSEOUT_AND_POST_SUCCESS',
    },
    sourceRunConclusionUnchanged: true,
    compositeGateClaimed: false,
    awsMutationsPerformed: 0,
    githubMutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const intake = { ...intakeBody, intakeSha256: objectSha256(intakeBody) };
  validatePublicationRecoveryPostSuccessIntake(intake);
  return intake;
};

export const validatePublicationRecoveryPostSuccessIntake = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'blockerId',
      'repository',
      'recoveryWorkflowPath',
      'protectedEnvironment',
      'observedAtUtc',
      'source',
      'recovery',
      'bindings',
      'closeoutAuthority',
      'sourceRunConclusionUnchanged',
      'compositeGateClaimed',
      'awsMutationsPerformed',
      'githubMutationsPerformed',
      'containsSensitiveData',
      'intakeSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_POST_SUCCESS_INTAKE' ||
    value.status !== 'BLOCKED_CLOSEOUT_AUTHORITY' ||
    value.blockerId !== RECOVERY_CLOSEOUT_BLOCKER ||
    value.repository !== RECOVERY_REPOSITORY ||
    value.recoveryWorkflowPath !== RECOVERY_WORKFLOW ||
    value.protectedEnvironment !== RECOVERY_ENVIRONMENT ||
    !ISO_UTC.test(value.observedAtUtc ?? '') ||
    !exactKeys(value.source, [
      'runId',
      'runAttempt',
      'conclusion',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'crashWindow',
    ]) ||
    !RUN_ID.test(value.source?.runId ?? '') ||
    value.source?.runAttempt !== 1 ||
    !['failure', 'cancelled', 'timed_out'].includes(value.source?.conclusion) ||
    !SHA.test(value.source?.candidateSha ?? '') ||
    !RELEASE_ID.test(value.source?.releaseId ?? '') ||
    !RELEASE_TAG.test(value.source?.releaseTag ?? '') ||
    !RECOVERY_CRASH_WINDOWS.includes(value.source?.crashWindow) ||
    !exactKeys(value.recovery, [
      'runId',
      'runAttempt',
      'conclusion',
      'planArtifactId',
      'planArtifactName',
      'planArtifactDigest',
      'planArchiveRawSha256',
      'resultArtifactId',
      'resultArtifactName',
      'resultArtifactDigest',
      'resultArchiveRawSha256',
      'executionMode',
      'githubPublicationPolicy',
      'recoveryGithubWritesPerformed',
    ]) ||
    !RUN_ID.test(value.recovery?.runId ?? '') ||
    value.recovery?.runAttempt !== 1 ||
    value.recovery?.conclusion !== 'success' ||
    !RUN_ID.test(value.recovery?.planArtifactId ?? '') ||
    value.recovery?.planArtifactName !==
      `stage7-release-successor-publication-recovery-plan-s${value.source.runId}` +
        `-r${value.recovery.runId}-a1` ||
    !DIGEST.test(value.recovery?.planArtifactDigest ?? '') ||
    !SHA256.test(value.recovery?.planArchiveRawSha256 ?? '') ||
    !RUN_ID.test(value.recovery?.resultArtifactId ?? '') ||
    value.recovery?.resultArtifactName !==
      `stage7-release-successor-publication-recovery-result-s${value.source.runId}` +
        `-r${value.recovery.runId}-a1` ||
    !DIGEST.test(value.recovery?.resultArtifactDigest ?? '') ||
    !SHA256.test(value.recovery?.resultArchiveRawSha256 ?? '') ||
    value.recovery?.executionMode !== expectedRoute(value.source.crashWindow)?.mode ||
    value.recovery?.githubPublicationPolicy !==
      expectedRoute(value.source.crashWindow)?.githubPublicationPolicy ||
    !Number.isSafeInteger(value.recovery?.recoveryGithubWritesPerformed) ||
    value.recovery.recoveryGithubWritesPerformed < 0 ||
    (value.recovery.githubPublicationPolicy === 'VERIFY_EXACT_NO_MUTATION' &&
      value.recovery.recoveryGithubWritesPerformed !== 0) ||
    (value.recovery.githubPublicationPolicy === 'VERIFY_EXACT_OR_CREATE_MISSING' &&
      value.recovery.recoveryGithubWritesPerformed > 2) ||
    !exactKeys(value.bindings, [
      'fenceSha256',
      'planSha256',
      'receiptSha256',
      'authoritySha256',
      'idempotencyKey',
      'sourceInventoryMetadataSha256',
      'sourceInventorySha256',
    ]) ||
    !Object.values(value.bindings ?? {}).every((binding) => SHA256.test(binding ?? '')) ||
    !exactKeys(value.closeoutAuthority, [
      'requiredKind',
      'present',
      'derivableFromPublicationAuthority',
      'requiredAction',
    ]) ||
    value.closeoutAuthority?.requiredKind !==
      'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_CLOSEOUT_AUTHORITY' ||
    value.closeoutAuthority?.present !== false ||
    value.closeoutAuthority?.derivableFromPublicationAuthority !== false ||
    value.closeoutAuthority?.requiredAction !==
      'AUTHORIZE_COMPOSITE_STAGE7_CLOSEOUT_AND_POST_SUCCESS' ||
    value.sourceRunConclusionUnchanged !== true ||
    value.compositeGateClaimed !== false ||
    value.awsMutationsPerformed !== 0 ||
    value.githubMutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.intakeSha256 !== objectSha256(withoutDigest(value, 'intakeSha256'))
  ) {
    fail('E7_PUBLICATION_RECOVERY_POST_SUCCESS_INTAKE_INVALID');
  }
  return value;
};
