import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { sha256 } from '../stage6/lib/evidence.mjs';
import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256 } from './core.mjs';
import {
  RECOVERY_CRASH_WINDOWS,
  RECOVERY_REPOSITORY,
  RECOVERY_SOURCE_WORKFLOW,
  RECOVERY_SOURCE_WORKFLOW_NAME,
  RECOVERY_WORKFLOW,
  createPublicationRecoveryPostSuccessIntake,
  extractPublicationRecoveryArtifacts,
  readPublicationRecoveryResultArchive,
  validatePublicationRecoveryPostSuccessIntake,
} from './release-successor-publication-recovery-contract.mjs';
import { readReleaseSuccessorZipEntries } from './release-successor-zip.mjs';

export const RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_NAME =
  'Stage 7 Release Successor Post-Success';
export const RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH =
  '.github/workflows/stage7-release-successor-post-success.yml';
export const RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT =
  'assessment-release-successor-post-success';
export const RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME =
  'Stage 7 Release Successor Publication Recovery';
export const RELEASE_SUCCESSOR_RECOVERY_COMPOSITE_STATUS = 'POST_SUCCESS_COMPOSITE_REQUIRED';
export const RELEASE_SUCCESSOR_RECOVERY_SHARED_CONTRACT = 'WIRED_CONTRACT';

const API_ROOT = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 1024 * 1024;
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const SAFE_ALIAS = /^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u;

const RECOVERY_ROUTE_EXPECTATIONS = Object.freeze(
  new Map([
    [
      RECOVERY_CRASH_WINDOWS[0],
      Object.freeze({
        executionMode: 'FORWARD_ONLY_IDEMPOTENT',
        githubPublicationPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
        fenceEvidenceOrigin: 'SSM_REHYDRATED',
        publicationEvidenceOrigin: 'RECOVERY_VERIFIED_OUTPUT',
        canonicalSupplementPolicy: 'COPY_EXACT_WITHOUT_SOURCE_DUPLICATION',
      }),
    ],
    [
      RECOVERY_CRASH_WINDOWS[1],
      Object.freeze({
        executionMode: 'FORWARD_ONLY_IDEMPOTENT',
        githubPublicationPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
        fenceEvidenceOrigin: 'SOURCE_ARTIFACT_BYTE_EQUAL_SSM',
        publicationEvidenceOrigin: 'RECOVERY_VERIFIED_OUTPUT',
        canonicalSupplementPolicy: 'COPY_EXACT_WITHOUT_SOURCE_DUPLICATION',
      }),
    ],
    [
      RECOVERY_CRASH_WINDOWS[2],
      Object.freeze({
        executionMode: 'VERIFY_EXACT_NOOP',
        githubPublicationPolicy: 'VERIFY_EXACT_NO_MUTATION',
        fenceEvidenceOrigin: 'SOURCE_ARTIFACT_BYTE_EQUAL_SSM',
        publicationEvidenceOrigin: 'SOURCE_ARTIFACT_LIVE_VERIFIED',
        canonicalSupplementPolicy: 'COPY_EXACT_WITHOUT_SOURCE_DUPLICATION',
      }),
    ],
  ]),
);

const RECOVERY_JOB_MAP = Object.freeze(
  new Map([
    ['Validate isolated publication recovery contract', 'validate-contract'],
    ['Preflight exact crash window under read-only GitHub authority', 'preflight-read-only'],
    ['Forward-only A or B publication under write authority', 'forward-publication'],
  ]),
);
export const RELEASE_SUCCESSOR_RECOVERY_JOB_IDS = Object.freeze(
  [...RECOVERY_JOB_MAP.values()].toSorted(),
);
const expectedRecoveryJobConclusion = ({ id, crashWindow }) =>
  id === 'forward-publication' && crashWindow === RECOVERY_CRASH_WINDOWS[2] ? 'skipped' : 'success';

const SOURCE_JOB_MAP = Object.freeze(
  new Map([
    ['01 Release metadata', 'release-metadata'],
    ['02 Verify candidate', 'verify-candidate'],
    ['03 Build or fetch immutable artifacts', 'build-or-fetch'],
    ['04 Checksums, inventory and provenance', 'checksums-sbom'],
    ['05 Secret scan', 'secret-scan'],
    ['06 AWS read-only identity', 'aws-auth'],
    ['07 IaC tests and offline synthesis', 'infra-synth-test'],
    ['08 IaC diff and change review', 'infra-diff'],
    ['09 Protected release approval', 'approval'],
    ['10 Deploy data and seed', 'deploy-data'],
    ['11 Deploy API and reconciler', 'deploy-api'],
    ['12 Deploy observability and budget', 'deploy-observability'],
    ['13 Deploy web and edge', 'deploy-web'],
    ['14 Post-deploy smoke', 'postdeploy-smoke'],
    ['15 Edge security', 'edge-security'],
    ['16 Cross-browser, accessibility and performance quality', 'quality'],
    ['17 Authorized sandbox smoke', 'sandbox-smoke'],
    ['18 Automatic durable recovery probe', 'emergency-recovery'],
    ['19 Open the immutable release reconciliation journal', 'release-reconciliation-intent'],
    ['20 Rollback and re-promotion rehearsal', 'rollback-check'],
    ['21 Protected rollback resilience', 'rollback-resilience'],
    ['22 Reconcile the exact candidate before publication', 'release-reconciliation'],
    ['23 Seal immutable pre-publication fence', 'release-successor-fence'],
    ['24 Publish release', 'publish-release'],
    ['25 Release summary and gates', 'summary'],
  ]),
);
export const RELEASE_SUCCESSOR_SOURCE_JOBS = Object.freeze(
  [...SOURCE_JOB_MAP.entries()].map(([name, id]) => Object.freeze({ id, name })),
);
export const RELEASE_SUCCESSOR_SOURCE_JOB_IDS = Object.freeze(
  RELEASE_SUCCESSOR_SOURCE_JOBS.map(({ id }) => id),
);
export const RELEASE_SUCCESSOR_COMPOSITE_GATE_JOB_IDS = Object.freeze(
  RELEASE_SUCCESSOR_SOURCE_JOB_IDS.filter((id) => id !== 'summary'),
);

export const RELEASE_SUCCESSOR_RECOVERY_CLOSEOUT_ALLOWED_ACTIONS = Object.freeze([
  'CONSOLIDATE_EXACT_SOURCE_AND_RECOVERY_EVIDENCE',
  'EMIT_COMPOSITE_STAGE7_AUTHORITIES_AND_REPORTS',
  'PRESERVE_EXACT_SUCCESSOR_SOURCE',
  'CLEAN_JOURNALS_ONLY_AFTER_DURABLE_SOURCE_VERIFICATION',
]);

export const RELEASE_SUCCESSOR_RECOVERY_CLOSEOUT_FORBIDDEN_ACTIONS = Object.freeze([
  'CHANGE_SOURCE_RUN_CONCLUSION',
  'CHANGE_RECOVERY_RUN_CONCLUSION',
  'REEXECUTE_GITHUB_PUBLICATION',
  'SUBSTITUTE_SOURCE_ARTIFACT_BYTES',
  'CLEAN_BEFORE_DURABLE_SOURCE_VERIFICATION',
]);

export class Stage7ReleaseSuccessorRecoveryIntegrationError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseSuccessorRecoveryIntegrationError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseSuccessorRecoveryIntegrationError(
    code,
    cause === undefined ? undefined : { cause },
  );
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const exactArray = (actual, expected) =>
  Array.isArray(actual) && canonicalJson(actual) === canonicalJson(expected);
const utc = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return false;
  return new Date(value).toISOString() === value;
};
const withoutDigest = (value, key) => {
  const body = { ...value };
  delete body[key];
  return body;
};
const strictJsonDocument = (source, code) => {
  try {
    const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
    if (bytes.length < 2 || bytes.length > MAX_RESPONSE_BYTES) fail(code);
    const value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
    return {
      bytes,
      value,
      rawSha256: sha256(bytes),
      canonicalSha256: objectSha256(value),
    };
  } catch (error) {
    if (error instanceof Stage7ReleaseSuccessorRecoveryIntegrationError) throw error;
    fail(code, error);
  }
};
const normalizeJobs = (value) => {
  const pages = Array.isArray(value) ? value : [value];
  if (pages.length !== 1 || !object(pages[0]) || !Array.isArray(pages[0].jobs)) return [];
  const [{ jobs, total_count: totalCount }] = pages;
  return Number.isSafeInteger(totalCount) && totalCount === jobs.length ? jobs : [];
};
const asRunId = (value) => String(value ?? '');
const validPostSuccessAttempt = (value) =>
  Number.isSafeInteger(value) && value >= 1 && value <= 100;

const validateRecoveryJobs = ({ source, recoveryRunId, crashWindow }) => {
  const document = strictJsonDocument(source, 'E7_RECOVERY_CLOSEOUT_JOBS_INVALID');
  const jobs = normalizeJobs(document.value).filter((job) => job?.run_attempt === 1);
  const expectedConclusions = new Map(
    RELEASE_SUCCESSOR_RECOVERY_JOB_IDS.map((id) => [
      id,
      expectedRecoveryJobConclusion({ id, crashWindow }),
    ]),
  );
  if (
    !RECOVERY_ROUTE_EXPECTATIONS.has(crashWindow) ||
    jobs.length !== RECOVERY_JOB_MAP.size ||
    new Set(jobs.map(({ name }) => name)).size !== jobs.length ||
    jobs.some(
      (job) =>
        !RECOVERY_JOB_MAP.has(job?.name) ||
        asRunId(job?.run_id) !== recoveryRunId ||
        job?.status !== 'completed' ||
        job?.conclusion !== expectedConclusions.get(RECOVERY_JOB_MAP.get(job.name)) ||
        !Number.isSafeInteger(job?.id) ||
        job.id < 1,
    )
  ) {
    fail('E7_RECOVERY_CLOSEOUT_JOBS_INVALID');
  }
  return {
    document,
    jobs: jobs
      .map((job) => ({
        id: RECOVERY_JOB_MAP.get(job.name),
        githubJobId: String(job.id),
        name: job.name,
        conclusion: job.conclusion,
      }))
      .toSorted((left, right) => left.id.localeCompare(right.id)),
  };
};

const nonSuccessConclusion = (value) => ['failure', 'cancelled', 'timed_out'].includes(value);
const expectedSourceJobConclusion = ({ id, crashWindow }) => {
  if (id === 'summary') return 'NON_SUCCESS';
  if (id === 'release-successor-fence') {
    return crashWindow === RECOVERY_CRASH_WINDOWS[0] ? 'NON_SUCCESS' : 'success';
  }
  if (id === 'publish-release') {
    if (crashWindow === RECOVERY_CRASH_WINDOWS[0]) return 'skipped';
    return crashWindow === RECOVERY_CRASH_WINDOWS[1] ? 'NON_SUCCESS' : 'success';
  }
  return 'success';
};
const validateSourceJobs = ({ source, sourceRunId, crashWindow }) => {
  const document = strictJsonDocument(source, 'E7_RECOVERY_CLOSEOUT_SOURCE_JOBS_INVALID');
  const jobs = normalizeJobs(document.value).filter((job) => job?.run_attempt === 1);
  if (
    !RECOVERY_ROUTE_EXPECTATIONS.has(crashWindow) ||
    jobs.length !== SOURCE_JOB_MAP.size ||
    new Set(jobs.map(({ name }) => name)).size !== jobs.length ||
    jobs.some((job) => {
      const id = SOURCE_JOB_MAP.get(job?.name);
      const expected = expectedSourceJobConclusion({ id, crashWindow });
      return (
        id === undefined ||
        asRunId(job?.run_id) !== sourceRunId ||
        job?.status !== 'completed' ||
        (expected === 'NON_SUCCESS'
          ? !nonSuccessConclusion(job?.conclusion)
          : job?.conclusion !== expected) ||
        !Number.isSafeInteger(job?.id) ||
        job.id < 1
      );
    })
  ) {
    fail('E7_RECOVERY_CLOSEOUT_SOURCE_JOBS_INVALID');
  }
  const byId = new Map(jobs.map((job) => [SOURCE_JOB_MAP.get(job.name), job]));
  return {
    document,
    jobs: RELEASE_SUCCESSOR_SOURCE_JOB_IDS.map((id) => {
      const job = byId.get(id);
      return {
        id,
        githubJobId: String(job.id),
        name: job.name,
        conclusion: job.conclusion,
      };
    }),
  };
};
const validateSourceJobsAgainstResult = ({ sourceJobs, result }) => {
  const byId = new Map(sourceJobs.jobs.map((job) => [job.id, job]));
  for (const [id, planned] of [
    ['release-successor-fence', result.plan.source.fenceJob],
    ['publish-release', result.plan.source.publicationJob],
    ['summary', result.plan.source.summaryJob],
  ]) {
    const observed = byId.get(id);
    if (observed?.githubJobId !== planned.id || observed?.conclusion !== planned.conclusion) {
      fail('E7_RECOVERY_CLOSEOUT_SOURCE_JOBS_PLAN_MISMATCH');
    }
  }
  return sourceJobs;
};

const validateTrigger = ({ source, intake, recoveryHeadSha }) => {
  const document = strictJsonDocument(source, 'E7_RECOVERY_CLOSEOUT_TRIGGER_INVALID');
  const trigger = document.value;
  const run = trigger?.workflow_run;
  if (
    trigger?.action !== 'completed' ||
    trigger?.repository?.full_name !== RECOVERY_REPOSITORY ||
    asRunId(run?.id) !== intake.recovery.runId ||
    run?.run_attempt !== 1 ||
    run?.name !== RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME ||
    run?.event !== 'workflow_dispatch' ||
    run?.head_branch !== 'master' ||
    run?.head_sha !== recoveryHeadSha ||
    run?.status !== 'completed' ||
    run?.conclusion !== 'success'
  ) {
    fail('E7_RECOVERY_CLOSEOUT_TRIGGER_INVALID');
  }
  return document;
};

const expectedApprovalComment = ({ sourceRunId, recoveryRunId, receiptSha256 }) =>
  `STAGE7_PUBLICATION_RECOVERY_CLOSEOUT source=${sourceRunId} recovery=${recoveryRunId} receipt=${receiptSha256}`;

const validateApprovalResponse = ({ source, intake }) => {
  const document = strictJsonDocument(source, 'E7_RECOVERY_CLOSEOUT_APPROVAL_INVALID');
  if (!Array.isArray(document.value)) fail('E7_RECOVERY_CLOSEOUT_APPROVAL_INVALID');
  const matches = document.value.filter(
    (review) =>
      object(review) &&
      Array.isArray(review.environments) &&
      review.environments.some(
        (environment) => environment?.name === RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT,
      ),
  );
  const review = matches[0];
  const environment = review?.environments?.[0];
  const reviewerAlias = review?.user?.login?.toLowerCase();
  if (
    matches.length !== 1 ||
    review.environments.length !== 1 ||
    review.state !== 'approved' ||
    review.comment !==
      expectedApprovalComment({
        sourceRunId: intake.source.runId,
        recoveryRunId: intake.recovery.runId,
        receiptSha256: intake.bindings.receiptSha256,
      }) ||
    environment?.name !== RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT ||
    environment?.url !==
      `${API_ROOT}/repos/${RECOVERY_REPOSITORY}/environments/${RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT}` ||
    !Number.isSafeInteger(environment?.id) ||
    environment.id < 1 ||
    review?.user?.type !== 'User' ||
    !Number.isSafeInteger(review?.user?.id) ||
    review.user.id < 1 ||
    !SAFE_ALIAS.test(reviewerAlias ?? '') ||
    reviewerAlias === 'github-actions'
  ) {
    fail('E7_RECOVERY_CLOSEOUT_APPROVAL_INVALID');
  }
  return { document, reviewerAlias };
};

const validateContext = ({ context, intake, recoveryHeadSha }) => {
  if (
    !exactKeys(context, [
      'repository',
      'runId',
      'runAttempt',
      'workflowName',
      'workflowPath',
      'eventName',
      'headSha',
      'protectedEnvironment',
      'githubActions',
    ]) ||
    context.repository !== RECOVERY_REPOSITORY ||
    !RUN_ID.test(context.runId ?? '') ||
    !validPostSuccessAttempt(context.runAttempt) ||
    context.workflowName !== RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_NAME ||
    context.workflowPath !== RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH ||
    context.eventName !== 'workflow_run' ||
    context.headSha !== recoveryHeadSha ||
    context.protectedEnvironment !== RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT ||
    context.githubActions !== 'true' ||
    context.runId === intake.source.runId ||
    context.runId === intake.recovery.runId
  ) {
    fail('E7_RECOVERY_CLOSEOUT_CONTEXT_INVALID');
  }
  return context;
};

const recoveryArtifactsResponse = (intake) => ({
  total_count: 2,
  artifacts: [
    {
      id: Number(intake.recovery.planArtifactId),
      name: intake.recovery.planArtifactName,
      digest: intake.recovery.planArtifactDigest,
      expired: false,
      workflow_run: { id: Number(intake.recovery.runId) },
    },
    {
      id: Number(intake.recovery.resultArtifactId),
      name: intake.recovery.resultArtifactName,
      digest: intake.recovery.resultArtifactDigest,
      expired: false,
      workflow_run: { id: Number(intake.recovery.runId) },
    },
  ],
});

export const readReleaseSuccessorRecoveryResultFromIntake = ({
  intake: input,
  planArchive,
  resultArchive,
}) => {
  const intake = validatePublicationRecoveryPostSuccessIntake(input);
  const result = readPublicationRecoveryResultArchive({
    recoveryRunId: intake.recovery.runId,
    recoveryArtifacts: recoveryArtifactsResponse(intake),
    planArchive,
    resultArchive,
  });
  if (
    result.plan.planSha256 !== intake.bindings.planSha256 ||
    result.receipt.receiptSha256 !== intake.bindings.receiptSha256 ||
    result.fence.fenceSha256 !== intake.bindings.fenceSha256 ||
    result.receipt.authoritySha256 !== intake.bindings.authoritySha256 ||
    result.receipt.idempotencyKey !== intake.bindings.idempotencyKey ||
    result.artifacts.plan.archiveRawSha256 !== intake.recovery.planArchiveRawSha256 ||
    result.artifacts.result.archiveRawSha256 !== intake.recovery.resultArchiveRawSha256 ||
    result.plan.source.crashWindow !== intake.source.crashWindow ||
    result.plan.route.mode !== intake.recovery.executionMode ||
    result.plan.route.githubPublicationPolicy !== intake.recovery.githubPublicationPolicy ||
    result.receipt.recoveryOperation.externalWritesPerformed !==
      intake.recovery.recoveryGithubWritesPerformed ||
    result.plan.artifactInventory.inventoryMetadataSha256 !==
      intake.bindings.sourceInventoryMetadataSha256 ||
    result.plan.artifactInventory.inventorySha256 !== intake.bindings.sourceInventorySha256
  ) {
    fail('E7_RECOVERY_CLOSEOUT_RESULT_MISMATCH');
  }
  return result;
};

export const extractReleaseSuccessorRecoveryCompositeInputs = ({
  intake: input,
  sourceArchiveDirectory,
  planArchive,
  resultArchive,
  outputDirectory,
}) => {
  const intake = validatePublicationRecoveryPostSuccessIntake(input);
  const result = readReleaseSuccessorRecoveryResultFromIntake({
    intake,
    planArchive,
    resultArchive,
  });
  if (existsSync(outputDirectory)) fail('E7_RECOVERY_COMPOSITE_OUTPUT_EXISTS');
  try {
    extractPublicationRecoveryArtifacts({
      plan: result.plan,
      archiveDirectory: sourceArchiveDirectory,
      outputDirectory,
    });
    const entries = readReleaseSuccessorZipEntries(resultArchive);
    const byBasename = new Map();
    for (const [entryPath, bytes] of entries) {
      const basename = path.posix.basename(entryPath);
      if (!byBasename.has(basename)) byBasename.set(basename, []);
      byBasename.get(basename).push(bytes);
    }
    const fenceBasename = 'release-successor-completion-fence.json';
    const publicationBasenames = result.receipt.publicationFiles.map(({ name }) => name);
    const selected = [fenceBasename, ...publicationBasenames];
    if (selected.some((basename) => byBasename.get(basename)?.length !== 1)) {
      fail('E7_RECOVERY_COMPOSITE_RESULT_FILE_SET_INVALID');
    }
    const fenceDirectory = path.join(outputDirectory, 'stage7-release-successor-fence');
    const publicationDirectory = path.join(outputDirectory, 'stage7-publication');
    mkdirSync(fenceDirectory, { recursive: false, mode: 0o700 });
    mkdirSync(publicationDirectory, { recursive: false, mode: 0o700 });
    writeFileSync(path.join(fenceDirectory, fenceBasename), byBasename.get(fenceBasename)[0], {
      flag: 'wx',
      mode: 0o600,
    });
    for (const basename of publicationBasenames) {
      writeFileSync(path.join(publicationDirectory, basename), byBasename.get(basename)[0], {
        flag: 'wx',
        mode: 0o600,
      });
    }
    return {
      sourceRunId: intake.source.runId,
      recoveryRunId: intake.recovery.runId,
      sourceArtifactCount: result.plan.artifactInventory.requiredCount,
      recoveredArtifactCount: 2,
      resultArtifactDigest: intake.recovery.resultArtifactDigest,
    };
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    throw error;
  }
};

export const validateReleaseSuccessorRecoveryCloseoutAuthority = (
  value,
  { intake: expectedIntake } = {},
) => {
  const routeExpectation = RECOVERY_ROUTE_EXPECTATIONS.get(value?.source?.crashWindow);
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'sharedContract',
      'repository',
      'protectedEnvironment',
      'source',
      'recovery',
      'postSuccess',
      'bindings',
      'allowedActions',
      'forbiddenActions',
      'sourceRunConclusionUnchanged',
      'recoveryRunConclusionVerified',
      'publicationReexecutionAllowed',
      'cleanupAllowedAfterDurableSourceOnly',
      'authorizedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'closeoutAuthoritySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_CLOSEOUT_AUTHORITY' ||
    value.status !== 'AUTHORIZED_COMPOSITE_CLOSEOUT' ||
    value.sharedContract !== RELEASE_SUCCESSOR_RECOVERY_SHARED_CONTRACT ||
    value.repository !== RECOVERY_REPOSITORY ||
    value.protectedEnvironment !== RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT ||
    !exactKeys(value.source, [
      'workflowName',
      'workflowPath',
      'runId',
      'runAttempt',
      'conclusion',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'crashWindow',
      'jobs',
      'jobsResponseRawSha256',
      'jobsResponseCanonicalSha256',
    ]) ||
    value.source.workflowName !== RECOVERY_SOURCE_WORKFLOW_NAME ||
    value.source.workflowPath !== RECOVERY_SOURCE_WORKFLOW ||
    !RUN_ID.test(value.source.runId ?? '') ||
    value.source.runAttempt !== 1 ||
    !['failure', 'cancelled', 'timed_out'].includes(value.source.conclusion) ||
    !SHA.test(value.source.candidateSha ?? '') ||
    !routeExpectation ||
    !exactArray(
      value.source.jobs?.map(({ id }) => id),
      RELEASE_SUCCESSOR_SOURCE_JOB_IDS,
    ) ||
    value.source.jobs.some((job) => {
      const expected = expectedSourceJobConclusion({
        id: job.id,
        crashWindow: value.source.crashWindow,
      });
      return (
        !exactKeys(job, ['id', 'githubJobId', 'name', 'conclusion']) ||
        !RUN_ID.test(job.githubJobId ?? '') ||
        SOURCE_JOB_MAP.get(job.name) !== job.id ||
        (expected === 'NON_SUCCESS'
          ? !nonSuccessConclusion(job.conclusion)
          : job.conclusion !== expected)
      );
    }) ||
    !SHA256.test(value.source.jobsResponseRawSha256 ?? '') ||
    !SHA256.test(value.source.jobsResponseCanonicalSha256 ?? '') ||
    !exactKeys(value.recovery, [
      'workflowName',
      'workflowPath',
      'runId',
      'runAttempt',
      'conclusion',
      'headSha',
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
      'fenceEvidenceOrigin',
      'publicationEvidenceOrigin',
      'canonicalSupplementPolicy',
      'jobs',
      'jobsResponseRawSha256',
      'jobsResponseCanonicalSha256',
    ]) ||
    value.recovery.workflowName !== RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME ||
    value.recovery.workflowPath !== RECOVERY_WORKFLOW ||
    !RUN_ID.test(value.recovery.runId ?? '') ||
    value.recovery.runAttempt !== 1 ||
    value.recovery.conclusion !== 'success' ||
    !SHA.test(value.recovery.headSha ?? '') ||
    !RUN_ID.test(value.recovery.planArtifactId ?? '') ||
    typeof value.recovery.planArtifactName !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.recovery.planArtifactDigest ?? '') ||
    !SHA256.test(value.recovery.planArchiveRawSha256 ?? '') ||
    !RUN_ID.test(value.recovery.resultArtifactId ?? '') ||
    typeof value.recovery.resultArtifactName !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.recovery.resultArtifactDigest ?? '') ||
    !SHA256.test(value.recovery.resultArchiveRawSha256 ?? '') ||
    value.recovery.executionMode !== routeExpectation?.executionMode ||
    value.recovery.githubPublicationPolicy !== routeExpectation?.githubPublicationPolicy ||
    !Number.isSafeInteger(value.recovery.recoveryGithubWritesPerformed) ||
    value.recovery.recoveryGithubWritesPerformed < 0 ||
    (value.recovery.githubPublicationPolicy === 'VERIFY_EXACT_NO_MUTATION' &&
      value.recovery.recoveryGithubWritesPerformed !== 0) ||
    (value.recovery.githubPublicationPolicy === 'VERIFY_EXACT_OR_CREATE_MISSING' &&
      value.recovery.recoveryGithubWritesPerformed > 2) ||
    value.recovery.fenceEvidenceOrigin !== routeExpectation?.fenceEvidenceOrigin ||
    value.recovery.publicationEvidenceOrigin !== routeExpectation?.publicationEvidenceOrigin ||
    value.recovery.canonicalSupplementPolicy !== routeExpectation?.canonicalSupplementPolicy ||
    !exactArray(
      value.recovery.jobs?.map(({ id }) => id),
      RELEASE_SUCCESSOR_RECOVERY_JOB_IDS,
    ) ||
    value.recovery.jobs.some(
      (job) =>
        !exactKeys(job, ['id', 'githubJobId', 'name', 'conclusion']) ||
        !RUN_ID.test(job.githubJobId ?? '') ||
        RECOVERY_JOB_MAP.get(job.name) !== job.id ||
        job.conclusion !==
          expectedRecoveryJobConclusion({
            id: job.id,
            crashWindow: value.source.crashWindow,
          }),
    ) ||
    !SHA256.test(value.recovery.jobsResponseRawSha256 ?? '') ||
    !SHA256.test(value.recovery.jobsResponseCanonicalSha256 ?? '') ||
    !exactKeys(value.postSuccess, [
      'workflowName',
      'workflowPath',
      'runId',
      'runAttempt',
      'eventName',
      'headSha',
      'reviewerAlias',
      'approvalResponseRawSha256',
      'approvalResponseCanonicalSha256',
      'triggerRawSha256',
      'triggerCanonicalSha256',
    ]) ||
    value.postSuccess.workflowName !== RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_NAME ||
    value.postSuccess.workflowPath !== RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH ||
    !RUN_ID.test(value.postSuccess.runId ?? '') ||
    !validPostSuccessAttempt(value.postSuccess.runAttempt) ||
    value.postSuccess.eventName !== 'workflow_run' ||
    value.postSuccess.headSha !== value.recovery.headSha ||
    !SAFE_ALIAS.test(value.postSuccess.reviewerAlias ?? '') ||
    [
      value.postSuccess.approvalResponseRawSha256,
      value.postSuccess.approvalResponseCanonicalSha256,
      value.postSuccess.triggerRawSha256,
      value.postSuccess.triggerCanonicalSha256,
    ].some((digest) => !SHA256.test(digest ?? '')) ||
    !exactKeys(value.bindings, [
      'intakeSha256',
      'planSha256',
      'receiptSha256',
      'fenceSha256',
      'publicationAuthoritySha256',
      'idempotencyKey',
      'planArtifactDigestSha256',
      'resultArtifactDigestSha256',
      'sourceArtifactManifestSha256',
      'publicationFilesSha256',
      'sourceInventoryMetadataSha256',
      'sourceInventorySha256',
      'sourceJobsSha256',
    ]) ||
    Object.values(value.bindings).some((digest) => !SHA256.test(digest ?? '')) ||
    value.bindings.planArtifactDigestSha256 !==
      value.recovery.planArtifactDigest.slice('sha256:'.length) ||
    value.bindings.resultArtifactDigestSha256 !==
      value.recovery.resultArtifactDigest.slice('sha256:'.length) ||
    value.bindings.sourceJobsSha256 !== objectSha256(value.source.jobs) ||
    !exactArray(value.allowedActions, RELEASE_SUCCESSOR_RECOVERY_CLOSEOUT_ALLOWED_ACTIONS) ||
    !exactArray(value.forbiddenActions, RELEASE_SUCCESSOR_RECOVERY_CLOSEOUT_FORBIDDEN_ACTIONS) ||
    value.sourceRunConclusionUnchanged !== true ||
    value.recoveryRunConclusionVerified !== true ||
    value.publicationReexecutionAllowed !== false ||
    value.cleanupAllowedAfterDurableSourceOnly !== true ||
    !utc(value.authorizedAtUtc) ||
    value.externalRequests !== 1 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.closeoutAuthoritySha256 !== objectSha256(withoutDigest(value, 'closeoutAuthoritySha256'))
  ) {
    fail('E7_RECOVERY_CLOSEOUT_AUTHORITY_INVALID');
  }
  if (expectedIntake !== undefined) {
    const intake = validatePublicationRecoveryPostSuccessIntake(expectedIntake);
    if (
      value.source.runId !== intake.source.runId ||
      value.source.runAttempt !== intake.source.runAttempt ||
      value.source.conclusion !== intake.source.conclusion ||
      value.source.candidateSha !== intake.source.candidateSha ||
      value.source.releaseId !== intake.source.releaseId ||
      value.source.releaseTag !== intake.source.releaseTag ||
      value.source.crashWindow !== intake.source.crashWindow ||
      value.recovery.runId !== intake.recovery.runId ||
      value.recovery.runAttempt !== intake.recovery.runAttempt ||
      value.recovery.conclusion !== intake.recovery.conclusion ||
      value.recovery.planArtifactId !== intake.recovery.planArtifactId ||
      value.recovery.planArtifactName !== intake.recovery.planArtifactName ||
      value.recovery.planArtifactDigest !== intake.recovery.planArtifactDigest ||
      value.recovery.planArchiveRawSha256 !== intake.recovery.planArchiveRawSha256 ||
      value.recovery.resultArtifactId !== intake.recovery.resultArtifactId ||
      value.recovery.resultArtifactName !== intake.recovery.resultArtifactName ||
      value.recovery.resultArtifactDigest !== intake.recovery.resultArtifactDigest ||
      value.recovery.resultArchiveRawSha256 !== intake.recovery.resultArchiveRawSha256 ||
      value.recovery.executionMode !== intake.recovery.executionMode ||
      value.recovery.githubPublicationPolicy !== intake.recovery.githubPublicationPolicy ||
      value.recovery.recoveryGithubWritesPerformed !==
        intake.recovery.recoveryGithubWritesPerformed ||
      value.bindings.intakeSha256 !== intake.intakeSha256 ||
      value.bindings.planSha256 !== intake.bindings.planSha256 ||
      value.bindings.receiptSha256 !== intake.bindings.receiptSha256 ||
      value.bindings.fenceSha256 !== intake.bindings.fenceSha256 ||
      value.bindings.publicationAuthoritySha256 !== intake.bindings.authoritySha256 ||
      value.bindings.idempotencyKey !== intake.bindings.idempotencyKey ||
      value.bindings.sourceInventoryMetadataSha256 !==
        intake.bindings.sourceInventoryMetadataSha256 ||
      value.bindings.sourceInventorySha256 !== intake.bindings.sourceInventorySha256
    ) {
      fail('E7_RECOVERY_CLOSEOUT_AUTHORITY_INTAKE_MISMATCH');
    }
  }
  return value;
};

export const createReleaseSuccessorRecoveryCloseoutAuthority = ({
  intake: input,
  recoveryHeadSha,
  sourceJobsSource,
  recoveryJobsSource,
  triggerSource,
  approvalResponseSource,
  planArchive,
  resultArchive,
  context,
  authorizedAtUtc,
}) => {
  const intake = validatePublicationRecoveryPostSuccessIntake(input);
  if (!SHA.test(recoveryHeadSha ?? '') || !utc(authorizedAtUtc)) {
    fail('E7_RECOVERY_CLOSEOUT_OPTIONS_INVALID');
  }
  validateContext({ context, intake, recoveryHeadSha });
  const result = readReleaseSuccessorRecoveryResultFromIntake({
    intake,
    planArchive,
    resultArchive,
  });
  if (Date.parse(authorizedAtUtc) < Date.parse(result.receipt.completedAtUtc)) {
    fail('E7_RECOVERY_CLOSEOUT_RESULT_MISMATCH');
  }
  const sourceJobs = validateSourceJobsAgainstResult({
    sourceJobs: validateSourceJobs({
      source: sourceJobsSource,
      sourceRunId: intake.source.runId,
      crashWindow: intake.source.crashWindow,
    }),
    result,
  });
  const recoveryJobs = validateRecoveryJobs({
    source: recoveryJobsSource,
    recoveryRunId: intake.recovery.runId,
    crashWindow: intake.source.crashWindow,
  });
  const trigger = validateTrigger({ source: triggerSource, intake, recoveryHeadSha });
  const approval = validateApprovalResponse({ source: approvalResponseSource, intake });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_CLOSEOUT_AUTHORITY',
    status: 'AUTHORIZED_COMPOSITE_CLOSEOUT',
    sharedContract: RELEASE_SUCCESSOR_RECOVERY_SHARED_CONTRACT,
    repository: RECOVERY_REPOSITORY,
    protectedEnvironment: RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT,
    source: {
      workflowName: RECOVERY_SOURCE_WORKFLOW_NAME,
      workflowPath: RECOVERY_SOURCE_WORKFLOW,
      runId: intake.source.runId,
      runAttempt: intake.source.runAttempt,
      conclusion: intake.source.conclusion,
      candidateSha: intake.source.candidateSha,
      releaseId: intake.source.releaseId,
      releaseTag: intake.source.releaseTag,
      crashWindow: intake.source.crashWindow,
      jobs: sourceJobs.jobs,
      jobsResponseRawSha256: sourceJobs.document.rawSha256,
      jobsResponseCanonicalSha256: sourceJobs.document.canonicalSha256,
    },
    recovery: {
      workflowName: RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME,
      workflowPath: RECOVERY_WORKFLOW,
      runId: intake.recovery.runId,
      runAttempt: intake.recovery.runAttempt,
      conclusion: intake.recovery.conclusion,
      headSha: recoveryHeadSha,
      planArtifactId: intake.recovery.planArtifactId,
      planArtifactName: intake.recovery.planArtifactName,
      planArtifactDigest: intake.recovery.planArtifactDigest,
      planArchiveRawSha256: intake.recovery.planArchiveRawSha256,
      resultArtifactId: intake.recovery.resultArtifactId,
      resultArtifactName: intake.recovery.resultArtifactName,
      resultArtifactDigest: intake.recovery.resultArtifactDigest,
      resultArchiveRawSha256: intake.recovery.resultArchiveRawSha256,
      executionMode: intake.recovery.executionMode,
      githubPublicationPolicy: intake.recovery.githubPublicationPolicy,
      recoveryGithubWritesPerformed: intake.recovery.recoveryGithubWritesPerformed,
      fenceEvidenceOrigin: result.plan.route.fenceEvidenceOrigin,
      publicationEvidenceOrigin: result.plan.route.publicationEvidenceOrigin,
      canonicalSupplementPolicy: result.plan.route.canonicalSupplementPolicy,
      jobs: recoveryJobs.jobs,
      jobsResponseRawSha256: recoveryJobs.document.rawSha256,
      jobsResponseCanonicalSha256: recoveryJobs.document.canonicalSha256,
    },
    postSuccess: {
      workflowName: context.workflowName,
      workflowPath: context.workflowPath,
      runId: context.runId,
      runAttempt: context.runAttempt,
      eventName: context.eventName,
      headSha: context.headSha,
      reviewerAlias: approval.reviewerAlias,
      approvalResponseRawSha256: approval.document.rawSha256,
      approvalResponseCanonicalSha256: approval.document.canonicalSha256,
      triggerRawSha256: trigger.rawSha256,
      triggerCanonicalSha256: trigger.canonicalSha256,
    },
    bindings: {
      intakeSha256: intake.intakeSha256,
      planSha256: result.plan.planSha256,
      receiptSha256: result.receipt.receiptSha256,
      fenceSha256: result.fence.fenceSha256,
      publicationAuthoritySha256: result.receipt.authoritySha256,
      idempotencyKey: result.receipt.idempotencyKey,
      planArtifactDigestSha256: intake.recovery.planArtifactDigest.slice('sha256:'.length),
      resultArtifactDigestSha256: intake.recovery.resultArtifactDigest.slice('sha256:'.length),
      sourceArtifactManifestSha256: objectSha256(result.plan.artifactInventory.downloadManifest),
      publicationFilesSha256: objectSha256(result.receipt.publicationFiles),
      sourceInventoryMetadataSha256: intake.bindings.sourceInventoryMetadataSha256,
      sourceInventorySha256: intake.bindings.sourceInventorySha256,
      sourceJobsSha256: objectSha256(sourceJobs.jobs),
    },
    allowedActions: [...RELEASE_SUCCESSOR_RECOVERY_CLOSEOUT_ALLOWED_ACTIONS],
    forbiddenActions: [...RELEASE_SUCCESSOR_RECOVERY_CLOSEOUT_FORBIDDEN_ACTIONS],
    sourceRunConclusionUnchanged: true,
    recoveryRunConclusionVerified: true,
    publicationReexecutionAllowed: false,
    cleanupAllowedAfterDurableSourceOnly: true,
    authorizedAtUtc,
    externalRequests: 1,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return validateReleaseSuccessorRecoveryCloseoutAuthority(
    { ...body, closeoutAuthoritySha256: objectSha256(body) },
    { intake },
  );
};

export const captureReleaseSuccessorRecoveryCloseoutAuthority = async ({
  token,
  fetchImpl = globalThis.fetch,
  ...options
}) => {
  if (
    typeof token !== 'string' ||
    token.length < 20 ||
    token.length > 4096 ||
    /\s/u.test(token) ||
    typeof fetchImpl !== 'function'
  ) {
    fail('E7_RECOVERY_CLOSEOUT_CAPTURE_CONTEXT_INVALID');
  }
  const intake = validatePublicationRecoveryPostSuccessIntake(options.intake);
  if (!SHA.test(options.recoveryHeadSha ?? '') || !utc(options.authorizedAtUtc)) {
    fail('E7_RECOVERY_CLOSEOUT_OPTIONS_INVALID');
  }
  validateContext({
    context: options.context,
    intake,
    recoveryHeadSha: options.recoveryHeadSha,
  });
  const result = readReleaseSuccessorRecoveryResultFromIntake({
    intake,
    planArchive: options.planArchive,
    resultArchive: options.resultArchive,
  });
  if (Date.parse(options.authorizedAtUtc) < Date.parse(result.receipt.completedAtUtc)) {
    fail('E7_RECOVERY_CLOSEOUT_RESULT_MISMATCH');
  }
  validateSourceJobsAgainstResult({
    sourceJobs: validateSourceJobs({
      source: options.sourceJobsSource,
      sourceRunId: intake.source.runId,
      crashWindow: intake.source.crashWindow,
    }),
    result,
  });
  validateRecoveryJobs({
    source: options.recoveryJobsSource,
    recoveryRunId: intake.recovery.runId,
    crashWindow: intake.source.crashWindow,
  });
  validateTrigger({
    source: options.triggerSource,
    intake,
    recoveryHeadSha: options.recoveryHeadSha,
  });
  const runId = options.context?.runId;
  if (!RUN_ID.test(runId ?? '')) fail('E7_RECOVERY_CLOSEOUT_CAPTURE_CONTEXT_INVALID');
  let response;
  try {
    response = await fetchImpl(
      `${API_ROOT}/repos/${RECOVERY_REPOSITORY}/actions/runs/${runId}/approvals`,
      {
        method: 'GET',
        headers: {
          accept: 'application/vnd.github+json',
          authorization: `Bearer ${token}`,
          'user-agent': 'async-checkout-demo-stage7-recovery-closeout',
          'x-github-api-version': API_VERSION,
        },
        redirect: 'error',
        signal: AbortSignal.timeout(15_000),
      },
    );
  } catch (error) {
    fail('E7_RECOVERY_CLOSEOUT_APPROVAL_REQUEST_FAILED', error);
  }
  if (response?.status !== 200 || response.redirected === true) {
    fail('E7_RECOVERY_CLOSEOUT_APPROVAL_REQUEST_REJECTED');
  }
  const contentType = response.headers?.get?.('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('application/json')) {
    fail('E7_RECOVERY_CLOSEOUT_APPROVAL_RESPONSE_INVALID');
  }
  const responseText = await response.text();
  return createReleaseSuccessorRecoveryCloseoutAuthority({
    ...options,
    approvalResponseSource: Buffer.from(responseText, 'utf8'),
  });
};

export const selfTestReleaseSuccessorRecoveryIntegration = async () => {
  const [
    { createPublicationRecoveryPostSuccessFixture },
    { createReleaseSuccessorStoredZipFixture },
  ] = await Promise.all([
    import('./release-successor-publication-recovery-self-test.mjs'),
    import('./release-successor-zip.mjs'),
  ]);
  const fixtures = RECOVERY_CRASH_WINDOWS.map((crashWindow) =>
    createPublicationRecoveryPostSuccessFixture({ crashWindow }),
  );
  const intakes = fixtures.map(({ intakeArguments }) =>
    createPublicationRecoveryPostSuccessIntake(intakeArguments),
  );
  const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  const clone = (value) => JSON.parse(JSON.stringify(value));
  const withDigest = (value, key) => {
    const body = clone(value);
    delete body[key];
    return { ...body, [key]: objectSha256(body) };
  };
  const optionsFor = ({ fixture, intake, fetchImpl }) => {
    const recoveryHeadSha = 'b'.repeat(40);
    const sourceBoundaryGithubIds = new Map([
      ['release-successor-fence', Number(fixture.plan.source.fenceJob.id)],
      ['publish-release', Number(fixture.plan.source.publicationJob.id)],
      ['summary', Number(fixture.plan.source.summaryJob.id)],
    ]);
    const sourceJobsSource = jsonBytes({
      total_count: SOURCE_JOB_MAP.size,
      jobs: [...SOURCE_JOB_MAP.entries()].map(([name, id], index) => {
        const expected = expectedSourceJobConclusion({
          id,
          crashWindow: intake.source.crashWindow,
        });
        return {
          id: sourceBoundaryGithubIds.get(id) ?? 9200 + index,
          run_id: Number(intake.source.runId),
          run_attempt: 1,
          name,
          status: 'completed',
          conclusion: expected === 'NON_SUCCESS' ? 'failure' : expected,
        };
      }),
    });
    const recoveryJobsSource = jsonBytes({
      total_count: 3,
      jobs: [
        {
          id: 9101,
          run_id: Number(intake.recovery.runId),
          run_attempt: 1,
          name: 'Validate isolated publication recovery contract',
          status: 'completed',
          conclusion: 'success',
        },
        {
          id: 9102,
          run_id: Number(intake.recovery.runId),
          run_attempt: 1,
          name: 'Preflight exact crash window under read-only GitHub authority',
          status: 'completed',
          conclusion: 'success',
        },
        {
          id: 9103,
          run_id: Number(intake.recovery.runId),
          run_attempt: 1,
          name: 'Forward-only A or B publication under write authority',
          status: 'completed',
          conclusion:
            intake.source.crashWindow === RECOVERY_CRASH_WINDOWS[2] ? 'skipped' : 'success',
        },
      ],
    });
    const triggerSource = jsonBytes({
      action: 'completed',
      repository: { full_name: RECOVERY_REPOSITORY },
      workflow_run: {
        id: Number(intake.recovery.runId),
        run_attempt: 1,
        name: RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME,
        event: 'workflow_dispatch',
        head_branch: 'master',
        head_sha: recoveryHeadSha,
        status: 'completed',
        conclusion: 'success',
      },
    });
    return {
      token: 'test-token-12345678901234567890',
      fetchImpl,
      intake,
      recoveryHeadSha,
      sourceJobsSource,
      recoveryJobsSource,
      triggerSource,
      planArchive: fixture.planArchive,
      resultArchive: fixture.resultArchive,
      context: {
        repository: RECOVERY_REPOSITORY,
        runId: '7004',
        runAttempt: 2,
        workflowName: RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_NAME,
        workflowPath: RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH,
        eventName: 'workflow_run',
        headSha: recoveryHeadSha,
        protectedEnvironment: RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT,
        githubActions: 'true',
      },
      authorizedAtUtc: '2026-08-18T14:01:00.000Z',
    };
  };
  const approvalFor = (intake) => [
    {
      state: 'approved',
      comment: expectedApprovalComment({
        sourceRunId: intake.source.runId,
        recoveryRunId: intake.recovery.runId,
        receiptSha256: intake.bindings.receiptSha256,
      }),
      environments: [
        {
          id: 1,
          name: RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT,
          url:
            `${API_ROOT}/repos/${RECOVERY_REPOSITORY}/environments/` +
            RELEASE_SUCCESSOR_POST_SUCCESS_ENVIRONMENT,
        },
      ],
      user: { id: 2, login: 'release-operator', type: 'User' },
    },
  ];

  let callbacks = 0;
  const successfulAuthorities = [];
  for (const [index, fixture] of fixtures.entries()) {
    const intake = intakes[index];
    const fetchImpl = async () => {
      callbacks += 1;
      return {
        status: 200,
        redirected: false,
        headers: { get: () => 'application/json; charset=utf-8' },
        text: async () => JSON.stringify(approvalFor(intake)),
      };
    };
    const authority = await captureReleaseSuccessorRecoveryCloseoutAuthority(
      optionsFor({ fixture, intake, fetchImpl }),
    );
    const expectation = RECOVERY_ROUTE_EXPECTATIONS.get(fixture.crashWindow);
    assert.equal(authority.source.crashWindow, fixture.crashWindow);
    assert.equal(authority.recovery.executionMode, expectation.executionMode);
    assert.equal(authority.recovery.githubPublicationPolicy, expectation.githubPublicationPolicy);
    assert.equal(authority.recovery.fenceEvidenceOrigin, expectation.fenceEvidenceOrigin);
    assert.equal(
      authority.recovery.publicationEvidenceOrigin,
      expectation.publicationEvidenceOrigin,
    );
    assert.equal(authority.recovery.recoveryGithubWritesPerformed, index === 2 ? 0 : 1);
    successfulAuthorities.push(authority);
  }
  assert.equal(callbacks, RECOVERY_CRASH_WINDOWS.length);

  const rejectBeforeFetch = async (options) => {
    const before = callbacks;
    await assert.rejects(captureReleaseSuccessorRecoveryCloseoutAuthority(options));
    assert.equal(callbacks, before);
  };
  const forbiddenFetch = async () => {
    callbacks += 1;
    throw new Error('network callback must not run');
  };

  for (const [fixtureIndex, wrongConclusion] of [
    [0, 'skipped'],
    [2, 'success'],
  ]) {
    const options = optionsFor({
      fixture: fixtures[fixtureIndex],
      intake: intakes[fixtureIndex],
      fetchImpl: forbiddenFetch,
    });
    const jobs = JSON.parse(options.recoveryJobsSource.toString('utf8'));
    jobs.jobs.find(
      ({ name }) => name === 'Forward-only A or B publication under write authority',
    ).conclusion = wrongConclusion;
    await rejectBeforeFetch({ ...options, recoveryJobsSource: jsonBytes(jobs) });
  }

  const tamperedSourceOptions = optionsFor({
    fixture: fixtures[0],
    intake: intakes[0],
    fetchImpl: forbiddenFetch,
  });
  const tamperedSourceJobs = JSON.parse(tamperedSourceOptions.sourceJobsSource.toString('utf8'));
  tamperedSourceJobs.jobs[0].conclusion = 'failure';
  await rejectBeforeFetch({
    ...tamperedSourceOptions,
    sourceJobsSource: jsonBytes(tamperedSourceJobs),
  });
  const swappedBoundaryJobs = JSON.parse(tamperedSourceOptions.sourceJobsSource.toString('utf8'));
  const fenceJob = swappedBoundaryJobs.jobs.find(
    ({ name }) => name === '23 Seal immutable pre-publication fence',
  );
  const publicationJob = swappedBoundaryJobs.jobs.find(({ name }) => name === '24 Publish release');
  [fenceJob.id, publicationJob.id] = [publicationJob.id, fenceJob.id];
  await rejectBeforeFetch({
    ...tamperedSourceOptions,
    sourceJobsSource: jsonBytes(swappedBoundaryJobs),
  });

  for (const [index, fixture] of fixtures.entries()) {
    const foreign = fixtures[(index + 1) % fixtures.length];
    await rejectBeforeFetch({
      ...optionsFor({ fixture, intake: intakes[index], fetchImpl: forbiddenFetch }),
      planArchive: foreign.planArchive,
      resultArchive: foreign.resultArchive,
    });
  }

  await rejectBeforeFetch({
    ...optionsFor({ fixture: fixtures[0], intake: intakes[0], fetchImpl: forbiddenFetch }),
    planArchive: fixtures[0].resultArchive,
    resultArchive: fixtures[0].planArchive,
  });

  const mismatchedPlanArchive = createReleaseSuccessorStoredZipFixture({
    'release-successor-completion-fence.json': Buffer.concat([
      fixtures[0].fenceSource,
      Buffer.from('\n'),
    ]),
    'release-successor-publication-recovery-plan.json': fixtures[0].planSource,
  });
  const mismatchedIntakeBody = clone(intakes[0]);
  delete mismatchedIntakeBody.intakeSha256;
  mismatchedIntakeBody.recovery.planArtifactDigest = `sha256:${sha256(mismatchedPlanArchive)}`;
  mismatchedIntakeBody.recovery.planArchiveRawSha256 = sha256(mismatchedPlanArchive);
  const mismatchedIntake = {
    ...mismatchedIntakeBody,
    intakeSha256: objectSha256(mismatchedIntakeBody),
  };
  await rejectBeforeFetch({
    ...optionsFor({ fixture: fixtures[0], intake: mismatchedIntake, fetchImpl: forbiddenFetch }),
    planArchive: mismatchedPlanArchive,
  });

  for (const [fixtureIndex, artifactName] of [
    [1, 'stage7-release-successor-fence'],
    [2, 'stage7-publication'],
  ]) {
    const sourceArtifacts = clone(fixtures[fixtureIndex].intakeArguments.sourceArtifacts);
    const artifact = sourceArtifacts.artifacts.find(({ name }) => name === artifactName);
    artifact.digest = `sha256:${'f'.repeat(64)}`;
    assert.throws(() =>
      createPublicationRecoveryPostSuccessIntake({
        ...fixtures[fixtureIndex].intakeArguments,
        sourceArtifacts,
      }),
    );
  }

  const tamperedIntake = withDigest(
    {
      ...intakes[2],
      source: { ...intakes[2].source, crashWindow: RECOVERY_CRASH_WINDOWS[0] },
    },
    'intakeSha256',
  );
  await rejectBeforeFetch(
    optionsFor({ fixture: fixtures[2], intake: tamperedIntake, fetchImpl: forbiddenFetch }),
  );

  const tamperedAuthority = withDigest(
    {
      ...successfulAuthorities[2],
      recovery: {
        ...successfulAuthorities[2].recovery,
        githubPublicationPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
      },
    },
    'closeoutAuthoritySha256',
  );
  assert.throws(() => validateReleaseSuccessorRecoveryCloseoutAuthority(tamperedAuthority));

  return {
    status: 'PASS',
    canaries: 16,
    routes: RECOVERY_CRASH_WINDOWS.length,
    simulatedApprovalReads: callbacks,
    externalRequests: 0,
  };
};
