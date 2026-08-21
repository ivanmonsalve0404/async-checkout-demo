#!/usr/bin/env node

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  closeSync,
  lstatSync,
  mkdtempSync,
  openSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { parseStrictJsonSource, validateJsonSchemaSubset } from '../stage6/strict-json.mjs';
import { normalizePnpmScriptArguments } from './cli-arguments.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const GITHUB_API_ROOT = 'https://api.github.com';
const GITHUB_API_VERSION = '2026-03-10';
const PROVIDER_HOST = 'sandbox.wompi.co';
const MAX_CLAIM_BYTES = 64 * 1024;
const MAX_REQUEST_BYTES = 32 * 1024;
const MAX_AUTHORIZATION_BYTES = 128 * 1024;
const MAX_APPROVAL_RESPONSE_BYTES = 1024 * 1024;
const MAX_CLAIM_WINDOW_MS = 30 * 60 * 1000;
const MAX_REQUEST_WINDOW_MS = 6 * 60 * 60 * 1000;
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const POSITIVE_INTEGER = /^[1-9][0-9]{0,19}$/u;
const SAFE_ALIAS = /^[a-z][a-z0-9-]{2,31}$/u;
const REVIEWER_ALIAS = /^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const UTC = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const SCOPES = Object.freeze({
  full: Object.freeze({
    workflowFile: '.github/workflows/release.yml',
    producerJob: 'quality',
    job: 'sandbox-smoke',
    environment: 'assessment-release-sandbox',
    stage7AuthorizationId: 'AUTH-E7-EXT-02',
  }),
  prerelease: Object.freeze({
    workflowFile: '.github/workflows/prerelease.yml',
    producerJob: 'deploy-prerelease',
    job: 'external-verification',
    environment: 'assessment-prerelease-external',
    stage7AuthorizationId: 'AUTH-E6-02',
  }),
});
const PROVIDER_CREDENTIAL_KEYS = [
  'STAGE6_SANDBOX_CARD_CVC',
  'STAGE6_SANDBOX_CARD_EXPIRY',
  'STAGE6_SANDBOX_CARD_HOLDER',
  'STAGE6_SANDBOX_CARD_NUMBER',
  'STAGE6_SANDBOX_CUSTOMER_EMAIL',
  'STAGE6_SANDBOX_INTEGRITY_SECRET',
  'STAGE6_SANDBOX_PRIVATE_KEY',
  'STAGE6_SANDBOX_PUBLIC_KEY',
];
const CLOUD_CREDENTIAL_KEYS = [
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'AWS_SECURITY_TOKEN',
];
const READY_KEYS = [
  'schemaVersion',
  'stage',
  'kind',
  'status',
  'claimSha256',
  'bindingSha256',
  'scope',
  'runId',
  'runAttempt',
  'workflowJob',
  'environment',
  'candidateSha',
  'releaseId',
  'configSha256',
  'referenceSha256',
  'preparedAtUtc',
  'containsSensitiveData',
];
const CONSUMED_KEYS = [...READY_KEYS.filter((key) => key !== 'preparedAtUtc'), 'consumedAtUtc'];
const EVIDENCE_KEYS = [
  'schemaVersion',
  'kind',
  'claimSha256',
  'bindingSha256',
  'runId',
  'runAttempt',
  'workflowSha',
  'workflowJob',
  'environment',
  'candidateSha',
  'releaseId',
  'configSha256',
  'stage6AuthorizationSha256',
  'stage7AuthorizationSha256',
  'approvalRequestSha256',
  'approvalResponseSha256',
  'approvedByAlias',
  'referenceSha256',
  'maximumExternalRequests',
  'maximumTokenizations',
  'maximumTransactions',
  'localAtomicConsumption',
  'providerDuplicateReferenceDefense',
  'containsSensitiveData',
];

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA_PATH = path.join(HERE, 'sandbox-execution-claim.schema.json');
const REQUEST_SCHEMA_PATH = path.join(HERE, 'sandbox-execution-request.schema.json');
const SCHEMA = parseStrictJsonSource(readFileSync(SCHEMA_PATH), { scanForbiddenData: false });
const REQUEST_SCHEMA = parseStrictJsonSource(readFileSync(REQUEST_SCHEMA_PATH), {
  scanForbiddenData: false,
});

export class SandboxExecutionClaimError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SandboxExecutionClaimError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new SandboxExecutionClaimError(code);
};
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
const required = (environment, name, code = 'E7_SANDBOX_CLAIM_CONTEXT_INVALID') => {
  const value = environment[name];
  return typeof value === 'string' && value.length > 0 ? value : fail(code);
};
const validUtc = (value) => {
  if (typeof value !== 'string' || !UTC.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
};
const scopeContract = (scope) => SCOPES[scope] ?? fail('E7_SANDBOX_CLAIM_SCOPE_INVALID');

const decodeCanonicalBase64 = (source, maximumBytes, code) => {
  if (
    typeof source !== 'string' ||
    source.length < 4 ||
    source.length > Math.ceil((maximumBytes * 4) / 3) + 4 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(source)
  ) {
    fail(code);
  }
  const decoded = Buffer.from(source, 'base64');
  if (
    decoded.length < 2 ||
    decoded.length > maximumBytes ||
    decoded.toString('base64') !== source
  ) {
    fail(code);
  }
  return decoded;
};

const localRegularFile = (sourcePath, maximumBytes, code) => {
  if (
    typeof sourcePath !== 'string' ||
    sourcePath.length === 0 ||
    sourcePath.trim() !== sourcePath ||
    !path.isAbsolute(sourcePath)
  ) {
    fail(code);
  }
  let stats;
  try {
    stats = lstatSync(sourcePath);
  } catch {
    fail(code);
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.size < 2 || stats.size > maximumBytes) {
    fail(code);
  }
  const resolved = realpathSync(sourcePath);
  if (resolved !== path.resolve(sourcePath)) fail(code);
  if (process.platform !== 'win32' && (stats.mode & 0o777) !== 0o600) fail(code);
  return { path: resolved, source: readFileSync(resolved) };
};

const authorizationSources = (environment) => {
  const stage6Source =
    environment.STAGE6_SANDBOX_AUTHORIZATION_B64 !== undefined
      ? decodeCanonicalBase64(
          environment.STAGE6_SANDBOX_AUTHORIZATION_B64,
          MAX_AUTHORIZATION_BYTES,
          'E7_SANDBOX_CLAIM_STAGE6_SOURCE_INVALID',
        )
      : localRegularFile(
          required(
            environment,
            'STAGE6_SANDBOX_AUTHORIZATION',
            'E7_SANDBOX_CLAIM_STAGE6_SOURCE_INVALID',
          ),
          MAX_AUTHORIZATION_BYTES,
          'E7_SANDBOX_CLAIM_STAGE6_SOURCE_INVALID',
        ).source;
  const stage7Source = localRegularFile(
    required(
      environment,
      'STAGE7_EXTERNAL_AUTHORIZATIONS',
      'E7_SANDBOX_CLAIM_STAGE7_SOURCE_INVALID',
    ),
    MAX_AUTHORIZATION_BYTES,
    'E7_SANDBOX_CLAIM_STAGE7_SOURCE_INVALID',
  ).source;
  let stage6;
  let stage7;
  try {
    stage6 = parseStrictJsonSource(stage6Source, { scanForbiddenData: false });
    stage7 = parseStrictJsonSource(stage7Source, { scanForbiddenData: false });
  } catch {
    fail('E7_SANDBOX_CLAIM_AUTHORIZATION_SOURCE_INVALID');
  }
  return { stage6Source, stage7Source, stage6, stage7 };
};

const contextFromEnvironment = (environment, scope) => {
  const contract = scopeContract(scope);
  const runId = required(environment, 'GITHUB_RUN_ID');
  const runAttemptSource = required(environment, 'GITHUB_RUN_ATTEMPT');
  const runAttempt = Number(runAttemptSource);
  const candidateSha = required(environment, 'STAGE7_CANDIDATE_SHA');
  const releaseId = required(environment, 'STAGE7_RELEASE_ID');
  const configSha256 = required(environment, 'EXPECTED_STAGE7_CONFIG_SHA256');
  const releaseTag =
    scope === 'full' ? required(environment, 'STAGE7_RELEASE_TAG') : 'NOT_APPLICABLE';
  if (
    environment.GITHUB_ACTIONS !== 'true' ||
    environment.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    environment.GITHUB_REF !== 'refs/heads/master' ||
    environment.GITHUB_REPOSITORY !== REPOSITORY ||
    environment.GITHUB_JOB !== contract.job ||
    environment.STAGE7_PROTECTED_ENVIRONMENT !== contract.environment ||
    environment.GITHUB_SHA !== candidateSha ||
    environment.GITHUB_WORKFLOW_SHA !== candidateSha ||
    environment.GITHUB_WORKFLOW_REF !==
      `${REPOSITORY}/${contract.workflowFile}@refs/heads/master` ||
    !POSITIVE_INTEGER.test(runId) ||
    !POSITIVE_INTEGER.test(runAttemptSource) ||
    !Number.isSafeInteger(runAttempt) ||
    runAttempt < 1 ||
    runAttempt > 1000 ||
    !SHA.test(candidateSha) ||
    !RELEASE_ID.test(releaseId) ||
    !SHA256.test(configSha256) ||
    (scope === 'full' && !RELEASE_TAG.test(releaseTag))
  ) {
    fail('E7_SANDBOX_CLAIM_CONTEXT_INVALID');
  }
  return {
    scope,
    repository: REPOSITORY,
    workflowFile: contract.workflowFile,
    workflowRef: `${REPOSITORY}/${contract.workflowFile}@refs/heads/master`,
    workflowSha: candidateSha,
    workflowJob: contract.job,
    environment: contract.environment,
    stage7AuthorizationId: contract.stage7AuthorizationId,
    runId,
    runAttempt,
    candidateSha,
    releaseId,
    releaseTag,
    configSha256,
  };
};

const requestContextFromEnvironment = (environment, scope) => {
  const contract = scopeContract(scope);
  const runId = required(environment, 'GITHUB_RUN_ID');
  const runAttemptSource = required(environment, 'GITHUB_RUN_ATTEMPT');
  const runAttempt = Number(runAttemptSource);
  const candidateSha = required(environment, 'STAGE7_CANDIDATE_SHA');
  const releaseId = required(environment, 'STAGE7_RELEASE_ID');
  const configSha256 = required(environment, 'EXPECTED_STAGE7_CONFIG_SHA256');
  const releaseTag =
    scope === 'full' ? required(environment, 'STAGE7_RELEASE_TAG') : 'NOT_APPLICABLE';
  if (
    environment.GITHUB_ACTIONS !== 'true' ||
    environment.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    environment.GITHUB_REF !== 'refs/heads/master' ||
    environment.GITHUB_REPOSITORY !== REPOSITORY ||
    environment.GITHUB_JOB !== contract.producerJob ||
    environment.GITHUB_SHA !== candidateSha ||
    environment.GITHUB_WORKFLOW_SHA !== candidateSha ||
    environment.GITHUB_WORKFLOW_REF !==
      `${REPOSITORY}/${contract.workflowFile}@refs/heads/master` ||
    !POSITIVE_INTEGER.test(runId) ||
    !POSITIVE_INTEGER.test(runAttemptSource) ||
    !Number.isSafeInteger(runAttempt) ||
    runAttempt < 1 ||
    runAttempt > 1000 ||
    !SHA.test(candidateSha) ||
    !RELEASE_ID.test(releaseId) ||
    !SHA256.test(configSha256) ||
    (scope === 'full' && !RELEASE_TAG.test(releaseTag))
  ) {
    fail('E7_SANDBOX_REQUEST_CONTEXT_INVALID');
  }
  return {
    scope,
    repository: REPOSITORY,
    workflowFile: contract.workflowFile,
    workflowRef: `${REPOSITORY}/${contract.workflowFile}@refs/heads/master`,
    workflowSha: candidateSha,
    producerJob: contract.producerJob,
    workflowJob: contract.job,
    environment: contract.environment,
    runId,
    runAttempt,
    candidateSha,
    releaseId,
    releaseTag,
    configSha256,
  };
};

const requestIdFor = (request) => {
  const withoutRequestId = { ...request };
  delete withoutRequestId.requestId;
  return sha256(JSON.stringify(withoutRequestId));
};

const requestDocument = (context, now) => {
  const requestedAtUtc = now.toISOString();
  const request = {
    schemaId: 'async-checkout-stage7-sandbox-execution-request',
    schemaVersion: 1,
    stage: 7,
    kind: 'SANDBOX_ONE_USE_EXECUTION_REQUEST',
    status: 'AWAITING_PROTECTED_APPROVAL',
    scope: context.scope,
    repository: context.repository,
    workflow: {
      file: context.workflowFile,
      ref: context.workflowRef,
      sha: context.workflowSha,
      producerJob: context.producerJob,
      targetJob: context.workflowJob,
    },
    execution: {
      runId: context.runId,
      runAttempt: context.runAttempt,
      environment: context.environment,
      candidateSha: context.candidateSha,
      releaseId: context.releaseId,
      releaseTag: context.releaseTag,
      configSha256: context.configSha256,
      rerunExplicitlyRequested: context.runAttempt > 1,
      rerunOfAttempt: context.runAttempt > 1 ? context.runAttempt - 1 : 0,
    },
    limits: { externalRequests: 8, tokenizations: 1, transactions: 1 },
    requestedAtUtc,
    expiresAtUtc: new Date(now.getTime() + MAX_REQUEST_WINDOW_MS).toISOString(),
    requestId: '0'.repeat(64),
    containsSensitiveData: false,
  };
  request.requestId = requestIdFor(request);
  return request;
};

export const createSandboxExecutionRequest = ({ environment, scope, now = new Date() }) => {
  assertPreCredentialBoundary(environment);
  const context = requestContextFromEnvironment(environment, scope);
  const request = requestDocument(context, now);
  const source = Buffer.from(`${JSON.stringify(request, null, 2)}\n`);
  return { request, source, requestSha256: sha256(source), context };
};

export const validateSandboxExecutionRequest = ({
  source,
  environment,
  scope,
  now = new Date(),
}) => {
  if (
    !(source instanceof Uint8Array) ||
    source.byteLength < 2 ||
    source.byteLength > MAX_REQUEST_BYTES
  ) {
    fail('E7_SANDBOX_REQUEST_SOURCE_INVALID');
  }
  let request;
  try {
    request = parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch {
    fail('E7_SANDBOX_REQUEST_JSON_INVALID');
  }
  if (!validateJsonSchemaSubset(request, REQUEST_SCHEMA)) fail('E7_SANDBOX_REQUEST_SCHEMA_INVALID');
  const context = contextFromEnvironment(environment, scope);
  const contract = scopeContract(scope);
  if (
    request.scope !== scope ||
    request.repository !== context.repository ||
    request.workflow.file !== context.workflowFile ||
    request.workflow.ref !== context.workflowRef ||
    request.workflow.sha !== context.workflowSha ||
    request.workflow.producerJob !== contract.producerJob ||
    request.workflow.targetJob !== context.workflowJob ||
    request.execution.runId !== context.runId ||
    request.execution.runAttempt !== context.runAttempt ||
    request.execution.environment !== context.environment ||
    request.execution.candidateSha !== context.candidateSha ||
    request.execution.releaseId !== context.releaseId ||
    request.execution.releaseTag !== context.releaseTag ||
    request.execution.configSha256 !== context.configSha256 ||
    request.limits.externalRequests !== 8 ||
    request.limits.tokenizations !== 1 ||
    request.limits.transactions !== 1 ||
    request.containsSensitiveData !== false ||
    request.requestId !== requestIdFor(request)
  ) {
    fail('E7_SANDBOX_REQUEST_BINDING_INVALID');
  }
  if (
    (context.runAttempt === 1 &&
      (request.execution.rerunExplicitlyRequested !== false ||
        request.execution.rerunOfAttempt !== 0)) ||
    (context.runAttempt > 1 &&
      (request.execution.rerunExplicitlyRequested !== true ||
        request.execution.rerunOfAttempt !== context.runAttempt - 1))
  ) {
    fail('E7_SANDBOX_REQUEST_RERUN_INVALID');
  }
  if (!validUtc(request.requestedAtUtc) || !validUtc(request.expiresAtUtc)) {
    fail('E7_SANDBOX_REQUEST_TIME_INVALID');
  }
  const requestedAt = Date.parse(request.requestedAtUtc);
  const expiresAt = Date.parse(request.expiresAtUtc);
  const current = now.getTime();
  if (
    requestedAt > current ||
    expiresAt <= current ||
    requestedAt >= expiresAt ||
    expiresAt - requestedAt !== MAX_REQUEST_WINDOW_MS
  ) {
    fail('E7_SANDBOX_REQUEST_NOT_ACTIVE');
  }
  return {
    request,
    requestSha256: sha256(source),
    context,
  };
};

const expectedEnvironmentUrl = (environment) =>
  `${GITHUB_API_ROOT}/repos/${REPOSITORY}/environments/${encodeURIComponent(environment)}`;

const approvalReviewer = ({ response, environment, requestSha256 }) => {
  if (!Array.isArray(response)) fail('E7_SANDBOX_APPROVAL_RESPONSE_INVALID');
  const expectedComment = `STAGE7_SANDBOX_CLAIM_REQUEST_SHA256=${requestSha256}`;
  const matches = response.filter(
    (review) =>
      object(review) &&
      review.state === 'approved' &&
      review.comment === expectedComment &&
      Array.isArray(review.environments) &&
      review.environments.some((entry) => object(entry) && entry.name === environment),
  );
  if (matches.length !== 1) fail('E7_SANDBOX_APPROVAL_REVIEW_AMBIGUOUS');
  const review = matches[0];
  const environmentRecord = review.environments[0];
  const reviewerAlias = review.user?.login?.toLowerCase();
  if (
    review.environments.length !== 1 ||
    !object(environmentRecord) ||
    environmentRecord.name !== environment ||
    environmentRecord.url !== expectedEnvironmentUrl(environment) ||
    !Number.isSafeInteger(environmentRecord.id) ||
    environmentRecord.id < 1
  ) {
    fail('E7_SANDBOX_APPROVAL_ENVIRONMENT_INVALID');
  }
  if (
    !object(review.user) ||
    review.user.type !== 'User' ||
    !Number.isSafeInteger(review.user.id) ||
    review.user.id < 1 ||
    !REVIEWER_ALIAS.test(reviewerAlias ?? '') ||
    reviewerAlias === 'github-actions'
  ) {
    fail('E7_SANDBOX_APPROVAL_REVIEWER_INVALID');
  }
  return reviewerAlias;
};

export const approveSandboxExecutionRequest = async ({
  requestSource,
  environment,
  scope,
  fetchImpl = globalThis.fetch,
  now = () => new Date(),
}) => {
  assertPreCredentialBoundary(environment);
  const current = now();
  const validatedRequest = validateSandboxExecutionRequest({
    source: requestSource,
    environment,
    scope,
    now: current,
  });
  const token = required(environment, 'GITHUB_TOKEN', 'E7_SANDBOX_APPROVAL_TOKEN_INVALID');
  if (token.length < 20 || token.length > 4096 || /\s/u.test(token)) {
    fail('E7_SANDBOX_APPROVAL_TOKEN_INVALID');
  }
  if (typeof fetchImpl !== 'function') fail('E7_SANDBOX_APPROVAL_FETCH_UNAVAILABLE');
  const url = `${GITHUB_API_ROOT}/repos/${REPOSITORY}/actions/runs/${validatedRequest.context.runId}/approvals`;
  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': 'async-checkout-demo-stage7-sandbox-claim',
        'x-github-api-version': GITHUB_API_VERSION,
      },
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    fail('E7_SANDBOX_APPROVAL_REQUEST_FAILED');
  }
  if (response?.status !== 200 || response.redirected === true) {
    fail('E7_SANDBOX_APPROVAL_REQUEST_REJECTED');
  }
  const contentType = response.headers?.get?.('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('application/json')) {
    fail('E7_SANDBOX_APPROVAL_RESPONSE_INVALID');
  }
  const responseText = await response.text();
  if (
    Buffer.byteLength(responseText) < 2 ||
    Buffer.byteLength(responseText) > MAX_APPROVAL_RESPONSE_BYTES
  ) {
    fail('E7_SANDBOX_APPROVAL_RESPONSE_INVALID');
  }
  let parsedResponse;
  try {
    parsedResponse = JSON.parse(responseText);
  } catch {
    fail('E7_SANDBOX_APPROVAL_RESPONSE_INVALID');
  }
  const approvedByAlias = approvalReviewer({
    response: parsedResponse,
    environment: validatedRequest.context.environment,
    requestSha256: validatedRequest.requestSha256,
  });
  const sources = authorizationSources(environment);
  const stage6Authorization = sources.stage6?.authorization;
  const stage7Authorization = sources.stage7?.authorizations?.sandboxSmoke;
  const expiresAt = Math.min(
    current.getTime() + MAX_CLAIM_WINDOW_MS,
    Date.parse(validatedRequest.request.expiresAtUtc),
    Date.parse(stage6Authorization?.expiresAtUtc ?? ''),
    Date.parse(stage7Authorization?.expiresAtUtc ?? ''),
  );
  if (!Number.isFinite(expiresAt) || expiresAt <= current.getTime()) {
    fail('E7_SANDBOX_CLAIM_NOT_ACTIVE');
  }
  const contract = scopeContract(scope);
  const claim = {
    schemaId: 'async-checkout-stage7-sandbox-execution-claim',
    schemaVersion: 1,
    stage: 7,
    kind: 'SANDBOX_ONE_USE_EXECUTION_CLAIM',
    status: 'APPROVED',
    scope,
    repository: REPOSITORY,
    workflow: {
      file: contract.workflowFile,
      ref: validatedRequest.context.workflowRef,
      sha: validatedRequest.context.workflowSha,
      job: contract.job,
    },
    execution: {
      runId: validatedRequest.context.runId,
      runAttempt: validatedRequest.context.runAttempt,
      environment: contract.environment,
      candidateSha: validatedRequest.context.candidateSha,
      releaseId: validatedRequest.context.releaseId,
      releaseTag: validatedRequest.context.releaseTag,
      configSha256: validatedRequest.context.configSha256,
      rerunExplicitlyApproved: validatedRequest.request.execution.rerunExplicitlyRequested,
      rerunOfAttempt: validatedRequest.request.execution.rerunOfAttempt,
    },
    authorization: {
      stage6Id: 'AUTH-E6-02',
      stage7Id: contract.stage7AuthorizationId,
      stage6SourceSha256: sha256(sources.stage6Source),
      stage7BundleSourceSha256: sha256(sources.stage7Source),
      providerHostSha256: sha256(PROVIDER_HOST),
    },
    limits: { externalRequests: 8, tokenizations: 1, transactions: 1 },
    approvedAtUtc: current.toISOString(),
    expiresAtUtc: new Date(expiresAt).toISOString(),
    ownerAlias: stage7Authorization?.ownerAlias,
    approvalSha256: stage7Authorization?.approvalSha256,
    executionApprovalSha256: '0'.repeat(64),
    approvedByAlias,
    approvalEvidence: {
      requestSha256: validatedRequest.requestSha256,
      responseSha256: sha256(responseText),
      reviewerAlias: approvedByAlias,
      externalRequests: 1,
    },
    claimId: '0'.repeat(64),
    containsSensitiveData: false,
  };
  const authorization = {
    stage6SourceSha256: sha256(sources.stage6Source),
    stage7BundleSourceSha256: sha256(sources.stage7Source),
  };
  claim.executionApprovalSha256 = executionApprovalFor(
    claim,
    validatedRequest.context,
    authorization,
  );
  claim.claimId = claimIdFor(claim);
  const claimSource = Buffer.from(`${JSON.stringify(claim, null, 2)}\n`);
  const validatedClaim = validateSandboxExecutionClaim({
    claimSource,
    environment,
    scope,
    now: current,
  });
  return {
    ...validatedClaim,
    claimSource,
    requestSha256: validatedRequest.requestSha256,
    approvalResponseSha256: claim.approvalEvidence.responseSha256,
    approvedByAlias,
    approvalExternalRequests: 1,
  };
};

const bindingFor = (context, authorization) => ({
  repository: context.repository,
  workflowFile: context.workflowFile,
  workflowRef: context.workflowRef,
  workflowSha: context.workflowSha,
  workflowJob: context.workflowJob,
  runId: context.runId,
  runAttempt: context.runAttempt,
  environment: context.environment,
  candidateSha: context.candidateSha,
  releaseId: context.releaseId,
  releaseTag: context.releaseTag,
  configSha256: context.configSha256,
  stage6SourceSha256: authorization.stage6SourceSha256,
  stage7BundleSourceSha256: authorization.stage7BundleSourceSha256,
});

const deterministicReference = (scope, runId, runAttempt, bindingSha256) =>
  `e6-${scope === 'full' ? 'rel' : 'pre'}-${runId}-${runAttempt}-${bindingSha256.slice(0, 12)}`;

const executionApprovalFor = (claim, context, authorization) =>
  sha256(
    JSON.stringify({
      repository: context.repository,
      workflowSha: context.workflowSha,
      workflowJob: context.workflowJob,
      runId: context.runId,
      runAttempt: context.runAttempt,
      environment: context.environment,
      candidateSha: context.candidateSha,
      releaseId: context.releaseId,
      releaseTag: context.releaseTag,
      configSha256: context.configSha256,
      stage6SourceSha256: authorization.stage6SourceSha256,
      stage7BundleSourceSha256: authorization.stage7BundleSourceSha256,
      limits: claim.limits,
      ownerAlias: claim.ownerAlias,
      trafficApprovalSha256: claim.approvalSha256,
      approvedByAlias: claim.approvedByAlias,
      approvalRequestSha256: claim.approvalEvidence.requestSha256,
      approvalResponseSha256: claim.approvalEvidence.responseSha256,
      approvedAtUtc: claim.approvedAtUtc,
      expiresAtUtc: claim.expiresAtUtc,
      rerunExplicitlyApproved: claim.execution.rerunExplicitlyApproved,
      rerunOfAttempt: claim.execution.rerunOfAttempt,
    }),
  );

const claimIdFor = (claim) => {
  const withoutClaimId = { ...claim };
  delete withoutClaimId.claimId;
  return sha256(JSON.stringify(withoutClaimId));
};

const executionClaimSource = ({ encodedClaim, claimSource, environment }) => {
  if (claimSource !== undefined) {
    if (
      !(claimSource instanceof Uint8Array) ||
      claimSource.byteLength < 2 ||
      claimSource.byteLength > MAX_CLAIM_BYTES
    ) {
      fail('E7_SANDBOX_CLAIM_SOURCE_INVALID');
    }
    return Buffer.from(claimSource);
  }
  if (encodedClaim !== undefined) {
    return decodeCanonicalBase64(encodedClaim, MAX_CLAIM_BYTES, 'E7_SANDBOX_CLAIM_BASE64_INVALID');
  }
  if (environment.STAGE7_SANDBOX_EXECUTION_CLAIM !== undefined) {
    return localRegularFile(
      required(environment, 'STAGE7_SANDBOX_EXECUTION_CLAIM', 'E7_SANDBOX_CLAIM_REQUIRED'),
      MAX_CLAIM_BYTES,
      'E7_SANDBOX_CLAIM_SOURCE_INVALID',
    ).source;
  }
  return decodeCanonicalBase64(
    required(environment, 'STAGE7_SANDBOX_EXECUTION_CLAIM_B64', 'E7_SANDBOX_CLAIM_REQUIRED'),
    MAX_CLAIM_BYTES,
    'E7_SANDBOX_CLAIM_BASE64_INVALID',
  );
};

export const validateSandboxExecutionClaim = ({
  encodedClaim,
  claimSource,
  environment,
  scope,
  now = new Date(),
}) => {
  const source = executionClaimSource({ encodedClaim, claimSource, environment });
  let claim;
  try {
    claim = parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch {
    fail('E7_SANDBOX_CLAIM_JSON_INVALID');
  }
  if (!validateJsonSchemaSubset(claim, SCHEMA)) fail('E7_SANDBOX_CLAIM_SCHEMA_INVALID');
  const context = contextFromEnvironment(environment, scope);
  const sources = authorizationSources(environment);
  const stage6Authorization = sources.stage6?.authorization;
  const stage7Authorization = sources.stage7?.authorizations?.sandboxSmoke;
  const stage6SourceSha256 = sha256(sources.stage6Source);
  const stage7BundleSourceSha256 = sha256(sources.stage7Source);
  const expectedApprovalSha256 = stage7Authorization?.approvalSha256;
  const expectedOwnerAlias = stage7Authorization?.ownerAlias;
  const providerHostSha256 = sha256(PROVIDER_HOST);
  if (
    claim.scope !== scope ||
    claim.repository !== context.repository ||
    claim.workflow.file !== context.workflowFile ||
    claim.workflow.ref !== context.workflowRef ||
    claim.workflow.sha !== context.workflowSha ||
    claim.workflow.job !== context.workflowJob ||
    claim.execution.runId !== context.runId ||
    claim.execution.runAttempt !== context.runAttempt ||
    claim.execution.environment !== context.environment ||
    claim.execution.candidateSha !== context.candidateSha ||
    claim.execution.releaseId !== context.releaseId ||
    claim.execution.releaseTag !== context.releaseTag ||
    claim.execution.configSha256 !== context.configSha256 ||
    claim.authorization.stage6Id !== 'AUTH-E6-02' ||
    claim.authorization.stage7Id !== context.stage7AuthorizationId ||
    claim.authorization.stage6SourceSha256 !== stage6SourceSha256 ||
    claim.authorization.stage7BundleSourceSha256 !== stage7BundleSourceSha256 ||
    claim.authorization.providerHostSha256 !== providerHostSha256 ||
    sources.stage6?.commitSha !== context.candidateSha ||
    sources.stage6?.target?.hostSha256 !== providerHostSha256 ||
    sources.stage6?.target?.production !== false ||
    stage6Authorization?.id !== 'AUTH-E6-02' ||
    stage6Authorization?.status !== 'APPROVED' ||
    stage6Authorization?.scope !== 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE' ||
    stage6Authorization?.approvedTargetSha256 !== providerHostSha256 ||
    stage7Authorization?.id !== context.stage7AuthorizationId ||
    stage7Authorization?.status !== 'APPROVED' ||
    stage7Authorization?.scope !== 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE' ||
    stage7Authorization?.approvedTargetSha256 !== providerHostSha256 ||
    sources.stage7?.candidateSha !== context.candidateSha ||
    sources.stage7?.releaseId !== context.releaseId ||
    sources.stage7?.stage7ConfigSha256 !== context.configSha256 ||
    sources.stage7?.targets?.sandboxHostSha256 !== providerHostSha256 ||
    stage6Authorization?.approvalSha256 !== expectedApprovalSha256 ||
    stage6Authorization?.ownerAlias !== expectedOwnerAlias ||
    claim.approvalSha256 !== expectedApprovalSha256 ||
    claim.ownerAlias !== expectedOwnerAlias ||
    !SHA256.test(expectedApprovalSha256 ?? '') ||
    !SAFE_ALIAS.test(expectedOwnerAlias ?? '') ||
    !SHA256.test(claim.executionApprovalSha256 ?? '') ||
    !REVIEWER_ALIAS.test(claim.approvedByAlias ?? '') ||
    !SHA256.test(claim.approvalEvidence?.requestSha256 ?? '') ||
    !SHA256.test(claim.approvalEvidence?.responseSha256 ?? '') ||
    claim.approvalEvidence?.reviewerAlias !== claim.approvedByAlias ||
    claim.approvalEvidence?.externalRequests !== 1 ||
    claim.executionApprovalSha256 === expectedApprovalSha256 ||
    !Number.isSafeInteger(stage6Authorization?.maxRequests) ||
    stage6Authorization.maxRequests < 8 ||
    !Number.isSafeInteger(stage7Authorization?.maxRequests) ||
    stage7Authorization.maxRequests < 8 ||
    claim.limits.externalRequests !== 8 ||
    claim.limits.tokenizations !== 1 ||
    claim.limits.transactions !== 1 ||
    claim.containsSensitiveData !== false
  ) {
    fail('E7_SANDBOX_CLAIM_BINDING_INVALID');
  }
  if (
    (context.runAttempt === 1 &&
      (claim.execution.rerunExplicitlyApproved !== false ||
        claim.execution.rerunOfAttempt !== 0)) ||
    (context.runAttempt > 1 &&
      (claim.execution.rerunExplicitlyApproved !== true ||
        claim.execution.rerunOfAttempt !== context.runAttempt - 1))
  ) {
    fail('E7_SANDBOX_CLAIM_RERUN_APPROVAL_INVALID');
  }
  if (!validUtc(claim.approvedAtUtc) || !validUtc(claim.expiresAtUtc)) {
    fail('E7_SANDBOX_CLAIM_TIME_INVALID');
  }
  const approvedAt = Date.parse(claim.approvedAtUtc);
  const expiresAt = Date.parse(claim.expiresAtUtc);
  const stage6ApprovedAt = Date.parse(stage6Authorization.approvedAtUtc ?? '');
  const stage6ExpiresAt = Date.parse(stage6Authorization.expiresAtUtc ?? '');
  const stage7ApprovedAt = Date.parse(stage7Authorization.approvedAtUtc ?? '');
  const stage7ExpiresAt = Date.parse(stage7Authorization.expiresAtUtc ?? '');
  const current = now.getTime();
  if (
    !validUtc(stage6Authorization.approvedAtUtc) ||
    !validUtc(stage6Authorization.expiresAtUtc) ||
    !validUtc(stage7Authorization.approvedAtUtc) ||
    !validUtc(stage7Authorization.expiresAtUtc) ||
    stage6ApprovedAt > current ||
    stage7ApprovedAt > current ||
    stage6ExpiresAt <= current ||
    stage7ExpiresAt <= current ||
    approvedAt > current ||
    expiresAt <= current ||
    approvedAt >= expiresAt ||
    expiresAt - approvedAt > MAX_CLAIM_WINDOW_MS ||
    approvedAt < Math.max(stage6ApprovedAt, stage7ApprovedAt) ||
    expiresAt > Math.min(stage6ExpiresAt, stage7ExpiresAt)
  ) {
    fail('E7_SANDBOX_CLAIM_NOT_ACTIVE');
  }
  const authorization = { stage6SourceSha256, stage7BundleSourceSha256 };
  const bindingSha256 = sha256(JSON.stringify(bindingFor(context, authorization)));
  if (
    claim.executionApprovalSha256 !== executionApprovalFor(claim, context, authorization) ||
    claim.claimId !== claimIdFor(claim)
  ) {
    fail('E7_SANDBOX_CLAIM_ID_INVALID');
  }
  const reference = deterministicReference(scope, context.runId, context.runAttempt, bindingSha256);
  if (reference.length > 64 || !/^e6-(?:rel|pre)-[0-9]+-[0-9]+-[0-9a-f]{12}$/u.test(reference)) {
    fail('E7_SANDBOX_CLAIM_REFERENCE_INVALID');
  }
  return {
    claim,
    claimSha256: sha256(source),
    bindingSha256,
    reference,
    referenceSha256: sha256(reference),
    context,
    authorization,
  };
};

const receiptPath = (environment) => {
  const runnerTemp = required(environment, 'RUNNER_TEMP', 'E7_SANDBOX_CLAIM_RECEIPT_INVALID');
  const candidate = required(
    environment,
    'STAGE7_SANDBOX_CLAIM_RECEIPT',
    'E7_SANDBOX_CLAIM_RECEIPT_INVALID',
  );
  const expected = path.resolve(runnerTemp, 'stage7-sandbox-execution-claim.json');
  if (path.resolve(candidate) !== expected) fail('E7_SANDBOX_CLAIM_RECEIPT_INVALID');
  return expected;
};

const receiptDocument = (validated, status, atUtc) => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'SANDBOX_ONE_USE_EXECUTION_RECEIPT',
  status,
  claimSha256: validated.claimSha256,
  bindingSha256: validated.bindingSha256,
  scope: validated.context.scope,
  runId: validated.context.runId,
  runAttempt: validated.context.runAttempt,
  workflowJob: validated.context.workflowJob,
  environment: validated.context.environment,
  candidateSha: validated.context.candidateSha,
  releaseId: validated.context.releaseId,
  configSha256: validated.context.configSha256,
  referenceSha256: validated.referenceSha256,
  ...(status === 'READY' ? { preparedAtUtc: atUtc } : { consumedAtUtc: atUtc }),
  containsSensitiveData: false,
});

const validateReceipt = (value, validated, status) => {
  const expected = receiptDocument(
    validated,
    status,
    status === 'READY' ? value?.preparedAtUtc : value?.consumedAtUtc,
  );
  const keys = status === 'READY' ? READY_KEYS : CONSUMED_KEYS;
  if (
    !exactKeys(value, keys) ||
    !validUtc(status === 'READY' ? value.preparedAtUtc : value.consumedAtUtc) ||
    JSON.stringify(value) !== JSON.stringify(expected)
  ) {
    fail('E7_SANDBOX_CLAIM_RECEIPT_TAMPERED');
  }
  return value;
};

const readReceipt = (filename, validated, status) => {
  const file = localRegularFile(filename, 16 * 1024, 'E7_SANDBOX_CLAIM_RECEIPT_INVALID');
  let parsed;
  try {
    parsed = parseStrictJsonSource(file.source, { scanForbiddenData: false });
  } catch {
    fail('E7_SANDBOX_CLAIM_RECEIPT_TAMPERED');
  }
  return validateReceipt(parsed, validated, status);
};

const assertPreCredentialBoundary = (environment) => {
  if (
    [...PROVIDER_CREDENTIAL_KEYS, ...CLOUD_CREDENTIAL_KEYS].some(
      (name) => environment[name] !== undefined && environment[name] !== '',
    )
  ) {
    fail('E7_SANDBOX_CLAIM_PREPARE_AFTER_CREDENTIALS');
  }
};

export const prepareSandboxExecutionClaim = ({ environment, scope, now = new Date() }) => {
  assertPreCredentialBoundary(environment);
  const validated = validateSandboxExecutionClaim({ environment, scope, now });
  const filename = receiptPath(environment);
  const consumedFilename = `${filename}.consumed`;
  try {
    lstatSync(consumedFilename);
    fail('E7_SANDBOX_CLAIM_REPLAY');
  } catch (error) {
    if (error instanceof SandboxExecutionClaimError) throw error;
    if (error?.code !== 'ENOENT') fail('E7_SANDBOX_CLAIM_RECEIPT_INVALID');
  }
  const ready = receiptDocument(validated, 'READY', now.toISOString());
  try {
    writeFileSync(filename, `${JSON.stringify(ready)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    chmodSync(filename, 0o600);
  } catch (error) {
    if (error?.code === 'EEXIST') fail('E7_SANDBOX_CLAIM_REPLAY');
    fail('E7_SANDBOX_CLAIM_RECEIPT_INVALID');
  }
  readReceipt(filename, validated, 'READY');
  return validated;
};

export const consumeSandboxExecutionClaim = ({ environment, scope, now = new Date() }) => {
  const validated = validateSandboxExecutionClaim({ environment, scope, now });
  const filename = receiptPath(environment);
  readReceipt(filename, validated, 'READY');
  const consumedFilename = `${filename}.consumed`;
  const consumed = receiptDocument(validated, 'CONSUMED', now.toISOString());
  let descriptor;
  try {
    descriptor = openSync(consumedFilename, 'wx', 0o600);
    writeFileSync(descriptor, `${JSON.stringify(consumed)}\n`, { encoding: 'utf8' });
    closeSync(descriptor);
    descriptor = undefined;
    chmodSync(consumedFilename, 0o600);
  } catch (error) {
    if (descriptor !== undefined) closeSync(descriptor);
    if (error?.code === 'EEXIST') fail('E7_SANDBOX_CLAIM_REPLAY');
    rmSync(consumedFilename, { force: true });
    fail('E7_SANDBOX_CLAIM_RECEIPT_INVALID');
  }
  readReceipt(consumedFilename, validated, 'CONSUMED');
  return validated;
};

export const revalidateConsumedSandboxExecutionClaim = ({
  environment,
  scope,
  expectedClaimSha256,
  expectedBindingSha256,
  expectedReferenceSha256,
  now = new Date(),
}) => {
  const validated = validateSandboxExecutionClaim({
    environment,
    scope,
    now,
  });
  if (
    validated.claimSha256 !== expectedClaimSha256 ||
    validated.bindingSha256 !== expectedBindingSha256 ||
    validated.referenceSha256 !== expectedReferenceSha256
  ) {
    fail('E7_SANDBOX_CLAIM_CHANGED_DURING_RUN');
  }
  const filename = receiptPath(environment);
  readReceipt(filename, validated, 'READY');
  readReceipt(`${filename}.consumed`, validated, 'CONSUMED');
  return validated;
};

export const sanitizedSandboxExecutionBinding = (validated) => ({
  schemaVersion: 1,
  kind: 'SANDBOX_ONE_USE_EXECUTION',
  claimSha256: validated.claimSha256,
  bindingSha256: validated.bindingSha256,
  runId: validated.context.runId,
  runAttempt: validated.context.runAttempt,
  workflowSha: validated.context.workflowSha,
  workflowJob: validated.context.workflowJob,
  environment: validated.context.environment,
  candidateSha: validated.context.candidateSha,
  releaseId: validated.context.releaseId,
  configSha256: validated.context.configSha256,
  stage6AuthorizationSha256: validated.authorization.stage6SourceSha256,
  stage7AuthorizationSha256: validated.authorization.stage7BundleSourceSha256,
  approvalRequestSha256: validated.claim.approvalEvidence.requestSha256,
  approvalResponseSha256: validated.claim.approvalEvidence.responseSha256,
  approvedByAlias: validated.claim.approvedByAlias,
  referenceSha256: validated.referenceSha256,
  maximumExternalRequests: 8,
  maximumTokenizations: 1,
  maximumTransactions: 1,
  localAtomicConsumption: true,
  providerDuplicateReferenceDefense: true,
  containsSensitiveData: false,
});

export const validateSandboxExecutionEvidence = (value, expected) => {
  const contract = scopeContract(expected.scope);
  if (
    !exactKeys(value, EVIDENCE_KEYS) ||
    value.schemaVersion !== 1 ||
    value.kind !== 'SANDBOX_ONE_USE_EXECUTION' ||
    !SHA256.test(value.claimSha256 ?? '') ||
    !SHA256.test(value.bindingSha256 ?? '') ||
    !POSITIVE_INTEGER.test(value.runId ?? '') ||
    !Number.isSafeInteger(value.runAttempt) ||
    value.runAttempt < 1 ||
    value.runAttempt > 1000 ||
    value.workflowSha !== expected.candidateSha ||
    value.workflowJob !== contract.job ||
    value.environment !== contract.environment ||
    value.candidateSha !== expected.candidateSha ||
    value.releaseId !== expected.releaseId ||
    value.configSha256 !== expected.configSha256 ||
    !SHA256.test(value.stage6AuthorizationSha256 ?? '') ||
    value.stage6AuthorizationSha256 !== expected.stage6AuthorizationSha256 ||
    !SHA256.test(value.stage7AuthorizationSha256 ?? '') ||
    !SHA256.test(value.approvalRequestSha256 ?? '') ||
    !SHA256.test(value.approvalResponseSha256 ?? '') ||
    !REVIEWER_ALIAS.test(value.approvedByAlias ?? '') ||
    value.referenceSha256 !== expected.referenceSha256 ||
    value.maximumExternalRequests !== 8 ||
    value.maximumTokenizations !== 1 ||
    value.maximumTransactions !== 1 ||
    value.localAtomicConsumption !== true ||
    value.providerDuplicateReferenceDefense !== true ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_SANDBOX_EXECUTION_EVIDENCE_INVALID');
  }
  return value;
};

const fixtureAuthorizationSources = (scope, overrides = {}) => {
  const approvalSha256 = 'a'.repeat(64);
  const ownerAlias = 'release-owner';
  const candidateSha = 'b'.repeat(40);
  const configSha256 = 'c'.repeat(64);
  const providerHostSha256 = sha256(PROVIDER_HOST);
  const authorization = {
    status: 'APPROVED',
    scope: 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
    approvalSha256,
    approvedTargetSha256: providerHostSha256,
    ownerAlias,
    maxRequests: overrides.maxRequests ?? 8,
    approvedAtUtc: '2026-08-18T11:00:00.000Z',
    expiresAtUtc: overrides.expiresAtUtc ?? '2026-08-18T12:30:00.000Z',
  };
  const stage6 = Buffer.from(
    JSON.stringify({
      commitSha: candidateSha,
      authorization: { id: 'AUTH-E6-02', ...authorization },
      target: { hostSha256: providerHostSha256, production: false },
    }),
  );
  const stage7 = Buffer.from(
    JSON.stringify({
      candidateSha,
      releaseId: 'rel-20260818-1200-bbbbbbb',
      stage7ConfigSha256: configSha256,
      targets: { sandboxHostSha256: providerHostSha256 },
      authorizations: {
        sandboxSmoke: {
          id: scopeContract(scope).stage7AuthorizationId,
          ...authorization,
        },
      },
    }),
  );
  return { approvalSha256, ownerAlias, stage6, stage7 };
};

const fixtureEnvironment = ({
  directory,
  scope = 'full',
  runId = '123456789',
  attempt = 1,
  releaseTag = 'v1.0.0-rc.1',
  authorizationOverrides = {},
}) => {
  const contract = scopeContract(scope);
  const candidateSha = 'b'.repeat(40);
  const sources = fixtureAuthorizationSources(scope, authorizationOverrides);
  const externalPath = path.join(directory, 'external.json');
  writeFileSync(externalPath, sources.stage7, { flag: 'wx', mode: 0o600 });
  chmodSync(externalPath, 0o600);
  const receipt = path.join(directory, 'stage7-sandbox-execution-claim.json');
  return {
    sources,
    receipt,
    environment: {
      GITHUB_ACTIONS: 'true',
      GITHUB_EVENT_NAME: 'workflow_dispatch',
      GITHUB_REF: 'refs/heads/master',
      GITHUB_REPOSITORY: REPOSITORY,
      GITHUB_JOB: contract.job,
      GITHUB_RUN_ID: runId,
      GITHUB_RUN_ATTEMPT: String(attempt),
      GITHUB_SHA: candidateSha,
      GITHUB_WORKFLOW_SHA: candidateSha,
      GITHUB_WORKFLOW_REF: `${REPOSITORY}/${contract.workflowFile}@refs/heads/master`,
      STAGE7_PROTECTED_ENVIRONMENT: contract.environment,
      STAGE7_CANDIDATE_SHA: candidateSha,
      STAGE7_RELEASE_ID: 'rel-20260818-1200-bbbbbbb',
      ...(scope === 'full' ? { STAGE7_RELEASE_TAG: releaseTag } : {}),
      EXPECTED_STAGE7_CONFIG_SHA256: 'c'.repeat(64),
      STAGE6_SANDBOX_AUTHORIZATION_B64: sources.stage6.toString('base64'),
      STAGE7_EXTERNAL_AUTHORIZATIONS: externalPath,
      RUNNER_TEMP: directory,
      STAGE7_SANDBOX_CLAIM_RECEIPT: receipt,
    },
  };
};

const fixtureClaim = ({ environment, sources, scope = 'full', attempt = 1 }) => {
  const contract = scopeContract(scope);
  const claim = {
    schemaId: 'async-checkout-stage7-sandbox-execution-claim',
    schemaVersion: 1,
    stage: 7,
    kind: 'SANDBOX_ONE_USE_EXECUTION_CLAIM',
    status: 'APPROVED',
    scope,
    repository: REPOSITORY,
    workflow: {
      file: contract.workflowFile,
      ref: environment.GITHUB_WORKFLOW_REF,
      sha: environment.GITHUB_WORKFLOW_SHA,
      job: contract.job,
    },
    execution: {
      runId: environment.GITHUB_RUN_ID,
      runAttempt: attempt,
      environment: contract.environment,
      candidateSha: environment.STAGE7_CANDIDATE_SHA,
      releaseId: environment.STAGE7_RELEASE_ID,
      releaseTag: scope === 'full' ? environment.STAGE7_RELEASE_TAG : 'NOT_APPLICABLE',
      configSha256: environment.EXPECTED_STAGE7_CONFIG_SHA256,
      rerunExplicitlyApproved: attempt > 1,
      rerunOfAttempt: attempt > 1 ? attempt - 1 : 0,
    },
    authorization: {
      stage6Id: 'AUTH-E6-02',
      stage7Id: contract.stage7AuthorizationId,
      stage6SourceSha256: sha256(sources.stage6),
      stage7BundleSourceSha256: sha256(sources.stage7),
      providerHostSha256: sha256(PROVIDER_HOST),
    },
    limits: { externalRequests: 8, tokenizations: 1, transactions: 1 },
    approvedAtUtc: '2026-08-18T11:50:00.000Z',
    expiresAtUtc: '2026-08-18T12:20:00.000Z',
    ownerAlias: sources.ownerAlias,
    approvalSha256: sources.approvalSha256,
    executionApprovalSha256: 'd'.repeat(64),
    approvedByAlias: 'sandbox-reviewer',
    approvalEvidence: {
      requestSha256: 'e'.repeat(64),
      responseSha256: 'f'.repeat(64),
      reviewerAlias: 'sandbox-reviewer',
      externalRequests: 1,
    },
    claimId: '0'.repeat(64),
    containsSensitiveData: false,
  };
  const context = contextFromEnvironment(environment, scope);
  const authorization = {
    stage6SourceSha256: sha256(sources.stage6),
    stage7BundleSourceSha256: sha256(sources.stage7),
  };
  claim.executionApprovalSha256 = executionApprovalFor(claim, context, authorization);
  claim.claimId = claimIdFor(claim);
  return claim;
};

export const selfTestSandboxExecutionClaim = async () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'stage7-sandbox-claim-'));
  try {
    const controlSource = readFileSync(path.join(HERE, 'control.mjs'), 'utf8');
    const wrapperStart = controlSource.indexOf('const sandboxSmokeRelease = async');
    const wrapperEnd = controlSource.indexOf('const execution = spawnSync', wrapperStart);
    const wrapperSource = controlSource.slice(wrapperStart, wrapperEnd);
    assert.ok(
      wrapperSource.indexOf('executionClaim = validateSandboxExecutionClaim') >= 0 &&
        wrapperSource.indexOf('executionClaim = validateSandboxExecutionClaim') <
          wrapperSource.indexOf('validateRequiredEnvironment(process.env'),
      'wrapper must reject an invalid claim before reading provider credentials',
    );
    const harnessSource = readFileSync(
      path.join(HERE, '../stage6/sandbox-authorized/run.mjs'),
      'utf8',
    );
    const harnessStart = harnessSource.indexOf('const execute = async');
    const harnessEnd = harnessSource.indexOf('const dryRun =', harnessStart);
    const harnessExecution = harnessSource.slice(harnessStart, harnessEnd);
    assert.ok(
      harnessExecution.indexOf('consumeSandboxExecutionClaim') >= 0 &&
        harnessExecution.indexOf('consumeSandboxExecutionClaim') <
          harnessExecution.indexOf('validateRequiredEnvironment(process.env'),
      'harness must atomically consume the claim before reading provider credentials',
    );
    const fixture = fixtureEnvironment({ directory });
    const now = new Date('2026-08-18T12:00:00.000Z');
    assert.equal(scopeContract('full').environment, 'assessment-release-sandbox');
    assert.throws(
      () =>
        contextFromEnvironment(
          { ...fixture.environment, STAGE7_PROTECTED_ENVIRONMENT: 'assessment-release' },
          'full',
        ),
      (error) => error.code === 'E7_SANDBOX_CLAIM_CONTEXT_INVALID',
    );
    const producerEnvironment = {
      ...fixture.environment,
      GITHUB_JOB: scopeContract('full').producerJob,
    };
    const request = createSandboxExecutionRequest({
      environment: producerEnvironment,
      scope: 'full',
      now,
    });
    assert.equal(request.request.execution.runId, fixture.environment.GITHUB_RUN_ID);
    assert.equal(
      validateSandboxExecutionRequest({
        source: request.source,
        environment: fixture.environment,
        scope: 'full',
        now,
      }).requestSha256,
      request.requestSha256,
    );
    const finalDirectory = mkdtempSync(path.join(tmpdir(), 'stage7-sandbox-final-tag-'));
    try {
      const finalFixture = fixtureEnvironment({
        directory: finalDirectory,
        releaseTag: 'v1.0.0',
      });
      const finalProducerEnvironment = {
        ...finalFixture.environment,
        GITHUB_JOB: scopeContract('full').producerJob,
      };
      const finalRequest = createSandboxExecutionRequest({
        environment: finalProducerEnvironment,
        scope: 'full',
        now,
      });
      assert.equal(finalRequest.request.execution.releaseTag, 'v1.0.0');
      assert.equal(
        validateSandboxExecutionRequest({
          source: finalRequest.source,
          environment: finalFixture.environment,
          scope: 'full',
          now,
        }).requestSha256,
        finalRequest.requestSha256,
      );
      const finalClaim = fixtureClaim({
        environment: finalFixture.environment,
        sources: finalFixture.sources,
      });
      assert.equal(
        validateSandboxExecutionClaim({
          encodedClaim: Buffer.from(JSON.stringify(finalClaim)).toString('base64'),
          environment: finalFixture.environment,
          scope: 'full',
          now,
        }).context.releaseTag,
        'v1.0.0',
      );
      for (const releaseTag of ['v01.0.0', 'v1.0.0-beta.1', 'v1.0.0-rc.0']) {
        assert.throws(
          () =>
            createSandboxExecutionRequest({
              environment: { ...finalProducerEnvironment, STAGE7_RELEASE_TAG: releaseTag },
              scope: 'full',
              now,
            }),
          (error) => error.code === 'E7_SANDBOX_REQUEST_CONTEXT_INVALID',
        );
      }
    } finally {
      rmSync(finalDirectory, { recursive: true, force: true });
    }
    let approvalCalls = 0;
    fixture.environment.GITHUB_TOKEN = 'github-token-fixture-value';
    const review = {
      state: 'approved',
      comment: `STAGE7_SANDBOX_CLAIM_REQUEST_SHA256=${request.requestSha256}`,
      environments: [
        {
          id: 101,
          name: scopeContract('full').environment,
          url: expectedEnvironmentUrl(scopeContract('full').environment),
        },
      ],
      user: { id: 7, login: 'sandbox-reviewer', type: 'User' },
    };
    const approved = await approveSandboxExecutionRequest({
      requestSource: request.source,
      environment: fixture.environment,
      scope: 'full',
      fetchImpl: async () => {
        approvalCalls += 1;
        return {
          status: 200,
          redirected: false,
          headers: { get: () => 'application/json; charset=utf-8' },
          text: async () => JSON.stringify([review]),
        };
      },
      now: () => now,
    });
    assert.equal(approvalCalls, 1);
    assert.equal(approved.claim.approvalEvidence.requestSha256, request.requestSha256);
    assert.equal(approved.approvalExternalRequests, 1);

    const claim = fixtureClaim({ environment: fixture.environment, sources: fixture.sources });
    const encoded = Buffer.from(JSON.stringify(claim)).toString('base64');
    fixture.environment.STAGE7_SANDBOX_EXECUTION_CLAIM_B64 = encoded;
    const prepared = prepareSandboxExecutionClaim({
      environment: fixture.environment,
      scope: 'full',
      now,
    });
    const consumed = consumeSandboxExecutionClaim({
      environment: fixture.environment,
      scope: 'full',
      now,
    });
    assert.equal(prepared.claimSha256, consumed.claimSha256);
    assert.equal(prepared.reference, consumed.reference);
    assert.match(prepared.reference, /^e6-rel-/u);
    const rebound = revalidateConsumedSandboxExecutionClaim({
      environment: fixture.environment,
      scope: 'full',
      expectedClaimSha256: consumed.claimSha256,
      expectedBindingSha256: consumed.bindingSha256,
      expectedReferenceSha256: consumed.referenceSha256,
      now,
    });
    assert.equal(rebound.referenceSha256, consumed.referenceSha256);
    assert.throws(
      () => consumeSandboxExecutionClaim({ environment: fixture.environment, scope: 'full', now }),
      (error) => error.code === 'E7_SANDBOX_CLAIM_REPLAY',
    );

    let credentialsRead = 0;
    let externalRequests = 0;
    const replayEnvironment = fixtureEnvironment({
      directory: mkdtempSync(path.join(tmpdir(), 'stage7-sandbox-replay-')),
      attempt: 2,
    });
    const guarded = new Proxy(replayEnvironment.environment, {
      get(target, property, receiver) {
        if (typeof property === 'string' && PROVIDER_CREDENTIAL_KEYS.includes(property)) {
          credentialsRead += 1;
        }
        return Reflect.get(target, property, receiver);
      },
    });
    guarded.STAGE7_SANDBOX_EXECUTION_CLAIM_B64 = encoded;
    assert.throws(
      () =>
        validateSandboxExecutionClaim({
          encodedClaim: encoded,
          environment: guarded,
          scope: 'full',
          now,
        }),
      (error) => error.code === 'E7_SANDBOX_CLAIM_BINDING_INVALID',
    );
    assert.equal(credentialsRead, 0);
    assert.equal(externalRequests, 0);
    rmSync(replayEnvironment.environment.RUNNER_TEMP, { recursive: true, force: true });

    const expectPreCredentialRejection = ({ fixtureValue, claimValue, code }) => {
      let protectedReads = 0;
      const protectedEnvironment = new Proxy(fixtureValue.environment, {
        get(target, property, receiver) {
          if (typeof property === 'string' && PROVIDER_CREDENTIAL_KEYS.includes(property)) {
            protectedReads += 1;
          }
          return Reflect.get(target, property, receiver);
        },
      });
      const candidate = Buffer.from(JSON.stringify(claimValue)).toString('base64');
      assert.throws(
        () =>
          validateSandboxExecutionClaim({
            encodedClaim: candidate,
            environment: protectedEnvironment,
            scope: 'full',
            now,
          }),
        (error) => error.code === code,
      );
      assert.equal(protectedReads, 0);
    };

    const expiredDirectory = mkdtempSync(path.join(tmpdir(), 'stage7-sandbox-expired-'));
    const expired = fixtureEnvironment({
      directory: expiredDirectory,
      authorizationOverrides: { expiresAtUtc: '2026-08-18T11:59:59.999Z' },
    });
    expectPreCredentialRejection({
      fixtureValue: expired,
      claimValue: fixtureClaim({ environment: expired.environment, sources: expired.sources }),
      code: 'E7_SANDBOX_CLAIM_NOT_ACTIVE',
    });
    rmSync(expiredDirectory, { recursive: true, force: true });

    const limitedDirectory = mkdtempSync(path.join(tmpdir(), 'stage7-sandbox-limited-'));
    const limited = fixtureEnvironment({
      directory: limitedDirectory,
      authorizationOverrides: { maxRequests: 7 },
    });
    expectPreCredentialRejection({
      fixtureValue: limited,
      claimValue: fixtureClaim({ environment: limited.environment, sources: limited.sources }),
      code: 'E7_SANDBOX_CLAIM_BINDING_INVALID',
    });
    rmSync(limitedDirectory, { recursive: true, force: true });

    expectPreCredentialRejection({
      fixtureValue: fixture,
      claimValue: { ...claim, claimId: 'f'.repeat(64) },
      code: 'E7_SANDBOX_CLAIM_ID_INVALID',
    });

    const tampered = Buffer.from(
      JSON.stringify({ ...claim, claimId: 'f'.repeat(64), extra: true }),
    ).toString('base64');
    assert.throws(
      () =>
        validateSandboxExecutionClaim({
          encodedClaim: tampered,
          environment: fixture.environment,
          scope: 'full',
          now,
        }),
      (error) => error.code === 'E7_SANDBOX_CLAIM_SCHEMA_INVALID',
    );
    const newRun = { ...fixture.environment, GITHUB_RUN_ID: '987654321' };
    assert.throws(
      () =>
        validateSandboxExecutionClaim({
          encodedClaim: encoded,
          environment: newRun,
          scope: 'full',
          now,
        }),
      (error) => error.code === 'E7_SANDBOX_CLAIM_BINDING_INVALID',
    );

    const rerunDirectory = mkdtempSync(path.join(tmpdir(), 'stage7-sandbox-new-claim-'));
    const rerun = fixtureEnvironment({ directory: rerunDirectory, attempt: 2 });
    const rerunClaim = fixtureClaim({
      environment: rerun.environment,
      sources: rerun.sources,
      attempt: 2,
    });
    const reusedExecutionApproval = {
      ...rerunClaim,
      executionApprovalSha256: claim.executionApprovalSha256,
    };
    reusedExecutionApproval.claimId = claimIdFor(reusedExecutionApproval);
    expectPreCredentialRejection({
      fixtureValue: rerun,
      claimValue: reusedExecutionApproval,
      code: 'E7_SANDBOX_CLAIM_ID_INVALID',
    });
    const rerunEncoded = Buffer.from(JSON.stringify(rerunClaim)).toString('base64');
    rerun.environment.STAGE7_SANDBOX_EXECUTION_CLAIM_B64 = rerunEncoded;
    assert.equal(
      validateSandboxExecutionClaim({
        encodedClaim: rerunEncoded,
        environment: rerun.environment,
        scope: 'full',
        now,
      }).context.runAttempt,
      2,
    );
    rmSync(rerunDirectory, { recursive: true, force: true });
    process.stdout.write(
      'stage-7 sandbox execution claim self-test: PASS (request handoff, protected approval, replay, tamper, wrong-attempt, new-run, expired-auth, request-limit, claim-id, cross-run approval reuse; 0 provider credentials, 0 real external requests)\n',
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

const writeExclusivePrivate = (filename, source, code) => {
  if (typeof filename !== 'string' || filename.length === 0 || !path.isAbsolute(filename)) {
    fail(code);
  }
  try {
    writeFileSync(filename, source, { flag: 'wx', mode: 0o600 });
    chmodSync(filename, 0o600);
  } catch {
    fail(code);
  }
  const written = localRegularFile(filename, Math.max(source.byteLength, 2), code).source;
  if (!Buffer.from(written).equals(Buffer.from(source))) fail(code);
};

const main = async () => {
  const arguments_ = normalizePnpmScriptArguments(process.argv.slice(2), { separatorIndex: 0 });
  if (arguments_.length === 1 && arguments_[0] === '--self-test') {
    await selfTestSandboxExecutionClaim();
    return;
  }
  if (
    arguments_.length === 5 &&
    arguments_[0] === '--request' &&
    arguments_[1] === '--scope' &&
    Object.hasOwn(SCOPES, arguments_[2]) &&
    arguments_[3] === '--output'
  ) {
    const created = createSandboxExecutionRequest({
      environment: process.env,
      scope: arguments_[2],
    });
    writeExclusivePrivate(
      path.resolve(arguments_[4]),
      created.source,
      'E7_SANDBOX_REQUEST_WRITE_INVALID',
    );
    process.stdout.write(
      `${JSON.stringify({ status: 'AWAITING_PROTECTED_APPROVAL', requestSha256: created.requestSha256, approvalComment: `STAGE7_SANDBOX_CLAIM_REQUEST_SHA256=${created.requestSha256}`, runId: created.context.runId, runAttempt: created.context.runAttempt, externalRequests: 0, credentialsRead: 0, containsSensitiveData: false })}\n`,
    );
    return;
  }
  if (
    arguments_.length === 9 &&
    arguments_[0] === '--approve' &&
    arguments_[1] === '--scope' &&
    Object.hasOwn(SCOPES, arguments_[2]) &&
    arguments_[3] === '--request' &&
    arguments_[5] === '--claim' &&
    arguments_[7] === '--receipt'
  ) {
    const requestFile = localRegularFile(
      path.resolve(arguments_[4]),
      MAX_REQUEST_BYTES,
      'E7_SANDBOX_REQUEST_SOURCE_INVALID',
    );
    const approved = await approveSandboxExecutionRequest({
      requestSource: requestFile.source,
      environment: process.env,
      scope: arguments_[2],
    });
    const claimPath = path.resolve(arguments_[6]);
    const receipt = path.resolve(arguments_[8]);
    writeExclusivePrivate(claimPath, approved.claimSource, 'E7_SANDBOX_CLAIM_WRITE_INVALID');
    const runtimeEnvironment = {
      ...process.env,
      STAGE7_SANDBOX_EXECUTION_CLAIM: claimPath,
      STAGE7_SANDBOX_CLAIM_RECEIPT: receipt,
    };
    const prepared = prepareSandboxExecutionClaim({
      environment: runtimeEnvironment,
      scope: arguments_[2],
    });
    if (
      prepared.claimSha256 !== approved.claimSha256 ||
      sha256(
        localRegularFile(claimPath, MAX_CLAIM_BYTES, 'E7_SANDBOX_CLAIM_SOURCE_INVALID').source,
      ) !== approved.claimSha256
    ) {
      fail('E7_SANDBOX_CLAIM_CHANGED_DURING_RUN');
    }
    process.stdout.write(
      `${JSON.stringify({ status: 'PASS', requestSha256: approved.requestSha256, claimSha256: approved.claimSha256, bindingSha256: approved.bindingSha256, approvedByAlias: approved.approvedByAlias, runId: approved.context.runId, runAttempt: approved.context.runAttempt, approvalExternalRequests: 1, providerExternalRequests: 0, credentialsRead: 0, containsSensitiveData: false })}\n`,
    );
    return;
  }
  if (
    arguments_.length !== 3 ||
    arguments_[0] !== '--prepare' ||
    arguments_[1] !== '--scope' ||
    !Object.hasOwn(SCOPES, arguments_[2])
  ) {
    fail('E7_SANDBOX_CLAIM_ARGUMENT_SET_INVALID');
  }
  const validated = prepareSandboxExecutionClaim({
    environment: process.env,
    scope: arguments_[2],
  });
  process.stdout.write(
    `${JSON.stringify({ status: 'PASS', claimSha256: validated.claimSha256, bindingSha256: validated.bindingSha256, runId: validated.context.runId, runAttempt: validated.context.runAttempt, externalRequests: 0, credentialsRead: 0, containsSensitiveData: false })}\n`,
  );
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code =
      error instanceof SandboxExecutionClaimError
        ? error.code
        : 'E7_SANDBOX_CLAIM_UNEXPECTED_FAILURE';
    process.stderr.write(`stage-7 sandbox execution claim: ${code}\n`);
    process.exitCode = 1;
  });
}
