#!/usr/bin/env node

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { TextEncoder } from 'node:util';

import { normalizePnpmScriptArguments } from './cli-arguments.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const API_ROOT = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const MAX_RESPONSE_BYTES = 1024 * 1024;
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const POSITIVE_INTEGER = /^[1-9][0-9]{0,19}$/u;
const SAFE_ALIAS = /^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u;
const SAFE_RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const ENVIRONMENTS = new Map([
  ['assessment-release', 'full'],
  ['assessment-prerelease', 'prerelease'],
  ['assessment-release-baseline', 'baseline'],
]);
const OUTPUT_KEYS = [
  'schemaVersion',
  'stage',
  'kind',
  'status',
  'scope',
  'repository',
  'candidateSha',
  'releaseId',
  'runId',
  'runAttempt',
  'environment',
  'reviewerAlias',
  'reviewed',
  'reviewState',
  'iamReviewAttested',
  'iamReviewedDiffSha256',
  'responseSha256',
  'capturedAtUtc',
  'externalRequests',
  'mutationsPerformed',
  'containsSensitiveData',
];

export class GithubEnvironmentApprovalError extends Error {
  constructor(code) {
    super(code);
    this.name = 'GithubEnvironmentApprovalError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new GithubEnvironmentApprovalError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const canonicalUtc = (value) =>
  typeof value === 'string' &&
  !Number.isNaN(Date.parse(value)) &&
  new Date(value).toISOString() === value;

const workspaceRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));

const checkedPath = (candidate, { mustExist = true } = {}) => {
  if (typeof candidate !== 'string' || candidate.length === 0) {
    fail('E7_GITHUB_APPROVAL_PATH_INVALID');
  }
  const absolute = path.resolve(candidate);
  const relative = path.relative(workspaceRoot, absolute);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('E7_GITHUB_APPROVAL_PATH_OUTSIDE_WORKSPACE');
  }
  if (mustExist) {
    let current = workspaceRoot;
    for (const segment of relative.split(path.sep).filter(Boolean)) {
      current = path.join(current, segment);
      const stat = lstatSync(current);
      if (stat.isSymbolicLink()) fail('E7_GITHUB_APPROVAL_SYMLINK_FORBIDDEN');
    }
    if (
      !lstatSync(absolute).isFile() ||
      !realpathSync(absolute).startsWith(`${workspaceRoot}${path.sep}`)
    ) {
      fail('E7_GITHUB_APPROVAL_PATH_INVALID');
    }
  } else {
    let current = workspaceRoot;
    for (const segment of path.dirname(relative).split(path.sep).filter(Boolean)) {
      current = path.join(current, segment);
      try {
        const stat = lstatSync(current);
        if (stat.isSymbolicLink()) fail('E7_GITHUB_APPROVAL_SYMLINK_FORBIDDEN');
        if (!stat.isDirectory()) fail('E7_GITHUB_APPROVAL_PATH_INVALID');
      } catch (error) {
        if (error instanceof GithubEnvironmentApprovalError) throw error;
        if (error?.code === 'ENOENT') break;
        fail('E7_GITHUB_APPROVAL_PATH_INVALID');
      }
    }
    try {
      if (lstatSync(absolute).isSymbolicLink()) fail('E7_GITHUB_APPROVAL_SYMLINK_FORBIDDEN');
    } catch (error) {
      if (error instanceof GithubEnvironmentApprovalError) throw error;
      if (error?.code !== 'ENOENT') fail('E7_GITHUB_APPROVAL_PATH_INVALID');
    }
  }
  return absolute;
};

const parseFlags = (values) => {
  const flags = {};
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name?.startsWith('--') || value === undefined || value.startsWith('--')) {
      fail('E7_GITHUB_APPROVAL_ARGUMENT_SET_INVALID');
    }
    const key = name.slice(2);
    if (Object.hasOwn(flags, key)) fail('E7_GITHUB_APPROVAL_ARGUMENT_SET_INVALID');
    flags[key] = value;
  }
  const expected = [
    'candidate-sha',
    'diff',
    'environment',
    'evidence',
    'release-id',
    'repository',
    'run-attempt',
    'run-id',
  ];
  if (Object.keys(flags).sort().join('\0') !== expected.sort().join('\0')) {
    fail('E7_GITHUB_APPROVAL_ARGUMENT_SET_INVALID');
  }
  return flags;
};

const expectedEnvironmentUrl = (repository, environment) =>
  `${API_ROOT}/repos/${repository}/environments/${encodeURIComponent(environment)}`;

const validateContext = (context) => {
  const scope = ENVIRONMENTS.get(context.environment);
  if (
    context.repository !== REPOSITORY ||
    context.githubRepository !== context.repository ||
    context.githubRunId !== context.runId ||
    context.githubRunAttempt !== context.runAttempt ||
    context.githubEnvironment !== context.environment ||
    context.githubActions !== 'true' ||
    context.githubEventName !== 'workflow_dispatch' ||
    context.githubRef !== 'refs/heads/master' ||
    context.githubSha !== context.candidateSha ||
    scope === undefined ||
    !SHA.test(context.candidateSha ?? '') ||
    !SAFE_RELEASE_ID.test(context.releaseId ?? '') ||
    !POSITIVE_INTEGER.test(context.runId ?? '') ||
    !POSITIVE_INTEGER.test(context.runAttempt ?? '') ||
    typeof context.token !== 'string' ||
    context.token.length < 20 ||
    context.token.length > 4096 ||
    /\s/u.test(context.token)
  ) {
    fail('E7_GITHUB_APPROVAL_CONTEXT_INVALID');
  }
  const runAttempt = Number(context.runAttempt);
  if (!Number.isSafeInteger(runAttempt)) fail('E7_GITHUB_APPROVAL_CONTEXT_INVALID');
  return { scope, runAttempt };
};

const matchingReview = ({ response, repository, environment, diffSha256 }) => {
  if (!Array.isArray(response)) fail('E7_GITHUB_APPROVAL_RESPONSE_INVALID');
  const expectedComment = `STAGE7_IAM_DIFF_REVIEWED_SHA256=${diffSha256}`;
  const environmentReviews = response.filter(
    (review) =>
      object(review) &&
      Array.isArray(review.environments) &&
      review.environments.some((entry) => object(entry) && entry.name === environment),
  );
  const matching = environmentReviews.filter(
    (review) => review.state === 'approved' && review.comment === expectedComment,
  );
  if (matching.length === 0 && environmentReviews.length === 1) {
    if (environmentReviews[0].state !== 'approved') {
      fail('E7_GITHUB_APPROVAL_STATE_INVALID');
    }
    fail('E7_GITHUB_APPROVAL_IAM_ATTESTATION_INVALID');
  }
  if (matching.length !== 1) fail('E7_GITHUB_APPROVAL_REVIEW_AMBIGUOUS');
  const review = matching[0];
  const environments = review.environments;
  const environmentRecord = environments[0];
  const reviewerAlias = review.user?.login?.toLowerCase();
  if (
    environments.length !== 1 ||
    !object(environmentRecord) ||
    environmentRecord.name !== environment ||
    environmentRecord.url !== expectedEnvironmentUrl(repository, environment) ||
    !Number.isSafeInteger(environmentRecord.id) ||
    environmentRecord.id < 1
  ) {
    fail('E7_GITHUB_APPROVAL_ENVIRONMENT_INVALID');
  }
  if (review.state !== 'approved') fail('E7_GITHUB_APPROVAL_STATE_INVALID');
  if (
    !object(review.user) ||
    review.user.type !== 'User' ||
    !Number.isSafeInteger(review.user.id) ||
    review.user.id < 1 ||
    !SAFE_ALIAS.test(reviewerAlias ?? '') ||
    reviewerAlias === 'github-actions'
  ) {
    fail('E7_GITHUB_APPROVAL_REVIEWER_INVALID');
  }
  if (review.comment !== expectedComment) fail('E7_GITHUB_APPROVAL_IAM_ATTESTATION_INVALID');
  return reviewerAlias;
};

export const validateGithubEnvironmentApproval = (value, expected) => {
  const expectedScope = ENVIRONMENTS.get(expected.environment);
  if (
    !exactKeys(value, OUTPUT_KEYS) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'GITHUB_ENVIRONMENT_APPROVAL' ||
    value.status !== 'PASS' ||
    value.scope !== expectedScope ||
    value.repository !== REPOSITORY ||
    value.repository !== expected.repository ||
    value.candidateSha !== expected.candidateSha ||
    value.releaseId !== expected.releaseId ||
    value.runId !== expected.runId ||
    !POSITIVE_INTEGER.test(value.runId ?? '') ||
    value.runAttempt !== expected.runAttempt ||
    !Number.isSafeInteger(value.runAttempt) ||
    value.runAttempt < 1 ||
    value.environment !== expected.environment ||
    !SAFE_ALIAS.test(value.reviewerAlias ?? '') ||
    value.reviewed !== true ||
    value.reviewState !== 'approved' ||
    value.iamReviewAttested !== true ||
    value.iamReviewedDiffSha256 !== expected.diffSha256 ||
    !SHA256.test(value.responseSha256 ?? '') ||
    !canonicalUtc(value.capturedAtUtc) ||
    value.externalRequests !== 1 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_GITHUB_APPROVAL_EVIDENCE_INVALID');
  }
  return value;
};

export const captureGithubEnvironmentApproval = async ({
  context,
  diff,
  fetchImpl = globalThis.fetch,
  now = () => new Date(),
}) => {
  const { scope, runAttempt } = validateContext(context);
  if (
    !(diff instanceof Uint8Array) ||
    diff.byteLength === 0 ||
    diff.byteLength > 16 * 1024 * 1024
  ) {
    fail('E7_GITHUB_APPROVAL_DIFF_INVALID');
  }
  if (typeof fetchImpl !== 'function') fail('E7_GITHUB_APPROVAL_FETCH_UNAVAILABLE');
  const diffSha256 = sha256(diff);
  const requestUrl = `${API_ROOT}/repos/${context.repository}/actions/runs/${context.runId}/approvals`;
  let response;
  try {
    response = await fetchImpl(requestUrl, {
      method: 'GET',
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${context.token}`,
        'user-agent': 'async-checkout-demo-stage7-approval',
        'x-github-api-version': API_VERSION,
      },
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    fail('E7_GITHUB_APPROVAL_REQUEST_FAILED');
  }
  if (response?.status !== 200 || response.redirected === true) {
    fail('E7_GITHUB_APPROVAL_REQUEST_REJECTED');
  }
  const contentType = response.headers?.get?.('content-type')?.toLowerCase() ?? '';
  if (!contentType.startsWith('application/json')) fail('E7_GITHUB_APPROVAL_RESPONSE_INVALID');
  const responseText = await response.text();
  if (
    Buffer.byteLength(responseText) === 0 ||
    Buffer.byteLength(responseText) > MAX_RESPONSE_BYTES
  ) {
    fail('E7_GITHUB_APPROVAL_RESPONSE_INVALID');
  }
  let parsed;
  try {
    parsed = JSON.parse(responseText);
  } catch {
    fail('E7_GITHUB_APPROVAL_RESPONSE_INVALID');
  }
  const reviewerAlias = matchingReview({
    response: parsed,
    repository: context.repository,
    environment: context.environment,
    diffSha256,
  });
  const capturedAtUtc = now().toISOString();
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'GITHUB_ENVIRONMENT_APPROVAL',
    status: 'PASS',
    scope,
    repository: context.repository,
    candidateSha: context.candidateSha,
    releaseId: context.releaseId,
    runId: context.runId,
    runAttempt,
    environment: context.environment,
    reviewerAlias,
    reviewed: true,
    reviewState: 'approved',
    iamReviewAttested: true,
    iamReviewedDiffSha256: diffSha256,
    responseSha256: sha256(responseText),
    capturedAtUtc,
    externalRequests: 1,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return validateGithubEnvironmentApproval(result, {
    repository: context.repository,
    candidateSha: context.candidateSha,
    releaseId: context.releaseId,
    runId: context.runId,
    runAttempt,
    environment: context.environment,
    diffSha256,
  });
};

const writeEvidence = (filename, value) => {
  const target = checkedPath(filename, { mustExist: false });
  mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const temporary = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    });
    chmodSync(temporary, 0o600);
    renameSync(temporary, target);
    chmodSync(target, 0o600);
  } finally {
    rmSync(temporary, { force: true });
  }
};

const fixtureContext = (overrides = {}) => ({
  repository: REPOSITORY,
  githubRepository: REPOSITORY,
  candidateSha: 'a'.repeat(40),
  githubSha: 'a'.repeat(40),
  releaseId: 'rel-20260817-1200-aaaaaaa',
  runId: '12345678901',
  githubRunId: '12345678901',
  runAttempt: '2',
  githubRunAttempt: '2',
  environment: 'assessment-release',
  githubEnvironment: 'assessment-release',
  githubActions: 'true',
  githubEventName: 'workflow_dispatch',
  githubRef: 'refs/heads/master',
  token: 'github-token-fixture-value',
  ...overrides,
});

const fixtureReview = ({ environment = 'assessment-release', state = 'approved', diff }) => ({
  state,
  comment: `STAGE7_IAM_DIFF_REVIEWED_SHA256=${sha256(diff)}`,
  environments: [
    {
      id: 161088068,
      name: environment,
      url: expectedEnvironmentUrl(REPOSITORY, environment),
    },
  ],
  user: { id: 1, login: 'release-reviewer', type: 'User' },
});

const fakeFetch = (body, inspectRequest) => async (url, options) => {
  inspectRequest?.(url, options);
  return {
    status: 200,
    redirected: false,
    headers: { get: (name) => (name.toLowerCase() === 'content-type' ? 'application/json' : null) },
    text: async () => JSON.stringify(body),
  };
};

export const selfTestGithubEnvironmentApproval = async () => {
  const diff = new TextEncoder().encode('exact reviewed infrastructure diff\n');
  const context = fixtureContext();
  let calls = 0;
  const valid = await captureGithubEnvironmentApproval({
    context,
    diff,
    fetchImpl: fakeFetch([fixtureReview({ diff })], (url, options) => {
      calls += 1;
      assert.equal(url, `${API_ROOT}/repos/${REPOSITORY}/actions/runs/${context.runId}/approvals`);
      assert.equal(options.method, 'GET');
      assert.equal(options.headers.authorization, `Bearer ${context.token}`);
    }),
    now: () => new Date('2026-08-17T17:00:00.000Z'),
  });
  assert.equal(calls, 1);
  assert.equal(valid.externalRequests, 1);
  assert.equal(valid.reviewerAlias, 'release-reviewer');

  const expectReject = async ({ nextContext = context, reviews, code }) => {
    let rejectedCalls = 0;
    await assert.rejects(
      captureGithubEnvironmentApproval({
        context: nextContext,
        diff,
        fetchImpl: fakeFetch(reviews, () => {
          rejectedCalls += 1;
        }),
        now: () => new Date('2026-08-17T17:00:00.000Z'),
      }),
      (error) => error.code === code,
    );
    assert.ok(rejectedCalls <= 1);
  };
  await expectReject({
    reviews: [fixtureReview({ environment: 'assessment-prerelease', diff })],
    code: 'E7_GITHUB_APPROVAL_REVIEW_AMBIGUOUS',
  });
  await expectReject({
    reviews: [fixtureReview({ state: 'rejected', diff })],
    code: 'E7_GITHUB_APPROVAL_STATE_INVALID',
  });
  await expectReject({
    nextContext: fixtureContext({ githubRunId: '99999999999' }),
    reviews: [fixtureReview({ diff })],
    code: 'E7_GITHUB_APPROVAL_CONTEXT_INVALID',
  });
  await expectReject({
    reviews: [fixtureReview({ diff }), fixtureReview({ diff })],
    code: 'E7_GITHUB_APPROVAL_REVIEW_AMBIGUOUS',
  });
  const unrelatedHistory = fixtureReview({ diff });
  unrelatedHistory.comment = 'Earlier approval before the reviewed diff existed.';
  const exactAfterUnrelatedHistory = await captureGithubEnvironmentApproval({
    context,
    diff,
    fetchImpl: fakeFetch([unrelatedHistory, fixtureReview({ diff })]),
    now: () => new Date('2026-08-17T17:00:00.000Z'),
  });
  assert.equal(exactAfterUnrelatedHistory.status, 'PASS');
  assert.equal(exactAfterUnrelatedHistory.iamReviewedDiffSha256, sha256(diff));
  const wrongComment = fixtureReview({ diff });
  wrongComment.comment = `STAGE7_IAM_DIFF_REVIEWED_SHA256=${'b'.repeat(64)}`;
  await expectReject({
    reviews: [wrongComment],
    code: 'E7_GITHUB_APPROVAL_IAM_ATTESTATION_INVALID',
  });
  process.stdout.write('stage-7 GitHub environment approval self-test: PASS (0 external calls)\n');
};

const main = async () => {
  const arguments_ = normalizePnpmScriptArguments(process.argv.slice(2), { separatorIndex: 0 });
  if (arguments_[0] === '--self-test') {
    if (arguments_.length !== 1) fail('E7_GITHUB_APPROVAL_ARGUMENT_SET_INVALID');
    await selfTestGithubEnvironmentApproval();
    return;
  }
  const flags = parseFlags(arguments_);
  const diffFilename = checkedPath(flags.diff);
  const result = await captureGithubEnvironmentApproval({
    context: {
      repository: flags.repository,
      githubRepository: process.env.GITHUB_REPOSITORY,
      candidateSha: flags['candidate-sha'],
      githubSha: process.env.GITHUB_SHA,
      releaseId: flags['release-id'],
      runId: flags['run-id'],
      githubRunId: process.env.GITHUB_RUN_ID,
      runAttempt: flags['run-attempt'],
      githubRunAttempt: process.env.GITHUB_RUN_ATTEMPT,
      environment: flags.environment,
      githubEnvironment: process.env.STAGE7_PROTECTED_ENVIRONMENT,
      githubActions: process.env.GITHUB_ACTIONS,
      githubEventName: process.env.GITHUB_EVENT_NAME,
      githubRef: process.env.GITHUB_REF,
      token: process.env.GITHUB_TOKEN,
    },
    diff: readFileSync(diffFilename),
  });
  writeEvidence(flags.evidence, result);
  process.stdout.write(
    `${JSON.stringify({ status: result.status, reviewerAlias: result.reviewerAlias, environment: result.environment, runId: result.runId, runAttempt: result.runAttempt, externalRequests: result.externalRequests })}\n`,
  );
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code =
      error instanceof GithubEnvironmentApprovalError
        ? error.code
        : 'E7_GITHUB_APPROVAL_UNEXPECTED_FAILURE';
    process.stderr.write(`stage-7 GitHub environment approval: ${code}\n`);
    process.exitCode = 1;
  });
}
