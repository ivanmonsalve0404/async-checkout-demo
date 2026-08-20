import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import path from 'node:path';

import { parseStrictJsonSource, validateJsonSchemaSubset } from '../strict-json.mjs';

export const SANDBOX_ORIGIN = 'https://sandbox.wompi.co';
export const SANDBOX_HOST = 'sandbox.wompi.co';
export const EXPECTED_EXTERNAL_REQUESTS = 8;

const RUN_ID = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const COMMIT_SHA = /^[0-9a-f]{40}$/u;
const SAFE_ALIAS = /^[a-z][a-z0-9-]{2,31}$/u;
const UTC = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;

export class SandboxAuthorizationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SandboxAuthorizationError';
    this.code = code;
  }
}

export const failAuthorization = (code) => {
  throw new SandboxAuthorizationError(code);
};
export const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const clone = (value) => JSON.parse(JSON.stringify(value));

const validUtc = (value) => {
  if (typeof value !== 'string' || !UTC.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
};

export const candidateState = (repositoryRoot) => {
  const git = (...arguments_) =>
    execFileSync('git', arguments_, {
      cwd: repositoryRoot,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  const commitSha = git('rev-parse', 'HEAD');
  if (!COMMIT_SHA.test(commitSha)) failAuthorization('CANDIDATE_SHA_INVALID');
  if (git('status', '--porcelain').length !== 0) {
    failAuthorization('CANDIDATE_WORKTREE_NOT_CLEAN');
  }
  return { commitSha };
};

const localRegularFile = (sourcePath) => {
  if (
    typeof sourcePath !== 'string' ||
    sourcePath.length === 0 ||
    sourcePath.trim() !== sourcePath ||
    !path.isAbsolute(sourcePath) ||
    /^(?:\\\\|\/\/|\\\\[.?]\\)/u.test(sourcePath)
  ) {
    failAuthorization('AUTHORIZATION_PATH_INVALID');
  }
  let stats;
  try {
    stats = lstatSync(sourcePath);
  } catch {
    failAuthorization('AUTHORIZATION_FILE_UNAVAILABLE');
  }
  if (!stats.isFile() || stats.isSymbolicLink() || stats.size < 2 || stats.size > 131_072) {
    failAuthorization('AUTHORIZATION_FILE_INVALID');
  }
  const resolved = realpathSync(sourcePath);
  if (resolved !== path.resolve(sourcePath)) {
    failAuthorization('AUTHORIZATION_PATH_NON_CANONICAL');
  }
  return { resolved, source: readFileSync(resolved) };
};

export const validateAuthorizationObject = (authorization, execution) => {
  if (!validateJsonSchemaSubset(authorization, execution.schema)) {
    failAuthorization('AUTHORIZATION_SCHEMA_INVALID');
  }
  if (
    authorization.commitSha !== execution.commitSha ||
    !RUN_ID.test(authorization.runId) ||
    !SAFE_ALIAS.test(authorization.reviewerAlias)
  ) {
    failAuthorization('AUTHORIZATION_CANDIDATE_MISMATCH');
  }
  const expectedHostSha256 = sha256(SANDBOX_HOST);
  if (
    authorization.target.hostSha256 !== expectedHostSha256 ||
    authorization.authorization.approvedTargetSha256 !== expectedHostSha256
  ) {
    failAuthorization('AUTHORIZATION_TARGET_MISMATCH');
  }
  const { approvedAtUtc, expiresAtUtc, maxRequests } = authorization.authorization;
  if (!validUtc(approvedAtUtc) || !validUtc(expiresAtUtc)) {
    failAuthorization('AUTHORIZATION_TIME_INVALID');
  }
  const approvedAt = Date.parse(approvedAtUtc);
  const expiresAt = Date.parse(expiresAtUtc);
  const now = execution.now.getTime();
  if (approvedAt > now || expiresAt <= now || approvedAt >= expiresAt) {
    failAuthorization('AUTHORIZATION_NOT_ACTIVE');
  }
  if (maxRequests < EXPECTED_EXTERNAL_REQUESTS) {
    failAuthorization('AUTHORIZATION_REQUEST_BUDGET_TOO_SMALL');
  }
  return authorization;
};

export const loadAuthorizationContext = ({
  repositoryRoot,
  schemaPath,
  sourcePath,
  now = new Date(),
  expectedCommitSha,
}) => {
  const state = candidateState(repositoryRoot);
  if (expectedCommitSha !== undefined && state.commitSha !== expectedCommitSha) {
    failAuthorization('CANDIDATE_CHANGED_DURING_RUN');
  }
  const file = localRegularFile(sourcePath);
  const schema = parseStrictJsonSource(readFileSync(schemaPath), { scanForbiddenData: false });
  const authorization = validateAuthorizationObject(parseStrictJsonSource(file.source), {
    schema,
    commitSha: state.commitSha,
    now,
  });
  return {
    authorization,
    commitSha: state.commitSha,
    sourcePath: file.resolved,
    sourceSha256: sha256(file.source),
    repositoryRoot,
    schemaPath,
  };
};

export const revalidateAuthorizationContext = (context, now = new Date()) => {
  const current = loadAuthorizationContext({
    repositoryRoot: context.repositoryRoot,
    schemaPath: context.schemaPath,
    sourcePath: context.sourcePath,
    now,
    expectedCommitSha: context.commitSha,
  });
  if (current.sourceSha256 !== context.sourceSha256) {
    failAuthorization('AUTHORIZATION_CHANGED_DURING_RUN');
  }
  return current;
};

export const validateRequiredEnvironment = (environment, authorization) => {
  const requireExact = (name, expected, failureCode) => {
    if (environment[name] !== expected) failAuthorization(failureCode);
  };
  requireExact('STAGE6_SANDBOX_EXECUTION', 'EXECUTE_AUTH02_ONCE', 'EXECUTION_NOT_ARMED');
  requireExact('STAGE6_SANDBOX_KILL_SWITCH', 'ARMED_AUTH02', 'KILL_SWITCH_OPEN');
  requireExact('STAGE6_SANDBOX_MUTATION_LIMIT', '1', 'MUTATION_LIMIT_INVALID');
  requireExact('STAGE6_SANDBOX_FIXTURE_AUTHORIZED', 'YES', 'FIXTURE_NOT_AUTHORIZED');
  requireExact('STAGE6_SANDBOX_ORIGIN', SANDBOX_ORIGIN, 'SANDBOX_ORIGIN_INVALID');
  if (!/^pub_test_[A-Za-z0-9_-]{8,128}$/u.test(environment.STAGE6_SANDBOX_PUBLIC_KEY ?? '')) {
    failAuthorization('SANDBOX_PUBLIC_KEY_INVALID');
  }
  if (!/^prv_test_[A-Za-z0-9_-]{8,128}$/u.test(environment.STAGE6_SANDBOX_PRIVATE_KEY ?? '')) {
    failAuthorization('SANDBOX_PRIVATE_KEY_INVALID');
  }
  if (
    !/^test_integrity_[A-Za-z0-9_-]{8,128}$/u.test(
      environment.STAGE6_SANDBOX_INTEGRITY_SECRET ?? '',
    )
  ) {
    failAuthorization('SANDBOX_INTEGRITY_SECRET_INVALID');
  }
  const cardNumber = (environment.STAGE6_SANDBOX_CARD_NUMBER ?? '').replace(/[^0-9]/gu, '');
  if (cardNumber.length !== 16 || sha256(cardNumber) !== authorization.fixture.cardNumberSha256) {
    failAuthorization('SANDBOX_CARD_FIXTURE_MISMATCH');
  }
  if (!/^\d{2}\/\d{2}$/u.test(environment.STAGE6_SANDBOX_CARD_EXPIRY ?? '')) {
    failAuthorization('SANDBOX_CARD_EXPIRY_INVALID');
  }
  if (!/^\d{3}$/u.test(environment.STAGE6_SANDBOX_CARD_CVC ?? '')) {
    failAuthorization('SANDBOX_CARD_CVC_INVALID');
  }
  if (!/^.{2,120}$/u.test(environment.STAGE6_SANDBOX_CARD_HOLDER ?? '')) {
    failAuthorization('SANDBOX_CARD_HOLDER_INVALID');
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(environment.STAGE6_SANDBOX_CUSTOMER_EMAIL ?? '')) {
    failAuthorization('SANDBOX_CUSTOMER_EMAIL_INVALID');
  }
};

export const selfTestAuthorizationPolicy = (schemaPath) => {
  const schema = parseStrictJsonSource(readFileSync(schemaPath), { scanForbiddenData: false });
  const hostSha256 = sha256(SANDBOX_HOST);
  const authorization = {
    schemaId: 'async-checkout-stage6-auth02-authorization',
    schemaVersion: 1,
    stage: 6,
    commitSha: 'a'.repeat(40),
    runId: 'e6-20260816t120000z-deadbeef',
    reviewerAlias: 'qa-reviewer',
    authorization: {
      id: 'AUTH-E6-02',
      status: 'APPROVED',
      scope: 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
      approvalSha256: 'b'.repeat(64),
      approvedTargetSha256: hostSha256,
      approvedAtUtc: '2026-08-16T11:00:00.123Z',
      expiresAtUtc: '2026-08-16T13:00:00.123Z',
      ownerAlias: 'appsec-owner',
      maxRequests: 8,
    },
    target: {
      classification: 'AUTHORIZED_PROVIDER_SANDBOX',
      environment: 'sandbox',
      hostSha256,
      allowlistVerified: true,
      production: false,
    },
    fixture: {
      classification: 'AUTHORIZED_PROVIDER_TEST_CARD',
      cardNumberSha256: 'c'.repeat(64),
      authorized: true,
      rawValueCaptured: false,
    },
    containsSensitiveData: false,
  };
  const active = validateAuthorizationObject(clone(authorization), {
    schema,
    commitSha: authorization.commitSha,
    now: new Date('2026-08-16T12:00:00.123Z'),
  });
  assert.equal(active.runId, authorization.runId);
  assert.throws(
    () =>
      validateAuthorizationObject(clone(authorization), {
        schema,
        commitSha: authorization.commitSha,
        now: new Date('2026-08-16T13:00:00.124Z'),
      }),
    /AUTHORIZATION_NOT_ACTIVE/u,
  );
  assert.throws(
    () =>
      validateAuthorizationObject(
        { ...clone(authorization), commitSha: 'd'.repeat(40) },
        {
          schema,
          commitSha: authorization.commitSha,
          now: new Date('2026-08-16T12:00:00.123Z'),
        },
      ),
    /AUTHORIZATION_CANDIDATE_MISMATCH/u,
  );
};
