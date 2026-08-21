#!/usr/bin/env node

import assert from 'node:assert/strict';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

export const GITHUB_OIDC_SUBJECT_CONTRACT_VERSION = 'stage7-github-oidc-subject/1';
export const GITHUB_OIDC_OWNER_LOGIN = 'ivanmonsalve0404';
export const GITHUB_OIDC_OWNER_ID = '192544565';
export const GITHUB_OIDC_REPOSITORY_NAME = 'async-checkout-demo';
export const GITHUB_OIDC_REPOSITORY_ID = '1335131225';
export const GITHUB_OIDC_REPOSITORY = `${GITHUB_OIDC_OWNER_LOGIN}/${GITHUB_OIDC_REPOSITORY_NAME}`;
export const GITHUB_OIDC_IMMUTABLE_REPOSITORY =
  `${GITHUB_OIDC_OWNER_LOGIN}@${GITHUB_OIDC_OWNER_ID}/` +
  `${GITHUB_OIDC_REPOSITORY_NAME}@${GITHUB_OIDC_REPOSITORY_ID}`;
export const STAGE7_GITHUB_OIDC_ENVIRONMENTS = Object.freeze([
  'assessment-prerelease',
  'assessment-prerelease-external',
  'assessment-prerelease-read',
  'assessment-release',
  'assessment-release-baseline',
  'assessment-release-read',
  'assessment-release-reconciliation-recovery',
  'assessment-release-recovery',
  'assessment-release-sandbox',
  'assessment-release-successor-post-success',
  'assessment-release-successor-publication-recovery',
]);
export const STAGE7_GITHUB_OIDC_REFS = Object.freeze(['refs/heads/master']);

const SUBJECT_PREFIX = `repo:${GITHUB_OIDC_IMMUTABLE_REPOSITORY}:`;
const ENVIRONMENT = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,253}[A-Za-z0-9])?$/u;
const BRANCH_REF = /^refs\/heads\/[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253}[A-Za-z0-9])?$/u;
const ENVIRONMENT_ALLOWLIST = new Set(STAGE7_GITHUB_OIDC_ENVIRONMENTS);
const REF_ALLOWLIST = new Set(STAGE7_GITHUB_OIDC_REFS);

export class GithubOidcSubjectContractError extends Error {
  constructor(code) {
    super(code);
    this.name = 'GithubOidcSubjectContractError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new GithubOidcSubjectContractError(code);
};

const exactToken = (value, pattern, code) => {
  if (typeof value !== 'string' || !pattern.test(value) || /[*?:]/u.test(value)) fail(code);
  return value;
};

export const githubOidcEnvironmentSubject = (environment) => {
  const normalized = exactToken(environment, ENVIRONMENT, 'E7_GITHUB_OIDC_ENVIRONMENT_INVALID');
  if (!ENVIRONMENT_ALLOWLIST.has(normalized)) fail('E7_GITHUB_OIDC_ENVIRONMENT_NOT_ALLOWLISTED');
  return `${SUBJECT_PREFIX}environment:${normalized}`;
};

export const githubOidcRefSubject = (ref) => {
  const normalized = exactToken(ref, BRANCH_REF, 'E7_GITHUB_OIDC_REF_INVALID');
  if (!REF_ALLOWLIST.has(normalized)) fail('E7_GITHUB_OIDC_REF_NOT_ALLOWLISTED');
  return `${SUBJECT_PREFIX}ref:${normalized}`;
};

export const assertGithubOidcEnvironmentSubject = (subject, environment) => {
  if (subject !== githubOidcEnvironmentSubject(environment)) {
    fail('E7_GITHUB_OIDC_ENVIRONMENT_SUBJECT_INVALID');
  }
  return subject;
};

export const assertGithubOidcRefSubject = (subject, ref) => {
  if (subject !== githubOidcRefSubject(ref)) fail('E7_GITHUB_OIDC_REF_SUBJECT_INVALID');
  return subject;
};

const expectCode = (operation, code) => {
  assert.throws(operation, (error) => error?.code === code);
};

export const selfTestGithubOidcSubjectContract = () => {
  const environment = 'assessment-release';
  const ref = 'refs/heads/master';
  const environmentSubject = githubOidcEnvironmentSubject(environment);
  const refSubject = githubOidcRefSubject(ref);

  assert.equal(
    environmentSubject,
    'repo:ivanmonsalve0404@192544565/async-checkout-demo@1335131225:' +
      'environment:assessment-release',
  );
  assert.equal(
    refSubject,
    'repo:ivanmonsalve0404@192544565/async-checkout-demo@1335131225:' + 'ref:refs/heads/master',
  );
  assert.equal(
    assertGithubOidcEnvironmentSubject(environmentSubject, environment),
    environmentSubject,
  );
  assert.equal(assertGithubOidcRefSubject(refSubject, ref), refSubject);

  const environmentMutations = [
    'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release',
    'repo:ivanmonsalve0404@1335131225/async-checkout-demo@192544565:' +
      'environment:assessment-release',
    'repo:ivanmonsalve0404@192544566/async-checkout-demo@1335131226:' +
      'environment:assessment-release',
    'repo:ivanmonsalve0404/async-checkout-demo@1335131225:' + 'environment:assessment-release',
    'repo:ivanmonsalve0404@192544565/async-checkout-demo:' + 'environment:assessment-release',
    refSubject,
  ];
  for (const mutation of environmentMutations) {
    expectCode(
      () => assertGithubOidcEnvironmentSubject(mutation, environment),
      'E7_GITHUB_OIDC_ENVIRONMENT_SUBJECT_INVALID',
    );
  }
  expectCode(
    () => assertGithubOidcRefSubject(environmentSubject, ref),
    'E7_GITHUB_OIDC_REF_SUBJECT_INVALID',
  );
  for (const invalidEnvironment of ['assessment-release:*', 'assessment-release:other', '']) {
    expectCode(
      () => githubOidcEnvironmentSubject(invalidEnvironment),
      'E7_GITHUB_OIDC_ENVIRONMENT_INVALID',
    );
  }
  expectCode(
    () => githubOidcEnvironmentSubject('assessment-release-other'),
    'E7_GITHUB_OIDC_ENVIRONMENT_NOT_ALLOWLISTED',
  );
  for (const invalidRef of ['refs/tags/v1', 'refs/heads/*', 'refs/heads/main:other', '']) {
    expectCode(() => githubOidcRefSubject(invalidRef), 'E7_GITHUB_OIDC_REF_INVALID');
  }
  expectCode(() => githubOidcRefSubject('refs/heads/main'), 'E7_GITHUB_OIDC_REF_NOT_ALLOWLISTED');
  assert.equal(STAGE7_GITHUB_OIDC_ENVIRONMENTS.length, 11);
  assert.equal(STAGE7_GITHUB_OIDC_REFS.length, 1);
  return 21;
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--self-test') {
    process.stderr.write('github OIDC subject contract: FAIL (expected --self-test)\n');
    process.exitCode = 1;
  } else {
    try {
      const canaries = selfTestGithubOidcSubjectContract();
      process.stdout.write(`github OIDC subject contract: PASS (${canaries} canaries)\n`);
    } catch (error) {
      const reason = error instanceof Error ? error.message : 'unexpected self-test failure';
      process.stderr.write(`github OIDC subject contract: FAIL (${reason})\n`);
      process.exitCode = 1;
    }
  }
}
