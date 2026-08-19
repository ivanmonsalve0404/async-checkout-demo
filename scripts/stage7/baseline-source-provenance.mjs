#!/usr/bin/env node

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { existsSync, lstatSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { assertSanitizedArtifactText } from '../stage6/lib/artifact-sanitizer.mjs';
import {
  Stage7BaselineError,
  validateBaselineSourceProvenance,
  validatePreviousReleaseBundle,
} from './baseline-establishment.mjs';
import { objectSha256, workspaceRoot } from './core.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const WORKFLOW_PATH = '.github/workflows/baseline.yml';
const API_ROOT = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const POSITIVE_INTEGER = /^[1-9][0-9]{0,19}$/u;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_PAGES = 100;

export class BaselineSourceProvenanceError extends Error {
  constructor(code) {
    super(code);
    this.name = 'BaselineSourceProvenanceError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new BaselineSourceProvenanceError(code);
};

const checkedPath = (candidate, { mustExist = true, directory = false } = {}) => {
  if (typeof candidate !== 'string' || candidate.length === 0)
    fail('E7_BASELINE_SOURCE_PATH_INVALID');
  const absolute = path.resolve(candidate);
  const relative = path.relative(workspaceRoot, absolute);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('E7_BASELINE_SOURCE_PATH_OUTSIDE_WORKSPACE');
  }
  let current = workspaceRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) break;
    if (lstatSync(current).isSymbolicLink()) fail('E7_BASELINE_SOURCE_SYMLINK_FORBIDDEN');
  }
  if (mustExist) {
    const stat = lstatSync(absolute);
    if (directory ? !stat.isDirectory() : !stat.isFile()) {
      fail('E7_BASELINE_SOURCE_PATH_INVALID');
    }
  }
  return absolute;
};

const writeEvidence = (filename, value) => {
  const target = checkedPath(filename, { mustExist: false });
  if (existsSync(target)) fail('E7_BASELINE_SOURCE_OUTPUT_EXISTS');
  const source = `${JSON.stringify(value, null, 2)}\n`;
  assertSanitizedArtifactText('stage7-baseline-source-provenance.json', source);
  mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const temporary = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, source, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    renameSync(temporary, target);
  } finally {
    rmSync(temporary, { force: true });
  }
};

const sha256 = (value) => createHash('sha256').update(value).digest('hex');

const fetchJson = async ({ url, token, fetcher }) => {
  let response;
  try {
    response = await fetcher(url, {
      method: 'GET',
      redirect: 'error',
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': API_VERSION,
      },
    });
  } catch {
    fail('E7_BASELINE_SOURCE_GITHUB_REQUEST_FAILED');
  }
  if (response.status !== 200) fail('E7_BASELINE_SOURCE_GITHUB_STATUS_INVALID');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length < 2 || bytes.length > MAX_RESPONSE_BYTES) {
    fail('E7_BASELINE_SOURCE_GITHUB_RESPONSE_SIZE_INVALID');
  }
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('E7_BASELINE_SOURCE_GITHUB_RESPONSE_INVALID');
  }
};

const createEvidence = ({
  run,
  artifacts,
  pages,
  bundle,
  repository,
  runId,
  artifactId,
  artifactDigest,
  now,
}) => {
  const matching = artifacts.filter(({ name }) => name === 'stage7-previous-release');
  const artifact = matching[0];
  if (
    run?.id !== Number(runId) ||
    run?.repository?.full_name !== repository ||
    run?.head_repository?.full_name !== repository ||
    run?.event !== 'workflow_dispatch' ||
    run?.head_branch !== 'master' ||
    run?.head_sha !== bundle.capture.baseline.candidateSha ||
    run?.status !== 'completed' ||
    run?.conclusion !== 'success' ||
    run?.run_attempt !== bundle.index.sourceRunAttempt ||
    run?.path !== WORKFLOW_PATH ||
    matching.length !== 1 ||
    artifact?.id !== Number(artifactId) ||
    artifact?.name !== bundle.index.artifactName ||
    artifact?.expired !== false ||
    artifact?.digest !== artifactDigest ||
    artifact?.workflow_run?.id !== Number(runId) ||
    bundle.index.sourceRunId !== String(runId) ||
    bundle.index.sourceWorkflowPath !== WORKFLOW_PATH ||
    bundle.index.sourceEvent !== run.event ||
    bundle.index.sourceRef !== `refs/heads/${run.head_branch}` ||
    bundle.index.sourceHeadSha !== run.head_sha
  ) {
    fail('E7_BASELINE_SOURCE_GITHUB_IDENTITY_INVALID');
  }
  const responseSummary = {
    run: {
      id: run.id,
      runAttempt: run.run_attempt,
      path: run.path,
      event: run.event,
      headBranch: run.head_branch,
      headSha: run.head_sha,
      conclusion: run.conclusion,
    },
    artifact: {
      id: artifact.id,
      name: artifact.name,
      digest: artifact.digest,
      expired: artifact.expired,
    },
  };
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'BASELINE_SOURCE_ARTIFACT_PROVENANCE',
    status: 'PASS',
    repository,
    workflowPath: run.path,
    event: run.event,
    ref: `refs/heads/${run.head_branch}`,
    headSha: run.head_sha,
    runId: String(run.id),
    runAttempt: run.run_attempt,
    conclusion: run.conclusion,
    artifactName: artifact.name,
    artifactId: artifact.id,
    artifactDigest: artifact.digest,
    artifactExpired: artifact.expired,
    bundleSha256: bundle.index.bundleSha256,
    responseSha256: sha256(JSON.stringify(responseSummary)),
    capturedAtUtc: now.toISOString(),
    externalRequests: pages + 1,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const value = { ...body, provenanceSha256: objectSha256(body) };
  return validateBaselineSourceProvenance(value, {
    bundleIndex: bundle.index,
    capture: bundle.capture,
    expectedArtifactId: artifactId,
    expectedArtifactDigest: artifactDigest,
  });
};

export const captureBaselineSourceProvenance = async ({
  repository,
  runId,
  artifactId,
  artifactDigest,
  bundleDirectory,
  bundleSha256,
  token,
  now = new Date(),
  fetcher = fetch,
}) => {
  if (
    repository !== REPOSITORY ||
    !POSITIVE_INTEGER.test(String(runId)) ||
    !POSITIVE_INTEGER.test(String(artifactId)) ||
    !SHA256_DIGEST.test(artifactDigest ?? '') ||
    !/^[0-9a-f]{64}$/u.test(bundleSha256 ?? '') ||
    typeof token !== 'string' ||
    token.length < 20 ||
    token.length > 4096 ||
    /\s/u.test(token) ||
    Number.isNaN(now.getTime())
  ) {
    fail('E7_BASELINE_SOURCE_INPUT_INVALID');
  }
  const bundle = validatePreviousReleaseBundle({
    directory: checkedPath(bundleDirectory, { directory: true }),
    expectedBundleSha256: bundleSha256,
    expectedRunId: runId,
  });
  const run = await fetchJson({
    url: `${API_ROOT}/repos/${repository}/actions/runs/${runId}`,
    token,
    fetcher,
  });
  const artifacts = [];
  let totalCount;
  let pages = 0;
  do {
    pages += 1;
    if (pages > MAX_PAGES) fail('E7_BASELINE_SOURCE_GITHUB_PAGINATION_INVALID');
    const response = await fetchJson({
      url: `${API_ROOT}/repos/${repository}/actions/runs/${runId}/artifacts?per_page=100&page=${pages}`,
      token,
      fetcher,
    });
    if (
      !Number.isSafeInteger(response?.total_count) ||
      response.total_count < 1 ||
      response.total_count > MAX_PAGES * 100 ||
      !Array.isArray(response.artifacts) ||
      response.artifacts.length > 100 ||
      (totalCount !== undefined && totalCount !== response.total_count)
    ) {
      fail('E7_BASELINE_SOURCE_GITHUB_ARTIFACTS_INVALID');
    }
    totalCount = response.total_count;
    artifacts.push(...response.artifacts);
    if (response.artifacts.length === 0 && artifacts.length < totalCount) {
      fail('E7_BASELINE_SOURCE_GITHUB_PAGINATION_INVALID');
    }
  } while (artifacts.length < totalCount);
  if (artifacts.length !== totalCount) fail('E7_BASELINE_SOURCE_GITHUB_PAGINATION_INVALID');
  return createEvidence({
    run,
    artifacts,
    pages,
    bundle,
    repository,
    runId,
    artifactId,
    artifactDigest,
    now,
  });
};

const response = (value) => ({
  status: 200,
  arrayBuffer: async () => Buffer.from(JSON.stringify(value)),
});

export const selfTestBaselineSourceProvenance = async () => {
  // The network loop is exercised with fixed in-memory GitHub responses. The
  // bundle contract itself is covered by baseline-establishment self-test.
  const run = {
    id: 123,
    repository: { full_name: REPOSITORY },
    head_repository: { full_name: REPOSITORY },
    event: 'workflow_dispatch',
    head_branch: 'master',
    head_sha: 'a'.repeat(40),
    status: 'completed',
    conclusion: 'success',
    run_attempt: 1,
    path: WORKFLOW_PATH,
  };
  const artifact = {
    id: 456,
    name: 'stage7-previous-release',
    expired: false,
    digest: `sha256:${'b'.repeat(64)}`,
    workflow_run: { id: 123 },
  };
  const calls = [];
  const fetcher = async (url) => {
    calls.push(url);
    return response(url.includes('/artifacts?') ? { total_count: 1, artifacts: [artifact] } : run);
  };
  assert.deepEqual(
    await fetchJson({ url: 'https://api.github.test/run', token: 'x'.repeat(32), fetcher }),
    run,
  );
  assert.equal(calls.length, 1);
  assert.throws(
    () =>
      createEvidence({
        run: { ...run, path: '.github/workflows/release.yml' },
        artifacts: [artifact],
        pages: 1,
        bundle: {
          index: {
            artifactName: artifact.name,
            sourceRunId: '123',
            sourceRunAttempt: 1,
            sourceWorkflowPath: WORKFLOW_PATH,
            sourceEvent: 'workflow_dispatch',
            sourceRef: 'refs/heads/master',
            sourceHeadSha: run.head_sha,
            bundleSha256: 'c'.repeat(64),
          },
          capture: { baseline: { candidateSha: run.head_sha } },
        },
        repository: REPOSITORY,
        runId: '123',
        artifactId: '456',
        artifactDigest: artifact.digest,
        now: new Date('2026-08-18T12:00:00.000Z'),
      }),
    BaselineSourceProvenanceError,
  );
  return { status: 'PASS', assertions: 3, externalRequests: 0, mutationsPerformed: 0 };
};

const parseFlags = (values) => {
  const flags = {};
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!/^--[a-z][a-z0-9-]*$/u.test(name ?? '') || !value || Object.hasOwn(flags, name.slice(2))) {
      fail('E7_BASELINE_SOURCE_ARGUMENT_INVALID');
    }
    flags[name.slice(2)] = value;
  }
  return flags;
};

const main = async () => {
  if (process.argv[2] === 'self-test') {
    if (process.argv.length !== 3) fail('E7_BASELINE_SOURCE_ARGUMENT_INVALID');
    process.stdout.write(`${JSON.stringify(await selfTestBaselineSourceProvenance())}\n`);
    return;
  }
  if (process.argv[2] !== 'capture') fail('E7_BASELINE_SOURCE_COMMAND_INVALID');
  const flags = parseFlags(process.argv.slice(3));
  const expected = [
    'repository',
    'run-id',
    'artifact-id',
    'artifact-digest',
    'bundle-directory',
    'bundle-sha256',
    'output',
  ];
  if (Object.keys(flags).toSorted().join('\0') !== expected.toSorted().join('\0')) {
    fail('E7_BASELINE_SOURCE_ARGUMENT_INVALID');
  }
  if (
    process.env.GITHUB_ACTIONS !== 'true' ||
    process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    process.env.GITHUB_REPOSITORY !== flags.repository
  ) {
    fail('E7_BASELINE_SOURCE_CONTEXT_INVALID');
  }
  const evidence = await captureBaselineSourceProvenance({
    repository: flags.repository,
    runId: flags['run-id'],
    artifactId: flags['artifact-id'],
    artifactDigest: flags['artifact-digest'],
    bundleDirectory: flags['bundle-directory'],
    bundleSha256: flags['bundle-sha256'],
    token: process.env.GITHUB_TOKEN,
  });
  writeEvidence(flags.output, evidence);
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code =
      error instanceof BaselineSourceProvenanceError || error instanceof Stage7BaselineError
        ? error.code
        : 'E7_BASELINE_SOURCE_UNEXPECTED';
    process.stderr.write(`stage-7 baseline source: ${code}\n`);
    process.exitCode = 1;
  });
}
