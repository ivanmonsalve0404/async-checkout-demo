#!/usr/bin/env node

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { assertSanitizedArtifactText } from '../stage6/lib/artifact-sanitizer.mjs';
import { assessStage6Manifest, objectSha256, readStrictJsonFile, workspaceRoot } from './core.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const WORKFLOW_PATH = '.github/workflows/ci.yml';
const ARTIFACT_NAME = 'verification-reports';
const API_ROOT = 'https://api.github.com';
const API_VERSION = '2026-03-10';
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const SHA256_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const POSITIVE_INTEGER = /^[1-9][0-9]{0,19}$/u;
const STAGE6_RUN_ID = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAX_PAGES = 100;

export class Stage6SourceProvenanceError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage6SourceProvenanceError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage6SourceProvenanceError(code);
};

const exactKeys = (value, keys) =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const fileSha256 = (filename) => sha256(readFileSync(filename));
const isoUtc = (value) => {
  if (typeof value !== 'string') return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
};

const checkedPath = (candidate, { mustExist = true } = {}) => {
  if (typeof candidate !== 'string' || candidate.length === 0) {
    fail('E7_STAGE6_SOURCE_PATH_INVALID');
  }
  const absolute = path.resolve(candidate);
  const relative = path.relative(workspaceRoot, absolute);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail('E7_STAGE6_SOURCE_PATH_OUTSIDE_WORKSPACE');
  }
  let current = workspaceRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) break;
    if (lstatSync(current).isSymbolicLink()) fail('E7_STAGE6_SOURCE_SYMLINK_FORBIDDEN');
  }
  if (mustExist && !lstatSync(absolute).isFile()) fail('E7_STAGE6_SOURCE_PATH_INVALID');
  return absolute;
};

const provenanceBody = (value) => {
  const body = { ...value };
  delete body.provenanceSha256;
  return body;
};
const responseSummary = (value) => ({
  run: {
    id: Number(value.runId),
    runAttempt: value.runAttempt,
    path: value.workflowPath,
    event: value.event,
    headBranch: value.ref?.replace(/^refs\/heads\//u, ''),
    headSha: value.headSha,
    conclusion: value.conclusion,
  },
  artifact: {
    id: value.artifactId,
    name: value.artifactName,
    digest: value.artifactDigest,
    expired: value.artifactExpired,
  },
});

export const validateStage6SourceProvenance = (
  value,
  {
    manifest,
    expectedCandidateSha,
    expectedRunId,
    expectedRunAttempt,
    expectedArtifactId,
    expectedArtifactDigest,
  } = {},
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'repository',
      'workflowPath',
      'event',
      'ref',
      'headSha',
      'runId',
      'runAttempt',
      'conclusion',
      'artifactName',
      'artifactId',
      'artifactDigest',
      'artifactExpired',
      'stage6ManifestSha256',
      'stage6InternalRunId',
      'stage6CandidateTreeSha',
      'responseSha256',
      'capturedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'provenanceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE6_SOURCE_ARTIFACT_PROVENANCE' ||
    value.status !== 'PASS' ||
    value.repository !== REPOSITORY ||
    value.workflowPath !== WORKFLOW_PATH ||
    value.event !== 'push' ||
    value.ref !== 'refs/heads/master' ||
    !SHA.test(value.headSha ?? '') ||
    !POSITIVE_INTEGER.test(value.runId ?? '') ||
    !Number.isSafeInteger(value.runAttempt) ||
    value.runAttempt < 1 ||
    value.conclusion !== 'success' ||
    value.artifactName !== ARTIFACT_NAME ||
    !Number.isSafeInteger(value.artifactId) ||
    value.artifactId < 1 ||
    !SHA256_DIGEST.test(value.artifactDigest ?? '') ||
    value.artifactExpired !== false ||
    !SHA256.test(value.stage6ManifestSha256 ?? '') ||
    !STAGE6_RUN_ID.test(value.stage6InternalRunId ?? '') ||
    !SHA.test(value.stage6CandidateTreeSha ?? '') ||
    !SHA256.test(value.responseSha256 ?? '') ||
    value.responseSha256 !== sha256(JSON.stringify(responseSummary(value))) ||
    !isoUtc(value.capturedAtUtc) ||
    !Number.isSafeInteger(value.externalRequests) ||
    value.externalRequests < 2 ||
    value.externalRequests > 101 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.provenanceSha256 !== objectSha256(provenanceBody(value)) ||
    (expectedCandidateSha !== undefined && value.headSha !== expectedCandidateSha) ||
    (expectedRunId !== undefined && value.runId !== String(expectedRunId)) ||
    (expectedRunAttempt !== undefined && value.runAttempt !== Number(expectedRunAttempt)) ||
    (expectedArtifactId !== undefined && value.artifactId !== Number(expectedArtifactId)) ||
    (expectedArtifactDigest !== undefined && value.artifactDigest !== expectedArtifactDigest)
  ) {
    fail('E7_STAGE6_SOURCE_PROVENANCE_INVALID');
  }
  if (manifest !== undefined) {
    const assessed = assessStage6Manifest(manifest);
    if (
      assessed.status !== 'PASS' ||
      assessed.runId !== value.stage6InternalRunId ||
      assessed.candidate.commitSha !== value.headSha ||
      assessed.candidate.treeSha !== value.stage6CandidateTreeSha
    ) {
      fail('E7_STAGE6_SOURCE_MANIFEST_BINDING_INVALID');
    }
  }
  return value;
};

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
    fail('E7_STAGE6_SOURCE_GITHUB_REQUEST_FAILED');
  }
  if (response.status !== 200) fail('E7_STAGE6_SOURCE_GITHUB_STATUS_INVALID');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length < 2 || bytes.length > MAX_RESPONSE_BYTES) {
    fail('E7_STAGE6_SOURCE_GITHUB_RESPONSE_SIZE_INVALID');
  }
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    fail('E7_STAGE6_SOURCE_GITHUB_RESPONSE_INVALID');
  }
};

const createEvidence = ({
  run,
  artifacts,
  pages,
  manifest,
  manifestSha256,
  candidateSha,
  repository,
  runId,
  artifactId,
  artifactDigest,
  now,
}) => {
  const stage6 = assessStage6Manifest(manifest);
  const matching = artifacts.filter(({ name }) => name === ARTIFACT_NAME);
  const artifact = matching[0];
  if (
    stage6.status !== 'PASS' ||
    run?.id !== Number(runId) ||
    run?.repository?.full_name !== repository ||
    run?.head_repository?.full_name !== repository ||
    run?.event !== 'push' ||
    run?.head_branch !== 'master' ||
    run?.head_sha !== candidateSha ||
    stage6.candidate.commitSha !== candidateSha ||
    run?.status !== 'completed' ||
    run?.conclusion !== 'success' ||
    !Number.isSafeInteger(run?.run_attempt) ||
    run.run_attempt < 1 ||
    run?.path !== WORKFLOW_PATH ||
    matching.length !== 1 ||
    artifact?.id !== Number(artifactId) ||
    artifact?.expired !== false ||
    artifact?.digest !== artifactDigest ||
    artifact?.workflow_run?.id !== Number(runId)
  ) {
    fail('E7_STAGE6_SOURCE_GITHUB_IDENTITY_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE6_SOURCE_ARTIFACT_PROVENANCE',
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
    stage6ManifestSha256: manifestSha256,
    stage6InternalRunId: stage6.runId,
    stage6CandidateTreeSha: stage6.candidate.treeSha,
    responseSha256: sha256(
      JSON.stringify({
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
      }),
    ),
    capturedAtUtc: now.toISOString(),
    externalRequests: pages + 1,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return validateStage6SourceProvenance(
    { ...body, provenanceSha256: objectSha256(body) },
    {
      manifest,
      expectedCandidateSha: candidateSha,
      expectedArtifactId: artifactId,
      expectedArtifactDigest: artifactDigest,
    },
  );
};

export const captureStage6SourceProvenance = async ({
  repository,
  runId,
  artifactId,
  artifactDigest,
  manifestFilename,
  manifestSha256,
  candidateSha,
  token,
  now = new Date(),
  fetcher = fetch,
}) => {
  const manifestPath = checkedPath(manifestFilename);
  if (
    repository !== REPOSITORY ||
    !POSITIVE_INTEGER.test(String(runId)) ||
    !POSITIVE_INTEGER.test(String(artifactId)) ||
    !SHA256_DIGEST.test(artifactDigest ?? '') ||
    !SHA256.test(manifestSha256 ?? '') ||
    fileSha256(manifestPath) !== manifestSha256 ||
    !SHA.test(candidateSha ?? '') ||
    typeof token !== 'string' ||
    token.length < 20 ||
    token.length > 4096 ||
    /\s/u.test(token) ||
    Number.isNaN(now.getTime())
  ) {
    fail('E7_STAGE6_SOURCE_INPUT_INVALID');
  }
  const manifest = readStrictJsonFile(manifestPath, {
    scanForbiddenData: false,
    validateConfig: false,
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
    if (pages > MAX_PAGES) fail('E7_STAGE6_SOURCE_GITHUB_PAGINATION_INVALID');
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
      fail('E7_STAGE6_SOURCE_GITHUB_ARTIFACTS_INVALID');
    }
    totalCount = response.total_count;
    artifacts.push(...response.artifacts);
    if (response.artifacts.length === 0 && artifacts.length < totalCount) {
      fail('E7_STAGE6_SOURCE_GITHUB_PAGINATION_INVALID');
    }
  } while (artifacts.length < totalCount);
  if (artifacts.length !== totalCount) fail('E7_STAGE6_SOURCE_GITHUB_PAGINATION_INVALID');
  return createEvidence({
    run,
    artifacts,
    pages,
    manifest,
    manifestSha256,
    candidateSha,
    repository,
    runId,
    artifactId,
    artifactDigest,
    now,
  });
};

const writeEvidence = (filename, value) => {
  const target = checkedPath(filename, { mustExist: false });
  if (existsSync(target)) fail('E7_STAGE6_SOURCE_OUTPUT_EXISTS');
  const source = `${JSON.stringify(value, null, 2)}\n`;
  assertSanitizedArtifactText('stage7-stage6-source-provenance.json', source);
  mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const temporary = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, source, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    renameSync(temporary, target);
  } finally {
    rmSync(temporary, { force: true });
  }
};

const response = (value) => ({
  status: 200,
  arrayBuffer: async () => Buffer.from(JSON.stringify(value)),
});

export const selfTestStage6SourceProvenance = async () => {
  const manifest = {
    stage: 6,
    runId: 'e6-20260818t120000z-0123abcd',
    status: 'PASS',
    candidate: { commitSha: 'a'.repeat(40), treeSha: 'b'.repeat(40) },
  };
  assert.throws(
    () =>
      createEvidence({
        run: { conclusion: 'failure' },
        artifacts: [],
        pages: 1,
        manifest,
        manifestSha256: 'c'.repeat(64),
        candidateSha: manifest.candidate.commitSha,
        repository: REPOSITORY,
        runId: '123',
        artifactId: '456',
        artifactDigest: `sha256:${'d'.repeat(64)}`,
        now: new Date('2026-08-18T12:00:00.000Z'),
      }),
    Stage6SourceProvenanceError,
  );
  const fetched = await fetchJson({
    url: 'https://api.github.test/run',
    token: 'x'.repeat(32),
    fetcher: async () => response({ status: 'completed' }),
  });
  assert.equal(fetched.status, 'completed');
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE6_SOURCE_ARTIFACT_PROVENANCE',
    status: 'PASS',
    repository: REPOSITORY,
    workflowPath: WORKFLOW_PATH,
    event: 'push',
    ref: 'refs/heads/master',
    headSha: 'a'.repeat(40),
    runId: '123',
    runAttempt: 1,
    conclusion: 'success',
    artifactName: ARTIFACT_NAME,
    artifactId: 456,
    artifactDigest: `sha256:${'d'.repeat(64)}`,
    artifactExpired: false,
    stage6ManifestSha256: 'c'.repeat(64),
    stage6InternalRunId: manifest.runId,
    stage6CandidateTreeSha: manifest.candidate.treeSha,
    responseSha256: '',
    capturedAtUtc: '2026-08-18T12:00:00.000Z',
    externalRequests: 2,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  body.responseSha256 = sha256(JSON.stringify(responseSummary(body)));
  const evidence = {
    ...body,
    provenanceSha256: objectSha256(body),
  };
  assert.equal(
    validateStage6SourceProvenance(evidence, {
      expectedRunId: '123',
      expectedRunAttempt: 1,
      expectedArtifactId: 456,
      expectedArtifactDigest: body.artifactDigest,
    }),
    evidence,
  );
  for (const [field, replacement] of [
    ['runId', '124'],
    ['runAttempt', 2],
    ['artifactId', 457],
    ['artifactDigest', `sha256:${'e'.repeat(64)}`],
  ]) {
    const tamperedBody = { ...body, [field]: replacement };
    assert.throws(
      () =>
        validateStage6SourceProvenance({
          ...tamperedBody,
          provenanceSha256: objectSha256(tamperedBody),
        }),
      Stage6SourceProvenanceError,
    );
  }
  return { status: 'PASS', assertions: 7, externalRequests: 0, mutationsPerformed: 0 };
};

const parseFlags = (values) => {
  const flags = {};
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!/^--[a-z][a-z0-9-]*$/u.test(name ?? '') || !value || Object.hasOwn(flags, name.slice(2))) {
      fail('E7_STAGE6_SOURCE_ARGUMENT_INVALID');
    }
    flags[name.slice(2)] = value;
  }
  return flags;
};

const main = async () => {
  if (process.argv[2] === 'self-test') {
    if (process.argv.length !== 3) fail('E7_STAGE6_SOURCE_ARGUMENT_INVALID');
    process.stdout.write(`${JSON.stringify(await selfTestStage6SourceProvenance())}\n`);
    return;
  }
  if (process.argv[2] !== 'capture') fail('E7_STAGE6_SOURCE_COMMAND_INVALID');
  const flags = parseFlags(process.argv.slice(3));
  const expected = [
    'repository',
    'run-id',
    'artifact-id',
    'artifact-digest',
    'manifest',
    'manifest-sha256',
    'candidate-sha',
    'output',
  ];
  if (Object.keys(flags).toSorted().join('\0') !== expected.toSorted().join('\0')) {
    fail('E7_STAGE6_SOURCE_ARGUMENT_INVALID');
  }
  if (
    process.env.GITHUB_ACTIONS !== 'true' ||
    process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    process.env.GITHUB_REPOSITORY !== flags.repository
  ) {
    fail('E7_STAGE6_SOURCE_CONTEXT_INVALID');
  }
  const evidence = await captureStage6SourceProvenance({
    repository: flags.repository,
    runId: flags['run-id'],
    artifactId: flags['artifact-id'],
    artifactDigest: flags['artifact-digest'],
    manifestFilename: flags.manifest,
    manifestSha256: flags['manifest-sha256'],
    candidateSha: flags['candidate-sha'],
    token: process.env.GITHUB_TOKEN,
  });
  writeEvidence(flags.output, evidence);
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code =
      error instanceof Stage6SourceProvenanceError ? error.code : 'E7_STAGE6_SOURCE_UNEXPECTED';
    process.stderr.write(`stage-7 Stage 6 source: ${code}\n`);
    process.exitCode = 1;
  });
}
