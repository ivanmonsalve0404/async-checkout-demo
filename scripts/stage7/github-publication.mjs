#!/usr/bin/env node

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
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

import {
  assertSanitizedArtifactText,
  serializeSanitizedEvidence,
} from '../stage6/lib/artifact-sanitizer.mjs';
import { normalizePnpmScriptArguments } from './cli-arguments.mjs';
import { objectSha256 } from './core.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const API_ROOT = 'https://api.github.com';
const UPLOAD_ROOT = 'https://uploads.github.com';
const API_VERSION = '2026-03-10';
const ASSET_NAME = 'candidate-manifest.json';
const MAX_JSON_BYTES = 4 * 1024 * 1024;
const MAX_ASSET_BYTES = 8 * 1024 * 1024;
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const workspaceRoot = path.resolve(fileURLToPath(new URL('../..', import.meta.url)));

export class GithubPublicationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'GithubPublicationError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new GithubPublicationError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const normalizeText = (value) => String(value).replace(/\r\n?/gu, '\n');
const isPrereleaseTag = (releaseTag) => /-rc\.[1-9][0-9]*$/u.test(releaseTag);

const publicationUrlsAreExact = (urls) => {
  if (!exactKeys(urls, ['application', 'api', 'docs', 'health', 'repository'])) return false;
  let application;
  try {
    application = new URL(urls.application);
  } catch {
    return false;
  }
  return (
    application.protocol === 'https:' &&
    !application.username &&
    !application.password &&
    !application.search &&
    !application.hash &&
    application.origin === urls.application &&
    urls.api === `${application.origin}/api` &&
    urls.docs === `${application.origin}/api/docs` &&
    urls.health === `${application.origin}/api/health/ready` &&
    urls.repository === `https://github.com/${REPOSITORY}`
  );
};

const checkedFile = (candidate) => {
  if (typeof candidate !== 'string' || candidate.length === 0) {
    fail('E7_GITHUB_PUBLICATION_PATH_INVALID');
  }
  const absolute = path.resolve(candidate);
  const relative = path.relative(workspaceRoot, absolute);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    fail('E7_GITHUB_PUBLICATION_PATH_OUTSIDE_WORKSPACE');
  }
  let current = workspaceRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    const stat = lstatSync(current);
    if (stat.isSymbolicLink()) fail('E7_GITHUB_PUBLICATION_SYMLINK_FORBIDDEN');
  }
  if (
    !lstatSync(absolute).isFile() ||
    !realpathSync(absolute).startsWith(`${workspaceRoot}${path.sep}`)
  ) {
    fail('E7_GITHUB_PUBLICATION_PATH_INVALID');
  }
  return absolute;
};

const checkedOutput = (candidate) => {
  if (typeof candidate !== 'string' || candidate.length === 0) {
    fail('E7_GITHUB_PUBLICATION_PATH_INVALID');
  }
  const absolute = path.resolve(candidate);
  const relative = path.relative(workspaceRoot, absolute);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative) ||
    path.extname(absolute) !== '.json'
  ) {
    fail('E7_GITHUB_PUBLICATION_PATH_OUTSIDE_WORKSPACE');
  }
  let current = workspaceRoot;
  for (const segment of path.dirname(relative).split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    try {
      const stat = lstatSync(current);
      if (stat.isSymbolicLink() || !stat.isDirectory()) {
        fail('E7_GITHUB_PUBLICATION_SYMLINK_FORBIDDEN');
      }
    } catch (error) {
      if (error instanceof GithubPublicationError) throw error;
      if (error?.code === 'ENOENT') break;
      fail('E7_GITHUB_PUBLICATION_PATH_INVALID');
    }
  }
  try {
    if (lstatSync(absolute).isSymbolicLink()) fail('E7_GITHUB_PUBLICATION_SYMLINK_FORBIDDEN');
  } catch (error) {
    if (error instanceof GithubPublicationError) throw error;
    if (error?.code !== 'ENOENT') fail('E7_GITHUB_PUBLICATION_PATH_INVALID');
  }
  return absolute;
};

const parseFlags = (values) => {
  const flags = {};
  for (let index = 0; index < values.length; index += 2) {
    const name = values[index];
    const value = values[index + 1];
    if (!name?.startsWith('--') || value === undefined || value.startsWith('--')) {
      fail('E7_GITHUB_PUBLICATION_ARGUMENT_SET_INVALID');
    }
    const key = name.slice(2);
    if (Object.hasOwn(flags, key)) fail('E7_GITHUB_PUBLICATION_ARGUMENT_SET_INVALID');
    flags[key] = value;
  }
  if (Object.keys(flags).sort().join('\0') !== ['plan', 'result'].sort().join('\0')) {
    fail('E7_GITHUB_PUBLICATION_ARGUMENT_SET_INVALID');
  }
  return flags;
};

const validatePlan = (plan) => {
  if (
    !exactKeys(plan, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'repository',
      'branch',
      'readmeGitBlobSha',
      'urls',
      'files',
      'release',
      'publicationOrder',
      'retryPolicy',
      'externalWritesPlanned',
      'externalWritesPerformed',
      'containsSensitiveData',
    ]) ||
    plan.schemaVersion !== 1 ||
    plan.stage !== 7 ||
    plan.kind !== 'PUBLICATION_PLAN' ||
    plan.status !== 'READY_FOR_EXTERNAL_PUBLICATION' ||
    !SHA.test(plan.candidateSha ?? '') ||
    !RELEASE_ID.test(plan.releaseId ?? '') ||
    !plan.releaseId.endsWith(plan.candidateSha.slice(0, 7)) ||
    !RELEASE_TAG.test(plan.releaseTag ?? '') ||
    plan.repository !== REPOSITORY ||
    plan.branch !== 'master' ||
    !SHA.test(plan.readmeGitBlobSha ?? '') ||
    !publicationUrlsAreExact(plan.urls) ||
    !exactKeys(plan.files, ['readmeSha256', 'releaseNotesSha256', 'candidateManifestSha256']) ||
    Object.values(plan.files).some((value) => !SHA256.test(value ?? '')) ||
    !exactKeys(plan.release, [
      'title',
      'targetSha',
      'draft',
      'prerelease',
      'assetName',
      'notesSha256',
    ]) ||
    plan.release.title !== plan.releaseTag ||
    plan.release.targetSha !== plan.candidateSha ||
    plan.release.draft !== false ||
    plan.release.prerelease !== isPrereleaseTag(plan.releaseTag) ||
    plan.release.assetName !== ASSET_NAME ||
    plan.release.notesSha256 !== plan.files.releaseNotesSha256 ||
    plan.publicationOrder?.join('\0') !== ['README_VERIFY', 'GITHUB_RELEASE'].join('\0') ||
    plan.retryPolicy !== 'VERIFY_EXACT_OR_CREATE_MISSING' ||
    plan.externalWritesPlanned !== 2 ||
    plan.externalWritesPerformed !== 0 ||
    plan.containsSensitiveData !== false
  ) {
    fail('E7_GITHUB_PUBLICATION_PLAN_INVALID');
  }
  return plan;
};

const validateContext = (context, plan) => {
  if (
    context.repository !== REPOSITORY ||
    context.ref !== 'refs/heads/master' ||
    context.actions !== 'true' ||
    context.eventName !== 'workflow_dispatch' ||
    context.candidateSha !== plan.candidateSha ||
    context.releaseTag !== plan.releaseTag ||
    context.releaseId !== plan.releaseId ||
    typeof context.credential !== 'string' ||
    context.credential.length < 20 ||
    context.credential.length > 4096 ||
    /\s/u.test(context.credential)
  ) {
    fail('E7_GITHUB_PUBLICATION_CONTEXT_INVALID');
  }
};

const responseText = async (response, code, maximum = MAX_JSON_BYTES) => {
  const source = await response.text();
  const bytes = Buffer.byteLength(source);
  if (bytes < 2 || bytes > maximum) fail(code);
  return source;
};

const apiClient = ({ credential, fetchImpl, requests }) => {
  if (typeof fetchImpl !== 'function') fail('E7_GITHUB_PUBLICATION_FETCH_UNAVAILABLE');
  const request = async (url, options, { expected, json = true, code }) => {
    requests.push({ method: options.method ?? 'GET', url });
    let response;
    try {
      response = await fetchImpl(url, {
        ...options,
        redirect: 'error',
        headers: {
          accept: 'application/vnd.github+json',
          authorization: `Bearer ${credential}`,
          'user-agent': 'async-checkout-demo-stage7-publication',
          'x-github-api-version': API_VERSION,
          ...(options.headers ?? {}),
        },
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      fail(code);
    }
    if (!expected.includes(response?.status) || response.redirected === true) fail(code);
    if (!json || response.status === 204 || response.status === 404) {
      return { status: response.status, value: null };
    }
    const contentType = response.headers?.get?.('content-type')?.toLowerCase() ?? '';
    if (!contentType.startsWith('application/json')) fail(code);
    const source = await responseText(response, `${code}_INVALID_RESPONSE`);
    let value;
    try {
      value = JSON.parse(source);
    } catch {
      fail(`${code}_INVALID_RESPONSE`);
    }
    return { status: response.status, value };
  };
  return { request };
};

const repositoryApi = (pathname) => `${API_ROOT}/repos/${REPOSITORY}${pathname}`;

const assertTag = (value, candidateSha) => {
  if (value?.object?.type !== 'commit' || value.object.sha !== candidateSha) {
    fail('E7_GITHUB_PUBLICATION_TAG_INVALID');
  }
};

export const createTagRefAuthority = ({ plan, tagResponse, headResponse }) => {
  assertTag(tagResponse, plan.candidateSha);
  if (headResponse?.object?.type !== 'commit' || headResponse.object.sha !== plan.candidateSha) {
    fail('E7_GITHUB_PUBLICATION_REPOSITORY_STATE_INVALID');
  }
  const binding = {
    repository: plan.repository,
    tagName: plan.releaseTag,
    tagCommitSha: tagResponse.object.sha,
    branchRef: 'refs/heads/master',
    branchCommitSha: headResponse.object.sha,
    candidateSha: plan.candidateSha,
  };
  return {
    tagRefAuthoritative: true,
    tagRefAuthoritySha256: objectSha256(binding),
  };
};

export const createCommitsEndpointAuthority = ({ plan, commitResponse }) => {
  const commitTreeSha = commitResponse?.commit?.tree?.sha;
  if (
    commitResponse?.sha !== plan.candidateSha ||
    !SHA.test(commitTreeSha ?? '') ||
    commitResponse?.html_url !== `https://github.com/${REPOSITORY}/commit/${plan.candidateSha}`
  ) {
    fail('E7_GITHUB_PUBLICATION_REPOSITORY_STATE_INVALID');
  }
  return {
    commitsEndpointVerified: true,
    commitsEndpointAuthoritySha256: objectSha256({
      repository: plan.repository,
      endpoint: `/repos/${REPOSITORY}/commits/${plan.candidateSha}`,
      candidateSha: commitResponse.sha,
      treeSha: commitTreeSha,
      htmlUrl: commitResponse.html_url,
    }),
  };
};

const assertExactRelease = (release, plan, notes, manifestBytes, tagRefAuthority) => {
  if (
    !object(release) ||
    !Number.isSafeInteger(release.id) ||
    release.id < 1 ||
    release.tag_name !== plan.releaseTag ||
    ![plan.candidateSha, 'master'].includes(release.target_commitish) ||
    tagRefAuthority?.tagRefAuthoritative !== true ||
    !SHA256.test(tagRefAuthority.tagRefAuthoritySha256 ?? '') ||
    release.name !== plan.release.title ||
    normalizeText(release.body ?? '') !== normalizeText(notes) ||
    release.draft !== false ||
    release.prerelease !== isPrereleaseTag(plan.releaseTag) ||
    !Array.isArray(release.assets) ||
    release.assets.length > 1
  ) {
    fail('E7_GITHUB_PUBLICATION_RELEASE_CONFLICT');
  }
  let upload;
  try {
    upload = new URL(release.upload_url.replace(/\{\?name,label\}$/u, ''));
  } catch {
    fail('E7_GITHUB_PUBLICATION_RELEASE_CONFLICT');
  }
  if (
    upload.origin !== UPLOAD_ROOT ||
    upload.pathname !== `/repos/${REPOSITORY}/releases/${release.id}/assets` ||
    upload.search ||
    upload.username ||
    upload.password ||
    upload.hash
  ) {
    fail('E7_GITHUB_PUBLICATION_RELEASE_CONFLICT');
  }
  const asset = release.assets[0];
  if (asset !== undefined) {
    if (
      asset.name !== ASSET_NAME ||
      asset.state !== 'uploaded' ||
      asset.digest !== `sha256:${plan.files.candidateManifestSha256}` ||
      asset.size !== manifestBytes ||
      asset.content_type !== 'application/json'
    ) {
      fail('E7_GITHUB_PUBLICATION_ASSET_CONFLICT');
    }
  }
  return { asset: asset ?? null, uploadUrl: upload.toString() };
};

const readRemoteState = async ({ client, plan, notes, manifestBytes }) => {
  const tagPath = `/git/ref/tags/${encodeURIComponent(plan.releaseTag)}`;
  const releasePath = `/releases/tags/${encodeURIComponent(plan.releaseTag)}`;
  const [tagResponse, headResponse, readmeResponse, commitResponse, releaseResponse] =
    await Promise.all([
      client.request(
        repositoryApi(tagPath),
        { method: 'GET' },
        { expected: [200], code: 'E7_GITHUB_PUBLICATION_TAG_READ_FAILED' },
      ),
      client.request(
        repositoryApi('/git/ref/heads/master'),
        { method: 'GET' },
        { expected: [200], code: 'E7_GITHUB_PUBLICATION_HEAD_READ_FAILED' },
      ),
      client.request(
        repositoryApi('/contents/README.md?ref=master'),
        { method: 'GET' },
        { expected: [200], code: 'E7_GITHUB_PUBLICATION_README_READ_FAILED' },
      ),
      client.request(
        repositoryApi(`/commits/${plan.candidateSha}`),
        { method: 'GET' },
        { expected: [200], code: 'E7_GITHUB_PUBLICATION_COMMIT_READ_FAILED' },
      ),
      client.request(
        repositoryApi(releasePath),
        { method: 'GET' },
        { expected: [200, 404], code: 'E7_GITHUB_PUBLICATION_RELEASE_READ_FAILED' },
      ),
    ]);
  const tagRefAuthority = createTagRefAuthority({
    plan,
    tagResponse: tagResponse.value,
    headResponse: headResponse.value,
  });
  const masterSha = headResponse.value?.object?.sha;
  const readmeSha = readmeResponse.value?.sha;
  if (
    headResponse.value?.object?.type !== 'commit' ||
    readmeResponse.value?.type !== 'file' ||
    !SHA.test(masterSha ?? '') ||
    !SHA.test(readmeSha ?? '')
  ) {
    fail('E7_GITHUB_PUBLICATION_REPOSITORY_STATE_INVALID');
  }
  if (masterSha !== plan.candidateSha || readmeSha !== plan.readmeGitBlobSha) {
    fail('E7_GITHUB_PUBLICATION_REPOSITORY_STATE_INVALID');
  }
  const commitsEndpointAuthority = createCommitsEndpointAuthority({
    plan,
    commitResponse: commitResponse.value,
  });
  let releaseState = 'MISSING';
  let release = null;
  let uploadUrl = null;
  if (releaseResponse.status === 200) {
    release = releaseResponse.value;
    const exact = assertExactRelease(release, plan, notes, manifestBytes, tagRefAuthority);
    uploadUrl = exact.uploadUrl;
    releaseState = exact.asset === null ? 'ASSET_MISSING' : 'COMPLETE';
  }
  return { release, releaseState, uploadUrl, ...tagRefAuthority, ...commitsEndpointAuthority };
};

const createRelease = async ({ client, plan, notes }) => {
  const response = await client.request(
    repositoryApi('/releases'),
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        tag_name: plan.releaseTag,
        target_commitish: plan.candidateSha,
        name: plan.release.title,
        body: notes,
        draft: false,
        prerelease: isPrereleaseTag(plan.releaseTag),
        generate_release_notes: false,
        make_latest: 'false',
      }),
    },
    { expected: [201], code: 'E7_GITHUB_PUBLICATION_RELEASE_CREATE_FAILED' },
  );
  return response.value;
};

const uploadAsset = async ({ client, uploadUrl, manifest }) => {
  const url = new URL(uploadUrl);
  url.searchParams.set('name', ASSET_NAME);
  await client.request(
    url.toString(),
    {
      method: 'POST',
      headers: {
        accept: 'application/vnd.github+json',
        'content-type': 'application/json',
      },
      body: manifest,
    },
    { expected: [201], code: 'E7_GITHUB_PUBLICATION_ASSET_UPLOAD_FAILED' },
  );
};

export const publishGithubRelease = async ({
  context,
  fetchImpl = globalThis.fetch,
  manifest,
  notes,
  plan,
  readme,
}) => {
  validatePlan(plan);
  validateContext(context, plan);
  if (
    !(manifest instanceof Uint8Array) ||
    manifest.byteLength < 2 ||
    manifest.byteLength > MAX_ASSET_BYTES ||
    !(readme instanceof Uint8Array) ||
    readme.byteLength < 2 ||
    !(notes instanceof Uint8Array) ||
    notes.byteLength < 2 ||
    sha256(manifest) !== plan.files.candidateManifestSha256 ||
    sha256(readme) !== plan.files.readmeSha256 ||
    sha256(notes) !== plan.files.releaseNotesSha256
  ) {
    fail('E7_GITHUB_PUBLICATION_PACKAGE_INVALID');
  }
  const manifestText = normalizeText(Buffer.from(manifest).toString('utf8'));
  const notesText = normalizeText(Buffer.from(notes).toString('utf8'));
  const readmeText = normalizeText(Buffer.from(readme).toString('utf8'));
  assertSanitizedArtifactText('stage7-github-publication-manifest.json', manifestText);
  assertSanitizedArtifactText('stage7-github-publication-notes.md', notesText);
  assertSanitizedArtifactText('stage7-github-publication-readme.md', readmeText);
  const requests = [];
  const client = apiClient({ credential: context.credential, fetchImpl, requests });
  let writesPerformed = 0;
  let state = await readRemoteState({
    client,
    plan,
    notes: notesText,
    manifestBytes: manifest.byteLength,
  });
  let releaseChanged = false;
  if (state.releaseState === 'MISSING') {
    const created = await createRelease({ client, plan, notes: notesText });
    writesPerformed += 1;
    releaseChanged = true;
    const exact = assertExactRelease(created, plan, notesText, manifest.byteLength, state);
    if (exact.asset !== null) fail('E7_GITHUB_PUBLICATION_RELEASE_CREATE_INVALID');
    state = {
      ...state,
      release: created,
      releaseState: 'ASSET_MISSING',
      uploadUrl: exact.uploadUrl,
    };
  }
  if (state.releaseState === 'ASSET_MISSING') {
    await uploadAsset({ client, uploadUrl: state.uploadUrl, manifest });
    writesPerformed += 1;
    releaseChanged = true;
  }

  if (releaseChanged) {
    state = await readRemoteState({
      client,
      plan,
      notes: notesText,
      manifestBytes: manifest.byteLength,
    });
  }
  if (state.releaseState !== 'COMPLETE') fail('E7_GITHUB_PUBLICATION_RELEASE_NOT_DURABLE');
  if (writesPerformed > 2) {
    fail('E7_GITHUB_PUBLICATION_FINAL_STATE_INVALID');
  }
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'GITHUB_PUBLICATION_OPERATION',
    status: 'PASS',
    candidateSha: plan.candidateSha,
    releaseId: plan.releaseId,
    releaseTag: plan.releaseTag,
    repository: plan.repository,
    publicationPlanSha256: objectSha256(plan),
    tagRefAuthoritative: state.tagRefAuthoritative,
    tagRefAuthoritySha256: state.tagRefAuthoritySha256,
    commitsEndpointVerified: state.commitsEndpointVerified,
    commitsEndpointAuthoritySha256: state.commitsEndpointAuthoritySha256,
    releaseState: 'COMPLETE',
    readmeState: 'VERIFIED_AT_CANDIDATE',
    externalRequests: requests.length,
    externalWritesPerformed: writesPerformed,
    containsSensitiveData: false,
  };
};

const atomicWrite = (target, value) => {
  const resolved = checkedOutput(target);
  mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const temporary = `${resolved}.${process.pid}.tmp`;
  try {
    writeFileSync(
      temporary,
      serializeSanitizedEvidence('stage7-github-publication-result.json', value),
      {
        encoding: 'utf8',
        flag: 'wx',
        mode: 0o600,
      },
    );
    renameSync(temporary, resolved);
  } finally {
    rmSync(temporary, { force: true });
  }
};

const fixturePlan = (releaseTag = 'v1.0.0-rc.1') => {
  const candidateSha = 'a'.repeat(40);
  const readme = Buffer.from('# deployed\n');
  const notes = Buffer.from(`# ${releaseTag}\n`);
  const manifest = Buffer.from('{"kind":"fixture"}\n');
  return {
    plan: {
      schemaVersion: 1,
      stage: 7,
      kind: 'PUBLICATION_PLAN',
      status: 'READY_FOR_EXTERNAL_PUBLICATION',
      candidateSha,
      releaseId: 'rel-20260817-1200-aaaaaaa',
      releaseTag,
      repository: REPOSITORY,
      branch: 'master',
      readmeGitBlobSha: 'b'.repeat(40),
      urls: {
        application: 'https://checkout.example.test',
        api: 'https://checkout.example.test/api',
        docs: 'https://checkout.example.test/api/docs',
        health: 'https://checkout.example.test/api/health/ready',
        repository: `https://github.com/${REPOSITORY}`,
      },
      files: {
        readmeSha256: sha256(readme),
        releaseNotesSha256: sha256(notes),
        candidateManifestSha256: sha256(manifest),
      },
      release: {
        title: releaseTag,
        targetSha: candidateSha,
        draft: false,
        prerelease: isPrereleaseTag(releaseTag),
        assetName: ASSET_NAME,
        notesSha256: sha256(notes),
      },
      publicationOrder: ['README_VERIFY', 'GITHUB_RELEASE'],
      retryPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
      externalWritesPlanned: 2,
      externalWritesPerformed: 0,
      containsSensitiveData: false,
    },
    readme,
    notes,
    manifest,
  };
};

const fixtureContext = (plan) => ({
  repository: REPOSITORY,
  ref: 'refs/heads/master',
  actions: 'true',
  eventName: 'workflow_dispatch',
  candidateSha: plan.candidateSha,
  releaseId: plan.releaseId,
  releaseTag: plan.releaseTag,
  credential: 'github-publication-fixture-credential',
});

const jsonResponse = (status, value) => ({
  status,
  redirected: false,
  headers: { get: () => (status === 404 ? '' : 'application/json; charset=utf-8') },
  text: async () => (status === 404 ? '' : JSON.stringify(value)),
});

const fixtureRelease = (
  plan,
  notes,
  manifest,
  { asset = true, targetCommitish = plan.candidateSha } = {},
) => ({
  id: 41,
  tag_name: plan.releaseTag,
  target_commitish: targetCommitish,
  name: plan.releaseTag,
  body: notes.toString('utf8'),
  draft: false,
  prerelease: plan.release.prerelease,
  upload_url: `${UPLOAD_ROOT}/repos/${REPOSITORY}/releases/41/assets{?name,label}`,
  assets: asset
    ? [
        {
          name: ASSET_NAME,
          state: 'uploaded',
          digest: `sha256:${plan.files.candidateManifestSha256}`,
          size: manifest.byteLength,
          content_type: 'application/json',
        },
      ]
    : [],
});

const fakeRemote = ({
  commitConflict = false,
  failAfterMutation,
  initialRelease = 'MISSING',
  masterSha,
  readmeConflict = false,
  releaseTargetCommitish,
  tagSha,
  fixture,
}) => {
  let releaseState = initialRelease;
  let failureInjected = false;
  const mutations = [];
  const mutationResponse = (name, success) => {
    mutations.push(name);
    if (failAfterMutation === name && !failureInjected) {
      failureInjected = true;
      return jsonResponse(503, { message: 'injected ambiguous failure' });
    }
    return success;
  };
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    const method = options.method ?? 'GET';
    if (method === 'GET' && parsed.pathname.endsWith(`/git/ref/tags/${fixture.plan.releaseTag}`)) {
      return jsonResponse(200, {
        object: { type: 'commit', sha: tagSha ?? fixture.plan.candidateSha },
      });
    }
    if (method === 'GET' && parsed.pathname.endsWith('/git/ref/heads/master')) {
      return jsonResponse(200, {
        object: { type: 'commit', sha: masterSha ?? fixture.plan.candidateSha },
      });
    }
    if (method === 'GET' && parsed.pathname.endsWith('/contents/README.md')) {
      return jsonResponse(200, {
        type: 'file',
        sha: readmeConflict ? 'e'.repeat(40) : fixture.plan.readmeGitBlobSha,
      });
    }
    if (method === 'GET' && parsed.pathname.endsWith(`/commits/${fixture.plan.candidateSha}`)) {
      const commitSha = commitConflict ? 'f'.repeat(40) : fixture.plan.candidateSha;
      return jsonResponse(200, {
        sha: commitSha,
        html_url: `https://github.com/${REPOSITORY}/commit/${commitSha}`,
        commit: { tree: { sha: '9'.repeat(40) } },
      });
    }
    if (method === 'GET' && parsed.pathname.includes('/releases/tags/')) {
      if (releaseState === 'MISSING') return jsonResponse(404, null);
      return jsonResponse(
        200,
        fixtureRelease(fixture.plan, fixture.notes, fixture.manifest, {
          asset: releaseState === 'COMPLETE',
          targetCommitish: releaseTargetCommitish,
        }),
      );
    }
    if (method === 'POST' && parsed.pathname.endsWith('/releases')) {
      const body = JSON.parse(options.body);
      assert.deepEqual(body, {
        tag_name: fixture.plan.releaseTag,
        target_commitish: fixture.plan.candidateSha,
        name: fixture.plan.release.title,
        body: fixture.notes.toString('utf8'),
        draft: false,
        prerelease: fixture.plan.release.prerelease,
        generate_release_notes: false,
        make_latest: 'false',
      });
      releaseState = 'ASSET_MISSING';
      return mutationResponse(
        'CREATE_RELEASE',
        jsonResponse(
          201,
          fixtureRelease(fixture.plan, fixture.notes, fixture.manifest, {
            asset: false,
            targetCommitish: releaseTargetCommitish,
          }),
        ),
      );
    }
    if (method === 'POST' && parsed.hostname === 'uploads.github.com') {
      releaseState = 'COMPLETE';
      return mutationResponse('UPLOAD_ASSET', jsonResponse(201, { state: 'uploaded' }));
    }
    throw new Error(`unexpected request: ${method} ${url}`);
  };
  return { fetchImpl, mutations };
};

export const selfTestGithubPublication = async () => {
  const fixture = fixturePlan();
  const fresh = fakeRemote({ fixture });
  const created = await publishGithubRelease({
    context: fixtureContext(fixture.plan),
    fetchImpl: fresh.fetchImpl,
    ...fixture,
  });
  assert.equal(created.externalWritesPerformed, 2);
  assert.equal(created.externalRequests, 12);
  assert.equal(created.tagRefAuthoritative, true);
  assert.equal(SHA256.test(created.tagRefAuthoritySha256), true);
  assert.equal(created.commitsEndpointVerified, true);
  assert.equal(SHA256.test(created.commitsEndpointAuthoritySha256), true);
  assert.deepEqual(fresh.mutations, ['CREATE_RELEASE', 'UPLOAD_ASSET']);

  const finalFixture = fixturePlan('v1.0.0');
  const finalRemote = fakeRemote({ fixture: finalFixture });
  const finalCreated = await publishGithubRelease({
    context: fixtureContext(finalFixture.plan),
    fetchImpl: finalRemote.fetchImpl,
    ...finalFixture,
  });
  assert.equal(finalCreated.externalWritesPerformed, 2);
  assert.equal(finalCreated.externalRequests, 12);
  assert.equal(finalFixture.plan.release.prerelease, false);
  assert.deepEqual(finalRemote.mutations, ['CREATE_RELEASE', 'UPLOAD_ASSET']);

  const complete = fakeRemote({
    fixture,
    initialRelease: 'COMPLETE',
  });
  const rerun = await publishGithubRelease({
    context: fixtureContext(fixture.plan),
    fetchImpl: complete.fetchImpl,
    ...fixture,
  });
  assert.equal(rerun.externalWritesPerformed, 0);
  assert.equal(rerun.externalRequests, 5);
  assert.deepEqual(complete.mutations, []);

  const masterTarget = fakeRemote({
    fixture,
    initialRelease: 'COMPLETE',
    releaseTargetCommitish: 'master',
  });
  const masterTargetVerified = await publishGithubRelease({
    context: fixtureContext(fixture.plan),
    fetchImpl: masterTarget.fetchImpl,
    ...fixture,
  });
  assert.equal(masterTargetVerified.tagRefAuthoritative, true);
  assert.equal(SHA256.test(masterTargetVerified.tagRefAuthoritySha256), true);
  assert.equal(masterTargetVerified.externalRequests, 5);
  assert.deepEqual(masterTarget.mutations, []);

  const commitConflict = fakeRemote({ fixture, commitConflict: true, initialRelease: 'COMPLETE' });
  await assert.rejects(
    publishGithubRelease({
      context: fixtureContext(fixture.plan),
      fetchImpl: commitConflict.fetchImpl,
      ...fixture,
    }),
    (error) => error.code === 'E7_GITHUB_PUBLICATION_REPOSITORY_STATE_INVALID',
  );
  assert.deepEqual(commitConflict.mutations, []);

  for (const authorityConflict of [{ masterSha: 'c'.repeat(40) }, { tagSha: 'd'.repeat(40) }]) {
    const mismatchedAuthority = fakeRemote({
      fixture,
      initialRelease: 'COMPLETE',
      releaseTargetCommitish: 'master',
      ...authorityConflict,
    });
    await assert.rejects(
      publishGithubRelease({
        context: fixtureContext(fixture.plan),
        fetchImpl: mismatchedAuthority.fetchImpl,
        ...fixture,
      }),
      (error) =>
        [
          'E7_GITHUB_PUBLICATION_REPOSITORY_STATE_INVALID',
          'E7_GITHUB_PUBLICATION_TAG_INVALID',
        ].includes(error.code),
    );
    assert.deepEqual(mismatchedAuthority.mutations, []);
  }

  const partial = fakeRemote({ fixture, initialRelease: 'ASSET_MISSING' });
  const resumed = await publishGithubRelease({
    context: fixtureContext(fixture.plan),
    fetchImpl: partial.fetchImpl,
    ...fixture,
  });
  assert.equal(resumed.externalWritesPerformed, 1);
  assert.equal(resumed.externalRequests, 11);
  assert.deepEqual(partial.mutations, ['UPLOAD_ASSET']);

  for (const [
    failure,
    expectedFailure,
    expectedResumeWrites,
    expectedResumeRequests,
    expectedMutations,
  ] of [
    [
      'CREATE_RELEASE',
      'E7_GITHUB_PUBLICATION_RELEASE_CREATE_FAILED',
      1,
      11,
      ['CREATE_RELEASE', 'UPLOAD_ASSET'],
    ],
    [
      'UPLOAD_ASSET',
      'E7_GITHUB_PUBLICATION_ASSET_UPLOAD_FAILED',
      0,
      5,
      ['CREATE_RELEASE', 'UPLOAD_ASSET'],
    ],
  ]) {
    const interrupted = fakeRemote({ fixture, failAfterMutation: failure });
    await assert.rejects(
      publishGithubRelease({
        context: fixtureContext(fixture.plan),
        fetchImpl: interrupted.fetchImpl,
        ...fixture,
      }),
      (error) => error.code === expectedFailure,
    );
    const recovered = await publishGithubRelease({
      context: fixtureContext(fixture.plan),
      fetchImpl: interrupted.fetchImpl,
      ...fixture,
    });
    assert.equal(recovered.externalWritesPerformed, expectedResumeWrites);
    assert.equal(recovered.externalRequests, expectedResumeRequests);
    assert.deepEqual(interrupted.mutations, expectedMutations);
  }

  const conflict = fakeRemote({ fixture, initialRelease: 'COMPLETE' });
  await assert.rejects(
    publishGithubRelease({
      context: fixtureContext(fixture.plan),
      fetchImpl: async (url, options) => {
        const response = await conflict.fetchImpl(url, options);
        if (url.includes('/releases/tags/')) {
          const release = await response.text().then(JSON.parse);
          release.body = 'different release';
          return jsonResponse(200, release);
        }
        return response;
      },
      ...fixture,
    }),
    (error) => error.code === 'E7_GITHUB_PUBLICATION_RELEASE_CONFLICT',
  );
  assert.deepEqual(conflict.mutations, []);
  const targetConflict = fakeRemote({ fixture, initialRelease: 'COMPLETE' });
  await assert.rejects(
    publishGithubRelease({
      context: fixtureContext(fixture.plan),
      fetchImpl: async (url, options) => {
        const response = await targetConflict.fetchImpl(url, options);
        if (url.includes('/releases/tags/')) {
          const release = await response.text().then(JSON.parse);
          release.target_commitish = 'development';
          return jsonResponse(200, release);
        }
        return response;
      },
      ...fixture,
    }),
    (error) => error.code === 'E7_GITHUB_PUBLICATION_RELEASE_CONFLICT',
  );
  assert.deepEqual(targetConflict.mutations, []);
  const readmeConflict = fakeRemote({ fixture, readmeConflict: true });
  await assert.rejects(
    publishGithubRelease({
      context: fixtureContext(fixture.plan),
      fetchImpl: readmeConflict.fetchImpl,
      ...fixture,
    }),
    (error) => error.code === 'E7_GITHUB_PUBLICATION_REPOSITORY_STATE_INVALID',
  );
  assert.deepEqual(readmeConflict.mutations, []);
  for (const api of ['https://api.example.test/api', 'https://checkout.example.test/api/v1']) {
    let requests = 0;
    const invalidPlan = { ...fixture.plan, urls: { ...fixture.plan.urls, api } };
    await assert.rejects(
      publishGithubRelease({
        context: fixtureContext(invalidPlan),
        fetchImpl: async () => {
          requests += 1;
          throw new Error('invalid publication plan reached the network');
        },
        ...fixture,
        plan: invalidPlan,
      }),
      (error) => error.code === 'E7_GITHUB_PUBLICATION_PLAN_INVALID',
    );
    assert.equal(requests, 0);
  }
  for (const releaseTag of ['v01.0.0', 'v1.0.0-beta.1', 'v1.0.0-rc.0']) {
    let requests = 0;
    const malformed = fixturePlan();
    malformed.plan.releaseTag = releaseTag;
    malformed.plan.release.title = releaseTag;
    await assert.rejects(
      publishGithubRelease({
        context: fixtureContext(malformed.plan),
        fetchImpl: async () => {
          requests += 1;
          throw new Error('invalid release tag reached the network');
        },
        ...malformed,
      }),
      (error) => error.code === 'E7_GITHUB_PUBLICATION_PLAN_INVALID',
    );
    assert.equal(requests, 0);
  }
  const prereleaseMismatch = fixturePlan('v1.0.0');
  prereleaseMismatch.plan.release.prerelease = true;
  let prereleaseMismatchRequests = 0;
  await assert.rejects(
    publishGithubRelease({
      context: fixtureContext(prereleaseMismatch.plan),
      fetchImpl: async () => {
        prereleaseMismatchRequests += 1;
        throw new Error('prerelease mismatch reached the network');
      },
      ...prereleaseMismatch,
    }),
    (error) => error.code === 'E7_GITHUB_PUBLICATION_PLAN_INVALID',
  );
  assert.equal(prereleaseMismatchRequests, 0);
  await assert.rejects(
    publishGithubRelease({
      context: { ...fixtureContext(fixture.plan), ref: 'refs/heads/feature' },
      fetchImpl: complete.fetchImpl,
      ...fixture,
    }),
    (error) => error.code === 'E7_GITHUB_PUBLICATION_CONTEXT_INVALID',
  );
  await assert.rejects(
    publishGithubRelease({
      context: fixtureContext(fixture.plan),
      fetchImpl: complete.fetchImpl,
      ...fixture,
      manifest: Buffer.from('{"kind":"changed"}\n'),
    }),
    (error) => error.code === 'E7_GITHUB_PUBLICATION_PACKAGE_INVALID',
  );
  process.stdout.write('stage-7 GitHub publication self-test: PASS (0 external calls)\n');
};

const main = async () => {
  const arguments_ = normalizePnpmScriptArguments(process.argv.slice(2), { separatorIndex: 0 });
  if (arguments_[0] === '--self-test') {
    if (arguments_.length !== 1) fail('E7_GITHUB_PUBLICATION_ARGUMENT_SET_INVALID');
    await selfTestGithubPublication();
    return;
  }
  const flags = parseFlags(arguments_);
  const planFilename = checkedFile(flags.plan);
  const directory = path.dirname(planFilename);
  const plan = validatePlan(JSON.parse(readFileSync(planFilename, 'utf8')));
  const result = await publishGithubRelease({
    context: {
      repository: process.env.GITHUB_REPOSITORY,
      ref: process.env.GITHUB_REF,
      actions: process.env.GITHUB_ACTIONS,
      eventName: process.env.GITHUB_EVENT_NAME,
      candidateSha: process.env.STAGE7_CANDIDATE_SHA,
      releaseId: process.env.STAGE7_RELEASE_ID,
      releaseTag: process.env.STAGE7_RELEASE_TAG,
      credential: process.env.GH_TOKEN,
    },
    plan,
    readme: readFileSync(checkedFile(path.join(directory, 'README.md'))),
    notes: readFileSync(checkedFile(path.join(directory, 'release-notes.md'))),
    manifest: readFileSync(checkedFile(path.join(directory, ASSET_NAME))),
  });
  atomicWrite(flags.result, result);
  process.stdout.write(
    `${JSON.stringify({ status: result.status, externalWritesPerformed: result.externalWritesPerformed, externalRequests: result.externalRequests })}\n`,
  );
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code =
      error instanceof GithubPublicationError
        ? error.code
        : 'E7_GITHUB_PUBLICATION_UNEXPECTED_FAILURE';
    process.stderr.write(`stage-7 GitHub publication: ${code}\n`);
    process.exitCode = 1;
  });
}
