import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256 } from './core.mjs';
import {
  RELEASE_SUCCESSOR_SOURCE_LAYOUT,
  validateReleaseSuccessorSourceBundleDirectory,
} from './release-successor-handoff.mjs';
import {
  RELEASE_SUCCESSOR_CLEANUP_RECEIPT_ARTIFACT_PREFIX,
  RELEASE_SUCCESSOR_PRESERVATION_ARTIFACT_PREFIX,
  validateReleaseSuccessorPreservationReceipt,
} from './release-successor-journal-cleanup.mjs';
import { readReleaseSuccessorZipEntries } from './release-successor-zip.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const ARTIFACT_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const MAX_PAGES = 1000;
const MAX_ARTIFACTS_PER_PAGE = 100;
const PRESERVATION_BASENAME = 'release-successor-preservation-receipt.json';

const ARTIFACT_PATTERNS = Object.freeze({
  source: /^stage7-release-successor-source-r([1-9][0-9]{0,19})-a([1-9][0-9]{0,2})$/u,
  preservation: new RegExp(
    `^${RELEASE_SUCCESSOR_PRESERVATION_ARTIFACT_PREFIX}-r([1-9][0-9]{0,19})-a([1-9][0-9]{0,2})$`,
    'u',
  ),
  cleanup: new RegExp(
    `^${RELEASE_SUCCESSOR_CLEANUP_RECEIPT_ARTIFACT_PREFIX}-r([1-9][0-9]{0,19})-a([1-9][0-9]{0,2})$`,
    'u',
  ),
});

export class Stage7ReleaseSuccessorRetryError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseSuccessorRetryError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseSuccessorRetryError(code, cause === undefined ? undefined : { cause });
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const attempt = (value) =>
  Number.isSafeInteger(value) && value >= 1 && value <= 999 ? value : null;
const withoutDigest = (value) => {
  const body = { ...value };
  delete body.selectionSha256;
  return body;
};
const strictExternalJson = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  try {
    return { value: parseStrictJsonSource(bytes, { scanForbiddenData: false }), bytes };
  } catch (error) {
    fail(code, error);
  }
};
const strictPublicJson = (source, code) => {
  const document = strictExternalJson(source, code);
  if (!object(document.value) || document.value.containsSensitiveData !== false) fail(code);
  return document;
};
const artifactProjection = ({ logicalName, attempt: artifactAttempt, artifact }) => ({
  logicalName,
  attempt: artifactAttempt,
  name: artifact.name,
  id: artifact.id,
  digest: artifact.digest,
  expired: false,
  workflowRunId: String(artifact.workflow_run.id),
});
const validateArtifactProjection = (value, { sourceRunId, postSuccessRunId }) => {
  if (
    !exactKeys(value, [
      'logicalName',
      'attempt',
      'name',
      'id',
      'digest',
      'expired',
      'workflowRunId',
    ]) ||
    !Object.hasOwn(ARTIFACT_PATTERNS, value.logicalName) ||
    attempt(value.attempt) === null ||
    ARTIFACT_PATTERNS[value.logicalName].exec(value.name ?? '')?.[1] !== sourceRunId ||
    Number(ARTIFACT_PATTERNS[value.logicalName].exec(value.name ?? '')?.[2]) !== value.attempt ||
    !Number.isSafeInteger(value.id) ||
    value.id < 1 ||
    !ARTIFACT_DIGEST.test(value.digest ?? '') ||
    value.expired !== false ||
    value.workflowRunId !== postSuccessRunId
  ) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_ARTIFACT_INVALID');
  }
  return value;
};

export const validateReleaseSuccessorRetrySelection = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'sourceRunId',
      'postSuccessRunId',
      'currentPostSuccessRunAttempt',
      'artifactListRequests',
      'artifactInventoryCount',
      'artifactInventory',
      'artifactInventorySha256',
      'selectedAttempt',
      'selectedSourceArtifact',
      'selectedPreservationArtifact',
      'containsSensitiveData',
      'selectionSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_RETRY_SOURCE_SELECTION' ||
    !['CAPTURE_CURRENT', 'REUSE_DURABLE_SOURCE'].includes(value.status) ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    !RUN_ID.test(value.postSuccessRunId ?? '') ||
    attempt(value.currentPostSuccessRunAttempt) === null ||
    !Number.isSafeInteger(value.artifactListRequests) ||
    value.artifactListRequests < 1 ||
    value.artifactListRequests > MAX_PAGES ||
    !Number.isSafeInteger(value.artifactInventoryCount) ||
    value.artifactInventoryCount < 0 ||
    !Array.isArray(value.artifactInventory) ||
    value.artifactInventory.length !== value.artifactInventoryCount ||
    value.artifactInventory.some((entry) => {
      validateArtifactProjection(entry, value);
      return entry.attempt >= value.currentPostSuccessRunAttempt;
    }) ||
    value.artifactInventorySha256 !== objectSha256(value.artifactInventory) ||
    value.containsSensitiveData !== false ||
    value.selectionSha256 !== objectSha256(withoutDigest(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_SELECTION_INVALID');
  }
  const identities = value.artifactInventory.map(
    ({ logicalName, attempt: artifactAttempt }) => `${logicalName}\0${artifactAttempt}`,
  );
  if (
    new Set(identities).size !== identities.length ||
    value.artifactInventory.map(({ id }) => id).length !==
      new Set(value.artifactInventory.map(({ id }) => id)).size ||
    value.artifactInventory.map(({ name }) => name).length !==
      new Set(value.artifactInventory.map(({ name }) => name)).size ||
    canonicalJson(value.artifactInventory) !==
      canonicalJson(
        [...value.artifactInventory].toSorted((left, right) =>
          left.attempt === right.attempt
            ? left.logicalName.localeCompare(right.logicalName)
            : left.attempt - right.attempt,
        ),
      )
  ) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_INVENTORY_INVALID');
  }
  const sets = new Map();
  for (const entry of value.artifactInventory) {
    const logicalNames = sets.get(entry.attempt) ?? new Set();
    logicalNames.add(entry.logicalName);
    sets.set(entry.attempt, logicalNames);
  }
  for (const logicalNames of sets.values()) {
    if (
      (logicalNames.has('preservation') && !logicalNames.has('source')) ||
      (logicalNames.has('cleanup') &&
        logicalNames.has('source') &&
        !logicalNames.has('preservation'))
    ) {
      fail('E7_RELEASE_SUCCESSOR_RETRY_INVENTORY_CAUSALITY_INVALID');
    }
  }
  const durableAttempts = [...sets]
    .filter(([, logicalNames]) => logicalNames.has('source') && logicalNames.has('preservation'))
    .map(([artifactAttempt]) => artifactAttempt)
    .toSorted((left, right) => right - left);
  const selectedAttempt = durableAttempts[0] ?? null;
  if (
    value.selectedAttempt !== selectedAttempt ||
    value.status !== (selectedAttempt === null ? 'CAPTURE_CURRENT' : 'REUSE_DURABLE_SOURCE') ||
    (selectedAttempt === null &&
      (value.selectedSourceArtifact !== null || value.selectedPreservationArtifact !== null))
  ) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_SELECTION_DECISION_INVALID');
  }
  if (selectedAttempt !== null) {
    const source = value.artifactInventory.find(
      (entry) => entry.logicalName === 'source' && entry.attempt === selectedAttempt,
    );
    const preservation = value.artifactInventory.find(
      (entry) => entry.logicalName === 'preservation' && entry.attempt === selectedAttempt,
    );
    if (
      canonicalJson(value.selectedSourceArtifact) !== canonicalJson(source) ||
      canonicalJson(value.selectedPreservationArtifact) !== canonicalJson(preservation)
    ) {
      fail('E7_RELEASE_SUCCESSOR_RETRY_SELECTION_DECISION_INVALID');
    }
  }
  return value;
};

export const createReleaseSuccessorRetrySelection = ({
  sourceRunId,
  postSuccessRunId,
  currentPostSuccessRunAttempt,
  artifactPagesSource,
}) => {
  const currentAttempt = Number(currentPostSuccessRunAttempt);
  if (
    !RUN_ID.test(sourceRunId ?? '') ||
    !RUN_ID.test(String(postSuccessRunId ?? '')) ||
    attempt(currentAttempt) === null
  ) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_INPUT_INVALID');
  }
  const parsed = strictExternalJson(
    artifactPagesSource,
    'E7_RELEASE_SUCCESSOR_RETRY_ARTIFACT_PAGES_INVALID',
  ).value;
  const pages = Array.isArray(parsed) ? parsed : [parsed];
  if (pages.length < 1 || pages.length > MAX_PAGES) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_ARTIFACT_PAGES_INVALID');
  }
  const expectedTotal = pages[0]?.total_count;
  if (
    !Number.isSafeInteger(expectedTotal) ||
    expectedTotal < 0 ||
    pages.some(
      (page) =>
        !object(page) ||
        page.total_count !== expectedTotal ||
        !Array.isArray(page.artifacts) ||
        page.artifacts.length > MAX_ARTIFACTS_PER_PAGE,
    )
  ) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_ARTIFACT_PAGES_INVALID');
  }
  const artifacts = pages.flatMap(({ artifacts: pageArtifacts }) => pageArtifacts);
  if (artifacts.length !== expectedTotal) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_ARTIFACT_COUNT_INVALID');
  }
  const inventory = artifacts.map((artifact) => {
    const matches = Object.entries(ARTIFACT_PATTERNS)
      .map(([logicalName, pattern]) => [logicalName, pattern.exec(artifact?.name ?? '')])
      .filter(([, match]) => match !== null);
    const logicalName = matches[0]?.[0];
    const match = matches[0]?.[1];
    const artifactAttempt = Number(match?.[2]);
    if (
      matches.length !== 1 ||
      match[1] !== sourceRunId ||
      attempt(artifactAttempt) === null ||
      artifactAttempt >= currentAttempt ||
      !Number.isSafeInteger(artifact.id) ||
      artifact.id < 1 ||
      !ARTIFACT_DIGEST.test(artifact.digest ?? '') ||
      artifact.expired !== false ||
      String(artifact.workflow_run?.id ?? '') !== String(postSuccessRunId)
    ) {
      fail('E7_RELEASE_SUCCESSOR_RETRY_ARTIFACT_INVALID');
    }
    return artifactProjection({ logicalName, attempt: artifactAttempt, artifact });
  });
  inventory.sort((left, right) =>
    left.attempt === right.attempt
      ? left.logicalName.localeCompare(right.logicalName)
      : left.attempt - right.attempt,
  );
  const grouped = new Map();
  for (const entry of inventory) {
    const logicalNames = grouped.get(entry.attempt) ?? new Set();
    logicalNames.add(entry.logicalName);
    grouped.set(entry.attempt, logicalNames);
  }
  const selectedAttempt =
    [...grouped]
      .filter(([, logicalNames]) => logicalNames.has('source') && logicalNames.has('preservation'))
      .map(([artifactAttempt]) => artifactAttempt)
      .toSorted((left, right) => right - left)[0] ?? null;
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_RETRY_SOURCE_SELECTION',
    status: selectedAttempt === null ? 'CAPTURE_CURRENT' : 'REUSE_DURABLE_SOURCE',
    sourceRunId,
    postSuccessRunId: String(postSuccessRunId),
    currentPostSuccessRunAttempt: currentAttempt,
    artifactListRequests: pages.length,
    artifactInventoryCount: inventory.length,
    artifactInventory: inventory,
    artifactInventorySha256: objectSha256(inventory),
    selectedAttempt,
    selectedSourceArtifact:
      selectedAttempt === null
        ? null
        : inventory.find(
            (entry) => entry.logicalName === 'source' && entry.attempt === selectedAttempt,
          ),
    selectedPreservationArtifact:
      selectedAttempt === null
        ? null
        : inventory.find(
            (entry) => entry.logicalName === 'preservation' && entry.attempt === selectedAttempt,
          ),
    containsSensitiveData: false,
  };
  return validateReleaseSuccessorRetrySelection({
    ...body,
    selectionSha256: objectSha256(body),
  });
};

const validateArtifactApiAndArchive = ({
  apiSource,
  archiveSource,
  selected,
  postSuccessRunId,
  code,
}) => {
  const api = strictExternalJson(apiSource, code).value;
  const archive = Buffer.isBuffer(archiveSource)
    ? Buffer.from(archiveSource)
    : Buffer.from(archiveSource ?? '');
  if (
    api?.id !== selected.id ||
    api?.name !== selected.name ||
    api?.digest !== selected.digest ||
    api?.expired !== false ||
    String(api?.workflow_run?.id ?? '') !== postSuccessRunId ||
    archive.length < 1 ||
    `sha256:${sha256(archive)}` !== selected.digest
  ) {
    fail(code);
  }
  let entries;
  try {
    entries = readReleaseSuccessorZipEntries(archive);
  } catch (error) {
    fail(code, error);
  }
  return { api, archive, entries };
};

export const materializeReleaseSuccessorRetrySource = ({
  selection,
  sourceArtifactApiSource,
  sourceArchiveSource,
  preservationArtifactApiSource,
  preservationArchiveSource,
  outputDirectory,
  preservationOutput,
  expectedHeadSha,
}) => {
  validateReleaseSuccessorRetrySelection(selection);
  const validPathInputs =
    typeof outputDirectory === 'string' &&
    outputDirectory.length > 0 &&
    typeof preservationOutput === 'string' &&
    preservationOutput.length > 0;
  const preservationRelativeToSource = validPathInputs
    ? path.relative(path.resolve(outputDirectory), path.resolve(preservationOutput))
    : null;
  if (
    selection.status !== 'REUSE_DURABLE_SOURCE' ||
    !SHA.test(expectedHeadSha ?? '') ||
    !validPathInputs ||
    preservationRelativeToSource === '' ||
    (!preservationRelativeToSource.startsWith(`..${path.sep}`) &&
      preservationRelativeToSource !== '..' &&
      !path.isAbsolute(preservationRelativeToSource)) ||
    existsSync(outputDirectory) ||
    existsSync(preservationOutput)
  ) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_MATERIALIZATION_INPUT_INVALID');
  }
  const source = validateArtifactApiAndArchive({
    apiSource: sourceArtifactApiSource,
    archiveSource: sourceArchiveSource,
    selected: selection.selectedSourceArtifact,
    postSuccessRunId: selection.postSuccessRunId,
    code: 'E7_RELEASE_SUCCESSOR_RETRY_SOURCE_ARTIFACT_INVALID',
  });
  const expectedSourcePaths = Object.values(RELEASE_SUCCESSOR_SOURCE_LAYOUT).toSorted();
  if ([...source.entries.keys()].toSorted().join('\0') !== expectedSourcePaths.join('\0')) {
    fail('E7_RELEASE_SUCCESSOR_RETRY_SOURCE_FILE_SET_INVALID');
  }
  mkdirSync(outputDirectory, { recursive: false, mode: 0o700 });
  try {
    for (const [name, bytes] of source.entries) {
      writeFileSync(path.join(outputDirectory, name), bytes, { flag: 'wx', mode: 0o600 });
    }
    const sourceBundle = validateReleaseSuccessorSourceBundleDirectory(outputDirectory);
    if (
      sourceBundle.provenance.sourceRunId !== selection.sourceRunId ||
      sourceBundle.provenance.headSha !== expectedHeadSha
    ) {
      fail('E7_RELEASE_SUCCESSOR_RETRY_SOURCE_IDENTITY_INVALID');
    }
    const preservation = validateArtifactApiAndArchive({
      apiSource: preservationArtifactApiSource,
      archiveSource: preservationArchiveSource,
      selected: selection.selectedPreservationArtifact,
      postSuccessRunId: selection.postSuccessRunId,
      code: 'E7_RELEASE_SUCCESSOR_RETRY_PRESERVATION_ARTIFACT_INVALID',
    });
    if (preservation.entries.size !== 1 || !preservation.entries.has(PRESERVATION_BASENAME)) {
      fail('E7_RELEASE_SUCCESSOR_RETRY_PRESERVATION_FILE_SET_INVALID');
    }
    const preservationBytes = preservation.entries.get(PRESERVATION_BASENAME);
    const preservationReceipt = strictPublicJson(
      preservationBytes,
      'E7_RELEASE_SUCCESSOR_RETRY_PRESERVATION_RECEIPT_INVALID',
    ).value;
    validateReleaseSuccessorPreservationReceipt(preservationReceipt, { sourceBundle });
    if (
      preservationReceipt.postSuccessRunId !== selection.postSuccessRunId ||
      preservationReceipt.postSuccessRunAttempt !== selection.selectedAttempt ||
      preservationReceipt.sourceArtifact.id !== selection.selectedSourceArtifact.id ||
      preservationReceipt.sourceArtifact.digest !== selection.selectedSourceArtifact.digest ||
      preservationReceipt.sourceArtifact.physicalName !== selection.selectedSourceArtifact.name
    ) {
      fail('E7_RELEASE_SUCCESSOR_RETRY_PRESERVATION_BINDING_INVALID');
    }
    mkdirSync(path.dirname(preservationOutput), { recursive: true, mode: 0o700 });
    writeFileSync(preservationOutput, preservationBytes, { flag: 'wx', mode: 0o600 });
    return {
      sourceBundle,
      preservationReceipt,
      selectionSha256: selection.selectionSha256,
    };
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    if (existsSync(preservationOutput)) rmSync(preservationOutput, { force: true });
    throw error;
  }
};

export const selfTestReleaseSuccessorRetry = () => {
  const sourceRunId = '123456789';
  const postSuccessRunId = '99887766';
  const artifact = (logicalName, artifactAttempt, id) => ({
    id,
    name:
      logicalName === 'source'
        ? `stage7-release-successor-source-r${sourceRunId}-a${artifactAttempt}`
        : logicalName === 'preservation'
          ? `${RELEASE_SUCCESSOR_PRESERVATION_ARTIFACT_PREFIX}-r${sourceRunId}-a${artifactAttempt}`
          : `${RELEASE_SUCCESSOR_CLEANUP_RECEIPT_ARTIFACT_PREFIX}-r${sourceRunId}-a${artifactAttempt}`,
    digest: `sha256:${String(id).padStart(64, '0')}`,
    expired: false,
    workflow_run: { id: Number(postSuccessRunId) },
  });
  const encode = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  const prior = [
    artifact('source', 1, 1),
    artifact('preservation', 1, 2),
    artifact('cleanup', 1, 3),
  ];
  const selection = createReleaseSuccessorRetrySelection({
    sourceRunId,
    postSuccessRunId,
    currentPostSuccessRunAttempt: 2,
    artifactPagesSource: encode([{ total_count: prior.length, artifacts: prior }]),
  });
  assert.equal(selection.status, 'REUSE_DURABLE_SOURCE');
  assert.equal(selection.selectedAttempt, 1);
  const retryAfterCleanupOnly = createReleaseSuccessorRetrySelection({
    sourceRunId,
    postSuccessRunId,
    currentPostSuccessRunAttempt: 3,
    artifactPagesSource: encode([
      {
        total_count: prior.length + 1,
        artifacts: [...prior, artifact('cleanup', 2, 4)],
      },
    ]),
  });
  assert.equal(retryAfterCleanupOnly.status, 'REUSE_DURABLE_SOURCE');
  assert.equal(retryAfterCleanupOnly.selectedAttempt, 1);
  const empty = createReleaseSuccessorRetrySelection({
    sourceRunId,
    postSuccessRunId,
    currentPostSuccessRunAttempt: 1,
    artifactPagesSource: encode([{ total_count: 0, artifacts: [] }]),
  });
  assert.equal(empty.status, 'CAPTURE_CURRENT');
  assert.throws(
    () =>
      createReleaseSuccessorRetrySelection({
        sourceRunId,
        postSuccessRunId,
        currentPostSuccessRunAttempt: 2,
        artifactPagesSource: encode([
          { total_count: 1, artifacts: [artifact('preservation', 1, 2)] },
        ]),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_RETRY_INVENTORY_CAUSALITY_INVALID',
  );
  assert.throws(
    () =>
      createReleaseSuccessorRetrySelection({
        sourceRunId,
        postSuccessRunId,
        currentPostSuccessRunAttempt: 2,
        artifactPagesSource: encode([{ total_count: 1, artifacts: [artifact('source', 2, 4)] }]),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_RETRY_ARTIFACT_INVALID',
  );
  const expired = artifact('source', 1, 5);
  expired.expired = true;
  assert.throws(
    () =>
      createReleaseSuccessorRetrySelection({
        sourceRunId,
        postSuccessRunId,
        currentPostSuccessRunAttempt: 2,
        artifactPagesSource: encode([{ total_count: 1, artifacts: [expired] }]),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_RETRY_ARTIFACT_INVALID',
  );
  const retryFixtureRoot = mkdtempSync(path.join(tmpdir(), 'stage7-successor-retry-'));
  const retryOutput = path.join(retryFixtureRoot, 'source');
  const retryPreservation = path.join(retryFixtureRoot, 'preservation', PRESERVATION_BASENAME);
  try {
    assert.throws(
      () =>
        materializeReleaseSuccessorRetrySource({
          selection,
          sourceArtifactApiSource: Buffer.alloc(0),
          sourceArchiveSource: Buffer.alloc(0),
          preservationArtifactApiSource: Buffer.alloc(0),
          preservationArchiveSource: Buffer.alloc(0),
          outputDirectory: retryOutput,
          preservationOutput: retryPreservation,
          expectedHeadSha: 'a'.repeat(40),
        }),
      (error) => error.code === 'E7_RELEASE_SUCCESSOR_RETRY_SOURCE_ARTIFACT_INVALID',
    );
    assert.equal(existsSync(retryOutput), false);
    assert.equal(existsSync(retryPreservation), false);
  } finally {
    rmSync(retryFixtureRoot, { recursive: true, force: true });
  }
  assert.equal(existsSync(retryFixtureRoot), false);
  return {
    status: 'PASS',
    canaries: 8,
    externalRequests: 0,
    selectionSha256: selection.selectionSha256,
  };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--self-test') {
    fail('E7_RELEASE_SUCCESSOR_RETRY_COMMAND_INVALID');
  }
  process.stdout.write(`${JSON.stringify(selfTestReleaseSuccessorRetry())}\n`);
}
