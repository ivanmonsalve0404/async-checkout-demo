import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import {
  canonicalJson,
  STAGE7_PROVIDER_EGRESS_CAPABILITY,
  createStage7PreviousReleaseManifest,
  objectSha256,
  validateFreezeManifest,
  validateStage7CandidateRollbackRecord,
  validateStage7Config,
  validateStage7PreviousReleaseForTarget,
  validateStage7PreviousReleaseHandoff,
  validateStage7PreviousReleaseManifest,
} from './core.mjs';
import {
  RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH,
  RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
  RELEASE_SUCCESSOR_SOURCE_LAYOUT,
  validateReleaseSuccessorCompletionFence,
  validateReleaseSuccessorConsumptionAuthority,
  validateReleaseSuccessorFinalDisableProvenance,
  validateReleaseSuccessorFinalizationMarker,
  validateReleaseSuccessorReconciliationAuthoritySources,
  validateReleaseSuccessorSourceBundleDirectory,
  validateReleaseSuccessorSourceProvenance,
} from './release-successor-handoff.mjs';
import {
  RELEASE_SUCCESSOR_CLEANUP_RECEIPT_ARTIFACT_PREFIX,
  RELEASE_SUCCESSOR_PRESERVATION_ARTIFACT_PREFIX,
  validateReleaseSuccessorJournalCleanupReceipt,
  validateReleaseSuccessorPreservationReceipt,
} from './release-successor-journal-cleanup.mjs';
import {
  createReleaseSuccessorStoredZipFixture,
  readReleaseSuccessorZipEntries,
} from './release-successor-zip.mjs';
import { validateReleaseSuccessorJournalSnapshot } from './release-successor-journal-snapshot.mjs';
import {
  createPreviousReleaseProjectionIndex,
  validatePreviousReleaseProjection,
} from './previous-release-projection.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const WORKFLOW_NAME = 'Stage 7 Release Successor Post-Success';
const MASTER_REF = 'refs/heads/master';
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const ARTIFACT_DIGEST = /^sha256:[0-9a-f]{64}$/u;

export const RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_NAME = WORKFLOW_NAME;

export class Stage7ReleaseSuccessorConsumerError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseSuccessorConsumerError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseSuccessorConsumerError(code, cause === undefined ? undefined : { cause });
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const utc = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return false;
  return new Date(value).toISOString() === value;
};
const withoutDigest = (value, field) => {
  const body = { ...value };
  delete body[field];
  return body;
};
const strictJson = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  let value;
  try {
    value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
  } catch (error) {
    fail(code, error);
  }
  if (!object(value)) fail(code);
  return { value, bytes, rawSha256: sha256(bytes), canonicalSha256: objectSha256(value) };
};
const normalizeAttempt = (value) =>
  Number.isSafeInteger(value) && value >= 1 && value <= 999 ? value : null;

const zipJsonPayload = ({ archive, path: pathName, onlyEntry, code }) => {
  let entries;
  try {
    entries = readReleaseSuccessorZipEntries(archive);
  } catch (error) {
    fail(code, error);
  }
  if ((onlyEntry && entries.size !== 1) || !entries.has(pathName)) fail(code);
  const document = strictJson(entries.get(pathName), code);
  if (document.value.containsSensitiveData !== false) fail(code);
  return {
    path: pathName,
    rawSha256: document.rawSha256,
    canonicalSha256: document.canonicalSha256,
    bytes: document.bytes.length,
  };
};

export const releaseSuccessorPostSuccessArtifactNames = ({
  sourceRunId,
  postSuccessRunAttempt,
}) => {
  if (!RUN_ID.test(sourceRunId ?? '') || normalizeAttempt(postSuccessRunAttempt) === null) {
    fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_ARTIFACT_IDENTITY_INVALID');
  }
  const suffix = `r${sourceRunId}-a${postSuccessRunAttempt}`;
  return Object.freeze({
    source: `stage7-release-successor-source-${suffix}`,
    preservation: `${RELEASE_SUCCESSOR_PRESERVATION_ARTIFACT_PREFIX}-${suffix}`,
    cleanup: `${RELEASE_SUCCESSOR_CLEANUP_RECEIPT_ARTIFACT_PREFIX}-${suffix}`,
  });
};

const observationBody = (value) => withoutDigest(value, 'observationSha256');

export const validateReleaseSuccessorPostSuccessObservation = (value, expected = {}) => {
  if (
    value?.artifacts?.some?.(({ expired }) => expired === true) ||
    value?.artifactInventory?.some?.(({ expired }) => expired === true)
  ) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_EXPIRED');
  }
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'repository',
      'workflowId',
      'workflowName',
      'workflowPath',
      'event',
      'ref',
      'headSha',
      'sourceRunId',
      'postSuccessRunId',
      'postSuccessRunAttempt',
      'sourcePreservationRunAttempt',
      'runStatus',
      'conclusion',
      'runResponseRawSha256',
      'runResponseCanonicalSha256',
      'workflowResponseRawSha256',
      'workflowResponseCanonicalSha256',
      'artifactsResponseRawSha256',
      'artifactsResponseCanonicalSha256',
      'artifactListRequests',
      'artifactInventoryCount',
      'artifactInventory',
      'artifactInventorySha256',
      'artifacts',
      'observedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'observationSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_OBSERVATION' ||
    value.status !== 'PASS' ||
    value.repository !== REPOSITORY ||
    !Number.isSafeInteger(value.workflowId) ||
    value.workflowId < 1 ||
    value.workflowName !== WORKFLOW_NAME ||
    value.workflowPath !== RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH ||
    value.event !== 'workflow_run' ||
    value.ref !== MASTER_REF ||
    !SHA.test(value.headSha ?? '') ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    !RUN_ID.test(value.postSuccessRunId ?? '') ||
    normalizeAttempt(value.postSuccessRunAttempt) === null ||
    normalizeAttempt(value.sourcePreservationRunAttempt) === null ||
    value.sourcePreservationRunAttempt > value.postSuccessRunAttempt ||
    value.runStatus !== 'completed' ||
    value.conclusion !== 'success' ||
    ![
      value.runResponseRawSha256,
      value.runResponseCanonicalSha256,
      value.workflowResponseRawSha256,
      value.workflowResponseCanonicalSha256,
      value.artifactsResponseRawSha256,
      value.artifactsResponseCanonicalSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !Array.isArray(value.artifacts) ||
    value.artifacts.length !== 3 ||
    !Number.isSafeInteger(value.artifactListRequests) ||
    value.artifactListRequests < 1 ||
    !Number.isSafeInteger(value.artifactInventoryCount) ||
    value.artifactInventoryCount < 3 ||
    !Array.isArray(value.artifactInventory) ||
    value.artifactInventory.length !== value.artifactInventoryCount ||
    value.artifactInventory.some(
      (entry) =>
        !exactKeys(entry, [
          'logicalName',
          'attempt',
          'name',
          'id',
          'digest',
          'expired',
          'workflowRunId',
        ]) ||
        !['source', 'preservation', 'cleanup'].includes(entry.logicalName) ||
        normalizeAttempt(entry.attempt) === null ||
        !Number.isSafeInteger(entry.id) ||
        entry.id < 1 ||
        !ARTIFACT_DIGEST.test(entry.digest ?? '') ||
        entry.expired !== false ||
        entry.workflowRunId !== value.postSuccessRunId,
    ) ||
    value.artifactInventorySha256 !== objectSha256(value.artifactInventory) ||
    !SHA256.test(value.artifactInventorySha256 ?? '') ||
    !utc(value.observedAtUtc) ||
    value.externalRequests !== 5 + value.artifactListRequests ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.observationSha256 !== objectSha256(observationBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_OBSERVATION_INVALID');
  }
  const sourceNames = releaseSuccessorPostSuccessArtifactNames({
    sourceRunId: value.sourceRunId,
    postSuccessRunAttempt: value.sourcePreservationRunAttempt,
  });
  const cleanupNames = releaseSuccessorPostSuccessArtifactNames({
    sourceRunId: value.sourceRunId,
    postSuccessRunAttempt: value.postSuccessRunAttempt,
  });
  const inventoryIdentities = new Set();
  for (const entry of value.artifactInventory) {
    const expectedName = releaseSuccessorPostSuccessArtifactNames({
      sourceRunId: value.sourceRunId,
      postSuccessRunAttempt: entry.attempt,
    })[entry.logicalName];
    const identity = `${entry.logicalName}\0${entry.attempt}`;
    if (
      entry.name !== expectedName ||
      entry.attempt > value.postSuccessRunAttempt ||
      inventoryIdentities.has(identity)
    ) {
      fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_ARTIFACT_INVENTORY_INVALID');
    }
    inventoryIdentities.add(identity);
  }
  if (
    !['source', 'preservation'].every((logicalName) =>
      inventoryIdentities.has(`${logicalName}\0${value.sourcePreservationRunAttempt}`),
    ) ||
    !inventoryIdentities.has(`cleanup\0${value.postSuccessRunAttempt}`)
  ) {
    fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_CURRENT_ARTIFACT_MISSING');
  }
  for (const [index, logicalName] of ['source', 'preservation', 'cleanup'].entries()) {
    const artifact = value.artifacts[index];
    const expectedAttempt =
      logicalName === 'cleanup' ? value.postSuccessRunAttempt : value.sourcePreservationRunAttempt;
    if (
      !exactKeys(artifact, [
        'logicalName',
        'attempt',
        'name',
        'id',
        'digest',
        'archiveRawSha256',
        'archiveBytes',
        'payload',
        'workflowRunId',
        'expired',
      ]) ||
      artifact.logicalName !== logicalName ||
      artifact.attempt !== expectedAttempt ||
      artifact.name !==
        (logicalName === 'cleanup' ? cleanupNames.cleanup : sourceNames[logicalName]) ||
      !Number.isSafeInteger(artifact.id) ||
      artifact.id < 1 ||
      !ARTIFACT_DIGEST.test(artifact.digest ?? '') ||
      artifact.archiveRawSha256 !== artifact.digest.slice('sha256:'.length) ||
      !Number.isSafeInteger(artifact.archiveBytes) ||
      artifact.archiveBytes < 1 ||
      !exactKeys(artifact.payload, ['path', 'rawSha256', 'canonicalSha256', 'bytes']) ||
      typeof artifact.payload.path !== 'string' ||
      !SHA256.test(artifact.payload.rawSha256 ?? '') ||
      !SHA256.test(artifact.payload.canonicalSha256 ?? '') ||
      !Number.isSafeInteger(artifact.payload.bytes) ||
      artifact.payload.bytes < 2 ||
      artifact.workflowRunId !== value.postSuccessRunId ||
      artifact.expired !== false
    ) {
      fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_ARTIFACT_INVALID');
    }
  }
  if (
    (expected.sourceRunId !== undefined && value.sourceRunId !== String(expected.sourceRunId)) ||
    (expected.postSuccessRunId !== undefined &&
      value.postSuccessRunId !== String(expected.postSuccessRunId)) ||
    (expected.postSuccessRunAttempt !== undefined &&
      value.postSuccessRunAttempt !== Number(expected.postSuccessRunAttempt)) ||
    (expected.sourcePreservationRunAttempt !== undefined &&
      value.sourcePreservationRunAttempt !== Number(expected.sourcePreservationRunAttempt)) ||
    (expected.headSha !== undefined && value.headSha !== expected.headSha)
  ) {
    fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_OBSERVATION_MISMATCH');
  }
  return value;
};

export const createReleaseSuccessorPostSuccessObservation = ({
  sourceRunId,
  runResponseSource,
  workflowResponseSource,
  artifactsResponseSource,
  artifactArchives,
  artifactListRequests,
  observedAtUtc,
}) => {
  const run = strictJson(runResponseSource, 'E7_RELEASE_SUCCESSOR_POST_SUCCESS_RUN_INVALID');
  const workflow = strictJson(
    workflowResponseSource,
    'E7_RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_INVALID',
  );
  const artifacts = strictJson(
    artifactsResponseSource,
    'E7_RELEASE_SUCCESSOR_POST_SUCCESS_ARTIFACTS_INVALID',
  );
  const apiRun = run.value;
  const apiWorkflow = workflow.value;
  const apiUpdatedAtUtc =
    typeof apiRun?.updated_at === 'string' && !Number.isNaN(Date.parse(apiRun.updated_at))
      ? new Date(apiRun.updated_at).toISOString()
      : null;
  const requestedObservedAtUtc =
    typeof observedAtUtc === 'string' && !Number.isNaN(Date.parse(observedAtUtc))
      ? new Date(observedAtUtc).toISOString()
      : null;
  if (
    !RUN_ID.test(sourceRunId ?? '') ||
    apiRun?.repository?.full_name !== REPOSITORY ||
    apiRun?.workflow_id !== apiWorkflow.id ||
    apiRun?.name !== WORKFLOW_NAME ||
    apiWorkflow?.name !== WORKFLOW_NAME ||
    apiWorkflow?.path !== RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH ||
    apiRun?.head_branch !== 'master' ||
    !SHA.test(apiRun?.head_sha ?? '') ||
    apiRun?.event !== 'workflow_run' ||
    apiRun?.status !== 'completed' ||
    apiRun?.conclusion !== 'success' ||
    !Number.isSafeInteger(apiRun?.id) ||
    normalizeAttempt(apiRun?.run_attempt) === null ||
    apiUpdatedAtUtc === null ||
    requestedObservedAtUtc !== apiUpdatedAtUtc ||
    !Array.isArray(artifacts.value?.artifacts) ||
    artifacts.value.total_count !== artifacts.value.artifacts.length ||
    !Number.isSafeInteger(artifactListRequests) ||
    artifactListRequests < 1 ||
    !object(artifactArchives)
  ) {
    fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_RUN_NOT_EXACT_SUCCESS');
  }
  if (artifacts.value.artifacts.some(({ expired } = {}) => expired === true)) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_EXPIRED');
  }
  const inventory = [];
  const seenLogicalAttempts = new Set();
  const physicalPatterns = Object.freeze({
    source: /^stage7-release-successor-source-r([1-9][0-9]{0,19})-a([1-9][0-9]{0,2})$/u,
    preservation: /^stage7-release-successor-preservation-r([1-9][0-9]{0,19})-a([1-9][0-9]{0,2})$/u,
    cleanup: /^stage7-release-successor-cleanup-receipt-r([1-9][0-9]{0,19})-a([1-9][0-9]{0,2})$/u,
  });
  for (const artifact of artifacts.value.artifacts) {
    const matches = Object.entries(physicalPatterns)
      .map(([logicalName, pattern]) => [logicalName, pattern.exec(artifact?.name ?? '')])
      .filter(([, match]) => match !== null);
    const logicalName = matches[0]?.[0];
    const match = matches[0]?.[1];
    const attempt = Number(match?.[2]);
    const identity = `${logicalName ?? ''}\0${attempt}`;
    if (
      matches.length !== 1 ||
      match[1] !== sourceRunId ||
      normalizeAttempt(attempt) === null ||
      attempt > apiRun.run_attempt ||
      seenLogicalAttempts.has(identity) ||
      !Number.isSafeInteger(artifact.id) ||
      artifact.id < 1 ||
      artifact.expired !== false ||
      artifact.workflow_run?.id !== apiRun.id ||
      !ARTIFACT_DIGEST.test(artifact.digest ?? '')
    ) {
      fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_ARTIFACT_INVENTORY_INVALID');
    }
    seenLogicalAttempts.add(identity);
    inventory.push({
      logicalName,
      attempt,
      name: artifact.name,
      id: artifact.id,
      digest: artifact.digest,
      expired: false,
      workflowRunId: String(apiRun.id),
    });
  }
  const durableAttempts = [...new Set(inventory.map(({ attempt }) => attempt))]
    .filter(
      (attempt) =>
        seenLogicalAttempts.has(`source\0${attempt}`) &&
        seenLogicalAttempts.has(`preservation\0${attempt}`),
    )
    .toSorted((left, right) => right - left);
  const sourcePreservationRunAttempt = durableAttempts[0];
  if (
    sourcePreservationRunAttempt === undefined ||
    !seenLogicalAttempts.has(`cleanup\0${apiRun.run_attempt}`)
  ) {
    fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_CURRENT_ARTIFACT_MISSING');
  }
  inventory.sort((left, right) =>
    left.attempt === right.attempt
      ? left.logicalName.localeCompare(right.logicalName)
      : left.attempt - right.attempt,
  );
  const selected = [];
  for (const logicalName of ['source', 'preservation', 'cleanup']) {
    const selectedAttempt =
      logicalName === 'cleanup' ? apiRun.run_attempt : sourcePreservationRunAttempt;
    const selectedName = releaseSuccessorPostSuccessArtifactNames({
      sourceRunId,
      postSuccessRunAttempt: selectedAttempt,
    })[logicalName];
    const matches = artifacts.value.artifacts.filter(({ name } = {}) => name === selectedName);
    const artifact = matches[0];
    const archive = Buffer.isBuffer(artifactArchives[logicalName])
      ? Buffer.from(artifactArchives[logicalName])
      : Buffer.from(artifactArchives[logicalName] ?? '');
    const digest = sha256(archive);
    if (
      matches.length !== 1 ||
      !Number.isSafeInteger(artifact?.id) ||
      artifact.id < 1 ||
      artifact.expired !== false ||
      artifact.workflow_run?.id !== apiRun.id ||
      artifact.digest !== `sha256:${digest}` ||
      archive.length < 1
    ) {
      fail('E7_RELEASE_SUCCESSOR_POST_SUCCESS_ARTIFACT_DIGEST_INVALID');
    }
    const payload = zipJsonPayload({
      archive,
      path:
        logicalName === 'source'
          ? RELEASE_SUCCESSOR_SOURCE_LAYOUT.index
          : logicalName === 'preservation'
            ? 'release-successor-preservation-receipt.json'
            : 'release-successor-journal-cleanup-receipt.json',
      onlyEntry: logicalName !== 'source',
      code: 'E7_RELEASE_SUCCESSOR_POST_SUCCESS_ARTIFACT_PAYLOAD_INVALID',
    });
    selected.push({
      logicalName,
      attempt: selectedAttempt,
      name: artifact.name,
      id: artifact.id,
      digest: artifact.digest,
      archiveRawSha256: digest,
      archiveBytes: archive.length,
      payload,
      workflowRunId: String(apiRun.id),
      expired: false,
    });
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_OBSERVATION',
    status: 'PASS',
    repository: REPOSITORY,
    workflowId: apiWorkflow.id,
    workflowName: WORKFLOW_NAME,
    workflowPath: RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH,
    event: 'workflow_run',
    ref: MASTER_REF,
    headSha: apiRun.head_sha,
    sourceRunId,
    postSuccessRunId: String(apiRun.id),
    postSuccessRunAttempt: apiRun.run_attempt,
    sourcePreservationRunAttempt,
    runStatus: 'completed',
    conclusion: 'success',
    runResponseRawSha256: run.rawSha256,
    runResponseCanonicalSha256: run.canonicalSha256,
    workflowResponseRawSha256: workflow.rawSha256,
    workflowResponseCanonicalSha256: workflow.canonicalSha256,
    artifactsResponseRawSha256: artifacts.rawSha256,
    artifactsResponseCanonicalSha256: artifacts.canonicalSha256,
    artifactListRequests,
    artifactInventoryCount: inventory.length,
    artifactInventory: inventory,
    artifactInventorySha256: objectSha256(inventory),
    artifacts: selected,
    observedAtUtc: apiUpdatedAtUtc,
    externalRequests: 5 + artifactListRequests,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return validateReleaseSuccessorPostSuccessObservation({
    ...body,
    observationSha256: objectSha256(body),
  });
};

const readLifecycle = (sourceBundle) => {
  const protectedRun = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackProtectedRun],
    'E7_RELEASE_SUCCESSOR_CONSUMER_LIFECYCLE_SOURCE_INVALID',
  ).value;
  const lifecycle = protectedRun?.runtimeAttestation?.journalLifecycle;
  if (
    !object(lifecycle) ||
    lifecycle.lifecycleSha256 !== sourceBundle.provenance.journalLifecycleSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_CONSUMER_LIFECYCLE_INVALID');
  }
  return lifecycle;
};

export const validateReleaseSuccessorConsumerInputs = ({
  sourceBundleDirectory,
  preservationReceiptSource,
  cleanupReceiptSource,
  postSuccessObservationSource,
}) => {
  const sourceBundle = validateReleaseSuccessorSourceBundleDirectory(sourceBundleDirectory);
  const preservation = strictJson(
    preservationReceiptSource,
    'E7_RELEASE_SUCCESSOR_CONSUMER_PRESERVATION_INVALID',
  );
  const cleanup = strictJson(cleanupReceiptSource, 'E7_RELEASE_SUCCESSOR_CONSUMER_CLEANUP_INVALID');
  const observation = strictJson(
    postSuccessObservationSource,
    'E7_RELEASE_SUCCESSOR_CONSUMER_OBSERVATION_INVALID',
  );
  validateReleaseSuccessorPreservationReceipt(preservation.value, { sourceBundle });
  const lifecycle = readLifecycle(sourceBundle);
  validateReleaseSuccessorJournalCleanupReceipt(cleanup.value, {
    preservationReceipt: preservation.value,
    lifecycle,
    reconciliationJournalAuthority: sourceBundle.provenance.reconciliationJournalAuthority,
  });
  validateReleaseSuccessorPostSuccessObservation(observation.value, {
    sourceRunId: sourceBundle.provenance.sourceRunId,
    postSuccessRunId: preservation.value.postSuccessRunId,
    headSha: sourceBundle.provenance.headSha,
  });
  const sourceArtifact = observation.value.artifacts[0];
  const preservationArtifact = observation.value.artifacts[1];
  const cleanupArtifact = observation.value.artifacts[2];
  const sourceIndex = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.index],
    'E7_RELEASE_SUCCESSOR_CONSUMER_SOURCE_INDEX_INVALID',
  );
  if (
    cleanup.value.status !== 'PASS' ||
    sourceArtifact.attempt !== preservation.value.postSuccessRunAttempt ||
    preservationArtifact.attempt !== preservation.value.postSuccessRunAttempt ||
    observation.value.sourcePreservationRunAttempt !== preservation.value.postSuccessRunAttempt ||
    sourceArtifact.id !== preservation.value.sourceArtifact.id ||
    sourceArtifact.digest !== preservation.value.sourceArtifact.digest ||
    sourceArtifact.name !== preservation.value.sourceArtifact.physicalName ||
    sourceArtifact.payload.rawSha256 !== sourceIndex.rawSha256 ||
    sourceArtifact.payload.canonicalSha256 !== sourceIndex.canonicalSha256 ||
    sourceArtifact.payload.bytes !== sourceIndex.bytes.length ||
    preservationArtifact.payload.rawSha256 !== preservation.rawSha256 ||
    preservationArtifact.payload.canonicalSha256 !== preservation.canonicalSha256 ||
    preservationArtifact.payload.bytes !== preservation.bytes.length ||
    cleanupArtifact.payload.rawSha256 !== cleanup.rawSha256 ||
    cleanupArtifact.payload.canonicalSha256 !== cleanup.canonicalSha256 ||
    cleanupArtifact.payload.bytes !== cleanup.bytes.length ||
    cleanup.value.postSuccessRunId !== observation.value.postSuccessRunId ||
    cleanup.value.postSuccessRunAttempt !== observation.value.postSuccessRunAttempt ||
    Date.parse(cleanup.value.completedAtUtc) > Date.parse(observation.value.observedAtUtc)
  ) {
    fail('E7_RELEASE_SUCCESSOR_CONSUMER_CLEANUP_NOT_SAME_SUCCESSFUL_RUN');
  }
  const artifactAuthority = (artifact) => ({
    attempt: artifact.attempt,
    id: artifact.id,
    digest: artifact.digest,
    archiveRawSha256: artifact.archiveRawSha256,
    payloadRawSha256: artifact.payload.rawSha256,
  });
  const consumptionBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_CONSUMPTION_AUTHORITY',
    status: 'SAME_POST_SUCCESS_RUN_VERIFIED',
    sourceRunId: sourceBundle.provenance.sourceRunId,
    headSha: sourceBundle.provenance.headSha,
    postSuccessRunId: observation.value.postSuccessRunId,
    postSuccessRunAttempt: observation.value.postSuccessRunAttempt,
    sourcePreservationRunAttempt: observation.value.sourcePreservationRunAttempt,
    sourceArtifact: artifactAuthority(sourceArtifact),
    preservationArtifact: artifactAuthority(preservationArtifact),
    cleanupArtifact: artifactAuthority(cleanupArtifact),
    preservationReceiptSha256: preservation.value.preservationReceiptSha256,
    cleanupReceiptSha256: cleanup.value.cleanupReceiptSha256,
    postSuccessObservationSha256: observation.value.observationSha256,
    artifactInventorySha256: observation.value.artifactInventorySha256,
    containsSensitiveData: false,
  };
  const consumptionAuthority = {
    ...consumptionBody,
    consumptionAuthoritySha256: objectSha256(consumptionBody),
  };
  return {
    sourceBundle,
    preservationReceipt: preservation.value,
    cleanupReceipt: cleanup.value,
    postSuccessObservation: observation.value,
    lifecycle,
    consumptionAuthority,
  };
};

const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
const journalSnapshotBinding = (document) => ({
  path: RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot,
  rawSha256: document.rawSha256,
  canonicalSha256: document.canonicalSha256,
  bytes: document.bytes.length,
  snapshotSha256: document.value.snapshotSha256,
  targetNameSetSha256: document.value.targetNameSetSha256,
  entryCount: document.value.entryCount,
});

const projectionSources = (sourceBundle) => {
  const readJson = (name, code) => strictJson(sourceBundle.files[name], code);
  return {
    config: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.config,
      'E7_RELEASE_SUCCESSOR_PROJECTION_CONFIG_INVALID',
    ),
    freeze: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.freeze,
      'E7_RELEASE_SUCCESSOR_PROJECTION_SOURCE_FREEZE_INVALID',
    ),
    predecessor: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessor,
      'E7_RELEASE_SUCCESSOR_PROJECTION_PREDECESSOR_INVALID',
    ),
    candidateRecord: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.candidateRecord,
      'E7_RELEASE_SUCCESSOR_PROJECTION_CANDIDATE_INVALID',
    ),
    approval: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.approval,
      'E7_RELEASE_SUCCESSOR_PROJECTION_APPROVAL_INVALID',
    ),
    closeout: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.closeout,
      'E7_RELEASE_SUCCESSOR_PROJECTION_CLOSEOUT_INVALID',
    ),
    releaseFence: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.releaseFence,
      'E7_RELEASE_SUCCESSOR_PROJECTION_RELEASE_FENCE_INVALID',
    ),
    reconciliationRollbackCheck: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackCheck,
      'E7_RELEASE_SUCCESSOR_PROJECTION_RECONCILIATION_ROLLBACK_CHECK_INVALID',
    ),
    reconciliationRollbackResilience: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackResilience,
      'E7_RELEASE_SUCCESSOR_PROJECTION_RECONCILIATION_ROLLBACK_RESILIENCE_INVALID',
    ),
    preFenceGate: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.preFenceGate,
      'E7_RELEASE_SUCCESSOR_PROJECTION_PRE_FENCE_GATE_INVALID',
    ),
    protectedRun: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackProtectedRun,
      'E7_RELEASE_SUCCESSOR_PROJECTION_PROTECTED_RUN_INVALID',
    ),
    journalSnapshot: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot,
      'E7_RELEASE_SUCCESSOR_PROJECTION_JOURNAL_SNAPSHOT_INVALID',
    ),
    marker: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalizationMarker,
      'E7_RELEASE_SUCCESSOR_PROJECTION_MARKER_INVALID',
    ),
    finalDisable: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalDisable,
      'E7_RELEASE_SUCCESSOR_PROJECTION_FINAL_DISABLE_INVALID',
    ),
    apiContract: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.apiContract,
      'E7_RELEASE_SUCCESSOR_PROJECTION_API_INVALID',
    ),
    pending: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.pendingReconciliation,
      'E7_RELEASE_SUCCESSOR_PROJECTION_PENDING_INVALID',
    ),
    smoke: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.smoke,
      'E7_RELEASE_SUCCESSOR_PROJECTION_SMOKE_INVALID',
    ),
    completion: readJson(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackCompletion,
      'E7_RELEASE_SUCCESSOR_PROJECTION_COMPLETION_INVALID',
    ),
  };
};

const createReleaseSuccessorTargetProjection = ({
  sourceBundle,
  consumptionAuthority,
  targetConfigSource,
  targetFreezeSource,
  capturedAtUtc,
}) => {
  if (!object(sourceBundle) || !object(sourceBundle.files) || !utc(capturedAtUtc)) {
    fail('E7_RELEASE_SUCCESSOR_PROJECTION_OPTIONS_INVALID');
  }
  const source = projectionSources(sourceBundle);
  const targetConfigDocument = strictJson(
    targetConfigSource,
    'E7_RELEASE_SUCCESSOR_TARGET_CONFIG_INVALID',
  );
  const targetFreezeDocument = strictJson(
    targetFreezeSource,
    'E7_RELEASE_SUCCESSOR_TARGET_FREEZE_INVALID',
  );
  let sourceConfig;
  let sourceFreeze;
  let predecessor;
  let candidateRecord;
  let targetConfig;
  let targetFreeze;
  try {
    sourceConfig = validateStage7Config(source.config.value, {
      now: new Date(source.config.value.window.startsAtUtc),
    });
    sourceFreeze = validateFreezeManifest(source.freeze.value);
    predecessor = validateStage7PreviousReleaseManifest(source.predecessor.value);
    candidateRecord = validateStage7CandidateRollbackRecord(source.candidateRecord.value, {
      previousManifest: predecessor,
    });
    targetConfig = validateStage7Config(targetConfigDocument.value, {
      now: new Date(targetConfigDocument.value.window.startsAtUtc),
    });
    targetFreeze = validateFreezeManifest(targetFreezeDocument.value);
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_PROJECTION_IDENTITY_INVALID', error);
  }
  const targetIac = targetFreeze.artifacts.find(({ name }) => name === 'iac');
  const provenance = validateReleaseSuccessorSourceProvenance(sourceBundle.provenance);
  const reconciliation = validateReleaseSuccessorReconciliationAuthoritySources({
    rollbackCheckSource: source.reconciliationRollbackCheck.bytes,
    rollbackResilienceSource: source.reconciliationRollbackResilience.bytes,
    preFenceGateSource: source.preFenceGate.bytes,
    expected: {
      sourceRunId: provenance.sourceRunId,
      sourceRunAttempt: provenance.sourceRunAttempt,
      candidateSha: sourceFreeze.candidateSha,
      releaseId: sourceFreeze.releaseId,
      releaseTag: sourceFreeze.releaseTag,
    },
  });
  const consumption = validateReleaseSuccessorConsumptionAuthority(consumptionAuthority, {
    sourceRunId: provenance.sourceRunId,
    headSha: provenance.headSha,
  });
  validateReleaseSuccessorJournalSnapshot(source.journalSnapshot.value, {
    reconciliationJournalAuthority: reconciliation.authority,
    rollbackCheckReceipt: reconciliation.rollbackCheck.value,
    rollbackResilienceReceipt: reconciliation.rollbackResilience.value,
    protectedRun: source.protectedRun.value,
  });
  const expectedJournalSnapshotBinding = journalSnapshotBinding(source.journalSnapshot);
  if (
    sourceBundle.index.bundleSha256 !== provenance.bundleSha256 ||
    sourceBundle.index.sourceHeadSha !== sourceFreeze.candidateSha ||
    provenance.reconciliationJournalAuthoritySha256 !==
      reconciliation.authority.journalAuthoritySha256 ||
    canonicalJson(provenance.reconciliationJournalAuthority) !==
      canonicalJson(reconciliation.authority) ||
    canonicalJson(provenance.reconciliationEvidenceBindings) !==
      canonicalJson(reconciliation.bindings) ||
    canonicalJson(provenance.journalSnapshotBinding) !==
      canonicalJson(expectedJournalSnapshotBinding) ||
    canonicalJson(sourceBundle.index.journalSnapshotBinding) !==
      canonicalJson(expectedJournalSnapshotBinding) ||
    sourceConfig.environment !== targetConfig.environment ||
    sourceConfig.aws.region !== targetConfig.aws.region ||
    sourceConfig.aws.accountId !== targetConfig.aws.accountId ||
    targetConfig.authorization.scope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    targetFreeze.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    targetFreeze.configSha256 !== objectSha256(targetConfig) ||
    targetFreeze.candidateSha === sourceFreeze.candidateSha ||
    targetFreeze.releaseId === sourceFreeze.releaseId ||
    targetFreeze.releaseTag === sourceFreeze.releaseTag ||
    Date.parse(targetFreeze.builtAt) <= Date.parse(sourceFreeze.builtAt) ||
    Date.parse(capturedAtUtc) < Date.parse(targetFreeze.builtAt) ||
    targetFreeze.openApiSha256 !== source.apiContract.value.openApiSha256 ||
    targetFreeze.generatedClientSha256 !== source.apiContract.value.generatedClientSha256 ||
    targetIac === undefined ||
    predecessor.target.candidateSha !== sourceFreeze.candidateSha ||
    candidateRecord.target.candidateSha !== sourceFreeze.candidateSha
  ) {
    fail('E7_RELEASE_SUCCESSOR_TARGET_NOT_IMMEDIATE_COMPATIBLE');
  }
  const releaseFence = validateReleaseSuccessorCompletionFence(source.releaseFence.value, {
    candidateSha: sourceFreeze.candidateSha,
    releaseId: sourceFreeze.releaseId,
    sourceRunId: provenance.sourceRunId,
    sourceRunAttempt: provenance.sourceRunAttempt,
    journalLifecycleSha256: provenance.journalLifecycleSha256,
  });
  validateReleaseSuccessorFinalizationMarker(source.marker.value, {
    candidateSha: sourceFreeze.candidateSha,
    releaseId: sourceFreeze.releaseId,
    sourceRunId: provenance.sourceRunId,
    sourceRunAttempt: provenance.sourceRunAttempt,
    releaseEvidenceSetSha256: provenance.releaseEvidenceSetSha256,
    journalLifecycleSha256: provenance.journalLifecycleSha256,
    releaseFenceSha256: releaseFence.fenceSha256,
    journalRoleAuthoritySha256: source.marker.value.journalRoleAuthoritySha256,
  });
  const finalDisable = validateReleaseSuccessorFinalDisableProvenance(source.finalDisable.value, {
    candidateSha: sourceFreeze.candidateSha,
    releaseId: sourceFreeze.releaseId,
    sourceRunId: provenance.sourceRunId,
    sourceRunAttempt: provenance.sourceRunAttempt,
    releaseEvidenceSetSha256: provenance.releaseEvidenceSetSha256,
    journalLifecycleSha256: provenance.journalLifecycleSha256,
    releaseFenceDocument: source.releaseFence,
    markerDocument: source.marker,
    earliestUtc: provenance.capturedAtUtc,
  });
  const sourceArtifactProvenanceSha256 = objectSha256(provenance);
  const finalDisableEvidenceSha256 = objectSha256(finalDisable);
  const compatibilityBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_COMPATIBILITY',
    status: 'PASS',
    baselineBundleSha256: provenance.bundleSha256,
    sourceArtifactProvenanceSha256,
    finalDisableEvidenceSha256,
    consumptionAuthoritySha256: consumption.consumptionAuthoritySha256,
    reconciliationJournalAuthoritySha256: reconciliation.authority.journalAuthoritySha256,
    releaseFenceAuthoritySetSha256: provenance.releaseFenceAuthoritySetSha256,
    journalSnapshotBinding: expectedJournalSnapshotBinding,
    predecessorManifestSha256: predecessor.manifestSha256,
    previousCandidateSha: sourceFreeze.candidateSha,
    previousReleaseId: sourceFreeze.releaseId,
    targetCandidateSha: targetFreeze.candidateSha,
    targetReleaseId: targetFreeze.releaseId,
    targetFreezeManifestSha256: targetFreeze.manifestSha256,
    schemaStrategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
    dataRollback: 'FORBIDDEN_FORWARD_ONLY',
    apiContractRawSha256: source.apiContract.rawSha256,
    apiContractCanonicalSha256: source.apiContract.canonicalSha256,
    pendingReconciliationRawSha256: source.pending.rawSha256,
    pendingReconciliationCanonicalSha256: source.pending.canonicalSha256,
    smokeRawSha256: source.smoke.rawSha256,
    smokeCanonicalSha256: source.smoke.canonicalSha256,
    originProtectionContractSha256:
      source.completion.value.versionedRollbackRehearsal.resilience.originProtectionContractSha256,
    verifiedAtUtc: capturedAtUtc,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const targetCompatibility = {
    ...compatibilityBody,
    compatibilitySha256: objectSha256(compatibilityBody),
  };
  const approval = source.approval.value;
  const previousRelease = createStage7PreviousReleaseManifest({
    schemaVersion: 1,
    stage: 7,
    kind: 'PREVIOUS_APPROVED_RELEASE',
    status: 'APPROVED_IMMUTABLE',
    capturedAtUtc,
    approvedAtUtc: approval.approvedAtUtc,
    environment: targetConfig.environment,
    region: targetConfig.aws.region,
    previous: { ...candidateRecord.target },
    target: {
      candidateSha: targetFreeze.candidateSha,
      candidateTreeSha: targetFreeze.candidateTreeSha,
      releaseId: targetFreeze.releaseId,
      releaseTag: targetFreeze.releaseTag,
      configSha256: objectSha256(targetConfig),
      freezeManifestSha256: targetFreeze.manifestSha256,
      assemblySha256: targetIac.sha256,
    },
    resources: candidateRecord.resources,
    compatibility: {
      status: 'PASS',
      schemaStrategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
      dataRollback: 'FORBIDDEN_FORWARD_ONLY',
      apiContractEvidenceSha256: source.apiContract.rawSha256,
      pendingReconciliationEvidenceSha256: source.pending.rawSha256,
      smokeEvidenceSha256: source.smoke.rawSha256,
      smokeVerifiedAtUtc: source.smoke.value.verifiedAtUtc,
      providerEgressCapability: STAGE7_PROVIDER_EGRESS_CAPABILITY,
    },
    handoff: {
      sourceKind: 'RELEASE_SUCCESSOR',
      sourceBundleSha256: provenance.bundleSha256,
      sourceArtifactProvenanceSha256,
      targetCompatibilityEvidenceSha256: objectSha256(targetCompatibility),
      finalDisableEvidenceSha256,
      predecessorManifestSha256: predecessor.manifestSha256,
    },
    approval: {
      status: 'APPROVED',
      reviewerAlias: approval.reviewerAlias,
      approvalEvidenceSha256: source.approval.rawSha256,
      releaseEvidenceSha256: source.closeout.rawSha256,
    },
    containsSensitiveData: false,
  });
  validateStage7PreviousReleaseForTarget(previousRelease, {
    config: targetConfig,
    freezeManifest: targetFreeze,
  });
  validateStage7PreviousReleaseHandoff(previousRelease, {
    sourceProvenance: provenance,
    targetCompatibility,
    finalDisableProvenance: finalDisable,
  });
  const files = {
    'previous-release-manifest.json': jsonBytes(previousRelease),
    'previous-source-provenance.json':
      sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance],
    'previous-target-compatibility.json': jsonBytes(targetCompatibility),
    'previous-final-disable-provenance.json':
      sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalDisable],
    'previous-api-contract-evidence.json':
      sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.apiContract],
    'previous-pending-evidence.json':
      sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.pendingReconciliation],
    'previous-smoke-evidence.json': sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.smoke],
  };
  const index = createPreviousReleaseProjectionIndex({
    sourceKind: 'RELEASE_SUCCESSOR',
    sourceBundle: {
      artifactName: RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
      bundleSha256: provenance.bundleSha256,
      sourceRunId: provenance.sourceRunId,
      sourceRunAttempt: provenance.sourceRunAttempt,
      headSha: provenance.headSha,
      consumptionAuthoritySha256: consumption.consumptionAuthoritySha256,
      reconciliationJournalAuthority: reconciliation.authority,
      reconciliationJournalAuthoritySha256: reconciliation.authority.journalAuthoritySha256,
      releaseFenceAuthoritySetSha256: provenance.releaseFenceAuthoritySetSha256,
      journalSnapshotBinding: expectedJournalSnapshotBinding,
    },
    previousReleaseManifest: previousRelease,
    files,
  });
  files['previous-release-projection-index.json'] = jsonBytes(index);
  return {
    files,
    index,
    previousRelease,
    sourceProvenance: provenance,
    targetCompatibility,
    finalDisableProvenance: finalDisable,
  };
};

const writeReleaseSuccessorTargetProjection = ({
  sourceBundleDirectory,
  consumptionAuthority,
  targetConfigSource,
  targetFreezeSource,
  capturedAtUtc,
  outputDirectory,
}) => {
  if (existsSync(outputDirectory)) fail('E7_PREVIOUS_RELEASE_PROJECTION_OUTPUT_EXISTS');
  const sourceBundle = validateReleaseSuccessorSourceBundleDirectory(sourceBundleDirectory);
  const projection = createReleaseSuccessorTargetProjection({
    sourceBundle,
    consumptionAuthority,
    targetConfigSource,
    targetFreezeSource,
    capturedAtUtc,
  });
  mkdirSync(outputDirectory, { recursive: false, mode: 0o700 });
  try {
    for (const [name, bytes] of Object.entries(projection.files)) {
      writeFileSync(path.join(outputDirectory, name), bytes, { flag: 'wx', mode: 0o600 });
    }
    return validatePreviousReleaseProjection(outputDirectory);
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    throw error;
  }
};

export const createVerifiedReleaseSuccessorTargetProjection = ({
  sourceBundleDirectory,
  preservationReceiptSource,
  cleanupReceiptSource,
  postSuccessObservationSource,
  targetConfigSource,
  targetFreezeSource,
  capturedAtUtc,
}) => {
  const validated = validateReleaseSuccessorConsumerInputs({
    sourceBundleDirectory,
    preservationReceiptSource,
    cleanupReceiptSource,
    postSuccessObservationSource,
  });
  return createReleaseSuccessorTargetProjection({
    sourceBundle: validated.sourceBundle,
    consumptionAuthority: validated.consumptionAuthority,
    targetConfigSource,
    targetFreezeSource,
    capturedAtUtc,
  });
};

export const writeVerifiedReleaseSuccessorTargetProjection = ({
  sourceBundleDirectory,
  preservationReceiptPath,
  cleanupReceiptPath,
  postSuccessObservationPath,
  targetConfigSource,
  targetFreezeSource,
  capturedAtUtc,
  outputDirectory,
}) => {
  const validated = validateReleaseSuccessorConsumerInputs({
    sourceBundleDirectory,
    preservationReceiptSource: readFileSync(preservationReceiptPath),
    cleanupReceiptSource: readFileSync(cleanupReceiptPath),
    postSuccessObservationSource: readFileSync(postSuccessObservationPath),
  });
  return writeReleaseSuccessorTargetProjection({
    sourceBundleDirectory,
    consumptionAuthority: validated.consumptionAuthority,
    targetConfigSource,
    targetFreezeSource,
    capturedAtUtc,
    outputDirectory,
  });
};

export const selfTestReleaseSuccessorConsumerObservation = () => {
  const sourceRunId = '123456789';
  const postSuccessRunId = 22334455;
  const headSha = 'a'.repeat(40);
  const attempt = 2;
  const storedZip = (name, contentValue) =>
    createReleaseSuccessorStoredZipFixture({
      [name]: Buffer.from(`${JSON.stringify(contentValue)}\n`),
    });
  const archives = {
    source: storedZip(RELEASE_SUCCESSOR_SOURCE_LAYOUT.index, {
      kind: 'STAGE7_RELEASE_SUCCESSOR_SOURCE_BUNDLE',
      containsSensitiveData: false,
    }),
    preservation: storedZip('release-successor-preservation-receipt.json', {
      kind: 'RELEASE_SUCCESSOR_DURABLE_HANDOFF_RECEIPT',
      containsSensitiveData: false,
    }),
    cleanup: storedZip('release-successor-journal-cleanup-receipt.json', {
      kind: 'RELEASE_SUCCESSOR_SSM_JOURNAL_CLEANUP_RECEIPT',
      containsSensitiveData: false,
    }),
  };
  const priorNames = releaseSuccessorPostSuccessArtifactNames({
    sourceRunId,
    postSuccessRunAttempt: 1,
  });
  const currentNames = releaseSuccessorPostSuccessArtifactNames({
    sourceRunId,
    postSuccessRunAttempt: attempt,
  });
  const artifacts = [
    {
      id: 10,
      name: priorNames.source,
      digest: `sha256:${sha256(archives.source)}`,
      expired: false,
      workflow_run: { id: postSuccessRunId },
    },
    {
      id: 11,
      name: priorNames.preservation,
      digest: `sha256:${sha256(archives.preservation)}`,
      expired: false,
      workflow_run: { id: postSuccessRunId },
    },
    {
      id: 12,
      name: priorNames.cleanup,
      digest: `sha256:${'9'.repeat(64)}`,
      expired: false,
      workflow_run: { id: postSuccessRunId },
    },
    {
      id: 13,
      name: currentNames.cleanup,
      digest: `sha256:${sha256(archives.cleanup)}`,
      expired: false,
      workflow_run: { id: postSuccessRunId },
    },
  ];
  const run = {
    id: postSuccessRunId,
    run_attempt: attempt,
    workflow_id: 44,
    name: WORKFLOW_NAME,
    head_branch: 'master',
    head_sha: headSha,
    event: 'workflow_run',
    status: 'completed',
    conclusion: 'success',
    updated_at: '2026-08-18T06:00:00Z',
    repository: { full_name: REPOSITORY },
  };
  const encode = (value) => Buffer.from(`${JSON.stringify(value)}\n`);
  const options = {
    sourceRunId,
    runResponseSource: encode(run),
    workflowResponseSource: encode({
      id: 44,
      name: WORKFLOW_NAME,
      path: RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH,
    }),
    artifactsResponseSource: encode({ total_count: artifacts.length, artifacts }),
    artifactArchives: archives,
    artifactListRequests: 1,
    observedAtUtc: run.updated_at,
  };
  const observation = createReleaseSuccessorPostSuccessObservation(options);
  assert.equal(observation.externalRequests, 6);
  assert.equal(observation.sourcePreservationRunAttempt, 1);
  assert.deepEqual(
    observation.artifacts.map(({ attempt: artifactAttempt }) => artifactAttempt),
    [1, 1, 2],
  );
  assert.throws(
    () =>
      createReleaseSuccessorPostSuccessObservation({
        ...options,
        runResponseSource: encode({ ...run, status: 'in_progress', conclusion: null }),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_POST_SUCCESS_RUN_NOT_EXACT_SUCCESS',
  );
  assert.throws(
    () =>
      createReleaseSuccessorPostSuccessObservation({
        ...options,
        artifactArchives: { ...archives, cleanup: Buffer.from('tampered') },
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_POST_SUCCESS_ARTIFACT_DIGEST_INVALID',
  );
  assert.throws(
    () =>
      createReleaseSuccessorPostSuccessObservation({
        ...options,
        artifactsResponseSource: encode({
          total_count: artifacts.length,
          artifacts: artifacts.map((artifact, index) =>
            index === 0 ? { ...artifact, expired: true } : artifact,
          ),
        }),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_SOURCE_EXPIRED',
  );
  return {
    status: 'PASS',
    canaries: 5,
    externalRequests: 0,
    observationSha256: observation.observationSha256,
  };
};
