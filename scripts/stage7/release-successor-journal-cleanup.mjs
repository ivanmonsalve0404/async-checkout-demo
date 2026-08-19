import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256 } from './core.mjs';
import {
  STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT,
  STAGE7_RELEASE_RECONCILIATION_SMOKE_USAGE_IDS,
  createReleasePreFenceGate,
  createReleaseReconciliationIntent,
  createReleaseReconciliationReceipt,
  createReleaseRollbackJournalOwner,
} from './release-reconciliation.mjs';
import {
  RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
  RELEASE_SUCCESSOR_SOURCE_LAYOUT,
  validateReleaseSuccessorReconciliationAuthoritySources,
  validateReleaseSuccessorSourceIndex,
  validateReleaseSuccessorSourceProvenance,
} from './release-successor-handoff.mjs';
import {
  validateReleaseSuccessorCallerAuthority,
  validateReleaseSuccessorFinalizationAuthority,
} from './release-successor-finalization.mjs';
import { createReleaseSuccessorIamAuthoritySelfTestFixture } from './release-successor-iam-authority.mjs';
import {
  createReleaseSuccessorStoredZipFixture,
  readReleaseSuccessorZipEntries,
} from './release-successor-zip.mjs';
import { validateReleaseReconciliationTerminal } from './release-reconciliation-executor.mjs';
import {
  captureReleaseSuccessorJournalSnapshot,
  requeryReleaseSuccessorJournalSnapshot,
  validateReleaseSuccessorJournalSnapshot,
} from './release-successor-journal-snapshot.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const ARTIFACT_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const SOURCE_ARTIFACT_NAME =
  /^stage7-release-successor-source-r([1-9][0-9]{0,19})-a([1-9][0-9]{0,2})$/u;
const MAX_PAGES_PER_PREFIX = 1000;

export const RELEASE_SUCCESSOR_PRESERVATION_ARTIFACT_PREFIX =
  'stage7-release-successor-preservation';
export const RELEASE_SUCCESSOR_CLEANUP_RECEIPT_ARTIFACT_PREFIX =
  'stage7-release-successor-cleanup-receipt';

export class Stage7ReleaseSuccessorCleanupError extends Error {
  constructor(code, { cause, receipt } = {}) {
    super(code, cause === undefined ? undefined : { cause });
    this.name = 'Stage7ReleaseSuccessorCleanupError';
    this.code = code;
    this.receipt = receipt;
  }
}

const fail = (code, options = {}) => {
  throw new Stage7ReleaseSuccessorCleanupError(code, options);
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
const strictJson = (source, code, { requirePublic = true } = {}) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  let value;
  try {
    value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
  } catch (error) {
    fail(code, { cause: error });
  }
  if (!object(value) || (requirePublic && value.containsSensitiveData !== false)) fail(code);
  return { value, bytes, rawSha256: sha256(bytes), canonicalSha256: objectSha256(value) };
};
const normalizeAttempt = (value) =>
  Number.isSafeInteger(value) && value >= 1 && value <= 999 ? value : null;
const parameterNotFound = (error) =>
  error?.code === 'ParameterNotFound' ||
  error?.name === 'ParameterNotFound' ||
  /ParameterNotFound/u.test(error?.message ?? '');

const validateSourceBundleObject = (sourceBundle) => {
  const expectedPaths = Object.values(RELEASE_SUCCESSOR_SOURCE_LAYOUT).toSorted();
  if (
    !object(sourceBundle) ||
    !object(sourceBundle.files) ||
    Object.keys(sourceBundle.files).toSorted().join('\0') !== expectedPaths.join('\0') ||
    Object.values(sourceBundle.files).some((bytes) => !Buffer.isBuffer(bytes))
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_SOURCE_BUNDLE_INVALID');
  }
  validateReleaseSuccessorSourceProvenance(sourceBundle.provenance);
  validateReleaseSuccessorSourceIndex(sourceBundle.index, {
    provenance: sourceBundle.provenance,
  });
  const provenanceDocument = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance],
    'E7_RELEASE_SUCCESSOR_CLEANUP_SOURCE_PROVENANCE_INVALID',
  );
  const indexDocument = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.index],
    'E7_RELEASE_SUCCESSOR_CLEANUP_SOURCE_INDEX_INVALID',
  );
  if (
    provenanceDocument.canonicalSha256 !== objectSha256(sourceBundle.provenance) ||
    indexDocument.canonicalSha256 !== objectSha256(sourceBundle.index) ||
    objectSha256(sourceBundle.provenance.files) !== sourceBundle.provenance.bundleSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_SOURCE_BUNDLE_MISMATCH');
  }
  for (const entry of [...sourceBundle.provenance.files, ...sourceBundle.index.files]) {
    const bytes = sourceBundle.files[entry.path];
    if (!Buffer.isBuffer(bytes) || bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) {
      fail('E7_RELEASE_SUCCESSOR_CLEANUP_SOURCE_RAW_DIGEST_MISMATCH');
    }
  }
  for (const [pathName, digest] of Object.entries(sourceBundle.provenance.canonicalSha256ByPath)) {
    if (
      strictJson(
        sourceBundle.files[pathName],
        'E7_RELEASE_SUCCESSOR_CLEANUP_SOURCE_DOCUMENT_INVALID',
      ).canonicalSha256 !== digest
    ) {
      fail('E7_RELEASE_SUCCESSOR_CLEANUP_SOURCE_CANONICAL_DIGEST_MISMATCH');
    }
  }
  const reconciliation = validateReleaseSuccessorReconciliationAuthoritySources({
    rollbackCheckSource:
      sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackCheck],
    rollbackResilienceSource:
      sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackResilience],
    preFenceGateSource: sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.preFenceGate],
    expected: {
      sourceRunId: sourceBundle.provenance.sourceRunId,
      sourceRunAttempt: sourceBundle.provenance.sourceRunAttempt,
      candidateSha: sourceBundle.provenance.headSha,
      releaseId: sourceBundle.provenance.releaseId,
    },
  });
  const protectedRun = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackProtectedRun],
    'E7_RELEASE_SUCCESSOR_CLEANUP_PROTECTED_RUN_INVALID',
  ).value;
  const journalSnapshotDocument = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot],
    'E7_RELEASE_SUCCESSOR_CLEANUP_JOURNAL_SNAPSHOT_INVALID',
  );
  validateReleaseSuccessorJournalSnapshot(journalSnapshotDocument.value, {
    reconciliationJournalAuthority: reconciliation.authority,
    rollbackCheckReceipt: reconciliation.rollbackCheck.value,
    rollbackResilienceReceipt: reconciliation.rollbackResilience.value,
    protectedRun,
  });
  const journalSnapshotBinding = {
    path: RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot,
    rawSha256: journalSnapshotDocument.rawSha256,
    canonicalSha256: journalSnapshotDocument.canonicalSha256,
    bytes: journalSnapshotDocument.bytes.length,
    snapshotSha256: journalSnapshotDocument.value.snapshotSha256,
    targetNameSetSha256: journalSnapshotDocument.value.targetNameSetSha256,
    entryCount: journalSnapshotDocument.value.entryCount,
  };
  if (
    sourceBundle.provenance.reconciliationJournalAuthoritySha256 !==
      reconciliation.authority.journalAuthoritySha256 ||
    objectSha256(sourceBundle.provenance.reconciliationJournalAuthority) !==
      objectSha256(reconciliation.authority) ||
    objectSha256(sourceBundle.provenance.reconciliationEvidenceBindings) !==
      objectSha256(reconciliation.bindings) ||
    sourceBundle.index.reconciliationJournalAuthoritySha256 !==
      reconciliation.authority.journalAuthoritySha256 ||
    objectSha256(sourceBundle.provenance.journalSnapshotBinding) !==
      objectSha256(journalSnapshotBinding) ||
    objectSha256(sourceBundle.index.journalSnapshotBinding) !== objectSha256(journalSnapshotBinding)
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_RECONCILIATION_AUTHORITY_MISMATCH');
  }
  return {
    ...sourceBundle,
    reconciliation,
    journalSnapshot: journalSnapshotDocument.value,
    journalSnapshotBinding,
  };
};

const preservationBody = (value) => withoutDigest(value, 'preservationReceiptSha256');

export const createReleaseSuccessorPreservationReceipt = ({
  sourceBundle,
  artifactApiSource,
  artifactArchiveSource,
  postSuccessRunId,
  postSuccessRunAttempt,
  postSuccessHeadSha,
  preservedAtUtc,
}) => {
  const validatedSourceBundle = validateSourceBundleObject(sourceBundle);
  const artifactResponse = strictJson(
    artifactApiSource,
    'E7_RELEASE_SUCCESSOR_SOURCE_ARTIFACT_RESPONSE_INVALID',
    { requirePublic: false },
  );
  const artifact = artifactResponse.value;
  const archive = Buffer.isBuffer(artifactArchiveSource)
    ? Buffer.from(artifactArchiveSource)
    : Buffer.from(artifactArchiveSource ?? '');
  let archiveEntries;
  try {
    archiveEntries = readReleaseSuccessorZipEntries(archive);
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_ARTIFACT_ZIP_INVALID', { cause: error });
  }
  const expectedPaths = Object.keys(sourceBundle.files).toSorted();
  if (
    [...archiveEntries.keys()].toSorted().join('\0') !== expectedPaths.join('\0') ||
    expectedPaths.some(
      (pathName) => !Buffer.from(sourceBundle.files[pathName]).equals(archiveEntries.get(pathName)),
    )
  ) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_ARTIFACT_CONTENT_MISMATCH');
  }
  const match = SOURCE_ARTIFACT_NAME.exec(artifact.name ?? '');
  if (
    !Number.isSafeInteger(artifact.id) ||
    artifact.id < 1 ||
    match === null ||
    match[1] !== sourceBundle.provenance.sourceRunId ||
    Number(match[2]) !== postSuccessRunAttempt ||
    !ARTIFACT_DIGEST.test(artifact.digest ?? '') ||
    artifact.digest !== `sha256:${sha256(archive)}` ||
    artifact.expired !== false ||
    !Number.isSafeInteger(artifact.workflow_run?.id) ||
    artifact.workflow_run.id < 1 ||
    String(artifact.workflow_run.id) !== String(postSuccessRunId) ||
    !RUN_ID.test(String(postSuccessRunId ?? '')) ||
    normalizeAttempt(postSuccessRunAttempt) === null ||
    !SHA.test(postSuccessHeadSha ?? '') ||
    postSuccessHeadSha !== sourceBundle.provenance.headSha ||
    !utc(preservedAtUtc) ||
    Date.parse(preservedAtUtc) < Date.parse(sourceBundle.provenance.capturedAtUtc)
  ) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NOT_DURABLE');
  }
  const marker = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalizationMarker],
    'E7_RELEASE_SUCCESSOR_PRESERVATION_MARKER_INVALID',
  );
  const finalization = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalDisable],
    'E7_RELEASE_SUCCESSOR_PRESERVATION_FINALIZATION_INVALID',
  ).value;
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_DURABLE_HANDOFF_RECEIPT',
    status: 'DURABLE_REQUERY_VERIFIED',
    sourceRunId: sourceBundle.provenance.sourceRunId,
    sourceRunAttempt: sourceBundle.provenance.sourceRunAttempt,
    postSuccessRunId: String(artifact.workflow_run.id),
    postSuccessRunAttempt,
    headSha: sourceBundle.provenance.headSha,
    sourceArtifact: {
      logicalName: RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
      physicalName: artifact.name,
      id: artifact.id,
      digest: artifact.digest,
      archiveRawSha256: sha256(archive),
      archiveBytes: archive.length,
      apiResponseRawSha256: artifactResponse.rawSha256,
      apiResponseCanonicalSha256: artifactResponse.canonicalSha256,
    },
    sourceBundleSha256: sourceBundle.index.bundleSha256,
    sourceIndexSha256: sourceBundle.index.indexSha256,
    sourceProvenanceSha256: sourceBundle.provenance.provenanceSha256,
    releaseEvidenceSetSha256: sourceBundle.provenance.releaseEvidenceSetSha256,
    finalizationMarkerSha256: marker.value.markerSha256,
    journalLifecycleSha256: sourceBundle.provenance.journalLifecycleSha256,
    reconciliationJournalAuthoritySha256:
      sourceBundle.provenance.reconciliationJournalAuthoritySha256,
    journalSnapshotBinding: validatedSourceBundle.journalSnapshotBinding,
    journalRoleAuthoritySha256: marker.value.journalRoleAuthoritySha256,
    callerAttemptAuthoritySha256: finalization.authority?.callerAttemptAuthoritySha256,
    auditEvidenceSha256: finalization.authority?.auditEvidenceSha256,
    preservedAtUtc,
    containsSensitiveData: false,
  };
  return validateReleaseSuccessorPreservationReceipt({
    ...body,
    preservationReceiptSha256: objectSha256(body),
  });
};

export const validateReleaseSuccessorPreservationReceipt = (value, { sourceBundle } = {}) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'sourceRunId',
      'sourceRunAttempt',
      'postSuccessRunId',
      'postSuccessRunAttempt',
      'headSha',
      'sourceArtifact',
      'sourceBundleSha256',
      'sourceIndexSha256',
      'sourceProvenanceSha256',
      'releaseEvidenceSetSha256',
      'finalizationMarkerSha256',
      'journalLifecycleSha256',
      'reconciliationJournalAuthoritySha256',
      'journalSnapshotBinding',
      'journalRoleAuthoritySha256',
      'callerAttemptAuthoritySha256',
      'auditEvidenceSha256',
      'preservedAtUtc',
      'containsSensitiveData',
      'preservationReceiptSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_DURABLE_HANDOFF_RECEIPT' ||
    value.status !== 'DURABLE_REQUERY_VERIFIED' ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    !Number.isSafeInteger(value.sourceRunAttempt) ||
    value.sourceRunAttempt < 1 ||
    !RUN_ID.test(value.postSuccessRunId ?? '') ||
    normalizeAttempt(value.postSuccessRunAttempt) === null ||
    !SHA.test(value.headSha ?? '') ||
    !exactKeys(value.sourceArtifact, [
      'logicalName',
      'physicalName',
      'id',
      'digest',
      'archiveRawSha256',
      'archiveBytes',
      'apiResponseRawSha256',
      'apiResponseCanonicalSha256',
    ]) ||
    value.sourceArtifact.logicalName !== RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME ||
    SOURCE_ARTIFACT_NAME.exec(value.sourceArtifact.physicalName ?? '')?.[1] !== value.sourceRunId ||
    Number(SOURCE_ARTIFACT_NAME.exec(value.sourceArtifact.physicalName ?? '')?.[2]) !==
      value.postSuccessRunAttempt ||
    !Number.isSafeInteger(value.sourceArtifact.id) ||
    value.sourceArtifact.id < 1 ||
    !ARTIFACT_DIGEST.test(value.sourceArtifact.digest ?? '') ||
    value.sourceArtifact.archiveRawSha256 !== value.sourceArtifact.digest.slice('sha256:'.length) ||
    !Number.isSafeInteger(value.sourceArtifact.archiveBytes) ||
    value.sourceArtifact.archiveBytes < 1 ||
    ![
      value.sourceArtifact.apiResponseRawSha256,
      value.sourceArtifact.apiResponseCanonicalSha256,
      value.sourceBundleSha256,
      value.sourceIndexSha256,
      value.sourceProvenanceSha256,
      value.releaseEvidenceSetSha256,
      value.finalizationMarkerSha256,
      value.journalLifecycleSha256,
      value.reconciliationJournalAuthoritySha256,
      value.journalRoleAuthoritySha256,
      value.callerAttemptAuthoritySha256,
      value.auditEvidenceSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !utc(value.preservedAtUtc) ||
    !exactKeys(value.journalSnapshotBinding, [
      'path',
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'snapshotSha256',
      'targetNameSetSha256',
      'entryCount',
    ]) ||
    value.journalSnapshotBinding.path !== RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot ||
    ![
      value.journalSnapshotBinding.rawSha256,
      value.journalSnapshotBinding.canonicalSha256,
      value.journalSnapshotBinding.snapshotSha256,
      value.journalSnapshotBinding.targetNameSetSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !Number.isSafeInteger(value.journalSnapshotBinding.bytes) ||
    value.journalSnapshotBinding.bytes < 2 ||
    !Number.isSafeInteger(value.journalSnapshotBinding.entryCount) ||
    value.journalSnapshotBinding.entryCount < 3 ||
    value.containsSensitiveData !== false ||
    value.preservationReceiptSha256 !== objectSha256(preservationBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_PRESERVATION_RECEIPT_INVALID');
  }
  if (sourceBundle !== undefined) {
    const validatedSourceBundle = validateSourceBundleObject(sourceBundle);
    const marker = strictJson(
      sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalizationMarker],
      'E7_RELEASE_SUCCESSOR_PRESERVATION_MARKER_INVALID',
    ).value;
    const finalization = strictJson(
      sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalDisable],
      'E7_RELEASE_SUCCESSOR_PRESERVATION_FINALIZATION_INVALID',
    ).value;
    if (
      value.sourceRunId !== sourceBundle.provenance.sourceRunId ||
      value.sourceRunAttempt !== sourceBundle.provenance.sourceRunAttempt ||
      value.headSha !== sourceBundle.provenance.headSha ||
      value.sourceBundleSha256 !== sourceBundle.index.bundleSha256 ||
      value.sourceIndexSha256 !== sourceBundle.index.indexSha256 ||
      value.sourceProvenanceSha256 !== sourceBundle.provenance.provenanceSha256 ||
      value.releaseEvidenceSetSha256 !== sourceBundle.provenance.releaseEvidenceSetSha256 ||
      value.finalizationMarkerSha256 !== marker.markerSha256 ||
      value.journalLifecycleSha256 !== sourceBundle.provenance.journalLifecycleSha256 ||
      value.reconciliationJournalAuthoritySha256 !==
        sourceBundle.provenance.reconciliationJournalAuthoritySha256 ||
      objectSha256(value.journalSnapshotBinding) !==
        objectSha256(validatedSourceBundle.journalSnapshotBinding) ||
      value.journalRoleAuthoritySha256 !== marker.journalRoleAuthoritySha256 ||
      value.callerAttemptAuthoritySha256 !== finalization.authority?.callerAttemptAuthoritySha256 ||
      value.auditEvidenceSha256 !== finalization.authority?.auditEvidenceSha256
    ) {
      fail('E7_RELEASE_SUCCESSOR_PRESERVATION_SOURCE_MISMATCH');
    }
  }
  return value;
};

const cleanupReceiptBody = (value) => withoutDigest(value, 'cleanupReceiptSha256');

export const validateReleaseSuccessorJournalCleanupReceipt = (
  value,
  { preservationReceipt, lifecycle, reconciliationJournalAuthority } = {},
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'sourceRunId',
      'postSuccessRunId',
      'postSuccessRunAttempt',
      'sourcePreservationRunAttempt',
      'sourceArtifactId',
      'sourceArtifactDigest',
      'sourceBundleSha256',
      'preservationReceiptSha256',
      'finalizationMarkerSha256',
      'journalLifecycleSha256',
      'cleanupScopeSha256',
      'journalCleanupRoleSha256',
      'journalRoleAuthoritySha256',
      'callerAttemptAuthoritySha256',
      'auditEvidenceSha256',
      'journalSnapshotBinding',
      'scenarioPrefixes',
      'reconciliationJournalAuthority',
      'reconciliationJournalAuthoritySha256',
      'cleanupTargetSet',
      'cleanupTargetSetSha256',
      'preDeleteObservedEntrySetSha256',
      'preDeleteObservedNameSetSha256',
      'preDeleteMissingNameSetSha256',
      'preDeleteMissingCount',
      'discoveredNameSetSha256',
      'deletedNameSetSha256',
      'remainingNameSetSha256',
      'discoveredCount',
      'deletedCount',
      'failedCount',
      'remainingCount',
      'listPages',
      'deleteRequests',
      'authorityReadRequests',
      'externalRequests',
      'idempotent',
      'startedAtUtc',
      'completedAtUtc',
      'containsSensitiveData',
      'cleanupReceiptSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_SSM_JOURNAL_CLEANUP_RECEIPT' ||
    !['PASS', 'FAILED_PARTIAL_DELETE', 'FAILED_DELETE_ERROR'].includes(value.status) ||
    !SHA.test(value.candidateSha ?? '') ||
    typeof value.releaseId !== 'string' ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    !RUN_ID.test(value.postSuccessRunId ?? '') ||
    normalizeAttempt(value.postSuccessRunAttempt) === null ||
    normalizeAttempt(value.sourcePreservationRunAttempt) === null ||
    value.sourcePreservationRunAttempt > value.postSuccessRunAttempt ||
    !Number.isSafeInteger(value.sourceArtifactId) ||
    value.sourceArtifactId < 1 ||
    !ARTIFACT_DIGEST.test(value.sourceArtifactDigest ?? '') ||
    ![
      value.sourceBundleSha256,
      value.preservationReceiptSha256,
      value.finalizationMarkerSha256,
      value.journalLifecycleSha256,
      value.cleanupScopeSha256,
      value.journalCleanupRoleSha256,
      value.journalRoleAuthoritySha256,
      value.callerAttemptAuthoritySha256,
      value.auditEvidenceSha256,
      value.journalSnapshotBinding?.rawSha256,
      value.journalSnapshotBinding?.canonicalSha256,
      value.journalSnapshotBinding?.snapshotSha256,
      value.journalSnapshotBinding?.targetNameSetSha256,
      value.reconciliationJournalAuthoritySha256,
      value.cleanupTargetSetSha256,
      value.preDeleteObservedEntrySetSha256,
      value.preDeleteObservedNameSetSha256,
      value.preDeleteMissingNameSetSha256,
      value.discoveredNameSetSha256,
      value.deletedNameSetSha256,
      value.remainingNameSetSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !exactKeys(value.scenarioPrefixes, ['RB-E7-06', 'RB-E7-08']) ||
    !exactKeys(value.journalSnapshotBinding, [
      'path',
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'snapshotSha256',
      'targetNameSetSha256',
      'entryCount',
    ]) ||
    value.journalSnapshotBinding.path !== RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot ||
    !Number.isSafeInteger(value.journalSnapshotBinding.bytes) ||
    value.journalSnapshotBinding.bytes < 2 ||
    !Number.isSafeInteger(value.journalSnapshotBinding.entryCount) ||
    value.journalSnapshotBinding.entryCount < 3 ||
    !Object.values(value.scenarioPrefixes).every((prefix) =>
      /^\/checkout\/stage7\/rollback\/[0-9a-f]{40}\/RB-E7-(?:06|08)$/u.test(prefix),
    ) ||
    !object(value.reconciliationJournalAuthority) ||
    value.reconciliationJournalAuthority.kind !==
      'STAGE7_RELEASE_RECONCILIATION_JOURNAL_AUTHORITY' ||
    value.reconciliationJournalAuthority.status !== 'PRESERVE_THEN_DELETE_EXACT_SET' ||
    value.reconciliationJournalAuthority.journalAuthoritySha256 !==
      value.reconciliationJournalAuthoritySha256 ||
    value.reconciliationJournalAuthoritySha256 !==
      objectSha256(withoutDigest(value.reconciliationJournalAuthority, 'journalAuthoritySha256')) ||
    value.reconciliationJournalAuthority.source?.candidateSha !== value.candidateSha ||
    value.reconciliationJournalAuthority.source?.runId !== value.sourceRunId ||
    value.reconciliationJournalAuthority.requiredResidualCount !== 0 ||
    !Array.isArray(value.reconciliationJournalAuthority.cleanupParameterNames) ||
    value.reconciliationJournalAuthority.cleanupParameterNames.length !==
      value.reconciliationJournalAuthority.cleanupParameterCount ||
    new Set(value.reconciliationJournalAuthority.cleanupParameterNames).size !==
      value.reconciliationJournalAuthority.cleanupParameterNames.length ||
    !exactKeys(value.cleanupTargetSet, [
      'scenarioPrefixes',
      'reconciliationParameterNames',
      'parameterNames',
      'targetNameSetSha256',
      'parameterCount',
    ]) ||
    objectSha256(value.cleanupTargetSet.scenarioPrefixes) !==
      objectSha256(value.scenarioPrefixes) ||
    !Array.isArray(value.cleanupTargetSet.reconciliationParameterNames) ||
    value.cleanupTargetSet.reconciliationParameterNames.join('\0') !==
      value.reconciliationJournalAuthority.cleanupParameterNames.join('\0') ||
    !Array.isArray(value.cleanupTargetSet.parameterNames) ||
    value.cleanupTargetSet.parameterNames.length !== value.cleanupTargetSet.parameterCount ||
    value.cleanupTargetSet.parameterNames.length !== value.journalSnapshotBinding.entryCount ||
    new Set(value.cleanupTargetSet.parameterNames).size !==
      value.cleanupTargetSet.parameterNames.length ||
    value.cleanupTargetSet.parameterNames.join('\0') !==
      [...value.cleanupTargetSet.parameterNames]
        .toSorted((left, right) => left.localeCompare(right))
        .join('\0') ||
    value.cleanupTargetSet.targetNameSetSha256 !==
      objectSha256(value.cleanupTargetSet.parameterNames) ||
    value.cleanupTargetSet.targetNameSetSha256 !==
      value.journalSnapshotBinding.targetNameSetSha256 ||
    value.cleanupTargetSetSha256 !== objectSha256(value.cleanupTargetSet) ||
    ![
      value.discoveredCount,
      value.deletedCount,
      value.failedCount,
      value.remainingCount,
      value.listPages,
      value.deleteRequests,
      value.authorityReadRequests,
      value.externalRequests,
      value.preDeleteMissingCount,
    ].every((count) => Number.isSafeInteger(count) && count >= 0) ||
    value.discoveredCount + value.preDeleteMissingCount !== value.cleanupTargetSet.parameterCount ||
    value.deletedCount > value.discoveredCount ||
    value.deleteRequests !== value.deletedCount + value.failedCount ||
    value.authorityReadRequests < 7 ||
    value.externalRequests !==
      value.listPages + value.deleteRequests + value.authorityReadRequests ||
    value.idempotent !== (value.discoveredCount === 0 && value.status === 'PASS') ||
    !utc(value.startedAtUtc) ||
    !utc(value.completedAtUtc) ||
    Date.parse(value.completedAtUtc) < Date.parse(value.startedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.cleanupReceiptSha256 !== objectSha256(cleanupReceiptBody(value)) ||
    (value.status === 'PASS' && (value.remainingCount !== 0 || value.failedCount !== 0)) ||
    (value.status === 'FAILED_PARTIAL_DELETE' && value.remainingCount === 0) ||
    (value.status === 'FAILED_DELETE_ERROR' &&
      (value.remainingCount !== 0 || value.failedCount === 0))
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_RECEIPT_INVALID');
  }
  if (
    [preservationReceipt, lifecycle, reconciliationJournalAuthority].some(
      (entry) => entry !== undefined,
    ) &&
    [preservationReceipt, lifecycle, reconciliationJournalAuthority].some(
      (entry) => entry === undefined,
    )
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_RECEIPT_EXPECTED_AUTHORITY_INCOMPLETE');
  }
  if (
    preservationReceipt !== undefined &&
    lifecycle !== undefined &&
    reconciliationJournalAuthority !== undefined
  ) {
    validateReleaseSuccessorPreservationReceipt(preservationReceipt);
    if (
      value.sourceRunId !== preservationReceipt.sourceRunId ||
      value.postSuccessRunId !== preservationReceipt.postSuccessRunId ||
      value.sourcePreservationRunAttempt !== preservationReceipt.postSuccessRunAttempt ||
      value.sourceArtifactId !== preservationReceipt.sourceArtifact.id ||
      value.sourceArtifactDigest !== preservationReceipt.sourceArtifact.digest ||
      value.sourceBundleSha256 !== preservationReceipt.sourceBundleSha256 ||
      value.preservationReceiptSha256 !== preservationReceipt.preservationReceiptSha256 ||
      value.finalizationMarkerSha256 !== preservationReceipt.finalizationMarkerSha256 ||
      value.journalLifecycleSha256 !== lifecycle.lifecycleSha256 ||
      value.cleanupScopeSha256 !== lifecycle.cleanupScopeSha256 ||
      value.journalCleanupRoleSha256 !== lifecycle.cleanupRoleSha256 ||
      value.journalRoleAuthoritySha256 !== preservationReceipt.journalRoleAuthoritySha256 ||
      objectSha256(value.scenarioPrefixes) !== objectSha256(lifecycle.scenarioPrefixes) ||
      value.reconciliationJournalAuthoritySha256 !==
        preservationReceipt.reconciliationJournalAuthoritySha256 ||
      objectSha256(value.journalSnapshotBinding) !==
        objectSha256(preservationReceipt.journalSnapshotBinding) ||
      objectSha256(value.reconciliationJournalAuthority) !==
        objectSha256(reconciliationJournalAuthority) ||
      value.cleanupTargetSetSha256 !==
        objectSha256({
          scenarioPrefixes: lifecycle.scenarioPrefixes,
          reconciliationParameterNames: reconciliationJournalAuthority.cleanupParameterNames,
          parameterNames: value.cleanupTargetSet.parameterNames,
          targetNameSetSha256: value.journalSnapshotBinding.targetNameSetSha256,
          parameterCount: value.journalSnapshotBinding.entryCount,
        })
    ) {
      fail('E7_RELEASE_SUCCESSOR_CLEANUP_RECEIPT_BINDING_INVALID');
    }
  }
  return value;
};

const hashNameSet = (names) => objectSha256([...names].toSorted().map((name) => sha256(name)));

const listExactPrefix = async ({ prefix, getParametersByPath }) => {
  const names = [];
  const seenTokens = new Set();
  let nextToken;
  let pages = 0;
  do {
    if (pages >= MAX_PAGES_PER_PREFIX) fail('E7_RELEASE_SUCCESSOR_CLEANUP_PAGINATION_LIMIT');
    const response = await getParametersByPath({
      path: prefix,
      recursive: true,
      withDecryption: false,
      maxResults: 10,
      ...(nextToken === undefined ? {} : { nextToken }),
    });
    pages += 1;
    if (!Array.isArray(response?.Parameters)) {
      fail('E7_RELEASE_SUCCESSOR_CLEANUP_LIST_RESPONSE_INVALID');
    }
    for (const parameter of response.Parameters) {
      const name = parameter?.Name;
      if (typeof name !== 'string' || !name.startsWith(`${prefix}/`)) {
        fail('E7_RELEASE_SUCCESSOR_CLEANUP_PARAMETER_OUTSIDE_SCOPE');
      }
      names.push(name);
    }
    nextToken = response.NextToken;
    if (nextToken !== undefined) {
      if (typeof nextToken !== 'string' || nextToken.length < 1 || seenTokens.has(nextToken)) {
        fail('E7_RELEASE_SUCCESSOR_CLEANUP_PAGINATION_INVALID');
      }
      seenTokens.add(nextToken);
    }
  } while (nextToken !== undefined);
  if (new Set(names).size !== names.length) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_DUPLICATE_PARAMETER');
  }
  return { names, pages };
};

const listJournal = async ({
  scenarioPrefixes,
  reconciliationJournalAuthority,
  getParametersByPath,
}) => {
  const names = [];
  let pages = 0;
  for (const scenarioId of ['RB-E7-06', 'RB-E7-08']) {
    const result = await listExactPrefix({
      prefix: scenarioPrefixes[scenarioId],
      getParametersByPath,
    });
    names.push(...result.names);
    pages += result.pages;
  }
  const reconciliation = await listExactPrefix({
    prefix: reconciliationJournalAuthority.reconciliationRootPrefix,
    getParametersByPath,
  });
  const allowedReconciliationNames = [
    ...reconciliationJournalAuthority.cleanupParameterNames,
  ].toSorted();
  if (reconciliation.names.some((name) => !allowedReconciliationNames.includes(name))) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_RECONCILIATION_PARAMETER_OUTSIDE_SCOPE');
  }
  names.push(...reconciliation.names);
  pages += reconciliation.pages;
  if (new Set(names).size !== names.length) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_CROSS_PREFIX_DUPLICATE');
  }
  return { names: names.toSorted(), pages };
};

export const cleanupReleaseSuccessorJournal = async ({
  sourceBundle,
  preservationReceipt,
  journalCleanupRoleArn,
  rollbackRoleArn,
  ephemeralCleanupRoleArn,
  callerIdentitySource,
  awsVersionSource,
  roleAuditSource,
  awsAuthSource,
  frozenEffectivePermissionsSource,
  liveEffectivePermissionsSource,
  postSuccessRunId,
  postSuccessRunAttempt,
  expectedSessionName,
  expectedPermissionsBoundaryArn,
  getParametersByPath,
  deleteParameter,
  now = () => new Date(),
}) => {
  const validatedSourceBundle = validateSourceBundleObject(sourceBundle);
  const reconciliationJournalAuthority = validatedSourceBundle.reconciliation.authority;
  validateReleaseSuccessorPreservationReceipt(preservationReceipt, { sourceBundle });
  if (
    !RUN_ID.test(String(postSuccessRunId ?? '')) ||
    normalizeAttempt(postSuccessRunAttempt) === null ||
    String(postSuccessRunId) !== preservationReceipt.postSuccessRunId ||
    postSuccessRunAttempt < preservationReceipt.postSuccessRunAttempt ||
    expectedSessionName !==
      `e7-release-journal-${String(postSuccessRunId)}-${postSuccessRunAttempt}` ||
    typeof getParametersByPath !== 'function' ||
    typeof deleteParameter !== 'function'
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_ADAPTER_REQUIRED');
  }
  const protectedRun = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackProtectedRun],
    'E7_RELEASE_SUCCESSOR_CLEANUP_PROTECTED_RUN_INVALID',
  ).value;
  const lifecycle = protectedRun?.runtimeAttestation?.journalLifecycle;
  const finalization = strictJson(
    sourceBundle.files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalDisable],
    'E7_RELEASE_SUCCESSOR_CLEANUP_FINALIZATION_INVALID',
  ).value;
  const expectedScenarioPrefixes = {
    'RB-E7-06': `/checkout/stage7/rollback/${sourceBundle.provenance.headSha}/RB-E7-06`,
    'RB-E7-08': `/checkout/stage7/rollback/${sourceBundle.provenance.headSha}/RB-E7-08`,
  };
  if (
    lifecycle?.status !== 'PENDING_POST_CLOSEOUT_CLEANUP' ||
    lifecycle?.deleteBeforeBoundaryAllowed !== false ||
    lifecycle?.cleanupAttempted !== false ||
    lifecycle?.retentionBoundary !== 'FINAL_EVIDENCE_AND_SUCCESSOR_HANDOFF_PRESERVED' ||
    objectSha256(lifecycle?.scenarioPrefixes) !== objectSha256(expectedScenarioPrefixes) ||
    reconciliationJournalAuthority.source.candidateSha !== sourceBundle.provenance.headSha ||
    reconciliationJournalAuthority.source.runId !== sourceBundle.provenance.sourceRunId ||
    reconciliationJournalAuthority.source.runAttempt !== sourceBundle.provenance.sourceRunAttempt ||
    reconciliationJournalAuthority.requiredResidualCount !== 0 ||
    preservationReceipt.reconciliationJournalAuthoritySha256 !==
      reconciliationJournalAuthority.journalAuthoritySha256 ||
    objectSha256(preservationReceipt.journalSnapshotBinding) !==
      objectSha256(validatedSourceBundle.journalSnapshotBinding) ||
    preservationReceipt.status !== 'DURABLE_REQUERY_VERIFIED' ||
    Date.parse(preservationReceipt.preservedAtUtc) < Date.parse(finalization.completedAtUtc)
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_BOUNDARY_NOT_PRESERVED');
  }
  validateReleaseSuccessorFinalizationAuthority({
    journalCleanupRoleArn,
    rollbackRoleArn,
    ephemeralCleanupRoleArn,
    lifecycleCleanupRoleSha256: lifecycle.cleanupRoleSha256,
  });
  const callerAuthority = validateReleaseSuccessorCallerAuthority({
    callerIdentitySource,
    awsVersionSource,
    roleAuditSource,
    awsAuthSource,
    frozenEffectivePermissionsSource,
    liveEffectivePermissionsSource,
    journalCleanupRoleArn,
    expectedSessionName,
    expectedAwsCliVersion: finalization.authority?.roleAuthority?.awsCliVersion,
    expectedPermissionsBoundaryArn,
  });
  if (
    finalization.authority?.journalCleanupRoleSha256 !== lifecycle.cleanupRoleSha256 ||
    finalization.authority?.rollbackRoleSha256 !== sha256(rollbackRoleArn) ||
    finalization.authority?.ephemeralCleanupRoleSha256 !== sha256(ephemeralCleanupRoleArn) ||
    finalization.authority?.rolesDistinct !== true ||
    callerAuthority.roleAuthoritySha256 !== finalization.authority?.roleAuthoritySha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_AUTHORITY_MISMATCH');
  }
  const startedAtUtc = now().toISOString();
  const liveSnapshot = await requeryReleaseSuccessorJournalSnapshot({
    snapshot: validatedSourceBundle.journalSnapshot,
    getParametersByPath,
  });
  if (
    postSuccessRunAttempt === preservationReceipt.postSuccessRunAttempt &&
    liveSnapshot.missingNames.length !== 0
  ) {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_INITIAL_SET_INCOMPLETE');
  }
  const initial = {
    names: liveSnapshot.observedNames,
    pages: liveSnapshot.listPages,
  };
  const deleted = [];
  const failures = [];
  for (const name of initial.names) {
    try {
      await deleteParameter({ name });
      deleted.push(name);
    } catch (error) {
      if (parameterNotFound(error)) deleted.push(name);
      else failures.push({ name, error });
    }
  }
  const remaining = await listJournal({
    scenarioPrefixes: lifecycle.scenarioPrefixes,
    reconciliationJournalAuthority,
    getParametersByPath,
  });
  const completedAtUtc = now().toISOString();
  const status =
    failures.length === 0 && remaining.names.length === 0
      ? 'PASS'
      : remaining.names.length > 0
        ? 'FAILED_PARTIAL_DELETE'
        : 'FAILED_DELETE_ERROR';
  const cleanupTargetSet = {
    scenarioPrefixes: lifecycle.scenarioPrefixes,
    reconciliationParameterNames: reconciliationJournalAuthority.cleanupParameterNames,
    parameterNames: validatedSourceBundle.journalSnapshot.entries.map(({ name }) => name),
    targetNameSetSha256: validatedSourceBundle.journalSnapshot.targetNameSetSha256,
    parameterCount: validatedSourceBundle.journalSnapshot.entryCount,
  };
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_SSM_JOURNAL_CLEANUP_RECEIPT',
    status,
    candidateSha: sourceBundle.provenance.headSha,
    releaseId: sourceBundle.provenance.releaseId,
    sourceRunId: sourceBundle.provenance.sourceRunId,
    postSuccessRunId: String(postSuccessRunId),
    postSuccessRunAttempt,
    sourcePreservationRunAttempt: preservationReceipt.postSuccessRunAttempt,
    sourceArtifactId: preservationReceipt.sourceArtifact.id,
    sourceArtifactDigest: preservationReceipt.sourceArtifact.digest,
    sourceBundleSha256: sourceBundle.index.bundleSha256,
    preservationReceiptSha256: preservationReceipt.preservationReceiptSha256,
    finalizationMarkerSha256: preservationReceipt.finalizationMarkerSha256,
    journalLifecycleSha256: lifecycle.lifecycleSha256,
    cleanupScopeSha256: lifecycle.cleanupScopeSha256,
    journalCleanupRoleSha256: lifecycle.cleanupRoleSha256,
    journalRoleAuthoritySha256: callerAuthority.roleAuthoritySha256,
    callerAttemptAuthoritySha256: callerAuthority.callerAttemptAuthoritySha256,
    auditEvidenceSha256: callerAuthority.auditEvidenceSha256,
    journalSnapshotBinding: validatedSourceBundle.journalSnapshotBinding,
    scenarioPrefixes: lifecycle.scenarioPrefixes,
    reconciliationJournalAuthority,
    reconciliationJournalAuthoritySha256: reconciliationJournalAuthority.journalAuthoritySha256,
    cleanupTargetSet,
    cleanupTargetSetSha256: objectSha256(cleanupTargetSet),
    preDeleteObservedEntrySetSha256: liveSnapshot.observedEntrySetSha256,
    preDeleteObservedNameSetSha256: liveSnapshot.observedNameSetSha256,
    preDeleteMissingNameSetSha256: liveSnapshot.missingNameSetSha256,
    preDeleteMissingCount: liveSnapshot.missingNames.length,
    discoveredNameSetSha256: hashNameSet(initial.names),
    deletedNameSetSha256: hashNameSet(deleted),
    remainingNameSetSha256: hashNameSet(remaining.names),
    discoveredCount: initial.names.length,
    deletedCount: deleted.length,
    failedCount: failures.length,
    remainingCount: remaining.names.length,
    listPages: initial.pages + remaining.pages,
    deleteRequests: initial.names.length,
    authorityReadRequests: callerAuthority.authorityReadRequests,
    externalRequests:
      initial.pages +
      remaining.pages +
      initial.names.length +
      callerAuthority.authorityReadRequests,
    idempotent: initial.names.length === 0 && status === 'PASS',
    startedAtUtc,
    completedAtUtc,
    containsSensitiveData: false,
  };
  const receipt = validateReleaseSuccessorJournalCleanupReceipt(
    { ...body, cleanupReceiptSha256: objectSha256(body) },
    { preservationReceipt, lifecycle, reconciliationJournalAuthority },
  );
  if (status !== 'PASS') {
    fail('E7_RELEASE_SUCCESSOR_CLEANUP_PARTIAL_FAILURE', {
      cause: failures[0]?.error,
      receipt,
    });
  }
  return receipt;
};

const createCleanupReconciliationFixture = ({ candidateSha, sourceRunId }) => {
  const source = {
    repository: 'ivanmonsalve0404/async-checkout-demo',
    workflowPath: '.github/workflows/release.yml',
    ref: 'refs/heads/master',
    runId: sourceRunId,
    runAttempt: 1,
    candidateSha,
    releaseId: 'rel-20260817-1100-aaaaaaa',
    releaseTag: 'v2026.8.17',
    configSha256: 'b'.repeat(64),
  };
  const intent = createReleaseReconciliationIntent({
    source,
    authority: {
      accountId: '123456789012',
      region: 'us-east-1',
      rollbackRoleArn: 'arn:aws:iam::123456789012:role/stage7-release-rollback',
      journalRoleArn: 'arn:aws:iam::123456789012:role/stage7-release-journal-cleanup',
      rollbackPermissionSetSha256: '2'.repeat(64),
      journalEffectivePermissionsSha256: '3'.repeat(64),
    },
    bindings: STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.map((descriptor, index) => ({
      ...descriptor,
      rawSha256:
        descriptor.sourceType === 'NESTED_JSON' ? null : (index + 1).toString(16).padStart(64, '0'),
      canonicalSha256:
        descriptor.sourceType === 'RAW_TEXT' ? null : (index + 101).toString(16).padStart(64, '0'),
      bytes: 100 + index,
    })),
  });
  const intentText = canonicalJson(intent);
  const intentValues = [];
  let current = '';
  for (const character of intentText) {
    if (Buffer.byteLength(current + character, 'utf8') > 3000) {
      intentValues.push(current);
      current = character;
    } else current += character;
  }
  if (current !== '') intentValues.push(current);
  const reconciliationRoot = `/checkout/stage7/rollback/${candidateSha}/release-reconciliation/${sourceRunId}`;
  const owner = createReleaseRollbackJournalOwner({
    source,
    intent,
    intentRawSha256: sha256(Buffer.from(intentText, 'utf8')),
    intentBytes: Buffer.byteLength(intentText, 'utf8'),
    intentChunks: intentValues.map((value, index) => ({
      index: index + 1,
      parameterName: `${reconciliationRoot}/intent/${String(index + 1).padStart(4, '0')}`,
      rawSha256: sha256(Buffer.from(value, 'utf8')),
      bytes: Buffer.byteLength(value, 'utf8'),
    })),
    createdAtUtc: '2026-08-18T04:50:00.000Z',
  });
  const runtimeProof = (phase, proofKind, sequence, observedAtUtc) => {
    const proof = {
      schemaVersion: 1,
      stage: 7,
      kind: 'STAGE7_RELEASE_RECONCILIATION_SELF_TEST_PROOF',
      phase,
      proofKind,
      sequence,
      observedAtUtc,
      containsSensitiveData: false,
    };
    const proofValue = JSON.stringify(proof);
    const proofBytes = Buffer.from(proofValue, 'utf8');
    const rawSha256 = sha256(proofBytes);
    const canonicalSha256 = objectSha256(proof);
    const phaseSlug = phase === 'ROLLBACK_CHECK' ? 'rollback-check' : 'rollback-resilience';
    const root = `${owner.runtimeProofRootPrefix}/${phaseSlug}/${proofKind.toLowerCase()}/${rawSha256}`;
    const chunkRawSha256 = rawSha256;
    const chunks = [
      {
        sequence: 1,
        parameterName: `${root}/chunk/0001-${chunkRawSha256}`,
        rawSha256: chunkRawSha256,
        bytes: proofBytes.length,
      },
    ];
    const indexBody = {
      schemaVersion: 1,
      stage: 7,
      kind: 'STAGE7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX',
      status: 'RAW_BYTES_DURABLE',
      phase,
      proofKind,
      source,
      ownerSha256: owner.ownerSha256,
      convergenceSha256: 'c'.repeat(64),
      indexParameterName: `${root}/index`,
      rawSha256,
      canonicalSha256,
      bytes: proofBytes.length,
      observedAtUtc,
      chunks,
      chunksSha256: objectSha256(chunks),
      containsSensitiveData: false,
    };
    const index = { ...indexBody, indexSha256: objectSha256(indexBody) };
    const indexValue = JSON.stringify(index);
    const indexBytes = Buffer.from(indexValue, 'utf8');
    return {
      reference: {
        indexParameterName: index.indexParameterName,
        indexSha256: index.indexSha256,
        rawSha256,
        canonicalSha256,
        bytes: proofBytes.length,
        observedAtUtc,
        chunkCount: 1,
        chunksSha256: index.chunksSha256,
      },
      parameters: [
        {
          name: index.indexParameterName,
          rawSha256: sha256(indexBytes),
          bytes: indexBytes.length,
          version: 1,
        },
        {
          name: chunks[0].parameterName,
          rawSha256: chunkRawSha256,
          bytes: proofBytes.length,
          version: 1,
        },
      ],
      values: new Map([
        [index.indexParameterName, indexValue],
        [chunks[0].parameterName, proofValue],
      ]),
    };
  };
  const createReceipt = (phase, startedAtUtc, observedAtUtc, completedAtUtc, sequence) => {
    const drift = runtimeProof(phase, 'DRIFT', sequence, observedAtUtc);
    const smoke = runtimeProof(phase, 'SMOKE', sequence + 2, observedAtUtc);
    const runtimeProofParameters = [...drift.parameters, ...smoke.parameters].toSorted(
      (left, right) => left.name.localeCompare(right.name),
    );
    const smokeAuthorizationUsage = {
      schemaVersion: 1,
      phase,
      usageId: STAGE7_RELEASE_RECONCILIATION_SMOKE_USAGE_IDS[phase],
      authorizationSha256: '9'.repeat(64),
      bundleSha256: '9'.repeat(64),
      configSha256: source.configSha256,
      candidateSha: source.candidateSha,
      releaseId: source.releaseId,
      ownedOriginSha256: 'a'.repeat(64),
      sandboxHostSha256: 'b'.repeat(64),
      requestCounts: {
        'AUTH-E7-EXT-01': 3,
        'AUTH-E7-EXT-02': 0,
        'AUTH-E7-EXT-03': 0,
      },
      total: 3,
      passed: 3,
      failed: 0,
      containsSensitiveData: false,
    };
    const expectedStateSha256 = '4'.repeat(64);
    const terminalName = `${owner.reconciliationRootPrefix}/${phase === 'ROLLBACK_CHECK' ? 'rollback-check' : 'rollback-resilience'}/terminal`;
    const terminalBody = {
      schemaVersion: 1,
      stage: 7,
      kind: 'STAGE7_RELEASE_RECONCILIATION_TERMINAL_N',
      status: 'EXACT_CANDIDATE_N_VERIFIED',
      phase,
      source,
      ownerSha256: owner.ownerSha256,
      originalJobConclusion: 'SUCCESS',
      recoveryAction: 'VERIFIED_NOOP',
      convergenceSha256: 'c'.repeat(64),
      expectedStateSha256,
      observedStateSha256: expectedStateSha256,
      readbackRawSha256: '5'.repeat(64),
      readbackCanonicalSha256: '6'.repeat(64),
      driftProofSha256: drift.reference.canonicalSha256,
      driftRawSha256: drift.reference.rawSha256,
      driftProofJournal: drift.reference,
      smokeProofSha256: smoke.reference.canonicalSha256,
      smokeRawSha256: smoke.reference.rawSha256,
      smokeAuthorizationUsageSha256: objectSha256(smokeAuthorizationUsage),
      smokeProofJournal: smoke.reference,
      runtimeProofParameterCount: runtimeProofParameters.length,
      runtimeProofParametersSha256: objectSha256(runtimeProofParameters),
      startedAtUtc,
      convergenceCompletedAtUtc: observedAtUtc,
      driftObservedAtUtc: observedAtUtc,
      smokeObservedAtUtc: observedAtUtc,
      observedAtUtc,
      completedAtUtc,
      containsSensitiveData: false,
    };
    const terminal = validateReleaseReconciliationTerminal({
      ...terminalBody,
      terminalSha256: objectSha256(terminalBody),
    });
    const receipt = createReleaseReconciliationReceipt({
      phase,
      source,
      owner,
      intent,
      originalJobConclusion: 'SUCCESS',
      recoveryAction: 'VERIFIED_NOOP',
      expectedStateSha256,
      observedStateSha256: expectedStateSha256,
      readbackRawSha256: '5'.repeat(64),
      readbackCanonicalSha256: '6'.repeat(64),
      driftProofSha256: drift.reference.canonicalSha256,
      smokeProofSha256: smoke.reference.canonicalSha256,
      smokeAuthorizationUsage,
      driftProofJournal: drift.reference,
      smokeProofJournal: smoke.reference,
      runtimeProofParameters,
      runtimeProofParameterCount: runtimeProofParameters.length,
      runtimeProofParametersSha256: objectSha256(runtimeProofParameters),
      journalScanSha256: '7'.repeat(64),
      terminalStateSha256: terminal.terminalSha256,
      startedAtUtc,
      convergenceCompletedAtUtc: observedAtUtc,
      driftObservedAtUtc: observedAtUtc,
      smokeObservedAtUtc: observedAtUtc,
      observedAtUtc,
      completedAtUtc,
    });
    return {
      receipt,
      values: new Map([...drift.values, ...smoke.values, [terminalName, JSON.stringify(terminal)]]),
    };
  };
  const rollbackCheckFixture = createReceipt(
    'ROLLBACK_CHECK',
    '2026-08-18T04:51:00.000Z',
    '2026-08-18T04:52:00.000Z',
    '2026-08-18T04:53:00.000Z',
    9,
  );
  const rollbackResilienceFixture = createReceipt(
    'ROLLBACK_RESILIENCE',
    '2026-08-18T04:54:00.000Z',
    '2026-08-18T04:55:00.000Z',
    '2026-08-18T04:56:00.000Z',
    11,
  );
  const rollbackCheck = rollbackCheckFixture.receipt;
  const rollbackResilience = rollbackResilienceFixture.receipt;
  const rollbackCheckSource = Buffer.from(`${JSON.stringify(rollbackCheck)}\n`);
  const rollbackResilienceSource = Buffer.from(`${JSON.stringify(rollbackResilience)}\n`);
  const gate = createReleasePreFenceGate({
    rollbackCheckSource,
    rollbackResilienceSource,
    evaluatedAtUtc: '2026-08-18T04:57:00.000Z',
  });
  return {
    rollbackCheckSource,
    rollbackResilienceSource,
    rollbackCheck,
    rollbackResilience,
    gateSource: Buffer.from(`${JSON.stringify(gate)}\n`),
    authority: gate.reconciliationJournalAuthority,
    parameterValues: new Map([
      [owner.parameterName, JSON.stringify(owner)],
      ...owner.intentChunks.map((binding, index) => [binding.parameterName, intentValues[index]]),
      ...rollbackCheckFixture.values,
      ...rollbackResilienceFixture.values,
    ]),
  };
};

const createCleanupRbJournalFixture = ({
  prefix,
  scenarioId,
  checkpoint,
  source,
  execution,
  rollbackBindingPreimage,
  rollbackBindingSha256,
  protectedBindingSha256,
  lifecycle,
  rollbackRole,
  journalRole,
}) => {
  const stateBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_DURABLE_STATE',
    scenarioId,
    bindingSha256: rollbackBindingSha256,
    phase: 'COMPLETE',
    resumptions: 0,
    progress: {},
    transcript: [],
    checkpoint,
    containsSensitiveData: false,
  };
  const state = { ...stateBody, stateSha256: objectSha256(stateBody) };
  const serialized = JSON.stringify(state);
  const encoded = gzipSync(Buffer.from(serialized, 'utf8'), { level: 9 }).toString('base64');
  const basename = `000001-${state.stateSha256}`;
  const manifest = {
    schemaVersion: 1,
    kind: 'ROLLBACK_RESILIENCE_SSM_JOURNAL_ENTRY',
    sequence: 1,
    stateSha256: state.stateSha256,
    previousStateSha256: null,
    encoding: 'gzip-base64',
    chunks: 1,
    payloadBytes: Buffer.byteLength(serialized, 'utf8'),
    payloadSha256: sha256(encoded),
    containsSensitiveData: false,
  };
  const premutationAuthorityBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_SSM_PREMUTATION_AUTHORITY',
    status: 'PREMUTATION_PREIMAGE_BOUND_IMMUTABLE',
    candidateSha: source.candidateSha,
    scenarioId,
    releaseId: source.releaseId,
    releaseTag: source.releaseTag,
    configSha256: source.configSha256,
    rollbackBindingPreimage,
    execution,
    executionSha256: objectSha256(execution),
    bindingSha256: state.bindingSha256,
    protectedBindingSha256,
    rollbackRoleSha256: sha256(rollbackRole),
    journalCleanupRoleSha256: sha256(journalRole),
    journalLifecycleSha256: lifecycle.lifecycleSha256,
    parameterName: `${prefix}/premutation-authority`,
    containsSensitiveData: false,
  };
  const premutationAuthority = {
    ...premutationAuthorityBody,
    authoritySha256: objectSha256(premutationAuthorityBody),
  };
  const premutationAuthorityValue = JSON.stringify(premutationAuthority);
  const ownerBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_SSM_JOURNAL_OWNER',
    status: 'OWNED_IMMUTABLE',
    candidateSha: source.candidateSha,
    scenarioId,
    sourceRunId: source.runId,
    sourceRunAttempt: 1,
    bindingSha256: state.bindingSha256,
    protectedBindingSha256,
    rollbackRoleSha256: sha256(rollbackRole),
    journalCleanupRoleSha256: sha256(journalRole),
    journalLifecycleSha256: lifecycle.lifecycleSha256,
    premutationAuthorityParameterName: premutationAuthority.parameterName,
    premutationAuthorityRawSha256: sha256(premutationAuthorityValue),
    premutationAuthorityCanonicalSha256: objectSha256(premutationAuthority),
    premutationAuthorityBytes: Buffer.byteLength(premutationAuthorityValue, 'utf8'),
    parameterName: `${prefix}/owner`,
    containsSensitiveData: false,
  };
  const owner = { ...ownerBody, ownerSha256: objectSha256(ownerBody) };
  return new Map([
    [premutationAuthority.parameterName, premutationAuthorityValue],
    [owner.parameterName, JSON.stringify(owner)],
    [`${prefix}/${basename}/chunk-0001`, encoded],
    [`${prefix}/${basename}/manifest`, JSON.stringify(manifest)],
  ]);
};

const cleanupParameterRecord = ({ name, value }) => ({
  Name: name,
  Type: 'String',
  Value: value,
  Version: 1,
  LastModifiedDate: '2026-08-18T04:58:00Z',
  ARN: `arn:aws:ssm:us-east-1:123456789012:parameter${name}`,
  DataType: 'text',
});

export const selfTestReleaseSuccessorJournalCleanup = async () => {
  const candidateSha = 'a'.repeat(40);
  const sourceRunId = '123456789';
  const journalRole = 'arn:aws:iam::123456789012:role/stage7-release-journal-cleanup';
  const rollbackRole = 'arn:aws:iam::123456789012:role/stage7-release-rollback';
  const ephemeralRole = 'arn:aws:iam::123456789012:role/stage7-prerelease-cleanup';
  const boundary = 'arn:aws:iam::123456789012:policy/stage7-release-journal-boundary';
  const sessionName = 'e7-release-journal-999-1';
  const rootPrefix = `/checkout/stage7/rollback/${candidateSha}`;
  const scenarioPrefixes = {
    'RB-E7-06': `${rootPrefix}/RB-E7-06`,
    'RB-E7-08': `${rootPrefix}/RB-E7-08`,
  };
  const reconciliation = createCleanupReconciliationFixture({ candidateSha, sourceRunId });
  const lifecycleBody = {
    status: 'PENDING_POST_CLOSEOUT_CLEANUP',
    cleanupRoleSha256: sha256(journalRole),
    cleanupScopeSha256: objectSha256({
      rootPrefix,
      scenarioPrefixes,
    }),
    scenarioPrefixes,
    deleteBeforeBoundaryAllowed: false,
    cleanupAttempted: false,
    retentionBoundary: 'FINAL_EVIDENCE_AND_SUCCESSOR_HANDOFF_PRESERVED',
  };
  const lifecycle = {
    ...lifecycleBody,
    lifecycleSha256: objectSha256(lifecycleBody),
  };
  const roleAuditSource = Buffer.from(
    `${JSON.stringify({
      Path: '/',
      RoleName: 'stage7-release-journal-cleanup',
      RoleId: 'AROAEXAMPLEROLE1234',
      Arn: journalRole,
      CreateDate: '2026-08-18T00:00:00Z',
      MaxSessionDuration: 3600,
      PermissionsBoundary: {
        PermissionsBoundaryType: 'Policy',
        PermissionsBoundaryArn: boundary,
      },
      AssumeRolePolicyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: {
              Federated:
                'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com',
            },
            Action: 'sts:AssumeRoleWithWebIdentity',
            Condition: {
              StringEquals: {
                'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
                'token.actions.githubusercontent.com:sub': [
                  'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release',
                  'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-reconciliation-recovery',
                  'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-successor-post-success',
                ],
              },
            },
          },
        ],
      },
    })}\n`,
  );
  const callerIdentityForSession = (session) =>
    Buffer.from(
      `${JSON.stringify({
        UserId: `AROAEXAMPLEROLE1234:${session}`,
        Account: '123456789012',
        Arn: `arn:aws:sts::123456789012:assumed-role/stage7-release-journal-cleanup/${session}`,
      })}\n`,
    );
  const callerIdentitySource = callerIdentityForSession(sessionName);
  const awsVersionSource = Buffer.from('aws-cli/2.31.0 Python/3.13 Linux/6.8\n');
  const effectivePermissions = createReleaseSuccessorIamAuthoritySelfTestFixture();
  const effectivePermissionsSource = Buffer.from(`${JSON.stringify(effectivePermissions)}\n`);
  const awsAuthSource = Buffer.from(
    `${JSON.stringify({
      kind: 'AWS_READ_ONLY_PREFLIGHT',
      status: 'PASS',
      scope: 'full',
      candidateSha,
      releaseId: 'rel-20260817-1100-aaaaaaa',
      configSha256: 'b'.repeat(64),
      manifestSha256: 'c'.repeat(64),
      mutationsPerformed: 0,
      journalRoleEffectivePermissionsRawSha256: sha256(effectivePermissionsSource),
      journalRoleEffectivePermissionsSha256: effectivePermissions.effectivePermissionsSha256,
      containsSensitiveData: false,
    })}\n`,
  );
  const callerAuthority = validateReleaseSuccessorCallerAuthority({
    callerIdentitySource,
    awsVersionSource,
    roleAuditSource,
    awsAuthSource,
    frozenEffectivePermissionsSource: effectivePermissionsSource,
    liveEffectivePermissionsSource: effectivePermissionsSource,
    postSuccessRunId: '999',
    postSuccessRunAttempt: 1,
    journalCleanupRoleArn: journalRole,
    expectedSessionName: sessionName,
    expectedAwsCliVersion: '2.31.0',
    expectedPermissionsBoundaryArn: boundary,
  });
  const rb06Checkpoint = {
    scenarioId: 'RB-E7-06',
    checkpointSha256: '6'.repeat(64),
  };
  const rb08Checkpoint = {
    scenarioId: 'RB-E7-08',
    checkpointSha256: '8'.repeat(64),
  };
  const protectedExecution = {
    mode: 'AWS_REAL',
    repository: reconciliation.authority.source.repository,
    workflow: 'stage7-rollback-resilience.yml',
    runId: sourceRunId,
    runAttempt: '1',
    githubActions: true,
    githubRef: 'refs/heads/master',
    githubSha: candidateSha,
    protectedEnvironment: 'assessment-release-recovery',
    accountId: '123456789012',
    region: 'us-east-1',
    roleArn: rollbackRole,
    startedAtUtc: '2026-08-18T04:49:00.000Z',
  };
  const rollbackBindingPreimage = {
    freezeManifestSha256: '1'.repeat(64),
    previousReleaseManifestSha256: '2'.repeat(64),
    candidateRecordSha256: '3'.repeat(64),
    approvalSha256: '4'.repeat(64),
    awsAuthEvidenceSha256: '5'.repeat(64),
    iamEffectivePermissionsBindingSha256: '6'.repeat(64),
    approvedPlanSha256: '7'.repeat(64),
    deploymentEvidenceSha256: '8'.repeat(64),
    observabilityEvidenceSha256: '9'.repeat(64),
    activationEvidenceSha256: 'a'.repeat(64),
    externalAuthorizationEvidenceSha256: 'b'.repeat(64),
    authorizationBudgetSha256: 'c'.repeat(64),
    reconciliationRecoveryRoleAuthoritySha256: 'd'.repeat(64),
    baseRehearsalSha256: 'e'.repeat(64),
  };
  const executionSha256 = objectSha256(protectedExecution);
  const rollbackBindingSha256 = objectSha256({
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_RESILIENCE_BINDING',
    candidateSha,
    releaseId: reconciliation.authority.source.releaseId,
    configSha256: reconciliation.authority.source.configSha256,
    ...rollbackBindingPreimage,
    journalCleanupRoleSha256: sha256(journalRole),
    executionSha256,
    containsSensitiveData: false,
  });
  const protectedBindingSha256 = objectSha256({
    STAGE7_AUTHORIZED_RUN_ID: protectedExecution.runId,
    STAGE7_AUTHORIZED_RUN_ATTEMPT: protectedExecution.runAttempt,
    STAGE7_AUTHORIZED_CANDIDATE_SHA: candidateSha,
    STAGE7_AUTHORIZED_FREEZE_SHA256: rollbackBindingPreimage.freezeManifestSha256,
    STAGE7_AUTHORIZED_APPROVAL_SHA256: rollbackBindingPreimage.approvalSha256,
    STAGE7_AUTHORIZED_AWS_AUTH_SHA256: rollbackBindingPreimage.awsAuthEvidenceSha256,
    STAGE7_AUTHORIZED_PLAN_SHA256: rollbackBindingPreimage.approvedPlanSha256,
    STAGE7_AUTHORIZED_DEPLOYMENT_SHA256: rollbackBindingPreimage.deploymentEvidenceSha256,
    STAGE7_AUTHORIZED_OBSERVABILITY_SHA256: rollbackBindingPreimage.observabilityEvidenceSha256,
    STAGE7_AUTHORIZED_ACTIVATION_SHA256: rollbackBindingPreimage.activationEvidenceSha256,
    STAGE7_AUTHORIZED_EXTERNAL_AUTHORIZATION_SHA256:
      rollbackBindingPreimage.externalAuthorizationEvidenceSha256,
    STAGE7_AUTHORIZED_AUTHORIZATION_BUDGET_SHA256:
      rollbackBindingPreimage.authorizationBudgetSha256,
    STAGE7_AUTHORIZED_REHEARSAL_SHA256: rollbackBindingPreimage.baseRehearsalSha256,
    STAGE7_AUTHORIZED_JOURNAL_CLEANUP_ROLE_SHA256: sha256(journalRole),
  });
  rb06Checkpoint.startedAtUtc = protectedExecution.startedAtUtc;
  rb08Checkpoint.startedAtUtc = protectedExecution.startedAtUtc;
  const protectedRun = {
    executionSha256,
    runtimeAttestation: {
      repository: protectedExecution.repository,
      workflow: protectedExecution.workflow,
      runId: sourceRunId,
      runAttempt: '1',
      githubSha: candidateSha,
      protectedEnvironment: protectedExecution.protectedEnvironment,
      protectedBindingSha256,
      identity: { roleSha256: sha256(rollbackRole) },
      journalLifecycle: lifecycle,
    },
    completion: { finalCandidateSha: candidateSha },
    rb06Checkpoint,
    rb08Checkpoint,
    containsSensitiveData: false,
  };
  const parameterValues = new Map([
    ...createCleanupRbJournalFixture({
      prefix: scenarioPrefixes['RB-E7-06'],
      scenarioId: 'RB-E7-06',
      checkpoint: rb06Checkpoint,
      source: reconciliation.authority.source,
      execution: protectedExecution,
      rollbackBindingPreimage,
      rollbackBindingSha256,
      protectedBindingSha256,
      lifecycle,
      rollbackRole,
      journalRole,
    }),
    ...createCleanupRbJournalFixture({
      prefix: scenarioPrefixes['RB-E7-08'],
      scenarioId: 'RB-E7-08',
      checkpoint: rb08Checkpoint,
      source: reconciliation.authority.source,
      execution: protectedExecution,
      rollbackBindingPreimage,
      rollbackBindingSha256,
      protectedBindingSha256,
      lifecycle,
      rollbackRole,
      journalRole,
    }),
    ...reconciliation.parameterValues,
  ]);
  const parameters = new Set(parameterValues.keys());
  const pageFor =
    (visibleParameters) =>
    async ({ path: prefix, nextToken }) => {
      const all = [...visibleParameters]
        .filter((name) => name.startsWith(`${prefix}/`))
        .toSorted((left, right) => left.localeCompare(right));
      const offset = nextToken === undefined ? 0 : Number(nextToken);
      const slice = all.slice(offset, offset + 5);
      const next = offset + slice.length < all.length ? String(offset + slice.length) : undefined;
      return {
        Parameters: slice.map((name) =>
          cleanupParameterRecord({ name, value: parameterValues.get(name) }),
        ),
        ...(next ? { NextToken: next } : {}),
      };
    };
  const page = pageFor(parameters);
  const journalSnapshot = (
    await captureReleaseSuccessorJournalSnapshot({
      scenarioPrefixes,
      reconciliationJournalAuthority: reconciliation.authority,
      rollbackCheckReceipt: reconciliation.rollbackCheck,
      rollbackResilienceReceipt: reconciliation.rollbackResilience,
      protectedRun,
      getParametersByPath: page,
    })
  ).snapshot;
  const corruptedSnapshotEntry = {
    ...journalSnapshot.entries[0],
    value: `${journalSnapshot.entries[0].value}x`,
  };
  assert.throws(
    () =>
      validateReleaseSuccessorJournalSnapshot({
        ...journalSnapshot,
        entries: [corruptedSnapshotEntry, ...journalSnapshot.entries.slice(1)],
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_ENTRY_INVALID',
  );
  const missingParameters = new Set(parameters);
  missingParameters.delete(reconciliation.authority.cleanupParameterNames[0]);
  await assert.rejects(
    captureReleaseSuccessorJournalSnapshot({
      scenarioPrefixes,
      reconciliationJournalAuthority: reconciliation.authority,
      rollbackCheckReceipt: reconciliation.rollbackCheck,
      rollbackResilienceReceipt: reconciliation.rollbackResilience,
      protectedRun,
      getParametersByPath: pageFor(missingParameters),
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_RECONCILIATION_JOURNAL_SET_INVALID',
  );
  const extraParameters = new Set(parameters);
  const unexpectedParameter = `${reconciliation.authority.reconciliationRootPrefix}/unexpected`;
  extraParameters.add(unexpectedParameter);
  parameterValues.set(unexpectedParameter, '{}');
  await assert.rejects(
    captureReleaseSuccessorJournalSnapshot({
      scenarioPrefixes,
      reconciliationJournalAuthority: reconciliation.authority,
      rollbackCheckReceipt: reconciliation.rollbackCheck,
      rollbackResilienceReceipt: reconciliation.rollbackResilience,
      protectedRun,
      getParametersByPath: pageFor(extraParameters),
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_RECONCILIATION_JOURNAL_SET_INVALID',
  );
  parameterValues.delete(unexpectedParameter);
  const finalization = {
    completedAtUtc: '2026-08-18T05:00:00.000Z',
    authority: {
      journalCleanupRoleSha256: sha256(journalRole),
      rollbackRoleSha256: sha256(rollbackRole),
      ephemeralCleanupRoleSha256: sha256(ephemeralRole),
      rolesDistinct: true,
      roleAuthority: callerAuthority.roleAuthority,
      roleAuthoritySha256: callerAuthority.roleAuthoritySha256,
      callerAttemptAuthority: callerAuthority.callerAttemptAuthority,
      callerAttemptAuthoritySha256: callerAuthority.callerAttemptAuthoritySha256,
      auditEvidence: callerAuthority.auditEvidence,
      auditEvidenceSha256: callerAuthority.auditEvidenceSha256,
    },
    containsSensitiveData: false,
  };
  const marker = {
    markerSha256: '4'.repeat(64),
    journalRoleAuthoritySha256: callerAuthority.roleAuthoritySha256,
    containsSensitiveData: false,
  };
  const payloadPaths = Object.values(RELEASE_SUCCESSOR_SOURCE_LAYOUT).filter(
    (pathName) =>
      ![RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance, RELEASE_SUCCESSOR_SOURCE_LAYOUT.index].includes(
        pathName,
      ),
  );
  const files = Object.fromEntries(
    payloadPaths.map((pathName) => [
      pathName,
      pathName === RELEASE_SUCCESSOR_SOURCE_LAYOUT.rawDiff
        ? Buffer.from('diff\n')
        : Buffer.from(`${JSON.stringify({ path: pathName, containsSensitiveData: false })}\n`),
    ]),
  );
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackProtectedRun] = Buffer.from(
    `${JSON.stringify(protectedRun)}\n`,
  );
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackCheck] =
    reconciliation.rollbackCheckSource;
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackResilience] =
    reconciliation.rollbackResilienceSource;
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.preFenceGate] = reconciliation.gateSource;
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalDisable] = Buffer.from(
    `${JSON.stringify(finalization)}\n`,
  );
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalizationMarker] = Buffer.from(
    `${JSON.stringify(marker)}\n`,
  );
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot] = Buffer.from(
    `${JSON.stringify(journalSnapshot)}\n`,
  );
  const reconciliationValidation = validateReleaseSuccessorReconciliationAuthoritySources({
    rollbackCheckSource: reconciliation.rollbackCheckSource,
    rollbackResilienceSource: reconciliation.rollbackResilienceSource,
    preFenceGateSource: reconciliation.gateSource,
    expected: {
      sourceRunId,
      sourceRunAttempt: 1,
      candidateSha,
      releaseId: 'rel-20260817-1100-aaaaaaa',
      releaseTag: 'v2026.8.17',
    },
  });
  const journalSnapshotBytes = files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot];
  const journalSnapshotBinding = {
    path: RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot,
    rawSha256: sha256(journalSnapshotBytes),
    canonicalSha256: objectSha256(journalSnapshot),
    bytes: journalSnapshotBytes.length,
    snapshotSha256: journalSnapshot.snapshotSha256,
    targetNameSetSha256: journalSnapshot.targetNameSetSha256,
    entryCount: journalSnapshot.entryCount,
  };
  const rawEntry = (pathName, bytes) => ({
    path: pathName,
    sha256: sha256(bytes),
    bytes: bytes.length,
  });
  const provenanceBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_SOURCE_PROVENANCE',
    status: 'PASS',
    artifactName: RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
    repository: 'ivanmonsalve0404/async-checkout-demo',
    workflowPath: '.github/workflows/release.yml',
    sourceEvent: 'workflow_dispatch',
    sourceRef: 'refs/heads/master',
    sourceRunId,
    sourceRunAttempt: 1,
    headSha: candidateSha,
    releaseId: 'rel-20260817-1100-aaaaaaa',
    releaseTag: 'v2026.8.17',
    sourceKind: 'RELEASE_SUCCESSOR_POST_SUCCESS',
    predecessorManifestSha256: '1'.repeat(64),
    candidateRecordSha256: '2'.repeat(64),
    rollbackRehearsalSha256: '3'.repeat(64),
    capturedAtUtc: '2026-08-18T05:00:00.000Z',
    releaseEvidenceSetSha256: '5'.repeat(64),
    journalLifecycleSha256: lifecycle.lifecycleSha256,
    reconciliationJournalAuthority: reconciliationValidation.authority,
    reconciliationJournalAuthoritySha256: reconciliationValidation.authority.journalAuthoritySha256,
    reconciliationEvidenceBindings: reconciliationValidation.bindings,
    releaseFenceAuthoritySetSha256: '6'.repeat(64),
    journalSnapshotBinding,
    finalDisableEvidenceSha256: objectSha256(finalization),
    files: payloadPaths.map((pathName) => rawEntry(pathName, files[pathName])),
    canonicalSha256ByPath: Object.fromEntries(
      payloadPaths
        .filter((pathName) => pathName !== RELEASE_SUCCESSOR_SOURCE_LAYOUT.rawDiff)
        .map((pathName) => [pathName, objectSha256(JSON.parse(files[pathName].toString('utf8')))]),
    ),
    artifactOriginsByPath: Object.fromEntries(
      payloadPaths.map((pathName) => [pathName, 'POST_SUCCESS_DERIVED']),
    ),
    bundleSha256: objectSha256(payloadPaths.map((pathName) => rawEntry(pathName, files[pathName]))),
    externalRequests: 33,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const provenance = {
    ...provenanceBody,
    provenanceSha256: objectSha256(provenanceBody),
  };
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance] = Buffer.from(
    `${JSON.stringify(provenance)}\n`,
  );
  const indexBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_SUCCESSOR_SOURCE_BUNDLE',
    status: 'RELEASE_N_POST_SUCCESS_VALIDATED',
    artifactName: RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
    sourceRunId,
    sourceRunAttempt: 1,
    sourceHeadSha: candidateSha,
    sourceReleaseId: provenance.releaseId,
    sourceProvenanceSha256: objectSha256(provenance),
    reconciliationJournalAuthoritySha256: reconciliationValidation.authority.journalAuthoritySha256,
    releaseFenceAuthoritySetSha256: provenance.releaseFenceAuthoritySetSha256,
    journalSnapshotBinding,
    files: [...payloadPaths, RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance].map((pathName) =>
      rawEntry(pathName, files[pathName]),
    ),
    immutable: true,
    targetCandidateBound: false,
    targetFreezeManifestSha256: null,
    containsSensitiveData: false,
    createdAtUtc: provenance.capturedAtUtc,
    bundleSha256: provenance.bundleSha256,
  };
  const index = { ...indexBody, indexSha256: objectSha256(indexBody) };
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.index] = Buffer.from(`${JSON.stringify(index)}\n`);
  const sourceBundle = {
    files,
    provenance,
    index,
  };
  const archive = createReleaseSuccessorStoredZipFixture(files);
  const preservationReceipt = createReleaseSuccessorPreservationReceipt({
    sourceBundle,
    artifactApiSource: Buffer.from(
      `${JSON.stringify({
        id: 987,
        name: `stage7-release-successor-source-r${sourceRunId}-a1`,
        digest: `sha256:${sha256(archive)}`,
        expired: false,
        workflow_run: { id: 999 },
      })}\n`,
    ),
    artifactArchiveSource: archive,
    postSuccessRunId: '999',
    postSuccessRunAttempt: 1,
    postSuccessHeadSha: candidateSha,
    preservedAtUtc: '2026-08-18T05:01:00.000Z',
  });
  let failOnce = [...parameters].find((name) => name.startsWith(scenarioPrefixes['RB-E7-08']));
  const remove = async ({ name }) => {
    if (name === failOnce) {
      failOnce = null;
      throw new Error('PARTIAL');
    }
    parameters.delete(name);
  };
  const cleanupOptions = {
    sourceBundle,
    preservationReceipt,
    journalCleanupRoleArn: journalRole,
    rollbackRoleArn: rollbackRole,
    ephemeralCleanupRoleArn: ephemeralRole,
    callerIdentitySource,
    awsVersionSource,
    roleAuditSource,
    awsAuthSource,
    frozenEffectivePermissionsSource: effectivePermissionsSource,
    liveEffectivePermissionsSource: effectivePermissionsSource,
    expectedSessionName: sessionName,
    expectedPermissionsBoundaryArn: boundary,
    postSuccessRunId: '999',
    postSuccessRunAttempt: 1,
    getParametersByPath: page,
    deleteParameter: remove,
    now: () => new Date('2026-08-18T05:02:00.000Z'),
  };
  const driftedName = [...parameters][0];
  const originalValue = parameterValues.get(driftedName);
  parameterValues.set(driftedName, `${originalValue}x`);
  let preDeleteAttempts = 0;
  await assert.rejects(
    cleanupReleaseSuccessorJournal({
      ...cleanupOptions,
      deleteParameter: async () => {
        preDeleteAttempts += 1;
      },
    }),
    (error) =>
      error.code === 'E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_LIVE_DRIFT' ||
      error.cause?.code === 'E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_LIVE_DRIFT',
  );
  assert.equal(preDeleteAttempts, 0);
  parameterValues.set(driftedName, originalValue);
  parameters.delete(driftedName);
  await assert.rejects(
    cleanupReleaseSuccessorJournal({
      ...cleanupOptions,
      deleteParameter: async () => {
        preDeleteAttempts += 1;
      },
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_INITIAL_SET_INCOMPLETE',
  );
  assert.equal(preDeleteAttempts, 0);
  parameters.add(driftedName);
  let partialReceipt;
  await assert.rejects(cleanupReleaseSuccessorJournal(cleanupOptions), (error) => {
    partialReceipt = error.receipt;
    return (
      error.code === 'E7_RELEASE_SUCCESSOR_CLEANUP_PARTIAL_FAILURE' &&
      partialReceipt?.status === 'FAILED_PARTIAL_DELETE' &&
      partialReceipt.remainingCount === 1
    );
  });
  assert.equal(parameters.size, 1);
  const retrySessionName = 'e7-release-journal-999-2';
  const retryReceipt = await cleanupReleaseSuccessorJournal({
    ...cleanupOptions,
    callerIdentitySource: callerIdentityForSession(retrySessionName),
    expectedSessionName: retrySessionName,
    postSuccessRunAttempt: 2,
    now: () => new Date('2026-08-18T05:03:00.000Z'),
  });
  assert.equal(retryReceipt.status, 'PASS');
  assert.equal(retryReceipt.idempotent, false);
  assert.equal(retryReceipt.sourcePreservationRunAttempt, 1);
  assert.equal(retryReceipt.postSuccessRunAttempt, 2);
  const idempotentReceipt = await cleanupReleaseSuccessorJournal({
    ...cleanupOptions,
    callerIdentitySource: callerIdentityForSession(retrySessionName),
    expectedSessionName: retrySessionName,
    postSuccessRunAttempt: 2,
    now: () => new Date('2026-08-18T05:04:00.000Z'),
  });
  assert.equal(idempotentReceipt.status, 'PASS');
  assert.equal(idempotentReceipt.idempotent, true);
  await assert.rejects(
    listExactPrefix({
      prefix: scenarioPrefixes['RB-E7-06'],
      getParametersByPath: async () => ({
        Parameters: [{ Name: `${rootPrefix}/RB-E7-08/confused` }],
      }),
    }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_CLEANUP_PARAMETER_OUTSIDE_SCOPE',
  );
  return {
    status: 'PASS',
    canaries: 16,
    externalRequests: 0,
    lifecycleSha256: lifecycle.lifecycleSha256,
    idempotentEmptySetSha256: idempotentReceipt.discoveredNameSetSha256,
  };
};
