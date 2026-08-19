import { objectSha256 } from './core.mjs';
import { STAGE7_RELEASE_RECONCILIATION_ARTIFACT } from './release-reconciliation.mjs';
import {
  RELEASE_SUCCESSOR_INPUT_ARTIFACT_NAME,
  RELEASE_SUCCESSOR_MASTER_REF,
  RELEASE_SUCCESSOR_REPOSITORY,
  RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS,
  RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
  RELEASE_SUCCESSOR_SOURCE_LAYOUT,
  RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES,
  RELEASE_SUCCESSOR_WORKFLOW_PATH,
} from './release-successor-contract.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;

export class Stage7ReleaseSuccessorSourceProvenanceError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7ReleaseSuccessorSourceProvenanceError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7ReleaseSuccessorSourceProvenanceError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const utc = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return false;
  return new Date(value).toISOString() === value;
};
const withoutDigest = (value, field) => {
  const body = { ...value };
  delete body[field];
  return body;
};
const validateRawEntry = (value) =>
  exactKeys(value, ['path', 'sha256', 'bytes']) &&
  typeof value.path === 'string' &&
  value.path.length > 0 &&
  SHA256.test(value.sha256 ?? '') &&
  Number.isSafeInteger(value.bytes) &&
  value.bytes >= 2;
const validateReconciliationEvidenceBinding = (value, { pathName, digestName, digest }) =>
  exactKeys(value, ['path', 'artifactName', 'rawSha256', 'canonicalSha256', 'bytes', digestName]) &&
  value.path === pathName &&
  value.artifactName === STAGE7_RELEASE_RECONCILIATION_ARTIFACT &&
  SHA256.test(value.rawSha256 ?? '') &&
  SHA256.test(value.canonicalSha256 ?? '') &&
  Number.isSafeInteger(value.bytes) &&
  value.bytes >= 2 &&
  SHA256.test(value[digestName] ?? '') &&
  value[digestName] === digest;
const validateJournalSnapshotBinding = (value) =>
  exactKeys(value, [
    'path',
    'rawSha256',
    'canonicalSha256',
    'bytes',
    'snapshotSha256',
    'targetNameSetSha256',
    'entryCount',
  ]) &&
  value.path === RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot &&
  [value.rawSha256, value.canonicalSha256, value.snapshotSha256, value.targetNameSetSha256].every(
    (digest) => SHA256.test(digest ?? ''),
  ) &&
  Number.isSafeInteger(value.bytes) &&
  value.bytes >= 2 &&
  Number.isSafeInteger(value.entryCount) &&
  value.entryCount >= 3;
const sourceProvenanceBody = (value) => withoutDigest(value, 'provenanceSha256');

export const validateReleaseSuccessorSourceProvenance = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'artifactName',
      'repository',
      'workflowPath',
      'sourceEvent',
      'sourceRef',
      'sourceRunId',
      'sourceRunAttempt',
      'headSha',
      'releaseId',
      'releaseTag',
      'sourceKind',
      'predecessorManifestSha256',
      'candidateRecordSha256',
      'rollbackRehearsalSha256',
      'journalLifecycleSha256',
      'reconciliationJournalAuthority',
      'reconciliationJournalAuthoritySha256',
      'reconciliationEvidenceBindings',
      'releaseFenceAuthoritySetSha256',
      'journalSnapshotBinding',
      'releaseEvidenceSetSha256',
      'finalDisableEvidenceSha256',
      'files',
      'canonicalSha256ByPath',
      'artifactOriginsByPath',
      'bundleSha256',
      'capturedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'provenanceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_SOURCE_PROVENANCE' ||
    value.status !== 'PASS' ||
    value.artifactName !== RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME ||
    value.artifactName === RELEASE_SUCCESSOR_INPUT_ARTIFACT_NAME ||
    value.repository !== RELEASE_SUCCESSOR_REPOSITORY ||
    value.workflowPath !== RELEASE_SUCCESSOR_WORKFLOW_PATH ||
    value.sourceEvent !== 'workflow_dispatch' ||
    value.sourceRef !== RELEASE_SUCCESSOR_MASTER_REF ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    value.sourceRunAttempt !== 1 ||
    !SHA.test(value.headSha ?? '') ||
    !RELEASE_ID.test(value.releaseId ?? '') ||
    !RELEASE_TAG.test(value.releaseTag ?? '') ||
    ![
      'RELEASE_SUCCESSOR_POST_SUCCESS',
      'RELEASE_SUCCESSOR_POST_SUCCESS_COMPOSITE_RECOVERY',
    ].includes(value.sourceKind) ||
    ![
      value.predecessorManifestSha256,
      value.candidateRecordSha256,
      value.rollbackRehearsalSha256,
      value.journalLifecycleSha256,
      value.reconciliationJournalAuthoritySha256,
      value.releaseFenceAuthoritySetSha256,
      value.releaseEvidenceSetSha256,
      value.finalDisableEvidenceSha256,
      value.bundleSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !object(value.reconciliationJournalAuthority) ||
    value.reconciliationJournalAuthority.journalAuthoritySha256 !==
      value.reconciliationJournalAuthoritySha256 ||
    value.reconciliationJournalAuthoritySha256 !==
      objectSha256(withoutDigest(value.reconciliationJournalAuthority, 'journalAuthoritySha256')) ||
    !exactKeys(value.reconciliationEvidenceBindings, [
      'rollbackCheck',
      'rollbackResilience',
      'preFenceGate',
    ]) ||
    !validateReconciliationEvidenceBinding(value.reconciliationEvidenceBindings.rollbackCheck, {
      pathName: RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackCheck,
      digestName: 'receiptSha256',
      digest: value.reconciliationEvidenceBindings.rollbackCheck?.receiptSha256,
    }) ||
    !validateReconciliationEvidenceBinding(
      value.reconciliationEvidenceBindings.rollbackResilience,
      {
        pathName: RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackResilience,
        digestName: 'receiptSha256',
        digest: value.reconciliationEvidenceBindings.rollbackResilience?.receiptSha256,
      },
    ) ||
    !validateReconciliationEvidenceBinding(value.reconciliationEvidenceBindings.preFenceGate, {
      pathName: RELEASE_SUCCESSOR_SOURCE_LAYOUT.preFenceGate,
      digestName: 'gateSha256',
      digest: value.reconciliationEvidenceBindings.preFenceGate?.gateSha256,
    }) ||
    !validateJournalSnapshotBinding(value.journalSnapshotBinding) ||
    !Array.isArray(value.files) ||
    value.files.length !== RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES.length ||
    value.files.map(({ path: pathName } = {}) => pathName).join('\0') !==
      RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES.join('\0') ||
    value.files.some((entry) => !validateRawEntry(entry)) ||
    !exactKeys(
      value.canonicalSha256ByPath,
      RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES.filter(
        (name) => name !== RELEASE_SUCCESSOR_SOURCE_LAYOUT.rawDiff,
      ),
    ) ||
    Object.values(value.canonicalSha256ByPath).some((digest) => !SHA256.test(digest ?? '')) ||
    !exactKeys(value.artifactOriginsByPath, RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES) ||
    Object.values(value.artifactOriginsByPath).some(
      (origin) =>
        ![
          ...RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS,
          'GITHUB_POST_SUCCESS_OBSERVATION',
          'PROTECTED_CURRENT_RELEASE_CONFIG',
          'POST_SUCCESS_DERIVED',
          'POST_SUCCESS_AWS_FINALIZATION',
          'POST_SUCCESS_SSM_JOURNAL_SNAPSHOT',
          'POST_SUCCESS_RECOMPUTED_ROLLBACK_CONTEXT',
          'RECOVERY_RESULT_SUPPLEMENT',
          'POST_SUCCESS_COMPOSITE_RECOVERY_CLOSEOUT',
        ].includes(origin),
    ) ||
    !utc(value.capturedAtUtc) ||
    !Number.isSafeInteger(value.externalRequests) ||
    value.externalRequests < 3 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.provenanceSha256 !== objectSha256(sourceProvenanceBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_PROVENANCE_INVALID');
  }
  return value;
};
