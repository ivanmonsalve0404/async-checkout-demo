import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import {
  canonicalJson,
  objectSha256,
  validateStage7PreviousReleaseHandoff,
  validateStage7PreviousReleaseManifest,
} from './core.mjs';
import { createRollbackResilienceSelfTestFixture } from './rollback-resilience-producer.mjs';
import { validateReleaseSuccessorSourceProvenance } from './release-successor-source-provenance.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const INPUT_ARTIFACT_NAME = 'stage7-previous-release';
const JOURNAL_SNAPSHOT_BASENAME = 'release-successor-journal-snapshot.json';

export const PREVIOUS_RELEASE_PROJECTION_FILENAMES = Object.freeze([
  'previous-release-manifest.json',
  'previous-source-provenance.json',
  'previous-target-compatibility.json',
  'previous-final-disable-provenance.json',
  'previous-api-contract-evidence.json',
  'previous-pending-evidence.json',
  'previous-smoke-evidence.json',
  'previous-release-projection-index.json',
]);

const PROJECTION_PAYLOAD_FILENAMES = PREVIOUS_RELEASE_PROJECTION_FILENAMES.slice(0, 7);

class Stage7PreviousReleaseProjectionError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7PreviousReleaseProjectionError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7PreviousReleaseProjectionError(code, cause === undefined ? undefined : { cause });
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
const normalizedRunAttempt = (value) =>
  Number.isSafeInteger(value) && value >= 1 && value <= 100 ? value : null;
const projectionIndexBody = (value) => withoutDigest(value, 'projectionIndexSha256');
const rawEntry = (pathName, source) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '');
  return { path: pathName, sha256: sha256(bytes), bytes: bytes.length };
};
const validateRawEntry = (value) =>
  exactKeys(value, ['path', 'sha256', 'bytes']) &&
  typeof value.path === 'string' &&
  value.path.length > 0 &&
  SHA256.test(value.sha256 ?? '') &&
  Number.isSafeInteger(value.bytes) &&
  value.bytes >= 2;
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
  value.path === JOURNAL_SNAPSHOT_BASENAME &&
  [value.rawSha256, value.canonicalSha256, value.snapshotSha256, value.targetNameSetSha256].every(
    (digest) => SHA256.test(digest ?? ''),
  ) &&
  Number.isSafeInteger(value.bytes) &&
  value.bytes >= 2 &&
  Number.isSafeInteger(value.entryCount) &&
  value.entryCount >= 3;

const strictJsonDocument = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_SOURCE_BYTES) fail(code);
  let value;
  try {
    value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
  } catch (error) {
    fail(code, error);
  }
  if (!object(value) || value.containsSensitiveData !== false) fail(code);
  return {
    value,
    bytes,
    rawSha256: sha256(bytes),
    canonicalSha256: objectSha256(value),
    byteLength: bytes.length,
  };
};

const exactDirectoryFiles = (directory, expected, code) => {
  let actual;
  try {
    actual = readFileSet(directory);
  } catch (error) {
    fail(code, error);
  }
  if (actual.join('\0') !== [...expected].toSorted().join('\0')) fail(code);
};

const readFileSet = (directory) => {
  const entries = [];
  const stack = [{ absolute: directory, relative: '' }];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of readDirectory(current.absolute)) {
      const relative = current.relative === '' ? entry.name : `${current.relative}/${entry.name}`;
      const absolute = path.join(current.absolute, entry.name);
      if (entry.isDirectory()) stack.push({ absolute, relative });
      else if (entry.isFile()) entries.push(relative);
      else fail('E7_PREVIOUS_RELEASE_PROJECTION_FILE_SET_INVALID');
    }
  }
  return entries.toSorted();
};

const readDirectory = (directory) => {
  try {
    return readdirSync(directory, { withFileTypes: true });
  } catch (error) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_FILE_SET_INVALID', error);
  }
};

const evidenceBody = (value) => withoutDigest(value, 'evidenceSha256');

const validateProjectedJsonBinding = (value) =>
  exactKeys(value, ['path', 'rawSha256', 'canonicalSha256', 'bytes']) &&
  typeof value.path === 'string' &&
  value.path.length > 0 &&
  SHA256.test(value.rawSha256 ?? '') &&
  SHA256.test(value.canonicalSha256 ?? '') &&
  Number.isSafeInteger(value.bytes) &&
  value.bytes >= 2;

const validateProjectedApiContractEvidence = (value, identity) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'freezeManifestSha256',
      'openApiSha256',
      'generatedClientSha256',
      'apiDeployment',
      'verifiedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'evidenceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_API_CONTRACT_EVIDENCE' ||
    value.status !== 'PASS' ||
    value.candidateSha !== identity.candidateSha ||
    value.releaseId !== identity.releaseId ||
    ![value.freezeManifestSha256, value.openApiSha256, value.generatedClientSha256].every(
      (digest) => SHA256.test(digest ?? ''),
    ) ||
    !validateProjectedJsonBinding(value.apiDeployment) ||
    !utc(value.verifiedAtUtc) ||
    value.externalRequests !== 0 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.evidenceSha256 !== objectSha256(evidenceBody(value))
  ) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_API_INVALID');
  }
  return value;
};

const validateProjectedPendingEvidence = (value, identity) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'policy',
      'pendingProducer',
      'rollbackCompletion',
      'pendingScenarioIds',
      'dataRollbackPerformed',
      'verifiedAtUtc',
      'containsSensitiveData',
      'evidenceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_PENDING_RECONCILIATION_EVIDENCE' ||
    value.status !== 'PASS' ||
    value.candidateSha !== identity.candidateSha ||
    value.releaseId !== identity.releaseId ||
    value.policy !== 'FORWARD_ONLY_NO_DATA_ROLLBACK' ||
    !validateProjectedJsonBinding(value.pendingProducer) ||
    !validateProjectedJsonBinding(value.rollbackCompletion) ||
    !Array.isArray(value.pendingScenarioIds) ||
    value.pendingScenarioIds.length !== 0 ||
    value.dataRollbackPerformed !== false ||
    !utc(value.verifiedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.evidenceSha256 !== objectSha256(evidenceBody(value))
  ) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_PENDING_INVALID');
  }
  return value;
};

const validateProjectedSmokeEvidence = (value, identity) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'postdeploySmoke',
      'repromotionSmoke',
      'rollbackCompletion',
      'finalTarget',
      'dataMutations',
      'verifiedAtUtc',
      'containsSensitiveData',
      'evidenceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_SMOKE_EVIDENCE' ||
    value.status !== 'PASS' ||
    value.candidateSha !== identity.candidateSha ||
    value.releaseId !== identity.releaseId ||
    !validateProjectedJsonBinding(value.postdeploySmoke) ||
    !validateProjectedJsonBinding(value.repromotionSmoke) ||
    !validateProjectedJsonBinding(value.rollbackCompletion) ||
    value.finalTarget !== 'RELEASE_N_REPROMOTED' ||
    value.dataMutations !== 0 ||
    !utc(value.verifiedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.evidenceSha256 !== objectSha256(evidenceBody(value))
  ) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_SMOKE_INVALID');
  }
  return value;
};

const validateReleaseSuccessorProjectionCompanions = ({
  previousReleaseManifest,
  sourceProvenanceSource,
  targetCompatibilitySource,
  finalDisableSource,
  apiContractSource,
  pendingSource,
  smokeSource,
}) => {
  validateStage7PreviousReleaseManifest(previousReleaseManifest);
  if (previousReleaseManifest.handoff.sourceKind !== 'RELEASE_SUCCESSOR') {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_SOURCE_KIND_INVALID');
  }
  const sourceProvenance = strictJsonDocument(
    sourceProvenanceSource,
    'E7_PREVIOUS_RELEASE_PROJECTION_SOURCE_PROVENANCE_INVALID',
  );
  const targetCompatibility = strictJsonDocument(
    targetCompatibilitySource,
    'E7_PREVIOUS_RELEASE_PROJECTION_TARGET_COMPATIBILITY_INVALID',
  );
  const finalDisable = strictJsonDocument(
    finalDisableSource,
    'E7_PREVIOUS_RELEASE_PROJECTION_FINAL_DISABLE_INVALID',
  );
  const api = strictJsonDocument(apiContractSource, 'E7_PREVIOUS_RELEASE_PROJECTION_API_INVALID');
  const pending = strictJsonDocument(
    pendingSource,
    'E7_PREVIOUS_RELEASE_PROJECTION_PENDING_INVALID',
  );
  const smoke = strictJsonDocument(smokeSource, 'E7_PREVIOUS_RELEASE_PROJECTION_SMOKE_INVALID');
  validateReleaseSuccessorSourceProvenance(sourceProvenance.value);
  const compatibility = targetCompatibility.value;
  const identity = {
    candidateSha: previousReleaseManifest.previous.candidateSha,
    releaseId: previousReleaseManifest.previous.releaseId,
  };
  validateProjectedApiContractEvidence(api.value, identity);
  validateProjectedPendingEvidence(pending.value, identity);
  validateProjectedSmokeEvidence(smoke.value, identity);
  try {
    validateStage7PreviousReleaseHandoff(previousReleaseManifest, {
      sourceProvenance: sourceProvenance.value,
      targetCompatibility: compatibility,
      finalDisableProvenance: finalDisable.value,
    });
  } catch (error) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_HANDOFF_INVALID', error);
  }
  if (
    !exactKeys(compatibility, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'baselineBundleSha256',
      'sourceArtifactProvenanceSha256',
      'finalDisableEvidenceSha256',
      'consumptionAuthoritySha256',
      'reconciliationJournalAuthoritySha256',
      'releaseFenceAuthoritySetSha256',
      'journalSnapshotBinding',
      'predecessorManifestSha256',
      'previousCandidateSha',
      'previousReleaseId',
      'targetCandidateSha',
      'targetReleaseId',
      'targetFreezeManifestSha256',
      'schemaStrategy',
      'dataRollback',
      'apiContractRawSha256',
      'apiContractCanonicalSha256',
      'pendingReconciliationRawSha256',
      'pendingReconciliationCanonicalSha256',
      'smokeRawSha256',
      'smokeCanonicalSha256',
      'originProtectionContractSha256',
      'verifiedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'compatibilitySha256',
    ]) ||
    compatibility.schemaVersion !== 1 ||
    compatibility?.stage !== 7 ||
    compatibility?.kind !== 'RELEASE_SUCCESSOR_COMPATIBILITY' ||
    compatibility?.status !== 'PASS' ||
    compatibility.previousCandidateSha !== identity.candidateSha ||
    compatibility.previousReleaseId !== identity.releaseId ||
    compatibility.targetCandidateSha !== previousReleaseManifest.target.candidateSha ||
    compatibility.targetReleaseId !== previousReleaseManifest.target.releaseId ||
    compatibility.targetFreezeManifestSha256 !==
      previousReleaseManifest.target.freezeManifestSha256 ||
    compatibility.baselineBundleSha256 !== sourceProvenance.value.bundleSha256 ||
    compatibility.sourceArtifactProvenanceSha256 !== sourceProvenance.canonicalSha256 ||
    compatibility.predecessorManifestSha256 !==
      previousReleaseManifest.handoff.predecessorManifestSha256 ||
    compatibility.apiContractRawSha256 !== api.rawSha256 ||
    compatibility.apiContractCanonicalSha256 !== api.canonicalSha256 ||
    compatibility.pendingReconciliationRawSha256 !== pending.rawSha256 ||
    compatibility.pendingReconciliationCanonicalSha256 !== pending.canonicalSha256 ||
    compatibility.smokeRawSha256 !== smoke.rawSha256 ||
    compatibility.smokeCanonicalSha256 !== smoke.canonicalSha256 ||
    compatibility.schemaStrategy !== 'EXPAND_CONTRACT_N_AND_N_MINUS_1' ||
    compatibility.dataRollback !== 'FORBIDDEN_FORWARD_ONLY' ||
    !SHA256.test(compatibility.consumptionAuthoritySha256 ?? '') ||
    compatibility.reconciliationJournalAuthoritySha256 !==
      sourceProvenance.value.reconciliationJournalAuthoritySha256 ||
    compatibility.releaseFenceAuthoritySetSha256 !==
      sourceProvenance.value.releaseFenceAuthoritySetSha256 ||
    !validateJournalSnapshotBinding(compatibility.journalSnapshotBinding) ||
    canonicalJson(compatibility.journalSnapshotBinding) !==
      canonicalJson(sourceProvenance.value.journalSnapshotBinding) ||
    !SHA256.test(compatibility.originProtectionContractSha256 ?? '') ||
    !utc(compatibility.verifiedAtUtc) ||
    compatibility.externalRequests !== 0 ||
    compatibility.mutationsPerformed !== 0 ||
    compatibility.containsSensitiveData !== false ||
    compatibility.compatibilitySha256 !==
      objectSha256(withoutDigest(compatibility, 'compatibilitySha256')) ||
    previousReleaseManifest.handoff.sourceBundleSha256 !== sourceProvenance.value.bundleSha256 ||
    previousReleaseManifest.handoff.sourceArtifactProvenanceSha256 !==
      sourceProvenance.canonicalSha256 ||
    previousReleaseManifest.handoff.targetCompatibilityEvidenceSha256 !==
      targetCompatibility.canonicalSha256 ||
    previousReleaseManifest.compatibility.apiContractEvidenceSha256 !== api.rawSha256 ||
    previousReleaseManifest.compatibility.pendingReconciliationEvidenceSha256 !==
      pending.rawSha256 ||
    previousReleaseManifest.compatibility.smokeEvidenceSha256 !== smoke.rawSha256 ||
    previousReleaseManifest.compatibility.smokeVerifiedAtUtc !== smoke.value.verifiedAtUtc
  ) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_COMPANION_BINDING_INVALID');
  }
  return {
    sourceProvenance,
    targetCompatibility,
    finalDisable,
    api,
    pending,
    smoke,
  };
};

export const createPreviousReleaseProjectionIndex = ({
  sourceKind,
  sourceBundle,
  previousReleaseManifest,
  files,
}) => {
  validateStage7PreviousReleaseManifest(previousReleaseManifest);
  if (
    !['BASELINE_BOOTSTRAP', 'RELEASE_SUCCESSOR'].includes(sourceKind) ||
    previousReleaseManifest.handoff.sourceKind !== sourceKind ||
    !exactKeys(
      sourceBundle,
      sourceKind === 'RELEASE_SUCCESSOR'
        ? [
            'artifactName',
            'bundleSha256',
            'sourceRunId',
            'sourceRunAttempt',
            'headSha',
            'consumptionAuthoritySha256',
            'reconciliationJournalAuthority',
            'reconciliationJournalAuthoritySha256',
            'releaseFenceAuthoritySetSha256',
            'journalSnapshotBinding',
          ]
        : ['artifactName', 'bundleSha256', 'sourceRunId', 'sourceRunAttempt', 'headSha'],
    ) ||
    typeof sourceBundle.artifactName !== 'string' ||
    sourceBundle.artifactName.length < 1 ||
    sourceBundle.bundleSha256 !== previousReleaseManifest.handoff.sourceBundleSha256 ||
    !RUN_ID.test(sourceBundle.sourceRunId ?? '') ||
    normalizedRunAttempt(sourceBundle.sourceRunAttempt) === null ||
    !SHA.test(sourceBundle.headSha ?? '') ||
    sourceBundle.headSha !== previousReleaseManifest.previous.candidateSha ||
    (sourceKind === 'RELEASE_SUCCESSOR' &&
      (!SHA256.test(sourceBundle.consumptionAuthoritySha256 ?? '') ||
        !object(sourceBundle.reconciliationJournalAuthority) ||
        !SHA256.test(sourceBundle.reconciliationJournalAuthoritySha256 ?? '') ||
        !SHA256.test(sourceBundle.releaseFenceAuthoritySetSha256 ?? '') ||
        sourceBundle.reconciliationJournalAuthority.journalAuthoritySha256 !==
          sourceBundle.reconciliationJournalAuthoritySha256 ||
        sourceBundle.reconciliationJournalAuthoritySha256 !==
          objectSha256(
            withoutDigest(sourceBundle.reconciliationJournalAuthority, 'journalAuthoritySha256'),
          ) ||
        !validateJournalSnapshotBinding(sourceBundle.journalSnapshotBinding) ||
        sourceBundle.sourceRunAttempt !== 1)) ||
    !object(files) ||
    !exactKeys(files, PROJECTION_PAYLOAD_FILENAMES)
  ) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_INPUT_INVALID');
  }
  const entries = PROJECTION_PAYLOAD_FILENAMES.map((pathName) => {
    const bytes = Buffer.isBuffer(files[pathName])
      ? files[pathName]
      : Buffer.from(files[pathName] ?? '');
    if (bytes.length < 2) fail('E7_PREVIOUS_RELEASE_PROJECTION_FILE_INVALID');
    return rawEntry(pathName, bytes);
  });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_PREVIOUS_RELEASE_TARGET_PROJECTION_INDEX',
    status: 'APPROVED_IMMUTABLE_TARGET_PROJECTION',
    artifactName: INPUT_ARTIFACT_NAME,
    identity: {
      previousCandidateSha: previousReleaseManifest.previous.candidateSha,
      previousReleaseId: previousReleaseManifest.previous.releaseId,
      targetCandidateSha: previousReleaseManifest.target.candidateSha,
      targetReleaseId: previousReleaseManifest.target.releaseId,
      targetFreezeManifestSha256: previousReleaseManifest.target.freezeManifestSha256,
      predecessorManifestSha256: previousReleaseManifest.handoff.predecessorManifestSha256,
    },
    sourceKind,
    sourceBundle,
    files: entries,
    containsSensitiveData: false,
  };
  return validatePreviousReleaseProjectionIndex({
    ...body,
    projectionIndexSha256: objectSha256(body),
  });
};

export const validatePreviousReleaseProjectionIndex = (
  value,
  { previousReleaseManifest, files } = {},
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'artifactName',
      'identity',
      'sourceKind',
      'sourceBundle',
      'files',
      'containsSensitiveData',
      'projectionIndexSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_PREVIOUS_RELEASE_TARGET_PROJECTION_INDEX' ||
    value.status !== 'APPROVED_IMMUTABLE_TARGET_PROJECTION' ||
    value.artifactName !== INPUT_ARTIFACT_NAME ||
    !exactKeys(value.identity, [
      'previousCandidateSha',
      'previousReleaseId',
      'targetCandidateSha',
      'targetReleaseId',
      'targetFreezeManifestSha256',
      'predecessorManifestSha256',
    ]) ||
    !SHA.test(value.identity.previousCandidateSha ?? '') ||
    !RELEASE_ID.test(value.identity.previousReleaseId ?? '') ||
    !SHA.test(value.identity.targetCandidateSha ?? '') ||
    value.identity.targetCandidateSha === value.identity.previousCandidateSha ||
    !RELEASE_ID.test(value.identity.targetReleaseId ?? '') ||
    !SHA256.test(value.identity.targetFreezeManifestSha256 ?? '') ||
    !(
      (value.sourceKind === 'BASELINE_BOOTSTRAP' &&
        value.identity.predecessorManifestSha256 === null) ||
      (value.sourceKind === 'RELEASE_SUCCESSOR' &&
        SHA256.test(value.identity.predecessorManifestSha256 ?? ''))
    ) ||
    !exactKeys(
      value.sourceBundle,
      value.sourceKind === 'RELEASE_SUCCESSOR'
        ? [
            'artifactName',
            'bundleSha256',
            'sourceRunId',
            'sourceRunAttempt',
            'headSha',
            'consumptionAuthoritySha256',
            'reconciliationJournalAuthority',
            'reconciliationJournalAuthoritySha256',
            'releaseFenceAuthoritySetSha256',
            'journalSnapshotBinding',
          ]
        : ['artifactName', 'bundleSha256', 'sourceRunId', 'sourceRunAttempt', 'headSha'],
    ) ||
    typeof value.sourceBundle.artifactName !== 'string' ||
    value.sourceBundle.artifactName.length < 1 ||
    !SHA256.test(value.sourceBundle.bundleSha256 ?? '') ||
    !RUN_ID.test(value.sourceBundle.sourceRunId ?? '') ||
    normalizedRunAttempt(value.sourceBundle.sourceRunAttempt) === null ||
    value.sourceBundle.headSha !== value.identity.previousCandidateSha ||
    (value.sourceKind === 'RELEASE_SUCCESSOR' &&
      (!SHA256.test(value.sourceBundle.consumptionAuthoritySha256 ?? '') ||
        !object(value.sourceBundle.reconciliationJournalAuthority) ||
        !SHA256.test(value.sourceBundle.reconciliationJournalAuthoritySha256 ?? '') ||
        !SHA256.test(value.sourceBundle.releaseFenceAuthoritySetSha256 ?? '') ||
        value.sourceBundle.reconciliationJournalAuthority.journalAuthoritySha256 !==
          value.sourceBundle.reconciliationJournalAuthoritySha256 ||
        value.sourceBundle.reconciliationJournalAuthoritySha256 !==
          objectSha256(
            withoutDigest(
              value.sourceBundle.reconciliationJournalAuthority,
              'journalAuthoritySha256',
            ),
          ) ||
        !validateJournalSnapshotBinding(value.sourceBundle.journalSnapshotBinding) ||
        value.sourceBundle.sourceRunAttempt !== 1)) ||
    !Array.isArray(value.files) ||
    value.files.length !== 7 ||
    value.files.map(({ path: pathName } = {}) => pathName).join('\0') !==
      PROJECTION_PAYLOAD_FILENAMES.join('\0') ||
    value.files.some((entry) => !validateRawEntry(entry)) ||
    value.containsSensitiveData !== false ||
    value.projectionIndexSha256 !== objectSha256(projectionIndexBody(value))
  ) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_INDEX_INVALID');
  }
  if (previousReleaseManifest !== undefined) {
    validateStage7PreviousReleaseManifest(previousReleaseManifest);
    if (
      previousReleaseManifest.handoff.sourceKind !== value.sourceKind ||
      previousReleaseManifest.handoff.sourceBundleSha256 !== value.sourceBundle.bundleSha256 ||
      previousReleaseManifest.previous.candidateSha !== value.identity.previousCandidateSha ||
      previousReleaseManifest.previous.releaseId !== value.identity.previousReleaseId ||
      previousReleaseManifest.target.candidateSha !== value.identity.targetCandidateSha ||
      previousReleaseManifest.target.releaseId !== value.identity.targetReleaseId ||
      previousReleaseManifest.target.freezeManifestSha256 !==
        value.identity.targetFreezeManifestSha256 ||
      previousReleaseManifest.handoff.predecessorManifestSha256 !==
        value.identity.predecessorManifestSha256
    ) {
      fail('E7_PREVIOUS_RELEASE_PROJECTION_IDENTITY_MISMATCH');
    }
  }
  if (files !== undefined) {
    if (!object(files) || !exactKeys(files, PROJECTION_PAYLOAD_FILENAMES)) {
      fail('E7_PREVIOUS_RELEASE_PROJECTION_FILE_SET_INVALID');
    }
    for (const entry of value.files) {
      const bytes = Buffer.isBuffer(files[entry.path])
        ? files[entry.path]
        : Buffer.from(files[entry.path] ?? '');
      if (bytes.length !== entry.bytes || sha256(bytes) !== entry.sha256) {
        fail('E7_PREVIOUS_RELEASE_PROJECTION_RAW_DIGEST_MISMATCH');
      }
    }
    if (value.sourceKind === 'RELEASE_SUCCESSOR') {
      const companions = validateReleaseSuccessorProjectionCompanions({
        previousReleaseManifest,
        sourceProvenanceSource: files['previous-source-provenance.json'],
        targetCompatibilitySource: files['previous-target-compatibility.json'],
        finalDisableSource: files['previous-final-disable-provenance.json'],
        apiContractSource: files['previous-api-contract-evidence.json'],
        pendingSource: files['previous-pending-evidence.json'],
        smokeSource: files['previous-smoke-evidence.json'],
      });
      if (
        value.sourceBundle.consumptionAuthoritySha256 !==
          companions.targetCompatibility.value.consumptionAuthoritySha256 ||
        value.sourceBundle.reconciliationJournalAuthoritySha256 !==
          companions.sourceProvenance.value.reconciliationJournalAuthoritySha256 ||
        value.sourceBundle.releaseFenceAuthoritySetSha256 !==
          companions.sourceProvenance.value.releaseFenceAuthoritySetSha256 ||
        canonicalJson(value.sourceBundle.reconciliationJournalAuthority) !==
          canonicalJson(companions.sourceProvenance.value.reconciliationJournalAuthority) ||
        value.sourceBundle.reconciliationJournalAuthoritySha256 !==
          companions.targetCompatibility.value.reconciliationJournalAuthoritySha256 ||
        canonicalJson(value.sourceBundle.journalSnapshotBinding) !==
          canonicalJson(companions.sourceProvenance.value.journalSnapshotBinding) ||
        canonicalJson(value.sourceBundle.journalSnapshotBinding) !==
          canonicalJson(companions.targetCompatibility.value.journalSnapshotBinding)
      ) {
        fail('E7_PREVIOUS_RELEASE_PROJECTION_AUTHORITY_MISMATCH');
      }
    }
  }
  return value;
};

export const validatePreviousReleaseProjection = (directory) => {
  exactDirectoryFiles(
    directory,
    PREVIOUS_RELEASE_PROJECTION_FILENAMES,
    'E7_PREVIOUS_RELEASE_PROJECTION_FILE_SET_INVALID',
  );
  const files = Object.fromEntries(
    PREVIOUS_RELEASE_PROJECTION_FILENAMES.map((name) => [
      name,
      readFileSync(path.join(directory, name)),
    ]),
  );
  const previousRelease = validateStage7PreviousReleaseManifest(
    strictJsonDocument(
      files['previous-release-manifest.json'],
      'E7_PREVIOUS_RELEASE_PROJECTION_MANIFEST_INVALID',
    ).value,
  );
  const index = validatePreviousReleaseProjectionIndex(
    strictJsonDocument(
      files['previous-release-projection-index.json'],
      'E7_PREVIOUS_RELEASE_PROJECTION_INDEX_FILE_INVALID',
    ).value,
    {
      previousReleaseManifest: previousRelease,
      files: Object.fromEntries(PROJECTION_PAYLOAD_FILENAMES.map((name) => [name, files[name]])),
    },
  );
  return { files, index, previousRelease };
};

export const selfTestPreviousReleaseProjection = () => {
  const previousReleaseManifest =
    createRollbackResilienceSelfTestFixture().inputs.previousReleaseManifest;
  const encode = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  const projectionFiles = Object.fromEntries(
    PROJECTION_PAYLOAD_FILENAMES.map((name) => [
      name,
      name === 'previous-release-manifest.json'
        ? encode(previousReleaseManifest)
        : encode({ name, containsSensitiveData: false }),
    ]),
  );
  const sourceBundle = {
    artifactName: 'stage7-baseline-source-r1-a1',
    bundleSha256: previousReleaseManifest.handoff.sourceBundleSha256,
    sourceRunId: '1',
    sourceRunAttempt: 1,
    headSha: previousReleaseManifest.previous.candidateSha,
  };
  const projectionIndex = createPreviousReleaseProjectionIndex({
    sourceKind: 'BASELINE_BOOTSTRAP',
    sourceBundle,
    previousReleaseManifest,
    files: projectionFiles,
  });
  assert.equal(projectionIndex.files.length, 7);
  assert.equal(
    projectionIndex.files.some(
      ({ path: pathName }) => pathName === 'previous-release-projection-index.json',
    ),
    false,
  );
  assert.throws(
    () =>
      createPreviousReleaseProjectionIndex({
        sourceKind: 'RELEASE_SUCCESSOR',
        sourceBundle,
        previousReleaseManifest,
        files: projectionFiles,
      }),
    (error) => error.code === 'E7_PREVIOUS_RELEASE_PROJECTION_INPUT_INVALID',
  );
  assert.throws(
    () =>
      validatePreviousReleaseProjectionIndex(projectionIndex, {
        previousReleaseManifest,
        files: {
          ...projectionFiles,
          'previous-smoke-evidence.json': Buffer.from('{"tampered":true}\n', 'utf8'),
        },
      }),
    (error) => error.code === 'E7_PREVIOUS_RELEASE_PROJECTION_RAW_DIGEST_MISMATCH',
  );
  const modified = {
    ...projectionIndex,
    files: projectionIndex.files.map((entry, index) =>
      index === 0 ? { ...entry, bytes: entry.bytes + 1 } : entry,
    ),
  };
  assert.throws(
    () => validatePreviousReleaseProjectionIndex(modified),
    (error) => error.code === 'E7_PREVIOUS_RELEASE_PROJECTION_INDEX_INVALID',
  );

  const temporaryRoot = mkdtempSync(path.join(os.tmpdir(), 'stage7-projection-selftest-'));
  const directory = path.join(temporaryRoot, 'projection');
  mkdirSync(directory, { mode: 0o700 });
  try {
    for (const [name, bytes] of Object.entries(projectionFiles)) {
      writeFileSync(path.join(directory, name), bytes, { flag: 'wx', mode: 0o600 });
    }
    writeFileSync(
      path.join(directory, 'previous-release-projection-index.json'),
      encode(projectionIndex),
      {
        flag: 'wx',
        mode: 0o600,
      },
    );
    const validated = validatePreviousReleaseProjection(directory);
    assert.equal(validated.index.projectionIndexSha256, projectionIndex.projectionIndexSha256);
    writeFileSync(
      path.join(directory, 'unexpected.json'),
      encode({ containsSensitiveData: false }),
      {
        flag: 'wx',
        mode: 0o600,
      },
    );
    assert.throws(
      () => validatePreviousReleaseProjection(directory),
      (error) => error.code === 'E7_PREVIOUS_RELEASE_PROJECTION_FILE_SET_INVALID',
    );
  } finally {
    rmSync(temporaryRoot, { recursive: true, force: true });
  }
  return { status: 'PASS', checks: 6, externalRequests: 0 };
};
