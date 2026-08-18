import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import {
  canonicalJson,
  assessStage6Manifest,
  objectSha256,
  validateFreezeManifest,
  validateStage7ActivationCheckpoint,
  validateStage7CandidateRollbackRecord,
  validateStage7Config,
  validateStage7DriftCheckpoint,
  validateStage7PreviousReleaseHandoff,
  validateStage7PreviousReleaseManifest,
} from './core.mjs';
import { validateRollbackResilienceCompletionEnvelope } from './rollback-resilience-integration.mjs';
import { createRollbackResilienceSelfTestFixture } from './rollback-resilience-producer.mjs';
import {
  createCandidateActiveNoActionRecovery,
  validateCandidateActiveNoActionOutcome,
} from './aws-operations.mjs';
import { validateGithubEnvironmentApproval } from './github-environment-approval.mjs';
import {
  STAGE7_FULL_SOURCE_ARTIFACT_NAMES,
  STAGE7_LEDGER_SOURCE_BINDING_SPECS,
  STAGE7_SOURCE_PRODUCERS,
  createCompositeRecoveryJobResultsDocument,
  validateStage7ProvenanceLedger,
} from './evidence-provenance.mjs';
import {
  createReleaseSuccessorStoredZipFixture,
  readReleaseSuccessorZipEntries,
} from './release-successor-zip.mjs';
import {
  STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
  STAGE7_RELEASE_RECONCILIATION_FILES,
  validateReleasePreFenceGate,
  validateReleaseReconciliationJournalAuthority,
} from './release-reconciliation.mjs';
import {
  RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  validateReleaseJournalRoleEffectivePermissionsBinding,
} from './release-successor-iam-authority.mjs';
import {
  RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource,
} from './release-reconciliation-recovery.mjs';
import { validateReleaseSuccessorJournalSnapshot } from './release-successor-journal-snapshot.mjs';
import {
  createPreviousReleaseProjectionIndex,
  validatePreviousReleaseProjectionIndex,
} from './previous-release-projection.mjs';
import { validateReleaseSuccessorCompletionFence } from './release-successor-fence-contract.mjs';
import {
  RELEASE_SUCCESSOR_MASTER_REF,
  RELEASE_SUCCESSOR_INTERNAL_ARTIFACTS,
  RELEASE_SUCCESSOR_REPOSITORY,
  RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS,
  RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
  RELEASE_SUCCESSOR_SOURCE_LAYOUT,
  RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES,
  RELEASE_SUCCESSOR_WORKFLOW_NAME,
  RELEASE_SUCCESSOR_WORKFLOW_PATH,
} from './release-successor-contract.mjs';
import { validateReleaseSuccessorSourceProvenance } from './release-successor-source-provenance.mjs';
import {
  RECOVERY_CRASH_WINDOWS,
  RECOVERY_SOURCE_ARTIFACTS,
  createPublicationRecoveryPostSuccessIntake,
  validatePublicationRecoveryPlan,
  validatePublicationRecoveryPostSuccessIntake,
  validatePublicationRecoveryReceipt,
} from './release-successor-publication-recovery-contract.mjs';
import {
  RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH,
  RELEASE_SUCCESSOR_SOURCE_JOBS,
  createReleaseSuccessorRecoveryCloseoutAuthority,
  readReleaseSuccessorRecoveryResultFromIntake,
  validateReleaseSuccessorRecoveryCloseoutAuthority,
} from './release-successor-recovery-integration.mjs';

export {
  RELEASE_SUCCESSOR_INPUT_ARTIFACT_NAME,
  RELEASE_SUCCESSOR_INTERNAL_ARTIFACTS,
  RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH,
  RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS,
  RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
  RELEASE_SUCCESSOR_SOURCE_LAYOUT,
  RELEASE_SUCCESSOR_WORKFLOW_NAME,
  RELEASE_SUCCESSOR_WORKFLOW_PATH,
} from './release-successor-contract.mjs';
export { validateReleaseSuccessorCompletionFence } from './release-successor-fence-contract.mjs';
export { validateReleaseSuccessorSourceProvenance } from './release-successor-source-provenance.mjs';

const REPOSITORY = RELEASE_SUCCESSOR_REPOSITORY;
const MASTER_REF = RELEASE_SUCCESSOR_MASTER_REF;
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const ARTIFACT_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const SELF_TEST_CAPABILITY = Symbol('release-successor-self-test');
const PREVIOUS_RELEASE_PROJECTION_FILE_SET = Object.freeze([
  'previous-release-manifest.json',
  'previous-source-provenance.json',
  'previous-target-compatibility.json',
  'previous-final-disable-provenance.json',
  'previous-api-contract-evidence.json',
  'previous-pending-evidence.json',
  'previous-smoke-evidence.json',
  'previous-release-projection-index.json',
]);

const PROJECTION_PAYLOAD_FILENAMES = PREVIOUS_RELEASE_PROJECTION_FILE_SET.slice(0, 7);
const SOURCE_PAYLOAD_FILENAMES = RELEASE_SUCCESSOR_SOURCE_PAYLOAD_FILENAMES;
const RECOVERY_ROLE_AUTHORITY_KEYS = Object.freeze([
  'reconciliationRecoveryRoleArn',
  'reconciliationRecoveryPermissionsBoundaryArn',
  'reconciliationRecoveryRoleEffectivePermissionsRawSha256',
  'reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256',
  'reconciliationRecoveryRoleEffectivePermissionsSha256',
  'reconciliationRecoveryRoleEffectivePolicyProjectionSha256',
]);
const recoveryRoleAuthority = (value) =>
  Object.fromEntries(RECOVERY_ROLE_AUTHORITY_KEYS.map((key) => [key, value?.[key]]));

const validateReleaseSuccessorAuxiliaryRoleEffectivePermissions = ({ documents, freeze }) => {
  try {
    const journalRoleEffectivePermissions = validateReleaseJournalRoleEffectivePermissionsBinding({
      awsAuthSource: documents.awsAuth.bytes,
      effectivePermissionsSource: documents.journalRoleEffectivePermissions.bytes,
      expected: {
        candidateSha: freeze.candidateSha,
        releaseId: freeze.releaseId,
        configSha256: freeze.configSha256,
        manifestSha256: freeze.manifestSha256,
      },
    }).effectivePermissions.value;
    const reconciliationRecoveryRoleEffectivePermissions =
      parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource(
        documents.reconciliationRecoveryRoleEffectivePermissions.bytes,
        {
          roleArn: documents.awsAuth.value.reconciliationRecoveryRoleArn,
          permissionsBoundaryArn:
            documents.awsAuth.value.reconciliationRecoveryPermissionsBoundaryArn,
        },
      );
    if (
      documents.awsAuth.value.reconciliationRecoveryRoleEffectivePermissionsRawSha256 !==
        reconciliationRecoveryRoleEffectivePermissions.rawSha256 ||
      documents.awsAuth.value.reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256 !==
        reconciliationRecoveryRoleEffectivePermissions.canonicalSha256 ||
      documents.awsAuth.value.reconciliationRecoveryRoleEffectivePermissionsSha256 !==
        reconciliationRecoveryRoleEffectivePermissions.value.effectivePermissionsSha256 ||
      documents.awsAuth.value.reconciliationRecoveryRoleEffectivePolicyProjectionSha256 !==
        reconciliationRecoveryRoleEffectivePermissions.value.effectivePolicyProjectionSha256
    ) {
      fail('E7_RELEASE_SUCCESSOR_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_INVALID');
    }
    return {
      journalRoleEffectivePermissions,
      reconciliationRecoveryRoleEffectivePermissions,
    };
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_AUXILIARY_ROLE_EFFECTIVE_PERMISSIONS_INVALID', error);
  }
};

const validateReleaseSuccessorAuxiliaryRoleBindings = ({ documents }) => {
  const recoveryAuthority = recoveryRoleAuthority(documents.awsAuth.value);
  if (
    documents.approval.value.journalRoleEffectivePermissionsRawSha256 !==
      documents.awsAuth.value.journalRoleEffectivePermissionsRawSha256 ||
    documents.approval.value.journalRoleEffectivePermissionsSha256 !==
      documents.awsAuth.value.journalRoleEffectivePermissionsSha256 ||
    canonicalJson(recoveryRoleAuthority(documents.approval.value)) !==
      canonicalJson(recoveryAuthority) ||
    documents.rollbackSourceBinding.value.reconciliationRecoveryRoleAuthoritySha256 !==
      objectSha256(recoveryAuthority)
  ) {
    fail('E7_RELEASE_SUCCESSOR_AUXILIARY_ROLE_BINDING_INVALID');
  }
};

const emergencyNoActionSourceBinding = (label, basename, document) => ({
  label,
  basename,
  rawSha256: document.rawSha256,
  canonicalSha256: document.canonicalSha256,
  bytes: document.byteLength,
});

const validateReleaseSuccessorEmergencyRecoveryNoAction = ({
  documents,
  config,
  freeze,
  predecessor,
  candidateRecord,
  sourceRunId,
}) => {
  try {
    const deploymentEvidence = strictJsonDocument(
      documents.rollbackInputs.value?.documents?.deploymentEvidence?.content,
      'E7_RELEASE_SUCCESSOR_EMERGENCY_RECOVERY_DEPLOYMENT_EVIDENCE_INVALID',
    );
    const expectedSourceBindings = [
      emergencyNoActionSourceBinding('manifest', 'candidate-manifest.json', documents.freeze),
      emergencyNoActionSourceBinding(
        'previous-manifest',
        'previous-release-manifest.json',
        documents.predecessor,
      ),
      emergencyNoActionSourceBinding(
        'previous-api-contract-evidence',
        'previous-api-contract-evidence.json',
        documents.predecessorApiContract,
      ),
      emergencyNoActionSourceBinding(
        'previous-pending-evidence',
        'previous-pending-evidence.json',
        documents.predecessorPending,
      ),
      emergencyNoActionSourceBinding(
        'previous-smoke-evidence',
        'previous-smoke-evidence.json',
        documents.predecessorSmoke,
      ),
      emergencyNoActionSourceBinding(
        'candidate-record',
        'versioned-rollback-candidate.json',
        documents.candidateRecord,
      ),
      emergencyNoActionSourceBinding('approval', 'approval.json', documents.approval),
      emergencyNoActionSourceBinding('aws-auth', 'aws-auth.json', documents.awsAuth),
      emergencyNoActionSourceBinding(
        'journal-role-effective-permissions',
        RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
        documents.journalRoleEffectivePermissions,
      ),
      emergencyNoActionSourceBinding('approved-plan', 'infra-diff.json', documents.approvedPlan),
      emergencyNoActionSourceBinding('deployment-evidence', 'web.json', deploymentEvidence),
    ];
    const outcome = documents.emergencyRecoveryNoActionOutcome.value;
    const recovery = documents.emergencyRecovery.value;
    if (outcome.status !== 'PASS' || outcome.decision !== 'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED') {
      fail('E7_RELEASE_SUCCESSOR_EMERGENCY_RECOVERY_NO_ACTION_REQUIRED');
    }
    const expectedRecovery = createCandidateActiveNoActionRecovery({
      previousManifest: predecessor,
      candidateRecord,
      publicationState: {
        api: outcome.observations?.before?.state?.publication?.api?.state,
        web: outcome.observations?.before?.state?.publication?.web?.state,
      },
      observedState: recovery.observedState,
      completedAtUtc: recovery.completedAtUtc,
    });
    const readRoleArn = config.aws.roles.readRoleArn;
    const readRoleName = readRoleArn.split('/').at(-1);
    if (
      typeof readRoleName !== 'string' ||
      readRoleName.length === 0 ||
      canonicalJson(recovery) !== canonicalJson(expectedRecovery) ||
      outcome.previousReleaseManifestSha256 !== predecessor.manifestSha256 ||
      outcome.candidateRecordSha256 !== candidateRecord.recordSha256 ||
      outcome.assemblySha256 !== predecessor.target.assemblySha256 ||
      outcome.completedAtUtc !== recovery.completedAtUtc
    ) {
      fail('E7_RELEASE_SUCCESSOR_EMERGENCY_RECOVERY_BINDING_INVALID');
    }
    const expectedSessionArn = `arn:aws:sts::${config.aws.accountId}:assumed-role/${readRoleName}/e7-emergency-observe-${sourceRunId}`;
    validateCandidateActiveNoActionOutcome({
      value: outcome,
      candidateRecord,
      expectedIdentity: {
        candidateSha: freeze.candidateSha,
        releaseId: freeze.releaseId,
      },
      expectedSourceBindings,
      expectedCaller: {
        accountSha256: sha256(config.aws.accountId),
        accountSuffix: config.aws.accountId.slice(-4),
        roleSha256: sha256(readRoleArn),
        sessionArnSha256: sha256(expectedSessionArn),
      },
      expectedRecoverySha256: recovery.recoverySha256,
    });
    return { recovery, outcome, expectedSourceBindings };
  } catch (error) {
    if (error?.code === 'E7_RELEASE_SUCCESSOR_EMERGENCY_RECOVERY_NO_ACTION_REQUIRED') throw error;
    fail('E7_RELEASE_SUCCESSOR_EMERGENCY_RECOVERY_NO_ACTION_INVALID', error);
  }
};

const DOCUMENT_ARTIFACT_ORIGIN = Object.freeze({
  releaseMetadata: 'stage7-release-metadata',
  stage6Closeout: 'stage7-release-metadata',
  freeze: 'stage7-candidate-manifest',
  predecessor: 'stage7-previous-release',
  predecessorSourceProvenance: 'stage7-previous-release',
  predecessorTargetCompatibility: 'stage7-previous-release',
  predecessorFinalDisable: 'stage7-previous-release',
  predecessorApiContract: 'stage7-previous-release',
  predecessorPending: 'stage7-previous-release',
  predecessorSmoke: 'stage7-previous-release',
  predecessorProjectionIndex: 'stage7-previous-release',
  candidateRecord: 'stage7-recovery-probe',
  emergencyRecovery: 'stage7-recovery-probe',
  emergencyRecoveryNoActionOutcome: 'stage7-recovery-probe',
  approvedPlan: 'stage7-infra-diff',
  rawDiff: 'stage7-infra-diff',
  githubApproval: 'stage7-approval',
  approval: 'stage7-approval',
  activation: 'stage7-activation',
  drift: 'stage7-rollback',
  rollback: 'stage7-rollback',
  rollbackSourceBinding: 'stage7-rollback-resilience',
  rollbackProtectedRun: 'stage7-rollback-resilience',
  rollbackCompletion: 'stage7-rollback-resilience',
  rollbackInputs: 'POST_SUCCESS_RECOMPUTED_ROLLBACK_CONTEXT',
  rollbackRb06: 'POST_SUCCESS_RECOMPUTED_ROLLBACK_CONTEXT',
  rollbackRb08: 'POST_SUCCESS_RECOMPUTED_ROLLBACK_CONTEXT',
  releaseManifest: 'stage7-release-reports',
  provenanceLedger: 'stage7-release-reports',
  closeout: 'stage7-release-reports',
  releaseHandoff: 'stage7-release-authorities',
  releaseFence: 'stage7-release-successor-fence',
  reconciliationRollbackCheck: STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
  reconciliationRollbackResilience: STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
  preFenceGate: STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
  awsAuth: 'stage7-aws-auth',
  journalRoleEffectivePermissions: 'stage7-aws-auth',
  reconciliationRecoveryRoleEffectivePermissions: 'stage7-aws-auth',
  publicationPreparation: 'stage7-publication',
  publicationPlan: 'stage7-publication',
  publicationTargetProof: 'stage7-publication',
  publicationOperation: 'stage7-publication',
  publicationProof: 'stage7-publication',
  apiDeployment: 'stage7-api',
  pendingProducer: 'stage7-rollback',
  postdeploySmoke: 'stage7-smoke',
  repromotionSmoke: 'stage7-rollback',
});

const DOCUMENT_ARTIFACT_BASENAME = Object.freeze({
  releaseMetadata: 'release-metadata.json',
  stage6Closeout: 'stage6-closeout.json',
  freeze: 'candidate-manifest.json',
  predecessor: 'previous-release-manifest.json',
  predecessorSourceProvenance: 'previous-source-provenance.json',
  predecessorTargetCompatibility: 'previous-target-compatibility.json',
  predecessorFinalDisable: 'previous-final-disable-provenance.json',
  predecessorApiContract: 'previous-api-contract-evidence.json',
  predecessorPending: 'previous-pending-evidence.json',
  predecessorSmoke: 'previous-smoke-evidence.json',
  predecessorProjectionIndex: 'previous-release-projection-index.json',
  candidateRecord: 'versioned-rollback-candidate.json',
  emergencyRecovery: 'emergency-recovery.json',
  emergencyRecoveryNoActionOutcome: 'emergency-recovery-no-action-outcome.json',
  approvedPlan: 'infra-diff.json',
  githubApproval: 'github-environment-approval.json',
  approval: 'approval.json',
  activation: 'activation.json',
  drift: 'drift.json',
  rollback: 'rollback.json',
  rollbackSourceBinding: 'stage7-rollback-resilience-source-binding.json',
  rollbackProtectedRun: 'stage7-rollback-resilience-protected-run.json',
  rollbackCompletion: 'stage7-rollback-resilience-complete.json',
  releaseManifest: 'release-manifest.json',
  provenanceLedger: 'provenance-ledger.json',
  closeout: 'closeout.json',
  releaseHandoff: 'handoff-payload.json',
  releaseFence: 'release-successor-completion-fence.json',
  reconciliationRollbackCheck: STAGE7_RELEASE_RECONCILIATION_FILES[0],
  reconciliationRollbackResilience: STAGE7_RELEASE_RECONCILIATION_FILES[1],
  preFenceGate: STAGE7_RELEASE_RECONCILIATION_FILES[2],
  awsAuth: 'aws-auth.json',
  journalRoleEffectivePermissions: RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  reconciliationRecoveryRoleEffectivePermissions:
    RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  publicationPreparation: 'publication.json',
  publicationPlan: 'publication-plan.json',
  publicationTargetProof: 'publication-target-proof.json',
  publicationOperation: 'publication-operation.json',
  publicationProof: 'publication-proof.json',
  apiDeployment: 'api.json',
  pendingProducer: 'rollback-pending-producer.json',
  postdeploySmoke: 'smoke.json',
  repromotionSmoke: 'versioned-repromotion-smoke.json',
});

const catalogArtifactEntrySets = Object.fromEntries(
  STAGE7_FULL_SOURCE_ARTIFACT_NAMES.map((artifactName) => [
    artifactName,
    Object.entries(STAGE7_SOURCE_PRODUCERS.full)
      .filter(([, producer]) => producer.artifactName === artifactName)
      .map(([basename]) => basename)
      .toSorted(),
  ]),
);
const EXACT_ARTIFACT_ENTRY_SETS = Object.freeze({
  ...catalogArtifactEntrySets,
  'stage7-aws-auth': [
    'aws-auth.json',
    RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
    RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  ],
  'stage7-previous-release': PREVIOUS_RELEASE_PROJECTION_FILE_SET,
  'stage7-publication': [
    'publication-plan.json',
    'publication.json',
    'publication-operation.json',
    'publication-proof.json',
    'publication-target-proof.json',
  ],
  'stage7-release-reports': [
    'closeout.json',
    'etapa-7-release-despliegue.md',
    'provenance-ledger.json',
    'release-manifest.json',
  ],
  'stage7-release-successor-fence': ['release-successor-completion-fence.json'],
  [STAGE7_RELEASE_RECONCILIATION_ARTIFACT]: [...STAGE7_RELEASE_RECONCILIATION_FILES],
  'stage7-rollback-resilience': [
    'stage7-rollback-resilience-complete.json',
    'stage7-rollback-resilience-protected-run.json',
    'stage7-rollback-resilience-source-binding.json',
  ],
});

export class Stage7ReleaseSuccessorHandoffError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseSuccessorHandoffError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseSuccessorHandoffError(code, cause === undefined ? undefined : { cause });
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
const jsonBytes = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
const normalizedRunAttempt = (value) =>
  Number.isSafeInteger(value) && value >= 1 && value <= 100 ? value : null;

const strictJsonDocument = (source, code, { requirePublic = true, allowArray = false } = {}) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_SOURCE_BYTES) fail(code);
  let value;
  try {
    value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
  } catch (error) {
    fail(code, error);
  }
  if (
    (!object(value) && !(allowArray && Array.isArray(value))) ||
    (requirePublic && value.containsSensitiveData !== false)
  ) {
    fail(code);
  }
  return Object.freeze({
    value,
    bytes,
    rawSha256: sha256(bytes),
    canonicalSha256: objectSha256(value),
    byteLength: bytes.length,
  });
};

const textDocument = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 1 || bytes.length > MAX_SOURCE_BYTES || bytes.includes(0)) fail(code);
  const text = bytes.toString('utf8');
  if (Buffer.from(text, 'utf8').compare(bytes) !== 0 || /\r/u.test(text)) fail(code);
  return Object.freeze({ bytes, rawSha256: sha256(bytes), byteLength: bytes.length });
};

const rawEntry = (pathName, source) => ({
  path: pathName,
  sha256: sha256(source),
  bytes: source.length,
});

const jsonBinding = (pathName, document, artifactName = undefined) => ({
  path: pathName,
  ...(artifactName === undefined ? {} : { artifactName }),
  rawSha256: document.rawSha256,
  canonicalSha256: document.canonicalSha256,
  bytes: document.byteLength,
});

const reconciliationEvidenceBinding = (pathName, document, digestName, digest) => ({
  path: pathName,
  artifactName: STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
  rawSha256: document.rawSha256,
  canonicalSha256: document.canonicalSha256,
  bytes: document.byteLength,
  [digestName]: digest,
});

export const validateReleaseSuccessorReconciliationAuthoritySources = ({
  rollbackCheckSource,
  rollbackResilienceSource,
  preFenceGateSource,
  expected = {},
}) => {
  const rollbackCheck = strictJsonDocument(
    rollbackCheckSource,
    'E7_RELEASE_SUCCESSOR_RECONCILIATION_ROLLBACK_CHECK_SOURCE_INVALID',
  );
  const rollbackResilience = strictJsonDocument(
    rollbackResilienceSource,
    'E7_RELEASE_SUCCESSOR_RECONCILIATION_ROLLBACK_RESILIENCE_SOURCE_INVALID',
  );
  const preFenceGate = strictJsonDocument(
    preFenceGateSource,
    'E7_RELEASE_SUCCESSOR_PRE_FENCE_GATE_SOURCE_INVALID',
  );
  let gate;
  let authority;
  try {
    gate = validateReleasePreFenceGate(preFenceGate.value, {
      rollbackCheckSource: rollbackCheck.bytes,
      rollbackResilienceSource: rollbackResilience.bytes,
    });
    authority = validateReleaseReconciliationJournalAuthority(gate.reconciliationJournalAuthority, {
      rollbackCheckReceipt: rollbackCheck.value,
      rollbackResilienceReceipt: rollbackResilience.value,
    });
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_INVALID', error);
  }
  const bindings = {
    rollbackCheck: reconciliationEvidenceBinding(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackCheck,
      rollbackCheck,
      'receiptSha256',
      rollbackCheck.value.receiptSha256,
    ),
    rollbackResilience: reconciliationEvidenceBinding(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackResilience,
      rollbackResilience,
      'receiptSha256',
      rollbackResilience.value.receiptSha256,
    ),
    preFenceGate: reconciliationEvidenceBinding(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.preFenceGate,
      preFenceGate,
      'gateSha256',
      gate.gateSha256,
    ),
  };
  if (
    (expected.sourceRunId !== undefined && authority.source.runId !== expected.sourceRunId) ||
    (expected.sourceRunAttempt !== undefined &&
      authority.source.runAttempt !== expected.sourceRunAttempt) ||
    (expected.candidateSha !== undefined &&
      authority.source.candidateSha !== expected.candidateSha) ||
    (expected.releaseId !== undefined && authority.source.releaseId !== expected.releaseId) ||
    (expected.releaseTag !== undefined && authority.source.releaseTag !== expected.releaseTag)
  ) {
    fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_IDENTITY_INVALID');
  }
  return { rollbackCheck, rollbackResilience, preFenceGate, gate, authority, bindings };
};

const validateRawEntry = (entry) =>
  exactKeys(entry, ['path', 'sha256', 'bytes']) &&
  typeof entry.path === 'string' &&
  entry.path.length > 0 &&
  !entry.path.includes('\\') &&
  !path.posix.isAbsolute(entry.path) &&
  !entry.path.split('/').includes('..') &&
  SHA256.test(entry.sha256 ?? '') &&
  Number.isSafeInteger(entry.bytes) &&
  entry.bytes > 0;

const validateObservedArchiveEntry = (entry) =>
  exactKeys(entry, ['path', 'sha256', 'bytes', 'canonicalSha256']) &&
  validateRawEntry({ path: entry.path, sha256: entry.sha256, bytes: entry.bytes }) &&
  (entry.path.endsWith('.json')
    ? SHA256.test(entry.canonicalSha256 ?? '')
    : entry.canonicalSha256 === null);

const artifactObservationBody = (value) => withoutDigest(value, 'observationSha256');

const compositeArtifactEntries = (entries, code) =>
  [...entries.entries()]
    .map(([pathName, content]) => ({
      ...rawEntry(pathName, content),
      canonicalSha256: pathName.endsWith('.json')
        ? strictJsonDocument(content, code, { requirePublic: false }).canonicalSha256
        : null,
    }))
    .toSorted((left, right) => left.path.localeCompare(right.path));

const normalizeExactArtifactResponse = (value, code) => {
  const pages = Array.isArray(value) ? value : [value];
  if (pages.length !== 1 || !object(pages[0]) || !Array.isArray(pages[0].artifacts)) fail(code);
  const [{ artifacts, total_count: totalCount }] = pages;
  if (!Number.isSafeInteger(totalCount) || totalCount !== artifacts.length) fail(code);
  return artifacts;
};

const compositeLocalArtifact = ({ name, files, workflowRunId }) => {
  const expected = EXACT_ARTIFACT_ENTRY_SETS[name];
  if (
    !object(files) ||
    expected === undefined ||
    Object.keys(files).toSorted().join('\0') !== [...expected].toSorted().join('\0') ||
    Object.values(files).some((bytes) => !Buffer.isBuffer(bytes) || bytes.length < 1)
  ) {
    fail('E7_RELEASE_SUCCESSOR_COMPOSITE_LOCAL_ARTIFACT_INVALID');
  }
  const entries = Object.entries(files)
    .map(([pathName, content]) => ({
      ...rawEntry(pathName, content),
      canonicalSha256: pathName.endsWith('.json')
        ? strictJsonDocument(content, 'E7_RELEASE_SUCCESSOR_COMPOSITE_LOCAL_JSON_INVALID', {
            requirePublic: false,
          }).canonicalSha256
        : null,
    }))
    .toSorted((left, right) => left.path.localeCompare(right.path));
  return {
    name,
    origin: 'POST_SUCCESS_COMPOSITE_RECOVERY_CLOSEOUT',
    artifactId: null,
    artifactDigest: null,
    containerRawSha256: null,
    containerBytes: entries.reduce((sum, entry) => sum + entry.bytes, 0),
    entries,
    workflowRunId,
  };
};

const validateCompositeObservedArtifact = (artifact, observation) => {
  if (
    !exactKeys(artifact, [
      'name',
      'origin',
      'artifactId',
      'artifactDigest',
      'containerRawSha256',
      'containerBytes',
      'entries',
      'workflowRunId',
    ]) ||
    !RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.includes(artifact.name) ||
    ![
      'SOURCE_RUN_ARTIFACT',
      'RECOVERY_RESULT_SUPPLEMENT',
      'POST_SUCCESS_COMPOSITE_RECOVERY_CLOSEOUT',
    ].includes(artifact.origin) ||
    !Number.isSafeInteger(artifact.containerBytes) ||
    artifact.containerBytes < 1 ||
    !Array.isArray(artifact.entries) ||
    artifact.entries.length < 1 ||
    artifact.entries.some((entry) => !validateObservedArchiveEntry(entry)) ||
    artifact.entries.map(({ path: pathName }) => pathName).join('\0') !==
      artifact.entries
        .map(({ path: pathName }) => pathName)
        .toSorted()
        .join('\0') ||
    new Set(artifact.entries.map(({ path: pathName }) => pathName)).size !== artifact.entries.length
  ) {
    return false;
  }
  const expectedEntries = EXACT_ARTIFACT_ENTRY_SETS[artifact.name];
  if (
    expectedEntries !== undefined &&
    artifact.entries.map(({ path: pathName }) => pathName).join('\0') !==
      [...expectedEntries].toSorted().join('\0')
  ) {
    return false;
  }
  if (artifact.origin === 'POST_SUCCESS_COMPOSITE_RECOVERY_CLOSEOUT') {
    return (
      ['stage7-release-authorities', 'stage7-release-reports'].includes(artifact.name) &&
      artifact.artifactId === null &&
      artifact.artifactDigest === null &&
      artifact.containerRawSha256 === null &&
      artifact.workflowRunId === observation.postSuccess.runId
    );
  }
  if (
    !RUN_ID.test(artifact.artifactId ?? '') ||
    !ARTIFACT_DIGEST.test(artifact.artifactDigest ?? '') ||
    artifact.containerRawSha256 !== artifact.artifactDigest.slice('sha256:'.length)
  ) {
    return false;
  }
  return artifact.origin === 'SOURCE_RUN_ARTIFACT'
    ? RECOVERY_SOURCE_ARTIFACTS.includes(artifact.name) &&
        artifact.workflowRunId === observation.runId
    : ['stage7-publication', 'stage7-release-successor-fence'].includes(artifact.name) &&
        artifact.artifactId === observation.recovery.resultArtifactId &&
        artifact.artifactDigest === observation.recovery.resultArtifactDigest &&
        artifact.workflowRunId === observation.recovery.runId;
};

export const validateReleaseSuccessorCompositeRecoveryObservation = (value, expected = {}) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'repository',
      'workflowName',
      'workflowPath',
      'event',
      'ref',
      'headSha',
      'runId',
      'runAttempt',
      'runStatus',
      'conclusion',
      'recovery',
      'postSuccess',
      'bindings',
      'recoveryIntake',
      'recoveryPlan',
      'recoveryReceipt',
      'closeoutAuthority',
      'artifacts',
      'observedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'observationSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_COMPOSITE_RECOVERY_RUN_OBSERVATION' ||
    value.status !== 'PASS' ||
    value.repository !== REPOSITORY ||
    value.workflowName !== RELEASE_SUCCESSOR_WORKFLOW_NAME ||
    value.workflowPath !== RELEASE_SUCCESSOR_WORKFLOW_PATH ||
    value.event !== 'workflow_dispatch' ||
    value.ref !== MASTER_REF ||
    !SHA.test(value.headSha ?? '') ||
    !RUN_ID.test(value.runId ?? '') ||
    value.runAttempt !== 1 ||
    value.runStatus !== 'completed' ||
    !['failure', 'cancelled', 'timed_out'].includes(value.conclusion) ||
    !exactKeys(value.recovery, [
      'workflowName',
      'workflowPath',
      'runId',
      'runAttempt',
      'conclusion',
      'headSha',
      'planArtifactId',
      'planArtifactName',
      'planArtifactDigest',
      'planArchiveRawSha256',
      'resultArtifactId',
      'resultArtifactName',
      'resultArtifactDigest',
      'resultArchiveRawSha256',
      'crashWindow',
      'executionMode',
      'githubPublicationPolicy',
      'recoveryGithubWritesPerformed',
      'fenceEvidenceOrigin',
      'publicationEvidenceOrigin',
      'canonicalSupplementPolicy',
    ]) ||
    value.recovery.runId === value.runId ||
    value.recovery.runAttempt !== 1 ||
    value.recovery.conclusion !== 'success' ||
    !SHA.test(value.recovery.headSha ?? '') ||
    !RUN_ID.test(value.recovery.runId ?? '') ||
    !RUN_ID.test(value.recovery.planArtifactId ?? '') ||
    !ARTIFACT_DIGEST.test(value.recovery.planArtifactDigest ?? '') ||
    !SHA256.test(value.recovery.planArchiveRawSha256 ?? '') ||
    !RUN_ID.test(value.recovery.resultArtifactId ?? '') ||
    !ARTIFACT_DIGEST.test(value.recovery.resultArtifactDigest ?? '') ||
    !SHA256.test(value.recovery.resultArchiveRawSha256 ?? '') ||
    !RECOVERY_CRASH_WINDOWS.includes(value.recovery.crashWindow) ||
    !['FORWARD_ONLY_IDEMPOTENT', 'VERIFY_EXACT_NOOP'].includes(value.recovery.executionMode) ||
    !['VERIFY_EXACT_OR_CREATE_MISSING', 'VERIFY_EXACT_NO_MUTATION'].includes(
      value.recovery.githubPublicationPolicy,
    ) ||
    !Number.isSafeInteger(value.recovery.recoveryGithubWritesPerformed) ||
    value.recovery.recoveryGithubWritesPerformed < 0 ||
    !['SSM_REHYDRATED', 'SOURCE_ARTIFACT_BYTE_EQUAL_SSM'].includes(
      value.recovery.fenceEvidenceOrigin,
    ) ||
    !['RECOVERY_VERIFIED_OUTPUT', 'SOURCE_ARTIFACT_LIVE_VERIFIED'].includes(
      value.recovery.publicationEvidenceOrigin,
    ) ||
    value.recovery.canonicalSupplementPolicy !== 'COPY_EXACT_WITHOUT_SOURCE_DUPLICATION' ||
    !exactKeys(value.postSuccess, [
      'runId',
      'runAttempt',
      'workflowName',
      'workflowPath',
      'protectedEnvironment',
      'reviewerAlias',
    ]) ||
    !RUN_ID.test(value.postSuccess.runId ?? '') ||
    normalizedRunAttempt(value.postSuccess.runAttempt) === null ||
    value.postSuccess.runId === value.runId ||
    value.postSuccess.runId === value.recovery.runId ||
    value.postSuccess.workflowName !== 'Stage 7 Release Successor Post-Success' ||
    value.postSuccess.workflowPath !== RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH ||
    value.postSuccess.protectedEnvironment !== 'assessment-release-successor-post-success' ||
    !/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u.test(value.postSuccess.reviewerAlias ?? '') ||
    !exactKeys(value.bindings, [
      'intakeSha256',
      'closeoutAuthoritySha256',
      'planSha256',
      'receiptSha256',
      'fenceSha256',
      'publicationAuthoritySha256',
      'idempotencyKey',
      'planArtifactDigestSha256',
      'resultArtifactDigestSha256',
      'sourceArtifactManifestSha256',
      'publicationFilesSha256',
      'sourceInventoryMetadataSha256',
      'sourceInventorySha256',
    ]) ||
    Object.values(value.bindings).some((digest) => !SHA256.test(digest ?? '')) ||
    !Array.isArray(value.artifacts) ||
    value.artifacts.length !== RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.length ||
    value.artifacts.map(({ name } = {}) => name).join('\0') !==
      RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.join('\0') ||
    value.artifacts.some((artifact) => !validateCompositeObservedArtifact(artifact, value)) ||
    !utc(value.observedAtUtc) ||
    value.externalRequests !== 38 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.observationSha256 !== objectSha256(artifactObservationBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_COMPOSITE_OBSERVATION_INVALID');
  }
  const intake = validatePublicationRecoveryPostSuccessIntake(value.recoveryIntake);
  const plan = validatePublicationRecoveryPlan(value.recoveryPlan);
  const receipt = validatePublicationRecoveryReceipt(value.recoveryReceipt);
  const authority = validateReleaseSuccessorRecoveryCloseoutAuthority(value.closeoutAuthority, {
    intake,
  });
  const plannedSourceArtifacts = new Map(
    plan.artifactInventory.downloadManifest.map((artifact) => [artifact.name, artifact]),
  );
  const observedSourceArtifacts = value.artifacts.filter(
    ({ origin }) => origin === 'SOURCE_RUN_ARTIFACT',
  );
  const observedPublication = value.artifacts.find(({ name }) => name === 'stage7-publication');
  const observedFence = value.artifacts.find(
    ({ name }) => name === 'stage7-release-successor-fence',
  );
  const observedPublicationBindings = observedPublication?.entries.map(
    ({ path: name, bytes, sha256: rawSha256, canonicalSha256 }) => ({
      name,
      bytes,
      rawSha256,
      canonicalSha256,
    }),
  );
  const receiptFenceBinding = receipt.artifactExpectations.preMutationFiles.find(
    ({ name }) => name === 'release-successor-completion-fence.json',
  );
  const expectedFenceBinding =
    receiptFenceBinding === undefined
      ? []
      : [
          {
            path: receiptFenceBinding.name,
            sha256: receiptFenceBinding.rawSha256,
            canonicalSha256: receiptFenceBinding.canonicalSha256,
          },
        ];
  const observedFenceBinding = observedFence?.entries.map(
    ({ path: pathName, sha256, canonicalSha256 }) => ({
      path: pathName,
      sha256,
      canonicalSha256,
    }),
  );
  if (
    intake.source.runId !== value.runId ||
    intake.source.conclusion !== value.conclusion ||
    intake.source.candidateSha !== value.headSha ||
    intake.source.crashWindow !== value.recovery.crashWindow ||
    intake.recovery.runId !== value.recovery.runId ||
    plan.source.runId !== value.runId ||
    plan.source.conclusion !== value.conclusion ||
    plan.owner.recoveryRunId !== value.recovery.runId ||
    receipt.sourceRunId !== value.runId ||
    receipt.recoveryRunId !== value.recovery.runId ||
    value.bindings.intakeSha256 !== intake.intakeSha256 ||
    value.bindings.planSha256 !== plan.planSha256 ||
    value.bindings.receiptSha256 !== receipt.receiptSha256 ||
    value.bindings.fenceSha256 !== receipt.fenceSha256 ||
    value.bindings.publicationAuthoritySha256 !== receipt.authoritySha256 ||
    value.bindings.idempotencyKey !== receipt.idempotencyKey ||
    value.bindings.closeoutAuthoritySha256 !== authority.closeoutAuthoritySha256 ||
    value.bindings.planArtifactDigestSha256 !== authority.bindings.planArtifactDigestSha256 ||
    value.bindings.resultArtifactDigestSha256 !== authority.bindings.resultArtifactDigestSha256 ||
    value.bindings.sourceInventoryMetadataSha256 !==
      authority.bindings.sourceInventoryMetadataSha256 ||
    value.bindings.sourceInventorySha256 !== authority.bindings.sourceInventorySha256 ||
    value.bindings.sourceArtifactManifestSha256 !==
      authority.bindings.sourceArtifactManifestSha256 ||
    value.bindings.publicationFilesSha256 !== authority.bindings.publicationFilesSha256 ||
    value.recovery.workflowName !== authority.recovery.workflowName ||
    value.recovery.workflowPath !== authority.recovery.workflowPath ||
    value.recovery.runId !== authority.recovery.runId ||
    value.recovery.runAttempt !== authority.recovery.runAttempt ||
    value.recovery.conclusion !== authority.recovery.conclusion ||
    value.recovery.headSha !== authority.recovery.headSha ||
    value.recovery.planArtifactId !== authority.recovery.planArtifactId ||
    value.recovery.planArtifactName !== authority.recovery.planArtifactName ||
    value.recovery.planArtifactDigest !== authority.recovery.planArtifactDigest ||
    value.recovery.planArchiveRawSha256 !== authority.recovery.planArchiveRawSha256 ||
    value.recovery.resultArtifactId !== authority.recovery.resultArtifactId ||
    value.recovery.resultArtifactName !== authority.recovery.resultArtifactName ||
    value.recovery.resultArtifactDigest !== authority.recovery.resultArtifactDigest ||
    value.recovery.resultArchiveRawSha256 !== authority.recovery.resultArchiveRawSha256 ||
    value.recovery.crashWindow !== authority.source.crashWindow ||
    value.recovery.executionMode !== authority.recovery.executionMode ||
    value.recovery.githubPublicationPolicy !== authority.recovery.githubPublicationPolicy ||
    value.recovery.recoveryGithubWritesPerformed !==
      authority.recovery.recoveryGithubWritesPerformed ||
    value.recovery.fenceEvidenceOrigin !== authority.recovery.fenceEvidenceOrigin ||
    value.recovery.publicationEvidenceOrigin !== authority.recovery.publicationEvidenceOrigin ||
    value.recovery.canonicalSupplementPolicy !== authority.recovery.canonicalSupplementPolicy ||
    value.postSuccess.runId !== authority.postSuccess.runId ||
    value.postSuccess.runAttempt !== authority.postSuccess.runAttempt ||
    value.postSuccess.workflowName !== authority.postSuccess.workflowName ||
    value.postSuccess.workflowPath !== authority.postSuccess.workflowPath ||
    value.postSuccess.protectedEnvironment !== authority.protectedEnvironment ||
    value.postSuccess.reviewerAlias !== authority.postSuccess.reviewerAlias ||
    observedSourceArtifacts.some((artifact) => {
      const planned = plannedSourceArtifacts.get(artifact.name);
      return (
        planned === undefined ||
        artifact.artifactId !== planned.artifactId ||
        artifact.artifactDigest !== planned.digest ||
        artifact.workflowRunId !== plan.source.runId
      );
    }) ||
    canonicalJson(observedPublicationBindings) !== canonicalJson(receipt.publicationFiles) ||
    canonicalJson(observedFenceBinding) !== canonicalJson(expectedFenceBinding) ||
    value.artifacts
      .filter(({ origin }) => origin === 'SOURCE_RUN_ARTIFACT')
      .map(({ name }) => name)
      .join('\0') !== RECOVERY_SOURCE_ARTIFACTS.join('\0') ||
    value.artifacts
      .filter(({ origin }) => origin === 'RECOVERY_RESULT_SUPPLEMENT')
      .map(({ name }) => name)
      .join('\0') !== ['stage7-publication', 'stage7-release-successor-fence'].join('\0') ||
    value.artifacts
      .filter(({ origin }) => origin === 'POST_SUCCESS_COMPOSITE_RECOVERY_CLOSEOUT')
      .map(({ name }) => name)
      .join('\0') !== ['stage7-release-authorities', 'stage7-release-reports'].join('\0') ||
    (expected.runId !== undefined && value.runId !== String(expected.runId)) ||
    (expected.runAttempt !== undefined && value.runAttempt !== Number(expected.runAttempt)) ||
    (expected.headSha !== undefined && value.headSha !== expected.headSha)
  ) {
    fail('E7_RELEASE_SUCCESSOR_COMPOSITE_OBSERVATION_MISMATCH');
  }
  return value;
};

export const createReleaseSuccessorCompositeRecoveryObservation = ({
  intake: input,
  closeoutAuthority: inputAuthority,
  sourceArtifactsResponseSource,
  sourceArtifactArchives,
  planArchive,
  resultArchive,
  localArtifacts,
  observedAtUtc,
}) => {
  const intake = validatePublicationRecoveryPostSuccessIntake(input);
  const authority = validateReleaseSuccessorRecoveryCloseoutAuthority(inputAuthority, { intake });
  const result = readReleaseSuccessorRecoveryResultFromIntake({
    intake,
    planArchive,
    resultArchive,
  });
  const artifactsDocument = strictJsonDocument(
    sourceArtifactsResponseSource,
    'E7_RELEASE_SUCCESSOR_COMPOSITE_ARTIFACTS_RESPONSE_INVALID',
    { requirePublic: false, allowArray: true },
  );
  const apiArtifacts = normalizeExactArtifactResponse(
    artifactsDocument.value,
    'E7_RELEASE_SUCCESSOR_COMPOSITE_ARTIFACTS_RESPONSE_INVALID',
  );
  if (
    observedAtUtc !== authority.authorizedAtUtc ||
    !Array.isArray(apiArtifacts) ||
    !exactKeys(sourceArtifactArchives, RECOVERY_SOURCE_ARTIFACTS) ||
    !exactKeys(localArtifacts, ['stage7-release-authorities', 'stage7-release-reports'])
  ) {
    fail('E7_RELEASE_SUCCESSOR_COMPOSITE_OPTIONS_INVALID');
  }
  const planByName = new Map(
    result.plan.artifactInventory.downloadManifest.map((artifact) => [artifact.name, artifact]),
  );
  const selected = [];
  for (const name of RECOVERY_SOURCE_ARTIFACTS) {
    const matches = apiArtifacts.filter((artifact) => artifact?.name === name);
    const artifact = matches[0];
    const planned = planByName.get(name);
    const archive = sourceArtifactArchives[name];
    const bytes = Buffer.isBuffer(archive) ? Buffer.from(archive) : Buffer.from(archive ?? '');
    let entries;
    try {
      entries = readReleaseSuccessorZipEntries(bytes);
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_COMPOSITE_SOURCE_ZIP_INVALID', error);
    }
    if (
      matches.length !== 1 ||
      !Number.isSafeInteger(artifact?.id) ||
      artifact.id < 1 ||
      String(artifact.id) !== planned?.artifactId ||
      artifact.expired !== false ||
      String(artifact.workflow_run?.id) !== intake.source.runId ||
      artifact.digest !== planned?.digest ||
      artifact.digest !== `sha256:${sha256(bytes)}`
    ) {
      fail('E7_RELEASE_SUCCESSOR_COMPOSITE_SOURCE_ARTIFACT_INVALID');
    }
    selected.push({
      name,
      origin: 'SOURCE_RUN_ARTIFACT',
      artifactId: String(artifact.id),
      artifactDigest: artifact.digest,
      containerRawSha256: sha256(bytes),
      containerBytes: bytes.length,
      entries: compositeArtifactEntries(
        entries,
        'E7_RELEASE_SUCCESSOR_COMPOSITE_SOURCE_JSON_INVALID',
      ),
      workflowRunId: intake.source.runId,
    });
  }
  const resultBytes = Buffer.isBuffer(resultArchive)
    ? Buffer.from(resultArchive)
    : Buffer.from(resultArchive ?? '');
  const resultEntries = readReleaseSuccessorZipEntries(resultBytes);
  const resultByBasename = new Map();
  for (const [entryPath, bytes] of resultEntries) {
    const basename = path.posix.basename(entryPath);
    if (!resultByBasename.has(basename)) resultByBasename.set(basename, []);
    resultByBasename.get(basename).push(bytes);
  }
  const supplement = [
    {
      name: 'stage7-publication',
      basenames: result.receipt.publicationFiles.map(({ name }) => name),
    },
    {
      name: 'stage7-release-successor-fence',
      basenames: ['release-successor-completion-fence.json'],
    },
  ];
  for (const { name, basenames } of supplement) {
    if (basenames.some((basename) => resultByBasename.get(basename)?.length !== 1)) {
      fail('E7_RELEASE_SUCCESSOR_COMPOSITE_SUPPLEMENT_INVALID');
    }
    const entries = new Map(
      basenames.map((basename) => [basename, resultByBasename.get(basename)[0]]),
    );
    selected.push({
      name,
      origin: 'RECOVERY_RESULT_SUPPLEMENT',
      artifactId: intake.recovery.resultArtifactId,
      artifactDigest: intake.recovery.resultArtifactDigest,
      containerRawSha256: sha256(resultBytes),
      containerBytes: resultBytes.length,
      entries: compositeArtifactEntries(
        entries,
        'E7_RELEASE_SUCCESSOR_COMPOSITE_SUPPLEMENT_JSON_INVALID',
      ),
      workflowRunId: intake.recovery.runId,
    });
  }
  selected.push(
    compositeLocalArtifact({
      name: 'stage7-release-authorities',
      files: localArtifacts['stage7-release-authorities'],
      workflowRunId: authority.postSuccess.runId,
    }),
    compositeLocalArtifact({
      name: 'stage7-release-reports',
      files: localArtifacts['stage7-release-reports'],
      workflowRunId: authority.postSuccess.runId,
    }),
  );
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_COMPOSITE_RECOVERY_RUN_OBSERVATION',
    status: 'PASS',
    repository: REPOSITORY,
    workflowName: RELEASE_SUCCESSOR_WORKFLOW_NAME,
    workflowPath: RELEASE_SUCCESSOR_WORKFLOW_PATH,
    event: 'workflow_dispatch',
    ref: MASTER_REF,
    headSha: intake.source.candidateSha,
    runId: intake.source.runId,
    runAttempt: intake.source.runAttempt,
    runStatus: 'completed',
    conclusion: intake.source.conclusion,
    recovery: {
      workflowName: authority.recovery.workflowName,
      workflowPath: authority.recovery.workflowPath,
      runId: authority.recovery.runId,
      runAttempt: authority.recovery.runAttempt,
      conclusion: authority.recovery.conclusion,
      headSha: authority.recovery.headSha,
      planArtifactId: authority.recovery.planArtifactId,
      planArtifactName: authority.recovery.planArtifactName,
      planArtifactDigest: authority.recovery.planArtifactDigest,
      planArchiveRawSha256: authority.recovery.planArchiveRawSha256,
      resultArtifactId: authority.recovery.resultArtifactId,
      resultArtifactName: authority.recovery.resultArtifactName,
      resultArtifactDigest: authority.recovery.resultArtifactDigest,
      resultArchiveRawSha256: authority.recovery.resultArchiveRawSha256,
      crashWindow: authority.source.crashWindow,
      executionMode: authority.recovery.executionMode,
      githubPublicationPolicy: authority.recovery.githubPublicationPolicy,
      recoveryGithubWritesPerformed: authority.recovery.recoveryGithubWritesPerformed,
      fenceEvidenceOrigin: authority.recovery.fenceEvidenceOrigin,
      publicationEvidenceOrigin: authority.recovery.publicationEvidenceOrigin,
      canonicalSupplementPolicy: authority.recovery.canonicalSupplementPolicy,
    },
    postSuccess: {
      runId: authority.postSuccess.runId,
      runAttempt: authority.postSuccess.runAttempt,
      workflowName: authority.postSuccess.workflowName,
      workflowPath: authority.postSuccess.workflowPath,
      protectedEnvironment: authority.protectedEnvironment,
      reviewerAlias: authority.postSuccess.reviewerAlias,
    },
    bindings: {
      intakeSha256: intake.intakeSha256,
      closeoutAuthoritySha256: authority.closeoutAuthoritySha256,
      planSha256: authority.bindings.planSha256,
      receiptSha256: authority.bindings.receiptSha256,
      fenceSha256: authority.bindings.fenceSha256,
      publicationAuthoritySha256: authority.bindings.publicationAuthoritySha256,
      idempotencyKey: authority.bindings.idempotencyKey,
      planArtifactDigestSha256: authority.bindings.planArtifactDigestSha256,
      resultArtifactDigestSha256: authority.bindings.resultArtifactDigestSha256,
      sourceArtifactManifestSha256: authority.bindings.sourceArtifactManifestSha256,
      publicationFilesSha256: authority.bindings.publicationFilesSha256,
      sourceInventoryMetadataSha256: authority.bindings.sourceInventoryMetadataSha256,
      sourceInventorySha256: authority.bindings.sourceInventorySha256,
    },
    recoveryIntake: intake,
    recoveryPlan: result.plan,
    recoveryReceipt: result.receipt,
    closeoutAuthority: authority,
    artifacts: selected.toSorted((left, right) => left.name.localeCompare(right.name)),
    observedAtUtc,
    externalRequests: 38,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return validateReleaseSuccessorCompositeRecoveryObservation({
    ...body,
    observationSha256: objectSha256(body),
  });
};

export const validateReleaseSuccessorRunObservation = (value, expected = {}) => {
  if (value?.kind === 'RELEASE_SUCCESSOR_COMPOSITE_RECOVERY_RUN_OBSERVATION') {
    return validateReleaseSuccessorCompositeRecoveryObservation(value, expected);
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
      'runId',
      'runAttempt',
      'runStatus',
      'conclusion',
      'triggerRawSha256',
      'runResponseRawSha256',
      'runResponseCanonicalSha256',
      'workflowResponseRawSha256',
      'workflowResponseCanonicalSha256',
      'artifactsResponseRawSha256',
      'artifactsResponseCanonicalSha256',
      'artifacts',
      'observedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'observationSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_POST_SUCCESS_RUN_OBSERVATION' ||
    value.status !== 'PASS' ||
    value.repository !== REPOSITORY ||
    !Number.isSafeInteger(value.workflowId) ||
    value.workflowId < 1 ||
    value.workflowName !== RELEASE_SUCCESSOR_WORKFLOW_NAME ||
    value.workflowPath !== RELEASE_SUCCESSOR_WORKFLOW_PATH ||
    value.event !== 'workflow_dispatch' ||
    value.ref !== MASTER_REF ||
    !SHA.test(value.headSha ?? '') ||
    !RUN_ID.test(value.runId ?? '') ||
    value.runAttempt !== 1 ||
    value.runStatus !== 'completed' ||
    value.conclusion !== 'success' ||
    ![
      value.triggerRawSha256,
      value.runResponseRawSha256,
      value.runResponseCanonicalSha256,
      value.workflowResponseRawSha256,
      value.workflowResponseCanonicalSha256,
      value.artifactsResponseRawSha256,
      value.artifactsResponseCanonicalSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !Array.isArray(value.artifacts) ||
    value.artifacts.length !== RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.length ||
    value.artifacts.map(({ name } = {}) => name).join('\0') !==
      RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.join('\0') ||
    !utc(value.observedAtUtc) ||
    value.externalRequests !== 3 + RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.length ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.observationSha256 !== objectSha256(artifactObservationBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_RUN_OBSERVATION_INVALID');
  }
  for (const artifact of value.artifacts) {
    if (
      !exactKeys(artifact, [
        'id',
        'name',
        'digest',
        'archiveRawSha256',
        'archiveBytes',
        'entries',
        'expired',
        'workflowRunId',
      ]) ||
      !Number.isSafeInteger(artifact.id) ||
      artifact.id < 1 ||
      !RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.includes(artifact.name) ||
      !ARTIFACT_DIGEST.test(artifact.digest ?? '') ||
      artifact.archiveRawSha256 !== artifact.digest.slice('sha256:'.length) ||
      !Number.isSafeInteger(artifact.archiveBytes) ||
      artifact.archiveBytes < 1 ||
      !Array.isArray(artifact.entries) ||
      artifact.entries.length < 1 ||
      artifact.entries.some((entry) => !validateObservedArchiveEntry(entry)) ||
      artifact.entries.map(({ path: pathName }) => pathName).join('\0') !==
        artifact.entries
          .map(({ path: pathName }) => pathName)
          .toSorted()
          .join('\0') ||
      new Set(artifact.entries.map(({ path: pathName }) => pathName)).size !==
        artifact.entries.length ||
      artifact.expired !== false ||
      artifact.workflowRunId !== value.runId
    ) {
      fail('E7_RELEASE_SUCCESSOR_ARTIFACT_OBSERVATION_INVALID');
    }
    const exactEntries = EXACT_ARTIFACT_ENTRY_SETS[artifact.name];
    if (
      exactEntries !== undefined &&
      artifact.entries.map(({ path: pathName }) => pathName).join('\0') !==
        [...exactEntries].toSorted().join('\0')
    ) {
      fail('E7_RELEASE_SUCCESSOR_ARTIFACT_ENTRY_SET_INVALID');
    }
  }
  if (
    (expected.runId !== undefined && value.runId !== String(expected.runId)) ||
    (expected.runAttempt !== undefined && value.runAttempt !== Number(expected.runAttempt)) ||
    (expected.headSha !== undefined && value.headSha !== expected.headSha)
  ) {
    fail('E7_RELEASE_SUCCESSOR_RUN_OBSERVATION_MISMATCH');
  }
  return value;
};

export const createReleaseSuccessorRunObservation = ({
  triggerSource,
  runResponseSource,
  workflowResponseSource,
  artifactsResponseSource,
  artifactArchives,
  observedAtUtc,
}) => {
  const trigger = strictJsonDocument(triggerSource, 'E7_RELEASE_SUCCESSOR_TRIGGER_INVALID', {
    requirePublic: false,
  });
  const run = strictJsonDocument(runResponseSource, 'E7_RELEASE_SUCCESSOR_RUN_RESPONSE_INVALID', {
    requirePublic: false,
  });
  const workflow = strictJsonDocument(
    workflowResponseSource,
    'E7_RELEASE_SUCCESSOR_WORKFLOW_RESPONSE_INVALID',
    { requirePublic: false },
  );
  const artifacts = strictJsonDocument(
    artifactsResponseSource,
    'E7_RELEASE_SUCCESSOR_ARTIFACTS_RESPONSE_INVALID',
    { requirePublic: false, allowArray: true },
  );
  const eventRun = trigger.value.workflow_run;
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
    trigger.value.action !== 'completed' ||
    trigger.value.repository?.full_name !== REPOSITORY ||
    eventRun?.id !== apiRun.id ||
    eventRun?.run_attempt !== apiRun.run_attempt ||
    eventRun?.head_sha !== apiRun.head_sha ||
    eventRun?.head_branch !== 'master' ||
    eventRun?.status !== 'completed' ||
    eventRun?.conclusion !== 'success' ||
    eventRun?.event !== 'workflow_dispatch' ||
    eventRun?.name !== RELEASE_SUCCESSOR_WORKFLOW_NAME ||
    apiRun?.repository?.full_name !== REPOSITORY ||
    apiRun?.workflow_id !== apiWorkflow.id ||
    apiRun?.name !== RELEASE_SUCCESSOR_WORKFLOW_NAME ||
    apiWorkflow?.name !== RELEASE_SUCCESSOR_WORKFLOW_NAME ||
    apiWorkflow?.path !== RELEASE_SUCCESSOR_WORKFLOW_PATH ||
    apiRun?.head_branch !== 'master' ||
    !SHA.test(apiRun?.head_sha ?? '') ||
    apiRun?.event !== 'workflow_dispatch' ||
    apiRun?.status !== 'completed' ||
    apiRun?.conclusion !== 'success' ||
    !Number.isSafeInteger(apiRun?.id) ||
    apiRun?.run_attempt !== 1 ||
    apiUpdatedAtUtc === null ||
    requestedObservedAtUtc !== apiUpdatedAtUtc
  ) {
    fail('E7_RELEASE_SUCCESSOR_RUN_NOT_EXACT_SUCCESS');
  }
  const apiArtifacts = normalizeExactArtifactResponse(
    artifacts.value,
    'E7_RELEASE_SUCCESSOR_ARTIFACT_ARCHIVES_INVALID',
  );
  const expectedRunArtifactNames = [
    ...RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS,
    ...RELEASE_SUCCESSOR_INTERNAL_ARTIFACTS,
  ].toSorted();
  if (
    !object(artifactArchives) ||
    apiArtifacts.length !== expectedRunArtifactNames.length ||
    new Set(apiArtifacts.map(({ name } = {}) => name)).size !== apiArtifacts.length ||
    apiArtifacts
      .map(({ name } = {}) => name)
      .toSorted()
      .join('\0') !== expectedRunArtifactNames.join('\0')
  ) {
    fail('E7_RELEASE_SUCCESSOR_ARTIFACT_ARCHIVES_INVALID');
  }
  for (const name of RELEASE_SUCCESSOR_INTERNAL_ARTIFACTS) {
    const matches = apiArtifacts.filter((entry) => entry?.name === name);
    const internalArtifact = matches[0];
    if (
      matches.length !== 1 ||
      !Number.isSafeInteger(internalArtifact?.id) ||
      internalArtifact.id < 1 ||
      internalArtifact.expired !== false ||
      internalArtifact.workflow_run?.id !== apiRun.id ||
      !ARTIFACT_DIGEST.test(internalArtifact.digest ?? '')
    ) {
      fail('E7_RELEASE_SUCCESSOR_NON_SOURCE_ARTIFACT_INVALID');
    }
  }
  const selected = [];
  for (const name of RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS) {
    const matches = apiArtifacts.filter((entry) => entry?.name === name);
    if (matches.length !== 1) fail('E7_RELEASE_SUCCESSOR_ARTIFACT_SET_INVALID');
    const artifact = matches[0];
    const archive = artifactArchives[name];
    const bytes = Buffer.isBuffer(archive) ? archive : Buffer.from(archive ?? '');
    const archiveRawSha256 = sha256(bytes);
    let archiveEntries;
    try {
      archiveEntries = readReleaseSuccessorZipEntries(bytes);
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_ARTIFACT_ZIP_INVALID', error);
    }
    if (
      !Number.isSafeInteger(artifact.id) ||
      artifact.id < 1 ||
      artifact.expired !== false ||
      artifact.workflow_run?.id !== apiRun.id ||
      !ARTIFACT_DIGEST.test(artifact.digest ?? '') ||
      bytes.length < 1 ||
      artifact.digest !== `sha256:${archiveRawSha256}`
    ) {
      fail('E7_RELEASE_SUCCESSOR_ARTIFACT_DIGEST_INVALID');
    }
    selected.push({
      id: artifact.id,
      name,
      digest: artifact.digest,
      archiveRawSha256,
      archiveBytes: bytes.length,
      entries: [...archiveEntries.entries()]
        .map(([pathName, content]) => ({
          ...rawEntry(pathName, content),
          canonicalSha256: pathName.endsWith('.json')
            ? strictJsonDocument(content, 'E7_RELEASE_SUCCESSOR_ARTIFACT_JSON_ENTRY_INVALID', {
                requirePublic: false,
              }).canonicalSha256
            : null,
        }))
        .toSorted((left, right) => left.path.localeCompare(right.path)),
      expired: false,
      workflowRunId: String(apiRun.id),
    });
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_POST_SUCCESS_RUN_OBSERVATION',
    status: 'PASS',
    repository: REPOSITORY,
    workflowId: apiWorkflow.id,
    workflowName: apiWorkflow.name,
    workflowPath: apiWorkflow.path,
    event: apiRun.event,
    ref: MASTER_REF,
    headSha: apiRun.head_sha,
    runId: String(apiRun.id),
    runAttempt: apiRun.run_attempt,
    runStatus: apiRun.status,
    conclusion: apiRun.conclusion,
    triggerRawSha256: trigger.rawSha256,
    runResponseRawSha256: run.rawSha256,
    runResponseCanonicalSha256: run.canonicalSha256,
    workflowResponseRawSha256: workflow.rawSha256,
    workflowResponseCanonicalSha256: workflow.canonicalSha256,
    artifactsResponseRawSha256: artifacts.rawSha256,
    artifactsResponseCanonicalSha256: artifacts.canonicalSha256,
    artifacts: selected,
    observedAtUtc: apiUpdatedAtUtc,
    externalRequests: 3 + selected.length,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return validateReleaseSuccessorRunObservation({
    ...body,
    observationSha256: objectSha256(body),
  });
};

export const assertReleaseSuccessorObservedArtifactSource = ({
  observation,
  artifactName,
  basename,
  source,
}) => {
  validateReleaseSuccessorRunObservation(observation);
  const artifact = observation.artifacts.find(({ name }) => name === artifactName);
  const matches = artifact?.entries.filter(
    ({ path: pathName }) => path.posix.basename(pathName) === basename,
  );
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (
    matches?.length !== 1 ||
    matches[0].sha256 !== sha256(bytes) ||
    matches[0].bytes !== bytes.length
  ) {
    fail('E7_RELEASE_SUCCESSOR_ARTIFACT_SOURCE_BYTES_MISMATCH');
  }
  return matches[0];
};

export const extractReleaseSuccessorObservedArtifacts = ({
  observationSource,
  archiveDirectory,
  outputDirectory,
}) => {
  const observation = validateReleaseSuccessorRunObservation(
    strictJsonDocument(observationSource, 'E7_RELEASE_SUCCESSOR_EXTRACT_OBSERVATION_INVALID').value,
  );
  const expectedArchives = RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.map((name) => `${name}.zip`);
  const archiveEntries = readdirSync(archiveDirectory, { withFileTypes: true });
  if (
    archiveEntries.some((entry) => !entry.isFile()) ||
    archiveEntries
      .map(({ name }) => name)
      .toSorted()
      .join('\0') !== expectedArchives.toSorted().join('\0') ||
    existsSync(outputDirectory)
  ) {
    fail('E7_RELEASE_SUCCESSOR_EXTRACT_FILE_SET_INVALID');
  }
  mkdirSync(outputDirectory, { recursive: false, mode: 0o700 });
  try {
    for (const artifact of observation.artifacts) {
      const archive = readFileSync(path.join(archiveDirectory, `${artifact.name}.zip`));
      if (
        archive.length !== artifact.archiveBytes ||
        sha256(archive) !== artifact.archiveRawSha256
      ) {
        fail('E7_RELEASE_SUCCESSOR_EXTRACT_ARCHIVE_MISMATCH');
      }
      const entries = readReleaseSuccessorZipEntries(archive);
      const rawEntries = [...entries.entries()]
        .map(([pathName, bytes]) => ({
          ...rawEntry(pathName, bytes),
          canonicalSha256: pathName.endsWith('.json')
            ? strictJsonDocument(bytes, 'E7_RELEASE_SUCCESSOR_EXTRACT_JSON_ENTRY_INVALID', {
                requirePublic: false,
              }).canonicalSha256
            : null,
        }))
        .toSorted((left, right) => left.path.localeCompare(right.path));
      if (canonicalJson(rawEntries) !== canonicalJson(artifact.entries)) {
        fail('E7_RELEASE_SUCCESSOR_EXTRACT_ENTRY_MISMATCH');
      }
      const artifactDirectory = path.join(outputDirectory, artifact.name);
      mkdirSync(artifactDirectory, { recursive: false, mode: 0o700 });
      for (const [pathName, bytes] of entries) {
        const filename = path.join(artifactDirectory, ...pathName.split('/'));
        mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
        writeFileSync(filename, bytes, { flag: 'wx', mode: 0o600 });
      }
    }
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    throw error;
  }
  return observation;
};

const validateReleaseApproval = ({
  approval,
  githubApproval,
  approvedPlan,
  rawDiff,
  config,
  freeze,
  predecessor,
  candidateRecord,
  observation,
  capability,
}) => {
  const value = approval.value;
  const review = githubApproval.value;
  const planValue = approvedPlan.value;
  if (
    value.kind !== 'PROTECTED_RELEASE_APPROVAL' ||
    value.status !== 'PASS' ||
    value.scope !== 'full' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.releaseTag !== freeze.releaseTag ||
    value.configSha256 !== objectSha256(config) ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.previousReleaseManifestSha256 !== predecessor.manifestSha256 ||
    value.cloudAssemblySha256 !== freeze.artifacts.find(({ name }) => name === 'iac')?.sha256 ||
    value.approvedPlanSha256 !== approvedPlan.rawSha256 ||
    value.approvedDiffSha256 !== rawDiff.rawSha256 ||
    candidateRecord.approvalSha256 !== approval.rawSha256 ||
    candidateRecord.planSha256 !== approvedPlan.rawSha256 ||
    planValue.kind !== 'RELEASE_DIFF_REVIEW' ||
    planValue.status !== 'READY_FOR_PROTECTED_REVIEW' ||
    planValue.candidateSha !== freeze.candidateSha ||
    planValue.releaseId !== freeze.releaseId ||
    planValue.configSha256 !== objectSha256(config) ||
    planValue.previousReleaseManifestSha256 !== predecessor.manifestSha256 ||
    planValue.rawDiffArtifactSha256 !== rawDiff.rawSha256 ||
    value.statefulReplacements !== 0 ||
    value.destructiveChanges !== 0 ||
    value.iamBroadeningReviewed !== true ||
    value.humanReviewConfirmed !== true ||
    value.explicitDispatchConfirmation !== true ||
    value.protectedEnvironment !== true ||
    value.protectedEnvironmentName !== 'assessment-release' ||
    value.nonPublic !== false ||
    value.reviewerAlias !== review.reviewerAlias ||
    value.approvedAtUtc !== review.capturedAtUtc ||
    !utc(value.approvedAtUtc) ||
    Date.parse(value.approvedAtUtc) > Date.parse(observation.observedAtUtc) ||
    value.externalRequests !== 0 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    review.candidateSha !== freeze.candidateSha ||
    review.releaseId !== freeze.releaseId ||
    String(review.runId) !== observation.runId ||
    Number(review.runAttempt) !== observation.runAttempt ||
    review.environment !== 'assessment-release' ||
    review.reviewed !== true ||
    review.iamReviewAttested !== true ||
    review.containsSensitiveData !== false
  ) {
    fail('E7_RELEASE_SUCCESSOR_APPROVAL_INVALID');
  }
  if (capability !== SELF_TEST_CAPABILITY) {
    try {
      validateGithubEnvironmentApproval(review, {
        repository: REPOSITORY,
        candidateSha: freeze.candidateSha,
        releaseId: freeze.releaseId,
        runId: observation.runId,
        runAttempt: String(observation.runAttempt),
        environment: 'assessment-release',
        diffSha256: rawDiff.rawSha256,
      });
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_GITHUB_APPROVAL_INVALID', error);
    }
  }
};

const validateReleaseActivationAndDrift = ({
  activation,
  drift,
  config,
  freeze,
  predecessor,
  capability,
}) => {
  const activationValue = activation.value;
  const driftValue = drift.value;
  const checkpoint = activationValue?.checkpoints?.activation;
  const driftCheckpoint = driftValue?.checkpoints?.drift;
  const iac = freeze.artifacts.find(({ name }) => name === 'iac');
  if (
    activationValue?.candidateSha !== freeze.candidateSha ||
    activationValue?.releaseId !== freeze.releaseId ||
    activationValue?.configSha256 !== objectSha256(config) ||
    checkpoint?.previousReleaseManifestSha256 !== predecessor.manifestSha256 ||
    checkpoint?.transitions?.at(-1)?.mode !== 'REPROMOTION' ||
    driftValue?.candidateSha !== freeze.candidateSha ||
    driftValue?.releaseId !== freeze.releaseId ||
    driftValue?.configSha256 !== objectSha256(config) ||
    driftCheckpoint?.previousReleaseManifestSha256 !== predecessor.manifestSha256 ||
    driftCheckpoint?.decision !== 'PASS' ||
    driftCheckpoint?.criticalCount !== 0 ||
    activationValue?.containsSensitiveData !== false ||
    driftValue?.containsSensitiveData !== false ||
    iac === undefined
  ) {
    fail('E7_RELEASE_SUCCESSOR_ACTIVATION_DRIFT_INVALID');
  }
  if (capability !== SELF_TEST_CAPABILITY) {
    try {
      validateStage7ActivationCheckpoint(checkpoint, {
        config,
        candidateSha: freeze.candidateSha,
        releaseId: freeze.releaseId,
        manifestSha256: freeze.manifestSha256,
        complete: true,
      });
      validateStage7DriftCheckpoint(driftCheckpoint, {
        config,
        manifestSha256: freeze.manifestSha256,
        assemblySha256: checkpoint.assemblySha256,
      });
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_ACTIVATION_DRIFT_INVALID', error);
    }
  }
};

const validateJournalLifecycle = (lifecycle, { candidateSha }) => {
  const rootPrefix = `/checkout/stage7/rollback/${candidateSha}`;
  const scenarioPrefixes = {
    'RB-E7-06': `${rootPrefix}/RB-E7-06`,
    'RB-E7-08': `${rootPrefix}/RB-E7-08`,
  };
  if (
    !object(lifecycle) ||
    lifecycle.schemaVersion !== 1 ||
    lifecycle.stage !== 7 ||
    lifecycle.kind !== 'ROLLBACK_RESILIENCE_SSM_JOURNAL_LIFECYCLE' ||
    lifecycle.status !== 'PENDING_POST_CLOSEOUT_CLEANUP' ||
    !SHA256.test(lifecycle.cleanupRoleSha256 ?? '') ||
    lifecycle.rootPrefix !== rootPrefix ||
    canonicalJson(lifecycle.scenarioPrefixes) !== canonicalJson(scenarioPrefixes) ||
    lifecycle.cleanupScopeSha256 !== objectSha256({ rootPrefix, scenarioPrefixes }) ||
    lifecycle.retentionBoundary !== 'FINAL_EVIDENCE_AND_SUCCESSOR_HANDOFF_PRESERVED' ||
    !utc(lifecycle.expiresAtUtc) ||
    lifecycle.evidenceRetentionDays !== 30 ||
    lifecycle.cleanupMode !== 'SEPARATE_IDEMPOTENT_PROTECTED_RUN' ||
    lifecycle.cleanupRequired !== true ||
    lifecycle.cleanupAttempted !== false ||
    lifecycle.deleteBeforeBoundaryAllowed !== false ||
    lifecycle.containsSensitiveData !== false ||
    lifecycle.lifecycleSha256 !== objectSha256(withoutDigest(lifecycle, 'lifecycleSha256'))
  ) {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_LIFECYCLE_INVALID');
  }
  return lifecycle;
};

const validateReleaseRollbackCompletion = ({
  rollback,
  sourceBinding,
  protectedRun,
  completion,
  rollbackValidationContext,
  freeze,
  predecessor,
  candidateRecord,
  capability,
}) => {
  const run = protectedRun.value;
  const envelope = completion.value;
  const lifecycle = validateJournalLifecycle(run?.runtimeAttestation?.journalLifecycle, {
    candidateSha: freeze.candidateSha,
  });
  const rehearsal = envelope?.versionedRollbackRehearsal;
  if (
    sourceBinding.value?.candidateSha !== freeze.candidateSha ||
    sourceBinding.value?.releaseId !== freeze.releaseId ||
    sourceBinding.value?.previousReleaseManifestSha256 !== predecessor.manifestSha256 ||
    sourceBinding.value?.candidateRecordSha256 !== candidateRecord.recordSha256 ||
    sourceBinding.value?.rollbackEvidenceSha256 !== rollback.rawSha256 ||
    sourceBinding.value?.sourceBindingSha256 !==
      objectSha256(withoutDigest(sourceBinding.value, 'sourceBindingSha256')) ||
    run?.kind !== 'PROTECTED_ROLLBACK_RESILIENCE_RUN' ||
    run?.status !== 'AWS_VERIFIED' ||
    run?.completion?.status !== 'AWS_VERIFIED' ||
    run?.completion?.finalCandidateSha !== freeze.candidateSha ||
    run?.completion?.finalReleaseId !== freeze.releaseId ||
    run?.completion?.journalLifecycleSha256 !== lifecycle.lifecycleSha256 ||
    run?.completion?.reconciliationRecoveryRoleAuthoritySha256 !==
      sourceBinding.value?.reconciliationRecoveryRoleAuthoritySha256 ||
    run?.completion?.completionSha256 !==
      objectSha256(withoutDigest(run.completion, 'completionSha256')) ||
    run?.runSha256 !== objectSha256(withoutDigest(run, 'runSha256')) ||
    envelope?.kind !== 'ROLLBACK_RESILIENCE_COMPLETION_ENVELOPE' ||
    envelope?.status !== 'PASS' ||
    envelope?.candidateSha !== freeze.candidateSha ||
    envelope?.releaseId !== freeze.releaseId ||
    envelope?.baseRollbackEvidenceRawSha256 !== rollback.rawSha256 ||
    envelope?.baseRollbackEvidenceObjectSha256 !== rollback.canonicalSha256 ||
    envelope?.sourceBindingRawSha256 !== sourceBinding.rawSha256 ||
    envelope?.sourceBindingObjectSha256 !== sourceBinding.canonicalSha256 ||
    envelope?.protectedRunRawSha256 !== protectedRun.rawSha256 ||
    envelope?.protectedRunObjectSha256 !== protectedRun.canonicalSha256 ||
    envelope?.journalLifecycleSha256 !== lifecycle.lifecycleSha256 ||
    envelope?.reconciliationRecoveryRoleAuthoritySha256 !==
      sourceBinding.value?.reconciliationRecoveryRoleAuthoritySha256 ||
    rehearsal?.status !== 'PASS' ||
    rehearsal?.pendingScenarioIds?.length !== 0 ||
    rehearsal?.scenarioIds?.join('\0') !==
      Array.from({ length: 8 }, (_, index) => `RB-E7-${String(index + 1).padStart(2, '0')}`).join(
        '\0',
      ) ||
    rehearsal?.resilience?.journalLifecycleSha256 !== lifecycle.lifecycleSha256 ||
    rehearsal?.dataPolicy !== 'NO_ROLLBACK_FORWARD_ONLY' ||
    rehearsal?.dataRollbackPerformed !== false ||
    rehearsal?.stacksDeleted !== 0 ||
    envelope?.envelopeSha256 !== objectSha256(withoutDigest(envelope, 'envelopeSha256')) ||
    envelope?.containsSensitiveData !== false
  ) {
    fail('E7_RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_INVALID');
  }
  if (capability !== SELF_TEST_CAPABILITY) {
    if (!object(rollbackValidationContext)) {
      fail('E7_RELEASE_SUCCESSOR_ROLLBACK_VALIDATION_CONTEXT_REQUIRED');
    }
    try {
      validateRollbackResilienceCompletionEnvelope({
        envelope,
        rollbackSource: rollback.bytes,
        sourceBindingSource: sourceBinding.bytes,
        protectedRunSource: protectedRun.bytes,
        validationContext: rollbackValidationContext,
      });
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_INVALID', error);
    }
  }
  return { rehearsal, lifecycle };
};

const RELEASE_SUCCESSOR_FENCE_AUTHORITY_KEYS = Object.freeze([
  'sourceRunId',
  'sourceRunAttempt',
  'candidateSha',
  'releaseId',
  'journalLifecycleSha256',
  'releaseMetadataSource',
  'configSource',
  'freezeSource',
  'predecessorSource',
  'predecessorApiContractSource',
  'predecessorPendingSource',
  'predecessorSmokeSource',
  'candidateRecordSource',
  'emergencyRecoverySource',
  'emergencyRecoveryNoActionOutcomeSource',
  'approvedPlanSource',
  'rawDiffSource',
  'githubApprovalSource',
  'approvalSource',
  'activationSource',
  'driftSource',
  'rollbackSource',
  'rollbackSourceBindingSource',
  'rollbackProtectedRunSource',
  'rollbackCompletionSource',
  'reconciliationRollbackCheckSource',
  'reconciliationRollbackResilienceSource',
  'preFenceGateSource',
  'rollbackInputsSource',
  'rb06DescriptorSource',
  'rb08DescriptorSource',
  'awsAuthSource',
  'journalRoleEffectivePermissionsSource',
  'reconciliationRecoveryRoleEffectivePermissionsSource',
]);
export const RELEASE_SUCCESSOR_FENCE_AUTHORITY_BINDING_KEYS = Object.freeze([
  'releaseMetadata',
  'config',
  'freeze',
  'predecessor',
  'predecessorApiContract',
  'predecessorPending',
  'predecessorSmoke',
  'candidateRecord',
  'emergencyRecovery',
  'emergencyRecoveryNoActionOutcome',
  'approvedPlan',
  'rawDiff',
  'githubApproval',
  'approval',
  'activation',
  'drift',
  'rollback',
  'rollbackSourceBinding',
  'rollbackProtectedRun',
  'rollbackCompletion',
  'reconciliationRollbackCheck',
  'reconciliationRollbackResilience',
  'preFenceGate',
  'rollbackInputs',
  'rb06Descriptor',
  'rb08Descriptor',
  'awsAuth',
  'journalRoleEffectivePermissions',
  'reconciliationRecoveryRoleEffectivePermissions',
]);
const VALIDATED_RELEASE_SUCCESSOR_FENCE_AUTHORITIES = new WeakSet();

const releaseFenceAuthorityBinding = (document, { canonical = true } = {}) => ({
  rawSha256: document.rawSha256,
  canonicalSha256: canonical ? document.canonicalSha256 : null,
  bytes: document.byteLength,
});

export const validateReleaseSuccessorFenceAuthorityBindings = (value) => {
  if (
    !exactKeys(value, RELEASE_SUCCESSOR_FENCE_AUTHORITY_BINDING_KEYS) ||
    Object.entries(value).some(
      ([name, binding]) =>
        !exactKeys(binding, ['rawSha256', 'canonicalSha256', 'bytes']) ||
        !SHA256.test(binding.rawSha256 ?? '') ||
        (name === 'rawDiff'
          ? binding.canonicalSha256 !== null
          : !SHA256.test(binding.canonicalSha256 ?? '')) ||
        !Number.isSafeInteger(binding.bytes) ||
        binding.bytes < 1 ||
        binding.bytes > MAX_SOURCE_BYTES,
    )
  ) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_AUTHORITY_BINDINGS_INVALID');
  }
  return value;
};

const createReleaseSuccessorFenceAuthorityBindings = ({ documents, rawDiff }) =>
  validateReleaseSuccessorFenceAuthorityBindings({
    releaseMetadata: releaseFenceAuthorityBinding(documents.releaseMetadata),
    config: releaseFenceAuthorityBinding(documents.config),
    freeze: releaseFenceAuthorityBinding(documents.freeze),
    predecessor: releaseFenceAuthorityBinding(documents.predecessor),
    predecessorApiContract: releaseFenceAuthorityBinding(documents.predecessorApiContract),
    predecessorPending: releaseFenceAuthorityBinding(documents.predecessorPending),
    predecessorSmoke: releaseFenceAuthorityBinding(documents.predecessorSmoke),
    candidateRecord: releaseFenceAuthorityBinding(documents.candidateRecord),
    emergencyRecovery: releaseFenceAuthorityBinding(documents.emergencyRecovery),
    emergencyRecoveryNoActionOutcome: releaseFenceAuthorityBinding(
      documents.emergencyRecoveryNoActionOutcome,
    ),
    approvedPlan: releaseFenceAuthorityBinding(documents.approvedPlan),
    rawDiff: releaseFenceAuthorityBinding(rawDiff, { canonical: false }),
    githubApproval: releaseFenceAuthorityBinding(documents.githubApproval),
    approval: releaseFenceAuthorityBinding(documents.approval),
    activation: releaseFenceAuthorityBinding(documents.activation),
    drift: releaseFenceAuthorityBinding(documents.drift),
    rollback: releaseFenceAuthorityBinding(documents.rollback),
    rollbackSourceBinding: releaseFenceAuthorityBinding(documents.rollbackSourceBinding),
    rollbackProtectedRun: releaseFenceAuthorityBinding(documents.rollbackProtectedRun),
    rollbackCompletion: releaseFenceAuthorityBinding(documents.rollbackCompletion),
    reconciliationRollbackCheck: releaseFenceAuthorityBinding(
      documents.reconciliationRollbackCheck,
    ),
    reconciliationRollbackResilience: releaseFenceAuthorityBinding(
      documents.reconciliationRollbackResilience,
    ),
    preFenceGate: releaseFenceAuthorityBinding(documents.preFenceGate),
    rollbackInputs: releaseFenceAuthorityBinding(documents.rollbackInputs),
    rb06Descriptor: releaseFenceAuthorityBinding(documents.rb06Descriptor),
    rb08Descriptor: releaseFenceAuthorityBinding(documents.rb08Descriptor),
    awsAuth: releaseFenceAuthorityBinding(documents.awsAuth),
    journalRoleEffectivePermissions: releaseFenceAuthorityBinding(
      documents.journalRoleEffectivePermissions,
    ),
    reconciliationRecoveryRoleEffectivePermissions: releaseFenceAuthorityBinding(
      documents.reconciliationRecoveryRoleEffectivePermissions,
    ),
  });

const RELEASE_SUCCESSOR_FENCE_AUTHORITY_LAYOUT = Object.freeze({
  releaseMetadata: RELEASE_SUCCESSOR_SOURCE_LAYOUT.releaseMetadata,
  config: RELEASE_SUCCESSOR_SOURCE_LAYOUT.config,
  freeze: RELEASE_SUCCESSOR_SOURCE_LAYOUT.freeze,
  predecessor: RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessor,
  predecessorApiContract: RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorApiContract,
  predecessorPending: RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorPending,
  predecessorSmoke: RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorSmoke,
  candidateRecord: RELEASE_SUCCESSOR_SOURCE_LAYOUT.candidateRecord,
  emergencyRecovery: RELEASE_SUCCESSOR_SOURCE_LAYOUT.emergencyRecovery,
  emergencyRecoveryNoActionOutcome:
    RELEASE_SUCCESSOR_SOURCE_LAYOUT.emergencyRecoveryNoActionOutcome,
  approvedPlan: RELEASE_SUCCESSOR_SOURCE_LAYOUT.approvedPlan,
  githubApproval: RELEASE_SUCCESSOR_SOURCE_LAYOUT.githubApproval,
  approval: RELEASE_SUCCESSOR_SOURCE_LAYOUT.approval,
  activation: RELEASE_SUCCESSOR_SOURCE_LAYOUT.activation,
  drift: RELEASE_SUCCESSOR_SOURCE_LAYOUT.drift,
  rollback: RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollback,
  rollbackSourceBinding: RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackSourceBinding,
  rollbackProtectedRun: RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackProtectedRun,
  rollbackCompletion: RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackCompletion,
  reconciliationRollbackCheck: RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackCheck,
  reconciliationRollbackResilience:
    RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackResilience,
  preFenceGate: RELEASE_SUCCESSOR_SOURCE_LAYOUT.preFenceGate,
  rollbackInputs: RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackInputs,
  rb06Descriptor: RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackRb06,
  rb08Descriptor: RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackRb08,
  awsAuth: RELEASE_SUCCESSOR_SOURCE_LAYOUT.awsAuth,
  journalRoleEffectivePermissions: RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalRoleEffectivePermissions,
  reconciliationRecoveryRoleEffectivePermissions:
    RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRecoveryRoleEffectivePermissions,
});

const releaseSuccessorFenceAuthoritySetFromSourceFiles = (files) => {
  const documents = Object.fromEntries(
    Object.entries(RELEASE_SUCCESSOR_FENCE_AUTHORITY_LAYOUT).map(([name, pathName]) => [
      name,
      strictJsonDocument(
        files[pathName],
        'E7_RELEASE_SUCCESSOR_SOURCE_FENCE_AUTHORITY_SOURCE_INVALID',
      ),
    ]),
  );
  const rawDiff = textDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.rawDiff],
    'E7_RELEASE_SUCCESSOR_SOURCE_FENCE_DIFF_INVALID',
  );
  const authorityBindings = createReleaseSuccessorFenceAuthorityBindings({
    documents,
    rawDiff,
  });
  return { authorityBindings, authoritySetSha256: objectSha256(authorityBindings) };
};

export const isValidatedReleaseSuccessorFenceAuthority = (value) =>
  object(value) && VALIDATED_RELEASE_SUCCESSOR_FENCE_AUTHORITIES.has(value);

/**
 * Validates the pre-publication fence authorities from their original bytes.
 * This is deliberately narrower than the post-success source validator, but it
 * repeats every semantic and cross-document check that is available before the
 * publication/report jobs exist. A raw/canonical digest alone is never an
 * authority to create the immutable SSM fence.
 */
export const validateReleaseSuccessorFenceAuthoritySources = (options, capability = undefined) => {
  if (!exactKeys(options, RELEASE_SUCCESSOR_FENCE_AUTHORITY_KEYS)) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_AUTHORITY_OPTIONS_INVALID');
  }
  const documents = {
    releaseMetadata: strictJsonDocument(
      options.releaseMetadataSource,
      'E7_RELEASE_SUCCESSOR_FENCE_RELEASE_METADATA_INVALID',
    ),
    config: strictJsonDocument(options.configSource, 'E7_RELEASE_SUCCESSOR_FENCE_CONFIG_INVALID'),
    freeze: strictJsonDocument(options.freezeSource, 'E7_RELEASE_SUCCESSOR_FENCE_FREEZE_INVALID'),
    predecessor: strictJsonDocument(
      options.predecessorSource,
      'E7_RELEASE_SUCCESSOR_FENCE_PREDECESSOR_INVALID',
    ),
    predecessorApiContract: strictJsonDocument(
      options.predecessorApiContractSource,
      'E7_RELEASE_SUCCESSOR_FENCE_PREDECESSOR_API_INVALID',
    ),
    predecessorPending: strictJsonDocument(
      options.predecessorPendingSource,
      'E7_RELEASE_SUCCESSOR_FENCE_PREDECESSOR_PENDING_INVALID',
    ),
    predecessorSmoke: strictJsonDocument(
      options.predecessorSmokeSource,
      'E7_RELEASE_SUCCESSOR_FENCE_PREDECESSOR_SMOKE_INVALID',
    ),
    candidateRecord: strictJsonDocument(
      options.candidateRecordSource,
      'E7_RELEASE_SUCCESSOR_FENCE_CANDIDATE_INVALID',
    ),
    emergencyRecovery: strictJsonDocument(
      options.emergencyRecoverySource,
      'E7_RELEASE_SUCCESSOR_FENCE_EMERGENCY_RECOVERY_INVALID',
    ),
    emergencyRecoveryNoActionOutcome: strictJsonDocument(
      options.emergencyRecoveryNoActionOutcomeSource,
      'E7_RELEASE_SUCCESSOR_FENCE_EMERGENCY_RECOVERY_OUTCOME_INVALID',
    ),
    approvedPlan: strictJsonDocument(
      options.approvedPlanSource,
      'E7_RELEASE_SUCCESSOR_FENCE_PLAN_INVALID',
    ),
    githubApproval: strictJsonDocument(
      options.githubApprovalSource,
      'E7_RELEASE_SUCCESSOR_FENCE_GITHUB_APPROVAL_INVALID',
    ),
    approval: strictJsonDocument(
      options.approvalSource,
      'E7_RELEASE_SUCCESSOR_FENCE_APPROVAL_INVALID',
    ),
    activation: strictJsonDocument(
      options.activationSource,
      'E7_RELEASE_SUCCESSOR_FENCE_ACTIVATION_INVALID',
    ),
    drift: strictJsonDocument(options.driftSource, 'E7_RELEASE_SUCCESSOR_FENCE_DRIFT_INVALID'),
    rollback: strictJsonDocument(
      options.rollbackSource,
      'E7_RELEASE_SUCCESSOR_FENCE_ROLLBACK_INVALID',
    ),
    rollbackSourceBinding: strictJsonDocument(
      options.rollbackSourceBindingSource,
      'E7_RELEASE_SUCCESSOR_FENCE_ROLLBACK_BINDING_INVALID',
    ),
    rollbackProtectedRun: strictJsonDocument(
      options.rollbackProtectedRunSource,
      'E7_RELEASE_SUCCESSOR_FENCE_ROLLBACK_RUN_INVALID',
    ),
    rollbackCompletion: strictJsonDocument(
      options.rollbackCompletionSource,
      'E7_RELEASE_SUCCESSOR_FENCE_ROLLBACK_COMPLETION_INVALID',
    ),
    reconciliationRollbackCheck: strictJsonDocument(
      options.reconciliationRollbackCheckSource,
      'E7_RELEASE_SUCCESSOR_FENCE_RECONCILIATION_CHECK_INVALID',
    ),
    reconciliationRollbackResilience: strictJsonDocument(
      options.reconciliationRollbackResilienceSource,
      'E7_RELEASE_SUCCESSOR_FENCE_RECONCILIATION_RESILIENCE_INVALID',
    ),
    preFenceGate: strictJsonDocument(
      options.preFenceGateSource,
      'E7_RELEASE_SUCCESSOR_FENCE_PRE_FENCE_GATE_INVALID',
    ),
    rollbackInputs: strictJsonDocument(
      options.rollbackInputsSource,
      'E7_RELEASE_SUCCESSOR_FENCE_ROLLBACK_INPUTS_INVALID',
    ),
    rb06Descriptor: strictJsonDocument(
      options.rb06DescriptorSource,
      'E7_RELEASE_SUCCESSOR_FENCE_RB06_DESCRIPTOR_INVALID',
    ),
    rb08Descriptor: strictJsonDocument(
      options.rb08DescriptorSource,
      'E7_RELEASE_SUCCESSOR_FENCE_RB08_DESCRIPTOR_INVALID',
    ),
    awsAuth: strictJsonDocument(
      options.awsAuthSource,
      'E7_RELEASE_SUCCESSOR_FENCE_AWS_AUTH_INVALID',
    ),
    journalRoleEffectivePermissions: strictJsonDocument(
      options.journalRoleEffectivePermissionsSource,
      'E7_RELEASE_SUCCESSOR_FENCE_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_INVALID',
    ),
    reconciliationRecoveryRoleEffectivePermissions: strictJsonDocument(
      options.reconciliationRecoveryRoleEffectivePermissionsSource,
      'E7_RELEASE_SUCCESSOR_FENCE_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_INVALID',
    ),
  };
  const rawDiff = textDocument(options.rawDiffSource, 'E7_RELEASE_SUCCESSOR_FENCE_DIFF_INVALID');
  let config;
  let freeze;
  let predecessor;
  let candidateRecord;
  try {
    config = validateStage7Config(documents.config.value, {
      now: new Date(documents.config.value.window.startsAtUtc),
    });
    freeze = validateFreezeManifest(documents.freeze.value);
    predecessor = validateStage7PreviousReleaseManifest(documents.predecessor.value);
    candidateRecord = validateStage7CandidateRollbackRecord(documents.candidateRecord.value, {
      previousManifest: predecessor,
    });
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_IDENTITY_INVALID', error);
  }
  const sourceRunId = String(options.sourceRunId ?? '');
  const sourceRunAttempt = Number(options.sourceRunAttempt);
  const metadata = documents.releaseMetadata.value;
  if (
    !RUN_ID.test(sourceRunId) ||
    sourceRunAttempt !== 1 ||
    options.candidateSha !== freeze.candidateSha ||
    options.releaseId !== freeze.releaseId ||
    config.authorization.scope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    objectSha256(config) !== freeze.configSha256 ||
    predecessor.target?.candidateSha !== freeze.candidateSha ||
    predecessor.target?.candidateTreeSha !== freeze.candidateTreeSha ||
    predecessor.target?.releaseId !== freeze.releaseId ||
    predecessor.target?.releaseTag !== freeze.releaseTag ||
    predecessor.target?.configSha256 !== freeze.configSha256 ||
    predecessor.target?.freezeManifestSha256 !== freeze.manifestSha256 ||
    candidateRecord.target?.candidateSha !== freeze.candidateSha ||
    candidateRecord.target?.releaseId !== freeze.releaseId ||
    candidateRecord.previousReleaseManifestSha256 !== predecessor.manifestSha256 ||
    metadata.scope !== 'full' ||
    metadata.candidateSha !== freeze.candidateSha ||
    metadata.candidateTreeSha !== freeze.candidateTreeSha ||
    metadata.releaseId !== freeze.releaseId ||
    String(metadata.releaseRunId) !== sourceRunId ||
    metadata.releaseRunAttempt !== 1 ||
    metadata.containsSensitiveData !== false
  ) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_IDENTITY_INVALID');
  }
  const fenceObservation = {
    runId: sourceRunId,
    runAttempt: sourceRunAttempt,
    observedAtUtc: config.window.endsAtUtc,
  };
  validateReleaseApproval({
    approval: documents.approval,
    githubApproval: documents.githubApproval,
    approvedPlan: documents.approvedPlan,
    rawDiff,
    config,
    freeze,
    predecessor,
    candidateRecord,
    observation: fenceObservation,
    capability,
  });
  validateReleaseSuccessorAuxiliaryRoleEffectivePermissions({ documents, freeze });
  validateReleaseSuccessorAuxiliaryRoleBindings({ documents });
  validateReleaseSuccessorEmergencyRecoveryNoAction({
    documents,
    config,
    freeze,
    predecessor,
    candidateRecord,
    sourceRunId,
  });
  validateReleaseActivationAndDrift({
    activation: documents.activation,
    drift: documents.drift,
    config,
    freeze,
    predecessor,
    capability,
  });
  const rollback = validateReleaseRollbackCompletion({
    rollback: documents.rollback,
    sourceBinding: documents.rollbackSourceBinding,
    protectedRun: documents.rollbackProtectedRun,
    completion: documents.rollbackCompletion,
    rollbackValidationContext: {
      inputsWithoutExecution: documents.rollbackInputs.value,
      rb06Descriptor: documents.rb06Descriptor.value,
      rb08Descriptor: documents.rb08Descriptor.value,
    },
    freeze,
    predecessor,
    candidateRecord,
    capability,
  });
  const reconciliation = validateReleaseSuccessorReconciliationAuthoritySources({
    rollbackCheckSource: documents.reconciliationRollbackCheck.bytes,
    rollbackResilienceSource: documents.reconciliationRollbackResilience.bytes,
    preFenceGateSource: documents.preFenceGate.bytes,
    expected: {
      sourceRunId,
      sourceRunAttempt,
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      releaseTag: freeze.releaseTag,
    },
  });
  if (
    rollback.lifecycle.lifecycleSha256 !== options.journalLifecycleSha256 ||
    reconciliation.gate.source.configSha256 !== freeze.configSha256 ||
    reconciliation.gate.runtime.expectedStateSha256 !==
      reconciliation.gate.runtime.observedStateSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_FENCE_LIFECYCLE_INVALID');
  }
  const evidenceBindings = Object.fromEntries(
    [
      ['approval', documents.approval],
      ['activation', documents.activation],
      ['drift', documents.drift],
      ['rollbackCompletion', documents.rollbackCompletion],
      ['preFenceGate', reconciliation.preFenceGate],
    ].map(([name, document]) => [
      name,
      {
        rawSha256: document.rawSha256,
        canonicalSha256: document.canonicalSha256,
        bytes: document.byteLength,
      },
    ]),
  );
  const authorityBindings = createReleaseSuccessorFenceAuthorityBindings({
    documents,
    rawDiff,
  });
  const result = Object.freeze({
    config,
    freeze,
    predecessor,
    candidateRecord,
    lifecycle: rollback.lifecycle,
    reconciliationJournalAuthority: reconciliation.authority,
    evidenceBindings,
    authorityBindings,
    authoritySetSha256: objectSha256(authorityBindings),
  });
  VALIDATED_RELEASE_SUCCESSOR_FENCE_AUTHORITIES.add(result);
  return result;
};

const validateReleaseCloseout = ({ closeout, freeze, observation }) => {
  const value = closeout.value;
  const observedSuccessfulExecution =
    observation.kind === 'RELEASE_SUCCESSOR_COMPOSITE_RECOVERY_RUN_OBSERVATION'
      ? ['failure', 'cancelled', 'timed_out'].includes(observation.conclusion) &&
        observation.recovery?.conclusion === 'success'
      : observation.conclusion === 'success';
  if (
    value.kind !== 'STAGE7_CLOSEOUT' ||
    value.status !== 'RELEASED' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.releaseTag !== freeze.releaseTag ||
    value.releaseMode !== 'VERSIONED_UPDATE' ||
    value.updateReleaseSupported !== true ||
    value.updateReleaseUnsupportedReason !== null ||
    value.cloudFormationDrift?.checked !== 4 ||
    value.cloudFormationDrift?.criticalCount !== 0 ||
    value.cloudFormationDrift?.status !== 'IN_SYNC' ||
    value.gates?.['GATE-E7-01'] !== 'PASS' ||
    value.gates?.['GATE-E7-02'] !== 'PASS' ||
    value.gates?.['GATE-E7-03'] !== 'PASS' ||
    value.artifacts?.verified !== 20 ||
    value.artifacts?.total !== 20 ||
    value.evidence?.pass !== 57 ||
    value.evidence?.total !== 57 ||
    value.publication?.repositoryPublic !== true ||
    value.publication?.urlsVerified !== true ||
    value.nextStage !== 8 ||
    value.mutationsPerformedByVerifier !== 0 ||
    value.containsSensitiveData !== false ||
    observation.runStatus !== 'completed' ||
    !observedSuccessfulExecution
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLOSEOUT_INVALID');
  }
};

const validateReleasePublication = ({
  preparation,
  plan,
  targetProof,
  operation,
  proof,
  releaseManifest,
  config,
  freeze,
}) => {
  const identityMatches = (value) =>
    value?.candidateSha === freeze.candidateSha &&
    value?.releaseId === freeze.releaseId &&
    value?.releaseTag === freeze.releaseTag &&
    value?.containsSensitiveData === false;
  const planValue = plan.value;
  const preparationValue = preparation.value;
  const targetValue = targetProof.value;
  const operationValue = operation.value;
  const proofValue = proof.value;
  const expectedReleaseUrl = `https://github.com/${REPOSITORY}/releases/tag/${encodeURIComponent(freeze.releaseTag)}`;
  if (
    !identityMatches(planValue) ||
    planValue.kind !== 'PUBLICATION_PLAN' ||
    planValue.status !== 'READY_FOR_EXTERNAL_PUBLICATION' ||
    planValue.repository !== REPOSITORY ||
    planValue.branch !== 'master' ||
    planValue.release?.targetSha !== freeze.candidateSha ||
    planValue.release?.draft !== false ||
    planValue.release?.prerelease !== freeze.releaseTag.includes('-rc.') ||
    planValue.release?.assetName !== 'candidate-manifest.json' ||
    planValue.publicationOrder?.join('\0') !== ['README_VERIFY', 'GITHUB_RELEASE'].join('\0') ||
    planValue.retryPolicy !== 'VERIFY_EXACT_OR_CREATE_MISSING' ||
    planValue.externalWritesPerformed !== 0 ||
    !identityMatches(preparationValue) ||
    preparationValue.kind !== 'PUBLICATION_PREPARATION' ||
    preparationValue.status !== planValue.status ||
    preparationValue.packageSha256 !== objectSha256(planValue.files) ||
    !identityMatches(targetValue) ||
    targetValue.kind !== 'PUBLICATION_TARGET_PREFLIGHT' ||
    targetValue.status !== 'PASS' ||
    targetValue.publicationPlanSha256 !== plan.canonicalSha256 ||
    targetValue.stage7ConfigSha256 !== objectSha256(config) ||
    targetValue.urlsSha256 !== objectSha256(planValue.urls) ||
    targetValue.externalRequests !== 3 ||
    targetValue.mutationsPerformed !== 0 ||
    !identityMatches(operationValue) ||
    operationValue.kind !== 'GITHUB_PUBLICATION_OPERATION' ||
    operationValue.status !== 'PASS' ||
    operationValue.repository !== REPOSITORY ||
    operationValue.publicationPlanSha256 !== plan.canonicalSha256 ||
    operationValue.releaseState !== 'COMPLETE' ||
    operationValue.readmeState !== 'VERIFIED_AT_CANDIDATE' ||
    !identityMatches(proofValue) ||
    proofValue.kind !== 'PUBLICATION_PROOF' ||
    proofValue.status !== 'PASS' ||
    proofValue.repository !== REPOSITORY ||
    proofValue.branch !== 'master' ||
    proofValue.repositoryPublic !== true ||
    proofValue.readmeVerifiedAtCandidate !== true ||
    proofValue.readmeCommitSha !== freeze.candidateSha ||
    proofValue.releasePresent !== true ||
    proofValue.releaseVerifiedExact !== true ||
    proofValue.releaseTargetSha !== freeze.candidateSha ||
    proofValue.tagRefAuthoritative !== true ||
    proofValue.commitsEndpointVerified !== true ||
    proofValue.releaseUrl !== expectedReleaseUrl ||
    proofValue.targetHealthyBeforePublication !== true ||
    proofValue.urlsVerified !== true ||
    proofValue.publicationPlanSha256 !== plan.canonicalSha256 ||
    proofValue.publicationTargetProofSha256 !== targetProof.canonicalSha256 ||
    proofValue.publicationOperationSha256 !== operation.canonicalSha256 ||
    !utc(proofValue.verifiedAtUtc) ||
    releaseManifest.value.publication?.releaseUrl !== proofValue.releaseUrl ||
    releaseManifest.value.publication?.readmeCommitSha !== proofValue.readmeCommitSha ||
    releaseManifest.value.publication?.repositoryPublic !== true ||
    releaseManifest.value.publication?.urlsVerified !== true ||
    releaseManifest.value.publication?.proofRawSha256 !== proof.rawSha256 ||
    releaseManifest.value.publication?.proofObjectSha256 !== proof.canonicalSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_PUBLICATION_INVALID');
  }
};

const validateFinalReleaseManifest = ({
  releaseManifest,
  provenanceLedger,
  closeout,
  rollbackCompletion,
  freeze,
  predecessor,
}) => {
  const value = releaseManifest.value;
  if (
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_FINAL_RELEASE_MANIFEST' ||
    value.status !== 'RELEASED' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.releaseTag !== freeze.releaseTag ||
    value.releaseMode !== 'VERSIONED_UPDATE' ||
    value.artifacts?.verified !== 20 ||
    value.artifacts?.total !== 20 ||
    value.evidence?.pass !== 57 ||
    value.evidence?.total !== 57 ||
    value.publication?.repositoryPublic !== true ||
    value.publication?.urlsVerified !== true ||
    value.gates?.['GATE-E7-01'] !== 'PASS' ||
    value.gates?.['GATE-E7-02'] !== 'PASS' ||
    value.gates?.['GATE-E7-03'] !== 'PASS' ||
    value.rollback?.predecessorManifestSha256 !== predecessor.manifestSha256 ||
    value.rollback?.completionRawSha256 !== rollbackCompletion.rawSha256 ||
    value.rollback?.completionObjectSha256 !== rollbackCompletion.canonicalSha256 ||
    value.rollback?.completionEnvelopeSha256 !== rollbackCompletion.value.envelopeSha256 ||
    !object(value.authorities) ||
    Object.values(value.authorities).some((digest) => !SHA256.test(digest ?? '')) ||
    !object(value.contentBindings) ||
    Object.values(value.contentBindings).some((digest) => !SHA256.test(digest ?? '')) ||
    value.containsSensitiveData !== false ||
    value.manifestSha256 !== objectSha256(withoutDigest(value, 'manifestSha256')) ||
    closeout.value.candidateSha !== value.candidateSha ||
    closeout.value.releaseId !== value.releaseId ||
    provenanceLedger.value.candidateSha !== value.candidateSha ||
    provenanceLedger.value.releaseId !== value.releaseId
  ) {
    fail('E7_RELEASE_SUCCESSOR_FINAL_RELEASE_MANIFEST_INVALID');
  }
  return value;
};

const LEDGER_SOURCE_DOCUMENT_MAP = Object.freeze({
  previousReleaseManifest: ['predecessor', 'stage7-previous-release'],
  previousSourceProvenance: ['predecessorSourceProvenance', 'stage7-previous-release'],
  previousTargetCompatibility: ['predecessorTargetCompatibility', 'stage7-previous-release'],
  previousFinalDisableProvenance: ['predecessorFinalDisable', 'stage7-previous-release'],
  previousReleaseProjectionIndex: ['predecessorProjectionIndex', 'stage7-previous-release'],
  previousApiContractEvidence: ['predecessorApiContract', 'stage7-previous-release'],
  previousPendingEvidence: ['predecessorPending', 'stage7-previous-release'],
  previousSmokeEvidence: ['predecessorSmoke', 'stage7-previous-release'],
  approval: ['approval', 'stage7-approval'],
  emergencyRecoveryNoActionOutcome: ['emergencyRecoveryNoActionOutcome', 'stage7-recovery-probe'],
  releaseJournalRoleEffectivePermissions: ['journalRoleEffectivePermissions', 'stage7-aws-auth'],
  releaseReconciliationRecoveryRoleEffectivePermissions: [
    'reconciliationRecoveryRoleEffectivePermissions',
    'stage7-aws-auth',
  ],
  activation: ['activation', 'stage7-activation'],
  drift: ['drift', 'stage7-rollback'],
  rollbackResilienceSourceBinding: ['rollbackSourceBinding', 'stage7-rollback-resilience'],
  rollbackResilienceProtectedRun: ['rollbackProtectedRun', 'stage7-rollback-resilience'],
  rollbackResilienceCompletion: ['rollbackCompletion', 'stage7-rollback-resilience'],
  rollbackCheckReconciliation: [
    'reconciliationRollbackCheck',
    STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
  ],
  rollbackResilienceReconciliation: [
    'reconciliationRollbackResilience',
    STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
  ],
  releasePreFenceGate: ['preFenceGate', STAGE7_RELEASE_RECONCILIATION_ARTIFACT],
  releaseSuccessorFence: ['releaseFence', 'stage7-release-successor-fence'],
  publicationPreparation: ['publicationPreparation', 'stage7-publication'],
  publicationPlan: ['publicationPlan', 'stage7-publication'],
  publicationTargetProof: ['publicationTargetProof', 'stage7-publication'],
  publicationOperation: ['publicationOperation', 'stage7-publication'],
  publicationProof: ['publicationProof', 'stage7-publication'],
});

const LEDGER_SOURCE_BINDING_SPECS = Object.freeze(
  STAGE7_LEDGER_SOURCE_BINDING_SPECS.map(({ key, basename }) => {
    const mapping = LEDGER_SOURCE_DOCUMENT_MAP[key];
    if (!Array.isArray(mapping) || mapping.length !== 2) {
      fail('E7_RELEASE_SUCCESSOR_LEDGER_BINDING_CATALOG_INVALID');
    }
    return Object.freeze([key, basename, ...mapping]);
  }),
);

const ledgerBindingFor = (ledger, key, basename) => {
  const binding = ledger.sourceBindings?.[key];
  if (!object(binding) || binding.basename !== basename) {
    fail('E7_RELEASE_SUCCESSOR_LEDGER_BINDING_MISSING');
  }
  return binding;
};

const validateProvenanceLedger = ({ provenanceLedger, freeze, documents }) => {
  const value = provenanceLedger.value;
  if (
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_PROVENANCE_LEDGER' ||
    value.status !== 'VERIFIED' ||
    value.scope !== 'full' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.counts?.artifacts?.verified !== 20 ||
    value.counts?.artifacts?.total !== 20 ||
    value.counts?.evidence?.pass !== 57 ||
    value.counts?.evidence?.total !== 57 ||
    value.gates?.['GATE-E7-01'] !== 'PASS' ||
    value.gates?.['GATE-E7-02'] !== 'PASS' ||
    value.gates?.['GATE-E7-03'] !== 'PASS' ||
    value.nextStage !== 8 ||
    !object(value.sourceBindings) ||
    Object.keys(value.sourceBindings).toSorted().join('\0') !==
      LEDGER_SOURCE_BINDING_SPECS.map(([key]) => key)
        .toSorted()
        .join('\0') ||
    value.containsSensitiveData !== false ||
    value.ledgerSha256 !== objectSha256(withoutDigest(value, 'ledgerSha256'))
  ) {
    fail('E7_RELEASE_SUCCESSOR_PROVENANCE_LEDGER_INVALID');
  }
  for (const [key, basename, documentKey, artifactName] of LEDGER_SOURCE_BINDING_SPECS) {
    const document = documents[documentKey];
    const binding = ledgerBindingFor(value, key, basename);
    if (
      !exactKeys(binding, [
        'status',
        'basename',
        'path',
        'artifactName',
        'producerJob',
        'rawSha256',
        'objectSha256',
      ]) ||
      binding.status !== 'BOUND' ||
      typeof binding.path !== 'string' ||
      path.posix.basename(binding.path.replaceAll('\\', '/')) !== basename ||
      binding.artifactName !== artifactName ||
      typeof binding.producerJob !== 'string' ||
      binding.producerJob.length < 1 ||
      binding.rawSha256 !== document.rawSha256 ||
      binding.objectSha256 !== document.canonicalSha256
    ) {
      fail('E7_RELEASE_SUCCESSOR_LEDGER_BINDING_MISMATCH');
    }
  }
  const observation = validateReleaseSuccessorRunObservation(documents.observation.value);
  const canonicalSha256ByBasename = {};
  for (const [basename, producer] of Object.entries(STAGE7_SOURCE_PRODUCERS.full)) {
    const artifact = observation.artifacts.find(({ name }) => name === producer.artifactName);
    const matches = artifact?.entries.filter(
      ({ path: pathName }) => path.posix.basename(pathName) === basename,
    );
    if (matches?.length !== 1 || !SHA256.test(matches[0].canonicalSha256 ?? '')) {
      if (basename.endsWith('.json')) {
        fail('E7_RELEASE_SUCCESSOR_CATALOG_SOURCE_NOT_OBSERVED');
      }
    } else {
      canonicalSha256ByBasename[basename] = matches[0].canonicalSha256;
    }
  }
  for (const row of [...(value.artifacts ?? []), ...(value.evidence ?? [])]) {
    for (const source of row?.sources ?? []) {
      const normalizedPath = source.path?.replaceAll('\\', '/');
      const basename = path.posix.basename(normalizedPath ?? '');
      const producer = STAGE7_SOURCE_PRODUCERS.full[basename];
      const artifact = observation.artifacts.find(({ name }) => name === producer?.artifactName);
      const matches = artifact?.entries.filter(
        ({ path: pathName }) => path.posix.basename(pathName) === basename,
      );
      if (
        producer === undefined ||
        source.artifactName !== producer.artifactName ||
        source.producerJob !== producer.producerJob ||
        normalizedPath !== `.stage7/evidence/${producer.artifactName}/${basename}` ||
        matches?.length !== 1 ||
        source.sha256 !== matches[0].sha256
      ) {
        fail('E7_RELEASE_SUCCESSOR_LEDGER_PHYSICAL_SOURCE_MISMATCH');
      }
    }
  }
  try {
    validateStage7ProvenanceLedger(value, {
      entryGate: value.entryGate,
      handoff: documents.releaseHandoff.value,
      canonicalSha256ByBasename,
    });
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_PROVENANCE_LEDGER_DEEP_INVALID', error);
  }
  return value;
};

const validateReleaseApi = ({ apiDeployment, freeze, config, observation }) => {
  const value = apiDeployment.value;
  const checkpoint = value?.checkpoints?.api;
  if (
    value?.candidateSha !== freeze.candidateSha ||
    value?.releaseId !== freeze.releaseId ||
    value?.configSha256 !== objectSha256(config) ||
    value?.containsSensitiveData !== false ||
    !object(checkpoint) ||
    !['PASS', 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION'].includes(
      checkpoint.status ?? checkpoint.decision,
    ) ||
    Date.parse(value.updatedAtUtc ?? observation.observedAtUtc) >
      Date.parse(observation.observedAtUtc)
  ) {
    fail('E7_RELEASE_SUCCESSOR_API_CONTRACT_INVALID');
  }
};

const validateReleasePending = ({ pendingProducer, freeze }) => {
  const value = pendingProducer.value;
  if (
    value.kind !== 'VERSIONED_ROLLBACK_PENDING_PRODUCER' ||
    value.status !== 'PASS' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.containsSensitiveData !== false ||
    !object(value.authorizationUsage)
  ) {
    fail('E7_RELEASE_SUCCESSOR_PENDING_RECONCILIATION_INVALID');
  }
};

const validateReleaseSmoke = ({ postdeploySmoke, repromotionSmoke, freeze, rehearsal }) => {
  const postdeploy = postdeploySmoke.value;
  const repromotion = repromotionSmoke.value;
  if (
    postdeploy.status !== 'PASS' ||
    postdeploy.candidateSha !== freeze.candidateSha ||
    postdeploy.releaseId !== freeze.releaseId ||
    postdeploy.containsSensitiveData !== false ||
    repromotion.status !== 'PASS' ||
    repromotion.candidateSha !== freeze.candidateSha ||
    repromotion.releaseId !== freeze.releaseId ||
    repromotion.kind !== 'DEPLOYED_BLACK_BOX_SMOKE' ||
    !['POST_REPROMOTION_VERSIONED', undefined].includes(repromotion.mode) ||
    ![3, undefined].includes(repromotion.total) ||
    ![3, undefined].includes(repromotion.passed) ||
    ![0, undefined].includes(repromotion.failed) ||
    ![0, undefined].includes(repromotion.dataMutations) ||
    repromotion.containsSensitiveData !== false ||
    rehearsal?.repromotion?.checkpoint?.smoke?.releaseId !== freeze.releaseId
  ) {
    fail('E7_RELEASE_SUCCESSOR_SMOKE_INVALID');
  }
};

export const validateReleaseSuccessorFinalDisableProvenance = (
  value,
  {
    candidateSha,
    releaseId,
    sourceRunId,
    sourceRunAttempt,
    releaseEvidenceSetSha256,
    journalLifecycleSha256,
    releaseFenceDocument,
    markerDocument,
    earliestUtc,
  },
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
      'sourceRunAttempt',
      'decision',
      'safeToHandoff',
      'releaseEvidenceSetSha256',
      'journalLifecycleSha256',
      'releaseFence',
      'marker',
      'authority',
      'writeMode',
      'idempotent',
      'completedAtUtc',
      'authorityReadRequests',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'provenanceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_FINAL_DISABLE_PROVENANCE' ||
    value.status !== 'PASS' ||
    value.candidateSha !== candidateSha ||
    value.releaseId !== releaseId ||
    value.sourceRunId !== sourceRunId ||
    value.sourceRunAttempt !== sourceRunAttempt ||
    value.decision !== 'SAME_RUN_RECOVERY_FINALIZED' ||
    value.safeToHandoff !== true ||
    value.releaseEvidenceSetSha256 !== releaseEvidenceSetSha256 ||
    value.journalLifecycleSha256 !== journalLifecycleSha256 ||
    !exactKeys(value.releaseFence, [
      'parameterName',
      'parameterNameSha256',
      'version',
      'valueRawSha256',
      'valueCanonicalSha256',
      'fenceSha256',
    ]) ||
    value.releaseFence.parameterName !==
      `/checkout/stage7/release-fence/${candidateSha}/${sourceRunId}` ||
    value.releaseFence.parameterNameSha256 !== sha256(value.releaseFence.parameterName) ||
    !Number.isSafeInteger(value.releaseFence.version) ||
    value.releaseFence.version < 1 ||
    value.releaseFence.valueRawSha256 !== sha256(releaseFenceDocument.bytes) ||
    value.releaseFence.valueCanonicalSha256 !== releaseFenceDocument.canonicalSha256 ||
    value.releaseFence.fenceSha256 !== releaseFenceDocument.value.fenceSha256 ||
    !exactKeys(value.marker, [
      'parameterName',
      'parameterNameSha256',
      'version',
      'valueRawSha256',
      'valueCanonicalSha256',
      'markerSha256',
    ]) ||
    value.marker.parameterName !==
      `/checkout/stage7/release-finalization/${candidateSha}/${sourceRunId}` ||
    value.marker.parameterNameSha256 !== sha256(value.marker.parameterName) ||
    !Number.isSafeInteger(value.marker.version) ||
    value.marker.version < 1 ||
    value.marker.valueRawSha256 !== sha256(markerDocument.bytes) ||
    value.marker.valueCanonicalSha256 !== markerDocument.canonicalSha256 ||
    value.marker.markerSha256 !== markerDocument.value.markerSha256 ||
    !exactKeys(value.authority, [
      'journalCleanupRoleSha256',
      'rollbackRoleSha256',
      'ephemeralCleanupRoleSha256',
      'roleAuthority',
      'roleAuthoritySha256',
      'callerAttemptAuthority',
      'callerAttemptAuthoritySha256',
      'auditEvidence',
      'auditEvidenceSha256',
      'rolesDistinct',
    ]) ||
    !SHA256.test(value.authority.journalCleanupRoleSha256 ?? '') ||
    !SHA256.test(value.authority.rollbackRoleSha256 ?? '') ||
    !SHA256.test(value.authority.ephemeralCleanupRoleSha256 ?? '') ||
    value.authority.journalCleanupRoleSha256 === value.authority.rollbackRoleSha256 ||
    value.authority.journalCleanupRoleSha256 === value.authority.ephemeralCleanupRoleSha256 ||
    value.authority.rollbackRoleSha256 === value.authority.ephemeralCleanupRoleSha256 ||
    !exactKeys(value.authority.roleAuthority, [
      'accountIdSha256',
      'awsCliVersion',
      'awsCliVersionSha256',
      'roleAuditCanonicalSha256',
      'trustPolicySha256',
      'permissionsBoundaryArnSha256',
      'trustSubjectsSha256',
      'effectivePolicyProjectionSha256',
    ]) ||
    !SHA256.test(value.authority.roleAuthority.accountIdSha256 ?? '') ||
    !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u.test(
      value.authority.roleAuthority.awsCliVersion ?? '',
    ) ||
    !Object.entries(value.authority.roleAuthority)
      .filter(([key]) => key !== 'awsCliVersion')
      .every(([, digest]) => SHA256.test(digest ?? '')) ||
    value.authority.roleAuthority.awsCliVersionSha256 !==
      sha256(value.authority.roleAuthority.awsCliVersion) ||
    value.authority.roleAuthoritySha256 !== objectSha256(value.authority.roleAuthority) ||
    !exactKeys(value.authority.callerAttemptAuthority, [
      'assumedRoleArnSha256',
      'sessionNameSha256',
      'callerIdentityRawSha256',
      'callerIdentityCanonicalSha256',
    ]) ||
    Object.values(value.authority.callerAttemptAuthority).some(
      (digest) => !SHA256.test(digest ?? ''),
    ) ||
    value.authority.callerAttemptAuthoritySha256 !==
      objectSha256(value.authority.callerAttemptAuthority) ||
    !exactKeys(value.authority.auditEvidence, [
      'awsVersionRawSha256',
      'roleAuditRawSha256',
      'awsAuthRawSha256',
      'awsAuthCanonicalSha256',
      'effectivePermissionsFrozenRawSha256',
      'effectivePermissionsLiveRawSha256',
      'effectivePermissionsLiveCanonicalSha256',
      'effectivePermissionsFrozenSha256',
      'effectivePermissionsLiveSha256',
    ]) ||
    Object.values(value.authority.auditEvidence).some((digest) => !SHA256.test(digest ?? '')) ||
    value.authority.auditEvidenceSha256 !== objectSha256(value.authority.auditEvidence) ||
    markerDocument.value.journalRoleAuthoritySha256 !== value.authority.roleAuthoritySha256 ||
    value.authority.rolesDistinct !== true ||
    value.writeMode !== 'SSM_PUT_PARAMETER_OVERWRITE_FALSE_THEN_GET' ||
    typeof value.idempotent !== 'boolean' ||
    !utc(value.completedAtUtc) ||
    Date.parse(value.completedAtUtc) < Date.parse(earliestUtc) ||
    !Number.isSafeInteger(value.authorityReadRequests) ||
    value.authorityReadRequests < 7 ||
    !Number.isSafeInteger(value.externalRequests) ||
    value.externalRequests !== 3 + value.authorityReadRequests ||
    !Number.isSafeInteger(value.mutationsPerformed) ||
    value.mutationsPerformed !== (value.idempotent ? 0 : 1) ||
    value.containsSensitiveData !== false ||
    value.provenanceSha256 !== objectSha256(withoutDigest(value, 'provenanceSha256'))
  ) {
    fail('E7_RELEASE_SUCCESSOR_FINAL_DISABLE_INVALID');
  }
  return value;
};

export const validateReleaseSuccessorFinalizationMarker = (
  value,
  {
    candidateSha,
    releaseId,
    sourceRunId,
    sourceRunAttempt,
    releaseEvidenceSetSha256,
    journalLifecycleSha256,
    releaseFenceSha256,
    journalRoleAuthoritySha256,
  },
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'repository',
      'sourceWorkflowPath',
      'sourceRunId',
      'sourceRunAttempt',
      'candidateSha',
      'releaseId',
      'releaseEvidenceSetSha256',
      'journalLifecycleSha256',
      'releaseFenceSha256',
      'journalRoleAuthoritySha256',
      'containsSensitiveData',
      'markerSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_RECOVERY_FINALIZATION_MARKER' ||
    value.status !== 'FINALIZED_IMMUTABLE' ||
    value.repository !== REPOSITORY ||
    value.sourceWorkflowPath !== RELEASE_SUCCESSOR_WORKFLOW_PATH ||
    value.sourceRunId !== sourceRunId ||
    value.sourceRunAttempt !== sourceRunAttempt ||
    value.candidateSha !== candidateSha ||
    value.releaseId !== releaseId ||
    value.releaseEvidenceSetSha256 !== releaseEvidenceSetSha256 ||
    value.journalLifecycleSha256 !== journalLifecycleSha256 ||
    value.releaseFenceSha256 !== releaseFenceSha256 ||
    value.journalRoleAuthoritySha256 !== journalRoleAuthoritySha256 ||
    !SHA256.test(value.releaseFenceSha256 ?? '') ||
    !SHA256.test(value.journalRoleAuthoritySha256 ?? '') ||
    value.containsSensitiveData !== false ||
    value.markerSha256 !== objectSha256(withoutDigest(value, 'markerSha256'))
  ) {
    fail('E7_RELEASE_SUCCESSOR_FINALIZATION_MARKER_INVALID');
  }
  return value;
};

const evidenceBody = (value) => withoutDigest(value, 'evidenceSha256');

const createApiContractEvidence = ({ freeze, apiDeployment, observedAtUtc }) => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_API_CONTRACT_EVIDENCE',
    status: 'PASS',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    freezeManifestSha256: freeze.manifestSha256,
    openApiSha256: freeze.openApiSha256,
    generatedClientSha256: freeze.generatedClientSha256,
    apiDeployment: jsonBinding(RELEASE_SUCCESSOR_SOURCE_LAYOUT.apiDeployment, apiDeployment),
    verifiedAtUtc: apiDeployment.value.updatedAtUtc ?? observedAtUtc,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return { ...body, evidenceSha256: objectSha256(body) };
};

const validateApiContractEvidence = (value, { freeze, apiDeployment, observedAtUtc }) => {
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
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.openApiSha256 !== freeze.openApiSha256 ||
    value.generatedClientSha256 !== freeze.generatedClientSha256 ||
    canonicalJson(value.apiDeployment) !==
      canonicalJson(jsonBinding(RELEASE_SUCCESSOR_SOURCE_LAYOUT.apiDeployment, apiDeployment)) ||
    !utc(value.verifiedAtUtc) ||
    Date.parse(value.verifiedAtUtc) > Date.parse(observedAtUtc) ||
    value.externalRequests !== 0 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.evidenceSha256 !== objectSha256(evidenceBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_API_CONTRACT_EVIDENCE_INVALID');
  }
  return value;
};

const createPendingReconciliationEvidence = ({
  freeze,
  pendingProducer,
  rollbackCompletion,
  rehearsal,
}) => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_PENDING_RECONCILIATION_EVIDENCE',
    status: 'PASS',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    policy: 'FORWARD_ONLY_NO_DATA_ROLLBACK',
    pendingProducer: jsonBinding(RELEASE_SUCCESSOR_SOURCE_LAYOUT.pendingProducer, pendingProducer),
    rollbackCompletion: jsonBinding(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackCompletion,
      rollbackCompletion,
    ),
    pendingScenarioIds: [],
    dataRollbackPerformed: false,
    verifiedAtUtc: rehearsal.completedAtUtc,
    containsSensitiveData: false,
  };
  return { ...body, evidenceSha256: objectSha256(body) };
};

const validatePendingReconciliationEvidence = (
  value,
  { freeze, pendingProducer, rollbackCompletion, rehearsal },
) => {
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
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.policy !== 'FORWARD_ONLY_NO_DATA_ROLLBACK' ||
    canonicalJson(value.pendingProducer) !==
      canonicalJson(
        jsonBinding(RELEASE_SUCCESSOR_SOURCE_LAYOUT.pendingProducer, pendingProducer),
      ) ||
    canonicalJson(value.rollbackCompletion) !==
      canonicalJson(
        jsonBinding(RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackCompletion, rollbackCompletion),
      ) ||
    value.pendingScenarioIds?.length !== 0 ||
    value.dataRollbackPerformed !== false ||
    value.verifiedAtUtc !== rehearsal.completedAtUtc ||
    value.containsSensitiveData !== false ||
    value.evidenceSha256 !== objectSha256(evidenceBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_PENDING_EVIDENCE_INVALID');
  }
  return value;
};

const createSmokeEvidence = ({
  freeze,
  postdeploySmoke,
  repromotionSmoke,
  rollbackCompletion,
  rehearsal,
}) => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_SMOKE_EVIDENCE',
    status: 'PASS',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    postdeploySmoke: jsonBinding(RELEASE_SUCCESSOR_SOURCE_LAYOUT.postdeploySmoke, postdeploySmoke),
    repromotionSmoke: jsonBinding(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.repromotionSmoke,
      repromotionSmoke,
    ),
    rollbackCompletion: jsonBinding(
      RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackCompletion,
      rollbackCompletion,
    ),
    finalTarget: 'RELEASE_N_REPROMOTED',
    dataMutations: 0,
    verifiedAtUtc: rehearsal.completedAtUtc,
    containsSensitiveData: false,
  };
  return { ...body, evidenceSha256: objectSha256(body) };
};

const validateSmokeEvidence = (
  value,
  { freeze, postdeploySmoke, repromotionSmoke, rollbackCompletion, rehearsal },
) => {
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
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    canonicalJson(value.postdeploySmoke) !==
      canonicalJson(
        jsonBinding(RELEASE_SUCCESSOR_SOURCE_LAYOUT.postdeploySmoke, postdeploySmoke),
      ) ||
    canonicalJson(value.repromotionSmoke) !==
      canonicalJson(
        jsonBinding(RELEASE_SUCCESSOR_SOURCE_LAYOUT.repromotionSmoke, repromotionSmoke),
      ) ||
    canonicalJson(value.rollbackCompletion) !==
      canonicalJson(
        jsonBinding(RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackCompletion, rollbackCompletion),
      ) ||
    value.finalTarget !== 'RELEASE_N_REPROMOTED' ||
    value.dataMutations !== 0 ||
    value.verifiedAtUtc !== rehearsal.completedAtUtc ||
    value.containsSensitiveData !== false ||
    value.evidenceSha256 !== objectSha256(evidenceBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_SMOKE_EVIDENCE_INVALID');
  }
  return value;
};

const PRE_FINALIZATION_SOURCE_KEYS = Object.freeze([
  'observationSource',
  'releaseMetadataSource',
  'stage6CloseoutSource',
  'configSource',
  'freezeSource',
  'predecessorSource',
  'predecessorSourceProvenanceSource',
  'predecessorTargetCompatibilitySource',
  'predecessorFinalDisableSource',
  'predecessorApiContractSource',
  'predecessorPendingSource',
  'predecessorSmokeSource',
  'predecessorProjectionIndexSource',
  'candidateRecordSource',
  'emergencyRecoverySource',
  'emergencyRecoveryNoActionOutcomeSource',
  'approvedPlanSource',
  'rawDiffSource',
  'githubApprovalSource',
  'approvalSource',
  'activationSource',
  'driftSource',
  'rollbackSource',
  'rollbackSourceBindingSource',
  'rollbackProtectedRunSource',
  'rollbackCompletionSource',
  'releaseManifestSource',
  'provenanceLedgerSource',
  'closeoutSource',
  'releaseHandoffSource',
  'publicationPreparationSource',
  'publicationPlanSource',
  'publicationTargetProofSource',
  'publicationOperationSource',
  'publicationProofSource',
  'apiDeploymentSource',
  'pendingProducerSource',
  'postdeploySmokeSource',
  'repromotionSmokeSource',
  'releaseFenceSource',
  'reconciliationRollbackCheckSource',
  'reconciliationRollbackResilienceSource',
  'preFenceGateSource',
  'awsAuthSource',
  'journalRoleEffectivePermissionsSource',
  'reconciliationRecoveryRoleEffectivePermissionsSource',
  'rollbackInputsSource',
  'rb06DescriptorSource',
  'rb08DescriptorSource',
]);

const RAW_SOURCE_KEYS = Object.freeze([
  ...PRE_FINALIZATION_SOURCE_KEYS,
  'finalizationMarkerSource',
  'finalDisableSource',
  'journalSnapshotSource',
]);

const parseAndValidateReleaseSources = (
  options,
  capability = undefined,
  { requireFinalization = true } = {},
) => {
  if (!exactKeys(options, requireFinalization ? RAW_SOURCE_KEYS : PRE_FINALIZATION_SOURCE_KEYS)) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_OPTIONS_INVALID');
  }
  const documents = {
    observation: strictJsonDocument(
      options.observationSource,
      'E7_RELEASE_SUCCESSOR_OBSERVATION_SOURCE_INVALID',
    ),
    releaseMetadata: strictJsonDocument(
      options.releaseMetadataSource,
      'E7_RELEASE_SUCCESSOR_RELEASE_METADATA_SOURCE_INVALID',
    ),
    stage6Closeout: strictJsonDocument(
      options.stage6CloseoutSource,
      'E7_RELEASE_SUCCESSOR_STAGE6_CLOSEOUT_SOURCE_INVALID',
    ),
    config: strictJsonDocument(options.configSource, 'E7_RELEASE_SUCCESSOR_CONFIG_SOURCE_INVALID'),
    freeze: strictJsonDocument(options.freezeSource, 'E7_RELEASE_SUCCESSOR_FREEZE_SOURCE_INVALID'),
    predecessor: strictJsonDocument(
      options.predecessorSource,
      'E7_RELEASE_SUCCESSOR_PREDECESSOR_SOURCE_INVALID',
    ),
    predecessorSourceProvenance: strictJsonDocument(
      options.predecessorSourceProvenanceSource,
      'E7_RELEASE_SUCCESSOR_PREDECESSOR_PROVENANCE_SOURCE_INVALID',
    ),
    predecessorTargetCompatibility: strictJsonDocument(
      options.predecessorTargetCompatibilitySource,
      'E7_RELEASE_SUCCESSOR_PREDECESSOR_COMPATIBILITY_SOURCE_INVALID',
    ),
    predecessorFinalDisable: strictJsonDocument(
      options.predecessorFinalDisableSource,
      'E7_RELEASE_SUCCESSOR_PREDECESSOR_FINAL_DISABLE_SOURCE_INVALID',
    ),
    predecessorApiContract: strictJsonDocument(
      options.predecessorApiContractSource,
      'E7_RELEASE_SUCCESSOR_PREDECESSOR_API_SOURCE_INVALID',
    ),
    predecessorPending: strictJsonDocument(
      options.predecessorPendingSource,
      'E7_RELEASE_SUCCESSOR_PREDECESSOR_PENDING_SOURCE_INVALID',
    ),
    predecessorSmoke: strictJsonDocument(
      options.predecessorSmokeSource,
      'E7_RELEASE_SUCCESSOR_PREDECESSOR_SMOKE_SOURCE_INVALID',
    ),
    predecessorProjectionIndex: strictJsonDocument(
      options.predecessorProjectionIndexSource,
      'E7_RELEASE_SUCCESSOR_PREDECESSOR_INDEX_SOURCE_INVALID',
    ),
    candidateRecord: strictJsonDocument(
      options.candidateRecordSource,
      'E7_RELEASE_SUCCESSOR_CANDIDATE_SOURCE_INVALID',
    ),
    emergencyRecovery: strictJsonDocument(
      options.emergencyRecoverySource,
      'E7_RELEASE_SUCCESSOR_EMERGENCY_RECOVERY_SOURCE_INVALID',
    ),
    emergencyRecoveryNoActionOutcome: strictJsonDocument(
      options.emergencyRecoveryNoActionOutcomeSource,
      'E7_RELEASE_SUCCESSOR_EMERGENCY_RECOVERY_OUTCOME_SOURCE_INVALID',
    ),
    approvedPlan: strictJsonDocument(
      options.approvedPlanSource,
      'E7_RELEASE_SUCCESSOR_PLAN_SOURCE_INVALID',
    ),
    githubApproval: strictJsonDocument(
      options.githubApprovalSource,
      'E7_RELEASE_SUCCESSOR_GITHUB_APPROVAL_SOURCE_INVALID',
    ),
    approval: strictJsonDocument(
      options.approvalSource,
      'E7_RELEASE_SUCCESSOR_APPROVAL_SOURCE_INVALID',
    ),
    activation: strictJsonDocument(
      options.activationSource,
      'E7_RELEASE_SUCCESSOR_ACTIVATION_SOURCE_INVALID',
    ),
    drift: strictJsonDocument(options.driftSource, 'E7_RELEASE_SUCCESSOR_DRIFT_SOURCE_INVALID'),
    rollback: strictJsonDocument(
      options.rollbackSource,
      'E7_RELEASE_SUCCESSOR_ROLLBACK_SOURCE_INVALID',
    ),
    rollbackSourceBinding: strictJsonDocument(
      options.rollbackSourceBindingSource,
      'E7_RELEASE_SUCCESSOR_ROLLBACK_BINDING_SOURCE_INVALID',
    ),
    rollbackProtectedRun: strictJsonDocument(
      options.rollbackProtectedRunSource,
      'E7_RELEASE_SUCCESSOR_ROLLBACK_RUN_SOURCE_INVALID',
    ),
    rollbackCompletion: strictJsonDocument(
      options.rollbackCompletionSource,
      'E7_RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_SOURCE_INVALID',
    ),
    releaseManifest: strictJsonDocument(
      options.releaseManifestSource,
      'E7_RELEASE_SUCCESSOR_RELEASE_MANIFEST_SOURCE_INVALID',
    ),
    provenanceLedger: strictJsonDocument(
      options.provenanceLedgerSource,
      'E7_RELEASE_SUCCESSOR_PROVENANCE_LEDGER_SOURCE_INVALID',
    ),
    closeout: strictJsonDocument(
      options.closeoutSource,
      'E7_RELEASE_SUCCESSOR_CLOSEOUT_SOURCE_INVALID',
    ),
    releaseHandoff: strictJsonDocument(
      options.releaseHandoffSource,
      'E7_RELEASE_SUCCESSOR_HANDOFF_SOURCE_INVALID',
    ),
    publicationPreparation: strictJsonDocument(
      options.publicationPreparationSource,
      'E7_RELEASE_SUCCESSOR_PUBLICATION_PREPARATION_SOURCE_INVALID',
    ),
    publicationPlan: strictJsonDocument(
      options.publicationPlanSource,
      'E7_RELEASE_SUCCESSOR_PUBLICATION_PLAN_SOURCE_INVALID',
    ),
    publicationTargetProof: strictJsonDocument(
      options.publicationTargetProofSource,
      'E7_RELEASE_SUCCESSOR_PUBLICATION_TARGET_SOURCE_INVALID',
    ),
    publicationOperation: strictJsonDocument(
      options.publicationOperationSource,
      'E7_RELEASE_SUCCESSOR_PUBLICATION_OPERATION_SOURCE_INVALID',
    ),
    publicationProof: strictJsonDocument(
      options.publicationProofSource,
      'E7_RELEASE_SUCCESSOR_PUBLICATION_PROOF_SOURCE_INVALID',
    ),
    apiDeployment: strictJsonDocument(
      options.apiDeploymentSource,
      'E7_RELEASE_SUCCESSOR_API_SOURCE_INVALID',
    ),
    pendingProducer: strictJsonDocument(
      options.pendingProducerSource,
      'E7_RELEASE_SUCCESSOR_PENDING_SOURCE_INVALID',
    ),
    postdeploySmoke: strictJsonDocument(
      options.postdeploySmokeSource,
      'E7_RELEASE_SUCCESSOR_POSTDEPLOY_SMOKE_SOURCE_INVALID',
    ),
    repromotionSmoke: strictJsonDocument(
      options.repromotionSmokeSource,
      'E7_RELEASE_SUCCESSOR_REPROMOTION_SMOKE_SOURCE_INVALID',
    ),
    releaseFence: strictJsonDocument(
      options.releaseFenceSource,
      'E7_RELEASE_SUCCESSOR_RELEASE_FENCE_SOURCE_INVALID',
    ),
    reconciliationRollbackCheck: strictJsonDocument(
      options.reconciliationRollbackCheckSource,
      'E7_RELEASE_SUCCESSOR_RECONCILIATION_ROLLBACK_CHECK_SOURCE_INVALID',
    ),
    reconciliationRollbackResilience: strictJsonDocument(
      options.reconciliationRollbackResilienceSource,
      'E7_RELEASE_SUCCESSOR_RECONCILIATION_ROLLBACK_RESILIENCE_SOURCE_INVALID',
    ),
    preFenceGate: strictJsonDocument(
      options.preFenceGateSource,
      'E7_RELEASE_SUCCESSOR_PRE_FENCE_GATE_SOURCE_INVALID',
    ),
    awsAuth: strictJsonDocument(
      options.awsAuthSource,
      'E7_RELEASE_SUCCESSOR_AWS_AUTH_SOURCE_INVALID',
    ),
    journalRoleEffectivePermissions: strictJsonDocument(
      options.journalRoleEffectivePermissionsSource,
      'E7_RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_SOURCE_INVALID',
    ),
    reconciliationRecoveryRoleEffectivePermissions: strictJsonDocument(
      options.reconciliationRecoveryRoleEffectivePermissionsSource,
      'E7_RELEASE_SUCCESSOR_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_SOURCE_INVALID',
    ),
    rollbackInputs: strictJsonDocument(
      options.rollbackInputsSource,
      'E7_RELEASE_SUCCESSOR_ROLLBACK_INPUTS_SOURCE_INVALID',
    ),
    rb06Descriptor: strictJsonDocument(
      options.rb06DescriptorSource,
      'E7_RELEASE_SUCCESSOR_RB06_DESCRIPTOR_SOURCE_INVALID',
    ),
    rb08Descriptor: strictJsonDocument(
      options.rb08DescriptorSource,
      'E7_RELEASE_SUCCESSOR_RB08_DESCRIPTOR_SOURCE_INVALID',
    ),
  };
  if (requireFinalization) {
    documents.finalizationMarker = strictJsonDocument(
      options.finalizationMarkerSource,
      'E7_RELEASE_SUCCESSOR_FINALIZATION_MARKER_SOURCE_INVALID',
    );
    documents.finalDisable = strictJsonDocument(
      options.finalDisableSource,
      'E7_RELEASE_SUCCESSOR_FINAL_DISABLE_SOURCE_INVALID',
    );
    documents.journalSnapshot = strictJsonDocument(
      options.journalSnapshotSource,
      'E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_SOURCE_INVALID',
    );
  }
  const rawDiff = textDocument(options.rawDiffSource, 'E7_RELEASE_SUCCESSOR_RAW_DIFF_INVALID');
  const observation = validateReleaseSuccessorRunObservation(documents.observation.value);
  for (const [documentKey, artifactName] of Object.entries(DOCUMENT_ARTIFACT_ORIGIN)) {
    if (!Object.hasOwn(DOCUMENT_ARTIFACT_BASENAME, documentKey)) continue;
    assertReleaseSuccessorObservedArtifactSource({
      observation,
      artifactName,
      basename: DOCUMENT_ARTIFACT_BASENAME[documentKey],
      source: documents[documentKey].bytes,
    });
  }
  assertReleaseSuccessorObservedArtifactSource({
    observation,
    artifactName: 'stage7-infra-diff',
    basename: 'infra-diff.txt',
    source: rawDiff.bytes,
  });
  const rollbackContextArtifactSources = [
    ['awsAuth', 'stage7-aws-auth', 'aws-auth.json'],
    ['deploymentEvidence', 'stage7-web', 'web.json'],
    ['observabilityEvidence', 'stage7-observability', 'observability.json'],
    [
      'externalAuthorizationEvidence',
      'stage7-external-authorization',
      'external-authorization.json',
    ],
  ];
  for (const [documentKey, artifactName, basename] of rollbackContextArtifactSources) {
    assertReleaseSuccessorObservedArtifactSource({
      observation,
      artifactName,
      basename,
      source: documents.rollbackInputs.value?.documents?.[documentKey]?.content,
    });
  }
  let config;
  let freeze;
  let predecessor;
  let candidateRecord;
  try {
    config = validateStage7Config(documents.config.value, {
      now: new Date(documents.config.value.window.startsAtUtc),
    });
    freeze = validateFreezeManifest(documents.freeze.value);
    predecessor = validateStage7PreviousReleaseManifest(documents.predecessor.value);
    candidateRecord = validateStage7CandidateRollbackRecord(documents.candidateRecord.value, {
      previousManifest: predecessor,
    });
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_RELEASE_IDENTITY_INVALID', error);
  }
  if (
    config.authorization.scope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    objectSha256(config) !== freeze.configSha256 ||
    freeze.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    freeze.candidateSha !== observation.headSha ||
    predecessor.target.candidateSha !== freeze.candidateSha ||
    predecessor.target.candidateTreeSha !== freeze.candidateTreeSha ||
    predecessor.target.releaseId !== freeze.releaseId ||
    predecessor.target.releaseTag !== freeze.releaseTag ||
    predecessor.target.configSha256 !== freeze.configSha256 ||
    predecessor.target.freezeManifestSha256 !== freeze.manifestSha256 ||
    candidateRecord.target.candidateSha !== freeze.candidateSha ||
    candidateRecord.target.releaseId !== freeze.releaseId ||
    candidateRecord.previousReleaseManifestSha256 !== predecessor.manifestSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_PREDECESSOR_NOT_IMMEDIATE');
  }
  const { journalRoleEffectivePermissions, reconciliationRecoveryRoleEffectivePermissions } =
    validateReleaseSuccessorAuxiliaryRoleEffectivePermissions({ documents, freeze });
  const stage6Assessment = assessStage6Manifest(documents.stage6Closeout.value);
  const releaseMetadata = documents.releaseMetadata.value;
  if (
    stage6Assessment.status !== 'PASS' ||
    stage6Assessment.candidate?.commitSha !== freeze.candidateSha ||
    stage6Assessment.candidate?.treeSha !== freeze.candidateTreeSha ||
    releaseMetadata.scope !== 'full' ||
    releaseMetadata.candidateSha !== freeze.candidateSha ||
    releaseMetadata.candidateTreeSha !== freeze.candidateTreeSha ||
    releaseMetadata.releaseId !== freeze.releaseId ||
    String(releaseMetadata.releaseRunId) !== observation.runId ||
    releaseMetadata.releaseRunAttempt !== 1 ||
    releaseMetadata.stage6RunId !== stage6Assessment.runId ||
    releaseMetadata.stage6ManifestSha256 !== documents.stage6Closeout.rawSha256 ||
    releaseMetadata.stage6Status !== 'PASS' ||
    releaseMetadata.decision !== 'READY_FOR_BUILD_FREEZE' ||
    freeze.sourceRunId !== stage6Assessment.runId ||
    objectSha256(freeze.stage6Gates) !== objectSha256(documents.stage6Closeout.value.gates)
  ) {
    fail('E7_RELEASE_SUCCESSOR_STAGE6_CLOSEOUT_BINDING_INVALID');
  }
  try {
    validateStage7PreviousReleaseHandoff(predecessor, {
      sourceProvenance: documents.predecessorSourceProvenance.value,
      targetCompatibility: documents.predecessorTargetCompatibility.value,
      finalDisableProvenance: documents.predecessorFinalDisable.value,
    });
    validatePreviousReleaseProjectionIndex(documents.predecessorProjectionIndex.value, {
      previousReleaseManifest: predecessor,
      files: {
        'previous-release-manifest.json': documents.predecessor.bytes,
        'previous-source-provenance.json': documents.predecessorSourceProvenance.bytes,
        'previous-target-compatibility.json': documents.predecessorTargetCompatibility.bytes,
        'previous-final-disable-provenance.json': documents.predecessorFinalDisable.bytes,
        'previous-api-contract-evidence.json': documents.predecessorApiContract.bytes,
        'previous-pending-evidence.json': documents.predecessorPending.bytes,
        'previous-smoke-evidence.json': documents.predecessorSmoke.bytes,
      },
    });
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_PREDECESSOR_PROJECTION_INVALID', error);
  }
  validateReleaseApproval({
    approval: documents.approval,
    githubApproval: documents.githubApproval,
    approvedPlan: documents.approvedPlan,
    rawDiff,
    config,
    freeze,
    predecessor,
    candidateRecord,
    observation,
    capability,
  });
  validateReleaseSuccessorAuxiliaryRoleBindings({ documents });
  validateReleaseSuccessorEmergencyRecoveryNoAction({
    documents,
    config,
    freeze,
    predecessor,
    candidateRecord,
    sourceRunId: observation.runId,
  });
  validateReleaseActivationAndDrift({
    activation: documents.activation,
    drift: documents.drift,
    config,
    freeze,
    predecessor,
    capability,
  });
  const { rehearsal, lifecycle } = validateReleaseRollbackCompletion({
    rollback: documents.rollback,
    sourceBinding: documents.rollbackSourceBinding,
    protectedRun: documents.rollbackProtectedRun,
    completion: documents.rollbackCompletion,
    rollbackValidationContext: {
      inputsWithoutExecution: documents.rollbackInputs.value,
      rb06Descriptor: documents.rb06Descriptor.value,
      rb08Descriptor: documents.rb08Descriptor.value,
    },
    freeze,
    predecessor,
    candidateRecord,
    capability,
  });
  const reconciliation = validateReleaseSuccessorReconciliationAuthoritySources({
    rollbackCheckSource: documents.reconciliationRollbackCheck.bytes,
    rollbackResilienceSource: documents.reconciliationRollbackResilience.bytes,
    preFenceGateSource: documents.preFenceGate.bytes,
    expected: {
      sourceRunId: observation.runId,
      sourceRunAttempt: observation.runAttempt,
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      releaseTag: freeze.releaseTag,
    },
  });
  const preFenceGate = reconciliation.gate;
  if (
    preFenceGate.source.runId !== observation.runId ||
    preFenceGate.source.runAttempt !== observation.runAttempt ||
    preFenceGate.source.candidateSha !== freeze.candidateSha ||
    preFenceGate.source.releaseId !== freeze.releaseId ||
    preFenceGate.source.releaseTag !== freeze.releaseTag ||
    preFenceGate.source.configSha256 !== freeze.configSha256 ||
    preFenceGate.runtime.expectedStateSha256 !== preFenceGate.runtime.observedStateSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_IDENTITY_INVALID');
  }
  validateReleaseCloseout({ closeout: documents.closeout, freeze, observation });
  validateProvenanceLedger({ provenanceLedger: documents.provenanceLedger, freeze, documents });
  validateReleasePublication({
    preparation: documents.publicationPreparation,
    plan: documents.publicationPlan,
    targetProof: documents.publicationTargetProof,
    operation: documents.publicationOperation,
    proof: documents.publicationProof,
    releaseManifest: documents.releaseManifest,
    config,
    freeze,
  });
  validateFinalReleaseManifest({
    releaseManifest: documents.releaseManifest,
    provenanceLedger: documents.provenanceLedger,
    closeout: documents.closeout,
    rollbackCompletion: documents.rollbackCompletion,
    freeze,
    predecessor,
  });
  validateReleaseApi({
    apiDeployment: documents.apiDeployment,
    freeze,
    config,
    observation,
  });
  validateReleasePending({ pendingProducer: documents.pendingProducer, freeze });
  validateReleaseSmoke({
    postdeploySmoke: documents.postdeploySmoke,
    repromotionSmoke: documents.repromotionSmoke,
    freeze,
    rehearsal,
  });
  const commitmentDocuments = Object.entries(documents)
    .filter(
      ([name]) =>
        ![
          'observation',
          'releaseFence',
          'finalizationMarker',
          'finalDisable',
          'journalSnapshot',
        ].includes(name),
    )
    .map(([name, document]) =>
      name === 'config'
        ? {
            name,
            canonicalSha256: document.canonicalSha256,
          }
        : {
            name,
            rawSha256: document.rawSha256,
            canonicalSha256: document.canonicalSha256,
            bytes: document.byteLength,
          },
    )
    .toSorted((left, right) => left.name.localeCompare(right.name));
  const releaseEvidenceSetSha256 = objectSha256({
    repository: REPOSITORY,
    workflowPath: RELEASE_SUCCESSOR_WORKFLOW_PATH,
    sourceRunId: observation.runId,
    sourceRunAttempt: observation.runAttempt,
    headSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    artifactArchives: observation.artifacts.map(
      ({ id, name, digest, archiveRawSha256, archiveBytes, entries }) => ({
        id,
        name,
        digest,
        archiveRawSha256,
        archiveBytes,
        entries,
      }),
    ),
    documents: commitmentDocuments,
    rawDiff: {
      rawSha256: rawDiff.rawSha256,
      bytes: rawDiff.byteLength,
    },
    journalLifecycleSha256: lifecycle.lifecycleSha256,
    reconciliationJournalAuthoritySha256: reconciliation.authority.journalAuthoritySha256,
  });
  const evidenceBindings = Object.fromEntries(
    [
      ['approval', documents.approval],
      ['activation', documents.activation],
      ['drift', documents.drift],
      ['rollbackCompletion', documents.rollbackCompletion],
      ['preFenceGate', documents.preFenceGate],
    ].map(([name, document]) => [
      name,
      {
        rawSha256: document.rawSha256,
        canonicalSha256: document.canonicalSha256,
        bytes: document.byteLength,
      },
    ]),
  );
  const authorityBindings = createReleaseSuccessorFenceAuthorityBindings({
    documents,
    rawDiff,
  });
  const authoritySetSha256 = objectSha256(authorityBindings);
  const releaseFence = validateReleaseSuccessorCompletionFence(documents.releaseFence.value, {
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    sourceRunId: observation.runId,
    sourceRunAttempt: observation.runAttempt,
    journalLifecycleSha256: lifecycle.lifecycleSha256,
    evidenceBindings,
    authorityBindings,
    authoritySetSha256,
  });
  if (requireFinalization) {
    validateReleaseSuccessorFinalizationMarker(documents.finalizationMarker.value, {
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      sourceRunId: observation.runId,
      sourceRunAttempt: observation.runAttempt,
      releaseEvidenceSetSha256,
      journalLifecycleSha256: lifecycle.lifecycleSha256,
      releaseFenceSha256: releaseFence.fenceSha256,
      journalRoleAuthoritySha256: documents.finalizationMarker.value.journalRoleAuthoritySha256,
    });
    validateReleaseSuccessorFinalDisableProvenance(documents.finalDisable.value, {
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      sourceRunId: observation.runId,
      sourceRunAttempt: observation.runAttempt,
      releaseEvidenceSetSha256,
      journalLifecycleSha256: lifecycle.lifecycleSha256,
      releaseFenceDocument: documents.releaseFence,
      markerDocument: documents.finalizationMarker,
      earliestUtc:
        Date.parse(observation.observedAtUtc) > Date.parse(rehearsal.completedAtUtc)
          ? observation.observedAtUtc
          : rehearsal.completedAtUtc,
    });
    try {
      validateReleaseSuccessorJournalSnapshot(documents.journalSnapshot.value, {
        reconciliationJournalAuthority: reconciliation.authority,
        rollbackCheckReceipt: documents.reconciliationRollbackCheck.value,
        rollbackResilienceReceipt: documents.reconciliationRollbackResilience.value,
        protectedRun: documents.rollbackProtectedRun.value,
      });
    } catch (error) {
      fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_INVALID', error);
    }
  }
  return {
    documents,
    rawDiff,
    observation,
    config,
    freeze,
    predecessor,
    candidateRecord,
    rehearsal,
    lifecycle,
    preFenceGate,
    reconciliationJournalAuthority: reconciliation.authority,
    reconciliationEvidenceBindings: reconciliation.bindings,
    journalRoleEffectivePermissions,
    reconciliationRecoveryRoleEffectivePermissions:
      reconciliationRecoveryRoleEffectivePermissions.value,
    releaseEvidenceSetSha256,
    evidenceBindings,
    authorityBindings,
    authoritySetSha256,
    releaseFence,
  };
};

export const createReleaseEvidenceSetCommitment = (options) => {
  const validated = parseAndValidateReleaseSources(options, undefined, {
    requireFinalization: false,
  });
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_EVIDENCE_SET_COMMITMENT',
    status: 'PASS',
    repository: REPOSITORY,
    sourceRunId: validated.observation.runId,
    sourceRunAttempt: validated.observation.runAttempt,
    candidateSha: validated.freeze.candidateSha,
    releaseId: validated.freeze.releaseId,
    journalLifecycleSha256: validated.lifecycle.lifecycleSha256,
    releaseEvidenceSetSha256: validated.releaseEvidenceSetSha256,
    awsCliVersion: validated.freeze.toolchain.awsCli,
    awsRegion: validated.config.aws.region,
    evidenceBindings: validated.evidenceBindings,
    releaseFenceSha256: validated.releaseFence.fenceSha256,
    journalCleanupRoleSha256: validated.releaseFence.journalCleanupRoleSha256,
    journalRoleAuthoritySha256: validated.releaseFence.journalRoleAuthoritySha256,
    containsSensitiveData: false,
  };
};

const sourcePayloadDigest = (files) =>
  objectSha256(
    SOURCE_PAYLOAD_FILENAMES.map((pathName) => {
      const bytes = files[pathName];
      if (!Buffer.isBuffer(bytes)) fail('E7_RELEASE_SUCCESSOR_SOURCE_FILE_MISSING');
      return rawEntry(pathName, bytes);
    }),
  );

const sourceIndexBody = (value) => withoutDigest(value, 'indexSha256');
const journalSnapshotBinding = (document) => ({
  path: RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot,
  rawSha256: document.rawSha256,
  canonicalSha256: document.canonicalSha256,
  bytes: document.byteLength,
  snapshotSha256: document.value.snapshotSha256,
  targetNameSetSha256: document.value.targetNameSetSha256,
  entryCount: document.value.entryCount,
});
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

export const validateReleaseSuccessorSourceIndex = (value, { provenance } = {}) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'artifactName',
      'sourceRunId',
      'sourceRunAttempt',
      'sourceHeadSha',
      'sourceReleaseId',
      'sourceProvenanceSha256',
      'reconciliationJournalAuthoritySha256',
      'releaseFenceAuthoritySetSha256',
      'journalSnapshotBinding',
      'files',
      'immutable',
      'targetCandidateBound',
      'targetFreezeManifestSha256',
      'containsSensitiveData',
      'createdAtUtc',
      'bundleSha256',
      'indexSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_SUCCESSOR_SOURCE_BUNDLE' ||
    value.status !== 'RELEASE_N_POST_SUCCESS_VALIDATED' ||
    value.artifactName !== RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    value.sourceRunAttempt !== 1 ||
    !SHA.test(value.sourceHeadSha ?? '') ||
    !RELEASE_ID.test(value.sourceReleaseId ?? '') ||
    !SHA256.test(value.sourceProvenanceSha256 ?? '') ||
    !SHA256.test(value.reconciliationJournalAuthoritySha256 ?? '') ||
    !SHA256.test(value.releaseFenceAuthoritySetSha256 ?? '') ||
    !validateJournalSnapshotBinding(value.journalSnapshotBinding) ||
    !Array.isArray(value.files) ||
    value.files.length !== SOURCE_PAYLOAD_FILENAMES.length + 1 ||
    value.files.map(({ path: pathName } = {}) => pathName).join('\0') !==
      [...SOURCE_PAYLOAD_FILENAMES, RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance].join('\0') ||
    value.files.some((entry) => !validateRawEntry(entry)) ||
    value.immutable !== true ||
    value.targetCandidateBound !== false ||
    value.targetFreezeManifestSha256 !== null ||
    value.containsSensitiveData !== false ||
    !utc(value.createdAtUtc) ||
    !SHA256.test(value.bundleSha256 ?? '') ||
    value.indexSha256 !== objectSha256(sourceIndexBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_INDEX_INVALID');
  }
  if (provenance !== undefined) {
    validateReleaseSuccessorSourceProvenance(provenance);
    if (
      value.sourceRunId !== provenance.sourceRunId ||
      value.sourceRunAttempt !== provenance.sourceRunAttempt ||
      value.sourceHeadSha !== provenance.headSha ||
      value.sourceReleaseId !== provenance.releaseId ||
      value.sourceProvenanceSha256 !== objectSha256(provenance) ||
      value.reconciliationJournalAuthoritySha256 !==
        provenance.reconciliationJournalAuthoritySha256 ||
      value.releaseFenceAuthoritySetSha256 !== provenance.releaseFenceAuthoritySetSha256 ||
      canonicalJson(value.journalSnapshotBinding) !==
        canonicalJson(provenance.journalSnapshotBinding) ||
      value.bundleSha256 !== provenance.bundleSha256
    ) {
      fail('E7_RELEASE_SUCCESSOR_SOURCE_INDEX_PROVENANCE_MISMATCH');
    }
  }
  return value;
};

const createSourceFiles = (validated) => {
  const {
    documents,
    rawDiff,
    observation,
    freeze,
    rehearsal,
    lifecycle,
    reconciliationJournalAuthority,
    reconciliationEvidenceBindings,
    authoritySetSha256,
  } = validated;
  const apiContract = createApiContractEvidence({
    freeze,
    apiDeployment: documents.apiDeployment,
    observedAtUtc: observation.observedAtUtc,
  });
  const pendingReconciliation = createPendingReconciliationEvidence({
    freeze,
    pendingProducer: documents.pendingProducer,
    rollbackCompletion: documents.rollbackCompletion,
    rehearsal,
  });
  const smoke = createSmokeEvidence({
    freeze,
    postdeploySmoke: documents.postdeploySmoke,
    repromotionSmoke: documents.repromotionSmoke,
    rollbackCompletion: documents.rollbackCompletion,
    rehearsal,
  });
  validateApiContractEvidence(apiContract, {
    freeze,
    apiDeployment: documents.apiDeployment,
    observedAtUtc: observation.observedAtUtc,
  });
  validatePendingReconciliationEvidence(pendingReconciliation, {
    freeze,
    pendingProducer: documents.pendingProducer,
    rollbackCompletion: documents.rollbackCompletion,
    rehearsal,
  });
  validateSmokeEvidence(smoke, {
    freeze,
    postdeploySmoke: documents.postdeploySmoke,
    repromotionSmoke: documents.repromotionSmoke,
    rollbackCompletion: documents.rollbackCompletion,
    rehearsal,
  });
  const files = {
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.observation]: documents.observation.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.releaseMetadata]: documents.releaseMetadata.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.stage6Closeout]: documents.stage6Closeout.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.config]: documents.config.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.freeze]: documents.freeze.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessor]: documents.predecessor.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorSourceProvenance]:
      documents.predecessorSourceProvenance.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorTargetCompatibility]:
      documents.predecessorTargetCompatibility.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorFinalDisable]:
      documents.predecessorFinalDisable.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorApiContract]:
      documents.predecessorApiContract.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorPending]: documents.predecessorPending.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorSmoke]: documents.predecessorSmoke.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorProjectionIndex]:
      documents.predecessorProjectionIndex.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.candidateRecord]: documents.candidateRecord.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.emergencyRecovery]: documents.emergencyRecovery.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.emergencyRecoveryNoActionOutcome]:
      documents.emergencyRecoveryNoActionOutcome.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.approvedPlan]: documents.approvedPlan.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.rawDiff]: rawDiff.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.githubApproval]: documents.githubApproval.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.approval]: documents.approval.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.activation]: documents.activation.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.drift]: documents.drift.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollback]: documents.rollback.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackSourceBinding]: documents.rollbackSourceBinding.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackProtectedRun]: documents.rollbackProtectedRun.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackCompletion]: documents.rollbackCompletion.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackInputs]: documents.rollbackInputs.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackRb06]: documents.rb06Descriptor.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackRb08]: documents.rb08Descriptor.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.releaseManifest]: documents.releaseManifest.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenanceLedger]: documents.provenanceLedger.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.closeout]: documents.closeout.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.releaseHandoff]: documents.releaseHandoff.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.publicationPreparation]:
      documents.publicationPreparation.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.publicationPlan]: documents.publicationPlan.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.publicationTargetProof]:
      documents.publicationTargetProof.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.publicationOperation]: documents.publicationOperation.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.publicationProof]: documents.publicationProof.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.apiDeployment]: documents.apiDeployment.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.pendingProducer]: documents.pendingProducer.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.postdeploySmoke]: documents.postdeploySmoke.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.repromotionSmoke]: documents.repromotionSmoke.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.releaseFence]: documents.releaseFence.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackCheck]:
      documents.reconciliationRollbackCheck.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackResilience]:
      documents.reconciliationRollbackResilience.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.preFenceGate]: documents.preFenceGate.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.awsAuth]: documents.awsAuth.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalRoleEffectivePermissions]:
      documents.journalRoleEffectivePermissions.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRecoveryRoleEffectivePermissions]:
      documents.reconciliationRecoveryRoleEffectivePermissions.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalizationMarker]: documents.finalizationMarker.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalDisable]: documents.finalDisable.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot]: documents.journalSnapshot.bytes,
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.apiContract]: jsonBytes(apiContract),
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.pendingReconciliation]: jsonBytes(pendingReconciliation),
    [RELEASE_SUCCESSOR_SOURCE_LAYOUT.smoke]: jsonBytes(smoke),
  };
  const parsedByPath = Object.fromEntries(
    Object.entries(files)
      .filter(([name]) => name !== RELEASE_SUCCESSOR_SOURCE_LAYOUT.rawDiff)
      .map(([name, bytes]) => [
        name,
        strictJsonDocument(bytes, 'E7_RELEASE_SUCCESSOR_GENERATED_SOURCE_INVALID'),
      ]),
  );
  const artifactOriginsByPath = Object.fromEntries(
    SOURCE_PAYLOAD_FILENAMES.map((name) => {
      const key = Object.entries(RELEASE_SUCCESSOR_SOURCE_LAYOUT).find(
        ([, value]) => value === name,
      )?.[0];
      if (key === 'observation') return [name, 'GITHUB_POST_SUCCESS_OBSERVATION'];
      if (key === 'config') return [name, 'PROTECTED_CURRENT_RELEASE_CONFIG'];
      if (['releaseFence', 'finalizationMarker', 'finalDisable'].includes(key)) {
        return [name, 'POST_SUCCESS_AWS_FINALIZATION'];
      }
      if (key === 'journalSnapshot') return [name, 'POST_SUCCESS_SSM_JOURNAL_SNAPSHOT'];
      if (['apiContract', 'pendingReconciliation', 'smoke'].includes(key)) {
        return [name, 'POST_SUCCESS_DERIVED'];
      }
      if (
        observation.kind === 'RELEASE_SUCCESSOR_COMPOSITE_RECOVERY_RUN_OBSERVATION' &&
        [
          'publicationPreparation',
          'publicationPlan',
          'publicationTargetProof',
          'publicationOperation',
          'publicationProof',
          'releaseFence',
        ].includes(key)
      ) {
        return [name, 'RECOVERY_RESULT_SUPPLEMENT'];
      }
      if (
        observation.kind === 'RELEASE_SUCCESSOR_COMPOSITE_RECOVERY_RUN_OBSERVATION' &&
        ['releaseManifest', 'provenanceLedger', 'closeout', 'releaseHandoff'].includes(key)
      ) {
        return [name, 'POST_SUCCESS_COMPOSITE_RECOVERY_CLOSEOUT'];
      }
      return [name, DOCUMENT_ARTIFACT_ORIGIN[key]];
    }),
  );
  const bundleSha256 = sourcePayloadDigest(files);
  const provenanceBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_SOURCE_PROVENANCE',
    status: 'PASS',
    artifactName: RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
    repository: REPOSITORY,
    workflowPath: RELEASE_SUCCESSOR_WORKFLOW_PATH,
    sourceEvent: observation.event,
    sourceRef: observation.ref,
    sourceRunId: observation.runId,
    sourceRunAttempt: observation.runAttempt,
    headSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    releaseTag: freeze.releaseTag,
    sourceKind:
      observation.kind === 'RELEASE_SUCCESSOR_COMPOSITE_RECOVERY_RUN_OBSERVATION'
        ? 'RELEASE_SUCCESSOR_POST_SUCCESS_COMPOSITE_RECOVERY'
        : 'RELEASE_SUCCESSOR_POST_SUCCESS',
    predecessorManifestSha256: validated.predecessor.manifestSha256,
    candidateRecordSha256: validated.candidateRecord.recordSha256,
    rollbackRehearsalSha256: rehearsal.rehearsalSha256,
    journalLifecycleSha256: lifecycle.lifecycleSha256,
    reconciliationJournalAuthority,
    reconciliationJournalAuthoritySha256: reconciliationJournalAuthority.journalAuthoritySha256,
    reconciliationEvidenceBindings,
    releaseFenceAuthoritySetSha256: authoritySetSha256,
    journalSnapshotBinding: journalSnapshotBinding(documents.journalSnapshot),
    releaseEvidenceSetSha256: validated.releaseEvidenceSetSha256,
    finalDisableEvidenceSha256: objectSha256(documents.finalDisable.value),
    files: SOURCE_PAYLOAD_FILENAMES.map((name) => rawEntry(name, files[name])),
    canonicalSha256ByPath: Object.fromEntries(
      SOURCE_PAYLOAD_FILENAMES.filter(
        (name) => name !== RELEASE_SUCCESSOR_SOURCE_LAYOUT.rawDiff,
      ).map((name) => [name, parsedByPath[name].canonicalSha256]),
    ),
    artifactOriginsByPath,
    bundleSha256,
    capturedAtUtc: documents.finalDisable.value.completedAtUtc,
    externalRequests: observation.externalRequests,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const provenance = validateReleaseSuccessorSourceProvenance({
    ...provenanceBody,
    provenanceSha256: objectSha256(provenanceBody),
  });
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance] = jsonBytes(provenance);
  const indexBody = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_SUCCESSOR_SOURCE_BUNDLE',
    status: 'RELEASE_N_POST_SUCCESS_VALIDATED',
    artifactName: RELEASE_SUCCESSOR_SOURCE_ARTIFACT_NAME,
    sourceRunId: observation.runId,
    sourceRunAttempt: observation.runAttempt,
    sourceHeadSha: freeze.candidateSha,
    sourceReleaseId: freeze.releaseId,
    sourceProvenanceSha256: objectSha256(provenance),
    reconciliationJournalAuthoritySha256: reconciliationJournalAuthority.journalAuthoritySha256,
    releaseFenceAuthoritySetSha256: authoritySetSha256,
    journalSnapshotBinding: journalSnapshotBinding(documents.journalSnapshot),
    files: [...SOURCE_PAYLOAD_FILENAMES, RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance].map((name) =>
      rawEntry(name, files[name]),
    ),
    immutable: true,
    targetCandidateBound: false,
    targetFreezeManifestSha256: null,
    containsSensitiveData: false,
    createdAtUtc: documents.finalDisable.value.completedAtUtc,
    bundleSha256,
  };
  const index = validateReleaseSuccessorSourceIndex(
    { ...indexBody, indexSha256: objectSha256(indexBody) },
    { provenance },
  );
  files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.index] = jsonBytes(index);
  return { files, index, provenance, apiContract, pendingReconciliation, smoke };
};

export const createReleaseSuccessorSourceBundle = (options) =>
  createSourceFiles(parseAndValidateReleaseSources(options));

const exactDirectoryFiles = (directory, expected, code) => {
  const names = readdirSync(directory, { withFileTypes: true });
  if (
    names.some((entry) => !entry.isFile()) ||
    names
      .map(({ name }) => name)
      .toSorted()
      .join('\0') !== [...expected].toSorted().join('\0')
  ) {
    fail(code);
  }
};

export const writeReleaseSuccessorSourceBundle = ({ outputDirectory, options }) => {
  if (existsSync(outputDirectory)) fail('E7_RELEASE_SUCCESSOR_OUTPUT_EXISTS');
  const bundle = createReleaseSuccessorSourceBundle(options);
  mkdirSync(outputDirectory, { recursive: false, mode: 0o700 });
  try {
    for (const [name, bytes] of Object.entries(bundle.files)) {
      writeFileSync(path.join(outputDirectory, name), bytes, { flag: 'wx', mode: 0o600 });
    }
    return validateReleaseSuccessorSourceBundleDirectory(outputDirectory);
  } catch (error) {
    rmSync(outputDirectory, { recursive: true, force: true });
    throw error;
  }
};

export const validateReleaseSuccessorSourceBundleDirectory = (directory) => {
  exactDirectoryFiles(
    directory,
    Object.values(RELEASE_SUCCESSOR_SOURCE_LAYOUT),
    'E7_RELEASE_SUCCESSOR_SOURCE_FILE_SET_INVALID',
  );
  const files = Object.fromEntries(
    Object.values(RELEASE_SUCCESSOR_SOURCE_LAYOUT).map((name) => [
      name,
      readFileSync(path.join(directory, name)),
    ]),
  );
  const provenanceDocument = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.provenance],
    'E7_RELEASE_SUCCESSOR_SOURCE_PROVENANCE_FILE_INVALID',
  );
  const indexDocument = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.index],
    'E7_RELEASE_SUCCESSOR_SOURCE_INDEX_FILE_INVALID',
  );
  const provenance = validateReleaseSuccessorSourceProvenance(provenanceDocument.value);
  const index = validateReleaseSuccessorSourceIndex(indexDocument.value, { provenance });
  for (const entry of index.files) {
    const bytes = files[entry.path];
    if (!Buffer.isBuffer(bytes) || sha256(bytes) !== entry.sha256 || bytes.length !== entry.bytes) {
      fail('E7_RELEASE_SUCCESSOR_SOURCE_RAW_DIGEST_MISMATCH');
    }
  }
  if (
    sourcePayloadDigest(files) !== index.bundleSha256 ||
    sourcePayloadDigest(files) !== provenance.bundleSha256 ||
    provenanceDocument.canonicalSha256 !== index.sourceProvenanceSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_BUNDLE_DIGEST_MISMATCH');
  }
  for (const [pathName, digest] of Object.entries(provenance.canonicalSha256ByPath)) {
    const document = strictJsonDocument(
      files[pathName],
      'E7_RELEASE_SUCCESSOR_SOURCE_DOCUMENT_INVALID',
    );
    const raw = provenance.files.find((entry) => entry.path === pathName);
    if (
      document.canonicalSha256 !== digest ||
      document.rawSha256 !== raw?.sha256 ||
      document.byteLength !== raw?.bytes
    ) {
      fail('E7_RELEASE_SUCCESSOR_SOURCE_CANONICAL_DIGEST_MISMATCH');
    }
  }
  const observation = validateReleaseSuccessorRunObservation(
    strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.observation],
      'E7_RELEASE_SUCCESSOR_SOURCE_OBSERVATION_INVALID',
    ).value,
    {
      runId: provenance.sourceRunId,
      runAttempt: provenance.sourceRunAttempt,
      headSha: provenance.headSha,
    },
  );
  const identityDocuments = {
    config: strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.config],
      'E7_RELEASE_SUCCESSOR_SOURCE_CONFIG_INVALID',
    ),
    freeze: strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.freeze],
      'E7_RELEASE_SUCCESSOR_SOURCE_FREEZE_INVALID',
    ),
    predecessor: strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessor],
      'E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_INVALID',
    ),
    candidateRecord: strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.candidateRecord],
      'E7_RELEASE_SUCCESSOR_SOURCE_CANDIDATE_INVALID',
    ),
  };
  let config;
  let freeze;
  let predecessor;
  let candidateRecord;
  try {
    config = validateStage7Config(identityDocuments.config.value, {
      now: new Date(identityDocuments.config.value.window.startsAtUtc),
    });
    freeze = validateFreezeManifest(identityDocuments.freeze.value);
    predecessor = validateStage7PreviousReleaseManifest(identityDocuments.predecessor.value);
    candidateRecord = validateStage7CandidateRollbackRecord(
      identityDocuments.candidateRecord.value,
      { previousManifest: predecessor },
    );
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_IDENTITY_INVALID', error);
  }
  try {
    const predecessorSourceProvenance = strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorSourceProvenance],
      'E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_PROVENANCE_INVALID',
    );
    const predecessorTargetCompatibility = strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorTargetCompatibility],
      'E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_COMPATIBILITY_INVALID',
    );
    const predecessorFinalDisable = strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorFinalDisable],
      'E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_FINAL_DISABLE_INVALID',
    );
    validateStage7PreviousReleaseHandoff(predecessor, {
      sourceProvenance: predecessorSourceProvenance.value,
      targetCompatibility: predecessorTargetCompatibility.value,
      finalDisableProvenance: predecessorFinalDisable.value,
    });
    validatePreviousReleaseProjectionIndex(
      strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorProjectionIndex],
        'E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_INDEX_INVALID',
      ).value,
      {
        previousReleaseManifest: predecessor,
        files: {
          'previous-release-manifest.json': files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessor],
          'previous-source-provenance.json':
            files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorSourceProvenance],
          'previous-target-compatibility.json':
            files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorTargetCompatibility],
          'previous-final-disable-provenance.json':
            files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorFinalDisable],
          'previous-api-contract-evidence.json':
            files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorApiContract],
          'previous-pending-evidence.json':
            files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorPending],
          'previous-smoke-evidence.json': files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorSmoke],
        },
      },
    );
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_PROJECTION_INVALID', error);
  }
  if (
    freeze.candidateSha !== observation.headSha ||
    predecessor.target.candidateSha !== freeze.candidateSha ||
    predecessor.target.releaseId !== freeze.releaseId ||
    predecessor.target.freezeManifestSha256 !== freeze.manifestSha256 ||
    candidateRecord.target.candidateSha !== freeze.candidateSha ||
    provenance.predecessorManifestSha256 !== predecessor.manifestSha256 ||
    provenance.candidateRecordSha256 !== candidateRecord.recordSha256 ||
    provenance.finalDisableEvidenceSha256 !==
      objectSha256(
        strictJsonDocument(
          files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalDisable],
          'E7_RELEASE_SUCCESSOR_SOURCE_FINAL_DISABLE_INVALID',
        ).value,
      )
  ) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_MISMATCH');
  }
  try {
    const awsAuthAuthorityDocument = strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.awsAuth],
      'E7_RELEASE_SUCCESSOR_SOURCE_AWS_AUTH_INVALID',
    );
    validateReleaseJournalRoleEffectivePermissionsBinding({
      awsAuthSource: awsAuthAuthorityDocument.bytes,
      effectivePermissionsSource:
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalRoleEffectivePermissions],
      expected: {
        candidateSha: freeze.candidateSha,
        releaseId: freeze.releaseId,
        configSha256: freeze.configSha256,
        manifestSha256: freeze.manifestSha256,
      },
    });
    const recoveryAuthority = parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRecoveryRoleEffectivePermissions],
      {
        roleArn: awsAuthAuthorityDocument.value.reconciliationRecoveryRoleArn,
        permissionsBoundaryArn:
          awsAuthAuthorityDocument.value.reconciliationRecoveryPermissionsBoundaryArn,
      },
    );
    if (
      awsAuthAuthorityDocument.value.reconciliationRecoveryRoleEffectivePermissionsRawSha256 !==
        recoveryAuthority.rawSha256 ||
      awsAuthAuthorityDocument.value
        .reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256 !==
        recoveryAuthority.canonicalSha256 ||
      awsAuthAuthorityDocument.value.reconciliationRecoveryRoleEffectivePermissionsSha256 !==
        recoveryAuthority.value.effectivePermissionsSha256 ||
      awsAuthAuthorityDocument.value.reconciliationRecoveryRoleEffectivePolicyProjectionSha256 !==
        recoveryAuthority.value.effectivePolicyProjectionSha256
    ) {
      fail('E7_RELEASE_SUCCESSOR_SOURCE_RECOVERY_ROLE_AUTHORITY_INVALID');
    }
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_AUXILIARY_ROLE_AUTHORITY_INVALID', error);
  }
  validateReleaseSuccessorEmergencyRecoveryNoAction({
    documents: {
      ...identityDocuments,
      predecessorApiContract: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorApiContract],
        'E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_API_INVALID',
      ),
      predecessorPending: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorPending],
        'E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_PENDING_INVALID',
      ),
      predecessorSmoke: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.predecessorSmoke],
        'E7_RELEASE_SUCCESSOR_SOURCE_PREDECESSOR_SMOKE_INVALID',
      ),
      emergencyRecovery: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.emergencyRecovery],
        'E7_RELEASE_SUCCESSOR_SOURCE_EMERGENCY_RECOVERY_INVALID',
      ),
      emergencyRecoveryNoActionOutcome: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.emergencyRecoveryNoActionOutcome],
        'E7_RELEASE_SUCCESSOR_SOURCE_EMERGENCY_RECOVERY_OUTCOME_INVALID',
      ),
      approval: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.approval],
        'E7_RELEASE_SUCCESSOR_SOURCE_APPROVAL_INVALID',
      ),
      awsAuth: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.awsAuth],
        'E7_RELEASE_SUCCESSOR_SOURCE_AWS_AUTH_INVALID',
      ),
      journalRoleEffectivePermissions: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalRoleEffectivePermissions],
        'E7_RELEASE_SUCCESSOR_SOURCE_JOURNAL_ROLE_AUTHORITY_INVALID',
      ),
      approvedPlan: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.approvedPlan],
        'E7_RELEASE_SUCCESSOR_SOURCE_PLAN_INVALID',
      ),
      rollbackInputs: strictJsonDocument(
        files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackInputs],
        'E7_RELEASE_SUCCESSOR_SOURCE_ROLLBACK_INPUTS_INVALID',
      ),
    },
    config,
    freeze,
    predecessor,
    candidateRecord,
    sourceRunId: provenance.sourceRunId,
  });
  const apiDeployment = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.apiDeployment],
    'E7_RELEASE_SUCCESSOR_SOURCE_API_DEPLOYMENT_INVALID',
  );
  const rollbackCompletion = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackCompletion],
    'E7_RELEASE_SUCCESSOR_SOURCE_COMPLETION_INVALID',
  );
  const pendingProducer = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.pendingProducer],
    'E7_RELEASE_SUCCESSOR_SOURCE_PENDING_PRODUCER_INVALID',
  );
  const postdeploySmoke = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.postdeploySmoke],
    'E7_RELEASE_SUCCESSOR_SOURCE_POSTDEPLOY_SMOKE_INVALID',
  );
  const repromotionSmoke = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.repromotionSmoke],
    'E7_RELEASE_SUCCESSOR_SOURCE_REPROMOTION_SMOKE_INVALID',
  );
  const rehearsal = rollbackCompletion.value.versionedRollbackRehearsal;
  const releaseFenceDocument = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.releaseFence],
    'E7_RELEASE_SUCCESSOR_SOURCE_RELEASE_FENCE_INVALID',
  );
  const reconciliation = validateReleaseSuccessorReconciliationAuthoritySources({
    rollbackCheckSource: files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackCheck],
    rollbackResilienceSource:
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.reconciliationRollbackResilience],
    preFenceGateSource: files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.preFenceGate],
    expected: {
      sourceRunId: provenance.sourceRunId,
      sourceRunAttempt: provenance.sourceRunAttempt,
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      releaseTag: freeze.releaseTag,
    },
  });
  const preFenceGateDocument = reconciliation.preFenceGate;
  const preFenceGate = reconciliation.gate;
  const protectedRunDocument = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.rollbackProtectedRun],
    'E7_RELEASE_SUCCESSOR_SOURCE_PROTECTED_RUN_INVALID',
  );
  const journalSnapshotDocument = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.journalSnapshot],
    'E7_RELEASE_SUCCESSOR_SOURCE_JOURNAL_SNAPSHOT_INVALID',
  );
  validateReleaseSuccessorJournalSnapshot(journalSnapshotDocument.value, {
    reconciliationJournalAuthority: reconciliation.authority,
    rollbackCheckReceipt: reconciliation.rollbackCheck.value,
    rollbackResilienceReceipt: reconciliation.rollbackResilience.value,
    protectedRun: protectedRunDocument.value,
  });
  const expectedJournalSnapshotBinding = journalSnapshotBinding(journalSnapshotDocument);
  const markerDocument = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalizationMarker],
    'E7_RELEASE_SUCCESSOR_SOURCE_FINALIZATION_MARKER_INVALID',
  );
  const finalDisableDocument = strictJsonDocument(
    files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.finalDisable],
    'E7_RELEASE_SUCCESSOR_SOURCE_FINAL_DISABLE_INVALID',
  );
  const fenceAuthoritySet = releaseSuccessorFenceAuthoritySetFromSourceFiles(files);
  const releaseFence = validateReleaseSuccessorCompletionFence(releaseFenceDocument.value, {
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    sourceRunId: provenance.sourceRunId,
    sourceRunAttempt: provenance.sourceRunAttempt,
    journalLifecycleSha256: provenance.journalLifecycleSha256,
    evidenceBindings: {
      ...releaseFenceDocument.value.evidenceBindings,
      preFenceGate: {
        rawSha256: preFenceGateDocument.rawSha256,
        canonicalSha256: preFenceGateDocument.canonicalSha256,
        bytes: preFenceGateDocument.byteLength,
      },
    },
    authorityBindings: fenceAuthoritySet.authorityBindings,
    authoritySetSha256: fenceAuthoritySet.authoritySetSha256,
  });
  if (
    preFenceGate.source.runId !== provenance.sourceRunId ||
    preFenceGate.source.candidateSha !== freeze.candidateSha ||
    preFenceGate.source.releaseId !== freeze.releaseId ||
    provenance.reconciliationJournalAuthoritySha256 !==
      reconciliation.authority.journalAuthoritySha256 ||
    canonicalJson(provenance.reconciliationJournalAuthority) !==
      canonicalJson(reconciliation.authority) ||
    canonicalJson(provenance.reconciliationEvidenceBindings) !==
      canonicalJson(reconciliation.bindings) ||
    index.reconciliationJournalAuthoritySha256 !==
      reconciliation.authority.journalAuthoritySha256 ||
    provenance.releaseFenceAuthoritySetSha256 !== fenceAuthoritySet.authoritySetSha256 ||
    index.releaseFenceAuthoritySetSha256 !== fenceAuthoritySet.authoritySetSha256 ||
    canonicalJson(provenance.journalSnapshotBinding) !==
      canonicalJson(expectedJournalSnapshotBinding) ||
    canonicalJson(index.journalSnapshotBinding) !== canonicalJson(expectedJournalSnapshotBinding)
  ) {
    fail('E7_RELEASE_SUCCESSOR_SOURCE_RECONCILIATION_IDENTITY_INVALID');
  }
  validateReleaseSuccessorFinalizationMarker(markerDocument.value, {
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    sourceRunId: provenance.sourceRunId,
    sourceRunAttempt: provenance.sourceRunAttempt,
    releaseEvidenceSetSha256: provenance.releaseEvidenceSetSha256,
    journalLifecycleSha256: provenance.journalLifecycleSha256,
    releaseFenceSha256: releaseFence.fenceSha256,
    journalRoleAuthoritySha256: markerDocument.value.journalRoleAuthoritySha256,
  });
  validateReleaseSuccessorFinalDisableProvenance(finalDisableDocument.value, {
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    sourceRunId: provenance.sourceRunId,
    sourceRunAttempt: provenance.sourceRunAttempt,
    journalLifecycleSha256: provenance.journalLifecycleSha256,
    releaseFenceDocument,
    markerDocument,
    earliestUtc: provenance.capturedAtUtc,
  });
  validateApiContractEvidence(
    strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.apiContract],
      'E7_RELEASE_SUCCESSOR_SOURCE_API_CONTRACT_INVALID',
    ).value,
    { freeze, apiDeployment, observedAtUtc: observation.observedAtUtc },
  );
  validatePendingReconciliationEvidence(
    strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.pendingReconciliation],
      'E7_RELEASE_SUCCESSOR_SOURCE_PENDING_INVALID',
    ).value,
    { freeze, pendingProducer, rollbackCompletion, rehearsal },
  );
  validateSmokeEvidence(
    strictJsonDocument(
      files[RELEASE_SUCCESSOR_SOURCE_LAYOUT.smoke],
      'E7_RELEASE_SUCCESSOR_SOURCE_SMOKE_INVALID',
    ).value,
    { freeze, postdeploySmoke, repromotionSmoke, rollbackCompletion, rehearsal },
  );
  return { files, index, provenance, observation, freeze, predecessor, candidateRecord };
};

const consumptionAuthorityBody = (value) => withoutDigest(value, 'consumptionAuthoritySha256');

export const validateReleaseSuccessorConsumptionAuthority = (value, expected = {}) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'sourceRunId',
      'headSha',
      'postSuccessRunId',
      'postSuccessRunAttempt',
      'sourcePreservationRunAttempt',
      'sourceArtifact',
      'preservationArtifact',
      'cleanupArtifact',
      'preservationReceiptSha256',
      'cleanupReceiptSha256',
      'postSuccessObservationSha256',
      'artifactInventorySha256',
      'containsSensitiveData',
      'consumptionAuthoritySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_CONSUMPTION_AUTHORITY' ||
    value.status !== 'SAME_POST_SUCCESS_RUN_VERIFIED' ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    !SHA.test(value.headSha ?? '') ||
    !RUN_ID.test(value.postSuccessRunId ?? '') ||
    normalizedRunAttempt(value.postSuccessRunAttempt) === null ||
    normalizedRunAttempt(value.sourcePreservationRunAttempt) === null ||
    value.sourcePreservationRunAttempt > value.postSuccessRunAttempt ||
    !['sourceArtifact', 'preservationArtifact', 'cleanupArtifact'].every((key) => {
      const artifact = value[key];
      return (
        exactKeys(artifact, ['attempt', 'id', 'digest', 'archiveRawSha256', 'payloadRawSha256']) &&
        normalizedRunAttempt(artifact.attempt) !== null &&
        Number.isSafeInteger(artifact.id) &&
        artifact.id > 0 &&
        ARTIFACT_DIGEST.test(artifact.digest ?? '') &&
        artifact.archiveRawSha256 === artifact.digest.slice('sha256:'.length) &&
        SHA256.test(artifact.payloadRawSha256 ?? '')
      );
    }) ||
    value.sourceArtifact.attempt !== value.sourcePreservationRunAttempt ||
    value.preservationArtifact.attempt !== value.sourcePreservationRunAttempt ||
    value.cleanupArtifact.attempt !== value.postSuccessRunAttempt ||
    ![
      value.preservationReceiptSha256,
      value.cleanupReceiptSha256,
      value.postSuccessObservationSha256,
      value.artifactInventorySha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    value.containsSensitiveData !== false ||
    value.consumptionAuthoritySha256 !== objectSha256(consumptionAuthorityBody(value)) ||
    (expected.sourceRunId !== undefined && value.sourceRunId !== expected.sourceRunId) ||
    (expected.headSha !== undefined && value.headSha !== expected.headSha)
  ) {
    fail('E7_RELEASE_SUCCESSOR_CONSUMPTION_AUTHORITY_INVALID');
  }
  return value;
};

export const selfTestReleaseSuccessorCompositeRecoveryObservation = async () => {
  const { createPublicationRecoveryPostSuccessFixture } =
    await import('./release-successor-publication-recovery-self-test.mjs');
  const recoveryHeadSha = 'b'.repeat(40);
  const postSuccessRunId = '7004';
  const authorizedAtUtc = '2026-08-18T14:01:00.000Z';
  const authorityFixture = (crashWindow) => {
    const fixture = createPublicationRecoveryPostSuccessFixture({ crashWindow });
    const intake = createPublicationRecoveryPostSuccessIntake(fixture.intakeArguments);
    const sourceConclusion = (id) => {
      if (id === 'summary') return 'failure';
      if (id === 'release-successor-fence' && crashWindow === RECOVERY_CRASH_WINDOWS[0]) {
        return 'failure';
      }
      if (id === 'publish-release') {
        if (crashWindow === RECOVERY_CRASH_WINDOWS[0]) return 'skipped';
        if (crashWindow === RECOVERY_CRASH_WINDOWS[1]) return 'failure';
      }
      return 'success';
    };
    const authority = createReleaseSuccessorRecoveryCloseoutAuthority({
      intake,
      recoveryHeadSha,
      sourceJobsSource: jsonBytes({
        total_count: RELEASE_SUCCESSOR_SOURCE_JOBS.length,
        jobs: RELEASE_SUCCESSOR_SOURCE_JOBS.map(({ id, name }, index) => ({
          id:
            id === 'release-successor-fence'
              ? Number(fixture.plan.source.fenceJob.id)
              : id === 'publish-release'
                ? Number(fixture.plan.source.publicationJob.id)
                : id === 'summary'
                  ? Number(fixture.plan.source.summaryJob.id)
                  : 9200 + index,
          run_id: Number(intake.source.runId),
          run_attempt: 1,
          name,
          status: 'completed',
          conclusion: sourceConclusion(id),
        })),
      }),
      recoveryJobsSource: jsonBytes({
        total_count: 3,
        jobs: [
          {
            id: 9101,
            run_id: Number(intake.recovery.runId),
            run_attempt: 1,
            name: 'Validate isolated publication recovery contract',
            status: 'completed',
            conclusion: 'success',
          },
          {
            id: 9102,
            run_id: Number(intake.recovery.runId),
            run_attempt: 1,
            name: 'Preflight exact crash window under read-only GitHub authority',
            status: 'completed',
            conclusion: 'success',
          },
          {
            id: 9103,
            run_id: Number(intake.recovery.runId),
            run_attempt: 1,
            name: 'Forward-only A or B publication under write authority',
            status: 'completed',
            conclusion: crashWindow === RECOVERY_CRASH_WINDOWS[2] ? 'skipped' : 'success',
          },
        ],
      }),
      triggerSource: jsonBytes({
        action: 'completed',
        repository: { full_name: REPOSITORY },
        workflow_run: {
          id: Number(intake.recovery.runId),
          run_attempt: 1,
          name: 'Stage 7 Release Successor Publication Recovery',
          event: 'workflow_dispatch',
          head_branch: 'master',
          head_sha: recoveryHeadSha,
          status: 'completed',
          conclusion: 'success',
        },
      }),
      approvalResponseSource: jsonBytes([
        {
          state: 'approved',
          comment:
            `STAGE7_PUBLICATION_RECOVERY_CLOSEOUT source=${intake.source.runId} ` +
            `recovery=${intake.recovery.runId} receipt=${intake.bindings.receiptSha256}`,
          environments: [
            {
              id: 1,
              name: 'assessment-release-successor-post-success',
              url:
                `https://api.github.com/repos/${REPOSITORY}/environments/` +
                'assessment-release-successor-post-success',
            },
          ],
          user: { id: 2, login: 'release-operator', type: 'User' },
        },
      ]),
      planArchive: fixture.planArchive,
      resultArchive: fixture.resultArchive,
      context: {
        repository: REPOSITORY,
        runId: postSuccessRunId,
        runAttempt: 2,
        workflowName: 'Stage 7 Release Successor Post-Success',
        workflowPath: RELEASE_SUCCESSOR_POST_SUCCESS_WORKFLOW_PATH,
        eventName: 'workflow_run',
        headSha: recoveryHeadSha,
        protectedEnvironment: 'assessment-release-successor-post-success',
        githubActions: 'true',
      },
      authorizedAtUtc,
    });
    return { fixture, intake, authority };
  };
  const routeFixtures = RECOVERY_CRASH_WINDOWS.map((crashWindow) => authorityFixture(crashWindow));
  const { fixture, intake, authority } = routeFixtures[2];
  const placeholderEntries = (artifactName) =>
    (EXACT_ARTIFACT_ENTRY_SETS[artifactName] ?? [`${artifactName}.json`])
      .map((pathName) => {
        const bytes = Buffer.from(`${artifactName}:${pathName}\n`, 'utf8');
        return {
          path: pathName,
          sha256: sha256(bytes),
          bytes: bytes.length,
          canonicalSha256: pathName.endsWith('.json')
            ? objectSha256({ artifactName, path: pathName })
            : null,
        };
      })
      .toSorted((left, right) => left.path.localeCompare(right.path));
  const artifacts = fixture.plan.artifactInventory.downloadManifest.map((artifact) => ({
    name: artifact.name,
    origin: 'SOURCE_RUN_ARTIFACT',
    artifactId: artifact.artifactId,
    artifactDigest: artifact.digest,
    containerRawSha256: artifact.digest.slice('sha256:'.length),
    containerBytes: 100,
    entries: placeholderEntries(artifact.name),
    workflowRunId: intake.source.runId,
  }));
  artifacts.push(
    {
      name: 'stage7-publication',
      origin: 'RECOVERY_RESULT_SUPPLEMENT',
      artifactId: intake.recovery.resultArtifactId,
      artifactDigest: intake.recovery.resultArtifactDigest,
      containerRawSha256: intake.recovery.resultArchiveRawSha256,
      containerBytes: fixture.resultArchive.length,
      entries: fixture.receipt.publicationFiles
        .map(({ name: pathName, rawSha256: entrySha256, bytes, canonicalSha256 }) => ({
          path: pathName,
          sha256: entrySha256,
          bytes,
          canonicalSha256,
        }))
        .toSorted((left, right) => left.path.localeCompare(right.path)),
      workflowRunId: intake.recovery.runId,
    },
    {
      name: 'stage7-release-successor-fence',
      origin: 'RECOVERY_RESULT_SUPPLEMENT',
      artifactId: intake.recovery.resultArtifactId,
      artifactDigest: intake.recovery.resultArtifactDigest,
      containerRawSha256: intake.recovery.resultArchiveRawSha256,
      containerBytes: fixture.resultArchive.length,
      entries: [
        {
          path: 'release-successor-completion-fence.json',
          sha256: fixture.plan.fence.parameterValueRawSha256,
          bytes: fixture.fenceSource.length,
          canonicalSha256: fixture.plan.fence.fenceSha256,
        },
      ],
      workflowRunId: intake.recovery.runId,
    },
    ...['stage7-release-authorities', 'stage7-release-reports'].map((name) => ({
      name,
      origin: 'POST_SUCCESS_COMPOSITE_RECOVERY_CLOSEOUT',
      artifactId: null,
      artifactDigest: null,
      containerRawSha256: null,
      containerBytes: 100,
      entries: placeholderEntries(name),
      workflowRunId: postSuccessRunId,
    })),
  );
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_COMPOSITE_RECOVERY_RUN_OBSERVATION',
    status: 'PASS',
    repository: REPOSITORY,
    workflowName: RELEASE_SUCCESSOR_WORKFLOW_NAME,
    workflowPath: RELEASE_SUCCESSOR_WORKFLOW_PATH,
    event: 'workflow_dispatch',
    ref: MASTER_REF,
    headSha: intake.source.candidateSha,
    runId: intake.source.runId,
    runAttempt: intake.source.runAttempt,
    runStatus: 'completed',
    conclusion: intake.source.conclusion,
    recovery: {
      workflowName: authority.recovery.workflowName,
      workflowPath: authority.recovery.workflowPath,
      runId: authority.recovery.runId,
      runAttempt: authority.recovery.runAttempt,
      conclusion: authority.recovery.conclusion,
      headSha: authority.recovery.headSha,
      planArtifactId: authority.recovery.planArtifactId,
      planArtifactName: authority.recovery.planArtifactName,
      planArtifactDigest: authority.recovery.planArtifactDigest,
      planArchiveRawSha256: authority.recovery.planArchiveRawSha256,
      resultArtifactId: authority.recovery.resultArtifactId,
      resultArtifactName: authority.recovery.resultArtifactName,
      resultArtifactDigest: authority.recovery.resultArtifactDigest,
      resultArchiveRawSha256: authority.recovery.resultArchiveRawSha256,
      crashWindow: authority.source.crashWindow,
      executionMode: authority.recovery.executionMode,
      githubPublicationPolicy: authority.recovery.githubPublicationPolicy,
      recoveryGithubWritesPerformed: authority.recovery.recoveryGithubWritesPerformed,
      fenceEvidenceOrigin: authority.recovery.fenceEvidenceOrigin,
      publicationEvidenceOrigin: authority.recovery.publicationEvidenceOrigin,
      canonicalSupplementPolicy: authority.recovery.canonicalSupplementPolicy,
    },
    postSuccess: {
      runId: authority.postSuccess.runId,
      runAttempt: authority.postSuccess.runAttempt,
      workflowName: authority.postSuccess.workflowName,
      workflowPath: authority.postSuccess.workflowPath,
      protectedEnvironment: authority.protectedEnvironment,
      reviewerAlias: authority.postSuccess.reviewerAlias,
    },
    bindings: {
      intakeSha256: intake.intakeSha256,
      closeoutAuthoritySha256: authority.closeoutAuthoritySha256,
      planSha256: authority.bindings.planSha256,
      receiptSha256: authority.bindings.receiptSha256,
      fenceSha256: authority.bindings.fenceSha256,
      publicationAuthoritySha256: authority.bindings.publicationAuthoritySha256,
      idempotencyKey: authority.bindings.idempotencyKey,
      planArtifactDigestSha256: authority.bindings.planArtifactDigestSha256,
      resultArtifactDigestSha256: authority.bindings.resultArtifactDigestSha256,
      sourceArtifactManifestSha256: authority.bindings.sourceArtifactManifestSha256,
      publicationFilesSha256: authority.bindings.publicationFilesSha256,
      sourceInventoryMetadataSha256: authority.bindings.sourceInventoryMetadataSha256,
      sourceInventorySha256: authority.bindings.sourceInventorySha256,
    },
    recoveryIntake: intake,
    recoveryPlan: fixture.plan,
    recoveryReceipt: fixture.receipt,
    closeoutAuthority: authority,
    artifacts: artifacts.toSorted((left, right) => left.name.localeCompare(right.name)),
    observedAtUtc: authorizedAtUtc,
    externalRequests: 38,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const observation = {
    ...body,
    observationSha256: objectSha256(body),
  };
  validateReleaseSuccessorCompositeRecoveryObservation(observation);
  const routeJobResults = routeFixtures.map(({ authority: routeAuthority }) =>
    createCompositeRecoveryJobResultsDocument({ authority: routeAuthority }),
  );
  const compositeJobResults = routeJobResults[2];
  assert.equal(compositeJobResults.status, 'PASS');
  assert.deepEqual(
    routeJobResults.map(({ jobs }) =>
      jobs.filter(({ result }) => result === 'RECOVERED_SUCCESS').map(({ id }) => id),
    ),
    [['release-successor-fence', 'publish-release'], ['publish-release'], []],
  );
  assert.deepEqual(
    routeJobResults.map(({ sourceExecution }) => sourceExecution.conclusion),
    routeFixtures.map(({ intake: routeIntake }) => routeIntake.source.conclusion),
  );
  assert.equal(
    compositeJobResults.jobs.find(({ id }) => id === 'release-successor-fence')?.result,
    'SOURCE_SUCCESS',
  );
  assert.equal(
    compositeJobResults.jobs.find(({ id }) => id === 'publish-release')?.result,
    'SOURCE_SUCCESS',
  );
  assert.equal(
    compositeJobResults.recoveryExecution.jobs.find(({ id }) => id === 'forward-publication')
      ?.conclusion,
    'skipped',
  );
  assert.equal(
    compositeJobResults.sourceExecution.jobs.find(({ id }) => id === 'summary')?.conclusion,
    'failure',
  );
  const rehashAfter = (mutate) => {
    const candidate = JSON.parse(JSON.stringify(observation));
    mutate(candidate);
    candidate.observationSha256 = objectSha256(artifactObservationBody(candidate));
    assert.throws(() => validateReleaseSuccessorCompositeRecoveryObservation(candidate));
  };
  rehashAfter((candidate) => {
    candidate.recovery.workflowPath = '.github/workflows/foreign-recovery.yml';
  });
  rehashAfter((candidate) => {
    candidate.artifacts.find(({ origin }) => origin === 'SOURCE_RUN_ARTIFACT').artifactId =
      '999999';
  });
  rehashAfter((candidate) => {
    candidate.artifacts.find(({ name }) => name === 'stage7-publication').entries[0].sha256 =
      '0'.repeat(64);
  });
  rehashAfter((candidate) => {
    candidate.artifacts.find(
      ({ name }) => name === 'stage7-release-successor-fence',
    ).entries[0].canonicalSha256 = '0'.repeat(64);
  });
  rehashAfter((candidate) => {
    candidate.bindings.sourceInventorySha256 = '0'.repeat(64);
  });
  rehashAfter((candidate) => {
    candidate.postSuccess.runAttempt += 1;
  });
  return {
    status: 'PASS',
    canaries: 9,
    externalRequests: 0,
    observationSha256: observation.observationSha256,
  };
};

export const selfTestReleaseSuccessorHandoff = () => {
  const sourceRunId = '123456789';
  const runId = Number(sourceRunId);
  const headSha = 'a'.repeat(40);
  const updatedAtUtc = '2026-08-18T05:00:00.000Z';
  const archives = Object.fromEntries(
    RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.map((name) => [
      name,
      createReleaseSuccessorStoredZipFixture(
        Object.fromEntries(
          (
            EXACT_ARTIFACT_ENTRY_SETS[name] ?? [name === 'stage7-api' ? 'api.json' : `${name}.json`]
          ).map((pathName) => [
            pathName,
            pathName.endsWith('.json')
              ? jsonBytes({ artifactName: name, containsSensitiveData: false })
              : Buffer.from(`artifact:${name}:${pathName}\n`, 'utf8'),
          ]),
        ),
      ),
    ]),
  );
  const artifactEntries = RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.map((name, index) => ({
    id: index + 101,
    name,
    digest: `sha256:${sha256(archives[name])}`,
    expired: false,
    workflow_run: { id: runId },
  }));
  artifactEntries.push(
    ...RELEASE_SUCCESSOR_INTERNAL_ARTIFACTS.map((name, index) => ({
      id: 10_000 + index,
      name,
      digest: `sha256:${String(index + 7).repeat(64)}`,
      expired: false,
      workflow_run: { id: runId },
    })),
  );
  const eventRun = {
    id: runId,
    run_attempt: 1,
    head_sha: headSha,
    head_branch: 'master',
    status: 'completed',
    conclusion: 'success',
    event: 'workflow_dispatch',
    name: RELEASE_SUCCESSOR_WORKFLOW_NAME,
  };
  const apiRun = {
    ...eventRun,
    workflow_id: 77,
    updated_at: updatedAtUtc,
    repository: { full_name: REPOSITORY },
  };
  const encode = (value) => jsonBytes(value);
  const observationOptions = {
    triggerSource: encode({
      action: 'completed',
      repository: { full_name: REPOSITORY },
      workflow_run: eventRun,
    }),
    runResponseSource: encode(apiRun),
    workflowResponseSource: encode({
      id: 77,
      name: RELEASE_SUCCESSOR_WORKFLOW_NAME,
      path: RELEASE_SUCCESSOR_WORKFLOW_PATH,
    }),
    artifactsResponseSource: encode({
      total_count: artifactEntries.length,
      artifacts: artifactEntries,
    }),
    artifactArchives: archives,
    observedAtUtc: updatedAtUtc,
  };
  const observation = createReleaseSuccessorRunObservation(observationOptions);
  assert.equal(observation.externalRequests, 3 + RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.length);
  assertReleaseSuccessorObservedArtifactSource({
    observation,
    artifactName: 'stage7-api',
    basename: 'api.json',
    source: jsonBytes({ artifactName: 'stage7-api', containsSensitiveData: false }),
  });
  assert.throws(
    () =>
      assertReleaseSuccessorObservedArtifactSource({
        observation,
        artifactName: 'stage7-api',
        basename: 'api.json',
        source: jsonBytes({ artifactName: 'stage7-api', resignedButDifferent: true }),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ARTIFACT_SOURCE_BYTES_MISMATCH',
  );
  assert.throws(
    () => validateReleaseSuccessorRunObservation(observation, { runId: '987654321' }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_RUN_OBSERVATION_MISMATCH',
  );
  assert.throws(
    () =>
      createReleaseSuccessorRunObservation({
        ...observationOptions,
        triggerSource: encode({
          action: 'completed',
          repository: { full_name: REPOSITORY },
          workflow_run: { ...eventRun, status: 'in_progress', conclusion: null },
        }),
        runResponseSource: encode({ ...apiRun, status: 'in_progress', conclusion: null }),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_RUN_NOT_EXACT_SUCCESS',
  );
  assert.throws(
    () =>
      createReleaseSuccessorRunObservation({
        ...observationOptions,
        triggerSource: encode({
          action: 'completed',
          repository: { full_name: REPOSITORY },
          workflow_run: { ...eventRun, run_attempt: 2 },
        }),
        runResponseSource: encode({ ...apiRun, run_attempt: 2 }),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_RUN_NOT_EXACT_SUCCESS',
  );
  assert.throws(
    () =>
      createReleaseSuccessorRunObservation({
        ...observationOptions,
        artifactArchives: {
          ...archives,
          'stage7-api': createReleaseSuccessorStoredZipFixture({
            'api.json': jsonBytes({ tampered: true, containsSensitiveData: false }),
          }),
        },
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ARTIFACT_DIGEST_INVALID',
  );
  assert.throws(
    () =>
      createReleaseSuccessorRunObservation({
        ...observationOptions,
        artifactsResponseSource: encode({
          total_count: artifactEntries.length - 1,
          artifacts: artifactEntries.slice(0, -1),
        }),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ARTIFACT_ARCHIVES_INVALID',
  );
  assert.throws(
    () =>
      createReleaseSuccessorRunObservation({
        ...observationOptions,
        artifactsResponseSource: encode([
          { total_count: artifactEntries.length, artifacts: artifactEntries },
          {
            total_count: artifactEntries.length + 1,
            artifacts: [{ ...artifactEntries[0], id: 30_000, name: 'page-two-injection' }],
          },
        ]),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ARTIFACT_ARCHIVES_INVALID',
  );
  assert.throws(
    () =>
      createReleaseSuccessorRunObservation({
        ...observationOptions,
        artifactsResponseSource: encode({
          total_count: artifactEntries.length + 1,
          artifacts: artifactEntries,
        }),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ARTIFACT_ARCHIVES_INVALID',
  );
  assert.throws(
    () =>
      createReleaseSuccessorRunObservation({
        ...observationOptions,
        artifactsResponseSource: encode({
          total_count: artifactEntries.length + 1,
          artifacts: [
            ...artifactEntries,
            {
              id: 20_000,
              name: 'release-unapproved-internal',
              digest: `sha256:${'6'.repeat(64)}`,
              expired: false,
              workflow_run: { id: runId },
            },
          ],
        }),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ARTIFACT_ARCHIVES_INVALID',
  );
  assert.throws(
    () =>
      createReleaseSuccessorRunObservation({
        ...observationOptions,
        artifactsResponseSource: encode({
          total_count: artifactEntries.length,
          artifacts: artifactEntries.map((artifact) =>
            artifact.name === 'release-sandbox-execution-request'
              ? { ...artifact, name: 'release-unapproved-internal' }
              : artifact,
          ),
        }),
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_ARTIFACT_ARCHIVES_INVALID',
  );

  const previousReleaseManifest =
    createRollbackResilienceSelfTestFixture().inputs.previousReleaseManifest;
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
  const compactAuthorityDocument = strictJsonDocument(
    Buffer.from('{"containsSensitiveData":false,"value":1}\n', 'utf8'),
    'E7_RELEASE_SUCCESSOR_SELF_TEST_AUTHORITY_INVALID',
  );
  const whitespaceAuthorityDocument = strictJsonDocument(
    Buffer.from('{ "containsSensitiveData": false, "value": 1 }\n', 'utf8'),
    'E7_RELEASE_SUCCESSOR_SELF_TEST_AUTHORITY_INVALID',
  );
  assert.equal(
    compactAuthorityDocument.canonicalSha256,
    whitespaceAuthorityDocument.canonicalSha256,
  );
  const authorityDocuments = Object.fromEntries(
    Object.keys(RELEASE_SUCCESSOR_FENCE_AUTHORITY_LAYOUT).map((name) => [
      name,
      compactAuthorityDocument,
    ]),
  );
  const authorityRawDiff = textDocument(
    Buffer.from('diff\n', 'utf8'),
    'E7_RELEASE_SUCCESSOR_SELF_TEST_DIFF_INVALID',
  );
  const authoritySet = createReleaseSuccessorFenceAuthorityBindings({
    documents: authorityDocuments,
    rawDiff: authorityRawDiff,
  });
  const whitespaceConfigSet = createReleaseSuccessorFenceAuthorityBindings({
    documents: { ...authorityDocuments, config: whitespaceAuthorityDocument },
    rawDiff: authorityRawDiff,
  });
  const receiptRawSwapSet = createReleaseSuccessorFenceAuthorityBindings({
    documents: { ...authorityDocuments, reconciliationRollbackCheck: whitespaceAuthorityDocument },
    rawDiff: authorityRawDiff,
  });
  const recoveryIamRawSwapSet = createReleaseSuccessorFenceAuthorityBindings({
    documents: {
      ...authorityDocuments,
      reconciliationRecoveryRoleEffectivePermissions: whitespaceAuthorityDocument,
    },
    rawDiff: authorityRawDiff,
  });
  const emergencyOutcomeRawSwapSet = createReleaseSuccessorFenceAuthorityBindings({
    documents: {
      ...authorityDocuments,
      emergencyRecoveryNoActionOutcome: whitespaceAuthorityDocument,
    },
    rawDiff: authorityRawDiff,
  });
  assert.notEqual(objectSha256(authoritySet), objectSha256(whitespaceConfigSet));
  assert.notEqual(objectSha256(authoritySet), objectSha256(receiptRawSwapSet));
  assert.notEqual(objectSha256(authoritySet), objectSha256(recoveryIamRawSwapSet));
  assert.notEqual(objectSha256(authoritySet), objectSha256(emergencyOutcomeRawSwapSet));
  return {
    status: 'PASS',
    canaries: 17,
    externalRequests: 0,
    observationSha256: observation.observationSha256,
    projectionIndexSha256: projectionIndex.projectionIndexSha256,
  };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--self-test') {
    fail('E7_RELEASE_SUCCESSOR_HANDOFF_COMMAND_INVALID');
  }
  process.stdout.write(`${JSON.stringify(selfTestReleaseSuccessorHandoff())}\n`);
}
