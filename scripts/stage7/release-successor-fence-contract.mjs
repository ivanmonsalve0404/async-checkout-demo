import { canonicalJson, objectSha256 } from './core.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const SOURCE_WORKFLOW_PATH = '.github/workflows/release.yml';
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const withoutDigest = (value) => {
  const body = { ...value };
  delete body.fenceSha256;
  return body;
};

export const RELEASE_SUCCESSOR_FENCE_EVIDENCE_BINDING_KEYS = Object.freeze([
  'approval',
  'activation',
  'drift',
  'rollbackCompletion',
  'preFenceGate',
]);

export class Stage7ReleaseSuccessorFenceContractError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7ReleaseSuccessorFenceContractError';
    this.code = code;
  }
}

const fail = () => {
  throw new Stage7ReleaseSuccessorFenceContractError(
    'E7_RELEASE_SUCCESSOR_COMPLETION_FENCE_INVALID',
  );
};

const validateEvidenceBindings = (value) =>
  exactKeys(value, RELEASE_SUCCESSOR_FENCE_EVIDENCE_BINDING_KEYS) &&
  Object.values(value).every(
    (binding) =>
      exactKeys(binding, ['rawSha256', 'canonicalSha256', 'bytes']) &&
      SHA256.test(binding.rawSha256 ?? '') &&
      SHA256.test(binding.canonicalSha256 ?? '') &&
      Number.isSafeInteger(binding.bytes) &&
      binding.bytes > 1,
  );

export const validateReleaseSuccessorCompletionFence = (value, expected = {}) => {
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
      'journalLifecycleSha256',
      'journalCleanupRoleSha256',
      'journalRoleAuthoritySha256',
      'evidenceBindings',
      'authoritySetSha256',
      'mutationsBlocked',
      'orphanedFailurePolicy',
      'containsSensitiveData',
      'fenceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_RELEASE_COMPLETION_FENCE' ||
    value.status !== 'RELEASE_EVIDENCE_FENCED_IMMUTABLE' ||
    value.repository !== REPOSITORY ||
    value.sourceWorkflowPath !== SOURCE_WORKFLOW_PATH ||
    !RUN_ID.test(value.sourceRunId ?? '') ||
    value.sourceRunAttempt !== 1 ||
    !SHA.test(value.candidateSha ?? '') ||
    !RELEASE_ID.test(value.releaseId ?? '') ||
    !SHA256.test(value.journalLifecycleSha256 ?? '') ||
    !SHA256.test(value.journalCleanupRoleSha256 ?? '') ||
    !SHA256.test(value.journalRoleAuthoritySha256 ?? '') ||
    !validateEvidenceBindings(value.evidenceBindings) ||
    !SHA256.test(value.authoritySetSha256 ?? '') ||
    value.mutationsBlocked !== true ||
    value.orphanedFailurePolicy !== 'BLOCKED_FENCE_REQUIRES_SEPARATE_AUTHORIZED_RECOVERY' ||
    value.containsSensitiveData !== false ||
    value.fenceSha256 !== objectSha256(withoutDigest(value)) ||
    (expected.candidateSha !== undefined && value.candidateSha !== expected.candidateSha) ||
    (expected.releaseId !== undefined && value.releaseId !== expected.releaseId) ||
    (expected.sourceRunId !== undefined && value.sourceRunId !== String(expected.sourceRunId)) ||
    (expected.sourceRunAttempt !== undefined &&
      value.sourceRunAttempt !== Number(expected.sourceRunAttempt)) ||
    (expected.journalLifecycleSha256 !== undefined &&
      value.journalLifecycleSha256 !== expected.journalLifecycleSha256) ||
    (expected.journalCleanupRoleSha256 !== undefined &&
      value.journalCleanupRoleSha256 !== expected.journalCleanupRoleSha256) ||
    (expected.journalRoleAuthoritySha256 !== undefined &&
      value.journalRoleAuthoritySha256 !== expected.journalRoleAuthoritySha256) ||
    (expected.evidenceBindings !== undefined &&
      canonicalJson(value.evidenceBindings) !== canonicalJson(expected.evidenceBindings)) ||
    (expected.authoritySetSha256 !== undefined &&
      value.authoritySetSha256 !== expected.authoritySetSha256)
  ) {
    fail();
  }
  return value;
};
