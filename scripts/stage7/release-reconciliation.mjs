import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256 } from './core.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const RELEASE_WORKFLOW_PATH = '.github/workflows/release.yml';
const RELEASE_REF = 'refs/heads/master';
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/[A-Za-z0-9+=,.@_/-]{1,512}$/u;
const AWS_REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$/u;
const PHASES = Object.freeze(['ROLLBACK_CHECK', 'ROLLBACK_RESILIENCE']);
const MAX_DOCUMENT_BYTES = 1024 * 1024;
const MAX_JOURNAL_PARAMETER_BYTES = 3900;
const MAX_INTENT_SOURCE_BYTES = 32 * 1024 * 1024;
const MAX_INTENT_CHUNKS = 16;
const MAX_RUNTIME_PROOF_PARAMETERS_PER_PHASE = 4 * (MAX_INTENT_CHUNKS + 1);
const MAX_JOURNAL_ENTRIES =
  1 + MAX_INTENT_CHUNKS + PHASES.length + PHASES.length * MAX_RUNTIME_PROOF_PARAMETERS_PER_PHASE;

export const STAGE7_RELEASE_RECONCILIATION_ARTIFACT = 'stage7-release-reconciliation';
export const STAGE7_RELEASE_RECONCILIATION_FILES = Object.freeze([
  'rollback-check-reconciliation.json',
  'rollback-resilience-reconciliation.json',
  'stage7-release-pre-fence-gate.json',
]);
export const STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT = Object.freeze(
  [
    ['config', 'stage7-config.json', 'JSON'],
    ['releaseMetadata', 'release-metadata.json', 'JSON'],
    ['candidateManifest', 'candidate-manifest.json', 'JSON'],
    ['releasePlan', 'release-plan.json', 'JSON'],
    ['approvedDiff', 'infra-diff.json', 'JSON'],
    ['rawDiff', 'infra-diff.txt', 'RAW_TEXT'],
    ['githubEnvironmentApproval', 'github-environment-approval.json', 'JSON'],
    ['approval', 'approval.json', 'JSON'],
    ['awsAuth', 'aws-auth.json', 'JSON'],
    ['iamEffectivePermissionsBinding', 'aws-auth.json#iamEffectivePermissions', 'NESTED_JSON'],
    [
      'journalRoleEffectivePermissions',
      'stage7-release-journal-role-effective-permissions.json',
      'JSON',
    ],
    ['activation', 'activation.json', 'JSON'],
    ['webDeployment', 'web.json', 'JSON'],
    ['candidateRecord', 'versioned-rollback-candidate.json', 'JSON'],
    ['externalAuthorization', 'external-authorization.json', 'JSON'],
    ['previousReleaseManifest', 'previous-release-manifest.json', 'JSON'],
    ['previousSourceProvenance', 'previous-source-provenance.json', 'JSON'],
    ['previousTargetCompatibility', 'previous-target-compatibility.json', 'JSON'],
    ['previousFinalDisableProvenance', 'previous-final-disable-provenance.json', 'JSON'],
    ['previousApiContractEvidence', 'previous-api-contract-evidence.json', 'JSON'],
    ['previousPendingEvidence', 'previous-pending-evidence.json', 'JSON'],
    ['previousSmokeEvidence', 'previous-smoke-evidence.json', 'JSON'],
    ['previousReleaseProjectionIndex', 'previous-release-projection-index.json', 'JSON'],
  ].map(([label, path, sourceType]) => Object.freeze({ label, path, sourceType })),
);
export const STAGE7_RELEASE_RECONCILIATION_CONTRACT = Object.freeze({
  schemaVersion: 1,
  artifactName: STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
  artifactEntries: STAGE7_RELEASE_RECONCILIATION_FILES,
  rollbackJournalRoot: '/checkout/stage7/rollback',
  sourceArtifactsWithFenceAndReconciliation: 31,
  approvedInternalArtifacts: Object.freeze(['release-observability-pending']),
  apiArtifactsWithFenceAndReconciliation: 32,
  sourceRunAttempt: 1,
  publicationRecovery: 'SAME_RUN_FORWARD_ONLY_OR_EXPLICITLY_BLOCKED',
});

const JOB_CONCLUSIONS = Object.freeze(['SUCCESS', 'FAILURE', 'CANCELLED', 'TIMED_OUT', 'SKIPPED']);
const RECOVERY_ACTIONS = Object.freeze(['VERIFIED_NOOP', 'REPROMOTED_CANDIDATE']);
const PUBLICATION_STATES = Object.freeze(['ABSENT', 'PARTIAL', 'EXACT', 'CONFLICT']);
const SMOKE_AUTHORIZATION_IDS = Object.freeze([
  'AUTH-E7-EXT-01',
  'AUTH-E7-EXT-02',
  'AUTH-E7-EXT-03',
]);
export const STAGE7_RELEASE_RECONCILIATION_SMOKE_USAGE_IDS = Object.freeze({
  ROLLBACK_CHECK: 'RECONCILIATION_ROLLBACK_CHECK_SMOKE',
  ROLLBACK_RESILIENCE: 'RECONCILIATION_ROLLBACK_RESILIENCE_SMOKE',
});

export class Stage7ReleaseReconciliationError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseReconciliationError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseReconciliationError(code, cause === undefined ? undefined : { cause });
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
const sameObject = (left, right) => canonicalJson(left) === canonicalJson(right);
const phaseSlug = (phase) =>
  phase === 'ROLLBACK_CHECK' ? 'rollback-check' : 'rollback-resilience';
const receiptPath = (phase) =>
  phase === 'ROLLBACK_CHECK'
    ? STAGE7_RELEASE_RECONCILIATION_FILES[0]
    : STAGE7_RELEASE_RECONCILIATION_FILES[1];
const journalRoot = (candidateSha) =>
  `${STAGE7_RELEASE_RECONCILIATION_CONTRACT.rollbackJournalRoot}/${candidateSha}`;
const reconciliationRoot = (source) =>
  `${journalRoot(source.candidateSha)}/release-reconciliation/${source.runId}`;
const journalOwnerParameter = (source) => `${reconciliationRoot(source)}/owner`;
const journalTerminalParameter = (source, phase) =>
  `${reconciliationRoot(source)}/${phaseSlug(phase)}/terminal`;

export const validateReleaseReconciliationSource = (value) => {
  if (
    !exactKeys(value, [
      'repository',
      'workflowPath',
      'ref',
      'runId',
      'runAttempt',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'configSha256',
    ]) ||
    value.repository !== REPOSITORY ||
    value.workflowPath !== RELEASE_WORKFLOW_PATH ||
    value.ref !== RELEASE_REF ||
    !RUN_ID.test(value.runId ?? '') ||
    value.runAttempt !== STAGE7_RELEASE_RECONCILIATION_CONTRACT.sourceRunAttempt ||
    !SHA.test(value.candidateSha ?? '') ||
    !RELEASE_ID.test(value.releaseId ?? '') ||
    !value.releaseId.endsWith(value.candidateSha.slice(0, 7)) ||
    !RELEASE_TAG.test(value.releaseTag ?? '') ||
    !SHA256.test(value.configSha256 ?? '')
  ) {
    fail('E7_RELEASE_RECONCILIATION_SOURCE_INVALID');
  }
  return value;
};

export const validateReleaseReconciliationSmokeAuthorizationUsage = (value, { phase, source }) => {
  validateReleaseReconciliationSource(source);
  if (
    !PHASES.includes(phase) ||
    !exactKeys(value, [
      'schemaVersion',
      'phase',
      'usageId',
      'authorizationSha256',
      'bundleSha256',
      'configSha256',
      'candidateSha',
      'releaseId',
      'ownedOriginSha256',
      'sandboxHostSha256',
      'requestCounts',
      'total',
      'passed',
      'failed',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.phase !== phase ||
    value.usageId !== STAGE7_RELEASE_RECONCILIATION_SMOKE_USAGE_IDS[phase] ||
    ![
      value.authorizationSha256,
      value.bundleSha256,
      value.configSha256,
      value.ownedOriginSha256,
      value.sandboxHostSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    value.authorizationSha256 !== value.bundleSha256 ||
    value.configSha256 !== source.configSha256 ||
    value.candidateSha !== source.candidateSha ||
    value.releaseId !== source.releaseId ||
    !exactKeys(value.requestCounts, SMOKE_AUTHORIZATION_IDS) ||
    value.requestCounts['AUTH-E7-EXT-01'] !== 3 ||
    value.requestCounts['AUTH-E7-EXT-02'] !== 0 ||
    value.requestCounts['AUTH-E7-EXT-03'] !== 0 ||
    value.total !== 3 ||
    value.passed !== 3 ||
    value.failed !== 0 ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_RELEASE_RECONCILIATION_SMOKE_AUTHORIZATION_USAGE_INVALID');
  }
  return value;
};

const validateIntentBinding = (value, expected) => {
  if (
    !exactKeys(value, ['label', 'path', 'sourceType', 'rawSha256', 'canonicalSha256', 'bytes']) ||
    value.label !== expected.label ||
    value.path !== expected.path ||
    value.sourceType !== expected.sourceType ||
    !Number.isSafeInteger(value.bytes) ||
    value.bytes < 1 ||
    value.bytes > MAX_INTENT_SOURCE_BYTES ||
    (expected.sourceType === 'RAW_TEXT'
      ? !SHA256.test(value.rawSha256 ?? '') || value.canonicalSha256 !== null
      : expected.sourceType === 'NESTED_JSON'
        ? value.rawSha256 !== null || !SHA256.test(value.canonicalSha256 ?? '')
        : !SHA256.test(value.rawSha256 ?? '') || !SHA256.test(value.canonicalSha256 ?? ''))
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_BINDING_INVALID');
  }
  return value;
};

export const createReleaseReconciliationIntent = ({ source, authority, bindings }) => {
  validateReleaseReconciliationSource(source);
  const rollbackRole = ROLE_ARN.exec(authority?.rollbackRoleArn ?? '');
  const journalRole = ROLE_ARN.exec(authority?.journalRoleArn ?? '');
  if (
    !exactKeys(authority, [
      'accountId',
      'region',
      'rollbackRoleArn',
      'journalRoleArn',
      'rollbackPermissionSetSha256',
      'journalEffectivePermissionsSha256',
    ]) ||
    !/^[0-9]{12}$/u.test(authority.accountId ?? '') ||
    !AWS_REGION.test(authority.region ?? '') ||
    rollbackRole?.[1] !== authority.accountId ||
    journalRole?.[1] !== authority.accountId ||
    authority.rollbackRoleArn === authority.journalRoleArn ||
    !SHA256.test(authority.rollbackPermissionSetSha256 ?? '') ||
    !SHA256.test(authority.journalEffectivePermissionsSha256 ?? '') ||
    !Array.isArray(bindings) ||
    bindings.length !== STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.length
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_BINDING_SET_INVALID');
  }
  bindings.forEach((binding, index) =>
    validateIntentBinding(binding, STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT[index]),
  );
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_INTENT',
    status: 'IMMUTABLE_PRE_MUTATION_BINDINGS',
    source: { ...source },
    authority: { ...authority },
    bindingSetVersion: 1,
    bindings: bindings.map((binding) => ({ ...binding })),
    bindingsSha256: objectSha256(bindings),
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationIntent({ ...body, intentSha256: objectSha256(body) });
};

export const validateReleaseReconciliationIntent = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'source',
      'authority',
      'bindingSetVersion',
      'bindings',
      'bindingsSha256',
      'containsSensitiveData',
      'intentSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_INTENT' ||
    value.status !== 'IMMUTABLE_PRE_MUTATION_BINDINGS' ||
    validateReleaseReconciliationSource(value.source) !== value.source ||
    !exactKeys(value.authority, [
      'accountId',
      'region',
      'rollbackRoleArn',
      'journalRoleArn',
      'rollbackPermissionSetSha256',
      'journalEffectivePermissionsSha256',
    ]) ||
    ROLE_ARN.exec(value.authority.rollbackRoleArn ?? '')?.[1] !== value.authority.accountId ||
    ROLE_ARN.exec(value.authority.journalRoleArn ?? '')?.[1] !== value.authority.accountId ||
    value.authority.rollbackRoleArn === value.authority.journalRoleArn ||
    !AWS_REGION.test(value.authority.region ?? '') ||
    !SHA256.test(value.authority.rollbackPermissionSetSha256 ?? '') ||
    !SHA256.test(value.authority.journalEffectivePermissionsSha256 ?? '') ||
    value.bindingSetVersion !== 1 ||
    !Array.isArray(value.bindings) ||
    value.bindings.length !== STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.length ||
    value.bindings.some((binding, index) => {
      try {
        validateIntentBinding(binding, STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT[index]);
        return false;
      } catch {
        return true;
      }
    }) ||
    value.bindingsSha256 !== objectSha256(value.bindings) ||
    value.containsSensitiveData !== false ||
    value.intentSha256 !== objectSha256(withoutDigest(value, 'intentSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_INVALID');
  }
  return value;
};

const validateIntentChunkBinding = (value, { source, index }) => {
  const expectedIndex = String(index + 1).padStart(4, '0');
  if (
    !exactKeys(value, ['index', 'parameterName', 'rawSha256', 'bytes']) ||
    value.index !== index + 1 ||
    value.parameterName !==
      `${journalRoot(source.candidateSha)}/release-reconciliation/${source.runId}/intent/${expectedIndex}` ||
    !SHA256.test(value.rawSha256 ?? '') ||
    !Number.isSafeInteger(value.bytes) ||
    value.bytes < 1 ||
    value.bytes > 3000
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_CHUNK_BINDING_INVALID');
  }
  return value;
};

export const createReleaseRollbackJournalOwner = ({
  source,
  intent,
  intentRawSha256,
  intentBytes,
  intentChunks,
  createdAtUtc,
}) => {
  validateReleaseReconciliationSource(source);
  validateReleaseReconciliationIntent(intent);
  if (
    !sameObject(source, intent.source) ||
    !SHA256.test(intentRawSha256 ?? '') ||
    !Number.isSafeInteger(intentBytes) ||
    intentBytes < 2 ||
    intentBytes > MAX_INTENT_SOURCE_BYTES ||
    !Array.isArray(intentChunks) ||
    intentChunks.length < 1 ||
    intentChunks.length > MAX_INTENT_CHUNKS ||
    intentChunks.some((chunk, index) => {
      try {
        validateIntentChunkBinding(chunk, { source, index });
        return false;
      } catch {
        return true;
      }
    }) ||
    intentChunks.reduce((total, chunk) => total + chunk.bytes, 0) !== intentBytes ||
    !utc(createdAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_JOURNAL_OWNER_INPUT_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_ROLLBACK_JOURNAL_OWNER',
    status: 'RECOVERY_REQUIRED_UNTIL_TERMINAL_RECEIPTS',
    source: { ...source },
    candidateRootPrefix: journalRoot(source.candidateSha),
    reconciliationRootPrefix: reconciliationRoot(source),
    runtimeProofRootPrefix: `${reconciliationRoot(source)}/runtime-proofs`,
    parameterName: journalOwnerParameter(source),
    intentBindingsSha256: intent.bindingsSha256,
    intentSha256: intent.intentSha256,
    intentRawSha256,
    intentBytes,
    intentChunks: intentChunks.map((chunk) => ({ ...chunk })),
    intentChunksSha256: objectSha256(intentChunks),
    createdAtUtc,
    writeMode: 'SSM_PUT_PARAMETER_OVERWRITE_FALSE',
    containsSensitiveData: false,
  };
  return validateReleaseRollbackJournalOwner({ ...body, ownerSha256: objectSha256(body) });
};

export const validateReleaseRollbackJournalOwner = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'source',
      'candidateRootPrefix',
      'reconciliationRootPrefix',
      'runtimeProofRootPrefix',
      'parameterName',
      'intentBindingsSha256',
      'intentSha256',
      'intentRawSha256',
      'intentBytes',
      'intentChunks',
      'intentChunksSha256',
      'createdAtUtc',
      'writeMode',
      'containsSensitiveData',
      'ownerSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_ROLLBACK_JOURNAL_OWNER' ||
    value.status !== 'RECOVERY_REQUIRED_UNTIL_TERMINAL_RECEIPTS' ||
    validateReleaseReconciliationSource(value.source) !== value.source ||
    value.candidateRootPrefix !== journalRoot(value.source.candidateSha) ||
    value.reconciliationRootPrefix !== reconciliationRoot(value.source) ||
    value.runtimeProofRootPrefix !== `${reconciliationRoot(value.source)}/runtime-proofs` ||
    value.parameterName !== journalOwnerParameter(value.source) ||
    !SHA256.test(value.intentBindingsSha256 ?? '') ||
    !SHA256.test(value.intentSha256 ?? '') ||
    !SHA256.test(value.intentRawSha256 ?? '') ||
    !Number.isSafeInteger(value.intentBytes) ||
    value.intentBytes < 2 ||
    value.intentBytes > MAX_INTENT_SOURCE_BYTES ||
    !Array.isArray(value.intentChunks) ||
    value.intentChunks.length < 1 ||
    value.intentChunks.length > MAX_INTENT_CHUNKS ||
    value.intentChunks.some((chunk, index) => {
      try {
        validateIntentChunkBinding(chunk, { source: value.source, index });
        return false;
      } catch {
        return true;
      }
    }) ||
    value.intentChunks.reduce((total, chunk) => total + chunk.bytes, 0) !== value.intentBytes ||
    value.intentChunksSha256 !== objectSha256(value.intentChunks) ||
    !utc(value.createdAtUtc) ||
    value.writeMode !== 'SSM_PUT_PARAMETER_OVERWRITE_FALSE' ||
    value.containsSensitiveData !== false ||
    Buffer.byteLength(JSON.stringify(value), 'utf8') > MAX_JOURNAL_PARAMETER_BYTES ||
    value.ownerSha256 !== objectSha256(withoutDigest(value, 'ownerSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_JOURNAL_OWNER_INVALID');
  }
  return value;
};

export const classifyReleaseRollbackJournalAccess = ({
  source,
  owner = null,
  journalEntryCount,
}) => {
  validateReleaseReconciliationSource(source);
  if (
    !Number.isSafeInteger(journalEntryCount) ||
    journalEntryCount < 0 ||
    journalEntryCount > MAX_JOURNAL_ENTRIES
  ) {
    fail('E7_RELEASE_RECONCILIATION_JOURNAL_ENTRY_COUNT_INVALID');
  }
  if (owner !== null) validateReleaseRollbackJournalOwner(owner);

  let decision;
  if (owner === null && journalEntryCount === 0) decision = 'ALLOW_NEW_INTENT';
  else if (owner === null) decision = 'BLOCK_UNOWNED_JOURNAL';
  else if (sameObject(owner.source, source)) decision = 'RESUME_SAME_RUN';
  else decision = 'BLOCK_DIFFERENT_RUN';

  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_ROLLBACK_JOURNAL_ACCESS',
    status: decision.startsWith('BLOCK_') ? 'BLOCKED' : 'PASS',
    source: { ...source },
    candidateRootPrefix: journalRoot(source.candidateSha),
    ownerSha256: owner?.ownerSha256 ?? null,
    journalEntryCount,
    decision,
    mutationAllowed: ['ALLOW_NEW_INTENT', 'RESUME_SAME_RUN'].includes(decision),
    containsSensitiveData: false,
  };
  return { ...body, accessSha256: objectSha256(body) };
};

const validateRuntimeProofJournal = (value, { source, phase, proofKind }) => {
  const expectedName = `${reconciliationRoot(source)}/runtime-proofs/${phaseSlug(phase)}/${proofKind.toLowerCase()}/${value?.rawSha256}/index`;
  if (
    !exactKeys(value, [
      'indexParameterName',
      'indexSha256',
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'observedAtUtc',
      'chunkCount',
      'chunksSha256',
    ]) ||
    value.indexParameterName !== expectedName ||
    ![value.indexSha256, value.rawSha256, value.canonicalSha256, value.chunksSha256].every(
      (digest) => SHA256.test(digest ?? ''),
    ) ||
    !Number.isSafeInteger(value.bytes) ||
    value.bytes < 2 ||
    value.bytes > MAX_INTENT_SOURCE_BYTES ||
    !utc(value.observedAtUtc) ||
    !Number.isSafeInteger(value.chunkCount) ||
    value.chunkCount < 1 ||
    value.chunkCount > MAX_INTENT_CHUNKS
  ) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_JOURNAL_INVALID');
  }
  return value;
};

const validateRuntimeProofParameterBindings = (value, rootPrefix) => {
  const escaped = rootPrefix.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const namePattern = new RegExp(
    `^${escaped}/(?:rollback-check|rollback-resilience)/(?:drift|smoke)/[0-9a-f]{64}/(?:index|chunk/[0-9]{4}-[0-9a-f]{64})$`,
    'u',
  );
  if (
    !Array.isArray(value) ||
    value.length < 4 ||
    value.length > MAX_RUNTIME_PROOF_PARAMETERS_PER_PHASE ||
    value.some(
      (entry) =>
        !exactKeys(entry, ['name', 'rawSha256', 'bytes', 'version']) ||
        !namePattern.test(entry.name ?? '') ||
        !SHA256.test(entry.rawSha256 ?? '') ||
        !Number.isSafeInteger(entry.bytes) ||
        entry.bytes < 1 ||
        entry.bytes > MAX_JOURNAL_PARAMETER_BYTES ||
        entry.version !== 1,
    ) ||
    new Set(value.map(({ name }) => name)).size !== value.length ||
    value.map(({ name }) => name).join('\0') !==
      value
        .map(({ name }) => name)
        .toSorted((left, right) => left.localeCompare(right))
        .join('\0')
  ) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_PARAMETERS_INVALID');
  }
  return value;
};

const validateRuntimeProof = (value, { source, phase }) => {
  if (
    !exactKeys(value, [
      'state',
      'expectedStateSha256',
      'observedStateSha256',
      'readbackRawSha256',
      'readbackCanonicalSha256',
      'driftProofSha256',
      'smokeProofSha256',
      'smokeAuthorizationUsage',
      'driftProofJournal',
      'smokeProofJournal',
      'mixedComponents',
      'pendingMutations',
      'convergenceCompletedAtUtc',
      'driftObservedAtUtc',
      'smokeObservedAtUtc',
      'observedAtUtc',
    ]) ||
    value.state !== 'EXACT_CANDIDATE_N' ||
    !SHA256.test(value.expectedStateSha256 ?? '') ||
    value.observedStateSha256 !== value.expectedStateSha256 ||
    !SHA256.test(value.readbackRawSha256 ?? '') ||
    !SHA256.test(value.readbackCanonicalSha256 ?? '') ||
    !SHA256.test(value.driftProofSha256 ?? '') ||
    !SHA256.test(value.smokeProofSha256 ?? '') ||
    validateReleaseReconciliationSmokeAuthorizationUsage(value.smokeAuthorizationUsage, {
      phase,
      source,
    }) !== value.smokeAuthorizationUsage ||
    validateRuntimeProofJournal(value.driftProofJournal, {
      source,
      phase,
      proofKind: 'DRIFT',
    }) !== value.driftProofJournal ||
    validateRuntimeProofJournal(value.smokeProofJournal, {
      source,
      phase,
      proofKind: 'SMOKE',
    }) !== value.smokeProofJournal ||
    value.driftProofJournal.canonicalSha256 !== value.driftProofSha256 ||
    value.smokeProofJournal.canonicalSha256 !== value.smokeProofSha256 ||
    !Array.isArray(value.mixedComponents) ||
    value.mixedComponents.length !== 0 ||
    !Array.isArray(value.pendingMutations) ||
    value.pendingMutations.length !== 0 ||
    ![
      value.convergenceCompletedAtUtc,
      value.driftObservedAtUtc,
      value.smokeObservedAtUtc,
      value.observedAtUtc,
    ].every(utc) ||
    Date.parse(value.driftObservedAtUtc) < Date.parse(value.convergenceCompletedAtUtc) ||
    Date.parse(value.smokeObservedAtUtc) < Date.parse(value.convergenceCompletedAtUtc) ||
    value.observedAtUtc !==
      [
        value.convergenceCompletedAtUtc,
        value.driftObservedAtUtc,
        value.smokeObservedAtUtc,
      ].toSorted((left, right) => Date.parse(right) - Date.parse(left))[0]
  ) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_NOT_TERMINAL_N');
  }
  return value;
};

export const createReleaseReconciliationReceipt = ({
  phase,
  source,
  owner,
  intent,
  originalJobConclusion,
  recoveryAction,
  expectedStateSha256,
  observedStateSha256,
  readbackRawSha256,
  readbackCanonicalSha256,
  driftProofSha256,
  smokeProofSha256,
  smokeAuthorizationUsage,
  driftProofJournal,
  smokeProofJournal,
  runtimeProofParameters,
  runtimeProofParameterCount,
  runtimeProofParametersSha256,
  journalScanSha256,
  terminalStateSha256,
  startedAtUtc,
  convergenceCompletedAtUtc,
  driftObservedAtUtc,
  smokeObservedAtUtc,
  observedAtUtc,
  completedAtUtc,
}) => {
  validateReleaseReconciliationSource(source);
  validateReleaseRollbackJournalOwner(owner);
  validateReleaseReconciliationIntent(intent);
  const intentBytes = Buffer.from(canonicalJson(intent), 'utf8');
  if (
    !PHASES.includes(phase) ||
    !sameObject(source, owner.source) ||
    !sameObject(source, intent.source) ||
    intent.intentSha256 !== owner.intentSha256 ||
    intent.bindingsSha256 !== owner.intentBindingsSha256 ||
    sha256(intentBytes) !== owner.intentRawSha256 ||
    intentBytes.length !== owner.intentBytes ||
    !JOB_CONCLUSIONS.includes(originalJobConclusion) ||
    !RECOVERY_ACTIONS.includes(recoveryAction) ||
    !SHA256.test(expectedStateSha256 ?? '') ||
    observedStateSha256 !== expectedStateSha256 ||
    validateRuntimeProofJournal(driftProofJournal, {
      source,
      phase,
      proofKind: 'DRIFT',
    }) !== driftProofJournal ||
    validateRuntimeProofJournal(smokeProofJournal, {
      source,
      phase,
      proofKind: 'SMOKE',
    }) !== smokeProofJournal ||
    driftProofJournal.canonicalSha256 !== driftProofSha256 ||
    smokeProofJournal.canonicalSha256 !== smokeProofSha256 ||
    validateReleaseReconciliationSmokeAuthorizationUsage(smokeAuthorizationUsage, {
      phase,
      source,
    }) !== smokeAuthorizationUsage ||
    validateRuntimeProofParameterBindings(runtimeProofParameters, owner.runtimeProofRootPrefix) !==
      runtimeProofParameters ||
    runtimeProofParameterCount !== runtimeProofParameters.length ||
    runtimeProofParametersSha256 !== objectSha256(runtimeProofParameters) ||
    !runtimeProofParameters.some(({ name }) => name === driftProofJournal.indexParameterName) ||
    !runtimeProofParameters.some(({ name }) => name === smokeProofJournal.indexParameterName) ||
    ![
      readbackRawSha256,
      readbackCanonicalSha256,
      driftProofSha256,
      smokeProofSha256,
      journalScanSha256,
      terminalStateSha256,
    ].every((value) => SHA256.test(value ?? '')) ||
    ![
      startedAtUtc,
      convergenceCompletedAtUtc,
      driftObservedAtUtc,
      smokeObservedAtUtc,
      observedAtUtc,
      completedAtUtc,
    ].every(utc) ||
    Date.parse(startedAtUtc) < Date.parse(owner.createdAtUtc) ||
    Date.parse(convergenceCompletedAtUtc) < Date.parse(startedAtUtc) ||
    Date.parse(driftObservedAtUtc) < Date.parse(convergenceCompletedAtUtc) ||
    Date.parse(smokeObservedAtUtc) < Date.parse(convergenceCompletedAtUtc) ||
    observedAtUtc !==
      [convergenceCompletedAtUtc, driftObservedAtUtc, smokeObservedAtUtc].toSorted(
        (left, right) => Date.parse(right) - Date.parse(left),
      )[0] ||
    Date.parse(completedAtUtc) < Date.parse(observedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECEIPT_INPUT_INVALID');
  }
  const eligibleForFence =
    originalJobConclusion === 'SUCCESS' && recoveryAction === 'VERIFIED_NOOP';
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_RECEIPT',
    status: 'TERMINAL_CANDIDATE_N_VERIFIED',
    phase,
    source: { ...source },
    originalJobConclusion,
    recoveryAction,
    journal: {
      candidateRootPrefix: owner.candidateRootPrefix,
      reconciliationRootPrefix: owner.reconciliationRootPrefix,
      ownerParameterName: owner.parameterName,
      ownerSha256: owner.ownerSha256,
      ownerIntentBindingsSha256: owner.intentBindingsSha256,
      ownerIndex: { ...owner },
      intentIndex: { ...intent, bindings: intent.bindings.map((binding) => ({ ...binding })) },
      ownerRunId: owner.source.runId,
      ownerRunAttempt: owner.source.runAttempt,
      ownerCreatedAtUtc: owner.createdAtUtc,
      terminalParameterName: journalTerminalParameter(source, phase),
      terminalParameterVersion: 1,
      journalScanSha256,
      terminalStateSha256,
      runtimeProofParameters: runtimeProofParameters.map((entry) => ({ ...entry })),
      runtimeProofParameterCount,
      runtimeProofParametersSha256,
      unresolvedEntryNames: [],
    },
    runtime: {
      state: 'EXACT_CANDIDATE_N',
      expectedStateSha256,
      observedStateSha256,
      readbackRawSha256,
      readbackCanonicalSha256,
      driftProofSha256,
      smokeProofSha256,
      smokeAuthorizationUsage: {
        ...smokeAuthorizationUsage,
        requestCounts: { ...smokeAuthorizationUsage.requestCounts },
      },
      driftProofJournal: { ...driftProofJournal },
      smokeProofJournal: { ...smokeProofJournal },
      mixedComponents: [],
      pendingMutations: [],
      convergenceCompletedAtUtc,
      driftObservedAtUtc,
      smokeObservedAtUtc,
      observedAtUtc,
    },
    eligibleForFence,
    startedAtUtc,
    completedAtUtc,
    containsSensitiveData: false,
  };
  return validateReleaseReconciliationReceipt({ ...body, receiptSha256: objectSha256(body) });
};

export const validateReleaseReconciliationReceipt = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'phase',
      'source',
      'originalJobConclusion',
      'recoveryAction',
      'journal',
      'runtime',
      'eligibleForFence',
      'startedAtUtc',
      'completedAtUtc',
      'containsSensitiveData',
      'receiptSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_RECEIPT' ||
    value.status !== 'TERMINAL_CANDIDATE_N_VERIFIED' ||
    !PHASES.includes(value.phase) ||
    validateReleaseReconciliationSource(value.source) !== value.source ||
    !JOB_CONCLUSIONS.includes(value.originalJobConclusion) ||
    !RECOVERY_ACTIONS.includes(value.recoveryAction) ||
    !exactKeys(value.journal, [
      'candidateRootPrefix',
      'reconciliationRootPrefix',
      'ownerParameterName',
      'ownerSha256',
      'ownerIntentBindingsSha256',
      'ownerIndex',
      'intentIndex',
      'ownerRunId',
      'ownerRunAttempt',
      'ownerCreatedAtUtc',
      'terminalParameterName',
      'terminalParameterVersion',
      'journalScanSha256',
      'terminalStateSha256',
      'runtimeProofParameters',
      'runtimeProofParameterCount',
      'runtimeProofParametersSha256',
      'unresolvedEntryNames',
    ]) ||
    value.journal.candidateRootPrefix !== journalRoot(value.source.candidateSha) ||
    value.journal.reconciliationRootPrefix !== reconciliationRoot(value.source) ||
    value.journal.ownerParameterName !== journalOwnerParameter(value.source) ||
    !SHA256.test(value.journal.ownerSha256 ?? '') ||
    !SHA256.test(value.journal.ownerIntentBindingsSha256 ?? '') ||
    validateReleaseRollbackJournalOwner(value.journal.ownerIndex) !== value.journal.ownerIndex ||
    !sameObject(value.journal.ownerIndex.source, value.source) ||
    value.journal.ownerIndex.parameterName !== value.journal.ownerParameterName ||
    value.journal.ownerIndex.ownerSha256 !== value.journal.ownerSha256 ||
    value.journal.ownerIndex.intentBindingsSha256 !== value.journal.ownerIntentBindingsSha256 ||
    value.journal.ownerIndex.createdAtUtc !== value.journal.ownerCreatedAtUtc ||
    validateReleaseReconciliationIntent(value.journal.intentIndex) !== value.journal.intentIndex ||
    !sameObject(value.journal.intentIndex.source, value.source) ||
    value.journal.intentIndex.intentSha256 !== value.journal.ownerIndex.intentSha256 ||
    value.journal.intentIndex.bindingsSha256 !== value.journal.ownerIndex.intentBindingsSha256 ||
    sha256(Buffer.from(canonicalJson(value.journal.intentIndex), 'utf8')) !==
      value.journal.ownerIndex.intentRawSha256 ||
    Buffer.byteLength(canonicalJson(value.journal.intentIndex), 'utf8') !==
      value.journal.ownerIndex.intentBytes ||
    value.journal.ownerRunId !== value.source.runId ||
    value.journal.ownerRunAttempt !== value.source.runAttempt ||
    !utc(value.journal.ownerCreatedAtUtc) ||
    value.journal.terminalParameterName !== journalTerminalParameter(value.source, value.phase) ||
    value.journal.terminalParameterVersion !== 1 ||
    !SHA256.test(value.journal.journalScanSha256 ?? '') ||
    !SHA256.test(value.journal.terminalStateSha256 ?? '') ||
    validateRuntimeProofParameterBindings(
      value.journal.runtimeProofParameters,
      value.journal.ownerIndex.runtimeProofRootPrefix,
    ) !== value.journal.runtimeProofParameters ||
    value.journal.runtimeProofParameterCount !== value.journal.runtimeProofParameters.length ||
    value.journal.runtimeProofParametersSha256 !==
      objectSha256(value.journal.runtimeProofParameters) ||
    !Array.isArray(value.journal.unresolvedEntryNames) ||
    value.journal.unresolvedEntryNames.length !== 0 ||
    validateRuntimeProof(value.runtime, { source: value.source, phase: value.phase }) !==
      value.runtime ||
    !value.journal.runtimeProofParameters.some(
      ({ name }) => name === value.runtime.driftProofJournal.indexParameterName,
    ) ||
    !value.journal.runtimeProofParameters.some(
      ({ name }) => name === value.runtime.smokeProofJournal.indexParameterName,
    ) ||
    value.eligibleForFence !==
      (value.originalJobConclusion === 'SUCCESS' && value.recoveryAction === 'VERIFIED_NOOP') ||
    !utc(value.startedAtUtc) ||
    !utc(value.completedAtUtc) ||
    Date.parse(value.startedAtUtc) < Date.parse(value.journal.ownerCreatedAtUtc) ||
    Date.parse(value.runtime.convergenceCompletedAtUtc) < Date.parse(value.startedAtUtc) ||
    Date.parse(value.completedAtUtc) < Date.parse(value.runtime.observedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.receiptSha256 !== objectSha256(withoutDigest(value, 'receiptSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECEIPT_INVALID');
  }
  return value;
};

export const createReleaseReconciliationJournalAuthority = ({
  rollbackCheckReceipt,
  rollbackResilienceReceipt,
}) => {
  validateReleaseReconciliationReceipt(rollbackCheckReceipt);
  validateReleaseReconciliationReceipt(rollbackResilienceReceipt);
  if (
    rollbackCheckReceipt.phase !== 'ROLLBACK_CHECK' ||
    rollbackResilienceReceipt.phase !== 'ROLLBACK_RESILIENCE' ||
    !sameObject(rollbackCheckReceipt.source, rollbackResilienceReceipt.source) ||
    !sameObject(
      rollbackCheckReceipt.journal.ownerIndex,
      rollbackResilienceReceipt.journal.ownerIndex,
    ) ||
    !sameObject(
      rollbackCheckReceipt.journal.intentIndex,
      rollbackResilienceReceipt.journal.intentIndex,
    )
  ) {
    fail('E7_RELEASE_RECONCILIATION_JOURNAL_AUTHORITY_INPUT_INVALID');
  }
  const owner = rollbackCheckReceipt.journal.ownerIndex;
  const intentIndex = rollbackCheckReceipt.journal.intentIndex;
  const chunks = owner.intentChunks.map((chunk) => ({
    name: chunk.parameterName,
    sha256: chunk.rawSha256,
    bytes: chunk.bytes,
    sequence: chunk.index,
  }));
  const terminals = [rollbackCheckReceipt, rollbackResilienceReceipt].map((receipt) => ({
    phase: receipt.phase,
    name: receipt.journal.terminalParameterName,
    version: receipt.journal.terminalParameterVersion,
    terminalStateSha256: receipt.journal.terminalStateSha256,
  }));
  const runtimeProofParametersByName = new Map();
  for (const receipt of [rollbackCheckReceipt, rollbackResilienceReceipt]) {
    for (const binding of receipt.journal.runtimeProofParameters) {
      const existing = runtimeProofParametersByName.get(binding.name);
      if (existing !== undefined && !sameObject(existing, binding)) {
        fail('E7_RELEASE_RECONCILIATION_JOURNAL_AUTHORITY_INPUT_INVALID');
      }
      runtimeProofParametersByName.set(binding.name, { ...binding });
    }
  }
  const runtimeProofParameters = [...runtimeProofParametersByName.values()].toSorted(
    (left, right) => left.name.localeCompare(right.name),
  );
  const smokeAuthorizationUsages = [rollbackCheckReceipt, rollbackResilienceReceipt].map(
    (receipt) => ({
      ...receipt.runtime.smokeAuthorizationUsage,
      requestCounts: { ...receipt.runtime.smokeAuthorizationUsage.requestCounts },
    }),
  );
  const cleanupParameterNames = [
    owner.parameterName,
    ...chunks.map(({ name }) => name),
    ...runtimeProofParameters.map(({ name }) => name),
    ...terminals.map(({ name }) => name),
  ];
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_JOURNAL_AUTHORITY',
    status: 'PRESERVE_THEN_DELETE_EXACT_SET',
    source: { ...rollbackCheckReceipt.source },
    candidateRootPrefix: owner.candidateRootPrefix,
    reconciliationRootPrefix: owner.reconciliationRootPrefix,
    ownerIndex: { ...owner, intentChunks: owner.intentChunks.map((chunk) => ({ ...chunk })) },
    intentIndex: {
      ...intentIndex,
      bindings: intentIndex.bindings.map((binding) => ({ ...binding })),
    },
    intentIndexSha256: objectSha256(intentIndex),
    intentBindingCount: intentIndex.bindings.length,
    chunks,
    terminals,
    runtimeProofParameters,
    smokeAuthorizationUsages,
    cleanupParameterNames,
    cleanupParameterCount: cleanupParameterNames.length,
    requiredResidualCount: 0,
    containsSensitiveData: false,
  };
  return {
    ...body,
    journalAuthoritySha256: objectSha256(body),
  };
};

export const validateReleaseReconciliationJournalAuthority = (
  value,
  { rollbackCheckReceipt, rollbackResilienceReceipt },
) => {
  const expected = createReleaseReconciliationJournalAuthority({
    rollbackCheckReceipt,
    rollbackResilienceReceipt,
  });
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'source',
      'candidateRootPrefix',
      'reconciliationRootPrefix',
      'ownerIndex',
      'intentIndex',
      'intentIndexSha256',
      'intentBindingCount',
      'chunks',
      'terminals',
      'runtimeProofParameters',
      'smokeAuthorizationUsages',
      'cleanupParameterNames',
      'cleanupParameterCount',
      'requiredResidualCount',
      'containsSensitiveData',
      'journalAuthoritySha256',
    ]) ||
    value.journalAuthoritySha256 !== objectSha256(withoutDigest(value, 'journalAuthoritySha256')) ||
    !sameObject(value, expected)
  ) {
    fail('E7_RELEASE_RECONCILIATION_JOURNAL_AUTHORITY_INVALID');
  }
  return value;
};

const parseReceiptDocument = (source, expectedPhase) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_DOCUMENT_BYTES) {
    fail('E7_RELEASE_RECONCILIATION_RECEIPT_DOCUMENT_INVALID');
  }
  let value;
  try {
    value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
  } catch (error) {
    fail('E7_RELEASE_RECONCILIATION_RECEIPT_DOCUMENT_INVALID', error);
  }
  validateReleaseReconciliationReceipt(value);
  if (value.phase !== expectedPhase) {
    fail('E7_RELEASE_RECONCILIATION_RECEIPT_PHASE_MISMATCH');
  }
  return {
    value,
    binding: {
      artifactName: STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
      path: receiptPath(expectedPhase),
      rawSha256: sha256(bytes),
      canonicalSha256: objectSha256(value),
      bytes: bytes.length,
      receiptSha256: value.receiptSha256,
    },
  };
};

const validateReceiptBinding = (value, phase) =>
  exactKeys(value, [
    'artifactName',
    'path',
    'rawSha256',
    'canonicalSha256',
    'bytes',
    'receiptSha256',
  ]) &&
  value.artifactName === STAGE7_RELEASE_RECONCILIATION_ARTIFACT &&
  value.path === receiptPath(phase) &&
  SHA256.test(value.rawSha256 ?? '') &&
  SHA256.test(value.canonicalSha256 ?? '') &&
  Number.isSafeInteger(value.bytes) &&
  value.bytes >= 2 &&
  value.bytes <= MAX_DOCUMENT_BYTES &&
  SHA256.test(value.receiptSha256 ?? '');

export const createReleasePreFenceGate = ({
  rollbackCheckSource,
  rollbackResilienceSource,
  evaluatedAtUtc,
}) => {
  if (!utc(evaluatedAtUtc)) fail('E7_RELEASE_RECONCILIATION_PRE_FENCE_TIME_INVALID');
  const rollbackCheck = parseReceiptDocument(rollbackCheckSource, 'ROLLBACK_CHECK');
  const rollbackResilience = parseReceiptDocument(rollbackResilienceSource, 'ROLLBACK_RESILIENCE');
  const receipts = [rollbackCheck.value, rollbackResilience.value];
  if (
    !sameObject(receipts[0].source, receipts[1].source) ||
    receipts[0].journal.ownerSha256 !== receipts[1].journal.ownerSha256 ||
    !sameObject(receipts[0].journal.intentIndex, receipts[1].journal.intentIndex) ||
    receipts[0].journal.candidateRootPrefix !== receipts[1].journal.candidateRootPrefix ||
    receipts[0].journal.reconciliationRootPrefix !== receipts[1].journal.reconciliationRootPrefix ||
    receipts[0].runtime.expectedStateSha256 !== receipts[1].runtime.expectedStateSha256 ||
    receipts[0].runtime.observedStateSha256 !== receipts[1].runtime.observedStateSha256 ||
    receipts.some(
      (receipt) =>
        receipt.originalJobConclusion !== 'SUCCESS' ||
        receipt.recoveryAction !== 'VERIFIED_NOOP' ||
        receipt.eligibleForFence !== true,
    ) ||
    Date.parse(receipts[1].startedAtUtc) < Date.parse(receipts[0].completedAtUtc) ||
    Date.parse(evaluatedAtUtc) < Date.parse(receipts[1].completedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_PRE_FENCE_NOT_ELIGIBLE');
  }
  const reconciliationJournalAuthority = createReleaseReconciliationJournalAuthority({
    rollbackCheckReceipt: receipts[0],
    rollbackResilienceReceipt: receipts[1],
  });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_PRE_FENCE_GATE',
    status: 'ALLOW_FENCE',
    source: { ...receipts[0].source },
    artifactName: STAGE7_RELEASE_RECONCILIATION_ARTIFACT,
    artifactEntries: [...STAGE7_RELEASE_RECONCILIATION_FILES],
    receiptBindings: {
      rollbackCheck: rollbackCheck.binding,
      rollbackResilience: rollbackResilience.binding,
    },
    requiredJobConclusions: {
      rollbackCheck: 'SUCCESS',
      rollbackResilience: 'SUCCESS',
    },
    candidateRootPrefix: receipts[0].journal.candidateRootPrefix,
    reconciliationRootPrefix: receipts[0].journal.reconciliationRootPrefix,
    intentCommitment: {
      intentSha256: receipts[0].journal.intentIndex.intentSha256,
      bindingsSha256: receipts[0].journal.intentIndex.bindingsSha256,
      rawSha256: receipts[0].journal.ownerIndex.intentRawSha256,
      bytes: receipts[0].journal.ownerIndex.intentBytes,
      chunkCount: receipts[0].journal.ownerIndex.intentChunks.length,
      chunksSha256: receipts[0].journal.ownerIndex.intentChunksSha256,
    },
    intentIndex: {
      ...receipts[0].journal.intentIndex,
      bindings: receipts[0].journal.intentIndex.bindings.map((binding) => ({ ...binding })),
    },
    reconciliationJournalAuthority,
    smokeAuthorizationUsages: reconciliationJournalAuthority.smokeAuthorizationUsages.map(
      (usage) => ({ ...usage, requestCounts: { ...usage.requestCounts } }),
    ),
    runtime: {
      state: 'EXACT_CANDIDATE_N',
      expectedStateSha256: receipts[0].runtime.expectedStateSha256,
      observedStateSha256: receipts[0].runtime.observedStateSha256,
    },
    publicationPolicy: 'FENCE_BEFORE_PUBLICATION_FORWARD_CONVERGE_OR_BLOCK',
    evaluatedAtUtc,
    containsSensitiveData: false,
  };
  return { ...body, gateSha256: objectSha256(body) };
};

export const validateReleasePreFenceGate = (
  value,
  { rollbackCheckSource, rollbackResilienceSource },
) => {
  const expected = createReleasePreFenceGate({
    rollbackCheckSource,
    rollbackResilienceSource,
    evaluatedAtUtc: value?.evaluatedAtUtc,
  });
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'source',
      'artifactName',
      'artifactEntries',
      'receiptBindings',
      'requiredJobConclusions',
      'candidateRootPrefix',
      'reconciliationRootPrefix',
      'intentCommitment',
      'intentIndex',
      'reconciliationJournalAuthority',
      'smokeAuthorizationUsages',
      'runtime',
      'publicationPolicy',
      'evaluatedAtUtc',
      'containsSensitiveData',
      'gateSha256',
    ]) ||
    !exactKeys(value.receiptBindings, ['rollbackCheck', 'rollbackResilience']) ||
    !validateReceiptBinding(value.receiptBindings.rollbackCheck, 'ROLLBACK_CHECK') ||
    !validateReceiptBinding(value.receiptBindings.rollbackResilience, 'ROLLBACK_RESILIENCE') ||
    value.gateSha256 !== objectSha256(withoutDigest(value, 'gateSha256')) ||
    !sameObject(value, expected)
  ) {
    fail('E7_RELEASE_RECONCILIATION_PRE_FENCE_GATE_INVALID');
  }
  return value;
};

const isPrereleaseTag = (releaseTag) => releaseTag.includes('-rc.');

export const validateReleasePublicationExpectation = (value) => {
  if (
    !exactKeys(value, [
      'source',
      'publicationPlanSha256',
      'releaseName',
      'notesSha256',
      'prerelease',
      'asset',
    ]) ||
    validateReleaseReconciliationSource(value.source) !== value.source ||
    !SHA256.test(value.publicationPlanSha256 ?? '') ||
    value.releaseName !== value.source.releaseTag ||
    !SHA256.test(value.notesSha256 ?? '') ||
    value.prerelease !== isPrereleaseTag(value.source.releaseTag) ||
    !exactKeys(value.asset, ['name', 'sha256', 'bytes', 'contentType']) ||
    value.asset.name !== 'candidate-manifest.json' ||
    !SHA256.test(value.asset.sha256 ?? '') ||
    !Number.isSafeInteger(value.asset.bytes) ||
    value.asset.bytes < 2 ||
    value.asset.bytes > MAX_DOCUMENT_BYTES ||
    value.asset.contentType !== 'application/json'
  ) {
    fail('E7_RELEASE_RECONCILIATION_PUBLICATION_EXPECTATION_INVALID');
  }
  return value;
};

const validPublicationAsset = (value) =>
  exactKeys(value, ['id', 'name', 'state', 'digest', 'size', 'contentType']) &&
  Number.isSafeInteger(value.id) &&
  value.id > 0 &&
  typeof value.name === 'string' &&
  /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u.test(value.name) &&
  typeof value.state === 'string' &&
  /^[a-z_]{2,32}$/u.test(value.state) &&
  typeof value.digest === 'string' &&
  /^sha256:[0-9a-f]{64}$/u.test(value.digest) &&
  Number.isSafeInteger(value.size) &&
  value.size >= 0 &&
  typeof value.contentType === 'string' &&
  /^[a-z0-9.+-]+\/[a-z0-9.+-]+$/u.test(value.contentType);

export const validateReleasePublicationObservation = (value) => {
  const tagValid =
    value?.tag === null ||
    (exactKeys(value?.tag, ['name', 'objectType', 'commitSha']) &&
      RELEASE_TAG.test(value.tag.name ?? '') &&
      ['commit', 'tag'].includes(value.tag.objectType) &&
      SHA.test(value.tag.commitSha ?? ''));
  const releaseValid =
    value?.release === null ||
    (exactKeys(value?.release, [
      'id',
      'tagName',
      'targetCommitish',
      'name',
      'bodySha256',
      'draft',
      'prerelease',
      'assets',
    ]) &&
      Number.isSafeInteger(value.release.id) &&
      value.release.id > 0 &&
      RELEASE_TAG.test(value.release.tagName ?? '') &&
      typeof value.release.targetCommitish === 'string' &&
      /^[A-Za-z0-9._/-]{1,255}$/u.test(value.release.targetCommitish) &&
      typeof value.release.name === 'string' &&
      value.release.name.length >= 1 &&
      value.release.name.length <= 128 &&
      !/[\r\n\0]/u.test(value.release.name) &&
      SHA256.test(value.release.bodySha256 ?? '') &&
      typeof value.release.draft === 'boolean' &&
      typeof value.release.prerelease === 'boolean' &&
      Array.isArray(value.release.assets) &&
      value.release.assets.length <= 32 &&
      value.release.assets.every(validPublicationAsset));
  if (!exactKeys(value, ['tag', 'release']) || !tagValid || !releaseValid) {
    fail('E7_RELEASE_RECONCILIATION_PUBLICATION_OBSERVATION_INVALID');
  }
  return value;
};

const classificationPolicy = (state) => {
  if (state === 'ABSENT') {
    return {
      decision: 'CREATE_EXACT_RELEASE_AND_ASSET',
      permittedOperations: ['CREATE_EXACT_RELEASE', 'UPLOAD_EXACT_ASSET'],
      externalWritesRequired: 2,
    };
  }
  if (state === 'PARTIAL') {
    return {
      decision: 'UPLOAD_MISSING_EXACT_ASSET',
      permittedOperations: ['UPLOAD_EXACT_ASSET'],
      externalWritesRequired: 1,
    };
  }
  if (state === 'EXACT') {
    return { decision: 'NOOP_VERIFIED', permittedOperations: [], externalWritesRequired: 0 };
  }
  return { decision: 'BLOCK_NO_MUTATION', permittedOperations: [], externalWritesRequired: 0 };
};

export const classifyReleasePublicationState = ({ expected, observation }) => {
  validateReleasePublicationExpectation(expected);
  validateReleasePublicationObservation(observation);
  const reasons = [];
  const tagExact =
    observation.tag !== null &&
    observation.tag.name === expected.source.releaseTag &&
    observation.tag.objectType === 'commit' &&
    observation.tag.commitSha === expected.source.candidateSha;
  if (observation.tag === null) reasons.push('TAG_ABSENT');
  else {
    if (observation.tag.name !== expected.source.releaseTag) reasons.push('TAG_NAME_CONFLICT');
    if (observation.tag.objectType !== 'commit') reasons.push('TAG_TYPE_CONFLICT');
    if (observation.tag.commitSha !== expected.source.candidateSha) {
      reasons.push('TAG_TARGET_CONFLICT');
    }
  }

  let state;
  if (!tagExact) state = 'CONFLICT';
  else if (observation.release === null) {
    state = 'ABSENT';
    reasons.push('RELEASE_ABSENT');
  } else {
    const release = observation.release;
    if (release.tagName !== expected.source.releaseTag) reasons.push('RELEASE_TAG_CONFLICT');
    if (release.targetCommitish !== expected.source.candidateSha) {
      reasons.push('RELEASE_TARGET_CONFLICT');
    }
    if (release.name !== expected.releaseName) reasons.push('RELEASE_NAME_CONFLICT');
    if (release.bodySha256 !== expected.notesSha256) reasons.push('RELEASE_BODY_CONFLICT');
    if (release.draft !== false) reasons.push('RELEASE_DRAFT_CONFLICT');
    if (release.prerelease !== expected.prerelease) reasons.push('RELEASE_PRERELEASE_CONFLICT');
    const assetNames = release.assets.map(({ name }) => name);
    const assetIds = release.assets.map(({ id }) => id);
    if (new Set(assetNames).size !== assetNames.length) reasons.push('ASSET_NAME_DUPLICATE');
    if (new Set(assetIds).size !== assetIds.length) reasons.push('ASSET_ID_DUPLICATE');
    if (release.assets.length > 1) reasons.push('ASSET_SET_CONFLICT');
    const asset = release.assets[0];
    if (asset !== undefined) {
      if (asset.name !== expected.asset.name) reasons.push('ASSET_NAME_CONFLICT');
      if (asset.state !== 'uploaded') reasons.push('ASSET_STATE_CONFLICT');
      if (asset.digest !== `sha256:${expected.asset.sha256}`) reasons.push('ASSET_DIGEST_CONFLICT');
      if (asset.size !== expected.asset.bytes) reasons.push('ASSET_SIZE_CONFLICT');
      if (asset.contentType !== expected.asset.contentType) reasons.push('ASSET_TYPE_CONFLICT');
    }
    const conflicts = reasons.filter(
      (reason) => reason.endsWith('_CONFLICT') || reason.endsWith('_DUPLICATE'),
    );
    if (conflicts.length > 0) state = 'CONFLICT';
    else if (release.assets.length === 0) {
      state = 'PARTIAL';
      reasons.push('EXACT_ASSET_MISSING');
    } else state = 'EXACT';
  }

  if (!PUBLICATION_STATES.includes(state)) {
    fail('E7_RELEASE_RECONCILIATION_PUBLICATION_CLASSIFICATION_INVALID');
  }
  const policy = classificationPolicy(state);
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_PUBLICATION_CLASSIFICATION',
    status: state === 'CONFLICT' ? 'BLOCKED' : 'PASS',
    source: { ...expected.source },
    state,
    decision: policy.decision,
    reasonCodes: [...new Set(reasons)].toSorted(),
    expectedSha256: objectSha256(expected),
    observationSha256: objectSha256(observation),
    permittedOperations: policy.permittedOperations,
    externalWritesRequired: policy.externalWritesRequired,
    destructiveOperationsAllowed: false,
    recoveryMode: state === 'CONFLICT' ? 'EXPLICITLY_BLOCKED' : 'SAME_RUN_FORWARD_ONLY',
    containsSensitiveData: false,
  };
  return { ...body, classificationSha256: objectSha256(body) };
};

export const validateReleasePublicationClassification = (value, { expected, observation }) => {
  const classified = classifyReleasePublicationState({ expected, observation });
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'source',
      'state',
      'decision',
      'reasonCodes',
      'expectedSha256',
      'observationSha256',
      'permittedOperations',
      'externalWritesRequired',
      'destructiveOperationsAllowed',
      'recoveryMode',
      'containsSensitiveData',
      'classificationSha256',
    ]) ||
    value.classificationSha256 !== objectSha256(withoutDigest(value, 'classificationSha256')) ||
    !sameObject(value, classified)
  ) {
    fail('E7_RELEASE_RECONCILIATION_PUBLICATION_CLASSIFICATION_INVALID');
  }
  return value;
};
