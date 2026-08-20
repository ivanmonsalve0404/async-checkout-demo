import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import process from 'node:process';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { executeVersionedRollback } from './aws-operations.mjs';
import { canonicalJson, objectSha256 } from './core.mjs';
export { createReleaseReconciliationIntentFromSources } from './release-reconciliation-authority.mjs';
import {
  STAGE7_RELEASE_RECONCILIATION_SMOKE_USAGE_IDS,
  Stage7ReleaseReconciliationError,
  classifyReleasePublicationState,
  createReleaseReconciliationReceipt,
  createReleaseRollbackJournalOwner,
  validateReleasePublicationExpectation,
  validateReleasePublicationObservation,
  validateReleaseReconciliationIntent,
  validateReleaseReconciliationReceipt,
  validateReleaseReconciliationSmokeAuthorizationUsage,
  validateReleaseReconciliationSource,
  validateReleaseRollbackJournalOwner,
} from './release-reconciliation.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/([A-Za-z0-9+=,.@_/-]{1,512})$/u;
const SESSION_NAME = /^[A-Za-z0-9+=,.@_-]{2,64}$/u;
const AWS_REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const FUNCTION_NAME = /^[A-Za-z0-9-_]{1,64}$/u;
const ALIAS_NAME = /^[A-Za-z0-9-_]{1,128}$/u;
const VERSION_ID = /^[A-Za-z0-9._~+/=-]{1,1024}$/u;
const BUCKET_NAME = /^(?=.{3,63}$)(?![0-9]+(?:\.[0-9]+){3}$)[a-z0-9][a-z0-9.-]*[a-z0-9]$/u;
const DISTRIBUTION_ID = /^[A-Z0-9]{8,64}$/u;
const PHASES = Object.freeze(['ROLLBACK_CHECK', 'ROLLBACK_RESILIENCE']);
const MAX_PARAMETER_BYTES = 3900;
const MAX_INTENT_CHUNKS = 16;
const RUNTIME_PROOF_CHUNK_BYTES = 3000;
const MAX_RUNTIME_PROOF_CHUNKS = 16;
const MAX_RUNTIME_PROOF_PARAMETERS_PER_PHASE = 4 * (MAX_RUNTIME_PROOF_CHUNKS + 1);
const MAX_AWS_OUTPUT_BYTES = 32 * 1024 * 1024;
const MAX_JOURNAL_PARAMETERS =
  1 + MAX_INTENT_CHUNKS + PHASES.length + PHASES.length * MAX_RUNTIME_PROOF_PARAMETERS_PER_PHASE;
const MAX_SSM_PAGES = Math.ceil(MAX_JOURNAL_PARAMETERS / 10);
const AWS_TIMEOUT_MS = 20 * 60 * 1000;
const JOB_CONCLUSIONS = Object.freeze(['SUCCESS', 'FAILURE', 'CANCELLED', 'TIMED_OUT', 'SKIPPED']);
const ROLLBACK_INTENT_FILE_BINDINGS = Object.freeze([
  ['manifest', 'candidateManifest'],
  ['previous-manifest', 'previousReleaseManifest'],
  ['previous-api-contract-evidence', 'previousApiContractEvidence'],
  ['previous-pending-evidence', 'previousPendingEvidence'],
  ['previous-smoke-evidence', 'previousSmokeEvidence'],
  ['candidate-record', 'candidateRecord'],
  ['approval', 'approval'],
  ['approved-plan', 'releasePlan'],
  ['deployment-evidence', 'webDeployment'],
  ['aws-auth', 'awsAuth'],
  ['journal-role-effective-permissions', 'journalRoleEffectivePermissions'],
]);

export class Stage7ReleaseReconciliationExecutorError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseReconciliationExecutorError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseReconciliationExecutorError(
    code,
    cause === undefined ? undefined : { cause },
  );
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const withoutDigest = (value, field) => {
  const body = { ...value };
  delete body[field];
  return body;
};
const utc = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return false;
  return new Date(value).toISOString() === value;
};
const nowUtc = (clock) => {
  const value = clock();
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) fail('E7_RELEASE_RECONCILIATION_CLOCK_INVALID');
  return date.toISOString();
};
const parseDocument = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_AWS_OUTPUT_BYTES) fail(code);
  try {
    return { value: parseStrictJsonSource(bytes, { scanForbiddenData: false }), bytes };
  } catch (error) {
    fail(code, error);
  }
};
const sameObject = (left, right) => canonicalJson(left) === canonicalJson(right);
const phaseSlug = (phase) =>
  phase === 'ROLLBACK_CHECK' ? 'rollback-check' : 'rollback-resilience';
const terminalParameterName = (owner, phase) =>
  `${owner.reconciliationRootPrefix}/${phaseSlug(phase)}/terminal`;

const validateIntentDocumentBinding = (intent, label, document) => {
  const binding = intent.bindings.find((entry) => entry.label === label);
  if (
    binding?.sourceType !== 'JSON' ||
    binding.rawSha256 !== sha256(document.bytes) ||
    binding.canonicalSha256 !== objectSha256(document.value) ||
    binding.bytes !== document.bytes.length
  ) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_INTENT_BINDING_MISMATCH');
  }
  return document;
};
const validateRollbackIntentFileBindings = (intent, rollbackFlags) => {
  for (const [flag, label] of ROLLBACK_INTENT_FILE_BINDINGS) {
    const filename = rollbackFlags?.[flag];
    if (typeof filename !== 'string' || filename === '') {
      fail('E7_RELEASE_RECONCILIATION_CONVERGENCE_INPUT_INVALID');
    }
    validateIntentDocumentBinding(
      intent,
      label,
      parseDocument(
        readFileSync(filename),
        'E7_RELEASE_RECONCILIATION_RUNTIME_INTENT_SOURCE_INVALID',
      ),
    );
  }
};

const validateStore = (store) => {
  const keys = Object.keys(store ?? {})
    .toSorted()
    .join('\0');
  const minimal = ['get', 'putImmutable', 'list'].toSorted().join('\0');
  const rooted = ['candidateRootPrefix', 'reconciliationRootPrefix', 'get', 'putImmutable', 'list']
    .toSorted()
    .join('\0');
  if (
    !object(store) ||
    ![minimal, rooted].includes(keys) ||
    (store.candidateRootPrefix !== undefined &&
      !/^\/checkout\/stage7\/rollback\/[0-9a-f]{40}$/u.test(store.candidateRootPrefix)) ||
    (store.reconciliationRootPrefix !== undefined &&
      (!/^\/checkout\/stage7\/rollback\/[0-9a-f]{40}\/release-reconciliation\/[1-9][0-9]{0,19}$/u.test(
        store.reconciliationRootPrefix,
      ) ||
        !store.reconciliationRootPrefix.startsWith(
          `${store.candidateRootPrefix}/release-reconciliation/`,
        ))) ||
    !['get', 'putImmutable', 'list'].every((key) => typeof store[key] === 'function')
  ) {
    fail('E7_RELEASE_RECONCILIATION_STORE_INVALID');
  }
  return store;
};

const validateParameter = (value, expectedName = undefined) => {
  if (
    !exactKeys(value, [
      'name',
      'type',
      'value',
      'version',
      'lastModifiedAtUtc',
      'arn',
      'dataType',
    ]) ||
    (expectedName !== undefined && value.name !== expectedName) ||
    typeof value.name !== 'string' ||
    !value.name.startsWith('/checkout/stage7/rollback/') ||
    value.type !== 'String' ||
    typeof value.value !== 'string' ||
    Buffer.byteLength(value.value, 'utf8') > MAX_PARAMETER_BYTES ||
    value.version !== 1 ||
    !utc(value.lastModifiedAtUtc) ||
    typeof value.arn !== 'string' ||
    !value.arn.endsWith(`:parameter${value.name}`) ||
    value.dataType !== 'text'
  ) {
    fail('E7_RELEASE_RECONCILIATION_PARAMETER_INVALID');
  }
  return value;
};

const runtimeProofParameterPattern = (owner) => {
  const escaped = owner.runtimeProofRootPrefix.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  return new RegExp(
    `^${escaped}/(?:rollback-check|rollback-resilience)/(?:drift|smoke)/[0-9a-f]{64}/(?:index|chunk/[0-9]{4}-[0-9a-f]{64})$`,
    'u',
  );
};
const runtimeProofRoot = (owner, phase, proofKind, rawSha256) =>
  `${owner.runtimeProofRootPrefix}/${phaseSlug(phase)}/${proofKind.toLowerCase()}/${rawSha256}`;
const runtimeProofJournalReference = (index) => ({
  indexParameterName: index.indexParameterName,
  indexSha256: index.indexSha256,
  rawSha256: index.rawSha256,
  canonicalSha256: index.canonicalSha256,
  bytes: index.bytes,
  observedAtUtc: index.observedAtUtc,
  chunkCount: index.chunks.length,
  chunksSha256: index.chunksSha256,
});
const validateRuntimeProofIndex = (value, { owner, phase, proofKind, convergenceSha256 }) => {
  const root = runtimeProofRoot(owner, phase, proofKind, value?.rawSha256);
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'phase',
      'proofKind',
      'source',
      'ownerSha256',
      'convergenceSha256',
      'indexParameterName',
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'observedAtUtc',
      'chunks',
      'chunksSha256',
      'containsSensitiveData',
      'indexSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX' ||
    value.status !== 'RAW_BYTES_DURABLE' ||
    value.phase !== phase ||
    value.proofKind !== proofKind ||
    !sameObject(value.source, owner.source) ||
    value.ownerSha256 !== owner.ownerSha256 ||
    (convergenceSha256 !== undefined && value.convergenceSha256 !== convergenceSha256) ||
    !SHA256.test(value.convergenceSha256 ?? '') ||
    value.indexParameterName !== `${root}/index` ||
    ![value.rawSha256, value.canonicalSha256, value.chunksSha256].every((digest) =>
      SHA256.test(digest ?? ''),
    ) ||
    !Number.isSafeInteger(value.bytes) ||
    value.bytes < 2 ||
    value.bytes > RUNTIME_PROOF_CHUNK_BYTES * MAX_RUNTIME_PROOF_CHUNKS ||
    !utc(value.observedAtUtc) ||
    !Array.isArray(value.chunks) ||
    value.chunks.length < 1 ||
    value.chunks.length > MAX_RUNTIME_PROOF_CHUNKS ||
    value.chunks.some(
      (chunk, index) =>
        !exactKeys(chunk, ['sequence', 'parameterName', 'rawSha256', 'bytes']) ||
        chunk.sequence !== index + 1 ||
        chunk.parameterName !==
          `${root}/chunk/${String(index + 1).padStart(4, '0')}-${chunk.rawSha256}` ||
        !SHA256.test(chunk.rawSha256 ?? '') ||
        !Number.isSafeInteger(chunk.bytes) ||
        chunk.bytes < 1 ||
        chunk.bytes > RUNTIME_PROOF_CHUNK_BYTES,
    ) ||
    value.chunks.reduce((total, chunk) => total + chunk.bytes, 0) !== value.bytes ||
    value.chunksSha256 !== objectSha256(value.chunks) ||
    value.containsSensitiveData !== false ||
    value.indexSha256 !== objectSha256(withoutDigest(value, 'indexSha256')) ||
    Buffer.byteLength(JSON.stringify(value), 'utf8') > MAX_PARAMETER_BYTES
  ) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_INVALID');
  }
  return value;
};
const runtimeProofPlan = ({ owner, phase, proofKind, proof, convergenceSha256 }) => {
  const text = proof.bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(proof.bytes)) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_BYTES_INVALID');
  }
  const values = [];
  let current = '';
  for (const character of text) {
    if (Buffer.byteLength(current + character, 'utf8') > RUNTIME_PROOF_CHUNK_BYTES) {
      if (current === '') fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_CHUNK_INVALID');
      values.push(current);
      current = character;
    } else current += character;
  }
  if (current !== '') values.push(current);
  if (values.length < 1 || values.length > MAX_RUNTIME_PROOF_CHUNKS) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_CHUNK_COUNT_INVALID');
  }
  const root = runtimeProofRoot(owner, phase, proofKind, proof.rawSha256);
  const chunks = values.map((value, index) => {
    const bytes = Buffer.from(value, 'utf8');
    const rawSha256 = sha256(bytes);
    return {
      sequence: index + 1,
      parameterName: `${root}/chunk/${String(index + 1).padStart(4, '0')}-${rawSha256}`,
      rawSha256,
      bytes: bytes.length,
    };
  });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX',
    status: 'RAW_BYTES_DURABLE',
    phase,
    proofKind,
    source: owner.source,
    ownerSha256: owner.ownerSha256,
    convergenceSha256,
    indexParameterName: `${root}/index`,
    rawSha256: proof.rawSha256,
    canonicalSha256: proof.canonicalSha256,
    bytes: proof.bytes.length,
    observedAtUtc: proof.observedAtUtc,
    chunks,
    chunksSha256: objectSha256(chunks),
    containsSensitiveData: false,
  };
  const index = validateRuntimeProofIndex(
    { ...body, indexSha256: objectSha256(body) },
    { owner, phase, proofKind, convergenceSha256 },
  );
  return { index, values };
};
const validateRuntimeProofJournalParameter = (owner, parameter) => {
  if (!runtimeProofParameterPattern(owner).test(parameter.name)) {
    fail('E7_RELEASE_RECONCILIATION_JOURNAL_UNEXPECTED_ENTRY');
  }
  if (parameter.name.includes('/chunk/')) {
    const rawSha256 = parameter.name.slice(parameter.name.lastIndexOf('-') + 1);
    if (sha256(Buffer.from(parameter.value, 'utf8')) !== rawSha256) {
      fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_CHUNK_MISMATCH');
    }
    return parameter;
  }
  const match = parameter.name.match(
    /\/(rollback-check|rollback-resilience)\/(drift|smoke)\/([0-9a-f]{64})\/index$/u,
  );
  const phase = match?.[1] === 'rollback-check' ? 'ROLLBACK_CHECK' : 'ROLLBACK_RESILIENCE';
  const proofKind = match?.[2]?.toUpperCase();
  const document = parseDocument(
    parameter.value,
    'E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_INVALID',
  );
  const index = validateRuntimeProofIndex(document.value, { owner, phase, proofKind });
  if (index.rawSha256 !== match?.[3]) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_INVALID');
  }
  return parameter;
};

const intentChunkPlan = (intent) => {
  validateReleaseReconciliationIntent(intent);
  const serialized = canonicalJson(intent);
  const chunks = [];
  let current = '';
  for (const character of serialized) {
    if (Buffer.byteLength(current + character, 'utf8') > 3000) {
      if (current === '') fail('E7_RELEASE_RECONCILIATION_INTENT_CHUNK_INVALID');
      chunks.push(current);
      current = character;
    } else current += character;
  }
  if (current !== '') chunks.push(current);
  if (chunks.length < 1 || chunks.length > MAX_INTENT_CHUNKS) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_CHUNK_COUNT_INVALID');
  }
  const root = `/checkout/stage7/rollback/${intent.source.candidateSha}/release-reconciliation/${intent.source.runId}`;
  const bindings = chunks.map((value, index) => ({
    index: index + 1,
    parameterName: `${root}/intent/${String(index + 1).padStart(4, '0')}`,
    rawSha256: sha256(Buffer.from(value, 'utf8')),
    bytes: Buffer.byteLength(value, 'utf8'),
  }));
  const bytes = Buffer.from(serialized, 'utf8');
  return { serialized, bytes, chunks, bindings };
};

const readOwnerFromParameter = (parameter, intent, plan) => {
  validateParameter(
    parameter,
    plan.bindings[0].parameterName.replace(/\/intent\/0001$/u, '/owner'),
  );
  const document = parseDocument(
    parameter.value,
    'E7_RELEASE_RECONCILIATION_OWNER_DOCUMENT_INVALID',
  );
  const owner = validateReleaseRollbackJournalOwner(document.value);
  if (
    !sameObject(owner.source, intent.source) ||
    owner.intentBindingsSha256 !== intent.bindingsSha256 ||
    owner.intentSha256 !== intent.intentSha256 ||
    owner.intentRawSha256 !== sha256(plan.bytes) ||
    owner.intentBytes !== plan.bytes.length ||
    !sameObject(owner.intentChunks, plan.bindings) ||
    owner.parameterName !== parameter.name
  ) {
    fail('E7_RELEASE_RECONCILIATION_OWNER_CONFLICT');
  }
  return owner;
};

const listJournal = async (store, rootPrefix) => {
  const parameters = await store.list(rootPrefix);
  if (
    !Array.isArray(parameters) ||
    parameters.length > MAX_JOURNAL_PARAMETERS ||
    parameters.some((parameter) => {
      try {
        validateParameter(parameter);
      } catch {
        return true;
      }
      return !parameter.name.startsWith(`${rootPrefix}/`);
    })
  ) {
    fail('E7_RELEASE_RECONCILIATION_JOURNAL_SCAN_INVALID');
  }
  const sorted = parameters.toSorted((left, right) => left.name.localeCompare(right.name));
  if (new Set(sorted.map(({ name }) => name)).size !== sorted.length) {
    fail('E7_RELEASE_RECONCILIATION_JOURNAL_SCAN_DUPLICATE');
  }
  return sorted;
};

const allowedJournalNames = (owner) =>
  new Set([
    owner.parameterName,
    ...owner.intentChunks.map(({ parameterName }) => parameterName),
    terminalParameterName(owner, 'ROLLBACK_CHECK'),
    terminalParameterName(owner, 'ROLLBACK_RESILIENCE'),
  ]);

const rejectUnexpectedJournalNames = (owner, parameters) => {
  const allowed = allowedJournalNames(owner);
  for (const parameter of parameters) {
    if (allowed.has(parameter.name)) continue;
    if (!parameter.name.startsWith(`${owner.runtimeProofRootPrefix}/`)) {
      fail('E7_RELEASE_RECONCILIATION_JOURNAL_UNEXPECTED_ENTRY');
    }
    validateRuntimeProofJournalParameter(owner, parameter);
  }
};

const validateExistingTerminalEntries = (owner, parameters) => {
  for (const phase of PHASES) {
    const name = terminalParameterName(owner, phase);
    const parameter = parameters.find((entry) => entry.name === name);
    if (parameter === undefined) continue;
    validateParameter(parameter, name);
    const document = parseDocument(
      parameter.value,
      'E7_RELEASE_RECONCILIATION_TERMINAL_DOCUMENT_INVALID',
    );
    const terminal = validateReleaseReconciliationTerminal(document.value);
    if (
      terminal.phase !== phase ||
      !sameObject(terminal.source, owner.source) ||
      terminal.ownerSha256 !== owner.ownerSha256
    ) {
      fail('E7_RELEASE_RECONCILIATION_TERMINAL_CONFLICT');
    }
  }
};

const reconstructIntentFromJournal = ({ owner, parameters, expectedIntent = undefined }) => {
  const chunks = owner.intentChunks.map((binding) => {
    const parameter = parameters.find(({ name }) => name === binding.parameterName);
    if (parameter === undefined) fail('E7_RELEASE_RECONCILIATION_INTENT_CHUNK_MISSING');
    validateParameter(parameter, binding.parameterName);
    const bytes = Buffer.from(parameter.value, 'utf8');
    if (bytes.length !== binding.bytes || sha256(bytes) !== binding.rawSha256) {
      fail('E7_RELEASE_RECONCILIATION_INTENT_CHUNK_MISMATCH');
    }
    return parameter.value;
  });
  const bytes = Buffer.from(chunks.join(''), 'utf8');
  if (bytes.length !== owner.intentBytes || sha256(bytes) !== owner.intentRawSha256) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_BYTES_MISMATCH');
  }
  const document = parseDocument(bytes, 'E7_RELEASE_RECONCILIATION_INTENT_DOCUMENT_INVALID');
  const intent = validateReleaseReconciliationIntent(document.value);
  if (
    intent.intentSha256 !== owner.intentSha256 ||
    intent.bindingsSha256 !== owner.intentBindingsSha256 ||
    !sameObject(intent.source, owner.source) ||
    (expectedIntent !== undefined && !sameObject(intent, expectedIntent))
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_OWNER_MISMATCH');
  }
  return intent;
};

export const openReleaseRollbackJournal = async ({ intent, store, clock = () => new Date() }) => {
  validateReleaseReconciliationIntent(intent);
  validateStore(store);
  const source = intent.source;
  const plan = intentChunkPlan(intent);
  const provisional = createReleaseRollbackJournalOwner({
    source,
    intent,
    intentRawSha256: sha256(plan.bytes),
    intentBytes: plan.bytes.length,
    intentChunks: plan.bindings,
    createdAtUtc: nowUtc(clock),
  });
  const before = await listJournal(store, provisional.reconciliationRootPrefix);
  const existingOwner = before.find(({ name }) => name === provisional.parameterName) ?? null;
  let owner;
  let idempotent = existingOwner !== null;
  if (existingOwner === null) {
    if (before.length !== 0) fail('E7_RELEASE_RECONCILIATION_UNOWNED_JOURNAL_BLOCKED');
    const written = await store.putImmutable({
      name: provisional.parameterName,
      value: JSON.stringify(provisional),
    });
    validateParameter(written, provisional.parameterName);
    owner = readOwnerFromParameter(written, intent, plan);
    idempotent = false;
  } else owner = readOwnerFromParameter(existingOwner, intent, plan);
  rejectUnexpectedJournalNames(owner, before);
  validateExistingTerminalEntries(owner, before);

  for (let index = 0; index < plan.bindings.length; index += 1) {
    const binding = plan.bindings[index];
    const existing = await store.get(binding.parameterName);
    if (existing !== null) {
      validateParameter(existing, binding.parameterName);
      const bytes = Buffer.from(existing.value, 'utf8');
      if (bytes.length !== binding.bytes || sha256(bytes) !== binding.rawSha256) {
        fail('E7_RELEASE_RECONCILIATION_INTENT_CHUNK_CONFLICT');
      }
      continue;
    }
    const written = await store.putImmutable({
      name: binding.parameterName,
      value: plan.chunks[index],
    });
    validateParameter(written, binding.parameterName);
    const bytes = Buffer.from(written.value, 'utf8');
    if (bytes.length !== binding.bytes || sha256(bytes) !== binding.rawSha256) {
      fail('E7_RELEASE_RECONCILIATION_INTENT_CHUNK_WRITE_MISMATCH');
    }
  }
  const after = await listJournal(store, owner.reconciliationRootPrefix);
  rejectUnexpectedJournalNames(owner, after);
  validateExistingTerminalEntries(owner, after);
  const reconstructed = reconstructIntentFromJournal({
    owner,
    parameters: after,
    expectedIntent: intent,
  });
  if (
    !idempotent &&
    (after.length !== owner.intentChunks.length + 1 ||
      !after.every(({ name }) =>
        [
          owner.parameterName,
          ...owner.intentChunks.map(({ parameterName }) => parameterName),
        ].includes(name),
      ))
  ) {
    fail('E7_RELEASE_RECONCILIATION_OWNER_RACE_DETECTED');
  }
  return {
    owner,
    intent: reconstructed,
    idempotent,
    journalEntryCount: after.length,
    journalScanSha256: objectSha256(after),
  };
};

export const requireReleaseRollbackJournalOwner = async ({ intent, store }) => {
  validateReleaseReconciliationIntent(intent);
  validateStore(store);
  const source = intent.source;
  const plan = intentChunkPlan(intent);
  const reconciliationRootPrefix = `/checkout/stage7/rollback/${source.candidateSha}/release-reconciliation/${source.runId}`;
  const parameterName = `${reconciliationRootPrefix}/owner`;
  const parameter = await store.get(parameterName);
  if (parameter === null) fail('E7_RELEASE_RECONCILIATION_OWNER_REQUIRED');
  const owner = readOwnerFromParameter(parameter, intent, plan);
  const parameters = await listJournal(store, owner.reconciliationRootPrefix);
  rejectUnexpectedJournalNames(owner, parameters);
  validateExistingTerminalEntries(owner, parameters);
  const reconstructed = reconstructIntentFromJournal({
    owner,
    parameters,
    expectedIntent: intent,
  });
  return { owner, intent: reconstructed, parameters };
};

const candidateStateProjection = (candidateRecord, source) => {
  const target = candidateRecord?.target;
  const resources = candidateRecord?.resources;
  if (
    candidateRecord?.kind !== 'VERSIONED_ROLLBACK_CANDIDATE' ||
    candidateRecord?.recordSha256 !==
      objectSha256(withoutDigest(candidateRecord, 'recordSha256')) ||
    target?.candidateSha !== source.candidateSha ||
    target?.releaseId !== source.releaseId ||
    !exactKeys(resources, ['api', 'worker', 'web']) ||
    !Array.isArray(resources.web?.objects)
  ) {
    fail('E7_RELEASE_RECONCILIATION_CANDIDATE_RECORD_INVALID');
  }
  const alias = (value) => ({
    functionName: value?.functionName,
    aliasName: value?.aliasName,
    version: value?.version,
  });
  const objects = resources.web.objects
    .map(({ key, contentSha256, bytes }) => ({ key, contentSha256, bytes }))
    .toSorted((left, right) => left.key.localeCompare(right.key));
  if (
    [alias(resources.api), alias(resources.worker)].some(
      (value) =>
        !exactKeys(value, ['functionName', 'aliasName', 'version']) ||
        Object.values(value).some((entry) => typeof entry !== 'string' || entry === ''),
    ) ||
    objects.length < 1 ||
    objects.some(
      (entry) =>
        typeof entry.key !== 'string' ||
        !SHA256.test(entry.contentSha256 ?? '') ||
        !Number.isSafeInteger(entry.bytes) ||
        entry.bytes < 1,
    )
  ) {
    fail('E7_RELEASE_RECONCILIATION_CANDIDATE_STATE_INVALID');
  }
  return {
    candidateSha: source.candidateSha,
    releaseId: source.releaseId,
    aliases: { api: alias(resources.api), worker: alias(resources.worker) },
    web: {
      bucketName: resources.web.bucketName,
      distributionId: resources.web.distributionId,
      objects,
    },
  };
};

const observedStateProjection = (transition, source) => {
  const aliasesValid =
    exactKeys(transition?.aliases, ['api', 'worker']) &&
    [transition.aliases.api, transition.aliases.worker].every(
      (alias) =>
        exactKeys(alias, ['functionName', 'aliasName', 'version']) &&
        FUNCTION_NAME.test(alias.functionName ?? '') &&
        ALIAS_NAME.test(alias.aliasName ?? '') &&
        /^[1-9][0-9]*$/u.test(alias.version ?? ''),
    );
  const webObjectsValid =
    Array.isArray(transition?.web?.objects) &&
    transition.web.objects.length >= 1 &&
    new Set(transition.web.objects.map(({ key }) => key)).size === transition.web.objects.length &&
    transition.web.objects.every(
      (entry) =>
        exactKeys(entry, ['key', 'sourceVersionId', 'activeVersionId', 'contentSha256', 'bytes']) &&
        typeof entry.key === 'string' &&
        entry.key !== '' &&
        !entry.key.startsWith('/') &&
        !entry.key.includes('..') &&
        VERSION_ID.test(entry.sourceVersionId ?? '') &&
        VERSION_ID.test(entry.activeVersionId ?? '') &&
        SHA256.test(entry.contentSha256 ?? '') &&
        Number.isSafeInteger(entry.bytes) &&
        entry.bytes >= 1,
    );
  const invalidationApplied = transition?.decision === 'APPLIED_AND_VERIFIED';
  const invalidationValid =
    exactKeys(transition?.web?.invalidation, ['status', 'idSha256', 'paths']) &&
    transition.web.invalidation.status === (invalidationApplied ? 'COMPLETED' : 'NOT_REQUIRED') &&
    (invalidationApplied
      ? SHA256.test(transition.web.invalidation.idSha256 ?? '')
      : transition.web.invalidation.idSha256 === null) &&
    Array.isArray(transition.web.invalidation.paths) &&
    (invalidationApplied
      ? transition.web.invalidation.paths.length >= 1 &&
        transition.web.invalidation.paths.every(
          (entry) => typeof entry === 'string' && entry.startsWith('/') && !entry.includes('..'),
        )
      : transition.web.invalidation.paths.length === 0);
  const pending = transition?.pendingIntegrity;
  const pendingValid =
    exactKeys(pending, [
      'status',
      'beforeSnapshotSha256',
      'afterSnapshotSha256',
      'correlationEvidenceSha256',
      'trackedBefore',
      'stillPending',
      'reconciled',
      'orphaned',
      'duplicateEffects',
      'lostFacts',
      'terminalStatusCounts',
    ]) &&
    pending.status === 'PASS' &&
    [
      pending.beforeSnapshotSha256,
      pending.afterSnapshotSha256,
      pending.correlationEvidenceSha256,
    ].every((value) => SHA256.test(value ?? '')) &&
    [pending.trackedBefore, pending.stillPending, pending.reconciled].every(
      (value) => Number.isSafeInteger(value) && value >= 0,
    ) &&
    pending.trackedBefore === pending.stillPending + pending.reconciled &&
    pending.orphaned === 0 &&
    pending.duplicateEffects === 0 &&
    pending.lostFacts === 0 &&
    exactKeys(pending.terminalStatusCounts, ['APPROVED', 'DECLINED', 'VOIDED', 'ERROR']) &&
    Object.values(pending.terminalStatusCounts).every(
      (value) => Number.isSafeInteger(value) && value >= 0,
    ) &&
    Object.values(pending.terminalStatusCounts).reduce((total, value) => total + value, 0) ===
      pending.reconciled;
  if (
    !exactKeys(transition, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'direction',
      'decision',
      'planSha256',
      'startedAtUtc',
      'completedAtUtc',
      'fromReleaseId',
      'toReleaseId',
      'aliases',
      'web',
      'pendingIntegrity',
      'dataFactsSha256',
      'dataFactsChanged',
      'dataRollbackPerformed',
      'stacksDeleted',
      'containsSensitiveData',
      'transitionSha256',
    ]) ||
    transition.schemaVersion !== 1 ||
    transition.stage !== 7 ||
    transition?.kind !== 'VERSIONED_ROLLBACK_AWS_TRANSITION' ||
    transition?.status !== 'AWS_VERIFIED_PENDING_READ_SMOKE' ||
    transition?.direction !== 'REPROMOTE_CANDIDATE' ||
    !['ALREADY_APPLIED_AND_VERIFIED', 'APPLIED_AND_VERIFIED'].includes(transition.decision) ||
    !SHA256.test(transition.planSha256 ?? '') ||
    !utc(transition.startedAtUtc) ||
    !utc(transition.completedAtUtc) ||
    Date.parse(transition.completedAtUtc) < Date.parse(transition.startedAtUtc) ||
    !RELEASE_ID.test(transition.fromReleaseId ?? '') ||
    transition.toReleaseId !== source.releaseId ||
    !aliasesValid ||
    !exactKeys(transition.web, ['bucketName', 'distributionId', 'objects', 'invalidation']) ||
    !BUCKET_NAME.test(transition.web.bucketName ?? '') ||
    !DISTRIBUTION_ID.test(transition.web.distributionId ?? '') ||
    !webObjectsValid ||
    !invalidationValid ||
    !pendingValid ||
    !SHA256.test(transition.dataFactsSha256 ?? '') ||
    transition.dataFactsChanged !== false ||
    transition.dataRollbackPerformed !== false ||
    transition.stacksDeleted !== 0 ||
    transition.containsSensitiveData !== false ||
    transition.transitionSha256 !== objectSha256(withoutDigest(transition, 'transitionSha256')) ||
    transition.pendingIntegrity.status !== 'PASS'
  ) {
    fail('E7_RELEASE_RECONCILIATION_TRANSITION_INVALID');
  }
  const objects = transition.web.objects
    .map(({ key, contentSha256, bytes }) => ({ key, contentSha256, bytes }))
    .toSorted((left, right) => left.key.localeCompare(right.key));
  return {
    candidateSha: source.candidateSha,
    releaseId: source.releaseId,
    aliases: transition.aliases,
    web: {
      bucketName: transition.web.bucketName,
      distributionId: transition.web.distributionId,
      objects,
    },
  };
};

export const validateReleaseRuntimeConvergence = (value) => {
  let observedStateSha256 = null;
  try {
    observedStateSha256 = objectSha256(observedStateProjection(value?.transition, value?.source));
  } catch {
    fail('E7_RELEASE_RECONCILIATION_CONVERGENCE_INVALID');
  }
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'phase',
      'source',
      'owner',
      'intent',
      'recoveryAction',
      'transition',
      'transitionBinding',
      'expectedStateSha256',
      'observedStateSha256',
      'startedAtUtc',
      'completedAtUtc',
      'containsSensitiveData',
      'convergenceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RUNTIME_CONVERGENCE' ||
    value.status !== 'EXACT_CANDIDATE_N_VERIFIED' ||
    !PHASES.includes(value.phase) ||
    validateReleaseReconciliationSource(value.source) !== value.source ||
    validateReleaseRollbackJournalOwner(value.owner) !== value.owner ||
    validateReleaseReconciliationIntent(value.intent) !== value.intent ||
    !sameObject(value.source, value.owner.source) ||
    !sameObject(value.source, value.intent.source) ||
    value.owner.intentSha256 !== value.intent.intentSha256 ||
    !['VERIFIED_NOOP', 'REPROMOTED_CANDIDATE'].includes(value.recoveryAction) ||
    value.recoveryAction !==
      (value.transition?.decision === 'ALREADY_APPLIED_AND_VERIFIED'
        ? 'VERIFIED_NOOP'
        : 'REPROMOTED_CANDIDATE') ||
    !exactKeys(value.transitionBinding, ['rawSha256', 'canonicalSha256', 'bytes']) ||
    !SHA256.test(value.transitionBinding.rawSha256 ?? '') ||
    value.transitionBinding.canonicalSha256 !== objectSha256(value.transition) ||
    !Number.isSafeInteger(value.transitionBinding.bytes) ||
    value.transitionBinding.bytes < 2 ||
    !SHA256.test(value.expectedStateSha256 ?? '') ||
    value.observedStateSha256 !== value.expectedStateSha256 ||
    value.observedStateSha256 !== observedStateSha256 ||
    !utc(value.startedAtUtc) ||
    !utc(value.completedAtUtc) ||
    value.startedAtUtc !== value.transition.startedAtUtc ||
    value.completedAtUtc !== value.transition.completedAtUtc ||
    Date.parse(value.startedAtUtc) < Date.parse(value.owner.createdAtUtc) ||
    Date.parse(value.completedAtUtc) < Date.parse(value.startedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.convergenceSha256 !== objectSha256(withoutDigest(value, 'convergenceSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_CONVERGENCE_INVALID');
  }
  return value;
};

const requireRuntimePhaseTerminalAbsent = async ({ phase, intent, store }) => {
  if (!PHASES.includes(phase)) fail('E7_RELEASE_RECONCILIATION_PHASE_INVALID');
  const owned = await requireReleaseRollbackJournalOwner({ intent, store });
  if (owned.parameters.some(({ name }) => name === terminalParameterName(owned.owner, phase))) {
    fail('E7_RELEASE_RECONCILIATION_TERMINAL_ALREADY_EXISTS');
  }
  return owned;
};

const convergenceFromDocuments = ({
  phase,
  intent,
  owner,
  candidateDocument,
  transitionDocument,
}) => {
  const source = intent.source;
  const expectedState = candidateStateProjection(candidateDocument.value, source);
  const transition = transitionDocument.value;
  const observedState = observedStateProjection(transition, source);
  const expectedStateSha256 = objectSha256(expectedState);
  const observedStateSha256 = objectSha256(observedState);
  if (observedStateSha256 !== expectedStateSha256) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_NOT_CANDIDATE_N');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RUNTIME_CONVERGENCE',
    status: 'EXACT_CANDIDATE_N_VERIFIED',
    phase,
    source: { ...source },
    owner,
    intent,
    recoveryAction:
      transition.decision === 'ALREADY_APPLIED_AND_VERIFIED'
        ? 'VERIFIED_NOOP'
        : 'REPROMOTED_CANDIDATE',
    transition,
    transitionBinding: {
      rawSha256: sha256(transitionDocument.bytes),
      canonicalSha256: objectSha256(transition),
      bytes: transitionDocument.bytes.length,
    },
    expectedStateSha256,
    observedStateSha256,
    startedAtUtc: transition.startedAtUtc,
    completedAtUtc: transition.completedAtUtc,
    containsSensitiveData: false,
  };
  return validateReleaseRuntimeConvergence({
    ...body,
    convergenceSha256: objectSha256(body),
  });
};

export const recoverVersionedReleaseRuntimeConvergenceCheckpoint = async ({
  phase,
  intent,
  candidateRecordSource,
  transitionSource,
  expectedConvergence = undefined,
  store,
}) => {
  if (!PHASES.includes(phase)) fail('E7_RELEASE_RECONCILIATION_CONVERGENCE_INPUT_INVALID');
  validateReleaseReconciliationIntent(intent);
  if (expectedConvergence !== undefined) validateReleaseRuntimeConvergence(expectedConvergence);
  const candidateDocument = parseDocument(
    candidateRecordSource,
    'E7_RELEASE_RECONCILIATION_CANDIDATE_RECORD_INVALID',
  );
  const transitionDocument = parseDocument(
    transitionSource,
    'E7_RELEASE_RECONCILIATION_TRANSITION_OUTPUT_INVALID',
  );
  const { owner } = await requireRuntimePhaseTerminalAbsent({ phase, intent, store });
  const convergence = convergenceFromDocuments({
    phase,
    intent,
    owner,
    candidateDocument,
    transitionDocument,
  });
  if (expectedConvergence !== undefined && !sameObject(convergence, expectedConvergence)) {
    fail('E7_RELEASE_RECONCILIATION_CONVERGENCE_CHECKPOINT_CONFLICT');
  }
  return convergence;
};

export const convergeVersionedReleaseRuntime = async ({
  phase,
  intent,
  store,
  rollbackFlags,
  environmentVariables = process.env,
  clock = () => new Date(),
  executeRollback = executeVersionedRollback,
  rollbackExecutor,
  delayImplementation,
}) => {
  if (!PHASES.includes(phase) || !object(rollbackFlags) || typeof executeRollback !== 'function') {
    fail('E7_RELEASE_RECONCILIATION_CONVERGENCE_INPUT_INVALID');
  }
  validateReleaseReconciliationIntent(intent);
  if (executeRollback === executeVersionedRollback) {
    validateRollbackIntentFileBindings(intent, rollbackFlags);
  }
  const { owner } = await requireRuntimePhaseTerminalAbsent({ phase, intent, store });
  const candidateDocument = parseDocument(
    readFileSync(rollbackFlags['candidate-record']),
    'E7_RELEASE_RECONCILIATION_CANDIDATE_RECORD_INVALID',
  );
  candidateStateProjection(candidateDocument.value, intent.source);
  const executionNow = new Date(nowUtc(clock));
  const transition = await executeRollback({
    flags: { ...rollbackFlags, direction: 'REPROMOTE_CANDIDATE' },
    environmentVariables,
    now: executionNow,
    ...(rollbackExecutor === undefined ? {} : { executor: rollbackExecutor }),
    ...(delayImplementation === undefined ? {} : { delayImplementation }),
  });
  const transitionDocument = parseDocument(
    readFileSync(rollbackFlags.output),
    'E7_RELEASE_RECONCILIATION_TRANSITION_OUTPUT_INVALID',
  );
  if (!sameObject(transition, transitionDocument.value)) {
    fail('E7_RELEASE_RECONCILIATION_TRANSITION_OUTPUT_MISMATCH');
  }
  return convergenceFromDocuments({
    phase,
    intent,
    owner,
    candidateDocument,
    transitionDocument,
  });
};

const validateDriftEvidence = (source, expected, { notBeforeUtc } = {}) => {
  const document = parseDocument(source, 'E7_RELEASE_RECONCILIATION_DRIFT_EVIDENCE_INVALID');
  const value = document.value;
  const checkpoint = value?.checkpoints?.drift;
  if (
    value?.schemaVersion !== 1 ||
    value?.stage !== 7 ||
    value?.candidateSha !== expected.candidateSha ||
    value?.releaseId !== expected.releaseId ||
    value?.configSha256 !== expected.configSha256 ||
    value?.containsSensitiveData !== false ||
    !utc(value?.updatedAtUtc) ||
    checkpoint?.decision !== 'PASS' ||
    checkpoint?.releaseMode !== 'VERSIONED_UPDATE' ||
    checkpoint?.updateReleaseSupported !== true ||
    checkpoint?.criticalCount !== 0 ||
    !Number.isSafeInteger(checkpoint?.checked) ||
    checkpoint.checked < 1 ||
    !Array.isArray(checkpoint?.stacks) ||
    checkpoint.stacks.length !== checkpoint.checked ||
    checkpoint.stacks.some(
      (stack) => stack?.status !== 'IN_SYNC' || stack?.driftedResourceCount !== 0,
    )
  ) {
    fail('E7_RELEASE_RECONCILIATION_DRIFT_EVIDENCE_INVALID');
  }
  if (notBeforeUtc !== undefined) {
    if (!utc(notBeforeUtc)) fail('E7_RELEASE_RECONCILIATION_FRESHNESS_BOUND_INVALID');
    if (Date.parse(value.updatedAtUtc) < Date.parse(notBeforeUtc)) {
      fail('E7_RELEASE_RECONCILIATION_DRIFT_EVIDENCE_STALE');
    }
  }
  return {
    value,
    bytes: document.bytes,
    canonicalSha256: objectSha256(value),
    rawSha256: sha256(document.bytes),
    observedAtUtc: value.updatedAtUtc,
  };
};

const reconciliationSmokeUsageId = (phase) => STAGE7_RELEASE_RECONCILIATION_SMOKE_USAGE_IDS[phase];

const validateSmokeEvidence = (
  source,
  expected,
  { notBeforeUtc, phase, intentSha256, convergenceSha256 } = {},
) => {
  const document = parseDocument(source, 'E7_RELEASE_RECONCILIATION_SMOKE_EVIDENCE_INVALID');
  const value = document.value;
  if (
    !PHASES.includes(phase) ||
    !SHA256.test(intentSha256 ?? '') ||
    !SHA256.test(convergenceSha256 ?? '') ||
    !utc(notBeforeUtc) ||
    value?.schemaVersion !== 1 ||
    value?.stage !== 7 ||
    value?.kind !== 'DEPLOYED_BLACK_BOX_SMOKE' ||
    value?.status !== 'PASS' ||
    value?.scope !== 'full' ||
    value?.mode !== 'POST_REPROMOTION_VERSIONED' ||
    value?.candidateSha !== expected.candidateSha ||
    value?.releaseId !== expected.releaseId ||
    value?.targetReleaseId !== expected.releaseId ||
    value?.stage7ConfigSha256 !== expected.configSha256 ||
    !exactKeys(value?.reconciliation, [
      'phase',
      'intentSha256',
      'convergenceSha256',
      'convergenceCompletedAtUtc',
    ]) ||
    value.reconciliation.phase !== phase ||
    value.reconciliation.intentSha256 !== intentSha256 ||
    value.reconciliation.convergenceSha256 !== convergenceSha256 ||
    value.reconciliation.convergenceCompletedAtUtc !== notBeforeUtc ||
    !exactKeys(value?.requests, [
      'total',
      'ownedOrigin',
      'provider',
      'production',
      'outsideAllowlist',
    ]) ||
    value.requests.total !== 3 ||
    value.requests.ownedOrigin !== 3 ||
    value.requests.provider !== 0 ||
    value.requests.production !== 0 ||
    value.requests.outsideAllowlist !== 0 ||
    !exactKeys(value?.externalAuthorization, [
      'authorizationSha256',
      'authorizationIds',
      'ownedOriginSha256',
      'sandboxHostSha256',
    ]) ||
    ![
      value.externalAuthorization.authorizationSha256,
      value.externalAuthorization.ownedOriginSha256,
      value.externalAuthorization.sandboxHostSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !Array.isArray(value.externalAuthorization.authorizationIds) ||
    value.externalAuthorization.authorizationIds?.join('\0') !==
      ['AUTH-E7-EXT-01', 'AUTH-E7-EXT-02', 'AUTH-E7-EXT-03'].join('\0') ||
    !exactKeys(value?.authorizationUsage, [
      'schemaVersion',
      'usageId',
      'bundleSha256',
      'candidateSha',
      'releaseId',
      'configSha256',
      'ownedOriginSha256',
      'sandboxHostSha256',
      'requestCounts',
    ]) ||
    value.authorizationUsage.schemaVersion !== 1 ||
    value.authorizationUsage.usageId !== reconciliationSmokeUsageId(phase) ||
    value.authorizationUsage.bundleSha256 !== value.externalAuthorization.authorizationSha256 ||
    value.authorizationUsage.candidateSha !== expected.candidateSha ||
    value.authorizationUsage.releaseId !== expected.releaseId ||
    value.authorizationUsage.configSha256 !== expected.configSha256 ||
    value.authorizationUsage.ownedOriginSha256 !== value.externalAuthorization.ownedOriginSha256 ||
    value.authorizationUsage.sandboxHostSha256 !== value.externalAuthorization.sandboxHostSha256 ||
    !exactKeys(value.authorizationUsage.requestCounts, [
      'AUTH-E7-EXT-01',
      'AUTH-E7-EXT-02',
      'AUTH-E7-EXT-03',
    ]) ||
    value.authorizationUsage.requestCounts['AUTH-E7-EXT-01'] !== 3 ||
    value.authorizationUsage.requestCounts['AUTH-E7-EXT-02'] !== 0 ||
    value.authorizationUsage.requestCounts['AUTH-E7-EXT-03'] !== 0 ||
    value?.total !== 3 ||
    value?.passed !== 3 ||
    value?.failed !== 0 ||
    value?.dataMutations !== 0 ||
    value?.mutationsPerformed !== 0 ||
    value?.externalRequests !== 3 ||
    value?.containsSensitiveData !== false ||
    !utc(value?.executedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_SMOKE_EVIDENCE_INVALID');
  }
  if (Date.parse(value.executedAtUtc) < Date.parse(notBeforeUtc)) {
    fail('E7_RELEASE_RECONCILIATION_SMOKE_EVIDENCE_STALE');
  }
  const authorizationUsage = {
    schemaVersion: 1,
    phase,
    usageId: value.authorizationUsage.usageId,
    authorizationSha256: value.externalAuthorization.authorizationSha256,
    bundleSha256: value.authorizationUsage.bundleSha256,
    configSha256: value.authorizationUsage.configSha256,
    candidateSha: value.authorizationUsage.candidateSha,
    releaseId: value.authorizationUsage.releaseId,
    ownedOriginSha256: value.authorizationUsage.ownedOriginSha256,
    sandboxHostSha256: value.authorizationUsage.sandboxHostSha256,
    requestCounts: { ...value.authorizationUsage.requestCounts },
    total: value.total,
    passed: value.passed,
    failed: value.failed,
    containsSensitiveData: false,
  };
  validateReleaseReconciliationSmokeAuthorizationUsage(authorizationUsage, {
    phase,
    source: expected,
  });
  return {
    value,
    bytes: document.bytes,
    canonicalSha256: objectSha256(value),
    rawSha256: sha256(document.bytes),
    observedAtUtc: value.executedAtUtc,
    authorizationUsage,
  };
};

const persistRuntimeProof = async ({
  owner,
  phase,
  proofKind,
  proof,
  convergenceSha256,
  store,
}) => {
  const plan = runtimeProofPlan({ owner, phase, proofKind, proof, convergenceSha256 });
  const existingParameters = await listJournal(store, owner.reconciliationRootPrefix);
  rejectUnexpectedJournalNames(owner, existingParameters);
  const expectedNames = new Set([
    plan.index.indexParameterName,
    ...plan.index.chunks.map(({ parameterName }) => parameterName),
  ]);
  const prefix = `${runtimeProofRoot(owner, phase, proofKind, proof.rawSha256)}/`;
  if (existingParameters.some(({ name }) => name.startsWith(prefix) && !expectedNames.has(name))) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_SET_CONFLICT');
  }
  for (let index = 0; index < plan.index.chunks.length; index += 1) {
    const binding = plan.index.chunks[index];
    let parameter = await store.get(binding.parameterName);
    if (parameter === null) {
      parameter = await store.putImmutable({
        name: binding.parameterName,
        value: plan.values[index],
      });
    }
    validateParameter(parameter, binding.parameterName);
    const bytes = Buffer.from(parameter.value, 'utf8');
    if (bytes.length !== binding.bytes || sha256(bytes) !== binding.rawSha256) {
      fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_CHUNK_MISMATCH');
    }
  }
  let indexParameter = await store.get(plan.index.indexParameterName);
  if (indexParameter === null) {
    indexParameter = await store.putImmutable({
      name: plan.index.indexParameterName,
      value: JSON.stringify(plan.index),
    });
  }
  validateParameter(indexParameter, plan.index.indexParameterName);
  const document = parseDocument(
    indexParameter.value,
    'E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_INVALID',
  );
  const index = validateRuntimeProofIndex(document.value, {
    owner,
    phase,
    proofKind,
    convergenceSha256,
  });
  if (!sameObject(index, plan.index)) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_CONFLICT');
  }
  return runtimeProofJournalReference(index);
};

const readRuntimeProofFromJournal = ({
  owner,
  phase,
  proofKind,
  reference,
  parameters,
  convergenceSha256,
  notBeforeUtc,
}) => {
  const indexParameter = parameters.find(({ name }) => name === reference.indexParameterName);
  if (indexParameter === undefined) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_MISSING');
  }
  validateParameter(indexParameter, reference.indexParameterName);
  const indexDocument = parseDocument(
    indexParameter.value,
    'E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_INVALID',
  );
  const index = validateRuntimeProofIndex(indexDocument.value, {
    owner,
    phase,
    proofKind,
    convergenceSha256,
  });
  if (!sameObject(runtimeProofJournalReference(index), reference)) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_REFERENCE_MISMATCH');
  }
  const values = index.chunks.map((binding) => {
    const parameter = parameters.find(({ name }) => name === binding.parameterName);
    if (parameter === undefined) {
      fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_CHUNK_MISSING');
    }
    validateParameter(parameter, binding.parameterName);
    const bytes = Buffer.from(parameter.value, 'utf8');
    if (bytes.length !== binding.bytes || sha256(bytes) !== binding.rawSha256) {
      fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_CHUNK_MISMATCH');
    }
    return parameter.value;
  });
  const bytes = Buffer.from(values.join(''), 'utf8');
  if (bytes.length !== index.bytes || sha256(bytes) !== index.rawSha256) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_BYTES_MISMATCH');
  }
  const proof =
    proofKind === 'DRIFT'
      ? validateDriftEvidence(bytes, owner.source, { notBeforeUtc })
      : validateSmokeEvidence(bytes, owner.source, {
          notBeforeUtc,
          phase,
          intentSha256: owner.intentSha256,
          convergenceSha256,
        });
  if (
    proof.rawSha256 !== index.rawSha256 ||
    proof.canonicalSha256 !== index.canonicalSha256 ||
    proof.observedAtUtc !== index.observedAtUtc
  ) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_MISMATCH');
  }
  return proof;
};

const runtimeProofParameterBindingsForPhase = (owner, phase, parameters) => {
  const phasePrefix = `${owner.runtimeProofRootPrefix}/${phaseSlug(phase)}/`;
  const phaseParameters = parameters
    .filter(({ name }) => name.startsWith(phasePrefix))
    .toSorted((left, right) => left.name.localeCompare(right.name));
  if (
    phaseParameters.length < 4 ||
    phaseParameters.length > MAX_RUNTIME_PROOF_PARAMETERS_PER_PHASE
  ) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_SET_CONFLICT');
  }
  return phaseParameters.map((parameter) => {
    validateParameter(parameter);
    validateRuntimeProofJournalParameter(owner, parameter);
    return {
      name: parameter.name,
      rawSha256: sha256(Buffer.from(parameter.value, 'utf8')),
      bytes: Buffer.byteLength(parameter.value, 'utf8'),
      version: parameter.version,
    };
  });
};

const runtimeProofParameterBindingsForTerminal = (owner, terminal, parameters) => {
  const requiredNames = [];
  for (const [proofKind, reference] of [
    ['DRIFT', terminal.driftProofJournal],
    ['SMOKE', terminal.smokeProofJournal],
  ]) {
    const parameter = parameters.find(({ name }) => name === reference.indexParameterName);
    if (parameter === undefined) {
      fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_MISSING');
    }
    const index = validateRuntimeProofIndex(
      parseDocument(parameter.value, 'E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX_INVALID').value,
      {
        owner,
        phase: terminal.phase,
        proofKind,
        convergenceSha256: terminal.convergenceSha256,
      },
    );
    if (!sameObject(runtimeProofJournalReference(index), reference)) {
      fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_REFERENCE_MISMATCH');
    }
    requiredNames.push(
      reference.indexParameterName,
      ...index.chunks.map(({ parameterName }) => parameterName),
    );
  }
  const inventory = runtimeProofParameterBindingsForPhase(owner, terminal.phase, parameters);
  const actualNames = new Set(inventory.map(({ name }) => name));
  if (
    new Set(requiredNames).size !== requiredNames.length ||
    requiredNames.some((name) => !actualNames.has(name)) ||
    terminal.runtimeProofParameterCount !== inventory.length ||
    terminal.runtimeProofParametersSha256 !== objectSha256(inventory)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RUNTIME_PROOF_SET_CONFLICT');
  }
  return inventory;
};

const terminalBody = ({
  convergence,
  originalJobConclusion,
  drift,
  smoke,
  driftProofJournal,
  smokeProofJournal,
  runtimeProofParameters,
  completedAtUtc,
}) => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'STAGE7_RELEASE_RECONCILIATION_TERMINAL_N',
  status: 'EXACT_CANDIDATE_N_VERIFIED',
  phase: convergence.phase,
  source: convergence.source,
  ownerSha256: convergence.owner.ownerSha256,
  originalJobConclusion,
  recoveryAction: convergence.recoveryAction,
  convergenceSha256: convergence.convergenceSha256,
  expectedStateSha256: convergence.expectedStateSha256,
  observedStateSha256: convergence.observedStateSha256,
  readbackRawSha256: convergence.transitionBinding.rawSha256,
  readbackCanonicalSha256: convergence.transitionBinding.canonicalSha256,
  driftProofSha256: drift.canonicalSha256,
  driftRawSha256: drift.rawSha256,
  driftProofJournal,
  smokeProofSha256: smoke.canonicalSha256,
  smokeRawSha256: smoke.rawSha256,
  smokeAuthorizationUsageSha256: objectSha256(smoke.authorizationUsage),
  smokeProofJournal,
  runtimeProofParameterCount: runtimeProofParameters.length,
  runtimeProofParametersSha256: objectSha256(runtimeProofParameters),
  startedAtUtc: convergence.startedAtUtc,
  convergenceCompletedAtUtc: convergence.completedAtUtc,
  driftObservedAtUtc: drift.observedAtUtc,
  smokeObservedAtUtc: smoke.observedAtUtc,
  observedAtUtc: [convergence.completedAtUtc, drift.observedAtUtc, smoke.observedAtUtc].toSorted(
    (left, right) => Date.parse(right) - Date.parse(left),
  )[0],
  completedAtUtc,
  containsSensitiveData: false,
});

export const validateReleaseReconciliationTerminal = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'phase',
      'source',
      'ownerSha256',
      'originalJobConclusion',
      'recoveryAction',
      'convergenceSha256',
      'expectedStateSha256',
      'observedStateSha256',
      'readbackRawSha256',
      'readbackCanonicalSha256',
      'driftProofSha256',
      'driftRawSha256',
      'driftProofJournal',
      'smokeProofSha256',
      'smokeRawSha256',
      'smokeAuthorizationUsageSha256',
      'smokeProofJournal',
      'runtimeProofParameterCount',
      'runtimeProofParametersSha256',
      'startedAtUtc',
      'convergenceCompletedAtUtc',
      'driftObservedAtUtc',
      'smokeObservedAtUtc',
      'observedAtUtc',
      'completedAtUtc',
      'containsSensitiveData',
      'terminalSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_TERMINAL_N' ||
    value.status !== 'EXACT_CANDIDATE_N_VERIFIED' ||
    !PHASES.includes(value.phase) ||
    validateReleaseReconciliationSource(value.source) !== value.source ||
    ![
      value.ownerSha256,
      value.convergenceSha256,
      value.expectedStateSha256,
      value.readbackRawSha256,
      value.readbackCanonicalSha256,
      value.driftProofSha256,
      value.driftRawSha256,
      value.smokeProofSha256,
      value.smokeRawSha256,
      value.smokeAuthorizationUsageSha256,
      value.runtimeProofParametersSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !exactKeys(value.driftProofJournal, [
      'indexParameterName',
      'indexSha256',
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'observedAtUtc',
      'chunkCount',
      'chunksSha256',
    ]) ||
    !exactKeys(value.smokeProofJournal, [
      'indexParameterName',
      'indexSha256',
      'rawSha256',
      'canonicalSha256',
      'bytes',
      'observedAtUtc',
      'chunkCount',
      'chunksSha256',
    ]) ||
    value.driftProofJournal.indexParameterName !==
      `/checkout/stage7/rollback/${value.source.candidateSha}/release-reconciliation/${value.source.runId}/runtime-proofs/${phaseSlug(value.phase)}/drift/${value.driftRawSha256}/index` ||
    value.smokeProofJournal.indexParameterName !==
      `/checkout/stage7/rollback/${value.source.candidateSha}/release-reconciliation/${value.source.runId}/runtime-proofs/${phaseSlug(value.phase)}/smoke/${value.smokeRawSha256}/index` ||
    ![
      value.driftProofJournal.indexSha256,
      value.driftProofJournal.rawSha256,
      value.driftProofJournal.canonicalSha256,
      value.driftProofJournal.chunksSha256,
      value.smokeProofJournal.indexSha256,
      value.smokeProofJournal.rawSha256,
      value.smokeProofJournal.canonicalSha256,
      value.smokeProofJournal.chunksSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    value.driftProofJournal.rawSha256 !== value.driftRawSha256 ||
    value.driftProofJournal.canonicalSha256 !== value.driftProofSha256 ||
    value.driftProofJournal.observedAtUtc !== value.driftObservedAtUtc ||
    value.smokeProofJournal.rawSha256 !== value.smokeRawSha256 ||
    value.smokeProofJournal.canonicalSha256 !== value.smokeProofSha256 ||
    value.smokeProofJournal.observedAtUtc !== value.smokeObservedAtUtc ||
    [value.driftProofJournal, value.smokeProofJournal].some(
      (reference) =>
        !Number.isSafeInteger(reference.bytes) ||
        reference.bytes < 2 ||
        !Number.isSafeInteger(reference.chunkCount) ||
        reference.chunkCount < 1 ||
        reference.chunkCount > MAX_RUNTIME_PROOF_CHUNKS,
    ) ||
    !Number.isSafeInteger(value.runtimeProofParameterCount) ||
    value.runtimeProofParameterCount < 4 ||
    value.runtimeProofParameterCount > MAX_RUNTIME_PROOF_PARAMETERS_PER_PHASE ||
    value.observedStateSha256 !== value.expectedStateSha256 ||
    !JOB_CONCLUSIONS.includes(value.originalJobConclusion) ||
    !['VERIFIED_NOOP', 'REPROMOTED_CANDIDATE'].includes(value.recoveryAction) ||
    ![
      value.startedAtUtc,
      value.convergenceCompletedAtUtc,
      value.driftObservedAtUtc,
      value.smokeObservedAtUtc,
      value.observedAtUtc,
      value.completedAtUtc,
    ].every(utc) ||
    Date.parse(value.convergenceCompletedAtUtc) < Date.parse(value.startedAtUtc) ||
    Date.parse(value.driftObservedAtUtc) < Date.parse(value.convergenceCompletedAtUtc) ||
    Date.parse(value.smokeObservedAtUtc) < Date.parse(value.convergenceCompletedAtUtc) ||
    value.observedAtUtc !==
      [
        value.convergenceCompletedAtUtc,
        value.driftObservedAtUtc,
        value.smokeObservedAtUtc,
      ].toSorted((left, right) => Date.parse(right) - Date.parse(left))[0] ||
    Date.parse(value.completedAtUtc) < Date.parse(value.observedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.terminalSha256 !== objectSha256(withoutDigest(value, 'terminalSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_TERMINAL_INVALID');
  }
  return value;
};

const readTerminalFromParameter = (parameter, { convergence, originalJobConclusion }) => {
  validateParameter(parameter, terminalParameterName(convergence.owner, convergence.phase));
  const document = parseDocument(
    parameter.value,
    'E7_RELEASE_RECONCILIATION_TERMINAL_DOCUMENT_INVALID',
  );
  const terminal = validateReleaseReconciliationTerminal(document.value);
  if (
    terminal.phase !== convergence.phase ||
    !sameObject(terminal.source, convergence.source) ||
    terminal.ownerSha256 !== convergence.owner.ownerSha256 ||
    terminal.originalJobConclusion !== originalJobConclusion ||
    terminal.recoveryAction !== convergence.recoveryAction ||
    terminal.convergenceSha256 !== convergence.convergenceSha256 ||
    terminal.expectedStateSha256 !== convergence.expectedStateSha256 ||
    terminal.observedStateSha256 !== convergence.observedStateSha256 ||
    terminal.readbackRawSha256 !== convergence.transitionBinding.rawSha256 ||
    terminal.readbackCanonicalSha256 !== convergence.transitionBinding.canonicalSha256 ||
    terminal.startedAtUtc !== convergence.startedAtUtc ||
    terminal.convergenceCompletedAtUtc !== convergence.completedAtUtc
  ) {
    fail('E7_RELEASE_RECONCILIATION_TERMINAL_CONFLICT');
  }
  return terminal;
};

const readTerminalForResume = (parameter, { phase, source, owner, originalJobConclusion }) => {
  validateParameter(parameter, terminalParameterName(owner, phase));
  const document = parseDocument(
    parameter.value,
    'E7_RELEASE_RECONCILIATION_TERMINAL_DOCUMENT_INVALID',
  );
  const terminal = validateReleaseReconciliationTerminal(document.value);
  if (
    terminal.phase !== phase ||
    !sameObject(terminal.source, source) ||
    terminal.ownerSha256 !== owner.ownerSha256 ||
    terminal.originalJobConclusion !== originalJobConclusion
  ) {
    fail('E7_RELEASE_RECONCILIATION_TERMINAL_CONFLICT');
  }
  return terminal;
};

export const validateReleaseRuntimeTerminalProbe = (value) => {
  const expectedTerminalName =
    object(value?.source) && PHASES.includes(value?.phase)
      ? `/checkout/stage7/rollback/${value.source.candidateSha}/release-reconciliation/${value.source.runId}/${phaseSlug(value.phase)}/terminal`
      : null;
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'phase',
      'source',
      'ownerSha256',
      'intentSha256',
      'originalJobConclusion',
      'terminalParameterName',
      'terminalSha256',
      'rollbackExecutionPerformed',
      'externalWritesPerformed',
      'containsSensitiveData',
      'probeSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'STAGE7_RELEASE_RECONCILIATION_TERMINAL_PROBE' ||
    !['TERMINAL_ABSENT', 'TERMINAL_PRESENT'].includes(value.status) ||
    !PHASES.includes(value.phase) ||
    validateReleaseReconciliationSource(value.source) !== value.source ||
    !SHA256.test(value.ownerSha256 ?? '') ||
    !SHA256.test(value.intentSha256 ?? '') ||
    !JOB_CONCLUSIONS.includes(value.originalJobConclusion) ||
    value.terminalParameterName !== expectedTerminalName ||
    (value.status === 'TERMINAL_ABSENT'
      ? value.terminalSha256 !== null
      : !SHA256.test(value.terminalSha256 ?? '')) ||
    value.rollbackExecutionPerformed !== false ||
    value.externalWritesPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.probeSha256 !== objectSha256(withoutDigest(value, 'probeSha256'))
  ) {
    fail('E7_RELEASE_RECONCILIATION_TERMINAL_PROBE_INVALID');
  }
  return value;
};

export const probeVersionedReleaseRuntimeTerminal = async ({
  phase,
  intent,
  originalJobConclusion,
  store,
}) => {
  if (!PHASES.includes(phase) || !JOB_CONCLUSIONS.includes(originalJobConclusion)) {
    fail('E7_RELEASE_RECONCILIATION_TERMINAL_PROBE_INPUT_INVALID');
  }
  validateReleaseReconciliationIntent(intent);
  validateStore(store);
  const { owner, parameters } = await requireReleaseRollbackJournalOwner({ intent, store });
  const name = terminalParameterName(owner, phase);
  const parameter = parameters.find((entry) => entry.name === name) ?? null;
  const terminal =
    parameter === null
      ? null
      : readTerminalForResume(parameter, {
          phase,
          source: intent.source,
          owner,
          originalJobConclusion,
        });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_RELEASE_RECONCILIATION_TERMINAL_PROBE',
    status: terminal === null ? 'TERMINAL_ABSENT' : 'TERMINAL_PRESENT',
    phase,
    source: intent.source,
    ownerSha256: owner.ownerSha256,
    intentSha256: intent.intentSha256,
    originalJobConclusion,
    terminalParameterName: name,
    terminalSha256: terminal?.terminalSha256 ?? null,
    rollbackExecutionPerformed: false,
    externalWritesPerformed: 0,
    containsSensitiveData: false,
  };
  return validateReleaseRuntimeTerminalProbe({
    ...body,
    probeSha256: objectSha256(body),
  });
};

const phaseJournalScanSha256 = ({
  owner,
  terminalParameter,
  runtimeProofParameters,
  parameters,
}) => {
  const requiredNames = [
    owner.parameterName,
    ...owner.intentChunks.map(({ parameterName }) => parameterName),
    ...runtimeProofParameters.map(({ name }) => name),
    terminalParameter.name,
  ];
  requiredNames.forEach((name) => {
    const parameter = parameters.find((entry) => entry.name === name);
    if (parameter === undefined) fail('E7_RELEASE_RECONCILIATION_JOURNAL_SCAN_INCOMPLETE');
    validateParameter(parameter, name);
  });
  const projection = requiredNames
    .map((name) => parameters.find((entry) => entry.name === name))
    .toSorted((left, right) => left.name.localeCompare(right.name));
  return objectSha256(projection);
};

const receiptFromTerminal = ({
  owner,
  intent,
  terminal,
  terminalParameter,
  parameters,
  smokeAuthorizationUsage,
}) => {
  validateReleaseReconciliationSmokeAuthorizationUsage(smokeAuthorizationUsage, {
    phase: terminal.phase,
    source: terminal.source,
  });
  if (objectSha256(smokeAuthorizationUsage) !== terminal.smokeAuthorizationUsageSha256) {
    fail('E7_RELEASE_RECONCILIATION_SMOKE_AUTHORIZATION_USAGE_MISMATCH');
  }
  const runtimeProofParameters = runtimeProofParameterBindingsForTerminal(
    owner,
    terminal,
    parameters,
  );
  return createReleaseReconciliationReceipt({
    phase: terminal.phase,
    source: terminal.source,
    owner,
    intent,
    originalJobConclusion: terminal.originalJobConclusion,
    recoveryAction: terminal.recoveryAction,
    expectedStateSha256: terminal.expectedStateSha256,
    observedStateSha256: terminal.observedStateSha256,
    readbackRawSha256: terminal.readbackRawSha256,
    readbackCanonicalSha256: terminal.readbackCanonicalSha256,
    driftProofSha256: terminal.driftProofSha256,
    smokeProofSha256: terminal.smokeProofSha256,
    smokeAuthorizationUsage,
    driftProofJournal: terminal.driftProofJournal,
    smokeProofJournal: terminal.smokeProofJournal,
    runtimeProofParameters,
    runtimeProofParameterCount: terminal.runtimeProofParameterCount,
    runtimeProofParametersSha256: terminal.runtimeProofParametersSha256,
    journalScanSha256: phaseJournalScanSha256({
      owner,
      terminalParameter,
      runtimeProofParameters,
      parameters,
    }),
    terminalStateSha256: terminal.terminalSha256,
    startedAtUtc: terminal.startedAtUtc,
    convergenceCompletedAtUtc: terminal.convergenceCompletedAtUtc,
    driftObservedAtUtc: terminal.driftObservedAtUtc,
    smokeObservedAtUtc: terminal.smokeObservedAtUtc,
    observedAtUtc: terminal.observedAtUtc,
    completedAtUtc: terminal.completedAtUtc,
  });
};

export const resumeVersionedReleaseRuntimeReconciliation = async ({
  phase,
  intent,
  originalJobConclusion,
  driftEvidenceSource,
  smokeEvidenceSource,
  store,
}) => {
  if (!PHASES.includes(phase) || !JOB_CONCLUSIONS.includes(originalJobConclusion)) {
    fail('E7_RELEASE_RECONCILIATION_RESUME_INPUT_INVALID');
  }
  validateReleaseReconciliationIntent(intent);
  validateStore(store);
  const { owner, parameters } = await requireReleaseRollbackJournalOwner({ intent, store });
  const name = terminalParameterName(owner, phase);
  const terminalParameter = parameters.find((parameter) => parameter.name === name) ?? null;
  if (terminalParameter === null) {
    return {
      status: 'TERMINAL_ABSENT',
      owner,
      intent,
      terminal: null,
      receipt: null,
      rollbackExecutionPerformed: false,
      terminalWritePerformed: false,
    };
  }
  const terminal = readTerminalForResume(terminalParameter, {
    phase,
    source: intent.source,
    owner,
    originalJobConclusion,
  });
  if ((driftEvidenceSource === undefined) !== (smokeEvidenceSource === undefined)) {
    fail('E7_RELEASE_RECONCILIATION_RESUME_EVIDENCE_PAIR_INVALID');
  }
  const durableDrift = readRuntimeProofFromJournal({
    owner,
    phase,
    proofKind: 'DRIFT',
    reference: terminal.driftProofJournal,
    parameters,
    convergenceSha256: terminal.convergenceSha256,
    notBeforeUtc: terminal.convergenceCompletedAtUtc,
  });
  const durableSmoke = readRuntimeProofFromJournal({
    owner,
    phase,
    proofKind: 'SMOKE',
    reference: terminal.smokeProofJournal,
    parameters,
    convergenceSha256: terminal.convergenceSha256,
    notBeforeUtc: terminal.convergenceCompletedAtUtc,
  });
  const drift =
    driftEvidenceSource === undefined
      ? durableDrift
      : validateDriftEvidence(driftEvidenceSource, intent.source, {
          notBeforeUtc: terminal.convergenceCompletedAtUtc,
        });
  const smoke =
    smokeEvidenceSource === undefined
      ? durableSmoke
      : validateSmokeEvidence(smokeEvidenceSource, intent.source, {
          notBeforeUtc: terminal.convergenceCompletedAtUtc,
          phase,
          intentSha256: intent.intentSha256,
          convergenceSha256: terminal.convergenceSha256,
        });
  if (
    drift.canonicalSha256 !== durableDrift.canonicalSha256 ||
    drift.rawSha256 !== durableDrift.rawSha256 ||
    smoke.canonicalSha256 !== durableSmoke.canonicalSha256 ||
    smoke.rawSha256 !== durableSmoke.rawSha256 ||
    drift.canonicalSha256 !== terminal.driftProofSha256 ||
    drift.rawSha256 !== terminal.driftRawSha256 ||
    smoke.canonicalSha256 !== terminal.smokeProofSha256 ||
    smoke.rawSha256 !== terminal.smokeRawSha256 ||
    objectSha256(smoke.authorizationUsage) !== terminal.smokeAuthorizationUsageSha256 ||
    drift.observedAtUtc !== terminal.driftObservedAtUtc ||
    smoke.observedAtUtc !== terminal.smokeObservedAtUtc
  ) {
    fail('E7_RELEASE_RECONCILIATION_RESUME_EVIDENCE_MISMATCH');
  }
  const receipt = receiptFromTerminal({
    owner,
    intent,
    terminal,
    terminalParameter,
    parameters,
    smokeAuthorizationUsage: smoke.authorizationUsage,
  });
  return {
    status: 'TERMINAL_RECEIPT_REUSED',
    owner,
    intent,
    terminal,
    receipt,
    rollbackExecutionPerformed: false,
    terminalWritePerformed: false,
  };
};

export const finalizeVersionedReleaseRuntimeReconciliation = async ({
  convergence,
  originalJobConclusion,
  driftEvidenceSource,
  smokeEvidenceSource,
  store,
  clock = () => new Date(),
}) => {
  validateReleaseRuntimeConvergence(convergence);
  validateStore(store);
  if (!JOB_CONCLUSIONS.includes(originalJobConclusion)) {
    fail('E7_RELEASE_RECONCILIATION_JOB_CONCLUSION_INVALID');
  }
  const freshness = { notBeforeUtc: convergence.completedAtUtc };
  const drift = validateDriftEvidence(driftEvidenceSource, convergence.source, freshness);
  const smoke = validateSmokeEvidence(smokeEvidenceSource, convergence.source, {
    ...freshness,
    phase: convergence.phase,
    intentSha256: convergence.intent.intentSha256,
    convergenceSha256: convergence.convergenceSha256,
  });
  const { owner, intent } = await requireReleaseRollbackJournalOwner({
    intent: convergence.intent,
    store,
  });
  if (owner.ownerSha256 !== convergence.owner.ownerSha256) {
    fail('E7_RELEASE_RECONCILIATION_OWNER_CHANGED');
  }
  const name = terminalParameterName(owner, convergence.phase);
  let parameter = await store.get(name);
  let terminal;
  let idempotent = parameter !== null;
  if (parameter === null) {
    const driftProofJournal = await persistRuntimeProof({
      owner,
      phase: convergence.phase,
      proofKind: 'DRIFT',
      proof: drift,
      convergenceSha256: convergence.convergenceSha256,
      store,
    });
    const smokeProofJournal = await persistRuntimeProof({
      owner,
      phase: convergence.phase,
      proofKind: 'SMOKE',
      proof: smoke,
      convergenceSha256: convergence.convergenceSha256,
      store,
    });
    const proofParametersBeforeTerminal = await listJournal(store, owner.reconciliationRootPrefix);
    rejectUnexpectedJournalNames(owner, proofParametersBeforeTerminal);
    validateExistingTerminalEntries(owner, proofParametersBeforeTerminal);
    const runtimeProofParameters = runtimeProofParameterBindingsForPhase(
      owner,
      convergence.phase,
      proofParametersBeforeTerminal,
    );
    const completedAtUtc = nowUtc(clock);
    const body = terminalBody({
      convergence,
      originalJobConclusion,
      drift,
      smoke,
      driftProofJournal,
      smokeProofJournal,
      runtimeProofParameters,
      completedAtUtc,
    });
    if (Date.parse(completedAtUtc) < Date.parse(body.observedAtUtc)) {
      fail('E7_RELEASE_RECONCILIATION_TERMINAL_TIME_INVALID');
    }
    terminal = validateReleaseReconciliationTerminal({
      ...body,
      terminalSha256: objectSha256(body),
    });
    if (Buffer.byteLength(JSON.stringify(terminal), 'utf8') > MAX_PARAMETER_BYTES) {
      fail('E7_RELEASE_RECONCILIATION_TERMINAL_PARAMETER_TOO_LARGE');
    }
    parameter = await store.putImmutable({ name, value: JSON.stringify(terminal) });
    validateParameter(parameter, name);
    idempotent = false;
  }
  terminal = readTerminalFromParameter(parameter, { convergence, originalJobConclusion });
  const durableParameters = await listJournal(store, owner.reconciliationRootPrefix);
  rejectUnexpectedJournalNames(owner, durableParameters);
  validateExistingTerminalEntries(owner, durableParameters);
  const durableDrift = readRuntimeProofFromJournal({
    owner,
    phase: convergence.phase,
    proofKind: 'DRIFT',
    reference: terminal.driftProofJournal,
    parameters: durableParameters,
    convergenceSha256: convergence.convergenceSha256,
    notBeforeUtc: convergence.completedAtUtc,
  });
  const durableSmoke = readRuntimeProofFromJournal({
    owner,
    phase: convergence.phase,
    proofKind: 'SMOKE',
    reference: terminal.smokeProofJournal,
    parameters: durableParameters,
    convergenceSha256: convergence.convergenceSha256,
    notBeforeUtc: convergence.completedAtUtc,
  });
  if (
    drift.canonicalSha256 !== durableDrift.canonicalSha256 ||
    drift.rawSha256 !== durableDrift.rawSha256 ||
    smoke.canonicalSha256 !== durableSmoke.canonicalSha256 ||
    smoke.rawSha256 !== durableSmoke.rawSha256 ||
    drift.canonicalSha256 !== terminal.driftProofSha256 ||
    drift.rawSha256 !== terminal.driftRawSha256 ||
    smoke.canonicalSha256 !== terminal.smokeProofSha256 ||
    smoke.rawSha256 !== terminal.smokeRawSha256 ||
    objectSha256(smoke.authorizationUsage) !== terminal.smokeAuthorizationUsageSha256 ||
    drift.observedAtUtc !== terminal.driftObservedAtUtc ||
    smoke.observedAtUtc !== terminal.smokeObservedAtUtc
  ) {
    fail('E7_RELEASE_RECONCILIATION_FINALIZE_EVIDENCE_MISMATCH');
  }
  const receipt = receiptFromTerminal({
    owner,
    intent,
    terminal,
    terminalParameter: parameter,
    parameters: durableParameters,
    smokeAuthorizationUsage: smoke.authorizationUsage,
  });
  validateReleaseReconciliationReceipt(receipt);
  return {
    owner,
    terminal,
    receipt,
    idempotent,
    journalEntryCount: durableParameters.length,
  };
};

export const executeReleasePublicationForwardReconciliation = async ({
  expected,
  observe,
  publish,
}) => {
  validateReleasePublicationExpectation(expected);
  if (typeof observe !== 'function' || typeof publish !== 'function') {
    fail('E7_RELEASE_RECONCILIATION_PUBLICATION_EXECUTOR_INVALID');
  }
  const beforeObservation = validateReleasePublicationObservation(await observe());
  const before = classifyReleasePublicationState({ expected, observation: beforeObservation });
  if (before.state === 'CONFLICT') {
    return {
      status: 'BLOCKED',
      before,
      after: null,
      operation: null,
      externalWritesPerformed: 0,
      destructiveOperationsPerformed: 0,
    };
  }
  let operation = null;
  if (before.state !== 'EXACT') {
    operation = await publish({
      expected,
      before,
      permittedOperations: [...before.permittedOperations],
    });
    if (
      !exactKeys(operation, [
        'performedOperations',
        'externalWritesPerformed',
        'operationSha256',
      ]) ||
      !Array.isArray(operation.performedOperations) ||
      operation.performedOperations.join('\0') !== before.permittedOperations.join('\0') ||
      operation.externalWritesPerformed !== before.externalWritesRequired ||
      !SHA256.test(operation.operationSha256 ?? '') ||
      operation.operationSha256 !== objectSha256(withoutDigest(operation, 'operationSha256'))
    ) {
      fail('E7_RELEASE_RECONCILIATION_PUBLICATION_OPERATION_INVALID');
    }
  }
  const afterObservation = validateReleasePublicationObservation(await observe());
  const after = classifyReleasePublicationState({ expected, observation: afterObservation });
  if (after.state !== 'EXACT') {
    fail('E7_RELEASE_RECONCILIATION_PUBLICATION_NOT_EXACT');
  }
  return {
    status: 'PASS',
    before,
    after,
    operation,
    externalWritesPerformed: operation?.externalWritesPerformed ?? 0,
    destructiveOperationsPerformed: 0,
  };
};

const normalizeLastModified = (value) => {
  if (!['string', 'number'].includes(typeof value) || Number.isNaN(new Date(value).getTime())) {
    fail('E7_RELEASE_RECONCILIATION_AWS_PARAMETER_INVALID');
  }
  return new Date(value).toISOString();
};

const normalizeAwsParameter = (value, { accountId, region }) => {
  const parameter = {
    name: value?.Name,
    type: value?.Type,
    value: value?.Value,
    version: value?.Version,
    lastModifiedAtUtc: normalizeLastModified(value?.LastModifiedDate),
    arn: value?.ARN,
    dataType: value?.DataType,
  };
  validateParameter(parameter);
  if (parameter.arn !== `arn:aws:ssm:${region}:${accountId}:parameter${parameter.name}`) {
    fail('E7_RELEASE_RECONCILIATION_AWS_PARAMETER_ARN_INVALID');
  }
  return parameter;
};

export const createAwsCliReleaseReconciliationRuntime = ({
  intent,
  capability,
  environmentVariables = process.env,
  awsCommand = process.platform === 'win32' ? 'aws.cmd' : 'aws',
  spawn = spawnSync,
}) => {
  validateReleaseReconciliationIntent(intent);
  const source = intent.source;
  const candidateRootPrefix = `/checkout/stage7/rollback/${source.candidateSha}`;
  const reconciliationRootPrefix = `${candidateRootPrefix}/release-reconciliation/${source.runId}`;
  const reconciliationParameterPrefix = `${reconciliationRootPrefix}/`;
  const expectedRoleArn =
    capability === 'JOURNAL'
      ? intent.authority.journalRoleArn
      : capability === 'ROLLBACK'
        ? intent.authority.rollbackRoleArn
        : null;
  const expectedSessionName =
    capability === 'JOURNAL'
      ? `e7-release-reconciliation-journal-${source.runId}`
      : capability === 'ROLLBACK'
        ? `e7-release-reconciliation-runtime-${source.runId}`
        : null;
  const roleEnvironmentName =
    capability === 'JOURNAL'
      ? 'STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN'
      : capability === 'ROLLBACK'
        ? 'STAGE7_AWS_ROLLBACK_ROLE_ARN'
        : null;
  const roleMatch = ROLE_ARN.exec(expectedRoleArn ?? '');
  const region = intent.authority.region;
  if (
    roleMatch === null ||
    !SESSION_NAME.test(expectedSessionName ?? '') ||
    typeof spawn !== 'function' ||
    !AWS_REGION.test(region ?? '') ||
    environmentVariables.AWS_REGION !== region ||
    environmentVariables.AWS_DEFAULT_REGION !== region ||
    roleEnvironmentName === null ||
    environmentVariables[roleEnvironmentName] !== expectedRoleArn
  ) {
    fail('E7_RELEASE_RECONCILIATION_AWS_RUNTIME_INPUT_INVALID');
  }
  if (
    environmentVariables.GITHUB_REPOSITORY !== source.repository ||
    environmentVariables.GITHUB_RUN_ID !== source.runId ||
    environmentVariables.GITHUB_RUN_ATTEMPT !== String(source.runAttempt) ||
    environmentVariables.GITHUB_SHA !== source.candidateSha ||
    environmentVariables.GITHUB_REF !== source.ref ||
    environmentVariables.GITHUB_WORKFLOW_REF !==
      `${source.repository}/${source.workflowPath}@${source.ref}`
  ) {
    fail('E7_RELEASE_RECONCILIATION_GITHUB_IDENTITY_INVALID');
  }
  const allowedAwsError = Symbol('allowedAwsError');
  const run = (arguments_, code, { allowedErrorCodes = [] } = {}) => {
    const result = spawn(awsCommand, arguments_, {
      encoding: 'utf8',
      env: { ...environmentVariables, AWS_PAGER: '' },
      maxBuffer: MAX_AWS_OUTPUT_BYTES,
      shell: false,
      timeout: AWS_TIMEOUT_MS,
      windowsHide: true,
    });
    if (result.error !== undefined || result.signal !== null || result.status !== 0) {
      const stderr = typeof result.stderr === 'string' ? result.stderr : '';
      const errorCode = /An error occurred \(([A-Za-z0-9.]+)\)/u.exec(stderr)?.[1] ?? null;
      if (
        result.error === undefined &&
        result.signal === null &&
        Number.isSafeInteger(result.status) &&
        result.status !== 0 &&
        allowedErrorCodes.includes(errorCode)
      ) {
        return { [allowedAwsError]: errorCode };
      }
      fail(code, result.error);
    }
    if (
      typeof result.stdout !== 'string' ||
      Buffer.byteLength(result.stdout, 'utf8') > MAX_AWS_OUTPUT_BYTES
    ) {
      fail(code);
    }
    try {
      return parseStrictJsonSource(Buffer.from(result.stdout, 'utf8'), {
        scanForbiddenData: false,
      });
    } catch (error) {
      fail(code, error);
    }
  };
  const identity = run(
    ['sts', 'get-caller-identity', '--output', 'json'],
    'E7_RELEASE_RECONCILIATION_STS_FAILED',
  );
  const roleName = roleMatch[2].split('/').at(-1);
  const expectedSessionArn = `arn:aws:sts::${roleMatch[1]}:assumed-role/${roleName}/${expectedSessionName}`;
  if (
    !exactKeys(identity, ['UserId', 'Account', 'Arn']) ||
    identity.Account !== roleMatch[1] ||
    identity?.Arn !== expectedSessionArn ||
    typeof identity?.UserId !== 'string' ||
    !identity.UserId.endsWith(`:${expectedSessionName}`)
  ) {
    fail('E7_RELEASE_RECONCILIATION_STS_IDENTITY_INVALID');
  }
  const get = async (name) => {
    if (typeof name !== 'string' || !name.startsWith(reconciliationParameterPrefix)) {
      fail('E7_RELEASE_RECONCILIATION_SSM_GET_INPUT_INVALID');
    }
    const response = run(
      ['ssm', 'get-parameter', '--name', name, '--with-decryption', '--output', 'json'],
      'E7_RELEASE_RECONCILIATION_SSM_GET_FAILED',
      { allowedErrorCodes: ['ParameterNotFound'] },
    );
    if (response?.[allowedAwsError] === 'ParameterNotFound') return null;
    if (!exactKeys(response, ['Parameter']) || !object(response.Parameter)) {
      fail('E7_RELEASE_RECONCILIATION_SSM_GET_INVALID');
    }
    const parameter = normalizeAwsParameter(response.Parameter, {
      accountId: roleMatch[1],
      region,
    });
    if (parameter.name !== name) fail('E7_RELEASE_RECONCILIATION_SSM_GET_INVALID');
    return parameter;
  };
  const putImmutable = async ({ name, value }) => {
    if (
      typeof name !== 'string' ||
      !name.startsWith(reconciliationParameterPrefix) ||
      typeof value !== 'string' ||
      Buffer.byteLength(value, 'utf8') > MAX_PARAMETER_BYTES
    ) {
      fail('E7_RELEASE_RECONCILIATION_SSM_PUT_INPUT_INVALID');
    }
    const response = run(
      [
        'ssm',
        'put-parameter',
        '--name',
        name,
        '--type',
        'String',
        '--value',
        value,
        '--tier',
        'Standard',
        '--no-overwrite',
        '--output',
        'json',
      ],
      'E7_RELEASE_RECONCILIATION_SSM_PUT_FAILED',
      { allowedErrorCodes: ['ParameterAlreadyExists'] },
    );
    const parameter = await get(name);
    if (
      parameter === null ||
      parameter.value !== value ||
      (response?.[allowedAwsError] === undefined &&
        (!exactKeys(response, ['Version', 'Tier']) ||
          response.Version !== 1 ||
          response.Tier !== 'Standard'))
    ) {
      fail('E7_RELEASE_RECONCILIATION_SSM_PUT_MISMATCH');
    }
    return parameter;
  };
  const list = async (rootPrefix) => {
    if (rootPrefix !== reconciliationRootPrefix) {
      fail('E7_RELEASE_RECONCILIATION_SSM_PATH_INVALID');
    }
    const output = [];
    let nextToken = null;
    let pageCount = 0;
    const seenTokens = new Set();
    do {
      pageCount += 1;
      if (pageCount > MAX_SSM_PAGES) {
        fail('E7_RELEASE_RECONCILIATION_SSM_PAGE_LIMIT_EXCEEDED');
      }
      const arguments_ = [
        'ssm',
        'get-parameters-by-path',
        '--path',
        rootPrefix,
        '--recursive',
        '--with-decryption',
        '--max-results',
        '10',
        '--no-paginate',
        '--output',
        'json',
      ];
      if (nextToken !== null) arguments_.push('--next-token', nextToken);
      const response = run(arguments_, 'E7_RELEASE_RECONCILIATION_SSM_LIST_FAILED');
      if (
        !object(response) ||
        !Array.isArray(response.Parameters) ||
        response.Parameters.length > 10 ||
        Object.keys(response).some((key) => !['Parameters', 'NextToken'].includes(key))
      ) {
        fail('E7_RELEASE_RECONCILIATION_SSM_LIST_INVALID');
      }
      output.push(
        ...response.Parameters.map((parameter) =>
          normalizeAwsParameter(parameter, { accountId: roleMatch[1], region }),
        ),
      );
      nextToken = response.NextToken ?? null;
      if (nextToken !== null && (typeof nextToken !== 'string' || nextToken === '')) {
        fail('E7_RELEASE_RECONCILIATION_SSM_TOKEN_INVALID');
      }
      if (nextToken !== null) {
        if (seenTokens.has(nextToken)) {
          fail('E7_RELEASE_RECONCILIATION_SSM_TOKEN_CYCLE');
        }
        seenTokens.add(nextToken);
      }
      if (output.length > MAX_JOURNAL_PARAMETERS) {
        fail('E7_RELEASE_RECONCILIATION_SSM_LIST_TOO_LARGE');
      }
    } while (nextToken !== null);
    return output;
  };
  return {
    store: Object.freeze({
      candidateRootPrefix,
      reconciliationRootPrefix,
      get,
      putImmutable,
      list,
    }),
    authority: {
      accountId: identity.Account,
      roleArn: expectedRoleArn,
      sessionArn: identity.Arn,
      sessionName: expectedSessionName,
      callerIdentitySha256: objectSha256(identity),
    },
  };
};

export const readReleaseReconciliationJsonFile = (filename, code) => {
  try {
    return parseDocument(readFileSync(filename), code);
  } catch (error) {
    if (error instanceof Stage7ReleaseReconciliationExecutorError) throw error;
    if (error instanceof Stage7ReleaseReconciliationError) fail(code, error);
    fail(code, error);
  }
};
