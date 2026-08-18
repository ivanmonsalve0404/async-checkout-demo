import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256 } from './core.mjs';
import {
  validateReleaseReconciliationIntent,
  validateReleaseReconciliationJournalAuthority,
  validateReleaseRollbackJournalOwner,
} from './release-reconciliation.mjs';
import { validateReleaseReconciliationTerminal } from './release-reconciliation-executor.mjs';
import {
  validateRollbackJournalOwner,
  validateRollbackSsmPremutationAuthority,
} from './rollback-resilience-protected-runtime.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_PAGES_PER_PREFIX = 1000;
const MAX_PARAMETER_BYTES = 3900;
const MAX_RB_STATE_BYTES = 16 * 1024 * 1024;
const SCENARIOS = Object.freeze(['RB-E7-06', 'RB-E7-08']);

export const RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_BASENAME =
  'release-reconciliation-journal-snapshot.json';

export class Stage7ReleaseSuccessorJournalSnapshotError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseSuccessorJournalSnapshotError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseSuccessorJournalSnapshotError(
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
const sameObject = (left, right) => canonicalJson(left) === canonicalJson(right);
const utc = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return false;
  return new Date(value).toISOString() === value;
};
const strictPublicJson = (value, code) => {
  const bytes = Buffer.from(value, 'utf8');
  let document;
  try {
    document = parseStrictJsonSource(bytes, { scanForbiddenData: false });
  } catch (error) {
    fail(code, error);
  }
  if (!object(document) || document.containsSensitiveData !== false) fail(code);
  return { value: document, bytes };
};

const normalizeParameter = (parameter, expectedPrefix) => {
  if (
    !exactKeys(parameter, [
      'Name',
      'Type',
      'Value',
      'Version',
      'LastModifiedDate',
      'ARN',
      'DataType',
    ]) ||
    typeof parameter.Name !== 'string' ||
    !parameter.Name.startsWith(`${expectedPrefix}/`) ||
    parameter.Type !== 'String' ||
    typeof parameter.Value !== 'string' ||
    Buffer.from(parameter.Value, 'utf8').toString('utf8') !== parameter.Value ||
    Buffer.byteLength(parameter.Value, 'utf8') < 1 ||
    Buffer.byteLength(parameter.Value, 'utf8') > MAX_PARAMETER_BYTES ||
    parameter.Version !== 1 ||
    parameter.DataType !== 'text' ||
    typeof parameter.ARN !== 'string' ||
    !parameter.ARN.endsWith(`:parameter${parameter.Name}`)
  ) {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_PARAMETER_INVALID');
  }
  const modified = new Date(parameter.LastModifiedDate);
  if (Number.isNaN(modified.valueOf())) {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_PARAMETER_TIMESTAMP_INVALID');
  }
  const bytes = Buffer.from(parameter.Value, 'utf8');
  return {
    name: parameter.Name,
    type: parameter.Type,
    value: parameter.Value,
    version: parameter.Version,
    lastModifiedAtUtc: modified.toISOString(),
    arn: parameter.ARN,
    dataType: parameter.DataType,
    rawSha256: sha256(bytes),
    bytes: bytes.length,
  };
};

const validateSnapshotEntry = (entry) => {
  if (
    !exactKeys(entry, [
      'name',
      'type',
      'value',
      'version',
      'lastModifiedAtUtc',
      'arn',
      'dataType',
      'rawSha256',
      'bytes',
    ]) ||
    typeof entry.name !== 'string' ||
    entry.type !== 'String' ||
    typeof entry.value !== 'string' ||
    Buffer.from(entry.value, 'utf8').toString('utf8') !== entry.value ||
    entry.version !== 1 ||
    !utc(entry.lastModifiedAtUtc) ||
    typeof entry.arn !== 'string' ||
    !entry.arn.endsWith(`:parameter${entry.name}`) ||
    entry.dataType !== 'text' ||
    !SHA256.test(entry.rawSha256 ?? '') ||
    !Number.isSafeInteger(entry.bytes) ||
    entry.bytes < 1 ||
    entry.bytes > MAX_PARAMETER_BYTES ||
    Buffer.byteLength(entry.value, 'utf8') !== entry.bytes ||
    sha256(Buffer.from(entry.value, 'utf8')) !== entry.rawSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_ENTRY_INVALID');
  }
  return entry;
};

const listPrefix = async ({ prefix, getParametersByPath }) => {
  const entries = [];
  const tokens = new Set();
  let nextToken;
  let pages = 0;
  do {
    if (pages >= MAX_PAGES_PER_PREFIX) {
      fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_PAGINATION_LIMIT');
    }
    const response = await getParametersByPath({
      path: prefix,
      recursive: true,
      withDecryption: false,
      maxResults: 10,
      ...(nextToken === undefined ? {} : { nextToken }),
    });
    pages += 1;
    if (!Array.isArray(response?.Parameters)) {
      fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_LIST_RESPONSE_INVALID');
    }
    entries.push(...response.Parameters.map((parameter) => normalizeParameter(parameter, prefix)));
    nextToken = response.NextToken;
    if (nextToken !== undefined) {
      if (typeof nextToken !== 'string' || nextToken === '' || tokens.has(nextToken)) {
        fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_PAGINATION_INVALID');
      }
      tokens.add(nextToken);
    }
  } while (nextToken !== undefined);
  if (new Set(entries.map(({ name }) => name)).size !== entries.length) {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_DUPLICATE_PARAMETER');
  }
  return {
    entries: entries.toSorted((left, right) => left.name.localeCompare(right.name)),
    pages,
  };
};

const validateRbState = (state, { scenarioId, bindingSha256 }) => {
  if (
    !exactKeys(state, [
      'schemaVersion',
      'stage',
      'kind',
      'scenarioId',
      'bindingSha256',
      'phase',
      'resumptions',
      'progress',
      'transcript',
      'checkpoint',
      'containsSensitiveData',
      'stateSha256',
    ]) ||
    state.schemaVersion !== 1 ||
    state.stage !== 7 ||
    state.kind !== 'ROLLBACK_RESILIENCE_DURABLE_STATE' ||
    state.scenarioId !== scenarioId ||
    (bindingSha256 !== undefined && state.bindingSha256 !== bindingSha256) ||
    !SHA256.test(state.bindingSha256 ?? '') ||
    typeof state.phase !== 'string' ||
    !Number.isSafeInteger(state.resumptions) ||
    state.resumptions < 0 ||
    !object(state.progress) ||
    !Array.isArray(state.transcript) ||
    !(state.checkpoint === null || object(state.checkpoint)) ||
    state.containsSensitiveData !== false ||
    state.stateSha256 !== objectSha256(withoutDigest(state, 'stateSha256'))
  ) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_STATE_INVALID');
  }
  return state;
};

const decodeRbGroup = ({ group, previousStateSha256, scenarioId, bindingSha256 }) => {
  const manifestEntry = group.entries.get('manifest');
  if (manifestEntry === undefined) return null;
  const manifest = strictPublicJson(
    manifestEntry.value,
    'E7_RELEASE_SUCCESSOR_RB_JOURNAL_MANIFEST_INVALID',
  ).value;
  if (
    !exactKeys(manifest, [
      'schemaVersion',
      'kind',
      'sequence',
      'stateSha256',
      'previousStateSha256',
      'encoding',
      'chunks',
      'payloadBytes',
      'payloadSha256',
      'containsSensitiveData',
    ]) ||
    manifest.schemaVersion !== 1 ||
    manifest.kind !== 'ROLLBACK_RESILIENCE_SSM_JOURNAL_ENTRY' ||
    manifest.sequence !== group.sequence ||
    manifest.stateSha256 !== group.stateSha256 ||
    manifest.previousStateSha256 !== previousStateSha256 ||
    manifest.encoding !== 'gzip-base64' ||
    !Number.isSafeInteger(manifest.chunks) ||
    manifest.chunks < 1 ||
    manifest.chunks > 32 ||
    !Number.isSafeInteger(manifest.payloadBytes) ||
    manifest.payloadBytes < 2 ||
    manifest.payloadBytes > MAX_RB_STATE_BYTES ||
    !SHA256.test(manifest.payloadSha256 ?? '') ||
    manifest.containsSensitiveData !== false
  ) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_MANIFEST_INVALID');
  }
  const pieces = [];
  for (let index = 1; index <= manifest.chunks; index += 1) {
    const entry = group.entries.get(`chunk-${String(index).padStart(4, '0')}`);
    if (entry === undefined) fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_CHUNK_MISSING');
    pieces.push(entry.value);
  }
  if (group.entries.size !== manifest.chunks + 1) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_CHUNK_EXTRA');
  }
  const encoded = pieces.join('');
  if (sha256(encoded) !== manifest.payloadSha256) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_PAYLOAD_DIGEST_INVALID');
  }
  let decoded;
  try {
    const compressed = Buffer.from(encoded, 'base64');
    if (compressed.toString('base64') !== encoded) throw new Error('NON_CANONICAL_BASE64');
    decoded = gunzipSync(compressed, { maxOutputLength: manifest.payloadBytes });
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_PAYLOAD_INVALID', error);
  }
  if (decoded.length !== manifest.payloadBytes) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_PAYLOAD_SIZE_INVALID');
  }
  const stateDocument = strictPublicJson(
    decoded.toString('utf8'),
    'E7_RELEASE_SUCCESSOR_RB_JOURNAL_STATE_INVALID',
  );
  const state = validateRbState(stateDocument.value, { scenarioId, bindingSha256 });
  if (state.stateSha256 !== group.stateSha256) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_STATE_DIGEST_INVALID');
  }
  return state;
};

const validateAbandonedRbGroup = ({ group, previousStateSha256 }) => {
  const abandonedEntry = group.entries.get('abandoned');
  if (abandonedEntry === undefined || group.entries.has('manifest')) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_ABANDONED_INVALID');
  }
  const marker = strictPublicJson(
    abandonedEntry.value,
    'E7_RELEASE_SUCCESSOR_RB_JOURNAL_ABANDONED_INVALID',
  ).value;
  if (
    !exactKeys(marker, [
      'schemaVersion',
      'kind',
      'sequence',
      'stateSha256',
      'previousStateSha256',
      'replacementStateSha256',
      'containsSensitiveData',
    ]) ||
    marker.schemaVersion !== 1 ||
    marker.kind !== 'ROLLBACK_RESILIENCE_SSM_JOURNAL_ABANDONED' ||
    marker.sequence !== group.sequence ||
    marker.stateSha256 !== group.stateSha256 ||
    marker.previousStateSha256 !== previousStateSha256 ||
    !SHA256.test(marker.replacementStateSha256 ?? '') ||
    marker.replacementStateSha256 === marker.stateSha256 ||
    marker.containsSensitiveData !== false
  ) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_ABANDONED_INVALID');
  }
  const chunks = [...group.entries.keys()].filter((name) => name.startsWith('chunk-')).toSorted();
  if (
    chunks.length < 1 ||
    chunks.some((name, index) => name !== `chunk-${String(index + 1).padStart(4, '0')}`)
  ) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_ABANDONED_CHUNKS_INVALID');
  }
  return marker;
};

const validateRbScenarioEntries = ({ entries, scenarioId, prefix, protectedRun, source }) => {
  const ownerName = `${prefix}/owner`;
  const premutationAuthorityName = `${prefix}/premutation-authority`;
  const ownerEntry = entries.find(({ name }) => name === ownerName);
  const premutationAuthorityEntry = entries.find(({ name }) => name === premutationAuthorityName);
  if (
    ownerEntry === undefined ||
    premutationAuthorityEntry === undefined ||
    entries.filter(({ name }) => name === ownerName).length !== 1 ||
    entries.filter(({ name }) => name === premutationAuthorityName).length !== 1
  ) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_OWNER_MISSING');
  }
  let owner;
  let premutationAuthority;
  try {
    premutationAuthority = validateRollbackSsmPremutationAuthority(
      strictPublicJson(
        premutationAuthorityEntry.value,
        'E7_RELEASE_SUCCESSOR_RB_PREMUTATION_AUTHORITY_INVALID',
      ).value,
      {
        candidateSha: source.candidateSha,
        scenarioId,
        releaseId: source.releaseId,
        releaseTag: source.releaseTag,
        configSha256: source.configSha256,
        sourceRunId: source.runId,
        sourceRunAttempt: source.runAttempt,
        protectedBindingSha256: protectedRun.runtimeAttestation.protectedBindingSha256,
        rollbackRoleSha256: protectedRun.runtimeAttestation.identity?.roleSha256,
        journalCleanupRoleSha256:
          protectedRun.runtimeAttestation.journalLifecycle.cleanupRoleSha256,
        journalLifecycleSha256: protectedRun.runtimeAttestation.journalLifecycle.lifecycleSha256,
      },
    );
    owner = validateRollbackJournalOwner(
      strictPublicJson(ownerEntry.value, 'E7_RELEASE_SUCCESSOR_RB_JOURNAL_OWNER_INVALID').value,
      {
        candidateSha: source.candidateSha,
        scenarioId,
        sourceRunId: source.runId,
        protectedBindingSha256: protectedRun.runtimeAttestation.protectedBindingSha256,
        rollbackRoleSha256: protectedRun.runtimeAttestation.identity?.roleSha256,
        journalCleanupRoleSha256:
          protectedRun.runtimeAttestation.journalLifecycle.cleanupRoleSha256,
        journalLifecycleSha256: protectedRun.runtimeAttestation.journalLifecycle.lifecycleSha256,
        premutationAuthority,
      },
    );
    const expectedCheckpoint =
      scenarioId === 'RB-E7-06' ? protectedRun.rb06Checkpoint : protectedRun.rb08Checkpoint;
    if (
      JSON.stringify(premutationAuthority) !== premutationAuthorityEntry.value ||
      JSON.stringify(owner) !== ownerEntry.value ||
      premutationAuthority.executionSha256 !== protectedRun.executionSha256 ||
      premutationAuthority.execution.repository !== protectedRun.runtimeAttestation.repository ||
      premutationAuthority.execution.workflow !== protectedRun.runtimeAttestation.workflow ||
      premutationAuthority.execution.runId !== protectedRun.runtimeAttestation.runId ||
      premutationAuthority.execution.runAttempt !== protectedRun.runtimeAttestation.runAttempt ||
      premutationAuthority.execution.githubSha !== protectedRun.runtimeAttestation.githubSha ||
      premutationAuthority.execution.protectedEnvironment !==
        protectedRun.runtimeAttestation.protectedEnvironment ||
      premutationAuthority.execution.startedAtUtc !== expectedCheckpoint?.startedAtUtc
    ) {
      fail('E7_RELEASE_SUCCESSOR_RB_PREMUTATION_AUTHORITY_MISMATCH');
    }
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_OWNER_INVALID', error);
  }
  const escaped = prefix.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  const pattern = new RegExp(
    `^${escaped}/([0-9]{6})-([0-9a-f]{64})/(manifest|abandoned|chunk-[0-9]{4})$`,
    'u',
  );
  const groups = new Map();
  for (const entry of entries.filter(
    ({ name }) => ![ownerName, premutationAuthorityName].includes(name),
  )) {
    const match = pattern.exec(entry.name);
    if (match === null) fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_NAME_INVALID');
    const sequence = Number(match[1]);
    if (sequence < 1) fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_SEQUENCE_INVALID');
    const key = `${match[1]}-${match[2]}`;
    const group = groups.get(key) ?? {
      sequence,
      stateSha256: match[2],
      entries: new Map(),
    };
    if (group.entries.has(match[3])) fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_ENTRY_DUPLICATE');
    group.entries.set(match[3], entry);
    groups.set(key, group);
  }
  const ordered = [...groups.values()].toSorted((left, right) => left.sequence - right.sequence);
  if (ordered.length < 1) fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_EMPTY');
  let previousStateSha256 = null;
  let bindingSha256;
  let lastState;
  for (const [index, group] of ordered.entries()) {
    if (group.sequence !== index + 1) fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_SEQUENCE_GAP');
    if (group.entries.has('abandoned')) {
      validateAbandonedRbGroup({ group, previousStateSha256 });
      continue;
    }
    const state = decodeRbGroup({
      group,
      previousStateSha256,
      scenarioId,
      bindingSha256,
    });
    if (state === null) fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_INCOMPLETE');
    bindingSha256 ??= state.bindingSha256;
    previousStateSha256 = state.stateSha256;
    lastState = state;
  }
  const expectedCheckpoint =
    scenarioId === 'RB-E7-06' ? protectedRun.rb06Checkpoint : protectedRun.rb08Checkpoint;
  if (
    lastState?.phase !== 'COMPLETE' ||
    owner.bindingSha256 !== bindingSha256 ||
    !object(lastState.checkpoint) ||
    !sameObject(lastState.checkpoint, expectedCheckpoint) ||
    lastState.checkpoint.checkpointSha256 !== expectedCheckpoint?.checkpointSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_RB_JOURNAL_FINAL_STATE_MISMATCH');
  }
  return {
    scenarioId,
    prefix,
    entryCount: entries.length,
    entrySetSha256: objectSha256(entries),
    ownerSha256: owner.ownerSha256,
    premutationAuthoritySha256: premutationAuthority.authoritySha256,
    finalStateSha256: lastState.stateSha256,
    finalCheckpointSha256: expectedCheckpoint.checkpointSha256,
    bindingSha256,
  };
};

const runtimeIndexPattern = (rootPrefix) => {
  const escaped = rootPrefix.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
  return new RegExp(
    `^${escaped}/(rollback-check|rollback-resilience)/(drift|smoke)/([0-9a-f]{64})/index$`,
    'u',
  );
};

const validateRuntimeProofIndex = ({ index, entry, owner, entriesByName }) => {
  const match = runtimeIndexPattern(owner.runtimeProofRootPrefix).exec(entry.name);
  const phase = match?.[1] === 'rollback-check' ? 'ROLLBACK_CHECK' : 'ROLLBACK_RESILIENCE';
  const proofKind = match?.[2]?.toUpperCase();
  if (
    match === null ||
    !exactKeys(index, [
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
    index.schemaVersion !== 1 ||
    index.stage !== 7 ||
    index.kind !== 'STAGE7_RELEASE_RECONCILIATION_RUNTIME_PROOF_INDEX' ||
    index.status !== 'RAW_BYTES_DURABLE' ||
    index.phase !== phase ||
    index.proofKind !== proofKind ||
    !sameObject(index.source, owner.source) ||
    index.ownerSha256 !== owner.ownerSha256 ||
    !SHA256.test(index.convergenceSha256 ?? '') ||
    index.indexParameterName !== entry.name ||
    index.rawSha256 !== match[3] ||
    ![index.rawSha256, index.canonicalSha256, index.chunksSha256].every((digest) =>
      SHA256.test(digest ?? ''),
    ) ||
    !Number.isSafeInteger(index.bytes) ||
    index.bytes < 2 ||
    index.bytes > MAX_RB_STATE_BYTES ||
    !utc(index.observedAtUtc) ||
    !Array.isArray(index.chunks) ||
    index.chunks.length < 1 ||
    index.chunks.length > 16 ||
    index.chunks.some(
      (chunk, offset) =>
        !exactKeys(chunk, ['sequence', 'parameterName', 'rawSha256', 'bytes']) ||
        chunk.sequence !== offset + 1 ||
        chunk.parameterName !==
          `${entry.name.slice(0, -'/index'.length)}/chunk/${String(offset + 1).padStart(4, '0')}-${chunk.rawSha256}` ||
        !SHA256.test(chunk.rawSha256 ?? '') ||
        !Number.isSafeInteger(chunk.bytes) ||
        chunk.bytes < 1 ||
        chunk.bytes > 3000,
    ) ||
    index.chunks.reduce((total, chunk) => total + chunk.bytes, 0) !== index.bytes ||
    index.chunksSha256 !== objectSha256(index.chunks) ||
    index.containsSensitiveData !== false ||
    index.indexSha256 !== objectSha256(withoutDigest(index, 'indexSha256'))
  ) {
    fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_PROOF_INDEX_INVALID');
  }
  const presentChunks = index.chunks.map((chunk) => entriesByName.get(chunk.parameterName));
  for (let offset = 0; offset < presentChunks.length; offset += 1) {
    const present = presentChunks[offset];
    if (present === undefined) continue;
    const expected = index.chunks[offset];
    if (present.rawSha256 !== expected.rawSha256 || present.bytes !== expected.bytes) {
      fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_PROOF_CHUNK_MISMATCH');
    }
  }
  return { index, presentChunks };
};

const validateReconciliationEntries = ({ entries, authority }) => {
  const expectedNames = authority.cleanupParameterNames;
  if (
    entries.map(({ name }) => name).join('\0') !==
    [...expectedNames].toSorted((left, right) => left.localeCompare(right)).join('\0')
  ) {
    fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_JOURNAL_SET_INVALID');
  }
  const entriesByName = new Map(entries.map((entry) => [entry.name, entry]));
  const ownerEntry = entriesByName.get(authority.ownerIndex.parameterName);
  if (ownerEntry === undefined) fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_OWNER_MISSING');
  const owner = validateReleaseRollbackJournalOwner(
    strictPublicJson(ownerEntry.value, 'E7_RELEASE_SUCCESSOR_RECONCILIATION_OWNER_INVALID').value,
  );
  if (!sameObject(owner, authority.ownerIndex)) {
    fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_OWNER_MISMATCH');
  }
  const intentText = owner.intentChunks
    .map((binding) => {
      const entry = entriesByName.get(binding.parameterName);
      if (
        entry === undefined ||
        entry.rawSha256 !== binding.rawSha256 ||
        entry.bytes !== binding.bytes
      ) {
        fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_INTENT_CHUNK_MISMATCH');
      }
      return entry.value;
    })
    .join('');
  const intentBytes = Buffer.from(intentText, 'utf8');
  const intent = validateReleaseReconciliationIntent(
    strictPublicJson(intentText, 'E7_RELEASE_SUCCESSOR_RECONCILIATION_INTENT_INVALID').value,
  );
  if (
    intentBytes.length !== owner.intentBytes ||
    sha256(intentBytes) !== owner.intentRawSha256 ||
    !sameObject(intent, authority.intentIndex)
  ) {
    fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_INTENT_MISMATCH');
  }
  const terminalsByIndexName = new Map();
  for (const binding of authority.terminals) {
    const entry = entriesByName.get(binding.name);
    if (entry === undefined || entry.version !== binding.version) {
      fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_TERMINAL_MISSING');
    }
    const terminal = validateReleaseReconciliationTerminal(
      strictPublicJson(entry.value, 'E7_RELEASE_SUCCESSOR_RECONCILIATION_TERMINAL_INVALID').value,
    );
    if (
      terminal.phase !== binding.phase ||
      terminal.terminalSha256 !== binding.terminalStateSha256 ||
      !sameObject(terminal.source, authority.source) ||
      terminal.ownerSha256 !== owner.ownerSha256
    ) {
      fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_TERMINAL_MISMATCH');
    }
    terminalsByIndexName.set(terminal.driftProofJournal.indexParameterName, {
      reference: terminal.driftProofJournal,
      terminal,
    });
    terminalsByIndexName.set(terminal.smokeProofJournal.indexParameterName, {
      reference: terminal.smokeProofJournal,
      terminal,
    });
  }
  const runtimeBindings = new Map(
    authority.runtimeProofParameters.map((binding) => [binding.name, binding]),
  );
  for (const [name, binding] of runtimeBindings) {
    const entry = entriesByName.get(name);
    if (
      entry === undefined ||
      entry.rawSha256 !== binding.rawSha256 ||
      entry.bytes !== binding.bytes ||
      entry.version !== binding.version
    ) {
      fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_PROOF_BINDING_MISMATCH');
    }
    if (name.includes('/chunk/') && !name.endsWith(`-${entry.rawSha256}`)) {
      fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_PROOF_CHUNK_NAME_INVALID');
    }
  }
  const validatedIndexes = new Map();
  for (const entry of entries.filter(({ name }) => name.endsWith('/index'))) {
    const index = strictPublicJson(
      entry.value,
      'E7_RELEASE_SUCCESSOR_RECONCILIATION_PROOF_INDEX_INVALID',
    ).value;
    validatedIndexes.set(
      entry.name,
      validateRuntimeProofIndex({ index, entry, owner, entriesByName }),
    );
  }
  for (const [indexName, { reference, terminal }] of terminalsByIndexName) {
    const validated = validatedIndexes.get(indexName);
    if (
      validated === undefined ||
      validated.presentChunks.some((entry) => entry === undefined) ||
      validated.index.indexSha256 !== reference.indexSha256 ||
      validated.index.rawSha256 !== reference.rawSha256 ||
      validated.index.canonicalSha256 !== reference.canonicalSha256 ||
      validated.index.bytes !== reference.bytes ||
      validated.index.observedAtUtc !== reference.observedAtUtc ||
      validated.index.chunks.length !== reference.chunkCount ||
      validated.index.chunksSha256 !== reference.chunksSha256
    ) {
      fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_PROOF_REFERENCE_MISMATCH');
    }
    const proofBytes = Buffer.from(
      validated.presentChunks.map((entry) => entry.value).join(''),
      'utf8',
    );
    const proof = strictPublicJson(
      proofBytes.toString('utf8'),
      'E7_RELEASE_SUCCESSOR_RECONCILIATION_PROOF_INVALID',
    ).value;
    if (
      proofBytes.length !== reference.bytes ||
      sha256(proofBytes) !== reference.rawSha256 ||
      objectSha256(proof) !== reference.canonicalSha256 ||
      reference.observedAtUtc !==
        (indexName.includes('/drift/') ? terminal.driftObservedAtUtc : terminal.smokeObservedAtUtc)
    ) {
      fail('E7_RELEASE_SUCCESSOR_RECONCILIATION_PROOF_MISMATCH');
    }
  }
  return {
    entryCount: entries.length,
    entrySetSha256: objectSha256(entries),
    ownerSha256: owner.ownerSha256,
    intentSha256: intent.intentSha256,
    runtimeProofParameterSetSha256: objectSha256(authority.runtimeProofParameters),
    terminalSetSha256: objectSha256(authority.terminals),
  };
};

const snapshotBody = (value) => withoutDigest(value, 'snapshotSha256');

export const validateReleaseSuccessorJournalSnapshot = (
  value,
  {
    reconciliationJournalAuthority,
    rollbackCheckReceipt,
    rollbackResilienceReceipt,
    protectedRun,
  } = {},
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'source',
      'scenarioPrefixes',
      'reconciliationRootPrefix',
      'reconciliationJournalAuthoritySha256',
      'entries',
      'entryCount',
      'targetNameSetSha256',
      'rbJournalEvidence',
      'reconciliationJournalEvidence',
      'containsSensitiveData',
      'snapshotSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'RELEASE_SUCCESSOR_COMBINED_JOURNAL_SNAPSHOT' ||
    value.status !== 'EXACT_VALUES_SEMANTICALLY_VALIDATED' ||
    !object(value.source) ||
    !exactKeys(value.scenarioPrefixes, SCENARIOS) ||
    !Object.values(value.scenarioPrefixes).every((prefix) =>
      /^\/checkout\/stage7\/rollback\/[0-9a-f]{40}\/RB-E7-(?:06|08)$/u.test(prefix),
    ) ||
    typeof value.reconciliationRootPrefix !== 'string' ||
    !SHA256.test(value.reconciliationJournalAuthoritySha256 ?? '') ||
    !Array.isArray(value.entries) ||
    value.entries.length < 3 ||
    value.entries.some((entry) => validateSnapshotEntry(entry) !== entry) ||
    value.entries.map(({ name }) => name).join('\0') !==
      value.entries
        .map(({ name }) => name)
        .toSorted((left, right) => left.localeCompare(right))
        .join('\0') ||
    new Set(value.entries.map(({ name }) => name)).size !== value.entries.length ||
    value.entryCount !== value.entries.length ||
    value.targetNameSetSha256 !== objectSha256(value.entries.map(({ name }) => name)) ||
    !exactKeys(value.rbJournalEvidence, SCENARIOS) ||
    !SCENARIOS.every((scenarioId) =>
      exactKeys(value.rbJournalEvidence[scenarioId], [
        'scenarioId',
        'prefix',
        'entryCount',
        'entrySetSha256',
        'ownerSha256',
        'premutationAuthoritySha256',
        'finalStateSha256',
        'finalCheckpointSha256',
        'bindingSha256',
      ]),
    ) ||
    !exactKeys(value.reconciliationJournalEvidence, [
      'entryCount',
      'entrySetSha256',
      'ownerSha256',
      'intentSha256',
      'runtimeProofParameterSetSha256',
      'terminalSetSha256',
    ]) ||
    value.containsSensitiveData !== false ||
    value.snapshotSha256 !== objectSha256(snapshotBody(value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_INVALID');
  }
  if (
    reconciliationJournalAuthority !== undefined ||
    rollbackCheckReceipt !== undefined ||
    rollbackResilienceReceipt !== undefined ||
    protectedRun !== undefined
  ) {
    if (
      reconciliationJournalAuthority === undefined ||
      rollbackCheckReceipt === undefined ||
      rollbackResilienceReceipt === undefined ||
      protectedRun === undefined
    ) {
      fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_EXPECTED_AUTHORITY_INCOMPLETE');
    }
    validateReleaseReconciliationJournalAuthority(reconciliationJournalAuthority, {
      rollbackCheckReceipt,
      rollbackResilienceReceipt,
    });
    if (
      value.reconciliationJournalAuthoritySha256 !==
        reconciliationJournalAuthority.journalAuthoritySha256 ||
      value.reconciliationRootPrefix !== reconciliationJournalAuthority.reconciliationRootPrefix ||
      !sameObject(value.source, reconciliationJournalAuthority.source)
    ) {
      fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_AUTHORITY_MISMATCH');
    }
    const rbEvidence = {};
    for (const scenarioId of SCENARIOS) {
      rbEvidence[scenarioId] = validateRbScenarioEntries({
        entries: value.entries.filter(({ name }) =>
          name.startsWith(`${value.scenarioPrefixes[scenarioId]}/`),
        ),
        scenarioId,
        prefix: value.scenarioPrefixes[scenarioId],
        protectedRun,
        source: value.source,
      });
    }
    const reconciliationEntries = value.entries.filter(({ name }) =>
      name.startsWith(`${value.reconciliationRootPrefix}/`),
    );
    const reconciliationEvidence = validateReconciliationEntries({
      entries: reconciliationEntries,
      authority: reconciliationJournalAuthority,
    });
    if (
      !sameObject(rbEvidence, value.rbJournalEvidence) ||
      !sameObject(reconciliationEvidence, value.reconciliationJournalEvidence) ||
      value.entries.length !==
        reconciliationEntries.length +
          SCENARIOS.reduce((total, scenarioId) => total + rbEvidence[scenarioId].entryCount, 0)
    ) {
      fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_EVIDENCE_MISMATCH');
    }
  }
  return value;
};

export const captureReleaseSuccessorJournalSnapshot = async ({
  scenarioPrefixes,
  reconciliationJournalAuthority,
  rollbackCheckReceipt,
  rollbackResilienceReceipt,
  protectedRun,
  getParametersByPath,
}) => {
  if (!exactKeys(scenarioPrefixes, SCENARIOS) || typeof getParametersByPath !== 'function') {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_INPUT_INVALID');
  }
  validateReleaseReconciliationJournalAuthority(reconciliationJournalAuthority, {
    rollbackCheckReceipt,
    rollbackResilienceReceipt,
  });
  const results = [];
  for (const scenarioId of SCENARIOS) {
    results.push(await listPrefix({ prefix: scenarioPrefixes[scenarioId], getParametersByPath }));
  }
  results.push(
    await listPrefix({
      prefix: reconciliationJournalAuthority.reconciliationRootPrefix,
      getParametersByPath,
    }),
  );
  const entries = results
    .flatMap(({ entries: listed }) => listed)
    .toSorted((left, right) => left.name.localeCompare(right.name));
  if (new Set(entries.map(({ name }) => name)).size !== entries.length) {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_CROSS_PREFIX_DUPLICATE');
  }
  const rbJournalEvidence = Object.fromEntries(
    SCENARIOS.map((scenarioId) => [
      scenarioId,
      validateRbScenarioEntries({
        entries: entries.filter(({ name }) => name.startsWith(`${scenarioPrefixes[scenarioId]}/`)),
        scenarioId,
        prefix: scenarioPrefixes[scenarioId],
        protectedRun,
        source: reconciliationJournalAuthority.source,
      }),
    ]),
  );
  const reconciliationEntries = entries.filter(({ name }) =>
    name.startsWith(`${reconciliationJournalAuthority.reconciliationRootPrefix}/`),
  );
  const reconciliationJournalEvidence = validateReconciliationEntries({
    entries: reconciliationEntries,
    authority: reconciliationJournalAuthority,
  });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_SUCCESSOR_COMBINED_JOURNAL_SNAPSHOT',
    status: 'EXACT_VALUES_SEMANTICALLY_VALIDATED',
    source: { ...reconciliationJournalAuthority.source },
    scenarioPrefixes: { ...scenarioPrefixes },
    reconciliationRootPrefix: reconciliationJournalAuthority.reconciliationRootPrefix,
    reconciliationJournalAuthoritySha256: reconciliationJournalAuthority.journalAuthoritySha256,
    entries,
    entryCount: entries.length,
    targetNameSetSha256: objectSha256(entries.map(({ name }) => name)),
    rbJournalEvidence,
    reconciliationJournalEvidence,
    containsSensitiveData: false,
  };
  return {
    snapshot: validateReleaseSuccessorJournalSnapshot(
      { ...body, snapshotSha256: objectSha256(body) },
      {
        reconciliationJournalAuthority,
        rollbackCheckReceipt,
        rollbackResilienceReceipt,
        protectedRun,
      },
    ),
    listPages: results.reduce((total, result) => total + result.pages, 0),
  };
};

export const requeryReleaseSuccessorJournalSnapshot = async ({ snapshot, getParametersByPath }) => {
  validateReleaseSuccessorJournalSnapshot(snapshot);
  if (typeof getParametersByPath !== 'function') {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_ADAPTER_REQUIRED');
  }
  const results = [];
  for (const scenarioId of SCENARIOS) {
    results.push(
      await listPrefix({ prefix: snapshot.scenarioPrefixes[scenarioId], getParametersByPath }),
    );
  }
  results.push(
    await listPrefix({
      prefix: snapshot.reconciliationRootPrefix,
      getParametersByPath,
    }),
  );
  const observedEntries = results
    .flatMap(({ entries }) => entries)
    .toSorted((left, right) => left.name.localeCompare(right.name));
  const expectedByName = new Map(snapshot.entries.map((entry) => [entry.name, entry]));
  if (
    new Set(observedEntries.map(({ name }) => name)).size !== observedEntries.length ||
    observedEntries.some((entry) => {
      const expected = expectedByName.get(entry.name);
      return expected === undefined || !sameObject(entry, expected);
    })
  ) {
    fail('E7_RELEASE_SUCCESSOR_JOURNAL_SNAPSHOT_LIVE_DRIFT');
  }
  const observedNames = new Set(observedEntries.map(({ name }) => name));
  const missingNames = snapshot.entries
    .map(({ name }) => name)
    .filter((name) => !observedNames.has(name));
  return {
    observedEntries,
    observedNames: observedEntries.map(({ name }) => name),
    missingNames,
    observedEntrySetSha256: objectSha256(observedEntries),
    observedNameSetSha256: objectSha256(observedEntries.map(({ name }) => name)),
    missingNameSetSha256: objectSha256(missingNames),
    listPages: results.reduce((total, result) => total + result.pages, 0),
  };
};
