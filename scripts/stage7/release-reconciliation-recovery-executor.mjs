import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import process from 'node:process';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson } from './core.mjs';
import {
  createReleaseReconciliationRecoveryActor,
  createReleaseReconciliationRecoveryClosure,
  createReleaseReconciliationRecoveryOutcome,
  createReleaseReconciliationRecoverySnapshot,
  validateReleaseReconciliationRecoveryActor,
  validateReleaseReconciliationRecoveryOutcome,
  validateReleaseReconciliationRecoveryPreservationIndex,
  validateReleaseReconciliationRecoverySnapshotForOutcome,
} from './release-reconciliation-recovery.mjs';
import {
  validateReleaseReconciliationIntent,
  validateReleaseRollbackJournalOwner,
} from './release-reconciliation.mjs';
import {
  convergeVersionedReleaseRuntime,
  finalizeVersionedReleaseRuntimeReconciliation,
  probeVersionedReleaseRuntimeTerminal,
  requireReleaseRollbackJournalOwner,
  resumeVersionedReleaseRuntimeReconciliation,
} from './release-reconciliation-executor.mjs';
import {
  RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT,
  RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT,
} from './release-successor-finalization.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const WORKFLOW_PATH = '.github/workflows/stage7-release-reconciliation-recovery.yml';
const REF = 'refs/heads/master';
const PROTECTED_ENVIRONMENT = 'assessment-release-reconciliation-recovery';
const SHA = /^[0-9a-f]{40}$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const ACCOUNT_ID = /^[0-9]{12}$/u;
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$/u;
const ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/([A-Za-z0-9+=,.@_/-]{1,512})$/u;
const PHASES = Object.freeze(['ROLLBACK_CHECK', 'ROLLBACK_RESILIENCE']);
const MAX_PARAMETER_BYTES = 3900;
const MAX_INTENT_CHUNKS = 16;
const MAX_RUNTIME_PROOF_PARAMETERS_PER_PHASE = 4 * (MAX_INTENT_CHUNKS + 1);
const MAX_RECONCILIATION_PARAMETERS =
  1 + MAX_INTENT_CHUNKS + PHASES.length + PHASES.length * MAX_RUNTIME_PROOF_PARAMETERS_PER_PHASE;
const MAX_RB_JOURNAL_PARAMETERS_PER_SCENARIO = 1 + 1 + 32;
const MAX_CANDIDATE_PARAMETERS =
  MAX_RECONCILIATION_PARAMETERS + PHASES.length * MAX_RB_JOURNAL_PARAMETERS_PER_SCENARIO;
const MAX_AWS_OUTPUT_BYTES = 32 * 1024 * 1024;
const AWS_TIMEOUT_MS = 20 * 60 * 1000;

export class Stage7ReleaseReconciliationRecoveryExecutorError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseReconciliationRecoveryExecutorError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseReconciliationRecoveryExecutorError(
    code,
    cause === undefined ? undefined : { cause },
  );
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const nowUtc = (clock) => {
  const value = clock();
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLOCK_INVALID');
  return date.toISOString();
};
const rootFor = (candidateSha, originalRunId) =>
  `/checkout/stage7/rollback/${candidateSha}/release-reconciliation/${originalRunId}`;
const phaseSlug = (phase) =>
  phase === 'ROLLBACK_CHECK' ? 'rollback-check' : 'rollback-resilience';
const parseDocument = (source, code) => {
  try {
    return parseStrictJsonSource(Buffer.from(source ?? '', 'utf8'), { scanForbiddenData: false });
  } catch (error) {
    fail(code, error);
  }
};
const normalizeModified = (value) => {
  if (!['string', 'number'].includes(typeof value) || Number.isNaN(new Date(value).getTime())) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_PARAMETER_INVALID');
  }
  return new Date(value).toISOString();
};
const normalizeParameter = (value, { accountId, region, root }) => {
  if (
    !exactKeys(value, [
      'Name',
      'Type',
      'Value',
      'Version',
      'LastModifiedDate',
      'ARN',
      'DataType',
    ]) ||
    typeof value.Name !== 'string' ||
    !value.Name.startsWith(`${root}/`) ||
    value.Type !== 'String' ||
    typeof value.Value !== 'string' ||
    Buffer.byteLength(value.Value, 'utf8') > MAX_PARAMETER_BYTES ||
    value.Version !== 1 ||
    value.ARN !== `arn:aws:ssm:${region}:${accountId}:parameter${value.Name}` ||
    value.DataType !== 'text'
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_PARAMETER_INVALID');
  }
  return {
    name: value.Name,
    type: value.Type,
    value: value.Value,
    version: value.Version,
    lastModifiedAtUtc: normalizeModified(value.LastModifiedDate),
    arn: value.ARN,
    dataType: value.DataType,
  };
};

export const createAwsCliReleaseReconciliationRecoveryRuntime = ({
  candidateSha,
  originalRunId,
  phase,
  accountId,
  region,
  recoveryRoleArn,
  capability = 'RECOVERY',
  controlSha,
  environmentVariables = process.env,
  awsCommand = process.platform === 'win32' ? 'aws.cmd' : 'aws',
  spawn = spawnSync,
}) => {
  const role = ROLE_ARN.exec(recoveryRoleArn ?? '');
  const cleanupCapability = capability === 'CLEANUP';
  const recoveryRunId = environmentVariables.GITHUB_RUN_ID;
  const recoveryRunAttempt = environmentVariables.GITHUB_RUN_ATTEMPT;
  const sessionName = cleanupCapability
    ? `e7-reconciliation-recovery-cleanup-${recoveryRunId}-${recoveryRunAttempt}`
    : `e7-reconciliation-recovery-${recoveryRunId}-${recoveryRunAttempt}`;
  const root = rootFor(candidateSha, originalRunId);
  const candidateRoot = `/checkout/stage7/rollback/${candidateSha}`;
  const completionGuardRoots = Object.freeze([
    `${RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT}/${candidateSha}`,
    `${RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT}/${candidateSha}`,
  ]);
  const readableRoots = new Set([root, candidateRoot, ...completionGuardRoots]);
  if (
    !['RECOVERY', 'CLEANUP'].includes(capability) ||
    !SHA.test(candidateSha ?? '') ||
    !RUN_ID.test(originalRunId ?? '') ||
    !PHASES.includes(phase) ||
    !ACCOUNT_ID.test(accountId ?? '') ||
    !REGION.test(region ?? '') ||
    role?.[1] !== accountId ||
    !SHA.test(controlSha ?? '') ||
    typeof spawn !== 'function' ||
    environmentVariables.GITHUB_REPOSITORY !== REPOSITORY ||
    environmentVariables.GITHUB_WORKFLOW_REF !== `${REPOSITORY}/${WORKFLOW_PATH}@${REF}` ||
    environmentVariables.GITHUB_REF !== REF ||
    environmentVariables.GITHUB_SHA !== controlSha ||
    environmentVariables.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    environmentVariables.STAGE7_PROTECTED_ENVIRONMENT !== PROTECTED_ENVIRONMENT ||
    environmentVariables.STAGE7_RECOVERY_CANDIDATE_SHA !== candidateSha ||
    environmentVariables.STAGE7_AWS_ACCOUNT_ID !== accountId ||
    environmentVariables.AWS_REGION !== region ||
    environmentVariables.AWS_DEFAULT_REGION !== region ||
    (cleanupCapability
      ? environmentVariables.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN !== recoveryRoleArn
      : environmentVariables.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN !== recoveryRoleArn) ||
    !RUN_ID.test(recoveryRunId ?? '') ||
    !/^[1-9][0-9]{0,2}$/u.test(recoveryRunAttempt ?? '') ||
    sessionName.length > 64
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_AWS_INPUT_INVALID');
  }
  const allowedError = Symbol('allowedError');
  let externalCalls = 0;
  const run = (arguments_, code, { allowedErrorCodes = [], emptySuccess = false } = {}) => {
    externalCalls += 1;
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
        return { [allowedError]: errorCode };
      }
      fail(code, result.error);
    }
    if (
      typeof result.stdout !== 'string' ||
      Buffer.byteLength(result.stdout, 'utf8') > MAX_AWS_OUTPUT_BYTES
    ) {
      fail(code);
    }
    if (emptySuccess && result.stdout.trim() === '') return null;
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
    'E7_RELEASE_RECONCILIATION_RECOVERY_STS_FAILED',
  );
  const roleName = role[2].split('/').at(-1);
  if (
    !exactKeys(identity, ['UserId', 'Account', 'Arn']) ||
    identity.Account !== accountId ||
    identity.Arn !== `arn:aws:sts::${accountId}:assumed-role/${roleName}/${sessionName}` ||
    typeof identity.UserId !== 'string' ||
    !identity.UserId.endsWith(`:${sessionName}`)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_STS_IDENTITY_INVALID');
  }
  const get = async (name) => {
    if (typeof name !== 'string' || !name.startsWith(`${root}/`)) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_GET_INPUT_INVALID');
    }
    const response = run(
      ['ssm', 'get-parameter', '--name', name, '--output', 'json'],
      'E7_RELEASE_RECONCILIATION_RECOVERY_GET_FAILED',
      { allowedErrorCodes: ['ParameterNotFound'] },
    );
    if (response?.[allowedError] === 'ParameterNotFound') return null;
    if (!exactKeys(response, ['Parameter']) || !object(response.Parameter)) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_GET_INVALID');
    }
    const parameter = normalizeParameter(response.Parameter, { accountId, region, root });
    if (parameter.name !== name) fail('E7_RELEASE_RECONCILIATION_RECOVERY_GET_INVALID');
    return parameter;
  };
  const listPath = async (requestedRoot, { stopAfterFirst = false } = {}) => {
    if (!readableRoots.has(requestedRoot)) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_LIST_INPUT_INVALID');
    }
    const maximumParameters =
      requestedRoot === candidateRoot ? MAX_CANDIDATE_PARAMETERS : MAX_RECONCILIATION_PARAMETERS;
    const maximumPages = Math.ceil(maximumParameters / 10);
    const output = [];
    const seenTokens = new Set();
    let nextToken = null;
    let pages = 0;
    do {
      pages += 1;
      if (pages > maximumPages) fail('E7_RELEASE_RECONCILIATION_RECOVERY_PAGE_LIMIT');
      const arguments_ = [
        'ssm',
        'get-parameters-by-path',
        '--path',
        requestedRoot,
        '--recursive',
        '--max-results',
        '10',
        '--no-paginate',
        '--output',
        'json',
      ];
      if (nextToken !== null) arguments_.push('--next-token', nextToken);
      const response = run(arguments_, 'E7_RELEASE_RECONCILIATION_RECOVERY_LIST_FAILED');
      if (
        !object(response) ||
        !Array.isArray(response.Parameters) ||
        response.Parameters.length > 10 ||
        Object.keys(response).some((key) => !['Parameters', 'NextToken'].includes(key))
      ) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_LIST_INVALID');
      }
      output.push(
        ...response.Parameters.map((parameter) =>
          normalizeParameter(parameter, { accountId, region, root: requestedRoot }),
        ),
      );
      if (output.length > maximumParameters) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_LIST_TOO_LARGE');
      }
      if (stopAfterFirst && output.length > 0) return output;
      nextToken = response.NextToken ?? null;
      if (nextToken !== null && (typeof nextToken !== 'string' || nextToken === '')) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_TOKEN_INVALID');
      }
      if (nextToken !== null) {
        if (seenTokens.has(nextToken)) fail('E7_RELEASE_RECONCILIATION_RECOVERY_TOKEN_CYCLE');
        seenTokens.add(nextToken);
      }
    } while (nextToken !== null);
    const names = output.map(({ name }) => name);
    if (new Set(names).size !== names.length) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_LIST_DUPLICATE');
    }
    return output.toSorted((left, right) => left.name.localeCompare(right.name));
  };
  const list = async (requestedRoot) => {
    if (requestedRoot !== root) fail('E7_RELEASE_RECONCILIATION_RECOVERY_LIST_INPUT_INVALID');
    return listPath(requestedRoot);
  };
  const writableName = (name) => {
    const escaped = root.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
    const phasePath = phaseSlug(phase);
    return new RegExp(
      `^${escaped}/(?:${phasePath}/terminal|runtime-proofs/${phasePath}/(?:drift|smoke)/[0-9a-f]{64}/(?:index|chunk/[0-9]{4}-[0-9a-f]{64}))$`,
      'u',
    ).test(name);
  };
  const putImmutable = async ({ name, value }) => {
    if (
      cleanupCapability ||
      typeof name !== 'string' ||
      !writableName(name) ||
      typeof value !== 'string' ||
      Buffer.byteLength(value, 'utf8') > MAX_PARAMETER_BYTES
    ) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_PUT_INPUT_INVALID');
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
      'E7_RELEASE_RECONCILIATION_RECOVERY_PUT_FAILED',
      { allowedErrorCodes: ['ParameterAlreadyExists'] },
    );
    const readback = await get(name);
    if (
      readback === null ||
      readback.value !== value ||
      (response?.[allowedError] === undefined &&
        (!exactKeys(response, ['Version', 'Tier']) ||
          response.Version !== 1 ||
          response.Tier !== 'Standard'))
    ) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_PUT_MISMATCH');
    }
    return readback;
  };
  const deleteOne = async (name) => {
    if (!cleanupCapability || typeof name !== 'string' || !name.startsWith(`${root}/`)) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_DELETE_INPUT_INVALID');
    }
    const response = run(
      ['ssm', 'delete-parameter', '--name', name, '--output', 'json'],
      'E7_RELEASE_RECONCILIATION_RECOVERY_DELETE_FAILED',
      { allowedErrorCodes: ['ParameterNotFound'], emptySuccess: true },
    );
    if (response !== null && response?.[allowedError] !== 'ParameterNotFound') {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_DELETE_INVALID');
    }
  };
  return {
    candidateRootPrefix: candidateRoot,
    reconciliationRootPrefix: root,
    completionGuardRoots,
    listCandidateJournal: () => listPath(candidateRoot),
    listCompletionGuard: (guardRoot) => listPath(guardRoot, { stopAfterFirst: true }),
    store: {
      candidateRootPrefix: candidateRoot,
      reconciliationRootPrefix: root,
      get,
      list,
      putImmutable,
    },
    deleteOne,
    externalCallCount: () => externalCalls,
  };
};

const requireRecoveryStillPreFence = async ({ runtime }) => {
  if (
    !Array.isArray(runtime?.completionGuardRoots) ||
    runtime.completionGuardRoots.length !== 2 ||
    typeof runtime.listCompletionGuard !== 'function' ||
    typeof runtime.listCandidateJournal !== 'function'
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_GUARD_RUNTIME_INVALID');
  }
  for (const guardRoot of runtime.completionGuardRoots) {
    const entries = await runtime.listCompletionGuard(guardRoot);
    if (!Array.isArray(entries) || entries.length !== 0) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_POST_FENCE_BLOCKED');
    }
  }
  const candidateEntries = await runtime.listCandidateJournal();
  const allowedPrefixes = [
    `${runtime.candidateRootPrefix}/RB-E7-06/`,
    `${runtime.candidateRootPrefix}/RB-E7-08/`,
    `${runtime.reconciliationRootPrefix}/`,
  ];
  if (
    !Array.isArray(candidateEntries) ||
    candidateEntries.some(({ name }) => allowedPrefixes.every((prefix) => !name.startsWith(prefix)))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_FOREIGN_JOURNAL_BLOCKED');
  }
};

export const loadReleaseReconciliationRecoveryJournal = async ({ runtime }) => {
  const root = runtime?.reconciliationRootPrefix;
  if (typeof root !== 'string' || !object(runtime.store)) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_RUNTIME_INVALID');
  }
  const parameters = await runtime.store.list(root);
  const ownerParameter = parameters.find(({ name }) => name === `${root}/owner`);
  if (ownerParameter === undefined) fail('E7_RELEASE_RECONCILIATION_RECOVERY_OWNER_REQUIRED');
  const owner = validateReleaseRollbackJournalOwner(
    parseDocument(ownerParameter.value, 'E7_RELEASE_RECONCILIATION_RECOVERY_OWNER_INVALID'),
  );
  if (owner.reconciliationRootPrefix !== root || owner.parameterName !== ownerParameter.name) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_OWNER_SCOPE_MISMATCH');
  }
  const chunks = owner.intentChunks.map((binding) => {
    const parameter = parameters.find(({ name }) => name === binding.parameterName);
    if (
      parameter === undefined ||
      parameter.version !== 1 ||
      Buffer.byteLength(parameter.value, 'utf8') !== binding.bytes ||
      sha256(Buffer.from(parameter.value, 'utf8')) !== binding.rawSha256
    ) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_INTENT_CHUNK_INVALID');
    }
    return parameter.value;
  });
  const intentBytes = Buffer.from(chunks.join(''), 'utf8');
  if (intentBytes.length !== owner.intentBytes || sha256(intentBytes) !== owner.intentRawSha256) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_INTENT_BYTES_INVALID');
  }
  const intent = validateReleaseReconciliationIntent(
    parseDocument(intentBytes, 'E7_RELEASE_RECONCILIATION_RECOVERY_INTENT_INVALID'),
  );
  if (
    canonicalJson(intent) !== intentBytes.toString('utf8') ||
    intent.intentSha256 !== owner.intentSha256 ||
    intent.bindingsSha256 !== owner.intentBindingsSha256 ||
    canonicalJson(intent.source) !== canonicalJson(owner.source)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_INTENT_OWNER_MISMATCH');
  }
  const validated = await requireReleaseRollbackJournalOwner({ intent, store: runtime.store });
  return { owner: validated.owner, intent: validated.intent, parameters: validated.parameters };
};

export const inspectReleaseReconciliationRecovery = async ({
  runtime,
  request,
  approval,
  liveRecoveryRoleEffectivePermissionsSource,
  recoveryRoleArn,
  environmentVariables = process.env,
  originalJobConclusion,
  phase,
  clock = () => new Date(),
}) => {
  await requireRecoveryStillPreFence({ runtime });
  const { owner, intent, parameters } = await loadReleaseReconciliationRecoveryJournal({ runtime });
  const actor = createReleaseReconciliationRecoveryActor({
    intent,
    request,
    approval,
    liveRecoveryRoleEffectivePermissionsSource,
    recoveryRoleArn,
    environmentVariables,
    createdAtUtc: nowUtc(clock),
    phase,
    originalJobConclusion,
  });
  const probe = await probeVersionedReleaseRuntimeTerminal({
    phase,
    intent,
    originalJobConclusion,
    store: runtime.store,
  });
  return {
    decision: probe.status === 'TERMINAL_PRESENT' ? 'RESUME_TERMINAL' : 'CONVERGE_FORWARD_N',
    actor,
    owner,
    intent,
    probe,
    journalParameterCount: parameters.length,
    externalWritesPerformed: 0,
  };
};

export const resumeReleaseReconciliationRecovery = async ({
  runtime,
  actor,
  intent,
  clock = () => new Date(),
}) => {
  validateReleaseReconciliationRecoveryActor(actor, intent);
  const result = await resumeVersionedReleaseRuntimeReconciliation({
    phase: actor.phase,
    intent,
    originalJobConclusion: actor.originalJobConclusion,
    store: runtime.store,
  });
  if (result.receipt === null) fail('E7_RELEASE_RECONCILIATION_RECOVERY_TERMINAL_REQUIRED');
  const receiptSource = Buffer.from(`${JSON.stringify(result.receipt)}\n`, 'utf8');
  return {
    ...result,
    outcome: createReleaseReconciliationRecoveryOutcome({
      actor,
      receiptSource,
      mode: 'TERMINAL_RESUMED',
      completedAtUtc: nowUtc(clock),
    }),
  };
};

export const convergeReleaseReconciliationRecoveryForward = async ({
  runtime,
  actor,
  intent,
  rollbackFlags,
  executeVersionedRollbackRecovery,
  environmentVariables = process.env,
  clock = () => new Date(),
  rollbackExecutor,
  delayImplementation,
}) => {
  validateReleaseReconciliationRecoveryActor(actor, intent);
  if (typeof executeVersionedRollbackRecovery !== 'function') {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_FORWARD_ADAPTER_REQUIRED');
  }
  return convergeVersionedReleaseRuntime({
    phase: actor.phase,
    intent,
    store: runtime.store,
    rollbackFlags,
    environmentVariables,
    clock,
    executeRollback: (arguments_) =>
      executeVersionedRollbackRecovery({
        ...arguments_,
        recoveryActor: actor,
        recoveryIntent: intent,
      }),
    rollbackExecutor,
    delayImplementation,
  });
};

export const finalizeReleaseReconciliationRecoveryForward = async ({
  runtime,
  actor,
  convergence,
  driftEvidenceSource,
  smokeEvidenceSource,
  clock = () => new Date(),
}) => {
  validateReleaseReconciliationRecoveryActor(actor, convergence.intent);
  if (
    convergence.phase !== actor.phase ||
    canonicalJson(convergence.source) !== canonicalJson(actor.originalSource)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CONVERGENCE_MISMATCH');
  }
  const smokeDocument = parseDocument(
    smokeEvidenceSource,
    'E7_RELEASE_RECONCILIATION_RECOVERY_SMOKE_ACTOR_BINDING_INVALID',
  );
  if (smokeDocument?.reconciliationRecoveryActorSha256 !== actor.actorSha256) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SMOKE_ACTOR_BINDING_INVALID');
  }
  const result = await finalizeVersionedReleaseRuntimeReconciliation({
    convergence,
    originalJobConclusion: actor.originalJobConclusion,
    driftEvidenceSource,
    smokeEvidenceSource,
    store: runtime.store,
    clock,
  });
  const receiptSource = Buffer.from(`${JSON.stringify(result.receipt)}\n`, 'utf8');
  return {
    ...result,
    outcome: createReleaseReconciliationRecoveryOutcome({
      actor,
      receiptSource,
      mode: 'FORWARD_CONVERGED',
      completedAtUtc: nowUtc(clock),
    }),
  };
};

export const snapshotReleaseReconciliationRecovery = async ({
  runtime,
  outcome,
  clock = () => new Date(),
}) => {
  validateReleaseReconciliationRecoveryOutcome(outcome);
  const parameters = await runtime.store.list(runtime.reconciliationRootPrefix);
  return createReleaseReconciliationRecoverySnapshot({
    outcome,
    parameters,
    capturedAtUtc: nowUtc(clock),
  });
};

export const cleanupReleaseReconciliationRecovery = async ({
  runtime,
  cleanupActor,
  outcome,
  snapshot,
  preservationIndex,
  preservationArtifact,
  cleanupRoleAuthority,
  clock = () => new Date(),
}) => {
  await requireRecoveryStillPreFence({ runtime });
  validateReleaseReconciliationRecoveryActor(cleanupActor);
  validateReleaseReconciliationRecoverySnapshotForOutcome(snapshot, outcome);
  validateReleaseReconciliationRecoveryPreservationIndex(preservationIndex);
  if (
    preservationIndex.outcomeSha256 !== outcome.outcomeSha256 ||
    preservationIndex.snapshotSha256 !== snapshot.snapshotSha256 ||
    preservationIndex.artifactName !== snapshot.preservationArtifactName
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_PRESERVATION_INDEX_MISMATCH');
  }
  const live = await runtime.store.list(runtime.reconciliationRootPrefix);
  const snapshotByName = new Map(
    snapshot.parameters.map((parameter) => [parameter.name, parameter]),
  );
  for (const parameter of live) {
    const preserved = snapshotByName.get(parameter.name);
    if (
      preserved === undefined ||
      parameter.version !== preserved.version ||
      parameter.value !== preserved.value ||
      sha256(Buffer.from(parameter.value, 'utf8')) !== preserved.rawSha256
    ) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLEANUP_DRIFT');
    }
  }
  const ownerName = `${runtime.reconciliationRootPrefix}/owner`;
  const orderedNames = snapshot.parameters
    .map(({ name }) => name)
    .toSorted((left, right) => {
      const rank = (name) => (name === ownerName ? 2 : name.includes('/intent/') ? 1 : 0);
      return rank(left) - rank(right) || left.localeCompare(right);
    });
  for (const name of orderedNames) await runtime.deleteOne(name);
  const residual = await runtime.store.list(runtime.reconciliationRootPrefix);
  if (residual.length !== 0) fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLEANUP_RESIDUAL');
  return createReleaseReconciliationRecoveryClosure({
    cleanupActor,
    outcome,
    snapshot,
    preservationIndex,
    preservationArtifact,
    cleanupRoleAuthority,
    deletedParameterNames: snapshot.parameters.map(({ name }) => name),
    residualParameterNames: [],
    completedAtUtc: nowUtc(clock),
  });
};
