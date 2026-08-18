#!/usr/bin/env node

import { Buffer } from 'node:buffer';
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, workspaceRoot } from './core.mjs';
import {
  STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT,
  classifyReleasePublicationState,
  createReleasePreFenceGate,
  validateReleasePublicationExpectation,
  validateReleasePublicationObservation,
  validateReleaseReconciliationIntent,
} from './release-reconciliation.mjs';
import { RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS } from './release-reconciliation-authority.mjs';
import {
  convergeVersionedReleaseRuntime,
  createAwsCliReleaseReconciliationRuntime,
  createReleaseReconciliationIntentFromSources,
  finalizeVersionedReleaseRuntimeReconciliation,
  openReleaseRollbackJournal,
  probeVersionedReleaseRuntimeTerminal,
  readReleaseReconciliationJsonFile,
  recoverVersionedReleaseRuntimeConvergenceCheckpoint,
  resumeVersionedReleaseRuntimeReconciliation,
  validateReleaseRuntimeConvergence,
} from './release-reconciliation-executor.mjs';
import {
  RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS,
  RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
  RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
} from './release-successor-rollback-authority.mjs';

const MAX_FILE_BYTES = 32 * 1024 * 1024;
const PHASES = Object.freeze(['ROLLBACK_CHECK', 'ROLLBACK_RESILIENCE']);
const JOB_CONCLUSIONS = Object.freeze(['SUCCESS', 'FAILURE', 'CANCELLED', 'TIMED_OUT', 'SKIPPED']);

class Stage7ReleaseReconciliationCliError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseReconciliationCliError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseReconciliationCliError(code, cause === undefined ? undefined : { cause });
};
const inside = (base, candidate) => {
  const relative = path.relative(base, candidate);
  return (
    relative !== '' &&
    relative !== '..' &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
  );
};
const resolveInput = (filename, code) => {
  if (typeof filename !== 'string' || filename === '') fail(code);
  const absolute = path.resolve(workspaceRoot, filename);
  if (!inside(workspaceRoot, absolute) || !existsSync(absolute)) fail(code);
  const metadata = lstatSync(absolute);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_FILE_BYTES) fail(code);
  const real = realpathSync(absolute);
  if (!inside(workspaceRoot, real)) fail(code);
  return absolute;
};
const resolveDirectory = (filename, code) => {
  if (typeof filename !== 'string' || filename === '') fail(code);
  const absolute = path.resolve(workspaceRoot, filename);
  if (!inside(workspaceRoot, absolute) || !existsSync(absolute)) fail(code);
  const metadata = lstatSync(absolute);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail(code);
  const real = realpathSync(absolute);
  if (!inside(workspaceRoot, real)) fail(code);
  return absolute;
};
const resolveOutput = (filename, code) => {
  if (typeof filename !== 'string' || filename === '') fail(code);
  const absolute = path.resolve(workspaceRoot, filename);
  if (!inside(workspaceRoot, absolute)) fail(code);
  const parent = path.dirname(absolute);
  const missing = [];
  let existingAncestor = parent;
  while (!existsSync(existingAncestor)) {
    missing.push(existingAncestor);
    const next = path.dirname(existingAncestor);
    if (next === existingAncestor) fail(code);
    existingAncestor = next;
  }
  const realAncestor = realpathSync(existingAncestor);
  if (!inside(workspaceRoot, realAncestor) && realAncestor !== workspaceRoot) fail(code);
  for (const directory of missing.reverse()) {
    try {
      mkdirSync(directory, { mode: 0o700 });
    } catch (error) {
      if (!existsSync(directory)) fail(code, error);
    }
    const metadata = lstatSync(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail(code);
    const realDirectory = realpathSync(directory);
    if (!inside(workspaceRoot, realDirectory)) fail(code);
  }
  const realParent = realpathSync(parent);
  if (!inside(workspaceRoot, realParent) && realParent !== workspaceRoot) fail(code);
  if (existsSync(absolute)) {
    const metadata = lstatSync(absolute);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_FILE_BYTES)
      fail(code);
  }
  return absolute;
};
const readBytes = (filename, code) => readFileSync(resolveInput(filename, code));
const readJson = (filename, code) =>
  readReleaseReconciliationJsonFile(resolveInput(filename, code), code).value;
const writeJsonImmutable = (filename, value, code) => {
  const absolute = resolveOutput(filename, code);
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8');
  if (bytes.length > MAX_FILE_BYTES) fail(code);
  if (existsSync(absolute)) {
    let existing;
    try {
      existing = parseStrictJsonSource(readFileSync(absolute), { scanForbiddenData: false });
    } catch (error) {
      fail('E7_RELEASE_RECONCILIATION_CLI_OUTPUT_CONFLICT', error);
    }
    if (canonicalJson(existing) !== canonicalJson(value)) {
      fail('E7_RELEASE_RECONCILIATION_CLI_OUTPUT_CONFLICT');
    }
    return absolute;
  }
  const temporary = `${absolute}.${process.pid}.${Date.now()}.tmp`;
  try {
    writeFileSync(temporary, bytes, { flag: 'wx', mode: 0o600 });
    chmodSync(temporary, 0o600);
    linkSync(temporary, absolute);
    unlinkSync(temporary);
  } catch (error) {
    if (existsSync(temporary)) unlinkSync(temporary);
    if (existsSync(absolute)) {
      let existing;
      try {
        existing = parseStrictJsonSource(readFileSync(absolute), { scanForbiddenData: false });
      } catch {
        fail('E7_RELEASE_RECONCILIATION_CLI_OUTPUT_CONFLICT', error);
      }
      if (canonicalJson(existing) === canonicalJson(value)) return absolute;
    }
    fail(code, error);
  }
  return absolute;
};
const parseFlags = (arguments_, { required, allowed = [] }) => {
  if (arguments_.length % 2 !== 0) fail('E7_RELEASE_RECONCILIATION_CLI_FLAGS_INVALID');
  const permitted = new Set([...required, ...allowed]);
  const flags = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const raw = arguments_[index];
    const value = arguments_[index + 1];
    const key = raw?.startsWith('--') && !raw.includes('=') ? raw.slice(2) : '';
    if (
      !permitted.has(key) ||
      typeof value !== 'string' ||
      value === '' ||
      value.startsWith('--') ||
      Object.hasOwn(flags, key)
    ) {
      fail('E7_RELEASE_RECONCILIATION_CLI_FLAGS_INVALID');
    }
    flags[key] = value;
  }
  if (required.some((key) => !Object.hasOwn(flags, key))) {
    fail('E7_RELEASE_RECONCILIATION_CLI_FLAGS_INVALID');
  }
  return flags;
};
const intentFrom = (flags) =>
  validateReleaseReconciliationIntent(
    readJson(flags.intent, 'E7_RELEASE_RECONCILIATION_CLI_INTENT_INVALID'),
  );
const runtimeFrom = (intent, capability) =>
  createAwsCliReleaseReconciliationRuntime({
    intent,
    capability,
  });
const phaseFrom = (flags) => {
  if (!PHASES.includes(flags.phase)) fail('E7_RELEASE_RECONCILIATION_CLI_PHASE_INVALID');
  return flags.phase;
};
const jobConclusionFrom = (flags) => {
  if (!JOB_CONCLUSIONS.includes(flags['original-job-conclusion'])) {
    fail('E7_RELEASE_RECONCILIATION_CLI_JOB_CONCLUSION_INVALID');
  }
  return flags['original-job-conclusion'];
};

const INTENT_SOURCE_FLAGS = RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS;
const INTENT_DESCRIPTORS = new Map(
  STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.map((descriptor) => [descriptor.label, descriptor]),
);
const createIntentSources = (flags) =>
  Object.fromEntries(
    INTENT_SOURCE_FLAGS.map(([label, flag]) => {
      const descriptor = INTENT_DESCRIPTORS.get(label);
      const absolute = resolveInput(
        flags[flag],
        `E7_RELEASE_RECONCILIATION_CLI_${flag.toUpperCase().replaceAll('-', '_')}_INVALID`,
      );
      if (path.basename(absolute) !== descriptor?.path) {
        fail('E7_RELEASE_RECONCILIATION_CLI_INTENT_BASENAME_INVALID');
      }
      return [label, readFileSync(absolute)];
    }),
  );
const githubIdentityFromEnvironment = () => ({
  repository: process.env.GITHUB_REPOSITORY,
  workflowRef: process.env.GITHUB_WORKFLOW_REF,
  ref: process.env.GITHUB_REF,
  runId: process.env.GITHUB_RUN_ID,
  runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
  candidateSha: process.env.GITHUB_SHA,
});
const ROLLBACK_FILE_FLAGS = Object.freeze([
  'app',
  'manifest',
  'previous-manifest',
  'previous-api-contract-evidence',
  'previous-pending-evidence',
  'previous-smoke-evidence',
  'candidate-record',
  'approval',
  'approved-plan',
  'deployment-evidence',
  'aws-auth',
  'journal-role-effective-permissions',
  'reconciliation-recovery-role-effective-permissions',
]);
const SUCCESSOR_GUARD_MODES = Object.freeze({
  ROLLBACK_CHECK: 'ROLLBACK_CHECK',
  ROLLBACK_RESILIENCE_COMPLETED: 'RECONCILIATION',
  ROLLBACK_RESILIENCE_INCOMPLETE: 'INCOMPLETE_RECONCILIATION',
});
const SUCCESSOR_GUARD_COMMON_FLAGS = Object.freeze([
  'successor-guard-mode',
  'reconciliation-intent',
  ...INTENT_SOURCE_FLAGS.map(([, flag]) => flag),
]);
const SUCCESSOR_GUARD_PREMUTATION_FLAGS = Object.freeze([
  ...RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
  ...RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
]);
const SUCCESSOR_GUARD_COMPLETION_FLAGS = RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS;
const SUCCESSOR_GUARD_RECONCILIATION_EXTRA_FLAGS = Object.freeze(
  [...SUCCESSOR_GUARD_PREMUTATION_FLAGS, ...SUCCESSOR_GUARD_COMPLETION_FLAGS].filter(
    (flag) => !ROLLBACK_FILE_FLAGS.includes(flag) && !SUCCESSOR_GUARD_COMMON_FLAGS.includes(flag),
  ),
);
const rollbackFlagsFrom = (flags, phase) => {
  const guardMode = flags['successor-guard-mode'];
  const rollbackCheckMode = phase === 'ROLLBACK_CHECK' && guardMode === 'ROLLBACK_CHECK';
  const completedReconciliationMode =
    phase === 'ROLLBACK_RESILIENCE' &&
    guardMode === SUCCESSOR_GUARD_MODES.ROLLBACK_RESILIENCE_COMPLETED;
  const incompleteReconciliationMode =
    phase === 'ROLLBACK_RESILIENCE' &&
    guardMode === SUCCESSOR_GUARD_MODES.ROLLBACK_RESILIENCE_INCOMPLETE;
  const reconciliationMode = completedReconciliationMode || incompleteReconciliationMode;
  const premutationExtraFlags = SUCCESSOR_GUARD_PREMUTATION_FLAGS.filter(
    (flag) => !ROLLBACK_FILE_FLAGS.includes(flag) && !SUCCESSOR_GUARD_COMMON_FLAGS.includes(flag),
  );
  const completionExtraFlags = SUCCESSOR_GUARD_COMPLETION_FLAGS.filter(
    (flag) => !ROLLBACK_FILE_FLAGS.includes(flag) && !SUCCESSOR_GUARD_COMMON_FLAGS.includes(flag),
  );
  if (
    (!rollbackCheckMode && !reconciliationMode) ||
    (completedReconciliationMode &&
      premutationExtraFlags.some((key) => !Object.hasOwn(flags, key))) ||
    (completedReconciliationMode &&
      completionExtraFlags.some((key) => !Object.hasOwn(flags, key))) ||
    (incompleteReconciliationMode &&
      [...premutationExtraFlags, ...completionExtraFlags].some((key) =>
        Object.hasOwn(flags, key),
      )) ||
    (!reconciliationMode &&
      SUCCESSOR_GUARD_RECONCILIATION_EXTRA_FLAGS.some((key) => Object.hasOwn(flags, key)))
  ) {
    fail('E7_RELEASE_RECONCILIATION_CLI_SUCCESSOR_GUARD_FLAGS_INVALID');
  }
  const runtimeIntentPath = resolveInput(
    flags.intent,
    'E7_RELEASE_RECONCILIATION_CLI_INTENT_INVALID',
  );
  const guardIntentPath = resolveInput(
    flags['reconciliation-intent'],
    'E7_RELEASE_RECONCILIATION_CLI_RECONCILIATION_INTENT_INVALID',
  );
  if (!readFileSync(runtimeIntentPath).equals(readFileSync(guardIntentPath))) {
    fail('E7_RELEASE_RECONCILIATION_CLI_INTENT_SOURCE_MISMATCH');
  }
  const rollbackFlags = Object.fromEntries(
    ROLLBACK_FILE_FLAGS.map((key) => [
      key,
      key === 'app'
        ? resolveDirectory(flags[key], 'E7_RELEASE_RECONCILIATION_CLI_APP_INVALID')
        : resolveInput(
            flags[key],
            `E7_RELEASE_RECONCILIATION_CLI_${key.toUpperCase().replaceAll('-', '_')}_INVALID`,
          ),
    ]),
  );
  rollbackFlags['successor-guard-mode'] = guardMode;
  rollbackFlags['reconciliation-intent'] = guardIntentPath;
  for (const [, key] of INTENT_SOURCE_FLAGS) {
    rollbackFlags[key] = resolveInput(
      flags[key],
      `E7_RELEASE_RECONCILIATION_CLI_${key.toUpperCase().replaceAll('-', '_')}_INVALID`,
    );
  }
  if (reconciliationMode) {
    const selectedExtraFlags = [
      ...(completedReconciliationMode ? premutationExtraFlags : []),
      ...(completedReconciliationMode ? completionExtraFlags : []),
    ];
    for (const key of selectedExtraFlags) {
      rollbackFlags[key] =
        key === 'journal-cleanup-role' || key === 'max-polls'
          ? flags[key]
          : key === 'assembly'
            ? resolveDirectory(flags[key], 'E7_RELEASE_RECONCILIATION_CLI_ASSEMBLY_INVALID')
            : resolveInput(
                flags[key],
                `E7_RELEASE_RECONCILIATION_CLI_${key.toUpperCase().replaceAll('-', '_')}_INVALID`,
              );
    }
  }
  rollbackFlags.output = resolveOutput(
    flags['transition-output'],
    'E7_RELEASE_RECONCILIATION_CLI_TRANSITION_OUTPUT_INVALID',
  );
  return rollbackFlags;
};
const samePath = (left, right) =>
  path.normalize(left).toLocaleLowerCase('en-US') ===
  path.normalize(right).toLocaleLowerCase('en-US');

const commands = Object.freeze({
  'create-intent': {
    required: [...INTENT_SOURCE_FLAGS.map(([, flag]) => flag), 'output'],
    execute: async (flags) => {
      const intent = createReleaseReconciliationIntentFromSources({
        sources: createIntentSources(flags),
        githubIdentity: githubIdentityFromEnvironment(),
      });
      writeJsonImmutable(
        flags.output,
        intent,
        'E7_RELEASE_RECONCILIATION_CLI_INTENT_OUTPUT_INVALID',
      );
      return { decision: 'INTENT_CREATED' };
    },
  },
  'open-journal': {
    required: ['intent', 'output'],
    execute: async (flags) => {
      const intent = intentFrom(flags);
      const { store } = runtimeFrom(intent, 'JOURNAL');
      const result = await openReleaseRollbackJournal({
        intent,
        store,
      });
      writeJsonImmutable(
        flags.output,
        result.owner,
        'E7_RELEASE_RECONCILIATION_CLI_OWNER_OUTPUT_INVALID',
      );
      return { decision: result.idempotent ? 'RESUME_SAME_RUN' : 'OWNER_CREATED' };
    },
  },
  'probe-terminal': {
    required: ['intent', 'phase', 'original-job-conclusion', 'output'],
    execute: async (flags) => {
      const intent = intentFrom(flags);
      const phase = phaseFrom(flags);
      const originalJobConclusion = jobConclusionFrom(flags);
      const { store } = runtimeFrom(intent, 'JOURNAL');
      const probe = await probeVersionedReleaseRuntimeTerminal({
        phase,
        intent,
        originalJobConclusion,
        store,
      });
      writeJsonImmutable(
        flags.output,
        probe,
        'E7_RELEASE_RECONCILIATION_CLI_TERMINAL_PROBE_OUTPUT_INVALID',
      );
      return { decision: probe.status };
    },
  },
  'resume-terminal': {
    required: ['intent', 'phase', 'original-job-conclusion', 'output'],
    allowed: ['drift-evidence', 'smoke-evidence'],
    execute: async (flags) => {
      const intent = intentFrom(flags);
      const phase = phaseFrom(flags);
      const originalJobConclusion = jobConclusionFrom(flags);
      if (Object.hasOwn(flags, 'drift-evidence') !== Object.hasOwn(flags, 'smoke-evidence')) {
        fail('E7_RELEASE_RECONCILIATION_CLI_EVIDENCE_PAIR_INVALID');
      }
      const driftEvidenceSource = Object.hasOwn(flags, 'drift-evidence')
        ? readBytes(flags['drift-evidence'], 'E7_RELEASE_RECONCILIATION_CLI_DRIFT_EVIDENCE_INVALID')
        : undefined;
      const smokeEvidenceSource = Object.hasOwn(flags, 'smoke-evidence')
        ? readBytes(flags['smoke-evidence'], 'E7_RELEASE_RECONCILIATION_CLI_SMOKE_EVIDENCE_INVALID')
        : undefined;
      const { store } = runtimeFrom(intent, 'JOURNAL');
      const result = await resumeVersionedReleaseRuntimeReconciliation({
        phase,
        intent,
        originalJobConclusion,
        driftEvidenceSource,
        smokeEvidenceSource,
        store,
      });
      if (result.receipt === null) {
        fail('E7_RELEASE_RECONCILIATION_CLI_TERMINAL_REQUIRED');
      }
      writeJsonImmutable(
        flags.output,
        result.receipt,
        'E7_RELEASE_RECONCILIATION_CLI_RECEIPT_OUTPUT_INVALID',
      );
      return { decision: result.status };
    },
  },
  'converge-runtime': {
    required: [
      'intent',
      'phase',
      ...ROLLBACK_FILE_FLAGS,
      ...SUCCESSOR_GUARD_COMMON_FLAGS,
      'transition-output',
      'output',
    ],
    allowed: SUCCESSOR_GUARD_RECONCILIATION_EXTRA_FLAGS,
    execute: async (flags) => {
      const intent = intentFrom(flags);
      const phase = phaseFrom(flags);
      const rollbackFlags = rollbackFlagsFrom(flags, phase);
      const checkpointOutput = resolveOutput(
        flags.output,
        'E7_RELEASE_RECONCILIATION_CLI_CONVERGENCE_OUTPUT_INVALID',
      );
      if (
        samePath(checkpointOutput, rollbackFlags.output) ||
        ROLLBACK_FILE_FLAGS.some(
          (key) =>
            samePath(checkpointOutput, rollbackFlags[key]) ||
            samePath(rollbackFlags.output, rollbackFlags[key]),
        )
      ) {
        fail('E7_RELEASE_RECONCILIATION_CLI_OUTPUT_ALIAS_INVALID');
      }
      const checkpointExists = existsSync(checkpointOutput);
      const transitionExists = existsSync(rollbackFlags.output);
      if (checkpointExists && !transitionExists) {
        fail('E7_RELEASE_RECONCILIATION_CLI_CONVERGENCE_PARTIAL_INVALID');
      }
      const { store } = runtimeFrom(intent, 'ROLLBACK');
      let convergence;
      let decision;
      if (transitionExists) {
        convergence = await recoverVersionedReleaseRuntimeConvergenceCheckpoint({
          phase,
          intent,
          candidateRecordSource: readFileSync(rollbackFlags['candidate-record']),
          transitionSource: readFileSync(rollbackFlags.output),
          ...(checkpointExists
            ? {
                expectedConvergence: validateReleaseRuntimeConvergence(
                  readJson(checkpointOutput, 'E7_RELEASE_RECONCILIATION_CLI_CONVERGENCE_INVALID'),
                ),
              }
            : {}),
          store,
        });
        decision = checkpointExists
          ? 'CONVERGENCE_CHECKPOINT_REUSED'
          : 'CONVERGENCE_CHECKPOINT_RECOVERED';
      } else {
        convergence = await convergeVersionedReleaseRuntime({
          phase,
          intent,
          store,
          rollbackFlags,
        });
        decision = 'RUNTIME_CONVERGED';
      }
      writeJsonImmutable(
        checkpointOutput,
        convergence,
        'E7_RELEASE_RECONCILIATION_CLI_CONVERGENCE_OUTPUT_INVALID',
      );
      return { decision };
    },
  },
  'finalize-runtime': {
    required: [
      'convergence',
      'original-job-conclusion',
      'drift-evidence',
      'smoke-evidence',
      'output',
    ],
    execute: async (flags) => {
      const convergence = validateReleaseRuntimeConvergence(
        readJson(flags.convergence, 'E7_RELEASE_RECONCILIATION_CLI_CONVERGENCE_INVALID'),
      );
      const originalJobConclusion = jobConclusionFrom(flags);
      const driftEvidenceSource = readBytes(
        flags['drift-evidence'],
        'E7_RELEASE_RECONCILIATION_CLI_DRIFT_EVIDENCE_INVALID',
      );
      const smokeEvidenceSource = readBytes(
        flags['smoke-evidence'],
        'E7_RELEASE_RECONCILIATION_CLI_SMOKE_EVIDENCE_INVALID',
      );
      const { store } = runtimeFrom(convergence.intent, 'JOURNAL');
      const result = await finalizeVersionedReleaseRuntimeReconciliation({
        convergence,
        originalJobConclusion,
        driftEvidenceSource,
        smokeEvidenceSource,
        store,
      });
      writeJsonImmutable(
        flags.output,
        result.receipt,
        'E7_RELEASE_RECONCILIATION_CLI_RECEIPT_OUTPUT_INVALID',
      );
      return { decision: result.idempotent ? 'TERMINAL_RECEIPT_REUSED' : 'TERMINAL_CREATED' };
    },
  },
  'pre-fence': {
    required: ['rollback-check', 'rollback-resilience', 'evaluated-at', 'output'],
    execute: async (flags) => {
      const gate = createReleasePreFenceGate({
        rollbackCheckSource: readBytes(
          flags['rollback-check'],
          'E7_RELEASE_RECONCILIATION_CLI_ROLLBACK_CHECK_INVALID',
        ),
        rollbackResilienceSource: readBytes(
          flags['rollback-resilience'],
          'E7_RELEASE_RECONCILIATION_CLI_ROLLBACK_RESILIENCE_INVALID',
        ),
        evaluatedAtUtc: flags['evaluated-at'],
      });
      writeJsonImmutable(
        flags.output,
        gate,
        'E7_RELEASE_RECONCILIATION_CLI_PRE_FENCE_OUTPUT_INVALID',
      );
      return { decision: gate.status };
    },
  },
  'classify-publication': {
    required: ['expectation', 'observation', 'output'],
    execute: async (flags) => {
      const expected = validateReleasePublicationExpectation(
        readJson(
          flags.expectation,
          'E7_RELEASE_RECONCILIATION_CLI_PUBLICATION_EXPECTATION_INVALID',
        ),
      );
      const observation = validateReleasePublicationObservation(
        readJson(
          flags.observation,
          'E7_RELEASE_RECONCILIATION_CLI_PUBLICATION_OBSERVATION_INVALID',
        ),
      );
      const classification = classifyReleasePublicationState({ expected, observation });
      writeJsonImmutable(
        flags.output,
        classification,
        'E7_RELEASE_RECONCILIATION_CLI_PUBLICATION_OUTPUT_INVALID',
      );
      return { decision: classification.decision };
    },
  },
});

const main = async () => {
  const command = process.argv[2];
  const definition = commands[command];
  if (definition === undefined) fail('E7_RELEASE_RECONCILIATION_CLI_COMMAND_INVALID');
  const flags = parseFlags(process.argv.slice(3), definition);
  const result = await definition.execute(flags);
  process.stdout.write(
    `${JSON.stringify({ status: 'PASS', command, decision: result.decision })}\n`,
  );
};

main().catch((error) => {
  const code =
    typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{2,127}$/u.test(error.code)
      ? error.code
      : 'E7_RELEASE_RECONCILIATION_CLI_UNEXPECTED_FAILURE';
  process.stderr.write(`stage-7 release reconciliation: ${code}\n`);
  process.exitCode = 1;
});
