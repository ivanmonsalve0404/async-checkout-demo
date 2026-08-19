#!/usr/bin/env node

import process from 'node:process';

import {
  Stage7AwsError,
  activateRelease,
  assertAwsFlagSet,
  captureCandidateRollbackRecord,
  captureCandidateRollbackRecordAws,
  cleanupRelease,
  deployApi,
  deployData,
  deployObservability,
  deployWeb,
  diffRelease,
  executeVersionedRollback,
  finalizeVersionedRollback,
  recoverVersionedRelease,
  rollbackApi,
  rollbackWeb,
  seedRelease,
  selfTestAwsOperations,
  synthRelease,
  verifyCandidateActiveNoActionOutcome,
  verifyObservability,
  verifyDrift,
  parseAwsFlags,
  planVersionedRollback,
  validatePreviousReleaseArtifact,
  verifyVersionedRollbackEvidence,
} from './aws-operations.mjs';
import { RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS } from './release-reconciliation-authority.mjs';
import {
  RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS,
  RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
  RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
} from './release-successor-rollback-authority.mjs';

const fail = (code) => {
  throw new Stage7AwsError(code);
};

const RELEASE_SUCCESSOR_INTENT_SOURCE_FLAGS = Object.freeze(
  RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS.map(([, flag]) => flag),
);
const RELEASE_SUCCESSOR_RECONCILIATION_ONLY_FLAGS = Object.freeze([
  ...RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS.filter(
    (flag) => flag !== 'reconciliation-recovery-role-effective-permissions',
  ),
  ...RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
  ...RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS,
]);

const commandDefinitions = {
  synth: {
    required: [],
    allowed: ['scope', 'output', 'verify', 'manifest', 'initial-release', 'versioned-update'],
    execute: synthRelease,
  },
  diff: {
    required: ['app', 'manifest'],
    allowed: [
      'scope',
      'initial-release',
      'versioned-update',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
    ],
    execute: diffRelease,
  },
  'deploy-data': {
    required: ['app', 'manifest', 'plan', 'approval', 'aws-auth'],
    allowed: [
      'scope',
      'synthetic-only',
      'non-public',
      'initial-release',
      'versioned-update',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'raw-diff',
      'safety-readiness',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: deployData,
  },
  'deploy-api': {
    required: ['app', 'manifest', 'plan', 'approval', 'aws-auth'],
    allowed: [
      'scope',
      'synthetic-only',
      'non-public',
      'initial-release',
      'versioned-update',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'raw-diff',
      'safety-readiness',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: deployApi,
  },
  'deploy-observability': {
    required: ['app', 'manifest', 'plan', 'approval', 'aws-auth'],
    allowed: [
      'scope',
      'synthetic-only',
      'non-public',
      'ephemeral',
      'initial-release',
      'versioned-update',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'raw-diff',
      'safety-readiness',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: deployObservability,
  },
  'deploy-web': {
    required: ['app', 'manifest', 'plan', 'approval', 'aws-auth'],
    allowed: [
      'scope',
      'synthetic-only',
      'non-public',
      'candidate',
      'initial-release',
      'versioned-update',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'raw-diff',
      'safety-readiness',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: deployWeb,
  },
  'verify-observability': {
    required: ['record'],
    allowed: ['scope'],
    execute: verifyObservability,
  },
  'verify-drift': {
    required: ['app', 'manifest'],
    allowed: [
      'scope',
      'versioned-update',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'reconciliation-intent',
      'reconciliation-recovery-actor',
    ],
    execute: verifyDrift,
  },
  seed: {
    required: ['manifest'],
    allowed: [
      'scope',
      'idempotent',
      'synthetic-only',
      'after-web-origin',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'app',
      'plan',
      'raw-diff',
      'approval',
      'aws-auth',
      'safety-readiness',
      'deployment-evidence',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: seedRelease,
  },
  activate: {
    required: [
      'app',
      'manifest',
      'api-record',
      'web-record',
      'seed-evidence',
      'observability-evidence',
    ],
    allowed: [
      'scope',
      'candidate',
      're-promote',
      'non-public',
      'initial-release',
      'versioned-update',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'plan',
      'raw-diff',
      'approval',
      'aws-auth',
      'safety-readiness',
      'deployment-evidence',
      'live-safety-recheck',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: activateRelease,
  },
  'rollback-api': {
    required: ['record', 'initial-release', 'to-disabled'],
    allowed: ['scope'],
    execute: rollbackApi,
  },
  'rollback-web': {
    required: ['record', 'initial-release', 'to-unpublished'],
    allowed: ['scope'],
    execute: rollbackWeb,
  },
  'validate-previous-release': {
    required: [
      'config',
      'manifest',
      'previous-manifest',
      'previous-source-provenance',
      'previous-target-compatibility',
      'previous-final-disable-provenance',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'previous-release-projection-index',
      'output',
    ],
    allowed: [],
    execute: validatePreviousReleaseArtifact,
  },
  'capture-rollback-candidate': {
    required: [
      'previous-manifest',
      'resource-state',
      'approval',
      'approved-plan',
      'deployment-evidence',
      'captured-at',
      'output',
    ],
    allowed: [],
    execute: captureCandidateRollbackRecord,
  },
  'capture-rollback-candidate-aws': {
    required: [
      'app',
      'manifest',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'approval',
      'approved-plan',
      'deployment-evidence',
      'web-record',
      'aws-auth',
      'output',
    ],
    allowed: [
      'captured-at',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: captureCandidateRollbackRecordAws,
  },
  'execute-versioned-rollback': {
    required: [
      ...new Set([
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
        'direction',
        'output',
        'successor-guard-mode',
        'reconciliation-intent',
        ...RELEASE_SUCCESSOR_INTENT_SOURCE_FLAGS,
      ]),
    ],
    allowed: [...RELEASE_SUCCESSOR_RECONCILIATION_ONLY_FLAGS],
    execute: executeVersionedRollback,
  },
  'finalize-versioned-rollback': {
    required: [
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
      'transition',
      'smoke-evidence',
      'output',
    ],
    allowed: [
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: finalizeVersionedRollback,
  },
  'recover-versioned-release': {
    required: [
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
      'output',
    ],
    allowed: [
      'recover-if-active',
      'verify-candidate-active-no-action',
      'outcome',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: recoverVersionedRelease,
  },
  'verify-emergency-recovery-no-action-outcome': {
    required: [
      'manifest',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'candidate-record',
      'approval',
      'aws-auth',
      'journal-role-effective-permissions',
      'approved-plan',
      'deployment-evidence',
      'emergency-recovery',
      'outcome',
      'reconciliation-recovery-role-effective-permissions',
    ],
    allowed: [],
    execute: verifyCandidateActiveNoActionOutcome,
  },
  'plan-versioned-rollback': {
    required: [
      'previous-manifest',
      'candidate-record',
      'approval',
      'approved-plan',
      'deployment-evidence',
      'current-state',
      'direction',
      'output',
    ],
    allowed: [],
    execute: planVersionedRollback,
  },
  'verify-versioned-rollback': {
    required: [
      'previous-manifest',
      'candidate-record',
      'approval',
      'approved-plan',
      'deployment-evidence',
      'plan',
      'checkpoint',
      'output',
    ],
    allowed: [],
    execute: verifyVersionedRollbackEvidence,
  },
  cleanup: {
    required: ['scope', 'ephemeral-only'],
    allowed: [
      'register-expiry',
      'execute',
      'enforce-expiry',
      'app',
      'manifest',
      'confirm',
      'plan',
      'raw-diff',
      'approval',
      'aws-auth',
      'safety-readiness',
      'deployment-evidence',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
    ],
    execute: cleanupRelease,
  },
};

const assertApprovalBoundCommandContracts = () => {
  for (const command of [
    'deploy-data',
    'deploy-api',
    'deploy-observability',
    'deploy-web',
    'capture-rollback-candidate-aws',
    'execute-versioned-rollback',
    'finalize-versioned-rollback',
    'recover-versioned-release',
    'verify-emergency-recovery-no-action-outcome',
  ]) {
    const definition = commandDefinitions[command];
    if (
      definition === undefined ||
      !definition.required.includes('aws-auth') ||
      definition.allowed.includes('aws-auth') ||
      ![...definition.required, ...definition.allowed].includes(
        'reconciliation-recovery-role-effective-permissions',
      )
    ) {
      fail('E7_AWS_AUTH_CLI_CONTRACT_INVALID');
    }
    assertAwsFlagSet(
      Object.fromEntries(definition.required.map((key) => [key, 'self-test'])),
      definition,
    );
    const withoutAwsAuth = Object.fromEntries(
      definition.required.filter((key) => key !== 'aws-auth').map((key) => [key, 'self-test']),
    );
    try {
      assertAwsFlagSet(withoutAwsAuth, definition);
      fail('E7_AWS_AUTH_CLI_CONTRACT_INVALID');
    } catch (error) {
      if (error?.code !== 'E7_AWS_CLI_ARGUMENT_SET_INVALID') throw error;
    }
  }
  const recovery = commandDefinitions['recover-versioned-release'];
  if (
    recovery.required.includes('recover-if-active') ||
    recovery.required.includes('verify-candidate-active-no-action') ||
    !recovery.allowed.includes('recover-if-active') ||
    !recovery.allowed.includes('verify-candidate-active-no-action') ||
    !recovery.allowed.includes('outcome')
  ) {
    fail('E7_EMERGENCY_RECOVERY_CLI_CONTRACT_INVALID');
  }
  for (const mode of ['recover-if-active', 'verify-candidate-active-no-action']) {
    assertAwsFlagSet(
      {
        ...Object.fromEntries(recovery.required.map((key) => [key, 'self-test'])),
        [mode]: true,
        ...(mode === 'verify-candidate-active-no-action' ? { outcome: 'self-test' } : {}),
      },
      recovery,
    );
  }
};

const assertReleaseReconciliationRecoveryDriftFlagSet = (command, flags) => {
  if (command !== 'verify-drift') return;
  const hasIntent = Object.hasOwn(flags, 'reconciliation-intent');
  const hasActor = Object.hasOwn(flags, 'reconciliation-recovery-actor');
  if (
    hasIntent !== hasActor ||
    (hasIntent &&
      (typeof flags['reconciliation-intent'] !== 'string' ||
        flags['reconciliation-intent'] === '' ||
        typeof flags['reconciliation-recovery-actor'] !== 'string' ||
        flags['reconciliation-recovery-actor'] === ''))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_DRIFT_CLI_ARGUMENT_SET_INVALID');
  }
};

const assertReleaseReconciliationRecoveryDriftCommandContract = () => {
  const definition = commandDefinitions['verify-drift'];
  for (const flag of ['reconciliation-intent', 'reconciliation-recovery-actor']) {
    if (!definition.allowed.includes(flag)) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_DRIFT_CLI_CONTRACT_INVALID');
    }
  }
  const base = Object.fromEntries(definition.required.map((key) => [key, 'self-test']));
  assertReleaseReconciliationRecoveryDriftFlagSet('verify-drift', {
    ...base,
    'reconciliation-intent': 'self-test-intent',
    'reconciliation-recovery-actor': 'self-test-actor',
  });
  for (const flag of ['reconciliation-intent', 'reconciliation-recovery-actor']) {
    try {
      assertReleaseReconciliationRecoveryDriftFlagSet('verify-drift', {
        ...base,
        [flag]: 'self-test',
      });
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_DRIFT_CLI_CONTRACT_INVALID');
    } catch (error) {
      if (error?.code !== 'E7_RELEASE_RECONCILIATION_RECOVERY_DRIFT_CLI_ARGUMENT_SET_INVALID') {
        throw error;
      }
    }
  }
  for (const invalid of [
    {
      ...base,
      'reconciliation-intent': true,
      'reconciliation-recovery-actor': true,
    },
    {
      ...base,
      'reconciliation-intent': '',
      'reconciliation-recovery-actor': '',
    },
  ]) {
    try {
      assertReleaseReconciliationRecoveryDriftFlagSet('verify-drift', invalid);
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_DRIFT_CLI_CONTRACT_INVALID');
    } catch (error) {
      if (error?.code !== 'E7_RELEASE_RECONCILIATION_RECOVERY_DRIFT_CLI_ARGUMENT_SET_INVALID') {
        throw error;
      }
    }
  }
};

const assertReleaseSuccessorGuardFlagSet = (command, flags) => {
  if (command !== 'execute-versioned-rollback') return;
  const mode = flags['successor-guard-mode'];
  const common = ['reconciliation-intent', ...RELEASE_SUCCESSOR_INTENT_SOURCE_FLAGS];
  if (
    !['ROLLBACK_CHECK', 'RECONCILIATION', 'INCOMPLETE_RECONCILIATION'].includes(mode) ||
    common.some((flag) => typeof flags[flag] !== 'string' || flags[flag] === '')
  ) {
    fail('E7_RELEASE_SUCCESSOR_GUARD_CLI_ARGUMENT_SET_INVALID');
  }
  if (mode === 'ROLLBACK_CHECK' || mode === 'INCOMPLETE_RECONCILIATION') {
    if (RELEASE_SUCCESSOR_RECONCILIATION_ONLY_FLAGS.some((flag) => Object.hasOwn(flags, flag))) {
      fail('E7_RELEASE_SUCCESSOR_GUARD_CLI_ARGUMENT_SET_INVALID');
    }
    if (mode === 'INCOMPLETE_RECONCILIATION' && flags.direction !== 'REPROMOTE_CANDIDATE') {
      fail('E7_RELEASE_SUCCESSOR_GUARD_CLI_ARGUMENT_SET_INVALID');
    }
  } else {
    const preparation = [
      ...RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
      ...RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
    ];
    const completion = RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS;
    if (
      preparation.some((flag) => typeof flags[flag] !== 'string' || flags[flag] === '') ||
      flags['max-polls'] !== '30' ||
      flags.direction !== 'REPROMOTE_CANDIDATE' ||
      completion.some((flag) => typeof flags[flag] !== 'string' || flags[flag] === '')
    ) {
      fail('E7_RELEASE_SUCCESSOR_GUARD_CLI_ARGUMENT_SET_INVALID');
    }
  }
};

const assertReleaseSuccessorGuardCommandContract = () => {
  const definition = commandDefinitions['execute-versioned-rollback'];
  const base = Object.fromEntries(definition.required.map((key) => [key, 'self-test']));
  base.direction = 'ROLLBACK_TO_PREVIOUS';
  base['successor-guard-mode'] = 'ROLLBACK_CHECK';
  assertReleaseSuccessorGuardFlagSet('execute-versioned-rollback', base);
  const reconciliation = {
    ...base,
    direction: 'REPROMOTE_CANDIDATE',
    'successor-guard-mode': 'RECONCILIATION',
    ...Object.fromEntries(
      RELEASE_SUCCESSOR_RECONCILIATION_ONLY_FLAGS.map((key) => [key, 'self-test']),
    ),
    'max-polls': '30',
  };
  assertReleaseSuccessorGuardFlagSet('execute-versioned-rollback', reconciliation);
  const incomplete = {
    ...base,
    direction: 'REPROMOTE_CANDIDATE',
    'successor-guard-mode': 'INCOMPLETE_RECONCILIATION',
  };
  assertReleaseSuccessorGuardFlagSet('execute-versioned-rollback', incomplete);
  for (const invalid of [
    { ...base, 'successor-guard-mode': 'BYPASS' },
    { ...base, rollback: 'self-test' },
    { ...reconciliation, direction: 'ROLLBACK_TO_PREVIOUS' },
    { ...reconciliation, 'max-polls': '31' },
    { ...reconciliation, completion: '' },
    { ...incomplete, completion: 'self-test' },
    { ...incomplete, rollback: 'self-test' },
    { ...incomplete, direction: 'ROLLBACK_TO_PREVIOUS' },
  ]) {
    try {
      assertReleaseSuccessorGuardFlagSet('execute-versioned-rollback', invalid);
      fail('E7_RELEASE_SUCCESSOR_GUARD_CLI_CONTRACT_INVALID');
    } catch (error) {
      if (error?.code !== 'E7_RELEASE_SUCCESSOR_GUARD_CLI_ARGUMENT_SET_INVALID') throw error;
    }
  }
};

const assertExternalOperationScope = (command, flags) => {
  if (flags.scope !== undefined && !['full', 'prerelease'].includes(flags.scope)) {
    fail('E7_OPERATION_SCOPE_INVALID');
  }
  const definition = commandDefinitions[command];
  if (
    flags.scope !== undefined &&
    definition !== undefined &&
    ![...definition.required, ...definition.allowed].includes('scope')
  ) {
    fail('E7_OPERATION_SCOPE_INVALID');
  }
};

const assertExternalOperationScopeCommandContracts = () => {
  for (const [command, definition] of Object.entries(commandDefinitions)) {
    if (![...definition.required, ...definition.allowed].includes('scope')) continue;
    assertExternalOperationScope(command, { scope: 'full' });
    assertExternalOperationScope(command, { scope: 'prerelease' });
    try {
      assertExternalOperationScope(command, { scope: 'production' });
      fail('E7_OPERATION_SCOPE_CLI_CONTRACT_INVALID');
    } catch (error) {
      if (error?.code !== 'E7_OPERATION_SCOPE_INVALID') throw error;
    }
  }
};

const prereleaseSafetyFlagsFor = (command, flags) => {
  if (flags.scope !== 'prerelease') return [];
  if (['deploy-data', 'deploy-api', 'deploy-observability', 'deploy-web'].includes(command)) {
    return ['raw-diff', 'safety-readiness'];
  }
  if (command === 'seed') {
    return [
      'app',
      'plan',
      'raw-diff',
      'approval',
      'aws-auth',
      'safety-readiness',
      'deployment-evidence',
    ];
  }
  if (command === 'activate') {
    return [
      'plan',
      'raw-diff',
      'approval',
      'aws-auth',
      'safety-readiness',
      'deployment-evidence',
      'live-safety-recheck',
    ];
  }
  if (command === 'cleanup' && flags['register-expiry'] === true) {
    return [
      'app',
      'manifest',
      'plan',
      'raw-diff',
      'approval',
      'aws-auth',
      'safety-readiness',
      'deployment-evidence',
    ];
  }
  return [];
};

const assertPrereleaseSafetyFlagSet = (command, flags) => {
  if (
    prereleaseSafetyFlagsFor(command, flags).some(
      (key) => typeof flags[key] !== 'string' || flags[key].length === 0,
    )
  ) {
    fail('E7_PRERELEASE_SAFETY_CLI_ARGUMENT_SET_INVALID');
  }
};

const assertPrereleaseSafetyCommandContracts = () => {
  for (const command of [
    'deploy-data',
    'deploy-api',
    'deploy-observability',
    'deploy-web',
    'seed',
    'activate',
  ]) {
    const definition = commandDefinitions[command];
    const flags = {
      ...Object.fromEntries(definition.required.map((key) => [key, 'self-test'])),
      scope: 'prerelease',
      ...Object.fromEntries(
        prereleaseSafetyFlagsFor(command, { scope: 'prerelease' }).map((key) => [key, 'self-test']),
      ),
    };
    assertPrereleaseSafetyFlagSet(command, flags);
    const missing = { ...flags };
    delete missing[prereleaseSafetyFlagsFor(command, flags)[0]];
    try {
      assertPrereleaseSafetyFlagSet(command, missing);
      fail('E7_PRERELEASE_SAFETY_CLI_CONTRACT_INVALID');
    } catch (error) {
      if (error?.code !== 'E7_PRERELEASE_SAFETY_CLI_ARGUMENT_SET_INVALID') throw error;
    }
  }
  const cleanupFlags = {
    scope: 'prerelease',
    'ephemeral-only': true,
    'register-expiry': true,
    ...Object.fromEntries(
      prereleaseSafetyFlagsFor('cleanup', {
        scope: 'prerelease',
        'register-expiry': true,
      }).map((key) => [key, 'self-test']),
    ),
  };
  assertPrereleaseSafetyFlagSet('cleanup', cleanupFlags);
};

const main = async () => {
  const command = process.argv[2];
  if (command === 'self-test') {
    if (process.argv.length !== 3) fail('E7_AWS_CLI_ARGUMENT_SET_INVALID');
    assertApprovalBoundCommandContracts();
    assertReleaseReconciliationRecoveryDriftCommandContract();
    assertReleaseSuccessorGuardCommandContract();
    assertExternalOperationScopeCommandContracts();
    assertPrereleaseSafetyCommandContracts();
    await selfTestAwsOperations();
    process.stdout.write('stage-7 AWS operations self-test: PASS (0 external calls)\n');
    return;
  }
  const definition = commandDefinitions[command];
  if (definition === undefined) fail('E7_AWS_CLI_COMMAND_INVALID');
  const flags = parseAwsFlags(process.argv.slice(3));
  assertAwsFlagSet(flags, definition);
  assertExternalOperationScope(command, flags);
  assertReleaseReconciliationRecoveryDriftFlagSet(command, flags);
  assertReleaseSuccessorGuardFlagSet(command, flags);
  assertPrereleaseSafetyFlagSet(command, flags);
  const result = await definition.execute({ flags });
  process.stdout.write(
    `${JSON.stringify({ status: 'PASS', command, decision: result.decision ?? 'PASS' })}\n`,
  );
};

main().catch((error) => {
  const code =
    error instanceof Stage7AwsError ||
    (typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{2,127}$/u.test(error.code))
      ? (error.code ?? error.message)
      : 'E7_AWS_OPERATION_UNEXPECTED_FAILURE';
  process.stderr.write(`stage-7 AWS operation: ${code}\n`);
  process.exitCode = 1;
});
