#!/usr/bin/env node

import process from 'node:process';

import {
  Stage7AwsError,
  activateRelease,
  assertAwsFlagSet,
  cleanupRelease,
  deployApi,
  deployData,
  deployObservability,
  deployWeb,
  diffRelease,
  rollbackApi,
  rollbackWeb,
  seedRelease,
  selfTestAwsOperations,
  synthRelease,
  verifyObservability,
  verifyDrift,
  parseAwsFlags,
} from './aws-operations.mjs';

const fail = (code) => {
  throw new Stage7AwsError(code);
};

const commandDefinitions = {
  synth: {
    required: ['initial-release'],
    allowed: ['scope', 'output', 'verify', 'manifest'],
    execute: synthRelease,
  },
  diff: {
    required: ['app', 'manifest', 'initial-release'],
    allowed: ['scope'],
    execute: diffRelease,
  },
  'deploy-data': {
    required: ['app', 'manifest', 'plan', 'approval', 'initial-release'],
    allowed: ['scope', 'synthetic-only', 'non-public'],
    execute: deployData,
  },
  'deploy-api': {
    required: ['app', 'manifest', 'plan', 'approval', 'initial-release'],
    allowed: ['scope', 'synthetic-only', 'non-public'],
    execute: deployApi,
  },
  'deploy-observability': {
    required: ['app', 'manifest', 'plan', 'approval', 'initial-release'],
    allowed: ['scope', 'synthetic-only', 'non-public', 'ephemeral'],
    execute: deployObservability,
  },
  'deploy-web': {
    required: ['app', 'manifest', 'plan', 'approval', 'initial-release'],
    allowed: ['scope', 'synthetic-only', 'non-public', 'candidate'],
    execute: deployWeb,
  },
  'verify-observability': {
    required: ['record'],
    allowed: ['scope'],
    execute: verifyObservability,
  },
  'verify-drift': {
    required: ['app', 'manifest'],
    allowed: ['scope'],
    execute: verifyDrift,
  },
  seed: {
    allowed: ['scope', 'idempotent', 'synthetic-only', 'after-web-origin'],
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
      'initial-release',
    ],
    allowed: ['scope', 'candidate', 're-promote', 'non-public'],
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
  cleanup: {
    required: ['scope', 'ephemeral-only'],
    allowed: ['register-expiry', 'execute', 'enforce-expiry', 'app', 'manifest', 'confirm'],
    execute: cleanupRelease,
  },
};

const main = async () => {
  const command = process.argv[2];
  if (command === 'self-test') {
    if (process.argv.length !== 3) fail('E7_AWS_CLI_ARGUMENT_SET_INVALID');
    await selfTestAwsOperations();
    process.stdout.write('stage-7 AWS operations self-test: PASS (0 external calls)\n');
    return;
  }
  const definition = commandDefinitions[command];
  if (definition === undefined) fail('E7_AWS_CLI_COMMAND_INVALID');
  const flags = parseAwsFlags(process.argv.slice(3));
  assertAwsFlagSet(flags, definition);
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
