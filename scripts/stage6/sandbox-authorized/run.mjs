#!/usr/bin/env node
import { Buffer } from 'node:buffer';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { parseStrictJsonSource, sourceContainsForbiddenData } from '../strict-json.mjs';
import {
  EXPECTED_EXTERNAL_REQUESTS,
  SANDBOX_HOST,
  SandboxAuthorizationError,
  loadAuthorizationContext,
  revalidateAuthorizationContext,
  selfTestAuthorizationPolicy,
  sha256,
  validateRequiredEnvironment,
} from './authorization-policy.mjs';
import {
  consumeSandboxExecutionClaim,
  revalidateConsumedSandboxExecutionClaim,
} from '../../stage7/sandbox-execution-claim.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(HERE, '..', '..', '..');
const AUTHORIZATION_SCHEMA_PATH = path.join(HERE, 'authorization.schema.json');
const CANDIDATE_RUNNER_PATH = path.join(HERE, 'candidate-smoke.ts');
const TSX_CLI_PATH = path.join(REPOSITORY_ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');
const PROTOCOL_PATH = path.join(REPOSITORY_ROOT, 'docs', 'verification', 'external-evidence.md');
const SHA256 = /^[0-9a-f]{64}$/u;
const UTC = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$/u;
const CHILD_OUTPUT_LIMIT = 262_144;
const CHILD_TIMEOUT_MS = 90_000;
const SANDBOX_CHECKS = [
  ['AUTH02-E6-01', 'acceptance-configuration-observed'],
  ['AUTH02-E6-02', 'authorized-test-payment-method-created'],
  ['AUTH02-E6-03', 'local-pending-created-first'],
  ['AUTH02-E6-04', 'provider-sandbox-transaction-created'],
  ['AUTH02-E6-05', 'provider-status-polled'],
  ['AUTH02-E6-06', 'amount-currency-reference-validated'],
  ['AUTH02-E6-07', 'provider-errors-redacted'],
  ['AUTH02-E6-08', 'reconciliation-replay-idempotent'],
];

class SandboxHarnessError extends Error {
  constructor(code) {
    super(code);
    this.name = 'SandboxHarnessError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new SandboxHarnessError(code);
};
const exactKeys = (value, keys) =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const validUtc = (value) => {
  if (typeof value !== 'string' || !UTC.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
};

const exactChildResult = (result, execution) => {
  if (
    !exactKeys(result, [
      'status',
      'commitSha',
      'runId',
      'executedAtUtc',
      'hostSha256',
      'referenceSha256',
      'checks',
      'requests',
      'result',
      'reportSha256',
      'containsSensitiveData',
    ]) ||
    result.status !== 'PASS' ||
    result.commitSha !== execution.commitSha ||
    result.runId !== execution.authorization.runId ||
    !validUtc(result.executedAtUtc) ||
    result.hostSha256 !== sha256(SANDBOX_HOST) ||
    result.referenceSha256 !== execution.referenceSha256 ||
    !SHA256.test(result.reportSha256) ||
    result.containsSensitiveData !== false ||
    !Array.isArray(result.checks) ||
    result.checks.length !== SANDBOX_CHECKS.length ||
    !result.checks.every(
      (check, index) =>
        exactKeys(check, ['id', 'name', 'status']) &&
        check.id === SANDBOX_CHECKS[index][0] &&
        check.name === SANDBOX_CHECKS[index][1] &&
        check.status === 'PASS',
    )
  ) {
    fail('CANDIDATE_RESULT_INVALID');
  }
  const requests = result.requests;
  if (
    !exactKeys(requests, [
      'total',
      'configurationReads',
      'paymentMethodCreations',
      'transactionCreates',
      'statusReads',
      'errorMappingProbes',
      'reconciliationReplays',
      'production',
      'globalMutations',
      'outsideAllowlist',
    ]) ||
    requests.total !== EXPECTED_EXTERNAL_REQUESTS ||
    requests.configurationReads !== 3 ||
    requests.paymentMethodCreations !== 1 ||
    requests.transactionCreates !== 1 ||
    requests.statusReads !== 1 ||
    requests.errorMappingProbes !== 1 ||
    requests.reconciliationReplays !== 1 ||
    requests.production !== 0 ||
    requests.globalMutations !== 0 ||
    requests.outsideAllowlist !== 0 ||
    requests.total > execution.authorization.authorization.maxRequests
  ) {
    fail('CANDIDATE_REQUEST_ACCOUNTING_INVALID');
  }
  const outcome = result.result;
  if (
    !exactKeys(outcome, [
      'providerState',
      'localState',
      'amountMatches',
      'currencyMatches',
      'referenceMatches',
      'reconciliationConsistent',
      'duplicateEffects',
      'adapterDisabledByConfiguration',
    ]) ||
    !['APPROVED', 'DECLINED', 'ERROR', 'PENDING'].includes(outcome.providerState) ||
    outcome.localState !== outcome.providerState ||
    outcome.amountMatches !== true ||
    outcome.currencyMatches !== true ||
    outcome.referenceMatches !== true ||
    outcome.reconciliationConsistent !== true ||
    outcome.duplicateEffects !== 0 ||
    outcome.adapterDisabledByConfiguration !== true
  ) {
    fail('CANDIDATE_OUTCOME_INVALID');
  }
  const executedAt = Date.parse(result.executedAtUtc);
  const approvedAt = Date.parse(execution.authorization.authorization.approvedAtUtc);
  const expiresAt = Date.parse(execution.authorization.authorization.expiresAtUtc);
  if (
    executedAt < approvedAt ||
    executedAt < execution.startedAt.getTime() ||
    executedAt >= expiresAt
  ) {
    fail('AUTHORIZATION_EXPIRED_DURING_RUN');
  }
  return result;
};

const SYSTEM_ENVIRONMENT_KEYS = [
  'PATH',
  'Path',
  'PATHEXT',
  'SystemRoot',
  'SYSTEMROOT',
  'ComSpec',
  'COMSPEC',
  'TEMP',
  'TMP',
];
const AUTHORIZED_ENVIRONMENT_KEYS = [
  'STAGE6_SANDBOX_EXECUTION',
  'STAGE6_SANDBOX_KILL_SWITCH',
  'STAGE6_SANDBOX_MUTATION_LIMIT',
  'STAGE6_SANDBOX_FIXTURE_AUTHORIZED',
  'STAGE6_SANDBOX_ORIGIN',
  'STAGE6_SANDBOX_PUBLIC_KEY',
  'STAGE6_SANDBOX_PRIVATE_KEY',
  'STAGE6_SANDBOX_INTEGRITY_SECRET',
  'STAGE6_SANDBOX_CARD_NUMBER',
  'STAGE6_SANDBOX_CARD_EXPIRY',
  'STAGE6_SANDBOX_CARD_CVC',
  'STAGE6_SANDBOX_CARD_HOLDER',
  'STAGE6_SANDBOX_CUSTOMER_EMAIL',
];

const selectedEnvironment = (names) => {
  const environment = {};
  for (const name of names) {
    const value = process.env[name];
    if (value !== undefined) environment[name] = value;
  }
  return environment;
};

const authorizedChildEnvironment = (authorizationPath) => ({
  ...selectedEnvironment(SYSTEM_ENVIRONMENT_KEYS),
  ...selectedEnvironment(AUTHORIZED_ENVIRONMENT_KEYS),
  STAGE6_SANDBOX_AUTHORIZATION: authorizationPath,
});

const runAuthorizedChild = (authorizationContext, executionClaim) =>
  new Promise((resolve, reject) => {
    const nonce = randomBytes(32).toString('base64url');
    const capability = {
      type: 'AUTH02_EXECUTE_CAPABILITY',
      nonce,
      parentPid: process.pid,
      commitSha: authorizationContext.commitSha,
      authorizationSha256: authorizationContext.sourceSha256,
      executionClaimSha256: executionClaim.claimSha256,
      executionBindingSha256: executionClaim.bindingSha256,
      deterministicReference: executionClaim.reference,
    };
    const child = spawn(
      process.execPath,
      [TSX_CLI_PATH, CANDIDATE_RUNNER_PATH, '--authorized-child'],
      {
        cwd: REPOSITORY_ROOT,
        env: authorizedChildEnvironment(authorizationContext.sourcePath),
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
        windowsHide: true,
      },
    );
    const chunks = [];
    let outputBytes = 0;
    let capabilityAccepted = false;
    let settled = false;
    const timeout = setTimeout(
      () => finishWithError('CANDIDATE_EXECUTION_TIMEOUT'),
      CHILD_TIMEOUT_MS,
    );

    const finishWithError = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      if (!child.killed) child.kill();
      reject(new SandboxHarnessError(code));
    };

    child.stdout.on('data', (chunk) => {
      const value = Buffer.from(chunk);
      outputBytes += value.length;
      if (outputBytes > CHILD_OUTPUT_LIMIT) {
        finishWithError('CANDIDATE_OUTPUT_TOO_LARGE');
        return;
      }
      chunks.push(value);
    });
    child.stderr.resume();
    child.once('error', () => finishWithError('CANDIDATE_LAUNCH_FAILED'));
    child.once('spawn', () => {
      child.send(capability, (error) => {
        if (error) finishWithError('CANDIDATE_CAPABILITY_DELIVERY_FAILED');
      });
    });
    child.on('message', (message) => {
      if (
        capabilityAccepted ||
        !exactKeys(message, ['type', 'nonceSha256', 'childPid']) ||
        message.type !== 'AUTH02_EXECUTION_ACCEPTED' ||
        message.nonceSha256 !== sha256(nonce) ||
        message.childPid !== child.pid
      ) {
        finishWithError('CANDIDATE_CAPABILITY_ACK_INVALID');
        return;
      }
      capabilityAccepted = true;
    });
    child.once('close', (code, signal) => {
      if (settled) return;
      clearTimeout(timeout);
      settled = true;
      if (code !== 0 || signal !== null || !capabilityAccepted) {
        reject(new SandboxHarnessError('CANDIDATE_EXECUTION_FAILED'));
        return;
      }
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
  });

const execute = async () => {
  const startedAt = new Date();
  const scope = process.env.STAGE7_SANDBOX_CLAIM_SCOPE;
  if (scope !== 'full' && scope !== 'prerelease') fail('EXECUTION_CLAIM_SCOPE_INVALID');
  const executionClaim = consumeSandboxExecutionClaim({
    environment: process.env,
    scope,
    now: startedAt,
  });
  const authorizationContext = loadAuthorizationContext({
    repositoryRoot: REPOSITORY_ROOT,
    schemaPath: AUTHORIZATION_SCHEMA_PATH,
    sourcePath: process.env.STAGE6_SANDBOX_AUTHORIZATION,
    now: startedAt,
  });
  validateRequiredEnvironment(process.env, authorizationContext.authorization);
  const childOutput = await runAuthorizedChild(authorizationContext, executionClaim);
  let currentContext = revalidateAuthorizationContext(authorizationContext, new Date());
  validateRequiredEnvironment(process.env, currentContext.authorization);
  const result = exactChildResult(parseStrictJsonSource(Buffer.from(childOutput, 'utf8')), {
    commitSha: authorizationContext.commitSha,
    authorization: currentContext.authorization,
    startedAt,
    referenceSha256: executionClaim.referenceSha256,
  });
  currentContext = revalidateAuthorizationContext(authorizationContext, new Date());
  validateRequiredEnvironment(process.env, currentContext.authorization);
  revalidateConsumedSandboxExecutionClaim({
    environment: process.env,
    scope,
    expectedClaimSha256: executionClaim.claimSha256,
    expectedBindingSha256: executionClaim.bindingSha256,
    expectedReferenceSha256: result.referenceSha256,
    now: new Date(),
  });
  const authorization = currentContext.authorization;
  const capability = {
    status: 'PASS',
    authorization: authorization.authorization,
    target: authorization.target,
    reference: {
      prefix: 'e6-',
      sha256: result.referenceSha256,
      runScoped: true,
      rawValueCaptured: false,
    },
    checks: result.checks,
    requests: result.requests,
    result: result.result,
    evidenceIds: ['AUTH-E6-02', 'EVD-E6-24', 'ART-VER-07'],
    reportSha256: result.reportSha256,
  };
  const evidence = {
    schemaId: 'async-checkout-stage6-external-evidence',
    schemaVersion: 1,
    stage: 6,
    protocolVersion: '1.0.0',
    protocolDocumentSha256: sha256(readFileSync(PROTOCOL_PATH)),
    commitSha: authorizationContext.commitSha,
    runId: authorization.runId,
    executedAtUtc: result.executedAtUtc,
    reviewerAlias: authorization.reviewerAlias,
    capabilities: { sandboxSmoke: capability },
    containsSensitiveData: false,
  };
  const serialized = JSON.stringify(evidence);
  if (sourceContainsForbiddenData(serialized)) fail('SANITIZED_OUTPUT_REJECTED');
  revalidateAuthorizationContext(authorizationContext, new Date());
  process.stdout.write(serialized + '\n');
};
const dryRun = () => {
  process.stdout.write(
    JSON.stringify({
      status: 'NOT_RUN_AUTH_REQUIRED',
      mode: 'DRY_RUN',
      externalRequests: 0,
      productionRequests: 0,
      mutations: 0,
      credentialsRead: 0,
      declaration: 'AUTH_E6_02_AND_EXPLICIT_EXECUTE_REQUIRED',
    }) + '\n',
  );
};

const invokeLocalCandidate = (mode) =>
  spawnSync(process.execPath, [TSX_CLI_PATH, CANDIDATE_RUNNER_PATH, mode], {
    cwd: REPOSITORY_ROOT,
    env: selectedEnvironment(SYSTEM_ENVIRONMENT_KEYS),
    encoding: 'utf8',
    maxBuffer: CHILD_OUTPUT_LIMIT,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 15_000,
    windowsHide: true,
  });

const selfTest = () => {
  selfTestAuthorizationPolicy(AUTHORIZATION_SCHEMA_PATH);
  const directInvocation = invokeLocalCandidate('--authorized-child');
  if (
    directInvocation.error !== undefined ||
    directInvocation.status === 0 ||
    directInvocation.signal !== null ||
    directInvocation.stdout.trim() !== '' ||
    !directInvocation.stderr.includes('PARENT_CAPABILITY_REQUIRED')
  ) {
    fail('DIRECT_CHILD_BYPASS_CANARY_FAILED');
  }
  const childSelfTest = invokeLocalCandidate('--self-test-child');
  if (
    childSelfTest.error !== undefined ||
    childSelfTest.status !== 0 ||
    childSelfTest.signal !== null ||
    !childSelfTest.stdout.includes('candidate self-test: PASS (0 external requests)')
  ) {
    fail('CHILD_EXPIRY_CANARY_FAILED');
  }
  process.stdout.write(
    'stage-6 authorized sandbox harness self-test: PASS (0 external requests)\n',
  );
};

const main = async () => {
  const arguments_ = process.argv.slice(2);
  if (new Set(arguments_).size !== arguments_.length || arguments_.some((value) => value === '')) {
    fail('CLI_ARGUMENT_INVALID');
  }
  if (arguments_.length === 0 || (arguments_.length === 1 && arguments_[0] === '--dry-run')) {
    dryRun();
  } else if (arguments_.length === 1 && arguments_[0] === '--self-test') {
    selfTest();
  } else if (arguments_.length === 1 && arguments_[0] === '--execute') {
    await execute();
  } else {
    fail('CLI_ARGUMENT_INVALID');
  }
};

void main().catch((error) => {
  const code =
    error instanceof SandboxHarnessError || error instanceof SandboxAuthorizationError
      ? error.code
      : 'SANDBOX_HARNESS_FAILED';
  process.stderr.write(`stage-6 authorized sandbox harness: ${code}\n`);
  process.exitCode = 1;
});
