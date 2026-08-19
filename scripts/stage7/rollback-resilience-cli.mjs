#!/usr/bin/env node

import { Buffer } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { readStrictJsonFile, workspaceRoot, writeStage7Json } from './core.mjs';
import {
  runProtectedAwsRollbackResilience,
  selfTestRollbackResilienceProducer,
} from './rollback-resilience-producer.mjs';
import {
  createRollbackResilienceCompletionEnvelope,
  prepareRollbackResilienceArtifacts,
  selfTestRollbackResilienceIntegration,
  validateRollbackResilienceCompletionEnvelope,
} from './rollback-resilience-integration.mjs';
import { RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS } from './release-reconciliation-authority.mjs';
import { runGuardedRollbackResilienceMutation } from './release-successor-finalization.mjs';
import { RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS } from './release-successor-rollback-authority.mjs';

const MAX_AWS_OUTPUT_BYTES = 32 * 1024 * 1024;
const AWS_TIMEOUT_MS = 20 * 60 * 1000;
const ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/([A-Za-z0-9+=,.@_/-]{1,512})$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const INTENT_SOURCE_FLAGS = Object.freeze(
  RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS.map(([, flag]) => flag),
);
const PREPARATION_ONLY_FLAGS = RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS;

class RollbackResilienceCliError extends Error {
  constructor(code) {
    super(code);
    this.name = 'RollbackResilienceCliError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new RollbackResilienceCliError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');

const parseFlags = (arguments_, names) => {
  const flags = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (
      typeof flag !== 'string' ||
      !names.includes(flag.slice(2)) ||
      typeof value !== 'string' ||
      value === '' ||
      Object.hasOwn(flags, flag.slice(2))
    ) {
      fail('E7_RESILIENCE_CLI_FLAGS_INVALID');
    }
    flags[flag.slice(2)] = value;
  }
  if (
    arguments_.length !== names.length * 2 ||
    Object.keys(flags).toSorted().join('\0') !== [...names].toSorted().join('\0')
  ) {
    fail('E7_RESILIENCE_CLI_FLAGS_INVALID');
  }
  return flags;
};

const insideWorkspace = (filename, code) => {
  const resolved = path.resolve(workspaceRoot, filename);
  const relative = path.relative(workspaceRoot, resolved);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail(code);
  }
  return resolved;
};

const sourceFile = (flags, name, code) => readFileSync(insideWorkspace(flags[name], code));

const awsJson = (arguments_, code, { allowedErrorCodes = [] } = {}) => {
  const command = process.platform === 'win32' ? 'aws.cmd' : 'aws';
  const result = spawnSync(command, [...arguments_, '--output', 'json', '--no-cli-pager'], {
    encoding: 'utf8',
    env: { ...process.env, AWS_PAGER: '' },
    maxBuffer: MAX_AWS_OUTPUT_BYTES,
    shell: false,
    timeout: AWS_TIMEOUT_MS,
    windowsHide: true,
  });
  const stderr = typeof result.stderr === 'string' ? result.stderr : '';
  const awsErrorCode = /An error occurred \(([A-Za-z0-9.]+)\)/u.exec(stderr)?.[1];
  if (
    result.error !== undefined ||
    result.signal !== null ||
    result.status !== 0 ||
    typeof result.stdout !== 'string' ||
    Buffer.byteLength(result.stdout, 'utf8') > MAX_AWS_OUTPUT_BYTES
  ) {
    if (
      result.error === undefined &&
      result.signal === null &&
      result.status !== 0 &&
      allowedErrorCodes.includes(awsErrorCode)
    ) {
      const error = new Error(awsErrorCode);
      error.code = awsErrorCode;
      throw error;
    }
    fail(code);
  }
  try {
    return parseStrictJsonSource(Buffer.from(result.stdout, 'utf8'), {
      scanForbiddenData: false,
    });
  } catch {
    fail(code);
  }
};

const createRollbackGuardAwsAdapters = ({ rollbackRoleArn, runId, region }) => {
  const role = ROLE_ARN.exec(rollbackRoleArn ?? '');
  const expectedSessionName = `e7-rb-resilience-${runId}`;
  if (
    role === null ||
    !RUN_ID.test(runId ?? '') ||
    process.env.AWS_REGION !== region ||
    process.env.AWS_DEFAULT_REGION !== region ||
    process.env.STAGE7_AWS_ROLLBACK_ROLE_ARN !== rollbackRoleArn ||
    expectedSessionName.length > 64
  ) {
    fail('E7_RESILIENCE_GUARD_AWS_CONTEXT_INVALID');
  }
  const roleName = role[2].split('/').at(-1);
  const expectedArn = `arn:aws:sts::${role[1]}:assumed-role/${roleName}/${expectedSessionName}`;
  let identityValidated = false;
  const validateIdentity = () => {
    if (identityValidated) return;
    const caller = awsJson(
      ['sts', 'get-caller-identity'],
      'E7_RESILIENCE_GUARD_STS_IDENTITY_FAILED',
    );
    if (
      !exactKeys(caller, ['UserId', 'Account', 'Arn']) ||
      caller?.Account !== role[1] ||
      caller?.Arn !== expectedArn ||
      typeof caller?.UserId !== 'string' ||
      !caller.UserId.endsWith(`:${expectedSessionName}`)
    ) {
      fail('E7_RESILIENCE_GUARD_STS_IDENTITY_INVALID');
    }
    identityValidated = true;
  };
  return Object.freeze({
    getParametersByPath: async ({
      path: parameterPath,
      recursive,
      withDecryption,
      maxResults,
      nextToken,
    }) => {
      validateIdentity();
      return awsJson(
        [
          'ssm',
          'get-parameters-by-path',
          '--path',
          parameterPath,
          recursive ? '--recursive' : '--no-recursive',
          withDecryption ? '--with-decryption' : '--no-with-decryption',
          '--max-results',
          String(maxResults),
          ...(nextToken === undefined ? [] : ['--next-token', nextToken]),
        ],
        'E7_RESILIENCE_GUARD_SSM_LIST_FAILED',
      );
    },
    putParameter: async ({ name, type, tier, value, overwrite }) => {
      if (overwrite !== false || type !== 'String' || tier !== 'Standard') {
        fail('E7_RESILIENCE_GUARD_SSM_PUT_POLICY_INVALID');
      }
      validateIdentity();
      return awsJson(
        [
          'ssm',
          'put-parameter',
          '--name',
          name,
          '--type',
          type,
          '--tier',
          tier,
          '--value',
          value,
          '--no-overwrite',
        ],
        'E7_RESILIENCE_GUARD_SSM_PUT_FAILED',
        { allowedErrorCodes: ['ParameterAlreadyExists'] },
      );
    },
    getParameter: async ({ name, withDecryption }) => {
      validateIdentity();
      return awsJson(
        [
          'ssm',
          'get-parameter',
          '--name',
          name,
          withDecryption ? '--with-decryption' : '--no-with-decryption',
        ],
        'E7_RESILIENCE_GUARD_SSM_GET_FAILED',
      );
    },
  });
};

const intentAuthoritySources = (flags) => ({
  intentSource: sourceFile(flags, 'intent', 'E7_RESILIENCE_INTENT_PATH_INVALID'),
  sources: {
    config: sourceFile(flags, 'config', 'E7_RESILIENCE_CONFIG_PATH_INVALID'),
    releaseMetadata: sourceFile(
      flags,
      'release-metadata',
      'E7_RESILIENCE_RELEASE_METADATA_PATH_INVALID',
    ),
    candidateManifest: sourceFile(flags, 'candidate-manifest', 'E7_RESILIENCE_FREEZE_PATH_INVALID'),
    releasePlan: sourceFile(flags, 'release-plan', 'E7_RESILIENCE_RELEASE_PLAN_PATH_INVALID'),
    approvedDiff: sourceFile(flags, 'approved-diff', 'E7_RESILIENCE_PLAN_PATH_INVALID'),
    rawDiff: sourceFile(flags, 'raw-diff', 'E7_RESILIENCE_DIFF_PATH_INVALID'),
    githubEnvironmentApproval: sourceFile(
      flags,
      'github-environment-approval',
      'E7_RESILIENCE_GITHUB_APPROVAL_PATH_INVALID',
    ),
    approval: sourceFile(flags, 'approval', 'E7_RESILIENCE_APPROVAL_PATH_INVALID'),
    awsAuth: sourceFile(flags, 'aws-auth', 'E7_RESILIENCE_AWS_AUTH_PATH_INVALID'),
    journalRoleEffectivePermissions: sourceFile(
      flags,
      'journal-role-effective-permissions',
      'E7_RESILIENCE_JOURNAL_ROLE_AUTHORITY_PATH_INVALID',
    ),
    activation: sourceFile(flags, 'activation', 'E7_RESILIENCE_ACTIVATION_PATH_INVALID'),
    webDeployment: sourceFile(flags, 'web-deployment', 'E7_RESILIENCE_DEPLOYMENT_PATH_INVALID'),
    candidateRecord: sourceFile(flags, 'candidate-record', 'E7_RESILIENCE_CANDIDATE_PATH_INVALID'),
    externalAuthorization: sourceFile(
      flags,
      'external-authorization',
      'E7_RESILIENCE_EXTERNAL_AUTHORIZATION_PATH_INVALID',
    ),
    previousReleaseManifest: sourceFile(
      flags,
      'previous-release-manifest',
      'E7_RESILIENCE_PREVIOUS_PATH_INVALID',
    ),
    previousSourceProvenance: sourceFile(
      flags,
      'previous-source-provenance',
      'E7_RESILIENCE_PREVIOUS_SOURCE_PROVENANCE_PATH_INVALID',
    ),
    previousTargetCompatibility: sourceFile(
      flags,
      'previous-target-compatibility',
      'E7_RESILIENCE_PREVIOUS_TARGET_COMPATIBILITY_PATH_INVALID',
    ),
    previousFinalDisableProvenance: sourceFile(
      flags,
      'previous-final-disable-provenance',
      'E7_RESILIENCE_PREVIOUS_FINAL_DISABLE_PATH_INVALID',
    ),
    previousApiContractEvidence: sourceFile(
      flags,
      'previous-api-contract-evidence',
      'E7_RESILIENCE_PREVIOUS_API_PATH_INVALID',
    ),
    previousPendingEvidence: sourceFile(
      flags,
      'previous-pending-evidence',
      'E7_RESILIENCE_PREVIOUS_PENDING_PATH_INVALID',
    ),
    previousSmokeEvidence: sourceFile(
      flags,
      'previous-smoke-evidence',
      'E7_RESILIENCE_PREVIOUS_SMOKE_PATH_INVALID',
    ),
    previousReleaseProjectionIndex: sourceFile(
      flags,
      'previous-release-projection-index',
      'E7_RESILIENCE_PREVIOUS_PROJECTION_INDEX_PATH_INVALID',
    ),
  },
  githubIdentity: {
    repository: process.env.GITHUB_REPOSITORY,
    workflowRef: process.env.GITHUB_WORKFLOW_REF,
    ref: process.env.GITHUB_REF,
    runId: process.env.GITHUB_RUN_ID,
    runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
    candidateSha: process.env.GITHUB_SHA,
  },
});

const main = async () => {
  const [command, ...arguments_] = process.argv.slice(2);
  if (command === 'self-test' && arguments_.length === 0) {
    const producer = await selfTestRollbackResilienceProducer();
    const integration = selfTestRollbackResilienceIntegration();
    process.stdout.write(
      `${JSON.stringify({
        status: 'PASS',
        canaries: producer.canaries + integration.canaries,
        simulatedAwsMutations: producer.simulatedAwsMutations,
        externalRequests: 0,
        producer,
        integration,
        gateE703: producer.gateE703,
      })}\n`,
    );
    return;
  }
  if (command === 'prepare') {
    const flags = parseFlags(arguments_, [
      'config',
      'freeze',
      'previous',
      'candidate',
      'rollback',
      'aws-auth',
      'approval',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
      'plan',
      'deployment',
      'observability',
      'activation',
      'external-authorization',
      'smoke-input',
      'smoke',
      'edge',
      'quality',
      'sandbox',
      'rollback-smoke-input',
      'pending-producer',
      'rollback-smoke',
      'repromotion-smoke',
      'journal-cleanup-role',
      'assembly',
      'inputs-output',
      'rb06-output',
      'rb08-output',
      'binding-output',
      'max-polls',
    ]);
    const maxPolls = Number(flags['max-polls']);
    const prepared = prepareRollbackResilienceArtifacts({
      config: readStrictJsonFile(
        insideWorkspace(flags.config, 'E7_RESILIENCE_CONFIG_PATH_INVALID'),
      ),
      freezeManifest: readStrictJsonFile(
        insideWorkspace(flags.freeze, 'E7_RESILIENCE_FREEZE_PATH_INVALID'),
      ),
      previousReleaseManifest: readStrictJsonFile(
        insideWorkspace(flags.previous, 'E7_RESILIENCE_PREVIOUS_PATH_INVALID'),
      ),
      candidateRecord: readStrictJsonFile(
        insideWorkspace(flags.candidate, 'E7_RESILIENCE_CANDIDATE_PATH_INVALID'),
      ),
      rollbackSource: readFileSync(
        insideWorkspace(flags.rollback, 'E7_RESILIENCE_ROLLBACK_PATH_INVALID'),
      ),
      awsAuthSource: readFileSync(
        insideWorkspace(flags['aws-auth'], 'E7_RESILIENCE_AWS_AUTH_PATH_INVALID'),
      ),
      approvalSource: readFileSync(
        insideWorkspace(flags.approval, 'E7_RESILIENCE_APPROVAL_PATH_INVALID'),
      ),
      approvedPlanSource: readFileSync(
        insideWorkspace(flags.plan, 'E7_RESILIENCE_PLAN_PATH_INVALID'),
      ),
      deploymentEvidenceSource: readFileSync(
        insideWorkspace(flags.deployment, 'E7_RESILIENCE_DEPLOYMENT_PATH_INVALID'),
      ),
      observabilityEvidenceSource: readFileSync(
        insideWorkspace(flags.observability, 'E7_RESILIENCE_OBSERVABILITY_PATH_INVALID'),
      ),
      activationEvidenceSource: readFileSync(
        insideWorkspace(flags.activation, 'E7_RESILIENCE_ACTIVATION_PATH_INVALID'),
      ),
      externalAuthorizationSource: readFileSync(
        insideWorkspace(
          flags['external-authorization'],
          'E7_RESILIENCE_EXTERNAL_AUTHORIZATION_PATH_INVALID',
        ),
      ),
      smokeInputSource: readFileSync(
        insideWorkspace(flags['smoke-input'], 'E7_RESILIENCE_SMOKE_INPUT_PATH_INVALID'),
      ),
      smokeEvidenceSource: readFileSync(
        insideWorkspace(flags.smoke, 'E7_RESILIENCE_SMOKE_PATH_INVALID'),
      ),
      edgeEvidenceSource: readFileSync(
        insideWorkspace(flags.edge, 'E7_RESILIENCE_EDGE_PATH_INVALID'),
      ),
      qualityEvidenceSource: readFileSync(
        insideWorkspace(flags.quality, 'E7_RESILIENCE_QUALITY_PATH_INVALID'),
      ),
      sandboxEvidenceSource: readFileSync(
        insideWorkspace(flags.sandbox, 'E7_RESILIENCE_SANDBOX_PATH_INVALID'),
      ),
      rollbackSmokeInputSource: readFileSync(
        insideWorkspace(
          flags['rollback-smoke-input'],
          'E7_RESILIENCE_ROLLBACK_SMOKE_INPUT_PATH_INVALID',
        ),
      ),
      pendingProducerSource: readFileSync(
        insideWorkspace(flags['pending-producer'], 'E7_RESILIENCE_PENDING_PRODUCER_PATH_INVALID'),
      ),
      rollbackSmokeSource: readFileSync(
        insideWorkspace(flags['rollback-smoke'], 'E7_RESILIENCE_ROLLBACK_SMOKE_PATH_INVALID'),
      ),
      repromotionSmokeSource: readFileSync(
        insideWorkspace(flags['repromotion-smoke'], 'E7_RESILIENCE_REPROMOTION_SMOKE_PATH_INVALID'),
      ),
      journalCleanupRoleArn: flags['journal-cleanup-role'],
      assemblyDirectory: insideWorkspace(flags.assembly, 'E7_RESILIENCE_ASSEMBLY_PATH_INVALID'),
      maxPolls,
    });
    await writeStage7Json(
      insideWorkspace(flags['inputs-output'], 'E7_RESILIENCE_INPUTS_OUTPUT_PATH_INVALID'),
      'stage7-rollback-resilience-inputs.json',
      prepared.inputsWithoutExecution,
    );
    await writeStage7Json(
      insideWorkspace(flags['rb06-output'], 'E7_RESILIENCE_RB06_OUTPUT_PATH_INVALID'),
      'stage7-rb-e7-06-descriptor.json',
      prepared.rb06Descriptor,
    );
    await writeStage7Json(
      insideWorkspace(flags['rb08-output'], 'E7_RESILIENCE_RB08_OUTPUT_PATH_INVALID'),
      'stage7-rb-e7-08-descriptor.json',
      prepared.rb08Descriptor,
    );
    await writeStage7Json(
      insideWorkspace(flags['binding-output'], 'E7_RESILIENCE_BINDING_OUTPUT_PATH_INVALID'),
      'stage7-rollback-resilience-source-binding.json',
      prepared.sourceBinding,
    );
    process.stdout.write(
      `${JSON.stringify({ status: 'PREPARED', sourceBindingSha256: prepared.sourceBinding.sourceBindingSha256 })}\n`,
    );
    return;
  }
  if (command === 'validate-completion') {
    const flags = parseFlags(arguments_, [
      'rollback',
      'source-binding',
      'protected-run',
      'completion',
      'inputs',
      'rb06',
      'rb08',
    ]);
    const completion = validateRollbackResilienceCompletionEnvelope({
      envelope: readStrictJsonFile(
        insideWorkspace(flags.completion, 'E7_RESILIENCE_CLI_COMPLETION_PATH_INVALID'),
      ),
      rollbackSource: readFileSync(
        insideWorkspace(flags.rollback, 'E7_RESILIENCE_CLI_ROLLBACK_PATH_INVALID'),
      ),
      sourceBindingSource: readFileSync(
        insideWorkspace(flags['source-binding'], 'E7_RESILIENCE_CLI_SOURCE_BINDING_PATH_INVALID'),
      ),
      protectedRunSource: readFileSync(
        insideWorkspace(flags['protected-run'], 'E7_RESILIENCE_CLI_PROTECTED_RUN_PATH_INVALID'),
      ),
      validationContext: {
        inputsWithoutExecution: readStrictJsonFile(
          insideWorkspace(flags.inputs, 'E7_RESILIENCE_CLI_INPUT_PATH_INVALID'),
        ),
        rb06Descriptor: readStrictJsonFile(
          insideWorkspace(flags.rb06, 'E7_RESILIENCE_CLI_RB06_PATH_INVALID'),
        ),
        rb08Descriptor: readStrictJsonFile(
          insideWorkspace(flags.rb08, 'E7_RESILIENCE_CLI_RB08_PATH_INVALID'),
        ),
      },
    });
    process.stdout.write(
      `${JSON.stringify({ status: 'PASS', envelopeSha256: completion.envelopeSha256, gateE703: completion.gateE703 })}\n`,
    );
    return;
  }
  if (command !== 'run-protected') fail('E7_RESILIENCE_CLI_COMMAND_INVALID');
  const flags = parseFlags(arguments_, [
    'inputs',
    'rb06',
    'rb08',
    'source-binding',
    'output',
    'completion-output',
    'intent',
    ...INTENT_SOURCE_FLAGS,
    ...PREPARATION_ONLY_FLAGS,
  ]);
  const inputsWithoutExecution = readStrictJsonFile(
    insideWorkspace(flags.inputs, 'E7_RESILIENCE_CLI_INPUT_PATH_INVALID'),
  );
  if (
    inputsWithoutExecution?.execution !== undefined ||
    inputsWithoutExecution?.executor !== undefined ||
    inputsWithoutExecution?.mode !== undefined
  ) {
    fail('E7_RESILIENCE_CLI_EXECUTION_ASSERTION_FORBIDDEN');
  }
  const rb06Descriptor = readStrictJsonFile(
    insideWorkspace(flags.rb06, 'E7_RESILIENCE_CLI_RB06_PATH_INVALID'),
  );
  const rb08Descriptor = readStrictJsonFile(
    insideWorkspace(flags.rb08, 'E7_RESILIENCE_CLI_RB08_PATH_INVALID'),
  );
  const config = readStrictJsonFile(
    insideWorkspace(flags.config, 'E7_RESILIENCE_CONFIG_PATH_INVALID'),
  );
  const freezeManifest = readStrictJsonFile(
    insideWorkspace(flags['candidate-manifest'], 'E7_RESILIENCE_FREEZE_PATH_INVALID'),
  );
  const previousReleaseManifest = readStrictJsonFile(
    insideWorkspace(flags['previous-release-manifest'], 'E7_RESILIENCE_PREVIOUS_PATH_INVALID'),
  );
  const candidateRecord = readStrictJsonFile(
    insideWorkspace(flags['candidate-record'], 'E7_RESILIENCE_CANDIDATE_PATH_INVALID'),
  );
  const runId = process.env.GITHUB_RUN_ID;
  const adapters = createRollbackGuardAwsAdapters({
    rollbackRoleArn: config?.aws?.roles?.rollbackRoleArn,
    runId,
    region: config?.aws?.region,
  });
  const guarded = await runGuardedRollbackResilienceMutation({
    intentAuthoritySources: intentAuthoritySources(flags),
    rollbackPremutationAuthoritySources: {
      preparation: {
        config,
        freezeManifest,
        previousReleaseManifest,
        candidateRecord,
        rollbackSource: sourceFile(flags, 'rollback', 'E7_RESILIENCE_ROLLBACK_PATH_INVALID'),
        awsAuthSource: sourceFile(flags, 'aws-auth', 'E7_RESILIENCE_AWS_AUTH_PATH_INVALID'),
        approvalSource: sourceFile(flags, 'approval', 'E7_RESILIENCE_APPROVAL_PATH_INVALID'),
        journalRoleEffectivePermissionsSource: sourceFile(
          flags,
          'journal-role-effective-permissions',
          'E7_RESILIENCE_JOURNAL_ROLE_AUTHORITY_PATH_INVALID',
        ),
        reconciliationRecoveryRoleEffectivePermissionsSource: sourceFile(
          flags,
          'reconciliation-recovery-role-effective-permissions',
          'E7_RESILIENCE_RECOVERY_ROLE_AUTHORITY_PATH_INVALID',
        ),
        approvedPlanSource: sourceFile(flags, 'approved-diff', 'E7_RESILIENCE_PLAN_PATH_INVALID'),
        deploymentEvidenceSource: sourceFile(
          flags,
          'web-deployment',
          'E7_RESILIENCE_DEPLOYMENT_PATH_INVALID',
        ),
        observabilityEvidenceSource: sourceFile(
          flags,
          'observability',
          'E7_RESILIENCE_OBSERVABILITY_PATH_INVALID',
        ),
        activationEvidenceSource: sourceFile(
          flags,
          'activation',
          'E7_RESILIENCE_ACTIVATION_PATH_INVALID',
        ),
        externalAuthorizationSource: sourceFile(
          flags,
          'external-authorization',
          'E7_RESILIENCE_EXTERNAL_AUTHORIZATION_PATH_INVALID',
        ),
        smokeInputSource: sourceFile(
          flags,
          'smoke-input',
          'E7_RESILIENCE_SMOKE_INPUT_PATH_INVALID',
        ),
        smokeEvidenceSource: sourceFile(flags, 'smoke', 'E7_RESILIENCE_SMOKE_PATH_INVALID'),
        edgeEvidenceSource: sourceFile(flags, 'edge', 'E7_RESILIENCE_EDGE_PATH_INVALID'),
        qualityEvidenceSource: sourceFile(flags, 'quality', 'E7_RESILIENCE_QUALITY_PATH_INVALID'),
        sandboxEvidenceSource: sourceFile(flags, 'sandbox', 'E7_RESILIENCE_SANDBOX_PATH_INVALID'),
        rollbackSmokeInputSource: sourceFile(
          flags,
          'rollback-smoke-input',
          'E7_RESILIENCE_ROLLBACK_SMOKE_INPUT_PATH_INVALID',
        ),
        pendingProducerSource: sourceFile(
          flags,
          'pending-producer',
          'E7_RESILIENCE_PENDING_PRODUCER_PATH_INVALID',
        ),
        rollbackSmokeSource: sourceFile(
          flags,
          'rollback-smoke',
          'E7_RESILIENCE_ROLLBACK_SMOKE_PATH_INVALID',
        ),
        repromotionSmokeSource: sourceFile(
          flags,
          'repromotion-smoke',
          'E7_RESILIENCE_REPROMOTION_SMOKE_PATH_INVALID',
        ),
        journalCleanupRoleArn: flags['journal-cleanup-role'],
        assemblyDirectory: insideWorkspace(flags.assembly, 'E7_RESILIENCE_ASSEMBLY_PATH_INVALID'),
        maxPolls: Number(flags['max-polls']),
      },
      preparedInputsSource: sourceFile(flags, 'inputs', 'E7_RESILIENCE_CLI_INPUT_PATH_INVALID'),
      rb06DescriptorSource: sourceFile(flags, 'rb06', 'E7_RESILIENCE_CLI_RB06_PATH_INVALID'),
      rb08DescriptorSource: sourceFile(flags, 'rb08', 'E7_RESILIENCE_CLI_RB08_PATH_INVALID'),
      sourceBindingSource: sourceFile(
        flags,
        'source-binding',
        'E7_RESILIENCE_CLI_SOURCE_BINDING_PATH_INVALID',
      ),
      githubIdentity: {
        repository: process.env.GITHUB_REPOSITORY,
        workflowRef: process.env.STAGE7_JOB_WORKFLOW_REF,
        ref: process.env.GITHUB_REF,
        runId,
        runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
        candidateSha: process.env.GITHUB_SHA,
        startedAtUtc: process.env.STAGE7_ROLLBACK_STARTED_AT_UTC,
      },
    },
    ...adapters,
    mutation: () =>
      runProtectedAwsRollbackResilience({
        inputsWithoutExecution,
        rb06Descriptor,
        rb08Descriptor,
      }),
  });
  const result = guarded.result;
  const output = insideWorkspace(flags.output, 'E7_RESILIENCE_CLI_OUTPUT_PATH_INVALID');
  await writeStage7Json(output, 'stage7-rollback-resilience-protected-run.json', result);
  const sourceBinding = readStrictJsonFile(
    insideWorkspace(flags['source-binding'], 'E7_RESILIENCE_CLI_SOURCE_BINDING_PATH_INVALID'),
  );
  const completion = createRollbackResilienceCompletionEnvelope({
    rollbackSource: readFileSync(
      insideWorkspace(flags.rollback, 'E7_RESILIENCE_CLI_ROLLBACK_PATH_INVALID'),
    ),
    sourceBinding,
    protectedRun: result,
    validationContext: { inputsWithoutExecution, rb06Descriptor, rb08Descriptor },
  });
  await writeStage7Json(
    insideWorkspace(flags['completion-output'], 'E7_RESILIENCE_CLI_COMPLETION_OUTPUT_PATH_INVALID'),
    'stage7-rollback-resilience-complete.json',
    completion,
  );
  process.stdout.write(
    `${JSON.stringify({ status: result.status, runSha256: result.runSha256, completionSha256: completion.envelopeSha256, gateE703: result.gateE703 })}\n`,
  );
};

if (path.resolve(process.argv[1] ?? '') === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error?.code ?? 'E7_RESILIENCE_CLI_FAILED'}\n`);
    process.exitCode = 1;
  });
}
