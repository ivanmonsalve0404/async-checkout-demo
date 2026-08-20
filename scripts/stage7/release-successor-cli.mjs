#!/usr/bin/env node

import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { Buffer } from 'node:buffer';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { readStrictJsonFile, workspaceRoot } from './core.mjs';
import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import {
  RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS,
  createReleaseEvidenceSetCommitment,
  createReleaseSuccessorCompositeRecoveryObservation,
  createReleaseSuccessorRunObservation,
  extractReleaseSuccessorObservedArtifacts,
  selfTestReleaseSuccessorCompositeRecoveryObservation,
  selfTestReleaseSuccessorHandoff,
  validateReleaseSuccessorFenceAuthoritySources,
  validateReleaseSuccessorReconciliationAuthoritySources,
  validateReleaseSuccessorSourceBundleDirectory,
  writeReleaseSuccessorSourceBundle,
} from './release-successor-handoff.mjs';
import {
  createReleaseSuccessorPostSuccessObservation,
  selfTestReleaseSuccessorConsumerObservation,
  writeVerifiedReleaseSuccessorTargetProjection,
} from './release-successor-consumer.mjs';
import {
  finalizeReleaseSuccessorRecovery,
  createReleaseSuccessorCompletionFence,
  putReleaseSuccessorCompletionFence,
  selfTestReleaseSuccessorFinalization,
  validateReleaseSuccessorCallerAuthority,
} from './release-successor-finalization.mjs';
import {
  cleanupReleaseSuccessorJournal,
  createReleaseSuccessorPreservationReceipt,
  selfTestReleaseSuccessorJournalCleanup,
} from './release-successor-journal-cleanup.mjs';
import { captureReleaseSuccessorJournalSnapshot } from './release-successor-journal-snapshot.mjs';
import {
  createReleaseSuccessorRetrySelection,
  materializeReleaseSuccessorRetrySource,
  selfTestReleaseSuccessorRetry,
} from './release-successor-retry.mjs';
import {
  captureReleaseJournalRoleEffectivePermissions,
  selfTestReleaseSuccessorIamAuthority,
} from './release-successor-iam-authority.mjs';
import { selfTestReleaseSuccessorSchemas } from './release-successor-schemas.mjs';
import { selfTestReleaseSuccessorZip } from './release-successor-zip.mjs';
import {
  selfTestPreviousReleaseProjection,
  validatePreviousReleaseProjection,
} from './previous-release-projection.mjs';
import {
  captureReleaseSuccessorRecoveryCloseoutAuthority,
  extractReleaseSuccessorRecoveryCompositeInputs,
  readReleaseSuccessorRecoveryResultFromIntake,
  selfTestReleaseSuccessorRecoveryIntegration,
} from './release-successor-recovery-integration.mjs';

class ReleaseSuccessorCliError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'ReleaseSuccessorCliError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new ReleaseSuccessorCliError(code, cause === undefined ? undefined : { cause });
};
const insideWorkspace = (filename, code, { mustExist = true } = {}) => {
  const resolved = path.resolve(workspaceRoot, filename);
  const relative = path.relative(workspaceRoot, resolved);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative) ||
    (mustExist && !existsSync(resolved))
  ) {
    fail(code);
  }
  return resolved;
};
const parseFlags = (arguments_, required, optional = []) => {
  if (arguments_.length % 2 !== 0) fail('E7_RELEASE_SUCCESSOR_CLI_FLAGS_INVALID');
  const allowed = new Set([...required, ...optional]);
  const flags = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const raw = arguments_[index];
    const value = arguments_[index + 1];
    const name = raw?.startsWith('--') ? raw.slice(2) : '';
    if (
      !allowed.has(name) ||
      typeof value !== 'string' ||
      value === '' ||
      Object.hasOwn(flags, name)
    ) {
      fail('E7_RELEASE_SUCCESSOR_CLI_FLAGS_INVALID');
    }
    flags[name] = value;
  }
  if (required.some((name) => !Object.hasOwn(flags, name))) {
    fail('E7_RELEASE_SUCCESSOR_CLI_FLAGS_INVALID');
  }
  return flags;
};
const read = (filename, code) => readFileSync(insideWorkspace(filename, code));
const outputPath = (filename, code) => insideWorkspace(filename, code, { mustExist: false });
const writeJson = (filename, value, code) => {
  const resolved = outputPath(filename, code);
  mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  writeFileSync(resolved, `${JSON.stringify(value)}\n`, { flag: 'wx', mode: 0o600 });
  return resolved;
};
const positiveInteger = (value, code, maximum = Number.MAX_SAFE_INTEGER) => {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1 || number > maximum) fail(code);
  return number;
};
const SOURCE_FLAG_MAP = Object.freeze({
  observationSource: 'observation',
  releaseMetadataSource: 'release-metadata',
  stage6CloseoutSource: 'stage6-closeout',
  configSource: 'config',
  freezeSource: 'freeze',
  predecessorSource: 'previous-manifest',
  predecessorSourceProvenanceSource: 'previous-source',
  predecessorTargetCompatibilitySource: 'previous-target',
  predecessorFinalDisableSource: 'previous-final-disable',
  predecessorApiContractSource: 'previous-api',
  predecessorPendingSource: 'previous-pending',
  predecessorSmokeSource: 'previous-smoke',
  predecessorProjectionIndexSource: 'previous-index',
  candidateRecordSource: 'candidate-record',
  emergencyRecoverySource: 'emergency-recovery',
  emergencyRecoveryNoActionOutcomeSource: 'emergency-recovery-no-action-outcome',
  approvedPlanSource: 'plan',
  rawDiffSource: 'diff',
  githubApprovalSource: 'github-approval',
  approvalSource: 'approval',
  activationSource: 'activation',
  driftSource: 'drift',
  rollbackSource: 'rollback',
  rollbackSourceBindingSource: 'rb-binding',
  rollbackProtectedRunSource: 'rb-run',
  rollbackCompletionSource: 'rb-completion',
  releaseManifestSource: 'release-manifest',
  provenanceLedgerSource: 'ledger',
  closeoutSource: 'closeout',
  releaseHandoffSource: 'release-handoff',
  publicationPreparationSource: 'publication',
  publicationPlanSource: 'publication-plan',
  publicationTargetProofSource: 'publication-target-proof',
  publicationOperationSource: 'publication-operation',
  publicationProofSource: 'publication-proof',
  apiDeploymentSource: 'api-deployment',
  pendingProducerSource: 'pending-producer',
  pendingEgressCloseoutSource: 'pending-egress-closeout',
  postdeploySmokeSource: 'postdeploy-smoke',
  repromotionSmokeSource: 'repromotion-smoke',
  releaseFenceSource: 'fence',
  reconciliationRollbackCheckSource: 'reconciliation-rollback-check',
  reconciliationRollbackResilienceSource: 'reconciliation-rollback-resilience',
  preFenceGateSource: 'pre-fence-gate',
  awsAuthSource: 'aws-auth',
  journalRoleEffectivePermissionsSource: 'journal-role-effective-permissions',
  reconciliationRecoveryRoleEffectivePermissionsSource: 'recovery-role-effective-permissions',
});
const SOURCE_FLAGS = Object.values(SOURCE_FLAG_MAP);
const ROLLBACK_CONTEXT_FLAGS = ['rb-inputs', 'rb06', 'rb08'];
const sourceOptions = (flags, { finalization = false } = {}) => {
  const options = Object.fromEntries(
    Object.entries(SOURCE_FLAG_MAP).map(([key, flag]) => [
      key,
      read(
        flags[flag],
        `E7_RELEASE_SUCCESSOR_CLI_${flag.toUpperCase().replaceAll('-', '_')}_INVALID`,
      ),
    ]),
  );
  options.rollbackInputsSource = read(
    flags['rb-inputs'],
    'E7_RELEASE_SUCCESSOR_CLI_RB_INPUTS_INVALID',
  );
  options.rb06DescriptorSource = read(flags.rb06, 'E7_RELEASE_SUCCESSOR_CLI_RB06_INVALID');
  options.rb08DescriptorSource = read(flags.rb08, 'E7_RELEASE_SUCCESSOR_CLI_RB08_INVALID');
  if (finalization) {
    options.finalizationMarkerSource = read(
      flags.marker,
      'E7_RELEASE_SUCCESSOR_CLI_MARKER_INVALID',
    );
    options.finalDisableSource = read(
      flags.finalization,
      'E7_RELEASE_SUCCESSOR_CLI_FINALIZATION_INVALID',
    );
    options.journalSnapshotSource = read(
      flags['journal-snapshot'],
      'E7_RELEASE_SUCCESSOR_CLI_JOURNAL_SNAPSHOT_INVALID',
    );
  }
  return options;
};

const awsJson = (arguments_, code) => {
  try {
    const output = execFileSync('aws', [...arguments_, '--output', 'json', '--no-cli-pager'], {
      encoding: 'utf8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 8 * 1024 * 1024,
    });
    return output.trim() === '' ? {} : JSON.parse(output);
  } catch (error) {
    const detail = `${error?.stderr ?? ''}${error?.message ?? ''}`;
    if (/ParameterAlreadyExists/u.test(detail)) {
      const exists = new Error('ParameterAlreadyExists');
      exists.code = 'ParameterAlreadyExists';
      throw exists;
    }
    if (/ParameterNotFound/u.test(detail)) {
      const missing = new Error('ParameterNotFound');
      missing.code = 'ParameterNotFound';
      throw missing;
    }
    fail(code, error);
  }
};
const awsRawJson = (arguments_, code) => {
  try {
    const output = execFileSync('aws', [...arguments_, '--output', 'json', '--no-cli-pager'], {
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 8 * 1024 * 1024,
    });
    if (!Buffer.isBuffer(output) || output.length < 2) fail(code);
    parseStrictJsonSource(output, { scanForbiddenData: false });
    return Buffer.from(output);
  } catch (error) {
    if (error instanceof ReleaseSuccessorCliError) throw error;
    fail(code, error);
  }
};

const captureJournalRoleAuthority = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'journal-role-arn',
    'permissions-boundary-arn',
    'aws-region',
    'output',
    'get-role-output',
  ]);
  const effectiveOutput = outputPath(
    flags.output,
    'E7_RELEASE_SUCCESSOR_CLI_JOURNAL_AUTHORITY_OUTPUT_INVALID',
  );
  const roleOutput = outputPath(
    flags['get-role-output'],
    'E7_RELEASE_SUCCESSOR_CLI_JOURNAL_ROLE_OUTPUT_INVALID',
  );
  if (effectiveOutput === roleOutput || existsSync(effectiveOutput) || existsSync(roleOutput)) {
    fail('E7_RELEASE_SUCCESSOR_CLI_JOURNAL_AUTHORITY_OUTPUT_INVALID');
  }
  const captured = captureReleaseJournalRoleEffectivePermissions({
    expectedRoleArn: flags['journal-role-arn'],
    expectedPermissionsBoundaryArn: flags['permissions-boundary-arn'],
    awsRegion: flags['aws-region'],
    callAwsRaw: (awsArguments) =>
      awsRawJson(awsArguments, 'E7_RELEASE_SUCCESSOR_CLI_JOURNAL_AUTHORITY_AWS_FAILED'),
  });
  mkdirSync(path.dirname(effectiveOutput), { recursive: true, mode: 0o700 });
  mkdirSync(path.dirname(roleOutput), { recursive: true, mode: 0o700 });
  try {
    writeFileSync(roleOutput, captured.roleAuditBytes, { flag: 'wx', mode: 0o600 });
    writeFileSync(effectiveOutput, captured.bytes, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    rmSync(roleOutput, { force: true });
    rmSync(effectiveOutput, { force: true });
    fail('E7_RELEASE_SUCCESSOR_CLI_JOURNAL_AUTHORITY_WRITE_FAILED', error);
  }
  return {
    status: 'PASS',
    effectivePermissionsSha256: captured.value.effectivePermissionsSha256,
    effectivePolicyProjectionSha256: captured.value.effectivePolicyProjectionSha256,
    sourceBindingCount: captured.sourceBindingCount,
    externalRequests: captured.sourceBindingCount,
    mutationsPerformed: 0,
  };
};

const captureCallerRuntime = (arguments_) => {
  const flags = parseFlags(arguments_, ['caller-identity-output', 'aws-version-output']);
  const callerOutput = outputPath(
    flags['caller-identity-output'],
    'E7_RELEASE_SUCCESSOR_CLI_CALLER_RUNTIME_OUTPUT_INVALID',
  );
  const versionOutput = outputPath(
    flags['aws-version-output'],
    'E7_RELEASE_SUCCESSOR_CLI_CALLER_RUNTIME_OUTPUT_INVALID',
  );
  if (callerOutput === versionOutput || existsSync(callerOutput) || existsSync(versionOutput)) {
    fail('E7_RELEASE_SUCCESSOR_CLI_CALLER_RUNTIME_OUTPUT_INVALID');
  }
  const version = spawnSync('aws', ['--version'], {
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30_000,
  });
  const versionText = `${version.stdout ?? ''}${version.stderr ?? ''}`.trim();
  if (
    version.status !== 0 ||
    version.error !== undefined ||
    !/^aws-cli\/[0-9]+\.[0-9]+\.[0-9]+(?:\s|$)/u.test(versionText) ||
    Buffer.byteLength(versionText, 'utf8') > 4096
  ) {
    fail('E7_RELEASE_SUCCESSOR_CLI_AWS_VERSION_CAPTURE_FAILED', version.error);
  }
  const callerBytes = awsRawJson(
    ['sts', 'get-caller-identity'],
    'E7_RELEASE_SUCCESSOR_CLI_CALLER_IDENTITY_CAPTURE_FAILED',
  );
  mkdirSync(path.dirname(callerOutput), { recursive: true, mode: 0o700 });
  mkdirSync(path.dirname(versionOutput), { recursive: true, mode: 0o700 });
  try {
    writeFileSync(callerOutput, callerBytes, { flag: 'wx', mode: 0o600 });
    writeFileSync(versionOutput, `${versionText}\n`, { flag: 'wx', mode: 0o600 });
  } catch (error) {
    rmSync(callerOutput, { force: true });
    rmSync(versionOutput, { force: true });
    fail('E7_RELEASE_SUCCESSOR_CLI_CALLER_RUNTIME_WRITE_FAILED', error);
  }
  return {
    status: 'PASS',
    externalRequests: 1,
    mutationsPerformed: 0,
  };
};
const putParameter = ({ name, type, tier, value, overwrite }) => {
  if (overwrite !== false || tier !== 'Standard') {
    fail('E7_RELEASE_SUCCESSOR_CLI_PARAMETER_WRITE_POLICY_INVALID');
  }
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
    'E7_RELEASE_SUCCESSOR_CLI_PUT_PARAMETER_FAILED',
  );
};
const getParameter = ({ name, withDecryption }) => {
  const response = awsJson(
    [
      'ssm',
      'get-parameter',
      '--name',
      name,
      withDecryption ? '--with-decryption' : '--no-with-decryption',
    ],
    'E7_RELEASE_SUCCESSOR_CLI_GET_PARAMETER_FAILED',
  );
  if (response?.Parameter?.LastModifiedDate !== undefined) {
    const parsed = new Date(response.Parameter.LastModifiedDate);
    if (Number.isNaN(parsed.valueOf())) {
      fail('E7_RELEASE_SUCCESSOR_CLI_PARAMETER_TIMESTAMP_INVALID');
    }
    response.Parameter.LastModifiedDate = parsed.toISOString();
  }
  return response;
};
const getParametersByPath = ({
  path: parameterPath,
  recursive,
  withDecryption,
  maxResults,
  nextToken,
}) =>
  awsJson(
    [
      'ssm',
      'get-parameters-by-path',
      '--path',
      parameterPath,
      recursive ? '--recursive' : '--no-recursive',
      withDecryption ? '--with-decryption' : '--no-with-decryption',
      ...(maxResults === undefined ? [] : ['--max-results', String(maxResults)]),
      ...(nextToken === undefined ? [] : ['--next-token', nextToken]),
    ],
    'E7_RELEASE_SUCCESSOR_CLI_GET_PARAMETERS_BY_PATH_FAILED',
  );
const deleteParameter = ({ name }) =>
  awsJson(
    ['ssm', 'delete-parameter', '--name', name],
    'E7_RELEASE_SUCCESSOR_CLI_DELETE_PARAMETER_FAILED',
  );

const observeRelease = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'event',
    'run-response',
    'workflow-response',
    'artifacts-response',
    'archives',
    'observed-at',
    'output',
  ]);
  const archiveDirectory = insideWorkspace(
    flags.archives,
    'E7_RELEASE_SUCCESSOR_CLI_ARCHIVES_INVALID',
  );
  const artifactArchives = Object.fromEntries(
    RELEASE_SUCCESSOR_REQUIRED_ARTIFACTS.map((name) => [
      name,
      readFileSync(path.join(archiveDirectory, `${name}.zip`)),
    ]),
  );
  const observation = createReleaseSuccessorRunObservation({
    triggerSource: read(flags.event, 'E7_RELEASE_SUCCESSOR_CLI_EVENT_INVALID'),
    runResponseSource: read(flags['run-response'], 'E7_RELEASE_SUCCESSOR_CLI_RUN_INVALID'),
    workflowResponseSource: read(
      flags['workflow-response'],
      'E7_RELEASE_SUCCESSOR_CLI_WORKFLOW_INVALID',
    ),
    artifactsResponseSource: read(
      flags['artifacts-response'],
      'E7_RELEASE_SUCCESSOR_CLI_ARTIFACTS_INVALID',
    ),
    artifactArchives,
    observedAtUtc: flags['observed-at'],
  });
  writeJson(flags.output, observation, 'E7_RELEASE_SUCCESSOR_CLI_OBSERVATION_OUTPUT_INVALID');
  return observation;
};

const extractRelease = (arguments_) => {
  const flags = parseFlags(arguments_, ['observation', 'archives', 'output-directory']);
  return extractReleaseSuccessorObservedArtifacts({
    observationSource: read(
      flags.observation,
      'E7_RELEASE_SUCCESSOR_CLI_EXTRACT_OBSERVATION_INVALID',
    ),
    archiveDirectory: insideWorkspace(
      flags.archives,
      'E7_RELEASE_SUCCESSOR_CLI_EXTRACT_ARCHIVES_INVALID',
    ),
    outputDirectory: outputPath(
      flags['output-directory'],
      'E7_RELEASE_SUCCESSOR_CLI_EXTRACT_OUTPUT_INVALID',
    ),
  });
};

const authorizeRecoveredRelease = async (arguments_) => {
  const flags = parseFlags(arguments_, [
    'intake',
    'plan-archive',
    'result-archive',
    'recovery-head-sha',
    'source-jobs',
    'recovery-jobs',
    'event',
    'context',
    'authorized-at',
    'output',
  ]);
  const authority = await captureReleaseSuccessorRecoveryCloseoutAuthority({
    token: process.env.GH_TOKEN,
    intake: readStrictJsonFile(
      insideWorkspace(flags.intake, 'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_INTAKE_INVALID'),
    ),
    recoveryHeadSha: flags['recovery-head-sha'],
    sourceJobsSource: read(
      flags['source-jobs'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_SOURCE_JOBS_INVALID',
    ),
    recoveryJobsSource: read(
      flags['recovery-jobs'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_JOBS_INVALID',
    ),
    triggerSource: read(flags.event, 'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_EVENT_INVALID'),
    planArchive: read(
      flags['plan-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_PLAN_ARCHIVE_INVALID',
    ),
    resultArchive: read(
      flags['result-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_RESULT_INVALID',
    ),
    context: readStrictJsonFile(
      insideWorkspace(flags.context, 'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_CONTEXT_INVALID'),
    ),
    authorizedAtUtc: flags['authorized-at'],
  });
  writeJson(flags.output, authority, 'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_AUTHORITY_OUTPUT_INVALID');
  return authority;
};

const extractRecoveredRelease = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'intake',
    'source-archives',
    'plan-archive',
    'result-archive',
    'output-directory',
  ]);
  return extractReleaseSuccessorRecoveryCompositeInputs({
    intake: readStrictJsonFile(
      insideWorkspace(flags.intake, 'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_INTAKE_INVALID'),
    ),
    sourceArchiveDirectory: insideWorkspace(
      flags['source-archives'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_ARCHIVES_INVALID',
    ),
    planArchive: read(
      flags['plan-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_PLAN_ARCHIVE_INVALID',
    ),
    resultArchive: read(
      flags['result-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_RESULT_INVALID',
    ),
    outputDirectory: outputPath(
      flags['output-directory'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_OUTPUT_INVALID',
    ),
  });
};

const manifestRecoveredRelease = (arguments_) => {
  const flags = parseFlags(arguments_, ['intake', 'plan-archive', 'result-archive']);
  const result = readReleaseSuccessorRecoveryResultFromIntake({
    intake: readStrictJsonFile(
      insideWorkspace(flags.intake, 'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_INTAKE_INVALID'),
    ),
    planArchive: read(
      flags['plan-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_PLAN_ARCHIVE_INVALID',
    ),
    resultArchive: read(
      flags['result-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_RESULT_INVALID',
    ),
  });
  for (const artifact of result.plan.artifactInventory.downloadManifest) {
    process.stdout.write(`${artifact.name}\t${artifact.artifactId}\t${artifact.digest}\n`);
  }
  return result.plan.artifactInventory.downloadManifest;
};

const readFlatArtifactDirectory = (directory, code) => {
  const resolved = insideWorkspace(directory, code);
  const entries = readdirSync(resolved, { withFileTypes: true });
  if (entries.length === 0 || entries.some((entry) => !entry.isFile())) fail(code);
  return Object.fromEntries(
    entries.map(({ name }) => [name, readFileSync(path.join(resolved, name))]),
  );
};

const observeRecoveredRelease = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'intake',
    'closeout-authority',
    'source-artifacts-response',
    'source-archives',
    'plan-archive',
    'result-archive',
    'reports-directory',
    'authorities-directory',
    'observed-at',
    'output',
  ]);
  const archives = insideWorkspace(
    flags['source-archives'],
    'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_ARCHIVES_INVALID',
  );
  const sourceArtifactArchives = Object.fromEntries(
    readdirSync(archives, { withFileTypes: true })
      .filter((entry) => entry.isFile() && entry.name.endsWith('.zip'))
      .map(({ name }) => [name.slice(0, -4), readFileSync(path.join(archives, name))]),
  );
  const observation = createReleaseSuccessorCompositeRecoveryObservation({
    intake: readStrictJsonFile(
      insideWorkspace(flags.intake, 'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_INTAKE_INVALID'),
    ),
    closeoutAuthority: readStrictJsonFile(
      insideWorkspace(
        flags['closeout-authority'],
        'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_AUTHORITY_INVALID',
      ),
    ),
    sourceArtifactsResponseSource: read(
      flags['source-artifacts-response'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_SOURCE_ARTIFACTS_INVALID',
    ),
    sourceArtifactArchives,
    planArchive: read(
      flags['plan-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_PLAN_ARCHIVE_INVALID',
    ),
    resultArchive: read(
      flags['result-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_RESULT_INVALID',
    ),
    localArtifacts: {
      'stage7-release-reports': readFlatArtifactDirectory(
        flags['reports-directory'],
        'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_REPORTS_INVALID',
      ),
      'stage7-release-authorities': readFlatArtifactDirectory(
        flags['authorities-directory'],
        'E7_RELEASE_SUCCESSOR_CLI_RECOVERY_AUTHORITIES_INVALID',
      ),
    },
    observedAtUtc: flags['observed-at'],
  });
  writeJson(flags.output, observation, 'E7_RELEASE_SUCCESSOR_CLI_OBSERVATION_OUTPUT_INVALID');
  return observation;
};

const fenceRelease = async (arguments_) => {
  const flags = parseFlags(arguments_, [
    'source-run-id',
    'source-run-attempt',
    'candidate-sha',
    'release-id',
    'journal-lifecycle-sha256',
    'release-metadata',
    'config',
    'freeze',
    'previous-manifest',
    'previous-api',
    'previous-pending',
    'previous-smoke',
    'candidate-record',
    'emergency-recovery',
    'emergency-recovery-no-action-outcome',
    'plan',
    'diff',
    'github-approval',
    'approval',
    'activation',
    'drift',
    'rollback',
    'rb-binding',
    'rb-run',
    'rb-completion',
    'reconciliation-rollback-check',
    'reconciliation-rollback-resilience',
    'pre-fence-gate',
    'rb-inputs',
    'rb06',
    'rb08',
    'journal-role',
    'aws-region',
    'aws-cli-version',
    'caller-identity',
    'aws-version',
    'role-audit',
    'aws-auth',
    'journal-role-effective-permissions',
    'reconciliation-recovery-role-effective-permissions',
    'live-effective-permissions',
    'permissions-boundary',
    'session-name',
    'output',
  ]);
  const validatedAuthorities = validateReleaseSuccessorFenceAuthoritySources({
    sourceRunId: flags['source-run-id'],
    sourceRunAttempt: positiveInteger(
      flags['source-run-attempt'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_ATTEMPT_INVALID',
      1,
    ),
    candidateSha: flags['candidate-sha'],
    releaseId: flags['release-id'],
    journalLifecycleSha256: flags['journal-lifecycle-sha256'],
    releaseMetadataSource: read(
      flags['release-metadata'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_RELEASE_METADATA_INVALID',
    ),
    configSource: read(flags.config, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_CONFIG_INVALID'),
    freezeSource: read(flags.freeze, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_FREEZE_INVALID'),
    predecessorSource: read(
      flags['previous-manifest'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_PREDECESSOR_INVALID',
    ),
    predecessorApiContractSource: read(
      flags['previous-api'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_PREDECESSOR_API_INVALID',
    ),
    predecessorPendingSource: read(
      flags['previous-pending'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_PREDECESSOR_PENDING_INVALID',
    ),
    predecessorSmokeSource: read(
      flags['previous-smoke'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_PREDECESSOR_SMOKE_INVALID',
    ),
    candidateRecordSource: read(
      flags['candidate-record'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_CANDIDATE_INVALID',
    ),
    emergencyRecoverySource: read(
      flags['emergency-recovery'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_EMERGENCY_RECOVERY_INVALID',
    ),
    emergencyRecoveryNoActionOutcomeSource: read(
      flags['emergency-recovery-no-action-outcome'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_EMERGENCY_RECOVERY_OUTCOME_INVALID',
    ),
    approvedPlanSource: read(flags.plan, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_PLAN_INVALID'),
    rawDiffSource: read(flags.diff, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_DIFF_INVALID'),
    githubApprovalSource: read(
      flags['github-approval'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_GITHUB_APPROVAL_INVALID',
    ),
    approvalSource: read(flags.approval, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_APPROVAL_INVALID'),
    activationSource: read(flags.activation, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_ACTIVATION_INVALID'),
    driftSource: read(flags.drift, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_DRIFT_INVALID'),
    rollbackSource: read(flags.rollback, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_ROLLBACK_INVALID'),
    rollbackSourceBindingSource: read(
      flags['rb-binding'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_ROLLBACK_BINDING_INVALID',
    ),
    rollbackProtectedRunSource: read(
      flags['rb-run'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_ROLLBACK_RUN_INVALID',
    ),
    rollbackCompletionSource: read(
      flags['rb-completion'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_ROLLBACK_COMPLETION_INVALID',
    ),
    reconciliationRollbackCheckSource: read(
      flags['reconciliation-rollback-check'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_RECONCILIATION_CHECK_INVALID',
    ),
    reconciliationRollbackResilienceSource: read(
      flags['reconciliation-rollback-resilience'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_RECONCILIATION_RESILIENCE_INVALID',
    ),
    preFenceGateSource: read(
      flags['pre-fence-gate'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_PRE_FENCE_GATE_INVALID',
    ),
    rollbackInputsSource: read(
      flags['rb-inputs'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_RB_INPUTS_INVALID',
    ),
    rb06DescriptorSource: read(flags.rb06, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_RB06_INVALID'),
    rb08DescriptorSource: read(flags.rb08, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_RB08_INVALID'),
    awsAuthSource: read(flags['aws-auth'], 'E7_RELEASE_SUCCESSOR_CLI_FENCE_AWS_AUTH_INVALID'),
    journalRoleEffectivePermissionsSource: read(
      flags['journal-role-effective-permissions'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_INVALID',
    ),
    reconciliationRecoveryRoleEffectivePermissionsSource: read(
      flags['reconciliation-recovery-role-effective-permissions'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_INVALID',
    ),
  });
  const evidenceBindings = validatedAuthorities.evidenceBindings;
  const authorityBindings = validatedAuthorities.authorityBindings;
  const callerAuthority = validateReleaseSuccessorCallerAuthority({
    callerIdentitySource: read(
      flags['caller-identity'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_CALLER_INVALID',
    ),
    awsVersionSource: read(
      flags['aws-version'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_AWS_VERSION_INVALID',
    ),
    roleAuditSource: read(flags['role-audit'], 'E7_RELEASE_SUCCESSOR_CLI_FENCE_ROLE_AUDIT_INVALID'),
    awsAuthSource: read(flags['aws-auth'], 'E7_RELEASE_SUCCESSOR_CLI_FENCE_AWS_AUTH_INVALID'),
    frozenEffectivePermissionsSource: read(
      flags['journal-role-effective-permissions'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_FROZEN_EFFECTIVE_PERMISSIONS_INVALID',
    ),
    liveEffectivePermissionsSource: read(
      flags['live-effective-permissions'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_LIVE_EFFECTIVE_PERMISSIONS_INVALID',
    ),
    journalCleanupRoleArn: flags['journal-role'],
    expectedSessionName: flags['session-name'],
    expectedAwsCliVersion: flags['aws-cli-version'],
    expectedPermissionsBoundaryArn: flags['permissions-boundary'],
  });
  const fence = createReleaseSuccessorCompletionFence({
    validatedAuthorities,
    validatedCallerAuthority: callerAuthority,
    sourceRunId: flags['source-run-id'],
    sourceRunAttempt: positiveInteger(
      flags['source-run-attempt'],
      'E7_RELEASE_SUCCESSOR_CLI_FENCE_ATTEMPT_INVALID',
      1,
    ),
    candidateSha: flags['candidate-sha'],
    releaseId: flags['release-id'],
    journalLifecycleSha256: flags['journal-lifecycle-sha256'],
    evidenceBindings,
    authorityBindings,
    authoritySetSha256: validatedAuthorities.authoritySetSha256,
    journalCleanupRoleArn: flags['journal-role'],
    journalRoleAuthoritySha256: callerAuthority.roleAuthoritySha256,
  });
  const result = await putReleaseSuccessorCompletionFence({
    fence,
    journalCleanupRoleArn: flags['journal-role'],
    awsRegion: flags['aws-region'],
    putParameter,
    getParameter,
  });
  writeJson(flags.output, fence, 'E7_RELEASE_SUCCESSOR_CLI_FENCE_OUTPUT_INVALID');
  return {
    fenceSha256: fence.fenceSha256,
    parameterName: result.parameterName,
    idempotent: result.idempotent,
  };
};

const createCommitment = (arguments_) => {
  const flags = parseFlags(arguments_, [...SOURCE_FLAGS, ...ROLLBACK_CONTEXT_FLAGS, 'output']);
  const commitment = createReleaseEvidenceSetCommitment(sourceOptions(flags));
  writeJson(flags.output, commitment, 'E7_RELEASE_SUCCESSOR_CLI_COMMITMENT_OUTPUT_INVALID');
  return commitment;
};

const finalize = async (arguments_) => {
  const flags = parseFlags(arguments_, [
    'commitment',
    'journal-role',
    'rollback-role',
    'ephemeral-cleanup-role',
    'lifecycle-role-sha256',
    'caller-identity',
    'aws-version',
    'role-audit',
    'aws-auth',
    'frozen-effective-permissions',
    'live-effective-permissions',
    'permissions-boundary',
    'session-name',
    'fence-output',
    'marker-output',
    'provenance-output',
  ]);
  const result = await finalizeReleaseSuccessorRecovery({
    commitment: readStrictJsonFile(
      insideWorkspace(flags.commitment, 'E7_RELEASE_SUCCESSOR_CLI_COMMITMENT_INVALID'),
    ),
    journalCleanupRoleArn: flags['journal-role'],
    rollbackRoleArn: flags['rollback-role'],
    ephemeralCleanupRoleArn: flags['ephemeral-cleanup-role'],
    lifecycleCleanupRoleSha256: flags['lifecycle-role-sha256'],
    callerIdentitySource: read(
      flags['caller-identity'],
      'E7_RELEASE_SUCCESSOR_CLI_CALLER_IDENTITY_INVALID',
    ),
    awsVersionSource: read(flags['aws-version'], 'E7_RELEASE_SUCCESSOR_CLI_AWS_VERSION_INVALID'),
    roleAuditSource: read(flags['role-audit'], 'E7_RELEASE_SUCCESSOR_CLI_ROLE_AUDIT_INVALID'),
    awsAuthSource: read(flags['aws-auth'], 'E7_RELEASE_SUCCESSOR_CLI_AWS_AUTH_INVALID'),
    frozenEffectivePermissionsSource: read(
      flags['frozen-effective-permissions'],
      'E7_RELEASE_SUCCESSOR_CLI_FROZEN_EFFECTIVE_PERMISSIONS_INVALID',
    ),
    liveEffectivePermissionsSource: read(
      flags['live-effective-permissions'],
      'E7_RELEASE_SUCCESSOR_CLI_LIVE_EFFECTIVE_PERMISSIONS_INVALID',
    ),
    expectedPermissionsBoundaryArn: flags['permissions-boundary'],
    expectedSessionName: flags['session-name'],
    putParameter,
    getParameter,
  });
  writeJson(
    flags['fence-output'],
    result.releaseFence,
    'E7_RELEASE_SUCCESSOR_CLI_FENCE_OUTPUT_INVALID',
  );
  writeJson(
    flags['marker-output'],
    result.marker,
    'E7_RELEASE_SUCCESSOR_CLI_MARKER_OUTPUT_INVALID',
  );
  writeJson(
    flags['provenance-output'],
    result.provenance,
    'E7_RELEASE_SUCCESSOR_CLI_FINALIZATION_OUTPUT_INVALID',
  );
  return result.provenance;
};

const buildSource = (arguments_) => {
  const flags = parseFlags(arguments_, [
    ...SOURCE_FLAGS,
    ...ROLLBACK_CONTEXT_FLAGS,
    'marker',
    'finalization',
    'journal-snapshot',
    'output-directory',
  ]);
  const result = writeReleaseSuccessorSourceBundle({
    outputDirectory: outputPath(
      flags['output-directory'],
      'E7_RELEASE_SUCCESSOR_CLI_SOURCE_OUTPUT_INVALID',
    ),
    options: sourceOptions(flags, { finalization: true }),
  });
  return result.index;
};

const captureJournalSnapshot = async (arguments_) => {
  const flags = parseFlags(arguments_, [
    'reconciliation-rollback-check',
    'reconciliation-rollback-resilience',
    'pre-fence-gate',
    'protected-run',
    'output',
  ]);
  const reconciliation = validateReleaseSuccessorReconciliationAuthoritySources({
    rollbackCheckSource: read(
      flags['reconciliation-rollback-check'],
      'E7_RELEASE_SUCCESSOR_CLI_SNAPSHOT_ROLLBACK_CHECK_INVALID',
    ),
    rollbackResilienceSource: read(
      flags['reconciliation-rollback-resilience'],
      'E7_RELEASE_SUCCESSOR_CLI_SNAPSHOT_ROLLBACK_RESILIENCE_INVALID',
    ),
    preFenceGateSource: read(
      flags['pre-fence-gate'],
      'E7_RELEASE_SUCCESSOR_CLI_SNAPSHOT_GATE_INVALID',
    ),
  });
  const candidateSha = reconciliation.authority.source.candidateSha;
  const result = await captureReleaseSuccessorJournalSnapshot({
    scenarioPrefixes: {
      'RB-E7-06': `/checkout/stage7/rollback/${candidateSha}/RB-E7-06`,
      'RB-E7-08': `/checkout/stage7/rollback/${candidateSha}/RB-E7-08`,
    },
    reconciliationJournalAuthority: reconciliation.authority,
    rollbackCheckReceipt: reconciliation.rollbackCheck.value,
    rollbackResilienceReceipt: reconciliation.rollbackResilience.value,
    protectedRun: readStrictJsonFile(
      insideWorkspace(
        flags['protected-run'],
        'E7_RELEASE_SUCCESSOR_CLI_SNAPSHOT_PROTECTED_RUN_INVALID',
      ),
    ),
    getParametersByPath,
  });
  writeJson(flags.output, result.snapshot, 'E7_RELEASE_SUCCESSOR_CLI_SNAPSHOT_OUTPUT_INVALID');
  return {
    snapshotSha256: result.snapshot.snapshotSha256,
    entryCount: result.snapshot.entryCount,
    listPages: result.listPages,
  };
};

const preserve = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'source-directory',
    'artifact-response',
    'artifact-archive',
    'post-run-id',
    'post-attempt',
    'post-head-sha',
    'preserved-at',
    'output',
  ]);
  const sourceBundle = validateReleaseSuccessorSourceBundleDirectory(
    insideWorkspace(flags['source-directory'], 'E7_RELEASE_SUCCESSOR_CLI_SOURCE_INVALID'),
  );
  const receipt = createReleaseSuccessorPreservationReceipt({
    sourceBundle,
    artifactApiSource: read(
      flags['artifact-response'],
      'E7_RELEASE_SUCCESSOR_CLI_SOURCE_ARTIFACT_RESPONSE_INVALID',
    ),
    artifactArchiveSource: read(
      flags['artifact-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_SOURCE_ARCHIVE_INVALID',
    ),
    postSuccessRunId: flags['post-run-id'],
    postSuccessRunAttempt: positiveInteger(
      flags['post-attempt'],
      'E7_RELEASE_SUCCESSOR_CLI_POST_ATTEMPT_INVALID',
      999,
    ),
    postSuccessHeadSha: flags['post-head-sha'],
    preservedAtUtc: flags['preserved-at'],
  });
  writeJson(flags.output, receipt, 'E7_RELEASE_SUCCESSOR_CLI_PRESERVATION_OUTPUT_INVALID');
  return receipt;
};

const selectRetrySource = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'source-run-id',
    'post-run-id',
    'post-attempt',
    'artifact-pages',
    'output',
  ]);
  const selection = createReleaseSuccessorRetrySelection({
    sourceRunId: flags['source-run-id'],
    postSuccessRunId: flags['post-run-id'],
    currentPostSuccessRunAttempt: positiveInteger(
      flags['post-attempt'],
      'E7_RELEASE_SUCCESSOR_CLI_RETRY_ATTEMPT_INVALID',
      999,
    ),
    artifactPagesSource: read(
      flags['artifact-pages'],
      'E7_RELEASE_SUCCESSOR_CLI_RETRY_ARTIFACT_PAGES_INVALID',
    ),
  });
  writeJson(flags.output, selection, 'E7_RELEASE_SUCCESSOR_CLI_RETRY_SELECTION_OUTPUT_INVALID');
  return selection;
};

const reuseRetrySource = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'selection',
    'source-artifact-response',
    'source-archive',
    'preservation-artifact-response',
    'preservation-archive',
    'post-head-sha',
    'output-directory',
    'preservation-output',
  ]);
  const result = materializeReleaseSuccessorRetrySource({
    selection: readStrictJsonFile(
      insideWorkspace(flags.selection, 'E7_RELEASE_SUCCESSOR_CLI_RETRY_SELECTION_INVALID'),
    ),
    sourceArtifactApiSource: read(
      flags['source-artifact-response'],
      'E7_RELEASE_SUCCESSOR_CLI_RETRY_SOURCE_RESPONSE_INVALID',
    ),
    sourceArchiveSource: read(
      flags['source-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RETRY_SOURCE_ARCHIVE_INVALID',
    ),
    preservationArtifactApiSource: read(
      flags['preservation-artifact-response'],
      'E7_RELEASE_SUCCESSOR_CLI_RETRY_PRESERVATION_RESPONSE_INVALID',
    ),
    preservationArchiveSource: read(
      flags['preservation-archive'],
      'E7_RELEASE_SUCCESSOR_CLI_RETRY_PRESERVATION_ARCHIVE_INVALID',
    ),
    expectedHeadSha: flags['post-head-sha'],
    outputDirectory: outputPath(
      flags['output-directory'],
      'E7_RELEASE_SUCCESSOR_CLI_RETRY_OUTPUT_DIRECTORY_INVALID',
    ),
    preservationOutput: outputPath(
      flags['preservation-output'],
      'E7_RELEASE_SUCCESSOR_CLI_RETRY_PRESERVATION_OUTPUT_INVALID',
    ),
  });
  return {
    status: 'REUSED_DURABLE_SOURCE',
    sourceRunId: result.sourceBundle.provenance.sourceRunId,
    sourceBundleSha256: result.sourceBundle.index.bundleSha256,
    preservationReceiptSha256: result.preservationReceipt.preservationReceiptSha256,
    selectionSha256: result.selectionSha256,
  };
};

const cleanup = async (arguments_) => {
  const flags = parseFlags(arguments_, [
    'source-directory',
    'preservation',
    'journal-role',
    'rollback-role',
    'ephemeral-cleanup-role',
    'caller-identity',
    'aws-version',
    'role-audit',
    'aws-auth',
    'frozen-effective-permissions',
    'live-effective-permissions',
    'permissions-boundary',
    'session-name',
    'post-run-id',
    'post-attempt',
    'output',
  ]);
  const sourceBundle = validateReleaseSuccessorSourceBundleDirectory(
    insideWorkspace(flags['source-directory'], 'E7_RELEASE_SUCCESSOR_CLI_SOURCE_INVALID'),
  );
  try {
    const receipt = await cleanupReleaseSuccessorJournal({
      sourceBundle,
      preservationReceipt: readStrictJsonFile(
        insideWorkspace(flags.preservation, 'E7_RELEASE_SUCCESSOR_CLI_PRESERVATION_INVALID'),
      ),
      journalCleanupRoleArn: flags['journal-role'],
      rollbackRoleArn: flags['rollback-role'],
      ephemeralCleanupRoleArn: flags['ephemeral-cleanup-role'],
      callerIdentitySource: read(
        flags['caller-identity'],
        'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_CALLER_INVALID',
      ),
      awsVersionSource: read(
        flags['aws-version'],
        'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_AWS_VERSION_INVALID',
      ),
      roleAuditSource: read(
        flags['role-audit'],
        'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_ROLE_AUDIT_INVALID',
      ),
      awsAuthSource: read(flags['aws-auth'], 'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_AWS_AUTH_INVALID'),
      frozenEffectivePermissionsSource: read(
        flags['frozen-effective-permissions'],
        'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_FROZEN_EFFECTIVE_PERMISSIONS_INVALID',
      ),
      liveEffectivePermissionsSource: read(
        flags['live-effective-permissions'],
        'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_LIVE_EFFECTIVE_PERMISSIONS_INVALID',
      ),
      expectedPermissionsBoundaryArn: flags['permissions-boundary'],
      expectedSessionName: flags['session-name'],
      postSuccessRunId: flags['post-run-id'],
      postSuccessRunAttempt: positiveInteger(
        flags['post-attempt'],
        'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_POST_ATTEMPT_INVALID',
        999,
      ),
      getParametersByPath,
      deleteParameter,
    });
    writeJson(flags.output, receipt, 'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_OUTPUT_INVALID');
    return receipt;
  } catch (error) {
    if (error?.receipt !== undefined) {
      writeJson(flags.output, error.receipt, 'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_OUTPUT_INVALID');
    }
    throw error;
  }
};

const observePostSuccess = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'source-run-id',
    'run-response',
    'workflow-response',
    'artifacts-response',
    'artifact-list-requests',
    'source-archive',
    'preservation-archive',
    'cleanup-archive',
    'observed-at',
    'output',
  ]);
  const observation = createReleaseSuccessorPostSuccessObservation({
    sourceRunId: flags['source-run-id'],
    runResponseSource: read(flags['run-response'], 'E7_RELEASE_SUCCESSOR_CLI_POST_RUN_INVALID'),
    workflowResponseSource: read(
      flags['workflow-response'],
      'E7_RELEASE_SUCCESSOR_CLI_POST_WORKFLOW_INVALID',
    ),
    artifactsResponseSource: read(
      flags['artifacts-response'],
      'E7_RELEASE_SUCCESSOR_CLI_POST_ARTIFACTS_INVALID',
    ),
    artifactArchives: {
      source: read(flags['source-archive'], 'E7_RELEASE_SUCCESSOR_CLI_POST_SOURCE_ARCHIVE_INVALID'),
      preservation: read(
        flags['preservation-archive'],
        'E7_RELEASE_SUCCESSOR_CLI_POST_PRESERVATION_ARCHIVE_INVALID',
      ),
      cleanup: read(
        flags['cleanup-archive'],
        'E7_RELEASE_SUCCESSOR_CLI_POST_CLEANUP_ARCHIVE_INVALID',
      ),
    },
    artifactListRequests: positiveInteger(
      flags['artifact-list-requests'],
      'E7_RELEASE_SUCCESSOR_CLI_POST_ARTIFACT_LIST_REQUESTS_INVALID',
      1000,
    ),
    observedAtUtc: flags['observed-at'],
  });
  writeJson(flags.output, observation, 'E7_RELEASE_SUCCESSOR_CLI_POST_OBSERVATION_OUTPUT_INVALID');
  return observation;
};

const project = (arguments_) => {
  const flags = parseFlags(arguments_, [
    'source-directory',
    'preservation',
    'cleanup',
    'post-observation',
    'target-config',
    'target-freeze',
    'captured-at',
    'output-directory',
  ]);
  const result = writeVerifiedReleaseSuccessorTargetProjection({
    sourceBundleDirectory: insideWorkspace(
      flags['source-directory'],
      'E7_RELEASE_SUCCESSOR_CLI_SOURCE_INVALID',
    ),
    preservationReceiptPath: insideWorkspace(
      flags.preservation,
      'E7_RELEASE_SUCCESSOR_CLI_PRESERVATION_INVALID',
    ),
    cleanupReceiptPath: insideWorkspace(flags.cleanup, 'E7_RELEASE_SUCCESSOR_CLI_CLEANUP_INVALID'),
    postSuccessObservationPath: insideWorkspace(
      flags['post-observation'],
      'E7_RELEASE_SUCCESSOR_CLI_POST_OBSERVATION_INVALID',
    ),
    targetConfigSource: read(
      flags['target-config'],
      'E7_RELEASE_SUCCESSOR_CLI_TARGET_CONFIG_INVALID',
    ),
    targetFreezeSource: read(
      flags['target-freeze'],
      'E7_RELEASE_SUCCESSOR_CLI_TARGET_FREEZE_INVALID',
    ),
    capturedAtUtc: flags['captured-at'],
    outputDirectory: outputPath(
      flags['output-directory'],
      'E7_RELEASE_SUCCESSOR_CLI_PROJECTION_OUTPUT_INVALID',
    ),
  });
  return result.index;
};

const selfTest = async () => {
  const handoff = selfTestReleaseSuccessorHandoff();
  const finalization = await selfTestReleaseSuccessorFinalization();
  const cleanupResult = await selfTestReleaseSuccessorJournalCleanup();
  const consumer = selfTestReleaseSuccessorConsumerObservation();
  const iamAuthority = selfTestReleaseSuccessorIamAuthority();
  const retry = selfTestReleaseSuccessorRetry();
  const schemas = selfTestReleaseSuccessorSchemas();
  const zip = selfTestReleaseSuccessorZip();
  const projection = selfTestPreviousReleaseProjection();
  const recoveryIntegration = await selfTestReleaseSuccessorRecoveryIntegration();
  const compositeRecoveryObservation = await selfTestReleaseSuccessorCompositeRecoveryObservation();
  assert.throws(
    () =>
      execFileSync(process.execPath, [fileURLToPath(import.meta.url), 'guard-mutation'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      }),
    (error) => error?.status !== 0,
  );
  const consumerModuleUrl = new URL('./release-successor-consumer.mjs', import.meta.url).href;
  const consumerExports = JSON.parse(
    execFileSync(
      process.execPath,
      [
        '--input-type=module',
        '--eval',
        `const m=await import(${JSON.stringify(consumerModuleUrl)});process.stdout.write(JSON.stringify({rawCreate:'createReleaseSuccessorTargetProjection' in m,rawWrite:'writeReleaseSuccessorTargetProjection' in m,verifiedCreate:'createVerifiedReleaseSuccessorTargetProjection' in m,verifiedWrite:'writeVerifiedReleaseSuccessorTargetProjection' in m}));`,
      ],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
    ),
  );
  assert.deepEqual(consumerExports, {
    rawCreate: false,
    rawWrite: false,
    verifiedCreate: true,
    verifiedWrite: true,
  });
  return {
    status: 'PASS',
    canaries:
      handoff.canaries +
      finalization.canaries +
      cleanupResult.canaries +
      consumer.canaries +
      iamAuthority.canaries +
      retry.canaries +
      schemas.canaries +
      zip.canaries +
      projection.checks +
      recoveryIntegration.canaries +
      compositeRecoveryObservation.canaries +
      2,
    externalRequests: 0,
    handoff,
    finalization,
    cleanup: cleanupResult,
    consumer,
    iamAuthority,
    retry,
    schemas,
    zip,
    projection,
    recoveryIntegration,
    compositeRecoveryObservation,
  };
};

const main = async () => {
  const [command, ...arguments_] = process.argv.slice(2);
  let result;
  if (command === 'self-test' && arguments_.length === 0) result = await selfTest();
  else if (command === 'capture-caller-runtime') result = captureCallerRuntime(arguments_);
  else if (command === 'capture-journal-role-authority') {
    result = captureJournalRoleAuthority(arguments_);
  } else if (command === 'observe-release') result = observeRelease(arguments_);
  else if (command === 'extract-release') result = extractRelease(arguments_);
  else if (command === 'authorize-recovered-release') {
    result = await authorizeRecoveredRelease(arguments_);
  } else if (command === 'extract-recovered-release') result = extractRecoveredRelease(arguments_);
  else if (command === 'manifest-recovered-release') result = manifestRecoveredRelease(arguments_);
  else if (command === 'observe-recovered-release') result = observeRecoveredRelease(arguments_);
  else if (command === 'fence-release') result = await fenceRelease(arguments_);
  else if (command === 'commit') result = createCommitment(arguments_);
  else if (command === 'finalize') result = await finalize(arguments_);
  else if (command === 'capture-journal-snapshot')
    result = await captureJournalSnapshot(arguments_);
  else if (command === 'build-source') result = buildSource(arguments_);
  else if (command === 'validate-source' && arguments_.length === 1) {
    result = validateReleaseSuccessorSourceBundleDirectory(
      insideWorkspace(arguments_[0], 'E7_RELEASE_SUCCESSOR_CLI_SOURCE_INVALID'),
    ).index;
  } else if (command === 'preserve') result = preserve(arguments_);
  else if (command === 'select-retry-source') result = selectRetrySource(arguments_);
  else if (command === 'reuse-retry-source') result = reuseRetrySource(arguments_);
  else if (command === 'cleanup-journal') result = await cleanup(arguments_);
  else if (command === 'observe-post-success') result = observePostSuccess(arguments_);
  else if (command === 'project') result = project(arguments_);
  else if (command === 'validate-projection' && arguments_.length === 1) {
    result = validatePreviousReleaseProjection(
      insideWorkspace(arguments_[0], 'E7_RELEASE_SUCCESSOR_CLI_PROJECTION_INVALID'),
    ).index;
  } else fail('E7_RELEASE_SUCCESSOR_CLI_COMMAND_INVALID');
  if (command !== 'manifest-recovered-release') {
    process.stdout.write(`${JSON.stringify({ status: 'PASS', result })}\n`);
  }
};

await main();
