#!/usr/bin/env node

import { Buffer } from 'node:buffer';
import { execFileSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, validateStage7Config, workspaceRoot } from './core.mjs';
import {
  createReleaseReconciliationRecoveryActor,
  createReleaseReconciliationRecoveryApproval,
  createReleaseReconciliationRecoveryArtifactBinding,
  createReleaseReconciliationRecoveryBasePolicy,
  createReleaseReconciliationRecoveryPreservationIndex,
  createReleaseReconciliationRecoveryRequest,
  captureReleaseReconciliationRecoveryRoleEffectivePermissions,
  compareReleaseReconciliationRecoveryRoleEffectivePermissions,
  validateReleaseReconciliationRecoveryActor,
  validateReleaseReconciliationRecoveryApproval,
  validateReleaseReconciliationRecoveryArtifactBinding,
  validateReleaseReconciliationRecoveryOutcome,
  validateReleaseReconciliationRecoveryPreservationIndex,
  validateReleaseReconciliationRecoveryPreservationSources,
  validateReleaseReconciliationRecoveryRequest,
  STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT,
} from './release-reconciliation-recovery.mjs';
import { readReleaseSuccessorZipEntries } from './release-successor-zip.mjs';
import { compareReleaseJournalRoleEffectivePermissions } from './release-successor-iam-authority.mjs';
import {
  cleanupReleaseReconciliationRecovery,
  convergeReleaseReconciliationRecoveryForward,
  createAwsCliReleaseReconciliationRecoveryRuntime,
  finalizeReleaseReconciliationRecoveryForward,
  inspectReleaseReconciliationRecovery,
  resumeReleaseReconciliationRecovery,
  snapshotReleaseReconciliationRecovery,
} from './release-reconciliation-recovery-executor.mjs';
import { validateReleaseReconciliationIntent } from './release-reconciliation.mjs';
import {
  createReleaseReconciliationIntentFromSources,
  readReleaseReconciliationJsonFile,
  recoverVersionedReleaseRuntimeConvergenceCheckpoint,
  validateReleaseRuntimeConvergence,
} from './release-reconciliation-executor.mjs';

const MAX_FILE_BYTES = 32 * 1024 * 1024;
const PHASES = Object.freeze(['ROLLBACK_CHECK', 'ROLLBACK_RESILIENCE']);
const ORIGINAL_CONCLUSIONS = Object.freeze(['FAILURE', 'CANCELLED', 'TIMED_OUT']);
const INTENT_SOURCE_FLAGS = Object.freeze([
  ['config', 'config', 'stage7-config.json'],
  ['releaseMetadata', 'release-metadata', 'release-metadata.json'],
  ['candidateManifest', 'candidate-manifest', 'candidate-manifest.json'],
  ['releasePlan', 'release-plan', 'release-plan.json'],
  ['approvedDiff', 'approved-diff', 'infra-diff.json'],
  ['rawDiff', 'raw-diff', 'infra-diff.txt'],
  ['githubEnvironmentApproval', 'github-environment-approval', 'github-environment-approval.json'],
  ['approval', 'approval', 'approval.json'],
  ['awsAuth', 'aws-auth', 'aws-auth.json'],
  [
    'journalRoleEffectivePermissions',
    'journal-role-effective-permissions',
    'stage7-release-journal-role-effective-permissions.json',
  ],
  ['activation', 'activation', 'activation.json'],
  ['webDeployment', 'web-deployment', 'web.json'],
  ['candidateRecord', 'candidate-record', 'versioned-rollback-candidate.json'],
  ['externalAuthorization', 'external-authorization', 'external-authorization.json'],
  ['previousReleaseManifest', 'previous-release-manifest', 'previous-release-manifest.json'],
  ['previousSourceProvenance', 'previous-source-provenance', 'previous-source-provenance.json'],
  [
    'previousTargetCompatibility',
    'previous-target-compatibility',
    'previous-target-compatibility.json',
  ],
  [
    'previousFinalDisableProvenance',
    'previous-final-disable-provenance',
    'previous-final-disable-provenance.json',
  ],
  [
    'previousApiContractEvidence',
    'previous-api-contract-evidence',
    'previous-api-contract-evidence.json',
  ],
  ['previousPendingEvidence', 'previous-pending-evidence', 'previous-pending-evidence.json'],
  ['previousSmokeEvidence', 'previous-smoke-evidence', 'previous-smoke-evidence.json'],
  [
    'previousReleaseProjectionIndex',
    'previous-release-projection-index',
    'previous-release-projection-index.json',
  ],
]);
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
]);

class Stage7ReleaseReconciliationRecoveryCliError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseReconciliationRecoveryCliError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseReconciliationRecoveryCliError(
    code,
    cause === undefined ? undefined : { cause },
  );
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
const resolveOutput = (filename, code) => {
  if (typeof filename !== 'string' || filename === '') fail(code);
  const absolute = path.resolve(workspaceRoot, filename);
  if (!inside(workspaceRoot, absolute)) fail(code);
  const parent = path.dirname(absolute);
  const missing = [];
  let ancestor = parent;
  while (!existsSync(ancestor)) {
    missing.push(ancestor);
    const next = path.dirname(ancestor);
    if (next === ancestor) fail(code);
    ancestor = next;
  }
  const realAncestor = realpathSync(ancestor);
  if (!inside(workspaceRoot, realAncestor) && realAncestor !== workspaceRoot) fail(code);
  for (const directory of missing.reverse()) {
    try {
      mkdirSync(directory, { mode: 0o700 });
    } catch (error) {
      if (!existsSync(directory)) fail(code, error);
    }
    const metadata = lstatSync(directory);
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) fail(code);
    if (!inside(workspaceRoot, realpathSync(directory))) fail(code);
  }
  if (existsSync(absolute)) {
    const metadata = lstatSync(absolute);
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size > MAX_FILE_BYTES) {
      fail(code);
    }
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
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_OUTPUT_CONFLICT', error);
    }
    if (canonicalJson(existing) !== canonicalJson(value)) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_OUTPUT_CONFLICT');
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
      try {
        const existing = parseStrictJsonSource(readFileSync(absolute), {
          scanForbiddenData: false,
        });
        if (canonicalJson(existing) === canonicalJson(value)) return absolute;
      } catch {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_OUTPUT_CONFLICT', error);
      }
    }
    fail(code, error);
  }
  return absolute;
};
const awsRawJson = (arguments_, code) => {
  try {
    const output = execFileSync(
      process.platform === 'win32' ? 'aws.cmd' : 'aws',
      [...arguments_, '--output', 'json', '--no-cli-pager'],
      {
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'pipe'],
        maxBuffer: MAX_FILE_BYTES,
        timeout: 20 * 60 * 1000,
      },
    );
    if (!Buffer.isBuffer(output) || output.length < 2 || output.length > MAX_FILE_BYTES) {
      fail(code);
    }
    parseStrictJsonSource(output, { scanForbiddenData: false });
    return Buffer.from(output);
  } catch (error) {
    if (error instanceof Stage7ReleaseReconciliationRecoveryCliError) throw error;
    fail(code, error);
  }
};
const parseFlags = (arguments_, required) => {
  if (arguments_.length % 2 !== 0) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_FLAGS_INVALID');
  }
  const permitted = new Set(required);
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
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_FLAGS_INVALID');
    }
    flags[key] = value;
  }
  if (required.some((key) => !Object.hasOwn(flags, key))) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_FLAGS_INVALID');
  }
  return flags;
};
const phaseFrom = (flags) => {
  if (!PHASES.includes(flags.phase)) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_PHASE_INVALID');
  }
  return flags.phase;
};
const conclusionFrom = (flags) => {
  if (!ORIGINAL_CONCLUSIONS.includes(flags['original-job-conclusion'])) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CONCLUSION_INVALID');
  }
  return flags['original-job-conclusion'];
};
const intentFrom = (flags) =>
  validateReleaseReconciliationIntent(
    readJson(flags.intent, 'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_INTENT_INVALID'),
  );
const requestFrom = (flags, intent = undefined) =>
  validateReleaseReconciliationRecoveryRequest(
    readJson(flags.request, 'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_REQUEST_INVALID'),
    intent,
  );
const approvalFrom = (flags, request) =>
  validateReleaseReconciliationRecoveryApproval(
    readJson(flags.approval, 'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_APPROVAL_INVALID'),
    request,
  );
const actorFrom = (flags, intent = undefined) =>
  validateReleaseReconciliationRecoveryActor(
    readJson(flags.actor, 'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ACTOR_INVALID'),
    intent,
  );
const runtimeFromActor = (actor) =>
  createAwsCliReleaseReconciliationRecoveryRuntime({
    candidateSha: actor.originalSource.candidateSha,
    originalRunId: actor.originalSource.runId,
    phase: actor.phase,
    accountId: actor.authority.accountId,
    region: actor.authority.region,
    recoveryRoleArn: actor.authority.recoveryRoleArn,
    controlSha: actor.recoveryRun.controlSha,
  });
const cleanupRuntimeFromActor = (actor, intent) =>
  createAwsCliReleaseReconciliationRecoveryRuntime({
    candidateSha: actor.originalSource.candidateSha,
    originalRunId: actor.originalSource.runId,
    phase: actor.phase,
    accountId: actor.authority.accountId,
    region: actor.authority.region,
    recoveryRoleArn: intent.authority.journalRoleArn,
    capability: 'CLEANUP',
    controlSha: actor.recoveryRun.controlSha,
  });
const samePath = (left, right) =>
  path.normalize(left).toLocaleLowerCase('en-US') ===
  path.normalize(right).toLocaleLowerCase('en-US');
const requireDistinct = (paths) => {
  const normalized = paths.map((value) => path.normalize(path.resolve(workspaceRoot, value)));
  if (new Set(normalized.map((value) => value.toLocaleLowerCase('en-US'))).size !== paths.length) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_PATH_ALIAS_INVALID');
  }
};
const rollbackFlagsFrom = (flags) => {
  const rollbackFlags = Object.fromEntries(
    ROLLBACK_FILE_FLAGS.map((key) => [
      key,
      resolveInput(
        flags[key],
        `E7_RELEASE_RECONCILIATION_RECOVERY_CLI_${key.toUpperCase().replaceAll('-', '_')}_INVALID`,
      ),
    ]),
  );
  rollbackFlags.output = resolveOutput(
    flags['transition-output'],
    'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_TRANSITION_OUTPUT_INVALID',
  );
  return rollbackFlags;
};
const intentSourcesFrom = (flags) =>
  Object.fromEntries(
    INTENT_SOURCE_FLAGS.map(([label, flag, basename]) => {
      const filename = resolveInput(
        flags[flag],
        `E7_RELEASE_RECONCILIATION_RECOVERY_CLI_${flag.toUpperCase().replaceAll('-', '_')}_INVALID`,
      );
      if (path.basename(filename) !== basename) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_INTENT_BASENAME_INVALID');
      }
      return [label, readFileSync(filename)];
    }),
  );

const commands = Object.freeze({
  'extract-preservation-archive': {
    required: ['archive', 'output-directory'],
    execute: async (flags) => {
      const archive = readBytes(
        flags.archive,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_ARCHIVE_INVALID',
      );
      let entries;
      try {
        entries = readReleaseSuccessorZipEntries(archive);
      } catch (error) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_ARCHIVE_INVALID', error);
      }
      const expected = [...STAGE7_RELEASE_RECONCILIATION_RECOVERY_CONTRACT.preservationFiles];
      if (
        entries.size !== expected.length ||
        [...entries.keys()].toSorted().join('\0') !== expected.toSorted().join('\0')
      ) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_ENTRY_SET_INVALID');
      }
      const directory = resolveOutput(
        flags['output-directory'],
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_OUTPUT_INVALID',
      );
      try {
        mkdirSync(directory, { mode: 0o700 });
        for (const name of expected) {
          if (name.includes('/') || name.includes('\\')) {
            fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_ENTRY_SET_INVALID');
          }
          const target = path.join(directory, name);
          writeFileSync(target, entries.get(name), { flag: 'wx', mode: 0o600 });
          chmodSync(target, 0o600);
        }
      } catch (error) {
        rmSync(directory, { recursive: true, force: true });
        if (error instanceof Stage7ReleaseReconciliationRecoveryCliError) throw error;
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_OUTPUT_INVALID', error);
      }
      return {
        decision: 'PRESERVATION_ARCHIVE_EXTRACTED_EXACTLY',
        entryCount: entries.size,
        mutationsPerformed: 0,
      };
    },
  },
  'capture-base-role-authority': {
    required: ['config', 'output', 'role-audit-output'],
    execute: async (flags) => {
      const config = parseStrictJsonSource(
        readBytes(flags.config, 'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_BASE_CONFIG_INVALID'),
        { scanForbiddenData: false },
      );
      try {
        validateStage7Config(config, { now: new Date(config?.window?.startsAtUtc) });
      } catch (error) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_BASE_CONFIG_INVALID', error);
      }
      const recoveryRoleArn = process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN;
      const permissionsBoundaryArn =
        process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN;
      const journalCleanupRoleArn = process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN;
      if (
        process.env.AWS_REGION !== config.aws.region ||
        process.env.AWS_DEFAULT_REGION !== config.aws.region ||
        process.env.STAGE7_AWS_ACCOUNT_ID !== config.aws.accountId ||
        Object.values(config.aws.roles).includes(recoveryRoleArn) ||
        typeof journalCleanupRoleArn !== 'string' ||
        journalCleanupRoleArn.length < 20 ||
        recoveryRoleArn === journalCleanupRoleArn
      ) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_BASE_CONTEXT_INVALID');
      }
      const basePolicy = createReleaseReconciliationRecoveryBasePolicy({
        accountId: config.aws.accountId,
        awsRegion: config.aws.region,
        recoveryRoleArn,
        permissionsBoundaryArn,
      });
      const captured = captureReleaseReconciliationRecoveryRoleEffectivePermissions({
        expectedRoleArn: recoveryRoleArn,
        expectedPermissionsBoundaryArn: permissionsBoundaryArn,
        awsRegion: config.aws.region,
        basePolicy,
        callAwsRaw: (arguments_) =>
          awsRawJson(
            arguments_,
            'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_BASE_ROLE_AUTHORITY_AWS_FAILED',
          ),
      });
      writeJsonImmutable(
        flags.output,
        captured.value,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_BASE_ROLE_AUTHORITY_OUTPUT_INVALID',
      );
      writeJsonImmutable(
        flags['role-audit-output'],
        parseStrictJsonSource(captured.roleAuditBytes, { scanForbiddenData: false }),
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_BASE_ROLE_AUDIT_OUTPUT_INVALID',
      );
      return {
        decision: 'FROZEN_RECOVERY_ROLE_BASE_AUTHORITY_CAPTURED',
        basePolicySha256: captured.value.basePolicySha256,
        effectivePermissionsSha256: captured.value.effectivePermissionsSha256,
        externalRequests: captured.sourceBindingCount,
        mutationsPerformed: 0,
      };
    },
  },
  'capture-role-authority': {
    required: ['request', 'output', 'role-audit-output'],
    execute: async (flags) => {
      const request = requestFrom(flags);
      const captured = captureReleaseReconciliationRecoveryRoleEffectivePermissions({
        expectedRoleArn: request.authority.recoveryRoleArn,
        expectedPermissionsBoundaryArn: request.recoveryRoleAuthority.permissionsBoundaryArn,
        awsRegion: request.authority.region,
        basePolicy: request.recoveryRoleAuthority.basePolicy,
        callAwsRaw: (arguments_) =>
          awsRawJson(
            arguments_,
            'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ROLE_AUTHORITY_AWS_FAILED',
          ),
      });
      writeJsonImmutable(
        flags.output,
        captured.value,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ROLE_AUTHORITY_OUTPUT_INVALID',
      );
      writeJsonImmutable(
        flags['role-audit-output'],
        parseStrictJsonSource(captured.roleAuditBytes, { scanForbiddenData: false }),
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ROLE_AUDIT_OUTPUT_INVALID',
      );
      return {
        decision: 'LIVE_RECOVERY_ROLE_AUTHORITY_CAPTURED',
        effectivePermissionsSha256: captured.value.effectivePermissionsSha256,
        externalRequests: captured.sourceBindingCount,
        mutationsPerformed: 0,
      };
    },
  },
  'verify-live-role-authority': {
    required: ['request', 'actor', 'live-recovery-role-effective-permissions'],
    execute: async (flags) => {
      const request = requestFrom(flags);
      const actor = actorFrom(flags);
      const binding = compareReleaseReconciliationRecoveryRoleEffectivePermissions({
        request,
        actor,
        liveSource: readBytes(
          flags['live-recovery-role-effective-permissions'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_LIVE_ROLE_AUTHORITY_INVALID',
        ),
      });
      return {
        decision: 'LIVE_RECOVERY_ROLE_AUTHORITY_UNCHANGED',
        effectivePermissionsSha256: binding.effectivePermissionsSha256,
        mutationsPerformed: 0,
      };
    },
  },
  'rebuild-intent': {
    required: [
      'original-run-id',
      'candidate-sha',
      ...INTENT_SOURCE_FLAGS.map(([, flag]) => flag),
      'output',
    ],
    execute: async (flags) => {
      const intent = createReleaseReconciliationIntentFromSources({
        sources: intentSourcesFrom(flags),
        githubIdentity: {
          repository: 'ivanmonsalve0404/async-checkout-demo',
          workflowRef:
            'ivanmonsalve0404/async-checkout-demo/.github/workflows/release.yml@refs/heads/master',
          ref: 'refs/heads/master',
          runId: flags['original-run-id'],
          runAttempt: 1,
          candidateSha: flags['candidate-sha'],
        },
      });
      writeJsonImmutable(
        flags.output,
        intent,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_INTENT_OUTPUT_INVALID',
      );
      return { decision: 'ORIGINAL_INTENT_REBUILT', intentSha256: intent.intentSha256 };
    },
  },
  'create-request': {
    required: [
      'intent',
      'config',
      'aws-auth',
      'candidate-manifest',
      'original-run',
      'original-jobs',
      'recovery-role-effective-permissions',
      'candidate-record',
      'previous-manifest',
      'phase',
      'original-job-conclusion',
      'output',
    ],
    execute: async (flags) => {
      const request = createReleaseReconciliationRecoveryRequest({
        intent: intentFrom(flags),
        configSource: readBytes(
          flags.config,
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CONFIG_INVALID',
        ),
        awsAuthSource: readBytes(
          flags['aws-auth'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_AWS_AUTH_INVALID',
        ),
        candidateManifestSource: readBytes(
          flags['candidate-manifest'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CANDIDATE_MANIFEST_INVALID',
        ),
        originalRunSource: readBytes(
          flags['original-run'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ORIGINAL_RUN_INVALID',
        ),
        originalJobsSource: readBytes(
          flags['original-jobs'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ORIGINAL_JOBS_INVALID',
        ),
        recoveryRoleEffectivePermissionsSource: readBytes(
          flags['recovery-role-effective-permissions'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ROLE_AUTHORITY_INVALID',
        ),
        permissionsBoundaryArn:
          process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN,
        candidateRecordSource: readBytes(
          flags['candidate-record'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CANDIDATE_RECORD_INVALID',
        ),
        previousManifestSource: readBytes(
          flags['previous-manifest'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_PREVIOUS_MANIFEST_INVALID',
        ),
        recoveryRoleArn: process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN,
        environmentVariables: process.env,
        phase: phaseFrom(flags),
        originalJobConclusion: conclusionFrom(flags),
        requestedAtUtc: new Date().toISOString(),
      });
      writeJsonImmutable(
        flags.output,
        request,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_REQUEST_OUTPUT_INVALID',
      );
      return { decision: 'PROTECTED_APPROVAL_REQUIRED', requestSha256: request.requestSha256 };
    },
  },
  'capture-approval': {
    required: ['request', 'review-response', 'output'],
    execute: async (flags) => {
      const request = requestFrom(flags);
      const approval = createReleaseReconciliationRecoveryApproval({
        request,
        reviewResponseSource: readBytes(
          flags['review-response'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_REVIEW_RESPONSE_INVALID',
        ),
        capturedAtUtc: new Date().toISOString(),
      });
      writeJsonImmutable(
        flags.output,
        approval,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_APPROVAL_OUTPUT_INVALID',
      );
      return { decision: 'RECOVERY_APPROVED', approvalSha256: approval.approvalSha256 };
    },
  },
  'create-actor': {
    required: [
      'intent',
      'request',
      'approval',
      'live-recovery-role-effective-permissions',
      'output',
    ],
    execute: async (flags) => {
      const intent = intentFrom(flags);
      const request = requestFrom(flags, intent);
      const approval = approvalFrom(flags, request);
      const actor = createReleaseReconciliationRecoveryActor({
        intent,
        request,
        approval,
        liveRecoveryRoleEffectivePermissionsSource: readBytes(
          flags['live-recovery-role-effective-permissions'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_LIVE_ROLE_AUTHORITY_INVALID',
        ),
        recoveryRoleArn: process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN,
        environmentVariables: process.env,
        createdAtUtc: new Date().toISOString(),
        phase: request.phase,
        originalJobConclusion: request.originalJobConclusion,
      });
      writeJsonImmutable(
        flags.output,
        actor,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ACTOR_OUTPUT_INVALID',
      );
      return { decision: 'RECOVERY_ACTOR_CREATED', actorSha256: actor.actorSha256 };
    },
  },
  inspect: {
    required: [
      'request',
      'approval',
      'live-recovery-role-effective-permissions',
      'actor-output',
      'intent-output',
      'owner-output',
      'probe-output',
    ],
    execute: async (flags) => {
      requireDistinct([
        flags.request,
        flags.approval,
        flags['actor-output'],
        flags['intent-output'],
        flags['owner-output'],
        flags['probe-output'],
      ]);
      const request = requestFrom(flags);
      const approval = approvalFrom(flags, request);
      const actorSeed = {
        originalSource: request.originalSource,
        phase: request.phase,
        authority: request.authority,
      };
      const result = await inspectReleaseReconciliationRecovery({
        runtime: runtimeFromActor(actorSeed),
        request,
        approval,
        liveRecoveryRoleEffectivePermissionsSource: readBytes(
          flags['live-recovery-role-effective-permissions'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_LIVE_ROLE_AUTHORITY_INVALID',
        ),
        recoveryRoleArn: request.authority.recoveryRoleArn,
        originalJobConclusion: request.originalJobConclusion,
        phase: request.phase,
      });
      writeJsonImmutable(
        flags['actor-output'],
        result.actor,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ACTOR_OUTPUT_INVALID',
      );
      writeJsonImmutable(
        flags['intent-output'],
        result.intent,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_INTENT_OUTPUT_INVALID',
      );
      writeJsonImmutable(
        flags['owner-output'],
        result.owner,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_OWNER_OUTPUT_INVALID',
      );
      writeJsonImmutable(
        flags['probe-output'],
        result.probe,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_PROBE_OUTPUT_INVALID',
      );
      return { decision: result.decision };
    },
  },
  'resume-terminal': {
    required: ['intent', 'actor', 'receipt-output', 'outcome-output'],
    execute: async (flags) => {
      requireDistinct([
        flags.intent,
        flags.actor,
        flags['receipt-output'],
        flags['outcome-output'],
      ]);
      const intent = intentFrom(flags);
      const actor = actorFrom(flags, intent);
      const result = await resumeReleaseReconciliationRecovery({
        runtime: runtimeFromActor(actor),
        actor,
        intent,
      });
      writeJsonImmutable(
        flags['receipt-output'],
        result.receipt,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_RECEIPT_OUTPUT_INVALID',
      );
      writeJsonImmutable(
        flags['outcome-output'],
        result.outcome,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_OUTCOME_OUTPUT_INVALID',
      );
      return { decision: 'TERMINAL_RESUMED' };
    },
  },
  'converge-forward': {
    required: [
      'intent',
      'actor',
      ...ROLLBACK_FILE_FLAGS,
      'transition-output',
      'convergence-output',
    ],
    execute: async (flags) => {
      const intent = intentFrom(flags);
      const actor = actorFrom(flags, intent);
      const rollbackFlags = rollbackFlagsFrom(flags);
      const convergenceOutput = resolveOutput(
        flags['convergence-output'],
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CONVERGENCE_OUTPUT_INVALID',
      );
      if (
        samePath(convergenceOutput, rollbackFlags.output) ||
        ROLLBACK_FILE_FLAGS.some(
          (key) =>
            samePath(convergenceOutput, rollbackFlags[key]) ||
            samePath(rollbackFlags.output, rollbackFlags[key]),
        )
      ) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_PATH_ALIAS_INVALID');
      }
      const transitionExists = existsSync(rollbackFlags.output);
      const convergenceExists = existsSync(convergenceOutput);
      if (convergenceExists && !transitionExists) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CONVERGENCE_PARTIAL_INVALID');
      }
      const runtime = runtimeFromActor(actor);
      let convergence;
      if (transitionExists) {
        convergence = await recoverVersionedReleaseRuntimeConvergenceCheckpoint({
          phase: actor.phase,
          intent,
          candidateRecordSource: readFileSync(rollbackFlags['candidate-record']),
          transitionSource: readFileSync(rollbackFlags.output),
          ...(convergenceExists
            ? {
                expectedConvergence: validateReleaseRuntimeConvergence(
                  readJson(
                    convergenceOutput,
                    'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CONVERGENCE_INVALID',
                  ),
                ),
              }
            : {}),
          store: runtime.store,
        });
      } else {
        const operations = await import('./aws-operations.mjs');
        if (typeof operations.executeVersionedRollbackRecovery !== 'function') {
          fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_FORWARD_ADAPTER_UNAVAILABLE');
        }
        convergence = await convergeReleaseReconciliationRecoveryForward({
          runtime,
          actor,
          intent,
          rollbackFlags,
          executeVersionedRollbackRecovery: operations.executeVersionedRollbackRecovery,
        });
      }
      writeJsonImmutable(
        convergenceOutput,
        convergence,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CONVERGENCE_OUTPUT_INVALID',
      );
      return {
        decision: transitionExists
          ? convergenceExists
            ? 'CONVERGENCE_CHECKPOINT_REUSED'
            : 'CONVERGENCE_CHECKPOINT_RECOVERED'
          : 'CANDIDATE_N_CONVERGED',
      };
    },
  },
  'finalize-forward': {
    required: [
      'intent',
      'actor',
      'convergence',
      'drift-evidence',
      'smoke-evidence',
      'receipt-output',
      'outcome-output',
    ],
    execute: async (flags) => {
      requireDistinct([
        flags.intent,
        flags.actor,
        flags.convergence,
        flags['drift-evidence'],
        flags['smoke-evidence'],
        flags['receipt-output'],
        flags['outcome-output'],
      ]);
      const intent = intentFrom(flags);
      const actor = actorFrom(flags, intent);
      const convergence = validateReleaseRuntimeConvergence(
        readJson(flags.convergence, 'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CONVERGENCE_INVALID'),
      );
      const result = await finalizeReleaseReconciliationRecoveryForward({
        runtime: runtimeFromActor(actor),
        actor,
        convergence,
        driftEvidenceSource: readBytes(
          flags['drift-evidence'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_DRIFT_INVALID',
        ),
        smokeEvidenceSource: readBytes(
          flags['smoke-evidence'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_SMOKE_INVALID',
        ),
      });
      writeJsonImmutable(
        flags['receipt-output'],
        result.receipt,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_RECEIPT_OUTPUT_INVALID',
      );
      writeJsonImmutable(
        flags['outcome-output'],
        result.outcome,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_OUTCOME_OUTPUT_INVALID',
      );
      return { decision: 'FORWARD_CANDIDATE_N_FINALIZED' };
    },
  },
  snapshot: {
    required: ['outcome', 'output'],
    execute: async (flags) => {
      const outcome = validateReleaseReconciliationRecoveryOutcome(
        readJson(flags.outcome, 'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_OUTCOME_INVALID'),
      );
      const snapshot = await snapshotReleaseReconciliationRecovery({
        runtime: runtimeFromActor(outcome.actor),
        outcome,
      });
      writeJsonImmutable(
        flags.output,
        snapshot,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_SNAPSHOT_OUTPUT_INVALID',
      );
      return { decision: 'RAW_JOURNAL_SNAPSHOT_CREATED' };
    },
  },
  'create-preservation-index': {
    required: [
      'intent',
      'receipt',
      'outcome',
      'snapshot',
      'recovery-role-effective-permissions',
      'output',
    ],
    execute: async (flags) => {
      requireDistinct([
        flags.intent,
        flags.receipt,
        flags.outcome,
        flags.snapshot,
        flags['recovery-role-effective-permissions'],
        flags.output,
      ]);
      const index = createReleaseReconciliationRecoveryPreservationIndex({
        sources: {
          intent: readBytes(flags.intent, 'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_INTENT_INVALID'),
          receipt: readBytes(
            flags.receipt,
            'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_RECEIPT_INVALID',
          ),
          outcome: readBytes(
            flags.outcome,
            'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_OUTCOME_INVALID',
          ),
          snapshot: readBytes(
            flags.snapshot,
            'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_SNAPSHOT_INVALID',
          ),
          recoveryRoleAuthority: readBytes(
            flags['recovery-role-effective-permissions'],
            'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ROLE_AUTHORITY_INVALID',
          ),
        },
        createdAtUtc: new Date().toISOString(),
      });
      writeJsonImmutable(
        flags.output,
        index,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_PRESERVATION_INDEX_OUTPUT_INVALID',
      );
      return { decision: 'PRESERVATION_INDEX_CREATED', artifactName: index.artifactName };
    },
  },
  'create-artifact-binding': {
    required: ['preservation-index', 'metadata', 'archive', 'expected-run-id', 'output'],
    execute: async (flags) => {
      const preservationIndex = validateReleaseReconciliationRecoveryPreservationIndex(
        readJson(
          flags['preservation-index'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_PRESERVATION_INDEX_INVALID',
        ),
      );
      const binding = createReleaseReconciliationRecoveryArtifactBinding({
        preservationIndex,
        metadataSource: readBytes(
          flags.metadata,
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_METADATA_INVALID',
        ),
        archiveSource: readBytes(
          flags.archive,
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_ARCHIVE_INVALID',
        ),
        expectedRunId: flags['expected-run-id'],
        capturedAtUtc: new Date().toISOString(),
      });
      writeJsonImmutable(
        flags.output,
        binding,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_BINDING_OUTPUT_INVALID',
      );
      return { decision: 'PRESERVATION_ARTIFACT_BOUND', artifactId: binding.id };
    },
  },
  cleanup: {
    required: [
      'actor',
      'intent',
      'receipt',
      'outcome',
      'snapshot',
      'recovery-role-effective-permissions',
      'preservation-index',
      'preservation-artifact-binding',
      'frozen-cleanup-role-effective-permissions',
      'live-cleanup-role-effective-permissions',
      'output',
    ],
    execute: async (flags) => {
      const intentSource = readBytes(
        flags.intent,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_INTENT_INVALID',
      );
      const receiptSource = readBytes(
        flags.receipt,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_RECEIPT_INVALID',
      );
      const outcomeSource = readBytes(
        flags.outcome,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_OUTCOME_INVALID',
      );
      const snapshotSource = readBytes(
        flags.snapshot,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_SNAPSHOT_INVALID',
      );
      const recoveryRoleAuthoritySource = readBytes(
        flags['recovery-role-effective-permissions'],
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ROLE_AUTHORITY_INVALID',
      );
      const preservationIndex = validateReleaseReconciliationRecoveryPreservationIndex(
        readJson(
          flags['preservation-index'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_PRESERVATION_INDEX_INVALID',
        ),
      );
      const preserved = validateReleaseReconciliationRecoveryPreservationSources({
        index: preservationIndex,
        sources: {
          intent: intentSource,
          receipt: receiptSource,
          outcome: outcomeSource,
          snapshot: snapshotSource,
          recoveryRoleAuthority: recoveryRoleAuthoritySource,
        },
      });
      const actor = actorFrom(flags, preserved.intent);
      const cleanupRoleArn = preserved.intent.authority.journalRoleArn;
      const cleanupBoundaryArn =
        process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN;
      const cleanupRoleComparison = compareReleaseJournalRoleEffectivePermissions({
        frozenSource: readBytes(
          flags['frozen-cleanup-role-effective-permissions'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_FROZEN_CLEANUP_ROLE_INVALID',
        ),
        liveSource: readBytes(
          flags['live-cleanup-role-effective-permissions'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_LIVE_CLEANUP_ROLE_INVALID',
        ),
        expectedRoleArn: cleanupRoleArn,
        expectedPermissionsBoundaryArn: cleanupBoundaryArn,
      });
      const cleanupRoleAuthority = {
        roleArn: cleanupRoleArn,
        permissionsBoundaryArn: cleanupBoundaryArn,
        ...cleanupRoleComparison,
      };
      const preservationArtifact = validateReleaseReconciliationRecoveryArtifactBinding(
        readJson(
          flags['preservation-artifact-binding'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_ARTIFACT_BINDING_INVALID',
        ),
        preservationIndex.artifactName,
      );
      const closure = await cleanupReleaseReconciliationRecovery({
        runtime: cleanupRuntimeFromActor(actor, preserved.intent),
        cleanupActor: actor,
        outcome: preserved.outcome,
        snapshot: preserved.snapshot,
        preservationIndex,
        preservationArtifact,
        cleanupRoleAuthority,
      });
      writeJsonImmutable(
        flags.output,
        closure,
        'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_CLOSURE_OUTPUT_INVALID',
      );
      return { decision: 'PRESERVED_AND_CLEANED_RESIDUAL_ZERO' };
    },
  },
});

const main = async () => {
  const [commandName, ...arguments_] = process.argv.slice(2);
  const command = commands[commandName];
  if (command === undefined) fail('E7_RELEASE_RECONCILIATION_RECOVERY_CLI_COMMAND_INVALID');
  const flags = parseFlags(arguments_, command.required);
  const result = await command.execute(flags);
  process.stdout.write(`${JSON.stringify({ status: 'PASS', command: commandName, ...result })}\n`);
};

try {
  await main();
} catch (error) {
  const code =
    typeof error?.code === 'string'
      ? error.code
      : error instanceof Stage7ReleaseReconciliationRecoveryCliError
        ? error.message
        : 'E7_RELEASE_RECONCILIATION_RECOVERY_CLI_FAILED';
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
}
