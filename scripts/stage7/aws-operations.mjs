/* global structuredClone */

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmdirSync,
  rmSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { setTimeout as delay } from 'node:timers/promises';

import {
  assertSanitizedArtifactText,
  writeSanitizedJsonAtomic,
  writeSanitizedTextAtomic,
} from '../stage6/lib/artifact-sanitizer.mjs';
import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import {
  Stage7Error,
  STAGE7_PROVIDER_EGRESS_CAPABILITY,
  createStage7CandidateRollbackRecord,
  createStage7PreviousReleaseManifest,
  createStage7VersionedRollbackPlan,
  createStage7VersionedRollbackRehearsal,
  createStage7VersionedRollbackTransition,
  canonicalJson,
  hashArtifactPath,
  objectSha256,
  readStrictJsonFile,
  validateStage7ActivationCheckpoint,
  validateStage7CandidateRollbackRecord,
  validateFreezeManifest,
  validateStage7DriftCheckpoint,
  validateStage7InitialRollbackCheckpoint,
  validateStage7InitialRollbackPublicationTransition,
  validateStage7PrereleaseCleanupCheckpoint,
  validateStage7PreviousReleaseForTarget,
  validateStage7PreviousReleaseHandoff,
  validateStage7PreviousReleaseManifest,
  validateStage7VersionedRollbackCheckpoint,
  validateStage7VersionedRollbackRehearsal,
  validateStage7VersionedRollbackTransition,
  validateStage7Config,
  workspaceRoot,
} from './core.mjs';
import { validateExternalAuthorizations } from './control.mjs';
import {
  validateBaselineFinalDisableProvenance,
  validateBaselineSourceProvenance,
  validateTargetCompatibilityEvidence,
} from './baseline-establishment.mjs';
import {
  IamEffectivePermissionsError,
  validateIamEffectivePermissionsEvidence,
} from './iam-effective-permissions.mjs';
import {
  Stage7ReleaseSuccessorIamAuthorityError,
  createReleaseSuccessorIamAuthoritySelfTestFixture,
  parseReleaseJournalRoleEffectivePermissionsSource,
  validateReleaseJournalRoleEffectivePermissionsBinding,
} from './release-successor-iam-authority.mjs';
import {
  runGuardedIncompleteReleaseReconciliationMutation,
  runGuardedReleaseReconciliationMutation,
  runGuardedVersionedRollbackCheckMutation,
} from './release-successor-finalization.mjs';
import {
  RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT,
  RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT,
} from './release-successor-parameter-roots.mjs';
import {
  prereleaseApprovedDeploymentCheckpointSha256,
  revalidatePrereleaseWatchdogLiveAuthority,
  validatePrereleaseDeploymentCheckpoint,
  validatePrereleaseLiveSafetyRecheck,
  validatePrereleaseSafetyReadinessFromFiles,
} from './prerelease-safety-readiness.mjs';
import { PrereleaseSafetyContractError } from './prerelease-safety-contract.mjs';
import { validatePrereleaseApiOrigin } from './cloudfront-access.mjs';
import { inspectReleaseStackResourceAllowlist } from './cloud-assembly-resource-contract.mjs';
import {
  PREVIOUS_RELEASE_PROJECTION_FILENAMES,
  validatePreviousReleaseProjection,
} from './previous-release-projection.mjs';
import {
  RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS,
  Stage7ReleaseReconciliationRecoveryError,
  createReleaseReconciliationRecoverySessionPolicy,
  parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource,
  validateReleaseReconciliationRecoveryActor,
  validateReleaseReconciliationRecoverySessionPolicySubset,
} from './release-reconciliation-recovery.mjs';
import { validateReleaseReconciliationIntent } from './release-reconciliation.mjs';
import { RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS } from './release-reconciliation-authority.mjs';
import {
  RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS,
  RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
  RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
} from './release-successor-rollback-authority.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const AWS_CLI_VERSION_OUTPUT = /(?:^|\s)aws-cli\/([0-9]+\.[0-9]+\.[0-9]+)(?=\s|$)/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-([0-9a-f]{7})$/u;
const CLOUDFORMATION_CLIENT_REQUEST_TOKEN = /^[A-Za-z0-9][-A-Za-z0-9]{0,127}$/u;
const STACK_NAME =
  /^checkout-(assessment-release|assessment-prerelease-[a-z0-9][a-z0-9-]{0,39})-(data|api|observability|web)$/u;
const AWS_REGION =
  /^(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9]$/u;
const VERSION = /^(?:[1-9][0-9]*)$/u;
const FUNCTION_NAME = /^[A-Za-z0-9-_]{1,64}$/u;
const ALIAS_NAME = /^[A-Za-z0-9-_]{1,128}$/u;
const SCHEDULE_NAME = /^[0-9A-Za-z_.-]{1,64}$/u;
const HTTP_API_ID = /^[a-z0-9]{10}$/u;
const API_MAPPING_ID = /^[a-z0-9]{1,64}$/u;
const DRIFT_DETECTION_ID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const CLOUDFRONT_DISTRIBUTION_ID = /^[A-Z0-9]{8,64}$/u;
const BUCKET_NAME = /^(?=.{3,63}$)(?![0-9]+(?:\.[0-9]+){3}$)[a-z0-9][a-z0-9.-]*[a-z0-9]$/u;
const DYNAMODB_TABLE_NAME = /^[A-Za-z0-9_.-]{3,255}$/u;
const VERSION_ID = /^[A-Za-z0-9._~+/=-]{1,1024}$/u;
const SAFE_OBJECT_KEY =
  /^(?:index\.html|public-config\.json|product-placeholder\.svg|legal\/[A-Za-z0-9._/-]{1,512})$/u;
const SAFE_DEPLOYED_WEB_KEY =
  /^(?=.{1,1024}$)(?!\/)(?!.*(?:^|\/)\.\.?(?:\/|$))[A-Za-z0-9][A-Za-z0-9._/-]*$/u;
const STACK_SUFFIXES = ['data', 'api', 'observability', 'web'];
const MUTABLE_WEB_KEYS = new Set(['index.html', 'public-config.json', 'product-placeholder.svg']);
const VERSIONED_ROLLBACK_WEB_KEYS = ['index.html', 'public-config.json'];
const VERSIONED_ROLLBACK_INVALIDATION_PATHS = ['/index.html', '/public-config.json'];
const PENDING_INDEX_NAME = 'GSI2-PendingAge';
const PENDING_INDEX_PARTITION = 'PAYMENT#PENDING';
const DEFAULT_OUTPUT_ROOT = 'output/evidence/runtime';
const DEFAULT_INTERNAL_ROOT = 'output/evidence/runtime/.private-stage7';
const COMMAND_TIMEOUT_MS = 20 * 60 * 1000;
const MAX_COMMAND_OUTPUT_BYTES = 32 * 1024 * 1024;
const WORKSPACE_TOOL_CONTRACTS = Object.freeze({
  cdk: {
    relativePath: 'infra/node_modules/aws-cdk/bin/cdk',
    packageName: 'aws-cdk',
    packageVersion: '2.1136.0',
    sha256: '99c234c2094e6e0c1087cdf54aa5c8879b67bf309cdab7433478c3daf5998f79',
  },
  tsx: {
    relativePath: 'node_modules/tsx/dist/cli.mjs',
    packageName: 'tsx',
    packageVersion: '4.23.12',
    sha256: 'fd00586b96028510c228365a4eeb1f163dac5245f1d0e40649969cf9560d376b',
  },
});
const RELEASE_RECONCILIATION_RECOVERY_WORKFLOW =
  'ivanmonsalve0404/async-checkout-demo/.github/workflows/stage7-release-reconciliation-recovery.yml@refs/heads/master';
const RELEASE_RECONCILIATION_RECOVERY_ENVIRONMENT = 'assessment-release-reconciliation-recovery';
const RELEASE_RECONCILIATION_RECOVERY_FILE_BINDINGS = Object.freeze([
  ['manifest', 'candidateManifest'],
  ['previous-manifest', 'previousReleaseManifest'],
  ['previous-api-contract-evidence', 'previousApiContractEvidence'],
  ['previous-pending-evidence', 'previousPendingEvidence'],
  ['previous-smoke-evidence', 'previousSmokeEvidence'],
  ['candidate-record', 'candidateRecord'],
  ['approval', 'approval'],
  ['approved-plan', 'approvedDiff'],
  ['deployment-evidence', 'webDeployment'],
  ['aws-auth', 'awsAuth'],
  ['journal-role-effective-permissions', 'journalRoleEffectivePermissions'],
]);
const RELEASE_RECONCILIATION_RECOVERY_DRIFT_FILE_BINDINGS = Object.freeze([
  ['manifest', 'candidateManifest'],
  ['previous-manifest', 'previousReleaseManifest'],
  ['previous-api-contract-evidence', 'previousApiContractEvidence'],
  ['previous-pending-evidence', 'previousPendingEvidence'],
  ['previous-smoke-evidence', 'previousSmokeEvidence'],
]);
const RELEASE_RECONCILIATION_RECOVERY_MAX_GUARD_PARAMETERS = 223;
const RELEASE_RECONCILIATION_RECOVERY_MAX_GUARD_PAGES = Math.ceil(
  RELEASE_RECONCILIATION_RECOVERY_MAX_GUARD_PARAMETERS / 10,
);
const RELEASE_SUCCESSOR_RELEASE_WORKFLOW =
  'ivanmonsalve0404/async-checkout-demo/.github/workflows/release.yml@refs/heads/master';
const RELEASE_SUCCESSOR_ROLLBACK_WORKFLOW =
  'ivanmonsalve0404/async-checkout-demo/.github/workflows/stage7-rollback-resilience.yml@refs/heads/master';
const RELEASE_SUCCESSOR_GUARD_MODES = Object.freeze([
  'ROLLBACK_CHECK',
  'RECONCILIATION',
  'INCOMPLETE_RECONCILIATION',
]);
const RELEASE_SUCCESSOR_INTENT_SOURCE_FLAG_BINDINGS =
  RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS;

export class Stage7AwsError extends Stage7Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7AwsError';
  }
}

const fail = (code) => {
  throw new Stage7AwsError(code);
};

export const parseAwsFlags = (arguments_) => {
  const flags = {};
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (!argument?.startsWith('--') || argument.length < 3 || argument.includes('=')) {
      fail('E7_AWS_CLI_ARGUMENT_INVALID');
    }
    const key = argument.slice(2);
    if (Object.hasOwn(flags, key)) fail('E7_AWS_CLI_ARGUMENT_DUPLICATE');
    const next = arguments_[index + 1];
    if (next !== undefined && !next.startsWith('--')) {
      flags[key] = next;
      index += 1;
    } else {
      flags[key] = true;
    }
  }
  return flags;
};

export const assertAwsFlagSet = (flags, { required = [], allowed = [] }) => {
  const permitted = new Set([...required, ...allowed]);
  const keys = Object.keys(flags);
  if (
    required.some((key) => !Object.hasOwn(flags, key)) ||
    keys.some((key) => !permitted.has(key))
  ) {
    fail('E7_AWS_CLI_ARGUMENT_SET_INVALID');
  }
};

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const jsonSha256 = (value) => sha256(JSON.stringify(value));
const fileSha256 = (filename) =>
  sha256(readFileSync(resolveInsideWorkspace(filename, 'E7_FILE_DIGEST_INPUT_INVALID')));
const EMERGENCY_NO_ACTION_SOURCE_FLAGS = Object.freeze([
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
]);

const jsonSourceBinding = (label, filename) => {
  const absolute = resolveInsideWorkspace(filename, 'E7_EMERGENCY_RECOVERY_SOURCE_MISSING', {
    allowDirectory: false,
  });
  const source = readFileSync(absolute);
  let value;
  try {
    value = parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch {
    fail('E7_EMERGENCY_RECOVERY_SOURCE_INVALID');
  }
  return {
    label,
    basename: path.basename(absolute),
    rawSha256: sha256(source),
    canonicalSha256: objectSha256(value),
    bytes: source.byteLength,
  };
};

const emergencyNoActionSourceBindings = (flags) =>
  EMERGENCY_NO_ACTION_SOURCE_FLAGS.map((label) => jsonSourceBinding(label, flags[label]));
const utc = (now) => now.toISOString();
const INITIAL_ROLLBACK_EVENT_CLOCK_SKEW_MS = 60_000;
const canonicalUtc = (value) => {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    return false;
  }
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
};
const expectedStacks = (environment) =>
  STACK_SUFFIXES.map((suffix) => `checkout-${environment}-${suffix}`);

const resolveInsideWorkspace = (
  candidate,
  code,
  { mustExist = true, allowDirectory = true } = {},
) => {
  if (typeof candidate !== 'string' || candidate.trim() === '') fail(code);
  const absolute = path.resolve(workspaceRoot, candidate);
  const relative = path.relative(workspaceRoot, absolute);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    fail(code);
  }
  if (mustExist) {
    if (!existsSync(absolute) || lstatSync(absolute).isSymbolicLink()) fail(code);
    if (!allowDirectory && !statSync(absolute).isFile()) fail(code);
  }
  return absolute;
};

const readReleaseSuccessorGuardSource = (flags, name, code) => {
  const filename = flags?.[name];
  if (typeof filename !== 'string' || filename === '') fail(code);
  const absolute = resolveInsideWorkspace(filename, code, {
    allowDirectory: false,
  });
  const size = statSync(absolute).size;
  if (size < 2 || size > MAX_COMMAND_OUTPUT_BYTES) fail(code);
  return readFileSync(absolute);
};

const parseReleaseSuccessorGuardJson = (source, code) => {
  try {
    const value = parseStrictJsonSource(source, { scanForbiddenData: false });
    if (!object(value)) fail(code);
    return value;
  } catch (error) {
    if (error instanceof Stage7AwsError) throw error;
    fail(code);
  }
};

const assertReleaseSuccessorGuardSourceAliases = ({ flags, environmentVariables }) => {
  const aliases = [
    ['candidate-manifest', 'manifest'],
    ['approved-diff', 'approved-plan'],
    ['web-deployment', 'deployment-evidence'],
    ['previous-release-manifest', 'previous-manifest'],
  ];
  for (const [intentFlag, operationFlag] of aliases) {
    if (
      !readReleaseSuccessorGuardSource(
        flags,
        intentFlag,
        'E7_RELEASE_SUCCESSOR_GUARD_SOURCE_INVALID',
      ).equals(
        readReleaseSuccessorGuardSource(
          flags,
          operationFlag,
          'E7_RELEASE_SUCCESSOR_GUARD_SOURCE_INVALID',
        ),
      )
    ) {
      fail('E7_RELEASE_SUCCESSOR_GUARD_SOURCE_ALIAS_MISMATCH');
    }
  }
  const configPath = environmentVariables?.STAGE7_CONFIG;
  let configSource;
  try {
    if (typeof configPath !== 'string' || configPath === '') {
      configSource = null;
    } else {
      const metadata = lstatSync(configPath);
      if (
        !metadata.isFile() ||
        metadata.isSymbolicLink() ||
        metadata.size < 2 ||
        metadata.size > MAX_COMMAND_OUTPUT_BYTES
      ) {
        fail('E7_RELEASE_SUCCESSOR_GUARD_CONFIG_SOURCE_INVALID');
      }
      configSource = readFileSync(configPath);
    }
  } catch {
    fail('E7_RELEASE_SUCCESSOR_GUARD_CONFIG_SOURCE_INVALID');
  }
  if (
    configSource === null ||
    !readReleaseSuccessorGuardSource(
      flags,
      'config',
      'E7_RELEASE_SUCCESSOR_GUARD_CONFIG_SOURCE_INVALID',
    ).equals(configSource)
  ) {
    fail('E7_RELEASE_SUCCESSOR_GUARD_CONFIG_SOURCE_MISMATCH');
  }
};

const validateReleaseSuccessorGuardFlagContract = (flags) => {
  const mode = flags?.['successor-guard-mode'];
  if (!RELEASE_SUCCESSOR_GUARD_MODES.includes(mode)) {
    fail('E7_RELEASE_SUCCESSOR_GUARD_MODE_INVALID');
  }
  const common = [
    'reconciliation-intent',
    ...RELEASE_SUCCESSOR_INTENT_SOURCE_FLAG_BINDINGS.map(([, flag]) => flag),
  ];
  if (common.some((flag) => typeof flags?.[flag] !== 'string' || flags[flag] === '')) {
    fail('E7_RELEASE_SUCCESSOR_GUARD_SOURCE_SET_INVALID');
  }
  const reconciliationOnly = [
    ...RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
    ...RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
    ...RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS,
  ].filter((flag) => flag !== 'reconciliation-recovery-role-effective-permissions');
  if (mode === 'ROLLBACK_CHECK' || mode === 'INCOMPLETE_RECONCILIATION') {
    if (
      reconciliationOnly.some((flag) => Object.hasOwn(flags, flag)) ||
      (mode === 'INCOMPLETE_RECONCILIATION' && flags.direction !== 'REPROMOTE_CANDIDATE')
    ) {
      fail('E7_RELEASE_SUCCESSOR_GUARD_MODE_SOURCE_SET_INVALID');
    }
  } else {
    const preparation = [
      ...RELEASE_SUCCESSOR_ROLLBACK_PREPARATION_ONLY_CLI_FLAGS,
      ...RELEASE_SUCCESSOR_ROLLBACK_PREPARED_CLI_FLAGS,
    ];
    const completion = RELEASE_SUCCESSOR_ROLLBACK_COMPLETION_CLI_FLAGS;
    if (
      preparation.some((flag) => typeof flags?.[flag] !== 'string' || flags[flag] === '') ||
      flags['max-polls'] !== '30' ||
      completion.some((flag) => typeof flags?.[flag] !== 'string' || flags[flag] === '')
    ) {
      fail('E7_RELEASE_SUCCESSOR_GUARD_MODE_SOURCE_SET_INVALID');
    }
  }
  return mode;
};

const releaseSuccessorIntentAuthoritySources = ({ flags, environmentVariables }) => ({
  intentSource: readReleaseSuccessorGuardSource(
    flags,
    'reconciliation-intent',
    'E7_RELEASE_SUCCESSOR_GUARD_INTENT_SOURCE_INVALID',
  ),
  sources: Object.fromEntries(
    RELEASE_SUCCESSOR_INTENT_SOURCE_FLAG_BINDINGS.map(([label, flag]) => [
      label,
      readReleaseSuccessorGuardSource(
        flags,
        flag,
        'E7_RELEASE_SUCCESSOR_GUARD_INTENT_SOURCE_INVALID',
      ),
    ]),
  ),
  githubIdentity: {
    repository: environmentVariables.GITHUB_REPOSITORY,
    workflowRef: environmentVariables.GITHUB_WORKFLOW_REF,
    ref: environmentVariables.GITHUB_REF,
    runId: environmentVariables.GITHUB_RUN_ID,
    runAttempt: Number(environmentVariables.GITHUB_RUN_ATTEMPT),
    candidateSha: environmentVariables.GITHUB_SHA,
  },
});

const releaseSuccessorRollbackPremutationPreparationSources = ({ flags }) => {
  const intentSources = Object.fromEntries(
    RELEASE_SUCCESSOR_INTENT_SOURCE_FLAG_BINDINGS.map(([label, flag]) => [
      label,
      readReleaseSuccessorGuardSource(
        flags,
        flag,
        'E7_RELEASE_SUCCESSOR_GUARD_PREMUTATION_SOURCE_INVALID',
      ),
    ]),
  );
  return {
    preparation: {
      config: parseReleaseSuccessorGuardJson(
        intentSources.config,
        'E7_RELEASE_SUCCESSOR_GUARD_CONFIG_SOURCE_INVALID',
      ),
      freezeManifest: parseReleaseSuccessorGuardJson(
        intentSources.candidateManifest,
        'E7_RELEASE_SUCCESSOR_GUARD_MANIFEST_SOURCE_INVALID',
      ),
      previousReleaseManifest: parseReleaseSuccessorGuardJson(
        intentSources.previousReleaseManifest,
        'E7_RELEASE_SUCCESSOR_GUARD_PREVIOUS_SOURCE_INVALID',
      ),
      candidateRecord: parseReleaseSuccessorGuardJson(
        intentSources.candidateRecord,
        'E7_RELEASE_SUCCESSOR_GUARD_CANDIDATE_SOURCE_INVALID',
      ),
      rollbackSource: readReleaseSuccessorGuardSource(
        flags,
        'rollback',
        'E7_RELEASE_SUCCESSOR_GUARD_ROLLBACK_SOURCE_INVALID',
      ),
      awsAuthSource: intentSources.awsAuth,
      approvalSource: intentSources.approval,
      journalRoleEffectivePermissionsSource: intentSources.journalRoleEffectivePermissions,
      reconciliationRecoveryRoleEffectivePermissionsSource: readReleaseSuccessorGuardSource(
        flags,
        'reconciliation-recovery-role-effective-permissions',
        'E7_RELEASE_SUCCESSOR_GUARD_RECOVERY_ROLE_SOURCE_INVALID',
      ),
      approvedPlanSource: intentSources.approvedDiff,
      deploymentEvidenceSource: intentSources.webDeployment,
      observabilityEvidenceSource: readReleaseSuccessorGuardSource(
        flags,
        'observability',
        'E7_RELEASE_SUCCESSOR_GUARD_OBSERVABILITY_SOURCE_INVALID',
      ),
      activationEvidenceSource: intentSources.activation,
      externalAuthorizationSource: intentSources.externalAuthorization,
      smokeInputSource: readReleaseSuccessorGuardSource(
        flags,
        'smoke-input',
        'E7_RELEASE_SUCCESSOR_GUARD_SMOKE_INPUT_SOURCE_INVALID',
      ),
      smokeEvidenceSource: readReleaseSuccessorGuardSource(
        flags,
        'smoke',
        'E7_RELEASE_SUCCESSOR_GUARD_SMOKE_SOURCE_INVALID',
      ),
      edgeEvidenceSource: readReleaseSuccessorGuardSource(
        flags,
        'edge',
        'E7_RELEASE_SUCCESSOR_GUARD_EDGE_SOURCE_INVALID',
      ),
      qualityEvidenceSource: readReleaseSuccessorGuardSource(
        flags,
        'quality',
        'E7_RELEASE_SUCCESSOR_GUARD_QUALITY_SOURCE_INVALID',
      ),
      sandboxEvidenceSource: readReleaseSuccessorGuardSource(
        flags,
        'sandbox',
        'E7_RELEASE_SUCCESSOR_GUARD_SANDBOX_SOURCE_INVALID',
      ),
      rollbackSmokeInputSource: readReleaseSuccessorGuardSource(
        flags,
        'rollback-smoke-input',
        'E7_RELEASE_SUCCESSOR_GUARD_ROLLBACK_SMOKE_INPUT_SOURCE_INVALID',
      ),
      pendingProducerSource: readReleaseSuccessorGuardSource(
        flags,
        'pending-producer',
        'E7_RELEASE_SUCCESSOR_GUARD_PENDING_SOURCE_INVALID',
      ),
      pendingEgressCloseoutSource: readReleaseSuccessorGuardSource(
        flags,
        'pending-egress-closeout',
        'E7_RELEASE_SUCCESSOR_GUARD_PENDING_EGRESS_CLOSEOUT_SOURCE_INVALID',
      ),
      rollbackSmokeSource: readReleaseSuccessorGuardSource(
        flags,
        'rollback-smoke',
        'E7_RELEASE_SUCCESSOR_GUARD_ROLLBACK_SMOKE_SOURCE_INVALID',
      ),
      repromotionSmokeSource: readReleaseSuccessorGuardSource(
        flags,
        'repromotion-smoke',
        'E7_RELEASE_SUCCESSOR_GUARD_REPROMOTION_SMOKE_SOURCE_INVALID',
      ),
      journalCleanupRoleArn: flags['journal-cleanup-role'],
      assemblyDirectory: resolveInsideWorkspace(
        flags.assembly,
        'E7_RELEASE_SUCCESSOR_GUARD_ASSEMBLY_INVALID',
      ),
      maxPolls: Number(flags['max-polls']),
    },
    preparedInputsSource: readReleaseSuccessorGuardSource(
      flags,
      'inputs',
      'E7_RELEASE_SUCCESSOR_GUARD_INPUTS_SOURCE_INVALID',
    ),
    rb06DescriptorSource: readReleaseSuccessorGuardSource(
      flags,
      'rb06',
      'E7_RELEASE_SUCCESSOR_GUARD_RB06_SOURCE_INVALID',
    ),
    rb08DescriptorSource: readReleaseSuccessorGuardSource(
      flags,
      'rb08',
      'E7_RELEASE_SUCCESSOR_GUARD_RB08_SOURCE_INVALID',
    ),
    sourceBindingSource: readReleaseSuccessorGuardSource(
      flags,
      'source-binding',
      'E7_RELEASE_SUCCESSOR_GUARD_SOURCE_BINDING_INVALID',
    ),
  };
};

const releaseSuccessorRollbackPremutationAuthoritySources = ({ flags }) => {
  const preparationSources = releaseSuccessorRollbackPremutationPreparationSources({ flags });
  const protectedRunSource = readReleaseSuccessorGuardSource(
    flags,
    'protected-run',
    'E7_RELEASE_SUCCESSOR_GUARD_PROTECTED_RUN_SOURCE_INVALID',
  );
  const protectedRun = parseReleaseSuccessorGuardJson(
    protectedRunSource,
    'E7_RELEASE_SUCCESSOR_GUARD_PROTECTED_RUN_SOURCE_INVALID',
  );
  const attestation = protectedRun.runtimeAttestation;
  const startedAtUtc = protectedRun.rb06Checkpoint?.startedAtUtc;
  if (
    protectedRun.rb08Checkpoint?.startedAtUtc !== startedAtUtc ||
    attestation?.workflow !== 'stage7-rollback-resilience.yml'
  ) {
    fail('E7_RELEASE_SUCCESSOR_GUARD_PROTECTED_RUN_IDENTITY_INVALID');
  }
  return {
    ...preparationSources,
    githubIdentity: {
      repository: attestation?.repository,
      workflowRef: RELEASE_SUCCESSOR_ROLLBACK_WORKFLOW,
      ref: 'refs/heads/master',
      runId: attestation?.runId,
      runAttempt: Number(attestation?.runAttempt),
      candidateSha: attestation?.githubSha,
      startedAtUtc,
    },
  };
};

const releaseSuccessorRollbackCompletionAuthoritySources = (flags) => ({
  protectedRunSource: readReleaseSuccessorGuardSource(
    flags,
    'protected-run',
    'E7_RELEASE_SUCCESSOR_GUARD_PROTECTED_RUN_SOURCE_INVALID',
  ),
  completionSource: readReleaseSuccessorGuardSource(
    flags,
    'completion',
    'E7_RELEASE_SUCCESSOR_GUARD_COMPLETION_SOURCE_INVALID',
  ),
});

const strictJson = (source, code) => {
  try {
    return JSON.parse(source);
  } catch {
    fail(code);
  }
};

const atomicPrivateJson = (target, value) => {
  const absolute = resolveInsideWorkspace(target, 'E7_INTERNAL_RECORD_PATH_INVALID', {
    mustExist: false,
  });
  mkdirSync(path.dirname(absolute), { recursive: true });
  const temporary = `${absolute}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
    chmodSync(temporary, 0o600);
    renameSync(temporary, absolute);
  } catch (error) {
    rmSync(temporary, { force: true });
    throw error;
  }
  return absolute;
};

const readJson = (filename, code) => {
  const absolute = resolveInsideWorkspace(filename, code, { allowDirectory: false });
  return strictJson(readFileSync(absolute, 'utf8'), code);
};

const defaultExecutor = ({ command, args, cwd = workspaceRoot, env = process.env }) => {
  const result = spawnSync(command, args, {
    cwd,
    encoding: 'utf8',
    env,
    maxBuffer: MAX_COMMAND_OUTPUT_BYTES,
    shell: false,
    timeout: COMMAND_TIMEOUT_MS,
    windowsHide: true,
  });
  if (result.error !== undefined) {
    return {
      status: null,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      error: result.error,
    };
  }
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
};

const workspaceToolEntrypoint = (name) => {
  const contract = WORKSPACE_TOOL_CONTRACTS[name];
  if (contract === undefined) fail('E7_WORKSPACE_TOOL_INVALID');
  try {
    const declaredPath = path.resolve(workspaceRoot, contract.relativePath);
    const resolvedPath = realpathSync.native(declaredPath);
    const relative = path.relative(workspaceRoot, resolvedPath);
    const packageRoot = path.dirname(path.dirname(resolvedPath));
    const packageJsonPath = path.join(packageRoot, 'package.json');
    const executableStat = lstatSync(resolvedPath);
    const packageStat = lstatSync(packageJsonPath);
    const packageJson = strictJson(
      readFileSync(packageJsonPath, 'utf8'),
      'E7_WORKSPACE_TOOL_INVALID',
    );
    if (
      relative === '..' ||
      relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative) ||
      !relative.split(path.sep).includes('node_modules') ||
      !executableStat.isFile() ||
      executableStat.isSymbolicLink() ||
      !packageStat.isFile() ||
      packageStat.isSymbolicLink() ||
      packageJson?.name !== contract.packageName ||
      packageJson?.version !== contract.packageVersion ||
      sha256(readFileSync(resolvedPath)) !== contract.sha256
    ) {
      fail('E7_WORKSPACE_TOOL_INVALID');
    }
    return resolvedPath;
  } catch (error) {
    if (error instanceof Stage7AwsError) throw error;
    fail('E7_WORKSPACE_TOOL_INVALID');
  }
};

const run = (executor, command, args, { cwd = workspaceRoot, env = process.env, code }) => {
  if (!Array.isArray(args) || args.some((argument) => typeof argument !== 'string')) {
    fail('E7_EXECUTOR_ARGUMENT_INVALID');
  }
  if (args.some((argument) => argument === '--hotswap' || argument.startsWith('--hotswap='))) {
    fail('E7_HOTSWAP_FORBIDDEN');
  }
  const result = executor({ command, args, cwd, env });
  if (!object(result) || result.status !== 0 || typeof result.stdout !== 'string') {
    fail(code);
  }
  return result.stdout.trim();
};

const aws = (context, args, code, options = {}) =>
  (() => {
    if (typeof context.awsCommand !== 'string' || context.awsCommand === '') {
      fail('E7_OFFLINE_AWS_EXECUTION_FORBIDDEN');
    }
    return run(
      context.executor,
      context.awsCommand,
      [...args, '--region', options.region ?? context.config.aws.region, '--no-cli-pager'],
      { code, env: options.env ?? context.childEnvironment },
    );
  })();

const awsJson = (context, args, code, options = {}) =>
  strictJson(aws(context, [...args, '--output', 'json'], code, options), code);

const frozenAwsCliVersion = (context, expectedVersion) => {
  const result = context.executor({
    command: context.awsCommand,
    args: ['--version'],
    cwd: workspaceRoot,
    env: context.childEnvironment,
  });
  if (
    !object(result) ||
    result.status !== 0 ||
    typeof result.stdout !== 'string' ||
    typeof result.stderr !== 'string'
  ) {
    fail('E7_AWS_CLI_VERSION_UNAVAILABLE');
  }
  const match = AWS_CLI_VERSION_OUTPUT.exec(`${result.stdout}\n${result.stderr}`.trim());
  if (match === null) fail('E7_AWS_CLI_VERSION_UNAVAILABLE');
  if (match[1] !== expectedVersion) fail('E7_AWS_CLI_VERSION_MISMATCH');
  return match[1];
};

const cdkResult = (context, args, code) => {
  if (args.some((argument) => argument === '--hotswap' || argument.startsWith('--hotswap='))) {
    fail('E7_HOTSWAP_FORBIDDEN');
  }
  const result = context.executor({
    command: process.execPath,
    args: [workspaceToolEntrypoint('cdk'), ...args],
    cwd: workspaceRoot,
    env: context.childEnvironment,
  });
  if (
    !object(result) ||
    result.status !== 0 ||
    typeof result.stdout !== 'string' ||
    typeof result.stderr !== 'string'
  ) {
    fail(code);
  }
  return result;
};

const cdk = (context, args, code) => cdkResult(context, args, code).stdout.trim();

const commandName = (base, platform = process.platform) =>
  platform === 'win32' ? (base === 'aws' ? 'aws.exe' : `${base}.cmd`) : base;

const isOutsideWorkspace = (candidate) => {
  const relative = path.relative(workspaceRoot, candidate);
  return relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
};

const protectedToolCommand = (environmentVariables, key, base, platform = process.platform) => {
  const fallback = commandName(base, platform);
  const override = environmentVariables[key];
  if (override === undefined) return fallback;
  if (typeof override !== 'string' || override === '') {
    fail('E7_PROTECTED_TOOL_COMMAND_INVALID');
  }
  if (environmentVariables.GITHUB_ACTIONS === 'true') {
    fail('E7_PROTECTED_TOOL_COMMAND_INVALID');
  }
  try {
    const resolved = realpathSync.native(override);
    const stat = lstatSync(resolved);
    if (
      !path.isAbsolute(override) ||
      path.basename(resolved).toLowerCase() !== fallback.toLowerCase() ||
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      !isOutsideWorkspace(resolved)
    ) {
      fail('E7_PROTECTED_TOOL_COMMAND_INVALID');
    }
    return resolved;
  } catch (error) {
    if (error instanceof Stage7AwsError) throw error;
    fail('E7_PROTECTED_TOOL_COMMAND_INVALID');
  }
};

const awsExecutableCommand = (
  environmentVariables,
  executor,
  { platform = process.platform, inspectFile = lstatSync, realpathFile = realpathSync.native } = {},
) => {
  const command = protectedToolCommand(environmentVariables, 'STAGE7_AWS_COMMAND', 'aws', platform);
  if (executor !== defaultExecutor || path.isAbsolute(command)) return command;
  const pathValue = Object.entries(environmentVariables).find(
    ([key]) => key.toUpperCase() === 'PATH',
  )?.[1];
  if (typeof pathValue !== 'string' || pathValue === '') {
    fail('E7_AWS_EXECUTABLE_INVALID');
  }
  for (const directory of pathValue.split(path.delimiter)) {
    if (directory === '') continue;
    const candidate = path.join(directory, command);
    try {
      const resolved = realpathFile(candidate);
      const stat = inspectFile(resolved);
      if (
        stat.isFile() &&
        !stat.isSymbolicLink() &&
        path.basename(resolved).toLowerCase() === command.toLowerCase() &&
        isOutsideWorkspace(resolved) &&
        (platform === 'win32' || (stat.uid === 0 && (stat.mode & 0o022) === 0))
      ) {
        return resolved;
      }
    } catch {
      // Continue searching the inherited, case-deduplicated PATH.
    }
  }
  fail('E7_AWS_EXECUTABLE_INVALID');
};

const childProcessEnvironment = (environmentVariables, { includeAwsCredentials, region }) => {
  const entries = Object.entries(environmentVariables);
  const normalizedKeys = entries.map(([key]) => key.toUpperCase());
  if (new Set(normalizedKeys).size !== normalizedKeys.length) {
    fail('E7_CHILD_PROCESS_ENVIRONMENT_INVALID');
  }
  const byUppercaseKey = new Map(entries.map(([key, value]) => [key.toUpperCase(), value]));
  const forbiddenExact = new Set([
    'ALL_PROXY',
    'AWS_CA_BUNDLE',
    'AWS_CONFIG_FILE',
    'AWS_DEFAULT_PROFILE',
    'AWS_EC2_METADATA_SERVICE_ENDPOINT',
    'AWS_PROFILE',
    'AWS_ROLE_ARN',
    'AWS_ROLE_SESSION_NAME',
    'AWS_SHARED_CREDENTIALS_FILE',
    'AWS_WEB_IDENTITY_TOKEN_FILE',
    'BOTO_CONFIG',
    'DYLD_INSERT_LIBRARIES',
    'HTTP_PROXY',
    'HTTPS_PROXY',
    'LD_PRELOAD',
    'NODE_EXTRA_CA_CERTS',
    'NODE_OPTIONS',
    'NODE_PATH',
    'NO_PROXY',
    'SSL_CERT_DIR',
    'SSL_CERT_FILE',
  ]);
  if (
    entries.some(([key]) => {
      const upper = key.toUpperCase();
      return (
        forbiddenExact.has(upper) ||
        upper.startsWith('AWS_ENDPOINT_URL') ||
        upper.startsWith('AWS_CONTAINER_CREDENTIALS_') ||
        upper.startsWith('DYLD_')
      );
    })
  ) {
    fail('E7_CHILD_PROCESS_ENVIRONMENT_INVALID');
  }
  if (byUppercaseKey.has('CI') && String(byUppercaseKey.get('CI')).toLowerCase() !== 'true') {
    fail('E7_CHILD_PROCESS_ENVIRONMENT_INVALID');
  }
  const allowedKeys = ['PATH', 'SYSTEMROOT', 'TEMP', 'TMP', 'TMPDIR', 'WINDIR'];
  const result = Object.fromEntries(
    allowedKeys
      .map((key) => [key, byUppercaseKey.get(key)])
      .filter(([, value]) => typeof value === 'string' && value !== ''),
  );
  result.AWS_EC2_METADATA_DISABLED = 'true';
  result.CI = 'true';
  if (includeAwsCredentials) {
    for (const key of ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']) {
      const value = byUppercaseKey.get(key);
      if (typeof value !== 'string' || value === '') {
        fail('E7_TEMPORARY_SESSION_REQUIRED');
      }
      result[key] = value;
    }
    result.AWS_REGION = region;
    result.AWS_DEFAULT_REGION = region;
  }
  return result;
};

const roleArnFor = (config, capability) => {
  const awsConfig = config.aws;
  const roleMap = awsConfig.roles;
  const directMap = {
    read: awsConfig.readRoleArn,
    deploy: awsConfig.deployRoleArn,
    rollback: awsConfig.rollbackRoleArn,
    cleanup: awsConfig.cleanupRoleArn,
  };
  const nestedMap = {
    read: roleMap?.readRoleArn,
    deploy: roleMap?.deployRoleArn,
    rollback: roleMap?.rollbackRoleArn,
    cleanup: roleMap?.cleanupRoleArn,
  };
  return nestedMap[capability] ?? directMap[capability] ?? awsConfig.roleArn;
};

const roleResource = (roleArn, code) => {
  const match = /^arn:aws:iam::([0-9]{12}):role\/(.+)$/u.exec(roleArn ?? '');
  if (match === null) fail(code);
  return { accountId: match[1], rolePath: match[2], roleName: match[2].split('/').at(-1) };
};

const assumedRoleMatches = (callerArn, expectedRoleArn) => {
  const expected = roleResource(expectedRoleArn, 'E7_EXPECTED_ROLE_INVALID');
  const match = /^arn:aws:sts::([0-9]{12}):assumed-role\/([^/]+)\/[^/]+$/u.exec(callerArn ?? '');
  return match !== null && match[1] === expected.accountId && match[2] === expected.roleName;
};

const authorizationScopeForFlag = (scope) =>
  scope === 'prerelease' ? 'EPHEMERAL_PRERELEASE' : 'FULL_RELEASE_VERSIONED_UPDATE';

const releaseModeForFlags = (scope, flags) => {
  const initial = flags['initial-release'] === true;
  const versionedUpdate = flags['versioned-update'] === true;
  if (scope === 'prerelease') {
    if (!initial || versionedUpdate) fail('E7_PRERELEASE_RELEASE_MODE_INVALID');
    return 'INITIAL';
  }
  if (initial || !versionedUpdate) fail('E7_VERSIONED_UPDATE_ACK_REQUIRED');
  return 'VERSIONED_UPDATE';
};

const validateOperationScope = (config, scope, { allowPlan = false } = {}) => {
  if (scope !== undefined && scope !== 'prerelease') fail('E7_OPERATION_SCOPE_INVALID');
  const expected = authorizationScopeForFlag(scope);
  if (config.authorization.scope === 'NON_MUTATING_PLAN') {
    if (!allowPlan) fail('E7_OPERATION_SCOPE_NOT_AUTHORIZED');
    return;
  }
  if (config.authorization.scope !== expected) fail('E7_OPERATION_SCOPE_MISMATCH');
  if (scope === 'prerelease') {
    if (
      !config.environment.startsWith('assessment-prerelease-') ||
      config.domain?.mode !== 'CUSTOM_AUTHORIZED'
    ) {
      fail('E7_PRERELEASE_BOUNDARY_INVALID');
    }
  } else if (
    config.environment !== 'assessment-release' ||
    config.domain.mode !== 'CUSTOM_AUTHORIZED'
  ) {
    fail('E7_FULL_RELEASE_BOUNDARY_INVALID');
  }
};

const normalizeOperationScope = (scope) => {
  if (scope === undefined || scope === 'full') return undefined;
  if (scope === 'prerelease') return 'prerelease';
  fail('E7_OPERATION_SCOPE_INVALID');
};

const validateWindowNow = (config, now) => {
  const current = now.getTime();
  const starts = Date.parse(config.window.startsAtUtc);
  const ends = Date.parse(config.window.endsAtUtc);
  const authorizationExpires = Date.parse(config.authorization.expiresAtUtc);
  if (
    !Number.isFinite(current) ||
    current < starts ||
    current >= ends ||
    current >= authorizationExpires
  ) {
    fail('E7_OPERATION_OUTSIDE_AUTHORIZED_WINDOW');
  }
};

const validateCandidateIdentity = (config, environmentVariables) => {
  const candidateSha = environmentVariables.STAGE7_CANDIDATE_SHA;
  const releaseId = environmentVariables.STAGE7_RELEASE_ID;
  if (!SHA.test(candidateSha ?? '')) fail('E7_OPERATION_CANDIDATE_SHA_INVALID');
  const match = RELEASE_ID.exec(releaseId ?? '');
  if (match === null || match[1] !== candidateSha.slice(0, 7)) {
    fail('E7_OPERATION_RELEASE_ID_INVALID');
  }
  if (
    environmentVariables.GITHUB_SHA !== undefined &&
    environmentVariables.GITHUB_SHA !== candidateSha
  ) {
    fail('E7_OPERATION_GITHUB_SHA_MISMATCH');
  }
  if (
    environmentVariables.STAGE7_ENVIRONMENT !== undefined &&
    environmentVariables.STAGE7_ENVIRONMENT !== config.environment
  ) {
    fail('E7_OPERATION_ENVIRONMENT_MISMATCH');
  }
  for (const key of ['AWS_REGION', 'AWS_DEFAULT_REGION', 'STAGE7_AWS_REGION']) {
    const value = environmentVariables[key];
    if (value !== undefined && value !== config.aws.region) fail('E7_OPERATION_REGION_MISMATCH');
  }
  if (
    environmentVariables.STAGE7_AWS_ACCOUNT_ID !== undefined &&
    environmentVariables.STAGE7_AWS_ACCOUNT_ID !== config.aws.accountId
  ) {
    fail('E7_OPERATION_ACCOUNT_MISMATCH');
  }
  return { candidateSha, releaseId };
};

const validateAuthorizedStacks = (config) => {
  const required = expectedStacks(config.environment);
  const approved = config.authorization.stacks;
  if (
    !Array.isArray(approved) ||
    approved.length !== required.length ||
    approved.toSorted().join('\0') !== required.toSorted().join('\0')
  ) {
    fail('E7_OPERATION_STACK_SCOPE_MISMATCH');
  }
  return required;
};

const assertJournalRoleAuthorityScope = (scope, flags) => {
  if (scope === 'prerelease' && flags['journal-role-effective-permissions'] !== undefined) {
    fail('E7_RELEASE_JOURNAL_ROLE_AUTHORITY_FORBIDDEN_FOR_PRERELEASE');
  }
  if (
    scope === 'prerelease' &&
    flags['reconciliation-recovery-role-effective-permissions'] !== undefined
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_AUTHORITY_FORBIDDEN_FOR_PRERELEASE');
  }
};

const loadOperationContext = ({
  capability,
  scope,
  flags = {},
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
  requireAws = true,
  allowPlan = false,
  windowMode = 'release',
}) => {
  const normalizedScope = normalizeOperationScope(scope);
  assertJournalRoleAuthorityScope(normalizedScope, flags);
  const configPath = environmentVariables.STAGE7_CONFIG;
  if (typeof configPath !== 'string' || configPath.length === 0) fail('E7_CONFIG_PATH_REQUIRED');
  const config = readStrictJsonFile(configPath, {
    // The exact Stage 7 schema contains a quoted 12-digit AWS account ID. The generic
    // PII detector treats any quoted 8-19 digit string as a phone number, so schema
    // validation and the runtime artifact sanitizer are the applicable allowlists here.
    scanForbiddenData: false,
    validateConfig: false,
  });
  const configValidationNow =
    windowMode === 'expired-cleanup' ? new Date(config?.window?.startsAtUtc) : now;
  validateStage7Config(config, { now: configValidationNow });
  validateOperationScope(config, normalizedScope, { allowPlan });
  if (windowMode === 'release') {
    validateWindowNow(config, now);
  } else if (windowMode === 'expired-cleanup') {
    if (
      !(now instanceof Date) ||
      !Number.isFinite(now.getTime()) ||
      now.getTime() < Date.parse(config.cleanup.expiresAtUtc)
    ) {
      fail('E7_CLEANUP_EXPIRY_NOT_REACHED');
    }
  } else {
    fail('E7_OPERATION_WINDOW_MODE_INVALID');
  }
  const identity = validateCandidateIdentity(config, environmentVariables);
  const stacks = validateAuthorizedStacks(config);
  const expectedRoleArn = roleArnFor(config, capability);
  roleResource(expectedRoleArn, 'E7_EXPECTED_ROLE_INVALID');
  if (!AWS_REGION.test(config.aws.region)) fail('E7_OPERATION_REGION_INVALID');
  if (
    config.aws.sessionMode === 'OIDC' &&
    requireAws &&
    environmentVariables.GITHUB_ACTIONS !== 'true'
  ) {
    fail('E7_OIDC_PROTECTED_WORKFLOW_REQUIRED');
  }
  if (requireAws) {
    if (
      !environmentVariables.AWS_ACCESS_KEY_ID ||
      !environmentVariables.AWS_SECRET_ACCESS_KEY ||
      !environmentVariables.AWS_SESSION_TOKEN
    ) {
      fail('E7_TEMPORARY_SESSION_REQUIRED');
    }
  }
  if (environmentVariables.STAGE7_PNPM_COMMAND !== undefined) {
    fail('E7_PROTECTED_TOOL_COMMAND_INVALID');
  }
  if (flags['aws-auth'] !== undefined) {
    if (normalizedScope !== 'prerelease') {
      const journalRoleArn = environmentVariables.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN;
      const permissionsBoundaryArn =
        environmentVariables.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN;
      const reconciliationRecoveryRoleArn =
        environmentVariables.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN;
      const reconciliationRecoveryPermissionsBoundaryArn =
        environmentVariables.STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN;
      if (
        flags.manifest === undefined ||
        flags['journal-role-effective-permissions'] === undefined ||
        typeof journalRoleArn !== 'string' ||
        journalRoleArn.length === 0 ||
        typeof permissionsBoundaryArn !== 'string' ||
        permissionsBoundaryArn.length === 0
      ) {
        fail('E7_RELEASE_JOURNAL_ROLE_AUTHORITY_REQUIRED');
      }
      if (
        flags['reconciliation-recovery-role-effective-permissions'] === undefined ||
        typeof reconciliationRecoveryRoleArn !== 'string' ||
        reconciliationRecoveryRoleArn.length === 0 ||
        typeof reconciliationRecoveryPermissionsBoundaryArn !== 'string' ||
        reconciliationRecoveryPermissionsBoundaryArn.length === 0
      ) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_AUTHORITY_REQUIRED');
      }
      const freezeManifest = validateFreezeManifest(
        readStrictJsonFile(flags.manifest, {
          scanForbiddenData: false,
          validateConfig: false,
        }),
      );
      const awsAuthSource = readFileSync(
        resolveInsideWorkspace(flags['aws-auth'], 'E7_AWS_AUTH_EVIDENCE_MISSING', {
          allowDirectory: false,
        }),
      );
      const journalRoleEffectivePermissionsSource = readFileSync(
        resolveInsideWorkspace(
          flags['journal-role-effective-permissions'],
          'E7_RELEASE_JOURNAL_ROLE_AUTHORITY_REQUIRED',
          { allowDirectory: false },
        ),
      );
      const reconciliationRecoveryRoleEffectivePermissionsSource = readFileSync(
        resolveInsideWorkspace(
          flags['reconciliation-recovery-role-effective-permissions'],
          'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_AUTHORITY_REQUIRED',
          { allowDirectory: false },
        ),
      );
      try {
        const awsAuth = parseStrictJsonSource(awsAuthSource, { scanForbiddenData: false });
        const journalRoleEffectivePermissions = parseReleaseJournalRoleEffectivePermissionsSource(
          journalRoleEffectivePermissionsSource,
          {
            roleArn: journalRoleArn,
            permissionsBoundaryArn,
          },
        );
        if (journalRoleEffectivePermissions.value.awsRegion !== config.aws.region) {
          fail('E7_RELEASE_JOURNAL_ROLE_AUTHORITY_REGION_MISMATCH');
        }
        validateReleaseJournalRoleEffectivePermissionsBinding({
          awsAuthSource,
          effectivePermissionsSource: journalRoleEffectivePermissionsSource,
          expected: {
            candidateSha: identity.candidateSha,
            releaseId: identity.releaseId,
            configSha256: objectSha256(config),
            manifestSha256: freezeManifest.manifestSha256,
          },
        });
        const reconciliationRecoveryRoleEffectivePermissions =
          parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource(
            reconciliationRecoveryRoleEffectivePermissionsSource,
            {
              roleArn: reconciliationRecoveryRoleArn,
              permissionsBoundaryArn: reconciliationRecoveryPermissionsBoundaryArn,
            },
          );
        const recoveryBinding = {
          reconciliationRecoveryRoleArn,
          reconciliationRecoveryPermissionsBoundaryArn,
          reconciliationRecoveryRoleEffectivePermissionsRawSha256:
            reconciliationRecoveryRoleEffectivePermissions.rawSha256,
          reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256:
            reconciliationRecoveryRoleEffectivePermissions.canonicalSha256,
          reconciliationRecoveryRoleEffectivePermissionsSha256:
            reconciliationRecoveryRoleEffectivePermissions.value.effectivePermissionsSha256,
          reconciliationRecoveryRoleEffectivePolicyProjectionSha256:
            reconciliationRecoveryRoleEffectivePermissions.value.effectivePolicyProjectionSha256,
        };
        if (
          reconciliationRecoveryRoleEffectivePermissions.value.awsRegion !== config.aws.region ||
          RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.some(
            (field) => awsAuth[field] !== recoveryBinding[field],
          )
        ) {
          fail('E7_RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_INVALID');
        }
      } catch (error) {
        if (error instanceof Stage7ReleaseSuccessorIamAuthorityError) {
          fail('E7_RELEASE_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BINDING_INVALID');
        }
        if (error instanceof Stage7ReleaseReconciliationRecoveryError) {
          fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BINDING_INVALID');
        }
        throw error;
      }
    }
  }
  return {
    awsCommand: requireAws ? awsExecutableCommand(environmentVariables, executor) : null,
    capability,
    childEnvironment: childProcessEnvironment(environmentVariables, {
      includeAwsCredentials: requireAws,
      region: config.aws.region,
    }),
    config,
    environmentVariables,
    executor,
    expectedRoleArn,
    flags,
    identity,
    now,
    scope: normalizedScope,
    stacks,
  };
};

const readRecoveryBoundJsonDocument = (filename, code) => {
  const resolved = resolveInsideWorkspace(filename, code, { allowDirectory: false });
  const bytes = readFileSync(resolved);
  try {
    return {
      bytes,
      value: parseStrictJsonSource(bytes, { scanForbiddenData: false }),
    };
  } catch {
    fail(code);
  }
};

const validateRecoveryIntentDocumentBinding = (intent, label, document) => {
  const binding = intent.bindings.find((entry) => entry.label === label);
  if (
    binding?.sourceType !== 'JSON' ||
    binding.rawSha256 !== sha256(document.bytes) ||
    binding.canonicalSha256 !== objectSha256(document.value) ||
    binding.bytes !== document.bytes.length
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_INTENT_FILE_BINDING_INVALID');
  }
  return document;
};

const validateRecoveryIntentFileBindings = (
  intent,
  flags,
  bindings = RELEASE_RECONCILIATION_RECOVERY_FILE_BINDINGS,
) => {
  const documents = new Map();
  for (const [flag, label] of bindings) {
    if (typeof flags?.[flag] !== 'string' || flags[flag] === '') {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_INTENT_FILE_REQUIRED');
    }
    documents.set(
      flag,
      validateRecoveryIntentDocumentBinding(
        intent,
        label,
        readRecoveryBoundJsonDocument(
          flags[flag],
          'E7_RELEASE_RECONCILIATION_RECOVERY_INTENT_FILE_INVALID',
        ),
      ),
    );
  }
  return documents;
};

const validateRecoveryRuntimeEnvironment = ({ actor, environmentVariables, capability }) => {
  const recoveryRun = actor?.recoveryRun;
  const source = actor?.originalSource;
  const authority = actor?.authority;
  const runAttempt = String(recoveryRun?.runAttempt ?? '');
  if (
    !['mutation', 'read'].includes(capability) ||
    source === undefined ||
    recoveryRun === undefined ||
    authority === undefined ||
    environmentVariables?.GITHUB_ACTIONS !== 'true' ||
    environmentVariables.GITHUB_REPOSITORY !== recoveryRun.repository ||
    environmentVariables.GITHUB_WORKFLOW_REF !== RELEASE_RECONCILIATION_RECOVERY_WORKFLOW ||
    environmentVariables.GITHUB_WORKFLOW_REF !== recoveryRun.workflowRef ||
    environmentVariables.GITHUB_REF !== 'refs/heads/master' ||
    environmentVariables.GITHUB_REF !== recoveryRun.ref ||
    environmentVariables.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    environmentVariables.GITHUB_EVENT_NAME !== recoveryRun.eventName ||
    environmentVariables.GITHUB_RUN_ID !== recoveryRun.runId ||
    environmentVariables.GITHUB_RUN_ATTEMPT !== runAttempt ||
    environmentVariables.GITHUB_ACTOR_ID !== recoveryRun.actorId ||
    environmentVariables.GITHUB_SHA !== recoveryRun.controlSha ||
    environmentVariables.STAGE7_PROTECTED_ENVIRONMENT !==
      RELEASE_RECONCILIATION_RECOVERY_ENVIRONMENT ||
    environmentVariables.STAGE7_PROTECTED_ENVIRONMENT !== recoveryRun.protectedEnvironment ||
    environmentVariables.STAGE7_RECOVERY_CANDIDATE_SHA !== source.candidateSha ||
    environmentVariables.STAGE7_AWS_ACCOUNT_ID !== authority.accountId ||
    environmentVariables.STAGE7_AWS_REGION !== authority.region ||
    environmentVariables.AWS_REGION !== authority.region ||
    environmentVariables.AWS_DEFAULT_REGION !== authority.region ||
    environmentVariables.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN !==
      authority.recoveryRoleArn ||
    (capability === 'mutation' &&
      environmentVariables.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN !==
        actor?.request?.recoveryRoleAuthority?.roleArn) ||
    typeof environmentVariables.STAGE7_CONFIG !== 'string' ||
    environmentVariables.STAGE7_CONFIG === '' ||
    !environmentVariables.AWS_ACCESS_KEY_ID ||
    !environmentVariables.AWS_SECRET_ACCESS_KEY ||
    !environmentVariables.AWS_SESSION_TOKEN
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_RUNTIME_CONTEXT_INVALID');
  }
};

const resolveRecoveryGitIdentity = ({ actor, gitSpawn = spawnSync }) => {
  const run = (arguments_, code) => {
    const result = gitSpawn('git', arguments_, {
      cwd: workspaceRoot,
      encoding: 'utf8',
      shell: false,
      windowsHide: true,
    });
    if (
      result?.error !== undefined ||
      result?.signal !== null ||
      result?.status !== 0 ||
      typeof result.stdout !== 'string'
    ) {
      fail(code);
    }
    return result.stdout.trim();
  };
  const controlSha = run(
    ['rev-parse', 'HEAD'],
    'E7_RELEASE_RECONCILIATION_RECOVERY_CONTROL_INVALID',
  );
  const taggedCandidateSha = run(
    ['rev-parse', `refs/tags/${actor.originalSource.releaseTag}^{commit}`],
    'E7_RELEASE_RECONCILIATION_RECOVERY_TAG_INVALID',
  );
  if (
    controlSha !== actor.recoveryRun.controlSha ||
    taggedCandidateSha !== actor.originalSource.candidateSha
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_GIT_IDENTITY_MISMATCH');
  }
  return { controlSha, taggedCandidateSha };
};

const loadReleaseReconciliationRecoveryOperationContext = ({
  capability,
  flags,
  recoveryActor,
  recoveryIntent,
  executor,
  environmentVariables,
  now,
  gitSpawn = spawnSync,
}) => {
  if (environmentVariables.STAGE7_PNPM_COMMAND !== undefined) {
    fail('E7_PROTECTED_TOOL_COMMAND_INVALID');
  }
  validateRecoveryRuntimeEnvironment({
    actor: recoveryActor,
    environmentVariables,
    capability,
  });
  validateReleaseReconciliationIntent(recoveryIntent);
  if (recoveryIntent.bindings.length !== 23) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_INTENT_BINDING_COUNT_INVALID');
  }
  validateReleaseReconciliationRecoveryActor(recoveryActor, recoveryIntent);
  if (
    !(now instanceof Date) ||
    !Number.isFinite(now.getTime()) ||
    now.getTime() < Date.parse(recoveryActor.approval.approvedAtUtc) ||
    now.getTime() >= Date.parse(recoveryActor.approval.expiresAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_RUNTIME_EXPIRED');
  }
  const configDocument = validateRecoveryIntentDocumentBinding(
    recoveryIntent,
    'config',
    readRecoveryBoundJsonDocument(
      environmentVariables.STAGE7_CONFIG,
      'E7_RELEASE_RECONCILIATION_RECOVERY_CONFIG_INVALID',
    ),
  );
  const config = configDocument.value;
  try {
    validateStage7Config(config, { now: new Date(config?.window?.startsAtUtc) });
  } catch {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CONFIG_INVALID');
  }
  validateOperationScope(config, undefined);
  if (
    objectSha256(config) !== recoveryIntent.source.configSha256 ||
    config.environment !== 'assessment-release' ||
    config.aws.accountId !== recoveryIntent.authority.accountId ||
    config.aws.region !== recoveryIntent.authority.region ||
    config.aws.roles.rollbackRoleArn !== recoveryIntent.authority.rollbackRoleArn ||
    now.getTime() >= Date.parse(config.cleanup.expiresAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_CONFIG_BINDING_INVALID');
  }
  const documents = validateRecoveryIntentFileBindings(
    recoveryIntent,
    flags,
    capability === 'mutation'
      ? RELEASE_RECONCILIATION_RECOVERY_FILE_BINDINGS
      : RELEASE_RECONCILIATION_RECOVERY_DRIFT_FILE_BINDINGS,
  );
  if (capability === 'mutation') {
    const expectedSessionPolicy = createReleaseReconciliationRecoverySessionPolicy({
      intent: recoveryIntent,
      recoveryRoleArn: recoveryActor.authority.recoveryRoleArn,
      permissionsBoundaryArn: recoveryActor.request.recoveryRoleAuthority.permissionsBoundaryArn,
      candidateRecordSource: documents.get('candidate-record').bytes,
      previousManifestSource: documents.get('previous-manifest').bytes,
    });
    const subset = validateReleaseReconciliationRecoverySessionPolicySubset({
      basePolicy: recoveryActor.request.recoveryRoleAuthority.basePolicy,
      sessionPolicy: expectedSessionPolicy,
    });
    if (
      canonicalJson(expectedSessionPolicy) !==
        canonicalJson(recoveryActor.request.recoveryRoleAuthority.sessionPolicy) ||
      canonicalJson(subset) !==
        canonicalJson(recoveryActor.request.recoveryRoleAuthority.sessionPolicySubset)
    ) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_SESSION_POLICY_MISMATCH');
    }
  }
  resolveRecoveryGitIdentity({ actor: recoveryActor, gitSpawn });
  const expectedRoleArn =
    capability === 'mutation'
      ? recoveryActor.authority.recoveryRoleArn
      : roleArnFor(config, 'read');
  roleResource(expectedRoleArn, 'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_INVALID');
  return {
    awsCommand: awsExecutableCommand(environmentVariables, executor),
    capability: capability === 'mutation' ? 'recovery' : 'read',
    childEnvironment: childProcessEnvironment(environmentVariables, {
      includeAwsCredentials: true,
      region: config.aws.region,
    }),
    config,
    environmentVariables,
    executor,
    expectedRoleArn,
    flags,
    identity: {
      candidateSha: recoveryIntent.source.candidateSha,
      releaseId: recoveryIntent.source.releaseId,
    },
    now,
    recoveryActor,
    recoveryIntent,
    scope: undefined,
    stacks: validateAuthorizedStacks(config),
  };
};

const validateRecoveryCallerIdentity = (context, capability) => {
  const caller = awsJson(
    context,
    ['sts', 'get-caller-identity'],
    'E7_RELEASE_RECONCILIATION_RECOVERY_STS_FAILED',
  );
  const role = roleResource(
    context.expectedRoleArn,
    'E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_INVALID',
  );
  const run = context.recoveryActor.recoveryRun;
  const expectedSession =
    capability === 'mutation'
      ? context.recoveryActor.authority.roleSessionName
      : `e7-reconciliation-recovery-read-${run.runId}-${run.runAttempt}`;
  if (
    caller?.Account !== context.config.aws.accountId ||
    caller?.Arn !==
      `arn:aws:sts::${context.config.aws.accountId}:assumed-role/${role.roleName}/${expectedSession}` ||
    typeof caller?.UserId !== 'string' ||
    !caller.UserId.endsWith(`:${expectedSession}`)
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_STS_IDENTITY_INVALID');
  }
  return caller;
};

const listReleaseReconciliationRecoveryGuardNames = (
  context,
  root,
  { stopAfterFirst = false } = {},
) => {
  const output = [];
  const tokens = new Set();
  let nextToken = null;
  let pages = 0;
  do {
    pages += 1;
    if (pages > RELEASE_RECONCILIATION_RECOVERY_MAX_GUARD_PAGES) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_GUARD_PAGE_LIMIT');
    }
    const arguments_ = [
      'ssm',
      'get-parameters-by-path',
      '--path',
      root,
      '--recursive',
      '--max-results',
      '10',
      '--no-with-decryption',
      '--no-paginate',
      '--output',
      'json',
    ];
    if (nextToken !== null) arguments_.push('--next-token', nextToken);
    const response = awsJson(
      context,
      arguments_,
      'E7_RELEASE_RECONCILIATION_RECOVERY_GUARD_READ_FAILED',
    );
    if (
      !object(response) ||
      !Array.isArray(response.Parameters) ||
      response.Parameters.length > 10 ||
      Object.keys(response).some((key) => !['Parameters', 'NextToken'].includes(key))
    ) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_GUARD_RESPONSE_INVALID');
    }
    for (const parameter of response.Parameters) {
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
        !parameter.Name.startsWith(`${root}/`) ||
        parameter.Type !== 'String' ||
        typeof parameter.Value !== 'string' ||
        parameter.Version !== 1 ||
        parameter.DataType !== 'text'
      ) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_GUARD_PARAMETER_INVALID');
      }
      output.push(parameter.Name);
    }
    if (output.length > RELEASE_RECONCILIATION_RECOVERY_MAX_GUARD_PARAMETERS) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_GUARD_TOO_LARGE');
    }
    if (stopAfterFirst && output.length > 0) return output;
    nextToken = response.NextToken ?? null;
    if (nextToken !== null) {
      if (typeof nextToken !== 'string' || nextToken === '' || tokens.has(nextToken)) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_GUARD_TOKEN_INVALID');
      }
      tokens.add(nextToken);
    }
  } while (nextToken !== null);
  if (new Set(output).size !== output.length) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_GUARD_DUPLICATE');
  }
  return output.toSorted();
};

const requireReleaseReconciliationRecoveryStillPreFence = (context) => {
  const candidateSha = context.recoveryIntent.source.candidateSha;
  for (const root of [
    `/checkout/stage7/release-fence/${candidateSha}`,
    `/checkout/stage7/release-finalization/${candidateSha}`,
  ]) {
    if (
      listReleaseReconciliationRecoveryGuardNames(context, root, { stopAfterFirst: true }).length
    ) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_POST_FENCE_BLOCKED');
    }
  }
  const candidateRoot = `/checkout/stage7/rollback/${candidateSha}`;
  const reconciliationRoot = `${candidateRoot}/release-reconciliation/${context.recoveryIntent.source.runId}`;
  const allowedPrefixes = [
    `${candidateRoot}/RB-E7-06/`,
    `${candidateRoot}/RB-E7-08/`,
    `${reconciliationRoot}/`,
  ];
  if (
    listReleaseReconciliationRecoveryGuardNames(context, candidateRoot).some((name) =>
      allowedPrefixes.every((prefix) => !name.startsWith(prefix)),
    )
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_FOREIGN_JOURNAL_BLOCKED');
  }
};

const validateAwsCallerIdentity = (context, caller) => {
  if (
    caller?.Account !== context.config.aws.accountId ||
    !assumedRoleMatches(caller?.Arn, context.expectedRoleArn)
  ) {
    fail('E7_AWS_IDENTITY_MISMATCH');
  }
  return {
    accountSha256: sha256(caller.Account),
    accountSuffix: caller.Account.slice(-4),
    roleSha256: sha256(context.expectedRoleArn),
    sessionArnSha256: sha256(caller.Arn),
  };
};

const revalidateAwsIdentity = (context) =>
  validateAwsCallerIdentity(
    context,
    awsJson(context, ['sts', 'get-caller-identity'], 'E7_STS_IDENTITY_FAILED'),
  );

const revalidateAwsIdentityBinding = (context) => {
  const source = aws(
    context,
    ['sts', 'get-caller-identity', '--output', 'json'],
    'E7_STS_IDENTITY_FAILED',
  );
  const caller = strictJson(source, 'E7_STS_IDENTITY_FAILED');
  const projection = validateAwsCallerIdentity(context, caller);
  const rawProjection = JSON.stringify(projection);
  return {
    projection,
    rawSha256: sha256(rawProjection),
    canonicalSha256: objectSha256(projection),
    bytes: Buffer.byteLength(rawProjection),
  };
};

const releaseSuccessorGuardSessionName = ({ mode, direction, runId }) => {
  if (mode === 'ROLLBACK_CHECK') {
    if (direction === 'ROLLBACK_TO_PREVIOUS') return `e7-rollback-apply-${runId}`;
    if (direction === 'REPROMOTE_CANDIDATE') return `e7-repromote-${runId}`;
  }
  if (
    ['RECONCILIATION', 'INCOMPLETE_RECONCILIATION'].includes(mode) &&
    direction === 'REPROMOTE_CANDIDATE'
  ) {
    return `e7-release-reconciliation-runtime-${runId}`;
  }
  fail('E7_RELEASE_SUCCESSOR_GUARD_SESSION_MODE_INVALID');
};

const createReleaseSuccessorGuardAwsAdapter = ({ context, mode, direction }) => {
  const environmentVariables = context.environmentVariables;
  const runId = environmentVariables.GITHUB_RUN_ID;
  const role = roleResource(context.expectedRoleArn, 'E7_RELEASE_SUCCESSOR_GUARD_ROLE_INVALID');
  const sessionName = releaseSuccessorGuardSessionName({ mode, direction, runId });
  if (
    environmentVariables.GITHUB_ACTIONS !== 'true' ||
    environmentVariables.GITHUB_REPOSITORY !== 'ivanmonsalve0404/async-checkout-demo' ||
    environmentVariables.GITHUB_WORKFLOW_REF !== RELEASE_SUCCESSOR_RELEASE_WORKFLOW ||
    environmentVariables.GITHUB_REF !== 'refs/heads/master' ||
    environmentVariables.GITHUB_RUN_ATTEMPT !== '1' ||
    environmentVariables.GITHUB_SHA !== context.identity.candidateSha ||
    environmentVariables.STAGE7_AWS_ROLLBACK_ROLE_ARN !== context.expectedRoleArn ||
    !/^[1-9][0-9]{0,19}$/u.test(runId ?? '') ||
    sessionName.length > 64
  ) {
    fail('E7_RELEASE_SUCCESSOR_GUARD_AWS_CONTEXT_INVALID');
  }
  const roots = new Map([
    [`${RELEASE_SUCCESSOR_FENCE_PARAMETER_ROOT}/${context.identity.candidateSha}`, false],
    [`${RELEASE_SUCCESSOR_FINALIZATION_PARAMETER_ROOT}/${context.identity.candidateSha}`, false],
    [`/checkout/stage7/rollback/${context.identity.candidateSha}`, true],
  ]);
  let identityValidated = false;
  const validateIdentity = () => {
    if (identityValidated) return;
    const caller = awsJson(
      context,
      ['sts', 'get-caller-identity'],
      'E7_RELEASE_SUCCESSOR_GUARD_STS_IDENTITY_FAILED',
    );
    if (
      !exactKeys(caller, ['UserId', 'Account', 'Arn']) ||
      caller.Account !== role.accountId ||
      caller.Arn !==
        `arn:aws:sts::${role.accountId}:assumed-role/${role.roleName}/${sessionName}` ||
      typeof caller.UserId !== 'string' ||
      !caller.UserId.endsWith(`:${sessionName}`)
    ) {
      fail('E7_RELEASE_SUCCESSOR_GUARD_STS_IDENTITY_INVALID');
    }
    identityValidated = true;
  };
  return async (request) => {
    const requestKeys =
      request?.nextToken === undefined
        ? ['path', 'recursive', 'withDecryption', 'maxResults']
        : ['path', 'recursive', 'withDecryption', 'maxResults', 'nextToken'];
    if (
      !exactKeys(request, requestKeys) ||
      !roots.has(request.path) ||
      roots.get(request.path) !== request.recursive ||
      request.withDecryption !== false ||
      request.maxResults !== 10 ||
      (request.nextToken !== undefined &&
        (typeof request.nextToken !== 'string' || request.nextToken === ''))
    ) {
      fail('E7_RELEASE_SUCCESSOR_GUARD_SSM_REQUEST_INVALID');
    }
    validateIdentity();
    return awsJson(
      context,
      [
        'ssm',
        'get-parameters-by-path',
        '--path',
        request.path,
        request.recursive ? '--recursive' : '--no-recursive',
        '--no-with-decryption',
        '--max-results',
        '10',
        '--no-paginate',
        ...(request.nextToken === undefined ? [] : ['--next-token', request.nextToken]),
      ],
      'E7_RELEASE_SUCCESSOR_GUARD_SSM_READ_FAILED',
    );
  };
};

const cloudAssemblyStacks = (assemblyPath) => {
  const app = resolveInsideWorkspace(assemblyPath, 'E7_CLOUD_ASSEMBLY_INVALID');
  if (!statSync(app).isDirectory()) fail('E7_CLOUD_ASSEMBLY_INVALID');
  const manifestPath = path.join(app, 'manifest.json');
  if (!existsSync(manifestPath) || lstatSync(manifestPath).isSymbolicLink()) {
    fail('E7_CLOUD_ASSEMBLY_MANIFEST_MISSING');
  }
  const manifest = strictJson(
    readFileSync(manifestPath, 'utf8'),
    'E7_CLOUD_ASSEMBLY_MANIFEST_INVALID',
  );
  if (!object(manifest) || !object(manifest.artifacts)) fail('E7_CLOUD_ASSEMBLY_MANIFEST_INVALID');
  const stacks = [];
  for (const [artifactId, artifact] of Object.entries(manifest.artifacts)) {
    if (artifact?.type !== 'aws:cloudformation:stack') continue;
    if (!STACK_NAME.test(artifactId)) fail('E7_CLOUD_ASSEMBLY_STACK_INVALID');
    const templateFile = artifact?.properties?.templateFile;
    if (
      typeof templateFile !== 'string' ||
      path.isAbsolute(templateFile) ||
      templateFile.split(/[\\/]/u).includes('..')
    ) {
      fail('E7_CLOUD_ASSEMBLY_TEMPLATE_INVALID');
    }
    const templatePath = path.resolve(app, templateFile);
    if (!templatePath.startsWith(`${app}${path.sep}`) || !existsSync(templatePath)) {
      fail('E7_CLOUD_ASSEMBLY_TEMPLATE_INVALID');
    }
    const template = strictJson(
      readFileSync(templatePath, 'utf8'),
      'E7_CLOUD_ASSEMBLY_TEMPLATE_INVALID',
    );
    const tags = artifact?.properties?.tags;
    if (!object(tags)) fail('E7_CLOUD_ASSEMBLY_STACK_TAGS_INVALID');
    if (
      artifact?.properties?.terminationProtection !== undefined &&
      typeof artifact.properties.terminationProtection !== 'boolean'
    ) {
      fail('E7_CLOUD_ASSEMBLY_TERMINATION_PROTECTION_INVALID');
    }
    stacks.push({
      artifactId,
      tags,
      template,
      templateFile,
      terminationProtection: artifact?.properties?.terminationProtection === true,
    });
  }
  return { app, manifest, stacks };
};

const validateWebApiOriginContract = (context, distributionConfig) => {
  const origins = Array.isArray(distributionConfig?.Origins) ? distributionConfig.Origins : [];
  const customOrigins = origins.filter(
    ({ CustomOriginConfig }) => CustomOriginConfig !== undefined,
  );
  const apiBehaviors = Array.isArray(distributionConfig?.CacheBehaviors)
    ? distributionConfig.CacheBehaviors.filter(({ PathPattern }) => PathPattern === 'api/*')
    : [];
  const apiOrigin = customOrigins[0];
  const apiBehavior = apiBehaviors[0];
  const customDomain = context.config.domain.mode === 'CUSTOM_AUTHORIZED';
  const serializedManagedDomain = JSON.stringify(apiOrigin?.DomainName) ?? '';
  const domainValid = customDomain
    ? apiOrigin?.DomainName === context.config.domain.apiHostname
    : serializedManagedDomain.includes('.execute-api.') &&
      serializedManagedDomain.includes(context.config.aws.region);
  if (
    customOrigins.length !== 1 ||
    apiBehaviors.length !== 1 ||
    typeof apiOrigin?.Id !== 'string' ||
    apiOrigin.Id === '' ||
    apiBehavior?.TargetOriginId !== apiOrigin.Id ||
    !domainValid ||
    apiOrigin.CustomOriginConfig?.OriginProtocolPolicy !== 'https-only' ||
    JSON.stringify(apiOrigin.CustomOriginConfig?.OriginSSLProtocols) !== JSON.stringify(['TLSv1.2'])
  ) {
    fail('E7_CLOUD_ASSEMBLY_INITIAL_WEB_PUBLICATION_INVALID');
  }
  return apiOrigin;
};

const logicalReference = (value) =>
  exactKeys(value, ['Ref']) && typeof value.Ref === 'string' ? value.Ref : null;

const logicalGetAtt = (value, attribute) =>
  exactKeys(value, ['Fn::GetAtt']) &&
  Array.isArray(value['Fn::GetAtt']) &&
  value['Fn::GetAtt'].length === 2 &&
  typeof value['Fn::GetAtt'][0] === 'string' &&
  value['Fn::GetAtt'][1] === attribute
    ? value['Fn::GetAtt'][0]
    : null;

const validatePublicationControlUsage = (template, { expectedLiteralPaths }, code) => {
  const actualLiteralPaths = [];
  const visit = (value, path = []) => {
    if (
      typeof value === 'string' &&
      (value.includes('PublicationState') || value.includes('PublicationEnabled'))
    ) {
      actualLiteralPaths.push(path.join('.'));
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((entry, index) => visit(entry, [...path, String(index)]));
      return;
    }
    if (!object(value)) return;
    for (const [key, entry] of Object.entries(value)) {
      const entryPath = [...path, key];
      if (key.includes('PublicationState') || key.includes('PublicationEnabled')) {
        actualLiteralPaths.push(`${entryPath.join('.')}#key`);
      }
      visit(entry, entryPath);
    }
  };
  visit(template);
  const expected = expectedLiteralPaths.toSorted();
  const actual = actualLiteralPaths.toSorted();
  if (
    JSON.stringify(actual) !== JSON.stringify(expected) ||
    (expected.length > 0 &&
      (canonicalJson(template.Parameters?.PublicationState) !==
        canonicalJson({
          Type: 'String',
          Default: 'DISABLED',
          AllowedValues: ['DISABLED', 'ENABLED'],
          Description:
            'CloudFormation-managed publication state; changed only by audited activation/rollback',
        }) ||
        canonicalJson(template.Conditions?.PublicationEnabled) !==
          canonicalJson({ 'Fn::Equals': [{ Ref: 'PublicationState' }, 'ENABLED'] })))
  ) {
    fail(code);
  }
};

const validateReleaseStackResourceAllowlist = (context, artifactId, template) => {
  const contract = inspectReleaseStackResourceAllowlist({
    artifactId,
    domainMode: context.config.domain.mode,
    scope: context.scope,
    template,
  });
  if (!contract.valid) fail('E7_CLOUD_ASSEMBLY_RESOURCE_ALLOWLIST_INVALID');
  const { suffix } = contract;
  if (['data', 'observability'].includes(suffix)) {
    validatePublicationControlUsage(
      template,
      { expectedLiteralPaths: [] },
      'E7_CLOUD_ASSEMBLY_RESOURCE_ALLOWLIST_INVALID',
    );
  }
};

const validateInitialWebPublicationContract = (context, template) => {
  const resourceEntries = object(template?.Resources) ? Object.entries(template.Resources) : [];
  const resourcesOfType = (type) =>
    resourceEntries.filter(([, resource]) => resource.Type === type);
  const distributions = resourcesOfType('AWS::CloudFront::Distribution');
  const buckets = resourcesOfType('AWS::S3::Bucket');
  const bucketPolicies = resourcesOfType('AWS::S3::BucketPolicy');
  const originAccessControls = resourcesOfType('AWS::CloudFront::OriginAccessControl');
  const cloudFrontFunctions = resourcesOfType('AWS::CloudFront::Function');
  const responseHeadersPolicies = resourcesOfType('AWS::CloudFront::ResponseHeadersPolicy');
  const dnsRecords = resourcesOfType('AWS::Route53::RecordSet');
  const parameters = resourcesOfType('AWS::SSM::Parameter');
  const [distributionLogicalId, distribution] = distributions[0] ?? [];
  const [bucketLogicalId] = buckets[0] ?? [];
  const bucket = buckets[0]?.[1];
  const bucketPolicy = bucketPolicies[0]?.[1];
  const [originAccessControlLogicalId, originAccessControl] = originAccessControls[0] ?? [];
  const [cloudFrontFunctionLogicalId] = cloudFrontFunctions[0] ?? [];
  validatePublicationControlUsage(
    template,
    {
      expectedLiteralPaths: [
        'Parameters.PublicationState#key',
        'Conditions.PublicationEnabled#key',
        'Conditions.PublicationEnabled.Fn::Equals.0.Ref',
        `Resources.${distributionLogicalId}.Properties.DistributionConfig.Enabled.Fn::If.0`,
        'Outputs.WebPublicationStatus.Value.Fn::If.0',
      ],
    },
    'E7_CLOUD_ASSEMBLY_INITIAL_WEB_PUBLICATION_INVALID',
  );
  const distributionConfig = distribution?.Properties?.DistributionConfig;
  const origins = distributionConfig?.Origins;
  const s3Origins = Array.isArray(origins)
    ? origins.filter((origin) => object(origin?.S3OriginConfig))
    : [];
  const customOrigins = Array.isArray(origins)
    ? origins.filter((origin) => object(origin?.CustomOriginConfig))
    : [];
  const webOrigin = s3Origins[0];
  const apiOrigin = customOrigins[0];
  const defaultBehavior = distributionConfig?.DefaultCacheBehavior;
  const cacheBehaviors = distributionConfig?.CacheBehaviors;
  const assetsBehaviors = Array.isArray(cacheBehaviors)
    ? cacheBehaviors.filter(({ PathPattern }) => PathPattern === 'assets/*')
    : [];
  const apiBehaviors = Array.isArray(cacheBehaviors)
    ? cacheBehaviors.filter(({ PathPattern }) => PathPattern === 'api/*')
    : [];
  const assetsBehavior = assetsBehaviors[0];
  const apiBehavior = apiBehaviors[0];
  const customDomain = context.config.domain.mode === 'CUSTOM_AUTHORIZED';
  const expectedBaseUrl = customDomain
    ? `https://${context.config.domain.hostname}`
    : {
        'Fn::Join': ['', ['https://', { 'Fn::GetAtt': [distributionLogicalId, 'DomainName'] }]],
      };
  const expectedOutput = (suffix) =>
    customDomain
      ? `${expectedBaseUrl}${suffix}`
      : {
          'Fn::Join': [
            '',
            [
              'https://',
              { 'Fn::GetAtt': [distributionLogicalId, 'DomainName'] },
              ...(suffix === '' ? [] : [suffix]),
            ],
          ],
        };
  const outputs = template?.Outputs;
  const expectedOriginAccessControlConfig =
    originAccessControl?.Properties?.OriginAccessControlConfig;
  const responseHeadersPolicyLogicalIds = responseHeadersPolicies.map(([logicalId]) => logicalId);
  const behaviorResponseHeadersPolicyLogicalIds = [
    logicalReference(defaultBehavior?.ResponseHeadersPolicyId),
    logicalReference(assetsBehavior?.ResponseHeadersPolicyId),
    logicalReference(apiBehavior?.ResponseHeadersPolicyId),
  ];
  const expectedDnsAliasTarget = {
    DNSName: { 'Fn::GetAtt': [distributionLogicalId, 'DomainName'] },
    HostedZoneId: {
      'Fn::FindInMap': [
        'AWSCloudFrontPartitionHostedZoneIdMap',
        { Ref: 'AWS::Partition' },
        'zoneId',
      ],
    },
  };
  const bucketPolicyStatements = bucketPolicy?.Properties?.PolicyDocument?.Statement;
  const expectedCloudFrontSourceArn = {
    'Fn::Join': [
      '',
      [
        'arn:',
        { Ref: 'AWS::Partition' },
        ':cloudfront::',
        { Ref: 'AWS::AccountId' },
        ':distribution/',
        { Ref: distributionLogicalId },
      ],
    ],
  };
  const expectedBucketObjectArn = {
    'Fn::Join': ['', [{ 'Fn::GetAtt': [bucketLogicalId, 'Arn'] }, '/*']],
  };
  const cloudFrontReadStatements = Array.isArray(bucketPolicyStatements)
    ? bucketPolicyStatements.filter(
        (statement) =>
          statement?.Effect === 'Allow' &&
          statement?.Principal?.Service === 'cloudfront.amazonaws.com',
      )
    : [];
  const bucketManagementStatements = Array.isArray(bucketPolicyStatements)
    ? bucketPolicyStatements.filter(
        (statement) =>
          statement?.Effect === 'Allow' &&
          statement?.Principal?.Service !== 'cloudfront.amazonaws.com',
      )
    : [];
  const expectedBucketResources = [
    { 'Fn::GetAtt': [bucketLogicalId, 'Arn'] },
    expectedBucketObjectArn,
  ];
  const prereleaseBucketManagementValid =
    context.scope === 'prerelease'
      ? bucketManagementStatements.length === 1 &&
        JSON.stringify(bucketManagementStatements[0]?.Action) ===
          JSON.stringify(['s3:PutBucketPolicy', 's3:GetBucket*', 's3:List*', 's3:DeleteObject*']) &&
        typeof logicalGetAtt(bucketManagementStatements[0]?.Principal?.AWS, 'Arn') === 'string' &&
        JSON.stringify(bucketManagementStatements[0]?.Resource) ===
          JSON.stringify(expectedBucketResources)
      : bucketManagementStatements.length === 0;
  const unsafeBucketAllow = Array.isArray(bucketPolicyStatements)
    ? bucketPolicyStatements.some((statement) => {
        if (statement?.Effect !== 'Allow') return false;
        const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
        const publicPrincipal = statement.Principal === '*' || statement.Principal?.AWS === '*';
        const objectReadOutsideCloudFront =
          statement.Principal?.Service !== 'cloudfront.amazonaws.com' &&
          actions.some((action) => action === 's3:GetObject' || action === 's3:*');
        return publicPrincipal || objectReadOutsideCloudFront;
      })
    : true;
  const bucketSecurityValid =
    bucketPolicies.length === 1 &&
    logicalReference(bucketPolicy?.Properties?.Bucket) === bucketLogicalId &&
    bucketPolicy?.Properties?.PolicyDocument?.Version === '2012-10-17' &&
    Array.isArray(bucketPolicyStatements) &&
    bucketPolicyStatements.length === (context.scope === 'prerelease' ? 3 : 2) &&
    cloudFrontReadStatements.length === 1 &&
    cloudFrontReadStatements[0]?.Action === 's3:GetObject' &&
    JSON.stringify(cloudFrontReadStatements[0]?.Condition) ===
      JSON.stringify({ StringEquals: { 'AWS:SourceArn': expectedCloudFrontSourceArn } }) &&
    JSON.stringify(cloudFrontReadStatements[0]?.Resource) ===
      JSON.stringify(expectedBucketObjectArn) &&
    prereleaseBucketManagementValid &&
    !unsafeBucketAllow &&
    bucketPolicyStatements.some(
      (statement) =>
        statement?.Effect === 'Deny' &&
        statement?.Action === 's3:*' &&
        statement?.Principal?.AWS === '*' &&
        statement?.Condition?.Bool?.['aws:SecureTransport'] === 'false',
    ) &&
    JSON.stringify(bucket?.Properties?.PublicAccessBlockConfiguration) ===
      JSON.stringify({
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      }) &&
    JSON.stringify(bucket?.Properties?.OwnershipControls) ===
      JSON.stringify({ Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] }) &&
    JSON.stringify(bucket?.Properties?.BucketEncryption) ===
      JSON.stringify({
        ServerSideEncryptionConfiguration: [
          { ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } },
        ],
      }) &&
    bucket?.Properties?.VersioningConfiguration?.Status === 'Enabled';
  const topologyValid =
    distributions.length === 1 &&
    buckets.length === 1 &&
    bucketSecurityValid &&
    originAccessControls.length === 1 &&
    cloudFrontFunctions.length === 1 &&
    responseHeadersPolicies.length === 3 &&
    Array.isArray(origins) &&
    origins.length === 2 &&
    s3Origins.length === 1 &&
    customOrigins.length === 1 &&
    typeof webOrigin?.Id === 'string' &&
    webOrigin.Id !== '' &&
    logicalGetAtt(webOrigin?.DomainName, 'RegionalDomainName') === bucketLogicalId &&
    JSON.stringify(webOrigin?.S3OriginConfig) === JSON.stringify({ OriginAccessIdentity: '' }) &&
    logicalGetAtt(webOrigin?.OriginAccessControlId, 'Id') === originAccessControlLogicalId &&
    expectedOriginAccessControlConfig?.OriginAccessControlOriginType === 's3' &&
    expectedOriginAccessControlConfig?.SigningBehavior === 'always' &&
    expectedOriginAccessControlConfig?.SigningProtocol === 'sigv4' &&
    validateWebApiOriginContract(context, distributionConfig) === apiOrigin &&
    Array.isArray(cacheBehaviors) &&
    cacheBehaviors.length === 2 &&
    assetsBehaviors.length === 1 &&
    apiBehaviors.length === 1 &&
    defaultBehavior?.TargetOriginId === webOrigin.Id &&
    defaultBehavior?.CachePolicyId === '4135ea2d-6df8-44a3-9df3-4b5a84be39ad' &&
    defaultBehavior?.Compress === true &&
    defaultBehavior?.ViewerProtocolPolicy === 'redirect-to-https' &&
    defaultBehavior?.AllowedMethods === undefined &&
    defaultBehavior?.OriginRequestPolicyId === undefined &&
    Array.isArray(defaultBehavior?.FunctionAssociations) &&
    defaultBehavior.FunctionAssociations.length === 1 &&
    defaultBehavior.FunctionAssociations[0]?.EventType === 'viewer-request' &&
    logicalGetAtt(defaultBehavior.FunctionAssociations[0]?.FunctionARN, 'FunctionARN') ===
      cloudFrontFunctionLogicalId &&
    assetsBehavior?.TargetOriginId === webOrigin.Id &&
    assetsBehavior?.CachePolicyId === '658327ea-f89d-4fab-a63d-7e88639e58f6' &&
    assetsBehavior?.Compress === true &&
    assetsBehavior?.ViewerProtocolPolicy === 'redirect-to-https' &&
    JSON.stringify(assetsBehavior?.AllowedMethods) === JSON.stringify(['GET', 'HEAD', 'OPTIONS']) &&
    assetsBehavior?.OriginRequestPolicyId === undefined &&
    assetsBehavior?.FunctionAssociations === undefined &&
    apiBehavior?.TargetOriginId === apiOrigin.Id &&
    apiBehavior?.CachePolicyId === '4135ea2d-6df8-44a3-9df3-4b5a84be39ad' &&
    apiBehavior?.OriginRequestPolicyId === 'b689b0a8-53d0-40ab-baf2-68738e2966ac' &&
    apiBehavior?.Compress === true &&
    apiBehavior?.ViewerProtocolPolicy === 'redirect-to-https' &&
    JSON.stringify(apiBehavior?.AllowedMethods) ===
      JSON.stringify(['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE']) &&
    apiBehavior?.FunctionAssociations === undefined &&
    new Set(behaviorResponseHeadersPolicyLogicalIds).size === 3 &&
    behaviorResponseHeadersPolicyLogicalIds.toSorted().join('\0') ===
      responseHeadersPolicyLogicalIds.toSorted().join('\0') &&
    distributionConfig?.DefaultRootObject === 'index.html' &&
    distributionConfig?.HttpVersion === 'http2and3' &&
    distributionConfig?.PriceClass === 'PriceClass_100' &&
    JSON.stringify(distributionConfig?.Enabled) ===
      JSON.stringify({ 'Fn::If': ['PublicationEnabled', true, false] });
  const domainValid = customDomain
    ? JSON.stringify(distributionConfig?.Aliases) ===
        JSON.stringify([context.config.domain.hostname]) &&
      distributionConfig?.ViewerCertificate?.AcmCertificateArn ===
        context.config.domain.webCertificateArn &&
      distributionConfig?.ViewerCertificate?.MinimumProtocolVersion === 'TLSv1.2_2021' &&
      distributionConfig?.ViewerCertificate?.SslSupportMethod === 'sni-only' &&
      dnsRecords.length === 2 &&
      dnsRecords
        .map(([, record]) => record.Properties?.Type)
        .toSorted()
        .join('\0') === ['A', 'AAAA'].join('\0') &&
      dnsRecords.every(([, record]) => {
        const properties = record.Properties;
        return (
          properties?.HostedZoneId === context.config.domain.hostedZoneId &&
          [context.config.domain.hostname, `${context.config.domain.hostname}.`].includes(
            properties?.Name,
          ) &&
          JSON.stringify(properties?.AliasTarget) === JSON.stringify(expectedDnsAliasTarget)
        );
      })
    : (distributionConfig?.Aliases === undefined || distributionConfig.Aliases.length === 0) &&
      JSON.stringify(distributionConfig?.ViewerCertificate) ===
        JSON.stringify({ CloudFrontDefaultCertificate: true }) &&
      dnsRecords.length === 0;
  const expectedParameterName = `/checkout-${context.config.environment}/public-origin`;
  const parameter = parameters[0]?.[1];
  const outputValid =
    object(outputs) &&
    JSON.stringify(outputs.ApplicationUrl?.Value) === JSON.stringify(expectedOutput('')) &&
    JSON.stringify(outputs.ApiUrl?.Value) === JSON.stringify(expectedOutput('/api')) &&
    JSON.stringify(outputs.ApiDocsUrl?.Value) === JSON.stringify(expectedOutput('/api/docs')) &&
    JSON.stringify(outputs.HealthUrl?.Value) ===
      JSON.stringify(expectedOutput('/api/health/ready')) &&
    outputs.PublicOriginParameterName?.Value === expectedParameterName &&
    logicalReference(outputs.WebBucketName?.Value) === bucketLogicalId &&
    logicalReference(outputs.DistributionId?.Value) === distributionLogicalId &&
    parameters.length === 1 &&
    parameter?.Properties?.Name === expectedParameterName &&
    parameter?.Properties?.Type === 'String' &&
    JSON.stringify(parameter?.Properties?.Value) === JSON.stringify(expectedOutput(''));
  if (!topologyValid || !domainValid || !outputValid) {
    fail('E7_CLOUD_ASSEMBLY_INITIAL_WEB_PUBLICATION_INVALID');
  }
  return {
    apiOrigin,
    behaviors: [defaultBehavior, ...cacheBehaviors],
    distributionConfig,
  };
};

const validateInitialApiPublicationContract = (context, template, dataTemplate) => {
  const outputs = template.Outputs;
  const resourceEntries = object(template.Resources) ? Object.entries(template.Resources) : [];
  const resources = resourceEntries.map(([, resource]) => resource);
  const publicationParameter = template.Parameters?.PublicationState;
  const publicationCondition = template.Conditions?.PublicationEnabled;
  const schedules = resourceEntries.filter(([, { Type }]) => Type === 'AWS::Scheduler::Schedule');
  const apis = resourceEntries.filter(([, { Type }]) => Type === 'AWS::ApiGatewayV2::Api');
  const integrations = resourceEntries.filter(
    ([, { Type }]) => Type === 'AWS::ApiGatewayV2::Integration',
  );
  const routes = resourceEntries.filter(([, { Type }]) => Type === 'AWS::ApiGatewayV2::Route');
  const stages = resourceEntries.filter(([, { Type }]) => Type === 'AWS::ApiGatewayV2::Stage');
  const mappings = resourceEntries.filter(
    ([, { Type }]) => Type === 'AWS::ApiGatewayV2::ApiMapping',
  );
  const domains = resourceEntries.filter(
    ([, { Type }]) => Type === 'AWS::ApiGatewayV2::DomainName',
  );
  const dnsRecords = resources.filter(({ Type }) => Type === 'AWS::Route53::RecordSet');
  const lambdaFunctions = resources.filter(({ Type }) => Type === 'AWS::Lambda::Function');
  const lambdaFunctionEntries = resourceEntries.filter(
    ([, { Type }]) => Type === 'AWS::Lambda::Function',
  );
  const lambdaVersionEntries = resourceEntries.filter(
    ([, { Type }]) => Type === 'AWS::Lambda::Version',
  );
  const lambdaAliasEntries = resourceEntries.filter(
    ([, { Type }]) => Type === 'AWS::Lambda::Alias',
  );
  const lambdaPermissions = resourceEntries.filter(
    ([, { Type }]) => Type === 'AWS::Lambda::Permission',
  );
  const iamPolicies = resourceEntries.filter(([, { Type }]) => Type === 'AWS::IAM::Policy');
  const runtimeFunctions = lambdaFunctions.filter(
    ({ Type, Properties }) =>
      Type === 'AWS::Lambda::Function' &&
      Properties?.Environment?.Variables?.PAYMENT_ADAPTER === 'sandbox',
  );
  const prerelease = context.scope === 'prerelease';
  const customDomain = context.config.domain.mode === 'CUSTOM_AUTHORIZED';
  const [apiLogicalId, api] = apis[0] ?? [];
  const [scheduleLogicalId] = schedules[0] ?? [];
  const [, stage] = stages[0] ?? [];
  const [domainLogicalId, domain] = domains[0] ?? [];
  const mapping = mappings[0]?.[1];
  const [mappingLogicalId] = mappings[0] ?? [];
  validatePublicationControlUsage(
    template,
    {
      expectedLiteralPaths: [
        'Parameters.PublicationState#key',
        'Conditions.PublicationEnabled#key',
        'Conditions.PublicationEnabled.Fn::Equals.0.Ref',
        `Resources.${apiLogicalId}.Properties.DisableExecuteApiEndpoint.Fn::If.0`,
        `Resources.${scheduleLogicalId}.Properties.State.Fn::If.0`,
        'Outputs.ApiPublicationStatus.Value.Fn::If.0',
        'Outputs.SchedulerStatus.Value.Fn::If.0',
        ...(customDomain ? [`Resources.${mappingLogicalId}.Condition`] : []),
      ],
    },
    'E7_CLOUD_ASSEMBLY_INITIAL_API_PUBLICATION_INVALID',
  );
  const domainConfiguration = domain?.Properties?.DomainNameConfigurations;
  const expectedDomainReference = { Ref: domainLogicalId };
  const expectedDomainName = context.config.domain.apiHostname;
  const expectedRuntimeSecretArn = runtimeSecretReference(context.config);
  const expectedRuntimeSecretVersionId = runtimeSecretVersionId(context.config);
  const expectedPublicOriginParameterName = `/checkout-${context.config.environment}/public-origin`;
  const dataResourceEntries = object(dataTemplate?.Resources)
    ? Object.entries(dataTemplate.Resources)
    : [];
  const dataTables = dataResourceEntries.filter(([, { Type }]) => Type === 'AWS::DynamoDB::Table');
  const [catalogTableLogicalId] =
    dataTables.find(
      ([, table]) =>
        table.Properties?.TableName === `checkout-${context.config.environment}-catalog`,
    ) ?? [];
  const [checkoutTableLogicalId] =
    dataTables.find(
      ([, table]) =>
        table.Properties?.TableName === `checkout-${context.config.environment}-checkout`,
    ) ?? [];
  const dataOutputs = object(dataTemplate?.Outputs) ? Object.values(dataTemplate.Outputs) : [];
  const exportNamesFor = (logicalId) =>
    dataOutputs
      .filter(
        (output) =>
          logicalReference(output?.Value) === logicalId && typeof output?.Export?.Name === 'string',
      )
      .map((output) => output.Export.Name);
  const catalogExportNames = exportNamesFor(catalogTableLogicalId);
  const checkoutExportNames = exportNamesFor(checkoutTableLogicalId);
  const dataBindingsValid =
    dataTables.length === 2 &&
    typeof catalogTableLogicalId === 'string' &&
    typeof checkoutTableLogicalId === 'string' &&
    catalogTableLogicalId !== checkoutTableLogicalId &&
    logicalReference(dataTemplate?.Outputs?.CatalogTableName?.Value) === catalogTableLogicalId &&
    logicalReference(dataTemplate?.Outputs?.CheckoutTableName?.Value) === checkoutTableLogicalId &&
    catalogExportNames.length === 1 &&
    checkoutExportNames.length === 1 &&
    catalogExportNames[0] !== checkoutExportNames[0];
  const expectedCatalogTableImport = { 'Fn::ImportValue': catalogExportNames[0] };
  const expectedCheckoutTableImport = { 'Fn::ImportValue': checkoutExportNames[0] };

  const apiAliasLogicalId = logicalReference(outputs?.ApiAliasArn?.Value);
  const workerAliasLogicalId = logicalReference(outputs?.WorkerAliasArn?.Value);
  const apiVersionLogicalId = logicalGetAtt(outputs?.ApiFunctionVersion?.Value, 'Version');
  const workerVersionLogicalId = logicalGetAtt(outputs?.WorkerFunctionVersion?.Value, 'Version');
  const aliasByLogicalId = new Map(lambdaAliasEntries);
  const versionByLogicalId = new Map(lambdaVersionEntries);
  const functionByLogicalId = new Map(lambdaFunctionEntries);
  const apiAlias = aliasByLogicalId.get(apiAliasLogicalId);
  const workerAlias = aliasByLogicalId.get(workerAliasLogicalId);
  const apiFunctionLogicalId = logicalReference(apiAlias?.Properties?.FunctionName);
  const workerFunctionLogicalId = logicalReference(workerAlias?.Properties?.FunctionName);
  const apiVersion = versionByLogicalId.get(apiVersionLogicalId);
  const workerVersion = versionByLogicalId.get(workerVersionLogicalId);
  const [integrationLogicalId, integration] = integrations[0] ?? [];
  const [, route] = routes[0] ?? [];
  const [, schedule] = schedules[0] ?? [];
  const schedulerRoleLogicalId = logicalGetAtt(schedule?.Properties?.Target?.RoleArn, 'Arn');
  const schedulerRole = resourceEntries.find(
    ([logicalId]) => logicalId === schedulerRoleLogicalId,
  )?.[1];
  const schedulerPolicies = iamPolicies.filter(([, policy]) =>
    policy.Properties?.Roles?.some(
      (roleReference) => logicalReference(roleReference) === schedulerRoleLogicalId,
    ),
  );
  const schedulerPolicyStatements =
    schedulerPolicies[0]?.[1]?.Properties?.PolicyDocument?.Statement;
  const apiPermission = lambdaPermissions[0]?.[1];
  const expectedApiPermissionSourceArn = {
    'Fn::Join': [
      '',
      [
        'arn:',
        { Ref: 'AWS::Partition' },
        `:execute-api:${context.config.aws.region}:`,
        { Ref: 'AWS::AccountId' },
        ':',
        { Ref: apiLogicalId },
        '/*/*/{proxy+}',
      ],
    ],
  };
  const apiRuntimeTopologyValid =
    lambdaFunctionEntries.length === 2 &&
    lambdaVersionEntries.length === 2 &&
    lambdaAliasEntries.length === 2 &&
    typeof apiAliasLogicalId === 'string' &&
    typeof workerAliasLogicalId === 'string' &&
    apiAliasLogicalId !== workerAliasLogicalId &&
    typeof apiVersionLogicalId === 'string' &&
    typeof workerVersionLogicalId === 'string' &&
    apiVersionLogicalId !== workerVersionLogicalId &&
    typeof apiFunctionLogicalId === 'string' &&
    typeof workerFunctionLogicalId === 'string' &&
    apiFunctionLogicalId !== workerFunctionLogicalId &&
    functionByLogicalId.has(apiFunctionLogicalId) &&
    functionByLogicalId.has(workerFunctionLogicalId) &&
    apiAlias?.Properties?.Name === 'live' &&
    workerAlias?.Properties?.Name === 'live' &&
    logicalGetAtt(apiAlias?.Properties?.FunctionVersion, 'Version') === apiVersionLogicalId &&
    logicalGetAtt(workerAlias?.Properties?.FunctionVersion, 'Version') === workerVersionLogicalId &&
    logicalReference(apiVersion?.Properties?.FunctionName) === apiFunctionLogicalId &&
    logicalReference(workerVersion?.Properties?.FunctionName) === workerFunctionLogicalId &&
    outputs?.ScheduleName?.Value === `checkout-${context.config.environment}-reconcile` &&
    logicalReference(outputs?.HttpApiId?.Value) === apiLogicalId &&
    integrations.length === 1 &&
    integration?.Properties?.IntegrationType === 'AWS_PROXY' &&
    integration?.Properties?.PayloadFormatVersion === '2.0' &&
    logicalReference(integration?.Properties?.ApiId) === apiLogicalId &&
    logicalReference(integration?.Properties?.IntegrationUri) === apiAliasLogicalId &&
    lambdaPermissions.length === 1 &&
    apiPermission?.Properties?.Action === 'lambda:InvokeFunction' &&
    logicalReference(apiPermission?.Properties?.FunctionName) === apiAliasLogicalId &&
    apiPermission?.Properties?.Principal === 'apigateway.amazonaws.com' &&
    JSON.stringify(apiPermission?.Properties?.SourceArn) ===
      JSON.stringify(expectedApiPermissionSourceArn) &&
    routes.length === 1 &&
    route?.Properties?.AuthorizationType === 'NONE' &&
    route?.Properties?.RouteKey === 'ANY /{proxy+}' &&
    logicalReference(route?.Properties?.ApiId) === apiLogicalId &&
    JSON.stringify(route?.Properties?.Target) ===
      JSON.stringify({
        'Fn::Join': ['', ['integrations/', { Ref: integrationLogicalId }]],
      }) &&
    schedule?.Properties?.Name === `checkout-${context.config.environment}-reconcile` &&
    schedule?.Properties?.ScheduleExpression === 'rate(1 minute)' &&
    schedule?.Properties?.FlexibleTimeWindow?.Mode === 'OFF' &&
    logicalReference(schedule?.Properties?.Target?.Arn) === workerAliasLogicalId &&
    schedule?.Properties?.Target?.Input === '{"action":"reconcile","mode":"sandbox"}' &&
    JSON.stringify(schedule?.Properties?.Target?.RetryPolicy) ===
      JSON.stringify({ MaximumEventAgeInSeconds: 300, MaximumRetryAttempts: 2 }) &&
    schedulerRole?.Type === 'AWS::IAM::Role' &&
    JSON.stringify(schedulerRole?.Properties?.AssumeRolePolicyDocument) ===
      JSON.stringify({
        Statement: [
          {
            Action: 'sts:AssumeRole',
            Effect: 'Allow',
            Principal: { Service: 'scheduler.amazonaws.com' },
          },
        ],
        Version: '2012-10-17',
      }) &&
    schedulerPolicies.length === 1 &&
    JSON.stringify(schedulerPolicyStatements) ===
      JSON.stringify([
        {
          Action: 'lambda:InvokeFunction',
          Effect: 'Allow',
          Resource: { Ref: workerAliasLogicalId },
          Sid: 'InvokeWorkerAlias',
        },
      ]);
  const expectedManagedApiOrigin = {
    'Fn::Join': [
      '',
      [
        'https://',
        { Ref: apiLogicalId },
        `.execute-api.${context.config.aws.region}.`,
        { Ref: 'AWS::URLSuffix' },
      ],
    ],
  };
  const customDomainResourcesValid = customDomain
    ? domains.length === 1 &&
      domain?.Condition === undefined &&
      domain?.Properties?.DomainName === expectedDomainName &&
      Array.isArray(domainConfiguration) &&
      domainConfiguration.length === 1 &&
      domainConfiguration[0]?.CertificateArn === context.config.domain.apiCertificateArn &&
      domainConfiguration[0]?.EndpointType === 'REGIONAL' &&
      domainConfiguration[0]?.SecurityPolicy === 'TLS_1_2' &&
      mappings.length === 1 &&
      mapping?.Condition === 'PublicationEnabled' &&
      JSON.stringify(mapping?.Properties?.ApiId) === JSON.stringify({ Ref: apiLogicalId }) &&
      JSON.stringify(mapping?.Properties?.DomainName) === JSON.stringify(expectedDomainReference) &&
      mapping?.Properties?.Stage === '$default' &&
      dnsRecords.length === 2 &&
      dnsRecords
        .map(({ Properties }) => Properties?.Type)
        .toSorted()
        .join('\0') === ['A', 'AAAA'].join('\0') &&
      dnsRecords.every(
        ({ Condition, Properties }) =>
          Condition === undefined &&
          [expectedDomainName, `${expectedDomainName}.`].includes(Properties?.Name) &&
          Properties?.HostedZoneId === context.config.domain.hostedZoneId &&
          JSON.stringify(Properties?.AliasTarget?.DNSName) ===
            JSON.stringify({ 'Fn::GetAtt': [domainLogicalId, 'RegionalDomainName'] }) &&
          JSON.stringify(Properties?.AliasTarget?.HostedZoneId) ===
            JSON.stringify({ 'Fn::GetAtt': [domainLogicalId, 'RegionalHostedZoneId'] }),
      ) &&
      outputs?.ApiCustomDomainName?.Value === expectedDomainName &&
      outputs?.ApiOriginUrl?.Value === `https://${expectedDomainName}`
    : domains.length === 0 &&
      mappings.length === 0 &&
      dnsRecords.length === 0 &&
      outputs?.ApiCustomDomainName?.Value === 'NONE_MANAGED_PRERELEASE' &&
      JSON.stringify(outputs?.ApiOriginUrl?.Value) === JSON.stringify(expectedManagedApiOrigin);
  if (
    publicationParameter?.Default !== 'DISABLED' ||
    JSON.stringify(publicationParameter?.AllowedValues) !==
      JSON.stringify(['DISABLED', 'ENABLED']) ||
    JSON.stringify(publicationCondition) !==
      JSON.stringify({ 'Fn::Equals': [{ Ref: 'PublicationState' }, 'ENABLED'] }) ||
    schedules.length !== 1 ||
    JSON.stringify(schedules[0]?.[1]?.Properties?.State) !==
      JSON.stringify({ 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] }) ||
    apis.length !== 1 ||
    stages.length !== 1 ||
    stage?.Properties?.StageName !== '$default' ||
    stage?.Properties?.AutoDeploy !== true ||
    JSON.stringify(stage?.Properties?.ApiId) !== JSON.stringify({ Ref: apiLogicalId }) ||
    api?.Properties?.ProtocolType !== 'HTTP' ||
    JSON.stringify(api?.Properties?.DisableExecuteApiEndpoint) !==
      JSON.stringify({ 'Fn::If': ['PublicationEnabled', customDomain, true] }) ||
    !customDomainResourcesValid ||
    !dataBindingsValid ||
    !apiRuntimeTopologyValid ||
    lambdaFunctions.length !== 2 ||
    runtimeFunctions.length !== 2 ||
    runtimeFunctions.some(
      ({ Properties }) =>
        Properties.Environment.Variables.APP_ENV !== 'assessment' ||
        Properties.Environment.Variables.AUTO_SEED_CATALOG !== 'false' ||
        Properties.Environment.Variables.CANDIDATE_SHA !== context.identity.candidateSha ||
        JSON.stringify(Properties.Environment.Variables.CATALOG_TABLE_NAME) !==
          JSON.stringify(expectedCatalogTableImport) ||
        JSON.stringify(Properties.Environment.Variables.CHECKOUT_TABLE_NAME) !==
          JSON.stringify(expectedCheckoutTableImport) ||
        Properties.Environment.Variables.DATA_ADAPTER !== 'dynamodb' ||
        Properties.Environment.Variables.PAYMENTS_ENABLED !== 'true' ||
        Properties.Environment.Variables.RELEASE_ID !== context.identity.releaseId ||
        Properties.Environment.Variables.RUNTIME_SECRET_ARN !== expectedRuntimeSecretArn ||
        Properties.Environment.Variables.RUNTIME_SECRET_VERSION_ID !==
          expectedRuntimeSecretVersionId ||
        Properties.Environment.Variables.SANDBOX_AUTHORIZED_UNTIL_UTC !==
          context.config.authorization.expiresAtUtc ||
        Properties.Environment.Variables.PRERELEASE_ACCESS_MODE !==
          (prerelease ? 'cloudfront_signed_cookie' : 'origin_gate') ||
        Properties.Environment.Variables.TOKENIZATION_MODE !== 'direct_jwe' ||
        Properties.Environment.Variables.ALLOWED_ORIGIN_PARAMETER_NAME !==
          expectedPublicOriginParameterName ||
        Properties.Environment.Variables.PUBLIC_ASSET_ORIGIN_PARAMETER_NAME !==
          expectedPublicOriginParameterName ||
        Properties.Handler !== 'index.handler' ||
        Properties.Runtime !== 'nodejs24.x' ||
        JSON.stringify(Properties.Architectures) !== JSON.stringify(['arm64']),
    ) ||
    JSON.stringify(outputs?.SchedulerStatus?.Value) !==
      JSON.stringify({ 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] }) ||
    JSON.stringify(outputs?.ApiPublicationStatus?.Value) !==
      JSON.stringify({ 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] })
  ) {
    fail('E7_CLOUD_ASSEMBLY_INITIAL_API_PUBLICATION_INVALID');
  }
};

const validateAssemblyIdentity = (context, assemblyPath, freezeManifestPath) => {
  const assembly = cloudAssemblyStacks(assemblyPath);
  const actualNames = assembly.stacks.map(({ artifactId }) => artifactId).toSorted();
  if (actualNames.join('\0') !== context.stacks.toSorted().join('\0')) {
    fail('E7_CLOUD_ASSEMBLY_STACK_SET_MISMATCH');
  }
  const dataTemplate = assembly.stacks.find(({ artifactId }) =>
    artifactId.endsWith('-data'),
  )?.template;
  const expectedTerminationProtection = context.scope !== 'prerelease';
  for (const { artifactId, tags, template, terminationProtection } of assembly.stacks) {
    const outputs = template.Outputs;
    if (
      !object(outputs) ||
      outputs.CandidateSha?.Value !== context.identity.candidateSha ||
      outputs.ReleaseId?.Value !== context.identity.releaseId
    ) {
      fail('E7_CLOUD_ASSEMBLY_IDENTITY_MISMATCH');
    }
    if (terminationProtection !== expectedTerminationProtection) {
      fail('E7_CLOUD_ASSEMBLY_TERMINATION_PROTECTION_INVALID');
    }
    if (
      tags.Project !== 'checkout' ||
      tags.ManagedBy !== 'cdk' ||
      tags.Environment !== context.config.environment ||
      tags.CandidateSha !== context.identity.candidateSha ||
      tags.ReleaseId !== context.identity.releaseId ||
      tags.ExpiresOn !== context.config.cleanup.expiresAtUtc.slice(0, 10) ||
      tags.CleanupExpiresAtUtc !== context.config.cleanup.expiresAtUtc
    ) {
      fail('E7_CLOUD_ASSEMBLY_STACK_TAGS_INVALID');
    }
    validateReleaseStackResourceAllowlist(context, artifactId, template);
    if (artifactId.endsWith('-api')) {
      validateInitialApiPublicationContract(context, template, dataTemplate);
    }
    if (artifactId.endsWith('-web')) {
      const publicationParameter = template.Parameters?.PublicationState;
      const publicationCondition = template.Conditions?.PublicationEnabled;
      const { apiOrigin, behaviors, distributionConfig } = validateInitialWebPublicationContract(
        context,
        template,
      );
      const originHeaders = apiOrigin?.OriginCustomHeaders ?? [];
      const prerelease = context.scope === 'prerelease';
      const secretReference = runtimeSecretReference(context.config);
      const expectedAccessBinding = sha256(
        [
          prerelease ? 'CLOUDFRONT_SIGNED_COOKIE' : 'ORIGIN_GATE_ONLY',
          context.config.prereleaseAccess.keyGroupId ?? 'NONE',
          context.config.prereleaseAccess.publicKeyId ?? 'NONE',
          secretReference,
          context.config.prereleaseAccess.originTokenSecretVersionId,
        ].join('\n'),
      );
      const prereleaseAccessValid = prerelease
        ? behaviors.length === 3 &&
          behaviors.every(
            (behavior) =>
              JSON.stringify(behavior?.TrustedKeyGroups) ===
              JSON.stringify([context.config.prereleaseAccess.keyGroupId]),
          ) &&
          originHeaders.length === 1 &&
          originHeaders[0]?.HeaderName === 'x-stage7-origin-verify' &&
          originHeaders[0]?.HeaderValue ===
            `{{resolve:secretsmanager:${secretReference}:SecretString:prereleaseOriginToken::${context.config.prereleaseAccess.originTokenSecretVersionId}}}`
        : behaviors.every((behavior) => behavior?.TrustedKeyGroups === undefined) &&
          originHeaders.length === 1 &&
          originHeaders[0]?.HeaderName === 'x-stage7-origin-verify' &&
          originHeaders[0]?.HeaderValue ===
            `{{resolve:secretsmanager:${secretReference}:SecretString:prereleaseOriginToken::${context.config.prereleaseAccess.originTokenSecretVersionId}}}`;
      if (
        publicationParameter?.Default !== 'DISABLED' ||
        JSON.stringify(publicationParameter?.AllowedValues) !==
          JSON.stringify(['DISABLED', 'ENABLED']) ||
        JSON.stringify(publicationCondition) !==
          JSON.stringify({ 'Fn::Equals': [{ Ref: 'PublicationState' }, 'ENABLED'] }) ||
        JSON.stringify(distributionConfig?.Enabled) !==
          JSON.stringify({ 'Fn::If': ['PublicationEnabled', true, false] }) ||
        !prereleaseAccessValid ||
        outputs.PrereleaseAccessBindingSha256?.Value !== expectedAccessBinding ||
        JSON.stringify(outputs.WebPublicationStatus?.Value) !==
          JSON.stringify({ 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] })
      ) {
        fail('E7_CLOUD_ASSEMBLY_INITIAL_WEB_PUBLICATION_INVALID');
      }
    }
    if (!context.config.authorization.stacks.includes(artifactId)) {
      fail('E7_CLOUD_ASSEMBLY_STACK_NOT_AUTHORIZED');
    }
    if (
      artifactId === `checkout-${context.config.environment}-observability` &&
      outputs.BudgetContract?.Value !== budgetContract(context.config)
    ) {
      fail('E7_CLOUD_ASSEMBLY_BUDGET_MISMATCH');
    }
  }
  let freezeManifestSha256 = null;
  if (freezeManifestPath !== undefined) {
    const freeze = validateFreezeManifest(
      readStrictJsonFile(freezeManifestPath, { scanForbiddenData: false, validateConfig: false }),
    );
    if (
      freeze.candidateSha !== context.identity.candidateSha ||
      freeze.releaseId !== context.identity.releaseId ||
      freeze.environment !== context.config.environment ||
      freeze.region !== context.config.aws.region ||
      freeze.authorizationScope !== context.config.authorization.scope
    ) {
      fail('E7_FREEZE_OPERATION_IDENTITY_MISMATCH');
    }
    frozenAwsCliVersion(context, freeze.toolchain.awsCli);
    const expectedIac = freeze.artifacts.find(({ name }) => name === 'iac');
    if (expectedIac === undefined || hashArtifactPath(assembly.app).sha256 !== expectedIac.sha256) {
      fail('E7_FROZEN_ASSEMBLY_DIGEST_MISMATCH');
    }
    freezeManifestSha256 = freeze.manifestSha256;
  }
  return {
    ...assembly,
    assemblySha256: hashArtifactPath(assembly.app).sha256,
    freezeManifestSha256,
  };
};

const evidenceRoot = (config) =>
  path.join(
    workspaceRoot,
    DEFAULT_OUTPUT_ROOT,
    config.authorization.scope === 'EPHEMERAL_PRERELEASE' ? 'stage-7-prerelease' : 'stage-7',
  );

const internalRoot = (config) =>
  path.join(workspaceRoot, DEFAULT_INTERNAL_ROOT, config.environment);

const evidenceTarget = (context, kind) => {
  if (context.config.authorization.scope === 'EPHEMERAL_PRERELEASE') {
    if (['data', 'api', 'observability', 'web', 'seed', 'expiry-registration'].includes(kind)) {
      return path.join(evidenceRoot(context.config), 'deployment.json');
    }
  }
  const filenames = {
    synth: 'infra-synth.json',
    diff: 'infra-diff.json',
    data: 'data.json',
    seed: 'data.json',
    api: 'api.json',
    observability: 'observability.json',
    web: 'web.json',
    activation: 'activation.json',
    drift: 'drift.json',
    rollback: 'rollback.json',
    cleanup: 'cleanup.json',
    'expiry-registration': 'cleanup.json',
  };
  return path.join(evidenceRoot(context.config), filenames[kind]);
};

const baseEvidence = (context) => ({
  schemaVersion: 1,
  stage: 7,
  ...(context.scope === 'prerelease'
    ? { kind: 'PRERELEASE_DEPLOYMENT_LEDGER', scope: 'prerelease' }
    : {}),
  environment: context.config.environment,
  authorizationId: context.config.authorization.id,
  authorizationScope: context.config.authorization.scope,
  configSha256: objectSha256(context.config),
  releaseId: context.identity.releaseId,
  candidateSha: context.identity.candidateSha,
  region: context.config.aws.region,
  status: 'IN_PROGRESS',
  checkpoints: {},
  containsSensitiveData: false,
});

const updateEvidence = async (context, kind, checkpoint, value) => {
  const target = evidenceTarget(context, kind);
  let current = baseEvidence(context);
  if (existsSync(target)) {
    const parsed = strictJson(readFileSync(target, 'utf8'), 'E7_EVIDENCE_INVALID');
    if (
      parsed?.schemaVersion !== 1 ||
      parsed?.stage !== 7 ||
      parsed?.environment !== context.config.environment ||
      parsed?.releaseId !== context.identity.releaseId ||
      parsed?.candidateSha !== context.identity.candidateSha ||
      parsed?.configSha256 !== objectSha256(context.config) ||
      parsed?.containsSensitiveData !== false ||
      !object(parsed.checkpoints)
    ) {
      fail('E7_EVIDENCE_IDENTITY_MISMATCH');
    }
    current = parsed;
  }
  const next = {
    ...current,
    status: current.status === 'PASS' ? 'PASS' : 'IN_PROGRESS',
    checkpoints: {
      ...current.checkpoints,
      [checkpoint]: value,
    },
    updatedAtUtc: utc(context.now),
  };
  await writeSanitizedJsonAtomic(target, path.basename(target), next);
  return next;
};

const finalizePrereleaseDeploymentEvidence = async (context) => {
  if (context.scope !== 'prerelease') fail('E7_PRERELEASE_EVIDENCE_SCOPE_INVALID');
  const target = evidenceTarget(context, 'expiry-registration');
  const source = readJson(target, 'E7_PRERELEASE_DEPLOYMENT_EVIDENCE_MISSING');
  const checkpoints = source?.checkpoints;
  const applicationUrl = checkpoints?.web?.outputs?.ApplicationUrl;
  const origin = assertExactHttpsOrigin(applicationUrl);
  if (
    checkpoints?.data?.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    checkpoints?.api?.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    checkpoints?.observability?.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    checkpoints?.web?.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    checkpoints?.seed?.decision !== 'PASS' ||
    checkpoints?.seed?.secondExecution !== 'EXISTS' ||
    checkpoints?.expiryRegistration?.decision !== 'EXPIRY_REGISTERED' ||
    checkpoints?.api?.outputs?.SchedulerStatus !== 'DISABLED' ||
    checkpoints?.api?.outputs?.ApiPublicationStatus !== 'DISABLED' ||
    checkpoints?.web?.outputs?.WebPublicationStatus !== 'DISABLED' ||
    checkpoints?.data?.releaseMode !== 'INITIAL' ||
    checkpoints?.api?.releaseMode !== 'INITIAL' ||
    checkpoints?.observability?.releaseMode !== 'INITIAL' ||
    checkpoints?.web?.releaseMode !== 'INITIAL'
  ) {
    fail('E7_PRERELEASE_DEPLOYMENT_EVIDENCE_INCOMPLETE');
  }
  const finalized = {
    ...source,
    status: 'PASS',
    scope: 'prerelease',
    applicationUrl: origin,
    urls: { application: origin },
    nonPublic: true,
    syntheticOnly: true,
    published: false,
    schedulerEnabled: false,
    updatedAtUtc: utc(context.now),
  };
  await writeSanitizedJsonAtomic(target, path.basename(target), finalized);
  return finalized;
};

const sanitizedOutput = (value, accountId) => {
  if (typeof value !== 'string') return value;
  return value.replaceAll(accountId, `[ACCOUNT-${accountId.slice(-4)}]`);
};

const sanitizeStackOutputs = (outputs, accountId) =>
  Object.fromEntries(
    Object.entries(outputs)
      .toSorted(([left], [right]) => left.localeCompare(right))
      .map(([key, value]) => [key, sanitizedOutput(value, accountId)]),
  );

const outputObjectForStack = (raw, stackName) => {
  if (!object(raw) || Object.keys(raw).length !== 1 || !object(raw[stackName])) {
    fail('E7_CDK_OUTPUT_CONTRACT_INVALID');
  }
  return raw[stackName];
};

const stackSuffix = (stackName) => stackName.slice(stackName.lastIndexOf('-') + 1);

const stackFor = (context, suffix) => {
  const stack = `checkout-${context.config.environment}-${suffix}`;
  if (!context.stacks.includes(stack)) fail('E7_OPERATION_STACK_NOT_AUTHORIZED');
  return stack;
};

const describeStack = (context, stackName, { allowMissing = false } = {}) => {
  const arguments_ = [
    'cloudformation',
    'describe-stacks',
    '--stack-name',
    stackName,
    '--output',
    'json',
    '--region',
    context.config.aws.region,
    '--no-cli-pager',
  ];
  const result = context.executor({
    command: context.awsCommand,
    args: arguments_,
    cwd: workspaceRoot,
    env: context.childEnvironment,
  });
  if (!object(result) || typeof result.stdout !== 'string') {
    fail('E7_CLOUDFORMATION_DESCRIBE_FAILED');
  }
  if (result.status !== 0) {
    const errorText = `${result.stderr ?? ''}\n${result.stdout}`;
    if (
      allowMissing &&
      /ValidationError/iu.test(errorText) &&
      /does not exist/iu.test(errorText) &&
      errorText.includes(stackName)
    ) {
      return {
        exists: false,
        outputs: {},
        parameters: {},
        tags: {},
        stackStatus: 'NOT_FOUND',
        stackId: null,
        creationTime: null,
        lastUpdatedTime: null,
        terminationProtection: null,
      };
    }
    fail('E7_CLOUDFORMATION_DESCRIBE_FAILED');
  }
  const response = strictJson(result.stdout, 'E7_CLOUDFORMATION_DESCRIBE_FAILED');
  const stacks = response?.Stacks;
  if (!Array.isArray(stacks) || stacks.length !== 1 || stacks[0]?.StackName !== stackName) {
    fail('E7_CLOUDFORMATION_STACK_IDENTITY_INVALID');
  }
  const stack = stacks[0];
  const stackArnPrefix = `arn:aws:cloudformation:${context.config.aws.region}:${context.config.aws.accountId}:stack/${stackName}/`;
  if (
    typeof stack.StackId !== 'string' ||
    !stack.StackId.startsWith(stackArnPrefix) ||
    typeof stack.StackStatus !== 'string' ||
    !/^[A-Z][A-Z0-9_]{2,63}$/u.test(stack.StackStatus) ||
    typeof stack.CreationTime !== 'string' ||
    Number.isNaN(Date.parse(stack.CreationTime)) ||
    (stack.LastUpdatedTime !== undefined &&
      (typeof stack.LastUpdatedTime !== 'string' ||
        Number.isNaN(Date.parse(stack.LastUpdatedTime)))) ||
    typeof stack.EnableTerminationProtection !== 'boolean'
  ) {
    fail('E7_CLOUDFORMATION_STACK_METADATA_INVALID');
  }
  const entries = stack.Outputs ?? [];
  if (
    !Array.isArray(entries) ||
    entries.some(
      ({ OutputKey, OutputValue }) =>
        typeof OutputKey !== 'string' ||
        OutputKey === '' ||
        typeof OutputValue !== 'string' ||
        OutputValue === '',
    ) ||
    new Set(entries.map(({ OutputKey }) => OutputKey)).size !== entries.length
  ) {
    fail('E7_CLOUDFORMATION_STACK_OUTPUTS_INVALID');
  }
  const outputs = Object.fromEntries(
    entries.map(({ OutputKey, OutputValue }) => [OutputKey, OutputValue]),
  );
  const parameterEntries = stack.Parameters ?? [];
  if (
    !Array.isArray(parameterEntries) ||
    parameterEntries.some(
      ({ ParameterKey, ParameterValue }) =>
        typeof ParameterKey !== 'string' ||
        ParameterKey === '' ||
        typeof ParameterValue !== 'string' ||
        ParameterValue === '',
    ) ||
    new Set(parameterEntries.map(({ ParameterKey }) => ParameterKey)).size !==
      parameterEntries.length
  ) {
    fail('E7_CLOUDFORMATION_STACK_PARAMETERS_INVALID');
  }
  const parameters = Object.fromEntries(
    parameterEntries.map(({ ParameterKey, ParameterValue }) => [ParameterKey, ParameterValue]),
  );
  const tagEntries = stack.Tags ?? [];
  if (
    !Array.isArray(tagEntries) ||
    tagEntries.some(
      ({ Key, Value }) =>
        typeof Key !== 'string' || Key === '' || typeof Value !== 'string' || Value === '',
    ) ||
    new Set(tagEntries.map(({ Key }) => Key)).size !== tagEntries.length
  ) {
    fail('E7_CLOUDFORMATION_STACK_TAGS_INVALID');
  }
  const tags = Object.fromEntries(tagEntries.map(({ Key, Value }) => [Key, Value]));
  return {
    exists: true,
    outputs,
    parameters,
    tags,
    stackStatus: stack.StackStatus,
    stackId: stack.StackId,
    creationTime: new Date(stack.CreationTime).toISOString(),
    lastUpdatedTime:
      stack.LastUpdatedTime === undefined ? null : new Date(stack.LastUpdatedTime).toISOString(),
    terminationProtection: stack.EnableTerminationProtection,
  };
};

const stackStateFingerprint = (stackName, state) =>
  jsonSha256({
    stackName,
    exists: state.exists,
    stackStatus: state.stackStatus,
    stackId: state.stackId,
    creationTime: state.creationTime,
    lastUpdatedTime: state.lastUpdatedTime,
    terminationProtection: state.terminationProtection,
    parametersSha256: objectSha256(state.parameters ?? {}),
    outputsSha256: objectSha256(state.outputs ?? {}),
    tagsSha256: objectSha256(state.tags ?? {}),
  });

const assemblyTemplateSha256 = (assembly, stackName) => {
  const stack = assembly.stacks.find(({ artifactId }) => artifactId === stackName);
  if (stack === undefined || !object(stack.template)) {
    fail('E7_CLOUD_ASSEMBLY_STACK_TEMPLATE_INVALID');
  }
  return objectSha256(stack.template);
};

const originalStackTemplateSha256 = (context, stackName) => {
  const response = awsJson(
    context,
    ['cloudformation', 'get-template', '--stack-name', stackName, '--template-stage', 'Original'],
    'E7_CLOUDFORMATION_ORIGINAL_TEMPLATE_READ_FAILED',
  );
  if (!object(response) || !object(response.TemplateBody)) {
    fail('E7_CLOUDFORMATION_ORIGINAL_TEMPLATE_INVALID');
  }
  return objectSha256(response.TemplateBody);
};

const validateOriginalStackTemplate = (context, stackName, expectedSha256) => {
  if (
    !SHA256.test(expectedSha256 ?? '') ||
    originalStackTemplateSha256(context, stackName) !== expectedSha256
  ) {
    fail('E7_CLOUDFORMATION_ORIGINAL_TEMPLATE_DRIFT');
  }
  return expectedSha256;
};

const publicationStateForStack = (context, suffix) => {
  if (!['api', 'web'].includes(suffix)) fail('E7_PUBLICATION_STACK_INVALID');
  const stackName = stackFor(context, suffix);
  const state = describeStack(context, stackName);
  const publicationState = state.parameters.PublicationState;
  const outputKey = suffix === 'api' ? 'ApiPublicationStatus' : 'WebPublicationStatus';
  if (
    !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus) ||
    !['DISABLED', 'ENABLED'].includes(publicationState) ||
    state.outputs[outputKey] !== publicationState ||
    state.outputs.CandidateSha !== context.identity.candidateSha ||
    state.outputs.ReleaseId !== context.identity.releaseId
  ) {
    fail('E7_PUBLICATION_STACK_STATE_INVALID');
  }
  return { publicationState, stackName, state };
};

const updatePublicationStack = (
  context,
  suffix,
  targetState,
  { expectedBeforeStateSha256, expectedTemplateSha256, clientRequestToken } = {},
) => {
  if (!['DISABLED', 'ENABLED'].includes(targetState)) {
    fail('E7_PUBLICATION_STATE_INVALID');
  }
  const before = publicationStateForStack(context, suffix);
  if (
    expectedBeforeStateSha256 !== undefined &&
    stackStateFingerprint(before.stackName, before.state) !== expectedBeforeStateSha256
  ) {
    fail('E7_PUBLICATION_STACK_PRECONDITION_CHANGED');
  }
  if (expectedTemplateSha256 !== undefined) {
    validateOriginalStackTemplate(context, before.state.stackId, expectedTemplateSha256);
  }
  if (
    clientRequestToken !== undefined &&
    !CLOUDFORMATION_CLIENT_REQUEST_TOKEN.test(clientRequestToken)
  ) {
    fail('E7_PUBLICATION_STACK_CLIENT_REQUEST_TOKEN_INVALID');
  }
  if (before.publicationState === targetState) {
    return {
      changed: false,
      previousState: before.publicationState,
      state: targetState,
      stackIdSha256: sha256(before.state.stackId),
      stackName: before.stackName,
    };
  }
  const updateArguments = [
    'cloudformation',
    'update-stack',
    '--stack-name',
    before.state.stackId,
    '--use-previous-template',
    '--parameters',
    `ParameterKey=PublicationState,ParameterValue=${targetState}`,
    '--capabilities',
    'CAPABILITY_NAMED_IAM',
    ...(clientRequestToken === undefined ? [] : ['--client-request-token', clientRequestToken]),
  ];
  const response = awsJson(context, updateArguments, 'E7_PUBLICATION_STACK_UPDATE_FAILED');
  if (response?.StackId !== before.state.stackId) {
    fail('E7_PUBLICATION_STACK_UPDATE_INVALID');
  }
  aws(
    context,
    ['cloudformation', 'wait', 'stack-update-complete', '--stack-name', before.state.stackId],
    'E7_PUBLICATION_STACK_WAIT_FAILED',
  );
  const after = publicationStateForStack(context, suffix);
  if (
    after.state.stackId !== before.state.stackId ||
    after.publicationState !== targetState ||
    after.state.lastUpdatedTime === before.state.lastUpdatedTime
  ) {
    fail('E7_PUBLICATION_STACK_STATE_NOT_APPLIED');
  }
  return {
    changed: true,
    previousState: before.publicationState,
    state: targetState,
    stackIdSha256: sha256(after.state.stackId),
    stackName: after.stackName,
  };
};

const initialRollbackCode = (suffix, reason) => {
  if (!['api', 'web'].includes(suffix) || !/^[A-Z_]{3,64}$/u.test(reason)) {
    fail('E7_INITIAL_ROLLBACK_COMPONENT_INVALID');
  }
  return `E7_INITIAL_${suffix.toUpperCase()}_ROLLBACK_${reason}`;
};

const rollbackEvidenceSource = (context, { allowMissing = false } = {}) => {
  const target = evidenceTarget(context, 'rollback');
  if (!existsSync(target)) {
    if (allowMissing) return null;
    fail('E7_INITIAL_ROLLBACK_EVIDENCE_MISSING');
  }
  const source = readJson(target, 'E7_INITIAL_ROLLBACK_EVIDENCE_INVALID');
  if (
    source?.schemaVersion !== 1 ||
    source?.stage !== 7 ||
    source?.environment !== context.config.environment ||
    source?.releaseId !== context.identity.releaseId ||
    source?.candidateSha !== context.identity.candidateSha ||
    source?.configSha256 !== objectSha256(context.config) ||
    source?.containsSensitiveData !== false ||
    !object(source.checkpoints)
  ) {
    fail('E7_INITIAL_ROLLBACK_EVIDENCE_INVALID');
  }
  return source;
};

const initialRollbackIntentCheckpoint = (suffix) => `${suffix}RollbackIntent`;

const createInitialRollbackIntent = ({ context, suffix, record, observed }) => ({
  decision: 'INITIAL_RELEASE_PUBLICATION_DISABLE_INTENT',
  releaseMode: 'INITIAL',
  component: suffix.toUpperCase(),
  candidateSha: context.identity.candidateSha,
  releaseId: context.identity.releaseId,
  configSha256: objectSha256(context.config),
  rollbackRecordSha256: record.recordSha256,
  stackName: observed.stackName,
  stackIdSha256: sha256(observed.state.stackId),
  preTransitionStateSha256: stackStateFingerprint(observed.stackName, observed.state),
  persistedAtUtc: utc(context.now),
  previousState: 'ENABLED',
  targetState: 'DISABLED',
});

const validateInitialRollbackIntent = ({
  context,
  suffix,
  record,
  observed,
  intent,
  requirePreTransitionState,
}) => {
  const code = initialRollbackCode(suffix, 'RESUME_INTENT_INVALID');
  if (
    !exactKeys(intent, [
      'decision',
      'releaseMode',
      'component',
      'candidateSha',
      'releaseId',
      'configSha256',
      'rollbackRecordSha256',
      'stackName',
      'stackIdSha256',
      'preTransitionStateSha256',
      'persistedAtUtc',
      'previousState',
      'targetState',
    ]) ||
    intent.decision !== 'INITIAL_RELEASE_PUBLICATION_DISABLE_INTENT' ||
    intent.releaseMode !== 'INITIAL' ||
    intent.component !== suffix.toUpperCase() ||
    intent.candidateSha !== context.identity.candidateSha ||
    intent.releaseId !== context.identity.releaseId ||
    intent.configSha256 !== objectSha256(context.config) ||
    !SHA256.test(record?.recordSha256 ?? '') ||
    intent.rollbackRecordSha256 !== record.recordSha256 ||
    intent.stackName !== observed.stackName ||
    intent.stackIdSha256 !== sha256(observed.state.stackId) ||
    !SHA256.test(intent.preTransitionStateSha256 ?? '') ||
    !canonicalUtc(intent.persistedAtUtc) ||
    Date.parse(intent.persistedAtUtc) >
      context.now.getTime() + INITIAL_ROLLBACK_EVENT_CLOCK_SKEW_MS ||
    intent.previousState !== 'ENABLED' ||
    intent.targetState !== 'DISABLED' ||
    (requirePreTransitionState &&
      intent.preTransitionStateSha256 !== stackStateFingerprint(observed.stackName, observed.state))
  ) {
    fail(code);
  }
  return intent;
};

const persistInitialRollbackIntent = async ({ context, suffix, record, observed }) => {
  const checkpoint = initialRollbackIntentCheckpoint(suffix);
  const source = rollbackEvidenceSource(context, { allowMissing: true });
  const expected = createInitialRollbackIntent({ context, suffix, record, observed });
  const existing = source?.checkpoints?.[checkpoint];
  if (existing !== undefined) {
    validateInitialRollbackIntent({
      context,
      suffix,
      record,
      observed,
      intent: existing,
      requirePreTransitionState: true,
    });
    return existing;
  }
  await updateEvidence(context, 'rollback', checkpoint, expected);
  const persisted = rollbackEvidenceSource(context)?.checkpoints?.[checkpoint];
  validateInitialRollbackIntent({
    context,
    suffix,
    record,
    observed,
    intent: persisted,
    requirePreTransitionState: true,
  });
  if (objectSha256(persisted) !== objectSha256(expected)) {
    fail(initialRollbackCode(suffix, 'RESUME_INTENT_PERSISTENCE_INVALID'));
  }
  return persisted;
};

const initialRollbackRequestBinding = ({ context, suffix, record, observed }) => ({
  component: suffix.toUpperCase(),
  candidateSha: context.identity.candidateSha,
  releaseId: context.identity.releaseId,
  configSha256: objectSha256(context.config),
  rollbackRecordSha256: record.recordSha256,
  stackName: observed.stackName,
  stackIdSha256: sha256(observed.state.stackId),
  previousState: 'ENABLED',
  targetState: 'DISABLED',
});

const initialRollbackClientRequestToken = ({ context, suffix, record, observed }) => {
  const requestSha256 = objectSha256(
    initialRollbackRequestBinding({ context, suffix, record, observed }),
  );
  const token = `e7-initial-${suffix}-${requestSha256}`;
  if (!CLOUDFORMATION_CLIENT_REQUEST_TOKEN.test(token)) {
    fail(initialRollbackCode(suffix, 'CLIENT_REQUEST_TOKEN_INVALID'));
  }
  return token;
};

const readInitialRollbackStackEventsPage = ({ context, suffix, observed, nextToken }) =>
  awsJson(
    context,
    [
      'cloudformation',
      'describe-stack-events',
      '--stack-name',
      observed.stackName,
      '--no-paginate',
      ...(nextToken === undefined ? [] : ['--next-token', nextToken]),
    ],
    initialRollbackCode(suffix, 'STACK_EVENTS_UNAVAILABLE'),
  );

const captureInitialRollbackCausality = ({
  context,
  suffix,
  observed,
  intent,
  clientRequestToken,
  readPage = readInitialRollbackStackEventsPage,
}) => {
  const eventsById = new Map();
  const seenTokens = new Set();
  let nextToken;
  let completed = false;
  for (let page = 0; page < 20; page += 1) {
    const response = readPage({ context, suffix, observed, nextToken });
    if (!Array.isArray(response?.StackEvents) || response.StackEvents.length > 1000) {
      fail(initialRollbackCode(suffix, 'STACK_EVENTS_INVALID'));
    }
    for (const event of response.StackEvents) {
      if (
        !object(event) ||
        typeof event.EventId !== 'string' ||
        event.EventId.length === 0 ||
        event.EventId.length > 1024
      ) {
        fail(initialRollbackCode(suffix, 'STACK_EVENTS_INVALID'));
      }
      const digest = objectSha256(event);
      const prior = eventsById.get(event.EventId);
      if (prior !== undefined && prior.digest !== digest) {
        fail(initialRollbackCode(suffix, 'STACK_EVENT_ID_COLLISION'));
      }
      if (prior === undefined) eventsById.set(event.EventId, { digest, event });
      if (eventsById.size > 5000) fail(initialRollbackCode(suffix, 'STACK_EVENTS_OVERFLOW'));
    }
    const responseToken = response.NextToken;
    if (responseToken === undefined) {
      completed = true;
      break;
    }
    const tokenContainsControlCharacter =
      typeof responseToken === 'string' &&
      [...responseToken].some((character) => {
        const codePoint = character.codePointAt(0);
        return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
      });
    if (
      typeof responseToken !== 'string' ||
      responseToken.length === 0 ||
      responseToken.length > 2048 ||
      tokenContainsControlCharacter ||
      seenTokens.has(responseToken)
    ) {
      fail(initialRollbackCode(suffix, 'STACK_EVENTS_PAGINATION_INVALID'));
    }
    seenTokens.add(responseToken);
    nextToken = responseToken;
  }
  if (!completed) fail(initialRollbackCode(suffix, 'STACK_EVENTS_PAGINATION_OVERFLOW'));

  const rootEvents = [...eventsById.values()]
    .map(({ event }) => event)
    .filter(
      (event) =>
        event?.StackId === observed.state.stackId &&
        event?.StackName === observed.stackName &&
        event?.LogicalResourceId === observed.stackName &&
        event?.PhysicalResourceId === observed.state.stackId &&
        event?.ResourceType === 'AWS::CloudFormation::Stack',
    );
  const matching = rootEvents.filter((event) => event?.ClientRequestToken === clientRequestToken);
  const started = matching.filter(({ ResourceStatus }) => ResourceStatus === 'UPDATE_IN_PROGRESS');
  const completedEvents = matching.filter(
    ({ ResourceStatus }) => ResourceStatus === 'UPDATE_COMPLETE',
  );
  const startedAt = new Date(started[0]?.Timestamp ?? 'invalid');
  const completedAt = new Date(completedEvents[0]?.Timestamp ?? 'invalid');
  const observedUpdatedAt = new Date(observed?.state?.lastUpdatedTime ?? 'invalid');
  const intentPersistedAt = new Date(intent?.persistedAtUtc ?? 'invalid');
  if (
    started.length !== 1 ||
    completedEvents.length !== 1 ||
    typeof started[0]?.EventId !== 'string' ||
    started[0].EventId.length === 0 ||
    typeof completedEvents[0]?.EventId !== 'string' ||
    completedEvents[0].EventId.length === 0 ||
    Number.isNaN(startedAt.getTime()) ||
    Number.isNaN(completedAt.getTime()) ||
    Number.isNaN(observedUpdatedAt.getTime()) ||
    Number.isNaN(intentPersistedAt.getTime()) ||
    startedAt.getTime() > completedAt.getTime() ||
    observedUpdatedAt.getTime() < startedAt.getTime() ||
    observedUpdatedAt.getTime() > completedAt.getTime() ||
    startedAt.getTime() + INITIAL_ROLLBACK_EVENT_CLOCK_SKEW_MS < intentPersistedAt.getTime()
  ) {
    fail(initialRollbackCode(suffix, 'STACK_EVENT_CAUSALITY_INVALID'));
  }
  const hasLaterOrAmbiguousRootEvent = rootEvents.some((event) => {
    if (event.EventId === completedEvents[0].EventId) return false;
    const timestamp = new Date(event.Timestamp ?? 'invalid');
    if (Number.isNaN(timestamp.getTime())) {
      fail(initialRollbackCode(suffix, 'STACK_EVENTS_INVALID'));
    }
    return timestamp.getTime() >= completedAt.getTime();
  });
  if (hasLaterOrAmbiguousRootEvent) {
    fail(initialRollbackCode(suffix, 'STACK_EVENT_CAUSALITY_INVALID'));
  }
  return {
    provider: 'CLOUDFORMATION_STACK_EVENT',
    requestTokenSha256: sha256(clientRequestToken),
    updateStartedEventIdSha256: sha256(started[0].EventId),
    updateCompletedEventIdSha256: sha256(completedEvents[0].EventId),
    updateStartedAtUtc: startedAt.toISOString(),
    updateCompletedAtUtc: completedAt.toISOString(),
    transition: 'UPDATE_IN_PROGRESS_TO_UPDATE_COMPLETE',
  };
};

const completedInitialRollbackPublication = (source, suffix) =>
  suffix === 'api'
    ? source?.checkpoints?.apiRollback?.publication
    : source?.checkpoints?.rollbackInfrastructure?.publication?.webStack;

const validateInitialRollbackLiveBinding = (context, suffix, record, observed) => {
  const outputs = observed?.state?.outputs;
  if (
    canonicalJson(observed?.state?.tags) !== canonicalJson(expectedReleaseStackTags(context)) ||
    outputs?.CandidateSha !== context.identity.candidateSha ||
    outputs?.ReleaseId !== context.identity.releaseId
  ) {
    fail(initialRollbackCode(suffix, 'LIVE_BINDING_INVALID'));
  }
  if (suffix === 'api') {
    const deployed = apiVersionsFromOutputs(
      context,
      outputs,
      initialRollbackCode(suffix, 'LIVE_BINDING_INVALID'),
    );
    if (
      canonicalJson(deployed) !== canonicalJson(record?.deployed) ||
      outputs.HttpApiId !== record?.publication?.apiId ||
      outputs.ApiCustomDomainName !== context.config.domain.apiHostname ||
      releaseApiOriginFromOutputs(
        context,
        outputs,
        initialRollbackCode(suffix, 'LIVE_BINDING_INVALID'),
      ) !== `https://${context.config.domain.apiHostname}`
    ) {
      fail(initialRollbackCode(suffix, 'LIVE_BINDING_INVALID'));
    }
    return observed;
  }
  const publicOriginValue = validateDeployedWebOutputs(
    context,
    outputs,
    initialRollbackCode(suffix, 'LIVE_BINDING_INVALID'),
  );
  if (
    outputs.WebBucketName !== record?.bucketName ||
    outputs.DistributionId !== record?.distributionId ||
    outputs.DistributionId !== record?.publication?.distributionId ||
    sha256(publicOriginValue) !== record?.publicOriginSha256
  ) {
    fail(initialRollbackCode(suffix, 'LIVE_BINDING_INVALID'));
  }
  return observed;
};

const transitionInitialRollbackPublication = async ({
  context,
  suffix,
  record,
  dependencies = {},
}) => {
  const readPublication = dependencies.readPublication ?? publicationStateForStack;
  const readEvidence = dependencies.readEvidence ?? rollbackEvidenceSource;
  const persistIntent = dependencies.persistIntent ?? persistInitialRollbackIntent;
  const applyUpdate = dependencies.applyUpdate ?? updatePublicationStack;
  const captureCausality = dependencies.captureCausality ?? captureInitialRollbackCausality;
  const validateTemplate = dependencies.validateTemplate ?? validateOriginalStackTemplate;
  const observed = readPublication(context, suffix);
  if (!SHA256.test(record?.templateSha256 ?? '')) {
    fail(initialRollbackCode(suffix, 'RECORD_TEMPLATE_INVALID'));
  }
  validateTemplate(context, observed.state.stackId, record.templateSha256);
  validateInitialRollbackLiveBinding(context, suffix, record, observed);
  const clientRequestToken = initialRollbackClientRequestToken({
    context,
    suffix,
    record,
    observed,
  });
  const requestSha256 = objectSha256(
    initialRollbackRequestBinding({ context, suffix, record, observed }),
  );
  const source = readEvidence(context, { allowMissing: true });
  const completed = completedInitialRollbackPublication(source, suffix);
  const intent = source?.checkpoints?.[initialRollbackIntentCheckpoint(suffix)];

  if (completed !== undefined) {
    try {
      validateStage7InitialRollbackPublicationTransition(completed, {
        stackName: observed.stackName,
      });
    } catch (error) {
      if (error instanceof Stage7Error) {
        fail(initialRollbackCode(suffix, 'COMPLETED_TRANSITION_INVALID'));
      }
      throw error;
    }
    if (intent === undefined) fail(initialRollbackCode(suffix, 'RESUME_INTENT_MISSING'));
    validateInitialRollbackIntent({
      context,
      suffix,
      record,
      observed,
      intent,
      requirePreTransitionState: false,
    });
    if (
      completed.intent.sha256 !== requestSha256 ||
      observed.publicationState !== 'DISABLED' ||
      completed.stackIdSha256 !== sha256(observed.state.stackId)
    ) {
      fail(initialRollbackCode(suffix, 'COMPLETED_TRANSITION_DRIFT'));
    }
    const causality = captureCausality({
      context,
      suffix,
      observed,
      intent,
      clientRequestToken,
    });
    if (objectSha256(completed.causality) !== objectSha256(causality)) {
      fail(initialRollbackCode(suffix, 'COMPLETED_TRANSITION_CAUSALITY_INVALID'));
    }
    return completed;
  }

  if (observed.publicationState === 'ENABLED') {
    const persistedIntent = await persistIntent({ context, suffix, record, observed });
    const updated = applyUpdate(context, suffix, 'DISABLED', {
      expectedBeforeStateSha256: persistedIntent.preTransitionStateSha256,
      expectedTemplateSha256: record.templateSha256,
      clientRequestToken,
    });
    if (
      updated?.changed !== true ||
      updated?.previousState !== 'ENABLED' ||
      updated?.state !== 'DISABLED' ||
      updated?.stackName !== observed.stackName ||
      updated?.stackIdSha256 !== sha256(observed.state.stackId)
    ) {
      fail(initialRollbackCode(suffix, 'TRANSITION_INVALID'));
    }
    const updatedObserved = readPublication(context, suffix);
    if (
      updatedObserved?.publicationState !== 'DISABLED' ||
      updatedObserved?.stackName !== observed.stackName ||
      updatedObserved?.state?.stackId !== observed.state.stackId
    ) {
      fail(initialRollbackCode(suffix, 'TRANSITION_INVALID'));
    }
    const causality = captureCausality({
      context,
      suffix,
      observed: updatedObserved,
      intent: persistedIntent,
      clientRequestToken,
    });
    return {
      ...updated,
      intent: {
        mode: 'APPLIED_AFTER_LOCAL_INTENT',
        sha256: requestSha256,
        previousState: 'ENABLED',
        targetState: 'DISABLED',
      },
      causality,
    };
  }

  if (intent === undefined) fail(initialRollbackCode(suffix, 'RESUME_INTENT_MISSING'));
  validateInitialRollbackIntent({
    context,
    suffix,
    record,
    observed,
    intent,
    requirePreTransitionState: false,
  });
  const causality = captureCausality({
    context,
    suffix,
    observed,
    intent,
    clientRequestToken,
  });
  return {
    changed: true,
    previousState: 'ENABLED',
    state: 'DISABLED',
    stackIdSha256: sha256(observed.state.stackId),
    stackName: observed.stackName,
    intent: {
      mode: 'RECOVERED_AFTER_CLOUDFORMATION_EVENT',
      sha256: requestSha256,
      previousState: 'ENABLED',
      targetState: 'DISABLED',
    },
    causality,
  };
};

const validateInitialApiRollbackEvidenceForWeb = ({
  context,
  apiRecord,
  apiStack,
  rollbackEvidence,
  captureCausality = captureInitialRollbackCausality,
}) => {
  const apiRollback = rollbackEvidence?.checkpoints?.apiRollback;
  const apiIntent = rollbackEvidence?.checkpoints?.apiRollbackIntent;
  if (
    apiRollback?.decision !== 'INITIAL_RELEASE_DISABLED_REQUIRES_UNAVAILABLE_SMOKE' ||
    apiRollback?.releaseMode !== 'INITIAL' ||
    apiRollback?.aliasesChanged !== false ||
    apiRollback?.dataFactsChanged !== false ||
    apiRollback?.stacksDeleted !== 0
  ) {
    fail('E7_INITIAL_API_ROLLBACK_EVIDENCE_INVALID');
  }
  try {
    validateInitialRollbackLiveBinding(context, 'api', apiRecord, apiStack);
  } catch (error) {
    if (error instanceof Stage7Error || error instanceof Stage7AwsError) {
      fail('E7_INITIAL_API_ROLLBACK_EVIDENCE_INVALID');
    }
    throw error;
  }
  try {
    validateStage7InitialRollbackPublicationTransition(apiRollback.publication, {
      stackName: stackFor(context, 'api'),
    });
    if (apiIntent === undefined) fail('E7_INITIAL_API_ROLLBACK_EVIDENCE_INVALID');
    validateInitialRollbackIntent({
      context,
      suffix: 'api',
      record: apiRecord,
      observed: apiStack,
      intent: apiIntent,
      requirePreTransitionState: false,
    });
  } catch (error) {
    if (error instanceof Stage7Error || error instanceof Stage7AwsError) {
      fail('E7_INITIAL_API_ROLLBACK_EVIDENCE_INVALID');
    }
    throw error;
  }
  const requestSha256 = objectSha256(
    initialRollbackRequestBinding({
      context,
      suffix: 'api',
      record: apiRecord,
      observed: apiStack,
    }),
  );
  const clientRequestToken = initialRollbackClientRequestToken({
    context,
    suffix: 'api',
    record: apiRecord,
    observed: apiStack,
  });
  const causality = captureCausality({
    context,
    suffix: 'api',
    observed: apiStack,
    intent: apiIntent,
    clientRequestToken,
  });
  if (
    apiRollback.publication.intent.sha256 !== requestSha256 ||
    apiRollback.publication.stackIdSha256 !== sha256(apiStack.state.stackId) ||
    objectSha256(apiRollback.publication.causality) !== objectSha256(causality)
  ) {
    fail('E7_INITIAL_API_ROLLBACK_EVIDENCE_INVALID');
  }
  return apiRollback;
};

const captureInitialApiRollbackPosture = ({
  context,
  expectedStack,
  readApiPublication = publicationStateForStack,
  readScheduler = getSchedule,
  readHttpApi = getHttpApi,
  readMappings = getApiMappings,
}) => {
  const apiStack = readApiPublication(context, 'api');
  const scheduler = readScheduler(context);
  const apiId = apiStack?.state?.outputs?.HttpApiId;
  const api = readHttpApi(context, apiId);
  const mappings =
    context.config.domain.mode === 'CUSTOM_AUTHORIZED'
      ? readMappings(context, context.config.domain.apiHostname)
      : [];
  if (
    expectedStack?.publicationState !== 'DISABLED' ||
    apiStack?.publicationState !== 'DISABLED' ||
    scheduler?.State !== 'DISABLED' ||
    api?.ApiId !== apiId ||
    api?.DisableExecuteApiEndpoint !== true ||
    !Array.isArray(mappings) ||
    mappings.length !== 0 ||
    apiStack?.stackName !== expectedStack.stackName ||
    apiStack?.state?.stackId !== expectedStack.state.stackId ||
    stackStateFingerprint(apiStack.stackName, apiStack.state) !==
      stackStateFingerprint(expectedStack.stackName, expectedStack.state)
  ) {
    fail('E7_INITIAL_API_ROLLBACK_POST_CAUSALITY_DRIFT');
  }
  return {
    apiId,
    apiStackSha256: stackStateFingerprint(apiStack.stackName, apiStack.state),
    disableExecuteApiEndpoint: true,
    mappingCount: 0,
    schedulerState: 'DISABLED',
  };
};

const transitionInitialWebRollback = async ({
  context,
  record,
  apiRecord,
  apiStack,
  rollbackEvidence,
  transition = transitionInitialRollbackPublication,
  captureApiCausality = captureInitialRollbackCausality,
  readApiPublication = publicationStateForStack,
  readScheduler = getSchedule,
  readHttpApi = getHttpApi,
  readApiMappings = getApiMappings,
}) => {
  const apiRollback = validateInitialApiRollbackEvidenceForWeb({
    context,
    apiRecord,
    apiStack,
    rollbackEvidence,
    captureCausality: captureApiCausality,
  });
  const postureDependencies = {
    context,
    expectedStack: apiStack,
    readApiPublication,
    readScheduler,
    readHttpApi,
    readMappings: readApiMappings,
  };
  captureInitialApiRollbackPosture(postureDependencies);
  const publication = await transition({ context, suffix: 'web', record });
  captureInitialApiRollbackPosture(postureDependencies);
  return { apiRollback, publication };
};

const captureStackState = (
  context,
  { releaseMode, previousManifest = null, readStack = describeStack } = {},
) => {
  const expectedIdentity =
    releaseMode === 'VERSIONED_UPDATE' && previousManifest !== null
      ? previousManifest.previous
      : releaseMode === 'INITIAL' && previousManifest === null
        ? context.identity
        : null;
  if (expectedIdentity === null) fail('E7_PRE_DEPLOYMENT_IDENTITY_MODE_INVALID');
  return Object.fromEntries(
    context.stacks.map((stackName) => {
      const state = readStack(context, stackName, { allowMissing: true });
      if (
        state.exists &&
        (state.outputs.CandidateSha !== expectedIdentity.candidateSha ||
          state.outputs.ReleaseId !== expectedIdentity.releaseId)
      ) {
        fail('E7_UPDATE_RELEASE_NOT_SUPPORTED');
      }
      return [stackName, stackStateFingerprint(stackName, state)];
    }),
  );
};

const selfTestPreDeploymentIdentityCapture = () => {
  const previous = {
    candidateSha: 'a'.repeat(40),
    releaseId: 'rel-20260816-1200-aaaaaaa',
  };
  const target = {
    candidateSha: 'b'.repeat(40),
    releaseId: 'rel-20260817-1200-bbbbbbb',
  };
  const context = {
    identity: target,
    stacks: ['data', 'api', 'observability', 'web'].map(
      (suffix) => `checkout-assessment-release-${suffix}`,
    ),
  };
  const stateFor = (stackName, identity) => ({
    exists: true,
    stackStatus: 'UPDATE_COMPLETE',
    stackId: `arn:aws:cloudformation:us-east-1:123456789012:stack/${stackName}/canary`,
    creationTime: '2026-08-16T12:00:00.000Z',
    lastUpdatedTime: '2026-08-16T12:01:00.000Z',
    terminationProtection: true,
    parameters: {},
    outputs: { CandidateSha: identity.candidateSha, ReleaseId: identity.releaseId },
    tags: {},
  });
  const capture = (identities, releaseMode, previousManifest) =>
    captureStackState(context, {
      releaseMode,
      previousManifest,
      readStack: (_activeContext, stackName) => stateFor(stackName, identities.get(stackName)),
    });
  const all = (identity) => new Map(context.stacks.map((stackName) => [stackName, identity]));
  const previousManifest = { previous };
  assert.equal(
    Object.keys(capture(all(previous), 'VERSIONED_UPDATE', previousManifest)).length,
    context.stacks.length,
  );
  for (const identities of [
    all(target),
    new Map(context.stacks.map((stackName, index) => [stackName, index === 0 ? target : previous])),
    all({ candidateSha: 'c'.repeat(40), releaseId: 'rel-20260815-1200-ccccccc' }),
  ]) {
    assert.throws(
      () => capture(identities, 'VERSIONED_UPDATE', previousManifest),
      (error) =>
        error instanceof Stage7AwsError && error.code === 'E7_UPDATE_RELEASE_NOT_SUPPORTED',
    );
  }
  assert.equal(Object.keys(capture(all(target), 'INITIAL', null)).length, context.stacks.length);
  assert.throws(
    () => capture(all(previous), 'INITIAL', null),
    (error) => error instanceof Stage7AwsError && error.code === 'E7_UPDATE_RELEASE_NOT_SUPPORTED',
  );
};

const parseAliasArn = (context, value, code) => {
  const match =
    /^arn:aws:lambda:([a-z0-9-]+):([0-9]{12}):function:([A-Za-z0-9-_]{1,64}):([A-Za-z0-9-_]{1,128})$/u.exec(
      value ?? '',
    );
  if (
    match === null ||
    match[1] !== context.config.aws.region ||
    match[2] !== context.config.aws.accountId
  ) {
    fail(code);
  }
  return { functionName: match[3], aliasName: match[4] };
};

const apiVersionsFromOutputs = (context, outputs, code) => {
  const api = parseAliasArn(context, outputs.ApiAliasArn, code);
  const worker = parseAliasArn(context, outputs.WorkerAliasArn, code);
  if (
    !VERSION.test(outputs.ApiFunctionVersion ?? '') ||
    !VERSION.test(outputs.WorkerFunctionVersion ?? '')
  ) {
    fail(code);
  }
  return {
    api: { ...api, version: outputs.ApiFunctionVersion },
    worker: { ...worker, version: outputs.WorkerFunctionVersion },
  };
};

const getHttpApi = (context, apiId) => {
  if (!HTTP_API_ID.test(apiId ?? '')) fail('E7_HTTP_API_ID_INVALID');
  const api = awsJson(
    context,
    ['apigatewayv2', 'get-api', '--api-id', apiId],
    'E7_HTTP_API_READ_FAILED',
  );
  if (
    api?.ApiId !== apiId ||
    api?.Name !== `checkout-${context.config.environment}-api` ||
    typeof api?.DisableExecuteApiEndpoint !== 'boolean'
  ) {
    fail('E7_HTTP_API_CONTRACT_INVALID');
  }
  return api;
};

const getApiMappings = (context, domainName) => {
  if (domainName !== context.config.domain.apiHostname) {
    fail('E7_API_MAPPING_DOMAIN_INVALID');
  }
  const response = awsJson(
    context,
    ['apigatewayv2', 'get-api-mappings', '--domain-name', domainName],
    'E7_API_MAPPING_READ_FAILED',
  );
  if (!Array.isArray(response?.Items) || response?.NextToken !== undefined) {
    fail('E7_API_MAPPING_CONTRACT_INVALID');
  }
  return response.Items;
};

const captureApiPublication = (context, outputs) => {
  const apiId = outputs.HttpApiId;
  const api = getHttpApi(context, apiId);
  const full = context.config.domain.mode === 'CUSTOM_AUTHORIZED';
  if (
    (full && outputs.ApiCustomDomainName !== context.config.domain.apiHostname) ||
    (!full && outputs.ApiCustomDomainName !== 'NONE_MANAGED_PRERELEASE') ||
    api.DisableExecuteApiEndpoint !== true
  ) {
    fail('E7_HTTP_API_PUBLICATION_INVALID');
  }
  let mapping = null;
  if (full) {
    const mappings = getApiMappings(context, context.config.domain.apiHostname);
    if (mappings.length !== 0) fail('E7_API_MAPPING_PREMATURE_PUBLICATION');
    mapping = {
      apiId,
      apiMappingId: null,
      apiMappingKey: '',
      domainName: context.config.domain.apiHostname,
      stage: '$default',
    };
  }
  return {
    apiId,
    apiEndpointSha256: sha256(api.ApiEndpoint ?? ''),
    disableExecuteApiEndpoint: api.DisableExecuteApiEndpoint,
    mapping,
  };
};

const listWebVersions = (context, bucketName, { allLatest = false } = {}) => {
  if (!BUCKET_NAME.test(bucketName ?? '')) fail('E7_WEB_BUCKET_INVALID');
  const latest = new Map();
  const seenEntries = new Set();
  const seenMarkers = new Set();
  let keyMarker;
  let versionIdMarker;
  for (let page = 0; page < 100; page += 1) {
    const arguments_ = [
      's3api',
      'list-object-versions',
      '--bucket',
      bucketName,
      '--max-keys',
      '1000',
      '--no-paginate',
      ...(keyMarker === undefined ? [] : ['--key-marker', keyMarker]),
      ...(versionIdMarker === undefined ? [] : ['--version-id-marker', versionIdMarker]),
    ];
    const response = awsJson(context, arguments_, 'E7_WEB_VERSION_INVENTORY_FAILED');
    if (
      !Array.isArray(response?.Versions ?? []) ||
      !Array.isArray(response?.DeleteMarkers ?? []) ||
      typeof response?.IsTruncated !== 'boolean' ||
      response?.NextToken !== undefined
    ) {
      fail('E7_WEB_VERSION_INVENTORY_INVALID');
    }
    for (const [kind, entries] of [
      ['version', response.Versions ?? []],
      ['delete', response.DeleteMarkers ?? []],
    ]) {
      for (const entry of entries) {
        if (
          typeof entry?.Key !== 'string' ||
          !VERSION_ID.test(entry?.VersionId ?? '') ||
          typeof entry?.IsLatest !== 'boolean'
        ) {
          fail('E7_WEB_VERSION_INVENTORY_INVALID');
        }
        const entryIdentity = `${kind}\0${entry.Key}\0${entry.VersionId}`;
        if (seenEntries.has(entryIdentity) || seenEntries.size >= 100_000) {
          fail('E7_WEB_VERSION_INVENTORY_INVALID');
        }
        seenEntries.add(entryIdentity);
        if (entry.IsLatest !== true) {
          continue;
        }
        const trackedMutable = MUTABLE_WEB_KEYS.has(entry.Key) || entry.Key.startsWith('legal/');
        if (!allLatest && !trackedMutable) continue;
        if (!(allLatest ? SAFE_DEPLOYED_WEB_KEY : SAFE_OBJECT_KEY).test(entry.Key)) {
          fail('E7_WEB_VERSION_INVENTORY_INVALID');
        }
        if (kind === 'delete') {
          latest.delete(entry.Key);
          continue;
        }
        if (
          typeof entry.ETag !== 'string' ||
          entry.ETag === '' ||
          !Number.isSafeInteger(entry.Size) ||
          entry.Size < 0
        ) {
          fail('E7_WEB_VERSION_INVENTORY_INVALID');
        }
        latest.set(entry.Key, {
          key: entry.Key,
          versionId: entry.VersionId,
          etagSha256: sha256(entry.ETag),
          size: entry.Size,
        });
      }
    }
    if (response.IsTruncated === false) {
      if (
        ![undefined, null, ''].includes(response.NextKeyMarker) ||
        ![undefined, null, ''].includes(response.NextVersionIdMarker)
      ) {
        fail('E7_WEB_VERSION_INVENTORY_INVALID');
      }
      return [...latest.values()].toSorted((left, right) => left.key.localeCompare(right.key));
    }
    const nextKeyMarker = response.NextKeyMarker;
    const nextVersionIdMarker = response.NextVersionIdMarker;
    if (
      typeof nextKeyMarker !== 'string' ||
      nextKeyMarker === '' ||
      nextKeyMarker.length > 1024 ||
      [...nextKeyMarker].some((character) => {
        const codePoint = character.codePointAt(0);
        return codePoint <= 31 || codePoint === 127;
      }) ||
      !VERSION_ID.test(nextVersionIdMarker ?? '')
    ) {
      fail('E7_WEB_VERSION_INVENTORY_INVALID');
    }
    const markerIdentity = `${nextKeyMarker}\0${nextVersionIdMarker}`;
    if (seenMarkers.has(markerIdentity)) fail('E7_WEB_VERSION_INVENTORY_INVALID');
    seenMarkers.add(markerIdentity);
    keyMarker = nextKeyMarker;
    versionIdMarker = nextVersionIdMarker;
  }
  fail('E7_WEB_VERSION_INVENTORY_INVALID');
};

const validateExactWebObjectInventory = (current, expected, code) => {
  const normalize = (entries) =>
    entries
      .map(({ key, versionId, etagSha256, size }) => ({ key, versionId, etagSha256, size }))
      .toSorted((left, right) => left.key.localeCompare(right.key));
  if (
    !Array.isArray(current) ||
    !Array.isArray(expected) ||
    JSON.stringify(normalize(current)) !== JSON.stringify(normalize(expected))
  ) {
    fail(code);
  }
  return current;
};

const getDistributionConfig = (context, distributionId) => {
  if (!CLOUDFRONT_DISTRIBUTION_ID.test(distributionId ?? '')) {
    fail('E7_WEB_DISTRIBUTION_ID_INVALID');
  }
  const response = awsJson(
    context,
    ['cloudfront', 'get-distribution-config', '--id', distributionId],
    'E7_WEB_DISTRIBUTION_READ_FAILED',
  );
  if (
    typeof response?.ETag !== 'string' ||
    response.ETag === '' ||
    !object(response?.DistributionConfig) ||
    typeof response.DistributionConfig.Enabled !== 'boolean'
  ) {
    fail('E7_WEB_DISTRIBUTION_CONTRACT_INVALID');
  }
  return response;
};

const distributionContractSha256 = (configuration) => {
  const contract = { ...configuration };
  delete contract.Enabled;
  return jsonSha256(contract);
};

const captureWebPublication = (context, distributionId) => {
  const current = getDistributionConfig(context, distributionId);
  const configuration = current.DistributionConfig;
  const aliases = configuration.Aliases;
  const expectedAliases =
    context.config.domain.mode === 'CUSTOM_AUTHORIZED' ? [context.config.domain.hostname] : [];
  const actualAliases = Array.isArray(aliases?.Items) ? aliases.Items.toSorted() : [];
  const expectedEnabled = false;
  if (
    configuration.Enabled !== expectedEnabled ||
    aliases?.Quantity !== expectedAliases.length ||
    actualAliases.join('\0') !== expectedAliases.toSorted().join('\0')
  ) {
    fail('E7_WEB_DISTRIBUTION_PUBLICATION_INVALID');
  }
  return {
    distributionId,
    distributionConfigSha256: distributionContractSha256(configuration),
    enabled: expectedEnabled,
  };
};

const privateRecordPath = (context, kind) =>
  path.join(internalRoot(context.config), `${kind}.json`);

const validateRecord = (context, kind, record) => {
  if (
    record?.schemaVersion !== 1 ||
    record?.stage !== 7 ||
    record?.kind !== kind ||
    record?.environment !== context.config.environment ||
    record?.releaseId !== context.identity.releaseId ||
    record?.candidateSha !== context.identity.candidateSha ||
    record?.containsSensitiveData !== false ||
    !SHA256.test(record.recordSha256 ?? '')
  ) {
    fail('E7_ROLLBACK_RECORD_INVALID');
  }
  const body = { ...record };
  delete body.recordSha256;
  if (objectSha256(body) !== record.recordSha256) fail('E7_ROLLBACK_RECORD_DIGEST_INVALID');
  return record;
};

const writeRecord = (context, kind, body) => {
  const recordBody = {
    schemaVersion: 1,
    stage: 7,
    kind,
    environment: context.config.environment,
    releaseId: context.identity.releaseId,
    candidateSha: context.identity.candidateSha,
    ...body,
    containsSensitiveData: false,
  };
  const record = { ...recordBody, recordSha256: objectSha256(recordBody) };
  atomicPrivateJson(privateRecordPath(context, kind), record);
  return record;
};

const readRecord = (context, kind, suppliedPath) =>
  (() => {
    const source = readJson(
      suppliedPath ?? privateRecordPath(context, kind),
      'E7_ROLLBACK_RECORD_MISSING',
    );
    const record =
      source?.kind === kind
        ? source
        : (source?.checkpoints?.[stackSuffix(kind)]?.rollbackRecord ??
          source?.checkpoints?.[kind]?.rollbackRecord);
    return validateRecord(context, kind, record);
  })();

const runtimeSecretReference = (config) => {
  const references = config.credentialReferences.filter((reference) =>
    reference.includes(':secretsmanager:'),
  );
  if (references.length !== 1) fail('E7_RUNTIME_SECRET_REFERENCE_INVALID');
  return references[0];
};

const rollbackResilienceDeploymentBinding = ({ context, assembly, deployed }) => {
  const stack = assembly.stacks.find(({ artifactId }) => artifactId === deployed.stackName);
  const alarmName = `checkout-${context.config.environment}-rollback-rehearsal`;
  const alarmArn = `arn:aws:cloudwatch:${context.config.aws.region}:${context.config.aws.accountId}:alarm:${alarmName}`;
  if (
    stack === undefined ||
    deployed.outputs.RollbackRehearsalAlarmName !== alarmName ||
    deployed.outputs.RollbackRehearsalAlarmArn !== alarmArn
  ) {
    fail('E7_ROLLBACK_RESILIENCE_OBSERVABILITY_OUTPUT_INVALID');
  }
  return {
    stackName: deployed.stackName,
    templateSha256: objectSha256(stack.template),
    cloudFormationExecutionRoleArn: cloudFormationExecutionRoleArn(context.config),
    rollbackRehearsalAlarm: {
      alarmName,
      alarmArn,
      metricNamespace: 'Checkout/Stage7Rehearsal',
      metricName: 'RollbackRehearsalFailure',
      dimensions: [
        { name: 'Environment', value: context.config.environment },
        { name: 'ReleaseId', value: context.identity.releaseId },
        { name: 'Scenario', value: 'RB-E7-08' },
      ],
      statistic: 'Maximum',
      unit: 'Count',
      periodSeconds: 60,
      evaluationPeriods: 1,
      threshold: 1,
      comparisonOperator: 'GreaterThanOrEqualToThreshold',
      treatMissingData: 'notBreaching',
      actionsEnabled: false,
      alarmActions: [],
      okActions: [],
      insufficientDataActions: [],
    },
  };
};

const runtimeSecretVersionId = (config) => {
  const value = config.prereleaseAccess.originTokenSecretVersionId;
  if (!/^[A-Za-z0-9-]{32,64}$/u.test(value ?? '')) {
    fail('E7_RUNTIME_SECRET_VERSION_INVALID');
  }
  return value;
};

const validateRuntimeSecretReferenceDocument = (context, response) => {
  const reference = runtimeSecretReference(context.config);
  const versionId = runtimeSecretVersionId(context.config);
  if (response?.ARN !== reference || response?.DeletedDate !== undefined) {
    fail('E7_RUNTIME_SECRET_REFERENCE_MISMATCH');
  }
  const current = Object.entries(response.VersionIdsToStages ?? {}).filter(
    ([, stages]) => Array.isArray(stages) && stages.includes('AWSCURRENT'),
  );
  if (
    response.KmsKeyId !== undefined ||
    response.RotationEnabled !== false ||
    current.length !== 1 ||
    current[0][0] !== versionId
  ) {
    fail('E7_RUNTIME_SECRET_VERSION_MISMATCH');
  }
  return {
    decision: 'PASS',
    bindingSha256: sha256(`${reference}\n${versionId}`),
    secretArnSha256: sha256(reference),
    versionIdSha256: sha256(versionId),
    currentVersionCount: 1,
    rotationEnabled: false,
    customerManagedKmsKeyUsed: false,
    rawSecretMaterialCaptured: false,
  };
};

const validateRuntimeSecretReferenceAws = (context) =>
  validateRuntimeSecretReferenceDocument(
    context,
    awsJson(
      context,
      ['secretsmanager', 'describe-secret', '--secret-id', runtimeSecretReference(context.config)],
      'E7_RUNTIME_SECRET_REFERENCE_UNAVAILABLE',
    ),
  );

const validateRuntimeSecretReferenceEvidence = (context, value) => {
  const reference = runtimeSecretReference(context.config);
  const versionId = runtimeSecretVersionId(context.config);
  return (
    exactKeys(value, [
      'decision',
      'bindingSha256',
      'secretArnSha256',
      'versionIdSha256',
      'currentVersionCount',
      'rotationEnabled',
      'customerManagedKmsKeyUsed',
      'rawSecretMaterialCaptured',
    ]) &&
    value.decision === 'PASS' &&
    value.bindingSha256 === sha256(`${reference}\n${versionId}`) &&
    value.secretArnSha256 === sha256(reference) &&
    value.versionIdSha256 === sha256(versionId) &&
    value.currentVersionCount === 1 &&
    value.rotationEnabled === false &&
    value.customerManagedKmsKeyUsed === false &&
    value.rawSecretMaterialCaptured === false
  );
};

const validatePrereleaseAccessDocuments = (context, keyGroupResponse, publicKeyResponse) => {
  if (context.scope !== 'prerelease') return null;
  const access = context.config.prereleaseAccess;
  const secretReference = runtimeSecretReference(context.config);
  const keyGroup = keyGroupResponse?.KeyGroup;
  const keyGroupConfig = keyGroup?.KeyGroupConfig;
  const publicKey = publicKeyResponse?.PublicKey;
  const publicKeyConfig = publicKey?.PublicKeyConfig;
  const encodedKey = publicKeyConfig?.EncodedKey;
  let keyObject;
  try {
    keyObject = createPublicKey(encodedKey);
  } catch {
    fail('E7_PRERELEASE_PUBLIC_KEY_INVALID');
  }
  if (
    access?.mode !== 'CLOUDFRONT_SIGNED_COOKIE' ||
    access.originTokenSecretArn !== secretReference ||
    keyGroupResponse?.ETag === undefined ||
    typeof keyGroupResponse.ETag !== 'string' ||
    keyGroupResponse.ETag.length < 1 ||
    keyGroup?.Id !== access.keyGroupId ||
    !Array.isArray(keyGroupConfig?.Items) ||
    keyGroupConfig.Items.length !== 1 ||
    keyGroupConfig.Items[0] !== access.publicKeyId ||
    publicKeyResponse?.ETag === undefined ||
    typeof publicKeyResponse.ETag !== 'string' ||
    publicKeyResponse.ETag.length < 1 ||
    publicKey?.Id !== access.publicKeyId ||
    typeof publicKeyConfig?.Name !== 'string' ||
    publicKeyConfig.Name.length < 1 ||
    typeof encodedKey !== 'string' ||
    !/^-----BEGIN PUBLIC KEY-----\r?\n(?:[A-Za-z0-9+/]{1,76}={0,2}\r?\n)+-----END PUBLIC KEY-----\r?\n?$/u.test(
      encodedKey,
    ) ||
    keyObject.asymmetricKeyType !== 'rsa' ||
    (keyObject.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
  ) {
    fail('E7_PRERELEASE_ACCESS_BINDING_INVALID');
  }
  return {
    decision: 'PASS',
    bindingSha256: sha256(
      [
        access.keyGroupId,
        access.publicKeyId,
        secretReference,
        runtimeSecretVersionId(context.config),
      ].join('\n'),
    ),
    keyGroupIdSha256: sha256(access.keyGroupId),
    keyGroupEtagSha256: sha256(keyGroupResponse.ETag),
    keyGroupPublicKeyCount: 1,
    publicKeyIdSha256: sha256(access.publicKeyId),
    publicKeyEtagSha256: sha256(publicKeyResponse.ETag),
    publicKeyMaterialSha256: sha256(encodedKey),
    publicKeyAlgorithm: 'RSA',
    originTokenSecretReferenceSha256: sha256(secretReference),
    originTokenSecretVersionIdSha256: sha256(runtimeSecretVersionId(context.config)),
    rawAccessMaterialCaptured: false,
  };
};

const validatePrereleaseAccessAws = (context) => {
  if (context.scope !== 'prerelease') return null;
  const access = context.config.prereleaseAccess;
  const keyGroup = awsJson(
    context,
    ['cloudfront', 'get-key-group', '--id', access.keyGroupId],
    'E7_PRERELEASE_KEY_GROUP_READ_FAILED',
  );
  const publicKey = awsJson(
    context,
    ['cloudfront', 'get-public-key', '--id', access.publicKeyId],
    'E7_PRERELEASE_PUBLIC_KEY_READ_FAILED',
  );
  return validatePrereleaseAccessDocuments(context, keyGroup, publicKey);
};

const validatePrereleaseAccessEvidence = (context, value) => {
  if (context.scope !== 'prerelease') return value === null;
  const access = context.config.prereleaseAccess;
  const secretReference = runtimeSecretReference(context.config);
  return (
    exactKeys(value, [
      'decision',
      'bindingSha256',
      'keyGroupIdSha256',
      'keyGroupEtagSha256',
      'keyGroupPublicKeyCount',
      'publicKeyIdSha256',
      'publicKeyEtagSha256',
      'publicKeyMaterialSha256',
      'publicKeyAlgorithm',
      'originTokenSecretReferenceSha256',
      'originTokenSecretVersionIdSha256',
      'rawAccessMaterialCaptured',
    ]) &&
    value.decision === 'PASS' &&
    value.bindingSha256 ===
      sha256(
        [
          access.keyGroupId,
          access.publicKeyId,
          secretReference,
          runtimeSecretVersionId(context.config),
        ].join('\n'),
      ) &&
    value.keyGroupIdSha256 === sha256(access.keyGroupId) &&
    SHA256.test(value.keyGroupEtagSha256 ?? '') &&
    value.keyGroupPublicKeyCount === 1 &&
    value.publicKeyIdSha256 === sha256(access.publicKeyId) &&
    SHA256.test(value.publicKeyEtagSha256 ?? '') &&
    SHA256.test(value.publicKeyMaterialSha256 ?? '') &&
    value.publicKeyAlgorithm === 'RSA' &&
    value.originTokenSecretReferenceSha256 === sha256(secretReference) &&
    value.originTokenSecretVersionIdSha256 === sha256(runtimeSecretVersionId(context.config)) &&
    value.rawAccessMaterialCaptured === false
  );
};

const domainContexts = (config) => {
  if (config.domain.mode === 'AWS_MANAGED') return [];
  const domain = config.domain;
  const values = {
    hostedZoneId: domain.hostedZoneId,
    hostedZoneName: domain.hostname.split('.').slice(1).join('.'),
    webDomainName: domain.hostname,
    webCertificateArn: domain.webCertificateArn,
    apiDomainName: domain.apiHostname,
    apiCertificateArn: domain.apiCertificateArn,
  };
  if (
    !/^Z[A-Z0-9]{5,31}$/u.test(values.hostedZoneId ?? '') ||
    !/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(
      values.hostedZoneName ?? '',
    ) ||
    !/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u.test(
      values.apiDomainName ?? '',
    ) ||
    !/^arn:aws:acm:us-east-1:[0-9]{12}:certificate\/[0-9a-f-]{36}$/u.test(
      values.webCertificateArn ?? '',
    ) ||
    !new RegExp(
      `^arn:aws:acm:${config.aws.region}:[0-9]{12}:certificate\\/[0-9a-f-]{36}$`,
      'u',
    ).test(values.apiCertificateArn ?? '')
  ) {
    fail('E7_DOMAIN_DEPLOYMENT_CONFIG_INVALID');
  }
  for (const certificate of [values.webCertificateArn, values.apiCertificateArn]) {
    if (certificate.split(':')[4] !== config.aws.accountId) fail('E7_DOMAIN_ACCOUNT_MISMATCH');
  }
  return Object.entries(values);
};

const validateHostedZoneDocument = (config, response) => {
  const hostedZoneId = config.domain.hostedZoneId;
  const expectedName = `${config.domain.hostname.split('.').slice(1).join('.')}.`;
  const zone = response?.HostedZone;
  const nameServers = response?.DelegationSet?.NameServers;
  if (
    zone?.Id !== `/hostedzone/${hostedZoneId}` ||
    zone?.Name?.toLowerCase() !== expectedName.toLowerCase() ||
    zone?.Config?.PrivateZone !== false ||
    !Array.isArray(nameServers) ||
    nameServers.length < 2 ||
    nameServers.some(
      (name) =>
        typeof name !== 'string' ||
        !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?$/iu.test(name),
    ) ||
    (Array.isArray(response?.VPCs) && response.VPCs.length !== 0)
  ) {
    fail('E7_HOSTED_ZONE_MISMATCH');
  }
  return {
    hostedZoneIdSha256: sha256(hostedZoneId),
    hostedZoneNameSha256: sha256(expectedName.toLowerCase()),
    publicZone: true,
  };
};

const validateHostedZoneAws = (context) => {
  if (context.config.domain.mode === 'AWS_MANAGED') return null;
  const response = awsJson(
    context,
    ['route53', 'get-hosted-zone', '--id', context.config.domain.hostedZoneId],
    'E7_HOSTED_ZONE_READ_FAILED',
  );
  return validateHostedZoneDocument(context.config, response);
};

const certificateNameCovers = (certificateName, hostname) => {
  const normalized = String(certificateName ?? '').toLowerCase();
  const target = String(hostname ?? '').toLowerCase();
  if (normalized === target) return true;
  if (!normalized.startsWith('*.')) return false;
  const suffix = normalized.slice(2);
  return target.endsWith(`.${suffix}`) && target.split('.').length === suffix.split('.').length + 1;
};

const validateCertificateAws = (context, { arn, hostname, region, purpose }) => {
  const response = awsJson(
    context,
    ['acm', 'describe-certificate', '--certificate-arn', arn],
    'E7_CERTIFICATE_READ_FAILED',
    { region },
  );
  const certificate = response?.Certificate;
  const names = certificate?.SubjectAlternativeNames;
  const notAfter = new Date(certificate?.NotAfter ?? '');
  if (
    certificate?.CertificateArn !== arn ||
    certificate?.Status !== 'ISSUED' ||
    !['AMAZON_ISSUED', 'IMPORTED'].includes(certificate?.Type) ||
    !['RSA_2048', 'RSA_3072', 'RSA_4096', 'EC_prime256v1'].includes(certificate?.KeyAlgorithm) ||
    !Array.isArray(names) ||
    names.length === 0 ||
    names.some((name) => typeof name !== 'string' || name === '') ||
    ![certificate?.DomainName, ...names].some((name) => certificateNameCovers(name, hostname)) ||
    Number.isNaN(notAfter.getTime()) ||
    notAfter.getTime() <= Date.parse(context.config.cleanup.expiresAtUtc) ||
    certificate?.RevocationReason !== undefined
  ) {
    fail('E7_CERTIFICATE_CONTRACT_INVALID');
  }
  return {
    certificateArnSha256: sha256(arn),
    hostnameSha256: sha256(hostname),
    keyAlgorithm: certificate.KeyAlgorithm,
    notAfterUtc: notAfter.toISOString(),
    purpose,
    region,
    status: 'ISSUED',
    type: certificate.Type,
  };
};

const validateCertificatesAws = (context) => {
  if (context.config.domain.mode === 'AWS_MANAGED') return [];
  return [
    validateCertificateAws(context, {
      arn: context.config.domain.webCertificateArn,
      hostname: context.config.domain.hostname,
      purpose: 'WEB_CLOUDFRONT',
      region: 'us-east-1',
    }),
    validateCertificateAws(context, {
      arn: context.config.domain.apiCertificateArn,
      hostname: context.config.domain.apiHostname,
      purpose: 'API_REGIONAL',
      region: context.config.aws.region,
    }),
  ];
};

const budgetContract = (config) =>
  `${config.budget.maxUsd.toFixed(2)}:${config.budget.warningUsd
    .map((amount) => amount.toFixed(2))
    .join(',')}`;

const publicationMode = (context) =>
  context.scope === 'prerelease' ? 'EPHEMERAL_NON_PUBLIC' : 'VERSIONED_UPDATE_CLOSED';

const frozenContextArguments = (context) => {
  const values = {
    environment: context.config.environment,
    releaseId: context.identity.releaseId,
    candidateSha: context.identity.candidateSha,
    publicationMode: publicationMode(context),
    sandboxAuthorizedUntilUtc: context.config.authorization.expiresAtUtc,
    budgetMaxUsd: context.config.budget.maxUsd.toFixed(2),
    budgetWarningUsd: context.config.budget.warningUsd.map((amount) => amount.toFixed(2)).join(','),
    ...(context.scope === 'prerelease'
      ? {
          prereleaseKeyGroupId: context.config.prereleaseAccess.keyGroupId,
          prereleasePublicKeyId: context.config.prereleaseAccess.publicKeyId,
        }
      : {}),
    ...Object.fromEntries(domainContexts(context.config)),
  };
  return Object.entries(values).flatMap(([key, value]) => ['--context', `${key}=${value}`]);
};

const synthContextValues = (context) => {
  const config = context.config;
  return {
    projectName: 'checkout',
    environment: config.environment,
    region: config.aws.region,
    releaseId: context.identity.releaseId,
    candidateSha: context.identity.candidateSha,
    owner: config.authorization.ownerAlias,
    expiresOn: config.cleanup.expiresAtUtc.slice(0, 10),
    cleanupExpiresAtUtc: config.cleanup.expiresAtUtc,
    paymentAdapter: 'sandbox',
    paymentsEnabled: 'true',
    tokenizationMode: 'direct_jwe',
    schedulerEnabled: 'true',
    publicationMode: publicationMode(context),
    sandboxAuthorizedUntilUtc: config.authorization.expiresAtUtc,
    pointInTimeRecoveryEnabled: 'true',
    budgetMaxUsd: config.budget.maxUsd.toFixed(2),
    budgetWarningUsd: config.budget.warningUsd.map((amount) => amount.toFixed(2)).join(','),
    apiArtifactPath: path.join(workspaceRoot, 'output/release/build/api'),
    workerArtifactPath: path.join(workspaceRoot, 'output/release/build/worker'),
    webArtifactPath: path.join(workspaceRoot, 'output/release/build/web'),
    runtimeSecretArn: runtimeSecretReference(config),
    runtimeSecretVersionId: runtimeSecretVersionId(config),
    ...(context.scope === 'prerelease'
      ? {
          prereleaseKeyGroupId: config.prereleaseAccess.keyGroupId,
          prereleasePublicKeyId: config.prereleaseAccess.publicKeyId,
        }
      : {}),
    ...Object.fromEntries(domainContexts(config)),
  };
};

const CDK_APP_PATH = /^[\p{L}\p{N}:\\/._@+\- ]+$/u;

const cdkAppCommand = (values, platform = process.platform) => {
  if (
    !Array.isArray(values) ||
    values.length === 0 ||
    values.some(
      (value) =>
        typeof value !== 'string' ||
        value === '' ||
        !CDK_APP_PATH.test(value) ||
        value.includes('\r') ||
        value.includes('\n'),
    )
  ) {
    fail('E7_CDK_APP_COMMAND_INVALID');
  }
  const command = values.map((value) => (value.includes(' ') ? `"${value}"` : value)).join(' ');
  return platform === 'win32' && values[0].includes(' ') ? `call ${command}` : command;
};

const synthContexts = (context, output) => {
  const contexts = synthContextValues(context);
  for (const artifact of ['api', 'worker', 'web']) {
    const artifactPath = contexts[`${artifact}ArtifactPath`];
    if (!existsSync(artifactPath) || !statSync(artifactPath).isDirectory()) {
      fail('E7_SYNTH_ARTIFACT_MISSING');
    }
  }
  const arguments_ = [
    'synth',
    ...context.stacks,
    '--app',
    cdkAppCommand([
      process.execPath,
      workspaceToolEntrypoint('tsx'),
      path.join(workspaceRoot, 'infra/bin/app.ts'),
    ]),
    '--output',
    output,
    '--asset-metadata',
    'false',
    '--path-metadata',
    'false',
    '--version-reporting',
    'false',
    '--lookups',
    'false',
    '--quiet',
  ];
  for (const [key, value] of Object.entries(contexts)) {
    arguments_.push('--context', `${key}=${value}`);
  }
  return { arguments_ };
};

const offlineSynthCloudAuthority = () => ({
  awsIdentity: null,
  certificates: [],
  hostedZone: null,
});

export const synthRelease = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
  writeEvidence = updateEvidence,
}) => {
  const context = loadOperationContext({
    capability: 'read',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: false,
    allowPlan: true,
  });
  const releaseMode = releaseModeForFlags(context.scope, flags);
  if ((flags.output === undefined) === (flags.verify === undefined)) {
    fail('E7_SYNTH_MODE_INVALID');
  }
  if (flags.verify !== undefined) {
    if (flags.manifest === undefined) fail('E7_FREEZE_MANIFEST_REQUIRED');
    const assembly = validateAssemblyIdentity(context, flags.verify, flags.manifest);
    const evidence = {
      decision: 'PASS',
      releaseMode,
      mode: 'VERIFY_FROZEN_ASSEMBLY',
      assemblySha256: assembly.assemblySha256,
      freezeManifestSha256: assembly.freezeManifestSha256,
      stacks: assembly.stacks.map(({ artifactId }) => artifactId),
      stackCount: assembly.stacks.length,
      hostedZone: null,
      awsIdentity: null,
    };
    await writeEvidence(context, 'synth', 'synth', evidence);
    return evidence;
  }
  const { hostedZone, certificates, awsIdentity } = offlineSynthCloudAuthority();
  const output = resolveInsideWorkspace(flags.output, 'E7_SYNTH_OUTPUT_PATH_INVALID', {
    mustExist: false,
  });
  if (existsSync(output)) fail('E7_SYNTH_OUTPUT_ALREADY_EXISTS');
  mkdirSync(path.dirname(output), { recursive: true });
  const { arguments_ } = synthContexts(context, output);
  cdk(context, arguments_, 'E7_CDK_SYNTH_FAILED');
  const assembly = validateAssemblyIdentity(context, output);
  const evidence = {
    decision: 'PASS',
    releaseMode,
    mode: 'OFFLINE_SYNTH_NO_LOOKUPS',
    assemblySha256: assembly.assemblySha256,
    stacks: assembly.stacks.map(({ artifactId }) => artifactId),
    stackCount: assembly.stacks.length,
    certificates,
    hostedZone,
    awsIdentity,
    lookupsAllowed: false,
    hotswapUsed: false,
  };
  await writeEvidence(context, 'synth', 'synth', evidence);
  return evidence;
};

const diffRisks = (source) => {
  const normalized = source.replaceAll('\r', '');
  const statefulResourceMentioned =
    /AWS::(?:DynamoDB::Table|S3::Bucket|SecretsManager::Secret)/u.test(normalized);
  const rollbackResourceMentioned =
    /AWS::(?:Lambda::Function|Lambda::Alias|CloudFront::Distribution)/u.test(normalized);
  const replacement =
    /(?:requires replacement|will be replaced|\[\+\/-\]|replacement\s*:\s*true)/iu.test(normalized);
  const destructive = /(?:\[-\]|will be destroyed|will be deleted|resource deletion)/iu.test(
    normalized,
  );
  const iamBroadening =
    /(?:IAM Statement Changes|Security Group Changes|Resource Policy Changes)/u.test(normalized);
  return {
    statefulReplacement: statefulResourceMentioned && replacement,
    statefulDeletion: statefulResourceMentioned && destructive,
    rollbackControlReplacement: rollbackResourceMentioned && replacement,
    destructiveChangeMentioned: destructive,
    iamOrPolicyReviewRequired: iamBroadening,
  };
};

const stackDiff = (context, assembly, stackName) => {
  const result = cdkResult(
    context,
    [
      'diff',
      stackName,
      '--app',
      assembly.app,
      '--method',
      'template',
      '--fail',
      'false',
      '--exclusively',
      '--no-color',
      ...frozenContextArguments(context),
    ],
    'E7_CDK_DIFF_FAILED',
  );
  const output = `${result.stdout}\n${result.stderr}`.trim();
  try {
    assertSanitizedArtifactText(`stage7-cdk-diff-${stackName}.txt`, output);
  } catch {
    fail('E7_CDK_DIFF_SENSITIVE_OUTPUT');
  }
  return {
    bytes: Buffer.byteLength(output),
    output,
    risks: diffRisks(output),
    sha256: sha256(output),
    stackName,
  };
};

export const diffRelease = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  if (flags.app === undefined || flags.manifest === undefined) fail('E7_DIFF_INPUT_REQUIRED');
  const context = loadOperationContext({
    capability: 'read',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
    allowPlan: true,
  });
  const releaseMode = releaseModeForFlags(context.scope, flags);
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  const previousManifest =
    releaseMode === 'VERSIONED_UPDATE' ? validateVersionedMutationTarget(context, flags) : null;
  const identity = revalidateAwsIdentity(context);
  if (previousManifest !== null) {
    verifyPreviousVersionedResourcesAws(context, previousManifest);
    verifyPreviousPublicationBaselineAws(context, previousManifest);
  }
  const runtimeSecret = validateRuntimeSecretReferenceAws(context);
  const prereleaseAccess = validatePrereleaseAccessAws(context);
  const hostedZone = validateHostedZoneAws(context);
  const certificates = validateCertificatesAws(context);
  const preDeploymentState = captureStackState(context, { releaseMode, previousManifest });
  const perStack = context.stacks.map((stackName) => stackDiff(context, assembly, stackName));
  const output = perStack
    .map(({ output: stackOutput, stackName }) => `===== ${stackName} =====\n${stackOutput}`)
    .join('\n');
  const risks = {
    destructiveChangeMentioned: perStack.some(
      ({ risks: value }) => value.destructiveChangeMentioned,
    ),
    iamOrPolicyReviewRequired: perStack.some(({ risks: value }) => value.iamOrPolicyReviewRequired),
    rollbackControlReplacement: perStack.some(
      ({ risks: value }) => value.rollbackControlReplacement,
    ),
    statefulDeletion: perStack.some(({ risks: value }) => value.statefulDeletion),
    statefulReplacement: perStack.some(({ risks: value }) => value.statefulReplacement),
  };
  if (risks.statefulReplacement) fail('E7_DIFF_STATEFUL_REPLACEMENT_FORBIDDEN');
  if (risks.statefulDeletion) fail('E7_DIFF_STATEFUL_DELETION_FORBIDDEN');
  if (risks.destructiveChangeMentioned) fail('E7_DIFF_DESTRUCTIVE_CHANGE_FORBIDDEN');
  if (risks.rollbackControlReplacement) {
    fail('E7_DIFF_ROLLBACK_RESOURCE_REPLACEMENT_FORBIDDEN');
  }
  const rawDiffTarget = path.join(evidenceRoot(context.config), 'infra-diff.txt');
  await writeSanitizedTextAtomic(rawDiffTarget, 'stage7-infra-diff.txt', `${output}\n`);
  const evidence = {
    decision: 'READY_FOR_PROTECTED_REVIEW',
    releaseMode,
    previousReleaseManifestSha256: previousManifest?.manifestSha256 ?? null,
    identity,
    assemblySha256: assembly.assemblySha256,
    freezeManifestSha256: assembly.freezeManifestSha256,
    diffSha256: sha256(output),
    diffBytes: Buffer.byteLength(output),
    rawDiffArtifactSha256: sha256(`${output}\n`),
    stacks: context.stacks,
    stackDiffs: perStack.map(({ bytes, risks: stackRisks, sha256: digest, stackName }) => ({
      bytes,
      risks: stackRisks,
      sha256: digest,
      stackName,
    })),
    certificates,
    hostedZone,
    prereleaseAccess,
    runtimeSecret,
    preDeploymentState,
    risks,
    exactChangeSetUsed: false,
    diffMethod: 'TEMPLATE',
    exactDiffRecomputedAtDeploy: true,
    hotswapUsed: false,
    containsRawDiff: true,
  };
  const review = {
    ...baseEvidence(context),
    kind: 'RELEASE_DIFF_REVIEW',
    status: 'READY_FOR_PROTECTED_REVIEW',
    scope: context.scope ?? 'full',
    cloudAssemblySha256: assembly.assemblySha256,
    previousReleaseManifestSha256: evidence.previousReleaseManifestSha256,
    destructiveChanges: 0,
    rawDiffArtifactSha256: evidence.rawDiffArtifactSha256,
    humanReviewRequired: true,
    iamBroadeningDetected: risks.iamOrPolicyReviewRequired,
    productionProviderReferences: 0,
    secretFindings: 0,
    statefulReplacements: 0,
    checkpoints: { diff: evidence },
    updatedAtUtc: utc(context.now),
  };
  await writeSanitizedJsonAtomic(evidenceTarget(context, 'diff'), 'stage7-infra-diff.json', review);
  return evidence;
};

const cdkOutputTemporary = (context, suffix) => {
  const directory = internalRoot(context.config);
  mkdirSync(directory, { recursive: true });
  return path.join(directory, `cdk-${suffix}-${process.pid}.json`);
};

const deployStack = (
  context,
  assembly,
  suffix,
  { parameters = [], preDeploymentStateSha256 } = {},
) => {
  const stackName = stackFor(context, suffix);
  const immediatelyBefore = describeStack(context, stackName, { allowMissing: true });
  if (
    !SHA256.test(preDeploymentStateSha256 ?? '') ||
    stackStateFingerprint(stackName, immediatelyBefore) !== preDeploymentStateSha256
  ) {
    fail('E7_APPROVED_PLAN_STACK_DRIFT');
  }
  const outputFile = cdkOutputTemporary(context, suffix);
  rmSync(outputFile, { force: true });
  writeFileSync(outputFile, '', { encoding: 'utf8', mode: 0o600 });
  chmodSync(outputFile, 0o600);
  const arguments_ = [
    'deploy',
    stackName,
    '--app',
    assembly.app,
    '--exclusively',
    '--concurrency',
    '1',
    '--method',
    'change-set',
    '--require-approval',
    'never',
    '--outputs-file',
    outputFile,
    '--progress',
    'events',
    ...frozenContextArguments(context),
  ];
  for (const parameter of parameters) arguments_.push('--parameters', `${stackName}:${parameter}`);
  try {
    cdk(context, arguments_, `E7_CDK_DEPLOY_${suffix.toUpperCase()}_FAILED`);
    const raw = readJson(outputFile, 'E7_CDK_OUTPUT_INVALID');
    const outputs = outputObjectForStack(raw, stackName);
    if (
      outputs.CandidateSha !== context.identity.candidateSha ||
      outputs.ReleaseId !== context.identity.releaseId
    ) {
      fail('E7_DEPLOYED_STACK_IDENTITY_MISMATCH');
    }
    const state = describeStack(context, stackName);
    if (
      !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus) ||
      state.terminationProtection !== (context.scope !== 'prerelease') ||
      state.outputs.CandidateSha !== context.identity.candidateSha ||
      state.outputs.ReleaseId !== context.identity.releaseId ||
      objectSha256(state.outputs) !== objectSha256(outputs)
    ) {
      fail('E7_DEPLOYED_STACK_STATE_INVALID');
    }
    return { stackName, outputs };
  } finally {
    rmSync(outputFile, { force: true });
  }
};

const assertDeployOrder = (context, suffix) => {
  const prerequisites = {
    data: [],
    api: ['data'],
    observability: ['data', 'api'],
    web: ['data', 'api', 'observability'],
  }[suffix];
  for (const prerequisite of prerequisites) {
    const state = describeStack(context, stackFor(context, prerequisite), { allowMissing: true });
    if (
      !state.exists ||
      !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus) ||
      state.outputs.CandidateSha !== context.identity.candidateSha ||
      state.outputs.ReleaseId !== context.identity.releaseId ||
      state.terminationProtection !== (context.scope !== 'prerelease')
    ) {
      fail('E7_DEPLOY_ORDER_VIOLATION');
    }
  }
};

const readLocalRollbackJson = (filename, code) => {
  const absolute = resolveInsideWorkspace(filename, code, { allowDirectory: false });
  try {
    return readStrictJsonFile(absolute, {
      scanForbiddenData: false,
      validateConfig: false,
    });
  } catch (error) {
    if (typeof error?.code === 'string') throw error;
    fail(code);
  }
};

const writeLocalRollbackJson = async (filename, label, value) => {
  const absolute = resolveInsideWorkspace(filename, 'E7_ROLLBACK_OUTPUT_INVALID', {
    mustExist: false,
    allowDirectory: false,
  });
  await writeSanitizedJsonAtomic(absolute, label, value);
  return value;
};

export const validatePreviousReleaseArtifact = async ({ flags }) => {
  const configSource = readLocalRollbackJson(flags.config, 'E7_ROLLBACK_CONFIG_INVALID');
  const config = validateStage7Config(configSource, {
    now: new Date(configSource?.window?.startsAtUtc ?? Number.NaN),
  });
  const freezeManifest = validateFreezeManifest(
    readLocalRollbackJson(flags.manifest, 'E7_FREEZE_MANIFEST_MISSING'),
  );
  const projectionDirectory = path.dirname(
    resolveInsideWorkspace(flags['previous-manifest'], 'E7_PREVIOUS_RELEASE_MANIFEST_MISSING', {
      allowDirectory: false,
    }),
  );
  const projectionFlagByBasename = new Map([
    ['previous-release-manifest.json', 'previous-manifest'],
    ['previous-source-provenance.json', 'previous-source-provenance'],
    ['previous-target-compatibility.json', 'previous-target-compatibility'],
    ['previous-final-disable-provenance.json', 'previous-final-disable-provenance'],
    ['previous-api-contract-evidence.json', 'previous-api-contract-evidence'],
    ['previous-pending-evidence.json', 'previous-pending-evidence'],
    ['previous-smoke-evidence.json', 'previous-smoke-evidence'],
    ['previous-release-projection-index.json', 'previous-release-projection-index'],
  ]);
  if (
    PREVIOUS_RELEASE_PROJECTION_FILENAMES.some((basename) => {
      const flag = projectionFlagByBasename.get(basename);
      if (flag === undefined || flags[flag] === undefined) return true;
      return (
        resolveInsideWorkspace(flags[flag], 'E7_PREVIOUS_RELEASE_PROJECTION_PATH_INVALID', {
          allowDirectory: false,
        }) !== path.join(projectionDirectory, basename)
      );
    })
  ) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_PATH_INVALID');
  }
  let projection;
  try {
    projection = validatePreviousReleaseProjection(projectionDirectory);
  } catch (error) {
    if (
      typeof error?.code === 'string' &&
      error.code.startsWith('E7_PREVIOUS_RELEASE_PROJECTION_')
    ) {
      fail('E7_PREVIOUS_RELEASE_PROJECTION_INVALID');
    }
    throw error;
  }
  const previousManifest = validateStage7PreviousReleaseForTarget(projection.previousRelease, {
    config,
    freezeManifest,
  });
  previousPublicationExpectation(previousManifest);
  try {
    validateStage7PreviousReleaseHandoff(previousManifest, {
      sourceProvenance: readLocalRollbackJson(
        flags['previous-source-provenance'],
        'E7_PREVIOUS_SOURCE_PROVENANCE_MISSING',
      ),
      targetCompatibility: readLocalRollbackJson(
        flags['previous-target-compatibility'],
        'E7_PREVIOUS_TARGET_COMPATIBILITY_MISSING',
      ),
      finalDisableProvenance: readLocalRollbackJson(
        flags['previous-final-disable-provenance'],
        'E7_PREVIOUS_FINAL_DISABLE_PROVENANCE_MISSING',
      ),
    });
  } catch (error) {
    if (error instanceof Stage7Error) fail('E7_PREVIOUS_RELEASE_HANDOFF_INVALID');
    throw error;
  }
  validatePreviousCompatibilityArtifacts(flags, previousManifest);
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PREVIOUS_RELEASE_LOCAL_PREFLIGHT',
    decision: 'READY_FOR_VERSIONED_UPDATE',
    previousReleaseManifestSha256: previousManifest.manifestSha256,
    previousReleaseId: previousManifest.previous.releaseId,
    targetReleaseId: previousManifest.target.releaseId,
    previousAssemblySha256: previousManifest.previous.assemblySha256,
    targetAssemblySha256: previousManifest.target.assemblySha256,
    mutableObjectKeys: previousManifest.resources.web.objects.map(({ key }) => key),
    apiAliasSha256: sha256(
      `${previousManifest.resources.api.functionName}:${previousManifest.resources.api.aliasName}`,
    ),
    workerAliasSha256: sha256(
      `${previousManifest.resources.worker.functionName}:${previousManifest.resources.worker.aliasName}`,
    ),
    versionedRollbackExecutionEnabled: true,
    blockingIssue: null,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return writeLocalRollbackJson(
    flags.output,
    'stage7-previous-release-local-preflight.json',
    result,
  );
};

export const captureCandidateRollbackRecord = async ({ flags }) => {
  const previousManifest = validateStage7PreviousReleaseManifest(
    readLocalRollbackJson(flags['previous-manifest'], 'E7_PREVIOUS_RELEASE_MANIFEST_MISSING'),
  );
  const resourceSource = readLocalRollbackJson(
    flags['resource-state'],
    'E7_CANDIDATE_ROLLBACK_RESOURCE_STATE_MISSING',
  );
  const resources = resourceSource?.resources ?? resourceSource;
  const record = createStage7CandidateRollbackRecord({
    previousManifest,
    createdAtUtc: flags['captured-at'],
    approvalSha256: fileSha256(flags.approval),
    planSha256: fileSha256(flags['approved-plan']),
    deploymentEvidenceSha256: fileSha256(flags['deployment-evidence']),
    resources,
  });
  return writeLocalRollbackJson(flags.output, 'stage7-versioned-rollback-candidate.json', record);
};

const validatedCandidateRollbackInputs = (flags) => {
  const previousManifest = validateStage7PreviousReleaseManifest(
    readLocalRollbackJson(flags['previous-manifest'], 'E7_PREVIOUS_RELEASE_MANIFEST_MISSING'),
  );
  const candidateRecord = validateStage7CandidateRollbackRecord(
    readLocalRollbackJson(flags['candidate-record'], 'E7_CANDIDATE_ROLLBACK_RECORD_MISSING'),
    {
      previousManifest,
      approvalSha256: fileSha256(flags.approval),
      planSha256: fileSha256(flags['approved-plan']),
      deploymentEvidenceSha256: fileSha256(flags['deployment-evidence']),
    },
  );
  return { previousManifest, candidateRecord };
};

export const planVersionedRollback = async ({ flags }) => {
  const { previousManifest, candidateRecord } = validatedCandidateRollbackInputs(flags);
  const plan = createStage7VersionedRollbackPlan({
    direction: flags.direction,
    previousManifest,
    candidateRecord,
    currentState: readLocalRollbackJson(
      flags['current-state'],
      'E7_ROLLBACK_OBSERVED_STATE_MISSING',
    ),
  });
  return writeLocalRollbackJson(flags.output, 'stage7-versioned-rollback-plan.json', plan);
};

export const verifyVersionedRollbackEvidence = async ({ flags }) => {
  const { previousManifest, candidateRecord } = validatedCandidateRollbackInputs(flags);
  const plan = readLocalRollbackJson(flags.plan, 'E7_VERSIONED_ROLLBACK_PLAN_MISSING');
  const checkpoint = validateStage7VersionedRollbackCheckpoint(
    readLocalRollbackJson(flags.checkpoint, 'E7_VERSIONED_ROLLBACK_CHECKPOINT_MISSING'),
    { plan, previousManifest, candidateRecord },
  );
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_EVIDENCE_VERIFICATION',
    decision: 'PASS',
    direction: checkpoint.direction,
    scenarioIds: [...checkpoint.scenarioIds],
    previousReleaseManifestSha256: previousManifest.manifestSha256,
    candidateRecordSha256: candidateRecord.recordSha256,
    planSha256: plan.planSha256,
    checkpointSha256: checkpoint.checkpointSha256,
    pendingIntegrity: checkpoint.pendingIntegrity.status,
    dataRollbackPerformed: checkpoint.dataRollbackPerformed,
    stacksDeleted: checkpoint.stacksDeleted,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return writeLocalRollbackJson(
    flags.output,
    'stage7-versioned-rollback-verification.json',
    result,
  );
};

const decodeLambdaCodeSha256 = (value) => {
  if (typeof value !== 'string' || value.length < 40 || value.length > 48) {
    fail('E7_ROLLBACK_LAMBDA_CODE_DIGEST_INVALID');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 32 || bytes.toString('base64') !== value) {
    fail('E7_ROLLBACK_LAMBDA_CODE_DIGEST_INVALID');
  }
  return bytes.toString('hex');
};

const readVersionedLambda = (context, target, identity) => {
  if (
    !FUNCTION_NAME.test(target?.functionName ?? '') ||
    !VERSION.test(target?.version ?? '') ||
    !SHA.test(identity?.candidateSha ?? '') ||
    !RELEASE_ID.test(identity?.releaseId ?? '')
  ) {
    fail('E7_ROLLBACK_LAMBDA_TARGET_INVALID');
  }
  const configuration = awsJson(
    context,
    [
      'lambda',
      'get-function-configuration',
      '--function-name',
      target.functionName,
      '--qualifier',
      target.version,
    ],
    'E7_ROLLBACK_LAMBDA_VERSION_READ_FAILED',
  );
  const variables = configuration?.Environment?.Variables;
  if (
    configuration?.FunctionName !== target.functionName ||
    configuration?.Version !== target.version ||
    configuration?.State !== 'Active' ||
    configuration?.LastUpdateStatus !== 'Successful' ||
    variables?.CANDIDATE_SHA !== identity.candidateSha ||
    variables?.RELEASE_ID !== identity.releaseId
  ) {
    fail('E7_ROLLBACK_LAMBDA_VERSION_IDENTITY_MISMATCH');
  }
  return {
    functionName: target.functionName,
    aliasName: target.aliasName,
    version: target.version,
    codeSha256: decodeLambdaCodeSha256(configuration.CodeSha256),
  };
};

const inspectVersionedWebObject = (context, { bucketName, key, versionId }) => {
  if (
    !BUCKET_NAME.test(bucketName ?? '') ||
    !VERSIONED_ROLLBACK_WEB_KEYS.includes(key) ||
    !VERSION_ID.test(versionId ?? '')
  ) {
    fail('E7_ROLLBACK_WEB_OBJECT_TARGET_INVALID');
  }
  const head = awsJson(
    context,
    ['s3api', 'head-object', '--bucket', bucketName, '--key', key, '--version-id', versionId],
    'E7_ROLLBACK_WEB_OBJECT_HEAD_FAILED',
  );
  if (
    head?.VersionId !== versionId ||
    typeof head?.ETag !== 'string' ||
    !Number.isSafeInteger(head?.ContentLength) ||
    head.ContentLength < 1
  ) {
    fail('E7_ROLLBACK_WEB_OBJECT_HEAD_INVALID');
  }
  const directory = mkdtempSync(path.join(tmpdir(), 'checkout-stage7-versioned-object-'));
  const target = path.join(directory, key.replaceAll('/', '_'));
  try {
    const response = awsJson(
      context,
      [
        's3api',
        'get-object',
        '--bucket',
        bucketName,
        '--key',
        key,
        '--version-id',
        versionId,
        target,
      ],
      'E7_ROLLBACK_WEB_OBJECT_READ_FAILED',
    );
    if (
      response?.VersionId !== versionId ||
      !existsSync(target) ||
      lstatSync(target).isSymbolicLink() ||
      statSync(target).size !== head.ContentLength
    ) {
      fail('E7_ROLLBACK_WEB_OBJECT_READ_INVALID');
    }
    return {
      key,
      versionId,
      etagSha256: sha256(head.ETag),
      contentSha256: sha256(readFileSync(target)),
      bytes: head.ContentLength,
    };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
};

const latestMutableWebObjects = (context, bucketName) => {
  const inventory = new Map(
    listWebVersions(context, bucketName).map((entry) => [entry.key, entry]),
  );
  if (
    VERSIONED_ROLLBACK_WEB_KEYS.some((key) => !inventory.has(key)) ||
    new Set(VERSIONED_ROLLBACK_WEB_KEYS).size !== VERSIONED_ROLLBACK_WEB_KEYS.length
  ) {
    fail('E7_ROLLBACK_WEB_MUTABLE_INVENTORY_INVALID');
  }
  return VERSIONED_ROLLBACK_WEB_KEYS.map((key) =>
    inspectVersionedWebObject(context, {
      bucketName,
      key,
      versionId: inventory.get(key).versionId,
    }),
  );
};

const assertVersionedResourceMatches = (actual, expected, code) => {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) fail(code);
  return actual;
};

const verifyPreviousVersionedResourcesAws = (context, previousManifest) => {
  const previous = previousManifest.resources;
  const api = readVersionedLambda(context, previous.api, previousManifest.previous);
  const worker = readVersionedLambda(context, previous.worker, previousManifest.previous);
  assertVersionedResourceMatches(api, previous.api, 'E7_PREVIOUS_RELEASE_API_AWS_MISMATCH');
  assertVersionedResourceMatches(
    worker,
    previous.worker,
    'E7_PREVIOUS_RELEASE_WORKER_AWS_MISMATCH',
  );
  const objects = previous.web.objects.map((entry) =>
    inspectVersionedWebObject(context, {
      bucketName: previous.web.bucketName,
      key: entry.key,
      versionId: entry.versionId,
    }),
  );
  assertVersionedResourceMatches(
    objects,
    previous.web.objects,
    'E7_PREVIOUS_RELEASE_WEB_AWS_MISMATCH',
  );
  return { api, worker, web: { ...previous.web, objects } };
};

const previousPublicationExpectation = (previousManifest) => {
  const sourceKind = previousManifest?.handoff?.sourceKind;
  if (sourceKind === 'BASELINE_BOOTSTRAP') {
    return Object.freeze({
      distributionEnabled: false,
      publicationState: 'DISABLED',
      schedulerState: 'DISABLED',
      sourceKind,
    });
  }
  if (sourceKind === 'RELEASE_SUCCESSOR') {
    return Object.freeze({
      distributionEnabled: true,
      publicationState: 'ENABLED',
      schedulerState: 'ENABLED',
      sourceKind,
    });
  }
  fail('E7_PREVIOUS_RELEASE_SOURCE_KIND_UNSUPPORTED');
};

const verifyApiPublicationPostureAws = (
  context,
  {
    expectedFingerprint,
    expectedIdentity,
    expectedPublication,
    expectedResources,
    expectedVersions = expectedResources,
    state,
  },
  {
    readAlias = getAlias,
    readHttpApi = getHttpApi,
    readMappings = getApiMappings,
    readSchedule = getSchedule,
  } = {},
) => {
  const versions = apiVersionsFromOutputs(
    context,
    state.outputs,
    'E7_VERSIONED_UPDATE_API_POSTURE_MISMATCH',
  );
  const activeApi = assertAliasWithoutWeightedRouting(readAlias(context, versions.api));
  const activeWorker = assertAliasWithoutWeightedRouting(readAlias(context, versions.worker));
  const schedule = readSchedule(context);
  const httpApi = readHttpApi(context, state.outputs.HttpApiId);
  const mappings = readMappings(context, context.config.domain.apiHostname);
  const expectedMappingCount = expectedPublication.publicationState === 'ENABLED' ? 1 : 0;
  if (
    state.outputs.CandidateSha !== expectedIdentity.candidateSha ||
    state.outputs.ReleaseId !== expectedIdentity.releaseId ||
    state.parameters.PublicationState !== expectedPublication.publicationState ||
    state.outputs.ApiPublicationStatus !== expectedPublication.publicationState ||
    state.outputs.ApiCustomDomainName !== context.config.domain.apiHostname ||
    versions.api.functionName !== expectedResources.api.functionName ||
    versions.api.aliasName !== expectedResources.api.aliasName ||
    versions.worker.functionName !== expectedResources.worker.functionName ||
    versions.worker.aliasName !== expectedResources.worker.aliasName ||
    (expectedVersions !== null &&
      (versions.api.version !== expectedVersions.api.version ||
        versions.worker.version !== expectedVersions.worker.version)) ||
    activeApi.FunctionVersion !== versions.api.version ||
    activeWorker.FunctionVersion !== versions.worker.version ||
    schedule.State !== expectedPublication.schedulerState ||
    httpApi.ApiId !== state.outputs.HttpApiId ||
    httpApi.DisableExecuteApiEndpoint !== true ||
    !Array.isArray(mappings) ||
    mappings.length !== expectedMappingCount ||
    (expectedMappingCount === 1 &&
      (mappings[0]?.ApiId !== state.outputs.HttpApiId ||
        mappings[0]?.Stage !== '$default' ||
        (mappings[0]?.ApiMappingKey ?? '') !== '' ||
        !API_MAPPING_ID.test(mappings[0]?.ApiMappingId ?? ''))) ||
    (expectedFingerprint !== undefined &&
      stackStateFingerprint(stackFor(context, 'api'), state) !== expectedFingerprint)
  ) {
    fail('E7_VERSIONED_UPDATE_API_POSTURE_MISMATCH');
  }
  validateScheduleTarget(context, state.outputs, schedule);
  return versions;
};

const verifyWebPublicationPostureAws = (
  context,
  { expectedFingerprint, expectedIdentity, expectedPublication, expectedResources, state },
  { readDistribution = getDistributionConfig, readMutableObjects = latestMutableWebObjects } = {},
) => {
  const currentObjects = readMutableObjects(context, expectedResources.web.bucketName);
  const distribution = readDistribution(context, expectedResources.web.distributionId);
  if (
    state.outputs.CandidateSha !== expectedIdentity.candidateSha ||
    state.outputs.ReleaseId !== expectedIdentity.releaseId ||
    state.parameters.PublicationState !== expectedPublication.publicationState ||
    state.outputs.WebPublicationStatus !== expectedPublication.publicationState ||
    state.outputs.WebBucketName !== expectedResources.web.bucketName ||
    state.outputs.DistributionId !== expectedResources.web.distributionId ||
    JSON.stringify(currentObjects) !== JSON.stringify(expectedResources.web.objects) ||
    distribution.DistributionConfig.Enabled !== expectedPublication.distributionEnabled ||
    (expectedFingerprint !== undefined &&
      stackStateFingerprint(stackFor(context, 'web'), state) !== expectedFingerprint)
  ) {
    fail('E7_VERSIONED_UPDATE_WEB_POSTURE_MISMATCH');
  }
  return currentObjects;
};

const verifyPreviousPublicationBaselineAws = (
  context,
  previousManifest,
  {
    readAlias = getAlias,
    readDistribution = getDistributionConfig,
    readHttpApi = getHttpApi,
    readMappings = getApiMappings,
    readMutableObjects = latestMutableWebObjects,
    readSchedule = getSchedule,
    readStack = (activeContext, suffix) =>
      describeStack(activeContext, stackFor(activeContext, suffix)),
  } = {},
) => {
  const previous = previousManifest.resources;
  const expectation = previousPublicationExpectation(previousManifest);
  const states = Object.fromEntries(
    STACK_SUFFIXES.map((suffix) => [suffix, readStack(context, suffix)]),
  );
  if (
    Object.values(states).some(
      (state) =>
        !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus) ||
        state.terminationProtection !== true ||
        state.outputs.CandidateSha !== previousManifest.previous.candidateSha ||
        state.outputs.ReleaseId !== previousManifest.previous.releaseId,
    ) ||
    states.api.parameters.PublicationState !== expectation.publicationState ||
    states.api.outputs.ApiPublicationStatus !== expectation.publicationState ||
    states.web.parameters.PublicationState !== expectation.publicationState ||
    states.web.outputs.WebPublicationStatus !== expectation.publicationState
  ) {
    fail('E7_VERSIONED_UPDATE_BASELINE_STACK_INVALID');
  }
  try {
    verifyApiPublicationPostureAws(
      context,
      {
        expectedIdentity: previousManifest.previous,
        expectedPublication: expectation,
        expectedResources: previous,
        state: states.api,
      },
      { readAlias, readHttpApi, readMappings, readSchedule },
    );
    verifyWebPublicationPostureAws(
      context,
      {
        expectedIdentity: previousManifest.previous,
        expectedPublication: expectation,
        expectedResources: previous,
        state: states.web,
      },
      { readDistribution, readMutableObjects },
    );
  } catch (error) {
    if (error?.code === 'E7_ROLLBACK_ALIAS_ROUTING_INVALID') throw error;
    fail('E7_VERSIONED_UPDATE_BASELINE_AWS_MISMATCH');
  }
  return states;
};

const selfTestPreviousPublicationExpectations = () => {
  const accountId = '123456789012';
  const region = 'us-east-1';
  const environment = 'assessment-release';
  const previousIdentity = {
    candidateSha: 'a'.repeat(40),
    releaseId: 'rel-20260816-1200-aaaaaaa',
  };
  const api = {
    functionName: 'checkout-assessment-release-api',
    aliasName: 'live',
    version: '7',
    codeSha256: '1'.repeat(64),
  };
  const worker = {
    functionName: 'checkout-assessment-release-worker',
    aliasName: 'live',
    version: '8',
    codeSha256: '2'.repeat(64),
  };
  const web = {
    bucketName: 'checkout-assessment-release-web-123456789012',
    distributionId: 'EDFDVBD6EXAMPLE',
    objects: [
      {
        key: 'index.html',
        versionId: 'index-version',
        etagSha256: '3'.repeat(64),
        contentSha256: '4'.repeat(64),
        bytes: 100,
      },
      {
        key: 'public-config.json',
        versionId: 'config-version',
        etagSha256: '5'.repeat(64),
        contentSha256: '6'.repeat(64),
        bytes: 101,
      },
    ],
    mutableInvalidationPaths: [...VERSIONED_ROLLBACK_INVALIDATION_PATHS],
  };
  const manifestFor = (sourceKind) => ({
    previous: previousIdentity,
    resources: { api, worker, web },
    handoff: { sourceKind },
  });
  const context = {
    config: {
      aws: { accountId, region },
      domain: { apiHostname: 'api.example.test' },
      environment,
    },
    stacks: expectedStacks(environment),
  };
  const fixtureFor = (
    sourceKind,
    { distributionEnabled, mappings: mappingOverride, schedulerState, weightedAlias = false } = {},
  ) => {
    const expectation = previousPublicationExpectation(manifestFor(sourceKind));
    const publicationState = expectation.publicationState;
    const apiOutputs = {
      CandidateSha: previousIdentity.candidateSha,
      ReleaseId: previousIdentity.releaseId,
      ApiAliasArn: `arn:aws:lambda:${region}:${accountId}:function:${api.functionName}:${api.aliasName}`,
      ApiFunctionVersion: api.version,
      WorkerAliasArn: `arn:aws:lambda:${region}:${accountId}:function:${worker.functionName}:${worker.aliasName}`,
      WorkerFunctionVersion: worker.version,
      ApiPublicationStatus: publicationState,
      ApiCustomDomainName: context.config.domain.apiHostname,
      HttpApiId: 'a1b2c3d4e5',
    };
    const state = (outputs, parameters = {}) => ({
      stackStatus: 'UPDATE_COMPLETE',
      terminationProtection: true,
      outputs: {
        CandidateSha: previousIdentity.candidateSha,
        ReleaseId: previousIdentity.releaseId,
        ...outputs,
      },
      parameters,
    });
    const states = {
      data: state({}),
      api: state(apiOutputs, { PublicationState: publicationState }),
      observability: state({}),
      web: state(
        {
          WebBucketName: web.bucketName,
          DistributionId: web.distributionId,
          WebPublicationStatus: publicationState,
        },
        { PublicationState: publicationState },
      ),
    };
    const schedule = {
      Name: `checkout-${environment}-reconcile`,
      State: schedulerState ?? expectation.schedulerState,
      ScheduleExpression: 'rate(1 minute)',
      FlexibleTimeWindow: { Mode: 'OFF' },
      Target: {
        Arn: apiOutputs.WorkerAliasArn,
        RoleArn: `arn:aws:iam::${accountId}:role/checkout-assessment-release-scheduler`,
        Input: JSON.stringify({ action: 'reconcile', mode: 'sandbox' }),
        RetryPolicy: { MaximumEventAgeInSeconds: 300, MaximumRetryAttempts: 2 },
      },
    };
    const mappings =
      mappingOverride ??
      (publicationState === 'ENABLED'
        ? [
            {
              ApiId: apiOutputs.HttpApiId,
              ApiMappingId: 'a1b2c3d4',
              ApiMappingKey: '',
              Stage: '$default',
            },
          ]
        : []);
    return {
      manifest: manifestFor(sourceKind),
      states,
      readers: {
        readAlias: (_activeContext, target) => ({
          FunctionVersion: target.version,
          RevisionId: `revision-${target.functionName}`,
          ...(weightedAlias ? { RoutingConfig: { AdditionalVersionWeights: { 99: 0.1 } } } : {}),
        }),
        readDistribution: () => ({
          ETag: 'etag',
          DistributionConfig: {
            Enabled: distributionEnabled ?? expectation.distributionEnabled,
          },
        }),
        readHttpApi: () => ({ ApiId: apiOutputs.HttpApiId, DisableExecuteApiEndpoint: true }),
        readMappings: () => mappings,
        readMutableObjects: () => web.objects,
        readSchedule: () => schedule,
        readStack: (_activeContext, suffix) => states[suffix],
      },
    };
  };
  for (const sourceKind of ['BASELINE_BOOTSTRAP', 'RELEASE_SUCCESSOR']) {
    const fixture = fixtureFor(sourceKind);
    assert.equal(
      Object.keys(verifyPreviousPublicationBaselineAws(context, fixture.manifest, fixture.readers))
        .length,
      STACK_SUFFIXES.length,
    );
    const expectation = previousPublicationExpectation(fixture.manifest);
    assert.deepEqual(
      verifyApiPublicationPostureAws(
        context,
        {
          expectedFingerprint: stackStateFingerprint(stackFor(context, 'api'), fixture.states.api),
          expectedIdentity: previousIdentity,
          expectedPublication: expectation,
          expectedResources: fixture.manifest.resources,
          state: fixture.states.api,
        },
        fixture.readers,
      ),
      {
        api: {
          aliasName: api.aliasName,
          functionName: api.functionName,
          version: api.version,
        },
        worker: {
          aliasName: worker.aliasName,
          functionName: worker.functionName,
          version: worker.version,
        },
      },
    );
    assert.deepEqual(
      verifyWebPublicationPostureAws(
        context,
        {
          expectedFingerprint: stackStateFingerprint(stackFor(context, 'web'), fixture.states.web),
          expectedIdentity: previousIdentity,
          expectedPublication: expectation,
          expectedResources: fixture.manifest.resources,
          state: fixture.states.web,
        },
        fixture.readers,
      ),
      web.objects,
    );
    assert.throws(
      () =>
        verifyApiPublicationPostureAws(
          context,
          {
            expectedFingerprint: '0'.repeat(64),
            expectedIdentity: previousIdentity,
            expectedPublication: expectation,
            expectedResources: fixture.manifest.resources,
            state: fixture.states.api,
          },
          fixture.readers,
        ),
      (error) =>
        error instanceof Stage7AwsError &&
        error.code === 'E7_VERSIONED_UPDATE_API_POSTURE_MISMATCH',
    );
  }
  for (const fixture of [
    fixtureFor('BASELINE_BOOTSTRAP', { schedulerState: 'ENABLED' }),
    fixtureFor('RELEASE_SUCCESSOR', { distributionEnabled: false }),
    fixtureFor('BASELINE_BOOTSTRAP', {
      mappings: [
        { ApiId: 'foreign1234', ApiMappingId: 'a1b2c3d4', ApiMappingKey: '', Stage: '$default' },
      ],
    }),
    fixtureFor('RELEASE_SUCCESSOR', {
      mappings: [
        { ApiId: 'foreign1234', ApiMappingId: 'a1b2c3d4', ApiMappingKey: '', Stage: '$default' },
      ],
    }),
  ]) {
    assert.throws(
      () => verifyPreviousPublicationBaselineAws(context, fixture.manifest, fixture.readers),
      (error) =>
        error instanceof Stage7AwsError &&
        error.code === 'E7_VERSIONED_UPDATE_BASELINE_AWS_MISMATCH',
    );
  }
  const weighted = fixtureFor('RELEASE_SUCCESSOR', { weightedAlias: true });
  assert.throws(
    () => verifyPreviousPublicationBaselineAws(context, weighted.manifest, weighted.readers),
    (error) =>
      error instanceof Stage7AwsError && error.code === 'E7_ROLLBACK_ALIAS_ROUTING_INVALID',
  );
  assert.throws(
    () => previousPublicationExpectation(manifestFor('UNKNOWN')),
    (error) =>
      error instanceof Stage7AwsError &&
      error.code === 'E7_PREVIOUS_RELEASE_SOURCE_KIND_UNSUPPORTED',
  );
};

const candidateVersionedResourcesAws = (context, previousManifest, { webRecordPath } = {}) => {
  const apiStack = describeStack(context, stackFor(context, 'api'));
  const webStack = describeStack(context, stackFor(context, 'web'));
  const versions = apiVersionsFromOutputs(
    context,
    apiStack.outputs,
    'E7_ROLLBACK_CANDIDATE_API_OUTPUT_INVALID',
  );
  if (
    apiStack.outputs.CandidateSha !== context.identity.candidateSha ||
    apiStack.outputs.ReleaseId !== context.identity.releaseId ||
    webStack.outputs.CandidateSha !== context.identity.candidateSha ||
    webStack.outputs.ReleaseId !== context.identity.releaseId ||
    !['DISABLED', 'ENABLED'].includes(apiStack.parameters.PublicationState) ||
    webStack.parameters.PublicationState !== apiStack.parameters.PublicationState ||
    versions.api.functionName !== previousManifest.resources.api.functionName ||
    versions.api.aliasName !== previousManifest.resources.api.aliasName ||
    versions.worker.functionName !== previousManifest.resources.worker.functionName ||
    versions.worker.aliasName !== previousManifest.resources.worker.aliasName ||
    webStack.outputs.WebBucketName !== previousManifest.resources.web.bucketName ||
    webStack.outputs.DistributionId !== previousManifest.resources.web.distributionId
  ) {
    fail('E7_ROLLBACK_CANDIDATE_RESOURCE_COORDINATES_INVALID');
  }
  const apiAlias = getAlias(context, versions.api);
  const workerAlias = getAlias(context, versions.worker);
  if (
    ![versions.api.version, previousManifest.resources.api.version].includes(
      apiAlias.FunctionVersion,
    ) ||
    ![versions.worker.version, previousManifest.resources.worker.version].includes(
      workerAlias.FunctionVersion,
    )
  ) {
    fail('E7_ROLLBACK_CANDIDATE_ALIAS_STATE_UNKNOWN');
  }
  const api = readVersionedLambda(context, versions.api, previousManifest.target);
  const worker = readVersionedLambda(context, versions.worker, previousManifest.target);
  let objects;
  if (webRecordPath === undefined) {
    objects = latestMutableWebObjects(context, webStack.outputs.WebBucketName);
  } else {
    const webRecord = readRecord(context, 'rollback-web', webRecordPath);
    const deployedByKey = new Map((webRecord.deployed ?? []).map((entry) => [entry.key, entry]));
    if (
      webRecord.bucketName !== webStack.outputs.WebBucketName ||
      webRecord.distributionId !== webStack.outputs.DistributionId ||
      VERSIONED_ROLLBACK_WEB_KEYS.some(
        (key) => !VERSION_ID.test(deployedByKey.get(key)?.versionId ?? ''),
      )
    ) {
      fail('E7_ROLLBACK_CANDIDATE_WEB_RECORD_INVALID');
    }
    objects = VERSIONED_ROLLBACK_WEB_KEYS.map((key) =>
      inspectVersionedWebObject(context, {
        bucketName: webStack.outputs.WebBucketName,
        key,
        versionId: deployedByKey.get(key).versionId,
      }),
    );
  }
  return {
    api,
    worker,
    web: {
      bucketName: webStack.outputs.WebBucketName,
      distributionId: webStack.outputs.DistributionId,
      objects,
      mutableInvalidationPaths: [...VERSIONED_ROLLBACK_INVALIDATION_PATHS],
    },
  };
};

const validatePreviousCompatibilityArtifacts = (flags, previousManifest) => {
  const bindings = [
    ['previous-api-contract-evidence', previousManifest.compatibility.apiContractEvidenceSha256],
    [
      'previous-pending-evidence',
      previousManifest.compatibility.pendingReconciliationEvidenceSha256,
    ],
    ['previous-smoke-evidence', previousManifest.compatibility.smokeEvidenceSha256],
  ];
  if (bindings.some(([flag]) => flags[flag] === undefined)) {
    fail('E7_PREVIOUS_RELEASE_COMPATIBILITY_ARTIFACT_REQUIRED');
  }
  for (const [flag, expected] of bindings) {
    if (fileSha256(flags[flag]) !== expected) {
      fail('E7_PREVIOUS_RELEASE_COMPATIBILITY_ARTIFACT_MISMATCH');
    }
  }
  const manifestDirectory = path.dirname(
    resolveInsideWorkspace(flags['previous-manifest'], 'E7_PREVIOUS_RELEASE_MANIFEST_MISSING', {
      allowDirectory: false,
    }),
  );
  if (previousManifest.handoff.sourceKind === 'RELEASE_SUCCESSOR') {
    let projection;
    try {
      projection = validatePreviousReleaseProjection(manifestDirectory);
    } catch (error) {
      if (
        typeof error?.code === 'string' &&
        error.code.startsWith('E7_PREVIOUS_RELEASE_PROJECTION_')
      ) {
        fail('E7_PREVIOUS_RELEASE_SUCCESSOR_PROJECTION_INVALID');
      }
      throw error;
    }
    if (objectSha256(projection.previousRelease) !== objectSha256(previousManifest)) {
      fail('E7_PREVIOUS_RELEASE_SUCCESSOR_PROJECTION_IDENTITY_MISMATCH');
    }
    return;
  }
  if (previousManifest.handoff.sourceKind !== 'BASELINE_BOOTSTRAP') {
    fail('E7_PREVIOUS_RELEASE_SOURCE_KIND_INVALID');
  }
  const sourceProvenance = readLocalRollbackJson(
    path.join(manifestDirectory, 'previous-source-provenance.json'),
    'E7_PREVIOUS_RELEASE_SOURCE_PROVENANCE_MISSING',
  );
  const targetCompatibility = readLocalRollbackJson(
    path.join(manifestDirectory, 'previous-target-compatibility.json'),
    'E7_PREVIOUS_RELEASE_TARGET_COMPATIBILITY_MISSING',
  );
  const finalDisableProvenance = readLocalRollbackJson(
    path.join(manifestDirectory, 'previous-final-disable-provenance.json'),
    'E7_PREVIOUS_RELEASE_FINAL_DISABLE_PROVENANCE_MISSING',
  );
  validateBaselineSourceProvenance(sourceProvenance);
  validateBaselineFinalDisableProvenance(finalDisableProvenance);
  validateTargetCompatibilityEvidence(targetCompatibility, { previousManifest });
  validateStage7PreviousReleaseHandoff(previousManifest, {
    sourceProvenance,
    targetCompatibility,
    finalDisableProvenance,
  });
};

export const captureCandidateRollbackRecordAws = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  if (flags.scope !== undefined) fail('E7_VERSIONED_ROLLBACK_FULL_SCOPE_REQUIRED');
  const context = loadOperationContext({
    capability: 'read',
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  const freezeManifest = validateFreezeManifest(
    readLocalRollbackJson(flags.manifest, 'E7_FREEZE_MANIFEST_MISSING'),
  );
  const previousManifest = validateStage7PreviousReleaseForTarget(
    readLocalRollbackJson(flags['previous-manifest'], 'E7_PREVIOUS_RELEASE_MANIFEST_MISSING'),
    { config: context.config, freezeManifest },
  );
  if (assembly.assemblySha256 !== previousManifest.target.assemblySha256) {
    fail('E7_PREVIOUS_RELEASE_TARGET_ASSEMBLY_MISMATCH');
  }
  validatePreviousCompatibilityArtifacts(flags, previousManifest);
  validateProtectedApproval(
    context,
    flags.approval,
    flags['approved-plan'],
    assembly,
    flags.manifest,
    flags['aws-auth'],
    previousManifest,
  );
  revalidateAwsIdentity(context);
  verifyPreviousVersionedResourcesAws(context, previousManifest);
  const resources = candidateVersionedResourcesAws(context, previousManifest, {
    webRecordPath: flags['web-record'],
  });
  const record = createStage7CandidateRollbackRecord({
    previousManifest,
    createdAtUtc: flags['captured-at'] ?? utc(now),
    approvalSha256: fileSha256(flags.approval),
    planSha256: fileSha256(flags['approved-plan']),
    deploymentEvidenceSha256: fileSha256(flags['deployment-evidence']),
    resources,
  });
  return writeLocalRollbackJson(flags.output, 'stage7-versioned-rollback-candidate.json', record);
};

const dynamoString = (item, name, code) => {
  const value = item?.[name];
  if (!exactKeys(value, ['S']) || typeof value.S !== 'string' || value.S === '') fail(code);
  return value.S;
};

const dynamoOptionalString = (item, name, code) => {
  if (item?.[name] === undefined) return null;
  return dynamoString(item, name, code);
};

const dynamoBoolean = (item, name, code) => {
  const value = item?.[name];
  if (!exactKeys(value, ['BOOL']) || typeof value.BOOL !== 'boolean') fail(code);
  return value.BOOL;
};

const checkoutTableName = (context) => {
  const state = describeStack(context, stackFor(context, 'data'));
  const tableName = state.outputs.CheckoutTableName;
  if (
    !DYNAMODB_TABLE_NAME.test(tableName ?? '') ||
    state.outputs.CandidateSha !== context.identity.candidateSha ||
    state.outputs.ReleaseId !== context.identity.releaseId
  ) {
    fail('E7_ROLLBACK_DATA_STACK_INVALID');
  }
  return tableName;
};

const capturePendingSnapshotAws = (context) => {
  const tableName = checkoutTableName(context);
  const response = awsJson(
    context,
    [
      'dynamodb',
      'query',
      '--table-name',
      tableName,
      '--index-name',
      PENDING_INDEX_NAME,
      '--key-condition-expression',
      '#pending = :pending',
      '--expression-attribute-names',
      JSON.stringify({ '#pending': 'GSI2PK' }),
      '--expression-attribute-values',
      JSON.stringify({ ':pending': { S: PENDING_INDEX_PARTITION } }),
      '--projection-expression',
      'PK, SK, acceptedAt, paymentStatus',
      '--scan-index-forward',
    ],
    'E7_ROLLBACK_PENDING_QUERY_FAILED',
  );
  if (
    !Array.isArray(response?.Items) ||
    response.LastEvaluatedKey !== undefined ||
    response.NextToken !== undefined
  ) {
    fail('E7_ROLLBACK_PENDING_QUERY_INCOMPLETE');
  }
  const privateItems = response.Items.map((item) => {
    const paymentStatus = dynamoString(item, 'paymentStatus', 'E7_ROLLBACK_PENDING_ITEM_INVALID');
    const acceptedAt = dynamoString(item, 'acceptedAt', 'E7_ROLLBACK_PENDING_ITEM_INVALID');
    if (paymentStatus !== 'PENDING' || !canonicalUtc(acceptedAt)) {
      fail('E7_ROLLBACK_PENDING_ITEM_INVALID');
    }
    return {
      PK: dynamoString(item, 'PK', 'E7_ROLLBACK_PENDING_ITEM_INVALID'),
      SK: dynamoString(item, 'SK', 'E7_ROLLBACK_PENDING_ITEM_INVALID'),
      acceptedAt,
    };
  });
  privateItems.sort((left, right) =>
    `${left.PK}\0${left.SK}`.localeCompare(`${right.PK}\0${right.SK}`),
  );
  if (new Set(privateItems.map(({ PK, SK }) => `${PK}\0${SK}`)).size !== privateItems.length) {
    fail('E7_ROLLBACK_PENDING_ITEM_DUPLICATE');
  }
  const publicItems = privateItems.map(({ PK, SK, acceptedAt }) => ({
    keySha256: sha256(`${PK}\0${SK}`),
    acceptedAt,
  }));
  const oldest = privateItems[0]?.acceptedAt;
  return {
    tableName,
    privateItems,
    public: {
      observedAtUtc: utc(context.now),
      trackedCount: privateItems.length,
      oldestAgeSeconds:
        oldest === undefined
          ? 0
          : Math.max(0, Math.floor((context.now.getTime() - Date.parse(oldest)) / 1000)),
      snapshotSha256: objectSha256(publicItems),
    },
  };
};

const stableTableFacts = (context, tableName) => {
  if (!DYNAMODB_TABLE_NAME.test(tableName ?? '')) fail('E7_ROLLBACK_TABLE_NAME_INVALID');
  const response = awsJson(
    context,
    ['dynamodb', 'describe-table', '--table-name', tableName],
    'E7_ROLLBACK_TABLE_DESCRIBE_FAILED',
  );
  const table = response?.Table;
  if (
    table?.TableName !== tableName ||
    table?.TableStatus !== 'ACTIVE' ||
    typeof table?.TableArn !== 'string' ||
    typeof table?.TableId !== 'string' ||
    table?.DeletionProtectionEnabled !== true ||
    table?.SSEDescription?.Status !== 'ENABLED'
  ) {
    fail('E7_ROLLBACK_TABLE_FACTS_INVALID');
  }
  return {
    tableName,
    tableArnSha256: sha256(table.TableArn),
    tableIdSha256: sha256(table.TableId),
    keySchemaSha256: objectSha256(table.KeySchema ?? []),
    attributeDefinitionsSha256: objectSha256(table.AttributeDefinitions ?? []),
    globalSecondaryIndexesSha256: objectSha256(
      (table.GlobalSecondaryIndexes ?? []).map(
        ({ IndexArn, IndexSizeBytes, ItemCount, ...index }) => {
          void IndexArn;
          void IndexSizeBytes;
          void ItemCount;
          return index;
        },
      ),
    ),
    billingMode: table.BillingModeSummary?.BillingMode ?? 'PAY_PER_REQUEST',
    deletionProtection: table.DeletionProtectionEnabled,
    sseStatus: table.SSEDescription.Status,
  };
};

const captureForwardOnlyDataFactsAws = (context) => {
  const state = describeStack(context, stackFor(context, 'data'));
  const catalogTableName = state.outputs.CatalogTableName;
  const checkoutName = state.outputs.CheckoutTableName;
  if (
    !DYNAMODB_TABLE_NAME.test(catalogTableName ?? '') ||
    !DYNAMODB_TABLE_NAME.test(checkoutName ?? '') ||
    state.terminationProtection !== true ||
    !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus)
  ) {
    fail('E7_ROLLBACK_DATA_FACTS_INVALID');
  }
  return objectSha256({
    stackIdSha256: sha256(state.stackId),
    catalog: stableTableFacts(context, catalogTableName),
    checkout: stableTableFacts(context, checkoutName),
    dataPolicy: 'NO_ROLLBACK_FORWARD_ONLY',
  });
};

const getDynamoItem = (context, tableName, PK, SK) => {
  const response = awsJson(
    context,
    [
      'dynamodb',
      'get-item',
      '--table-name',
      tableName,
      '--key',
      JSON.stringify({ PK: { S: PK }, SK: { S: SK } }),
      '--consistent-read',
    ],
    'E7_ROLLBACK_PENDING_ITEM_READ_FAILED',
  );
  return response?.Item ?? null;
};

const queryCheckoutPartition = (context, tableName, PK) => {
  const response = awsJson(
    context,
    [
      'dynamodb',
      'query',
      '--table-name',
      tableName,
      '--key-condition-expression',
      'PK = :pk',
      '--expression-attribute-values',
      JSON.stringify({ ':pk': { S: PK } }),
      '--projection-expression',
      'PK, SK, itemType, transactionId, #status',
      '--expression-attribute-names',
      JSON.stringify({ '#status': 'status' }),
      '--consistent-read',
    ],
    'E7_ROLLBACK_PENDING_PARTITION_READ_FAILED',
  );
  if (
    !Array.isArray(response?.Items) ||
    response.LastEvaluatedKey !== undefined ||
    response.NextToken !== undefined
  ) {
    fail('E7_ROLLBACK_PENDING_PARTITION_INCOMPLETE');
  }
  return response.Items;
};

const terminalPendingFacts = (context, tableName, tracked) => {
  let orphaned = 0;
  let duplicateEffects = 0;
  let lostFacts = 0;
  const terminalStatusCounts = { APPROVED: 0, DECLINED: 0, VOIDED: 0, ERROR: 0 };
  const correlation = [];
  for (const { PK, SK } of tracked) {
    const payment = getDynamoItem(context, tableName, PK, SK);
    if (payment === null) {
      orphaned += 1;
      continue;
    }
    const status = dynamoString(payment, 'paymentStatus', 'E7_ROLLBACK_TERMINAL_ITEM_INVALID');
    const transactionId = dynamoString(
      payment,
      'transactionId',
      'E7_ROLLBACK_TERMINAL_ITEM_INVALID',
    );
    const reservationStatus = dynamoString(
      payment,
      'reservationStatus',
      'E7_ROLLBACK_TERMINAL_ITEM_INVALID',
    );
    const integrityStatus = dynamoString(
      payment,
      'integrityStatus',
      'E7_ROLLBACK_TERMINAL_ITEM_INVALID',
    );
    const deliveryId = dynamoOptionalString(
      payment,
      'deliveryId',
      'E7_ROLLBACK_TERMINAL_ITEM_INVALID',
    );
    const effectsApplied = dynamoBoolean(
      payment,
      'effectsApplied',
      'E7_ROLLBACK_TERMINAL_ITEM_INVALID',
    );
    const terminal = ['APPROVED', 'DECLINED', 'VOIDED', 'ERROR'].includes(status);
    const approved = status === 'APPROVED';
    if (terminal) terminalStatusCounts[status] += 1;
    if (
      !terminal ||
      integrityStatus !== 'OK' ||
      effectsApplied !== true ||
      reservationStatus !== (approved ? 'CONSUMED' : 'RELEASED') ||
      (approved ? deliveryId === null : deliveryId !== null) ||
      payment.GSI2PK !== undefined ||
      payment.GSI2SK !== undefined
    ) {
      lostFacts += 1;
      continue;
    }
    const partition = queryCheckoutPartition(context, tableName, PK);
    const reservation = partition.filter(
      (item) =>
        dynamoOptionalString(item, 'itemType', 'E7_ROLLBACK_TERMINAL_PARTITION_INVALID') ===
          'RESERVATION' &&
        dynamoOptionalString(item, 'transactionId', 'E7_ROLLBACK_TERMINAL_PARTITION_INVALID') ===
          transactionId,
    );
    const deliveries = partition.filter(
      (item) =>
        dynamoOptionalString(item, 'itemType', 'E7_ROLLBACK_TERMINAL_PARTITION_INVALID') ===
          'DELIVERY' &&
        dynamoOptionalString(item, 'transactionId', 'E7_ROLLBACK_TERMINAL_PARTITION_INVALID') ===
          transactionId,
    );
    if (reservation.length !== 1) lostFacts += 1;
    else if (
      dynamoOptionalString(reservation[0], 'status', 'E7_ROLLBACK_TERMINAL_PARTITION_INVALID') !==
      reservationStatus
    ) {
      lostFacts += 1;
    }
    const expectedDeliveries = approved ? 1 : 0;
    if (deliveries.length > expectedDeliveries) duplicateEffects += 1;
    if (deliveries.length < expectedDeliveries) lostFacts += 1;
    correlation.push({ keySha256: sha256(`${PK}\0${SK}`), status, reservationStatus });
  }
  return {
    orphaned,
    duplicateEffects,
    lostFacts,
    terminalStatusCounts,
    correlationEvidenceSha256: objectSha256(correlation),
  };
};

const verifyPendingIntegrityAws = async (
  context,
  baseline,
  { delayImplementation = delay, attempts = 20 } = {},
) => {
  let after = capturePendingSnapshotAws(context);
  const trackedKeys = new Set(baseline.privateItems.map(({ PK, SK }) => `${PK}\0${SK}`));
  let stillPending = after.privateItems.filter(({ PK, SK }) =>
    trackedKeys.has(`${PK}\0${SK}`),
  ).length;
  for (let attempt = 1; stillPending > 0 && attempt < attempts; attempt += 1) {
    await delayImplementation(2000);
    after = capturePendingSnapshotAws(context);
    stillPending = after.privateItems.filter(({ PK, SK }) =>
      trackedKeys.has(`${PK}\0${SK}`),
    ).length;
  }
  if (stillPending > 0) fail('E7_ROLLBACK_PENDING_RECONCILIATION_TIMEOUT');
  const terminal = terminalPendingFacts(context, baseline.tableName, baseline.privateItems);
  const result = {
    status: 'PASS',
    beforeSnapshotSha256: baseline.public.snapshotSha256,
    afterSnapshotSha256: after.public.snapshotSha256,
    correlationEvidenceSha256: terminal.correlationEvidenceSha256,
    trackedBefore: baseline.privateItems.length,
    stillPending,
    reconciled: baseline.privateItems.length - stillPending,
    orphaned: terminal.orphaned,
    duplicateEffects: terminal.duplicateEffects,
    lostFacts: terminal.lostFacts,
    terminalStatusCounts: terminal.terminalStatusCounts,
  };
  if (terminal.orphaned !== 0 || terminal.duplicateEffects !== 0 || terminal.lostFacts !== 0) {
    fail('E7_ROLLBACK_PENDING_INTEGRITY_FAILED');
  }
  return result;
};

const assertAliasWithoutWeightedRouting = (alias) => {
  const weights = alias?.RoutingConfig?.AdditionalVersionWeights;
  if (
    typeof alias?.RevisionId !== 'string' ||
    alias.RevisionId === '' ||
    (weights !== undefined && (!object(weights) || Object.keys(weights).length !== 0))
  ) {
    fail('E7_ROLLBACK_ALIAS_ROUTING_INVALID');
  }
  return alias;
};

const verifyCandidateVersionedResourcesAws = (context, previousManifest, candidateRecord) => {
  const candidate = candidateRecord.resources;
  const api = readVersionedLambda(context, candidate.api, previousManifest.target);
  const worker = readVersionedLambda(context, candidate.worker, previousManifest.target);
  assertVersionedResourceMatches(api, candidate.api, 'E7_CANDIDATE_ROLLBACK_API_AWS_MISMATCH');
  assertVersionedResourceMatches(
    worker,
    candidate.worker,
    'E7_CANDIDATE_ROLLBACK_WORKER_AWS_MISMATCH',
  );
  const objects = candidate.web.objects.map((entry) =>
    inspectVersionedWebObject(context, {
      bucketName: candidate.web.bucketName,
      key: entry.key,
      versionId: entry.versionId,
    }),
  );
  assertVersionedResourceMatches(
    objects,
    candidate.web.objects,
    'E7_CANDIDATE_ROLLBACK_WEB_AWS_MISMATCH',
  );
};

const observedVersionedRollbackStateAws = (context, previousManifest, candidateRecord) => {
  const coordinates = candidateRecord.resources;
  const apiAlias = assertAliasWithoutWeightedRouting(getAlias(context, coordinates.api));
  const workerAlias = assertAliasWithoutWeightedRouting(getAlias(context, coordinates.worker));
  const objects = latestMutableWebObjects(context, coordinates.web.bucketName);
  const pending = capturePendingSnapshotAws(context);
  const dataFactsSha256 = captureForwardOnlyDataFactsAws(context);
  return {
    state: {
      api: {
        functionName: coordinates.api.functionName,
        aliasName: coordinates.api.aliasName,
        version: apiAlias.FunctionVersion,
      },
      worker: {
        functionName: coordinates.worker.functionName,
        aliasName: coordinates.worker.aliasName,
        version: workerAlias.FunctionVersion,
      },
      web: {
        bucketName: coordinates.web.bucketName,
        distributionId: coordinates.web.distributionId,
        objects: objects.map(({ key, versionId, contentSha256 }) => ({
          key,
          versionId,
          contentSha256,
        })),
      },
      pending: pending.public,
      dataFactsSha256,
    },
    pending,
  };
};

const updateAliasVersionAws = (context, operation) => {
  const before = assertAliasWithoutWeightedRouting(getAlias(context, operation));
  if (before.FunctionVersion === operation.toVersion) return before;
  if (before.FunctionVersion !== operation.fromVersion || operation.changed !== true) {
    fail('E7_ROLLBACK_ALIAS_PRECONDITION_FAILED');
  }
  const updated = awsJson(
    context,
    [
      'lambda',
      'update-alias',
      '--function-name',
      operation.functionName,
      '--name',
      operation.aliasName,
      '--function-version',
      operation.toVersion,
      '--revision-id',
      before.RevisionId,
    ],
    'E7_ROLLBACK_ALIAS_UPDATE_FAILED',
  );
  if (
    updated?.Name !== operation.aliasName ||
    updated?.FunctionVersion !== operation.toVersion ||
    typeof updated?.RevisionId !== 'string'
  ) {
    fail('E7_ROLLBACK_ALIAS_UPDATE_INVALID');
  }
  const after = assertAliasWithoutWeightedRouting(getAlias(context, operation));
  if (after.FunctionVersion !== operation.toVersion) fail('E7_ROLLBACK_ALIAS_UPDATE_NOT_VISIBLE');
  return after;
};

const copyArchivedWebVersionAws = (context, web, operation) => {
  if (!operation.changed) return null;
  const copySource = `${web.bucketName}/${encodeURIComponent(operation.key)}?versionId=${encodeURIComponent(operation.toVersionId)}`;
  const response = awsJson(
    context,
    [
      's3api',
      'copy-object',
      '--bucket',
      web.bucketName,
      '--key',
      operation.key,
      '--copy-source',
      copySource,
      '--metadata-directive',
      'COPY',
      '--tagging-directive',
      'COPY',
    ],
    'E7_ROLLBACK_WEB_OBJECT_RESTORE_FAILED',
  );
  if (!VERSION_ID.test(response?.VersionId ?? '')) fail('E7_ROLLBACK_WEB_OBJECT_RESTORE_INVALID');
  const restored = inspectVersionedWebObject(context, {
    bucketName: web.bucketName,
    key: operation.key,
    versionId: response.VersionId,
  });
  if (restored.contentSha256 !== operation.toContentSha256) {
    fail('E7_ROLLBACK_WEB_OBJECT_RESTORE_DIGEST_MISMATCH');
  }
  return restored;
};

const invalidateMutableWebPathsAws = async (
  context,
  plan,
  { delayImplementation = delay, attempts = 30 } = {},
) => {
  if (plan.decision === 'NOOP_ALREADY_APPLIED') {
    return { status: 'NOT_REQUIRED', idSha256: null, paths: [] };
  }
  const callerReference = `stage7-${plan.planSha256}`;
  const response = awsJson(
    context,
    [
      'cloudfront',
      'create-invalidation',
      '--distribution-id',
      plan.web.distributionId,
      '--invalidation-batch',
      JSON.stringify({
        Paths: { Quantity: plan.web.invalidationPaths.length, Items: plan.web.invalidationPaths },
        CallerReference: callerReference,
      }),
    ],
    'E7_ROLLBACK_WEB_INVALIDATION_FAILED',
    { region: 'us-east-1' },
  );
  const invalidation = response?.Invalidation;
  if (
    typeof invalidation?.Id !== 'string' ||
    invalidation.Id === '' ||
    invalidation?.InvalidationBatch?.CallerReference !== callerReference ||
    invalidation?.InvalidationBatch?.Paths?.Items?.join('\0') !==
      plan.web.invalidationPaths.join('\0')
  ) {
    fail('E7_ROLLBACK_WEB_INVALIDATION_INVALID');
  }
  let status = invalidation.Status;
  for (let attempt = 0; status !== 'Completed' && attempt < attempts; attempt += 1) {
    if (attempt > 0) await delayImplementation(2000);
    const current = awsJson(
      context,
      [
        'cloudfront',
        'get-invalidation',
        '--distribution-id',
        plan.web.distributionId,
        '--id',
        invalidation.Id,
      ],
      'E7_ROLLBACK_WEB_INVALIDATION_READ_FAILED',
      { region: 'us-east-1' },
    );
    status = current?.Invalidation?.Status;
  }
  if (status !== 'Completed') fail('E7_ROLLBACK_WEB_INVALIDATION_TIMEOUT');
  return {
    status: 'COMPLETED',
    idSha256: sha256(invalidation.Id),
    paths: [...plan.web.invalidationPaths],
  };
};

const applyVersionedRollbackPlanAws = async (
  context,
  plan,
  { delayImplementation = delay } = {},
) => {
  if (plan.decision !== 'NOOP_ALREADY_APPLIED') {
    if (plan.aliases.api.changed) updateAliasVersionAws(context, plan.aliases.api);
    if (plan.aliases.worker.changed) updateAliasVersionAws(context, plan.aliases.worker);
    for (const operation of plan.web.objects) {
      copyArchivedWebVersionAws(context, plan.web, operation);
    }
  }
  return invalidateMutableWebPathsAws(context, plan, { delayImplementation });
};

const verifyDestinationStateAws = (context, destination) => {
  const api = assertAliasWithoutWeightedRouting(getAlias(context, destination.api));
  const worker = assertAliasWithoutWeightedRouting(getAlias(context, destination.worker));
  if (
    api.FunctionVersion !== destination.api.version ||
    worker.FunctionVersion !== destination.worker.version
  ) {
    fail('E7_ROLLBACK_DESTINATION_ALIAS_MISMATCH');
  }
  const expectedByKey = new Map(destination.web.objects.map((entry) => [entry.key, entry]));
  const objects = latestMutableWebObjects(context, destination.web.bucketName);
  if (
    objects.some((entry) => {
      const expected = expectedByKey.get(entry.key);
      return (
        expected === undefined ||
        entry.contentSha256 !== expected.contentSha256 ||
        entry.bytes !== expected.bytes
      );
    })
  ) {
    fail('E7_ROLLBACK_DESTINATION_WEB_MISMATCH');
  }
  return {
    aliases: {
      api: {
        functionName: destination.api.functionName,
        aliasName: destination.api.aliasName,
        version: destination.api.version,
      },
      worker: {
        functionName: destination.worker.functionName,
        aliasName: destination.worker.aliasName,
        version: destination.worker.version,
      },
    },
    web: {
      bucketName: destination.web.bucketName,
      distributionId: destination.web.distributionId,
      objects: objects.map((entry) => ({
        key: entry.key,
        sourceVersionId: expectedByKey.get(entry.key).versionId,
        activeVersionId: entry.versionId,
        contentSha256: entry.contentSha256,
        bytes: entry.bytes,
      })),
    },
  };
};

const validateVersionedRollbackExecutionInputs = (
  context,
  flags,
  { requireActive = true, bindCaller = false } = {},
) => {
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  const freezeManifest = validateFreezeManifest(
    readLocalRollbackJson(flags.manifest, 'E7_FREEZE_MANIFEST_MISSING'),
  );
  const previousManifest = validateStage7PreviousReleaseForTarget(
    readLocalRollbackJson(flags['previous-manifest'], 'E7_PREVIOUS_RELEASE_MANIFEST_MISSING'),
    { config: context.config, freezeManifest },
  );
  if (assembly.assemblySha256 !== previousManifest.target.assemblySha256) {
    fail('E7_PREVIOUS_RELEASE_TARGET_ASSEMBLY_MISMATCH');
  }
  validatePreviousCompatibilityArtifacts(flags, previousManifest);
  const candidateRecord = validateStage7CandidateRollbackRecord(
    readLocalRollbackJson(flags['candidate-record'], 'E7_CANDIDATE_ROLLBACK_RECORD_MISSING'),
    {
      previousManifest,
      approvalSha256: fileSha256(flags.approval),
      planSha256: fileSha256(flags['approved-plan']),
      deploymentEvidenceSha256: fileSha256(flags['deployment-evidence']),
    },
  );
  validateProtectedApproval(
    context,
    flags.approval,
    flags['approved-plan'],
    assembly,
    flags.manifest,
    flags['aws-auth'],
    previousManifest,
  );
  const apiState = describeStack(context, stackFor(context, 'api'));
  const webState = describeStack(context, stackFor(context, 'web'));
  if (
    !['DISABLED', 'ENABLED'].includes(apiState.parameters.PublicationState) ||
    !['DISABLED', 'ENABLED'].includes(webState.parameters.PublicationState) ||
    (requireActive &&
      (apiState.parameters.PublicationState !== 'ENABLED' ||
        webState.parameters.PublicationState !== 'ENABLED')) ||
    apiState.outputs.ApiAliasArn === undefined ||
    apiState.outputs.WorkerAliasArn === undefined ||
    webState.outputs.WebBucketName !== candidateRecord.resources.web.bucketName ||
    webState.outputs.DistributionId !== candidateRecord.resources.web.distributionId
  ) {
    fail('E7_VERSIONED_ROLLBACK_PUBLICATION_NOT_ACTIVE');
  }
  const callerBinding = bindCaller ? revalidateAwsIdentityBinding(context) : null;
  if (!bindCaller) revalidateAwsIdentity(context);
  verifyPreviousVersionedResourcesAws(context, previousManifest);
  verifyCandidateVersionedResourcesAws(context, previousManifest, candidateRecord);
  return {
    assembly,
    previousManifest,
    candidateRecord,
    callerBinding,
    publicationState: {
      api: apiState.parameters.PublicationState,
      web: webState.parameters.PublicationState,
    },
  };
};

const versionedRollbackIntentPath = (context) =>
  path.join(internalRoot(context.config), 'versioned-rollback-intent.json');

const rollbackIntentBody = (intent) => {
  const body = { ...intent };
  delete body.intentSha256;
  return body;
};

const validateRollbackIntent = (intent, context, previousManifest, candidateRecord) => {
  if (
    !exactKeys(intent, [
      'schemaVersion',
      'stage',
      'kind',
      'environment',
      'candidateSha',
      'releaseId',
      'previousReleaseManifestSha256',
      'candidateRecordSha256',
      'tableName',
      'pendingBaseline',
      'privateItems',
      'privateItemsSha256',
      'dataFactsSha256',
      'createdAtUtc',
      'intentSha256',
    ]) ||
    intent.schemaVersion !== 1 ||
    intent.stage !== 7 ||
    intent.kind !== 'VERSIONED_ROLLBACK_PRIVATE_INTENT' ||
    intent.environment !== context.config.environment ||
    intent.candidateSha !== context.identity.candidateSha ||
    intent.releaseId !== context.identity.releaseId ||
    intent.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    intent.candidateRecordSha256 !== candidateRecord.recordSha256 ||
    !DYNAMODB_TABLE_NAME.test(intent.tableName ?? '') ||
    !Array.isArray(intent.privateItems) ||
    intent.privateItems.some(
      (item) =>
        !exactKeys(item, ['PK', 'SK', 'acceptedAt']) ||
        typeof item.PK !== 'string' ||
        item.PK === '' ||
        typeof item.SK !== 'string' ||
        item.SK === '' ||
        !canonicalUtc(item.acceptedAt),
    ) ||
    intent.privateItemsSha256 !== objectSha256(intent.privateItems) ||
    intent.pendingBaseline?.trackedCount !== intent.privateItems.length ||
    !SHA256.test(intent.pendingBaseline?.snapshotSha256 ?? '') ||
    !SHA256.test(intent.dataFactsSha256 ?? '') ||
    !canonicalUtc(intent.createdAtUtc) ||
    intent.intentSha256 !== objectSha256(rollbackIntentBody(intent))
  ) {
    fail('E7_ROLLBACK_PRIVATE_INTENT_INVALID');
  }
  return intent;
};

const createOrLoadRollbackIntent = (context, previousManifest, candidateRecord, observed) => {
  const target = versionedRollbackIntentPath(context);
  if (existsSync(target)) {
    const intent = validateRollbackIntent(
      readJson(target, 'E7_ROLLBACK_PRIVATE_INTENT_INVALID'),
      context,
      previousManifest,
      candidateRecord,
    );
    if (
      intent.tableName !== observed.pending.tableName ||
      intent.dataFactsSha256 !== observed.state.dataFactsSha256
    ) {
      fail('E7_ROLLBACK_PRIVATE_INTENT_STATE_MISMATCH');
    }
    return intent;
  }
  if (observed.pending.privateItems.length < 1) {
    fail('E7_ROLLBACK_PENDING_REHEARSAL_REQUIRED');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_PRIVATE_INTENT',
    environment: context.config.environment,
    candidateSha: context.identity.candidateSha,
    releaseId: context.identity.releaseId,
    previousReleaseManifestSha256: previousManifest.manifestSha256,
    candidateRecordSha256: candidateRecord.recordSha256,
    tableName: observed.pending.tableName,
    pendingBaseline: observed.pending.public,
    privateItems: observed.pending.privateItems,
    privateItemsSha256: objectSha256(observed.pending.privateItems),
    dataFactsSha256: observed.state.dataFactsSha256,
    createdAtUtc: utc(context.now),
  };
  const intent = { ...body, intentSha256: objectSha256(body) };
  validateRollbackIntent(intent, context, previousManifest, candidateRecord);
  atomicPrivateJson(target, intent);
  return intent;
};

const publicIntentEvidence = (intent) => ({
  status: 'LOCKED_BEFORE_MUTATION',
  previousReleaseManifestSha256: intent.previousReleaseManifestSha256,
  candidateRecordSha256: intent.candidateRecordSha256,
  pendingBaseline: intent.pendingBaseline,
  pendingCorrelationSha256: intent.privateItemsSha256,
  dataFactsSha256: intent.dataFactsSha256,
  intentSha256: intent.intentSha256,
  containsSensitiveData: false,
});

const transitionForVersionedRollback = ({
  context,
  plan,
  previousManifest,
  candidateRecord,
  verified,
  invalidation,
  pendingIntegrity,
}) => {
  return createStage7VersionedRollbackTransition({
    plan,
    previousManifest,
    candidateRecord,
    startedAtUtc: utc(context.now),
    completedAtUtc: utc(context.now),
    aliases: verified.aliases,
    web: { ...verified.web, invalidation },
    pendingIntegrity,
  });
};

const finalizeVersionedRollbackEnvelope = async (context, previousManifest, candidateRecord) => {
  const target = evidenceTarget(context, 'rollback');
  const evidence = readJson(target, 'E7_VERSIONED_ROLLBACK_EVIDENCE_MISSING');
  const checkpoints = evidence?.checkpoints;
  if (
    checkpoints?.rollbackPlan === undefined ||
    checkpoints?.rollbackCheckpoint === undefined ||
    checkpoints?.repromotionPlan === undefined ||
    checkpoints?.repromotionCheckpoint === undefined
  ) {
    return null;
  }
  const rehearsal = createStage7VersionedRollbackRehearsal({
    previousManifest,
    candidateRecord,
    rollbackPlan: checkpoints.rollbackPlan,
    rollbackCheckpoint: checkpoints.rollbackCheckpoint,
    repromotionPlan: checkpoints.repromotionPlan,
    repromotionCheckpoint: checkpoints.repromotionCheckpoint,
  });
  validateStage7VersionedRollbackRehearsal(rehearsal, {
    previousManifest,
    candidateRecord,
  });
  const finalized = {
    ...evidence,
    status: 'BLOCKED_REQUIRED_SCENARIOS',
    checkpoints: { ...checkpoints, versionedRollbackRehearsal: rehearsal },
    updatedAtUtc: rehearsal.completedAtUtc,
  };
  await writeSanitizedJsonAtomic(target, 'stage7-rollback.json', finalized);
  return rehearsal;
};

const versionedRollbackTransitionBodyForAws = (transition) => {
  const body = { ...transition };
  delete body.transitionSha256;
  return body;
};

const validateVersionedRollbackSmokeEvidence = (
  smoke,
  { context, plan, transition, freezeManifest },
) => {
  const expectedMode =
    plan.direction === 'ROLLBACK_TO_PREVIOUS'
      ? 'POST_ROLLBACK_VERSIONED'
      : 'POST_REPROMOTION_VERSIONED';
  if (
    smoke?.schemaVersion !== 1 ||
    smoke?.stage !== 7 ||
    smoke?.kind !== 'DEPLOYED_BLACK_BOX_SMOKE' ||
    smoke?.status !== 'PASS' ||
    smoke?.scope !== 'full' ||
    smoke?.mode !== expectedMode ||
    smoke?.candidateSha !== context.identity.candidateSha ||
    smoke?.releaseId !== context.identity.releaseId ||
    smoke?.targetReleaseId !== plan.toReleaseId ||
    smoke?.manifestSha256 !== freezeManifest.manifestSha256 ||
    smoke?.stage7ConfigSha256 !== objectSha256(context.config) ||
    !canonicalUtc(smoke?.executedAtUtc) ||
    Date.parse(smoke.executedAtUtc) < Date.parse(transition.completedAtUtc) ||
    smoke?.total !== 3 ||
    smoke?.passed !== 3 ||
    smoke?.failed !== 0 ||
    smoke?.requests?.total !== 3 ||
    smoke?.requests?.ownedOrigin !== 3 ||
    smoke?.requests?.provider !== 0 ||
    smoke?.requests?.production !== 0 ||
    smoke?.requests?.outsideAllowlist !== 0 ||
    smoke?.dataMutations !== 0 ||
    smoke?.externalRequests !== 3 ||
    smoke?.mutationsPerformed !== 0 ||
    smoke?.containsSensitiveData !== false ||
    !SHA256.test(smoke?.externalAuthorization?.authorizationSha256 ?? '') ||
    !SHA256.test(smoke?.authorizationUsage?.bundleSha256 ?? '')
  ) {
    fail('E7_VERSIONED_ROLLBACK_SMOKE_EVIDENCE_INVALID');
  }
  return smoke;
};

const checkpointFromTransitionAndSmoke = ({
  transition,
  smokeEvidenceSha256,
  plan,
  previousManifest,
  candidateRecord,
}) => {
  const body = {
    ...versionedRollbackTransitionBodyForAws(transition),
    kind: 'VERSIONED_ROLLBACK_CHECKPOINT',
    status: 'PASS',
    scenarioIds:
      transition.direction === 'ROLLBACK_TO_PREVIOUS'
        ? ['RB-E7-01', 'RB-E7-03', 'RB-E7-05', 'RB-E7-07']
        : ['RB-E7-02', 'RB-E7-04', 'RB-E7-05', 'RB-E7-07'],
    smoke: {
      status: 'PASS',
      releaseId: transition.toReleaseId,
      evidenceSha256: smokeEvidenceSha256,
    },
  };
  const checkpoint = { ...body, checkpointSha256: objectSha256(body) };
  return validateStage7VersionedRollbackCheckpoint(checkpoint, {
    plan,
    previousManifest,
    candidateRecord,
  });
};

export const finalizeVersionedRollback = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  if (flags.scope !== undefined) fail('E7_VERSIONED_ROLLBACK_FULL_SCOPE_REQUIRED');
  const context = loadOperationContext({
    capability: 'read',
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const { previousManifest, candidateRecord } = validateVersionedRollbackExecutionInputs(
    context,
    flags,
  );
  const freezeManifest = validateFreezeManifest(
    readLocalRollbackJson(flags.manifest, 'E7_FREEZE_MANIFEST_MISSING'),
  );
  const transition = readLocalRollbackJson(
    flags.transition,
    'E7_VERSIONED_ROLLBACK_TRANSITION_MISSING',
  );
  const evidence = readJson(
    evidenceTarget(context, 'rollback'),
    'E7_VERSIONED_ROLLBACK_EVIDENCE_MISSING',
  );
  const planKey =
    transition?.direction === 'ROLLBACK_TO_PREVIOUS' ? 'rollbackPlan' : 'repromotionPlan';
  const checkpointKey =
    transition?.direction === 'ROLLBACK_TO_PREVIOUS'
      ? 'rollbackCheckpoint'
      : 'repromotionCheckpoint';
  const plan = evidence?.checkpoints?.[planKey];
  validateStage7VersionedRollbackTransition(transition, {
    plan,
    previousManifest,
    candidateRecord,
  });
  const destination =
    transition.direction === 'ROLLBACK_TO_PREVIOUS'
      ? previousManifest.resources
      : candidateRecord.resources;
  const live = verifyDestinationStateAws(context, destination);
  if (
    objectSha256(live.aliases) !== objectSha256(transition.aliases) ||
    objectSha256(live.web) !==
      objectSha256({
        bucketName: transition.web.bucketName,
        distributionId: transition.web.distributionId,
        objects: transition.web.objects,
      })
  ) {
    fail('E7_VERSIONED_ROLLBACK_STATE_CHANGED_BEFORE_SMOKE_FINALIZATION');
  }
  const smokePath = flags['smoke-evidence'];
  validateVersionedRollbackSmokeEvidence(
    readLocalRollbackJson(smokePath, 'E7_VERSIONED_ROLLBACK_SMOKE_EVIDENCE_MISSING'),
    { context, plan, transition, freezeManifest },
  );
  const checkpoint = checkpointFromTransitionAndSmoke({
    transition,
    smokeEvidenceSha256: fileSha256(smokePath),
    plan,
    previousManifest,
    candidateRecord,
  });
  await updateEvidence(context, 'rollback', checkpointKey, checkpoint);
  const rehearsal = await finalizeVersionedRollbackEnvelope(
    context,
    previousManifest,
    candidateRecord,
  );
  await writeLocalRollbackJson(
    flags.output,
    `stage7-${transition.direction.toLowerCase()}-checkpoint.json`,
    checkpoint,
  );
  return { ...checkpoint, rehearsalSha256: rehearsal?.rehearsalSha256 ?? null };
};

const executeVersionedRollbackWithContext = async ({
  context,
  flags,
  delayImplementation,
  runMutation = ({ mutation }) => mutation(),
}) => {
  const { previousManifest, candidateRecord } = validateVersionedRollbackExecutionInputs(
    context,
    flags,
  );
  const observed = observedVersionedRollbackStateAws(context, previousManifest, candidateRecord);
  let baseline = observed.pending;
  if (flags.direction === 'ROLLBACK_TO_PREVIOUS') {
    const intent = createOrLoadRollbackIntent(context, previousManifest, candidateRecord, observed);
    baseline = {
      tableName: intent.tableName,
      privateItems: intent.privateItems,
      public: intent.pendingBaseline,
    };
    await updateEvidence(context, 'rollback', 'rollbackIntent', publicIntentEvidence(intent));
  }
  const plan = createStage7VersionedRollbackPlan({
    direction: flags.direction,
    previousManifest,
    candidateRecord,
    currentState: observed.state,
    pendingBaseline: baseline.public,
  });
  const planCheckpoint =
    flags.direction === 'ROLLBACK_TO_PREVIOUS' ? 'rollbackPlan' : 'repromotionPlan';
  const transitionCheckpoint =
    flags.direction === 'ROLLBACK_TO_PREVIOUS'
      ? 'rollbackAwsTransition'
      : 'repromotionAwsTransition';
  await updateEvidence(context, 'rollback', planCheckpoint, plan);
  try {
    return await runMutation({
      context,
      plan,
      previousManifest,
      candidateRecord,
      mutation: async () => {
        const invalidation = await applyVersionedRollbackPlanAws(context, plan, {
          delayImplementation,
        });
        const destination =
          flags.direction === 'ROLLBACK_TO_PREVIOUS'
            ? previousManifest.resources
            : candidateRecord.resources;
        const verified = verifyDestinationStateAws(context, destination);
        const pendingIntegrity = await verifyPendingIntegrityAws(context, baseline, {
          delayImplementation,
        });
        if (captureForwardOnlyDataFactsAws(context) !== plan.dataFactsSha256) {
          fail('E7_ROLLBACK_DATA_FACTS_CHANGED');
        }
        const transition = transitionForVersionedRollback({
          context,
          plan,
          previousManifest,
          candidateRecord,
          verified,
          invalidation,
          pendingIntegrity,
        });
        validateStage7VersionedRollbackTransition(transition, {
          plan,
          previousManifest,
          candidateRecord,
        });
        await updateEvidence(context, 'rollback', transitionCheckpoint, transition);
        await writeLocalRollbackJson(
          flags.output,
          `stage7-${flags.direction.toLowerCase()}-aws-transition.json`,
          transition,
        );
        return transition;
      },
    });
  } catch (error) {
    const failureCode =
      error instanceof Stage7Error ? error.code : 'E7_VERSIONED_ROLLBACK_UNEXPECTED_FAILURE';
    await updateEvidence(context, 'rollback', 'lastVersionedRollbackFailure', {
      status: 'FAIL_RESUMABLE',
      direction: flags.direction,
      planSha256: plan.planSha256,
      decision: plan.decision,
      failureCode,
      compensationAttempted: false,
      resumeFromLiveStateRequired: true,
      dataRollbackPerformed: false,
      stacksDeleted: 0,
      containsSensitiveData: false,
    });
    throw error;
  }
};

export const executeVersionedRollback = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
  delayImplementation = delay,
}) => {
  const guardMode = validateReleaseSuccessorGuardFlagContract(flags);
  if (
    flags.scope !== undefined ||
    !['ROLLBACK_TO_PREVIOUS', 'REPROMOTE_CANDIDATE'].includes(flags.direction) ||
    (guardMode !== 'ROLLBACK_CHECK' && flags.direction !== 'REPROMOTE_CANDIDATE')
  ) {
    fail('E7_VERSIONED_ROLLBACK_EXECUTION_FLAGS_INVALID');
  }
  assertReleaseSuccessorGuardSourceAliases({ flags, environmentVariables });
  const intentAuthoritySources = releaseSuccessorIntentAuthoritySources({
    flags,
    environmentVariables,
  });
  const rollbackPremutationAuthoritySources =
    guardMode === 'RECONCILIATION'
      ? releaseSuccessorRollbackPremutationAuthoritySources({ flags })
      : null;
  const rollbackCompletionAuthoritySources =
    guardMode === 'RECONCILIATION'
      ? releaseSuccessorRollbackCompletionAuthoritySources(flags)
      : null;
  const context = loadOperationContext({
    capability: 'rollback',
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const getParametersByPath = createReleaseSuccessorGuardAwsAdapter({
    context,
    mode: guardMode,
    direction: flags.direction,
  });
  return executeVersionedRollbackWithContext({
    context,
    flags,
    delayImplementation,
    runMutation: async ({ mutation }) => {
      let guarded;
      if (guardMode === 'ROLLBACK_CHECK') {
        guarded = await runGuardedVersionedRollbackCheckMutation({
          intentAuthoritySources,
          getParametersByPath,
          mutation,
        });
      } else if (guardMode === 'RECONCILIATION') {
        guarded = await runGuardedReleaseReconciliationMutation({
          intentAuthoritySources,
          rollbackPremutationAuthoritySources,
          rollbackCompletionAuthoritySources,
          getParametersByPath,
          mutation,
        });
      } else {
        guarded = await runGuardedIncompleteReleaseReconciliationMutation({
          direction: flags.direction,
          intentAuthoritySources,
          getParametersByPath,
          mutation,
        });
      }
      return guarded.result;
    },
  });
};

export const executeVersionedRollbackRecovery = async ({
  flags,
  recoveryActor,
  recoveryIntent,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
  delayImplementation = delay,
}) => {
  if (flags?.scope !== undefined || flags?.direction !== 'REPROMOTE_CANDIDATE') {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_DIRECTION_INVALID');
  }
  const context = loadReleaseReconciliationRecoveryOperationContext({
    capability: 'mutation',
    flags,
    recoveryActor,
    recoveryIntent,
    executor,
    environmentVariables,
    now,
  });
  validateRecoveryCallerIdentity(context, 'mutation');
  return executeVersionedRollbackWithContext({
    context,
    flags,
    delayImplementation,
    runMutation: ({ mutation }) => {
      validateRecoveryCallerIdentity(context, 'mutation');
      requireReleaseReconciliationRecoveryStillPreFence(context);
      return mutation();
    },
  });
};

export const decideStage7EmergencyRecoveryFromAwsState = (publicationState) => {
  if (
    !exactKeys(publicationState, ['api', 'web']) ||
    !['DISABLED', 'ENABLED'].includes(publicationState.api) ||
    !['DISABLED', 'ENABLED'].includes(publicationState.web)
  ) {
    fail('E7_EMERGENCY_RECOVERY_PUBLICATION_STATE_INVALID');
  }
  return publicationState.api === 'DISABLED' && publicationState.web === 'DISABLED'
    ? 'NO_ACTION_ACTIVATION_NOT_OBSERVED'
    : 'RECOVER_TO_PREVIOUS';
};

const EMERGENCY_NO_ACTION_FAILURE_STAGES = new Set([
  'INPUT_BINDING',
  'CONTEXT',
  'AUTHORITY_AND_INPUTS',
  'BEFORE_OBSERVATION',
  'MIDDLE_OBSERVATION',
  'AFTER_OBSERVATION',
  'EVIDENCE_WRITE',
]);

const validateEmergencyNoActionCallerBinding = (binding) => {
  if (
    !exactKeys(binding, ['projection', 'rawSha256', 'canonicalSha256', 'bytes']) ||
    !exactKeys(binding.projection, [
      'accountSha256',
      'accountSuffix',
      'roleSha256',
      'sessionArnSha256',
    ]) ||
    !SHA256.test(binding.projection.accountSha256 ?? '') ||
    !/^[0-9]{4}$/u.test(binding.projection.accountSuffix ?? '') ||
    !SHA256.test(binding.projection.roleSha256 ?? '') ||
    !SHA256.test(binding.projection.sessionArnSha256 ?? '')
  ) {
    fail('E7_EMERGENCY_RECOVERY_CALLER_BINDING_INVALID');
  }
  const rawProjection = JSON.stringify(binding.projection);
  if (
    binding.rawSha256 !== sha256(rawProjection) ||
    binding.canonicalSha256 !== objectSha256(binding.projection) ||
    binding.bytes !== Buffer.byteLength(rawProjection)
  ) {
    fail('E7_EMERGENCY_RECOVERY_CALLER_BINDING_INVALID');
  }
  return binding;
};

const validateEmergencyNoActionSourceBindings = (bindings) => {
  if (
    !Array.isArray(bindings) ||
    bindings.length !== EMERGENCY_NO_ACTION_SOURCE_FLAGS.length ||
    bindings.some(
      (binding, index) =>
        !exactKeys(binding, ['label', 'basename', 'rawSha256', 'canonicalSha256', 'bytes']) ||
        binding.label !== EMERGENCY_NO_ACTION_SOURCE_FLAGS[index] ||
        typeof binding.basename !== 'string' ||
        binding.basename === '' ||
        binding.basename !== path.basename(binding.basename) ||
        !SHA256.test(binding.rawSha256 ?? '') ||
        !SHA256.test(binding.canonicalSha256 ?? '') ||
        !Number.isSafeInteger(binding.bytes) ||
        binding.bytes <= 0,
    )
  ) {
    fail('E7_EMERGENCY_RECOVERY_SOURCE_BINDING_INVALID');
  }
  return bindings;
};

const captureCandidateActiveNoActionSnapshot = (context, candidateRecord, sequence) => {
  if (!['BEFORE', 'AFTER'].includes(sequence)) {
    fail('E7_EMERGENCY_RECOVERY_OBSERVATION_SEQUENCE_INVALID');
  }
  const apiPublication = publicationStateForStack(context, 'api');
  const webPublication = publicationStateForStack(context, 'web');
  const candidate = candidateRecord.resources;
  const apiAlias = assertAliasWithoutWeightedRouting(getAlias(context, candidate.api));
  const workerAlias = assertAliasWithoutWeightedRouting(getAlias(context, candidate.worker));
  const objects = latestMutableWebObjects(context, candidate.web.bucketName).map(
    ({ key, versionId, contentSha256, bytes }) => ({ key, versionId, contentSha256, bytes }),
  );
  const publicationProjection = ({ publicationState, stackName, state }, suffix) => ({
    state: publicationState,
    stackName,
    stackStatus: state.stackStatus,
    createdAtUtc: state.creationTime,
    updatedAtUtc: state.lastUpdatedTime,
    terminationProtection: state.terminationProtection,
    candidateSha: state.outputs.CandidateSha,
    releaseId: state.outputs.ReleaseId,
    publicationOutput:
      state.outputs[suffix === 'api' ? 'ApiPublicationStatus' : 'WebPublicationStatus'],
  });
  const state = {
    publication: {
      api: publicationProjection(apiPublication, 'api'),
      web: publicationProjection(webPublication, 'web'),
    },
    aliases: {
      api: {
        functionName: candidate.api.functionName,
        aliasName: candidate.api.aliasName,
        version: apiAlias.FunctionVersion,
        revisionId: apiAlias.RevisionId,
      },
      worker: {
        functionName: candidate.worker.functionName,
        aliasName: candidate.worker.aliasName,
        version: workerAlias.FunctionVersion,
        revisionId: workerAlias.RevisionId,
      },
    },
    web: {
      bucketName: candidate.web.bucketName,
      distributionId: candidate.web.distributionId,
      objects,
    },
  };
  return { sequence, state, stateSha256: objectSha256(state) };
};

const validateCandidateActiveNoActionSnapshot = ({
  snapshot,
  sequence,
  candidateRecord,
  expectedIdentity = null,
}) => {
  const candidate = candidateRecord.resources;
  const expectedObjects = candidate.web.objects.map(({ key, versionId, contentSha256, bytes }) => ({
    key,
    versionId,
    contentSha256,
    bytes,
  }));
  if (
    !exactKeys(snapshot, ['sequence', 'state', 'stateSha256']) ||
    snapshot.sequence !== sequence ||
    snapshot.stateSha256 !== objectSha256(snapshot.state) ||
    !exactKeys(snapshot.state, ['publication', 'aliases', 'web']) ||
    !exactKeys(snapshot.state.publication, ['api', 'web']) ||
    !['api', 'web'].every(
      (suffix) =>
        exactKeys(snapshot.state.publication[suffix], [
          'state',
          'stackName',
          'stackStatus',
          'createdAtUtc',
          'updatedAtUtc',
          'terminationProtection',
          'candidateSha',
          'releaseId',
          'publicationOutput',
        ]) &&
        snapshot.state.publication[suffix].state === 'ENABLED' &&
        STACK_NAME.test(snapshot.state.publication[suffix].stackName ?? '') &&
        snapshot.state.publication[suffix].stackName.endsWith(`-${suffix}`) &&
        /^(?:CREATE|UPDATE)_COMPLETE$/u.test(
          snapshot.state.publication[suffix].stackStatus ?? '',
        ) &&
        canonicalUtc(snapshot.state.publication[suffix].createdAtUtc) &&
        (snapshot.state.publication[suffix].updatedAtUtc === null ||
          canonicalUtc(snapshot.state.publication[suffix].updatedAtUtc)) &&
        snapshot.state.publication[suffix].terminationProtection === true &&
        SHA.test(snapshot.state.publication[suffix].candidateSha ?? '') &&
        RELEASE_ID.test(snapshot.state.publication[suffix].releaseId ?? '') &&
        snapshot.state.publication[suffix].publicationOutput === 'ENABLED' &&
        (expectedIdentity === null ||
          (snapshot.state.publication[suffix].candidateSha === expectedIdentity.candidateSha &&
            snapshot.state.publication[suffix].releaseId === expectedIdentity.releaseId)),
    ) ||
    !exactKeys(snapshot.state.aliases, ['api', 'worker']) ||
    !['api', 'worker'].every((suffix) => {
      const actual = snapshot.state.aliases[suffix];
      const expected = candidate[suffix];
      return (
        exactKeys(actual, ['functionName', 'aliasName', 'version', 'revisionId']) &&
        actual.functionName === expected.functionName &&
        actual.aliasName === expected.aliasName &&
        actual.version === expected.version &&
        typeof actual.revisionId === 'string' &&
        actual.revisionId.length > 0 &&
        actual.revisionId.length <= 256
      );
    }) ||
    !exactKeys(snapshot.state.web, ['bucketName', 'distributionId', 'objects']) ||
    snapshot.state.web.bucketName !== candidate.web.bucketName ||
    snapshot.state.web.distributionId !== candidate.web.distributionId ||
    objectSha256(snapshot.state.web.objects) !== objectSha256(expectedObjects)
  ) {
    fail('E7_EMERGENCY_RECOVERY_CANDIDATE_NOT_ACTIVE');
  }
  return snapshot;
};

const assertCandidateActiveNoActionSandwich = ({
  before,
  after,
  candidateRecord,
  expectedIdentity = null,
}) => {
  validateCandidateActiveNoActionSnapshot({
    snapshot: before,
    sequence: 'BEFORE',
    candidateRecord,
    expectedIdentity,
  });
  validateCandidateActiveNoActionSnapshot({
    snapshot: after,
    sequence: 'AFTER',
    candidateRecord,
    expectedIdentity,
  });
  if (
    before.stateSha256 !== after.stateSha256 ||
    objectSha256(before.state) !== objectSha256(after.state)
  ) {
    fail('E7_EMERGENCY_RECOVERY_OBSERVATION_CHANGED');
  }
};

const emergencyNoActionOutcomeBody = ({
  status,
  failureCode,
  failureStage,
  previousReleaseManifestSha256,
  candidateRecordSha256,
  assemblySha256,
  sourceBindings,
  callerBinding,
  before,
  after,
  recoverySha256,
  completedAtUtc,
}) => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'VERSIONED_ROLLBACK_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME',
  status,
  decision:
    status === 'PASS' ? 'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED' : 'NO_ACTION_VERIFICATION_FAILED',
  failureCode,
  failureStage,
  previousReleaseManifestSha256,
  candidateRecordSha256,
  assemblySha256,
  sourceBindings,
  sourceBindingsSha256: sourceBindings === null ? null : objectSha256(sourceBindings),
  callerBinding,
  observations: { before, after },
  recoverySha256,
  mutationsPerformed: 0,
  dataRollbackPerformed: false,
  stacksDeleted: 0,
  completedAtUtc,
  containsSensitiveData: false,
});

const sealEmergencyNoActionOutcome = (body) => ({
  ...body,
  outcomeSha256: objectSha256(body),
});

export const validateCandidateActiveNoActionOutcome = ({
  value,
  candidateRecord = null,
  expectedIdentity = null,
  expectedSourceBindings = null,
  expectedCaller = null,
  expectedRecoverySha256 = null,
}) => {
  const body = { ...value };
  delete body.outcomeSha256;
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'decision',
      'failureCode',
      'failureStage',
      'previousReleaseManifestSha256',
      'candidateRecordSha256',
      'assemblySha256',
      'sourceBindings',
      'sourceBindingsSha256',
      'callerBinding',
      'observations',
      'recoverySha256',
      'mutationsPerformed',
      'dataRollbackPerformed',
      'stacksDeleted',
      'completedAtUtc',
      'containsSensitiveData',
      'outcomeSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'VERSIONED_ROLLBACK_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME' ||
    !['PASS', 'FAIL'].includes(value.status) ||
    !exactKeys(value.observations, ['before', 'after']) ||
    value.mutationsPerformed !== 0 ||
    value.dataRollbackPerformed !== false ||
    value.stacksDeleted !== 0 ||
    !canonicalUtc(value.completedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.outcomeSha256 !== objectSha256(body)
  ) {
    fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_INVALID');
  }
  if (value.sourceBindings !== null) {
    validateEmergencyNoActionSourceBindings(value.sourceBindings);
    if (value.sourceBindingsSha256 !== objectSha256(value.sourceBindings)) {
      fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_INVALID');
    }
  } else if (value.sourceBindingsSha256 !== null) {
    fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_INVALID');
  }
  if (value.callerBinding !== null) validateEmergencyNoActionCallerBinding(value.callerBinding);
  if (value.status === 'FAIL') {
    if (
      value.decision !== 'NO_ACTION_VERIFICATION_FAILED' ||
      !/^E7_[A-Z0-9_]{3,124}$/u.test(value.failureCode ?? '') ||
      !EMERGENCY_NO_ACTION_FAILURE_STAGES.has(value.failureStage) ||
      value.recoverySha256 !== null ||
      ![
        value.previousReleaseManifestSha256,
        value.candidateRecordSha256,
        value.assemblySha256,
      ].every((entry) => entry === null || SHA256.test(entry ?? '')) ||
      (value.observations.before === null && value.observations.after !== null) ||
      (value.observations.before !== null && candidateRecord === null) ||
      (value.observations.after !== null && candidateRecord === null)
    ) {
      fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_INVALID');
    }
    if (value.observations.before !== null) {
      validateCandidateActiveNoActionSnapshot({
        snapshot: value.observations.before,
        sequence: 'BEFORE',
        candidateRecord,
        expectedIdentity,
      });
    }
    if (value.observations.after !== null) {
      validateCandidateActiveNoActionSnapshot({
        snapshot: value.observations.after,
        sequence: 'AFTER',
        candidateRecord,
        expectedIdentity,
      });
    }
    return value;
  }
  if (
    value.decision !== 'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED' ||
    value.failureCode !== null ||
    value.failureStage !== null ||
    !SHA256.test(value.previousReleaseManifestSha256 ?? '') ||
    !SHA256.test(value.candidateRecordSha256 ?? '') ||
    !SHA256.test(value.assemblySha256 ?? '') ||
    value.sourceBindings === null ||
    value.callerBinding === null ||
    !SHA256.test(value.recoverySha256 ?? '') ||
    candidateRecord === null ||
    (expectedSourceBindings !== null &&
      objectSha256(value.sourceBindings) !== objectSha256(expectedSourceBindings)) ||
    (expectedCaller !== null &&
      objectSha256(value.callerBinding.projection) !== objectSha256(expectedCaller)) ||
    (expectedRecoverySha256 !== null && value.recoverySha256 !== expectedRecoverySha256)
  ) {
    fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_INVALID');
  }
  assertCandidateActiveNoActionSandwich({
    before: value.observations.before,
    after: value.observations.after,
    candidateRecord,
    expectedIdentity,
  });
  return value;
};

export const createCandidateActiveNoActionRecovery = ({
  previousManifest,
  candidateRecord,
  publicationState,
  observedState,
  completedAtUtc,
}) => {
  if (
    !exactKeys(publicationState, ['api', 'web']) ||
    publicationState.api !== 'ENABLED' ||
    publicationState.web !== 'ENABLED'
  ) {
    fail('E7_EMERGENCY_RECOVERY_CANDIDATE_NOT_ACTIVE');
  }
  if (
    typeof completedAtUtc !== 'string' ||
    Number.isNaN(Date.parse(completedAtUtc)) ||
    new Date(completedAtUtc).toISOString() !== completedAtUtc
  ) {
    fail('E7_EMERGENCY_RECOVERY_COMPLETION_TIME_INVALID');
  }
  const expectedObservedState = {
    api: {
      functionName: candidateRecord.resources.api.functionName,
      aliasName: candidateRecord.resources.api.aliasName,
      version: candidateRecord.resources.api.version,
    },
    worker: {
      functionName: candidateRecord.resources.worker.functionName,
      aliasName: candidateRecord.resources.worker.aliasName,
      version: candidateRecord.resources.worker.version,
    },
    web: {
      bucketName: candidateRecord.resources.web.bucketName,
      distributionId: candidateRecord.resources.web.distributionId,
      objects: candidateRecord.resources.web.objects.map(({ key, versionId, contentSha256 }) => ({
        key,
        versionId,
        contentSha256,
      })),
    },
  };
  if (
    objectSha256(observedState?.api) !== objectSha256(expectedObservedState.api) ||
    objectSha256(observedState?.worker) !== objectSha256(expectedObservedState.worker) ||
    objectSha256(observedState?.web) !== objectSha256(expectedObservedState.web)
  ) {
    fail('E7_EMERGENCY_RECOVERY_CANDIDATE_NOT_ACTIVE');
  }
  const verificationPlan = createStage7VersionedRollbackPlan({
    direction: 'REPROMOTE_CANDIDATE',
    purpose: 'EMERGENCY_RECOVERY',
    previousManifest,
    candidateRecord,
    currentState: observedState,
  });
  if (verificationPlan.decision !== 'NOOP_ALREADY_APPLIED') {
    fail('E7_EMERGENCY_RECOVERY_CANDIDATE_NOT_ACTIVE');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'VERSIONED_ROLLBACK_EMERGENCY_RECOVERY',
    status: 'PASS',
    decision: 'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED',
    previousReleaseManifestSha256: previousManifest.manifestSha256,
    candidateRecordSha256: candidateRecord.recordSha256,
    publicationState,
    observedState,
    verificationPlan,
    mutationsPerformed: 0,
    dataRollbackPerformed: false,
    stacksDeleted: 0,
    completedAtUtc,
    containsSensitiveData: false,
  };
  return { ...body, recoverySha256: objectSha256(body) };
};

export const verifyCandidateActiveNoActionOutcome = async ({
  flags,
  environmentVariables = process.env,
}) => {
  const outcome = readLocalRollbackJson(
    flags.outcome,
    'E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_MISSING',
  );
  const previousManifest = validateStage7PreviousReleaseManifest(
    readLocalRollbackJson(flags['previous-manifest'], 'E7_PREVIOUS_RELEASE_MANIFEST_MISSING'),
  );
  const candidateRecord = validateStage7CandidateRollbackRecord(
    readLocalRollbackJson(flags['candidate-record'], 'E7_CANDIDATE_ROLLBACK_RECORD_MISSING'),
    {
      previousManifest,
      approvalSha256: fileSha256(flags.approval),
      planSha256: fileSha256(flags['approved-plan']),
      deploymentEvidenceSha256: fileSha256(flags['deployment-evidence']),
    },
  );
  const recovery = readLocalRollbackJson(
    flags['emergency-recovery'],
    'E7_EMERGENCY_RECOVERY_EVIDENCE_MISSING',
  );
  const expectedRecovery = createCandidateActiveNoActionRecovery({
    previousManifest,
    candidateRecord,
    publicationState: {
      api: outcome?.observations?.before?.state?.publication?.api?.state,
      web: outcome?.observations?.before?.state?.publication?.web?.state,
    },
    observedState: recovery.observedState,
    completedAtUtc: recovery.completedAtUtc,
  });
  if (
    objectSha256(recovery) !== objectSha256(expectedRecovery) ||
    outcome.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    outcome.candidateRecordSha256 !== candidateRecord.recordSha256 ||
    outcome.assemblySha256 !== previousManifest.target.assemblySha256 ||
    outcome.completedAtUtc !== recovery.completedAtUtc
  ) {
    fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_INVALID');
  }
  const configPath = environmentVariables.STAGE7_CONFIG;
  if (typeof configPath !== 'string' || configPath.length === 0) {
    fail('E7_CONFIG_PATH_REQUIRED');
  }
  const configSource = readStrictJsonFile(configPath, {
    scanForbiddenData: false,
    validateConfig: false,
  });
  const config = validateStage7Config(configSource, {
    now: new Date(configSource?.window?.startsAtUtc ?? Number.NaN),
  });
  const githubRunId = environmentVariables.GITHUB_RUN_ID;
  if (!/^[1-9][0-9]{0,19}$/u.test(githubRunId ?? '')) {
    fail('E7_EMERGENCY_RECOVERY_CALLER_BINDING_INVALID');
  }
  const readRoleArn = roleArnFor(config, 'read');
  const readRole = roleResource(readRoleArn, 'E7_EXPECTED_ROLE_INVALID');
  const expectedSessionArn = `arn:aws:sts::${config.aws.accountId}:assumed-role/${readRole.roleName}/e7-emergency-observe-${githubRunId}`;
  const expectedCaller = {
    accountSha256: sha256(config.aws.accountId),
    accountSuffix: config.aws.accountId.slice(-4),
    roleSha256: sha256(readRoleArn),
    sessionArnSha256: sha256(expectedSessionArn),
  };
  const expectedSourceBindings = emergencyNoActionSourceBindings(flags);
  return validateCandidateActiveNoActionOutcome({
    value: outcome,
    candidateRecord,
    expectedIdentity: {
      candidateSha: previousManifest.target.candidateSha,
      releaseId: previousManifest.target.releaseId,
    },
    expectedSourceBindings,
    expectedCaller,
    expectedRecoverySha256: recovery.recoverySha256,
  });
};

export const recoverVersionedRelease = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
  delayImplementation = delay,
}) => {
  const recoverIfActive = flags['recover-if-active'] === true;
  const verifyCandidateActiveNoAction = flags['verify-candidate-active-no-action'] === true;
  if (
    recoverIfActive === verifyCandidateActiveNoAction ||
    flags.scope !== undefined ||
    (verifyCandidateActiveNoAction &&
      (typeof flags.outcome !== 'string' || flags.outcome.length === 0)) ||
    (recoverIfActive && flags.outcome !== undefined)
  ) {
    fail('E7_EMERGENCY_RECOVERY_FLAGS_INVALID');
  }
  if (verifyCandidateActiveNoAction) {
    let failureStage = 'INPUT_BINDING';
    let sourceBindings = null;
    let callerBinding = null;
    let previousManifest = null;
    let candidateRecord = null;
    let assemblySha256 = null;
    let before = null;
    let after = null;
    try {
      sourceBindings = emergencyNoActionSourceBindings(flags);
      validateEmergencyNoActionSourceBindings(sourceBindings);
      failureStage = 'CONTEXT';
      const context = loadOperationContext({
        capability: 'read',
        flags,
        executor,
        environmentVariables,
        now,
        requireAws: true,
      });
      failureStage = 'AUTHORITY_AND_INPUTS';
      const inputs = validateVersionedRollbackExecutionInputs(context, flags, {
        requireActive: false,
        bindCaller: true,
      });
      ({ previousManifest, candidateRecord, callerBinding } = inputs);
      assemblySha256 = inputs.assembly.assemblySha256;
      failureStage = 'BEFORE_OBSERVATION';
      before = captureCandidateActiveNoActionSnapshot(context, candidateRecord, 'BEFORE');
      failureStage = 'MIDDLE_OBSERVATION';
      const observed = observedVersionedRollbackStateAws(
        context,
        previousManifest,
        candidateRecord,
      );
      failureStage = 'AFTER_OBSERVATION';
      after = captureCandidateActiveNoActionSnapshot(context, candidateRecord, 'AFTER');
      assertCandidateActiveNoActionSandwich({
        before,
        after,
        candidateRecord,
        expectedIdentity: {
          candidateSha: previousManifest.target.candidateSha,
          releaseId: previousManifest.target.releaseId,
        },
      });
      const record = createCandidateActiveNoActionRecovery({
        previousManifest,
        candidateRecord,
        publicationState: {
          api: before.state.publication.api.state,
          web: before.state.publication.web.state,
        },
        observedState: observed.state,
        completedAtUtc: utc(context.now),
      });
      failureStage = 'EVIDENCE_WRITE';
      await updateEvidence(context, 'rollback', 'emergencyRecovery', record);
      await writeLocalRollbackJson(flags.output, 'stage7-emergency-recovery.json', record);
      const outcome = sealEmergencyNoActionOutcome(
        emergencyNoActionOutcomeBody({
          status: 'PASS',
          failureCode: null,
          failureStage: null,
          previousReleaseManifestSha256: previousManifest.manifestSha256,
          candidateRecordSha256: candidateRecord.recordSha256,
          assemblySha256,
          sourceBindings,
          callerBinding,
          before,
          after,
          recoverySha256: record.recoverySha256,
          completedAtUtc: utc(context.now),
        }),
      );
      validateCandidateActiveNoActionOutcome({
        value: outcome,
        candidateRecord,
        expectedIdentity: {
          candidateSha: previousManifest.target.candidateSha,
          releaseId: previousManifest.target.releaseId,
        },
        expectedSourceBindings: sourceBindings,
        expectedCaller: callerBinding.projection,
        expectedRecoverySha256: record.recoverySha256,
      });
      await writeLocalRollbackJson(
        flags.outcome,
        'stage7-emergency-recovery-no-action-outcome.json',
        outcome,
      );
      return record;
    } catch (error) {
      const failureCode =
        error instanceof Stage7Error ? error.code : 'E7_EMERGENCY_RECOVERY_UNEXPECTED_FAILURE';
      const failureOutcome = sealEmergencyNoActionOutcome(
        emergencyNoActionOutcomeBody({
          status: 'FAIL',
          failureCode,
          failureStage,
          previousReleaseManifestSha256: previousManifest?.manifestSha256 ?? null,
          candidateRecordSha256: candidateRecord?.recordSha256 ?? null,
          assemblySha256,
          sourceBindings,
          callerBinding,
          before,
          after,
          recoverySha256: null,
          completedAtUtc: utc(now),
        }),
      );
      validateCandidateActiveNoActionOutcome({
        value: failureOutcome,
        candidateRecord,
        expectedIdentity:
          previousManifest === null
            ? null
            : {
                candidateSha: previousManifest.target.candidateSha,
                releaseId: previousManifest.target.releaseId,
              },
      });
      await writeLocalRollbackJson(
        flags.outcome,
        'stage7-emergency-recovery-no-action-outcome.json',
        failureOutcome,
      );
      throw error;
    }
  }
  const context = loadOperationContext({
    capability: 'rollback',
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const { previousManifest, candidateRecord, publicationState } =
    validateVersionedRollbackExecutionInputs(context, flags, { requireActive: false });
  const durableDecision = decideStage7EmergencyRecoveryFromAwsState(publicationState);
  if (durableDecision === 'NO_ACTION_ACTIVATION_NOT_OBSERVED') {
    const body = {
      schemaVersion: 1,
      stage: 7,
      kind: 'VERSIONED_ROLLBACK_EMERGENCY_RECOVERY',
      status: 'PASS',
      decision: 'NO_ACTION_ACTIVATION_NOT_OBSERVED',
      previousReleaseManifestSha256: previousManifest.manifestSha256,
      candidateRecordSha256: candidateRecord.recordSha256,
      mutationsPerformed: 0,
      dataRollbackPerformed: false,
      stacksDeleted: 0,
      completedAtUtc: utc(context.now),
      containsSensitiveData: false,
    };
    const record = { ...body, recoverySha256: objectSha256(body) };
    await updateEvidence(context, 'rollback', 'emergencyRecovery', record);
    await writeLocalRollbackJson(flags.output, 'stage7-emergency-recovery.json', record);
    return record;
  }
  // Publication is repaired before moving aliases. A later CloudFormation
  // parameter update could otherwise reset an intentionally rolled-back alias.
  if (publicationState.api !== 'ENABLED') updatePublicationStack(context, 'api', 'ENABLED');
  if (publicationState.web !== 'ENABLED') updatePublicationStack(context, 'web', 'ENABLED');
  const observed = observedVersionedRollbackStateAws(context, previousManifest, candidateRecord);
  const plan = createStage7VersionedRollbackPlan({
    direction: 'ROLLBACK_TO_PREVIOUS',
    purpose: 'EMERGENCY_RECOVERY',
    previousManifest,
    candidateRecord,
    currentState: observed.state,
  });
  await updateEvidence(context, 'rollback', 'emergencyRecoveryPlan', plan);
  try {
    const invalidation = await applyVersionedRollbackPlanAws(context, plan, {
      delayImplementation,
    });
    const verified = verifyDestinationStateAws(context, previousManifest.resources);
    const pendingIntegrity = await verifyPendingIntegrityAws(context, observed.pending, {
      delayImplementation,
    });
    if (captureForwardOnlyDataFactsAws(context) !== plan.dataFactsSha256) {
      fail('E7_ROLLBACK_DATA_FACTS_CHANGED');
    }
    const body = {
      schemaVersion: 1,
      stage: 7,
      kind: 'VERSIONED_ROLLBACK_EMERGENCY_RECOVERY',
      status: 'PASS',
      decision: 'RECOVERED_TO_PREVIOUS_REQUIRES_READ_SMOKE',
      previousReleaseManifestSha256: previousManifest.manifestSha256,
      candidateRecordSha256: candidateRecord.recordSha256,
      plan,
      aliases: verified.aliases,
      web: { ...verified.web, invalidation },
      pendingIntegrity,
      dataFactsSha256: plan.dataFactsSha256,
      dataRollbackPerformed: false,
      stacksDeleted: 0,
      completedAtUtc: utc(context.now),
      containsSensitiveData: false,
    };
    const record = { ...body, recoverySha256: objectSha256(body) };
    await updateEvidence(context, 'rollback', 'emergencyRecovery', record);
    await writeLocalRollbackJson(flags.output, 'stage7-emergency-recovery.json', record);
    return record;
  } catch (error) {
    const failureCode =
      error instanceof Stage7Error ? error.code : 'E7_EMERGENCY_RECOVERY_UNEXPECTED_FAILURE';
    await updateEvidence(context, 'rollback', 'emergencyRecoveryFailure', {
      status: 'FAIL_RESUMABLE',
      planSha256: plan.planSha256,
      failureCode,
      compensationAttempted: false,
      resumeFromLiveStateRequired: true,
      dataRollbackPerformed: false,
      stacksDeleted: 0,
      containsSensitiveData: false,
    });
    throw error;
  }
};

const assertReleaseMutationReady = (flags) => {
  if (flags['previous-manifest'] === undefined) {
    fail('E7_PREVIOUS_APPROVED_RELEASE_REQUIRED');
  }
  const previousManifest = validateStage7PreviousReleaseManifest(
    readLocalRollbackJson(flags['previous-manifest'], 'E7_PREVIOUS_RELEASE_MANIFEST_MISSING'),
  );
  validatePreviousCompatibilityArtifacts(flags, previousManifest);
  return previousManifest;
};

const PRERELEASE_SAFETY_SOURCE_FLAGS = [
  'app',
  'manifest',
  'plan',
  'raw-diff',
  'approval',
  'aws-auth',
  'safety-readiness',
];

const validatePrereleaseMutationSafety = async ({
  flags,
  environmentVariables,
  now,
  authorityPhase,
  protectedEnvironment = 'assessment-prerelease',
  deploymentPhase,
  livePhase,
}) => {
  assertJournalRoleAuthorityScope(flags.scope, flags);
  if (flags.scope !== 'prerelease') return null;
  if (
    PRERELEASE_SAFETY_SOURCE_FLAGS.some(
      (key) => typeof flags[key] !== 'string' || flags[key].length === 0,
    ) ||
    typeof environmentVariables.STAGE7_CONFIG !== 'string' ||
    typeof environmentVariables.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN !== 'string'
  ) {
    fail('E7_PRERELEASE_SAFETY_INPUT_REQUIRED');
  }
  try {
    const validated = validatePrereleaseSafetyReadinessFromFiles({
      readinessPath: flags['safety-readiness'],
      configPath: environmentVariables.STAGE7_CONFIG,
      manifestPath: flags.manifest,
      assemblyPath: flags.app,
      planPath: flags.plan,
      rawDiffPath: flags['raw-diff'],
      approvalPath: flags.approval,
      awsAuthPath: flags['aws-auth'],
      watchdogRoleArn: environmentVariables.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN,
      environmentVariables,
      now,
      expectedProtectedEnvironment: protectedEnvironment,
    });
    let deployment = null;
    if (deploymentPhase !== undefined) {
      if (
        typeof flags['deployment-evidence'] !== 'string' ||
        flags['deployment-evidence'].length === 0
      ) {
        fail('E7_PRERELEASE_DEPLOYMENT_CHECKPOINT_REQUIRED');
      }
      deployment = readJson(
        flags['deployment-evidence'],
        'E7_PRERELEASE_DEPLOYMENT_CHECKPOINT_REQUIRED',
      );
      validatePrereleaseDeploymentCheckpoint({
        value: deployment,
        config: validated.config,
        freeze: validated.freeze,
        readiness: validated.readiness,
        phase: deploymentPhase,
      });
    }
    let liveSafetyRecheck = null;
    if (livePhase !== undefined) {
      if (
        typeof flags['live-safety-recheck'] !== 'string' ||
        flags['live-safety-recheck'].length === 0
      ) {
        fail('E7_PRERELEASE_LIVE_SAFETY_RECHECK_REQUIRED');
      }
      liveSafetyRecheck = readJson(
        flags['live-safety-recheck'],
        'E7_PRERELEASE_LIVE_SAFETY_RECHECK_REQUIRED',
      );
      validatePrereleaseLiveSafetyRecheck(liveSafetyRecheck, {
        readiness: validated.readiness,
        config: validated.config,
        freeze: validated.freeze,
        phase: livePhase,
        expectedGithubRunId: environmentVariables.GITHUB_RUN_ID,
        expectedGithubRunAttempt: environmentVariables.GITHUB_RUN_ATTEMPT,
        now,
      });
    }
    const watchdogLiveAuthority = await revalidatePrereleaseWatchdogLiveAuthority({
      readiness: validated.readiness,
      freeze: validated.freeze,
      candidateWorkflowSha256: validated.local.watchdog.candidateBlobSha256,
      phase: authorityPhase,
      environmentVariables,
      now,
    });
    return { ...validated, deployment, liveSafetyRecheck, watchdogLiveAuthority };
  } catch (error) {
    if (
      error instanceof PrereleaseSafetyContractError ||
      (typeof error?.code === 'string' && error.code.startsWith('E7_'))
    ) {
      fail(error.code);
    }
    throw error;
  }
};

const validateVersionedMutationTarget = (context, flags) => {
  const previousManifest = assertReleaseMutationReady(flags);
  const freezeManifest = validateFreezeManifest(
    readLocalRollbackJson(flags.manifest, 'E7_FREEZE_MANIFEST_MISSING'),
  );
  return validateStage7PreviousReleaseForTarget(previousManifest, {
    config: context.config,
    freezeManifest,
  });
};

const validateDeployFlags = (context, flags) => {
  if (
    flags.app === undefined ||
    flags.manifest === undefined ||
    flags.plan === undefined ||
    flags.approval === undefined ||
    flags['aws-auth'] === undefined
  ) {
    fail('E7_DEPLOY_INPUT_REQUIRED');
  }
  const releaseMode = releaseModeForFlags(context.scope, flags);
  if (context.scope === 'prerelease') {
    if (flags['synthetic-only'] !== true || flags['non-public'] !== true) {
      fail('E7_PRERELEASE_DEPLOY_FLAGS_REQUIRED');
    }
  } else if (flags['synthetic-only'] || flags['non-public'] || flags.ephemeral) {
    fail('E7_FULL_RELEASE_DEPLOY_FLAG_INVALID');
  }
  return releaseMode;
};

const validateProtectedApproval = (
  context,
  filename,
  planFilename,
  assembly,
  manifestFilename,
  awsAuthFilename,
  previousManifest,
) => {
  const approval = readJson(filename, 'E7_PROTECTED_APPROVAL_MISSING');
  const plan = readJson(planFilename, 'E7_APPROVED_PLAN_MISSING');
  const awsAuth = readJson(awsAuthFilename, 'E7_AWS_AUTH_EVIDENCE_MISSING');
  const freeze = validateFreezeManifest(
    readStrictJsonFile(manifestFilename, { scanForbiddenData: false, validateConfig: false }),
  );
  const expectedScope = context.scope ?? 'full';
  const expectedEnvironment =
    expectedScope === 'prerelease' ? 'assessment-prerelease' : 'assessment-release';
  let iamEffectivePermissions;
  try {
    if (
      awsAuth?.kind !== 'AWS_READ_ONLY_PREFLIGHT' ||
      awsAuth?.status !== 'PASS' ||
      awsAuth?.scope !== expectedScope ||
      awsAuth?.candidateSha !== context.identity.candidateSha ||
      awsAuth?.releaseId !== context.identity.releaseId ||
      awsAuth?.manifestSha256 !== freeze.manifestSha256 ||
      awsAuth?.configSha256 !== objectSha256(context.config) ||
      awsAuth?.mutationsPerformed !== 0 ||
      awsAuth?.containsSensitiveData !== false
    ) {
      fail('E7_AWS_AUTH_EVIDENCE_INVALID');
    }
    iamEffectivePermissions = validateIamEffectivePermissionsEvidence({
      value: awsAuth.iamEffectivePermissions,
      config: context.config,
      scope: expectedScope,
      candidateSha: context.identity.candidateSha,
      releaseId: context.identity.releaseId,
      manifestSha256: freeze.manifestSha256,
      bootstrapAssetInventory:
        awsAuth.iamEffectivePermissions?.bootstrapRoles?.assetInventory?.inventory,
      cleanupWatchdogRoleArn:
        expectedScope === 'prerelease'
          ? context.environmentVariables.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN
          : null,
      baselineRoleArn: null,
      journalRoleArn:
        expectedScope === 'full'
          ? context.environmentVariables.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN
          : null,
      journalPermissionsBoundaryArn:
        expectedScope === 'full'
          ? context.environmentVariables.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN
          : null,
      reconciliationRecoveryRoleArn:
        expectedScope === 'full'
          ? context.environmentVariables.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN
          : null,
      reconciliationRecoveryPermissionsBoundaryArn:
        expectedScope === 'full'
          ? context.environmentVariables
              .STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN
          : null,
    });
  } catch (error) {
    if (error instanceof IamEffectivePermissionsError) {
      fail('E7_IAM_EFFECTIVE_PERMISSIONS_INVALID');
    }
    throw error;
  }
  const keys = [
    'schemaVersion',
    'stage',
    'kind',
    'status',
    'scope',
    'candidateSha',
    'releaseId',
    'releaseTag',
    'configSha256',
    'cloudAssemblySha256',
    'freezeManifestSha256',
    'previousReleaseManifestSha256',
    'approvedPlanSha256',
    'approvedDiffSha256',
    'iamEffectivePermissionsBindingSha256',
    'iamEffectivePermissionsEvidenceSha256',
    'journalRoleEffectivePermissionsRawSha256',
    'journalRoleEffectivePermissionsSha256',
    ...RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS,
    'approvedAtUtc',
    'statefulReplacements',
    'destructiveChanges',
    'iamBroadeningDetected',
    'iamBroadeningReviewed',
    'humanReviewConfirmed',
    'explicitDispatchConfirmation',
    'protectedEnvironment',
    'protectedEnvironmentName',
    'nonPublic',
    'accountSha256',
    'accountSuffix',
    'region',
    'stacks',
    'budget',
    'approvalOwnerAlias',
    'reviewerAlias',
    'authorizedWindow',
    'externalRequests',
    'mutationsPerformed',
    'containsSensitiveData',
  ];
  if (
    !exactKeys(approval, keys) ||
    approval.schemaVersion !== 1 ||
    approval.stage !== 7 ||
    approval.kind !== 'PROTECTED_RELEASE_APPROVAL' ||
    approval.status !== 'PASS' ||
    approval.scope !== expectedScope ||
    approval.candidateSha !== context.identity.candidateSha ||
    approval.releaseId !== context.identity.releaseId ||
    approval.releaseTag !== freeze.releaseTag ||
    approval.configSha256 !== objectSha256(context.config) ||
    approval.cloudAssemblySha256 !== assembly.assemblySha256 ||
    approval.freezeManifestSha256 !== assembly.freezeManifestSha256 ||
    approval.previousReleaseManifestSha256 !== (previousManifest?.manifestSha256 ?? null) ||
    approval.approvedPlanSha256 !== fileSha256(planFilename) ||
    approval.approvedDiffSha256 !== plan.rawDiffArtifactSha256 ||
    approval.iamEffectivePermissionsBindingSha256 !== iamEffectivePermissions.bindingSha256 ||
    approval.iamEffectivePermissionsEvidenceSha256 !== fileSha256(awsAuthFilename) ||
    (expectedScope === 'full'
      ? approval.journalRoleEffectivePermissionsRawSha256 !==
          awsAuth.journalRoleEffectivePermissionsRawSha256 ||
        approval.journalRoleEffectivePermissionsSha256 !==
          awsAuth.journalRoleEffectivePermissionsSha256 ||
        !SHA256.test(approval.journalRoleEffectivePermissionsRawSha256 ?? '') ||
        !SHA256.test(approval.journalRoleEffectivePermissionsSha256 ?? '')
      : approval.journalRoleEffectivePermissionsRawSha256 !== null ||
        approval.journalRoleEffectivePermissionsSha256 !== null) ||
    (expectedScope === 'full'
      ? approval.reconciliationRecoveryRoleArn !== awsAuth.reconciliationRecoveryRoleArn ||
        approval.reconciliationRecoveryPermissionsBoundaryArn !==
          awsAuth.reconciliationRecoveryPermissionsBoundaryArn ||
        !/^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/u.test(
          approval.reconciliationRecoveryRoleArn ?? '',
        ) ||
        !/^arn:aws:iam::[0-9]{12}:policy\/[A-Za-z0-9+=,.@_/-]{1,512}$/u.test(
          approval.reconciliationRecoveryPermissionsBoundaryArn ?? '',
        ) ||
        RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.slice(2).some(
          (field) => approval[field] !== awsAuth[field] || !SHA256.test(approval[field] ?? ''),
        )
      : RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.some(
          (field) => approval[field] !== null,
        )) ||
    !canonicalUtc(approval.approvedAtUtc) ||
    Date.parse(approval.approvedAtUtc) < Date.parse(context.config.window.startsAtUtc) ||
    Date.parse(approval.approvedAtUtc) > context.now.getTime() ||
    Date.parse(approval.approvedAtUtc) > Date.parse(context.config.window.endsAtUtc) ||
    approval.statefulReplacements !== 0 ||
    approval.destructiveChanges !== 0 ||
    approval.iamBroadeningDetected !== plan.iamBroadeningDetected ||
    approval.iamBroadeningReviewed !== true ||
    approval.humanReviewConfirmed !== true ||
    approval.explicitDispatchConfirmation !== true ||
    approval.protectedEnvironment !== true ||
    approval.protectedEnvironmentName !== expectedEnvironment ||
    approval.nonPublic !== (expectedScope === 'prerelease') ||
    approval.accountSha256 !== sha256(context.config.aws.accountId) ||
    approval.accountSuffix !== context.config.aws.accountId.slice(-4) ||
    approval.region !== context.config.aws.region ||
    approval.stacks?.join('\0') !== context.config.authorization.stacks.join('\0') ||
    jsonSha256(approval.budget) !==
      jsonSha256({
        maxUsd: context.config.budget.maxUsd,
        warningUsd: context.config.budget.warningUsd,
        alertDestinationSha256: context.config.budget.alertDestinationSha256,
      }) ||
    approval.approvalOwnerAlias !== context.config.authorization.ownerAlias ||
    !/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u.test(approval.reviewerAlias ?? '') ||
    jsonSha256(approval.authorizedWindow) !== jsonSha256(context.config.window) ||
    approval.externalRequests !== 0 ||
    approval.mutationsPerformed !== 0 ||
    approval.containsSensitiveData !== false
  ) {
    fail('E7_PROTECTED_APPROVAL_INVALID');
  }
  return { approvalSha256: fileSha256(filename) };
};

const validateApprovedPlan = (
  context,
  filename,
  assembly,
  suffix,
  hostedZone,
  certificates,
  currentPrereleaseAccess,
  currentRuntimeSecret,
  previousManifest,
) => {
  const source = readJson(filename, 'E7_APPROVED_PLAN_MISSING');
  const diff = source?.checkpoints?.diff;
  const expectedStack = stackFor(context, suffix);
  const expectedStackSet = context.stacks.toSorted().join('\0');
  const planStackSet = Array.isArray(diff?.stacks) ? diff.stacks.toSorted().join('\0') : '';
  const stateKeys = object(diff?.preDeploymentState)
    ? Object.keys(diff.preDeploymentState).toSorted().join('\0')
    : '';
  const stackDiffs = Array.isArray(diff?.stackDiffs) ? diff.stackDiffs : [];
  const plannedStackDiff = stackDiffs.find(({ stackName }) => stackName === expectedStack);
  if (
    source?.schemaVersion !== 1 ||
    source?.stage !== 7 ||
    source?.kind !== 'RELEASE_DIFF_REVIEW' ||
    source?.status !== 'READY_FOR_PROTECTED_REVIEW' ||
    source?.scope !== (context.scope ?? 'full') ||
    source?.environment !== context.config.environment ||
    source?.authorizationId !== context.config.authorization.id ||
    source?.authorizationScope !== context.config.authorization.scope ||
    source?.configSha256 !== objectSha256(context.config) ||
    source?.releaseId !== context.identity.releaseId ||
    source?.candidateSha !== context.identity.candidateSha ||
    source?.previousReleaseManifestSha256 !== (previousManifest?.manifestSha256 ?? null) ||
    source?.containsSensitiveData !== false ||
    diff?.decision !== 'READY_FOR_PROTECTED_REVIEW' ||
    diff?.releaseMode !== (context.scope === 'prerelease' ? 'INITIAL' : 'VERSIONED_UPDATE') ||
    diff?.previousReleaseManifestSha256 !== (previousManifest?.manifestSha256 ?? null) ||
    diff?.assemblySha256 !== assembly.assemblySha256 ||
    diff?.freezeManifestSha256 !== assembly.freezeManifestSha256 ||
    !SHA256.test(diff?.diffSha256 ?? '') ||
    !Number.isSafeInteger(diff?.diffBytes) ||
    diff.diffBytes < 0 ||
    planStackSet !== expectedStackSet ||
    stateKeys !== expectedStackSet ||
    Object.values(diff.preDeploymentState).some((digest) => !SHA256.test(digest ?? '')) ||
    !SHA256.test(diff?.rawDiffArtifactSha256 ?? '') ||
    source?.rawDiffArtifactSha256 !== diff.rawDiffArtifactSha256 ||
    stackDiffs.length !== context.stacks.length ||
    new Set(stackDiffs.map(({ stackName }) => stackName)).size !== context.stacks.length ||
    stackDiffs.some(
      ({ bytes, risks, sha256: digest, stackName }) =>
        !context.stacks.includes(stackName) ||
        !Number.isSafeInteger(bytes) ||
        bytes < 0 ||
        !SHA256.test(digest ?? '') ||
        !object(risks),
    ) ||
    plannedStackDiff === undefined ||
    diff?.exactChangeSetUsed !== false ||
    diff?.diffMethod !== 'TEMPLATE' ||
    diff?.exactDiffRecomputedAtDeploy !== true ||
    diff?.hotswapUsed !== false ||
    diff?.containsRawDiff !== true ||
    jsonSha256(diff?.hostedZone ?? null) !== jsonSha256(hostedZone) ||
    jsonSha256(diff?.certificates ?? []) !== jsonSha256(certificates) ||
    !validatePrereleaseAccessEvidence(context, diff?.prereleaseAccess) ||
    jsonSha256(diff?.prereleaseAccess ?? null) !== jsonSha256(currentPrereleaseAccess) ||
    !validateRuntimeSecretReferenceEvidence(context, diff?.runtimeSecret) ||
    jsonSha256(diff?.runtimeSecret ?? null) !== jsonSha256(currentRuntimeSecret) ||
    diff?.risks?.statefulReplacement !== false ||
    diff?.risks?.statefulDeletion !== false ||
    diff?.risks?.rollbackControlReplacement !== false
  ) {
    fail('E7_APPROVED_PLAN_INVALID');
  }
  const current = describeStack(context, expectedStack, { allowMissing: true });
  if (current.exists && current.terminationProtection !== (context.scope !== 'prerelease')) {
    fail('E7_STACK_TERMINATION_PROTECTION_INVALID');
  }
  if (context.scope !== 'prerelease') {
    if (
      !current.exists ||
      current.outputs.CandidateSha !== previousManifest.previous.candidateSha ||
      current.outputs.ReleaseId !== previousManifest.previous.releaseId
    ) {
      fail('E7_VERSIONED_UPDATE_BASELINE_STACK_INVALID');
    }
  } else if (
    current.exists &&
    (current.outputs.CandidateSha !== context.identity.candidateSha ||
      current.outputs.ReleaseId !== context.identity.releaseId)
  ) {
    fail('E7_INITIAL_RELEASE_EXISTING_STACK_INVALID');
  }
  const currentFingerprint = stackStateFingerprint(expectedStack, current);
  if (currentFingerprint !== diff.preDeploymentState[expectedStack]) {
    fail('E7_APPROVED_PLAN_STACK_DRIFT');
  }
  const recomputed = stackDiff(context, assembly, expectedStack);
  if (
    recomputed.sha256 !== plannedStackDiff.sha256 ||
    recomputed.bytes !== plannedStackDiff.bytes ||
    jsonSha256(recomputed.risks) !== jsonSha256(plannedStackDiff.risks)
  ) {
    fail('E7_APPROVED_DIFF_RECOMPUTATION_MISMATCH');
  }
  return { planSha256: fileSha256(filename), preDeploymentStateSha256: currentFingerprint };
};

const deployContext = async ({
  flags,
  executor,
  environmentVariables,
  now,
  suffix,
  capability = 'deploy',
}) => {
  const prereleaseSafety = await validatePrereleaseMutationSafety({
    flags,
    environmentVariables,
    now,
    authorityPhase: `deploy-${suffix}`,
  });
  const context = loadOperationContext({
    capability,
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const releaseMode = validateDeployFlags(context, flags);
  const previousManifest =
    releaseMode === 'VERSIONED_UPDATE' ? validateVersionedMutationTarget(context, flags) : null;
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  const protectedApproval = validateProtectedApproval(
    context,
    flags.approval,
    flags.plan,
    assembly,
    flags.manifest,
    flags['aws-auth'],
    previousManifest,
  );
  const identity = revalidateAwsIdentity(context);
  if (previousManifest !== null) verifyPreviousVersionedResourcesAws(context, previousManifest);
  const runtimeSecret = validateRuntimeSecretReferenceAws(context);
  const prereleaseAccess = validatePrereleaseAccessAws(context);
  const hostedZone = validateHostedZoneAws(context);
  const certificates = validateCertificatesAws(context);
  const approvedPlan = validateApprovedPlan(
    context,
    flags.plan,
    assembly,
    suffix,
    hostedZone,
    certificates,
    prereleaseAccess,
    runtimeSecret,
    previousManifest,
  );
  return {
    approvedPlan: { ...approvedPlan, ...protectedApproval },
    assembly,
    context: { ...context, prereleaseSafety },
    identity,
    previousManifest,
    prereleaseSafety,
    releaseMode,
  };
};

const deploymentCheckpoint = (context, identity, assembly, stackName, outputs, extra = {}) => {
  const sanitizedOutputs = sanitizeStackOutputs(outputs, context.config.aws.accountId);
  return {
    decision: 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION',
    releaseMode: context.scope === 'prerelease' ? 'INITIAL' : 'VERSIONED_UPDATE',
    previousReleaseManifestSha256: extra.previousReleaseManifestSha256 ?? null,
    identity,
    stackName,
    stackSuffix: stackSuffix(stackName),
    assemblySha256: assembly.assemblySha256,
    freezeManifestSha256: assembly.freezeManifestSha256,
    outputs: sanitizedOutputs,
    outputsSha256: jsonSha256(sanitizedOutputs),
    deploymentMethod: 'CLOUDFORMATION_CHANGE_SET',
    requireApprovalMode: 'PROTECTED_WORKFLOW_PREAPPROVED',
    hotswapUsed: false,
    ...(context.scope === 'prerelease'
      ? {
          safetyReadinessSha256: context.prereleaseSafety.readiness.readinessSha256,
          ...watchdogLiveAuthorityCheckpoint(context.prereleaseSafety),
        }
      : {}),
    ...extra,
  };
};

const deployReleaseMode = (flags) => {
  return releaseModeForFlags(flags.scope, flags);
};

const watchdogLiveAuthorityCheckpoint = (prereleaseSafety) => {
  const authority = prereleaseSafety.watchdogLiveAuthority;
  return {
    watchdogLiveAuthoritySha256: authority.watchdogLiveAuthoritySha256,
    watchdogDefaultBranchHeadSha256: authority.defaultBranchHeadSha256,
    watchdogApiRequests: authority.apiRequests,
    watchdogVerifiedAtUtc: authority.verifiedAtUtc,
    watchdogVerificationPhase: authority.phase,
  };
};

export const deployData = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const { approvedPlan, assembly, context, identity, previousManifest, releaseMode } =
    await deployContext({
      flags,
      executor,
      environmentVariables,
      now,
      suffix: 'data',
    });
  assertDeployOrder(context, 'data');
  const deployed = deployStack(context, assembly, 'data', {
    preDeploymentStateSha256: approvedPlan.preDeploymentStateSha256,
  });
  if (
    deployed.outputs.CandidateSha !== context.identity.candidateSha ||
    deployed.outputs.ReleaseId !== context.identity.releaseId
  ) {
    fail('E7_DEPLOYED_STACK_IDENTITY_MISMATCH');
  }
  const checkpoint = deploymentCheckpoint(
    context,
    identity,
    assembly,
    deployed.stackName,
    deployed.outputs,
    {
      approvedPlan,
      previousReleaseManifestSha256: previousManifest?.manifestSha256 ?? null,
      releaseMode,
    },
  );
  await updateEvidence(context, 'data', 'data', checkpoint);
  return checkpoint;
};

export const deployApi = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const { approvedPlan, assembly, context, identity, previousManifest, releaseMode } =
    await deployContext({
      flags,
      executor,
      environmentVariables,
      now,
      suffix: 'api',
    });
  assertDeployOrder(context, 'api');
  const stackName = stackFor(context, 'api');
  let before = describeStack(context, stackName, { allowMissing: true });
  deployReleaseMode(flags);
  const previousPublication =
    releaseMode === 'VERSIONED_UPDATE' ? previousPublicationExpectation(previousManifest) : null;
  if (releaseMode === 'VERSIONED_UPDATE') {
    if (
      !before.exists ||
      before.outputs.CandidateSha !== previousManifest.previous.candidateSha ||
      before.outputs.ReleaseId !== previousManifest.previous.releaseId ||
      before.parameters.PublicationState !== previousPublication.publicationState ||
      before.outputs.ApiPublicationStatus !== previousPublication.publicationState
    ) {
      fail('E7_VERSIONED_UPDATE_BASELINE_STACK_INVALID');
    }
  } else if (
    before.exists &&
    (before.outputs.CandidateSha !== context.identity.candidateSha ||
      before.outputs.ReleaseId !== context.identity.releaseId)
  ) {
    fail('E7_INITIAL_RELEASE_EXISTING_STACK_INVALID');
  }
  let previousSchedulerState = null;
  if (before.exists) {
    validateScheduleTarget(context, before.outputs);
    previousSchedulerState = getSchedule(context).State;
    if (
      previousSchedulerState !==
      (releaseMode === 'VERSIONED_UPDATE' ? previousPublication.schedulerState : 'DISABLED')
    ) {
      fail('E7_SCHEDULER_PREMATURE_ACTIVATION_DETECTED');
    }
  }
  const runtimeSecretReferenceSha256 = validateRuntimeSecretReferenceAws(context).bindingSha256;
  if (releaseMode === 'VERSIONED_UPDATE') {
    before = describeStack(context, stackName);
    verifyApiPublicationPostureAws(context, {
      expectedFingerprint: approvedPlan.preDeploymentStateSha256,
      expectedIdentity: previousManifest.previous,
      expectedPublication: previousPublication,
      expectedResources: previousManifest.resources,
      state: before,
    });
    verifyWebPublicationPostureAws(context, {
      expectedIdentity: previousManifest.previous,
      expectedPublication: previousPublication,
      expectedResources: previousManifest.resources,
      state: describeStack(context, stackFor(context, 'web')),
    });
  }
  const deployed = deployStack(context, assembly, 'api', {
    preDeploymentStateSha256: approvedPlan.preDeploymentStateSha256,
  });
  const deployedVersions = apiVersionsFromOutputs(
    context,
    deployed.outputs,
    'E7_DEPLOYED_API_OUTPUT_INVALID',
  );
  if (
    deployed.outputs.SchedulerStatus !== 'DISABLED' ||
    deployed.outputs.ApiPublicationStatus !== 'DISABLED'
  ) {
    fail('E7_SCHEDULER_PREMATURE_ACTIVATION_DETECTED');
  }
  if (getSchedule(context).State !== 'DISABLED') {
    fail('E7_SCHEDULER_PREMATURE_ACTIVATION_DETECTED');
  }
  const publication = captureApiPublication(context, deployed.outputs);
  const templateSha256 = assemblyTemplateSha256(assembly, stackName);
  validateOriginalStackTemplate(context, stackName, templateSha256);
  const rollbackBody = {
    createdAtUtc: utc(now),
    releaseMode,
    previousManifest: previousManifest?.manifestSha256 ?? null,
    previousSchedulerState,
    previous:
      previousManifest === null
        ? null
        : {
            api: previousManifest.resources.api,
            worker: previousManifest.resources.worker,
          },
    deployed: deployedVersions,
    publication,
    templateSha256,
    rollbackAvailable: previousManifest !== null,
    initialDisableAvailable: previousManifest === null,
  };
  const rollbackRecord = writeRecord(context, 'rollback-api', rollbackBody);
  const checkpoint = deploymentCheckpoint(
    context,
    identity,
    assembly,
    deployed.stackName,
    deployed.outputs,
    {
      approvedPlan,
      previousReleaseManifestSha256: previousManifest?.manifestSha256 ?? null,
      releaseMode,
      rollbackRecord,
      runtimeSecretReferenceSha256,
    },
  );
  await updateEvidence(context, 'api', 'api', checkpoint);
  return checkpoint;
};

const alertEmail = (context) => {
  const value = context.environmentVariables.STAGE7_ALERT_EMAIL;
  if (
    typeof value !== 'string' ||
    value.length > 254 ||
    !/^[^\s@]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$/u.test(value) ||
    value.includes('..')
  ) {
    fail('E7_ALERT_EMAIL_INVALID');
  }
  if (!SHA256.test(context.config.budget.alertDestinationSha256 ?? '')) {
    fail('E7_ALERT_DESTINATION_DIGEST_INVALID');
  }
  const digest = sha256(value.trim().toLowerCase());
  if (digest !== context.config.budget.alertDestinationSha256) {
    fail('E7_ALERT_DESTINATION_MISMATCH');
  }
  return { digest, value: value.trim() };
};

const validateCostAllocationTag = (context) => {
  const response = awsJson(
    context,
    ['ce', 'list-cost-allocation-tags', '--tag-keys', 'Project', '--type', 'UserDefined'],
    'E7_COST_ALLOCATION_TAG_READ_FAILED',
  );
  const tags = response?.CostAllocationTags;
  if (
    !Array.isArray(tags) ||
    tags.length !== 1 ||
    response?.NextPageToken !== undefined ||
    tags[0]?.TagKey !== 'Project' ||
    tags[0]?.Type !== 'UserDefined' ||
    tags[0]?.Status !== 'Active'
  ) {
    fail('E7_COST_ALLOCATION_TAG_NOT_ACTIVE');
  }
  return {
    status: 'ACTIVE',
    tagKeySha256: sha256(tags[0].TagKey),
    contractSha256: jsonSha256({
      key: tags[0].TagKey,
      status: tags[0].Status,
      type: tags[0].Type,
    }),
  };
};

export const deployObservability = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const { approvedPlan, assembly, context, identity, previousManifest, releaseMode } =
    await deployContext({
      flags,
      executor,
      environmentVariables,
      now,
      suffix: 'observability',
    });
  assertDeployOrder(context, 'observability');
  const costAllocationTag = validateCostAllocationTag(context);
  const destination = alertEmail(context);
  const deployed = deployStack(context, assembly, 'observability', {
    parameters: [`AlertEmail=${destination.value}`],
    preDeploymentStateSha256: approvedPlan.preDeploymentStateSha256,
  });
  if (deployed.outputs.BudgetContract !== budgetContract(context.config)) {
    fail('E7_DEPLOYED_BUDGET_MISMATCH');
  }
  const rollbackResilience = rollbackResilienceDeploymentBinding({
    context,
    assembly,
    deployed,
  });
  const checkpoint = deploymentCheckpoint(
    context,
    identity,
    assembly,
    deployed.stackName,
    deployed.outputs,
    {
      alertDestinationSha256: destination.digest,
      approvedPlan,
      costAllocationTag,
      previousReleaseManifestSha256: previousManifest?.manifestSha256 ?? null,
      releaseMode,
      rollbackResilience,
    },
  );
  await updateEvidence(context, 'observability', 'observability', checkpoint);
  return checkpoint;
};

const observabilityDeploymentEvidence = (context, filename) => {
  const source = readJson(filename, 'E7_OBSERVABILITY_RECORD_MISSING');
  const checkpoint = source?.checkpoints?.observability;
  if (
    source?.schemaVersion !== 1 ||
    source?.stage !== 7 ||
    source?.environment !== context.config.environment ||
    source?.authorizationId !== context.config.authorization.id ||
    source?.authorizationScope !== context.config.authorization.scope ||
    source?.configSha256 !== objectSha256(context.config) ||
    source?.releaseId !== context.identity.releaseId ||
    source?.candidateSha !== context.identity.candidateSha ||
    source?.containsSensitiveData !== false ||
    checkpoint?.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    checkpoint?.releaseMode !== (context.scope === 'prerelease' ? 'INITIAL' : 'VERSIONED_UPDATE') ||
    checkpoint?.stackName !== stackFor(context, 'observability') ||
    checkpoint?.alertDestinationSha256 !== context.config.budget.alertDestinationSha256 ||
    checkpoint?.outputs?.BudgetContract !== budgetContract(context.config) ||
    checkpoint?.outputs?.CandidateSha !== context.identity.candidateSha ||
    checkpoint?.outputs?.ReleaseId !== context.identity.releaseId ||
    checkpoint?.costAllocationTag?.status !== 'ACTIVE' ||
    checkpoint?.rollbackResilience?.stackName !== stackFor(context, 'observability') ||
    !SHA256.test(checkpoint?.rollbackResilience?.templateSha256 ?? '') ||
    checkpoint?.rollbackResilience?.cloudFormationExecutionRoleArn !==
      cloudFormationExecutionRoleArn(context.config) ||
    checkpoint?.rollbackResilience?.rollbackRehearsalAlarm?.alarmName !==
      `checkout-${context.config.environment}-rollback-rehearsal` ||
    checkpoint?.rollbackResilience?.rollbackRehearsalAlarm?.alarmArn !==
      `arn:aws:cloudwatch:${context.config.aws.region}:${context.config.aws.accountId}:alarm:checkout-${context.config.environment}-rollback-rehearsal`
  ) {
    fail('E7_OBSERVABILITY_RECORD_INVALID');
  }
  return source;
};

const validateObservabilityReadinessEvidence = (context, filename) => {
  const source = observabilityDeploymentEvidence(context, filename);
  const readiness = source?.checkpoints?.observabilityReadiness;
  if (
    readiness?.decision !== 'PASS' ||
    readiness?.status !== 'CONFIRMED' ||
    readiness?.protocol !== 'email' ||
    readiness?.alertDestinationSha256 !== context.config.budget.alertDestinationSha256 ||
    !SHA256.test(readiness?.alertTopicSha256 ?? '') ||
    !SHA256.test(readiness?.subscriptionArnSha256 ?? '') ||
    readiness?.rawDestinationCaptured !== false
  ) {
    fail('E7_OBSERVABILITY_READINESS_REQUIRED');
  }
  return {
    evidenceSha256: jsonSha256(source),
    alertDestinationSha256: readiness.alertDestinationSha256,
    alertTopicSha256: readiness.alertTopicSha256,
    status: 'CONFIRMED',
  };
};

const hydrateEvidenceTarget = async (context, kind, source) => {
  const target = evidenceTarget(context, kind);
  const sourceCheckpoints = source?.checkpoints;
  if (
    source?.schemaVersion !== 1 ||
    source?.stage !== 7 ||
    source?.environment !== context.config.environment ||
    source?.releaseId !== context.identity.releaseId ||
    source?.candidateSha !== context.identity.candidateSha ||
    source?.configSha256 !== objectSha256(context.config) ||
    source?.containsSensitiveData !== false ||
    !object(sourceCheckpoints)
  ) {
    fail('E7_EVIDENCE_HYDRATION_SOURCE_INVALID');
  }
  if (!existsSync(target)) {
    await writeSanitizedJsonAtomic(target, path.basename(target), source);
  } else {
    const current = readJson(target, 'E7_EVIDENCE_HYDRATION_TARGET_INVALID');
    if (
      current?.schemaVersion !== source.schemaVersion ||
      current?.stage !== source.stage ||
      current?.environment !== source.environment ||
      current?.releaseId !== source.releaseId ||
      current?.candidateSha !== source.candidateSha ||
      current?.configSha256 !== source.configSha256 ||
      current?.containsSensitiveData !== false ||
      !object(current.checkpoints) ||
      Object.entries(sourceCheckpoints).some(
        ([checkpoint, value]) =>
          !Object.hasOwn(current.checkpoints, checkpoint) ||
          objectSha256(current.checkpoints[checkpoint]) !== objectSha256(value),
      )
    ) {
      fail('E7_EVIDENCE_HYDRATION_MISMATCH');
    }
  }
  return Object.fromEntries(
    Object.entries(sourceCheckpoints).map(([checkpoint, value]) => [
      checkpoint,
      objectSha256(value),
    ]),
  );
};

const releaseApiOriginFromOutputs = (context, outputs, code) => {
  if (
    outputs?.CandidateSha !== context.identity.candidateSha ||
    outputs?.ReleaseId !== context.identity.releaseId
  ) {
    fail(code);
  }
  try {
    return validatePrereleaseApiOrigin({ origin: outputs.ApiOriginUrl, config: context.config });
  } catch {
    fail(code);
  }
};

const validateDeployedWebOutputs = (context, outputs, code) => {
  if (context.config.domain.mode !== 'CUSTOM_AUTHORIZED') fail(code);
  const applicationUrl = `https://${context.config.domain.hostname}`;
  if (
    outputs?.CandidateSha !== context.identity.candidateSha ||
    outputs?.ReleaseId !== context.identity.releaseId ||
    outputs?.ApplicationUrl !== applicationUrl ||
    outputs?.ApiUrl !== `${applicationUrl}/api` ||
    outputs?.ApiDocsUrl !== `${applicationUrl}/api/docs` ||
    outputs?.HealthUrl !== `${applicationUrl}/api/health/ready` ||
    outputs?.PublicOriginParameterName !==
      `/checkout-${context.config.environment}/public-origin` ||
    !BUCKET_NAME.test(outputs?.WebBucketName ?? '') ||
    typeof outputs?.DistributionId !== 'string' ||
    outputs.DistributionId === ''
  ) {
    fail(code);
  }
  return applicationUrl;
};

const validateActivationLiveBindings = (
  context,
  { apiOutputs, webOutputs, apiRecord, webRecord },
) => {
  const deployedVersions = apiVersionsFromOutputs(
    context,
    apiOutputs,
    'E7_ACTIVATION_LIVE_BINDING_INVALID',
  );
  const apiOrigin = releaseApiOriginFromOutputs(
    context,
    apiOutputs,
    'E7_ACTIVATION_LIVE_BINDING_INVALID',
  );
  const publicOriginValue = validateDeployedWebOutputs(
    context,
    webOutputs,
    'E7_ACTIVATION_LIVE_BINDING_INVALID',
  );
  const expectedFunctionNames = {
    api: `checkout-${context.config.environment}-api`,
    worker: `checkout-${context.config.environment}-worker`,
  };
  if (
    JSON.stringify(deployedVersions) !== JSON.stringify(apiRecord?.deployed) ||
    deployedVersions.api.functionName !== expectedFunctionNames.api ||
    deployedVersions.worker.functionName !== expectedFunctionNames.worker ||
    deployedVersions.api.aliasName !== 'live' ||
    deployedVersions.worker.aliasName !== 'live' ||
    apiOutputs.HttpApiId !== apiRecord?.publication?.apiId ||
    apiOutputs.ApiCustomDomainName !== context.config.domain.apiHostname ||
    sha256(apiOrigin) !== webRecord?.apiOriginSha256 ||
    webOutputs.WebBucketName !== webRecord?.bucketName ||
    webOutputs.DistributionId !== webRecord?.distributionId ||
    webOutputs.DistributionId !== webRecord?.publication?.distributionId ||
    sha256(publicOriginValue) !== webRecord?.publicOriginSha256
  ) {
    fail('E7_ACTIVATION_LIVE_BINDING_INVALID');
  }
  return { apiOriginSha256: sha256(apiOrigin), publicOriginSha256: sha256(publicOriginValue) };
};

const assertHydratedCheckpointsPreserved = (context, kind, expected) => {
  const hydrated = readJson(evidenceTarget(context, kind), 'E7_EVIDENCE_HYDRATION_TARGET_INVALID');
  if (
    Object.entries(expected).some(
      ([checkpoint, digest]) =>
        !Object.hasOwn(hydrated?.checkpoints ?? {}, checkpoint) ||
        objectSha256(hydrated.checkpoints[checkpoint]) !== digest,
    )
  ) {
    fail('E7_EVIDENCE_HYDRATION_MUTATED_SOURCE');
  }
};

export const verifyObservability = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const context = loadOperationContext({
    capability: 'read',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const source = observabilityDeploymentEvidence(context, flags.record);
  const identity = revalidateAwsIdentity(context);
  const state = describeStack(context, stackFor(context, 'observability'));
  const topicArn = state.outputs.AlertTopicArn;
  const expectedTopicArn = `arn:aws:sns:${context.config.aws.region}:${context.config.aws.accountId}:checkout-${context.config.environment}-alerts`;
  if (
    !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus) ||
    state.outputs.CandidateSha !== context.identity.candidateSha ||
    state.outputs.ReleaseId !== context.identity.releaseId ||
    state.outputs.BudgetContract !== budgetContract(context.config) ||
    topicArn !== expectedTopicArn
  ) {
    fail('E7_OBSERVABILITY_STACK_NOT_READY');
  }
  const response = awsJson(
    context,
    ['sns', 'list-subscriptions-by-topic', '--topic-arn', topicArn],
    'E7_ALERT_SUBSCRIPTION_READ_FAILED',
  );
  const subscriptions = response?.Subscriptions;
  if (
    !Array.isArray(subscriptions) ||
    subscriptions.length !== 1 ||
    response?.NextToken !== undefined
  ) {
    fail('E7_ALERT_SUBSCRIPTION_NOT_CONFIRMED');
  }
  const subscription = subscriptions[0];
  const endpoint = subscription?.Endpoint;
  const endpointSha256 =
    typeof endpoint === 'string' ? sha256(endpoint.trim().toLowerCase()) : null;
  if (
    subscription?.Protocol !== 'email' ||
    subscription?.TopicArn !== topicArn ||
    typeof subscription?.SubscriptionArn !== 'string' ||
    subscription.SubscriptionArn === 'PendingConfirmation' ||
    !subscription.SubscriptionArn.startsWith(`${topicArn}:`) ||
    !/^[0-9a-f-]{36}$/u.test(subscription.SubscriptionArn.slice(topicArn.length + 1)) ||
    endpointSha256 !== context.config.budget.alertDestinationSha256
  ) {
    fail('E7_ALERT_SUBSCRIPTION_NOT_CONFIRMED');
  }
  const hydratedCheckpoints = await hydrateEvidenceTarget(context, 'observability', source);
  const checkpoint = {
    decision: 'PASS',
    identity,
    alertDestinationSha256: endpointSha256,
    alertTopicSha256: sha256(topicArn),
    subscriptionArnSha256: sha256(subscription.SubscriptionArn),
    protocol: 'email',
    status: 'CONFIRMED',
    rawDestinationCaptured: false,
  };
  await updateEvidence(context, 'observability', 'observabilityReadiness', checkpoint);
  assertHydratedCheckpointsPreserved(context, 'observability', hydratedCheckpoints);
  return checkpoint;
};

export const deployWeb = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const { approvedPlan, assembly, context, identity, previousManifest, releaseMode } =
    await deployContext({
      flags,
      executor,
      environmentVariables,
      now,
      suffix: 'web',
    });
  assertDeployOrder(context, 'web');
  const apiOrigin = releaseApiOriginFromOutputs(
    context,
    describeStack(context, stackFor(context, 'api')).outputs,
    'E7_DEPLOYED_API_OUTPUT_INVALID',
  );
  const stackName = stackFor(context, 'web');
  let before = describeStack(context, stackName, { allowMissing: true });
  deployReleaseMode(flags);
  const previousPublication =
    releaseMode === 'VERSIONED_UPDATE' ? previousPublicationExpectation(previousManifest) : null;
  if (releaseMode === 'VERSIONED_UPDATE') {
    if (
      !before.exists ||
      before.outputs.CandidateSha !== previousManifest.previous.candidateSha ||
      before.outputs.ReleaseId !== previousManifest.previous.releaseId ||
      before.parameters.PublicationState !== previousPublication.publicationState ||
      before.outputs.WebPublicationStatus !== previousPublication.publicationState ||
      before.outputs.WebBucketName !== previousManifest.resources.web.bucketName ||
      before.outputs.DistributionId !== previousManifest.resources.web.distributionId ||
      getDistributionConfig(context, before.outputs.DistributionId).DistributionConfig.Enabled !==
        previousPublication.distributionEnabled
    ) {
      fail('E7_VERSIONED_UPDATE_BASELINE_STACK_INVALID');
    }
  } else if (
    before.exists &&
    (before.outputs.CandidateSha !== context.identity.candidateSha ||
      before.outputs.ReleaseId !== context.identity.releaseId)
  ) {
    fail('E7_INITIAL_RELEASE_EXISTING_STACK_INVALID');
  }
  const previousObjects = previousManifest?.resources.web.objects ?? [];
  if (releaseMode === 'VERSIONED_UPDATE') {
    const candidateDisabledPublication = Object.freeze({
      publicationState: 'DISABLED',
      schedulerState: 'DISABLED',
    });
    verifyApiPublicationPostureAws(context, {
      expectedIdentity: context.identity,
      expectedPublication: candidateDisabledPublication,
      expectedResources: previousManifest.resources,
      expectedVersions: null,
      state: describeStack(context, stackFor(context, 'api')),
    });
    before = describeStack(context, stackName);
    verifyWebPublicationPostureAws(context, {
      expectedFingerprint: approvedPlan.preDeploymentStateSha256,
      expectedIdentity: previousManifest.previous,
      expectedPublication: previousPublication,
      expectedResources: previousManifest.resources,
      state: before,
    });
  }
  const deployed = deployStack(context, assembly, 'web', {
    preDeploymentStateSha256: approvedPlan.preDeploymentStateSha256,
  });
  const deployedOrigin = assertExactHttpsOrigin(
    validateDeployedWebOutputs(context, deployed.outputs, 'E7_DEPLOYED_WEB_OUTPUT_INVALID'),
  );
  if (deployed.outputs.WebPublicationStatus !== 'DISABLED') {
    fail('E7_WEB_PREMATURE_ACTIVATION_DETECTED');
  }
  if (
    before.exists &&
    (before.outputs.WebBucketName !== deployed.outputs.WebBucketName ||
      before.outputs.DistributionId !== deployed.outputs.DistributionId)
  ) {
    fail('E7_WEB_ROLLBACK_TARGET_NOT_PRESERVED');
  }
  const deployedObjects = listWebVersions(context, deployed.outputs.WebBucketName, {
    allLatest: true,
  });
  if (!deployedObjects.some(({ key }) => key === 'index.html'))
    fail('E7_DEPLOYED_WEB_INDEX_MISSING');
  const publication = captureWebPublication(context, deployed.outputs.DistributionId);
  const templateSha256 = assemblyTemplateSha256(assembly, stackName);
  validateOriginalStackTemplate(context, stackName, templateSha256);
  const rollbackBody = {
    createdAtUtc: utc(now),
    releaseMode,
    previousManifest: previousManifest?.manifestSha256 ?? null,
    bucketName: deployed.outputs.WebBucketName,
    distributionId: deployed.outputs.DistributionId,
    publicOriginSha256: sha256(deployedOrigin),
    apiOriginSha256: sha256(apiOrigin),
    previous: previousObjects,
    deployed: deployedObjects,
    publication,
    templateSha256,
    rollbackAvailable: previousManifest !== null,
    initialUnpublishAvailable: previousManifest === null,
  };
  const rollbackRecord = writeRecord(context, 'rollback-web', rollbackBody);
  const checkpoint = deploymentCheckpoint(
    context,
    identity,
    assembly,
    deployed.stackName,
    deployed.outputs,
    {
      approvedPlan,
      previousReleaseManifestSha256: previousManifest?.manifestSha256 ?? null,
      releaseMode,
      publicOriginSha256: sha256(deployedOrigin),
      apiOriginSha256: sha256(apiOrigin),
      rollbackRecord,
    },
  );
  await updateEvidence(context, 'web', 'web', checkpoint);
  return checkpoint;
};

const parseSeedStatus = (output, code) => {
  const lines = output.split(/\r?\n/u).filter(Boolean);
  const statuses = lines
    .map((line) => /^SEED_STATUS=(CREATED|EXISTS)$/u.exec(line)?.[1])
    .filter(Boolean);
  if (statuses.length !== 1) fail(code);
  return statuses[0];
};

const publicOrigin = (context, { requireWeb }) => {
  const parameterName = `/checkout-${context.config.environment}/public-origin`;
  if (!requireWeb) {
    const value = `https://${context.config.domain.hostname}`;
    return { parameterName, source: 'AUTHORIZED_CUSTOM_DOMAIN', value };
  }
  const web = describeStack(context, stackFor(context, 'web'));
  const expectedOrigin = validateDeployedWebOutputs(
    context,
    web.outputs,
    'E7_PUBLIC_ORIGIN_PARAMETER_MISMATCH',
  );
  const response = awsJson(
    context,
    ['ssm', 'get-parameter', '--name', parameterName, '--no-with-decryption'],
    'E7_PUBLIC_ORIGIN_UNAVAILABLE',
  );
  const value = response?.Parameter?.Value;
  if (typeof value !== 'string' || value !== expectedOrigin) {
    fail('E7_PUBLIC_ORIGIN_VALUE_MISMATCH');
  }
  return { parameterName, source: 'SSM_AFTER_WEB', value };
};

const assertExactHttpsOrigin = (value) => {
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== 'https:' ||
      parsed.origin !== value ||
      parsed.username !== '' ||
      parsed.password !== ''
    ) {
      fail('E7_PUBLIC_ORIGIN_INVALID');
    }
    return parsed.origin;
  } catch (error) {
    if (error instanceof Stage7AwsError) throw error;
    fail('E7_PUBLIC_ORIGIN_INVALID');
  }
};

const validateSeedRuntimeEnvironment = (context, origin, environment) => {
  const prereleaseAccessMode =
    context.scope === 'prerelease' ? 'cloudfront_signed_cookie' : 'origin_gate';
  const expected = {
    ALLOWED_ORIGIN: origin,
    API_BASE_PATH: '/api/v1',
    APP_ENV: 'assessment',
    AUTO_SEED_CATALOG: 'false',
    AWS_REGION: context.config.aws.region,
    CATALOG_TABLE_NAME: `checkout-${context.config.environment}-catalog`,
    CANDIDATE_SHA: context.identity.candidateSha,
    CHECKOUT_TABLE_NAME: `checkout-${context.config.environment}-checkout`,
    DATA_ADAPTER: 'dynamodb',
    PAYMENT_ADAPTER: 'sandbox',
    PAYMENTS_ENABLED: 'true',
    PRERELEASE_ACCESS_MODE: prereleaseAccessMode,
    PRODUCT_SEED_ID: 'product-demo-001',
    PUBLIC_ASSET_ORIGIN: origin,
    RELEASE_ID: context.identity.releaseId,
    RUNTIME_SECRET_ARN: runtimeSecretReference(context.config),
    RUNTIME_SECRET_VERSION_ID: runtimeSecretVersionId(context.config),
    SANDBOX_AUTHORIZED_UNTIL_UTC: context.config.authorization.expiresAtUtc,
    TOKENIZATION_MODE: 'direct_jwe',
  };
  const expectedKeys = [
    ...new Set([...Object.keys(context.childEnvironment), ...Object.keys(expected)]),
  ].toSorted();
  if (
    Object.keys(environment).toSorted().join('\0') !== expectedKeys.join('\0') ||
    Object.entries(expected).some(([key, value]) => environment[key] !== value) ||
    environment.ALLOWED_ORIGIN_PARAMETER_NAME !== undefined ||
    environment.DYNAMODB_ENDPOINT !== undefined ||
    environment.PUBLIC_ASSET_ORIGIN_PARAMETER_NAME !== undefined ||
    environment.RUNTIME_SECURITY_ROOT_KEY !== undefined
  ) {
    fail('E7_SEED_RUNTIME_ENVIRONMENT_INVALID');
  }
  return environment;
};

const seedRuntimeEnvironment = (context, origin) => {
  const sandboxAuthorizedUntilUtc = context.config.authorization.expiresAtUtc;
  const authorizationExpiry = Date.parse(sandboxAuthorizedUntilUtc ?? '');
  if (
    typeof sandboxAuthorizedUntilUtc !== 'string' ||
    !Number.isFinite(authorizationExpiry) ||
    new Date(authorizationExpiry).toISOString() !== sandboxAuthorizedUntilUtc
  ) {
    fail('E7_SEED_SANDBOX_AUTHORIZATION_INVALID');
  }
  const environment = {
    ...context.childEnvironment,
    ALLOWED_ORIGIN: origin,
    API_BASE_PATH: '/api/v1',
    APP_ENV: 'assessment',
    AUTO_SEED_CATALOG: 'false',
    AWS_REGION: context.config.aws.region,
    CATALOG_TABLE_NAME: `checkout-${context.config.environment}-catalog`,
    CANDIDATE_SHA: context.identity.candidateSha,
    CHECKOUT_TABLE_NAME: `checkout-${context.config.environment}-checkout`,
    DATA_ADAPTER: 'dynamodb',
    PAYMENT_ADAPTER: 'sandbox',
    PAYMENTS_ENABLED: 'true',
    PRERELEASE_ACCESS_MODE:
      context.scope === 'prerelease' ? 'cloudfront_signed_cookie' : 'origin_gate',
    PRODUCT_SEED_ID: 'product-demo-001',
    PUBLIC_ASSET_ORIGIN: origin,
    RELEASE_ID: context.identity.releaseId,
    RUNTIME_SECRET_ARN: runtimeSecretReference(context.config),
    RUNTIME_SECRET_VERSION_ID: runtimeSecretVersionId(context.config),
    SANDBOX_AUTHORIZED_UNTIL_UTC: sandboxAuthorizedUntilUtc,
    TOKENIZATION_MODE: 'direct_jwe',
  };
  delete environment.ALLOWED_ORIGIN_PARAMETER_NAME;
  delete environment.DYNAMODB_ENDPOINT;
  delete environment.PUBLIC_ASSET_ORIGIN_PARAMETER_NAME;
  delete environment.RUNTIME_SECURITY_ROOT_KEY;
  return validateSeedRuntimeEnvironment(context, origin, environment);
};

export const seedRelease = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const prereleaseSafety = await validatePrereleaseMutationSafety({
    flags,
    environmentVariables,
    now,
    authorityPhase: 'seed',
    deploymentPhase: 'before-seed',
  });
  const context = loadOperationContext({
    capability: 'deploy',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const previousManifest =
    context.scope === 'prerelease' ? null : validateVersionedMutationTarget(context, flags);
  if (context.scope !== 'prerelease') {
    const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
    validateProtectedApproval(
      context,
      flags.approval,
      flags.plan,
      assembly,
      flags.manifest,
      flags['aws-auth'],
      previousManifest,
    );
  }
  if (context.scope === 'prerelease') {
    if (flags['synthetic-only'] !== true || flags['after-web-origin'] !== true) {
      fail('E7_PRERELEASE_SEED_FLAGS_REQUIRED');
    }
  } else if (flags['after-web-origin'] || flags['synthetic-only']) {
    fail('E7_FULL_RELEASE_SEED_FLAG_INVALID');
  }
  const identity = revalidateAwsIdentity(context);
  const prereleaseAccess = validatePrereleaseAccessAws(context);
  const runtimeSecretReferenceSha256 = validateRuntimeSecretReferenceAws(context).bindingSha256;
  const data = describeStack(context, stackFor(context, 'data'));
  if (
    data.outputs.CandidateSha !== context.identity.candidateSha ||
    data.outputs.ReleaseId !== context.identity.releaseId
  ) {
    fail('E7_SEED_DATA_STACK_IDENTITY_MISMATCH');
  }
  const origin = publicOrigin(context, { requireWeb: context.scope === 'prerelease' });
  assertExactHttpsOrigin(origin.value);
  const seedEnvironment = seedRuntimeEnvironment(context, origin.value);
  const seedArguments = [
    workspaceToolEntrypoint('tsx'),
    path.join(workspaceRoot, 'apps/api/src/infrastructure/persistence/seed.cli.ts'),
  ];
  const first = parseSeedStatus(
    run(context.executor, process.execPath, seedArguments, {
      code: 'E7_SEED_FIRST_EXECUTION_FAILED',
      env: seedEnvironment,
    }),
    'E7_SEED_FIRST_RESULT_INVALID',
  );
  const second = parseSeedStatus(
    run(context.executor, process.execPath, seedArguments, {
      code: 'E7_SEED_SECOND_EXECUTION_FAILED',
      env: seedEnvironment,
    }),
    'E7_SEED_SECOND_RESULT_INVALID',
  );
  if (second !== 'EXISTS') fail('E7_SEED_NOT_IDEMPOTENT');
  const checkpoint = {
    decision: 'PASS',
    identity,
    firstExecution: first,
    secondExecution: second,
    productId: 'product-demo-001',
    publicOriginSha256: sha256(origin.value),
    publicOriginSource: origin.source,
    publicOriginParameterName: origin.parameterName,
    syntheticDataOnly: true,
    stockResetPerformed: false,
    previousReleaseManifestSha256: previousManifest?.manifestSha256 ?? null,
    runtimeSecretReferenceSha256,
    ...(prereleaseAccess === null
      ? {}
      : {
          prereleaseAccessBindingSha256: prereleaseAccess.bindingSha256,
          safetyReadinessSha256: prereleaseSafety.readiness.readinessSha256,
          ...watchdogLiveAuthorityCheckpoint(prereleaseSafety),
          approvedDeploymentCheckpointSha256: prereleaseApprovedDeploymentCheckpointSha256(
            prereleaseSafety.deployment,
          ),
        }),
  };
  await updateEvidence(context, 'seed', 'seed', checkpoint);
  return checkpoint;
};

const getSchedule = (context) => {
  const name = `checkout-${context.config.environment}-reconcile`;
  if (!SCHEDULE_NAME.test(name)) fail('E7_SCHEDULE_NAME_INVALID');
  const schedule = awsJson(
    context,
    ['scheduler', 'get-schedule', '--name', name],
    'E7_SCHEDULE_READ_FAILED',
  );
  if (schedule?.Name !== name || !object(schedule.Target) || !object(schedule.FlexibleTimeWindow)) {
    fail('E7_SCHEDULE_CONTRACT_INVALID');
  }
  return schedule;
};

const validateScheduleTarget = (context, apiOutputs, schedule = getSchedule(context)) => {
  const input = strictJson(schedule.Target.Input ?? '', 'E7_SCHEDULE_INPUT_INVALID');
  if (
    schedule.ScheduleExpression !== 'rate(1 minute)' ||
    schedule.FlexibleTimeWindow?.Mode !== 'OFF' ||
    schedule.Target?.Arn !== apiOutputs.WorkerAliasArn ||
    schedule.Target?.RetryPolicy?.MaximumEventAgeInSeconds !== 300 ||
    schedule.Target?.RetryPolicy?.MaximumRetryAttempts !== 2 ||
    Object.keys(input).toSorted().join('\0') !== ['action', 'mode'].join('\0') ||
    input.action !== 'reconcile' ||
    input.mode !== 'sandbox'
  ) {
    fail('E7_SCHEDULE_TARGET_MISMATCH');
  }
  const roleAccount = /^arn:aws:iam::([0-9]{12}):role\//u.exec(schedule.Target?.RoleArn ?? '')?.[1];
  if (roleAccount !== context.config.aws.accountId) fail('E7_SCHEDULE_ROLE_ACCOUNT_MISMATCH');
  return sha256(
    JSON.stringify({
      expression: schedule.ScheduleExpression,
      targetArn: schedule.Target.Arn,
      roleArn: schedule.Target.RoleArn,
      input,
    }),
  );
};

const validateActivatedApiPosture = (context, apiRecord, apiOutputs) => {
  const api = getHttpApi(context, apiRecord.publication.apiId);
  const customDomain = context.config.domain.mode === 'CUSTOM_AUTHORIZED';
  const mappings = customDomain ? getApiMappings(context, context.config.domain.apiHostname) : [];
  const target = apiRecord.publication.mapping;
  const schedule = getSchedule(context);
  const apiAlias = assertAliasWithoutWeightedRouting(getAlias(context, apiRecord.deployed.api));
  const workerAlias = assertAliasWithoutWeightedRouting(
    getAlias(context, apiRecord.deployed.worker),
  );
  if (
    api.ApiId !== apiRecord.publication.apiId ||
    sha256(api.ApiEndpoint ?? '') !== apiRecord.publication.apiEndpointSha256 ||
    api.DisableExecuteApiEndpoint !== customDomain ||
    schedule.State !== 'ENABLED' ||
    apiAlias.FunctionVersion !== apiRecord.deployed.api.version ||
    workerAlias.FunctionVersion !== apiRecord.deployed.worker.version ||
    (customDomain &&
      (mappings.length !== 1 ||
        mappings[0]?.ApiId !== target?.apiId ||
        mappings[0]?.Stage !== target?.stage ||
        (mappings[0]?.ApiMappingKey ?? '') !== target?.apiMappingKey ||
        !API_MAPPING_ID.test(mappings[0]?.ApiMappingId ?? ''))) ||
    (!customDomain && mappings.length !== 0)
  ) {
    fail('E7_ACTIVATION_API_POSTURE_INVALID');
  }
  validateScheduleTarget(context, apiOutputs, schedule);
  return { api, apiAlias, mappings, schedule, workerAlias };
};

const getAlias = (context, target) => {
  if (!FUNCTION_NAME.test(target.functionName) || !ALIAS_NAME.test(target.aliasName)) {
    fail('E7_ALIAS_TARGET_INVALID');
  }
  const alias = awsJson(
    context,
    ['lambda', 'get-alias', '--function-name', target.functionName, '--name', target.aliasName],
    'E7_ALIAS_READ_FAILED',
  );
  if (alias?.Name !== target.aliasName || !VERSION.test(alias.FunctionVersion ?? '')) {
    fail('E7_ALIAS_CONTRACT_INVALID');
  }
  return alias;
};

const classifyInitialPublicationState = ({
  baselineDistributionEnabled,
  distributionEnabled,
  mappingExpected,
  mappingPublished,
  scheduleState,
}) => {
  const baseline =
    !mappingPublished &&
    distributionEnabled === baselineDistributionEnabled &&
    scheduleState === 'DISABLED';
  const activated =
    mappingPublished === mappingExpected &&
    distributionEnabled === true &&
    scheduleState === 'ENABLED';
  if (baseline === activated) fail('E7_ACTIVATION_PARTIAL_STATE_DETECTED');
  return { activated, baseline };
};

const initialPublicationState = (context, apiPublication, webPublication) => {
  if (!object(apiPublication) || !object(webPublication)) {
    fail('E7_INITIAL_PUBLICATION_RECORD_INVALID');
  }
  const apiStack = publicationStateForStack(context, 'api');
  const webStack = publicationStateForStack(context, 'web');
  const apiEnabled = apiStack.publicationState === 'ENABLED';
  const webEnabled = webStack.publicationState === 'ENABLED';
  const full = context.config.domain.mode === 'CUSTOM_AUTHORIZED';
  const api = getHttpApi(context, apiPublication.apiId);
  if (
    sha256(api.ApiEndpoint ?? '') !== apiPublication.apiEndpointSha256 ||
    api.DisableExecuteApiEndpoint !== (!apiEnabled || full)
  ) {
    fail('E7_INITIAL_PUBLICATION_DRIFT_DETECTED');
  }
  let mappingPublished = false;
  if (apiPublication.mapping !== null) {
    const target = apiPublication.mapping;
    if (
      !object(target) ||
      target.apiId !== apiPublication.apiId ||
      target.apiMappingId !== null ||
      target.domainName !== context.config.domain.apiHostname ||
      target.stage !== '$default' ||
      target.apiMappingKey !== ''
    ) {
      fail('E7_INITIAL_API_PUBLICATION_RECORD_INVALID');
    }
    const mappings = getApiMappings(context, target.domainName);
    const exact = mappings.filter(
      (mapping) =>
        mapping?.ApiId === target.apiId &&
        mapping?.Stage === target.stage &&
        (mapping?.ApiMappingKey ?? '') === target.apiMappingKey,
    );
    if (exact.length > 1 || mappings.length !== exact.length) {
      fail('E7_API_MAPPING_DRIFT_DETECTED');
    }
    if (exact.length === 1 && !API_MAPPING_ID.test(exact[0]?.ApiMappingId ?? '')) {
      fail('E7_API_MAPPING_TARGET_INVALID');
    }
    mappingPublished = exact.length === 1;
  }
  const distribution = getDistributionConfig(context, webPublication.distributionId);
  if (
    distributionContractSha256(distribution.DistributionConfig) !==
    webPublication.distributionConfigSha256
  ) {
    fail('E7_WEB_DISTRIBUTION_DRIFT_DETECTED');
  }
  const schedule = getSchedule(context);
  const resourceStateValid =
    distribution.DistributionConfig.Enabled === webEnabled &&
    mappingPublished === (apiEnabled && full) &&
    schedule.State === (apiEnabled ? 'ENABLED' : 'DISABLED');
  const baseline =
    resourceStateValid &&
    apiStack.publicationState === 'DISABLED' &&
    webStack.publicationState === 'DISABLED';
  const activated =
    resourceStateValid &&
    apiStack.publicationState === 'ENABLED' &&
    webStack.publicationState === 'ENABLED';
  if (baseline === activated) fail('E7_ACTIVATION_PARTIAL_STATE_DETECTED');
  return {
    activated,
    apiStack,
    baseline,
    schedule,
    webStack,
  };
};

const restoreInitialPublicationBaseline = (
  context,
  apiPublication,
  webPublication,
  { apiRecord, webRecord },
) => {
  const recoveryFailures = [];
  const recover = (callback) => {
    try {
      callback();
    } catch {
      recoveryFailures.push(true);
    }
  };
  const recoverStack = (suffix, record) => {
    const current = publicationStateForStack(context, suffix);
    if (
      canonicalJson(current.state.tags) !== canonicalJson(expectedReleaseStackTags(context)) ||
      (suffix === 'api' &&
        (JSON.stringify(
          apiVersionsFromOutputs(
            context,
            current.state.outputs,
            'E7_ACTIVATION_COMPENSATION_BINDING_INVALID',
          ),
        ) !== JSON.stringify(record.deployed) ||
          current.state.outputs.HttpApiId !== record.publication.apiId)) ||
      (suffix === 'web' &&
        (current.state.outputs.WebBucketName !== record.bucketName ||
          current.state.outputs.DistributionId !== record.distributionId ||
          current.state.outputs.DistributionId !== record.publication.distributionId))
    ) {
      fail('E7_ACTIVATION_COMPENSATION_BINDING_INVALID');
    }
    validateOriginalStackTemplate(context, current.stackName, record.templateSha256);
    return updatePublicationStack(context, suffix, 'DISABLED', {
      expectedBeforeStateSha256: stackStateFingerprint(current.stackName, current.state),
      expectedTemplateSha256: record.templateSha256,
    });
  };
  recover(() => recoverStack('web', webRecord));
  recover(() => recoverStack('api', apiRecord));
  if (recoveryFailures.length !== 0) fail('E7_ACTIVATION_COMPENSATION_FAILED');
  try {
    const restored = initialPublicationState(context, apiPublication, webPublication);
    if (!restored.baseline) fail('E7_ACTIVATION_COMPENSATION_FAILED');
  } catch {
    fail('E7_ACTIVATION_COMPENSATION_FAILED');
  }
};

const rollbackReleaseMode = (flags, record, targetFlag) => {
  const initial = flags['initial-release'] === true;
  if (
    !initial ||
    flags[targetFlag] !== true ||
    flags['previous-manifest'] !== undefined ||
    record.releaseMode !== 'INITIAL'
  ) {
    fail('E7_UPDATE_RELEASE_NOT_SUPPORTED');
  }
  return 'INITIAL';
};

const validateSeedEvidence = (context, filename) => {
  const source = readJson(filename ?? evidenceTarget(context, 'seed'), 'E7_SEED_EVIDENCE_MISSING');
  if (
    source?.environment !== context.config.environment ||
    source?.releaseId !== context.identity.releaseId ||
    source?.candidateSha !== context.identity.candidateSha ||
    source?.configSha256 !== objectSha256(context.config) ||
    source?.checkpoints?.seed?.decision !== 'PASS' ||
    source?.checkpoints?.seed?.secondExecution !== 'EXISTS'
  ) {
    fail('E7_SEED_EVIDENCE_INVALID');
  }
  return sha256(JSON.stringify(source.checkpoints.seed));
};

const externalAuthorizationBundle = (context) => {
  const filename = context.environmentVariables.STAGE7_EXTERNAL_AUTHORIZATIONS;
  if (typeof filename !== 'string' || filename.trim() === '') {
    fail('E7_EXTERNAL_AUTHORIZATION_REQUIRED');
  }
  const absolute = path.resolve(workspaceRoot, filename);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch {
    fail('E7_EXTERNAL_AUTHORIZATION_REQUIRED');
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 128 * 1024) {
    fail('E7_EXTERNAL_AUTHORIZATION_FILE_INVALID');
  }
  try {
    const source = readFileSync(absolute);
    assertSanitizedArtifactText('stage7-external-authorizations.json', source.toString('utf8'));
    return parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch (error) {
    if (error instanceof Stage7AwsError) throw error;
    fail('E7_EXTERNAL_AUTHORIZATION_FILE_INVALID');
  }
};

const validateActivationAuthorization = (context, webRecord) => {
  if (context.scope === 'prerelease') {
    if (context.flags['non-public'] !== true) fail('E7_PRERELEASE_ACTIVATION_FLAGS_REQUIRED');
  } else if (context.flags['non-public'] !== undefined) {
    fail('E7_FULL_RELEASE_ACTIVATION_FLAG_INVALID');
  }
  if (
    !SHA256.test(webRecord?.publicOriginSha256 ?? '') ||
    (context.scope === 'prerelease' && !SHA256.test(webRecord?.apiOriginSha256 ?? ''))
  ) {
    fail('E7_EXTERNAL_AUTHORIZATION_ORIGIN_INVALID');
  }
  let validated;
  try {
    validated = validateExternalAuthorizations({
      value: externalAuthorizationBundle(context),
      config: context.config,
      candidateSha: context.identity.candidateSha,
      releaseId: context.identity.releaseId,
      deployedOriginSha256: webRecord.publicOriginSha256,
      ...(context.scope === 'prerelease'
        ? { deployedApiOriginSha256: webRecord.apiOriginSha256 }
        : {}),
      now: context.now,
    });
  } catch (error) {
    if (typeof error?.code === 'string' && error.code.startsWith('E7_EXTERNAL_AUTHORIZATION')) {
      fail(error.code);
    }
    throw error;
  }
  const fullRelease = context.config.authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE';
  const authorizationIds = fullRelease
    ? ['AUTH-E7-EXT-01', 'AUTH-E7-EXT-02', 'AUTH-E7-EXT-03']
    : ['AUTH-E6-01', 'AUTH-E6-02', 'AUTH-E6-03'];
  return {
    externalAuthorization: {
      authorizationSha256: objectSha256(validated.value),
      authorizationIds,
      publicOriginSha256: validated.originSha256,
    },
    authorizationUsage: {
      schemaVersion: 1,
      usageId:
        context.flags['re-promote'] === true ? 'ACTIVATION_REPROMOTION' : 'ACTIVATION_CANDIDATE',
      bundleSha256: objectSha256(validated.value),
      candidateSha: context.identity.candidateSha,
      releaseId: context.identity.releaseId,
      configSha256: objectSha256(context.config),
      ownedOriginSha256: validated.originSha256,
      sandboxHostSha256: validated.sandboxHostSha256,
      requestCounts: Object.fromEntries(authorizationIds.map((id) => [id, 0])),
    },
  };
};

export const activateRelease = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const prereleaseSafety = await validatePrereleaseMutationSafety({
    flags,
    environmentVariables,
    now,
    authorityPhase: 'activation',
    protectedEnvironment: 'assessment-prerelease-external',
    deploymentPhase: 'before-activation',
    livePhase: 'activation',
  });
  if (flags.app === undefined || flags.manifest === undefined) fail('E7_ACTIVATION_INPUT_REQUIRED');
  /* c8 ignore start -- unreachable until the recovery contracts above are implemented */
  const context = loadOperationContext({
    capability: flags['re-promote'] === true ? 'rollback' : 'deploy',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const releaseMode = releaseModeForFlags(context.scope, flags);
  const previousManifest =
    releaseMode === 'VERSIONED_UPDATE' ? validateVersionedMutationTarget(context, flags) : null;
  // The protected external bundle is a local, immutable input. Validate it and the
  // rollback records before even reading STS so an unauthorized prerelease cannot
  // cause any AWS or provider request.
  const apiRecord = readRecord(context, 'rollback-api', flags['api-record']);
  const webRecord = readRecord(context, 'rollback-web', flags['web-record']);
  const observabilityReadiness = validateObservabilityReadinessEvidence(
    context,
    flags['observability-evidence'],
  );
  if (
    apiRecord.releaseMode !== releaseMode ||
    webRecord.releaseMode !== releaseMode ||
    apiRecord.previousManifest !== (previousManifest?.manifestSha256 ?? null) ||
    webRecord.previousManifest !== (previousManifest?.manifestSha256 ?? null) ||
    apiRecord.releaseMode !== webRecord.releaseMode
  ) {
    fail('E7_RELEASE_MODE_RECORD_MISMATCH');
  }
  const authorization = validateActivationAuthorization(context, webRecord);
  const activationTarget = evidenceTarget(context, 'activation');
  let previousTransitions = [];
  if (flags['re-promote'] === true) {
    const previousEvidence = readJson(activationTarget, 'E7_INITIAL_ACTIVATION_EVIDENCE_MISSING');
    const previousCheckpoint = previousEvidence?.checkpoints?.activation;
    if (context.scope !== 'prerelease') {
      validateStage7ActivationCheckpoint(previousCheckpoint, {
        config: context.config,
        candidateSha: context.identity.candidateSha,
        releaseId: context.identity.releaseId,
        manifestSha256: previousCheckpoint?.freezeManifestSha256,
        complete: false,
      });
    }
    if (
      !Array.isArray(previousCheckpoint?.transitions) ||
      previousCheckpoint.transitions.length !== 1
    ) {
      fail('E7_INITIAL_ACTIVATION_EVIDENCE_INVALID');
    }
    previousTransitions = previousCheckpoint.transitions;
  } else if (existsSync(activationTarget)) {
    fail('E7_ACTIVATION_EVIDENCE_ALREADY_EXISTS');
  }
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  const expectedTemplateSha256BySuffix = new Map(
    STACK_SUFFIXES.map((suffix) => [
      suffix,
      assemblyTemplateSha256(assembly, stackFor(context, suffix)),
    ]),
  );
  if (
    apiRecord.templateSha256 !== expectedTemplateSha256BySuffix.get('api') ||
    webRecord.templateSha256 !== expectedTemplateSha256BySuffix.get('web')
  ) {
    fail('E7_ACTIVATION_RECORD_TEMPLATE_BINDING_INVALID');
  }
  if (context.scope !== 'prerelease') {
    validateProtectedApproval(
      context,
      flags.approval,
      flags.plan,
      assembly,
      flags.manifest,
      flags['aws-auth'],
      previousManifest,
    );
  }
  revalidateAwsIdentity(context);
  const prereleaseAccess = validatePrereleaseAccessAws(context);
  const activationStackStates = new Map();
  let apiOutputs;
  let webOutputs;
  for (const suffix of STACK_SUFFIXES) {
    const state = describeStack(context, stackFor(context, suffix));
    if (
      !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus) ||
      state.terminationProtection !== (context.scope !== 'prerelease') ||
      state.outputs.CandidateSha !== context.identity.candidateSha ||
      state.outputs.ReleaseId !== context.identity.releaseId ||
      canonicalJson(state.tags) !== canonicalJson(expectedReleaseStackTags(context))
    )
      fail('E7_ACTIVATION_STACK_NOT_READY');
    if (suffix === 'api') apiOutputs = state.outputs;
    if (suffix === 'web') webOutputs = state.outputs;
    activationStackStates.set(suffix, state);
    validateOriginalStackTemplate(
      context,
      stackFor(context, suffix),
      expectedTemplateSha256BySuffix.get(suffix),
    );
  }
  if (
    webOutputs.PrereleaseAccessBindingSha256 !==
    (prereleaseAccess === null ? 'NOT_APPLICABLE' : prereleaseAccess.bindingSha256)
  ) {
    fail('E7_ACTIVATION_PRERELEASE_ACCESS_BINDING_MISMATCH');
  }
  const origin = publicOrigin(context, { requireWeb: true });
  assertExactHttpsOrigin(origin.value);
  const seedEvidenceSha256 = validateSeedEvidence(context, flags['seed-evidence']);
  const scheduleTargetSha256 = validateScheduleTarget(context, apiOutputs);
  const apiCurrent = assertAliasWithoutWeightedRouting(getAlias(context, apiRecord.deployed.api));
  const workerCurrent = assertAliasWithoutWeightedRouting(
    getAlias(context, apiRecord.deployed.worker),
  );
  if (
    apiCurrent.FunctionVersion !== apiRecord.deployed.api.version ||
    workerCurrent.FunctionVersion !== apiRecord.deployed.worker.version
  ) {
    fail('E7_ALIAS_DRIFT_DETECTED');
  }
  const apiPromotion = { changed: false, version: apiRecord.deployed.api.version };
  const workerPromotion = { changed: false, version: apiRecord.deployed.worker.version };
  const currentWeb = listWebVersions(context, webRecord.bucketName, { allLatest: true });
  validateExactWebObjectInventory(currentWeb, webRecord.deployed, 'E7_WEB_OBJECT_DRIFT_DETECTED');
  const webPromotion = { invalidatedPaths: [], restoredObjects: 0 };
  const immediatelyBeforeActivationStates = new Map();
  for (const suffix of STACK_SUFFIXES) {
    const stackName = stackFor(context, suffix);
    const state = describeStack(context, stackName);
    const initialState = activationStackStates.get(suffix);
    if (
      !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus) ||
      state.terminationProtection !== (context.scope !== 'prerelease') ||
      state.outputs.CandidateSha !== context.identity.candidateSha ||
      state.outputs.ReleaseId !== context.identity.releaseId ||
      canonicalJson(state.tags) !== canonicalJson(expectedReleaseStackTags(context)) ||
      state.stackId !== initialState.stackId ||
      stackStateFingerprint(stackName, state) !== stackStateFingerprint(stackName, initialState)
    ) {
      fail('E7_ACTIVATION_STACK_NOT_READY');
    }
    validateOriginalStackTemplate(context, stackName, expectedTemplateSha256BySuffix.get(suffix));
    immediatelyBeforeActivationStates.set(suffix, state);
  }
  const activationApiState = immediatelyBeforeActivationStates.get('api');
  const activationWebState = immediatelyBeforeActivationStates.get('web');
  validateActivationLiveBindings(context, {
    apiOutputs: activationApiState.outputs,
    webOutputs: activationWebState.outputs,
    apiRecord,
    webRecord,
  });
  validateOriginalStackTemplate(context, stackFor(context, 'api'), apiRecord.templateSha256);
  validateOriginalStackTemplate(context, stackFor(context, 'web'), webRecord.templateSha256);
  validateHostedZoneAws(context);
  validateCertificatesAws(context);
  await Promise.all(
    STACK_SUFFIXES.map((suffix) =>
      detectStackDrift(context, stackFor(context, suffix), {
        expectedStackId: immediatelyBeforeActivationStates.get(suffix).stackId,
      }),
    ),
  );
  const publicationState = initialPublicationState(
    context,
    apiRecord.publication,
    webRecord.publication,
  );
  if (!publicationState?.baseline) fail('E7_ACTIVATION_REQUIRES_DISABLED_BASELINE');
  let apiPublication;
  let webPublication;
  try {
    apiPublication = updatePublicationStack(context, 'api', 'ENABLED', {
      expectedBeforeStateSha256: stackStateFingerprint(
        stackFor(context, 'api'),
        activationApiState,
      ),
      expectedTemplateSha256: apiRecord.templateSha256,
    });
    const immediatelyBeforeWebApi = publicationStateForStack(context, 'api');
    const immediatelyBeforeWeb = publicationStateForStack(context, 'web');
    if (
      immediatelyBeforeWebApi.publicationState !== 'ENABLED' ||
      immediatelyBeforeWeb.publicationState !== 'DISABLED' ||
      immediatelyBeforeWebApi.state.stackId !== activationApiState.stackId ||
      immediatelyBeforeWeb.state.stackId !== activationWebState.stackId ||
      stackStateFingerprint(immediatelyBeforeWeb.stackName, immediatelyBeforeWeb.state) !==
        stackStateFingerprint(stackFor(context, 'web'), activationWebState)
    ) {
      fail('E7_ACTIVATION_WEB_PRECONDITION_INVALID');
    }
    validateActivationLiveBindings(context, {
      apiOutputs: immediatelyBeforeWebApi.state.outputs,
      webOutputs: immediatelyBeforeWeb.state.outputs,
      apiRecord,
      webRecord,
    });
    validateOriginalStackTemplate(
      context,
      immediatelyBeforeWebApi.stackName,
      apiRecord.templateSha256,
    );
    validateOriginalStackTemplate(
      context,
      immediatelyBeforeWeb.stackName,
      webRecord.templateSha256,
    );
    validateExactWebObjectInventory(
      listWebVersions(context, webRecord.bucketName, { allLatest: true }),
      webRecord.deployed,
      'E7_WEB_OBJECT_DRIFT_DETECTED',
    );
    await Promise.all([
      detectStackDrift(context, immediatelyBeforeWebApi.stackName, {
        expectedStackId: immediatelyBeforeWebApi.state.stackId,
      }),
      detectStackDrift(context, immediatelyBeforeWeb.stackName, {
        expectedStackId: immediatelyBeforeWeb.state.stackId,
      }),
    ]);
    validateActivatedApiPosture(context, apiRecord, immediatelyBeforeWebApi.state.outputs);
    webPublication = updatePublicationStack(context, 'web', 'ENABLED', {
      expectedBeforeStateSha256: stackStateFingerprint(
        immediatelyBeforeWeb.stackName,
        immediatelyBeforeWeb.state,
      ),
      expectedTemplateSha256: webRecord.templateSha256,
    });
    validateActivatedApiPosture(
      context,
      apiRecord,
      publicationStateForStack(context, 'api').state.outputs,
    );
    const activated = initialPublicationState(
      context,
      apiRecord.publication,
      webRecord.publication,
    );
    if (!activated.activated) fail('E7_ACTIVATION_STATE_NOT_APPLIED');
  } catch (error) {
    restoreInitialPublicationBaseline(context, apiRecord.publication, webRecord.publication, {
      apiRecord,
      webRecord,
    });
    throw error;
  }
  const scheduler = {
    controlledBy: 'PublicationState',
    stackName: apiPublication.stackName,
    state: 'ENABLED',
  };
  const transition = {
    sequence: previousTransitions.length + 1,
    mode:
      flags['re-promote'] === true
        ? 'REPROMOTION'
        : releaseMode === 'VERSIONED_UPDATE'
          ? 'CANDIDATE_ACTIVATION'
          : 'INITIAL_ACTIVATION',
    apiStack: apiPublication,
    webStack: webPublication,
    scheduler,
    authorizationUsage: authorization.authorizationUsage,
  };
  const checkpoint = {
    decision: 'ACTIVATED_REQUIRES_SMOKE',
    releaseMode,
    updateReleaseSupported: releaseMode === 'VERSIONED_UPDATE',
    previousReleaseManifestSha256: previousManifest?.manifestSha256 ?? null,
    assemblySha256: assembly.assemblySha256,
    freezeManifestSha256: assembly.freezeManifestSha256,
    seedEvidenceSha256,
    publicOriginSha256: sha256(origin.value),
    externalAuthorization: authorization.externalAuthorization,
    observabilityReadiness,
    publication: {
      managedByCloudFormation: true,
      apiStack: {
        stackName: apiPublication.stackName,
        stackIdSha256: apiPublication.stackIdSha256,
        state: 'ENABLED',
      },
      webStack: {
        stackName: webPublication.stackName,
        stackIdSha256: webPublication.stackIdSha256,
        state: 'ENABLED',
      },
      scheduler,
    },
    promotions: {
      api: apiPromotion,
      worker: workerPromotion,
      web: webPromotion,
    },
    scheduleTargetSha256,
    transitions: [...previousTransitions, transition],
    ...(context.scope === 'prerelease'
      ? {
          safetyReadinessSha256: prereleaseSafety.readiness.readinessSha256,
          liveSafetyRecheckSha256: prereleaseSafety.liveSafetyRecheck.liveSafetyRecheckSha256,
          prereleaseDeploymentCheckpointSha256: objectSha256(prereleaseSafety.deployment),
          ...watchdogLiveAuthorityCheckpoint(prereleaseSafety),
        }
      : {}),
  };
  if (context.scope !== 'prerelease') {
    validateStage7ActivationCheckpoint(checkpoint, {
      config: context.config,
      candidateSha: context.identity.candidateSha,
      releaseId: context.identity.releaseId,
      manifestSha256: assembly.freezeManifestSha256,
      complete: flags['re-promote'] === true,
    });
  }
  await updateEvidence(context, 'activation', 'activation', checkpoint);
  return checkpoint;
  /* c8 ignore stop */
};

const detectStackDrift = async (context, stackName, { expectedStackId } = {}) => {
  const boundStackId = expectedStackId ?? describeStack(context, stackName).stackId;
  if (typeof boundStackId !== 'string' || !boundStackId.includes(`:stack/${stackName}/`)) {
    fail('E7_DRIFT_DETECTION_STACK_ID_INVALID');
  }
  const started = awsJson(
    context,
    ['cloudformation', 'detect-stack-drift', '--stack-name', boundStackId],
    'E7_DRIFT_DETECTION_START_FAILED',
  );
  const detectionId = started?.StackDriftDetectionId;
  if (!DRIFT_DETECTION_ID.test(detectionId ?? '')) {
    fail('E7_DRIFT_DETECTION_ID_INVALID');
  }
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const status = awsJson(
      context,
      [
        'cloudformation',
        'describe-stack-drift-detection-status',
        '--stack-drift-detection-id',
        detectionId,
      ],
      'E7_DRIFT_DETECTION_STATUS_FAILED',
    );
    if (
      status?.StackDriftDetectionId !== detectionId ||
      status?.StackId !== boundStackId ||
      !['DETECTION_IN_PROGRESS', 'DETECTION_COMPLETE', 'DETECTION_FAILED'].includes(
        status?.DetectionStatus,
      )
    ) {
      fail('E7_DRIFT_DETECTION_STATUS_INVALID');
    }
    if (status.DetectionStatus === 'DETECTION_FAILED') {
      fail('E7_DRIFT_DETECTION_FAILED');
    }
    if (status.DetectionStatus === 'DETECTION_COMPLETE') {
      if (status.StackDriftStatus !== 'IN_SYNC' || status.DriftedStackResourceCount !== 0) {
        fail('E7_CRITICAL_DRIFT_DETECTED');
      }
      return {
        detectionIdSha256: sha256(detectionId),
        driftedResourceCount: 0,
        stackIdSha256: sha256(status.StackId),
        stackName,
        status: 'IN_SYNC',
      };
    }
    await delay(5_000);
  }
  fail('E7_DRIFT_DETECTION_TIMEOUT');
};

export const verifyDrift = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const recoveryIntentFilename = flags['reconciliation-intent'];
  const recoveryActorFilename = flags['reconciliation-recovery-actor'];
  const hasRecoveryIntent = Object.hasOwn(flags, 'reconciliation-intent');
  const hasRecoveryActor = Object.hasOwn(flags, 'reconciliation-recovery-actor');
  const recoveryAware = hasRecoveryIntent && hasRecoveryActor;
  if (
    hasRecoveryIntent !== hasRecoveryActor ||
    (recoveryAware &&
      (typeof recoveryIntentFilename !== 'string' ||
        recoveryIntentFilename === '' ||
        typeof recoveryActorFilename !== 'string' ||
        recoveryActorFilename === ''))
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_DRIFT_FLAGS_INVALID');
  }
  let context;
  if (recoveryAware) {
    if (flags.scope !== 'full') {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_DRIFT_SCOPE_INVALID');
    }
    const recoveryIntent = readRecoveryBoundJsonDocument(
      recoveryIntentFilename,
      'E7_RELEASE_RECONCILIATION_RECOVERY_INTENT_INVALID',
    ).value;
    const recoveryActor = readRecoveryBoundJsonDocument(
      recoveryActorFilename,
      'E7_RELEASE_RECONCILIATION_RECOVERY_ACTOR_INVALID',
    ).value;
    context = loadReleaseReconciliationRecoveryOperationContext({
      capability: 'read',
      flags,
      recoveryActor,
      recoveryIntent,
      executor,
      environmentVariables,
      now,
    });
    validateRecoveryCallerIdentity(context, 'read');
  } else {
    context = loadOperationContext({
      capability: 'read',
      scope: flags.scope,
      flags,
      executor,
      environmentVariables,
      now,
      requireAws: true,
    });
  }
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  if (context.scope === 'prerelease') fail('E7_DRIFT_FULL_SCOPE_REQUIRED');
  releaseModeForFlags(context.scope, flags);
  const previousManifest = validateVersionedMutationTarget(context, flags);
  verifyPreviousVersionedResourcesAws(context, previousManifest);
  if (recoveryAware) {
    validateRecoveryCallerIdentity(context, 'read');
  } else {
    revalidateAwsIdentity(context);
  }
  for (const suffix of ['api', 'web']) {
    if (publicationStateForStack(context, suffix).publicationState !== 'ENABLED') {
      fail('E7_DRIFT_VERIFICATION_REQUIRES_ACTIVE_RELEASE');
    }
  }
  const results = await Promise.all(
    context.stacks.map((stackName) => detectStackDrift(context, stackName)),
  );
  const checkpoint = {
    decision: 'PASS',
    releaseMode: 'VERSIONED_UPDATE',
    updateReleaseSupported: true,
    previousReleaseManifestSha256: previousManifest.manifestSha256,
    assemblySha256: assembly.assemblySha256,
    freezeManifestSha256: assembly.freezeManifestSha256,
    publicationManagedByCloudFormation: true,
    checked: results.length,
    criticalCount: 0,
    stacks: results,
  };
  validateStage7DriftCheckpoint(checkpoint, {
    config: context.config,
    manifestSha256: assembly.freezeManifestSha256,
    assemblySha256: assembly.assemblySha256,
  });
  await updateEvidence(context, 'drift', 'drift', checkpoint);
  return checkpoint;
};

export const rollbackApi = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const context = loadOperationContext({
    capability: 'rollback',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const record = readRecord(context, 'rollback-api', flags.record);
  const initialRelease = rollbackReleaseMode(flags, record, 'to-disabled') === 'INITIAL';
  const identity = revalidateAwsIdentity(context);
  if (initialRelease) {
    if (!record.initialDisableAvailable || record.previous !== null) {
      fail('E7_INITIAL_API_ROLLBACK_RECORD_INVALID');
    }
    validateOriginalStackTemplate(context, stackFor(context, 'api'), record.templateSha256);
    const publication = await transitionInitialRollbackPublication({
      context,
      suffix: 'api',
      record,
    });
    const apiStack = publicationStateForStack(context, 'api');
    const api = getHttpApi(context, apiStack.state.outputs.HttpApiId);
    const schedule = getSchedule(context);
    const mappings =
      context.config.domain.mode === 'CUSTOM_AUTHORIZED'
        ? getApiMappings(context, context.config.domain.apiHostname)
        : [];
    if (
      api.DisableExecuteApiEndpoint !== true ||
      schedule.State !== 'DISABLED' ||
      mappings.length !== 0
    ) {
      fail('E7_INITIAL_API_ROLLBACK_STATE_NOT_APPLIED');
    }
    const checkpoint = {
      decision: 'INITIAL_RELEASE_DISABLED_REQUIRES_UNAVAILABLE_SMOKE',
      identity,
      releaseMode: 'INITIAL',
      publication,
      schedulerState: schedule.State,
      aliasesChanged: false,
      dataFactsChanged: false,
      stacksDeleted: 0,
    };
    await updateEvidence(context, 'rollback', 'apiRollback', checkpoint);
    return checkpoint;
  }
  fail('E7_UPDATE_RELEASE_NOT_SUPPORTED');
};

export const rollbackWeb = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const context = loadOperationContext({
    capability: 'rollback',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  const record = readRecord(context, 'rollback-web', flags.record);
  const apiRecord = readRecord(context, 'rollback-api');
  const initialRelease = rollbackReleaseMode(flags, record, 'to-unpublished') === 'INITIAL';
  revalidateAwsIdentity(context);
  if (initialRelease) {
    if (
      !record.initialUnpublishAvailable ||
      !Array.isArray(record.previous) ||
      record.previous.length !== 0 ||
      !apiRecord.initialDisableAvailable ||
      apiRecord.previous !== null ||
      apiRecord.releaseMode !== 'INITIAL'
    ) {
      fail('E7_INITIAL_WEB_ROLLBACK_RECORD_INVALID');
    }
    validateOriginalStackTemplate(context, stackFor(context, 'api'), apiRecord.templateSha256);
    validateOriginalStackTemplate(context, stackFor(context, 'web'), record.templateSha256);
    const apiStack = publicationStateForStack(context, 'api');
    if (apiStack.publicationState !== 'DISABLED' || getSchedule(context).State !== 'DISABLED') {
      fail('E7_INITIAL_API_ROLLBACK_REQUIRED');
    }
    const rollbackEvidence = rollbackEvidenceSource(context);
    const { apiRollback, publication } = await transitionInitialWebRollback({
      context,
      record,
      apiRecord,
      apiStack,
      rollbackEvidence,
    });
    const distribution = getDistributionConfig(context, record.publication.distributionId);
    if (distribution.DistributionConfig.Enabled !== false) {
      fail('E7_INITIAL_WEB_ROLLBACK_STATE_NOT_APPLIED');
    }
    const rollbackInfrastructure = {
      decision: 'INITIAL_RELEASE_DISABLED_AND_UNPUBLISHED_REQUIRES_SMOKE',
      releaseMode: 'INITIAL',
      updateReleaseSupported: false,
      publication: {
        managedByCloudFormation: true,
        apiStack: apiRollback.publication,
        webStack: publication,
        scheduler: {
          controlledBy: 'PublicationState',
          stackName: stackFor(context, 'api'),
          state: 'DISABLED',
        },
      },
      aliasesChanged: false,
      objectsChanged: false,
      dataFactsChanged: false,
      stacksDeleted: 0,
      secretDeleted: false,
    };
    validateStage7InitialRollbackCheckpoint(rollbackInfrastructure, {
      config: context.config,
    });
    await updateEvidence(context, 'rollback', 'rollbackInfrastructure', rollbackInfrastructure);
    return rollbackInfrastructure;
  }
  fail('E7_UPDATE_RELEASE_NOT_SUPPORTED');
};

export const cleanupConfirmation = (config) =>
  sha256(
    [
      config.authorization.id,
      config.environment,
      config.cleanup.expiresAtUtc,
      'DESTROY_EPHEMERAL_STACKS',
    ].join('\0'),
  );

const residualResources = (context) => {
  const response = awsJson(
    context,
    [
      'resourcegroupstaggingapi',
      'get-resources',
      '--tag-filters',
      `Key=Environment,Values=${context.config.environment}`,
      'Key=Project,Values=checkout',
    ],
    'E7_CLEANUP_RESIDUAL_SCAN_FAILED',
  );
  const resources = response?.ResourceTagMappingList ?? [];
  if (
    !Array.isArray(resources) ||
    (typeof response?.PaginationToken === 'string' && response.PaginationToken !== '')
  ) {
    fail('E7_CLEANUP_RESIDUAL_SCAN_INVALID');
  }
  const authorizedExternal = new Set(
    [
      ...context.config.credentialReferences,
      context.config.domain.webCertificateArn,
      context.config.domain.apiCertificateArn,
      context.config.domain.hostedZoneId === null
        ? null
        : `arn:aws:route53:::hostedzone/${context.config.domain.hostedZoneId}`,
    ].filter((value) => typeof value === 'string'),
  );
  const ownedResiduals = resources.filter(
    ({ ResourceARN }) => !authorizedExternal.has(ResourceARN),
  );
  return {
    count: ownedResiduals.length,
    preservedExternalReferences: resources.length - ownedResiduals.length,
    resourceTypeHashes: ownedResiduals.map(({ ResourceARN }) => {
      const arn = String(ResourceARN ?? '');
      const type = arn
        .split(':')
        .slice(0, 6)
        .join(':')
        .replace(/[0-9]{12}/u, '[ACCOUNT]');
      return sha256(type);
    }),
  };
};

const cloudFormationExecutionRoleArn = (config) =>
  `arn:aws:iam::${config.aws.accountId}:role/cdk-hnb659fds-cfn-exec-role-${config.aws.accountId}-${config.aws.region}`;

const expectedReleaseStackTags = (context) => ({
  Project: 'checkout',
  ManagedBy: 'cdk',
  Environment: context.config.environment,
  CandidateSha: context.identity.candidateSha,
  ReleaseId: context.identity.releaseId,
  ExpiresOn: context.config.cleanup.expiresAtUtc.slice(0, 10),
  CleanupExpiresAtUtc: context.config.cleanup.expiresAtUtc,
  CostCenter: 'technical-assessment',
  DataClass: 'synthetic-only',
  Owner: context.config.authorization.ownerAlias,
  PaymentMode: 'sandbox',
});

const validateCleanupStackState = (context, suffix, state, { expectedFingerprint } = {}) => {
  const stackName = stackFor(context, suffix);
  if (!state?.exists) return null;
  const fingerprint = stackStateFingerprint(stackName, state);
  if (
    !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus ?? '') ||
    state.terminationProtection !== false ||
    typeof state.stackId !== 'string' ||
    !state.stackId.includes(`:stack/${stackName}/`) ||
    state.outputs?.CandidateSha !== context.identity.candidateSha ||
    state.outputs?.ReleaseId !== context.identity.releaseId ||
    JSON.stringify(
      Object.entries(state.tags ?? {}).toSorted(([left], [right]) => left.localeCompare(right)),
    ) !==
      JSON.stringify(
        Object.entries(expectedReleaseStackTags(context)).toSorted(([left], [right]) =>
          left.localeCompare(right),
        ),
      ) ||
    (expectedFingerprint !== undefined && fingerprint !== expectedFingerprint)
  ) {
    fail('E7_CLEANUP_STACK_IDENTITY_INVALID');
  }
  return { fingerprint, stackId: state.stackId, stackName };
};

const refreshCleanupStackState = (
  context,
  suffix,
  state,
  initial,
  { validateTemplate = validateOriginalStackTemplate } = {},
) => {
  const validated = validateCleanupStackState(context, suffix, state);
  if (validated?.stackId !== initial?.stackId) fail('E7_CLEANUP_STACK_IDENTITY_INVALID');
  validateTemplate(context, initial.stackId, initial.templateSha256);
  return {
    ...validated,
    stackId: initial.stackId,
    templateSha256: initial.templateSha256,
  };
};

const destroyCleanupStackSet = (context, states, validatedStates, destroy = destroyStack) =>
  [...STACK_SUFFIXES]
    .reverse()
    .map((suffix) =>
      states.get(suffix)?.exists
        ? destroy(context, suffix, validatedStates.get(suffix))
        : stackFor(context, suffix),
    );

const destroyStack = (context, suffix, expected) => {
  const stackName = stackFor(context, suffix);
  const current = describeStack(context, stackName, { allowMissing: true });
  const validated = validateCleanupStackState(context, suffix, current, {
    expectedFingerprint: expected.fingerprint,
  });
  if (validated?.stackId !== expected.stackId) fail('E7_CLEANUP_STACK_IDENTITY_INVALID');
  validateOriginalStackTemplate(context, expected.stackId, expected.templateSha256);
  aws(
    context,
    [
      'cloudformation',
      'delete-stack',
      '--stack-name',
      expected.stackId,
      '--role-arn',
      cloudFormationExecutionRoleArn(context.config),
    ],
    `E7_CLOUDFORMATION_DELETE_${suffix.toUpperCase()}_FAILED`,
  );
  aws(
    context,
    ['cloudformation', 'wait', 'stack-delete-complete', '--stack-name', expected.stackId],
    `E7_CLOUDFORMATION_DELETE_WAIT_${suffix.toUpperCase()}_FAILED`,
  );
  const state = describeStack(context, stackName, { allowMissing: true });
  if (state.exists) fail('E7_CLEANUP_STACK_STILL_EXISTS');
  return stackName;
};

const capturePrereleaseExpiryStackInventory = (context) => {
  const requiredTags = {
    CandidateSha: context.identity.candidateSha,
    ReleaseId: context.identity.releaseId,
    Environment: context.config.environment,
    ExpiresOn: context.config.cleanup.expiresAtUtc.slice(0, 10),
    CleanupExpiresAtUtc: context.config.cleanup.expiresAtUtc,
  };
  return STACK_SUFFIXES.map((suffix) => {
    const stackName = stackFor(context, suffix);
    const state = describeStack(context, stackName);
    if (
      !state.exists ||
      !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus) ||
      state.outputs.CandidateSha !== context.identity.candidateSha ||
      state.outputs.ReleaseId !== context.identity.releaseId ||
      Object.entries(requiredTags).some(([key, value]) => state.tags[key] !== value)
    ) {
      fail('E7_PRERELEASE_EXPIRY_STACK_INVENTORY_INVALID');
    }
    return {
      stackName,
      stackIdSha256: sha256(state.stackId),
      stackStatus: state.stackStatus,
      outputsIdentity: {
        CandidateSha: state.outputs.CandidateSha,
        ReleaseId: state.outputs.ReleaseId,
      },
      requiredTags,
      requiredTagsSha256: objectSha256(requiredTags),
    };
  });
};

export const cleanupRelease = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  if (flags.scope !== 'prerelease' || flags['ephemeral-only'] !== true) {
    fail('E7_CLEANUP_EPHEMERAL_SCOPE_REQUIRED');
  }
  if (flags['register-expiry'] === true) {
    if (flags.execute || flags['enforce-expiry'] || flags.confirm !== undefined) {
      fail('E7_CLEANUP_REGISTRATION_FLAGS_INVALID');
    }
    const prereleaseSafety = await validatePrereleaseMutationSafety({
      flags,
      environmentVariables,
      now,
      authorityPhase: 'register-expiry',
      deploymentPhase: 'before-expiry',
    });
    const context = loadOperationContext({
      capability: 'deploy',
      scope: flags.scope,
      flags,
      executor,
      environmentVariables,
      now,
      requireAws: true,
    });
    const identity = revalidateAwsIdentity(context);
    const stackInventory = capturePrereleaseExpiryStackInventory(context);
    const approvedDeploymentCheckpointSha256 = prereleaseApprovedDeploymentCheckpointSha256(
      prereleaseSafety.deployment,
    );
    const checkpoint = {
      decision: 'EXPIRY_REGISTERED',
      identity,
      expiresAtUtc: context.config.cleanup.expiresAtUtc,
      cleanupOwnerAlias: context.config.cleanup.ownerAlias,
      safetyReadinessSha256: prereleaseSafety.readiness.readinessSha256,
      durableCleanupReadinessSha256: objectSha256(prereleaseSafety.readiness.durableCleanup),
      ...watchdogLiveAuthorityCheckpoint(prereleaseSafety),
      approvedDeploymentCheckpointSha256,
      expectedStackNamesSha256: objectSha256(context.config.authorization.stacks),
      stackInventory,
      stackInventorySha256: objectSha256(stackInventory),
      verifiedStackCount: stackInventory.length,
      liveStackTagsVerified: true,
      liveStackOutputsVerified: true,
      externalRequests: 5,
      mutationsPerformed: 0,
      immediateCleanupStillRequired: true,
      bootstrapPreserved: true,
      previousReleasePreserved: true,
    };
    await updateEvidence(context, 'expiry-registration', 'expiryRegistration', checkpoint);
    await finalizePrereleaseDeploymentEvidence(context);
    return checkpoint;
  }
  if (
    flags.execute !== true ||
    flags.app === undefined ||
    flags.manifest === undefined ||
    typeof flags.confirm !== 'string'
  ) {
    fail('E7_CLEANUP_EXECUTION_FLAGS_REQUIRED');
  }
  const context = loadOperationContext({
    capability: 'cleanup',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
    windowMode: flags['enforce-expiry'] ? 'expired-cleanup' : 'release',
  });
  const expectedConfirmation = cleanupConfirmation(context.config);
  if (flags.confirm !== expectedConfirmation) fail('E7_CLEANUP_CONFIRMATION_MISMATCH');
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  const identity = revalidateAwsIdentity(context);
  const destroyedStacks = [];
  try {
    const states = new Map(
      STACK_SUFFIXES.map((suffix) => [
        suffix,
        describeStack(context, stackFor(context, suffix), { allowMissing: true }),
      ]),
    );
    const validatedStates = new Map(
      STACK_SUFFIXES.map((suffix) => [
        suffix,
        validateCleanupStackState(context, suffix, states.get(suffix)),
      ]),
    );
    for (const suffix of STACK_SUFFIXES) {
      const validated = validatedStates.get(suffix);
      if (validated !== null) {
        const templateSha256 = assemblyTemplateSha256(assembly, validated.stackName);
        validateOriginalStackTemplate(context, validated.stackName, templateSha256);
        validatedStates.set(suffix, { ...validated, templateSha256 });
      }
    }
    const web = states.get('web');
    if (web.exists) {
      const initial = validatedStates.get('web');
      updatePublicationStack(context, 'web', 'DISABLED', {
        expectedBeforeStateSha256: initial.fingerprint,
        expectedTemplateSha256: initial.templateSha256,
      });
      const state = describeStack(context, stackFor(context, 'web'));
      validatedStates.set('web', refreshCleanupStackState(context, 'web', state, initial));
    }
    const api = states.get('api');
    if (api.exists) {
      const initial = validatedStates.get('api');
      updatePublicationStack(context, 'api', 'DISABLED', {
        expectedBeforeStateSha256: initial.fingerprint,
        expectedTemplateSha256: initial.templateSha256,
      });
      const state = describeStack(context, stackFor(context, 'api'));
      validatedStates.set('api', refreshCleanupStackState(context, 'api', state, initial));
    }
    destroyedStacks.push(...destroyCleanupStackSet(context, states, validatedStates));
    const residual = residualResources(context);
    const checkpoint = {
      decision: residual.count === 0 ? 'PASS' : 'FAIL_RESIDUAL_RESOURCES',
      identity,
      assemblySha256: assembly.assemblySha256,
      confirmationSha256: flags.confirm,
      enforceExpiry: flags['enforce-expiry'] === true,
      destroyedStacks,
      destructionOrder: [...expectedStacks(context.config.environment)].reverse(),
      bootstrapPreserved: true,
      previousReleasePreserved: true,
      retainedDataDeleted: false,
      residual,
    };
    if (residual.count === 0) {
      validateStage7PrereleaseCleanupCheckpoint(checkpoint, {
        config: context.config,
        assemblySha256: assembly.assemblySha256,
        enforceExpiry: flags['enforce-expiry'] === true,
      });
    }
    const cleanupEvidence = await updateEvidence(context, 'cleanup', 'cleanup', checkpoint);
    if (residual.count !== 0) fail('E7_CLEANUP_RESIDUAL_RESOURCES');
    const finalized = {
      ...cleanupEvidence,
      status: 'PASS',
      ephemeralResourcesRemaining: 0,
      bootstrapPreserved: true,
      retainedDataDeleted: false,
    };
    await writeSanitizedJsonAtomic(
      evidenceTarget(context, 'cleanup'),
      'stage7-prerelease-cleanup.json',
      finalized,
    );
    return checkpoint;
  } catch (error) {
    const code = error instanceof Stage7AwsError ? error.code : 'E7_CLEANUP_UNEXPECTED_FAILURE';
    await updateEvidence(context, 'cleanup', 'cleanupFailure', {
      decision: 'FAIL',
      failureCode: code,
      identity,
      assemblySha256: assembly.assemblySha256,
      confirmationSha256: flags.confirm,
      enforceExpiry: flags['enforce-expiry'] === true,
      destroyedStacks,
      bootstrapPreserved: true,
      previousReleasePreserved: true,
    });
    throw error;
  }
};

const expectCode = (callback, code) => {
  assert.throws(callback, (error) => error instanceof Stage7Error && error.code === code, code);
};

const selfTestConfig = (now) => {
  const accountId = ['123456', '789012'].join('');
  const environment = 'assessment-prerelease-ops-canary';
  const role = (name) => `arn:aws:iam::${accountId}:role/checkout/${name}`;
  const iso = (milliseconds) => new Date(now.getTime() + milliseconds).toISOString();
  const destination = [['release', 'alerts'].join('-'), ['example', 'invalid'].join('.')].join('@');
  return {
    config: {
      schemaVersion: 1,
      stage: 7,
      environment,
      authorization: {
        id: 'AUTH-E7-OPS-CANARY',
        status: 'APPROVED',
        scope: 'EPHEMERAL_PRERELEASE',
        ownerAlias: 'release-owner',
        approvedAtUtc: iso(-60 * 60 * 1000),
        expiresAtUtc: iso(8 * 60 * 60 * 1000),
        stacks: expectedStacks(environment),
        sandboxIncluded: true,
        destructiveActionsAllowed: false,
        communicationChannelAlias: 'release-channel',
        abortCriteria: [
          'ACCOUNT_MISMATCH',
          'REGION_MISMATCH',
          'SECRET_EXPOSURE',
          'PRODUCTION_PROVIDER',
          'STATEFUL_REPLACEMENT',
          'SMOKE_FAILURE',
          'ROLLBACK_FAILURE',
          'BUDGET_BREACH',
        ],
        rollbackOwnerAlias: 'rollback-owner',
      },
      aws: {
        accountId,
        region: 'us-east-1',
        roles: {
          readRoleArn: role('release-read'),
          deployRoleArn: role('release-deploy'),
          rollbackRoleArn: role('release-rollback'),
          cleanupRoleArn: role('release-cleanup'),
          baselineRoleArn: role('release-baseline'),
        },
        sessionMode: 'OIDC',
      },
      window: {
        startsAtUtc: iso(-5 * 60 * 1000),
        endsAtUtc: iso(2 * 60 * 60 * 1000),
      },
      budget: {
        maxUsd: 10,
        warningUsd: [5, 8],
        alertOwnerAlias: 'cost-owner',
        alertChannelAlias: 'cost-alerts',
        alertDestinationSha256: sha256(destination),
      },
      domain: {
        mode: 'CUSTOM_AUTHORIZED',
        hostname: 'preview.example.test',
        apiHostname: 'api-preview.example.test',
        hostedZoneId: 'Z1234567890ABC',
        webCertificateArn:
          'arn:aws:acm:us-east-1:123456789012:certificate/11111111-1111-1111-1111-111111111111',
        apiCertificateArn:
          'arn:aws:acm:us-east-1:123456789012:certificate/22222222-2222-2222-2222-222222222222',
        dnsIncluded: true,
      },
      cleanup: {
        ownerAlias: 'cleanup-owner',
        expiresAtUtc: iso(3 * 60 * 60 * 1000),
        preserveBootstrap: true,
        preservePreviousRelease: true,
      },
      prereleaseAccess: {
        mode: 'CLOUDFRONT_SIGNED_COOKIE',
        keyGroupId: 'c2f83d9a-4f1e-4d7a-8b21-6c9d3e5f7a10',
        publicKeyId: 'K2STAGE7CHECKOUT',
        originTokenSecretArn: [
          'arn',
          'aws',
          'secretsmanager',
          'us-east-1',
          accountId,
          'secret:e7/root',
        ].join(':'),
        originTokenSecretVersionId: 'a'.repeat(32),
        rotationDuringWindow: 'FORBIDDEN',
      },
      credentialReferences: [
        ['arn', 'aws', 'secretsmanager', 'us-east-1', accountId, 'secret:e7/root'].join(':'),
      ],
      containsSensitiveData: false,
    },
    destination,
  };
};

const selfTestInitialDataPublicationTemplate = (config) => {
  const catalogExportName = `checkout-${config.environment}-data:catalog-table-name`;
  const checkoutExportName = `checkout-${config.environment}-data:checkout-table-name`;
  return {
    Resources: {
      CatalogTable: {
        Type: 'AWS::DynamoDB::Table',
        Properties: { TableName: `checkout-${config.environment}-catalog` },
      },
      CheckoutTable: {
        Type: 'AWS::DynamoDB::Table',
        Properties: { TableName: `checkout-${config.environment}-checkout` },
      },
    },
    Outputs: {
      CatalogTableName: { Value: { Ref: 'CatalogTable' } },
      CheckoutTableName: { Value: { Ref: 'CheckoutTable' } },
      CatalogTableExport: {
        Value: { Ref: 'CatalogTable' },
        Export: { Name: catalogExportName },
      },
      CheckoutTableExport: {
        Value: { Ref: 'CheckoutTable' },
        Export: { Name: checkoutExportName },
      },
    },
  };
};

const selfTestInitialWebPublicationTemplate = (context) => {
  const { config } = context;
  const customDomain = config.domain.mode === 'CUSTOM_AUTHORIZED';
  const distributionLogicalId = 'WebDistribution';
  const bucketLogicalId = 'WebBucket';
  const apiOriginDomain = customDomain
    ? config.domain.apiHostname
    : {
        'Fn::Join': [
          '',
          [{ Ref: 'HttpApi' }, `.execute-api.${config.aws.region}.`, { Ref: 'AWS::URLSuffix' }],
        ],
      };
  const baseUrl = customDomain
    ? `https://${config.domain.hostname}`
    : {
        'Fn::Join': ['', ['https://', { 'Fn::GetAtt': [distributionLogicalId, 'DomainName'] }]],
      };
  const outputUrl = (suffix) =>
    customDomain
      ? `${baseUrl}${suffix}`
      : {
          'Fn::Join': [
            '',
            [
              'https://',
              { 'Fn::GetAtt': [distributionLogicalId, 'DomainName'] },
              ...(suffix === '' ? [] : [suffix]),
            ],
          ],
        };
  const keyGroups = [config.prereleaseAccess.keyGroupId];
  const webOriginId = 'WebOrigin';
  const apiOriginId = 'ApiOrigin';
  const aliasTarget = {
    DNSName: { 'Fn::GetAtt': [distributionLogicalId, 'DomainName'] },
    HostedZoneId: {
      'Fn::FindInMap': [
        'AWSCloudFrontPartitionHostedZoneIdMap',
        { Ref: 'AWS::Partition' },
        'zoneId',
      ],
    },
  };
  const resources = {
    [bucketLogicalId]: {
      Type: 'AWS::S3::Bucket',
      Properties: {
        BucketEncryption: {
          ServerSideEncryptionConfiguration: [
            { ServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } },
          ],
        },
        OwnershipControls: { Rules: [{ ObjectOwnership: 'BucketOwnerEnforced' }] },
        PublicAccessBlockConfiguration: {
          BlockPublicAcls: true,
          BlockPublicPolicy: true,
          IgnorePublicAcls: true,
          RestrictPublicBuckets: true,
        },
        VersioningConfiguration: { Status: 'Enabled' },
      },
    },
    WebBucketPolicy: {
      Type: 'AWS::S3::BucketPolicy',
      Properties: {
        Bucket: { Ref: bucketLogicalId },
        PolicyDocument: {
          Statement: [
            {
              Action: 's3:*',
              Condition: { Bool: { 'aws:SecureTransport': 'false' } },
              Effect: 'Deny',
              Principal: { AWS: '*' },
              Resource: [
                { 'Fn::GetAtt': [bucketLogicalId, 'Arn'] },
                { 'Fn::Join': ['', [{ 'Fn::GetAtt': [bucketLogicalId, 'Arn'] }, '/*']] },
              ],
            },
            {
              Action: ['s3:PutBucketPolicy', 's3:GetBucket*', 's3:List*', 's3:DeleteObject*'],
              Effect: 'Allow',
              Principal: { AWS: { 'Fn::GetAtt': ['AutoDeleteRole', 'Arn'] } },
              Resource: [
                { 'Fn::GetAtt': [bucketLogicalId, 'Arn'] },
                { 'Fn::Join': ['', [{ 'Fn::GetAtt': [bucketLogicalId, 'Arn'] }, '/*']] },
              ],
            },
            {
              Action: 's3:GetObject',
              Condition: {
                StringEquals: {
                  'AWS:SourceArn': {
                    'Fn::Join': [
                      '',
                      [
                        'arn:',
                        { Ref: 'AWS::Partition' },
                        ':cloudfront::',
                        { Ref: 'AWS::AccountId' },
                        ':distribution/',
                        { Ref: distributionLogicalId },
                      ],
                    ],
                  },
                },
              },
              Effect: 'Allow',
              Principal: { Service: 'cloudfront.amazonaws.com' },
              Resource: {
                'Fn::Join': ['', [{ 'Fn::GetAtt': [bucketLogicalId, 'Arn'] }, '/*']],
              },
            },
          ],
          Version: '2012-10-17',
        },
      },
    },
    AutoDeleteRole: { Type: 'AWS::IAM::Role', Properties: {} },
    WebOriginAccessControl: {
      Type: 'AWS::CloudFront::OriginAccessControl',
      Properties: {
        OriginAccessControlConfig: {
          OriginAccessControlOriginType: 's3',
          SigningBehavior: 'always',
          SigningProtocol: 'sigv4',
        },
      },
    },
    SpaRewrite: { Type: 'AWS::CloudFront::Function', Properties: {} },
    DocumentHeaders: { Type: 'AWS::CloudFront::ResponseHeadersPolicy', Properties: {} },
    SecurityHeaders: { Type: 'AWS::CloudFront::ResponseHeadersPolicy', Properties: {} },
    ApiHeaders: { Type: 'AWS::CloudFront::ResponseHeadersPolicy', Properties: {} },
    [distributionLogicalId]: {
      Type: 'AWS::CloudFront::Distribution',
      Properties: {
        DistributionConfig: {
          ...(customDomain ? { Aliases: [config.domain.hostname] } : {}),
          CacheBehaviors: [
            {
              AllowedMethods: ['GET', 'HEAD', 'OPTIONS'],
              CachePolicyId: '658327ea-f89d-4fab-a63d-7e88639e58f6',
              Compress: true,
              PathPattern: 'assets/*',
              ResponseHeadersPolicyId: { Ref: 'SecurityHeaders' },
              TargetOriginId: webOriginId,
              TrustedKeyGroups: keyGroups,
              ViewerProtocolPolicy: 'redirect-to-https',
            },
            {
              AllowedMethods: ['GET', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'POST', 'DELETE'],
              CachePolicyId: '4135ea2d-6df8-44a3-9df3-4b5a84be39ad',
              Compress: true,
              OriginRequestPolicyId: 'b689b0a8-53d0-40ab-baf2-68738e2966ac',
              PathPattern: 'api/*',
              ResponseHeadersPolicyId: { Ref: 'ApiHeaders' },
              TargetOriginId: apiOriginId,
              TrustedKeyGroups: keyGroups,
              ViewerProtocolPolicy: 'redirect-to-https',
            },
          ],
          DefaultCacheBehavior: {
            CachePolicyId: '4135ea2d-6df8-44a3-9df3-4b5a84be39ad',
            Compress: true,
            FunctionAssociations: [
              {
                EventType: 'viewer-request',
                FunctionARN: { 'Fn::GetAtt': ['SpaRewrite', 'FunctionARN'] },
              },
            ],
            ResponseHeadersPolicyId: { Ref: 'DocumentHeaders' },
            TargetOriginId: webOriginId,
            TrustedKeyGroups: keyGroups,
            ViewerProtocolPolicy: 'redirect-to-https',
          },
          DefaultRootObject: 'index.html',
          Enabled: { 'Fn::If': ['PublicationEnabled', true, false] },
          HttpVersion: 'http2and3',
          Origins: [
            {
              DomainName: { 'Fn::GetAtt': [bucketLogicalId, 'RegionalDomainName'] },
              Id: webOriginId,
              OriginAccessControlId: { 'Fn::GetAtt': ['WebOriginAccessControl', 'Id'] },
              S3OriginConfig: { OriginAccessIdentity: '' },
            },
            {
              CustomOriginConfig: {
                OriginProtocolPolicy: 'https-only',
                OriginSSLProtocols: ['TLSv1.2'],
              },
              DomainName: apiOriginDomain,
              Id: apiOriginId,
              OriginCustomHeaders: [
                {
                  HeaderName: 'x-stage7-origin-verify',
                  HeaderValue: `{{resolve:secretsmanager:${runtimeSecretReference(config)}:SecretString:prereleaseOriginToken::${config.prereleaseAccess.originTokenSecretVersionId}}}`,
                },
              ],
            },
          ],
          PriceClass: 'PriceClass_100',
          ViewerCertificate: customDomain
            ? {
                AcmCertificateArn: config.domain.webCertificateArn,
                MinimumProtocolVersion: 'TLSv1.2_2021',
                SslSupportMethod: 'sni-only',
              }
            : { CloudFrontDefaultCertificate: true },
        },
      },
    },
    PublicOriginParameter: {
      Type: 'AWS::SSM::Parameter',
      Properties: {
        Name: `/checkout-${config.environment}/public-origin`,
        Type: 'String',
        Value: structuredClone(baseUrl),
      },
    },
  };
  if (customDomain) {
    resources.WebAliasA = {
      Type: 'AWS::Route53::RecordSet',
      Properties: {
        AliasTarget: structuredClone(aliasTarget),
        HostedZoneId: config.domain.hostedZoneId,
        Name: `${config.domain.hostname}.`,
        Type: 'A',
      },
    };
    resources.WebAliasAAAA = {
      Type: 'AWS::Route53::RecordSet',
      Properties: {
        AliasTarget: structuredClone(aliasTarget),
        HostedZoneId: config.domain.hostedZoneId,
        Name: `${config.domain.hostname}.`,
        Type: 'AAAA',
      },
    };
  }
  return {
    Parameters: {
      PublicationState: {
        Type: 'String',
        Default: 'DISABLED',
        AllowedValues: ['DISABLED', 'ENABLED'],
        Description:
          'CloudFormation-managed publication state; changed only by audited activation/rollback',
      },
    },
    Conditions: {
      PublicationEnabled: { 'Fn::Equals': [{ Ref: 'PublicationState' }, 'ENABLED'] },
    },
    Resources: resources,
    Outputs: {
      ApplicationUrl: { Value: outputUrl('') },
      ApiUrl: { Value: outputUrl('/api') },
      ApiDocsUrl: { Value: outputUrl('/api/docs') },
      HealthUrl: { Value: outputUrl('/api/health/ready') },
      WebBucketName: { Value: { Ref: bucketLogicalId } },
      DistributionId: { Value: { Ref: distributionLogicalId } },
      PublicOriginParameterName: {
        Value: `/checkout-${config.environment}/public-origin`,
      },
      WebPublicationStatus: {
        Value: { 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] },
      },
    },
  };
};

const selfTestInitialApiPublicationTemplate = (context) => {
  const { config, identity } = context;
  const dataTemplate = selfTestInitialDataPublicationTemplate(config);
  const catalogImport = {
    'Fn::ImportValue': dataTemplate.Outputs.CatalogTableExport.Export.Name,
  };
  const checkoutImport = {
    'Fn::ImportValue': dataTemplate.Outputs.CheckoutTableExport.Export.Name,
  };
  const domainLogicalId = 'ApiCustomDomain';
  const aliasTarget = {
    DNSName: { 'Fn::GetAtt': [domainLogicalId, 'RegionalDomainName'] },
    HostedZoneId: { 'Fn::GetAtt': [domainLogicalId, 'RegionalHostedZoneId'] },
  };
  const runtimeFunction = (id) => ({
    Type: 'AWS::Lambda::Function',
    Properties: {
      Architectures: ['arm64'],
      FunctionName: id,
      Handler: 'index.handler',
      Runtime: 'nodejs24.x',
      Environment: {
        Variables: {
          ALLOWED_ORIGIN_PARAMETER_NAME: `/checkout-${config.environment}/public-origin`,
          APP_ENV: 'assessment',
          AUTO_SEED_CATALOG: 'false',
          PAYMENT_ADAPTER: 'sandbox',
          DATA_ADAPTER: 'dynamodb',
          CANDIDATE_SHA: identity.candidateSha,
          CATALOG_TABLE_NAME: structuredClone(catalogImport),
          CHECKOUT_TABLE_NAME: structuredClone(checkoutImport),
          PAYMENTS_ENABLED: 'true',
          RELEASE_ID: identity.releaseId,
          PUBLIC_ASSET_ORIGIN_PARAMETER_NAME: `/checkout-${config.environment}/public-origin`,
          RUNTIME_SECRET_ARN: runtimeSecretReference(config),
          RUNTIME_SECRET_VERSION_ID: runtimeSecretVersionId(config),
          SANDBOX_AUTHORIZED_UNTIL_UTC: config.authorization.expiresAtUtc,
          PRERELEASE_ACCESS_MODE: 'cloudfront_signed_cookie',
          TOKENIZATION_MODE: 'direct_jwe',
        },
      },
    },
  });
  return {
    Parameters: {
      PublicationState: {
        Type: 'String',
        Default: 'DISABLED',
        AllowedValues: ['DISABLED', 'ENABLED'],
        Description:
          'CloudFormation-managed publication state; changed only by audited activation/rollback',
      },
    },
    Conditions: {
      PublicationEnabled: { 'Fn::Equals': [{ Ref: 'PublicationState' }, 'ENABLED'] },
    },
    Resources: {
      ReconcileSchedule: {
        Type: 'AWS::Scheduler::Schedule',
        Properties: {
          FlexibleTimeWindow: { Mode: 'OFF' },
          Name: `checkout-${config.environment}-reconcile`,
          ScheduleExpression: 'rate(1 minute)',
          State: { 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] },
          Target: {
            Arn: { Ref: 'WorkerAlias' },
            Input: '{"action":"reconcile","mode":"sandbox"}',
            RetryPolicy: { MaximumEventAgeInSeconds: 300, MaximumRetryAttempts: 2 },
            RoleArn: { 'Fn::GetAtt': ['SchedulerRole', 'Arn'] },
          },
        },
      },
      HttpApi: {
        Type: 'AWS::ApiGatewayV2::Api',
        Properties: {
          DisableExecuteApiEndpoint: { 'Fn::If': ['PublicationEnabled', true, true] },
          ProtocolType: 'HTTP',
        },
      },
      ApiIntegration: {
        Type: 'AWS::ApiGatewayV2::Integration',
        Properties: {
          ApiId: { Ref: 'HttpApi' },
          IntegrationType: 'AWS_PROXY',
          IntegrationUri: { Ref: 'ApiAlias' },
          PayloadFormatVersion: '2.0',
        },
      },
      ApiRoute: {
        Type: 'AWS::ApiGatewayV2::Route',
        Properties: {
          ApiId: { Ref: 'HttpApi' },
          AuthorizationType: 'NONE',
          RouteKey: 'ANY /{proxy+}',
          Target: { 'Fn::Join': ['', ['integrations/', { Ref: 'ApiIntegration' }]] },
        },
      },
      ApiIntegrationPermission: {
        Type: 'AWS::Lambda::Permission',
        Properties: {
          Action: 'lambda:InvokeFunction',
          FunctionName: { Ref: 'ApiAlias' },
          Principal: 'apigateway.amazonaws.com',
          SourceArn: {
            'Fn::Join': [
              '',
              [
                'arn:',
                { Ref: 'AWS::Partition' },
                `:execute-api:${config.aws.region}:`,
                { Ref: 'AWS::AccountId' },
                ':',
                { Ref: 'HttpApi' },
                '/*/*/{proxy+}',
              ],
            ],
          },
        },
      },
      HttpApiDefaultStage: {
        Type: 'AWS::ApiGatewayV2::Stage',
        Properties: { ApiId: { Ref: 'HttpApi' }, AutoDeploy: true, StageName: '$default' },
      },
      [domainLogicalId]: {
        Type: 'AWS::ApiGatewayV2::DomainName',
        Properties: {
          DomainName: config.domain.apiHostname,
          DomainNameConfigurations: [
            {
              CertificateArn: config.domain.apiCertificateArn,
              EndpointType: 'REGIONAL',
              SecurityPolicy: 'TLS_1_2',
            },
          ],
        },
      },
      ApiDefaultMapping: {
        Type: 'AWS::ApiGatewayV2::ApiMapping',
        Condition: 'PublicationEnabled',
        Properties: {
          ApiId: { Ref: 'HttpApi' },
          DomainName: { Ref: domainLogicalId },
          Stage: '$default',
        },
      },
      ApiAliasA: {
        Type: 'AWS::Route53::RecordSet',
        Properties: {
          Name: config.domain.apiHostname,
          Type: 'A',
          HostedZoneId: config.domain.hostedZoneId,
          AliasTarget: structuredClone(aliasTarget),
        },
      },
      ApiAliasAAAA: {
        Type: 'AWS::Route53::RecordSet',
        Properties: {
          Name: `${config.domain.apiHostname}.`,
          Type: 'AAAA',
          HostedZoneId: config.domain.hostedZoneId,
          AliasTarget: structuredClone(aliasTarget),
        },
      },
      ApiRuntime: runtimeFunction('api'),
      WorkerRuntime: runtimeFunction('worker'),
      ApiVersion: {
        Type: 'AWS::Lambda::Version',
        Properties: { FunctionName: { Ref: 'ApiRuntime' } },
      },
      WorkerVersion: {
        Type: 'AWS::Lambda::Version',
        Properties: { FunctionName: { Ref: 'WorkerRuntime' } },
      },
      ApiAlias: {
        Type: 'AWS::Lambda::Alias',
        Properties: {
          FunctionName: { Ref: 'ApiRuntime' },
          FunctionVersion: { 'Fn::GetAtt': ['ApiVersion', 'Version'] },
          Name: 'live',
        },
      },
      WorkerAlias: {
        Type: 'AWS::Lambda::Alias',
        Properties: {
          FunctionName: { Ref: 'WorkerRuntime' },
          FunctionVersion: { 'Fn::GetAtt': ['WorkerVersion', 'Version'] },
          Name: 'live',
        },
      },
      SchedulerRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Statement: [
              {
                Action: 'sts:AssumeRole',
                Effect: 'Allow',
                Principal: { Service: 'scheduler.amazonaws.com' },
              },
            ],
            Version: '2012-10-17',
          },
        },
      },
      SchedulerRolePolicy: {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyDocument: {
            Statement: [
              {
                Action: 'lambda:InvokeFunction',
                Effect: 'Allow',
                Resource: { Ref: 'WorkerAlias' },
                Sid: 'InvokeWorkerAlias',
              },
            ],
            Version: '2012-10-17',
          },
          PolicyName: 'SchedulerRolePolicy',
          Roles: [{ Ref: 'SchedulerRole' }],
        },
      },
    },
    Outputs: {
      ApiAliasArn: { Value: { Ref: 'ApiAlias' } },
      ApiFunctionVersion: { Value: { 'Fn::GetAtt': ['ApiVersion', 'Version'] } },
      ApiCustomDomainName: { Value: config.domain.apiHostname },
      ApiOriginUrl: { Value: `https://${config.domain.apiHostname}` },
      HttpApiId: { Value: { Ref: 'HttpApi' } },
      ScheduleName: { Value: `checkout-${config.environment}-reconcile` },
      SchedulerStatus: {
        Value: { 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] },
      },
      WorkerAliasArn: { Value: { Ref: 'WorkerAlias' } },
      WorkerFunctionVersion: { Value: { 'Fn::GetAtt': ['WorkerVersion', 'Version'] } },
      ApiPublicationStatus: {
        Value: { 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] },
      },
    },
  };
};

const selfTestVersionedRollbackAwsLayer = async () => {
  assert.equal(
    decideStage7EmergencyRecoveryFromAwsState({ api: 'DISABLED', web: 'DISABLED' }),
    'NO_ACTION_ACTIVATION_NOT_OBSERVED',
  );
  assert.equal(
    decideStage7EmergencyRecoveryFromAwsState({ api: 'ENABLED', web: 'ENABLED' }),
    'RECOVER_TO_PREVIOUS',
  );
  assert.equal(
    decideStage7EmergencyRecoveryFromAwsState({ api: 'ENABLED', web: 'DISABLED' }),
    'RECOVER_TO_PREVIOUS',
  );
  assert.throws(
    () =>
      decideStage7EmergencyRecoveryFromAwsState({
        api: 'DISABLED',
        web: 'DISABLED',
        activationArtifactObserved: true,
      }),
    (error) =>
      error instanceof Stage7Error &&
      error.code === 'E7_EMERGENCY_RECOVERY_PUBLICATION_STATE_INVALID',
  );
  const accountId = '123456789012';
  const region = 'us-east-1';
  const environment = 'assessment-release';
  const candidateSha = 'a'.repeat(40);
  const previousSha = 'b'.repeat(40);
  const candidateReleaseId = 'rel-20260817-1200-aaaaaaa';
  const previousReleaseId = 'rel-20260816-1200-bbbbbbb';
  const bucketName = 'checkout-release-web-123456789012';
  const distributionId = 'EDFDVBD6EXAMPLE';
  const functionNames = {
    api: 'checkout-assessment-release-api',
    worker: 'checkout-assessment-release-worker',
  };
  const aliases = {
    api: { version: '12', revision: 1 },
    worker: { version: '22', revision: 1 },
  };
  const contents = new Map([
    ['old-index', Buffer.from('<!doctype html><title>old</title>')],
    ['old-config', Buffer.from('{"apiBaseUrl":"/api","release":"old"}')],
    ['new-index', Buffer.from('<!doctype html><title>new</title>')],
    ['new-config', Buffer.from('{"apiBaseUrl":"/api","release":"new"}')],
  ]);
  const etags = new Map([...contents].map(([version]) => [version, `"etag-${version}"`]));
  const active = new Map([
    ['index.html', 'new-index'],
    ['public-config.json', 'new-config'],
  ]);
  const objectFor = (key, versionId) => {
    const body = contents.get(versionId);
    if (body === undefined) throw new Error(`missing canary object ${key}:${versionId}`);
    return {
      key,
      versionId,
      etagSha256: sha256(etags.get(versionId)),
      contentSha256: sha256(body),
      bytes: body.length,
    };
  };
  const previousObjects = [
    objectFor('index.html', 'old-index'),
    objectFor('public-config.json', 'old-config'),
  ];
  const candidateObjects = [
    objectFor('index.html', 'new-index'),
    objectFor('public-config.json', 'new-config'),
  ];
  const previousManifest = createStage7PreviousReleaseManifest({
    schemaVersion: 1,
    stage: 7,
    kind: 'PREVIOUS_APPROVED_RELEASE',
    status: 'APPROVED_IMMUTABLE',
    capturedAtUtc: '2026-08-17T10:30:00.000Z',
    approvedAtUtc: '2026-08-17T10:00:00.000Z',
    environment,
    region,
    previous: {
      candidateSha: previousSha,
      candidateTreeSha: 'c'.repeat(40),
      releaseId: previousReleaseId,
      releaseTag: 'v1.0.0',
      configSha256: '1'.repeat(64),
      freezeManifestSha256: '2'.repeat(64),
      assemblySha256: '3'.repeat(64),
    },
    target: {
      candidateSha,
      candidateTreeSha: 'd'.repeat(40),
      releaseId: candidateReleaseId,
      releaseTag: 'v1.1.0',
      configSha256: '4'.repeat(64),
      freezeManifestSha256: '5'.repeat(64),
      assemblySha256: '6'.repeat(64),
    },
    resources: {
      api: {
        functionName: functionNames.api,
        aliasName: 'live',
        version: '11',
        codeSha256: '7'.repeat(64),
      },
      worker: {
        functionName: functionNames.worker,
        aliasName: 'live',
        version: '21',
        codeSha256: '8'.repeat(64),
      },
      web: {
        bucketName,
        distributionId,
        objects: previousObjects,
        mutableInvalidationPaths: [...VERSIONED_ROLLBACK_INVALIDATION_PATHS],
      },
    },
    compatibility: {
      status: 'PASS',
      schemaStrategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
      dataRollback: 'FORBIDDEN_FORWARD_ONLY',
      apiContractEvidenceSha256: '9'.repeat(64),
      pendingReconciliationEvidenceSha256: 'a'.repeat(64),
      smokeEvidenceSha256: 'b'.repeat(64),
      smokeVerifiedAtUtc: '2026-08-17T10:15:00.000Z',
      providerEgressCapability: STAGE7_PROVIDER_EGRESS_CAPABILITY,
    },
    handoff: {
      sourceKind: 'BASELINE_BOOTSTRAP',
      sourceBundleSha256: 'e'.repeat(64),
      sourceArtifactProvenanceSha256: 'f'.repeat(64),
      targetCompatibilityEvidenceSha256: '0'.repeat(64),
      finalDisableEvidenceSha256: '1'.repeat(64),
      predecessorManifestSha256: null,
    },
    approval: {
      status: 'APPROVED',
      reviewerAlias: 'release-reviewer',
      approvalEvidenceSha256: 'c'.repeat(64),
      releaseEvidenceSha256: 'd'.repeat(64),
    },
    containsSensitiveData: false,
  });
  const candidateRecord = createStage7CandidateRollbackRecord({
    previousManifest,
    createdAtUtc: '2026-08-17T12:05:00.000Z',
    approvalSha256: 'e'.repeat(64),
    planSha256: 'f'.repeat(64),
    deploymentEvidenceSha256: '0'.repeat(64),
    resources: {
      api: {
        functionName: functionNames.api,
        aliasName: 'live',
        version: '12',
        codeSha256: '1'.repeat(64),
      },
      worker: {
        functionName: functionNames.worker,
        aliasName: 'live',
        version: '22',
        codeSha256: '2'.repeat(64),
      },
      web: {
        bucketName,
        distributionId,
        objects: candidateObjects,
        mutableInvalidationPaths: [...VERSIONED_ROLLBACK_INVALIDATION_PATHS],
      },
    },
  });
  const calls = [];
  let failWorkerOnce = true;
  let copySequence = 0;
  let invalidationSequence = 0;
  const flag = (args, name) => args[args.indexOf(name) + 1];
  const lambdaIdentity = (version) =>
    version === '11' || version === '21'
      ? { candidateSha: previousSha, releaseId: previousReleaseId }
      : { candidateSha, releaseId: candidateReleaseId };
  const codeDigest = (functionName, version) => {
    const resource =
      functionName === functionNames.api
        ? version === '11'
          ? previousManifest.resources.api
          : candidateRecord.resources.api
        : version === '21'
          ? previousManifest.resources.worker
          : candidateRecord.resources.worker;
    return Buffer.from(resource.codeSha256, 'hex').toString('base64');
  };
  const fakeExecutor = ({ command, args }) => {
    assert.equal(command, 'aws');
    const operation = `${args[0]}:${args[1]}`;
    calls.push({ operation, args: [...args] });
    const success = (value) => ({ status: 0, stdout: JSON.stringify(value), stderr: '' });
    if (operation === 'lambda:get-function-configuration') {
      const functionName = flag(args, '--function-name');
      const version = flag(args, '--qualifier');
      const identity = lambdaIdentity(version);
      return success({
        FunctionName: functionName,
        Version: version,
        State: 'Active',
        LastUpdateStatus: 'Successful',
        CodeSha256: codeDigest(functionName, version),
        Environment: {
          Variables: { CANDIDATE_SHA: identity.candidateSha, RELEASE_ID: identity.releaseId },
        },
      });
    }
    if (operation === 'lambda:get-alias') {
      const functionName = flag(args, '--function-name');
      const key = functionName === functionNames.api ? 'api' : 'worker';
      return success({
        Name: 'live',
        FunctionVersion: aliases[key].version,
        RevisionId: `revision-${aliases[key].revision}`,
        RoutingConfig: { AdditionalVersionWeights: {} },
      });
    }
    if (operation === 'lambda:update-alias') {
      const functionName = flag(args, '--function-name');
      const key = functionName === functionNames.api ? 'api' : 'worker';
      if (key === 'worker' && failWorkerOnce) {
        failWorkerOnce = false;
        return { status: 1, stdout: '', stderr: 'injected partial failure' };
      }
      assert.equal(flag(args, '--revision-id'), `revision-${aliases[key].revision}`);
      aliases[key].version = flag(args, '--function-version');
      aliases[key].revision += 1;
      return success({
        Name: 'live',
        FunctionVersion: aliases[key].version,
        RevisionId: `revision-${aliases[key].revision}`,
      });
    }
    if (operation === 's3api:list-object-versions') {
      return success({
        DeleteMarkers: [],
        IsTruncated: false,
        Versions: VERSIONED_ROLLBACK_WEB_KEYS.map((key) => {
          const versionId = active.get(key);
          const body = contents.get(versionId);
          return {
            Key: key,
            VersionId: versionId,
            IsLatest: true,
            ETag: etags.get(versionId),
            Size: body.length,
          };
        }),
      });
    }
    if (operation === 's3api:head-object') {
      const versionId = flag(args, '--version-id');
      const body = contents.get(versionId);
      return success({
        VersionId: versionId,
        ETag: etags.get(versionId),
        ContentLength: body.length,
      });
    }
    if (operation === 's3api:get-object') {
      const versionIndex = args.indexOf('--version-id');
      const versionId = args[versionIndex + 1];
      const filename = args[versionIndex + 2];
      writeFileSync(filename, contents.get(versionId));
      return success({ VersionId: versionId, ETag: etags.get(versionId) });
    }
    if (operation === 's3api:copy-object') {
      const key = flag(args, '--key');
      const source = flag(args, '--copy-source');
      const sourceVersion = decodeURIComponent(source.slice(source.indexOf('?versionId=') + 11));
      copySequence += 1;
      const versionId = `restored-${String(copySequence).padStart(2, '0')}`;
      contents.set(versionId, Buffer.from(contents.get(sourceVersion)));
      etags.set(versionId, etags.get(sourceVersion));
      active.set(key, versionId);
      return success({ VersionId: versionId, CopyObjectResult: { ETag: etags.get(versionId) } });
    }
    if (operation === 'cloudfront:create-invalidation') {
      invalidationSequence += 1;
      const batch = JSON.parse(flag(args, '--invalidation-batch'));
      return success({
        Invalidation: {
          Id: `IROLLBACK${invalidationSequence}`,
          Status: 'InProgress',
          InvalidationBatch: batch,
        },
      });
    }
    if (operation === 'cloudfront:get-invalidation') {
      return success({ Invalidation: { Id: flag(args, '--id'), Status: 'Completed' } });
    }
    if (operation === 'cloudformation:describe-stacks') {
      const stackName = flag(args, '--stack-name');
      const suffix = stackName.endsWith('-api') ? 'api' : 'web';
      const output =
        suffix === 'api'
          ? {
              CandidateSha: candidateSha,
              ReleaseId: candidateReleaseId,
              ApiAliasArn: `arn:aws:lambda:${region}:${accountId}:function:${functionNames.api}:live`,
              ApiFunctionVersion: '12',
              WorkerAliasArn: `arn:aws:lambda:${region}:${accountId}:function:${functionNames.worker}:live`,
              WorkerFunctionVersion: '22',
              ApiPublicationStatus: 'ENABLED',
            }
          : {
              CandidateSha: candidateSha,
              ReleaseId: candidateReleaseId,
              WebBucketName: bucketName,
              DistributionId: distributionId,
              WebPublicationStatus: 'ENABLED',
            };
      return success({
        Stacks: [
          {
            StackName: stackName,
            StackId: `arn:aws:cloudformation:${region}:${accountId}:stack/${stackName}/canary`,
            StackStatus: 'UPDATE_COMPLETE',
            CreationTime: '2026-08-16T12:00:00.000Z',
            LastUpdatedTime: '2026-08-17T12:00:00.000Z',
            EnableTerminationProtection: true,
            Parameters: [{ ParameterKey: 'PublicationState', ParameterValue: 'ENABLED' }],
            Outputs: Object.entries(output).map(([OutputKey, OutputValue]) => ({
              OutputKey,
              OutputValue,
            })),
          },
        ],
      });
    }
    throw new Error(`unexpected AWS canary operation ${operation}`);
  };
  const context = {
    awsCommand: 'aws',
    config: { aws: { accountId, region }, environment },
    environmentVariables: {},
    executor: fakeExecutor,
    identity: { candidateSha, releaseId: candidateReleaseId },
    now: new Date('2026-08-17T12:10:00.000Z'),
    stacks: ['api', 'web'].map((suffix) => `checkout-${environment}-${suffix}`),
  };
  verifyPreviousVersionedResourcesAws(context, previousManifest);
  verifyCandidateVersionedResourcesAws(context, previousManifest, candidateRecord);
  assert.deepEqual(
    candidateVersionedResourcesAws(context, previousManifest),
    candidateRecord.resources,
  );
  const pendingBaseline = {
    observedAtUtc: '2026-08-17T12:10:00.000Z',
    trackedCount: 1,
    oldestAgeSeconds: 10,
    snapshotSha256: '3'.repeat(64),
  };
  const currentState = () => ({
    api: {
      functionName: functionNames.api,
      aliasName: 'live',
      version: aliases.api.version,
    },
    worker: {
      functionName: functionNames.worker,
      aliasName: 'live',
      version: aliases.worker.version,
    },
    web: {
      bucketName,
      distributionId,
      objects: VERSIONED_ROLLBACK_WEB_KEYS.map((key) => ({
        key,
        versionId: active.get(key),
        contentSha256: sha256(contents.get(active.get(key))),
      })),
    },
    pending: pendingBaseline,
    dataFactsSha256: '4'.repeat(64),
  });
  const noActionRecovery = createCandidateActiveNoActionRecovery({
    previousManifest,
    candidateRecord,
    publicationState: { api: 'ENABLED', web: 'ENABLED' },
    observedState: currentState(),
    completedAtUtc: '2026-08-17T12:10:00.000Z',
  });
  assert.equal(noActionRecovery.decision, 'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED');
  assert.equal(noActionRecovery.verificationPlan.decision, 'NOOP_ALREADY_APPLIED');
  assert.equal(noActionRecovery.mutationsPerformed, 0);
  assert.equal(
    noActionRecovery.recoverySha256,
    objectSha256(
      Object.fromEntries(
        Object.entries(noActionRecovery).filter(([key]) => key !== 'recoverySha256'),
      ),
    ),
  );
  const noActionCallsStart = calls.length;
  const beforeNoAction = captureCandidateActiveNoActionSnapshot(context, candidateRecord, 'BEFORE');
  const afterNoAction = captureCandidateActiveNoActionSnapshot(context, candidateRecord, 'AFTER');
  assertCandidateActiveNoActionSandwich({
    before: beforeNoAction,
    after: afterNoAction,
    candidateRecord,
  });
  const noActionCalls = calls.slice(noActionCallsStart);
  const mutatingOperations = new Set([
    'cloudformation:update-stack',
    'lambda:update-alias',
    's3api:copy-object',
    'cloudfront:create-invalidation',
    'dynamodb:update-item',
    'dynamodb:put-item',
    'dynamodb:delete-item',
  ]);
  assert.equal(
    noActionCalls.some(({ operation }) => mutatingOperations.has(operation)),
    false,
  );
  const readOnlyOperations = new Set([
    'cloudformation:describe-stacks',
    'lambda:get-alias',
    's3api:list-object-versions',
    's3api:head-object',
    's3api:get-object',
  ]);
  assert.equal(
    noActionCalls.every(({ operation }) => readOnlyOperations.has(operation)),
    true,
  );
  const sourceBindings = EMERGENCY_NO_ACTION_SOURCE_FLAGS.map((label, index) => ({
    label,
    basename: `${label}.json`,
    rawSha256: String((index % 9) + 1).repeat(64),
    canonicalSha256: String(((index + 1) % 9) + 1).repeat(64),
    bytes: index + 1,
  }));
  const callerProjection = {
    accountSha256: sha256(accountId),
    accountSuffix: accountId.slice(-4),
    roleSha256: 'd'.repeat(64),
    sessionArnSha256: 'e'.repeat(64),
  };
  const callerRaw = JSON.stringify(callerProjection);
  const callerBinding = {
    projection: callerProjection,
    rawSha256: sha256(callerRaw),
    canonicalSha256: objectSha256(callerProjection),
    bytes: Buffer.byteLength(callerRaw),
  };
  const noActionOutcome = sealEmergencyNoActionOutcome(
    emergencyNoActionOutcomeBody({
      status: 'PASS',
      failureCode: null,
      failureStage: null,
      previousReleaseManifestSha256: previousManifest.manifestSha256,
      candidateRecordSha256: candidateRecord.recordSha256,
      assemblySha256: previousManifest.target.assemblySha256,
      sourceBindings,
      callerBinding,
      before: beforeNoAction,
      after: afterNoAction,
      recoverySha256: noActionRecovery.recoverySha256,
      completedAtUtc: noActionRecovery.completedAtUtc,
    }),
  );
  assert.equal(
    validateCandidateActiveNoActionOutcome({
      value: noActionOutcome,
      candidateRecord,
      expectedIdentity: {
        candidateSha: previousManifest.target.candidateSha,
        releaseId: previousManifest.target.releaseId,
      },
      expectedSourceBindings: sourceBindings,
      expectedCaller: callerProjection,
      expectedRecoverySha256: noActionRecovery.recoverySha256,
    }),
    noActionOutcome,
  );
  const resignOutcome = (mutate) => {
    const value = structuredClone(noActionOutcome);
    mutate(value);
    delete value.outcomeSha256;
    return sealEmergencyNoActionOutcome(value);
  };
  for (const value of [
    resignOutcome((entry) => {
      entry.observations.after.state.publication.web.state = 'DISABLED';
      entry.observations.after.stateSha256 = objectSha256(entry.observations.after.state);
    }),
    resignOutcome((entry) => {
      entry.observations.after.state.aliases.api.version = '11';
      entry.observations.after.stateSha256 = objectSha256(entry.observations.after.state);
    }),
    resignOutcome((entry) => {
      entry.observations.after.state.aliases.api.revisionId = 'tampered-revision';
      entry.observations.after.stateSha256 = objectSha256(entry.observations.after.state);
    }),
    resignOutcome((entry) => {
      entry.sourceBindings[0].rawSha256 = '0'.repeat(64);
      entry.sourceBindingsSha256 = objectSha256(entry.sourceBindings);
    }),
    resignOutcome((entry) => {
      entry.callerBinding.projection.roleSha256 = '0'.repeat(64);
      const raw = JSON.stringify(entry.callerBinding.projection);
      entry.callerBinding.rawSha256 = sha256(raw);
      entry.callerBinding.canonicalSha256 = objectSha256(entry.callerBinding.projection);
      entry.callerBinding.bytes = Buffer.byteLength(raw);
    }),
  ]) {
    assert.throws(
      () =>
        validateCandidateActiveNoActionOutcome({
          value,
          candidateRecord,
          expectedIdentity: {
            candidateSha: previousManifest.target.candidateSha,
            releaseId: previousManifest.target.releaseId,
          },
          expectedSourceBindings: sourceBindings,
          expectedCaller: callerProjection,
          expectedRecoverySha256: noActionRecovery.recoverySha256,
        }),
      (error) => error instanceof Stage7Error,
    );
  }
  const failureOutcome = sealEmergencyNoActionOutcome(
    emergencyNoActionOutcomeBody({
      status: 'FAIL',
      failureCode: 'E7_EMERGENCY_RECOVERY_CANDIDATE_NOT_ACTIVE',
      failureStage: 'BEFORE_OBSERVATION',
      previousReleaseManifestSha256: previousManifest.manifestSha256,
      candidateRecordSha256: candidateRecord.recordSha256,
      assemblySha256: previousManifest.target.assemblySha256,
      sourceBindings,
      callerBinding,
      before: null,
      after: null,
      recoverySha256: null,
      completedAtUtc: '2026-08-17T12:10:00.000Z',
    }),
  );
  assert.equal(
    validateCandidateActiveNoActionOutcome({ value: failureOutcome, candidateRecord }),
    failureOutcome,
  );
  assert.throws(
    () =>
      createCandidateActiveNoActionRecovery({
        previousManifest,
        candidateRecord,
        publicationState: { api: 'ENABLED', web: 'DISABLED' },
        observedState: currentState(),
        completedAtUtc: '2026-08-17T12:10:00.000Z',
      }),
    (error) =>
      error instanceof Stage7Error && error.code === 'E7_EMERGENCY_RECOVERY_CANDIDATE_NOT_ACTIVE',
  );
  assert.throws(
    () =>
      createCandidateActiveNoActionRecovery({
        previousManifest,
        candidateRecord,
        publicationState: { api: 'ENABLED', web: 'ENABLED' },
        observedState: {
          ...currentState(),
          api: { ...currentState().api, version: previousManifest.resources.api.version },
        },
        completedAtUtc: '2026-08-17T12:10:00.000Z',
      }),
    (error) =>
      error instanceof Stage7Error && error.code === 'E7_EMERGENCY_RECOVERY_CANDIDATE_NOT_ACTIVE',
  );
  assert.throws(
    () =>
      createCandidateActiveNoActionRecovery({
        previousManifest,
        candidateRecord,
        publicationState: { api: 'ENABLED', web: 'ENABLED' },
        observedState: currentState(),
        completedAtUtc: '2026-08-17T12:10:00Z',
      }),
    (error) =>
      error instanceof Stage7Error &&
      error.code === 'E7_EMERGENCY_RECOVERY_COMPLETION_TIME_INVALID',
  );
  const initialPlan = createStage7VersionedRollbackPlan({
    direction: 'ROLLBACK_TO_PREVIOUS',
    previousManifest,
    candidateRecord,
    currentState: currentState(),
  });
  await assert.rejects(
    () =>
      applyVersionedRollbackPlanAws(context, initialPlan, { delayImplementation: async () => {} }),
    (error) => error instanceof Stage7Error && error.code === 'E7_ROLLBACK_ALIAS_UPDATE_FAILED',
  );
  assert.equal(aliases.api.version, '11');
  assert.equal(aliases.worker.version, '22');
  const resumePlan = createStage7VersionedRollbackPlan({
    direction: 'ROLLBACK_TO_PREVIOUS',
    previousManifest,
    candidateRecord,
    currentState: currentState(),
    pendingBaseline,
  });
  assert.equal(resumePlan.decision, 'RESUME_PARTIAL');
  assert.equal(resumePlan.aliases.api.changed, false);
  assert.equal(resumePlan.aliases.worker.changed, true);
  const rollbackInvalidation = await applyVersionedRollbackPlanAws(context, resumePlan, {
    delayImplementation: async () => {},
  });
  assert.equal(rollbackInvalidation.status, 'COMPLETED');
  assert.equal(aliases.worker.version, '21');
  assert.deepEqual(
    VERSIONED_ROLLBACK_WEB_KEYS.map((key) => sha256(contents.get(active.get(key)))),
    previousObjects.map(({ contentSha256 }) => contentSha256),
  );
  const retryPlan = createStage7VersionedRollbackPlan({
    direction: 'ROLLBACK_TO_PREVIOUS',
    previousManifest,
    candidateRecord,
    currentState: currentState(),
    pendingBaseline,
  });
  assert.equal(retryPlan.decision, 'NOOP_ALREADY_APPLIED');
  const callsBeforeRetry = calls.length;
  assert.equal(
    (
      await applyVersionedRollbackPlanAws(context, retryPlan, {
        delayImplementation: async () => {},
      })
    ).status,
    'NOT_REQUIRED',
  );
  assert.equal(calls.length, callsBeforeRetry);
  const repromotionPlan = createStage7VersionedRollbackPlan({
    direction: 'REPROMOTE_CANDIDATE',
    previousManifest,
    candidateRecord,
    currentState: currentState(),
  });
  assert.equal(repromotionPlan.decision, 'APPLY');
  await applyVersionedRollbackPlanAws(context, repromotionPlan, {
    delayImplementation: async () => {},
  });
  assert.equal(aliases.api.version, '12');
  assert.equal(aliases.worker.version, '22');
  assert.deepEqual(
    VERSIONED_ROLLBACK_WEB_KEYS.map((key) => sha256(contents.get(active.get(key)))),
    candidateObjects.map(({ contentSha256 }) => contentSha256),
  );
  assert.equal(copySequence, 4);
  assert.equal(invalidationSequence, 2);
  assert.equal(
    calls.some(
      ({ operation, args }) =>
        operation === 'dynamodb:update-item' ||
        operation === 'dynamodb:put-item' ||
        operation === 'dynamodb:delete-item' ||
        args.includes('delete-stack'),
    ),
    false,
  );
  return { calls: calls.length, copySequence, invalidationSequence };
};

const selfTestReleaseReconciliationRecoveryBoundary = async () => {
  const candidateSha = 'a'.repeat(40);
  const controlSha = 'b'.repeat(40);
  const accountId = '123456789012';
  const recoveryRoleArn = `arn:aws:iam::${accountId}:role/checkout/release-reconciliation-recovery`;
  const actor = {
    originalSource: {
      candidateSha,
      releaseTag: `stage7-release-${candidateSha.slice(0, 12)}`,
    },
    recoveryRun: {
      repository: 'ivanmonsalve0404/async-checkout-demo',
      workflowRef: RELEASE_RECONCILIATION_RECOVERY_WORKFLOW,
      ref: 'refs/heads/master',
      eventName: 'workflow_dispatch',
      runId: '99887766',
      runAttempt: 1,
      actorId: '11223344',
      controlSha,
      protectedEnvironment: RELEASE_RECONCILIATION_RECOVERY_ENVIRONMENT,
      candidateSha,
    },
    authority: {
      accountId,
      region: 'us-east-1',
      recoveryRoleArn,
    },
    request: {
      recoveryRoleAuthority: { roleArn: recoveryRoleArn },
    },
  };
  const environmentVariables = {
    GITHUB_ACTIONS: 'true',
    GITHUB_REPOSITORY: actor.recoveryRun.repository,
    GITHUB_WORKFLOW_REF: actor.recoveryRun.workflowRef,
    GITHUB_REF: actor.recoveryRun.ref,
    GITHUB_EVENT_NAME: actor.recoveryRun.eventName,
    GITHUB_RUN_ID: actor.recoveryRun.runId,
    GITHUB_RUN_ATTEMPT: String(actor.recoveryRun.runAttempt),
    GITHUB_ACTOR_ID: actor.recoveryRun.actorId,
    GITHUB_SHA: controlSha,
    STAGE7_PROTECTED_ENVIRONMENT: actor.recoveryRun.protectedEnvironment,
    STAGE7_RECOVERY_CANDIDATE_SHA: candidateSha,
    STAGE7_AWS_ACCOUNT_ID: accountId,
    STAGE7_AWS_REGION: actor.authority.region,
    AWS_REGION: actor.authority.region,
    AWS_DEFAULT_REGION: actor.authority.region,
    STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN: recoveryRoleArn,
    STAGE7_CONFIG: '.stage7/recovery-private/stage7-config.json',
    AWS_ACCESS_KEY_ID: ['ASI', 'RECOVERY', 'CANARY'].join(''),
    AWS_SECRET_ACCESS_KEY: ['synthetic', 'recovery', 'canary'].join('-'),
    AWS_SESSION_TOKEN: ['synthetic', 'recovery', 'session', 'canary'].join('-'),
  };
  validateRecoveryRuntimeEnvironment({
    actor,
    environmentVariables,
    capability: 'mutation',
  });
  let awsCalls = 0;
  const executor = () => {
    awsCalls += 1;
    throw new Error('unreachable recovery boundary AWS canary');
  };
  const invalidCases = [
    { actor: null, environmentVariables },
    {
      actor,
      environmentVariables: { ...environmentVariables, GITHUB_RUN_ID: '99887767' },
    },
    {
      actor,
      environmentVariables: { ...environmentVariables, STAGE7_CONFIG: '' },
    },
    {
      actor,
      environmentVariables: { ...environmentVariables, GITHUB_SHA: candidateSha },
    },
    {
      actor,
      environmentVariables: {
        ...environmentVariables,
        STAGE7_RECOVERY_CANDIDATE_SHA: controlSha,
      },
    },
    {
      actor,
      environmentVariables: {
        ...environmentVariables,
        STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN: `arn:aws:iam::${accountId}:role/checkout/release-rollback`,
      },
    },
  ];
  for (const invalid of invalidCases) {
    await assert.rejects(
      () =>
        executeVersionedRollbackRecovery({
          flags: { direction: 'REPROMOTE_CANDIDATE' },
          recoveryActor: invalid.actor,
          recoveryIntent: null,
          executor,
          environmentVariables: invalid.environmentVariables,
        }),
      (error) =>
        error instanceof Stage7AwsError &&
        error.code === 'E7_RELEASE_RECONCILIATION_RECOVERY_RUNTIME_CONTEXT_INVALID',
    );
  }
  await assert.rejects(
    () =>
      executeVersionedRollbackRecovery({
        flags: { direction: 'ROLLBACK_TO_PREVIOUS' },
        recoveryActor: actor,
        recoveryIntent: null,
        executor,
        environmentVariables,
      }),
    (error) =>
      error instanceof Stage7AwsError &&
      error.code === 'E7_RELEASE_RECONCILIATION_RECOVERY_DIRECTION_INVALID',
  );
  for (const driftFlags of [
    { 'reconciliation-intent': 'intent.json' },
    {
      'reconciliation-intent': true,
      'reconciliation-recovery-actor': true,
    },
  ]) {
    await assert.rejects(
      () =>
        verifyDrift({
          flags: driftFlags,
          executor,
          environmentVariables: {},
        }),
      (error) =>
        error instanceof Stage7AwsError &&
        error.code === 'E7_RELEASE_RECONCILIATION_RECOVERY_DRIFT_FLAGS_INVALID',
    );
  }
  const gitResult = (stdout) => ({ error: undefined, signal: null, status: 0, stdout });
  for (const outputs of [
    [`${candidateSha}\n`, `${candidateSha}\n`],
    [`${controlSha}\n`, `${controlSha}\n`],
  ]) {
    let index = 0;
    assert.throws(
      () =>
        resolveRecoveryGitIdentity({
          actor,
          gitSpawn: () => gitResult(outputs[index++]),
        }),
      (error) =>
        error instanceof Stage7AwsError &&
        error.code === 'E7_RELEASE_RECONCILIATION_RECOVERY_GIT_IDENTITY_MISMATCH',
    );
  }
  assert.equal(awsCalls, 0);
  return { canaries: invalidCases.length + 5, mutations: 0 };
};

const selfTestReleaseSuccessorGuardBoundary = async () => {
  let invalidModeCalls = 0;
  for (const flags of [
    {},
    { 'successor-guard-mode': 'BYPASS' },
    { 'successor-guard-mode': 'RECONCILIATION', direction: 'ROLLBACK_TO_PREVIOUS' },
  ]) {
    await assert.rejects(
      () =>
        executeVersionedRollback({
          flags,
          executor: () => {
            invalidModeCalls += 1;
            throw new Error('unreachable successor guard mode canary');
          },
          environmentVariables: {},
        }),
      (error) =>
        error instanceof Stage7AwsError &&
        [
          'E7_RELEASE_SUCCESSOR_GUARD_MODE_INVALID',
          'E7_RELEASE_SUCCESSOR_GUARD_SOURCE_SET_INVALID',
        ].includes(error.code),
    );
  }
  assert.equal(invalidModeCalls, 0);

  const accountId = '123456789012';
  const candidateSha = 'a'.repeat(40);
  const runId = '99887766';
  const expectedRoleArn = `arn:aws:iam::${accountId}:role/checkout/release-rollback`;
  const calls = [];
  const context = {
    awsCommand: 'aws',
    config: { aws: { accountId, region: 'us-east-1' } },
    environmentVariables: {
      GITHUB_ACTIONS: 'true',
      GITHUB_REPOSITORY: 'ivanmonsalve0404/async-checkout-demo',
      GITHUB_WORKFLOW_REF: RELEASE_SUCCESSOR_RELEASE_WORKFLOW,
      GITHUB_REF: 'refs/heads/master',
      GITHUB_RUN_ID: runId,
      GITHUB_RUN_ATTEMPT: '1',
      GITHUB_SHA: candidateSha,
      STAGE7_AWS_ROLLBACK_ROLE_ARN: expectedRoleArn,
    },
    executor: ({ command, args }) => {
      calls.push({ command, args: [...args] });
      const operation = `${args[0]}:${args[1]}`;
      if (operation === 'sts:get-caller-identity') {
        return {
          status: 0,
          stdout: JSON.stringify({
            UserId: `CANARY:e7-rollback-apply-${runId}`,
            Account: accountId,
            Arn: `arn:aws:sts::${accountId}:assumed-role/release-rollback/e7-rollback-apply-${runId}`,
          }),
          stderr: '',
        };
      }
      if (operation === 'ssm:get-parameters-by-path') {
        return { status: 0, stdout: JSON.stringify({ Parameters: [] }), stderr: '' };
      }
      throw new Error(`unexpected successor guard canary operation ${operation}`);
    },
    expectedRoleArn,
    identity: { candidateSha, releaseId: 'rel-20260817-1200-aaaaaaa' },
  };
  const getParametersByPath = createReleaseSuccessorGuardAwsAdapter({
    context,
    mode: 'ROLLBACK_CHECK',
    direction: 'ROLLBACK_TO_PREVIOUS',
  });
  for (const request of [
    {
      path: `/checkout/stage7/rollback/${'b'.repeat(40)}`,
      recursive: true,
      withDecryption: false,
      maxResults: 10,
    },
    {
      path: `/checkout/stage7/rollback/${candidateSha}`,
      recursive: true,
      withDecryption: true,
      maxResults: 10,
    },
    {
      path: `/checkout/stage7/rollback/${candidateSha}`,
      recursive: true,
      withDecryption: false,
      maxResults: 11,
    },
  ]) {
    await assert.rejects(
      () => getParametersByPath(request),
      (error) =>
        error instanceof Stage7AwsError &&
        error.code === 'E7_RELEASE_SUCCESSOR_GUARD_SSM_REQUEST_INVALID',
    );
  }
  assert.equal(calls.length, 0);
  assert.deepEqual(
    await getParametersByPath({
      path: `/checkout/stage7/rollback/${candidateSha}`,
      recursive: true,
      withDecryption: false,
      maxResults: 10,
    }),
    { Parameters: [] },
  );
  assert.deepEqual(
    calls.map(({ args }) => `${args[0]}:${args[1]}`),
    ['sts:get-caller-identity', 'ssm:get-parameters-by-path'],
  );
  assert.equal(
    calls.some(({ args }) =>
      ['put-parameter', 'delete-parameter', 'update-alias', 'copy-object'].some((operation) =>
        args.includes(operation),
      ),
    ),
    false,
  );
  return { canaries: 7, mutations: 0, simulatedAwsReads: calls.length };
};

const selfTestInitialRollbackResumption = async (config) => {
  const context = {
    config,
    now: new Date('2026-08-17T11:58:00.000Z'),
    identity: {
      candidateSha: 'a'.repeat(40),
      releaseId: 'rel-20260817-1200-aaaaaaa',
    },
    stacks: config.authorization.stacks,
  };
  const stackState = (suffix, publicationState) => {
    const stackName = stackFor(context, suffix);
    const apiFunctionName = `checkout-${config.environment}-api`;
    const workerFunctionName = `checkout-${config.environment}-worker`;
    const applicationUrl = `https://${config.domain.hostname}`;
    return {
      publicationState,
      stackName,
      state: {
        exists: true,
        outputs: {
          CandidateSha: context.identity.candidateSha,
          ...(suffix === 'api'
            ? {
                ApiAliasArn: `arn:aws:lambda:${config.aws.region}:${config.aws.accountId}:function:${apiFunctionName}:live`,
                ApiCustomDomainName: config.domain.apiHostname,
                ApiFunctionVersion: '1',
                ApiOriginUrl: `https://${config.domain.apiHostname}`,
                HttpApiId: 'a1b2c3d4e5',
                WorkerAliasArn: `arn:aws:lambda:${config.aws.region}:${config.aws.accountId}:function:${workerFunctionName}:live`,
                WorkerFunctionVersion: '2',
              }
            : {
                ApiDocsUrl: `${applicationUrl}/api/docs`,
                ApiUrl: `${applicationUrl}/api`,
                ApplicationUrl: applicationUrl,
                DistributionId: 'E1234567890ABC',
                HealthUrl: `${applicationUrl}/api/health/ready`,
                PublicOriginParameterName: `/checkout-${config.environment}/public-origin`,
                WebBucketName: `checkout-${config.environment}-web-canary`,
              }),
          ReleaseId: context.identity.releaseId,
          [suffix === 'api' ? 'ApiPublicationStatus' : 'WebPublicationStatus']: publicationState,
        },
        parameters: { PublicationState: publicationState },
        tags: expectedReleaseStackTags(context),
        stackStatus: 'UPDATE_COMPLETE',
        stackId: `arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/${stackName}/12345678-1234-4123-8123-123456789012`,
        creationTime: '2026-08-17T11:00:00.000Z',
        lastUpdatedTime:
          publicationState === 'ENABLED' ? '2026-08-17T11:30:00.000Z' : '2026-08-17T12:00:00.000Z',
        terminationProtection: true,
      },
    };
  };
  const live = {
    api: stackState('api', 'ENABLED'),
    web: stackState('web', 'ENABLED'),
  };
  const records = {
    api: {
      deployed: {
        api: {
          aliasName: 'live',
          functionName: `checkout-${config.environment}-api`,
          version: '1',
        },
        worker: {
          aliasName: 'live',
          functionName: `checkout-${config.environment}-worker`,
          version: '2',
        },
      },
      publication: { apiId: 'a1b2c3d4e5' },
      recordSha256: 'd'.repeat(64),
      templateSha256: '1'.repeat(64),
    },
    web: {
      bucketName: `checkout-${config.environment}-web-canary`,
      distributionId: 'E1234567890ABC',
      publication: { distributionId: 'E1234567890ABC' },
      publicOriginSha256: sha256(`https://${config.domain.hostname}`),
      recordSha256: 'e'.repeat(64),
      templateSha256: '2'.repeat(64),
    },
  };
  const ledger = { checkpoints: {} };
  let applyCalls = 0;
  const causalProof = ({ clientRequestToken, suffix }) => ({
    provider: 'CLOUDFORMATION_STACK_EVENT',
    requestTokenSha256: sha256(clientRequestToken),
    updateStartedEventIdSha256: sha256(`${suffix}-started`),
    updateCompletedEventIdSha256: sha256(`${suffix}-completed`),
    updateStartedAtUtc: '2026-08-17T11:59:00.000Z',
    updateCompletedAtUtc: '2026-08-17T12:00:00.000Z',
    transition: 'UPDATE_IN_PROGRESS_TO_UPDATE_COMPLETE',
  });
  const dependencies = {
    readPublication: (_context, suffix) => live[suffix],
    readEvidence: () => ledger,
    persistIntent: async ({ context: current, suffix, record, observed }) => {
      const intent = createInitialRollbackIntent({
        context: current,
        suffix,
        record,
        observed,
      });
      ledger.checkpoints[initialRollbackIntentCheckpoint(suffix)] = intent;
      return intent;
    },
    applyUpdate: (_context, suffix, targetState, options) => {
      applyCalls += 1;
      const before = live[suffix];
      assert.equal(targetState, 'DISABLED');
      assert.equal(
        options.expectedBeforeStateSha256,
        stackStateFingerprint(before.stackName, before.state),
      );
      assert.equal(
        options.clientRequestToken,
        initialRollbackClientRequestToken({
          context,
          suffix,
          record: records[suffix],
          observed: before,
        }),
      );
      assert.equal(options.expectedTemplateSha256, records[suffix].templateSha256);
      const result = {
        changed: true,
        previousState: 'ENABLED',
        state: 'DISABLED',
        stackIdSha256: sha256(before.state.stackId),
        stackName: before.stackName,
      };
      live[suffix] = stackState(suffix, 'DISABLED');
      return result;
    },
    captureCausality: ({ suffix, clientRequestToken }) =>
      causalProof({ suffix, clientRequestToken }),
    validateTemplate: (_context, stackId, expectedSha256) => {
      const suffix = stackId.includes(`:stack/${stackFor(context, 'api')}/`) ? 'api' : 'web';
      assert.equal(expectedSha256, records[suffix].templateSha256);
      return expectedSha256;
    },
  };

  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'api',
        record: { ...records.api, templateSha256: 'invalid' },
        dependencies,
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_RECORD_TEMPLATE_INVALID',
  );
  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'api',
        record: records.api,
        dependencies: {
          ...dependencies,
          validateTemplate: () => fail('E7_CLOUDFORMATION_ORIGINAL_TEMPLATE_DRIFT'),
        },
      }),
    (error) => error?.code === 'E7_CLOUDFORMATION_ORIGINAL_TEMPLATE_DRIFT',
  );
  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'api',
        record: { ...records.api, publication: { apiId: 'f9e8d7c6b5' } },
        dependencies,
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_LIVE_BINDING_INVALID',
  );
  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'web',
        record: { ...records.web, distributionId: 'EFOREIGN123456' },
        dependencies,
      }),
    (error) => error?.code === 'E7_INITIAL_WEB_ROLLBACK_LIVE_BINDING_INVALID',
  );
  assert.equal(applyCalls, 0);

  const apiApplied = await transitionInitialRollbackPublication({
    context,
    suffix: 'api',
    record: records.api,
    dependencies,
  });
  assert.equal(apiApplied.changed, true);
  assert.equal(apiApplied.intent.mode, 'APPLIED_AFTER_LOCAL_INTENT');
  assert.equal(applyCalls, 1);

  const apiRecoveredAfterCut = await transitionInitialRollbackPublication({
    context,
    suffix: 'api',
    record: records.api,
    dependencies,
  });
  assert.equal(apiRecoveredAfterCut.changed, true);
  assert.equal(apiRecoveredAfterCut.intent.mode, 'RECOVERED_AFTER_CLOUDFORMATION_EVENT');
  assert.equal(applyCalls, 1);

  const apiIntent = ledger.checkpoints.apiRollbackIntent;
  delete ledger.checkpoints.apiRollbackIntent;
  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'api',
        record: records.api,
        dependencies,
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_RESUME_INTENT_MISSING',
  );
  assert.equal(applyCalls, 1);
  ledger.checkpoints.apiRollbackIntent = apiIntent;

  ledger.checkpoints.apiRollback = {
    decision: 'INITIAL_RELEASE_DISABLED_REQUIRES_UNAVAILABLE_SMOKE',
    releaseMode: 'INITIAL',
    aliasesChanged: false,
    dataFactsChanged: false,
    stacksDeleted: 0,
    publication: apiRecoveredAfterCut,
  };
  const apiCompleted = await transitionInitialRollbackPublication({
    context,
    suffix: 'api',
    record: records.api,
    dependencies,
  });
  assert.deepEqual(apiCompleted, apiRecoveredAfterCut);
  assert.equal(applyCalls, 1);
  live.api = stackState('api', 'ENABLED');
  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'api',
        record: records.api,
        dependencies,
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_COMPLETED_TRANSITION_DRIFT',
  );
  live.api = stackState('api', 'DISABLED');

  const webApplied = await transitionInitialRollbackPublication({
    context,
    suffix: 'web',
    record: records.web,
    dependencies,
  });
  assert.equal(webApplied.intent.mode, 'APPLIED_AFTER_LOCAL_INTENT');
  assert.equal(applyCalls, 2);
  const webRecoveredAfterCut = await transitionInitialRollbackPublication({
    context,
    suffix: 'web',
    record: records.web,
    dependencies,
  });
  assert.equal(webRecoveredAfterCut.intent.mode, 'RECOVERED_AFTER_CLOUDFORMATION_EVENT');
  assert.equal(applyCalls, 2);
  ledger.checkpoints.rollbackInfrastructure = {
    publication: { webStack: webRecoveredAfterCut },
  };
  const webCompleted = await transitionInitialRollbackPublication({
    context,
    suffix: 'web',
    record: records.web,
    dependencies,
  });
  assert.deepEqual(webCompleted, webRecoveredAfterCut);
  assert.equal(applyCalls, 2);

  const rollbackCheckpoint = {
    decision: 'INITIAL_RELEASE_DISABLED_AND_UNPUBLISHED_REQUIRES_SMOKE',
    releaseMode: 'INITIAL',
    updateReleaseSupported: false,
    publication: {
      managedByCloudFormation: true,
      apiStack: apiRecoveredAfterCut,
      webStack: webRecoveredAfterCut,
      scheduler: {
        controlledBy: 'PublicationState',
        stackName: stackFor(context, 'api'),
        state: 'DISABLED',
      },
    },
    aliasesChanged: false,
    objectsChanged: false,
    dataFactsChanged: false,
    stacksDeleted: 0,
    secretDeleted: false,
  };
  validateStage7InitialRollbackCheckpoint(rollbackCheckpoint, { config });

  const missingEventDependencies = {
    ...dependencies,
    captureCausality: () => fail('E7_INITIAL_WEB_ROLLBACK_STACK_EVENT_CAUSALITY_INVALID'),
  };
  delete ledger.checkpoints.rollbackInfrastructure;
  delete ledger.checkpoints.webRollbackIntent;
  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'web',
        record: records.web,
        dependencies: missingEventDependencies,
      }),
    (error) => error?.code === 'E7_INITIAL_WEB_ROLLBACK_RESUME_INTENT_MISSING',
  );
  ledger.checkpoints.webRollbackIntent = createInitialRollbackIntent({
    context,
    suffix: 'web',
    record: records.web,
    observed: stackState('web', 'ENABLED'),
  });
  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'web',
        record: records.web,
        dependencies: missingEventDependencies,
      }),
    (error) => error?.code === 'E7_INITIAL_WEB_ROLLBACK_STACK_EVENT_CAUSALITY_INVALID',
  );
  ledger.checkpoints.webRollbackIntent.rollbackRecordSha256 = 'f'.repeat(64);
  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'web',
        record: records.web,
        dependencies,
      }),
    (error) => error?.code === 'E7_INITIAL_WEB_ROLLBACK_RESUME_INTENT_INVALID',
  );
  ledger.checkpoints.webRollbackIntent = createInitialRollbackIntent({
    context,
    suffix: 'web',
    record: records.web,
    observed: stackState('web', 'ENABLED'),
  });
  ledger.checkpoints.webRollbackIntent.stackName = stackFor(context, 'api');
  await assert.rejects(
    () =>
      transitionInitialRollbackPublication({
        context,
        suffix: 'web',
        record: records.web,
        dependencies,
      }),
    (error) => error?.code === 'E7_INITIAL_WEB_ROLLBACK_RESUME_INTENT_INVALID',
  );
  delete ledger.checkpoints.webRollbackIntent;

  const apiRollbackRequestId = initialRollbackClientRequestToken({
    context,
    suffix: 'api',
    record: records.api,
    observed: live.api,
  });
  assert.match(apiRollbackRequestId, /^e7-initial-api-[0-9a-f]{64}$/u);
  const stackEvent = (status, eventId, timestamp, token = apiRollbackRequestId) => ({
    EventId: eventId,
    StackId: live.api.state.stackId,
    StackName: live.api.stackName,
    LogicalResourceId: live.api.stackName,
    PhysicalResourceId: live.api.state.stackId,
    ResourceType: 'AWS::CloudFormation::Stack',
    ResourceStatus: status,
    ClientRequestToken: token,
    Timestamp: timestamp,
  });
  const startedEvent = stackEvent('UPDATE_IN_PROGRESS', 'api-started', '2026-08-17T11:59:00Z');
  const completedEvent = stackEvent('UPDATE_COMPLETE', 'api-completed', '2026-08-17T12:00:00Z');
  const pages = [];
  const pagedCausality = captureInitialRollbackCausality({
    context,
    suffix: 'api',
    observed: live.api,
    intent: apiIntent,
    clientRequestToken: apiRollbackRequestId,
    readPage: ({ nextToken }) => {
      pages.push(nextToken ?? null);
      return nextToken === undefined
        ? { StackEvents: [startedEvent], NextToken: 'opaque.page:2' }
        : { StackEvents: [startedEvent, completedEvent] };
    },
  });
  assert.deepEqual(pages, [null, 'opaque.page:2']);
  assert.equal(pagedCausality.transition, 'UPDATE_IN_PROGRESS_TO_UPDATE_COMPLETE');
  assert.equal(pagedCausality.requestTokenSha256, sha256(apiRollbackRequestId));
  assert.throws(
    () =>
      captureInitialRollbackCausality({
        context,
        suffix: 'api',
        observed: {
          ...live.api,
          state: { ...live.api.state, lastUpdatedTime: '2026-08-17T12:10:00.000Z' },
        },
        intent: apiIntent,
        clientRequestToken: apiRollbackRequestId,
        readPage: () => ({ StackEvents: [startedEvent, completedEvent] }),
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_STACK_EVENT_CAUSALITY_INVALID',
  );
  assert.throws(
    () =>
      captureInitialRollbackCausality({
        context,
        suffix: 'api',
        observed: live.api,
        intent: { ...apiIntent, persistedAtUtc: '2026-08-17T12:02:00.000Z' },
        clientRequestToken: apiRollbackRequestId,
        readPage: () => ({ StackEvents: [startedEvent, completedEvent] }),
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_STACK_EVENT_CAUSALITY_INVALID',
  );
  const stackEventCliCalls = [];
  readInitialRollbackStackEventsPage({
    context: {
      ...context,
      awsCommand: 'aws',
      environmentVariables: {},
      executor: (invocation) => {
        stackEventCliCalls.push(invocation);
        return { status: 0, stdout: JSON.stringify({ StackEvents: [] }), stderr: '' };
      },
    },
    suffix: 'api',
    observed: live.api,
    nextToken: 'opaque.page:2',
  });
  assert.deepEqual(stackEventCliCalls[0].args, [
    'cloudformation',
    'describe-stack-events',
    '--stack-name',
    live.api.stackName,
    '--no-paginate',
    '--next-token',
    'opaque.page:2',
    '--output',
    'json',
    '--region',
    config.aws.region,
    '--no-cli-pager',
  ]);
  assert.throws(
    () =>
      captureInitialRollbackCausality({
        context,
        suffix: 'api',
        observed: live.api,
        intent: apiIntent,
        clientRequestToken: apiRollbackRequestId,
        readPage: () => ({ StackEvents: [startedEvent], NextToken: 'loop' }),
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_STACK_EVENTS_PAGINATION_INVALID',
  );
  assert.throws(
    () =>
      captureInitialRollbackCausality({
        context,
        suffix: 'api',
        observed: live.api,
        intent: apiIntent,
        clientRequestToken: apiRollbackRequestId,
        readPage: () => ({
          StackEvents: [startedEvent, { ...startedEvent, ResourceStatus: 'UPDATE_COMPLETE' }],
        }),
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_STACK_EVENT_ID_COLLISION',
  );
  assert.throws(
    () =>
      captureInitialRollbackCausality({
        context,
        suffix: 'api',
        observed: live.api,
        intent: apiIntent,
        clientRequestToken: apiRollbackRequestId,
        readPage: () => ({
          StackEvents: [
            stackEvent('UPDATE_IN_PROGRESS', 'foreign-start', '2026-08-17T11:59:00Z', 'foreign'),
            stackEvent('UPDATE_COMPLETE', 'foreign-complete', '2026-08-17T12:00:00Z', 'foreign'),
          ],
        }),
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_STACK_EVENT_CAUSALITY_INVALID',
  );
  for (const [status, eventId] of [
    ['UPDATE_IN_PROGRESS', 'later-foreign-update-root'],
    ['UPDATE_ROLLBACK_COMPLETE', 'later-foreign-rollback-root'],
  ]) {
    assert.throws(
      () =>
        captureInitialRollbackCausality({
          context,
          suffix: 'api',
          observed: live.api,
          intent: apiIntent,
          clientRequestToken: apiRollbackRequestId,
          readPage: () => ({
            StackEvents: [
              startedEvent,
              completedEvent,
              stackEvent(status, eventId, '2026-08-17T12:01:00Z', 'foreign'),
            ],
          }),
        }),
      (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_STACK_EVENT_CAUSALITY_INVALID',
    );
  }

  let webTransitions = 0;
  let schedulerPublicationState = 'DISABLED';
  let executeApiEndpointDisabled = true;
  let apiMappings = [];
  const postCausalityReaders = {
    readApiPublication: () => live.api,
    readScheduler: () => ({ State: schedulerPublicationState }),
    readHttpApi: (_context, apiId) => ({
      ApiId: apiId,
      DisableExecuteApiEndpoint: executeApiEndpointDisabled,
    }),
    readApiMappings: () => apiMappings,
  };
  const validWebTransition = await transitionInitialWebRollback({
    context,
    record: records.web,
    apiRecord: records.api,
    apiStack: live.api,
    rollbackEvidence: ledger,
    captureApiCausality: ({ suffix, clientRequestToken }) =>
      causalProof({ suffix, clientRequestToken }),
    ...postCausalityReaders,
    transition: async () => {
      webTransitions += 1;
      return webRecoveredAfterCut;
    },
  });
  assert.deepEqual(validWebTransition.publication, webRecoveredAfterCut);
  assert.equal(webTransitions, 1);
  webTransitions = 0;
  const invalidApiEvidence = structuredClone(ledger);
  invalidApiEvidence.checkpoints.apiRollback.publication.causality.requestTokenSha256 = 'invalid';
  await assert.rejects(
    () =>
      transitionInitialWebRollback({
        context,
        record: records.web,
        apiRecord: records.api,
        apiStack: live.api,
        rollbackEvidence: invalidApiEvidence,
        captureApiCausality: ({ suffix, clientRequestToken }) =>
          causalProof({ suffix, clientRequestToken }),
        ...postCausalityReaders,
        transition: async () => {
          webTransitions += 1;
          return webRecoveredAfterCut;
        },
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_EVIDENCE_INVALID',
  );
  assert.equal(webTransitions, 0);
  await assert.rejects(
    () =>
      transitionInitialWebRollback({
        context,
        record: records.web,
        apiRecord: { recordSha256: 'f'.repeat(64) },
        apiStack: live.api,
        rollbackEvidence: ledger,
        captureApiCausality: ({ suffix, clientRequestToken }) =>
          causalProof({ suffix, clientRequestToken }),
        ...postCausalityReaders,
        transition: async () => {
          webTransitions += 1;
          return webRecoveredAfterCut;
        },
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_EVIDENCE_INVALID',
  );
  assert.equal(webTransitions, 0);
  await assert.rejects(
    () =>
      transitionInitialWebRollback({
        context,
        record: records.web,
        apiRecord: records.api,
        apiStack: live.api,
        rollbackEvidence: ledger,
        captureApiCausality: ({ suffix, clientRequestToken }) => ({
          ...causalProof({ suffix, clientRequestToken }),
          updateCompletedEventIdSha256: sha256('foreign-completed-event'),
        }),
        ...postCausalityReaders,
        transition: async () => {
          webTransitions += 1;
          return webRecoveredAfterCut;
        },
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_EVIDENCE_INVALID',
  );
  assert.equal(webTransitions, 0);
  const stableApiStack = live.api;
  await assert.rejects(
    () =>
      transitionInitialWebRollback({
        context,
        record: records.web,
        apiRecord: records.api,
        apiStack: stableApiStack,
        rollbackEvidence: ledger,
        captureApiCausality: ({ suffix, clientRequestToken }) => {
          live.api = stackState('api', 'ENABLED');
          return causalProof({ suffix, clientRequestToken });
        },
        ...postCausalityReaders,
        transition: async () => {
          webTransitions += 1;
          return webRecoveredAfterCut;
        },
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_POST_CAUSALITY_DRIFT',
  );
  assert.equal(webTransitions, 0);
  live.api = stableApiStack;
  await assert.rejects(
    () =>
      transitionInitialWebRollback({
        context,
        record: records.web,
        apiRecord: records.api,
        apiStack: stableApiStack,
        rollbackEvidence: ledger,
        captureApiCausality: ({ suffix, clientRequestToken }) => {
          schedulerPublicationState = 'ENABLED';
          return causalProof({ suffix, clientRequestToken });
        },
        ...postCausalityReaders,
        transition: async () => {
          webTransitions += 1;
          return webRecoveredAfterCut;
        },
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_POST_CAUSALITY_DRIFT',
  );
  assert.equal(webTransitions, 0);
  schedulerPublicationState = 'DISABLED';
  executeApiEndpointDisabled = false;
  await assert.rejects(
    () =>
      transitionInitialWebRollback({
        context,
        record: records.web,
        apiRecord: records.api,
        apiStack: stableApiStack,
        rollbackEvidence: ledger,
        captureApiCausality: ({ suffix, clientRequestToken }) =>
          causalProof({ suffix, clientRequestToken }),
        ...postCausalityReaders,
        transition: async () => {
          webTransitions += 1;
          return webRecoveredAfterCut;
        },
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_POST_CAUSALITY_DRIFT',
  );
  assert.equal(webTransitions, 0);
  executeApiEndpointDisabled = true;
  apiMappings = [{ ApiMappingId: 'foreign' }];
  await assert.rejects(
    () =>
      transitionInitialWebRollback({
        context,
        record: records.web,
        apiRecord: records.api,
        apiStack: stableApiStack,
        rollbackEvidence: ledger,
        captureApiCausality: ({ suffix, clientRequestToken }) =>
          causalProof({ suffix, clientRequestToken }),
        ...postCausalityReaders,
        transition: async () => {
          webTransitions += 1;
          return webRecoveredAfterCut;
        },
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_POST_CAUSALITY_DRIFT',
  );
  assert.equal(webTransitions, 0);
  apiMappings = [];
  await assert.rejects(
    () =>
      transitionInitialWebRollback({
        context,
        record: records.web,
        apiRecord: records.api,
        apiStack: stableApiStack,
        rollbackEvidence: ledger,
        captureApiCausality: ({ suffix, clientRequestToken }) =>
          causalProof({ suffix, clientRequestToken }),
        ...postCausalityReaders,
        transition: async () => {
          webTransitions += 1;
          executeApiEndpointDisabled = false;
          return webRecoveredAfterCut;
        },
      }),
    (error) => error?.code === 'E7_INITIAL_API_ROLLBACK_POST_CAUSALITY_DRIFT',
  );
  assert.equal(webTransitions, 1);
  executeApiEndpointDisabled = true;
};

export const selfTestAwsOperations = async () => {
  selfTestPreDeploymentIdentityCapture();
  selfTestPreviousPublicationExpectations();
  for (const tool of ['cdk', 'tsx']) {
    const entrypoint = workspaceToolEntrypoint(tool);
    assert.equal(path.isAbsolute(entrypoint), true);
    assert.equal(path.relative(workspaceRoot, entrypoint).startsWith('..'), false);
  }
  assert.equal(
    cdkAppCommand(
      [
        'C:\\Node\\node.exe',
        'C:\\Prueba Técnica\\node_modules\\tsx.mjs',
        'C:\\Prueba Técnica\\infra\\app.ts',
      ],
      'win32',
    ),
    'C:\\Node\\node.exe "C:\\Prueba Técnica\\node_modules\\tsx.mjs" "C:\\Prueba Técnica\\infra\\app.ts"',
  );
  assert.equal(
    cdkAppCommand(
      [
        'C:\\Program Files\\nodejs\\node.exe',
        'C:\\Prueba Técnica\\node_modules\\tsx.mjs',
        'C:\\Prueba Técnica\\infra\\app.ts',
      ],
      'win32',
    ),
    'call "C:\\Program Files\\nodejs\\node.exe" "C:\\Prueba Técnica\\node_modules\\tsx.mjs" "C:\\Prueba Técnica\\infra\\app.ts"',
  );
  assert.equal(
    cdkAppCommand(
      ['/opt/node/bin/node', '/work/repo/node_modules/tsx.mjs', '/work/repo/infra/app.ts'],
      'linux',
    ),
    '/opt/node/bin/node /work/repo/node_modules/tsx.mjs /work/repo/infra/app.ts',
  );
  assert.throws(
    () => cdkAppCommand(['/opt/node/bin/node', '/work/$(invalid)', '/work/app.ts'], 'linux'),
    (error) => error instanceof Stage7AwsError && error.code === 'E7_CDK_APP_COMMAND_INVALID',
  );
  assert.equal(
    RELEASE_RECONCILIATION_RECOVERY_FILE_BINDINGS.find(([flag]) => flag === 'approved-plan')?.[1],
    'approvedDiff',
  );
  assert.equal(normalizeOperationScope(undefined), undefined);
  assert.equal(normalizeOperationScope('full'), undefined);
  assert.equal(normalizeOperationScope('prerelease'), 'prerelease');
  assert.throws(
    () => normalizeOperationScope('production'),
    (error) => error instanceof Stage7AwsError && error.code === 'E7_OPERATION_SCOPE_INVALID',
  );
  await selfTestReleaseReconciliationRecoveryBoundary();
  await selfTestReleaseSuccessorGuardBoundary();
  let invalidRecoveryModeCalls = 0;
  for (const flags of [
    {},
    { 'recover-if-active': true, 'verify-candidate-active-no-action': true },
    { 'verify-candidate-active-no-action': true },
    { 'recover-if-active': true, outcome: 'unexpected.json' },
  ]) {
    await assert.rejects(
      () =>
        recoverVersionedRelease({
          flags,
          executor: () => {
            invalidRecoveryModeCalls += 1;
            throw new Error('unreachable recovery mode canary');
          },
          environmentVariables: {},
        }),
      (error) =>
        error instanceof Stage7AwsError && error.code === 'E7_EMERGENCY_RECOVERY_FLAGS_INVALID',
    );
  }
  assert.equal(invalidRecoveryModeCalls, 0);
  const noActionSelfTestParent = path.join(workspaceRoot, '.stage7', 'self-tests');
  mkdirSync(noActionSelfTestParent, { recursive: true, mode: 0o700 });
  chmodSync(noActionSelfTestParent, 0o700);
  const noActionSelfTestRoot = mkdtempSync(
    path.join(noActionSelfTestParent, 'aws-emergency-no-action-'),
  );
  const missingOutcome = path.join(noActionSelfTestRoot, 'failure-outcome.json');
  const bindingCanary = path.join(noActionSelfTestRoot, 'binding-canary.json');
  let missingInputCalls = 0;
  try {
    await assert.rejects(
      () =>
        recoverVersionedRelease({
          flags: {
            'verify-candidate-active-no-action': true,
            outcome: missingOutcome,
            output: path.join(noActionSelfTestRoot, 'recovery.json'),
          },
          executor: () => {
            missingInputCalls += 1;
            throw new Error('unreachable no-action AWS canary');
          },
          environmentVariables: {},
          now: new Date('2026-08-17T12:00:00.000Z'),
        }),
      (error) =>
        error instanceof Stage7AwsError && error.code === 'E7_EMERGENCY_RECOVERY_SOURCE_MISSING',
    );
    assert.equal(missingInputCalls, 0);
    const failureOutcome = readLocalRollbackJson(
      missingOutcome,
      'E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_MISSING',
    );
    assert.equal(failureOutcome.status, 'FAIL');
    assert.equal(failureOutcome.failureStage, 'INPUT_BINDING');
    assert.equal(validateCandidateActiveNoActionOutcome({ value: failureOutcome }), failureOutcome);
    writeFileSync(bindingCanary, '{"value":1}\n', 'utf8');
    const compactBinding = jsonSourceBinding('manifest', bindingCanary);
    writeFileSync(bindingCanary, '{\n  "value": 1\n}\n', 'utf8');
    const formattedBinding = jsonSourceBinding('manifest', bindingCanary);
    assert.notEqual(compactBinding.rawSha256, formattedBinding.rawSha256);
    assert.equal(compactBinding.canonicalSha256, formattedBinding.canonicalSha256);
    writeFileSync(bindingCanary, '{"value":2}\n', 'utf8');
    const tamperedBinding = jsonSourceBinding('manifest', bindingCanary);
    assert.notEqual(formattedBinding.canonicalSha256, tamperedBinding.canonicalSha256);
  } finally {
    if (existsSync(bindingCanary)) unlinkSync(bindingCanary);
    if (existsSync(missingOutcome)) unlinkSync(missingOutcome);
    rmdirSync(noActionSelfTestRoot);
  }
  assert.equal(existsSync(noActionSelfTestRoot), false);
  await selfTestVersionedRollbackAwsLayer();
  const now = new Date('2026-08-17T12:00:00.000Z');
  const { config } = selfTestConfig(now);
  validateStage7Config(config, { now });
  await selfTestInitialRollbackResumption(config);
  validateOperationScope(config, 'prerelease');
  const apiPublicationContext = {
    config,
    scope: 'prerelease',
    identity: {
      candidateSha: 'a'.repeat(40),
      releaseId: 'rel-20260817-1200-aaaaaaa',
    },
  };
  const activationApiOutputs = {
    CandidateSha: apiPublicationContext.identity.candidateSha,
    ReleaseId: apiPublicationContext.identity.releaseId,
    ApiAliasArn: `arn:aws:lambda:${config.aws.region}:${config.aws.accountId}:function:checkout-${config.environment}-api:live`,
    WorkerAliasArn: `arn:aws:lambda:${config.aws.region}:${config.aws.accountId}:function:checkout-${config.environment}-worker:live`,
    ApiFunctionVersion: '7',
    WorkerFunctionVersion: '8',
    HttpApiId: 'abc123def4',
    ApiCustomDomainName: config.domain.apiHostname,
    ApiOriginUrl: `https://${config.domain.apiHostname}`,
  };
  const activationWebOutputs = {
    CandidateSha: apiPublicationContext.identity.candidateSha,
    ReleaseId: apiPublicationContext.identity.releaseId,
    ApplicationUrl: `https://${config.domain.hostname}`,
    ApiUrl: `https://${config.domain.hostname}/api`,
    ApiDocsUrl: `https://${config.domain.hostname}/api/docs`,
    HealthUrl: `https://${config.domain.hostname}/api/health/ready`,
    PublicOriginParameterName: `/checkout-${config.environment}/public-origin`,
    WebBucketName: `checkout-${config.environment}-web-assets`,
    DistributionId: 'E123456789ABC',
  };
  const activationApiRecord = {
    deployed: apiVersionsFromOutputs(
      apiPublicationContext,
      activationApiOutputs,
      'E7_SELF_TEST_INVALID',
    ),
    publication: { apiId: activationApiOutputs.HttpApiId },
  };
  const activationWebRecord = {
    bucketName: activationWebOutputs.WebBucketName,
    distributionId: activationWebOutputs.DistributionId,
    publicOriginSha256: sha256(activationWebOutputs.ApplicationUrl),
    apiOriginSha256: sha256(activationApiOutputs.ApiOriginUrl),
    publication: { distributionId: activationWebOutputs.DistributionId },
  };
  validateActivationLiveBindings(apiPublicationContext, {
    apiOutputs: activationApiOutputs,
    webOutputs: activationWebOutputs,
    apiRecord: activationApiRecord,
    webRecord: activationWebRecord,
  });
  for (const mutate of [
    ({ apiOutputs }) => {
      apiOutputs.ApiAliasArn = apiOutputs.ApiAliasArn.replace('-api:live', '-foreign:live');
    },
    ({ apiOutputs }) => {
      apiOutputs.WorkerAliasArn = apiOutputs.WorkerAliasArn.replace(
        '-worker:live',
        '-foreign:live',
      );
    },
    ({ apiOutputs }) => {
      apiOutputs.HttpApiId = 'foreign1234';
    },
    ({ apiOutputs }) => {
      apiOutputs.ApiOriginUrl = 'https://api-foreign.example.test';
    },
    ({ webOutputs }) => {
      webOutputs.WebBucketName = 'checkout-foreign-web-assets';
    },
    ({ webOutputs }) => {
      webOutputs.DistributionId = 'EFOREIGN1234';
    },
    ({ webOutputs }) => {
      webOutputs.ApplicationUrl = 'https://foreign.example.test';
    },
  ]) {
    const candidate = {
      apiOutputs: structuredClone(activationApiOutputs),
      webOutputs: structuredClone(activationWebOutputs),
      apiRecord: structuredClone(activationApiRecord),
      webRecord: structuredClone(activationWebRecord),
    };
    mutate(candidate);
    expectCode(
      () => validateActivationLiveBindings(apiPublicationContext, candidate),
      'E7_ACTIVATION_LIVE_BINDING_INVALID',
    );
  }
  const originalTemplate = { Resources: { BoundResource: { Type: 'AWS::SSM::Parameter' } } };
  const originalTemplateCalls = [];
  const originalTemplateContext = {
    ...apiPublicationContext,
    awsCommand: 'aws',
    environmentVariables: {},
    stacks: config.authorization.stacks,
    executor: ({ args }) => {
      originalTemplateCalls.push(args);
      return {
        status: 0,
        stdout: JSON.stringify({ TemplateBody: originalTemplate }),
        stderr: '',
      };
    },
  };
  validateOriginalStackTemplate(
    originalTemplateContext,
    stackFor(originalTemplateContext, 'api'),
    objectSha256(originalTemplate),
  );
  expectCode(
    () =>
      validateOriginalStackTemplate(
        originalTemplateContext,
        stackFor(originalTemplateContext, 'api'),
        objectSha256({ Resources: {} }),
      ),
    'E7_CLOUDFORMATION_ORIGINAL_TEMPLATE_DRIFT',
  );
  assert.equal(originalTemplateCalls.length, 2);
  assert.equal(
    originalTemplateCalls.some((args) => args.includes('update-stack')),
    false,
  );
  for (const args of originalTemplateCalls) {
    assert.deepEqual(args.slice(0, 7), [
      'cloudformation',
      'get-template',
      '--stack-name',
      stackFor(originalTemplateContext, 'api'),
      '--template-stage',
      'Original',
      '--output',
    ]);
  }
  const dataPublicationTemplate = selfTestInitialDataPublicationTemplate(config);
  const apiPublicationTemplate = selfTestInitialApiPublicationTemplate(apiPublicationContext);
  validateInitialApiPublicationContract(
    apiPublicationContext,
    apiPublicationTemplate,
    dataPublicationTemplate,
  );
  const managedApiPublicationContext = {
    ...apiPublicationContext,
    config: {
      ...config,
      authorization: { ...config.authorization, scope: 'NON_MUTATING_PLAN' },
      domain: {
        mode: 'AWS_MANAGED',
        hostname: null,
        apiHostname: null,
        hostedZoneId: null,
        webCertificateArn: null,
        apiCertificateArn: null,
        dnsIncluded: false,
      },
    },
  };
  const managedApiPublicationTemplate = structuredClone(apiPublicationTemplate);
  for (const logicalId of ['ApiCustomDomain', 'ApiDefaultMapping', 'ApiAliasA', 'ApiAliasAAAA']) {
    delete managedApiPublicationTemplate.Resources[logicalId];
  }
  managedApiPublicationTemplate.Resources.HttpApi.Properties.DisableExecuteApiEndpoint = {
    'Fn::If': ['PublicationEnabled', false, true],
  };
  managedApiPublicationTemplate.Outputs.ApiCustomDomainName.Value = 'NONE_MANAGED_PRERELEASE';
  managedApiPublicationTemplate.Outputs.ApiOriginUrl.Value = {
    'Fn::Join': [
      '',
      ['https://', { Ref: 'HttpApi' }, '.execute-api.us-east-1.', { Ref: 'AWS::URLSuffix' }],
    ],
  };
  validateInitialApiPublicationContract(
    managedApiPublicationContext,
    managedApiPublicationTemplate,
    dataPublicationTemplate,
  );
  for (const mutate of [
    (template) => delete template.Resources.ApiCustomDomain,
    (template) => delete template.Resources.ApiDefaultMapping,
    (template) => {
      template.Resources.ExtraApiDomain = structuredClone(template.Resources.ApiCustomDomain);
    },
    (template) => {
      template.Resources.ExtraApiMapping = structuredClone(template.Resources.ApiDefaultMapping);
    },
    (template) => delete template.Resources.ApiDefaultMapping.Condition,
    (template) => {
      template.Resources.ApiDefaultMapping.Properties.ApiId = { Ref: 'ForeignApi' };
    },
    (template) => {
      template.Resources.ApiDefaultMapping.Properties.Stage = { Ref: 'ForeignStage' };
    },
    (template) => {
      template.Resources.ExtraStage = structuredClone(template.Resources.HttpApiDefaultStage);
    },
    (template) => {
      template.Resources.ApiCustomDomain.Properties.DomainName = 'api-foreign.example.test';
    },
    (template) => delete template.Resources.ApiAliasAAAA,
    (template) => {
      template.Resources.ApiAliasA.Properties.Name = 'api-foreign.example.test';
    },
    (template) => {
      template.Outputs.ApiOriginUrl.Value = 'https://api-foreign.example.test';
    },
    (template) => {
      delete template.Resources.ApiRuntime.Properties.Environment.Variables.RUNTIME_SECRET_ARN;
    },
    (template) => {
      template.Resources.WorkerRuntime.Properties.Environment.Variables.RELEASE_ID =
        'rel-20260817-1200-bbbbbbb';
    },
    (template) => {
      template.Resources.ApiRuntime.Properties.Environment.Variables.CANDIDATE_SHA = 'b'.repeat(40);
    },
    (template) => {
      template.Resources.WorkerRuntime.Properties.Environment.Variables.RUNTIME_SECRET_VERSION_ID =
        'b'.repeat(32);
    },
    (template) => {
      template.Resources.ExtraRuntime = structuredClone(template.Resources.ApiRuntime);
    },
    (template) => {
      template.Resources.ApiRuntime.Properties.Environment.Variables.PAYMENTS_ENABLED = 'false';
    },
    (template) => {
      template.Resources.WorkerRuntime.Properties.Environment.Variables.TOKENIZATION_MODE = 'fake';
    },
    (template) => {
      template.Resources.ApiRuntime.Properties.Environment.Variables.APP_ENV = 'preview';
    },
    (template) => {
      template.Resources.WorkerRuntime.Properties.Environment.Variables.AUTO_SEED_CATALOG = 'true';
    },
    (template) => {
      template.Resources.WorkerRuntime.Properties.Environment.Variables.DATA_ADAPTER = 'memory';
    },
    (template) => {
      template.Resources.ApiRuntime.Properties.Environment.Variables.ALLOWED_ORIGIN_PARAMETER_NAME =
        '/checkout-foreign/public-origin';
    },
    (template) => {
      template.Resources.WorkerRuntime.Properties.Environment.Variables.PUBLIC_ASSET_ORIGIN_PARAMETER_NAME =
        '/checkout-foreign/public-origin';
    },
    (template) => {
      template.Resources.ApiRuntime.Properties.Environment.Variables.CATALOG_TABLE_NAME =
        'checkout-foreign-catalog';
    },
    (template) => {
      template.Resources.WorkerRuntime.Properties.Environment.Variables.CHECKOUT_TABLE_NAME =
        structuredClone(
          template.Resources.WorkerRuntime.Properties.Environment.Variables.CATALOG_TABLE_NAME,
        );
    },
    (template) => {
      template.Resources.ApiIntegration.Properties.IntegrationUri = { Ref: 'WorkerAlias' };
    },
    (template) => {
      template.Resources.ApiRoute.Properties.Target = {
        'Fn::Join': ['', ['integrations/', { Ref: 'ForeignIntegration' }]],
      };
    },
    (template) => {
      template.Resources.ReconcileSchedule.Properties.Target.Arn = { Ref: 'ApiAlias' };
    },
    (template) => {
      template.Outputs.ApiAliasArn.Value = { Ref: 'WorkerAlias' };
    },
    (template) => {
      template.Outputs.WorkerFunctionVersion.Value = {
        'Fn::GetAtt': ['ApiVersion', 'Version'],
      };
    },
    (template) => {
      template.Resources.ApiAlias.Properties.FunctionName = { Ref: 'WorkerRuntime' };
    },
    (template) => {
      template.Resources.ApiIntegrationPermission.Properties.FunctionName = {
        Ref: 'WorkerAlias',
      };
    },
    (template) => {
      template.Resources.ApiIntegrationPermission.Properties.SourceArn['Fn::Join'][1][5] = {
        Ref: 'ForeignApi',
      };
    },
    (template) => {
      template.Resources.SchedulerRolePolicy.Properties.PolicyDocument.Statement[0].Resource = {
        Ref: 'ApiAlias',
      };
    },
    (template) => {
      template.Resources.ExtraConditionalBucket = {
        Type: 'AWS::S3::Bucket',
        Condition: 'PublicationEnabled',
        Properties: {},
      };
    },
    (template) => {
      template.Resources.ApiRuntime.Properties.Metadata = {
        'Fn::If': ['PublicationEnabled', 'enabled', 'disabled'],
      };
    },
    (template) => {
      template.Resources.ApiRuntime.Properties.Tags = [
        { Key: 'hidden-publication-control', Value: { 'Fn::Sub': '${PublicationState}' } },
      ];
    },
  ]) {
    const invalidTemplate = structuredClone(apiPublicationTemplate);
    mutate(invalidTemplate);
    expectCode(
      () =>
        validateInitialApiPublicationContract(
          apiPublicationContext,
          invalidTemplate,
          dataPublicationTemplate,
        ),
      'E7_CLOUD_ASSEMBLY_INITIAL_API_PUBLICATION_INVALID',
    );
  }
  for (const mutate of [
    (template) => {
      template.Resources.CatalogTable.Properties.TableName = 'checkout-foreign-catalog';
    },
    (template) => {
      template.Outputs.CheckoutTableName.Value = { Ref: 'CatalogTable' };
    },
    (template) => {
      template.Outputs.CatalogTableExport.Export.Name =
        template.Outputs.CheckoutTableExport.Export.Name;
    },
    (template) => {
      template.Resources.ExtraTable = structuredClone(template.Resources.CatalogTable);
    },
  ]) {
    const invalidDataTemplate = structuredClone(dataPublicationTemplate);
    mutate(invalidDataTemplate);
    expectCode(
      () =>
        validateInitialApiPublicationContract(
          apiPublicationContext,
          apiPublicationTemplate,
          invalidDataTemplate,
        ),
      'E7_CLOUD_ASSEMBLY_INITIAL_API_PUBLICATION_INVALID',
    );
  }
  const webDistributionConfig = {
    Origins: [
      {
        Id: 'ApiOrigin',
        DomainName: config.domain.apiHostname,
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
          OriginSSLProtocols: ['TLSv1.2'],
        },
      },
    ],
    CacheBehaviors: [{ PathPattern: 'api/*', TargetOriginId: 'ApiOrigin' }],
  };
  validateWebApiOriginContract(apiPublicationContext, webDistributionConfig);
  for (const invalidApiOrigin of [
    'api-foreign.example.test',
    'abc123def4.execute-api.us-east-1.amazonaws.com',
  ]) {
    const invalidDistribution = structuredClone(webDistributionConfig);
    invalidDistribution.Origins[0].DomainName = invalidApiOrigin;
    expectCode(
      () => validateWebApiOriginContract(apiPublicationContext, invalidDistribution),
      'E7_CLOUD_ASSEMBLY_INITIAL_WEB_PUBLICATION_INVALID',
    );
  }
  const webPublicationTemplate = selfTestInitialWebPublicationTemplate(apiPublicationContext);
  validateInitialWebPublicationContract(apiPublicationContext, webPublicationTemplate);
  const managedWebPublicationTemplate = selfTestInitialWebPublicationTemplate(
    managedApiPublicationContext,
  );
  validateInitialWebPublicationContract(
    managedApiPublicationContext,
    managedWebPublicationTemplate,
  );
  for (const mutate of [
    (template) => {
      template.Resources.WebDistribution.Properties.DistributionConfig.Origins.push({
        Id: 'ForeignOrigin',
        DomainName: 'foreign.example.test',
        CustomOriginConfig: {
          OriginProtocolPolicy: 'https-only',
          OriginSSLProtocols: ['TLSv1.2'],
        },
      });
      template.Resources.WebDistribution.Properties.DistributionConfig.CacheBehaviors.push({
        PathPattern: 'api/private/*',
        TargetOriginId: 'ForeignOrigin',
      });
    },
    (template) => {
      template.Resources.WebDistribution.Properties.DistributionConfig.Origins[1].DomainName =
        'abc123def4.execute-api.us-east-1.amazonaws.com';
    },
    (template) => {
      delete template.Resources.WebDistribution.Properties.DistributionConfig.Aliases;
    },
    (template) => {
      template.Resources.WebDistribution.Properties.DistributionConfig.ViewerCertificate.AcmCertificateArn =
        'arn:aws:acm:us-east-1:123456789012:certificate/ffffffff-ffff-4fff-8fff-ffffffffffff';
    },
    (template) => delete template.Resources.WebAliasAAAA,
    (template) => {
      template.Resources.WebAliasA.Properties.HostedZoneId = 'ZFOREIGN123456';
    },
    (template) => {
      template.Outputs.ApplicationUrl.Value = 'https://foreign.example.test';
    },
    (template) => {
      template.Outputs.ApiUrl.Value = `https://${config.domain.hostname}/foreign`;
    },
    (template) => {
      template.Outputs.ApiDocsUrl.Value = `https://${config.domain.hostname}/api/foreign`;
    },
    (template) => {
      template.Outputs.HealthUrl.Value = `https://${config.domain.hostname}/api/health/live`;
    },
    (template) => {
      template.Resources.PublicOriginParameter.Properties.Value = 'https://foreign.example.test';
    },
    (template) => {
      template.Resources.WebDistribution.Properties.DistributionConfig.CacheBehaviors[1].TargetOriginId =
        'WebOrigin';
    },
    (template) => {
      template.Resources.WebBucket.Properties.PublicAccessBlockConfiguration.BlockPublicPolicy = false;
    },
    (template) => {
      template.Resources.WebBucketPolicy.Properties.PolicyDocument.Statement[2].Principal = {
        AWS: '*',
      };
    },
    (template) => {
      template.Resources.ExtraBucket = {
        Type: 'AWS::S3::Bucket',
        Condition: 'PublicationEnabled',
        Properties: {},
      };
    },
    (template) => {
      template.Resources.WebBucket.Properties.Metadata = {
        'Fn::If': ['PublicationEnabled', 'enabled', 'disabled'],
      };
    },
    (template) => {
      template.Resources.WebBucket.Properties.Tags = [
        { Key: 'hidden-publication-control', Value: { 'Fn::Sub': '${PublicationEnabled}' } },
      ];
    },
  ]) {
    const invalidTemplate = structuredClone(webPublicationTemplate);
    mutate(invalidTemplate);
    expectCode(
      () => validateInitialWebPublicationContract(apiPublicationContext, invalidTemplate),
      'E7_CLOUD_ASSEMBLY_INITIAL_WEB_PUBLICATION_INVALID',
    );
  }
  for (const domain of [
    {
      mode: 'AWS_MANAGED',
      hostname: null,
      apiHostname: null,
      hostedZoneId: null,
      webCertificateArn: null,
      apiCertificateArn: null,
      dnsIncluded: false,
    },
    null,
  ]) {
    expectCode(
      () => validateOperationScope({ ...config, domain }, 'prerelease'),
      'E7_PRERELEASE_BOUNDARY_INVALID',
    );
  }
  const directCleanupCalls = [];
  const directCleanupStackName = `checkout-${config.environment}-web`;
  const directCleanupStackId = `arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/${directCleanupStackName}/12345678-1234-4123-8123-123456789012`;
  const directCleanupTags = {
    Project: 'checkout',
    ManagedBy: 'cdk',
    Environment: config.environment,
    CandidateSha: apiPublicationContext.identity.candidateSha,
    ReleaseId: apiPublicationContext.identity.releaseId,
    ExpiresOn: config.cleanup.expiresAtUtc.slice(0, 10),
    CleanupExpiresAtUtc: config.cleanup.expiresAtUtc,
    CostCenter: 'technical-assessment',
    DataClass: 'synthetic-only',
    Owner: config.authorization.ownerAlias,
    PaymentMode: 'sandbox',
  };
  const directCleanupState = {
    exists: true,
    outputs: {
      CandidateSha: apiPublicationContext.identity.candidateSha,
      ReleaseId: apiPublicationContext.identity.releaseId,
    },
    parameters: {},
    tags: directCleanupTags,
    stackStatus: 'UPDATE_COMPLETE',
    stackId: directCleanupStackId,
    creationTime: '2026-08-17T11:00:00.000Z',
    lastUpdatedTime: '2026-08-17T12:00:00.000Z',
    terminationProtection: false,
  };
  let directCleanupDescribeCalls = 0;
  const directCleanupTemplate = { Resources: { WebBucket: { Type: 'AWS::S3::Bucket' } } };
  const directCleanupContext = {
    config,
    identity: apiPublicationContext.identity,
    stacks: config.authorization.stacks,
    awsCommand: 'aws',
    childEnvironment: {},
    environmentVariables: {},
    executor: ({ command, args }) => {
      directCleanupCalls.push({ command, args });
      assert.equal(command, 'aws');
      if (args.includes('describe-stacks')) {
        const stackName = args[args.indexOf('--stack-name') + 1];
        directCleanupDescribeCalls += 1;
        if (directCleanupDescribeCalls === 1) {
          return {
            status: 0,
            stdout: JSON.stringify({
              Stacks: [
                {
                  StackName: directCleanupStackName,
                  StackId: directCleanupStackId,
                  StackStatus: 'UPDATE_COMPLETE',
                  CreationTime: directCleanupState.creationTime,
                  LastUpdatedTime: directCleanupState.lastUpdatedTime,
                  EnableTerminationProtection: false,
                  Outputs: Object.entries(directCleanupState.outputs).map(
                    ([OutputKey, OutputValue]) => ({ OutputKey, OutputValue }),
                  ),
                  Tags: Object.entries(directCleanupTags).map(([Key, Value]) => ({ Key, Value })),
                },
              ],
            }),
            stderr: '',
          };
        }
        return {
          status: 255,
          stdout: '',
          stderr: `ValidationError: Stack with id ${stackName} does not exist`,
        };
      }
      if (args.includes('get-template')) {
        return {
          status: 0,
          stdout: JSON.stringify({ TemplateBody: directCleanupTemplate }),
          stderr: '',
        };
      }
      return { status: 0, stdout: '', stderr: '' };
    },
  };
  const directCleanupExpected = validateCleanupStackState(
    directCleanupContext,
    'web',
    directCleanupState,
  );
  directCleanupExpected.templateSha256 = objectSha256(directCleanupTemplate);
  assert.equal(
    refreshCleanupStackState(
      directCleanupContext,
      'web',
      directCleanupState,
      directCleanupExpected,
      {
        validateTemplate: (_context, stackId, expectedSha256) => {
          assert.equal(stackId, directCleanupStackId);
          assert.equal(expectedSha256, directCleanupExpected.templateSha256);
        },
      },
    ).stackId,
    directCleanupStackId,
  );
  const replacementCleanupState = {
    ...directCleanupState,
    stackId: directCleanupStackId.replace(
      '12345678-1234-4123-8123-123456789012',
      'fedcba98-dcba-4cba-8cba-fedcba987654',
    ),
  };
  expectCode(
    () =>
      refreshCleanupStackState(
        directCleanupContext,
        'web',
        replacementCleanupState,
        directCleanupExpected,
        { validateTemplate: () => undefined },
      ),
    'E7_CLEANUP_STACK_IDENTITY_INVALID',
  );
  const partialCleanupStates = new Map(
    STACK_SUFFIXES.map((suffix) => [suffix, { exists: suffix !== 'web' }]),
  );
  const partialCleanupValidated = new Map(
    STACK_SUFFIXES.map((suffix) => [suffix, { stackName: stackFor(directCleanupContext, suffix) }]),
  );
  const deletedNow = [];
  assert.deepEqual(
    destroyCleanupStackSet(
      directCleanupContext,
      partialCleanupStates,
      partialCleanupValidated,
      (_context, suffix) => {
        deletedNow.push(suffix);
        return stackFor(directCleanupContext, suffix);
      },
    ),
    [...STACK_SUFFIXES].reverse().map((suffix) => stackFor(directCleanupContext, suffix)),
  );
  assert.deepEqual(deletedNow, ['observability', 'api', 'data']);
  assert.equal(validateCleanupStackState(directCleanupContext, 'data', { exists: false }), null);
  for (const mutate of [
    (state) => {
      state.outputs.CandidateSha = 'b'.repeat(40);
    },
    (state) => {
      state.tags.ManagedBy = 'foreign';
    },
    (state) => {
      state.tags.Owner = 'foreign-owner';
    },
    (state) => {
      state.tags.ForeignOwnership = 'true';
    },
    (state) => {
      state.stackId = state.stackId.replace(directCleanupStackName, 'checkout-foreign-web');
    },
    (state) => {
      state.terminationProtection = true;
    },
  ]) {
    const invalidState = structuredClone(directCleanupState);
    mutate(invalidState);
    expectCode(
      () => validateCleanupStackState(directCleanupContext, 'web', invalidState),
      'E7_CLEANUP_STACK_IDENTITY_INVALID',
    );
  }
  const racedState = structuredClone(directCleanupState);
  racedState.lastUpdatedTime = '2026-08-17T12:01:00.000Z';
  expectCode(
    () =>
      validateCleanupStackState(directCleanupContext, 'web', racedState, {
        expectedFingerprint: directCleanupExpected.fingerprint,
      }),
    'E7_CLEANUP_STACK_IDENTITY_INVALID',
  );
  assert.equal(
    destroyStack(directCleanupContext, 'web', directCleanupExpected),
    directCleanupStackName,
  );
  assert.equal(directCleanupCalls.length, 5);
  assert.equal(
    directCleanupCalls.some(({ command, args }) => command !== 'aws' || args.includes('destroy')),
    false,
  );
  const deleteCall = directCleanupCalls.find(({ args }) => args.includes('delete-stack'));
  assert.equal(deleteCall.args[deleteCall.args.indexOf('--stack-name') + 1], directCleanupStackId);
  assert.equal(
    deleteCall.args[deleteCall.args.indexOf('--role-arn') + 1],
    cloudFormationExecutionRoleArn(config),
  );
  assert.equal(
    directCleanupCalls.some(({ args }) => args.includes('stack-delete-complete')),
    true,
  );
  const driftDetectionCalls = [];
  const driftDetectionId = '12345678-1234-4123-8123-123456789012';
  const driftContext = {
    ...directCleanupContext,
    executor: ({ command, args }) => {
      driftDetectionCalls.push({ command, args });
      if (args.includes('detect-stack-drift')) {
        assert.equal(args[args.indexOf('--stack-name') + 1], directCleanupStackId);
        return {
          status: 0,
          stdout: JSON.stringify({ StackDriftDetectionId: driftDetectionId }),
          stderr: '',
        };
      }
      if (args.includes('describe-stack-drift-detection-status')) {
        return {
          status: 0,
          stdout: JSON.stringify({
            StackDriftDetectionId: driftDetectionId,
            StackId: replacementCleanupState.stackId,
            DetectionStatus: 'DETECTION_COMPLETE',
            StackDriftStatus: 'IN_SYNC',
            DriftedStackResourceCount: 0,
          }),
          stderr: '',
        };
      }
      throw new Error(`unexpected drift canary operation ${args.slice(0, 2).join(':')}`);
    },
  };
  await assert.rejects(
    () =>
      detectStackDrift(driftContext, directCleanupStackName, {
        expectedStackId: directCleanupStackId,
      }),
    (error) => error?.code === 'E7_DRIFT_DETECTION_STATUS_INVALID',
  );
  assert.equal(
    driftDetectionCalls.some(({ args }) =>
      ['update-stack', 'delete-stack'].some((operation) => args.includes(operation)),
    ),
    false,
  );
  const directory = mkdtempSync(path.join(tmpdir(), 'checkout-stage7-aws-ops-selftest-'));
  const configPath = path.join(directory, 'config.json');
  const journalRoleAuthorityPath = path.join(
    directory,
    'stage7-release-journal-role-effective-permissions.json',
  );
  const journalRoleAuthority = createReleaseSuccessorIamAuthoritySelfTestFixture();
  assert.equal(
    directory.startsWith(path.join(tmpdir(), 'checkout-stage7-aws-ops-selftest-')),
    true,
  );
  writeFileSync(configPath, `${JSON.stringify(config)}\n`, { encoding: 'utf8', mode: 0o600 });
  writeFileSync(journalRoleAuthorityPath, `${JSON.stringify(journalRoleAuthority)}\n`, {
    encoding: 'utf8',
    mode: 0o600,
  });
  let fakeCalls = 0;
  const fakeExecutor = ({ command, args }) => {
    fakeCalls += 1;
    assert.equal(command, commandName('aws'));
    assert.deepEqual(args.slice(0, 2), ['sts', 'get-caller-identity']);
    return {
      status: 0,
      stdout: JSON.stringify({
        Account: config.aws.accountId,
        Arn: `arn:aws:sts::${config.aws.accountId}:assumed-role/release-read/e7-canary`,
        UserId: 'CANARY:e7-canary',
      }),
      stderr: '',
    };
  };
  const baseEnvironment = {
    STAGE7_CONFIG: configPath,
    STAGE7_CANDIDATE_SHA: 'a'.repeat(40),
    STAGE7_RELEASE_ID: `rel-20260817-1200-${'a'.repeat(7)}`,
    STAGE7_ENVIRONMENT: config.environment,
    STAGE7_AWS_ACCOUNT_ID: config.aws.accountId,
    STAGE7_AWS_REGION: config.aws.region,
    AWS_REGION: config.aws.region,
    AWS_DEFAULT_REGION: config.aws.region,
    AWS_ACCESS_KEY_ID: ['ASI', 'CANARYONLY'].join(''),
    AWS_SECRET_ACCESS_KEY: ['synthetic', 'canary', 'only'].join('-'),
    AWS_SESSION_TOKEN: ['synthetic', 'session', 'canary'].join('-'),
    GITHUB_ACTIONS: 'true',
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_REPOSITORY: 'ivanmonsalve0404/async-checkout-demo',
    GITHUB_REF: 'refs/heads/master',
    GITHUB_TOKEN: 'synthetic-readiness-token-for-selftest',
    GITHUB_SHA: 'a'.repeat(40),
    CONFIRM_DEPLOY: 'true',
    STAGE7_PROTECTED_ENVIRONMENT: 'assessment-prerelease',
    STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN: `arn:aws:iam::${config.aws.accountId}:role/checkout/cleanup-watchdog`,
  };
  for (const [key, value, code] of [
    ['NODE_OPTIONS', '--import=foreign.mjs', 'E7_CHILD_PROCESS_ENVIRONMENT_INVALID'],
    ['AWS_ENDPOINT_URL', 'https://foreign.example.test', 'E7_CHILD_PROCESS_ENVIRONMENT_INVALID'],
    ['HTTPS_PROXY', 'https://foreign.example.test', 'E7_CHILD_PROCESS_ENVIRONMENT_INVALID'],
    ['STAGE7_AWS_COMMAND', 'foreign-aws.exe', 'E7_PROTECTED_TOOL_COMMAND_INVALID'],
    ['STAGE7_PNPM_COMMAND', 'foreign-pnpm.exe', 'E7_PROTECTED_TOOL_COMMAND_INVALID'],
  ]) {
    expectCode(
      () =>
        loadOperationContext({
          capability: 'read',
          scope: 'prerelease',
          executor: fakeExecutor,
          environmentVariables: { ...baseEnvironment, [key]: value },
          now,
          requireAws: true,
        }),
      code,
    );
  }
  expectCode(
    () =>
      loadOperationContext({
        capability: 'read',
        scope: 'prerelease',
        executor: fakeExecutor,
        environmentVariables: { ...baseEnvironment, aws_region: config.aws.region },
        now,
        requireAws: true,
      }),
    'E7_CHILD_PROCESS_ENVIRONMENT_INVALID',
  );
  const sanitizedEnvironmentContext = loadOperationContext({
    capability: 'read',
    scope: 'prerelease',
    executor: fakeExecutor,
    environmentVariables: {
      ...baseEnvironment,
      INIT_CWD: 'C:\\foreign',
      PNPM_HOME: 'C:\\foreign-pnpm',
      npm_config_script_shell: 'foreign-shell',
    },
    now,
    requireAws: true,
  });
  assert.equal(sanitizedEnvironmentContext.childEnvironment.INIT_CWD, undefined);
  assert.equal(sanitizedEnvironmentContext.childEnvironment.PNPM_HOME, undefined);
  assert.equal(sanitizedEnvironmentContext.childEnvironment.npm_config_script_shell, undefined);
  assert.deepEqual(Object.keys(sanitizedEnvironmentContext.childEnvironment).toSorted(), [
    'AWS_ACCESS_KEY_ID',
    'AWS_DEFAULT_REGION',
    'AWS_EC2_METADATA_DISABLED',
    'AWS_REGION',
    'AWS_SECRET_ACCESS_KEY',
    'AWS_SESSION_TOKEN',
    'CI',
  ]);
  assert.equal(fakeCalls, 0, 'child environment canaries must fail before executor invocation');
  let offlineSynthAwsCalls = 0;
  const offlineSynthContext = loadOperationContext({
    capability: 'read',
    scope: 'prerelease',
    flags: { scope: 'prerelease', initial: true },
    executor: () => {
      offlineSynthAwsCalls += 1;
      throw new Error('offline synth must not invoke AWS');
    },
    environmentVariables: baseEnvironment,
    now,
    requireAws: false,
    allowPlan: true,
  });
  assert.equal(offlineSynthContext.config.domain.mode, 'CUSTOM_AUTHORIZED');
  assert.deepEqual(offlineSynthCloudAuthority(), {
    awsIdentity: null,
    certificates: [],
    hostedZone: null,
  });
  assert.deepEqual(Object.keys(offlineSynthContext.childEnvironment).toSorted(), [
    'AWS_EC2_METADATA_DISABLED',
    'CI',
  ]);
  assert.equal(
    Object.keys(offlineSynthContext.childEnvironment).some((key) =>
      /^(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_REGION|AWS_DEFAULT_REGION)$/u.test(
        key,
      ),
    ),
    false,
  );
  const emittedSynthContextKeys = Object.keys(synthContextValues(offlineSynthContext)).toSorted();
  const infraAppSource = readFileSync(path.join(workspaceRoot, 'infra/bin/app.ts'), 'utf8');
  const consumedSynthContextKeys = [...infraAppSource.matchAll(/tryGetContext\('([^']+)'\)/gu)]
    .map(([, key]) => key)
    .toSorted();
  assert.deepEqual(
    emittedSynthContextKeys,
    consumedSynthContextKeys,
    'offline synth and the CDK entrypoint must share the exact context-key contract',
  );
  assert.equal(offlineSynthAwsCalls, 0, 'custom-domain synth preflight must remain AWS-offline');
  try {
    for (const invoke of [
      () =>
        deployData({
          flags: { scope: 'prerelease' },
          executor: fakeExecutor,
          environmentVariables: baseEnvironment,
          now,
        }),
      () =>
        seedRelease({
          flags: { scope: 'prerelease' },
          executor: fakeExecutor,
          environmentVariables: baseEnvironment,
          now,
        }),
      () =>
        activateRelease({
          flags: { scope: 'prerelease' },
          executor: fakeExecutor,
          environmentVariables: baseEnvironment,
          now,
        }),
      () =>
        cleanupRelease({
          flags: { scope: 'prerelease', 'ephemeral-only': true, 'register-expiry': true },
          executor: fakeExecutor,
          environmentVariables: baseEnvironment,
          now,
        }),
    ]) {
      await assert.rejects(
        invoke,
        (error) =>
          error instanceof Stage7AwsError && error.code === 'E7_PRERELEASE_SAFETY_INPUT_REQUIRED',
      );
      assert.equal(fakeCalls, 0);
    }
    for (const flags of [
      {
        scope: 'prerelease',
        'journal-role-effective-permissions': journalRoleAuthorityPath,
      },
      {
        scope: 'prerelease',
        'aws-auth': path.join(directory, 'unused-prerelease-aws-auth.json'),
        'journal-role-effective-permissions': journalRoleAuthorityPath,
      },
    ]) {
      expectCode(
        () =>
          loadOperationContext({
            capability: 'deploy',
            scope: 'prerelease',
            flags,
            executor: fakeExecutor,
            environmentVariables: baseEnvironment,
            now,
            requireAws: true,
          }),
        'E7_RELEASE_JOURNAL_ROLE_AUTHORITY_FORBIDDEN_FOR_PRERELEASE',
      );
    }
    assert.equal(fakeCalls, 0, 'prerelease journal authority must fail before AWS execution');
    await assert.rejects(
      () =>
        deployData({
          flags: {
            scope: 'prerelease',
            'journal-role-effective-permissions': journalRoleAuthorityPath,
          },
          executor: fakeExecutor,
          environmentVariables: baseEnvironment,
          now,
        }),
      (error) =>
        error instanceof Stage7AwsError &&
        error.code === 'E7_RELEASE_JOURNAL_ROLE_AUTHORITY_FORBIDDEN_FOR_PRERELEASE',
    );
    assert.equal(
      fakeCalls,
      0,
      'prerelease journal authority must fail before readiness or AWS adapters',
    );
    const context = loadOperationContext({
      capability: 'read',
      scope: 'prerelease',
      executor: fakeExecutor,
      environmentVariables: baseEnvironment,
      now,
      requireAws: true,
    });
    assert.equal(context.stacks.length, 4);
    assert.equal(publicationMode(context), 'EPHEMERAL_NON_PUBLIC');
    assert.equal(publicationMode({ ...context, scope: undefined }), 'VERSIONED_UPDATE_CLOSED');
    const syntheticPublicKey = generateKeyPairSync('rsa', { modulusLength: 2048 })
      .publicKey.export({ format: 'pem', type: 'spki' })
      .toString();
    const keyGroupDocument = {
      ETag: 'synthetic-key-group-etag',
      KeyGroup: {
        Id: config.prereleaseAccess.keyGroupId,
        KeyGroupConfig: {
          Name: 'stage7-synthetic-key-group',
          Items: [config.prereleaseAccess.publicKeyId],
        },
      },
    };
    const publicKeyDocument = {
      ETag: 'synthetic-public-key-etag',
      PublicKey: {
        Id: config.prereleaseAccess.publicKeyId,
        PublicKeyConfig: {
          Name: 'stage7-synthetic-public-key',
          EncodedKey: syntheticPublicKey,
        },
      },
    };
    const runtimeSecretDocument = {
      ARN: config.prereleaseAccess.originTokenSecretArn,
      RotationEnabled: false,
      VersionIdsToStages: {
        [config.prereleaseAccess.originTokenSecretVersionId]: ['AWSCURRENT'],
      },
    };
    const runtimeSecretBinding = validateRuntimeSecretReferenceDocument(
      context,
      runtimeSecretDocument,
    );
    assert.equal(runtimeSecretBinding.decision, 'PASS');
    assert.equal(validateRuntimeSecretReferenceEvidence(context, runtimeSecretBinding), true);
    expectCode(
      () =>
        validateRuntimeSecretReferenceDocument(context, {
          ...runtimeSecretDocument,
          VersionIdsToStages: { ['b'.repeat(32)]: ['AWSCURRENT'] },
        }),
      'E7_RUNTIME_SECRET_VERSION_MISMATCH',
    );
    expectCode(
      () =>
        validateRuntimeSecretReferenceDocument(context, {
          ...runtimeSecretDocument,
          VersionIdsToStages: {},
        }),
      'E7_RUNTIME_SECRET_VERSION_MISMATCH',
    );
    expectCode(
      () =>
        validateRuntimeSecretReferenceDocument(context, {
          ...runtimeSecretDocument,
          RotationEnabled: true,
        }),
      'E7_RUNTIME_SECRET_VERSION_MISMATCH',
    );
    const accessBinding = validatePrereleaseAccessDocuments(
      context,
      keyGroupDocument,
      publicKeyDocument,
    );
    assert.equal(accessBinding.decision, 'PASS');
    assert.equal(accessBinding.keyGroupPublicKeyCount, 1);
    assert.equal(validatePrereleaseAccessEvidence(context, accessBinding), true);
    assert.equal(
      validatePrereleaseAccessEvidence(context, {
        ...accessBinding,
        originTokenSecretVersionIdSha256: sha256('stale-version'),
      }),
      false,
    );
    assert.equal(
      validatePrereleaseAccessDocuments(
        { ...context, scope: undefined },
        keyGroupDocument,
        publicKeyDocument,
      ),
      null,
    );
    expectCode(
      () =>
        validatePrereleaseAccessDocuments(
          context,
          {
            ...keyGroupDocument,
            KeyGroup: {
              ...keyGroupDocument.KeyGroup,
              KeyGroupConfig: {
                ...keyGroupDocument.KeyGroup.KeyGroupConfig,
                Items: ['K9DIFFERENTPUBLICKEY'],
              },
            },
          },
          publicKeyDocument,
        ),
      'E7_PRERELEASE_ACCESS_BINDING_INVALID',
    );
    expectCode(
      () =>
        validatePrereleaseAccessDocuments(context, keyGroupDocument, {
          ...publicKeyDocument,
          PublicKey: {
            ...publicKeyDocument.PublicKey,
            Id: 'K9DIFFERENTPUBLICKEY',
          },
        }),
      'E7_PRERELEASE_ACCESS_BINDING_INVALID',
    );
    assert.equal(
      certificateNameCovers('checkout.example.invalid', 'checkout.example.invalid'),
      true,
    );
    assert.equal(certificateNameCovers('*.example.invalid', 'checkout.example.invalid'), true);
    assert.equal(certificateNameCovers('*.example.invalid', 'a.checkout.example.invalid'), false);
    const certificateArn = `arn:aws:acm:us-east-1:${config.aws.accountId}:certificate/11111111-1111-1111-1111-111111111111`;
    const certificateRegions = [];
    const certificateContext = {
      ...context,
      executor: ({ args }) => {
        const regionIndex = args.indexOf('--region');
        certificateRegions.push(args[regionIndex + 1]);
        return {
          status: 0,
          stderr: '',
          stdout: JSON.stringify({
            Certificate: {
              CertificateArn: certificateArn,
              DomainName: '*.example.invalid',
              SubjectAlternativeNames: ['*.example.invalid'],
              Status: 'ISSUED',
              Type: 'AMAZON_ISSUED',
              KeyAlgorithm: 'RSA_2048',
              NotAfter: '2027-08-17T12:00:00.000Z',
            },
          }),
        };
      },
    };
    assert.equal(
      validateCertificateAws(certificateContext, {
        arn: certificateArn,
        hostname: 'checkout.example.invalid',
        purpose: 'WEB_CLOUDFRONT',
        region: 'us-east-1',
      }).status,
      'ISSUED',
    );
    assert.deepEqual(certificateRegions, ['us-east-1']);
    const seedEnvironment = seedRuntimeEnvironment(context, 'https://prerelease.example.invalid');
    assert.equal(seedEnvironment.SANDBOX_AUTHORIZED_UNTIL_UTC, config.authorization.expiresAtUtc);
    assert.deepEqual(
      {
        CANDIDATE_SHA: seedEnvironment.CANDIDATE_SHA,
        RELEASE_ID: seedEnvironment.RELEASE_ID,
        RUNTIME_SECRET_VERSION_ID: seedEnvironment.RUNTIME_SECRET_VERSION_ID,
        PRERELEASE_ACCESS_MODE: seedEnvironment.PRERELEASE_ACCESS_MODE,
      },
      {
        CANDIDATE_SHA: context.identity.candidateSha,
        RELEASE_ID: context.identity.releaseId,
        RUNTIME_SECRET_VERSION_ID: config.prereleaseAccess.originTokenSecretVersionId,
        PRERELEASE_ACCESS_MODE: 'cloudfront_signed_cookie',
      },
    );
    for (const key of [
      'CANDIDATE_SHA',
      'RELEASE_ID',
      'RUNTIME_SECRET_VERSION_ID',
      'PRERELEASE_ACCESS_MODE',
      'DATA_ADAPTER',
    ]) {
      expectCode(
        () =>
          validateSeedRuntimeEnvironment(context, 'https://prerelease.example.invalid', {
            ...seedEnvironment,
            [key]: 'tampered',
          }),
        'E7_SEED_RUNTIME_ENVIRONMENT_INVALID',
      );
    }
    expectCode(
      () =>
        seedRuntimeEnvironment(
          {
            ...context,
            config: {
              ...context.config,
              authorization: { ...context.config.authorization, expiresAtUtc: undefined },
            },
          },
          'https://prerelease.example.invalid',
        ),
      'E7_SEED_SANDBOX_AUTHORIZATION_INVALID',
    );
    assert.equal(revalidateAwsIdentity(context).accountSuffix, config.aws.accountId.slice(-4));
    assert.equal(fakeCalls, 1);
    const expiredCleanupContext = loadOperationContext({
      capability: 'cleanup',
      scope: 'prerelease',
      executor: fakeExecutor,
      environmentVariables: baseEnvironment,
      now: new Date(now.getTime() + 9 * 60 * 60 * 1000),
      requireAws: false,
      windowMode: 'expired-cleanup',
    });
    assert.equal(expiredCleanupContext.config.environment, config.environment);
    expectCode(
      () =>
        loadOperationContext({
          capability: 'cleanup',
          scope: 'prerelease',
          executor: fakeExecutor,
          environmentVariables: baseEnvironment,
          now: new Date(now.getTime() + 150 * 60 * 1000),
          requireAws: false,
          windowMode: 'expired-cleanup',
        }),
      'E7_CLEANUP_EXPIRY_NOT_REACHED',
    );
    assert.equal(
      assumedRoleMatches(
        `arn:aws:sts::${config.aws.accountId}:assumed-role/release-read/e7-canary`,
        config.aws.roles.readRoleArn,
      ),
      true,
    );
    assert.equal(
      assumedRoleMatches(
        `arn:aws:sts::${config.aws.accountId}:assumed-role/release-deploy/e7-canary`,
        config.aws.roles.readRoleArn,
      ),
      false,
    );
    for (const caller of [
      {
        Account: '999999999999',
        Arn: 'arn:aws:sts::999999999999:assumed-role/release-read/e7-canary',
      },
      {
        Account: config.aws.accountId,
        Arn: `arn:aws:sts::${config.aws.accountId}:assumed-role/release-deploy/e7-canary`,
      },
    ]) {
      const mismatchContext = loadOperationContext({
        capability: 'read',
        scope: 'prerelease',
        executor: () => ({ status: 0, stdout: JSON.stringify(caller), stderr: '' }),
        environmentVariables: baseEnvironment,
        now,
        requireAws: true,
      });
      expectCode(() => revalidateAwsIdentity(mismatchContext), 'E7_AWS_IDENTITY_MISMATCH');
    }

    expectCode(
      () =>
        loadOperationContext({
          capability: 'read',
          scope: 'prerelease',
          executor: fakeExecutor,
          environmentVariables: { ...baseEnvironment, STAGE7_AWS_ACCOUNT_ID: '999999999999' },
          now,
          requireAws: true,
        }),
      'E7_OPERATION_ACCOUNT_MISMATCH',
    );
    const beforeWindow = new Date(Date.parse(config.window.startsAtUtc) - 1000);
    expectCode(
      () =>
        loadOperationContext({
          capability: 'read',
          scope: 'prerelease',
          executor: fakeExecutor,
          environmentVariables: baseEnvironment,
          now: beforeWindow,
          requireAws: true,
        }),
      'E7_OPERATION_OUTSIDE_AUTHORIZED_WINDOW',
    );
    const invalidStackConfig = {
      ...config,
      authorization: { ...config.authorization, stacks: config.authorization.stacks.slice(0, 3) },
    };
    writeFileSync(configPath, `${JSON.stringify(invalidStackConfig)}\n`, 'utf8');
    expectCode(
      () =>
        loadOperationContext({
          capability: 'read',
          scope: 'prerelease',
          executor: fakeExecutor,
          environmentVariables: baseEnvironment,
          now,
          requireAws: true,
        }),
      'E7_STACK_SCOPE_INVALID',
    );
    writeFileSync(configPath, `${JSON.stringify(config)}\n`, 'utf8');
    expectCode(
      () =>
        loadOperationContext({
          capability: 'read',
          scope: 'prerelease',
          executor: fakeExecutor,
          environmentVariables: { ...baseEnvironment, GITHUB_SHA: 'b'.repeat(40) },
          now,
          requireAws: true,
        }),
      'E7_OPERATION_GITHUB_SHA_MISMATCH',
    );
    let hotswapExecutorCalls = 0;
    expectCode(
      () =>
        run(
          () => {
            hotswapExecutorCalls += 1;
            return { status: 0, stdout: '', stderr: '' };
          },
          'pnpm',
          ['cdk', 'deploy', '--hotswap'],
          { code: 'E7_CANARY' },
        ),
      'E7_HOTSWAP_FORBIDDEN',
    );
    assert.equal(hotswapExecutorCalls, 0);
    assert.deepEqual(parseAwsFlags(['--app', 'candidate/iac', '--ephemeral-only']), {
      app: 'candidate/iac',
      'ephemeral-only': true,
    });
    expectCode(() => parseAwsFlags(['--app', 'a', '--app', 'b']), 'E7_AWS_CLI_ARGUMENT_DUPLICATE');
    expectCode(
      () => assertAwsFlagSet({ app: 'x', bypass: true }, { required: ['app'] }),
      'E7_AWS_CLI_ARGUMENT_SET_INVALID',
    );
    assert.equal(
      frozenAwsCliVersion(
        {
          ...context,
          executor: () => ({
            status: 0,
            stdout: '',
            stderr: 'aws-cli/2.31.0 Python/3.13.7 Windows/11 exe/AMD64',
          }),
        },
        '2.31.0',
      ),
      '2.31.0',
    );
    expectCode(
      () =>
        frozenAwsCliVersion(
          {
            ...context,
            executor: () => ({
              status: 0,
              stdout: 'aws-cli/2.32.0 Python/3.13.7 Linux/6 exe/x86_64',
              stderr: '',
            }),
          },
          '2.31.0',
        ),
      'E7_AWS_CLI_VERSION_MISMATCH',
    );
    expectCode(
      () =>
        frozenAwsCliVersion(
          {
            ...context,
            executor: () => ({ status: 1, stdout: '', stderr: 'not available' }),
          },
          '2.31.0',
        ),
      'E7_AWS_CLI_VERSION_UNAVAILABLE',
    );
    const validationOnlyContext = loadOperationContext({
      capability: 'deploy',
      scope: 'prerelease',
      flags: { scope: 'prerelease', 'synthetic-only': true, 'non-public': true },
      executor: fakeExecutor,
      environmentVariables: baseEnvironment,
      now,
      requireAws: true,
    });
    expectCode(
      () =>
        validateDeployFlags(validationOnlyContext, {
          app: 'candidate/iac',
          manifest: 'candidate-manifest.json',
          scope: 'prerelease',
          'synthetic-only': true,
          'non-public': true,
        }),
      'E7_DEPLOY_INPUT_REQUIRED',
    );
    expectCode(
      () => assertReleaseMutationReady({ scope: 'prerelease' }),
      'E7_PREVIOUS_APPROVED_RELEASE_REQUIRED',
    );
    expectCode(
      () => assertReleaseMutationReady({ scope: 'full' }),
      'E7_PREVIOUS_APPROVED_RELEASE_REQUIRED',
    );
    const missingState = {
      exists: false,
      outputs: {},
      parameters: {},
      stackStatus: 'NOT_FOUND',
      stackId: null,
      creationTime: null,
      lastUpdatedTime: null,
      terminationProtection: null,
    };
    assert.notEqual(
      stackStateFingerprint(config.authorization.stacks[0], missingState),
      stackStateFingerprint(config.authorization.stacks[0], {
        ...missingState,
        exists: true,
        stackStatus: 'CREATE_COMPLETE',
      }),
      'approved plan fingerprints must detect target-stack drift',
    );
    assert.equal(deployReleaseMode({ scope: 'prerelease', 'initial-release': true }), 'INITIAL');
    assert.equal(deployReleaseMode({ 'versioned-update': true }), 'VERSIONED_UPDATE');
    expectCode(
      () => deployReleaseMode({ 'previous-manifest': 'previous.json' }),
      'E7_VERSIONED_UPDATE_ACK_REQUIRED',
    );
    expectCode(
      () =>
        deployReleaseMode({
          'initial-release': true,
          'versioned-update': true,
          'previous-manifest': 'previous.json',
        }),
      'E7_VERSIONED_UPDATE_ACK_REQUIRED',
    );
    expectCode(() => deployReleaseMode({}), 'E7_VERSIONED_UPDATE_ACK_REQUIRED');
    assert.deepEqual(
      classifyInitialPublicationState({
        baselineDistributionEnabled: false,
        distributionEnabled: false,
        mappingExpected: true,
        mappingPublished: false,
        scheduleState: 'DISABLED',
      }),
      { activated: false, baseline: true },
    );
    assert.deepEqual(
      classifyInitialPublicationState({
        baselineDistributionEnabled: true,
        distributionEnabled: true,
        mappingExpected: false,
        mappingPublished: false,
        scheduleState: 'DISABLED',
      }),
      { activated: false, baseline: true },
    );
    assert.deepEqual(
      classifyInitialPublicationState({
        baselineDistributionEnabled: false,
        distributionEnabled: true,
        mappingExpected: true,
        mappingPublished: true,
        scheduleState: 'ENABLED',
      }),
      { activated: true, baseline: false },
    );
    expectCode(
      () =>
        classifyInitialPublicationState({
          baselineDistributionEnabled: false,
          distributionEnabled: true,
          mappingExpected: true,
          mappingPublished: false,
          scheduleState: 'DISABLED',
        }),
      'E7_ACTIVATION_PARTIAL_STATE_DETECTED',
    );
    assert.equal(
      rollbackReleaseMode(
        { 'initial-release': true, 'to-disabled': true },
        { releaseMode: 'INITIAL' },
        'to-disabled',
      ),
      'INITIAL',
    );
    expectCode(
      () =>
        rollbackReleaseMode(
          { 'previous-manifest': 'previous.json' },
          { releaseMode: 'UPDATE' },
          'to-disabled',
        ),
      'E7_UPDATE_RELEASE_NOT_SUPPORTED',
    );
    expectCode(
      () =>
        rollbackReleaseMode(
          { 'initial-release': true, 'to-disabled': true },
          { releaseMode: 'UPDATE' },
          'to-disabled',
        ),
      'E7_UPDATE_RELEASE_NOT_SUPPORTED',
    );
    const hostedZoneConfig = {
      ...config,
      domain: {
        ...config.domain,
        mode: 'CUSTOM_AUTHORIZED',
        hostname: 'preview.release.example.invalid',
        apiHostname: 'api-preview.release.example.invalid',
        hostedZoneId: 'Z1234567890ABC',
      },
    };
    const hostedZoneDocument = {
      HostedZone: {
        Id: '/hostedzone/Z1234567890ABC',
        Name: 'release.example.invalid.',
        Config: { PrivateZone: false },
      },
      DelegationSet: {
        NameServers: ['ns-1.awsdns-01.com.', 'ns-2.awsdns-02.net.'],
      },
      VPCs: [],
    };
    assert.equal(validateHostedZoneDocument(hostedZoneConfig, hostedZoneDocument).publicZone, true);
    expectCode(
      () =>
        validateHostedZoneDocument(hostedZoneConfig, {
          ...hostedZoneDocument,
          HostedZone: { ...hostedZoneDocument.HostedZone, Name: 'other.example.invalid.' },
        }),
      'E7_HOSTED_ZONE_MISMATCH',
    );
    expectCode(
      () =>
        validateHostedZoneDocument(hostedZoneConfig, {
          ...hostedZoneDocument,
          HostedZone: {
            ...hostedZoneDocument.HostedZone,
            Config: { PrivateZone: true },
          },
          VPCs: [{ VPCId: 'vpc-canary', VPCRegion: 'us-east-1' }],
        }),
      'E7_HOSTED_ZONE_MISMATCH',
    );
    const ownedOriginSha256 = sha256('https://prerelease.example.invalid');
    const apiOriginSha256 = sha256(`https://${config.domain.apiHostname}`);
    const externalFilename = path.join(directory, 'external-authorizations.json');
    const authorization = (id, scope, approvedTargetSha256, minimumRequests) => ({
      id,
      status: 'APPROVED',
      scope,
      approvalSha256: sha256(`${id}:approval`),
      approvedTargetSha256,
      approvedAtUtc: new Date(now.getTime() - 60_000).toISOString(),
      expiresAtUtc: new Date(now.getTime() + 60 * 60 * 1000).toISOString(),
      ownerAlias: 'qa-owner',
      maxRequests: minimumRequests,
    });
    const externalBundle = {
      schemaId: 'async-checkout-stage7-external-authorizations',
      schemaVersion: 1,
      stage: 7,
      candidateSha: baseEnvironment.STAGE7_CANDIDATE_SHA,
      releaseId: baseEnvironment.STAGE7_RELEASE_ID,
      stage7ConfigSha256: objectSha256(config),
      targets: {
        ownedOriginSha256,
        apiOriginSha256,
        sandboxHostSha256: sha256('sandbox.wompi.co'),
      },
      authorizations: {
        ownedTarget: authorization(
          'AUTH-E6-01',
          'OWNED_EPHEMERAL_QA_HTTPS_VERIFICATION',
          ownedOriginSha256,
          9,
        ),
        sandboxSmoke: authorization(
          'AUTH-E6-02',
          'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
          sha256('sandbox.wompi.co'),
          8,
        ),
        passiveSecurity: authorization(
          'AUTH-E6-03',
          'PASSIVE_BASELINE_OWNED_QA_ONLY',
          ownedOriginSha256,
          12,
        ),
      },
      containsSensitiveData: false,
    };
    const activationContextWithoutExternalAuthorization = loadOperationContext({
      capability: 'deploy',
      scope: 'prerelease',
      flags: { scope: 'prerelease', 'non-public': true },
      executor: fakeExecutor,
      environmentVariables: baseEnvironment,
      now,
      requireAws: true,
    });
    expectCode(
      () =>
        validateActivationAuthorization(activationContextWithoutExternalAuthorization, {
          publicOriginSha256: ownedOriginSha256,
          apiOriginSha256,
        }),
      'E7_EXTERNAL_AUTHORIZATION_REQUIRED',
    );
    expectCode(
      () =>
        validateActivationAuthorization(
          {
            ...activationContextWithoutExternalAuthorization,
            flags: {},
            scope: undefined,
          },
          { publicOriginSha256: ownedOriginSha256, apiOriginSha256 },
        ),
      'E7_EXTERNAL_AUTHORIZATION_REQUIRED',
    );
    writeFileSync(externalFilename, `${JSON.stringify(externalBundle)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
    const activationContextWithMismatchedTarget = loadOperationContext({
      capability: 'deploy',
      scope: 'prerelease',
      flags: { scope: 'prerelease', 'non-public': true },
      executor: fakeExecutor,
      environmentVariables: {
        ...baseEnvironment,
        STAGE7_EXTERNAL_AUTHORIZATIONS: externalFilename,
      },
      now,
      requireAws: true,
    });
    expectCode(
      () =>
        validateActivationAuthorization(activationContextWithMismatchedTarget, {
          publicOriginSha256: sha256('https://different.example.invalid'),
          apiOriginSha256,
        }),
      'E7_EXTERNAL_AUTHORIZATION_ENVELOPE_INVALID',
    );
    const prereleaseAuthorization = validateActivationAuthorization(
      activationContextWithMismatchedTarget,
      { publicOriginSha256: ownedOriginSha256, apiOriginSha256 },
    );
    assert.deepEqual(prereleaseAuthorization.externalAuthorization.authorizationIds, [
      'AUTH-E6-01',
      'AUTH-E6-02',
      'AUTH-E6-03',
    ]);
    const fullEnvironment = 'assessment-release';
    const fullConfig = {
      ...config,
      environment: fullEnvironment,
      authorization: {
        ...config.authorization,
        scope: 'FULL_RELEASE_VERSIONED_UPDATE',
        stacks: expectedStacks(fullEnvironment),
      },
      domain: {
        mode: 'CUSTOM_AUTHORIZED',
        hostname: 'app.release.example.invalid',
        apiHostname: 'api.release.example.invalid',
        hostedZoneId: 'Z1234567890ABC',
        webCertificateArn: `arn:aws:acm:us-east-1:${config.aws.accountId}:certificate/11111111-1111-1111-1111-111111111111`,
        apiCertificateArn: `arn:aws:acm:us-east-1:${config.aws.accountId}:certificate/22222222-2222-2222-2222-222222222222`,
        dnsIncluded: true,
      },
      prereleaseAccess: {
        mode: 'ORIGIN_GATE_ONLY',
        keyGroupId: null,
        publicKeyId: null,
        originTokenSecretArn: config.credentialReferences[0],
        originTokenSecretVersionId: config.prereleaseAccess.originTokenSecretVersionId,
        rotationDuringWindow: 'FORBIDDEN',
      },
    };
    validateStage7Config(fullConfig, { now });
    const fullOriginSha256 = sha256('https://app.release.example.invalid');
    const fullBundle = {
      ...externalBundle,
      stage7ConfigSha256: objectSha256(fullConfig),
      targets: {
        ownedOriginSha256: fullOriginSha256,
        sandboxHostSha256: externalBundle.targets.sandboxHostSha256,
      },
      authorizations: {
        ownedTarget: authorization(
          'AUTH-E7-EXT-01',
          'OWNED_FINAL_RELEASE_HTTPS_VERIFICATION',
          fullOriginSha256,
          3,
        ),
        sandboxSmoke: authorization(
          'AUTH-E7-EXT-02',
          'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
          sha256('sandbox.wompi.co'),
          64,
        ),
        passiveSecurity: authorization(
          'AUTH-E7-EXT-03',
          'PASSIVE_BASELINE_OWNED_RELEASE_ONLY',
          fullOriginSha256,
          6,
        ),
      },
    };
    const fullExternalFilename = path.join(directory, 'full-external-authorizations.json');
    writeFileSync(configPath, `${JSON.stringify(fullConfig)}\n`, 'utf8');
    writeFileSync(fullExternalFilename, `${JSON.stringify(fullBundle)}\n`, {
      encoding: 'utf8',
      mode: 0o600,
    });
    const fullAuthorityEnvironment = {
      ...baseEnvironment,
      STAGE7_ENVIRONMENT: fullEnvironment,
      STAGE7_PROTECTED_ENVIRONMENT: 'assessment-release',
      STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN: journalRoleAuthority.role.arn,
      STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN:
        journalRoleAuthority.permissionsBoundary.policyArn,
    };
    const callsBeforeMissingJournalAuthority = fakeCalls;
    expectCode(
      () =>
        loadOperationContext({
          capability: 'deploy',
          flags: {
            manifest: path.join(directory, 'unused-full-manifest.json'),
            'aws-auth': path.join(directory, 'unused-full-aws-auth.json'),
          },
          executor: fakeExecutor,
          environmentVariables: fullAuthorityEnvironment,
          now,
          requireAws: true,
        }),
      'E7_RELEASE_JOURNAL_ROLE_AUTHORITY_REQUIRED',
    );
    assert.equal(
      fakeCalls,
      callsBeforeMissingJournalAuthority,
      'missing full journal authority must fail before AWS execution',
    );
    const fullActivationContext = loadOperationContext({
      capability: 'deploy',
      flags: {},
      executor: fakeExecutor,
      environmentVariables: {
        ...baseEnvironment,
        STAGE7_ENVIRONMENT: fullEnvironment,
        STAGE7_EXTERNAL_AUTHORIZATIONS: fullExternalFilename,
      },
      now,
      requireAws: true,
    });
    const fullAuthorization = validateActivationAuthorization(fullActivationContext, {
      publicOriginSha256: fullOriginSha256,
    });
    assert.deepEqual(fullAuthorization.externalAuthorization.authorizationIds, [
      'AUTH-E7-EXT-01',
      'AUTH-E7-EXT-02',
      'AUTH-E7-EXT-03',
    ]);
    validateStage7ActivationCheckpoint(
      {
        decision: 'ACTIVATED_REQUIRES_SMOKE',
        releaseMode: 'VERSIONED_UPDATE',
        updateReleaseSupported: true,
        previousReleaseManifestSha256: '9'.repeat(64),
        assemblySha256: 'a'.repeat(64),
        freezeManifestSha256: 'b'.repeat(64),
        seedEvidenceSha256: 'c'.repeat(64),
        publicOriginSha256: fullOriginSha256,
        externalAuthorization: fullAuthorization.externalAuthorization,
        observabilityReadiness: {
          evidenceSha256: 'd'.repeat(64),
          alertDestinationSha256: fullConfig.budget.alertDestinationSha256,
          alertTopicSha256: 'e'.repeat(64),
          status: 'CONFIRMED',
        },
        publication: {
          managedByCloudFormation: true,
          apiStack: {
            stackName: expectedStacks(fullEnvironment)[1],
            stackIdSha256: 'f'.repeat(64),
            state: 'ENABLED',
          },
          webStack: {
            stackName: expectedStacks(fullEnvironment)[3],
            stackIdSha256: '1'.repeat(64),
            state: 'ENABLED',
          },
          scheduler: {
            controlledBy: 'PublicationState',
            stackName: expectedStacks(fullEnvironment)[1],
            state: 'ENABLED',
          },
        },
        promotions: {
          api: { changed: false, version: '1' },
          worker: { changed: false, version: '1' },
          web: { invalidatedPaths: [], restoredObjects: 0 },
        },
        scheduleTargetSha256: '2'.repeat(64),
        transitions: [
          {
            sequence: 1,
            mode: 'CANDIDATE_ACTIVATION',
            apiStack: {
              changed: true,
              previousState: 'DISABLED',
              state: 'ENABLED',
              stackIdSha256: 'f'.repeat(64),
              stackName: expectedStacks(fullEnvironment)[1],
            },
            webStack: {
              changed: true,
              previousState: 'DISABLED',
              state: 'ENABLED',
              stackIdSha256: '1'.repeat(64),
              stackName: expectedStacks(fullEnvironment)[3],
            },
            scheduler: {
              controlledBy: 'PublicationState',
              stackName: expectedStacks(fullEnvironment)[1],
              state: 'ENABLED',
            },
            authorizationUsage: fullAuthorization.authorizationUsage,
          },
        ],
      },
      {
        config: fullConfig,
        candidateSha: fullActivationContext.identity.candidateSha,
        releaseId: fullActivationContext.identity.releaseId,
        manifestSha256: 'b'.repeat(64),
      },
    );
    assert.match(cleanupConfirmation(config), SHA256);
    assert.notEqual(
      cleanupConfirmation(config),
      cleanupConfirmation({
        ...config,
        cleanup: { ...config.cleanup, expiresAtUtc: '2026-08-18T00:00:00.000Z' },
      }),
    );
    assert.equal(fakeCalls, 1, 'validation canaries must fail before executor invocation');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  assert.equal(existsSync(directory), false, 'AWS operations self-test temporary directory leaked');
  return { externalNetworkCalls: 0, externalMutations: 0, injectedReadCalls: fakeCalls };
};
