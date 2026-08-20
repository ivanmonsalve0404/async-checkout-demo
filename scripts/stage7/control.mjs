#!/usr/bin/env node
/* global structuredClone */

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import {
  STAGE7_EVIDENCE,
  STAGE7_PROVIDER_EGRESS_CAPABILITY,
  Stage7Error,
  assessStage6Manifest,
  createFreezeManifest,
  createLocalPreflight,
  createStage7CandidateRollbackRecord,
  createStage7PreviousReleaseManifest,
  createStage7Index,
  createStage7VersionedRollbackPlan,
  currentCandidate,
  expectedStage7Stacks,
  hashArtifactPath,
  objectSha256,
  readStrictJsonFile,
  selfTestStage7,
  validateFreezeManifest,
  validateStage7ActivationCheckpoint,
  validateStage7DriftCheckpoint,
  validateStage7Config,
  validateStage7InitialRollbackCheckpoint,
  validateStage7CandidateRollbackRecord,
  validateStage7PrereleaseCleanupCheckpoint,
  validateStage7PreviousReleaseHandoff,
  validateStage7PreviousReleaseForTarget,
  validateStage7PreviousReleaseManifest,
  validateStage7VersionedRollbackCheckpoint,
  validateStage7VersionedRollbackRehearsal,
  validateStage7VersionedRollbackTransition,
  workspaceRoot,
  writeStage7Json,
} from './core.mjs';
import {
  assertSanitizedArtifactText,
  selfTestArtifactSanitizer,
  writeSanitizedTextAtomic,
} from '../stage6/lib/artifact-sanitizer.mjs';
import { loadExternalEvidence, selfTestExternalEvidence } from '../stage6/external-evidence.mjs';
import {
  SANDBOX_HOST,
  loadAuthorizationContext,
  validateRequiredEnvironment,
} from '../stage6/sandbox-authorized/authorization-policy.mjs';
import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { scanText } from '../security/scan-repository.mjs';
import {
  Stage7SmokeError,
  prepareVersionedRollbackPendingCanary,
  readPrivateSmokeInputs,
  runCanonicalStage7Smoke,
  validateCapabilityCookieEvidence,
  selfTestDeployedSmoke,
  validateCanonicalSmokeResults,
} from './deployed-smoke.mjs';
import {
  collectStage7ProviderEgressEvidence,
  createAwsCliProviderEgressClient,
  stage7ProviderEgressLogGroups,
} from './provider-egress-evidence.mjs';
import {
  Stage7QualityError,
  runDeployedQuality,
  selfTestDeployedQuality,
  validateQualityPayload,
} from './deployed-quality.mjs';
import {
  assertCloudFrontAccessMaterialExcluded,
  readCloudFrontSignedCookieFile,
  validatePrereleaseApiOrigin,
} from './cloudfront-access.mjs';
import {
  GithubEnvironmentApprovalError,
  validateGithubEnvironmentApproval,
} from './github-environment-approval.mjs';
import {
  IAM_ROLE_PERMISSION_PROFILES,
  IamEffectivePermissionsError,
  collectIamEffectivePermissions,
  selfTestIamEffectivePermissions,
  validateBootstrapAssetInventory,
  validateIamEffectivePermissionsEvidence,
} from './iam-effective-permissions.mjs';
import {
  RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  Stage7ReleaseSuccessorIamAuthorityError,
  compareReleaseJournalRoleEffectivePermissions,
  parseReleaseJournalRoleEffectivePermissionsSource,
  validateReleaseJournalRoleEffectivePermissionsBinding,
} from './release-successor-iam-authority.mjs';
import {
  Stage7ReleaseSuccessorFenceContractError,
  validateReleaseSuccessorCompletionFence,
} from './release-successor-fence-contract.mjs';
import {
  RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS,
  RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  Stage7ReleaseReconciliationRecoveryError,
  parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource,
  validateReleaseReconciliationRecoveryActor,
} from './release-reconciliation-recovery.mjs';
import {
  createBaselineConfigSelfTestFixture,
  createBaselineFreezeSelfTestFixture,
  validateBaselineConfig,
  validateBaselineFreeze,
} from './baseline-establishment.mjs';
import {
  revalidateConsumedSandboxExecutionClaim,
  sanitizedSandboxExecutionBinding,
  validateSandboxExecutionClaim,
  validateSandboxExecutionEvidence,
} from './sandbox-execution-claim.mjs';
import {
  Stage7RollbackResilienceIntegrationError,
  prepareRollbackResilienceArtifacts,
  validateRollbackResilienceCompletionEnvelope,
} from './rollback-resilience-integration.mjs';
import {
  Stage7ReleaseReconciliationError,
  validateReleaseReconciliationIntent,
  validateReleaseReconciliationSmokeAuthorizationUsage,
  validateReleasePreFenceGate,
} from './release-reconciliation.mjs';
import {
  Stage7ReleaseReconciliationExecutorError,
  validateReleaseRuntimeConvergence,
} from './release-reconciliation-executor.mjs';
import {
  revalidatePrereleaseWatchdogLiveAuthority,
  validatePrereleaseDeploymentCheckpoint,
  validatePrereleaseLiveSafetyRecheck,
  validatePrereleaseSafetyReadinessFromFiles,
} from './prerelease-safety-readiness.mjs';
import { PrereleaseSafetyContractError } from './prerelease-safety-contract.mjs';
import { createCommitsEndpointAuthority, createTagRefAuthority } from './github-publication.mjs';
import {
  PREVIOUS_RELEASE_PROJECTION_FILENAMES,
  validatePreviousReleaseProjectionIndex,
} from './previous-release-projection.mjs';
import {
  Stage7ExternalRequestBudgetError,
  createFullExternalRequestComponentCounter,
  createFullExternalRequestCounter,
  createFullExternalRequestBudgetPlan,
  validateFullExternalRequestBudgetCheckpoint,
  validateFullExternalRequestBudgetPlan,
} from './external-request-budget.mjs';
import { validateZapPassiveCaptureEvidence } from './zap-passive-capture.mjs';
import {
  ZAP_PASSIVE_REQUEST_COUNT,
  validateZapPassiveRequestInventory,
} from './zap-passive-inventory.mjs';
import {
  STAGE7_EVIDENCE_SOURCE_REQUIREMENTS,
  STAGE7_LEDGER_SOURCE_BINDING_SPECS,
  STAGE7_SOURCE_PRODUCERS,
  Stage7ProvenanceError,
  createArtifactRows,
  createAuthorityArtifactRows,
  createEvidenceIndexCheckpoint,
  createGateEvaluationCheckpoint,
  createCompositeRecoveryJobResultsDocument,
  createJobResultsDocument,
  createOperationalArtifactRows,
  createProvenanceRow,
  createSourceReference,
  createStage7FinalManifest,
  createStage7Handoff,
  createStage7OperationsRunbook,
  createStage7ProvenanceLedger,
  createStage7Scorecard,
  renderStage7Report,
} from './evidence-provenance.mjs';
import { validatePublicationRecoveryPostSuccessIntake } from './release-successor-publication-recovery-contract.mjs';
import {
  RELEASE_SUCCESSOR_COMPOSITE_GATE_JOB_IDS,
  RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME,
  readReleaseSuccessorRecoveryResultFromIntake,
  validateReleaseSuccessorRecoveryCloseoutAuthority,
} from './release-successor-recovery-integration.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-([0-9]{8})-([0-9]{4})-([0-9a-f]{7})$/u;
const RELEASE_TAG =
  /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-rc\.[1-9][0-9]*)?$/u;
const RUN_ID = /^[1-9][0-9]{0,19}$/u;
const PRERELEASE_COOKIE_EXPIRY_MARGIN_MS = 2 * 60 * 60 * 1000;
const EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_BASENAME = 'emergency-recovery-no-action-outcome.json';
const RELEASE_SUCCESSOR_COMPLETION_FENCE_BASENAME = 'release-successor-completion-fence.json';
const EMERGENCY_NO_ACTION_SOURCE_BINDING_SPECS = Object.freeze([
  ['manifest', 'candidate-manifest.json'],
  ['previous-manifest', 'previous-release-manifest.json'],
  ['previous-api-contract-evidence', 'previous-api-contract-evidence.json'],
  ['previous-pending-evidence', 'previous-pending-evidence.json'],
  ['previous-smoke-evidence', 'previous-smoke-evidence.json'],
  ['candidate-record', 'versioned-rollback-candidate.json'],
  ['approval', 'approval.json'],
  ['aws-auth', 'aws-auth.json'],
  [
    'journal-role-effective-permissions',
    RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  ],
  ['approved-plan', 'infra-diff.json'],
  ['deployment-evidence', 'web.json'],
]);
const EVIDENCE_ROOTS = Object.freeze({
  full: 'output/evidence/runtime/stage-7',
  prerelease: 'output/evidence/runtime/stage-7-prerelease',
});
const TEXT_EXTENSIONS = new Set([
  '.cjs',
  '.css',
  '.html',
  '.js',
  '.json',
  '.md',
  '.mjs',
  '.mts',
  '.svg',
  '.ts',
  '.tsx',
  '.txt',
  '.yaml',
  '.yml',
]);
const EVIDENCE_TEXT_EXTENSIONS = new Set(['.html', '.json', '.md', '.txt', '.yaml', '.yml']);
const FORBIDDEN_ARTIFACT_PATH =
  /(?:^|\/)(?:credentials?|secrets?)(?:[._/-]|$)|(?:^|\/)\.env(?:\.|$)|\.(?:key|map|p12|pem|pfx)$/iu;
const REQUIRED_HEADERS = [
  'content-security-policy',
  'referrer-policy',
  'x-content-type-options',
  'permissions-policy',
  'strict-transport-security',
];
const PROTECTED_APPROVAL_KEYS = Object.freeze([
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
]);
const REQUIRED_FULL_EVIDENCE = [
  'release-metadata.json',
  'stage6-closeout.json',
  'verify-candidate.json',
  'candidate-manifest.json',
  'checksums-sbom.json',
  'security.json',
  'prefreeze.json',
  'aws-auth.json',
  RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  'infra-synth.json',
  'release-plan.json',
  'infra-diff.json',
  'github-environment-approval.json',
  'approval.json',
  'data.json',
  'api.json',
  'observability.json',
  'web.json',
  'external-authorization.json',
  'smoke-input-preflight.json',
  'activation.json',
  'smoke.json',
  'quality.json',
  'edge-security.json',
  'sandbox-smoke.json',
  'rollback-smoke-input-preflight.json',
  'previous-release-readiness.json',
  'previous-release-manifest.json',
  'previous-api-contract-evidence.json',
  'previous-pending-evidence.json',
  'previous-smoke-evidence.json',
  'previous-source-provenance.json',
  'previous-target-compatibility.json',
  'previous-final-disable-provenance.json',
  'previous-release-projection-index.json',
  'versioned-rollback-candidate.json',
  'emergency-recovery.json',
  EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_BASENAME,
  'rollback-pending-producer.json',
  'rollback-pending-egress-closeout.json',
  'versioned-rollback-aws-transition.json',
  'versioned-rollback-smoke.json',
  'versioned-rollback-checkpoint.json',
  'versioned-repromotion-aws-transition.json',
  'versioned-repromotion-smoke.json',
  'versioned-repromotion-checkpoint.json',
  'rollback.json',
  'stage7-rollback-resilience-source-binding.json',
  'stage7-rollback-resilience-protected-run.json',
  'stage7-rollback-resilience-complete.json',
  'rollback-check-reconciliation.json',
  'rollback-resilience-reconciliation.json',
  'stage7-release-pre-fence-gate.json',
  RELEASE_SUCCESSOR_COMPLETION_FENCE_BASENAME,
  'drift.json',
];
const FULL_COMPLEX_EVIDENCE = new Set([
  'infra-diff.json',
  'stage6-closeout.json',
  'release-plan.json',
  'approval.json',
  RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  'data.json',
  'api.json',
  'observability.json',
  'web.json',
  'activation.json',
  'drift.json',
  'previous-release-manifest.json',
  'previous-release-readiness.json',
  'previous-api-contract-evidence.json',
  'previous-pending-evidence.json',
  'previous-smoke-evidence.json',
  'previous-source-provenance.json',
  'previous-target-compatibility.json',
  'previous-final-disable-provenance.json',
  'previous-release-projection-index.json',
  'versioned-rollback-candidate.json',
  'emergency-recovery.json',
  EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_BASENAME,
  'rollback-pending-producer.json',
  'rollback-pending-egress-closeout.json',
  'versioned-rollback-aws-transition.json',
  'versioned-rollback-checkpoint.json',
  'versioned-repromotion-aws-transition.json',
  'versioned-repromotion-checkpoint.json',
  'rollback.json',
  'stage7-rollback-resilience-source-binding.json',
  'stage7-rollback-resilience-protected-run.json',
  'stage7-rollback-resilience-complete.json',
  'rollback-check-reconciliation.json',
  'rollback-resilience-reconciliation.json',
  'stage7-release-pre-fence-gate.json',
  RELEASE_SUCCESSOR_COMPLETION_FENCE_BASENAME,
]);
const OPERATION_CHECKPOINT_BY_BASENAME = Object.freeze({
  'data.json': 'data',
  'api.json': 'api',
  'observability.json': 'observability',
  'web.json': 'web',
  'activation.json': 'activation',
  'drift.json': 'drift',
});
const REQUIRED_FULL_JOBS = [
  'release-metadata',
  'verify-candidate',
  'build-or-fetch',
  'checksums-sbom',
  'secret-scan',
  'aws-auth',
  'infra-synth-test',
  'infra-diff',
  'approval',
  'deploy-data',
  'deploy-api',
  'deploy-observability',
  'deploy-web',
  'postdeploy-smoke',
  'edge-security',
  'quality',
  'sandbox-smoke',
  'emergency-recovery',
  'release-reconciliation-intent',
  'rollback-check',
  'rollback-resilience',
  'release-reconciliation',
  'release-successor-fence',
  'publish-release',
];
const REQUIRED_PRERELEASE_JOBS = [
  'prerelease-metadata',
  'verify-candidate',
  'build-once',
  'integrity-security',
  'infra-synth-test',
  'infra-diff',
  'approval',
  'prerelease-safety-readiness',
  'deploy-prerelease',
  'external-verification',
  'external-evidence',
  'cleanup',
];
const PRERELEASE_BLOCKED_EVIDENCE = new Set(
  [20, 30, 35, 36, 37, 38, 39, 40, 46, 47, 48, 49, 51, 52].map(
    (number) => `EVD-E7-${String(number).padStart(2, '0')}`,
  ),
);
const PRERELEASE_NOT_RUN_EVIDENCE = new Set(
  [42, 43, 44, 53].map((number) => `EVD-E7-${String(number).padStart(2, '0')}`),
);

export class Stage7ControlError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7ControlError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7ControlError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const digest = (value) => createHash('sha256').update(value).digest('hex');
const fileDigest = (filename) => digest(readFileSync(filename));
const stableCompare = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

const assertNode24 = () => {
  const [major, minor] = process.versions.node.split('.').map(Number);
  if (major !== 24 || minor < 19) fail('E7_CONTROL_NODE_VERSION_UNSUPPORTED');
};

const relativeInside = (rootDirectory, candidate, code = 'E7_CONTROL_PATH_OUTSIDE_WORKSPACE') => {
  const absolute = path.resolve(candidate);
  const relative = path.relative(rootDirectory, absolute);
  if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    fail(code);
  }
  return { absolute, relative: relative.replaceAll('\\', '/') };
};

const checkedWorkspacePath = (candidate, { directory } = {}) => {
  const requested = path.resolve(candidate);
  relativeInside(workspaceRoot, requested);
  let current = workspaceRoot;
  const relative = path.relative(workspaceRoot, requested);
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    let stat;
    try {
      stat = lstatSync(current);
    } catch {
      fail('E7_CONTROL_PATH_MISSING');
    }
    if (stat.isSymbolicLink()) fail('E7_CONTROL_SYMLINK_REJECTED');
  }
  let canonical;
  try {
    canonical = realpathSync(requested);
  } catch {
    fail('E7_CONTROL_PATH_MISSING');
  }
  relativeInside(realpathSync(workspaceRoot), canonical);
  const stat = lstatSync(canonical);
  if (directory === true && !stat.isDirectory()) fail('E7_CONTROL_DIRECTORY_REQUIRED');
  if (directory === false && !stat.isFile()) fail('E7_CONTROL_FILE_REQUIRED');
  return canonical;
};

const walkFiles = (directory) => {
  const root = checkedWorkspacePath(directory, { directory: true });
  const files = [];
  const visit = (current, prefix = '') => {
    for (const entry of readdirSync(current, { withFileTypes: true }).sort((left, right) =>
      stableCompare(left.name, right.name),
    )) {
      const absolute = path.join(current, entry.name);
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const stat = lstatSync(absolute);
      if (entry.isSymbolicLink() || stat.isSymbolicLink()) fail('E7_CONTROL_SYMLINK_REJECTED');
      if (entry.isDirectory()) visit(absolute, relative);
      else if (entry.isFile()) {
        if (stat.size > 64 * 1024 * 1024) fail('E7_CONTROL_FILE_TOO_LARGE');
        files.push({ absolute, relative, bytes: stat.size });
        if (files.length > 50_000) fail('E7_CONTROL_FILE_LIMIT_EXCEEDED');
      } else fail('E7_CONTROL_SPECIAL_FILE_REJECTED');
    }
  };
  visit(root);
  return { root, files };
};

const findExactlyOne = (directory, basename) => {
  const matches = walkFiles(directory).files.filter(
    (file) => path.basename(file.relative) === basename,
  );
  if (matches.length !== 1)
    fail(`E7_${basename.replaceAll(/[^A-Za-z0-9]/gu, '_').toUpperCase()}_COUNT_INVALID`);
  return matches[0].absolute;
};

const readEvidence = (filename) => {
  const absolute = checkedWorkspacePath(filename, { directory: false });
  const source = readFileSync(absolute);
  if (source.length === 0 || source.length > 2 * 1024 * 1024) fail('E7_EVIDENCE_SIZE_INVALID');
  const text = source.toString('utf8');
  try {
    assertSanitizedArtifactText(path.basename(absolute), text);
    return parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch {
    fail('E7_EVIDENCE_CONTRACT_INVALID');
  }
};

const readEvidenceSource = (filename) => {
  const absolute = checkedWorkspacePath(filename, { directory: false });
  const source = readFileSync(absolute);
  if (source.length === 0 || source.length > 4 * 1024 * 1024) {
    fail('E7_EVIDENCE_SIZE_INVALID');
  }
  return source;
};

const evidenceFileBinding = (filename) => {
  const source = readEvidenceSource(filename);
  return {
    rawSha256: digest(source),
    canonicalSha256: objectSha256(readEvidence(filename)),
    bytes: source.length,
  };
};

const configFromEnvironment = () => {
  const filename = process.env.STAGE7_CONFIG;
  if (typeof filename !== 'string' || filename.trim() === '') fail('E7_CONFIG_PATH_REQUIRED');
  try {
    // Stage 7 configuration is an exact, field-aware allowlist.  The generic
    // evidence scanner deliberately is not used here: valid 12-digit AWS
    // account IDs and Secrets Manager ARNs resemble forbidden evidence data.
    return readStrictJsonFile(filename, { scanForbiddenData: false, validateConfig: true });
  } catch (error) {
    if (error instanceof Stage7Error) throw error;
    fail('E7_CONFIG_READ_FAILED');
  }
};

const baselineConfigFromEnvironment = () => {
  const filename = process.env.STAGE7_CONFIG;
  if (typeof filename !== 'string' || filename.trim() === '') fail('E7_CONFIG_PATH_REQUIRED');
  try {
    return validateBaselineConfig(
      readStrictJsonFile(filename, { scanForbiddenData: false, validateConfig: false }),
    );
  } catch {
    fail('E7_BASELINE_CONFIG_READ_FAILED');
  }
};

const utc = (value) =>
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
  !Number.isNaN(Date.parse(value)) &&
  new Date(value).toISOString() === value;

const exactKeys = (value, expected) =>
  object(value) && Object.keys(value).toSorted().join('\0') === expected.toSorted().join('\0');

const externalAuthorization = (value, expected, targetSha256, now) => {
  if (
    !exactKeys(value, [
      'id',
      'status',
      'scope',
      'approvalSha256',
      'approvedTargetSha256',
      'approvedAtUtc',
      'expiresAtUtc',
      'ownerAlias',
      'maxRequests',
    ]) ||
    value.id !== expected.id ||
    value.status !== 'APPROVED' ||
    value.scope !== expected.scope ||
    !SHA256.test(value.approvalSha256 ?? '') ||
    value.approvedTargetSha256 !== targetSha256 ||
    !utc(value.approvedAtUtc) ||
    !utc(value.expiresAtUtc) ||
    !/^[a-z][a-z0-9-]{2,31}$/u.test(value.ownerAlias ?? '') ||
    !Number.isSafeInteger(value.maxRequests) ||
    value.maxRequests < expected.minimumRequests ||
    value.maxRequests > 100 ||
    Date.parse(value.approvedAtUtc) > now.getTime() ||
    Date.parse(value.expiresAtUtc) < now.getTime() ||
    Date.parse(value.approvedAtUtc) >= Date.parse(value.expiresAtUtc)
  ) {
    fail('E7_EXTERNAL_AUTHORIZATION_INVALID');
  }
  return value;
};

export const validateExternalAuthorizations = ({
  value,
  config,
  candidateSha,
  releaseId,
  deployedOrigin,
  deployedOriginSha256,
  deployedApiOrigin,
  deployedApiOriginSha256,
  now = new Date(),
}) => {
  validateStage7Config(config, { now });
  let origin = null;
  let originSha256 = deployedOriginSha256;
  if (deployedOrigin !== undefined) {
    try {
      const parsed = new URL(deployedOrigin);
      if (parsed.protocol !== 'https:' || parsed.pathname !== '/' || parsed.search || parsed.hash) {
        fail('E7_EXTERNAL_AUTHORIZATION_ORIGIN_INVALID');
      }
      origin = parsed.origin;
      originSha256 = digest(origin);
    } catch (error) {
      if (error instanceof Stage7ControlError) fail(error.code);
      fail('E7_EXTERNAL_AUTHORIZATION_ORIGIN_INVALID');
    }
  }
  if (!SHA256.test(originSha256 ?? '')) fail('E7_EXTERNAL_AUTHORIZATION_ORIGIN_INVALID');
  let apiOrigin = null;
  let apiOriginSha256 = deployedApiOriginSha256;
  if (deployedApiOrigin !== undefined) {
    try {
      apiOrigin = validatePrereleaseApiOrigin({
        origin: deployedApiOrigin,
        region: config.aws.region,
      });
      apiOriginSha256 = digest(apiOrigin);
    } catch {
      fail('E7_EXTERNAL_AUTHORIZATION_API_ORIGIN_INVALID');
    }
  }
  const sandboxHostSha256 = digest('sandbox.wompi.co');
  const fullRelease = config.authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE';
  const expectedTargetKeys = fullRelease
    ? ['ownedOriginSha256', 'sandboxHostSha256']
    : ['ownedOriginSha256', 'apiOriginSha256', 'sandboxHostSha256'];
  if (
    !exactKeys(value, [
      'schemaId',
      'schemaVersion',
      'stage',
      'candidateSha',
      'releaseId',
      'stage7ConfigSha256',
      'targets',
      'authorizations',
      'containsSensitiveData',
    ]) ||
    value.schemaId !== 'async-checkout-stage7-external-authorizations' ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.candidateSha !== candidateSha ||
    value.releaseId !== releaseId ||
    value.stage7ConfigSha256 !== objectSha256(config) ||
    value.containsSensitiveData !== false ||
    !exactKeys(value.targets, expectedTargetKeys) ||
    value.targets.ownedOriginSha256 !== originSha256 ||
    (!fullRelease &&
      (!SHA256.test(apiOriginSha256 ?? '') || value.targets.apiOriginSha256 !== apiOriginSha256)) ||
    value.targets.sandboxHostSha256 !== sandboxHostSha256 ||
    !exactKeys(value.authorizations, ['ownedTarget', 'sandboxSmoke', 'passiveSecurity'])
  ) {
    fail('E7_EXTERNAL_AUTHORIZATION_ENVELOPE_INVALID');
  }
  const authorizations = {
    ownedTarget: externalAuthorization(
      value.authorizations.ownedTarget,
      {
        id: fullRelease ? 'AUTH-E7-EXT-01' : 'AUTH-E6-01',
        scope: fullRelease
          ? 'OWNED_FINAL_RELEASE_HTTPS_VERIFICATION'
          : 'OWNED_EPHEMERAL_QA_HTTPS_VERIFICATION',
        minimumRequests: fullRelease ? 3 : 9,
      },
      originSha256,
      now,
    ),
    sandboxSmoke: externalAuthorization(
      value.authorizations.sandboxSmoke,
      {
        id: fullRelease ? 'AUTH-E7-EXT-02' : 'AUTH-E6-02',
        scope: 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
        minimumRequests: fullRelease ? 64 : 8,
      },
      sandboxHostSha256,
      now,
    ),
    passiveSecurity: externalAuthorization(
      value.authorizations.passiveSecurity,
      {
        id: fullRelease ? 'AUTH-E7-EXT-03' : 'AUTH-E6-03',
        scope: fullRelease
          ? 'PASSIVE_BASELINE_OWNED_RELEASE_ONLY'
          : 'PASSIVE_BASELINE_OWNED_QA_ONLY',
        minimumRequests: 6,
      },
      originSha256,
      now,
    ),
  };
  const configApproved = Date.parse(config.authorization.approvedAtUtc);
  const configExpires = Date.parse(config.authorization.expiresAtUtc);
  if (
    Object.values(authorizations).some(
      (authorization) =>
        Date.parse(authorization.approvedAtUtc) < configApproved ||
        Date.parse(authorization.expiresAtUtc) > configExpires,
    )
  ) {
    fail('E7_EXTERNAL_AUTHORIZATION_WINDOW_MISMATCH');
  }
  return {
    value,
    authorizations,
    origin,
    originSha256,
    apiOrigin,
    apiOriginSha256: fullRelease ? null : apiOriginSha256,
    sandboxHostSha256,
  };
};

const externalAuthorizationFile = () => {
  const filename = process.env.STAGE7_EXTERNAL_AUTHORIZATIONS;
  if (typeof filename !== 'string' || filename.trim() === '') {
    fail('E7_EXTERNAL_AUTHORIZATION_REQUIRED');
  }
  let stat;
  try {
    stat = lstatSync(filename);
  } catch {
    fail('E7_EXTERNAL_AUTHORIZATION_REQUIRED');
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 128 * 1024) {
    fail('E7_EXTERNAL_AUTHORIZATION_FILE_INVALID');
  }
  let value;
  try {
    const source = readFileSync(filename);
    assertSanitizedArtifactText('stage7-external-authorizations.json', source.toString('utf8'));
    value = parseStrictJsonSource(source, { scanForbiddenData: false });
  } catch {
    fail('E7_EXTERNAL_AUTHORIZATION_FILE_INVALID');
  }
  return value;
};

const readExternalAuthorizations = ({ config, identity, deployedOrigin, now = new Date() }) => {
  return validateExternalAuthorizations({
    value: externalAuthorizationFile(),
    config,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    deployedOrigin,
    now,
  });
};

const scopeOf = (flags) => {
  const value = flags.scope ?? 'full';
  if (!['full', 'prerelease'].includes(value)) fail('E7_SCOPE_INVALID');
  return value;
};

const awsScopeOf = (flags) => {
  const value = flags.scope ?? 'full';
  if (!['full', 'prerelease', 'baseline'].includes(value)) fail('E7_SCOPE_INVALID');
  return value;
};

const evidenceRoot = (scope) => path.resolve(workspaceRoot, EVIDENCE_ROOTS[scope]);

const candidateIdentity = (scope, { requireGitTag = false } = {}) => {
  const candidateSha = process.env.STAGE7_CANDIDATE_SHA;
  if (!SHA.test(candidateSha ?? '')) fail('E7_CANDIDATE_SHA_REQUIRED');
  const actual = currentCandidate();
  if (
    actual.commitSha !== candidateSha ||
    actual.workingTree !== 'CLEAN' ||
    actual.changedFiles !== 0
  ) {
    fail('E7_CANDIDATE_WORKTREE_MISMATCH');
  }
  const releaseId = process.env.STAGE7_RELEASE_ID;
  const idMatch = RELEASE_ID.exec(releaseId ?? '');
  if (idMatch?.[3] !== candidateSha.slice(0, 7)) fail('E7_RELEASE_IDENTITY_INVALID');
  if (scope === 'full') {
    const releaseTag = process.env.STAGE7_RELEASE_TAG;
    if (!RELEASE_TAG.test(releaseTag ?? '')) fail('E7_RELEASE_IDENTITY_INVALID');
    if (requireGitTag) {
      let tagged;
      try {
        tagged = execFileSync('git', ['rev-parse', `refs/tags/${releaseTag}^{commit}`], {
          cwd: workspaceRoot,
          encoding: 'utf8',
          windowsHide: true,
        }).trim();
      } catch {
        fail('E7_RELEASE_TAG_NOT_FOUND');
      }
      if (tagged !== candidateSha) fail('E7_RELEASE_TAG_CANDIDATE_MISMATCH');
    }
    return { ...actual, candidateSha, releaseId, releaseTag };
  }
  return { ...actual, candidateSha, releaseId };
};

const verifyConfigScope = (config, scope) => {
  const expected = scope === 'full' ? 'FULL_RELEASE_VERSIONED_UPDATE' : 'EPHEMERAL_PRERELEASE';
  if (config.authorization.scope !== expected) fail('E7_CONFIG_SCOPE_MISMATCH');
  if (
    (process.env.STAGE7_AWS_ACCOUNT_ID !== undefined &&
      process.env.STAGE7_AWS_ACCOUNT_ID !== config.aws.accountId) ||
    (process.env.STAGE7_AWS_REGION !== undefined &&
      process.env.STAGE7_AWS_REGION !== config.aws.region)
  ) {
    fail('E7_CONFIG_AWS_TARGET_MISMATCH');
  }
};

const verifyAwsConfigScope = (config, scope) => {
  if (scope !== 'baseline') {
    verifyConfigScope(config, scope);
    return;
  }
  if (
    config.authorization.scope !== 'FULL_RELEASE_BASELINE_CLOSED' ||
    (process.env.STAGE7_AWS_ACCOUNT_ID !== undefined &&
      process.env.STAGE7_AWS_ACCOUNT_ID !== config.aws.accountId) ||
    (process.env.STAGE7_AWS_REGION !== undefined &&
      process.env.STAGE7_AWS_REGION !== config.aws.region)
  ) {
    fail('E7_CONFIG_SCOPE_MISMATCH');
  }
};

export const loadExactStage6Closeout = ({ directory, expectedSha256, scope }) => {
  if (!SHA256.test(expectedSha256 ?? '')) fail('E7_STAGE6_MANIFEST_DIGEST_INVALID');
  const filename = findExactlyOne(directory, 'closeout.json');
  const actualSha256 = fileDigest(filename);
  if (actualSha256 !== expectedSha256) fail('E7_STAGE6_MANIFEST_DIGEST_MISMATCH');
  const manifest = readEvidence(filename);
  const assessment = assessStage6Manifest(manifest);
  const expectedStatus = scope === 'full' ? 'PASS' : 'CONDITIONAL_GO';
  if (assessment.status !== expectedStatus) fail('E7_STAGE6_SCOPE_GATE_MISMATCH');
  return {
    assessment,
    manifest,
    manifestSha256: actualSha256,
    relativePath: path.relative(workspaceRoot, filename).replaceAll('\\', '/'),
  };
};

const validateStage6CloseoutBinding = ({ map, identity, metadata, freezeManifest, scope }) => {
  const stage6CloseoutFilename = map.get('stage6-closeout.json');
  if (stage6CloseoutFilename === undefined) fail('E7_STAGE6_CLOSEOUT_BINDING_INVALID');
  const stage6Closeout = readEvidence(stage6CloseoutFilename);
  const assessment = assessStage6Manifest(stage6Closeout);
  const expectedStatus = scope === 'full' ? 'PASS' : 'CONDITIONAL_GO';
  const expectedDecision =
    scope === 'full' ? 'READY_FOR_BUILD_FREEZE' : 'READY_FOR_AUTHORIZED_EPHEMERAL_PREFLIGHT';
  if (
    assessment.status !== expectedStatus ||
    assessment.candidate?.commitSha !== identity.candidateSha ||
    assessment.candidate?.treeSha !== identity.treeSha ||
    metadata.scope !== scope ||
    metadata.candidateSha !== identity.candidateSha ||
    metadata.candidateTreeSha !== identity.treeSha ||
    metadata.releaseId !== identity.releaseId ||
    !RUN_ID.test(metadata.releaseRunId ?? '') ||
    metadata.releaseRunAttempt !== 1 ||
    metadata.stage6RunId !== assessment.runId ||
    metadata.stage6ManifestSha256 !== fileDigest(stage6CloseoutFilename) ||
    metadata.stage6Status !== expectedStatus ||
    metadata.decision !== expectedDecision ||
    freezeManifest.candidateSha !== identity.candidateSha ||
    freezeManifest.candidateTreeSha !== identity.treeSha ||
    freezeManifest.sourceRunId !== assessment.runId ||
    objectSha256(freezeManifest.stage6Gates) !== objectSha256(stage6Closeout.gates)
  ) {
    fail('E7_STAGE6_CLOSEOUT_BINDING_INVALID');
  }
  return stage6Closeout;
};

const assertStage6Flags = (flags, scope) => {
  if (scope === 'prerelease' && flags['require-e6-conditional-go'] !== true) {
    fail('E7_CONDITIONAL_GO_ACK_REQUIRED');
  }
  if (scope === 'full' && flags['require-e6-conditional-go'] !== undefined) {
    fail('E7_CONDITIONAL_GO_SCOPE_INVALID');
  }
};

const awsCliVersion = () => {
  let output;
  try {
    output = execFileSync('aws', ['--version'], {
      encoding: 'utf8',
      maxBuffer: 1024 * 1024,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (error) {
    output = `${error?.stdout ?? ''}${error?.stderr ?? ''}`;
  }
  const match = /aws-cli\/(\d+\.\d+\.\d+)/u.exec(output ?? '');
  if (match === null) fail('E7_AWS_CLI_VERSION_UNAVAILABLE');
  return match[1];
};

const parseFlags = (arguments_) => {
  const result = {};
  for (let index = 0; index < arguments_.length; index += 1) {
    const name = arguments_[index];
    if (!name.startsWith('--')) fail('E7_CONTROL_ARGUMENT_INVALID');
    const key = name.slice(2);
    if (Object.hasOwn(result, key)) fail('E7_CONTROL_ARGUMENT_DUPLICATE');
    if (key === 'pre-upload') {
      const values = [];
      while (arguments_[index + 1] !== undefined && !arguments_[index + 1].startsWith('--')) {
        values.push(arguments_[(index += 1)]);
      }
      if (values.length === 0) fail('E7_CONTROL_ARGUMENT_VALUE_REQUIRED');
      result[key] = values;
    } else if (arguments_[index + 1] !== undefined && !arguments_[index + 1].startsWith('--')) {
      result[key] = arguments_[(index += 1)];
    } else result[key] = true;
  }
  return result;
};

const exactFlags = (flags, allowed) => {
  if (Object.keys(flags).some((key) => !allowed.includes(key))) {
    fail('E7_CONTROL_ARGUMENT_SET_INVALID');
  }
};

const requiredString = (flags, key) => {
  if (typeof flags[key] !== 'string' || flags[key].trim() === '') {
    fail('E7_CONTROL_ARGUMENT_VALUE_REQUIRED');
  }
  return flags[key];
};

const emitJson = async (value, target, label) => {
  if (target !== undefined) await writeStage7Json(target, label, value);
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
};

const preflightLocal = async (flags) => {
  const scope = scopeOf(flags);
  assertStage6Flags(flags, scope);
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope);
  const stage6 = loadExactStage6Closeout({
    directory: requiredString(flags, 'stage6-evidence'),
    expectedSha256: requiredString(flags, 'stage6-manifest-sha256'),
    scope,
  });
  if (
    stage6.assessment.candidate.commitSha !== identity.commitSha ||
    stage6.assessment.candidate.treeSha !== identity.treeSha
  ) {
    fail('E7_STAGE6_CANDIDATE_MISMATCH');
  }
  const preflight = createLocalPreflight({
    config,
    e6Manifest: stage6.manifest,
    candidate: identity,
  });
  const expectedDecision =
    scope === 'full' ? 'READY_FOR_BUILD_FREEZE' : 'READY_FOR_AUTHORIZED_EPHEMERAL_PREFLIGHT';
  if (preflight.decision !== expectedDecision) fail('E7_LOCAL_PREFLIGHT_NOT_READY');
  const releaseRunId = String(process.env.GITHUB_RUN_ID ?? '');
  const releaseRunAttempt = String(process.env.GITHUB_RUN_ATTEMPT ?? '');
  if (!RUN_ID.test(releaseRunId) || releaseRunAttempt !== '1') {
    fail('E7_RELEASE_RUN_ORIGIN_INVALID');
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_ENTRY_PREFLIGHT',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    candidateTreeSha: identity.treeSha,
    releaseRunId,
    releaseRunAttempt: 1,
    stage6RunId: stage6.assessment.runId,
    stage6ManifestSha256: stage6.manifestSha256,
    stage6Status: stage6.assessment.status,
    decision: preflight.decision,
    authorizationScope: config.authorization.scope,
    configSha256: objectSha256(config),
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(
    result,
    flags.evidence ??
      path.join(evidenceRoot(scope), scope === 'full' ? 'release-metadata.json' : 'metadata.json'),
    'stage7-release-entry-preflight.json',
  );
};

const verifyCandidate = async (flags) => {
  const scope = scopeOf(flags);
  assertStage6Flags(flags, scope);
  const identity = candidateIdentity(scope, { requireGitTag: scope === 'full' });
  const stage6 = loadExactStage6Closeout({
    directory: requiredString(flags, 'stage6-evidence'),
    expectedSha256: requiredString(flags, 'stage6-manifest-sha256'),
    scope,
  });
  if (
    stage6.assessment.candidate.commitSha !== identity.commitSha ||
    stage6.assessment.candidate.treeSha !== identity.treeSha
  ) {
    fail('E7_STAGE6_CANDIDATE_MISMATCH');
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'CANDIDATE_VERIFICATION',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    candidateTreeSha: identity.treeSha,
    immutableIdentifier: scope === 'full' ? identity.releaseTag : identity.releaseId,
    releaseId: identity.releaseId,
    stage6RunId: stage6.assessment.runId,
    stage6ManifestSha256: stage6.manifestSha256,
    stage6Status: stage6.assessment.status,
    workingTree: identity.workingTree,
    changedFiles: identity.changedFiles,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(
    result,
    path.join(evidenceRoot(scope), 'verify-candidate.json'),
    'stage7-verify-candidate.json',
  );
};

const builtAtFromIdentity = (scope, identity) => {
  const match = RELEASE_ID.exec(identity.releaseId);
  const date = match[1];
  const time = match[2];
  const value = `${date.slice(0, 4)}-${date.slice(4, 6)}-${date.slice(6, 8)}T${time.slice(0, 2)}:${time.slice(2)}:00.000Z`;
  if (Number.isNaN(Date.parse(value))) fail('E7_RELEASE_ID_TIMESTAMP_INVALID');
  return value;
};

const freezeExisting = async (flags) => {
  const scope = scopeOf(flags);
  assertStage6Flags(flags, scope);
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope, { requireGitTag: scope === 'full' });
  const stage6 = loadExactStage6Closeout({
    directory: requiredString(flags, 'stage6-evidence'),
    expectedSha256: requiredString(flags, 'stage6-manifest-sha256'),
    scope,
  });
  const sourceArtifactId = requiredString(flags, 'source-artifact-id');
  const sourceArtifactSha256 = requiredString(flags, 'source-artifact-sha256');
  const tag = scope === 'full' ? requiredString(flags, 'tag') : null;
  if (scope === 'full' && tag !== identity.releaseTag) fail('E7_RELEASE_TAG_CANDIDATE_MISMATCH');
  let preFreezeEvidenceSha256 = null;
  if (scope === 'full') {
    const preFreezeFilename = requiredString(flags, 'pre-freeze-evidence');
    const preFreeze = readEvidence(preFreezeFilename);
    if (
      preFreeze.schemaVersion !== 1 ||
      preFreeze.stage !== 7 ||
      preFreeze.kind !== 'AWS_PRE_FREEZE_SYNTH_PREFLIGHT' ||
      preFreeze.status !== 'PASS' ||
      preFreeze.candidateSha !== identity.candidateSha ||
      preFreeze.releaseId !== identity.releaseId ||
      preFreeze.configSha256 !== objectSha256(config) ||
      preFreeze.decision !== 'READY_FOR_BUILD_FREEZE' ||
      preFreeze.preFreezeException !== true ||
      preFreeze.manifestSha256 !== null ||
      preFreeze.mutationsPerformed !== 0 ||
      preFreeze.containsSensitiveData !== false
    ) {
      fail('E7_PRE_FREEZE_EVIDENCE_INVALID');
    }
    preFreezeEvidenceSha256 = fileDigest(preFreezeFilename);
  } else if (flags['pre-freeze-evidence'] !== undefined) {
    fail('E7_PRE_FREEZE_EVIDENCE_SCOPE_INVALID');
  }
  const manifest = createFreezeManifest({
    config,
    e6Manifest: stage6.manifest,
    candidate: identity,
    releaseTag: tag,
    builtAt: builtAtFromIdentity(scope, identity),
    sourceArtifactId,
    sourceArtifactSha256,
    preFreezeEvidenceSha256,
    awsCliVersion: awsCliVersion(),
    paths: {
      web: path.join(workspaceRoot, 'output/release/build/web'),
      api: path.join(workspaceRoot, 'output/release/build/api'),
      worker: path.join(workspaceRoot, 'output/release/build/worker'),
      iac: path.join(workspaceRoot, 'output/release/build/iac'),
      lockfile: path.join(workspaceRoot, 'pnpm-lock.yaml'),
      openapi: path.join(workspaceRoot, 'output/architecture/openapi.yaml'),
      generatedClient: path.join(workspaceRoot, 'packages/contracts/src/generated/openapi.d.ts'),
      publicConfig: path.join(workspaceRoot, 'output/release/build/public-config.json'),
    },
  });
  if (manifest.releaseId !== identity.releaseId) {
    fail('E7_RELEASE_ID_FREEZE_MISMATCH');
  }
  await emitJson(
    manifest,
    path.join(evidenceRoot(scope), 'candidate-manifest.json'),
    'stage7-candidate-manifest.json',
  );
};

const downloadedArtifactPath = (root, sourcePath) => {
  const choices = [
    path.join(root, ...sourcePath.split('/')),
    sourcePath.startsWith('output/release/build/')
      ? path.join(root, ...sourcePath.slice('output/release/build/'.length).split('/'))
      : undefined,
  ].filter(Boolean);
  const existing = choices.filter((choice) => {
    try {
      lstatSync(choice);
      return true;
    } catch {
      return false;
    }
  });
  if (existing.length !== 1) fail('E7_DOWNLOADED_ARTIFACT_LAYOUT_INVALID');
  return checkedWorkspacePath(existing[0]);
};

const inventoryFiles = (root) => {
  const { files } = walkFiles(root);
  if (files.length === 0) fail('E7_DOWNLOADED_ARTIFACT_EMPTY');
  return files.map((file) => ({
    path: file.relative,
    bytes: file.bytes,
    sha256: fileDigest(file.absolute),
  }));
};

const verifyDownloadedArtifact = async (flags) => {
  const scope = scopeOf(flags);
  const identity = candidateIdentity(scope, { requireGitTag: scope === 'full' });
  const root = checkedWorkspacePath(requiredString(flags, 'verify-artifact'), { directory: true });
  const manifest = validateFreezeManifest(readEvidence(requiredString(flags, 'manifest')));
  if (
    manifest.candidateSha !== identity.candidateSha ||
    manifest.candidateTreeSha !== identity.treeSha ||
    manifest.authorizationScope !==
      (scope === 'full' ? 'FULL_RELEASE_VERSIONED_UPDATE' : 'EPHEMERAL_PRERELEASE') ||
    manifest.releaseId !== identity.releaseId ||
    (scope === 'full' && manifest.releaseTag !== identity.releaseTag)
  ) {
    fail('E7_DOWNLOADED_MANIFEST_IDENTITY_MISMATCH');
  }
  const coveredFiles = new Set();
  for (const expected of manifest.artifacts) {
    const candidate = downloadedArtifactPath(root, expected.sourcePath);
    const actual = hashArtifactPath(candidate, { rootDirectory: root });
    for (const key of ['kind', 'files', 'bytes', 'sha256']) {
      if (actual[key] !== expected[key]) fail('E7_DOWNLOADED_ARTIFACT_DIGEST_MISMATCH');
    }
    const stat = lstatSync(candidate);
    if (stat.isFile()) coveredFiles.add(path.relative(root, candidate).replaceAll('\\', '/'));
    else {
      for (const file of walkFiles(candidate).files) {
        coveredFiles.add(path.relative(root, file.absolute).replaceAll('\\', '/'));
      }
    }
  }
  const publicConfig = downloadedArtifactPath(root, 'output/release/build/public-config.json');
  if (fileDigest(publicConfig) !== manifest.publicConfigSha256) {
    fail('E7_DOWNLOADED_PUBLIC_CONFIG_MISMATCH');
  }
  coveredFiles.add(path.relative(root, publicConfig).replaceAll('\\', '/'));
  const inventory = inventoryFiles(root);
  if (
    inventory.length !== coveredFiles.size ||
    inventory.some((entry) => !coveredFiles.has(entry.path))
  ) {
    fail('E7_DOWNLOADED_ARTIFACT_INVENTORY_MISMATCH');
  }
  const provenance = {
    lockfileSha256: fileDigest(path.join(workspaceRoot, 'pnpm-lock.yaml')),
    openApiSha256: fileDigest(path.join(workspaceRoot, 'output/architecture/openapi.yaml')),
    generatedClientSha256: fileDigest(
      path.join(workspaceRoot, 'packages/contracts/src/generated/openapi.d.ts'),
    ),
  };
  if (
    provenance.lockfileSha256 !== manifest.lockfileSha256 ||
    provenance.openApiSha256 !== manifest.openApiSha256 ||
    provenance.generatedClientSha256 !== manifest.generatedClientSha256 ||
    process.version !== manifest.toolchain.node
  ) {
    fail('E7_DOWNLOADED_ARTIFACT_PROVENANCE_MISMATCH');
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'CHECKSUMS_INVENTORY_PROVENANCE',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    manifestSha256: manifest.manifestSha256,
    sourceArtifactId: manifest.sourceArtifactId,
    sourceArtifactSha256: manifest.sourceArtifactSha256,
    artifactDigests: Object.fromEntries(
      manifest.artifacts.map(({ name, sha256 }) => [name, sha256]),
    ),
    inventoryFormat: 'SHA256_INVENTORY_V1',
    inventory,
    provenance,
    findings: 0,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(
    result,
    path.join(evidenceRoot(scope), 'checksums-sbom.json'),
    'stage7-checksums-sbom.json',
  );
};

const verifyPreviousManifest = async (flags) => {
  const approvedCopy = requiredString(flags, 'approved-copy');
  const expectedSha256 = requiredString(flags, 'manifest-sha256');
  if (!SHA256.test(expectedSha256)) fail('E7_PREVIOUS_RELEASE_MANIFEST_SHA_INVALID');
  const manifest = validateStage7PreviousReleaseManifest(readEvidence(approvedCopy));
  if (fileDigest(approvedCopy) !== expectedSha256 || manifest.manifestSha256 !== expectedSha256) {
    fail('E7_PREVIOUS_RELEASE_MANIFEST_SHA_MISMATCH');
  }
  await emitJson(
    {
      schemaVersion: 1,
      stage: 7,
      kind: 'PREVIOUS_RELEASE_MANIFEST_VERIFICATION',
      status: 'PASS',
      previousReleaseManifestSha256: manifest.manifestSha256,
      previousCandidateSha: manifest.previous.candidateSha,
      targetCandidateSha: manifest.target.candidateSha,
      compatibilityStatus: manifest.compatibility.status,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    },
    requiredString(flags, 'evidence'),
    'stage7-previous-release-manifest-verification.json',
  );
};

const requireCurrentFreeze = (flags, scope, identity, config) => {
  const manifest = validateFreezeManifest(readEvidence(requiredString(flags, 'manifest')));
  if (
    manifest.candidateSha !== identity.candidateSha ||
    manifest.candidateTreeSha !== identity.treeSha ||
    manifest.releaseId !== identity.releaseId ||
    manifest.releaseTag !== (scope === 'full' ? identity.releaseTag : null) ||
    manifest.authorizationScope !==
      (scope === 'full' ? 'FULL_RELEASE_VERSIONED_UPDATE' : 'EPHEMERAL_PRERELEASE') ||
    manifest.environment !== config.environment ||
    manifest.region !== config.aws.region ||
    manifest.configSha256 !== objectSha256(config)
  ) {
    fail('E7_CLOUD_PREFLIGHT_FREEZE_MISMATCH');
  }
  return manifest;
};

const verifyLiveJournalRoleAuthority = (flags) => {
  exactFlags(flags, [
    'scope',
    'manifest',
    'aws-auth',
    'frozen-effective-permissions',
    'live-effective-permissions',
  ]);
  const scope = scopeOf(flags);
  if (scope !== 'full') fail('E7_RELEASE_JOURNAL_ROLE_AUTHORITY_SCOPE_INVALID');
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope, { requireGitTag: true });
  const manifest = requireCurrentFreeze(flags, scope, identity, config);
  const awsAuthSource = readEvidenceSource(requiredString(flags, 'aws-auth'));
  const frozenSource = readEvidenceSource(requiredString(flags, 'frozen-effective-permissions'));
  const liveSource = readEvidenceSource(requiredString(flags, 'live-effective-permissions'));
  const roleArn = process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN;
  const permissionsBoundaryArn =
    process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN;
  if (
    typeof roleArn !== 'string' ||
    roleArn.length === 0 ||
    typeof permissionsBoundaryArn !== 'string' ||
    permissionsBoundaryArn.length === 0
  ) {
    fail('E7_RELEASE_JOURNAL_ROLE_AUTHORITY_ENVIRONMENT_REQUIRED');
  }
  try {
    validateReleaseJournalRoleEffectivePermissionsBinding({
      awsAuthSource,
      effectivePermissionsSource: frozenSource,
      expected: {
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        configSha256: objectSha256(config),
        manifestSha256: manifest.manifestSha256,
      },
    });
    const comparison = compareReleaseJournalRoleEffectivePermissions({
      frozenSource,
      liveSource,
      expectedRoleArn: roleArn,
      expectedPermissionsBoundaryArn: permissionsBoundaryArn,
    });
    process.stdout.write(
      `${JSON.stringify({
        schemaVersion: 1,
        stage: 7,
        kind: 'LIVE_RELEASE_JOURNAL_ROLE_AUTHORITY_CHECK',
        status: 'PASS',
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        effectivePolicyProjectionSha256: comparison.effectivePolicyProjectionSha256,
        frozenEffectivePermissionsSha256: comparison.frozenEffectivePermissionsSha256,
        liveEffectivePermissionsSha256: comparison.liveEffectivePermissionsSha256,
        liveSourceBindingCount: comparison.liveSourceBindingCount,
        externalRequests: 0,
        mutationsPerformed: 0,
        containsSensitiveData: false,
      })}\n`,
    );
  } catch (error) {
    if (error instanceof Stage7ReleaseSuccessorIamAuthorityError) {
      fail('E7_RELEASE_JOURNAL_ROLE_LIVE_AUTHORITY_MISMATCH');
    }
    throw error;
  }
};

const verifyReleaseSuccessorFenceCheckpoint = (flags) => {
  exactFlags(flags, [
    'fence',
    'release-metadata',
    'approval',
    'activation',
    'drift',
    'protected-run',
    'completion',
    'pre-fence-gate',
  ]);
  const metadata = readEvidence(requiredString(flags, 'release-metadata'));
  const protectedRun = readEvidence(requiredString(flags, 'protected-run'));
  const completion = readEvidence(requiredString(flags, 'completion'));
  const candidateSha = process.env.STAGE7_CANDIDATE_SHA;
  const releaseId = process.env.STAGE7_RELEASE_ID;
  if (
    !SHA.test(candidateSha ?? '') ||
    !RELEASE_ID.test(releaseId ?? '') ||
    metadata.scope !== 'full' ||
    metadata.candidateSha !== candidateSha ||
    metadata.releaseId !== releaseId ||
    String(metadata.releaseRunId) !== process.env.GITHUB_RUN_ID ||
    metadata.releaseRunAttempt !== 1 ||
    process.env.GITHUB_RUN_ATTEMPT !== '1'
  ) {
    fail('E7_RELEASE_SUCCESSOR_COMPLETION_FENCE_IDENTITY_INVALID');
  }
  try {
    const fence = validateReleaseSuccessorCompletionFence(
      readEvidence(requiredString(flags, 'fence')),
      {
        candidateSha,
        releaseId,
        sourceRunId: metadata.releaseRunId,
        sourceRunAttempt: metadata.releaseRunAttempt,
        journalLifecycleSha256: completion.journalLifecycleSha256,
        journalCleanupRoleSha256:
          protectedRun.runtimeAttestation?.journalLifecycle?.cleanupRoleSha256,
        evidenceBindings: {
          approval: evidenceFileBinding(requiredString(flags, 'approval')),
          activation: evidenceFileBinding(requiredString(flags, 'activation')),
          drift: evidenceFileBinding(requiredString(flags, 'drift')),
          rollbackCompletion: evidenceFileBinding(requiredString(flags, 'completion')),
          preFenceGate: evidenceFileBinding(requiredString(flags, 'pre-fence-gate')),
        },
      },
    );
    process.stdout.write(
      `${JSON.stringify({
        schemaVersion: 1,
        stage: 7,
        kind: 'RELEASE_SUCCESSOR_COMPLETION_FENCE_CHECK',
        status: 'PASS',
        candidateSha,
        releaseId,
        fenceSha256: fence.fenceSha256,
        externalRequests: 0,
        mutationsPerformed: 0,
        containsSensitiveData: false,
      })}\n`,
    );
  } catch (error) {
    if (error instanceof Stage7ReleaseSuccessorFenceContractError) {
      fail('E7_RELEASE_SUCCESSOR_COMPLETION_FENCE_INVALID');
    }
    throw error;
  }
};

const requireBaselineFreeze = (flags, identity, config) => {
  let manifest;
  try {
    manifest = validateBaselineFreeze(readEvidence(requiredString(flags, 'manifest')));
  } catch {
    fail('E7_CLOUD_PREFLIGHT_BASELINE_FREEZE_INVALID');
  }
  if (
    manifest.candidateSha !== identity.candidateSha ||
    manifest.candidateTreeSha !== identity.treeSha ||
    manifest.releaseId !== identity.releaseId ||
    manifest.authorizationScope !== 'FULL_RELEASE_BASELINE_CLOSED' ||
    manifest.environment !== config.environment ||
    manifest.region !== config.aws.region ||
    manifest.configSha256 !== objectSha256(config)
  ) {
    fail('E7_CLOUD_PREFLIGHT_FREEZE_MISMATCH');
  }
  return manifest;
};

const scanFileSet = (paths) => {
  let filesScanned = 0;
  let bytesScanned = 0;
  for (const requested of paths) {
    const absolute = checkedWorkspacePath(requested);
    const files = lstatSync(absolute).isDirectory()
      ? walkFiles(absolute).files
      : [{ absolute, relative: path.basename(absolute), bytes: lstatSync(absolute).size }];
    for (const file of files) {
      if (FORBIDDEN_ARTIFACT_PATH.test(file.relative)) fail('E7_SCAN_FORBIDDEN_ARTIFACT_PATH');
      const source = readFileSync(file.absolute);
      bytesScanned += source.length;
      filesScanned += 1;
      const prefix = source.subarray(0, Math.min(source.length, 1024 * 1024)).toString('utf8');
      if (/-----BEGIN (?:EC |OPENSSH |RSA )?PRIVATE KEY-----/u.test(prefix)) {
        fail('E7_SCAN_PRIVATE_KEY_FOUND');
      }
      const extension = path.extname(file.relative).toLowerCase();
      if (!TEXT_EXTENSIONS.has(extension)) continue;
      const text = source.toString('utf8');
      if (scanText(file.relative, text).length > 0) fail('E7_SCAN_SECRET_OR_PAYMENT_DATA_FOUND');
      if (EVIDENCE_TEXT_EXTENSIONS.has(extension)) {
        try {
          assertSanitizedArtifactText(file.relative, text);
        } catch {
          fail('E7_SCAN_UNSANITIZED_EVIDENCE_FOUND');
        }
      }
      if (/https:\/\/(?:api\.)?wompi\.co\b/iu.test(text)) fail('E7_SCAN_PRODUCTION_PROVIDER_FOUND');
    }
  }
  return { filesScanned, bytesScanned };
};

const removeControlSelfTestDirectory = (outputRoot, target) => {
  relativeInside(outputRoot, target, 'E7_SELFTEST_CLEANUP_PATH_INVALID');
  for (const child of readdirSync(target, { withFileTypes: true })) {
    if (
      ![
        '.active',
        'assets.json',
        'partial-security.json',
        'readiness-api.txt',
        'readiness-generatedClient.txt',
        'readiness-iac.txt',
        'readiness-lockfile.txt',
        'readiness-openapi.txt',
        'readiness-publicConfig.txt',
        'readiness-web.txt',
        'readiness-worker.txt',
        'safe.txt',
        'stage6-closeout.json',
        'unsafe.bin',
      ].includes(child.name)
    ) {
      fail('E7_SELFTEST_CLEANUP_CONTENT_INVALID');
    }
    if (!child.isFile() || child.isSymbolicLink()) fail('E7_SELFTEST_CLEANUP_CONTENT_INVALID');
    const childPath = path.join(target, child.name);
    relativeInside(target, childPath, 'E7_SELFTEST_CLEANUP_PATH_INVALID');
    unlinkSync(childPath);
  }
  rmdirSync(target);
};

const cleanupControlSelfTestDirectories = (outputRoot) => {
  const active = [];
  for (const entry of readdirSync(outputRoot, { withFileTypes: true })) {
    if (!/^\.stage7-control-selftest-[A-Za-z0-9_-]{4,64}$/u.test(entry.name)) continue;
    const target = path.join(outputRoot, entry.name);
    relativeInside(outputRoot, target, 'E7_SELFTEST_CLEANUP_PATH_INVALID');
    const stat = lstatSync(target);
    if (!entry.isDirectory() || stat.isSymbolicLink()) {
      fail('E7_SELFTEST_CLEANUP_TARGET_INVALID');
    }
    const marker = path.join(target, '.active');
    try {
      const markerStat = lstatSync(marker);
      if (!markerStat.isFile() || markerStat.isSymbolicLink()) {
        fail('E7_SELFTEST_CLEANUP_TARGET_INVALID');
      }
      const markerText = readFileSync(marker, 'utf8').trim();
      const pid = /^\d{1,10}$/u.test(markerText) ? Number(markerText) : Number.NaN;
      if (!Number.isSafeInteger(pid) || pid <= 0) fail('E7_SELFTEST_CLEANUP_MARKER_INVALID');
      try {
        process.kill(pid, 0);
        active.push(target);
        continue;
      } catch (error) {
        if (error?.code !== 'ESRCH') {
          // EPERM means that a process with this pid exists but is owned by a
          // different principal.  Treat it as active rather than deleting a
          // directory that could belong to a concurrent protected runner.
          if (error?.code === 'EPERM') {
            active.push(target);
            continue;
          }
          fail('E7_SELFTEST_CLEANUP_MARKER_UNVERIFIABLE');
        }
      }
    } catch (error) {
      if (error instanceof Stage7ControlError) throw error;
    }
    removeControlSelfTestDirectory(outputRoot, target);
  }
  return active;
};

const runHistoryScan = () => {
  const result = spawnSync(
    process.execPath,
    [
      path.join(workspaceRoot, 'scripts/security/scan-repository.mjs'),
      '--root',
      workspaceRoot,
      '--history',
    ],
    {
      cwd: workspaceRoot,
      encoding: 'utf8',
      maxBuffer: 64 * 1024 * 1024,
      windowsHide: true,
    },
  );
  if (result.status !== 0) fail('E7_SCAN_HISTORY_FAILED');
};

const jsonTemplates = (assembly) =>
  walkFiles(assembly).files.filter((file) => file.relative.endsWith('.template.json'));

const statements = (document) => {
  const value = document?.Statement;
  return Array.isArray(value) ? value : value === undefined ? [] : [value];
};

const cloudFormationTags = (resource) => {
  const tags = resource?.Properties?.Tags;
  if (!Array.isArray(tags)) return new Map();
  const entries = [];
  for (const tag of tags) {
    if (
      !object(tag) ||
      typeof tag.Key !== 'string' ||
      typeof tag.Value !== 'string' ||
      entries.some(([key]) => key === tag.Key)
    ) {
      fail('E7_CLOUD_ASSEMBLY_TAGS_INVALID');
    }
    entries.push([tag.Key, tag.Value]);
  }
  return new Map(entries);
};

const assertEphemeralResourceTags = (resource) => {
  const tags = cloudFormationTags(resource);
  const expiry = tags.get('ExpiresOn');
  if (
    tags.get('DataClass') !== 'synthetic-only' ||
    !/^assessment-prerelease-[a-z0-9][a-z0-9-]{0,18}$/u.test(tags.get('Environment') ?? '') ||
    !/^\d{4}-\d{2}-\d{2}$/u.test(expiry ?? '') ||
    Number.isNaN(Date.parse(`${expiry}T00:00:00.000Z`)) ||
    new Date(`${expiry}T00:00:00.000Z`).toISOString().slice(0, 10) !== expiry
  ) {
    fail('E7_CLOUD_ASSEMBLY_EPHEMERAL_TAGS_INVALID');
  }
};

export const validateCloudAssemblyLifecycle = ({ scope, manifest, templates, templateFiles }) => {
  if (!['full', 'prerelease'].includes(scope)) fail('E7_CLOUD_ASSEMBLY_SCOPE_INVALID');
  if (!object(manifest?.artifacts) || !Array.isArray(templates) || templates.length !== 4) {
    fail('E7_CLOUD_ASSEMBLY_STACK_SET_INVALID');
  }
  const stackArtifacts = Object.entries(manifest.artifacts).filter(
    ([, artifact]) => artifact?.type === 'aws:cloudformation:stack',
  );
  if (
    stackArtifacts.length !== 4 ||
    stackArtifacts.some(
      ([, artifact]) =>
        !object(artifact.properties) ||
        typeof artifact.properties.templateFile !== 'string' ||
        typeof artifact.properties.terminationProtection !== 'boolean' ||
        artifact.properties.terminationProtection !== (scope === 'full'),
    )
  ) {
    fail('E7_CLOUD_ASSEMBLY_TERMINATION_PROTECTION_INVALID');
  }
  if (templateFiles !== undefined) {
    const expectedFiles = stackArtifacts.map(([, artifact]) =>
      artifact.properties.templateFile.replaceAll('\\', '/'),
    );
    const actualFiles = templateFiles.map((filename) => filename.replaceAll('\\', '/'));
    if (
      expectedFiles.some(
        (filename) =>
          path.posix.isAbsolute(filename) ||
          filename.split('/').includes('..') ||
          !filename.endsWith('.template.json'),
      ) ||
      new Set(expectedFiles).size !== 4 ||
      expectedFiles.toSorted().join('\0') !== actualFiles.toSorted().join('\0')
    ) {
      fail('E7_CLOUD_ASSEMBLY_TEMPLATE_BINDING_INVALID');
    }
  }

  const expectedPolicy = scope === 'full' ? 'Retain' : 'Delete';
  const lifecycle = {
    statefulResources: 0,
    tables: 0,
    buckets: 0,
    lambdaVersions: 0,
    autoDeleteResources: 0,
    bucketDeployments: 0,
  };
  for (const template of templates) {
    if (!object(template?.Resources)) fail('E7_CLOUD_ASSEMBLY_TEMPLATE_INVALID');
    for (const resource of Object.values(template.Resources)) {
      if (!object(resource) || typeof resource.Type !== 'string') {
        fail('E7_CLOUD_ASSEMBLY_RESOURCE_INVALID');
      }
      const hasLifecycle =
        resource.DeletionPolicy !== undefined || resource.UpdateReplacePolicy !== undefined;
      if (hasLifecycle) {
        lifecycle.statefulResources += 1;
        const resourcePolicy =
          scope === 'full' && resource.Type === 'Custom::CDKBucketDeployment'
            ? 'Delete'
            : expectedPolicy;
        if (
          resource.DeletionPolicy !== resourcePolicy ||
          resource.UpdateReplacePolicy !== resourcePolicy
        ) {
          fail('E7_CLOUD_ASSEMBLY_LIFECYCLE_POLICY_INVALID');
        }
      }
      if (resource.Type === 'AWS::DynamoDB::Table') {
        lifecycle.tables += 1;
        if (
          resource.DeletionPolicy !== expectedPolicy ||
          resource.UpdateReplacePolicy !== expectedPolicy ||
          resource.Properties?.SSESpecification?.SSEEnabled !== true ||
          resource.Properties?.PointInTimeRecoverySpecification?.PointInTimeRecoveryEnabled !==
            true ||
          resource.Properties?.DeletionProtectionEnabled !== (scope === 'full')
        ) {
          fail('E7_CLOUD_ASSEMBLY_STATEFUL_PROTECTION_INVALID');
        }
        if (scope === 'prerelease') assertEphemeralResourceTags(resource);
      }
      if (resource.Type === 'AWS::S3::Bucket') {
        lifecycle.buckets += 1;
        if (
          resource.DeletionPolicy !== expectedPolicy ||
          resource.UpdateReplacePolicy !== expectedPolicy
        ) {
          fail('E7_CLOUD_ASSEMBLY_STATEFUL_PROTECTION_INVALID');
        }
        if (scope === 'prerelease') assertEphemeralResourceTags(resource);
      }
      if (resource.Type === 'AWS::Lambda::Version') {
        lifecycle.lambdaVersions += 1;
        if (
          resource.DeletionPolicy !== expectedPolicy ||
          resource.UpdateReplacePolicy !== expectedPolicy
        ) {
          fail('E7_CLOUD_ASSEMBLY_LAMBDA_VERSION_LIFECYCLE_INVALID');
        }
      }
      if (resource.Type === 'Custom::S3AutoDeleteObjects') {
        lifecycle.autoDeleteResources += 1;
      }
      if (resource.Type === 'Custom::CDKBucketDeployment') {
        lifecycle.bucketDeployments += 1;
        if (resource.Properties?.RetainOnDelete !== (scope === 'full')) {
          fail('E7_CLOUD_ASSEMBLY_BUCKET_DEPLOYMENT_CLEANUP_INVALID');
        }
      }
    }
  }
  if (
    lifecycle.statefulResources < 5 ||
    lifecycle.tables !== 2 ||
    lifecycle.buckets !== 1 ||
    lifecycle.lambdaVersions !== 2 ||
    lifecycle.bucketDeployments !== 2 ||
    lifecycle.autoDeleteResources !== (scope === 'prerelease' ? 1 : 0)
  ) {
    fail('E7_CLOUD_ASSEMBLY_CLEANUP_CONTRACT_INVALID');
  }
  return lifecycle;
};

const inspectBootstrapAssetInventory = ({ root, manifest, assemblySha256 }) => {
  const assetArtifacts = Object.entries(manifest.artifacts).filter(
    ([, artifact]) => artifact?.type === 'cdk:asset-manifest',
  );
  if (assetArtifacts.length < 1) fail('E7_CDK_ASSET_MANIFEST_MISSING');
  const manifestSummaries = [];
  const regions = new Set();
  let fileAssetCount = 0;
  let dockerImageAssetCount = 0;
  for (const [, artifact] of assetArtifacts) {
    const relative = artifact?.properties?.file;
    if (
      typeof relative !== 'string' ||
      relative.length === 0 ||
      relative.includes('\\') ||
      path.posix.isAbsolute(relative) ||
      relative.split('/').includes('..')
    ) {
      fail('E7_CDK_ASSET_MANIFEST_PATH_INVALID');
    }
    const absolute = path.resolve(root, ...relative.split('/'));
    const inside = path.relative(root, absolute);
    if (inside === '' || inside === '..' || inside.startsWith(`..${path.sep}`)) {
      fail('E7_CDK_ASSET_MANIFEST_PATH_INVALID');
    }
    checkedWorkspacePath(absolute, { directory: false });
    const assetManifest = readEvidence(absolute);
    if (
      typeof assetManifest.version !== 'string' ||
      !object(assetManifest.files) ||
      !object(assetManifest.dockerImages ?? {})
    ) {
      fail('E7_CDK_ASSET_MANIFEST_INVALID');
    }
    for (const fileAsset of Object.values(assetManifest.files)) {
      if (
        !object(fileAsset) ||
        !object(fileAsset.source) ||
        !['file', 'zip'].includes(fileAsset.source.packaging) ||
        !object(fileAsset.destinations) ||
        Object.keys(fileAsset.destinations).length < 1
      ) {
        fail('E7_CDK_FILE_ASSET_INVALID');
      }
      for (const destination of Object.values(fileAsset.destinations)) {
        const region = destination?.region;
        if (
          typeof region !== 'string' ||
          destination.bucketName !== `cdk-hnb659fds-assets-\${AWS::AccountId}-${region}` ||
          destination.assumeRoleArn !==
            `arn:\${AWS::Partition}:iam::\${AWS::AccountId}:role/cdk-hnb659fds-file-publishing-role-\${AWS::AccountId}-${region}`
        ) {
          fail('E7_CDK_FILE_ASSET_DESTINATION_INVALID');
        }
        regions.add(region);
      }
      fileAssetCount += 1;
    }
    dockerImageAssetCount += Object.keys(assetManifest.dockerImages).length;
    manifestSummaries.push({ relativeSha256: digest(relative), sha256: fileDigest(absolute) });
  }
  if (regions.size !== 1) fail('E7_CDK_ASSET_REGION_INVALID');
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'CDK_BOOTSTRAP_ASSET_INVENTORY',
    status: 'PASS',
    qualifier: 'hnb659fds',
    region: [...regions][0],
    assemblySha256,
    assetManifestCount: assetArtifacts.length,
    assetManifestSha256: objectSha256(
      manifestSummaries.sort((left, right) =>
        stableCompare(left.relativeSha256, right.relativeSha256),
      ),
    ),
    fileAssetCount,
    dockerImageAssetCount,
    requiredPublishingRoleKeys: ['bootstrapFilePublishingRoleArn'],
    deniedPublishingRoleKeys: ['bootstrapImagePublishingRoleArn'],
    containsSensitiveData: false,
  };
  return validateBootstrapAssetInventory({ ...body, inventorySha256: objectSha256(body) });
};

export const inspectCloudAssembly = (directory, { scope = 'full' } = {}) => {
  const root = checkedWorkspacePath(directory, { directory: true });
  const manifestPath = path.join(root, 'manifest.json');
  checkedWorkspacePath(manifestPath, { directory: false });
  const staticScan = scanFileSet([root]);
  const manifest = readEvidence(manifestPath);
  if (manifest.version === undefined || !object(manifest.artifacts)) {
    fail('E7_CLOUD_ASSEMBLY_MANIFEST_INVALID');
  }
  const templates = jsonTemplates(root);
  if (templates.length !== 4) fail('E7_CLOUD_ASSEMBLY_STACK_SET_INVALID');
  const templateDocuments = templates.map((template) => readEvidence(template.absolute));
  const lifecycle = validateCloudAssemblyLifecycle({
    scope,
    manifest,
    templates: templateDocuments,
    templateFiles: templates.map(({ relative }) => relative),
  });
  const resourceCounts = new Map();
  let resources = 0;
  for (const template of templateDocuments) {
    if (!object(template.Resources)) fail('E7_CLOUD_ASSEMBLY_TEMPLATE_INVALID');
    for (const resource of Object.values(template.Resources)) {
      if (
        !object(resource) ||
        typeof resource.Type !== 'string' ||
        !object(resource.Properties ?? {})
      ) {
        fail('E7_CLOUD_ASSEMBLY_RESOURCE_INVALID');
      }
      resources += 1;
      resourceCounts.set(resource.Type, (resourceCounts.get(resource.Type) ?? 0) + 1);
      const properties = resource.Properties ?? {};
      if (resource.Type === 'AWS::S3::Bucket') {
        const block = properties.PublicAccessBlockConfiguration;
        if (
          !object(block) ||
          ![
            'BlockPublicAcls',
            'BlockPublicPolicy',
            'IgnorePublicAcls',
            'RestrictPublicBuckets',
          ].every((key) => block[key] === true) ||
          properties.WebsiteConfiguration !== undefined
        ) {
          fail('E7_CLOUD_ASSEMBLY_PUBLIC_BUCKET_RISK');
        }
      }
      if (resource.Type === 'AWS::S3::BucketPolicy') {
        for (const statement of statements(properties.PolicyDocument)) {
          if (statement?.Effect === 'Allow' && statement?.Principal === '*') {
            fail('E7_CLOUD_ASSEMBLY_PUBLIC_BUCKET_POLICY_RISK');
          }
        }
      }
      if (resource.Type === 'AWS::ApiGatewayV2::Api') {
        const origins = properties.CorsConfiguration?.AllowOrigins ?? [];
        if (origins === '*' || (Array.isArray(origins) && origins.includes('*'))) {
          fail('E7_CLOUD_ASSEMBLY_WILDCARD_CORS_RISK');
        }
      }
      if (resource.Type === 'AWS::IAM::Role' || resource.Type === 'AWS::IAM::Policy') {
        const serialized = JSON.stringify(properties);
        if (
          /AdministratorAccess/iu.test(serialized) ||
          /"Action"\s*:\s*"\*"/u.test(serialized) ||
          /"Action"\s*:\s*\[[^\]]*"\*"/u.test(serialized)
        ) {
          fail('E7_CLOUD_ASSEMBLY_IAM_BROADENING_RISK');
        }
      }
      if (resource.Type === 'AWS::CloudFront::Distribution') {
        const distribution = properties.DistributionConfig;
        if (
          !object(distribution) ||
          distribution.DefaultCacheBehavior?.ViewerProtocolPolicy !== 'redirect-to-https' ||
          Object.values(distribution.CacheBehaviors ?? {}).some(
            (behavior) => behavior?.ViewerProtocolPolicy !== 'redirect-to-https',
          )
        ) {
          fail('E7_CLOUD_ASSEMBLY_HTTPS_POLICY_INVALID');
        }
        if (
          scope === 'full' &&
          distribution.ViewerCertificate?.MinimumProtocolVersion !== 'TLSv1.2_2021'
        ) {
          fail('E7_CLOUD_ASSEMBLY_TLS_BASELINE_INVALID');
        }
      }
      if (resource.Type === 'AWS::DynamoDB::Table') {
        if (properties.SSESpecification?.SSEEnabled !== true) {
          fail('E7_CLOUD_ASSEMBLY_STATEFUL_PROTECTION_INVALID');
        }
      }
    }
  }
  if (resources === 0) fail('E7_CLOUD_ASSEMBLY_EMPTY');
  const assemblySha256 = hashArtifactPath(root, { rootDirectory: workspaceRoot }).sha256;
  const bootstrapAssetInventory = inspectBootstrapAssetInventory({
    root,
    manifest,
    assemblySha256,
  });
  return {
    root,
    assemblySha256,
    bootstrapAssetInventory,
    templates: templates.length,
    resources,
    resourceCounts: Object.fromEntries(
      [...resourceCounts].sort(([left], [right]) => stableCompare(left, right)),
    ),
    lifecycle,
    ...staticScan,
  };
};

const scanCandidate = async (flags) => {
  const scope = scopeOf(flags);
  if (scope === 'prerelease' && flags['synthetic-only'] !== true) {
    fail('E7_SCAN_SYNTHETIC_ONLY_REQUIRED');
  }
  const identity = candidateIdentity(scope);
  const candidate = requiredString(flags, 'candidate');
  const scan = scanFileSet([candidate]);
  runHistoryScan();
  if (flags.integrity !== undefined) {
    const integrity = readEvidence(
      findExactlyOne(requiredString(flags, 'integrity'), 'checksums-sbom.json'),
    );
    if (
      integrity.kind !== 'CHECKSUMS_INVENTORY_PROVENANCE' ||
      integrity.status !== 'PASS' ||
      integrity.candidateSha !== identity.candidateSha ||
      integrity.findings !== 0 ||
      integrity.containsSensitiveData !== false
    ) {
      fail('E7_SCAN_INTEGRITY_EVIDENCE_INVALID');
    }
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'REPOSITORY_AND_CANDIDATE_SECURITY',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    tree: 'PASS',
    history: 'PASS',
    candidateArtifact: 'PASS',
    providerProductionReferences: 0,
    secretFindings: 0,
    paymentDataFindings: 0,
    syntheticOnly: scope === 'prerelease',
    ...scan,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(result, path.join(evidenceRoot(scope), 'security.json'), 'stage7-security.json');
};

const scanAssembly = async (flags) => {
  const scope = scopeOf(flags);
  const identity = candidateIdentity(scope);
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const assessment = inspectCloudAssembly(requiredString(flags, 'cloud-assembly'), { scope });
  const target = path.join(evidenceRoot(scope), 'infra-synth.json');
  const frozenVerification = readEvidence(target);
  const synthCheckpoint = frozenVerification?.checkpoints?.synth;
  if (
    frozenVerification.schemaVersion !== 1 ||
    frozenVerification.stage !== 7 ||
    frozenVerification.status !== 'IN_PROGRESS' ||
    frozenVerification.environment !== config.environment ||
    frozenVerification.authorizationId !== config.authorization.id ||
    frozenVerification.authorizationScope !== config.authorization.scope ||
    frozenVerification.configSha256 !== objectSha256(config) ||
    frozenVerification.candidateSha !== identity.candidateSha ||
    frozenVerification.releaseId !== identity.releaseId ||
    frozenVerification.containsSensitiveData !== false ||
    synthCheckpoint?.decision !== 'PASS' ||
    synthCheckpoint?.releaseMode !== (scope === 'full' ? 'VERSIONED_UPDATE' : 'INITIAL') ||
    synthCheckpoint?.mode !== 'VERIFY_FROZEN_ASSEMBLY' ||
    synthCheckpoint?.assemblySha256 !== assessment.assemblySha256 ||
    !SHA256.test(synthCheckpoint?.freezeManifestSha256 ?? '') ||
    synthCheckpoint?.stackCount !== 4 ||
    synthCheckpoint?.stacks?.join('\0') !== config.authorization.stacks.join('\0') ||
    synthCheckpoint?.hostedZone !== null ||
    synthCheckpoint?.awsIdentity !== null
  ) {
    fail('E7_CLOUD_ASSEMBLY_FROZEN_VERIFICATION_INVALID');
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'CLOUD_ASSEMBLY_SECURITY',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    assemblySha256: assessment.assemblySha256,
    freezeManifestSha256: synthCheckpoint.freezeManifestSha256,
    frozenVerificationSha256: objectSha256(frozenVerification),
    templates: assessment.templates,
    resources: assessment.resources,
    resourceCounts: assessment.resourceCounts,
    secretFindings: 0,
    productionProviderReferences: 0,
    publicBucketRisks: 0,
    wildcardCorsRisks: 0,
    iamWildcardActionRisks: 0,
    statefulProtectionRisks: 0,
    filesScanned: assessment.filesScanned,
    bytesScanned: assessment.bytesScanned,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(result, target, 'stage7-infra-synth.json');
};

const awsJson = (service, operation, arguments_ = []) => {
  const allowed = new Set([
    'sts:get-caller-identity',
    'cloudformation:list-stacks',
    'cloudformation:describe-stacks',
    'iam:get-role',
    'iam:get-role-policy',
    'iam:list-role-policies',
    'iam:list-attached-role-policies',
    'iam:get-policy',
    'iam:get-policy-version',
    'service-quotas:list-service-quotas',
    'lambda:get-account-settings',
    'dynamodb:list-tables',
    'cloudfront:list-distributions',
    's3api:get-public-access-block',
    's3api:get-bucket-policy-status',
  ]);
  if (!allowed.has(`${service}:${operation}`)) fail('E7_AWS_READ_COMMAND_NOT_ALLOWLISTED');
  let source;
  try {
    source = execFileSync(
      'aws',
      [service, operation, ...arguments_, '--output', 'json', '--no-cli-pager'],
      {
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
        env: { ...process.env, AWS_PAGER: '' },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
  } catch {
    fail('E7_AWS_READ_COMMAND_FAILED');
  }
  try {
    return parseStrictJsonSource(Buffer.from(source), { scanForbiddenData: false });
  } catch {
    fail('E7_AWS_READ_RESPONSE_INVALID');
  }
};

const roleName = (roleArn) => roleArn.slice(roleArn.lastIndexOf('/') + 1);

const assertGithubOidcContext = () => {
  if (
    process.env.GITHUB_ACTIONS !== 'true' ||
    process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    process.env.GITHUB_REF !== 'refs/heads/master' ||
    process.env.GITHUB_REPOSITORY !== 'ivanmonsalve0404/async-checkout-demo' ||
    typeof process.env.AWS_SESSION_TOKEN !== 'string' ||
    process.env.AWS_SESSION_TOKEN.length < 16 ||
    !/^ASIA[A-Z0-9]{16}$/u.test(process.env.AWS_ACCESS_KEY_ID ?? '')
  ) {
    fail('E7_OIDC_SESSION_CONTEXT_INVALID');
  }
};

const callerIdentityFor = (config, expectedRoleArn) => {
  assertGithubOidcContext();
  const caller = awsJson('sts', 'get-caller-identity');
  const match = /^arn:aws:sts::([0-9]{12}):assumed-role\/([^/]+)\/[^/]+$/u.exec(caller.Arn ?? '');
  if (
    caller.Account !== config.aws.accountId ||
    match === null ||
    match[1] !== config.aws.accountId ||
    match[2] !== roleName(expectedRoleArn) ||
    process.env.AWS_REGION !== config.aws.region ||
    process.env.AWS_DEFAULT_REGION !== config.aws.region
  ) {
    fail('E7_AWS_CALLER_IDENTITY_MISMATCH');
  }
  return caller;
};

export const validateGithubOidcTrustPolicy = ({ policy, accountId, expectedSubs }) => {
  const allowStatements = statements(policy).filter((statement) => statement?.Effect === 'Allow');
  if (
    !/^[0-9]{12}$/u.test(accountId ?? '') ||
    !Array.isArray(expectedSubs) ||
    expectedSubs.length < 1 ||
    expectedSubs.length > 3 ||
    new Set(expectedSubs).size !== expectedSubs.length ||
    allowStatements.length < 1 ||
    allowStatements.length > expectedSubs.length ||
    statements(policy).some((statement) => !['Allow', 'Deny'].includes(statement?.Effect))
  ) {
    fail('E7_AWS_ROLE_TRUST_INVALID');
  }
  const actualSubs = [];
  for (const statement of allowStatements) {
    const expectedProvider = `arn:aws:iam::${accountId}:oidc-provider/token.actions.githubusercontent.com`;
    if (
      !exactKeys(statement, ['Effect', 'Principal', 'Action', 'Condition']) ||
      statement.Effect !== 'Allow' ||
      !exactKeys(statement.Principal, ['Federated']) ||
      statement.Principal.Federated !== expectedProvider ||
      statement.Action !== 'sts:AssumeRoleWithWebIdentity' ||
      !exactKeys(statement.Condition, ['StringEquals']) ||
      !exactKeys(statement.Condition.StringEquals, [
        'token.actions.githubusercontent.com:aud',
        'token.actions.githubusercontent.com:sub',
      ]) ||
      statement.Condition.StringEquals['token.actions.githubusercontent.com:aud'] !==
        'sts.amazonaws.com'
    ) {
      fail('E7_AWS_ROLE_TRUST_INVALID');
    }
    const subs = statement.Condition.StringEquals['token.actions.githubusercontent.com:sub'];
    if (!(
      typeof subs === 'string' ||
      (Array.isArray(subs) &&
        subs.length === expectedSubs.length &&
        new Set(subs).size === subs.length &&
        subs.every((value) => typeof value === 'string'))
    )) {
      fail('E7_AWS_ROLE_TRUST_INVALID');
    }
    actualSubs.push(...(Array.isArray(subs) ? subs : [subs]));
  }
  if (
    actualSubs.length !== expectedSubs.length ||
    new Set(actualSubs).size !== actualSubs.length ||
    actualSubs.toSorted().join('\0') !== expectedSubs.toSorted().join('\0')
  ) {
    fail('E7_AWS_ROLE_TRUST_INVALID');
  }
  return true;
};

export const expectedGithubOidcSubjects = (config, roleArn) => {
  const roleKey = Object.entries(config.aws.roles).find(([, arn]) => arn === roleArn)?.[0];
  const scope =
    config.authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE'
      ? 'full'
      : config.authorization.scope === 'FULL_RELEASE_BASELINE_CLOSED'
        ? 'baseline'
        : config.authorization.scope === 'EPHEMERAL_PRERELEASE'
          ? 'prerelease'
          : null;
  if (roleKey === undefined || scope === null || !(roleKey in IAM_ROLE_PERMISSION_PROFILES)) {
    fail('E7_AWS_ROLE_TRUST_INVALID');
  }
  return [...IAM_ROLE_PERMISSION_PROFILES[roleKey].oidcSubjects[scope]];
};

const validateRoleTrust = (config, roleArn) => {
  const result = awsJson('iam', 'get-role', ['--role-name', roleName(roleArn)]);
  if (result.Role?.Arn !== roleArn) fail('E7_AWS_ROLE_TRUST_INVALID');
  return validateGithubOidcTrustPolicy({
    policy: result.Role.AssumeRolePolicyDocument,
    accountId: config.aws.accountId,
    expectedSubs: expectedGithubOidcSubjects(config, roleArn),
  });
};

const STABLE_STACK_STATUSES = new Set([
  'CREATE_COMPLETE',
  'IMPORT_COMPLETE',
  'UPDATE_COMPLETE',
  'UPDATE_ROLLBACK_COMPLETE',
]);

const describedStackSummary = ({ response, config, stackName }) => {
  const stacks = response?.Stacks;
  const stack = Array.isArray(stacks) && stacks.length === 1 ? stacks[0] : null;
  const stackIdPrefix = `arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/${stackName}/`;
  if (
    !object(stack) ||
    stack.StackName !== stackName ||
    typeof stack.StackId !== 'string' ||
    !stack.StackId.startsWith(stackIdPrefix) ||
    !/^[A-Za-z0-9-]{8,128}$/u.test(stack.StackId.slice(stackIdPrefix.length)) ||
    !STABLE_STACK_STATUSES.has(stack.StackStatus)
  ) {
    fail('E7_AWS_STACK_IDENTITY_OR_STATE_INVALID');
  }
  return {
    stackName,
    stackIdSha256: objectSha256(stack.StackId),
    stackStatus: stack.StackStatus,
  };
};

const validateBootstrap = (config) => {
  const result = awsJson('cloudformation', 'describe-stacks', ['--stack-name', 'CDKToolkit']);
  const summary = describedStackSummary({ response: result, config, stackName: 'CDKToolkit' });
  const stack = result.Stacks[0];
  const outputs = stack.Outputs?.filter((output) => output?.OutputKey === 'BootstrapVersion');
  const version = Number(
    Array.isArray(outputs) && outputs.length === 1 ? outputs[0].OutputValue : Number.NaN,
  );
  if (!Number.isSafeInteger(version) || version < 14) fail('E7_CDK_BOOTSTRAP_INCOMPATIBLE');
  return { ...summary, version };
};

export const readPaginatedStackInventory = (config, callAws = awsJson) => {
  const summaries = [];
  const seenTokens = new Set();
  const seenStackIds = new Set();
  let startingToken;
  for (let page = 0; page < 100; page += 1) {
    const arguments_ = ['--max-items', '100'];
    if (startingToken !== undefined) arguments_.push('--starting-token', startingToken);
    const response = callAws('cloudformation', 'list-stacks', arguments_);
    if (!object(response) || !Array.isArray(response.StackSummaries)) {
      fail('E7_AWS_STACK_INVENTORY_INVALID');
    }
    for (const stack of response.StackSummaries) {
      const prefix = `arn:aws:cloudformation:${config.aws.region}:${config.aws.accountId}:stack/`;
      if (
        !object(stack) ||
        typeof stack.StackName !== 'string' ||
        !/^[A-Za-z][A-Za-z0-9-]{1,127}$/u.test(stack.StackName) ||
        typeof stack.StackId !== 'string' ||
        !stack.StackId.startsWith(`${prefix}${stack.StackName}/`) ||
        typeof stack.StackStatus !== 'string' ||
        stack.StackStatus.length === 0 ||
        seenStackIds.has(stack.StackId)
      ) {
        fail('E7_AWS_STACK_INVENTORY_INVALID');
      }
      seenStackIds.add(stack.StackId);
      summaries.push({
        stackNameSha256: objectSha256(stack.StackName),
        stackIdSha256: objectSha256(stack.StackId),
        stackStatus: stack.StackStatus,
      });
    }
    const next = response.NextToken;
    if (next === undefined || next === null) {
      const sorted = summaries.toSorted((left, right) =>
        JSON.stringify(left).localeCompare(JSON.stringify(right)),
      );
      return {
        status: 'PASS',
        pages: page + 1,
        activeStackCount: sorted.filter((stack) => stack.stackStatus !== 'DELETE_COMPLETE').length,
        inventorySha256: objectSha256(sorted),
        parametersOrOutputsCaptured: false,
      };
    }
    if (typeof next !== 'string' || next.length === 0 || seenTokens.has(next)) {
      fail('E7_AWS_STACK_INVENTORY_PAGINATION_INVALID');
    }
    seenTokens.add(next);
    startingToken = next;
  }
  fail('E7_AWS_STACK_INVENTORY_PAGINATION_LIMIT');
};

const validateAuthorizedStacks = (config, scope, callAws = awsJson) => {
  if (scope === 'prerelease' || scope === 'baseline') {
    return {
      status: 'NOT_APPLICABLE_INITIAL_CREATION',
      stackCount: 0,
      stackSummariesSha256: objectSha256([]),
      stacks: [],
      externalRequests: 0,
    };
  }
  const stacks = config.authorization.stacks.map((stackName) =>
    describedStackSummary({
      response: callAws('cloudformation', 'describe-stacks', ['--stack-name', stackName]),
      config,
      stackName,
    }),
  );
  return {
    status: 'PASS',
    stackCount: stacks.length,
    stackSummariesSha256: objectSha256(stacks),
    stacks,
    externalRequests: stacks.length,
  };
};

const REQUIRED_QUOTAS = Object.freeze({
  cloudformation: { quotaCode: 'L-0485CB21', additional: 4 },
  lambda: { quotaCode: 'L-B99A9384', additional: 6 },
  dynamodb: { quotaCode: 'L-F98FE922', additional: 2 },
  cloudfront: { quotaCode: 'L-24B04930', additional: 1 },
});

export const validateRequiredQuotaCapacity = ({ quotaResponses, usage }) => {
  if (!object(quotaResponses) || !object(usage)) fail('E7_AWS_QUOTA_READ_INVALID');
  const capacity = {};
  for (const [service, requirement] of Object.entries(REQUIRED_QUOTAS)) {
    const quotas = quotaResponses[service]?.Quotas;
    if (!Array.isArray(quotas)) fail('E7_AWS_QUOTA_READ_INVALID');
    const matches = quotas.filter((quota) => quota?.QuotaCode === requirement.quotaCode);
    if (matches.length !== 1 || !(matches[0].Value > 0)) {
      fail('E7_AWS_REQUIRED_QUOTA_MISSING');
    }
    const limit = Number(matches[0].Value);
    const used = Number(usage[service]);
    if (
      !Number.isFinite(limit) ||
      !Number.isSafeInteger(used) ||
      used < 0 ||
      limit - used < requirement.additional
    ) {
      fail('E7_AWS_QUOTA_CAPACITY_INSUFFICIENT');
    }
    capacity[service] = {
      quotaCode: requirement.quotaCode,
      limit,
      used,
      requiredAdditional: requirement.additional,
      remainingAfterRelease: limit - used - requirement.additional,
    };
  }
  return capacity;
};

const validateQuotas = (config) => {
  const quotaResponses = Object.fromEntries(
    Object.keys(REQUIRED_QUOTAS).map((service) => [
      service,
      awsJson('service-quotas', 'list-service-quotas', [
        '--service-code',
        service,
        '--max-results',
        '100',
      ]),
    ]),
  );
  if (Object.values(quotaResponses).some((response) => response.NextToken !== undefined)) {
    fail('E7_AWS_QUOTA_READ_PAGINATED');
  }
  const stackInventory = readPaginatedStackInventory(config);
  const lambdaSettings = awsJson('lambda', 'get-account-settings');
  const tableResponse = awsJson('dynamodb', 'list-tables');
  const tables = tableResponse.TableNames;
  const distributionResponse = awsJson('cloudfront', 'list-distributions');
  const distributions = distributionResponse.DistributionList;
  if (
    !Array.isArray(tables) ||
    !object(distributions) ||
    tableResponse.LastEvaluatedTableName !== undefined ||
    distributions.IsTruncated !== false ||
    distributions.NextMarker !== undefined ||
    !Number.isSafeInteger(Number(distributions.Quantity)) ||
    !Number.isSafeInteger(Number(lambdaSettings.AccountLimit?.ConcurrentExecutions)) ||
    !Number.isSafeInteger(Number(lambdaSettings.AccountLimit?.UnreservedConcurrentExecutions))
  ) {
    fail('E7_AWS_QUOTA_USAGE_READ_INVALID');
  }
  const quotaCapacity = validateRequiredQuotaCapacity({
    quotaResponses,
    usage: {
      cloudformation: stackInventory.activeStackCount,
      lambda:
        Number(lambdaSettings.AccountLimit.UnreservedConcurrentExecutions) >= 0
          ? Number(lambdaSettings.AccountLimit.ConcurrentExecutions ?? 0) -
            Number(lambdaSettings.AccountLimit.UnreservedConcurrentExecutions)
          : Number.NaN,
      dynamodb: tables.length,
      cloudfront: Number(distributions.Quantity),
    },
  });
  return { quotaCapacity, stackInventory };
};

const awsReadPreflight = async (flags) => {
  const scope = awsScopeOf(flags);
  const config = scope === 'baseline' ? baselineConfigFromEnvironment() : configFromEnvironment();
  verifyAwsConfigScope(config, scope);
  const identity = candidateIdentity(scope);
  const preFreeze = flags['pre-freeze-synth'] === true;
  if (
    preFreeze &&
    (scope !== 'full' ||
      flags['approved-environment'] !== true ||
      flags['no-write'] !== true ||
      flags.manifest !== undefined)
  ) {
    fail('E7_PRE_FREEZE_SYNTH_SCOPE_INVALID');
  }
  const freeze = preFreeze
    ? null
    : scope === 'baseline'
      ? requireBaselineFreeze(flags, identity, config)
      : requireCurrentFreeze(flags, scope, identity, config);
  const cloudAssembly = preFreeze
    ? null
    : inspectCloudAssembly(requiredString(flags, 'cloud-assembly'), {
        scope: scope === 'baseline' ? 'full' : scope,
      });
  const expectedAssemblySha256 =
    freeze === null
      ? null
      : scope === 'baseline'
        ? freeze.assemblySha256
        : freeze.artifacts.find(({ name }) => name === 'iac')?.sha256;
  if (
    (preFreeze && flags['cloud-assembly'] !== undefined) ||
    (!preFreeze && cloudAssembly.assemblySha256 !== expectedAssemblySha256)
  ) {
    fail('E7_AWS_READ_ASSEMBLY_BINDING_INVALID');
  }
  let journalRoleAuthority = null;
  let journalRoleAuthoritySource = null;
  let reconciliationRecoveryRoleAuthority = null;
  let reconciliationRecoveryRoleAuthoritySource = null;
  if (!preFreeze && scope === 'full') {
    const journalRoleArn = process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN;
    const permissionsBoundaryArn =
      process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN;
    const reconciliationRecoveryRoleArn =
      process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN;
    const reconciliationRecoveryPermissionsBoundaryArn =
      process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN;
    if (
      typeof journalRoleArn !== 'string' ||
      journalRoleArn.length === 0 ||
      typeof permissionsBoundaryArn !== 'string' ||
      permissionsBoundaryArn.length === 0 ||
      typeof reconciliationRecoveryRoleArn !== 'string' ||
      reconciliationRecoveryRoleArn.length === 0 ||
      typeof reconciliationRecoveryPermissionsBoundaryArn !== 'string' ||
      reconciliationRecoveryPermissionsBoundaryArn.length === 0
    ) {
      fail('E7_RELEASE_AUXILIARY_ROLE_AUTHORITY_ENVIRONMENT_REQUIRED');
    }
    journalRoleAuthoritySource = readEvidenceSource(
      requiredString(flags, 'journal-role-effective-permissions'),
    );
    try {
      journalRoleAuthority = parseReleaseJournalRoleEffectivePermissionsSource(
        journalRoleAuthoritySource,
        {
          roleArn: journalRoleArn,
          permissionsBoundaryArn,
        },
      );
    } catch (error) {
      if (error instanceof Stage7ReleaseSuccessorIamAuthorityError) {
        fail('E7_RELEASE_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_INVALID');
      }
      throw error;
    }
    reconciliationRecoveryRoleAuthoritySource = readEvidenceSource(
      requiredString(flags, 'reconciliation-recovery-role-effective-permissions'),
    );
    try {
      reconciliationRecoveryRoleAuthority =
        parseReleaseReconciliationRecoveryRoleEffectivePermissionsSource(
          reconciliationRecoveryRoleAuthoritySource,
          {
            roleArn: reconciliationRecoveryRoleArn,
            permissionsBoundaryArn: reconciliationRecoveryPermissionsBoundaryArn,
          },
        );
      if (
        reconciliationRecoveryRoleAuthority.value.awsRegion !== config.aws.region ||
        !reconciliationRecoveryRoleAuthority.value.role.arn.startsWith(
          `arn:aws:iam::${config.aws.accountId}:role/`,
        ) ||
        !reconciliationRecoveryRoleAuthority.value.permissionsBoundary.policyArn.startsWith(
          `arn:aws:iam::${config.aws.accountId}:policy/`,
        )
      ) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_INVALID');
      }
    } catch (error) {
      if (error instanceof Stage7ReleaseReconciliationRecoveryError) {
        fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_INVALID');
      }
      throw error;
    }
  } else if (flags['journal-role-effective-permissions'] !== undefined) {
    fail('E7_RELEASE_JOURNAL_ROLE_AUTHORITY_SCOPE_INVALID');
  } else if (flags['reconciliation-recovery-role-effective-permissions'] !== undefined) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_AUTHORITY_SCOPE_INVALID');
  }
  const caller = callerIdentityFor(config, config.aws.roles.readRoleArn);
  const cleanupWatchdogRoleArn =
    scope === 'prerelease' ? process.env.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN : null;
  const baselineRoleArn = scope === 'baseline' ? config.aws.roles.baselineRoleArn : null;
  const iamEffectivePermissions = collectIamEffectivePermissions({
    config,
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    manifestSha256: freeze?.manifestSha256 ?? null,
    bootstrapAssetInventory: cloudAssembly?.bootstrapAssetInventory ?? null,
    cleanupWatchdogRoleArn,
    baselineRoleArn,
    journalRoleArn:
      scope === 'full' && !preFreeze ? process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN : null,
    journalPermissionsBoundaryArn:
      scope === 'full' && !preFreeze
        ? process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN
        : null,
    reconciliationRecoveryRoleArn:
      scope === 'full' && !preFreeze
        ? process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN
        : null,
    reconciliationRecoveryPermissionsBoundaryArn:
      scope === 'full' && !preFreeze
        ? process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN
        : null,
    callAws: awsJson,
    validateTrust: ({ policy, accountId, expectedSubjects }) =>
      validateGithubOidcTrustPolicy({ policy, accountId, expectedSubs: expectedSubjects }),
  });
  validateIamEffectivePermissionsEvidence({
    value: iamEffectivePermissions,
    config,
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    manifestSha256: freeze?.manifestSha256 ?? null,
    bootstrapAssetInventory: cloudAssembly?.bootstrapAssetInventory ?? null,
    cleanupWatchdogRoleArn,
    baselineRoleArn,
    journalRoleArn:
      scope === 'full' && !preFreeze ? process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN : null,
    journalPermissionsBoundaryArn:
      scope === 'full' && !preFreeze
        ? process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN
        : null,
    reconciliationRecoveryRoleArn:
      scope === 'full' && !preFreeze
        ? process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN
        : null,
    reconciliationRecoveryPermissionsBoundaryArn:
      scope === 'full' && !preFreeze
        ? process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN
        : null,
  });
  const bootstrap = validateBootstrap(config);
  const { quotaCapacity, stackInventory } = validateQuotas(config);
  const authorizedStacks = validateAuthorizedStacks(config, scope);
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: preFreeze ? 'AWS_PRE_FREEZE_SYNTH_PREFLIGHT' : 'AWS_READ_ONLY_PREFLIGHT',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    manifestSha256: freeze?.manifestSha256 ?? null,
    configSha256: objectSha256(config),
    accountSha256: digest(caller.Account),
    accountSuffix: caller.Account.slice(-4),
    callerArnSha256: digest(caller.Arn),
    expectedRoleArnSha256: digest(config.aws.roles.readRoleArn),
    region: config.aws.region,
    sessionMode: config.aws.sessionMode,
    roleTrust: 'PASS',
    bootstrapVersion: bootstrap.version,
    bootstrapStackIdSha256: bootstrap.stackIdSha256,
    bootstrapStackStatus: bootstrap.stackStatus,
    quotaCapacity,
    stackInventory,
    authorizedStacks,
    iamEffectivePermissions,
    ...(journalRoleAuthority === null
      ? {}
      : {
          journalRoleEffectivePermissionsRawSha256: journalRoleAuthority.rawSha256,
          journalRoleEffectivePermissionsSha256:
            journalRoleAuthority.value.effectivePermissionsSha256,
        }),
    ...(reconciliationRecoveryRoleAuthority === null
      ? {}
      : {
          reconciliationRecoveryRoleArn: reconciliationRecoveryRoleAuthority.value.role.arn,
          reconciliationRecoveryPermissionsBoundaryArn:
            reconciliationRecoveryRoleAuthority.value.permissionsBoundary.policyArn,
          reconciliationRecoveryRoleEffectivePermissionsRawSha256:
            reconciliationRecoveryRoleAuthority.rawSha256,
          reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256:
            reconciliationRecoveryRoleAuthority.canonicalSha256,
          reconciliationRecoveryRoleEffectivePermissionsSha256:
            reconciliationRecoveryRoleAuthority.value.effectivePermissionsSha256,
          reconciliationRecoveryRoleEffectivePolicyProjectionSha256:
            reconciliationRecoveryRoleAuthority.value.effectivePolicyProjectionSha256,
        }),
    capacityProven: true,
    decision: preFreeze ? 'READY_FOR_BUILD_FREEZE' : 'READY_FOR_CLOUD_OPERATIONS',
    preFreezeException: preFreeze,
    longLivedCredentials: false,
    externalRequests:
      9 +
      iamEffectivePermissions.externalRequests +
      (journalRoleAuthority?.value.sourceBindings.length ?? 0) +
      (reconciliationRecoveryRoleAuthority?.value.sourceBindings.length ?? 0) +
      stackInventory.pages +
      authorizedStacks.externalRequests,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  if (journalRoleAuthoritySource !== null) {
    try {
      validateReleaseJournalRoleEffectivePermissionsBinding({
        awsAuthSource: Buffer.from(`${JSON.stringify(result)}\n`, 'utf8'),
        effectivePermissionsSource: journalRoleAuthoritySource,
        expected: {
          candidateSha: identity.candidateSha,
          releaseId: identity.releaseId,
          configSha256: objectSha256(config),
          manifestSha256: freeze.manifestSha256,
        },
      });
    } catch (error) {
      if (error instanceof Stage7ReleaseSuccessorIamAuthorityError) {
        fail('E7_RELEASE_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BINDING_INVALID');
      }
      throw error;
    }
  }
  if (
    reconciliationRecoveryRoleAuthoritySource !== null &&
    RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.some(
      (field) => result[field] === undefined,
    )
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_INVALID');
  }
  await emitJson(result, flags.evidence, 'stage7-aws-read-preflight.json');
};

const validateAwsAuthEffectivePermissions = ({
  value,
  valueSource,
  journalRoleEffectivePermissionsSource,
  reconciliationRecoveryRoleEffectivePermissionsSource,
  config,
  scope,
  identity,
  manifestSha256,
}) => {
  const cleanupWatchdogRoleArn =
    scope === 'prerelease' ? process.env.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN : null;
  const baselineRoleArn = scope === 'baseline' ? config.aws.roles.baselineRoleArn : null;
  const journalRoleArn =
    scope === 'full' ? process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN : null;
  const journalPermissionsBoundaryArn =
    scope === 'full' ? process.env.STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN : null;
  const reconciliationRecoveryRoleArn =
    scope === 'full' ? process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN : null;
  const reconciliationRecoveryPermissionsBoundaryArn =
    scope === 'full'
      ? process.env.STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN
      : null;
  if (
    !object(value) ||
    value.kind !== 'AWS_READ_ONLY_PREFLIGHT' ||
    value.status !== 'PASS' ||
    value.scope !== scope ||
    value.candidateSha !== identity.candidateSha ||
    value.releaseId !== identity.releaseId ||
    value.manifestSha256 !== manifestSha256 ||
    value.configSha256 !== objectSha256(config) ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_AWS_AUTH_EVIDENCE_INVALID');
  }
  try {
    const iamEffectivePermissions = validateIamEffectivePermissionsEvidence({
      value: value.iamEffectivePermissions,
      config,
      scope,
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      manifestSha256,
      bootstrapAssetInventory:
        value.iamEffectivePermissions?.bootstrapRoles?.assetInventory?.inventory,
      cleanupWatchdogRoleArn,
      baselineRoleArn,
      journalRoleArn,
      journalPermissionsBoundaryArn,
      reconciliationRecoveryRoleArn,
      reconciliationRecoveryPermissionsBoundaryArn,
    });
    if (scope !== 'full') {
      if (
        value.journalRoleEffectivePermissionsRawSha256 !== undefined ||
        value.journalRoleEffectivePermissionsSha256 !== undefined ||
        journalRoleEffectivePermissionsSource !== undefined ||
        reconciliationRecoveryRoleEffectivePermissionsSource !== undefined ||
        RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.some(
          (field) => value[field] !== undefined,
        )
      ) {
        fail('E7_RELEASE_JOURNAL_ROLE_AUTHORITY_SCOPE_INVALID');
      }
      return {
        ...iamEffectivePermissions,
        journalRoleEffectivePermissionsRawSha256: null,
        journalRoleEffectivePermissionsSha256: null,
        ...Object.fromEntries(
          RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.map((field) => [field, null]),
        ),
      };
    }
    if (
      valueSource === undefined ||
      journalRoleEffectivePermissionsSource === undefined ||
      reconciliationRecoveryRoleEffectivePermissionsSource === undefined ||
      typeof journalRoleArn !== 'string' ||
      typeof journalPermissionsBoundaryArn !== 'string' ||
      typeof reconciliationRecoveryRoleArn !== 'string' ||
      typeof reconciliationRecoveryPermissionsBoundaryArn !== 'string'
    ) {
      fail('E7_RELEASE_JOURNAL_ROLE_AUTHORITY_REQUIRED');
    }
    const effectivePermissions = parseReleaseJournalRoleEffectivePermissionsSource(
      journalRoleEffectivePermissionsSource,
      {
        roleArn: journalRoleArn,
        permissionsBoundaryArn: journalPermissionsBoundaryArn,
      },
    );
    validateReleaseJournalRoleEffectivePermissionsBinding({
      awsAuthSource: valueSource,
      effectivePermissionsSource: journalRoleEffectivePermissionsSource,
      expected: {
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        configSha256: objectSha256(config),
        manifestSha256,
      },
    });
    const reconciliationRecoveryEffectivePermissions =
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
        reconciliationRecoveryEffectivePermissions.rawSha256,
      reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256:
        reconciliationRecoveryEffectivePermissions.canonicalSha256,
      reconciliationRecoveryRoleEffectivePermissionsSha256:
        reconciliationRecoveryEffectivePermissions.value.effectivePermissionsSha256,
      reconciliationRecoveryRoleEffectivePolicyProjectionSha256:
        reconciliationRecoveryEffectivePermissions.value.effectivePolicyProjectionSha256,
    };
    if (
      reconciliationRecoveryEffectivePermissions.value.awsRegion !== config.aws.region ||
      RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.some(
        (field) => value[field] !== recoveryBinding[field],
      )
    ) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_INVALID');
    }
    return {
      ...iamEffectivePermissions,
      journalRoleEffectivePermissionsRawSha256: effectivePermissions.rawSha256,
      journalRoleEffectivePermissionsSha256: effectivePermissions.value.effectivePermissionsSha256,
      ...recoveryBinding,
    };
  } catch (error) {
    if (error instanceof IamEffectivePermissionsError) {
      fail('E7_IAM_EFFECTIVE_PERMISSIONS_INVALID');
    }
    if (error instanceof Stage7ReleaseSuccessorIamAuthorityError) {
      fail('E7_RELEASE_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BINDING_INVALID');
    }
    if (error instanceof Stage7ReleaseReconciliationRecoveryError) {
      fail('E7_RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BINDING_INVALID');
    }
    throw error;
  }
};

const validateControlPrereleaseSafety = async ({
  flags,
  now = new Date(),
  expectedProtectedEnvironment = 'assessment-prerelease',
  deploymentPhase,
  livePhase,
  authorityPhase,
}) => {
  const requiredSources = [
    'manifest',
    'cloud-assembly',
    'plan',
    'raw-diff',
    'approval',
    'aws-auth',
    'safety-readiness',
  ];
  if (
    requiredSources.some((key) => typeof flags[key] !== 'string' || flags[key].length === 0) ||
    typeof process.env.STAGE7_CONFIG !== 'string' ||
    typeof process.env.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN !== 'string'
  ) {
    fail('E7_PRERELEASE_SAFETY_INPUT_REQUIRED');
  }
  try {
    const validated = validatePrereleaseSafetyReadinessFromFiles({
      readinessPath: flags['safety-readiness'],
      configPath: process.env.STAGE7_CONFIG,
      manifestPath: flags.manifest,
      assemblyPath: flags['cloud-assembly'],
      planPath: flags.plan,
      rawDiffPath: flags['raw-diff'],
      approvalPath: flags.approval,
      awsAuthPath: flags['aws-auth'],
      watchdogRoleArn: process.env.STAGE7_PRERELEASE_CLEANUP_WATCHDOG_ROLE_ARN,
      environmentVariables: process.env,
      now,
      expectedProtectedEnvironment,
    });
    let deployment = null;
    if (deploymentPhase !== undefined) {
      deployment = readEvidence(requiredString(flags, 'deployment-evidence'));
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
      liveSafetyRecheck = readEvidence(requiredString(flags, 'live-safety-recheck'));
      validatePrereleaseLiveSafetyRecheck(liveSafetyRecheck, {
        readiness: validated.readiness,
        config: validated.config,
        freeze: validated.freeze,
        phase: livePhase,
        expectedGithubRunId: process.env.GITHUB_RUN_ID,
        expectedGithubRunAttempt: process.env.GITHUB_RUN_ATTEMPT,
        now,
      });
    }
    const watchdogLiveAuthority = await revalidatePrereleaseWatchdogLiveAuthority({
      readiness: validated.readiness,
      freeze: validated.freeze,
      candidateWorkflowSha256: validated.local.watchdog.candidateBlobSha256,
      phase: authorityPhase,
      environmentVariables: process.env,
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

const mutationAuthorityPreflight = async (flags, mode) => {
  const scope = scopeOf(flags);
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope);
  const freeze = requireCurrentFreeze(flags, scope, identity, config);
  if (scope === 'full') {
    const awsAuthPath = requiredString(flags, 'aws-auth');
    validateAwsAuthEffectivePermissions({
      value: readEvidence(awsAuthPath),
      valueSource: readEvidenceSource(awsAuthPath),
      journalRoleEffectivePermissionsSource: readEvidenceSource(
        requiredString(flags, 'journal-role-effective-permissions'),
      ),
      reconciliationRecoveryRoleEffectivePermissionsSource: readEvidenceSource(
        requiredString(flags, 'reconciliation-recovery-role-effective-permissions'),
      ),
      config,
      scope,
      identity,
      manifestSha256: freeze.manifestSha256,
    });
  }
  if (mode === 'deploy' && scope === 'full') {
    const previousManifest = validateStage7PreviousReleaseForTarget(
      readEvidence(requiredString(flags, 'previous-manifest')),
      { config, freezeManifest: freeze },
    );
    const compatibilityBindings = [
      ['previous-api-contract-evidence', previousManifest.compatibility.apiContractEvidenceSha256],
      [
        'previous-pending-evidence',
        previousManifest.compatibility.pendingReconciliationEvidenceSha256,
      ],
      ['previous-smoke-evidence', previousManifest.compatibility.smokeEvidenceSha256],
    ];
    if (
      compatibilityBindings.some(
        ([flag, expectedSha256]) => fileDigest(requiredString(flags, flag)) !== expectedSha256,
      )
    ) {
      fail('E7_PREVIOUS_RELEASE_COMPATIBILITY_ARTIFACT_MISMATCH');
    }
  } else if (mode === 'deploy' || mode === 'sandbox') {
    if (scope === 'prerelease') {
      const activationGuard = mode === 'deploy' && typeof flags['live-safety-recheck'] === 'string';
      await validateControlPrereleaseSafety({
        flags,
        expectedProtectedEnvironment:
          mode === 'sandbox' || activationGuard
            ? 'assessment-prerelease-external'
            : 'assessment-prerelease',
        deploymentPhase: mode === 'sandbox' || activationGuard ? 'before-activation' : undefined,
        livePhase: mode === 'sandbox' ? 'sandbox' : activationGuard ? 'activation' : undefined,
        authorityPhase:
          mode === 'sandbox' ? 'sandbox' : activationGuard ? 'activation' : 'deploy-data',
      });
    } else {
      fail('E7_PREVIOUS_APPROVED_RELEASE_REQUIRED');
    }
  }
  const expectedRoleArn =
    mode === 'deploy'
      ? config.aws.roles.deployRoleArn
      : mode === 'cleanup'
        ? config.aws.roles.cleanupRoleArn
        : mode === 'rollback'
          ? config.aws.roles.rollbackRoleArn
          : config.aws.roles.readRoleArn;
  const caller = callerIdentityFor(config, expectedRoleArn);
  validateRoleTrust(config, expectedRoleArn);
  if (flags['approved-environment'] !== true) fail('E7_PROTECTED_ENVIRONMENT_REQUIRED');
  if (scope === 'prerelease' && flags['non-public'] !== true && mode !== 'cleanup') {
    fail('E7_PRERELEASE_NON_PUBLIC_REQUIRED');
  }
  if (mode === 'sandbox') {
    if (process.env.CONFIRM_SANDBOX_SMOKE !== 'true' || !config.authorization.sandboxIncluded) {
      fail('E7_SANDBOX_AUTHORIZATION_REQUIRED');
    }
  } else if (mode !== 'cleanup' && process.env.CONFIRM_DEPLOY !== 'true') {
    fail('E7_EXPLICIT_DEPLOY_CONFIRMATION_REQUIRED');
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'IMMEDIATE_MUTATION_AUTHORITY_CHECK',
    status: 'PASS',
    scope,
    mode,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    manifestSha256: freeze.manifestSha256,
    accountSha256: digest(caller.Account),
    callerArnSha256: digest(caller.Arn),
    expectedRoleArnSha256: digest(expectedRoleArn),
    authorizationId: config.authorization.id,
    windowEndsAtUtc: config.window.endsAtUtc,
    destructiveActionsAllowed: false,
    externalRequests: 2,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
};

const validateDiffReview = (document, scope, identity, config) => {
  const checkpoint = document?.checkpoints?.diff;
  if (
    document?.schemaVersion !== 1 ||
    document?.stage !== 7 ||
    document?.kind !== 'RELEASE_DIFF_REVIEW' ||
    document?.status !== 'READY_FOR_PROTECTED_REVIEW' ||
    document?.scope !== scope ||
    document?.environment !== config.environment ||
    document?.authorizationId !== config.authorization.id ||
    document?.authorizationScope !== config.authorization.scope ||
    document?.configSha256 !== objectSha256(config) ||
    document?.candidateSha !== identity.candidateSha ||
    document?.releaseId !== identity.releaseId ||
    !SHA256.test(document?.cloudAssemblySha256 ?? '') ||
    document?.statefulReplacements !== 0 ||
    document?.destructiveChanges !== 0 ||
    document?.secretFindings !== 0 ||
    document?.productionProviderReferences !== 0 ||
    document?.humanReviewRequired !== true ||
    typeof document?.iamBroadeningDetected !== 'boolean' ||
    !SHA256.test(document?.rawDiffArtifactSha256 ?? '') ||
    document?.previousReleaseManifestSha256 !== checkpoint?.previousReleaseManifestSha256 ||
    (scope === 'full'
      ? !SHA256.test(document?.previousReleaseManifestSha256 ?? '')
      : document?.previousReleaseManifestSha256 !== null) ||
    !object(checkpoint) ||
    checkpoint.decision !== 'READY_FOR_PROTECTED_REVIEW' ||
    checkpoint.releaseMode !== (scope === 'full' ? 'VERSIONED_UPDATE' : 'INITIAL') ||
    checkpoint.assemblySha256 !== document.cloudAssemblySha256 ||
    !SHA256.test(checkpoint.freezeManifestSha256 ?? '') ||
    checkpoint.rawDiffArtifactSha256 !== document.rawDiffArtifactSha256 ||
    checkpoint.risks?.statefulReplacement !== false ||
    checkpoint.risks?.statefulDeletion !== false ||
    checkpoint.risks?.destructiveChangeMentioned !== false ||
    checkpoint.risks?.rollbackControlReplacement !== false ||
    checkpoint.exactChangeSetUsed !== false ||
    checkpoint.diffMethod !== 'TEMPLATE' ||
    checkpoint.exactDiffRecomputedAtDeploy !== true ||
    checkpoint.hotswapUsed !== false ||
    checkpoint.containsRawDiff !== true ||
    !Array.isArray(checkpoint.stacks) ||
    checkpoint.stacks.join('\0') !== config.authorization.stacks.join('\0') ||
    document?.containsSensitiveData !== false
  ) {
    fail('E7_RELEASE_DIFF_REVIEW_INVALID');
  }
  return document;
};

const approvalPreflight = async (flags) => {
  const scope = scopeOf(flags);
  const identity = candidateIdentity(scope);
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  if (
    process.env.CONFIRM_DEPLOY !== 'true' ||
    process.env.GITHUB_ACTIONS !== 'true' ||
    process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    process.env.GITHUB_REF !== 'refs/heads/master' ||
    process.env.GITHUB_REPOSITORY !== 'ivanmonsalve0404/async-checkout-demo'
  ) {
    fail('E7_PROTECTED_APPROVAL_CONTEXT_INVALID');
  }
  const expectedProtectedEnvironment =
    scope === 'full' ? 'assessment-release' : 'assessment-prerelease';
  if (process.env.STAGE7_PROTECTED_ENVIRONMENT !== expectedProtectedEnvironment) {
    fail('E7_PROTECTED_APPROVAL_ENVIRONMENT_INVALID');
  }
  if (scope === 'prerelease') {
    assertStage6Flags(flags, scope);
    if (flags['approved-environment'] !== true || flags['non-public'] !== true) {
      fail('E7_PRERELEASE_APPROVAL_SCOPE_INVALID');
    }
  }
  const approvalDirectory = requiredString(flags, 'approval');
  const planFilename = findExactlyOne(approvalDirectory, 'infra-diff.json');
  const rawDiffFilename = findExactlyOne(approvalDirectory, 'infra-diff.txt');
  const awsAuthFilename = findExactlyOne(approvalDirectory, 'aws-auth.json');
  const journalRoleEffectivePermissionsFilename =
    scope === 'full'
      ? findExactlyOne(
          approvalDirectory,
          RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
        )
      : null;
  const reconciliationRecoveryRoleEffectivePermissionsFilename =
    scope === 'full'
      ? findExactlyOne(
          approvalDirectory,
          RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
        )
      : null;
  const plan = validateDiffReview(readEvidence(planFilename), scope, identity, config);
  const iamEffectivePermissions = validateAwsAuthEffectivePermissions({
    value: readEvidence(awsAuthFilename),
    valueSource: readEvidenceSource(awsAuthFilename),
    journalRoleEffectivePermissionsSource:
      journalRoleEffectivePermissionsFilename === null
        ? undefined
        : readEvidenceSource(journalRoleEffectivePermissionsFilename),
    reconciliationRecoveryRoleEffectivePermissionsSource:
      reconciliationRecoveryRoleEffectivePermissionsFilename === null
        ? undefined
        : readEvidenceSource(reconciliationRecoveryRoleEffectivePermissionsFilename),
    config,
    scope,
    identity,
    manifestSha256: plan.checkpoints.diff.freezeManifestSha256,
  });
  let previousReleaseManifestSha256 = null;
  if (scope === 'full') {
    const freeze = requireCurrentFreeze(flags, scope, identity, config);
    const previousManifest = validateStage7PreviousReleaseForTarget(
      readEvidence(requiredString(flags, 'previous-manifest')),
      { config, freezeManifest: freeze },
    );
    const compatibilityBindings = [
      ['previous-api-contract-evidence', previousManifest.compatibility.apiContractEvidenceSha256],
      [
        'previous-pending-evidence',
        previousManifest.compatibility.pendingReconciliationEvidenceSha256,
      ],
      ['previous-smoke-evidence', previousManifest.compatibility.smokeEvidenceSha256],
    ];
    if (
      compatibilityBindings.some(
        ([flag, expectedSha256]) => fileDigest(requiredString(flags, flag)) !== expectedSha256,
      ) ||
      plan.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
      plan.checkpoints.diff.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
      plan.checkpoints.diff.releaseMode !== 'VERSIONED_UPDATE'
    ) {
      fail('E7_PREVIOUS_RELEASE_APPROVAL_BINDING_INVALID');
    }
    previousReleaseManifestSha256 = previousManifest.manifestSha256;
  }
  const rawDiff = readFileSync(checkedWorkspacePath(rawDiffFilename, { directory: false }));
  if (rawDiff.length === 0 || rawDiff.length > 16 * 1024 * 1024) {
    fail('E7_RELEASE_RAW_DIFF_SIZE_INVALID');
  }
  try {
    assertSanitizedArtifactText('stage7-infra-diff.txt', rawDiff.toString('utf8'));
  } catch {
    fail('E7_RELEASE_RAW_DIFF_SANITIZATION_INVALID');
  }
  const rawDiffSha256 = digest(rawDiff);
  if (rawDiffSha256 !== plan.rawDiffArtifactSha256) {
    fail('E7_RELEASE_RAW_DIFF_DIGEST_MISMATCH');
  }
  let githubApproval;
  try {
    githubApproval = validateGithubEnvironmentApproval(
      readEvidence(requiredString(flags, 'github-approval-evidence')),
      {
        repository: process.env.GITHUB_REPOSITORY,
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        runId: process.env.GITHUB_RUN_ID,
        runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
        environment: expectedProtectedEnvironment,
        diffSha256: rawDiffSha256,
      },
    );
  } catch (error) {
    if (error instanceof GithubEnvironmentApprovalError) {
      fail('E7_PROTECTED_GITHUB_APPROVAL_INVALID');
    }
    throw error;
  }
  const reviewerAlias = githubApproval.reviewerAlias;
  const approvedAtUtc = githubApproval.capturedAtUtc;
  if (
    Date.parse(approvedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(approvedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    Date.parse(approvedAtUtc) > Date.now()
  ) {
    fail('E7_PROTECTED_APPROVAL_OUTSIDE_WINDOW');
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PROTECTED_RELEASE_APPROVAL',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: scope === 'full' ? identity.releaseTag : null,
    configSha256: objectSha256(config),
    cloudAssemblySha256: plan.cloudAssemblySha256,
    freezeManifestSha256: plan.checkpoints.diff.freezeManifestSha256,
    previousReleaseManifestSha256,
    approvedPlanSha256: fileDigest(planFilename),
    approvedDiffSha256: rawDiffSha256,
    iamEffectivePermissionsBindingSha256: iamEffectivePermissions.bindingSha256,
    iamEffectivePermissionsEvidenceSha256: fileDigest(awsAuthFilename),
    journalRoleEffectivePermissionsRawSha256:
      iamEffectivePermissions.journalRoleEffectivePermissionsRawSha256,
    journalRoleEffectivePermissionsSha256:
      iamEffectivePermissions.journalRoleEffectivePermissionsSha256,
    ...Object.fromEntries(
      RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.map((field) => [
        field,
        iamEffectivePermissions[field],
      ]),
    ),
    approvedAtUtc,
    statefulReplacements: 0,
    destructiveChanges: 0,
    iamBroadeningDetected: plan.iamBroadeningDetected,
    iamBroadeningReviewed: githubApproval.iamReviewAttested,
    humanReviewConfirmed: githubApproval.reviewed,
    explicitDispatchConfirmation: true,
    protectedEnvironment: true,
    protectedEnvironmentName: expectedProtectedEnvironment,
    nonPublic: scope === 'prerelease',
    accountSha256: digest(config.aws.accountId),
    accountSuffix: config.aws.accountId.slice(-4),
    region: config.aws.region,
    stacks: config.authorization.stacks,
    budget: {
      maxUsd: config.budget.maxUsd,
      warningUsd: config.budget.warningUsd,
      alertDestinationSha256: config.budget.alertDestinationSha256,
    },
    approvalOwnerAlias: config.authorization.ownerAlias,
    reviewerAlias,
    authorizedWindow: config.window,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(
    result,
    flags.evidence ?? path.join(evidenceRoot(scope), 'approval.json'),
    'stage7-protected-approval.json',
  );
};

const planRelease = async (flags) => {
  const scope = scopeOf(flags);
  const identity = candidateIdentity(scope);
  const assembly = inspectCloudAssembly(requiredString(flags, 'cloud-assembly'), { scope });
  const stacks = Object.entries(readEvidence(path.join(assembly.root, 'manifest.json')).artifacts)
    .filter(([, artifact]) => artifact?.type === 'aws:cloudformation:stack')
    .map(([id]) => id)
    .sort(stableCompare);
  if (stacks.length !== 4) fail('E7_RELEASE_PLAN_STACK_SET_INVALID');
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_PLAN',
    status: 'READY_FOR_DIFF',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: scope === 'full' ? identity.releaseTag : null,
    cloudAssemblySha256: assembly.assemblySha256,
    stacks,
    dependencyOrder: stacks,
    templates: assembly.templates,
    resources: assembly.resources,
    resourceCounts: assembly.resourceCounts,
    statefulReplacements: 'PENDING_CDK_DIFF',
    iamReviewStatus: 'PENDING_PROTECTED_REVIEW',
    destructiveChanges: 'PENDING_CDK_DIFF',
    mutationsPlannedOnly: true,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(
    result,
    path.join(evidenceRoot(scope), 'release-plan.json'),
    'stage7-release-plan.json',
  );
};

const webTarget = (config, identity) => {
  const stackName = `checkout-${config.environment}-web`;
  const result = awsJson('cloudformation', 'describe-stacks', ['--stack-name', stackName]);
  const stack = result.Stacks?.[0];
  const outputs = Object.fromEntries(
    (stack?.Outputs ?? []).map((output) => [output.OutputKey, output.OutputValue]),
  );
  if (
    outputs.CandidateSha !== identity.candidateSha ||
    outputs.ReleaseId !== identity.releaseId ||
    typeof outputs.ApplicationUrl !== 'string' ||
    typeof outputs.ApiUrl !== 'string' ||
    typeof outputs.ApiDocsUrl !== 'string' ||
    typeof outputs.HealthUrl !== 'string' ||
    typeof outputs.WebBucketName !== 'string'
  ) {
    fail('E7_DEPLOYED_WEB_OUTPUTS_INVALID');
  }
  let application;
  for (const [name, value] of Object.entries({
    application: outputs.ApplicationUrl,
    api: outputs.ApiUrl,
    docs: outputs.ApiDocsUrl,
    health: outputs.HealthUrl,
  })) {
    try {
      const parsed = new URL(value);
      if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) {
        fail('E7_DEPLOYED_URL_INVALID');
      }
      if (name === 'application') application = parsed;
    } catch (error) {
      if (error instanceof Stage7ControlError) throw error;
      fail('E7_DEPLOYED_URL_INVALID');
    }
  }
  if (
    config.domain.mode === 'CUSTOM_AUTHORIZED' &&
    application.hostname !== config.domain.hostname
  ) {
    fail('E7_DEPLOYED_DOMAIN_MISMATCH');
  }
  return { stackName, outputs, applicationOrigin: application.origin };
};

const apiTarget = (config, identity) => {
  const stackName = `checkout-${config.environment}-api`;
  const result = awsJson('cloudformation', 'describe-stacks', ['--stack-name', stackName]);
  const stack = result.Stacks?.[0];
  const rawOutputs = stack?.Outputs ?? [];
  const outputKeys = rawOutputs.map(({ OutputKey }) => OutputKey);
  if (
    result.Stacks?.length !== 1 ||
    outputKeys.some((key) => typeof key !== 'string') ||
    new Set(outputKeys).size !== outputKeys.length
  ) {
    fail('E7_DEPLOYED_API_OUTPUTS_INVALID');
  }
  const outputs = Object.fromEntries(
    rawOutputs.map((output) => [output.OutputKey, output.OutputValue]),
  );
  let apiOrigin;
  try {
    apiOrigin = validatePrereleaseApiOrigin({
      origin: outputs.ApiOriginUrl,
      region: config.aws.region,
    });
  } catch {
    fail('E7_DEPLOYED_API_OUTPUTS_INVALID');
  }
  if (
    outputs.CandidateSha !== identity.candidateSha ||
    outputs.ReleaseId !== identity.releaseId ||
    apiOrigin !== outputs.ApiOriginUrl
  ) {
    fail('E7_DEPLOYED_API_OUTPUTS_INVALID');
  }
  return { stackName, outputs, apiOrigin };
};

const deploymentTarget = (directory, config, identity) => {
  const document = readEvidence(findExactlyOne(directory, 'deployment.json'));
  const applicationUrl = document?.urls?.application ?? document?.applicationUrl;
  const apiCheckpoint = document?.checkpoints?.api;
  const apiOriginUrl = apiCheckpoint?.outputs?.ApiOriginUrl;
  let origin;
  let apiOrigin;
  try {
    const parsed = new URL(applicationUrl);
    if (parsed.protocol !== 'https:' || parsed.pathname !== '/' || parsed.search || parsed.hash) {
      fail('E7_DEPLOYMENT_EVIDENCE_TARGET_INVALID');
    }
    origin = parsed.origin;
    apiOrigin = validatePrereleaseApiOrigin({
      origin: apiOriginUrl,
      region: config.aws.region,
    });
  } catch (error) {
    if (error instanceof Stage7ControlError) throw error;
    fail('E7_DEPLOYMENT_EVIDENCE_TARGET_INVALID');
  }
  if (
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.status !== 'PASS' ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.configSha256 !== objectSha256(config) ||
    apiCheckpoint?.stackName !== `checkout-${config.environment}-api` ||
    apiCheckpoint?.outputs?.CandidateSha !== identity.candidateSha ||
    apiCheckpoint?.outputs?.ReleaseId !== identity.releaseId ||
    apiCheckpoint?.outputs?.ApiOriginUrl !== apiOrigin ||
    document.nonPublic !== true ||
    document.syntheticOnly !== true ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_DEPLOYMENT_EVIDENCE_INVALID');
  }
  return { document, applicationOrigin: origin, apiOrigin };
};

const webEvidenceTarget = (directory, config, identity) => {
  const document = readEvidence(findExactlyOne(directory, 'web.json'));
  const checkpoint = document?.checkpoints?.web;
  const applicationUrl = checkpoint?.outputs?.ApplicationUrl;
  let origin;
  try {
    const parsed = new URL(applicationUrl);
    if (parsed.protocol !== 'https:' || parsed.pathname !== '/' || parsed.search || parsed.hash) {
      fail('E7_WEB_EVIDENCE_TARGET_INVALID');
    }
    origin = parsed.origin;
  } catch (error) {
    if (error instanceof Stage7ControlError) throw error;
    fail('E7_WEB_EVIDENCE_TARGET_INVALID');
  }
  if (
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.environment !== config.environment ||
    document.authorizationId !== config.authorization.id ||
    document.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    document.configSha256 !== objectSha256(config) ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.status !== 'IN_PROGRESS' ||
    document.containsSensitiveData !== false ||
    checkpoint?.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    checkpoint?.releaseMode !== 'INITIAL' ||
    checkpoint?.stackName !== `checkout-${config.environment}-web` ||
    checkpoint?.outputs?.CandidateSha !== identity.candidateSha ||
    checkpoint?.outputs?.ReleaseId !== identity.releaseId ||
    checkpoint?.publicOriginSha256 !== digest(origin)
  ) {
    fail('E7_WEB_EVIDENCE_TARGET_INVALID');
  }
  if (
    config.domain.mode !== 'CUSTOM_AUTHORIZED' ||
    origin !== `https://${config.domain.hostname}`
  ) {
    fail('E7_WEB_EVIDENCE_DOMAIN_MISMATCH');
  }
  return { document, applicationOrigin: origin };
};

const externalAuthorizationRequirements = (scope) => [
  {
    key: 'ownedTarget',
    id: scope === 'full' ? 'AUTH-E7-EXT-01' : 'AUTH-E6-01',
    scope:
      scope === 'full'
        ? 'OWNED_FINAL_RELEASE_HTTPS_VERIFICATION'
        : 'OWNED_EPHEMERAL_QA_HTTPS_VERIFICATION',
    minimumRequests: scope === 'full' ? 3 : 9,
  },
  {
    key: 'sandboxSmoke',
    id: scope === 'full' ? 'AUTH-E7-EXT-02' : 'AUTH-E6-02',
    scope: 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
    minimumRequests: scope === 'full' ? 64 : 8,
  },
  {
    key: 'passiveSecurity',
    id: scope === 'full' ? 'AUTH-E7-EXT-03' : 'AUTH-E6-03',
    scope:
      scope === 'full' ? 'PASSIVE_BASELINE_OWNED_RELEASE_ONLY' : 'PASSIVE_BASELINE_OWNED_QA_ONLY',
    minimumRequests: scope === 'full' ? 6 : 12,
  },
];

const authorizationTarget = (scope, directory, config, identity) =>
  scope === 'full'
    ? webEvidenceTarget(directory, config, identity)
    : deploymentTarget(directory, config, identity);

const authorizationUsage = ({
  scope,
  authority,
  identity,
  config,
  usageId,
  requestCounts = {},
}) => {
  const requirements = externalAuthorizationRequirements(scope);
  const counts = Object.fromEntries(
    requirements.map(({ id }) => {
      const value = requestCounts[id] ?? 0;
      if (!Number.isSafeInteger(value) || value < 0) fail('E7_AUTHORIZATION_LEDGER_COUNT_INVALID');
      return [id, value];
    }),
  );
  if (
    !/^[A-Z0-9][A-Z0-9_-]{2,63}$/u.test(usageId ?? '') ||
    Object.keys(requestCounts).some((id) => !requirements.some((entry) => entry.id === id))
  ) {
    fail('E7_AUTHORIZATION_LEDGER_USAGE_INVALID');
  }
  return {
    schemaVersion: 1,
    usageId,
    bundleSha256: objectSha256(authority.value),
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    configSha256: objectSha256(config),
    ownedOriginSha256: authority.originSha256,
    sandboxHostSha256: authority.sandboxHostSha256,
    requestCounts: counts,
  };
};

export const validateSandboxAuthorizationBridge = ({
  stage6Authorization,
  externalAuthorization,
  candidateSha,
}) => {
  const source = stage6Authorization?.authorization;
  if (
    stage6Authorization?.schemaId !== 'async-checkout-stage6-auth02-authorization' ||
    stage6Authorization?.schemaVersion !== 1 ||
    stage6Authorization?.stage !== 6 ||
    stage6Authorization?.commitSha !== candidateSha ||
    stage6Authorization?.containsSensitiveData !== false ||
    source?.id !== 'AUTH-E6-02' ||
    source?.status !== 'APPROVED' ||
    source?.scope !== 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE' ||
    source?.approvalSha256 !== externalAuthorization?.approvalSha256 ||
    source?.approvedTargetSha256 !== externalAuthorization?.approvedTargetSha256 ||
    source?.approvedAtUtc !== externalAuthorization?.approvedAtUtc ||
    source?.expiresAtUtc !== externalAuthorization?.expiresAtUtc ||
    source?.ownerAlias !== externalAuthorization?.ownerAlias ||
    source?.maxRequests !== externalAuthorization?.maxRequests ||
    stage6Authorization?.target?.classification !== 'AUTHORIZED_PROVIDER_SANDBOX' ||
    stage6Authorization?.target?.environment !== 'sandbox' ||
    stage6Authorization?.target?.hostSha256 !== digest(SANDBOX_HOST) ||
    stage6Authorization?.target?.allowlistVerified !== true ||
    stage6Authorization?.target?.production !== false ||
    stage6Authorization?.fixture?.classification !== 'AUTHORIZED_PROVIDER_TEST_CARD' ||
    !SHA256.test(stage6Authorization?.fixture?.cardNumberSha256 ?? '') ||
    stage6Authorization?.fixture?.authorized !== true ||
    stage6Authorization?.fixture?.rawValueCaptured !== false
  ) {
    fail('E7_SANDBOX_AUTHORIZATION_BRIDGE_INVALID');
  }
  return stage6Authorization;
};

const externalAuthorizationRequest = async (flags) => {
  const scope = scopeOf(flags);
  if (
    (scope === 'prerelease' && flags['non-public'] !== true) ||
    (scope === 'full' && flags['non-public'] !== undefined)
  ) {
    fail('E7_EXTERNAL_AUTHORIZATION_REQUEST_SCOPE_INVALID');
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope);
  const target = authorizationTarget(
    scope,
    requiredString(flags, 'external-authorization-request'),
    config,
    identity,
  );
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'EXTERNAL_AUTHORIZATION_REQUEST',
    status: 'BLOCKED_AUTH',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    stage7ConfigSha256: objectSha256(config),
    targets: {
      ownedOriginSha256: digest(target.applicationOrigin),
      ...(scope === 'prerelease' ? { apiOriginSha256: digest(target.apiOrigin) } : {}),
      sandboxHostSha256: digest('sandbox.wompi.co'),
    },
    requiredAuthorizations: externalAuthorizationRequirements(scope),
    authorizationSchemaId: 'async-checkout-stage7-external-authorizations',
    rawTargetValuesCaptured: false,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(
    result,
    flags.evidence ?? path.join(evidenceRoot(scope), 'external-authorization-request.json'),
    'stage7-external-authorization-request.json',
  );
};

const externalAuthorizationPreflight = async (flags) => {
  const scope = scopeOf(flags);
  if (
    flags['approved-environment'] !== true ||
    (scope === 'prerelease' && flags['non-public'] !== true) ||
    (scope === 'full' && flags['non-public'] !== undefined)
  ) {
    fail('E7_EXTERNAL_AUTHORIZATION_SCOPE_INVALID');
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope);
  const target = authorizationTarget(
    scope,
    requiredString(flags, 'external-authorization'),
    config,
    identity,
  );
  const validated = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
    ...(scope === 'prerelease' ? { deployedApiOrigin: target.apiOrigin } : {}),
  });
  const requestLimits = Object.fromEntries(
    externalAuthorizationRequirements(scope).map(({ key, id }) => [
      id,
      validated.authorizations[key].maxRequests,
    ]),
  );
  const externalRequestBudgetPlan =
    scope === 'full'
      ? createFullExternalRequestBudgetPlan({
          candidateSha: identity.candidateSha,
          releaseId: identity.releaseId,
          configSha256: objectSha256(config),
          authorizationSha256: objectSha256(validated.value),
          ownedOriginSha256: validated.originSha256,
          sandboxHostSha256: validated.sandboxHostSha256,
          requestLimits,
        })
      : null;
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'EXTERNAL_AUTHORIZATION_PREFLIGHT',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    stage7ConfigSha256: objectSha256(config),
    ownedOriginSha256: validated.originSha256,
    ...(scope === 'prerelease' ? { apiOriginSha256: validated.apiOriginSha256 } : {}),
    sandboxHostSha256: validated.sandboxHostSha256,
    authorizationSha256: objectSha256(validated.value),
    authorizationIds: externalAuthorizationRequirements(scope).map(({ id }) => id),
    requestLimits,
    ...(externalRequestBudgetPlan === null ? {} : { externalRequestBudgetPlan }),
    authorizationUsage: authorizationUsage({
      scope,
      authority: validated,
      identity,
      config,
      usageId: 'EXTERNAL_AUTHORIZATION_PREFLIGHT',
    }),
    targetValuesCaptured: false,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(
    result,
    flags.evidence ?? path.join(evidenceRoot(scope), 'external-authorization.json'),
    'stage7-external-authorization-preflight.json',
  );
};

const readExternalJson = (filename, label) => {
  let stat;
  try {
    stat = lstatSync(filename);
  } catch {
    fail('E7_EXTERNAL_REPORT_MISSING');
  }
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > 16 * 1024 * 1024) {
    fail('E7_EXTERNAL_REPORT_INVALID');
  }
  try {
    const source = readFileSync(filename);
    assertSanitizedArtifactText(label, source.toString('utf8'));
    return { source, value: parseStrictJsonSource(source, { scanForbiddenData: false }) };
  } catch {
    fail('E7_EXTERNAL_REPORT_INVALID');
  }
};

const writePrivateTextAtomic = (target, value) => {
  const runnerRoot = process.env.RUNNER_TEMP;
  const roots = [workspaceRoot];
  if (typeof runnerRoot === 'string' && runnerRoot.trim() !== '')
    roots.push(path.resolve(runnerRoot));
  const absolute = path.resolve(target);
  if (
    !roots.some((root) => {
      const relative = path.relative(root, absolute);
      return (
        relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative)
      );
    })
  ) {
    fail('E7_PRIVATE_OUTPUT_PATH_INVALID');
  }
  const parent = path.dirname(absolute);
  mkdirSync(parent, { recursive: true });
  if (lstatSync(parent).isSymbolicLink()) fail('E7_PRIVATE_OUTPUT_PATH_INVALID');
  try {
    if (lstatSync(absolute).isSymbolicLink()) fail('E7_PRIVATE_OUTPUT_PATH_INVALID');
  } catch (error) {
    if (error instanceof Stage7ControlError) throw error;
  }
  assertSanitizedArtifactText(path.basename(absolute), value);
  const temporary = `${absolute}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, value, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, absolute);
    chmodSync(absolute, 0o600);
  } catch {
    rmSync(temporary, { force: true });
    fail('E7_PRIVATE_OUTPUT_WRITE_FAILED');
  }
};

const prepareZapTarget = (flags) => {
  const scope = scopeOf(flags);
  if (scope === 'prerelease' && flags['non-public'] !== true) {
    fail('E7_PRERELEASE_NON_PUBLIC_REQUIRED');
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope);
  let target;
  let authority;
  if (scope === 'full') {
    if (flags.deployment !== undefined) fail('E7_ZAP_DEPLOYMENT_SOURCE_SCOPE_INVALID');
    callerIdentityFor(config, config.aws.roles.readRoleArn);
    target = webTarget(config, identity);
    authority = readExternalAuthorizations({
      config,
      identity,
      deployedOrigin: target.applicationOrigin,
    });
    createFullExternalRequestBudgetPlan({
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      configSha256: objectSha256(config),
      authorizationSha256: objectSha256(authority.value),
      ownedOriginSha256: authority.originSha256,
      sandboxHostSha256: authority.sandboxHostSha256,
      requestLimits: Object.fromEntries(
        externalAuthorizationRequirements(scope).map(({ key, id }) => [
          id,
          authority.authorizations[key].maxRequests,
        ]),
      ),
    });
  } else {
    target = deploymentTarget(requiredString(flags, 'deployment'), config, identity);
    authority = readExternalAuthorizations({
      config,
      identity,
      deployedOrigin: target.applicationOrigin,
      deployedApiOrigin: target.apiOrigin,
    });
    if (authority.authorizations.passiveSecurity.maxRequests < 12) {
      fail('E7_EXTERNAL_AUTHORIZATION_REQUEST_LIMIT_EXCEEDED');
    }
  }
  writePrivateTextAtomic(
    requiredString(flags, 'prepare-zap-target'),
    `${target.applicationOrigin}\n`,
  );
};

const fetchChecked = async (url, options = {}) => {
  try {
    return await fetch(url, {
      ...options,
      redirect: options.redirect ?? 'manual',
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    fail('E7_DEPLOYED_EDGE_REQUEST_FAILED');
  }
};

const nativeZapSummary = (expectedOrigin) => {
  const filename = process.env.STAGE7_ZAP_REPORT;
  const inventoryFilename = process.env.STAGE7_ZAP_INVENTORY;
  const captureFilename = process.env.STAGE7_ZAP_CAPTURE;
  const ruleset = process.env.STAGE7_ZAP_RULESET;
  const requestCount = Number(process.env.STAGE7_ZAP_REQUEST_COUNT);
  if (
    typeof filename !== 'string' ||
    typeof inventoryFilename !== 'string' ||
    typeof captureFilename !== 'string' ||
    typeof ruleset !== 'string' ||
    process.env.STAGE7_ZAP_VERSION !== '2.16.1' ||
    !Number.isSafeInteger(requestCount) ||
    requestCount !== ZAP_PASSIVE_REQUEST_COUNT
  ) {
    fail('E7_ZAP_CAPTURE_METADATA_INVALID');
  }
  const report = readExternalJson(filename, 'zap-passive-report.json');
  const inventorySource = readExternalJson(inventoryFilename, 'zap-passive-inventory.json');
  const captureSource = readExternalJson(captureFilename, 'zap-passive-capture.json');
  let inventory;
  let capture;
  try {
    inventory = validateZapPassiveRequestInventory(inventorySource.value, {
      targetOrigin: expectedOrigin,
      openApiSource: readFileSync(path.join(workspaceRoot, 'output/architecture/openapi.yaml')),
    });
    capture = validateZapPassiveCaptureEvidence(captureSource.value, inventory);
  } catch {
    fail('E7_ZAP_EXACT_CAPTURE_INVALID');
  }
  if (capture.requestCount !== requestCount) fail('E7_ZAP_CAPTURE_METADATA_INVALID');
  let rulesetSha256;
  try {
    const stat = lstatSync(ruleset);
    const expectedRuleset = path.join(workspaceRoot, 'scripts/stage7/zap-passive-rules.tsv');
    const rulesetSource = readFileSync(ruleset, 'utf8').replaceAll('\r\n', '\n');
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.size === 0 ||
      stat.size > 16 * 1024 ||
      realpathSync(ruleset) !== realpathSync(expectedRuleset) ||
      rulesetSource.split('\n').some((line) => line.trim() !== '' && !line.startsWith('#')) ||
      !rulesetSource.includes('No alert is ignored')
    ) {
      fail('E7_ZAP_RULESET_INVALID');
    }
    rulesetSha256 = fileDigest(ruleset);
  } catch (error) {
    if (error instanceof Stage7ControlError) throw error;
    fail('E7_ZAP_RULESET_INVALID');
  }
  const alerts = Array.isArray(report.value.alerts) ? report.value.alerts : null;
  if (alerts === null) fail('E7_ZAP_NATIVE_REPORT_INVALID');
  const counts = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 };
  for (const alert of alerts) {
    const alertUrl = alert?.url ?? alert?.uri;
    if (typeof alertUrl === 'string') {
      let origin;
      try {
        origin = new URL(alertUrl).origin;
      } catch {
        fail('E7_ZAP_NATIVE_REPORT_INVALID');
      }
      if (origin !== expectedOrigin) fail('E7_ZAP_EXTERNAL_NAVIGATION_DETECTED');
    }
    const risk = Number(alert?.riskcode);
    if (risk === 3) counts.high += 1;
    else if (risk === 2) counts.medium += 1;
    else if (risk === 1) counts.low += 1;
    else counts.informational += 1;
  }
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
  if (counts.critical !== 0 || counts.high !== 0 || total !== 0) {
    fail('E7_ZAP_FINDINGS_REQUIRE_REVIEW');
  }
  return {
    mode: 'PASSIVE_BASELINE',
    tool: { name: 'OWASP_ZAP_BASELINE', version: '2.16.1' },
    rulesetSha256,
    reportSha256: digest(report.source),
    inventorySha256: inventory.inventorySha256,
    captureSha256: capture.captureSha256,
    openApiRawSha256: inventory.openApiRawSha256,
    observationsSha256: capture.observationsSha256,
    ownEndpointsScanned: requestCount,
    ownEndpointsOutOfScope: 0,
    findings: { total, reviewed: total, ...counts },
    manualValidation: 'ALL_ALERTS_REVIEWED',
    budgetEnforcement: 'ENFORCED_BEFORE_EGRESS',
    requestCount,
  };
};

const deployedEdgeScan = async (flags) => {
  const scope = scopeOf(flags);
  if (scope === 'prerelease' && flags['non-public'] !== true) {
    fail('E7_PRERELEASE_NON_PUBLIC_REQUIRED');
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope);
  callerIdentityFor(config, config.aws.roles.readRoleArn);
  const target = webTarget(config, identity);
  const deployedApi = scope === 'prerelease' ? apiTarget(config, identity) : null;
  let authority;
  try {
    authority = readExternalAuthorizations({
      config,
      identity,
      deployedOrigin: target.applicationOrigin,
      ...(deployedApi === null ? {} : { deployedApiOrigin: deployedApi.apiOrigin }),
    });
  } catch (error) {
    if (error instanceof Stage7ControlError && error.code.startsWith('E7_EXTERNAL_AUTHORIZATION')) {
      await writeStage7Json(
        path.join(evidenceRoot(scope), 'edge-security.json'),
        'stage7-edge-security-blocked.json',
        {
          schemaVersion: 1,
          stage: 7,
          kind: 'DEPLOYED_EDGE_SECURITY',
          status: 'BLOCKED_AUTH',
          scope,
          candidateSha: identity.candidateSha,
          releaseId: identity.releaseId,
          reason: error.code,
          externalRequests: 2,
          mutationsPerformed: 0,
          containsSensitiveData: false,
        },
      );
    }
    throw error;
  }
  const applicationUrl = target.outputs.ApplicationUrl;
  const passiveAuthorizationId = externalAuthorizationRequirements(scope).find(
    ({ key }) => key === 'passiveSecurity',
  ).id;
  let directRequestBudget = null;
  if (scope === 'full') {
    const plan = createFullExternalRequestBudgetPlan({
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      configSha256: objectSha256(config),
      authorizationSha256: objectSha256(authority.value),
      ownedOriginSha256: authority.originSha256,
      sandboxHostSha256: authority.sandboxHostSha256,
      requestLimits: Object.fromEntries(
        externalAuthorizationRequirements(scope).map(({ key, id }) => [
          id,
          authority.authorizations[key].maxRequests,
        ]),
      ),
    });
    directRequestBudget = createFullExternalRequestComponentCounter({
      plan,
      componentId: 'EDGE_PASSIVE_DIRECT',
    });
  } else if (authority.authorizations.passiveSecurity.maxRequests < 12) {
    fail('E7_EXTERNAL_AUTHORIZATION_REQUEST_LIMIT_EXCEEDED');
  }
  const beforeDirectRequest = () => directRequestBudget?.beforeRequest(passiveAuthorizationId);
  const signedCookies =
    scope === 'prerelease'
      ? readCloudFrontSignedCookieFile({
          origin: target.applicationOrigin,
          filename: process.env.STAGE7_CLOUDFRONT_SIGNED_COOKIE_FILE,
          expectedPublicKeyId: config.prereleaseAccess.publicKeyId,
          maxExpiresAtUtc: prereleaseCookieMaxExpiresAtUtc(config),
        })
      : [];
  if (scope === 'prerelease' && signedCookies.length !== 4) {
    fail('E7_PRERELEASE_SIGNED_COOKIE_REQUIRED');
  }
  const accessHeaders =
    signedCookies.length === 0
      ? {}
      : {
          cookie: signedCookies.map(({ name, value }) => `${name}=${value}`).join('; '),
        };
  const httpUrl = `http://${new URL(applicationUrl).host}/`;
  beforeDirectRequest();
  const redirect = await fetchChecked(httpUrl);
  const redirectLocation = redirect.headers.get('location');
  if (![301, 308].includes(redirect.status) || redirectLocation !== `${applicationUrl}/`) {
    fail('E7_DEPLOYED_HTTP_REDIRECT_INVALID');
  }
  beforeDirectRequest();
  const document = await fetchChecked(`${applicationUrl}/`, { headers: accessHeaders });
  const documentText = await document.text();
  if (document.status !== 200 || /(?:src|href)=["']http:\/\//iu.test(documentText)) {
    fail('E7_DEPLOYED_DOCUMENT_INVALID');
  }
  const headerStatus = Object.fromEntries(
    REQUIRED_HEADERS.map((header) => [header, document.headers.has(header) ? 'PASS' : 'FAIL']),
  );
  const clickjacking =
    document.headers.has('x-frame-options') ||
    /(?:^|;)\s*frame-ancestors\s+'none'(?:;|$)/iu.test(
      document.headers.get('content-security-policy') ?? '',
    );
  if (Object.values(headerStatus).includes('FAIL') || !clickjacking) {
    fail('E7_DEPLOYED_SECURITY_HEADERS_INVALID');
  }
  beforeDirectRequest();
  const health = await fetchChecked(target.outputs.HealthUrl, { headers: accessHeaders });
  beforeDirectRequest();
  const docs = await fetchChecked(target.outputs.ApiDocsUrl, { headers: accessHeaders });
  if (
    health.status !== 200 ||
    docs.status !== 200 ||
    !/^no-store(?:,|$)/iu.test(health.headers.get('cache-control') ?? '')
  ) {
    fail('E7_DEPLOYED_SENSITIVE_RESPONSE_INVALID');
  }
  beforeDirectRequest();
  const allowedCors = await fetchChecked(target.outputs.HealthUrl, {
    method: 'OPTIONS',
    headers: {
      ...accessHeaders,
      origin: target.applicationOrigin,
      'access-control-request-method': 'GET',
    },
  });
  beforeDirectRequest();
  const deniedCors = await fetchChecked(target.outputs.HealthUrl, {
    method: 'OPTIONS',
    headers: {
      ...accessHeaders,
      origin: 'https://cross-origin.example.invalid',
      'access-control-request-method': 'GET',
    },
  });
  if (
    allowedCors.headers.get('access-control-allow-origin') !== target.applicationOrigin ||
    deniedCors.headers.has('access-control-allow-origin')
  ) {
    fail('E7_DEPLOYED_CORS_INVALID');
  }
  const directRequestBudgetEvidence = directRequestBudget?.close() ?? null;
  let directS3Denied = 'NOT_RUN_PRERELEASE';
  let awsPrivateOriginRequests = 0;
  if (scope === 'full') {
    const access = awsJson('s3api', 'get-public-access-block', [
      '--bucket',
      target.outputs.WebBucketName,
    ]);
    const policy = awsJson('s3api', 'get-bucket-policy-status', [
      '--bucket',
      target.outputs.WebBucketName,
    ]);
    if (
      !['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'].every(
        (key) => access?.PublicAccessBlockConfiguration?.[key] === true,
      ) ||
      policy?.PolicyStatus?.IsPublic !== false
    ) {
      fail('E7_DEPLOYED_S3_ORIGIN_PUBLIC');
    }
    directS3Denied = 'PASS';
    awsPrivateOriginRequests = 2;
  }
  const zap =
    flags['zap-passive-only'] === true ? nativeZapSummary(target.applicationOrigin) : null;
  if (flags.headers === true && zap === null) fail('E7_ZAP_PASSIVE_CAPTURE_REQUIRED');
  const directOriginRequests = 6;
  const passiveRequests = directOriginRequests + (zap?.requestCount ?? 0);
  if (zap !== null && passiveRequests > authority.authorizations.passiveSecurity.maxRequests) {
    fail('E7_EXTERNAL_AUTHORIZATION_REQUEST_LIMIT_EXCEEDED');
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'DEPLOYED_EDGE_SECURITY',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    urls: {
      application: target.outputs.ApplicationUrl,
      api: target.outputs.ApiUrl,
      docs: target.outputs.ApiDocsUrl,
      health: target.outputs.HealthUrl,
    },
    httpRedirect: 'PASS',
    httpsDocument: 'PASS',
    mixedContentRequests: 0,
    headers: { ...headerStatus, clickjacking: 'PASS' },
    sensitiveResponsesNoStore: true,
    corsExact: true,
    directS3Denied,
    tlsBaseline:
      config.domain.mode === 'CUSTOM_AUTHORIZED' ? 'TLS12_CONFIGURED' : 'PRERELEASE_LIMITED',
    zap: zap === null ? 'NOT_RUN' : { ...zap, requestCount: undefined },
    stage6Capability:
      scope === 'full' || zap === null
        ? undefined
        : {
            passiveSecurity: {
              status: 'PASS',
              authorization: authority.authorizations.passiveSecurity,
              target: {
                classification: 'OWNED_EPHEMERAL_QA',
                environment: 'ENV-E6-QA',
                originSha256: authority.originSha256,
                ownershipVerified: true,
                production: false,
              },
              headerChecks: [
                ['AUTH03-E6-HDR-01', 'content-security-policy'],
                ['AUTH03-E6-HDR-02', 'referrer-policy'],
                ['AUTH03-E6-HDR-03', 'x-content-type-options'],
                ['AUTH03-E6-HDR-04', 'clickjacking-protection'],
                ['AUTH03-E6-HDR-05', 'permissions-policy'],
                ['AUTH03-E6-HDR-06', 'strict-transport-security'],
              ].map(([id, name]) => ({ id, name, status: 'PASS' })),
              sensitiveResponsesNoStore: true,
              criticalHeadersMissing: 0,
              zap: Object.fromEntries(
                Object.entries(zap).filter(([key]) => key !== 'requestCount'),
              ),
              requests: {
                total: passiveRequests,
                outsideAllowlist: 0,
                provider: 0,
                production: 0,
                externalRedirectsFollowed: 0,
                activeScan: 0,
              },
              evidenceIds: ['AUTH-E6-03', 'EVD-E6-33', 'EVD-E6-34'],
            },
          },
    externalAuthorization: {
      authorizationSha256: objectSha256(authority.value),
      authorizationIds: externalAuthorizationRequirements(scope).map(({ id }) => id),
      ownedOriginSha256: authority.originSha256,
      sandboxHostSha256: authority.sandboxHostSha256,
    },
    authorizationUsage: authorizationUsage({
      scope,
      authority,
      identity,
      config,
      usageId: 'EDGE_PASSIVE',
      requestCounts: {
        [externalAuthorizationRequirements(scope).find(({ key }) => key === 'passiveSecurity').id]:
          passiveRequests,
      },
    }),
    requests: {
      ownedOrigin: directOriginRequests,
      directS3: 0,
      awsPrivateOrigin: awsPrivateOriginRequests,
      zap: zap?.requestCount ?? 0,
    },
    ...(directRequestBudgetEvidence === null
      ? {}
      : {
          requestBudgetComponents: {
            direct: directRequestBudgetEvidence,
            zap: {
              componentId: 'EDGE_PASSIVE_ZAP_EXACT_INVENTORY',
              requestCounts: {
                'AUTH-E7-EXT-01': 0,
                'AUTH-E7-EXT-02': 0,
                'AUTH-E7-EXT-03': zap?.requestCount ?? 0,
              },
            },
          },
        }),
    externalRequests:
      directOriginRequests + awsPrivateOriginRequests + (zap?.requestCount ?? 0) + 2,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  assertCloudFrontAccessMaterialExcluded(result, signedCookies);
  await emitJson(
    result,
    path.join(evidenceRoot(scope), 'edge-security.json'),
    'stage7-edge-security.json',
  );
};

const boundedResponseText = async (response) => {
  const source = await response.text();
  if (source.length > 2 * 1024 * 1024) fail('E7_SMOKE_RESPONSE_TOO_LARGE');
  return source;
};

const prereleaseCookieMaxExpiresAtUtc = (config) => {
  const maximum = Math.min(
    Date.parse(config.authorization.expiresAtUtc),
    Date.parse(config.cleanup.expiresAtUtc),
    Date.parse(config.window.endsAtUtc) + PRERELEASE_COOKIE_EXPIRY_MARGIN_MS,
  );
  if (!Number.isFinite(maximum)) fail('E7_PRERELEASE_COOKIE_EXPIRY_BOUND_INVALID');
  return new Date(maximum).toISOString();
};

const prereleaseOriginGatePassed = (facts) =>
  exactKeys(facts, [
    'directAnonymousStatus',
    'directOriginSpoofStatus',
    'authorizedApiStatus',
    'originProtectionHeaderExposed',
    'originProtectionHeaderValueExposed',
    'originProtectionMetadataReflected',
    'jsonContentType',
    'noStore',
    'readyBodyValid',
  ]) &&
  facts.directAnonymousStatus === 403 &&
  facts.directOriginSpoofStatus === 403 &&
  facts.authorizedApiStatus === 200 &&
  facts.originProtectionHeaderExposed === false &&
  facts.originProtectionHeaderValueExposed === false &&
  facts.originProtectionMetadataReflected === false &&
  facts.jsonContentType === true &&
  facts.noStore === true &&
  facts.readyBodyValid === true;

const runAvailableSmoke = async ({
  origin,
  apiOrigin: requestedApiOrigin,
  region,
  publicKeyId,
  maxCookieExpiresAtUtc,
}) => {
  const apiOrigin = validatePrereleaseApiOrigin({
    origin: requestedApiOrigin,
    region,
  });
  let ownedOriginRequests = 0;
  let directApiOriginRequests = 0;
  const signedCookies = readCloudFrontSignedCookieFile({
    origin,
    filename: process.env.STAGE7_CLOUDFRONT_SIGNED_COOKIE_FILE,
    expectedPublicKeyId: publicKeyId,
    maxExpiresAtUtc: maxCookieExpiresAtUtc,
  });
  const expiredCookies = readCloudFrontSignedCookieFile({
    origin,
    filename: process.env.STAGE7_CLOUDFRONT_EXPIRED_SIGNED_COOKIE_FILE,
    expectedState: 'EXPIRED',
    expectedPublicKeyId: publicKeyId,
  });
  if (signedCookies.length !== 4 || expiredCookies.length !== 4) {
    fail('E7_PRERELEASE_SIGNED_COOKIE_REQUIRED');
  }
  const tamperedCookies = signedCookies.map((cookie) =>
    cookie.name === 'CloudFront-Signature'
      ? {
          ...cookie,
          value: `${cookie.value[0] === 'A' ? 'B' : 'A'}${cookie.value.slice(1)}`,
        }
      : cookie,
  );
  const cookieHeader = (cookies) => cookies.map(({ name, value }) => `${name}=${value}`).join('; ');
  const requestOwnedOrigin = async (pathname, cookies = [], accept = 'text/html') => {
    const url = new URL(pathname, `${origin}/`);
    if (url.origin !== origin) fail('E7_SMOKE_TARGET_ESCAPE');
    ownedOriginRequests += 1;
    if (ownedOriginRequests > 6) fail('E7_SMOKE_REQUEST_LIMIT_EXCEEDED');
    let response;
    try {
      response = await fetch(url, {
        redirect: 'error',
        headers: {
          accept,
          origin,
          'sec-fetch-site': 'same-origin',
          ...(cookies.length === 0 ? {} : { cookie: cookieHeader(cookies) }),
        },
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      fail('E7_SMOKE_REQUEST_FAILED');
    }
    return response;
  };
  const requestDirectApi = async (headers = {}) => {
    const url = new URL('/api/health/ready', `${apiOrigin}/`);
    if (url.origin !== apiOrigin) fail('E7_SMOKE_TARGET_ESCAPE');
    directApiOriginRequests += 1;
    if (directApiOriginRequests > 2) fail('E7_SMOKE_REQUEST_LIMIT_EXCEEDED');
    let response;
    try {
      response = await fetch(url, {
        redirect: 'error',
        headers: { accept: 'application/json', ...headers },
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      fail('E7_SMOKE_REQUEST_FAILED');
    }
    return response;
  };
  const anonymous = await requestOwnedOrigin('/');
  const anonymousText = await boundedResponseText(anonymous);
  const expired = await requestOwnedOrigin('/', expiredCookies);
  const expiredText = await boundedResponseText(expired);
  const tampered = await requestOwnedOrigin('/', tamperedCookies);
  const tamperedText = await boundedResponseText(tampered);
  const root = await requestOwnedOrigin('/', signedCookies);
  const rootText = await boundedResponseText(root);
  const deepLink = await requestOwnedOrigin('/products/product-demo-001', signedCookies);
  const deepLinkText = await boundedResponseText(deepLink);
  const directAnonymous = await requestDirectApi();
  const directAnonymousText = await boundedResponseText(directAnonymous);
  const directOriginSpoof = await requestDirectApi({ origin: 'https://spoof.example.invalid' });
  const directOriginSpoofText = await boundedResponseText(directOriginSpoof);
  const ready = await requestOwnedOrigin('/api/health/ready', signedCookies, 'application/json');
  const readyText = await boundedResponseText(ready);
  const observedResponses = [
    anonymous,
    expired,
    tampered,
    root,
    deepLink,
    directAnonymous,
    directOriginSpoof,
    ready,
  ];
  const originProtectionHeaderExposed = observedResponses.some((response) =>
    response.headers.has('x-stage7-origin-verify'),
  );
  const originProtectionHeaderValueExposed = observedResponses.some(
    (response) => response.headers.get('x-stage7-origin-verify') !== null,
  );
  const originProtectionMetadataReflected = /x-stage7-origin-verify/iu.test(
    [
      anonymousText,
      expiredText,
      tamperedText,
      rootText,
      deepLinkText,
      directAnonymousText,
      directOriginSpoofText,
      readyText,
    ].join('\n'),
  );
  let readyBody;
  try {
    readyBody = JSON.parse(readyText);
  } catch {
    readyBody = null;
  }
  const originGateFacts = {
    directAnonymousStatus: directAnonymous.status,
    directOriginSpoofStatus: directOriginSpoof.status,
    authorizedApiStatus: ready.status,
    originProtectionHeaderExposed,
    originProtectionHeaderValueExposed,
    originProtectionMetadataReflected,
    jsonContentType: /^application\/json\b/iu.test(ready.headers.get('content-type') ?? ''),
    noStore: /(?:^|,)\s*no-store\s*(?:,|$)/iu.test(ready.headers.get('cache-control') ?? ''),
    readyBodyValid:
      exactKeys(readyBody, ['status', 'checkedAt']) &&
      readyBody.status === 'ok' &&
      utc(readyBody.checkedAt),
  };
  const results = [
    {
      id: 'PR-UAT-E7-01',
      name: 'cloudfront-viewer-access-gate',
      status:
        anonymous.status === 403 &&
        expired.status === 403 &&
        tampered.status === 403 &&
        root.status === 200 &&
        /^text\/html\b/iu.test(root.headers.get('content-type') ?? '')
          ? 'PASS'
          : 'FAIL',
    },
    {
      id: 'PR-UAT-E7-02',
      name: 'direct-api-origin-gate',
      status: prereleaseOriginGatePassed(originGateFacts) ? 'PASS' : 'FAIL',
    },
    {
      id: 'PR-UAT-E7-03',
      name: 'deep-link-and-mixed-content',
      status:
        deepLink.status === 200 &&
        /^text\/html\b/iu.test(deepLink.headers.get('content-type') ?? '') &&
        !/(?:src|href)=["']http:\/\//iu.test(`${rootText}\n${deepLinkText}`)
          ? 'PASS'
          : 'FAIL',
    },
  ];
  if (results.some(({ status }) => status !== 'PASS')) fail('E7_PRERELEASE_UAT_FAILED');
  return assertCloudFrontAccessMaterialExcluded(
    {
      results,
      requests: {
        ownedOrigin: ownedOriginRequests,
        directApiOrigin: directApiOriginRequests,
        outsideAllowlist: 0,
      },
      accessGate: {
        viewerOriginSha256: digest(origin),
        apiOriginSha256: digest(apiOrigin),
        anonymousStatus: anonymous.status,
        expiredStatus: expired.status,
        tamperedStatus: tampered.status,
        authorizedDocumentStatus: root.status,
        directAnonymousStatus: directAnonymous.status,
        directOriginSpoofStatus: directOriginSpoof.status,
        authorizedApiStatus: ready.status,
        originProtectionHeaderExposed: false,
        originProtectionHeaderValueExposed: false,
        originProtectionMetadataReflected: false,
        accessMaterialCaptured: false,
      },
      rootStatus: root.status,
      rootText,
    },
    [...signedCookies, ...expiredCookies, ...tamperedCookies],
  );
};

const runUnavailableSmoke = async ({ origin }) => {
  const observations = [];
  for (const pathname of ['/', '/api/health', '/api/docs', '/api/v1/products']) {
    let observation;
    try {
      const response = await fetch(new URL(pathname, `${origin}/`), {
        method: 'GET',
        redirect: 'error',
        signal: AbortSignal.timeout(10_000),
      });
      await response.body?.cancel();
      observation = {
        unavailable: response.status === 403 || response.status === 404 || response.status >= 500,
      };
    } catch {
      observation = { unavailable: true };
    }
    observations.push(observation);
  }
  if (!observations.every(({ unavailable }) => unavailable)) {
    fail('E7_INITIAL_ROLLBACK_STILL_PUBLIC');
  }
  return {
    results: observations.map((_, index) => ({
      id: `RB-SMK-E7-${String(index + 1).padStart(2, '0')}`,
      name: `initial-unavailable-oracle-${String(index + 1).padStart(2, '0')}`,
      status: 'PASS',
    })),
    requests: observations.length,
    rootStatus: null,
    rootText: '',
  };
};

const smokeReviewer = () => {
  const alias = process.env.GITHUB_ACTOR?.toLowerCase();
  if (!/^[a-z][a-z0-9-]{2,31}$/u.test(alias ?? '')) fail('E7_SMOKE_REVIEWER_INVALID');
  return alias;
};

const initialRollbackInfrastructure = (document, config) => {
  try {
    return validateStage7InitialRollbackCheckpoint(document?.checkpoints?.rollbackInfrastructure, {
      config,
    });
  } catch (error) {
    if (error instanceof Stage7Error) fail('E7_INITIAL_ROLLBACK_INFRASTRUCTURE_INVALID');
    throw error;
  }
};

const updateRollbackSmoke = async ({ identity, config, manifestSha256, smoke, mode, usage }) => {
  const target = path.join(evidenceRoot('full'), 'rollback.json');
  const current = readEvidence(target);
  if (
    current.schemaVersion !== 1 ||
    current.stage !== 7 ||
    current.candidateSha !== identity.candidateSha ||
    current.releaseId !== identity.releaseId ||
    current.configSha256 !== objectSha256(config) ||
    current.containsSensitiveData !== false
  ) {
    fail('E7_ROLLBACK_EVIDENCE_INVALID');
  }
  if (mode === 'POST_ROLLBACK_INITIAL') initialRollbackInfrastructure(current, config);
  const checkpointName = mode === 'POST_ROLLBACK_INITIAL' ? 'rollbackSmoke' : 'repromotionSmoke';
  if (mode === 'POST_REPROMOTION') {
    if (current.checkpoints?.rollbackSmoke?.status !== 'PASS') {
      fail('E7_ROLLBACK_SMOKE_ORDER_INVALID');
    }
    const activation = readEvidence(path.join(evidenceRoot('full'), 'activation.json'));
    const activated = activation?.checkpoints?.activation;
    try {
      if (
        activation.candidateSha !== identity.candidateSha ||
        activation.releaseId !== identity.releaseId
      ) {
        fail('E7_REPROMOTION_ACTIVATION_INVALID');
      }
      validateStage7ActivationCheckpoint(activated, {
        config,
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        manifestSha256,
        complete: true,
      });
    } catch (error) {
      if (
        error instanceof Stage7Error ||
        (error instanceof Stage7ControlError && error.code === 'E7_REPROMOTION_ACTIVATION_INVALID')
      ) {
        fail('E7_REPROMOTION_ACTIVATION_INVALID');
      }
      throw error;
    }
    if (activated.publication.scheduler.state !== 'ENABLED') {
      fail('E7_REPROMOTION_ACTIVATION_INVALID');
    }
  }
  const next = {
    ...current,
    status: mode === 'POST_REPROMOTION' ? 'PASS' : 'IN_PROGRESS',
    initialRelease: true,
    updateReleaseSupported: false,
    updateReleaseUnsupportedReason: 'PRE_ACTIVATION_PUBLICATION_RISK',
    rollbackMode: 'INITIAL_DISABLE_UNPUBLISH',
    checkpoints: {
      ...current.checkpoints,
      [checkpointName]: {
        status: 'PASS',
        mode,
        reportSha256: objectSha256(smoke.results),
        total: smoke.results.length,
        passed: smoke.results.length,
        failed: 0,
        requests:
          typeof smoke.requests === 'number'
            ? smoke.requests
            : smoke.requests.ownedOrigin + smoke.requests.sandbox,
        dataMutations: mode === 'POST_ROLLBACK_INITIAL' ? 0 : smoke.requests.mutations,
        authorizationUsage: usage,
      },
    },
    updatedAtUtc: new Date().toISOString(),
  };
  await writeStage7Json(target, 'stage7-initial-rollback.json', next);
};

const smokeRelease = async (flags) => {
  const scope = scopeOf(flags);
  const mode =
    flags['post-rollback'] === true
      ? 'POST_ROLLBACK_INITIAL'
      : flags['post-repromotion'] === true
        ? 'POST_REPROMOTION'
        : 'POST_DEPLOY';
  if (flags['post-rollback'] !== undefined && flags['post-rollback'] !== true) {
    fail('E7_SMOKE_MODE_INVALID');
  }
  if (flags['post-repromotion'] !== undefined && flags['post-repromotion'] !== true) {
    fail('E7_SMOKE_MODE_INVALID');
  }
  if (flags['post-rollback'] === true && flags['post-repromotion'] === true) {
    fail('E7_SMOKE_MODE_INVALID');
  }
  if (scope === 'prerelease') {
    if (
      mode !== 'POST_DEPLOY' ||
      flags['synthetic-only'] !== true ||
      flags['external-uat'] !== true ||
      flags['non-public'] !== true
    ) {
      fail('E7_PRERELEASE_SMOKE_SCOPE_INVALID');
    }
  } else if (mode === 'POST_ROLLBACK_INITIAL' && flags['initial-release'] !== true) {
    fail('E7_INITIAL_RELEASE_ROLLBACK_ACK_REQUIRED');
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope, { requireGitTag: scope === 'full' });
  const manifest = requireCurrentFreeze(flags, scope, identity, config);
  callerIdentityFor(config, config.aws.roles.readRoleArn);
  const target = webTarget(config, identity);
  const deployedApi = scope === 'prerelease' ? apiTarget(config, identity) : null;
  const authority = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
    ...(deployedApi === null ? {} : { deployedApiOrigin: deployedApi.apiOrigin }),
  });
  let requestBudgetCounter;
  if (scope === 'full' && mode === 'POST_DEPLOY') {
    const authorizationEvidence = readEvidence(
      path.join(evidenceRoot(scope), 'external-authorization.json'),
    );
    const budgetPlan = validateAuthorizationBudgetPlan({
      authorization: authorizationEvidence,
      identity,
      config,
    });
    if (
      budgetPlan.authorizationSha256 !== objectSha256(authority.value) ||
      budgetPlan.ownedOriginSha256 !== authority.originSha256 ||
      budgetPlan.sandboxHostSha256 !== authority.sandboxHostSha256 ||
      objectSha256(budgetPlan.requestLimits) !==
        objectSha256(
          Object.fromEntries(
            externalAuthorizationRequirements(scope).map(({ key, id }) => [
              id,
              authority.authorizations[key].maxRequests,
            ]),
          ),
        )
    ) {
      fail('E7_EXTERNAL_REQUEST_BUDGET_AUTHORITY_MISMATCH');
    }
    const smokeInput = readEvidence(path.join(evidenceRoot(scope), 'smoke-input-preflight.json'));
    const activation = readEvidence(path.join(evidenceRoot(scope), 'activation.json'));
    const activationUsages = activation.checkpoints?.activation?.transitions?.map(
      ({ authorizationUsage: usage }) => usage,
    );
    if (!Array.isArray(activationUsages)) {
      fail('E7_EXTERNAL_REQUEST_BUDGET_PRIOR_USAGE_INVALID');
    }
    try {
      requestBudgetCounter = createFullExternalRequestCounter({
        plan: budgetPlan,
        usages: [
          authorizationEvidence.authorizationUsage,
          smokeInput.authorizationUsage,
          ...activationUsages,
        ],
        usageId: 'SMOKE_POST_DEPLOY',
      });
    } catch (error) {
      if (error instanceof Stage7ExternalRequestBudgetError) {
        fail('E7_EXTERNAL_REQUEST_BUDGET_PRIOR_USAGE_INVALID');
      }
      throw error;
    }
  }
  const evidenceName =
    mode === 'POST_DEPLOY'
      ? 'smoke.json'
      : mode === 'POST_ROLLBACK_INITIAL'
        ? 'rollback-state-smoke.json'
        : 'repromotion-smoke.json';
  const output = path.join(evidenceRoot(scope), evidenceName);
  try {
    const smoke =
      mode === 'POST_ROLLBACK_INITIAL'
        ? await runUnavailableSmoke({ origin: target.applicationOrigin })
        : scope === 'full'
          ? await runCanonicalStage7Smoke({
              origin: target.applicationOrigin,
              candidateSha: identity.candidateSha,
              releaseId: identity.releaseId,
              configSha256: objectSha256(config),
              authorization: authority.authorizations,
              ...(requestBudgetCounter === undefined
                ? {}
                : {
                    beforeRequest: (targetName) => {
                      const authorizationId = externalAuthorizationRequirements(scope).find(
                        ({ key }) => key === targetName,
                      )?.id;
                      if (authorizationId === undefined) {
                        fail('E7_EXTERNAL_REQUEST_BUDGET_COUNTER_INVALID');
                      }
                      requestBudgetCounter.beforeRequest(authorizationId);
                    },
                  }),
            })
          : await runAvailableSmoke({
              origin: target.applicationOrigin,
              apiOrigin: deployedApi.apiOrigin,
              region: config.aws.region,
              publicKeyId: config.prereleaseAccess.publicKeyId,
              maxCookieExpiresAtUtc: prereleaseCookieMaxExpiresAtUtc(config),
            });
    let backendProviderEgress;
    if (scope === 'full' && mode !== 'POST_ROLLBACK_INITIAL') {
      const expectation = smoke.providerEgressExpectation;
      if (
        !object(expectation) ||
        !utc(expectation.observationStartedAtUtc) ||
        !utc(expectation.observationEndedAtUtc) ||
        !Array.isArray(expectation.correlations) ||
        !SHA256.test(expectation.correlationSetSha256 ?? '')
      ) {
        fail('E7_PROVIDER_EGRESS_EXPECTATION_INVALID');
      }
      backendProviderEgress = await collectStage7ProviderEgressEvidence({
        logGroups: stage7ProviderEgressLogGroups(config.environment),
        startTimeMs: Date.parse(expectation.observationStartedAtUtc) - 5_000,
        endTimeMs: Date.parse(expectation.observationEndedAtUtc) + 5_000,
        allowedReleaseIdentities: [
          { candidateSha: identity.candidateSha, releaseId: identity.releaseId },
        ],
        expectedCorrelations: expectation.correlations,
        client: createAwsCliProviderEgressClient({ region: config.aws.region }),
      });
      if (backendProviderEgress.correlationSetSha256 !== expectation.correlationSetSha256) {
        fail('E7_PROVIDER_EGRESS_CORRELATION_SET_MISMATCH');
      }
    }
    const viewerOriginRequestCount =
      typeof smoke.requests === 'number' ? smoke.requests : smoke.requests.ownedOrigin;
    const directApiOriginRequestCount =
      typeof smoke.requests === 'number' ? 0 : (smoke.requests.directApiOrigin ?? 0);
    const ownedRequestCount = viewerOriginRequestCount + directApiOriginRequestCount;
    const browserSandboxRequestCount =
      typeof smoke.requests === 'number' ? 0 : smoke.requests.sandbox;
    const backendSandboxRequestCount = backendProviderEgress?.attempts?.total ?? 0;
    const sandboxRequestCount = browserSandboxRequestCount + backendSandboxRequestCount;
    const outsideAllowlist =
      typeof smoke.requests === 'number' ? 0 : smoke.requests.outsideAllowlist;
    const mutations =
      mode === 'POST_ROLLBACK_INITIAL' || scope === 'prerelease' ? 0 : smoke.requests.mutations;
    if (requestBudgetCounter !== undefined) {
      requestBudgetCounter.recordObservedRequests('AUTH-E7-EXT-02', backendSandboxRequestCount);
    }
    const requestBudgetUsage = requestBudgetCounter?.close();
    if (
      ownedRequestCount > authority.authorizations.ownedTarget.maxRequests ||
      sandboxRequestCount > authority.authorizations.sandboxSmoke.maxRequests ||
      outsideAllowlist !== 0
    ) {
      fail('E7_EXTERNAL_AUTHORIZATION_REQUEST_LIMIT_EXCEEDED');
    }
    if (mode === 'POST_ROLLBACK_INITIAL') {
      if (
        smoke.results.length !== 4 ||
        smoke.results.some(
          ({ id, status }, index) =>
            id !== `RB-SMK-E7-${String(index + 1).padStart(2, '0')}` || status !== 'PASS',
        )
      ) {
        fail('E7_INITIAL_ROLLBACK_SMOKE_INVALID');
      }
    } else if (scope === 'full') {
      validateCanonicalSmokeResults(smoke.results);
      if (!Number.isSafeInteger(mutations) || mutations <= 0) {
        fail('E7_SMOKE_MUTATION_ACCOUNTING_INVALID');
      }
    } else if (
      smoke.results.length !== 3 ||
      smoke.results.some(
        ({ id, status }, index) =>
          id !== `PR-UAT-E7-${String(index + 1).padStart(2, '0')}` || status !== 'PASS',
      )
    ) {
      fail('E7_PRERELEASE_UAT_INVALID');
    }
    const executedAtUtc = new Date().toISOString();
    const reviewerAlias = smokeReviewer();
    const usageIds = Object.fromEntries(
      externalAuthorizationRequirements(scope).map(({ key, id }) => [key, id]),
    );
    const computedAuthorizationUsage = authorizationUsage({
      scope,
      authority,
      identity,
      config,
      usageId:
        mode === 'POST_DEPLOY'
          ? 'SMOKE_POST_DEPLOY'
          : mode === 'POST_ROLLBACK_INITIAL'
            ? 'SMOKE_POST_ROLLBACK_INITIAL'
            : 'SMOKE_POST_REPROMOTION',
      requestCounts: {
        [usageIds.ownedTarget]: ownedRequestCount,
        [usageIds.sandboxSmoke]: sandboxRequestCount,
      },
    });
    if (
      requestBudgetUsage !== undefined &&
      objectSha256(requestBudgetUsage) !== objectSha256(computedAuthorizationUsage)
    ) {
      fail('E7_EXTERNAL_REQUEST_BUDGET_COUNTER_MISMATCH');
    }
    const result = {
      schemaVersion: 1,
      stage: 7,
      kind: 'DEPLOYED_BLACK_BOX_SMOKE',
      status: 'PASS',
      scope,
      mode,
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      manifestSha256: manifest.manifestSha256,
      stage7ConfigSha256: objectSha256(config),
      targetOriginSha256: digest(target.applicationOrigin),
      executedAtUtc,
      reviewerAlias,
      total: smoke.results.length,
      passed: smoke.results.length,
      failed: 0,
      results: smoke.results,
      requests: {
        total: ownedRequestCount + sandboxRequestCount,
        ownedOrigin: ownedRequestCount,
        ...(directApiOriginRequestCount === 0
          ? {}
          : {
              viewerOrigin: viewerOriginRequestCount,
              directApiOrigin: directApiOriginRequestCount,
            }),
        provider: sandboxRequestCount,
        providerBrowser: browserSandboxRequestCount,
        providerBackend: backendSandboxRequestCount,
        production: 0,
        outsideAllowlist,
      },
      syntheticDataOnly: true,
      dataMutations: mutations,
      ...(smoke.effects === undefined ? {} : { effects: smoke.effects }),
      ...(smoke.criticalErrors === undefined ? {} : { criticalErrors: smoke.criticalErrors }),
      ...(smoke.browser === undefined ? {} : { browser: smoke.browser }),
      ...(smoke.accessGate === undefined ? {} : { accessGate: smoke.accessGate }),
      ...(backendProviderEgress === undefined ? {} : { backendProviderEgress }),
      externalAuthorization: {
        authorizationSha256: objectSha256(authority.value),
        authorizationIds: externalAuthorizationRequirements(scope).map(({ id }) => id),
        ownedOriginSha256: authority.originSha256,
        ...(authority.apiOriginSha256 === null
          ? {}
          : { apiOriginSha256: authority.apiOriginSha256 }),
        sandboxHostSha256: authority.sandboxHostSha256,
      },
      authorizationUsage: requestBudgetUsage ?? computedAuthorizationUsage,
      externalRequests: ownedRequestCount + sandboxRequestCount + (scope === 'prerelease' ? 3 : 2),
      mutationsPerformed: mutations,
      containsSensitiveData: false,
    };
    await writeStage7Json(output, `stage7-${evidenceName}`, result);
    if (mode !== 'POST_DEPLOY') {
      await updateRollbackSmoke({
        identity,
        config,
        manifestSha256: manifest.manifestSha256,
        smoke,
        mode,
        usage: result.authorizationUsage,
      });
    }
    if (scope === 'prerelease') {
      const redirect = await fetchChecked(`http://${new URL(target.applicationOrigin).host}/`);
      const redirectLocation = redirect.headers.get('location');
      const ownedRequests = ownedRequestCount + 1;
      if (
        ![301, 308].includes(redirect.status) ||
        redirectLocation !== `${target.applicationOrigin}/` ||
        ownedRequests > authority.authorizations.ownedTarget.maxRequests
      ) {
        fail('E7_EXTERNAL_OWNED_TARGET_CHECK_FAILED');
      }
      const externalUat = {
        ...result,
        kind: 'EXTERNAL_OWNED_TARGET_UAT',
        stage6Capability: {
          ownedTarget: {
            status: 'PASS',
            authorization: authority.authorizations.ownedTarget,
            target: {
              classification: 'OWNED_EPHEMERAL_QA',
              environment: 'ENV-E6-QA',
              originSha256: authority.originSha256,
              ownershipVerified: true,
              production: false,
            },
            checks: [
              {
                id: 'AUTH01-E6-01',
                name: 'http-redirect-to-https',
                status: 'PASS',
                observedStatus: redirect.status,
              },
              {
                id: 'AUTH01-E6-02',
                name: 'https-document-available',
                status: 'PASS',
                observedStatus: smoke.rootStatus,
              },
              {
                id: 'AUTH01-E6-03',
                name: 'mixed-content-requests-zero',
                status: 'PASS',
                observedRequests: 0,
              },
            ],
            requests: {
              total: ownedRequests,
              outsideAllowlist: 0,
              provider: 0,
              production: 0,
            },
            evidenceIds: ['AUTH-E6-01', 'UAT-33', 'EVD-E6-36/UAT-33'],
            reportSha256: objectSha256(smoke.results),
          },
        },
      };
      await writeStage7Json(
        path.join(evidenceRoot(scope), 'external-uat.json'),
        'stage7-external-uat.json',
        externalUat,
      );
    }
    process.stdout.write(
      `stage-7 smoke ${mode}: PASS (${smoke.results.length}/${smoke.results.length})\n`,
    );
  } catch (error) {
    const expectedTotal = mode === 'POST_ROLLBACK_INITIAL' ? 4 : scope === 'full' ? 18 : 3;
    await writeStage7Json(output, `stage7-${evidenceName}-failed.json`, {
      schemaVersion: 1,
      stage: 7,
      kind: 'DEPLOYED_BLACK_BOX_SMOKE',
      status: 'FAIL',
      scope,
      mode,
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      reason:
        error instanceof Stage7ControlError ||
        error instanceof Stage7Error ||
        error instanceof Stage7SmokeError
          ? error.code
          : 'E7_SMOKE_UNEXPECTED_FAILURE',
      total: expectedTotal,
      passed: 0,
      failed: expectedTotal,
      externalRequests: 'UNKNOWN_BOUNDED_BY_AUTHORIZATION',
      mutationsPerformed:
        mode === 'POST_ROLLBACK_INITIAL' || scope === 'prerelease'
          ? 0
          : 'UNKNOWN_BOUNDED_BY_TEST_MATRIX',
      containsSensitiveData: false,
    });
    throw error;
  }
};

const prepareVersionedRollbackPending = async (flags) => {
  if (
    scopeOf(flags) !== 'full' ||
    flags['prepare-versioned-rollback-pending'] !== true ||
    flags['approved-environment'] !== true ||
    process.env.STAGE7_PROTECTED_ENVIRONMENT !== 'assessment-release'
  ) {
    fail('E7_ROLLBACK_PENDING_PRODUCER_FLAGS_INVALID');
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const identity = candidateIdentity('full', { requireGitTag: true });
  const manifest = requireCurrentFreeze(flags, 'full', identity, config);
  callerIdentityFor(config, config.aws.roles.readRoleArn);
  const target = authorizationTarget('full', requiredString(flags, 'deployment'), config, identity);
  const authority = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
  });
  const configSha256 = objectSha256(config);
  const producer = await prepareVersionedRollbackPendingCanary({
    origin: target.applicationOrigin,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    configSha256,
    authorization: authority.authorizations,
    privateInputs: readPrivateSmokeInputs({
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      configSha256,
      now: new Date(),
    }),
  });
  const usageIds = Object.fromEntries(
    externalAuthorizationRequirements('full').map(({ key, id }) => [key, id]),
  );
  const result = {
    ...producer,
    manifestSha256: manifest.manifestSha256,
    externalAuthorization: {
      authorizationSha256: objectSha256(authority.value),
      authorizationIds: externalAuthorizationRequirements('full').map(({ id }) => id),
      ownedOriginSha256: authority.originSha256,
      sandboxHostSha256: authority.sandboxHostSha256,
    },
    authorizationUsage: authorizationUsage({
      scope: 'full',
      authority,
      identity,
      config,
      usageId: 'RB_E7_05_PENDING_PRODUCER',
      requestCounts: {
        [usageIds.ownedTarget]: producer.requests.ownedOrigin,
        [usageIds.sandboxSmoke]: producer.requests.sandbox,
      },
    }),
    externalRequests: producer.requests.ownedOrigin + producer.requests.sandbox,
    mutationsPerformed: producer.requests.mutations,
  };
  await writeStage7Json(
    requiredString(flags, 'evidence'),
    'stage7-versioned-rollback-pending-producer.json',
    result,
  );
};

const validateRollbackPendingProducerForCloseout = ({
  value,
  identity,
  manifest,
  config,
  authority,
  applicationOrigin,
}) => {
  const providerEgress = value?.providerEgress;
  const requests = value?.requests;
  const authorizationSha256 =
    authority.value === undefined ? authority.authorizationSha256 : objectSha256(authority.value);
  const ownedOriginSha256 = authority.originSha256 ?? authority.ownedOriginSha256;
  const authorizationIds = externalAuthorizationRequirements('full').map(({ id }) => id);
  const usageIds = Object.fromEntries(
    externalAuthorizationRequirements('full').map(({ key, id }) => [key, id]),
  );
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'configSha256',
      'targetOriginSha256',
      'transactionCorrelationSha256',
      'checkoutCorrelationSha256',
      'providerEgress',
      'observedAtUtc',
      'requests',
      'syntheticOnly',
      'expectedTerminalStatus',
      'containsSensitiveData',
      'manifestSha256',
      'externalAuthorization',
      'authorizationUsage',
      'externalRequests',
      'mutationsPerformed',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'VERSIONED_ROLLBACK_PENDING_PRODUCER' ||
    value.status !== 'PENDING_OBSERVED' ||
    value.candidateSha !== identity.candidateSha ||
    value.releaseId !== identity.releaseId ||
    value.configSha256 !== objectSha256(config) ||
    value.manifestSha256 !== manifest.manifestSha256 ||
    value.targetOriginSha256 !== digest(applicationOrigin) ||
    !SHA256.test(value.transactionCorrelationSha256 ?? '') ||
    !SHA256.test(value.checkoutCorrelationSha256 ?? '') ||
    !exactKeys(providerEgress, [
      'observationStartedAtUtc',
      'correlationSha256',
      'correlationSetSha256',
    ]) ||
    !utc(providerEgress.observationStartedAtUtc) ||
    !SHA256.test(providerEgress.correlationSha256 ?? '') ||
    providerEgress.correlationSetSha256 !== digest(providerEgress.correlationSha256) ||
    !utc(value.observedAtUtc) ||
    Date.parse(providerEgress.observationStartedAtUtc) > Date.parse(value.observedAtUtc) ||
    !exactKeys(requests, ['ownedOrigin', 'sandbox', 'outsideAllowlist', 'mutations']) ||
    !Object.values(requests).every((count) => Number.isSafeInteger(count) && count >= 0) ||
    requests.sandbox !== 2 ||
    requests.outsideAllowlist !== 0 ||
    requests.mutations !== 1 ||
    value.externalRequests !== requests.ownedOrigin + requests.sandbox ||
    value.mutationsPerformed !== requests.mutations ||
    value.syntheticOnly !== true ||
    !['DECLINED', 'ERROR'].includes(value.expectedTerminalStatus) ||
    value.containsSensitiveData !== false ||
    !exactKeys(value.externalAuthorization, [
      'authorizationSha256',
      'authorizationIds',
      'ownedOriginSha256',
      'sandboxHostSha256',
    ]) ||
    value.externalAuthorization.authorizationSha256 !== authorizationSha256 ||
    value.externalAuthorization.authorizationIds?.join('\0') !== authorizationIds.join('\0') ||
    value.externalAuthorization.ownedOriginSha256 !== ownedOriginSha256 ||
    value.externalAuthorization.sandboxHostSha256 !== authority.sandboxHostSha256
  ) {
    fail('E7_ROLLBACK_PENDING_PRODUCER_INVALID');
  }
  validateAuthorizationUsageEnvelope({
    usage: value.authorizationUsage,
    scope: 'full',
    identity,
    config,
    authorizationSha256,
    ownedOriginSha256,
    sandboxHostSha256: authority.sandboxHostSha256,
    usageId: 'RB_E7_05_PENDING_PRODUCER',
    requestCounts: {
      [usageIds.ownedTarget]: requests.ownedOrigin,
      [usageIds.sandboxSmoke]: requests.sandbox,
    },
  });
  return value;
};

const closeVersionedRollbackPendingEgress = async (flags) => {
  if (
    scopeOf(flags) !== 'full' ||
    flags['close-versioned-rollback-pending-egress'] !== true ||
    flags['approved-environment'] !== true ||
    process.env.STAGE7_PROTECTED_ENVIRONMENT !== 'assessment-release'
  ) {
    fail('E7_ROLLBACK_PENDING_EGRESS_CLOSEOUT_FLAGS_INVALID');
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const identity = candidateIdentity('full', { requireGitTag: true });
  const manifest = requireCurrentFreeze(flags, 'full', identity, config);
  const previousManifest = validateStage7PreviousReleaseForTarget(
    readEvidence(requiredString(flags, 'previous-manifest')),
    { config, freezeManifest: manifest },
  );
  const candidateRecord = validateStage7CandidateRollbackRecord(
    readEvidence(requiredString(flags, 'candidate-record')),
    { previousManifest },
  );
  const rollbackEvidence = readEvidence(requiredString(flags, 'rollback-evidence'));
  const rollbackPlan = rollbackEvidence?.checkpoints?.rollbackPlan;
  const repromotionPlan = rollbackEvidence?.checkpoints?.repromotionPlan;
  const rollbackCheckpoint = validateStage7VersionedRollbackCheckpoint(
    readEvidence(requiredString(flags, 'rollback-checkpoint')),
    { plan: rollbackPlan, previousManifest, candidateRecord },
  );
  const repromotionCheckpoint = validateStage7VersionedRollbackCheckpoint(
    readEvidence(requiredString(flags, 'repromotion-checkpoint')),
    { plan: repromotionPlan, previousManifest, candidateRecord },
  );
  const target = webTarget(config, identity);
  callerIdentityFor(config, config.aws.roles.readRoleArn);
  const authority = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
  });
  const pendingProducer = validateRollbackPendingProducerForCloseout({
    value: readEvidence(requiredString(flags, 'pending-producer')),
    identity,
    manifest,
    config,
    authority,
    applicationOrigin: target.applicationOrigin,
  });
  const terminal = rollbackCheckpoint.pendingIntegrity;
  if (
    rollbackCheckpoint.direction !== 'ROLLBACK_TO_PREVIOUS' ||
    repromotionCheckpoint.direction !== 'REPROMOTE_CANDIDATE' ||
    terminal.status !== 'PASS' ||
    terminal.trackedBefore !== 1 ||
    terminal.stillPending !== 0 ||
    terminal.reconciled !== terminal.trackedBefore ||
    terminal.orphaned !== 0 ||
    terminal.duplicateEffects !== 0 ||
    terminal.lostFacts !== 0 ||
    !exactKeys(terminal.terminalStatusCounts, ['APPROVED', 'DECLINED', 'VOIDED', 'ERROR']) ||
    terminal.terminalStatusCounts[pendingProducer.expectedTerminalStatus] !== 1 ||
    Object.entries(terminal.terminalStatusCounts).some(
      ([status, count]) => status !== pendingProducer.expectedTerminalStatus && count !== 0,
    ) ||
    Date.parse(pendingProducer.observedAtUtc) > Date.parse(rollbackCheckpoint.startedAtUtc) ||
    Date.parse(rollbackCheckpoint.completedAtUtc) > Date.parse(repromotionCheckpoint.startedAtUtc)
  ) {
    fail('E7_ROLLBACK_PENDING_TERMINAL_READBACK_INVALID');
  }
  const observationStartedAtMs = Date.parse(pendingProducer.providerEgress.observationStartedAtUtc);
  const observationEndedAtMs = Date.now();
  if (
    !Number.isSafeInteger(observationStartedAtMs) ||
    observationEndedAtMs <= observationStartedAtMs ||
    observationEndedAtMs - observationStartedAtMs > 60 * 60 * 1_000
  ) {
    fail('E7_ROLLBACK_PENDING_EGRESS_WINDOW_INVALID');
  }
  const previousIdentity = {
    candidateSha: previousManifest.previous.candidateSha,
    releaseId: previousManifest.previous.releaseId,
  };
  const backendProviderEgress = await collectStage7ProviderEgressEvidence({
    logGroups: stage7ProviderEgressLogGroups(config.environment),
    startTimeMs: Math.max(0, observationStartedAtMs - 5_000),
    endTimeMs: observationEndedAtMs,
    allowedReleaseIdentities: [
      { candidateSha: identity.candidateSha, releaseId: identity.releaseId },
      previousIdentity,
    ],
    requiredStatusReleaseIdentity: previousIdentity,
    expectedCorrelations: [
      {
        correlationSha256: pendingProducer.providerEgress.correlationSha256,
        requiresStatusRead: true,
      },
    ],
    client: createAwsCliProviderEgressClient({ region: config.aws.region }),
  });
  if (
    backendProviderEgress.correlationSetSha256 !==
      pendingProducer.providerEgress.correlationSetSha256 ||
    backendProviderEgress.requiredStatusReleaseIdentitySha256 !==
      digest(`${previousIdentity.candidateSha}\0${previousIdentity.releaseId}`)
  ) {
    fail('E7_ROLLBACK_PENDING_EGRESS_CORRELATION_MISMATCH');
  }
  const usageIds = Object.fromEntries(
    externalAuthorizationRequirements('full').map(({ key, id }) => [key, id]),
  );
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'ROLLBACK_PENDING_EGRESS_CLOSEOUT',
    status: 'PASS',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    stage7ConfigSha256: objectSha256(config),
    manifestSha256: manifest.manifestSha256,
    pendingProducerSha256: objectSha256(pendingProducer),
    rollbackCheckpointSha256: rollbackCheckpoint.checkpointSha256,
    repromotionCheckpointSha256: repromotionCheckpoint.checkpointSha256,
    expectedTerminalStatus: pendingProducer.expectedTerminalStatus,
    terminalReadback: {
      status: terminal.status,
      trackedBefore: terminal.trackedBefore,
      reconciled: terminal.reconciled,
      stillPending: terminal.stillPending,
      orphaned: terminal.orphaned,
      duplicateEffects: terminal.duplicateEffects,
      lostFacts: terminal.lostFacts,
      terminalStatusCounts: terminal.terminalStatusCounts,
      correlationEvidenceSha256: terminal.correlationEvidenceSha256,
    },
    backendProviderEgress,
    externalAuthorization: {
      authorizationSha256: objectSha256(authority.value),
      authorizationIds: externalAuthorizationRequirements('full').map(({ id }) => id),
      ownedOriginSha256: authority.originSha256,
      sandboxHostSha256: authority.sandboxHostSha256,
    },
    authorizationUsage: authorizationUsage({
      scope: 'full',
      authority,
      identity,
      config,
      usageId: 'RB_E7_05_PENDING_EGRESS_CLOSEOUT',
      requestCounts: {
        [usageIds.ownedTarget]: 0,
        [usageIds.sandboxSmoke]: backendProviderEgress.attempts.total,
      },
    }),
    externalRequests: backendProviderEgress.attempts.total,
    mutationsPerformed: 0,
    rawIdentifiersCaptured: false,
    containsSensitiveData: false,
  };
  validateRollbackPendingEgressCloseout({
    value: result,
    identity,
    manifest,
    config,
    authority,
    pendingProducer,
    previousIdentity,
    rollbackCheckpoint,
    repromotionCheckpoint,
  });
  await writeStage7Json(
    requiredString(flags, 'evidence'),
    'stage7-rollback-pending-egress-closeout.json',
    result,
  );
};

const validateRollbackPendingEgressCloseout = ({
  value,
  identity,
  manifest,
  config,
  authority,
  pendingProducer,
  previousIdentity,
  rollbackCheckpoint,
  repromotionCheckpoint,
}) => {
  const providerEgress = value?.backendProviderEgress;
  const attempts = providerEgress?.attempts;
  const terminal = value?.terminalReadback;
  const authorizationIds = externalAuthorizationRequirements('full').map(({ id }) => id);
  const usageIds = Object.fromEntries(
    externalAuthorizationRequirements('full').map(({ key, id }) => [key, id]),
  );
  const authorizationSha256 =
    authority.value === undefined ? authority.authorizationSha256 : objectSha256(authority.value);
  const ownedOriginSha256 = authority.originSha256 ?? authority.ownedOriginSha256;
  const allowedIdentityKeys = [
    `${identity.candidateSha}\0${identity.releaseId}`,
    `${previousIdentity.candidateSha}\0${previousIdentity.releaseId}`,
  ];
  const expectedLogGroups = stage7ProviderEgressLogGroups(config.environment);
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'stage7ConfigSha256',
      'manifestSha256',
      'pendingProducerSha256',
      'rollbackCheckpointSha256',
      'repromotionCheckpointSha256',
      'expectedTerminalStatus',
      'terminalReadback',
      'backendProviderEgress',
      'externalAuthorization',
      'authorizationUsage',
      'externalRequests',
      'mutationsPerformed',
      'rawIdentifiersCaptured',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'ROLLBACK_PENDING_EGRESS_CLOSEOUT' ||
    value.status !== 'PASS' ||
    value.candidateSha !== identity.candidateSha ||
    value.releaseId !== identity.releaseId ||
    value.stage7ConfigSha256 !== objectSha256(config) ||
    value.manifestSha256 !== manifest.manifestSha256 ||
    value.pendingProducerSha256 !== objectSha256(pendingProducer) ||
    value.rollbackCheckpointSha256 !== rollbackCheckpoint.checkpointSha256 ||
    value.repromotionCheckpointSha256 !== repromotionCheckpoint.checkpointSha256 ||
    value.expectedTerminalStatus !== pendingProducer.expectedTerminalStatus ||
    !exactKeys(terminal, [
      'status',
      'trackedBefore',
      'reconciled',
      'stillPending',
      'orphaned',
      'duplicateEffects',
      'lostFacts',
      'terminalStatusCounts',
      'correlationEvidenceSha256',
    ]) ||
    terminal.status !== 'PASS' ||
    terminal.trackedBefore !== 1 ||
    terminal.reconciled !== terminal.trackedBefore ||
    terminal.stillPending !== 0 ||
    terminal.orphaned !== 0 ||
    terminal.duplicateEffects !== 0 ||
    terminal.lostFacts !== 0 ||
    !exactKeys(terminal.terminalStatusCounts, ['APPROVED', 'DECLINED', 'VOIDED', 'ERROR']) ||
    terminal.terminalStatusCounts[pendingProducer.expectedTerminalStatus] !== 1 ||
    Object.entries(terminal.terminalStatusCounts).some(
      ([status, count]) => status !== pendingProducer.expectedTerminalStatus && count !== 0,
    ) ||
    objectSha256(terminal.terminalStatusCounts) !==
      objectSha256(rollbackCheckpoint.pendingIntegrity.terminalStatusCounts) ||
    terminal.correlationEvidenceSha256 !==
      rollbackCheckpoint.pendingIntegrity.correlationEvidenceSha256 ||
    !exactKeys(providerEgress, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'observationWindow',
      'allowedReleaseIdentitySetSha256',
      'logGroupSetSha256',
      'correlationSetSha256',
      'attempts',
      'cloudWatchReadCount',
      'eventSetSha256',
      'requiredStatusReleaseIdentitySha256',
      'rawIdentifiersCaptured',
      'containsSensitiveData',
    ]) ||
    providerEgress.schemaVersion !== 1 ||
    providerEgress.stage !== 7 ||
    providerEgress.kind !== 'BACKEND_PROVIDER_EGRESS_EVIDENCE' ||
    providerEgress.status !== 'PASS' ||
    !exactKeys(providerEgress.observationWindow, ['startedAtUtc', 'endedAtUtc']) ||
    !utc(providerEgress.observationWindow.startedAtUtc) ||
    !utc(providerEgress.observationWindow.endedAtUtc) ||
    Date.parse(providerEgress.observationWindow.startedAtUtc) >
      Date.parse(pendingProducer.providerEgress.observationStartedAtUtc) ||
    Date.parse(providerEgress.observationWindow.endedAtUtc) <
      Date.parse(repromotionCheckpoint.completedAtUtc) ||
    providerEgress.allowedReleaseIdentitySetSha256 !==
      digest(allowedIdentityKeys.toSorted().join('\0')) ||
    providerEgress.logGroupSetSha256 !==
      digest(Object.values(expectedLogGroups).toSorted().join('\0')) ||
    providerEgress.correlationSetSha256 !== pendingProducer.providerEgress.correlationSetSha256 ||
    providerEgress.requiredStatusReleaseIdentitySha256 !==
      digest(`${previousIdentity.candidateSha}\0${previousIdentity.releaseId}`) ||
    !exactKeys(attempts, [
      'total',
      'merchantConfiguration',
      'transactionCreate',
      'transactionStatus',
      'byRuntime',
    ]) ||
    !exactKeys(attempts.byRuntime, ['api', 'worker']) ||
    ![
      attempts.total,
      attempts.merchantConfiguration,
      attempts.transactionCreate,
      attempts.transactionStatus,
      attempts.byRuntime.api,
      attempts.byRuntime.worker,
      providerEgress.cloudWatchReadCount,
    ].every((count) => Number.isSafeInteger(count) && count >= 0) ||
    attempts.transactionCreate !== 1 ||
    attempts.merchantConfiguration > 1 ||
    attempts.transactionStatus < 1 ||
    attempts.total !==
      attempts.merchantConfiguration + attempts.transactionCreate + attempts.transactionStatus ||
    attempts.byRuntime.api !== attempts.merchantConfiguration + attempts.transactionCreate ||
    attempts.byRuntime.worker !== attempts.transactionStatus ||
    !SHA256.test(providerEgress.eventSetSha256 ?? '') ||
    providerEgress.rawIdentifiersCaptured !== false ||
    providerEgress.containsSensitiveData !== false ||
    !exactKeys(value.externalAuthorization, [
      'authorizationSha256',
      'authorizationIds',
      'ownedOriginSha256',
      'sandboxHostSha256',
    ]) ||
    value.externalAuthorization.authorizationSha256 !== authorizationSha256 ||
    value.externalAuthorization.authorizationIds?.join('\0') !== authorizationIds.join('\0') ||
    value.externalAuthorization.ownedOriginSha256 !== ownedOriginSha256 ||
    value.externalAuthorization.sandboxHostSha256 !== authority.sandboxHostSha256 ||
    value.externalRequests !== attempts.total ||
    value.mutationsPerformed !== 0 ||
    value.rawIdentifiersCaptured !== false ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_ROLLBACK_PENDING_EGRESS_CLOSEOUT_INVALID');
  }
  validateAuthorizationUsageEnvelope({
    usage: value.authorizationUsage,
    scope: 'full',
    identity,
    config,
    authorizationSha256,
    ownedOriginSha256,
    sandboxHostSha256: authority.sandboxHostSha256,
    usageId: 'RB_E7_05_PENDING_EGRESS_CLOSEOUT',
    requestCounts: {
      [usageIds.ownedTarget]: 0,
      [usageIds.sandboxSmoke]: attempts.total,
    },
  });
  return value;
};

const validateEmergencyRecoveryForSmoke = ({ value, previousManifest, candidateRecord }) => {
  const body = { ...value };
  delete body.recoverySha256;
  const previousByKey = new Map(
    previousManifest.resources.web.objects.map((entry) => [entry.key, entry]),
  );
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'decision',
      'previousReleaseManifestSha256',
      'candidateRecordSha256',
      'plan',
      'aliases',
      'web',
      'pendingIntegrity',
      'dataFactsSha256',
      'dataRollbackPerformed',
      'stacksDeleted',
      'completedAtUtc',
      'containsSensitiveData',
      'recoverySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'VERSIONED_ROLLBACK_EMERGENCY_RECOVERY' ||
    value.status !== 'PASS' ||
    value.decision !== 'RECOVERED_TO_PREVIOUS_REQUIRES_READ_SMOKE' ||
    value.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    value.candidateRecordSha256 !== candidateRecord.recordSha256 ||
    value.plan?.direction !== 'ROLLBACK_TO_PREVIOUS' ||
    value.plan?.purpose !== 'EMERGENCY_RECOVERY' ||
    value.plan?.toReleaseId !== previousManifest.previous.releaseId ||
    value.aliases?.api?.version !== previousManifest.resources.api.version ||
    value.aliases?.worker?.version !== previousManifest.resources.worker.version ||
    value.web?.bucketName !== previousManifest.resources.web.bucketName ||
    value.web?.distributionId !== previousManifest.resources.web.distributionId ||
    value.web?.objects?.length !== 2 ||
    value.web.objects.some((entry) => {
      const expected = previousByKey.get(entry.key);
      return (
        expected === undefined ||
        entry.sourceVersionId !== expected.versionId ||
        entry.contentSha256 !== expected.contentSha256 ||
        entry.bytes !== expected.bytes
      );
    }) ||
    value.pendingIntegrity?.status !== 'PASS' ||
    value.dataRollbackPerformed !== false ||
    value.stacksDeleted !== 0 ||
    value.containsSensitiveData !== false ||
    !SHA256.test(value.dataFactsSha256 ?? '') ||
    !Number.isFinite(Date.parse(value.completedAtUtc ?? '')) ||
    value.recoverySha256 !== objectSha256(body)
  ) {
    fail('E7_EMERGENCY_RECOVERY_EVIDENCE_INVALID');
  }
  return value;
};

const validateCandidateActiveNoActionRecovery = ({ value, previousManifest, candidateRecord }) => {
  const body = { ...value };
  delete body.recoverySha256;
  const observedAlias = ({ functionName, aliasName, version }) => ({
    functionName,
    aliasName,
    version,
  });
  const expectedObservedWeb = {
    bucketName: candidateRecord.resources.web.bucketName,
    distributionId: candidateRecord.resources.web.distributionId,
    objects: candidateRecord.resources.web.objects.map(({ key, versionId, contentSha256 }) => ({
      key,
      versionId,
      contentSha256,
    })),
  };
  let expectedPlan;
  try {
    expectedPlan = createStage7VersionedRollbackPlan({
      direction: 'REPROMOTE_CANDIDATE',
      purpose: 'EMERGENCY_RECOVERY',
      previousManifest,
      candidateRecord,
      currentState: value.observedState,
    });
  } catch (error) {
    if (error instanceof Stage7Error) fail('E7_EMERGENCY_RECOVERY_NO_ACTION_INVALID');
    throw error;
  }
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'decision',
      'previousReleaseManifestSha256',
      'candidateRecordSha256',
      'publicationState',
      'observedState',
      'verificationPlan',
      'mutationsPerformed',
      'dataRollbackPerformed',
      'stacksDeleted',
      'completedAtUtc',
      'containsSensitiveData',
      'recoverySha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'VERSIONED_ROLLBACK_EMERGENCY_RECOVERY' ||
    value.status !== 'PASS' ||
    value.decision !== 'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED' ||
    value.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    value.candidateRecordSha256 !== candidateRecord.recordSha256 ||
    !exactKeys(value.publicationState, ['api', 'web']) ||
    value.publicationState.api !== 'ENABLED' ||
    value.publicationState.web !== 'ENABLED' ||
    objectSha256(value.observedState?.api) !==
      objectSha256(observedAlias(candidateRecord.resources.api)) ||
    objectSha256(value.observedState?.worker) !==
      objectSha256(observedAlias(candidateRecord.resources.worker)) ||
    objectSha256(value.observedState?.web) !== objectSha256(expectedObservedWeb) ||
    expectedPlan.decision !== 'NOOP_ALREADY_APPLIED' ||
    objectSha256(value.verificationPlan) !== objectSha256(expectedPlan) ||
    value.mutationsPerformed !== 0 ||
    value.dataRollbackPerformed !== false ||
    value.stacksDeleted !== 0 ||
    !utc(value.completedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.recoverySha256 !== objectSha256(body)
  ) {
    fail('E7_EMERGENCY_RECOVERY_NO_ACTION_INVALID');
  }
  return value;
};

const expectedEmergencyNoActionSourceBindings = (map) =>
  EMERGENCY_NO_ACTION_SOURCE_BINDING_SPECS.map(([label, basename]) => {
    const filename = map.get(basename);
    if (filename === undefined) fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_SOURCE_MISSING');
    const source = readEvidenceSource(filename);
    return {
      label,
      basename,
      rawSha256: digest(source),
      canonicalSha256: objectSha256(readEvidence(filename)),
      bytes: source.byteLength,
    };
  });

const expectedEmergencyNoActionCallerBinding = ({ config, runId }) => {
  if (!RUN_ID.test(runId ?? '')) fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_CALLER_INVALID');
  const readRoleArn = config.aws.roles.readRoleArn;
  const projection = {
    accountSha256: digest(config.aws.accountId),
    accountSuffix: config.aws.accountId.slice(-4),
    roleSha256: digest(readRoleArn),
    sessionArnSha256: digest(
      `arn:aws:sts::${config.aws.accountId}:assumed-role/${roleName(readRoleArn)}/e7-emergency-observe-${runId}`,
    ),
  };
  const rawProjection = JSON.stringify(projection);
  return {
    projection,
    rawSha256: digest(rawProjection),
    canonicalSha256: objectSha256(projection),
    bytes: Buffer.byteLength(rawProjection),
  };
};

const validateCandidateActiveNoActionSnapshotCheckpoint = ({
  value,
  sequence,
  candidateRecord,
  identity,
  expectedStackNames,
}) => {
  const expectedObjects = candidateRecord.resources.web.objects.map(
    ({ key, versionId, contentSha256, bytes }) => ({ key, versionId, contentSha256, bytes }),
  );
  if (
    !exactKeys(value, ['sequence', 'state', 'stateSha256']) ||
    value.sequence !== sequence ||
    value.stateSha256 !== objectSha256(value.state) ||
    !exactKeys(value.state, ['publication', 'aliases', 'web']) ||
    !exactKeys(value.state.publication, ['api', 'web']) ||
    !['api', 'web'].every((suffix) => {
      const publication = value.state.publication[suffix];
      return (
        exactKeys(publication, [
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
        publication.state === 'ENABLED' &&
        publication.stackName === expectedStackNames[suffix] &&
        /^(?:CREATE|UPDATE)_COMPLETE$/u.test(publication.stackStatus ?? '') &&
        utc(publication.createdAtUtc) &&
        (publication.updatedAtUtc === null || utc(publication.updatedAtUtc)) &&
        publication.terminationProtection === true &&
        publication.candidateSha === identity.candidateSha &&
        publication.releaseId === identity.releaseId &&
        publication.publicationOutput === 'ENABLED'
      );
    }) ||
    !exactKeys(value.state.aliases, ['api', 'worker']) ||
    !['api', 'worker'].every((suffix) => {
      const actual = value.state.aliases[suffix];
      const expected = candidateRecord.resources[suffix];
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
    !exactKeys(value.state.web, ['bucketName', 'distributionId', 'objects']) ||
    value.state.web.bucketName !== candidateRecord.resources.web.bucketName ||
    value.state.web.distributionId !== candidateRecord.resources.web.distributionId ||
    objectSha256(value.state.web.objects) !== objectSha256(expectedObjects)
  ) {
    fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_SNAPSHOT_INVALID');
  }
  return value;
};

const validateCandidateActiveNoActionOutcomeCheckpoint = ({
  value,
  previousManifest,
  candidateRecord,
  emergencyRecovery,
  identity,
  expectedSourceBindings,
  expectedCallerBinding,
  expectedStackNames,
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
    value.status !== 'PASS' ||
    value.decision !== 'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED' ||
    value.failureCode !== null ||
    value.failureStage !== null ||
    value.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    value.candidateRecordSha256 !== candidateRecord.recordSha256 ||
    value.assemblySha256 !== previousManifest.target.assemblySha256 ||
    !Array.isArray(value.sourceBindings) ||
    objectSha256(value.sourceBindings) !== objectSha256(expectedSourceBindings) ||
    value.sourceBindingsSha256 !== objectSha256(value.sourceBindings) ||
    !exactKeys(value.callerBinding, ['projection', 'rawSha256', 'canonicalSha256', 'bytes']) ||
    objectSha256(value.callerBinding) !== objectSha256(expectedCallerBinding) ||
    !exactKeys(value.observations, ['before', 'after']) ||
    value.recoverySha256 !== emergencyRecovery.recoverySha256 ||
    value.mutationsPerformed !== 0 ||
    value.dataRollbackPerformed !== false ||
    value.stacksDeleted !== 0 ||
    value.completedAtUtc !== emergencyRecovery.completedAtUtc ||
    !utc(value.completedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.outcomeSha256 !== objectSha256(body)
  ) {
    fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_INVALID');
  }
  validateCandidateActiveNoActionSnapshotCheckpoint({
    value: value.observations.before,
    sequence: 'BEFORE',
    candidateRecord,
    identity,
    expectedStackNames,
  });
  validateCandidateActiveNoActionSnapshotCheckpoint({
    value: value.observations.after,
    sequence: 'AFTER',
    candidateRecord,
    identity,
    expectedStackNames,
  });
  if (
    value.observations.before.stateSha256 !== value.observations.after.stateSha256 ||
    objectSha256(value.observations.before.state) !== objectSha256(value.observations.after.state)
  ) {
    fail('E7_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_SANDWICH_INVALID');
  }
  return value;
};

const validateEmergencyRecoveryNoActionOutcomeEvidence = ({
  value,
  map,
  previousManifest,
  candidateRecord,
  emergencyRecovery,
  identity,
  config,
}) => {
  const [, apiStack, , webStack] = expectedStage7Stacks(config.environment);
  return validateCandidateActiveNoActionOutcomeCheckpoint({
    value,
    previousManifest,
    candidateRecord,
    emergencyRecovery,
    identity,
    expectedSourceBindings: expectedEmergencyNoActionSourceBindings(map),
    expectedCallerBinding: expectedEmergencyNoActionCallerBinding({
      config,
      runId: String(process.env.GITHUB_RUN_ID ?? ''),
    }),
    expectedStackNames: { api: apiStack, web: webStack },
  });
};

const verifyCandidateActiveNoActionRecovery = async (flags) => {
  if (flags['emergency-recovery-no-action'] !== true) {
    fail('E7_EMERGENCY_RECOVERY_NO_ACTION_FLAG_REQUIRED');
  }
  const identity = candidateIdentity('full', { requireGitTag: true });
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const freezeManifest = requireCurrentFreeze(flags, 'full', identity, config);
  const previousManifest = validateStage7PreviousReleaseForTarget(
    readEvidence(requiredString(flags, 'previous-manifest')),
    { config, freezeManifest },
  );
  const candidateRecord = validateStage7CandidateRollbackRecord(
    readEvidence(requiredString(flags, 'candidate-record')),
    {
      previousManifest,
      approvalSha256: fileDigest(requiredString(flags, 'approval')),
      planSha256: fileDigest(requiredString(flags, 'approved-plan')),
      deploymentEvidenceSha256: fileDigest(requiredString(flags, 'deployment-evidence')),
    },
  );
  return validateCandidateActiveNoActionRecovery({
    value: readEvidence(requiredString(flags, 'emergency-recovery')),
    previousManifest,
    candidateRecord,
  });
};

const validateRecoverySmokeRunIdentity = ({
  recoveryActor,
  config,
  manifest,
  controlIdentity,
  environmentVariables,
  taggedCandidate,
}) => {
  const expectedRecoveryRun = {
    repository: environmentVariables.GITHUB_REPOSITORY,
    workflowPath: '.github/workflows/stage7-release-reconciliation-recovery.yml',
    workflowRef: environmentVariables.GITHUB_WORKFLOW_REF,
    ref: environmentVariables.GITHUB_REF,
    eventName: environmentVariables.GITHUB_EVENT_NAME,
    runId: environmentVariables.GITHUB_RUN_ID,
    runAttempt: Number(environmentVariables.GITHUB_RUN_ATTEMPT),
    actorId: environmentVariables.GITHUB_ACTOR_ID,
    controlSha: environmentVariables.GITHUB_SHA,
    protectedEnvironment: environmentVariables.STAGE7_PROTECTED_ENVIRONMENT,
    candidateSha: environmentVariables.STAGE7_RECOVERY_CANDIDATE_SHA,
  };
  const source = recoveryActor?.originalSource;
  if (
    Object.entries(expectedRecoveryRun).some(([key, value]) =>
      key === 'runAttempt'
        ? !Number.isSafeInteger(value) || value < 1
        : typeof value !== 'string' || value.length === 0,
    ) ||
    objectSha256(recoveryActor?.recoveryRun) !== objectSha256(expectedRecoveryRun) ||
    controlIdentity?.commitSha !== recoveryActor?.recoveryRun?.controlSha ||
    controlIdentity?.workingTree !== 'CLEAN' ||
    controlIdentity?.changedFiles !== 0 ||
    taggedCandidate !== source?.candidateSha ||
    source?.configSha256 !== objectSha256(config) ||
    manifest?.candidateSha !== source?.candidateSha ||
    manifest?.releaseId !== source?.releaseId ||
    manifest?.releaseTag !== source?.releaseTag ||
    manifest?.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    manifest?.environment !== config.environment ||
    manifest?.region !== config.aws.region ||
    manifest?.configSha256 !== source?.configSha256
  ) {
    fail('E7_RELEASE_RECONCILIATION_RECOVERY_SMOKE_IDENTITY_INVALID');
  }
  return {
    commitSha: source.candidateSha,
    treeSha: manifest.candidateTreeSha,
    workingTree: 'CLEAN',
    changedFiles: 0,
    candidateSha: source.candidateSha,
    releaseId: source.releaseId,
    releaseTag: source.releaseTag,
  };
};

const runVersionedRollbackReadSmoke = async (flags) => {
  const rollbackMode = flags['post-versioned-rollback'] === true;
  const repromotionMode = flags['post-versioned-repromotion'] === true;
  const reconciliationMode =
    flags['reconciliation-intent'] !== undefined ||
    flags['reconciliation-convergence'] !== undefined;
  const recoveryActorMode = flags['reconciliation-recovery-actor'] !== undefined;
  if (
    scopeOf(flags) !== 'full' ||
    Number(rollbackMode) + Number(repromotionMode) + Number(reconciliationMode) !== 1 ||
    (reconciliationMode &&
      (typeof flags['reconciliation-intent'] !== 'string' ||
        typeof flags['reconciliation-convergence'] !== 'string' ||
        (recoveryActorMode && typeof flags['reconciliation-recovery-actor'] !== 'string') ||
        flags.transition !== undefined ||
        flags['emergency-recovery'] !== undefined ||
        flags['rollback-evidence'] !== undefined)) ||
    (!reconciliationMode &&
      ((flags.transition === undefined) === (flags['emergency-recovery'] === undefined) ||
        flags['rollback-evidence'] === undefined ||
        flags['external-authorization-evidence'] !== undefined ||
        recoveryActorMode))
  ) {
    fail('E7_VERSIONED_ROLLBACK_SMOKE_FLAGS_INVALID');
  }
  const reconciliationIntent = reconciliationMode
    ? validateReleaseReconciliationIntent(
        readEvidence(requiredString(flags, 'reconciliation-intent')),
      )
    : undefined;
  const recoveryActor = recoveryActorMode
    ? validateReleaseReconciliationRecoveryActor(
        readEvidence(requiredString(flags, 'reconciliation-recovery-actor')),
        reconciliationIntent,
      )
    : undefined;
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  let identity;
  let manifest;
  if (recoveryActor === undefined) {
    identity = candidateIdentity('full', { requireGitTag: true });
    manifest = requireCurrentFreeze(flags, 'full', identity, config);
  } else {
    const controlIdentity = currentCandidate();
    const source = recoveryActor.originalSource;
    let taggedCandidate;
    try {
      taggedCandidate = execFileSync(
        'git',
        ['rev-parse', `refs/tags/${source.releaseTag}^{commit}`],
        {
          cwd: workspaceRoot,
          encoding: 'utf8',
          windowsHide: true,
        },
      ).trim();
    } catch {
      fail('E7_RELEASE_TAG_NOT_FOUND');
    }
    manifest = validateFreezeManifest(readEvidence(requiredString(flags, 'manifest')));
    identity = validateRecoverySmokeRunIdentity({
      recoveryActor,
      config,
      manifest,
      controlIdentity,
      environmentVariables: process.env,
      taggedCandidate,
    });
  }
  const previousManifest = validateStage7PreviousReleaseForTarget(
    readEvidence(requiredString(flags, 'previous-manifest')),
    { config, freezeManifest: manifest },
  );
  const candidateRecord = validateStage7CandidateRollbackRecord(
    readEvidence(requiredString(flags, 'candidate-record')),
    { previousManifest },
  );
  const mode = rollbackMode ? 'POST_ROLLBACK_VERSIONED' : 'POST_REPROMOTION_VERSIONED';
  let targetReleaseId;
  let reconciliation;
  let reconciliationUsageId;
  let reconciliationAuthorizationEvidence;
  if (reconciliationMode) {
    const intent = reconciliationIntent;
    const convergence = validateReleaseRuntimeConvergence(
      readEvidence(requiredString(flags, 'reconciliation-convergence')),
    );
    const expectedSource =
      recoveryActor?.originalSource ??
      Object.freeze({
        repository: process.env.GITHUB_REPOSITORY,
        workflowPath: '.github/workflows/release.yml',
        ref: process.env.GITHUB_REF,
        runId: process.env.GITHUB_RUN_ID,
        runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        releaseTag: identity.releaseTag,
        configSha256: objectSha256(config),
      });
    const binding = (label) => intent.bindings.find((entry) => entry.label === label);
    const externalAuthorizationFilename = requiredString(flags, 'external-authorization-evidence');
    reconciliationAuthorizationEvidence = readEvidence(externalAuthorizationFilename);
    if (
      objectSha256(intent.source) !== objectSha256(expectedSource) ||
      objectSha256(convergence.source) !== objectSha256(expectedSource) ||
      convergence.intent.intentSha256 !== intent.intentSha256 ||
      objectSha256(convergence.intent) !== objectSha256(intent) ||
      binding('config')?.rawSha256 !== fileDigest(process.env.STAGE7_CONFIG) ||
      binding('config')?.canonicalSha256 !== objectSha256(config) ||
      binding('candidateManifest')?.rawSha256 !== fileDigest(requiredString(flags, 'manifest')) ||
      binding('candidateManifest')?.canonicalSha256 !== objectSha256(manifest) ||
      binding('previousReleaseManifest')?.rawSha256 !==
        fileDigest(requiredString(flags, 'previous-manifest')) ||
      binding('previousReleaseManifest')?.canonicalSha256 !== objectSha256(previousManifest) ||
      binding('candidateRecord')?.rawSha256 !==
        fileDigest(requiredString(flags, 'candidate-record')) ||
      binding('candidateRecord')?.canonicalSha256 !== objectSha256(candidateRecord) ||
      binding('externalAuthorization')?.rawSha256 !== fileDigest(externalAuthorizationFilename) ||
      binding('externalAuthorization')?.canonicalSha256 !==
        objectSha256(reconciliationAuthorizationEvidence)
    ) {
      fail('E7_RELEASE_RECONCILIATION_SMOKE_BINDING_INVALID');
    }
    reconciliationUsageId =
      convergence.phase === 'ROLLBACK_CHECK'
        ? 'RECONCILIATION_ROLLBACK_CHECK_SMOKE'
        : convergence.phase === 'ROLLBACK_RESILIENCE'
          ? 'RECONCILIATION_ROLLBACK_RESILIENCE_SMOKE'
          : fail('E7_RELEASE_RECONCILIATION_SMOKE_PHASE_INVALID');
    reconciliation = {
      phase: convergence.phase,
      intentSha256: intent.intentSha256,
      convergenceSha256: convergence.convergenceSha256,
      convergenceCompletedAtUtc: convergence.completedAtUtc,
    };
    targetReleaseId = identity.releaseId;
  } else if (flags.transition !== undefined) {
    const rollbackEvidence = readEvidence(requiredString(flags, 'rollback-evidence'));
    const transition = readEvidence(flags.transition);
    const plan = rollbackMode
      ? rollbackEvidence?.checkpoints?.rollbackPlan
      : rollbackEvidence?.checkpoints?.repromotionPlan;
    validateStage7VersionedRollbackTransition(transition, {
      plan,
      previousManifest,
      candidateRecord,
    });
    const expectedDirection = rollbackMode ? 'ROLLBACK_TO_PREVIOUS' : 'REPROMOTE_CANDIDATE';
    if (transition.direction !== expectedDirection) fail('E7_VERSIONED_ROLLBACK_SMOKE_DIRECTION');
    targetReleaseId = transition.toReleaseId;
  } else {
    if (!rollbackMode) fail('E7_EMERGENCY_RECOVERY_SMOKE_MODE_INVALID');
    readEvidence(requiredString(flags, 'rollback-evidence'));
    validateEmergencyRecoveryForSmoke({
      value: readEvidence(flags['emergency-recovery']),
      previousManifest,
      candidateRecord,
    });
    targetReleaseId = previousManifest.previous.releaseId;
  }
  callerIdentityFor(config, config.aws.roles.readRoleArn);
  const target = webTarget(config, identity);
  const authority = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
  });
  if (
    reconciliationAuthorizationEvidence !== undefined &&
    (reconciliationAuthorizationEvidence.kind !== 'EXTERNAL_AUTHORIZATION_PREFLIGHT' ||
      reconciliationAuthorizationEvidence.status !== 'PASS' ||
      reconciliationAuthorizationEvidence.scope !== 'full' ||
      reconciliationAuthorizationEvidence.candidateSha !== identity.candidateSha ||
      reconciliationAuthorizationEvidence.releaseId !== identity.releaseId ||
      reconciliationAuthorizationEvidence.stage7ConfigSha256 !== objectSha256(config) ||
      reconciliationAuthorizationEvidence.authorizationSha256 !== objectSha256(authority.value) ||
      reconciliationAuthorizationEvidence.ownedOriginSha256 !== authority.originSha256 ||
      reconciliationAuthorizationEvidence.sandboxHostSha256 !== authority.sandboxHostSha256)
  ) {
    fail('E7_RELEASE_RECONCILIATION_SMOKE_AUTHORIZATION_INVALID');
  }
  const checks = [
    { id: 'RB-SMK-E7-V01', name: 'mutable-index', pathname: '/' },
    { id: 'RB-SMK-E7-V02', name: 'mutable-public-config', pathname: '/public-config.json' },
    { id: 'RB-SMK-E7-V03', name: 'api-readiness-through-viewer', pathname: '/api/health/ready' },
  ];
  const results = [];
  for (const check of checks) {
    const response = await fetchChecked(`${target.applicationOrigin}${check.pathname}`);
    const text = await boundedResponseText(response);
    let oracle;
    if (check.id === 'RB-SMK-E7-V01') {
      oracle =
        response.status === 200 &&
        /text\/html/iu.test(response.headers.get('content-type') ?? '') &&
        /<div[^>]+id=["']root["']/iu.test(text);
    } else {
      let parsed;
      try {
        parsed = JSON.parse(text);
      } catch {
        fail('E7_VERSIONED_ROLLBACK_SMOKE_JSON_INVALID');
      }
      oracle =
        check.id === 'RB-SMK-E7-V02'
          ? response.status === 200 &&
            exactKeys(parsed, ['apiBaseUrl', 'productId']) &&
            parsed.apiBaseUrl === '/api/v1' &&
            parsed.productId === 'product-demo-001'
          : response.status === 200 &&
            exactKeys(parsed, ['status', 'checkedAt']) &&
            parsed.status === 'ok' &&
            Number.isFinite(Date.parse(parsed.checkedAt ?? '')) &&
            /^[0-9a-f-]{36}$/u.test(response.headers.get('x-correlation-id') ?? '') &&
            /^no-store(?:,|$)/iu.test(response.headers.get('cache-control') ?? '');
    }
    if (!oracle) fail('E7_VERSIONED_ROLLBACK_SMOKE_ORACLE_FAILED');
    results.push({
      id: check.id,
      name: check.name,
      status: 'PASS',
      normalizedPath: check.pathname,
      observedStatus: response.status,
    });
  }
  if (authority.authorizations.ownedTarget.maxRequests < results.length) {
    fail('E7_EXTERNAL_AUTHORIZATION_REQUEST_LIMIT_EXCEEDED');
  }
  const usageIds = Object.fromEntries(
    externalAuthorizationRequirements('full').map(({ key, id }) => [key, id]),
  );
  const executedAtUtc = new Date().toISOString();
  if (
    reconciliation !== undefined &&
    Date.parse(executedAtUtc) < Date.parse(reconciliation.convergenceCompletedAtUtc)
  ) {
    fail('E7_RELEASE_RECONCILIATION_SMOKE_STALE');
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'DEPLOYED_BLACK_BOX_SMOKE',
    status: 'PASS',
    scope: 'full',
    mode,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    targetReleaseId,
    manifestSha256: manifest.manifestSha256,
    stage7ConfigSha256: objectSha256(config),
    targetOriginSha256: digest(target.applicationOrigin),
    executedAtUtc,
    reviewerAlias: smokeReviewer(),
    total: 3,
    passed: 3,
    failed: 0,
    results,
    requests: {
      total: 3,
      ownedOrigin: 3,
      provider: 0,
      production: 0,
      outsideAllowlist: 0,
    },
    syntheticDataOnly: true,
    dataMutations: 0,
    externalAuthorization: {
      authorizationSha256: objectSha256(authority.value),
      authorizationIds: externalAuthorizationRequirements('full').map(({ id }) => id),
      ownedOriginSha256: authority.originSha256,
      sandboxHostSha256: authority.sandboxHostSha256,
    },
    authorizationUsage: authorizationUsage({
      scope: 'full',
      authority,
      identity,
      config,
      usageId: reconciliationUsageId ?? mode,
      requestCounts: { [usageIds.ownedTarget]: 3, [usageIds.sandboxSmoke]: 0 },
    }),
    ...(reconciliation === undefined ? {} : { reconciliation }),
    ...(recoveryActor === undefined
      ? {}
      : { reconciliationRecoveryActorSha256: recoveryActor.actorSha256 }),
    externalRequests: 3,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await writeStage7Json(
    requiredString(flags, 'evidence'),
    `stage7-${mode.toLowerCase()}.json`,
    result,
  );
};

const smokeInputsPreflight = async (flags) => {
  const scope = scopeOf(flags);
  if (
    scope !== 'full' ||
    flags['smoke-inputs'] !== true ||
    flags['approved-environment'] !== true ||
    process.env.STAGE7_PROTECTED_ENVIRONMENT !== 'assessment-release'
  ) {
    fail('E7_SMOKE_INPUT_PREFLIGHT_PROTECTED_ENVIRONMENT_REQUIRED');
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope, { requireGitTag: true });
  const manifest = requireCurrentFreeze(flags, scope, identity, config);
  const target = authorizationTarget(scope, requiredString(flags, 'deployment'), config, identity);
  const external = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
    ...(scope === 'prerelease' ? { deployedApiOrigin: target.apiOrigin } : {}),
  });
  const inputs = readPrivateSmokeInputs({
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    configSha256: objectSha256(config),
    now: new Date(),
  });
  const evidenceBasename = path.basename(requiredString(flags, 'evidence'));
  const usageId =
    evidenceBasename === 'smoke-input-preflight.json'
      ? 'SMOKE_INPUT_PREFLIGHT_CANDIDATE'
      : evidenceBasename === 'rollback-smoke-input-preflight.json'
        ? 'ROLLBACK_PENDING_INPUT_PREFLIGHT'
        : fail('E7_SMOKE_INPUT_PREFLIGHT_EVIDENCE_NAME_INVALID');
  await emitJson(
    {
      schemaVersion: 1,
      stage: 7,
      kind: 'PRIVATE_SMOKE_INPUT_PREFLIGHT',
      status: 'PASS',
      scope,
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      manifestSha256: manifest.manifestSha256,
      configSha256: objectSha256(config),
      targetOriginSha256: digest(target.applicationOrigin),
      authorizationSha256: objectSha256(external.value),
      authorizationUsage: authorizationUsage({
        scope,
        authority: external,
        identity,
        config,
        usageId,
      }),
      classification: inputs.classification,
      providerHostSha256: digest(inputs.providerHost),
      scenarios: ['approved', 'failed', 'pending'],
      decision:
        evidenceBasename === 'smoke-input-preflight.json'
          ? 'READY_FOR_CANDIDATE_ACTIVATION_SMOKE'
          : 'READY_FOR_VERSIONED_ROLLBACK_PENDING_CANARY',
      externalRequests: 0,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    },
    flags.evidence,
    'stage7-smoke-input-preflight.json',
  );
};

const qualityRelease = async (flags) => {
  const scope = scopeOf(flags);
  if (
    scope !== 'full' ||
    flags['approved-environment'] !== true ||
    process.env.STAGE7_PROTECTED_ENVIRONMENT !== 'assessment-release'
  ) {
    fail('E7_QUALITY_PROTECTED_ENVIRONMENT_REQUIRED');
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope, { requireGitTag: true });
  const manifest = requireCurrentFreeze(flags, scope, identity, config);
  const target = authorizationTarget(scope, requiredString(flags, 'deployment'), config, identity);
  const external = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
    ...(scope === 'prerelease' ? { deployedApiOrigin: target.apiOrigin } : {}),
  });
  const output = path.join(evidenceRoot(scope), 'quality.json');
  try {
    const payload = await runDeployedQuality({
      origin: target.applicationOrigin,
      authorization: external.authorizations,
      workspaceRoot,
    });
    validateQualityPayload(payload);
    const passiveAuthorizationId = externalAuthorizationRequirements(scope).find(
      ({ key }) => key === 'passiveSecurity',
    )?.id;
    if (passiveAuthorizationId === undefined) fail('E7_QUALITY_AUTHORIZATION_INVALID');
    const result = {
      schemaVersion: 1,
      stage: 7,
      kind: 'DEPLOYED_FOCAL_QUALITY',
      status: 'PASS',
      scope,
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      manifestSha256: manifest.manifestSha256,
      configSha256: objectSha256(config),
      targetOriginSha256: digest(target.applicationOrigin),
      authorizationSha256: objectSha256(external.value),
      authorizationUsage: authorizationUsage({
        scope,
        authority: external,
        identity,
        config,
        usageId: 'QUALITY_FOCAL',
        requestCounts: { [passiveAuthorizationId]: payload.requests.ownedOrigin },
      }),
      evidenceIds: ['EVD-E7-42', 'EVD-E7-43', 'EVD-E7-44'],
      ...payload,
      externalRequests: payload.requests.ownedOrigin,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    await emitJson(result, output, 'stage7-quality.json');
    process.stdout.write('stage-7 deployed quality: PASS (3 browsers, axe, Lighthouse 3/3)\n');
  } catch (error) {
    await writeStage7Json(output, 'stage7-quality-failed.json', {
      schemaVersion: 1,
      stage: 7,
      kind: 'DEPLOYED_FOCAL_QUALITY',
      status: 'FAIL',
      scope,
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      reason:
        error instanceof Stage7QualityError || error instanceof Stage7ControlError
          ? error.code
          : 'E7_QUALITY_UNEXPECTED_FAILURE',
      externalRequests: 'UNKNOWN_BOUNDED_BY_AUTHORIZATION',
      mutationsPerformed: 0,
      containsSensitiveData: false,
    });
    throw error;
  }
};

const sandboxSmokeRelease = async (flags) => {
  const scope = scopeOf(flags);
  if (
    flags['approved-environment'] !== true ||
    process.env.CONFIRM_SANDBOX_SMOKE !== 'true' ||
    (scope === 'prerelease' && flags['non-public'] !== true) ||
    (scope === 'full' && flags['non-public'] !== undefined)
  ) {
    fail('E7_SANDBOX_PROTECTED_EXECUTION_REQUIRED');
  }
  const expectedEnvironment =
    scope === 'full' ? 'assessment-release' : 'assessment-prerelease-external';
  if (process.env.STAGE7_PROTECTED_ENVIRONMENT !== expectedEnvironment) {
    fail('E7_SANDBOX_PROTECTED_ENVIRONMENT_MISMATCH');
  }
  let prereleaseSafety = null;
  if (scope === 'prerelease') {
    prereleaseSafety = await validateControlPrereleaseSafety({
      flags,
      expectedProtectedEnvironment: 'assessment-prerelease-external',
      deploymentPhase: 'before-activation',
      livePhase: 'sandbox',
      authorityPhase: 'sandbox',
    });
  }
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  if (config.authorization.sandboxIncluded !== true) {
    fail('E7_SANDBOX_AUTHORIZATION_REQUIRED');
  }
  const identity = candidateIdentity(scope, { requireGitTag: scope === 'full' });
  const manifest = requireCurrentFreeze(flags, scope, identity, config);
  const target = authorizationTarget(scope, requiredString(flags, 'deployment'), config, identity);
  const external = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
    ...(scope === 'prerelease' ? { deployedApiOrigin: target.apiOrigin } : {}),
  });
  const sourcePath = process.env.STAGE6_SANDBOX_AUTHORIZATION;
  if (typeof sourcePath !== 'string' || sourcePath.trim() === '') {
    fail('E7_STAGE6_SANDBOX_AUTHORIZATION_REQUIRED');
  }
  const schemaPath = path.join(
    workspaceRoot,
    'scripts/stage6/sandbox-authorized/authorization.schema.json',
  );
  let stage6Context;
  let executionClaim;
  try {
    stage6Context = loadAuthorizationContext({
      repositoryRoot: workspaceRoot,
      schemaPath,
      sourcePath,
      now: new Date(),
      expectedCommitSha: identity.candidateSha,
    });
    validateSandboxAuthorizationBridge({
      stage6Authorization: stage6Context.authorization,
      externalAuthorization: external.authorizations.sandboxSmoke,
      candidateSha: identity.candidateSha,
    });
    executionClaim = validateSandboxExecutionClaim({
      environment: process.env,
      scope,
      now: new Date(),
    });
    validateRequiredEnvironment(process.env, stage6Context.authorization);
  } catch (error) {
    if (error instanceof Stage7ControlError) throw error;
    fail('E7_STAGE6_SANDBOX_AUTHORIZATION_INVALID');
  }

  const execution = spawnSync(
    process.execPath,
    [path.join(workspaceRoot, 'scripts/stage6/sandbox-authorized/run.mjs'), '--execute'],
    {
      cwd: workspaceRoot,
      env: { ...process.env, STAGE6_SANDBOX_AUTHORIZATION: stage6Context.sourcePath },
      encoding: 'utf8',
      maxBuffer: 512 * 1024,
      timeout: 100_000,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    },
  );
  if (
    execution.status !== 0 ||
    execution.signal !== null ||
    execution.error !== undefined ||
    execution.stderr.trim() !== ''
  ) {
    fail('E7_SANDBOX_RUNNER_FAILED');
  }
  const lines = execution.stdout.trim().split(/\r?\n/u);
  if (lines.length !== 1 || lines[0].length < 2) fail('E7_SANDBOX_RUNNER_OUTPUT_INVALID');
  let raw;
  try {
    assertSanitizedArtifactText('stage7-stage6-sandbox-raw.json', lines[0]);
    raw = parseStrictJsonSource(Buffer.from(lines[0]), { scanForbiddenData: false });
  } catch {
    fail('E7_SANDBOX_RUNNER_OUTPUT_INVALID');
  }
  const runnerTemp = process.env.RUNNER_TEMP;
  if (typeof runnerTemp !== 'string' || runnerTemp.trim() === '') {
    fail('E7_SANDBOX_PRIVATE_RUNTIME_REQUIRED');
  }
  const rawPath = path.join(runnerTemp, `stage7-sandbox-raw-${process.pid}.json`);
  try {
    writePrivateTextAtomic(rawPath, `${lines[0]}\n`);
    const ingestedByRunId =
      raw.runId === 'e6-19700101t000000z-00000000'
        ? 'e6-19700101t000001z-00000001'
        : 'e6-19700101t000000z-00000000';
    await loadExternalEvidence({
      sourcePath: rawPath,
      commitSha: identity.candidateSha,
      ingestedByRunId,
    });
  } catch (error) {
    if (error instanceof Stage7ControlError) throw error;
    fail('E7_SANDBOX_RUNNER_CONTRACT_INVALID');
  } finally {
    rmSync(rawPath, { force: true });
  }
  const after = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
    ...(scope === 'prerelease' ? { deployedApiOrigin: target.apiOrigin } : {}),
  });
  let stage6After;
  try {
    stage6After = loadAuthorizationContext({
      repositoryRoot: workspaceRoot,
      schemaPath,
      sourcePath: stage6Context.sourcePath,
      now: new Date(),
      expectedCommitSha: identity.candidateSha,
    });
  } catch {
    fail('E7_STAGE6_SANDBOX_AUTHORIZATION_CHANGED');
  }
  if (
    objectSha256(after.value) !== objectSha256(external.value) ||
    stage6After.sourceSha256 !== stage6Context.sourceSha256
  ) {
    fail('E7_SANDBOX_AUTHORIZATION_CHANGED_DURING_RUN');
  }
  const capability = raw?.capabilities?.sandboxSmoke;
  if (
    raw?.schemaId !== 'async-checkout-stage6-external-evidence' ||
    raw?.stage !== 6 ||
    raw?.commitSha !== identity.candidateSha ||
    capability?.status !== 'PASS' ||
    objectSha256(capability.authorization) !==
      objectSha256(stage6Context.authorization.authorization) ||
    capability?.requests?.total !== 7 ||
    capability?.requests?.production !== 0 ||
    capability?.requests?.outsideAllowlist !== 0 ||
    capability?.result?.duplicateEffects !== 0
  ) {
    fail('E7_SANDBOX_RUNNER_CONTRACT_INVALID');
  }
  let consumedExecutionClaim;
  try {
    consumedExecutionClaim = revalidateConsumedSandboxExecutionClaim({
      environment: process.env,
      scope,
      expectedClaimSha256: executionClaim.claimSha256,
      expectedBindingSha256: executionClaim.bindingSha256,
      expectedReferenceSha256: capability.reference.sha256,
      now: new Date(),
    });
  } catch {
    fail('E7_SANDBOX_EXECUTION_CLAIM_INVALID');
  }
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'AUTHORIZED_SANDBOX_SMOKE',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    manifestSha256: manifest.manifestSha256,
    stage7ConfigSha256: objectSha256(config),
    executedAtUtc: raw.executedAtUtc,
    reviewerAlias: raw.reviewerAlias,
    targetOriginSha256: external.originSha256,
    sandboxHostSha256: external.sandboxHostSha256,
    externalAuthorization: {
      authorizationSha256: objectSha256(after.value),
      authorization: after.authorizations.sandboxSmoke,
    },
    authorizationUsage: authorizationUsage({
      scope,
      authority: after,
      identity,
      config,
      usageId: 'SANDBOX_ONE_USE',
      requestCounts: {
        [externalAuthorizationRequirements(scope).find(({ key }) => key === 'sandboxSmoke').id]:
          capability.requests.total,
      },
    }),
    stage6Authorization: {
      authorizationId: 'AUTH-E6-02',
      authorizationSha256: stage6Context.sourceSha256,
      runId: raw.runId,
      fixtureSha256: stage6Context.authorization.fixture.cardNumberSha256,
      rawFixtureCaptured: false,
    },
    oneUseExecution: sanitizedSandboxExecutionBinding(consumedExecutionClaim),
    checks: capability.checks,
    referenceSha256: capability.reference.sha256,
    requests: capability.requests,
    result: capability.result,
    productionRequests: 0,
    duplicateEffects: 0,
    stage6Capability: scope === 'prerelease' ? { sandboxSmoke: capability } : undefined,
    ...(prereleaseSafety === null
      ? {}
      : {
          watchdogLiveAuthoritySha256:
            prereleaseSafety.watchdogLiveAuthority.watchdogLiveAuthoritySha256,
          watchdogDefaultBranchHeadSha256:
            prereleaseSafety.watchdogLiveAuthority.defaultBranchHeadSha256,
          watchdogApiRequests: prereleaseSafety.watchdogLiveAuthority.apiRequests,
          watchdogVerifiedAtUtc: prereleaseSafety.watchdogLiveAuthority.verifiedAtUtc,
          watchdogVerificationPhase: prereleaseSafety.watchdogLiveAuthority.phase,
        }),
    externalRequests: capability.requests.total,
    mutationsPerformed: capability.requests.transactionCreates,
    containsSensitiveData: false,
  };
  await writeStage7Json(
    path.join(evidenceRoot(scope), 'sandbox-smoke.json'),
    'stage7-authorized-sandbox-smoke.json',
    result,
  );
  process.stdout.write('stage-7 authorized sandbox smoke: PASS (7 bounded requests)\n');
};

const checkedCapabilityDocument = (directory, basename, key, identity, config) => {
  const document = readEvidence(findExactlyOne(directory, basename));
  const capability = document?.stage6Capability?.[key];
  if (
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.status !== 'PASS' ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.stage7ConfigSha256 !== objectSha256(config) ||
    !utc(document.executedAtUtc) ||
    !/^[a-z][a-z0-9-]{2,31}$/u.test(document.reviewerAlias ?? '') ||
    !object(capability) ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_STAGE6_CAPABILITY_SOURCE_INVALID');
  }
  if (key === 'sandboxSmoke') {
    try {
      validateSandboxExecutionEvidence(document.oneUseExecution, {
        scope: 'prerelease',
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        configSha256: objectSha256(config),
        referenceSha256: capability.reference?.sha256,
        stage6AuthorizationSha256: document.stage6Authorization?.authorizationSha256,
      });
    } catch {
      fail('E7_SANDBOX_EXECUTION_CLAIM_INVALID');
    }
  }
  return { capability, document };
};

const externalRunId = (executedAtUtc, sourceSha256) => {
  const date = executedAtUtc.slice(0, 10).replaceAll('-', '');
  const time = executedAtUtc.slice(11, 19).replaceAll(':', '');
  return `e6-${date}t${time}z-${sourceSha256.slice(0, 8)}`;
};

const emitStage6ExternalRaw = async (flags) => {
  const scope = scopeOf(flags);
  if (scope !== 'prerelease' || flags['forbid-e7-pass'] !== true) {
    fail('E7_STAGE6_RAW_SCOPE_INVALID');
  }
  if (process.env.SANDBOX_EXECUTED !== 'true') fail('E7_SANDBOX_EXECUTION_REQUIRED');
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope);
  const directory = requiredString(flags, 'external-checks');
  const owned = checkedCapabilityDocument(
    directory,
    'external-uat.json',
    'ownedTarget',
    identity,
    config,
  );
  const sandbox = checkedCapabilityDocument(
    directory,
    'sandbox-smoke.json',
    'sandboxSmoke',
    identity,
    config,
  );
  const passive = checkedCapabilityDocument(
    directory,
    'edge-security.json',
    'passiveSecurity',
    identity,
    config,
  );
  const documents = [owned.document, sandbox.document, passive.document];
  if (new Set(documents.map(({ reviewerAlias }) => reviewerAlias)).size !== 1) {
    fail('E7_STAGE6_CAPABILITY_REVIEWER_MISMATCH');
  }
  if (
    owned.capability.target?.originSha256 !== passive.capability.target?.originSha256 ||
    sandbox.capability.target?.hostSha256 !== digest('sandbox.wompi.co')
  ) {
    fail('E7_STAGE6_CAPABILITY_TARGET_MISMATCH');
  }
  const authorization = validateExternalAuthorizations({
    value: externalAuthorizationFile(),
    config,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    deployedOriginSha256: owned.capability.target.originSha256,
    deployedApiOriginSha256: owned.document.accessGate?.apiOriginSha256,
  });
  for (const [key, capability] of [
    ['ownedTarget', owned.capability],
    ['sandboxSmoke', sandbox.capability],
    ['passiveSecurity', passive.capability],
  ]) {
    if (
      objectSha256(capability.authorization) !== objectSha256(authorization.authorizations[key])
    ) {
      fail('E7_STAGE6_CAPABILITY_AUTHORIZATION_MISMATCH');
    }
  }
  const executedAtUtc = documents
    .map(({ executedAtUtc: value }) => value)
    .sort(stableCompare)
    .at(-1);
  const capabilities = {
    ownedTarget: owned.capability,
    sandboxSmoke: sandbox.capability,
    passiveSecurity: passive.capability,
  };
  const capabilitySha256 = objectSha256(capabilities);
  const raw = {
    schemaId: 'async-checkout-stage6-external-evidence',
    schemaVersion: 1,
    stage: 6,
    protocolVersion: '1.0.0',
    protocolDocumentSha256: fileDigest(
      path.join(workspaceRoot, 'docs/verification/external-evidence.md'),
    ),
    commitSha: identity.candidateSha,
    runId: externalRunId(executedAtUtc, capabilitySha256),
    executedAtUtc,
    reviewerAlias: documents[0].reviewerAlias,
    capabilities,
    containsSensitiveData: false,
  };
  const target = flags['emit-stage6-external-raw'] ?? flags['emit-stage6-external'];
  if (typeof target !== 'string') fail('E7_STAGE6_RAW_OUTPUT_REQUIRED');
  await writeStage7Json(target, 'stage6-external-evidence.json', raw);
  try {
    const ingestedByRunId =
      raw.runId === 'e6-19700101t000000z-00000000'
        ? 'e6-19700101t000001z-00000001'
        : 'e6-19700101t000000z-00000000';
    await loadExternalEvidence({
      sourcePath: target,
      commitSha: identity.candidateSha,
      ingestedByRunId,
    });
  } catch {
    rmSync(path.resolve(target), { force: true });
    fail('E7_STAGE6_RAW_CONTRACT_INVALID');
  }
  process.stdout.write('stage-7 external evidence: PASS (raw Stage 6 schema v1)\n');
};

const evidenceFileMap = (directory, scope) => {
  if (!['full', 'prerelease'].includes(scope)) fail('E7_EVIDENCE_SCOPE_INVALID');
  const map = new Map();
  for (const file of walkFiles(directory).files) {
    const basename = path.basename(file.relative);
    if (!basename.endsWith('.json') && basename !== 'infra-diff.txt') continue;
    if (map.has(basename)) fail('E7_EVIDENCE_BASENAME_DUPLICATE');
    const producer = STAGE7_SOURCE_PRODUCERS[scope][basename];
    if (producer !== undefined) {
      const expectedRelative = `${producer.artifactName}/${basename}`;
      if (file.relative.replaceAll('\\', '/') !== expectedRelative) {
        fail('E7_EVIDENCE_PRODUCER_PATH_INVALID');
      }
    }
    map.set(basename, file.absolute);
  }
  return map;
};

const passEvidence = (map, basename, identity) => {
  const filename = map.get(basename);
  if (filename === undefined) fail('E7_REQUIRED_EVIDENCE_MISSING');
  if (basename === 'candidate-manifest.json') {
    const manifest = validateFreezeManifest(readEvidence(filename));
    if (
      manifest.candidateSha !== identity.candidateSha ||
      manifest.releaseId !== identity.releaseId
    ) {
      fail('E7_REQUIRED_EVIDENCE_IDENTITY_MISMATCH');
    }
    return manifest;
  }
  const document = readEvidence(filename);
  if (
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.status !== 'PASS' ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_REQUIRED_EVIDENCE_NOT_PASS');
  }
  return document;
};

const operationEvidence = (map, basename, checkpointName, identity, config) => {
  const filename = map.get(basename);
  if (filename === undefined) fail('E7_REQUIRED_EVIDENCE_MISSING');
  const document = readEvidence(filename);
  if (
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.status !== 'IN_PROGRESS' ||
    document.environment !== config.environment ||
    document.authorizationId !== config.authorization.id ||
    document.authorizationScope !== config.authorization.scope ||
    document.configSha256 !== objectSha256(config) ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.containsSensitiveData !== false ||
    !object(document.checkpoints?.[checkpointName])
  ) {
    fail('E7_OPERATION_EVIDENCE_INVALID');
  }
  return document;
};

const deployedCheckpoint = (document, key, suffix, identity, config, manifest) => {
  const checkpoint = document.checkpoints[key];
  const iacArtifact = manifest.artifacts.find(({ name }) => name === 'iac');
  if (
    checkpoint.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    checkpoint.releaseMode !== 'VERSIONED_UPDATE' ||
    !SHA256.test(checkpoint.previousReleaseManifestSha256 ?? '') ||
    checkpoint.stackName !== `checkout-${config.environment}-${suffix}` ||
    checkpoint.freezeManifestSha256 !== manifest.manifestSha256 ||
    checkpoint.deploymentMethod !== 'CLOUDFORMATION_CHANGE_SET' ||
    checkpoint.hotswapUsed !== false ||
    checkpoint.outputs?.CandidateSha !== identity.candidateSha ||
    checkpoint.outputs?.ReleaseId !== identity.releaseId ||
    checkpoint.assemblySha256 !== iacArtifact?.sha256 ||
    checkpoint.outputsSha256 !== digest(JSON.stringify(checkpoint.outputs)) ||
    !exactKeys(checkpoint.approvedPlan, [
      'approvalSha256',
      'planSha256',
      'preDeploymentStateSha256',
    ]) ||
    !Object.values(checkpoint.approvedPlan).every((value) => SHA256.test(value ?? ''))
  ) {
    fail('E7_DEPLOYMENT_CHECKPOINT_INVALID');
  }
  return checkpoint;
};

const budgetContract = (config) =>
  `${config.budget.maxUsd.toFixed(2)}:${config.budget.warningUsd
    .map((amount) => amount.toFixed(2))
    .join(',')}`;

const validateAuthorizationLedger = ({
  authorization,
  usages,
  identity,
  config,
  expectedUsageIds,
  reservations = [],
  expectedReservationIds = [],
}) => {
  const ids = externalAuthorizationRequirements('full').map(({ id }) => id);
  if (
    !exactKeys(authorization.requestLimits, ids) ||
    !SHA256.test(authorization.authorizationSha256 ?? '') ||
    !SHA256.test(authorization.ownedOriginSha256 ?? '') ||
    !SHA256.test(authorization.sandboxHostSha256 ?? '') ||
    !Array.isArray(usages) ||
    usages.length !== expectedUsageIds.length ||
    !Array.isArray(reservations) ||
    reservations.length !== expectedReservationIds.length
  ) {
    fail('E7_AUTHORIZATION_LEDGER_INVALID');
  }
  const seen = new Set();
  const totals = Object.fromEntries(ids.map((id) => [id, 0]));
  const reservedTotals = Object.fromEntries(ids.map((id) => [id, 0]));
  const consume = (usage, target) => {
    if (
      !exactKeys(usage, [
        'schemaVersion',
        'usageId',
        'bundleSha256',
        'candidateSha',
        'releaseId',
        'configSha256',
        'ownedOriginSha256',
        'sandboxHostSha256',
        'requestCounts',
      ]) ||
      usage.schemaVersion !== 1 ||
      seen.has(usage.usageId) ||
      usage.bundleSha256 !== authorization.authorizationSha256 ||
      usage.candidateSha !== identity.candidateSha ||
      usage.releaseId !== identity.releaseId ||
      usage.configSha256 !== objectSha256(config) ||
      usage.ownedOriginSha256 !== authorization.ownedOriginSha256 ||
      usage.sandboxHostSha256 !== authorization.sandboxHostSha256 ||
      !exactKeys(usage.requestCounts, ids)
    ) {
      fail('E7_AUTHORIZATION_LEDGER_INVALID');
    }
    seen.add(usage.usageId);
    for (const id of ids) {
      const count = usage.requestCounts[id];
      if (!Number.isSafeInteger(count) || count < 0) fail('E7_AUTHORIZATION_LEDGER_INVALID');
      target[id] += count;
    }
  };
  for (const usage of usages) consume(usage, totals);
  const seenUsageIds = [...seen];
  for (const reservation of reservations) consume(reservation, reservedTotals);
  const seenReservationIds = [...seen].filter((usageId) => !seenUsageIds.includes(usageId));
  const committedTotals = Object.fromEntries(
    ids.map((id) => [id, totals[id] + reservedTotals[id]]),
  );
  const limitsValid = ids.every(
    (id) =>
      Number.isSafeInteger(authorization.requestLimits[id]) && authorization.requestLimits[id] >= 1,
  );
  const usageSetValid =
    [...seenUsageIds].sort(stableCompare).join('\0') ===
    [...expectedUsageIds].sort(stableCompare).join('\0');
  const reservationSetValid =
    [...seenReservationIds].sort(stableCompare).join('\0') ===
    [...expectedReservationIds].sort(stableCompare).join('\0');
  if (
    !usageSetValid ||
    !reservationSetValid ||
    !limitsValid ||
    ids.some((id) => committedTotals[id] > authorization.requestLimits[id])
  ) {
    fail('E7_AUTHORIZATION_LEDGER_LIMIT_EXCEEDED');
  }
  return {
    totals,
    reservedTotals,
    committedTotals,
    limits: authorization.requestLimits,
    remaining: Object.fromEntries(
      ids.map((id) => [id, authorization.requestLimits[id] - totals[id]]),
    ),
    remainingAfterReservations: Object.fromEntries(
      ids.map((id) => [id, authorization.requestLimits[id] - committedTotals[id]]),
    ),
    usageIds: seenUsageIds.sort(stableCompare),
    reservationIds: seenReservationIds.sort(stableCompare),
  };
};

const validateAuthorizationBudgetPlan = ({ authorization, identity, config }) => {
  let plan;
  try {
    plan = validateFullExternalRequestBudgetPlan(authorization.externalRequestBudgetPlan);
  } catch (error) {
    if (error instanceof Stage7ExternalRequestBudgetError) {
      fail('E7_EXTERNAL_REQUEST_BUDGET_PLAN_INVALID');
    }
    throw error;
  }
  if (
    plan.candidateSha !== identity.candidateSha ||
    plan.releaseId !== identity.releaseId ||
    plan.configSha256 !== objectSha256(config) ||
    plan.authorizationSha256 !== authorization.authorizationSha256 ||
    plan.ownedOriginSha256 !== authorization.ownedOriginSha256 ||
    plan.sandboxHostSha256 !== authorization.sandboxHostSha256 ||
    objectSha256(plan.requestLimits) !== objectSha256(authorization.requestLimits)
  ) {
    fail('E7_EXTERNAL_REQUEST_BUDGET_PLAN_INVALID');
  }
  return plan;
};

const validateAuthorizationBudgetCheckpoint = ({ plan, usages, phase }) => {
  try {
    return validateFullExternalRequestBudgetCheckpoint({ plan, usages, phase });
  } catch (error) {
    if (error instanceof Stage7ExternalRequestBudgetError) {
      fail('E7_EXTERNAL_REQUEST_BUDGET_CHECKPOINT_INVALID');
    }
    throw error;
  }
};

const reconciliationAuthorizationLedgerUsage = ({ usage, phase, source }) => {
  try {
    validateReleaseReconciliationSmokeAuthorizationUsage(usage, { phase, source });
  } catch (error) {
    if (error instanceof Stage7ReleaseReconciliationError) {
      fail('E7_RELEASE_RECONCILIATION_AUTHORIZATION_USAGE_INVALID');
    }
    throw error;
  }
  if (usage.authorizationSha256 !== usage.bundleSha256) {
    fail('E7_RELEASE_RECONCILIATION_AUTHORIZATION_USAGE_INVALID');
  }
  return {
    schemaVersion: usage.schemaVersion,
    usageId: usage.usageId,
    bundleSha256: usage.bundleSha256,
    candidateSha: usage.candidateSha,
    releaseId: usage.releaseId,
    configSha256: usage.configSha256,
    ownedOriginSha256: usage.ownedOriginSha256,
    sandboxHostSha256: usage.sandboxHostSha256,
    requestCounts: { ...usage.requestCounts },
  };
};

const validatePreviousReleaseReadiness = ({
  value,
  previousManifest,
  config,
  freezeManifest,
  targetAssemblySha256,
}) => {
  try {
    validateStage7PreviousReleaseForTarget(previousManifest, { config, freezeManifest });
  } catch (error) {
    if (error instanceof Stage7Error) fail('E7_PREVIOUS_RELEASE_READINESS_TARGET_INVALID');
    throw error;
  }
  const targetIac = freezeManifest.artifacts.find(({ name }) => name === 'iac');
  const expectedMutableObjectKeys = previousManifest.resources.web.objects.map(({ key }) => key);
  const expectedApiAliasSha256 = digest(
    `${previousManifest.resources.api.functionName}:${previousManifest.resources.api.aliasName}`,
  );
  const expectedWorkerAliasSha256 = digest(
    `${previousManifest.resources.worker.functionName}:${previousManifest.resources.worker.aliasName}`,
  );
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'decision',
      'previousReleaseManifestSha256',
      'previousReleaseId',
      'targetReleaseId',
      'previousAssemblySha256',
      'targetAssemblySha256',
      'mutableObjectKeys',
      'apiAliasSha256',
      'workerAliasSha256',
      'versionedRollbackExecutionEnabled',
      'blockingIssue',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'PREVIOUS_RELEASE_LOCAL_PREFLIGHT' ||
    value.decision !== 'READY_FOR_VERSIONED_UPDATE' ||
    value.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    value.previousReleaseId !== previousManifest.previous.releaseId ||
    value.targetReleaseId !== previousManifest.target.releaseId ||
    value.previousAssemblySha256 !== previousManifest.previous.assemblySha256 ||
    value.targetAssemblySha256 !== previousManifest.target.assemblySha256 ||
    value.targetAssemblySha256 !== targetIac?.sha256 ||
    value.targetAssemblySha256 !== targetAssemblySha256 ||
    value.mutableObjectKeys?.join('\0') !== expectedMutableObjectKeys.join('\0') ||
    value.apiAliasSha256 !== expectedApiAliasSha256 ||
    value.workerAliasSha256 !== expectedWorkerAliasSha256 ||
    value.versionedRollbackExecutionEnabled !== true ||
    value.blockingIssue !== null ||
    value.externalRequests !== 0 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_PREVIOUS_RELEASE_READINESS_INVALID');
  }
  return value;
};

const validateVersionedTransitionEvidenceSet = ({
  map,
  prefix,
  direction,
  plan,
  embeddedCheckpoint,
  previousManifest,
  candidateRecord,
}) => {
  const transitionBasename = `versioned-${prefix}-aws-transition.json`;
  const smokeBasename = `versioned-${prefix}-smoke.json`;
  const checkpointBasename = `versioned-${prefix}-checkpoint.json`;
  const transition = readEvidence(map.get(transitionBasename));
  const smoke = readEvidence(map.get(smokeBasename));
  const checkpoint = readEvidence(map.get(checkpointBasename));
  try {
    validateStage7VersionedRollbackTransition(transition, {
      plan,
      previousManifest,
      candidateRecord,
    });
    validateStage7VersionedRollbackCheckpoint(checkpoint, {
      plan,
      previousManifest,
      candidateRecord,
    });
  } catch (error) {
    if (error instanceof Stage7Error) fail('E7_VERSIONED_TRANSITION_EVIDENCE_INVALID');
    throw error;
  }
  const expectedScenarioIds =
    direction === 'ROLLBACK_TO_PREVIOUS'
      ? ['RB-E7-01', 'RB-E7-03', 'RB-E7-05', 'RB-E7-07']
      : ['RB-E7-02', 'RB-E7-04', 'RB-E7-05', 'RB-E7-07'];
  const transitionBody = { ...transition };
  delete transitionBody.transitionSha256;
  const expectedCheckpointBody = {
    ...transitionBody,
    kind: 'VERSIONED_ROLLBACK_CHECKPOINT',
    status: 'PASS',
    scenarioIds: expectedScenarioIds,
    smoke: {
      status: 'PASS',
      releaseId: transition.toReleaseId,
      evidenceSha256: fileDigest(map.get(smokeBasename)),
    },
  };
  const expectedCheckpoint = {
    ...expectedCheckpointBody,
    checkpointSha256: objectSha256(expectedCheckpointBody),
  };
  if (
    transition.direction !== direction ||
    objectSha256(checkpoint) !== objectSha256(expectedCheckpoint) ||
    objectSha256(checkpoint) !== objectSha256(embeddedCheckpoint)
  ) {
    fail('E7_VERSIONED_TRANSITION_EVIDENCE_BINDING_INVALID');
  }
  return { transition, smoke, checkpoint };
};

const assertFullEvidence = (map, identity, config, resilienceAssemblyDirectory) => {
  if (REQUIRED_FULL_EVIDENCE.some((basename) => map.get(basename) === undefined)) {
    fail('E7_REQUIRED_EVIDENCE_MISSING');
  }
  const passNames = REQUIRED_FULL_EVIDENCE.filter(
    (basename) => !FULL_COMPLEX_EVIDENCE.has(basename),
  );
  const evidence = Object.fromEntries(
    passNames.map((basename) => [basename, passEvidence(map, basename, identity)]),
  );
  evidence['data.json'] = operationEvidence(map, 'data.json', 'data', identity, config);
  evidence['api.json'] = operationEvidence(map, 'api.json', 'api', identity, config);
  evidence['observability.json'] = operationEvidence(
    map,
    'observability.json',
    'observability',
    identity,
    config,
  );
  evidence['web.json'] = operationEvidence(map, 'web.json', 'web', identity, config);
  evidence['activation.json'] = operationEvidence(
    map,
    'activation.json',
    'activation',
    identity,
    config,
  );
  evidence['drift.json'] = operationEvidence(map, 'drift.json', 'drift', identity, config);
  const diffFilename = map.get('infra-diff.json');
  const approvalFilename = map.get('approval.json');
  const rawDiffFilename = map.get('infra-diff.txt');
  const awsAuthFilename = map.get('aws-auth.json');
  const journalRoleEffectivePermissionsFilename = map.get(
    RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  );
  const reconciliationRecoveryRoleEffectivePermissionsFilename = map.get(
    RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
  );
  if (
    diffFilename === undefined ||
    approvalFilename === undefined ||
    rawDiffFilename === undefined ||
    awsAuthFilename === undefined ||
    journalRoleEffectivePermissionsFilename === undefined ||
    reconciliationRecoveryRoleEffectivePermissionsFilename === undefined
  ) {
    fail('E7_REQUIRED_EVIDENCE_MISSING');
  }
  evidence['infra-diff.json'] = validateDiffReview(
    readEvidence(diffFilename),
    'full',
    identity,
    config,
  );
  evidence['release-plan.json'] = validateReleasePlanCheckpoint(
    readEvidence(map.get('release-plan.json')),
    'full',
    identity,
    config,
  );
  evidence['approval.json'] = readEvidence(approvalFilename);
  const manifest = evidence['candidate-manifest.json'];
  if (
    manifest.configSha256 !== objectSha256(config) ||
    manifest.releaseMode !== 'VERSIONED_UPDATE' ||
    manifest.updateReleaseSupported !== true ||
    manifest.updateReleaseUnsupportedReason !== null
  ) {
    fail('E7_FULL_MANIFEST_MODE_INVALID');
  }
  evidence['stage6-closeout.json'] = validateStage6CloseoutBinding({
    map,
    identity,
    metadata: evidence['release-metadata.json'],
    freezeManifest: manifest,
    scope: 'full',
  });
  evidence['verify-candidate.json'] = validateCandidateVerificationCheckpoint({
    document: readEvidence(map.get('verify-candidate.json')),
    scope: 'full',
    identity,
    metadata: evidence['release-metadata.json'],
    freezeManifest: manifest,
  });
  evidence['checksums-sbom.json'] = validateChecksumsInventoryCheckpoint({
    document: readEvidence(map.get('checksums-sbom.json')),
    scope: 'full',
    identity,
    freezeManifest: manifest,
  });
  evidence['security.json'] = validateSecurityCheckpoint({
    document: readEvidence(map.get('security.json')),
    scope: 'full',
    identity,
  });
  evidence['prefreeze.json'] = validatePreFreezeCheckpoint({
    document: readEvidence(map.get('prefreeze.json')),
    sourceFilename: map.get('prefreeze.json'),
    identity,
    config,
    freezeManifest: manifest,
  });
  const previousManifestFilename = map.get('previous-release-manifest.json');
  const candidateRecordFilename = map.get('versioned-rollback-candidate.json');
  const noActionOutcomeFilename = map.get(EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_BASENAME);
  const rollbackFilename = map.get('rollback.json');
  const resilienceBindingFilename = map.get('stage7-rollback-resilience-source-binding.json');
  const resilienceRunFilename = map.get('stage7-rollback-resilience-protected-run.json');
  const resilienceCompletionFilename = map.get('stage7-rollback-resilience-complete.json');
  const releaseSuccessorFenceFilename = map.get(RELEASE_SUCCESSOR_COMPLETION_FENCE_BASENAME);
  if (
    previousManifestFilename === undefined ||
    candidateRecordFilename === undefined ||
    noActionOutcomeFilename === undefined ||
    rollbackFilename === undefined ||
    resilienceBindingFilename === undefined ||
    resilienceRunFilename === undefined ||
    resilienceCompletionFilename === undefined ||
    releaseSuccessorFenceFilename === undefined
  ) {
    fail('E7_REQUIRED_EVIDENCE_MISSING');
  }
  const previousManifest = validateStage7PreviousReleaseForTarget(
    readEvidence(previousManifestFilename),
    { config, freezeManifest: manifest },
  );
  const previousSourceProvenance = readEvidence(map.get('previous-source-provenance.json'));
  const previousTargetCompatibility = readEvidence(map.get('previous-target-compatibility.json'));
  const previousFinalDisableProvenance = readEvidence(
    map.get('previous-final-disable-provenance.json'),
  );
  try {
    validateStage7PreviousReleaseHandoff(previousManifest, {
      sourceProvenance: previousSourceProvenance,
      targetCompatibility: previousTargetCompatibility,
      finalDisableProvenance: previousFinalDisableProvenance,
    });
  } catch (error) {
    if (error instanceof Stage7Error) fail('E7_PREVIOUS_RELEASE_HANDOFF_INVALID');
    throw error;
  }
  const previousProjectionPayloadNames = PREVIOUS_RELEASE_PROJECTION_FILENAMES.filter(
    (basename) => basename !== 'previous-release-projection-index.json',
  );
  const previousProjectionIndexFilename = map.get('previous-release-projection-index.json');
  if (
    previousProjectionIndexFilename === undefined ||
    previousProjectionPayloadNames.some((basename) => map.get(basename) === undefined)
  ) {
    fail('E7_PREVIOUS_RELEASE_PROJECTION_MISSING');
  }
  let previousProjectionIndex;
  try {
    previousProjectionIndex = validatePreviousReleaseProjectionIndex(
      readEvidence(previousProjectionIndexFilename),
      {
        previousReleaseManifest: previousManifest,
        files: Object.fromEntries(
          previousProjectionPayloadNames.map((basename) => [
            basename,
            readFileSync(map.get(basename)),
          ]),
        ),
      },
    );
  } catch (error) {
    if (
      typeof error?.code === 'string' &&
      error.code.startsWith('E7_PREVIOUS_RELEASE_PROJECTION_')
    ) {
      fail('E7_PREVIOUS_RELEASE_PROJECTION_INVALID');
    }
    throw error;
  }
  const previousCompatibilityBindings = [
    [
      'previous-api-contract-evidence.json',
      previousManifest.compatibility.apiContractEvidenceSha256,
    ],
    [
      'previous-pending-evidence.json',
      previousManifest.compatibility.pendingReconciliationEvidenceSha256,
    ],
    ['previous-smoke-evidence.json', previousManifest.compatibility.smokeEvidenceSha256],
  ];
  if (
    previousCompatibilityBindings.some(
      ([basename, expectedSha256]) => fileDigest(map.get(basename)) !== expectedSha256,
    )
  ) {
    fail('E7_PREVIOUS_RELEASE_COMPATIBILITY_RAW_BINDING_INVALID');
  }
  const previousReleaseReadiness = validatePreviousReleaseReadiness({
    value: readEvidence(map.get('previous-release-readiness.json')),
    previousManifest,
    config,
    freezeManifest: manifest,
    targetAssemblySha256: hashArtifactPath(resilienceAssemblyDirectory, {
      rootDirectory: workspaceRoot,
    }).sha256,
  });
  const candidateRecord = validateStage7CandidateRollbackRecord(
    readEvidence(candidateRecordFilename),
    {
      previousManifest,
      approvalSha256: fileDigest(approvalFilename),
      planSha256: fileDigest(diffFilename),
      deploymentEvidenceSha256: fileDigest(map.get('web.json')),
    },
  );
  const emergencyRecovery = validateCandidateActiveNoActionRecovery({
    value: readEvidence(map.get('emergency-recovery.json')),
    previousManifest,
    candidateRecord,
  });
  const emergencyRecoveryNoActionOutcome = validateEmergencyRecoveryNoActionOutcomeEvidence({
    value: readEvidence(noActionOutcomeFilename),
    map,
    previousManifest,
    candidateRecord,
    emergencyRecovery,
    identity,
    config,
  });
  const rollback = readEvidence(rollbackFilename);
  let baseRehearsal;
  try {
    baseRehearsal = validateStage7VersionedRollbackRehearsal(
      rollback?.checkpoints?.versionedRollbackRehearsal,
      { previousManifest, candidateRecord },
    );
  } catch (error) {
    if (error instanceof Stage7Error) fail('E7_VERSIONED_ROLLBACK_REHEARSAL_INVALID');
    throw error;
  }
  if (
    rollback.status !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    baseRehearsal.status !== 'BLOCKED_REQUIRED_SCENARIOS' ||
    baseRehearsal.pendingScenarioIds.join('\0') !== ['RB-E7-06', 'RB-E7-08'].join('\0')
  ) {
    fail('E7_ROLLBACK_REQUIRED_SCENARIOS_PENDING');
  }
  const rollbackTransitionEvidence = validateVersionedTransitionEvidenceSet({
    map,
    prefix: 'rollback',
    direction: 'ROLLBACK_TO_PREVIOUS',
    plan: baseRehearsal.rollback.plan,
    embeddedCheckpoint: baseRehearsal.rollback.checkpoint,
    previousManifest,
    candidateRecord,
  });
  const repromotionTransitionEvidence = validateVersionedTransitionEvidenceSet({
    map,
    prefix: 'repromotion',
    direction: 'REPROMOTE_CANDIDATE',
    plan: baseRehearsal.repromotion.plan,
    embeddedCheckpoint: baseRehearsal.repromotion.checkpoint,
    previousManifest,
    candidateRecord,
  });
  evidence['rollback-pending-producer.json'] = readEvidence(
    map.get('rollback-pending-producer.json'),
  );
  evidence['rollback-pending-egress-closeout.json'] = readEvidence(
    map.get('rollback-pending-egress-closeout.json'),
  );
  let resilienceValidationContext;
  try {
    const prepared = prepareRollbackResilienceArtifacts({
      config,
      freezeManifest: manifest,
      previousReleaseManifest: previousManifest,
      candidateRecord,
      rollbackSource: readFileSync(rollbackFilename),
      awsAuthSource: readFileSync(awsAuthFilename),
      approvalSource: readFileSync(approvalFilename),
      approvedPlanSource: readFileSync(diffFilename),
      deploymentEvidenceSource: readFileSync(map.get('web.json')),
      observabilityEvidenceSource: readFileSync(map.get('observability.json')),
      activationEvidenceSource: readFileSync(map.get('activation.json')),
      externalAuthorizationSource: readFileSync(map.get('external-authorization.json')),
      smokeInputSource: readFileSync(map.get('smoke-input-preflight.json')),
      smokeEvidenceSource: readFileSync(map.get('smoke.json')),
      edgeEvidenceSource: readFileSync(map.get('edge-security.json')),
      qualityEvidenceSource: readFileSync(map.get('quality.json')),
      sandboxEvidenceSource: readFileSync(map.get('sandbox-smoke.json')),
      rollbackSmokeInputSource: readFileSync(map.get('rollback-smoke-input-preflight.json')),
      pendingProducerSource: readFileSync(map.get('rollback-pending-producer.json')),
      pendingEgressCloseoutSource: readFileSync(map.get('rollback-pending-egress-closeout.json')),
      rollbackSmokeSource: readFileSync(map.get('versioned-rollback-smoke.json')),
      repromotionSmokeSource: readFileSync(map.get('versioned-repromotion-smoke.json')),
      assemblyDirectory: resilienceAssemblyDirectory,
      maxPolls: 30,
    });
    resilienceValidationContext = {
      inputsWithoutExecution: prepared.inputsWithoutExecution,
      rb06Descriptor: prepared.rb06Descriptor,
      rb08Descriptor: prepared.rb08Descriptor,
    };
  } catch (error) {
    if (error instanceof Stage7RollbackResilienceIntegrationError) {
      fail('E7_ROLLBACK_RESILIENCE_SOURCE_RECONSTRUCTION_INVALID');
    }
    throw error;
  }
  let resilienceCompletion;
  const resilienceRunDocument = readEvidence(resilienceRunFilename);
  try {
    resilienceCompletion = validateRollbackResilienceCompletionEnvelope({
      envelope: readEvidence(resilienceCompletionFilename),
      rollbackSource: readFileSync(rollbackFilename),
      sourceBindingSource: readFileSync(resilienceBindingFilename),
      protectedRunSource: readFileSync(resilienceRunFilename),
      validationContext: resilienceValidationContext,
    });
  } catch (error) {
    if (error instanceof Stage7RollbackResilienceIntegrationError) {
      fail('E7_ROLLBACK_RESILIENCE_COMPLETION_INVALID');
    }
    throw error;
  }
  const versionedRehearsal = resilienceCompletion.versionedRollbackRehearsal;
  if (
    resilienceCompletion.status !== 'PASS' ||
    resilienceCompletion.candidateSha !== identity.candidateSha ||
    resilienceCompletion.releaseId !== identity.releaseId ||
    resilienceCompletion.gateE703 !== 'ELIGIBLE_PENDING_RELEASE_CLOSEOUT' ||
    versionedRehearsal.status !== 'PASS' ||
    versionedRehearsal.scenarioIds.join('\0') !==
      [
        'RB-E7-01',
        'RB-E7-02',
        'RB-E7-03',
        'RB-E7-04',
        'RB-E7-05',
        'RB-E7-06',
        'RB-E7-07',
        'RB-E7-08',
      ].join('\0') ||
    versionedRehearsal.pendingScenarioIds.length !== 0 ||
    versionedRehearsal.dataPolicy !== 'NO_ROLLBACK_FORWARD_ONLY' ||
    versionedRehearsal.dataRollbackPerformed !== false ||
    versionedRehearsal.stacksDeleted !== 0
  ) {
    fail('E7_ROLLBACK_RESILIENCE_COMPLETION_INVALID');
  }
  const rollbackCheckReconciliationFilename = map.get('rollback-check-reconciliation.json');
  const rollbackResilienceReconciliationFilename = map.get(
    'rollback-resilience-reconciliation.json',
  );
  const preFenceGateFilename = map.get('stage7-release-pre-fence-gate.json');
  if (
    rollbackCheckReconciliationFilename === undefined ||
    rollbackResilienceReconciliationFilename === undefined ||
    preFenceGateFilename === undefined
  ) {
    fail('E7_RELEASE_RECONCILIATION_EVIDENCE_MISSING');
  }
  let releasePreFenceGate;
  try {
    releasePreFenceGate = validateReleasePreFenceGate(readEvidence(preFenceGateFilename), {
      rollbackCheckSource: readFileSync(rollbackCheckReconciliationFilename),
      rollbackResilienceSource: readFileSync(rollbackResilienceReconciliationFilename),
    });
  } catch (error) {
    if (error instanceof Stage7ReleaseReconciliationError) {
      fail('E7_RELEASE_RECONCILIATION_EVIDENCE_INVALID');
    }
    throw error;
  }
  const releaseMetadata = evidence['release-metadata.json'];
  if (
    releasePreFenceGate.source.candidateSha !== identity.candidateSha ||
    releasePreFenceGate.source.releaseId !== identity.releaseId ||
    releasePreFenceGate.source.releaseTag !== identity.releaseTag ||
    releasePreFenceGate.source.configSha256 !== objectSha256(config) ||
    releasePreFenceGate.source.runId !== releaseMetadata.releaseRunId ||
    releasePreFenceGate.source.runAttempt !== releaseMetadata.releaseRunAttempt
  ) {
    fail('E7_RELEASE_RECONCILIATION_IDENTITY_MISMATCH');
  }
  evidence['rollback-check-reconciliation.json'] = readEvidence(
    rollbackCheckReconciliationFilename,
  );
  evidence['rollback-resilience-reconciliation.json'] = readEvidence(
    rollbackResilienceReconciliationFilename,
  );
  evidence['stage7-release-pre-fence-gate.json'] = releasePreFenceGate;
  const releaseSuccessorFenceEvidenceBindings = {
    approval: evidenceFileBinding(approvalFilename),
    activation: evidenceFileBinding(map.get('activation.json')),
    drift: evidenceFileBinding(map.get('drift.json')),
    rollbackCompletion: evidenceFileBinding(resilienceCompletionFilename),
    preFenceGate: evidenceFileBinding(preFenceGateFilename),
  };
  let releaseSuccessorFence;
  try {
    releaseSuccessorFence = validateReleaseSuccessorCompletionFence(
      readEvidence(releaseSuccessorFenceFilename),
      {
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        sourceRunId: releaseMetadata.releaseRunId,
        sourceRunAttempt: releaseMetadata.releaseRunAttempt,
        journalLifecycleSha256: resilienceCompletion.journalLifecycleSha256,
        journalCleanupRoleSha256:
          resilienceRunDocument.runtimeAttestation?.journalLifecycle?.cleanupRoleSha256,
        evidenceBindings: releaseSuccessorFenceEvidenceBindings,
      },
    );
  } catch (error) {
    if (error instanceof Stage7ReleaseSuccessorFenceContractError) {
      fail('E7_RELEASE_SUCCESSOR_COMPLETION_FENCE_INVALID');
    }
    throw error;
  }
  evidence[RELEASE_SUCCESSOR_COMPLETION_FENCE_BASENAME] = releaseSuccessorFence;
  const data = deployedCheckpoint(
    evidence['data.json'],
    'data',
    'data',
    identity,
    config,
    manifest,
  );
  const api = deployedCheckpoint(evidence['api.json'], 'api', 'api', identity, config, manifest);
  const observability = deployedCheckpoint(
    evidence['observability.json'],
    'observability',
    'observability',
    identity,
    config,
    manifest,
  );
  const web = deployedCheckpoint(evidence['web.json'], 'web', 'web', identity, config, manifest);
  const security = evidence['security.json'];
  const aws = evidence['aws-auth.json'];
  const verifiedIamPermissions = validateAwsAuthEffectivePermissions({
    value: aws,
    valueSource: readEvidenceSource(awsAuthFilename),
    journalRoleEffectivePermissionsSource: readEvidenceSource(
      journalRoleEffectivePermissionsFilename,
    ),
    reconciliationRecoveryRoleEffectivePermissionsSource: readEvidenceSource(
      reconciliationRecoveryRoleEffectivePermissionsFilename,
    ),
    config,
    scope: 'full',
    identity,
    manifestSha256: manifest.manifestSha256,
  });
  evidence[RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME] = readEvidence(
    journalRoleEffectivePermissionsFilename,
  );
  evidence[RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME] = readEvidence(
    reconciliationRecoveryRoleEffectivePermissionsFilename,
  );
  const releasePlan = evidence['release-plan.json'];
  const diff = evidence['infra-diff.json'];
  const synth = validateInfraSynthCheckpoint({
    document: evidence['infra-synth.json'],
    scope: 'full',
    identity,
    freezeManifest: manifest,
    releasePlan,
    diff,
  });
  const githubApproval = evidence['github-environment-approval.json'];
  const approval = evidence['approval.json'];
  const smoke = evidence['smoke.json'];
  const qualitySource = evidence['quality.json'];
  const edgeSource = evidence['edge-security.json'];
  const sandboxSource = evidence['sandbox-smoke.json'];
  evidence['previous-release-manifest.json'] = previousManifest;
  evidence['previous-release-readiness.json'] = previousReleaseReadiness;
  evidence['previous-source-provenance.json'] = previousSourceProvenance;
  evidence['previous-target-compatibility.json'] = previousTargetCompatibility;
  evidence['previous-final-disable-provenance.json'] = previousFinalDisableProvenance;
  evidence['previous-api-contract-evidence.json'] = readEvidence(
    map.get('previous-api-contract-evidence.json'),
  );
  evidence['previous-pending-evidence.json'] = readEvidence(
    map.get('previous-pending-evidence.json'),
  );
  evidence['previous-smoke-evidence.json'] = readEvidence(map.get('previous-smoke-evidence.json'));
  evidence['previous-release-projection-index.json'] = previousProjectionIndex;
  evidence['versioned-rollback-candidate.json'] = candidateRecord;
  evidence['emergency-recovery.json'] = emergencyRecovery;
  evidence[EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_BASENAME] = emergencyRecoveryNoActionOutcome;
  evidence['versioned-rollback-aws-transition.json'] = rollbackTransitionEvidence.transition;
  evidence['versioned-rollback-checkpoint.json'] = rollbackTransitionEvidence.checkpoint;
  evidence['versioned-repromotion-aws-transition.json'] = repromotionTransitionEvidence.transition;
  evidence['versioned-repromotion-checkpoint.json'] = repromotionTransitionEvidence.checkpoint;
  evidence['rollback.json'] = rollback;
  evidence['stage7-rollback-resilience-source-binding.json'] =
    readEvidence(resilienceBindingFilename);
  evidence['stage7-rollback-resilience-protected-run.json'] = resilienceRunDocument;
  evidence['stage7-rollback-resilience-complete.json'] = resilienceCompletion;
  const authorization = validateExternalAuthorizationCheckpoint({
    document: evidence['external-authorization.json'],
    scope: 'full',
    identity,
    config,
  });
  const quality = validateQualityCheckpoint({
    document: qualitySource,
    identity,
    config,
    freezeManifest: manifest,
    authorization,
    applicationOrigin: web.outputs.ApplicationUrl,
  });
  const edge = validateEdgeSecurityCheckpoint({
    document: edgeSource,
    scope: 'full',
    identity,
    config,
    authorization,
    applicationOrigin: web.outputs.ApplicationUrl,
  });
  const sandbox = validateSandboxCheckpoint({
    document: sandboxSource,
    scope: 'full',
    identity,
    config,
    freezeManifest: manifest,
    authorization,
    applicationOrigin: web.outputs.ApplicationUrl,
  });
  const smokeInput = evidence['smoke-input-preflight.json'];
  const rollbackInput = evidence['rollback-smoke-input-preflight.json'];
  const pendingProducer = validateRollbackPendingProducerForCloseout({
    value: evidence['rollback-pending-producer.json'],
    identity,
    manifest,
    config,
    authority: authorization,
    applicationOrigin: web.outputs.ApplicationUrl,
  });
  const pendingEgressCloseout = validateRollbackPendingEgressCloseout({
    value: evidence['rollback-pending-egress-closeout.json'],
    identity,
    manifest,
    config,
    authority: authorization,
    pendingProducer,
    previousIdentity: {
      candidateSha: previousManifest.previous.candidateSha,
      releaseId: previousManifest.previous.releaseId,
    },
    rollbackCheckpoint: rollbackTransitionEvidence.checkpoint,
    repromotionCheckpoint: repromotionTransitionEvidence.checkpoint,
  });
  const activation = evidence['activation.json'].checkpoints.activation;
  const readiness = evidence['observability.json'].checkpoints.observabilityReadiness;
  const drift = evidence['drift.json'].checkpoints.drift;
  validateCanonicalSmokeResults(smoke.results);
  try {
    validateCapabilityCookieEvidence(smoke.capabilityCookie);
  } catch (error) {
    if (error instanceof Stage7SmokeError) fail('E7_CAPABILITY_COOKIE_EVIDENCE_INVALID');
    throw error;
  }
  const expectedAuthorizationIds = externalAuthorizationRequirements('full').map(({ id }) => id);
  const expectedTopic = `arn:aws:sns:${config.aws.region}:${config.aws.accountId}:checkout-${config.environment}-alerts`;
  const rollbackSmoke = evidence['versioned-rollback-smoke.json'];
  const repromotionSmoke = evidence['versioned-repromotion-smoke.json'];
  try {
    validateStage7ActivationCheckpoint(activation, {
      config,
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      manifestSha256: manifest.manifestSha256,
      complete: true,
    });
    validateStage7DriftCheckpoint(drift, {
      config,
      manifestSha256: manifest.manifestSha256,
      assemblySha256: activation.assemblySha256,
    });
  } catch (error) {
    if (error instanceof Stage7Error) fail('E7_REQUIRED_EVIDENCE_CONTROL_FAILED');
    throw error;
  }
  const activationUsages = activation.transitions.map(({ authorizationUsage: usage }) => usage);
  const resilienceAuthorizationUsage = versionedRehearsal.resilience?.authorizationUsage;
  const reconciliationAuthorizationUsages = [
    reconciliationAuthorizationLedgerUsage({
      usage: releasePreFenceGate.smokeAuthorizationUsages[0],
      phase: 'ROLLBACK_CHECK',
      source: releasePreFenceGate.source,
    }),
    reconciliationAuthorizationLedgerUsage({
      usage: releasePreFenceGate.smokeAuthorizationUsages[1],
      phase: 'ROLLBACK_RESILIENCE',
      source: releasePreFenceGate.source,
    }),
  ];
  const ledgerUsages = [
    authorization.authorizationUsage,
    smokeInput.authorizationUsage,
    ...activationUsages,
    smoke.authorizationUsage,
    quality.authorizationUsage,
    edge.authorizationUsage,
    sandbox.authorizationUsage,
    rollbackInput.authorizationUsage,
    pendingProducer.authorizationUsage,
    rollbackSmoke?.authorizationUsage,
    repromotionSmoke?.authorizationUsage,
    pendingEgressCloseout.authorizationUsage,
    resilienceAuthorizationUsage,
    ...reconciliationAuthorizationUsages,
  ];
  const externalRequestBudgetPlan = validateAuthorizationBudgetPlan({
    authorization,
    identity,
    config,
  });
  const ledger = validateAuthorizationBudgetCheckpoint({
    plan: externalRequestBudgetPlan,
    usages: ledgerUsages,
    phase: 'PRE_FENCE',
  });
  const usageCount = (usage, id) => usage?.requestCounts?.[id];
  const [ownedAuthorizationId, sandboxAuthorizationId, passiveAuthorizationId] =
    expectedAuthorizationIds;
  const exactDriftStacks = drift.stacks.map(({ stackName }) => stackName);
  const approvalPlanSha256 = fileDigest(diffFilename);
  const approvalDiffSha256 = fileDigest(rawDiffFilename);
  const approvalEvidenceSha256 = fileDigest(approvalFilename);
  validateBoundGithubEnvironmentApproval({
    document: githubApproval,
    scope: 'full',
    identity,
    map,
  });
  const deploymentPlanBindingsValid = [data, api, observability, web].every(
    (checkpoint) =>
      checkpoint.previousReleaseManifestSha256 === previousManifest.manifestSha256 &&
      checkpoint.approvedPlan.approvalSha256 === approvalEvidenceSha256 &&
      checkpoint.approvedPlan.planSha256 === approvalPlanSha256 &&
      checkpoint.approvedPlan.preDeploymentStateSha256 ===
        diff.checkpoints.diff.preDeploymentState?.[checkpoint.stackName],
  );
  if (
    security.secretFindings !== 0 ||
    security.providerProductionReferences !== 0 ||
    aws.longLivedCredentials !== false ||
    aws.roleTrust !== 'PASS' ||
    synth.secretFindings !== 0 ||
    synth.publicBucketRisks !== 0 ||
    synth.wildcardCorsRisks !== 0 ||
    synth.freezeManifestSha256 !== manifest.manifestSha256 ||
    synth.assemblySha256 !== diff.cloudAssemblySha256 ||
    releasePlan.cloudAssemblySha256 !== diff.cloudAssemblySha256 ||
    !SHA256.test(synth.frozenVerificationSha256 ?? '') ||
    diff.checkpoints.diff.freezeManifestSha256 !== manifest.manifestSha256 ||
    diff.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    diff.checkpoints.diff.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    diff.statefulReplacements !== 0 ||
    diff.destructiveChanges !== 0 ||
    !exactKeys(approval, PROTECTED_APPROVAL_KEYS) ||
    approval.kind !== 'PROTECTED_RELEASE_APPROVAL' ||
    approval.status !== 'PASS' ||
    approval.scope !== 'full' ||
    approval.candidateSha !== identity.candidateSha ||
    approval.releaseId !== identity.releaseId ||
    approval.releaseTag !== identity.releaseTag ||
    approval.configSha256 !== objectSha256(config) ||
    approval.cloudAssemblySha256 !== diff.cloudAssemblySha256 ||
    approval.freezeManifestSha256 !== diff.checkpoints.diff.freezeManifestSha256 ||
    approval.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    approval.approvedPlanSha256 !== approvalPlanSha256 ||
    approval.approvedDiffSha256 !== approvalDiffSha256 ||
    approval.approvedDiffSha256 !== diff.rawDiffArtifactSha256 ||
    approval.iamEffectivePermissionsBindingSha256 !== verifiedIamPermissions.bindingSha256 ||
    approval.iamEffectivePermissionsEvidenceSha256 !== fileDigest(awsAuthFilename) ||
    approval.journalRoleEffectivePermissionsRawSha256 !==
      verifiedIamPermissions.journalRoleEffectivePermissionsRawSha256 ||
    approval.journalRoleEffectivePermissionsSha256 !==
      verifiedIamPermissions.journalRoleEffectivePermissionsSha256 ||
    RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.some(
      (field) => approval[field] !== verifiedIamPermissions[field],
    ) ||
    approval.approvedAtUtc !== githubApproval.capturedAtUtc ||
    approval.reviewerAlias !== githubApproval.reviewerAlias ||
    approval.humanReviewConfirmed !== githubApproval.reviewed ||
    approval.iamBroadeningReviewed !== githubApproval.iamReviewAttested ||
    !utc(approval.approvedAtUtc) ||
    Date.parse(approval.approvedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(approval.approvedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    approval.humanReviewConfirmed !== true ||
    approval.iamBroadeningReviewed !== true ||
    approval.explicitDispatchConfirmation !== true ||
    approval.protectedEnvironment !== true ||
    approval.protectedEnvironmentName !== 'assessment-release' ||
    approval.nonPublic !== false ||
    approval.accountSha256 !== digest(config.aws.accountId) ||
    approval.accountSuffix !== config.aws.accountId.slice(-4) ||
    approval.region !== config.aws.region ||
    approval.stacks?.join('\0') !== config.authorization.stacks.join('\0') ||
    approval.approvalOwnerAlias !== config.authorization.ownerAlias ||
    !/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u.test(approval.reviewerAlias ?? '') ||
    objectSha256(approval.authorizedWindow) !== objectSha256(config.window) ||
    objectSha256(approval.budget) !==
      objectSha256({
        maxUsd: config.budget.maxUsd,
        warningUsd: config.budget.warningUsd,
        alertDestinationSha256: config.budget.alertDestinationSha256,
      }) ||
    approval.externalRequests !== 0 ||
    approval.mutationsPerformed !== 0 ||
    approval.containsSensitiveData !== false ||
    !deploymentPlanBindingsValid ||
    activation.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    drift.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    activation.assemblySha256 !== manifest.artifacts.find(({ name }) => name === 'iac')?.sha256 ||
    activation.seedEvidenceSha256 !==
      digest(JSON.stringify(evidence['data.json'].checkpoints.seed)) ||
    activation.observabilityReadiness.evidenceSha256 !==
      digest(JSON.stringify(evidence['observability.json'])) ||
    activation.publicOriginSha256 !== web.publicOriginSha256 ||
    data.outputs?.PointInTimeRecoveryStatus !== 'ENABLED' ||
    api.outputs?.SchedulerStatus !== 'DISABLED' ||
    api.outputs?.ApiPublicationStatus !== 'DISABLED' ||
    web.outputs?.WebPublicationStatus !== 'DISABLED' ||
    observability.outputs?.BudgetContract !== budgetContract(config) ||
    observability.alertDestinationSha256 !== config.budget.alertDestinationSha256 ||
    readiness?.decision !== 'PASS' ||
    readiness?.status !== 'CONFIRMED' ||
    readiness?.protocol !== 'email' ||
    readiness?.alertDestinationSha256 !== config.budget.alertDestinationSha256 ||
    readiness?.alertTopicSha256 !== digest(expectedTopic) ||
    !SHA256.test(readiness?.subscriptionArnSha256 ?? '') ||
    readiness?.rawDestinationCaptured !== false ||
    authorization.kind !== 'EXTERNAL_AUTHORIZATION_PREFLIGHT' ||
    authorization.stage7ConfigSha256 !== objectSha256(config) ||
    authorization.authorizationIds?.join('\0') !== expectedAuthorizationIds.join('\0') ||
    ledger.usageIds.length !== 16 ||
    usageCount(resilienceAuthorizationUsage, ownedAuthorizationId) !== 11 ||
    usageCount(resilienceAuthorizationUsage, sandboxAuthorizationId) !== 0 ||
    usageCount(resilienceAuthorizationUsage, passiveAuthorizationId) !== 0 ||
    reconciliationAuthorizationUsages.some(
      (usage) =>
        usageCount(usage, ownedAuthorizationId) !== 3 ||
        usageCount(usage, sandboxAuthorizationId) !== 0 ||
        usageCount(usage, passiveAuthorizationId) !== 0,
    ) ||
    smokeInput.kind !== 'PRIVATE_SMOKE_INPUT_PREFLIGHT' ||
    smokeInput.decision !== 'READY_FOR_CANDIDATE_ACTIVATION_SMOKE' ||
    smokeInput.configSha256 !== objectSha256(config) ||
    rollbackInput.kind !== 'PRIVATE_SMOKE_INPUT_PREFLIGHT' ||
    rollbackInput.decision !== 'READY_FOR_VERSIONED_ROLLBACK_PENDING_CANARY' ||
    rollbackInput.configSha256 !== objectSha256(config) ||
    pendingProducer.kind !== 'VERSIONED_ROLLBACK_PENDING_PRODUCER' ||
    pendingProducer.status !== 'PENDING_OBSERVED' ||
    pendingEgressCloseout.kind !== 'ROLLBACK_PENDING_EGRESS_CLOSEOUT' ||
    pendingEgressCloseout.status !== 'PASS' ||
    smoke.total !== 18 ||
    smoke.passed !== 18 ||
    smoke.failed !== 0 ||
    smoke.mode !== 'POST_DEPLOY' ||
    smoke.stage7ConfigSha256 !== objectSha256(config) ||
    smoke.externalAuthorization?.authorizationIds?.join('\0') !==
      expectedAuthorizationIds.join('\0') ||
    smoke.requests?.production !== 0 ||
    smoke.requests?.outsideAllowlist !== 0 ||
    usageCount(smoke.authorizationUsage, ownedAuthorizationId) !== smoke.requests?.ownedOrigin ||
    usageCount(smoke.authorizationUsage, sandboxAuthorizationId) !== smoke.requests?.provider ||
    usageCount(smoke.authorizationUsage, passiveAuthorizationId) !== 0 ||
    smoke.effects?.approvedStockDelta !== 1 ||
    smoke.effects?.approvedDeliveries !== 1 ||
    smoke.effects?.failedStockDelta !== 0 ||
    smoke.effects?.failedDeliveries !== 0 ||
    smoke.effects?.duplicateTransactionPosts !== 0 ||
    smoke.effects?.negativeStockObserved !== false ||
    Object.values(smoke.criticalErrors ?? {}).some((value) => value !== 0) ||
    quality.kind !== 'DEPLOYED_FOCAL_QUALITY' ||
    quality.evidenceIds?.join('\0') !== ['EVD-E7-42', 'EVD-E7-43', 'EVD-E7-44'].join('\0') ||
    quality.configSha256 !== objectSha256(config) ||
    quality.mutationsPerformed !== 0 ||
    usageCount(quality.authorizationUsage, passiveAuthorizationId) !==
      quality.requests?.ownedOrigin ||
    edge.corsExact !== true ||
    edge.directS3Denied !== 'PASS' ||
    edge.mixedContentRequests !== 0 ||
    edge.externalAuthorization?.authorizationIds?.join('\0') !==
      expectedAuthorizationIds.join('\0') ||
    edge.zap?.findings?.critical !== 0 ||
    edge.zap?.findings?.high !== 0 ||
    edge.zap?.findings?.total !== 0 ||
    edge.zap?.budgetEnforcement !== 'ENFORCED_BEFORE_EGRESS' ||
    edge.zap?.ownEndpointsScanned !== ZAP_PASSIVE_REQUEST_COUNT ||
    edge.zap?.ownEndpointsOutOfScope !== 0 ||
    ![
      edge.zap?.inventorySha256,
      edge.zap?.captureSha256,
      edge.zap?.openApiRawSha256,
      edge.zap?.observationsSha256,
    ].every((value) => SHA256.test(value ?? '')) ||
    edge.requests?.ownedOrigin !== 6 ||
    edge.requests?.zap !== ZAP_PASSIVE_REQUEST_COUNT ||
    edge.requestBudgetComponents?.direct?.componentId !== 'EDGE_PASSIVE_DIRECT' ||
    usageCount(
      { requestCounts: edge.requestBudgetComponents?.direct?.requestCounts },
      passiveAuthorizationId,
    ) !== 6 ||
    edge.requestBudgetComponents?.zap?.componentId !== 'EDGE_PASSIVE_ZAP_EXACT_INVENTORY' ||
    usageCount(
      { requestCounts: edge.requestBudgetComponents?.zap?.requestCounts },
      passiveAuthorizationId,
    ) !== ZAP_PASSIVE_REQUEST_COUNT ||
    usageCount(edge.authorizationUsage, passiveAuthorizationId) !==
      edge.requests?.ownedOrigin + edge.requests?.zap ||
    sandbox.productionRequests !== 0 ||
    sandbox.duplicateEffects !== 0 ||
    sandbox.requests?.outsideAllowlist !== 0 ||
    sandbox.requests?.production !== 0 ||
    sandbox.result?.duplicateEffects !== 0 ||
    usageCount(sandbox.authorizationUsage, sandboxAuthorizationId) !== sandbox.requests?.total ||
    rollbackSmoke?.status !== 'PASS' ||
    rollbackSmoke?.mode !== 'POST_ROLLBACK_VERSIONED' ||
    rollbackSmoke?.targetReleaseId !== previousManifest.previous.releaseId ||
    rollbackSmoke?.total !== 3 ||
    rollbackSmoke?.passed !== 3 ||
    rollbackSmoke?.failed !== 0 ||
    rollbackSmoke?.dataMutations !== 0 ||
    usageCount(rollbackSmoke?.authorizationUsage, ownedAuthorizationId) !==
      rollbackSmoke?.requests?.ownedOrigin ||
    repromotionSmoke?.status !== 'PASS' ||
    repromotionSmoke?.mode !== 'POST_REPROMOTION_VERSIONED' ||
    repromotionSmoke?.targetReleaseId !== previousManifest.target.releaseId ||
    repromotionSmoke?.total !== 3 ||
    repromotionSmoke?.passed !== 3 ||
    repromotionSmoke?.failed !== 0 ||
    repromotionSmoke?.dataMutations !== 0 ||
    usageCount(repromotionSmoke?.authorizationUsage, ownedAuthorizationId) !==
      repromotionSmoke?.requests?.ownedOrigin ||
    versionedRehearsal.previousReleaseManifestSha256 !== previousManifest.manifestSha256 ||
    versionedRehearsal.candidateRecordSha256 !== candidateRecord.recordSha256 ||
    exactDriftStacks.join('\0') !== config.authorization.stacks.join('\0')
  ) {
    fail('E7_REQUIRED_EVIDENCE_CONTROL_FAILED');
  }
  evidence.authorizationLedger = ledger;
  evidence.authorizationUsages = ledgerUsages;
  evidence.externalRequestBudgetPlan = externalRequestBudgetPlan;
  return evidence;
};

const publicationUrlsAreExact = (urls) => {
  if (!exactKeys(urls, ['application', 'api', 'docs', 'health', 'repository'])) return false;
  let application;
  try {
    application = new URL(urls.application);
  } catch {
    return false;
  }
  return (
    application.protocol === 'https:' &&
    !application.username &&
    !application.password &&
    !application.search &&
    !application.hash &&
    application.origin === urls.application &&
    urls.api === `${application.origin}/api` &&
    urls.docs === `${application.origin}/api/docs` &&
    urls.health === `${application.origin}/api/health/ready` &&
    urls.repository === 'https://github.com/ivanmonsalve0404/async-checkout-demo'
  );
};

const publicationUrls = (web) => {
  const outputs = web?.checkpoints?.web?.outputs;
  const urls = {
    application: outputs?.ApplicationUrl,
    api: outputs?.ApiUrl,
    docs: outputs?.ApiDocsUrl,
    health: outputs?.HealthUrl,
  };
  const resolved = {
    ...urls,
    repository: 'https://github.com/ivanmonsalve0404/async-checkout-demo',
  };
  if (!publicationUrlsAreExact(resolved)) fail('E7_PUBLICATION_URLS_INVALID');
  return resolved;
};

const configuredPublicationUrls = (config) => {
  if (config.domain?.mode !== 'CUSTOM_AUTHORIZED') fail('E7_PUBLICATION_URLS_INVALID');
  const application = `https://${config.domain.hostname}`;
  return {
    application,
    api: `${application}/api`,
    docs: `${application}/api/docs`,
    health: `${application}/api/health/ready`,
    repository: 'https://github.com/ivanmonsalve0404/async-checkout-demo',
  };
};

const releaseReadme = (readme, urls) => {
  const startMarker = '<!-- STAGE7_URLS_START -->';
  const endMarker = '<!-- STAGE7_URLS_END -->';
  if (
    readme.split(startMarker).length !== 2 ||
    readme.split(endMarker).length !== 2 ||
    readme.indexOf(startMarker) >= readme.indexOf(endMarker)
  ) {
    fail('E7_PUBLICATION_README_MARKERS_INVALID');
  }
  const deploymentSection = [
    startMarker,
    '',
    '## Entorno desplegado',
    '',
    `- Aplicación: ${urls.application}`,
    `- API: ${urls.api}`,
    `- OpenAPI: ${urls.docs}`,
    `- Salud: ${urls.health}`,
    `- Repositorio: ${urls.repository}`,
    '',
    endMarker,
  ].join('\n');
  return readme.replace(
    /<!-- STAGE7_URLS_START -->[\s\S]*?<!-- STAGE7_URLS_END -->/u,
    deploymentSection,
  );
};

const prepareReleaseReadme = async () => {
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const filename = path.join(workspaceRoot, 'README.md');
  checkedWorkspacePath(filename, { directory: false });
  const readme = readFileSync(filename, 'utf8').replace(/\r\n?/gu, '\n');
  await writeSanitizedTextAtomic(
    filename,
    'stage7-candidate-readme.md',
    releaseReadme(readme, configuredPublicationUrls(config)),
  );
};

const publicationPackage = async (flags) => {
  const identity = candidateIdentity('full', { requireGitTag: true });
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const map = evidenceFileMap(requiredString(flags, 'evidence'), 'full');
  const evidence = assertFullEvidence(
    map,
    identity,
    config,
    requiredString(flags, 'resilience-app'),
  );
  const urls = publicationUrls(evidence['web.json']);
  if (objectSha256(urls) !== objectSha256(configuredPublicationUrls(config))) {
    fail('E7_PUBLICATION_URLS_INVALID');
  }
  const readme = readFileSync(path.join(workspaceRoot, 'README.md'), 'utf8').replace(
    /\r\n?/gu,
    '\n',
  );
  const nextReadme = releaseReadme(readme, urls);
  if (nextReadme !== readme) fail('E7_PUBLICATION_README_NOT_IN_CANDIDATE');
  const releaseNotes =
    [
      `# ${identity.releaseTag}`,
      '',
      `Candidato inmutable: \`${identity.candidateSha}\``,
      `Release ID: \`${identity.releaseId}\``,
      '',
      '## Enlaces verificados',
      '',
      `- Aplicación: ${urls.application}`,
      `- API: ${urls.api}`,
      `- OpenAPI: ${urls.docs}`,
      `- Salud: ${urls.health}`,
      '',
      '## Controles',
      '',
      '- Smoke desplegado: 18/18.',
      '- Sandbox autorizado: PASS.',
      '- Compatibilidad, accesibilidad y Lighthouse focal: PASS.',
      '- Edge, TLS, headers y CORS: PASS.',
      '- Rollback, re-promoción y drift CloudFormation 4/4: PASS.',
      '- Presupuesto global de requests autorizados: PASS.',
    ].join('\n') + '\n';
  const output = path.join(workspaceRoot, 'output/release/publication');
  const readmeTarget = path.join(output, 'README.md');
  const notesTarget = path.join(output, 'release-notes.md');
  const manifestTarget = path.join(output, 'candidate-manifest.json');
  await writeSanitizedTextAtomic(readmeTarget, 'stage7-publication-readme.md', nextReadme);
  await writeSanitizedTextAtomic(notesTarget, 'stage7-release-notes.md', releaseNotes);
  await writeStage7Json(
    manifestTarget,
    'stage7-publication-candidate-manifest.json',
    evidence['candidate-manifest.json'],
  );
  let readmeGitBlobSha;
  let packagedReadmeGitBlobSha;
  try {
    readmeGitBlobSha = execFileSync('git', ['rev-parse', 'HEAD:README.md'], {
      cwd: workspaceRoot,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
    packagedReadmeGitBlobSha = execFileSync('git', ['hash-object', readmeTarget], {
      cwd: workspaceRoot,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
  } catch {
    fail('E7_PUBLICATION_README_BLOB_UNAVAILABLE');
  }
  if (
    !SHA.test(readmeGitBlobSha) ||
    !SHA.test(packagedReadmeGitBlobSha) ||
    packagedReadmeGitBlobSha !== readmeGitBlobSha
  ) {
    fail('E7_PUBLICATION_README_NOT_IN_CANDIDATE');
  }
  const plan = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PUBLICATION_PLAN',
    status: 'READY_FOR_EXTERNAL_PUBLICATION',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: identity.releaseTag,
    repository: 'ivanmonsalve0404/async-checkout-demo',
    branch: 'master',
    readmeGitBlobSha,
    urls,
    files: {
      readmeSha256: fileDigest(readmeTarget),
      releaseNotesSha256: fileDigest(notesTarget),
      candidateManifestSha256: fileDigest(manifestTarget),
    },
    release: {
      title: identity.releaseTag,
      targetSha: identity.candidateSha,
      draft: false,
      prerelease: identity.releaseTag.includes('-rc.'),
      assetName: 'candidate-manifest.json',
      notesSha256: fileDigest(notesTarget),
    },
    publicationOrder: ['README_VERIFY', 'GITHUB_RELEASE'],
    retryPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
    externalWritesPlanned: 2,
    externalWritesPerformed: 0,
    containsSensitiveData: false,
  };
  await writeStage7Json(
    path.join(output, 'publication-plan.json'),
    'stage7-publication-plan.json',
    plan,
  );
  await emitJson(
    {
      ...plan,
      kind: 'PUBLICATION_PREPARATION',
      packageSha256: objectSha256(plan.files),
    },
    path.join(evidenceRoot('full'), 'publication.json'),
    'stage7-publication-preparation.json',
  );
};

const validatePublicationPlan = (plan, identity) => {
  if (
    !exactKeys(plan, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'repository',
      'branch',
      'readmeGitBlobSha',
      'urls',
      'files',
      'release',
      'publicationOrder',
      'retryPolicy',
      'externalWritesPlanned',
      'externalWritesPerformed',
      'containsSensitiveData',
    ]) ||
    plan.schemaVersion !== 1 ||
    plan.stage !== 7 ||
    plan.kind !== 'PUBLICATION_PLAN' ||
    plan.status !== 'READY_FOR_EXTERNAL_PUBLICATION' ||
    plan.candidateSha !== identity.candidateSha ||
    plan.releaseId !== identity.releaseId ||
    plan.releaseTag !== identity.releaseTag ||
    plan.repository !== 'ivanmonsalve0404/async-checkout-demo' ||
    plan.branch !== 'master' ||
    !SHA.test(plan.readmeGitBlobSha ?? '') ||
    !publicationUrlsAreExact(plan.urls) ||
    !exactKeys(plan.files, ['readmeSha256', 'releaseNotesSha256', 'candidateManifestSha256']) ||
    Object.values(plan.files).some((value) => !SHA256.test(value ?? '')) ||
    !exactKeys(plan.release, [
      'title',
      'targetSha',
      'draft',
      'prerelease',
      'assetName',
      'notesSha256',
    ]) ||
    plan.release.title !== identity.releaseTag ||
    plan.release.targetSha !== identity.candidateSha ||
    plan.release.draft !== false ||
    plan.release.prerelease !== identity.releaseTag.includes('-rc.') ||
    plan.release.assetName !== 'candidate-manifest.json' ||
    plan.release.notesSha256 !== plan.files.releaseNotesSha256 ||
    plan.publicationOrder?.join('\0') !== ['README_VERIFY', 'GITHUB_RELEASE'].join('\0') ||
    plan.retryPolicy !== 'VERIFY_EXACT_OR_CREATE_MISSING' ||
    plan.externalWritesPlanned !== 2 ||
    plan.externalWritesPerformed !== 0 ||
    plan.containsSensitiveData !== false
  ) {
    fail('E7_PUBLICATION_PLAN_INVALID');
  }
  return plan;
};

const githubJson = async (pathname) => {
  const token = process.env.GH_TOKEN;
  if (typeof token !== 'string' || token.length < 20 || token.length > 512) {
    fail('E7_GITHUB_READ_TOKEN_REQUIRED');
  }
  let response;
  try {
    response = await fetch(`https://api.github.com${pathname}`, {
      redirect: 'error',
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'user-agent': 'async-checkout-stage7-verifier',
        'x-github-api-version': '2026-03-10',
      },
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    fail('E7_GITHUB_READ_FAILED');
  }
  if (
    response.status !== 200 ||
    response.redirected === true ||
    !(response.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')
  ) {
    fail('E7_GITHUB_READ_FAILED');
  }
  const source = await response.text();
  if (Buffer.byteLength(source) < 2 || Buffer.byteLength(source) > 4 * 1024 * 1024) {
    fail('E7_GITHUB_READ_INVALID');
  }
  try {
    return JSON.parse(source);
  } catch {
    fail('E7_GITHUB_READ_INVALID');
  }
};

const verifyPublishedUrl = async (value, fetchImpl = globalThis.fetch) => {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail('E7_PUBLICATION_URL_VERIFICATION_FAILED');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) {
    fail('E7_PUBLICATION_URL_VERIFICATION_FAILED');
  }
  let response;
  try {
    response = await fetchImpl(parsed, {
      redirect: 'error',
      headers: { 'user-agent': 'async-checkout-stage7-verifier' },
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    fail('E7_PUBLICATION_URL_VERIFICATION_FAILED');
  }
  if (response.status < 200 || response.status >= 300) {
    fail('E7_PUBLICATION_URL_VERIFICATION_FAILED');
  }
  try {
    await response.body?.cancel();
  } catch {
    fail('E7_PUBLICATION_URL_VERIFICATION_FAILED');
  }
};

const verifyPublishedUrls = async (urls, fetchImpl = globalThis.fetch) =>
  Promise.all(
    ['application', 'docs', 'health'].map((name) => verifyPublishedUrl(urls?.[name], fetchImpl)),
  );

const authorizationEvidenceFromAuthority = (authority) => ({
  authorizationSha256: objectSha256(authority.value),
  ownedOriginSha256: authority.originSha256,
  sandboxHostSha256: authority.sandboxHostSha256,
  requestLimits: Object.fromEntries(
    externalAuthorizationRequirements('full').map(({ key, id }) => [
      id,
      authority.authorizations[key].maxRequests,
    ]),
  ),
});

const validatePublicationTargetProof = (document, identity, plan, config, authorization) => {
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'publicationPlanSha256',
      'stage7ConfigSha256',
      'ownedOriginSha256',
      'authorizationSha256',
      'urlsSha256',
      'verifiedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'authorizationUsage',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'PUBLICATION_TARGET_PREFLIGHT' ||
    document.status !== 'PASS' ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.releaseTag !== identity.releaseTag ||
    document.publicationPlanSha256 !== objectSha256(plan) ||
    document.stage7ConfigSha256 !== objectSha256(config) ||
    document.ownedOriginSha256 !== authorization.ownedOriginSha256 ||
    document.authorizationSha256 !== authorization.authorizationSha256 ||
    document.urlsSha256 !== objectSha256(plan.urls) ||
    !utc(document.verifiedAtUtc) ||
    document.externalRequests !== 3 ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_PUBLICATION_TARGET_PROOF_INVALID');
  }
  const ledger = validateAuthorizationLedger({
    authorization,
    usages: [document.authorizationUsage],
    identity,
    config,
    expectedUsageIds: ['PUBLICATION_TARGET_PREFLIGHT'],
  });
  if (
    ledger.totals['AUTH-E7-EXT-01'] !== 3 ||
    ledger.totals['AUTH-E7-EXT-02'] !== 0 ||
    ledger.totals['AUTH-E7-EXT-03'] !== 0
  ) {
    fail('E7_PUBLICATION_TARGET_PROOF_INVALID');
  }
  return document;
};

const publicationTargetVerification = async (flags) => {
  const identity = candidateIdentity('full', { requireGitTag: true });
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const plan = validatePublicationPlan(
    readEvidence(
      checkedWorkspacePath(requiredString(flags, 'publication-target'), { directory: false }),
    ),
    identity,
  );
  if (objectSha256(plan.urls) !== objectSha256(configuredPublicationUrls(config))) {
    fail('E7_PUBLICATION_URLS_INVALID');
  }
  const evidence = assertFullEvidence(
    evidenceFileMap(requiredString(flags, 'publication-evidence'), 'full'),
    identity,
    config,
    requiredString(flags, 'resilience-app'),
  );
  const authority = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: plan.urls.application,
  });
  const authorization = authorizationEvidenceFromAuthority(authority);
  if (
    authorization.authorizationSha256 !==
      evidence['external-authorization.json'].authorizationSha256 ||
    authorization.ownedOriginSha256 !== evidence['external-authorization.json'].ownedOriginSha256 ||
    authorization.sandboxHostSha256 !== evidence['external-authorization.json'].sandboxHostSha256 ||
    objectSha256(authorization.requestLimits) !==
      objectSha256(evidence['external-authorization.json'].requestLimits)
  ) {
    fail('E7_PUBLICATION_TARGET_AUTHORIZATION_MISMATCH');
  }
  const usage = authorizationUsage({
    scope: 'full',
    authority,
    identity,
    config,
    usageId: 'PUBLICATION_TARGET_PREFLIGHT',
    requestCounts: { 'AUTH-E7-EXT-01': 3 },
  });
  validateAuthorizationBudgetCheckpoint({
    plan: evidence.externalRequestBudgetPlan,
    usages: [...evidence.authorizationUsages, usage],
    phase: 'POST_PUBLICATION',
  });
  await verifyPublishedUrls(plan.urls);
  const proof = validatePublicationTargetProof(
    {
      schemaVersion: 1,
      stage: 7,
      kind: 'PUBLICATION_TARGET_PREFLIGHT',
      status: 'PASS',
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      releaseTag: identity.releaseTag,
      publicationPlanSha256: objectSha256(plan),
      stage7ConfigSha256: objectSha256(config),
      ownedOriginSha256: authority.originSha256,
      authorizationSha256: objectSha256(authority.value),
      urlsSha256: objectSha256(plan.urls),
      verifiedAtUtc: new Date().toISOString(),
      externalRequests: 3,
      mutationsPerformed: 0,
      authorizationUsage: usage,
      containsSensitiveData: false,
    },
    identity,
    plan,
    config,
    authorization,
  );
  await emitJson(proof, requiredString(flags, 'evidence'), 'stage7-publication-target-proof.json');
};

const validatePublicationOperation = (document, identity, plan) => {
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'repository',
      'publicationPlanSha256',
      'releaseState',
      'readmeState',
      'externalRequests',
      'externalWritesPerformed',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'GITHUB_PUBLICATION_OPERATION' ||
    document.status !== 'PASS' ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.releaseTag !== identity.releaseTag ||
    document.repository !== plan.repository ||
    document.publicationPlanSha256 !== objectSha256(plan) ||
    document.releaseState !== 'COMPLETE' ||
    document.readmeState !== 'VERIFIED_AT_CANDIDATE' ||
    !Number.isSafeInteger(document.externalRequests) ||
    document.externalRequests < 4 ||
    document.externalRequests > 32 ||
    !Number.isSafeInteger(document.externalWritesPerformed) ||
    document.externalWritesPerformed < 0 ||
    document.externalWritesPerformed > 2 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_PUBLICATION_OPERATION_INVALID');
  }
  return document;
};

const publicationNativeVerification = async (flags) => {
  const identity = candidateIdentity('full', { requireGitTag: true });
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const planFilename = checkedWorkspacePath(requiredString(flags, 'publication-native'), {
    directory: false,
  });
  const plan = validatePublicationPlan(readEvidence(planFilename), identity);
  if (objectSha256(plan.urls) !== objectSha256(configuredPublicationUrls(config))) {
    fail('E7_PUBLICATION_URLS_INVALID');
  }
  const authority = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: plan.urls.application,
  });
  const targetProof = validatePublicationTargetProof(
    readEvidence(
      checkedWorkspacePath(requiredString(flags, 'publication-target-proof'), {
        directory: false,
      }),
    ),
    identity,
    plan,
    config,
    authorizationEvidenceFromAuthority(authority),
  );
  const operation = validatePublicationOperation(
    readEvidence(
      checkedWorkspacePath(requiredString(flags, 'publication-operation'), { directory: false }),
    ),
    identity,
    plan,
  );
  const publicationDirectory = path.dirname(planFilename);
  const outputs = {
    readme: path.join(publicationDirectory, 'README.md'),
    notes: path.join(publicationDirectory, 'release-notes.md'),
    manifest: path.join(publicationDirectory, 'candidate-manifest.json'),
  };
  for (const filename of Object.values(outputs))
    checkedWorkspacePath(filename, { directory: false });
  let readmeGitBlobSha;
  try {
    readmeGitBlobSha = execFileSync('git', ['hash-object', outputs.readme], {
      cwd: workspaceRoot,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
  } catch {
    fail('E7_PUBLICATION_PACKAGE_INVALID');
  }
  if (
    readmeGitBlobSha !== plan.readmeGitBlobSha ||
    fileDigest(outputs.readme) !== plan.files?.readmeSha256 ||
    fileDigest(outputs.notes) !== plan.files?.releaseNotesSha256 ||
    fileDigest(outputs.manifest) !== plan.files?.candidateManifestSha256
  ) {
    fail('E7_PUBLICATION_PACKAGE_INVALID');
  }
  const repositoryPath = '/repos/ivanmonsalve0404/async-checkout-demo';
  const [repository, readme, headReference, tagReference, candidateCommit, release] =
    await Promise.all([
      githubJson(repositoryPath),
      githubJson(`${repositoryPath}/contents/README.md?ref=master`),
      githubJson(`${repositoryPath}/git/ref/heads/master`),
      githubJson(`${repositoryPath}/git/ref/tags/${encodeURIComponent(identity.releaseTag)}`),
      githubJson(`${repositoryPath}/commits/${identity.candidateSha}`),
      githubJson(`${repositoryPath}/releases/tags/${encodeURIComponent(identity.releaseTag)}`),
    ]);
  let tagAuthority;
  let commitsAuthority;
  try {
    tagAuthority = createTagRefAuthority({
      plan,
      tagResponse: tagReference,
      headResponse: headReference,
    });
    commitsAuthority = createCommitsEndpointAuthority({ plan, commitResponse: candidateCommit });
  } catch {
    fail('E7_PUBLICATION_REMOTE_STATE_INVALID');
  }
  const readmeCommitSha = headReference.object?.sha;
  const asset = Array.isArray(release.assets)
    ? release.assets.find((entry) => entry?.name === 'candidate-manifest.json')
    : undefined;
  if (
    repository.full_name !== plan.repository ||
    repository.private !== false ||
    repository.default_branch !== 'master' ||
    repository.html_url !== plan.urls?.repository ||
    readme.type !== 'file' ||
    readme.sha !== plan.readmeGitBlobSha ||
    headReference.object?.type !== 'commit' ||
    readmeCommitSha !== identity.candidateSha ||
    tagReference.object?.type !== 'commit' ||
    tagReference.object?.sha !== identity.candidateSha ||
    release.tag_name !== plan.release.title ||
    ![identity.candidateSha, 'master'].includes(release.target_commitish) ||
    release.name !== plan.release.title ||
    release.draft !== plan.release.draft ||
    release.prerelease !== plan.release.prerelease ||
    String(release.body ?? '').replace(/\r\n?/gu, '\n') !==
      readFileSync(outputs.notes, 'utf8').replace(/\r\n?/gu, '\n') ||
    release.html_url !==
      `https://github.com/${plan.repository}/releases/tag/${encodeURIComponent(identity.releaseTag)}` ||
    release.assets?.length !== 1 ||
    asset?.name !== plan.release.assetName ||
    asset?.state !== 'uploaded' ||
    asset?.digest !== `sha256:${plan.files.candidateManifestSha256}` ||
    asset?.size !== readFileSync(outputs.manifest).byteLength ||
    asset?.content_type !== 'application/json'
  ) {
    fail('E7_PUBLICATION_REMOTE_STATE_INVALID');
  }
  const githubApiRequests = operation.externalRequests + 6;
  const ownedTargetRequests = targetProof.externalRequests;
  const proof = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PUBLICATION_PROOF',
    status: 'PASS',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: identity.releaseTag,
    repository: plan.repository,
    branch: 'master',
    repositoryPublic: true,
    readmeVerifiedAtCandidate: true,
    readmeCommitSha,
    releasePresent: true,
    releaseVerifiedExact: true,
    releaseTargetSha: identity.candidateSha,
    tagRefAuthoritative: tagAuthority.tagRefAuthoritative,
    tagRefAuthoritySha256: tagAuthority.tagRefAuthoritySha256,
    commitsEndpointVerified: commitsAuthority.commitsEndpointVerified,
    commitsEndpointAuthoritySha256: commitsAuthority.commitsEndpointAuthoritySha256,
    releaseUrl: release.html_url,
    targetHealthyBeforePublication: true,
    urlsVerified: true,
    publicationPlanSha256: objectSha256(plan),
    publicationTargetProofSha256: objectSha256(targetProof),
    publicationOperationSha256: objectSha256(operation),
    verifiedAtUtc: new Date().toISOString(),
    githubApiRequests,
    ownedTargetRequests,
    externalRequests: githubApiRequests + ownedTargetRequests,
    externalWritesPerformed: operation.externalWritesPerformed,
    containsSensitiveData: false,
  };
  await emitJson(
    proof,
    flags.evidence ?? path.join(evidenceRoot('full'), 'publication-proof.json'),
    'stage7-publication-proof.json',
  );
};

const validatePublicationProof = (document, identity, plan) => {
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'repository',
      'branch',
      'repositoryPublic',
      'readmeVerifiedAtCandidate',
      'readmeCommitSha',
      'releasePresent',
      'releaseVerifiedExact',
      'releaseTargetSha',
      'tagRefAuthoritative',
      'tagRefAuthoritySha256',
      'commitsEndpointVerified',
      'commitsEndpointAuthoritySha256',
      'releaseUrl',
      'targetHealthyBeforePublication',
      'urlsVerified',
      'publicationPlanSha256',
      'publicationTargetProofSha256',
      'publicationOperationSha256',
      'verifiedAtUtc',
      'githubApiRequests',
      'ownedTargetRequests',
      'externalRequests',
      'externalWritesPerformed',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'PUBLICATION_PROOF' ||
    document.status !== 'PASS' ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.releaseTag !== identity.releaseTag ||
    document.repository !== plan.repository ||
    document.branch !== 'master' ||
    document.repositoryPublic !== true ||
    document.readmeVerifiedAtCandidate !== true ||
    document.readmeCommitSha !== identity.candidateSha ||
    document.releasePresent !== true ||
    document.releaseVerifiedExact !== true ||
    document.releaseTargetSha !== identity.candidateSha ||
    document.tagRefAuthoritative !== true ||
    !SHA256.test(document.tagRefAuthoritySha256 ?? '') ||
    document.commitsEndpointVerified !== true ||
    !SHA256.test(document.commitsEndpointAuthoritySha256 ?? '') ||
    document.releaseUrl !==
      `https://github.com/${plan.repository}/releases/tag/${encodeURIComponent(identity.releaseTag)}` ||
    document.targetHealthyBeforePublication !== true ||
    document.urlsVerified !== true ||
    document.publicationPlanSha256 !== objectSha256(plan) ||
    !SHA256.test(document.publicationTargetProofSha256 ?? '') ||
    !SHA256.test(document.publicationOperationSha256 ?? '') ||
    !utc(document.verifiedAtUtc) ||
    !Number.isSafeInteger(document.githubApiRequests) ||
    document.githubApiRequests < 10 ||
    document.githubApiRequests > 38 ||
    document.ownedTargetRequests !== 3 ||
    !Number.isSafeInteger(document.externalRequests) ||
    document.externalRequests !== document.githubApiRequests + document.ownedTargetRequests ||
    !Number.isSafeInteger(document.externalWritesPerformed) ||
    document.externalWritesPerformed < 0 ||
    document.externalWritesPerformed > 2 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_PUBLICATION_PROOF_INVALID');
  }
  return document;
};

const parseExactJobResults = (source, scope) => {
  if (typeof source !== 'string' || source.length === 0 || source.length > 256 * 1024) {
    fail('E7_JOB_RESULTS_REQUIRED');
  }
  let results;
  try {
    results = parseStrictJsonSource(Buffer.from(source), { scanForbiddenData: false });
  } catch {
    fail('E7_JOB_RESULTS_INVALID');
  }
  if (!object(results)) fail('E7_JOB_RESULTS_NOT_SUCCESSFUL');
  const expected = scope === 'prerelease' ? REQUIRED_PRERELEASE_JOBS : REQUIRED_FULL_JOBS;
  const keys = Object.keys(results);
  if (
    keys.toSorted(stableCompare).join('\0') !== expected.toSorted(stableCompare).join('\0') ||
    Object.values(results).some(
      (job) => !object(job) || !['success', 'failure', 'cancelled', 'skipped'].includes(job.result),
    )
  ) {
    fail('E7_JOB_RESULTS_INVALID');
  }
  return results;
};

const validateSuccessfulJobResults = (source, scope) => {
  const results = parseExactJobResults(source, scope);
  if (Object.values(results).some((job) => job.result !== 'success')) {
    fail('E7_JOB_RESULTS_NOT_SUCCESSFUL');
  }
  return Object.keys(results).sort(stableCompare);
};

const exactJobResults = (scope) => parseExactJobResults(process.env.STAGE7_JOB_RESULTS, scope);

const provenanceSource = (map, scope, basename) => {
  const filename = map.get(basename);
  const producer = STAGE7_SOURCE_PRODUCERS[scope]?.[basename];
  if (filename === undefined || producer === undefined) fail('E7_PROVENANCE_SOURCE_MISSING');
  return createSourceReference({
    path: `.stage7/evidence/${producer.artifactName}/${basename}`,
    sha256: fileDigest(filename),
    artifactName: producer.artifactName,
    producerJob: producer.producerJob,
    selectors: [basename.endsWith('.txt') ? '/rawSha256' : '/status'],
  });
};

const validateCandidateVerificationCheckpoint = ({
  document,
  scope,
  identity,
  metadata,
  freezeManifest,
}) => {
  const expectedStage6Status = scope === 'full' ? 'PASS' : 'CONDITIONAL_GO';
  const expectedImmutableIdentifier = scope === 'full' ? identity.releaseTag : identity.releaseId;
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'candidateTreeSha',
      'immutableIdentifier',
      'releaseId',
      'stage6RunId',
      'stage6ManifestSha256',
      'stage6Status',
      'workingTree',
      'changedFiles',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'CANDIDATE_VERIFICATION' ||
    document.status !== 'PASS' ||
    document.scope !== scope ||
    document.candidateSha !== identity.candidateSha ||
    document.candidateTreeSha !== identity.treeSha ||
    document.immutableIdentifier !== expectedImmutableIdentifier ||
    document.releaseId !== identity.releaseId ||
    document.stage6RunId !== metadata?.stage6RunId ||
    document.stage6RunId !== freezeManifest?.sourceRunId ||
    document.stage6ManifestSha256 !== metadata?.stage6ManifestSha256 ||
    document.stage6Status !== expectedStage6Status ||
    document.stage6Status !== metadata?.stage6Status ||
    document.workingTree !== 'CLEAN' ||
    (identity.workingTree !== undefined && document.workingTree !== identity.workingTree) ||
    document.changedFiles !== 0 ||
    (identity.changedFiles !== undefined && document.changedFiles !== identity.changedFiles) ||
    document.externalRequests !== 0 ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_CANDIDATE_VERIFICATION_CHECKPOINT_INVALID');
  }
  return document;
};

const validateChecksumsInventoryCheckpoint = ({ document, scope, identity, freezeManifest }) => {
  const expectedArtifactDigests = Object.fromEntries(
    freezeManifest.artifacts.map(({ name, sha256 }) => [name, sha256]),
  );
  const inventory = document?.inventory;
  const inventoryPaths = Array.isArray(inventory)
    ? inventory.map(({ path: pathName }) => pathName)
    : [];
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'manifestSha256',
      'sourceArtifactId',
      'sourceArtifactSha256',
      'artifactDigests',
      'inventoryFormat',
      'inventory',
      'provenance',
      'findings',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'CHECKSUMS_INVENTORY_PROVENANCE' ||
    document.status !== 'PASS' ||
    document.scope !== scope ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.manifestSha256 !== freezeManifest.manifestSha256 ||
    document.sourceArtifactId !== freezeManifest.sourceArtifactId ||
    document.sourceArtifactSha256 !== freezeManifest.sourceArtifactSha256 ||
    !exactKeys(document.artifactDigests, Object.keys(expectedArtifactDigests)) ||
    objectSha256(document.artifactDigests) !== objectSha256(expectedArtifactDigests) ||
    document.inventoryFormat !== 'SHA256_INVENTORY_V1' ||
    !Array.isArray(inventory) ||
    inventory.length < 1 ||
    inventory.length > 50_000 ||
    new Set(inventoryPaths).size !== inventoryPaths.length ||
    inventory.some(
      (entry) =>
        !exactKeys(entry, ['path', 'bytes', 'sha256']) ||
        typeof entry.path !== 'string' ||
        entry.path.length < 1 ||
        entry.path.length > 512 ||
        entry.path.includes('\\') ||
        path.isAbsolute(entry.path) ||
        entry.path
          .split('/')
          .some((segment) => segment === '' || segment === '.' || segment === '..') ||
        !Number.isSafeInteger(entry.bytes) ||
        entry.bytes < 0 ||
        !SHA256.test(entry.sha256 ?? ''),
    ) ||
    !exactKeys(document.provenance, ['lockfileSha256', 'openApiSha256', 'generatedClientSha256']) ||
    document.provenance.lockfileSha256 !== freezeManifest.lockfileSha256 ||
    document.provenance.openApiSha256 !== freezeManifest.openApiSha256 ||
    document.provenance.generatedClientSha256 !== freezeManifest.generatedClientSha256 ||
    document.findings !== 0 ||
    document.externalRequests !== 0 ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_CHECKSUMS_INVENTORY_CHECKPOINT_INVALID');
  }
  return document;
};

const validateSecurityCheckpoint = ({ document, scope, identity }) => {
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'tree',
      'history',
      'candidateArtifact',
      'providerProductionReferences',
      'secretFindings',
      'paymentDataFindings',
      'syntheticOnly',
      'filesScanned',
      'bytesScanned',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'REPOSITORY_AND_CANDIDATE_SECURITY' ||
    document.status !== 'PASS' ||
    document.scope !== scope ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.tree !== 'PASS' ||
    document.history !== 'PASS' ||
    document.candidateArtifact !== 'PASS' ||
    document.providerProductionReferences !== 0 ||
    document.secretFindings !== 0 ||
    document.paymentDataFindings !== 0 ||
    document.syntheticOnly !== (scope === 'prerelease') ||
    !Number.isSafeInteger(document.filesScanned) ||
    document.filesScanned < 1 ||
    !Number.isSafeInteger(document.bytesScanned) ||
    document.bytesScanned < 1 ||
    document.externalRequests !== 0 ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_SECURITY_CHECKPOINT_INVALID');
  }
  return document;
};

const validatePreFreezeSourceBinding = ({ sourceFilename, freezeManifest }) => {
  if (
    typeof sourceFilename !== 'string' ||
    !SHA256.test(freezeManifest?.preFreezeEvidenceSha256 ?? '') ||
    fileDigest(sourceFilename) !== freezeManifest.preFreezeEvidenceSha256
  ) {
    fail('E7_PRE_FREEZE_SOURCE_BINDING_INVALID');
  }
  return freezeManifest.preFreezeEvidenceSha256;
};

const validatePreFreezeCheckpoint = ({
  document,
  sourceFilename,
  identity,
  config,
  freezeManifest,
}) => {
  const quotaServices = Object.keys(REQUIRED_QUOTAS);
  const quotaCapacity = document?.quotaCapacity;
  const stackInventory = document?.stackInventory;
  const authorizedStacks = document?.authorizedStacks;
  validatePreFreezeSourceBinding({ sourceFilename, freezeManifest });
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'manifestSha256',
      'configSha256',
      'accountSha256',
      'accountSuffix',
      'callerArnSha256',
      'expectedRoleArnSha256',
      'region',
      'sessionMode',
      'roleTrust',
      'bootstrapVersion',
      'bootstrapStackIdSha256',
      'bootstrapStackStatus',
      'quotaCapacity',
      'stackInventory',
      'authorizedStacks',
      'iamEffectivePermissions',
      'capacityProven',
      'decision',
      'preFreezeException',
      'longLivedCredentials',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'AWS_PRE_FREEZE_SYNTH_PREFLIGHT' ||
    document.status !== 'PASS' ||
    document.scope !== 'full' ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.manifestSha256 !== null ||
    document.configSha256 !== objectSha256(config) ||
    document.accountSha256 !== digest(config.aws.accountId) ||
    document.accountSuffix !== config.aws.accountId.slice(-4) ||
    !SHA256.test(document.callerArnSha256 ?? '') ||
    document.expectedRoleArnSha256 !== digest(config.aws.roles.readRoleArn) ||
    document.region !== config.aws.region ||
    document.sessionMode !== config.aws.sessionMode ||
    document.roleTrust !== 'PASS' ||
    !Number.isSafeInteger(document.bootstrapVersion) ||
    document.bootstrapVersion < 14 ||
    !SHA256.test(document.bootstrapStackIdSha256 ?? '') ||
    !STABLE_STACK_STATUSES.has(document.bootstrapStackStatus) ||
    !exactKeys(quotaCapacity, quotaServices) ||
    quotaServices.some((service) => {
      const capacity = quotaCapacity[service];
      const required = REQUIRED_QUOTAS[service];
      return (
        !exactKeys(capacity, [
          'quotaCode',
          'limit',
          'used',
          'requiredAdditional',
          'remainingAfterRelease',
        ]) ||
        capacity.quotaCode !== required.quotaCode ||
        !Number.isFinite(capacity.limit) ||
        !Number.isSafeInteger(capacity.used) ||
        capacity.used < 0 ||
        capacity.requiredAdditional !== required.additional ||
        capacity.remainingAfterRelease !==
          capacity.limit - capacity.used - capacity.requiredAdditional ||
        capacity.remainingAfterRelease < 0
      );
    }) ||
    !exactKeys(stackInventory, [
      'status',
      'pages',
      'activeStackCount',
      'inventorySha256',
      'parametersOrOutputsCaptured',
    ]) ||
    stackInventory.status !== 'PASS' ||
    !Number.isSafeInteger(stackInventory.pages) ||
    stackInventory.pages < 1 ||
    !Number.isSafeInteger(stackInventory.activeStackCount) ||
    stackInventory.activeStackCount < 0 ||
    !SHA256.test(stackInventory.inventorySha256 ?? '') ||
    stackInventory.parametersOrOutputsCaptured !== false ||
    !exactKeys(authorizedStacks, [
      'status',
      'stackCount',
      'stackSummariesSha256',
      'stacks',
      'externalRequests',
    ]) ||
    authorizedStacks.status !== 'PASS' ||
    authorizedStacks.stackCount !== config.authorization.stacks.length ||
    authorizedStacks.externalRequests !== config.authorization.stacks.length ||
    !SHA256.test(authorizedStacks.stackSummariesSha256 ?? '') ||
    !Array.isArray(authorizedStacks.stacks) ||
    authorizedStacks.stacks.length !== config.authorization.stacks.length ||
    authorizedStacks.stacks.some(
      (stack, index) =>
        !exactKeys(stack, ['stackName', 'stackIdSha256', 'stackStatus']) ||
        stack.stackName !== config.authorization.stacks[index] ||
        !SHA256.test(stack.stackIdSha256 ?? '') ||
        !STABLE_STACK_STATUSES.has(stack.stackStatus),
    ) ||
    authorizedStacks.stackSummariesSha256 !== objectSha256(authorizedStacks.stacks) ||
    document.capacityProven !== true ||
    document.decision !== 'READY_FOR_BUILD_FREEZE' ||
    document.preFreezeException !== true ||
    document.longLivedCredentials !== false ||
    document.externalRequests !==
      9 +
        document.iamEffectivePermissions?.externalRequests +
        stackInventory.pages +
        authorizedStacks.externalRequests ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_PRE_FREEZE_CHECKPOINT_INVALID');
  }
  try {
    validateIamEffectivePermissionsEvidence({
      value: document.iamEffectivePermissions,
      config,
      scope: 'full',
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      manifestSha256: null,
      bootstrapAssetInventory: null,
      cleanupWatchdogRoleArn: null,
      baselineRoleArn: null,
    });
  } catch {
    fail('E7_PRE_FREEZE_CHECKPOINT_INVALID');
  }
  return document;
};

const validateReleasePlanCheckpoint = (document, scope, identity, config) => {
  const expectedReleaseTag = scope === 'full' ? identity.releaseTag : null;
  const resourceCounts = document.resourceCounts;
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'releaseTag',
      'cloudAssemblySha256',
      'stacks',
      'dependencyOrder',
      'templates',
      'resources',
      'resourceCounts',
      'statefulReplacements',
      'iamReviewStatus',
      'destructiveChanges',
      'mutationsPlannedOnly',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'RELEASE_PLAN' ||
    document.status !== 'READY_FOR_DIFF' ||
    document.scope !== scope ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.releaseTag !== expectedReleaseTag ||
    !SHA256.test(document.cloudAssemblySha256 ?? '') ||
    document.stacks?.join('\0') !==
      config.authorization.stacks.toSorted(stableCompare).join('\0') ||
    document.dependencyOrder?.join('\0') !== document.stacks.join('\0') ||
    new Set(document.stacks ?? []).size !== 4 ||
    document.templates !== 4 ||
    !Number.isSafeInteger(document.resources) ||
    document.resources < 1 ||
    !object(resourceCounts) ||
    Object.keys(resourceCounts).length < 1 ||
    Object.entries(resourceCounts).some(
      ([resourceType, count]) =>
        !/^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$/u.test(resourceType) ||
        !Number.isSafeInteger(count) ||
        count < 1,
    ) ||
    Object.values(resourceCounts).reduce((total, count) => total + count, 0) !==
      document.resources ||
    document.statefulReplacements !== 'PENDING_CDK_DIFF' ||
    document.iamReviewStatus !== 'PENDING_PROTECTED_REVIEW' ||
    document.destructiveChanges !== 'PENDING_CDK_DIFF' ||
    document.mutationsPlannedOnly !== true ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_RELEASE_PLAN_CHECKPOINT_INVALID');
  }
  return document;
};

const validateInfraSynthCheckpoint = ({
  document,
  scope,
  identity,
  freezeManifest,
  releasePlan,
  diff,
}) => {
  const frozenAssemblySha256 = freezeManifest?.artifacts?.find(
    ({ name }) => name === 'iac',
  )?.sha256;
  const resourceCounts = document?.resourceCounts;
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'assemblySha256',
      'freezeManifestSha256',
      'frozenVerificationSha256',
      'templates',
      'resources',
      'resourceCounts',
      'secretFindings',
      'productionProviderReferences',
      'publicBucketRisks',
      'wildcardCorsRisks',
      'iamWildcardActionRisks',
      'statefulProtectionRisks',
      'filesScanned',
      'bytesScanned',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'CLOUD_ASSEMBLY_SECURITY' ||
    document.status !== 'PASS' ||
    document.scope !== scope ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    !SHA256.test(frozenAssemblySha256 ?? '') ||
    document.assemblySha256 !== frozenAssemblySha256 ||
    document.assemblySha256 !== releasePlan?.cloudAssemblySha256 ||
    document.assemblySha256 !== diff?.cloudAssemblySha256 ||
    document.assemblySha256 !== diff?.checkpoints?.diff?.assemblySha256 ||
    document.freezeManifestSha256 !== freezeManifest?.manifestSha256 ||
    document.freezeManifestSha256 !== diff?.checkpoints?.diff?.freezeManifestSha256 ||
    !SHA256.test(document.frozenVerificationSha256 ?? '') ||
    document.templates !== releasePlan?.templates ||
    document.resources !== releasePlan?.resources ||
    !object(resourceCounts) ||
    !exactKeys(resourceCounts, Object.keys(releasePlan?.resourceCounts ?? {})) ||
    objectSha256(resourceCounts) !== objectSha256(releasePlan?.resourceCounts ?? {}) ||
    Object.entries(resourceCounts).some(
      ([resourceType, count]) =>
        !/^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$/u.test(resourceType) ||
        !Number.isSafeInteger(count) ||
        count < 1,
    ) ||
    Object.values(resourceCounts).reduce((total, count) => total + count, 0) !==
      document.resources ||
    document.secretFindings !== 0 ||
    document.productionProviderReferences !== 0 ||
    document.publicBucketRisks !== 0 ||
    document.wildcardCorsRisks !== 0 ||
    document.iamWildcardActionRisks !== 0 ||
    document.statefulProtectionRisks !== 0 ||
    !Number.isSafeInteger(document.filesScanned) ||
    document.filesScanned < 1 ||
    !Number.isSafeInteger(document.bytesScanned) ||
    document.bytesScanned < 1 ||
    document.externalRequests !== 0 ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_INFRA_SYNTH_CHECKPOINT_INVALID');
  }
  return document;
};

const validateAuthorizationUsageEnvelope = ({
  usage,
  scope,
  identity,
  config,
  authorizationSha256,
  ownedOriginSha256,
  sandboxHostSha256,
  usageId,
  requestCounts,
}) => {
  const authorizationIds = externalAuthorizationRequirements(scope).map(({ id }) => id);
  if (
    !exactKeys(usage, [
      'schemaVersion',
      'usageId',
      'bundleSha256',
      'candidateSha',
      'releaseId',
      'configSha256',
      'ownedOriginSha256',
      'sandboxHostSha256',
      'requestCounts',
    ]) ||
    usage.schemaVersion !== 1 ||
    usage.usageId !== usageId ||
    usage.bundleSha256 !== authorizationSha256 ||
    usage.candidateSha !== identity.candidateSha ||
    usage.releaseId !== identity.releaseId ||
    usage.configSha256 !== objectSha256(config) ||
    usage.ownedOriginSha256 !== ownedOriginSha256 ||
    usage.sandboxHostSha256 !== sandboxHostSha256 ||
    !exactKeys(usage.requestCounts, authorizationIds) ||
    !exactKeys(requestCounts, authorizationIds) ||
    objectSha256(usage.requestCounts) !== objectSha256(requestCounts) ||
    Object.values(usage.requestCounts).some((count) => !Number.isSafeInteger(count) || count < 0)
  ) {
    fail('E7_AUTHORIZATION_USAGE_ENVELOPE_INVALID');
  }
  return usage;
};

const validateExternalAuthorizationCheckpoint = ({ document, scope, identity, config }) => {
  const authorizationIds = externalAuthorizationRequirements(scope).map(({ id }) => id);
  const expectedKeys = [
    'schemaVersion',
    'stage',
    'kind',
    'status',
    'scope',
    'candidateSha',
    'releaseId',
    'stage7ConfigSha256',
    'ownedOriginSha256',
    ...(scope === 'prerelease' ? ['apiOriginSha256'] : []),
    'sandboxHostSha256',
    'authorizationSha256',
    'authorizationIds',
    'requestLimits',
    ...(scope === 'full' ? ['externalRequestBudgetPlan'] : []),
    'authorizationUsage',
    'targetValuesCaptured',
    'externalRequests',
    'mutationsPerformed',
    'containsSensitiveData',
  ];
  if (
    !exactKeys(document, expectedKeys) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'EXTERNAL_AUTHORIZATION_PREFLIGHT' ||
    document.status !== 'PASS' ||
    document.scope !== scope ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.stage7ConfigSha256 !== objectSha256(config) ||
    ![
      document.ownedOriginSha256,
      document.sandboxHostSha256,
      document.authorizationSha256,
      ...(scope === 'prerelease' ? [document.apiOriginSha256] : []),
    ].every((value) => SHA256.test(value ?? '')) ||
    document.authorizationIds?.join('\0') !== authorizationIds.join('\0') ||
    !exactKeys(document.requestLimits, authorizationIds) ||
    Object.values(document.requestLimits).some(
      (limit) => !Number.isSafeInteger(limit) || limit < 1,
    ) ||
    document.targetValuesCaptured !== false ||
    document.externalRequests !== 0 ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_EXTERNAL_AUTHORIZATION_CHECKPOINT_INVALID');
  }
  try {
    validateAuthorizationUsageEnvelope({
      usage: document.authorizationUsage,
      scope,
      identity,
      config,
      authorizationSha256: document.authorizationSha256,
      ownedOriginSha256: document.ownedOriginSha256,
      sandboxHostSha256: document.sandboxHostSha256,
      usageId: 'EXTERNAL_AUTHORIZATION_PREFLIGHT',
      requestCounts: Object.fromEntries(authorizationIds.map((id) => [id, 0])),
    });
    if (scope === 'full') {
      validateAuthorizationBudgetPlan({ authorization: document, identity, config });
    }
  } catch (error) {
    if (error instanceof Stage7ControlError || error instanceof Stage7ExternalRequestBudgetError) {
      fail('E7_EXTERNAL_AUTHORIZATION_CHECKPOINT_INVALID');
    }
    throw error;
  }
  return document;
};

const validateQualityCheckpoint = ({
  document,
  identity,
  config,
  freezeManifest,
  authorization,
  applicationOrigin,
}) => {
  const passiveAuthorizationId = externalAuthorizationRequirements('full').find(
    ({ key }) => key === 'passiveSecurity',
  )?.id;
  const payload = {
    crossBrowser: document?.crossBrowser,
    accessibility: document?.accessibility,
    lighthouse: document?.lighthouse,
    requests: document?.requests,
    criticalErrors: document?.criticalErrors,
  };
  if (
    !exactKeys(document, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'manifestSha256',
      'configSha256',
      'targetOriginSha256',
      'authorizationSha256',
      'authorizationUsage',
      'evidenceIds',
      'crossBrowser',
      'accessibility',
      'lighthouse',
      'requests',
      'criticalErrors',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
    ]) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'DEPLOYED_FOCAL_QUALITY' ||
    document.status !== 'PASS' ||
    document.scope !== 'full' ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.manifestSha256 !== freezeManifest?.manifestSha256 ||
    document.configSha256 !== objectSha256(config) ||
    document.targetOriginSha256 !== digest(applicationOrigin) ||
    document.targetOriginSha256 !== authorization?.ownedOriginSha256 ||
    document.authorizationSha256 !== authorization?.authorizationSha256 ||
    document.evidenceIds?.join('\0') !== ['EVD-E7-42', 'EVD-E7-43', 'EVD-E7-44'].join('\0') ||
    document.externalRequests !== document.requests?.ownedOrigin ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false ||
    passiveAuthorizationId === undefined
  ) {
    fail('E7_QUALITY_CHECKPOINT_INVALID');
  }
  try {
    validateQualityPayload(payload);
    validateAuthorizationUsageEnvelope({
      usage: document.authorizationUsage,
      scope: 'full',
      identity,
      config,
      authorizationSha256: authorization.authorizationSha256,
      ownedOriginSha256: authorization.ownedOriginSha256,
      sandboxHostSha256: authorization.sandboxHostSha256,
      usageId: 'QUALITY_FOCAL',
      requestCounts: Object.fromEntries(
        externalAuthorizationRequirements('full').map(({ id }) => [
          id,
          id === passiveAuthorizationId ? document.requests.ownedOrigin : 0,
        ]),
      ),
    });
  } catch (error) {
    if (
      error instanceof Stage7QualityError ||
      (error instanceof Stage7ControlError &&
        error.code === 'E7_AUTHORIZATION_USAGE_ENVELOPE_INVALID')
    ) {
      fail('E7_QUALITY_CHECKPOINT_INVALID');
    }
    throw error;
  }
  return document;
};

const validateZapSummaryCheckpoint = (zap) => {
  if (
    !exactKeys(zap, [
      'mode',
      'tool',
      'rulesetSha256',
      'reportSha256',
      'inventorySha256',
      'captureSha256',
      'openApiRawSha256',
      'observationsSha256',
      'ownEndpointsScanned',
      'ownEndpointsOutOfScope',
      'findings',
      'manualValidation',
      'budgetEnforcement',
    ]) ||
    zap.mode !== 'PASSIVE_BASELINE' ||
    !exactKeys(zap.tool, ['name', 'version']) ||
    zap.tool.name !== 'OWASP_ZAP_BASELINE' ||
    zap.tool.version !== '2.16.1' ||
    ![
      zap.rulesetSha256,
      zap.reportSha256,
      zap.inventorySha256,
      zap.captureSha256,
      zap.openApiRawSha256,
      zap.observationsSha256,
    ].every((value) => SHA256.test(value ?? '')) ||
    zap.ownEndpointsScanned !== ZAP_PASSIVE_REQUEST_COUNT ||
    zap.ownEndpointsOutOfScope !== 0 ||
    !exactKeys(zap.findings, [
      'total',
      'reviewed',
      'critical',
      'high',
      'medium',
      'low',
      'informational',
    ]) ||
    Object.values(zap.findings).some((value) => value !== 0) ||
    zap.manualValidation !== 'ALL_ALERTS_REVIEWED' ||
    zap.budgetEnforcement !== 'ENFORCED_BEFORE_EGRESS'
  ) {
    fail('E7_EDGE_ZAP_CHECKPOINT_INVALID');
  }
  return zap;
};

const edgeUrlsAreExact = (urls, applicationOrigin) =>
  exactKeys(urls, ['application', 'api', 'docs', 'health']) &&
  urls.application === applicationOrigin &&
  urls.api === `${applicationOrigin}/api` &&
  urls.docs === `${applicationOrigin}/api/docs` &&
  urls.health === `${applicationOrigin}/api/health/ready`;

const validatePrereleaseEdgeCapability = ({ capability, document }) => {
  const passive = capability?.passiveSecurity;
  const expectedHeaderChecks = [
    ['AUTH03-E6-HDR-01', 'content-security-policy'],
    ['AUTH03-E6-HDR-02', 'referrer-policy'],
    ['AUTH03-E6-HDR-03', 'x-content-type-options'],
    ['AUTH03-E6-HDR-04', 'clickjacking-protection'],
    ['AUTH03-E6-HDR-05', 'permissions-policy'],
    ['AUTH03-E6-HDR-06', 'strict-transport-security'],
  ];
  if (
    !exactKeys(capability, ['passiveSecurity']) ||
    !exactKeys(passive, [
      'status',
      'authorization',
      'target',
      'headerChecks',
      'sensitiveResponsesNoStore',
      'criticalHeadersMissing',
      'zap',
      'requests',
      'evidenceIds',
    ]) ||
    passive.status !== 'PASS' ||
    !exactKeys(passive.authorization, [
      'id',
      'status',
      'scope',
      'approvalSha256',
      'approvedTargetSha256',
      'approvedAtUtc',
      'expiresAtUtc',
      'ownerAlias',
      'maxRequests',
    ]) ||
    passive.authorization.id !== 'AUTH-E6-03' ||
    passive.authorization.status !== 'APPROVED' ||
    passive.authorization.scope !== 'PASSIVE_BASELINE_OWNED_QA_ONLY' ||
    passive.authorization.approvedTargetSha256 !==
      document.externalAuthorization.ownedOriginSha256 ||
    !exactKeys(passive.target, [
      'classification',
      'environment',
      'originSha256',
      'ownershipVerified',
      'production',
    ]) ||
    passive.target.classification !== 'OWNED_EPHEMERAL_QA' ||
    passive.target.environment !== 'ENV-E6-QA' ||
    passive.target.originSha256 !== document.externalAuthorization.ownedOriginSha256 ||
    passive.target.ownershipVerified !== true ||
    passive.target.production !== false ||
    !Array.isArray(passive.headerChecks) ||
    passive.headerChecks.length !== expectedHeaderChecks.length ||
    passive.headerChecks.some(
      (entry, index) =>
        !exactKeys(entry, ['id', 'name', 'status']) ||
        entry.id !== expectedHeaderChecks[index][0] ||
        entry.name !== expectedHeaderChecks[index][1] ||
        entry.status !== 'PASS',
    ) ||
    passive.sensitiveResponsesNoStore !== true ||
    passive.criticalHeadersMissing !== 0 ||
    objectSha256(passive.zap) !== objectSha256(document.zap) ||
    !exactKeys(passive.requests, [
      'total',
      'outsideAllowlist',
      'provider',
      'production',
      'externalRedirectsFollowed',
      'activeScan',
    ]) ||
    passive.requests.total !== document.requests.ownedOrigin + document.requests.zap ||
    passive.requests.outsideAllowlist !== 0 ||
    passive.requests.provider !== 0 ||
    passive.requests.production !== 0 ||
    passive.requests.externalRedirectsFollowed !== 0 ||
    passive.requests.activeScan !== 0 ||
    passive.evidenceIds?.join('\0') !== ['AUTH-E6-03', 'EVD-E6-33', 'EVD-E6-34'].join('\0')
  ) {
    fail('E7_PRERELEASE_EDGE_CAPABILITY_INVALID');
  }
  return capability;
};

const validateEdgeSecurityCheckpoint = ({
  document,
  scope,
  identity,
  config,
  authorization,
  applicationOrigin,
}) => {
  const expectedKeys = [
    'schemaVersion',
    'stage',
    'kind',
    'status',
    'scope',
    'candidateSha',
    'releaseId',
    'urls',
    'httpRedirect',
    'httpsDocument',
    'mixedContentRequests',
    'headers',
    'sensitiveResponsesNoStore',
    'corsExact',
    'directS3Denied',
    'tlsBaseline',
    'zap',
    ...(scope === 'prerelease' ? ['stage6Capability'] : []),
    'externalAuthorization',
    'authorizationUsage',
    'requests',
    ...(scope === 'full' ? ['requestBudgetComponents'] : []),
    'externalRequests',
    'mutationsPerformed',
    'containsSensitiveData',
  ];
  const expectedAuthorizationIds = externalAuthorizationRequirements(scope).map(({ id }) => id);
  const passiveAuthorizationId = externalAuthorizationRequirements(scope).find(
    ({ key }) => key === 'passiveSecurity',
  )?.id;
  const externalAuthorization = document?.externalAuthorization;
  const expectedExternalAuthorization = authorization ?? externalAuthorization;
  const expectedHeaders = [...REQUIRED_HEADERS, 'clickjacking'];
  if (
    !exactKeys(document, expectedKeys) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'DEPLOYED_EDGE_SECURITY' ||
    document.status !== 'PASS' ||
    document.scope !== scope ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    !edgeUrlsAreExact(document.urls, applicationOrigin) ||
    document.httpRedirect !== 'PASS' ||
    document.httpsDocument !== 'PASS' ||
    document.mixedContentRequests !== 0 ||
    !exactKeys(document.headers, expectedHeaders) ||
    Object.values(document.headers).some((value) => value !== 'PASS') ||
    document.sensitiveResponsesNoStore !== true ||
    document.corsExact !== true ||
    document.directS3Denied !== (scope === 'full' ? 'PASS' : 'NOT_RUN_PRERELEASE') ||
    document.tlsBaseline !==
      (config.domain.mode === 'CUSTOM_AUTHORIZED' ? 'TLS12_CONFIGURED' : 'PRERELEASE_LIMITED') ||
    !exactKeys(externalAuthorization, [
      'authorizationSha256',
      'authorizationIds',
      'ownedOriginSha256',
      'sandboxHostSha256',
    ]) ||
    ![
      externalAuthorization.authorizationSha256,
      externalAuthorization.ownedOriginSha256,
      externalAuthorization.sandboxHostSha256,
    ].every((value) => SHA256.test(value ?? '')) ||
    externalAuthorization.authorizationIds?.join('\0') !== expectedAuthorizationIds.join('\0') ||
    externalAuthorization.ownedOriginSha256 !== digest(applicationOrigin) ||
    externalAuthorization.authorizationSha256 !==
      expectedExternalAuthorization?.authorizationSha256 ||
    externalAuthorization.ownedOriginSha256 !== expectedExternalAuthorization?.ownedOriginSha256 ||
    externalAuthorization.sandboxHostSha256 !== expectedExternalAuthorization?.sandboxHostSha256 ||
    !exactKeys(document.requests, ['ownedOrigin', 'directS3', 'awsPrivateOrigin', 'zap']) ||
    document.requests.ownedOrigin !== 6 ||
    document.requests.directS3 !== 0 ||
    document.requests.awsPrivateOrigin !== (scope === 'full' ? 2 : 0) ||
    document.requests.zap !== ZAP_PASSIVE_REQUEST_COUNT ||
    document.externalRequests !==
      document.requests.ownedOrigin +
        document.requests.directS3 +
        document.requests.awsPrivateOrigin +
        document.requests.zap +
        2 ||
    document.mutationsPerformed !== 0 ||
    document.containsSensitiveData !== false ||
    passiveAuthorizationId === undefined
  ) {
    fail('E7_EDGE_SECURITY_CHECKPOINT_INVALID');
  }
  try {
    validateZapSummaryCheckpoint(document.zap);
    validateAuthorizationUsageEnvelope({
      usage: document.authorizationUsage,
      scope,
      identity,
      config,
      authorizationSha256: externalAuthorization.authorizationSha256,
      ownedOriginSha256: externalAuthorization.ownedOriginSha256,
      sandboxHostSha256: externalAuthorization.sandboxHostSha256,
      usageId: 'EDGE_PASSIVE',
      requestCounts: Object.fromEntries(
        expectedAuthorizationIds.map((id) => [
          id,
          id === passiveAuthorizationId ? document.requests.ownedOrigin + document.requests.zap : 0,
        ]),
      ),
    });
    if (scope === 'full') {
      const components = document.requestBudgetComponents;
      if (
        !exactKeys(components, ['direct', 'zap']) ||
        !exactKeys(components.direct, ['componentId', 'requestCounts']) ||
        components.direct.componentId !== 'EDGE_PASSIVE_DIRECT' ||
        !exactKeys(components.zap, ['componentId', 'requestCounts']) ||
        components.zap.componentId !== 'EDGE_PASSIVE_ZAP_EXACT_INVENTORY' ||
        !exactKeys(components.direct.requestCounts, expectedAuthorizationIds) ||
        !exactKeys(components.zap.requestCounts, expectedAuthorizationIds) ||
        expectedAuthorizationIds.some(
          (id) =>
            components.direct.requestCounts[id] !==
              (id === passiveAuthorizationId ? document.requests.ownedOrigin : 0) ||
            components.zap.requestCounts[id] !==
              (id === passiveAuthorizationId ? document.requests.zap : 0),
        )
      ) {
        fail('E7_EDGE_SECURITY_CHECKPOINT_INVALID');
      }
    } else {
      validatePrereleaseEdgeCapability({ capability: document.stage6Capability, document });
    }
  } catch (error) {
    if (
      error instanceof Stage7ControlError &&
      [
        'E7_EDGE_ZAP_CHECKPOINT_INVALID',
        'E7_AUTHORIZATION_USAGE_ENVELOPE_INVALID',
        'E7_PRERELEASE_EDGE_CAPABILITY_INVALID',
      ].includes(error.code)
    ) {
      fail('E7_EDGE_SECURITY_CHECKPOINT_INVALID');
    }
    throw error;
  }
  return document;
};

const validateSandboxPayloadCheckpoint = ({ checks, requests, result, referenceSha256 }) => {
  const expectedChecks = [
    ['AUTH02-E6-01', 'acceptance-configuration-observed'],
    ['AUTH02-E6-02', 'authorized-test-payment-method-created'],
    ['AUTH02-E6-03', 'local-pending-created-first'],
    ['AUTH02-E6-04', 'provider-sandbox-transaction-created'],
    ['AUTH02-E6-05', 'provider-status-polled'],
    ['AUTH02-E6-06', 'amount-currency-reference-validated'],
    ['AUTH02-E6-07', 'provider-errors-redacted'],
    ['AUTH02-E6-08', 'reconciliation-replay-idempotent'],
  ];
  if (
    !Array.isArray(checks) ||
    checks.length !== expectedChecks.length ||
    checks.some(
      (entry, index) =>
        !exactKeys(entry, ['id', 'name', 'status']) ||
        entry.id !== expectedChecks[index][0] ||
        entry.name !== expectedChecks[index][1] ||
        entry.status !== 'PASS',
    ) ||
    !SHA256.test(referenceSha256 ?? '') ||
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
    ![
      requests.configurationReads,
      requests.paymentMethodCreations,
      requests.transactionCreates,
      requests.statusReads,
      requests.errorMappingProbes,
      requests.reconciliationReplays,
    ].every((value) => Number.isSafeInteger(value) && value >= 0) ||
    requests.configurationReads !== 3 ||
    requests.paymentMethodCreations !== 1 ||
    requests.transactionCreates !== 1 ||
    requests.statusReads < 1 ||
    requests.errorMappingProbes < 1 ||
    requests.reconciliationReplays < 1 ||
    requests.total !==
      requests.configurationReads +
        requests.paymentMethodCreations +
        requests.transactionCreates +
        requests.statusReads +
        requests.errorMappingProbes +
        requests.reconciliationReplays ||
    requests.total !== 8 ||
    requests.production !== 0 ||
    requests.globalMutations !== 0 ||
    requests.outsideAllowlist !== 0 ||
    !exactKeys(result, [
      'providerState',
      'localState',
      'amountMatches',
      'currencyMatches',
      'referenceMatches',
      'reconciliationConsistent',
      'duplicateEffects',
      'adapterDisabledByConfiguration',
    ]) ||
    !['APPROVED', 'DECLINED', 'ERROR', 'PENDING'].includes(result.providerState) ||
    result.localState !== result.providerState ||
    result.amountMatches !== true ||
    result.currencyMatches !== true ||
    result.referenceMatches !== true ||
    result.reconciliationConsistent !== true ||
    result.duplicateEffects !== 0 ||
    result.adapterDisabledByConfiguration !== true
  ) {
    fail('E7_SANDBOX_PAYLOAD_CHECKPOINT_INVALID');
  }
  return { checks, requests, result };
};

const validatePrereleaseSandboxCapability = ({ capability, document }) => {
  const sandbox = capability?.sandboxSmoke;
  if (
    !exactKeys(capability, ['sandboxSmoke']) ||
    !exactKeys(sandbox, [
      'status',
      'authorization',
      'target',
      'reference',
      'checks',
      'requests',
      'result',
      'evidenceIds',
      'reportSha256',
    ]) ||
    sandbox.status !== 'PASS' ||
    objectSha256(sandbox.authorization) !==
      objectSha256(document.externalAuthorization.authorization) ||
    !exactKeys(sandbox.target, [
      'classification',
      'environment',
      'hostSha256',
      'allowlistVerified',
      'production',
    ]) ||
    sandbox.target.classification !== 'AUTHORIZED_PROVIDER_SANDBOX' ||
    sandbox.target.environment !== 'sandbox' ||
    sandbox.target.hostSha256 !== document.sandboxHostSha256 ||
    sandbox.target.allowlistVerified !== true ||
    sandbox.target.production !== false ||
    !exactKeys(sandbox.reference, ['prefix', 'sha256', 'runScoped', 'rawValueCaptured']) ||
    sandbox.reference.prefix !== 'e6-' ||
    sandbox.reference.sha256 !== document.referenceSha256 ||
    sandbox.reference.runScoped !== true ||
    sandbox.reference.rawValueCaptured !== false ||
    objectSha256(sandbox.checks) !== objectSha256(document.checks) ||
    objectSha256(sandbox.requests) !== objectSha256(document.requests) ||
    objectSha256(sandbox.result) !== objectSha256(document.result) ||
    sandbox.evidenceIds?.join('\0') !== ['AUTH-E6-02', 'EVD-E6-24', 'ART-VER-07'].join('\0') ||
    !SHA256.test(sandbox.reportSha256 ?? '')
  ) {
    fail('E7_PRERELEASE_SANDBOX_CAPABILITY_INVALID');
  }
  return capability;
};

const validateSandboxCheckpoint = ({
  document,
  scope,
  identity,
  config,
  freezeManifest,
  authorization,
  applicationOrigin,
}) => {
  const expectedKeys = [
    'schemaVersion',
    'stage',
    'kind',
    'status',
    'scope',
    'candidateSha',
    'releaseId',
    'manifestSha256',
    'stage7ConfigSha256',
    'executedAtUtc',
    'reviewerAlias',
    'targetOriginSha256',
    'sandboxHostSha256',
    'externalAuthorization',
    'authorizationUsage',
    'stage6Authorization',
    'oneUseExecution',
    'checks',
    'referenceSha256',
    'requests',
    'result',
    'productionRequests',
    'duplicateEffects',
    ...(scope === 'prerelease'
      ? [
          'stage6Capability',
          'watchdogLiveAuthoritySha256',
          'watchdogDefaultBranchHeadSha256',
          'watchdogApiRequests',
          'watchdogVerifiedAtUtc',
          'watchdogVerificationPhase',
        ]
      : []),
    'externalRequests',
    'mutationsPerformed',
    'containsSensitiveData',
  ];
  const authorizationIds = externalAuthorizationRequirements(scope).map(({ id }) => id);
  const sandboxAuthorizationId = externalAuthorizationRequirements(scope).find(
    ({ key }) => key === 'sandboxSmoke',
  )?.id;
  const externalAuthorization = document?.externalAuthorization;
  const stage7Authorization = externalAuthorization?.authorization;
  const expectedAuthorizationSha256 =
    authorization?.authorizationSha256 ?? externalAuthorization?.authorizationSha256;
  const expectedOwnedOriginSha256 =
    authorization?.ownedOriginSha256 ?? document?.targetOriginSha256;
  const expectedSandboxHostSha256 = authorization?.sandboxHostSha256 ?? document?.sandboxHostSha256;
  if (
    !exactKeys(document, expectedKeys) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'AUTHORIZED_SANDBOX_SMOKE' ||
    document.status !== 'PASS' ||
    document.scope !== scope ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.manifestSha256 !== freezeManifest?.manifestSha256 ||
    document.stage7ConfigSha256 !== objectSha256(config) ||
    !utc(document.executedAtUtc) ||
    !/^[a-z][a-z0-9-]{2,31}$/u.test(document.reviewerAlias ?? '') ||
    document.targetOriginSha256 !== digest(applicationOrigin) ||
    document.targetOriginSha256 !== expectedOwnedOriginSha256 ||
    document.sandboxHostSha256 !== digest(SANDBOX_HOST) ||
    document.sandboxHostSha256 !== expectedSandboxHostSha256 ||
    !exactKeys(externalAuthorization, ['authorizationSha256', 'authorization']) ||
    !SHA256.test(externalAuthorization.authorizationSha256 ?? '') ||
    externalAuthorization.authorizationSha256 !== expectedAuthorizationSha256 ||
    !exactKeys(stage7Authorization, [
      'id',
      'status',
      'scope',
      'approvalSha256',
      'approvedTargetSha256',
      'approvedAtUtc',
      'expiresAtUtc',
      'ownerAlias',
      'maxRequests',
    ]) ||
    stage7Authorization.id !== sandboxAuthorizationId ||
    stage7Authorization.status !== 'APPROVED' ||
    stage7Authorization.scope !== 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE' ||
    !SHA256.test(stage7Authorization.approvalSha256 ?? '') ||
    stage7Authorization.approvedTargetSha256 !== document.sandboxHostSha256 ||
    !utc(stage7Authorization.approvedAtUtc) ||
    !utc(stage7Authorization.expiresAtUtc) ||
    Date.parse(stage7Authorization.approvedAtUtc) > Date.parse(document.executedAtUtc) ||
    Date.parse(stage7Authorization.expiresAtUtc) < Date.parse(document.executedAtUtc) ||
    !/^[a-z][a-z0-9-]{2,31}$/u.test(stage7Authorization.ownerAlias ?? '') ||
    !Number.isSafeInteger(stage7Authorization.maxRequests) ||
    stage7Authorization.maxRequests < document.requests?.total ||
    !exactKeys(document.stage6Authorization, [
      'authorizationId',
      'authorizationSha256',
      'runId',
      'fixtureSha256',
      'rawFixtureCaptured',
    ]) ||
    document.stage6Authorization.authorizationId !== 'AUTH-E6-02' ||
    !SHA256.test(document.stage6Authorization.authorizationSha256 ?? '') ||
    !/^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u.test(document.stage6Authorization.runId ?? '') ||
    !SHA256.test(document.stage6Authorization.fixtureSha256 ?? '') ||
    document.stage6Authorization.rawFixtureCaptured !== false ||
    document.productionRequests !== 0 ||
    document.duplicateEffects !== 0 ||
    document.externalRequests !== document.requests?.total ||
    document.mutationsPerformed !== document.requests?.transactionCreates ||
    document.containsSensitiveData !== false ||
    sandboxAuthorizationId === undefined
  ) {
    fail('E7_SANDBOX_CHECKPOINT_INVALID');
  }
  try {
    validateSandboxPayloadCheckpoint({
      checks: document.checks,
      requests: document.requests,
      result: document.result,
      referenceSha256: document.referenceSha256,
    });
    validateAuthorizationUsageEnvelope({
      usage: document.authorizationUsage,
      scope,
      identity,
      config,
      authorizationSha256: externalAuthorization.authorizationSha256,
      ownedOriginSha256: document.targetOriginSha256,
      sandboxHostSha256: document.sandboxHostSha256,
      usageId: 'SANDBOX_ONE_USE',
      requestCounts: Object.fromEntries(
        authorizationIds.map((id) => [
          id,
          id === sandboxAuthorizationId ? document.requests.total : 0,
        ]),
      ),
    });
    validateSandboxExecutionEvidence(document.oneUseExecution, {
      scope,
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      configSha256: objectSha256(config),
      referenceSha256: document.referenceSha256,
      stage6AuthorizationSha256: document.stage6Authorization.authorizationSha256,
    });
    if (scope === 'prerelease') {
      validatePrereleaseSandboxCapability({ capability: document.stage6Capability, document });
      if (
        !SHA256.test(document.watchdogLiveAuthoritySha256 ?? '') ||
        !SHA256.test(document.watchdogDefaultBranchHeadSha256 ?? '') ||
        !Number.isSafeInteger(document.watchdogApiRequests) ||
        document.watchdogApiRequests !== 3 ||
        !utc(document.watchdogVerifiedAtUtc) ||
        document.watchdogVerificationPhase !== 'sandbox'
      ) {
        fail('E7_SANDBOX_CHECKPOINT_INVALID');
      }
    }
  } catch (error) {
    if (
      error instanceof Stage7ControlError ||
      error?.code === 'E7_SANDBOX_EXECUTION_EVIDENCE_INVALID'
    ) {
      fail('E7_SANDBOX_CHECKPOINT_INVALID');
    }
    throw error;
  }
  return document;
};

const validateProtectedApprovalCheckpoint = (document, scope, identity, config) => {
  const expectedReleaseTag = scope === 'full' ? identity.releaseTag : null;
  const expectedEnvironment = scope === 'full' ? 'assessment-release' : 'assessment-prerelease';
  if (
    !exactKeys(document, PROTECTED_APPROVAL_KEYS) ||
    document.schemaVersion !== 1 ||
    document.stage !== 7 ||
    document.kind !== 'PROTECTED_RELEASE_APPROVAL' ||
    document.status !== 'PASS' ||
    document.scope !== scope ||
    document.candidateSha !== identity.candidateSha ||
    document.releaseId !== identity.releaseId ||
    document.releaseTag !== expectedReleaseTag ||
    document.configSha256 !== objectSha256(config) ||
    ![
      document.cloudAssemblySha256,
      document.freezeManifestSha256,
      document.approvedPlanSha256,
      document.approvedDiffSha256,
      document.iamEffectivePermissionsBindingSha256,
      document.iamEffectivePermissionsEvidenceSha256,
    ].every((value) => SHA256.test(value ?? '')) ||
    (scope === 'full'
      ? ![
          document.journalRoleEffectivePermissionsRawSha256,
          document.journalRoleEffectivePermissionsSha256,
        ].every((value) => SHA256.test(value ?? ''))
      : document.journalRoleEffectivePermissionsRawSha256 !== null ||
        document.journalRoleEffectivePermissionsSha256 !== null) ||
    (scope === 'full'
      ? !document.reconciliationRecoveryRoleArn?.startsWith(
          `arn:aws:iam::${config.aws.accountId}:role/`,
        ) ||
        !document.reconciliationRecoveryPermissionsBoundaryArn?.startsWith(
          `arn:aws:iam::${config.aws.accountId}:policy/`,
        ) ||
        RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.slice(2).some(
          (field) => !SHA256.test(document[field] ?? ''),
        )
      : RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.some(
          (field) => document[field] !== null,
        )) ||
    !utc(document.approvedAtUtc) ||
    Date.parse(document.approvedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(document.approvedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    document.statefulReplacements !== 0 ||
    document.destructiveChanges !== 0 ||
    document.humanReviewConfirmed !== true ||
    document.explicitDispatchConfirmation !== true ||
    document.protectedEnvironment !== true ||
    document.protectedEnvironmentName !== expectedEnvironment ||
    document.nonPublic !== (scope === 'prerelease') ||
    document.accountSha256 !== digest(config.aws.accountId) ||
    document.accountSuffix !== config.aws.accountId.slice(-4) ||
    document.region !== config.aws.region ||
    document.stacks?.join('\0') !== config.authorization.stacks.join('\0') ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_PROTECTED_APPROVAL_CHECKPOINT_INVALID');
  }
  return document;
};

const validateBoundGithubEnvironmentApproval = ({ document, scope, identity, map }) => {
  const metadataBasename = scope === 'full' ? 'release-metadata.json' : 'metadata.json';
  const metadataFilename = map.get(metadataBasename);
  const rawDiffFilename = map.get('infra-diff.txt');
  if (metadataFilename === undefined || rawDiffFilename === undefined) {
    fail('E7_PROTECTED_GITHUB_APPROVAL_BINDING_MISSING');
  }
  const metadata = passEvidence(map, metadataBasename, identity);
  if (!RUN_ID.test(metadata.releaseRunId ?? '') || metadata.releaseRunAttempt !== 1) {
    fail('E7_PROTECTED_GITHUB_APPROVAL_ORIGIN_INVALID');
  }
  try {
    validateGithubEnvironmentApproval(document, {
      repository: 'ivanmonsalve0404/async-checkout-demo',
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      runId: metadata.releaseRunId,
      runAttempt: metadata.releaseRunAttempt,
      environment: scope === 'full' ? 'assessment-release' : 'assessment-prerelease',
      diffSha256: fileDigest(rawDiffFilename),
    });
  } catch (error) {
    if (error instanceof GithubEnvironmentApprovalError) {
      fail('E7_PROTECTED_GITHUB_APPROVAL_INVALID');
    }
    throw error;
  }
  return document;
};

const validateSuccessfulProducerCheckpoint = ({
  scope,
  map,
  identity,
  config,
  basename,
  expectedJobExecution,
}) => {
  const filename = map.get(basename);
  if (filename === undefined || STAGE7_SOURCE_PRODUCERS[scope]?.[basename] === undefined) {
    fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_MISSING');
  }
  // Constructing the source reference binds the raw bytes to the static
  // producer/artifact/path contract before any semantic status can be claimed.
  provenanceSource(map, scope, basename);

  if (basename === 'infra-diff.txt') {
    const source = readFileSync(checkedWorkspacePath(filename, { directory: false }));
    if (source.length === 0 || source.length > 16 * 1024 * 1024) {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    try {
      assertSanitizedArtifactText('stage7-infra-diff.txt', source.toString('utf8'));
    } catch {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    const diffFilename = map.get('infra-diff.json');
    if (diffFilename === undefined) fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    const diff = validateDiffReview(readEvidence(diffFilename), scope, identity, config);
    if (digest(source) !== diff.rawDiffArtifactSha256) {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    return true;
  }

  if (basename === 'stage6-closeout.json') {
    const metadataBasename = scope === 'full' ? 'release-metadata.json' : 'metadata.json';
    const metadataFilename = map.get(metadataBasename);
    const manifestFilename = map.get('candidate-manifest.json');
    if (metadataFilename === undefined || manifestFilename === undefined) {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    const metadata = readEvidence(metadataFilename);
    validateJobAuthorityReleaseOrigin(metadata, expectedJobExecution);
    validateStage6CloseoutBinding({
      map,
      identity,
      metadata,
      freezeManifest: validateFreezeManifest(readEvidence(manifestFilename)),
      scope,
    });
    return true;
  }

  if (basename === 'verify-candidate.json') {
    const metadataBasename = scope === 'full' ? 'release-metadata.json' : 'metadata.json';
    const metadataFilename = map.get(metadataBasename);
    const manifestFilename = map.get('candidate-manifest.json');
    if (metadataFilename === undefined || manifestFilename === undefined) return false;
    const metadata = passEvidence(map, metadataBasename, identity);
    validateJobAuthorityReleaseOrigin(metadata, expectedJobExecution);
    validateCandidateVerificationCheckpoint({
      document: readEvidence(filename),
      scope,
      identity,
      metadata,
      freezeManifest: validateFreezeManifest(readEvidence(manifestFilename)),
    });
    return true;
  }

  if (basename === 'checksums-sbom.json') {
    const manifestFilename = map.get('candidate-manifest.json');
    if (manifestFilename === undefined) return false;
    validateChecksumsInventoryCheckpoint({
      document: readEvidence(filename),
      scope,
      identity,
      freezeManifest: validateFreezeManifest(readEvidence(manifestFilename)),
    });
    return true;
  }

  if (basename === 'security.json') {
    validateSecurityCheckpoint({ document: readEvidence(filename), scope, identity });
    return true;
  }

  if (basename === 'prefreeze.json') {
    const manifestFilename = map.get('candidate-manifest.json');
    if (scope !== 'full' || manifestFilename === undefined) return false;
    validatePreFreezeCheckpoint({
      document: readEvidence(filename),
      sourceFilename: filename,
      identity,
      config,
      freezeManifest: validateFreezeManifest(readEvidence(manifestFilename)),
    });
    return true;
  }

  if (basename === 'candidate-manifest.json') {
    const manifest = validateFreezeManifest(readEvidence(filename));
    if (
      manifest.candidateSha !== identity.candidateSha ||
      manifest.candidateTreeSha !== identity.treeSha ||
      manifest.releaseId !== identity.releaseId ||
      manifest.releaseTag !== (scope === 'full' ? identity.releaseTag : null) ||
      manifest.configSha256 !== objectSha256(config) ||
      manifest.releaseMode !== (scope === 'full' ? 'VERSIONED_UPDATE' : 'INITIAL')
    ) {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    return true;
  }

  if (basename === 'infra-synth.json') {
    const manifestFilename = map.get('candidate-manifest.json');
    const releasePlanFilename = map.get('release-plan.json');
    const diffFilename = map.get('infra-diff.json');
    if (
      manifestFilename === undefined ||
      releasePlanFilename === undefined ||
      diffFilename === undefined
    ) {
      return false;
    }
    const freezeManifest = validateFreezeManifest(readEvidence(manifestFilename));
    const releasePlan = validateReleasePlanCheckpoint(
      readEvidence(releasePlanFilename),
      scope,
      identity,
      config,
    );
    const diff = validateDiffReview(readEvidence(diffFilename), scope, identity, config);
    validateInfraSynthCheckpoint({
      document: readEvidence(filename),
      scope,
      identity,
      freezeManifest,
      releasePlan,
      diff,
    });
    return true;
  }

  if (basename === 'external-authorization.json') {
    validateExternalAuthorizationCheckpoint({
      document: readEvidence(filename),
      scope,
      identity,
      config,
    });
    return true;
  }

  if (basename === 'deployment.json') {
    if (scope !== 'prerelease') return false;
    deploymentTarget(path.dirname(filename), config, identity);
    return true;
  }

  if (basename === 'release-plan.json') {
    validateReleasePlanCheckpoint(readEvidence(filename), scope, identity, config);
    return true;
  }

  if (basename === 'infra-diff.json') {
    validateDiffReview(readEvidence(filename), scope, identity, config);
    return true;
  }

  if (basename === 'github-environment-approval.json') {
    validateBoundGithubEnvironmentApproval({
      document: readEvidence(filename),
      scope,
      identity,
      map,
    });
    const metadataBasename = scope === 'full' ? 'release-metadata.json' : 'metadata.json';
    validateJobAuthorityReleaseOrigin(
      readEvidence(map.get(metadataBasename)),
      expectedJobExecution,
    );
    return true;
  }

  if (basename === 'approval.json') {
    validateProtectedApprovalCheckpoint(readEvidence(filename), scope, identity, config);
    return true;
  }

  if (Object.hasOwn(OPERATION_CHECKPOINT_BY_BASENAME, basename)) {
    const checkpointName = OPERATION_CHECKPOINT_BY_BASENAME[basename];
    const operation = operationEvidence(map, basename, checkpointName, identity, config);
    const manifestFilename = map.get('candidate-manifest.json');
    if (manifestFilename === undefined) fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    const manifest = validateFreezeManifest(readEvidence(manifestFilename));
    if (['data', 'api', 'observability', 'web'].includes(checkpointName)) {
      deployedCheckpoint(operation, checkpointName, checkpointName, identity, config, manifest);
    } else if (checkpointName === 'activation') {
      validateStage7ActivationCheckpoint(operation.checkpoints.activation, {
        config,
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        manifestSha256: manifest.manifestSha256,
        complete: true,
      });
    } else {
      const activationFilename = map.get('activation.json');
      if (activationFilename === undefined) fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
      const activation = operationEvidence(map, 'activation.json', 'activation', identity, config);
      const activationCheckpoint = validateStage7ActivationCheckpoint(
        activation.checkpoints.activation,
        {
          config,
          candidateSha: identity.candidateSha,
          releaseId: identity.releaseId,
          manifestSha256: manifest.manifestSha256,
          complete: true,
        },
      );
      validateStage7DriftCheckpoint(operation.checkpoints.drift, {
        config,
        manifestSha256: manifest.manifestSha256,
        assemblySha256: activationCheckpoint.assemblySha256,
      });
    }
    return true;
  }

  if (basename === 'aws-auth.json') {
    const document = passEvidence(map, basename, identity);
    const manifestFilename = map.get('candidate-manifest.json');
    const journalRoleEffectivePermissionsFilename = map.get(
      RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
    );
    const reconciliationRecoveryRoleEffectivePermissionsFilename = map.get(
      RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
    );
    if (
      manifestFilename === undefined ||
      (scope === 'full' &&
        (journalRoleEffectivePermissionsFilename === undefined ||
          reconciliationRecoveryRoleEffectivePermissionsFilename === undefined))
    ) {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    const manifest = validateFreezeManifest(readEvidence(manifestFilename));
    validateAwsAuthEffectivePermissions({
      value: document,
      valueSource: readEvidenceSource(filename),
      journalRoleEffectivePermissionsSource:
        scope === 'full' ? readEvidenceSource(journalRoleEffectivePermissionsFilename) : undefined,
      reconciliationRecoveryRoleEffectivePermissionsSource:
        scope === 'full'
          ? readEvidenceSource(reconciliationRecoveryRoleEffectivePermissionsFilename)
          : undefined,
      config,
      scope,
      identity,
      manifestSha256: manifest.manifestSha256,
    });
    return true;
  }

  if (basename === RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME) {
    const awsAuthFilename = map.get('aws-auth.json');
    const manifestFilename = map.get('candidate-manifest.json');
    const reconciliationRecoveryRoleEffectivePermissionsFilename = map.get(
      RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
    );
    if (
      scope !== 'full' ||
      awsAuthFilename === undefined ||
      manifestFilename === undefined ||
      reconciliationRecoveryRoleEffectivePermissionsFilename === undefined
    ) {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    const manifest = validateFreezeManifest(readEvidence(manifestFilename));
    validateAwsAuthEffectivePermissions({
      value: readEvidence(awsAuthFilename),
      valueSource: readEvidenceSource(awsAuthFilename),
      journalRoleEffectivePermissionsSource: readEvidenceSource(filename),
      reconciliationRecoveryRoleEffectivePermissionsSource: readEvidenceSource(
        reconciliationRecoveryRoleEffectivePermissionsFilename,
      ),
      config,
      scope,
      identity,
      manifestSha256: manifest.manifestSha256,
    });
    return true;
  }

  if (basename === RELEASE_RECONCILIATION_RECOVERY_ROLE_EFFECTIVE_PERMISSIONS_BASENAME) {
    const awsAuthFilename = map.get('aws-auth.json');
    const manifestFilename = map.get('candidate-manifest.json');
    const journalRoleEffectivePermissionsFilename = map.get(
      RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME,
    );
    if (
      scope !== 'full' ||
      awsAuthFilename === undefined ||
      manifestFilename === undefined ||
      journalRoleEffectivePermissionsFilename === undefined
    ) {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    const manifest = validateFreezeManifest(readEvidence(manifestFilename));
    validateAwsAuthEffectivePermissions({
      value: readEvidence(awsAuthFilename),
      valueSource: readEvidenceSource(awsAuthFilename),
      journalRoleEffectivePermissionsSource: readEvidenceSource(
        journalRoleEffectivePermissionsFilename,
      ),
      reconciliationRecoveryRoleEffectivePermissionsSource: readEvidenceSource(filename),
      config,
      scope,
      identity,
      manifestSha256: manifest.manifestSha256,
    });
    return true;
  }

  if (basename === 'quality.json') {
    const manifestFilename = map.get('candidate-manifest.json');
    const authorizationFilename = map.get('external-authorization.json');
    const webFilename = map.get('web.json');
    if (
      scope !== 'full' ||
      manifestFilename === undefined ||
      authorizationFilename === undefined ||
      webFilename === undefined
    ) {
      return false;
    }
    const freezeManifest = validateFreezeManifest(readEvidence(manifestFilename));
    const webDocument = operationEvidence(map, 'web.json', 'web', identity, config);
    const web = deployedCheckpoint(webDocument, 'web', 'web', identity, config, freezeManifest);
    validateQualityCheckpoint({
      document: readEvidence(filename),
      identity,
      config,
      freezeManifest,
      authorization: validateExternalAuthorizationCheckpoint({
        document: readEvidence(authorizationFilename),
        scope: 'full',
        identity,
        config,
      }),
      applicationOrigin: web.outputs.ApplicationUrl,
    });
    return true;
  }

  if (basename === 'edge-security.json') {
    let applicationOrigin;
    let authorization = null;
    if (scope === 'full') {
      const manifestFilename = map.get('candidate-manifest.json');
      const authorizationFilename = map.get('external-authorization.json');
      const webFilename = map.get('web.json');
      if (
        manifestFilename === undefined ||
        authorizationFilename === undefined ||
        webFilename === undefined
      ) {
        return false;
      }
      const freezeManifest = validateFreezeManifest(readEvidence(manifestFilename));
      const web = deployedCheckpoint(
        operationEvidence(map, 'web.json', 'web', identity, config),
        'web',
        'web',
        identity,
        config,
        freezeManifest,
      );
      applicationOrigin = web.outputs.ApplicationUrl;
      authorization = validateExternalAuthorizationCheckpoint({
        document: readEvidence(authorizationFilename),
        scope: 'full',
        identity,
        config,
      });
    } else {
      const deploymentFilename = map.get('deployment.json');
      if (deploymentFilename === undefined) return false;
      applicationOrigin = deploymentTarget(
        path.dirname(deploymentFilename),
        config,
        identity,
      ).applicationOrigin;
    }
    validateEdgeSecurityCheckpoint({
      document: readEvidence(filename),
      scope,
      identity,
      config,
      authorization,
      applicationOrigin,
    });
    return true;
  }

  if (basename === 'sandbox-smoke.json') {
    const manifestFilename = map.get('candidate-manifest.json');
    if (manifestFilename === undefined) return false;
    const freezeManifest = validateFreezeManifest(readEvidence(manifestFilename));
    let applicationOrigin;
    let authorization = null;
    if (scope === 'full') {
      const authorizationFilename = map.get('external-authorization.json');
      const webFilename = map.get('web.json');
      if (authorizationFilename === undefined || webFilename === undefined) return false;
      const web = deployedCheckpoint(
        operationEvidence(map, 'web.json', 'web', identity, config),
        'web',
        'web',
        identity,
        config,
        freezeManifest,
      );
      applicationOrigin = web.outputs.ApplicationUrl;
      authorization = validateExternalAuthorizationCheckpoint({
        document: readEvidence(authorizationFilename),
        scope: 'full',
        identity,
        config,
      });
    } else {
      const deploymentFilename = map.get('deployment.json');
      if (deploymentFilename === undefined) return false;
      applicationOrigin = deploymentTarget(
        path.dirname(deploymentFilename),
        config,
        identity,
      ).applicationOrigin;
    }
    validateSandboxCheckpoint({
      document: readEvidence(filename),
      scope,
      identity,
      config,
      freezeManifest,
      authorization,
      applicationOrigin,
    });
    return true;
  }

  if (basename === EMERGENCY_RECOVERY_NO_ACTION_OUTCOME_BASENAME) {
    if (scope !== 'full') return false;
    const required = new Set([
      ...EMERGENCY_NO_ACTION_SOURCE_BINDING_SPECS.map(([, sourceBasename]) => sourceBasename),
      'emergency-recovery.json',
    ]);
    if ([...required].some((sourceBasename) => map.get(sourceBasename) === undefined)) {
      return false;
    }
    const freezeManifest = validateFreezeManifest(readEvidence(map.get('candidate-manifest.json')));
    const previousManifest = validateStage7PreviousReleaseForTarget(
      readEvidence(map.get('previous-release-manifest.json')),
      { config, freezeManifest },
    );
    const candidateRecord = validateStage7CandidateRollbackRecord(
      readEvidence(map.get('versioned-rollback-candidate.json')),
      {
        previousManifest,
        approvalSha256: fileDigest(map.get('approval.json')),
        planSha256: fileDigest(map.get('infra-diff.json')),
        deploymentEvidenceSha256: fileDigest(map.get('web.json')),
      },
    );
    const emergencyRecovery = validateCandidateActiveNoActionRecovery({
      value: readEvidence(map.get('emergency-recovery.json')),
      previousManifest,
      candidateRecord,
    });
    validateEmergencyRecoveryNoActionOutcomeEvidence({
      value: readEvidence(filename),
      map,
      previousManifest,
      candidateRecord,
      emergencyRecovery,
      identity,
      config,
    });
    return true;
  }

  if (basename === RELEASE_SUCCESSOR_COMPLETION_FENCE_BASENAME) {
    if (scope !== 'full') return false;
    const requiredBasenames = [
      'release-metadata.json',
      'approval.json',
      'activation.json',
      'drift.json',
      'stage7-rollback-resilience-protected-run.json',
      'stage7-rollback-resilience-complete.json',
      'stage7-release-pre-fence-gate.json',
    ];
    if (requiredBasenames.some((sourceBasename) => map.get(sourceBasename) === undefined)) {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    const metadata = readEvidence(map.get('release-metadata.json'));
    validateJobAuthorityReleaseOrigin(metadata, expectedJobExecution);
    const protectedRun = readEvidence(map.get('stage7-rollback-resilience-protected-run.json'));
    const completion = readEvidence(map.get('stage7-rollback-resilience-complete.json'));
    try {
      validateReleaseSuccessorCompletionFence(readEvidence(filename), {
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        sourceRunId: metadata.releaseRunId,
        sourceRunAttempt: metadata.releaseRunAttempt,
        journalLifecycleSha256: completion.journalLifecycleSha256,
        journalCleanupRoleSha256:
          protectedRun.runtimeAttestation?.journalLifecycle?.cleanupRoleSha256,
        evidenceBindings: {
          approval: evidenceFileBinding(map.get('approval.json')),
          activation: evidenceFileBinding(map.get('activation.json')),
          drift: evidenceFileBinding(map.get('drift.json')),
          rollbackCompletion: evidenceFileBinding(
            map.get('stage7-rollback-resilience-complete.json'),
          ),
          preFenceGate: evidenceFileBinding(map.get('stage7-release-pre-fence-gate.json')),
        },
      });
    } catch (error) {
      if (error instanceof Stage7ReleaseSuccessorFenceContractError) {
        fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
      }
      throw error;
    }
    return true;
  }

  if (
    (FULL_COMPLEX_EVIDENCE.has(basename) && basename !== 'approval.json') ||
    basename === 'stage6-external-evidence.json'
  ) {
    // These authorities require a multi-file reconstruction. Strict parsing
    // still detects corrupt bytes, but incomplete closeout must not invent a
    // PASS until the complete semantic consumer can run.
    readEvidence(filename);
    return false;
  }

  const document = passEvidence(map, basename, identity);
  const expectedReleaseTag = scope === 'full' ? identity.releaseTag : null;
  if (
    (document.scope !== undefined && document.scope !== scope) ||
    (document.releaseTag !== undefined && document.releaseTag !== expectedReleaseTag) ||
    (document.candidateTreeSha !== undefined && document.candidateTreeSha !== identity.treeSha) ||
    (document.configSha256 !== undefined && document.configSha256 !== objectSha256(config))
  ) {
    fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
  }
  if (['release-metadata.json', 'metadata.json'].includes(basename)) {
    if (
      document.candidateTreeSha !== identity.treeSha ||
      !RUN_ID.test(document.releaseRunId ?? '') ||
      document.releaseRunAttempt !== 1
    ) {
      fail('E7_SUCCESSFUL_PRODUCER_CHECKPOINT_INVALID');
    }
    validateJobAuthorityReleaseOrigin(document, expectedJobExecution);
    return true;
  }
  // A producer success plus a syntactically valid PASS envelope is not enough
  // to establish a semantic checkpoint. Sources without an explicit validator
  // stay NOT_RUN in an incomplete closeout; malformed or identity-tampered
  // envelopes fail above before reaching this boundary.
  return false;
};

const incompleteEvidenceRowStatus = ({
  scope,
  map,
  identity,
  config,
  index,
  jobResultsById,
  expectedJobExecution,
}) => {
  const requirements = STAGE7_EVIDENCE_SOURCE_REQUIREMENTS[scope][index];
  if (requirements.length === 0) {
    return { status: 'NOT_RUN', validator: 'recordStage7FormalBoundary' };
  }
  const producerResults = requirements.map((basename) => {
    const producer = STAGE7_SOURCE_PRODUCERS[scope]?.[basename];
    return producer === undefined ? undefined : jobResultsById.get(producer.producerJob);
  });
  if (producerResults.includes('failure')) {
    return { status: 'FAIL', validator: 'recordStage7ProducerFailure' };
  }
  if (producerResults.some((result) => !['success', 'failure'].includes(result))) {
    return { status: 'NOT_RUN', validator: 'recordStage7ProducerNotRun' };
  }
  let unsupported = false;
  for (const basename of requirements) {
    if (!map.has(basename)) {
      return { status: 'FAIL', validator: 'recordStage7ProducerArtifactFailure' };
    }
    try {
      const supported = validateSuccessfulProducerCheckpoint({
        scope,
        map,
        identity,
        config,
        basename,
        expectedJobExecution,
      });
      unsupported = unsupported || !supported;
    } catch {
      return { status: 'FAIL', validator: 'recordStage7ProducerArtifactFailure' };
    }
  }
  return unsupported
    ? { status: 'NOT_RUN', validator: 'recordStage7SemanticCheckpointNotRun' }
    : { status: 'PASS', validator: 'validateSuccessfulProducerCheckpoint' };
};

const provenanceRows = ({ scope, map, ownerAlias, generatedAtUtc, start, end }) =>
  STAGE7_EVIDENCE.slice(start, end).map(({ id, name }, offset) => {
    const index = start + offset;
    return createProvenanceRow({
      id,
      name,
      status: 'PASS',
      ownerAlias,
      validatedAtUtc: generatedAtUtc,
      validator: 'assertStage7PhysicalEvidence',
      sources: STAGE7_EVIDENCE_SOURCE_REQUIREMENTS[scope][index].map((basename) =>
        provenanceSource(map, scope, basename),
      ),
    });
  });

const writeAuthorityFile = async ({ map, basename, value, scope = 'full' }) => {
  const artifactName =
    scope === 'full' ? 'stage7-release-authorities' : 'stage7-prerelease-authorities';
  const directory = path.join(workspaceRoot, '.stage7/evidence', artifactName);
  mkdirSync(directory, { recursive: true });
  const target = path.join(directory, basename);
  await writeStage7Json(target, `stage7-${basename}`, value);
  map.set(basename, target);
  return target;
};

const materializeJobResultsAuthority = async ({
  scope,
  map,
  identity,
  rawJobResults,
  compositeAuthority,
}) => {
  const composite = compositeAuthority !== undefined;
  const expectedJobs = composite
    ? RELEASE_SUCCESSOR_COMPOSITE_GATE_JOB_IDS
    : scope === 'prerelease'
      ? REQUIRED_PRERELEASE_JOBS
      : REQUIRED_FULL_JOBS;
  const expectedJobExecution = composite
    ? {
        runId: compositeAuthority.recovery.runId,
        runAttempt: compositeAuthority.recovery.runAttempt,
        workflow: RELEASE_SUCCESSOR_RECOVERY_WORKFLOW_NAME,
      }
    : {
        runId: String(process.env.GITHUB_RUN_ID ?? ''),
        runAttempt: Number(process.env.GITHUB_RUN_ATTEMPT),
        workflow: process.env.GITHUB_WORKFLOW,
      };
  const jobResults = composite
    ? createCompositeRecoveryJobResultsDocument({ authority: compositeAuthority })
    : createJobResultsDocument({
        scope,
        candidateSha: identity.candidateSha,
        releaseId: identity.releaseId,
        releaseTag: scope === 'full' ? identity.releaseTag : null,
        generatedAtUtc: new Date().toISOString(),
        ...expectedJobExecution,
        jobs: expectedJobs.map((id) => ({ id, result: rawJobResults[id].result })),
      });
  const jobResultsFilename = await writeAuthorityFile({
    scope,
    map,
    basename: 'job-results.json',
    value: jobResults,
  });
  return {
    expectedJobs,
    expectedJobExecution,
    expectedCompositeAuthority: compositeAuthority,
    jobResults,
    jobResultsFilename,
  };
};

const validateJobAuthorityReleaseOrigin = (
  metadata,
  expectedJobExecution,
  compositeAuthority = undefined,
) => {
  const expectedWorkflow =
    metadata?.scope === 'full' ? 'Stage 7 Release' : 'Stage 7 Conditional Prerelease';
  if (compositeAuthority !== undefined) {
    const authority = validateReleaseSuccessorRecoveryCloseoutAuthority(compositeAuthority);
    if (
      metadata?.scope !== 'full' ||
      !RUN_ID.test(metadata?.releaseRunId ?? '') ||
      metadata.releaseRunAttempt !== 1 ||
      metadata.releaseRunId !== authority.source.runId ||
      expectedJobExecution?.runId !== authority.recovery.runId ||
      expectedJobExecution?.runAttempt !== authority.recovery.runAttempt ||
      expectedJobExecution?.workflow !== authority.recovery.workflowName
    ) {
      fail('E7_COMPOSITE_JOB_AUTHORITY_RELEASE_ORIGIN_MISMATCH');
    }
    return metadata;
  }
  if (
    !RUN_ID.test(metadata?.releaseRunId ?? '') ||
    metadata.releaseRunAttempt !== 1 ||
    expectedJobExecution?.runId !== metadata.releaseRunId ||
    expectedJobExecution?.runAttempt !== metadata.releaseRunAttempt ||
    expectedJobExecution?.workflow !== expectedWorkflow
  ) {
    fail('E7_JOB_AUTHORITY_RELEASE_ORIGIN_MISMATCH');
  }
  return metadata;
};

const provenanceRowWithStatus = ({
  scope,
  map,
  ownerAlias,
  generatedAtUtc,
  index,
  status,
  validator,
}) => {
  const requirements = STAGE7_EVIDENCE_SOURCE_REQUIREMENTS[scope][index];
  const sources =
    status === 'PASS'
      ? requirements.map((basename) => provenanceSource(map, scope, basename))
      : [
          provenanceSource(map, scope, 'job-results.json'),
          ...requirements
            .filter((basename) => map.has(basename))
            .map((basename) => provenanceSource(map, scope, basename)),
        ];
  return createProvenanceRow({
    ...STAGE7_EVIDENCE[index],
    status,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    validator,
    sources,
  });
};

const materializeIncompleteProvenance = async ({
  scope,
  map,
  identity,
  config,
  jobAuthority,
  reason,
}) => {
  const ownerAlias = config.authorization.ownerAlias;
  const generatedAtUtc = jobAuthority.jobResults.generatedAtUtc;
  const jobResultsById = new Map(
    jobAuthority.jobResults.jobs.map(({ id, result }) => [id, result]),
  );
  const first54Rows = STAGE7_EVIDENCE.slice(0, 54).map((_, index) => {
    const { status, validator } = incompleteEvidenceRowStatus({
      scope,
      map,
      identity,
      config,
      index,
      jobResultsById,
      expectedJobExecution: jobAuthority.expectedJobExecution,
    });
    return provenanceRowWithStatus({
      scope,
      map,
      ownerAlias,
      generatedAtUtc,
      index,
      status,
      validator,
    });
  });
  const entryGate =
    first54Rows[0].status === 'PASS'
      ? scope === 'prerelease'
        ? 'CONDITIONAL_GO'
        : 'PASS'
      : first54Rows[0].status === 'FAIL'
        ? 'FAIL'
        : 'NOT_RUN';
  const operationalArtifactRows = createOperationalArtifactRows({
    evidenceRows: first54Rows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
  });
  const gateEvaluationCheckpoint = createGateEvaluationCheckpoint({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: scope === 'full' ? identity.releaseTag : null,
    ownerAlias,
    generatedAtUtc,
    entryGate,
    operationalArtifactRows,
    evidenceRows: first54Rows,
  });
  await writeAuthorityFile({
    scope,
    map,
    basename: 'gate-evaluation.json',
    value: gateEvaluationCheckpoint,
  });
  const gateRows = STAGE7_EVIDENCE.slice(54).map((_, offset) =>
    provenanceRowWithStatus({
      scope,
      map,
      ownerAlias,
      generatedAtUtc,
      index: offset + 54,
      status: gateEvaluationCheckpoint.gates[`GATE-E7-0${offset + 1}`],
      validator: 'deriveStage7Gates',
    }),
  );
  const evidenceRows = [...first54Rows, ...gateRows];
  const evidenceIndexCheckpoint = createEvidenceIndexCheckpoint({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: scope === 'full' ? identity.releaseTag : null,
    ownerAlias,
    generatedAtUtc,
    evidenceRows,
  });
  await writeAuthorityFile({
    scope,
    map,
    basename: 'evidence-index-checkpoint.json',
    value: evidenceIndexCheckpoint,
  });
  const evidenceIndexSource = provenanceSource(map, scope, 'evidence-index-checkpoint.json');
  const gateEvaluationSource = provenanceSource(map, scope, 'gate-evaluation.json');
  const authorityArtifactRows = createAuthorityArtifactRows({
    evidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    operationalArtifactRows,
    evidenceIndexCheckpoint,
    evidenceIndexSource,
    gateEvaluationCheckpoint,
    gateEvaluationSource,
    entryGate,
  });
  const handoff = createStage7Handoff({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: scope === 'full' ? identity.releaseTag : null,
    ownerAlias,
    generatedAtUtc,
    artifactRows: authorityArtifactRows,
    evidenceRows,
  });
  await writeAuthorityFile({
    scope,
    map,
    basename: 'handoff-payload.json',
    value: handoff,
  });
  const artifactRows = createArtifactRows({
    authorityArtifactRows,
    evidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    operationalArtifactRows,
    evidenceIndexCheckpoint,
    evidenceIndexSource,
    gateEvaluationCheckpoint,
    gateEvaluationSource,
    entryGate,
    handoff,
    handoffSource: provenanceSource(map, scope, 'handoff-payload.json'),
  });
  const ledger = createStage7ProvenanceLedger({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: scope === 'full' ? identity.releaseTag : null,
    generatedAtUtc,
    entryGate,
    artifactRows,
    evidenceRows,
    handoff,
    canonicalSha256ByBasename: {},
  });
  const reportsDirectory = evidenceRoot(scope);
  const reportBasename = scope === 'full' ? 'etapa-7-release-despliegue.md' : 'stage7-report.md';
  await writeStage7Json(
    path.join(reportsDirectory, 'provenance-ledger.json'),
    'stage7-provenance-ledger.json',
    ledger,
  );
  await writeSanitizedTextAtomic(
    path.join(reportsDirectory, reportBasename),
    reportBasename,
    [
      '# Etapa 7 — cierre causal incompleto',
      '',
      `- Estado del ledger: **${ledger.status}**.`,
      `- Estado de jobs: **${jobAuthority.jobResults.status}**.`,
      `- Razón validada: \`${reason}\`.`,
      `- Artefactos verificados: ${ledger.counts.artifacts.verified}/20.`,
      `- Evidencias aprobadas: ${ledger.counts.evidence.pass}/57.`,
      '- Siguiente etapa: bloqueada hasta una nueva ejecución completa y verificable.',
      '',
    ].join('\n'),
  );
  return { ledger, handoff };
};

const materializePrereleaseProvenance = async ({ map, identity, config, jobAuthority }) => {
  const scope = 'prerelease';
  const ownerAlias = config.authorization.ownerAlias;
  const generatedAtUtc = jobAuthority.jobResults.generatedAtUtc;
  validateJobAuthorityReleaseOrigin(
    passEvidence(map, 'metadata.json', identity),
    jobAuthority.expectedJobExecution,
  );
  const first52Rows = STAGE7_EVIDENCE.slice(0, 52).map(({ id }, index) => {
    const status = PRERELEASE_BLOCKED_EVIDENCE.has(id)
      ? 'BLOCKED_AUTH'
      : PRERELEASE_NOT_RUN_EVIDENCE.has(id) ||
          STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.prerelease[index].length === 0
        ? 'NOT_RUN'
        : 'PASS';
    return provenanceRowWithStatus({
      scope,
      map,
      ownerAlias,
      generatedAtUtc,
      index,
      status,
      validator: status === 'PASS' ? 'assertStage7PhysicalEvidence' : 'enforcePrereleaseBoundary',
    });
  });
  const stage6CloseoutFilename = map.get('stage6-closeout.json');
  const stage6Closeout = readEvidence(stage6CloseoutFilename);
  const scorecard = createStage7Scorecard({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: null,
    ownerAlias,
    generatedAtUtc,
    stage6Closeout,
    stage6CloseoutSha256: fileDigest(stage6CloseoutFilename),
    evidenceRows: first52Rows,
  });
  await writeAuthorityFile({
    scope,
    map,
    basename: 'scorecard.json',
    value: scorecard,
  });
  const runbook = createStage7OperationsRunbook({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: null,
    ownerAlias,
    generatedAtUtc,
    expiresAtUtc: config.cleanup.expiresAtUtc,
    environment: config.environment,
    stacks: config.authorization.stacks,
    budgetMaxUsd: config.budget.maxUsd,
    cleanupVerified: true,
    sourceSha256: fileDigest(map.get('cleanup.json')),
  });
  await writeAuthorityFile({
    scope,
    map,
    basename: 'operations-runbook.json',
    value: runbook,
  });
  const evidenceRows54 = [
    ...first52Rows,
    provenanceRowWithStatus({
      scope,
      map,
      ownerAlias,
      generatedAtUtc,
      index: 52,
      status: 'NOT_RUN',
      validator: 'enforcePrereleaseBoundary',
    }),
    provenanceRowWithStatus({
      scope,
      map,
      ownerAlias,
      generatedAtUtc,
      index: 53,
      status: 'PASS',
      validator: 'validatePrereleaseCleanupEvidence',
    }),
  ];
  const operationalArtifactRows = createOperationalArtifactRows({
    evidenceRows: evidenceRows54,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
  });
  const entryGate = 'CONDITIONAL_GO';
  const gateEvaluationCheckpoint = createGateEvaluationCheckpoint({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: null,
    ownerAlias,
    generatedAtUtc,
    entryGate,
    operationalArtifactRows,
    evidenceRows: evidenceRows54,
  });
  await writeAuthorityFile({
    scope,
    map,
    basename: 'gate-evaluation.json',
    value: gateEvaluationCheckpoint,
  });
  const gateRows = STAGE7_EVIDENCE.slice(54).map((_, offset) =>
    provenanceRowWithStatus({
      scope,
      map,
      ownerAlias,
      generatedAtUtc,
      index: offset + 54,
      status: gateEvaluationCheckpoint.gates[`GATE-E7-0${offset + 1}`],
      validator: 'deriveStage7Gates',
    }),
  );
  const evidenceRows = [...evidenceRows54, ...gateRows];
  const evidenceIndexCheckpoint = createEvidenceIndexCheckpoint({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: null,
    ownerAlias,
    generatedAtUtc,
    evidenceRows,
  });
  await writeAuthorityFile({
    scope,
    map,
    basename: 'evidence-index-checkpoint.json',
    value: evidenceIndexCheckpoint,
  });
  const evidenceIndexSource = provenanceSource(map, scope, 'evidence-index-checkpoint.json');
  const gateEvaluationSource = provenanceSource(map, scope, 'gate-evaluation.json');
  const authorityArtifactRows = createAuthorityArtifactRows({
    evidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    operationalArtifactRows,
    evidenceIndexCheckpoint,
    evidenceIndexSource,
    gateEvaluationCheckpoint,
    gateEvaluationSource,
    entryGate,
  });
  const handoff = createStage7Handoff({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: null,
    ownerAlias,
    generatedAtUtc,
    artifactRows: authorityArtifactRows,
    evidenceRows,
  });
  await writeAuthorityFile({
    scope,
    map,
    basename: 'handoff-payload.json',
    value: handoff,
  });
  const artifactRows = createArtifactRows({
    authorityArtifactRows,
    evidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    operationalArtifactRows,
    evidenceIndexCheckpoint,
    evidenceIndexSource,
    gateEvaluationCheckpoint,
    gateEvaluationSource,
    entryGate,
    handoff,
    handoffSource: provenanceSource(map, scope, 'handoff-payload.json'),
  });
  const ledger = createStage7ProvenanceLedger({
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: null,
    generatedAtUtc,
    entryGate,
    artifactRows,
    evidenceRows,
    handoff,
    canonicalSha256ByBasename: {},
  });
  const reportsDirectory = evidenceRoot(scope);
  await writeStage7Json(
    path.join(reportsDirectory, 'provenance-ledger.json'),
    'stage7-prerelease-provenance-ledger.json',
    ledger,
  );
  await writeSanitizedTextAtomic(
    path.join(reportsDirectory, 'stage7-report.md'),
    'stage7-prerelease-report.md',
    renderStage7Report({ ledger, scorecard, runbook, handoff }),
  );
  return { ledger, handoff };
};

const materializeFullProvenance = async ({
  map,
  identity,
  config,
  evidence,
  plan,
  proof,
  resilienceCompletion,
  jobAuthority,
  compositeAuthority,
}) => {
  const ownerAlias = config.authorization.ownerAlias;
  const generatedAtUtc = jobAuthority.jobResults.generatedAtUtc;
  const { expectedJobExecution, jobResults, jobResultsFilename } = jobAuthority;
  validateJobAuthorityReleaseOrigin(
    evidence['release-metadata.json'],
    expectedJobExecution,
    compositeAuthority,
  );
  const first52Rows = provenanceRows({
    scope: 'full',
    map,
    ownerAlias,
    generatedAtUtc,
    start: 0,
    end: 52,
  });
  const stage6CloseoutFilename = map.get('stage6-closeout.json');
  const stage6Closeout = readEvidence(stage6CloseoutFilename);
  const scorecard = createStage7Scorecard({
    scope: 'full',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: identity.releaseTag,
    ownerAlias,
    generatedAtUtc,
    stage6Closeout,
    stage6CloseoutSha256: fileDigest(stage6CloseoutFilename),
    evidenceRows: first52Rows,
  });
  const scorecardFilename = await writeAuthorityFile({
    map,
    basename: 'scorecard.json',
    value: scorecard,
  });
  const runbook = createStage7OperationsRunbook({
    scope: 'full',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: identity.releaseTag,
    ownerAlias,
    generatedAtUtc,
    expiresAtUtc: config.cleanup.expiresAtUtc,
    environment: config.environment,
    stacks: config.authorization.stacks,
    budgetMaxUsd: config.budget.maxUsd,
    cleanupVerified: false,
    sourceSha256: fileDigest(map.get('drift.json')),
  });
  const runbookFilename = await writeAuthorityFile({
    map,
    basename: 'operations-runbook.json',
    value: runbook,
  });
  const evidenceRows54 = [
    ...first52Rows,
    ...provenanceRows({
      scope: 'full',
      map,
      ownerAlias,
      generatedAtUtc,
      start: 52,
      end: 54,
    }),
  ];
  const operationalArtifactRows = createOperationalArtifactRows({
    evidenceRows: evidenceRows54,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
  });
  const gateEvaluationCheckpoint = createGateEvaluationCheckpoint({
    scope: 'full',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: identity.releaseTag,
    ownerAlias,
    generatedAtUtc,
    entryGate: 'PASS',
    operationalArtifactRows,
    evidenceRows: evidenceRows54,
  });
  const gateEvaluationFilename = await writeAuthorityFile({
    map,
    basename: 'gate-evaluation.json',
    value: gateEvaluationCheckpoint,
  });
  const gateRows = STAGE7_EVIDENCE.slice(54).map(({ id, name }, index) =>
    createProvenanceRow({
      id,
      name,
      status: gateEvaluationCheckpoint.gates[`GATE-E7-0${index + 1}`],
      ownerAlias,
      validatedAtUtc: generatedAtUtc,
      validator: 'deriveStage7Gates',
      sources: STAGE7_EVIDENCE_SOURCE_REQUIREMENTS.full[index + 54].map((basename) =>
        provenanceSource(map, 'full', basename),
      ),
    }),
  );
  const evidenceRows = [...evidenceRows54, ...gateRows];
  const evidenceIndexCheckpoint = createEvidenceIndexCheckpoint({
    scope: 'full',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: identity.releaseTag,
    ownerAlias,
    generatedAtUtc,
    evidenceRows,
  });
  const evidenceIndexFilename = await writeAuthorityFile({
    map,
    basename: 'evidence-index-checkpoint.json',
    value: evidenceIndexCheckpoint,
  });
  const evidenceIndexSource = provenanceSource(map, 'full', 'evidence-index-checkpoint.json');
  const gateEvaluationSource = provenanceSource(map, 'full', 'gate-evaluation.json');
  const authorityArtifactRows = createAuthorityArtifactRows({
    evidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    operationalArtifactRows,
    evidenceIndexCheckpoint,
    evidenceIndexSource,
    gateEvaluationCheckpoint,
    gateEvaluationSource,
    entryGate: 'PASS',
  });
  const handoff = createStage7Handoff({
    scope: 'full',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: identity.releaseTag,
    ownerAlias,
    generatedAtUtc,
    artifactRows: authorityArtifactRows,
    evidenceRows,
  });
  const handoffFilename = await writeAuthorityFile({
    map,
    basename: 'handoff-payload.json',
    value: handoff,
  });
  const artifactRows = createArtifactRows({
    authorityArtifactRows,
    evidenceRows,
    ownerAlias,
    validatedAtUtc: generatedAtUtc,
    operationalArtifactRows,
    evidenceIndexCheckpoint,
    evidenceIndexSource,
    gateEvaluationCheckpoint,
    gateEvaluationSource,
    entryGate: 'PASS',
    handoff,
    handoffSource: provenanceSource(map, 'full', 'handoff-payload.json'),
  });
  const canonicalSha256ByBasename = Object.fromEntries(
    STAGE7_LEDGER_SOURCE_BINDING_SPECS.map(({ basename }) => [
      basename,
      objectSha256(readEvidence(map.get(basename))),
    ]),
  );
  const ledger = createStage7ProvenanceLedger({
    scope: 'full',
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    releaseTag: identity.releaseTag,
    generatedAtUtc,
    entryGate: 'PASS',
    artifactRows,
    evidenceRows,
    handoff,
    canonicalSha256ByBasename,
  });
  const reportsDirectory = evidenceRoot('full');
  const ledgerFilename = path.join(reportsDirectory, 'provenance-ledger.json');
  await writeStage7Json(ledgerFilename, 'stage7-provenance-ledger.json', ledger);
  const report = renderStage7Report({ ledger, scorecard, runbook, handoff });
  const reportFilename = path.join(reportsDirectory, 'etapa-7-release-despliegue.md');
  await writeSanitizedTextAtomic(reportFilename, 'etapa-7-release-despliegue.md', report);
  const finalManifest = createStage7FinalManifest({
    ledger,
    handoff,
    evidenceIndexCheckpoint,
    gateEvaluationCheckpoint,
    scorecard,
    runbook,
    jobResults,
    stage6Closeout,
    expectedJobs: jobAuthority.expectedJobs,
    expectedJobExecution,
    expectedCompositeAuthority: jobAuthority.expectedCompositeAuthority,
    reportSha256: fileDigest(reportFilename),
    ledgerSha256: fileDigest(ledgerFilename),
    evidenceIndexSha256: fileDigest(evidenceIndexFilename),
    gateEvaluationSha256: fileDigest(gateEvaluationFilename),
    handoffSha256: fileDigest(handoffFilename),
    scorecardSha256: fileDigest(scorecardFilename),
    runbookSha256: fileDigest(runbookFilename),
    jobResultsSha256: fileDigest(jobResultsFilename),
    stage6CloseoutSha256: fileDigest(stage6CloseoutFilename),
    urls: plan.urls,
    publication: {
      releaseUrl: proof.releaseUrl,
      readmeCommitSha: proof.readmeCommitSha,
      repositoryPublic: proof.repositoryPublic,
      urlsVerified: proof.urlsVerified,
      proofRawSha256: fileDigest(map.get('publication-proof.json')),
      proofObjectSha256: objectSha256(proof),
    },
    rollback: {
      predecessorManifestSha256: evidence['previous-release-manifest.json'].manifestSha256,
      completionRawSha256: fileDigest(map.get('stage7-rollback-resilience-complete.json')),
      completionObjectSha256: objectSha256(resilienceCompletion),
      completionEnvelopeSha256: resilienceCompletion.envelopeSha256,
    },
    canonicalSha256ByBasename,
  });
  await writeStage7Json(
    path.join(reportsDirectory, 'release-manifest.json'),
    'stage7-final-release-manifest.json',
    finalManifest,
  );
  return { ledger, handoff, finalManifest };
};

const loadPublicationRecoveryControlContext = ({ flags }) => {
  const intake = validatePublicationRecoveryPostSuccessIntake(
    readEvidence(requiredString(flags, 'publication-recovery-intake')),
  );
  const authority = validateReleaseSuccessorRecoveryCloseoutAuthority(
    readEvidence(requiredString(flags, 'publication-recovery-closeout-authority')),
    { intake },
  );
  const resultArchive = readFileSync(
    checkedWorkspacePath(requiredString(flags, 'publication-recovery-result'), {
      directory: false,
    }),
  );
  const planArchive = readFileSync(
    checkedWorkspacePath(requiredString(flags, 'publication-recovery-plan'), {
      directory: false,
    }),
  );
  const result = readReleaseSuccessorRecoveryResultFromIntake({
    intake,
    planArchive,
    resultArchive,
  });
  return { intake, authority, result };
};

const publicationRecoveryCandidateIdentity = ({ recovery, map }) => {
  const actual = currentCandidate();
  const manifestFilename = map.get('candidate-manifest.json');
  if (manifestFilename === undefined) fail('E7_PUBLICATION_RECOVERY_CANDIDATE_INVALID');
  const manifest = validateFreezeManifest(readEvidence(manifestFilename));
  const candidateSha = process.env.STAGE7_CANDIDATE_SHA;
  const releaseId = process.env.STAGE7_RELEASE_ID;
  const releaseTag = process.env.STAGE7_RELEASE_TAG;
  if (
    actual.commitSha !== recovery.authority.postSuccess.headSha ||
    actual.workingTree !== 'CLEAN' ||
    actual.changedFiles !== 0 ||
    candidateSha !== recovery.authority.source.candidateSha ||
    releaseId !== recovery.authority.source.releaseId ||
    releaseTag !== recovery.authority.source.releaseTag ||
    manifest.candidateSha !== candidateSha ||
    manifest.releaseId !== releaseId ||
    manifest.releaseTag !== releaseTag
  ) {
    fail('E7_PUBLICATION_RECOVERY_CANDIDATE_INVALID');
  }
  return {
    ...actual,
    commitSha: candidateSha,
    treeSha: manifest.candidateTreeSha,
    candidateSha,
    releaseId,
    releaseTag,
    controlRevisionSha: actual.commitSha,
  };
};

const validatePublicationRecoveryControlContext = ({ recovery, identity, map }) => {
  const { intake, authority, result } = recovery;
  if (
    intake.source.candidateSha !== identity.candidateSha ||
    intake.source.releaseId !== identity.releaseId ||
    intake.source.releaseTag !== identity.releaseTag ||
    authority.source.candidateSha !== identity.candidateSha ||
    authority.source.releaseId !== identity.releaseId ||
    authority.source.releaseTag !== identity.releaseTag ||
    authority.bindings.sourceArtifactManifestSha256 !==
      objectSha256(result.plan.artifactInventory.downloadManifest) ||
    authority.bindings.publicationFilesSha256 !== objectSha256(result.receipt.publicationFiles)
  ) {
    fail('E7_PUBLICATION_RECOVERY_CONTROL_IDENTITY_INVALID');
  }
  const fenceFilename = map.get(RELEASE_SUCCESSOR_COMPLETION_FENCE_BASENAME);
  if (
    fenceFilename === undefined ||
    fileDigest(fenceFilename) !== result.plan.fence.parameterValueRawSha256 ||
    objectSha256(readEvidence(fenceFilename)) !== objectSha256(result.fence)
  ) {
    fail('E7_PUBLICATION_RECOVERY_CONTROL_FENCE_INVALID');
  }
  for (const binding of result.receipt.publicationFiles) {
    const filename = map.get(binding.name);
    if (
      filename === undefined ||
      fileDigest(filename) !== binding.rawSha256 ||
      objectSha256(readEvidence(filename)) !== binding.canonicalSha256
    ) {
      fail('E7_PUBLICATION_RECOVERY_CONTROL_PUBLICATION_INVALID');
    }
  }
  return { intake, authority, result };
};

const verifyFullRelease = async (flags) => {
  const recoveryMode = flags['publication-recovery-intake'] !== undefined;
  const map = evidenceFileMap(requiredString(flags, 'evidence'), 'full');
  const loadedRecovery = recoveryMode
    ? loadPublicationRecoveryControlContext({ flags })
    : undefined;
  const identity = recoveryMode
    ? publicationRecoveryCandidateIdentity({ recovery: loadedRecovery, map })
    : candidateIdentity('full', { requireGitTag: true });
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const recovery = recoveryMode
    ? validatePublicationRecoveryControlContext({
        recovery: loadedRecovery,
        identity,
        map,
      })
    : undefined;
  const rawJobResults = recoveryMode ? undefined : exactJobResults('full');
  const jobAuthority = await materializeJobResultsAuthority({
    scope: 'full',
    map,
    identity,
    rawJobResults,
    compositeAuthority: recovery?.authority,
  });
  const jobs = jobAuthority.expectedJobs.toSorted(stableCompare);
  if (jobAuthority.jobResults.status !== 'PASS') {
    await materializeIncompleteProvenance({
      scope: 'full',
      map,
      identity,
      config,
      jobAuthority,
      reason: 'E7_JOB_RESULTS_NOT_SUCCESSFUL',
    });
    fail('E7_JOB_RESULTS_NOT_SUCCESSFUL');
  }
  try {
    const evidence = assertFullEvidence(
      map,
      identity,
      config,
      requiredString(flags, 'resilience-app'),
    );
    const planFilename = map.get('publication-plan.json');
    const targetProofFilename = map.get('publication-target-proof.json');
    const operationFilename = map.get('publication-operation.json');
    const proofFilename = map.get('publication-proof.json');
    if (
      planFilename === undefined ||
      targetProofFilename === undefined ||
      operationFilename === undefined ||
      proofFilename === undefined
    ) {
      fail('E7_PUBLICATION_PROOF_MISSING');
    }
    const plan = validatePublicationPlan(readEvidence(planFilename), identity);
    const targetProof = validatePublicationTargetProof(
      readEvidence(targetProofFilename),
      identity,
      plan,
      config,
      evidence['external-authorization.json'],
    );
    const operation = validatePublicationOperation(readEvidence(operationFilename), identity, plan);
    const proof = validatePublicationProof(readEvidence(proofFilename), identity, plan);
    const publicationLedger = validateAuthorizationBudgetCheckpoint({
      plan: evidence.externalRequestBudgetPlan,
      usages: [...evidence.authorizationUsages, targetProof.authorizationUsage],
      phase: 'POST_PUBLICATION',
    });
    if (
      proof.publicationTargetProofSha256 !== objectSha256(targetProof) ||
      proof.publicationOperationSha256 !== objectSha256(operation) ||
      proof.githubApiRequests !== operation.externalRequests + 6 ||
      proof.ownedTargetRequests !== targetProof.externalRequests ||
      proof.externalRequests !== proof.githubApiRequests + proof.ownedTargetRequests ||
      proof.externalWritesPerformed !== operation.externalWritesPerformed
    ) {
      fail('E7_PUBLICATION_PROOF_INVALID');
    }
    const provenance = await materializeFullProvenance({
      map,
      identity,
      config,
      evidence,
      plan,
      proof,
      resilienceCompletion: evidence['stage7-rollback-resilience-complete.json'],
      jobAuthority,
      compositeAuthority: recovery?.authority,
    });
    const index = createStage7Index({
      entryGate: 'PASS',
      artifactStates: Object.fromEntries(
        provenance.ledger.artifacts.map(({ id, status }) => [id, status]),
      ),
      evidenceStates: Object.fromEntries(
        provenance.ledger.evidence.slice(0, 54).map(({ id, status }) => [id, status]),
      ),
    });
    if (index.gates['GATE-E7-03'] !== 'PASS') fail('E7_FINAL_GATE_NOT_PASS');
    return {
      schemaVersion: 1,
      stage: 7,
      kind: 'STAGE7_CLOSEOUT',
      status: 'RELEASED',
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      releaseTag: identity.releaseTag,
      stage6RunId: evidence['candidate-manifest.json'].sourceRunId,
      stage6ManifestSha256: evidence['release-metadata.json'].stage6ManifestSha256,
      releaseMode: 'VERSIONED_UPDATE',
      updateReleaseSupported: true,
      updateReleaseUnsupportedReason: null,
      cloudFormationDrift: { checked: 4, criticalCount: 0, status: 'IN_SYNC' },
      authorizationLedger: publicationLedger,
      publication: {
        releaseUrl: proof.releaseUrl,
        readmeCommitSha: proof.readmeCommitSha,
        repositoryPublic: true,
        urlsVerified: true,
      },
      jobs,
      index,
      gates: index.gates,
      artifacts: provenance.finalManifest.artifacts,
      evidence: provenance.finalManifest.evidence,
      releaseManifestSha256: provenance.finalManifest.manifestSha256,
      provenanceLedgerSha256: provenance.ledger.ledgerSha256,
      nextStage: 8,
      mutationsPerformedByVerifier: 0,
      containsSensitiveData: false,
    };
  } catch (error) {
    const reason =
      error instanceof Stage7ControlError ||
      error instanceof Stage7Error ||
      error instanceof Stage7ProvenanceError
        ? error.code
        : 'E7_VERIFY_UNEXPECTED_FAILURE';
    await materializeIncompleteProvenance({
      scope: 'full',
      map,
      identity,
      config,
      jobAuthority,
      reason,
    });
    throw error;
  }
};

const verifyPrerelease = async (flags) => {
  if (flags['forbid-e7-pass'] !== true) fail('E7_PRERELEASE_PASS_GUARD_REQUIRED');
  const identity = candidateIdentity('prerelease');
  const config = configFromEnvironment();
  verifyConfigScope(config, 'prerelease');
  const map = evidenceFileMap(requiredString(flags, 'evidence'), 'prerelease');
  const rawJobResults = exactJobResults('prerelease');
  const jobAuthority = await materializeJobResultsAuthority({
    scope: 'prerelease',
    map,
    identity,
    rawJobResults,
  });
  const jobs = jobAuthority.expectedJobs.toSorted(stableCompare);
  if (jobAuthority.jobResults.status !== 'PASS') {
    await materializeIncompleteProvenance({
      scope: 'prerelease',
      map,
      identity,
      config,
      jobAuthority,
      reason: 'E7_JOB_RESULTS_NOT_SUCCESSFUL',
    });
    fail('E7_JOB_RESULTS_NOT_SUCCESSFUL');
  }
  try {
    for (const basename of [
      'metadata.json',
      'verify-candidate.json',
      'candidate-manifest.json',
      'checksums-sbom.json',
      'security.json',
      'aws-auth.json',
      'infra-synth.json',
      'github-environment-approval.json',
      'deployment.json',
      'smoke.json',
      'external-uat.json',
      'edge-security.json',
      'sandbox-smoke.json',
      'cleanup.json',
    ]) {
      passEvidence(map, basename, identity);
    }
    const diffFilename = map.get('infra-diff.json');
    const rawDiffFilename = map.get('infra-diff.txt');
    const approvalFilename = map.get('approval.json');
    const awsAuthFilename = map.get('aws-auth.json');
    if (
      diffFilename === undefined ||
      rawDiffFilename === undefined ||
      approvalFilename === undefined ||
      awsAuthFilename === undefined
    ) {
      fail('E7_REQUIRED_EVIDENCE_MISSING');
    }
    const diff = validateDiffReview(readEvidence(diffFilename), 'prerelease', identity, config);
    const releasePlan = validateReleasePlanCheckpoint(
      readEvidence(map.get('release-plan.json')),
      'prerelease',
      identity,
      config,
    );
    const manifest = validateFreezeManifest(readEvidence(map.get('candidate-manifest.json')));
    const releaseMetadata = readEvidence(map.get('metadata.json'));
    validateStage6CloseoutBinding({
      map,
      identity,
      metadata: releaseMetadata,
      freezeManifest: manifest,
      scope: 'prerelease',
    });
    validateCandidateVerificationCheckpoint({
      document: readEvidence(map.get('verify-candidate.json')),
      scope: 'prerelease',
      identity,
      metadata: releaseMetadata,
      freezeManifest: manifest,
    });
    validateChecksumsInventoryCheckpoint({
      document: readEvidence(map.get('checksums-sbom.json')),
      scope: 'prerelease',
      identity,
      freezeManifest: manifest,
    });
    validateSecurityCheckpoint({
      document: readEvidence(map.get('security.json')),
      scope: 'prerelease',
      identity,
    });
    const synth = validateInfraSynthCheckpoint({
      document: readEvidence(map.get('infra-synth.json')),
      scope: 'prerelease',
      identity,
      freezeManifest: manifest,
      releasePlan,
      diff,
    });
    const prereleaseDeployment = deploymentTarget(
      path.dirname(map.get('deployment.json')),
      config,
      identity,
    );
    validateEdgeSecurityCheckpoint({
      document: readEvidence(map.get('edge-security.json')),
      scope: 'prerelease',
      identity,
      config,
      authorization: null,
      applicationOrigin: prereleaseDeployment.applicationOrigin,
    });
    validateSandboxCheckpoint({
      document: readEvidence(map.get('sandbox-smoke.json')),
      scope: 'prerelease',
      identity,
      config,
      freezeManifest: manifest,
      authorization: null,
      applicationOrigin: prereleaseDeployment.applicationOrigin,
    });
    const verifiedIamPermissions = validateAwsAuthEffectivePermissions({
      value: readEvidence(awsAuthFilename),
      config,
      scope: 'prerelease',
      identity,
      manifestSha256: manifest.manifestSha256,
    });
    if (
      manifest.configSha256 !== objectSha256(config) ||
      synth.freezeManifestSha256 !== manifest.manifestSha256 ||
      synth.assemblySha256 !== diff.cloudAssemblySha256 ||
      releasePlan.cloudAssemblySha256 !== diff.cloudAssemblySha256 ||
      !SHA256.test(synth.frozenVerificationSha256 ?? '') ||
      diff.checkpoints.diff.freezeManifestSha256 !== manifest.manifestSha256
    ) {
      fail('E7_PRERELEASE_ASSEMBLY_BINDING_INVALID');
    }
    const approval = readEvidence(approvalFilename);
    const githubApproval = readEvidence(map.get('github-environment-approval.json'));
    validateBoundGithubEnvironmentApproval({
      document: githubApproval,
      scope: 'prerelease',
      identity,
      map,
    });
    if (
      !exactKeys(approval, PROTECTED_APPROVAL_KEYS) ||
      approval.kind !== 'PROTECTED_RELEASE_APPROVAL' ||
      approval.status !== 'PASS' ||
      approval.scope !== 'prerelease' ||
      approval.candidateSha !== identity.candidateSha ||
      approval.releaseId !== identity.releaseId ||
      approval.releaseTag !== null ||
      approval.configSha256 !== objectSha256(config) ||
      approval.cloudAssemblySha256 !== diff.cloudAssemblySha256 ||
      approval.freezeManifestSha256 !== diff.checkpoints.diff.freezeManifestSha256 ||
      approval.approvedPlanSha256 !== fileDigest(diffFilename) ||
      approval.approvedDiffSha256 !== fileDigest(rawDiffFilename) ||
      approval.approvedDiffSha256 !== diff.rawDiffArtifactSha256 ||
      approval.iamEffectivePermissionsBindingSha256 !== verifiedIamPermissions.bindingSha256 ||
      approval.iamEffectivePermissionsEvidenceSha256 !== fileDigest(awsAuthFilename) ||
      approval.journalRoleEffectivePermissionsRawSha256 !== null ||
      approval.journalRoleEffectivePermissionsSha256 !== null ||
      RELEASE_RECONCILIATION_RECOVERY_AWS_AUTH_BINDING_FIELDS.some(
        (field) => approval[field] !== null,
      ) ||
      approval.approvedAtUtc !== githubApproval.capturedAtUtc ||
      approval.reviewerAlias !== githubApproval.reviewerAlias ||
      approval.humanReviewConfirmed !== githubApproval.reviewed ||
      approval.iamBroadeningReviewed !== githubApproval.iamReviewAttested ||
      !utc(approval.approvedAtUtc) ||
      Date.parse(approval.approvedAtUtc) < Date.parse(config.window.startsAtUtc) ||
      Date.parse(approval.approvedAtUtc) > Date.parse(config.window.endsAtUtc) ||
      approval.humanReviewConfirmed !== true ||
      approval.iamBroadeningReviewed !== true ||
      approval.explicitDispatchConfirmation !== true ||
      approval.protectedEnvironment !== true ||
      approval.protectedEnvironmentName !== 'assessment-prerelease' ||
      approval.nonPublic !== true ||
      approval.accountSha256 !== digest(config.aws.accountId) ||
      approval.accountSuffix !== config.aws.accountId.slice(-4) ||
      approval.region !== config.aws.region ||
      approval.stacks?.join('\0') !== config.authorization.stacks.join('\0') ||
      approval.approvalOwnerAlias !== config.authorization.ownerAlias ||
      !/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u.test(approval.reviewerAlias ?? '') ||
      objectSha256(approval.authorizedWindow) !== objectSha256(config.window) ||
      objectSha256(approval.budget) !==
        objectSha256({
          maxUsd: config.budget.maxUsd,
          warningUsd: config.budget.warningUsd,
          alertDestinationSha256: config.budget.alertDestinationSha256,
        }) ||
      approval.externalRequests !== 0 ||
      approval.mutationsPerformed !== 0 ||
      approval.containsSensitiveData !== false
    ) {
      fail('E7_PROTECTED_APPROVAL_EVIDENCE_INVALID');
    }
    const rawFilename = map.get('stage6-external-evidence.json');
    if (rawFilename === undefined) fail('E7_STAGE6_RAW_EVIDENCE_MISSING');
    const raw = readEvidence(rawFilename);
    const ingestedByRunId =
      raw.runId === 'e6-19700101t000000z-00000000'
        ? 'e6-19700101t000001z-00000001'
        : 'e6-19700101t000000z-00000000';
    await loadExternalEvidence({
      sourcePath: rawFilename,
      commitSha: identity.candidateSha,
      ingestedByRunId,
    }).catch(() => fail('E7_STAGE6_RAW_CONTRACT_INVALID'));
    const cleanup = readEvidence(map.get('cleanup.json'));
    if (
      flags['require-cleanup'] !== true ||
      cleanup.environment !== config.environment ||
      cleanup.authorizationId !== config.authorization.id ||
      cleanup.authorizationScope !== config.authorization.scope ||
      cleanup.configSha256 !== objectSha256(config)
    ) {
      fail('E7_PRERELEASE_CLEANUP_INVALID');
    }
    validateStage7PrereleaseCleanupCheckpoint(cleanup.checkpoints?.cleanup, {
      config,
      assemblySha256: diff.cloudAssemblySha256,
      enforceExpiry: false,
    });
    const provenance = await materializePrereleaseProvenance({
      map,
      identity,
      config,
      jobAuthority,
    });
    const index = createStage7Index({
      entryGate: 'CONDITIONAL_GO',
      artifactStates: Object.fromEntries(
        provenance.ledger.artifacts.map(({ id, status }) => [id, status]),
      ),
      evidenceStates: Object.fromEntries(
        provenance.ledger.evidence.slice(0, 54).map(({ id, status }) => [id, status]),
      ),
    });
    if (Object.values(index.gates).includes('PASS')) fail('E7_PRERELEASE_GATE_ESCALATION');
    return {
      schemaVersion: 1,
      stage: 7,
      kind: 'STAGE7_PRERELEASE_CLOSEOUT',
      status: 'EXTERNAL_EVIDENCE_READY_FOR_STAGE6_REEVALUATION',
      scope: 'prerelease',
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      rawStage6EvidenceSha256: fileDigest(rawFilename),
      rawStage6ExternalRunId: raw.runId,
      cleanup: 'PASS',
      published: false,
      finalTagCreated: false,
      jobs,
      index,
      gates: index.gates,
      nextAction: 'INGEST_RAW_EVIDENCE_AND_REEMIT_GATE_E6_03',
      mutationsPerformedByVerifier: 0,
      containsSensitiveData: false,
      artifacts: provenance.ledger.counts.artifacts,
      evidence: provenance.ledger.counts.evidence,
      provenanceLedgerSha256: provenance.ledger.ledgerSha256,
    };
  } catch (error) {
    const reason =
      error instanceof Stage7ControlError ||
      error instanceof Stage7Error ||
      error instanceof Stage7ProvenanceError
        ? error.code
        : 'E7_VERIFY_UNEXPECTED_FAILURE';
    await materializeIncompleteProvenance({
      scope: 'prerelease',
      map,
      identity,
      config,
      jobAuthority,
      reason,
    });
    throw error;
  }
};

const verifyRelease = async (flags) => {
  const scope = scopeOf(flags);
  const output = path.join(evidenceRoot(scope), 'closeout.json');
  try {
    const result =
      scope === 'full' ? await verifyFullRelease(flags) : await verifyPrerelease(flags);
    await emitJson(result, output, 'stage7-closeout.json');
  } catch (error) {
    const code =
      error instanceof Stage7ControlError ||
      error instanceof Stage7Error ||
      error instanceof Stage7ProvenanceError
        ? error.code
        : 'E7_VERIFY_UNEXPECTED_FAILURE';
    const ledgerFilename = path.join(evidenceRoot(scope), 'provenance-ledger.json');
    const jobResultsArtifact =
      scope === 'full' ? 'stage7-release-authorities' : 'stage7-prerelease-authorities';
    const jobResultsFilename = path.join(
      workspaceRoot,
      '.stage7/evidence',
      jobResultsArtifact,
      'job-results.json',
    );
    const ledgerCandidate = existsSync(ledgerFilename) ? readEvidence(ledgerFilename) : null;
    const jobResultsCandidate = existsSync(jobResultsFilename)
      ? readEvidence(jobResultsFilename)
      : null;
    const expectedCandidateSha = process.env.STAGE7_CANDIDATE_SHA;
    const expectedReleaseId = process.env.STAGE7_RELEASE_ID;
    const expectedReleaseTag = scope === 'full' ? process.env.STAGE7_RELEASE_TAG : null;
    const ledger =
      ledgerCandidate?.scope === scope &&
      ledgerCandidate.candidateSha === expectedCandidateSha &&
      ledgerCandidate.releaseId === expectedReleaseId &&
      ledgerCandidate.releaseTag === expectedReleaseTag
        ? ledgerCandidate
        : null;
    const jobResults =
      jobResultsCandidate?.scope === scope &&
      jobResultsCandidate.candidateSha === expectedCandidateSha &&
      jobResultsCandidate.releaseId === expectedReleaseId &&
      jobResultsCandidate.releaseTag === expectedReleaseTag
        ? jobResultsCandidate
        : null;
    const status =
      ledger?.status === 'FAILED'
        ? 'FAILED'
        : ledger?.status === 'BLOCKED_AUTH'
          ? 'BLOCKED_AUTH'
          : ledger?.status === 'IN_PROGRESS'
            ? 'INCOMPLETE'
            : 'FAIL';
    await writeStage7Json(output, 'stage7-closeout-failed.json', {
      schemaVersion: 1,
      stage: 7,
      kind: scope === 'full' ? 'STAGE7_CLOSEOUT' : 'STAGE7_PRERELEASE_CLOSEOUT',
      status,
      scope,
      candidateSha: SHA.test(process.env.STAGE7_CANDIDATE_SHA ?? '')
        ? process.env.STAGE7_CANDIDATE_SHA
        : null,
      releaseId: RELEASE_ID.test(process.env.STAGE7_RELEASE_ID ?? '')
        ? process.env.STAGE7_RELEASE_ID
        : null,
      reason: code,
      gates: ledger?.gates ?? {
        'GATE-E7-01': 'FAIL',
        'GATE-E7-02': 'FAIL',
        'GATE-E7-03': 'FAIL',
      },
      jobResults:
        jobResults === null
          ? null
          : {
              status: jobResults.status,
              rawSha256: fileDigest(jobResultsFilename),
            },
      provenance:
        ledger === null
          ? null
          : {
              status: ledger.status,
              rawSha256: fileDigest(ledgerFilename),
              ledgerSha256: ledger.ledgerSha256,
              artifacts: ledger.counts?.artifacts,
              evidence: ledger.counts?.evidence,
            },
      nextStage: null,
      mutationsPerformedByVerifier: 0,
      containsSensitiveData: false,
    });
    throw error;
  }
};

const preUploadScan = (flags) => {
  const result = scanFileSet(flags['pre-upload']);
  process.stdout.write(
    `${JSON.stringify({
      schemaVersion: 1,
      stage: 7,
      kind: 'PRE_UPLOAD_SANITIZATION_SCAN',
      status: 'PASS',
      ...result,
      externalRequests: 0,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    })}\n`,
  );
};

const dispatchPreflight = async (flags) => {
  const operations = [
    'local-only',
    'aws-read',
    'approval',
    'aws-deploy',
    'aws-rollback',
    'aws-cleanup',
    'sandbox-authorized',
    'smoke-inputs',
    'external-authorization-request',
    'external-authorization',
  ].filter((key) => flags[key] !== undefined);
  if (operations.length !== 1) fail('E7_PREFLIGHT_MODE_INVALID');
  const operation = operations[0];
  if (operation === 'local-only') {
    exactFlags(flags, [
      'scope',
      'local-only',
      'stage6-evidence',
      'stage6-manifest-sha256',
      'require-e6-conditional-go',
      'evidence',
    ]);
    if (flags['local-only'] !== true) fail('E7_PREFLIGHT_MODE_INVALID');
    await preflightLocal(flags);
    return;
  }
  if (operation === 'aws-read') {
    exactFlags(flags, [
      'scope',
      'aws-read',
      'manifest',
      'cloud-assembly',
      'pre-freeze-synth',
      'no-write',
      'evidence',
      'journal-role-effective-permissions',
      'reconciliation-recovery-role-effective-permissions',
      'approved-environment',
      'non-public',
      'require-e6-conditional-go',
    ]);
    if (flags['aws-read'] !== true) fail('E7_PREFLIGHT_MODE_INVALID');
    await awsReadPreflight(flags);
    return;
  }
  if (operation === 'approval') {
    exactFlags(flags, [
      'scope',
      'approval',
      'github-approval-evidence',
      'manifest',
      'previous-manifest',
      'previous-api-contract-evidence',
      'previous-pending-evidence',
      'previous-smoke-evidence',
      'evidence',
      'approved-environment',
      'non-public',
      'require-e6-conditional-go',
    ]);
    await approvalPreflight(flags);
    return;
  }
  if (operation === 'external-authorization-request') {
    exactFlags(flags, ['scope', 'external-authorization-request', 'non-public', 'evidence']);
    await externalAuthorizationRequest(flags);
    return;
  }
  if (operation === 'external-authorization') {
    exactFlags(flags, [
      'scope',
      'external-authorization',
      'approved-environment',
      'non-public',
      'evidence',
    ]);
    await externalAuthorizationPreflight(flags);
    return;
  }
  if (operation === 'smoke-inputs') {
    exactFlags(flags, [
      'scope',
      'smoke-inputs',
      'manifest',
      'deployment',
      'approved-environment',
      'evidence',
    ]);
    await smokeInputsPreflight(flags);
    return;
  }
  exactFlags(flags, [
    'scope',
    operation,
    'manifest',
    'approved-environment',
    'non-public',
    'synthetic-only',
    'ephemeral-only',
    'previous-manifest',
    'previous-api-contract-evidence',
    'previous-pending-evidence',
    'previous-smoke-evidence',
    'cloud-assembly',
    'plan',
    'raw-diff',
    'approval',
    'aws-auth',
    'journal-role-effective-permissions',
    'reconciliation-recovery-role-effective-permissions',
    'safety-readiness',
    'deployment-evidence',
    'live-safety-recheck',
  ]);
  if (flags[operation] !== true) fail('E7_PREFLIGHT_MODE_INVALID');
  const scope = scopeOf(flags);
  if (operation === 'aws-deploy') {
    if (scope === 'prerelease' && flags['synthetic-only'] !== true) {
      fail('E7_PRERELEASE_SYNTHETIC_ONLY_REQUIRED');
    }
    await mutationAuthorityPreflight(flags, 'deploy');
  } else if (operation === 'aws-rollback') {
    if (scope !== 'full') fail('E7_ROLLBACK_SCOPE_INVALID');
    await mutationAuthorityPreflight(flags, 'rollback');
  } else if (operation === 'aws-cleanup') {
    if (scope !== 'prerelease' || flags['ephemeral-only'] !== true) {
      fail('E7_CLEANUP_SCOPE_INVALID');
    }
    await mutationAuthorityPreflight(flags, 'cleanup');
  } else {
    await mutationAuthorityPreflight(flags, 'sandbox');
  }
};

const dispatchVerifyCandidate = async (flags) => {
  exactFlags(flags, [
    'scope',
    'stage6-evidence',
    'stage6-manifest-sha256',
    'require-e6-conditional-go',
  ]);
  await verifyCandidate(flags);
};

const dispatchManifest = async (flags) => {
  const modes = ['freeze-existing', 'verify-artifact', 'verify-previous-manifest'].filter(
    (key) => flags[key] !== undefined,
  );
  if (modes.length !== 1) fail('E7_MANIFEST_MODE_INVALID');
  if (modes[0] === 'freeze-existing') {
    exactFlags(flags, [
      'scope',
      'freeze-existing',
      'stage6-evidence',
      'stage6-manifest-sha256',
      'source-artifact-id',
      'source-artifact-sha256',
      'tag',
      'pre-freeze-evidence',
      'require-e6-conditional-go',
    ]);
    if (flags['freeze-existing'] !== true) fail('E7_MANIFEST_MODE_INVALID');
    await freezeExisting(flags);
  } else if (modes[0] === 'verify-artifact') {
    exactFlags(flags, ['scope', 'verify-artifact', 'manifest', 'inventory', 'provenance']);
    if (flags.inventory !== true || flags.provenance !== true) {
      fail('E7_ARTIFACT_VERIFICATION_GUARDS_REQUIRED');
    }
    await verifyDownloadedArtifact(flags);
  } else {
    exactFlags(flags, [
      'scope',
      'verify-previous-manifest',
      'manifest-sha256',
      'approved-copy',
      'evidence',
    ]);
    await verifyPreviousManifest(flags);
  }
};

const dispatchScan = async (flags) => {
  const modes = [
    'pre-upload',
    'candidate',
    'cloud-assembly',
    'prepare-zap-target',
    'deployed-edge',
  ].filter((key) => flags[key] !== undefined);
  if (modes.length !== 1) fail('E7_SCAN_MODE_INVALID');
  if (modes[0] === 'pre-upload') {
    exactFlags(flags, ['scope', 'pre-upload']);
    if (flags.scope !== undefined) scopeOf(flags);
    preUploadScan(flags);
  } else if (modes[0] === 'candidate') {
    exactFlags(flags, ['scope', 'candidate', 'history', 'integrity', 'synthetic-only']);
    if (flags.history !== undefined && flags.history !== true) fail('E7_SCAN_HISTORY_FLAG_INVALID');
    await scanCandidate(flags);
  } else if (modes[0] === 'cloud-assembly') {
    exactFlags(flags, ['scope', 'cloud-assembly']);
    await scanAssembly(flags);
  } else if (modes[0] === 'prepare-zap-target') {
    exactFlags(flags, ['scope', 'prepare-zap-target', 'deployment', 'non-public']);
    await prepareZapTarget(flags);
  } else {
    exactFlags(flags, [
      'scope',
      'deployed-edge',
      'headers',
      'zap-passive-only',
      'passive-only',
      'non-public',
    ]);
    if (flags['deployed-edge'] !== true || flags['zap-passive-only'] !== true) {
      fail('E7_DEPLOYED_EDGE_PASSIVE_CAPTURE_REQUIRED');
    }
    if (scopeOf(flags) === 'full' && flags['passive-only'] !== true) {
      fail('E7_DEPLOYED_EDGE_PASSIVE_ONLY_REQUIRED');
    }
    if (scopeOf(flags) === 'prerelease' && flags.headers !== true) {
      fail('E7_DEPLOYED_EDGE_HEADERS_REQUIRED');
    }
    await deployedEdgeScan(flags);
  }
};

const dispatchPlan = async (flags) => {
  exactFlags(flags, ['scope', 'cloud-assembly']);
  await planRelease(flags);
};

const dispatchSmoke = async (flags) => {
  if (flags['close-versioned-rollback-pending-egress'] !== undefined) {
    exactFlags(flags, [
      'scope',
      'close-versioned-rollback-pending-egress',
      'manifest',
      'previous-manifest',
      'candidate-record',
      'rollback-evidence',
      'rollback-checkpoint',
      'repromotion-checkpoint',
      'pending-producer',
      'approved-environment',
      'evidence',
    ]);
    await closeVersionedRollbackPendingEgress(flags);
    return;
  }
  if (flags['prepare-versioned-rollback-pending'] !== undefined) {
    exactFlags(flags, [
      'scope',
      'prepare-versioned-rollback-pending',
      'manifest',
      'deployment',
      'approved-environment',
      'evidence',
    ]);
    await prepareVersionedRollbackPending(flags);
    return;
  }
  if (
    flags['post-versioned-rollback'] !== undefined ||
    flags['post-versioned-repromotion'] !== undefined ||
    flags['reconciliation-intent'] !== undefined ||
    flags['reconciliation-convergence'] !== undefined ||
    flags['reconciliation-recovery-actor'] !== undefined
  ) {
    exactFlags(flags, [
      'scope',
      'post-versioned-rollback',
      'post-versioned-repromotion',
      'previous-manifest',
      'candidate-record',
      'rollback-evidence',
      'transition',
      'emergency-recovery',
      'reconciliation-intent',
      'reconciliation-convergence',
      'reconciliation-recovery-actor',
      'external-authorization-evidence',
      'manifest',
      'evidence',
    ]);
    if (
      (flags['post-versioned-rollback'] !== undefined &&
        flags['post-versioned-rollback'] !== true) ||
      (flags['post-versioned-repromotion'] !== undefined &&
        flags['post-versioned-repromotion'] !== true)
    ) {
      fail('E7_VERSIONED_ROLLBACK_SMOKE_FLAGS_INVALID');
    }
    await runVersionedRollbackReadSmoke(flags);
    return;
  }
  exactFlags(flags, [
    'scope',
    'manifest',
    'expected-manifest',
    'synthetic-only',
    'external-uat',
    'non-public',
    'post-rollback',
    'post-repromotion',
    'initial-release',
  ]);
  if ((flags.manifest === undefined) === (flags['expected-manifest'] === undefined)) {
    fail('E7_SMOKE_MANIFEST_FLAG_INVALID');
  }
  await smokeRelease({
    ...flags,
    manifest: flags.manifest ?? flags['expected-manifest'],
    'expected-manifest': undefined,
  });
};

const dispatchSandboxSmoke = async (flags) => {
  exactFlags(flags, [
    'scope',
    'manifest',
    'deployment',
    'approved-environment',
    'non-public',
    'cloud-assembly',
    'plan',
    'raw-diff',
    'approval',
    'aws-auth',
    'safety-readiness',
    'deployment-evidence',
    'live-safety-recheck',
  ]);
  await sandboxSmokeRelease(flags);
};

const dispatchQuality = async (flags) => {
  exactFlags(flags, ['scope', 'manifest', 'deployment', 'approved-environment']);
  await qualityRelease(flags);
};

const dispatchPublish = async (flags) => {
  exactFlags(flags, ['evidence', 'resilience-app']);
  await publicationPackage(flags);
};

const dispatchPrepareReadme = async (flags) => {
  exactFlags(flags, []);
  await prepareReleaseReadme();
};

const dispatchVerify = async (flags) => {
  if (flags['emergency-recovery-no-action'] !== undefined) {
    exactFlags(flags, [
      'emergency-recovery-no-action',
      'manifest',
      'previous-manifest',
      'candidate-record',
      'emergency-recovery',
      'approval',
      'approved-plan',
      'deployment-evidence',
    ]);
    await verifyCandidateActiveNoActionRecovery(flags);
    return;
  }
  if (flags['publication-target'] !== undefined) {
    exactFlags(flags, ['publication-target', 'publication-evidence', 'resilience-app', 'evidence']);
    await publicationTargetVerification(flags);
    return;
  }
  if (flags['publication-native'] !== undefined) {
    exactFlags(flags, [
      'publication-native',
      'publication-target-proof',
      'publication-operation',
      'evidence',
    ]);
    await publicationNativeVerification(flags);
    return;
  }
  if (flags['external-checks'] !== undefined) {
    exactFlags(flags, [
      'scope',
      'external-checks',
      'emit-stage6-external-raw',
      'emit-stage6-external',
      'forbid-e7-pass',
    ]);
    if (
      (flags['emit-stage6-external-raw'] === undefined) ===
      (flags['emit-stage6-external'] === undefined)
    ) {
      fail('E7_STAGE6_RAW_OUTPUT_FLAG_INVALID');
    }
    await emitStage6ExternalRaw(flags);
    return;
  }
  const recoveryFlags = [
    'publication-recovery-intake',
    'publication-recovery-closeout-authority',
    'publication-recovery-plan',
    'publication-recovery-result',
  ];
  const recoveryMode = recoveryFlags.some((key) => flags[key] !== undefined);
  exactFlags(
    flags,
    recoveryMode
      ? ['scope', 'evidence', 'resilience-app', ...recoveryFlags]
      : ['scope', 'evidence', 'resilience-app', 'forbid-e7-pass', 'require-cleanup'],
  );
  if (
    recoveryMode &&
    (flags.scope !== 'full' || recoveryFlags.some((key) => typeof flags[key] !== 'string'))
  ) {
    fail('E7_PUBLICATION_RECOVERY_CONTROL_FLAGS_INVALID');
  }
  await verifyRelease(flags);
};

const controlConfigFixture = ({ scope = 'prerelease' } = {}) => {
  const full = scope === 'full';
  const environment = full ? 'assessment-release' : 'assessment-prerelease-e7-check';
  return {
    schemaVersion: 1,
    stage: 7,
    environment,
    authorization: {
      id: 'AUTH-E7-CONTROL-01',
      status: 'APPROVED',
      scope: full ? 'FULL_RELEASE_VERSIONED_UPDATE' : 'EPHEMERAL_PRERELEASE',
      ownerAlias: 'release-owner',
      approvedAtUtc: '2026-08-17T10:00:00.000Z',
      expiresAtUtc: '2026-08-18T10:00:00.000Z',
      stacks: expectedStage7Stacks(environment),
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
      accountId: '123456789012',
      region: 'us-east-1',
      roles: {
        readRoleArn: 'arn:aws:iam::123456789012:role/checkout-read',
        deployRoleArn: 'arn:aws:iam::123456789012:role/checkout-deploy',
        rollbackRoleArn: 'arn:aws:iam::123456789012:role/checkout-rollback',
        cleanupRoleArn: 'arn:aws:iam::123456789012:role/checkout-cleanup',
        baselineRoleArn: 'arn:aws:iam::123456789012:role/checkout-baseline',
      },
      sessionMode: 'OIDC',
    },
    window: {
      startsAtUtc: '2026-08-17T11:00:00.000Z',
      endsAtUtc: '2026-08-17T15:00:00.000Z',
    },
    budget: {
      maxUsd: 10,
      warningUsd: [5, 8],
      alertOwnerAlias: 'cost-owner',
      alertChannelAlias: 'cost-alerts',
      alertDestinationSha256: '3'.repeat(64),
    },
    domain: full
      ? {
          mode: 'CUSTOM_AUTHORIZED',
          hostname: 'checkout.example.test',
          apiHostname: 'api.example.test',
          hostedZoneId: 'Z1234567890ABC',
          webCertificateArn:
            'arn:aws:acm:us-east-1:123456789012:certificate/11111111-1111-1111-1111-111111111111',
          apiCertificateArn:
            'arn:aws:acm:us-east-1:123456789012:certificate/22222222-2222-2222-2222-222222222222',
          dnsIncluded: true,
        }
      : {
          mode: 'AWS_MANAGED',
          hostname: null,
          apiHostname: null,
          hostedZoneId: null,
          webCertificateArn: null,
          apiCertificateArn: null,
          dnsIncluded: false,
        },
    cleanup: {
      ownerAlias: 'cleanup-owner',
      expiresAtUtc: full ? '2026-08-20T15:00:00.000Z' : '2026-08-18T08:00:00.000Z',
      preserveBootstrap: true,
      preservePreviousRelease: true,
    },
    prereleaseAccess: full
      ? {
          mode: 'ORIGIN_GATE_ONLY',
          keyGroupId: null,
          publicKeyId: null,
          originTokenSecretArn: [
            'arn:aws:secretsmanager:us-east-1:123456789012',
            ['sec', 'ret'].join(''),
            'checkout/runtime-security',
          ].join(':'),
          originTokenSecretVersionId: 'a'.repeat(32),
          rotationDuringWindow: 'FORBIDDEN',
        }
      : {
          mode: 'CLOUDFRONT_SIGNED_COOKIE',
          keyGroupId: 'c2f83d9a-4f1e-4d7a-8b21-6c9d3e5f7a10',
          publicKeyId: 'K2STAGE7CHECKOUT',
          originTokenSecretArn: [
            'arn:aws:secretsmanager:us-east-1:123456789012',
            ['sec', 'ret'].join(''),
            'checkout/runtime-security',
          ].join(':'),
          originTokenSecretVersionId: 'a'.repeat(32),
          rotationDuringWindow: 'FORBIDDEN',
        },
    credentialReferences: [
      [
        'arn:aws:secretsmanager:us-east-1:123456789012',
        ['sec', 'ret'].join(''),
        'checkout/runtime-security',
      ].join(':'),
    ],
    containsSensitiveData: false,
  };
};

const authorizationFixture = ({ config, candidateSha, releaseId, origin, apiOrigin }) => {
  const scope =
    config.authorization.scope === 'FULL_RELEASE_VERSIONED_UPDATE' ? 'full' : 'prerelease';
  const requirements = Object.fromEntries(
    externalAuthorizationRequirements(scope).map((requirement) => [requirement.key, requirement]),
  );
  const authorization = (requirement, targetSha256, maxRequests, approvalIndex) => ({
    id: requirement.id,
    status: 'APPROVED',
    scope: requirement.scope,
    approvalSha256: String(approvalIndex).repeat(64),
    approvedTargetSha256: targetSha256,
    approvedAtUtc: '2026-08-17T11:00:00.000Z',
    expiresAtUtc: '2026-08-17T14:00:00.000Z',
    ownerAlias: 'qa-owner',
    maxRequests,
  });
  return {
    schemaId: 'async-checkout-stage7-external-authorizations',
    schemaVersion: 1,
    stage: 7,
    candidateSha,
    releaseId,
    stage7ConfigSha256: objectSha256(config),
    targets: {
      ownedOriginSha256: digest(origin),
      ...(scope === 'prerelease'
        ? {
            apiOriginSha256: digest(
              apiOrigin ?? 'https://abc123def4.execute-api.us-east-1.amazonaws.com',
            ),
          }
        : {}),
      sandboxHostSha256: digest('sandbox.wompi.co'),
    },
    authorizations: {
      ownedTarget: authorization(
        requirements.ownedTarget,
        digest(origin),
        scope === 'full' ? 100 : 10,
        4,
      ),
      sandboxSmoke: authorization(
        requirements.sandboxSmoke,
        digest('sandbox.wompi.co'),
        scope === 'full' ? 64 : 20,
        5,
      ),
      passiveSecurity: authorization(
        requirements.passiveSecurity,
        digest(origin),
        scope === 'full' ? 100 : 20,
        6,
      ),
    },
    containsSensitiveData: false,
  };
};

const cloudAssemblyLifecycleFixture = (scope) => {
  const policy = scope === 'full' ? 'Retain' : 'Delete';
  const tags = [
    { Key: 'DataClass', Value: 'synthetic-only' },
    {
      Key: 'Environment',
      Value: scope === 'full' ? 'assessment-release' : 'assessment-prerelease-lifecycle',
    },
    { Key: 'ExpiresOn', Value: '2026-08-20' },
  ];
  const lifecycle = (Type, Properties) => ({
    Type,
    Properties,
    DeletionPolicy: policy,
    UpdateReplacePolicy: policy,
  });
  const table = () =>
    lifecycle('AWS::DynamoDB::Table', {
      DeletionProtectionEnabled: scope === 'full',
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
      SSESpecification: { SSEEnabled: true },
      Tags: structuredClone(tags),
    });
  const templates = [
    { Resources: { CatalogTable: table(), CheckoutTable: table() } },
    {
      Resources: {
        ApiVersion: lifecycle('AWS::Lambda::Version', {}),
        WorkerVersion: lifecycle('AWS::Lambda::Version', {}),
      },
    },
    { Resources: {} },
    {
      Resources: {
        WebBucket: lifecycle('AWS::S3::Bucket', { Tags: structuredClone(tags) }),
        DeployImmutable: {
          Type: 'Custom::CDKBucketDeployment',
          Properties: { RetainOnDelete: scope === 'full' },
          DeletionPolicy: 'Delete',
          UpdateReplacePolicy: 'Delete',
        },
        DeployMutable: {
          Type: 'Custom::CDKBucketDeployment',
          Properties: { RetainOnDelete: scope === 'full' },
          DeletionPolicy: 'Delete',
          UpdateReplacePolicy: 'Delete',
        },
        ...(scope === 'prerelease'
          ? { AutoDelete: { Type: 'Custom::S3AutoDeleteObjects', Properties: {} } }
          : {}),
      },
    },
  ];
  const suffixes = ['data', 'api', 'observability', 'web'];
  const manifest = {
    artifacts: Object.fromEntries(
      suffixes.map((suffix, index) => [
        `checkout-${scope === 'full' ? 'assessment-release' : 'assessment-prerelease-lifecycle'}-${suffix}`,
        {
          type: 'aws:cloudformation:stack',
          properties: {
            templateFile: `${index}-${suffix}.template.json`,
            terminationProtection: scope === 'full',
          },
        },
      ]),
    ),
  };
  return { manifest, templates };
};

export const selfTestStage7Control = async () => {
  selfTestStage7();
  selfTestArtifactSanitizer();
  selfTestExternalEvidence();
  selfTestDeployedSmoke();
  selfTestDeployedQuality();
  assert.equal(
    readFileSync(path.join(workspaceRoot, '.gitignore'), 'utf8')
      .split(/\r?\n/u)
      .includes('.stage7/'),
    true,
    'downloaded Stage 7 artifacts must not dirty the immutable candidate checkout',
  );
  const iamSelfTest = selfTestIamEffectivePermissions();
  assert.equal(iamSelfTest.status, 'PASS');
  assert.equal(iamSelfTest.externalRequests, 0);
  assert.equal(iamSelfTest.mutationsPerformed, 0);
  await assert.rejects(
    validateControlPrereleaseSafety({ flags: { scope: 'prerelease' } }),
    (error) =>
      error instanceof Stage7ControlError && error.code === 'E7_PRERELEASE_SAFETY_INPUT_REQUIRED',
  );
  assert.deepEqual(parseFlags(['--scope', 'full', '--local-only']), {
    scope: 'full',
    'local-only': true,
  });
  assert.throws(() => parseFlags(['--scope', 'full', '--scope', 'full']), Stage7ControlError);
  assert.equal(awsScopeOf({ scope: 'baseline' }), 'baseline');
  for (const command of ['publish', 'smoke', 'verify']) {
    assert.throws(
      () => scopeOf({ scope: 'baseline' }),
      (error) => error.code === 'E7_SCOPE_INVALID',
      `${command} must reject the baseline-only scope`,
    );
  }
  const jobResultsFixture = (jobs) =>
    JSON.stringify(Object.fromEntries(jobs.map((job) => [job, { result: 'success' }])));
  assert.deepEqual(
    validateSuccessfulJobResults(jobResultsFixture(REQUIRED_FULL_JOBS), 'full'),
    REQUIRED_FULL_JOBS.toSorted(stableCompare),
  );
  assert.deepEqual(
    validateSuccessfulJobResults(jobResultsFixture(REQUIRED_PRERELEASE_JOBS), 'prerelease'),
    REQUIRED_PRERELEASE_JOBS.toSorted(stableCompare),
  );
  assert.throws(
    () => validateSuccessfulJobResults(jobResultsFixture(REQUIRED_FULL_JOBS.slice(1)), 'full'),
    (error) => error.code === 'E7_JOB_RESULTS_INVALID',
  );
  assert.throws(
    () =>
      validateSuccessfulJobResults(
        JSON.stringify({
          ...JSON.parse(jobResultsFixture(REQUIRED_FULL_JOBS)),
          unexpected: { result: 'success' },
        }),
        'full',
      ),
    (error) => error.code === 'E7_JOB_RESULTS_INVALID',
  );
  const failedJobs = JSON.parse(jobResultsFixture(REQUIRED_PRERELEASE_JOBS));
  failedJobs.cleanup.result = 'failure';
  assert.deepEqual(parseExactJobResults(JSON.stringify(failedJobs), 'prerelease'), failedJobs);
  assert.throws(
    () => validateSuccessfulJobResults(JSON.stringify(failedJobs), 'prerelease'),
    (error) => error.code === 'E7_JOB_RESULTS_NOT_SUCCESSFUL',
  );
  const incompleteJobs = JSON.parse(jobResultsFixture(REQUIRED_PRERELEASE_JOBS));
  incompleteJobs['external-evidence'].result = 'skipped';
  assert.deepEqual(
    parseExactJobResults(JSON.stringify(incompleteJobs), 'prerelease'),
    incompleteJobs,
  );

  const config = controlConfigFixture();
  const now = new Date('2026-08-17T12:00:00.000Z');
  validateStage7Config(config, { now });
  const recoverySmokeSource = {
    candidateSha: 'a'.repeat(40),
    releaseId: 'rel-20260818-0100-aaaaaaa',
    releaseTag: 'v1.0.0',
    configSha256: objectSha256(config),
  };
  const recoverySmokeEnvironment = {
    GITHUB_REPOSITORY: 'ivanmonsalve0404/async-checkout-demo',
    GITHUB_WORKFLOW_REF:
      'ivanmonsalve0404/async-checkout-demo/.github/workflows/stage7-release-reconciliation-recovery.yml@refs/heads/master',
    GITHUB_REF: 'refs/heads/master',
    GITHUB_EVENT_NAME: 'workflow_dispatch',
    GITHUB_RUN_ID: '123456789',
    GITHUB_RUN_ATTEMPT: '2',
    GITHUB_ACTOR_ID: '987654321',
    GITHUB_SHA: 'c'.repeat(40),
    STAGE7_PROTECTED_ENVIRONMENT: 'assessment-release-reconciliation-recovery',
    STAGE7_RECOVERY_CANDIDATE_SHA: recoverySmokeSource.candidateSha,
  };
  const recoverySmokeRun = {
    repository: recoverySmokeEnvironment.GITHUB_REPOSITORY,
    workflowPath: '.github/workflows/stage7-release-reconciliation-recovery.yml',
    workflowRef: recoverySmokeEnvironment.GITHUB_WORKFLOW_REF,
    ref: recoverySmokeEnvironment.GITHUB_REF,
    eventName: recoverySmokeEnvironment.GITHUB_EVENT_NAME,
    runId: recoverySmokeEnvironment.GITHUB_RUN_ID,
    runAttempt: Number(recoverySmokeEnvironment.GITHUB_RUN_ATTEMPT),
    actorId: recoverySmokeEnvironment.GITHUB_ACTOR_ID,
    controlSha: recoverySmokeEnvironment.GITHUB_SHA,
    protectedEnvironment: recoverySmokeEnvironment.STAGE7_PROTECTED_ENVIRONMENT,
    candidateSha: recoverySmokeSource.candidateSha,
  };
  const recoverySmokeManifest = {
    candidateSha: recoverySmokeSource.candidateSha,
    candidateTreeSha: 'b'.repeat(40),
    releaseId: recoverySmokeSource.releaseId,
    releaseTag: recoverySmokeSource.releaseTag,
    authorizationScope: 'FULL_RELEASE_VERSIONED_UPDATE',
    environment: config.environment,
    region: config.aws.region,
    configSha256: recoverySmokeSource.configSha256,
  };
  const recoveryControlIdentity = {
    commitSha: recoverySmokeRun.controlSha,
    workingTree: 'CLEAN',
    changedFiles: 0,
  };
  assert.deepEqual(
    validateRecoverySmokeRunIdentity({
      recoveryActor: {
        recoveryRun: recoverySmokeRun,
        originalSource: recoverySmokeSource,
      },
      config,
      manifest: recoverySmokeManifest,
      controlIdentity: recoveryControlIdentity,
      environmentVariables: recoverySmokeEnvironment,
      taggedCandidate: recoverySmokeSource.candidateSha,
    }),
    {
      commitSha: recoverySmokeSource.candidateSha,
      treeSha: recoverySmokeManifest.candidateTreeSha,
      workingTree: 'CLEAN',
      changedFiles: 0,
      candidateSha: recoverySmokeSource.candidateSha,
      releaseId: recoverySmokeSource.releaseId,
      releaseTag: recoverySmokeSource.releaseTag,
    },
  );
  for (const mutation of [
    ({ environmentVariables }) => {
      environmentVariables.GITHUB_RUN_ID = '123456788';
    },
    ({ controlIdentity }) => {
      controlIdentity.commitSha = 'd'.repeat(40);
    },
    ({ manifest }) => {
      manifest.configSha256 = 'e'.repeat(64);
    },
    (fixture) => {
      fixture.taggedCandidate = 'f'.repeat(40);
    },
  ]) {
    const fixture = {
      recoveryActor: {
        recoveryRun: structuredClone(recoverySmokeRun),
        originalSource: structuredClone(recoverySmokeSource),
      },
      config,
      manifest: structuredClone(recoverySmokeManifest),
      controlIdentity: structuredClone(recoveryControlIdentity),
      environmentVariables: structuredClone(recoverySmokeEnvironment),
      taggedCandidate: recoverySmokeSource.candidateSha,
    };
    mutation(fixture);
    assert.throws(
      () => validateRecoverySmokeRunIdentity(fixture),
      (error) =>
        error instanceof Stage7ControlError &&
        error.code === 'E7_RELEASE_RECONCILIATION_RECOVERY_SMOKE_IDENTITY_INVALID',
    );
  }
  const accessProbeFixture = {
    directAnonymousStatus: 403,
    directOriginSpoofStatus: 403,
    authorizedApiStatus: 200,
    originProtectionHeaderExposed: false,
    originProtectionHeaderValueExposed: false,
    originProtectionMetadataReflected: false,
    jsonContentType: true,
    noStore: true,
    readyBodyValid: true,
  };
  assert.equal(prereleaseOriginGatePassed(accessProbeFixture), true);
  for (const mutation of [
    { directAnonymousStatus: 200 },
    { directOriginSpoofStatus: 200 },
    { authorizedApiStatus: 403 },
    { originProtectionHeaderExposed: true },
    { originProtectionHeaderValueExposed: true },
    { originProtectionMetadataReflected: true },
    { noStore: false },
  ]) {
    assert.equal(prereleaseOriginGatePassed({ ...accessProbeFixture, ...mutation }), false);
  }
  const fullLifecycle = cloudAssemblyLifecycleFixture('full');
  const prereleaseLifecycle = cloudAssemblyLifecycleFixture('prerelease');
  assert.deepEqual(validateCloudAssemblyLifecycle({ scope: 'full', ...fullLifecycle }), {
    statefulResources: 7,
    tables: 2,
    buckets: 1,
    lambdaVersions: 2,
    autoDeleteResources: 0,
    bucketDeployments: 2,
  });
  assert.equal(
    validateCloudAssemblyLifecycle({ scope: 'prerelease', ...prereleaseLifecycle })
      .autoDeleteResources,
    1,
  );
  assert.throws(
    () => validateCloudAssemblyLifecycle({ scope: 'full', ...prereleaseLifecycle }),
    (error) => error.code === 'E7_CLOUD_ASSEMBLY_TERMINATION_PROTECTION_INVALID',
  );
  assert.throws(
    () => validateCloudAssemblyLifecycle({ scope: 'prerelease', ...fullLifecycle }),
    (error) => error.code === 'E7_CLOUD_ASSEMBLY_TERMINATION_PROTECTION_INVALID',
  );
  const weakFullLifecycle = structuredClone(fullLifecycle);
  weakFullLifecycle.templates[0].Resources.CatalogTable.Properties.DeletionProtectionEnabled = false;
  assert.throws(
    () => validateCloudAssemblyLifecycle({ scope: 'full', ...weakFullLifecycle }),
    (error) => error.code === 'E7_CLOUD_ASSEMBLY_STATEFUL_PROTECTION_INVALID',
  );
  const untaggedPrereleaseLifecycle = structuredClone(prereleaseLifecycle);
  untaggedPrereleaseLifecycle.templates[0].Resources.CatalogTable.Properties.Tags.pop();
  assert.throws(
    () => validateCloudAssemblyLifecycle({ scope: 'prerelease', ...untaggedPrereleaseLifecycle }),
    (error) => error.code === 'E7_CLOUD_ASSEMBLY_EPHEMERAL_TAGS_INVALID',
  );
  const uncleanablePrereleaseLifecycle = structuredClone(prereleaseLifecycle);
  delete uncleanablePrereleaseLifecycle.templates[3].Resources.AutoDelete;
  assert.throws(
    () =>
      validateCloudAssemblyLifecycle({ scope: 'prerelease', ...uncleanablePrereleaseLifecycle }),
    (error) => error.code === 'E7_CLOUD_ASSEMBLY_CLEANUP_CONTRACT_INVALID',
  );
  const candidateSha = 'a'.repeat(40);
  const releaseId = 'rel-20260817-1200-aaaaaaa';
  const origin = 'https://owned-qa.example.test';
  const apiOrigin = 'https://abc123def4.execute-api.us-east-1.amazonaws.com';
  const authorization = authorizationFixture({
    config,
    candidateSha,
    releaseId,
    origin,
    apiOrigin,
  });
  validateExternalAuthorizations({
    value: authorization,
    config,
    candidateSha,
    releaseId,
    deployedOrigin: origin,
    deployedApiOrigin: apiOrigin,
    now,
  });
  const fullConfig = controlConfigFixture({ scope: 'full' });
  validateStage7Config(fullConfig, { now });
  const baselineConfig = createBaselineConfigSelfTestFixture();
  verifyAwsConfigScope(baselineConfig, 'baseline');
  const baselineFreeze = createBaselineFreezeSelfTestFixture(baselineConfig);
  assert.equal(validateBaselineFreeze(baselineFreeze), baselineFreeze);
  assert.throws(() => validateFreezeManifest(baselineFreeze), Stage7Error);
  const fullOrigin = 'https://checkout.example.test';
  const fullAuthorization = authorizationFixture({
    config: fullConfig,
    candidateSha,
    releaseId,
    origin: fullOrigin,
  });
  const validatedFullAuthorization = validateExternalAuthorizations({
    value: fullAuthorization,
    config: fullConfig,
    candidateSha,
    releaseId,
    deployedOrigin: fullOrigin,
    now,
  });
  const fullAuthorizationIds = externalAuthorizationRequirements('full').map(({ id }) => id);
  const authorizationEvidenceFixture = {
    authorizationSha256: objectSha256(validatedFullAuthorization.value),
    ownedOriginSha256: validatedFullAuthorization.originSha256,
    sandboxHostSha256: validatedFullAuthorization.sandboxHostSha256,
    requestLimits: Object.fromEntries(
      externalAuthorizationRequirements('full').map(({ key, id }) => [
        id,
        validatedFullAuthorization.authorizations[key].maxRequests,
      ]),
    ),
  };
  authorizationEvidenceFixture.externalRequestBudgetPlan = createFullExternalRequestBudgetPlan({
    candidateSha,
    releaseId,
    configSha256: objectSha256(fullConfig),
    authorizationSha256: authorizationEvidenceFixture.authorizationSha256,
    ownedOriginSha256: authorizationEvidenceFixture.ownedOriginSha256,
    sandboxHostSha256: authorizationEvidenceFixture.sandboxHostSha256,
    requestLimits: authorizationEvidenceFixture.requestLimits,
  });
  assert.equal(
    validateAuthorizationBudgetPlan({
      authorization: authorizationEvidenceFixture,
      identity: { candidateSha, releaseId },
      config: fullConfig,
    }).planSha256,
    authorizationEvidenceFixture.externalRequestBudgetPlan.planSha256,
  );
  assert.throws(
    () =>
      validateAuthorizationBudgetPlan({
        authorization: {
          ...authorizationEvidenceFixture,
          externalRequestBudgetPlan: {
            ...authorizationEvidenceFixture.externalRequestBudgetPlan,
            ownedOriginSha256: '9'.repeat(64),
          },
        },
        identity: { candidateSha, releaseId },
        config: fullConfig,
      }),
    (error) => error.code === 'E7_EXTERNAL_REQUEST_BUDGET_PLAN_INVALID',
  );
  const usageFixture = (usageId, count = 1) =>
    authorizationUsage({
      scope: 'full',
      authority: validatedFullAuthorization,
      identity: { candidateSha, releaseId },
      config: fullConfig,
      usageId,
      requestCounts: { [fullAuthorizationIds[0]]: count },
    });
  const externalAuthorizationCheckpointFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'EXTERNAL_AUTHORIZATION_PREFLIGHT',
    status: 'PASS',
    scope: 'full',
    candidateSha,
    releaseId,
    stage7ConfigSha256: objectSha256(fullConfig),
    ownedOriginSha256: authorizationEvidenceFixture.ownedOriginSha256,
    sandboxHostSha256: authorizationEvidenceFixture.sandboxHostSha256,
    authorizationSha256: authorizationEvidenceFixture.authorizationSha256,
    authorizationIds: fullAuthorizationIds,
    requestLimits: authorizationEvidenceFixture.requestLimits,
    externalRequestBudgetPlan: authorizationEvidenceFixture.externalRequestBudgetPlan,
    authorizationUsage: authorizationUsage({
      scope: 'full',
      authority: validatedFullAuthorization,
      identity: { candidateSha, releaseId },
      config: fullConfig,
      usageId: 'EXTERNAL_AUTHORIZATION_PREFLIGHT',
    }),
    targetValuesCaptured: false,
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  assert.equal(
    validateExternalAuthorizationCheckpoint({
      document: externalAuthorizationCheckpointFixture,
      scope: 'full',
      identity: { candidateSha, releaseId },
      config: fullConfig,
    }),
    externalAuthorizationCheckpointFixture,
  );
  for (const document of [
    {},
    { ...externalAuthorizationCheckpointFixture, unexpected: true },
    { ...externalAuthorizationCheckpointFixture, scope: 'prerelease' },
    { ...externalAuthorizationCheckpointFixture, candidateSha: 'b'.repeat(40) },
  ]) {
    assert.throws(
      () =>
        validateExternalAuthorizationCheckpoint({
          document,
          scope: 'full',
          identity: { candidateSha, releaseId },
          config: fullConfig,
        }),
      (error) => error.code === 'E7_EXTERNAL_AUTHORIZATION_CHECKPOINT_INVALID',
    );
  }
  const qualityPayloadFixture = {
    crossBrowser: ['chromium', 'firefox', 'webkit'].map((engine) => ({
      engine,
      version: '1.2.3',
      status: 'PASS',
      viewport: '390x844',
      product: 'PASS',
      keyboard: 'PASS',
      responsive: 'PASS',
      targetSize: 'PASS',
    })),
    accessibility: {
      status: 'PASS',
      tool: { name: 'axe-core', version: '4.12.1' },
      surface: '/products/product-demo-001',
      violations: 0,
      incomplete: 0,
      passes: 10,
      duplicateIds: 0,
      keyboardCta: 'PASS',
      reducedMotion: 'PASS',
      assistivePriceCop: 'PASS',
    },
    lighthouse: {
      status: 'PASS',
      tool: { name: 'lighthouse', version: '13.4.1' },
      surface: '/products/product-demo-001',
      formFactor: 'mobile-390x844',
      measuredRuns: 3,
      budgets: {},
      runs: Array.from({ length: 3 }, (_, index) => ({
        run: index + 1,
        performanceScore: 0.9,
        accessibilityScore: 1,
        bestPracticesScore: 1,
        lcpMs: 1_000,
        cls: 0.01,
        totalByteWeight: 500_000,
        https: 1,
        mixedContent: 1,
      })),
      fieldTelemetry: 'NOT_AVAILABLE_LAB_ONLY',
      rawHtmlPersisted: false,
      requests: 12,
    },
    requests: { ownedOrigin: 24, outsideAllowlist: 0, mutations: 0 },
    criticalErrors: { console: 0, page: 0, network: 0 },
  };
  const qualityCheckpointFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'DEPLOYED_FOCAL_QUALITY',
    status: 'PASS',
    scope: 'full',
    candidateSha,
    releaseId,
    manifestSha256: '7'.repeat(64),
    configSha256: objectSha256(fullConfig),
    targetOriginSha256: digest(fullOrigin),
    authorizationSha256: authorizationEvidenceFixture.authorizationSha256,
    authorizationUsage: authorizationUsage({
      scope: 'full',
      authority: validatedFullAuthorization,
      identity: { candidateSha, releaseId },
      config: fullConfig,
      usageId: 'QUALITY_FOCAL',
      requestCounts: { [fullAuthorizationIds[2]]: 24 },
    }),
    evidenceIds: ['EVD-E7-42', 'EVD-E7-43', 'EVD-E7-44'],
    ...qualityPayloadFixture,
    externalRequests: 24,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const qualityCheckpointInput = {
    identity: { candidateSha, releaseId },
    config: fullConfig,
    freezeManifest: { manifestSha256: '7'.repeat(64) },
    authorization: authorizationEvidenceFixture,
    applicationOrigin: fullOrigin,
  };
  assert.equal(
    validateQualityCheckpoint({
      document: qualityCheckpointFixture,
      ...qualityCheckpointInput,
    }),
    qualityCheckpointFixture,
  );
  for (const document of [
    {},
    { ...qualityCheckpointFixture, unexpected: true },
    { ...qualityCheckpointFixture, scope: 'prerelease' },
    { ...qualityCheckpointFixture, candidateSha: 'b'.repeat(40) },
    { ...qualityCheckpointFixture, authorizationSha256: '0'.repeat(64) },
  ]) {
    assert.throws(
      () => validateQualityCheckpoint({ document, ...qualityCheckpointInput }),
      (error) => error.code === 'E7_QUALITY_CHECKPOINT_INVALID',
    );
  }
  const zapSummaryFixture = {
    mode: 'PASSIVE_BASELINE',
    tool: { name: 'OWASP_ZAP_BASELINE', version: '2.16.1' },
    rulesetSha256: '1'.repeat(64),
    reportSha256: '2'.repeat(64),
    inventorySha256: '3'.repeat(64),
    captureSha256: '4'.repeat(64),
    openApiRawSha256: '5'.repeat(64),
    observationsSha256: '6'.repeat(64),
    ownEndpointsScanned: ZAP_PASSIVE_REQUEST_COUNT,
    ownEndpointsOutOfScope: 0,
    findings: {
      total: 0,
      reviewed: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    },
    manualValidation: 'ALL_ALERTS_REVIEWED',
    budgetEnforcement: 'ENFORCED_BEFORE_EGRESS',
  };
  const passiveCounts = Object.fromEntries(
    fullAuthorizationIds.map((id) => [id, id === fullAuthorizationIds[2] ? 12 : 0]),
  );
  const edgeCheckpointFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'DEPLOYED_EDGE_SECURITY',
    status: 'PASS',
    scope: 'full',
    candidateSha,
    releaseId,
    urls: {
      application: fullOrigin,
      api: `${fullOrigin}/api`,
      docs: `${fullOrigin}/api/docs`,
      health: `${fullOrigin}/api/health/ready`,
    },
    httpRedirect: 'PASS',
    httpsDocument: 'PASS',
    mixedContentRequests: 0,
    headers: Object.fromEntries(
      [...REQUIRED_HEADERS, 'clickjacking'].map((header) => [header, 'PASS']),
    ),
    sensitiveResponsesNoStore: true,
    corsExact: true,
    directS3Denied: 'PASS',
    tlsBaseline:
      fullConfig.domain.mode === 'CUSTOM_AUTHORIZED' ? 'TLS12_CONFIGURED' : 'PRERELEASE_LIMITED',
    zap: zapSummaryFixture,
    externalAuthorization: {
      authorizationSha256: authorizationEvidenceFixture.authorizationSha256,
      authorizationIds: fullAuthorizationIds,
      ownedOriginSha256: authorizationEvidenceFixture.ownedOriginSha256,
      sandboxHostSha256: authorizationEvidenceFixture.sandboxHostSha256,
    },
    authorizationUsage: authorizationUsage({
      scope: 'full',
      authority: validatedFullAuthorization,
      identity: { candidateSha, releaseId },
      config: fullConfig,
      usageId: 'EDGE_PASSIVE',
      requestCounts: { [fullAuthorizationIds[2]]: 12 },
    }),
    requests: { ownedOrigin: 6, directS3: 0, awsPrivateOrigin: 2, zap: 6 },
    requestBudgetComponents: {
      direct: {
        componentId: 'EDGE_PASSIVE_DIRECT',
        requestCounts: Object.fromEntries(
          fullAuthorizationIds.map((id) => [id, id === fullAuthorizationIds[2] ? 6 : 0]),
        ),
      },
      zap: {
        componentId: 'EDGE_PASSIVE_ZAP_EXACT_INVENTORY',
        requestCounts: Object.fromEntries(
          fullAuthorizationIds.map((id) => [id, id === fullAuthorizationIds[2] ? 6 : 0]),
        ),
      },
    },
    externalRequests: 16,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const edgeCheckpointInput = {
    scope: 'full',
    identity: { candidateSha, releaseId },
    config: fullConfig,
    authorization: authorizationEvidenceFixture,
    applicationOrigin: fullOrigin,
  };
  assert.deepEqual(edgeCheckpointFixture.authorizationUsage.requestCounts, passiveCounts);
  assert.equal(
    validateEdgeSecurityCheckpoint({
      document: edgeCheckpointFixture,
      ...edgeCheckpointInput,
    }),
    edgeCheckpointFixture,
  );
  for (const document of [
    {},
    { ...edgeCheckpointFixture, unexpected: true },
    { ...edgeCheckpointFixture, scope: 'prerelease' },
    { ...edgeCheckpointFixture, candidateSha: 'b'.repeat(40) },
    { ...edgeCheckpointFixture, zap: { ...zapSummaryFixture, unexpected: true } },
    {
      ...edgeCheckpointFixture,
      requestBudgetComponents: {
        ...edgeCheckpointFixture.requestBudgetComponents,
        direct: {
          ...edgeCheckpointFixture.requestBudgetComponents.direct,
          requestCounts: { ...passiveCounts, [fullAuthorizationIds[2]]: 5 },
        },
      },
    },
  ]) {
    assert.throws(
      () => validateEdgeSecurityCheckpoint({ document, ...edgeCheckpointInput }),
      (error) => error.code === 'E7_EDGE_SECURITY_CHECKPOINT_INVALID',
    );
  }
  const sandboxChecksFixture = [
    ['AUTH02-E6-01', 'acceptance-configuration-observed'],
    ['AUTH02-E6-02', 'authorized-test-payment-method-created'],
    ['AUTH02-E6-03', 'local-pending-created-first'],
    ['AUTH02-E6-04', 'provider-sandbox-transaction-created'],
    ['AUTH02-E6-05', 'provider-status-polled'],
    ['AUTH02-E6-06', 'amount-currency-reference-validated'],
    ['AUTH02-E6-07', 'provider-errors-redacted'],
    ['AUTH02-E6-08', 'reconciliation-replay-idempotent'],
  ].map(([id, name]) => ({ id, name, status: 'PASS' }));
  const sandboxRequestsFixture = {
    total: 8,
    configurationReads: 3,
    paymentMethodCreations: 1,
    transactionCreates: 1,
    statusReads: 1,
    errorMappingProbes: 1,
    reconciliationReplays: 1,
    production: 0,
    globalMutations: 0,
    outsideAllowlist: 0,
  };
  const sandboxResultFixture = {
    providerState: 'APPROVED',
    localState: 'APPROVED',
    amountMatches: true,
    currencyMatches: true,
    referenceMatches: true,
    reconciliationConsistent: true,
    duplicateEffects: 0,
    adapterDisabledByConfiguration: true,
  };
  const stage6SandboxAuthorizationSha256 = '8'.repeat(64);
  const sandboxReferenceSha256 = '9'.repeat(64);
  const sandboxExecutionFixture = {
    schemaVersion: 1,
    kind: 'SANDBOX_ONE_USE_EXECUTION',
    claimSha256: '1'.repeat(64),
    bindingSha256: '2'.repeat(64),
    runId: '123456789',
    runAttempt: 1,
    workflowSha: candidateSha,
    workflowJob: 'sandbox-smoke',
    environment: 'assessment-release',
    candidateSha,
    releaseId,
    configSha256: objectSha256(fullConfig),
    stage6AuthorizationSha256: stage6SandboxAuthorizationSha256,
    stage7AuthorizationSha256: '3'.repeat(64),
    approvalRequestSha256: '4'.repeat(64),
    approvalResponseSha256: '5'.repeat(64),
    approvedByAlias: 'release-reviewer',
    referenceSha256: sandboxReferenceSha256,
    maximumExternalRequests: 8,
    maximumTokenizations: 1,
    maximumTransactions: 1,
    localAtomicConsumption: true,
    providerDuplicateReferenceDefense: true,
    containsSensitiveData: false,
  };
  const sandboxCheckpointFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'AUTHORIZED_SANDBOX_SMOKE',
    status: 'PASS',
    scope: 'full',
    candidateSha,
    releaseId,
    manifestSha256: '7'.repeat(64),
    stage7ConfigSha256: objectSha256(fullConfig),
    executedAtUtc: '2026-08-17T12:00:00.000Z',
    reviewerAlias: 'release-reviewer',
    targetOriginSha256: digest(fullOrigin),
    sandboxHostSha256: digest(SANDBOX_HOST),
    externalAuthorization: {
      authorizationSha256: authorizationEvidenceFixture.authorizationSha256,
      authorization: validatedFullAuthorization.authorizations.sandboxSmoke,
    },
    authorizationUsage: authorizationUsage({
      scope: 'full',
      authority: validatedFullAuthorization,
      identity: { candidateSha, releaseId },
      config: fullConfig,
      usageId: 'SANDBOX_ONE_USE',
      requestCounts: { [fullAuthorizationIds[1]]: 8 },
    }),
    stage6Authorization: {
      authorizationId: 'AUTH-E6-02',
      authorizationSha256: stage6SandboxAuthorizationSha256,
      runId: 'e6-20260817t120000z-aaaaaaaa',
      fixtureSha256: '6'.repeat(64),
      rawFixtureCaptured: false,
    },
    oneUseExecution: sandboxExecutionFixture,
    checks: sandboxChecksFixture,
    referenceSha256: sandboxReferenceSha256,
    requests: sandboxRequestsFixture,
    result: sandboxResultFixture,
    productionRequests: 0,
    duplicateEffects: 0,
    externalRequests: 8,
    mutationsPerformed: 1,
    containsSensitiveData: false,
  };
  const sandboxCheckpointInput = {
    scope: 'full',
    identity: { candidateSha, releaseId },
    config: fullConfig,
    freezeManifest: { manifestSha256: '7'.repeat(64) },
    authorization: authorizationEvidenceFixture,
    applicationOrigin: fullOrigin,
  };
  assert.equal(
    validateSandboxCheckpoint({
      document: sandboxCheckpointFixture,
      ...sandboxCheckpointInput,
    }),
    sandboxCheckpointFixture,
  );
  for (const document of [
    {},
    { ...sandboxCheckpointFixture, unexpected: true },
    { ...sandboxCheckpointFixture, scope: 'prerelease' },
    { ...sandboxCheckpointFixture, candidateSha: 'b'.repeat(40) },
    {
      ...sandboxCheckpointFixture,
      requests: { ...sandboxRequestsFixture, unexpected: true },
    },
    {
      ...sandboxCheckpointFixture,
      oneUseExecution: { ...sandboxExecutionFixture, workflowSha: 'b'.repeat(40) },
    },
  ]) {
    assert.throws(
      () => validateSandboxCheckpoint({ document, ...sandboxCheckpointInput }),
      (error) => error.code === 'E7_SANDBOX_CHECKPOINT_INVALID',
    );
  }
  const reconciliationSourceFixture = {
    repository: 'ivanmonsalve0404/async-checkout-demo',
    workflowPath: '.github/workflows/release.yml',
    ref: 'refs/heads/master',
    runId: '123456789',
    runAttempt: 1,
    candidateSha,
    releaseId,
    releaseTag: 'v1.0.0',
    configSha256: objectSha256(fullConfig),
  };
  const reconciliationUsageFixture = (phase, usageId) => {
    const usage = usageFixture(usageId, 3);
    return {
      schemaVersion: usage.schemaVersion,
      phase,
      usageId: usage.usageId,
      authorizationSha256: usage.bundleSha256,
      bundleSha256: usage.bundleSha256,
      configSha256: usage.configSha256,
      candidateSha: usage.candidateSha,
      releaseId: usage.releaseId,
      ownedOriginSha256: usage.ownedOriginSha256,
      sandboxHostSha256: usage.sandboxHostSha256,
      requestCounts: usage.requestCounts,
      total: 3,
      passed: 3,
      failed: 0,
      containsSensitiveData: false,
    };
  };
  for (const [phase, usageId] of [
    ['ROLLBACK_CHECK', 'RECONCILIATION_ROLLBACK_CHECK_SMOKE'],
    ['ROLLBACK_RESILIENCE', 'RECONCILIATION_ROLLBACK_RESILIENCE_SMOKE'],
  ]) {
    const reconciliationUsage = reconciliationUsageFixture(phase, usageId);
    assert.equal(
      reconciliationAuthorizationLedgerUsage({
        usage: reconciliationUsage,
        phase,
        source: reconciliationSourceFixture,
      }).usageId,
      usageId,
    );
    assert.throws(
      () =>
        reconciliationAuthorizationLedgerUsage({
          usage: { ...reconciliationUsage, authorizationSha256: '9'.repeat(64) },
          phase,
          source: reconciliationSourceFixture,
        }),
      (error) => error.code === 'E7_RELEASE_RECONCILIATION_AUTHORIZATION_USAGE_INVALID',
    );
  }
  const manifestSha256 = '7'.repeat(64);
  const [dataStackName, apiStackName, observabilityStackName, webStackName] =
    fullConfig.authorization.stacks;
  void dataStackName;
  void observabilityStackName;
  const enabledState = (stackName) => ({
    stackName,
    stackIdSha256: '8'.repeat(64),
    state: 'ENABLED',
  });
  const transitionState = (stackName, state) => ({
    changed: true,
    previousState: state === 'ENABLED' ? 'DISABLED' : 'ENABLED',
    state,
    stackIdSha256: '8'.repeat(64),
    stackName,
  });
  const schedulerState = (state) => ({
    controlledBy: 'PublicationState',
    stackName: apiStackName,
    state,
  });
  const activationCheckpointFixture = {
    decision: 'ACTIVATED_REQUIRES_SMOKE',
    releaseMode: 'VERSIONED_UPDATE',
    updateReleaseSupported: true,
    previousReleaseManifestSha256: '6'.repeat(64),
    assemblySha256: '1'.repeat(64),
    freezeManifestSha256: manifestSha256,
    seedEvidenceSha256: '2'.repeat(64),
    publicOriginSha256: validatedFullAuthorization.originSha256,
    externalAuthorization: {
      authorizationSha256: objectSha256(validatedFullAuthorization.value),
      authorizationIds: fullAuthorizationIds,
      publicOriginSha256: validatedFullAuthorization.originSha256,
    },
    observabilityReadiness: {
      evidenceSha256: '3'.repeat(64),
      alertDestinationSha256: fullConfig.budget.alertDestinationSha256,
      alertTopicSha256: '4'.repeat(64),
      status: 'CONFIRMED',
    },
    publication: {
      managedByCloudFormation: true,
      apiStack: enabledState(apiStackName),
      webStack: enabledState(webStackName),
      scheduler: schedulerState('ENABLED'),
    },
    promotions: {
      api: { changed: false, version: '1' },
      worker: { changed: false, version: '1' },
      web: { invalidatedPaths: [], restoredObjects: 0 },
    },
    scheduleTargetSha256: '5'.repeat(64),
    transitions: [
      {
        sequence: 1,
        mode: 'CANDIDATE_ACTIVATION',
        apiStack: transitionState(apiStackName, 'ENABLED'),
        webStack: transitionState(webStackName, 'ENABLED'),
        scheduler: schedulerState('ENABLED'),
        authorizationUsage: usageFixture('ACTIVATION_CANDIDATE'),
      },
      {
        sequence: 2,
        mode: 'REPROMOTION',
        apiStack: transitionState(apiStackName, 'ENABLED'),
        webStack: transitionState(webStackName, 'ENABLED'),
        scheduler: schedulerState('ENABLED'),
        authorizationUsage: usageFixture('ACTIVATION_REPROMOTION'),
      },
    ],
  };
  validateStage7ActivationCheckpoint(activationCheckpointFixture, {
    config: fullConfig,
    candidateSha,
    releaseId,
    manifestSha256,
    complete: true,
  });
  const activationWrongCasing = structuredClone(activationCheckpointFixture);
  activationWrongCasing.publication.scheduler.State =
    activationWrongCasing.publication.scheduler.state;
  delete activationWrongCasing.publication.scheduler.state;
  assert.throws(
    () =>
      validateStage7ActivationCheckpoint(activationWrongCasing, {
        config: fullConfig,
        candidateSha,
        releaseId,
        manifestSha256,
        complete: true,
      }),
    (error) => error.code === 'E7_ACTIVATION_PUBLICATION_INVALID',
  );
  assert.throws(
    () =>
      validateStage7ActivationCheckpoint(
        {
          ...activationCheckpointFixture,
          transitions: activationCheckpointFixture.transitions.slice(0, 1),
        },
        {
          config: fullConfig,
          candidateSha,
          releaseId,
          manifestSha256,
          complete: true,
        },
      ),
    (error) => error.code === 'E7_ACTIVATION_CHECKPOINT_INVALID',
  );
  const activationFinalTransitionMismatch = structuredClone(activationCheckpointFixture);
  activationFinalTransitionMismatch.publication.webStack.stackIdSha256 = 'f'.repeat(64);
  assert.throws(
    () =>
      validateStage7ActivationCheckpoint(activationFinalTransitionMismatch, {
        config: fullConfig,
        candidateSha,
        releaseId,
        manifestSha256,
        complete: true,
      }),
    (error) => error.code === 'E7_ACTIVATION_FINAL_TRANSITION_MISMATCH',
  );
  const rollbackCheckpointFixture = {
    decision: 'INITIAL_RELEASE_DISABLED_AND_UNPUBLISHED_REQUIRES_SMOKE',
    releaseMode: 'INITIAL',
    updateReleaseSupported: false,
    publication: {
      managedByCloudFormation: true,
      apiStack: transitionState(apiStackName, 'DISABLED'),
      webStack: transitionState(webStackName, 'DISABLED'),
      scheduler: schedulerState('DISABLED'),
    },
    aliasesChanged: false,
    objectsChanged: false,
    dataFactsChanged: false,
    stacksDeleted: 0,
    secretDeleted: false,
  };
  validateStage7InitialRollbackCheckpoint(rollbackCheckpointFixture, { config: fullConfig });
  assert.throws(
    () =>
      validateStage7InitialRollbackCheckpoint(
        { ...rollbackCheckpointFixture, stacksDeleted: 1 },
        { config: fullConfig },
      ),
    (error) => error.code === 'E7_INITIAL_ROLLBACK_CHECKPOINT_INVALID',
  );
  const driftCheckpointFixture = {
    decision: 'PASS',
    releaseMode: 'VERSIONED_UPDATE',
    updateReleaseSupported: true,
    previousReleaseManifestSha256: '6'.repeat(64),
    assemblySha256: activationCheckpointFixture.assemblySha256,
    freezeManifestSha256: manifestSha256,
    publicationManagedByCloudFormation: true,
    checked: 4,
    criticalCount: 0,
    stacks: fullConfig.authorization.stacks.map((stackName, index) => ({
      detectionIdSha256: String(index + 1).repeat(64),
      driftedResourceCount: 0,
      stackIdSha256: String(index + 5).repeat(64),
      stackName,
      status: 'IN_SYNC',
    })),
  };
  validateStage7DriftCheckpoint(driftCheckpointFixture, {
    config: fullConfig,
    manifestSha256,
    assemblySha256: activationCheckpointFixture.assemblySha256,
  });
  const driftedCheckpoint = structuredClone(driftCheckpointFixture);
  driftedCheckpoint.stacks[0].status = 'DRIFTED';
  assert.throws(
    () =>
      validateStage7DriftCheckpoint(driftedCheckpoint, {
        config: fullConfig,
        manifestSha256,
        assemblySha256: activationCheckpointFixture.assemblySha256,
      }),
    (error) => error.code === 'E7_DRIFT_STACK_INVALID',
  );
  const prereleaseConfig = controlConfigFixture();
  validateStage7Config(prereleaseConfig, { now });
  const cleanupAssemblySha256 = '9'.repeat(64);
  const cleanupDestructionOrder = [...expectedStage7Stacks(prereleaseConfig.environment)].reverse();
  const cleanupCheckpointFixture = {
    decision: 'PASS',
    identity: {
      accountSha256: digest(prereleaseConfig.aws.accountId),
      accountSuffix: prereleaseConfig.aws.accountId.slice(-4),
      roleSha256: digest(prereleaseConfig.aws.roles.cleanupRoleArn),
      sessionArnSha256: 'a'.repeat(64),
    },
    assemblySha256: cleanupAssemblySha256,
    confirmationSha256: digest(
      [
        prereleaseConfig.authorization.id,
        prereleaseConfig.environment,
        prereleaseConfig.cleanup.expiresAtUtc,
        'DESTROY_EPHEMERAL_STACKS',
      ].join('\0'),
    ),
    enforceExpiry: false,
    destroyedStacks: cleanupDestructionOrder,
    destructionOrder: cleanupDestructionOrder,
    bootstrapPreserved: true,
    previousReleasePreserved: true,
    retainedDataDeleted: false,
    residual: {
      count: 0,
      preservedExternalReferences: 1,
      resourceTypeHashes: [],
    },
  };
  validateStage7PrereleaseCleanupCheckpoint(cleanupCheckpointFixture, {
    config: prereleaseConfig,
    assemblySha256: cleanupAssemblySha256,
  });
  for (const invalidCleanup of [
    { ...cleanupCheckpointFixture, previousReleasePreserved: false },
    {
      ...cleanupCheckpointFixture,
      residual: {
        ...cleanupCheckpointFixture.residual,
        count: 1,
        resourceTypeHashes: ['b'.repeat(64)],
      },
    },
    { ...cleanupCheckpointFixture, retainedDataDeleted: true },
  ]) {
    assert.throws(
      () =>
        validateStage7PrereleaseCleanupCheckpoint(invalidCleanup, {
          config: prereleaseConfig,
          assemblySha256: cleanupAssemblySha256,
        }),
      (error) => error.code === 'E7_PRERELEASE_CLEANUP_CHECKPOINT_INVALID',
    );
  }
  const releasePlanCheckpointFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_PLAN',
    status: 'READY_FOR_DIFF',
    scope: 'full',
    candidateSha,
    releaseId,
    releaseTag: 'v0.1.0-rc.1',
    cloudAssemblySha256: '1'.repeat(64),
    stacks: fullConfig.authorization.stacks.toSorted(stableCompare),
    dependencyOrder: fullConfig.authorization.stacks.toSorted(stableCompare),
    templates: 4,
    resources: 3,
    resourceCounts: {
      'AWS::DynamoDB::Table': 1,
      'AWS::Lambda::Function': 2,
    },
    statefulReplacements: 'PENDING_CDK_DIFF',
    iamReviewStatus: 'PENDING_PROTECTED_REVIEW',
    destructiveChanges: 'PENDING_CDK_DIFF',
    mutationsPlannedOnly: true,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  assert.equal(
    validateReleasePlanCheckpoint(
      releasePlanCheckpointFixture,
      'full',
      { candidateSha, releaseId, releaseTag: 'v0.1.0-rc.1' },
      fullConfig,
    ),
    releasePlanCheckpointFixture,
  );
  for (const value of [
    { ...releasePlanCheckpointFixture, unexpected: true },
    { ...releasePlanCheckpointFixture, templates: 3 },
    { ...releasePlanCheckpointFixture, resources: 4 },
    { ...releasePlanCheckpointFixture, iamReviewStatus: 'PASS' },
  ]) {
    assert.throws(
      () =>
        validateReleasePlanCheckpoint(
          value,
          'full',
          { candidateSha, releaseId, releaseTag: 'v0.1.0-rc.1' },
          fullConfig,
        ),
      (error) => error.code === 'E7_RELEASE_PLAN_CHECKPOINT_INVALID',
    );
  }
  const publicationIdentity = {
    candidateSha,
    releaseId,
    releaseTag: 'v0.1.0-rc.1',
  };
  const readmeUrlsFixture = {
    application: 'https://checkout.example.test',
    api: 'https://checkout.example.test/api',
    docs: 'https://checkout.example.test/api/docs',
    health: 'https://checkout.example.test/api/health/ready',
    repository: 'https://github.com/ivanmonsalve0404/async-checkout-demo',
  };
  const preparedReadmeFixture = releaseReadme(
    '# Checkout\n\n<!-- STAGE7_URLS_START -->placeholder<!-- STAGE7_URLS_END -->\n',
    readmeUrlsFixture,
  );
  const expectedPreparedReadmeFixture = [
    '# Checkout',
    '',
    '<!-- STAGE7_URLS_START -->',
    '',
    '## Entorno desplegado',
    '',
    '- Aplicación: https://checkout.example.test',
    '- API: https://checkout.example.test/api',
    '- OpenAPI: https://checkout.example.test/api/docs',
    '- Salud: https://checkout.example.test/api/health/ready',
    '- Repositorio: https://github.com/ivanmonsalve0404/async-checkout-demo',
    '',
    '<!-- STAGE7_URLS_END -->',
    '',
  ].join('\n');
  assert.equal(preparedReadmeFixture, expectedPreparedReadmeFixture);
  assert.equal(
    releaseReadme(preparedReadmeFixture, readmeUrlsFixture),
    expectedPreparedReadmeFixture,
  );
  assert.ok(!preparedReadmeFixture.includes(candidateSha));
  assert.throws(
    () =>
      releaseReadme(
        `${preparedReadmeFixture}<!-- STAGE7_URLS_START --><!-- STAGE7_URLS_END -->`,
        readmeUrlsFixture,
      ),
    (error) => error.code === 'E7_PUBLICATION_README_MARKERS_INVALID',
  );
  const publicationPlanFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PUBLICATION_PLAN',
    status: 'READY_FOR_EXTERNAL_PUBLICATION',
    candidateSha,
    releaseId,
    releaseTag: publicationIdentity.releaseTag,
    repository: 'ivanmonsalve0404/async-checkout-demo',
    branch: 'master',
    readmeGitBlobSha: 'b'.repeat(40),
    urls: {
      application: 'https://checkout.example.test',
      api: 'https://checkout.example.test/api',
      docs: 'https://checkout.example.test/api/docs',
      health: 'https://checkout.example.test/api/health/ready',
      repository: 'https://github.com/ivanmonsalve0404/async-checkout-demo',
    },
    files: {
      readmeSha256: '1'.repeat(64),
      releaseNotesSha256: '2'.repeat(64),
      candidateManifestSha256: '3'.repeat(64),
    },
    release: {
      title: publicationIdentity.releaseTag,
      targetSha: candidateSha,
      draft: false,
      prerelease: true,
      assetName: 'candidate-manifest.json',
      notesSha256: '2'.repeat(64),
    },
    publicationOrder: ['README_VERIFY', 'GITHUB_RELEASE'],
    retryPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
    externalWritesPlanned: 2,
    externalWritesPerformed: 0,
    containsSensitiveData: false,
  };
  validatePublicationPlan(publicationPlanFixture, publicationIdentity);
  const finalPublicationIdentity = { ...publicationIdentity, releaseTag: 'v0.1.0' };
  const finalPublicationPlanFixture = {
    ...publicationPlanFixture,
    releaseTag: finalPublicationIdentity.releaseTag,
    release: {
      ...publicationPlanFixture.release,
      title: finalPublicationIdentity.releaseTag,
      prerelease: false,
    },
  };
  validatePublicationPlan(finalPublicationPlanFixture, finalPublicationIdentity);
  assert.throws(
    () =>
      validatePublicationPlan(
        {
          ...finalPublicationPlanFixture,
          release: { ...finalPublicationPlanFixture.release, prerelease: true },
        },
        finalPublicationIdentity,
      ),
    (error) => error.code === 'E7_PUBLICATION_PLAN_INVALID',
  );
  for (const api of ['https://api.example.test/api', 'https://checkout.example.test/api/v1']) {
    assert.throws(
      () =>
        validatePublicationPlan(
          { ...publicationPlanFixture, urls: { ...publicationPlanFixture.urls, api } },
          publicationIdentity,
        ),
      (error) => error.code === 'E7_PUBLICATION_PLAN_INVALID',
    );
  }
  const publicationProbeRequests = [];
  await verifyPublishedUrls(readmeUrlsFixture, async (url) => {
    publicationProbeRequests.push(url.toString());
    return {
      status: url.pathname === '/api' ? 404 : 200,
      body: { cancel: async () => undefined },
    };
  });
  assert.deepEqual(publicationProbeRequests, [
    'https://checkout.example.test/',
    'https://checkout.example.test/api/docs',
    'https://checkout.example.test/api/health/ready',
  ]);
  assert.ok(publicationProbeRequests.every((request) => new URL(request).pathname !== '/api'));
  const unhealthyPublicationProbeRequests = [];
  await assert.rejects(
    verifyPublishedUrls(readmeUrlsFixture, async (url) => {
      unhealthyPublicationProbeRequests.push(url.toString());
      return {
        status: url.pathname === '/api/docs' ? 503 : 200,
        body: { cancel: async () => undefined },
      };
    }),
    (error) => error.code === 'E7_PUBLICATION_URL_VERIFICATION_FAILED',
  );
  assert.equal(unhealthyPublicationProbeRequests.length, 3);
  assert.ok(
    unhealthyPublicationProbeRequests.every((request) => new URL(request).pathname !== '/api'),
  );
  assert.throws(
    () =>
      validatePublicationPlan(
        { ...publicationPlanFixture, retryPolicy: 'OVERWRITE_EXISTING' },
        publicationIdentity,
      ),
    (error) => error.code === 'E7_PUBLICATION_PLAN_INVALID',
  );
  const publicationTargetProofFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PUBLICATION_TARGET_PREFLIGHT',
    status: 'PASS',
    candidateSha,
    releaseId,
    releaseTag: publicationIdentity.releaseTag,
    publicationPlanSha256: objectSha256(publicationPlanFixture),
    stage7ConfigSha256: objectSha256(fullConfig),
    ownedOriginSha256: authorizationEvidenceFixture.ownedOriginSha256,
    authorizationSha256: authorizationEvidenceFixture.authorizationSha256,
    urlsSha256: objectSha256(publicationPlanFixture.urls),
    verifiedAtUtc: '2026-08-17T12:00:00.000Z',
    externalRequests: 3,
    mutationsPerformed: 0,
    authorizationUsage: usageFixture('PUBLICATION_TARGET_PREFLIGHT', 3),
    containsSensitiveData: false,
  };
  validatePublicationTargetProof(
    publicationTargetProofFixture,
    publicationIdentity,
    publicationPlanFixture,
    fullConfig,
    authorizationEvidenceFixture,
  );
  assert.throws(
    () =>
      validatePublicationTargetProof(
        { ...publicationTargetProofFixture, externalRequests: 2 },
        publicationIdentity,
        publicationPlanFixture,
        fullConfig,
        authorizationEvidenceFixture,
      ),
    (error) => error.code === 'E7_PUBLICATION_TARGET_PROOF_INVALID',
  );
  const publicationOperationFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'GITHUB_PUBLICATION_OPERATION',
    status: 'PASS',
    candidateSha,
    releaseId,
    releaseTag: publicationIdentity.releaseTag,
    repository: publicationPlanFixture.repository,
    publicationPlanSha256: objectSha256(publicationPlanFixture),
    releaseState: 'COMPLETE',
    readmeState: 'VERIFIED_AT_CANDIDATE',
    externalRequests: 4,
    externalWritesPerformed: 0,
    containsSensitiveData: false,
  };
  validatePublicationOperation(
    publicationOperationFixture,
    publicationIdentity,
    publicationPlanFixture,
  );
  assert.throws(
    () =>
      validatePublicationOperation(
        { ...publicationOperationFixture, externalWritesPerformed: 3 },
        publicationIdentity,
        publicationPlanFixture,
      ),
    (error) => error.code === 'E7_PUBLICATION_OPERATION_INVALID',
  );
  const publicationProofFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PUBLICATION_PROOF',
    status: 'PASS',
    candidateSha,
    releaseId,
    releaseTag: publicationIdentity.releaseTag,
    repository: publicationPlanFixture.repository,
    branch: 'master',
    repositoryPublic: true,
    readmeVerifiedAtCandidate: true,
    readmeCommitSha: candidateSha,
    releasePresent: true,
    releaseVerifiedExact: true,
    releaseTargetSha: candidateSha,
    tagRefAuthoritative: true,
    tagRefAuthoritySha256: '4'.repeat(64),
    commitsEndpointVerified: true,
    commitsEndpointAuthoritySha256: '5'.repeat(64),
    releaseUrl: `https://github.com/${publicationPlanFixture.repository}/releases/tag/${publicationIdentity.releaseTag}`,
    targetHealthyBeforePublication: true,
    urlsVerified: true,
    publicationPlanSha256: objectSha256(publicationPlanFixture),
    publicationTargetProofSha256: objectSha256(publicationTargetProofFixture),
    publicationOperationSha256: objectSha256(publicationOperationFixture),
    verifiedAtUtc: '2026-08-17T12:00:00.000Z',
    githubApiRequests: 10,
    ownedTargetRequests: 3,
    externalRequests: 13,
    externalWritesPerformed: 0,
    containsSensitiveData: false,
  };
  validatePublicationProof(publicationProofFixture, publicationIdentity, publicationPlanFixture);
  assert.throws(
    () =>
      validatePublicationProof(
        { ...publicationProofFixture, releaseVerifiedExact: false },
        publicationIdentity,
        publicationPlanFixture,
      ),
    (error) => error.code === 'E7_PUBLICATION_PROOF_INVALID',
  );
  const reservationLedger = validateAuthorizationLedger({
    authorization: authorizationEvidenceFixture,
    usages: [usageFixture('LEDGER_CANARY_A'), usageFixture('LEDGER_CANARY_B')],
    identity: { candidateSha, releaseId },
    config: fullConfig,
    expectedUsageIds: ['LEDGER_CANARY_A', 'LEDGER_CANARY_B'],
    reservations: [
      usageFixture(
        'LEDGER_RESERVATION_A',
        authorizationEvidenceFixture.requestLimits[fullAuthorizationIds[0]] - 2,
      ),
    ],
    expectedReservationIds: ['LEDGER_RESERVATION_A'],
  });
  assert.equal(reservationLedger.totals[fullAuthorizationIds[0]], 2);
  assert.equal(
    reservationLedger.committedTotals[fullAuthorizationIds[0]],
    authorizationEvidenceFixture.requestLimits[fullAuthorizationIds[0]],
  );
  assert.equal(reservationLedger.remainingAfterReservations[fullAuthorizationIds[0]], 0);
  assert.throws(
    () =>
      validateAuthorizationLedger({
        authorization: authorizationEvidenceFixture,
        usages: [usageFixture('LEDGER_CANARY_A'), usageFixture('LEDGER_CANARY_B')],
        identity: { candidateSha, releaseId },
        config: fullConfig,
        expectedUsageIds: ['LEDGER_CANARY_A', 'LEDGER_CANARY_B'],
        reservations: [
          usageFixture(
            'LEDGER_RESERVATION_OVERRUN',
            authorizationEvidenceFixture.requestLimits[fullAuthorizationIds[0]] - 1,
          ),
        ],
        expectedReservationIds: ['LEDGER_RESERVATION_OVERRUN'],
      }),
    (error) => error.code === 'E7_AUTHORIZATION_LEDGER_LIMIT_EXCEEDED',
  );
  assert.throws(
    () =>
      validateAuthorizationLedger({
        authorization: authorizationEvidenceFixture,
        usages: [usageFixture('LEDGER_CANARY_A'), usageFixture('LEDGER_CANARY_B')],
        identity: { candidateSha, releaseId },
        config: fullConfig,
        expectedUsageIds: ['LEDGER_CANARY_A', 'LEDGER_CANARY_B'],
        reservations: [
          usageFixture(
            'LEDGER_RESERVATION_A',
            authorizationEvidenceFixture.requestLimits[fullAuthorizationIds[0]] - 2,
          ),
        ],
        expectedReservationIds: ['LEDGER_RESERVATION_SWAPPED'],
      }),
    (error) => error.code === 'E7_AUTHORIZATION_LEDGER_LIMIT_EXCEEDED',
  );
  assert.throws(
    () =>
      validateAuthorizationLedger({
        authorization: authorizationEvidenceFixture,
        usages: [
          usageFixture(
            'LEDGER_OVER_LIMIT',
            authorizationEvidenceFixture.requestLimits[fullAuthorizationIds[0]] + 1,
          ),
        ],
        identity: { candidateSha, releaseId },
        config: fullConfig,
        expectedUsageIds: ['LEDGER_OVER_LIMIT'],
      }),
    (error) => error.code === 'E7_AUTHORIZATION_LEDGER_LIMIT_EXCEEDED',
  );
  assert.throws(
    () =>
      validateAuthorizationLedger({
        authorization: authorizationEvidenceFixture,
        usages: [usageFixture('LEDGER_DUPLICATE'), usageFixture('LEDGER_DUPLICATE')],
        identity: { candidateSha, releaseId },
        config: fullConfig,
        expectedUsageIds: ['LEDGER_DUPLICATE', 'LEDGER_DUPLICATE'],
      }),
    (error) => error.code === 'E7_AUTHORIZATION_LEDGER_INVALID',
  );
  const wrongBundleUsage = usageFixture('LEDGER_WRONG_BUNDLE');
  wrongBundleUsage.bundleSha256 = '9'.repeat(64);
  assert.throws(
    () =>
      validateAuthorizationLedger({
        authorization: authorizationEvidenceFixture,
        usages: [wrongBundleUsage],
        identity: { candidateSha, releaseId },
        config: fullConfig,
        expectedUsageIds: ['LEDGER_WRONG_BUNDLE'],
      }),
    (error) => error.code === 'E7_AUTHORIZATION_LEDGER_INVALID',
  );
  assert.deepEqual(
    externalAuthorizationRequirements('full').map(({ id }) => id),
    ['AUTH-E7-EXT-01', 'AUTH-E7-EXT-02', 'AUTH-E7-EXT-03'],
  );
  const stage6BridgeFixture = {
    schemaId: 'async-checkout-stage6-auth02-authorization',
    schemaVersion: 1,
    stage: 6,
    commitSha: candidateSha,
    runId: 'e6-20260817t120000z-deadbeef',
    reviewerAlias: 'qa-reviewer',
    authorization: {
      ...validatedFullAuthorization.authorizations.sandboxSmoke,
      id: 'AUTH-E6-02',
    },
    target: {
      classification: 'AUTHORIZED_PROVIDER_SANDBOX',
      environment: 'sandbox',
      hostSha256: digest(SANDBOX_HOST),
      allowlistVerified: true,
      production: false,
    },
    fixture: {
      classification: 'AUTHORIZED_PROVIDER_TEST_CARD',
      cardNumberSha256: '7'.repeat(64),
      authorized: true,
      rawValueCaptured: false,
    },
    containsSensitiveData: false,
  };
  validateSandboxAuthorizationBridge({
    stage6Authorization: stage6BridgeFixture,
    externalAuthorization: validatedFullAuthorization.authorizations.sandboxSmoke,
    candidateSha,
  });
  for (const mutate of [
    (value) => {
      value.commitSha = 'b'.repeat(40);
    },
    (value) => {
      value.authorization.approvalSha256 = '8'.repeat(64);
    },
    (value) => {
      value.authorization.maxRequests += 1;
    },
    (value) => {
      value.fixture.authorized = false;
    },
  ]) {
    const value = structuredClone(stage6BridgeFixture);
    mutate(value);
    assert.throws(
      () =>
        validateSandboxAuthorizationBridge({
          stage6Authorization: value,
          externalAuthorization: validatedFullAuthorization.authorizations.sandboxSmoke,
          candidateSha,
        }),
      (error) => error.code === 'E7_SANDBOX_AUTHORIZATION_BRIDGE_INVALID',
    );
  }
  const changed = (mutate) => {
    const value = structuredClone(authorization);
    mutate(value);
    return value;
  };
  for (const value of [
    changed((entry) => {
      entry.targets.ownedOriginSha256 = '9'.repeat(64);
    }),
    changed((entry) => {
      entry.targets.apiOriginSha256 = '8'.repeat(64);
    }),
    changed((entry) => {
      entry.candidateSha = 'b'.repeat(40);
    }),
    changed((entry) => {
      entry.releaseId = 'rel-20260817-1200-bbbbbbb';
    }),
    changed((entry) => {
      entry.stage7ConfigSha256 = '8'.repeat(64);
    }),
    changed((entry) => {
      entry.authorizations.ownedTarget.expiresAtUtc = '2026-08-17T11:30:00.000Z';
    }),
    changed((entry) => {
      entry.authorizations.passiveSecurity.maxRequests = 101;
    }),
  ]) {
    assert.throws(
      () =>
        validateExternalAuthorizations({
          value,
          config,
          candidateSha,
          releaseId,
          deployedOrigin: origin,
          deployedApiOrigin: apiOrigin,
          now,
        }),
      Stage7ControlError,
    );
  }
  const previousExternalPath = process.env.STAGE7_EXTERNAL_AUTHORIZATIONS;
  delete process.env.STAGE7_EXTERNAL_AUTHORIZATIONS;
  assert.throws(
    () => externalAuthorizationFile(),
    (error) => error.code === 'E7_EXTERNAL_AUTHORIZATION_REQUIRED',
  );
  if (previousExternalPath === undefined) delete process.env.STAGE7_EXTERNAL_AUTHORIZATIONS;
  else process.env.STAGE7_EXTERNAL_AUTHORIZATIONS = previousExternalPath;

  const provider = 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com';
  const sub = 'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release';
  const trustStatement = (subject = sub, principal = provider) => ({
    Effect: 'Allow',
    Principal: { Federated: principal },
    Action: 'sts:AssumeRoleWithWebIdentity',
    Condition: {
      StringEquals: {
        'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
        'token.actions.githubusercontent.com:sub': subject,
      },
    },
  });
  validateGithubOidcTrustPolicy({
    policy: { Statement: [trustStatement()] },
    accountId: '123456789012',
    expectedSubs: [sub],
  });
  const externalSub =
    'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-prerelease-external';
  const baseSub = 'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-prerelease';
  const recoverySub =
    'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-recovery';
  const reconciliationRecoverySub =
    'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-reconciliation-recovery';
  assert.deepEqual(expectedGithubOidcSubjects(config, config.aws.roles.readRoleArn), [
    baseSub,
    externalSub,
  ]);
  assert.deepEqual(expectedGithubOidcSubjects(config, config.aws.roles.deployRoleArn), [
    baseSub,
    externalSub,
  ]);
  assert.deepEqual(expectedGithubOidcSubjects(config, config.aws.roles.rollbackRoleArn), [baseSub]);
  assert.deepEqual(expectedGithubOidcSubjects(config, config.aws.roles.cleanupRoleArn), [baseSub]);
  assert.deepEqual(expectedGithubOidcSubjects(fullConfig, fullConfig.aws.roles.readRoleArn), [
    sub,
    recoverySub,
    reconciliationRecoverySub,
  ]);
  assert.deepEqual(expectedGithubOidcSubjects(fullConfig, fullConfig.aws.roles.rollbackRoleArn), [
    sub,
    recoverySub,
  ]);
  validateGithubOidcTrustPolicy({
    policy: { Statement: [trustStatement([baseSub, externalSub])] },
    accountId: '123456789012',
    expectedSubs: [baseSub, externalSub],
  });
  validateGithubOidcTrustPolicy({
    policy: {
      Statement: [trustStatement([sub, recoverySub, reconciliationRecoverySub])],
    },
    accountId: '123456789012',
    expectedSubs: [sub, recoverySub, reconciliationRecoverySub],
  });
  assert.throws(
    () =>
      validateGithubOidcTrustPolicy({
        policy: {
          Statement: [
            trustStatement([sub, recoverySub, reconciliationRecoverySub, `${sub}-extra`]),
          ],
        },
        accountId: '123456789012',
        expectedSubs: [sub, recoverySub, reconciliationRecoverySub, `${sub}-extra`],
      }),
    (error) => error.code === 'E7_AWS_ROLE_TRUST_INVALID',
  );
  for (const policy of [
    { Statement: [trustStatement(), { ...trustStatement(), Principal: { AWS: '*' } }] },
    { Statement: [trustStatement(`${sub}:*`)] },
    {
      Statement: [
        trustStatement(
          sub,
          'arn:aws:iam::999999999999:oidc-provider/token.actions.githubusercontent.com',
        ),
      ],
    },
    { Statement: [trustStatement([sub, `${sub}-extra`])] },
  ]) {
    assert.throws(
      () =>
        validateGithubOidcTrustPolicy({
          policy,
          accountId: '123456789012',
          expectedSubs: [sub],
        }),
      (error) => error.code === 'E7_AWS_ROLE_TRUST_INVALID',
    );
  }

  const inventoryCalls = [];
  const stackInventory = readPaginatedStackInventory(config, (service, operation, arguments_) => {
    inventoryCalls.push({ service, operation, arguments_ });
    assert.equal(service, 'cloudformation');
    assert.equal(operation, 'list-stacks');
    const secondPage = arguments_.includes('--starting-token');
    return {
      StackSummaries: [
        {
          StackName: secondPage ? 'checkout-second' : 'checkout-first',
          StackId: `arn:aws:cloudformation:us-east-1:123456789012:stack/${secondPage ? 'checkout-second' : 'checkout-first'}/${secondPage ? 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' : 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'}`,
          StackStatus: secondPage ? 'DELETE_COMPLETE' : 'UPDATE_COMPLETE',
          Parameters: [{ ParameterKey: 'must-not-be-captured', ParameterValue: 'fixture' }],
          Outputs: [{ OutputKey: 'must-not-be-captured', OutputValue: 'fixture' }],
        },
      ],
      ...(secondPage ? {} : { NextToken: 'stack-page-2' }),
    };
  });
  assert.equal(stackInventory.pages, 2);
  assert.equal(stackInventory.activeStackCount, 1);
  assert.equal(stackInventory.parametersOrOutputsCaptured, false);
  assert.equal(inventoryCalls[1].arguments_.at(-2), '--starting-token');
  assert.equal(inventoryCalls[1].arguments_.at(-1), 'stack-page-2');
  assert.throws(
    () =>
      readPaginatedStackInventory(config, () => ({
        StackSummaries: [],
        NextToken: 'repeated-stack-token',
      })),
    (error) => error.code === 'E7_AWS_STACK_INVENTORY_PAGINATION_INVALID',
  );

  let initialCreationStackReads = 0;
  for (const initialScope of ['prerelease', 'baseline']) {
    const authorizedStacks = validateAuthorizedStacks(fullConfig, initialScope, () => {
      initialCreationStackReads += 1;
      throw new Error('initial creation must not describe absent stacks');
    });
    assert.equal(authorizedStacks.status, 'NOT_APPLICABLE_INITIAL_CREATION');
    assert.equal(authorizedStacks.stackCount, 0);
    assert.equal(authorizedStacks.externalRequests, 0);
  }
  assert.equal(initialCreationStackReads, 0);
  const fullStackReads = [];
  const existingAuthorizedStacks = validateAuthorizedStacks(
    fullConfig,
    'full',
    (service, operation, arguments_) => {
      assert.equal(service, 'cloudformation');
      assert.equal(operation, 'describe-stacks');
      assert.deepEqual(arguments_.slice(0, 1), ['--stack-name']);
      const stackName = arguments_[1];
      fullStackReads.push(stackName);
      return {
        Stacks: [
          {
            StackName: stackName,
            StackId: `arn:aws:cloudformation:${fullConfig.aws.region}:${fullConfig.aws.accountId}:stack/${stackName}/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa`,
            StackStatus: 'UPDATE_COMPLETE',
          },
        ],
      };
    },
  );
  assert.equal(existingAuthorizedStacks.status, 'PASS');
  assert.equal(existingAuthorizedStacks.stackCount, 4);
  assert.equal(existingAuthorizedStacks.externalRequests, 4);
  assert.deepEqual(fullStackReads, fullConfig.authorization.stacks);

  const quotaResponses = Object.fromEntries(
    Object.entries(REQUIRED_QUOTAS).map(([service, requirement]) => [
      service,
      { Quotas: [{ QuotaCode: requirement.quotaCode, Value: 100 }] },
    ]),
  );
  validateRequiredQuotaCapacity({
    quotaResponses,
    usage: { cloudformation: 1, lambda: 1, dynamodb: 1, cloudfront: 1 },
  });
  assert.throws(
    () =>
      validateRequiredQuotaCapacity({
        quotaResponses: { ...quotaResponses, dynamodb: { Quotas: [] } },
        usage: { cloudformation: 1, lambda: 1, dynamodb: 1, cloudfront: 1 },
      }),
    (error) => error.code === 'E7_AWS_REQUIRED_QUOTA_MISSING',
  );
  assert.throws(
    () =>
      validateRequiredQuotaCapacity({
        quotaResponses: {
          ...quotaResponses,
          cloudformation: {
            Quotas: [{ QuotaCode: REQUIRED_QUOTAS.cloudformation.quotaCode, Value: 4 }],
          },
        },
        usage: { cloudformation: 1, lambda: 1, dynamodb: 1, cloudfront: 1 },
      }),
    (error) => error.code === 'E7_AWS_QUOTA_CAPACITY_INSUFFICIENT',
  );

  const outputRoot = path.join(workspaceRoot, 'output');
  mkdirSync(outputRoot, { recursive: true });
  if (cleanupControlSelfTestDirectories(outputRoot).length !== 0) {
    fail('E7_SELFTEST_CONCURRENT_EXECUTION_DETECTED');
  }
  const temporary = mkdtempSync(path.join(outputRoot, '.stage7-control-selftest-'));
  relativeInside(workspaceRoot, temporary);
  const activeMarker = path.join(temporary, '.active');
  writeFileSync(activeMarker, `${process.pid}\n`, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  try {
    const stage6CloseoutFixture = (status) => {
      const pass = status === 'PASS';
      const gates = {
        'GATE-E6-01': 'PASS',
        'GATE-E6-02': pass ? 'PASS' : 'CONDITIONAL_GO',
        'GATE-E6-03': pass ? 'PASS' : 'CONDITIONAL_GO',
      };
      return {
        schemaVersion: 1,
        stage: 6,
        artifactId: 'ART-VER-16',
        runId: 'e6-20260817t120000z-0123abcd',
        dataClassification: 'C0_SANITIZED_SUMMARY',
        containsSensitiveData: false,
        requiredDocumentsValid: true,
        externalRequestsMadeByCloseout: 0,
        candidate: {
          commitSha: candidateSha,
          treeSha: 'b'.repeat(40),
          workingTree: 'CLEAN',
          changedFiles: 0,
        },
        status: pass ? 'RELEASE_CANDIDATE' : 'CONDITIONAL_GO_NOT_PUBLIC_RELEASE',
        releasePolicy: pass ? 'STAGE_7_FULL_ENABLED' : 'STAGE_7_NON_PUBLIC_PRERELEASE_ONLY',
        gates,
        artifactSummary: { total: 18, validStates: 18, failed: 0 },
        evidenceSummary: pass
          ? { total: 40, pass: 40, notRunAuth: 0, blocked: 0 }
          : { total: 40, pass: 37, notRunAuth: 3, blocked: 0 },
        artifacts: Array.from({ length: 18 }, (_, index) => ({
          id: `ART-VER-${String(index + 1).padStart(2, '0')}`,
        })),
        evidence: Array.from({ length: 40 }, (_, index) => ({
          id: `EVD-E6-${String(index + 1).padStart(2, '0')}`,
        })),
      };
    };
    const stage6Filename = path.join(temporary, 'stage6-closeout.json');
    const stage6Map = new Map([['stage6-closeout.json', stage6Filename]]);
    const stage6Identity = {
      candidateSha,
      treeSha: 'b'.repeat(40),
      releaseId,
    };
    const githubApprovalRawDiffFilename = path.join(temporary, 'safe.txt');
    const githubApprovalRunId = '123456789';
    writeFileSync(githubApprovalRawDiffFilename, 'exact reviewed infrastructure diff\n', 'utf8');
    writeFileSync(
      stage6Filename,
      JSON.stringify({
        schemaVersion: 1,
        stage: 7,
        kind: 'RELEASE_ENTRY_PREFLIGHT',
        status: 'PASS',
        scope: 'full',
        candidateSha,
        candidateTreeSha: stage6Identity.treeSha,
        releaseId,
        releaseRunId: githubApprovalRunId,
        releaseRunAttempt: 1,
        containsSensitiveData: false,
      }),
      'utf8',
    );
    const githubApprovalBindingMap = new Map([
      ['release-metadata.json', stage6Filename],
      ['infra-diff.txt', githubApprovalRawDiffFilename],
    ]);
    const githubApprovalBindingFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'GITHUB_ENVIRONMENT_APPROVAL',
      status: 'PASS',
      scope: 'full',
      repository: 'ivanmonsalve0404/async-checkout-demo',
      candidateSha,
      releaseId,
      runId: githubApprovalRunId,
      runAttempt: 1,
      environment: 'assessment-release',
      reviewerAlias: 'release-reviewer',
      reviewed: true,
      reviewState: 'approved',
      iamReviewAttested: true,
      iamReviewedDiffSha256: fileDigest(githubApprovalRawDiffFilename),
      responseSha256: 'a'.repeat(64),
      capturedAtUtc: '2026-08-17T17:00:00.000Z',
      externalRequests: 1,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    assert.deepEqual(
      validateBoundGithubEnvironmentApproval({
        document: githubApprovalBindingFixture,
        scope: 'full',
        identity: stage6Identity,
        map: githubApprovalBindingMap,
      }),
      githubApprovalBindingFixture,
    );
    for (const document of [
      { ...githubApprovalBindingFixture, runId: '987654321' },
      { ...githubApprovalBindingFixture, iamReviewedDiffSha256: 'b'.repeat(64) },
    ]) {
      assert.throws(
        () =>
          validateBoundGithubEnvironmentApproval({
            document,
            scope: 'full',
            identity: stage6Identity,
            map: githubApprovalBindingMap,
          }),
        (error) => error.code === 'E7_PROTECTED_GITHUB_APPROVAL_INVALID',
      );
    }
    const incompleteCheckpointFilename = path.join(temporary, 'partial-security.json');
    const incompleteCheckpointMap = new Map([['security.json', incompleteCheckpointFilename]]);
    const successfulFullJobs = new Map(REQUIRED_FULL_JOBS.map((id) => [id, 'success']));
    writeFileSync(
      incompleteCheckpointFilename,
      JSON.stringify({
        schemaVersion: 1,
        stage: 7,
        kind: 'RELEASE_SECURITY_CHECKPOINT',
        status: 'PASS',
        scope: 'full',
        candidateSha,
        releaseId,
        containsSensitiveData: false,
      }),
      'utf8',
    );
    assert.deepEqual(
      incompleteEvidenceRowStatus({
        scope: 'full',
        map: incompleteCheckpointMap,
        identity: stage6Identity,
        config: fullConfig,
        index: 49,
        jobResultsById: successfulFullJobs,
      }),
      { status: 'FAIL', validator: 'recordStage7ProducerArtifactFailure' },
    );
    const exactSecurityFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'REPOSITORY_AND_CANDIDATE_SECURITY',
      status: 'PASS',
      scope: 'full',
      candidateSha,
      releaseId,
      tree: 'PASS',
      history: 'PASS',
      candidateArtifact: 'PASS',
      providerProductionReferences: 0,
      secretFindings: 0,
      paymentDataFindings: 0,
      syntheticOnly: false,
      filesScanned: 1,
      bytesScanned: 1,
      externalRequests: 0,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    writeFileSync(incompleteCheckpointFilename, JSON.stringify(exactSecurityFixture), 'utf8');
    assert.deepEqual(
      incompleteEvidenceRowStatus({
        scope: 'full',
        map: incompleteCheckpointMap,
        identity: stage6Identity,
        config: fullConfig,
        index: 49,
        jobResultsById: successfulFullJobs,
      }),
      { status: 'PASS', validator: 'validateSuccessfulProducerCheckpoint' },
    );
    writeFileSync(
      incompleteCheckpointFilename,
      JSON.stringify({ ...exactSecurityFixture, history: 'NOT_RUN' }),
      'utf8',
    );
    assert.deepEqual(
      incompleteEvidenceRowStatus({
        scope: 'full',
        map: incompleteCheckpointMap,
        identity: stage6Identity,
        config: fullConfig,
        index: 49,
        jobResultsById: successfulFullJobs,
      }),
      { status: 'FAIL', validator: 'recordStage7ProducerArtifactFailure' },
    );
    assert.deepEqual(
      incompleteEvidenceRowStatus({
        scope: 'full',
        map: new Map(),
        identity: stage6Identity,
        config: fullConfig,
        index: 49,
        jobResultsById: successfulFullJobs,
      }),
      { status: 'FAIL', validator: 'recordStage7ProducerArtifactFailure' },
    );
    writeFileSync(
      incompleteCheckpointFilename,
      JSON.stringify({
        schemaVersion: 1,
        stage: 7,
        status: 'PASS',
        scope: 'full',
        candidateSha: 'f'.repeat(40),
        releaseId,
        containsSensitiveData: false,
      }),
      'utf8',
    );
    assert.deepEqual(
      incompleteEvidenceRowStatus({
        scope: 'full',
        map: incompleteCheckpointMap,
        identity: stage6Identity,
        config: fullConfig,
        index: 49,
        jobResultsById: successfulFullJobs,
      }),
      { status: 'FAIL', validator: 'recordStage7ProducerArtifactFailure' },
    );
    for (const [result, expected] of [
      ['failure', { status: 'FAIL', validator: 'recordStage7ProducerFailure' }],
      ['skipped', { status: 'NOT_RUN', validator: 'recordStage7ProducerNotRun' }],
      ['cancelled', { status: 'NOT_RUN', validator: 'recordStage7ProducerNotRun' }],
    ]) {
      assert.deepEqual(
        incompleteEvidenceRowStatus({
          scope: 'full',
          map: new Map(),
          identity: stage6Identity,
          config: fullConfig,
          index: 49,
          jobResultsById: new Map(successfulFullJobs).set('secret-scan', result),
        }),
        expected,
      );
    }
    assert.deepEqual(
      incompleteEvidenceRowStatus({
        scope: 'full',
        map: new Map(),
        identity: stage6Identity,
        config: fullConfig,
        index: 2,
        jobResultsById: new Map(successfulFullJobs).set('checksums-sbom', 'skipped'),
      }),
      { status: 'NOT_RUN', validator: 'recordStage7ProducerNotRun' },
    );
    assert.deepEqual(
      incompleteEvidenceRowStatus({
        scope: 'full',
        map: new Map(),
        identity: stage6Identity,
        config: fullConfig,
        index: 2,
        jobResultsById: new Map(successfulFullJobs)
          .set('build-or-fetch', 'skipped')
          .set('checksums-sbom', 'failure'),
      }),
      { status: 'FAIL', validator: 'recordStage7ProducerFailure' },
    );
    assert.deepEqual(
      incompleteEvidenceRowStatus({
        scope: 'full',
        map: new Map(),
        identity: stage6Identity,
        config: fullConfig,
        index: 52,
        jobResultsById: successfulFullJobs,
      }),
      { status: 'NOT_RUN', validator: 'recordStage7ProducerNotRun' },
    );
    assert.deepEqual(
      incompleteEvidenceRowStatus({
        scope: 'prerelease',
        map: new Map(),
        identity: stage6Identity,
        config,
        index: 19,
        jobResultsById: new Map(),
      }),
      { status: 'NOT_RUN', validator: 'recordStage7FormalBoundary' },
    );
    const fullStage6 = stage6CloseoutFixture('PASS');
    writeFileSync(stage6Filename, JSON.stringify(fullStage6), 'utf8');
    const fullStage6Metadata = {
      scope: 'full',
      candidateSha,
      candidateTreeSha: stage6Identity.treeSha,
      releaseId,
      releaseRunId: '123456789',
      releaseRunAttempt: 1,
      stage6RunId: fullStage6.runId,
      stage6ManifestSha256: fileDigest(stage6Filename),
      stage6Status: 'PASS',
      decision: 'READY_FOR_BUILD_FREEZE',
    };
    const releaseExecutionFixture = {
      runId: fullStage6Metadata.releaseRunId,
      runAttempt: 1,
      workflow: 'Stage 7 Release',
    };
    assert.equal(
      validateJobAuthorityReleaseOrigin(fullStage6Metadata, releaseExecutionFixture),
      fullStage6Metadata,
    );
    for (const execution of [
      { ...releaseExecutionFixture, runId: '987654321' },
      { ...releaseExecutionFixture, runAttempt: 2 },
      { ...releaseExecutionFixture, workflow: 'Stage 7 Conditional Prerelease' },
    ]) {
      assert.throws(
        () => validateJobAuthorityReleaseOrigin(fullStage6Metadata, execution),
        (error) => error.code === 'E7_JOB_AUTHORITY_RELEASE_ORIGIN_MISMATCH',
      );
    }
    assert.equal(
      validateJobAuthorityReleaseOrigin(
        { ...fullStage6Metadata, scope: 'prerelease' },
        { ...releaseExecutionFixture, workflow: 'Stage 7 Conditional Prerelease' },
      ).scope,
      'prerelease',
    );
    const fullStage6Freeze = {
      candidateSha,
      candidateTreeSha: stage6Identity.treeSha,
      sourceRunId: fullStage6.runId,
      stage6Gates: structuredClone(fullStage6.gates),
    };
    assert.deepEqual(
      validateStage6CloseoutBinding({
        map: stage6Map,
        identity: stage6Identity,
        metadata: fullStage6Metadata,
        freezeManifest: fullStage6Freeze,
        scope: 'full',
      }),
      fullStage6,
    );
    assert.throws(
      () =>
        validateStage6CloseoutBinding({
          map: stage6Map,
          identity: stage6Identity,
          metadata: { ...fullStage6Metadata, stage6ManifestSha256: '0'.repeat(64) },
          freezeManifest: fullStage6Freeze,
          scope: 'full',
        }),
      (error) => error.code === 'E7_STAGE6_CLOSEOUT_BINDING_INVALID',
    );
    assert.throws(
      () =>
        validateStage6CloseoutBinding({
          map: stage6Map,
          identity: stage6Identity,
          metadata: { ...fullStage6Metadata, releaseRunAttempt: 2 },
          freezeManifest: fullStage6Freeze,
          scope: 'full',
        }),
      (error) => error.code === 'E7_STAGE6_CLOSEOUT_BINDING_INVALID',
    );
    assert.throws(
      () =>
        validateStage6CloseoutBinding({
          map: stage6Map,
          identity: stage6Identity,
          metadata: fullStage6Metadata,
          freezeManifest: {
            ...fullStage6Freeze,
            stage6Gates: { ...fullStage6Freeze.stage6Gates, 'GATE-E6-03': 'CONDITIONAL_GO' },
          },
          scope: 'full',
        }),
      (error) => error.code === 'E7_STAGE6_CLOSEOUT_BINDING_INVALID',
    );
    const readinessFixtureRoot = temporary;
    const readinessAssemblyPath = path.join(readinessFixtureRoot, 'readiness-iac.txt');
    const readinessPaths = Object.fromEntries(
      ['web', 'api', 'worker', 'lockfile', 'openapi', 'generatedClient', 'publicConfig'].map(
        (name) => {
          const filename = path.join(readinessFixtureRoot, `readiness-${name}.txt`);
          writeFileSync(filename, `stage-7 previous readiness ${name}\n`, 'utf8');
          return [name, filename];
        },
      ),
    );
    writeFileSync(readinessAssemblyPath, '{"version":"fixture"}\n', 'utf8');
    const readinessFreeze = createFreezeManifest({
      config: fullConfig,
      e6Manifest: fullStage6,
      candidate: {
        commitSha: candidateSha,
        treeSha: stage6Identity.treeSha,
        workingTree: 'CLEAN',
        changedFiles: 0,
      },
      releaseTag: 'v0.1.0-rc.1',
      builtAt: '2026-08-17T12:00:00.000Z',
      sourceArtifactId: '123456789',
      sourceArtifactSha256: '1'.repeat(64),
      preFreezeEvidenceSha256: '2'.repeat(64),
      awsCliVersion: '2.27.49',
      paths: { ...readinessPaths, iac: readinessAssemblyPath },
      rootDirectory: workspaceRoot,
    });
    const exactFullIdentity = {
      ...stage6Identity,
      releaseTag: readinessFreeze.releaseTag,
      workingTree: 'CLEAN',
      changedFiles: 0,
    };
    const infraAssemblySha256 = readinessFreeze.artifacts.find(({ name }) => name === 'iac').sha256;
    const infraReleasePlanFixture = {
      ...releasePlanCheckpointFixture,
      cloudAssemblySha256: infraAssemblySha256,
    };
    const infraDiffFixture = {
      cloudAssemblySha256: infraAssemblySha256,
      checkpoints: {
        diff: {
          assemblySha256: infraAssemblySha256,
          freezeManifestSha256: readinessFreeze.manifestSha256,
        },
      },
    };
    const infraSynthFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'CLOUD_ASSEMBLY_SECURITY',
      status: 'PASS',
      scope: 'full',
      candidateSha,
      releaseId,
      assemblySha256: infraAssemblySha256,
      freezeManifestSha256: readinessFreeze.manifestSha256,
      frozenVerificationSha256: '4'.repeat(64),
      templates: infraReleasePlanFixture.templates,
      resources: infraReleasePlanFixture.resources,
      resourceCounts: structuredClone(infraReleasePlanFixture.resourceCounts),
      secretFindings: 0,
      productionProviderReferences: 0,
      publicBucketRisks: 0,
      wildcardCorsRisks: 0,
      iamWildcardActionRisks: 0,
      statefulProtectionRisks: 0,
      filesScanned: 4,
      bytesScanned: 1024,
      externalRequests: 0,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    assert.equal(
      validateInfraSynthCheckpoint({
        document: infraSynthFixture,
        scope: 'full',
        identity: exactFullIdentity,
        freezeManifest: readinessFreeze,
        releasePlan: infraReleasePlanFixture,
        diff: infraDiffFixture,
      }),
      infraSynthFixture,
    );
    for (const input of [
      { document: {}, releasePlan: infraReleasePlanFixture, diff: infraDiffFixture },
      {
        document: { ...infraSynthFixture, unexpected: true },
        releasePlan: infraReleasePlanFixture,
        diff: infraDiffFixture,
      },
      {
        document: { ...infraSynthFixture, assemblySha256: '0'.repeat(64) },
        releasePlan: infraReleasePlanFixture,
        diff: infraDiffFixture,
      },
      {
        document: infraSynthFixture,
        releasePlan: { ...infraReleasePlanFixture, cloudAssemblySha256: '0'.repeat(64) },
        diff: infraDiffFixture,
      },
      {
        document: infraSynthFixture,
        releasePlan: infraReleasePlanFixture,
        diff: { ...infraDiffFixture, cloudAssemblySha256: '0'.repeat(64) },
      },
      {
        document: infraSynthFixture,
        releasePlan: infraReleasePlanFixture,
        diff: infraDiffFixture,
        freezeManifest: { ...readinessFreeze, manifestSha256: '0'.repeat(64) },
      },
    ]) {
      assert.throws(
        () =>
          validateInfraSynthCheckpoint({
            document: input.document,
            scope: 'full',
            identity: exactFullIdentity,
            freezeManifest: input.freezeManifest ?? readinessFreeze,
            releasePlan: input.releasePlan,
            diff: input.diff,
          }),
        (error) => error.code === 'E7_INFRA_SYNTH_CHECKPOINT_INVALID',
      );
    }
    const candidateVerificationFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'CANDIDATE_VERIFICATION',
      status: 'PASS',
      scope: 'full',
      candidateSha,
      candidateTreeSha: stage6Identity.treeSha,
      immutableIdentifier: readinessFreeze.releaseTag,
      releaseId,
      stage6RunId: fullStage6Metadata.stage6RunId,
      stage6ManifestSha256: fullStage6Metadata.stage6ManifestSha256,
      stage6Status: 'PASS',
      workingTree: 'CLEAN',
      changedFiles: 0,
      externalRequests: 0,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    assert.equal(
      validateCandidateVerificationCheckpoint({
        document: candidateVerificationFixture,
        scope: 'full',
        identity: exactFullIdentity,
        metadata: fullStage6Metadata,
        freezeManifest: readinessFreeze,
      }),
      candidateVerificationFixture,
    );
    for (const document of [
      { ...candidateVerificationFixture, unexpected: true },
      { ...candidateVerificationFixture, stage6ManifestSha256: '0'.repeat(64) },
    ]) {
      assert.throws(
        () =>
          validateCandidateVerificationCheckpoint({
            document,
            scope: 'full',
            identity: exactFullIdentity,
            metadata: fullStage6Metadata,
            freezeManifest: readinessFreeze,
          }),
        (error) => error.code === 'E7_CANDIDATE_VERIFICATION_CHECKPOINT_INVALID',
      );
    }
    const checksumsFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'CHECKSUMS_INVENTORY_PROVENANCE',
      status: 'PASS',
      scope: 'full',
      candidateSha,
      releaseId,
      manifestSha256: readinessFreeze.manifestSha256,
      sourceArtifactId: readinessFreeze.sourceArtifactId,
      sourceArtifactSha256: readinessFreeze.sourceArtifactSha256,
      artifactDigests: Object.fromEntries(
        readinessFreeze.artifacts.map(({ name, sha256 }) => [name, sha256]),
      ),
      inventoryFormat: 'SHA256_INVENTORY_V1',
      inventory: [{ path: 'fixture.txt', bytes: 1, sha256: '3'.repeat(64) }],
      provenance: {
        lockfileSha256: readinessFreeze.lockfileSha256,
        openApiSha256: readinessFreeze.openApiSha256,
        generatedClientSha256: readinessFreeze.generatedClientSha256,
      },
      findings: 0,
      externalRequests: 0,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    assert.equal(
      validateChecksumsInventoryCheckpoint({
        document: checksumsFixture,
        scope: 'full',
        identity: exactFullIdentity,
        freezeManifest: readinessFreeze,
      }),
      checksumsFixture,
    );
    for (const document of [
      { ...checksumsFixture, unexpected: true },
      { ...checksumsFixture, manifestSha256: '0'.repeat(64) },
    ]) {
      assert.throws(
        () =>
          validateChecksumsInventoryCheckpoint({
            document,
            scope: 'full',
            identity: exactFullIdentity,
            freezeManifest: readinessFreeze,
          }),
        (error) => error.code === 'E7_CHECKSUMS_INVENTORY_CHECKPOINT_INVALID',
      );
    }
    const preFreezeRawSha256 = fileDigest(incompleteCheckpointFilename);
    assert.equal(
      validatePreFreezeSourceBinding({
        sourceFilename: incompleteCheckpointFilename,
        freezeManifest: { preFreezeEvidenceSha256: preFreezeRawSha256 },
      }),
      preFreezeRawSha256,
    );
    assert.throws(
      () =>
        validatePreFreezeSourceBinding({
          sourceFilename: incompleteCheckpointFilename,
          freezeManifest: { preFreezeEvidenceSha256: '0'.repeat(64) },
        }),
      (error) => error.code === 'E7_PRE_FREEZE_SOURCE_BINDING_INVALID',
    );
    assert.throws(
      () =>
        validatePreFreezeCheckpoint({
          document: {},
          sourceFilename: incompleteCheckpointFilename,
          identity: exactFullIdentity,
          config: fullConfig,
          freezeManifest: {
            ...readinessFreeze,
            preFreezeEvidenceSha256: preFreezeRawSha256,
          },
        }),
      (error) => error.code === 'E7_PRE_FREEZE_CHECKPOINT_INVALID',
    );
    const previousManifest = createStage7PreviousReleaseManifest({
      schemaVersion: 1,
      stage: 7,
      kind: 'PREVIOUS_APPROVED_RELEASE',
      status: 'APPROVED_IMMUTABLE',
      capturedAtUtc: '2026-08-17T11:00:00.000Z',
      approvedAtUtc: '2026-08-17T10:30:00.000Z',
      environment: fullConfig.environment,
      region: fullConfig.aws.region,
      previous: {
        candidateSha: 'c'.repeat(40),
        candidateTreeSha: 'd'.repeat(40),
        releaseId: 'rel-20260816-1200-ccccccc',
        releaseTag: 'v0.0.9',
        configSha256: '3'.repeat(64),
        freezeManifestSha256: '4'.repeat(64),
        assemblySha256: '5'.repeat(64),
      },
      target: {
        candidateSha: readinessFreeze.candidateSha,
        candidateTreeSha: readinessFreeze.candidateTreeSha,
        releaseId: readinessFreeze.releaseId,
        releaseTag: readinessFreeze.releaseTag,
        configSha256: objectSha256(fullConfig),
        freezeManifestSha256: readinessFreeze.manifestSha256,
        assemblySha256: readinessFreeze.artifacts.find(({ name }) => name === 'iac').sha256,
      },
      resources: {
        api: {
          functionName: 'checkout-assessment-release-api',
          aliasName: 'live',
          version: '7',
          codeSha256: '6'.repeat(64),
        },
        worker: {
          functionName: 'checkout-assessment-release-worker',
          aliasName: 'live',
          version: '9',
          codeSha256: '7'.repeat(64),
        },
        web: {
          bucketName: 'checkout-assessment-release-web',
          distributionId: 'E123456789ABC',
          objects: [
            {
              key: 'index.html',
              versionId: 'index-version-1',
              etagSha256: '8'.repeat(64),
              contentSha256: '9'.repeat(64),
              bytes: 1024,
            },
            {
              key: 'public-config.json',
              versionId: 'config-version-1',
              etagSha256: 'a'.repeat(64),
              contentSha256: 'b'.repeat(64),
              bytes: 256,
            },
          ],
          mutableInvalidationPaths: ['/index.html', '/public-config.json'],
        },
      },
      compatibility: {
        status: 'PASS',
        schemaStrategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
        dataRollback: 'FORBIDDEN_FORWARD_ONLY',
        apiContractEvidenceSha256: 'c'.repeat(64),
        pendingReconciliationEvidenceSha256: 'd'.repeat(64),
        smokeEvidenceSha256: 'e'.repeat(64),
        smokeVerifiedAtUtc: '2026-08-17T10:45:00.000Z',
        providerEgressCapability: STAGE7_PROVIDER_EGRESS_CAPABILITY,
      },
      handoff: {
        sourceKind: 'BASELINE_BOOTSTRAP',
        sourceBundleSha256: 'f'.repeat(64),
        sourceArtifactProvenanceSha256: '1'.repeat(64),
        targetCompatibilityEvidenceSha256: '2'.repeat(64),
        finalDisableEvidenceSha256: '3'.repeat(64),
        predecessorManifestSha256: null,
      },
      approval: {
        status: 'APPROVED',
        reviewerAlias: 'baseline-reviewer',
        approvalEvidenceSha256: '4'.repeat(64),
        releaseEvidenceSha256: '5'.repeat(64),
      },
      containsSensitiveData: false,
    });
    const targetAssemblySha256 = hashArtifactPath(readinessAssemblyPath, {
      rootDirectory: workspaceRoot,
    }).sha256;
    const previousReadinessFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'PREVIOUS_RELEASE_LOCAL_PREFLIGHT',
      decision: 'READY_FOR_VERSIONED_UPDATE',
      previousReleaseManifestSha256: previousManifest.manifestSha256,
      previousReleaseId: previousManifest.previous.releaseId,
      targetReleaseId: previousManifest.target.releaseId,
      previousAssemblySha256: previousManifest.previous.assemblySha256,
      targetAssemblySha256: previousManifest.target.assemblySha256,
      mutableObjectKeys: ['index.html', 'public-config.json'],
      apiAliasSha256: digest('checkout-assessment-release-api:live'),
      workerAliasSha256: digest('checkout-assessment-release-worker:live'),
      versionedRollbackExecutionEnabled: true,
      blockingIssue: null,
      externalRequests: 0,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    assert.equal(
      validatePreviousReleaseReadiness({
        value: previousReadinessFixture,
        previousManifest,
        config: fullConfig,
        freezeManifest: readinessFreeze,
        targetAssemblySha256,
      }),
      previousReadinessFixture,
    );
    for (const value of [
      { ...previousReadinessFixture, unexpected: true },
      { ...previousReadinessFixture, previousReleaseManifestSha256: '0'.repeat(64) },
      { ...previousReadinessFixture, mutableObjectKeys: ['public-config.json', 'index.html'] },
      { ...previousReadinessFixture, apiAliasSha256: '0'.repeat(64) },
      { ...previousReadinessFixture, versionedRollbackExecutionEnabled: false },
    ]) {
      assert.throws(
        () =>
          validatePreviousReleaseReadiness({
            value,
            previousManifest,
            config: fullConfig,
            freezeManifest: readinessFreeze,
            targetAssemblySha256,
          }),
        (error) => error.code === 'E7_PREVIOUS_RELEASE_READINESS_INVALID',
      );
    }
    assert.throws(
      () =>
        validatePreviousReleaseReadiness({
          value: previousReadinessFixture,
          previousManifest,
          config: fullConfig,
          freezeManifest: readinessFreeze,
          targetAssemblySha256: '0'.repeat(64),
        }),
      (error) => error.code === 'E7_PREVIOUS_RELEASE_READINESS_INVALID',
    );
    const invalidPreviousVersion = structuredClone(previousManifest);
    invalidPreviousVersion.resources.web.objects[0].versionId = '';
    const invalidPreviousVersionBody = { ...invalidPreviousVersion };
    delete invalidPreviousVersionBody.manifestSha256;
    invalidPreviousVersion.manifestSha256 = objectSha256(invalidPreviousVersionBody);
    assert.throws(
      () =>
        validatePreviousReleaseReadiness({
          value: previousReadinessFixture,
          previousManifest: invalidPreviousVersion,
          config: fullConfig,
          freezeManifest: readinessFreeze,
          targetAssemblySha256,
        }),
      (error) => error.code === 'E7_PREVIOUS_RELEASE_READINESS_TARGET_INVALID',
    );
    const recoveryCandidate = createStage7CandidateRollbackRecord({
      previousManifest,
      createdAtUtc: '2026-08-17T17:00:00.000Z',
      approvalSha256: '6'.repeat(64),
      planSha256: '7'.repeat(64),
      deploymentEvidenceSha256: '8'.repeat(64),
      resources: {
        api: {
          ...previousManifest.resources.api,
          version: '8',
          codeSha256: '9'.repeat(64),
        },
        worker: {
          ...previousManifest.resources.worker,
          version: '10',
          codeSha256: 'a'.repeat(64),
        },
        web: {
          ...previousManifest.resources.web,
          objects: previousManifest.resources.web.objects.map((entry, index) => ({
            ...entry,
            versionId: `candidate-version-${index + 1}`,
            etagSha256: `${index + 1}`.repeat(64),
            contentSha256: `${index + 3}`.repeat(64),
          })),
        },
      },
    });
    const recoveryObservedState = {
      api: {
        functionName: recoveryCandidate.resources.api.functionName,
        aliasName: recoveryCandidate.resources.api.aliasName,
        version: recoveryCandidate.resources.api.version,
      },
      worker: {
        functionName: recoveryCandidate.resources.worker.functionName,
        aliasName: recoveryCandidate.resources.worker.aliasName,
        version: recoveryCandidate.resources.worker.version,
      },
      web: {
        bucketName: recoveryCandidate.resources.web.bucketName,
        distributionId: recoveryCandidate.resources.web.distributionId,
        objects: recoveryCandidate.resources.web.objects.map(
          ({ key, versionId, contentSha256 }) => ({ key, versionId, contentSha256 }),
        ),
      },
      pending: {
        observedAtUtc: '2026-08-17T17:01:00.000Z',
        trackedCount: 1,
        oldestAgeSeconds: 30,
        snapshotSha256: 'b'.repeat(64),
      },
      dataFactsSha256: 'c'.repeat(64),
    };
    const recoveryVerificationPlan = createStage7VersionedRollbackPlan({
      direction: 'REPROMOTE_CANDIDATE',
      purpose: 'EMERGENCY_RECOVERY',
      previousManifest,
      candidateRecord: recoveryCandidate,
      currentState: recoveryObservedState,
    });
    const recoveryBody = {
      schemaVersion: 1,
      stage: 7,
      kind: 'VERSIONED_ROLLBACK_EMERGENCY_RECOVERY',
      status: 'PASS',
      decision: 'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED',
      previousReleaseManifestSha256: previousManifest.manifestSha256,
      candidateRecordSha256: recoveryCandidate.recordSha256,
      publicationState: { api: 'ENABLED', web: 'ENABLED' },
      observedState: recoveryObservedState,
      verificationPlan: recoveryVerificationPlan,
      mutationsPerformed: 0,
      dataRollbackPerformed: false,
      stacksDeleted: 0,
      completedAtUtc: '2026-08-17T17:02:00.000Z',
      containsSensitiveData: false,
    };
    const recoveryFixture = {
      ...recoveryBody,
      recoverySha256: objectSha256(recoveryBody),
    };
    assert.equal(
      validateStage7CandidateRollbackRecord(recoveryCandidate, {
        previousManifest,
        approvalSha256: '6'.repeat(64),
        planSha256: '7'.repeat(64),
        deploymentEvidenceSha256: '8'.repeat(64),
      }),
      recoveryCandidate,
    );
    for (const bindings of [
      { approvalSha256: '0'.repeat(64), planSha256: '7'.repeat(64) },
      { approvalSha256: '6'.repeat(64), planSha256: '0'.repeat(64) },
      { approvalSha256: '6'.repeat(64), planSha256: '7'.repeat(64), deployment: '0' },
    ]) {
      assert.throws(
        () =>
          validateStage7CandidateRollbackRecord(recoveryCandidate, {
            previousManifest,
            approvalSha256: bindings.approvalSha256,
            planSha256: bindings.planSha256,
            deploymentEvidenceSha256: (bindings.deployment ?? '8').repeat(64),
          }),
        Stage7Error,
      );
    }
    assert.equal(
      validateCandidateActiveNoActionRecovery({
        value: recoveryFixture,
        previousManifest,
        candidateRecord: recoveryCandidate,
      }),
      recoveryFixture,
    );
    const resignRecovery = (mutate) => {
      const value = structuredClone(recoveryFixture);
      mutate(value);
      delete value.recoverySha256;
      return { ...value, recoverySha256: objectSha256(value) };
    };
    for (const value of [
      resignRecovery((entry) => {
        entry.unexpected = true;
      }),
      resignRecovery((entry) => {
        entry.publicationState.api = 'DISABLED';
      }),
      resignRecovery((entry) => {
        entry.observedState.web.objects[0].versionId = 'wrong-version';
      }),
      resignRecovery((entry) => {
        entry.verificationPlan.decision = 'APPLY';
      }),
      resignRecovery((entry) => {
        entry.mutationsPerformed = 1;
      }),
      resignRecovery((entry) => {
        entry.completedAtUtc = '2026-08-17T17:02:00Z';
      }),
    ]) {
      assert.throws(
        () =>
          validateCandidateActiveNoActionRecovery({
            value,
            previousManifest,
            candidateRecord: recoveryCandidate,
          }),
        (error) => error.code === 'E7_EMERGENCY_RECOVERY_NO_ACTION_INVALID',
      );
    }
    const noActionSourceBindings = EMERGENCY_NO_ACTION_SOURCE_BINDING_SPECS.map(
      ([label, basename], index) => ({
        label,
        basename,
        rawSha256: `${(index % 9) + 1}`.repeat(64),
        canonicalSha256: `${((index + 3) % 9) + 1}`.repeat(64),
        bytes: index + 100,
      }),
    );
    const noActionCallerProjection = {
      accountSha256: '1'.repeat(64),
      accountSuffix: '9012',
      roleSha256: '2'.repeat(64),
      sessionArnSha256: '3'.repeat(64),
    };
    const noActionCallerRaw = JSON.stringify(noActionCallerProjection);
    const noActionCallerBinding = {
      projection: noActionCallerProjection,
      rawSha256: digest(noActionCallerRaw),
      canonicalSha256: objectSha256(noActionCallerProjection),
      bytes: Buffer.byteLength(noActionCallerRaw),
    };
    const noActionPublication = (suffix) => ({
      state: 'ENABLED',
      stackName: `checkout-assessment-release-${suffix}`,
      stackStatus: 'UPDATE_COMPLETE',
      createdAtUtc: '2026-08-17T16:00:00.000Z',
      updatedAtUtc: '2026-08-17T17:00:00.000Z',
      terminationProtection: true,
      candidateSha: previousManifest.target.candidateSha,
      releaseId: previousManifest.target.releaseId,
      publicationOutput: 'ENABLED',
    });
    const noActionState = {
      publication: {
        api: noActionPublication('api'),
        web: noActionPublication('web'),
      },
      aliases: {
        api: {
          functionName: recoveryCandidate.resources.api.functionName,
          aliasName: recoveryCandidate.resources.api.aliasName,
          version: recoveryCandidate.resources.api.version,
          revisionId: 'api-revision',
        },
        worker: {
          functionName: recoveryCandidate.resources.worker.functionName,
          aliasName: recoveryCandidate.resources.worker.aliasName,
          version: recoveryCandidate.resources.worker.version,
          revisionId: 'worker-revision',
        },
      },
      web: {
        bucketName: recoveryCandidate.resources.web.bucketName,
        distributionId: recoveryCandidate.resources.web.distributionId,
        objects: recoveryCandidate.resources.web.objects.map(
          ({ key, versionId, contentSha256, bytes }) => ({
            key,
            versionId,
            contentSha256,
            bytes,
          }),
        ),
      },
    };
    const noActionSnapshot = (sequence) => ({
      sequence,
      state: structuredClone(noActionState),
      stateSha256: objectSha256(noActionState),
    });
    const noActionOutcomeBody = {
      schemaVersion: 1,
      stage: 7,
      kind: 'VERSIONED_ROLLBACK_EMERGENCY_RECOVERY_NO_ACTION_OUTCOME',
      status: 'PASS',
      decision: 'NO_ACTION_CANDIDATE_ACTIVE_VERIFIED',
      failureCode: null,
      failureStage: null,
      previousReleaseManifestSha256: previousManifest.manifestSha256,
      candidateRecordSha256: recoveryCandidate.recordSha256,
      assemblySha256: previousManifest.target.assemblySha256,
      sourceBindings: noActionSourceBindings,
      sourceBindingsSha256: objectSha256(noActionSourceBindings),
      callerBinding: noActionCallerBinding,
      observations: {
        before: noActionSnapshot('BEFORE'),
        after: noActionSnapshot('AFTER'),
      },
      recoverySha256: recoveryFixture.recoverySha256,
      mutationsPerformed: 0,
      dataRollbackPerformed: false,
      stacksDeleted: 0,
      completedAtUtc: recoveryFixture.completedAtUtc,
      containsSensitiveData: false,
    };
    const noActionOutcome = {
      ...noActionOutcomeBody,
      outcomeSha256: objectSha256(noActionOutcomeBody),
    };
    const noActionOutcomeArguments = {
      previousManifest,
      candidateRecord: recoveryCandidate,
      emergencyRecovery: recoveryFixture,
      identity: {
        candidateSha: previousManifest.target.candidateSha,
        releaseId: previousManifest.target.releaseId,
      },
      expectedSourceBindings: noActionSourceBindings,
      expectedCallerBinding: noActionCallerBinding,
      expectedStackNames: {
        api: 'checkout-assessment-release-api',
        web: 'checkout-assessment-release-web',
      },
    };
    assert.equal(
      validateCandidateActiveNoActionOutcomeCheckpoint({
        value: noActionOutcome,
        ...noActionOutcomeArguments,
      }),
      noActionOutcome,
    );
    const resignNoActionOutcome = (mutate) => {
      const value = structuredClone(noActionOutcome);
      mutate(value);
      delete value.outcomeSha256;
      return { ...value, outcomeSha256: objectSha256(value) };
    };
    for (const value of [
      resignNoActionOutcome((entry) => {
        entry.unexpected = true;
      }),
      resignNoActionOutcome((entry) => {
        entry.status = 'FAIL';
        entry.decision = 'NO_ACTION_VERIFICATION_FAILED';
        entry.failureCode = 'E7_TEST_FAILURE';
        entry.failureStage = 'AFTER_OBSERVATION';
        entry.recoverySha256 = null;
      }),
      resignNoActionOutcome((entry) => {
        entry.sourceBindings[0].rawSha256 = '0'.repeat(64);
        entry.sourceBindingsSha256 = objectSha256(entry.sourceBindings);
      }),
      resignNoActionOutcome((entry) => {
        entry.callerBinding.projection.roleSha256 = '0'.repeat(64);
        const raw = JSON.stringify(entry.callerBinding.projection);
        entry.callerBinding.rawSha256 = digest(raw);
        entry.callerBinding.canonicalSha256 = objectSha256(entry.callerBinding.projection);
        entry.callerBinding.bytes = Buffer.byteLength(raw);
      }),
      resignNoActionOutcome((entry) => {
        entry.observations.after.state.aliases.api.version = '999';
        entry.observations.after.stateSha256 = objectSha256(entry.observations.after.state);
      }),
      resignNoActionOutcome((entry) => {
        entry.recoverySha256 = '0'.repeat(64);
      }),
      resignNoActionOutcome((entry) => {
        entry.completedAtUtc = '2026-08-17T17:02:01.000Z';
      }),
    ]) {
      assert.throws(
        () =>
          validateCandidateActiveNoActionOutcomeCheckpoint({
            value,
            ...noActionOutcomeArguments,
          }),
        Stage7ControlError,
      );
    }
    const prereleaseStage6 = stage6CloseoutFixture('CONDITIONAL_GO');
    writeFileSync(stage6Filename, JSON.stringify(prereleaseStage6), 'utf8');
    assert.deepEqual(
      validateStage6CloseoutBinding({
        map: stage6Map,
        identity: stage6Identity,
        metadata: {
          ...fullStage6Metadata,
          scope: 'prerelease',
          stage6ManifestSha256: fileDigest(stage6Filename),
          stage6Status: 'CONDITIONAL_GO',
          decision: 'READY_FOR_AUTHORIZED_EPHEMERAL_PREFLIGHT',
        },
        freezeManifest: {
          ...fullStage6Freeze,
          stage6Gates: structuredClone(prereleaseStage6.gates),
        },
        scope: 'prerelease',
      }),
      prereleaseStage6,
    );
    const safe = path.join(temporary, 'safe.txt');
    writeFileSync(safe, 'sanitized self-test\n', 'utf8');
    assert.deepEqual(scanFileSet([safe]), { filesScanned: 1, bytesScanned: 20 });
    const unsafe = path.join(temporary, 'unsafe.bin');
    const begin = [['-----BEGIN', 'PRIVATE'].join(' '), 'KEY-----'].join(' ');
    const end = [['-----END', 'PRIVATE'].join(' '), 'KEY-----'].join(' ');
    writeFileSync(unsafe, [begin, 'x', end].join('\n'), 'utf8');
    assert.throws(
      () => scanFileSet([unsafe]),
      (error) => error.code === 'E7_SCAN_PRIVATE_KEY_FOUND',
    );
    const assetManifestFilename = path.join(temporary, 'assets.json');
    const fileDestination = {
      bucketName: 'cdk-hnb659fds-assets-${AWS::AccountId}-us-east-1',
      objectKey: 'fixture.zip',
      region: 'us-east-1',
      assumeRoleArn:
        'arn:${AWS::Partition}:iam::${AWS::AccountId}:role/cdk-hnb659fds-file-publishing-role-${AWS::AccountId}-us-east-1',
    };
    const assetManifestFixture = (dockerImages = {}) => ({
      version: '54.0.0',
      files: {
        fixture: {
          source: { path: 'asset.fixture', packaging: 'zip' },
          destinations: { destination: fileDestination },
        },
      },
      dockerImages,
    });
    writeFileSync(assetManifestFilename, JSON.stringify(assetManifestFixture()), 'utf8');
    const assemblyManifestFixture = {
      artifacts: {
        assets: { type: 'cdk:asset-manifest', properties: { file: 'assets.json' } },
      },
    };
    const assetInventory = inspectBootstrapAssetInventory({
      root: temporary,
      manifest: assemblyManifestFixture,
      assemblySha256: 'a'.repeat(64),
    });
    assert.equal(assetInventory.fileAssetCount, 1);
    assert.equal(assetInventory.dockerImageAssetCount, 0);
    writeFileSync(
      assetManifestFilename,
      JSON.stringify(assetManifestFixture({ image: { source: {}, destinations: {} } })),
      'utf8',
    );
    assert.throws(
      () =>
        inspectBootstrapAssetInventory({
          root: temporary,
          manifest: assemblyManifestFixture,
          assemblySha256: 'a'.repeat(64),
        }),
      (error) => error.code === 'E7_IAM_BOOTSTRAP_ASSET_INVENTORY_INVALID',
    );
    assert.throws(
      () =>
        inspectBootstrapAssetInventory({
          root: temporary,
          manifest: {
            artifacts: {
              assets: { type: 'cdk:asset-manifest', properties: { file: '../safe.txt' } },
            },
          },
          assemblySha256: 'a'.repeat(64),
        }),
      (error) => error.code === 'E7_CDK_ASSET_MANIFEST_PATH_INVALID',
    );
  } finally {
    relativeInside(outputRoot, temporary);
    removeControlSelfTestDirectory(outputRoot, temporary);
    try {
      lstatSync(temporary);
      fail('E7_SELFTEST_OWN_RESIDUE_DETECTED');
    } catch (error) {
      if (error instanceof Stage7ControlError) fail(error.code);
      if (error?.code !== 'ENOENT') fail('E7_SELFTEST_OWN_RESIDUE_UNVERIFIABLE');
    }
  }
  if (cleanupControlSelfTestDirectories(outputRoot).length !== 0) {
    fail('E7_SELFTEST_RESIDUE_DETECTED');
  }
  process.stdout.write('stage-7 release control self-test: PASS (0 external calls)\n');
};

const main = async () => {
  const command = process.argv[2];
  if (command === 'self-test') {
    if (process.argv.length !== 3) fail('E7_CONTROL_ARGUMENT_SET_INVALID');
    await selfTestStage7Control();
    return;
  }
  assertNode24();
  const flags = parseFlags(process.argv.slice(3));
  if (command === 'preflight') await dispatchPreflight(flags);
  else if (command === 'verify-journal-authority') verifyLiveJournalRoleAuthority(flags);
  else if (command === 'verify-successor-fence') verifyReleaseSuccessorFenceCheckpoint(flags);
  else if (command === 'verify-candidate') await dispatchVerifyCandidate(flags);
  else if (command === 'manifest') await dispatchManifest(flags);
  else if (command === 'scan') await dispatchScan(flags);
  else if (command === 'plan') await dispatchPlan(flags);
  else if (command === 'smoke') await dispatchSmoke(flags);
  else if (command === 'sandbox-smoke') await dispatchSandboxSmoke(flags);
  else if (command === 'quality') await dispatchQuality(flags);
  else if (command === 'prepare-readme') await dispatchPrepareReadme(flags);
  else if (command === 'publish') await dispatchPublish(flags);
  else if (command === 'verify') await dispatchVerify(flags);
  else fail('E7_CONTROL_COMMAND_INVALID');
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    const code =
      error instanceof Stage7ControlError ||
      error instanceof Stage7Error ||
      error instanceof Stage7SmokeError ||
      error instanceof Stage7QualityError ||
      error instanceof IamEffectivePermissionsError ||
      error instanceof Stage7ReleaseReconciliationError ||
      error instanceof Stage7ReleaseReconciliationExecutorError
        ? error.code
        : 'E7_CONTROL_UNEXPECTED_FAILURE';
    process.stderr.write(`stage-7 release control: ${code}\n`);
    process.exitCode = 1;
  });
}
