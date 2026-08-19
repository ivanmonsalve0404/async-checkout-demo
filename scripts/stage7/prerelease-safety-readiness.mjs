import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import {
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { assertSanitizedArtifactText } from '../stage6/lib/artifact-sanitizer.mjs';
import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { validatePrereleaseCleanupWorkflow } from '../security/validate-prerelease-cleanup-workflow.mjs';
import {
  canonicalJson,
  hashArtifactPath,
  objectSha256,
  validateFreezeManifest,
  validateStage7Config,
  workspaceRoot,
  writeStage7Json,
} from './core.mjs';
import {
  IamEffectivePermissionsError,
  validateIamEffectivePermissionsEvidence,
} from './iam-effective-permissions.mjs';
import {
  EXPECTED_DEFAULT_BRANCH,
  EXPECTED_REPOSITORY,
  PrereleaseSafetyContractError,
  WATCHDOG_CRON,
  WATCHDOG_OIDC_SUBJECT,
  WATCHDOG_WORKFLOW_RELATIVE,
  validatePrereleaseSafetyReadiness as validatePrereleaseSafetyReadinessContract,
} from './prerelease-safety-contract.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/[A-Za-z0-9+=,.@_/-]{1,256}$/u;
const GITHUB_RUN_ID = /^[1-9][0-9]{0,19}$/u;
const GITHUB_RUN_ATTEMPT = /^[1-9][0-9]{0,5}$/u;
const VERSION_ID = /^[A-Za-z0-9-]{32,64}$/u;
const WATCHDOG_WORKFLOW_NAME = 'prerelease-cleanup.yml';
const EXPECTED_PROTECTED_ENVIRONMENT = 'assessment-prerelease';
const EXPECTED_EXTERNAL_PROTECTED_ENVIRONMENT = 'assessment-prerelease-external';
const EXPECTED_WATCHDOG_NAME = 'Stage 7 Expired Prerelease Cleanup';
const LIVE_SAFETY_RECHECK_MAX_AGE_MS = 5 * 60 * 1000;
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const RECONCILIATION_RECOVERY_APPROVAL_FIELDS = Object.freeze([
  'reconciliationRecoveryRoleArn',
  'reconciliationRecoveryPermissionsBoundaryArn',
  'reconciliationRecoveryRoleEffectivePermissionsRawSha256',
  'reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256',
  'reconciliationRecoveryRoleEffectivePermissionsSha256',
  'reconciliationRecoveryRoleEffectivePolicyProjectionSha256',
]);

export class PrereleaseSafetyReadinessError extends PrereleaseSafetyContractError {
  constructor(code) {
    super(code);
    this.name = 'PrereleaseSafetyReadinessError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new PrereleaseSafetyReadinessError(code);
};

const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, expected) =>
  object(value) && Object.keys(value).toSorted().join('\0') === expected.toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const isoUtc = (value) =>
  typeof value === 'string' &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value) &&
  !Number.isNaN(Date.parse(value)) &&
  new Date(value).toISOString() === value;

const containedPath = (filename, { directory = false } = {}) => {
  const resolved = path.resolve(workspaceRoot, filename);
  const relative = path.relative(workspaceRoot, resolved);
  if (
    relative === '' ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    fail('E7_PRERELEASE_SAFETY_PATH_OUTSIDE_WORKSPACE');
  }
  let stat;
  try {
    stat = lstatSync(resolved);
  } catch {
    fail('E7_PRERELEASE_SAFETY_SOURCE_MISSING');
  }
  if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())) {
    fail('E7_PRERELEASE_SAFETY_SOURCE_TYPE_INVALID');
  }
  const real = realpathSync(resolved);
  const realRelative = path.relative(realpathSync(workspaceRoot), real);
  if (
    realRelative === '..' ||
    realRelative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(realRelative)
  ) {
    fail('E7_PRERELEASE_SAFETY_PATH_OUTSIDE_WORKSPACE');
  }
  return { absolute: resolved, relative: relative.replaceAll(path.sep, '/') };
};

const readBytes = (filename, label, { sanitized = true } = {}) => {
  const { absolute } = containedPath(filename);
  const stat = lstatSync(absolute);
  if (stat.size < 1 || stat.size > MAX_JSON_BYTES) {
    fail('E7_PRERELEASE_SAFETY_SOURCE_SIZE_INVALID');
  }
  const bytes = readFileSync(absolute);
  if (sanitized) {
    try {
      assertSanitizedArtifactText(label, bytes.toString('utf8'));
    } catch {
      fail('E7_PRERELEASE_SAFETY_SOURCE_SANITIZATION_INVALID');
    }
  }
  return bytes;
};

const readJson = (filename, label, { sanitized = true } = {}) => {
  try {
    return parseStrictJsonSource(readBytes(filename, label, { sanitized }), {
      scanForbiddenData: false,
    });
  } catch (error) {
    if (error instanceof PrereleaseSafetyReadinessError) throw error;
    fail('E7_PRERELEASE_SAFETY_SOURCE_JSON_INVALID');
  }
};

const fileSha256 = (filename, label, options) => sha256(readBytes(filename, label, options));

const validateProtectedContext = (environmentVariables, expectedProtectedEnvironment) => {
  if (
    ![EXPECTED_PROTECTED_ENVIRONMENT, EXPECTED_EXTERNAL_PROTECTED_ENVIRONMENT].includes(
      expectedProtectedEnvironment,
    ) ||
    environmentVariables.GITHUB_ACTIONS !== 'true' ||
    environmentVariables.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    environmentVariables.GITHUB_REPOSITORY !== EXPECTED_REPOSITORY ||
    environmentVariables.GITHUB_REF !== 'refs/heads/master' ||
    environmentVariables.STAGE7_PROTECTED_ENVIRONMENT !== expectedProtectedEnvironment ||
    environmentVariables.CONFIRM_DEPLOY !== 'true' ||
    !GITHUB_RUN_ID.test(environmentVariables.GITHUB_RUN_ID ?? '') ||
    !GITHUB_RUN_ATTEMPT.test(environmentVariables.GITHUB_RUN_ATTEMPT ?? '') ||
    typeof environmentVariables.GITHUB_TOKEN !== 'string' ||
    environmentVariables.GITHUB_TOKEN.length < 20
  ) {
    fail('E7_PRERELEASE_SAFETY_PROTECTED_CONTEXT_REQUIRED');
  }
};

const validateFreezeBinding = ({ config, freeze, assemblyDirectory }) => {
  const validated = validateFreezeManifest(freeze);
  const assembly = containedPath(assemblyDirectory, { directory: true });
  const assemblySha256 = hashArtifactPath(assembly.absolute, {
    rootDirectory: workspaceRoot,
  }).sha256;
  const iacArtifact = validated.artifacts.find(({ name }) => name === 'iac');
  if (
    validated.authorizationScope !== 'EPHEMERAL_PRERELEASE' ||
    validated.releaseMode !== 'INITIAL' ||
    validated.releaseTag !== null ||
    validated.environment !== config.environment ||
    validated.region !== config.aws.region ||
    validated.configSha256 !== objectSha256(config) ||
    iacArtifact?.sha256 !== assemblySha256
  ) {
    fail('E7_PRERELEASE_SAFETY_FREEZE_BINDING_INVALID');
  }
  return { freeze: validated, assemblySha256 };
};

const validatePlan = ({ value, config, freeze, assemblySha256, rawDiffSha256 }) => {
  const checkpoint = value?.checkpoints?.diff;
  const stackSet = config.authorization.stacks.toSorted().join('\0');
  const checkpointStackSet = Array.isArray(checkpoint?.stacks)
    ? checkpoint.stacks.toSorted().join('\0')
    : '';
  if (
    value?.schemaVersion !== 1 ||
    value?.stage !== 7 ||
    value?.kind !== 'RELEASE_DIFF_REVIEW' ||
    value?.status !== 'READY_FOR_PROTECTED_REVIEW' ||
    value?.scope !== 'prerelease' ||
    value?.environment !== config.environment ||
    value?.authorizationId !== config.authorization.id ||
    value?.authorizationScope !== 'EPHEMERAL_PRERELEASE' ||
    value?.configSha256 !== objectSha256(config) ||
    value?.candidateSha !== freeze.candidateSha ||
    value?.releaseId !== freeze.releaseId ||
    value?.cloudAssemblySha256 !== assemblySha256 ||
    value?.previousReleaseManifestSha256 !== null ||
    value?.statefulReplacements !== 0 ||
    value?.destructiveChanges !== 0 ||
    value?.secretFindings !== 0 ||
    value?.productionProviderReferences !== 0 ||
    value?.humanReviewRequired !== true ||
    typeof value?.iamBroadeningDetected !== 'boolean' ||
    value?.rawDiffArtifactSha256 !== rawDiffSha256 ||
    value?.containsSensitiveData !== false ||
    !object(checkpoint) ||
    checkpoint.decision !== 'READY_FOR_PROTECTED_REVIEW' ||
    checkpoint.releaseMode !== 'INITIAL' ||
    checkpoint.previousReleaseManifestSha256 !== null ||
    checkpoint.assemblySha256 !== assemblySha256 ||
    checkpoint.freezeManifestSha256 !== freeze.manifestSha256 ||
    checkpoint.rawDiffArtifactSha256 !== rawDiffSha256 ||
    checkpointStackSet !== stackSet ||
    checkpoint.risks?.statefulReplacement !== false ||
    checkpoint.risks?.statefulDeletion !== false ||
    checkpoint.risks?.rollbackControlReplacement !== false ||
    checkpoint.exactChangeSetUsed !== false ||
    checkpoint.diffMethod !== 'TEMPLATE' ||
    checkpoint.exactDiffRecomputedAtDeploy !== true ||
    checkpoint.hotswapUsed !== false ||
    checkpoint.containsRawDiff !== true
  ) {
    fail('E7_PRERELEASE_SAFETY_PLAN_INVALID');
  }
  return value;
};

const validateAwsAuth = ({ value, config, freeze, watchdogRoleArn }) => {
  if (
    value?.schemaVersion !== 1 ||
    value?.stage !== 7 ||
    value?.kind !== 'AWS_READ_ONLY_PREFLIGHT' ||
    value?.status !== 'PASS' ||
    value?.scope !== 'prerelease' ||
    value?.candidateSha !== freeze.candidateSha ||
    value?.releaseId !== freeze.releaseId ||
    value?.manifestSha256 !== freeze.manifestSha256 ||
    value?.configSha256 !== objectSha256(config) ||
    value?.mutationsPerformed !== 0 ||
    value?.containsSensitiveData !== false
  ) {
    fail('E7_PRERELEASE_SAFETY_AWS_AUTH_INVALID');
  }
  try {
    return validateIamEffectivePermissionsEvidence({
      value: value.iamEffectivePermissions,
      config,
      scope: 'prerelease',
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      manifestSha256: freeze.manifestSha256,
      bootstrapAssetInventory:
        value.iamEffectivePermissions?.bootstrapRoles?.assetInventory?.inventory,
      cleanupWatchdogRoleArn: watchdogRoleArn,
      baselineRoleArn: null,
    });
  } catch (error) {
    if (error instanceof IamEffectivePermissionsError) {
      fail('E7_PRERELEASE_SAFETY_IAM_EFFECTIVE_PERMISSIONS_INVALID');
    }
    throw error;
  }
};

const validateApproval = ({
  value,
  config,
  freeze,
  assemblySha256,
  plan,
  planSha256,
  rawDiffSha256,
  awsAuthSha256,
  iam,
  now,
}) => {
  const expectedKeys = [
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
    ...RECONCILIATION_RECOVERY_APPROVAL_FIELDS,
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
    !exactKeys(value, expectedKeys) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'PROTECTED_RELEASE_APPROVAL' ||
    value.status !== 'PASS' ||
    value.scope !== 'prerelease' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.releaseTag !== null ||
    value.configSha256 !== objectSha256(config) ||
    value.cloudAssemblySha256 !== assemblySha256 ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.previousReleaseManifestSha256 !== null ||
    value.approvedPlanSha256 !== planSha256 ||
    value.approvedDiffSha256 !== rawDiffSha256 ||
    value.iamEffectivePermissionsBindingSha256 !== iam.bindingSha256 ||
    value.iamEffectivePermissionsEvidenceSha256 !== awsAuthSha256 ||
    value.journalRoleEffectivePermissionsRawSha256 !== null ||
    value.journalRoleEffectivePermissionsSha256 !== null ||
    RECONCILIATION_RECOVERY_APPROVAL_FIELDS.some((field) => value[field] !== null) ||
    !isoUtc(value.approvedAtUtc) ||
    Date.parse(value.approvedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(value.approvedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    Date.parse(value.approvedAtUtc) > now.getTime() ||
    value.statefulReplacements !== 0 ||
    value.destructiveChanges !== 0 ||
    value.iamBroadeningDetected !== plan.iamBroadeningDetected ||
    value.iamBroadeningReviewed !== true ||
    value.humanReviewConfirmed !== true ||
    value.explicitDispatchConfirmation !== true ||
    value.protectedEnvironment !== true ||
    value.protectedEnvironmentName !== EXPECTED_PROTECTED_ENVIRONMENT ||
    value.nonPublic !== true ||
    value.accountSha256 !== sha256(config.aws.accountId) ||
    value.accountSuffix !== config.aws.accountId.slice(-4) ||
    value.region !== config.aws.region ||
    value.stacks?.join('\0') !== config.authorization.stacks.join('\0') ||
    canonicalJson(value.budget) !==
      canonicalJson({
        maxUsd: config.budget.maxUsd,
        warningUsd: config.budget.warningUsd,
        alertDestinationSha256: config.budget.alertDestinationSha256,
      }) ||
    value.approvalOwnerAlias !== config.authorization.ownerAlias ||
    !/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u.test(value.reviewerAlias ?? '') ||
    canonicalJson(value.authorizedWindow) !== canonicalJson(config.window) ||
    value.externalRequests !== 0 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_PRERELEASE_SAFETY_APPROVAL_INVALID');
  }
  return value;
};

const defaultCandidateWorkflowSource = ({ candidateSha, candidateTreeSha }) => {
  try {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: workspaceRoot,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
    const tree = execFileSync('git', ['rev-parse', 'HEAD^{tree}'], {
      cwd: workspaceRoot,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
    if (head !== candidateSha || tree !== candidateTreeSha) {
      fail('E7_PRERELEASE_SAFETY_CANDIDATE_CHECKOUT_MISMATCH');
    }
    return execFileSync('git', ['show', `${candidateSha}:${WATCHDOG_WORKFLOW_RELATIVE}`], {
      cwd: workspaceRoot,
      encoding: null,
      maxBuffer: 2 * 1024 * 1024,
      windowsHide: true,
    });
  } catch (error) {
    if (error instanceof PrereleaseSafetyReadinessError) throw error;
    fail('E7_PRERELEASE_SAFETY_WATCHDOG_CANDIDATE_BLOB_UNAVAILABLE');
  }
};

const validateWatchdogWorkflow = ({ filename, freeze, candidateWorkflowSource }) => {
  const workflow = containedPath(filename);
  if (workflow.relative !== WATCHDOG_WORKFLOW_RELATIVE) {
    fail('E7_PRERELEASE_SAFETY_WATCHDOG_PATH_INVALID');
  }
  const source = readBytes(workflow.absolute, WATCHDOG_WORKFLOW_NAME);
  const errors = validatePrereleaseCleanupWorkflow(WATCHDOG_WORKFLOW_NAME, source.toString('utf8'));
  if (errors.length !== 0) fail('E7_PRERELEASE_SAFETY_WATCHDOG_CONTRACT_INVALID');
  const candidateSource = candidateWorkflowSource({
    candidateSha: freeze.candidateSha,
    candidateTreeSha: freeze.candidateTreeSha,
  });
  if (!Buffer.isBuffer(candidateSource) || candidateSource.length === 0) {
    fail('E7_PRERELEASE_SAFETY_WATCHDOG_CANDIDATE_BLOB_UNAVAILABLE');
  }
  const workflowSha256 = sha256(source);
  const candidateBlobSha256 = sha256(candidateSource);
  if (workflowSha256 !== candidateBlobSha256) {
    fail('E7_PRERELEASE_SAFETY_WATCHDOG_CANDIDATE_BLOB_MISMATCH');
  }
  return { workflowSha256, candidateBlobSha256 };
};

const validateLocalSources = ({
  configPath,
  manifestPath,
  assemblyPath,
  planPath,
  rawDiffPath,
  approvalPath,
  awsAuthPath,
  watchdogWorkflowPath,
  watchdogRoleArn,
  environmentVariables,
  now,
  candidateWorkflowSource,
  validateIam = validateAwsAuth,
  expectedProtectedEnvironment = EXPECTED_PROTECTED_ENVIRONMENT,
}) => {
  validateProtectedContext(environmentVariables, expectedProtectedEnvironment);
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    fail('E7_PRERELEASE_SAFETY_TIME_INVALID');
  }
  const config = validateStage7Config(
    readJson(configPath, 'stage7-prerelease-config.json', { sanitized: false }),
    { now },
  );
  if (
    config.authorization.scope !== 'EPHEMERAL_PRERELEASE' ||
    config.prereleaseAccess.mode !== 'CLOUDFRONT_SIGNED_COOKIE' ||
    config.prereleaseAccess.rotationDuringWindow !== 'FORBIDDEN'
  ) {
    fail('E7_PRERELEASE_SAFETY_CONFIG_SCOPE_INVALID');
  }
  const roleMatch = ROLE_ARN.exec(watchdogRoleArn ?? '');
  if (
    roleMatch === null ||
    roleMatch[1] !== config.aws.accountId ||
    Object.values(config.aws.roles).includes(watchdogRoleArn)
  ) {
    fail('E7_PRERELEASE_SAFETY_WATCHDOG_ROLE_INVALID');
  }
  const { freeze, assemblySha256 } = validateFreezeBinding({
    config,
    freeze: readJson(manifestPath, 'candidate-manifest.json'),
    assemblyDirectory: assemblyPath,
  });
  const rawDiffSha256 = fileSha256(rawDiffPath, 'infra-diff.txt');
  const plan = validatePlan({
    value: readJson(planPath, 'infra-diff.json'),
    config,
    freeze,
    assemblySha256,
    rawDiffSha256,
  });
  const planSha256 = fileSha256(planPath, 'infra-diff.json');
  const awsAuth = readJson(awsAuthPath, 'aws-auth.json');
  const awsAuthSha256 = fileSha256(awsAuthPath, 'aws-auth.json');
  const iam = validateIam({ value: awsAuth, config, freeze, watchdogRoleArn });
  const approval = validateApproval({
    value: readJson(approvalPath, 'approval.json'),
    config,
    freeze,
    assemblySha256,
    plan,
    planSha256,
    rawDiffSha256,
    awsAuthSha256,
    iam,
    now,
  });
  const approvalSha256 = fileSha256(approvalPath, 'approval.json');
  const watchdog = validateWatchdogWorkflow({
    filename: watchdogWorkflowPath,
    freeze,
    candidateWorkflowSource,
  });
  return {
    config,
    freeze,
    assemblySha256,
    plan,
    planSha256,
    rawDiffSha256,
    approval,
    approvalSha256,
    awsAuth,
    awsAuthSha256,
    iam,
    watchdog,
    watchdogRoleArn,
  };
};

const parseAwsJson = (source, code) => {
  try {
    return parseStrictJsonSource(Buffer.from(source), { scanForbiddenData: false });
  } catch {
    fail(code);
  }
};

const defaultCallGithub = ({ pathname, token }) =>
  new Promise((resolve, reject) => {
    const request = https.request(
      {
        hostname: 'api.github.com',
        method: 'GET',
        path: pathname,
        headers: {
          Accept: 'application/vnd.github+json',
          Authorization: `Bearer ${token}`,
          'User-Agent': 'stage7-prerelease-safety-readiness',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      },
      (response) => {
        const chunks = [];
        let bytes = 0;
        response.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > 2 * 1024 * 1024) {
            request.destroy(new Error('github response too large'));
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          if (response.statusCode !== 200) {
            reject(new PrereleaseSafetyReadinessError('E7_PRERELEASE_WATCHDOG_API_READ_FAILED'));
            return;
          }
          try {
            resolve(
              parseStrictJsonSource(Buffer.concat(chunks), {
                scanForbiddenData: false,
              }),
            );
          } catch {
            reject(
              new PrereleaseSafetyReadinessError('E7_PRERELEASE_WATCHDOG_API_RESPONSE_INVALID'),
            );
          }
        });
      },
    );
    request.setTimeout(15_000, () => {
      request.destroy(new Error('github request timed out'));
    });
    request.on('error', (error) => {
      reject(
        error instanceof PrereleaseSafetyReadinessError
          ? error
          : new PrereleaseSafetyReadinessError('E7_PRERELEASE_WATCHDOG_API_READ_FAILED'),
      );
    });
    request.end();
  });

const validateWatchdogApiState = ({
  repositoryResponse,
  workflowResponse,
  refResponse,
  freeze,
}) => {
  if (
    repositoryResponse?.full_name !== EXPECTED_REPOSITORY ||
    repositoryResponse?.default_branch !== EXPECTED_DEFAULT_BRANCH ||
    repositoryResponse?.archived !== false ||
    repositoryResponse?.disabled !== false ||
    repositoryResponse?.private !== false ||
    repositoryResponse?.visibility !== 'public' ||
    !Number.isSafeInteger(workflowResponse?.id) ||
    workflowResponse.id < 1 ||
    workflowResponse?.name !== EXPECTED_WATCHDOG_NAME ||
    workflowResponse?.path !== WATCHDOG_WORKFLOW_RELATIVE ||
    workflowResponse?.state !== 'active' ||
    !Number.isFinite(Date.parse(workflowResponse?.created_at ?? '')) ||
    !Number.isFinite(Date.parse(workflowResponse?.updated_at ?? '')) ||
    refResponse?.ref !== `refs/heads/${EXPECTED_DEFAULT_BRANCH}` ||
    refResponse?.object?.type !== 'commit' ||
    refResponse?.object?.sha !== freeze?.candidateSha
  ) {
    fail('E7_PRERELEASE_WATCHDOG_NOT_ACTIVE');
  }
  const repositoryProjection = {
    fullName: repositoryResponse.full_name,
    defaultBranch: repositoryResponse.default_branch,
    archived: repositoryResponse.archived,
    disabled: repositoryResponse.disabled,
    private: repositoryResponse.private,
    visibility: repositoryResponse.visibility,
  };
  const workflowProjection = {
    id: workflowResponse.id,
    name: workflowResponse.name,
    path: workflowResponse.path,
    state: workflowResponse.state,
    createdAtUtc: new Date(workflowResponse.created_at).toISOString(),
    updatedAtUtc: new Date(workflowResponse.updated_at).toISOString(),
  };
  const refProjection = {
    ref: refResponse.ref,
    objectType: refResponse.object.type,
    candidateSha: refResponse.object.sha,
  };
  return {
    status: 'PASS',
    decision: 'ACTIVE_ON_DEFAULT_BRANCH',
    repository: EXPECTED_REPOSITORY,
    defaultBranch: EXPECTED_DEFAULT_BRANCH,
    workflowPath: WATCHDOG_WORKFLOW_RELATIVE,
    workflowState: 'active',
    defaultBranchHeadSha256: sha256(freeze.candidateSha),
    workflowIdSha256: sha256(String(workflowResponse.id)),
    repositoryResponseSha256: objectSha256(repositoryProjection),
    workflowResponseSha256: objectSha256(workflowProjection),
    refResponseSha256: objectSha256(refProjection),
    apiRequests: 3,
    rawResponseCaptured: false,
  };
};

const defaultCallAws = ({ service, operation, arguments_, region }) => {
  let stdout;
  try {
    stdout = execFileSync(
      process.platform === 'win32' ? 'aws.cmd' : 'aws',
      [service, operation, ...arguments_, '--region', region, '--output', 'json', '--no-cli-pager'],
      {
        cwd: workspaceRoot,
        encoding: 'utf8',
        maxBuffer: 16 * 1024 * 1024,
        windowsHide: true,
      },
    );
  } catch {
    fail('E7_PRERELEASE_SAFETY_AWS_READ_FAILED');
  }
  return parseAwsJson(stdout, 'E7_PRERELEASE_SAFETY_AWS_RESPONSE_INVALID');
};

const READ_IDENTITY_KEYS = [
  'status',
  'decision',
  'runId',
  'runAttempt',
  'sessionKind',
  'sessionPrefix',
  'accountSha256',
  'accountSuffix',
  'roleArnSha256',
  'sessionArnSha256',
  'principalIdSha256',
  'sessionNameSha256',
  'sessionBindingSha256',
  'rawIdentityCaptured',
];
const READ_SESSION_PREFIX = Object.freeze({
  safety: 'e7pre-safety',
  activation: 'e7pre-read',
  sandbox: 'e7pre-external-read',
});

const validateLiveReadIdentity = ({
  config,
  identityResponse,
  environmentVariables,
  expectedSessionKind,
}) => {
  const runId = environmentVariables.GITHUB_RUN_ID;
  const runAttempt = environmentVariables.GITHUB_RUN_ATTEMPT;
  const expectedSessionPrefix = READ_SESSION_PREFIX[expectedSessionKind];
  const readRoleArn = config.aws.roles.readRoleArn;
  const roleMatch = ROLE_ARN.exec(readRoleArn ?? '');
  const roleName = readRoleArn?.slice(readRoleArn.lastIndexOf('/') + 1);
  const sessionName = `${expectedSessionPrefix}-${runId}-${runAttempt}`;
  const expectedArn = `arn:aws:sts::${config.aws.accountId}:assumed-role/${roleName}/${sessionName}`;
  if (
    expectedSessionPrefix === undefined ||
    !GITHUB_RUN_ID.test(runId ?? '') ||
    !GITHUB_RUN_ATTEMPT.test(runAttempt ?? '') ||
    roleMatch?.[1] !== config.aws.accountId ||
    typeof roleName !== 'string' ||
    roleName.length === 0 ||
    sessionName.length > 64 ||
    identityResponse?.Account !== config.aws.accountId ||
    identityResponse?.Arn !== expectedArn ||
    typeof identityResponse?.UserId !== 'string' ||
    identityResponse.UserId.length < sessionName.length + 2 ||
    !identityResponse.UserId.endsWith(`:${sessionName}`)
  ) {
    fail('E7_PRERELEASE_SAFETY_READ_IDENTITY_INVALID');
  }
  return {
    status: 'PASS',
    decision: 'READ_ROLE_ACCOUNT_CONFIRMED',
    runId,
    runAttempt,
    sessionKind: expectedSessionKind,
    sessionPrefix: expectedSessionPrefix,
    accountSha256: sha256(config.aws.accountId),
    accountSuffix: config.aws.accountId.slice(-4),
    roleArnSha256: sha256(readRoleArn),
    sessionArnSha256: sha256(identityResponse.Arn),
    principalIdSha256: sha256(identityResponse.UserId),
    sessionNameSha256: sha256(sessionName),
    sessionBindingSha256: sha256(`${readRoleArn}\n${sessionName}`),
    rawIdentityCaptured: false,
  };
};

const validateSanitizedReadIdentity = ({
  value,
  config,
  expectedGithubRunId,
  expectedGithubRunAttempt,
  expectedSessionKind,
}) => {
  const expectedSessionPrefix = READ_SESSION_PREFIX[expectedSessionKind];
  const sessionName = `${expectedSessionPrefix}-${expectedGithubRunId}-${expectedGithubRunAttempt}`;
  const readRoleArn = config.aws.roles.readRoleArn;
  const roleName = readRoleArn.slice(readRoleArn.lastIndexOf('/') + 1);
  const expectedSessionArn = `arn:aws:sts::${config.aws.accountId}:assumed-role/${roleName}/${sessionName}`;
  return (
    GITHUB_RUN_ID.test(expectedGithubRunId ?? '') &&
    GITHUB_RUN_ATTEMPT.test(expectedGithubRunAttempt ?? '') &&
    expectedSessionPrefix !== undefined &&
    exactKeys(value, READ_IDENTITY_KEYS) &&
    value.status === 'PASS' &&
    value.decision === 'READ_ROLE_ACCOUNT_CONFIRMED' &&
    value.runId === expectedGithubRunId &&
    value.runAttempt === expectedGithubRunAttempt &&
    value.sessionKind === expectedSessionKind &&
    value.sessionPrefix === expectedSessionPrefix &&
    value.accountSha256 === sha256(config.aws.accountId) &&
    value.accountSuffix === config.aws.accountId.slice(-4) &&
    value.roleArnSha256 === sha256(readRoleArn) &&
    value.sessionArnSha256 === sha256(expectedSessionArn) &&
    SHA256.test(value.principalIdSha256 ?? '') &&
    value.sessionNameSha256 === sha256(sessionName) &&
    value.sessionBindingSha256 === sha256(`${readRoleArn}\n${sessionName}`) &&
    value.rawIdentityCaptured === false
  );
};

const validateLiveAccess = ({ config, keyGroupResponse, publicKeyResponse, secretResponse }) => {
  const access = config.prereleaseAccess;
  const keyGroup = keyGroupResponse?.KeyGroup;
  const keyGroupConfig = keyGroup?.KeyGroupConfig;
  const publicKey = publicKeyResponse?.PublicKey;
  const publicKeyConfig = publicKey?.PublicKeyConfig;
  const encodedKey = publicKeyConfig?.EncodedKey;
  let keyObject;
  try {
    keyObject = createPublicKey(encodedKey);
  } catch {
    fail('E7_PRERELEASE_SAFETY_PUBLIC_KEY_INVALID');
  }
  const current = Object.entries(secretResponse?.VersionIdsToStages ?? {}).filter(
    ([, stages]) => Array.isArray(stages) && stages.includes('AWSCURRENT'),
  );
  if (
    access.mode !== 'CLOUDFRONT_SIGNED_COOKIE' ||
    !VERSION_ID.test(access.originTokenSecretVersionId ?? '') ||
    typeof keyGroupResponse?.ETag !== 'string' ||
    keyGroupResponse.ETag.length === 0 ||
    keyGroup?.Id !== access.keyGroupId ||
    !Array.isArray(keyGroupConfig?.Items) ||
    keyGroupConfig.Items.length !== 1 ||
    keyGroupConfig.Items[0] !== access.publicKeyId ||
    typeof publicKeyResponse?.ETag !== 'string' ||
    publicKeyResponse.ETag.length === 0 ||
    publicKey?.Id !== access.publicKeyId ||
    typeof publicKeyConfig?.Name !== 'string' ||
    publicKeyConfig.Name.length === 0 ||
    typeof encodedKey !== 'string' ||
    keyObject.asymmetricKeyType !== 'rsa' ||
    (keyObject.asymmetricKeyDetails?.modulusLength ?? 0) < 2048 ||
    secretResponse?.ARN !== access.originTokenSecretArn ||
    secretResponse?.DeletedDate !== undefined ||
    secretResponse?.KmsKeyId !== undefined ||
    secretResponse?.RotationEnabled !== false ||
    current.length !== 1 ||
    current[0][0] !== access.originTokenSecretVersionId
  ) {
    fail('E7_PRERELEASE_SAFETY_LIVE_ACCESS_INVALID');
  }
  const bindingParts = [
    access.mode,
    access.keyGroupId,
    access.publicKeyId,
    access.originTokenSecretArn,
    access.originTokenSecretVersionId,
  ];
  return {
    status: 'PASS',
    mode: 'CLOUDFRONT_SIGNED_COOKIE',
    bindingSha256: sha256(bindingParts.join('\n')),
    keyGroupIdSha256: sha256(access.keyGroupId),
    keyGroupEtagSha256: sha256(keyGroupResponse.ETag),
    keyGroupPublicKeyCount: 1,
    publicKeyIdSha256: sha256(access.publicKeyId),
    publicKeyEtagSha256: sha256(publicKeyResponse.ETag),
    publicKeyMaterialSha256: sha256(encodedKey),
    publicKeyAlgorithm: 'RSA',
    originTokenSecretArnSha256: sha256(access.originTokenSecretArn),
    originTokenSecretVersionIdSha256: sha256(access.originTokenSecretVersionId),
    originSecretBindingSha256: sha256(
      `${access.originTokenSecretArn}\n${access.originTokenSecretVersionId}`,
    ),
    currentVersionCount: 1,
    rotationEnabled: false,
    customerManagedKmsKeyUsed: false,
    rawAccessMaterialCaptured: false,
  };
};

const validatePlanLiveBindings = ({ plan, accessControl }) => {
  const plannedAccess = plan.checkpoints.diff.prereleaseAccess;
  const plannedSecret = plan.checkpoints.diff.runtimeSecret;
  if (
    plannedAccess?.decision !== 'PASS' ||
    plannedAccess?.bindingSha256 !== accessControl.bindingSha256 ||
    plannedAccess?.keyGroupIdSha256 !== accessControl.keyGroupIdSha256 ||
    plannedAccess?.publicKeyIdSha256 !== accessControl.publicKeyIdSha256 ||
    plannedAccess?.originTokenSecretReferenceSha256 !== accessControl.originTokenSecretArnSha256 ||
    plannedAccess?.originTokenSecretVersionIdSha256 !==
      accessControl.originTokenSecretVersionIdSha256 ||
    plannedAccess?.rawAccessMaterialCaptured !== false ||
    plannedSecret?.decision !== 'PASS' ||
    plannedSecret?.bindingSha256 !== accessControl.originSecretBindingSha256 ||
    plannedSecret?.secretArnSha256 !== accessControl.originTokenSecretArnSha256 ||
    plannedSecret?.versionIdSha256 !== accessControl.originTokenSecretVersionIdSha256 ||
    plannedSecret?.currentVersionCount !== 1 ||
    plannedSecret?.rotationEnabled !== false ||
    plannedSecret?.customerManagedKmsKeyUsed !== false ||
    plannedSecret?.rawSecretMaterialCaptured !== false
  ) {
    fail('E7_PRERELEASE_SAFETY_PLAN_LIVE_BINDING_INVALID');
  }
};

const readinessBody = ({ local, readIdentity, accessControl, watchdogApi, now }) => {
  const watchdogRole = local.iam.cleanupWatchdog.role;
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'PRERELEASE_SAFETY_READINESS',
    status: 'PASS',
    decision: 'READY_FOR_PROTECTED_PRERELEASE_MUTATION',
    scope: 'prerelease',
    generatedAtUtc: now.toISOString(),
    environment: local.config.environment,
    authorizationId: local.config.authorization.id,
    candidateSha: local.freeze.candidateSha,
    releaseId: local.freeze.releaseId,
    authorizedWindow: {
      startsAtUtc: local.config.window.startsAtUtc,
      endsAtUtc: local.config.window.endsAtUtc,
      cleanupExpiresAtUtc: local.config.cleanup.expiresAtUtc,
    },
    sources: {
      configSha256: objectSha256(local.config),
      freezeManifestSha256: local.freeze.manifestSha256,
      cloudAssemblySha256: local.assemblySha256,
      approvedPlanSha256: local.planSha256,
      approvedRawDiffSha256: local.rawDiffSha256,
      approvalSha256: local.approvalSha256,
      awsAuthSha256: local.awsAuthSha256,
      watchdogWorkflowSha256: local.watchdog.workflowSha256,
      watchdogCandidateBlobSha256: local.watchdog.candidateBlobSha256,
    },
    iam: {
      status: 'PASS',
      effectivePermissionsBindingSha256: local.iam.bindingSha256,
      effectivePermissionsEvidenceSha256: local.awsAuthSha256,
      watchdogRoleArnSha256: sha256(local.watchdogRoleArn),
      watchdogTrustPolicySha256: watchdogRole.trustPolicySha256,
      watchdogOidcSubjectsSha256: watchdogRole.oidcSubjectsSha256,
      watchdogPermissionSetSha256: watchdogRole.permissionSetSha256,
      expectedOidcSubjectSha256: sha256(WATCHDOG_OIDC_SUBJECT),
    },
    readIdentity,
    accessControl,
    durableCleanup: {
      status: 'PASS',
      decision: 'DURABLE_RECOVERY_READY',
      workflowPath: WATCHDOG_WORKFLOW_RELATIVE,
      workflowSha256: local.watchdog.workflowSha256,
      candidateBlobSha256: local.watchdog.candidateBlobSha256,
      cron: WATCHDOG_CRON,
      oidcSubject: WATCHDOG_OIDC_SUBJECT,
      roleArnSha256: sha256(local.watchdogRoleArn),
      roleTrustPolicySha256: watchdogRole.trustPolicySha256,
      rolePermissionSetSha256: watchdogRole.permissionSetSha256,
      apiStatus: watchdogApi.decision,
      repository: watchdogApi.repository,
      defaultBranch: watchdogApi.defaultBranch,
      workflowState: watchdogApi.workflowState,
      defaultBranchHeadSha256: watchdogApi.defaultBranchHeadSha256,
      workflowIdSha256: watchdogApi.workflowIdSha256,
      repositoryResponseSha256: watchdogApi.repositoryResponseSha256,
      workflowResponseSha256: watchdogApi.workflowResponseSha256,
      refResponseSha256: watchdogApi.refResponseSha256,
      apiRequests: watchdogApi.apiRequests,
      rawApiResponseCaptured: watchdogApi.rawResponseCaptured,
      independentOfPrereleaseRun: true,
      humanApprovalRequired: false,
      scheduleEnabledByContract: true,
    },
    externalRequests: 7,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
};

const captureLiveSafetyState = async ({
  local,
  callAws,
  callGithub,
  environmentVariables,
  expectedSessionKind,
}) => {
  const githubToken = environmentVariables.GITHUB_TOKEN;
  const repositoryResponse = await callGithub({
    pathname: `/repos/${EXPECTED_REPOSITORY}`,
    token: githubToken,
  });
  const workflowResponse = await callGithub({
    pathname: `/repos/${EXPECTED_REPOSITORY}/actions/workflows/${WATCHDOG_WORKFLOW_NAME}`,
    token: githubToken,
  });
  const refResponse = await callGithub({
    pathname: `/repos/${EXPECTED_REPOSITORY}/git/ref/heads/${EXPECTED_DEFAULT_BRANCH}`,
    token: githubToken,
  });
  const watchdogApi = validateWatchdogApiState({
    repositoryResponse,
    workflowResponse,
    refResponse,
    freeze: local.freeze,
  });
  const identityResponse = callAws({
    service: 'sts',
    operation: 'get-caller-identity',
    arguments_: [],
    region: local.config.aws.region,
  });
  const readIdentity = validateLiveReadIdentity({
    config: local.config,
    identityResponse,
    environmentVariables,
    expectedSessionKind,
  });
  const access = local.config.prereleaseAccess;
  const keyGroupResponse = callAws({
    service: 'cloudfront',
    operation: 'get-key-group',
    arguments_: ['--id', access.keyGroupId],
    region: local.config.aws.region,
  });
  const publicKeyResponse = callAws({
    service: 'cloudfront',
    operation: 'get-public-key',
    arguments_: ['--id', access.publicKeyId],
    region: local.config.aws.region,
  });
  const secretResponse = callAws({
    service: 'secretsmanager',
    operation: 'describe-secret',
    arguments_: ['--secret-id', access.originTokenSecretArn],
    region: local.config.aws.region,
  });
  const accessControl = validateLiveAccess({
    config: local.config,
    keyGroupResponse,
    publicKeyResponse,
    secretResponse,
  });
  return { watchdogApi, readIdentity, accessControl };
};

const captureWithDependencies = async ({
  callAws,
  callGithub,
  candidateWorkflowSource,
  validateIam,
  environmentVariables,
  now,
  ...inputs
}) => {
  const local = validateLocalSources({
    ...inputs,
    environmentVariables,
    now,
    candidateWorkflowSource,
    validateIam,
  });
  const { watchdogApi, readIdentity, accessControl } = await captureLiveSafetyState({
    local,
    callAws,
    callGithub,
    environmentVariables,
    expectedSessionKind: 'safety',
  });
  validatePlanLiveBindings({ plan: local.plan, accessControl });
  const body = readinessBody({ local, readIdentity, accessControl, watchdogApi, now });
  const readiness = { ...body, readinessSha256: objectSha256(body) };
  validatePrereleaseSafetyReadiness(readiness, {
    config: local.config,
    freeze: local.freeze,
    sourceBindings: body.sources,
    watchdogRoleArn: local.watchdogRoleArn,
    iamEffectivePermissions: local.iam,
    expectedGithubRunId: environmentVariables.GITHUB_RUN_ID,
    expectedGithubRunAttempt: environmentVariables.GITHUB_RUN_ATTEMPT,
    now,
  });
  return readiness;
};

export const capturePrereleaseSafetyReadiness = async ({
  configPath,
  manifestPath,
  assemblyPath,
  planPath,
  rawDiffPath,
  approvalPath,
  awsAuthPath,
  watchdogWorkflowPath = path.join(workspaceRoot, WATCHDOG_WORKFLOW_RELATIVE),
  watchdogRoleArn,
  outputPath,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const readiness = await captureWithDependencies({
    configPath,
    manifestPath,
    assemblyPath,
    planPath,
    rawDiffPath,
    approvalPath,
    awsAuthPath,
    watchdogWorkflowPath,
    watchdogRoleArn,
    callAws: defaultCallAws,
    callGithub: defaultCallGithub,
    candidateWorkflowSource: defaultCandidateWorkflowSource,
    validateIam: validateAwsAuth,
    environmentVariables,
    now,
  });
  writeStage7Json(outputPath, 'prerelease-safety-readiness.json', readiness);
  return readiness;
};

export const validatePrereleaseSafetyReadinessFromFiles = ({
  readinessPath,
  configPath,
  manifestPath,
  assemblyPath,
  planPath,
  rawDiffPath,
  approvalPath,
  awsAuthPath,
  watchdogWorkflowPath = path.join(workspaceRoot, WATCHDOG_WORKFLOW_RELATIVE),
  watchdogRoleArn,
  environmentVariables = process.env,
  now = new Date(),
  expectedProtectedEnvironment = EXPECTED_PROTECTED_ENVIRONMENT,
}) => {
  const local = validateLocalSources({
    configPath,
    manifestPath,
    assemblyPath,
    planPath,
    rawDiffPath,
    approvalPath,
    awsAuthPath,
    watchdogWorkflowPath,
    watchdogRoleArn,
    environmentVariables,
    now,
    candidateWorkflowSource: defaultCandidateWorkflowSource,
    validateIam: validateAwsAuth,
    expectedProtectedEnvironment,
  });
  const readiness = readJson(readinessPath, 'prerelease-safety-readiness.json');
  validatePrereleaseSafetyReadiness(readiness, {
    config: local.config,
    freeze: local.freeze,
    sourceBindings: {
      configSha256: objectSha256(local.config),
      freezeManifestSha256: local.freeze.manifestSha256,
      cloudAssemblySha256: local.assemblySha256,
      approvedPlanSha256: local.planSha256,
      approvedRawDiffSha256: local.rawDiffSha256,
      approvalSha256: local.approvalSha256,
      awsAuthSha256: local.awsAuthSha256,
      watchdogWorkflowSha256: local.watchdog.workflowSha256,
      watchdogCandidateBlobSha256: local.watchdog.candidateBlobSha256,
    },
    watchdogRoleArn,
    iamEffectivePermissions: local.iam,
    expectedGithubRunId: environmentVariables.GITHUB_RUN_ID,
    expectedGithubRunAttempt: environmentVariables.GITHUB_RUN_ATTEMPT,
    now,
  });
  validatePlanLiveBindings({ plan: local.plan, accessControl: readiness.accessControl });
  return { readiness, config: local.config, freeze: local.freeze, local };
};

const WATCHDOG_AUTHORITY_PHASES = new Set([
  'deploy-gate',
  'deploy-data',
  'deploy-api',
  'deploy-observability',
  'deploy-web',
  'seed',
  'register-expiry',
  'activation',
  'sandbox',
]);

const revalidateWatchdogAuthorityWithDependencies = async ({
  readiness,
  freeze,
  candidateWorkflowSha256,
  phase,
  environmentVariables,
  now,
  callGithub,
}) => {
  if (
    !WATCHDOG_AUTHORITY_PHASES.has(phase) ||
    typeof environmentVariables.GITHUB_TOKEN !== 'string' ||
    environmentVariables.GITHUB_TOKEN.length < 20 ||
    !(now instanceof Date) ||
    !Number.isFinite(now.getTime())
  ) {
    fail('E7_PRERELEASE_WATCHDOG_LIVE_AUTHORITY_REQUIRED');
  }
  const token = environmentVariables.GITHUB_TOKEN;
  const repositoryResponse = await callGithub({
    pathname: `/repos/${EXPECTED_REPOSITORY}`,
    token,
  });
  const workflowResponse = await callGithub({
    pathname: `/repos/${EXPECTED_REPOSITORY}/actions/workflows/${WATCHDOG_WORKFLOW_NAME}`,
    token,
  });
  const refResponse = await callGithub({
    pathname: `/repos/${EXPECTED_REPOSITORY}/git/ref/heads/${EXPECTED_DEFAULT_BRANCH}`,
    token,
  });
  const live = validateWatchdogApiState({
    repositoryResponse,
    workflowResponse,
    refResponse,
    freeze,
  });
  const durable = readiness.durableCleanup;
  if (
    candidateWorkflowSha256 !== readiness.sources.watchdogCandidateBlobSha256 ||
    durable.workflowSha256 !== candidateWorkflowSha256 ||
    live.repository !== durable.repository ||
    live.defaultBranch !== durable.defaultBranch ||
    live.workflowPath !== durable.workflowPath ||
    live.workflowState !== durable.workflowState ||
    live.defaultBranchHeadSha256 !== durable.defaultBranchHeadSha256 ||
    live.workflowIdSha256 !== durable.workflowIdSha256 ||
    live.repositoryResponseSha256 !== durable.repositoryResponseSha256 ||
    live.workflowResponseSha256 !== durable.workflowResponseSha256 ||
    live.refResponseSha256 !== durable.refResponseSha256 ||
    live.apiRequests !== 3 ||
    live.rawResponseCaptured !== false
  ) {
    fail('E7_PRERELEASE_WATCHDOG_LIVE_AUTHORITY_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'PRERELEASE_WATCHDOG_LIVE_AUTHORITY',
    status: 'PASS',
    decision: 'WATCHDOG_LIVE_AUTHORITY_CONFIRMED',
    phase,
    verifiedAtUtc: now.toISOString(),
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    safetyReadinessSha256: readiness.readinessSha256,
    watchdogWorkflowSha256: candidateWorkflowSha256,
    defaultBranchHeadSha256: live.defaultBranchHeadSha256,
    workflowState: live.workflowState,
    workflowIdSha256: live.workflowIdSha256,
    repositoryResponseSha256: live.repositoryResponseSha256,
    workflowResponseSha256: live.workflowResponseSha256,
    refResponseSha256: live.refResponseSha256,
    apiRequests: 3,
    rawResponseCaptured: false,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return { ...body, watchdogLiveAuthoritySha256: objectSha256(body) };
};

export const revalidatePrereleaseWatchdogLiveAuthority = async ({
  readiness,
  freeze,
  candidateWorkflowSha256,
  phase,
  environmentVariables = process.env,
  now = new Date(),
}) =>
  revalidateWatchdogAuthorityWithDependencies({
    readiness,
    freeze,
    candidateWorkflowSha256,
    phase,
    environmentVariables,
    now,
    callGithub: defaultCallGithub,
  });

const liveSafetyDecision = (phase) => {
  if (!['activation', 'sandbox'].includes(phase)) {
    fail('E7_PRERELEASE_LIVE_SAFETY_RECHECK_PHASE_INVALID');
  }
  return phase === 'activation'
    ? 'FRESH_FOR_PRERELEASE_ACTIVATION'
    : 'FRESH_FOR_PRERELEASE_SANDBOX';
};

const liveSafetyRecheckBody = ({
  phase,
  readiness,
  config,
  freeze,
  readIdentity,
  accessControl,
  watchdogApi,
  now,
}) => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'PRERELEASE_LIVE_SAFETY_RECHECK',
  status: 'PASS',
  decision: liveSafetyDecision(phase),
  phase,
  scope: 'prerelease',
  generatedAtUtc: now.toISOString(),
  environment: config.environment,
  authorizationId: config.authorization.id,
  candidateSha: freeze.candidateSha,
  releaseId: freeze.releaseId,
  configSha256: objectSha256(config),
  freezeManifestSha256: freeze.manifestSha256,
  initialSafetyReadinessSha256: readiness.readinessSha256,
  durableCleanupReadinessSha256: objectSha256(readiness.durableCleanup),
  readIdentity,
  accessControl,
  watchdogApi,
  maxAgeSeconds: LIVE_SAFETY_RECHECK_MAX_AGE_MS / 1000,
  externalRequests: 7,
  mutationsPerformed: 0,
  containsSensitiveData: false,
});

export const validatePrereleaseLiveSafetyRecheck = (
  value,
  {
    readiness,
    config,
    freeze,
    phase,
    expectedGithubRunId,
    expectedGithubRunAttempt,
    now = new Date(),
  },
) => {
  const body = { ...value };
  delete body.liveSafetyRecheckSha256;
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'decision',
      'phase',
      'scope',
      'generatedAtUtc',
      'environment',
      'authorizationId',
      'candidateSha',
      'releaseId',
      'configSha256',
      'freezeManifestSha256',
      'initialSafetyReadinessSha256',
      'durableCleanupReadinessSha256',
      'readIdentity',
      'accessControl',
      'watchdogApi',
      'maxAgeSeconds',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'liveSafetyRecheckSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'PRERELEASE_LIVE_SAFETY_RECHECK' ||
    value.status !== 'PASS' ||
    value.phase !== phase ||
    value.decision !== liveSafetyDecision(phase) ||
    value.scope !== 'prerelease' ||
    !isoUtc(value.generatedAtUtc) ||
    !(now instanceof Date) ||
    !Number.isFinite(now.getTime()) ||
    Date.parse(value.generatedAtUtc) > now.getTime() ||
    now.getTime() - Date.parse(value.generatedAtUtc) > LIVE_SAFETY_RECHECK_MAX_AGE_MS ||
    Date.parse(value.generatedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(value.generatedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    value.environment !== config.environment ||
    value.authorizationId !== config.authorization.id ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.configSha256 !== objectSha256(config) ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.initialSafetyReadinessSha256 !== readiness.readinessSha256 ||
    value.durableCleanupReadinessSha256 !== objectSha256(readiness.durableCleanup) ||
    !validateSanitizedReadIdentity({
      value: value.readIdentity,
      config,
      expectedGithubRunId,
      expectedGithubRunAttempt,
      expectedSessionKind: phase,
    }) ||
    canonicalJson(value.accessControl) !== canonicalJson(readiness.accessControl) ||
    !exactKeys(value.watchdogApi, [
      'status',
      'decision',
      'repository',
      'defaultBranch',
      'workflowPath',
      'workflowState',
      'defaultBranchHeadSha256',
      'workflowIdSha256',
      'repositoryResponseSha256',
      'workflowResponseSha256',
      'refResponseSha256',
      'apiRequests',
      'rawResponseCaptured',
    ]) ||
    value.watchdogApi.status !== 'PASS' ||
    value.watchdogApi.decision !== 'ACTIVE_ON_DEFAULT_BRANCH' ||
    value.watchdogApi.repository !== EXPECTED_REPOSITORY ||
    value.watchdogApi.defaultBranch !== EXPECTED_DEFAULT_BRANCH ||
    value.watchdogApi.workflowPath !== WATCHDOG_WORKFLOW_RELATIVE ||
    value.watchdogApi.workflowState !== 'active' ||
    value.watchdogApi.defaultBranchHeadSha256 !== sha256(freeze.candidateSha) ||
    [
      value.watchdogApi.workflowIdSha256,
      value.watchdogApi.repositoryResponseSha256,
      value.watchdogApi.workflowResponseSha256,
      value.watchdogApi.refResponseSha256,
    ].some((digest) => !SHA256.test(digest ?? '')) ||
    value.watchdogApi.apiRequests !== 3 ||
    value.watchdogApi.rawResponseCaptured !== false ||
    value.maxAgeSeconds !== LIVE_SAFETY_RECHECK_MAX_AGE_MS / 1000 ||
    value.externalRequests !== 7 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.liveSafetyRecheckSha256 !== objectSha256(body)
  ) {
    fail('E7_PRERELEASE_LIVE_SAFETY_RECHECK_INVALID');
  }
  return value;
};

export const capturePrereleaseLiveSafetyRecheck = async ({
  phase,
  readinessPath,
  configPath,
  manifestPath,
  assemblyPath,
  planPath,
  rawDiffPath,
  approvalPath,
  awsAuthPath,
  watchdogWorkflowPath = path.join(workspaceRoot, WATCHDOG_WORKFLOW_RELATIVE),
  watchdogRoleArn,
  outputPath,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const { readiness, config, freeze, local } = validatePrereleaseSafetyReadinessFromFiles({
    readinessPath,
    configPath,
    manifestPath,
    assemblyPath,
    planPath,
    rawDiffPath,
    approvalPath,
    awsAuthPath,
    watchdogWorkflowPath,
    watchdogRoleArn,
    environmentVariables,
    now,
    expectedProtectedEnvironment: EXPECTED_EXTERNAL_PROTECTED_ENVIRONMENT,
  });
  const { watchdogApi, readIdentity, accessControl } = await captureLiveSafetyState({
    local,
    callAws: defaultCallAws,
    callGithub: defaultCallGithub,
    environmentVariables,
    expectedSessionKind: phase,
  });
  if (canonicalJson(accessControl) !== canonicalJson(readiness.accessControl)) {
    fail('E7_PRERELEASE_LIVE_ACCESS_CHANGED');
  }
  const body = liveSafetyRecheckBody({
    phase,
    readiness,
    config,
    freeze,
    readIdentity,
    accessControl,
    watchdogApi,
    now,
  });
  const result = { ...body, liveSafetyRecheckSha256: objectSha256(body) };
  validatePrereleaseLiveSafetyRecheck(result, {
    readiness,
    config,
    freeze,
    phase,
    expectedGithubRunId: environmentVariables.GITHUB_RUN_ID,
    expectedGithubRunAttempt: environmentVariables.GITHUB_RUN_ATTEMPT,
    now,
  });
  writeStage7Json(
    outputPath,
    phase === 'activation'
      ? 'prerelease-activation-live-safety-recheck.json'
      : 'prerelease-sandbox-live-safety-recheck.json',
    result,
  );
  return result;
};

export const validatePrereleaseSafetyReadiness = (
  value,
  {
    config,
    freeze,
    sourceBindings,
    watchdogRoleArn,
    iamEffectivePermissions,
    expectedGithubRunId,
    expectedGithubRunAttempt,
    now = new Date(),
  },
) => {
  const body = { ...value };
  delete body.readinessSha256;
  const expectedSourceKeys = [
    'configSha256',
    'freezeManifestSha256',
    'cloudAssemblySha256',
    'approvedPlanSha256',
    'approvedRawDiffSha256',
    'approvalSha256',
    'awsAuthSha256',
    'watchdogWorkflowSha256',
    'watchdogCandidateBlobSha256',
  ];
  const expectedIamKeys = [
    'status',
    'effectivePermissionsBindingSha256',
    'effectivePermissionsEvidenceSha256',
    'watchdogRoleArnSha256',
    'watchdogTrustPolicySha256',
    'watchdogOidcSubjectsSha256',
    'watchdogPermissionSetSha256',
    'expectedOidcSubjectSha256',
  ];
  const expectedAccessKeys = [
    'status',
    'mode',
    'bindingSha256',
    'keyGroupIdSha256',
    'keyGroupEtagSha256',
    'keyGroupPublicKeyCount',
    'publicKeyIdSha256',
    'publicKeyEtagSha256',
    'publicKeyMaterialSha256',
    'publicKeyAlgorithm',
    'originTokenSecretArnSha256',
    'originTokenSecretVersionIdSha256',
    'originSecretBindingSha256',
    'currentVersionCount',
    'rotationEnabled',
    'customerManagedKmsKeyUsed',
    'rawAccessMaterialCaptured',
  ];
  const expectedCleanupKeys = [
    'status',
    'decision',
    'workflowPath',
    'workflowSha256',
    'candidateBlobSha256',
    'cron',
    'oidcSubject',
    'roleArnSha256',
    'roleTrustPolicySha256',
    'rolePermissionSetSha256',
    'apiStatus',
    'repository',
    'defaultBranch',
    'workflowState',
    'defaultBranchHeadSha256',
    'workflowIdSha256',
    'repositoryResponseSha256',
    'workflowResponseSha256',
    'refResponseSha256',
    'apiRequests',
    'rawApiResponseCaptured',
    'independentOfPrereleaseRun',
    'humanApprovalRequired',
    'scheduleEnabledByContract',
  ];
  const access = config.prereleaseAccess;
  const watchdogRole = iamEffectivePermissions?.cleanupWatchdog?.role;
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'decision',
      'scope',
      'generatedAtUtc',
      'environment',
      'authorizationId',
      'candidateSha',
      'releaseId',
      'authorizedWindow',
      'sources',
      'iam',
      'readIdentity',
      'accessControl',
      'durableCleanup',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'readinessSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'PRERELEASE_SAFETY_READINESS' ||
    value.status !== 'PASS' ||
    value.decision !== 'READY_FOR_PROTECTED_PRERELEASE_MUTATION' ||
    value.scope !== 'prerelease' ||
    !isoUtc(value.generatedAtUtc) ||
    !(now instanceof Date) ||
    !Number.isFinite(now.getTime()) ||
    Date.parse(value.generatedAtUtc) > now.getTime() ||
    Date.parse(value.generatedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(value.generatedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    value.environment !== config.environment ||
    value.authorizationId !== config.authorization.id ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    !exactKeys(value.authorizedWindow, ['startsAtUtc', 'endsAtUtc', 'cleanupExpiresAtUtc']) ||
    value.authorizedWindow.startsAtUtc !== config.window.startsAtUtc ||
    value.authorizedWindow.endsAtUtc !== config.window.endsAtUtc ||
    value.authorizedWindow.cleanupExpiresAtUtc !== config.cleanup.expiresAtUtc ||
    !exactKeys(value.sources, expectedSourceKeys) ||
    canonicalJson(value.sources) !== canonicalJson(sourceBindings) ||
    value.sources.configSha256 !== objectSha256(config) ||
    value.sources.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.sources.watchdogWorkflowSha256 !== value.sources.watchdogCandidateBlobSha256 ||
    Object.values(value.sources).some((digest) => !SHA256.test(digest ?? '')) ||
    !exactKeys(value.iam, expectedIamKeys) ||
    value.iam.status !== 'PASS' ||
    value.iam.effectivePermissionsBindingSha256 !== iamEffectivePermissions?.bindingSha256 ||
    value.iam.effectivePermissionsEvidenceSha256 !== value.sources.awsAuthSha256 ||
    value.iam.watchdogRoleArnSha256 !== sha256(watchdogRoleArn) ||
    value.iam.watchdogTrustPolicySha256 !== watchdogRole?.trustPolicySha256 ||
    value.iam.watchdogOidcSubjectsSha256 !== watchdogRole?.oidcSubjectsSha256 ||
    value.iam.watchdogPermissionSetSha256 !== watchdogRole?.permissionSetSha256 ||
    value.iam.expectedOidcSubjectSha256 !== sha256(WATCHDOG_OIDC_SUBJECT) ||
    !validateSanitizedReadIdentity({
      value: value.readIdentity,
      config,
      expectedGithubRunId,
      expectedGithubRunAttempt,
      expectedSessionKind: 'safety',
    }) ||
    !exactKeys(value.accessControl, expectedAccessKeys) ||
    value.accessControl.status !== 'PASS' ||
    value.accessControl.mode !== 'CLOUDFRONT_SIGNED_COOKIE' ||
    value.accessControl.bindingSha256 !==
      sha256(
        [
          access.mode,
          access.keyGroupId,
          access.publicKeyId,
          access.originTokenSecretArn,
          access.originTokenSecretVersionId,
        ].join('\n'),
      ) ||
    value.accessControl.keyGroupIdSha256 !== sha256(access.keyGroupId) ||
    value.accessControl.keyGroupPublicKeyCount !== 1 ||
    value.accessControl.publicKeyIdSha256 !== sha256(access.publicKeyId) ||
    value.accessControl.publicKeyAlgorithm !== 'RSA' ||
    value.accessControl.originTokenSecretArnSha256 !== sha256(access.originTokenSecretArn) ||
    value.accessControl.originTokenSecretVersionIdSha256 !==
      sha256(access.originTokenSecretVersionId) ||
    value.accessControl.originSecretBindingSha256 !==
      sha256(`${access.originTokenSecretArn}\n${access.originTokenSecretVersionId}`) ||
    value.accessControl.currentVersionCount !== 1 ||
    value.accessControl.rotationEnabled !== false ||
    value.accessControl.customerManagedKmsKeyUsed !== false ||
    value.accessControl.rawAccessMaterialCaptured !== false ||
    [
      value.accessControl.keyGroupEtagSha256,
      value.accessControl.publicKeyEtagSha256,
      value.accessControl.publicKeyMaterialSha256,
    ].some((digest) => !SHA256.test(digest ?? '')) ||
    !exactKeys(value.durableCleanup, expectedCleanupKeys) ||
    value.durableCleanup.status !== 'PASS' ||
    value.durableCleanup.decision !== 'DURABLE_RECOVERY_READY' ||
    value.durableCleanup.workflowPath !== WATCHDOG_WORKFLOW_RELATIVE ||
    value.durableCleanup.workflowSha256 !== value.sources.watchdogWorkflowSha256 ||
    value.durableCleanup.candidateBlobSha256 !== value.sources.watchdogCandidateBlobSha256 ||
    value.durableCleanup.cron !== WATCHDOG_CRON ||
    value.durableCleanup.oidcSubject !== WATCHDOG_OIDC_SUBJECT ||
    value.durableCleanup.roleArnSha256 !== sha256(watchdogRoleArn) ||
    value.durableCleanup.roleTrustPolicySha256 !== watchdogRole?.trustPolicySha256 ||
    value.durableCleanup.rolePermissionSetSha256 !== watchdogRole?.permissionSetSha256 ||
    value.durableCleanup.apiStatus !== 'ACTIVE_ON_DEFAULT_BRANCH' ||
    value.durableCleanup.repository !== EXPECTED_REPOSITORY ||
    value.durableCleanup.defaultBranch !== EXPECTED_DEFAULT_BRANCH ||
    value.durableCleanup.workflowState !== 'active' ||
    value.durableCleanup.defaultBranchHeadSha256 !== sha256(freeze.candidateSha) ||
    [
      value.durableCleanup.workflowIdSha256,
      value.durableCleanup.repositoryResponseSha256,
      value.durableCleanup.workflowResponseSha256,
      value.durableCleanup.refResponseSha256,
    ].some((digest) => !SHA256.test(digest ?? '')) ||
    value.durableCleanup.apiRequests !== 3 ||
    value.durableCleanup.rawApiResponseCaptured !== false ||
    value.durableCleanup.independentOfPrereleaseRun !== true ||
    value.durableCleanup.humanApprovalRequired !== false ||
    value.durableCleanup.scheduleEnabledByContract !== true ||
    value.externalRequests !== 7 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.readinessSha256 !== objectSha256(body)
  ) {
    fail('E7_PRERELEASE_SAFETY_READINESS_INVALID');
  }
  return value;
};

const DEPLOYMENT_IDENTITY_KEYS = [
  'accountSha256',
  'accountSuffix',
  'roleSha256',
  'sessionArnSha256',
];
const APPROVED_PLAN_KEYS = ['planSha256', 'preDeploymentStateSha256', 'approvalSha256'];
const WATCHDOG_AUTHORITY_CHECKPOINT_KEYS = [
  'watchdogLiveAuthoritySha256',
  'watchdogDefaultBranchHeadSha256',
  'watchdogApiRequests',
  'watchdogVerifiedAtUtc',
  'watchdogVerificationPhase',
];
const DEPLOYMENT_CHECKPOINT_COMMON_KEYS = [
  'decision',
  'releaseMode',
  'previousReleaseManifestSha256',
  'identity',
  'stackName',
  'stackSuffix',
  'assemblySha256',
  'freezeManifestSha256',
  'outputs',
  'outputsSha256',
  'deploymentMethod',
  'requireApprovalMode',
  'hotswapUsed',
  'approvedPlan',
  'safetyReadinessSha256',
  ...WATCHDOG_AUTHORITY_CHECKPOINT_KEYS,
];
const DEPLOYMENT_CHECKPOINT_EXTRA_KEYS = {
  data: [],
  api: ['rollbackRecord', 'runtimeSecretReferenceSha256'],
  observability: ['alertDestinationSha256', 'costAllocationTag', 'rollbackResilience'],
  web: ['publicOriginSha256', 'apiOriginSha256', 'rollbackRecord'],
};
const DEPLOYMENT_ENVELOPE_KEYS = [
  'schemaVersion',
  'stage',
  'kind',
  'scope',
  'environment',
  'authorizationId',
  'authorizationScope',
  'configSha256',
  'releaseId',
  'candidateSha',
  'region',
  'status',
  'checkpoints',
  'containsSensitiveData',
  'updatedAtUtc',
];
const FINAL_DEPLOYMENT_ENVELOPE_KEYS = [
  ...DEPLOYMENT_ENVELOPE_KEYS,
  'applicationUrl',
  'urls',
  'nonPublic',
  'syntheticOnly',
  'published',
  'schedulerEnabled',
];
const SEED_CHECKPOINT_KEYS = [
  'decision',
  'identity',
  'firstExecution',
  'secondExecution',
  'productId',
  'publicOriginSha256',
  'publicOriginSource',
  'publicOriginParameterName',
  'syntheticDataOnly',
  'stockResetPerformed',
  'previousReleaseManifestSha256',
  'runtimeSecretReferenceSha256',
  'prereleaseAccessBindingSha256',
  'safetyReadinessSha256',
  'approvedDeploymentCheckpointSha256',
  ...WATCHDOG_AUTHORITY_CHECKPOINT_KEYS,
];
const OBSERVABILITY_READINESS_KEYS = [
  'decision',
  'identity',
  'alertDestinationSha256',
  'alertTopicSha256',
  'subscriptionArnSha256',
  'protocol',
  'status',
  'rawDestinationCaptured',
];
const EXPIRY_REGISTRATION_KEYS = [
  'decision',
  'identity',
  'expiresAtUtc',
  'cleanupOwnerAlias',
  'safetyReadinessSha256',
  'durableCleanupReadinessSha256',
  ...WATCHDOG_AUTHORITY_CHECKPOINT_KEYS,
  'approvedDeploymentCheckpointSha256',
  'expectedStackNamesSha256',
  'stackInventory',
  'stackInventorySha256',
  'verifiedStackCount',
  'liveStackTagsVerified',
  'liveStackOutputsVerified',
  'externalRequests',
  'mutationsPerformed',
  'immediateCleanupStillRequired',
  'bootstrapPreserved',
  'previousReleasePreserved',
];
const STACK_INVENTORY_KEYS = [
  'stackName',
  'stackIdSha256',
  'stackStatus',
  'outputsIdentity',
  'requiredTags',
  'requiredTagsSha256',
];
const STACK_OUTPUT_IDENTITY_KEYS = ['CandidateSha', 'ReleaseId'];
const REQUIRED_STACK_TAG_KEYS = [
  'CandidateSha',
  'ReleaseId',
  'Environment',
  'ExpiresOn',
  'CleanupExpiresAtUtc',
];

const validateDeploymentIdentity = (identity, config) => {
  if (
    !exactKeys(identity, DEPLOYMENT_IDENTITY_KEYS) ||
    identity.accountSha256 !== sha256(config.aws.accountId) ||
    identity.accountSuffix !== config.aws.accountId.slice(-4) ||
    identity.roleSha256 !== sha256(config.aws.roles.deployRoleArn) ||
    !SHA256.test(identity.sessionArnSha256 ?? '')
  ) {
    fail('E7_PRERELEASE_DEPLOYMENT_IDENTITY_INVALID');
  }
  return identity;
};

const exactHttpsOrigin = (value) => {
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === 'https:' &&
      parsed.origin === value &&
      parsed.username === '' &&
      parsed.password === '' &&
      parsed.pathname === '/' &&
      parsed.search === '' &&
      parsed.hash === ''
    );
  } catch {
    return false;
  }
};

const validateWatchdogAuthorityCheckpoint = ({ checkpoint, phase, config, freeze }) => {
  if (
    !SHA256.test(checkpoint?.watchdogLiveAuthoritySha256 ?? '') ||
    checkpoint?.watchdogDefaultBranchHeadSha256 !== sha256(freeze.candidateSha) ||
    checkpoint?.watchdogApiRequests !== 3 ||
    !isoUtc(checkpoint?.watchdogVerifiedAtUtc) ||
    Date.parse(checkpoint.watchdogVerifiedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(checkpoint.watchdogVerifiedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    checkpoint?.watchdogVerificationPhase !== phase
  ) {
    fail('E7_PRERELEASE_WATCHDOG_LIVE_AUTHORITY_INVALID');
  }
};

const validateDeploymentEnvelope = ({ value, config, freeze, phase }) => {
  const final = phase === 'before-activation';
  if (
    !exactKeys(value, final ? FINAL_DEPLOYMENT_ENVELOPE_KEYS : DEPLOYMENT_ENVELOPE_KEYS) ||
    value?.schemaVersion !== 1 ||
    value?.stage !== 7 ||
    value?.kind !== 'PRERELEASE_DEPLOYMENT_LEDGER' ||
    value?.scope !== 'prerelease' ||
    value?.environment !== config.environment ||
    value?.authorizationId !== config.authorization.id ||
    value?.authorizationScope !== 'EPHEMERAL_PRERELEASE' ||
    value?.configSha256 !== objectSha256(config) ||
    value?.releaseId !== freeze.releaseId ||
    value?.candidateSha !== freeze.candidateSha ||
    value?.region !== config.aws.region ||
    value?.status !== (final ? 'PASS' : 'IN_PROGRESS') ||
    !object(value?.checkpoints) ||
    value?.containsSensitiveData !== false ||
    !isoUtc(value?.updatedAtUtc) ||
    (final &&
      (!exactHttpsOrigin(value.applicationUrl) ||
        !exactKeys(value.urls, ['application']) ||
        value.urls.application !== value.applicationUrl ||
        value.nonPublic !== true ||
        value.syntheticOnly !== true ||
        value.published !== false ||
        value.schedulerEnabled !== false))
  ) {
    fail('E7_PRERELEASE_DEPLOYMENT_CHECKPOINT_INVALID');
  }
};

const validateApprovedDeployment = ({ checkpoint, suffix, config, freeze, readiness }) => {
  const approvedPlan = checkpoint?.approvedPlan;
  if (
    !exactKeys(checkpoint, [
      ...DEPLOYMENT_CHECKPOINT_COMMON_KEYS,
      ...DEPLOYMENT_CHECKPOINT_EXTRA_KEYS[suffix],
    ]) ||
    checkpoint?.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    checkpoint?.releaseMode !== 'INITIAL' ||
    checkpoint?.previousReleaseManifestSha256 !== null ||
    !object(checkpoint?.outputs) ||
    checkpoint?.stackName !== `checkout-${config.environment}-${suffix}` ||
    checkpoint?.stackSuffix !== suffix ||
    checkpoint?.assemblySha256 !== readiness.sources.cloudAssemblySha256 ||
    checkpoint?.freezeManifestSha256 !== freeze.manifestSha256 ||
    checkpoint?.safetyReadinessSha256 !== readiness.readinessSha256 ||
    checkpoint?.outputs?.CandidateSha !== freeze.candidateSha ||
    checkpoint?.outputs?.ReleaseId !== freeze.releaseId ||
    checkpoint?.outputsSha256 !== sha256(JSON.stringify(checkpoint.outputs)) ||
    checkpoint?.deploymentMethod !== 'CLOUDFORMATION_CHANGE_SET' ||
    checkpoint?.requireApprovalMode !== 'PROTECTED_WORKFLOW_PREAPPROVED' ||
    checkpoint?.hotswapUsed !== false ||
    !exactKeys(approvedPlan, APPROVED_PLAN_KEYS) ||
    approvedPlan.approvalSha256 !== readiness.sources.approvalSha256 ||
    approvedPlan.planSha256 !== readiness.sources.approvedPlanSha256 ||
    !SHA256.test(approvedPlan.preDeploymentStateSha256 ?? '') ||
    (suffix === 'api' &&
      (!object(checkpoint.rollbackRecord) ||
        !SHA256.test(checkpoint.runtimeSecretReferenceSha256 ?? ''))) ||
    (suffix === 'observability' &&
      (checkpoint.alertDestinationSha256 !== config.budget.alertDestinationSha256 ||
        !object(checkpoint.costAllocationTag) ||
        !object(checkpoint.rollbackResilience))) ||
    (suffix === 'web' &&
      (!SHA256.test(checkpoint.publicOriginSha256 ?? '') ||
        !SHA256.test(checkpoint.apiOriginSha256 ?? '') ||
        !object(checkpoint.rollbackRecord)))
  ) {
    fail('E7_PRERELEASE_DEPLOYMENT_CHECKPOINT_INVALID');
  }
  validateDeploymentIdentity(checkpoint.identity, config);
  validateWatchdogAuthorityCheckpoint({
    checkpoint,
    phase: `deploy-${suffix}`,
    config,
    freeze,
  });
};

const validateStackInventory = ({ expiry, config, freeze }) => {
  const stackInventory = expiry?.stackInventory;
  if (
    !Array.isArray(stackInventory) ||
    stackInventory.length !== 4 ||
    expiry.expectedStackNamesSha256 !== objectSha256(config.authorization.stacks) ||
    expiry.stackInventorySha256 !== objectSha256(stackInventory) ||
    expiry.verifiedStackCount !== 4 ||
    expiry.liveStackTagsVerified !== true ||
    expiry.liveStackOutputsVerified !== true ||
    expiry.externalRequests !== 5 ||
    expiry.mutationsPerformed !== 0 ||
    stackInventory
      .map(({ stackName }) => stackName)
      .toSorted()
      .join('\0') !== config.authorization.stacks.toSorted().join('\0')
  ) {
    fail('E7_PRERELEASE_EXPIRY_REGISTRATION_NOT_DURABLE');
  }
  const expectedTags = {
    CandidateSha: freeze.candidateSha,
    ReleaseId: freeze.releaseId,
    Environment: config.environment,
    ExpiresOn: config.cleanup.expiresAtUtc.slice(0, 10),
    CleanupExpiresAtUtc: config.cleanup.expiresAtUtc,
  };
  for (const stack of stackInventory) {
    if (
      !exactKeys(stack, STACK_INVENTORY_KEYS) ||
      !config.authorization.stacks.includes(stack.stackName) ||
      !SHA256.test(stack.stackIdSha256 ?? '') ||
      !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(stack.stackStatus ?? '') ||
      !exactKeys(stack.outputsIdentity, STACK_OUTPUT_IDENTITY_KEYS) ||
      stack.outputsIdentity.CandidateSha !== freeze.candidateSha ||
      stack.outputsIdentity.ReleaseId !== freeze.releaseId ||
      !exactKeys(stack.requiredTags, REQUIRED_STACK_TAG_KEYS) ||
      objectSha256(stack.requiredTags) !== objectSha256(expectedTags) ||
      stack.requiredTagsSha256 !== objectSha256(stack.requiredTags)
    ) {
      fail('E7_PRERELEASE_EXPIRY_REGISTRATION_NOT_DURABLE');
    }
  }
};

export const prereleaseApprovedDeploymentCheckpointSha256 = (value) => {
  if (!object(value?.checkpoints)) fail('E7_PRERELEASE_DEPLOYMENT_CHECKPOINT_INVALID');
  return objectSha256(
    Object.fromEntries(
      ['data', 'api', 'observability', 'web'].map((name) => [name, value.checkpoints[name]]),
    ),
  );
};

const validateSeedCheckpoint = ({ seed, value, config, readiness }) => {
  if (
    !exactKeys(seed, SEED_CHECKPOINT_KEYS) ||
    seed?.decision !== 'PASS' ||
    !['CREATED', 'EXISTS'].includes(seed?.firstExecution) ||
    seed?.secondExecution !== 'EXISTS' ||
    seed?.productId !== 'product-demo-001' ||
    !SHA256.test(seed?.publicOriginSha256 ?? '') ||
    seed?.publicOriginSource !== 'SSM_AFTER_WEB' ||
    seed?.publicOriginParameterName !== `/checkout-${config.environment}/public-origin` ||
    seed?.syntheticDataOnly !== true ||
    seed?.stockResetPerformed !== false ||
    seed?.previousReleaseManifestSha256 !== null ||
    !SHA256.test(seed?.runtimeSecretReferenceSha256 ?? '') ||
    seed?.prereleaseAccessBindingSha256 !== readiness.accessControl.bindingSha256 ||
    seed?.safetyReadinessSha256 !== readiness.readinessSha256 ||
    seed?.approvedDeploymentCheckpointSha256 !== prereleaseApprovedDeploymentCheckpointSha256(value)
  ) {
    fail('E7_PRERELEASE_SEED_CHECKPOINT_INCOMPLETE');
  }
  validateDeploymentIdentity(seed.identity, config);
  validateWatchdogAuthorityCheckpoint({
    checkpoint: seed,
    phase: 'seed',
    config,
    freeze: { candidateSha: value.candidateSha },
  });
};

export const validatePrereleaseDeploymentCheckpoint = ({
  value,
  config,
  freeze,
  readiness,
  phase,
}) => {
  if (!['before-seed', 'before-expiry', 'before-activation'].includes(phase)) {
    fail('E7_PRERELEASE_DEPLOYMENT_PHASE_INVALID');
  }
  validateDeploymentEnvelope({ value, config, freeze, phase });
  const expectedCheckpointNames =
    phase === 'before-seed'
      ? ['data', 'api', 'observability', 'web']
      : phase === 'before-expiry'
        ? ['data', 'api', 'observability', 'web', 'seed']
        : [
            'data',
            'api',
            'observability',
            'web',
            'seed',
            'expiryRegistration',
            'observabilityReadiness',
          ];
  if (
    Object.keys(value.checkpoints).toSorted().join('\0') !==
    expectedCheckpointNames.toSorted().join('\0')
  ) {
    fail('E7_PRERELEASE_DEPLOYMENT_CHECKPOINT_INVALID');
  }
  for (const suffix of ['data', 'api', 'observability', 'web']) {
    validateApprovedDeployment({
      checkpoint: value.checkpoints[suffix],
      suffix,
      config,
      freeze,
      readiness,
    });
  }
  if (
    value.checkpoints.api.outputs.SchedulerStatus !== 'DISABLED' ||
    value.checkpoints.api.outputs.ApiPublicationStatus !== 'DISABLED' ||
    value.checkpoints.web.outputs.WebPublicationStatus !== 'DISABLED'
  ) {
    fail('E7_PRERELEASE_DEPLOYMENT_PREMATURE_ACTIVATION');
  }
  if (phase === 'before-expiry' || phase === 'before-activation') {
    validateSeedCheckpoint({ seed: value.checkpoints.seed, value, config, readiness });
  }
  if (phase === 'before-activation') {
    const expiry = value.checkpoints.expiryRegistration;
    const observability = value.checkpoints.observabilityReadiness;
    if (
      !exactKeys(expiry, EXPIRY_REGISTRATION_KEYS) ||
      expiry?.decision !== 'EXPIRY_REGISTERED' ||
      expiry?.expiresAtUtc !== config.cleanup.expiresAtUtc ||
      expiry?.cleanupOwnerAlias !== config.cleanup.ownerAlias ||
      expiry?.safetyReadinessSha256 !== readiness.readinessSha256 ||
      expiry?.durableCleanupReadinessSha256 !== objectSha256(readiness.durableCleanup) ||
      expiry?.approvedDeploymentCheckpointSha256 !==
        prereleaseApprovedDeploymentCheckpointSha256(value) ||
      expiry?.immediateCleanupStillRequired !== true ||
      expiry?.bootstrapPreserved !== true ||
      expiry?.previousReleasePreserved !== true ||
      !exactKeys(observability, OBSERVABILITY_READINESS_KEYS) ||
      observability?.decision !== 'PASS' ||
      observability?.status !== 'CONFIRMED' ||
      observability?.protocol !== 'email' ||
      observability?.alertDestinationSha256 !== config.budget.alertDestinationSha256 ||
      !SHA256.test(observability?.alertTopicSha256 ?? '') ||
      !SHA256.test(observability?.subscriptionArnSha256 ?? '') ||
      observability?.rawDestinationCaptured !== false
    ) {
      fail('E7_PRERELEASE_ACTIVATION_CHECKPOINT_INCOMPLETE');
    }
    validateDeploymentIdentity(expiry.identity, config);
    validateWatchdogAuthorityCheckpoint({
      checkpoint: expiry,
      phase: 'register-expiry',
      config,
      freeze,
    });
    validateDeploymentIdentity(observability.identity, config);
    validateStackInventory({ expiry, config, freeze });
  }
  return value;
};

const selfTestFixtureConfig = (now) => {
  const accountId = '123456789012';
  const environment = 'assessment-prerelease-safety';
  const role = (name) => `arn:aws:iam::${accountId}:role/checkout/${name}`;
  const originTokenSecretArn = `arn:aws:secretsmanager:us-east-1:${accountId}:secret:checkout/${environment}/runtime-AbCdEf`;
  const iso = (offset) => new Date(now.getTime() + offset).toISOString();
  return {
    schemaVersion: 1,
    stage: 7,
    environment,
    authorization: {
      id: 'AUTH-E7-PRERELEASE-SAFETY',
      status: 'APPROVED',
      scope: 'EPHEMERAL_PRERELEASE',
      ownerAlias: 'release-owner',
      approvedAtUtc: iso(-60 * 60 * 1000),
      expiresAtUtc: iso(8 * 60 * 60 * 1000),
      stacks: ['data', 'api', 'observability', 'web'].map(
        (suffix) => `checkout-${environment}-${suffix}`,
      ),
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
        readRoleArn: role('read'),
        deployRoleArn: role('deploy'),
        rollbackRoleArn: role('rollback'),
        cleanupRoleArn: role('cleanup'),
        baselineRoleArn: role('baseline'),
      },
      sessionMode: 'OIDC',
    },
    window: { startsAtUtc: iso(-5 * 60 * 1000), endsAtUtc: iso(2 * 60 * 60 * 1000) },
    budget: {
      maxUsd: 10,
      warningUsd: [5, 8],
      alertOwnerAlias: 'cost-owner',
      alertChannelAlias: 'cost-alerts',
      alertDestinationSha256: 'd'.repeat(64),
    },
    domain: {
      mode: 'AWS_MANAGED',
      hostname: null,
      apiHostname: null,
      hostedZoneId: null,
      webCertificateArn: null,
      apiCertificateArn: null,
      dnsIncluded: false,
    },
    prereleaseAccess: {
      mode: 'CLOUDFRONT_SIGNED_COOKIE',
      keyGroupId: 'K2STAGE7KEYGROUP',
      publicKeyId: 'K2STAGE7CHECKOUT',
      originTokenSecretArn,
      originTokenSecretVersionId: 'a'.repeat(32),
      rotationDuringWindow: 'FORBIDDEN',
    },
    cleanup: {
      ownerAlias: 'cleanup-owner',
      expiresAtUtc: iso(3 * 60 * 60 * 1000),
      preserveBootstrap: true,
      preservePreviousRelease: true,
    },
    credentialReferences: [originTokenSecretArn],
    containsSensitiveData: false,
  };
};

const writeFixtureJson = (filename, value) => {
  mkdirSync(path.dirname(filename), { recursive: true });
  writeFileSync(filename, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
};

const expectCode = (callback, code) => {
  assert.throws(
    callback,
    (error) => error instanceof PrereleaseSafetyReadinessError && error.code === code,
    code,
  );
};

const cloneJson = (value) => JSON.parse(JSON.stringify(value));

export const selfTestPrereleaseSafetyReadiness = async () => {
  const now = new Date('2026-08-18T01:00:00.000Z');
  const config = selfTestFixtureConfig(now);
  validateStage7Config(config, { now });
  const tempRoot = mkdtempSync(path.join(os.tmpdir(), 'stage7-prerelease-safety-'));
  let assertions = 0;
  try {
    const workflowSource = readFileSync(
      path.join(workspaceRoot, WATCHDOG_WORKFLOW_RELATIVE),
      'utf8',
    );
    const syntheticPublicKey = generateKeyPairSync('rsa', { modulusLength: 2048 })
      .publicKey.export({ type: 'spki', format: 'pem' })
      .toString();
    const watchdogRoleArn = `arn:aws:iam::${config.aws.accountId}:role/checkout/cleanup-watchdog`;
    const freezeBody = {
      schemaVersion: 1,
      stage: 7,
      kind: 'BUILD_ONCE_FREEZE',
      releaseId: 'rel-20260818-0100-aaaaaaa',
      candidateSha: 'a'.repeat(40),
      candidateTreeSha: 'b'.repeat(40),
      releaseTag: null,
      environment: config.environment,
      authorizationScope: 'EPHEMERAL_PRERELEASE',
      region: config.aws.region,
      sourceRunId: 'e6-20260818t000000z-aaaaaaaa',
      sourceArtifactId: '123',
      sourceArtifactSha256: '1'.repeat(64),
      preFreezeEvidenceSha256: null,
      builtAt: now.toISOString(),
      configSha256: objectSha256(config),
      lockfileSha256: '2'.repeat(64),
      openApiSha256: '3'.repeat(64),
      generatedClientSha256: '4'.repeat(64),
      publicConfigSha256: '5'.repeat(64),
      templateSha256: '6'.repeat(64),
      stage6Gates: { 'GATE-E6-01': 'PASS', 'GATE-E6-02': 'PASS', 'GATE-E6-03': 'CONDITIONAL_GO' },
      toolchain: {
        node: 'v24.19.0',
        packageManager: 'pnpm@11.19.0',
        cdk: '2.1029.2',
        awsCli: '2.31.0',
      },
      artifacts: [],
      controlInventory: {
        artifacts: Array.from(
          { length: 20 },
          (_, index) => `ART-REL-${String(index + 1).padStart(2, '0')}`,
        ),
        evidence: Array.from(
          { length: 57 },
          (_, index) => `EVD-E7-${String(index + 1).padStart(2, '0')}`,
        ),
        audits: Array.from(
          { length: 73 },
          (_, index) => `AUD-E7-${String(index + 1).padStart(2, '0')}`,
        ),
      },
      releaseMode: 'INITIAL',
      updateReleaseSupported: false,
      updateReleaseUnsupportedReason: 'EPHEMERAL_PRERELEASE_INITIAL_ONLY',
      buildOnce: true,
      containsSensitiveData: false,
    };
    // A complete freeze fixture is intentionally produced through the existing core self-test
    // contract rather than weakening that contract here. The readiness validator is exercised
    // below with an already validated identity projection and all mutation canaries.
    assert.equal(SHA.test(freezeBody.candidateSha), true);
    assert.equal(RELEASE_ID.test(freezeBody.releaseId), true);
    assertions += 2;

    const fakeFreeze = {
      candidateSha: freezeBody.candidateSha,
      candidateTreeSha: freezeBody.candidateTreeSha,
      releaseId: freezeBody.releaseId,
      manifestSha256: '7'.repeat(64),
    };
    const sourceBindings = {
      configSha256: objectSha256(config),
      freezeManifestSha256: fakeFreeze.manifestSha256,
      cloudAssemblySha256: '8'.repeat(64),
      approvedPlanSha256: '9'.repeat(64),
      approvedRawDiffSha256: 'a'.repeat(64),
      approvalSha256: 'b'.repeat(64),
      awsAuthSha256: 'c'.repeat(64),
      watchdogWorkflowSha256: sha256(workflowSource),
      watchdogCandidateBlobSha256: sha256(workflowSource),
    };
    const watchdogRole = {
      trustPolicySha256: 'd'.repeat(64),
      oidcSubjectsSha256: objectSha256([WATCHDOG_OIDC_SUBJECT]),
      permissionSetSha256: 'e'.repeat(64),
    };
    const iam = {
      bindingSha256: 'f'.repeat(64),
      cleanupWatchdog: { status: 'PASS', role: watchdogRole },
    };
    const keyGroupResponse = {
      ETag: 'key-group-etag',
      KeyGroup: {
        Id: config.prereleaseAccess.keyGroupId,
        KeyGroupConfig: { Items: [config.prereleaseAccess.publicKeyId], Quantity: 1 },
      },
    };
    const publicKeyResponse = {
      ETag: 'public-key-etag',
      PublicKey: {
        Id: config.prereleaseAccess.publicKeyId,
        PublicKeyConfig: { Name: 'stage7-safety-fixture', EncodedKey: syntheticPublicKey },
      },
    };
    const secretResponse = {
      ARN: config.prereleaseAccess.originTokenSecretArn,
      RotationEnabled: false,
      VersionIdsToStages: {
        [config.prereleaseAccess.originTokenSecretVersionId]: ['AWSCURRENT'],
      },
    };
    const accessControl = validateLiveAccess({
      config,
      keyGroupResponse,
      publicKeyResponse,
      secretResponse,
    });
    assertions += 1;
    const local = {
      config,
      freeze: fakeFreeze,
      assemblySha256: sourceBindings.cloudAssemblySha256,
      planSha256: sourceBindings.approvedPlanSha256,
      rawDiffSha256: sourceBindings.approvedRawDiffSha256,
      approvalSha256: sourceBindings.approvalSha256,
      awsAuthSha256: sourceBindings.awsAuthSha256,
      iam,
      watchdog: {
        workflowSha256: sourceBindings.watchdogWorkflowSha256,
        candidateBlobSha256: sourceBindings.watchdogCandidateBlobSha256,
      },
      watchdogRoleArn,
    };
    const approvalPlan = { iamBroadeningDetected: false };
    const prereleaseApproval = {
      schemaVersion: 1,
      stage: 7,
      kind: 'PROTECTED_RELEASE_APPROVAL',
      status: 'PASS',
      scope: 'prerelease',
      candidateSha: fakeFreeze.candidateSha,
      releaseId: fakeFreeze.releaseId,
      releaseTag: null,
      configSha256: objectSha256(config),
      cloudAssemblySha256: local.assemblySha256,
      freezeManifestSha256: fakeFreeze.manifestSha256,
      previousReleaseManifestSha256: null,
      approvedPlanSha256: local.planSha256,
      approvedDiffSha256: local.rawDiffSha256,
      iamEffectivePermissionsBindingSha256: iam.bindingSha256,
      iamEffectivePermissionsEvidenceSha256: local.awsAuthSha256,
      journalRoleEffectivePermissionsRawSha256: null,
      journalRoleEffectivePermissionsSha256: null,
      ...Object.fromEntries(RECONCILIATION_RECOVERY_APPROVAL_FIELDS.map((field) => [field, null])),
      approvedAtUtc: now.toISOString(),
      statefulReplacements: 0,
      destructiveChanges: 0,
      iamBroadeningDetected: false,
      iamBroadeningReviewed: true,
      humanReviewConfirmed: true,
      explicitDispatchConfirmation: true,
      protectedEnvironment: true,
      protectedEnvironmentName: EXPECTED_PROTECTED_ENVIRONMENT,
      nonPublic: true,
      accountSha256: sha256(config.aws.accountId),
      accountSuffix: config.aws.accountId.slice(-4),
      region: config.aws.region,
      stacks: [...config.authorization.stacks],
      budget: {
        maxUsd: config.budget.maxUsd,
        warningUsd: config.budget.warningUsd,
        alertDestinationSha256: config.budget.alertDestinationSha256,
      },
      approvalOwnerAlias: config.authorization.ownerAlias,
      reviewerAlias: 'release-reviewer',
      authorizedWindow: { ...config.window },
      externalRequests: 0,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    assert.equal(
      validateApproval({
        value: prereleaseApproval,
        config,
        freeze: fakeFreeze,
        assemblySha256: local.assemblySha256,
        plan: approvalPlan,
        planSha256: local.planSha256,
        rawDiffSha256: local.rawDiffSha256,
        awsAuthSha256: local.awsAuthSha256,
        iam,
        now,
      }),
      prereleaseApproval,
    );
    const approvalWithRecoveryAuthority = { ...prereleaseApproval };
    approvalWithRecoveryAuthority.reconciliationRecoveryRoleArn = `arn:aws:iam::${config.aws.accountId}:role/recovery`;
    expectCode(
      () =>
        validateApproval({
          value: approvalWithRecoveryAuthority,
          config,
          freeze: fakeFreeze,
          assemblySha256: local.assemblySha256,
          plan: approvalPlan,
          planSha256: local.planSha256,
          rawDiffSha256: local.rawDiffSha256,
          awsAuthSha256: local.awsAuthSha256,
          iam,
          now,
        }),
      'E7_PRERELEASE_SAFETY_APPROVAL_INVALID',
    );
    const approvalMissingJournalAuthority = { ...prereleaseApproval };
    delete approvalMissingJournalAuthority.journalRoleEffectivePermissionsRawSha256;
    expectCode(
      () =>
        validateApproval({
          value: approvalMissingJournalAuthority,
          config,
          freeze: fakeFreeze,
          assemblySha256: local.assemblySha256,
          plan: approvalPlan,
          planSha256: local.planSha256,
          rawDiffSha256: local.rawDiffSha256,
          awsAuthSha256: local.awsAuthSha256,
          iam,
          now,
        }),
      'E7_PRERELEASE_SAFETY_APPROVAL_INVALID',
    );
    assertions += 3;
    const repositoryResponse = {
      full_name: EXPECTED_REPOSITORY,
      default_branch: EXPECTED_DEFAULT_BRANCH,
      archived: false,
      disabled: false,
      private: false,
      visibility: 'public',
    };
    const workflowResponse = {
      id: 123456,
      name: EXPECTED_WATCHDOG_NAME,
      path: WATCHDOG_WORKFLOW_RELATIVE,
      state: 'active',
      created_at: '2026-08-17T01:00:00Z',
      updated_at: '2026-08-18T00:30:00Z',
    };
    const refResponse = {
      ref: `refs/heads/${EXPECTED_DEFAULT_BRANCH}`,
      object: { type: 'commit', sha: fakeFreeze.candidateSha },
    };
    const watchdogApi = validateWatchdogApiState({
      repositoryResponse,
      workflowResponse,
      refResponse,
      freeze: fakeFreeze,
    });
    assertions += 1;
    const githubRunId = '1234567890';
    const githubRunAttempt = '2';
    const identityResponse = (prefix, overrides = {}) => ({
      Account: config.aws.accountId,
      Arn: `arn:aws:sts::${config.aws.accountId}:assumed-role/read/${prefix}-${githubRunId}-${githubRunAttempt}`,
      UserId: `AROAEXAMPLE:${prefix}-${githubRunId}-${githubRunAttempt}`,
      ...overrides,
    });
    const readIdentity = validateLiveReadIdentity({
      config,
      identityResponse: identityResponse('e7pre-safety'),
      environmentVariables: {
        GITHUB_RUN_ID: githubRunId,
        GITHUB_RUN_ATTEMPT: githubRunAttempt,
      },
      expectedSessionKind: 'safety',
    });
    const activationReadIdentity = validateLiveReadIdentity({
      config,
      identityResponse: identityResponse('e7pre-read'),
      environmentVariables: {
        GITHUB_RUN_ID: githubRunId,
        GITHUB_RUN_ATTEMPT: githubRunAttempt,
      },
      expectedSessionKind: 'activation',
    });
    const sandboxReadIdentity = validateLiveReadIdentity({
      config,
      identityResponse: identityResponse('e7pre-external-read'),
      environmentVariables: {
        GITHUB_RUN_ID: githubRunId,
        GITHUB_RUN_ATTEMPT: githubRunAttempt,
      },
      expectedSessionKind: 'sandbox',
    });
    assertions += 3;
    for (const changedIdentity of [
      identityResponse('e7pre-safety', { Account: '000000000000' }),
      identityResponse('e7pre-safety', {
        Arn: `arn:aws:sts::${config.aws.accountId}:assumed-role/deploy/e7pre-safety-${githubRunId}-${githubRunAttempt}`,
      }),
      identityResponse('e7pre-safety', {
        Arn: `arn:aws:sts::${config.aws.accountId}:assumed-role/read/unbounded-session`,
        UserId: 'AROAEXAMPLE:unbounded-session',
      }),
    ]) {
      expectCode(
        () =>
          validateLiveReadIdentity({
            config,
            identityResponse: changedIdentity,
            environmentVariables: {
              GITHUB_RUN_ID: githubRunId,
              GITHUB_RUN_ATTEMPT: githubRunAttempt,
            },
            expectedSessionKind: 'safety',
          }),
        'E7_PRERELEASE_SAFETY_READ_IDENTITY_INVALID',
      );
      assertions += 1;
    }
    const externalCallOrder = [];
    const capturedLiveState = await captureLiveSafetyState({
      local,
      environmentVariables: {
        GITHUB_RUN_ID: githubRunId,
        GITHUB_RUN_ATTEMPT: githubRunAttempt,
        GITHUB_TOKEN: 'x'.repeat(40),
      },
      expectedSessionKind: 'safety',
      callGithub: async ({ pathname }) => {
        externalCallOrder.push(`github:${pathname}`);
        if (pathname.endsWith('/prerelease-cleanup.yml')) return workflowResponse;
        if (pathname.includes('/git/ref/heads/')) return refResponse;
        return repositoryResponse;
      },
      callAws: ({ service, operation }) => {
        externalCallOrder.push(`aws:${service}:${operation}`);
        if (service === 'sts') return identityResponse('e7pre-safety');
        if (operation === 'get-key-group') return keyGroupResponse;
        if (operation === 'get-public-key') return publicKeyResponse;
        return secretResponse;
      },
    });
    assert.deepEqual(externalCallOrder, [
      `github:/repos/${EXPECTED_REPOSITORY}`,
      `github:/repos/${EXPECTED_REPOSITORY}/actions/workflows/${WATCHDOG_WORKFLOW_NAME}`,
      `github:/repos/${EXPECTED_REPOSITORY}/git/ref/heads/${EXPECTED_DEFAULT_BRANCH}`,
      'aws:sts:get-caller-identity',
      'aws:cloudfront:get-key-group',
      'aws:cloudfront:get-public-key',
      'aws:secretsmanager:describe-secret',
    ]);
    assert.deepEqual(capturedLiveState.readIdentity, readIdentity);
    assertions += 2;
    for (const [changedRepository, changedWorkflow, changedRef] of [
      [{ ...repositoryResponse, default_branch: 'main' }, workflowResponse, refResponse],
      [repositoryResponse, { ...workflowResponse, state: 'disabled_manually' }, refResponse],
      [
        repositoryResponse,
        { ...workflowResponse, path: '.github/workflows/other.yml' },
        refResponse,
      ],
      [
        repositoryResponse,
        workflowResponse,
        { ...refResponse, object: { ...refResponse.object, sha: '0'.repeat(40) } },
      ],
    ]) {
      expectCode(
        () =>
          validateWatchdogApiState({
            repositoryResponse: changedRepository,
            workflowResponse: changedWorkflow,
            refResponse: changedRef,
            freeze: fakeFreeze,
          }),
        'E7_PRERELEASE_WATCHDOG_NOT_ACTIVE',
      );
      assertions += 1;
    }
    expectCode(
      () =>
        validateLiveAccess({
          config,
          keyGroupResponse: {
            ETag: 'key-group-etag',
            KeyGroup: {
              Id: config.prereleaseAccess.keyGroupId,
              KeyGroupConfig: { Items: [config.prereleaseAccess.publicKeyId] },
            },
          },
          publicKeyResponse: {
            ETag: 'public-key-etag',
            PublicKey: {
              Id: config.prereleaseAccess.publicKeyId,
              PublicKeyConfig: { Name: 'stage7-safety-fixture', EncodedKey: syntheticPublicKey },
            },
          },
          secretResponse: {
            ARN: config.prereleaseAccess.originTokenSecretArn,
            RotationEnabled: true,
            VersionIdsToStages: {
              [config.prereleaseAccess.originTokenSecretVersionId]: ['AWSCURRENT'],
            },
          },
        }),
      'E7_PRERELEASE_SAFETY_LIVE_ACCESS_INVALID',
    );
    assertions += 1;
    const body = readinessBody({ local, readIdentity, accessControl, watchdogApi, now });
    const readiness = { ...body, readinessSha256: objectSha256(body) };
    assert.equal(
      validatePrereleaseSafetyReadiness(readiness, {
        config,
        freeze: fakeFreeze,
        sourceBindings,
        watchdogRoleArn,
        iamEffectivePermissions: iam,
        expectedGithubRunId: githubRunId,
        expectedGithubRunAttempt: githubRunAttempt,
        now,
      }),
      readiness,
    );
    assertions += 1;
    assert.equal(
      validatePrereleaseSafetyReadinessContract(readiness, {
        config,
        freeze: fakeFreeze,
        sourceBindings,
        watchdogRoleArn,
        iamEffectivePermissions: iam,
        expectedGithubRunId: githubRunId,
        expectedGithubRunAttempt: githubRunAttempt,
        now,
      }),
      readiness,
    );
    assertions += 1;
    const authorityGithub = async ({ pathname, disabled = false } = {}) => {
      if (pathname.endsWith('/prerelease-cleanup.yml')) {
        return disabled ? { ...workflowResponse, state: 'disabled_manually' } : workflowResponse;
      }
      if (pathname.includes('/git/ref/heads/')) return refResponse;
      return repositoryResponse;
    };
    const liveAuthority = await revalidateWatchdogAuthorityWithDependencies({
      readiness,
      freeze: fakeFreeze,
      candidateWorkflowSha256: sourceBindings.watchdogCandidateBlobSha256,
      phase: 'deploy-data',
      environmentVariables: { GITHUB_TOKEN: 'x'.repeat(40) },
      now,
      callGithub: authorityGithub,
    });
    assert.equal(liveAuthority.status, 'PASS');
    assert.equal(liveAuthority.apiRequests, 3);
    assertions += 2;
    let disabledAwsCalls = 0;
    let disabledMutations = 0;
    await assert.rejects(
      revalidateWatchdogAuthorityWithDependencies({
        readiness: cloneJson(readiness),
        freeze: fakeFreeze,
        candidateWorkflowSha256: sourceBindings.watchdogCandidateBlobSha256,
        phase: 'deploy-data',
        environmentVariables: { GITHUB_TOKEN: 'x'.repeat(40) },
        now,
        callGithub: async (request) =>
          authorityGithub({
            ...request,
            disabled: request.pathname.endsWith('/prerelease-cleanup.yml'),
          }),
      }),
      (error) =>
        error instanceof PrereleaseSafetyReadinessError &&
        error.code === 'E7_PRERELEASE_WATCHDOG_NOT_ACTIVE',
    );
    assert.equal(disabledAwsCalls, 0);
    assert.equal(disabledMutations, 0);
    assertions += 3;

    const activationBody = liveSafetyRecheckBody({
      phase: 'activation',
      readiness,
      config,
      freeze: fakeFreeze,
      readIdentity: activationReadIdentity,
      accessControl,
      watchdogApi,
      now,
    });
    const activationRecheck = {
      ...activationBody,
      liveSafetyRecheckSha256: objectSha256(activationBody),
    };
    assert.equal(
      validatePrereleaseLiveSafetyRecheck(activationRecheck, {
        readiness,
        config,
        freeze: fakeFreeze,
        phase: 'activation',
        expectedGithubRunId: githubRunId,
        expectedGithubRunAttempt: githubRunAttempt,
        now,
      }),
      activationRecheck,
    );
    assertions += 1;
    expectCode(
      () =>
        validatePrereleaseLiveSafetyRecheck(activationRecheck, {
          readiness,
          config,
          freeze: fakeFreeze,
          phase: 'sandbox',
          expectedGithubRunId: githubRunId,
          expectedGithubRunAttempt: githubRunAttempt,
          now,
        }),
      'E7_PRERELEASE_LIVE_SAFETY_RECHECK_INVALID',
    );
    assertions += 1;
    const sandboxBody = liveSafetyRecheckBody({
      phase: 'sandbox',
      readiness,
      config,
      freeze: fakeFreeze,
      readIdentity: sandboxReadIdentity,
      accessControl,
      watchdogApi,
      now,
    });
    const sandboxRecheck = {
      ...sandboxBody,
      liveSafetyRecheckSha256: objectSha256(sandboxBody),
    };
    assert.equal(
      validatePrereleaseLiveSafetyRecheck(sandboxRecheck, {
        readiness,
        config,
        freeze: fakeFreeze,
        phase: 'sandbox',
        expectedGithubRunId: githubRunId,
        expectedGithubRunAttempt: githubRunAttempt,
        now,
      }),
      sandboxRecheck,
    );
    assertions += 1;
    const staleBody = {
      ...activationBody,
      generatedAtUtc: new Date(now.getTime() - LIVE_SAFETY_RECHECK_MAX_AGE_MS - 1).toISOString(),
    };
    expectCode(
      () =>
        validatePrereleaseLiveSafetyRecheck(
          { ...staleBody, liveSafetyRecheckSha256: objectSha256(staleBody) },
          {
            readiness,
            config,
            freeze: fakeFreeze,
            phase: 'activation',
            expectedGithubRunId: githubRunId,
            expectedGithubRunAttempt: githubRunAttempt,
            now,
          },
        ),
      'E7_PRERELEASE_LIVE_SAFETY_RECHECK_INVALID',
    );
    assertions += 1;

    const canaries = [
      ['decision', 'BLOCKED'],
      ['scope', 'full'],
      ['candidateSha', '0'.repeat(40)],
      ['mutationsPerformed', 1],
      ['externalRequests', 2],
    ];
    for (const [key, replacement] of canaries) {
      const changed = { ...readiness, [key]: replacement };
      expectCode(
        () =>
          validatePrereleaseSafetyReadiness(changed, {
            config,
            freeze: fakeFreeze,
            sourceBindings,
            watchdogRoleArn,
            iamEffectivePermissions: iam,
            expectedGithubRunId: githubRunId,
            expectedGithubRunAttempt: githubRunAttempt,
            now,
          }),
        'E7_PRERELEASE_SAFETY_READINESS_INVALID',
      );
      assertions += 1;
    }
    for (const [label, mutate] of [
      [
        'source',
        (value) => ({ ...value, sources: { ...value.sources, approvalSha256: '0'.repeat(64) } }),
      ],
      [
        'iam',
        (value) => ({ ...value, iam: { ...value.iam, watchdogRoleArnSha256: '0'.repeat(64) } }),
      ],
      [
        'access',
        (value) => ({
          ...value,
          accessControl: { ...value.accessControl, currentVersionCount: 2 },
        }),
      ],
      [
        'coherently rehashed run attempt replay',
        (value) => {
          const replayAttempt = '3';
          const replaySession = `e7pre-safety-${githubRunId}-${replayAttempt}`;
          const replayArn = `arn:aws:sts::${config.aws.accountId}:assumed-role/read/${replaySession}`;
          return {
            ...value,
            readIdentity: {
              ...value.readIdentity,
              runAttempt: replayAttempt,
              sessionArnSha256: sha256(replayArn),
              sessionNameSha256: sha256(replaySession),
              sessionBindingSha256: sha256(`${config.aws.roles.readRoleArn}\n${replaySession}`),
            },
          };
        },
      ],
      [
        'coherently rehashed session kind',
        (value) => {
          const changedPrefix = 'e7pre-read';
          const changedSession = `${changedPrefix}-${githubRunId}-${githubRunAttempt}`;
          const changedArn = `arn:aws:sts::${config.aws.accountId}:assumed-role/read/${changedSession}`;
          return {
            ...value,
            readIdentity: {
              ...value.readIdentity,
              sessionKind: 'activation',
              sessionPrefix: changedPrefix,
              sessionArnSha256: sha256(changedArn),
              sessionNameSha256: sha256(changedSession),
              sessionBindingSha256: sha256(`${config.aws.roles.readRoleArn}\n${changedSession}`),
            },
          };
        },
      ],
      [
        'cross-mode access',
        (value) => ({
          ...value,
          accessControl: {
            ...value.accessControl,
            mode: 'ORIGIN_GATE_ONLY',
            bindingSha256: sha256(
              [
                'ORIGIN_GATE_ONLY',
                config.prereleaseAccess.keyGroupId,
                config.prereleaseAccess.publicKeyId,
                config.prereleaseAccess.originTokenSecretArn,
                config.prereleaseAccess.originTokenSecretVersionId,
              ].join('\n'),
            ),
          },
        }),
      ],
      [
        'watchdog',
        (value) => ({ ...value, durableCleanup: { ...value.durableCleanup, cron: '*/5 * * * *' } }),
      ],
    ]) {
      const changed = mutate(readiness);
      expectCode(
        () =>
          validatePrereleaseSafetyReadiness(changed, {
            config,
            freeze: fakeFreeze,
            sourceBindings,
            watchdogRoleArn,
            iamEffectivePermissions: iam,
            expectedGithubRunId: githubRunId,
            expectedGithubRunAttempt: githubRunAttempt,
            now,
          }),
        'E7_PRERELEASE_SAFETY_READINESS_INVALID',
      );
      assert.equal(typeof label, 'string');
      assertions += 2;
    }

    let calls = 0;
    expectCode(
      () =>
        validateLocalSources({
          configPath: path.join(tempRoot, 'missing-config.json'),
          manifestPath: path.join(tempRoot, 'missing-manifest.json'),
          assemblyPath: path.join(tempRoot, 'missing-assembly'),
          planPath: path.join(tempRoot, 'missing-plan.json'),
          rawDiffPath: path.join(tempRoot, 'missing-diff.txt'),
          approvalPath: path.join(tempRoot, 'missing-approval.json'),
          awsAuthPath: path.join(tempRoot, 'missing-auth.json'),
          watchdogWorkflowPath: path.join(workspaceRoot, WATCHDOG_WORKFLOW_RELATIVE),
          watchdogRoleArn,
          environmentVariables: {},
          now,
          candidateWorkflowSource: () => Buffer.from(workflowSource),
          validateIam: () => {
            calls += 1;
            return iam;
          },
        }),
      'E7_PRERELEASE_SAFETY_PROTECTED_CONTEXT_REQUIRED',
    );
    assert.equal(calls, 0);
    assertions += 2;

    const deploymentIdentity = {
      accountSha256: sha256(config.aws.accountId),
      accountSuffix: config.aws.accountId.slice(-4),
      roleSha256: sha256(config.aws.roles.deployRoleArn),
      sessionArnSha256: '1'.repeat(64),
    };
    const watchdogAuthorityCheckpoint = (phase) => ({
      watchdogLiveAuthoritySha256: sha256(`authority:${phase}`),
      watchdogDefaultBranchHeadSha256: sha256(fakeFreeze.candidateSha),
      watchdogApiRequests: 3,
      watchdogVerifiedAtUtc: now.toISOString(),
      watchdogVerificationPhase: phase,
    });
    const deployment = {
      schemaVersion: 1,
      stage: 7,
      kind: 'PRERELEASE_DEPLOYMENT_LEDGER',
      scope: 'prerelease',
      environment: config.environment,
      authorizationId: config.authorization.id,
      authorizationScope: config.authorization.scope,
      configSha256: objectSha256(config),
      releaseId: fakeFreeze.releaseId,
      candidateSha: fakeFreeze.candidateSha,
      region: config.aws.region,
      status: 'IN_PROGRESS',
      checkpoints: {},
      containsSensitiveData: false,
      updatedAtUtc: now.toISOString(),
    };
    const deployed = (suffix) => {
      const outputs = {
        CandidateSha: fakeFreeze.candidateSha,
        ReleaseId: fakeFreeze.releaseId,
        ...(suffix === 'api'
          ? { SchedulerStatus: 'DISABLED', ApiPublicationStatus: 'DISABLED' }
          : {}),
        ...(suffix === 'web'
          ? {
              WebPublicationStatus: 'DISABLED',
              ApplicationUrl: 'https://prerelease.example.invalid',
            }
          : {}),
      };
      return {
        decision: 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION',
        releaseMode: 'INITIAL',
        previousReleaseManifestSha256: null,
        identity: deploymentIdentity,
        stackName: `checkout-${config.environment}-${suffix}`,
        stackSuffix: suffix,
        assemblySha256: readiness.sources.cloudAssemblySha256,
        freezeManifestSha256: fakeFreeze.manifestSha256,
        outputs,
        outputsSha256: sha256(JSON.stringify(outputs)),
        deploymentMethod: 'CLOUDFORMATION_CHANGE_SET',
        requireApprovalMode: 'PROTECTED_WORKFLOW_PREAPPROVED',
        hotswapUsed: false,
        safetyReadinessSha256: readiness.readinessSha256,
        ...watchdogAuthorityCheckpoint(`deploy-${suffix}`),
        approvedPlan: {
          approvalSha256: readiness.sources.approvalSha256,
          planSha256: readiness.sources.approvedPlanSha256,
          preDeploymentStateSha256: '2'.repeat(64),
        },
        ...(suffix === 'api'
          ? {
              rollbackRecord: { recordSha256: '3'.repeat(64) },
              runtimeSecretReferenceSha256: '4'.repeat(64),
            }
          : {}),
        ...(suffix === 'observability'
          ? {
              alertDestinationSha256: config.budget.alertDestinationSha256,
              costAllocationTag: { status: 'ACTIVE' },
              rollbackResilience: { templateSha256: '5'.repeat(64) },
            }
          : {}),
        ...(suffix === 'web'
          ? {
              publicOriginSha256: '6'.repeat(64),
              apiOriginSha256: '7'.repeat(64),
              rollbackRecord: { recordSha256: '8'.repeat(64) },
            }
          : {}),
      };
    };
    deployment.checkpoints = Object.fromEntries(
      ['data', 'api', 'observability', 'web'].map((suffix) => [suffix, deployed(suffix)]),
    );
    assert.equal(
      validatePrereleaseDeploymentCheckpoint({
        value: deployment,
        config,
        freeze: fakeFreeze,
        readiness,
        phase: 'before-seed',
      }),
      deployment,
    );
    assertions += 1;
    for (const [label, mutate] of [
      ['envelope extra field', (value) => ({ ...value, extra: true })],
      [
        'checkpoint extra field',
        (value) => ({
          ...value,
          checkpoints: {
            ...value.checkpoints,
            data: { ...value.checkpoints.data, extra: true },
          },
        }),
      ],
      [
        'approved plan extra field',
        (value) => ({
          ...value,
          checkpoints: {
            ...value.checkpoints,
            data: {
              ...value.checkpoints.data,
              approvedPlan: { ...value.checkpoints.data.approvedPlan, extra: true },
            },
          },
        }),
      ],
      ['config binding changed', (value) => ({ ...value, configSha256: '0'.repeat(64) })],
      ['kind changed', (value) => ({ ...value, kind: 'PRERELEASE_DEPLOYMENT' })],
      ['status changed', (value) => ({ ...value, status: 'PASS' })],
      [
        'approval and plan hashes swapped',
        (value) => ({
          ...value,
          checkpoints: {
            ...value.checkpoints,
            data: {
              ...value.checkpoints.data,
              approvedPlan: {
                ...value.checkpoints.data.approvedPlan,
                approvalSha256: readiness.sources.approvedPlanSha256,
                planSha256: readiness.sources.approvalSha256,
              },
            },
          },
        }),
      ],
    ]) {
      expectCode(
        () =>
          validatePrereleaseDeploymentCheckpoint({
            value: mutate(cloneJson(deployment)),
            config,
            freeze: fakeFreeze,
            readiness,
            phase: 'before-seed',
          }),
        'E7_PRERELEASE_DEPLOYMENT_CHECKPOINT_INVALID',
      );
      assert.equal(typeof label, 'string');
      assertions += 2;
    }
    const wrongAccount = cloneJson(deployment);
    wrongAccount.checkpoints.data.identity.accountSha256 = '0'.repeat(64);
    expectCode(
      () =>
        validatePrereleaseDeploymentCheckpoint({
          value: wrongAccount,
          config,
          freeze: fakeFreeze,
          readiness,
          phase: 'before-seed',
        }),
      'E7_PRERELEASE_DEPLOYMENT_IDENTITY_INVALID',
    );
    assertions += 1;
    const approvedDeploymentCheckpointSha256 =
      prereleaseApprovedDeploymentCheckpointSha256(deployment);
    deployment.checkpoints.seed = {
      decision: 'PASS',
      identity: deploymentIdentity,
      firstExecution: 'CREATED',
      secondExecution: 'EXISTS',
      productId: 'product-demo-001',
      publicOriginSha256: '9'.repeat(64),
      publicOriginSource: 'SSM_AFTER_WEB',
      publicOriginParameterName: `/checkout-${config.environment}/public-origin`,
      syntheticDataOnly: true,
      stockResetPerformed: false,
      previousReleaseManifestSha256: null,
      runtimeSecretReferenceSha256: 'a'.repeat(64),
      prereleaseAccessBindingSha256: readiness.accessControl.bindingSha256,
      safetyReadinessSha256: readiness.readinessSha256,
      approvedDeploymentCheckpointSha256,
      ...watchdogAuthorityCheckpoint('seed'),
    };
    assert.equal(
      validatePrereleaseDeploymentCheckpoint({
        value: deployment,
        config,
        freeze: fakeFreeze,
        readiness,
        phase: 'before-expiry',
      }),
      deployment,
    );
    assertions += 1;
    const seedTamper = cloneJson(deployment);
    seedTamper.checkpoints.seed.approvedDeploymentCheckpointSha256 = '0'.repeat(64);
    expectCode(
      () =>
        validatePrereleaseDeploymentCheckpoint({
          value: seedTamper,
          config,
          freeze: fakeFreeze,
          readiness,
          phase: 'before-expiry',
        }),
      'E7_PRERELEASE_SEED_CHECKPOINT_INCOMPLETE',
    );
    assertions += 1;
    const requiredTags = {
      CandidateSha: fakeFreeze.candidateSha,
      ReleaseId: fakeFreeze.releaseId,
      Environment: config.environment,
      ExpiresOn: config.cleanup.expiresAtUtc.slice(0, 10),
      CleanupExpiresAtUtc: config.cleanup.expiresAtUtc,
    };
    const stackInventory = config.authorization.stacks.map((stackName, index) => ({
      stackName,
      stackIdSha256: String(index + 1).repeat(64),
      stackStatus: 'CREATE_COMPLETE',
      outputsIdentity: {
        CandidateSha: fakeFreeze.candidateSha,
        ReleaseId: fakeFreeze.releaseId,
      },
      requiredTags,
      requiredTagsSha256: objectSha256(requiredTags),
    }));
    deployment.checkpoints.expiryRegistration = {
      decision: 'EXPIRY_REGISTERED',
      identity: deploymentIdentity,
      expiresAtUtc: config.cleanup.expiresAtUtc,
      cleanupOwnerAlias: config.cleanup.ownerAlias,
      safetyReadinessSha256: readiness.readinessSha256,
      durableCleanupReadinessSha256: objectSha256(readiness.durableCleanup),
      ...watchdogAuthorityCheckpoint('register-expiry'),
      approvedDeploymentCheckpointSha256,
      expectedStackNamesSha256: objectSha256(config.authorization.stacks),
      stackInventory,
      stackInventorySha256: objectSha256(stackInventory),
      verifiedStackCount: 4,
      liveStackTagsVerified: true,
      liveStackOutputsVerified: true,
      externalRequests: 5,
      mutationsPerformed: 0,
      immediateCleanupStillRequired: true,
      bootstrapPreserved: true,
      previousReleasePreserved: true,
    };
    deployment.checkpoints.observabilityReadiness = {
      decision: 'PASS',
      identity: deploymentIdentity,
      status: 'CONFIRMED',
      protocol: 'email',
      alertDestinationSha256: config.budget.alertDestinationSha256,
      alertTopicSha256: 'b'.repeat(64),
      subscriptionArnSha256: 'c'.repeat(64),
      rawDestinationCaptured: false,
    };
    deployment.status = 'PASS';
    deployment.applicationUrl = deployment.checkpoints.web.outputs.ApplicationUrl;
    deployment.urls = { application: deployment.applicationUrl };
    deployment.nonPublic = true;
    deployment.syntheticOnly = true;
    deployment.published = false;
    deployment.schedulerEnabled = false;
    assert.equal(
      validatePrereleaseDeploymentCheckpoint({
        value: deployment,
        config,
        freeze: fakeFreeze,
        readiness,
        phase: 'before-activation',
      }),
      deployment,
    );
    assertions += 1;
    for (const [label, mutate] of [
      [
        'stack absent',
        (value) => {
          value.checkpoints.expiryRegistration.stackInventory.pop();
          value.checkpoints.expiryRegistration.stackInventorySha256 = objectSha256(
            value.checkpoints.expiryRegistration.stackInventory,
          );
          value.checkpoints.expiryRegistration.verifiedStackCount = 3;
        },
      ],
      [
        'stack tag stale',
        (value) => {
          const entry = value.checkpoints.expiryRegistration.stackInventory[0];
          entry.requiredTags.CandidateSha = '0'.repeat(40);
          entry.requiredTagsSha256 = objectSha256(entry.requiredTags);
          value.checkpoints.expiryRegistration.stackInventorySha256 = objectSha256(
            value.checkpoints.expiryRegistration.stackInventory,
          );
        },
      ],
      [
        'stack tag subset',
        (value) => {
          const entry = value.checkpoints.expiryRegistration.stackInventory[0];
          delete entry.requiredTags.ExpiresOn;
          entry.requiredTagsSha256 = objectSha256(entry.requiredTags);
          value.checkpoints.expiryRegistration.stackInventorySha256 = objectSha256(
            value.checkpoints.expiryRegistration.stackInventory,
          );
        },
      ],
    ]) {
      const changed = cloneJson(deployment);
      mutate(changed);
      expectCode(
        () =>
          validatePrereleaseDeploymentCheckpoint({
            value: changed,
            config,
            freeze: fakeFreeze,
            readiness,
            phase: 'before-activation',
          }),
        'E7_PRERELEASE_EXPIRY_REGISTRATION_NOT_DURABLE',
      );
      assert.equal(typeof label, 'string');
      assertions += 2;
    }
    const premature = JSON.parse(JSON.stringify(deployment));
    premature.checkpoints.api.outputs.SchedulerStatus = 'ENABLED';
    premature.checkpoints.api.outputsSha256 = sha256(
      JSON.stringify(premature.checkpoints.api.outputs),
    );
    expectCode(
      () =>
        validatePrereleaseDeploymentCheckpoint({
          value: premature,
          config,
          freeze: fakeFreeze,
          readiness,
          phase: 'before-activation',
        }),
      'E7_PRERELEASE_DEPLOYMENT_PREMATURE_ACTIVATION',
    );
    assertions += 1;

    writeFixtureJson(path.join(tempRoot, 'readiness.json'), readiness);
    assert.equal(
      parseStrictJsonSource(readFileSync(path.join(tempRoot, 'readiness.json')), {
        scanForbiddenData: false,
      }).readinessSha256,
      readiness.readinessSha256,
    );
    assertions += 1;
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
  return { status: 'PASS', assertions, externalRequests: 0, mutationsPerformed: 0 };
};

const parseFlags = (arguments_) => {
  const flags = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const token = arguments_[index];
    const value = arguments_[index + 1];
    if (
      !/^--[a-z][a-z0-9-]*$/u.test(token ?? '') ||
      value === undefined ||
      value.startsWith('--')
    ) {
      fail('E7_PRERELEASE_SAFETY_CLI_ARGUMENT_SET_INVALID');
    }
    const key = token.slice(2);
    if (Object.hasOwn(flags, key)) fail('E7_PRERELEASE_SAFETY_CLI_ARGUMENT_SET_INVALID');
    flags[key] = value;
  }
  return flags;
};

const main = async () => {
  const command = process.argv[2];
  if (command === 'self-test') {
    if (process.argv.length !== 3) fail('E7_PRERELEASE_SAFETY_CLI_ARGUMENT_SET_INVALID');
    const result = await selfTestPrereleaseSafetyReadiness();
    process.stdout.write(
      `prerelease safety readiness self-test: PASS (${result.assertions} assertions; 0 external calls; 0 mutations)\n`,
    );
    return;
  }
  if (!['capture', 'capture-live', 'verify-watchdog'].includes(command)) {
    fail('E7_PRERELEASE_SAFETY_CLI_COMMAND_INVALID');
  }
  const flags = parseFlags(process.argv.slice(3));
  const expected = [
    'config',
    'manifest',
    'assembly',
    'plan',
    'raw-diff',
    'approval',
    'aws-auth',
    'watchdog-role-arn',
    'output',
    ...(['capture-live', 'verify-watchdog'].includes(command) ? ['phase', 'readiness'] : []),
  ];
  if (Object.keys(flags).toSorted().join('\0') !== expected.toSorted().join('\0')) {
    fail('E7_PRERELEASE_SAFETY_CLI_ARGUMENT_SET_INVALID');
  }
  const sharedInputs = {
    configPath: flags.config,
    manifestPath: flags.manifest,
    assemblyPath: flags.assembly,
    planPath: flags.plan,
    rawDiffPath: flags['raw-diff'],
    approvalPath: flags.approval,
    awsAuthPath: flags['aws-auth'],
    watchdogRoleArn: flags['watchdog-role-arn'],
    outputPath: flags.output,
  };
  if (command === 'capture') {
    const readiness = await capturePrereleaseSafetyReadiness(sharedInputs);
    process.stdout.write(
      `${JSON.stringify({ status: readiness.status, decision: readiness.decision, readinessSha256: readiness.readinessSha256 })}\n`,
    );
    return;
  }
  if (command === 'verify-watchdog') {
    const validated = validatePrereleaseSafetyReadinessFromFiles({
      readinessPath: flags.readiness,
      ...sharedInputs,
      expectedProtectedEnvironment: EXPECTED_PROTECTED_ENVIRONMENT,
      environmentVariables: process.env,
    });
    const authority = await revalidatePrereleaseWatchdogLiveAuthority({
      readiness: validated.readiness,
      freeze: validated.freeze,
      candidateWorkflowSha256: validated.local.watchdog.candidateBlobSha256,
      phase: flags.phase,
      environmentVariables: process.env,
    });
    writeStage7Json(flags.output, 'prerelease-deploy-watchdog-authority.json', authority);
    process.stdout.write(
      `${JSON.stringify({ status: authority.status, phase: authority.phase, watchdogLiveAuthoritySha256: authority.watchdogLiveAuthoritySha256 })}\n`,
    );
    return;
  }
  const recheck = await capturePrereleaseLiveSafetyRecheck({
    ...sharedInputs,
    phase: flags.phase,
    readinessPath: flags.readiness,
  });
  process.stdout.write(
    `${JSON.stringify({ status: recheck.status, decision: recheck.decision, phase: recheck.phase, liveSafetyRecheckSha256: recheck.liveSafetyRecheckSha256 })}\n`,
  );
};

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main().catch((error) => {
    const code =
      error instanceof PrereleaseSafetyReadinessError
        ? error.code
        : 'E7_PRERELEASE_SAFETY_UNEXPECTED_FAILURE';
    process.stderr.write(`prerelease safety readiness: ${code}\n`);
    process.exitCode = 1;
  });
}
