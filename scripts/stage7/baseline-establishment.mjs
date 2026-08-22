#!/usr/bin/env node

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { execFileSync } from 'node:child_process';
import { createHash, createPublicKey } from 'node:crypto';
import {
  chmodSync,
  constants as fsConstants,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import process from 'node:process';

import {
  assertSanitizedArtifactText,
  scanArtifactText,
} from '../stage6/lib/artifact-sanitizer.mjs';
import {
  assertCloudFrontAccessMaterialExcluded,
  readCloudFrontSignedCookieFile,
} from './cloudfront-access.mjs';
import {
  CLOUDFRONT_KEY_GROUP_ID,
  CLOUDFRONT_PUBLIC_KEY_ID,
  assessStage6Manifest,
  createStage7PreviousReleaseManifest,
  currentCandidate,
  hashArtifactPath,
  objectSha256,
  readStrictJsonFile,
  STAGE7_ARTIFACTS,
  STAGE7_AUDITS,
  STAGE7_EVIDENCE,
  STAGE7_PROVIDER_EGRESS_CAPABILITY,
  validateFreezeManifest,
  validateStage7PreviousReleaseManifest,
  validateStage7PreviousReleaseHandoff,
  validateStage7Config,
  workspaceRoot,
} from './core.mjs';
import {
  createIamEffectivePermissionsSelfTestFixture,
  IAM_ROLE_PERMISSION_PROFILES,
  validateIamEffectivePermissionsEvidence,
} from './iam-effective-permissions.mjs';
import { validateStage6SourceProvenance } from './stage6-source-provenance.mjs';
import { validatePublicReleaseIdentity } from './public-release-identity.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-([0-9a-f]{7})$/u;
const BASELINE_VERSION = /^v0\.0\.0-rc\.[1-9][0-9]*$/u;
const STAGE6_RUN_ID = /^e6-[0-9]{8}t[0-9]{6}z-[0-9a-f]{8}$/u;
const AWS_REGION =
  /^(?:af|ap|ca|eu|il|me|mx|sa|us)-(?:central|east|north|northeast|northwest|south|southeast|southwest|west)-[1-9]$/u;
const ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/[A-Za-z0-9+=,.@_/-]{1,256}$/u;
const SECRET_ARN =
  /^arn:aws:secretsmanager:([a-z0-9-]+):([0-9]{12}):secret:[A-Za-z0-9/_+=.@-]{1,256}$/u;
const SECRET_VERSION_ID = /^[A-Za-z0-9-]{32,64}$/u;
const HOSTNAME = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u;
const STACK_SUFFIXES = ['data', 'api', 'observability', 'web'];
const ABORT_CRITERIA = [
  'ACCOUNT_MISMATCH',
  'REGION_MISMATCH',
  'SECRET_EXPOSURE',
  'PRODUCTION_PROVIDER',
  'STATEFUL_REPLACEMENT',
  'SMOKE_FAILURE',
  'ROLLBACK_FAILURE',
  'BUDGET_BREACH',
];
const BASELINE_EVIDENCE_FILENAMES = [
  'baseline-api-contract-evidence.json',
  'baseline-pending-evidence.json',
  'baseline-smoke-evidence.json',
  'baseline-traffic-ledger.json',
];
const BASELINE_CAPTURE_FILENAME = 'stage7-baseline-capture.json';
const BASELINE_BUNDLE_INDEX_FILENAME = 'stage7-previous-release-bundle.json';
const BASELINE_FINAL_DISABLE_FILENAME = 'baseline-final-disable.json';
const BASELINE_WORKFLOW_PATH = '.github/workflows/baseline.yml';
const BASELINE_PROVENANCE_FILENAMES = Object.freeze({
  config: 'baseline-config.json',
  freeze: 'baseline-freeze.json',
  stage6Source: 'baseline-stage6-source-provenance.json',
  awsPreflight: 'baseline-aws-preflight.json',
  iam: 'baseline-iam.json',
  rawDiff: 'baseline-infra-diff.txt',
  plan: 'baseline-plan.json',
  githubApproval: 'baseline-github-approval.json',
  approval: 'baseline-approval.json',
  deployment: 'baseline-deployment.json',
  seed: 'baseline-seed.json',
  notification: 'baseline-notification.json',
  activation: 'baseline-activation.json',
  disable: 'baseline-disable.json',
});
export const BASELINE_FILE_LAYOUT = Object.freeze({
  capture: BASELINE_CAPTURE_FILENAME,
  bundleIndex: BASELINE_BUNDLE_INDEX_FILENAME,
  finalDisable: BASELINE_FINAL_DISABLE_FILENAME,
  provenance: BASELINE_PROVENANCE_FILENAMES,
  evidence: Object.freeze([...BASELINE_EVIDENCE_FILENAMES]),
});
const BASELINE_REQUEST_LIMIT = 8;
const ROLLBACK_MUTABLE_WEB_KEYS = new Set(['index.html', 'public-config.json']);
const MAX_IMMUTABLE_WEB_FILES = 4_096;
const SELF_TEST_CAPTURE_TOKEN = Symbol('stage7-baseline-capture-self-test');
let commandExecutor = execFileSync;
let requestExecutor = (...arguments_) => fetch(...arguments_);
let activeBaselineSelfTestRoot = null;
export const BASELINE_DIRECT_AWS_ACTIONS = Object.freeze({
  readRoleArn: Object.freeze([
    'acm:DescribeCertificate',
    'cloudformation:DescribeStacks',
    'cloudformation:GetTemplate',
    'cloudfront:GetKeyGroup',
    'cloudfront:GetPublicKey',
    'lambda:GetAccountSettings',
    'route53:GetHostedZone',
    'route53:ListResourceRecordSets',
    'secretsmanager:DescribeSecret',
    'servicequotas:GetServiceQuota',
    'sts:GetCallerIdentity',
  ]),
  baselineRoleArn: Object.freeze([
    'cloudformation:DescribeStacks',
    'cloudformation:GetTemplate',
    'cloudformation:UpdateStack',
    'cloudfront:GetDistributionConfig',
    'dynamodb:TransactWriteItems',
    'lambda:GetAlias',
    'lambda:GetFunction',
    's3:GetBucketVersioning',
    's3:GetObjectVersion',
    's3:ListBucketVersions',
    'scheduler:GetSchedule',
    'sns:ListSubscriptionsByTopic',
    'sts:GetCallerIdentity',
  ]),
});

export const validateBaselineAwsCommandInventory = () => {
  for (const [roleKey, actions] of Object.entries(BASELINE_DIRECT_AWS_ACTIONS)) {
    const authorized = new Set(IAM_ROLE_PERMISSION_PROFILES[roleKey].actions);
    if (actions.some((action) => !authorized.has(action.toLowerCase()))) {
      fail('E7_BASELINE_IAM_COMMAND_INVENTORY_MISMATCH');
    }
  }
  const declaredBaseline = new Set(
    BASELINE_DIRECT_AWS_ACTIONS.baselineRoleArn.map((action) => action.toLowerCase()),
  );
  const effectiveBaseline = IAM_ROLE_PERMISSION_PROFILES.baselineRoleArn.actions.filter(
    (action) => action !== 'sts:assumerole',
  );
  if (
    effectiveBaseline.length !== declaredBaseline.size ||
    effectiveBaseline.some((action) => !declaredBaseline.has(action))
  ) {
    fail('E7_BASELINE_IAM_COMMAND_INVENTORY_MISMATCH');
  }
  return BASELINE_DIRECT_AWS_ACTIONS;
};

export class Stage7BaselineError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7BaselineError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7BaselineError(code);
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const fileSha256 = (filename) => sha256(readFileSync(filename));
const isoUtc = (value) => {
  if (typeof value !== 'string') return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
};
const safeAlias = (value) =>
  typeof value === 'string' && /^[a-z0-9](?:[a-z0-9._-]{0,62}[a-z0-9])?$/u.test(value);
const expectedStacks = () =>
  STACK_SUFFIXES.map((suffix) => `checkout-assessment-release-${suffix}`);
const accessBindingSha256 = (config) =>
  sha256(
    [
      config.prereleaseAccess.mode,
      config.prereleaseAccess.keyGroupId ?? 'NONE',
      config.prereleaseAccess.publicKeyId ?? 'NONE',
      config.prereleaseAccess.originTokenSecretArn,
      config.prereleaseAccess.originTokenSecretVersionId,
    ].join('\n'),
  );

const checkedPath = (candidate, { mustExist = true, directory = false } = {}) => {
  if (typeof candidate !== 'string' || candidate.length === 0) fail('E7_BASELINE_PATH_INVALID');
  const absolute = path.resolve(candidate);
  const within = (root) => {
    const relative = path.relative(root, absolute);
    return !(
      relative === '..' ||
      relative.startsWith(`..${path.sep}`) ||
      path.isAbsolute(relative)
    );
  };
  const root = within(workspaceRoot)
    ? workspaceRoot
    : activeBaselineSelfTestRoot !== null && within(activeBaselineSelfTestRoot)
      ? activeBaselineSelfTestRoot
      : null;
  if (root === null) {
    fail('E7_BASELINE_PATH_OUTSIDE_WORKSPACE');
  }
  const relative = path.relative(root, absolute);
  let current = root;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) break;
    if (lstatSync(current).isSymbolicLink()) fail('E7_BASELINE_SYMLINK_FORBIDDEN');
  }
  if (mustExist) {
    const stat = lstatSync(absolute);
    if (directory ? !stat.isDirectory() : !stat.isFile()) fail('E7_BASELINE_PATH_INVALID');
  }
  return absolute;
};

const validateImmutableWebInventory = (value) => {
  if (
    !exactKeys(value, ['files', 'totalFiles', 'totalBytes', 'digestSha256']) ||
    !Array.isArray(value.files) ||
    value.files.length < 1 ||
    value.files.length > MAX_IMMUTABLE_WEB_FILES ||
    value.totalFiles !== value.files.length ||
    !Number.isSafeInteger(value.totalBytes) ||
    value.totalBytes < 1 ||
    value.digestSha256 !== objectSha256(value.files)
  ) {
    fail('E7_BASELINE_IMMUTABLE_WEB_INVENTORY_INVALID');
  }
  let previousPath = '';
  let totalBytes = 0;
  for (const file of value.files) {
    if (
      !exactKeys(file, ['path', 'bytes', 'sha256']) ||
      typeof file.path !== 'string' ||
      file.path.length === 0 ||
      file.path.includes('\\') ||
      path.posix.isAbsolute(file.path) ||
      file.path
        .split('/')
        .some((segment) => segment === '' || segment === '.' || segment === '..') ||
      ROLLBACK_MUTABLE_WEB_KEYS.has(file.path) ||
      file.path <= previousPath ||
      !Number.isSafeInteger(file.bytes) ||
      file.bytes < 0 ||
      !SHA256.test(file.sha256 ?? '')
    ) {
      fail('E7_BASELINE_IMMUTABLE_WEB_INVENTORY_INVALID');
    }
    previousPath = file.path;
    totalBytes += file.bytes;
  }
  if (totalBytes !== value.totalBytes) fail('E7_BASELINE_IMMUTABLE_WEB_INVENTORY_INVALID');
  return value;
};

const immutableWebInventory = (directory) => {
  const root = checkedPath(directory, { directory: true });
  const files = [];
  const visit = (current, prefix = '') => {
    for (const entry of readdirSync(current, { withFileTypes: true }).toSorted((left, right) =>
      left.name.localeCompare(right.name),
    )) {
      const relative = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      const absolute = path.join(current, entry.name);
      if (entry.isSymbolicLink()) fail('E7_BASELINE_SYMLINK_FORBIDDEN');
      if (entry.isDirectory()) {
        visit(absolute, relative);
      } else if (entry.isFile()) {
        if (!ROLLBACK_MUTABLE_WEB_KEYS.has(relative)) {
          const stat = lstatSync(absolute);
          files.push({ path: relative, bytes: stat.size, sha256: fileSha256(absolute) });
          if (files.length > MAX_IMMUTABLE_WEB_FILES) {
            fail('E7_BASELINE_IMMUTABLE_WEB_INVENTORY_INVALID');
          }
        }
      } else {
        fail('E7_BASELINE_PATH_INVALID');
      }
    }
  };
  visit(root);
  const body = {
    files,
    totalFiles: files.length,
    totalBytes: files.reduce((total, file) => total + file.bytes, 0),
  };
  return validateImmutableWebInventory({ ...body, digestSha256: objectSha256(files) });
};

const readJson = (filename) =>
  readStrictJsonFile(checkedPath(filename), { scanForbiddenData: false, validateConfig: false });

const writeJson = (filename, value, label) => {
  const target = checkedPath(filename, { mustExist: false });
  const source = `${JSON.stringify(value, null, 2)}\n`;
  assertSanitizedArtifactText(label, source);
  mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const temporary = `${target}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, source, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, target);
    chmodSync(target, 0o600);
  } finally {
    rmSync(temporary, { force: true });
  }
};

const roleMatchesAccount = (value, accountId) => ROLE_ARN.exec(value ?? '')?.[1] === accountId;

export const validateBaselineConfig = (value, { now = new Date(), phase = 'ACTIVE' } = {}) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'environment',
      'authorization',
      'aws',
      'window',
      'budget',
      'traffic',
      'domain',
      'prereleaseAccess',
      'cleanup',
      'credentialReferences',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.environment !== 'assessment-release' ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_BASELINE_CONFIG_ENVELOPE_INVALID');
  }
  const authorization = value.authorization;
  if (
    !exactKeys(authorization, [
      'id',
      'status',
      'scope',
      'ownerAlias',
      'approvedAtUtc',
      'expiresAtUtc',
      'stacks',
      'sandboxIncluded',
      'destructiveActionsAllowed',
      'communicationChannelAlias',
      'abortCriteria',
      'rollbackOwnerAlias',
    ]) ||
    !/^AUTH-E7-BASELINE-[A-Z0-9-]{1,24}$/u.test(authorization?.id ?? '') ||
    authorization.status !== 'APPROVED' ||
    authorization.scope !== 'FULL_RELEASE_BASELINE_CLOSED' ||
    !safeAlias(authorization.ownerAlias) ||
    !safeAlias(authorization.communicationChannelAlias) ||
    !safeAlias(authorization.rollbackOwnerAlias) ||
    !isoUtc(authorization.approvedAtUtc) ||
    !isoUtc(authorization.expiresAtUtc) ||
    authorization.stacks?.join('\0') !== expectedStacks().join('\0') ||
    authorization.sandboxIncluded !== true ||
    authorization.destructiveActionsAllowed !== false ||
    authorization.abortCriteria?.join('\0') !== ABORT_CRITERIA.join('\0')
  ) {
    fail('E7_BASELINE_AUTHORIZATION_INVALID');
  }
  const aws = value.aws;
  if (
    !exactKeys(aws, ['accountId', 'region', 'roles', 'sessionMode']) ||
    !/^[0-9]{12}$/u.test(aws?.accountId ?? '') ||
    !AWS_REGION.test(aws?.region ?? '') ||
    aws.sessionMode !== 'OIDC' ||
    !exactKeys(aws.roles, [
      'readRoleArn',
      'deployRoleArn',
      'rollbackRoleArn',
      'cleanupRoleArn',
      'baselineRoleArn',
    ]) ||
    !Object.values(aws.roles).every((role) => roleMatchesAccount(role, aws.accountId)) ||
    new Set(Object.values(aws.roles)).size !== 5
  ) {
    fail('E7_BASELINE_AWS_TARGET_INVALID');
  }
  const window = value.window;
  const current = now instanceof Date ? now.getTime() : Number.NaN;
  if (
    !['ACTIVE', 'RECOVERY'].includes(phase) ||
    !exactKeys(window, ['startsAtUtc', 'endsAtUtc']) ||
    !isoUtc(window.startsAtUtc) ||
    !isoUtc(window.endsAtUtc) ||
    !Number.isFinite(current) ||
    (phase === 'ACTIVE' && Date.parse(authorization.approvedAtUtc) > current) ||
    (phase === 'ACTIVE' && Date.parse(authorization.expiresAtUtc) <= current) ||
    (phase === 'ACTIVE' && Date.parse(window.startsAtUtc) > current) ||
    (phase === 'ACTIVE' && Date.parse(window.endsAtUtc) <= current) ||
    Date.parse(window.startsAtUtc) < Date.parse(authorization.approvedAtUtc) ||
    Date.parse(window.endsAtUtc) <= Date.parse(window.startsAtUtc) ||
    Date.parse(window.endsAtUtc) > Date.parse(authorization.expiresAtUtc) ||
    Date.parse(window.endsAtUtc) - Date.parse(window.startsAtUtc) > 24 * 60 * 60 * 1000
  ) {
    fail('E7_BASELINE_WINDOW_INVALID');
  }
  if (
    !exactKeys(value.budget, [
      'maxUsd',
      'warningUsd',
      'alertOwnerAlias',
      'alertChannelAlias',
      'alertDestinationSha256',
    ]) ||
    !Number.isFinite(value.budget.maxUsd) ||
    value.budget.maxUsd <= 0 ||
    value.budget.maxUsd > 100 ||
    !Array.isArray(value.budget.warningUsd) ||
    value.budget.warningUsd.length < 1 ||
    value.budget.warningUsd.length > 3 ||
    value.budget.warningUsd.some(
      (amount, index) =>
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount >= value.budget.maxUsd ||
        (index > 0 && amount <= value.budget.warningUsd[index - 1]),
    ) ||
    !safeAlias(value.budget.alertOwnerAlias) ||
    !safeAlias(value.budget.alertChannelAlias) ||
    !SHA256.test(value.budget.alertDestinationSha256 ?? '')
  ) {
    fail('E7_BASELINE_BUDGET_INVALID');
  }
  if (
    !exactKeys(value.traffic, ['targetOwnership', 'maxRequests']) ||
    value.traffic.targetOwnership !== 'AUTHORIZED_ASSESSMENT_TARGET' ||
    value.traffic.maxRequests !== BASELINE_REQUEST_LIMIT
  ) {
    fail('E7_BASELINE_TRAFFIC_AUTHORITY_INVALID');
  }
  const domain = value.domain;
  if (
    !exactKeys(domain, [
      'mode',
      'hostname',
      'apiHostname',
      'hostedZoneId',
      'hostedZoneName',
      'webCertificateArn',
      'apiCertificateArn',
      'dnsIncluded',
    ]) ||
    domain.mode !== 'CUSTOM_AUTHORIZED' ||
    !HOSTNAME.test(domain.hostname ?? '') ||
    !HOSTNAME.test(domain.apiHostname ?? '') ||
    !HOSTNAME.test(domain.hostedZoneName ?? '') ||
    domain.hostname === domain.apiHostname ||
    !domain.hostname.endsWith(`.${domain.hostedZoneName}`) ||
    !domain.apiHostname.endsWith(`.${domain.hostedZoneName}`) ||
    !/^Z[A-Z0-9]{5,31}$/u.test(domain.hostedZoneId ?? '') ||
    !new RegExp(`^arn:aws:acm:us-east-1:${aws.accountId}:certificate/[0-9a-f-]{36}$`, 'u').test(
      domain.webCertificateArn ?? '',
    ) ||
    !new RegExp(`^arn:aws:acm:${aws.region}:${aws.accountId}:certificate/[0-9a-f-]{36}$`, 'u').test(
      domain.apiCertificateArn ?? '',
    ) ||
    domain.dnsIncluded !== true
  ) {
    fail('E7_BASELINE_DOMAIN_INVALID');
  }
  const access = value.prereleaseAccess;
  const originSecret = SECRET_ARN.exec(access?.originTokenSecretArn ?? '');
  if (
    !exactKeys(access, [
      'mode',
      'keyGroupId',
      'publicKeyId',
      'originTokenSecretArn',
      'originTokenSecretVersionId',
      'rotationDuringWindow',
    ]) ||
    access.mode !== 'CLOUDFRONT_SIGNED_COOKIE' ||
    !CLOUDFRONT_KEY_GROUP_ID.test(access.keyGroupId ?? '') ||
    !CLOUDFRONT_PUBLIC_KEY_ID.test(access.publicKeyId ?? '') ||
    !SECRET_VERSION_ID.test(access.originTokenSecretVersionId ?? '') ||
    access.rotationDuringWindow !== 'FORBIDDEN' ||
    originSecret?.[1] !== aws.region ||
    originSecret?.[2] !== aws.accountId ||
    !Array.isArray(value.credentialReferences) ||
    value.credentialReferences.length < 1 ||
    value.credentialReferences.length > 6 ||
    new Set(value.credentialReferences).size !== value.credentialReferences.length ||
    !value.credentialReferences.includes(access.originTokenSecretArn) ||
    !value.credentialReferences.every((entry) => {
      const match = SECRET_ARN.exec(entry);
      return match?.[1] === aws.region && match?.[2] === aws.accountId;
    })
  ) {
    fail('E7_BASELINE_RESTRICTED_ACCESS_INVALID');
  }
  const cleanup = value.cleanup;
  if (
    !exactKeys(cleanup, [
      'ownerAlias',
      'expiresAtUtc',
      'preserveBootstrap',
      'preservePreviousRelease',
    ]) ||
    !safeAlias(cleanup.ownerAlias) ||
    !isoUtc(cleanup.expiresAtUtc) ||
    Date.parse(cleanup.expiresAtUtc) <= Date.parse(window.endsAtUtc) ||
    cleanup.preserveBootstrap !== true ||
    cleanup.preservePreviousRelease !== true
  ) {
    fail('E7_BASELINE_CLEANUP_INVALID');
  }
  return value;
};

const baselineFreezeBody = (value) => {
  const body = { ...value };
  delete body.manifestSha256;
  return body;
};

export const validateBaselineFreeze = (value) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'candidateTreeSha',
      'releaseId',
      'baselineVersion',
      'environment',
      'authorizationScope',
      'region',
      'configSha256',
      'stage6ManifestSha256',
      'stage6RunId',
      'stage6SourceProvenanceSha256',
      'stage6SourceProvenanceObjectSha256',
      'stage6SourceRunId',
      'stage6SourceRunAttempt',
      'stage6SourceArtifactId',
      'stage6SourceArtifactDigest',
      'sourceRunId',
      'sourceArtifactId',
      'sourceArtifactSha256',
      'sourceArtifactContentSha256',
      'builtAtUtc',
      'toolchain',
      'lockfileSha256',
      'openApiSha256',
      'generatedClientSha256',
      'publicConfigSha256',
      'immutableWebInventory',
      'runtimeSecretVersionIdSha256',
      'artifacts',
      'assemblySha256',
      'publicationState',
      'publicReleaseEffectsAllowed',
      'containsSensitiveData',
      'manifestSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_BUILD_ONCE' ||
    value.status !== 'FROZEN_FOR_CLOSED_BASELINE_ONLY' ||
    !SHA.test(value.candidateSha ?? '') ||
    !SHA.test(value.candidateTreeSha ?? '') ||
    RELEASE_ID.exec(value.releaseId ?? '')?.[1] !== value.candidateSha.slice(0, 7) ||
    !BASELINE_VERSION.test(value.baselineVersion ?? '') ||
    value.environment !== 'assessment-release' ||
    value.authorizationScope !== 'FULL_RELEASE_BASELINE_CLOSED' ||
    !AWS_REGION.test(value.region ?? '') ||
    ![
      value.configSha256,
      value.stage6ManifestSha256,
      value.stage6SourceProvenanceSha256,
      value.stage6SourceProvenanceObjectSha256,
      value.sourceArtifactSha256,
      value.sourceArtifactContentSha256,
      value.lockfileSha256,
      value.openApiSha256,
      value.generatedClientSha256,
      value.publicConfigSha256,
      value.runtimeSecretVersionIdSha256,
      value.assemblySha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !STAGE6_RUN_ID.test(value.stage6RunId ?? '') ||
    !/^[1-9][0-9]{0,19}$/u.test(value.stage6SourceRunId ?? '') ||
    !Number.isSafeInteger(value.stage6SourceRunAttempt) ||
    value.stage6SourceRunAttempt < 1 ||
    !Number.isSafeInteger(value.stage6SourceArtifactId) ||
    value.stage6SourceArtifactId < 1 ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.stage6SourceArtifactDigest ?? '') ||
    !/^[1-9][0-9]{0,19}$/u.test(value.sourceRunId ?? '') ||
    !/^[1-9][0-9]{0,19}$/u.test(value.sourceArtifactId ?? '') ||
    !isoUtc(value.builtAtUtc) ||
    !exactKeys(value.toolchain, ['node', 'packageManager', 'cdk', 'awsCli']) ||
    !/^v24\.[0-9]+\.[0-9]+$/u.test(value.toolchain.node ?? '') ||
    !/^pnpm@11\.[0-9]+\.[0-9]+$/u.test(value.toolchain.packageManager ?? '') ||
    !/^[0-9]+\.[0-9]+\.[0-9]+$/u.test(value.toolchain.cdk ?? '') ||
    !/^[0-9]+\.[0-9]+\.[0-9]+$/u.test(value.toolchain.awsCli ?? '') ||
    !exactKeys(value.artifacts, ['web', 'api', 'worker', 'iac']) ||
    !Object.values(value.artifacts).every(
      (artifact) =>
        exactKeys(artifact, ['sha256', 'files', 'bytes']) &&
        SHA256.test(artifact.sha256 ?? '') &&
        Number.isSafeInteger(artifact.files) &&
        artifact.files > 0 &&
        Number.isSafeInteger(artifact.bytes) &&
        artifact.bytes > 0,
    ) ||
    validateImmutableWebInventory(value.immutableWebInventory) !== value.immutableWebInventory ||
    value.artifacts.web.files !== value.immutableWebInventory.totalFiles + 2 ||
    value.artifacts.web.bytes <= value.immutableWebInventory.totalBytes ||
    value.artifacts.iac.sha256 !== value.assemblySha256 ||
    value.publicationState !== 'DISABLED' ||
    value.publicReleaseEffectsAllowed !== false ||
    value.containsSensitiveData !== false ||
    value.manifestSha256 !== objectSha256(baselineFreezeBody(value))
  ) {
    fail('E7_BASELINE_FREEZE_INVALID');
  }
  return value;
};

export const createBaselineFreeze = ({
  config,
  stage6Manifest,
  stage6ManifestFilename,
  stage6ManifestSha256,
  stage6SourceProvenance,
  stage6SourceProvenanceFilename,
  stage6SourceRunId,
  stage6SourceArtifactId,
  stage6SourceArtifactDigest,
  sourceRunId,
  sourceArtifactId,
  sourceArtifactSha256,
  sourceArtifactPath,
  baselineVersion,
  candidate,
  releaseId,
  artifacts,
  lockfile = 'pnpm-lock.yaml',
  openApi = 'output/architecture/openapi.yaml',
  generatedClient = 'packages/contracts/src/generated/openapi.d.ts',
  publicConfig = 'output/release/build/public-config.json',
  toolchain,
  builtAtUtc = new Date().toISOString(),
}) => {
  validateBaselineConfig(config, { now: new Date(builtAtUtc) });
  const repositoryCandidate = currentCandidate();
  const stage6ManifestPath = checkedPath(stage6ManifestFilename);
  const stage6ManifestFromFile = readJson(stage6ManifestPath);
  const stage6 = assessStage6Manifest(stage6ManifestFromFile);
  const stage6Source = validateStage6SourceProvenance(stage6SourceProvenance, {
    manifest: stage6ManifestFromFile,
    expectedCandidateSha: candidate?.commitSha,
    expectedRunId: stage6SourceRunId,
    expectedArtifactId: stage6SourceArtifactId,
    expectedArtifactDigest: stage6SourceArtifactDigest,
  });
  const stage6SourcePath = checkedPath(stage6SourceProvenanceFilename);
  if (
    stage6.status !== 'PASS' ||
    fileSha256(stage6ManifestPath) !== stage6ManifestSha256 ||
    objectSha256(stage6ManifestFromFile) !== objectSha256(stage6Manifest) ||
    objectSha256(readJson(stage6SourcePath)) !== objectSha256(stage6Source) ||
    stage6Source.stage6ManifestSha256 !== stage6ManifestSha256 ||
    !/^[1-9][0-9]{0,19}$/u.test(stage6SourceRunId ?? '') ||
    !/^[1-9][0-9]{0,15}$/u.test(stage6SourceArtifactId ?? '') ||
    !/^sha256:[0-9a-f]{64}$/u.test(stage6SourceArtifactDigest ?? '') ||
    !object(candidate) ||
    candidate.workingTree !== 'CLEAN' ||
    candidate.changedFiles !== 0 ||
    candidate.commitSha !== repositoryCandidate.commitSha ||
    candidate.treeSha !== repositoryCandidate.treeSha ||
    candidate.workingTree !== repositoryCandidate.workingTree ||
    candidate.changedFiles !== repositoryCandidate.changedFiles ||
    stage6.candidate.commitSha !== candidate.commitSha ||
    stage6.candidate.treeSha !== candidate.treeSha ||
    !SHA256.test(sourceArtifactSha256 ?? '') ||
    RELEASE_ID.exec(releaseId ?? '')?.[1] !== candidate.commitSha?.slice(0, 7) ||
    !BASELINE_VERSION.test(baselineVersion ?? '')
  ) {
    fail('E7_BASELINE_FREEZE_INPUT_INVALID');
  }
  const hashed = Object.fromEntries(
    Object.entries(artifacts).map(([name, filename]) => {
      const result = hashArtifactPath(
        checkedPath(filename, { directory: name !== 'publicConfig' }),
      );
      return [name, { sha256: result.sha256, files: result.files, bytes: result.bytes }];
    }),
  );
  const sourceArtifactContentSha256 = hashArtifactPath(
    checkedPath(sourceArtifactPath, { directory: true }),
  ).sha256;
  if (!exactKeys(hashed, ['web', 'api', 'worker', 'iac'])) {
    fail('E7_BASELINE_FREEZE_ARTIFACT_SET_INVALID');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_BUILD_ONCE',
    status: 'FROZEN_FOR_CLOSED_BASELINE_ONLY',
    candidateSha: candidate.commitSha,
    candidateTreeSha: candidate.treeSha,
    releaseId,
    baselineVersion,
    environment: config.environment,
    authorizationScope: config.authorization.scope,
    region: config.aws.region,
    configSha256: objectSha256(config),
    stage6ManifestSha256,
    stage6RunId: stage6.runId,
    stage6SourceProvenanceSha256: fileSha256(stage6SourcePath),
    stage6SourceProvenanceObjectSha256: stage6Source.provenanceSha256,
    stage6SourceRunId: stage6Source.runId,
    stage6SourceRunAttempt: stage6Source.runAttempt,
    stage6SourceArtifactId: stage6Source.artifactId,
    stage6SourceArtifactDigest: stage6Source.artifactDigest,
    sourceRunId,
    sourceArtifactId,
    sourceArtifactSha256,
    sourceArtifactContentSha256,
    builtAtUtc,
    toolchain,
    lockfileSha256: fileSha256(checkedPath(lockfile)),
    openApiSha256: fileSha256(checkedPath(openApi)),
    generatedClientSha256: fileSha256(checkedPath(generatedClient)),
    publicConfigSha256: fileSha256(checkedPath(publicConfig)),
    immutableWebInventory: immutableWebInventory(artifacts.web),
    runtimeSecretVersionIdSha256: sha256(config.prereleaseAccess.originTokenSecretVersionId),
    artifacts: hashed,
    assemblySha256: hashed.iac.sha256,
    publicationState: 'DISABLED',
    publicReleaseEffectsAllowed: false,
    containsSensitiveData: false,
  };
  return validateBaselineFreeze({ ...body, manifestSha256: objectSha256(body) });
};

const planBody = (value) => {
  const body = { ...value };
  delete body.planSha256;
  return body;
};

const validateBaselinePreDeploymentState = (state) => {
  if (!exactKeys(state, expectedStacks())) fail('E7_BASELINE_PLAN_STATE_INVALID');
  let absentSeen = false;
  let absentCount = 0;
  for (const stackName of expectedStacks()) {
    const value = state[stackName];
    if (value === 'ABSENT') {
      absentSeen = true;
      absentCount += 1;
    } else if (value === 'EXISTING_BASELINE_EXACT') {
      if (absentSeen) fail('E7_BASELINE_PLAN_STATE_INVALID');
    } else {
      fail('E7_BASELINE_PLAN_STATE_INVALID');
    }
  }
  if (absentCount === 0) fail('E7_BASELINE_ALREADY_DEPLOYED');
  return state;
};

export const validateBaselinePlan = (value, { config, freeze, iamEvidence, awsPreflight }) => {
  validateBaselineConfig(config, { now: new Date(config.window.startsAtUtc) });
  validateBaselineFreeze(freeze);
  validateBaselinePreDeploymentState(value?.preDeploymentState);
  const iam = iamEvidence?.iamEffectivePermissions ?? iamEvidence;
  validateIamEffectivePermissionsEvidence({
    value: iam,
    config,
    scope: 'baseline',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    manifestSha256: freeze.manifestSha256,
    bootstrapAssetInventory: iam?.bootstrapRoles?.assetInventory?.inventory,
    baselineRoleArn: config.aws.roles.baselineRoleArn,
  });
  validateBaselineAwsPreflight(awsPreflight, { config, freeze });
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'configSha256',
      'freezeManifestSha256',
      'assemblySha256',
      'iamEvidenceSha256',
      'iamBindingSha256',
      'awsPreflightSha256',
      'stacks',
      'preDeploymentState',
      'diffSha256',
      'rawDiffArtifactSha256',
      'risks',
      'publicationState',
      'publicReleaseEffectsAllowed',
      'generatedAtUtc',
      'containsSensitiveData',
      'planSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_CLOSED_DIFF' ||
    value.status !== 'READY_FOR_PROTECTED_BASELINE_REVIEW' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.configSha256 !== objectSha256(config) ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.assemblySha256 !== freeze.assemblySha256 ||
    value.iamEvidenceSha256 !== objectSha256(iamEvidence) ||
    value.iamBindingSha256 !== iam?.bindingSha256 ||
    value.awsPreflightSha256 !== awsPreflight.preflightSha256 ||
    iam?.kind !== 'IAM_EFFECTIVE_PERMISSIONS' ||
    iam?.status !== 'PASS' ||
    iam?.scope !== 'baseline' ||
    iam?.candidateSha !== freeze.candidateSha ||
    iam?.releaseId !== freeze.releaseId ||
    iam?.manifestSha256 !== freeze.manifestSha256 ||
    iam?.configSha256 !== objectSha256(config) ||
    iam?.administratorPolicies !== 0 ||
    iam?.wildcardAllows !== 0 ||
    iam?.outsideProfileCapabilities !== 0 ||
    iam?.containsSensitiveData !== false ||
    iam?.baselineRole?.status !== 'PASS' ||
    iam?.baselineRole?.role?.roleKey !== 'baselineRoleArn' ||
    value.stacks?.join('\0') !== expectedStacks().join('\0') ||
    !SHA256.test(value.diffSha256 ?? '') ||
    !SHA256.test(value.rawDiffArtifactSha256 ?? '') ||
    !exactKeys(value.risks, [
      'statefulReplacement',
      'statefulDeletion',
      'rollbackControlReplacement',
      'destructiveChangeMentioned',
      'iamOrPolicyReviewRequired',
    ]) ||
    value.risks.statefulReplacement !== false ||
    value.risks.statefulDeletion !== false ||
    value.risks.rollbackControlReplacement !== false ||
    value.risks.destructiveChangeMentioned !== false ||
    typeof value.risks.iamOrPolicyReviewRequired !== 'boolean' ||
    value.publicationState !== 'DISABLED' ||
    value.publicReleaseEffectsAllowed !== false ||
    !isoUtc(value.generatedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.planSha256 !== objectSha256(planBody(value))
  ) {
    fail('E7_BASELINE_PLAN_INVALID');
  }
  return value;
};

const approvalBody = (value) => {
  const body = { ...value };
  delete body.approvalSha256;
  return body;
};

export const validateBaselineApproval = (value, { config, freeze, plan }) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'scope',
      'candidateSha',
      'releaseId',
      'configSha256',
      'freezeManifestSha256',
      'approvedPlanSha256',
      'approvedDiffSha256',
      'iamBindingSha256',
      'githubApprovalEvidenceSha256',
      'runId',
      'runAttempt',
      'reviewerAlias',
      'approvedAtUtc',
      'protectedEnvironment',
      'trafficAuthorization',
      'publicationState',
      'publicReleaseEffectsAllowed',
      'destructiveActionsAllowed',
      'containsSensitiveData',
      'approvalSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_CLOSED_APPROVAL' ||
    value.status !== 'APPROVED_FOR_ONE_CLOSED_BASELINE' ||
    value.scope !== 'baseline' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.configSha256 !== objectSha256(config) ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.approvedPlanSha256 !== plan.planSha256 ||
    value.approvedDiffSha256 !== plan.rawDiffArtifactSha256 ||
    value.iamBindingSha256 !== plan.iamBindingSha256 ||
    !SHA256.test(value.githubApprovalEvidenceSha256 ?? '') ||
    !/^[1-9][0-9]{0,19}$/u.test(value.runId ?? '') ||
    !Number.isSafeInteger(value.runAttempt) ||
    value.runAttempt < 1 ||
    !safeAlias(value.reviewerAlias) ||
    !isoUtc(value.approvedAtUtc) ||
    Date.parse(value.approvedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(value.approvedAtUtc) > Date.parse(config.window.endsAtUtc) ||
    value.protectedEnvironment !== 'assessment-release-baseline' ||
    !exactKeys(value.trafficAuthorization, ['targetSha256', 'maxRequests']) ||
    value.trafficAuthorization.targetSha256 !== sha256(`https://${config.domain.hostname}`) ||
    value.trafficAuthorization.maxRequests !== config.traffic.maxRequests ||
    value.publicationState !== 'DISABLED' ||
    value.publicReleaseEffectsAllowed !== false ||
    value.destructiveActionsAllowed !== false ||
    value.containsSensitiveData !== false ||
    value.approvalSha256 !== objectSha256(approvalBody(value))
  ) {
    fail('E7_BASELINE_APPROVAL_INVALID');
  }
  return value;
};

const deploymentBody = (value) => {
  const body = { ...value };
  delete body.deploymentSha256;
  return body;
};

export const validateBaselineDeployment = (value, { config, freeze, plan, approval }) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'configSha256',
      'freezeManifestSha256',
      'approvedPlanSha256',
      'approvalSha256',
      'stacks',
      'deploymentMethod',
      'publicationState',
      'restrictedAccessBindingSha256',
      'publicReleaseEffectsAllowed',
      'tagCreated',
      'releaseCreated',
      'readmeChanged',
      'gateE703',
      'deployedAtUtc',
      'containsSensitiveData',
      'deploymentSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_CLOSED_DEPLOYMENT' ||
    value.status !== 'DEPLOYED_DISABLED_REQUIRES_RESTRICTED_SMOKE' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.configSha256 !== objectSha256(config) ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.approvedPlanSha256 !== plan.planSha256 ||
    value.approvalSha256 !== approval.approvalSha256 ||
    !exactKeys(value.stacks, expectedStacks()) ||
    Object.values(value.stacks).some(
      (stack) =>
        !exactKeys(stack, [
          'status',
          'stackIdSha256',
          'terminationProtection',
          'publicationState',
        ]) ||
        stack.status !== 'CREATE_COMPLETE' ||
        !SHA256.test(stack.stackIdSha256 ?? '') ||
        stack.terminationProtection !== true ||
        !['DISABLED', 'NOT_APPLICABLE'].includes(stack.publicationState),
    ) ||
    value.deploymentMethod !== 'CLOUDFORMATION_CHANGE_SET' ||
    value.publicationState !== 'DISABLED' ||
    !SHA256.test(value.restrictedAccessBindingSha256 ?? '') ||
    value.publicReleaseEffectsAllowed !== false ||
    value.tagCreated !== false ||
    value.releaseCreated !== false ||
    value.readmeChanged !== false ||
    value.gateE703 !== 'NOT_RUN' ||
    !isoUtc(value.deployedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.deploymentSha256 !== objectSha256(deploymentBody(value))
  ) {
    fail('E7_BASELINE_DEPLOYMENT_INVALID');
  }
  return value;
};

const compatibilityEvidence = (value, kind) => {
  if (
    !object(value) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== kind ||
    value.status !== 'PASS' ||
    !SHA.test(value.candidateSha ?? '') ||
    !RELEASE_ID.test(value.releaseId ?? '') ||
    !isoUtc(value.verifiedAtUtc) ||
    value.externalRequests < 0 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_BASELINE_COMPATIBILITY_EVIDENCE_INVALID');
  }
  return value;
};

const captureBody = (value) => {
  const body = { ...value };
  delete body.captureSha256;
  return body;
};

export const validateBaselineCapture = (value, evidenceDirectory) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'capturedAtUtc',
      'environment',
      'region',
      'accountSha256',
      'provenance',
      'baseline',
      'topology',
      'resources',
      'compatibility',
      'approval',
      'deploymentSha256',
      'notificationSha256',
      'activationEvidenceSha256',
      'disableEvidenceSha256',
      'publication',
      'rollbackScenarios',
      'publicReleaseEffects',
      'containsSensitiveData',
      'captureSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_CLOSED_CAPTURE' ||
    value.status !== 'APPROVED_IMMUTABLE_CLOSED_N_MINUS_1' ||
    !isoUtc(value.capturedAtUtc) ||
    value.environment !== 'assessment-release' ||
    !AWS_REGION.test(value.region ?? '') ||
    !SHA256.test(value.accountSha256 ?? '') ||
    !exactKeys(value.provenance, Object.keys(BASELINE_PROVENANCE_FILENAMES)) ||
    !Object.values(value.provenance).every((digest) => SHA256.test(digest ?? '')) ||
    !exactKeys(value.baseline, [
      'candidateSha',
      'candidateTreeSha',
      'releaseId',
      'baselineVersion',
      'configSha256',
      'freezeManifestSha256',
      'assemblySha256',
      'openApiSha256',
      'generatedClientSha256',
      'apiArtifactSha256',
    ]) ||
    !SHA.test(value.baseline.candidateSha ?? '') ||
    !SHA.test(value.baseline.candidateTreeSha ?? '') ||
    RELEASE_ID.exec(value.baseline.releaseId ?? '')?.[1] !==
      value.baseline.candidateSha.slice(0, 7) ||
    !BASELINE_VERSION.test(value.baseline.baselineVersion ?? '') ||
    ![
      value.baseline.configSha256,
      value.baseline.freezeManifestSha256,
      value.baseline.assemblySha256,
      value.baseline.openApiSha256,
      value.baseline.generatedClientSha256,
      value.baseline.apiArtifactSha256,
      value.deploymentSha256,
      value.notificationSha256,
      value.activationEvidenceSha256,
      value.disableEvidenceSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !exactKeys(value.topology, ['stackNames', 'domain', 'access', 'data', 'runtime']) ||
    value.topology.stackNames?.join('\0') !== expectedStacks().join('\0') ||
    !exactKeys(value.topology.domain, [
      'hostnameSha256',
      'apiHostnameSha256',
      'hostedZoneIdSha256',
      'webCertificateArnSha256',
      'apiCertificateArnSha256',
    ]) ||
    !Object.values(value.topology.domain).every((digest) => SHA256.test(digest ?? '')) ||
    !exactKeys(value.topology.access, [
      'baselineMode',
      'targetMode',
      'keyGroupIdSha256',
      'publicKeyIdSha256',
      'originTokenSecretArnSha256',
      'originTokenSecretVersionIdSha256',
    ]) ||
    value.topology.access.baselineMode !== 'CLOUDFRONT_SIGNED_COOKIE' ||
    value.topology.access.targetMode !== 'ORIGIN_GATE_ONLY' ||
    ![
      value.topology.access.keyGroupIdSha256,
      value.topology.access.publicKeyIdSha256,
      value.topology.access.originTokenSecretArnSha256,
      value.topology.access.originTokenSecretVersionIdSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !exactKeys(value.topology.data, [
      'schemaStrategy',
      'catalogTableName',
      'checkoutTableName',
      'seedEvidenceSha256',
    ]) ||
    value.topology.data.schemaStrategy !== 'EXPAND_CONTRACT_N_AND_N_MINUS_1' ||
    !/^[A-Za-z0-9_.-]{3,255}$/u.test(value.topology.data.catalogTableName ?? '') ||
    !/^[A-Za-z0-9_.-]{3,255}$/u.test(value.topology.data.checkoutTableName ?? '') ||
    !SHA256.test(value.topology.data.seedEvidenceSha256 ?? '') ||
    !exactKeys(value.topology.runtime, [
      'apiFunctionName',
      'apiAliasName',
      'workerFunctionName',
      'workerAliasName',
      'bucketName',
      'distributionId',
    ]) ||
    value.topology.runtime.apiFunctionName !== value.resources?.api?.functionName ||
    value.topology.runtime.apiAliasName !== value.resources?.api?.aliasName ||
    value.topology.runtime.workerFunctionName !== value.resources?.worker?.functionName ||
    value.topology.runtime.workerAliasName !== value.resources?.worker?.aliasName ||
    value.topology.runtime.bucketName !== value.resources?.web?.bucketName ||
    value.topology.runtime.distributionId !== value.resources?.web?.distributionId ||
    !exactKeys(value.resources, ['api', 'worker', 'web']) ||
    !exactKeys(value.resources.api, ['functionName', 'aliasName', 'version', 'codeSha256']) ||
    !exactKeys(value.resources.worker, ['functionName', 'aliasName', 'version', 'codeSha256']) ||
    ![value.resources.api, value.resources.worker].every(
      (resource) =>
        /^[A-Za-z0-9-_]{1,64}$/u.test(resource.functionName ?? '') &&
        /^[A-Za-z0-9-_]{1,128}$/u.test(resource.aliasName ?? '') &&
        /^[1-9][0-9]*$/u.test(resource.version ?? '') &&
        SHA256.test(resource.codeSha256 ?? ''),
    ) ||
    !exactKeys(value.resources.web, [
      'bucketName',
      'distributionId',
      'objects',
      'mutableInvalidationPaths',
    ]) ||
    !/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/u.test(value.resources.web.bucketName ?? '') ||
    !/^[A-Z0-9]{8,64}$/u.test(value.resources.web.distributionId ?? '') ||
    value.resources.web.mutableInvalidationPaths?.join('\0') !==
      ['/index.html', '/public-config.json'].join('\0') ||
    value.resources.web.objects?.map(({ key }) => key).join('\0') !==
      ['index.html', 'public-config.json'].join('\0') ||
    value.resources.web.objects.some(
      (entry) =>
        !exactKeys(entry, ['key', 'versionId', 'etagSha256', 'contentSha256', 'bytes']) ||
        typeof entry.versionId !== 'string' ||
        entry.versionId.length === 0 ||
        !SHA256.test(entry.etagSha256 ?? '') ||
        !SHA256.test(entry.contentSha256 ?? '') ||
        !Number.isSafeInteger(entry.bytes) ||
        entry.bytes < 1,
    ) ||
    !exactKeys(value.compatibility, [
      'status',
      'schemaStrategy',
      'dataRollback',
      'apiContractEvidenceSha256',
      'pendingReconciliationEvidenceSha256',
      'smokeEvidenceSha256',
      'trafficLedgerSha256',
      'smokeVerifiedAtUtc',
    ]) ||
    value.compatibility.status !== 'PASS' ||
    value.compatibility.schemaStrategy !== 'EXPAND_CONTRACT_N_AND_N_MINUS_1' ||
    value.compatibility.dataRollback !== 'FORBIDDEN_FORWARD_ONLY' ||
    ![
      value.compatibility.apiContractEvidenceSha256,
      value.compatibility.pendingReconciliationEvidenceSha256,
      value.compatibility.smokeEvidenceSha256,
      value.compatibility.trafficLedgerSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !isoUtc(value.compatibility.smokeVerifiedAtUtc) ||
    !exactKeys(value.approval, [
      'status',
      'reviewerAlias',
      'approvedAtUtc',
      'approvalEvidenceSha256',
    ]) ||
    value.approval.status !== 'APPROVED' ||
    !safeAlias(value.approval.reviewerAlias) ||
    !isoUtc(value.approval.approvedAtUtc) ||
    !SHA256.test(value.approval.approvalEvidenceSha256 ?? '') ||
    !exactKeys(value.publication, [
      'state',
      'restrictedAccessVerified',
      'anonymousWebStatus',
      'directApiStatus',
      'schedulerState',
    ]) ||
    value.publication.state !== 'DISABLED' ||
    value.publication.restrictedAccessVerified !== true ||
    value.publication.anonymousWebStatus !== 403 ||
    value.publication.directApiStatus !== 403 ||
    value.publication.schedulerState !== 'DISABLED' ||
    !exactKeys(value.rollbackScenarios, ['RB-E7-06', 'RB-E7-08']) ||
    value.rollbackScenarios['RB-E7-06'] !== 'BLOCKED_NO_REAL_PRODUCER' ||
    value.rollbackScenarios['RB-E7-08'] !== 'BLOCKED_NO_REAL_PRODUCER' ||
    !exactKeys(value.publicReleaseEffects, [
      'tagCreated',
      'releaseCreated',
      'readmeChanged',
      'gateE703',
      'trafficPublicAfterCapture',
    ]) ||
    value.publicReleaseEffects.tagCreated !== false ||
    value.publicReleaseEffects.releaseCreated !== false ||
    value.publicReleaseEffects.readmeChanged !== false ||
    value.publicReleaseEffects.gateE703 !== 'NOT_RUN' ||
    value.publicReleaseEffects.trafficPublicAfterCapture !== false ||
    value.containsSensitiveData !== false ||
    value.captureSha256 !== objectSha256(captureBody(value))
  ) {
    fail('E7_BASELINE_CAPTURE_INVALID');
  }
  if (evidenceDirectory !== undefined) {
    const directory = checkedPath(evidenceDirectory, { directory: true });
    for (const [key, filename] of Object.entries(BASELINE_PROVENANCE_FILENAMES)) {
      if (fileSha256(path.join(directory, filename)) !== value.provenance[key]) {
        fail('E7_BASELINE_CAPTURE_PROVENANCE_DIGEST_MISMATCH');
      }
    }
    const config = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.config));
    const freeze = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.freeze));
    const stage6Source = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.stage6Source));
    const awsPreflight = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.awsPreflight));
    const iamEvidence = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.iam));
    const plan = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.plan));
    const githubApproval = readJson(
      path.join(directory, BASELINE_PROVENANCE_FILENAMES.githubApproval),
    );
    const approval = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.approval));
    const deployment = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.deployment));
    const seed = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.seed));
    const notification = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.notification));
    const activation = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.activation));
    const disable = readJson(path.join(directory, BASELINE_PROVENANCE_FILENAMES.disable));
    const api = readJson(path.join(directory, BASELINE_EVIDENCE_FILENAMES[0]));
    const pending = readJson(path.join(directory, BASELINE_EVIDENCE_FILENAMES[1]));
    const smoke = readJson(path.join(directory, BASELINE_EVIDENCE_FILENAMES[2]));
    const ledger = readJson(path.join(directory, BASELINE_EVIDENCE_FILENAMES[3]));
    validateBaselineConfig(config, { now: new Date(value.capturedAtUtc), phase: 'RECOVERY' });
    validateBaselineFreeze(freeze);
    validateStage6SourceProvenance(stage6Source, {
      expectedCandidateSha: freeze.candidateSha,
      expectedRunId: freeze.stage6SourceRunId,
      expectedRunAttempt: freeze.stage6SourceRunAttempt,
      expectedArtifactId: freeze.stage6SourceArtifactId,
      expectedArtifactDigest: freeze.stage6SourceArtifactDigest,
    });
    validateBaselineAwsPreflight(awsPreflight, { config, freeze });
    validateBaselinePlan(plan, { config, freeze, iamEvidence, awsPreflight });
    validateBaselineApproval(approval, { config, freeze, plan });
    validateBaselineDeployment(deployment, { config, freeze, plan, approval });
    validateBaselineNotification(notification, { config, freeze, deployment });
    validateBaselineSeed(seed, { config, freeze, deployment });
    validateBaselineActivation(activation, { config, freeze, deployment, notification, seed });
    validateBaselineDisable(disable, { freeze });
    if (
      fileSha256(path.join(directory, BASELINE_PROVENANCE_FILENAMES.rawDiff)) !==
        plan.rawDiffArtifactSha256 ||
      fileSha256(path.join(directory, BASELINE_PROVENANCE_FILENAMES.githubApproval)) !==
        approval.githubApprovalEvidenceSha256 ||
      githubApproval.candidateSha !== freeze.candidateSha ||
      githubApproval.releaseId !== freeze.releaseId ||
      githubApproval.environment !== 'assessment-release-baseline' ||
      githubApproval.runId !== approval.runId ||
      githubApproval.runAttempt !== approval.runAttempt ||
      value.region !== config.aws.region ||
      value.accountSha256 !== sha256(config.aws.accountId) ||
      freeze.configSha256 !== objectSha256(config) ||
      fileSha256(path.join(directory, BASELINE_PROVENANCE_FILENAMES.stage6Source)) !==
        freeze.stage6SourceProvenanceSha256 ||
      stage6Source.provenanceSha256 !== freeze.stage6SourceProvenanceObjectSha256 ||
      stage6Source.stage6ManifestSha256 !== freeze.stage6ManifestSha256 ||
      stage6Source.stage6InternalRunId !== freeze.stage6RunId ||
      stage6Source.stage6CandidateTreeSha !== freeze.candidateTreeSha ||
      value.baseline.configSha256 !== freeze.configSha256 ||
      value.baseline.freezeManifestSha256 !== freeze.manifestSha256 ||
      value.baseline.assemblySha256 !== freeze.assemblySha256 ||
      value.baseline.openApiSha256 !== freeze.openApiSha256 ||
      value.baseline.generatedClientSha256 !== freeze.generatedClientSha256 ||
      value.baseline.apiArtifactSha256 !== freeze.artifacts.api.sha256 ||
      value.topology.data.seedEvidenceSha256 !== seed.seedSha256 ||
      value.topology.domain.hostnameSha256 !== sha256(config.domain.hostname) ||
      value.topology.domain.apiHostnameSha256 !== sha256(config.domain.apiHostname) ||
      value.topology.domain.hostedZoneIdSha256 !== sha256(config.domain.hostedZoneId) ||
      value.topology.domain.webCertificateArnSha256 !== sha256(config.domain.webCertificateArn) ||
      value.topology.domain.apiCertificateArnSha256 !== sha256(config.domain.apiCertificateArn) ||
      value.topology.access.baselineMode !== config.prereleaseAccess.mode ||
      value.topology.access.keyGroupIdSha256 !== sha256(config.prereleaseAccess.keyGroupId) ||
      value.topology.access.publicKeyIdSha256 !== sha256(config.prereleaseAccess.publicKeyId) ||
      value.topology.access.originTokenSecretArnSha256 !==
        sha256(config.prereleaseAccess.originTokenSecretArn) ||
      value.topology.access.originTokenSecretVersionIdSha256 !==
        sha256(config.prereleaseAccess.originTokenSecretVersionId) ||
      value.deploymentSha256 !== deployment.deploymentSha256 ||
      value.notificationSha256 !== notification.notificationSha256 ||
      value.activationEvidenceSha256 !== objectSha256(activation) ||
      value.disableEvidenceSha256 !== objectSha256(disable) ||
      value.approval.reviewerAlias !== approval.reviewerAlias ||
      value.approval.approvedAtUtc !== approval.approvedAtUtc ||
      value.approval.approvalEvidenceSha256 !== approval.approvalSha256 ||
      value.publication.anonymousWebStatus !== smoke.anonymousWebStatus ||
      value.publication.directApiStatus !== smoke.directApiStatus ||
      value.publication.schedulerState !== disable.schedulerState ||
      value.publication.state !== disable.publicationState ||
      value.publicReleaseEffects.trafficPublicAfterCapture !== disable.trafficPublicAfterCapture
    ) {
      fail('E7_BASELINE_CAPTURE_PROVENANCE_SEMANTICS_INVALID');
    }
    const bindings = [
      [BASELINE_EVIDENCE_FILENAMES[0], value.compatibility.apiContractEvidenceSha256],
      [BASELINE_EVIDENCE_FILENAMES[1], value.compatibility.pendingReconciliationEvidenceSha256],
      [BASELINE_EVIDENCE_FILENAMES[2], value.compatibility.smokeEvidenceSha256],
      [BASELINE_EVIDENCE_FILENAMES[3], value.compatibility.trafficLedgerSha256],
    ];
    if (bindings.some(([name, digest]) => fileSha256(path.join(directory, name)) !== digest)) {
      fail('E7_BASELINE_CAPTURE_EVIDENCE_DIGEST_MISMATCH');
    }
    if (
      [api, pending, smoke, ledger].some(
        (entry) =>
          entry.candidateSha !== value.baseline.candidateSha ||
          entry.releaseId !== value.baseline.releaseId ||
          entry.containsSensitiveData !== false,
      ) ||
      compatibilityEvidence(api, 'BASELINE_API_CONTRACT_COMPATIBILITY').openApiSha256 !==
        value.baseline.openApiSha256 ||
      api.openApiSha256 !== api.frozenOpenApiSha256 ||
      compatibilityEvidence(pending, 'BASELINE_PENDING_RECONCILIATION_COMPATIBILITY')
        .apiArtifactSha256 !== value.baseline.apiArtifactSha256 ||
      compatibilityEvidence(smoke, 'BASELINE_RESTRICTED_SMOKE').externalRequests !==
        BASELINE_REQUEST_LIMIT ||
      smoke.trafficRequestsUsed !== BASELINE_REQUEST_LIMIT ||
      smoke.trafficLedgerSha256 !== value.compatibility.trafficLedgerSha256 ||
      ledger.kind !== 'FULL_BASELINE_TRAFFIC_LEDGER' ||
      ledger.status !== 'COMPLETE' ||
      ledger.maxRequests !== BASELINE_REQUEST_LIMIT ||
      ledger.usedRequests !== BASELINE_REQUEST_LIMIT ||
      ledger.ledgerSha256 !== objectSha256(trafficLedgerBody(ledger))
    ) {
      fail('E7_BASELINE_CAPTURE_EVIDENCE_SEMANTICS_INVALID');
    }
  }
  return value;
};

const sourceProvenanceBody = (value) => {
  const body = { ...value };
  delete body.provenanceSha256;
  return body;
};

const baselineSourceResponseSummary = (value) => ({
  run: {
    id: Number(value.runId),
    runAttempt: value.runAttempt,
    path: value.workflowPath,
    event: value.event,
    headBranch: value.ref?.replace(/^refs\/heads\//u, ''),
    headSha: value.headSha,
    conclusion: value.conclusion,
  },
  artifact: {
    id: value.artifactId,
    name: value.artifactName,
    digest: value.artifactDigest,
    expired: value.artifactExpired,
  },
});

export const validateBaselineSourceProvenance = (
  value,
  { bundleIndex, capture, expectedArtifactId, expectedArtifactDigest } = {},
) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'repository',
      'workflowPath',
      'event',
      'ref',
      'headSha',
      'runId',
      'runAttempt',
      'conclusion',
      'artifactName',
      'artifactId',
      'artifactDigest',
      'artifactExpired',
      'bundleSha256',
      'responseSha256',
      'capturedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'provenanceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'BASELINE_SOURCE_ARTIFACT_PROVENANCE' ||
    value.status !== 'PASS' ||
    value.repository !== 'ivanmonsalve0404/async-checkout-demo' ||
    value.workflowPath !== BASELINE_WORKFLOW_PATH ||
    value.event !== 'workflow_dispatch' ||
    value.ref !== 'refs/heads/master' ||
    !SHA.test(value.headSha ?? '') ||
    !/^[1-9][0-9]{0,19}$/u.test(value.runId ?? '') ||
    !Number.isSafeInteger(value.runAttempt) ||
    value.runAttempt < 1 ||
    value.runAttempt > 100 ||
    value.conclusion !== 'success' ||
    value.artifactName !== 'stage7-previous-release' ||
    !Number.isSafeInteger(value.artifactId) ||
    value.artifactId < 1 ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.artifactDigest ?? '') ||
    value.artifactExpired !== false ||
    !SHA256.test(value.bundleSha256 ?? '') ||
    !SHA256.test(value.responseSha256 ?? '') ||
    value.responseSha256 !== sha256(JSON.stringify(baselineSourceResponseSummary(value))) ||
    !isoUtc(value.capturedAtUtc) ||
    !Number.isSafeInteger(value.externalRequests) ||
    value.externalRequests < 2 ||
    value.externalRequests > 102 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    value.provenanceSha256 !== objectSha256(sourceProvenanceBody(value)) ||
    (bundleIndex !== undefined &&
      (!object(bundleIndex) ||
        value.runId !== bundleIndex.sourceRunId ||
        value.runAttempt !== bundleIndex.sourceRunAttempt ||
        value.workflowPath !== bundleIndex.sourceWorkflowPath ||
        value.event !== bundleIndex.sourceEvent ||
        value.ref !== bundleIndex.sourceRef ||
        value.headSha !== bundleIndex.sourceHeadSha ||
        value.bundleSha256 !== bundleIndex.bundleSha256)) ||
    (capture !== undefined &&
      (!object(capture) || value.headSha !== capture.baseline?.candidateSha)) ||
    (expectedArtifactId !== undefined && value.artifactId !== Number(expectedArtifactId)) ||
    (expectedArtifactDigest !== undefined && value.artifactDigest !== expectedArtifactDigest)
  ) {
    fail('E7_BASELINE_SOURCE_PROVENANCE_INVALID');
  }
  return value;
};

const finalDisableProvenanceBody = (value) => {
  const body = { ...value };
  delete body.provenanceSha256;
  return body;
};

export const validateBaselineFinalDisableProvenance = (value, { bundleIndex, capture } = {}) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'sourceBundleSha256',
      'previousCandidateSha',
      'previousReleaseId',
      'recoveryArtifactId',
      'recoveryArtifactDigest',
      'evidenceSha256',
      'evidenceObjectSha256',
      'disabledAtUtc',
      'containsSensitiveData',
      'provenanceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'BASELINE_FINAL_DISABLE_PROVENANCE' ||
    value.status !== 'PASS' ||
    !SHA256.test(value.sourceBundleSha256 ?? '') ||
    !SHA.test(value.previousCandidateSha ?? '') ||
    !RELEASE_ID.test(value.previousReleaseId ?? '') ||
    !Number.isSafeInteger(value.recoveryArtifactId) ||
    value.recoveryArtifactId < 1 ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.recoveryArtifactDigest ?? '') ||
    !SHA256.test(value.evidenceSha256 ?? '') ||
    !SHA256.test(value.evidenceObjectSha256 ?? '') ||
    !isoUtc(value.disabledAtUtc) ||
    value.containsSensitiveData !== false ||
    value.provenanceSha256 !== objectSha256(finalDisableProvenanceBody(value)) ||
    (bundleIndex !== undefined &&
      (value.sourceBundleSha256 !== bundleIndex.bundleSha256 ||
        value.recoveryArtifactId !== bundleIndex.finalRecovery.artifactId ||
        value.recoveryArtifactDigest !== bundleIndex.finalRecovery.artifactDigest ||
        value.evidenceSha256 !== bundleIndex.finalRecovery.evidenceSha256 ||
        value.evidenceObjectSha256 !== bundleIndex.finalRecovery.evidenceObjectSha256 ||
        value.disabledAtUtc !== bundleIndex.finalRecovery.disabledAtUtc)) ||
    (capture !== undefined &&
      (value.previousCandidateSha !== capture.baseline?.candidateSha ||
        value.previousReleaseId !== capture.baseline?.releaseId))
  ) {
    fail('E7_BASELINE_FINAL_DISABLE_PROVENANCE_INVALID');
  }
  return value;
};

export const validateTargetWebRollbackDelta = ({
  baselineFreeze,
  capture,
  targetFreeze,
  targetWebDirectory,
}) => {
  let directory;
  let targetArtifact;
  let targetIndexSha256;
  let targetPublicConfigSha256;
  let targetImmutableInventory;
  let targetIndexSource;
  let targetPublicConfigSource;
  try {
    directory = checkedPath(targetWebDirectory, { directory: true });
    targetImmutableInventory = immutableWebInventory(directory);
    targetArtifact = hashArtifactPath(directory, { rootDirectory: path.dirname(directory) });
    targetIndexSource = readFileSync(checkedPath(path.join(directory, 'index.html')));
    targetPublicConfigSource = readFileSync(
      checkedPath(path.join(directory, 'public-config.json')),
    );
    targetIndexSha256 = sha256(targetIndexSource);
    targetPublicConfigSha256 = sha256(targetPublicConfigSource);
  } catch {
    fail('E7_BASELINE_TARGET_WEB_ARTIFACT_INVALID');
  }
  const frozenWeb = targetFreeze.artifacts.find(({ name }) => name === 'web');
  const baselineObjects = capture?.resources?.web?.objects;
  const baselineIndex = Array.isArray(baselineObjects)
    ? baselineObjects.find(({ key }) => key === 'index.html')
    : undefined;
  const baselinePublicConfig = Array.isArray(baselineObjects)
    ? baselineObjects.find(({ key }) => key === 'public-config.json')
    : undefined;
  validateBaselineFreeze(baselineFreeze);
  if (
    !validatePublicReleaseIdentity({
      indexSource: targetIndexSource,
      publicConfigSource: targetPublicConfigSource,
      releaseId: targetFreeze.releaseId,
    })
  ) {
    fail('E7_BASELINE_TARGET_WEB_RELEASE_IDENTITY_INVALID');
  }
  if (
    targetImmutableInventory.digestSha256 !== baselineFreeze.immutableWebInventory.digestSha256 ||
    targetImmutableInventory.totalFiles !== baselineFreeze.immutableWebInventory.totalFiles ||
    targetImmutableInventory.totalBytes !== baselineFreeze.immutableWebInventory.totalBytes ||
    JSON.stringify(targetImmutableInventory.files) !==
      JSON.stringify(baselineFreeze.immutableWebInventory.files)
  ) {
    fail('E7_BASELINE_TARGET_WEB_IMMUTABLE_CONTENT_CHANGED');
  }
  if (
    frozenWeb === undefined ||
    targetArtifact.kind !== frozenWeb.kind ||
    targetArtifact.files !== frozenWeb.files ||
    targetArtifact.bytes !== frozenWeb.bytes ||
    targetArtifact.sha256 !== frozenWeb.sha256 ||
    targetPublicConfigSha256 !== targetFreeze.publicConfigSha256 ||
    baselineObjects?.length !== 2 ||
    baselineIndex === undefined ||
    baselinePublicConfig === undefined ||
    !SHA256.test(baselineIndex.contentSha256 ?? '') ||
    !SHA256.test(baselinePublicConfig.contentSha256 ?? '')
  ) {
    fail('E7_BASELINE_TARGET_WEB_ARTIFACT_INVALID');
  }
  if (
    targetIndexSha256 === baselineIndex.contentSha256 ||
    targetPublicConfigSha256 === baselinePublicConfig.contentSha256
  ) {
    fail('E7_BASELINE_TARGET_WEB_ROLLBACK_NOT_DISTINCT');
  }
  return Object.freeze({ targetIndexSha256, targetPublicConfigSha256 });
};

export const bindBaselineForTarget = ({
  capture,
  captureFilename,
  evidenceDirectory,
  expectedCaptureSha256,
  bundleIndex,
  sourceProvenance,
  targetConfig,
  targetFreeze,
  targetWebDirectory,
  targetCompatibilityOutput,
}) => {
  if (fileSha256(checkedPath(captureFilename)) !== expectedCaptureSha256) {
    fail('E7_BASELINE_CROSS_RUN_DIGEST_MISMATCH');
  }
  validateBaselineCapture(capture, evidenceDirectory);
  validateBaselineSourceProvenance(sourceProvenance, { bundleIndex, capture });
  validateStage7Config(targetConfig, { now: new Date(targetConfig.window.startsAtUtc) });
  validateFreezeManifest(targetFreeze);
  const baselineFreeze = readJson(
    path.join(evidenceDirectory, BASELINE_PROVENANCE_FILENAMES.freeze),
  );
  const targetIac = targetFreeze.artifacts.find(({ name }) => name === 'iac');
  if (
    targetConfig.authorization.scope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    targetConfig.environment !== capture.environment ||
    targetConfig.aws.region !== capture.region ||
    sha256(targetConfig.aws.accountId) !== capture.accountSha256 ||
    targetFreeze.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    targetFreeze.candidateSha === capture.baseline.candidateSha ||
    targetFreeze.releaseId === capture.baseline.releaseId ||
    targetFreeze.releaseTag === capture.baseline.baselineVersion ||
    targetFreeze.openApiSha256 !== capture.baseline.openApiSha256 ||
    targetFreeze.generatedClientSha256 !== capture.baseline.generatedClientSha256 ||
    targetIac === undefined ||
    targetConfig.authorization.stacks.join('\0') !== capture.topology.stackNames.join('\0') ||
    objectSha256({
      hostnameSha256: sha256(targetConfig.domain.hostname),
      apiHostnameSha256: sha256(targetConfig.domain.apiHostname),
      hostedZoneIdSha256: sha256(targetConfig.domain.hostedZoneId),
      webCertificateArnSha256: sha256(targetConfig.domain.webCertificateArn),
      apiCertificateArnSha256: sha256(targetConfig.domain.apiCertificateArn),
    }) !== objectSha256(capture.topology.domain) ||
    targetConfig.prereleaseAccess.mode !== capture.topology.access.targetMode ||
    sha256(targetConfig.prereleaseAccess.originTokenSecretArn) !==
      capture.topology.access.originTokenSecretArnSha256 ||
    sha256(targetConfig.prereleaseAccess.originTokenSecretVersionId) !==
      capture.topology.access.originTokenSecretVersionIdSha256 ||
    capture.topology.data.schemaStrategy !== 'EXPAND_CONTRACT_N_AND_N_MINUS_1' ||
    capture.topology.runtime.apiFunctionName !== capture.resources.api.functionName ||
    capture.topology.runtime.apiAliasName !== capture.resources.api.aliasName ||
    capture.topology.runtime.workerFunctionName !== capture.resources.worker.functionName ||
    capture.topology.runtime.workerAliasName !== capture.resources.worker.aliasName ||
    capture.topology.runtime.bucketName !== capture.resources.web.bucketName ||
    capture.topology.runtime.distributionId !== capture.resources.web.distributionId
  ) {
    fail('E7_BASELINE_TARGET_BINDING_INVALID');
  }
  validateTargetWebRollbackDelta({
    baselineFreeze,
    capture,
    targetFreeze,
    targetWebDirectory,
  });
  const targetCompatibility = runTargetCompatibilityFocalTest({
    capture,
    targetFreeze,
    now: new Date(targetFreeze.builtAt),
  });
  const finalDisableProvenanceBodyValue = {
    schemaVersion: 1,
    stage: 7,
    kind: 'BASELINE_FINAL_DISABLE_PROVENANCE',
    status: 'PASS',
    sourceBundleSha256: bundleIndex.bundleSha256,
    previousCandidateSha: capture.baseline.candidateSha,
    previousReleaseId: capture.baseline.releaseId,
    recoveryArtifactId: bundleIndex.finalRecovery.artifactId,
    recoveryArtifactDigest: bundleIndex.finalRecovery.artifactDigest,
    evidenceSha256: bundleIndex.finalRecovery.evidenceSha256,
    evidenceObjectSha256: bundleIndex.finalRecovery.evidenceObjectSha256,
    disabledAtUtc: bundleIndex.finalRecovery.disabledAtUtc,
    containsSensitiveData: false,
  };
  const finalDisableProvenance = validateBaselineFinalDisableProvenance(
    {
      ...finalDisableProvenanceBodyValue,
      provenanceSha256: objectSha256(finalDisableProvenanceBodyValue),
    },
    { bundleIndex, capture },
  );
  const targetCompatibilityWithSource = {
    ...targetCompatibility,
    baselineBundleSha256: bundleIndex.bundleSha256,
    sourceArtifactProvenanceSha256: objectSha256(sourceProvenance),
    finalDisableEvidenceSha256: objectSha256(finalDisableProvenance),
  };
  const previous = createStage7PreviousReleaseManifest({
    schemaVersion: 1,
    stage: 7,
    kind: 'PREVIOUS_APPROVED_RELEASE',
    status: 'APPROVED_IMMUTABLE',
    capturedAtUtc: capture.capturedAtUtc,
    approvedAtUtc: capture.approval.approvedAtUtc,
    environment: capture.environment,
    region: capture.region,
    previous: {
      candidateSha: capture.baseline.candidateSha,
      candidateTreeSha: capture.baseline.candidateTreeSha,
      releaseId: capture.baseline.releaseId,
      releaseTag: capture.baseline.baselineVersion,
      configSha256: capture.baseline.configSha256,
      freezeManifestSha256: capture.baseline.freezeManifestSha256,
      assemblySha256: capture.baseline.assemblySha256,
    },
    target: {
      candidateSha: targetFreeze.candidateSha,
      candidateTreeSha: targetFreeze.candidateTreeSha,
      releaseId: targetFreeze.releaseId,
      releaseTag: targetFreeze.releaseTag,
      configSha256: objectSha256(targetConfig),
      freezeManifestSha256: targetFreeze.manifestSha256,
      assemblySha256: targetIac.sha256,
    },
    resources: capture.resources,
    compatibility: {
      status: capture.compatibility.status,
      schemaStrategy: capture.compatibility.schemaStrategy,
      dataRollback: capture.compatibility.dataRollback,
      apiContractEvidenceSha256: capture.compatibility.apiContractEvidenceSha256,
      pendingReconciliationEvidenceSha256:
        capture.compatibility.pendingReconciliationEvidenceSha256,
      smokeEvidenceSha256: capture.compatibility.smokeEvidenceSha256,
      smokeVerifiedAtUtc: capture.compatibility.smokeVerifiedAtUtc,
      providerEgressCapability: STAGE7_PROVIDER_EGRESS_CAPABILITY,
    },
    handoff: {
      sourceKind: 'BASELINE_BOOTSTRAP',
      sourceBundleSha256: bundleIndex.bundleSha256,
      sourceArtifactProvenanceSha256: objectSha256(sourceProvenance),
      targetCompatibilityEvidenceSha256: objectSha256(targetCompatibilityWithSource),
      finalDisableEvidenceSha256: objectSha256(finalDisableProvenance),
      predecessorManifestSha256: null,
    },
    approval: {
      status: 'APPROVED',
      reviewerAlias: capture.approval.reviewerAlias,
      approvalEvidenceSha256: capture.approval.approvalEvidenceSha256,
      releaseEvidenceSha256: capture.deploymentSha256,
    },
    containsSensitiveData: false,
  });
  if (targetCompatibilityOutput !== undefined) {
    writeJson(
      targetCompatibilityOutput,
      targetCompatibilityWithSource,
      'stage7-baseline-target-compatibility.json',
    );
  }
  return {
    previousRelease: previous,
    targetCompatibility: targetCompatibilityWithSource,
    finalDisableProvenance,
  };
};

const baselineBundleBody = (value) => {
  const body = { ...value };
  delete body.bundleSha256;
  return body;
};

export const validatePreviousReleaseBundle = ({
  directory,
  expectedBundleSha256,
  expectedRunId,
}) => {
  const root = checkedPath(directory, { directory: true });
  const index = readJson(path.join(root, BASELINE_BUNDLE_INDEX_FILENAME));
  const expectedFiles = [
    BASELINE_CAPTURE_FILENAME,
    BASELINE_FINAL_DISABLE_FILENAME,
    ...Object.values(BASELINE_PROVENANCE_FILENAMES),
    ...BASELINE_EVIDENCE_FILENAMES,
  ].toSorted();
  if (
    !exactKeys(index, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'artifactName',
      'sourceWorkflowPath',
      'sourceEvent',
      'sourceRef',
      'sourceHeadSha',
      'sourceRunId',
      'sourceRunAttempt',
      'captureSha256',
      'finalRecovery',
      'files',
      'immutable',
      'publicReleaseEffectsAllowed',
      'containsSensitiveData',
      'createdAtUtc',
      'bundleSha256',
    ]) ||
    index.schemaVersion !== 1 ||
    index.stage !== 7 ||
    index.kind !== 'STAGE7_PREVIOUS_RELEASE_BASELINE_BUNDLE' ||
    index.status !== 'APPROVED_IMMUTABLE_CLOSED_N_MINUS_1' ||
    index.artifactName !== 'stage7-previous-release' ||
    index.sourceWorkflowPath !== BASELINE_WORKFLOW_PATH ||
    index.sourceEvent !== 'workflow_dispatch' ||
    index.sourceRef !== 'refs/heads/master' ||
    !SHA.test(index.sourceHeadSha ?? '') ||
    !/^[1-9][0-9]{0,19}$/u.test(index.sourceRunId ?? '') ||
    !Number.isSafeInteger(index.sourceRunAttempt) ||
    index.sourceRunAttempt < 1 ||
    index.sourceRunAttempt > 100 ||
    !SHA256.test(index.captureSha256 ?? '') ||
    !exactKeys(index.finalRecovery, [
      'artifactId',
      'artifactDigest',
      'evidenceSha256',
      'evidenceObjectSha256',
      'disabledAtUtc',
    ]) ||
    !Number.isSafeInteger(index.finalRecovery.artifactId) ||
    index.finalRecovery.artifactId < 1 ||
    !/^sha256:[0-9a-f]{64}$/u.test(index.finalRecovery.artifactDigest ?? '') ||
    !SHA256.test(index.finalRecovery.evidenceSha256 ?? '') ||
    !SHA256.test(index.finalRecovery.evidenceObjectSha256 ?? '') ||
    !isoUtc(index.finalRecovery.disabledAtUtc) ||
    !exactKeys(index.files, expectedFiles) ||
    Object.entries(index.files).some(
      ([name, file]) =>
        !exactKeys(file, ['sha256', 'bytes']) ||
        !SHA256.test(file.sha256 ?? '') ||
        !Number.isSafeInteger(file.bytes) ||
        file.bytes < 1 ||
        fileSha256(path.join(root, name)) !== file.sha256 ||
        readFileSync(path.join(root, name)).length !== file.bytes,
    ) ||
    index.files[BASELINE_CAPTURE_FILENAME].sha256 !== index.captureSha256 ||
    index.immutable !== true ||
    index.publicReleaseEffectsAllowed !== false ||
    index.containsSensitiveData !== false ||
    !isoUtc(index.createdAtUtc) ||
    index.bundleSha256 !== objectSha256(baselineBundleBody(index)) ||
    (expectedBundleSha256 !== undefined && index.bundleSha256 !== expectedBundleSha256) ||
    (expectedRunId !== undefined && index.sourceRunId !== String(expectedRunId))
  ) {
    fail('E7_BASELINE_BUNDLE_INVALID');
  }
  const capture = readJson(path.join(root, BASELINE_CAPTURE_FILENAME));
  validateBaselineCapture(capture, root);
  const freeze = readJson(path.join(root, BASELINE_PROVENANCE_FILENAMES.freeze));
  const normalDisable = readJson(path.join(root, BASELINE_PROVENANCE_FILENAMES.disable));
  const finalDisable = readJson(path.join(root, BASELINE_FINAL_DISABLE_FILENAME));
  validateBaselineDisable(finalDisable, { freeze });
  if (
    index.files[BASELINE_FINAL_DISABLE_FILENAME].sha256 !== index.finalRecovery.evidenceSha256 ||
    objectSha256(finalDisable) !== index.finalRecovery.evidenceObjectSha256 ||
    finalDisable.disabledAtUtc !== index.finalRecovery.disabledAtUtc ||
    Date.parse(finalDisable.disabledAtUtc) < Date.parse(normalDisable.disabledAtUtc)
  ) {
    fail('E7_BASELINE_FINAL_DISABLE_BINDING_INVALID');
  }
  return { index, capture };
};

export const createPreviousReleaseBundle = ({
  capture,
  captureFilename,
  finalDisableFilename,
  recoveryArtifactId,
  recoveryArtifactDigest,
  evidenceDirectory,
  outputDirectory,
  sourceRunId,
  sourceRunAttempt,
  sourceWorkflowPath,
  sourceEvent,
  sourceRef,
  sourceHeadSha,
  now = new Date(),
}) => {
  const source = checkedPath(evidenceDirectory, { directory: true });
  const capturePath = checkedPath(captureFilename);
  if (objectSha256(readJson(capturePath)) !== objectSha256(capture)) {
    fail('E7_BASELINE_CAPTURE_FILE_DIGEST_MISMATCH');
  }
  validateBaselineCapture(capture, source);
  const freeze = readJson(path.join(source, BASELINE_PROVENANCE_FILENAMES.freeze));
  const normalDisable = readJson(path.join(source, BASELINE_PROVENANCE_FILENAMES.disable));
  const finalDisablePath = checkedPath(finalDisableFilename);
  const finalDisable = validateBaselineDisable(readJson(finalDisablePath), { freeze });
  if (
    !/^[1-9][0-9]{0,19}$/u.test(String(sourceRunId)) ||
    !Number.isSafeInteger(sourceRunAttempt) ||
    sourceRunAttempt < 1 ||
    sourceRunAttempt > 100 ||
    sourceWorkflowPath !== BASELINE_WORKFLOW_PATH ||
    sourceEvent !== 'workflow_dispatch' ||
    sourceRef !== 'refs/heads/master' ||
    sourceHeadSha !== capture.baseline.candidateSha ||
    !Number.isSafeInteger(Number(recoveryArtifactId)) ||
    Number(recoveryArtifactId) < 1 ||
    !/^sha256:[0-9a-f]{64}$/u.test(recoveryArtifactDigest ?? '') ||
    Date.parse(finalDisable.disabledAtUtc) < Date.parse(normalDisable.disabledAtUtc) ||
    !isoUtc(now.toISOString())
  ) {
    fail('E7_BASELINE_BUNDLE_RUN_IDENTITY_INVALID');
  }
  const output = checkedPath(outputDirectory, { mustExist: false });
  if (existsSync(output)) fail('E7_BASELINE_BUNDLE_OUTPUT_EXISTS');
  mkdirSync(output, { recursive: false, mode: 0o700 });
  try {
    const sources = {
      [BASELINE_CAPTURE_FILENAME]: capturePath,
      [BASELINE_FINAL_DISABLE_FILENAME]: finalDisablePath,
      ...Object.fromEntries(
        Object.values(BASELINE_PROVENANCE_FILENAMES).map((name) => [name, path.join(source, name)]),
      ),
      ...Object.fromEntries(
        BASELINE_EVIDENCE_FILENAMES.map((name) => [name, path.join(source, name)]),
      ),
    };
    const files = {};
    for (const [name, filename] of Object.entries(sources)) {
      const target = path.join(output, name);
      copyFileSync(checkedPath(filename), target, fsConstants.COPYFILE_EXCL);
      chmodSync(target, 0o600);
      assertSanitizedArtifactText(name, readFileSync(target, 'utf8'));
      files[name] = { sha256: fileSha256(target), bytes: readFileSync(target).length };
    }
    const body = {
      schemaVersion: 1,
      stage: 7,
      kind: 'STAGE7_PREVIOUS_RELEASE_BASELINE_BUNDLE',
      status: 'APPROVED_IMMUTABLE_CLOSED_N_MINUS_1',
      artifactName: 'stage7-previous-release',
      sourceWorkflowPath,
      sourceEvent,
      sourceRef,
      sourceHeadSha,
      sourceRunId: String(sourceRunId),
      sourceRunAttempt,
      captureSha256: files[BASELINE_CAPTURE_FILENAME].sha256,
      finalRecovery: {
        artifactId: Number(recoveryArtifactId),
        artifactDigest: recoveryArtifactDigest,
        evidenceSha256: files[BASELINE_FINAL_DISABLE_FILENAME].sha256,
        evidenceObjectSha256: objectSha256(finalDisable),
        disabledAtUtc: finalDisable.disabledAtUtc,
      },
      files,
      immutable: true,
      publicReleaseEffectsAllowed: false,
      containsSensitiveData: false,
      createdAtUtc: now.toISOString(),
    };
    writeJson(
      path.join(output, BASELINE_BUNDLE_INDEX_FILENAME),
      { ...body, bundleSha256: objectSha256(body) },
      BASELINE_BUNDLE_INDEX_FILENAME,
    );
    return validatePreviousReleaseBundle({ directory: output });
  } catch (error) {
    rmSync(output, { force: true, recursive: true });
    throw error;
  }
};

const commandResult = (program, arguments_, code, options = {}) => {
  try {
    return commandExecutor(program, arguments_, {
      cwd: workspaceRoot,
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
      ...options,
    });
  } catch (error) {
    if (options.allowFailure === true) {
      return { failed: true, stdout: `${error?.stdout ?? ''}`, stderr: `${error?.stderr ?? ''}` };
    }
    fail(code);
  }
};

const cdkProgram = () =>
  path.join(
    workspaceRoot,
    'infra',
    'node_modules',
    '.bin',
    process.platform === 'win32' ? 'cdk.cmd' : 'cdk',
  );

const awsJson = (arguments_, code) => {
  const source = commandResult('aws', [...arguments_, '--output', 'json', '--no-cli-pager'], code);
  try {
    return JSON.parse(source);
  } catch {
    fail(`${code}_RESPONSE_INVALID`);
  }
};

const operationContext = (config, freeze, { capability, now = new Date(), recovery = false }) => {
  validateBaselineConfig(config, { now, phase: recovery ? 'RECOVERY' : 'ACTIVE' });
  validateBaselineFreeze(freeze);
  const awsVersionSource = commandResult('aws', ['--version'], 'E7_BASELINE_AWS_VERSION_FAILED');
  const awsVersion = /aws-cli\/([0-9]+\.[0-9]+\.[0-9]+)/u.exec(awsVersionSource)?.[1];
  const packageManager = JSON.parse(
    readFileSync(path.join(workspaceRoot, 'package.json'), 'utf8'),
  ).packageManager;
  const cdkVersionSource = commandResult(
    cdkProgram(),
    ['--version'],
    'E7_BASELINE_CDK_VERSION_FAILED',
  );
  const cdkVersion = /^([0-9]+\.[0-9]+\.[0-9]+)/u.exec(cdkVersionSource.trim())?.[1];
  if (
    process.version !== freeze.toolchain.node ||
    packageManager !== freeze.toolchain.packageManager ||
    cdkVersion !== freeze.toolchain.cdk ||
    awsVersion !== freeze.toolchain.awsCli
  ) {
    fail('E7_BASELINE_TOOLCHAIN_DRIFT');
  }
  const expectedRole =
    capability === 'read'
      ? config.aws.roles.readRoleArn
      : capability === 'recovery'
        ? config.aws.roles.rollbackRoleArn
        : config.aws.roles.baselineRoleArn;
  const candidate = process.env.STAGE7_CANDIDATE_SHA;
  const releaseId = process.env.STAGE7_RELEASE_ID;
  if (
    process.env.GITHUB_ACTIONS !== 'true' ||
    process.env.GITHUB_EVENT_NAME !== 'workflow_dispatch' ||
    process.env.GITHUB_REF !== 'refs/heads/master' ||
    process.env.GITHUB_REPOSITORY !== 'ivanmonsalve0404/async-checkout-demo' ||
    process.env.GITHUB_SHA !== freeze.candidateSha ||
    candidate !== freeze.candidateSha ||
    releaseId !== freeze.releaseId ||
    process.env.STAGE7_AWS_ACCOUNT_ID !== config.aws.accountId ||
    process.env.STAGE7_AWS_REGION !== config.aws.region ||
    process.env.AWS_REGION !== config.aws.region ||
    process.env.AWS_DEFAULT_REGION !== config.aws.region ||
    !process.env.AWS_ACCESS_KEY_ID ||
    !process.env.AWS_SECRET_ACCESS_KEY ||
    !process.env.AWS_SESSION_TOKEN
  ) {
    fail('E7_BASELINE_OPERATION_CONTEXT_INVALID');
  }
  const caller = awsJson(['sts', 'get-caller-identity'], 'E7_BASELINE_STS_FAILED');
  const expectedName = expectedRole.split('/').at(-1);
  const assumedRolePrefix = `arn:aws:sts::${config.aws.accountId}:assumed-role/${expectedName}/`;
  const sessionName =
    typeof caller?.Arn === 'string' && caller.Arn.startsWith(assumedRolePrefix)
      ? caller.Arn.slice(assumedRolePrefix.length)
      : '';
  if (
    caller?.Account !== config.aws.accountId ||
    sessionName.length === 0 ||
    sessionName.includes('/')
  ) {
    fail('E7_BASELINE_CALLER_IDENTITY_MISMATCH');
  }
  if (
    capability === 'baseline' &&
    (process.env.STAGE7_PROTECTED_ENVIRONMENT !== 'assessment-release-baseline' ||
      process.env.CONFIRM_BASELINE !== 'true')
  ) {
    fail('E7_BASELINE_PROTECTED_APPROVAL_REQUIRED');
  }
  if (
    capability === 'recovery' &&
    process.env.STAGE7_PROTECTED_ENVIRONMENT !== 'assessment-release-recovery'
  ) {
    fail('E7_BASELINE_RECOVERY_ENVIRONMENT_REQUIRED');
  }
  return { callerSha256: sha256(caller.Arn), accountSha256: sha256(caller.Account) };
};

const stackDescription = (stackName, { allowMissing = false } = {}) => {
  const result = commandResult(
    'aws',
    [
      'cloudformation',
      'describe-stacks',
      '--stack-name',
      stackName,
      '--output',
      'json',
      '--no-cli-pager',
    ],
    'E7_BASELINE_STACK_DESCRIBE_FAILED',
    { allowFailure: true },
  );
  if (object(result) && result.failed === true) {
    const escapedName = stackName.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
    if (
      allowMissing &&
      new RegExp(`Stack with id ${escapedName} does not exist(?:\\.|$)`, 'u').test(
        `${result.stderr}\n${result.stdout}`,
      )
    ) {
      return null;
    }
    fail('E7_BASELINE_STACK_DESCRIBE_FAILED');
  }
  let parsed;
  try {
    parsed = JSON.parse(result);
  } catch {
    fail('E7_BASELINE_STACK_DESCRIBE_RESPONSE_INVALID');
  }
  if (!Array.isArray(parsed?.Stacks) || parsed.Stacks.length !== 1) {
    fail('E7_BASELINE_STACK_DESCRIBE_RESPONSE_INVALID');
  }
  return parsed.Stacks[0];
};

const stackParameters = (stack) =>
  Object.fromEntries(
    (stack.Parameters ?? []).map(({ ParameterKey, ParameterValue }) => [
      ParameterKey,
      ParameterValue,
    ]),
  );
const stackOutputs = (stack) =>
  Object.fromEntries(
    (stack.Outputs ?? []).map(({ OutputKey, OutputValue }) => [OutputKey, OutputValue]),
  );
const stackTags = (stack) =>
  Object.fromEntries((stack.Tags ?? []).map(({ Key, Value }) => [Key, Value]));

const assemblyTemplate = (assemblyPath, stackName) => {
  const assembly = checkedPath(assemblyPath, { directory: true });
  const manifest = readJson(path.join(assembly, 'manifest.json'));
  const artifact = manifest?.artifacts?.[stackName];
  const templateFile = artifact?.properties?.templateFile;
  if (
    artifact?.type !== 'aws:cloudformation:stack' ||
    typeof templateFile !== 'string' ||
    path.basename(templateFile) !== templateFile
  ) {
    fail('E7_BASELINE_ASSEMBLY_TEMPLATE_INVALID');
  }
  const template = readJson(path.join(assembly, templateFile));
  return { template, sha256: objectSha256(template) };
};

const liveTemplateSha256 = (stackName) => {
  const response = awsJson(
    ['cloudformation', 'get-template', '--stack-name', stackName, '--template-stage', 'Original'],
    'E7_BASELINE_STACK_TEMPLATE_READ_FAILED',
  );
  let template = response?.TemplateBody;
  if (typeof template === 'string') {
    try {
      template = JSON.parse(template);
    } catch {
      fail('E7_BASELINE_STACK_TEMPLATE_INVALID');
    }
  }
  if (!object(template)) fail('E7_BASELINE_STACK_TEMPLATE_INVALID');
  return objectSha256(template);
};

const certificateCovers = (name, hostname) => {
  const source = String(name ?? '').toLowerCase();
  const target = String(hostname ?? '').toLowerCase();
  if (source === target) return true;
  if (!source.startsWith('*.')) return false;
  const suffix = source.slice(2);
  return target.endsWith(`.${suffix}`) && target.split('.').length === suffix.split('.').length + 1;
};

const preflightBody = (value) => {
  const body = { ...value };
  delete body.preflightSha256;
  return body;
};

export const validateBaselineAwsPreflight = (value, { config, freeze }) => {
  if (
    freeze.configSha256 !== objectSha256(config) ||
    freeze.runtimeSecretVersionIdSha256 !==
      sha256(config.prereleaseAccess.originTokenSecretVersionId) ||
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'configSha256',
      'freezeManifestSha256',
      'hostedZone',
      'certificates',
      'restrictedAccess',
      'bootstrap',
      'capacity',
      'costGuard',
      'notificationConfirmation',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'verifiedAtUtc',
      'preflightSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_AWS_PREFLIGHT' ||
    value.status !== 'PASS_CLOSED_BASELINE_ONLY' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.configSha256 !== objectSha256(config) ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    !exactKeys(value.hostedZone, ['idSha256', 'nameSha256', 'public', 'targetRecordsAbsent']) ||
    value.hostedZone.idSha256 !== sha256(config.domain.hostedZoneId) ||
    value.hostedZone.nameSha256 !== sha256(`${config.domain.hostedZoneName}.`) ||
    value.hostedZone.public !== true ||
    value.hostedZone.targetRecordsAbsent !== true ||
    !Array.isArray(value.certificates) ||
    value.certificates.length !== 2 ||
    value.certificates.some(
      (certificate) =>
        !exactKeys(certificate, ['purpose', 'region', 'arnSha256', 'hostnameSha256', 'status']) ||
        certificate.status !== 'ISSUED' ||
        !SHA256.test(certificate.arnSha256 ?? '') ||
        !SHA256.test(certificate.hostnameSha256 ?? ''),
    ) ||
    !exactKeys(value.restrictedAccess, [
      'bindingSha256',
      'keyGroupSha256',
      'publicKeySha256',
      'algorithm',
      'secretArnSha256',
      'secretVersionIdSha256',
      'secretStatus',
      'kmsKeyMode',
      'rotationDuringWindow',
    ]) ||
    value.restrictedAccess.bindingSha256 !== accessBindingSha256(config) ||
    value.restrictedAccess.algorithm !== 'RSA' ||
    value.restrictedAccess.secretArnSha256 !==
      sha256(config.prereleaseAccess.originTokenSecretArn) ||
    value.restrictedAccess.secretVersionIdSha256 !==
      sha256(config.prereleaseAccess.originTokenSecretVersionId) ||
    value.restrictedAccess.secretStatus !== 'ACTIVE' ||
    value.restrictedAccess.kmsKeyMode !== 'AWS_MANAGED_SECRETS_MANAGER' ||
    value.restrictedAccess.rotationDuringWindow !== 'FORBIDDEN' ||
    !exactKeys(value.bootstrap, ['status', 'version', 'stackIdSha256']) ||
    value.bootstrap.status !== 'PASS' ||
    !Number.isSafeInteger(value.bootstrap.version) ||
    value.bootstrap.version < 14 ||
    !SHA256.test(value.bootstrap.stackIdSha256 ?? '') ||
    !exactKeys(value.capacity, [
      'lambdaReservedRequired',
      'lambdaConcurrentLimit',
      'lambdaReservedInUse',
      'remainingAfterBaseline',
    ]) ||
    value.capacity.lambdaReservedRequired !== 6 ||
    !Number.isSafeInteger(value.capacity.lambdaConcurrentLimit) ||
    !Number.isSafeInteger(value.capacity.lambdaReservedInUse) ||
    !Number.isSafeInteger(value.capacity.remainingAfterBaseline) ||
    value.capacity.remainingAfterBaseline < 100 ||
    !exactKeys(value.costGuard, ['budgetContractSha256', 'maxUsd', 'upperBoundUsd']) ||
    value.costGuard.budgetContractSha256 !== objectSha256(config.budget) ||
    value.costGuard.maxUsd !== config.budget.maxUsd ||
    !Number.isFinite(value.costGuard.upperBoundUsd) ||
    value.costGuard.upperBoundUsd <= 0 ||
    value.costGuard.upperBoundUsd > config.budget.maxUsd ||
    value.notificationConfirmation !== 'REQUIRED_AFTER_DEPLOY_BEFORE_ACTIVATION' ||
    !Number.isSafeInteger(value.externalRequests) ||
    value.externalRequests < 11 ||
    value.externalRequests > 110 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    !isoUtc(value.verifiedAtUtc) ||
    value.preflightSha256 !== objectSha256(preflightBody(value))
  ) {
    fail('E7_BASELINE_AWS_PREFLIGHT_INVALID');
  }
  return value;
};

export const createBaselineAwsPreflight = ({ config, freeze, now = new Date() }) => {
  operationContext(config, freeze, { capability: 'read', now });
  const zone = awsJson(
    ['route53', 'get-hosted-zone', '--id', config.domain.hostedZoneId],
    'E7_BASELINE_HOSTED_ZONE_READ_FAILED',
  );
  const expectedZoneName = `${config.domain.hostedZoneName}.`;
  if (
    zone?.HostedZone?.Id !== `/hostedzone/${config.domain.hostedZoneId}` ||
    zone?.HostedZone?.Name?.toLowerCase() !== expectedZoneName.toLowerCase() ||
    zone?.HostedZone?.Config?.PrivateZone !== false
  ) {
    fail('E7_BASELINE_HOSTED_ZONE_INVALID');
  }
  const recordSets = [];
  const seenDnsTokens = new Set();
  let dnsToken;
  let dnsPages = 0;
  for (; dnsPages < 100; dnsPages += 1) {
    const records = awsJson(
      [
        'route53',
        'list-resource-record-sets',
        '--hosted-zone-id',
        config.domain.hostedZoneId,
        '--max-items',
        '100',
        ...(dnsToken === undefined ? [] : ['--starting-token', dnsToken]),
      ],
      'E7_BASELINE_DNS_READ_FAILED',
    );
    if (!Array.isArray(records?.ResourceRecordSets)) fail('E7_BASELINE_DNS_READ_INVALID');
    recordSets.push(...records.ResourceRecordSets);
    const next = records.NextToken;
    if (next === undefined) break;
    if (typeof next !== 'string' || next.length === 0 || seenDnsTokens.has(next)) {
      fail('E7_BASELINE_DNS_PAGINATION_INVALID');
    }
    seenDnsTokens.add(next);
    dnsToken = next;
  }
  if (
    dnsPages >= 100 ||
    recordSets.some(
      (record) =>
        [config.domain.hostname, config.domain.apiHostname].includes(
          String(record?.Name ?? '')
            .replace(/\.$/u, '')
            .toLowerCase(),
        ) && ['A', 'AAAA', 'CNAME'].includes(record?.Type),
    )
  ) {
    fail('E7_BASELINE_DNS_TARGET_CONFLICT');
  }
  const certificates = [
    {
      purpose: 'WEB_CLOUDFRONT',
      region: 'us-east-1',
      arn: config.domain.webCertificateArn,
      hostname: config.domain.hostname,
    },
    {
      purpose: 'API_REGIONAL',
      region: config.aws.region,
      arn: config.domain.apiCertificateArn,
      hostname: config.domain.apiHostname,
    },
  ].map((expected) => {
    const response = awsJson(
      [
        'acm',
        'describe-certificate',
        '--certificate-arn',
        expected.arn,
        '--region',
        expected.region,
      ],
      'E7_BASELINE_CERTIFICATE_READ_FAILED',
    );
    const certificate = response?.Certificate;
    const names = [certificate?.DomainName, ...(certificate?.SubjectAlternativeNames ?? [])];
    if (
      certificate?.CertificateArn !== expected.arn ||
      certificate?.Status !== 'ISSUED' ||
      !names.some((name) => certificateCovers(name, expected.hostname)) ||
      Date.parse(certificate?.NotAfter ?? '') <= Date.parse(config.cleanup.expiresAtUtc)
    ) {
      fail('E7_BASELINE_CERTIFICATE_INVALID');
    }
    return {
      purpose: expected.purpose,
      region: expected.region,
      arnSha256: sha256(expected.arn),
      hostnameSha256: sha256(expected.hostname),
      status: 'ISSUED',
    };
  });
  const keyGroup = awsJson(
    ['cloudfront', 'get-key-group', '--id', config.prereleaseAccess.keyGroupId],
    'E7_BASELINE_KEY_GROUP_READ_FAILED',
  );
  const publicKey = awsJson(
    ['cloudfront', 'get-public-key', '--id', config.prereleaseAccess.publicKeyId],
    'E7_BASELINE_PUBLIC_KEY_READ_FAILED',
  );
  const encodedKey = publicKey?.PublicKey?.PublicKeyConfig?.EncodedKey;
  let key;
  try {
    key = createPublicKey(encodedKey);
  } catch {
    fail('E7_BASELINE_PUBLIC_KEY_INVALID');
  }
  if (
    keyGroup?.KeyGroup?.Id !== config.prereleaseAccess.keyGroupId ||
    keyGroup?.KeyGroup?.KeyGroupConfig?.Items?.join('\0') !== config.prereleaseAccess.publicKeyId ||
    publicKey?.PublicKey?.Id !== config.prereleaseAccess.publicKeyId ||
    key.asymmetricKeyType !== 'rsa' ||
    (key.asymmetricKeyDetails?.modulusLength ?? 0) < 2048
  ) {
    fail('E7_BASELINE_RESTRICTED_ACCESS_AWS_INVALID');
  }
  const secret = awsJson(
    [
      'secretsmanager',
      'describe-secret',
      '--secret-id',
      config.prereleaseAccess.originTokenSecretArn,
    ],
    'E7_BASELINE_ORIGIN_SECRET_READ_FAILED',
  );
  if (
    secret?.ARN !== config.prereleaseAccess.originTokenSecretArn ||
    secret?.DeletedDate !== undefined ||
    secret?.OwningService !== undefined ||
    secret?.KmsKeyId !== undefined ||
    secret?.RotationEnabled !== false
  ) {
    fail('E7_BASELINE_ORIGIN_SECRET_INVALID');
  }
  const currentVersions = Object.entries(secret.VersionIdsToStages ?? {}).filter(
    ([, stages]) => Array.isArray(stages) && stages.includes('AWSCURRENT'),
  );
  if (
    currentVersions.length !== 1 ||
    currentVersions[0][0] !== config.prereleaseAccess.originTokenSecretVersionId
  ) {
    fail('E7_BASELINE_ORIGIN_SECRET_VERSION_INVALID');
  }
  const bootstrapStack = stackDescription('CDKToolkit');
  const bootstrapOutputs = stackOutputs(bootstrapStack);
  const bootstrapVersion = Number(bootstrapOutputs.BootstrapVersion);
  if (!Number.isSafeInteger(bootstrapVersion) || bootstrapVersion < 14) {
    fail('E7_BASELINE_CDK_BOOTSTRAP_INVALID');
  }
  const quota = awsJson(
    [
      'service-quotas',
      'get-service-quota',
      '--service-code',
      'lambda',
      '--quota-code',
      'L-B99A9384',
    ],
    'E7_BASELINE_LAMBDA_QUOTA_READ_FAILED',
  );
  const settings = awsJson(
    ['lambda', 'get-account-settings'],
    'E7_BASELINE_LAMBDA_SETTINGS_READ_FAILED',
  );
  const lambdaLimit = Number(quota?.Quota?.Value);
  const concurrentLimit = Number(settings?.AccountLimit?.ConcurrentExecutions);
  const unreserved = Number(settings?.AccountLimit?.UnreservedConcurrentExecutions);
  const reservedInUse = concurrentLimit - unreserved;
  if (
    !Number.isSafeInteger(lambdaLimit) ||
    !Number.isSafeInteger(concurrentLimit) ||
    !Number.isSafeInteger(unreserved) ||
    lambdaLimit !== concurrentLimit ||
    reservedInUse < 0 ||
    unreserved < 106
  ) {
    fail('E7_BASELINE_LAMBDA_CAPACITY_INSUFFICIENT');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_AWS_PREFLIGHT',
    status: 'PASS_CLOSED_BASELINE_ONLY',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    configSha256: objectSha256(config),
    freezeManifestSha256: freeze.manifestSha256,
    hostedZone: {
      idSha256: sha256(config.domain.hostedZoneId),
      nameSha256: sha256(expectedZoneName),
      public: true,
      targetRecordsAbsent: true,
    },
    certificates,
    restrictedAccess: {
      bindingSha256: accessBindingSha256(config),
      keyGroupSha256: sha256(config.prereleaseAccess.keyGroupId),
      publicKeySha256: sha256(config.prereleaseAccess.publicKeyId),
      algorithm: 'RSA',
      secretArnSha256: sha256(config.prereleaseAccess.originTokenSecretArn),
      secretVersionIdSha256: sha256(config.prereleaseAccess.originTokenSecretVersionId),
      secretStatus: 'ACTIVE',
      kmsKeyMode: 'AWS_MANAGED_SECRETS_MANAGER',
      rotationDuringWindow: 'FORBIDDEN',
    },
    bootstrap: {
      status: 'PASS',
      version: bootstrapVersion,
      stackIdSha256: sha256(bootstrapStack.StackId),
    },
    capacity: {
      lambdaReservedRequired: 6,
      lambdaConcurrentLimit: concurrentLimit,
      lambdaReservedInUse: reservedInUse,
      remainingAfterBaseline: unreserved - 6,
    },
    costGuard: {
      budgetContractSha256: objectSha256(config.budget),
      maxUsd: config.budget.maxUsd,
      upperBoundUsd: Math.min(config.budget.maxUsd, 10),
    },
    notificationConfirmation: 'REQUIRED_AFTER_DEPLOY_BEFORE_ACTIVATION',
    externalRequests: 10 + dnsPages + 1,
    mutationsPerformed: 0,
    containsSensitiveData: false,
    verifiedAtUtc: now.toISOString(),
  };
  return validateBaselineAwsPreflight(
    { ...body, preflightSha256: objectSha256(body) },
    { config, freeze },
  );
};

const cdkContexts = (config, freeze) => {
  const values = {
    projectName: 'checkout',
    environment: config.environment,
    region: config.aws.region,
    releaseId: freeze.releaseId,
    candidateSha: freeze.candidateSha,
    owner: config.authorization.ownerAlias,
    expiresOn: config.cleanup.expiresAtUtc.slice(0, 10),
    cleanupExpiresAtUtc: config.cleanup.expiresAtUtc,
    paymentAdapter: 'sandbox',
    paymentsEnabled: 'true',
    tokenizationMode: 'direct_jwe',
    schedulerEnabled: 'false',
    sandboxAuthorizedUntilUtc: config.authorization.expiresAtUtc,
    pointInTimeRecoveryEnabled: 'true',
    publicationMode: 'FULL_BASELINE_CLOSED',
    baselineConfigSha256: objectSha256(config),
    prereleaseKeyGroupId: config.prereleaseAccess.keyGroupId,
    prereleasePublicKeyId: config.prereleaseAccess.publicKeyId,
    budgetMaxUsd: config.budget.maxUsd.toFixed(2),
    budgetWarningUsd: config.budget.warningUsd.map((amount) => amount.toFixed(2)).join(','),
    apiArtifactPath: path.join(workspaceRoot, 'output/release/build/api'),
    workerArtifactPath: path.join(workspaceRoot, 'output/release/build/worker'),
    webArtifactPath: path.join(workspaceRoot, 'output/release/build/web'),
    runtimeSecretArn: config.prereleaseAccess.originTokenSecretArn,
    runtimeSecretVersionId: config.prereleaseAccess.originTokenSecretVersionId,
    hostedZoneId: config.domain.hostedZoneId,
    hostedZoneName: config.domain.hostedZoneName,
    webDomainName: config.domain.hostname,
    webCertificateArn: config.domain.webCertificateArn,
    apiDomainName: config.domain.apiHostname,
    apiCertificateArn: config.domain.apiCertificateArn,
  };
  return Object.entries(values).flatMap(([key, value]) => ['--context', `${key}=${value}`]);
};

const assertFrozenArtifacts = (freeze, app) => {
  const paths = {
    web: path.join(workspaceRoot, 'output/release/build/web'),
    api: path.join(workspaceRoot, 'output/release/build/api'),
    worker: path.join(workspaceRoot, 'output/release/build/worker'),
    iac: checkedPath(app, { directory: true }),
  };
  for (const [name, filename] of Object.entries(paths)) {
    const actual = hashArtifactPath(filename);
    const expected = freeze.artifacts[name];
    if (
      actual.sha256 !== expected?.sha256 ||
      actual.files !== expected.files ||
      actual.bytes !== expected.bytes
    ) {
      fail('E7_BASELINE_FROZEN_ARTIFACT_MISMATCH');
    }
  }
  if (freeze.assemblySha256 !== freeze.artifacts.iac.sha256) {
    fail('E7_BASELINE_ASSEMBLY_BINDING_INVALID');
  }
  return paths;
};

export const synthBaseline = ({ config, freezeIdentity, output }) => {
  const target = checkedPath(output, { mustExist: false });
  if (existsSync(target)) fail('E7_BASELINE_SYNTH_OUTPUT_EXISTS');
  mkdirSync(path.dirname(target), { recursive: true });
  const placeholder = {
    ...freezeIdentity,
    artifacts: { iac: { sha256: '0'.repeat(64) } },
  };
  commandResult(
    cdkProgram(),
    [
      'synth',
      ...expectedStacks(),
      '--output',
      target,
      '--asset-metadata',
      'false',
      '--path-metadata',
      'false',
      '--version-reporting',
      'false',
      '--lookups',
      'false',
      '--quiet',
      ...cdkContexts(config, placeholder),
    ],
    'E7_BASELINE_CDK_SYNTH_FAILED',
  );
  return target;
};

const diffRisks = (source) => ({
  statefulReplacement:
    /AWS::(?:DynamoDB::Table|S3::Bucket|SecretsManager::Secret)/u.test(source) &&
    /requires replacement|will be replaced|\[\+\/-\]/iu.test(source),
  statefulDeletion:
    /AWS::(?:DynamoDB::Table|S3::Bucket|SecretsManager::Secret)/u.test(source) &&
    /\[-\]|will be destroyed|will be deleted|resource deletion/iu.test(source),
  rollbackControlReplacement:
    /AWS::(?:Lambda::Function|Lambda::Alias|CloudFront::Distribution)/u.test(source) &&
    /requires replacement|will be replaced|\[\+\/-\]/iu.test(source),
  destructiveChangeMentioned: /\[-\]|will be destroyed|will be deleted|resource deletion/iu.test(
    source,
  ),
  iamOrPolicyReviewRequired:
    /IAM Statement Changes|Security Group Changes|Resource Policy Changes/iu.test(source),
});

export const createBaselinePlanAws = ({
  config,
  freeze,
  iamEvidence,
  awsPreflight,
  rawDiffOutput,
}) => {
  operationContext(config, freeze, { capability: 'read' });
  validateBaselineAwsPreflight(awsPreflight, { config, freeze });
  const assembly = checkedPath(rawDiffOutput.app, { directory: true });
  assertFrozenArtifacts(freeze, assembly);
  const preDeploymentState = {};
  let missingSeen = false;
  for (const stackName of expectedStacks()) {
    const stack = stackDescription(stackName, { allowMissing: true });
    if (stack === null) {
      missingSeen = true;
      preDeploymentState[stackName] = 'ABSENT';
      continue;
    }
    if (missingSeen) fail('E7_BASELINE_PARTIAL_STACK_ORDER_INVALID');
    validateResumableStack({ stackName, stack, config, freeze, assembly });
    preDeploymentState[stackName] = 'EXISTING_BASELINE_EXACT';
  }
  validateBaselinePreDeploymentState(preDeploymentState);
  const outputs = [];
  for (const stackName of expectedStacks().filter(
    (name) => preDeploymentState[name] === 'ABSENT',
  )) {
    const result = commandResult(
      cdkProgram(),
      [
        'diff',
        stackName,
        '--app',
        assembly,
        '--method',
        'template',
        '--fail',
        'false',
        '--exclusively',
        '--no-color',
        ...cdkContexts(config, freeze),
      ],
      'E7_BASELINE_CDK_DIFF_FAILED',
    );
    outputs.push(`===== ${stackName} =====\n${result.trim()}`);
  }
  const raw = `${outputs.join('\n')}\n`;
  assertSanitizedArtifactText('stage7-baseline-infra-diff.txt', raw);
  const target = checkedPath(rawDiffOutput.filename, { mustExist: false });
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, raw, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
  const risks = diffRisks(raw);
  if (
    risks.statefulReplacement ||
    risks.statefulDeletion ||
    risks.rollbackControlReplacement ||
    risks.destructiveChangeMentioned
  ) {
    fail('E7_BASELINE_DIFF_RISK_FORBIDDEN');
  }
  const iam = iamEvidence?.iamEffectivePermissions ?? iamEvidence;
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_CLOSED_DIFF',
    status: 'READY_FOR_PROTECTED_BASELINE_REVIEW',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    configSha256: objectSha256(config),
    freezeManifestSha256: freeze.manifestSha256,
    assemblySha256: freeze.assemblySha256,
    iamEvidenceSha256: objectSha256(iamEvidence),
    iamBindingSha256: iam?.bindingSha256,
    awsPreflightSha256: awsPreflight.preflightSha256,
    stacks: expectedStacks(),
    preDeploymentState,
    diffSha256: sha256(raw.trim()),
    rawDiffArtifactSha256: sha256(raw),
    risks,
    publicationState: 'DISABLED',
    publicReleaseEffectsAllowed: false,
    generatedAtUtc: new Date().toISOString(),
    containsSensitiveData: false,
  };
  return validateBaselinePlan(
    { ...body, planSha256: objectSha256(body) },
    { config, freeze, iamEvidence, awsPreflight },
  );
};

const githubApprovalForBaseline = (value, { freeze, plan }) => {
  if (
    value?.schemaVersion !== 1 ||
    value?.stage !== 7 ||
    value?.kind !== 'GITHUB_ENVIRONMENT_APPROVAL' ||
    value?.status !== 'PASS' ||
    value?.scope !== 'baseline' ||
    value?.candidateSha !== freeze.candidateSha ||
    value?.releaseId !== freeze.releaseId ||
    value?.environment !== 'assessment-release-baseline' ||
    value?.repository !== 'ivanmonsalve0404/async-checkout-demo' ||
    value?.runId !== process.env.GITHUB_RUN_ID ||
    value?.runAttempt !== Number(process.env.GITHUB_RUN_ATTEMPT) ||
    value?.reviewed !== true ||
    value?.reviewState !== 'approved' ||
    value?.iamReviewAttested !== true ||
    value?.iamReviewedDiffSha256 !== plan.rawDiffArtifactSha256 ||
    !safeAlias(value?.reviewerAlias) ||
    !isoUtc(value?.capturedAtUtc) ||
    value?.externalRequests !== 1 ||
    value?.mutationsPerformed !== 0 ||
    value?.containsSensitiveData !== false
  ) {
    fail('E7_BASELINE_GITHUB_APPROVAL_INVALID');
  }
  return value;
};

export const createBaselineApproval = ({
  config,
  freeze,
  plan,
  githubApproval,
  githubApprovalFilename,
}) => {
  githubApprovalForBaseline(githubApproval, { freeze, plan });
  const githubApprovalPath = checkedPath(githubApprovalFilename);
  if (objectSha256(readJson(githubApprovalPath)) !== objectSha256(githubApproval)) {
    fail('E7_BASELINE_GITHUB_APPROVAL_FILE_MISMATCH');
  }
  const githubApprovalEvidenceSha256 = fileSha256(githubApprovalPath);
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_CLOSED_APPROVAL',
    status: 'APPROVED_FOR_ONE_CLOSED_BASELINE',
    scope: 'baseline',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    configSha256: objectSha256(config),
    freezeManifestSha256: freeze.manifestSha256,
    approvedPlanSha256: plan.planSha256,
    approvedDiffSha256: plan.rawDiffArtifactSha256,
    iamBindingSha256: plan.iamBindingSha256,
    githubApprovalEvidenceSha256,
    runId: githubApproval.runId,
    runAttempt: githubApproval.runAttempt,
    reviewerAlias: githubApproval.reviewerAlias,
    approvedAtUtc: githubApproval.capturedAtUtc,
    protectedEnvironment: 'assessment-release-baseline',
    trafficAuthorization: {
      targetSha256: sha256(`https://${config.domain.hostname}`),
      maxRequests: config.traffic.maxRequests,
    },
    publicationState: 'DISABLED',
    publicReleaseEffectsAllowed: false,
    destructiveActionsAllowed: false,
    containsSensitiveData: false,
  };
  return validateBaselineApproval(
    { ...body, approvalSha256: objectSha256(body) },
    { config, freeze, plan },
  );
};

const validateBaselineMutationChain = ({
  config,
  freeze,
  awsPreflight,
  iamEvidence,
  plan,
  approval,
  githubApproval,
  rawDiffFilename,
  githubApprovalFilename,
  recovery = false,
  now = new Date(),
}) => {
  validateBaselineConfig(config, { now, phase: recovery ? 'RECOVERY' : 'ACTIVE' });
  validateBaselinePlan(plan, { config, freeze, iamEvidence, awsPreflight });
  validateBaselineApproval(approval, { config, freeze, plan });
  githubApprovalForBaseline(githubApproval, { freeze, plan });
  if (
    fileSha256(checkedPath(rawDiffFilename)) !== plan.rawDiffArtifactSha256 ||
    fileSha256(checkedPath(githubApprovalFilename)) !== approval.githubApprovalEvidenceSha256 ||
    githubApproval.runId !== approval.runId ||
    githubApproval.runAttempt !== approval.runAttempt
  ) {
    fail('E7_BASELINE_MUTATION_CHAIN_INVALID');
  }
  return true;
};

const validatePlanFiles = ({
  config,
  freeze,
  plan,
  iamEvidence,
  awsPreflight,
  rawDiffFilename,
}) => {
  validateBaselinePlan(plan, { config, freeze, iamEvidence, awsPreflight });
  if (fileSha256(checkedPath(rawDiffFilename)) !== plan.rawDiffArtifactSha256) {
    fail('E7_BASELINE_RAW_DIFF_DIGEST_MISMATCH');
  }
};

const publicationOf = (stack) => stackParameters(stack).PublicationState ?? 'NOT_APPLICABLE';

const validateLiveBaselineStack = ({
  stackName,
  stack,
  config,
  freeze,
  publicationState,
  assembly,
}) => {
  const outputs = stackOutputs(stack);
  const tags = stackTags(stack);
  if (
    !['CREATE_COMPLETE', 'UPDATE_COMPLETE'].includes(stack.StackStatus) ||
    stack.EnableTerminationProtection !== true ||
    outputs.CandidateSha !== freeze.candidateSha ||
    outputs.ReleaseId !== freeze.releaseId ||
    outputs.BaselineConfigSha256 !== objectSha256(config) ||
    tags.ManagedBy !== 'cdk' ||
    tags.Environment !== config.environment ||
    tags.CandidateSha !== freeze.candidateSha ||
    tags.ReleaseId !== freeze.releaseId ||
    publicationOf(stack) !== publicationState ||
    (stackName.endsWith('-api') &&
      (outputs.SchedulerStatus !== 'DISABLED_EXPLICIT' ||
        outputs.ApiArtifactSha256 !== freeze.artifacts.api.sha256 ||
        outputs.WorkerArtifactSha256 !== freeze.artifacts.worker.sha256)) ||
    (stackName.endsWith('-web') && outputs.WebArtifactSha256 !== freeze.artifacts.web.sha256)
  ) {
    fail('E7_BASELINE_LIVE_STACK_IDENTITY_MISMATCH');
  }
  if (
    assembly !== undefined &&
    liveTemplateSha256(stackName) !== assemblyTemplate(assembly, stackName).sha256
  ) {
    fail('E7_BASELINE_LIVE_TEMPLATE_MISMATCH');
  }
  return stack;
};

const validateResumableStack = ({ stackName, stack, config, freeze, assembly }) =>
  validateLiveBaselineStack({
    stackName,
    stack,
    config,
    freeze,
    publicationState:
      stackName.endsWith('-api') || stackName.endsWith('-web') ? 'DISABLED' : 'NOT_APPLICABLE',
    assembly,
  });

export const deployBaselineAws = ({
  config,
  freeze,
  plan,
  approval,
  iamEvidence,
  awsPreflight,
  githubApproval,
  githubApprovalFilename,
  rawDiffFilename,
  app,
  now = new Date(),
}) => {
  validateBaselineMutationChain({
    config,
    freeze,
    awsPreflight,
    iamEvidence,
    plan,
    approval,
    githubApproval,
    rawDiffFilename,
    githubApprovalFilename,
    now,
  });
  validatePlanFiles({ config, freeze, plan, iamEvidence, awsPreflight, rawDiffFilename });
  validateBaselineApproval(approval, { config, freeze, plan });
  operationContext(config, freeze, { capability: 'baseline', now });
  const alertEmail = process.env.STAGE7_ALERT_EMAIL;
  if (
    typeof alertEmail !== 'string' ||
    alertEmail.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(alertEmail) ||
    sha256(alertEmail) !== config.budget.alertDestinationSha256
  ) {
    fail('E7_BASELINE_ALERT_DESTINATION_REQUIRED');
  }
  const assembly = checkedPath(app, { directory: true });
  assertFrozenArtifacts(freeze, assembly);
  mkdirSync(path.join(workspaceRoot, '.tmp'), { recursive: true, mode: 0o700 });
  const deployed = [];
  let missingSeen = false;
  for (const stackName of expectedStacks()) {
    const stack = stackDescription(stackName, { allowMissing: true });
    if (stack === null) {
      missingSeen = true;
      continue;
    }
    if (missingSeen) fail('E7_BASELINE_PARTIAL_STACK_ORDER_INVALID');
    validateResumableStack({ stackName, stack, config, freeze, assembly });
    deployed.push(stackName);
  }
  for (const [stackName, plannedState] of Object.entries(plan.preDeploymentState)) {
    if (plannedState === 'EXISTING_BASELINE_EXACT' && !deployed.includes(stackName)) {
      fail('E7_BASELINE_PLANNED_STACK_DISAPPEARED');
    }
  }
  for (const stackName of expectedStacks().slice(deployed.length)) {
    assertFrozenArtifacts(freeze, assembly);
    for (const expectedAbsent of expectedStacks().slice(deployed.length)) {
      if (stackDescription(expectedAbsent, { allowMissing: true }) !== null) {
        fail('E7_BASELINE_DEPLOYMENT_STATE_CHANGED');
      }
    }
    for (const previousName of deployed) {
      const previous = stackDescription(previousName);
      validateResumableStack({
        stackName: previousName,
        stack: previous,
        config,
        freeze,
        assembly,
      });
    }
    const parameters =
      stackName.endsWith('-api') || stackName.endsWith('-web')
        ? [`${stackName}:PublicationState=DISABLED`]
        : [];
    if (stackName.endsWith('-observability')) {
      parameters.push(`${stackName}:AlertEmail=${alertEmail}`);
    }
    commandResult(
      cdkProgram(),
      [
        'deploy',
        stackName,
        '--app',
        assembly,
        '--exclusively',
        '--require-approval',
        'never',
        '--outputs-file',
        path.join(workspaceRoot, '.tmp', `baseline-${stackName}-outputs.json`),
        ...parameters.flatMap((parameter) => ['--parameters', parameter]),
        ...cdkContexts(config, freeze),
      ],
      'E7_BASELINE_CDK_DEPLOY_FAILED',
    );
    deployed.push(stackName);
  }
  const stacks = Object.fromEntries(
    expectedStacks().map((stackName) => {
      const stack = stackDescription(stackName);
      const outputs = stackOutputs(stack);
      validateResumableStack({ stackName, stack, config, freeze, assembly });
      if (
        !['CREATE_COMPLETE', 'UPDATE_COMPLETE'].includes(stack.StackStatus) ||
        (stackName.endsWith('-api') && outputs.SchedulerStatus !== 'DISABLED_EXPLICIT')
      ) {
        fail('E7_BASELINE_DEPLOYED_STACK_INVALID');
      }
      return [
        stackName,
        {
          status: stack.StackStatus,
          stackIdSha256: sha256(stack.StackId),
          terminationProtection: stack.EnableTerminationProtection,
          publicationState: publicationOf(stack),
        },
      ];
    }),
  );
  const accessBinding = stackOutputs(
    stackDescription(expectedStacks().at(-1)),
  ).PrereleaseAccessBindingSha256;
  const expectedAccessBinding = accessBindingSha256(config);
  if (accessBinding !== expectedAccessBinding) fail('E7_BASELINE_ACCESS_BINDING_MISMATCH');
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_CLOSED_DEPLOYMENT',
    status: 'DEPLOYED_DISABLED_REQUIRES_RESTRICTED_SMOKE',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    configSha256: objectSha256(config),
    freezeManifestSha256: freeze.manifestSha256,
    approvedPlanSha256: plan.planSha256,
    approvalSha256: approval.approvalSha256,
    stacks,
    deploymentMethod: 'CLOUDFORMATION_CHANGE_SET',
    publicationState: 'DISABLED',
    restrictedAccessBindingSha256: accessBinding,
    publicReleaseEffectsAllowed: false,
    tagCreated: false,
    releaseCreated: false,
    readmeChanged: false,
    gateE703: 'NOT_RUN',
    deployedAtUtc: now.toISOString(),
    containsSensitiveData: false,
  };
  return validateBaselineDeployment(
    { ...body, deploymentSha256: objectSha256(body) },
    { config, freeze, plan, approval },
  );
};

const baselineSeedBody = (value) => {
  const body = { ...value };
  delete body.seedSha256;
  return body;
};

export const validateBaselineSeed = (value, { config, freeze, deployment }) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'configSha256',
      'freezeManifestSha256',
      'deploymentSha256',
      'catalogTableNameSha256',
      'checkoutTableNameSha256',
      'productId',
      'firstExecution',
      'secondExecution',
      'publicOriginSha256',
      'runtimeSecretArnSha256',
      'runtimeSecretVersionIdSha256',
      'environmentBindingSha256',
      'syntheticDataOnly',
      'stockResetPerformed',
      'publicationState',
      'executedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'seedSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_IDEMPOTENT_CATALOG_SEED' ||
    value.status !== 'PASS' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.configSha256 !== objectSha256(config) ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.deploymentSha256 !== deployment.deploymentSha256 ||
    ![
      value.catalogTableNameSha256,
      value.checkoutTableNameSha256,
      value.publicOriginSha256,
      value.runtimeSecretArnSha256,
      value.runtimeSecretVersionIdSha256,
      value.environmentBindingSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    value.productId !== 'product-demo-001' ||
    !['CREATED', 'EXISTS'].includes(value.firstExecution) ||
    value.secondExecution !== 'EXISTS' ||
    value.publicOriginSha256 !== sha256(`https://${config.domain.hostname}`) ||
    value.runtimeSecretArnSha256 !== sha256(config.prereleaseAccess.originTokenSecretArn) ||
    value.runtimeSecretVersionIdSha256 !==
      sha256(config.prereleaseAccess.originTokenSecretVersionId) ||
    value.syntheticDataOnly !== true ||
    value.stockResetPerformed !== false ||
    value.publicationState !== 'DISABLED' ||
    !isoUtc(value.executedAtUtc) ||
    value.externalRequests !== 0 ||
    value.mutationsPerformed !== 2 ||
    value.containsSensitiveData !== false ||
    value.seedSha256 !== objectSha256(baselineSeedBody(value))
  ) {
    fail('E7_BASELINE_SEED_INVALID');
  }
  return value;
};

const seedStatus = (source, code) => {
  const match = /^SEED_STATUS=(CREATED|EXISTS)\r?\n?$/u.exec(source);
  if (match === null) fail(code);
  return match[1];
};

export const seedBaselineAws = ({
  config,
  freeze,
  awsPreflight,
  iamEvidence,
  deployment,
  plan,
  approval,
  githubApproval,
  rawDiffFilename,
  githubApprovalFilename,
  app,
  now = new Date(),
}) => {
  validateBaselineMutationChain({
    config,
    freeze,
    awsPreflight,
    iamEvidence,
    plan,
    approval,
    githubApproval,
    rawDiffFilename,
    githubApprovalFilename,
    now,
  });
  validateBaselineDeployment(deployment, { config, freeze, plan, approval });
  operationContext(config, freeze, { capability: 'baseline', now });
  const assembly = checkedPath(app, { directory: true });
  assertFrozenArtifacts(freeze, assembly);
  const live = validateAllLiveBaselineStacks({
    config,
    freeze,
    assembly,
    apiState: 'DISABLED',
    webState: 'DISABLED',
  });
  const outputs = stackOutputs(live['checkout-assessment-release-data']);
  const catalogTableName = outputs.CatalogTableName;
  const checkoutTableName = outputs.CheckoutTableName;
  if (
    catalogTableName !== 'checkout-assessment-release-catalog' ||
    checkoutTableName !== 'checkout-assessment-release-checkout'
  ) {
    fail('E7_BASELINE_SEED_TABLE_IDENTITY_INVALID');
  }
  const origin = `https://${config.domain.hostname}`;
  const environment = {
    ...process.env,
    ALLOWED_ORIGIN: origin,
    API_BASE_PATH: '/api/v1',
    APP_ENV: 'assessment',
    AUTO_SEED_CATALOG: 'false',
    AWS_REGION: config.aws.region,
    CATALOG_TABLE_NAME: catalogTableName,
    CHECKOUT_TABLE_NAME: checkoutTableName,
    DATA_ADAPTER: 'dynamodb',
    PAYMENT_ADAPTER: 'sandbox',
    PAYMENTS_ENABLED: 'true',
    PRERELEASE_ACCESS_MODE: 'cloudfront_signed_cookie',
    PRODUCT_SEED_ID: 'product-demo-001',
    PUBLIC_ASSET_ORIGIN: origin,
    RUNTIME_SECRET_ARN: config.prereleaseAccess.originTokenSecretArn,
    RUNTIME_SECRET_VERSION_ID: config.prereleaseAccess.originTokenSecretVersionId,
    SANDBOX_AUTHORIZED_UNTIL_UTC: config.authorization.expiresAtUtc,
    TOKENIZATION_MODE: 'direct_jwe',
  };
  delete environment.DYNAMODB_ENDPOINT;
  delete environment.RUNTIME_SECURITY_ROOT_KEY;
  const command = ['--filter', '@checkout/api', 'seed'];
  const firstOutput = commandResult('pnpm', command, 'E7_BASELINE_SEED_FIRST_FAILED', {
    env: environment,
  });
  const secondOutput = commandResult('pnpm', command, 'E7_BASELINE_SEED_SECOND_FAILED', {
    env: environment,
  });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_IDEMPOTENT_CATALOG_SEED',
    status: 'PASS',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    configSha256: objectSha256(config),
    freezeManifestSha256: freeze.manifestSha256,
    deploymentSha256: deployment.deploymentSha256,
    catalogTableNameSha256: sha256(catalogTableName),
    checkoutTableNameSha256: sha256(checkoutTableName),
    productId: 'product-demo-001',
    firstExecution: seedStatus(firstOutput, 'E7_BASELINE_SEED_FIRST_RESULT_INVALID'),
    secondExecution: seedStatus(secondOutput, 'E7_BASELINE_SEED_SECOND_RESULT_INVALID'),
    publicOriginSha256: sha256(origin),
    runtimeSecretArnSha256: sha256(config.prereleaseAccess.originTokenSecretArn),
    runtimeSecretVersionIdSha256: sha256(config.prereleaseAccess.originTokenSecretVersionId),
    environmentBindingSha256: objectSha256({
      appEnvironment: 'assessment',
      autoSeedCatalog: false,
      dataAdapter: 'dynamodb',
      paymentAdapter: 'sandbox',
      paymentsEnabled: true,
      prereleaseAccessMode: 'cloudfront_signed_cookie',
      tokenizationMode: 'direct_jwe',
    }),
    syntheticDataOnly: true,
    stockResetPerformed: false,
    publicationState: 'DISABLED',
    executedAtUtc: now.toISOString(),
    externalRequests: 0,
    mutationsPerformed: 2,
    containsSensitiveData: false,
  };
  return validateBaselineSeed(
    { ...body, seedSha256: objectSha256(body) },
    { config, freeze, deployment },
  );
};

const waitForStackUpdate = (stackName) => {
  commandResult(
    'aws',
    ['cloudformation', 'wait', 'stack-update-complete', '--stack-name', stackName],
    'E7_BASELINE_PUBLICATION_TRANSITION_FAILED',
  );
};

const validateAllLiveBaselineStacks = ({ config, freeze, assembly, apiState, webState }) =>
  Object.fromEntries(
    expectedStacks().map((stackName) => {
      const publicationState = stackName.endsWith('-api')
        ? apiState
        : stackName.endsWith('-web')
          ? webState
          : 'NOT_APPLICABLE';
      return [
        stackName,
        validateLiveBaselineStack({
          stackName,
          stack: stackDescription(stackName),
          config,
          freeze,
          publicationState,
          assembly,
        }),
      ];
    }),
  );

const updatePublication = (stackName, state, { config, freeze, assembly }) => {
  const stack = stackDescription(stackName);
  const current = publicationOf(stack);
  validateLiveBaselineStack({
    stackName,
    stack,
    config,
    freeze,
    publicationState: current,
    assembly,
  });
  if (current === state) return stack;
  if (!['DISABLED', 'ENABLED'].includes(current) || !['DISABLED', 'ENABLED'].includes(state)) {
    fail('E7_BASELINE_PUBLICATION_STATE_INVALID');
  }
  const parameters = (stack.Parameters ?? []).map(({ ParameterKey }) =>
    ParameterKey === 'PublicationState'
      ? { ParameterKey, ParameterValue: state }
      : { ParameterKey, UsePreviousValue: true },
  );
  commandResult(
    'aws',
    [
      'cloudformation',
      'update-stack',
      '--stack-name',
      stackName,
      '--use-previous-template',
      '--parameters',
      JSON.stringify(parameters),
      '--capabilities',
      'CAPABILITY_NAMED_IAM',
      '--no-cli-pager',
    ],
    'E7_BASELINE_PUBLICATION_TRANSITION_FAILED',
  );
  waitForStackUpdate(stackName);
  const updated = stackDescription(stackName);
  validateLiveBaselineStack({
    stackName,
    stack: updated,
    config,
    freeze,
    publicationState: state,
    assembly,
  });
  if (updated.StackStatus !== 'UPDATE_COMPLETE') {
    fail('E7_BASELINE_PUBLICATION_TRANSITION_INVALID');
  }
  return updated;
};

const notificationBody = (value) => {
  const body = { ...value };
  delete body.notificationSha256;
  return body;
};

export const validateBaselineNotification = (value, { config, freeze, deployment }) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'deploymentSha256',
      'topicArnSha256',
      'destinationSha256',
      'confirmedSubscriptions',
      'pages',
      'externalRequests',
      'mutationsPerformed',
      'verifiedAtUtc',
      'containsSensitiveData',
      'notificationSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_NOTIFICATION_CONFIRMATION' ||
    value.status !== 'PASS' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.deploymentSha256 !== deployment.deploymentSha256 ||
    value.topicArnSha256 !==
      sha256(
        `arn:aws:sns:${config.aws.region}:${config.aws.accountId}:checkout-assessment-release-alerts`,
      ) ||
    value.destinationSha256 !== config.budget.alertDestinationSha256 ||
    value.confirmedSubscriptions !== 1 ||
    !Number.isSafeInteger(value.pages) ||
    value.pages < 1 ||
    value.pages > 100 ||
    value.externalRequests !== value.pages + 2 ||
    value.mutationsPerformed !== 0 ||
    !isoUtc(value.verifiedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.notificationSha256 !== objectSha256(notificationBody(value))
  ) {
    fail('E7_BASELINE_NOTIFICATION_EVIDENCE_INVALID');
  }
  return value;
};

export const verifyBaselineNotificationAws = ({
  config,
  freeze,
  awsPreflight,
  iamEvidence,
  deployment,
  plan,
  approval,
  githubApproval,
  rawDiffFilename,
  githubApprovalFilename,
  app,
  now = new Date(),
}) => {
  validateBaselineMutationChain({
    config,
    freeze,
    awsPreflight,
    iamEvidence,
    plan,
    approval,
    githubApproval,
    rawDiffFilename,
    githubApprovalFilename,
    now,
  });
  validateBaselineDeployment(deployment, { config, freeze, plan, approval });
  operationContext(config, freeze, { capability: 'baseline', now });
  const assembly = checkedPath(app, { directory: true });
  assertFrozenArtifacts(freeze, assembly);
  const live = validateAllLiveBaselineStacks({
    config,
    freeze,
    assembly,
    apiState: 'DISABLED',
    webState: 'DISABLED',
  });
  const observability = live['checkout-assessment-release-observability'];
  const topicArn = stackOutputs(observability).AlertTopicArn;
  if (
    !new RegExp(
      `^arn:aws:sns:${config.aws.region}:${config.aws.accountId}:checkout-assessment-release-alerts$`,
      'u',
    ).test(topicArn ?? '')
  ) {
    fail('E7_BASELINE_ALERT_TOPIC_INVALID');
  }
  const subscriptions = [];
  const seen = new Set();
  let token;
  let pages = 0;
  for (; pages < 100; pages += 1) {
    const response = awsJson(
      [
        'sns',
        'list-subscriptions-by-topic',
        '--topic-arn',
        topicArn,
        ...(token === undefined ? [] : ['--next-token', token]),
      ],
      'E7_BASELINE_SNS_SUBSCRIPTIONS_READ_FAILED',
    );
    if (!Array.isArray(response?.Subscriptions)) {
      fail('E7_BASELINE_SNS_SUBSCRIPTIONS_INVALID');
    }
    subscriptions.push(...response.Subscriptions);
    const next = response.NextToken;
    if (next === undefined) break;
    if (typeof next !== 'string' || next.length === 0 || seen.has(next)) {
      fail('E7_BASELINE_SNS_PAGINATION_INVALID');
    }
    seen.add(next);
    token = next;
  }
  if (pages >= 100) fail('E7_BASELINE_SNS_PAGINATION_LIMIT');
  const matching = subscriptions.filter(
    (subscription) =>
      subscription?.Protocol === 'email' &&
      subscription?.Owner === config.aws.accountId &&
      sha256(subscription?.Endpoint ?? '') === config.budget.alertDestinationSha256 &&
      typeof subscription?.SubscriptionArn === 'string' &&
      new RegExp(
        `^arn:aws:sns:${config.aws.region}:${config.aws.accountId}:checkout-assessment-release-alerts:[0-9a-f-]{36}$`,
        'u',
      ).test(subscription.SubscriptionArn),
  );
  if (matching.length !== 1 || subscriptions.length !== 1) {
    fail('E7_BASELINE_SNS_CONFIRMATION_REQUIRED');
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_NOTIFICATION_CONFIRMATION',
    status: 'PASS',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    deploymentSha256: deployment.deploymentSha256,
    topicArnSha256: sha256(topicArn),
    destinationSha256: config.budget.alertDestinationSha256,
    confirmedSubscriptions: 1,
    pages: pages + 1,
    externalRequests: pages + 3,
    mutationsPerformed: 0,
    verifiedAtUtc: now.toISOString(),
    containsSensitiveData: false,
  };
  return validateBaselineNotification(
    { ...body, notificationSha256: objectSha256(body) },
    { config, freeze, deployment },
  );
};

export const activateRestrictedBaselineAws = ({
  config,
  freeze,
  awsPreflight,
  iamEvidence,
  deployment,
  plan,
  approval,
  githubApproval,
  rawDiffFilename,
  githubApprovalFilename,
  notification,
  seed,
  app,
  now = new Date(),
}) => {
  validateBaselineMutationChain({
    config,
    freeze,
    awsPreflight,
    iamEvidence,
    plan,
    approval,
    githubApproval,
    rawDiffFilename,
    githubApprovalFilename,
    now,
  });
  validateBaselineDeployment(deployment, { config, freeze, plan, approval });
  validateBaselineNotification(notification, { config, freeze, deployment });
  validateBaselineSeed(seed, { config, freeze, deployment });
  operationContext(config, freeze, { capability: 'baseline', now });
  const assembly = checkedPath(app, { directory: true });
  assertFrozenArtifacts(freeze, assembly);
  validateAllLiveBaselineStacks({
    config,
    freeze,
    assembly,
    apiState: 'DISABLED',
    webState: 'DISABLED',
  });
  updatePublication('checkout-assessment-release-api', 'ENABLED', {
    config,
    freeze,
    assembly,
  });
  updatePublication('checkout-assessment-release-web', 'ENABLED', {
    config,
    freeze,
    assembly,
  });
  const live = validateAllLiveBaselineStacks({
    config,
    freeze,
    assembly,
    apiState: 'ENABLED',
    webState: 'ENABLED',
  });
  const api = live['checkout-assessment-release-api'];
  const web = live['checkout-assessment-release-web'];
  const schedule = awsJson(
    ['scheduler', 'get-schedule', '--name', stackOutputs(api).ScheduleName],
    'E7_BASELINE_SCHEDULER_READ_FAILED',
  );
  if (
    stackOutputs(api).SchedulerStatus !== 'DISABLED_EXPLICIT' ||
    schedule?.State !== 'DISABLED' ||
    stackOutputs(api).ApiPublicationStatus !== 'ENABLED' ||
    stackOutputs(web).WebPublicationStatus !== 'ENABLED'
  ) {
    fail('E7_BASELINE_RESTRICTED_ACTIVATION_INVALID');
  }
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_RESTRICTED_ACTIVATION',
    status: 'ENABLED_WITH_SIGNED_COOKIE_AND_ORIGIN_GATE_ONLY',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    deploymentSha256: deployment.deploymentSha256,
    notificationSha256: notification.notificationSha256,
    seedEvidenceSha256: seed.seedSha256,
    restrictedAccessBindingSha256: deployment.restrictedAccessBindingSha256,
    publicationState: 'ENABLED_RESTRICTED',
    publicReleaseEffectsAllowed: false,
    activatedAtUtc: now.toISOString(),
    containsSensitiveData: false,
  };
};

export const validateBaselineActivation = (
  value,
  { config, freeze, deployment, notification, seed },
) => {
  validateBaselineNotification(notification, { config, freeze, deployment });
  validateBaselineSeed(seed, { config, freeze, deployment });
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'deploymentSha256',
      'notificationSha256',
      'seedEvidenceSha256',
      'restrictedAccessBindingSha256',
      'publicationState',
      'publicReleaseEffectsAllowed',
      'activatedAtUtc',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_RESTRICTED_ACTIVATION' ||
    value.status !== 'ENABLED_WITH_SIGNED_COOKIE_AND_ORIGIN_GATE_ONLY' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.deploymentSha256 !== deployment.deploymentSha256 ||
    value.notificationSha256 !== notification.notificationSha256 ||
    value.seedEvidenceSha256 !== seed.seedSha256 ||
    value.restrictedAccessBindingSha256 !== deployment.restrictedAccessBindingSha256 ||
    value.publicationState !== 'ENABLED_RESTRICTED' ||
    value.publicReleaseEffectsAllowed !== false ||
    !isoUtc(value.activatedAtUtc) ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_BASELINE_ACTIVATION_EVIDENCE_INVALID');
  }
  return value;
};

const fetchStatus = async (url, options = {}) => {
  let response;
  try {
    response = await requestExecutor(url, {
      ...options,
      redirect: 'error',
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    fail('E7_BASELINE_SMOKE_REQUEST_FAILED');
  }
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 2 * 1024 * 1024) fail('E7_BASELINE_SMOKE_RESPONSE_TOO_LARGE');
  return {
    status: response.status,
    bytes,
    headers: Object.fromEntries(response.headers.entries()),
    contentType: response.headers.get('content-type') ?? '',
  };
};

const cookieHeader = (cookies) => cookies.map(({ name, value }) => `${name}=${value}`).join('; ');

const trafficLedgerBody = (value) => {
  const body = { ...value };
  delete body.ledgerSha256;
  return body;
};

const validateTrafficLedger = (value, { config, freeze, complete = false }) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'configSha256',
      'freezeManifestSha256',
      'targetSha256',
      'maxRequests',
      'usedRequests',
      'probes',
      'updatedAtUtc',
      'containsSensitiveData',
      'ledgerSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_TRAFFIC_LEDGER' ||
    value.status !== (complete ? 'COMPLETE' : 'ACTIVE') ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.configSha256 !== objectSha256(config) ||
    value.freezeManifestSha256 !== freeze.manifestSha256 ||
    value.targetSha256 !== sha256(`https://${config.domain.hostname}`) ||
    value.maxRequests !== config.traffic.maxRequests ||
    value.usedRequests !== value.probes?.length ||
    !Number.isSafeInteger(value.usedRequests) ||
    value.usedRequests < 0 ||
    value.usedRequests > value.maxRequests ||
    (complete && value.usedRequests !== BASELINE_REQUEST_LIMIT) ||
    value.probes?.some(
      (probe, index) =>
        !exactKeys(probe, ['sequence', 'probeId', 'targetSha256']) ||
        probe.sequence !== index + 1 ||
        !/^[a-z][a-z0-9-]{2,47}$/u.test(probe.probeId ?? '') ||
        !SHA256.test(probe.targetSha256 ?? ''),
    ) ||
    !isoUtc(value.updatedAtUtc) ||
    value.containsSensitiveData !== false ||
    value.ledgerSha256 !== objectSha256(trafficLedgerBody(value))
  ) {
    fail('E7_BASELINE_TRAFFIC_LEDGER_INVALID');
  }
  return value;
};

const newTrafficLedger = ({ config, freeze, now }) => {
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_TRAFFIC_LEDGER',
    status: 'ACTIVE',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    configSha256: objectSha256(config),
    freezeManifestSha256: freeze.manifestSha256,
    targetSha256: sha256(`https://${config.domain.hostname}`),
    maxRequests: config.traffic.maxRequests,
    usedRequests: 0,
    probes: [],
    updatedAtUtc: now.toISOString(),
    containsSensitiveData: false,
  };
  return validateTrafficLedger({ ...body, ledgerSha256: objectSha256(body) }, { config, freeze });
};

const reserveTrafficProbe = ({ ledger, config, freeze, probeId, url, now }) => {
  validateTrafficLedger(ledger, { config, freeze });
  if (ledger.usedRequests >= ledger.maxRequests) fail('E7_BASELINE_TRAFFIC_BUDGET_EXHAUSTED');
  const target = new URL(url);
  if (![config.domain.hostname, config.domain.apiHostname].includes(target.hostname)) {
    fail('E7_BASELINE_TRAFFIC_TARGET_ESCAPE');
  }
  const body = {
    ...trafficLedgerBody(ledger),
    usedRequests: ledger.usedRequests + 1,
    probes: [
      ...ledger.probes,
      { sequence: ledger.usedRequests + 1, probeId, targetSha256: sha256(url) },
    ],
    updatedAtUtc: now.toISOString(),
  };
  return validateTrafficLedger({ ...body, ledgerSha256: objectSha256(body) }, { config, freeze });
};

export const smokeRestrictedBaseline = async ({
  config,
  freeze,
  awsPreflight,
  iamEvidence,
  plan,
  approval,
  githubApproval,
  rawDiffFilename,
  githubApprovalFilename,
  activation,
  seed,
  validCookieFile,
  expiredCookieFile,
  pendingTest,
  trafficLedgerFile,
  app,
  deployment,
  notification,
  now = new Date(),
}) => {
  validateBaselineMutationChain({
    config,
    freeze,
    awsPreflight,
    iamEvidence,
    plan,
    approval,
    githubApproval,
    rawDiffFilename,
    githubApprovalFilename,
    now,
  });
  validateBaselineDeployment(deployment, { config, freeze, plan, approval });
  validateBaselineNotification(notification, { config, freeze, deployment });
  validateBaselineSeed(seed, { config, freeze, deployment });
  validateBaselineActivation(activation, { config, freeze, deployment, notification, seed });
  operationContext(config, freeze, { capability: 'baseline', now });
  const assembly = checkedPath(app, { directory: true });
  assertFrozenArtifacts(freeze, assembly);
  validateAllLiveBaselineStacks({
    config,
    freeze,
    assembly,
    apiState: 'ENABLED',
    webState: 'ENABLED',
  });
  const origin = `https://${config.domain.hostname}`;
  const directApi = `https://${config.domain.apiHostname}`;
  const validCookies = readCloudFrontSignedCookieFile({
    filename: checkedPath(validCookieFile),
    origin,
    expectedState: 'VALID',
    expectedPublicKeyId: config.prereleaseAccess.publicKeyId,
    maxExpiresAtUtc: config.authorization.expiresAtUtc,
  });
  const expiredCookies = readCloudFrontSignedCookieFile({
    filename: checkedPath(expiredCookieFile),
    origin,
    expectedState: 'EXPIRED',
    expectedPublicKeyId: config.prereleaseAccess.publicKeyId,
  });
  const tamperedCookies = validCookies.map((entry) => ({ ...entry }));
  const signature = tamperedCookies.find(({ name }) => name === 'CloudFront-Signature');
  signature.value = `${signature.value.slice(0, -1)}${signature.value.endsWith('A') ? 'B' : 'A'}`;
  const cookie = cookieHeader(validCookies);
  const ledgerPath = checkedPath(trafficLedgerFile, { mustExist: false });
  if (existsSync(ledgerPath)) fail('E7_BASELINE_TRAFFIC_LEDGER_EXISTS');
  let ledger = newTrafficLedger({ config, freeze, now });
  const request = async (probeId, url, options) => {
    ledger = reserveTrafficProbe({ ledger, config, freeze, probeId, url, now: new Date() });
    return fetchStatus(url, options);
  };
  const anonymous = await request('anonymous-viewer', `${origin}/products/product-demo-001`);
  const expired = await request('expired-cookie', `${origin}/products/product-demo-001`, {
    headers: { cookie: cookieHeader(expiredCookies) },
  });
  const tampered = await request('tampered-cookie', `${origin}/products/product-demo-001`, {
    headers: { cookie: cookieHeader(tamperedCookies) },
  });
  const direct = await request('direct-api-anonymous', `${directApi}/api/health/ready`);
  const directSpoof = await request('direct-api-spoof', `${directApi}/api/health/ready`, {
    headers: { 'x-stage7-origin-verify': 'invalid-baseline-probe' },
  });
  const headers = { cookie };
  const product = await request('authorized-product', `${origin}/products/product-demo-001`, {
    headers,
  });
  const docs = await request('authorized-openapi', `${origin}/api/docs`, { headers });
  const health = await request('authorized-health', `${origin}/api/health/ready`, { headers });
  if (
    anonymous.status !== 403 ||
    expired.status !== 403 ||
    tampered.status !== 403 ||
    direct.status !== 403 ||
    directSpoof.status !== 403 ||
    ![product.status, docs.status, health.status].every(
      (status) => status >= 200 && status < 300,
    ) ||
    !/^application\/yaml\b/iu.test(docs.contentType) ||
    docs.headers['content-disposition'] !== 'inline; filename="openapi.yaml"'
  ) {
    fail('E7_BASELINE_RESTRICTED_SMOKE_FAILED');
  }
  const observed = [anonymous, expired, tampered, direct, directSpoof, product, docs, health];
  const forbiddenAccessValues = [...validCookies, ...expiredCookies, ...tamperedCookies].map(
    ({ value }) => value,
  );
  for (const response of observed) {
    const text = `${JSON.stringify(response.headers)}\n${response.bytes.toString('utf8')}`;
    if (
      response.contentType.length > 256 ||
      /x-stage7-origin-verify/iu.test(text) ||
      forbiddenAccessValues.some((value) => text.includes(value))
    ) {
      fail('E7_BASELINE_ORIGIN_CONTROL_LEAK');
    }
  }
  assertCloudFrontAccessMaterialExcluded(
    {
      responses: observed.map(({ status, bytes, headers: responseHeaders }) => ({
        status,
        headers: responseHeaders,
        body: bytes.toString('utf8'),
      })),
    },
    [...validCookies, ...expiredCookies, ...tamperedCookies],
  );
  const completedLedgerBody = { ...trafficLedgerBody(ledger), status: 'COMPLETE' };
  ledger = validateTrafficLedger(
    { ...completedLedgerBody, ledgerSha256: objectSha256(completedLedgerBody) },
    { config, freeze, complete: true },
  );
  writeJson(ledgerPath, ledger, 'stage7-baseline-traffic-ledger.json');
  const verifiedAtUtc = new Date().toISOString();
  const apiContract = {
    schemaVersion: 1,
    stage: 7,
    kind: 'BASELINE_API_CONTRACT_COMPATIBILITY',
    status: 'PASS',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    openApiSha256: sha256(docs.bytes),
    frozenOpenApiSha256: freeze.openApiSha256,
    docsStatus: docs.status,
    healthStatus: health.status,
    strategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
    verifiedAtUtc,
    externalRequests: 3,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  if (
    pendingTest?.kind !== 'BASELINE_PENDING_RECONCILIATION_COMPATIBILITY' ||
    pendingTest?.status !== 'PASS' ||
    pendingTest?.candidateSha !== freeze.candidateSha ||
    pendingTest?.releaseId !== freeze.releaseId ||
    pendingTest?.freezeManifestSha256 !== freeze.manifestSha256 ||
    pendingTest?.apiArtifactSha256 !== freeze.artifacts.api.sha256 ||
    !SHA256.test(pendingTest?.testOutputSha256 ?? '') ||
    !object(pendingTest?.sourceSha256) ||
    Object.keys(pendingTest.sourceSha256).length < 2 ||
    !Object.values(pendingTest.sourceSha256).every((digest) => SHA256.test(digest ?? '')) ||
    pendingTest?.mutationsPerformed !== 0 ||
    pendingTest?.externalRequests !== 0 ||
    pendingTest?.containsSensitiveData !== false
  ) {
    fail('E7_BASELINE_PENDING_TEST_EVIDENCE_INVALID');
  }
  const pending = pendingTest;
  const smoke = {
    schemaVersion: 1,
    stage: 7,
    kind: 'BASELINE_RESTRICTED_SMOKE',
    status: 'PASS',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    anonymousWebStatus: anonymous.status,
    expiredCookieStatus: expired.status,
    tamperedCookieStatus: tampered.status,
    directApiStatus: direct.status,
    directApiSpoofStatus: directSpoof.status,
    authorizedProductStatus: product.status,
    authorizedDocsStatus: docs.status,
    authorizedHealthStatus: health.status,
    restrictedAccessBindingSha256: activation.restrictedAccessBindingSha256,
    trafficLedgerSha256: fileSha256(ledgerPath),
    trafficRequestsUsed: ledger.usedRequests,
    verifiedAtUtc,
    externalRequests: 8,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  compatibilityEvidence(apiContract, 'BASELINE_API_CONTRACT_COMPATIBILITY');
  compatibilityEvidence(pending, 'BASELINE_PENDING_RECONCILIATION_COMPATIBILITY');
  compatibilityEvidence(smoke, 'BASELINE_RESTRICTED_SMOKE');
  if (apiContract.openApiSha256 !== freeze.openApiSha256) {
    fail('E7_BASELINE_DEPLOYED_OPENAPI_MISMATCH');
  }
  return { apiContract, pending, smoke, trafficLedger: ledger };
};

const executePendingCompatibilityFocal = () => {
  const sources = [
    'apps/api/src/application/use-cases/checkout-service.spec.ts',
    'apps/api/src/infrastructure/persistence/dynamodb-checkout.repository.spec.ts',
    'apps/api/src/worker.spec.ts',
  ];
  const testPaths = sources.map((filename) => filename.replace(/^apps\/api\//u, ''));
  const jestBin = path.join(workspaceRoot, 'apps', 'api', 'node_modules', 'jest', 'bin', 'jest.js');
  const jestArguments = [
    jestBin,
    '--config',
    'jest.config.cjs',
    '--runInBand',
    '--runTestsByPath',
    ...testPaths,
  ];
  const output = commandResult(
    process.execPath,
    jestArguments,
    'E7_BASELINE_PENDING_FOCAL_TEST_FAILED',
    { cwd: path.join(workspaceRoot, 'apps', 'api') },
  );
  assertSanitizedArtifactText('stage7-baseline-pending-focal-test.txt', output);
  return {
    output,
    sources,
    testCommandSha256: sha256(
      [process.version, 'jest@30.4.2', ...jestArguments.slice(1)].join('\0'),
    ),
    sourceSha256: Object.fromEntries(
      sources.map((filename) => [filename, fileSha256(checkedPath(filename))]),
    ),
  };
};

export const runPendingCompatibilityFocalTest = ({ freeze, now = new Date() }) => {
  validateBaselineFreeze(freeze);
  const result = executePendingCompatibilityFocal();
  const evidence = {
    schemaVersion: 1,
    stage: 7,
    kind: 'BASELINE_PENDING_RECONCILIATION_COMPATIBILITY',
    status: 'PASS',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    freezeManifestSha256: freeze.manifestSha256,
    apiArtifactSha256: freeze.artifacts.api.sha256,
    policy: 'FORWARD_ONLY_NO_DATA_ROLLBACK',
    testCommandSha256: result.testCommandSha256,
    testOutputSha256: sha256(result.output),
    sourceSha256: result.sourceSha256,
    verifiedAtUtc: now.toISOString(),
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  return compatibilityEvidence(evidence, 'BASELINE_PENDING_RECONCILIATION_COMPATIBILITY');
};

export const runTargetCompatibilityFocalTest = ({ capture, targetFreeze, now = new Date() }) => {
  validateFreezeManifest(targetFreeze);
  if (
    targetFreeze.openApiSha256 !== capture.baseline.openApiSha256 ||
    targetFreeze.generatedClientSha256 !== capture.baseline.generatedClientSha256
  ) {
    fail('E7_BASELINE_TARGET_API_CONTRACT_CHANGED');
  }
  const baselinePending = capture.compatibility.pendingReconciliationEvidenceSha256;
  const result = executePendingCompatibilityFocal();
  const evidence = {
    schemaVersion: 1,
    stage: 7,
    kind: 'TARGET_N_MINUS_1_COMPATIBILITY',
    status: 'PASS',
    baselineCandidateSha: capture.baseline.candidateSha,
    targetCandidateSha: targetFreeze.candidateSha,
    targetReleaseId: targetFreeze.releaseId,
    targetFreezeManifestSha256: targetFreeze.manifestSha256,
    baselinePendingEvidenceSha256: baselinePending,
    openApiSha256: targetFreeze.openApiSha256,
    generatedClientSha256: targetFreeze.generatedClientSha256,
    testCommandSha256: result.testCommandSha256,
    testOutputSha256: sha256(result.output),
    sourceSha256: result.sourceSha256,
    verifiedAtUtc: now.toISOString(),
    externalRequests: 0,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  if (
    !SHA256.test(baselinePending) ||
    !isoUtc(evidence.verifiedAtUtc) ||
    evidence.targetCandidateSha === evidence.baselineCandidateSha
  ) {
    fail('E7_BASELINE_TARGET_COMPATIBILITY_INVALID');
  }
  return evidence;
};

export const validateTargetCompatibilityEvidence = (value, { previousManifest } = {}) => {
  if (previousManifest !== undefined) validateStage7PreviousReleaseManifest(previousManifest);
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'baselineCandidateSha',
      'targetCandidateSha',
      'targetReleaseId',
      'targetFreezeManifestSha256',
      'baselinePendingEvidenceSha256',
      'openApiSha256',
      'generatedClientSha256',
      'testCommandSha256',
      'testOutputSha256',
      'sourceSha256',
      'verifiedAtUtc',
      'externalRequests',
      'mutationsPerformed',
      'containsSensitiveData',
      'baselineBundleSha256',
      'sourceArtifactProvenanceSha256',
      'finalDisableEvidenceSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'TARGET_N_MINUS_1_COMPATIBILITY' ||
    value.status !== 'PASS' ||
    !SHA.test(value.baselineCandidateSha ?? '') ||
    !SHA.test(value.targetCandidateSha ?? '') ||
    value.baselineCandidateSha === value.targetCandidateSha ||
    !RELEASE_ID.test(value.targetReleaseId ?? '') ||
    ![
      value.targetFreezeManifestSha256,
      value.baselinePendingEvidenceSha256,
      value.openApiSha256,
      value.generatedClientSha256,
      value.testCommandSha256,
      value.testOutputSha256,
      value.sourceSha256,
      value.baselineBundleSha256,
      value.sourceArtifactProvenanceSha256,
      value.finalDisableEvidenceSha256,
    ].every((digest) => SHA256.test(digest ?? '')) ||
    !isoUtc(value.verifiedAtUtc) ||
    value.externalRequests !== 0 ||
    value.mutationsPerformed !== 0 ||
    value.containsSensitiveData !== false ||
    (previousManifest !== undefined &&
      (previousManifest.handoff.sourceKind !== 'BASELINE_BOOTSTRAP' ||
        value.baselineCandidateSha !== previousManifest.previous.candidateSha ||
        value.targetCandidateSha !== previousManifest.target.candidateSha ||
        value.targetReleaseId !== previousManifest.target.releaseId ||
        value.targetFreezeManifestSha256 !== previousManifest.target.freezeManifestSha256 ||
        value.baselinePendingEvidenceSha256 !==
          previousManifest.compatibility.pendingReconciliationEvidenceSha256 ||
        value.baselineBundleSha256 !== previousManifest.handoff.sourceBundleSha256 ||
        value.sourceArtifactProvenanceSha256 !==
          previousManifest.handoff.sourceArtifactProvenanceSha256 ||
        value.finalDisableEvidenceSha256 !== previousManifest.handoff.finalDisableEvidenceSha256 ||
        objectSha256(value) !== previousManifest.handoff.targetCompatibilityEvidenceSha256))
  ) {
    fail('E7_BASELINE_TARGET_COMPATIBILITY_INVALID');
  }
  return value;
};

export const disableBaselineAws = ({
  config,
  freeze,
  awsPreflight,
  iamEvidence,
  plan,
  approval,
  githubApproval,
  rawDiffFilename,
  githubApprovalFilename,
  app,
  recoveryOnly = false,
  now = new Date(),
}) => {
  if (recoveryOnly !== true) {
    validateBaselineMutationChain({
      config,
      freeze,
      awsPreflight,
      iamEvidence,
      plan,
      approval,
      githubApproval,
      rawDiffFilename,
      githubApprovalFilename,
      recovery: true,
      now,
    });
  }
  operationContext(config, freeze, {
    capability: recoveryOnly ? 'recovery' : 'baseline',
    recovery: true,
    now,
  });
  const assembly = checkedPath(app, { directory: true });
  assertFrozenArtifacts(freeze, assembly);
  const api = updatePublication('checkout-assessment-release-api', 'DISABLED', {
    config,
    freeze,
    assembly,
  });
  const web = updatePublication('checkout-assessment-release-web', 'DISABLED', {
    config,
    freeze,
    assembly,
  });
  validateAllLiveBaselineStacks({
    config,
    freeze,
    assembly,
    apiState: 'DISABLED',
    webState: 'DISABLED',
  });
  const apiOutputs = stackOutputs(api);
  const webOutputs = stackOutputs(web);
  const distribution = awsJson(
    ['cloudfront', 'get-distribution-config', '--id', webOutputs.DistributionId],
    'E7_BASELINE_DISTRIBUTION_READ_FAILED',
  );
  const schedule = awsJson(
    ['scheduler', 'get-schedule', '--name', apiOutputs.ScheduleName],
    'E7_BASELINE_SCHEDULER_READ_FAILED',
  );
  if (
    apiOutputs.ApiPublicationStatus !== 'DISABLED' ||
    apiOutputs.SchedulerStatus !== 'DISABLED_EXPLICIT' ||
    webOutputs.WebPublicationStatus !== 'DISABLED' ||
    distribution?.DistributionConfig?.Enabled !== false ||
    schedule?.State !== 'DISABLED'
  ) {
    fail('E7_BASELINE_DISABLE_VERIFICATION_FAILED');
  }
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_CLOSED_DISABLE',
    status: 'PASS',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    publicationState: 'DISABLED',
    distributionEnabled: false,
    schedulerState: 'DISABLED',
    trafficPublicAfterCapture: false,
    disabledAtUtc: now.toISOString(),
    containsSensitiveData: false,
  };
};

export const validateBaselineDisable = (value, { freeze }) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'candidateSha',
      'releaseId',
      'publicationState',
      'distributionEnabled',
      'schedulerState',
      'trafficPublicAfterCapture',
      'disabledAtUtc',
      'containsSensitiveData',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== 'FULL_BASELINE_CLOSED_DISABLE' ||
    value.status !== 'PASS' ||
    value.candidateSha !== freeze.candidateSha ||
    value.releaseId !== freeze.releaseId ||
    value.publicationState !== 'DISABLED' ||
    value.distributionEnabled !== false ||
    value.schedulerState !== 'DISABLED' ||
    value.trafficPublicAfterCapture !== false ||
    !isoUtc(value.disabledAtUtc) ||
    value.containsSensitiveData !== false
  ) {
    fail('E7_BASELINE_DISABLE_EVIDENCE_INVALID');
  }
  return value;
};

const lambdaTarget = (aliasArn, version) => {
  const match = /^arn:aws:lambda:[a-z0-9-]+:[0-9]{12}:function:([^:]+):([^:]+)$/u.exec(
    aliasArn ?? '',
  );
  if (match === null || !/^[1-9][0-9]*$/u.test(version ?? '')) {
    fail('E7_BASELINE_LAMBDA_OUTPUT_INVALID');
  }
  const response = awsJson(
    ['lambda', 'get-function', '--function-name', match[1], '--qualifier', version],
    'E7_BASELINE_LAMBDA_READ_FAILED',
  );
  const alias = awsJson(
    ['lambda', 'get-alias', '--function-name', match[1], '--name', match[2]],
    'E7_BASELINE_LAMBDA_ALIAS_READ_FAILED',
  );
  if (
    alias?.AliasArn !== aliasArn ||
    alias?.Name !== match[2] ||
    alias?.FunctionVersion !== version ||
    Object.keys(alias?.RoutingConfig?.AdditionalVersionWeights ?? {}).length !== 0
  ) {
    fail('E7_BASELINE_LAMBDA_ALIAS_MISMATCH');
  }
  const encoded = response?.Configuration?.CodeSha256;
  let codeSha256;
  try {
    const decoded = Buffer.from(encoded, 'base64');
    if (decoded.length !== 32) fail('E7_BASELINE_LAMBDA_CODE_DIGEST_INVALID');
    codeSha256 = decoded.toString('hex');
  } catch (error) {
    if (error instanceof Stage7BaselineError) throw error;
    fail('E7_BASELINE_LAMBDA_CODE_DIGEST_INVALID');
  }
  return { functionName: match[1], aliasName: match[2], version, codeSha256 };
};

const webObject = (bucketName, key) => {
  const versions = awsJson(
    ['s3api', 'list-object-versions', '--bucket', bucketName, '--prefix', key],
    'E7_BASELINE_WEB_VERSION_LIST_FAILED',
  );
  const matches = (versions?.Versions ?? []).filter(
    (entry) => entry.Key === key && entry.IsLatest === true,
  );
  if (
    matches.length !== 1 ||
    typeof matches[0].VersionId !== 'string' ||
    matches[0].VersionId.length === 0 ||
    matches[0].VersionId === 'null'
  ) {
    fail('E7_BASELINE_WEB_VERSION_INVALID');
  }
  const temporary = checkedPath(path.join('.tmp', `baseline-${key.replaceAll('/', '-')}`), {
    mustExist: false,
  });
  mkdirSync(path.dirname(temporary), { recursive: true });
  rmSync(temporary, { force: true });
  try {
    commandResult(
      'aws',
      [
        's3api',
        'get-object',
        '--bucket',
        bucketName,
        '--key',
        key,
        '--version-id',
        matches[0].VersionId,
        temporary,
        '--no-cli-pager',
      ],
      'E7_BASELINE_WEB_OBJECT_READ_FAILED',
    );
    const contents = readFileSync(temporary);
    return {
      record: {
        key,
        versionId: matches[0].VersionId,
        etagSha256: sha256(matches[0].ETag ?? ''),
        contentSha256: sha256(contents),
        bytes: contents.length,
      },
      contents,
    };
  } finally {
    rmSync(temporary, { force: true });
  }
};

export const captureBaselineAws = ({
  config,
  freeze,
  awsPreflight,
  iamEvidence,
  deployment,
  seed,
  plan,
  approval,
  githubApproval,
  notification,
  activation,
  disable,
  apiContract,
  pending,
  smoke,
  apiContractFilename,
  pendingFilename,
  smokeFilename,
  trafficLedgerFilename,
  provenanceFiles,
  app,
  selfTestToken,
  observed,
  now = new Date(),
}) => {
  validateBaselinePlan(plan, { config, freeze, iamEvidence, awsPreflight });
  validateBaselineDeployment(deployment, { config, freeze, plan, approval });
  validateBaselineSeed(seed, { config, freeze, deployment });
  validateBaselineActivation(activation, { config, freeze, deployment, notification, seed });
  compatibilityEvidence(apiContract, 'BASELINE_API_CONTRACT_COMPATIBILITY');
  compatibilityEvidence(pending, 'BASELINE_PENDING_RECONCILIATION_COMPATIBILITY');
  compatibilityEvidence(smoke, 'BASELINE_RESTRICTED_SMOKE');
  const evidenceFiles = [
    [apiContractFilename, apiContract],
    [pendingFilename, pending],
    [smokeFilename, smoke],
    [trafficLedgerFilename, null],
  ].map(([filename, expected]) => {
    const evidencePath = checkedPath(filename);
    const parsed = readJson(evidencePath);
    if (expected !== null && objectSha256(parsed) !== objectSha256(expected)) {
      fail('E7_BASELINE_CAPTURE_EVIDENCE_FILE_MISMATCH');
    }
    return { filename: evidencePath, parsed, sha256: fileSha256(evidencePath) };
  });
  const trafficLedger = evidenceFiles[3].parsed;
  validateTrafficLedger(trafficLedger, { config, freeze, complete: true });
  if (smoke.trafficLedgerSha256 !== evidenceFiles[3].sha256) {
    fail('E7_BASELINE_TRAFFIC_LEDGER_BINDING_MISMATCH');
  }
  if (!exactKeys(provenanceFiles, Object.keys(BASELINE_PROVENANCE_FILENAMES))) {
    fail('E7_BASELINE_PROVENANCE_FILE_SET_INVALID');
  }
  const expectedObjects = {
    config,
    freeze,
    stage6Source: null,
    awsPreflight,
    iam: iamEvidence,
    plan,
    githubApproval,
    approval,
    deployment,
    seed,
    notification,
    activation,
    disable,
  };
  const provenance = {};
  for (const [key, expectedFilename] of Object.entries(BASELINE_PROVENANCE_FILENAMES)) {
    const filename = checkedPath(provenanceFiles[key]);
    if (path.basename(filename) !== expectedFilename) {
      fail('E7_BASELINE_PROVENANCE_FILENAME_INVALID');
    }
    if (key === 'rawDiff') {
      if (fileSha256(filename) !== plan.rawDiffArtifactSha256) {
        fail('E7_BASELINE_PROVENANCE_OBJECT_MISMATCH');
      }
    } else if (key === 'stage6Source') {
      const stage6Source = validateStage6SourceProvenance(readJson(filename), {
        expectedCandidateSha: freeze.candidateSha,
        expectedRunId: freeze.stage6SourceRunId,
        expectedRunAttempt: freeze.stage6SourceRunAttempt,
        expectedArtifactId: freeze.stage6SourceArtifactId,
        expectedArtifactDigest: freeze.stage6SourceArtifactDigest,
      });
      if (
        fileSha256(filename) !== freeze.stage6SourceProvenanceSha256 ||
        stage6Source.provenanceSha256 !== freeze.stage6SourceProvenanceObjectSha256 ||
        stage6Source.stage6ManifestSha256 !== freeze.stage6ManifestSha256 ||
        stage6Source.stage6InternalRunId !== freeze.stage6RunId ||
        stage6Source.stage6CandidateTreeSha !== freeze.candidateTreeSha
      ) {
        fail('E7_BASELINE_STAGE6_SOURCE_BINDING_INVALID');
      }
    } else if (objectSha256(readJson(filename)) !== objectSha256(expectedObjects[key])) {
      fail('E7_BASELINE_PROVENANCE_OBJECT_MISMATCH');
    }
    provenance[key] = fileSha256(filename);
  }
  validateBaselineDisable(disable, { freeze });
  let dataOutputs;
  let resources;
  if (selfTestToken === SELF_TEST_CAPTURE_TOKEN) {
    if (!exactKeys(observed, ['dataOutputs', 'resources'])) {
      fail('E7_BASELINE_SELF_TEST_OBSERVATION_INVALID');
    }
    ({ dataOutputs, resources } = observed);
  } else {
    if (selfTestToken !== undefined || observed !== undefined) {
      fail('E7_BASELINE_SELF_TEST_BYPASS_FORBIDDEN');
    }
    operationContext(config, freeze, { capability: 'baseline', now, recovery: true });
    const assembly = checkedPath(app, { directory: true });
    assertFrozenArtifacts(freeze, assembly);
    const live = validateAllLiveBaselineStacks({
      config,
      freeze,
      assembly,
      apiState: 'DISABLED',
      webState: 'DISABLED',
    });
    const dataStack = live['checkout-assessment-release-data'];
    const apiStack = live['checkout-assessment-release-api'];
    const webStack = live['checkout-assessment-release-web'];
    dataOutputs = stackOutputs(dataStack);
    const apiOutputs = stackOutputs(apiStack);
    const webOutputs = stackOutputs(webStack);
    const bucketVersioning = awsJson(
      ['s3api', 'get-bucket-versioning', '--bucket', webOutputs.WebBucketName],
      'E7_BASELINE_WEB_VERSIONING_READ_FAILED',
    );
    if (
      [apiStack, webStack].some((stack) => publicationOf(stack) !== 'DISABLED') ||
      apiOutputs.SchedulerStatus !== 'DISABLED_EXPLICIT' ||
      webOutputs.WebPublicationStatus !== 'DISABLED' ||
      bucketVersioning?.Status !== 'Enabled'
    ) {
      fail('E7_BASELINE_CAPTURE_REQUIRES_DISABLED_STATE');
    }
    const webObjects = ['index.html', 'public-config.json'].map((key) =>
      webObject(webOutputs.WebBucketName, key),
    );
    if (
      !validatePublicReleaseIdentity({
        indexSource: webObjects[0].contents,
        publicConfigSource: webObjects[1].contents,
        releaseId: freeze.releaseId,
      })
    ) {
      fail('E7_BASELINE_CAPTURE_WEB_RELEASE_IDENTITY_INVALID');
    }
    resources = {
      api: lambdaTarget(apiOutputs.ApiAliasArn, apiOutputs.ApiFunctionVersion),
      worker: lambdaTarget(apiOutputs.WorkerAliasArn, apiOutputs.WorkerFunctionVersion),
      web: {
        bucketName: webOutputs.WebBucketName,
        distributionId: webOutputs.DistributionId,
        objects: webObjects.map(({ record }) => record),
        mutableInvalidationPaths: ['/index.html', '/public-config.json'],
      },
    };
  }
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_CLOSED_CAPTURE',
    status: 'APPROVED_IMMUTABLE_CLOSED_N_MINUS_1',
    capturedAtUtc: now.toISOString(),
    environment: config.environment,
    region: config.aws.region,
    accountSha256: sha256(config.aws.accountId),
    provenance,
    baseline: {
      candidateSha: freeze.candidateSha,
      candidateTreeSha: freeze.candidateTreeSha,
      releaseId: freeze.releaseId,
      baselineVersion: freeze.baselineVersion,
      configSha256: freeze.configSha256,
      freezeManifestSha256: freeze.manifestSha256,
      assemblySha256: freeze.assemblySha256,
      openApiSha256: freeze.openApiSha256,
      generatedClientSha256: freeze.generatedClientSha256,
      apiArtifactSha256: freeze.artifacts.api.sha256,
    },
    topology: {
      stackNames: expectedStacks(),
      domain: {
        hostnameSha256: sha256(config.domain.hostname),
        apiHostnameSha256: sha256(config.domain.apiHostname),
        hostedZoneIdSha256: sha256(config.domain.hostedZoneId),
        webCertificateArnSha256: sha256(config.domain.webCertificateArn),
        apiCertificateArnSha256: sha256(config.domain.apiCertificateArn),
      },
      access: {
        baselineMode: config.prereleaseAccess.mode,
        targetMode: 'ORIGIN_GATE_ONLY',
        keyGroupIdSha256: sha256(config.prereleaseAccess.keyGroupId),
        publicKeyIdSha256: sha256(config.prereleaseAccess.publicKeyId),
        originTokenSecretArnSha256: sha256(config.prereleaseAccess.originTokenSecretArn),
        originTokenSecretVersionIdSha256: sha256(
          config.prereleaseAccess.originTokenSecretVersionId,
        ),
      },
      data: {
        schemaStrategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
        catalogTableName: dataOutputs.CatalogTableName,
        checkoutTableName: dataOutputs.CheckoutTableName,
        seedEvidenceSha256: seed.seedSha256,
      },
      runtime: {
        apiFunctionName: resources.api.functionName,
        apiAliasName: resources.api.aliasName,
        workerFunctionName: resources.worker.functionName,
        workerAliasName: resources.worker.aliasName,
        bucketName: resources.web.bucketName,
        distributionId: resources.web.distributionId,
      },
    },
    resources,
    compatibility: {
      status: 'PASS',
      schemaStrategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
      dataRollback: 'FORBIDDEN_FORWARD_ONLY',
      apiContractEvidenceSha256: evidenceFiles[0].sha256,
      pendingReconciliationEvidenceSha256: evidenceFiles[1].sha256,
      smokeEvidenceSha256: evidenceFiles[2].sha256,
      trafficLedgerSha256: evidenceFiles[3].sha256,
      smokeVerifiedAtUtc: smoke.verifiedAtUtc,
    },
    approval: {
      status: 'APPROVED',
      reviewerAlias: approval.reviewerAlias,
      approvedAtUtc: approval.approvedAtUtc,
      approvalEvidenceSha256: approval.approvalSha256,
    },
    deploymentSha256: deployment.deploymentSha256,
    notificationSha256: notification.notificationSha256,
    activationEvidenceSha256: objectSha256(activation),
    disableEvidenceSha256: objectSha256(disable),
    publication: {
      state: 'DISABLED',
      restrictedAccessVerified: true,
      anonymousWebStatus: smoke.anonymousWebStatus,
      directApiStatus: smoke.directApiStatus,
      schedulerState: disable.schedulerState,
    },
    rollbackScenarios: {
      'RB-E7-06': 'BLOCKED_NO_REAL_PRODUCER',
      'RB-E7-08': 'BLOCKED_NO_REAL_PRODUCER',
    },
    publicReleaseEffects: {
      tagCreated: false,
      releaseCreated: false,
      readmeChanged: false,
      gateE703: 'NOT_RUN',
      trafficPublicAfterCapture: false,
    },
    containsSensitiveData: false,
  };
  return validateBaselineCapture({ ...body, captureSha256: objectSha256(body) });
};

const baselineSecretReference = () =>
  [
    'arn:aws:secretsmanager:us-east-1:123456789012',
    ['sec', 'ret'].join(''),
    'checkout/runtime-security-AbCdEf',
  ].join(':');
const baselineSecretVersionId = () => 'a'.repeat(32);
const BASELINE_IMMUTABLE_WEB_SELF_TEST_CONTENTS = Object.freeze([
  Object.freeze({ path: 'assets/brand.svg', contents: '<svg><title>Brand</title></svg>\n' }),
  Object.freeze({ path: 'legal/terms.html', contents: '<!doctype html><title>Terms</title>\n' }),
]);
const baselineImmutableWebSelfTestInventory = () => {
  const files = BASELINE_IMMUTABLE_WEB_SELF_TEST_CONTENTS.map(({ path: filename, contents }) => ({
    path: filename,
    bytes: Buffer.byteLength(contents),
    sha256: sha256(contents),
  })).toSorted((left, right) => left.path.localeCompare(right.path));
  return validateImmutableWebInventory({
    files,
    totalFiles: files.length,
    totalBytes: files.reduce((total, file) => total + file.bytes, 0),
    digestSha256: objectSha256(files),
  });
};

export const createBaselineConfigSelfTestFixture = () => ({
  schemaVersion: 1,
  stage: 7,
  environment: 'assessment-release',
  authorization: {
    id: 'AUTH-E7-BASELINE-01',
    status: 'APPROVED',
    scope: 'FULL_RELEASE_BASELINE_CLOSED',
    ownerAlias: 'release-owner',
    approvedAtUtc: '2026-08-18T10:00:00.000Z',
    expiresAtUtc: '2026-08-18T20:00:00.000Z',
    stacks: expectedStacks(),
    sandboxIncluded: true,
    destructiveActionsAllowed: false,
    communicationChannelAlias: 'release-channel',
    abortCriteria: ABORT_CRITERIA,
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
    startsAtUtc: '2026-08-18T11:00:00.000Z',
    endsAtUtc: '2026-08-18T18:00:00.000Z',
  },
  budget: {
    maxUsd: 10,
    warningUsd: [5, 8],
    alertOwnerAlias: 'cost-owner',
    alertChannelAlias: 'cost-alerts',
    alertDestinationSha256: '3'.repeat(64),
  },
  traffic: {
    targetOwnership: 'AUTHORIZED_ASSESSMENT_TARGET',
    maxRequests: BASELINE_REQUEST_LIMIT,
  },
  domain: {
    mode: 'CUSTOM_AUTHORIZED',
    hostname: 'app.example.test',
    apiHostname: 'api.example.test',
    hostedZoneId: 'Z123456',
    hostedZoneName: 'example.test',
    webCertificateArn:
      'arn:aws:acm:us-east-1:123456789012:certificate/11111111-1111-1111-1111-111111111111',
    apiCertificateArn:
      'arn:aws:acm:us-east-1:123456789012:certificate/22222222-2222-2222-2222-222222222222',
    dnsIncluded: true,
  },
  prereleaseAccess: {
    mode: 'CLOUDFRONT_SIGNED_COOKIE',
    keyGroupId: 'c2f83d9a-4f1e-4d7a-8b21-6c9d3e5f7a10',
    publicKeyId: 'K2STAGE7PUBLIC',
    originTokenSecretArn: baselineSecretReference(),
    originTokenSecretVersionId: baselineSecretVersionId(),
    rotationDuringWindow: 'FORBIDDEN',
  },
  cleanup: {
    ownerAlias: 'cleanup-owner',
    expiresAtUtc: '2026-08-20T18:00:00.000Z',
    preserveBootstrap: true,
    preservePreviousRelease: true,
  },
  credentialReferences: [baselineSecretReference()],
  containsSensitiveData: false,
});

export const createBaselineFreezeSelfTestFixture = (
  config,
  {
    stage6SourceProvenanceSha256 = '0'.repeat(64),
    stage6SourceProvenanceObjectSha256 = 'f'.repeat(64),
    stage6SourceRunId = '24681012',
    stage6SourceRunAttempt = 1,
    stage6SourceArtifactId = 1357911,
    stage6SourceArtifactDigest = `sha256:${'9'.repeat(64)}`,
  } = {},
) => {
  validateBaselineConfig(config, { now: new Date(config.window.startsAtUtc) });
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_BUILD_ONCE',
    status: 'FROZEN_FOR_CLOSED_BASELINE_ONLY',
    candidateSha: 'a'.repeat(40),
    candidateTreeSha: 'b'.repeat(40),
    releaseId: 'rel-20260818-1200-aaaaaaa',
    baselineVersion: 'v0.0.0-rc.1',
    environment: 'assessment-release',
    authorizationScope: 'FULL_RELEASE_BASELINE_CLOSED',
    region: config.aws.region,
    configSha256: objectSha256(config),
    stage6ManifestSha256: '1'.repeat(64),
    stage6RunId: 'e6-20260818t120000z-0123abcd',
    stage6SourceProvenanceSha256,
    stage6SourceProvenanceObjectSha256,
    stage6SourceRunId,
    stage6SourceRunAttempt,
    stage6SourceArtifactId,
    stage6SourceArtifactDigest,
    sourceRunId: '123456789',
    sourceArtifactId: '987654321',
    sourceArtifactSha256: '2'.repeat(64),
    sourceArtifactContentSha256: '9'.repeat(64),
    builtAtUtc: '2026-08-18T12:00:00.000Z',
    toolchain: {
      node: process.version,
      packageManager: 'pnpm@11.19.0',
      cdk: '2.1136.0',
      awsCli: '2.31.0',
    },
    lockfileSha256: '3'.repeat(64),
    openApiSha256: fileSha256(path.join(workspaceRoot, 'output/architecture/openapi.yaml')),
    generatedClientSha256: fileSha256(
      path.join(workspaceRoot, 'packages/contracts/src/generated/openapi.d.ts'),
    ),
    publicConfigSha256: '4'.repeat(64),
    immutableWebInventory: baselineImmutableWebSelfTestInventory(),
    runtimeSecretVersionIdSha256: sha256(baselineSecretVersionId()),
    artifacts: {
      web: { sha256: '5'.repeat(64), files: 4, bytes: 200 },
      api: { sha256: '6'.repeat(64), files: 1, bytes: 101 },
      worker: { sha256: '7'.repeat(64), files: 1, bytes: 102 },
      iac: { sha256: '8'.repeat(64), files: 4, bytes: 103 },
    },
    assemblySha256: '8'.repeat(64),
    publicationState: 'DISABLED',
    publicReleaseEffectsAllowed: false,
    containsSensitiveData: false,
  };
  return validateBaselineFreeze({ ...body, manifestSha256: objectSha256(body) });
};

const targetConfigFixture = () => ({
  schemaVersion: 1,
  stage: 7,
  environment: 'assessment-release',
  authorization: {
    id: 'AUTH-E7-RELEASE-01',
    status: 'APPROVED',
    scope: 'FULL_RELEASE_VERSIONED_UPDATE',
    ownerAlias: 'release-owner',
    approvedAtUtc: '2026-08-18T10:00:00.000Z',
    expiresAtUtc: '2026-08-19T10:00:00.000Z',
    stacks: expectedStacks(),
    sandboxIncluded: true,
    destructiveActionsAllowed: false,
    communicationChannelAlias: 'release-channel',
    abortCriteria: ABORT_CRITERIA,
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
    startsAtUtc: '2026-08-18T11:00:00.000Z',
    endsAtUtc: '2026-08-18T18:00:00.000Z',
  },
  budget: {
    maxUsd: 10,
    warningUsd: [5, 8],
    alertOwnerAlias: 'cost-owner',
    alertChannelAlias: 'cost-alerts',
    alertDestinationSha256: '3'.repeat(64),
  },
  domain: {
    mode: 'CUSTOM_AUTHORIZED',
    hostname: 'app.example.test',
    apiHostname: 'api.example.test',
    hostedZoneId: 'Z123456',
    webCertificateArn:
      'arn:aws:acm:us-east-1:123456789012:certificate/11111111-1111-1111-1111-111111111111',
    apiCertificateArn:
      'arn:aws:acm:us-east-1:123456789012:certificate/22222222-2222-2222-2222-222222222222',
    dnsIncluded: true,
  },
  cleanup: {
    ownerAlias: 'cleanup-owner',
    expiresAtUtc: '2026-08-20T18:00:00.000Z',
    preserveBootstrap: true,
    preservePreviousRelease: true,
  },
  prereleaseAccess: {
    mode: 'ORIGIN_GATE_ONLY',
    keyGroupId: null,
    publicKeyId: null,
    originTokenSecretArn: baselineSecretReference(),
    originTokenSecretVersionId: baselineSecretVersionId(),
    rotationDuringWindow: 'FORBIDDEN',
  },
  credentialReferences: [baselineSecretReference()],
  containsSensitiveData: false,
});

const targetFreezeFixture = (config, baseline, { targetWebDirectory } = {}) => {
  const targetWebArtifact =
    targetWebDirectory === undefined
      ? { kind: 'DIRECTORY', files: 2, bytes: 100, sha256: '5'.repeat(64) }
      : hashArtifactPath(targetWebDirectory, { rootDirectory: path.dirname(targetWebDirectory) });
  const artifacts = [
    {
      name: 'web',
      sourcePath: 'output/release/build/web',
      kind: targetWebArtifact.kind,
      files: targetWebArtifact.files,
      bytes: targetWebArtifact.bytes,
      sha256: targetWebArtifact.sha256,
    },
    ['api', 'output/release/build/api', '9'.repeat(64), 1, 101],
    ['worker', 'output/release/build/worker', 'a'.repeat(64), 1, 102],
    ['iac', 'output/release/cdk.out', 'b'.repeat(64), 4, 103],
  ].map((entry) =>
    Array.isArray(entry)
      ? {
          name: entry[0],
          sourcePath: entry[1],
          kind: 'DIRECTORY',
          files: entry[3],
          bytes: entry[4],
          sha256: entry[2],
        }
      : entry,
  );
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: 'BUILD_ONCE_FREEZE',
    releaseId: 'rel-20260818-1300-ccccccc',
    candidateSha: 'c'.repeat(40),
    candidateTreeSha: 'd'.repeat(40),
    releaseTag: 'v0.1.0-rc.1',
    environment: config.environment,
    authorizationScope: config.authorization.scope,
    region: config.aws.region,
    sourceRunId: 'e6-20260818t120000z-0123abcd',
    sourceArtifactId: '123456',
    sourceArtifactSha256: 'c'.repeat(64),
    preFreezeEvidenceSha256: 'd'.repeat(64),
    builtAt: '2026-08-18T13:00:00.000Z',
    configSha256: objectSha256(config),
    lockfileSha256: 'e'.repeat(64),
    openApiSha256: baseline.openApiSha256,
    generatedClientSha256: baseline.generatedClientSha256,
    publicConfigSha256:
      targetWebDirectory === undefined
        ? 'f'.repeat(64)
        : fileSha256(path.join(targetWebDirectory, 'public-config.json')),
    templateSha256: artifacts[3].sha256,
    stage6Gates: { 'GATE-E6-01': 'PASS', 'GATE-E6-02': 'PASS', 'GATE-E6-03': 'PASS' },
    toolchain: {
      node: process.version,
      packageManager: 'pnpm@11.19.0',
      cdkCli: '2.1136.0',
      cdkLibrary: '2.265.0',
      awsCli: '2.31.0',
    },
    artifacts,
    controlInventory: {
      artifacts: {
        total: STAGE7_ARTIFACTS.length,
        idsSha256: objectSha256(STAGE7_ARTIFACTS.map(({ id }) => id)),
      },
      evidence: {
        total: STAGE7_EVIDENCE.length,
        idsSha256: objectSha256(STAGE7_EVIDENCE.map(({ id }) => id)),
      },
      audits: {
        total: STAGE7_AUDITS.length,
        idsSha256: objectSha256(STAGE7_AUDITS.map(({ id }) => id)),
      },
    },
    releaseMode: 'VERSIONED_UPDATE',
    updateReleaseSupported: true,
    updateReleaseUnsupportedReason: null,
    buildOnce: { immutable: true, rebuilt: false },
    containsSensitiveData: false,
  };
  return validateFreezeManifest({ ...body, manifestSha256: objectSha256(body) });
};

const withBaselineSelfTestExecutors = ({ command, request }, work) => {
  const previousCommand = commandExecutor;
  const previousRequest = requestExecutor;
  commandExecutor = command;
  requestExecutor = request;
  try {
    return work();
  } finally {
    commandExecutor = previousCommand;
    requestExecutor = previousRequest;
  }
};

export const selfTestBaselineEstablishment = () => {
  validateBaselineAwsCommandInventory();
  const now = new Date('2026-08-18T12:30:00.000Z');
  const config = validateBaselineConfig(createBaselineConfigSelfTestFixture(), { now });
  const stage6SourceBodyFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE6_SOURCE_ARTIFACT_PROVENANCE',
    status: 'PASS',
    repository: 'ivanmonsalve0404/async-checkout-demo',
    workflowPath: '.github/workflows/ci.yml',
    event: 'push',
    ref: 'refs/heads/master',
    headSha: 'a'.repeat(40),
    runId: '24681012',
    runAttempt: 1,
    conclusion: 'success',
    artifactName: 'verification-reports',
    artifactId: 1357911,
    artifactDigest: `sha256:${'9'.repeat(64)}`,
    artifactExpired: false,
    stage6ManifestSha256: '1'.repeat(64),
    stage6InternalRunId: 'e6-20260818t120000z-0123abcd',
    stage6CandidateTreeSha: 'b'.repeat(40),
    responseSha256: sha256(
      JSON.stringify({
        run: {
          id: 24681012,
          runAttempt: 1,
          path: '.github/workflows/ci.yml',
          event: 'push',
          headBranch: 'master',
          headSha: 'a'.repeat(40),
          conclusion: 'success',
        },
        artifact: {
          id: 1357911,
          name: 'verification-reports',
          digest: `sha256:${'9'.repeat(64)}`,
          expired: false,
        },
      }),
    ),
    capturedAtUtc: now.toISOString(),
    externalRequests: 2,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  const stage6Source = validateStage6SourceProvenance({
    ...stage6SourceBodyFixture,
    provenanceSha256: objectSha256(stage6SourceBodyFixture),
  });
  validateStage6SourceProvenance(stage6Source, {
    expectedRunId: '24681012',
    expectedArtifactId: '1357911',
    expectedArtifactDigest: `sha256:${'9'.repeat(64)}`,
  });
  for (const expected of [
    { expectedRunId: '24681013' },
    { expectedArtifactId: '1357912' },
    { expectedArtifactDigest: `sha256:${'8'.repeat(64)}` },
  ]) {
    assert.throws(
      () => validateStage6SourceProvenance(stage6Source, expected),
      /E7_STAGE6_SOURCE_PROVENANCE_INVALID/u,
    );
  }
  const freeze = createBaselineFreezeSelfTestFixture(config, {
    stage6SourceProvenanceSha256: sha256(`${JSON.stringify(stage6Source, null, 2)}\n`),
    stage6SourceProvenanceObjectSha256: stage6Source.provenanceSha256,
  });
  const iamEvidence = createIamEffectivePermissionsSelfTestFixture({
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    manifestSha256: freeze.manifestSha256,
    config,
  });
  const preflightBodyFixture = {
    schemaVersion: 1,
    stage: 7,
    kind: 'FULL_BASELINE_AWS_PREFLIGHT',
    status: 'PASS_CLOSED_BASELINE_ONLY',
    candidateSha: freeze.candidateSha,
    releaseId: freeze.releaseId,
    configSha256: objectSha256(config),
    freezeManifestSha256: freeze.manifestSha256,
    hostedZone: {
      idSha256: sha256(config.domain.hostedZoneId),
      nameSha256: sha256(`${config.domain.hostedZoneName}.`),
      public: true,
      targetRecordsAbsent: true,
    },
    certificates: [
      {
        purpose: 'WEB_CLOUDFRONT',
        region: 'us-east-1',
        arnSha256: sha256(config.domain.webCertificateArn),
        hostnameSha256: sha256(config.domain.hostname),
        status: 'ISSUED',
      },
      {
        purpose: 'API_REGIONAL',
        region: config.aws.region,
        arnSha256: sha256(config.domain.apiCertificateArn),
        hostnameSha256: sha256(config.domain.apiHostname),
        status: 'ISSUED',
      },
    ],
    restrictedAccess: {
      bindingSha256: accessBindingSha256(config),
      keyGroupSha256: sha256(config.prereleaseAccess.keyGroupId),
      publicKeySha256: sha256(config.prereleaseAccess.publicKeyId),
      algorithm: 'RSA',
      secretArnSha256: sha256(config.prereleaseAccess.originTokenSecretArn),
      secretVersionIdSha256: sha256(config.prereleaseAccess.originTokenSecretVersionId),
      secretStatus: 'ACTIVE',
      kmsKeyMode: 'AWS_MANAGED_SECRETS_MANAGER',
      rotationDuringWindow: 'FORBIDDEN',
    },
    bootstrap: { status: 'PASS', version: 24, stackIdSha256: 'a'.repeat(64) },
    capacity: {
      lambdaReservedRequired: 6,
      lambdaConcurrentLimit: 1000,
      lambdaReservedInUse: 200,
      remainingAfterBaseline: 794,
    },
    costGuard: {
      budgetContractSha256: objectSha256(config.budget),
      maxUsd: 10,
      upperBoundUsd: 10,
    },
    notificationConfirmation: 'REQUIRED_AFTER_DEPLOY_BEFORE_ACTIVATION',
    externalRequests: 11,
    mutationsPerformed: 0,
    containsSensitiveData: false,
    verifiedAtUtc: now.toISOString(),
  };
  const awsPreflight = validateBaselineAwsPreflight(
    {
      ...preflightBodyFixture,
      preflightSha256: objectSha256(preflightBodyFixture),
    },
    { config, freeze },
  );
  for (const restrictedAccess of [
    { ...awsPreflight.restrictedAccess, kmsKeyMode: 'CUSTOM_KMS' },
    { ...awsPreflight.restrictedAccess, secretVersionIdSha256: '0'.repeat(64) },
  ]) {
    const tampered = { ...preflightBody(awsPreflight), restrictedAccess };
    assert.throws(
      () =>
        validateBaselineAwsPreflight(
          { ...tampered, preflightSha256: objectSha256(tampered) },
          { config, freeze },
        ),
      Stage7BaselineError,
    );
  }
  for (const prereleaseAccess of [
    {
      ...config.prereleaseAccess,
      keyGroupId: config.prereleaseAccess.publicKeyId,
    },
    {
      ...config.prereleaseAccess,
      publicKeyId: config.prereleaseAccess.keyGroupId,
    },
  ]) {
    assert.throws(
      () => validateBaselineConfig({ ...config, prereleaseAccess }, { now }),
      Stage7BaselineError,
    );
  }
  const crossAccountConfig = {
    ...config,
    prereleaseAccess: {
      ...config.prereleaseAccess,
      originTokenSecretArn: config.prereleaseAccess.originTokenSecretArn.replace(
        config.aws.accountId,
        '999999999999',
      ),
    },
  };
  assert.throws(() => validateBaselineConfig(crossAccountConfig, { now }), Stage7BaselineError);
  validateBaselinePreDeploymentState({
    ...Object.fromEntries(expectedStacks().map((name) => [name, 'ABSENT'])),
    [expectedStacks()[0]]: 'EXISTING_BASELINE_EXACT',
  });
  assert.throws(
    () =>
      validateBaselinePreDeploymentState({
        ...Object.fromEntries(expectedStacks().map((name) => [name, 'ABSENT'])),
        [expectedStacks()[1]]: 'EXISTING_BASELINE_EXACT',
      }),
    Stage7BaselineError,
  );
  const temporary = mkdtempSync(path.join(os.tmpdir(), 'stage7-baseline-self-test-'));
  activeBaselineSelfTestRoot = temporary;
  let selfTestResult;
  const write = (name, value) => {
    const filename = path.join(temporary, name);
    writeJson(filename, value, name);
    return filename;
  };
  try {
    const rawDiff = 'safe closed baseline creation diff\n';
    const rawDiffFilename = path.join(temporary, BASELINE_PROVENANCE_FILENAMES.rawDiff);
    writeFileSync(rawDiffFilename, rawDiff, { encoding: 'utf8', mode: 0o600 });
    const iam = iamEvidence.iamEffectivePermissions ?? iamEvidence;
    const planBodyFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'FULL_BASELINE_CLOSED_DIFF',
      status: 'READY_FOR_PROTECTED_BASELINE_REVIEW',
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      configSha256: objectSha256(config),
      freezeManifestSha256: freeze.manifestSha256,
      assemblySha256: freeze.assemblySha256,
      iamEvidenceSha256: objectSha256(iamEvidence),
      iamBindingSha256: iam.bindingSha256,
      awsPreflightSha256: awsPreflight.preflightSha256,
      stacks: expectedStacks(),
      preDeploymentState: Object.fromEntries(expectedStacks().map((name) => [name, 'ABSENT'])),
      diffSha256: sha256(rawDiff.trim()),
      rawDiffArtifactSha256: fileSha256(rawDiffFilename),
      risks: {
        statefulReplacement: false,
        statefulDeletion: false,
        rollbackControlReplacement: false,
        destructiveChangeMentioned: false,
        iamOrPolicyReviewRequired: true,
      },
      publicationState: 'DISABLED',
      publicReleaseEffectsAllowed: false,
      generatedAtUtc: now.toISOString(),
      containsSensitiveData: false,
    };
    const plan = validateBaselinePlan(
      { ...planBodyFixture, planSha256: objectSha256(planBodyFixture) },
      { config, freeze, iamEvidence, awsPreflight },
    );
    const githubApproval = {
      schemaVersion: 1,
      stage: 7,
      kind: 'GITHUB_ENVIRONMENT_APPROVAL',
      status: 'PASS',
      scope: 'baseline',
      repository: 'ivanmonsalve0404/async-checkout-demo',
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      runId: '123456789',
      runAttempt: 1,
      environment: 'assessment-release-baseline',
      reviewerAlias: 'release-reviewer',
      reviewed: true,
      reviewState: 'approved',
      iamReviewAttested: true,
      iamReviewedDiffSha256: plan.rawDiffArtifactSha256,
      responseSha256: 'b'.repeat(64),
      capturedAtUtc: now.toISOString(),
      externalRequests: 1,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    const githubApprovalFilename = write(
      BASELINE_PROVENANCE_FILENAMES.githubApproval,
      githubApproval,
    );
    const oldRunId = process.env.GITHUB_RUN_ID;
    const oldRunAttempt = process.env.GITHUB_RUN_ATTEMPT;
    process.env.GITHUB_RUN_ID = githubApproval.runId;
    process.env.GITHUB_RUN_ATTEMPT = String(githubApproval.runAttempt);
    const approval = createBaselineApproval({
      config,
      freeze,
      plan,
      githubApproval,
      githubApprovalFilename,
    });
    if (oldRunId === undefined) delete process.env.GITHUB_RUN_ID;
    else process.env.GITHUB_RUN_ID = oldRunId;
    if (oldRunAttempt === undefined) delete process.env.GITHUB_RUN_ATTEMPT;
    else process.env.GITHUB_RUN_ATTEMPT = oldRunAttempt;
    const stackEvidence = Object.fromEntries(
      expectedStacks().map((name) => [
        name,
        {
          status: 'CREATE_COMPLETE',
          stackIdSha256: sha256(name),
          terminationProtection: true,
          publicationState:
            name.endsWith('-api') || name.endsWith('-web') ? 'DISABLED' : 'NOT_APPLICABLE',
        },
      ]),
    );
    const deploymentBodyFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'FULL_BASELINE_CLOSED_DEPLOYMENT',
      status: 'DEPLOYED_DISABLED_REQUIRES_RESTRICTED_SMOKE',
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      configSha256: objectSha256(config),
      freezeManifestSha256: freeze.manifestSha256,
      approvedPlanSha256: plan.planSha256,
      approvalSha256: approval.approvalSha256,
      stacks: stackEvidence,
      deploymentMethod: 'CLOUDFORMATION_CHANGE_SET',
      publicationState: 'DISABLED',
      restrictedAccessBindingSha256: awsPreflight.restrictedAccess.bindingSha256,
      publicReleaseEffectsAllowed: false,
      tagCreated: false,
      releaseCreated: false,
      readmeChanged: false,
      gateE703: 'NOT_RUN',
      deployedAtUtc: now.toISOString(),
      containsSensitiveData: false,
    };
    const deployment = validateBaselineDeployment(
      {
        ...deploymentBodyFixture,
        deploymentSha256: objectSha256(deploymentBodyFixture),
      },
      { config, freeze, plan, approval },
    );
    const seedBodyFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'FULL_BASELINE_IDEMPOTENT_CATALOG_SEED',
      status: 'PASS',
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      configSha256: objectSha256(config),
      freezeManifestSha256: freeze.manifestSha256,
      deploymentSha256: deployment.deploymentSha256,
      catalogTableNameSha256: sha256('checkout-assessment-release-catalog'),
      checkoutTableNameSha256: sha256('checkout-assessment-release-checkout'),
      productId: 'product-demo-001',
      firstExecution: 'CREATED',
      secondExecution: 'EXISTS',
      publicOriginSha256: sha256(`https://${config.domain.hostname}`),
      runtimeSecretArnSha256: sha256(config.prereleaseAccess.originTokenSecretArn),
      runtimeSecretVersionIdSha256: sha256(config.prereleaseAccess.originTokenSecretVersionId),
      environmentBindingSha256: objectSha256({
        appEnvironment: 'assessment',
        autoSeedCatalog: false,
        dataAdapter: 'dynamodb',
        paymentAdapter: 'sandbox',
        paymentsEnabled: true,
        prereleaseAccessMode: 'cloudfront_signed_cookie',
        tokenizationMode: 'direct_jwe',
      }),
      syntheticDataOnly: true,
      stockResetPerformed: false,
      publicationState: 'DISABLED',
      executedAtUtc: now.toISOString(),
      externalRequests: 0,
      mutationsPerformed: 2,
      containsSensitiveData: false,
    };
    const seed = validateBaselineSeed(
      { ...seedBodyFixture, seedSha256: objectSha256(seedBodyFixture) },
      { config, freeze, deployment },
    );
    const notificationBodyFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'FULL_BASELINE_NOTIFICATION_CONFIRMATION',
      status: 'PASS',
      candidateSha: freeze.candidateSha,
      releaseId: freeze.releaseId,
      deploymentSha256: deployment.deploymentSha256,
      topicArnSha256: sha256(
        `arn:aws:sns:${config.aws.region}:${config.aws.accountId}:checkout-assessment-release-alerts`,
      ),
      destinationSha256: config.budget.alertDestinationSha256,
      confirmedSubscriptions: 1,
      pages: 1,
      externalRequests: 3,
      mutationsPerformed: 0,
      verifiedAtUtc: now.toISOString(),
      containsSensitiveData: false,
    };
    const notification = validateBaselineNotification(
      {
        ...notificationBodyFixture,
        notificationSha256: objectSha256(notificationBodyFixture),
      },
      { config, freeze, deployment },
    );
    const activation = validateBaselineActivation(
      {
        schemaVersion: 1,
        stage: 7,
        kind: 'FULL_BASELINE_RESTRICTED_ACTIVATION',
        status: 'ENABLED_WITH_SIGNED_COOKIE_AND_ORIGIN_GATE_ONLY',
        candidateSha: freeze.candidateSha,
        releaseId: freeze.releaseId,
        deploymentSha256: deployment.deploymentSha256,
        notificationSha256: notification.notificationSha256,
        seedEvidenceSha256: seed.seedSha256,
        restrictedAccessBindingSha256: deployment.restrictedAccessBindingSha256,
        publicationState: 'ENABLED_RESTRICTED',
        publicReleaseEffectsAllowed: false,
        activatedAtUtc: now.toISOString(),
        containsSensitiveData: false,
      },
      { config, freeze, deployment, notification, seed },
    );
    const tamperedNotificationBody = {
      ...notificationBody(notification),
      topicArnSha256: '0'.repeat(64),
    };
    assert.throws(
      () =>
        validateBaselineNotification(
          {
            ...tamperedNotificationBody,
            notificationSha256: objectSha256(tamperedNotificationBody),
          },
          { config, freeze, deployment },
        ),
      Stage7BaselineError,
    );
    let interceptedCommands = 0;
    let interceptedRequests = 0;
    const previousRunId = process.env.GITHUB_RUN_ID;
    const previousRunAttempt = process.env.GITHUB_RUN_ATTEMPT;
    process.env.GITHUB_RUN_ID = githubApproval.runId;
    process.env.GITHUB_RUN_ATTEMPT = String(githubApproval.runAttempt);
    try {
      withBaselineSelfTestExecutors(
        {
          command: () => {
            interceptedCommands += 1;
            throw new Error('SELF_TEST_COMMAND_MUST_NOT_RUN');
          },
          request: async () => {
            interceptedRequests += 1;
            throw new Error('SELF_TEST_REQUEST_MUST_NOT_RUN');
          },
        },
        () => {
          assert.throws(
            () =>
              deployBaselineAws({
                config,
                freeze,
                plan: { ...plan, planSha256: '0'.repeat(64) },
                approval,
                iamEvidence,
                awsPreflight,
                githubApproval,
                githubApprovalFilename,
                rawDiffFilename,
                app: temporary,
                now,
              }),
            Stage7BaselineError,
          );
          assert.throws(
            () =>
              activateRestrictedBaselineAws({
                config,
                freeze,
                awsPreflight,
                iamEvidence,
                deployment,
                plan,
                approval,
                githubApproval,
                rawDiffFilename,
                githubApprovalFilename,
                notification,
                seed,
                app: temporary,
                now: new Date(config.window.endsAtUtc),
              }),
            Stage7BaselineError,
          );
        },
      );
    } finally {
      if (previousRunId === undefined) delete process.env.GITHUB_RUN_ID;
      else process.env.GITHUB_RUN_ID = previousRunId;
      if (previousRunAttempt === undefined) delete process.env.GITHUB_RUN_ATTEMPT;
      else process.env.GITHUB_RUN_ATTEMPT = previousRunAttempt;
    }
    assert.equal(interceptedCommands, 0);
    assert.equal(interceptedRequests, 0);
    const pending = runPendingCompatibilityFocalTest({ freeze, now });
    const apiContract = compatibilityEvidence(
      {
        schemaVersion: 1,
        stage: 7,
        kind: 'BASELINE_API_CONTRACT_COMPATIBILITY',
        status: 'PASS',
        candidateSha: freeze.candidateSha,
        releaseId: freeze.releaseId,
        openApiSha256: freeze.openApiSha256,
        frozenOpenApiSha256: freeze.openApiSha256,
        docsStatus: 200,
        healthStatus: 200,
        strategy: 'EXPAND_CONTRACT_N_AND_N_MINUS_1',
        verifiedAtUtc: now.toISOString(),
        externalRequests: 3,
        mutationsPerformed: 0,
        containsSensitiveData: false,
      },
      'BASELINE_API_CONTRACT_COMPATIBILITY',
    );
    let ledger = newTrafficLedger({ config, freeze, now });
    for (let index = 0; index < BASELINE_REQUEST_LIMIT; index += 1) {
      ledger = reserveTrafficProbe({
        ledger,
        config,
        freeze,
        probeId: `probe-${index + 1}`,
        url: `https://${config.domain.hostname}/probe-${index + 1}`,
        now,
      });
    }
    const completedLedger = { ...trafficLedgerBody(ledger), status: 'COMPLETE' };
    ledger = validateTrafficLedger(
      { ...completedLedger, ledgerSha256: objectSha256(completedLedger) },
      { config, freeze, complete: true },
    );
    const apiContractFilename = write(BASELINE_EVIDENCE_FILENAMES[0], apiContract);
    const pendingFilename = write(BASELINE_EVIDENCE_FILENAMES[1], pending);
    const trafficLedgerFilename = write(BASELINE_EVIDENCE_FILENAMES[3], ledger);
    const smoke = compatibilityEvidence(
      {
        schemaVersion: 1,
        stage: 7,
        kind: 'BASELINE_RESTRICTED_SMOKE',
        status: 'PASS',
        candidateSha: freeze.candidateSha,
        releaseId: freeze.releaseId,
        anonymousWebStatus: 403,
        expiredCookieStatus: 403,
        tamperedCookieStatus: 403,
        directApiStatus: 403,
        directApiSpoofStatus: 403,
        authorizedProductStatus: 200,
        authorizedDocsStatus: 200,
        authorizedHealthStatus: 200,
        restrictedAccessBindingSha256: deployment.restrictedAccessBindingSha256,
        trafficLedgerSha256: fileSha256(trafficLedgerFilename),
        trafficRequestsUsed: BASELINE_REQUEST_LIMIT,
        verifiedAtUtc: now.toISOString(),
        externalRequests: BASELINE_REQUEST_LIMIT,
        mutationsPerformed: 0,
        containsSensitiveData: false,
      },
      'BASELINE_RESTRICTED_SMOKE',
    );
    const smokeFilename = write(BASELINE_EVIDENCE_FILENAMES[2], smoke);
    const disable = validateBaselineDisable(
      {
        schemaVersion: 1,
        stage: 7,
        kind: 'FULL_BASELINE_CLOSED_DISABLE',
        status: 'PASS',
        candidateSha: freeze.candidateSha,
        releaseId: freeze.releaseId,
        publicationState: 'DISABLED',
        distributionEnabled: false,
        schedulerState: 'DISABLED',
        trafficPublicAfterCapture: false,
        disabledAtUtc: now.toISOString(),
        containsSensitiveData: false,
      },
      { freeze },
    );
    const provenanceValues = {
      config,
      freeze,
      stage6Source,
      awsPreflight,
      iam: iamEvidence,
      plan,
      githubApproval,
      approval,
      deployment,
      seed,
      notification,
      activation,
      disable,
    };
    const provenanceFiles = { rawDiff: rawDiffFilename };
    for (const [key, value] of Object.entries(provenanceValues)) {
      try {
        provenanceFiles[key] =
          key === 'githubApproval'
            ? githubApprovalFilename
            : write(BASELINE_PROVENANCE_FILENAMES[key], value);
      } catch (error) {
        throw new Error(
          `BASELINE_SELF_TEST_PROVENANCE_WRITE_FAILED:${key}:${JSON.stringify(
            scanArtifactText(key, `${JSON.stringify(value, null, 2)}\n`),
          )}`,
          { cause: error },
        );
      }
    }
    const resources = {
      api: {
        functionName: 'checkout-assessment-release-api',
        aliasName: 'live',
        version: '7',
        codeSha256: 'd'.repeat(64),
      },
      worker: {
        functionName: 'checkout-assessment-release-worker',
        aliasName: 'live',
        version: '8',
        codeSha256: 'e'.repeat(64),
      },
      web: {
        bucketName: 'checkout-assessment-release-web-123456789012',
        distributionId: 'EDFDVBD6EXAMPLE',
        objects: [
          {
            key: 'index.html',
            versionId: 'version-index-1',
            etagSha256: 'f'.repeat(64),
            contentSha256: '1'.repeat(64),
            bytes: 100,
          },
          {
            key: 'public-config.json',
            versionId: 'version-config-1',
            etagSha256: '2'.repeat(64),
            contentSha256: '3'.repeat(64),
            bytes: 101,
          },
        ],
        mutableInvalidationPaths: ['/index.html', '/public-config.json'],
      },
    };
    const capture = captureBaselineAws({
      config,
      freeze,
      awsPreflight,
      iamEvidence,
      deployment,
      seed,
      plan,
      approval,
      githubApproval,
      notification,
      activation,
      disable,
      apiContract,
      pending,
      smoke,
      apiContractFilename,
      pendingFilename,
      smokeFilename,
      trafficLedgerFilename,
      provenanceFiles,
      selfTestToken: SELF_TEST_CAPTURE_TOKEN,
      observed: {
        dataOutputs: {
          CatalogTableName: 'checkout-assessment-release-catalog',
          CheckoutTableName: 'checkout-assessment-release-checkout',
        },
        resources,
      },
      now,
    });
    const captureFilename = write('stage7-previous-release.json', capture);
    validateBaselineCapture(capture, temporary);
    const finalDisable = validateBaselineDisable(
      { ...disable, disabledAtUtc: new Date(now.getTime() + 1_000).toISOString() },
      { freeze },
    );
    const finalDisableFilename = write(BASELINE_FINAL_DISABLE_FILENAME, finalDisable);
    const bundleDirectory = path.join(temporary, 'stage7-previous-release');
    const bundle = createPreviousReleaseBundle({
      capture,
      captureFilename,
      finalDisableFilename,
      recoveryArtifactId: 192837465,
      recoveryArtifactDigest: `sha256:${'c'.repeat(64)}`,
      evidenceDirectory: temporary,
      outputDirectory: bundleDirectory,
      sourceRunId: '123456789',
      sourceRunAttempt: 1,
      sourceWorkflowPath: BASELINE_WORKFLOW_PATH,
      sourceEvent: 'workflow_dispatch',
      sourceRef: 'refs/heads/master',
      sourceHeadSha: capture.baseline.candidateSha,
      now,
    });
    assert.equal(bundle.index.artifactName, 'stage7-previous-release');
    const bundleCaptureFilename = path.join(bundleDirectory, BASELINE_CAPTURE_FILENAME);
    const targetConfig = validateStage7Config(targetConfigFixture(), { now });
    const targetWebDirectory = path.join(temporary, 'target-web');
    mkdirSync(targetWebDirectory, { mode: 0o700 });
    writeFileSync(
      path.join(targetWebDirectory, 'index.html'),
      '<!doctype html><meta name="stage7-release-id" content="rel-20260818-1300-ccccccc">\n',
      { encoding: 'utf8', flag: 'wx', mode: 0o600 },
    );
    writeFileSync(
      path.join(targetWebDirectory, 'public-config.json'),
      `${JSON.stringify({
        apiBaseUrl: '/api/v1',
        productId: 'product-demo-001',
        releaseId: 'rel-20260818-1300-ccccccc',
      })}\n`,
      { encoding: 'utf8', flag: 'wx', mode: 0o600 },
    );
    for (const { path: relative, contents } of BASELINE_IMMUTABLE_WEB_SELF_TEST_CONTENTS) {
      const filename = path.join(targetWebDirectory, ...relative.split('/'));
      mkdirSync(path.dirname(filename), { recursive: true, mode: 0o700 });
      writeFileSync(filename, contents, { encoding: 'utf8', flag: 'wx', mode: 0o600 });
    }
    const targetFreeze = targetFreezeFixture(targetConfig, capture.baseline, {
      targetWebDirectory,
    });
    const targetWebDelta = validateTargetWebRollbackDelta({
      baselineFreeze: freeze,
      capture,
      targetFreeze,
      targetWebDirectory,
    });
    assert.notEqual(
      targetWebDelta.targetIndexSha256,
      capture.resources.web.objects.find(({ key }) => key === 'index.html').contentSha256,
    );
    assert.notEqual(
      targetWebDelta.targetPublicConfigSha256,
      capture.resources.web.objects.find(({ key }) => key === 'public-config.json').contentSha256,
    );
    const targetIndexFixture = readFileSync(path.join(targetWebDirectory, 'index.html'));
    const targetPublicConfigFixture = readFileSync(
      path.join(targetWebDirectory, 'public-config.json'),
    );
    const assertTargetReleaseIdentityRejected = (basename, contents) => {
      const filename = path.join(targetWebDirectory, basename);
      writeFileSync(filename, contents, { mode: 0o600 });
      assert.throws(
        () =>
          validateTargetWebRollbackDelta({
            baselineFreeze: freeze,
            capture,
            targetFreeze,
            targetWebDirectory,
          }),
        /E7_BASELINE_TARGET_WEB_RELEASE_IDENTITY_INVALID/u,
      );
      writeFileSync(
        filename,
        basename === 'index.html' ? targetIndexFixture : targetPublicConfigFixture,
        { mode: 0o600 },
      );
    };
    assertTargetReleaseIdentityRejected('index.html', '<!doctype html><div id="root"></div>\n');
    assertTargetReleaseIdentityRejected(
      'index.html',
      `${targetIndexFixture.toString('utf8')}<meta name="stage7-release-id" content="rel-20260818-1300-ccccccc">\n`,
    );
    assertTargetReleaseIdentityRejected(
      'index.html',
      targetIndexFixture
        .toString('utf8')
        .replace('rel-20260818-1300-ccccccc', 'rel-20260818-1300-ddddddd'),
    );
    assertTargetReleaseIdentityRejected(
      'public-config.json',
      `${JSON.stringify({
        apiBaseUrl: '/api/v1',
        productId: 'product-demo-001',
        releaseId: 'rel-20260818-1300-ddddddd',
      })}\n`,
    );
    assertTargetReleaseIdentityRejected(
      'public-config.json',
      `${JSON.stringify({
        apiBaseUrl: '/api/v1',
        productId: 'product-demo-001',
        releaseId: 'rel-20260818-1300-ccccccc',
        unexpected: true,
      })}\n`,
    );
    for (const { path: relative, contents } of BASELINE_IMMUTABLE_WEB_SELF_TEST_CONTENTS) {
      const filename = path.join(targetWebDirectory, ...relative.split('/'));
      writeFileSync(filename, `${contents}changed\n`, { encoding: 'utf8', mode: 0o600 });
      assert.throws(
        () =>
          validateTargetWebRollbackDelta({
            baselineFreeze: freeze,
            capture,
            targetFreeze,
            targetWebDirectory,
          }),
        /E7_BASELINE_TARGET_WEB_IMMUTABLE_CONTENT_CHANGED/u,
      );
      writeFileSync(filename, contents, { encoding: 'utf8', mode: 0o600 });
    }
    for (const [key, contentSha256] of [
      ['index.html', targetWebDelta.targetIndexSha256],
      ['public-config.json', targetWebDelta.targetPublicConfigSha256],
    ]) {
      const sameContentCapture = {
        ...capture,
        resources: {
          ...capture.resources,
          web: {
            ...capture.resources.web,
            objects: capture.resources.web.objects.map((entry) =>
              entry.key === key ? { ...entry, contentSha256 } : entry,
            ),
          },
        },
      };
      assert.throws(
        () =>
          validateTargetWebRollbackDelta({
            baselineFreeze: freeze,
            capture: sameContentCapture,
            targetFreeze,
            targetWebDirectory,
          }),
        /E7_BASELINE_TARGET_WEB_ROLLBACK_NOT_DISTINCT/u,
      );
    }
    const sourceProvenanceBodyFixture = {
      schemaVersion: 1,
      stage: 7,
      kind: 'BASELINE_SOURCE_ARTIFACT_PROVENANCE',
      status: 'PASS',
      repository: 'ivanmonsalve0404/async-checkout-demo',
      workflowPath: BASELINE_WORKFLOW_PATH,
      event: 'workflow_dispatch',
      ref: 'refs/heads/master',
      headSha: capture.baseline.candidateSha,
      runId: bundle.index.sourceRunId,
      runAttempt: bundle.index.sourceRunAttempt,
      conclusion: 'success',
      artifactName: bundle.index.artifactName,
      artifactId: 987654321,
      artifactDigest: `sha256:${'f'.repeat(64)}`,
      artifactExpired: false,
      bundleSha256: bundle.index.bundleSha256,
      responseSha256: sha256(
        JSON.stringify({
          run: {
            id: Number(bundle.index.sourceRunId),
            runAttempt: bundle.index.sourceRunAttempt,
            path: BASELINE_WORKFLOW_PATH,
            event: 'workflow_dispatch',
            headBranch: 'master',
            headSha: capture.baseline.candidateSha,
            conclusion: 'success',
          },
          artifact: {
            id: 987654321,
            name: bundle.index.artifactName,
            digest: `sha256:${'f'.repeat(64)}`,
            expired: false,
          },
        }),
      ),
      capturedAtUtc: now.toISOString(),
      externalRequests: 2,
      mutationsPerformed: 0,
      containsSensitiveData: false,
    };
    const sourceProvenance = validateBaselineSourceProvenance(
      {
        ...sourceProvenanceBodyFixture,
        provenanceSha256: objectSha256(sourceProvenanceBodyFixture),
      },
      { bundleIndex: bundle.index, capture },
    );
    const tamperedSourceBody = {
      ...sourceProvenanceBodyFixture,
      responseSha256: '0'.repeat(64),
    };
    assert.throws(
      () =>
        validateBaselineSourceProvenance({
          ...tamperedSourceBody,
          provenanceSha256: objectSha256(tamperedSourceBody),
        }),
      Stage7BaselineError,
    );
    const bound = bindBaselineForTarget({
      capture,
      captureFilename: bundleCaptureFilename,
      evidenceDirectory: bundleDirectory,
      expectedCaptureSha256: fileSha256(bundleCaptureFilename),
      bundleIndex: bundle.index,
      sourceProvenance,
      targetConfig,
      targetFreeze,
      targetWebDirectory,
      targetCompatibilityOutput: path.join(temporary, 'baseline-target-compatibility.json'),
    });
    validateStage7PreviousReleaseManifest(bound.previousRelease);
    validateStage7PreviousReleaseHandoff(bound.previousRelease, {
      sourceProvenance,
      targetCompatibility: bound.targetCompatibility,
      finalDisableProvenance: bound.finalDisableProvenance,
    });
    assert.equal(bound.targetCompatibility.status, 'PASS');
    assert.equal(
      bound.finalDisableProvenance.evidenceSha256,
      bundle.index.finalRecovery.evidenceSha256,
    );
    const tamperedFinalDisableBody = {
      ...finalDisable,
      disabledAtUtc: new Date(now.getTime() - 1_000).toISOString(),
    };
    const tamperedFinalDisableFilename = write(
      'baseline-final-disable-tampered.json',
      tamperedFinalDisableBody,
    );
    assert.throws(
      () =>
        createPreviousReleaseBundle({
          capture,
          captureFilename,
          finalDisableFilename: tamperedFinalDisableFilename,
          recoveryArtifactId: 192837465,
          recoveryArtifactDigest: `sha256:${'c'.repeat(64)}`,
          evidenceDirectory: temporary,
          outputDirectory: path.join(temporary, 'tampered-stage7-previous-release'),
          sourceRunId: '123456789',
          sourceRunAttempt: 1,
          sourceWorkflowPath: BASELINE_WORKFLOW_PATH,
          sourceEvent: 'workflow_dispatch',
          sourceRef: 'refs/heads/master',
          sourceHeadSha: capture.baseline.candidateSha,
          now,
        }),
      Stage7BaselineError,
    );
    for (const mutate of [
      (value) => ({ ...value, region: 'us-west-2' }),
      (value) => ({
        ...value,
        baseline: { ...value.baseline, openApiSha256: '0'.repeat(64) },
      }),
      (value) => ({
        ...value,
        topology: {
          ...value.topology,
          domain: { ...value.topology.domain, hostnameSha256: '0'.repeat(64) },
        },
      }),
      (value) => ({
        ...value,
        provenance: { ...value.provenance, plan: '0'.repeat(64) },
      }),
    ]) {
      const tamperedBody = captureBody(mutate(capture));
      assert.throws(
        () =>
          validateBaselineCapture(
            { ...tamperedBody, captureSha256: objectSha256(tamperedBody) },
            temporary,
          ),
        Stage7BaselineError,
      );
    }
    selfTestResult = {
      status: 'PASS',
      assertions: 46,
      focalTests: 125,
      externalRequests: 0,
      mutationsPerformed: 0,
    };
  } finally {
    rmSync(temporary, { force: true, recursive: true, maxRetries: 10, retryDelay: 100 });
    activeBaselineSelfTestRoot = null;
  }
  if (existsSync(temporary)) fail('E7_BASELINE_SELF_TEST_CLEANUP_FAILED');
  return selfTestResult;
};
