#!/usr/bin/env node
/* global structuredClone */

import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
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
  STAGE7_ARTIFACTS,
  STAGE7_EVIDENCE,
  Stage7Error,
  assessStage6Manifest,
  createFreezeManifest,
  createLocalPreflight,
  createStage7Index,
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
  validateStage7PrereleaseCleanupCheckpoint,
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
  readPrivateSmokeInputs,
  runCanonicalStage7Smoke,
  selfTestDeployedSmoke,
  validateCanonicalSmokeResults,
} from './deployed-smoke.mjs';
import {
  Stage7QualityError,
  runDeployedQuality,
  selfTestDeployedQuality,
  validateQualityPayload,
} from './deployed-quality.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-([0-9]{8})-([0-9]{4})-([0-9a-f]{7})$/u;
const RELEASE_TAG = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-rc\.[1-9][0-9]*$/u;
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
const REQUIRED_FULL_EVIDENCE = [
  'release-metadata.json',
  'verify-candidate.json',
  'candidate-manifest.json',
  'checksums-sbom.json',
  'security.json',
  'prefreeze.json',
  'aws-auth.json',
  'infra-synth.json',
  'infra-diff.json',
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
  'repromotion-smoke-input-preflight.json',
  'rollback.json',
  'drift.json',
];
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
  'rollback-check',
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
  'deploy-prerelease',
  'external-verification',
  'external-evidence',
  'cleanup',
];

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
  const sandboxHostSha256 = digest('sandbox.wompi.co');
  const fullRelease = config.authorization.scope === 'FULL_RELEASE_INITIAL_ONLY';
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
    !exactKeys(value.targets, ['ownedOriginSha256', 'sandboxHostSha256']) ||
    value.targets.ownedOriginSha256 !== originSha256 ||
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
        minimumRequests: 3,
      },
      originSha256,
      now,
    ),
    sandboxSmoke: externalAuthorization(
      value.authorizations.sandboxSmoke,
      {
        id: fullRelease ? 'AUTH-E7-EXT-02' : 'AUTH-E6-02',
        scope: 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
        minimumRequests: 7,
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
  return { value, authorizations, origin, originSha256, sandboxHostSha256 };
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
  const expected = scope === 'full' ? 'FULL_RELEASE_INITIAL_ONLY' : 'EPHEMERAL_PRERELEASE';
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
  const result = {
    schemaVersion: 1,
    stage: 7,
    kind: 'RELEASE_ENTRY_PREFLIGHT',
    status: 'PASS',
    scope,
    candidateSha: identity.candidateSha,
    releaseId: identity.releaseId,
    candidateTreeSha: identity.treeSha,
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
      (scope === 'full' ? 'FULL_RELEASE_INITIAL_ONLY' : 'EPHEMERAL_PRERELEASE') ||
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
  void flags;
  fail('E7_UPDATE_RELEASE_NOT_SUPPORTED_INITIAL_ONLY');
};

const requireCurrentFreeze = (flags, scope, identity, config) => {
  const manifest = validateFreezeManifest(readEvidence(requiredString(flags, 'manifest')));
  if (
    manifest.candidateSha !== identity.candidateSha ||
    manifest.candidateTreeSha !== identity.treeSha ||
    manifest.releaseId !== identity.releaseId ||
    manifest.releaseTag !== (scope === 'full' ? identity.releaseTag : null) ||
    manifest.authorizationScope !==
      (scope === 'full' ? 'FULL_RELEASE_INITIAL_ONLY' : 'EPHEMERAL_PRERELEASE') ||
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
    if (!['.active', 'safe.txt', 'unsafe.bin'].includes(child.name)) {
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
  return {
    root,
    assemblySha256: hashArtifactPath(root, { rootDirectory: workspaceRoot }).sha256,
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
    synthCheckpoint?.releaseMode !== 'INITIAL' ||
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
    'cloudformation:describe-stacks',
    'iam:get-role',
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
    expectedSubs.length > 2 ||
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
  const baseEnvironment =
    config.authorization.scope === 'FULL_RELEASE_INITIAL_ONLY'
      ? 'assessment-release'
      : 'assessment-prerelease';
  const expectedEnvironments =
    config.authorization.scope === 'EPHEMERAL_PRERELEASE' &&
    [config.aws.roles.readRoleArn, config.aws.roles.deployRoleArn].includes(roleArn)
      ? [baseEnvironment, 'assessment-prerelease-external']
      : [baseEnvironment];
  return expectedEnvironments.map(
    (environment) => `repo:ivanmonsalve0404/async-checkout-demo:environment:${environment}`,
  );
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

const validateBootstrap = () => {
  const result = awsJson('cloudformation', 'describe-stacks', ['--stack-name', 'CDKToolkit']);
  const stack = result.Stacks?.[0];
  const version = Number(
    stack?.Outputs?.find((output) => output.OutputKey === 'BootstrapVersion')?.OutputValue,
  );
  if (!Number.isSafeInteger(version) || version < 14) fail('E7_CDK_BOOTSTRAP_INCOMPATIBLE');
  return version;
};

const REQUIRED_QUOTAS = Object.freeze({
  cloudformation: { quotaCode: 'L-0485CB21', additional: 4 },
  lambda: { quotaCode: 'L-B99A9384', additional: 2 },
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

const validateQuotas = () => {
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
  const stacks = awsJson('cloudformation', 'describe-stacks').Stacks;
  const lambdaSettings = awsJson('lambda', 'get-account-settings');
  const tables = awsJson('dynamodb', 'list-tables').TableNames;
  const distributions = awsJson('cloudfront', 'list-distributions').DistributionList;
  if (
    !Array.isArray(stacks) ||
    !Array.isArray(tables) ||
    !object(distributions) ||
    !Number.isSafeInteger(Number(distributions.Quantity)) ||
    !Number.isSafeInteger(Number(lambdaSettings.AccountLimit?.ConcurrentExecutions)) ||
    !Number.isSafeInteger(Number(lambdaSettings.AccountLimit?.UnreservedConcurrentExecutions))
  ) {
    fail('E7_AWS_QUOTA_USAGE_READ_INVALID');
  }
  return validateRequiredQuotaCapacity({
    quotaResponses,
    usage: {
      cloudformation: stacks.length,
      lambda:
        Number(lambdaSettings.AccountLimit.UnreservedConcurrentExecutions) >= 0
          ? Number(lambdaSettings.AccountLimit.ConcurrentExecutions ?? 0) -
            Number(lambdaSettings.AccountLimit.UnreservedConcurrentExecutions)
          : Number.NaN,
      dynamodb: tables.length,
      cloudfront: Number(distributions.Quantity),
    },
  });
};

const awsReadPreflight = async (flags) => {
  const scope = scopeOf(flags);
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
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
  const freeze = preFreeze ? null : requireCurrentFreeze(flags, scope, identity, config);
  const caller = callerIdentityFor(config, config.aws.roles.readRoleArn);
  validateRoleTrust(config, config.aws.roles.readRoleArn);
  const bootstrapVersion = validateBootstrap();
  const quotaCapacity = validateQuotas();
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
    bootstrapVersion,
    quotaCapacity,
    capacityProven: true,
    decision: preFreeze ? 'READY_FOR_BUILD_FREEZE' : 'READY_FOR_CLOUD_OPERATIONS',
    preFreezeException: preFreeze,
    longLivedCredentials: false,
    externalRequests: 11,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
  await emitJson(result, flags.evidence, 'stage7-aws-read-preflight.json');
};

const mutationAuthorityPreflight = async (flags, mode) => {
  const scope = scopeOf(flags);
  const config = configFromEnvironment();
  verifyConfigScope(config, scope);
  const identity = candidateIdentity(scope);
  const freeze = requireCurrentFreeze(flags, scope, identity, config);
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
    !object(checkpoint) ||
    checkpoint.decision !== 'READY_FOR_PROTECTED_REVIEW' ||
    checkpoint.releaseMode !== 'INITIAL' ||
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
  const plan = validateDiffReview(readEvidence(planFilename), scope, identity, config);
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
  const reviewerAlias = process.env.GITHUB_ACTOR?.toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$/u.test(reviewerAlias ?? '')) {
    fail('E7_PROTECTED_APPROVAL_REVIEWER_INVALID');
  }
  const approvedAtUtc = new Date().toISOString();
  if (
    Date.parse(approvedAtUtc) < Date.parse(config.window.startsAtUtc) ||
    Date.parse(approvedAtUtc) > Date.parse(config.window.endsAtUtc)
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
    approvedPlanSha256: fileDigest(planFilename),
    approvedDiffSha256: rawDiffSha256,
    approvedAtUtc,
    statefulReplacements: 0,
    destructiveChanges: 0,
    iamBroadeningDetected: plan.iamBroadeningDetected,
    iamBroadeningReviewed: true,
    humanReviewConfirmed: true,
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

const deploymentTarget = (directory, config, identity) => {
  const document = readEvidence(findExactlyOne(directory, 'deployment.json'));
  const applicationUrl = document?.urls?.application ?? document?.applicationUrl;
  let origin;
  try {
    const parsed = new URL(applicationUrl);
    if (parsed.protocol !== 'https:' || parsed.pathname !== '/' || parsed.search || parsed.hash) {
      fail('E7_DEPLOYMENT_EVIDENCE_TARGET_INVALID');
    }
    origin = parsed.origin;
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
    document.nonPublic !== true ||
    document.syntheticOnly !== true ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_DEPLOYMENT_EVIDENCE_INVALID');
  }
  return { document, applicationOrigin: origin };
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
    document.authorizationScope !== 'FULL_RELEASE_INITIAL_ONLY' ||
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
    minimumRequests: 3,
  },
  {
    key: 'sandboxSmoke',
    id: scope === 'full' ? 'AUTH-E7-EXT-02' : 'AUTH-E6-02',
    scope: 'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
    minimumRequests: 7,
  },
  {
    key: 'passiveSecurity',
    id: scope === 'full' ? 'AUTH-E7-EXT-03' : 'AUTH-E6-03',
    scope:
      scope === 'full' ? 'PASSIVE_BASELINE_OWNED_RELEASE_ONLY' : 'PASSIVE_BASELINE_OWNED_QA_ONLY',
    minimumRequests: 6,
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
  });
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
    sandboxHostSha256: validated.sandboxHostSha256,
    authorizationSha256: objectSha256(validated.value),
    authorizationIds: externalAuthorizationRequirements(scope).map(({ id }) => id),
    requestLimits: Object.fromEntries(
      externalAuthorizationRequirements(scope).map(({ key, id }) => [
        id,
        validated.authorizations[key].maxRequests,
      ]),
    ),
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
  if (scope === 'full') {
    if (flags.deployment !== undefined) fail('E7_ZAP_DEPLOYMENT_SOURCE_SCOPE_INVALID');
    callerIdentityFor(config, config.aws.roles.readRoleArn);
    target = webTarget(config, identity);
    readExternalAuthorizations({
      config,
      identity,
      deployedOrigin: target.applicationOrigin,
    });
  } else {
    target = deploymentTarget(requiredString(flags, 'deployment'), config, identity);
    readExternalAuthorizations({
      config,
      identity,
      deployedOrigin: target.applicationOrigin,
    });
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
  const ruleset = process.env.STAGE7_ZAP_RULESET;
  const requestCount = Number(process.env.STAGE7_ZAP_REQUEST_COUNT);
  if (
    typeof filename !== 'string' ||
    typeof ruleset !== 'string' ||
    process.env.STAGE7_ZAP_VERSION !== '2.16.1' ||
    !Number.isSafeInteger(requestCount) ||
    requestCount < 1 ||
    requestCount > 100
  ) {
    fail('E7_ZAP_CAPTURE_METADATA_INVALID');
  }
  const report = readExternalJson(filename, 'zap-passive-report.json');
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
    ownEndpointsScanned: requestCount,
    ownEndpointsOutOfScope: 0,
    findings: { total, reviewed: total, ...counts },
    manualValidation: 'ALL_ALERTS_REVIEWED',
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
  let authority;
  try {
    authority = readExternalAuthorizations({
      config,
      identity,
      deployedOrigin: target.applicationOrigin,
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
  const httpUrl = `http://${new URL(applicationUrl).host}/`;
  const redirect = await fetchChecked(httpUrl);
  const redirectLocation = redirect.headers.get('location');
  if (![301, 308].includes(redirect.status) || redirectLocation !== `${applicationUrl}/`) {
    fail('E7_DEPLOYED_HTTP_REDIRECT_INVALID');
  }
  const document = await fetchChecked(`${applicationUrl}/`);
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
  const health = await fetchChecked(target.outputs.HealthUrl);
  const docs = await fetchChecked(target.outputs.ApiDocsUrl);
  if (
    health.status !== 200 ||
    docs.status !== 200 ||
    !/^no-store(?:,|$)/iu.test(health.headers.get('cache-control') ?? '')
  ) {
    fail('E7_DEPLOYED_SENSITIVE_RESPONSE_INVALID');
  }
  const allowedCors = await fetchChecked(target.outputs.HealthUrl, {
    method: 'OPTIONS',
    headers: {
      origin: target.applicationOrigin,
      'access-control-request-method': 'GET',
    },
  });
  const deniedCors = await fetchChecked(target.outputs.HealthUrl, {
    method: 'OPTIONS',
    headers: {
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
    externalRequests:
      directOriginRequests + awsPrivateOriginRequests + (zap?.requestCount ?? 0) + 2,
    mutationsPerformed: 0,
    containsSensitiveData: false,
  };
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

const runAvailableSmoke = async ({ origin }) => {
  let requests = 0;
  const request = async (pathname) => {
    const url = new URL(pathname, `${origin}/`);
    if (url.origin !== origin) fail('E7_SMOKE_TARGET_ESCAPE');
    requests += 1;
    if (requests > 2) fail('E7_SMOKE_REQUEST_LIMIT_EXCEEDED');
    let response;
    try {
      response = await fetch(url, {
        redirect: 'error',
        headers: {
          accept: 'text/html',
          origin,
          'sec-fetch-site': 'same-origin',
        },
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      fail('E7_SMOKE_REQUEST_FAILED');
    }
    return response;
  };
  const root = await request('/');
  const rootText = await boundedResponseText(root);
  const deepLink = await request('/products/product-demo-001');
  const deepLinkText = await boundedResponseText(deepLink);
  const results = [
    {
      id: 'PR-UAT-E7-01',
      name: 'https-document-available',
      status:
        root.status === 200 && /^text\/html\b/iu.test(root.headers.get('content-type') ?? '')
          ? 'PASS'
          : 'FAIL',
    },
    {
      id: 'PR-UAT-E7-02',
      name: 'deep-link-document-available',
      status:
        deepLink.status === 200 &&
        /^text\/html\b/iu.test(deepLink.headers.get('content-type') ?? '')
          ? 'PASS'
          : 'FAIL',
    },
    {
      id: 'PR-UAT-E7-03',
      name: 'mixed-content-markup-zero',
      status: !/(?:src|href)=["']http:\/\//iu.test(`${rootText}\n${deepLinkText}`)
        ? 'PASS'
        : 'FAIL',
    },
  ];
  if (results.some(({ status }) => status !== 'PASS')) fail('E7_PRERELEASE_UAT_FAILED');
  return { results, requests, rootStatus: root.status, rootText };
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
  const authority = readExternalAuthorizations({
    config,
    identity,
    deployedOrigin: target.applicationOrigin,
  });
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
            })
          : await runAvailableSmoke({ origin: target.applicationOrigin });
    const ownedRequestCount =
      typeof smoke.requests === 'number' ? smoke.requests : smoke.requests.ownedOrigin;
    const sandboxRequestCount = typeof smoke.requests === 'number' ? 0 : smoke.requests.sandbox;
    const outsideAllowlist =
      typeof smoke.requests === 'number' ? 0 : smoke.requests.outsideAllowlist;
    const mutations =
      mode === 'POST_ROLLBACK_INITIAL' || scope === 'prerelease' ? 0 : smoke.requests.mutations;
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
        provider: sandboxRequestCount,
        production: 0,
        outsideAllowlist,
      },
      syntheticDataOnly: true,
      dataMutations: mutations,
      ...(smoke.effects === undefined ? {} : { effects: smoke.effects }),
      ...(smoke.criticalErrors === undefined ? {} : { criticalErrors: smoke.criticalErrors }),
      ...(smoke.browser === undefined ? {} : { browser: smoke.browser }),
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
      }),
      externalRequests: ownedRequestCount + sandboxRequestCount + 2,
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
      ? 'SMOKE_INPUT_PREFLIGHT_INITIAL'
      : evidenceBasename === 'repromotion-smoke-input-preflight.json'
        ? 'SMOKE_INPUT_PREFLIGHT_REPROMOTION'
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
      decision: 'READY_FOR_INITIAL_ACTIVATION_SMOKE',
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
    checks: capability.checks,
    requests: capability.requests,
    result: capability.result,
    productionRequests: 0,
    duplicateEffects: 0,
    stage6Capability: scope === 'prerelease' ? { sandboxSmoke: capability } : undefined,
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

const evidenceFileMap = (directory) => {
  const map = new Map();
  for (const file of walkFiles(directory).files) {
    const basename = path.basename(file.relative);
    if (!basename.endsWith('.json') && basename !== 'infra-diff.txt') continue;
    if (map.has(basename)) fail('E7_EVIDENCE_BASENAME_DUPLICATE');
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
  if (
    checkpoint.decision !== 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION' ||
    checkpoint.releaseMode !== 'INITIAL' ||
    checkpoint.stackName !== `checkout-${config.environment}-${suffix}` ||
    checkpoint.freezeManifestSha256 !== manifest.manifestSha256 ||
    checkpoint.deploymentMethod !== 'CLOUDFORMATION_CHANGE_SET' ||
    checkpoint.hotswapUsed !== false ||
    checkpoint.outputs?.CandidateSha !== identity.candidateSha ||
    checkpoint.outputs?.ReleaseId !== identity.releaseId ||
    !SHA256.test(checkpoint.assemblySha256 ?? '') ||
    !SHA256.test(checkpoint.outputsSha256 ?? '')
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
}) => {
  const ids = externalAuthorizationRequirements('full').map(({ id }) => id);
  if (
    !exactKeys(authorization.requestLimits, ids) ||
    !SHA256.test(authorization.authorizationSha256 ?? '') ||
    !SHA256.test(authorization.ownedOriginSha256 ?? '') ||
    !SHA256.test(authorization.sandboxHostSha256 ?? '') ||
    !Array.isArray(usages) ||
    usages.length !== expectedUsageIds.length
  ) {
    fail('E7_AUTHORIZATION_LEDGER_INVALID');
  }
  const seen = new Set();
  const totals = Object.fromEntries(ids.map((id) => [id, 0]));
  for (const usage of usages) {
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
      totals[id] += count;
    }
  }
  if (
    [...seen].sort(stableCompare).join('\0') !==
      [...expectedUsageIds].sort(stableCompare).join('\0') ||
    ids.some(
      (id) =>
        !Number.isSafeInteger(authorization.requestLimits[id]) ||
        authorization.requestLimits[id] < 1 ||
        totals[id] > authorization.requestLimits[id],
    )
  ) {
    fail('E7_AUTHORIZATION_LEDGER_LIMIT_EXCEEDED');
  }
  return { totals, limits: authorization.requestLimits, usageIds: [...seen].sort(stableCompare) };
};

const assertFullEvidence = (map, identity, config) => {
  const passNames = REQUIRED_FULL_EVIDENCE.filter(
    (basename) =>
      ![
        'infra-diff.json',
        'approval.json',
        'data.json',
        'api.json',
        'observability.json',
        'web.json',
        'activation.json',
        'drift.json',
      ].includes(basename),
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
  if (
    diffFilename === undefined ||
    approvalFilename === undefined ||
    rawDiffFilename === undefined
  ) {
    fail('E7_REQUIRED_EVIDENCE_MISSING');
  }
  evidence['infra-diff.json'] = validateDiffReview(
    readEvidence(diffFilename),
    'full',
    identity,
    config,
  );
  evidence['approval.json'] = readEvidence(approvalFilename);
  const manifest = evidence['candidate-manifest.json'];
  if (
    manifest.configSha256 !== objectSha256(config) ||
    manifest.releaseMode !== 'INITIAL_ONLY' ||
    manifest.updateReleaseSupported !== false
  ) {
    fail('E7_FULL_MANIFEST_MODE_INVALID');
  }
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
  const synth = evidence['infra-synth.json'];
  const diff = evidence['infra-diff.json'];
  const approval = evidence['approval.json'];
  const smoke = evidence['smoke.json'];
  const quality = evidence['quality.json'];
  const edge = evidence['edge-security.json'];
  const sandbox = evidence['sandbox-smoke.json'];
  const rollback = evidence['rollback.json'];
  const authorization = evidence['external-authorization.json'];
  const smokeInput = evidence['smoke-input-preflight.json'];
  const repromotionInput = evidence['repromotion-smoke-input-preflight.json'];
  const activation = evidence['activation.json'].checkpoints.activation;
  const readiness = evidence['observability.json'].checkpoints.observabilityReadiness;
  const drift = evidence['drift.json'].checkpoints.drift;
  const qualityPayload = {
    crossBrowser: quality.crossBrowser,
    accessibility: quality.accessibility,
    lighthouse: quality.lighthouse,
    requests: quality.requests,
    criticalErrors: quality.criticalErrors,
  };
  validateCanonicalSmokeResults(smoke.results);
  validateQualityPayload(qualityPayload);
  const expectedAuthorizationIds = externalAuthorizationRequirements('full').map(({ id }) => id);
  const expectedTopic = `arn:aws:sns:${config.aws.region}:${config.aws.accountId}:checkout-${config.environment}-alerts`;
  const rollbackSmoke = rollback.checkpoints?.rollbackSmoke;
  const repromotionSmoke = rollback.checkpoints?.repromotionSmoke;
  try {
    validateStage7ActivationCheckpoint(activation, {
      config,
      candidateSha: identity.candidateSha,
      releaseId: identity.releaseId,
      manifestSha256: manifest.manifestSha256,
      complete: true,
    });
    validateStage7InitialRollbackCheckpoint(rollback.checkpoints?.rollbackInfrastructure, {
      config,
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
  const ledgerUsages = [
    authorization.authorizationUsage,
    smokeInput.authorizationUsage,
    ...activationUsages,
    smoke.authorizationUsage,
    quality.authorizationUsage,
    edge.authorizationUsage,
    sandbox.authorizationUsage,
    rollbackSmoke?.authorizationUsage,
    repromotionInput.authorizationUsage,
    repromotionSmoke?.authorizationUsage,
  ];
  const ledger = validateAuthorizationLedger({
    authorization,
    usages: ledgerUsages,
    identity,
    config,
    expectedUsageIds: [
      'EXTERNAL_AUTHORIZATION_PREFLIGHT',
      'SMOKE_INPUT_PREFLIGHT_INITIAL',
      'ACTIVATION_INITIAL',
      'SMOKE_POST_DEPLOY',
      'QUALITY_FOCAL',
      'EDGE_PASSIVE',
      'SANDBOX_ONE_USE',
      'SMOKE_POST_ROLLBACK_INITIAL',
      'SMOKE_INPUT_PREFLIGHT_REPROMOTION',
      'ACTIVATION_REPROMOTION',
      'SMOKE_POST_REPROMOTION',
    ],
  });
  const usageCount = (usage, id) => usage?.requestCounts?.[id];
  const [ownedAuthorizationId, sandboxAuthorizationId, passiveAuthorizationId] =
    expectedAuthorizationIds;
  const exactDriftStacks = drift.stacks.map(({ stackName }) => stackName);
  const approvalPlanSha256 = fileDigest(diffFilename);
  const approvalDiffSha256 = fileDigest(rawDiffFilename);
  if (
    security.secretFindings !== 0 ||
    security.productionProviderReferences !== 0 ||
    aws.longLivedCredentials !== false ||
    aws.roleTrust !== 'PASS' ||
    synth.secretFindings !== 0 ||
    synth.publicBucketRisks !== 0 ||
    synth.wildcardCorsRisks !== 0 ||
    synth.freezeManifestSha256 !== manifest.manifestSha256 ||
    synth.assemblySha256 !== diff.cloudAssemblySha256 ||
    !SHA256.test(synth.frozenVerificationSha256 ?? '') ||
    diff.checkpoints.diff.freezeManifestSha256 !== manifest.manifestSha256 ||
    diff.statefulReplacements !== 0 ||
    diff.destructiveChanges !== 0 ||
    approval.kind !== 'PROTECTED_RELEASE_APPROVAL' ||
    approval.status !== 'PASS' ||
    approval.scope !== 'full' ||
    approval.candidateSha !== identity.candidateSha ||
    approval.releaseId !== identity.releaseId ||
    approval.releaseTag !== identity.releaseTag ||
    approval.configSha256 !== objectSha256(config) ||
    approval.cloudAssemblySha256 !== diff.cloudAssemblySha256 ||
    approval.freezeManifestSha256 !== diff.checkpoints.diff.freezeManifestSha256 ||
    approval.approvedPlanSha256 !== approvalPlanSha256 ||
    approval.approvedDiffSha256 !== approvalDiffSha256 ||
    approval.approvedDiffSha256 !== diff.rawDiffArtifactSha256 ||
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
    ledger.usageIds.length !== 11 ||
    smokeInput.kind !== 'PRIVATE_SMOKE_INPUT_PREFLIGHT' ||
    smokeInput.decision !== 'READY_FOR_INITIAL_ACTIVATION_SMOKE' ||
    smokeInput.configSha256 !== objectSha256(config) ||
    repromotionInput.kind !== 'PRIVATE_SMOKE_INPUT_PREFLIGHT' ||
    repromotionInput.decision !== 'READY_FOR_INITIAL_ACTIVATION_SMOKE' ||
    repromotionInput.configSha256 !== objectSha256(config) ||
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
    usageCount(edge.authorizationUsage, passiveAuthorizationId) !==
      edge.requests?.ownedOrigin + edge.requests?.zap ||
    sandbox.productionRequests !== 0 ||
    sandbox.duplicateEffects !== 0 ||
    sandbox.requests?.outsideAllowlist !== 0 ||
    sandbox.requests?.production !== 0 ||
    sandbox.result?.duplicateEffects !== 0 ||
    usageCount(sandbox.authorizationUsage, sandboxAuthorizationId) !== sandbox.requests?.total ||
    rollback.initialRelease !== true ||
    rollback.updateReleaseSupported !== false ||
    rollback.rollbackMode !== 'INITIAL_DISABLE_UNPUBLISH' ||
    rollbackSmoke?.status !== 'PASS' ||
    rollbackSmoke?.mode !== 'POST_ROLLBACK_INITIAL' ||
    rollbackSmoke?.total !== 4 ||
    rollbackSmoke?.passed !== 4 ||
    rollbackSmoke?.failed !== 0 ||
    rollbackSmoke?.dataMutations !== 0 ||
    usageCount(rollbackSmoke?.authorizationUsage, ownedAuthorizationId) !==
      rollbackSmoke?.requests ||
    repromotionSmoke?.status !== 'PASS' ||
    repromotionSmoke?.mode !== 'POST_REPROMOTION' ||
    repromotionSmoke?.total !== 18 ||
    repromotionSmoke?.passed !== 18 ||
    repromotionSmoke?.failed !== 0 ||
    !Number.isSafeInteger(repromotionSmoke?.dataMutations) ||
    repromotionSmoke.dataMutations <= 0 ||
    usageCount(repromotionSmoke?.authorizationUsage, ownedAuthorizationId) +
      usageCount(repromotionSmoke?.authorizationUsage, sandboxAuthorizationId) !==
      repromotionSmoke?.requests ||
    exactDriftStacks.join('\0') !== config.authorization.stacks.join('\0')
  ) {
    fail('E7_REQUIRED_EVIDENCE_CONTROL_FAILED');
  }
  if (
    manifest.releaseMode === 'INITIAL_ONLY' ||
    manifest.updateReleaseSupported !== true ||
    rollback.initialRelease === true ||
    rollback.rollbackMode === 'INITIAL_DISABLE_UNPUBLISH'
  ) {
    fail('E7_PREVIOUS_APPROVED_RELEASE_REQUIRED');
  }
  evidence.authorizationLedger = ledger;
  return evidence;
};

const publicationUrls = (web) => {
  const outputs = web?.checkpoints?.web?.outputs;
  const urls = {
    application: outputs?.ApplicationUrl,
    api: outputs?.ApiUrl,
    docs: outputs?.ApiDocsUrl,
    health: outputs?.HealthUrl,
  };
  if (!exactKeys(urls, ['application', 'api', 'docs', 'health'])) {
    fail('E7_PUBLICATION_URLS_INVALID');
  }
  const resolved = {
    ...urls,
    repository: 'https://github.com/ivanmonsalve0404/async-checkout-demo',
  };
  for (const [name, value] of Object.entries(resolved)) {
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      fail('E7_PUBLICATION_URLS_INVALID');
    }
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.hash) {
      fail('E7_PUBLICATION_URLS_INVALID');
    }
    if (name === 'repository' && parsed.hostname !== 'github.com')
      fail('E7_PUBLICATION_URLS_INVALID');
  }
  return resolved;
};

const publicationPackage = async (flags) => {
  const identity = candidateIdentity('full', { requireGitTag: true });
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const map = evidenceFileMap(requiredString(flags, 'evidence'));
  const evidence = assertFullEvidence(map, identity, config);
  const urls = publicationUrls(evidence['web.json']);
  const readme = readFileSync(path.join(workspaceRoot, 'README.md'), 'utf8').replace(
    /\r\n?/gu,
    '\n',
  );
  const deploymentSection = [
    '<!-- STAGE7_URLS_START -->',
    '## Entorno desplegado',
    '',
    `- Aplicación: ${urls.application}`,
    `- API: ${urls.api}`,
    `- OpenAPI: ${urls.docs}`,
    `- Salud: ${urls.health}`,
    `- Repositorio: ${urls.repository}`,
    '',
    `Release candidate: \`${identity.releaseTag}\` (\`${identity.candidateSha}\`).`,
    '<!-- STAGE7_URLS_END -->',
  ].join('\n');
  const nextReadme = /<!-- STAGE7_URLS_START -->[\s\S]*?<!-- STAGE7_URLS_END -->/u.test(readme)
    ? readme.replace(
        /<!-- STAGE7_URLS_START -->[\s\S]*?<!-- STAGE7_URLS_END -->/u,
        deploymentSection,
      )
    : `${readme.trimEnd()}\n\n${deploymentSection}\n`;
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
  let desiredReadmeGitBlobSha;
  try {
    readmeGitBlobSha = execFileSync('git', ['rev-parse', 'HEAD:README.md'], {
      cwd: workspaceRoot,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
    desiredReadmeGitBlobSha = execFileSync('git', ['hash-object', readmeTarget], {
      cwd: workspaceRoot,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
  } catch {
    fail('E7_PUBLICATION_README_BLOB_UNAVAILABLE');
  }
  if (!SHA.test(readmeGitBlobSha) || !SHA.test(desiredReadmeGitBlobSha)) {
    fail('E7_PUBLICATION_README_BLOB_UNAVAILABLE');
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
    expectedReadmeGitBlobSha: readmeGitBlobSha,
    desiredReadmeGitBlobSha,
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
      prerelease: true,
      assetName: 'candidate-manifest.json',
      notesSha256: fileDigest(notesTarget),
    },
    publicationOrder: ['GITHUB_RELEASE', 'README'],
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
      'expectedReadmeGitBlobSha',
      'desiredReadmeGitBlobSha',
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
    !SHA.test(plan.expectedReadmeGitBlobSha ?? '') ||
    !SHA.test(plan.desiredReadmeGitBlobSha ?? '') ||
    !exactKeys(plan.urls, ['application', 'api', 'docs', 'health', 'repository']) ||
    Object.values(plan.urls).some((value) => typeof value !== 'string') ||
    plan.urls.repository !== `https://github.com/${plan.repository}` ||
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
    plan.release.prerelease !== true ||
    plan.release.assetName !== 'candidate-manifest.json' ||
    plan.release.notesSha256 !== plan.files.releaseNotesSha256 ||
    plan.publicationOrder?.join('\0') !== ['GITHUB_RELEASE', 'README'].join('\0') ||
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
        'x-github-api-version': '2022-11-28',
      },
      signal: AbortSignal.timeout(15_000),
    });
  } catch {
    fail('E7_GITHUB_READ_FAILED');
  }
  if (response.status !== 200) fail('E7_GITHUB_READ_FAILED');
  const source = await response.text();
  if (source.length < 2 || source.length > 4 * 1024 * 1024) fail('E7_GITHUB_READ_INVALID');
  try {
    return JSON.parse(source);
  } catch {
    fail('E7_GITHUB_READ_INVALID');
  }
};

const verifyPublishedUrl = async (value) => {
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
    response = await fetch(parsed, {
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

const publicationNativeVerification = async (flags) => {
  const identity = candidateIdentity('full', { requireGitTag: true });
  const planFilename = checkedWorkspacePath(requiredString(flags, 'publication-native'), {
    directory: false,
  });
  const plan = validatePublicationPlan(readEvidence(planFilename), identity);
  const publicationDirectory = path.dirname(planFilename);
  const outputs = {
    readme: path.join(publicationDirectory, 'README.md'),
    notes: path.join(publicationDirectory, 'release-notes.md'),
    manifest: path.join(publicationDirectory, 'candidate-manifest.json'),
  };
  for (const filename of Object.values(outputs))
    checkedWorkspacePath(filename, { directory: false });
  let desiredReadmeGitBlobSha;
  try {
    desiredReadmeGitBlobSha = execFileSync('git', ['hash-object', outputs.readme], {
      cwd: workspaceRoot,
      encoding: 'utf8',
      windowsHide: true,
    }).trim();
  } catch {
    fail('E7_PUBLICATION_PACKAGE_INVALID');
  }
  if (
    desiredReadmeGitBlobSha !== plan.desiredReadmeGitBlobSha ||
    fileDigest(outputs.readme) !== plan.files?.readmeSha256 ||
    fileDigest(outputs.notes) !== plan.files?.releaseNotesSha256 ||
    fileDigest(outputs.manifest) !== plan.files?.candidateManifestSha256
  ) {
    fail('E7_PUBLICATION_PACKAGE_INVALID');
  }
  const repositoryPath = '/repos/ivanmonsalve0404/async-checkout-demo';
  const [repository, readme, commits, tagReference, release] = await Promise.all([
    githubJson(repositoryPath),
    githubJson(`${repositoryPath}/contents/README.md?ref=master`),
    githubJson(`${repositoryPath}/commits?sha=master&path=README.md&per_page=1`),
    githubJson(`${repositoryPath}/git/ref/tags/${encodeURIComponent(identity.releaseTag)}`),
    githubJson(`${repositoryPath}/releases/tags/${encodeURIComponent(identity.releaseTag)}`),
  ]);
  const asset = Array.isArray(release.assets)
    ? release.assets.find((entry) => entry?.name === 'candidate-manifest.json')
    : undefined;
  if (
    repository.full_name !== plan.repository ||
    repository.private !== false ||
    repository.html_url !== plan.urls?.repository ||
    readme.sha !== plan.desiredReadmeGitBlobSha ||
    !Array.isArray(commits) ||
    !SHA.test(commits[0]?.sha ?? '') ||
    tagReference.object?.type !== 'commit' ||
    tagReference.object?.sha !== identity.candidateSha ||
    release.tag_name !== plan.release.title ||
    release.name !== plan.release.title ||
    release.draft !== plan.release.draft ||
    release.prerelease !== plan.release.prerelease ||
    String(release.body ?? '').replace(/\r\n?/gu, '\n') !==
      readFileSync(outputs.notes, 'utf8').replace(/\r\n?/gu, '\n') ||
    typeof release.html_url !== 'string' ||
    release.assets?.length !== 1 ||
    asset?.name !== plan.release.assetName ||
    asset?.state !== 'uploaded' ||
    asset?.digest !== `sha256:${plan.files.candidateManifestSha256}`
  ) {
    fail('E7_PUBLICATION_REMOTE_STATE_INVALID');
  }
  await Promise.all(
    ['application', 'api', 'docs', 'health'].map((name) => verifyPublishedUrl(plan.urls?.[name])),
  );
  const externalWritesPerformed = Number(requiredString(flags, 'external-writes-performed'));
  if (
    !Number.isSafeInteger(externalWritesPerformed) ||
    externalWritesPerformed < 0 ||
    externalWritesPerformed > 2
  ) {
    fail('E7_PUBLICATION_WRITE_COUNT_INVALID');
  }
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
    readmeUpdated: true,
    readmeCommitSha: commits[0].sha,
    releaseCreated: true,
    releaseVerifiedExact: true,
    releaseTargetSha: identity.candidateSha,
    releaseUrl: release.html_url,
    urlsVerified: true,
    publicationPlanSha256: objectSha256(plan),
    verifiedAtUtc: new Date().toISOString(),
    externalWritesPerformed,
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
      'readmeUpdated',
      'readmeCommitSha',
      'releaseCreated',
      'releaseVerifiedExact',
      'releaseTargetSha',
      'releaseUrl',
      'urlsVerified',
      'publicationPlanSha256',
      'verifiedAtUtc',
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
    document.readmeUpdated !== true ||
    !SHA.test(document.readmeCommitSha ?? '') ||
    document.releaseCreated !== true ||
    document.releaseVerifiedExact !== true ||
    document.releaseTargetSha !== identity.candidateSha ||
    typeof document.releaseUrl !== 'string' ||
    !document.releaseUrl.startsWith(`https://github.com/${plan.repository}/releases/tag/`) ||
    document.urlsVerified !== true ||
    document.publicationPlanSha256 !== objectSha256(plan) ||
    !utc(document.verifiedAtUtc) ||
    document.externalWritesPerformed < 0 ||
    document.externalWritesPerformed > 2 ||
    document.containsSensitiveData !== false
  ) {
    fail('E7_PUBLICATION_PROOF_INVALID');
  }
  return document;
};

const validateSuccessfulJobResults = (source, scope) => {
  if (typeof source !== 'string' || source.length === 0 || source.length > 256 * 1024) {
    fail('E7_JOB_RESULTS_REQUIRED');
  }
  let results;
  try {
    results = parseStrictJsonSource(Buffer.from(source), { scanForbiddenData: false });
  } catch {
    fail('E7_JOB_RESULTS_INVALID');
  }
  const expected = scope === 'prerelease' ? REQUIRED_PRERELEASE_JOBS : REQUIRED_FULL_JOBS;
  const keys = Object.keys(results);
  if (
    !object(results) ||
    keys.toSorted(stableCompare).join('\0') !== expected.toSorted(stableCompare).join('\0') ||
    Object.values(results).some((job) => !object(job) || job.result !== 'success')
  ) {
    fail('E7_JOB_RESULTS_NOT_SUCCESSFUL');
  }
  return keys.sort(stableCompare);
};

const successfulJobResults = (scope) =>
  validateSuccessfulJobResults(process.env.STAGE7_JOB_RESULTS, scope);

const verifiedArtifactStates = () =>
  Object.fromEntries(
    Array.from({ length: STAGE7_ARTIFACTS.length }, (_, index) => [
      `ART-REL-${String(index + 1).padStart(2, '0')}`,
      'VERIFIED',
    ]),
  );

const passedEvidenceStates = () =>
  Object.fromEntries(
    Array.from({ length: STAGE7_EVIDENCE.length - 3 }, (_, index) => [
      `EVD-E7-${String(index + 1).padStart(2, '0')}`,
      'PASS',
    ]),
  );

const verifyFullRelease = async (flags) => {
  const identity = candidateIdentity('full', { requireGitTag: true });
  const config = configFromEnvironment();
  verifyConfigScope(config, 'full');
  const jobs = successfulJobResults('full');
  const map = evidenceFileMap(requiredString(flags, 'evidence'));
  const evidence = assertFullEvidence(map, identity, config);
  const planFilename = map.get('publication-plan.json');
  const proofFilename = map.get('publication-proof.json');
  if (planFilename === undefined || proofFilename === undefined) {
    fail('E7_PUBLICATION_PROOF_MISSING');
  }
  const plan = validatePublicationPlan(readEvidence(planFilename), identity);
  const proof = validatePublicationProof(readEvidence(proofFilename), identity, plan);
  const index = createStage7Index({
    entryGate: 'PASS',
    artifactStates: verifiedArtifactStates(),
    evidenceStates: passedEvidenceStates(),
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
    releaseMode: 'INITIAL_ONLY',
    updateReleaseSupported: false,
    updateReleaseUnsupportedReason: 'PRE_ACTIVATION_PUBLICATION_RISK',
    cloudFormationDrift: { checked: 4, criticalCount: 0, status: 'IN_SYNC' },
    authorizationLedger: evidence.authorizationLedger,
    publication: {
      releaseUrl: proof.releaseUrl,
      readmeCommitSha: proof.readmeCommitSha,
      repositoryPublic: true,
      urlsVerified: true,
    },
    jobs,
    index,
    gates: index.gates,
    artifacts: { verified: 20, total: 20 },
    evidence: { pass: 57, total: 57 },
    nextStage: 8,
    mutationsPerformedByVerifier: 0,
    containsSensitiveData: false,
  };
};

const verifyPrerelease = async (flags) => {
  if (flags['forbid-e7-pass'] !== true) fail('E7_PRERELEASE_PASS_GUARD_REQUIRED');
  const identity = candidateIdentity('prerelease');
  const config = configFromEnvironment();
  verifyConfigScope(config, 'prerelease');
  const jobs = successfulJobResults('prerelease');
  const map = evidenceFileMap(requiredString(flags, 'evidence'));
  for (const basename of [
    'metadata.json',
    'verify-candidate.json',
    'candidate-manifest.json',
    'checksums-sbom.json',
    'security.json',
    'infra-synth.json',
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
  if (
    diffFilename === undefined ||
    rawDiffFilename === undefined ||
    approvalFilename === undefined
  ) {
    fail('E7_REQUIRED_EVIDENCE_MISSING');
  }
  const diff = validateDiffReview(readEvidence(diffFilename), 'prerelease', identity, config);
  const manifest = validateFreezeManifest(readEvidence(map.get('candidate-manifest.json')));
  const synth = readEvidence(map.get('infra-synth.json'));
  if (
    manifest.configSha256 !== objectSha256(config) ||
    synth.freezeManifestSha256 !== manifest.manifestSha256 ||
    synth.assemblySha256 !== diff.cloudAssemblySha256 ||
    !SHA256.test(synth.frozenVerificationSha256 ?? '') ||
    diff.checkpoints.diff.freezeManifestSha256 !== manifest.manifestSha256
  ) {
    fail('E7_PRERELEASE_ASSEMBLY_BINDING_INVALID');
  }
  const approval = readEvidence(approvalFilename);
  if (
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
  const index = createStage7Index({
    entryGate: 'CONDITIONAL_GO',
    artifactStates: verifiedArtifactStates(),
    evidenceStates: passedEvidenceStates(),
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
  };
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
      error instanceof Stage7ControlError || error instanceof Stage7Error
        ? error.code
        : 'E7_VERIFY_UNEXPECTED_FAILURE';
    await writeStage7Json(output, 'stage7-closeout-failed.json', {
      schemaVersion: 1,
      stage: 7,
      kind: scope === 'full' ? 'STAGE7_CLOSEOUT' : 'STAGE7_PRERELEASE_CLOSEOUT',
      status: 'FAIL',
      scope,
      candidateSha: SHA.test(process.env.STAGE7_CANDIDATE_SHA ?? '')
        ? process.env.STAGE7_CANDIDATE_SHA
        : null,
      releaseId: RELEASE_ID.test(process.env.STAGE7_RELEASE_ID ?? '')
        ? process.env.STAGE7_RELEASE_ID
        : null,
      reason: code,
      gates: {
        'GATE-E7-01': 'FAIL',
        'GATE-E7-02': 'FAIL',
        'GATE-E7-03': 'FAIL',
      },
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
      'pre-freeze-synth',
      'no-write',
      'evidence',
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
    exactFlags(flags, ['pre-upload']);
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
  exactFlags(flags, ['scope', 'manifest', 'deployment', 'approved-environment', 'non-public']);
  await sandboxSmokeRelease(flags);
};

const dispatchQuality = async (flags) => {
  exactFlags(flags, ['scope', 'manifest', 'deployment', 'approved-environment']);
  await qualityRelease(flags);
};

const dispatchPublish = async (flags) => {
  exactFlags(flags, ['evidence']);
  await publicationPackage(flags);
};

const dispatchVerify = async (flags) => {
  if (flags['publication-native'] !== undefined) {
    exactFlags(flags, ['publication-native', 'evidence', 'external-writes-performed']);
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
  exactFlags(flags, ['scope', 'evidence', 'forbid-e7-pass', 'require-cleanup']);
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
      scope: full ? 'FULL_RELEASE_INITIAL_ONLY' : 'EPHEMERAL_PRERELEASE',
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
      expiresAtUtc: '2026-08-20T15:00:00.000Z',
      preserveBootstrap: true,
      preservePreviousRelease: true,
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

const authorizationFixture = ({ config, candidateSha, releaseId, origin }) => {
  const scope = config.authorization.scope === 'FULL_RELEASE_INITIAL_ONLY' ? 'full' : 'prerelease';
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
      sandboxHostSha256: digest('sandbox.wompi.co'),
    },
    authorizations: {
      ownedTarget: authorization(requirements.ownedTarget, digest(origin), 10, 4),
      sandboxSmoke: authorization(requirements.sandboxSmoke, digest('sandbox.wompi.co'), 20, 5),
      passiveSecurity: authorization(requirements.passiveSecurity, digest(origin), 20, 6),
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

export const selfTestStage7Control = () => {
  selfTestStage7();
  selfTestArtifactSanitizer();
  selfTestExternalEvidence();
  selfTestDeployedSmoke();
  selfTestDeployedQuality();
  assert.deepEqual(parseFlags(['--scope', 'full', '--local-only']), {
    scope: 'full',
    'local-only': true,
  });
  assert.throws(() => parseFlags(['--scope', 'full', '--scope', 'full']), Stage7ControlError);

  const config = controlConfigFixture();
  const now = new Date('2026-08-17T12:00:00.000Z');
  validateStage7Config(config, { now });
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
  const authorization = authorizationFixture({ config, candidateSha, releaseId, origin });
  validateExternalAuthorizations({
    value: authorization,
    config,
    candidateSha,
    releaseId,
    deployedOrigin: origin,
    now,
  });
  const fullConfig = controlConfigFixture({ scope: 'full' });
  validateStage7Config(fullConfig, { now });
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
  const usageFixture = (usageId, count = 1) =>
    authorizationUsage({
      scope: 'full',
      authority: validatedFullAuthorization,
      identity: { candidateSha, releaseId },
      config: fullConfig,
      usageId,
      requestCounts: { [fullAuthorizationIds[0]]: count },
    });
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
    releaseMode: 'INITIAL',
    updateReleaseSupported: false,
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
        mode: 'INITIAL_ACTIVATION',
        apiStack: transitionState(apiStackName, 'ENABLED'),
        webStack: transitionState(webStackName, 'ENABLED'),
        scheduler: schedulerState('ENABLED'),
        authorizationUsage: usageFixture('ACTIVATION_INITIAL'),
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
    releaseMode: 'INITIAL',
    updateReleaseSupported: false,
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
  const publicationIdentity = {
    candidateSha,
    releaseId,
    releaseTag: 'v0.1.0-rc.1',
  };
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
    expectedReadmeGitBlobSha: 'b'.repeat(40),
    desiredReadmeGitBlobSha: 'c'.repeat(40),
    urls: {
      application: 'https://checkout.example.test',
      api: 'https://api.example.test',
      docs: 'https://api.example.test/docs',
      health: 'https://api.example.test/health',
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
    publicationOrder: ['GITHUB_RELEASE', 'README'],
    retryPolicy: 'VERIFY_EXACT_OR_CREATE_MISSING',
    externalWritesPlanned: 2,
    externalWritesPerformed: 0,
    containsSensitiveData: false,
  };
  validatePublicationPlan(publicationPlanFixture, publicationIdentity);
  assert.throws(
    () =>
      validatePublicationPlan(
        { ...publicationPlanFixture, retryPolicy: 'OVERWRITE_EXISTING' },
        publicationIdentity,
      ),
    (error) => error.code === 'E7_PUBLICATION_PLAN_INVALID',
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
    readmeUpdated: true,
    readmeCommitSha: 'd'.repeat(40),
    releaseCreated: true,
    releaseVerifiedExact: true,
    releaseTargetSha: candidateSha,
    releaseUrl: `https://github.com/${publicationPlanFixture.repository}/releases/tag/${publicationIdentity.releaseTag}`,
    urlsVerified: true,
    publicationPlanSha256: objectSha256(publicationPlanFixture),
    verifiedAtUtc: '2026-08-17T12:00:00.000Z',
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
  validateAuthorizationLedger({
    authorization: authorizationEvidenceFixture,
    usages: [usageFixture('LEDGER_CANARY_A'), usageFixture('LEDGER_CANARY_B')],
    identity: { candidateSha, releaseId },
    config: fullConfig,
    expectedUsageIds: ['LEDGER_CANARY_A', 'LEDGER_CANARY_B'],
  });
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
  assert.deepEqual(expectedGithubOidcSubjects(fullConfig, fullConfig.aws.roles.readRoleArn), [sub]);
  validateGithubOidcTrustPolicy({
    policy: { Statement: [trustStatement([baseSub, externalSub])] },
    accountId: '123456789012',
    expectedSubs: [baseSub, externalSub],
  });
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
    selfTestStage7Control();
    return;
  }
  assertNode24();
  const flags = parseFlags(process.argv.slice(3));
  if (command === 'preflight') await dispatchPreflight(flags);
  else if (command === 'verify-candidate') await dispatchVerifyCandidate(flags);
  else if (command === 'manifest') await dispatchManifest(flags);
  else if (command === 'scan') await dispatchScan(flags);
  else if (command === 'plan') await dispatchPlan(flags);
  else if (command === 'smoke') await dispatchSmoke(flags);
  else if (command === 'sandbox-smoke') await dispatchSandboxSmoke(flags);
  else if (command === 'quality') await dispatchQuality(flags);
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
      error instanceof Stage7QualityError
        ? error.code
        : 'E7_CONTROL_UNEXPECTED_FAILURE';
    process.stderr.write(`stage-7 release control: ${code}\n`);
    process.exitCode = 1;
  });
}
