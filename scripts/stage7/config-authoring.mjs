import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { parseStrictJsonSource, validateJsonSchemaSubset } from '../stage6/strict-json.mjs';
import { validateBaselineConfig } from './baseline-establishment.mjs';
import { normalizePnpmScriptArguments } from './cli-arguments.mjs';
import {
  canonicalJson,
  expectedStage7Stacks,
  hasUniqueIamRoleNames,
  objectSha256,
  parseIamRoleArn,
  validateStage7Config,
  workspaceRoot,
} from './core.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const INPUT_SCHEMA_PATH = path.join(HERE, 'config-authoring-input.schema.json');
const INPUT_SCHEMA = parseStrictJsonSource(readFileSync(INPUT_SCHEMA_PATH), {
  scanForbiddenData: false,
});
const ENVIRONMENT = 'assessment-release';
const ABORT_CRITERIA = Object.freeze([
  'ACCOUNT_MISMATCH',
  'REGION_MISMATCH',
  'SECRET_EXPOSURE',
  'PRODUCTION_PROVIDER',
  'STATEFUL_REPLACEMENT',
  'SMOKE_FAILURE',
  'ROLLBACK_FAILURE',
  'BUDGET_BREACH',
]);
const OUTPUT_FILENAMES = Object.freeze({
  full: 'stage7-full-config.json',
  prerelease: 'stage7-prerelease-config.json',
  baseline: 'stage7-baseline-config.json',
});
const PLACEHOLDER =
  /(?:<[^<>]+>|\$\{[^{}]+\}|\{\{[^{}]+\}\}|\b(?:todo|tbd|changeme|dummy|sample|replace(?:[-_ ]?me)?|placeholder|your[-_ ][a-z0-9_-]+)\b)/iu;
const RESERVED_HOST = /(?:^|\.)(?:example(?:\.com|\.net|\.org)?|invalid|localhost|test)(?:\.|$)/iu;
const SECRET_ARN =
  /^arn:aws:secretsmanager:([a-z0-9-]+):([0-9]{12}):secret:[A-Za-z0-9/_+=.@-]{1,256}$/u;
const CERTIFICATE_ARN =
  /^arn:aws:acm:([a-z0-9-]+):([0-9]{12}):certificate\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/u;
const EXAMPLE_ACCOUNT_IDS = new Set([
  '000000000000',
  '111111111111',
  '123456789012',
  '999999999999',
]);
const SCOPE_SPECIFIC_ROLE_KEYS = Object.freeze([
  'readRoleArn',
  'deployRoleArn',
  'rollbackRoleArn',
  'cleanupRoleArn',
]);
const KNOWN_PLACEHOLDER_VALUES = new Set([
  'release-owner',
  'rollback-owner',
  'release-channel',
  'cost-owner',
  'cost-alerts',
  'cleanup-owner',
  'Z123456',
  'Z1234567890ABC',
  'K2STAGE7CHECKOUT',
  'K2STAGE7PUBLIC',
  'K2STAGE7KEYGROUP',
]);

export class Stage7ConfigAuthoringError extends Error {
  constructor(code) {
    super(code);
    this.name = 'Stage7ConfigAuthoringError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new Stage7ConfigAuthoringError(code);
};

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const isoUtc = (value) => {
  if (typeof value !== 'string') return false;
  const time = Date.parse(value);
  return Number.isFinite(time) && new Date(time).toISOString() === value;
};

const stringsIn = function* (value) {
  if (typeof value === 'string') {
    yield value;
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) yield* stringsIn(entry);
    return;
  }
  if (value !== null && typeof value === 'object') {
    for (const entry of Object.values(value)) yield* stringsIn(entry);
  }
};

const validateNoPlaceholders = (value) => {
  const strings = [...stringsIn(value)];
  if (strings.some((entry) => PLACEHOLDER.test(entry) || KNOWN_PLACEHOLDER_VALUES.has(entry))) {
    fail('E7_CONFIG_AUTHORING_PLACEHOLDER_FORBIDDEN');
  }
  if (EXAMPLE_ACCOUNT_IDS.has(value.aws.accountId) || /^(.)\1{11}$/u.test(value.aws.accountId)) {
    fail('E7_CONFIG_AUTHORING_EXAMPLE_ACCOUNT_FORBIDDEN');
  }
  const hostValues = [
    ...Object.values(value.domains).flatMap(({ hostname, apiHostname, hostedZoneName }) => [
      hostname,
      apiHostname,
      hostedZoneName,
    ]),
    value.budget.alertDestination.split('@').at(-1),
  ];
  if (hostValues.some((hostname) => RESERVED_HOST.test(hostname ?? ''))) {
    fail('E7_CONFIG_AUTHORING_RESERVED_HOST_FORBIDDEN');
  }
};

const validateDates = (value) => {
  const dates = [
    value.release.authorization.approvedAtUtc,
    value.release.authorization.expiresAtUtc,
    value.release.window.startsAtUtc,
    value.release.window.endsAtUtc,
    value.release.cleanup.expiresAtUtc,
    value.prerelease.authorization.approvedAtUtc,
    value.prerelease.authorization.expiresAtUtc,
    value.prerelease.window.startsAtUtc,
    value.prerelease.window.endsAtUtc,
    value.prerelease.cleanup.expiresAtUtc,
    value.baseline.authorization.approvedAtUtc,
    value.baseline.authorization.expiresAtUtc,
    value.baseline.window.startsAtUtc,
    value.baseline.window.endsAtUtc,
    value.baseline.cleanup.expiresAtUtc,
  ];
  if (!dates.every(isoUtc)) fail('E7_CONFIG_AUTHORING_TIMESTAMP_INVALID');
};

const validateDomains = (value) => {
  const hostnames = [];
  for (const domain of Object.values(value.domains)) {
    const immediateZoneFor = (hostname) => hostname.split('.').slice(1).join('.');
    if (
      domain.hostname === domain.apiHostname ||
      immediateZoneFor(domain.hostname) !== domain.hostedZoneName ||
      immediateZoneFor(domain.apiHostname) !== domain.hostedZoneName
    ) {
      fail('E7_CONFIG_AUTHORING_DOMAIN_ZONE_INVALID');
    }
    hostnames.push(domain.hostname, domain.apiHostname);
  }
  if (new Set(hostnames).size !== hostnames.length) {
    fail('E7_CONFIG_AUTHORING_DOMAIN_SEPARATION_INVALID');
  }
  const { full, prerelease } = value.domains;
  if (
    (full.hostedZoneName === prerelease.hostedZoneName) !==
    (full.hostedZoneId === prerelease.hostedZoneId)
  ) {
    fail('E7_CONFIG_AUTHORING_HOSTED_ZONE_BINDING_INVALID');
  }
};

const validateAwsReferences = (value) => {
  const { accountId, targets } = value.aws;
  if (targets.full.region === targets.prerelease.region) {
    fail('E7_CONFIG_AUTHORING_REGION_SEPARATION_INVALID');
  }
  const scopeSpecificRoleArns = [];
  const allRoleArns = [];
  for (const { roles } of Object.values(targets)) {
    const roleArns = Object.values(roles);
    if (new Set(roleArns).size !== 5 || !hasUniqueIamRoleNames(roleArns)) {
      fail('E7_CONFIG_AUTHORING_ROLE_SEPARATION_INVALID');
    }
    for (const roleArn of roleArns) {
      const identity = parseIamRoleArn(roleArn);
      if (
        identity?.accountId !== accountId ||
        /(?:^|[/_-])admin(?:istrator)?(?:$|[/_-])/iu.test(identity?.resource ?? '')
      ) {
        fail('E7_CONFIG_AUTHORING_ROLE_ARN_INVALID');
      }
    }
    scopeSpecificRoleArns.push(...SCOPE_SPECIFIC_ROLE_KEYS.map((roleKey) => roles[roleKey]));
    allRoleArns.push(...roleArns);
  }
  if (new Set(scopeSpecificRoleArns).size !== scopeSpecificRoleArns.length) {
    fail('E7_CONFIG_AUTHORING_SCOPE_ROLE_REUSE_FORBIDDEN');
  }
  if (targets.full.roles.baselineRoleArn !== targets.prerelease.roles.baselineRoleArn) {
    fail('E7_CONFIG_AUTHORING_SHARED_BASELINE_ROLE_REQUIRED');
  }
  if (!hasUniqueIamRoleNames([...new Set(allRoleArns)])) {
    fail('E7_CONFIG_AUTHORING_SCOPE_ROLE_REUSE_FORBIDDEN');
  }
  for (const [scope, access] of Object.entries(value.access)) {
    const region = targets[scope].region;
    const secret = SECRET_ARN.exec(access.originTokenSecretArn);
    if (secret?.[1] !== region || secret?.[2] !== accountId) {
      fail('E7_CONFIG_AUTHORING_SECRET_ARN_INVALID');
    }
    if (/^(.)\1{31,63}$/u.test(access.originTokenSecretVersionId)) {
      fail('E7_CONFIG_AUTHORING_SECRET_VERSION_PLACEHOLDER_FORBIDDEN');
    }
  }
  for (const [scope, domain] of Object.entries(value.domains)) {
    for (const [certificateArn, expectedRegion] of [
      [domain.webCertificateArn, 'us-east-1'],
      [domain.apiCertificateArn, targets[scope].region],
    ]) {
      const match = CERTIFICATE_ARN.exec(certificateArn);
      if (
        match?.[1] !== expectedRegion ||
        match?.[2] !== accountId ||
        /^([0-9a-f])\1{7}-\1{4}-\1{4}-\1{4}-\1{12}$/u.test(match?.[3] ?? '')
      ) {
        fail('E7_CONFIG_AUTHORING_CERTIFICATE_ARN_INVALID');
      }
    }
  }
};

const authorization = (source, scope, environment) => ({
  id: source.id,
  status: 'APPROVED',
  scope,
  ownerAlias: source.ownerAlias,
  approvedAtUtc: source.approvedAtUtc,
  expiresAtUtc: source.expiresAtUtc,
  stacks: expectedStage7Stacks(environment),
  sandboxIncluded: true,
  destructiveActionsAllowed: false,
  communicationChannelAlias: source.communicationChannelAlias,
  abortCriteria: [...ABORT_CRITERIA],
  rollbackOwnerAlias: source.rollbackOwnerAlias,
});

const aws = (source, target) => ({
  accountId: source.accountId,
  region: target.region,
  roles: { ...target.roles },
  sessionMode: 'OIDC',
});

const budget = (source) => ({
  maxUsd: source.maxUsd,
  warningUsd: [...source.warningUsd],
  alertOwnerAlias: source.alertOwnerAlias,
  alertChannelAlias: source.alertChannelAlias,
  alertDestinationSha256: sha256(source.alertDestination),
});

const cleanup = (source) => ({
  ownerAlias: source.ownerAlias,
  expiresAtUtc: source.expiresAtUtc,
  preserveBootstrap: true,
  preservePreviousRelease: true,
});

const fullConfig = (input) => ({
  schemaVersion: 1,
  stage: 7,
  environment: ENVIRONMENT,
  authorization: authorization(
    input.release.authorization,
    'FULL_RELEASE_VERSIONED_UPDATE',
    ENVIRONMENT,
  ),
  aws: aws(input.aws, input.aws.targets.full),
  window: { ...input.release.window },
  budget: budget(input.budget),
  domain: {
    mode: 'CUSTOM_AUTHORIZED',
    hostname: input.domains.full.hostname,
    apiHostname: input.domains.full.apiHostname,
    hostedZoneId: input.domains.full.hostedZoneId,
    webCertificateArn: input.domains.full.webCertificateArn,
    apiCertificateArn: input.domains.full.apiCertificateArn,
    dnsIncluded: true,
  },
  prereleaseAccess: {
    mode: 'ORIGIN_GATE_ONLY',
    keyGroupId: null,
    publicKeyId: null,
    originTokenSecretArn: input.access.full.originTokenSecretArn,
    originTokenSecretVersionId: input.access.full.originTokenSecretVersionId,
    rotationDuringWindow: 'FORBIDDEN',
  },
  cleanup: cleanup(input.release.cleanup),
  credentialReferences: [input.access.full.originTokenSecretArn],
  containsSensitiveData: false,
});

const prereleaseConfig = (input) => ({
  schemaVersion: 1,
  stage: 7,
  environment: input.prerelease.environment,
  authorization: authorization(
    input.prerelease.authorization,
    'EPHEMERAL_PRERELEASE',
    input.prerelease.environment,
  ),
  aws: aws(input.aws, input.aws.targets.prerelease),
  window: { ...input.prerelease.window },
  budget: budget(input.budget),
  domain: {
    mode: 'CUSTOM_AUTHORIZED',
    hostname: input.domains.prerelease.hostname,
    apiHostname: input.domains.prerelease.apiHostname,
    hostedZoneId: input.domains.prerelease.hostedZoneId,
    webCertificateArn: input.domains.prerelease.webCertificateArn,
    apiCertificateArn: input.domains.prerelease.apiCertificateArn,
    dnsIncluded: true,
  },
  prereleaseAccess: {
    mode: 'CLOUDFRONT_SIGNED_COOKIE',
    keyGroupId: input.access.prerelease.keyGroupId,
    publicKeyId: input.access.prerelease.publicKeyId,
    originTokenSecretArn: input.access.prerelease.originTokenSecretArn,
    originTokenSecretVersionId: input.access.prerelease.originTokenSecretVersionId,
    rotationDuringWindow: 'FORBIDDEN',
  },
  cleanup: cleanup(input.prerelease.cleanup),
  credentialReferences: [input.access.prerelease.originTokenSecretArn],
  containsSensitiveData: false,
});

const baselineConfig = (input) => ({
  schemaVersion: 1,
  stage: 7,
  environment: ENVIRONMENT,
  authorization: authorization(
    input.baseline.authorization,
    'FULL_RELEASE_BASELINE_CLOSED',
    ENVIRONMENT,
  ),
  aws: aws(input.aws, input.aws.targets.full),
  window: { ...input.baseline.window },
  budget: budget(input.budget),
  traffic: {
    targetOwnership: 'AUTHORIZED_ASSESSMENT_TARGET',
    maxRequests: 8,
  },
  domain: {
    mode: 'CUSTOM_AUTHORIZED',
    hostname: input.domains.full.hostname,
    apiHostname: input.domains.full.apiHostname,
    hostedZoneId: input.domains.full.hostedZoneId,
    hostedZoneName: input.domains.full.hostedZoneName,
    webCertificateArn: input.domains.full.webCertificateArn,
    apiCertificateArn: input.domains.full.apiCertificateArn,
    dnsIncluded: true,
  },
  prereleaseAccess: {
    mode: 'CLOUDFRONT_SIGNED_COOKIE',
    keyGroupId: input.access.full.keyGroupId,
    publicKeyId: input.access.full.publicKeyId,
    originTokenSecretArn: input.access.full.originTokenSecretArn,
    originTokenSecretVersionId: input.access.full.originTokenSecretVersionId,
    rotationDuringWindow: 'FORBIDDEN',
  },
  cleanup: cleanup(input.baseline.cleanup),
  credentialReferences: [input.access.full.originTokenSecretArn],
  containsSensitiveData: false,
});

export const parseStage7ConfigAuthoringSource = (source) =>
  parseStrictJsonSource(source, { scanForbiddenData: false });

export const validateStage7ConfigAuthoringInput = (value) => {
  if (!validateJsonSchemaSubset(value, INPUT_SCHEMA)) {
    fail('E7_CONFIG_AUTHORING_INPUT_SCHEMA_INVALID');
  }
  if (!/^AUTH-E7-(?!BASELINE-)[A-Z0-9][A-Z0-9-]{1,31}$/u.test(value.release.authorization.id)) {
    fail('E7_CONFIG_AUTHORING_RELEASE_AUTHORITY_INVALID');
  }
  if (!/^AUTH-E7-PRERELEASE-[A-Z0-9-]{1,20}$/u.test(value.prerelease.authorization.id)) {
    fail('E7_CONFIG_AUTHORING_PRERELEASE_AUTHORITY_INVALID');
  }
  if (!/^AUTH-E7-BASELINE-[A-Z0-9-]{1,24}$/u.test(value.baseline.authorization.id)) {
    fail('E7_CONFIG_AUTHORING_BASELINE_AUTHORITY_INVALID');
  }
  if (
    new Set([
      value.release.authorization.id,
      value.prerelease.authorization.id,
      value.baseline.authorization.id,
    ]).size !== 3
  ) {
    fail('E7_CONFIG_AUTHORING_AUTHORITY_SEPARATION_INVALID');
  }
  validateNoPlaceholders(value);
  validateDates(value);
  validateDomains(value);
  validateAwsReferences(value);
  return value;
};

const authoredDocument = (value) => {
  const source = canonicalJson(value);
  const digest = sha256(source);
  if (digest !== objectSha256(value)) fail('E7_CONFIG_AUTHORING_CANONICAL_DIGEST_MISMATCH');
  return Object.freeze({ value, source, sha256: digest, bytes: Buffer.byteLength(source) });
};

const variableMapping = ({ input, full, prerelease, baseline }) => ({
  shared: {
    STAGE7_AWS_ACCOUNT_ID: input.aws.accountId,
  },
  full: {
    STAGE7_CONFIG_B64: Buffer.from(full.source, 'utf8').toString('base64'),
    STAGE7_AWS_REGION: input.aws.targets.full.region,
    STAGE7_AWS_READ_ROLE_ARN: input.aws.targets.full.roles.readRoleArn,
    STAGE7_AWS_DEPLOY_ROLE_ARN: input.aws.targets.full.roles.deployRoleArn,
    STAGE7_AWS_ROLLBACK_ROLE_ARN: input.aws.targets.full.roles.rollbackRoleArn,
    STAGE7_AWS_CLEANUP_ROLE_ARN: input.aws.targets.full.roles.cleanupRoleArn,
  },
  baseline: {
    STAGE7_BASELINE_CONFIG_B64: Buffer.from(baseline.source, 'utf8').toString('base64'),
    STAGE7_AWS_REGION: input.aws.targets.full.region,
    STAGE7_AWS_READ_ROLE_ARN: input.aws.targets.full.roles.readRoleArn,
    STAGE7_AWS_DEPLOY_ROLE_ARN: input.aws.targets.full.roles.deployRoleArn,
    STAGE7_AWS_ROLLBACK_ROLE_ARN: input.aws.targets.full.roles.rollbackRoleArn,
    STAGE7_AWS_CLEANUP_ROLE_ARN: input.aws.targets.full.roles.cleanupRoleArn,
    STAGE7_AWS_BASELINE_ROLE_ARN: input.aws.targets.full.roles.baselineRoleArn,
  },
  prerelease: {
    STAGE7_PRERELEASE_CONFIG_B64: Buffer.from(prerelease.source, 'utf8').toString('base64'),
    STAGE7_PRERELEASE_AWS_REGION: input.aws.targets.prerelease.region,
    STAGE7_PRERELEASE_AWS_READ_ROLE_ARN: input.aws.targets.prerelease.roles.readRoleArn,
    STAGE7_PRERELEASE_AWS_DEPLOY_ROLE_ARN: input.aws.targets.prerelease.roles.deployRoleArn,
    STAGE7_PRERELEASE_AWS_ROLLBACK_ROLE_ARN: input.aws.targets.prerelease.roles.rollbackRoleArn,
    STAGE7_PRERELEASE_AWS_CLEANUP_ROLE_ARN: input.aws.targets.prerelease.roles.cleanupRoleArn,
  },
  workflowDispatchInputs: {
    release: { config_sha256: full.sha256 },
    prerelease: { config_sha256: prerelease.sha256 },
    baseline: { config_sha256: baseline.sha256 },
  },
});

export const authorStage7Configs = (input, { now = new Date() } = {}) => {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    fail('E7_CONFIG_AUTHORING_VALIDATION_TIME_INVALID');
  }
  validateStage7ConfigAuthoringInput(input);
  const full = fullConfig(input);
  const prerelease = prereleaseConfig(input);
  const baseline = baselineConfig(input);
  validateStage7Config(full, { now });
  validateStage7Config(prerelease, { now });
  validateBaselineConfig(baseline, { now });
  const authoredFull = authoredDocument(full);
  const authoredPrerelease = authoredDocument(prerelease);
  const authoredBaseline = authoredDocument(baseline);
  return Object.freeze({
    fullConfig: authoredFull,
    prereleaseConfig: authoredPrerelease,
    baselineConfig: authoredBaseline,
    alertDestinationSha256: full.budget.alertDestinationSha256,
    variableMapping: variableMapping({
      input,
      full: authoredFull,
      prerelease: authoredPrerelease,
      baseline: authoredBaseline,
    }),
  });
};

const workspacePath = (
  candidate,
  { existing = true, directory = false, allowWorkspaceRoot = false } = {},
) => {
  if (typeof candidate !== 'string' || candidate.length === 0) {
    fail('E7_CONFIG_AUTHORING_PATH_INVALID');
  }
  const absolute = path.resolve(candidate);
  const relative = path.relative(workspaceRoot, absolute);
  if (
    (!allowWorkspaceRoot && relative === '') ||
    relative === '..' ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    fail('E7_CONFIG_AUTHORING_PATH_OUTSIDE_WORKSPACE');
  }
  let current = workspaceRoot;
  for (const segment of relative.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) break;
    if (lstatSync(current).isSymbolicLink()) fail('E7_CONFIG_AUTHORING_SYMLINK_FORBIDDEN');
  }
  if (existing) {
    if (!existsSync(absolute)) fail('E7_CONFIG_AUTHORING_PATH_INVALID');
    const stat = lstatSync(absolute);
    if (directory ? !stat.isDirectory() : !stat.isFile()) {
      fail('E7_CONFIG_AUTHORING_PATH_INVALID');
    }
    const real = realpathSync(absolute);
    const realRelative = path.relative(realpathSync(workspaceRoot), real);
    if (realRelative.startsWith(`..${path.sep}`) || path.isAbsolute(realRelative)) {
      fail('E7_CONFIG_AUTHORING_PATH_OUTSIDE_WORKSPACE');
    }
  }
  return absolute;
};

export const authorStage7ConfigFiles = ({ inputFilename, outputDirectory, now = new Date() }) => {
  const inputPath = workspacePath(inputFilename);
  const outputPath = workspacePath(outputDirectory, { existing: false });
  const outputParent = workspacePath(path.dirname(outputPath), {
    directory: true,
    allowWorkspaceRoot: true,
  });
  if (path.dirname(outputPath) !== outputParent || existsSync(outputPath)) {
    fail('E7_CONFIG_AUTHORING_OUTPUT_DIRECTORY_EXISTS');
  }
  const input = parseStage7ConfigAuthoringSource(readFileSync(inputPath));
  const authored = authorStage7Configs(input, { now });
  mkdirSync(outputPath, { mode: 0o700 });
  const fullPath = path.join(outputPath, OUTPUT_FILENAMES.full);
  const prereleasePath = path.join(outputPath, OUTPUT_FILENAMES.prerelease);
  const baselinePath = path.join(outputPath, OUTPUT_FILENAMES.baseline);
  writeFileSync(fullPath, authored.fullConfig.source, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  writeFileSync(prereleasePath, authored.prereleaseConfig.source, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  writeFileSync(baselinePath, authored.baselineConfig.source, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  return {
    schemaVersion: 1,
    stage: 7,
    kind: 'STAGE7_CONFIG_AUTHORING_SUMMARY',
    outputs: {
      fullConfig: {
        filename: path.relative(workspaceRoot, fullPath).replaceAll(path.sep, '/'),
        sha256: authored.fullConfig.sha256,
        bytes: authored.fullConfig.bytes,
      },
      prereleaseConfig: {
        filename: path.relative(workspaceRoot, prereleasePath).replaceAll(path.sep, '/'),
        sha256: authored.prereleaseConfig.sha256,
        bytes: authored.prereleaseConfig.bytes,
      },
      baselineConfig: {
        filename: path.relative(workspaceRoot, baselinePath).replaceAll(path.sep, '/'),
        sha256: authored.baselineConfig.sha256,
        bytes: authored.baselineConfig.bytes,
      },
    },
    alertDestinationSha256: authored.alertDestinationSha256,
    variableMapping: authored.variableMapping,
    containsSensitiveData: false,
  };
};

const flags = (arguments_) => {
  if (arguments_.length === 0 || arguments_[0] !== 'author') {
    fail('E7_CONFIG_AUTHORING_COMMAND_INVALID');
  }
  const parsed = {};
  for (let index = 1; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (
      !['--input', '--output-directory'].includes(name) ||
      value === undefined ||
      name in parsed
    ) {
      fail('E7_CONFIG_AUTHORING_ARGUMENTS_INVALID');
    }
    parsed[name] = value;
  }
  if (Object.keys(parsed).length !== 2) fail('E7_CONFIG_AUTHORING_ARGUMENTS_INVALID');
  return parsed;
};

const main = () => {
  const invocation = normalizePnpmScriptArguments(process.argv.slice(2), { separatorIndex: 1 });
  const parsed = flags(invocation);
  const summary = authorStage7ConfigFiles({
    inputFilename: parsed['--input'],
    outputDirectory: parsed['--output-directory'],
  });
  process.stdout.write(`${canonicalJson(summary)}\n`);
};

const direct =
  process.argv[1] !== undefined &&
  pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url;
if (direct) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error?.code ?? 'E7_CONFIG_AUTHORING_FAILED'}\n`);
    process.exitCode = 1;
  }
}
