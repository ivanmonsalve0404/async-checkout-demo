import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
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
  hashArtifactPath,
  objectSha256,
  readStrictJsonFile,
  validateStage7ActivationCheckpoint,
  validateFreezeManifest,
  validateStage7DriftCheckpoint,
  validateStage7InitialRollbackCheckpoint,
  validateStage7PrereleaseCleanupCheckpoint,
  validateStage7Config,
  workspaceRoot,
} from './core.mjs';
import { validateExternalAuthorizations } from './control.mjs';

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-([0-9a-f]{7})$/u;
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
const VERSION_ID = /^[A-Za-z0-9._~+/=-]{1,1024}$/u;
const SAFE_OBJECT_KEY =
  /^(?:index\.html|public-config\.json|product-placeholder\.svg|legal\/[A-Za-z0-9._/-]{1,512})$/u;
const STACK_SUFFIXES = ['data', 'api', 'observability', 'web'];
const MUTABLE_WEB_KEYS = new Set(['index.html', 'public-config.json', 'product-placeholder.svg']);
const DEFAULT_OUTPUT_ROOT = 'output/evidence/runtime';
const DEFAULT_INTERNAL_ROOT = 'output/evidence/runtime/.private-stage7';
const COMMAND_TIMEOUT_MS = 20 * 60 * 1000;
const MAX_COMMAND_OUTPUT_BYTES = 32 * 1024 * 1024;

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
const utc = (now) => now.toISOString();
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
  run(
    context.executor,
    context.awsCommand,
    [...args, '--region', options.region ?? context.config.aws.region, '--no-cli-pager'],
    { code, env: options.env ?? context.environmentVariables },
  );

const awsJson = (context, args, code, options = {}) =>
  strictJson(aws(context, [...args, '--output', 'json'], code, options), code);

const cdkResult = (context, args, code) => {
  if (args.some((argument) => argument === '--hotswap' || argument.startsWith('--hotswap='))) {
    fail('E7_HOTSWAP_FORBIDDEN');
  }
  const result = context.executor({
    command: context.pnpmCommand,
    args: ['--filter', '@checkout/infra', 'exec', 'cdk', ...args],
    cwd: workspaceRoot,
    env: context.environmentVariables,
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

const commandName = (base) => (process.platform === 'win32' ? `${base}.cmd` : base);

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
  scope === 'prerelease' ? 'EPHEMERAL_PRERELEASE' : 'FULL_RELEASE_INITIAL_ONLY';

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
      config.domain.mode !== 'AWS_MANAGED'
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
  validateOperationScope(config, scope, { allowPlan });
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
  return {
    awsCommand: environmentVariables.STAGE7_AWS_COMMAND ?? commandName('aws'),
    capability,
    config,
    environmentVariables,
    executor,
    expectedRoleArn,
    flags,
    identity,
    now,
    pnpmCommand: environmentVariables.STAGE7_PNPM_COMMAND ?? commandName('pnpm'),
    scope,
    stacks,
  };
};

const revalidateAwsIdentity = (context) => {
  const caller = awsJson(context, ['sts', 'get-caller-identity'], 'E7_STS_IDENTITY_FAILED');
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
    if (
      artifact?.properties?.terminationProtection !== undefined &&
      typeof artifact.properties.terminationProtection !== 'boolean'
    ) {
      fail('E7_CLOUD_ASSEMBLY_TERMINATION_PROTECTION_INVALID');
    }
    stacks.push({
      artifactId,
      template,
      templateFile,
      terminationProtection: artifact?.properties?.terminationProtection === true,
    });
  }
  return { app, manifest, stacks };
};

const validateAssemblyIdentity = (context, assemblyPath, freezeManifestPath) => {
  const assembly = cloudAssemblyStacks(assemblyPath);
  const actualNames = assembly.stacks.map(({ artifactId }) => artifactId).toSorted();
  if (actualNames.join('\0') !== context.stacks.toSorted().join('\0')) {
    fail('E7_CLOUD_ASSEMBLY_STACK_SET_MISMATCH');
  }
  const expectedTerminationProtection = context.scope !== 'prerelease';
  for (const { artifactId, template, terminationProtection } of assembly.stacks) {
    const outputs = template.Outputs;
    const resources = object(template.Resources) ? Object.values(template.Resources) : [];
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
    if (artifactId.endsWith('-api')) {
      const publicationParameter = template.Parameters?.PublicationState;
      const publicationCondition = template.Conditions?.PublicationEnabled;
      const schedules = resources.filter(({ Type }) => Type === 'AWS::Scheduler::Schedule');
      const apis = resources.filter(({ Type }) => Type === 'AWS::ApiGatewayV2::Api');
      const mappings = resources.filter(({ Type }) => Type === 'AWS::ApiGatewayV2::ApiMapping');
      const domains = resources.filter(({ Type }) => Type === 'AWS::ApiGatewayV2::DomainName');
      const runtimeFunctions = resources.filter(
        ({ Type, Properties }) =>
          Type === 'AWS::Lambda::Function' &&
          Properties?.Environment?.Variables?.PAYMENT_ADAPTER === 'sandbox',
      );
      const full = context.scope !== 'prerelease';
      if (
        publicationParameter?.Default !== 'DISABLED' ||
        JSON.stringify(publicationParameter?.AllowedValues) !==
          JSON.stringify(['DISABLED', 'ENABLED']) ||
        JSON.stringify(publicationCondition) !==
          JSON.stringify({ 'Fn::Equals': [{ Ref: 'PublicationState' }, 'ENABLED'] }) ||
        schedules.length !== 1 ||
        JSON.stringify(schedules[0]?.Properties?.State) !==
          JSON.stringify({ 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] }) ||
        apis.length !== 1 ||
        JSON.stringify(apis[0]?.Properties?.DisableExecuteApiEndpoint) !==
          JSON.stringify({ 'Fn::If': ['PublicationEnabled', full, true] }) ||
        mappings.length !== (full ? 1 : 0) ||
        (full && mappings[0]?.Condition !== 'PublicationEnabled') ||
        domains.length !== (full ? 1 : 0) ||
        runtimeFunctions.length !== 2 ||
        runtimeFunctions.some(
          ({ Properties }) =>
            Properties.Environment.Variables.SANDBOX_AUTHORIZED_UNTIL_UTC !==
            context.config.authorization.expiresAtUtc,
        ) ||
        JSON.stringify(outputs.SchedulerStatus?.Value) !==
          JSON.stringify({ 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] }) ||
        JSON.stringify(outputs.ApiPublicationStatus?.Value) !==
          JSON.stringify({ 'Fn::If': ['PublicationEnabled', 'ENABLED', 'DISABLED'] })
      ) {
        fail('E7_CLOUD_ASSEMBLY_INITIAL_API_PUBLICATION_INVALID');
      }
    }
    if (artifactId.endsWith('-web')) {
      const publicationParameter = template.Parameters?.PublicationState;
      const publicationCondition = template.Conditions?.PublicationEnabled;
      const distributions = resources.filter(
        ({ Type }) => Type === 'AWS::CloudFront::Distribution',
      );
      if (
        publicationParameter?.Default !== 'DISABLED' ||
        JSON.stringify(publicationParameter?.AllowedValues) !==
          JSON.stringify(['DISABLED', 'ENABLED']) ||
        JSON.stringify(publicationCondition) !==
          JSON.stringify({ 'Fn::Equals': [{ Ref: 'PublicationState' }, 'ENABLED'] }) ||
        distributions.length !== 1 ||
        JSON.stringify(distributions[0]?.Properties?.DistributionConfig?.Enabled) !==
          JSON.stringify({ 'Fn::If': ['PublicationEnabled', true, false] }) ||
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
    env: context.environmentVariables,
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
  return {
    exists: true,
    outputs,
    parameters,
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
    parametersSha256: objectSha256(state.parameters),
    outputsSha256: objectSha256(state.outputs),
  });

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

const updatePublicationStack = (context, suffix, targetState) => {
  if (!['DISABLED', 'ENABLED'].includes(targetState)) {
    fail('E7_PUBLICATION_STATE_INVALID');
  }
  const before = publicationStateForStack(context, suffix);
  if (before.publicationState === targetState) {
    return {
      changed: false,
      previousState: before.publicationState,
      state: targetState,
      stackIdSha256: sha256(before.state.stackId),
      stackName: before.stackName,
    };
  }
  const response = awsJson(
    context,
    [
      'cloudformation',
      'update-stack',
      '--stack-name',
      before.stackName,
      '--use-previous-template',
      '--parameters',
      `ParameterKey=PublicationState,ParameterValue=${targetState}`,
      '--capabilities',
      'CAPABILITY_NAMED_IAM',
    ],
    'E7_PUBLICATION_STACK_UPDATE_FAILED',
  );
  if (response?.StackId !== before.state.stackId) {
    fail('E7_PUBLICATION_STACK_UPDATE_INVALID');
  }
  aws(
    context,
    ['cloudformation', 'wait', 'stack-update-complete', '--stack-name', before.stackName],
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

const captureStackState = (context) =>
  Object.fromEntries(
    context.stacks.map((stackName) => {
      const state = describeStack(context, stackName, { allowMissing: true });
      if (
        state.exists &&
        (state.outputs.CandidateSha !== context.identity.candidateSha ||
          state.outputs.ReleaseId !== context.identity.releaseId)
      ) {
        fail('E7_UPDATE_RELEASE_NOT_SUPPORTED');
      }
      return [stackName, stackStateFingerprint(stackName, state)];
    }),
  );

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

const listWebVersions = (context, bucketName) => {
  if (!BUCKET_NAME.test(bucketName ?? '')) fail('E7_WEB_BUCKET_INVALID');
  const response = awsJson(
    context,
    ['s3api', 'list-object-versions', '--bucket', bucketName],
    'E7_WEB_VERSION_INVENTORY_FAILED',
  );
  const latest = new Map();
  for (const entry of response?.Versions ?? []) {
    if (
      entry?.IsLatest !== true ||
      typeof entry.Key !== 'string' ||
      (!MUTABLE_WEB_KEYS.has(entry.Key) && !entry.Key.startsWith('legal/'))
    ) {
      continue;
    }
    if (!SAFE_OBJECT_KEY.test(entry.Key) || !VERSION_ID.test(entry.VersionId ?? '')) {
      fail('E7_WEB_VERSION_INVENTORY_INVALID');
    }
    latest.set(entry.Key, {
      key: entry.Key,
      versionId: entry.VersionId,
      etagSha256: sha256(String(entry.ETag ?? '')),
      size: Number(entry.Size ?? 0),
    });
  }
  return [...latest.values()].toSorted((left, right) => left.key.localeCompare(right.key));
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

const validateRuntimeSecretReferenceAws = (context) => {
  const reference = runtimeSecretReference(context.config);
  const response = awsJson(
    context,
    ['secretsmanager', 'describe-secret', '--secret-id', reference],
    'E7_RUNTIME_SECRET_REFERENCE_UNAVAILABLE',
  );
  if (response?.ARN !== reference || response?.DeletedDate !== undefined) {
    fail('E7_RUNTIME_SECRET_REFERENCE_MISMATCH');
  }
  return sha256(reference);
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
  context.scope === 'prerelease' ? 'EPHEMERAL_NON_PUBLIC' : 'INITIAL_CLOSED';

const frozenContextArguments = (context) => {
  const values = {
    environment: context.config.environment,
    releaseId: context.identity.releaseId,
    candidateSha: context.identity.candidateSha,
    publicationMode: publicationMode(context),
    sandboxAuthorizedUntilUtc: context.config.authorization.expiresAtUtc,
    budgetMaxUsd: context.config.budget.maxUsd.toFixed(2),
    budgetWarningUsd: context.config.budget.warningUsd.map((amount) => amount.toFixed(2)).join(','),
    ...Object.fromEntries(domainContexts(context.config)),
  };
  return Object.entries(values).flatMap(([key, value]) => ['--context', `${key}=${value}`]);
};

const synthContexts = (context, output) => {
  const config = context.config;
  const contexts = {
    projectName: 'checkout',
    environment: config.environment,
    region: config.aws.region,
    releaseId: context.identity.releaseId,
    candidateSha: context.identity.candidateSha,
    owner: config.authorization.ownerAlias,
    expiresOn: config.cleanup.expiresAtUtc.slice(0, 10),
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
    ...Object.fromEntries(domainContexts(config)),
  };
  for (const artifact of ['api', 'worker', 'web']) {
    const artifactPath = contexts[`${artifact}ArtifactPath`];
    if (!existsSync(artifactPath) || !statSync(artifactPath).isDirectory()) {
      fail('E7_SYNTH_ARTIFACT_MISSING');
    }
  }
  const arguments_ = [
    'synth',
    ...context.stacks,
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

export const synthRelease = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  if (flags['initial-release'] !== true) fail('E7_UPDATE_RELEASE_NOT_SUPPORTED');
  let context = loadOperationContext({
    capability: 'read',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: false,
    allowPlan: true,
  });
  if ((flags.output === undefined) === (flags.verify === undefined)) {
    fail('E7_SYNTH_MODE_INVALID');
  }
  if (flags.verify !== undefined) {
    if (flags.manifest === undefined) fail('E7_FREEZE_MANIFEST_REQUIRED');
    const assembly = validateAssemblyIdentity(context, flags.verify, flags.manifest);
    const evidence = {
      decision: 'PASS',
      releaseMode: 'INITIAL',
      mode: 'VERIFY_FROZEN_ASSEMBLY',
      assemblySha256: assembly.assemblySha256,
      freezeManifestSha256: assembly.freezeManifestSha256,
      stacks: assembly.stacks.map(({ artifactId }) => artifactId),
      stackCount: assembly.stacks.length,
      hostedZone: null,
      awsIdentity: null,
    };
    await updateEvidence(context, 'synth', 'synth', evidence);
    return evidence;
  }
  let hostedZone = null;
  let certificates = [];
  let awsIdentity = null;
  if (context.config.domain.mode === 'CUSTOM_AUTHORIZED') {
    context = loadOperationContext({
      capability: 'read',
      scope: flags.scope,
      flags,
      executor,
      environmentVariables,
      now,
      requireAws: true,
      allowPlan: true,
    });
    awsIdentity = revalidateAwsIdentity(context);
    hostedZone = validateHostedZoneAws(context);
    certificates = validateCertificatesAws(context);
  }
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
    releaseMode: 'INITIAL',
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
  await updateEvidence(context, 'synth', 'synth', evidence);
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
  if (flags['initial-release'] !== true) fail('E7_UPDATE_RELEASE_NOT_SUPPORTED');
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
  const identity = revalidateAwsIdentity(context);
  const hostedZone = validateHostedZoneAws(context);
  const certificates = validateCertificatesAws(context);
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  const preDeploymentState = captureStackState(context);
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
    releaseMode: 'INITIAL',
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

const assertReleaseMutationReady = (flags) => {
  if (flags.scope === 'prerelease') {
    fail('E7_PRERELEASE_SAFETY_CONTROLS_REQUIRED');
  }
  fail('E7_PREVIOUS_APPROVED_RELEASE_REQUIRED');
};

const validateDeployFlags = (context, flags) => {
  if (
    flags.app === undefined ||
    flags.manifest === undefined ||
    flags.plan === undefined ||
    flags.approval === undefined
  ) {
    fail('E7_DEPLOY_INPUT_REQUIRED');
  }
  if (flags['initial-release'] !== true || flags['previous-manifest'] !== undefined) {
    fail('E7_UPDATE_RELEASE_NOT_SUPPORTED');
  }
  if (context.scope === 'prerelease') {
    if (flags['synthetic-only'] !== true || flags['non-public'] !== true) {
      fail('E7_PRERELEASE_DEPLOY_FLAGS_REQUIRED');
    }
  } else if (flags['synthetic-only'] || flags['non-public'] || flags.ephemeral) {
    fail('E7_FULL_RELEASE_DEPLOY_FLAG_INVALID');
  }
  assertReleaseMutationReady(flags);
};

const validateProtectedApproval = (context, filename, planFilename, assembly, manifestFilename) => {
  const approval = readJson(filename, 'E7_PROTECTED_APPROVAL_MISSING');
  const plan = readJson(planFilename, 'E7_APPROVED_PLAN_MISSING');
  const freeze = validateFreezeManifest(
    readStrictJsonFile(manifestFilename, { scanForbiddenData: false, validateConfig: false }),
  );
  const expectedScope = context.scope ?? 'full';
  const expectedEnvironment =
    expectedScope === 'prerelease' ? 'assessment-prerelease' : 'assessment-release';
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
    'approvedPlanSha256',
    'approvedDiffSha256',
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
    approval.approvedPlanSha256 !== fileSha256(planFilename) ||
    approval.approvedDiffSha256 !== plan.rawDiffArtifactSha256 ||
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

const validateApprovedPlan = (context, filename, assembly, suffix, hostedZone) => {
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
    source?.containsSensitiveData !== false ||
    diff?.decision !== 'READY_FOR_PROTECTED_REVIEW' ||
    diff?.releaseMode !== 'INITIAL' ||
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
  if (
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

const deployContext = ({
  flags,
  executor,
  environmentVariables,
  now,
  suffix,
  capability = 'deploy',
}) => {
  assertReleaseMutationReady(flags);
  const context = loadOperationContext({
    capability,
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  validateDeployFlags(context, flags);
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  const protectedApproval = validateProtectedApproval(
    context,
    flags.approval,
    flags.plan,
    assembly,
    flags.manifest,
  );
  const identity = revalidateAwsIdentity(context);
  const hostedZone = validateHostedZoneAws(context);
  const approvedPlan = validateApprovedPlan(context, flags.plan, assembly, suffix, hostedZone);
  return {
    approvedPlan: { ...approvedPlan, ...protectedApproval },
    assembly,
    context,
    identity,
  };
};

const deploymentCheckpoint = (context, identity, assembly, stackName, outputs, extra = {}) => ({
  decision: 'DEPLOYED_REQUIRES_FUNCTIONAL_VERIFICATION',
  releaseMode: 'INITIAL',
  identity,
  stackName,
  stackSuffix: stackSuffix(stackName),
  assemblySha256: assembly.assemblySha256,
  freezeManifestSha256: assembly.freezeManifestSha256,
  outputs: sanitizeStackOutputs(outputs, context.config.aws.accountId),
  outputsSha256: jsonSha256(outputs),
  deploymentMethod: 'CLOUDFORMATION_CHANGE_SET',
  requireApprovalMode: 'PROTECTED_WORKFLOW_PREAPPROVED',
  hotswapUsed: false,
  ...extra,
});

const deployReleaseMode = (flags) => {
  const initial = flags['initial-release'] === true;
  if (!initial || flags['previous-manifest'] !== undefined) {
    fail('E7_UPDATE_RELEASE_NOT_SUPPORTED');
  }
  return 'INITIAL';
};

export const deployData = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  const { approvedPlan, assembly, context, identity } = deployContext({
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
    { approvedPlan },
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
  const { approvedPlan, assembly, context, identity } = deployContext({
    flags,
    executor,
    environmentVariables,
    now,
    suffix: 'api',
  });
  assertDeployOrder(context, 'api');
  const stackName = stackFor(context, 'api');
  const before = describeStack(context, stackName, { allowMissing: true });
  deployReleaseMode(flags);
  if (
    before.exists &&
    (before.outputs.CandidateSha !== context.identity.candidateSha ||
      before.outputs.ReleaseId !== context.identity.releaseId)
  ) {
    fail('E7_INITIAL_RELEASE_EXISTING_STACK_INVALID');
  }
  let previousSchedulerState = null;
  if (before.exists) {
    if (before.parameters.PublicationState !== 'DISABLED') {
      fail('E7_API_PREMATURE_ACTIVATION_DETECTED');
    }
    validateScheduleTarget(context, before.outputs);
    previousSchedulerState = getSchedule(context).State;
    if (previousSchedulerState !== 'DISABLED') {
      fail('E7_SCHEDULER_PREMATURE_ACTIVATION_DETECTED');
    }
  }
  const runtimeSecretReferenceSha256 = validateRuntimeSecretReferenceAws(context);
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
  const rollbackBody = {
    createdAtUtc: utc(now),
    releaseMode: 'INITIAL',
    previousManifest: null,
    previousSchedulerState,
    previous: null,
    deployed: deployedVersions,
    publication,
    rollbackAvailable: false,
    initialDisableAvailable: true,
  };
  const rollbackRecord = writeRecord(context, 'rollback-api', rollbackBody);
  const checkpoint = deploymentCheckpoint(
    context,
    identity,
    assembly,
    deployed.stackName,
    deployed.outputs,
    { approvedPlan, rollbackRecord, runtimeSecretReferenceSha256 },
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
  const { approvedPlan, assembly, context, identity } = deployContext({
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
  const checkpoint = deploymentCheckpoint(
    context,
    identity,
    assembly,
    deployed.stackName,
    deployed.outputs,
    { alertDestinationSha256: destination.digest, approvedPlan, costAllocationTag },
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
    checkpoint?.releaseMode !== 'INITIAL' ||
    checkpoint?.stackName !== stackFor(context, 'observability') ||
    checkpoint?.alertDestinationSha256 !== context.config.budget.alertDestinationSha256 ||
    checkpoint?.outputs?.BudgetContract !== budgetContract(context.config) ||
    checkpoint?.outputs?.CandidateSha !== context.identity.candidateSha ||
    checkpoint?.outputs?.ReleaseId !== context.identity.releaseId ||
    checkpoint?.costAllocationTag?.status !== 'ACTIVE'
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
  const { approvedPlan, assembly, context, identity } = deployContext({
    flags,
    executor,
    environmentVariables,
    now,
    suffix: 'web',
  });
  assertDeployOrder(context, 'web');
  const stackName = stackFor(context, 'web');
  const before = describeStack(context, stackName, { allowMissing: true });
  deployReleaseMode(flags);
  if (
    before.exists &&
    (before.outputs.CandidateSha !== context.identity.candidateSha ||
      before.outputs.ReleaseId !== context.identity.releaseId)
  ) {
    fail('E7_INITIAL_RELEASE_EXISTING_STACK_INVALID');
  }
  const previousObjects = [];
  const deployed = deployStack(context, assembly, 'web', {
    preDeploymentStateSha256: approvedPlan.preDeploymentStateSha256,
  });
  if (!BUCKET_NAME.test(deployed.outputs.WebBucketName ?? ''))
    fail('E7_DEPLOYED_WEB_OUTPUT_INVALID');
  const deployedOrigin = assertExactHttpsOrigin(deployed.outputs.ApplicationUrl);
  if (deployed.outputs.WebPublicationStatus !== 'DISABLED') {
    fail('E7_WEB_PREMATURE_ACTIVATION_DETECTED');
  }
  if (before.exists && before.parameters.PublicationState !== 'DISABLED') {
    fail('E7_WEB_PREMATURE_ACTIVATION_DETECTED');
  }
  if (
    before.exists &&
    (before.outputs.WebBucketName !== deployed.outputs.WebBucketName ||
      before.outputs.DistributionId !== deployed.outputs.DistributionId)
  ) {
    fail('E7_WEB_ROLLBACK_TARGET_NOT_PRESERVED');
  }
  const deployedObjects = listWebVersions(context, deployed.outputs.WebBucketName);
  for (const requiredKey of ['index.html', 'public-config.json']) {
    if (!deployedObjects.some(({ key }) => key === requiredKey)) {
      fail(
        requiredKey === 'index.html'
          ? 'E7_DEPLOYED_WEB_INDEX_MISSING'
          : 'E7_DEPLOYED_WEB_PUBLIC_CONFIG_MISSING',
      );
    }
  }
  const publication = captureWebPublication(context, deployed.outputs.DistributionId);
  const rollbackBody = {
    createdAtUtc: utc(now),
    releaseMode: 'INITIAL',
    previousManifest: null,
    bucketName: deployed.outputs.WebBucketName,
    distributionId: deployed.outputs.DistributionId,
    publicOriginSha256: sha256(deployedOrigin),
    previous: previousObjects,
    deployed: deployedObjects,
    publication,
    rollbackAvailable: false,
    initialUnpublishAvailable: true,
  };
  const rollbackRecord = writeRecord(context, 'rollback-web', rollbackBody);
  const checkpoint = deploymentCheckpoint(
    context,
    identity,
    assembly,
    deployed.stackName,
    deployed.outputs,
    { approvedPlan, publicOriginSha256: sha256(deployedOrigin), rollbackRecord },
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
  if (web.outputs.PublicOriginParameterName !== parameterName) {
    fail('E7_PUBLIC_ORIGIN_PARAMETER_MISMATCH');
  }
  const response = awsJson(
    context,
    ['ssm', 'get-parameter', '--name', parameterName, '--no-with-decryption'],
    'E7_PUBLIC_ORIGIN_UNAVAILABLE',
  );
  const value = response?.Parameter?.Value;
  if (typeof value !== 'string' || web.outputs.ApplicationUrl !== value) {
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
  return {
    ...context.environmentVariables,
    ALLOWED_ORIGIN: origin,
    API_BASE_PATH: '/api/v1',
    APP_ENV: 'assessment',
    AUTO_SEED_CATALOG: 'false',
    AWS_REGION: context.config.aws.region,
    CATALOG_TABLE_NAME: `checkout-${context.config.environment}-catalog`,
    CHECKOUT_TABLE_NAME: `checkout-${context.config.environment}-checkout`,
    DATA_ADAPTER: 'dynamodb',
    PAYMENT_ADAPTER: 'sandbox',
    PAYMENTS_ENABLED: 'true',
    PRODUCT_SEED_ID: 'product-demo-001',
    PUBLIC_ASSET_ORIGIN: origin,
    RUNTIME_SECRET_ARN: runtimeSecretReference(context.config),
    SANDBOX_AUTHORIZED_UNTIL_UTC: sandboxAuthorizedUntilUtc,
    TOKENIZATION_MODE: 'direct_jwe',
  };
};

export const seedRelease = async ({
  flags,
  executor = defaultExecutor,
  environmentVariables = process.env,
  now = new Date(),
}) => {
  assertReleaseMutationReady(flags);
  const context = loadOperationContext({
    capability: 'deploy',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  if (context.scope === 'prerelease') {
    if (flags['synthetic-only'] !== true || flags['after-web-origin'] !== true) {
      fail('E7_PRERELEASE_SEED_FLAGS_REQUIRED');
    }
  } else if (flags['after-web-origin'] || flags['synthetic-only']) {
    fail('E7_FULL_RELEASE_SEED_FLAG_INVALID');
  }
  const identity = revalidateAwsIdentity(context);
  const runtimeSecretReferenceSha256 = validateRuntimeSecretReferenceAws(context);
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
  delete seedEnvironment.ALLOWED_ORIGIN_PARAMETER_NAME;
  delete seedEnvironment.DYNAMODB_ENDPOINT;
  delete seedEnvironment.PUBLIC_ASSET_ORIGIN_PARAMETER_NAME;
  delete seedEnvironment.RUNTIME_SECURITY_ROOT_KEY;
  const first = parseSeedStatus(
    run(context.executor, context.pnpmCommand, ['--filter', '@checkout/api', 'seed'], {
      code: 'E7_SEED_FIRST_EXECUTION_FAILED',
      env: seedEnvironment,
    }),
    'E7_SEED_FIRST_RESULT_INVALID',
  );
  const second = parseSeedStatus(
    run(context.executor, context.pnpmCommand, ['--filter', '@checkout/api', 'seed'], {
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
    runtimeSecretReferenceSha256,
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

const validateScheduleTarget = (context, apiOutputs) => {
  const schedule = getSchedule(context);
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

const restoreInitialPublicationBaseline = (context, apiPublication, webPublication) => {
  const recoveryFailures = [];
  const recover = (callback) => {
    try {
      callback();
    } catch {
      recoveryFailures.push(true);
    }
  };
  recover(() => updatePublicationStack(context, 'web', 'DISABLED'));
  recover(() => updatePublicationStack(context, 'api', 'DISABLED'));
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
  if (!SHA256.test(webRecord?.publicOriginSha256 ?? '')) {
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
      now: context.now,
    });
  } catch (error) {
    if (typeof error?.code === 'string' && error.code.startsWith('E7_EXTERNAL_AUTHORIZATION')) {
      fail(error.code);
    }
    throw error;
  }
  const fullRelease = context.config.authorization.scope === 'FULL_RELEASE_INITIAL_ONLY';
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
        context.flags['re-promote'] === true ? 'ACTIVATION_REPROMOTION' : 'ACTIVATION_INITIAL',
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
  if (flags.app === undefined || flags.manifest === undefined) fail('E7_ACTIVATION_INPUT_REQUIRED');
  assertReleaseMutationReady(flags);
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
  // The protected external bundle is a local, immutable input. Validate it and the
  // rollback records before even reading STS so an unauthorized prerelease cannot
  // cause any AWS or provider request.
  const apiRecord = readRecord(context, 'rollback-api', flags['api-record']);
  const webRecord = readRecord(context, 'rollback-web', flags['web-record']);
  const observabilityReadiness = validateObservabilityReadinessEvidence(
    context,
    flags['observability-evidence'],
  );
  const initialRelease = flags['initial-release'] === true;
  if (
    (flags['initial-release'] !== undefined && !initialRelease) ||
    (apiRecord.releaseMode === 'INITIAL') !== initialRelease ||
    (webRecord.releaseMode === 'INITIAL') !== initialRelease ||
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
  revalidateAwsIdentity(context);
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  let apiOutputs;
  for (const suffix of STACK_SUFFIXES) {
    const state = describeStack(context, stackFor(context, suffix));
    if (
      !/^(?:CREATE|UPDATE)_COMPLETE$/u.test(state.stackStatus) ||
      state.terminationProtection !== (context.scope !== 'prerelease') ||
      state.outputs.CandidateSha !== context.identity.candidateSha ||
      state.outputs.ReleaseId !== context.identity.releaseId
    )
      fail('E7_ACTIVATION_STACK_NOT_READY');
    if (suffix === 'api') apiOutputs = state.outputs;
  }
  const origin = publicOrigin(context, { requireWeb: true });
  assertExactHttpsOrigin(origin.value);
  const seedEvidenceSha256 = validateSeedEvidence(context, flags['seed-evidence']);
  const scheduleTargetSha256 = validateScheduleTarget(context, apiOutputs);
  const apiCurrent = getAlias(context, apiRecord.deployed.api);
  const workerCurrent = getAlias(context, apiRecord.deployed.worker);
  if (
    apiCurrent.FunctionVersion !== apiRecord.deployed.api.version ||
    workerCurrent.FunctionVersion !== apiRecord.deployed.worker.version
  ) {
    fail('E7_ALIAS_DRIFT_DETECTED');
  }
  const apiPromotion = { changed: false, version: apiRecord.deployed.api.version };
  const workerPromotion = { changed: false, version: apiRecord.deployed.worker.version };
  const currentWeb = listWebVersions(context, webRecord.bucketName);
  const currentByKey = new Map(currentWeb.map((entry) => [entry.key, entry]));
  const alreadyPromoted = webRecord.deployed.every(
    (entry) => currentByKey.get(entry.key)?.etagSha256 === entry.etagSha256,
  );
  if (!alreadyPromoted) fail('E7_WEB_OBJECT_DRIFT_DETECTED');
  const webPromotion = { invalidatedPaths: [], restoredObjects: 0 };
  const publicationState = initialRelease
    ? initialPublicationState(context, apiRecord.publication, webRecord.publication)
    : null;
  if (!publicationState?.baseline) fail('E7_ACTIVATION_REQUIRES_DISABLED_BASELINE');
  let apiPublication;
  let webPublication;
  try {
    apiPublication = updatePublicationStack(context, 'api', 'ENABLED');
    webPublication = updatePublicationStack(context, 'web', 'ENABLED');
    const activated = initialPublicationState(
      context,
      apiRecord.publication,
      webRecord.publication,
    );
    if (!activated.activated) fail('E7_ACTIVATION_STATE_NOT_APPLIED');
  } catch (error) {
    restoreInitialPublicationBaseline(context, apiRecord.publication, webRecord.publication);
    throw error;
  }
  const scheduler = {
    controlledBy: 'PublicationState',
    stackName: apiPublication.stackName,
    state: 'ENABLED',
  };
  const transition = {
    sequence: previousTransitions.length + 1,
    mode: flags['re-promote'] === true ? 'REPROMOTION' : 'INITIAL_ACTIVATION',
    apiStack: apiPublication,
    webStack: webPublication,
    scheduler,
    authorizationUsage: authorization.authorizationUsage,
  };
  const checkpoint = {
    decision: 'ACTIVATED_REQUIRES_SMOKE',
    releaseMode: 'INITIAL',
    updateReleaseSupported: false,
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

const detectStackDrift = async (context, stackName) => {
  const started = awsJson(
    context,
    ['cloudformation', 'detect-stack-drift', '--stack-name', stackName],
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
      typeof status?.StackId !== 'string' ||
      status.StackId === '' ||
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
  const context = loadOperationContext({
    capability: 'read',
    scope: flags.scope,
    flags,
    executor,
    environmentVariables,
    now,
    requireAws: true,
  });
  revalidateAwsIdentity(context);
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  for (const suffix of ['api', 'web']) {
    if (publicationStateForStack(context, suffix).publicationState !== 'ENABLED') {
      fail('E7_DRIFT_VERIFICATION_REQUIRES_ACTIVE_RELEASE');
    }
  }
  const results = [];
  for (const stackName of context.stacks) results.push(await detectStackDrift(context, stackName));
  const checkpoint = {
    decision: 'PASS',
    releaseMode: 'INITIAL',
    updateReleaseSupported: false,
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
    const publication = updatePublicationStack(context, 'api', 'DISABLED');
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
  const initialRelease = rollbackReleaseMode(flags, record, 'to-unpublished') === 'INITIAL';
  revalidateAwsIdentity(context);
  if (initialRelease) {
    if (
      !record.initialUnpublishAvailable ||
      !Array.isArray(record.previous) ||
      record.previous.length !== 0
    ) {
      fail('E7_INITIAL_WEB_ROLLBACK_RECORD_INVALID');
    }
    const apiStack = publicationStateForStack(context, 'api');
    if (apiStack.publicationState !== 'DISABLED' || getSchedule(context).State !== 'DISABLED') {
      fail('E7_INITIAL_API_ROLLBACK_REQUIRED');
    }
    const publication = updatePublicationStack(context, 'web', 'DISABLED');
    const distribution = getDistributionConfig(context, record.publication.distributionId);
    if (distribution.DistributionConfig.Enabled !== false) {
      fail('E7_INITIAL_WEB_ROLLBACK_STATE_NOT_APPLIED');
    }
    const rollbackEvidence = readJson(
      evidenceTarget(context, 'rollback'),
      'E7_INITIAL_API_ROLLBACK_EVIDENCE_MISSING',
    );
    const apiRollback = rollbackEvidence?.checkpoints?.apiRollback;
    if (
      apiRollback?.decision !== 'INITIAL_RELEASE_DISABLED_REQUIRES_UNAVAILABLE_SMOKE' ||
      apiRollback?.releaseMode !== 'INITIAL' ||
      apiRollback?.aliasesChanged !== false ||
      apiRollback?.dataFactsChanged !== false ||
      apiRollback?.stacksDeleted !== 0 ||
      apiRollback?.publication?.changed !== true ||
      apiRollback?.publication?.previousState !== 'ENABLED' ||
      apiRollback?.publication?.state !== 'DISABLED' ||
      apiRollback?.publication?.stackName !== stackFor(context, 'api') ||
      !SHA256.test(apiRollback?.publication?.stackIdSha256 ?? '')
    ) {
      fail('E7_INITIAL_API_ROLLBACK_EVIDENCE_INVALID');
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

const destroyStack = (context, assembly, suffix) => {
  const stackName = stackFor(context, suffix);
  cdk(
    context,
    [
      'destroy',
      stackName,
      '--app',
      assembly.app,
      '--exclusively',
      '--force',
      ...frozenContextArguments(context),
    ],
    `E7_CDK_DESTROY_${suffix.toUpperCase()}_FAILED`,
  );
  const state = describeStack(context, stackName, { allowMissing: true });
  if (state.exists) fail('E7_CLEANUP_STACK_STILL_EXISTS');
  return stackName;
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
    const context = loadOperationContext({
      capability: 'cleanup',
      scope: flags.scope,
      flags,
      executor,
      environmentVariables,
      now,
      requireAws: false,
    });
    const checkpoint = {
      decision: 'EXPIRY_REGISTERED',
      expiresAtUtc: context.config.cleanup.expiresAtUtc,
      cleanupOwnerAlias: context.config.cleanup.ownerAlias,
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
  const identity = revalidateAwsIdentity(context);
  const assembly = validateAssemblyIdentity(context, flags.app, flags.manifest);
  const destroyedStacks = [];
  try {
    const states = new Map(
      STACK_SUFFIXES.map((suffix) => [
        suffix,
        describeStack(context, stackFor(context, suffix), { allowMissing: true }),
      ]),
    );
    if (
      [...states.values()].some((state) => state.exists && state.terminationProtection !== false)
    ) {
      fail('E7_EPHEMERAL_TERMINATION_PROTECTION_INVALID');
    }
    const web = states.get('web');
    if (web.exists) updatePublicationStack(context, 'web', 'DISABLED');
    const api = states.get('api');
    if (api.exists) updatePublicationStack(context, 'api', 'DISABLED');
    for (const suffix of [...STACK_SUFFIXES].reverse()) {
      const state = states.get(suffix);
      if (state.exists) destroyedStacks.push(destroyStack(context, assembly, suffix));
    }
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
        expiresAtUtc: iso(3 * 60 * 60 * 1000),
        preserveBootstrap: true,
        preservePreviousRelease: true,
      },
      credentialReferences: [
        ['arn', 'aws', 'secretsmanager', 'us-east-1', accountId, 'secret:e7/root'].join(':'),
      ],
      containsSensitiveData: false,
    },
    destination,
  };
};

export const selfTestAwsOperations = async () => {
  const now = new Date('2026-08-17T12:00:00.000Z');
  const { config } = selfTestConfig(now);
  validateStage7Config(config, { now });
  const directory = mkdtempSync(path.join(tmpdir(), 'checkout-stage7-aws-ops-selftest-'));
  const configPath = path.join(directory, 'config.json');
  assert.equal(
    directory.startsWith(path.join(tmpdir(), 'checkout-stage7-aws-ops-selftest-')),
    true,
  );
  writeFileSync(configPath, `${JSON.stringify(config)}\n`, { encoding: 'utf8', mode: 0o600 });
  let fakeCalls = 0;
  const fakeExecutor = ({ command, args }) => {
    fakeCalls += 1;
    assert.equal(command, 'aws');
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
    GITHUB_SHA: 'a'.repeat(40),
    STAGE7_AWS_COMMAND: 'aws',
  };
  try {
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
    assert.equal(publicationMode({ ...context, scope: undefined }), 'INITIAL_CLOSED');
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
      'E7_PRERELEASE_SAFETY_CONTROLS_REQUIRED',
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
    assert.equal(deployReleaseMode({ 'initial-release': true }), 'INITIAL');
    expectCode(
      () => deployReleaseMode({ 'previous-manifest': 'previous.json' }),
      'E7_UPDATE_RELEASE_NOT_SUPPORTED',
    );
    expectCode(
      () =>
        deployReleaseMode({
          'initial-release': true,
          'previous-manifest': 'previous.json',
        }),
      'E7_UPDATE_RELEASE_NOT_SUPPORTED',
    );
    expectCode(() => deployReleaseMode({}), 'E7_UPDATE_RELEASE_NOT_SUPPORTED');
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
        hostname: 'checkout.release.example.invalid',
        apiHostname: 'api.release.example.invalid',
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
        sandboxHostSha256: sha256('sandbox.wompi.co'),
      },
      authorizations: {
        ownedTarget: authorization(
          'AUTH-E6-01',
          'OWNED_EPHEMERAL_QA_HTTPS_VERIFICATION',
          ownedOriginSha256,
          3,
        ),
        sandboxSmoke: authorization(
          'AUTH-E6-02',
          'AUTHORIZED_PROVIDER_SANDBOX_SMOKE',
          sha256('sandbox.wompi.co'),
          7,
        ),
        passiveSecurity: authorization(
          'AUTH-E6-03',
          'PASSIVE_BASELINE_OWNED_QA_ONLY',
          ownedOriginSha256,
          6,
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
          { publicOriginSha256: ownedOriginSha256 },
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
        }),
      'E7_EXTERNAL_AUTHORIZATION_ENVELOPE_INVALID',
    );
    const prereleaseAuthorization = validateActivationAuthorization(
      activationContextWithMismatchedTarget,
      { publicOriginSha256: ownedOriginSha256 },
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
        scope: 'FULL_RELEASE_INITIAL_ONLY',
        stacks: expectedStacks(fullEnvironment),
      },
      domain: {
        mode: 'CUSTOM_AUTHORIZED',
        hostname: 'checkout.release.example.invalid',
        apiHostname: 'api.release.example.invalid',
        hostedZoneId: 'Z1234567890ABC',
        webCertificateArn: `arn:aws:acm:us-east-1:${config.aws.accountId}:certificate/11111111-1111-1111-1111-111111111111`,
        apiCertificateArn: `arn:aws:acm:us-east-1:${config.aws.accountId}:certificate/22222222-2222-2222-2222-222222222222`,
        dnsIncluded: true,
      },
    };
    validateStage7Config(fullConfig, { now });
    const fullOriginSha256 = sha256('https://checkout.release.example.invalid');
    const fullBundle = {
      ...externalBundle,
      stage7ConfigSha256: objectSha256(fullConfig),
      targets: { ...externalBundle.targets, ownedOriginSha256: fullOriginSha256 },
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
          7,
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
        releaseMode: 'INITIAL',
        updateReleaseSupported: false,
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
            mode: 'INITIAL_ACTIVATION',
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
