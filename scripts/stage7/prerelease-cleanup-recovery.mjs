#!/usr/bin/env node

import { strict as assert } from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  GITHUB_OIDC_REPOSITORY,
  githubOidcEnvironmentSubject,
  githubOidcRefSubject,
} from './github-oidc-subject-contract.mjs';

const STACK_SUFFIXES = ['data', 'api', 'observability', 'web'];
const DELETION_ORDER = [...STACK_SUFFIXES].reverse();
const STABLE_STACK_STATUSES = new Set([
  'CREATE_COMPLETE',
  'ROLLBACK_COMPLETE',
  'UPDATE_COMPLETE',
  'UPDATE_ROLLBACK_COMPLETE',
]);
const ENVIRONMENT_PATTERN = /^assessment-prerelease-[a-z0-9][a-z0-9-]{0,39}$/u;
const RELEASE_ID_PATTERN = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const CANDIDATE_SHA_PATTERN = /^[0-9a-f]{40}$/u;
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/u;
const UTC_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const ACCOUNT_PATTERN = /^\d{12}$/u;
const REGION_PATTERN = /^[a-z]{2}(?:-[a-z0-9]+)+-\d$/u;
const ROLE_ARN_PATTERN =
  /^arn:aws:iam::(\d{12}):role\/(?:[A-Za-z0-9+=,.@_-]+\/)*([A-Za-z0-9+=,.@_-]+)$/u;
const STACK_ARN_PATTERN = /^arn:aws:cloudformation:([^:]+):(\d{12}):stack\/([^/]+)\/([^/]+)$/u;
const MARKER_PROTOCOL_KEY = 'Stage7CleanupProtocol';
const MARKER_PROTOCOL_VALUE = 'expired-prerelease-v1';
const MARKER_SET_KEY = 'Stage7CleanupSetSha256';
const MAX_PAGES = 100;
const MAX_GROUPS = 20;
const EVIDENCE_ROOT = path.join('output', 'evidence', 'runtime', 'stage-7-prerelease-cleanup');
const EXPECTED_REPOSITORY = GITHUB_OIDC_REPOSITORY;
const EXPECTED_REF = 'refs/heads/master';
const EXPECTED_OIDC_SUBJECT = githubOidcRefSubject(EXPECTED_REF);

export class PrereleaseCleanupError extends Error {
  constructor(code) {
    super(code);
    this.name = 'PrereleaseCleanupError';
    this.code = code;
  }
}

const fail = (code) => {
  throw new PrereleaseCleanupError(code);
};

const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

const normalizeSource = (value) => String(value ?? '').replace(/\r\n?/gu, '\n');

const exactDate = (value) => {
  if (!DATE_PATTERN.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
};

const exactUtcTimestamp = (value) => {
  if (!UTC_TIMESTAMP_PATTERN.test(value)) return false;
  const parsed = new Date(value);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
};

const tagMap = (tags, code = 'E7_CLEANUP_TAG_SET_INVALID') => {
  if (!Array.isArray(tags)) fail(code);
  const result = new Map();
  for (const tag of tags) {
    if (
      tag === null ||
      typeof tag !== 'object' ||
      typeof tag.Key !== 'string' ||
      typeof tag.Value !== 'string' ||
      tag.Key.length === 0 ||
      result.has(tag.Key)
    ) {
      fail(code);
    }
    result.set(tag.Key, tag.Value);
  }
  return result;
};

const parameterMap = (parameters) => {
  if (!Array.isArray(parameters)) fail('E7_CLEANUP_PARAMETER_SET_INVALID');
  const result = new Map();
  for (const parameter of parameters) {
    if (
      parameter === null ||
      typeof parameter !== 'object' ||
      typeof parameter.ParameterKey !== 'string' ||
      typeof parameter.ParameterValue !== 'string' ||
      result.has(parameter.ParameterKey)
    ) {
      fail('E7_CLEANUP_PARAMETER_SET_INVALID');
    }
    result.set(parameter.ParameterKey, parameter.ParameterValue);
  }
  return result;
};

const outputMap = (outputs) => {
  if (!Array.isArray(outputs)) fail('E7_CLEANUP_OUTPUT_SET_INVALID');
  const result = new Map();
  for (const output of outputs) {
    if (
      output === null ||
      typeof output !== 'object' ||
      typeof output.OutputKey !== 'string' ||
      typeof output.OutputValue !== 'string' ||
      result.has(output.OutputKey)
    ) {
      fail('E7_CLEANUP_OUTPUT_SET_INVALID');
    }
    result.set(output.OutputKey, output.OutputValue);
  }
  return result;
};

const expectedStackName = (environment, suffix) => `checkout-${environment}-${suffix}`;

const cleanupSetSha256 = ({
  candidateSha,
  cleanupExpiresAtUtc,
  environment,
  expiresOn,
  releaseId,
}) =>
  sha256(
    [
      environment,
      releaseId,
      candidateSha,
      expiresOn,
      cleanupExpiresAtUtc,
      ...STACK_SUFFIXES.map((suffix) => expectedStackName(environment, suffix)),
    ].join('\0'),
  );

const requiredTagIdentity = (tags) => ({
  candidateSha: tags.get('CandidateSha'),
  cleanupExpiresAtUtc: tags.get('CleanupExpiresAtUtc'),
  environment: tags.get('Environment'),
  expiresOn: tags.get('ExpiresOn'),
  managedBy: tags.get('ManagedBy'),
  project: tags.get('Project'),
  releaseId: tags.get('ReleaseId'),
});

const markerState = (tags, expectedSetSha256) => {
  const protocol = tags.get(MARKER_PROTOCOL_KEY);
  const set = tags.get(MARKER_SET_KEY);
  if (protocol === undefined && set === undefined) return 'ABSENT';
  if (protocol === MARKER_PROTOCOL_VALUE && set === expectedSetSha256) return 'EXACT';
  fail('E7_CLEANUP_MARKER_AMBIGUOUS');
};

const parseStackArn = (arn, account, region) => {
  const match = STACK_ARN_PATTERN.exec(arn);
  if (match === null || match[1] !== region || match[2] !== account) {
    fail('E7_CLEANUP_STACK_ARN_OUTSIDE_BOUNDARY');
  }
  return { name: match[3], id: match[4] };
};

const validateRequiredTags = (tags) => {
  const identity = requiredTagIdentity(tags);
  if (identity.managedBy !== 'cdk' || identity.project !== 'checkout') {
    fail('E7_CLEANUP_OWNERSHIP_TAG_MISMATCH');
  }
  if (typeof identity.environment !== 'string' || !ENVIRONMENT_PATTERN.test(identity.environment)) {
    fail('E7_CLEANUP_ENVIRONMENT_TAG_INVALID');
  }
  if (typeof identity.releaseId !== 'string' || !RELEASE_ID_PATTERN.test(identity.releaseId)) {
    fail('E7_CLEANUP_RELEASE_TAG_INVALID');
  }
  if (
    typeof identity.candidateSha !== 'string' ||
    !CANDIDATE_SHA_PATTERN.test(identity.candidateSha)
  ) {
    fail('E7_CLEANUP_CANDIDATE_SHA_TAG_INVALID');
  }
  if (identity.releaseId.slice(-7) !== identity.candidateSha.slice(0, 7)) {
    fail('E7_CLEANUP_RELEASE_CANDIDATE_BINDING_INVALID');
  }
  if (typeof identity.expiresOn !== 'string' || !exactDate(identity.expiresOn)) {
    fail('E7_CLEANUP_EXPIRY_TAG_INVALID');
  }
  if (
    typeof identity.cleanupExpiresAtUtc !== 'string' ||
    !exactUtcTimestamp(identity.cleanupExpiresAtUtc) ||
    identity.cleanupExpiresAtUtc.slice(0, 10) !== identity.expiresOn
  ) {
    fail('E7_CLEANUP_EXACT_EXPIRY_TAG_INVALID');
  }
  if (tags.has('expiry')) fail('E7_CLEANUP_EXPIRY_TAG_AMBIGUOUS');
  return identity;
};

const mappingCandidate = (mapping, account, region) => {
  if (mapping === null || typeof mapping !== 'object' || typeof mapping.ResourceARN !== 'string') {
    fail('E7_CLEANUP_RESOURCE_MAPPING_INVALID');
  }
  const tags = tagMap(mapping.Tags, 'E7_CLEANUP_RESOURCE_MAPPING_TAGS_INVALID');
  const parsedArn = parseStackArn(mapping.ResourceARN, account, region);
  const environment = tags.get('Environment');
  const nameLooksLikePrerelease = parsedArn.name.startsWith('checkout-assessment-prerelease-');
  const tagLooksLikePrerelease =
    typeof environment === 'string' && environment.startsWith('assessment-prerelease');

  if (!nameLooksLikePrerelease && !tagLooksLikePrerelease) return null;
  const identity = validateRequiredTags(tags);
  const suffix = STACK_SUFFIXES.find(
    (candidate) => parsedArn.name === expectedStackName(identity.environment, candidate),
  );
  if (suffix === undefined) fail('E7_CLEANUP_STACK_NAME_AMBIGUOUS');
  return {
    arn: mapping.ResourceARN,
    identity,
    mappingTags: tags,
    name: parsedArn.name,
    suffix,
  };
};

const defaultExecutor = (args) => {
  const result = spawnSync('aws', [...args, '--no-cli-pager'], {
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
    shell: false,
    windowsHide: true,
  });
  return {
    status: result.status ?? 1,
    stderr: normalizeSource(result.stderr),
    stdout: normalizeSource(result.stdout),
  };
};

const awsClient = (executor, region, calls) => {
  const invoke = (service, operation, args, code, options = {}) => {
    const command = [service, operation, ...args, '--region', region, '--output', 'json'];
    calls.push({ operation: `${service}:${operation}`, mutation: options.mutation === true });
    const result = executor(command);
    if (result === null || typeof result !== 'object' || !Number.isInteger(result.status)) {
      fail('E7_CLEANUP_AWS_EXECUTOR_INVALID');
    }
    if (result.status !== 0) {
      if (options.allowMissing && /does not exist|not exist/iu.test(result.stderr ?? '')) {
        return { missing: true };
      }
      if (options.allowNoUpdates && /No updates are to be performed/iu.test(result.stderr ?? '')) {
        return { noUpdates: true };
      }
      fail(code);
    }
    if (options.json === false) return {};
    try {
      return JSON.parse(result.stdout || '{}');
    } catch {
      fail(`${code}_INVALID_JSON`);
    }
  };
  return { invoke };
};

const validateExecutionEnvironment = ({ account, environmentVariables, roleArn }) => {
  if (!ACCOUNT_PATTERN.test(account)) fail('E7_CLEANUP_ACCOUNT_INVALID');
  const roleMatch = ROLE_ARN_PATTERN.exec(roleArn);
  if (roleMatch === null || roleMatch[1] !== account) fail('E7_CLEANUP_ROLE_BOUNDARY_INVALID');
  if (
    environmentVariables.GITHUB_ACTIONS !== 'true' ||
    environmentVariables.GITHUB_REPOSITORY !== EXPECTED_REPOSITORY ||
    environmentVariables.GITHUB_REF !== EXPECTED_REF ||
    environmentVariables.STAGE7_CLEANUP_OIDC !== 'true' ||
    environmentVariables.STAGE7_PRERELEASE_CLEANUP_OIDC_SUBJECT !== EXPECTED_OIDC_SUBJECT ||
    typeof environmentVariables.AWS_SESSION_TOKEN !== 'string' ||
    environmentVariables.AWS_SESSION_TOKEN.length < 16
  ) {
    fail('E7_CLEANUP_OIDC_SESSION_REQUIRED');
  }
  return { roleName: roleMatch[2] };
};

const verifyCallerIdentity = (client, account, roleName) => {
  const response = client.invoke(
    'sts',
    'get-caller-identity',
    [],
    'E7_CLEANUP_CALLER_IDENTITY_FAILED',
  );
  const assumedRole = /^arn:aws:sts::(\d{12}):assumed-role\/([^/]+)\/[^/]+$/u.exec(
    response?.Arn ?? '',
  );
  if (
    response?.Account !== account ||
    assumedRole === null ||
    assumedRole[1] !== account ||
    assumedRole[2] !== roleName
  ) {
    fail('E7_CLEANUP_CALLER_IDENTITY_MISMATCH');
  }
};

const verifyCleanupRoleTrust = (client, account, roleArn, roleName) => {
  const response = client.invoke(
    'iam',
    'get-role',
    ['--role-name', roleName],
    'E7_CLEANUP_ROLE_TRUST_READ_FAILED',
  );
  const role = response?.Role;
  const policy = role?.AssumeRolePolicyDocument;
  const statement = Array.isArray(policy?.Statement) ? policy.Statement : [];
  const expectedProvider = `arn:aws:iam::${account}:oidc-provider/token.actions.githubusercontent.com`;
  const stringEquals = statement[0]?.Condition?.StringEquals;
  if (
    role?.Arn !== roleArn ||
    policy?.Version !== '2012-10-17' ||
    statement.length !== 1 ||
    JSON.stringify(Object.keys(statement[0]).sort()) !==
      JSON.stringify(['Action', 'Condition', 'Effect', 'Principal']) ||
    statement[0].Effect !== 'Allow' ||
    statement[0].Action !== 'sts:AssumeRoleWithWebIdentity' ||
    JSON.stringify(statement[0].Principal) !== JSON.stringify({ Federated: expectedProvider }) ||
    JSON.stringify(Object.keys(statement[0].Condition ?? {})) !==
      JSON.stringify(['StringEquals']) ||
    JSON.stringify(Object.keys(stringEquals ?? {}).sort()) !==
      JSON.stringify([
        'token.actions.githubusercontent.com:aud',
        'token.actions.githubusercontent.com:sub',
      ]) ||
    stringEquals['token.actions.githubusercontent.com:aud'] !== 'sts.amazonaws.com' ||
    stringEquals['token.actions.githubusercontent.com:sub'] !== EXPECTED_OIDC_SUBJECT
  ) {
    fail('E7_CLEANUP_ROLE_TRUST_INVALID');
  }
};

const listTaggedStackMappings = (client) => {
  const mappings = [];
  const seenArns = new Set();
  const seenTokens = new Set();
  let token = '';
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const args = [
      '--resource-type-filters',
      'cloudformation:stack',
      '--tag-filters',
      'Key=ManagedBy,Values=cdk',
      'Key=Project,Values=checkout',
      '--no-paginate',
    ];
    if (token !== '') args.push('--pagination-token', token);
    const response = client.invoke(
      'resourcegroupstaggingapi',
      'get-resources',
      args,
      'E7_CLEANUP_TAGGED_STACK_SCAN_FAILED',
    );
    if (!Array.isArray(response?.ResourceTagMappingList)) {
      fail('E7_CLEANUP_TAGGED_STACK_SCAN_INVALID');
    }
    for (const mapping of response.ResourceTagMappingList) {
      if (typeof mapping?.ResourceARN !== 'string' || seenArns.has(mapping.ResourceARN)) {
        fail('E7_CLEANUP_TAGGED_STACK_SCAN_DUPLICATE');
      }
      seenArns.add(mapping.ResourceARN);
      mappings.push(mapping);
    }
    const next = response.PaginationToken ?? '';
    if (typeof next !== 'string') fail('E7_CLEANUP_TAGGED_STACK_PAGINATION_INVALID');
    if (next === '') return mappings;
    if (seenTokens.has(next)) fail('E7_CLEANUP_TAGGED_STACK_PAGINATION_LOOP');
    seenTokens.add(next);
    token = next;
  }
  fail('E7_CLEANUP_TAGGED_STACK_PAGINATION_LIMIT');
};

const describeStack = (client, arn, { allowMissing = false } = {}) => {
  const response = client.invoke(
    'cloudformation',
    'describe-stacks',
    ['--stack-name', arn],
    'E7_CLEANUP_DESCRIBE_STACK_FAILED',
    { allowMissing },
  );
  if (response.missing === true) return null;
  if (!Array.isArray(response.Stacks) || response.Stacks.length !== 1) {
    fail('E7_CLEANUP_DESCRIBE_STACK_INVALID');
  }
  return response.Stacks[0];
};

const hydrateCandidate = (client, candidate, account, region) => {
  const stack = describeStack(client, candidate.arn);
  if (
    stack === null ||
    stack.StackId !== candidate.arn ||
    stack.StackName !== candidate.name ||
    !STABLE_STACK_STATUSES.has(stack.StackStatus) ||
    stack.EnableTerminationProtection !== false
  ) {
    fail('E7_CLEANUP_STACK_STATE_AMBIGUOUS');
  }
  parseStackArn(stack.StackId, account, region);
  const tags = tagMap(stack.Tags);
  const identity = validateRequiredTags(tags);
  for (const [key, expected] of Object.entries(candidate.identity)) {
    if (identity[key] !== expected) fail('E7_CLEANUP_TAG_AUTHORITY_MISMATCH');
  }
  if (tags.size > 48) fail('E7_CLEANUP_TAG_CAPACITY_EXCEEDED');
  const parameters = parameterMap(stack.Parameters ?? []);
  const outputs = outputMap(stack.Outputs ?? []);
  if (outputs.get('ReleaseId') !== identity.releaseId) fail('E7_CLEANUP_RELEASE_OUTPUT_MISMATCH');
  if (outputs.get('CandidateSha') !== identity.candidateSha) {
    fail('E7_CLEANUP_CANDIDATE_SHA_OUTPUT_MISMATCH');
  }
  if (candidate.suffix === 'api' || candidate.suffix === 'web') {
    if (!['DISABLED', 'ENABLED'].includes(parameters.get('PublicationState'))) {
      fail('E7_CLEANUP_PUBLICATION_PARAMETER_INVALID');
    }
  } else if (parameters.has('PublicationState')) {
    fail('E7_CLEANUP_PUBLICATION_PARAMETER_UNEXPECTED');
  }
  return { ...candidate, outputs, parameters, stack, tags };
};

const groupCandidates = (candidates, now) => {
  const byEnvironment = new Map();
  for (const candidate of candidates) {
    const group = byEnvironment.get(candidate.identity.environment) ?? [];
    if (group.some((entry) => entry.suffix === candidate.suffix)) {
      fail('E7_CLEANUP_DUPLICATE_STACK_KIND');
    }
    group.push(candidate);
    byEnvironment.set(candidate.identity.environment, group);
  }
  if (byEnvironment.size > MAX_GROUPS) fail('E7_CLEANUP_GROUP_LIMIT_EXCEEDED');

  const releaseIds = new Set();
  const plans = [];
  for (const [environment, stacks] of [...byEnvironment.entries()].sort(([left], [right]) =>
    left.localeCompare(right),
  )) {
    const candidateSha = stacks[0].identity.candidateSha;
    const releaseId = stacks[0].identity.releaseId;
    const expiresOn = stacks[0].identity.expiresOn;
    const cleanupExpiresAtUtc = stacks[0].identity.cleanupExpiresAtUtc;
    if (
      stacks.some(
        (stack) =>
          stack.identity.environment !== environment ||
          stack.identity.candidateSha !== candidateSha ||
          stack.identity.releaseId !== releaseId ||
          stack.identity.expiresOn !== expiresOn ||
          stack.identity.cleanupExpiresAtUtc !== cleanupExpiresAtUtc,
      )
    ) {
      fail('E7_CLEANUP_QUARTET_IDENTITY_AMBIGUOUS');
    }
    if (releaseIds.has(releaseId)) fail('E7_CLEANUP_RELEASE_REUSED_ACROSS_ENVIRONMENTS');
    releaseIds.add(releaseId);
    const setSha256 = cleanupSetSha256({
      candidateSha,
      cleanupExpiresAtUtc,
      environment,
      expiresOn,
      releaseId,
    });
    const markerStates = new Map(
      stacks.map((stack) => [stack.suffix, markerState(stack.tags, setSha256)]),
    );
    const present = STACK_SUFFIXES.filter((suffix) =>
      stacks.some((stack) => stack.suffix === suffix),
    );
    const expired = now.getTime() >= new Date(cleanupExpiresAtUtc).getTime();
    const fullQuartet = present.length === STACK_SUFFIXES.length;
    const exactDeployPrefix =
      present.length > 0 &&
      JSON.stringify(present) === JSON.stringify(STACK_SUFFIXES.slice(0, present.length));
    const markersPresent = [...markerStates.values()].filter((value) => value === 'EXACT').length;

    if (!exactDeployPrefix) fail('E7_CLEANUP_STACK_SUBSET_IMPOSSIBLE');

    if (!expired) {
      if (markersPresent !== 0) fail('E7_CLEANUP_NONEXPIRED_STATE_AMBIGUOUS');
      plans.push({
        candidateSha,
        cleanupExpiresAtUtc,
        environment,
        expired,
        expiresOn,
        mode: fullQuartet ? 'NOT_EXPIRED' : 'INCOMPLETE_DEPLOY_PENDING_EXPIRY',
        releaseId,
        stacks,
      });
      continue;
    }
    plans.push({
      candidateSha,
      environment,
      cleanupExpiresAtUtc,
      expired,
      expiresOn,
      mode: fullQuartet
        ? markersPresent === 0
          ? 'NEW_QUARTET'
          : markersPresent === STACK_SUFFIXES.length
            ? 'MARKED_QUARTET'
            : 'MARKING_RESUME'
        : markersPresent === 0
          ? 'ABANDONED_DEPLOY'
          : markersPresent === present.length
            ? 'DELETION_RESUME'
            : 'PARTIAL_MARKING_RESUME',
      releaseId,
      setSha256,
      stacks,
    });
  }
  return plans;
};

const discovery = (client, account, region, now) => {
  const mappings = listTaggedStackMappings(client);
  const candidates = mappings
    .map((mapping) => mappingCandidate(mapping, account, region))
    .filter((candidate) => candidate !== null)
    .map((candidate) => hydrateCandidate(client, candidate, account, region));
  return {
    mappingsScanned: mappings.length,
    plans: groupCandidates(candidates, now),
  };
};

const previousParameters = (parameters, publicationState) =>
  [...parameters.keys()]
    .sort()
    .map((key) =>
      key === 'PublicationState' && publicationState !== undefined
        ? { ParameterKey: key, ParameterValue: publicationState }
        : { ParameterKey: key, UsePreviousValue: true },
    );

const serializedTags = (tags, setSha256) => {
  const next = new Map(tags);
  next.set(MARKER_PROTOCOL_KEY, MARKER_PROTOCOL_VALUE);
  next.set(MARKER_SET_KEY, setSha256);
  return [...next.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([Key, Value]) => ({ Key, Value }));
};

const updateStack = (client, stack, setSha256, publicationState) => {
  const args = [
    '--stack-name',
    stack.arn,
    '--use-previous-template',
    '--capabilities',
    'CAPABILITY_IAM',
    'CAPABILITY_NAMED_IAM',
    'CAPABILITY_AUTO_EXPAND',
    '--tags',
    JSON.stringify(serializedTags(stack.tags, setSha256)),
  ];
  const parameters = previousParameters(stack.parameters, publicationState);
  if (parameters.length > 0) args.push('--parameters', JSON.stringify(parameters));
  const update = client.invoke(
    'cloudformation',
    'update-stack',
    args,
    'E7_CLEANUP_UPDATE_STACK_FAILED',
    {
      allowNoUpdates: true,
      mutation: true,
    },
  );
  if (update.noUpdates === true) return false;
  client.invoke(
    'cloudformation',
    'wait',
    ['stack-update-complete', '--stack-name', stack.arn],
    'E7_CLEANUP_UPDATE_WAIT_FAILED',
    { json: false },
  );
  return true;
};

const refreshStack = (client, stack, expectedSetSha256, publicationState, updated) => {
  const refreshed = describeStack(client, stack.arn);
  if (
    refreshed === null ||
    (updated
      ? refreshed.StackStatus !== 'UPDATE_COMPLETE'
      : !STABLE_STACK_STATUSES.has(refreshed.StackStatus)) ||
    refreshed.StackId !== stack.arn ||
    refreshed.StackName !== stack.name ||
    refreshed.EnableTerminationProtection !== false
  ) {
    fail('E7_CLEANUP_UPDATED_STACK_STATE_INVALID');
  }
  const tags = tagMap(refreshed.Tags);
  const identity = validateRequiredTags(tags);
  if (
    identity.candidateSha !== stack.identity.candidateSha ||
    identity.environment !== stack.identity.environment ||
    identity.releaseId !== stack.identity.releaseId ||
    identity.expiresOn !== stack.identity.expiresOn ||
    identity.cleanupExpiresAtUtc !== stack.identity.cleanupExpiresAtUtc ||
    markerState(tags, expectedSetSha256) !== 'EXACT'
  ) {
    fail('E7_CLEANUP_UPDATED_STACK_IDENTITY_INVALID');
  }
  const parameters = parameterMap(refreshed.Parameters ?? []);
  if (publicationState !== undefined && parameters.get('PublicationState') !== publicationState) {
    fail('E7_CLEANUP_PUBLICATION_UPDATE_NOT_APPLIED');
  }
  return { ...stack, parameters, stack: refreshed, tags };
};

const ensureMarked = (client, stack, setSha256) => {
  if (markerState(stack.tags, setSha256) === 'EXACT') return stack;
  const updated = updateStack(client, stack, setSha256);
  return refreshStack(client, stack, setSha256, undefined, updated);
};

const ensureUnpublished = (client, stack, setSha256) => {
  if (stack.parameters.get('PublicationState') === 'DISABLED') return stack;
  const updated = updateStack(client, stack, setSha256, 'DISABLED');
  return refreshStack(client, stack, setSha256, 'DISABLED', updated);
};

const deleteStack = (client, stack, setSha256) => {
  const token = `e7-cleanup-${setSha256.slice(0, 32)}-${stack.suffix}`;
  client.invoke(
    'cloudformation',
    'delete-stack',
    ['--stack-name', stack.arn, '--client-request-token', token],
    'E7_CLEANUP_DELETE_STACK_FAILED',
    { json: false, mutation: true },
  );
  client.invoke(
    'cloudformation',
    'wait',
    ['stack-delete-complete', '--stack-name', stack.arn],
    'E7_CLEANUP_DELETE_WAIT_FAILED',
    { json: false },
  );
  if (describeStack(client, stack.arn, { allowMissing: true }) !== null) {
    fail('E7_CLEANUP_STACK_STILL_EXISTS');
  }
};

const executePlan = (client, plan) => {
  if (!plan.expired || plan.setSha256 === undefined) fail('E7_CLEANUP_PLAN_NOT_EXPIRED');
  const stacks = new Map(plan.stacks.map((stack) => [stack.suffix, stack]));
  for (const suffix of STACK_SUFFIXES) {
    const stack = stacks.get(suffix);
    if (stack !== undefined) stacks.set(suffix, ensureMarked(client, stack, plan.setSha256));
  }
  for (const suffix of ['web', 'api']) {
    const stack = stacks.get(suffix);
    if (stack !== undefined) stacks.set(suffix, ensureUnpublished(client, stack, plan.setSha256));
  }
  for (const suffix of ['web', 'api']) {
    const stack = stacks.get(suffix);
    if (stack !== undefined && stack.parameters.get('PublicationState') !== 'DISABLED') {
      fail('E7_CLEANUP_PUBLICATION_PRECONDITION_FAILED');
    }
  }
  const destroyed = [];
  for (const suffix of DELETION_ORDER) {
    const stack = stacks.get(suffix);
    if (stack === undefined) continue;
    deleteStack(client, stack, plan.setSha256);
    destroyed.push(suffix);
  }
  return {
    decision: 'EXPIRED_PRERELEASE_DELETED',
    candidateSha: plan.candidateSha,
    environment: plan.environment,
    expiresOn: plan.expiresOn,
    cleanupExpiresAtUtc: plan.cleanupExpiresAtUtc,
    releaseId: plan.releaseId,
    resumed: plan.mode !== 'NEW_QUARTET',
    stackSetSha256: plan.setSha256,
    topologyAtDiscovery: STACK_SUFFIXES.filter((suffix) => stacks.has(suffix)),
    unpublishedByCloudFormation: true,
    deletionOrder: destroyed,
    remainingStacks: 0,
  };
};

const baseEvidence = ({ account, now, region, roleArn }) => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'expired-prerelease-cleanup-recovery',
  generatedAtUtc: now.toISOString(),
  accountIdSha256: sha256(account),
  region,
  cleanupRoleArnSha256: sha256(roleArn),
  containsSensitiveData: false,
  safeguards: {
    exactOwnershipTagsRequired: true,
    exactDeploymentPrefixRequired: true,
    completeTopology: STACK_SUFFIXES,
    abandonedDeploymentPrefixesRecoveredOnlyAfterExpiry: true,
    partialResumeRequiresDurableCloudFormationTagMarker: true,
    publicationManagedByCloudFormation: true,
    oidcSubject: EXPECTED_OIDC_SUBJECT,
    deletionOrder: DELETION_ORDER,
    fullReleaseExcluded: true,
    bootstrapExcluded: true,
    paginationRequired: true,
  },
});

export const runExpiredPrereleaseCleanup = ({
  account,
  environmentVariables = process.env,
  executor = defaultExecutor,
  now = new Date(),
  region,
  roleArn,
}) => {
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) fail('E7_CLEANUP_CLOCK_INVALID');
  if (!REGION_PATTERN.test(region)) fail('E7_CLEANUP_REGION_INVALID');
  const { roleName } = validateExecutionEnvironment({
    account,
    environmentVariables,
    roleArn,
  });
  const calls = [];
  const client = awsClient(executor, region, calls);
  verifyCallerIdentity(client, account, roleName);
  verifyCleanupRoleTrust(client, account, roleArn, roleName);
  const discovered = discovery(client, account, region, now);
  const expired = discovered.plans.filter((plan) => plan.expired);
  const pending = discovered.plans.filter((plan) => !plan.expired);
  const cleaned = expired.map((plan) => executePlan(client, plan));
  const fullRecoveryVerified = cleaned.some(
    (group) => JSON.stringify(group.topologyAtDiscovery) === JSON.stringify(STACK_SUFFIXES),
  );
  return {
    ...baseEvidence({ account, now: new Date(), region, roleArn }),
    status: 'PASS',
    decision: cleaned.length === 0 ? 'NO_EXPIRED_PRERELEASES' : 'EXPIRED_PRERELEASES_CLEANED',
    durableRecoveryReady: fullRecoveryVerified,
    runtimeVerification: fullRecoveryVerified
      ? 'AWS_FULL_CLEANUP_EXECUTED'
      : cleaned.length > 0
        ? 'AWS_PARTIAL_CLEANUP_EXECUTED'
        : 'AWS_SCAN_ONLY',
    mappingsScanned: discovered.mappingsScanned,
    candidateGroups: discovered.plans.length,
    pendingGroups: pending.length,
    cleanedGroups: cleaned,
    awsCallCount: calls.length,
    mutationCallCount: calls.filter((call) => call.mutation).length,
  };
};

export const dryRunEvidence = ({ now = new Date() } = {}) => ({
  schemaVersion: 1,
  stage: 7,
  kind: 'expired-prerelease-cleanup-recovery',
  generatedAtUtc: now.toISOString(),
  status: 'NOT_RUN',
  decision: 'DRY_RUN_ZERO_AWS',
  durableRecoveryReady: false,
  runtimeVerification: 'NOT_RUN',
  awsCallCount: 0,
  mutationCallCount: 0,
  containsSensitiveData: false,
});

const writeEvidence = (target, evidence) => {
  const root = path.resolve(process.cwd(), EVIDENCE_ROOT);
  const resolved = path.resolve(process.cwd(), target);
  if (
    resolved === root ||
    !resolved.startsWith(`${root}${path.sep}`) ||
    !resolved.endsWith('.json')
  ) {
    fail('E7_CLEANUP_EVIDENCE_PATH_INVALID');
  }
  fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
  const parent = fs.lstatSync(path.dirname(resolved));
  if (parent.isSymbolicLink() || !parent.isDirectory())
    fail('E7_CLEANUP_EVIDENCE_DIRECTORY_INVALID');
  const temporary = `${resolved}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(evidence, null, 2)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
  fs.renameSync(temporary, resolved);
};

const parseFlags = (values) => {
  const flags = {};
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (!token.startsWith('--')) fail('E7_CLEANUP_CLI_ARGUMENT_INVALID');
    const key = token.slice(2);
    if (Object.hasOwn(flags, key)) fail('E7_CLEANUP_CLI_ARGUMENT_DUPLICATE');
    if (key === 'execute') {
      flags[key] = true;
      continue;
    }
    const value = values[index + 1];
    if (value === undefined || value.startsWith('--')) fail('E7_CLEANUP_CLI_VALUE_MISSING');
    flags[key] = value;
    index += 1;
  }
  return flags;
};

const assertExactFlags = (flags, required, allowed) => {
  const keys = Object.keys(flags);
  if (
    required.some((key) => !Object.hasOwn(flags, key)) ||
    keys.some((key) => !allowed.includes(key))
  ) {
    fail('E7_CLEANUP_CLI_ARGUMENT_SET_INVALID');
  }
};

const fixtureTags = (
  { candidateSha, cleanupExpiresAtUtc, environment, expiresOn, releaseId },
  markers = false,
) => {
  const values = [
    { Key: 'CandidateSha', Value: candidateSha },
    { Key: 'CleanupExpiresAtUtc', Value: cleanupExpiresAtUtc },
    { Key: 'Environment', Value: environment },
    { Key: 'ExpiresOn', Value: expiresOn },
    { Key: 'ManagedBy', Value: 'cdk' },
    { Key: 'Project', Value: 'checkout' },
    { Key: 'ReleaseId', Value: releaseId },
  ];
  if (markers) {
    values.push({ Key: MARKER_PROTOCOL_KEY, Value: MARKER_PROTOCOL_VALUE });
    values.push({
      Key: MARKER_SET_KEY,
      Value: cleanupSetSha256({
        candidateSha,
        cleanupExpiresAtUtc,
        environment,
        expiresOn,
        releaseId,
      }),
    });
  }
  return values;
};

const fakeAws = ({
  initialSuffixes = STACK_SUFFIXES,
  markers = false,
  outputCandidateSha,
  status = 'UPDATE_COMPLETE',
  trustSubject = EXPECTED_OIDC_SUBJECT,
} = {}) => {
  const account = '123456789012';
  const region = 'us-east-1';
  const roleName = 'stage7-prerelease-cleanup';
  const identity = {
    candidateSha: 'abcdef0123456789abcdef0123456789abcdef01',
    cleanupExpiresAtUtc: '2026-08-15T09:00:00.000Z',
    environment: 'assessment-prerelease-watchdog',
    expiresOn: '2026-08-15',
    releaseId: 'rel-20260814-1200-abcdef0',
  };
  const stacks = new Map();
  for (const suffix of initialSuffixes) {
    const name = expectedStackName(identity.environment, suffix);
    const arn = `arn:aws:cloudformation:${region}:${account}:stack/${name}/${suffix}-id`;
    stacks.set(suffix, {
      arn,
      name,
      parameters:
        suffix === 'api' || suffix === 'web'
          ? [{ ParameterKey: 'PublicationState', ParameterValue: markers ? 'DISABLED' : 'ENABLED' }]
          : [],
      status,
      tags: fixtureTags(identity, markers),
    });
  }
  const calls = [];
  const result = (statusCode, stdout = {}, stderr = '') => ({
    status: statusCode,
    stderr,
    stdout: typeof stdout === 'string' ? stdout : JSON.stringify(stdout),
  });
  const executor = (args) => {
    calls.push([...args]);
    const service = args[0];
    const operation = args[1];
    if (service === 'sts' && operation === 'get-caller-identity') {
      return result(0, {
        Account: account,
        Arn: `arn:aws:sts::${account}:assumed-role/${roleName}/watchdog`,
      });
    }
    if (service === 'iam' && operation === 'get-role') {
      return result(0, {
        Role: {
          Arn: `arn:aws:iam::${account}:role/${roleName}`,
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Action: 'sts:AssumeRoleWithWebIdentity',
                Condition: {
                  StringEquals: {
                    'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
                    'token.actions.githubusercontent.com:sub': trustSubject,
                  },
                },
                Effect: 'Allow',
                Principal: {
                  Federated: `arn:aws:iam::${account}:oidc-provider/token.actions.githubusercontent.com`,
                },
              },
            ],
          },
        },
      });
    }
    if (service === 'resourcegroupstaggingapi' && operation === 'get-resources') {
      const mappings = [...stacks.values()].map((stack) => ({
        ResourceARN: stack.arn,
        Tags: stack.tags,
      }));
      const tokenIndex = args.indexOf('--pagination-token');
      if (tokenIndex === -1 && mappings.length > 2) {
        return result(0, {
          PaginationToken: 'page-2',
          ResourceTagMappingList: mappings.slice(0, 2),
        });
      }
      return result(0, {
        PaginationToken: '',
        ResourceTagMappingList: tokenIndex === -1 ? mappings : mappings.slice(2),
      });
    }
    const stackIndex = args.indexOf('--stack-name');
    const arn = stackIndex === -1 ? '' : args[stackIndex + 1];
    const entry = [...stacks.entries()].find(([, stack]) => stack.arn === arn);
    if (service === 'cloudformation' && operation === 'describe-stacks') {
      if (entry === undefined) return result(255, '', 'Stack with id does not exist');
      const [, stack] = entry;
      return result(0, {
        Stacks: [
          {
            EnableTerminationProtection: false,
            Outputs: [
              {
                OutputKey: 'CandidateSha',
                OutputValue: outputCandidateSha ?? identity.candidateSha,
              },
              { OutputKey: 'ReleaseId', OutputValue: identity.releaseId },
            ],
            Parameters: stack.parameters,
            StackId: stack.arn,
            StackName: stack.name,
            StackStatus: stack.status,
            Tags: stack.tags,
          },
        ],
      });
    }
    if (service === 'cloudformation' && operation === 'update-stack') {
      if (entry === undefined) return result(255, '', 'missing');
      const [, stack] = entry;
      const tagsIndex = args.indexOf('--tags');
      stack.tags = JSON.parse(args[tagsIndex + 1]);
      const parameterIndex = args.indexOf('--parameters');
      if (parameterIndex !== -1) {
        const supplied = JSON.parse(args[parameterIndex + 1]);
        const publication = supplied.find(
          (parameter) => parameter.ParameterKey === 'PublicationState',
        );
        if (publication?.ParameterValue !== undefined) {
          stack.parameters = [
            { ParameterKey: 'PublicationState', ParameterValue: publication.ParameterValue },
          ];
        }
      }
      stack.status = 'UPDATE_COMPLETE';
      return result(0, { StackId: stack.arn });
    }
    if (service === 'cloudformation' && operation === 'delete-stack') {
      if (entry === undefined) return result(255, '', 'missing');
      stacks.delete(entry[0]);
      return result(0);
    }
    if (service === 'cloudformation' && operation === 'wait') return result(0);
    return result(255, '', 'unexpected fake AWS command');
  };
  return { account, calls, executor, identity, region, roleName, stacks };
};

const executionEnvironment = (roleName, now) => ({
  AWS_CREDENTIAL_EXPIRATION: new Date(now.getTime() + 60 * 60 * 1000).toISOString(),
  AWS_SESSION_TOKEN: 'temporary-session-token-for-self-test',
  GITHUB_ACTIONS: 'true',
  GITHUB_REF: EXPECTED_REF,
  GITHUB_REPOSITORY: EXPECTED_REPOSITORY,
  STAGE7_CLEANUP_OIDC: 'true',
  STAGE7_PRERELEASE_CLEANUP_OIDC_SUBJECT: EXPECTED_OIDC_SUBJECT,
  roleArn: `arn:aws:iam::123456789012:role/${roleName}`,
});

export const selfTestPrereleaseCleanupRecovery = () => {
  const now = new Date('2026-08-17T12:00:00.000Z');
  const first = fakeAws();
  const environment = executionEnvironment(first.roleName, now);
  const evidence = runExpiredPrereleaseCleanup({
    account: first.account,
    environmentVariables: environment,
    executor: first.executor,
    now,
    region: first.region,
    roleArn: environment.roleArn,
  });
  assert.equal(evidence.decision, 'EXPIRED_PRERELEASES_CLEANED');
  assert.equal(evidence.durableRecoveryReady, true);
  assert.equal(evidence.runtimeVerification, 'AWS_FULL_CLEANUP_EXECUTED');
  assert.equal(evidence.cleanedGroups.length, 1);
  assert.deepEqual(evidence.cleanedGroups[0].deletionOrder, DELETION_ORDER);
  assert.equal(first.stacks.size, 0);
  const mutationCommands = first.calls
    .filter((args) => ['update-stack', 'delete-stack'].includes(args[1]))
    .map((args) => args[1]);
  assert.deepEqual(mutationCommands, [
    'update-stack',
    'update-stack',
    'update-stack',
    'update-stack',
    'update-stack',
    'update-stack',
    'delete-stack',
    'delete-stack',
    'delete-stack',
    'delete-stack',
  ]);
  assert.ok(
    first.calls
      .filter((args) => ['update-stack', 'delete-stack'].includes(args[1]))
      .every(
        (args) =>
          !args.join(' ').includes('assessment-release') && !args.join(' ').includes('CDKToolkit'),
      ),
  );

  const second = runExpiredPrereleaseCleanup({
    account: first.account,
    environmentVariables: environment,
    executor: first.executor,
    now,
    region: first.region,
    roleArn: environment.roleArn,
  });
  assert.equal(second.decision, 'NO_EXPIRED_PRERELEASES');
  assert.equal(second.durableRecoveryReady, false);
  assert.equal(second.mutationCallCount, 0);

  const partial = fakeAws({ initialSuffixes: ['data', 'api'], markers: true });
  const resumed = runExpiredPrereleaseCleanup({
    account: partial.account,
    environmentVariables: executionEnvironment(partial.roleName, now),
    executor: partial.executor,
    now,
    region: partial.region,
    roleArn: `arn:aws:iam::${partial.account}:role/${partial.roleName}`,
  });
  assert.equal(resumed.cleanedGroups[0].resumed, true);
  assert.deepEqual(resumed.cleanedGroups[0].deletionOrder, ['api', 'data']);

  for (const length of [1, 2, 3]) {
    const abandoned = fakeAws({ initialSuffixes: STACK_SUFFIXES.slice(0, length) });
    const cleaned = runExpiredPrereleaseCleanup({
      account: abandoned.account,
      environmentVariables: executionEnvironment(abandoned.roleName, now),
      executor: abandoned.executor,
      now,
      region: abandoned.region,
      roleArn: `arn:aws:iam::${abandoned.account}:role/${abandoned.roleName}`,
    });
    assert.deepEqual(
      cleaned.cleanedGroups[0].deletionOrder,
      STACK_SUFFIXES.slice(0, length).reverse(),
    );
    assert.equal(cleaned.durableRecoveryReady, false);
    assert.equal(cleaned.runtimeVerification, 'AWS_PARTIAL_CLEANUP_EXECUTED');
    assert.equal(abandoned.stacks.size, 0);
  }

  const interruptedMarking = fakeAws({ initialSuffixes: ['data', 'api'] });
  interruptedMarking.stacks.get('data').tags = fixtureTags(interruptedMarking.identity, true);
  const markingResumed = runExpiredPrereleaseCleanup({
    account: interruptedMarking.account,
    environmentVariables: executionEnvironment(interruptedMarking.roleName, now),
    executor: interruptedMarking.executor,
    now,
    region: interruptedMarking.region,
    roleArn: `arn:aws:iam::${interruptedMarking.account}:role/${interruptedMarking.roleName}`,
  });
  assert.deepEqual(markingResumed.cleanedGroups[0].deletionOrder, ['api', 'data']);

  for (const subset of [['api'], ['data', 'observability'], ['data', 'api', 'web']]) {
    const impossible = fakeAws({ initialSuffixes: subset });
    assert.throws(
      () =>
        runExpiredPrereleaseCleanup({
          account: impossible.account,
          environmentVariables: executionEnvironment(impossible.roleName, now),
          executor: impossible.executor,
          now,
          region: impossible.region,
          roleArn: `arn:aws:iam::${impossible.account}:role/${impossible.roleName}`,
        }),
      (error) => error?.code === 'E7_CLEANUP_STACK_SUBSET_IMPOSSIBLE',
    );
    assert.equal(
      impossible.calls.filter((args) => ['update-stack', 'delete-stack'].includes(args[1])).length,
      0,
    );
  }

  const transient = fakeAws({ status: 'UPDATE_IN_PROGRESS' });
  assert.throws(
    () =>
      runExpiredPrereleaseCleanup({
        account: transient.account,
        environmentVariables: executionEnvironment(transient.roleName, now),
        executor: transient.executor,
        now,
        region: transient.region,
        roleArn: `arn:aws:iam::${transient.account}:role/${transient.roleName}`,
      }),
    (error) => error?.code === 'E7_CLEANUP_STACK_STATE_AMBIGUOUS',
  );
  assert.equal(
    transient.calls.filter((args) => ['update-stack', 'delete-stack'].includes(args[1])).length,
    0,
  );

  const wrongTrust = fakeAws({
    trustSubject: githubOidcEnvironmentSubject('assessment-prerelease'),
  });
  assert.throws(
    () =>
      runExpiredPrereleaseCleanup({
        account: wrongTrust.account,
        environmentVariables: executionEnvironment(wrongTrust.roleName, now),
        executor: wrongTrust.executor,
        now,
        region: wrongTrust.region,
        roleArn: `arn:aws:iam::${wrongTrust.account}:role/${wrongTrust.roleName}`,
      }),
    (error) => error?.code === 'E7_CLEANUP_ROLE_TRUST_INVALID',
  );
  assert.equal(
    wrongTrust.calls.filter((args) => ['update-stack', 'delete-stack'].includes(args[1])).length,
    0,
  );

  const missingExactExpiry = fakeAws();
  for (const stack of missingExactExpiry.stacks.values()) {
    stack.tags = stack.tags.filter((tag) => tag.Key !== 'CleanupExpiresAtUtc');
  }
  assert.throws(
    () =>
      runExpiredPrereleaseCleanup({
        account: missingExactExpiry.account,
        environmentVariables: executionEnvironment(missingExactExpiry.roleName, now),
        executor: missingExactExpiry.executor,
        now,
        region: missingExactExpiry.region,
        roleArn: `arn:aws:iam::${missingExactExpiry.account}:role/${missingExactExpiry.roleName}`,
      }),
    (error) => error?.code === 'E7_CLEANUP_EXACT_EXPIRY_TAG_INVALID',
  );
  assert.equal(
    missingExactExpiry.calls.filter((args) => ['update-stack', 'delete-stack'].includes(args[1]))
      .length,
    0,
  );

  const candidateOutputMismatch = fakeAws({ outputCandidateSha: '1'.repeat(40) });
  assert.throws(
    () =>
      runExpiredPrereleaseCleanup({
        account: candidateOutputMismatch.account,
        environmentVariables: executionEnvironment(candidateOutputMismatch.roleName, now),
        executor: candidateOutputMismatch.executor,
        now,
        region: candidateOutputMismatch.region,
        roleArn: `arn:aws:iam::${candidateOutputMismatch.account}:role/${candidateOutputMismatch.roleName}`,
      }),
    (error) => error?.code === 'E7_CLEANUP_CANDIDATE_SHA_OUTPUT_MISMATCH',
  );
  assert.equal(
    candidateOutputMismatch.calls.filter((args) =>
      ['update-stack', 'delete-stack'].includes(args[1]),
    ).length,
    0,
  );

  const candidateTagInvalid = fakeAws();
  for (const stack of candidateTagInvalid.stacks.values()) {
    stack.tags = stack.tags.map((tag) =>
      tag.Key === 'CandidateSha' ? { ...tag, Value: 'abcdef0' } : tag,
    );
  }
  assert.throws(
    () =>
      runExpiredPrereleaseCleanup({
        account: candidateTagInvalid.account,
        environmentVariables: executionEnvironment(candidateTagInvalid.roleName, now),
        executor: candidateTagInvalid.executor,
        now,
        region: candidateTagInvalid.region,
        roleArn: `arn:aws:iam::${candidateTagInvalid.account}:role/${candidateTagInvalid.roleName}`,
      }),
    (error) => error?.code === 'E7_CLEANUP_CANDIDATE_SHA_TAG_INVALID',
  );
  assert.equal(
    candidateTagInvalid.calls.filter((args) => ['update-stack', 'delete-stack'].includes(args[1]))
      .length,
    0,
  );

  const candidateBindingInvalid = fakeAws({ outputCandidateSha: '1'.repeat(40) });
  for (const stack of candidateBindingInvalid.stacks.values()) {
    stack.tags = stack.tags.map((tag) =>
      tag.Key === 'CandidateSha' ? { ...tag, Value: '1'.repeat(40) } : tag,
    );
  }
  assert.throws(
    () =>
      runExpiredPrereleaseCleanup({
        account: candidateBindingInvalid.account,
        environmentVariables: executionEnvironment(candidateBindingInvalid.roleName, now),
        executor: candidateBindingInvalid.executor,
        now,
        region: candidateBindingInvalid.region,
        roleArn: `arn:aws:iam::${candidateBindingInvalid.account}:role/${candidateBindingInvalid.roleName}`,
      }),
    (error) => error?.code === 'E7_CLEANUP_RELEASE_CANDIDATE_BINDING_INVALID',
  );
  assert.equal(
    candidateBindingInvalid.calls.filter((args) =>
      ['update-stack', 'delete-stack'].includes(args[1]),
    ).length,
    0,
  );

  const moveExpiryAfterNow = (fixture) => {
    for (const stack of fixture.stacks.values()) {
      stack.tags = stack.tags.map((tag) =>
        tag.Key === 'ExpiresOn'
          ? { ...tag, Value: '2026-08-17' }
          : tag.Key === 'CleanupExpiresAtUtc'
            ? { ...tag, Value: '2026-08-17T18:00:00.000Z' }
            : tag,
      );
    }
  };

  const nonexpired = fakeAws();
  moveExpiryAfterNow(nonexpired);
  const waiting = runExpiredPrereleaseCleanup({
    account: nonexpired.account,
    environmentVariables: executionEnvironment(nonexpired.roleName, now),
    executor: nonexpired.executor,
    now,
    region: nonexpired.region,
    roleArn: `arn:aws:iam::${nonexpired.account}:role/${nonexpired.roleName}`,
  });
  assert.equal(waiting.decision, 'NO_EXPIRED_PRERELEASES');
  assert.equal(waiting.pendingGroups, 1);
  assert.equal(waiting.mutationCallCount, 0);

  for (const length of [1, 2, 3]) {
    const incompletePending = fakeAws({ initialSuffixes: STACK_SUFFIXES.slice(0, length) });
    moveExpiryAfterNow(incompletePending);
    const pending = runExpiredPrereleaseCleanup({
      account: incompletePending.account,
      environmentVariables: executionEnvironment(incompletePending.roleName, now),
      executor: incompletePending.executor,
      now,
      region: incompletePending.region,
      roleArn: `arn:aws:iam::${incompletePending.account}:role/${incompletePending.roleName}`,
    });
    assert.equal(pending.pendingGroups, 1);
    assert.equal(pending.mutationCallCount, 0);
    assert.equal(incompletePending.stacks.size, length);
  }

  let dryRunCalls = 0;
  const dry = dryRunEvidence({ now });
  dryRunCalls += dry.awsCallCount;
  assert.equal(dry.durableRecoveryReady, false);
  assert.equal(dryRunCalls, 0);

  return 29;
};

const cli = () => {
  const command = process.argv[2];
  if (command === 'self-test') {
    if (process.argv.length !== 3) fail('E7_CLEANUP_CLI_ARGUMENT_SET_INVALID');
    const canaries = selfTestPrereleaseCleanupRecovery();
    process.stdout.write(
      `prerelease cleanup recovery self-test: PASS (${canaries} canaries; 0 AWS calls)\n`,
    );
    return;
  }
  const flags = parseFlags(process.argv.slice(3));
  if (command === 'dry-run') {
    assertExactFlags(flags, ['evidence'], ['evidence']);
    const evidence = dryRunEvidence();
    writeEvidence(flags.evidence, evidence);
    process.stdout.write(
      `${JSON.stringify({ status: evidence.status, decision: evidence.decision })}\n`,
    );
    return;
  }
  if (command !== 'run') fail('E7_CLEANUP_CLI_COMMAND_INVALID');
  assertExactFlags(
    flags,
    ['execute', 'account', 'region', 'role-arn', 'evidence'],
    ['execute', 'account', 'region', 'role-arn', 'evidence'],
  );
  let evidence;
  try {
    evidence = runExpiredPrereleaseCleanup({
      account: flags.account,
      region: flags.region,
      roleArn: flags['role-arn'],
    });
    writeEvidence(flags.evidence, evidence);
  } catch (error) {
    const code =
      error instanceof PrereleaseCleanupError ? error.code : 'E7_CLEANUP_UNEXPECTED_FAILURE';
    const failed = {
      schemaVersion: 1,
      stage: 7,
      kind: 'expired-prerelease-cleanup-recovery',
      generatedAtUtc: new Date().toISOString(),
      status: 'FAIL',
      decision: 'FAIL_CLOSED',
      failureCode: code,
      durableRecoveryReady: false,
      runtimeVerification: 'FAILED',
      containsSensitiveData: false,
    };
    try {
      writeEvidence(flags.evidence, failed);
    } catch {
      // The original fail-closed error remains authoritative.
    }
    throw error;
  }
  process.stdout.write(
    `${JSON.stringify({
      status: evidence.status,
      decision: evidence.decision,
      cleanedGroups: evidence.cleanedGroups.length,
    })}\n`,
  );
};

if (
  process.argv[1] !== undefined &&
  path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  try {
    cli();
  } catch (error) {
    const code =
      error instanceof PrereleaseCleanupError ? error.code : 'E7_CLEANUP_UNEXPECTED_FAILURE';
    process.stderr.write(`prerelease cleanup recovery: ${code}\n`);
    process.exitCode = 1;
  }
}
