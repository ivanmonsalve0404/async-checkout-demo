/* global structuredClone */
import assert from 'node:assert/strict';
import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { canonicalJson, objectSha256 } from './core.mjs';
import { IAM_EFFECTIVE_PERMISSIONS_CONTRACT_VERSION } from './iam-effective-permissions.mjs';

const REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
const SHA256 = /^[0-9a-f]{64}$/u;
const SHA = /^[0-9a-f]{40}$/u;
const RELEASE_ID = /^rel-[0-9]{8}-[0-9]{4}-[0-9a-f]{7}$/u;
const ROLE_ARN = /^arn:aws:iam::[0-9]{12}:role\/[A-Za-z0-9+=,.@_/-]{1,512}$/u;
const POLICY_ARN = /^arn:aws:iam::[0-9]{12}:policy\/[A-Za-z0-9+=,.@_/-]{1,512}$/u;
const POLICY_VERSION = /^v[1-9][0-9]{0,3}$/u;
const POLICY_NAME = /^[\w+=,.@-]{1,128}$/u;
const AWS_REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$/u;
const MAX_DOCUMENT_BYTES = 4 * 1024 * 1024;
const SOURCE_OPERATIONS = Object.freeze([
  'GET_ROLE',
  'LIST_ROLE_POLICIES',
  'GET_ROLE_POLICY',
  'LIST_ATTACHED_ROLE_POLICIES',
  'GET_POLICY',
  'GET_POLICY_VERSION',
  'GET_BOUNDARY_POLICY',
  'GET_BOUNDARY_POLICY_VERSION',
]);
const JOURNAL_ROLE_ALLOWED_ACTIONS = Object.freeze(
  [
    'iam:GetPolicy',
    'iam:GetPolicyVersion',
    'iam:GetRole',
    'iam:GetRolePolicy',
    'iam:ListAttachedRolePolicies',
    'iam:ListRolePolicies',
    'ssm:DeleteParameter',
    'ssm:GetParameter',
    'ssm:GetParametersByPath',
    'ssm:PutParameter',
    'sts:GetCallerIdentity',
  ]
    .map((action) => action.toLowerCase())
    .toSorted(),
);
const JOURNAL_ROLE_PERMISSION_PROFILE = Object.freeze({
  contractVersion: IAM_EFFECTIVE_PERMISSIONS_CONTRACT_VERSION,
  profileKey: 'journalCleanupRoleArn',
  capability: 'RELEASE_SUCCESSOR_FINALIZATION_AND_JOURNAL_CLEANUP_ONLY',
  allowedActions: JOURNAL_ROLE_ALLOWED_ACTIONS,
  resourceRules: Object.freeze({
    iamRoleReads: 'EXACT_SELF_ROLE_ARN',
    iamPolicyReads: 'EXACT_ATTACHED_AND_BOUNDARY_POLICY_ARNS',
    finalizationReadWrite: 'EXACT_STAGE7_RELEASE_FINALIZATION_ROOT',
    fenceReadWrite: 'EXACT_STAGE7_RELEASE_FENCE_ROOT',
    journalReadWriteListDelete: 'EXACT_STAGE7_ROLLBACK_ROOT',
    putCondition: 'StringEquals:ssm:Overwrite=false',
    callerIdentity: 'GLOBAL_STS_GET_CALLER_IDENTITY_ONLY',
  }),
});
const JOURNAL_ROLE_PERMISSION_PROFILE_SHA256 = objectSha256(JOURNAL_ROLE_PERMISSION_PROFILE);

export const RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_BASENAME =
  'stage7-release-journal-role-effective-permissions.json';
export const RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_KIND =
  'STAGE7_RELEASE_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS';

export class Stage7ReleaseSuccessorIamAuthorityError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseSuccessorIamAuthorityError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseSuccessorIamAuthorityError(
    code,
    cause === undefined ? undefined : { cause },
  );
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const utc = (value) => {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return false;
  return new Date(value).toISOString() === value;
};
const withoutDigest = (value) => {
  const body = { ...value };
  delete body.effectivePermissionsSha256;
  return body;
};
const stableProjection = (value) => ({
  repository: value.repository,
  awsRegion: value.awsRegion,
  role: value.role,
  permissionProfile: value.permissionProfile,
  inlinePolicies: value.inlinePolicies,
  attachedPolicies: value.attachedPolicies,
  permissionsBoundary: value.permissionsBoundary,
});
const strictDocument = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_DOCUMENT_BYTES) fail(code);
  let value;
  try {
    value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
  } catch (error) {
    fail(code, error);
  }
  if (!object(value) || value.containsSensitiveData !== false) fail(code);
  return {
    value,
    bytes,
    rawSha256: sha256(bytes),
    canonicalSha256: objectSha256(value),
  };
};
const strictExternalDocument = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_DOCUMENT_BYTES) fail(code);
  let value;
  try {
    value = parseStrictJsonSource(bytes, { scanForbiddenData: false });
  } catch (error) {
    fail(code, error);
  }
  if (!object(value)) fail(code);
  return { value, bytes, rawSha256: sha256(bytes), canonicalSha256: objectSha256(value) };
};
const canonicalClone = (value) => JSON.parse(canonicalJson(value));
const decodePolicyDocumentOnce = (value) => {
  if (object(value)) return value;
  if (typeof value !== 'string' || value.length < 2) {
    fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_SOURCE_INVALID');
  }
  let decoded;
  try {
    decoded = decodeURIComponent(value);
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_SOURCE_INVALID', error);
  }
  if (decoded === value) fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_SOURCE_INVALID');
  let parsed;
  try {
    parsed = JSON.parse(decoded);
  } catch (error) {
    fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_SOURCE_INVALID', error);
  }
  if (!object(parsed)) fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_SOURCE_INVALID');
  return parsed;
};
const normalizeProjectedPolicyDocument = (source) => {
  const value = decodePolicyDocumentOnce(source);
  if (
    !exactKeys(value, ['Version', 'Statement']) ||
    value.Version !== '2012-10-17' ||
    !Array.isArray(value.Statement) ||
    value.Statement.length < 1
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_SOURCE_INVALID');
  }
  const statements = value.Statement.map((statement) => {
    if (
      !object(statement) ||
      !Object.keys(statement).every((key) =>
        ['Sid', 'Effect', 'Action', 'Resource', 'Condition'].includes(key),
      ) ||
      !['Allow', 'Deny'].includes(statement.Effect)
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_SOURCE_INVALID');
    }
    const actions = asArray(statement.Action)
      .map((action) => (typeof action === 'string' ? action.toLowerCase() : ''))
      .toSorted();
    const resources = asArray(statement.Resource).toSorted();
    if (
      actions.length < 1 ||
      new Set(actions).size !== actions.length ||
      actions.some((action) => action.length < 1) ||
      resources.length < 1 ||
      new Set(resources).size !== resources.length ||
      resources.some((resource) => typeof resource !== 'string' || resource.length < 1)
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_SOURCE_INVALID');
    }
    return {
      ...(statement.Sid === undefined ? {} : { Sid: statement.Sid }),
      Effect: statement.Effect,
      Action: actions.length === 1 ? actions[0] : actions,
      Resource: resources.length === 1 ? resources[0] : resources,
      ...(statement.Condition === undefined
        ? {}
        : { Condition: canonicalClone(statement.Condition) }),
    };
  }).toSorted((left, right) => canonicalJson(left).localeCompare(canonicalJson(right)));
  return { Version: value.Version, Statement: statements };
};
const normalizeProjectedTrustPolicy = (value) => {
  if (!object(value)) fail('E7_RELEASE_SUCCESSOR_IAM_TRUST_SOURCE_INVALID');
  const normalized = canonicalClone(value);
  const subjects =
    normalized?.Statement?.[0]?.Condition?.StringEquals?.[
      'token.actions.githubusercontent.com:sub'
    ];
  if (Array.isArray(subjects)) {
    normalized.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:sub'] =
      subjects.toSorted();
  }
  return normalized;
};
const asArray = (value) => (Array.isArray(value) ? value : [value]);
const permissionResources = ({ roleArn, policyArns, awsRegion }) => {
  const accountId = roleArn.split(':')[4];
  const rootArn = (root) =>
    `arn:aws:ssm:${awsRegion}:${accountId}:parameter/checkout/stage7/${root}/*`;
  return Object.freeze({
    'iam:getrole': Object.freeze([roleArn]),
    'iam:getrolepolicy': Object.freeze([roleArn]),
    'iam:listattachedrolepolicies': Object.freeze([roleArn]),
    'iam:listrolepolicies': Object.freeze([roleArn]),
    'iam:getpolicy': Object.freeze([...policyArns].toSorted()),
    'iam:getpolicyversion': Object.freeze([...policyArns].toSorted()),
    'ssm:getparameter': Object.freeze(
      [rootArn('release-finalization'), rootArn('release-fence'), rootArn('rollback')].toSorted(),
    ),
    'ssm:putparameter': Object.freeze(
      [rootArn('release-finalization'), rootArn('release-fence'), rootArn('rollback')].toSorted(),
    ),
    'ssm:getparametersbypath': Object.freeze([rootArn('rollback')]),
    'ssm:deleteparameter': Object.freeze([rootArn('rollback')]),
    'sts:getcalleridentity': Object.freeze(['*']),
  });
};
const requiredCondition = (action) =>
  action === 'ssm:putparameter' ? { StringEquals: { 'ssm:Overwrite': 'false' } } : undefined;
const validatePolicyDocument = (value, { roleArn, policyArns, awsRegion }) => {
  const normalizedValue = normalizeProjectedPolicyDocument(value);
  if (
    canonicalJson(value) !== canonicalJson(normalizedValue) ||
    !object(value) ||
    value.Version !== '2012-10-17' ||
    !Array.isArray(value.Statement) ||
    value.Statement.length < 1 ||
    value.Statement.some(
      (statement) =>
        !object(statement) ||
        !Object.keys(statement).every((key) =>
          ['Sid', 'Effect', 'Action', 'Resource', 'Condition'].includes(key),
        ) ||
        (statement.Sid !== undefined &&
          (typeof statement.Sid !== 'string' || statement.Sid.length < 1)) ||
        !['Allow', 'Deny'].includes(statement.Effect) ||
        statement.Action === undefined ||
        statement.Resource === undefined,
    )
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_DOCUMENT_INVALID');
  }
  const allowedResources = permissionResources({ roleArn, policyArns, awsRegion });
  const allows = [];
  const deniedActions = new Set();
  for (const statement of value.Statement) {
    const actions = asArray(statement.Action).map((action) =>
      typeof action === 'string' ? action.toLowerCase() : '',
    );
    const resources = asArray(statement.Resource).toSorted();
    if (
      actions.length < 1 ||
      new Set(actions).size !== actions.length ||
      actions.some(
        (action) => !JOURNAL_ROLE_ALLOWED_ACTIONS.includes(action) || action.includes('*'),
      ) ||
      resources.length < 1 ||
      new Set(resources).size !== resources.length ||
      resources.some((resource) => typeof resource !== 'string' || resource.length < 1) ||
      actions.some((action) =>
        resources.some((resource) => !allowedResources[action]?.includes(resource)),
      ) ||
      actions.some(
        (action) => canonicalJson(statement.Condition) !== canonicalJson(requiredCondition(action)),
      )
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_POLICY_OUTSIDE_PROFILE');
    }
    for (const action of actions) {
      if (statement.Effect === 'Deny') {
        deniedActions.add(action);
      } else {
        allows.push({ action, resources });
      }
    }
  }
  return { allows, deniedActions };
};

const validateEffectivePermissionSet = ({ identityPolicies, boundaryPolicy, context }) => {
  const expectedResources = permissionResources(context);
  const identityAllows = identityPolicies.flatMap(({ allows }) => allows);
  const identityDenied = new Set(
    identityPolicies.flatMap(({ deniedActions }) => [...deniedActions]),
  );
  const effectiveActions = [];
  for (const action of JOURNAL_ROLE_ALLOWED_ACTIONS) {
    const identityResources = new Set(
      identityAllows.filter((grant) => grant.action === action).flatMap((grant) => grant.resources),
    );
    const boundaryResources = new Set(
      boundaryPolicy.allows
        .filter((grant) => grant.action === action)
        .flatMap((grant) => grant.resources),
    );
    const effectiveResources = [...identityResources]
      .filter((resource) => boundaryResources.has(resource))
      .toSorted();
    if (
      identityDenied.has(action) ||
      boundaryPolicy.deniedActions.has(action) ||
      canonicalJson(effectiveResources) !== canonicalJson(expectedResources[action])
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_ACTION_SET_INCOMPLETE');
    }
    effectiveActions.push(action);
  }
  if (canonicalJson(effectiveActions) !== canonicalJson(JOURNAL_ROLE_ALLOWED_ACTIONS)) {
    fail('E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_ACTION_SET_INCOMPLETE');
  }
};
const validateSourceBinding = (value) =>
  exactKeys(value, ['operation', 'target', 'rawSha256', 'canonicalSha256', 'bytes']) &&
  SOURCE_OPERATIONS.includes(value.operation) &&
  typeof value.target === 'string' &&
  value.target.length >= 1 &&
  value.target.length <= 1024 &&
  SHA256.test(value.rawSha256 ?? '') &&
  SHA256.test(value.canonicalSha256 ?? '') &&
  Number.isSafeInteger(value.bytes) &&
  value.bytes >= 2 &&
  value.bytes <= MAX_DOCUMENT_BYTES;

const validateTrust = (role, accountId) => {
  const trust = role.trustPolicy;
  const statement = trust?.Statement?.[0];
  const host = 'token.actions.githubusercontent.com';
  const subjects = [
    'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release',
    'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-reconciliation-recovery',
    'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-successor-post-success',
  ].toSorted();
  if (
    !exactKeys(trust, ['Version', 'Statement']) ||
    trust.Version !== '2012-10-17' ||
    !Array.isArray(trust.Statement) ||
    trust.Statement.length !== 1 ||
    !exactKeys(statement, ['Effect', 'Principal', 'Action', 'Condition']) ||
    statement.Effect !== 'Allow' ||
    statement.Action !== 'sts:AssumeRoleWithWebIdentity' ||
    !exactKeys(statement.Principal, ['Federated']) ||
    statement.Principal.Federated !== `arn:aws:iam::${accountId}:oidc-provider/${host}` ||
    !exactKeys(statement.Condition, ['StringEquals']) ||
    !exactKeys(statement.Condition.StringEquals, [`${host}:aud`, `${host}:sub`]) ||
    statement.Condition.StringEquals[`${host}:aud`] !== 'sts.amazonaws.com' ||
    !Array.isArray(statement.Condition.StringEquals[`${host}:sub`]) ||
    statement.Condition.StringEquals[`${host}:sub`].toSorted().join('\0') !== subjects.join('\0')
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_TRUST_INVALID');
  }
};

const sourceBinding = (document, operation, target) => ({
  operation,
  target,
  rawSha256: document.rawSha256,
  canonicalSha256: document.canonicalSha256,
  bytes: document.bytes.length,
});

const parseListPages = ({ pages, field, operation, targetPrefix, entryValidator }) => {
  if (!Array.isArray(pages) || pages.length < 1 || pages.length > 100) {
    fail('E7_RELEASE_SUCCESSOR_IAM_LIST_PAGE_SET_INVALID');
  }
  const entries = [];
  const bindings = [];
  const seenTokens = new Set();
  let expectedToken = null;
  for (const [index, page] of pages.entries()) {
    if (
      !exactKeys(page, ['requestToken', 'source']) ||
      page.requestToken !== expectedToken ||
      (!Buffer.isBuffer(page.source) && typeof page.source !== 'string')
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_LIST_PAGE_SET_INVALID');
    }
    const document = strictExternalDocument(
      page.source,
      'E7_RELEASE_SUCCESSOR_IAM_LIST_RESPONSE_INVALID',
    );
    const response = document.value;
    if (
      !Object.keys(response).every((key) => [field, 'NextToken'].includes(key)) ||
      !Array.isArray(response[field]) ||
      response[field].some((entry) => !entryValidator(entry))
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_LIST_RESPONSE_INVALID');
    }
    entries.push(...response[field]);
    bindings.push(sourceBinding(document, operation, `${targetPrefix}#page=${index + 1}`));
    const nextToken = response.NextToken;
    if (nextToken === undefined) {
      if (index !== pages.length - 1) fail('E7_RELEASE_SUCCESSOR_IAM_LIST_PAGE_SET_INVALID');
      expectedToken = null;
      continue;
    }
    if (
      typeof nextToken !== 'string' ||
      nextToken.length < 1 ||
      seenTokens.has(nextToken) ||
      index === pages.length - 1
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_LIST_PAGINATION_INVALID');
    }
    seenTokens.add(nextToken);
    expectedToken = nextToken;
  }
  return { entries, bindings };
};

const exactMappedSources = (sources, expectedKeys, keyName, code) => {
  if (
    !Array.isArray(sources) ||
    sources.some(
      (entry) =>
        !exactKeys(entry, [keyName, 'source']) ||
        typeof entry[keyName] !== 'string' ||
        (!Buffer.isBuffer(entry.source) && typeof entry.source !== 'string'),
    ) ||
    new Set(sources.map((entry) => entry[keyName])).size !== sources.length ||
    sources
      .map((entry) => entry[keyName])
      .toSorted()
      .join('\0') !== [...expectedKeys].toSorted().join('\0')
  ) {
    fail(code);
  }
  return new Map(sources.map((entry) => [entry[keyName], entry.source]));
};

export const createReleaseJournalRoleEffectivePermissions = ({
  expectedRoleArn,
  expectedPermissionsBoundaryArn,
  awsRegion,
  rawSources,
}) => {
  if (
    !ROLE_ARN.test(expectedRoleArn ?? '') ||
    !POLICY_ARN.test(expectedPermissionsBoundaryArn ?? '') ||
    expectedRoleArn.split(':')[4] !== expectedPermissionsBoundaryArn.split(':')[4] ||
    !AWS_REGION.test(awsRegion ?? '') ||
    !exactKeys(rawSources, [
      'getRoleSource',
      'listRolePoliciesPages',
      'getRolePolicySources',
      'listAttachedRolePoliciesPages',
      'getPolicySources',
      'getPolicyVersionSources',
    ])
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_CAPTURE_INPUT_INVALID');
  }
  const getRole = strictExternalDocument(
    rawSources.getRoleSource,
    'E7_RELEASE_SUCCESSOR_IAM_GET_ROLE_RESPONSE_INVALID',
  );
  const role = getRole.value.Role;
  const expectedRoleName = expectedRoleArn.split('/').at(-1);
  if (
    !object(role) ||
    role.Arn !== expectedRoleArn ||
    role.RoleName !== expectedRoleName ||
    role.PermissionsBoundary?.PermissionsBoundaryType !== 'Policy' ||
    role.PermissionsBoundary?.PermissionsBoundaryArn !== expectedPermissionsBoundaryArn ||
    typeof role.Path !== 'string' ||
    typeof role.RoleId !== 'string' ||
    Number.isNaN(Date.parse(role.CreateDate)) ||
    role.MaxSessionDuration !== 3600
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_GET_ROLE_RESPONSE_INVALID');
  }
  const inlineList = parseListPages({
    pages: rawSources.listRolePoliciesPages,
    field: 'PolicyNames',
    operation: 'LIST_ROLE_POLICIES',
    targetPrefix: expectedRoleArn,
    entryValidator: (name) => POLICY_NAME.test(name ?? ''),
  });
  const inlineNames = inlineList.entries.toSorted();
  if (new Set(inlineNames).size !== inlineNames.length) {
    fail('E7_RELEASE_SUCCESSOR_IAM_INLINE_POLICY_SET_INVALID');
  }
  const inlineSources = exactMappedSources(
    rawSources.getRolePolicySources,
    inlineNames,
    'policyName',
    'E7_RELEASE_SUCCESSOR_IAM_INLINE_POLICY_SET_INVALID',
  );
  const sourceBindings = [
    sourceBinding(getRole, 'GET_ROLE', expectedRoleArn),
    ...inlineList.bindings,
  ];
  const inlinePolicies = inlineNames.map((policyName) => {
    const document = strictExternalDocument(
      inlineSources.get(policyName),
      'E7_RELEASE_SUCCESSOR_IAM_GET_ROLE_POLICY_RESPONSE_INVALID',
    );
    const response = document.value;
    if (
      !exactKeys(response, ['RoleName', 'PolicyName', 'PolicyDocument']) ||
      response.RoleName !== expectedRoleName ||
      response.PolicyName !== policyName
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_GET_ROLE_POLICY_RESPONSE_INVALID');
    }
    const policyDocument = normalizeProjectedPolicyDocument(response.PolicyDocument);
    sourceBindings.push(
      sourceBinding(document, 'GET_ROLE_POLICY', `${expectedRoleArn}#inline=${policyName}`),
    );
    return {
      policyName,
      policyDocument,
      policyDocumentSha256: objectSha256(policyDocument),
    };
  });
  const attachedList = parseListPages({
    pages: rawSources.listAttachedRolePoliciesPages,
    field: 'AttachedPolicies',
    operation: 'LIST_ATTACHED_ROLE_POLICIES',
    targetPrefix: expectedRoleArn,
    entryValidator: (entry) =>
      object(entry) &&
      exactKeys(entry, ['PolicyName', 'PolicyArn']) &&
      POLICY_NAME.test(entry.PolicyName ?? '') &&
      POLICY_ARN.test(entry.PolicyArn ?? '') &&
      entry.PolicyArn.split(':')[4] === expectedRoleArn.split(':')[4] &&
      entry.PolicyArn.split('/').at(-1) === entry.PolicyName,
  });
  const attachedEntries = attachedList.entries.toSorted((left, right) =>
    left.PolicyArn.localeCompare(right.PolicyArn),
  );
  const attachedArns = attachedEntries.map(({ PolicyArn }) => PolicyArn);
  if (
    attachedArns.length !== 0 ||
    new Set(attachedArns).size !== attachedArns.length ||
    attachedArns.includes(expectedPermissionsBoundaryArn)
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_ATTACHED_POLICY_SET_INVALID');
  }
  sourceBindings.push(...attachedList.bindings);
  const managedArns = [...attachedArns, expectedPermissionsBoundaryArn].toSorted();
  const policySources = exactMappedSources(
    rawSources.getPolicySources,
    managedArns,
    'policyArn',
    'E7_RELEASE_SUCCESSOR_IAM_MANAGED_POLICY_SET_INVALID',
  );
  const versionSources = exactMappedSources(
    rawSources.getPolicyVersionSources,
    managedArns,
    'policyArn',
    'E7_RELEASE_SUCCESSOR_IAM_MANAGED_POLICY_SET_INVALID',
  );
  const managed = new Map();
  for (const policyArn of managedArns) {
    const metadata = strictExternalDocument(
      policySources.get(policyArn),
      'E7_RELEASE_SUCCESSOR_IAM_GET_POLICY_RESPONSE_INVALID',
    );
    const policy = metadata.value.Policy;
    if (
      !object(policy) ||
      policy.Arn !== policyArn ||
      policy.PolicyName !== policyArn.split('/').at(-1) ||
      !POLICY_VERSION.test(policy.DefaultVersionId ?? '')
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_GET_POLICY_RESPONSE_INVALID');
    }
    const version = strictExternalDocument(
      versionSources.get(policyArn),
      'E7_RELEASE_SUCCESSOR_IAM_GET_POLICY_VERSION_RESPONSE_INVALID',
    );
    if (
      version.value?.PolicyVersion?.VersionId !== policy.DefaultVersionId ||
      version.value.PolicyVersion.IsDefaultVersion !== true
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_GET_POLICY_VERSION_RESPONSE_INVALID');
    }
    const policyDocument = normalizeProjectedPolicyDocument(version.value.PolicyVersion.Document);
    const boundary = policyArn === expectedPermissionsBoundaryArn;
    sourceBindings.push(
      sourceBinding(metadata, boundary ? 'GET_BOUNDARY_POLICY' : 'GET_POLICY', policyArn),
      sourceBinding(
        version,
        boundary ? 'GET_BOUNDARY_POLICY_VERSION' : 'GET_POLICY_VERSION',
        `${policyArn}#version=${policy.DefaultVersionId}`,
      ),
    );
    managed.set(policyArn, {
      policyArn,
      defaultVersionId: policy.DefaultVersionId,
      policyDocument,
      policyDocumentSha256: objectSha256(policyDocument),
    });
  }
  const trustPolicy = normalizeProjectedTrustPolicy(
    decodePolicyDocumentOnce(role.AssumeRolePolicyDocument),
  );
  const body = {
    schemaVersion: 1,
    stage: 7,
    kind: RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_KIND,
    status: 'PASS',
    repository: REPOSITORY,
    awsRegion,
    role: {
      arn: expectedRoleArn,
      path: role.Path,
      name: role.RoleName,
      id: role.RoleId,
      createdAtUtc: new Date(role.CreateDate).toISOString(),
      maxSessionDuration: role.MaxSessionDuration,
      trustPolicy,
      trustPolicySha256: objectSha256(trustPolicy),
    },
    permissionProfile: {
      ...JOURNAL_ROLE_PERMISSION_PROFILE,
      profileSha256: JOURNAL_ROLE_PERMISSION_PROFILE_SHA256,
    },
    inlinePolicies,
    attachedPolicies: attachedArns.map((policyArn) => managed.get(policyArn)),
    permissionsBoundary: managed.get(expectedPermissionsBoundaryArn),
    sourceBindings: sourceBindings.toSorted((left, right) => {
      const leftKey = `${left.operation}\0${left.target}`;
      const rightKey = `${right.operation}\0${right.target}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    }),
    containsSensitiveData: false,
  };
  const projected = {
    ...body,
    effectivePolicyProjectionSha256: objectSha256(stableProjection(body)),
  };
  const value = {
    ...projected,
    effectivePermissionsSha256: objectSha256(projected),
  };
  validateReleaseJournalRoleEffectivePermissions(value, {
    roleArn: expectedRoleArn,
    permissionsBoundaryArn: expectedPermissionsBoundaryArn,
  });
  const roleAudit = {
    Path: value.role.path,
    RoleName: value.role.name,
    RoleId: value.role.id,
    Arn: value.role.arn,
    CreateDate: value.role.createdAtUtc,
    MaxSessionDuration: value.role.maxSessionDuration,
    PermissionsBoundary: {
      PermissionsBoundaryType: 'Policy',
      PermissionsBoundaryArn: value.permissionsBoundary.policyArn,
    },
    AssumeRolePolicyDocument: value.role.trustPolicy,
  };
  return {
    value,
    bytes: Buffer.from(`${JSON.stringify(value)}\n`, 'utf8'),
    getRoleSource: Buffer.from(getRole.bytes),
    roleAuditBytes: Buffer.from(`${JSON.stringify(roleAudit)}\n`, 'utf8'),
    sourceBindingCount: value.sourceBindings.length,
  };
};

export const captureReleaseJournalRoleEffectivePermissions = ({
  expectedRoleArn,
  expectedPermissionsBoundaryArn,
  awsRegion,
  callAwsRaw,
}) => {
  const roleName = expectedRoleArn?.split('/').at(-1);
  if (
    typeof callAwsRaw !== 'function' ||
    !ROLE_ARN.test(expectedRoleArn ?? '') ||
    !POLICY_ARN.test(expectedPermissionsBoundaryArn ?? '') ||
    expectedRoleArn.split(':')[4] !== expectedPermissionsBoundaryArn.split(':')[4] ||
    !AWS_REGION.test(awsRegion ?? '') ||
    !POLICY_NAME.test(roleName ?? '')
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_CAPTURE_INPUT_INVALID');
  }
  const call = (arguments_) => {
    const source = callAwsRaw(arguments_);
    if (!Buffer.isBuffer(source) && typeof source !== 'string') {
      fail('E7_RELEASE_SUCCESSOR_IAM_CAPTURE_RESPONSE_INVALID');
    }
    return Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source, 'utf8');
  };
  const getRoleSource = call(['iam', 'get-role', '--role-name', roleName]);
  const capturePages = (operation, field) => {
    const pages = [];
    const seen = new Set();
    let requestToken = null;
    for (let index = 0; index < 100; index += 1) {
      const arguments_ = [
        'iam',
        operation,
        '--role-name',
        roleName,
        '--page-size',
        '100',
        '--max-items',
        '100',
      ];
      if (requestToken !== null) arguments_.push('--starting-token', requestToken);
      const source = call(arguments_);
      const response = strictExternalDocument(
        source,
        'E7_RELEASE_SUCCESSOR_IAM_LIST_RESPONSE_INVALID',
      ).value;
      if (!Array.isArray(response[field])) {
        fail('E7_RELEASE_SUCCESSOR_IAM_LIST_RESPONSE_INVALID');
      }
      pages.push({ requestToken, source });
      if (response.NextToken === undefined) return pages;
      if (
        typeof response.NextToken !== 'string' ||
        response.NextToken.length < 1 ||
        seen.has(response.NextToken)
      ) {
        fail('E7_RELEASE_SUCCESSOR_IAM_LIST_PAGINATION_INVALID');
      }
      seen.add(response.NextToken);
      requestToken = response.NextToken;
    }
    fail('E7_RELEASE_SUCCESSOR_IAM_LIST_PAGE_LIMIT');
  };
  const listRolePoliciesPages = capturePages('list-role-policies', 'PolicyNames');
  const listAttachedRolePoliciesPages = capturePages(
    'list-attached-role-policies',
    'AttachedPolicies',
  );
  const inlineNames = listRolePoliciesPages
    .flatMap(
      ({ source }) =>
        strictExternalDocument(source, 'E7_RELEASE_SUCCESSOR_IAM_LIST_RESPONSE_INVALID').value
          .PolicyNames,
    )
    .toSorted();
  const attachedArns = listAttachedRolePoliciesPages
    .flatMap(
      ({ source }) =>
        strictExternalDocument(source, 'E7_RELEASE_SUCCESSOR_IAM_LIST_RESPONSE_INVALID').value
          .AttachedPolicies,
    )
    .map(({ PolicyArn }) => PolicyArn)
    .toSorted();
  if (attachedArns.length !== 0) {
    fail('E7_RELEASE_SUCCESSOR_IAM_ATTACHED_POLICY_SET_INVALID');
  }
  const getRolePolicySources = inlineNames.map((policyName) => ({
    policyName,
    source: call(['iam', 'get-role-policy', '--role-name', roleName, '--policy-name', policyName]),
  }));
  const managedArns = [...attachedArns, expectedPermissionsBoundaryArn].toSorted();
  const getPolicySources = managedArns.map((policyArn) => ({
    policyArn,
    source: call(['iam', 'get-policy', '--policy-arn', policyArn]),
  }));
  const getPolicyVersionSources = getPolicySources.map(({ policyArn, source }) => {
    const versionId = strictExternalDocument(
      source,
      'E7_RELEASE_SUCCESSOR_IAM_GET_POLICY_RESPONSE_INVALID',
    ).value?.Policy?.DefaultVersionId;
    if (!POLICY_VERSION.test(versionId ?? '')) {
      fail('E7_RELEASE_SUCCESSOR_IAM_GET_POLICY_RESPONSE_INVALID');
    }
    return {
      policyArn,
      source: call([
        'iam',
        'get-policy-version',
        '--policy-arn',
        policyArn,
        '--version-id',
        versionId,
      ]),
    };
  });
  return createReleaseJournalRoleEffectivePermissions({
    expectedRoleArn,
    expectedPermissionsBoundaryArn,
    awsRegion,
    rawSources: {
      getRoleSource,
      listRolePoliciesPages,
      getRolePolicySources,
      listAttachedRolePoliciesPages,
      getPolicySources,
      getPolicyVersionSources,
    },
  });
};

export const validateReleaseJournalRoleEffectivePermissions = (value, expected = {}) => {
  if (
    !exactKeys(value, [
      'schemaVersion',
      'stage',
      'kind',
      'status',
      'repository',
      'awsRegion',
      'role',
      'permissionProfile',
      'inlinePolicies',
      'attachedPolicies',
      'permissionsBoundary',
      'sourceBindings',
      'containsSensitiveData',
      'effectivePolicyProjectionSha256',
      'effectivePermissionsSha256',
    ]) ||
    value.schemaVersion !== 1 ||
    value.stage !== 7 ||
    value.kind !== RELEASE_SUCCESSOR_JOURNAL_ROLE_EFFECTIVE_PERMISSIONS_KIND ||
    value.status !== 'PASS' ||
    value.repository !== REPOSITORY ||
    !AWS_REGION.test(value.awsRegion ?? '') ||
    !exactKeys(value.permissionProfile, [
      'contractVersion',
      'profileKey',
      'capability',
      'allowedActions',
      'resourceRules',
      'profileSha256',
    ]) ||
    value.permissionProfile.contractVersion !== IAM_EFFECTIVE_PERMISSIONS_CONTRACT_VERSION ||
    value.permissionProfile.profileKey !== JOURNAL_ROLE_PERMISSION_PROFILE.profileKey ||
    value.permissionProfile.capability !== JOURNAL_ROLE_PERMISSION_PROFILE.capability ||
    canonicalJson(value.permissionProfile.allowedActions) !==
      canonicalJson(JOURNAL_ROLE_ALLOWED_ACTIONS) ||
    canonicalJson(value.permissionProfile.resourceRules) !==
      canonicalJson(JOURNAL_ROLE_PERMISSION_PROFILE.resourceRules) ||
    value.permissionProfile.profileSha256 !== JOURNAL_ROLE_PERMISSION_PROFILE_SHA256 ||
    !exactKeys(value.role, [
      'arn',
      'path',
      'name',
      'id',
      'createdAtUtc',
      'maxSessionDuration',
      'trustPolicy',
      'trustPolicySha256',
    ]) ||
    !ROLE_ARN.test(value.role.arn ?? '') ||
    typeof value.role.path !== 'string' ||
    !value.role.path.startsWith('/') ||
    !value.role.path.endsWith('/') ||
    !POLICY_NAME.test(value.role.name ?? '') ||
    value.role.arn.split('/').at(-1) !== value.role.name ||
    typeof value.role.id !== 'string' ||
    value.role.id.length < 16 ||
    !utc(value.role.createdAtUtc) ||
    value.role.maxSessionDuration !== 3600 ||
    value.role.trustPolicySha256 !== objectSha256(value.role.trustPolicy) ||
    !Array.isArray(value.inlinePolicies) ||
    !Array.isArray(value.attachedPolicies) ||
    value.attachedPolicies.length !== 0 ||
    !exactKeys(value.permissionsBoundary, [
      'policyArn',
      'defaultVersionId',
      'policyDocument',
      'policyDocumentSha256',
    ]) ||
    !POLICY_ARN.test(value.permissionsBoundary.policyArn ?? '') ||
    !POLICY_VERSION.test(value.permissionsBoundary.defaultVersionId ?? '') ||
    value.permissionsBoundary.policyDocumentSha256 !==
      objectSha256(value.permissionsBoundary.policyDocument) ||
    !Array.isArray(value.sourceBindings) ||
    value.sourceBindings.length < 5 ||
    value.sourceBindings.some((binding) => !validateSourceBinding(binding)) ||
    new Set(value.sourceBindings.map(({ operation, target }) => `${operation}\0${target}`)).size !==
      value.sourceBindings.length ||
    value.sourceBindings.map(({ operation, target }) => `${operation}\0${target}`).join('\n') !==
      value.sourceBindings
        .map(({ operation, target }) => `${operation}\0${target}`)
        .toSorted()
        .join('\n') ||
    value.containsSensitiveData !== false ||
    value.effectivePolicyProjectionSha256 !== objectSha256(stableProjection(value)) ||
    value.effectivePermissionsSha256 !== objectSha256(withoutDigest(value)) ||
    (expected.roleArn !== undefined && value.role.arn !== expected.roleArn) ||
    (expected.permissionsBoundaryArn !== undefined &&
      value.permissionsBoundary.policyArn !== expected.permissionsBoundaryArn) ||
    (expected.effectivePermissionsSha256 !== undefined &&
      value.effectivePermissionsSha256 !== expected.effectivePermissionsSha256)
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_PERMISSIONS_INVALID');
  }
  const accountId = value.role.arn.split(':')[4];
  validateTrust(value.role, accountId);
  const policyArns = [
    value.permissionsBoundary.policyArn,
    ...value.attachedPolicies.map(({ policyArn }) => policyArn),
  ].toSorted();
  const policyContext = {
    roleArn: value.role.arn,
    policyArns,
    awsRegion: value.awsRegion,
  };
  const identityPolicies = [];
  for (const [index, policy] of value.inlinePolicies.entries()) {
    if (
      !exactKeys(policy, ['policyName', 'policyDocument', 'policyDocumentSha256']) ||
      !POLICY_NAME.test(policy.policyName ?? '') ||
      policy.policyDocumentSha256 !== objectSha256(policy.policyDocument) ||
      (index > 0 && value.inlinePolicies[index - 1].policyName >= policy.policyName)
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_INLINE_POLICY_INVALID');
    }
    identityPolicies.push(validatePolicyDocument(policy.policyDocument, policyContext));
  }
  for (const [index, policy] of value.attachedPolicies.entries()) {
    if (
      !exactKeys(policy, [
        'policyArn',
        'defaultVersionId',
        'policyDocument',
        'policyDocumentSha256',
      ]) ||
      !POLICY_ARN.test(policy.policyArn ?? '') ||
      !POLICY_VERSION.test(policy.defaultVersionId ?? '') ||
      policy.policyDocumentSha256 !== objectSha256(policy.policyDocument) ||
      (index > 0 && value.attachedPolicies[index - 1].policyArn >= policy.policyArn)
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_ATTACHED_POLICY_INVALID');
    }
    identityPolicies.push(validatePolicyDocument(policy.policyDocument, policyContext));
  }
  if (identityPolicies.length < 1) {
    fail('E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_ACTION_SET_INCOMPLETE');
  }
  const boundaryPolicy = validatePolicyDocument(
    value.permissionsBoundary.policyDocument,
    policyContext,
  );
  validateEffectivePermissionSet({ identityPolicies, boundaryPolicy, context: policyContext });
  const requiredOperations = new Set([
    'GET_ROLE',
    'LIST_ROLE_POLICIES',
    'LIST_ATTACHED_ROLE_POLICIES',
    'GET_BOUNDARY_POLICY',
    'GET_BOUNDARY_POLICY_VERSION',
  ]);
  if (value.inlinePolicies.length > 0) requiredOperations.add('GET_ROLE_POLICY');
  if (value.attachedPolicies.length > 0) {
    requiredOperations.add('GET_POLICY');
    requiredOperations.add('GET_POLICY_VERSION');
  }
  const observedOperations = new Set(value.sourceBindings.map(({ operation }) => operation));
  if ([...requiredOperations].some((operation) => !observedOperations.has(operation))) {
    fail('E7_RELEASE_SUCCESSOR_IAM_AUDIT_SOURCE_SET_INCOMPLETE');
  }
  const expectedBindingIdentities = new Set([
    `GET_ROLE\0${value.role.arn}`,
    ...value.inlinePolicies.map(
      ({ policyName }) => `GET_ROLE_POLICY\0${value.role.arn}#inline=${policyName}`,
    ),
    ...value.attachedPolicies.flatMap(({ policyArn, defaultVersionId }) => [
      `GET_POLICY\0${policyArn}`,
      `GET_POLICY_VERSION\0${policyArn}#version=${defaultVersionId}`,
    ]),
    `GET_BOUNDARY_POLICY\0${value.permissionsBoundary.policyArn}`,
    `GET_BOUNDARY_POLICY_VERSION\0${value.permissionsBoundary.policyArn}#version=${value.permissionsBoundary.defaultVersionId}`,
  ]);
  for (const operation of ['LIST_ROLE_POLICIES', 'LIST_ATTACHED_ROLE_POLICIES']) {
    const pages = value.sourceBindings.filter((binding) => binding.operation === operation);
    if (
      pages.length < 1 ||
      pages.some((binding, index) => binding.target !== `${value.role.arn}#page=${index + 1}`)
    ) {
      fail('E7_RELEASE_SUCCESSOR_IAM_AUDIT_SOURCE_SET_INCOMPLETE');
    }
    for (const binding of pages) expectedBindingIdentities.add(`${operation}\0${binding.target}`);
  }
  const observedBindingIdentities = value.sourceBindings.map(
    ({ operation, target }) => `${operation}\0${target}`,
  );
  if (
    expectedBindingIdentities.size !== observedBindingIdentities.length ||
    observedBindingIdentities.some((identity) => !expectedBindingIdentities.has(identity))
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_AUDIT_SOURCE_SET_INCOMPLETE');
  }
  return value;
};

export const parseReleaseJournalRoleEffectivePermissionsSource = (source, expected = {}) => {
  const document = strictDocument(
    source,
    'E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_PERMISSIONS_SOURCE_INVALID',
  );
  validateReleaseJournalRoleEffectivePermissions(document.value, expected);
  return document;
};

export const validateReleaseJournalRoleEffectivePermissionsBinding = ({
  awsAuthSource,
  effectivePermissionsSource,
  expected = {},
}) => {
  const awsAuth = strictDocument(awsAuthSource, 'E7_RELEASE_SUCCESSOR_AWS_AUTH_INVALID');
  const effective = parseReleaseJournalRoleEffectivePermissionsSource(effectivePermissionsSource);
  if (
    awsAuth.value.kind !== 'AWS_READ_ONLY_PREFLIGHT' ||
    awsAuth.value.status !== 'PASS' ||
    awsAuth.value.scope !== 'full' ||
    !SHA.test(awsAuth.value.candidateSha ?? '') ||
    !RELEASE_ID.test(awsAuth.value.releaseId ?? '') ||
    !SHA256.test(awsAuth.value.configSha256 ?? '') ||
    !SHA256.test(awsAuth.value.manifestSha256 ?? '') ||
    (expected.candidateSha !== undefined && awsAuth.value.candidateSha !== expected.candidateSha) ||
    (expected.releaseId !== undefined && awsAuth.value.releaseId !== expected.releaseId) ||
    (expected.configSha256 !== undefined && awsAuth.value.configSha256 !== expected.configSha256) ||
    (expected.manifestSha256 !== undefined &&
      awsAuth.value.manifestSha256 !== expected.manifestSha256) ||
    awsAuth.value.mutationsPerformed !== 0 ||
    awsAuth.value.journalRoleEffectivePermissionsRawSha256 !== effective.rawSha256 ||
    awsAuth.value.journalRoleEffectivePermissionsSha256 !==
      effective.value.effectivePermissionsSha256
  ) {
    fail('E7_RELEASE_SUCCESSOR_AWS_AUTH_EFFECTIVE_PERMISSIONS_BINDING_INVALID');
  }
  return { awsAuth, effectivePermissions: effective };
};

export const compareReleaseJournalRoleEffectivePermissions = ({
  frozenSource,
  liveSource,
  expectedRoleArn,
  expectedPermissionsBoundaryArn,
}) => {
  const frozen = parseReleaseJournalRoleEffectivePermissionsSource(frozenSource, {
    roleArn: expectedRoleArn,
    permissionsBoundaryArn: expectedPermissionsBoundaryArn,
  });
  const live = parseReleaseJournalRoleEffectivePermissionsSource(liveSource, {
    roleArn: expectedRoleArn,
    permissionsBoundaryArn: expectedPermissionsBoundaryArn,
    effectivePolicyProjectionSha256: frozen.value.effectivePolicyProjectionSha256,
  });
  if (
    frozen.value.effectivePolicyProjectionSha256 !== live.value.effectivePolicyProjectionSha256 ||
    canonicalJson(stableProjection(frozen.value)) !== canonicalJson(stableProjection(live.value))
  ) {
    fail('E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_PERMISSIONS_DRIFT');
  }
  return {
    effectivePolicyProjectionSha256: frozen.value.effectivePolicyProjectionSha256,
    frozenEffectivePermissionsSha256: frozen.value.effectivePermissionsSha256,
    liveEffectivePermissionsSha256: live.value.effectivePermissionsSha256,
    frozenRawSha256: frozen.rawSha256,
    liveRawSha256: live.rawSha256,
    liveCanonicalSha256: live.canonicalSha256,
    liveSourceBindingCount: live.value.sourceBindings.length,
  };
};

const createIamCaptureFixture = () => {
  const roleArn = 'arn:aws:iam::123456789012:role/stage7-release-journal-cleanup';
  const boundaryArn = 'arn:aws:iam::123456789012:policy/stage7-release-journal-boundary';
  const resources = permissionResources({
    roleArn,
    policyArns: [boundaryArn],
    awsRegion: 'us-east-1',
  });
  const policyDocument = {
    Version: '2012-10-17',
    Statement: JOURNAL_ROLE_ALLOWED_ACTIONS.map((action) => ({
      Effect: 'Allow',
      Action: action,
      Resource: resources[action],
      ...(requiredCondition(action) === undefined ? {} : { Condition: requiredCondition(action) }),
    })),
  };
  const json = (value) => Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  const trustPolicy = {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: {
          Federated: 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com',
        },
        Action: 'sts:AssumeRoleWithWebIdentity',
        Condition: {
          StringEquals: {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
            'token.actions.githubusercontent.com:sub': [
              'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-reconciliation-recovery',
              'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release-successor-post-success',
              'repo:ivanmonsalve0404/async-checkout-demo:environment:assessment-release',
            ],
          },
        },
      },
    ],
  };
  const getRoleSource = json({
    Role: {
      Path: '/',
      RoleName: 'stage7-release-journal-cleanup',
      RoleId: 'AROAEXAMPLEROLE1234',
      Arn: roleArn,
      CreateDate: '2026-08-18T00:00:00Z',
      MaxSessionDuration: 3600,
      AssumeRolePolicyDocument: trustPolicy,
      PermissionsBoundary: {
        PermissionsBoundaryType: 'Policy',
        PermissionsBoundaryArn: boundaryArn,
      },
      RoleLastUsed: { LastUsedDate: '2026-08-18T01:00:00Z', Region: 'us-east-1' },
    },
  });
  const rawSources = {
    getRoleSource,
    listRolePoliciesPages: [
      { requestToken: null, source: json({ PolicyNames: ['stage7-release-journal'] }) },
    ],
    getRolePolicySources: [
      {
        policyName: 'stage7-release-journal',
        source: json({
          RoleName: 'stage7-release-journal-cleanup',
          PolicyName: 'stage7-release-journal',
          PolicyDocument: policyDocument,
        }),
      },
    ],
    listAttachedRolePoliciesPages: [{ requestToken: null, source: json({ AttachedPolicies: [] }) }],
    getPolicySources: [
      {
        policyArn: boundaryArn,
        source: json({
          Policy: {
            PolicyName: 'stage7-release-journal-boundary',
            Arn: boundaryArn,
            DefaultVersionId: 'v1',
          },
        }),
      },
    ],
    getPolicyVersionSources: [
      {
        policyArn: boundaryArn,
        source: json({
          PolicyVersion: {
            Document: encodeURIComponent(JSON.stringify(policyDocument)),
            VersionId: 'v1',
            IsDefaultVersion: true,
          },
        }),
      },
    ],
  };
  return { roleArn, boundaryArn, policyDocument, rawSources, json };
};

export const createReleaseSuccessorIamAuthoritySelfTestFixture = () => {
  const fixture = createIamCaptureFixture();
  return createReleaseJournalRoleEffectivePermissions({
    expectedRoleArn: fixture.roleArn,
    expectedPermissionsBoundaryArn: fixture.boundaryArn,
    awsRegion: 'us-east-1',
    rawSources: fixture.rawSources,
  }).value;
};

export const selfTestReleaseSuccessorIamAuthority = () => {
  const captureFixture = createIamCaptureFixture();
  const value = createReleaseSuccessorIamAuthoritySelfTestFixture();
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  const result = compareReleaseJournalRoleEffectivePermissions({
    frozenSource: bytes,
    liveSource: bytes,
    expectedRoleArn: value.role.arn,
    expectedPermissionsBoundaryArn: value.permissionsBoundary.policyArn,
  });
  for (const subjects of [
    value.role.trustPolicy.Statement[0].Condition.StringEquals[
      'token.actions.githubusercontent.com:sub'
    ].filter((subject) => !subject.endsWith(':assessment-release-reconciliation-recovery')),
    [
      ...value.role.trustPolicy.Statement[0].Condition.StringEquals[
        'token.actions.githubusercontent.com:sub'
      ],
      'repo:ivanmonsalve0404/async-checkout-demo:environment:*',
    ],
  ]) {
    const invalidTrust = structuredClone(value);
    invalidTrust.role.trustPolicy.Statement[0].Condition.StringEquals[
      'token.actions.githubusercontent.com:sub'
    ] = subjects;
    invalidTrust.role.trustPolicySha256 = objectSha256(invalidTrust.role.trustPolicy);
    invalidTrust.effectivePolicyProjectionSha256 = objectSha256(stableProjection(invalidTrust));
    invalidTrust.effectivePermissionsSha256 = objectSha256(withoutDigest(invalidTrust));
    assert.throws(
      () => validateReleaseJournalRoleEffectivePermissions(invalidTrust),
      (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_TRUST_INVALID',
    );
  }
  const awsAuthBody = {
    kind: 'AWS_READ_ONLY_PREFLIGHT',
    status: 'PASS',
    scope: 'full',
    candidateSha: 'a'.repeat(40),
    releaseId: 'rel-20260817-1100-aaaaaaa',
    configSha256: 'b'.repeat(64),
    manifestSha256: 'c'.repeat(64),
    mutationsPerformed: 0,
    journalRoleEffectivePermissionsRawSha256: sha256(bytes),
    journalRoleEffectivePermissionsSha256: value.effectivePermissionsSha256,
    containsSensitiveData: false,
  };
  validateReleaseJournalRoleEffectivePermissionsBinding({
    awsAuthSource: Buffer.from(`${JSON.stringify(awsAuthBody)}\n`, 'utf8'),
    effectivePermissionsSource: bytes,
    expected: {
      candidateSha: awsAuthBody.candidateSha,
      releaseId: awsAuthBody.releaseId,
      configSha256: awsAuthBody.configSha256,
      manifestSha256: awsAuthBody.manifestSha256,
    },
  });
  assert.throws(
    () =>
      compareReleaseJournalRoleEffectivePermissions({
        frozenSource: bytes,
        liveSource: Buffer.from(`${JSON.stringify({ ...value, status: 'DRIFTED' })}\n`, 'utf8'),
        expectedRoleArn: value.role.arn,
        expectedPermissionsBoundaryArn: value.permissionsBoundary.policyArn,
      }),
    (error) =>
      [
        'E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_PERMISSIONS_INVALID',
        'E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_PERMISSIONS_DRIFT',
      ].includes(error.code),
  );
  assert.throws(
    () =>
      validateReleaseJournalRoleEffectivePermissionsBinding({
        awsAuthSource: Buffer.from(
          `${JSON.stringify({
            ...awsAuthBody,
            journalRoleEffectivePermissionsRawSha256: 'f'.repeat(64),
          })}\n`,
          'utf8',
        ),
        effectivePermissionsSource: bytes,
        expected: {
          candidateSha: awsAuthBody.candidateSha,
          releaseId: awsAuthBody.releaseId,
          configSha256: awsAuthBody.configSha256,
          manifestSha256: awsAuthBody.manifestSha256,
        },
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_AWS_AUTH_EFFECTIVE_PERMISSIONS_BINDING_INVALID',
  );
  assert.throws(
    () => parseReleaseJournalRoleEffectivePermissionsSource(Buffer.from('{}\n', 'utf8')),
    (error) =>
      [
        'E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_PERMISSIONS_SOURCE_INVALID',
        'E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_PERMISSIONS_INVALID',
      ].includes(error.code),
  );
  const wildcardPolicy = structuredClone(value);
  wildcardPolicy.inlinePolicies[0].policyDocument.Statement[0].Resource = '*';
  wildcardPolicy.inlinePolicies[0].policyDocumentSha256 = objectSha256(
    wildcardPolicy.inlinePolicies[0].policyDocument,
  );
  wildcardPolicy.effectivePolicyProjectionSha256 = objectSha256(stableProjection(wildcardPolicy));
  wildcardPolicy.effectivePermissionsSha256 = objectSha256(withoutDigest(wildcardPolicy));
  assert.throws(
    () => validateReleaseJournalRoleEffectivePermissions(wildcardPolicy),
    (error) =>
      [
        'E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_PERMISSIONS_INVALID',
        'E7_RELEASE_SUCCESSOR_IAM_POLICY_DOCUMENT_INVALID',
        'E7_RELEASE_SUCCESSOR_IAM_POLICY_OUTSIDE_PROFILE',
      ].includes(error.code),
  );
  const foreignRolePolicy = structuredClone(value);
  foreignRolePolicy.inlinePolicies[0].policyDocument.Statement[0] = {
    Effect: 'Allow',
    Action: 'iam:GetRole',
    Resource: 'arn:aws:iam::123456789012:role/foreign',
  };
  foreignRolePolicy.inlinePolicies[0].policyDocumentSha256 = objectSha256(
    foreignRolePolicy.inlinePolicies[0].policyDocument,
  );
  foreignRolePolicy.effectivePolicyProjectionSha256 = objectSha256(
    stableProjection(foreignRolePolicy),
  );
  foreignRolePolicy.effectivePermissionsSha256 = objectSha256(withoutDigest(foreignRolePolicy));
  assert.throws(
    () => validateReleaseJournalRoleEffectivePermissions(foreignRolePolicy),
    (error) =>
      [
        'E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_PERMISSIONS_INVALID',
        'E7_RELEASE_SUCCESSOR_IAM_POLICY_DOCUMENT_INVALID',
        'E7_RELEASE_SUCCESSOR_IAM_POLICY_OUTSIDE_PROFILE',
      ].includes(error.code),
  );
  const withoutRequiredAction = (action) => {
    const mutated = structuredClone(value);
    mutated.inlinePolicies[0].policyDocument.Statement =
      mutated.inlinePolicies[0].policyDocument.Statement.filter(
        (statement) => statement.Action !== action,
      );
    mutated.inlinePolicies[0].policyDocumentSha256 = objectSha256(
      mutated.inlinePolicies[0].policyDocument,
    );
    mutated.effectivePolicyProjectionSha256 = objectSha256(stableProjection(mutated));
    mutated.effectivePermissionsSha256 = objectSha256(withoutDigest(mutated));
    return mutated;
  };
  for (const action of ['ssm:deleteparameter', 'ssm:putparameter', 'iam:getrole']) {
    assert.throws(
      () => validateReleaseJournalRoleEffectivePermissions(withoutRequiredAction(action)),
      (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_ACTION_SET_INCOMPLETE',
    );
  }
  for (const action of ['ssm:getparameter', 'ssm:putparameter']) {
    const withoutRollbackJournalAccess = structuredClone(value);
    const statement = withoutRollbackJournalAccess.inlinePolicies[0].policyDocument.Statement.find(
      (candidate) => candidate.Action === action,
    );
    statement.Resource = statement.Resource.filter(
      (resource) => !resource.endsWith('/checkout/stage7/rollback/*'),
    );
    withoutRollbackJournalAccess.inlinePolicies[0].policyDocumentSha256 = objectSha256(
      withoutRollbackJournalAccess.inlinePolicies[0].policyDocument,
    );
    withoutRollbackJournalAccess.effectivePolicyProjectionSha256 = objectSha256(
      stableProjection(withoutRollbackJournalAccess),
    );
    withoutRollbackJournalAccess.effectivePermissionsSha256 = objectSha256(
      withoutDigest(withoutRollbackJournalAccess),
    );
    assert.throws(
      () => validateReleaseJournalRoleEffectivePermissions(withoutRollbackJournalAccess),
      (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_EFFECTIVE_ACTION_SET_INCOMPLETE',
    );
  }
  const captureCalls = [];
  const captured = captureReleaseJournalRoleEffectivePermissions({
    expectedRoleArn: captureFixture.roleArn,
    expectedPermissionsBoundaryArn: captureFixture.boundaryArn,
    awsRegion: 'us-east-1',
    callAwsRaw: (arguments_) => {
      captureCalls.push([...arguments_]);
      const operation = arguments_[1];
      if (operation === 'get-role') return captureFixture.rawSources.getRoleSource;
      if (operation === 'list-role-policies') {
        return captureFixture.rawSources.listRolePoliciesPages[0].source;
      }
      if (operation === 'list-attached-role-policies') {
        return captureFixture.rawSources.listAttachedRolePoliciesPages[0].source;
      }
      if (operation === 'get-role-policy') {
        return captureFixture.rawSources.getRolePolicySources[0].source;
      }
      if (operation === 'get-policy') return captureFixture.rawSources.getPolicySources[0].source;
      if (operation === 'get-policy-version') {
        return captureFixture.rawSources.getPolicyVersionSources[0].source;
      }
      throw new Error('UNEXPECTED_SELF_TEST_OPERATION');
    },
  });
  assert.equal(canonicalJson(captured.value), canonicalJson(value));
  assert.equal(captured.bytes.toString('utf8'), `${JSON.stringify(value)}\n`);
  assert.equal(captured.getRoleSource.equals(captureFixture.rawSources.getRoleSource), true);
  assert.deepEqual(JSON.parse(captured.roleAuditBytes.toString('utf8')), {
    Path: value.role.path,
    RoleName: value.role.name,
    RoleId: value.role.id,
    Arn: value.role.arn,
    CreateDate: value.role.createdAtUtc,
    MaxSessionDuration: value.role.maxSessionDuration,
    PermissionsBoundary: {
      PermissionsBoundaryType: 'Policy',
      PermissionsBoundaryArn: value.permissionsBoundary.policyArn,
    },
    AssumeRolePolicyDocument: value.role.trustPolicy,
  });
  assert.equal(captureCalls.length, value.sourceBindings.length);
  for (const invalid of [
    { awsRegion: 'US-EAST-1', boundaryArn: captureFixture.boundaryArn },
    {
      awsRegion: 'us-east-1',
      boundaryArn: 'arn:aws:iam::210987654321:policy/stage7-release-journal-boundary',
    },
  ]) {
    let adapterCalls = 0;
    assert.throws(
      () =>
        captureReleaseJournalRoleEffectivePermissions({
          expectedRoleArn: captureFixture.roleArn,
          expectedPermissionsBoundaryArn: invalid.boundaryArn,
          awsRegion: invalid.awsRegion,
          callAwsRaw: () => {
            adapterCalls += 1;
            return captureFixture.rawSources.getRoleSource;
          },
        }),
      (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_CAPTURE_INPUT_INVALID',
    );
    assert.equal(adapterCalls, 0);
  }
  const siblingAttachedSources = {
    ...captureFixture.rawSources,
    listAttachedRolePoliciesPages: [
      {
        requestToken: null,
        source: captureFixture.json({
          AttachedPolicies: [
            {
              PolicyName: 'foreign-account-policy',
              PolicyArn: 'arn:aws:iam::210987654321:policy/foreign-account-policy',
            },
          ],
        }),
      },
    ],
  };
  assert.throws(
    () =>
      createReleaseJournalRoleEffectivePermissions({
        expectedRoleArn: captureFixture.roleArn,
        expectedPermissionsBoundaryArn: captureFixture.boundaryArn,
        awsRegion: 'us-east-1',
        rawSources: siblingAttachedSources,
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_LIST_RESPONSE_INVALID',
  );
  const attachedPolicyArn = 'arn:aws:iam::123456789012:policy/forbidden-attached-policy';
  const attachedPolicySources = {
    ...captureFixture.rawSources,
    listAttachedRolePoliciesPages: [
      {
        requestToken: null,
        source: captureFixture.json({
          AttachedPolicies: [
            {
              PolicyName: 'forbidden-attached-policy',
              PolicyArn: attachedPolicyArn,
            },
          ],
        }),
      },
    ],
  };
  assert.throws(
    () =>
      createReleaseJournalRoleEffectivePermissions({
        expectedRoleArn: captureFixture.roleArn,
        expectedPermissionsBoundaryArn: captureFixture.boundaryArn,
        awsRegion: 'us-east-1',
        rawSources: attachedPolicySources,
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_ATTACHED_POLICY_SET_INVALID',
  );
  let attachedCaptureCalls = 0;
  assert.throws(
    () =>
      captureReleaseJournalRoleEffectivePermissions({
        expectedRoleArn: captureFixture.roleArn,
        expectedPermissionsBoundaryArn: captureFixture.boundaryArn,
        awsRegion: 'us-east-1',
        callAwsRaw: (arguments_) => {
          attachedCaptureCalls += 1;
          if (arguments_[1] === 'get-role') return captureFixture.rawSources.getRoleSource;
          if (arguments_[1] === 'list-role-policies') {
            return captureFixture.rawSources.listRolePoliciesPages[0].source;
          }
          if (arguments_[1] === 'list-attached-role-policies') {
            return attachedPolicySources.listAttachedRolePoliciesPages[0].source;
          }
          throw new Error('ATTACHED_POLICY_MUST_FAIL_BEFORE_POLICY_READ');
        },
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_ATTACHED_POLICY_SET_INVALID',
  );
  assert.equal(attachedCaptureCalls, 3);
  assert.throws(
    () =>
      captureReleaseJournalRoleEffectivePermissions({
        expectedRoleArn: captureFixture.roleArn,
        expectedPermissionsBoundaryArn: captureFixture.boundaryArn,
        awsRegion: 'us-east-1',
        callAwsRaw: (arguments_) => {
          if (arguments_[1] === 'get-role') return captureFixture.rawSources.getRoleSource;
          if (arguments_[1] === 'list-role-policies') {
            return captureFixture.json({ PolicyNames: [], NextToken: 'cycle' });
          }
          throw new Error('UNEXPECTED_SELF_TEST_OPERATION');
        },
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_LIST_PAGINATION_INVALID',
  );
  let cappedPage = 0;
  assert.throws(
    () =>
      captureReleaseJournalRoleEffectivePermissions({
        expectedRoleArn: captureFixture.roleArn,
        expectedPermissionsBoundaryArn: captureFixture.boundaryArn,
        awsRegion: 'us-east-1',
        callAwsRaw: (arguments_) => {
          if (arguments_[1] === 'get-role') return captureFixture.rawSources.getRoleSource;
          if (arguments_[1] === 'list-role-policies') {
            cappedPage += 1;
            return captureFixture.json({ PolicyNames: [], NextToken: `page-${cappedPage}` });
          }
          throw new Error('UNEXPECTED_SELF_TEST_OPERATION');
        },
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_LIST_PAGE_LIMIT',
  );
  const mismatchedVersionSources = {
    ...captureFixture.rawSources,
    getPolicyVersionSources: [
      {
        policyArn: captureFixture.boundaryArn,
        source: captureFixture.json({
          PolicyVersion: {
            Document: captureFixture.policyDocument,
            VersionId: 'v2',
            IsDefaultVersion: true,
          },
        }),
      },
    ],
  };
  assert.throws(
    () =>
      createReleaseJournalRoleEffectivePermissions({
        expectedRoleArn: captureFixture.roleArn,
        expectedPermissionsBoundaryArn: captureFixture.boundaryArn,
        awsRegion: 'us-east-1',
        rawSources: mismatchedVersionSources,
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_GET_POLICY_VERSION_RESPONSE_INVALID',
  );
  const doubleEncodedSources = {
    ...captureFixture.rawSources,
    getPolicyVersionSources: [
      {
        policyArn: captureFixture.boundaryArn,
        source: captureFixture.json({
          PolicyVersion: {
            Document: encodeURIComponent(
              encodeURIComponent(JSON.stringify(captureFixture.policyDocument)),
            ),
            VersionId: 'v1',
            IsDefaultVersion: true,
          },
        }),
      },
    ],
  };
  assert.throws(
    () =>
      createReleaseJournalRoleEffectivePermissions({
        expectedRoleArn: captureFixture.roleArn,
        expectedPermissionsBoundaryArn: captureFixture.boundaryArn,
        awsRegion: 'us-east-1',
        rawSources: doubleEncodedSources,
      }),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_POLICY_SOURCE_INVALID',
  );
  const incompleteInventory = structuredClone(value);
  incompleteInventory.sourceBindings = incompleteInventory.sourceBindings.filter(
    ({ operation }) => operation !== 'GET_ROLE',
  );
  incompleteInventory.effectivePermissionsSha256 = objectSha256(withoutDigest(incompleteInventory));
  assert.throws(
    () => validateReleaseJournalRoleEffectivePermissions(incompleteInventory),
    (error) => error.code === 'E7_RELEASE_SUCCESSOR_IAM_AUDIT_SOURCE_SET_INCOMPLETE',
  );
  return {
    status: 'PASS',
    canaries: 23,
    externalRequests: 0,
    effectivePolicyProjectionSha256: result.effectivePolicyProjectionSha256,
  };
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || process.argv[2] !== '--self-test') {
    fail('E7_RELEASE_SUCCESSOR_IAM_AUTHORITY_COMMAND_INVALID');
  }
  process.stdout.write(`${JSON.stringify(selfTestReleaseSuccessorIamAuthority())}\n`);
}
