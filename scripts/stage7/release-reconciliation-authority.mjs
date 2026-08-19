import { Buffer } from 'node:buffer';
import { createHash } from 'node:crypto';

import { parseStrictJsonSource } from '../stage6/strict-json.mjs';
import { assertSanitizedArtifactText } from '../stage6/lib/artifact-sanitizer.mjs';
import { canonicalJson, objectSha256, validateStage7Config } from './core.mjs';
import {
  STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT,
  createReleaseReconciliationIntent,
  validateReleaseReconciliationIntent,
  validateReleaseReconciliationSource,
} from './release-reconciliation.mjs';
import { validateReleaseJournalRoleEffectivePermissions } from './release-successor-iam-authority.mjs';

const SHA256 = /^[0-9a-f]{64}$/u;
const ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/([A-Za-z0-9+=,.@_/-]{1,512})$/u;
const POLICY_ARN = /^arn:aws:iam::([0-9]{12}):policy\/([A-Za-z0-9+=,.@_/-]{1,512})$/u;
const AWS_REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]?$/u;
const MAX_SOURCE_BYTES = 32 * 1024 * 1024;
const INTENT_SOURCE_LAYOUT = STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.filter(
  ({ sourceType }) => sourceType !== 'NESTED_JSON',
);
const PREVIOUS_PROJECTION_PATHS = Object.freeze([
  'previous-release-manifest.json',
  'previous-source-provenance.json',
  'previous-target-compatibility.json',
  'previous-final-disable-provenance.json',
  'previous-api-contract-evidence.json',
  'previous-pending-evidence.json',
  'previous-smoke-evidence.json',
]);
const RECOVERY_ROLE_AUTHORITY_KEYS = Object.freeze([
  'reconciliationRecoveryRoleArn',
  'reconciliationRecoveryPermissionsBoundaryArn',
  'reconciliationRecoveryRoleEffectivePermissionsRawSha256',
  'reconciliationRecoveryRoleEffectivePermissionsCanonicalSha256',
  'reconciliationRecoveryRoleEffectivePermissionsSha256',
  'reconciliationRecoveryRoleEffectivePolicyProjectionSha256',
]);
const VALIDATED_INTENT_AUTHORITIES = new WeakSet();
export const RELEASE_RECONCILIATION_INTENT_AUTHORITY_CLI_FLAGS = Object.freeze(
  [
    ['config', 'config'],
    ['releaseMetadata', 'release-metadata'],
    ['candidateManifest', 'candidate-manifest'],
    ['releasePlan', 'release-plan'],
    ['approvedDiff', 'approved-diff'],
    ['rawDiff', 'raw-diff'],
    ['githubEnvironmentApproval', 'github-environment-approval'],
    ['approval', 'approval'],
    ['awsAuth', 'aws-auth'],
    ['journalRoleEffectivePermissions', 'journal-role-effective-permissions'],
    ['activation', 'activation'],
    ['webDeployment', 'web-deployment'],
    ['candidateRecord', 'candidate-record'],
    ['externalAuthorization', 'external-authorization'],
    ['previousReleaseManifest', 'previous-release-manifest'],
    ['previousSourceProvenance', 'previous-source-provenance'],
    ['previousTargetCompatibility', 'previous-target-compatibility'],
    ['previousFinalDisableProvenance', 'previous-final-disable-provenance'],
    ['previousApiContractEvidence', 'previous-api-contract-evidence'],
    ['previousPendingEvidence', 'previous-pending-evidence'],
    ['previousSmokeEvidence', 'previous-smoke-evidence'],
    ['previousReleaseProjectionIndex', 'previous-release-projection-index'],
  ].map((entry) => Object.freeze(entry)),
);
export const RELEASE_RECONCILIATION_INTENT_AUTHORITY_SOURCE_KEYS = Object.freeze([
  'intentSource',
  'sources',
  'githubIdentity',
]);

export class Stage7ReleaseReconciliationAuthorityError extends Error {
  constructor(code, options = undefined) {
    super(code, options);
    this.name = 'Stage7ReleaseReconciliationAuthorityError';
    this.code = code;
  }
}

const fail = (code, cause = undefined) => {
  throw new Stage7ReleaseReconciliationAuthorityError(
    code,
    cause === undefined ? undefined : { cause },
  );
};
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const exactKeys = (value, keys) =>
  object(value) && Object.keys(value).toSorted().join('\0') === [...keys].toSorted().join('\0');
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const withoutDigest = (value, field) => {
  const body = { ...value };
  delete body[field];
  return body;
};
const parseDocument = (source, code) => {
  const bytes = Buffer.isBuffer(source) ? Buffer.from(source) : Buffer.from(source ?? '', 'utf8');
  if (bytes.length < 2 || bytes.length > MAX_SOURCE_BYTES) fail(code);
  try {
    return { value: parseStrictJsonSource(bytes, { scanForbiddenData: false }), bytes };
  } catch (error) {
    fail(code, error);
  }
};
const jsonBodyDigestValid = (value, field) =>
  SHA256.test(value?.[field] ?? '') && value[field] === objectSha256(withoutDigest(value, field));
const recoveryRoleAuthority = (value) =>
  Object.fromEntries(RECOVERY_ROLE_AUTHORITY_KEYS.map((key) => [key, value?.[key]]));

const createValidatedIntent = ({ sources, githubIdentity }) => {
  if (
    !exactKeys(
      sources,
      INTENT_SOURCE_LAYOUT.map(({ label }) => label),
    ) ||
    !exactKeys(githubIdentity, [
      'repository',
      'workflowRef',
      'ref',
      'runId',
      'runAttempt',
      'candidateSha',
    ])
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_SOURCE_SET_INVALID');
  }
  const documents = {};
  const bindingsByLabel = new Map();
  for (const descriptor of INTENT_SOURCE_LAYOUT) {
    const bytes = Buffer.isBuffer(sources[descriptor.label])
      ? Buffer.from(sources[descriptor.label])
      : Buffer.from(sources[descriptor.label] ?? '', 'utf8');
    if (bytes.length < 1 || bytes.length > MAX_SOURCE_BYTES) {
      fail('E7_RELEASE_RECONCILIATION_INTENT_SOURCE_INVALID');
    }
    try {
      assertSanitizedArtifactText(`stage7-${descriptor.path}`, bytes.toString('utf8'));
    } catch (error) {
      fail(
        'E7_RELEASE_RECONCILIATION_INTENT_SOURCE_UNSAFE',
        new Error(`unsafe intent source: ${descriptor.label}`, { cause: error }),
      );
    }
    if (descriptor.sourceType === 'RAW_TEXT') {
      bindingsByLabel.set(descriptor.label, {
        ...descriptor,
        rawSha256: sha256(bytes),
        canonicalSha256: null,
        bytes: bytes.length,
      });
      continue;
    }
    const document = parseDocument(bytes, 'E7_RELEASE_RECONCILIATION_INTENT_JSON_SOURCE_INVALID');
    if (!object(document.value) || document.value.containsSensitiveData !== false) {
      fail('E7_RELEASE_RECONCILIATION_INTENT_JSON_SOURCE_INVALID');
    }
    documents[descriptor.label] = document.value;
    bindingsByLabel.set(descriptor.label, {
      ...descriptor,
      rawSha256: sha256(document.bytes),
      canonicalSha256: objectSha256(document.value),
      bytes: document.bytes.length,
    });
  }
  const metadata = documents.releaseMetadata;
  const freeze = documents.candidateManifest;
  try {
    validateStage7Config(documents.config);
  } catch (error) {
    fail('E7_RELEASE_RECONCILIATION_CONFIG_INVALID', error);
  }
  const source = validateReleaseReconciliationSource({
    repository: githubIdentity.repository,
    workflowPath: '.github/workflows/release.yml',
    ref: githubIdentity.ref,
    runId: String(metadata?.releaseRunId ?? ''),
    runAttempt: metadata?.releaseRunAttempt,
    candidateSha: freeze?.candidateSha,
    releaseId: freeze?.releaseId,
    releaseTag: freeze?.releaseTag,
    configSha256: freeze?.configSha256,
  });
  if (
    githubIdentity.workflowRef !== `${source.repository}/${source.workflowPath}@${source.ref}` ||
    githubIdentity.runId !== source.runId ||
    githubIdentity.runAttempt !== source.runAttempt ||
    githubIdentity.candidateSha !== source.candidateSha ||
    metadata?.schemaVersion !== 1 ||
    metadata?.stage !== 7 ||
    metadata?.kind !== 'RELEASE_ENTRY_PREFLIGHT' ||
    metadata?.status !== 'PASS' ||
    metadata?.scope !== 'full' ||
    metadata?.candidateSha !== source.candidateSha ||
    metadata?.releaseId !== source.releaseId ||
    metadata?.configSha256 !== source.configSha256 ||
    metadata?.decision !== 'READY_FOR_BUILD_FREEZE' ||
    freeze?.schemaVersion !== 1 ||
    freeze?.stage !== 7 ||
    freeze?.kind !== 'BUILD_ONCE_FREEZE' ||
    freeze?.authorizationScope !== 'FULL_RELEASE_VERSIONED_UPDATE' ||
    freeze?.releaseMode !== 'VERSIONED_UPDATE' ||
    freeze?.updateReleaseSupported !== true ||
    !jsonBodyDigestValid(freeze, 'manifestSha256') ||
    objectSha256(documents.config) !== source.configSha256
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_IDENTITY_INVALID');
  }
  for (const value of Object.values(documents)) {
    if (
      (value.candidateSha !== undefined && value.candidateSha !== source.candidateSha) ||
      (value.releaseId !== undefined && value.releaseId !== source.releaseId) ||
      (value.releaseTag !== undefined &&
        value.releaseTag !== null &&
        value.releaseTag !== source.releaseTag) ||
      (value.configSha256 !== undefined && value.configSha256 !== source.configSha256)
    ) {
      fail('E7_RELEASE_RECONCILIATION_INTENT_IDENTITY_INVALID');
    }
  }
  const iam = documents.awsAuth?.iamEffectivePermissions;
  const configAws = documents.config?.aws;
  const journalPermissions = documents.journalRoleEffectivePermissions;
  const recoveryRole = ROLE_ARN.exec(documents.awsAuth?.reconciliationRecoveryRoleArn ?? '');
  const recoveryBoundary = POLICY_ARN.exec(
    documents.awsAuth?.reconciliationRecoveryPermissionsBoundaryArn ?? '',
  );
  try {
    validateReleaseJournalRoleEffectivePermissions(journalPermissions);
  } catch (error) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_JOURNAL_ROLE_INVALID', error);
  }
  if (
    !object(iam) ||
    iam.kind !== 'IAM_EFFECTIVE_PERMISSIONS' ||
    iam.status !== 'PASS' ||
    iam.scope !== 'full' ||
    iam.candidateSha !== source.candidateSha ||
    iam.releaseId !== source.releaseId ||
    iam.manifestSha256 !== freeze.manifestSha256 ||
    iam.configSha256 !== source.configSha256 ||
    !SHA256.test(iam.bindingSha256 ?? '') ||
    !object(configAws) ||
    !/^[0-9]{12}$/u.test(configAws.accountId ?? '') ||
    !AWS_REGION.test(configAws.region ?? '') ||
    !object(configAws.roles) ||
    ROLE_ARN.exec(configAws.roles.rollbackRoleArn ?? '')?.[1] !== configAws.accountId ||
    journalPermissions.awsRegion !== configAws.region ||
    ROLE_ARN.exec(journalPermissions.role?.arn ?? '')?.[1] !== configAws.accountId ||
    journalPermissions.role.arn === configAws.roles.rollbackRoleArn ||
    recoveryRole?.[1] !== configAws.accountId ||
    recoveryBoundary?.[1] !== configAws.accountId ||
    recoveryRole?.[0] === journalPermissions.role.arn ||
    Object.values(configAws.roles).includes(recoveryRole?.[0]) ||
    !RECOVERY_ROLE_AUTHORITY_KEYS.slice(2).every((key) =>
      SHA256.test(documents.awsAuth?.[key] ?? ''),
    ) ||
    iam.roles?.rollbackRoleArn?.roleArnSha256 !== sha256(configAws.roles.rollbackRoleArn) ||
    !SHA256.test(iam.roles?.rollbackRoleArn?.permissionSetSha256 ?? '')
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_IAM_BINDING_INVALID');
  }
  const iamBytes = Buffer.from(canonicalJson(iam), 'utf8');
  const iamDescriptor = STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.find(
    ({ label }) => label === 'iamEffectivePermissionsBinding',
  );
  bindingsByLabel.set(iamDescriptor.label, {
    ...iamDescriptor,
    rawSha256: null,
    canonicalSha256: objectSha256(iam),
    bytes: iamBytes.length,
  });
  const rawDiffBinding = bindingsByLabel.get('rawDiff');
  const awsAuthBinding = bindingsByLabel.get('awsAuth');
  const approvedDiffBinding = bindingsByLabel.get('approvedDiff');
  const approvalBinding = bindingsByLabel.get('approval');
  const webBinding = bindingsByLabel.get('webDeployment');
  const approval = documents.approval;
  const candidate = documents.candidateRecord;
  const previous = documents.previousReleaseManifest;
  if (
    documents.githubEnvironmentApproval?.iamReviewedDiffSha256 !== rawDiffBinding.rawSha256 ||
    documents.externalAuthorization?.stage7ConfigSha256 !== source.configSha256 ||
    approval?.approvedPlanSha256 !== approvedDiffBinding.rawSha256 ||
    approval?.approvedDiffSha256 !== rawDiffBinding.rawSha256 ||
    approval?.iamEffectivePermissionsBindingSha256 !== iam.bindingSha256 ||
    approval?.iamEffectivePermissionsEvidenceSha256 !== awsAuthBinding.rawSha256 ||
    approval?.journalRoleEffectivePermissionsRawSha256 !==
      documents.awsAuth.journalRoleEffectivePermissionsRawSha256 ||
    approval?.journalRoleEffectivePermissionsSha256 !==
      documents.awsAuth.journalRoleEffectivePermissionsSha256 ||
    canonicalJson(recoveryRoleAuthority(approval)) !==
      canonicalJson(recoveryRoleAuthority(documents.awsAuth)) ||
    approval?.freezeManifestSha256 !== freeze.manifestSha256 ||
    !jsonBodyDigestValid(candidate, 'recordSha256') ||
    candidate?.target?.candidateSha !== source.candidateSha ||
    candidate?.target?.releaseId !== source.releaseId ||
    candidate?.previousReleaseManifestSha256 !== previous?.manifestSha256 ||
    candidate?.approvalSha256 !== approvalBinding.rawSha256 ||
    candidate?.planSha256 !== approvedDiffBinding.rawSha256 ||
    candidate?.deploymentEvidenceSha256 !== webBinding.rawSha256
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_APPROVAL_CHAIN_INVALID');
  }
  const previousIndex = documents.previousReleaseProjectionIndex;
  if (
    !jsonBodyDigestValid(previousIndex, 'projectionIndexSha256') ||
    previousIndex?.identity?.targetCandidateSha !== source.candidateSha ||
    previousIndex?.identity?.targetReleaseId !== source.releaseId ||
    previousIndex?.identity?.targetFreezeManifestSha256 !== freeze.manifestSha256 ||
    !Array.isArray(previousIndex?.files) ||
    previousIndex.files.length !== PREVIOUS_PROJECTION_PATHS.length ||
    previousIndex.files.some((entry, index) => {
      const expectedPath = PREVIOUS_PROJECTION_PATHS[index];
      const binding = [...bindingsByLabel.values()].find(({ path }) => path === expectedPath);
      return (
        !exactKeys(entry, ['path', 'sha256', 'bytes']) ||
        entry?.path !== expectedPath ||
        entry?.sha256 !== binding?.rawSha256 ||
        entry?.bytes !== binding?.bytes
      );
    })
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_PREVIOUS_PROJECTION_INVALID');
  }
  const bindings = STAGE7_RELEASE_RECONCILIATION_INTENT_LAYOUT.map(({ label }) =>
    bindingsByLabel.get(label),
  );
  const journalBinding = bindingsByLabel.get('journalRoleEffectivePermissions');
  if (
    documents.awsAuth.journalRoleEffectivePermissionsRawSha256 !== journalBinding.rawSha256 ||
    documents.awsAuth.journalRoleEffectivePermissionsSha256 !==
      journalPermissions.effectivePermissionsSha256
  ) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_JOURNAL_ROLE_BINDING_INVALID');
  }
  return createReleaseReconciliationIntent({
    source,
    authority: {
      accountId: configAws.accountId,
      region: configAws.region,
      rollbackRoleArn: configAws.roles.rollbackRoleArn,
      journalRoleArn: journalPermissions.role.arn,
      rollbackPermissionSetSha256: iam.roles.rollbackRoleArn.permissionSetSha256,
      journalEffectivePermissionsSha256: journalPermissions.effectivePermissionsSha256,
    },
    bindings,
  });
};

export const createReleaseReconciliationIntentFromSources = (options) =>
  createValidatedIntent(options);

export const validateReleaseReconciliationIntentAuthority = (options) => {
  if (!exactKeys(options, RELEASE_RECONCILIATION_INTENT_AUTHORITY_SOURCE_KEYS)) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_AUTHORITY_SOURCE_SET_INVALID');
  }
  const { intentSource, sources, githubIdentity } = options;
  const expected = createValidatedIntent({ sources, githubIdentity });
  const supplied = parseDocument(
    intentSource,
    'E7_RELEASE_RECONCILIATION_INTENT_AUTHORITY_SOURCE_INVALID',
  );
  let intent;
  try {
    intent = validateReleaseReconciliationIntent(supplied.value);
  } catch (error) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_AUTHORITY_SOURCE_INVALID', error);
  }
  if (canonicalJson(intent) !== canonicalJson(expected)) {
    fail('E7_RELEASE_RECONCILIATION_INTENT_AUTHORITY_MISMATCH');
  }
  const authority = Object.freeze({
    intent,
    source: Object.freeze({ ...intent.source }),
    authority: Object.freeze({ ...intent.authority }),
    rawSha256: sha256(supplied.bytes),
    canonicalSha256: objectSha256(intent),
    bytes: supplied.bytes.length,
    sourceSetSha256: objectSha256(
      Object.fromEntries(
        INTENT_SOURCE_LAYOUT.map(({ label }) => {
          const bytes = Buffer.isBuffer(sources[label])
            ? Buffer.from(sources[label])
            : Buffer.from(sources[label] ?? '', 'utf8');
          return [label, { rawSha256: sha256(bytes), bytes: bytes.length }];
        }),
      ),
    ),
  });
  VALIDATED_INTENT_AUTHORITIES.add(authority);
  return authority;
};

export const isValidatedReleaseReconciliationIntentAuthority = (value) =>
  object(value) && VALIDATED_INTENT_AUTHORITIES.has(value);
