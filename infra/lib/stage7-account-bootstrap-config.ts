export const STAGE7_ACCOUNT_BOOTSTRAP_REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
export const STAGE7_ACCOUNT_BOOTSTRAP_OIDC_HOST = 'token.actions.githubusercontent.com';
export const STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER = 'hnb659fds';
export const STAGE7_ACCOUNT_BOOTSTRAP_VERSION = 32;
export const STAGE7_ACCOUNT_BOOTSTRAP_ROLE_PATH = '/checkout/';
export const STAGE7_ACCOUNT_BOOTSTRAP_SCOPES = Object.freeze([
  'FULL_RELEASE',
  'PRERELEASE',
] as const);
export type Stage7AccountBootstrapScope = (typeof STAGE7_ACCOUNT_BOOTSTRAP_SCOPES)[number];

export const STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_NAMES = Object.freeze({
  release: Object.freeze({
    readRoleArn: 'stage7-release-read',
    deployRoleArn: 'stage7-release-deploy',
    rollbackRoleArn: 'stage7-release-rollback',
    cleanupRoleArn: 'stage7-release-cleanup',
  }),
  prerelease: Object.freeze({
    readRoleArn: 'stage7-prerelease-read',
    deployRoleArn: 'stage7-prerelease-deploy',
    rollbackRoleArn: 'stage7-prerelease-rollback',
    cleanupRoleArn: 'stage7-prerelease-cleanup',
  }),
  baselineRoleArn: 'stage7-release-baseline',
  cleanupWatchdogRoleArn: 'stage7-prerelease-cleanup-watchdog',
});

export const STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS = Object.freeze([
  'readRoleArn',
  'deployRoleArn',
  'rollbackRoleArn',
  'cleanupRoleArn',
] as const);

export const STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS = Object.freeze([
  'bootstrapDeployRoleArn',
  'bootstrapFilePublishingRoleArn',
  'bootstrapImagePublishingRoleArn',
  'bootstrapLookupRoleArn',
  'bootstrapCloudFormationExecutionRoleArn',
] as const);

export type Stage7PrimaryRoleKey = (typeof STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS)[number];
export type Stage7CdkRoleKey = (typeof STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS)[number];

export interface RawStage7AccountBootstrapConfig {
  readonly accountId?: unknown;
  readonly region?: unknown;
  readonly counterpartRegion?: unknown;
  readonly candidateSha?: unknown;
  readonly prereleaseEnvironment?: unknown;
  readonly originTokenSecretArn?: unknown;
  readonly credentialReferences?: unknown;
  readonly hostedZoneId?: unknown;
  readonly webHostname?: unknown;
  readonly apiHostname?: unknown;
  readonly webCertificateArn?: unknown;
  readonly apiCertificateArn?: unknown;
  readonly activeBootstrapScope?: unknown;
  readonly includeAuxiliaryReadAuthority?: unknown;
}

export interface Stage7RoleSet {
  readonly readRoleArn: string;
  readonly deployRoleArn: string;
  readonly rollbackRoleArn: string;
  readonly cleanupRoleArn: string;
  readonly baselineRoleArn: string;
}

export interface Stage7BoundarySet {
  readonly readRoleArn: string;
  readonly deployRoleArn: string;
  readonly rollbackRoleArn: string;
  readonly cleanupRoleArn: string;
  readonly baselineRoleArn: string;
}

export interface Stage7AccountBootstrapConfig {
  readonly accountId: string;
  readonly region: string;
  readonly counterpartRegion: string;
  readonly candidateSha: string;
  readonly prereleaseEnvironment: string;
  readonly repository: typeof STAGE7_ACCOUNT_BOOTSTRAP_REPOSITORY;
  readonly oidcProviderArn: string;
  readonly originTokenSecretArn: string;
  readonly credentialReferences: readonly string[];
  readonly domain: Readonly<{
    hostedZoneId: string;
    webHostname: string;
    apiHostname: string;
    webCertificateArn: string;
    apiCertificateArn: string;
  }>;
  readonly activeBootstrapScope: Stage7AccountBootstrapScope;
  readonly includeAuxiliaryReadAuthority: boolean;
  readonly roles: Readonly<{
    release: Stage7RoleSet;
    prerelease: Stage7RoleSet;
    cleanupWatchdogRoleArn: string;
  }>;
  readonly boundaries: Readonly<{
    release: Stage7BoundarySet;
    prerelease: Stage7BoundarySet;
    cleanupWatchdogRoleArn: string;
  }>;
  readonly auxiliary: Readonly<{
    journalRoleArn: string;
    journalPermissionsBoundaryArn: string;
    reconciliationRecoveryRoleArn: string;
    reconciliationRecoveryPermissionsBoundaryArn: string;
  }>;
  readonly bootstrap: Readonly<{
    qualifier: typeof STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER;
    version: typeof STAGE7_ACCOUNT_BOOTSTRAP_VERSION;
    assetBucketName: string;
    imageRepositoryName: string;
    versionParameterName: string;
    roles: Readonly<Record<Stage7CdkRoleKey, string>>;
    boundaries: Readonly<Record<Stage7CdkRoleKey, string>>;
  }>;
}

const ACCOUNT_ID = /^[0-9]{12}$/u;
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$/u;
const SHA = /^[0-9a-f]{40}$/u;
const PRERELEASE_ENVIRONMENT = /^assessment-prerelease-[a-z0-9](?:[a-z0-9-]{0,17}[a-z0-9])?$/u;
const HOSTNAME = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/u;
const HOSTED_ZONE_ID = /^Z[A-Z0-9]{5,31}$/u;
const CERTIFICATE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u;
const SECRET_REFERENCE =
  /^arn:aws:(secretsmanager|ssm):([a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*):([0-9]{12}):(?:secret:|parameter\/)([A-Za-z0-9/_+=.@-]{1,512})$/u;
const IAM_RESOURCE_NAME = /^[A-Za-z0-9+=,.@_-]+$/u;
const S3_BUCKET_NAME = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u;
const ECR_REPOSITORY_NAME = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/u;
const SSM_PARAMETER_NAME = /^\/[A-Za-z0-9_./-]+$/u;
const IAM_ROLE_NAME_MAX_LENGTH = 64;
const IAM_POLICY_NAME_MAX_LENGTH = 128;
const S3_BUCKET_NAME_MAX_LENGTH = 63;
const ECR_REPOSITORY_NAME_MAX_LENGTH = 256;
const SSM_PARAMETER_NAME_MAX_LENGTH = 1_011;

const fail = (code: string): never => {
  throw new Error(code);
};

const requiredString = (value: unknown, name: string): string => {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    fail(`E7_ACCOUNT_BOOTSTRAP_${name.toUpperCase()}_INVALID`);
  }
  return value as string;
};

const roleArn = (accountId: string, name: string): string =>
  `arn:aws:iam::${accountId}:role${STAGE7_ACCOUNT_BOOTSTRAP_ROLE_PATH}${name}`;
const boundaryName = (environment: string, roleName: string): string =>
  `checkout-stage7-${environment}-${roleName}-boundary`;
const boundaryArn = (accountId: string, environment: string, roleName: string): string =>
  `arn:aws:iam::${accountId}:policy/${boundaryName(environment, roleName)}`;

const validateDerivedNameQuota = (
  names: readonly string[],
  maximumLength: number,
  code: string,
): void => {
  if (
    names.some(
      (name) => name.length === 0 || name.length > maximumLength || !IAM_RESOURCE_NAME.test(name),
    )
  ) {
    fail(`E7_ACCOUNT_BOOTSTRAP_${code}_QUOTA_EXCEEDED`);
  }
};

const validateDerivedResourceName = (
  name: string,
  maximumLength: number,
  expression: RegExp,
  code: string,
): void => {
  if (name.length === 0 || name.length > maximumLength || !expression.test(name)) {
    fail(`E7_ACCOUNT_BOOTSTRAP_${code}_QUOTA_EXCEEDED`);
  }
};

const primaryRoleSet = (
  accountId: string,
  names: Readonly<Record<Stage7PrimaryRoleKey, string>>,
  baselineRoleName: string,
): Stage7RoleSet =>
  Object.freeze({
    readRoleArn: roleArn(accountId, names.readRoleArn),
    deployRoleArn: roleArn(accountId, names.deployRoleArn),
    rollbackRoleArn: roleArn(accountId, names.rollbackRoleArn),
    cleanupRoleArn: roleArn(accountId, names.cleanupRoleArn),
    baselineRoleArn: roleArn(accountId, baselineRoleName),
  });

const primaryBoundarySet = (
  accountId: string,
  environment: string,
  names: Readonly<Record<Stage7PrimaryRoleKey, string>>,
  baselineRoleName: string,
): Stage7BoundarySet =>
  Object.freeze({
    readRoleArn: boundaryArn(accountId, environment, names.readRoleArn),
    deployRoleArn: boundaryArn(accountId, environment, names.deployRoleArn),
    rollbackRoleArn: boundaryArn(accountId, environment, names.rollbackRoleArn),
    cleanupRoleArn: boundaryArn(accountId, environment, names.cleanupRoleArn),
    baselineRoleArn: boundaryArn(accountId, environment, baselineRoleName),
  });

const cdkRoleNames = (accountId: string, region: string): Record<Stage7CdkRoleKey, string> => {
  const suffix = `${accountId}-${region}`;
  return {
    bootstrapDeployRoleArn: `cdk-${STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER}-deploy-role-${suffix}`,
    bootstrapFilePublishingRoleArn: `cdk-${STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER}-file-publishing-role-${suffix}`,
    bootstrapImagePublishingRoleArn: `cdk-${STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER}-image-publishing-role-${suffix}`,
    bootstrapLookupRoleArn: `cdk-${STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER}-lookup-role-${suffix}`,
    bootstrapCloudFormationExecutionRoleArn: `cdk-${STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER}-cfn-exec-role-${suffix}`,
  };
};

export const parseStage7AccountBootstrapConfig = (
  raw: RawStage7AccountBootstrapConfig,
): Stage7AccountBootstrapConfig => {
  const accountId = requiredString(raw.accountId, 'account_id');
  const region = requiredString(raw.region, 'region');
  const counterpartRegion = requiredString(raw.counterpartRegion, 'counterpart_region');
  const candidateSha = requiredString(raw.candidateSha, 'candidate_sha');
  const prereleaseEnvironment = requiredString(raw.prereleaseEnvironment, 'prerelease_environment');
  const originTokenSecretArn = requiredString(raw.originTokenSecretArn, 'origin_token_secret_arn');
  const hostedZoneId = requiredString(raw.hostedZoneId, 'hosted_zone_id');
  const webHostname = requiredString(raw.webHostname, 'web_hostname');
  const apiHostname = requiredString(raw.apiHostname, 'api_hostname');
  const webCertificateArn = requiredString(raw.webCertificateArn, 'web_certificate_arn');
  const apiCertificateArn = requiredString(raw.apiCertificateArn, 'api_certificate_arn');
  const activeBootstrapScope = requiredString(raw.activeBootstrapScope, 'active_bootstrap_scope');

  if (!ACCOUNT_ID.test(accountId)) fail('E7_ACCOUNT_BOOTSTRAP_ACCOUNT_ID_INVALID');
  if (!REGION.test(region)) fail('E7_ACCOUNT_BOOTSTRAP_REGION_INVALID');
  if (!REGION.test(counterpartRegion) || counterpartRegion === region) {
    fail('E7_ACCOUNT_BOOTSTRAP_COUNTERPART_REGION_INVALID');
  }
  if (!SHA.test(candidateSha)) fail('E7_ACCOUNT_BOOTSTRAP_CANDIDATE_SHA_INVALID');
  if (!PRERELEASE_ENVIRONMENT.test(prereleaseEnvironment)) {
    fail('E7_ACCOUNT_BOOTSTRAP_PRERELEASE_ENVIRONMENT_INVALID');
  }
  if (
    !STAGE7_ACCOUNT_BOOTSTRAP_SCOPES.includes(activeBootstrapScope as Stage7AccountBootstrapScope)
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_ACTIVE_BOOTSTRAP_SCOPE_INVALID');
  }
  if (typeof raw.includeAuxiliaryReadAuthority !== 'boolean') {
    fail('E7_ACCOUNT_BOOTSTRAP_INCLUDE_AUXILIARY_READ_AUTHORITY_INVALID');
  }
  const includeAuxiliaryReadAuthority = raw.includeAuxiliaryReadAuthority as boolean;
  if (activeBootstrapScope === 'PRERELEASE' && includeAuxiliaryReadAuthority) {
    fail('E7_ACCOUNT_BOOTSTRAP_AUXILIARY_READ_AUTHORITY_SCOPE_INVALID');
  }
  if (
    !HOSTNAME.test(webHostname) ||
    !HOSTNAME.test(apiHostname) ||
    webHostname === apiHostname ||
    webHostname.split('.').slice(1).join('.') !== apiHostname.split('.').slice(1).join('.')
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_DOMAIN_INVALID');
  }
  if (!HOSTED_ZONE_ID.test(hostedZoneId)) {
    fail('E7_ACCOUNT_BOOTSTRAP_HOSTED_ZONE_ID_INVALID');
  }
  const webCertificatePrefix = `arn:aws:acm:us-east-1:${accountId}:certificate/`;
  const apiCertificatePrefix = `arn:aws:acm:${region}:${accountId}:certificate/`;
  if (
    !webCertificateArn.startsWith(webCertificatePrefix) ||
    !CERTIFICATE_ID.test(webCertificateArn.slice(webCertificatePrefix.length))
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_WEB_CERTIFICATE_ARN_INVALID');
  }
  if (
    !apiCertificateArn.startsWith(apiCertificatePrefix) ||
    !CERTIFICATE_ID.test(apiCertificateArn.slice(apiCertificatePrefix.length))
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_API_CERTIFICATE_ARN_INVALID');
  }
  if (
    !Array.isArray(raw.credentialReferences) ||
    raw.credentialReferences.length < 1 ||
    raw.credentialReferences.length > 6 ||
    raw.credentialReferences.some(
      (entry) => typeof entry !== 'string' || entry.length === 0 || entry.trim() !== entry,
    )
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_CREDENTIAL_REFERENCES_INVALID');
  }
  const credentialReferences = [...(raw.credentialReferences as string[])];
  if (
    new Set(credentialReferences).size !== credentialReferences.length ||
    !credentialReferences.includes(originTokenSecretArn) ||
    credentialReferences.some((reference) => {
      const match = SECRET_REFERENCE.exec(reference);
      return (
        match === null || match[2] !== region || match[3] !== accountId || reference.includes('*')
      );
    }) ||
    !originTokenSecretArn.startsWith(`arn:aws:secretsmanager:${region}:${accountId}:secret:`)
  ) {
    fail('E7_ACCOUNT_BOOTSTRAP_CREDENTIAL_REFERENCES_INVALID');
  }

  const baselineRoleName = STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_NAMES.baselineRoleArn;
  const releaseRoles = primaryRoleSet(
    accountId,
    STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_NAMES.release,
    baselineRoleName,
  );
  const prereleaseRoles = primaryRoleSet(
    accountId,
    STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_NAMES.prerelease,
    baselineRoleName,
  );
  const releaseBoundaries = primaryBoundarySet(
    accountId,
    'assessment-release',
    STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_NAMES.release,
    baselineRoleName,
  );
  const prereleaseScopedBoundaries = primaryBoundarySet(
    accountId,
    prereleaseEnvironment,
    STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_NAMES.prerelease,
    baselineRoleName,
  );
  // The baseline role is intentionally shared with the full-release set. Its boundary is never
  // taken from the prerelease namespace, even though the prerelease config must carry its ARN.
  const prereleaseBoundaries = Object.freeze({
    ...prereleaseScopedBoundaries,
    baselineRoleArn: releaseBoundaries.baselineRoleArn,
  });

  const cdkNames = cdkRoleNames(accountId, region);
  const activeEnvironment =
    activeBootstrapScope === 'FULL_RELEASE' ? 'assessment-release' : prereleaseEnvironment;
  const cdkRoles = Object.freeze(
    Object.fromEntries(
      STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS.map((key) => [
        key,
        `arn:aws:iam::${accountId}:role/${cdkNames[key]}`,
      ]),
    ) as Record<Stage7CdkRoleKey, string>,
  );
  const cdkBoundaries = Object.freeze(
    Object.fromEntries(
      STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS.map((key) => [
        key,
        `arn:aws:iam::${accountId}:policy/checkout-stage7-${activeEnvironment}-${cdkNames[key]}-boundary`,
      ]),
    ) as Record<Stage7CdkRoleKey, string>,
  );
  const cleanupWatchdogRoleName =
    STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_NAMES.cleanupWatchdogRoleArn;
  const cleanupWatchdogRole = roleArn(accountId, cleanupWatchdogRoleName);
  const cleanupWatchdogBoundary = boundaryArn(
    accountId,
    prereleaseEnvironment,
    cleanupWatchdogRoleName,
  );
  const assetBucketName = `cdk-${STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER}-assets-${accountId}-${region}`;
  const imageRepositoryName = `cdk-${STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER}-container-assets-${accountId}-${region}`;
  const versionParameterName = `/cdk-bootstrap/${STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER}/version`;
  const allRoles = [
    ...STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS.map((key) => releaseRoles[key]),
    releaseRoles.baselineRoleArn,
    ...STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS.map((key) => prereleaseRoles[key]),
    cleanupWatchdogRole,
    ...Object.values(cdkRoles),
  ];
  if (new Set(allRoles).size !== allRoles.length) {
    fail('E7_ACCOUNT_BOOTSTRAP_ROLE_SET_INVALID');
  }
  validateDerivedNameQuota(
    [
      ...Object.values(STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_NAMES.release),
      ...Object.values(STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_NAMES.prerelease),
      baselineRoleName,
      cleanupWatchdogRoleName,
      ...Object.values(cdkNames),
    ],
    IAM_ROLE_NAME_MAX_LENGTH,
    'IAM_ROLE_NAME',
  );
  validateDerivedNameQuota(
    [
      ...STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS.map((key) => releaseBoundaries[key]),
      releaseBoundaries.baselineRoleArn,
      ...STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS.map((key) => prereleaseBoundaries[key]),
      prereleaseBoundaries.baselineRoleArn,
      cleanupWatchdogBoundary,
      ...STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS.map((key) => cdkBoundaries[key]),
    ].map((arn) => arn.split('/').at(-1) ?? ''),
    IAM_POLICY_NAME_MAX_LENGTH,
    'IAM_MANAGED_POLICY_NAME',
  );
  validateDerivedNameQuota(
    [
      ...STAGE7_ACCOUNT_BOOTSTRAP_PRIMARY_ROLE_KEYS,
      'baselineRoleArn',
      'cleanupWatchdogRoleArn',
      ...STAGE7_ACCOUNT_BOOTSTRAP_CDK_ROLE_KEYS,
    ].map((roleKey) => `stage7-${roleKey}`),
    IAM_POLICY_NAME_MAX_LENGTH,
    'IAM_INLINE_POLICY_NAME',
  );
  validateDerivedResourceName(
    assetBucketName,
    S3_BUCKET_NAME_MAX_LENGTH,
    S3_BUCKET_NAME,
    'ASSET_BUCKET_NAME',
  );
  validateDerivedResourceName(
    imageRepositoryName,
    ECR_REPOSITORY_NAME_MAX_LENGTH,
    ECR_REPOSITORY_NAME,
    'IMAGE_REPOSITORY_NAME',
  );
  validateDerivedResourceName(
    versionParameterName,
    SSM_PARAMETER_NAME_MAX_LENGTH,
    SSM_PARAMETER_NAME,
    'VERSION_PARAMETER_NAME',
  );

  return Object.freeze({
    accountId,
    region,
    counterpartRegion,
    candidateSha,
    prereleaseEnvironment,
    repository: STAGE7_ACCOUNT_BOOTSTRAP_REPOSITORY,
    oidcProviderArn: `arn:aws:iam::${accountId}:oidc-provider/${STAGE7_ACCOUNT_BOOTSTRAP_OIDC_HOST}`,
    originTokenSecretArn,
    credentialReferences: Object.freeze(credentialReferences.toSorted()),
    domain: Object.freeze({
      hostedZoneId,
      webHostname,
      apiHostname,
      webCertificateArn,
      apiCertificateArn,
    }),
    activeBootstrapScope: activeBootstrapScope as Stage7AccountBootstrapScope,
    includeAuxiliaryReadAuthority,
    roles: Object.freeze({
      release: releaseRoles,
      prerelease: prereleaseRoles,
      cleanupWatchdogRoleArn: cleanupWatchdogRole,
    }),
    boundaries: Object.freeze({
      release: releaseBoundaries,
      prerelease: prereleaseBoundaries,
      cleanupWatchdogRoleArn: cleanupWatchdogBoundary,
    }),
    auxiliary: Object.freeze({
      journalRoleArn: roleArn(accountId, 'release-journal-cleanup'),
      journalPermissionsBoundaryArn: `arn:aws:iam::${accountId}:policy/stage7-release-journal-cleanup-boundary`,
      reconciliationRecoveryRoleArn: roleArn(accountId, 'release-reconciliation-recovery'),
      reconciliationRecoveryPermissionsBoundaryArn: `arn:aws:iam::${accountId}:policy/stage7-release-reconciliation-recovery-boundary`,
    }),
    bootstrap: Object.freeze({
      qualifier: STAGE7_ACCOUNT_BOOTSTRAP_QUALIFIER,
      version: STAGE7_ACCOUNT_BOOTSTRAP_VERSION,
      assetBucketName,
      imageRepositoryName,
      versionParameterName,
      roles: cdkRoles,
      boundaries: cdkBoundaries,
    }),
  });
};
