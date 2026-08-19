export const STAGE7_GITHUB_REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
export const STAGE7_GITHUB_OIDC_HOST = 'token.actions.githubusercontent.com';
export const STAGE7_AUTHORITY_ROLE_PATH = '/checkout/';
export const STAGE7_JOURNAL_ROLE_NAME = 'release-journal-cleanup';
export const STAGE7_JOURNAL_BOUNDARY_NAME = 'stage7-release-journal-cleanup-boundary';
export const STAGE7_RECOVERY_ROLE_NAME = 'release-reconciliation-recovery';
export const STAGE7_RECOVERY_BOUNDARY_NAME = 'stage7-release-reconciliation-recovery-boundary';

export interface RawReleaseAuthorityConfig {
  readonly accountId?: unknown;
  readonly region?: unknown;
  readonly readRoleArn?: unknown;
}

export interface ReleaseAuthorityConfig {
  readonly accountId: string;
  readonly region: string;
  readonly repository: typeof STAGE7_GITHUB_REPOSITORY;
  readonly oidcProviderArn: string;
  readonly readRoleArn: string;
  readonly readRoleName: string;
  readonly journalRoleArn: string;
  readonly journalPermissionsBoundaryArn: string;
  readonly reconciliationRecoveryRoleArn: string;
  readonly reconciliationRecoveryPermissionsBoundaryArn: string;
}

const ACCOUNT_ID = /^[0-9]{12}$/u;
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$/u;
const READ_ROLE_ARN = /^arn:aws:iam::([0-9]{12}):role\/checkout\/([A-Za-z0-9+=,.@_-]{1,64})$/u;

const requiredString = (value: unknown, name: string): string => {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`E7_RELEASE_AUTHORITY_${name.toUpperCase()}_INVALID`);
  }
  return value;
};

export function parseReleaseAuthorityConfig(
  raw: RawReleaseAuthorityConfig,
): ReleaseAuthorityConfig {
  const accountId = requiredString(raw.accountId, 'account_id');
  const region = requiredString(raw.region, 'region');
  const readRoleArn = requiredString(raw.readRoleArn, 'read_role_arn');
  const readRole = READ_ROLE_ARN.exec(readRoleArn);
  if (!ACCOUNT_ID.test(accountId)) {
    throw new Error('E7_RELEASE_AUTHORITY_ACCOUNT_ID_INVALID');
  }
  if (!REGION.test(region)) {
    throw new Error('E7_RELEASE_AUTHORITY_REGION_INVALID');
  }
  if (
    readRole === null ||
    readRole[1] !== accountId ||
    [STAGE7_JOURNAL_ROLE_NAME, STAGE7_RECOVERY_ROLE_NAME].includes(readRole[2] ?? '')
  ) {
    throw new Error('E7_RELEASE_AUTHORITY_READ_ROLE_ARN_INVALID');
  }

  const roleArn = (name: string): string =>
    `arn:aws:iam::${accountId}:role${STAGE7_AUTHORITY_ROLE_PATH}${name}`;
  const policyArn = (name: string): string => `arn:aws:iam::${accountId}:policy/${name}`;
  const journalRoleArn = roleArn(STAGE7_JOURNAL_ROLE_NAME);
  const reconciliationRecoveryRoleArn = roleArn(STAGE7_RECOVERY_ROLE_NAME);
  if (
    new Set([readRoleArn, journalRoleArn, reconciliationRecoveryRoleArn]).size !== 3 ||
    readRoleArn.includes('*')
  ) {
    throw new Error('E7_RELEASE_AUTHORITY_ROLE_SET_INVALID');
  }

  return Object.freeze({
    accountId,
    region,
    repository: STAGE7_GITHUB_REPOSITORY,
    oidcProviderArn: `arn:aws:iam::${accountId}:oidc-provider/${STAGE7_GITHUB_OIDC_HOST}`,
    readRoleArn,
    readRoleName: readRole[2] ?? '',
    journalRoleArn,
    journalPermissionsBoundaryArn: policyArn(STAGE7_JOURNAL_BOUNDARY_NAME),
    reconciliationRecoveryRoleArn,
    reconciliationRecoveryPermissionsBoundaryArn: policyArn(STAGE7_RECOVERY_BOUNDARY_NAME),
  });
}
