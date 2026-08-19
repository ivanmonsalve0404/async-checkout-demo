export const STAGE7_PUBLICATION_RECOVERY_REPOSITORY = 'ivanmonsalve0404/async-checkout-demo';
export const STAGE7_PUBLICATION_RECOVERY_ENVIRONMENT =
  'assessment-release-successor-publication-recovery';
export const STAGE7_PUBLICATION_RECOVERY_ROLE_PATH = '/checkout/';
export const STAGE7_PUBLICATION_RECOVERY_ROLE_NAME = 'release-successor-publication-recovery';
export const STAGE7_PUBLICATION_RECOVERY_BOUNDARY_NAME =
  'stage7-release-successor-publication-recovery-boundary';
export const STAGE7_PUBLICATION_RECOVERY_ROLE_VARIABLE =
  'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_ROLE_ARN';
export const STAGE7_PUBLICATION_RECOVERY_BOUNDARY_VARIABLE =
  'STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN';

export interface RawReleaseSuccessorPublicationRecoveryAuthorityConfig {
  readonly accountId?: unknown;
  readonly region?: unknown;
}

export interface ReleaseSuccessorPublicationRecoveryAuthorityConfig {
  readonly accountId: string;
  readonly region: string;
  readonly repository: typeof STAGE7_PUBLICATION_RECOVERY_REPOSITORY;
  readonly protectedEnvironment: typeof STAGE7_PUBLICATION_RECOVERY_ENVIRONMENT;
  readonly roleArn: string;
  readonly permissionsBoundaryArn: string;
}

const ACCOUNT_ID = /^[0-9]{12}$/u;
const REGION = /^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$/u;

const requiredString = (value: unknown, name: string): string => {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    throw new Error(`E7_PUBLICATION_RECOVERY_IAC_${name.toUpperCase()}_INVALID`);
  }
  return value;
};

export function parseReleaseSuccessorPublicationRecoveryAuthorityConfig(
  raw: RawReleaseSuccessorPublicationRecoveryAuthorityConfig,
): ReleaseSuccessorPublicationRecoveryAuthorityConfig {
  const accountId = requiredString(raw.accountId, 'account_id');
  const region = requiredString(raw.region, 'region');
  if (!ACCOUNT_ID.test(accountId)) {
    throw new Error('E7_PUBLICATION_RECOVERY_IAC_ACCOUNT_ID_INVALID');
  }
  if (!REGION.test(region)) {
    throw new Error('E7_PUBLICATION_RECOVERY_IAC_REGION_INVALID');
  }

  return Object.freeze({
    accountId,
    region,
    repository: STAGE7_PUBLICATION_RECOVERY_REPOSITORY,
    protectedEnvironment: STAGE7_PUBLICATION_RECOVERY_ENVIRONMENT,
    roleArn: `arn:aws:iam::${accountId}:role${STAGE7_PUBLICATION_RECOVERY_ROLE_PATH}${STAGE7_PUBLICATION_RECOVERY_ROLE_NAME}`,
    permissionsBoundaryArn: `arn:aws:iam::${accountId}:policy/${STAGE7_PUBLICATION_RECOVERY_BOUNDARY_NAME}`,
  });
}
