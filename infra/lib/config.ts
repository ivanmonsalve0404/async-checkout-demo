export interface PreviewConfig {
  readonly projectName: string;
  readonly environment: 'preview';
  readonly region: string;
  readonly paymentAdapter: 'fake';
  readonly paymentsEnabled: false;
  readonly tokenizationMode: 'disabled';
}

export interface DomainConfig {
  readonly hostedZoneId: string;
  readonly hostedZoneName: string;
  readonly webDomainName: string;
  readonly webCertificateArn: string;
  readonly apiDomainName: string;
  readonly apiCertificateArn: string;
}

export type ReleaseEnvironment = 'assessment-release' | `assessment-prerelease-${string}`;

export interface ReleaseConfig {
  readonly projectName: string;
  readonly environment: ReleaseEnvironment;
  readonly region: string;
  readonly releaseId: string;
  readonly candidateSha: string;
  readonly owner: string;
  readonly expiresOn: string;
  readonly cleanupExpiresAtUtc: string;
  readonly paymentAdapter: 'fake' | 'sandbox';
  readonly paymentsEnabled: boolean;
  readonly tokenizationMode: 'disabled' | 'direct_jwe';
  readonly schedulerEnabled: boolean;
  readonly sandboxAuthorizedUntilUtc?: string;
  readonly pointInTimeRecoveryEnabled: boolean;
  readonly publicationMode:
    'VERSIONED_UPDATE_CLOSED' | 'FULL_BASELINE_CLOSED' | 'EPHEMERAL_NON_PUBLIC';
  readonly prereleaseKeyGroupId?: string;
  readonly prereleasePublicKeyId?: string;
  readonly budgetMaxUsd: number;
  readonly budgetWarningUsd: readonly number[];
  readonly apiArtifactPath: string;
  readonly workerArtifactPath: string;
  readonly webArtifactPath: string;
  readonly runtimeSecretArn?: string;
  readonly runtimeSecretVersionId?: string;
  readonly baselineConfigSha256?: string;
  readonly domain?: DomainConfig;
}

export type FoundationConfig = PreviewConfig | ReleaseConfig;

export interface RawFoundationConfig {
  readonly projectName?: unknown;
  readonly environment?: unknown;
  readonly region?: unknown;
  readonly releaseId?: unknown;
  readonly candidateSha?: unknown;
  readonly owner?: unknown;
  readonly expiresOn?: unknown;
  readonly cleanupExpiresAtUtc?: unknown;
  readonly paymentAdapter?: unknown;
  readonly paymentsEnabled?: unknown;
  readonly tokenizationMode?: unknown;
  readonly schedulerEnabled?: unknown;
  readonly sandboxAuthorizedUntilUtc?: unknown;
  readonly pointInTimeRecoveryEnabled?: unknown;
  readonly publicationMode?: unknown;
  readonly prereleaseKeyGroupId?: unknown;
  readonly prereleasePublicKeyId?: unknown;
  readonly budgetMaxUsd?: unknown;
  readonly budgetWarningUsd?: unknown;
  readonly apiArtifactPath?: unknown;
  readonly workerArtifactPath?: unknown;
  readonly webArtifactPath?: unknown;
  readonly runtimeSecretArn?: unknown;
  readonly runtimeSecretVersionId?: unknown;
  readonly baselineConfigSha256?: unknown;
  readonly hostedZoneId?: unknown;
  readonly hostedZoneName?: unknown;
  readonly webDomainName?: unknown;
  readonly webCertificateArn?: unknown;
  readonly apiDomainName?: unknown;
  readonly apiCertificateArn?: unknown;
}

const PROJECT_NAME_PATTERN = /^[a-z][a-z0-9-]{1,30}[a-z0-9]$/;
const REGION_PATTERN = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;
const RELEASE_ID_PATTERN = /^rel-\d{8}-\d{4}-([a-f0-9]{7})$/;
const SHA_PATTERN = /^[a-f0-9]{40}$/;
const OWNER_PATTERN = /^[a-z][a-z0-9-]{1,30}[a-z0-9]$/;
const RELEASE_ENVIRONMENT_PATTERN = /^assessment-prerelease-[a-z0-9][a-z0-9-]{0,39}$/;
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const FQDN_PATTERN = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const HOSTED_ZONE_ID_PATTERN = /^Z[A-Z0-9]{5,31}$/;

function asBoolean(value: unknown, fallback: boolean, name: string): boolean {
  const resolved = value ?? fallback;
  if (resolved === true || resolved === 'true') return true;
  if (resolved === false || resolved === 'false') return false;
  throw new Error(name + ' must be a boolean');
}

function asString(value: unknown, fallback: string | undefined, name: string): string {
  const resolved = value ?? fallback;
  if (typeof resolved !== 'string' || resolved.length === 0) {
    throw new Error(name + ' must be a non-empty string');
  }
  return resolved;
}

function optionalString(value: unknown, name: string): string | undefined {
  if (value === undefined) return undefined;
  return asString(value, undefined, name);
}

function money(value: unknown, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  const parsed =
    typeof resolved === 'number'
      ? resolved
      : typeof resolved === 'string' && /^(?:0|[1-9][0-9]*)(?:\.[0-9]{1,2})?$/u.test(resolved)
        ? Number(resolved)
        : Number.NaN;
  if (
    !Number.isFinite(parsed) ||
    parsed <= 0 ||
    parsed > 10_000 ||
    !Number.isSafeInteger(Math.round(parsed * 100)) ||
    Math.abs(parsed * 100 - Math.round(parsed * 100)) > 1e-8
  ) {
    throw new Error(name + ' must be a positive USD amount with at most two decimals');
  }
  return parsed;
}

function warningAmounts(value: unknown, maximum: number): readonly number[] {
  const source =
    value === undefined
      ? [5, 8]
      : Array.isArray(value)
        ? value
        : typeof value === 'string'
          ? value.split(',')
          : [];
  const parsed = source.map((entry, index) => money(entry, 0, `budgetWarningUsd[${index}]`));
  if (
    parsed.length < 1 ||
    parsed.length > 3 ||
    parsed.some(
      (entry, index) => entry >= maximum || (index > 0 && entry <= (parsed[index - 1] ?? 0)),
    )
  ) {
    throw new Error('budgetWarningUsd must contain one to three increasing amounts below max');
  }
  return parsed;
}

function secretArn(value: unknown, name: string, region: string): string | undefined {
  const resolved = optionalString(value, name);
  if (resolved === undefined) return undefined;
  const pattern = new RegExp(
    '^arn:(?:aws|aws-us-gov):secretsmanager:' +
      region.replaceAll('-', '\\-') +
      ':\\d{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$',
  );
  if (!pattern.test(resolved)) throw new Error(name + ' must be a Secrets Manager ARN in region');
  return resolved;
}

function certificateArn(value: unknown, name: string, region: string): string {
  const resolved = asString(value, undefined, name);
  const pattern = new RegExp(
    '^arn:(?:aws|aws-us-gov):acm:' +
      region.replaceAll('-', '\\-') +
      ':\\d{12}:certificate/[a-f0-9-]{36}$',
  );
  if (!pattern.test(resolved))
    throw new Error(name + ' must be an ACM certificate ARN in ' + region);
  return resolved;
}

function utcTimestamp(value: unknown, name: string): string | undefined {
  const resolved = optionalString(value, name);
  if (resolved === undefined) return undefined;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(resolved)) {
    throw new Error(name + ' must be an exact UTC timestamp');
  }
  const parsed = new Date(resolved);
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== resolved) {
    throw new Error(name + ' must be an exact UTC timestamp');
  }
  return resolved;
}

function parseDomain(raw: RawFoundationConfig, region: string): DomainConfig | undefined {
  const values = [
    raw.hostedZoneId,
    raw.hostedZoneName,
    raw.webDomainName,
    raw.webCertificateArn,
    raw.apiDomainName,
    raw.apiCertificateArn,
  ];
  if (values.every((value) => value === undefined)) return undefined;
  if (values.some((value) => value === undefined)) {
    throw new Error('custom domain configuration must be complete');
  }

  const hostedZoneId = asString(raw.hostedZoneId, undefined, 'hostedZoneId');
  const hostedZoneName = asString(raw.hostedZoneName, undefined, 'hostedZoneName').toLowerCase();
  const webDomainName = asString(raw.webDomainName, undefined, 'webDomainName').toLowerCase();
  const apiDomainName = asString(raw.apiDomainName, undefined, 'apiDomainName').toLowerCase();
  if (!HOSTED_ZONE_ID_PATTERN.test(hostedZoneId)) throw new Error('hostedZoneId is invalid');
  for (const [name, value] of [
    ['hostedZoneName', hostedZoneName],
    ['webDomainName', webDomainName],
    ['apiDomainName', apiDomainName],
  ] as const) {
    if (!FQDN_PATTERN.test(value)) throw new Error(name + ' must be a lowercase FQDN');
  }
  if (
    webDomainName === apiDomainName ||
    !webDomainName.endsWith('.' + hostedZoneName) ||
    !apiDomainName.endsWith('.' + hostedZoneName)
  ) {
    throw new Error('web and API domains must be distinct names inside the hosted zone');
  }

  return {
    hostedZoneId,
    hostedZoneName,
    webDomainName,
    webCertificateArn: certificateArn(raw.webCertificateArn, 'webCertificateArn', 'us-east-1'),
    apiDomainName,
    apiCertificateArn: certificateArn(raw.apiCertificateArn, 'apiCertificateArn', region),
  };
}

export function parseFoundationConfig(raw: RawFoundationConfig): FoundationConfig {
  const projectName = asString(raw.projectName, 'checkout', 'projectName');
  const environment = asString(raw.environment, 'preview', 'environment');
  const region = asString(raw.region, 'us-east-1', 'region');
  if (!PROJECT_NAME_PATTERN.test(projectName)) {
    throw new Error('projectName must be a lowercase, hyphenated slug');
  }
  if (!REGION_PATTERN.test(region)) throw new Error('region must be an AWS region identifier');

  if (environment === 'preview') {
    if (raw.prereleaseKeyGroupId !== undefined || raw.prereleasePublicKeyId !== undefined) {
      throw new Error('preview cannot configure prerelease edge access');
    }
    const paymentAdapter = asString(raw.paymentAdapter, 'fake', 'paymentAdapter');
    const paymentsEnabled = asBoolean(raw.paymentsEnabled, false, 'paymentsEnabled');
    const tokenizationMode = asString(raw.tokenizationMode, 'disabled', 'tokenizationMode');
    if (paymentAdapter !== 'fake') throw new Error('Preview only permits the fake payment adapter');
    if (paymentsEnabled) throw new Error('Preview requires paymentsEnabled=false');
    if (tokenizationMode !== 'disabled')
      throw new Error('Preview requires tokenizationMode=disabled');
    return {
      projectName,
      environment: 'preview',
      region,
      paymentAdapter: 'fake',
      paymentsEnabled: false,
      tokenizationMode: 'disabled',
    };
  }

  if (environment !== 'assessment-release' && !RELEASE_ENVIRONMENT_PATTERN.test(environment)) {
    throw new Error(
      'environment must be preview, assessment-release or assessment-prerelease-<slug>',
    );
  }
  if (`${projectName}-${environment}`.length > 50) {
    throw new Error('projectName and environment exceed the bounded AWS resource-name prefix');
  }

  const candidateSha = asString(raw.candidateSha, undefined, 'candidateSha');
  const releaseId = asString(raw.releaseId, undefined, 'releaseId');
  const releaseMatch = RELEASE_ID_PATTERN.exec(releaseId);
  if (!SHA_PATTERN.test(candidateSha)) throw new Error('candidateSha must be a full lowercase SHA');
  if (releaseMatch?.[1] !== candidateSha.slice(0, 7)) {
    throw new Error('releaseId must end with the candidate SHA prefix');
  }
  const owner = asString(raw.owner, undefined, 'owner');
  if (!OWNER_PATTERN.test(owner)) throw new Error('owner must be a neutral lowercase slug');
  const expiresOn = asString(raw.expiresOn, undefined, 'expiresOn');
  const expiry = new Date(expiresOn + 'T00:00:00.000Z');
  if (
    !DATE_PATTERN.test(expiresOn) ||
    Number.isNaN(expiry.getTime()) ||
    expiry.toISOString().slice(0, 10) !== expiresOn
  ) {
    throw new Error('expiresOn must be a valid YYYY-MM-DD date');
  }
  const cleanupExpiresAtUtc = utcTimestamp(raw.cleanupExpiresAtUtc, 'cleanupExpiresAtUtc');
  if (cleanupExpiresAtUtc === undefined || cleanupExpiresAtUtc.slice(0, 10) !== expiresOn) {
    throw new Error('cleanupExpiresAtUtc must be an exact UTC timestamp on expiresOn');
  }

  const paymentAdapter = asString(raw.paymentAdapter, 'fake', 'paymentAdapter');
  const paymentsEnabled = asBoolean(raw.paymentsEnabled, false, 'paymentsEnabled');
  const tokenizationMode = asString(raw.tokenizationMode, 'disabled', 'tokenizationMode');
  const schedulerEnabled = asBoolean(raw.schedulerEnabled, false, 'schedulerEnabled');
  const pointInTimeRecoveryEnabled = asBoolean(
    raw.pointInTimeRecoveryEnabled,
    false,
    'pointInTimeRecoveryEnabled',
  );
  const publicationModeValue = asString(raw.publicationMode, undefined, 'publicationMode');
  const budgetMaxUsd = money(raw.budgetMaxUsd, 10, 'budgetMaxUsd');
  const budgetWarningUsd = warningAmounts(raw.budgetWarningUsd, budgetMaxUsd);
  if (paymentAdapter !== 'fake' && paymentAdapter !== 'sandbox') {
    throw new Error('assessment release supports only fake or sandbox');
  }

  const domain = parseDomain(raw, region);
  const runtimeSecretArn = secretArn(raw.runtimeSecretArn, 'runtimeSecretArn', region);
  const runtimeSecretVersionId = optionalString(
    raw.runtimeSecretVersionId,
    'runtimeSecretVersionId',
  );
  const sandboxAuthorizedUntilUtc = utcTimestamp(
    raw.sandboxAuthorizedUntilUtc,
    'sandboxAuthorizedUntilUtc',
  );

  if (
    (environment === 'assessment-release' &&
      !['VERSIONED_UPDATE_CLOSED', 'FULL_BASELINE_CLOSED'].includes(publicationModeValue)) ||
    (environment.startsWith('assessment-prerelease-') &&
      publicationModeValue !== 'EPHEMERAL_NON_PUBLIC')
  ) {
    throw new Error(
      'assessment-release requires VERSIONED_UPDATE_CLOSED or FULL_BASELINE_CLOSED and prerelease requires EPHEMERAL_NON_PUBLIC',
    );
  }
  const publicationMode = publicationModeValue as ReleaseConfig['publicationMode'];
  const prereleaseKeyGroupId = optionalString(raw.prereleaseKeyGroupId, 'prereleaseKeyGroupId');
  const prereleasePublicKeyId = optionalString(raw.prereleasePublicKeyId, 'prereleasePublicKeyId');
  const baselineConfigSha256 = optionalString(raw.baselineConfigSha256, 'baselineConfigSha256');
  const restrictedAccess =
    environment.startsWith('assessment-prerelease-') || publicationMode === 'FULL_BASELINE_CLOSED';
  if (
    (restrictedAccess &&
      (prereleaseKeyGroupId === undefined ||
        !/^[A-Z0-9]{8,64}$/u.test(prereleaseKeyGroupId) ||
        prereleasePublicKeyId === undefined ||
        !/^[A-Z0-9]{8,64}$/u.test(prereleasePublicKeyId) ||
        runtimeSecretArn === undefined)) ||
    (!restrictedAccess &&
      (prereleaseKeyGroupId !== undefined || prereleasePublicKeyId !== undefined))
  ) {
    throw new Error(
      'prerelease requires CloudFront key-group/public-key IDs and a runtime secret; other modes forbid them',
    );
  }
  if (
    (runtimeSecretArn === undefined && runtimeSecretVersionId !== undefined) ||
    (runtimeSecretArn !== undefined && !/^[A-Za-z0-9-]{32,64}$/u.test(runtimeSecretVersionId ?? ''))
  ) {
    throw new Error('runtimeSecretVersionId must pin every runtime secret reference');
  }

  if (paymentAdapter === 'fake') {
    if (
      paymentsEnabled ||
      tokenizationMode !== 'disabled' ||
      sandboxAuthorizedUntilUtc !== undefined
    ) {
      throw new Error(
        'fake assessment release requires payments disabled and tokenization disabled',
      );
    }
  } else {
    if (!paymentsEnabled || tokenizationMode !== 'direct_jwe') {
      throw new Error('sandbox requires payments enabled and direct tokenization');
    }
    if (runtimeSecretArn === undefined) {
      throw new Error('sandbox requires one complete runtime JSON secret ARN');
    }
    if (
      (publicationMode === 'FULL_BASELINE_CLOSED' && schedulerEnabled) ||
      (publicationMode !== 'FULL_BASELINE_CLOSED' && !schedulerEnabled)
    ) {
      throw new Error(
        'sandbox versioned releases require the reconciler enabled; closed baseline requires it disabled',
      );
    }
    if (sandboxAuthorizedUntilUtc === undefined) {
      throw new Error('sandbox requires an exact authorization expiry');
    }
  }
  if (
    environment === 'assessment-release' &&
    (paymentAdapter !== 'sandbox' || domain === undefined)
  ) {
    throw new Error(
      'the full versioned release requires sandbox mode and a complete custom domain',
    );
  }
  if (
    (publicationMode === 'FULL_BASELINE_CLOSED' &&
      !/^[0-9a-f]{64}$/u.test(baselineConfigSha256 ?? '')) ||
    (publicationMode !== 'FULL_BASELINE_CLOSED' && baselineConfigSha256 !== undefined)
  ) {
    throw new Error('baselineConfigSha256 is required only for FULL_BASELINE_CLOSED');
  }

  return {
    projectName,
    environment: environment as ReleaseEnvironment,
    region,
    releaseId,
    candidateSha,
    owner,
    expiresOn,
    cleanupExpiresAtUtc,
    paymentAdapter,
    paymentsEnabled,
    tokenizationMode,
    schedulerEnabled,
    sandboxAuthorizedUntilUtc,
    pointInTimeRecoveryEnabled,
    publicationMode,
    prereleaseKeyGroupId,
    prereleasePublicKeyId,
    budgetMaxUsd,
    budgetWarningUsd,
    apiArtifactPath: asString(
      raw.apiArtifactPath,
      '../output/release/build/api',
      'apiArtifactPath',
    ),
    workerArtifactPath: asString(
      raw.workerArtifactPath,
      '../output/release/build/worker',
      'workerArtifactPath',
    ),
    webArtifactPath: asString(
      raw.webArtifactPath,
      '../output/release/build/web',
      'webArtifactPath',
    ),
    runtimeSecretArn,
    runtimeSecretVersionId,
    baselineConfigSha256,
    domain,
  };
}
