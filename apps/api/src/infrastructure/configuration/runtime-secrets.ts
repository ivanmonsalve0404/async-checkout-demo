import { GetSecretValueCommand, SecretsManagerClient } from '@aws-sdk/client-secrets-manager';

import type { AppConfig } from './app-config';

export interface RuntimeSecrets {
  readonly prereleaseOriginToken: string | undefined;
  readonly runtimeSecurityRootKey: string | undefined;
  readonly sandbox:
    | Readonly<{
        publicKey: string;
        privateKey: string;
        integritySecret: string;
        termsAcceptanceToken: string;
        termsPermalink: string;
        personalDataAcceptanceToken: string;
        personalDataPermalink: string;
      }>
    | undefined;
}

export interface SecretReader {
  send(command: GetSecretValueCommand): Promise<Readonly<{ SecretString?: string }>>;
}

export const RUNTIME_SECRETS = Symbol('RUNTIME_SECRETS');

const canonicalBase64Url = (value: string): boolean =>
  /^[A-Za-z0-9_-]{43,128}$/u.test(value) &&
  Buffer.from(value, 'base64url').toString('base64url') === value;

const canonicalJwtSegment = (value: string): boolean =>
  value.length > 0 &&
  /^[A-Za-z0-9_-]+$/u.test(value) &&
  Buffer.from(value, 'base64url').toString('base64url') === value;

const jwtObjectSegment = (value: string): Readonly<Record<string, unknown>> | undefined => {
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(value, 'base64url').toString('utf8')) as unknown;
  } catch {
    return undefined;
  }
  return typeof decoded === 'object' && decoded !== null && !Array.isArray(decoded)
    ? (decoded as Readonly<Record<string, unknown>>)
    : undefined;
};

type ProviderAcceptanceTokenInspection = Readonly<{
  valid: boolean;
  expiration?: number;
}>;

const inspectProviderAcceptanceToken = (value: unknown): ProviderAcceptanceTokenInspection => {
  if (
    typeof value !== 'string' ||
    value.length < 8 ||
    value.length > 8_192 ||
    !/^[\x21-\x7e]+$/u.test(value)
  ) {
    return { valid: false };
  }
  if (!value.includes('.')) return { valid: true };
  const segments = value.split('.');
  if (segments.length !== 3 || !segments.every(canonicalJwtSegment)) return { valid: false };
  let payload: unknown;
  try {
    payload = JSON.parse(
      Buffer.from(segments[1] as string, 'base64url').toString('utf8'),
    ) as unknown;
  } catch {
    return { valid: false };
  }
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) {
    return { valid: false };
  }
  const expiration = (payload as Readonly<Record<string, unknown>>).exp;
  if (expiration === undefined) return { valid: true };
  return Number.isSafeInteger(expiration) && (expiration as number) > 0
    ? { valid: true, expiration: expiration as number }
    : { valid: false };
};

export const isProviderAcceptanceTokenStructurallyValid = (value: unknown): value is string =>
  inspectProviderAcceptanceToken(value).valid;

export const isProviderAcceptanceTokenUsable = (
  value: unknown,
  now: Date,
  minimumRemainingSeconds = 0,
): value is string => {
  if (
    !Number.isFinite(now.getTime()) ||
    !Number.isSafeInteger(minimumRemainingSeconds) ||
    minimumRemainingSeconds < 0
  ) {
    return false;
  }
  const inspection = inspectProviderAcceptanceToken(value);
  if (!inspection.valid) return false;
  if (inspection.expiration === undefined) return true;
  // The unverified payload can only make the adapter reject a token; it never grants authority.
  return inspection.expiration > now.getTime() / 1_000 + minimumRemainingSeconds;
};

export const isProviderAcceptanceJwtUsable = (
  value: unknown,
  now: Date,
  minimumRemainingSeconds = 0,
): value is string => {
  if (typeof value !== 'string') return false;
  const segments = value.split('.');
  if (segments.length !== 3 || !segments.every(canonicalJwtSegment)) return false;
  const header = jwtObjectSegment(segments[0] as string);
  if (header === undefined) return false;
  const algorithm = header.alg;
  const type = header.typ;
  if (
    typeof algorithm !== 'string' ||
    !/^[A-Za-z0-9_-]{2,64}$/u.test(algorithm) ||
    algorithm.toLowerCase() === 'none' ||
    (type !== undefined && type !== 'JWT')
  ) {
    return false;
  }
  return isProviderAcceptanceTokenUsable(value, now, minimumRemainingSeconds);
};

export const isWompiProviderPermalink = (value: unknown): value is string => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048) return false;
  try {
    const parsed = new URL(value);
    const officialHost =
      parsed.hostname === 'wompi.co' ||
      parsed.hostname.endsWith('.wompi.co') ||
      parsed.hostname === 'wompi.com' ||
      parsed.hostname.endsWith('.wompi.com');
    return (
      parsed.protocol === 'https:' &&
      officialHost &&
      parsed.username.length === 0 &&
      parsed.password.length === 0 &&
      parsed.toString() === value
    );
  } catch {
    return false;
  }
};

const parseRuntimeSecret = (
  source: string,
  sandboxRequired: boolean,
  prereleaseOriginTokenRequired: boolean,
): RuntimeSecrets => {
  let value: unknown;
  try {
    value = JSON.parse(source) as unknown;
  } catch {
    throw new Error('RUNTIME_SECRET_INVALID');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('RUNTIME_SECRET_INVALID');
  }
  const record = value as Readonly<Record<string, unknown>>;
  const expectedKeys = [
    ...(sandboxRequired
      ? [
          'integritySecret',
          'personalDataAcceptanceToken',
          'personalDataPermalink',
          'privateKey',
          'publicKey',
          'termsAcceptanceToken',
          'termsPermalink',
        ]
      : []),
    ...(prereleaseOriginTokenRequired ? ['prereleaseOriginToken'] : []),
    'runtimeSecurityRootKey',
  ];
  if (
    Object.keys(record).length !== expectedKeys.length ||
    !expectedKeys.every((key) => Object.hasOwn(record, key))
  ) {
    throw new Error('RUNTIME_SECRET_INVALID');
  }
  const rootKey = record.runtimeSecurityRootKey;
  if (typeof rootKey !== 'string' || !canonicalBase64Url(rootKey)) {
    throw new Error('RUNTIME_SECRET_INVALID');
  }
  const prereleaseOriginToken = record.prereleaseOriginToken;
  if (
    prereleaseOriginTokenRequired &&
    (typeof prereleaseOriginToken !== 'string' || !canonicalBase64Url(prereleaseOriginToken))
  ) {
    throw new Error('RUNTIME_SECRET_INVALID');
  }
  if (!sandboxRequired) {
    return {
      prereleaseOriginToken:
        typeof prereleaseOriginToken === 'string' ? prereleaseOriginToken : undefined,
      runtimeSecurityRootKey: rootKey,
      sandbox: undefined,
    };
  }
  const {
    publicKey,
    privateKey,
    integritySecret,
    termsAcceptanceToken,
    termsPermalink,
    personalDataAcceptanceToken,
    personalDataPermalink,
  } = record;
  if (
    typeof publicKey !== 'string' ||
    !/^pub_test_[A-Za-z0-9_-]{8,128}$/u.test(publicKey) ||
    typeof privateKey !== 'string' ||
    !/^prv_test_[A-Za-z0-9_-]{8,256}$/u.test(privateKey) ||
    typeof integritySecret !== 'string' ||
    !/^test_integrity_[A-Za-z0-9_-]{8,256}$/u.test(integritySecret) ||
    !isProviderAcceptanceTokenStructurallyValid(termsAcceptanceToken) ||
    !isWompiProviderPermalink(termsPermalink) ||
    !isProviderAcceptanceTokenStructurallyValid(personalDataAcceptanceToken) ||
    !isWompiProviderPermalink(personalDataPermalink)
  ) {
    throw new Error('RUNTIME_SECRET_INVALID');
  }
  return {
    prereleaseOriginToken:
      typeof prereleaseOriginToken === 'string' ? prereleaseOriginToken : undefined,
    runtimeSecurityRootKey: rootKey,
    sandbox: {
      publicKey,
      privateKey,
      integritySecret,
      termsAcceptanceToken,
      termsPermalink,
      personalDataAcceptanceToken,
      personalDataPermalink,
    },
  };
};

export const loadRuntimeSecrets = async (
  config: AppConfig,
  reader: SecretReader = new SecretsManagerClient({ region: config.awsRegion }),
): Promise<RuntimeSecrets> => {
  if (config.runtimeSecretArn === undefined) {
    return {
      prereleaseOriginToken: undefined,
      runtimeSecurityRootKey: config.runtimeSecurityRootKey,
      sandbox: undefined,
    };
  }
  const response = await reader.send(
    new GetSecretValueCommand({
      SecretId: config.runtimeSecretArn,
      VersionId: config.runtimeSecretVersionId,
    }),
  );
  if (typeof response.SecretString !== 'string') throw new Error('RUNTIME_SECRET_INVALID');
  return parseRuntimeSecret(
    response.SecretString,
    config.paymentsEnabled && config.paymentAdapter === 'sandbox',
    config.prereleaseAccessMode !== 'disabled',
  );
};
