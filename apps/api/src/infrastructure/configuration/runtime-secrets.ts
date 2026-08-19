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

const providerAcceptanceToken = (value: unknown): value is string =>
  typeof value === 'string' && value.length >= 8 && value.length <= 8_192;

const providerPermalink = (value: unknown): value is string => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048) return false;
  try {
    const parsed = new URL(value);
    return (
      parsed.protocol === 'https:' &&
      (parsed.hostname === 'wompi.co' || parsed.hostname.endsWith('.wompi.co')) &&
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
    !providerAcceptanceToken(termsAcceptanceToken) ||
    !providerPermalink(termsPermalink) ||
    !providerAcceptanceToken(personalDataAcceptanceToken) ||
    !providerPermalink(personalDataPermalink)
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
