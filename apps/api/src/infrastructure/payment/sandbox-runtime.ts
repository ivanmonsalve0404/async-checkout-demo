import { createHash } from 'node:crypto';

import type { AppConfig } from '../configuration/app-config';
import {
  isProviderAcceptanceJwtUsable,
  isWompiProviderPermalink,
  type RuntimeSecrets,
} from '../configuration/runtime-secrets';
import type { MerchantContractSet } from '../../application/ports/merchant-contract';
import type {
  SandboxAcceptanceReader,
  SandboxProviderAcceptanceSnapshot,
  SandboxTransport,
  SandboxTransportRequest,
  SandboxTransportResponse,
} from './sandbox-payment-provider';

export const WOMPI_SANDBOX_ORIGIN = 'https://sandbox.wompi.co' as const;
export const SANDBOX_ACCEPTANCE_CACHE_TTL_MS = 60_000 as const;
export const SANDBOX_EGRESS_EVENT_NAME = 'provider.sandbox.egress.attempted' as const;
export const SANDBOX_PROVIDER_HOST_SHA256 = createHash('sha256')
  .update('sandbox.wompi.co', 'utf8')
  .digest('hex');

export type SandboxEgressOperation =
  'MERCHANT_CONFIGURATION' | 'TRANSACTION_CREATE' | 'TRANSACTION_STATUS';

export interface SandboxEgressAttemptEvent {
  readonly eventName: typeof SANDBOX_EGRESS_EVENT_NAME;
  readonly schemaVersion: 1;
  readonly candidateSha: string;
  readonly releaseId: string;
  readonly providerHostSha256: string;
  readonly operation: SandboxEgressOperation;
  readonly method: 'GET' | 'POST';
  readonly correlationSha256: string;
  readonly containsSensitiveData: false;
}

export type SandboxEgressRecorder = (event: SandboxEgressAttemptEvent) => void;

export const sandboxEgressCorrelationSha256 = (providerReference: string): string =>
  createHash('sha256')
    .update(`stage7-sandbox-egress/v1\0${providerReference}`, 'utf8')
    .digest('hex');

export interface SandboxRuntimeConfiguration {
  readonly contracts: MerchantContractSet;
}

export const SANDBOX_RUNTIME_CONFIGURATION = Symbol('SANDBOX_RUNTIME_CONFIGURATION');

type FetchImplementation = typeof fetch;

const assertSandboxAuthorizationActive = (config: AppConfig, now: Date): void => {
  const expiresAt = Date.parse(config.sandboxAuthorizedUntilUtc ?? '');
  if (!Number.isFinite(expiresAt) || now.getTime() >= expiresAt) {
    throw new Error('SANDBOX_AUTHORIZATION_EXPIRED');
  }
};

const safeString = (value: unknown, maximum = 8_192): string => {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum) {
    throw new Error('SANDBOX_CONFIGURATION_INVALID');
  }
  return value;
};

const safePermalink = (value: unknown): string => {
  const candidate = safeString(value, 2_048);
  if (!isWompiProviderPermalink(candidate)) {
    throw new Error('SANDBOX_CONFIGURATION_INVALID');
  }
  return candidate;
};

const safeAcceptanceToken = (
  value: unknown,
  now: Date,
  minimumRemainingSeconds: number,
): string => {
  if (!isProviderAcceptanceJwtUsable(value, now, minimumRemainingSeconds)) {
    throw new Error('SANDBOX_CONFIGURATION_INVALID');
  }
  return value;
};

export const sandboxContractVersion = (permalink: string): string =>
  'provider-' + createHash('sha256').update(permalink).digest('hex').slice(0, 16);

const exactKeys = (value: Readonly<Record<string, unknown>>, keys: readonly string[]): boolean =>
  Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));

const providerContract = (
  value: unknown,
  type: 'END_USER_POLICY' | 'PERSONAL_DATA_AUTH',
  contractType: 'TERMS' | 'PERSONAL_DATA',
  now: Date,
  minimumRemainingSeconds: number,
): Readonly<{
  contract: MerchantContractSet[number];
  acceptanceToken: string;
}> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('SANDBOX_PROVIDER_CONFIGURATION_INVALID');
  }
  const record = value as Readonly<Record<string, unknown>>;
  if (!exactKeys(record, ['acceptance_token', 'permalink', 'type']) || record.type !== type) {
    throw new Error('SANDBOX_PROVIDER_CONFIGURATION_INVALID');
  }
  const permalink = safePermalink(record.permalink);
  return {
    contract: {
      type: contractType,
      permalink,
      version: sandboxContractVersion(permalink),
    },
    acceptanceToken: safeAcceptanceToken(record.acceptance_token, now, minimumRemainingSeconds),
  };
};

const providerAcceptanceSnapshot = (
  body: unknown,
  now: Date,
  minimumRemainingSeconds: number,
): SandboxProviderAcceptanceSnapshot => {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new Error('SANDBOX_PROVIDER_CONFIGURATION_INVALID');
  }
  const data = (body as Readonly<Record<string, unknown>>).data;
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new Error('SANDBOX_PROVIDER_CONFIGURATION_INVALID');
  }
  const record = data as Readonly<Record<string, unknown>>;
  const terms = providerContract(
    record.presigned_acceptance,
    'END_USER_POLICY',
    'TERMS',
    now,
    minimumRemainingSeconds,
  );
  const personalData = providerContract(
    record.presigned_personal_data_auth,
    'PERSONAL_DATA_AUTH',
    'PERSONAL_DATA',
    now,
    minimumRemainingSeconds,
  );
  return {
    contracts: [
      terms.contract as MerchantContractSet[0],
      personalData.contract as MerchantContractSet[1],
    ],
    providerAcceptances: {
      terms: terms.acceptanceToken,
      personalData: personalData.acceptanceToken,
    },
  };
};

const snapshotUsable = (
  snapshot: SandboxProviderAcceptanceSnapshot,
  now: Date,
  minimumRemainingSeconds: number,
): boolean =>
  isProviderAcceptanceJwtUsable(snapshot.providerAcceptances.terms, now, minimumRemainingSeconds) &&
  isProviderAcceptanceJwtUsable(
    snapshot.providerAcceptances.personalData,
    now,
    minimumRemainingSeconds,
  );

const request = async (
  fetchImplementation: FetchImplementation,
  resource: string,
  init: RequestInit,
  timeoutMs: number,
  beforeFetch: () => void,
): Promise<Response> => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const target = WOMPI_SANDBOX_ORIGIN + resource;
    beforeFetch();
    const response = await fetchImplementation(target, {
      ...init,
      redirect: 'error',
      signal: controller.signal,
    });
    if (response.url !== target) throw new Error('SANDBOX_PROVIDER_UNAVAILABLE');
    return response;
  } finally {
    clearTimeout(timer);
  }
};

export const loadSandboxRuntimeConfiguration = (
  config: AppConfig,
  secrets: RuntimeSecrets,
): Promise<SandboxRuntimeConfiguration | undefined> => {
  if (!config.paymentsEnabled || config.paymentAdapter !== 'sandbox') {
    return Promise.resolve(undefined);
  }
  const sandbox = secrets.sandbox;
  if (sandbox === undefined) throw new Error('SANDBOX_CONFIGURATION_INVALID');
  const termsPermalink = safePermalink(sandbox.termsPermalink);
  const personalDataPermalink = safePermalink(sandbox.personalDataPermalink);
  return Promise.resolve({
    contracts: [
      {
        type: 'TERMS',
        permalink: termsPermalink,
        version: sandboxContractVersion(termsPermalink),
      },
      {
        type: 'PERSONAL_DATA',
        permalink: personalDataPermalink,
        version: sandboxContractVersion(personalDataPermalink),
      },
    ],
  });
};

const allowedProviderRequest = (
  requestValue: SandboxTransportRequest,
  publicKey: string,
  privateKey: string,
): boolean => {
  const authorization = requestValue.headers.Authorization;
  if (
    requestValue.method === 'GET' &&
    requestValue.resource === `/v1/merchants/${encodeURIComponent(publicKey)}` &&
    Object.keys(requestValue.headers).length === 1 &&
    requestValue.headers.Accept === 'application/json'
  ) {
    return true;
  }
  if (
    requestValue.method === 'POST' &&
    requestValue.resource === '/v1/transactions' &&
    authorization === `Bearer ${privateKey}`
  ) {
    return true;
  }
  return (
    requestValue.method === 'GET' &&
    /^\/v1\/transactions\/[A-Za-z0-9._~%-]{1,512}$/u.test(requestValue.resource) &&
    authorization === `Bearer ${publicKey}`
  );
};

const providerOperation = (
  requestValue: SandboxTransportRequest,
  publicKey: string,
): SandboxEgressOperation | null => {
  if (
    requestValue.method === 'GET' &&
    requestValue.resource === `/v1/merchants/${encodeURIComponent(publicKey)}`
  ) {
    return 'MERCHANT_CONFIGURATION';
  }
  if (requestValue.method === 'POST' && requestValue.resource === '/v1/transactions') {
    return 'TRANSACTION_CREATE';
  }
  return requestValue.method === 'GET' && requestValue.resource.startsWith('/v1/transactions/')
    ? 'TRANSACTION_STATUS'
    : null;
};

export const createSandboxAcceptanceReader = (
  config: AppConfig,
  secrets: RuntimeSecrets,
  transport: SandboxTransport | undefined,
  options: Readonly<{
    now?: () => Date;
    cacheTtlMs?: number;
    timeoutMs?: number;
  }> = {},
): SandboxAcceptanceReader | undefined => {
  const publicKey = secrets.sandbox?.publicKey;
  if (
    !config.paymentsEnabled ||
    config.paymentAdapter !== 'sandbox' ||
    publicKey === undefined ||
    transport === undefined
  ) {
    return undefined;
  }
  const now = options.now ?? (() => new Date());
  const cacheTtlMs = options.cacheTtlMs ?? SANDBOX_ACCEPTANCE_CACHE_TTL_MS;
  const timeoutMs = options.timeoutMs ?? 8_000;
  if (
    !Number.isSafeInteger(cacheTtlMs) ||
    cacheTtlMs <= 0 ||
    cacheTtlMs > SANDBOX_ACCEPTANCE_CACHE_TTL_MS ||
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs <= 0 ||
    timeoutMs > 30_000
  ) {
    throw new Error('SANDBOX_CONFIGURATION_INVALID');
  }
  let cached:
    | Readonly<{ snapshot: SandboxProviderAcceptanceSnapshot; expiresAtMilliseconds: number }>
    | undefined;
  let inFlight: Promise<SandboxProviderAcceptanceSnapshot> | undefined;
  const read = async (correlationReference: string): Promise<SandboxProviderAcceptanceSnapshot> => {
    const currentTime = now();
    if (
      cached !== undefined &&
      currentTime.getTime() < cached.expiresAtMilliseconds &&
      snapshotUsable(cached.snapshot, currentTime, config.quoteTtlSeconds)
    ) {
      return cached.snapshot;
    }
    if (inFlight !== undefined) return inFlight;
    const operation = (async (): Promise<SandboxProviderAcceptanceSnapshot> => {
      const response = await transport({
        method: 'GET',
        resource: `/v1/merchants/${encodeURIComponent(publicKey)}`,
        headers: { Accept: 'application/json' },
        timeoutMs,
        correlationReference,
      });
      if (
        response.status < 200 ||
        response.status >= 300 ||
        response.contentType?.toLowerCase().includes('application/json') !== true
      ) {
        throw new Error('SANDBOX_PROVIDER_CONFIGURATION_INVALID');
      }
      const validatedAt = now();
      const snapshot = providerAcceptanceSnapshot(
        response.body,
        validatedAt,
        config.quoteTtlSeconds,
      );
      cached = {
        snapshot,
        expiresAtMilliseconds: validatedAt.getTime() + cacheTtlMs,
      };
      return snapshot;
    })();
    inFlight = operation;
    try {
      return await operation;
    } finally {
      if (inFlight === operation) inFlight = undefined;
    }
  };
  return read;
};

export const createSandboxTransport = (
  config: AppConfig,
  secrets: RuntimeSecrets,
  fetchImplementation: FetchImplementation = globalThis.fetch,
  now: () => Date = () => new Date(),
  recordEgress: SandboxEgressRecorder = () => undefined,
): SandboxTransport | undefined => {
  const publicKey = secrets.sandbox?.publicKey;
  const privateKey = secrets.sandbox?.privateKey;
  if (!config.paymentsEnabled || publicKey === undefined || privateKey === undefined)
    return undefined;
  return async (requestValue): Promise<SandboxTransportResponse> => {
    assertSandboxAuthorizationActive(config, now());
    if (!allowedProviderRequest(requestValue, publicKey, privateKey)) {
      throw new Error('SANDBOX_REQUEST_BLOCKED');
    }
    const operation = providerOperation(requestValue, publicKey);
    if (
      operation === null ||
      !/^[A-Za-z0-9._~-]{1,512}$/u.test(requestValue.correlationReference)
    ) {
      throw new Error('SANDBOX_REQUEST_BLOCKED');
    }
    if (config.candidateSha === undefined || config.releaseId === undefined) {
      throw new Error('SANDBOX_CONFIGURATION_INVALID');
    }
    const response = await request(
      fetchImplementation,
      requestValue.resource,
      {
        method: requestValue.method,
        headers: requestValue.headers,
        ...(requestValue.body === undefined ? {} : { body: JSON.stringify(requestValue.body) }),
      },
      requestValue.timeoutMs,
      () => {
        recordEgress({
          eventName: SANDBOX_EGRESS_EVENT_NAME,
          schemaVersion: 1,
          candidateSha: config.candidateSha as string,
          releaseId: config.releaseId as string,
          providerHostSha256: SANDBOX_PROVIDER_HOST_SHA256,
          operation,
          method: requestValue.method,
          correlationSha256: sandboxEgressCorrelationSha256(requestValue.correlationReference),
          containsSensitiveData: false,
        });
      },
    );
    const contentType = response.headers.get('content-type');
    let body: unknown = null;
    if (contentType?.toLowerCase().includes('application/json') === true) {
      const text = await response.text();
      if (text.length > 65_536) throw new Error('SANDBOX_PROVIDER_UNAVAILABLE');
      try {
        body = text.length === 0 ? null : (JSON.parse(text) as unknown);
      } catch {
        body = null;
      }
    }
    return { status: response.status, contentType, body };
  };
};
