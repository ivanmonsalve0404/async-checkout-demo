import { createHash } from 'node:crypto';

import type { AppConfig } from '../configuration/app-config';
import type { RuntimeSecrets } from '../configuration/runtime-secrets';
import type { MerchantContractSet } from '../../application/ports/merchant-contract';
import type {
  SandboxTransport,
  SandboxTransportRequest,
  SandboxTransportResponse,
} from './sandbox-payment-provider';

export const WOMPI_SANDBOX_ORIGIN = 'https://sandbox.wompi.co' as const;

export interface SandboxRuntimeConfiguration {
  readonly contracts: MerchantContractSet;
  readonly providerAcceptances: Readonly<{
    terms: string;
    personalData: string;
  }>;
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
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error('SANDBOX_CONFIGURATION_INVALID');
  }
  if (
    parsed.protocol !== 'https:' ||
    !(parsed.hostname === 'wompi.co' || parsed.hostname.endsWith('.wompi.co')) ||
    parsed.username.length > 0 ||
    parsed.password.length > 0
  ) {
    throw new Error('SANDBOX_CONFIGURATION_INVALID');
  }
  return parsed.toString();
};

const version = (permalink: string): string =>
  'provider-' + createHash('sha256').update(permalink).digest('hex').slice(0, 16);

const request = async (
  fetchImplementation: FetchImplementation,
  resource: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImplementation(WOMPI_SANDBOX_ORIGIN + resource, {
      ...init,
      redirect: 'error',
      signal: controller.signal,
    });
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
      { type: 'TERMS', permalink: termsPermalink, version: version(termsPermalink) },
      {
        type: 'PERSONAL_DATA',
        permalink: personalDataPermalink,
        version: version(personalDataPermalink),
      },
    ],
    providerAcceptances: {
      terms: safeString(sandbox.termsAcceptanceToken),
      personalData: safeString(sandbox.personalDataAcceptanceToken),
    },
  });
};

const allowedProviderRequest = (
  requestValue: SandboxTransportRequest,
  publicKey: string,
  privateKey: string,
): boolean => {
  const authorization = requestValue.headers.Authorization;
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

export const createSandboxTransport = (
  config: AppConfig,
  secrets: RuntimeSecrets,
  fetchImplementation: FetchImplementation = globalThis.fetch,
  now: () => Date = () => new Date(),
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
    const response = await request(
      fetchImplementation,
      requestValue.resource,
      {
        method: requestValue.method,
        headers: requestValue.headers,
        ...(requestValue.body === undefined ? {} : { body: JSON.stringify(requestValue.body) }),
      },
      requestValue.timeoutMs,
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
