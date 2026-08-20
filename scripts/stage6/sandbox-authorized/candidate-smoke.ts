import { strict as assert } from 'node:assert';
import { createHash, randomBytes, webcrypto } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import type { Result } from '../../../apps/api/src/application/result/result';
import type {
  ProviderObservation,
  ProviderPaymentCommand,
} from '../../../apps/api/src/application/ports/payment-provider';
import type {
  Checkout,
  PaymentStatus,
  Transaction,
} from '../../../apps/api/src/domain/checkout/checkout';
import { SandboxPaymentProvider } from '../../../apps/api/src/infrastructure/payment/sandbox-payment-provider';
import { redactSandboxDiagnostic } from '../../../apps/api/src/infrastructure/payment/sandbox-payment-provider';
import {
  isProviderAcceptanceJwtUsable,
  isWompiProviderPermalink,
} from '../../../apps/api/src/infrastructure/configuration/runtime-secrets';
import { InMemoryCatalogRepository } from '../../../apps/api/src/infrastructure/persistence/in-memory-catalog.repository';
import { InMemoryCheckoutRepository } from '../../../apps/api/src/infrastructure/persistence/in-memory-checkout.repository';
import { createProductSeed } from '../../../apps/api/src/infrastructure/persistence/product-seed';
import { SystemRuntimeSecurity } from '../../../apps/api/src/infrastructure/security/system-runtime-security';
import {
  SandboxCardTokenizationAdapter,
  TokenizationError,
  WOMPI_CARD_TOKENIZATION_RESOURCE,
  WOMPI_SANDBOX_ORIGIN,
  type SandboxTokenizationRequest,
} from '../../../apps/web/src/features/checkout/services/payment-tokenization';
import type { CardInput } from '../../../apps/web/src/features/checkout/validation/card-validation';
import {
  EXPECTED_EXTERNAL_REQUESTS,
  SANDBOX_HOST,
  SandboxAuthorizationError,
  loadAuthorizationContext,
  revalidateAuthorizationContext,
  validateRequiredEnvironment,
} from './authorization-policy.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(HERE, '..', '..', '..');
const AUTHORIZATION_SCHEMA_PATH = path.join(HERE, 'authorization.schema.json');
const EXPECTED_REQUESTS = EXPECTED_EXTERNAL_REQUESTS;
const QUOTE_TTL_SECONDS = 900;
const ALLOWED_RESULT_STATES = new Set(['APPROVED', 'DECLINED', 'ERROR', 'PENDING']);
const CHECKS = [
  ['AUTH02-E6-01', 'acceptance-configuration-observed'],
  ['AUTH02-E6-02', 'authorized-test-payment-method-created'],
  ['AUTH02-E6-03', 'local-pending-created-first'],
  ['AUTH02-E6-04', 'provider-sandbox-transaction-created'],
  ['AUTH02-E6-05', 'provider-status-polled'],
  ['AUTH02-E6-06', 'amount-currency-reference-validated'],
  ['AUTH02-E6-07', 'provider-errors-redacted'],
  ['AUTH02-E6-08', 'reconciliation-replay-idempotent'],
] as const;

type RequestCategory =
  | 'configurationReads'
  | 'paymentMethodCreations'
  | 'transactionCreates'
  | 'statusReads'
  | 'errorMappingProbes'
  | 'reconciliationReplays';

class CandidateSmokeError extends Error {
  public constructor(public readonly code: string) {
    super(code);
    this.name = 'CandidateSmokeError';
  }
}

const fail = (code: string): never => {
  throw new CandidateSmokeError(code);
};
const valueOf = <T, E>(result: Result<T, E>, failureCode: string): T =>
  result.ok ? result.value : fail(failureCode);
const sha256 = (value: string | Buffer): string => createHash('sha256').update(value).digest('hex');
const required = (name: string): string => {
  const value = process.env[name];
  return typeof value === 'string' && value.length > 0
    ? value
    : fail('REQUIRED_ENVIRONMENT_MISSING');
};
const record = (value: unknown, failureCode: string): Readonly<Record<string, unknown>> => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) fail(failureCode);
  return value as Readonly<Record<string, unknown>>;
};
const safeString = (value: unknown, maximum: number, failureCode: string): string =>
  typeof value === 'string' && value.length > 0 && value.length <= maximum
    ? value
    : fail(failureCode);
const canonicalHttpsUrl = (value: unknown, failureCode: string): string => {
  const candidate = safeString(value, 2_048, failureCode);
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return fail(failureCode);
  }
  if (
    parsed.protocol !== 'https:' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    !isWompiProviderPermalink(candidate)
  ) {
    fail(failureCode);
  }
  return parsed.toString();
};
const exactKeys = (
  value: unknown,
  keys: readonly string[],
): value is Readonly<Record<string, unknown>> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.hasOwn(value, key));

interface ParentExecutionCapability {
  readonly type: 'AUTH02_EXECUTE_CAPABILITY';
  readonly nonce: string;
  readonly parentPid: number;
  readonly commitSha: string;
  readonly authorizationSha256: string;
  readonly executionClaimSha256: string;
  readonly executionBindingSha256: string;
  readonly deterministicReference: string;
}

const receiveParentCapability = async (): Promise<ParentExecutionCapability> => {
  if (!process.connected || process.send === undefined) fail('PARENT_CAPABILITY_REQUIRED');
  return new Promise<ParentExecutionCapability>((resolve, reject) => {
    const onMessage = (message: unknown): void => {
      if (
        !exactKeys(message, [
          'type',
          'nonce',
          'parentPid',
          'commitSha',
          'authorizationSha256',
          'executionClaimSha256',
          'executionBindingSha256',
          'deterministicReference',
        ]) ||
        message.type !== 'AUTH02_EXECUTE_CAPABILITY' ||
        typeof message.nonce !== 'string' ||
        !/^[A-Za-z0-9_-]{43}$/u.test(message.nonce) ||
        message.parentPid !== process.ppid ||
        typeof message.commitSha !== 'string' ||
        !/^[0-9a-f]{40}$/u.test(message.commitSha) ||
        typeof message.authorizationSha256 !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(message.authorizationSha256) ||
        typeof message.executionClaimSha256 !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(message.executionClaimSha256) ||
        typeof message.executionBindingSha256 !== 'string' ||
        !/^[0-9a-f]{64}$/u.test(message.executionBindingSha256) ||
        typeof message.deterministicReference !== 'string' ||
        message.deterministicReference.length > 64 ||
        !/^e6-(?:rel|pre)-[0-9]+-[0-9]+-[0-9a-f]{12}$/u.test(message.deterministicReference)
      ) {
        rejectCapability('PARENT_CAPABILITY_INVALID');
        return;
      }
      cleanup();
      resolve(message as unknown as ParentExecutionCapability);
    };
    const onDisconnect = (): void => rejectCapability('PARENT_CAPABILITY_DISCONNECTED');
    const timeout = setTimeout(() => rejectCapability('PARENT_CAPABILITY_TIMEOUT'), 3_000);
    const cleanup = (): void => {
      clearTimeout(timeout);
      process.off('message', onMessage);
      process.off('disconnect', onDisconnect);
    };
    const rejectCapability = (code: string): void => {
      cleanup();
      if (process.connected) process.disconnect();
      reject(new CandidateSmokeError(code));
    };
    process.once('message', onMessage);
    process.once('disconnect', onDisconnect);
  });
};

const acknowledgeParentCapability = async (
  capability: ParentExecutionCapability,
): Promise<void> => {
  if (!process.connected || process.send === undefined) fail('PARENT_CAPABILITY_DISCONNECTED');
  await new Promise<void>((resolve, reject) => {
    process.send?.(
      {
        type: 'AUTH02_EXECUTION_ACCEPTED',
        nonceSha256: sha256(capability.nonce),
        childPid: process.pid,
      },
      (error) => {
        if (error === null) resolve();
        else reject(new CandidateSmokeError('PARENT_CAPABILITY_ACK_FAILED'));
      },
    );
  });
  if (process.connected) process.disconnect();
};

interface RequestCounters {
  configurationReads: number;
  paymentMethodCreations: number;
  transactionCreates: number;
  statusReads: number;
  errorMappingProbes: number;
  reconciliationReplays: number;
}

interface GuardedSandboxNetworkOptions {
  readonly maximumRequests: number;
  readonly publicKey: string;
  readonly transactionAuthorizationValue: string;
  readonly authorizationGate: () => Date;
  readonly beforeTransactionCreate: () => Promise<void>;
  readonly fetchImplementation?: typeof fetch;
  readonly killSwitchIsArmed?: () => boolean;
}

class GuardedSandboxNetwork {
  private readonly counters: RequestCounters = {
    configurationReads: 0,
    paymentMethodCreations: 0,
    transactionCreates: 0,
    statusReads: 0,
    errorMappingProbes: 0,
    reconciliationReplays: 0,
  };
  private readonly maximumRequests: number;
  private readonly publicKey: string;
  private readonly transactionAuthorizationValue: string;
  private readonly authorizationGate: () => Date;
  private readonly beforeTransactionCreate: () => Promise<void>;
  private readonly fetchImplementation: typeof fetch;
  private readonly killSwitchIsArmed: () => boolean;

  public constructor(options: GuardedSandboxNetworkOptions) {
    this.maximumRequests = options.maximumRequests;
    this.publicKey = options.publicKey;
    this.transactionAuthorizationValue = options.transactionAuthorizationValue;
    this.authorizationGate = options.authorizationGate;
    this.beforeTransactionCreate = options.beforeTransactionCreate;
    this.fetchImplementation = options.fetchImplementation ?? fetch;
    this.killSwitchIsArmed =
      options.killSwitchIsArmed ??
      (() => process.env.STAGE6_SANDBOX_KILL_SWITCH === 'ARMED_AUTH02');
  }

  public async json(
    category: RequestCategory,
    method: 'GET' | 'POST',
    resource: string,
    headers: Readonly<Record<string, string>>,
    body: unknown,
    timeoutMs: number,
  ): Promise<Readonly<{ status: number; contentType: string | null; body: unknown }>> {
    this.assertExecutionAuthorized();
    this.assertRequest(category, method, resource, headers, body);
    const nextTotal = this.total() + 1;
    if (nextTotal > this.maximumRequests || nextTotal > EXPECTED_REQUESTS) {
      fail('REQUEST_BUDGET_EXCEEDED');
    }
    this.counters[category] += 1;
    if (category === 'transactionCreates') await this.beforeTransactionCreate();
    this.assertExecutionAuthorized();
    const target = new URL(resource, WOMPI_SANDBOX_ORIGIN);
    if (target.origin !== WOMPI_SANDBOX_ORIGIN) fail('REQUEST_OUTSIDE_ALLOWLIST');
    let response: Response;
    try {
      response = await this.fetchImplementation(target, {
        method,
        headers,
        ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
        redirect: 'error',
        cache: 'no-store',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      this.assertExecutionAuthorized();
      return fail('SANDBOX_TRANSPORT_FAILED');
    }
    this.assertExecutionAuthorized();
    if (response.redirected || response.url.length === 0) fail('SANDBOX_REDIRECT_REJECTED');
    const responseUrl = new URL(response.url);
    if (responseUrl.origin !== WOMPI_SANDBOX_ORIGIN) fail('SANDBOX_RESPONSE_OUTSIDE_ALLOWLIST');
    let text: string;
    try {
      text = await response.text();
    } catch {
      this.assertExecutionAuthorized();
      return fail('SANDBOX_RESPONSE_READ_FAILED');
    }
    this.assertExecutionAuthorized();
    if (Buffer.byteLength(text, 'utf8') > 65_536) fail('SANDBOX_RESPONSE_TOO_LARGE');
    let responseBody: unknown;
    try {
      responseBody = text.length === 0 ? null : JSON.parse(text);
    } catch {
      responseBody = null;
    }
    this.assertExecutionAuthorized();
    return {
      status: response.status,
      contentType: response.headers.get('content-type'),
      body: responseBody,
    };
  }

  public summary(): Readonly<RequestCounters & { total: number }> {
    return { ...this.counters, total: this.total() };
  }

  private total(): number {
    return (
      this.counters.configurationReads +
      this.counters.paymentMethodCreations +
      this.counters.transactionCreates +
      this.counters.statusReads +
      this.counters.errorMappingProbes +
      this.counters.reconciliationReplays
    );
  }

  private assertExecutionAuthorized(): void {
    if (!this.killSwitchIsArmed()) fail('KILL_SWITCH_OPEN');
    this.authorizationGate();
  }

  private assertRequest(
    category: RequestCategory,
    method: 'GET' | 'POST',
    resource: string,
    headers: Readonly<Record<string, string>>,
    body: unknown,
  ): void {
    if (!resource.startsWith('/v1/') || resource.includes('?') || resource.includes('#')) {
      fail('REQUEST_RESOURCE_INVALID');
    }
    const authorization = headers.Authorization;
    if (category === 'configurationReads') {
      const merchantResource = `/v1/merchants/${encodeURIComponent(this.publicKey)}`;
      const keyResource = '/v1/tokens/keys/tokenization';
      const merchantRequest =
        method === 'GET' &&
        resource === merchantResource &&
        body === undefined &&
        authorization === undefined &&
        Object.keys(headers).length === 1 &&
        headers.Accept === 'application/json';
      const keyRequest =
        method === 'GET' &&
        resource === keyResource &&
        body === undefined &&
        authorization === `Bearer ${this.publicKey}` &&
        Object.keys(headers).length === 2 &&
        headers.Accept === 'application/json';
      if (!merchantRequest && !keyRequest) fail('CONFIGURATION_REQUEST_INVALID');
    } else if (category === 'paymentMethodCreations') {
      const payload = record(body, 'TOKENIZATION_BODY_INVALID');
      if (
        method !== 'POST' ||
        resource !== WOMPI_CARD_TOKENIZATION_RESOURCE ||
        authorization !== `Bearer ${this.publicKey}` ||
        Object.keys(payload).length !== 1 ||
        typeof payload.payload !== 'string'
      ) {
        fail('TOKENIZATION_REQUEST_INVALID');
      }
      if (this.counters.paymentMethodCreations >= 1) fail('TOKENIZATION_MUTATION_LIMIT');
    } else if (category === 'transactionCreates') {
      if (
        method !== 'POST' ||
        resource !== '/v1/transactions' ||
        authorization !== `Bearer ${this.transactionAuthorizationValue}` ||
        this.counters.transactionCreates >= 1
      ) {
        fail('TRANSACTION_MUTATION_LIMIT');
      }
    } else if (
      method !== 'GET' ||
      !/^\/v1\/transactions\/[A-Za-z0-9._~%-]{1,512}$/u.test(resource) ||
      authorization !== `Bearer ${this.publicKey}`
    ) {
      fail('TRANSACTION_READ_INVALID');
    }
  }
}
const compactJweEncryptor = async (publicKeyPem: string, input: CardInput): Promise<string> => {
  const expiry = /^(\d{2})\/(\d{2})$/u.exec(input.expiry.trim()) ?? fail('CARD_EXPIRY_INVALID');
  const expiryMonth = expiry[1] ?? fail('CARD_EXPIRY_INVALID');
  const expiryYear = expiry[2] ?? fail('CARD_EXPIRY_INVALID');
  const der = Buffer.from(
    publicKeyPem
      .replace(/-----BEGIN PUBLIC KEY-----/gu, '')
      .replace(/-----END PUBLIC KEY-----/gu, '')
      .replace(/\s/gu, ''),
    'base64',
  );
  if (der.length < 128 || der.length > 8_192) fail('TOKENIZATION_PUBLIC_KEY_INVALID');
  const rsaKey = await (async () => {
    try {
      return await webcrypto.subtle.importKey(
        'spki',
        der,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt'],
      );
    } catch {
      return fail('TOKENIZATION_PUBLIC_KEY_INVALID');
    }
  })();
  const protectedHeader = Buffer.from(
    JSON.stringify({ alg: 'RSA-OAEP-256', enc: 'A256GCM' }),
    'utf8',
  ).toString('base64url');
  const cek = randomBytes(32);
  const iv = randomBytes(12);
  const aesKey = await webcrypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const plaintext = Buffer.from(
    JSON.stringify({
      number: input.number.replace(/\D/gu, ''),
      cvc: input.securityCode.replace(/\D/gu, ''),
      exp_month: expiryMonth,
      exp_year: expiryYear,
      card_holder: input.holderName.trim(),
    }),
    'utf8',
  );
  const encryptedKey = new Uint8Array(
    await webcrypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaKey, cek),
  );
  const ciphertextAndTag = new Uint8Array(
    await webcrypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        additionalData: Buffer.from(protectedHeader, 'utf8'),
        tagLength: 128,
      },
      aesKey,
      plaintext,
    ),
  );
  if (ciphertextAndTag.length <= 16) fail('TOKENIZATION_ENCRYPTION_FAILED');
  const ciphertext = ciphertextAndTag.subarray(0, ciphertextAndTag.length - 16);
  const tag = ciphertextAndTag.subarray(ciphertextAndTag.length - 16);
  return [
    protectedHeader,
    Buffer.from(encryptedKey).toString('base64url'),
    iv.toString('base64url'),
    Buffer.from(ciphertext).toString('base64url'),
    Buffer.from(tag).toString('base64url'),
  ].join('.');
};

interface AcceptanceConfiguration {
  readonly termsToken: string;
  readonly termsPermalink: string;
  readonly personalDataToken: string;
  readonly personalDataPermalink: string;
}

const acceptanceConfiguration = (body: unknown, now: Date): AcceptanceConfiguration => {
  const envelope = record(body, 'MERCHANT_CONFIGURATION_INVALID');
  const data = record(envelope.data, 'MERCHANT_CONFIGURATION_INVALID');
  const terms = record(data.presigned_acceptance, 'MERCHANT_CONFIGURATION_INVALID');
  const personalData = record(data.presigned_personal_data_auth, 'MERCHANT_CONFIGURATION_INVALID');
  if (
    !exactKeys(terms, ['acceptance_token', 'permalink', 'type']) ||
    terms.type !== 'END_USER_POLICY' ||
    !exactKeys(personalData, ['acceptance_token', 'permalink', 'type']) ||
    personalData.type !== 'PERSONAL_DATA_AUTH'
  ) {
    fail('MERCHANT_CONFIGURATION_INVALID');
  }
  const termsToken = safeString(terms.acceptance_token, 8_192, 'MERCHANT_CONFIGURATION_INVALID');
  const personalDataToken = safeString(
    personalData.acceptance_token,
    8_192,
    'MERCHANT_CONFIGURATION_INVALID',
  );
  if (
    !isProviderAcceptanceJwtUsable(termsToken, now, QUOTE_TTL_SECONDS) ||
    !isProviderAcceptanceJwtUsable(personalDataToken, now, QUOTE_TTL_SECONDS)
  ) {
    fail('MERCHANT_CONFIGURATION_INVALID');
  }
  return {
    termsToken,
    termsPermalink: canonicalHttpsUrl(terms.permalink, 'MERCHANT_CONFIGURATION_INVALID'),
    personalDataToken,
    personalDataPermalink: canonicalHttpsUrl(
      personalData.permalink,
      'MERCHANT_CONFIGURATION_INVALID',
    ),
  };
};

const tokenizationPublicKey = (body: unknown): string => {
  const envelope = record(body, 'TOKENIZATION_CONFIGURATION_INVALID');
  const data = record(envelope.data, 'TOKENIZATION_CONFIGURATION_INVALID');
  const publicKey = safeString(data.publicKey, 8_192, 'TOKENIZATION_CONFIGURATION_INVALID');
  if (!publicKey.includes('BEGIN PUBLIC KEY')) fail('TOKENIZATION_CONFIGURATION_INVALID');
  return publicKey;
};

const applyObservation = async (
  repository: InMemoryCheckoutRepository,
  transactionId: string,
  reference: string,
  amountInCents: number,
  observation: ProviderObservation,
  attempts: number,
  now: string,
): Promise<Transaction> => {
  const current =
    valueOf(await repository.findTransaction(transactionId), 'LOCAL_TRANSACTION_READ_FAILED') ??
    fail('LOCAL_TRANSACTION_MISSING');
  const status = providerPaymentStatus(observation.status);
  if (
    observation.reference !== reference ||
    observation.amountInCents !== amountInCents ||
    observation.currency !== 'COP' ||
    (current.providerId !== undefined && current.providerId !== observation.providerId)
  ) {
    fail('PROVIDER_OBSERVATION_DIVERGENT');
  }
  const acknowledged = valueOf(
    await repository.acknowledgeProvider(transactionId, observation.providerId, status, now, {
      attempts,
      lastCheckedAt: now,
      nextCheckAt: now,
    }),
    'LOCAL_ACKNOWLEDGEMENT_FAILED',
  );
  if (status === 'PENDING') return acknowledged;
  return valueOf(
    await repository.finalize(transactionId, status, status, undefined, now),
    'LOCAL_FINALIZATION_FAILED',
  );
};

const providerPaymentStatus = (status: ProviderObservation['status']): PaymentStatus =>
  status === 'PENDING' ||
  status === 'APPROVED' ||
  status === 'DECLINED' ||
  status === 'VOIDED' ||
  status === 'ERROR'
    ? status
    : fail('PROVIDER_OBSERVATION_DIVERGENT');

const stableEffects = (
  beforeProduct: Readonly<{ onHand: number; reserved: number; available: number; version: number }>,
  afterProduct: Readonly<{ onHand: number; reserved: number; available: number; version: number }>,
  beforeTransaction: Transaction,
  afterTransaction: Transaction,
): boolean =>
  beforeProduct.onHand === afterProduct.onHand &&
  beforeProduct.reserved === afterProduct.reserved &&
  beforeProduct.available === afterProduct.available &&
  beforeProduct.version === afterProduct.version &&
  beforeTransaction.paymentStatus === afterTransaction.paymentStatus &&
  beforeTransaction.reservationStatus === afterTransaction.reservationStatus &&
  beforeTransaction.deliveryId === afterTransaction.deliveryId &&
  beforeTransaction.effectsApplied === afterTransaction.effectsApplied;

const monotonicProviderStatus = (
  previous: ProviderObservation,
  next: ProviderObservation,
): void => {
  if (previous.status !== 'PENDING' && previous.status !== next.status) {
    fail('PROVIDER_FINAL_STATE_REGRESSION');
  }
};

const selfTestChild = async (): Promise<void> => {
  const publicKey = ['pub', 'test', 'candidate-canary'].join('_');
  const privateKey = ['prv', 'test', 'candidate-canary'].join('_');
  const activeAt = new Date('2026-08-16T12:00:00.123Z');
  const merchantConfiguration = (termsToken: string, personalDataToken: string) => ({
    data: {
      presigned_acceptance: {
        acceptance_token: termsToken,
        permalink: 'https://sandbox.wompi.co/terms/test',
        type: 'END_USER_POLICY',
      },
      presigned_personal_data_auth: {
        acceptance_token: personalDataToken,
        permalink: 'https://sandbox.wompi.co/personal-data/test',
        type: 'PERSONAL_DATA_AUTH',
      },
    },
  });
  const jwt = [
    Buffer.from('{"alg":"RS256","typ":"JWT"}', 'utf8').toString('base64url'),
    Buffer.from(
      JSON.stringify({ exp: Math.floor(activeAt.getTime() / 1_000) + QUOTE_TTL_SECONDS + 60 }),
      'utf8',
    ).toString('base64url'),
    Buffer.from('synthetic-signature', 'utf8').toString('base64url'),
  ].join('.');
  const jwtFromSources = (header: string, payload: string): string =>
    [
      Buffer.from(header, 'utf8').toString('base64url'),
      Buffer.from(payload, 'utf8').toString('base64url'),
      Buffer.from('synthetic-signature', 'utf8').toString('base64url'),
    ].join('.');
  const futurePayload = JSON.stringify({
    exp: Math.floor(activeAt.getTime() / 1_000) + QUOTE_TTL_SECONDS + 60,
  });
  assert.equal(acceptanceConfiguration(merchantConfiguration(jwt, jwt), activeAt).termsToken, jwt);
  let postContinuations = 0;
  const parseBeforePost = (termsToken: string): void => {
    acceptanceConfiguration(merchantConfiguration(termsToken, jwt), activeAt);
    postContinuations += 1;
  };
  for (const malformed of [
    'opaque-acceptance-token',
    'header.payload',
    'a.b.c.d',
    jwtFromSources('not-json', futurePayload),
    jwtFromSources('[]', futurePayload),
    jwtFromSources('{"alg":"none","typ":"JWT"}', futurePayload),
    jwtFromSources('{"alg":"RS256","typ":"JWT"}', 'not-json'),
    jwtFromSources('{"alg":"RS256","typ":"JWT"}', '[]'),
  ]) {
    assert.throws(() => parseBeforePost(malformed), /MERCHANT_CONFIGURATION_INVALID/u);
  }
  assert.equal(postContinuations, 0);
  let expired = false;
  let syntheticCalls = 0;
  const syntheticFetch: typeof fetch = (input) => {
    syntheticCalls += 1;
    const target =
      input instanceof URL ? input : new URL(typeof input === 'string' ? input : input.url);
    const response = new Response('{"data":{}}', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    Object.defineProperty(response, 'url', { value: target.toString() });
    return Promise.resolve(response);
  };
  const network = new GuardedSandboxNetwork({
    maximumRequests: EXPECTED_REQUESTS,
    publicKey,
    transactionAuthorizationValue: privateKey,
    authorizationGate: () => (expired ? fail('AUTHORIZATION_NOT_ACTIVE') : new Date(activeAt)),
    beforeTransactionCreate: () => Promise.resolve(),
    fetchImplementation: syntheticFetch,
    killSwitchIsArmed: () => true,
  });
  await network.json(
    'configurationReads',
    'GET',
    `/v1/merchants/${encodeURIComponent(publicKey)}`,
    { Accept: 'application/json' },
    undefined,
    100,
  );
  expired = true;
  await assert.rejects(
    network.json(
      'transactionCreates',
      'POST',
      '/v1/transactions',
      { Authorization: `Bearer ${privateKey}` },
      {},
      100,
    ),
    /AUTHORIZATION_NOT_ACTIVE/u,
  );
  assert.equal(syntheticCalls, 1);
  assert.equal(network.summary().transactionCreates, 0);

  let expiredDuringRequest = false;
  let postFetchCalls = 0;
  const postFetchNetwork = new GuardedSandboxNetwork({
    maximumRequests: EXPECTED_REQUESTS,
    publicKey,
    transactionAuthorizationValue: privateKey,
    authorizationGate: () =>
      expiredDuringRequest ? fail('AUTHORIZATION_NOT_ACTIVE') : new Date(activeAt),
    beforeTransactionCreate: () => Promise.resolve(),
    fetchImplementation: async (input) => {
      postFetchCalls += 1;
      expiredDuringRequest = true;
      return syntheticFetch(input);
    },
    killSwitchIsArmed: () => true,
  });
  await assert.rejects(
    postFetchNetwork.json(
      'configurationReads',
      'GET',
      `/v1/merchants/${encodeURIComponent(publicKey)}`,
      { Accept: 'application/json' },
      undefined,
      100,
    ),
    /AUTHORIZATION_NOT_ACTIVE/u,
  );
  assert.equal(postFetchCalls, 1);
  assert.equal(postFetchNetwork.summary().total, 1);
  process.stdout.write(
    'stage-6 authorized sandbox candidate self-test: PASS (0 external requests)\n',
  );
};

const run = async (): Promise<void> => {
  const arguments_ = process.argv.slice(2);
  if (arguments_.length === 1 && arguments_[0] === '--self-test-child') {
    await selfTestChild();
    return;
  }
  if (arguments_.length !== 1 || arguments_[0] !== '--authorized-child') {
    fail('CHILD_INVOCATION_INVALID');
  }
  const parentCapability = await receiveParentCapability();
  const authorizationContext = loadAuthorizationContext({
    repositoryRoot: REPOSITORY_ROOT,
    schemaPath: AUTHORIZATION_SCHEMA_PATH,
    sourcePath: required('STAGE6_SANDBOX_AUTHORIZATION'),
    now: new Date(),
    expectedCommitSha: parentCapability.commitSha,
  });
  if (authorizationContext.sourceSha256 !== parentCapability.authorizationSha256) {
    fail('CHILD_AUTHORIZATION_MISMATCH');
  }
  validateRequiredEnvironment(process.env, authorizationContext.authorization);
  const authorizationGate = (): Date => {
    const verifiedAt = new Date();
    const current = revalidateAuthorizationContext(authorizationContext, verifiedAt);
    validateRequiredEnvironment(process.env, current.authorization);
    return verifiedAt;
  };
  authorizationGate();
  await acknowledgeParentCapability(parentCapability);
  const commitSha = authorizationContext.commitSha;
  const runId = authorizationContext.authorization.runId;
  const maximumRequests = authorizationContext.authorization.authorization.maxRequests;
  const publicKey = required('STAGE6_SANDBOX_PUBLIC_KEY');
  const privateKey = required('STAGE6_SANDBOX_PRIVATE_KEY');
  const integritySecret = required('STAGE6_SANDBOX_INTEGRITY_SECRET');
  const card: CardInput = {
    number: required('STAGE6_SANDBOX_CARD_NUMBER'),
    expiry: required('STAGE6_SANDBOX_CARD_EXPIRY'),
    securityCode: required('STAGE6_SANDBOX_CARD_CVC'),
    holderName: required('STAGE6_SANDBOX_CARD_HOLDER'),
  };
  const customerEmail = required('STAGE6_SANDBOX_CUSTOMER_EMAIL');
  const startedAtUtc = authorizationGate().toISOString();
  const reference = parentCapability.deterministicReference;
  const transactionId = `transaction_${randomBytes(18).toString('base64url')}`;
  const checkoutId = `checkout_${randomBytes(18).toString('base64url')}`;
  const productId = 'product-e6-sandbox';
  const amountInCents = 3_200_000;
  const catalog = new InMemoryCatalogRepository([
    createProductSeed(productId, 'http://127.0.0.1:1', 1),
  ]);
  const repository = new InMemoryCheckoutRepository(catalog);
  const runtime = new SystemRuntimeSecurity(() => new Date(startedAtUtc), Buffer.alloc(32, 7));
  const rawCapability = `${checkoutId}.${randomBytes(32).toString('base64url')}`;
  const capabilityHash = runtime.hashCapability(rawCapability);
  const checkout: Checkout = {
    checkoutId,
    status: 'READY',
    version: 3,
    capabilityHash,
    productId,
    quote: {
      quoteId: `quote_${randomBytes(18).toString('base64url')}`,
      version: 1,
      productId,
      quantity: 1,
      subtotal: { amountInCents: 2_500_000, currency: 'COP' },
      baseFee: { amountInCents: 200_000, currency: 'COP' },
      deliveryFee: { amountInCents: 500_000, currency: 'COP' },
      total: { amountInCents, currency: 'COP' },
      expiresAt: new Date(Date.parse(startedAtUtc) + 900_000).toISOString(),
    },
    customer: {
      customerId: `customer_${randomBytes(18).toString('base64url')}`,
      checkoutId,
      version: 1,
      fullName: card.holderName,
      email: customerEmail,
      phone: '+570000000000',
    },
    deliveryDetails: {
      checkoutId,
      version: 1,
      addressLine1: 'Sandbox synthetic destination',
      city: 'Bogota',
      region: 'Cundinamarca',
    },
    expiresAt: new Date(Date.parse(startedAtUtc) + 1_800_000).toISOString(),
  };
  valueOf(await repository.create(checkout), 'LOCAL_CHECKOUT_CREATE_FAILED');

  let localPendingObservedFirst = false;
  const network = new GuardedSandboxNetwork({
    maximumRequests,
    publicKey,
    transactionAuthorizationValue: privateKey,
    authorizationGate,
    beforeTransactionCreate: async () => {
      const pending = valueOf(
        await repository.findTransaction(transactionId),
        'LOCAL_PENDING_READ_FAILED',
      );
      if (
        pending === null ||
        pending.paymentStatus !== 'PENDING' ||
        pending.reservationStatus !== 'ACTIVE' ||
        pending.dispatchPhase !== 'SENDING'
      ) {
        fail('LOCAL_PENDING_NOT_DURABLE_BEFORE_PROVIDER');
      }
      localPendingObservedFirst = true;
    },
  });

  const merchantResponse = await network.json(
    'configurationReads',
    'GET',
    `/v1/merchants/${encodeURIComponent(publicKey)}`,
    { Accept: 'application/json' },
    undefined,
    8_000,
  );
  if (merchantResponse.status < 200 || merchantResponse.status >= 300) {
    fail('MERCHANT_CONFIGURATION_UNAVAILABLE');
  }
  const acceptances = acceptanceConfiguration(merchantResponse.body, authorizationGate());
  const encryptionKeyResponse = await network.json(
    'configurationReads',
    'GET',
    '/v1/tokens/keys/tokenization',
    { Accept: 'application/json', Authorization: `Bearer ${publicKey}` },
    undefined,
    8_000,
  );
  if (encryptionKeyResponse.status < 200 || encryptionKeyResponse.status >= 300) {
    fail('TOKENIZATION_CONFIGURATION_UNAVAILABLE');
  }
  const encryptionPublicKey = tokenizationPublicKey(encryptionKeyResponse.body);

  const tokenization = new SandboxCardTokenizationAdapter({
    enabled: true,
    environment: 'sandbox',
    origin: WOMPI_SANDBOX_ORIGIN,
    publicKey,
    expiresAtUtc: authorizationContext.authorization.authorization.expiresAtUtc,
    now: () => authorizationGate().getTime(),
    encrypt: (input) => compactJweEncryptor(encryptionPublicKey, input),
    transport: async (request: SandboxTokenizationRequest) => {
      if (
        request.origin !== WOMPI_SANDBOX_ORIGIN ||
        request.redirect !== 'error' ||
        request.resource !== WOMPI_CARD_TOKENIZATION_RESOURCE
      ) {
        fail('CLIENT_TOKENIZATION_BOUNDARY_INVALID');
      }
      return network.json(
        'paymentMethodCreations',
        request.method,
        request.resource,
        request.headers,
        request.body,
        request.timeoutMs,
      );
    },
  });
  const paymentMethodToken = await tokenization.tokenize(card);

  const disabled = new SandboxCardTokenizationAdapter({ enabled: false });
  try {
    await disabled.tokenize(card);
    fail('DISABLED_ADAPTER_DID_NOT_FAIL');
  } catch (error: unknown) {
    if (!(error instanceof TokenizationError) || error.code !== 'SANDBOX_DISABLED') throw error;
  }

  const providerContracts = [
    {
      type: 'TERMS',
      permalink: acceptances.termsPermalink,
      version: `provider-${sha256(acceptances.termsPermalink).slice(0, 16)}`,
    },
    {
      type: 'PERSONAL_DATA',
      permalink: acceptances.personalDataPermalink,
      version: `provider-${sha256(acceptances.personalDataPermalink).slice(0, 16)}`,
    },
  ] as const;
  const provider = new SandboxPaymentProvider({
    enabled: true,
    publicKey,
    privateKey,
    integritySecret,
    acceptanceReader: async () => {
      const response = await network.json(
        'configurationReads',
        'GET',
        `/v1/merchants/${encodeURIComponent(publicKey)}`,
        { Accept: 'application/json' },
        undefined,
        8_000,
      );
      if (response.status < 200 || response.status >= 300) {
        fail('MERCHANT_CONFIGURATION_UNAVAILABLE');
      }
      const currentAcceptances = acceptanceConfiguration(response.body, authorizationGate());
      return {
        contracts: [
          {
            type: 'TERMS',
            permalink: currentAcceptances.termsPermalink,
            version: `provider-${sha256(currentAcceptances.termsPermalink).slice(0, 16)}`,
          },
          {
            type: 'PERSONAL_DATA',
            permalink: currentAcceptances.personalDataPermalink,
            version: `provider-${sha256(currentAcceptances.personalDataPermalink).slice(0, 16)}`,
          },
        ],
        providerAcceptances: {
          terms: currentAcceptances.termsToken,
          personalData: currentAcceptances.personalDataToken,
        },
      };
    },
    expectedContracts: providerContracts,
    quoteTtlSeconds: QUOTE_TTL_SECONDS,
    authorizedUntilUtc: authorizationContext.authorization.authorization.expiresAtUtc,
    now: authorizationGate,
    timeoutMs: 8_000,
    transport: async (request) => {
      const category: RequestCategory =
        request.method === 'POST'
          ? 'transactionCreates'
          : (currentReadCategory ?? fail('PROVIDER_READ_CATEGORY_MISSING'));
      return network.json(
        category,
        request.method,
        request.resource,
        request.headers,
        request.body,
        request.timeoutMs,
      );
    },
  });
  const providerConfiguration = valueOf(
    provider.getPublicConfiguration(),
    'PROVIDER_CONFIGURATION_INVALID',
  );
  if (
    providerConfiguration.mode !== 'sandbox' ||
    providerConfiguration.captureVariant !== 'DIRECT_JWE' ||
    providerConfiguration.publicKey !== publicKey
  ) {
    fail('PROVIDER_CONFIGURATION_INVALID');
  }

  const acceptanceEvidence = {
    termsVersion: `provider-${sha256(acceptances.termsPermalink).slice(0, 16)}`,
    termsContractHash: runtime.semanticHash(acceptances.termsPermalink),
    personalDataVersion: `provider-${sha256(acceptances.personalDataPermalink).slice(0, 16)}`,
    personalDataContractHash: runtime.semanticHash(acceptances.personalDataPermalink),
    acceptedAt: startedAtUtc,
  };
  const transaction: Transaction = {
    transactionId,
    checkoutId,
    providerReference: reference,
    paymentStatus: 'PENDING',
    dispatchPhase: 'NOT_SENT',
    providerStatus: null,
    reservationStatus: 'ACTIVE',
    integrityStatus: 'OK',
    acceptanceEvidence,
    acceptedAt: startedAtUtc,
    updatedAt: startedAtUtc,
    attempts: 0,
    nextCheckAt: startedAtUtc,
    amountInCents,
    currency: 'COP',
    effectsApplied: false,
  };
  const idempotencyKey = `idem.${runId}`;
  const keyHash = runtime.hashIdempotency(checkoutId, idempotencyKey);
  const semanticHash = runtime.semanticHash(`auth02|${checkoutId}|${reference}`);
  const submission = {
    transactionId,
    statusUrl: `/api/v1/transactions/${transactionId}`,
    submissionState: 'ACCEPTED' as const,
    acceptedAt: startedAtUtc,
  };
  const prepared = valueOf(
    await repository.preparePayment({
      checkoutId,
      capabilityHash,
      expectedVersion: checkout.version,
      keyHash,
      semanticHash,
      transaction,
      submission,
    }),
    'LOCAL_PENDING_CREATE_FAILED',
  );
  if (prepared.kind !== 'CREATED' || prepared.transaction.paymentStatus !== 'PENDING') {
    fail('LOCAL_PENDING_CREATE_FAILED');
  }
  const claimed = valueOf(
    await repository.claimDispatch(transactionId, startedAtUtc, startedAtUtc),
    'LOCAL_DISPATCH_CLAIM_FAILED',
  );
  if (claimed.kind !== 'CLAIMED') fail('LOCAL_DISPATCH_CLAIM_FAILED');

  let currentReadCategory:
    | Exclude<
        RequestCategory,
        'configurationReads' | 'paymentMethodCreations' | 'transactionCreates'
      >
    | undefined;
  const command: ProviderPaymentCommand = {
    reference,
    amountInCents,
    currency: 'COP',
    customerEmail,
    installments: 1,
    paymentMethodHandle: { kind: 'OPAQUE_TOKEN', value: paymentMethodToken },
    acceptances: {
      termsAcceptanceToken: acceptances.termsToken,
      personalDataAcceptanceToken: acceptances.personalDataToken,
    },
  };
  const createOutcome = valueOf(await provider.createOnce(command), 'PROVIDER_CREATE_FAILED');
  const created =
    createOutcome.kind === 'ACKNOWLEDGED'
      ? createOutcome
      : fail('PROVIDER_CREATE_NOT_ACKNOWLEDGED');
  if (!localPendingObservedFirst) fail('LOCAL_PENDING_ORDER_NOT_OBSERVED');
  await applyObservation(
    repository,
    transactionId,
    reference,
    amountInCents,
    created,
    0,
    startedAtUtc,
  );

  currentReadCategory = 'statusReads';
  const firstObservation = valueOf(
    await provider.getById(created.providerId, reference),
    'PROVIDER_STATUS_READ_FAILED',
  );
  monotonicProviderStatus(created, firstObservation);
  await applyObservation(
    repository,
    transactionId,
    reference,
    amountInCents,
    firstObservation,
    1,
    startedAtUtc,
  );

  currentReadCategory = 'errorMappingProbes';
  const missingSuffix = randomBytes(8).toString('hex');
  const mappedError = await provider.getById(
    `e6-missing-${missingSuffix}`,
    `e6-missing-reference-${missingSuffix}`,
  );
  if (mappedError.ok || mappedError.error.code !== 'PROVIDER_UNAVAILABLE') {
    fail('PROVIDER_ERROR_MAPPING_INVALID');
  }
  const redacted = JSON.stringify(
    redactSandboxDiagnostic({
      authorization: privateKey,
      paymentToken: paymentMethodToken,
      integritySecret,
      card: card.number,
      cvc: card.securityCode,
    }),
  );
  if (
    redacted.includes(privateKey) ||
    redacted.includes(paymentMethodToken) ||
    redacted.includes(integritySecret) ||
    redacted.includes(card.number) ||
    redacted.includes(card.securityCode)
  ) {
    fail('PROVIDER_REDACTION_INVALID');
  }

  currentReadCategory = 'reconciliationReplays';
  const replayObservation = valueOf(
    await provider.getById(created.providerId, reference),
    'PROVIDER_REPLAY_READ_FAILED',
  );
  monotonicProviderStatus(firstObservation, replayObservation);
  let local = await applyObservation(
    repository,
    transactionId,
    reference,
    amountInCents,
    replayObservation,
    2,
    startedAtUtc,
  );
  const productBeforeDuplicate =
    valueOf(await catalog.findById(productId), 'LOCAL_PRODUCT_READ_FAILED') ??
    fail('LOCAL_PRODUCT_MISSING');
  const transactionBeforeDuplicate = local;
  local = await applyObservation(
    repository,
    transactionId,
    reference,
    amountInCents,
    replayObservation,
    2,
    startedAtUtc,
  );
  const productAfterDuplicate =
    valueOf(await catalog.findById(productId), 'LOCAL_PRODUCT_READ_FAILED') ??
    fail('LOCAL_PRODUCT_MISSING');
  if (
    !stableEffects(productBeforeDuplicate, productAfterDuplicate, transactionBeforeDuplicate, local)
  ) {
    fail('DUPLICATE_LOCAL_EFFECT_DETECTED');
  }
  const replay = valueOf(
    await repository.preparePayment({
      checkoutId,
      capabilityHash,
      expectedVersion: checkout.version,
      keyHash,
      semanticHash,
      transaction,
      submission,
    }),
    'LOCAL_IDEMPOTENCY_REPLAY_FAILED',
  );
  if (replay.kind !== 'REPLAY' || replay.transaction.transactionId !== transactionId) {
    fail('LOCAL_IDEMPOTENCY_REPLAY_FAILED');
  }
  if (!ALLOWED_RESULT_STATES.has(replayObservation.status)) fail('EVIDENCE_STATE_UNSUPPORTED');
  if (
    local.paymentStatus !== replayObservation.status ||
    local.providerId !== replayObservation.providerId ||
    local.providerReference !== reference ||
    local.amountInCents !== amountInCents ||
    local.currency !== 'COP'
  ) {
    fail('LOCAL_PROVIDER_STATE_DIVERGENT');
  }
  const requestSummary = network.summary();
  if (
    requestSummary.total !== EXPECTED_REQUESTS ||
    requestSummary.configurationReads !== 3 ||
    requestSummary.paymentMethodCreations !== 1 ||
    requestSummary.transactionCreates !== 1 ||
    requestSummary.statusReads !== 1 ||
    requestSummary.errorMappingProbes !== 1 ||
    requestSummary.reconciliationReplays !== 1
  ) {
    fail('REQUEST_ACCOUNTING_INVALID');
  }
  const executedAtUtc = authorizationGate().toISOString();
  const sanitizedReport = {
    commitSha,
    runId,
    hostSha256: sha256(SANDBOX_HOST),
    referenceSha256: sha256(reference),
    requestSummary,
    providerState: replayObservation.status,
    localState: local.paymentStatus,
    localPendingObservedFirst,
    duplicateEffects: 0,
  };
  const result = {
    status: 'PASS',
    commitSha,
    runId,
    executedAtUtc,
    hostSha256: sha256(SANDBOX_HOST),
    referenceSha256: sha256(reference),
    checks: CHECKS.map(([id, name]) => ({ id, name, status: 'PASS' })),
    requests: {
      total: requestSummary.total,
      configurationReads: requestSummary.configurationReads,
      paymentMethodCreations: requestSummary.paymentMethodCreations,
      transactionCreates: requestSummary.transactionCreates,
      statusReads: requestSummary.statusReads,
      errorMappingProbes: requestSummary.errorMappingProbes,
      reconciliationReplays: requestSummary.reconciliationReplays,
      production: 0,
      globalMutations: 0,
      outsideAllowlist: 0,
    },
    result: {
      providerState: replayObservation.status,
      localState: local.paymentStatus,
      amountMatches: true,
      currencyMatches: true,
      referenceMatches: true,
      reconciliationConsistent: true,
      duplicateEffects: 0,
      adapterDisabledByConfiguration: true,
    },
    reportSha256: sha256(JSON.stringify(sanitizedReport)),
    containsSensitiveData: false,
  };
  process.stdout.write(JSON.stringify(result) + '\n');
};

void run().catch((error: unknown) => {
  if (process.connected) process.disconnect();
  const code =
    error instanceof CandidateSmokeError || error instanceof SandboxAuthorizationError
      ? error.code
      : 'CANDIDATE_UNEXPECTED_FAILURE';
  process.stderr.write(`stage-6 authorized sandbox candidate: ${code}\n`);
  process.exitCode = 1;
});
