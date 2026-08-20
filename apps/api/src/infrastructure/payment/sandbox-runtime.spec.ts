import { loadAppConfig } from '../configuration/app-config';
import type { RuntimeSecrets } from '../configuration/runtime-secrets';
import type { ProviderPaymentCommand } from '../../application/ports/payment-provider';
import { SandboxPaymentProvider } from './sandbox-payment-provider';
import {
  createSandboxAcceptanceReader,
  createSandboxTransport,
  loadSandboxRuntimeConfiguration,
  sandboxEgressCorrelationSha256,
  SANDBOX_EGRESS_EVENT_NAME,
  SANDBOX_PROVIDER_HOST_SHA256,
  type SandboxEgressAttemptEvent,
  WOMPI_SANDBOX_ORIGIN,
} from './sandbox-runtime';

const publicKey = ['pub', 'test', 'synthetic-not-a-real'].join('_');
const privateKey = ['prv', 'test', 'synthetic-not-a-real'].join('_');
const assessmentConfig = loadAppConfig({
  ALLOWED_ORIGIN: 'https://checkout.example.test',
  APP_ENV: 'assessment',
  AUTO_SEED_CATALOG: 'false',
  CANDIDATE_SHA: 'a'.repeat(40),
  DATA_ADAPTER: 'dynamodb',
  PAYMENT_ADAPTER: 'sandbox',
  PAYMENTS_ENABLED: 'true',
  PRERELEASE_ACCESS_MODE: 'origin_gate',
  SANDBOX_AUTHORIZED_UNTIL_UTC: '2099-01-01T00:00:00.000Z',
  PUBLIC_ASSET_ORIGIN: 'https://checkout.example.test',
  RELEASE_ID: 'rel-20260819-1200-aaaaaaa',
  RUNTIME_SECRET_ARN: [
    'arn:aws:secretsmanager:us-east-1:000000000000',
    'secret',
    'checkout/assessment/runtime-AbCd12',
  ].join(':'),
  RUNTIME_SECRET_VERSION_ID: 'a'.repeat(32),
  TOKENIZATION_MODE: 'direct_jwe',
});
const secrets: RuntimeSecrets = {
  prereleaseOriginToken: Buffer.alloc(32, 4).toString('base64url'),
  runtimeSecurityRootKey: Buffer.alloc(32, 3).toString('base64url'),
  sandbox: {
    publicKey,
    privateKey,
    integritySecret: ['test', 'integrity', 'synthetic-not-a-real'].join('_'),
    termsAcceptanceToken: 'terms-provider-synthetic',
    termsPermalink: 'https://comercios.wompi.co/terminos/synthetic',
    personalDataAcceptanceToken: 'personal-provider-synthetic',
    personalDataPermalink: 'https://wompi.com/datos/synthetic',
  },
};
const acceptanceJwt = (payload: Readonly<Record<string, unknown>>): string =>
  [
    Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify(payload)).toString('base64url'),
    Buffer.from('synthetic-signature').toString('base64url'),
  ].join('.');
const response = (body: unknown, url: string, status = 200): Response =>
  ({
    status,
    url,
    headers: { get: () => 'application/json' },
    text: async () => JSON.stringify(body),
  }) as unknown as Response;

const requestTarget = (input: RequestInfo | URL): string =>
  input instanceof URL ? input.toString() : typeof input === 'string' ? input : input.url;

const merchantBody = (
  termsAcceptanceToken: string,
  personalDataAcceptanceToken: string,
): unknown => ({
  data: {
    presigned_acceptance: {
      acceptance_token: termsAcceptanceToken,
      permalink: 'https://comercios.wompi.co/terminos/synthetic',
      type: 'END_USER_POLICY',
    },
    presigned_personal_data_auth: {
      acceptance_token: personalDataAcceptanceToken,
      permalink: 'https://wompi.com/datos/synthetic',
      type: 'PERSONAL_DATA_AUTH',
    },
  },
});

const paymentCommand: ProviderPaymentCommand = {
  reference: 'ref-runtime-001',
  amountInCents: 3_200_000,
  currency: 'COP',
  customerEmail: 'buyer@example.invalid',
  installments: 1,
  paymentMethodHandle: { kind: 'OPAQUE_TOKEN', value: 'tok_synthetic' },
  acceptances: {
    termsAcceptanceToken: 'terms-client-synthetic',
    personalDataAcceptanceToken: 'personal-client-synthetic',
  },
};

describe('sandbox runtime boundary', () => {
  it('loads the authorized merchant contracts without provider traffic during bootstrap', async () => {
    const fetchImplementation = jest.fn();
    await expect(loadSandboxRuntimeConfiguration(assessmentConfig, secrets)).resolves.toMatchObject(
      {
        contracts: [
          { type: 'TERMS', permalink: 'https://comercios.wompi.co/terminos/synthetic' },
          { type: 'PERSONAL_DATA', permalink: 'https://wompi.com/datos/synthetic' },
        ],
      },
    );
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it('keeps an expired pinned token as a non-authoritative deployment snapshot', async () => {
    const currentTime = new Date('2026-08-19T12:00:00.000Z');
    const currentEpochSeconds = currentTime.getTime() / 1_000;
    await expect(
      loadSandboxRuntimeConfiguration(assessmentConfig, {
        ...secrets,
        sandbox: {
          ...(secrets.sandbox as NonNullable<RuntimeSecrets['sandbox']>),
          termsAcceptanceToken: acceptanceJwt({
            exp: currentEpochSeconds - 1,
          }),
        },
      }),
    ).resolves.toBeDefined();
  });

  it('keeps disabled sandbox configuration at zero external requests', async () => {
    const fetchImplementation = jest.fn();
    await expect(
      loadSandboxRuntimeConfiguration(
        loadAppConfig({ APP_ENV: 'test', PAYMENT_ADAPTER: 'sandbox' }),
        {
          prereleaseOriginToken: undefined,
          runtimeSecurityRootKey: undefined,
          sandbox: undefined,
        },
      ),
    ).resolves.toBeUndefined();
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it('coalesces concurrent merchant reads and refreshes only after the bounded cache expires', async () => {
    let currentTime = new Date('2026-08-19T12:00:00.000Z');
    const termsToken = acceptanceJwt({
      exp: currentTime.getTime() / 1_000 + assessmentConfig.quoteTtlSeconds + 3_600,
    });
    const personalDataToken = acceptanceJwt({ contract_id: 2 });
    const fetchImplementation = jest.fn((input: RequestInfo | URL, init?: RequestInit) => {
      void init;
      return Promise.resolve(
        response(merchantBody(termsToken, personalDataToken), requestTarget(input)),
      );
    });
    const egressEvents: SandboxEgressAttemptEvent[] = [];
    const transport = createSandboxTransport(
      assessmentConfig,
      secrets,
      fetchImplementation,
      () => currentTime,
      (event) => egressEvents.push(event),
    );
    const acceptanceReader = createSandboxAcceptanceReader(assessmentConfig, secrets, transport, {
      now: () => currentTime,
      cacheTtlMs: 1_000,
    });
    expect(acceptanceReader).toBeDefined();
    if (acceptanceReader === undefined) throw new Error('missing acceptance reader');

    const [first, concurrent] = await Promise.all([
      acceptanceReader('ref-reader-001'),
      acceptanceReader('ref-reader-002'),
    ]);
    expect(concurrent).toBe(first);
    await expect(acceptanceReader('ref-reader-003')).resolves.toBe(first);
    expect(fetchImplementation).toHaveBeenCalledTimes(1);
    expect(egressEvents).toHaveLength(1);
    expect(egressEvents[0]).toMatchObject({
      eventName: SANDBOX_EGRESS_EVENT_NAME,
      operation: 'MERCHANT_CONFIGURATION',
      method: 'GET',
      correlationSha256: sandboxEgressCorrelationSha256('ref-reader-001'),
      providerHostSha256: SANDBOX_PROVIDER_HOST_SHA256,
      containsSensitiveData: false,
    });
    expect(fetchImplementation.mock.calls[0]?.[0]).toBe(
      `${WOMPI_SANDBOX_ORIGIN}/v1/merchants/${encodeURIComponent(publicKey)}`,
    );
    expect(fetchImplementation.mock.calls[0]?.[1]).toMatchObject({
      method: 'GET',
      headers: { Accept: 'application/json' },
      redirect: 'error',
    });

    currentTime = new Date(currentTime.getTime() + 1_001);
    await expect(acceptanceReader('ref-reader-004')).resolves.toMatchObject({
      contracts: [{ type: 'TERMS' }, { type: 'PERSONAL_DATA' }],
    });
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
    expect(egressEvents).toHaveLength(2);
  });

  it('records one sanitized event immediately before every allowed fetch and zero when blocked', async () => {
    const sequence: string[] = [];
    const events: SandboxEgressAttemptEvent[] = [];
    const fetchImplementation = jest.fn(() => {
      sequence.push('fetch');
      return Promise.reject(new Error('synthetic network failure'));
    });
    const transport = createSandboxTransport(
      assessmentConfig,
      secrets,
      fetchImplementation,
      () => new Date('2026-08-19T12:00:00.000Z'),
      (event) => {
        sequence.push('event');
        events.push(event);
      },
    );
    expect(transport).toBeDefined();
    if (transport === undefined) throw new Error('missing transport');

    await expect(
      transport({
        method: 'POST',
        resource: '/v1/transactions',
        headers: { Authorization: `Bearer ${privateKey}` },
        timeoutMs: 1_000,
        correlationReference: 'reference_transaction-001',
      }),
    ).rejects.toThrow('synthetic network failure');
    expect(sequence).toEqual(['event', 'fetch']);
    expect(events).toEqual([
      {
        eventName: SANDBOX_EGRESS_EVENT_NAME,
        schemaVersion: 1,
        candidateSha: 'a'.repeat(40),
        releaseId: 'rel-20260819-1200-aaaaaaa',
        providerHostSha256: SANDBOX_PROVIDER_HOST_SHA256,
        operation: 'TRANSACTION_CREATE',
        method: 'POST',
        correlationSha256: '012dc06ee0e083dc8fea80a018270f1638e66a317f8ff42985b88066264f823b',
        containsSensitiveData: false,
      },
    ]);
    expect(JSON.stringify(events)).not.toContain('reference_transaction-001');

    await expect(
      transport({
        method: 'GET',
        resource: '/v1/merchants/not-allowlisted',
        headers: { Accept: 'application/json' },
        timeoutMs: 1_000,
        correlationReference: 'reference_transaction-002',
      }),
    ).rejects.toThrow('SANDBOX_REQUEST_BLOCKED');
    expect(events).toHaveLength(1);
    expect(fetchImplementation).toHaveBeenCalledTimes(1);
  });

  it('does not cache an invalid or expired merchant response', async () => {
    const currentTime = new Date('2026-08-19T12:00:00.000Z');
    const currentEpochSeconds = currentTime.getTime() / 1_000;
    const transport = jest
      .fn()
      .mockResolvedValueOnce({
        status: 200,
        contentType: 'application/json',
        body: merchantBody(
          acceptanceJwt({ exp: currentEpochSeconds + assessmentConfig.quoteTtlSeconds }),
          acceptanceJwt({ contract_id: 2 }),
        ),
      })
      .mockResolvedValueOnce({
        status: 200,
        contentType: 'application/json',
        body: merchantBody(
          acceptanceJwt({
            exp: currentEpochSeconds + assessmentConfig.quoteTtlSeconds + 600,
          }),
          acceptanceJwt({ contract_id: 2 }),
        ),
      });
    const acceptanceReader = createSandboxAcceptanceReader(assessmentConfig, secrets, transport, {
      now: () => currentTime,
    });
    expect(acceptanceReader).toBeDefined();
    if (acceptanceReader === undefined) throw new Error('missing acceptance reader');
    await expect(acceptanceReader('ref-reader-invalid')).rejects.toThrow(
      'SANDBOX_CONFIGURATION_INVALID',
    );
    await expect(acceptanceReader('ref-reader-valid')).resolves.toBeDefined();
    expect(transport).toHaveBeenCalledTimes(2);
  });

  it.each([
    {
      name: 'non-2xx status',
      response: {
        status: 503,
        contentType: 'application/json',
        body: merchantBody('terms-provider-synthetic', 'personal-provider-synthetic'),
      },
    },
    {
      name: 'non-JSON response',
      response: {
        status: 200,
        contentType: 'text/html',
        body: merchantBody('terms-provider-synthetic', 'personal-provider-synthetic'),
      },
    },
    {
      name: 'wrong contract type',
      response: {
        status: 200,
        contentType: 'application/json',
        body: {
          data: {
            presigned_acceptance: {
              acceptance_token: 'terms-provider-synthetic',
              permalink: 'https://wompi.co/terms/synthetic',
              type: 'PERSONAL_DATA_AUTH',
            },
            presigned_personal_data_auth: {
              acceptance_token: 'personal-provider-synthetic',
              permalink: 'https://wompi.com/data/synthetic',
              type: 'PERSONAL_DATA_AUTH',
            },
          },
        },
      },
    },
    {
      name: 'extended inner contract shape',
      response: {
        status: 200,
        contentType: 'application/json',
        body: {
          data: {
            presigned_acceptance: {
              acceptance_token: 'terms-provider-synthetic',
              permalink: 'https://wompi.co/terms/synthetic',
              type: 'END_USER_POLICY',
              unexpected: true,
            },
            presigned_personal_data_auth: {
              acceptance_token: 'personal-provider-synthetic',
              permalink: 'https://wompi.com/data/synthetic',
              type: 'PERSONAL_DATA_AUTH',
            },
          },
        },
      },
    },
  ])('rejects a $name merchant response', async ({ response: providerResponse }) => {
    const transport = jest.fn().mockResolvedValue(providerResponse);
    const acceptanceReader = createSandboxAcceptanceReader(assessmentConfig, secrets, transport);
    expect(acceptanceReader).toBeDefined();
    if (acceptanceReader === undefined) throw new Error('missing acceptance reader');
    await expect(acceptanceReader('ref-reader-rejected')).rejects.toThrow();
    expect(transport).toHaveBeenCalledTimes(1);
  });

  it('performs one merchant GET before the one transaction POST on the happy path', async () => {
    const currentTime = new Date('2026-08-19T12:00:00.000Z');
    const termsToken = acceptanceJwt({
      exp: currentTime.getTime() / 1_000 + assessmentConfig.quoteTtlSeconds + 600,
    });
    const personalDataToken = acceptanceJwt({ contract_id: 2 });
    const fetchImplementation = jest.fn((input: RequestInfo | URL) => {
      const target = requestTarget(input);
      const body = target.includes('/v1/merchants/')
        ? merchantBody(termsToken, personalDataToken)
        : {
            data: {
              id: 'provider-runtime-001',
              reference: paymentCommand.reference,
              amount_in_cents: paymentCommand.amountInCents,
              currency: paymentCommand.currency,
              status: 'PENDING',
            },
          };
      return Promise.resolve(response(body, target, target.includes('/v1/merchants/') ? 200 : 201));
    });
    const transport = createSandboxTransport(
      assessmentConfig,
      secrets,
      fetchImplementation,
      () => currentTime,
    );
    const acceptanceReader = createSandboxAcceptanceReader(assessmentConfig, secrets, transport, {
      now: () => currentTime,
    });
    const configuration = await loadSandboxRuntimeConfiguration(assessmentConfig, secrets);
    if (
      transport === undefined ||
      acceptanceReader === undefined ||
      configuration === undefined ||
      secrets.sandbox === undefined ||
      assessmentConfig.sandboxAuthorizedUntilUtc === undefined
    ) {
      throw new Error('missing sandbox runtime');
    }
    const provider = new SandboxPaymentProvider({
      enabled: true,
      publicKey,
      privateKey,
      integritySecret: secrets.sandbox.integritySecret,
      transport,
      acceptanceReader,
      expectedContracts: configuration.contracts,
      quoteTtlSeconds: assessmentConfig.quoteTtlSeconds,
      authorizedUntilUtc: assessmentConfig.sandboxAuthorizedUntilUtc,
      now: () => currentTime,
    });
    await expect(provider.createOnce(paymentCommand)).resolves.toMatchObject({
      value: { kind: 'ACKNOWLEDGED', providerId: 'provider-runtime-001' },
    });
    expect(fetchImplementation.mock.calls.map(([input]) => requestTarget(input))).toEqual([
      `${WOMPI_SANDBOX_ORIGIN}/v1/merchants/${encodeURIComponent(publicKey)}`,
      `${WOMPI_SANDBOX_ORIGIN}/v1/transactions`,
    ]);
  });

  it('keeps bootstrap alive but rejects an expired authorization before transaction traffic', async () => {
    const fetchImplementation = jest.fn();
    const expired = loadAppConfig({
      ALLOWED_ORIGIN: 'https://checkout.example.test',
      APP_ENV: 'assessment',
      AUTO_SEED_CATALOG: 'false',
      CANDIDATE_SHA: 'a'.repeat(40),
      DATA_ADAPTER: 'dynamodb',
      PAYMENT_ADAPTER: 'sandbox',
      PAYMENTS_ENABLED: 'true',
      PRERELEASE_ACCESS_MODE: 'origin_gate',
      PUBLIC_ASSET_ORIGIN: 'https://checkout.example.test',
      RELEASE_ID: 'rel-20260819-1200-aaaaaaa',
      RUNTIME_SECRET_ARN: [
        'arn:aws:secretsmanager:us-east-1:000000000000',
        'secret',
        'checkout/assessment/runtime-AbCd12',
      ].join(':'),
      RUNTIME_SECRET_VERSION_ID: 'a'.repeat(32),
      SANDBOX_AUTHORIZED_UNTIL_UTC: '2026-08-17T12:00:00.000Z',
      TOKENIZATION_MODE: 'direct_jwe',
    });
    await expect(loadSandboxRuntimeConfiguration(expired, secrets)).resolves.toBeDefined();
    const transport = createSandboxTransport(
      expired,
      secrets,
      fetchImplementation,
      () => new Date('2026-08-17T12:00:00.000Z'),
    );
    expect(transport).toBeDefined();
    if (transport === undefined) throw new Error('missing transport');
    await expect(
      transport({
        method: 'GET',
        resource: '/v1/transactions/provider-synthetic',
        headers: { Authorization: `Bearer ${publicKey}` },
        timeoutMs: 1_000,
        correlationReference: 'ref-expired-001',
      }),
    ).rejects.toThrow('SANDBOX_AUTHORIZATION_EXPIRED');
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it('allows only one transaction create and bounded transaction reads', async () => {
    const fetchImplementation = jest.fn((input: RequestInfo | URL) =>
      Promise.resolve(response({ data: { status: 'PENDING' } }, requestTarget(input))),
    );
    const transport = createSandboxTransport(assessmentConfig, secrets, fetchImplementation);
    expect(transport).toBeDefined();
    if (transport === undefined) throw new Error('missing transport');
    await expect(
      transport({
        method: 'POST',
        resource: '/v1/transactions',
        headers: { Authorization: `Bearer ${privateKey}` },
        body: { synthetic: true },
        timeoutMs: 1_000,
        correlationReference: 'ref-create-001',
      }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      transport({
        method: 'GET',
        resource: '/v1/transactions/provider-synthetic',
        headers: { Authorization: `Bearer ${publicKey}` },
        timeoutMs: 1_000,
        correlationReference: 'ref-status-001',
      }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      transport({
        method: 'GET',
        resource: `/v1/merchants/${encodeURIComponent(publicKey)}`,
        headers: { Accept: 'application/json' },
        timeoutMs: 1_000,
        correlationReference: 'ref-merchant-001',
      }),
    ).resolves.toMatchObject({ status: 200 });
    for (const blocked of [
      {
        method: 'GET',
        resource: '/v1/merchants/unapproved',
        headers: { Authorization: `Bearer ${publicKey}` },
        timeoutMs: 1_000,
        correlationReference: 'ref-blocked-001',
      },
      {
        method: 'GET',
        resource: `/v1/merchants/${encodeURIComponent(publicKey)}?unexpected=true`,
        headers: { Accept: 'application/json' },
        timeoutMs: 1_000,
        correlationReference: 'ref-blocked-002',
      },
      {
        method: 'GET',
        resource: `/v1/merchants/${encodeURIComponent(publicKey)}`,
        headers: { Accept: 'application/json', Authorization: `Bearer ${privateKey}` },
        timeoutMs: 1_000,
        correlationReference: 'ref-blocked-003',
      },
    ] as const) {
      await expect(transport(blocked)).rejects.toThrow('SANDBOX_REQUEST_BLOCKED');
    }
    expect(fetchImplementation).toHaveBeenCalledTimes(3);
  });
});
