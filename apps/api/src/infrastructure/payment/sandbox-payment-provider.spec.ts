import type { ProviderPaymentCommand } from '../../application/ports/payment-provider';
import {
  redactSandboxDiagnostic,
  SandboxPaymentProvider,
  signSandboxIntegrity,
  type SandboxAcceptanceReader,
  type SandboxProviderAcceptanceSnapshot,
  type SandboxTransport,
  type SandboxTransportResponse,
} from './sandbox-payment-provider';

const command: ProviderPaymentCommand = {
  reference: 'ref-001',
  amountInCents: 3_200_000,
  currency: 'COP',
  customerEmail: 'buyer@example.invalid',
  installments: 1,
  paymentMethodHandle: { kind: 'OPAQUE_TOKEN', value: 'tok_synthetic' },
  acceptances: {
    termsAcceptanceToken: 'terms_synthetic',
    personalDataAcceptanceToken: 'personal_synthetic',
  },
};

const observation = {
  data: {
    id: 'provider-001',
    reference: command.reference,
    amount_in_cents: command.amountInCents,
    currency: 'COP',
    status: 'PENDING',
  },
};

const acceptanceJwt = (payload: Readonly<Record<string, unknown>>): string =>
  [
    Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify(payload)).toString('base64url'),
    Buffer.from('synthetic-signature').toString('base64url'),
  ].join('.');

const acceptanceJwtFromSources = (header: string, payload: string): string =>
  [
    Buffer.from(header).toString('base64url'),
    Buffer.from(payload).toString('base64url'),
    Buffer.from('synthetic-signature').toString('base64url'),
  ].join('.');

const termsProviderAcceptance = acceptanceJwt({ contract_id: 'terms' });
const personalProviderAcceptance = acceptanceJwt({ contract_id: 'personal-data' });

const expectedContracts = [
  {
    type: 'TERMS',
    permalink: 'https://comercios.wompi.co/terminos/synthetic',
    version: 'provider-terms-v1',
  },
  {
    type: 'PERSONAL_DATA',
    permalink: 'https://wompi.com/datos/synthetic',
    version: 'provider-personal-v1',
  },
] as const;

const acceptanceSnapshot = (
  overrides: Partial<SandboxProviderAcceptanceSnapshot> = {},
): SandboxProviderAcceptanceSnapshot => ({
  contracts: expectedContracts,
  providerAcceptances: {
    terms: termsProviderAcceptance,
    personalData: personalProviderAcceptance,
  },
  ...overrides,
});

const enabled = (
  transport: SandboxTransport,
  acceptanceReader: SandboxAcceptanceReader = () => Promise.resolve(acceptanceSnapshot()),
): SandboxPaymentProvider =>
  new SandboxPaymentProvider({
    enabled: true,
    publicKey: 'pub_test_not-a-real',
    privateKey: 'prv_test_not-a-real',
    integritySecret: 'integrity-secret',
    acceptanceReader,
    expectedContracts,
    quoteTtlSeconds: 900,
    authorizedUntilUtc: '2099-01-01T00:00:00.000Z',
    transport,
    timeoutMs: 1234,
  });

const transportMock = (): jest.MockedFunction<SandboxTransport> =>
  jest.fn<Promise<SandboxTransportResponse>, Parameters<SandboxTransport>>();

describe('SandboxPaymentProvider pure adapter', () => {
  it('stays READY_DISABLED with zero network when runtime credentials/transport are absent', async () => {
    const transport = transportMock();
    const provider = new SandboxPaymentProvider({ enabled: false, transport });
    expect(provider.getPublicConfiguration()).toMatchObject({
      error: { code: 'ENVIRONMENT_DISABLED' },
    });
    await expect(provider.createOnce(command)).resolves.toMatchObject({
      error: { code: 'ENVIRONMENT_DISABLED' },
    });
    await expect(provider.getById('provider-001')).resolves.toMatchObject({
      error: { code: 'ENVIRONMENT_DISABLED' },
    });
    expect(provider.verifyAndNormalizeEvent('event')).toMatchObject({
      error: { code: 'ENVIRONMENT_DISABLED' },
    });
    expect(transport).not.toHaveBeenCalled();
  });
  it('fails closed when reference lookup is not contractually available', async () => {
    const transport = transportMock();
    await expect(enabled(transport).getByReference(command.reference)).resolves.toEqual({
      ok: false,
      error: { code: 'REFERENCE_LOOKUP_UNSUPPORTED' },
    });
    expect(transport).not.toHaveBeenCalled();
  });

  it('blocks configuration and provider traffic at the authorization boundary', async () => {
    const transport = transportMock();
    const provider = new SandboxPaymentProvider({
      enabled: true,
      publicKey: 'pub_test_not-a-real',
      privateKey: 'prv_test_not-a-real',
      integritySecret: 'integrity-secret',
      acceptanceReader: () => Promise.resolve(acceptanceSnapshot()),
      expectedContracts,
      quoteTtlSeconds: 900,
      authorizedUntilUtc: '2026-08-17T12:00:00.000Z',
      now: () => new Date('2026-08-17T12:00:00.000Z'),
      transport,
    });
    expect(provider.getPublicConfiguration()).toMatchObject({
      error: { code: 'ENVIRONMENT_DISABLED' },
    });
    await expect(provider.createOnce(command)).resolves.toMatchObject({
      error: { code: 'ENVIRONMENT_DISABLED' },
    });

    const impossibleDate = new SandboxPaymentProvider({
      enabled: true,
      publicKey: 'pub_test_not-a-real',
      privateKey: 'prv_test_not-a-real',
      integritySecret: 'integrity-secret',
      acceptanceReader: () => Promise.resolve(acceptanceSnapshot()),
      expectedContracts,
      quoteTtlSeconds: 900,
      authorizedUntilUtc: '2099-02-31T00:00:00.000Z',
      transport,
    });
    expect(impossibleDate.getPublicConfiguration()).toMatchObject({
      error: { code: 'ENVIRONMENT_DISABLED' },
    });
    expect(transport).not.toHaveBeenCalled();
  });

  it('returns PROVEN_NOT_SENT and never POSTs an expired dynamic acceptance token', async () => {
    const transport = transportMock();
    let currentTime = new Date('2026-08-19T12:00:00.000Z');
    const expiration = currentTime.getTime() / 1_000 + 60;
    const provider = new SandboxPaymentProvider({
      enabled: true,
      publicKey: 'pub_test_not-a-real',
      privateKey: 'prv_test_not-a-real',
      integritySecret: 'integrity-secret',
      acceptanceReader: () =>
        Promise.resolve(
          acceptanceSnapshot({
            providerAcceptances: {
              terms: acceptanceJwt({ exp: expiration }),
              personalData: acceptanceJwt({ contract_id: 2 }),
            },
          }),
        ),
      expectedContracts,
      quoteTtlSeconds: 30,
      authorizedUntilUtc: '2099-01-01T00:00:00.000Z',
      now: () => currentTime,
      transport,
    });
    expect(provider.getPublicConfiguration()).toMatchObject({ value: { mode: 'sandbox' } });

    currentTime = new Date(expiration * 1_000);
    await expect(provider.createOnce(command)).resolves.toMatchObject({
      value: { kind: 'PROVEN_NOT_SENT' },
    });
    expect(transport).not.toHaveBeenCalled();
  });

  it('returns PROVEN_NOT_SENT when the dynamic read fails or contracts changed', async () => {
    const failedTransport = transportMock();
    const failedRead = jest
      .fn<ReturnType<SandboxAcceptanceReader>, []>()
      .mockRejectedValue(new Error('synthetic provider configuration failure'));
    await expect(enabled(failedTransport, failedRead).createOnce(command)).resolves.toMatchObject({
      value: { kind: 'PROVEN_NOT_SENT' },
    });
    expect(failedRead).toHaveBeenCalledTimes(1);
    expect(failedTransport).not.toHaveBeenCalled();

    const changedTransport = transportMock();
    const changedRead = jest.fn<ReturnType<SandboxAcceptanceReader>, []>().mockResolvedValue(
      acceptanceSnapshot({
        contracts: [
          {
            ...expectedContracts[0],
            permalink: 'https://wompi.co/terminos/changed',
            version: 'provider-terms-v2',
          },
          expectedContracts[1],
        ],
      }),
    );
    await expect(enabled(changedTransport, changedRead).createOnce(command)).resolves.toMatchObject(
      { value: { kind: 'PROVEN_NOT_SENT' } },
    );
    expect(changedTransport).not.toHaveBeenCalled();
  });

  it.each([
    'opaque-provider-token',
    'one.two',
    'one.two.three.four',
    acceptanceJwtFromSources('not-json', '{"contract_id":1}'),
    acceptanceJwtFromSources('[]', '{"contract_id":1}'),
    acceptanceJwtFromSources('{"alg":"none","typ":"JWT"}', '{"contract_id":1}'),
    acceptanceJwtFromSources('{"alg":"HS256","typ":"JWT"}', 'not-json'),
    acceptanceJwtFromSources('{"alg":"HS256","typ":"JWT"}', '[]'),
  ])(
    'returns PROVEN_NOT_SENT and zero POST for a non-canonical dynamic token: %s',
    async (token) => {
      const transport = transportMock();
      const provider = enabled(transport, () =>
        Promise.resolve(
          acceptanceSnapshot({
            providerAcceptances: { terms: token, personalData: personalProviderAcceptance },
          }),
        ),
      );
      await expect(provider.createOnce(command)).resolves.toMatchObject({
        value: { kind: 'PROVEN_NOT_SENT' },
      });
      expect(transport).not.toHaveBeenCalled();
    },
  );

  it('uses the canonical SHA-256 vector without separators or HMAC', () => {
    expect(signSandboxIntegrity('ref-001', 3_200_000, 'COP', 'integrity-secret')).toBe(
      '5cca8e9f4c84835d78932a70bab91f024cdc990eb5f9556f4d207a765752dd7e',
    );
  });

  it('maps POST with private key/snake_case and GET with public key', async () => {
    const transport = transportMock()
      .mockResolvedValueOnce({
        status: 201,
        contentType: 'application/json; charset=utf-8',
        body: observation,
      })
      .mockResolvedValueOnce({ status: 200, contentType: 'application/json', body: observation });
    const provider = enabled(transport);
    expect(provider.getPublicConfiguration()).toMatchObject({
      value: { mode: 'sandbox', captureVariant: 'DIRECT_JWE', publicKey: 'pub_test_not-a-real' },
    });
    await expect(provider.createOnce(command)).resolves.toMatchObject({
      value: { kind: 'ACKNOWLEDGED', providerId: 'provider-001', status: 'PENDING' },
    });
    expect(transport.mock.calls[0]?.[0]).toEqual({
      method: 'POST',
      resource: '/v1/transactions',
      headers: {
        Accept: 'application/json',
        Authorization: 'Bearer prv_test_not-a-real',
        'Content-Type': 'application/json',
      },
      timeoutMs: 1234,
      body: {
        acceptance_token: termsProviderAcceptance,
        accept_personal_auth: personalProviderAcceptance,
        amount_in_cents: 3_200_000,
        currency: 'COP',
        customer_email: 'buyer@example.invalid',
        payment_method: { type: 'CARD', token: 'tok_synthetic', installments: 1 },
        reference: 'ref-001',
        signature: '5cca8e9f4c84835d78932a70bab91f024cdc990eb5f9556f4d207a765752dd7e',
      },
      correlationReference: command.reference,
    });
    await expect(provider.getById('provider/001', command.reference)).resolves.toMatchObject({
      value: { providerId: 'provider-001', status: 'PENDING' },
    });
    expect(transport.mock.calls[1]?.[0]).toMatchObject({
      method: 'GET',
      resource: '/v1/transactions/provider%2F001',
      correlationReference: command.reference,
      headers: { Authorization: 'Bearer pub_test_not-a-real' },
    });
  });

  it.each([400, 401, 403, 422, 429, 500])(
    'treats POST HTTP %s without authenticated proof as OUTCOME_UNKNOWN and never retries',
    async (status) => {
      const transport = transportMock().mockResolvedValue({
        status,
        contentType: 'application/json',
        body: { error: 'synthetic' },
      });
      await expect(enabled(transport).createOnce(command)).resolves.toMatchObject({
        value: { kind: 'OUTCOME_UNKNOWN' },
      });
      expect(transport).toHaveBeenCalledTimes(1);
    },
  );

  it('maps timeout, non-JSON, malformed JSON model, and unknown external conservatively', async () => {
    const timeout = transportMock().mockRejectedValue(new Error('synthetic timeout'));
    await expect(enabled(timeout).createOnce(command)).resolves.toMatchObject({
      value: { kind: 'OUTCOME_UNKNOWN' },
    });
    expect(timeout).toHaveBeenCalledTimes(1);

    const responses: SandboxTransportResponse[] = [
      { status: 201, contentType: 'text/html', body: '<html />' },
      { status: 201, contentType: 'application/json', body: { data: { id: 1 } } },
      {
        status: 201,
        contentType: 'application/json',
        body: { ...observation, data: { ...observation.data, status: 'UNKNOWN_EXTERNAL' } },
      },
    ];
    for (const response of responses) {
      const transport = transportMock().mockResolvedValue(response);
      await expect(enabled(transport).createOnce(command)).resolves.toMatchObject({
        value: { kind: 'PROTOCOL_VIOLATION_AFTER_POSSIBLE_SEND' },
      });
      expect(transport).toHaveBeenCalledTimes(1);
    }
  });

  it('normalizes all allowed final statuses and rejects broken GET responses', async () => {
    for (const status of ['APPROVED', 'DECLINED', 'VOIDED', 'ERROR'] as const) {
      const transport = transportMock().mockResolvedValue({
        status: 201,
        contentType: 'application/json',
        body: { data: { ...observation.data, status } },
      });
      await expect(enabled(transport).createOnce(command)).resolves.toMatchObject({
        value: { kind: 'ACKNOWLEDGED', status },
      });
    }

    for (const response of [
      { status: 429, contentType: 'application/json', body: {} },
      { status: 503, contentType: 'application/json', body: {} },
      { status: 200, contentType: 'text/plain', body: 'bad' },
      { status: 200, contentType: 'application/json', body: {} },
    ] satisfies SandboxTransportResponse[]) {
      await expect(
        enabled(transportMock().mockResolvedValue(response)).getById('id', command.reference),
      ).resolves.toMatchObject({
        error: {
          code: response.status === 429 ? 'PROVIDER_RATE_LIMITED' : expect.any(String),
        },
      });
    }
    await expect(
      enabled(transportMock().mockRejectedValue(new Error('timeout'))).getById(
        'id',
        command.reference,
      ),
    ).resolves.toMatchObject({ error: { code: 'PROVIDER_UNAVAILABLE' } });
    const aborted = new Error('request aborted');
    aborted.name = 'AbortError';
    await expect(
      enabled(transportMock().mockRejectedValue(aborted)).getById('id', command.reference),
    ).resolves.toMatchObject({ error: { code: 'PROVIDER_TIMEOUT' } });
  });

  it('redacts credentials, tokens, card aliases, signatures, and nested arrays', () => {
    expect(
      redactSandboxDiagnostic({
        authorization: 'secret',
        paymentToken: 'secret',
        privateKey: 'value',
        signature: 'secret',
        payload: [{ cvc: '123', safe: 'value' }],
      }),
    ).toEqual({
      authorization: '[REDACTED]',
      paymentToken: '[REDACTED]',
      privateKey: '[REDACTED]',
      signature: '[REDACTED]',
      payload: [{ cvc: '[REDACTED]', safe: 'value' }],
    });
  });
});
