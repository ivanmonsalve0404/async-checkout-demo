import { loadAppConfig } from '../configuration/app-config';
import type { RuntimeSecrets } from '../configuration/runtime-secrets';
import { createSandboxTransport, loadSandboxRuntimeConfiguration } from './sandbox-runtime';

const publicKey = ['pub', 'test', 'synthetic-not-a-real'].join('_');
const privateKey = ['prv', 'test', 'synthetic-not-a-real'].join('_');
const assessmentConfig = loadAppConfig({
  ALLOWED_ORIGIN: 'https://checkout.example.test',
  APP_ENV: 'assessment',
  AUTO_SEED_CATALOG: 'false',
  DATA_ADAPTER: 'dynamodb',
  PAYMENT_ADAPTER: 'sandbox',
  PAYMENTS_ENABLED: 'true',
  PRERELEASE_ACCESS_MODE: 'origin_gate',
  SANDBOX_AUTHORIZED_UNTIL_UTC: '2099-01-01T00:00:00.000Z',
  PUBLIC_ASSET_ORIGIN: 'https://checkout.example.test',
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
    personalDataPermalink: 'https://comercios.wompi.co/datos/synthetic',
  },
};
const response = (body: unknown, status = 200): Response =>
  ({
    status,
    headers: { get: () => 'application/json' },
    text: async () => JSON.stringify(body),
  }) as unknown as Response;

describe('sandbox runtime boundary', () => {
  it('loads the authorized merchant contracts without provider traffic during bootstrap', async () => {
    const fetchImplementation = jest.fn();
    await expect(loadSandboxRuntimeConfiguration(assessmentConfig, secrets)).resolves.toMatchObject(
      {
        contracts: [{ type: 'TERMS' }, { type: 'PERSONAL_DATA' }],
        providerAcceptances: {
          terms: 'terms-provider-synthetic',
          personalData: 'personal-provider-synthetic',
        },
      },
    );
    expect(fetchImplementation).not.toHaveBeenCalled();
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

  it('keeps bootstrap alive but rejects an expired authorization before transaction traffic', async () => {
    const fetchImplementation = jest.fn();
    const expired = loadAppConfig({
      ALLOWED_ORIGIN: 'https://checkout.example.test',
      APP_ENV: 'assessment',
      AUTO_SEED_CATALOG: 'false',
      DATA_ADAPTER: 'dynamodb',
      PAYMENT_ADAPTER: 'sandbox',
      PAYMENTS_ENABLED: 'true',
      PRERELEASE_ACCESS_MODE: 'origin_gate',
      PUBLIC_ASSET_ORIGIN: 'https://checkout.example.test',
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
      }),
    ).rejects.toThrow('SANDBOX_AUTHORIZATION_EXPIRED');
    expect(fetchImplementation).not.toHaveBeenCalled();
  });

  it('allows only one transaction create and bounded transaction reads', async () => {
    const fetchImplementation = jest
      .fn()
      .mockResolvedValue(response({ data: { status: 'PENDING' } }));
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
      }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      transport({
        method: 'GET',
        resource: '/v1/transactions/provider-synthetic',
        headers: { Authorization: `Bearer ${publicKey}` },
        timeoutMs: 1_000,
      }),
    ).resolves.toMatchObject({ status: 200 });
    await expect(
      transport({
        method: 'GET',
        resource: '/v1/merchants/unapproved',
        headers: { Authorization: `Bearer ${publicKey}` },
        timeoutMs: 1_000,
      }),
    ).rejects.toThrow('SANDBOX_REQUEST_BLOCKED');
    expect(fetchImplementation).toHaveBeenCalledTimes(2);
  });
});
