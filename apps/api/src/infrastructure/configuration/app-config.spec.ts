import { loadAppConfig } from './app-config';

const runtimeSecurityRootKey = Buffer.alloc(32, 7).toString('base64url');

describe('loadAppConfig', () => {
  it('uses fake-only local defaults', () => {
    expect(loadAppConfig({ NODE_ENV: 'test' })).toMatchObject({
      apiPort: 3000,
      appEnvironment: 'local',
      dataAdapter: 'memory',
      paymentAdapter: 'fake',
      paymentsEnabled: false,
      tokenizationMode: 'disabled',
    });
  });

  it.each([
    { ALLOWED_ORIGIN: '*' },
    { PAYMENT_ADAPTER: 'real' },
    { PAYMENTS_ENABLED: 'true' },
    { DATA_ADAPTER: 'dynamodb', DYNAMODB_ENDPOINT: 'https://dynamodb.example.invalid' },
  ])('fails closed for invalid configuration %#', (environment) => {
    expect(() => loadAppConfig(environment)).toThrow();
  });

  it('allows an explicitly local DynamoDB endpoint', () => {
    expect(
      loadAppConfig({
        DATA_ADAPTER: 'dynamodb',
        DYNAMODB_ENDPOINT: 'http://127.0.0.1:8000',
        RUNTIME_SECURITY_ROOT_KEY: runtimeSecurityRootKey,
      }).dataAdapter,
    ).toBe('dynamodb');
  });

  it('requires a valid stable root key only for DynamoDB', () => {
    expect(() =>
      loadAppConfig({ DATA_ADAPTER: 'dynamodb', DYNAMODB_ENDPOINT: 'http://localhost:8000' }),
    ).toThrow();
    expect(() => loadAppConfig({ RUNTIME_SECURITY_ROOT_KEY: 'too-short' })).toThrow();
    expect(() => loadAppConfig({ RUNTIME_SECURITY_ROOT_KEY: 'A'.repeat(45) })).toThrow();
    expect(loadAppConfig({ RUNTIME_SECURITY_ROOT_KEY: runtimeSecurityRootKey })).toMatchObject({
      dataAdapter: 'memory',
      runtimeSecurityRootKey,
    });
  });

  it('allows zero TTL only in APP_ENV=test for deterministic expiry checks', () => {
    expect(
      loadAppConfig({ APP_ENV: 'test', CHECKOUT_TTL_SECONDS: '0', QUOTE_TTL_SECONDS: '0' }),
    ).toMatchObject({ checkoutTtlSeconds: 0, quoteTtlSeconds: 0 });
    expect(() =>
      loadAppConfig({ APP_ENV: 'local', CHECKOUT_TTL_SECONDS: '0', QUOTE_TTL_SECONDS: '0' }),
    ).toThrow();
    expect(() => loadAppConfig({ APP_ENV: 'preview', CHECKOUT_TTL_SECONDS: '0' })).toThrow();
  });

  it.each(
    Array.from({ length: 12 }, (_value, index) => {
      const number = String(index + 1).padStart(2, '0');
      return 'FAKE-E5-' + number;
    }),
  )('accepts exact deterministic scenario %s', (scenario) => {
    expect(loadAppConfig({ FAKE_PAYMENT_SCENARIO: scenario }).fakePaymentScenario).toBe(scenario);
  });
});
