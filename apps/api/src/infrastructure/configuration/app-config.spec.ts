import { loadAppConfig } from './app-config';

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
      loadAppConfig({ DATA_ADAPTER: 'dynamodb', DYNAMODB_ENDPOINT: 'http://127.0.0.1:8000' })
        .dataAdapter,
    ).toBe('dynamodb');
  });
});
