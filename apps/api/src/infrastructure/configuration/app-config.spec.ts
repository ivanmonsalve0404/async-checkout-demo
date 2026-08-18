import { loadAppConfig, loadRuntimeAppConfig } from './app-config';

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
    { ALLOWED_ORIGIN: 'https://user:password@example.test' },
    { ALLOWED_ORIGIN: 'https://example.test/path' },
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

  it('accepts only the complete authorized assessment sandbox shape', () => {
    const configuration = loadAppConfig({
      ALLOWED_ORIGIN: 'https://checkout.example.test',
      APP_ENV: 'assessment',
      AUTO_SEED_CATALOG: 'false',
      AWS_REGION: 'us-east-1',
      DATA_ADAPTER: 'dynamodb',
      PAYMENT_ADAPTER: 'sandbox',
      PAYMENTS_ENABLED: 'true',
      PUBLIC_ASSET_ORIGIN: 'https://checkout.example.test',
      RUNTIME_SECRET_ARN: [
        'arn:aws:secretsmanager:us-east-1:000000000000',
        'secret',
        'checkout/assessment/runtime-AbCd12',
      ].join(':'),
      SANDBOX_AUTHORIZED_UNTIL_UTC: '2099-01-01T00:00:00.000Z',
      TOKENIZATION_MODE: 'direct_jwe',
    });
    expect(configuration).toMatchObject({
      appEnvironment: 'assessment',
      autoSeedCatalog: false,
      awsRegion: 'us-east-1',
      dataAdapter: 'dynamodb',
      dynamoDbEndpoint: undefined,
      paymentAdapter: 'sandbox',
      paymentsEnabled: true,
      sandboxAuthorizedUntilUtc: '2099-01-01T00:00:00.000Z',
      tokenizationMode: 'direct_jwe',
    });
    expect(() =>
      loadAppConfig({
        ALLOWED_ORIGIN: 'https://checkout.example.test',
        APP_ENV: 'assessment',
        AUTO_SEED_CATALOG: 'false',
        DATA_ADAPTER: 'dynamodb',
        PAYMENT_ADAPTER: 'sandbox',
        PAYMENTS_ENABLED: 'true',
        PUBLIC_ASSET_ORIGIN: 'https://checkout.example.test',
        RUNTIME_SECRET_ARN: [
          'arn:aws:secretsmanager:us-east-1:000000000000',
          'secret',
          'checkout/assessment/runtime-AbCd12',
        ].join(':'),
        SANDBOX_AUTHORIZED_UNTIL_UTC: '2099-02-31T00:00:00.000Z',
        TOKENIZATION_MODE: 'direct_jwe',
      }),
    ).toThrow();
  });

  it.each([
    { APP_ENV: 'assessment', AUTO_SEED_CATALOG: 'false', DATA_ADAPTER: 'memory' },
    {
      APP_ENV: 'assessment',
      AUTO_SEED_CATALOG: 'false',
      DATA_ADAPTER: 'dynamodb',
      DYNAMODB_ENDPOINT: 'http://127.0.0.1:8000',
      RUNTIME_SECRET_ARN: [
        'arn:aws:secretsmanager:us-east-1:000000000000',
        'secret',
        'checkout/assessment/runtime-AbCd12',
      ].join(':'),
    },
    {
      APP_ENV: 'assessment',
      DATA_ADAPTER: 'dynamodb',
      RUNTIME_SECRET_ARN: [
        'arn:aws:secretsmanager:us-east-1:000000000000',
        'secret',
        'checkout/assessment/runtime-AbCd12',
      ].join(':'),
    },
    {
      ALLOWED_ORIGIN: 'http://checkout.example.test',
      APP_ENV: 'assessment',
      AUTO_SEED_CATALOG: 'false',
      DATA_ADAPTER: 'dynamodb',
      PUBLIC_ASSET_ORIGIN: 'http://checkout.example.test',
      RUNTIME_SECRET_ARN: [
        'arn:aws:secretsmanager:us-east-1:000000000000',
        'secret',
        'checkout/assessment/runtime-AbCd12',
      ].join(':'),
    },
    {
      ALLOWED_ORIGIN: 'https://checkout.example.test',
      APP_ENV: 'assessment',
      AUTO_SEED_CATALOG: 'false',
      DATA_ADAPTER: 'dynamodb',
      PUBLIC_ASSET_ORIGIN: 'https://assets.example.test',
      RUNTIME_SECRET_ARN: [
        'arn:aws:secretsmanager:us-east-1:000000000000',
        'secret',
        'checkout/assessment/runtime-AbCd12',
      ].join(':'),
    },
  ])('rejects an incomplete assessment configuration %#', (environment) => {
    expect(() => loadAppConfig(environment)).toThrow();
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

  it('resolves assessment public origins from exact SSM parameter references', async () => {
    const send = jest.fn().mockResolvedValue({
      Parameter: { Value: 'https://d111111abcdef8.cloudfront.net' },
    });
    await expect(
      loadRuntimeAppConfig(
        {
          ALLOWED_ORIGIN_PARAMETER_NAME: '/checkout/assessment-release/public-origin',
          APP_ENV: 'assessment',
          AUTO_SEED_CATALOG: 'false',
          DATA_ADAPTER: 'dynamodb',
          PAYMENT_ADAPTER: 'fake',
          PUBLIC_ASSET_ORIGIN_PARAMETER_NAME: '/checkout/assessment-release/public-origin',
          RUNTIME_SECRET_ARN: [
            'arn:aws:secretsmanager:us-east-1:000000000000',
            'secret',
            'checkout/assessment/runtime-AbCd12',
          ].join(':'),
        },
        { send },
      ),
    ).resolves.toMatchObject({
      allowedOrigin: 'https://d111111abcdef8.cloudfront.net',
      publicAssetOrigin: 'https://d111111abcdef8.cloudfront.net',
    });
    expect(send).toHaveBeenCalledTimes(1);
    expect(send.mock.calls[0]?.[0].input).toEqual({
      Name: '/checkout/assessment-release/public-origin',
      WithDecryption: false,
    });
  });

  it('fails closed for incomplete or unavailable public configuration references', async () => {
    await expect(
      loadRuntimeAppConfig({
        ALLOWED_ORIGIN_PARAMETER_NAME: '/checkout/assessment-release/public-origin',
        APP_ENV: 'assessment',
      }),
    ).rejects.toThrow('PUBLIC_CONFIGURATION_REFERENCE_INVALID');
    await expect(
      loadRuntimeAppConfig(
        {
          ALLOWED_ORIGIN_PARAMETER_NAME: '/checkout/assessment-release/public-origin',
          APP_ENV: 'assessment',
          PUBLIC_ASSET_ORIGIN_PARAMETER_NAME: '/checkout/assessment-release/public-origin',
        },
        { send: jest.fn().mockResolvedValue({}) },
      ),
    ).rejects.toThrow('PUBLIC_CONFIGURATION_UNAVAILABLE');
  });
});
