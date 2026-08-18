import { loadAppConfig } from './app-config';
import { loadRuntimeSecrets, type SecretReader } from './runtime-secrets';

const secretArn = [
  'arn:aws:secretsmanager:us-east-1:000000000000',
  'secret',
  'checkout/assessment/runtime-AbCd12',
].join(':');
const assessmentConfig = loadAppConfig({
  ALLOWED_ORIGIN: 'https://checkout.example.test',
  APP_ENV: 'assessment',
  AUTO_SEED_CATALOG: 'false',
  DATA_ADAPTER: 'dynamodb',
  PAYMENT_ADAPTER: 'sandbox',
  PAYMENTS_ENABLED: 'true',
  PUBLIC_ASSET_ORIGIN: 'https://checkout.example.test',
  RUNTIME_SECRET_ARN: secretArn,
  SANDBOX_AUTHORIZED_UNTIL_UTC: '2099-01-01T00:00:00.000Z',
  TOKENIZATION_MODE: 'direct_jwe',
});
const fakeAssessmentConfig = loadAppConfig({
  ALLOWED_ORIGIN: 'https://checkout.example.test',
  APP_ENV: 'assessment',
  AUTO_SEED_CATALOG: 'false',
  DATA_ADAPTER: 'dynamodb',
  PAYMENT_ADAPTER: 'fake',
  PAYMENTS_ENABLED: 'false',
  PUBLIC_ASSET_ORIGIN: 'https://checkout.example.test',
  RUNTIME_SECRET_ARN: secretArn,
  TOKENIZATION_MODE: 'disabled',
});

const secretDocument = (): string =>
  JSON.stringify({
    runtimeSecurityRootKey: Buffer.alloc(32, 7).toString('base64url'),
    publicKey: ['pub', 'test', 'synthetic-not-a-real'].join('_'),
    privateKey: ['prv', 'test', 'synthetic-not-a-real'].join('_'),
    integritySecret: ['test', 'integrity', 'synthetic-not-a-real'].join('_'),
    termsAcceptanceToken: 'terms-provider-synthetic',
    termsPermalink: 'https://comercios.wompi.co/terminos/synthetic',
    personalDataAcceptanceToken: 'personal-provider-synthetic',
    personalDataPermalink: 'https://comercios.wompi.co/datos/synthetic',
  });

describe('runtime secrets boundary', () => {
  it('loads one exact secret document by ARN and returns only required fields', async () => {
    const reader = { send: jest.fn().mockResolvedValue({ SecretString: secretDocument() }) };
    await expect(loadRuntimeSecrets(assessmentConfig, reader)).resolves.toMatchObject({
      runtimeSecurityRootKey: Buffer.alloc(32, 7).toString('base64url'),
      sandbox: {
        publicKey: ['pub', 'test', 'synthetic-not-a-real'].join('_'),
        privateKey: ['prv', 'test', 'synthetic-not-a-real'].join('_'),
        integritySecret: ['test', 'integrity', 'synthetic-not-a-real'].join('_'),
        termsAcceptanceToken: 'terms-provider-synthetic',
        termsPermalink: 'https://comercios.wompi.co/terminos/synthetic',
        personalDataAcceptanceToken: 'personal-provider-synthetic',
        personalDataPermalink: 'https://comercios.wompi.co/datos/synthetic',
      },
    });
    expect(reader.send).toHaveBeenCalledTimes(1);
    expect(reader.send.mock.calls[0]?.[0].input).toEqual({ SecretId: secretArn });
  });

  it('fails closed for missing, malformed, or extended secret documents', async () => {
    const reader = (SecretString: string | undefined): SecretReader => ({
      send: jest.fn().mockResolvedValue({ SecretString }),
    });
    await expect(loadRuntimeSecrets(assessmentConfig, reader(undefined))).rejects.toThrow(
      'RUNTIME_SECRET_INVALID',
    );
    await expect(loadRuntimeSecrets(assessmentConfig, reader('{'))).rejects.toThrow(
      'RUNTIME_SECRET_INVALID',
    );
    await expect(
      loadRuntimeSecrets(
        assessmentConfig,
        reader(JSON.stringify({ ...JSON.parse(secretDocument()), unexpected: true })),
      ),
    ).rejects.toThrow('RUNTIME_SECRET_INVALID');
  });

  it('accepts only a root-key document when the release keeps sandbox disabled', async () => {
    const reader = {
      send: jest.fn().mockResolvedValue({
        SecretString: JSON.stringify({
          runtimeSecurityRootKey: Buffer.alloc(32, 11).toString('base64url'),
        }),
      }),
    };
    await expect(loadRuntimeSecrets(fakeAssessmentConfig, reader)).resolves.toEqual({
      runtimeSecurityRootKey: Buffer.alloc(32, 11).toString('base64url'),
      sandbox: undefined,
    });
    await expect(
      loadRuntimeSecrets(fakeAssessmentConfig, {
        send: jest.fn().mockResolvedValue({ SecretString: secretDocument() }),
      }),
    ).rejects.toThrow('RUNTIME_SECRET_INVALID');
  });

  it('does not call Secrets Manager in local fake mode', async () => {
    const reader = { send: jest.fn() };
    await expect(
      loadRuntimeSecrets(
        loadAppConfig({
          APP_ENV: 'test',
          RUNTIME_SECURITY_ROOT_KEY: Buffer.alloc(32, 9).toString('base64url'),
        }),
        reader,
      ),
    ).resolves.toMatchObject({ sandbox: undefined });
    expect(reader.send).not.toHaveBeenCalled();
  });
});
