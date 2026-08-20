import { loadAppConfig } from './app-config';
import { loadRuntimeSecrets, type SecretReader } from './runtime-secrets';

const secretArn = [
  'arn:aws:secretsmanager:us-east-1:000000000000',
  'secret',
  'checkout/assessment/runtime-AbCd12',
].join(':');
const secretVersionId = 'a'.repeat(32);
const assessmentConfig = loadAppConfig({
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
  RUNTIME_SECRET_ARN: secretArn,
  RUNTIME_SECRET_VERSION_ID: secretVersionId,
  SANDBOX_AUTHORIZED_UNTIL_UTC: '2099-01-01T00:00:00.000Z',
  TOKENIZATION_MODE: 'direct_jwe',
});
const fakeAssessmentConfig = loadAppConfig({
  ALLOWED_ORIGIN: 'https://checkout.example.test',
  APP_ENV: 'assessment',
  AUTO_SEED_CATALOG: 'false',
  CANDIDATE_SHA: 'a'.repeat(40),
  DATA_ADAPTER: 'dynamodb',
  PAYMENT_ADAPTER: 'fake',
  PAYMENTS_ENABLED: 'false',
  PRERELEASE_ACCESS_MODE: 'origin_gate',
  PUBLIC_ASSET_ORIGIN: 'https://checkout.example.test',
  RUNTIME_SECRET_ARN: secretArn,
  RUNTIME_SECRET_VERSION_ID: secretVersionId,
  TOKENIZATION_MODE: 'disabled',
});
const prereleaseAssessmentConfig = loadAppConfig({
  ALLOWED_ORIGIN: 'https://d111111abcdef8.cloudfront.net',
  APP_ENV: 'assessment',
  AUTO_SEED_CATALOG: 'false',
  CANDIDATE_SHA: 'a'.repeat(40),
  DATA_ADAPTER: 'dynamodb',
  PAYMENT_ADAPTER: 'sandbox',
  PAYMENTS_ENABLED: 'true',
  PRERELEASE_ACCESS_MODE: 'cloudfront_signed_cookie',
  PUBLIC_ASSET_ORIGIN: 'https://d111111abcdef8.cloudfront.net',
  RELEASE_ID: 'rel-20260819-1200-aaaaaaa',
  RUNTIME_SECRET_ARN: secretArn,
  RUNTIME_SECRET_VERSION_ID: secretVersionId,
  SANDBOX_AUTHORIZED_UNTIL_UTC: '2099-01-01T00:00:00.000Z',
  TOKENIZATION_MODE: 'direct_jwe',
});

const acceptanceJwt = (payload: Readonly<Record<string, unknown>>): string =>
  [
    Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify(payload)).toString('base64url'),
    Buffer.from('synthetic-signature').toString('base64url'),
  ].join('.');

const secretDocument = (overrides: Readonly<Record<string, unknown>> = {}): string =>
  JSON.stringify({
    runtimeSecurityRootKey: Buffer.alloc(32, 7).toString('base64url'),
    publicKey: ['pub', 'test', 'synthetic-not-a-real'].join('_'),
    privateKey: ['prv', 'test', 'synthetic-not-a-real'].join('_'),
    integritySecret: ['test', 'integrity', 'synthetic-not-a-real'].join('_'),
    termsAcceptanceToken: 'terms-provider-synthetic',
    termsPermalink: 'https://comercios.wompi.co/terminos/synthetic',
    personalDataAcceptanceToken: 'personal-provider-synthetic',
    personalDataPermalink: 'https://wompi.com/datos/synthetic',
    ...overrides,
  });

const prereleaseSecretDocument = (overrides: Readonly<Record<string, unknown>> = {}): string =>
  JSON.stringify({
    ...JSON.parse(secretDocument(overrides)),
    prereleaseOriginToken: Buffer.alloc(32, 13).toString('base64url'),
  });

describe('runtime secrets boundary', () => {
  it('loads one exact secret document by ARN and returns only required fields', async () => {
    const reader = {
      send: jest.fn().mockResolvedValue({ SecretString: prereleaseSecretDocument() }),
    };
    await expect(loadRuntimeSecrets(assessmentConfig, reader)).resolves.toMatchObject({
      prereleaseOriginToken: Buffer.alloc(32, 13).toString('base64url'),
      runtimeSecurityRootKey: Buffer.alloc(32, 7).toString('base64url'),
      sandbox: {
        publicKey: ['pub', 'test', 'synthetic-not-a-real'].join('_'),
        privateKey: ['prv', 'test', 'synthetic-not-a-real'].join('_'),
        integritySecret: ['test', 'integrity', 'synthetic-not-a-real'].join('_'),
        termsAcceptanceToken: 'terms-provider-synthetic',
        termsPermalink: 'https://comercios.wompi.co/terminos/synthetic',
        personalDataAcceptanceToken: 'personal-provider-synthetic',
        personalDataPermalink: 'https://wompi.com/datos/synthetic',
      },
    });
    expect(reader.send).toHaveBeenCalledTimes(1);
    expect(reader.send.mock.calls[0]?.[0].input).toEqual({
      SecretId: secretArn,
      VersionId: secretVersionId,
    });
  });

  it('requires one canonical origin token for every guarded assessment release', async () => {
    const reader = (SecretString: string): SecretReader => ({
      send: jest.fn().mockResolvedValue({ SecretString }),
    });
    await expect(
      loadRuntimeSecrets(prereleaseAssessmentConfig, reader(prereleaseSecretDocument())),
    ).resolves.toMatchObject({
      prereleaseOriginToken: Buffer.alloc(32, 13).toString('base64url'),
    });
    await expect(
      loadRuntimeSecrets(prereleaseAssessmentConfig, reader(secretDocument())),
    ).rejects.toThrow('RUNTIME_SECRET_INVALID');
    await expect(
      loadRuntimeSecrets(
        prereleaseAssessmentConfig,
        reader(
          JSON.stringify({
            ...JSON.parse(secretDocument()),
            prereleaseOriginToken: 'manual-boolean-like-bypass',
          }),
        ),
      ),
    ).rejects.toThrow('RUNTIME_SECRET_INVALID');
    await expect(loadRuntimeSecrets(assessmentConfig, reader(secretDocument()))).rejects.toThrow(
      'RUNTIME_SECRET_INVALID',
    );
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

  it('keeps structurally valid expired and short-lived tokens as non-authoritative snapshots', async () => {
    const currentTime = new Date('2026-08-19T12:00:00.000Z');
    const currentEpochSeconds = currentTime.getTime() / 1_000;
    const reader = (SecretString: string): SecretReader => ({
      send: jest.fn().mockResolvedValue({ SecretString }),
    });
    for (const termsAcceptanceToken of [
      acceptanceJwt({ exp: currentEpochSeconds - 1 }),
      acceptanceJwt({ exp: currentEpochSeconds + assessmentConfig.quoteTtlSeconds }),
    ]) {
      await expect(
        loadRuntimeSecrets(
          assessmentConfig,
          reader(prereleaseSecretDocument({ termsAcceptanceToken })),
        ),
      ).resolves.toMatchObject({ sandbox: { termsAcceptanceToken } });
    }
  });

  it('fails closed for a structurally malformed acceptance token snapshot', async () => {
    const reader: SecretReader = {
      send: jest.fn().mockResolvedValue({
        SecretString: prereleaseSecretDocument({
          termsAcceptanceToken: 'synthetic.invalid-token.signature',
        }),
      }),
    };
    await expect(loadRuntimeSecrets(assessmentConfig, reader)).rejects.toThrow(
      'RUNTIME_SECRET_INVALID',
    );
  });

  it('accepts JWT tokens that cover the quote lifetime and JWT tokens without exp', async () => {
    const currentTime = new Date('2026-08-19T12:00:00.000Z');
    const currentEpochSeconds = currentTime.getTime() / 1_000;
    const reader = (SecretString: string): SecretReader => ({
      send: jest.fn().mockResolvedValue({ SecretString }),
    });
    await expect(
      loadRuntimeSecrets(
        assessmentConfig,
        reader(
          prereleaseSecretDocument({
            termsAcceptanceToken: acceptanceJwt({
              exp: currentEpochSeconds + assessmentConfig.quoteTtlSeconds + 1,
            }),
            personalDataAcceptanceToken: acceptanceJwt({ contract_id: 2 }),
          }),
        ),
      ),
    ).resolves.toMatchObject({
      sandbox: { personalDataPermalink: 'https://wompi.com/datos/synthetic' },
    });
  });

  it('rejects non-official and lookalike permalink hosts', async () => {
    const reader = (SecretString: string): SecretReader => ({
      send: jest.fn().mockResolvedValue({ SecretString }),
    });
    for (const termsPermalink of [
      'http://wompi.com/terms',
      'https://wompi.com.example.test/terms',
      'https://evilwompi.co/terms',
    ]) {
      await expect(
        loadRuntimeSecrets(assessmentConfig, reader(prereleaseSecretDocument({ termsPermalink }))),
      ).rejects.toThrow('RUNTIME_SECRET_INVALID');
    }
  });

  it('accepts only a root-key document when the release keeps sandbox disabled', async () => {
    const reader = {
      send: jest.fn().mockResolvedValue({
        SecretString: JSON.stringify({
          runtimeSecurityRootKey: Buffer.alloc(32, 11).toString('base64url'),
          prereleaseOriginToken: Buffer.alloc(32, 13).toString('base64url'),
        }),
      }),
    };
    await expect(loadRuntimeSecrets(fakeAssessmentConfig, reader)).resolves.toEqual({
      prereleaseOriginToken: Buffer.alloc(32, 13).toString('base64url'),
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
