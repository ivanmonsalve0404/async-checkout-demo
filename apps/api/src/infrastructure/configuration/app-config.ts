import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import { z } from 'zod';

const httpOrigin = z
  .string()
  .url()
  .refine((value) => {
    const parsed = new URL(value);
    return (
      !value.includes('*') &&
      parsed.origin === value &&
      parsed.username.length === 0 &&
      parsed.password.length === 0 &&
      (parsed.protocol === 'http:' || parsed.protocol === 'https:')
    );
  }, 'an exact HTTP origin without credentials is required');

const awsRegion = z.string().regex(/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/u);
const secretArn = z
  .string()
  .regex(
    /^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]{1,512}$/u,
  );
const canonicalUtc = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u)
  .refine((value) => {
    const parsed = new Date(value);
    return !Number.isNaN(parsed.getTime()) && parsed.toISOString() === value;
  }, 'an exact UTC timestamp is required');

const environmentSchema = z
  .object({
    ALLOWED_ORIGIN: httpOrigin.default('http://localhost:5173'),
    API_BASE_PATH: z.literal('/api/v1').default('/api/v1'),
    API_PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
    APP_ENV: z.enum(['local', 'test', 'preview', 'assessment']).default('local'),
    AWS_REGION: awsRegion.default('us-east-1'),
    CATALOG_TABLE_NAME: z.string().min(3).max(255).default('checkout-catalog-local'),
    CHECKOUT_TABLE_NAME: z.string().min(3).max(255).default('checkout-session-local'),
    DATA_ADAPTER: z.enum(['memory', 'dynamodb']).default('memory'),
    CHECKOUT_TTL_SECONDS: z.coerce.number().int().min(0).max(86_400).default(1800),
    FAKE_PAYMENT_SCENARIO: z
      .enum([
        'FAKE-PAY-01',
        'FAKE-PAY-02',
        'FAKE-PAY-03',
        'FAKE-PAY-04',
        'FAKE-PAY-05',
        'FAKE-PAY-06',
        'FAKE-PAY-07',
        'FAKE-PAY-08',
        'FAKE-PAY-09',
        'FAKE-PAY-10',
        'FAKE-PAY-11',
        'FAKE-PAY-12',
        'FAKE-E5-01',
        'FAKE-E5-02',
        'FAKE-E5-03',
        'FAKE-E5-04',
        'FAKE-E5-05',
        'FAKE-E5-06',
        'FAKE-E5-07',
        'FAKE-E5-08',
        'FAKE-E5-09',
        'FAKE-E5-10',
        'FAKE-E5-11',
        'FAKE-E5-12',
      ])
      .default('FAKE-E5-01'),
    FAKE_RECONCILE_INTERVAL_MS: z.coerce.number().int().min(10).max(60_000).default(100),
    PRODUCT_INITIAL_STOCK: z.coerce.number().int().min(0).max(999_999).default(3),
    QUOTE_TTL_SECONDS: z.coerce.number().int().min(0).max(3600).default(900),
    DYNAMODB_ENDPOINT: z.string().url().optional(),
    LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    PAYMENT_ADAPTER: z.enum(['fake', 'sandbox']).default('fake'),
    PAYMENTS_ENABLED: z.enum(['true', 'false']).default('false'),
    PRODUCT_SEED_ID: z
      .string()
      .regex(/^[A-Za-z0-9_-]{8,128}$/)
      .default('product-demo-001'),
    PRERELEASE_ACCESS_MODE: z
      .enum(['disabled', 'origin_gate', 'cloudfront_signed_cookie'])
      .default('disabled'),
    PUBLIC_ASSET_ORIGIN: httpOrigin.default('http://localhost:5173'),
    AUTO_SEED_CATALOG: z.enum(['true', 'false']).default('true'),
    RUNTIME_SECURITY_ROOT_KEY: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43,128}$/)
      .refine(
        (value) => Buffer.from(value, 'base64url').toString('base64url') === value,
        'root key must be canonical base64url',
      )
      .optional(),
    RUNTIME_SECRET_ARN: secretArn.optional(),
    RUNTIME_SECRET_VERSION_ID: z
      .string()
      .regex(/^[A-Za-z0-9-]{32,64}$/u)
      .optional(),
    SANDBOX_AUTHORIZED_UNTIL_UTC: canonicalUtc.optional(),
    TOKENIZATION_MODE: z.enum(['disabled', 'direct_jwe']).default('disabled'),
  })
  .superRefine((configuration, context) => {
    if (configuration.DATA_ADAPTER === 'dynamodb') {
      const endpoint = configuration.DYNAMODB_ENDPOINT;
      if (configuration.APP_ENV === 'assessment') {
        if (endpoint !== undefined) {
          context.addIssue({
            code: 'custom',
            path: ['DYNAMODB_ENDPOINT'],
            message: 'assessment uses the regional DynamoDB endpoint through the AWS SDK',
          });
        }
        if (
          configuration.RUNTIME_SECRET_ARN === undefined ||
          configuration.RUNTIME_SECRET_VERSION_ID === undefined
        ) {
          context.addIssue({
            code: 'custom',
            path: ['RUNTIME_SECRET_ARN'],
            message: 'assessment DynamoDB requires a runtime secret reference',
          });
        }
      } else if (endpoint === undefined) {
        context.addIssue({
          code: 'custom',
          path: ['DYNAMODB_ENDPOINT'],
          message: 'local DynamoDB requires an explicit endpoint',
        });
      } else if (!['localhost', '127.0.0.1'].includes(new URL(endpoint).hostname)) {
        context.addIssue({
          code: 'custom',
          path: ['DYNAMODB_ENDPOINT'],
          message: 'stage 4 permits DynamoDB only through a local endpoint',
        });
      }
      if (
        configuration.APP_ENV !== 'assessment' &&
        configuration.RUNTIME_SECURITY_ROOT_KEY === undefined
      ) {
        context.addIssue({
          code: 'custom',
          path: ['RUNTIME_SECURITY_ROOT_KEY'],
          message: 'DynamoDB requires a stable runtime security root key',
        });
      }
    }
    if (configuration.APP_ENV === 'assessment' && configuration.DATA_ADAPTER !== 'dynamodb') {
      context.addIssue({
        code: 'custom',
        path: ['DATA_ADAPTER'],
        message: 'assessment requires the DynamoDB adapter',
      });
    }
    if (
      configuration.APP_ENV === 'assessment' &&
      (new URL(configuration.ALLOWED_ORIGIN).protocol !== 'https:' ||
        configuration.ALLOWED_ORIGIN !== configuration.PUBLIC_ASSET_ORIGIN)
    ) {
      context.addIssue({
        code: 'custom',
        path: ['ALLOWED_ORIGIN'],
        message: 'assessment requires one exact HTTPS same-origin entry point',
      });
    }
    if (
      configuration.APP_ENV === 'assessment' &&
      configuration.PRERELEASE_ACCESS_MODE === 'disabled'
    ) {
      context.addIssue({
        code: 'custom',
        path: ['PRERELEASE_ACCESS_MODE'],
        message: 'assessment requires the CloudFront-to-origin verification gate',
      });
    }
    const paymentsEnabled = configuration.PAYMENTS_ENABLED === 'true';
    if (
      paymentsEnabled &&
      (configuration.APP_ENV !== 'assessment' ||
        configuration.PAYMENT_ADAPTER !== 'sandbox' ||
        configuration.TOKENIZATION_MODE !== 'direct_jwe' ||
        configuration.RUNTIME_SECRET_ARN === undefined ||
        configuration.RUNTIME_SECRET_VERSION_ID === undefined ||
        configuration.SANDBOX_AUTHORIZED_UNTIL_UTC === undefined)
    ) {
      context.addIssue({
        code: 'custom',
        path: ['PAYMENTS_ENABLED'],
        message: 'payments require the authorized assessment sandbox configuration',
      });
    }
    if (configuration.APP_ENV === 'assessment' && configuration.AUTO_SEED_CATALOG !== 'false') {
      context.addIssue({
        code: 'custom',
        path: ['AUTO_SEED_CATALOG'],
        message: 'assessment seed must run as an explicit idempotent release step',
      });
    }
    if (
      configuration.PRERELEASE_ACCESS_MODE !== 'disabled' &&
      (configuration.APP_ENV !== 'assessment' ||
        configuration.RUNTIME_SECRET_ARN === undefined ||
        configuration.RUNTIME_SECRET_VERSION_ID === undefined)
    ) {
      context.addIssue({
        code: 'custom',
        path: ['PRERELEASE_ACCESS_MODE'],
        message: 'prerelease access requires assessment and one runtime secret reference',
      });
    }
    if (
      configuration.APP_ENV !== 'test' &&
      (configuration.CHECKOUT_TTL_SECONDS === 0 || configuration.QUOTE_TTL_SECONDS === 0)
    ) {
      context.addIssue({
        code: 'custom',
        path: ['CHECKOUT_TTL_SECONDS'],
        message: 'zero TTL is restricted to deterministic tests',
      });
    }
  });

export interface AppConfig {
  readonly allowedOrigin: string;
  readonly apiBasePath: '/api/v1';
  readonly apiPort: number;
  readonly appEnvironment: 'local' | 'test' | 'preview' | 'assessment';
  readonly awsRegion: string;
  readonly autoSeedCatalog: boolean;
  readonly catalogTableName: string;
  readonly checkoutTableName: string;
  readonly dataAdapter: 'memory' | 'dynamodb';
  readonly checkoutTtlSeconds: number;
  readonly fakePaymentScenario:
    | 'FAKE-PAY-01'
    | 'FAKE-PAY-02'
    | 'FAKE-PAY-03'
    | 'FAKE-PAY-04'
    | 'FAKE-PAY-05'
    | 'FAKE-PAY-06'
    | 'FAKE-PAY-07'
    | 'FAKE-PAY-08'
    | 'FAKE-PAY-09'
    | 'FAKE-PAY-10'
    | 'FAKE-PAY-11'
    | 'FAKE-PAY-12'
    | 'FAKE-E5-01'
    | 'FAKE-E5-02'
    | 'FAKE-E5-03'
    | 'FAKE-E5-04'
    | 'FAKE-E5-05'
    | 'FAKE-E5-06'
    | 'FAKE-E5-07'
    | 'FAKE-E5-08'
    | 'FAKE-E5-09'
    | 'FAKE-E5-10'
    | 'FAKE-E5-11'
    | 'FAKE-E5-12';
  readonly fakeReconcileIntervalMs: number;
  readonly productInitialStock: number;
  readonly quoteTtlSeconds: number;
  readonly dynamoDbEndpoint: string | undefined;
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
  readonly paymentAdapter: 'fake' | 'sandbox';
  readonly paymentsEnabled: boolean;
  readonly productSeedId: string;
  readonly prereleaseAccessMode: 'disabled' | 'origin_gate' | 'cloudfront_signed_cookie';
  readonly publicAssetOrigin: string;
  readonly tokenizationMode: 'disabled' | 'direct_jwe';
  readonly runtimeSecurityRootKey: string | undefined;
  readonly runtimeSecretArn: string | undefined;
  readonly runtimeSecretVersionId: string | undefined;
  readonly sandboxAuthorizedUntilUtc: string | undefined;
}

export const loadAppConfig = (environment: NodeJS.ProcessEnv): AppConfig => {
  const parsed = environmentSchema.parse(environment);
  return {
    allowedOrigin: parsed.ALLOWED_ORIGIN,
    apiBasePath: parsed.API_BASE_PATH,
    apiPort: parsed.API_PORT,
    appEnvironment: parsed.APP_ENV,
    awsRegion: parsed.AWS_REGION,
    autoSeedCatalog: parsed.AUTO_SEED_CATALOG === 'true',
    catalogTableName: parsed.CATALOG_TABLE_NAME,
    checkoutTableName: parsed.CHECKOUT_TABLE_NAME,
    dataAdapter: parsed.DATA_ADAPTER,
    dynamoDbEndpoint:
      parsed.DYNAMODB_ENDPOINT ??
      (parsed.APP_ENV === 'assessment' ? undefined : 'http://localhost:8000'),
    checkoutTtlSeconds: parsed.CHECKOUT_TTL_SECONDS,
    fakePaymentScenario: parsed.FAKE_PAYMENT_SCENARIO,
    fakeReconcileIntervalMs: parsed.FAKE_RECONCILE_INTERVAL_MS,
    productInitialStock: parsed.PRODUCT_INITIAL_STOCK,
    quoteTtlSeconds: parsed.QUOTE_TTL_SECONDS,
    logLevel: parsed.LOG_LEVEL,
    paymentAdapter: parsed.PAYMENT_ADAPTER,
    paymentsEnabled: parsed.PAYMENTS_ENABLED === 'true',
    productSeedId: parsed.PRODUCT_SEED_ID,
    prereleaseAccessMode: parsed.PRERELEASE_ACCESS_MODE,
    publicAssetOrigin: parsed.PUBLIC_ASSET_ORIGIN,
    tokenizationMode: parsed.TOKENIZATION_MODE,
    runtimeSecurityRootKey: parsed.RUNTIME_SECURITY_ROOT_KEY,
    runtimeSecretArn: parsed.RUNTIME_SECRET_ARN,
    runtimeSecretVersionId: parsed.RUNTIME_SECRET_VERSION_ID,
    sandboxAuthorizedUntilUtc: parsed.SANDBOX_AUTHORIZED_UNTIL_UTC,
  };
};

export interface PublicConfigurationReader {
  send(command: GetParameterCommand): Promise<Readonly<{ Parameter?: { Value?: string } }>>;
}

const parameterName = /^\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+){1,9}$/u;

export const loadRuntimeAppConfig = async (
  environment: NodeJS.ProcessEnv,
  reader?: PublicConfigurationReader,
): Promise<AppConfig> => {
  const allowedOriginParameter = environment.ALLOWED_ORIGIN_PARAMETER_NAME;
  const publicAssetOriginParameter = environment.PUBLIC_ASSET_ORIGIN_PARAMETER_NAME;
  if (allowedOriginParameter === undefined && publicAssetOriginParameter === undefined) {
    return loadAppConfig(environment);
  }
  if (
    environment.APP_ENV !== 'assessment' ||
    typeof allowedOriginParameter !== 'string' ||
    typeof publicAssetOriginParameter !== 'string' ||
    !parameterName.test(allowedOriginParameter) ||
    !parameterName.test(publicAssetOriginParameter)
  ) {
    throw new Error('PUBLIC_CONFIGURATION_REFERENCE_INVALID');
  }
  const parameterReader =
    reader ?? new SSMClient({ region: environment.AWS_REGION ?? 'us-east-1' });
  const values = new Map<string, string>();
  for (const name of new Set([allowedOriginParameter, publicAssetOriginParameter])) {
    const response = await parameterReader.send(
      new GetParameterCommand({ Name: name, WithDecryption: false }),
    );
    const value = response.Parameter?.Value;
    if (typeof value !== 'string' || value.length === 0) {
      throw new Error('PUBLIC_CONFIGURATION_UNAVAILABLE');
    }
    values.set(name, value);
  }
  return loadAppConfig({
    ...environment,
    ALLOWED_ORIGIN: values.get(allowedOriginParameter),
    PUBLIC_ASSET_ORIGIN: values.get(publicAssetOriginParameter),
  });
};

export const APP_CONFIG = Symbol('APP_CONFIG');
