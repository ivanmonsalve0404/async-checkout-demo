import { z } from 'zod';

const httpOrigin = z
  .string()
  .url()
  .refine((value) => !value.includes('*'), 'wildcard origin is forbidden');

const environmentSchema = z
  .object({
    ALLOWED_ORIGIN: httpOrigin.default('http://localhost:5173'),
    API_BASE_PATH: z.literal('/api/v1').default('/api/v1'),
    API_PORT: z.coerce.number().int().min(1).max(65_535).default(3000),
    APP_ENV: z.enum(['local', 'test', 'preview']).default('local'),
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
    DYNAMODB_ENDPOINT: z.string().url().default('http://localhost:8000'),
    LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    PAYMENT_ADAPTER: z.enum(['fake', 'sandbox']).default('fake'),
    PAYMENTS_ENABLED: z.literal('false').default('false'),
    PRODUCT_SEED_ID: z
      .string()
      .regex(/^[A-Za-z0-9_-]{8,128}$/)
      .default('product-demo-001'),
    PUBLIC_ASSET_ORIGIN: httpOrigin.default('http://localhost:5173'),
    RUNTIME_SECURITY_ROOT_KEY: z
      .string()
      .regex(/^[A-Za-z0-9_-]{43,128}$/)
      .refine(
        (value) => Buffer.from(value, 'base64url').toString('base64url') === value,
        'root key must be canonical base64url',
      )
      .optional(),
    TOKENIZATION_MODE: z.literal('disabled').default('disabled'),
  })
  .superRefine((configuration, context) => {
    if (configuration.DATA_ADAPTER === 'dynamodb') {
      const hostname = new URL(configuration.DYNAMODB_ENDPOINT).hostname;
      if (hostname !== 'localhost' && hostname !== '127.0.0.1') {
        context.addIssue({
          code: 'custom',
          path: ['DYNAMODB_ENDPOINT'],
          message: 'stage 4 permits DynamoDB only through a local endpoint',
        });
      }
      if (configuration.RUNTIME_SECURITY_ROOT_KEY === undefined) {
        context.addIssue({
          code: 'custom',
          path: ['RUNTIME_SECURITY_ROOT_KEY'],
          message: 'DynamoDB requires a stable runtime security root key',
        });
      }
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
  readonly appEnvironment: 'local' | 'test' | 'preview';
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
  readonly dynamoDbEndpoint: string;
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
  readonly paymentAdapter: 'fake' | 'sandbox';
  readonly paymentsEnabled: false;
  readonly productSeedId: string;
  readonly publicAssetOrigin: string;
  readonly tokenizationMode: 'disabled';
  readonly runtimeSecurityRootKey: string | undefined;
}

export const loadAppConfig = (environment: NodeJS.ProcessEnv): AppConfig => {
  const parsed = environmentSchema.parse(environment);
  return {
    allowedOrigin: parsed.ALLOWED_ORIGIN,
    apiBasePath: parsed.API_BASE_PATH,
    apiPort: parsed.API_PORT,
    appEnvironment: parsed.APP_ENV,
    catalogTableName: parsed.CATALOG_TABLE_NAME,
    checkoutTableName: parsed.CHECKOUT_TABLE_NAME,
    dataAdapter: parsed.DATA_ADAPTER,
    dynamoDbEndpoint: parsed.DYNAMODB_ENDPOINT,
    checkoutTtlSeconds: parsed.CHECKOUT_TTL_SECONDS,
    fakePaymentScenario: parsed.FAKE_PAYMENT_SCENARIO,
    fakeReconcileIntervalMs: parsed.FAKE_RECONCILE_INTERVAL_MS,
    productInitialStock: parsed.PRODUCT_INITIAL_STOCK,
    quoteTtlSeconds: parsed.QUOTE_TTL_SECONDS,
    logLevel: parsed.LOG_LEVEL,
    paymentAdapter: parsed.PAYMENT_ADAPTER,
    paymentsEnabled: false,
    productSeedId: parsed.PRODUCT_SEED_ID,
    publicAssetOrigin: parsed.PUBLIC_ASSET_ORIGIN,
    tokenizationMode: parsed.TOKENIZATION_MODE,
    runtimeSecurityRootKey: parsed.RUNTIME_SECURITY_ROOT_KEY,
  };
};

export const APP_CONFIG = Symbol('APP_CONFIG');
