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
    DYNAMODB_ENDPOINT: z.string().url().default('http://localhost:8000'),
    LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    PAYMENT_ADAPTER: z.literal('fake').default('fake'),
    PAYMENTS_ENABLED: z.literal('false').default('false'),
    PRODUCT_SEED_ID: z
      .string()
      .regex(/^[A-Za-z0-9_-]{8,128}$/)
      .default('product-demo-001'),
    PUBLIC_ASSET_ORIGIN: httpOrigin.default('http://localhost:5173'),
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
  readonly dynamoDbEndpoint: string;
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
  readonly paymentAdapter: 'fake';
  readonly paymentsEnabled: false;
  readonly productSeedId: string;
  readonly publicAssetOrigin: string;
  readonly tokenizationMode: 'disabled';
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
    logLevel: parsed.LOG_LEVEL,
    paymentAdapter: parsed.PAYMENT_ADAPTER,
    paymentsEnabled: false,
    productSeedId: parsed.PRODUCT_SEED_ID,
    publicAssetOrigin: parsed.PUBLIC_ASSET_ORIGIN,
    tokenizationMode: parsed.TOKENIZATION_MODE,
  };
};

export const APP_CONFIG = Symbol('APP_CONFIG');
