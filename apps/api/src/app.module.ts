import { MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { CATALOG_REPOSITORY, type CatalogRepository } from './application/ports/catalog-repository';
import {
  CHECKOUT_REPOSITORY,
  type CheckoutRepository,
} from './application/ports/checkout-repository';
import {
  MERCHANT_CONTRACT_PORT,
  type MerchantContractPort,
} from './application/ports/merchant-contract';
import { PAYMENT_PROVIDER, type PaymentProvider } from './application/ports/payment-provider';
import { RUNTIME_SECURITY, type RuntimeSecurity } from './application/ports/runtime-security';
import { OBSERVABILITY, type ObservabilityPort } from './application/ports/observability';
import {
  CheckoutService,
  LOCAL_FAKE_RECONCILIATION_BACKOFF_POLICY,
  PRODUCTION_RECONCILIATION_BACKOFF_POLICY,
  type ReconciliationBackoffPolicy,
} from './application/use-cases/checkout-service';
import { GetProductAvailability } from './application/use-cases/get-product-availability';
import { GetProductStock } from './application/use-cases/get-product-stock';
import { ListProducts } from './application/use-cases/list-products';
import {
  APP_CONFIG,
  loadRuntimeAppConfig,
  type AppConfig,
} from './infrastructure/configuration/app-config';
import {
  loadRuntimeSecrets,
  RUNTIME_SECRETS,
  type RuntimeSecrets,
} from './infrastructure/configuration/runtime-secrets';
import { FakeMerchantContractAdapter } from './infrastructure/payment/fake-merchant-contract.adapter';
import { SafeLogger } from './infrastructure/logging/safe-logger';
import { SafeLoggerObservability } from './infrastructure/observability/observability.adapter';
import {
  E5ScriptedPaymentProvider,
  type E5PaymentScenario,
} from './infrastructure/payment/e5-scripted-payment-provider';
import { FakeReconciliationRunner } from './infrastructure/payment/fake-reconciliation-runner';
import { SandboxMerchantContractAdapter } from './infrastructure/payment/sandbox-merchant-contract.adapter';
import { SandboxPaymentProvider } from './infrastructure/payment/sandbox-payment-provider';
import {
  createSandboxAcceptanceReader,
  createSandboxTransport,
  loadSandboxRuntimeConfiguration,
  SANDBOX_RUNTIME_CONFIGURATION,
  type SandboxRuntimeConfiguration,
} from './infrastructure/payment/sandbox-runtime';
import {
  ScriptedPaymentProvider,
  type FakePaymentScenario,
} from './infrastructure/payment/scripted-payment-provider';
import { CatalogSeedService } from './infrastructure/persistence/catalog-seed.service';
import {
  createCatalogRepository,
  createDynamoDocumentClient,
  DYNAMODB_DOCUMENT_CLIENT,
} from './infrastructure/persistence/catalog-repository.factory';
import { DynamoDbCheckoutRepository } from './infrastructure/persistence/dynamodb-checkout.repository';
import { InMemoryCheckoutRepository } from './infrastructure/persistence/in-memory-checkout.repository';
import { SystemRuntimeSecurity } from './infrastructure/security/system-runtime-security';
import { CheckoutsController } from './interfaces/http/controllers/checkouts.controller';
import { DeliveriesController } from './interfaces/http/controllers/deliveries.controller';
import { DocsController } from './interfaces/http/controllers/docs.controller';
import { HealthController } from './interfaces/http/controllers/health.controller';
import { PaymentConfigurationController } from './interfaces/http/controllers/payment-configuration.controller';
import { ProductsController } from './interfaces/http/controllers/products.controller';
import { StockController } from './interfaces/http/controllers/stock.controller';
import { TransactionsController } from './interfaces/http/controllers/transactions.controller';
import { OriginValidationMiddleware } from './interfaces/http/middleware/origin-validation.middleware';
import { RateLimitMiddleware } from './interfaces/http/middleware/rate-limit.middleware';
import { RequestLoggingMiddleware } from './interfaces/http/middleware/request-logging.middleware';

const createPaymentProvider = (
  config: AppConfig,
  observability: ObservabilityPort,
  secrets: RuntimeSecrets,
  sandboxConfiguration: SandboxRuntimeConfiguration | undefined,
  logger: SafeLogger,
): PaymentProvider => {
  const sandboxTransport = createSandboxTransport(
    config,
    secrets,
    globalThis.fetch,
    () => new Date(),
    ({ eventName, ...fields }) => logger.info(eventName, fields),
  );
  const acceptanceReader = createSandboxAcceptanceReader(config, secrets, sandboxTransport);
  const provider =
    config.paymentAdapter === 'sandbox'
      ? config.paymentsEnabled &&
        secrets.sandbox !== undefined &&
        sandboxTransport !== undefined &&
        acceptanceReader !== undefined &&
        sandboxConfiguration !== undefined
        ? (() => {
            const { publicKey, privateKey, integritySecret } = secrets.sandbox;
            return new SandboxPaymentProvider({
              enabled: true,
              publicKey,
              privateKey,
              integritySecret,
              ...(config.sandboxAuthorizedUntilUtc === undefined
                ? {}
                : { authorizedUntilUtc: config.sandboxAuthorizedUntilUtc }),
              transport: sandboxTransport,
              acceptanceReader,
              expectedContracts: sandboxConfiguration.contracts,
              quoteTtlSeconds: config.quoteTtlSeconds,
            });
          })()
        : new SandboxPaymentProvider({ enabled: false })
      : config.fakePaymentScenario.startsWith('FAKE-E5-')
        ? new E5ScriptedPaymentProvider(config.fakePaymentScenario as E5PaymentScenario)
        : new ScriptedPaymentProvider(config.fakePaymentScenario as FakePaymentScenario);
  const readiness = provider.getPublicConfiguration();
  if (config.paymentAdapter === 'sandbox' && !readiness.ok) {
    observability.event('sandbox_guard.blocked', { errorCode: readiness.error.code });
    observability.increment('sandbox_guard_blocked_total');
  }
  return provider;
};

const createMerchantContractAdapter = (
  config: AppConfig,
  sandboxConfiguration: SandboxRuntimeConfiguration | undefined,
): MerchantContractPort =>
  config.paymentAdapter === 'sandbox'
    ? new SandboxMerchantContractAdapter(sandboxConfiguration?.contracts)
    : new FakeMerchantContractAdapter(config.publicAssetOrigin);
export const selectReconciliationBackoffPolicy = (
  config: Pick<AppConfig, 'appEnvironment' | 'paymentAdapter'>,
): ReconciliationBackoffPolicy =>
  config.paymentAdapter === 'fake' &&
  (config.appEnvironment === 'local' || config.appEnvironment === 'test')
    ? LOCAL_FAKE_RECONCILIATION_BACKOFF_POLICY
    : PRODUCTION_RECONCILIATION_BACKOFF_POLICY;

@Module({
  controllers: [
    DocsController,
    HealthController,
    ProductsController,
    StockController,
    CheckoutsController,
    PaymentConfigurationController,
    TransactionsController,
    DeliveriesController,
  ],
  providers: [
    {
      provide: APP_CONFIG,
      useFactory: (): Promise<AppConfig> => loadRuntimeAppConfig(process.env),
    },
    {
      provide: RUNTIME_SECRETS,
      inject: [APP_CONFIG],
      useFactory: loadRuntimeSecrets,
    },
    {
      provide: SANDBOX_RUNTIME_CONFIGURATION,
      inject: [APP_CONFIG, RUNTIME_SECRETS],
      useFactory: loadSandboxRuntimeConfiguration,
    },
    {
      provide: DYNAMODB_DOCUMENT_CLIENT,
      inject: [APP_CONFIG],
      useFactory: createDynamoDocumentClient,
    },
    {
      provide: RUNTIME_SECURITY,
      inject: [APP_CONFIG, RUNTIME_SECRETS],
      useFactory: (config: AppConfig, secrets: RuntimeSecrets): RuntimeSecurity =>
        new SystemRuntimeSecurity(
          undefined,
          secrets.runtimeSecurityRootKey ?? config.runtimeSecurityRootKey,
        ),
    },
    {
      provide: CATALOG_REPOSITORY,
      inject: [APP_CONFIG, DYNAMODB_DOCUMENT_CLIENT],
      useFactory: (config: AppConfig, client: DynamoDBDocumentClient): CatalogRepository =>
        createCatalogRepository(config, client),
    },
    {
      provide: CHECKOUT_REPOSITORY,
      inject: [CATALOG_REPOSITORY, RUNTIME_SECURITY, APP_CONFIG, DYNAMODB_DOCUMENT_CLIENT],
      useFactory: (
        catalog: CatalogRepository,
        runtime: RuntimeSecurity,
        config: AppConfig,
        client: DynamoDBDocumentClient,
      ): CheckoutRepository => {
        if (config.dataAdapter === 'dynamodb') {
          return new DynamoDbCheckoutRepository(
            client,
            config.catalogTableName,
            config.checkoutTableName,
            (value) => runtime.semanticHash('dynamodb-lookup|' + value),
          );
        }
        return new InMemoryCheckoutRepository(catalog);
      },
    },
    {
      provide: PAYMENT_PROVIDER,
      inject: [
        APP_CONFIG,
        OBSERVABILITY,
        RUNTIME_SECRETS,
        SANDBOX_RUNTIME_CONFIGURATION,
        SafeLogger,
      ],
      useFactory: createPaymentProvider,
    },
    {
      provide: MERCHANT_CONTRACT_PORT,
      inject: [APP_CONFIG, SANDBOX_RUNTIME_CONFIGURATION],
      useFactory: createMerchantContractAdapter,
    },
    {
      provide: CheckoutService,
      inject: [
        CATALOG_REPOSITORY,
        CHECKOUT_REPOSITORY,
        PAYMENT_PROVIDER,
        RUNTIME_SECURITY,
        MERCHANT_CONTRACT_PORT,
        APP_CONFIG,
        OBSERVABILITY,
      ],
      useFactory: (
        catalog: CatalogRepository,
        repository: CheckoutRepository,
        paymentProvider: PaymentProvider,
        runtime: RuntimeSecurity,
        merchantContracts: MerchantContractPort,
        config: AppConfig,
        observability: ObservabilityPort,
      ): CheckoutService =>
        new CheckoutService(
          catalog,
          repository,
          paymentProvider,
          runtime,
          merchantContracts,
          config.quoteTtlSeconds,
          config.checkoutTtlSeconds,
          observability,
          () => Math.random(),
          selectReconciliationBackoffPolicy(config),
        ),
    },
    {
      provide: GetProductAvailability,
      inject: [CATALOG_REPOSITORY],
      useFactory: (repository: CatalogRepository): GetProductAvailability =>
        new GetProductAvailability(repository),
    },
    {
      provide: ListProducts,
      inject: [CATALOG_REPOSITORY],
      useFactory: (repository: CatalogRepository): ListProducts => new ListProducts(repository),
    },
    {
      provide: GetProductStock,
      inject: [CATALOG_REPOSITORY],
      useFactory: (repository: CatalogRepository): GetProductStock =>
        new GetProductStock(repository),
    },
    {
      provide: SafeLogger,
      inject: [APP_CONFIG],
      useFactory: (config: AppConfig): SafeLogger =>
        new SafeLogger('checkout-api', config.appEnvironment, '0.1.0'),
    },
    {
      provide: OBSERVABILITY,
      inject: [SafeLogger],
      useFactory: (logger: SafeLogger): ObservabilityPort => new SafeLoggerObservability(logger),
    },
    CatalogSeedService,
    FakeReconciliationRunner,
    OriginValidationMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
  ],
})
export class AppModule implements NestModule {
  public configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(RequestLoggingMiddleware, OriginValidationMiddleware, RateLimitMiddleware)
      .forRoutes('*');
  }
}
