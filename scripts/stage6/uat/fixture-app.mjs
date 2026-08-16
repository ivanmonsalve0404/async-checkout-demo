import '../../smoke/deny-external-network.cjs';

import { createRequire } from 'node:module';
import path from 'node:path';

import { workspaceRoot } from '../lib/evidence.mjs';

const apiRoot = path.join(workspaceRoot, 'apps', 'api');
const requireApi = createRequire(path.join(apiRoot, 'package.json'));
requireApi('reflect-metadata');

const { Test } = requireApi('@nestjs/testing');
const { json } = requireApi('express');
const helmetModule = requireApi('helmet');
const helmet = helmetModule.default ?? helmetModule;
const { AppModule } = requireApi('./dist/app.module.js');
const { APP_CONFIG } = requireApi('./dist/infrastructure/configuration/app-config.js');
const { CATALOG_REPOSITORY } = requireApi('./dist/application/ports/catalog-repository.js');
const { CHECKOUT_REPOSITORY } = requireApi('./dist/application/ports/checkout-repository.js');
const { PAYMENT_PROVIDER } = requireApi('./dist/application/ports/payment-provider.js');
const { CatalogSeedService } = requireApi(
  './dist/infrastructure/persistence/catalog-seed.service.js',
);
const { InMemoryCatalogRepository } = requireApi(
  './dist/infrastructure/persistence/in-memory-catalog.repository.js',
);
const { ProblemFilter } = requireApi('./dist/interfaces/http/filters/problem.filter.js');
const { CorrelationMiddleware } = requireApi(
  './dist/interfaces/http/middleware/correlation.middleware.js',
);

const PRODUCT_ID = 'product-demo-001';
const ok = (value) => ({ ok: true, value });
const err = (code) => ({ ok: false, error: { code } });
const iso = () => new Date().toISOString();

const environment = {
  ALLOWED_ORIGIN: 'http://127.0.0.1:4173',
  API_PORT: '3000',
  APP_ENV: 'test',
  CHECKOUT_TTL_SECONDS: '1800',
  DATA_ADAPTER: 'memory',
  FAKE_PAYMENT_SCENARIO: 'FAKE-E5-04',
  FAKE_RECONCILE_INTERVAL_MS: '60000',
  PAYMENT_ADAPTER: 'fake',
  PAYMENTS_ENABLED: 'false',
  PRODUCT_INITIAL_STOCK: '1',
  PUBLIC_ASSET_ORIGIN: 'http://127.0.0.1:4173',
  QUOTE_TTL_SECONDS: '900',
  TOKENIZATION_MODE: 'disabled',
};

const fixtureProvider = (status) => {
  let createCalls = 0;
  const provider = {
    getPublicConfiguration: () =>
      ok({
        mode: 'fake',
        captureVariant: 'FAKE_CONTRACT',
        publicKey: 'FAKE_CONTRACT_NO_CARD_DATA',
        installments: [1, 2, 3],
      }),
    createOnce: async (command) => {
      createCalls += 1;
      return ok({
        kind: 'ACKNOWLEDGED',
        providerId: 'provider_fixture_' + command.reference,
        status,
        reference: command.reference,
        amountInCents: command.amountInCents,
        currency: command.currency,
      });
    },
    getByReference: async () => err('REFERENCE_LOOKUP_UNSUPPORTED'),
    getById: async () => err('REFERENCE_LOOKUP_UNSUPPORTED'),
    verifyAndNormalizeEvent: () => err('ENVIRONMENT_DISABLED'),
  };
  return { provider, createCalls: () => createCalls };
};

const failingCatalog = () => {
  const inner = new InMemoryCatalogRepository();
  let failFind = false;
  return {
    repository: {
      findById: (...arguments_) =>
        failFind
          ? Promise.reject(new Error('SYNTHETIC_PRE_IO_FAILURE'))
          : inner.findById(...arguments_),
      listActive: (...arguments_) => inner.listActive(...arguments_),
      seedIfAbsent: (...arguments_) => inner.seedIfAbsent(...arguments_),
      reserve: (...arguments_) => inner.reserve(...arguments_),
      consume: (...arguments_) => inner.consume(...arguments_),
      release: (...arguments_) => inner.release(...arguments_),
      isReady: (...arguments_) => inner.isReady(...arguments_),
    },
    setFailFind: (value) => {
      failFind = value;
    },
  };
};

const restoreEnvironment = (previous) => {
  for (const [key, value] of previous) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
};

const resultValue = (result, code) => {
  if (!result.ok) throw new Error(code + '_' + result.error.code);
  return result.value;
};

export const withFixtureApi = async (
  { providerStatus = 'PENDING', catalogFailure = false, overrides = {} },
  run,
) => {
  const nextEnvironment = { ...environment, ...overrides };
  const previous = new Map(Object.keys(nextEnvironment).map((key) => [key, process.env[key]]));
  Object.assign(process.env, nextEnvironment);

  const providerFixture = fixtureProvider(providerStatus);
  const catalogFixture = catalogFailure ? failingCatalog() : undefined;
  let builder = Test.createTestingModule({ imports: [AppModule] })
    .overrideProvider(PAYMENT_PROVIDER)
    .useValue(providerFixture.provider);
  if (catalogFixture !== undefined) {
    builder = builder.overrideProvider(CATALOG_REPOSITORY).useValue(catalogFixture.repository);
  }

  const moduleReference = await builder.compile();
  const application = moduleReference.createNestApplication({
    bodyParser: false,
    logger: false,
  });
  const config = application.get(APP_CONFIG);
  const correlation = new CorrelationMiddleware();
  application.use(correlation.use.bind(correlation));
  application.use(helmet());
  application.use(json({ limit: 16_384, strict: true }));
  application.enableCors({
    origin: config.allowedOrigin,
    methods: ['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT'],
    credentials: true,
    maxAge: 600,
  });
  application.useGlobalFilters(new ProblemFilter());

  try {
    await application.listen(3000, '127.0.0.1');
    const checkoutRepository = application.get(CHECKOUT_REPOSITORY);
    const catalogRepository = application.get(CATALOG_REPOSITORY);
    const seed = application.get(CatalogSeedService);
    const reconciliationCheck = () => {
      const checkedAt = iso();
      return {
        attempts: 1,
        lastCheckedAt: checkedAt,
        nextCheckAt: new Date(Date.now() + 60_000).toISOString(),
      };
    };
    const controls = {
      providerCreateCalls: providerFixture.createCalls,
      seedTwice: async () => {
        await seed.onModuleInit();
        await seed.onModuleInit();
      },
      setCatalogFindFailure: (value) => {
        if (catalogFixture === undefined) throw new Error('CATALOG_FAULT_NOT_CONFIGURED');
        catalogFixture.setFailFind(value);
      },
      approveWithoutReservation: async (transactionId) => {
        const transaction = resultValue(
          await checkoutRepository.findTransaction(transactionId),
          'FIXTURE_TRANSACTION',
        );
        if (transaction === null || transaction.providerId === undefined) {
          throw new Error('FIXTURE_PROVIDER_ID_MISSING');
        }
        const checkedAt = iso();
        resultValue(
          await checkoutRepository.acknowledgeProvider(
            transactionId,
            transaction.providerId,
            'APPROVED',
            checkedAt,
            reconciliationCheck(),
          ),
          'FIXTURE_ACKNOWLEDGE',
        );
        resultValue(await catalogRepository.release(PRODUCT_ID, 1, checkedAt), 'FIXTURE_RELEASE');
        return resultValue(
          await checkoutRepository.finalize(
            transactionId,
            'APPROVED',
            'APPROVED',
            undefined,
            checkedAt,
          ),
          'FIXTURE_APPROVE',
        );
      },
      injectConflictingFinal: async (transactionId, status) =>
        resultValue(
          await checkoutRepository.finalize(transactionId, status, status, undefined, iso()),
          'FIXTURE_FINAL_CONFLICT',
        ),
    };
    return await run(controls);
  } finally {
    await application.close();
    await moduleReference.close();
    restoreEnvironment(previous);
  }
};
