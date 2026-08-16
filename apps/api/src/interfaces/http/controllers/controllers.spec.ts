import type { CatalogRepository } from '../../../application/ports/catalog-repository';
import type { PaymentProvider } from '../../../application/ports/payment-provider';
import { err, ok } from '../../../application/result/result';
import { GetProductAvailability } from '../../../application/use-cases/get-product-availability';
import { ListProducts } from '../../../application/use-cases/list-products';
import type { RequestWithCorrelation } from '../request-context';
import { HealthController } from './health.controller';
import { ProductsController } from './products.controller';

const requestContext = {
  correlationId: 'correlation-01',
  originalUrl: '/api/v1/products/product-demo-001',
} as RequestWithCorrelation;

const readyPaymentProvider: PaymentProvider = {
  getPublicConfiguration: () =>
    ok({
      mode: 'fake',
      captureVariant: 'FAKE_CONTRACT',
      publicKey: 'FAKE_CONTRACT_NO_CARD_DATA',
      installments: [1, 2, 3],
    }),
  createOnce: async () => err({ code: 'ENVIRONMENT_DISABLED' }),
  getByReference: async () => err({ code: 'ENVIRONMENT_DISABLED' }),
  getById: async () => err({ code: 'ENVIRONMENT_DISABLED' }),
  verifyAndNormalizeEvent: () => err({ code: 'ENVIRONMENT_DISABLED' }),
};

describe('HTTP controller mappings', () => {
  it('maps repository failure to a safe 500 problem', async () => {
    const repository: CatalogRepository = {
      findById: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      listActive: jest.fn().mockResolvedValue(ok([])),
      reserve: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      consume: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      release: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      isReady: jest.fn().mockResolvedValue(true),
      seedIfAbsent: jest.fn().mockResolvedValue(ok('EXISTS')),
    };
    const controller = new ProductsController(
      new ListProducts(repository),
      new GetProductAvailability(repository),
    );
    await expect(controller.getProduct('product-demo-001', requestContext)).rejects.toMatchObject({
      status: 500,
    });
  });

  it('fails readiness closed', async () => {
    const repository: CatalogRepository = {
      findById: jest.fn(),
      isReady: jest.fn().mockResolvedValue(false),
      listActive: jest.fn().mockResolvedValue(ok([])),
      reserve: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      consume: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      release: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      seedIfAbsent: jest.fn(),
    };
    await expect(
      new HealthController(repository, readyPaymentProvider).getHealth(requestContext),
    ).rejects.toMatchObject({ status: 503 });
  });

  it('fails readiness closed when the payment adapter is disabled', async () => {
    const repository: CatalogRepository = {
      findById: jest.fn(),
      isReady: jest.fn().mockResolvedValue(true),
      listActive: jest.fn().mockResolvedValue(ok([])),
      reserve: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      consume: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      release: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      seedIfAbsent: jest.fn(),
    };
    const disabledPaymentProvider: PaymentProvider = {
      ...readyPaymentProvider,
      getPublicConfiguration: () => err({ code: 'ENVIRONMENT_DISABLED' }),
    };

    await expect(
      new HealthController(repository, disabledPaymentProvider).getHealth(requestContext),
    ).rejects.toMatchObject({ status: 503 });
  });
});
