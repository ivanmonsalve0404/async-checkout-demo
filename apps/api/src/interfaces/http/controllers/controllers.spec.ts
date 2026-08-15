import type { CatalogRepository } from '../../../application/ports/catalog-repository';
import { err, ok } from '../../../application/result/result';
import { GetProductAvailability } from '../../../application/use-cases/get-product-availability';
import type { RequestWithCorrelation } from '../request-context';
import { HealthController } from './health.controller';
import { ProductsController } from './products.controller';

const requestContext = {
  correlationId: 'correlation-01',
  originalUrl: '/api/v1/products/product-demo-001',
} as RequestWithCorrelation;

describe('HTTP controller mappings', () => {
  it('maps repository failure to a safe 500 problem', async () => {
    const repository: CatalogRepository = {
      findById: jest.fn().mockResolvedValue(err({ code: 'REPOSITORY_UNAVAILABLE' })),
      isReady: jest.fn().mockResolvedValue(true),
      seedIfAbsent: jest.fn().mockResolvedValue(ok('EXISTS')),
    };
    const controller = new ProductsController(new GetProductAvailability(repository));
    await expect(controller.getProduct('product-demo-001', requestContext)).rejects.toMatchObject({
      status: 500,
    });
  });

  it('fails readiness closed', async () => {
    const repository: CatalogRepository = {
      findById: jest.fn(),
      isReady: jest.fn().mockResolvedValue(false),
      seedIfAbsent: jest.fn(),
    };
    await expect(new HealthController(repository).getHealth(requestContext)).rejects.toMatchObject({
      status: 503,
    });
  });
});
