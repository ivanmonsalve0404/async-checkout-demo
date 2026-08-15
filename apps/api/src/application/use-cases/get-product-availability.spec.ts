import type { CatalogRepository } from '../ports/catalog-repository';
import { err, ok } from '../result/result';
import { createProductSeed } from '../../infrastructure/persistence/product-seed';
import { GetProductAvailability } from './get-product-availability';

const product = createProductSeed('product-demo-001', 'http://localhost:5173');

describe('GetProductAvailability', () => {
  const repository = (
    result: ReturnType<typeof ok> | ReturnType<typeof err>,
  ): CatalogRepository => ({
    findById: jest.fn().mockResolvedValue(result),
    isReady: jest.fn().mockResolvedValue(true),
    seedIfAbsent: jest.fn().mockResolvedValue(ok('EXISTS')),
  });

  it('returns an active, consistent product', async () => {
    await expect(
      new GetProductAvailability(repository(ok(product))).execute(product.productId),
    ).resolves.toEqual(ok(product));
  });

  it.each([
    ['short', 'INVALID_PRODUCT_ID'],
    ['missing-product', 'PRODUCT_NOT_FOUND'],
  ])('maps %s to %s', async (candidate, expectedCode) => {
    const result = await new GetProductAvailability(repository(ok(null))).execute(candidate);
    expect(result).toEqual(err({ code: expectedCode }));
  });

  it('hides inactive products', async () => {
    const result = await new GetProductAvailability(
      repository(ok({ ...product, active: false })),
    ).execute(product.productId);
    expect(result).toEqual(err({ code: 'PRODUCT_NOT_FOUND' }));
  });

  it('rejects inconsistent inventory records', async () => {
    const result = await new GetProductAvailability(
      repository(ok({ ...product, available: 99 })),
    ).execute(product.productId);
    expect(result).toEqual(err({ code: 'INVALID_RECORD' }));
  });

  it('preserves repository errors', async () => {
    const result = await new GetProductAvailability(
      repository(err({ code: 'REPOSITORY_UNAVAILABLE' })),
    ).execute(product.productId);
    expect(result).toEqual(err({ code: 'REPOSITORY_UNAVAILABLE' }));
  });
});
