import type { CatalogRepository } from '../ports/catalog-repository';
import type { Result } from '../result/result';
import { err, ok } from '../result/result';
import type { ProductAvailability } from '../../domain/catalog/product';
import { createProductSeed } from '../../infrastructure/persistence/product-seed';
import { GetProductStock } from './get-product-stock';
import { ListProducts } from './list-products';

const product = createProductSeed('product-demo-001', 'http://localhost:5173');

const repository = (
  findResult: Result<ProductAvailability | null, { code: 'REPOSITORY_UNAVAILABLE' }> = ok(product),
  listResult: Result<readonly ProductAvailability[], { code: 'REPOSITORY_UNAVAILABLE' }> = ok([
    product,
  ]),
): CatalogRepository => ({
  findById: jest.fn().mockResolvedValue(findResult),
  listActive: jest.fn().mockResolvedValue(listResult),
  seedIfAbsent: jest.fn().mockResolvedValue(ok('EXISTS')),
  isReady: jest.fn().mockResolvedValue(true),
  reserve: jest.fn().mockResolvedValue(ok(product)),
  consume: jest.fn().mockResolvedValue(ok(product)),
  release: jest.fn().mockResolvedValue(ok(product)),
});

describe('catalog query use cases', () => {
  it('lists active products through the bounded repository operation', async () => {
    const listActive = jest.fn().mockResolvedValue(ok([product]));
    const catalog = { ...repository(), listActive };
    await expect(new ListProducts(catalog).execute()).resolves.toEqual(ok([product]));
    expect(listActive).toHaveBeenCalledWith(100);
  });

  it('maps list repository failures without leaking adapter details', async () => {
    await expect(
      new ListProducts(repository(ok(product), err({ code: 'REPOSITORY_UNAVAILABLE' }))).execute(),
    ).resolves.toEqual(err({ code: 'REPOSITORY_UNAVAILABLE' }));
  });

  it('returns only public stock fields', async () => {
    await expect(new GetProductStock(repository()).execute(product.productId)).resolves.toEqual(
      ok({ productId: product.productId, available: product.available, asOf: product.updatedAt }),
    );
  });

  it.each([
    ['short', ok(product), 'INVALID_PRODUCT_ID'],
    [product.productId, ok(null), 'PRODUCT_NOT_FOUND'],
    [product.productId, ok({ ...product, active: false }), 'PRODUCT_NOT_FOUND'],
    [product.productId, err({ code: 'REPOSITORY_UNAVAILABLE' as const }), 'REPOSITORY_UNAVAILABLE'],
  ] as const)('maps stock query %# to %s', async (candidate, found, expectedCode) => {
    await expect(new GetProductStock(repository(found)).execute(candidate)).resolves.toEqual(
      err({ code: expectedCode }),
    );
  });
});
