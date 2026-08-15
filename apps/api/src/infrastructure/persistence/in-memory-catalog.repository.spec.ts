import { createProductSeed } from './product-seed';
import { InMemoryCatalogRepository } from './in-memory-catalog.repository';

describe('InMemoryCatalogRepository', () => {
  const product = createProductSeed('product-demo-001', 'http://localhost:5173');

  it('seeds idempotently and does not overwrite', async () => {
    const repository = new InMemoryCatalogRepository();
    await expect(repository.seedIfAbsent(product)).resolves.toMatchObject({ value: 'CREATED' });
    await expect(
      repository.seedIfAbsent({ ...product, onHand: 99, available: 99 }),
    ).resolves.toMatchObject({
      value: 'EXISTS',
    });
    await expect(repository.findById(product.productId)).resolves.toMatchObject({ value: product });
  });

  it('returns clones, missing values, and readiness', async () => {
    const repository = new InMemoryCatalogRepository([product]);
    const first = await repository.findById(product.productId);
    const second = await repository.findById(product.productId);
    expect(first).not.toBe(second);
    await expect(repository.findById('missing-product')).resolves.toMatchObject({ value: null });
    await expect(repository.isReady()).resolves.toBe(true);
  });
});
