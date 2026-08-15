import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { createProductSeed } from './product-seed';
import { DynamoDbCatalogRepository } from './dynamodb-catalog.repository';

describe('DynamoDbCatalogRepository', () => {
  const product = createProductSeed('product-demo-001', 'http://localhost:5173');
  const productItem = {
    ...product,
    PK: `PRODUCT#${product.productId}`,
    SK: 'META',
    itemType: 'PRODUCT',
  };

  const setup = (responses: readonly unknown[]) => {
    const send = jest.fn();
    for (const response of responses) {
      if (response instanceof Error) {
        send.mockRejectedValueOnce(response);
      } else {
        send.mockResolvedValueOnce(response);
      }
    }
    const client = { send } as unknown as DynamoDBDocumentClient;
    return { repository: new DynamoDbCatalogRepository(client, 'catalog-local'), send };
  };

  it('reads a valid item without leaking storage keys', async () => {
    const { repository } = setup([{ Item: productItem }]);
    await expect(repository.findById(product.productId)).resolves.toEqual({
      ok: true,
      value: product,
    });
  });

  it('returns missing and invalid records safely', async () => {
    const { repository } = setup([{ Item: undefined }, { Item: { itemType: 'PRODUCT' } }]);
    await expect(repository.findById(product.productId)).resolves.toEqual({
      ok: true,
      value: null,
    });
    await expect(repository.findById(product.productId)).resolves.toEqual({
      ok: false,
      error: { code: 'INVALID_RECORD' },
    });
  });

  it('maps read failures and readiness without exposing errors', async () => {
    const { repository } = setup([new Error('private detail'), {}, new Error('offline')]);
    await expect(repository.findById(product.productId)).resolves.toMatchObject({
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
    await expect(repository.isReady()).resolves.toBe(true);
    await expect(repository.isReady()).resolves.toBe(false);
  });

  it('creates once and treats a conditional conflict as idempotent', async () => {
    const conditional = Object.assign(new Error('exists'), {
      name: 'ConditionalCheckFailedException',
    });
    const { repository } = setup([{}, conditional, new Error('offline')]);
    await expect(repository.seedIfAbsent(product)).resolves.toMatchObject({ value: 'CREATED' });
    await expect(repository.seedIfAbsent(product)).resolves.toMatchObject({ value: 'EXISTS' });
    await expect(repository.seedIfAbsent(product)).resolves.toMatchObject({
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
  });
});
