import {
  BatchGetCommand,
  QueryCommand,
  TransactWriteCommand,
  type UpdateCommand,
  type DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import { createProductSeed } from './product-seed';
import { DynamoDbCatalogRepository } from './dynamodb-catalog.repository';

describe('DynamoDbCatalogRepository', () => {
  const product = createProductSeed('product-demo-001', 'http://localhost:5173');
  const productItem = {
    ...product,
    PK: `PRODUCT#${product.productId}`,
    SK: 'META',
    schemaVersion: 1,
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

  it.each([
    ['null', null],
    ['schema', { ...productItem, schemaVersion: 2 }],
    ['sort key', { ...productItem, SK: 'OTHER' }],
    ['product id', { ...productItem, productId: 1 }],
    ['sku', { ...productItem, sku: 1 }],
    ['name', { ...productItem, name: 1 }],
    ['description', { ...productItem, description: 1 }],
    ['image', { ...productItem, imageUrl: 1 }],
    ['on hand', { ...productItem, onHand: '3' }],
    ['reserved', { ...productItem, reserved: '0' }],
    ['available', { ...productItem, available: '3' }],
    ['active', { ...productItem, active: 'true' }],
    ['version', { ...productItem, version: '1' }],
    ['created at', { ...productItem, createdAt: 1 }],
    ['updated at', { ...productItem, updatedAt: 1 }],
    ['money object', { ...productItem, unitPrice: null }],
    ['currency', { ...productItem, unitPrice: { amountInCents: 1, currency: 'USD' } }],
    ['amount', { ...productItem, unitPrice: { amountInCents: '1', currency: 'COP' } }],
    ['inventory invariant', { ...productItem, available: productItem.available + 1 }],
  ])('rejects a malformed %s product record', async (_label, item) => {
    const { repository } = setup([{ Item: item }]);
    await expect(repository.findById(product.productId)).resolves.toEqual({
      ok: false,
      error: { code: 'INVALID_RECORD' },
    });
  });

  it('lists the active projection with Query plus BatchGet and preserves projection order', async () => {
    const second = {
      ...productItem,
      productId: 'product-demo-002',
      PK: 'PRODUCT#product-demo-002',
      sku: 'SKU_DEMO_002',
    };
    const { repository, send } = setup([
      {
        Items: [
          {
            PK: 'CATALOG#ACTIVE',
            SK: 'PRODUCT#' + product.productId,
            itemType: 'ACTIVE_PRODUCT',
            productId: product.productId,
            schemaVersion: 1,
          },
          {
            PK: 'CATALOG#ACTIVE',
            SK: 'PRODUCT#' + second.productId,
            itemType: 'ACTIVE_PRODUCT',
            productId: second.productId,
            schemaVersion: 1,
          },
        ],
      },
      { Responses: { 'catalog-local': [second, productItem] } },
    ]);

    await expect(repository.listActive(999)).resolves.toEqual({
      ok: true,
      value: [product, { ...product, productId: second.productId, sku: second.sku }],
    });
    expect(send.mock.calls[0]?.[0]).toBeInstanceOf(QueryCommand);
    expect(send.mock.calls[1]?.[0]).toBeInstanceOf(BatchGetCommand);
    expect((send.mock.calls[0]?.[0] as QueryCommand).input.Limit).toBe(50);
  });

  it('handles empty, malformed, incomplete and unavailable active projections', async () => {
    const malformed = setup([{ Items: [{ itemType: 'ACTIVE_PRODUCT' }] }]);
    await expect(malformed.repository.listActive(1)).resolves.toMatchObject({
      error: { code: 'INVALID_RECORD' },
    });

    const empty = setup([{ Items: [] }]);
    await expect(empty.repository.listActive(0)).resolves.toEqual({ ok: true, value: [] });

    const incomplete = setup([
      {
        Items: [
          {
            itemType: 'ACTIVE_PRODUCT',
            productId: product.productId,
            schemaVersion: 1,
          },
        ],
      },
      { Responses: { 'catalog-local': [] } },
    ]);
    await expect(incomplete.repository.listActive(1)).resolves.toMatchObject({
      error: { code: 'INVALID_RECORD' },
    });

    const unavailable = setup([new Error('offline')]);
    await expect(unavailable.repository.listActive(1)).resolves.toMatchObject({
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
  });

  it('seeds DBITEM01–03 atomically with schema versions and normalized SKU', async () => {
    const { repository, send } = setup([{}]);
    await expect(repository.seedIfAbsent(product)).resolves.toEqual({
      ok: true,
      value: 'CREATED',
    });

    const command = send.mock.calls[0]?.[0] as TransactWriteCommand;
    expect(command).toBeInstanceOf(TransactWriteCommand);
    expect(command.input.TransactItems?.map((entry) => entry.Put?.Item?.itemType)).toEqual([
      'PRODUCT',
      'ACTIVE_PRODUCT',
      'SKU_LOOKUP',
    ]);
    expect(
      command.input.TransactItems?.every((entry) => entry.Put?.Item?.schemaVersion === 1),
    ).toBe(true);
    expect(command.input.TransactItems?.[2]?.Put?.Item?.PK).toBe('SKU#SKU_DEMO_001');
  });

  it('reserves, consumes and releases with conditional deltas and no unused placeholders', async () => {
    const reserved = { ...productItem, reserved: 1, available: 2, version: 2 };
    const consumed = { ...productItem, onHand: 2, available: 2, version: 3 };
    const released = { ...productItem, version: 3 };
    const { repository, send } = setup([
      { Attributes: reserved },
      { Attributes: consumed },
      { Attributes: released },
    ]);

    await expect(
      repository.reserve(product.productId, 1, product.updatedAt),
    ).resolves.toMatchObject({
      value: { reserved: 1, available: 2 },
    });
    await expect(
      repository.consume(product.productId, 1, product.updatedAt),
    ).resolves.toMatchObject({
      value: { onHand: 2, reserved: 0, available: 2 },
    });
    await expect(
      repository.release(product.productId, 1, product.updatedAt),
    ).resolves.toMatchObject({
      value: { onHand: 3, reserved: 0, available: 3 },
    });

    const [reserve, consume, release] = send.mock.calls.map(
      ([command]) => command as UpdateCommand,
    );
    expect(reserve?.input.ConditionExpression).toContain('#active = :active');
    for (const command of [consume, release]) {
      expect(command?.input.ExpressionAttributeNames).not.toHaveProperty('#active');
      expect(command?.input.ExpressionAttributeValues).not.toHaveProperty(':active');
    }
  });

  it('maps inventory conditions, malformed writes and dependency failures', async () => {
    const conditional = Object.assign(new Error('condition'), {
      name: 'ConditionalCheckFailedException',
    });
    const { repository } = setup([
      conditional,
      conditional,
      { Attributes: { ...productItem, available: 999 } },
      new Error('offline'),
    ]);
    await expect(
      repository.reserve(product.productId, 1, product.updatedAt),
    ).resolves.toMatchObject({
      error: { code: 'OUT_OF_STOCK' },
    });
    await expect(
      repository.consume(product.productId, 1, product.updatedAt),
    ).resolves.toMatchObject({
      error: { code: 'INVENTORY_CONFLICT' },
    });
    await expect(
      repository.release(product.productId, 1, product.updatedAt),
    ).resolves.toMatchObject({
      error: { code: 'INVALID_RECORD' },
    });
    await expect(
      repository.release(product.productId, 1, product.updatedAt),
    ).resolves.toMatchObject({
      error: { code: 'REPOSITORY_UNAVAILABLE' },
    });
  });
});
