import {
  BatchGetCommand,
  GetCommand,
  QueryCommand,
  TransactWriteCommand,
  UpdateCommand,
  type DynamoDBDocumentClient,
} from '@aws-sdk/lib-dynamodb';
import type {
  CatalogRepository,
  RepositoryError,
} from '../../application/ports/catalog-repository';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';
import { isConsistentAvailability, type ProductAvailability } from '../../domain/catalog/product';

type DynamoProductItem = ProductAvailability &
  Readonly<{ PK: string; SK: 'META'; itemType: 'PRODUCT'; schemaVersion: 1 }>;

type ActiveProductItem = Readonly<{
  PK: 'CATALOG#ACTIVE';
  schemaVersion: 1;
  SK: string;
  itemType: 'ACTIVE_PRODUCT';
  productId: string;
}>;

const normalizeSku = (sku: string): string => sku.trim().toUpperCase();

const isProductItem = (candidate: unknown): candidate is DynamoProductItem => {
  if (typeof candidate !== 'object' || candidate === null) {
    return false;
  }
  const item = candidate as Partial<DynamoProductItem>;
  return (
    item.itemType === 'PRODUCT' &&
    item.schemaVersion === 1 &&
    item.SK === 'META' &&
    typeof item.productId === 'string' &&
    typeof item.sku === 'string' &&
    typeof item.name === 'string' &&
    typeof item.description === 'string' &&
    typeof item.imageUrl === 'string' &&
    typeof item.onHand === 'number' &&
    typeof item.reserved === 'number' &&
    typeof item.available === 'number' &&
    typeof item.active === 'boolean' &&
    typeof item.version === 'number' &&
    typeof item.createdAt === 'string' &&
    typeof item.updatedAt === 'string' &&
    typeof item.unitPrice === 'object' &&
    item.unitPrice !== null &&
    item.unitPrice.currency === 'COP' &&
    typeof item.unitPrice.amountInCents === 'number'
  );
};

export class DynamoDbCatalogRepository implements CatalogRepository {
  public constructor(
    private readonly client: DynamoDBDocumentClient,
    private readonly tableName: string,
  ) {}

  public async findById(
    productId: string,
  ): Promise<Result<ProductAvailability | null, RepositoryError>> {
    try {
      const response = await this.client.send(
        new GetCommand({
          TableName: this.tableName,
          Key: { PK: `PRODUCT#${productId}`, SK: 'META' },
          ConsistentRead: true,
        }),
      );
      if (response.Item === undefined) {
        return ok(null);
      }
      if (!isProductItem(response.Item) || !isConsistentAvailability(response.Item)) {
        return err({ code: 'INVALID_RECORD' });
      }
      const { PK, SK, itemType, schemaVersion, ...product } = response.Item;
      void PK;
      void SK;
      void itemType;
      void schemaVersion;
      return ok(product);
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async listActive(
    limit: number,
  ): Promise<Result<readonly ProductAvailability[], RepositoryError>> {
    try {
      const projection = await this.client.send(
        new QueryCommand({
          TableName: this.tableName,
          KeyConditionExpression: 'PK = :catalog',
          ExpressionAttributeValues: { ':catalog': 'CATALOG#ACTIVE' },
          Limit: Math.min(Math.max(limit, 1), 50),
          ConsistentRead: false,
        }),
      );
      const productIds: string[] = [];
      for (const item of projection.Items ?? []) {
        if (
          typeof item !== 'object' ||
          item === null ||
          item.itemType !== 'ACTIVE_PRODUCT' ||
          item.schemaVersion !== 1 ||
          typeof item.productId !== 'string'
        ) {
          return err({ code: 'INVALID_RECORD' });
        }
        productIds.push(item.productId);
      }
      if (productIds.length === 0) return ok([]);

      const response = await this.client.send(
        new BatchGetCommand({
          RequestItems: {
            [this.tableName]: {
              Keys: productIds.map((productId) => ({
                PK: 'PRODUCT#' + productId,
                SK: 'META',
              })),
              ConsistentRead: true,
            },
          },
        }),
      );
      const byId = new Map<string, ProductAvailability>();
      for (const item of response.Responses?.[this.tableName] ?? []) {
        if (!isProductItem(item) || !isConsistentAvailability(item)) {
          return err({ code: 'INVALID_RECORD' });
        }
        const { PK, SK, itemType, schemaVersion, ...product } = item;
        void PK;
        void SK;
        void itemType;
        void schemaVersion;
        byId.set(product.productId, product);
      }
      const products = productIds.map((productId) => byId.get(productId));
      return products.some((product) => product === undefined)
        ? err({ code: 'INVALID_RECORD' })
        : ok(products as ProductAvailability[]);
    } catch {
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async seedIfAbsent(
    product: ProductAvailability,
  ): Promise<Result<'CREATED' | 'EXISTS', RepositoryError>> {
    const item: DynamoProductItem = {
      ...product,
      PK: `PRODUCT#${product.productId}`,
      SK: 'META',
      itemType: 'PRODUCT',
      schemaVersion: 1,
    };
    const projection: ActiveProductItem = {
      PK: 'CATALOG#ACTIVE',
      SK: 'PRODUCT#' + product.productId,
      itemType: 'ACTIVE_PRODUCT',
      productId: product.productId,
      schemaVersion: 1,
    };
    try {
      await this.client.send(
        new TransactWriteCommand({
          TransactItems: [
            {
              Put: {
                TableName: this.tableName,
                Item: item,
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
            {
              Put: {
                TableName: this.tableName,
                Item: projection,
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
            {
              Put: {
                TableName: this.tableName,
                Item: {
                  PK: 'SKU#' + normalizeSku(product.sku),
                  SK: 'LOOKUP',
                  itemType: 'SKU_LOOKUP',
                  productId: product.productId,
                  schemaVersion: 1,
                },
                ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
              },
            },
          ],
        }),
      );
      return ok('CREATED');
    } catch (error: unknown) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'name' in error &&
        (error.name === 'ConditionalCheckFailedException' ||
          error.name === 'TransactionCanceledException')
      ) {
        return ok('EXISTS');
      }
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public reserve(
    productId: string,
    quantity: 1,
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>> {
    return this.mutateInventory(productId, quantity, 'RESERVE', updatedAt);
  }

  public consume(
    productId: string,
    quantity: 1,
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>> {
    return this.mutateInventory(productId, quantity, 'CONSUME', updatedAt);
  }

  public release(
    productId: string,
    quantity: 1,
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>> {
    return this.mutateInventory(productId, quantity, 'RELEASE', updatedAt);
  }

  private async mutateInventory(
    productId: string,
    quantity: 1,
    operation: 'RESERVE' | 'CONSUME' | 'RELEASE',
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>> {
    const deltas =
      operation === 'RESERVE'
        ? { onHand: 0, reserved: quantity, available: -quantity }
        : operation === 'CONSUME'
          ? { onHand: -quantity, reserved: -quantity, available: 0 }
          : { onHand: 0, reserved: -quantity, available: quantity };
    const condition =
      operation === 'RESERVE'
        ? '#active = :active AND #available >= :quantity'
        : '#reserved >= :quantity';
    try {
      const response = await this.client.send(
        new UpdateCommand({
          TableName: this.tableName,
          Key: { PK: `PRODUCT#${productId}`, SK: 'META' },
          ConditionExpression: `attribute_exists(PK) AND ${condition}`,
          UpdateExpression:
            'SET #onHand = #onHand + :onHand, #reserved = #reserved + :reserved, #available = #available + :available, #version = #version + :one, #updatedAt = :updatedAt',
          ExpressionAttributeNames: {
            ...(operation === 'RESERVE' ? { '#active': 'active' } : {}),
            '#available': 'available',
            '#onHand': 'onHand',
            '#reserved': 'reserved',
            '#updatedAt': 'updatedAt',
            '#version': 'version',
          },
          ExpressionAttributeValues: {
            ...(operation === 'RESERVE' ? { ':active': true } : {}),
            ':available': deltas.available,
            ':onHand': deltas.onHand,
            ':one': 1,
            ':quantity': quantity,
            ':reserved': deltas.reserved,
            ':updatedAt': updatedAt,
          },
          ReturnValues: 'ALL_NEW',
        }),
      );
      if (!isProductItem(response.Attributes) || !isConsistentAvailability(response.Attributes)) {
        return err({ code: 'INVALID_RECORD' });
      }
      const { PK, SK, itemType, schemaVersion, ...product } = response.Attributes;
      void schemaVersion;
      void PK;
      void SK;
      void itemType;
      return ok(product);
    } catch (error: unknown) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'name' in error &&
        error.name === 'ConditionalCheckFailedException'
      ) {
        return err({ code: operation === 'RESERVE' ? 'OUT_OF_STOCK' : 'INVENTORY_CONFLICT' });
      }
      return err({ code: 'REPOSITORY_UNAVAILABLE' });
    }
  }

  public async isReady(): Promise<boolean> {
    try {
      await this.client.send(
        new GetCommand({ TableName: this.tableName, Key: { PK: 'HEALTH', SK: 'READINESS' } }),
      );
      return true;
    } catch {
      return false;
    }
  }
}
