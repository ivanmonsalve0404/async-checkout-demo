import { GetCommand, PutCommand, type DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import type {
  CatalogRepository,
  RepositoryError,
} from '../../application/ports/catalog-repository';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';
import { isConsistentAvailability, type ProductAvailability } from '../../domain/catalog/product';

type DynamoProductItem = ProductAvailability &
  Readonly<{ PK: string; SK: 'META'; itemType: 'PRODUCT' }>;

const isProductItem = (candidate: unknown): candidate is DynamoProductItem => {
  if (typeof candidate !== 'object' || candidate === null) {
    return false;
  }
  const item = candidate as Partial<DynamoProductItem>;
  return (
    item.itemType === 'PRODUCT' &&
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
      const { PK, SK, itemType, ...product } = response.Item;
      void PK;
      void SK;
      void itemType;
      return ok(product);
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
    };
    try {
      await this.client.send(
        new PutCommand({
          TableName: this.tableName,
          Item: item,
          ConditionExpression: 'attribute_not_exists(PK) AND attribute_not_exists(SK)',
        }),
      );
      return ok('CREATED');
    } catch (error: unknown) {
      if (
        typeof error === 'object' &&
        error !== null &&
        'name' in error &&
        error.name === 'ConditionalCheckFailedException'
      ) {
        return ok('EXISTS');
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
