import type { Result } from '../result/result';
import type { ProductAvailability } from '../../domain/catalog/product';

export type RepositoryError = Readonly<{
  code: 'REPOSITORY_UNAVAILABLE' | 'INVALID_RECORD' | 'OUT_OF_STOCK' | 'INVENTORY_CONFLICT';
}>;

export interface CatalogRepository {
  findById(productId: string): Promise<Result<ProductAvailability | null, RepositoryError>>;
  listActive(limit: number): Promise<Result<readonly ProductAvailability[], RepositoryError>>;
  seedIfAbsent(
    product: ProductAvailability,
  ): Promise<Result<'CREATED' | 'EXISTS', RepositoryError>>;
  isReady(): Promise<boolean>;
  reserve(
    productId: string,
    quantity: 1,
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>>;
  consume(
    productId: string,
    quantity: 1,
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>>;
  release(
    productId: string,
    quantity: 1,
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>>;
}

export const CATALOG_REPOSITORY = Symbol('CATALOG_REPOSITORY');
