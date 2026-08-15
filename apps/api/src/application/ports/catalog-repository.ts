import type { Result } from '../result/result';
import type { ProductAvailability } from '../../domain/catalog/product';

export type RepositoryError = Readonly<{
  code: 'REPOSITORY_UNAVAILABLE' | 'INVALID_RECORD';
}>;

export interface CatalogRepository {
  findById(productId: string): Promise<Result<ProductAvailability | null, RepositoryError>>;
  seedIfAbsent(
    product: ProductAvailability,
  ): Promise<Result<'CREATED' | 'EXISTS', RepositoryError>>;
  isReady(): Promise<boolean>;
}

export const CATALOG_REPOSITORY = Symbol('CATALOG_REPOSITORY');
