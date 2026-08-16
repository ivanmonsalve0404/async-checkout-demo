import type { CatalogRepository } from '../ports/catalog-repository';
import type { Result } from '../result/result';
import { err, ok } from '../result/result';
import type { ProductAvailability } from '../../domain/catalog/product';

export type ListProductsError = Readonly<{ code: 'REPOSITORY_UNAVAILABLE' }>;

export class ListProducts {
  public constructor(private readonly repository: CatalogRepository) {}

  public async execute(): Promise<Result<readonly ProductAvailability[], ListProductsError>> {
    const products = await this.repository.listActive(100);
    return products.ok ? ok(products.value) : err({ code: 'REPOSITORY_UNAVAILABLE' });
  }
}
