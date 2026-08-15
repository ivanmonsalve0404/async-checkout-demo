import type {
  CatalogRepository,
  RepositoryError,
} from '../../application/ports/catalog-repository';
import type { Result } from '../../application/result/result';
import { ok } from '../../application/result/result';
import type { ProductAvailability } from '../../domain/catalog/product';

export class InMemoryCatalogRepository implements CatalogRepository {
  private readonly products = new Map<string, ProductAvailability>();

  public constructor(initialProducts: readonly ProductAvailability[] = []) {
    for (const product of initialProducts) {
      this.products.set(product.productId, structuredClone(product));
    }
  }

  public findById(productId: string): Promise<Result<ProductAvailability | null, RepositoryError>> {
    const product = this.products.get(productId);
    return Promise.resolve(ok(product === undefined ? null : structuredClone(product)));
  }

  public seedIfAbsent(
    product: ProductAvailability,
  ): Promise<Result<'CREATED' | 'EXISTS', RepositoryError>> {
    if (this.products.has(product.productId)) {
      return Promise.resolve(ok('EXISTS'));
    }
    this.products.set(product.productId, structuredClone(product));
    return Promise.resolve(ok('CREATED'));
  }

  public isReady(): Promise<boolean> {
    return Promise.resolve(true);
  }
}
