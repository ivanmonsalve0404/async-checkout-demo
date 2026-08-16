import type {
  CatalogRepository,
  RepositoryError,
} from '../../application/ports/catalog-repository';
import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';
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

  public listActive(
    limit: number,
  ): Promise<Result<readonly ProductAvailability[], RepositoryError>> {
    const products = [...this.products.values()]
      .filter((product) => product.active)
      .slice(0, Math.min(Math.max(limit, 0), 100))
      .map((product) => structuredClone(product));
    return Promise.resolve(ok(products));
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

  public reserve(
    productId: string,
    quantity: 1,
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>> {
    const product = this.products.get(productId);
    if (product === undefined || product.available < quantity) {
      return Promise.resolve(err({ code: 'OUT_OF_STOCK' }));
    }
    return Promise.resolve(
      this.update(product, { reserved: quantity, available: -quantity }, updatedAt),
    );
  }

  public consume(
    productId: string,
    quantity: 1,
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>> {
    const product = this.products.get(productId);
    if (product === undefined || product.reserved < quantity || product.onHand < quantity) {
      return Promise.resolve(err({ code: 'INVENTORY_CONFLICT' }));
    }
    return Promise.resolve(
      this.update(product, { onHand: -quantity, reserved: -quantity }, updatedAt),
    );
  }

  public release(
    productId: string,
    quantity: 1,
    updatedAt: string,
  ): Promise<Result<ProductAvailability, RepositoryError>> {
    const product = this.products.get(productId);
    if (product === undefined || product.reserved < quantity) {
      return Promise.resolve(err({ code: 'INVENTORY_CONFLICT' }));
    }
    return Promise.resolve(
      this.update(product, { reserved: -quantity, available: quantity }, updatedAt),
    );
  }

  private update(
    product: ProductAvailability,
    delta: Readonly<{ onHand?: number; reserved?: number; available?: number }>,
    updatedAt: string,
  ): Result<ProductAvailability, RepositoryError> {
    const updated: ProductAvailability = {
      ...product,
      onHand: product.onHand + (delta.onHand ?? 0),
      reserved: product.reserved + (delta.reserved ?? 0),
      available: product.available + (delta.available ?? 0),
      version: product.version + 1,
      updatedAt,
    };
    this.products.set(product.productId, updated);
    return ok(structuredClone(updated));
  }
  public isReady(): Promise<boolean> {
    return Promise.resolve(true);
  }
}
