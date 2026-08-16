import type { CatalogRepository } from '../ports/catalog-repository';
import type { Result } from '../result/result';
import { err, ok } from '../result/result';
import { parseProductId } from '../../domain/catalog/product';

export type GetProductStockError = Readonly<{
  code: 'INVALID_PRODUCT_ID' | 'PRODUCT_NOT_FOUND' | 'REPOSITORY_UNAVAILABLE';
}>;

export interface ProductStock {
  readonly productId: string;
  readonly available: number;
  readonly asOf: string;
}

export class GetProductStock {
  public constructor(private readonly repository: CatalogRepository) {}

  public async execute(
    productIdCandidate: string,
  ): Promise<Result<ProductStock, GetProductStockError>> {
    const productId = parseProductId(productIdCandidate);
    if (!productId.ok) return productId;
    const product = await this.repository.findById(productId.value);
    if (!product.ok) return err({ code: 'REPOSITORY_UNAVAILABLE' });
    if (product.value === null || !product.value.active) return err({ code: 'PRODUCT_NOT_FOUND' });
    return ok({
      productId: product.value.productId,
      available: product.value.available,
      asOf: product.value.updatedAt,
    });
  }
}
