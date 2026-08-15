import type { CatalogRepository, RepositoryError } from '../ports/catalog-repository';
import type { Result } from '../result/result';
import { err } from '../result/result';
import { isConsistentAvailability, parseProductId } from '../../domain/catalog/product';
import type { ProductAvailability } from '../../domain/catalog/product';

export type GetProductError =
  | Readonly<{ code: 'INVALID_PRODUCT_ID' }>
  | Readonly<{ code: 'PRODUCT_NOT_FOUND' }>
  | RepositoryError;

export class GetProductAvailability {
  public constructor(private readonly catalogRepository: CatalogRepository) {}

  public async execute(
    productIdCandidate: string,
  ): Promise<Result<ProductAvailability, GetProductError>> {
    const parsedId = parseProductId(productIdCandidate);
    if (!parsedId.ok) {
      return parsedId;
    }

    const found = await this.catalogRepository.findById(parsedId.value);
    if (!found.ok) {
      return found;
    }
    if (found.value === null || !found.value.active) {
      return err({ code: 'PRODUCT_NOT_FOUND' });
    }
    if (!isConsistentAvailability(found.value)) {
      return err({ code: 'INVALID_RECORD' });
    }
    return { ok: true, value: found.value };
  }
}
