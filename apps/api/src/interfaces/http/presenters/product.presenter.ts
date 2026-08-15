import type { ProductAvailability } from '../../../domain/catalog/product';

export interface ProductResponse {
  readonly productId: string;
  readonly sku: string;
  readonly name: string;
  readonly description: string;
  readonly imageUrl: string;
  readonly unitPrice: Readonly<{ amountInCents: number; currency: 'COP' }>;
  readonly available: number;
}

export const presentProduct = (product: ProductAvailability): ProductResponse => ({
  productId: product.productId,
  sku: product.sku,
  name: product.name,
  description: product.description,
  imageUrl: product.imageUrl,
  unitPrice: product.unitPrice,
  available: product.available,
});
