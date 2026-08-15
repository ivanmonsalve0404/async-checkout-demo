import type { Result } from '../../application/result/result';
import { err, ok } from '../../application/result/result';

export interface Money {
  readonly amountInCents: number;
  readonly currency: 'COP';
}

export interface ProductAvailability {
  readonly productId: string;
  readonly sku: string;
  readonly name: string;
  readonly description: string;
  readonly imageUrl: string;
  readonly unitPrice: Money;
  readonly onHand: number;
  readonly reserved: number;
  readonly available: number;
  readonly active: boolean;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export type ProductIdError = Readonly<{ code: 'INVALID_PRODUCT_ID' }>;

const opaqueIdPattern = /^[A-Za-z0-9_-]{8,128}$/;

export const parseProductId = (candidate: string): Result<string, ProductIdError> =>
  opaqueIdPattern.test(candidate) ? ok(candidate) : err({ code: 'INVALID_PRODUCT_ID' });

export const isConsistentAvailability = (product: ProductAvailability): boolean =>
  product.onHand >= 0 &&
  product.reserved >= 0 &&
  product.available >= 0 &&
  product.available === product.onHand - product.reserved &&
  Number.isSafeInteger(product.unitPrice.amountInCents) &&
  product.unitPrice.amountInCents >= 0;
