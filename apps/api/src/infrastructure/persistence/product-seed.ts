import type { ProductAvailability } from '../../domain/catalog/product';

export const createProductSeed = (
  productId: string,
  publicAssetOrigin: string,
): ProductAvailability => ({
  productId,
  sku: 'SKU_DEMO_001',
  name: 'Morral urbano de demostración',
  description: 'Producto sintético para validar el recorrido técnico de lectura y disponibilidad.',
  imageUrl: new URL('/product-placeholder.svg', publicAssetOrigin).toString(),
  unitPrice: { amountInCents: 2_500_000, currency: 'COP' },
  onHand: 3,
  reserved: 0,
  available: 3,
  active: true,
  version: 1,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
});
