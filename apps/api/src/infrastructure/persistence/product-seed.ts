import type { ProductAvailability } from '../../domain/catalog/product';

export const createProductSeed = (
  productId: string,
  publicAssetOrigin: string,
  initialStock = 3,
): ProductAvailability => ({
  productId,
  sku: 'SKU_DEMO_001',
  name: 'Morral urbano de demostración',
  description: 'Producto sintético para validar el recorrido técnico de lectura y disponibilidad.',
  imageUrl: new URL('/product-placeholder.svg', publicAssetOrigin).toString(),
  unitPrice: { amountInCents: 2_500_000, currency: 'COP' },
  onHand: initialStock,
  reserved: 0,
  available: initialStock,
  active: true,
  version: 1,
  createdAt: '2026-01-01T00:00:00.000Z',
  updatedAt: '2026-01-01T00:00:00.000Z',
});
