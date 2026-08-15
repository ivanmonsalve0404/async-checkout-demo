import { buildProductRequest, parseProductResponse } from './product-api';

describe('productApi', () => {
  it('builds the canonical encoded product request', () => {
    expect(buildProductRequest('sku / demo')).toEqual({
      url: '/products/sku%20%2F%20demo',
      method: 'GET',
    });
  });

  it('accepts only the public product contract', () => {
    const product = {
      productId: 'product-demo-001',
      sku: 'SKU_DEMO_001',
      name: 'Producto de demostración',
      description: 'Producto sintético',
      imageUrl: 'http://localhost/product.svg',
      unitPrice: { amountInCents: 2_500_000, currency: 'COP' },
      available: 3,
    };
    expect(parseProductResponse(product)).toEqual(product);
    expect(() => parseProductResponse({ ...product, unexpected: true })).toThrow();
    expect(() => parseProductResponse({ unsafe: 'shape' })).toThrow();
  });
});
