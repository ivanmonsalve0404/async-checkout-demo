import { readPublicConfig } from './public-config';

describe('public frontend configuration', () => {
  it('uses the documented public default and accepts an override', () => {
    expect(readPublicConfig({}).productId).toBe('product-demo-001');
    expect(readPublicConfig({ VITE_PRODUCT_ID: 'product-other-001' }).productId).toBe(
      'product-other-001',
    );
  });

  it('rejects malformed public identifiers', () => {
    expect(() => readPublicConfig({ VITE_PRODUCT_ID: 'bad/id' })).toThrow();
  });
});
